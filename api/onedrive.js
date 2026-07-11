// api/onedrive.js — Étape C : proxy graph.microsoft.com/v1.0/me/drive*
// Session exigée (header X-Session). Access token obtenu via le refresh token
// chiffré AES-256-GCM (clé MS_ENC_KEY) lu dans secrets/ms-refresh.enc du repo
// Reconcilia ; rotation gérée (nouveau refresh token re-chiffré et re-poussé).
// 428 onedrive_non_connecte si absent/révoqué.
// Téléchargements : Graph répond 302 → renvoi de l'URL directe Microsoft
// (header X-Proxy-Redirect + JSON {downloadUrl}) que le client suit lui-même.
import crypto from 'crypto';
import zlib from 'zlib';

export const config = { api: { bodyParser: false } };
export const maxDuration = 60;

const OWNER = 'pharmaciemichelet127-cyber';
const REPO = 'Reconcilia';
const SECRET_PATH = 'secrets/ms-refresh.enc';
const GRAPH = 'https://graph.microsoft.com/v1.0';
const TOKEN_URL = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token';
const SCOPE = 'Files.ReadWrite offline_access User.Read';

/* ---------- Session ---------- */
function sessionValide(req) {
  const s = String(req.headers['x-session'] || '');
  const i = s.indexOf('.');
  if (i < 1) return false;
  const exp = s.slice(0, i), sig = s.slice(i + 1);
  if (!/^\d+$/.test(exp) || Date.now() > Number(exp)) return false;
  const expected = crypto.createHmac('sha256', process.env.SESSION_SECRET || '').update(exp).digest('hex');
  try {
    return sig.length === expected.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch { return false; }
}

/* ---------- AES-256-GCM : iv(12) | authTag(16) | data ---------- */
function decrypt(buf, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const iv = buf.subarray(0, 12), tag = buf.subarray(12, 28), data = buf.subarray(28);
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(data), d.final()]).toString('utf8');
}
function encrypt(text, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), data]);
}

/* ---------- Secret dans le repo GitHub ---------- */
const GH_HEADERS = () => ({
  'Authorization': 'Bearer ' + process.env.GH_TOKEN,
  'Accept': 'application/vnd.github+json',
  'User-Agent': 'reconcilia-proxy'
});
async function ghGetSecret() {
  const r = await fetch(`https://api.github.com/repos/${OWNER}/${REPO}/contents/${SECRET_PATH}`, { headers: GH_HEADERS() });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error('GitHub ' + r.status);
  const j = await r.json();
  return { buf: Buffer.from(j.content, 'base64'), sha: j.sha };
}
async function ghPutSecret(buf, sha) {
  const body = { message: 'Rotation refresh token OneDrive', content: buf.toString('base64') };
  if (sha) body.sha = sha;
  const r = await fetch(`https://api.github.com/repos/${OWNER}/${REPO}/contents/${SECRET_PATH}`, {
    method: 'PUT',
    headers: { ...GH_HEADERS(), 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error('GitHub PUT ' + r.status);
}

/* ---------- Access token (cache mémoire tant que la lambda est chaude) ---------- */
let _cache = { token: null, exp: 0 };
function err428() { const e = new Error('onedrive_non_connecte'); e.code = 428; return e; }

async function getAccessToken() {
  if (_cache.token && Date.now() < _cache.exp - 120000) return _cache.token;
  const enc = await ghGetSecret();
  if (!enc) throw err428();
  let refresh;
  try { refresh = decrypt(enc.buf, process.env.MS_ENC_KEY); }
  catch { throw err428(); } // MS_ENC_KEY changée → secret illisible → refaire la connexion
  const r = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.MS_CLIENT_ID,
      client_secret: process.env.MS_CLIENT_SECRET,
      grant_type: 'refresh_token',
      refresh_token: refresh,
      scope: SCOPE
    })
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) throw err428(); // refresh token révoqué/expiré
  _cache = { token: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
  // Rotation : re-chiffrer et re-pousser le nouveau refresh token
  if (j.refresh_token && j.refresh_token !== refresh) {
    try { await ghPutSecret(encrypt(j.refresh_token, process.env.MS_ENC_KEY), enc.sha); }
    catch (e) { console.warn('Rotation refresh token non poussée:', e.message); }
  }
  return _cache.token;
}

/* ---------- Corps brut (bodyParser désactivé) ---------- */
async function readRaw(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks);
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'OPTIONS') return res.status(200).end();

  for (const v of ['SESSION_SECRET', 'GH_TOKEN', 'MS_CLIENT_ID', 'MS_CLIENT_SECRET', 'MS_ENC_KEY']) {
    if (!process.env[v]) return res.status(500).json({ error: v + ' non configuré sur Vercel' });
  }
  if (!sessionValide(req)) return res.status(401).json({ error: 'Session invalide ou expirée' });

  const path = String(req.query.path || '');
  if (!path.startsWith('/me/drive')) return res.status(400).json({ error: 'Chemin non autorisé' });

  let token;
  try { token = await getAccessToken(); }
  catch (e) {
    if (e.code === 428) return res.status(428).json({ error: 'onedrive_non_connecte' });
    return res.status(502).json({ error: 'Token OneDrive: ' + e.message });
  }

  try {
    let body;
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      body = await readRaw(req);
      if (req.headers['x-gzip'] === '1') body = zlib.gunzipSync(body);
      if (!body.length) body = undefined;
    }
    const headers = { 'Authorization': 'Bearer ' + token };
    if (req.headers['content-type']) headers['Content-Type'] = req.headers['content-type'];
    if (req.headers['prefer']) headers['Prefer'] = req.headers['prefer'];

    const gr = await fetch(GRAPH + path, { method: req.method, headers, body, redirect: 'manual' });

    // Téléchargement : Graph répond 302 → renvoyer l'URL directe Microsoft
    if (gr.status === 301 || gr.status === 302) {
      const loc = gr.headers.get('location') || '';
      res.setHeader('X-Proxy-Redirect', loc);
      return res.status(200).json({ downloadUrl: loc });
    }

    const buf = Buffer.from(await gr.arrayBuffer());
    const ct = gr.headers.get('content-type');
    if (ct) res.setHeader('Content-Type', ct);
    if (buf.length > 4 * 1024 * 1024) {
      // Sécurité limite Vercel 4,5 Mo — ne devrait jamais arriver (les contenus passent par le 302)
      return res.status(502).json({ error: 'Réponse Graph trop volumineuse pour le proxy' });
    }
    return res.status(gr.status).send(buf);
  } catch (e) {
    return res.status(502).json({ error: 'Proxy OneDrive: ' + e.message });
  }
}
