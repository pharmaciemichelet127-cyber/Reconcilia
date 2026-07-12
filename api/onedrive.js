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
  const body = { message: 'MAJ jeton OneDrive', content: buf.toString('base64') };
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
let _inflight = null; // dédoublonne les renouvellements concurrents d'une même instance
function err428() { const e = new Error('onedrive_non_connecte'); e.code = 428; return e; }

// Le fichier chiffré contient depuis z86 un JSON {refresh_token, access_token, access_exp}
// (l'ancien format « refresh token brut » reste lu de façon transparente).
async function readStored() {
  const enc = await ghGetSecret();
  if (!enc) return null;
  let txt;
  try { txt = decrypt(enc.buf, process.env.MS_ENC_KEY); }
  catch { return { bad: true, sha: enc.sha }; } // MS_ENC_KEY changée → refaire la connexion
  let obj;
  try { obj = JSON.parse(txt); } catch { obj = { refresh_token: txt }; }
  if (!obj.refresh_token) obj = { refresh_token: txt };
  return { obj, sha: enc.sha };
}

// Push avec gestion du conflit 409 (une autre instance a écrit entre-temps :
// on relit le sha et on réessaie — le jeton le plus récent doit gagner)
async function pushStored(obj, sha) {
  const buf = encrypt(JSON.stringify(obj), process.env.MS_ENC_KEY);
  for (let i = 0; i < 3; i++) {
    try { await ghPutSecret(buf, sha); return true; }
    catch (e) {
      if (!/409/.test(e.message)) throw e;
      const cur = await ghGetSecret();
      sha = cur ? cur.sha : undefined;
    }
  }
  return false;
}

async function refreshOnce() {
  let st = await readStored();
  if (!st || st.bad) throw err428();

  // 1. Access token stocké encore valable → zéro appel Microsoft, zéro rotation
  if (st.obj.access_token && st.obj.access_exp && Date.now() < st.obj.access_exp - 120000) {
    _cache = { token: st.obj.access_token, exp: st.obj.access_exp };
    return _cache.token;
  }

  // 2. Échange du refresh token — 2 tentatives, avec relecture du fichier entre
  //    les deux (une autre instance a pu le renouveler pendant ce temps)
  for (let attempt = 0; attempt < 2; attempt++) {
    const r = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.MS_CLIENT_ID,
        client_secret: process.env.MS_CLIENT_SECRET,
        grant_type: 'refresh_token',
        refresh_token: st.obj.refresh_token,
        scope: SCOPE
      })
    });
    const j = await r.json().catch(() => ({}));
    if (r.ok && j.access_token) {
      _cache = { token: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
      const newObj = {
        refresh_token: j.refresh_token || st.obj.refresh_token,
        access_token: j.access_token,
        access_exp: _cache.exp
      };
      try { await pushStored(newObj, st.sha); }
      catch (e) { console.warn('Sauvegarde jeton OneDrive non poussée:', e.message); }
      return _cache.token;
    }
    // Refus Microsoft : attendre 1,5 s puis relire le fichier avant de conclure
    await new Promise(rs => setTimeout(rs, 1500));
    st = await readStored();
    if (!st || st.bad) break;
    if (st.obj.access_token && st.obj.access_exp && Date.now() < st.obj.access_exp - 120000) {
      _cache = { token: st.obj.access_token, exp: st.obj.access_exp };
      return _cache.token;
    }
  }
  throw err428();
}

async function getAccessToken() {
  if (_cache.token && Date.now() < _cache.exp - 120000) return _cache.token;
  if (!_inflight) _inflight = refreshOnce().finally(() => { _inflight = null; });
  return _inflight;
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
