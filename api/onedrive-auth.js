// api/onedrive-auth.js — Étape C : connexion Microsoft unique pour toute la pharmacie.
// Sans ?code : vérifie ?session=… puis redirige vers l'authorize /consumers
// (scope Files.ReadWrite offline_access User.Read, state signé HMAC 10 min).
// Avec ?code : échange, chiffre le refresh token (AES-256-GCM), le pousse dans
// secrets/ms-refresh.enc du repo Reconcilia, redirige vers /?onedrive=ok.
import crypto from 'crypto';

export const maxDuration = 30;

const OWNER = 'pharmaciemichelet127-cyber';
const REPO = 'Reconcilia';
const SECRET_PATH = 'secrets/ms-refresh.enc';
const APP_URL = 'https://reconcilia-bice.vercel.app';
const REDIRECT_URI = APP_URL + '/api/onedrive-auth';
const AUTHORIZE_URL = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize';
const TOKEN_URL = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token';
const SCOPE = 'Files.ReadWrite offline_access User.Read';

function hmac(msg) {
  return crypto.createHmac('sha256', process.env.SESSION_SECRET || '').update(msg).digest('hex');
}
function sessionValide(s) {
  s = String(s || '');
  const i = s.indexOf('.');
  if (i < 1) return false;
  const exp = s.slice(0, i), sig = s.slice(i + 1);
  if (!/^\d+$/.test(exp) || Date.now() > Number(exp)) return false;
  const expected = hmac(exp);
  try {
    return sig.length === expected.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch { return false; }
}
function encrypt(text, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), data]); // iv(12) | authTag(16) | data
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  for (const v of ['SESSION_SECRET', 'GH_TOKEN', 'MS_CLIENT_ID', 'MS_CLIENT_SECRET', 'MS_ENC_KEY']) {
    if (!process.env[v]) return res.status(500).send(v + ' non configuré sur Vercel');
  }

  const { code, state, session, error, error_description } = req.query;

  if (error) {
    return res.status(400).send('Connexion Microsoft refusée : ' + (error_description || error));
  }

  /* ---- Phase 1 : départ vers Microsoft ---- */
  if (!code) {
    if (!sessionValide(session)) {
      return res.status(401).send('Session invalide ou expirée — rechargez ReconcilIA et ressaisissez le mot de passe.');
    }
    const exp = Date.now() + 10 * 60 * 1000; // state valable 10 minutes
    const st = exp + '.' + hmac('state.' + exp);
    const url = AUTHORIZE_URL + '?' + new URLSearchParams({
      client_id: process.env.MS_CLIENT_ID,
      response_type: 'code',
      redirect_uri: REDIRECT_URI,
      response_mode: 'query',
      scope: SCOPE,
      state: st,
      prompt: 'select_account'
    });
    res.setHeader('Location', url);
    return res.status(302).end();
  }

  /* ---- Phase 2 : retour de Microsoft avec ?code ---- */
  const s = String(state || '');
  const i = s.indexOf('.');
  const exp = i > 0 ? s.slice(0, i) : '';
  const sig = i > 0 ? s.slice(i + 1) : '';
  const expected = hmac('state.' + exp);
  let stateOk = /^\d+$/.test(exp) && Date.now() < Number(exp) && sig.length === expected.length;
  if (stateOk) { try { stateOk = crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected)); } catch { stateOk = false; } }
  if (!stateOk) return res.status(401).send('State invalide ou expiré (10 min) — relancez la connexion depuis ReconcilIA.');

  try {
    const tr = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.MS_CLIENT_ID,
        client_secret: process.env.MS_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: String(code),
        redirect_uri: REDIRECT_URI,
        scope: SCOPE
      })
    });
    const tj = await tr.json().catch(() => ({}));
    if (!tr.ok || !tj.refresh_token) {
      return res.status(502).send('Échange du code Microsoft échoué : ' + (tj.error_description || tj.error || tr.status));
    }

    // Chiffrer et pousser le refresh token dans le repo
    const encBuf = encrypt(JSON.stringify({ refresh_token: tj.refresh_token }), process.env.MS_ENC_KEY);
    const ghHeaders = {
      'Authorization': 'Bearer ' + process.env.GH_TOKEN,
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'reconcilia-proxy',
      'Content-Type': 'application/json'
    };
    let sha;
    const gr = await fetch(`https://api.github.com/repos/${OWNER}/${REPO}/contents/${SECRET_PATH}`, { headers: ghHeaders });
    if (gr.ok) sha = (await gr.json()).sha;
    const body = { message: 'Connexion OneDrive pharmacie', content: encBuf.toString('base64') };
    if (sha) body.sha = sha;
    const pr = await fetch(`https://api.github.com/repos/${OWNER}/${REPO}/contents/${SECRET_PATH}`, {
      method: 'PUT', headers: ghHeaders, body: JSON.stringify(body)
    });
    if (!pr.ok) return res.status(502).send('Sauvegarde du secret échouée (GitHub ' + pr.status + ') — vérifier GH_TOKEN.');

    res.setHeader('Location', APP_URL + '/?onedrive=ok');
    return res.status(302).end();
  } catch (e) {
    return res.status(500).send('Erreur connexion OneDrive : ' + e.message);
  }
}
