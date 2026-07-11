// api/claude.js — proxy Anthropic. Depuis v2.0.20260712z85 : session exigée
// (header X-Session, même jeton que /api/onedrive) pour protéger la clé API.
import crypto from 'crypto';

export const maxDuration = 120; // 2 minutes pour les gros PDFs

export const config = {
  api: {
    bodyParser: {
      sizeLimit: '10mb',
    },
  },
};

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

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-key, X-Session');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  if (!process.env.SESSION_SECRET) return res.status(500).json({ error: 'SESSION_SECRET non configuré sur Vercel' });
  if (!sessionValide(req)) return res.status(401).json({ error: 'Session invalide ou expirée — rechargez la page et ressaisissez le mot de passe' });

  try {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) return res.status(500).json({ error: 'ANTHROPIC_API_KEY non configurée' });

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(req.body)
    });

    const data = await response.json();
    return res.status(response.status).json(data);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}
