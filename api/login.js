// api/login.js — Étape A : accès par mot de passe partagé
// POST {password} → compare à APP_PASSWORD (temps constant)
// → délivre un jeton "expiration.signatureHMAC(SESSION_SECRET)" valable 30 jours.
import crypto from 'crypto';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const appPassword = process.env.APP_PASSWORD;
  const secret = process.env.SESSION_SECRET;
  if (!appPassword || !secret) {
    return res.status(500).json({ error: 'APP_PASSWORD ou SESSION_SECRET non configuré sur Vercel' });
  }

  const password = (req.body && typeof req.body.password === 'string') ? req.body.password : '';
  if (!password) return res.status(400).json({ error: 'Mot de passe requis' });

  // Comparaison en temps constant (hachage préalable → longueurs identiques)
  const a = crypto.createHash('sha256').update(password, 'utf8').digest();
  const b = crypto.createHash('sha256').update(appPassword, 'utf8').digest();
  if (!crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'Mot de passe incorrect' });
  }

  const expiration = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 jours
  const sig = crypto.createHmac('sha256', secret).update(String(expiration)).digest('hex');
  return res.status(200).json({ session: expiration + '.' + sig, expiration });
}
