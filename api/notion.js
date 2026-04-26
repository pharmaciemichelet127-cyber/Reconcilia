export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const token = process.env.NOTION_TOKEN;
  if (!token) return res.status(500).json({ error: 'NOTION_TOKEN non configuré' });

  const { path, method = 'POST', body } = req.body || {};
  if (!path) return res.status(400).json({ error: 'path manquant' });

  try {
    const notionRes = await fetch(`https://api.notion.com/v1${path}`, {
      method,
      headers: {
        'Authorization': 'Bearer ' + token,
        'Notion-Version': '2022-06-28',
        'Content-Type': 'application/json',
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await notionRes.json();
    res.status(notionRes.status).json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}
