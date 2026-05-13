const crypto = require('crypto');

module.exports = function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  const token = req.headers['x-sign-token'];
  if (token !== process.env.SIGN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  const { method, uri, payload = '', timestamp } = req.body || {};
  if (!method || !uri || !timestamp) return res.status(400).json({ error: 'Missing fields' });
  const message = [method, uri, payload, String(timestamp)].join('\n');
  const signature = crypto.createHmac('sha256', process.env.KL_SECRET).update(message).digest('hex');
  return res.status(200).json({ signature });
};
