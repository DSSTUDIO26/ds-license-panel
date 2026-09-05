// server.js
const express = require('express');
const { Pool } = require('pg');
const path = require('path');

const app = express();
app.use(express.json());

app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const verifySecret = (req, res, next) => {
  const secret = req.headers['x-api-secret'] || req.query.secret || req.body.secret;
  if (secret !== process.env.API_SECRET) {
    return res.status(403).json({ success: false, message: 'Unauthorized: Invalid API Secret' });
  }
  next();
};

app.get('/api/status', (req, res) => {
  res.json({ success: true, message: 'DS License Panel API is online!' });
});

// Diperbarui: Mendukung pencarian via license_key ATAU owner_name (Username Roblox)
app.post('/api/verify', async (req, res) => {
  const { license_key, owner_name } = req.body;
  const searchParam = license_key || owner_name;

  if (!searchParam) {
    return res.status(400).json({ success: false, message: 'License key or username required' });
  }

  try {
    const result = await pool.query(
      'SELECT * FROM licenses WHERE (license_key = $1 OR owner_name ILIKE $1) AND is_active = true',
      [searchParam]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Lisensi tidak ditemukan atau tidak aktif' });
    }

    const license = result.rows[0];

    if (license.expires_at && new Date(license.expires_at) < new Date()) {
      return res.status(403).json({ success: false, message: 'Lisensi telah kedaluwarsa' });
    }

    res.json({
      success: true,
      message: 'Lisensi valid',
      data: {
        key: license.license_key,
        owner: license.owner_name,
        expires_at: license.expires_at
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

app.post('/api/licenses/create', verifySecret, async (req, res) => {
  const { license_key, owner_name, expires_at } = req.body;
  try {
    await pool.query(
      'INSERT INTO licenses (license_key, owner_name, expires_at, is_active) VALUES ($1, $2, $3, true)',
      [license_key, owner_name, expires_at || null]
    );
    res.json({ success: true, message: 'License created successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to create license' });
  }
});

app.get('/api/licenses', verifySecret, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM licenses ORDER BY created_at DESC');
    res.json({ success: true, licenses: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch licenses' });
  }
});

module.exports = app;

if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}
