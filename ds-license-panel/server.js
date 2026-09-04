const express = require('express');
const { Pool } = require('pg');
const path = require('path');

const app = express();
app.use(express.json());

// 1. Sajikan file statis (index.html, CSS, JS frontend)
app.use(express.static(__dirname));

// 2. Route Halaman Utama (Membuka Admin Panel)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// 3. Setup Koneksi Database Neon PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Middleware Cek API Secret (Kunci Keamanan)
const verifySecret = (req, res, next) => {
  const secret = req.headers['x-api-secret'] || req.query.secret || req.body.secret;
  if (secret !== process.env.API_SECRET) {
    return res.status(403).json({ success: false, message: 'Unauthorized: Invalid API Secret' });
  }
  next();
};

// ---------------- API ENDPOINTS ----------------

// API Cek Status Server
app.get('/api/status', (req, res) => {
  res.json({ success: true, message: 'DS License Panel API is online!' });
});

// API Verifikasi Lisensi (Dipanggil dari Roblox Studio)
app.post('/api/verify', async (req, res) => {
  const { license_key, place_id } = req.body;

  if (!license_key) {
    return res.status(400).json({ success: false, message: 'License key required' });
  }

  try {
    const result = await pool.query(
      'SELECT * FROM licenses WHERE license_key = $1 AND is_active = true',
      [license_key]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Invalid or inactive license' });
    }

    const license = result.rows[0];

    // Cek Expired
    if (license.expires_at && new Date(license.expires_at) < new Date()) {
      return res.status(403).json({ success: false, message: 'License expired' });
    }

    res.json({
      success: true,
      message: 'License verified successfully',
      data: {
        owner: license.owner_name,
        expires_at: license.expires_at
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// API Buat Lisensi Baru (Dipanggil dari Panel Admin)
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

// API Ambil Semua Lisensi (Dipanggil dari Panel Admin)
app.get('/api/licenses', verifySecret, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM licenses ORDER BY created_at DESC');
    res.json({ success: true, licenses: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch licenses' });
  }
});

// Export untuk Vercel Serverless
module.exports = app;

// Jalankan server lokal jika bukan di Vercel
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}
