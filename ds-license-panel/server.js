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

// Konfigurasi Pool Database PostgreSQL yang Aman
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Middleware Verifikasi Admin Secret
const verifySecret = (req, res, next) => {
  const secret = req.headers['x-api-secret'] || req.headers['authorization'] || req.body?.secret || req.query?.secret;
  const expectedSecret = process.env.API_SECRET;

  if (!expectedSecret) {
    console.error("CRITICAL ERROR: API_SECRET belum diset di Environment Variables Vercel!");
    return res.status(500).json({ success: false, message: 'Kesalahan konfigurasi server.' });
  }

  if (!secret || secret.trim() !== expectedSecret.trim()) {
    return res.status(403).json({ success: false, message: 'Unauthorized: API Secret salah.' });
  }

  next();
};

// Endpoint Cek Status
app.get('/api/status', (req, res) => {
  res.json({ success: true, message: 'DS License Panel API online dan aman.' });
});

// Endpoint Verifikasi Lisensi (Publik)
app.post('/api/verify', async (req, res) => {
  const { license_key, owner_name } = req.body;
  const searchParam = license_key || owner_name;

  if (!searchParam || typeof searchParam !== 'string' || searchParam.trim() === '') {
    return res.status(400).json({ success: false, message: 'License key atau username wajib diisi.' });
  }

  try {
    const result = await pool.query(
      'SELECT * FROM licenses WHERE (license_key = $1 OR owner_name ILIKE $1) AND is_active = true',
      [searchParam.trim()]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Lisensi tidak ditemukan atau tidak aktif.' });
    }

    const license = result.rows[0];

    if (license.expires_at && new Date(license.expires_at) < new Date()) {
      return res.status(403).json({ success: false, message: 'Lisensi telah kedaluwarsa.' });
    }

    res.json({
      success: true,
      message: 'Lisensi valid.',
      data: {
        key: license.license_key,
        owner: license.owner_name,
        expires_at: license.expires_at
      }
    });
  } catch (err) {
    console.error('Database Error /api/verify:', err.message);
    res.status(500).json({ success: false, message: 'Gagal mengambil data dari database.' });
  }
});

// Endpoint Tambah Lisensi (Admin)
app.post('/api/licenses/create', verifySecret, async (req, res) => {
  const { license_key, owner_name, expires_at } = req.body;

  if (!license_key || !owner_name) {
    return res.status(400).json({ success: false, message: 'License key dan owner name wajib diisi.' });
  }

  try {
    await pool.query(
      'INSERT INTO licenses (license_key, owner_name, expires_at, is_active) VALUES ($1, $2, $3, true)',
      [license_key.trim(), owner_name.trim(), expires_at || null]
    );
    res.json({ success: true, message: 'Lisensi berhasil dibuat.' });
  } catch (err) {
    console.error('Database Error /api/licenses/create:', err.message);
    res.status(500).json({ success: false, message: 'Gagal membuat lisensi (kemungkinan Key sudah terdaftar).' });
  }
});

// Endpoint Ambil Semua Lisensi (Admin)
app.get('/api/licenses', verifySecret, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM licenses ORDER BY created_at DESC');
    res.json({ success: true, licenses: result.rows });
  } catch (err) {
    console.error('Database Error /api/licenses:', err.message);
    res.status(500).json({ success: false, message: 'Gagal mengambil dari database' });
  }
});

// Ekspor untuk Serverless Vercel
module.exports = app;

if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server lokal berjalan di port ${PORT}`));
}
