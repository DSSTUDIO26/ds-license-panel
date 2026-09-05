const express = require('express');
const { Pool } = require('pg');
const path = require('path');

const app = express();
app.use(express.json());

// Konfigurasi Database PostgreSQL (Neon)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Middleware Proteksi Admin menggunakan Header x-api-secret
const verifyAdmin = (req, res, next) => {
    const secret = req.headers['x-api-secret'];
    if (!secret || secret !== process.env.ADMIN_SECRET) {
        return res.status(401).json({ success: false, message: 'Unauthorized: API Secret salah.' });
    }
    next();
};

// 1. Endpoint Verifikasi Klien (Client Hub)
app.post('/api/verify', async (req, res) => {
    const { owner_name } = req.body;
    if (!owner_name) {
        return res.status(400).json({ success: false, message: 'Username Roblox wajib diisi.' });
    }

    try {
        const query = `
            SELECT license_key, owner_name, product_name AS product, image_url, expires_at 
            FROM licenses 
            WHERE LOWER(owner_name) = LOWER($1)
        `;
        const result = await pool.query(query, [owner_name.trim()]);

        if (result.rows.length === 0) {
            return.json({ success: false, message: 'Tidak ada lisensi yang ditemukan untuk username ini.' });
        }

        res.json({ success: true, data: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Terjadi kesalahan pada database server.' });
    }
});

// 2. Endpoint Mengambil Semua Data Lisensi (Admin Dashboard)
app.get('/api/licenses', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM licenses ORDER BY id DESC');
        res.json({ success: true, licenses: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Gagal mengambil data dari database.' });
    }
});

// 3. Endpoint Membuat Lisensi Baru (Admin Dashboard)
app.post('/api/licenses/create', verifyAdmin, async (req, res) => {
    const { license_key, owner_name, product_name, image_url, expires_at } = req.body;

    if (!license_key || !owner_name || !product_name) {
        return res.status(400).json({ success: false, message: 'Key, Owner, dan Nama Produk wajib diisi.' });
    }

    try {
        const query = `
            INSERT INTO licenses (license_key, owner_name, product_name, image_url, expires_at) 
            VALUES ($1, $2, $3, $4, $5) 
            RETURNING *
        `;
        const values = [
            license_key, 
            owner_name, 
            product_name, 
            image_url || null, 
            expires_at || null
        ];

        const result = await pool.query(query, values);
        res.json({ success: true, message: 'Lisensi berhasil dibuat!', data: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Gagal menyimpan lisensi (Kemungkinan key sudah terdaftar).' });
    }
});

// 4. Endpoint Menghapus Lisensi (Admin Dashboard)
app.delete('/api/licenses/:id', verifyAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM licenses WHERE id = $1', [id]);
        res.json({ success: true, message: 'Lisensi berhasil dihapus.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Gagal menghapus lisensi dari database.' });
    }
});

// Routing statis untuk frontend index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Jalankan Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server Dragon Stell Studio berjalan di port ${PORT}`);
});

