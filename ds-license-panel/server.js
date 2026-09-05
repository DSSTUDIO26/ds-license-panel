const express = require('express');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const API_SECRET = process.env.API_SECRET || 'dragonsteel_secret_key_123';

// Middleware
app.use(express.json());

// Karena index.html ada di root, gunakan folder saat ini (.) untuk file statis
app.use(express.static(__dirname));

// Route explicit untuk root URL (/)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Konfigurasi Database PostgreSQL (Neon / External)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Inisialisasi Tabel di PostgreSQL secara otomatis saat server berjalan
async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS licenses (
                id SERIAL PRIMARY KEY,
                license_key VARCHAR(255) UNIQUE NOT NULL,
                owner_name VARCHAR(255) NOT NULL,
                product_name VARCHAR(100) DEFAULT 'General Product',
                is_active BOOLEAN DEFAULT TRUE,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('Database table "licenses" verified/created successfully.');
    } catch (err) {
        console.error('Error initializing database table:', err.message);
    }
}
initDB();

// ==========================================
// API ROUTES
// ==========================================

// 1. Verify Client Hub (Buyer View)
app.post('/api/verify', async (req, res) => {
    const { owner_name } = req.body;
    if (!owner_name) {
        return res.status(400).json({ success: false, message: 'Username wajib diisi!' });
    }

    try {
        const query = `SELECT product_name as product, is_active, expires_at FROM licenses WHERE LOWER(owner_name) = LOWER($1) AND is_active = TRUE`;
        const { rows } = await pool.query(query, [owner_name.trim()]);
        
        if (rows && rows.length > 0) {
            return res.json({
                success: true,
                multi: true,
                data: rows
            });
        } else {
            return res.status(404).json({ success: false, message: 'Lisensi tidak ditemukan' });
        }
    } catch (err) {
        console.error('Database query error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
    }
});

// 2. Roblox Script Verification Endpoint
app.post('/api/game-verify', async (req, res) => {
    const { owner_name, product_name } = req.body;
    
    if (!owner_name) {
        return res.status(400).json({ success: false, authorized: false, message: 'Missing owner_name' });
    }

    try {
        let query = `SELECT * FROM licenses WHERE LOWER(owner_name) = LOWER($1) AND is_active = TRUE`;
        let params = [owner_name.trim()];

        if (product_name) {
            query += ` AND LOWER(product_name) = LOWER($2)`;
            params.push(product_name.trim());
        }

        const { rows } = await pool.query(query, params);
        if (!rows || rows.length === 0) {
            return res.json({ success: true, authorized: false, message: 'No active license found for this user.' });
        }

        const now = new Date();
        const validLicenses = rows.filter(row => {
            if (!row.expires_at) return true;
            return new Date(row.expires_at) > now;
        });

        if (validLicenses.length === 0) {
            return res.json({ success: true, authorized: false, message: 'Licenses expired.' });
        }

        return res.json({
            success: true,
            authorized: true,
            message: 'Access granted!',
            products: validLicenses.map(l => l.product_name)
        });
    } catch (err) {
        return res.status(500).json({ success: false, authorized: false, message: 'Server error' });
    }
});

// Middleware untuk Proteksi Admin API
function verifyAdminSecret(req, res, next) {
    const secret = req.headers['x-api-secret'];
    if (!secret || secret !== API_SECRET) {
        return res.status(401).json({ success: false, message: 'Unauthorized: Invalid API Secret' });
    }
    next();
}

// 3. Get All Licenses (Admin Only)
app.get('/api/licenses', verifyAdminSecret, async (req, res) => {
    try {
        const { rows } = await pool.query(`SELECT * FROM licenses ORDER BY created_at DESC`);
        res.json({ success: true, licenses: rows });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// 4. Create New License (Admin Only)
app.post('/api/licenses/create', verifyAdminSecret, async (req, res) => {
    const { license_key, owner_name, product_name, expires_at } = req.body;

    if (!license_key || !owner_name) {
        return res.status(400).json({ success: false, message: 'License key and owner name are required' });
    }

    try {
        const query = `INSERT INTO licenses (license_key, owner_name, product_name, expires_at) VALUES ($1, $2, $3, $4) RETURNING id`;
        const values = [
            license_key.trim(), 
            owner_name.trim(), 
            product_name ? product_name.trim() : 'General Product', 
            expires_at || null
        ];
        
        const { rows } = await pool.query(query, values);
        res.json({ success: true, message: 'Lisensi berhasil dibuat!', id: rows[0].id });
    } catch (err) {
        console.error('Insert error:', err);
        res.status(400).json({ success: false, message: 'Key sudah terdaftar atau terjadi kesalahan database.' });
    }
});

// Start Server
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`Dragonsteel Studio Server berjalan di port ${PORT}`);
    });
}

module.exports = app;
