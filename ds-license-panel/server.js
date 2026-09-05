const express = require('express');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const API_SECRET = process.env.API_SECRET || 'dragonsteel_secret_key_123';

// Middleware
app.use(express.json());
app.use(express.static(__dirname));

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

// Inisialisasi Tabel di PostgreSQL secara otomatis
async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS licenses (
                id SERIAL PRIMARY KEY,
                license_key VARCHAR(255) UNIQUE NOT NULL,
                owner_name VARCHAR(255) NOT NULL,
                product_name VARCHAR(100) DEFAULT 'General Product',
                image_url TEXT,
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

// Fungsi helper untuk memvalidasi apakah username benar-benar ada di Roblox
async function checkRobloxUserExists(username) {
    try {
        const response = await fetch('https://users.roblox.com/v1/usernames/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                usernames: [username],
                excludeBannedUsers: true
            })
        });
        
        if (!response.ok) return false;
        const data = await response.json();
        
        if (data && data.data && data.data.length > 0) {
            return true;
        }
        return false;
    } catch (err) {
        console.error('Gagal memvalidasi ke API Roblox:', err);
        return false;
    }
}

// ==========================================
// API ROUTES
// ==========================================

// 1. Verify Client Hub (Buyer View) - Exact Case Match
app.post('/api/verify', async (req, res) => {
    const { owner_name } = req.body;
    if (!owner_name) {
        return res.status(400).json({ success: false, message: 'Username wajib diisi!' });
    }

    const trimmedUsername = owner_name.trim();

    // Validasi ke server Roblox
    const isValidRobloxUser = await checkRobloxUserExists(trimmedUsername);
    if (!isValidRobloxUser) {
        return res.status(404).json({ success: false, message: 'Akun Roblox tidak ditemukan atau tidak valid di platform Roblox!' });
    }

    // Pencarian di Database dengan pencocokan PERSIS (Case-Sensitive, menggunakan operator = biasa tanpa LOWER)
    try {
        const query = `SELECT product_name as product, image_url, is_active, expires_at FROM licenses WHERE owner_name = $1 AND is_active = TRUE`;
        const { rows } = await pool.query(query, [trimmedUsername]);
        
        if (rows && rows.length > 0) {
            return res.json({
                success: true,
                multi: true,
                data: rows
            });
        } else {
            return res.status(404).json({ success: false, message: 'Akun Roblox valid, tetapi penulisan huruf besar/kecil tidak cocok dengan database.' });
        }
    } catch (err) {
        console.error('Database query error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
    }
});

// 2. Roblox Script Verification Endpoint (Untuk Game / HttpService) - Exact Case Match
app.post('/api/game-verify', async (req, res) => {
    const { owner_name, product_name } = req.body;
    
    if (!owner_name) {
        return res.status(400).json({ success: false, authorized: false, message: 'Missing owner_name' });
    }

    const trimmedUsername = owner_name.trim();

    const isValidRobloxUser = await checkRobloxUserExists(trimmedUsername);
    if (!isValidRobloxUser) {
        return res.json({ success: true, authorized: false, message: 'Invalid Roblox account.' });
    }

    try {
        let query = `SELECT * FROM licenses WHERE owner_name = $1 AND is_active = TRUE`;
        let params = [trimmedUsername];

        if (product_name) {
            query += ` AND product_name = $2`;
            params.push(product_name.trim());
        }

        const { rows } = await pool.query(query, params);
        if (!rows || rows.length === 0) {
            return res.json({ success: true, authorized: false, message: 'No active license found with exact case match.' });
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
    const { license_key, owner_name, product_name, image_url, expires_at } = req.body;

    if (!license_key || !owner_name) {
        return res.status(400).json({ success: false, message: 'License key and owner name are required' });
    }

    try {
        const query = `INSERT INTO licenses (license_key, owner_name, product_name, image_url, expires_at) VALUES ($1, $2, $3, $4, $5) RETURNING id`;
        const values = [
            license_key.trim(), 
            owner_name.trim(), 
            product_name ? product_name.trim() : 'General Product', 
            image_url ? image_url.trim() : null,
            expires_at || null
        ];
        
        const { rows } = await pool.query(query, values);
        res.json({ success: true, message: 'Lisensi berhasil dibuat!', id: rows[0].id });
    } catch (err) {
        console.error('Insert error:', err);
        res.status(400).json({ success: false, message: 'Key sudah terdaftar atau terjadi kesalahan database.' });
    }
});

// 5. Delete License (Admin Only)
app.delete('/api/licenses/:id', verifyAdminSecret, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM licenses WHERE id = $1', [id]);
        res.json({ success: true, message: 'Lisensi berhasil dihapus.' });
    } catch (err) {
        console.error('Delete error:', err);
        res.status(500).json({ success: false, message: 'Gagal menghapus lisensi dari database.' });
    }
});

// Start Server
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`Dragonsteel Studio Server berjalan di port ${PORT}`);
    });
}

module.exports = app;
