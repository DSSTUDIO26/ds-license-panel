const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const API_SECRET = process.env.API_SECRET || 'dragonsteel_secret_key_123';

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database Setup
const dbPath = path.join(__dirname, 'database.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('Error opening database', err.message);
    else console.log('Connected to SQLite database.');
});

// Initialize Tables
db.run(`CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT UNIQUE NOT NULL,
    owner_name TEXT NOT NULL,
    product_name TEXT DEFAULT 'General Product',
    is_active INTEGER DEFAULT 1,
    expires_at TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// ==========================================
// API ROUTES
// ==========================================

// 1. Verify Client Hub (Buyer View) - Mengembalikan semua produk milik username tanpa menampilkan key
app.post('/api/verify', (req, res) => {
    const { owner_name } = req.body;
    if (!owner_name) {
        return res.status(400).json({ success: false, message: 'Username wajib diisi!' });
    }

    const query = `SELECT product_name as product, is_active, expires_at FROM licenses WHERE LOWER(owner_name) = LOWER(?) AND is_active = 1`;
    
    db.all(query, [owner_name.trim()], (err, rows) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Database error' });
        }
        
        if (rows && rows.length > 0) {
            // Mengirimkan array data karena satu user bisa punya banyak produk
            return res.json({
                success: true,
                multi: true,
                data: rows
            });
        } else {
            return res.status(404).json({ success: false, message: 'Lisensi tidak ditemukan' });
        }
    });
});

// 2. Roblox Script Verification Endpoint (Untuk di-fetch di dalam game Roblox Studio)
// Game cukup mengirimkan username Roblox pemain untuk verifikasi akses otomatis tanpa key
app.post('/api/game-verify', (req, res) => {
    const { owner_name, product_name } = req.body;
    
    if (!owner_name) {
        return res.status(400).json({ success: false, authorized: false, message: 'Missing owner_name' });
    }

    let query = `SELECT * FROM licenses WHERE LOWER(owner_name) = LOWER(?) AND is_active = 1`;
    let params = [owner_name.trim()];

    if (product_name) {
        query += ` AND LOWER(product_name) = LOWER(?)`;
        params.push(product_name.trim());
    }

    db.all(query, params, (err, rows) => {
        if (err || !rows || rows.length === 0) {
            return res.json({ success: true, authorized: false, message: 'No active license found for this user.' });
        }

        // Cek masa kedaluwarsa (expires_at) jika ada
        const now = new Date();
        const validLicenses = rows.filter(row => {
            if (!row.expires_at) return true; // Permanent
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
    });
});

// Middleware untuk proteksi Admin API
function verifyAdminSecret(req, res, next) {
    const secret = req.headers['x-api-secret'];
    if (!secret || secret !== API_SECRET) {
        return res.status(401).json({ success: false, message: 'Unauthorized: Invalid API Secret' });
    }
    next();
}

// 3. Get All Licenses (Admin Only)
app.get('/api/licenses', verifyAdminSecret, (req, res) => {
    db.all(`SELECT * FROM licenses ORDER BY created_at DESC`, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ success: false, message: err.message });
        }
        res.json({ success: true, licenses: rows });
    });
});

// 4. Create New License (Admin Only)
app.post('/api/licenses/create', verifyAdminSecret, (req, res) => {
    const { license_key, owner_name, product_name, expires_at } = req.body;

    if (!license_key || !owner_name) {
        return res.status(400).json({ success: false, message: 'License key and owner name are required' });
    }

    const query = `INSERT INTO licenses (license_key, owner_name, product_name, expires_at) VALUES (?, ?, ?, ?)`;
    db.run(query, [license_key.trim(), owner_name.trim(), product_name ? product_name.trim() : 'General Product', expires_at || null], function(err) {
        if (err) {
            return res.status(400).json({ success: false, message: 'Key sudah terdaftar atau terjadi kesalahan database.' });
        }
        res.json({ success: true, message: 'Lisensi berhasil dibuat!', id: this.lastID });
    });
});

// Start Server
app.listen(PORT, () => {
    console.log(`Dragonsteel Studio Server berjalan di port ${PORT}`);
});
