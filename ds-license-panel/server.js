const express = require('express');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const API_SECRET = process.env.API_SECRET || 'dragonsteel_secret_key_123';

app.use(express.json());
app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS licenses (
                id SERIAL PRIMARY KEY,
                license_key VARCHAR(255) UNIQUE NOT NULL,
                owner_name VARCHAR(255) NOT NULL,
                product_name VARCHAR(100) DEFAULT 'General Product',
                image_url TEXT,
                download_url TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
    } catch (err) {
        console.error('Error init DB:', err.message);
    }
}
initDB();

async function getRobloxUserInfo(username) {
    try {
        const userRes = await fetch('https://users.roblox.com/v1/usernames/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usernames: [username], excludeBannedUsers: true })
        });
        if (!userRes.ok) return null;
        const userData = await userRes.json();
        if (!userData || !userData.data || userData.data.length === 0) return null;

        const userId = userData.data[0].id;
        const exactUsername = userData.data[0].name;

        const thumbRes = await fetch(`https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${userId}&size=150x150&format=Png&isCircular=false`);
        if (!thumbRes.ok) return { userId, exactUsername, avatarUrl: null };
        const thumbData = await thumbRes.json();
        
        let avatarUrl = null;
        if (thumbData && thumbData.data && thumbData.data.length > 0) {
            avatarUrl = thumbData.data[0].imageUrl;
        }

        return { userId, exactUsername, avatarUrl };
    } catch (err) {
        console.error('Error Roblox API:', err);
        return null;
    }
}

app.post('/api/client-login', async (req, res) => {
    const { owner_name, license_key } = req.body;
    if (!owner_name || !license_key) {
        return res.status(400).json({ success: false, message: 'Username dan License Key wajib diisi!' });
    }

    const trimmedUsername = owner_name.trim();
    const trimmedKey = license_key.trim();

    const robloxInfo = await getRobloxUserInfo(trimmedUsername);
    if (!robloxInfo || robloxInfo.exactUsername !== trimmedUsername) {
        return res.status(404).json({ success: false, message: 'Akun Roblox tidak ditemukan atau penulisan huruf tidak sesuai!' });
    }

    try {
        const checkQuery = `SELECT * FROM licenses WHERE owner_name = $1 AND license_key = $2 AND is_active = TRUE`;
        const checkRes = await pool.query(checkQuery, [trimmedUsername, trimmedKey]);
        
        if (checkRes.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'License Key salah atau tidak terdaftar untuk akun ini!' });
        }

        const allProductsQuery = `SELECT product_name as product, image_url, download_url, is_active, expires_at FROM licenses WHERE owner_name = $1 AND is_active = TRUE`;
        const { rows } = await pool.query(allProductsQuery, [trimmedUsername]);

        return res.json({
            success: true,
            avatar_url: robloxInfo.avatarUrl,
            data: rows
        });
    } catch (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Server database error.' });
    }
});

app.post('/api/client-refresh', async (req, res) => {
    const { owner_name } = req.body;
    if (!owner_name) return res.status(400).json({ success: false });

    try {
        const robloxInfo = await getRobloxUserInfo(owner_name.trim());
        const query = `SELECT product_name as product, image_url, download_url, is_active, expires_at FROM licenses WHERE owner_name = $1 AND is_active = TRUE`;
        const { rows } = await pool.query(query, [owner_name.trim()]);
        
        return res.json({
            success: true,
            avatar_url: robloxInfo ? robloxInfo.avatarUrl : null,
            data: rows
        });
    } catch (err) {
        return res.status(500).json({ success: false });
    }
});

app.post('/api/game-verify', async (req, res) => {
    const { owner_name, product_name } = req.body;
    if (!owner_name) {
        return res.status(400).json({ success: false, authorized: false, message: 'Missing owner_name' });
    }

    const trimmedUsername = owner_name.trim();
    const robloxInfo = await getRobloxUserInfo(trimmedUsername);
    if (!robloxInfo || robloxInfo.exactUsername !== trimmedUsername) {
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
            return res.json({ success: true, authorized: false, message: 'No active license found.' });
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

function verifyAdminSecret(req, res, next) {
    const secret = req.headers['x-api-secret'];
    if (!secret || secret !== API_SECRET) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    next();
}

app.get('/api/licenses', verifyAdminSecret, async (req, res) => {
    try {
        const { rows } = await pool.query(`SELECT * FROM licenses ORDER BY created_at DESC`);
        res.json({ success: true, licenses: rows });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/licenses/create', verifyAdminSecret, async (req, res) => {
    const { license_key, owner_name, product_name, image_url, download_url, expires_at } = req.body;
    if (!license_key || !owner_name) {
        return res.status(400).json({ success: false, message: 'Key and owner are required' });
    }

    const robloxInfo = await getRobloxUserInfo(owner_name.trim());
    if (!robloxInfo) {
        return res.status(400).json({ success: false, message: 'Username Roblox tidak valid di server Roblox!' });
    }

    try {
        const query = `INSERT INTO licenses (license_key, owner_name, product_name, image_url, download_url, expires_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`;
        const values = [
            license_key.trim(), 
            robloxInfo.exactUsername, 
            product_name ? product_name.trim() : 'General Product', 
            image_url ? image_url.trim() : null,
            download_url ? download_url.trim() : null,
            expires_at || null
        ];
        
        const { rows } = await pool.query(query, values);
        res.json({ success: true, message: 'Lisensi berhasil dibuat!', id: rows[0].id });
    } catch (err) {
        res.status(400).json({ success: false, message: 'Key sudah terdaftar.' });
    }
});

app.delete('/api/licenses/:id', verifyAdminSecret, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM licenses WHERE id = $1', [id]);
        res.json({ success: true, message: 'Lisensi berhasil dihapus.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Gagal menghapus.' });
    }
});

if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => console.log(`Running on port ${PORT}`));
}

module.exports = app;
