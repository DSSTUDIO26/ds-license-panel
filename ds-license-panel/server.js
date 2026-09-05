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
                group_id VARCHAR(100),
                product_name VARCHAR(100) DEFAULT 'General Product',
                image_url TEXT,
                download_url TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        // Otomatis tambahkan kolom group_id jika tabel lama sudah terlanjur dibuat tanpa kolom ini
        await pool.query(`ALTER TABLE licenses ADD COLUMN IF NOT EXISTS group_id VARCHAR(100);`);
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
        // Cek lisensi yang cocok dengan owner_name atau mencakup group_id milik owner tersebut
        const checkQuery = `SELECT * FROM licenses WHERE (owner_name = $1 OR group_id IS NOT NULL) AND license_key = $2 AND is_active = TRUE`;
        const checkRes = await pool.query(checkQuery, [trimmedUsername, trimmedKey]);
        
        if (checkRes.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'License Key salah atau tidak terdaftar!' });
        }

        const allProductsQuery = `SELECT product_name as product, image_url, download_url, is_active, expires_at, group_id FROM licenses WHERE (owner_name = $1 OR group_id IS NOT NULL) AND is_active = TRUE`;
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
        const trimmedUsername = owner_name.trim();
        const robloxInfo = await getRobloxUserInfo(trimmedUsername);
        const query = `SELECT product_name as product, image_url, download_url, is_active, expires_at, group_id FROM licenses WHERE (owner_name = $1 OR group_id IS NOT NULL) AND is_active = TRUE`;
        const { rows } = await pool.query(query, [trimmedUsername]);
        
        return res.json({
            success: true,
            avatar_url: robloxInfo ? robloxInfo.avatarUrl : null,
            data: rows
        });
    } catch (err) {
        return res.status(500).json({ success: false });
    }
});

// Endpoint Verifikasi dari Game Roblox secara Otomatis (Support Grup & Pribadi)
app.post('/api/game-verify', async (req, res) => {
    const { product_name, creator_type, creator_id } = req.body;
    
    if (!creator_id) {
        return res.status(400).json({ success: false, authorized: false, message: 'Missing creator_id' });
    }

    try {
        let query = '';
        let params = [];

        // Jika game dipublikasikan lewat Group Komunitas
        if (creator_type === 'Group') {
            query = `SELECT * FROM licenses WHERE group_id = $1 AND is_active = TRUE`;
            params = [String(creator_id)];
        } else {
            // Jika dipublikasikan lewat Akun Pribadi (User)
            query = `SELECT * FROM licenses WHERE group_id IS NULL AND is_active = TRUE`;
            params = [];
        }

        if (product_name) {
            query += (params.length > 0 ? ` AND` : ` WHERE`) + ` product_name = $${params.length + 1}`;
            params.push(product_name.trim());
        }

        const { rows } = await pool.query(query, params);
        if (!rows || rows.length === 0) {
            return res.json({ success: true, authorized: false, message: 'No active license found for this Creator ID.' });
        }

        const now = new Date();
        const validLicenses = rows.filter(row => {
            if (row.expires_at && new Date(row.expires_at) <= now) return false;
            return true;
        });

        if (validLicenses.length === 0) {
            return res.json({ success: true, authorized: false, message: 'License expired.' });
        }

        return res.json({
            success: true,
            authorized: true,
            message: 'Access granted!',
            products: validLicenses.map(l => l.product_name)
        });
    } catch (err) {
        console.error('Verify error:', err);
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
    const { license_key, owner_name, group_id, product_name, image_url, download_url, expires_at } = req.body;
    if (!license_key) {
        return res.status(400).json({ success: false, message: 'License key is required' });
    }

    let finalOwner = owner_name ? owner_name.trim() : "COMMUNITY_GROUP";
    let finalGroupId = group_id ? group_id.trim() : null;

    if (!finalGroupId && owner_name) {
        const robloxInfo = await getRobloxUserInfo(owner_name.trim());
        if (!robloxInfo) {
            return res.status(400).json({ success: false, message: 'Username Roblox tidak valid di server Roblox!' });
        }
        finalOwner = robloxInfo.exactUsername;
    }

    try {
        const query = `INSERT INTO licenses (license_key, owner_name, group_id, product_name, image_url, download_url, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`;
        const values = [
            license_key.trim(), 
            finalOwner, 
            finalGroupId,
            product_name ? product_name.trim() : 'General Product', 
            image_url ? image_url.trim() : null,
            download_url ? download_url.trim() : null,
            expires_at || null
        ];
        
        const { rows } = await pool.query(query, values);
        res.json({ success: true, message: 'Lisensi berhasil dibuat!', id: rows[0].id });
    } catch (err) {
        console.error(err);
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

