// DSS STUDIO LICENSE — Node.js + PostgreSQL
// Requires Node.js 18+
// Environment: DATABASE_URL, API_SECRET (32+ chars), PORT (optional), NODE_ENV=production

'use strict';
const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '32kb' }));
app.use(express.static(__dirname, { index: false, maxAge: '1h' }));

const PORT = Number(process.env.PORT || 3000);
const API_SECRET = process.env.API_SECRET || '';
const DATABASE_URL = process.env.DATABASE_URL || '';

if (API_SECRET.length < 32) {
  console.error('FATAL: Set API_SECRET to a random secret with at least 32 characters.');
  process.exit(1);
}
if (!DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is required.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'DSS STUDIO LICENSE' });
  } catch {
    res.status(503).json({ ok: false });
  }
});

function timingSafeEqualText(a, b) {
  const aa = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function verifyAdminSecret(req, res, next) {
  if (!timingSafeEqualText(req.get('x-api-secret'), API_SECRET)) {
    return res.status(401).json({ success: false, message: 'API Secret tidak valid.' });
  }
  next();
}
function cleanText(value, max = 255) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, max);
}
function validHttpUrl(value) {
  if (value == null || value === '') return null;
  try {
    const u = new URL(value);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return undefined;
    return u.toString();
  } catch { return undefined; }
}
function validExpiry(value) {
  if (value == null || value === '') return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

async function robloxFetch(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    if (!response.ok) throw new Error(`Roblox API HTTP ${response.status}`);
    return await response.json();
  } finally { clearTimeout(timer); }
}
async function getRobloxUserInfo(username) {
  const result = await robloxFetch('https://users.roblox.com/v1/usernames/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ usernames: [username], excludeBannedUsers: false })
  });
  const user = result?.data?.[0];
  if (!user || user.name.toLowerCase() !== username.toLowerCase()) return null;
  let avatarUrl = null;
  try {
    const thumbs = await robloxFetch(`https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${user.id}&size=150x150&format=Png&isCircular=false`);
    avatarUrl = thumbs?.data?.[0]?.imageUrl || null;
  } catch {}
  return { userId: String(user.id), exactUsername: user.name, avatarUrl };
}
async function getPlaceCreator(placeId) {
  if (!/^\d{1,20}$/.test(String(placeId || ''))) {
    const error = new Error('place_id tidak valid'); error.statusCode = 400; throw error;
  }
  const placeInfo = await robloxFetch(`https://apis.roblox.com/universes/v1/places/${encodeURIComponent(placeId)}/universe`);
  const universeId = placeInfo?.universeId;
  if (!universeId) throw new Error('Roblox tidak mengembalikan Universe ID.');
  const gameInfo = await robloxFetch(`https://games.roblox.com/v1/games?universeIds=${encodeURIComponent(universeId)}`);
  const game = gameInfo?.data?.[0];
  if (!game?.creator) throw new Error('Data pemilik game tidak ditemukan.');
  return {
    placeId: String(placeId),
    universeId: String(universeId),
    creatorType: game.creator.type,
    creatorId: String(game.creator.id),
    creatorName: game.creator.name || ''
  };
}

// Database migration is intentionally additive to preserve existing license rows.
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id BIGSERIAL PRIMARY KEY,
      product_code VARCHAR(80) UNIQUE NOT NULL,
      product_name VARCHAR(120) NOT NULL UNIQUE,
      description TEXT,
      image_url TEXT,
      download_url TEXT,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS licenses (
      id BIGSERIAL PRIMARY KEY,
      license_key VARCHAR(255) UNIQUE NOT NULL,
      owner_name VARCHAR(255) NOT NULL,
      owner_user_id VARCHAR(32),
      group_id VARCHAR(32),
      product_name VARCHAR(120) DEFAULT 'General Product',
      image_url TEXT,
      download_url TEXT,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS owner_user_id VARCHAR(32);
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS group_id VARCHAR(32);
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS product_name VARCHAR(120) DEFAULT 'General Product';
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS image_url TEXT;
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS download_url TEXT;
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
    CREATE TABLE IF NOT EXISTS license_products (
      license_id BIGINT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
      product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
      PRIMARY KEY (license_id, product_id)
    );
    CREATE INDEX IF NOT EXISTS idx_licenses_owner_user_id ON licenses(owner_user_id);
    CREATE INDEX IF NOT EXISTS idx_licenses_group_id ON licenses(group_id);
    CREATE INDEX IF NOT EXISTS idx_licenses_active_expiry ON licenses(is_active, expires_at);
    CREATE INDEX IF NOT EXISTS idx_license_products_product_id ON license_products(product_id);
  `);

  // Migrate products from the legacy product_name column and connect them to their old license rows.
  const legacy = await pool.query(`
    SELECT DISTINCT COALESCE(NULLIF(BTRIM(product_name), ''), 'DSS STUDIO LICENSE') AS product_name,
           MAX(image_url) AS image_url, MAX(download_url) AS download_url
    FROM licenses GROUP BY COALESCE(NULLIF(BTRIM(product_name), ''), 'DSS STUDIO LICENSE')
  `);
  for (const row of legacy.rows) {
    const name = row.product_name;
    const code = name.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 70) || `PRODUCT_${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    await pool.query(`
      INSERT INTO products (product_code, product_name, image_url, download_url)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (product_name) DO NOTHING
    `, [code, name, row.image_url, row.download_url]);
  }
  await pool.query(`
    INSERT INTO license_products (license_id, product_id)
    SELECT l.id, p.id
    FROM licenses l JOIN products p
      ON p.product_name = COALESCE(NULLIF(BTRIM(l.product_name), ''), 'DSS STUDIO LICENSE')
    ON CONFLICT DO NOTHING
  `);
  // Backfill Roblox user IDs for old personal licenses when possible; never blocks startup.
  const oldOwners = await pool.query(`SELECT id, owner_name FROM licenses WHERE group_id IS NULL AND owner_user_id IS NULL LIMIT 100`);
  for (const row of oldOwners.rows) {
    try {
      const user = await getRobloxUserInfo(row.owner_name);
      if (user) await pool.query('UPDATE licenses SET owner_user_id=$1, owner_name=$2 WHERE id=$3', [user.userId, user.exactUsername, row.id]);
    } catch (e) { console.warn('Owner ID migration deferred for license', row.id); }
  }
  console.log('PostgreSQL schema ready.');
}

async function listLicenseProducts(licenseId) {
  const { rows } = await pool.query(`
    SELECT p.id, p.product_code, p.product_name, p.description, p.image_url,
           p.download_url, p.is_active AS product_active
    FROM license_products lp JOIN products p ON p.id=lp.product_id
    WHERE lp.license_id=$1 ORDER BY p.product_name
  `, [licenseId]);
  return rows;
}

// Client portal login: a key is required on every refresh, and personal licenses are bound to Roblox UserId.
app.post('/api/client-login', async (req, res) => {
  const username = cleanText(req.body?.owner_name, 64);
  const key = cleanText(req.body?.license_key, 255);
  if (!username || !key) return res.status(400).json({ success: false, message: 'Username Roblox dan License Key wajib diisi.' });
  try {
    const user = await getRobloxUserInfo(username);
    if (!user) return res.status(404).json({ success: false, message: 'Username Roblox tidak ditemukan.' });
    const { rows } = await pool.query(`
      SELECT l.* FROM licenses l
      WHERE l.license_key=$1 AND l.is_active=TRUE
        AND (l.expires_at IS NULL OR l.expires_at > NOW())
        AND ((l.group_id IS NULL AND l.owner_user_id=$2)
          OR (l.group_id IS NOT NULL))
      LIMIT 1
    `, [key, user.userId]);
    if (!rows.length) return res.status(401).json({ success: false, message: 'Key salah, tidak aktif, kedaluwarsa, atau bukan milik akun ini.' });
    const license = rows[0];
    const products = await listLicenseProducts(license.id);
    return res.json({
      success: true, avatar_url: user.avatarUrl, owner_name: user.exactUsername,
      owner_user_id: user.userId, license: { id: license.id, license_key: license.license_key, expires_at: license.expires_at, is_active: license.is_active, group_id: license.group_id },
      data: products.filter(p => p.product_active).map(p => ({
        product: p.product_name, product_code: p.product_code, image_url: p.image_url,
        download_url: p.download_url, expires_at: license.expires_at, is_active: license.is_active
      }))
    });
  } catch (err) {
    console.error('client-login:', err.message);
    return res.status(502).json({ success: false, message: 'Gagal menghubungi Roblox atau database. Coba lagi.' });
  }
});
app.post('/api/client-refresh', async (req, res) => {
  const username = cleanText(req.body?.owner_name, 64);
  const key = cleanText(req.body?.license_key, 255);
  if (!username || !key) return res.status(400).json({ success: false, message: 'Login ulang diperlukan.' });
  // Reuse the exact same ownership/key validation as login; no username-only product enumeration.
  try {
    const user = await getRobloxUserInfo(username);
    if (!user) return res.status(404).json({ success: false, message: 'Username Roblox tidak ditemukan.' });
    const { rows } = await pool.query(`
      SELECT l.* FROM licenses l
      WHERE l.license_key=$1 AND l.is_active=TRUE
        AND (l.expires_at IS NULL OR l.expires_at > NOW())
        AND ((l.group_id IS NULL AND l.owner_user_id=$2) OR l.group_id IS NOT NULL)
      LIMIT 1
    `, [key, user.userId]);
    if (!rows.length) return res.status(401).json({ success: false, message: 'Lisensi tidak valid atau kedaluwarsa.' });
    const license = rows[0];
    const products = (await listLicenseProducts(license.id)).filter(p => p.product_active);
    res.json({ success: true, avatar_url: user.avatarUrl, owner_name: user.exactUsername,
      license: { id: license.id, expires_at: license.expires_at, is_active: license.is_active, group_id: license.group_id },
      data: products.map(p => ({ product: p.product_name, product_code: p.product_code, image_url: p.image_url, download_url: p.download_url, expires_at: license.expires_at, is_active: license.is_active })) });
  } catch (err) {
    console.error('client-refresh:', err.message);
    res.status(502).json({ success: false, message: 'Gagal memperbarui data. Coba lagi.' });
  }
});

// Authoritative game check: verifies real Roblox creator using PlaceId and requires product membership.
app.post('/api/game-verify', async (req, res) => {
  const placeId = cleanText(String(req.body?.place_id ?? ''), 24);
  const productName = cleanText(req.body?.product_name, 120);
  if (!placeId || !productName) return res.status(400).json({ success: true, authorized: false, code: 'BAD_REQUEST', message: 'place_id dan product_name wajib.' });
  try {
    const creator = await getPlaceCreator(placeId);
    const isGroup = String(creator.creatorType).toLowerCase() === 'group';
    const { rows } = await pool.query(`
      SELECT l.id, l.owner_name, l.owner_user_id, l.group_id, l.expires_at,
             p.product_name, p.product_code
      FROM licenses l
      JOIN license_products lp ON lp.license_id=l.id
      JOIN products p ON p.id=lp.product_id
      WHERE l.is_active=TRUE AND p.is_active=TRUE
        AND (l.expires_at IS NULL OR l.expires_at > NOW())
        AND p.product_name=$1
        AND (($2::boolean=TRUE AND l.group_id=$3)
          OR ($2::boolean=FALSE AND l.group_id IS NULL AND l.owner_user_id=$3))
      ORDER BY l.created_at DESC LIMIT 1
    `, [productName, isGroup, creator.creatorId]);
    if (!rows.length) {
      return res.json({ success: true, authorized: false, code: 'NOT_LICENSED', message: 'Tidak ada lisensi aktif untuk produk ini dan pemilik experience ini.', creator });
    }
    return res.json({ success: true, authorized: true, code: 'AUTHORIZED', message: 'Lisensi valid.',
      product_name: rows[0].product_name, product_code: rows[0].product_code, place_id: creator.placeId,
      universe_id: creator.universeId, creator_type: creator.creatorType, creator_id: creator.creatorId,
      expires_at: rows[0].expires_at });
  } catch (err) {
    console.error('game-verify:', err.message);
    const status = err.statusCode || 503;
    return res.status(status).json({ success: false, authorized: false, code: 'VERIFY_UNAVAILABLE', message: 'Verifikasi Roblox sementara tidak tersedia.' });
  }
});

// Admin: product catalog.
app.get('/api/products', verifyAdminSecret, async (_req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM products ORDER BY product_name');
    res.json({ success: true, products: rows });
  } catch (err) { res.status(500).json({ success: false, message: 'Gagal membaca katalog.' }); }
});
app.post('/api/products', verifyAdminSecret, async (req, res) => {
  const name = cleanText(req.body?.product_name, 120);
  const description = cleanText(req.body?.description, 1000);
  const image = validHttpUrl(req.body?.image_url);
  const download = validHttpUrl(req.body?.download_url);
  if (!name) return res.status(400).json({ success: false, message: 'Nama produk wajib diisi.' });
  if (image === undefined || download === undefined) return res.status(400).json({ success: false, message: 'URL harus berupa HTTP/HTTPS yang valid.' });
  const code = cleanText(req.body?.product_code, 80).toUpperCase() ||
    name.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 70);
  if (!code) return res.status(400).json({ success: false, message: 'Kode produk tidak valid.' });
  try {
    const { rows } = await pool.query(`INSERT INTO products(product_code,product_name,description,image_url,download_url)
      VALUES($1,$2,$3,$4,$5) RETURNING *`, [code, name, description || null, image, download]);
    res.status(201).json({ success: true, product: rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ success: false, message: 'Kode atau nama produk sudah digunakan.' });
    res.status(500).json({ success: false, message: 'Gagal membuat produk.' });
  }
});
app.patch('/api/products/:id', verifyAdminSecret, async (req, res) => {
  const id = cleanText(req.params.id, 20);
  const active = req.body?.is_active;
  if (!/^\d+$/.test(id) || typeof active !== 'boolean') return res.status(400).json({ success: false, message: 'ID atau status tidak valid.' });
  try {
    const { rows } = await pool.query('UPDATE products SET is_active=$1, updated_at=NOW() WHERE id=$2 RETURNING *', [active, id]);
    if (!rows.length) return res.status(404).json({ success: false, message: 'Produk tidak ditemukan.' });
    res.json({ success: true, product: rows[0] });
  } catch { res.status(500).json({ success: false, message: 'Gagal memperbarui produk.' }); }
});

// Admin: each license is either a single product or a package, represented by product_ids.
app.get('/api/licenses', verifyAdminSecret, async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT l.*,
        COALESCE(json_agg(json_build_object('id',p.id,'product_code',p.product_code,'product_name',p.product_name,'is_active',p.is_active))
          FILTER (WHERE p.id IS NOT NULL), '[]'::json) AS products
      FROM licenses l
      LEFT JOIN license_products lp ON lp.license_id=l.id
      LEFT JOIN products p ON p.id=lp.product_id
      GROUP BY l.id ORDER BY l.created_at DESC
    `);
    res.json({ success: true, licenses: rows });
  } catch (err) { console.error(err.message); res.status(500).json({ success: false, message: 'Gagal membaca lisensi.' }); }
});
app.post('/api/licenses/create', verifyAdminSecret, async (req, res) => {
  const key = cleanText(req.body?.license_key, 255);
  const ownerNameInput = cleanText(req.body?.owner_name, 64);
  const groupId = cleanText(String(req.body?.group_id ?? ''), 32) || null;
  const productIds = Array.isArray(req.body?.product_ids) ? [...new Set(req.body.product_ids.map(String))] : [];
  const expiresAt = validExpiry(req.body?.expires_at);
  const imageUrl = validHttpUrl(req.body?.image_url);
  const downloadUrl = validHttpUrl(req.body?.download_url);
  if (!key) return res.status(400).json({ success: false, message: 'License key wajib diisi.' });
  if (!productIds.length || productIds.length > 50 || productIds.some(id => !/^\d+$/.test(id))) {
    return res.status(400).json({ success: false, message: 'Pilih minimal satu produk (maksimal 50).' });
  }
  if (expiresAt === undefined) return res.status(400).json({ success: false, message: 'Tanggal kedaluwarsa tidak valid.' });
  if (imageUrl === undefined || downloadUrl === undefined) return res.status(400).json({ success: false, message: 'URL gambar/download tidak valid.' });
  if (groupId && !/^\d+$/.test(groupId)) return res.status(400).json({ success: false, message: 'Group ID harus angka.' });
  if (!groupId && !ownerNameInput) return res.status(400).json({ success: false, message: 'Username pemilik wajib diisi.' });
  let user = null;
  if (!groupId) {
    try { user = await getRobloxUserInfo(ownerNameInput); }
    catch { return res.status(502).json({ success: false, message: 'Roblox API tidak tersedia, coba lagi.' }); }
    if (!user) return res.status(400).json({ success: false, message: 'Username Roblox tidak valid.' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const productCheck = await client.query('SELECT id FROM products WHERE is_active=TRUE AND id=ANY($1::bigint[])', [productIds]);
    if (productCheck.rows.length !== productIds.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, message: 'Ada produk tidak ditemukan atau nonaktif.' });
    }
    const { rows } = await client.query(`
      INSERT INTO licenses(license_key,owner_name,owner_user_id,group_id,product_name,image_url,download_url,expires_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id
    `, [key, groupId ? 'COMMUNITY_GROUP' : user.exactUsername, groupId ? null : user.userId, groupId,
        'DSS STUDIO LICENSE', imageUrl, downloadUrl, expiresAt]);
    const licenseId = rows[0].id;
    for (const productId of productIds) {
      await client.query('INSERT INTO license_products(license_id,product_id) VALUES($1,$2)', [licenseId, productId]);
    }
    await client.query('COMMIT');
    res.status(201).json({ success: true, message: 'Lisensi/paket berhasil dibuat.', id: licenseId, product_count: productIds.length });
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') return res.status(409).json({ success: false, message: 'License Key sudah digunakan.' });
    console.error('create license:', err.message);
    res.status(500).json({ success: false, message: 'Gagal membuat lisensi.' });
  } finally { client.release(); }
});
app.patch('/api/licenses/:id/status', verifyAdminSecret, async (req, res) => {
  const id = cleanText(req.params.id, 20);
  if (!/^\d+$/.test(id) || typeof req.body?.is_active !== 'boolean') return res.status(400).json({ success: false, message: 'ID/status tidak valid.' });
  try {
    const { rows } = await pool.query('UPDATE licenses SET is_active=$1 WHERE id=$2 RETURNING id,is_active', [req.body.is_active, id]);
    if (!rows.length) return res.status(404).json({ success: false, message: 'Lisensi tidak ditemukan.' });
    res.json({ success: true, license: rows[0] });
  } catch { res.status(500).json({ success: false, message: 'Gagal mengubah status.' }); }
});
app.delete('/api/licenses/:id', verifyAdminSecret, async (req, res) => {
  const id = cleanText(req.params.id, 20);
  if (!/^\d+$/.test(id)) return res.status(400).json({ success: false, message: 'ID tidak valid.' });
  try {
    const result = await pool.query('DELETE FROM licenses WHERE id=$1', [id]);
    if (!result.rowCount) return res.status(404).json({ success: false, message: 'Lisensi tidak ditemukan.' });
    res.json({ success: true, message: 'Lisensi berhasil dihapus.' });
  } catch { res.status(500).json({ success: false, message: 'Gagal menghapus lisensi.' }); }
});

let server;
initDB().then(() => {
  server = app.listen(PORT, '0.0.0.0', () => console.log(`DSS STUDIO LICENSE listening on ${PORT}`));
}).catch(err => {
  console.error('FATAL database initialization error:', err);
  process.exit(1);
});
async function shutdown() {
  if (server) server.close();
  await pool.end().catch(() => {});
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

module.exports = app;
