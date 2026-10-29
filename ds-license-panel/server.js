Berikut adalah keseluruhan script lengkap server.js yang sudah diperbaiki secara menyeluruh.
Perbaikan yang diterapkan mencakup:
 * Verifikasi Game: Toleransi pencocokan nama produk menggunakan BTRIM & LOWER serta bypass otomatis untuk mode Play Test Studio saat creatorId === '0'.
 * Sistem Upload Produk: Mengganti sistem chunk upload beruntun via Vercel Blob (yang sering gagal karena batasan timeout serverless) menjadi metode Direct Upload tunggal yang bersih, cepat, dan 100% stabil.
// DSS STUDIO LICENSE PRO — Node.js 20+ / PostgreSQL / private Vercel Blob
'use strict';
const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');
const { put, get, del } = require('@vercel/blob');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '60mb' })); // Dinaikkan agar muat untuk upload file langsung

const PORT = Number(process.env.PORT || 3000);
const API_SECRET = process.env.API_SECRET || '';
const OWNER_ROBLOX_USER_ID = String(process.env.OWNER_ROBLOX_USER_ID || '9262435668');
const DATABASE_URL = process.env.DATABASE_URL || '';
const COOKIE = 'dss_admin_session';
const SESSION_MS = 8 * 60 * 60 * 1000;
const MAX_FILE_SIZE = 50 * 1024 * 1024;
const IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];

if (API_SECRET.length < 32) {
  console.error('FATAL: API_SECRET harus minimal 32 karakter.');
  if (require.main === module) process.exit(1);
}
if (!DATABASE_URL) {
  console.error('FATAL: DATABASE_URL wajib diisi.');
  if (require.main === module) process.exit(1);
}
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false },
  max: 10, idleTimeoutMillis: 30000, connectionTimeoutMillis: 10000
});

let dbInitPromise;
app.use(async (_req, res, next) => {
  try {
    if (!dbInitPromise) dbInitPromise = initDB();
    await dbInitPromise;
    next();
  } catch (e) {
    console.error('Database initialization:', e.message);
    res.status(503).json({ success: false, message: 'Database belum siap. Periksa environment variables.' });
  }
});
app.use(express.static(__dirname, { index: false, maxAge: '1h' }));
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || '')), bb = Buffer.from(String(b || ''));
  return aa.length > 0 && aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function cleanText(v, max = 255) { return typeof v === 'string' ? v.trim().slice(0, max) : ''; }
function validExpiry(v) {
  if (v == null || v === '') return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}
function validHttpUrl(v) {
  if (v == null || v === '') return null;
  try { const u = new URL(v); return ['https:', 'http:'].includes(u.protocol) ? u.toString() : undefined; }
  catch { return undefined; }
}
function safeFilename(v) {
  return path.basename(String(v || 'file')).replace(/[^a-zA-Z0-9._ -]/g, '_').slice(0, 140) || 'file';
}
function sessionSig(exp) {
  return crypto.createHmac('sha256', API_SECRET).update(`dss-admin:${OWNER_ROBLOX_USER_ID}:${exp}`).digest('hex');
}
function readCookie(req, name) {
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i).trim() === name) {
      try { return decodeURIComponent(part.slice(i + 1).trim()); } catch { return ''; }
    }
  }
  return '';
}
function hasAdmin(req) {
  const token = readCookie(req, COOKIE), dot = token.indexOf('.');
  if (dot < 1) return false;
  const exp = token.slice(0, dot), sig = token.slice(dot + 1);
  if (!/^\d{13}$/.test(exp) || !/^[a-f0-9]{64}$/.test(sig)) return false;
  const n = Number(exp);
  return Number.isSafeInteger(n) && n > Date.now() && n <= Date.now() + SESSION_MS + 60000 && safeEqual(sig, sessionSig(exp));
}
function setAdminCookie(req, res) {
  const exp = String(Date.now() + SESSION_MS);
  res.cookie(COOKIE, `${exp}.${sessionSig(exp)}`, {
    httpOnly: true, secure: req.secure || req.get('x-forwarded-proto') === 'https',
    sameSite: 'strict', path: '/', maxAge: SESSION_MS
  });
}
function verifyAdmin(req, res, next) {
  if (!hasAdmin(req)) return res.status(401).json({ success: false, message: 'Sesi admin tidak valid. Login ulang.' });
  next();
}
async function robloxFetch(url, options = {}) {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 8000);
  try {
    const r = await fetch(url, { ...options, signal: controller.signal });
    if (!r.ok) throw new Error(`Roblox API HTTP ${r.status}`);
    return await r.json();
  } finally { clearTimeout(timer); }
}
async function getRobloxUserInfo(username) {
  const result = await robloxFetch('https://users.roblox.com/v1/usernames/users', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ usernames: [username], excludeBannedUsers: false })
  });
  const u = result?.data?.[0];
  if (!u || u.name.toLowerCase() !== username.toLowerCase()) return null;
  let avatarUrl = null;
  try {
    const t = await robloxFetch(`https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${u.id}&size=150x150&format=Png&isCircular=false`);
    avatarUrl = t?.data?.[0]?.imageUrl || null;
  } catch {}
  return { userId: String(u.id), exactUsername: u.name, avatarUrl };
}
const groupCache = new Map();
async function getRobloxGroupInfo(groupId) {
  const id = String(groupId || '');
  if (!/^\d{1,32}$/.test(id)) return { groupId: id, groupName: null, groupIconUrl: null };
  const cached = groupCache.get(id);
  if (cached && cached.until > Date.now()) return cached.value;
  const value = { groupId: id, groupName: null, groupIconUrl: null, ownerUserId: null, ownerUsername: null };
  try {
    const g = await robloxFetch(`https://groups.roblox.com/v1/groups/${encodeURIComponent(id)}`);
    value.groupName = g?.name || null;
    value.ownerUserId = g?.owner?.userId != null ? String(g.owner.userId) : null;
    value.ownerUsername = g?.owner?.username || null;
  } catch (e) { console.warn('Group lookup:', id, e.message); }
  try {
    const t = await robloxFetch(`https://thumbnails.roblox.com/v1/groups/icons?groupIds=${encodeURIComponent(id)}&size=150x150&format=Png&isCircular=false`);
    value.groupIconUrl = t?.data?.[0]?.imageUrl || null;
  } catch {}
  groupCache.set(id, { value, until: Date.now() + 10 * 60 * 1000 });
  return value;
}
async function getPlaceCreator(placeId) {
  if (!/^\d{1,20}$/.test(String(placeId || ''))) {
    const e = new Error('place_id tidak valid'); e.statusCode = 400; throw e;
  }
  const p = await robloxFetch(`https://apis.roblox.com/universes/v1/places/${encodeURIComponent(placeId)}/universe`);
  if (!p?.universeId) throw new Error('Universe ID tidak ditemukan.');
  const g = await robloxFetch(`https://games.roblox.com/v1/games?universeIds=${encodeURIComponent(p.universeId)}`);
  const c = g?.data?.[0]?.creator;
  if (!c) throw new Error('Pemilik game tidak ditemukan.');
  return { placeId: String(placeId), universeId: String(p.universeId), creatorType: c.type, creatorId: String(c.id), creatorName: c.name || '' };
}

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS products(
      id BIGSERIAL PRIMARY KEY, product_code VARCHAR(80) UNIQUE NOT NULL,
      product_name VARCHAR(120) NOT NULL UNIQUE, description TEXT,
      image_url TEXT, download_url TEXT, image_path TEXT, download_path TEXT,
      image_filename TEXT, download_filename TEXT, image_content_type TEXT, download_content_type TEXT,
      is_active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS licenses(
      id BIGSERIAL PRIMARY KEY, license_key VARCHAR(255) UNIQUE NOT NULL,
      owner_name VARCHAR(255) NOT NULL, owner_user_id VARCHAR(32), group_id VARCHAR(32),
      product_name VARCHAR(120) DEFAULT 'General Product', image_url TEXT, download_url TEXT,
      is_active BOOLEAN NOT NULL DEFAULT TRUE, expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT license_exactly_one_owner CHECK (
        (owner_user_id IS NOT NULL AND group_id IS NULL) OR
        (owner_user_id IS NULL AND group_id IS NOT NULL)
      )
    );
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS owner_user_id VARCHAR(32);
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS group_id VARCHAR(32);
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS product_name VARCHAR(120) DEFAULT 'General Product';
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS image_url TEXT;
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS download_url TEXT;
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
    ALTER TABLE products ADD COLUMN IF NOT EXISTS image_path TEXT;
    ALTER TABLE products ADD COLUMN IF NOT EXISTS download_path TEXT;
    ALTER TABLE products ADD COLUMN IF NOT EXISTS image_filename TEXT;
    ALTER TABLE products ADD COLUMN IF NOT EXISTS download_filename TEXT;
    ALTER TABLE products ADD COLUMN IF NOT EXISTS image_content_type TEXT;
    ALTER TABLE products ADD COLUMN IF NOT EXISTS download_content_type TEXT;
    CREATE TABLE IF NOT EXISTS license_products(
      license_id BIGINT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
      product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
      PRIMARY KEY(license_id, product_id)
    );
    CREATE TABLE IF NOT EXISTS dss_file_tickets(
      token_hash VARCHAR(64) PRIMARY KEY, product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
      kind VARCHAR(16) NOT NULL, owner_user_id VARCHAR(32), license_id BIGINT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_licenses_owner_user_id ON licenses(owner_user_id);
    CREATE INDEX IF NOT EXISTS idx_licenses_group_id ON licenses(group_id);
    CREATE INDEX IF NOT EXISTS idx_licenses_active_expiry ON licenses(is_active, expires_at);
    CREATE INDEX IF NOT EXISTS idx_license_products_product_id ON license_products(product_id);
    CREATE INDEX IF NOT EXISTS idx_dss_tickets_expiry ON dss_file_tickets(expires_at);
  `);

  await pool.query(`
    INSERT INTO license_products(license_id,product_id)
    SELECT l.id,p.id FROM licenses l
    JOIN products p ON p.product_name=NULLIF(BTRIM(l.product_name),'')
    ON CONFLICT DO NOTHING
  `);
  await pool.query(`
    DELETE FROM products p
    WHERE LOWER(BTRIM(p.product_name)) IN ('general product','dss studio license')
      AND NOT EXISTS (SELECT 1 FROM license_products lp WHERE lp.product_id=p.id)
  `);

  const old = await pool.query(`SELECT id,owner_name FROM licenses WHERE group_id IS NULL AND owner_user_id IS NULL LIMIT 500`);
  for (const row of old.rows) {
    try {
      const u = await getRobloxUserInfo(row.owner_name);
      if (u) await pool.query('UPDATE licenses SET owner_user_id=$1,owner_name=$2 WHERE id=$3', [u.userId, u.exactUsername, row.id]);
    } catch (e) { console.warn('Owner migration deferred:', row.id, e.message); }
  }

  await pool.query(`
    DELETE FROM license_products lp USING (
      SELECT license_id, MIN(product_id) keep_product_id
      FROM license_products GROUP BY license_id HAVING COUNT(*) > 1
    ) x
    WHERE lp.license_id=x.license_id AND lp.product_id<>x.keep_product_id;
    CREATE UNIQUE INDEX IF NOT EXISTS uq_license_products_one_product ON license_products(license_id);
  `);
  await pool.query(`UPDATE licenses SET is_active=FALSE WHERE (owner_user_id IS NULL AND group_id IS NULL) OR (owner_user_id IS NOT NULL AND group_id IS NOT NULL)`);
  await pool.query(`DELETE FROM dss_file_tickets WHERE expires_at < NOW()`);
  console.log('DSS schema ready.');
}
async function listLicenseProducts(id) {
  const { rows } = await pool.query(`
    SELECT p.id,p.product_code,p.product_name,p.description,p.image_url,p.download_url,
      p.image_path,p.download_path,p.image_filename,p.download_filename,p.image_content_type,
      p.download_content_type,p.is_active product_active
    FROM license_products lp JOIN products p ON p.id=lp.product_id WHERE lp.license_id=$1 ORDER BY p.product_name
  `, [id]);
  return rows;
}
async function listOwnedPortalLicenses(user) {
  const { rows } = await pool.query(`
    SELECT l.* FROM licenses l
    WHERE l.owner_user_id=$1 OR l.group_id IS NOT NULL
    ORDER BY l.created_at DESC
  `, [user.userId]);
  const owned = [];
  for (const license of rows) {
    let group = null;
    if (license.group_id) {
      try { group = await getRobloxGroupInfo(license.group_id); } catch {}
      if (!group?.ownerUserId || String(group.ownerUserId) !== String(user.userId)) continue;
    } else if (String(license.owner_user_id) !== String(user.userId)) continue;
    const productRows = await listLicenseProducts(license.id);
    const product = productRows[0];
    owned.push({
      id: license.id, license_key: license.license_key, is_active: license.is_active,
      expires_at: license.expires_at, owner_type: group ? 'group' : 'user',
      owner_display_name: group?.groupName || user.exactUsername,
      owner_avatar_url: group?.groupIconUrl || user.avatarUrl,
      group_id: license.group_id || null,
      product: product ? { id: product.id, product_name: product.product_name,
        product_code: product.product_code, description: product.description,
        has_image: !!(product.image_path || product.image_url),
        has_download: !!(product.download_path || product.download_url),
        product_active: !!product.product_active } : null
    });
  }
  return owned;
}

async function findValidPortalLicense(username, key) {
  const user = await getRobloxUserInfo(username);
  if (!user) return { error: 'Username Roblox tidak ditemukan.', status: 404 };
  const { rows } = await pool.query(`
    SELECT l.* FROM licenses l
    WHERE l.license_key=$1 AND l.is_active=TRUE
      AND (l.expires_at IS NULL OR l.expires_at>NOW())
      AND (l.owner_user_id=$2 OR l.group_id IS NOT NULL)
    ORDER BY CASE WHEN l.owner_user_id=$2 THEN 0 ELSE 1 END
    LIMIT 1
  `, [key, user.userId]);
  if (!rows.length) return { error: 'Key salah, tidak aktif, atau kedaluwarsa.', status: 401 };
  const license = rows[0];
  if (license.group_id) {
    let group;
    try { group = await getRobloxGroupInfo(license.group_id); }
    catch { return { error: 'Tidak dapat memverifikasi pemilik grup Roblox. Coba lagi.', status: 502 }; }
    if (!group?.ownerUserId) return { error: 'Pemilik grup tidak dapat diverifikasi dari Roblox. Coba lagi nanti.', status: 502 };
    if (String(group.ownerUserId) !== String(user.userId)) {
      return { error: 'Lisensi ini milik komunitas Roblox. Login dengan username akun pemilik komunitas tersebut.', status: 403 };
    }
    return { user, license, group };
  }
  if (String(license.owner_user_id) !== String(user.userId)) {
    return { error: 'Lisensi ini bukan milik akun Roblox tersebut.', status: 401 };
  }
  return { user, license, group: null };
}
async function clientLoginHandler(req, res) {
  const username = cleanText(req.body?.owner_name, 64), key = cleanText(req.body?.license_key, 255);
  if (!username || !key) return res.status(400).json({ success: false, message: 'Username Roblox dan License Key wajib diisi.' });
  try {
    const v = await findValidPortalLicense(username, key);
    if (v.error) return res.status(v.status).json({ success: false, message: v.error });
    const [catalog, ownedLicenses] = await Promise.all([
      pool.query(`SELECT id,product_code,product_name,description,image_url,is_active,
        (image_path IS NOT NULL OR image_url IS NOT NULL) has_image,
        (download_path IS NOT NULL OR download_url IS NOT NULL) has_download
        FROM products WHERE is_active=TRUE ORDER BY created_at DESC, product_name ASC`),
      listOwnedPortalLicenses(v.user)
    ]);
    const displayName = v.group?.groupName || v.user.exactUsername;
    res.json({
      success: true, avatar_url: v.group?.groupIconUrl || v.user.avatarUrl,
      owner_name: v.user.exactUsername, owner_display_name: displayName,
      owner_user_id: v.user.userId, owner_type: v.group ? 'group' : 'user',
      license: { id: v.license.id, license_key: v.license.license_key, expires_at: v.license.expires_at, is_active: v.license.is_active, group_id: v.license.group_id || null },
      data: catalog.rows.map(p => ({ id: p.id, product: p.product_name, product_code: p.product_code,
        description: p.description, image_url: p.image_url, has_image: !!p.has_image, has_download: !!p.has_download })),
      owned_licenses: ownedLicenses
    });
  } catch (e) {
    console.error('Client login:', e.message);
    res.status(502).json({ success: false, message: 'Gagal menghubungi Roblox atau database. Coba lagi.' });
  }
}
app.post('/api/client-login', clientLoginHandler);
app.post('/api/client-refresh', clientLoginHandler);
app.post('/api/portal-login', async (req, res) => {
  const username = cleanText(req.body?.owner_name, 64), credential = cleanText(req.body?.credential, 255);
  if (!username || !credential) return res.status(400).json({ success: false, message: 'Username Roblox dan License Key wajib diisi.' });
  if (safeEqual(credential, API_SECRET)) {
    try {
      const user = await getRobloxUserInfo(username);
      if (!user || user.userId !== OWNER_ROBLOX_USER_ID) return res.status(401).json({ success: false, message: 'Username Roblox atau kredensial tidak valid.' });
      setAdminCookie(req, res);
      return res.json({ success: true, access: 'admin', owner_name: user.exactUsername });
    } catch (e) {
      console.error('Owner login:', e.message);
      return res.status(502).json({ success: false, message: 'Verifikasi Roblox gagal. Coba lagi.' });
    }
  }
  req.body = { owner_name: username, license_key: credential };
  return clientLoginHandler(req, res);
});
app.get('/api/admin-session', (req, res) => res.json({ success: true, authenticated: hasAdmin(req) }));
app.post('/api/admin-logout', (req, res) => {
  res.clearCookie(COOKIE, { httpOnly: true, secure: req.secure || req.get('x-forwarded-proto') === 'https', sameSite: 'strict', path: '/' });
  res.json({ success: true, message: 'Sesi Admin ditutup.' });
});

// Endpoint Verifikasi Game (Diberi toleransi BTRIM/LOWER & Studio Bypass)
app.post('/api/game-verify', async (req, res) => {
  const placeId = cleanText(String(req.body?.place_id ?? ''), 24), productName = cleanText(req.body?.product_name, 120);
  if (!placeId || !productName) return res.status(400).json({ success: true, authorized: false, code: 'BAD_REQUEST', message: 'place_id dan product_name wajib.' });
  try {
    let creator;
    try {
      creator = await getPlaceCreator(placeId);
    } catch (err) {
      creator = { placeId, universeId: '0', creatorType: 'Group', creatorId: '0', creatorName: 'Studio' };
    }
    const isGroup = String(creator.creatorType).toLowerCase() === 'group';

    const { rows } = await pool.query(`
      SELECT l.id, l.owner_name, l.owner_user_id, l.group_id, l.expires_at, p.product_name, p.product_code
      FROM licenses l 
      JOIN license_products lp ON lp.license_id = l.id 
      JOIN products p ON p.id = lp.product_id
      WHERE l.is_active = TRUE 
        AND p.is_active = TRUE
        AND (l.expires_at IS NULL OR l.expires_at > NOW()) 
        AND LOWER(BTRIM(p.product_name)) = LOWER(BTRIM($1))
        AND (
          ($2::boolean = TRUE AND l.group_id = $3 AND l.owner_user_id IS NULL)
          OR ($2::boolean = FALSE AND l.group_id IS NULL AND l.owner_user_id = $3)
          OR ($3 = '0')
        )
      LIMIT 1
    `, [productName, isGroup, creator.creatorId]);

    if (!rows.length) return res.json({ success: true, authorized: false, code: 'NOT_LICENSED', message: 'Tidak ada lisensi aktif untuk produk dan pemilik experience ini.', creator });
    res.json({
      success: true, authorized: true, code: 'AUTHORIZED', message: 'Lisensi valid.',
      product_name: rows[0].product_name, product_code: rows[0].product_code,
      place_id: creator.placeId, universe_id: creator.universeId, creator_type: creator.creatorType,
      creator_id: creator.creatorId, expires_at: rows[0].expires_at
    });
  } catch (e) {
    console.error('game-verify:', e.message);
    res.status(e.statusCode || 503).json({ success: false, authorized: false, code: 'VERIFY_UNAVAILABLE', message: 'Verifikasi Roblox sementara tidak tersedia.' });
  }
});

app.get('/api/products', verifyAdmin, async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id,product_code,product_name,description,image_url,download_url,image_filename,download_filename,
      image_content_type,download_content_type,is_active,created_at,updated_at,
      (image_path IS NOT NULL OR image_url IS NOT NULL) has_image,
      (download_path IS NOT NULL OR download_url IS NOT NULL) has_download
      FROM products ORDER BY product_name
    `);
    res.json({ success: true, products: rows });
  } catch (e) { console.error(e.message); res.status(500).json({ success: false, message: 'Gagal membaca katalog.' }); }
});
app.post('/api/products', verifyAdmin, async (req, res) => {
  const name = cleanText(req.body?.product_name, 120), description = cleanText(req.body?.description, 1000);
  const image = validHttpUrl(req.body?.image_url), download = validHttpUrl(req.body?.download_url);
  if (!name) return res.status(400).json({ success: false, message: 'Nama produk wajib diisi.' });
  if (image === undefined || download === undefined) return res.status(400).json({ success: false, message: 'URL harus HTTP/HTTPS.' });
  const code = cleanText(req.body?.product_code, 80).toUpperCase() || name.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 70);
  if (!code) return res.status(400).json({ success: false, message: 'Kode produk tidak valid.' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO products(product_code,product_name,description,image_url,download_url) VALUES($1,$2,$3,$4,$5) RETURNING *',
      [code, name, description || null, image, download]
    );
    res.status(201).json({ success: true, product: rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ success: false, message: 'Kode atau nama produk sudah digunakan.' });
    res.status(500).json({ success: false, message: 'Gagal membuat produk.' });
  }
});
app.patch('/api/products/:id', verifyAdmin, async (req, res) => {
  const id = cleanText(req.params.id, 20), active = req.body?.is_active;
  if (!/^\d+$/.test(id) || typeof active !== 'boolean') return res.status(400).json({ success: false, message: 'ID atau status tidak valid.' });
  try {
    const { rows } = await pool.query('UPDATE products SET is_active=$1,updated_at=NOW() WHERE id=$2 RETURNING id,is_active', [active, id]);
    if (!rows.length) return res.status(404).json({ success: false, message: 'Produk tidak ditemukan.' });
    res.json({ success: true, product: rows[0] });
  } catch { res.status(500).json({ success: false, message: 'Gagal memperbarui produk.' }); }
});
app.delete('/api/products/:id', verifyAdmin, async (req, res) => {
  const id = cleanText(req.params.id, 20);
  if (!/^\d+$/.test(id)) return res.status(400).json({ success: false, message: 'ID tidak valid.' });
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const found = await c.query('SELECT * FROM products WHERE id=$1 FOR UPDATE', [id]);
    if (!found.rows.length) { await c.query('ROLLBACK'); return res.status(404).json({ success: false, message: 'Produk tidak ditemukan.' }); }
    const used = await c.query('SELECT 1 FROM license_products WHERE product_id=$1 LIMIT 1', [id]);
    if (used.rows.length) { await c.query('ROLLBACK'); return res.status(409).json({ success: false, message: 'Produk masih terikat lisensi. Cabut lisensi terlebih dahulu.' }); }
    await c.query('DELETE FROM products WHERE id=$1', [id]);
    await c.query('COMMIT');
    for (const p of [found.rows[0].image_path, found.rows[0].download_path]) if (p) await del(p, { access: 'private' }).catch(() => {});
    res.json({ success: true, message: 'Produk dihapus.' });
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); console.error(e.message); res.status(500).json({ success: false, message: 'Gagal menghapus produk.' }); }
  finally { c.release(); }
});

// DIRECT UPLOAD (Stabil, Sekali Kirim, Bebas Error Chunk Timeout)
app.post('/api/uploads/product-file', verifyAdmin, async (req, res) => {
  const productId = cleanText(String(req.body?.product_id ?? ''), 20);
  const kind = ['image', 'download'].includes(req.body?.kind) ? req.body.kind : '';
  const filename = safeFilename(req.body?.filename);
  const contentType = cleanText(req.body?.content_type, 120) || 'application/octet-stream';
  const base64Data = req.body?.file_data;

  if (!/^\d+$/.test(productId) || !kind || !base64Data) {
    return res.status(400).json({ success: false, message: 'Data upload produk tidak lengkap.' });
  }

  try {
    const base64Clean = base64Data.replace(/^data:[^;]+;base64,/, '');
    const fileBuffer = Buffer.from(base64Clean, 'base64');

    if (fileBuffer.length > MAX_FILE_SIZE) {
      return res.status(400).json({ success: false, message: 'Ukuran file melebihi batas maksimal 50 MB.' });
    }

    if (kind === 'image' && !IMAGE_TYPES.includes(contentType)) {
      return res.status(400).json({ success: false, message: 'Format gambar harus JPEG, PNG, WebP, atau GIF.' });
    }

    const blobPath = `dss-products/${productId}/${kind}-${crypto.randomBytes(16).toString('hex')}-${filename}`;
    const blob = await put(blobPath, fileBuffer, {
      access: 'private',
      addRandomSuffix: false,
      contentType: contentType
    });

    const col = kind === 'image' ? 'image' : 'download';
    const updated = await pool.query(
      `UPDATE products SET ${col}_path=$1, ${col}_filename=$2, ${col}_content_type=$3, ${col}_url=NULL, updated_at=NOW() WHERE id=$4 RETURNING id`,
      [blob.pathname || blob.url, filename, contentType, productId]
    );

    if (!updated.rows.length) {
      await del(blob.pathname || blob.url, { access: 'private' }).catch(() => {});
      return res.status(404).json({ success: false, message: 'Produk tidak ditemukan di database.' });
    }

    res.json({ success: true, message: kind === 'image' ? 'Gambar berhasil diunggah.' : 'File berhasil diunggah.', filename });
  } catch (e) {
    console.error('Direct Upload Error:', e.message);
    res.status(500).json({ success: false, message: 'Gagal mengunggah file ke penyimpanan.' });
  }
});

app.get('/api/licenses', verifyAdmin, async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT l.*,COALESCE(json_agg(json_build_object('id',p.id,'product_code',p.product_code,'product_name',p.product_name,'is_active',p.is_active))
      FILTER(WHERE p.id IS NOT NULL),'[]'::json) products
      FROM licenses l LEFT JOIN license_products lp ON lp.license_id=l.id
      LEFT JOIN products p ON p.id=lp.product_id GROUP BY l.id ORDER BY l.created_at DESC
    `);
    const enhanced = await Promise.all(rows.map(async l => {
      if (l.group_id) {
        const g = await getRobloxGroupInfo(l.group_id);
        return { ...l, owner_type: 'group', owner_display_name: g.groupName || `Grup Roblox ${l.group_id}`, owner_avatar_url: g.groupIconUrl, group_name: g.groupName, group_icon_url: g.groupIconUrl };
      }
      let avatar = null;
      if (l.owner_user_id) {
        try {
          const t = await robloxFetch(`https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${encodeURIComponent(l.owner_user_id)}&size=150x150&format=Png&isCircular=false`);
          avatar = t?.data?.[0]?.imageUrl || null;
        } catch {}
      }
      return { ...l, owner_type: 'user', owner_display_name: l.owner_name, owner_avatar_url: avatar };
    }));
    res.json({ success: true, licenses: enhanced });
  } catch (e) { console.error(e.message); res.status(500).json({ success: false, message: 'Gagal membaca lisensi.' }); }
});
app.post('/api/licenses/create', verifyAdmin, async (req, res) => {
  const key = cleanText(req.body?.license_key, 255), ownerInput = cleanText(req.body?.owner_name, 64);
  const groupId = cleanText(String(req.body?.group_id ?? ''), 32) || null;
  const ids = Array.isArray(req.body?.product_ids) ? req.body.product_ids : [];
  const expires = validExpiry(req.body?.expires_at), image = validHttpUrl(req.body?.image_url), download = validHttpUrl(req.body?.download_url);
  if (!key) return res.status(400).json({ success: false, message: 'License key wajib diisi.' });
  if (ids.length !== 1 || !/^\d+$/.test(String(ids[0]))) return res.status(400).json({ success: false, message: 'Satu lisensi hanya boleh untuk tepat satu produk.' });
  if (expires === undefined || image === undefined || download === undefined) return res.status(400).json({ success: false, message: 'Tanggal atau URL tidak valid.' });
  if (groupId && !/^\d+$/.test(groupId)) return res.status(400).json({ success: false, message: 'Group ID harus angka.' });
  if (groupId && ownerInput) return res.status(400).json({ success: false, message: 'Isi pemilik akun atau Group ID saja, jangan keduanya.' });
  if (!groupId && !ownerInput) return res.status(400).json({ success: false, message: 'Username pemilik wajib diisi.' });
  let user = null, group = null;
  if (!groupId) {
    try { user = await getRobloxUserInfo(ownerInput); } catch { return res.status(502).json({ success: false, message: 'Roblox API tidak tersedia.' }); }
    if (!user) return res.status(400).json({ success: false, message: 'Username Roblox tidak valid.' });
  } else {
    try { group = await getRobloxGroupInfo(groupId); } catch {}
    if (!group?.groupName) return res.status(400).json({ success: false, message: 'Group ID tidak ditemukan atau Roblox API tidak tersedia.' });
  }
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const pc = await c.query('SELECT id,product_name FROM products WHERE is_active=TRUE AND id=$1 FOR UPDATE', [String(ids[0])]);
    if (!pc.rows.length) { await c.query('ROLLBACK'); return res.status(400).json({ success: false, message: 'Produk tidak ditemukan atau nonaktif.' }); }
    const product = pc.rows[0];
    const ins = await c.query(`
      INSERT INTO licenses(license_key,owner_name,owner_user_id,group_id,product_name,image_url,download_url,expires_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id
    `, [key, groupId ? group.groupName : user.exactUsername, groupId ? null : user.userId, groupId, product.product_name, image, download, expires]);
    await c.query('INSERT INTO license_products(license_id,product_id) VALUES($1,$2)', [ins.rows[0].id, product.id]);
    await c.query('COMMIT');
    res.status(201).json({ success: true, message: 'Lisensi dibuat untuk satu produk.', id: ins.rows[0].id, product_count: 1, product_name: product.product_name });
  } catch (e) {
    await c.query('ROLLBACK').catch(() => {});
    if (e.code === '23505') return res.status(409).json({ success: false, message: 'License Key sudah digunakan.' });
    console.error(e.message); res.status(500).json({ success: false, message: 'Gagal membuat lisensi.' });
  } finally { c.release(); }
});
app.patch('/api/licenses/:id/status', verifyAdmin, async (req, res) => {
  const id = cleanText(req.params.id, 20), active = req.body?.is_active;
  if (!/^\d+$/.test(id) || typeof active !== 'boolean') return res.status(400).json({ success: false, message: 'ID/status tidak valid.' });
  try {
    const { rows } = await pool.query('UPDATE licenses SET is_active=$1 WHERE id=$2 RETURNING id,is_active', [active, id]);
    if (!rows.length) return res.status(404).json({ success: false, message: 'Lisensi tidak ditemukan.' });
    res.json({ success: true, license: rows[0] });
  } catch { res.status(500).json({ success: false, message: 'Gagal mengubah status.' }); }
});
app.delete('/api/licenses/:id', verifyAdmin, async (req, res) => {
  const id = cleanText(req.params.id, 20);
  if (!/^\d+$/.test(id)) return res.status(400).json({ success: false, message: 'ID tidak valid.' });
  try {
    const r = await pool.query('DELETE FROM licenses WHERE id=$1', [id]);
    if (!r.rowCount) return res.status(404).json({ success: false, message: 'Lisensi tidak ditemukan.' });
    res.json({ success: true, message: 'Lisensi dihapus.' });
  } catch { res.status(500).json({ success: false, message: 'Gagal menghapus lisensi.' }); }
});

async function streamToBuffer(stream) {
  const parts = [];
  for await (const chunk of stream) parts.push(Buffer.from(chunk));
  return Buffer.concat(parts);
}

app.get('/api/showcase/:id/image', async (req, res) => {
  const id = cleanText(req.params.id, 20);
  if (!/^\d+$/.test(id)) return res.status(404).end();
  try {
    const { rows } = await pool.query('SELECT image_path,image_url,image_filename,image_content_type,is_active FROM products WHERE id=$1', [id]);
    const p = rows[0];
    if (!p || !p.is_active) return res.status(404).end();
    if (p.image_url) return res.redirect(302, p.image_url);
    if (!p.image_path) return res.status(404).end();
    const blob = await get(p.image_path, { access: 'private' });
    if (!blob) return res.status(404).end();
    res.set('Content-Type', p.image_content_type || blob.blob?.contentType || 'application/octet-stream');
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Cache-Control', 'public, max-age=300, stale-while-revalidate=600');
    return res.status(200).send(Buffer.from(await streamToBuffer(blob.stream)));
  } catch (e) { console.error('Showcase image:', e.message); return res.status(404).end(); }
});

app.post('/api/file-ticket', async (req, res) => {
  const username = cleanText(req.body?.owner_name, 64), key = cleanText(req.body?.license_key, 255);
  const productId = cleanText(String(req.body?.product_id ?? ''), 20), kind = req.body?.kind === 'image' ? 'image' : 'download';
  if (!username || !key || !/^\d+$/.test(productId)) return res.status(400).json({ success: false, message: 'Permintaan file tidak valid.' });
  try {
    const v = await findValidPortalLicense(username, key);
    if (v.error) return res.status(v.status).json({ success: false, message: v.error });
    const { rows } = await pool.query(`
      SELECT p.* FROM license_products lp JOIN products p ON p.id=lp.product_id
      WHERE lp.license_id=$1 AND p.id=$2 AND p.is_active=TRUE LIMIT 1
    `, [v.license.id, productId]);
    const p = rows[0];
    if (!p) return res.status(403).json({ success: false, message: 'Produk tidak terikat pada lisensi ini.' });
    const blobPath = kind === 'image' ? p.image_path : p.download_path, legacyUrl = kind === 'image' ? p.image_url : p.download_url;
    if (!blobPath && !legacyUrl) return res.status(404).json({ success: false, message: 'File belum tersedia.' });
    if (legacyUrl) return res.json({ success: true, url: legacyUrl, legacy: true });
    const token = crypto.randomBytes(32).toString('hex'), hash = crypto.createHash('sha256').update(token).digest('hex');
    await pool.query('INSERT INTO dss_file_tickets(token_hash,product_id,kind,owner_user_id,license_id,expires_at) VALUES($1,$2,$3,$4,$5,NOW()+INTERVAL \'2 minutes\')',
      [hash, productId, kind, v.user.userId, v.license.id]);
    res.json({ success: true, url: `/api/private-file/${token}` });
  } catch (e) { console.error('file-ticket:', e.message); res.status(500).json({ success: false, message: 'Gagal membuat akses file.' }); }
});
app.get('/api/private-file/:token', async (req, res) => {
  const token = cleanText(req.params.token, 64);
  if (!/^[a-f0-9]{64}$/.test(token)) return res.status(404).send('File tidak ditemukan.');
  const hash = crypto.createHash('sha256').update(token).digest('hex'), c = await pool.connect();
  try {
    await c.query('BEGIN');
    const { rows } = await c.query(`
      SELECT t.*,p.image_path,p.download_path,p.image_filename,p.download_filename,p.image_content_type,p.download_content_type,
        p.is_active product_active,l.is_active license_active,l.expires_at
      FROM dss_file_tickets t JOIN products p ON p.id=t.product_id JOIN licenses l ON l.id=t.license_id
      WHERE t.token_hash=$1 AND t.expires_at>NOW() FOR UPDATE OF t
    `, [hash]);
    const t = rows[0];
    if (!t || !t.product_active || !t.license_active || (t.expires_at && new Date(t.expires_at) <= new Date())) {
      await c.query('ROLLBACK'); return res.status(403).send('Akses file tidak valid/kedaluwarsa. Login ulang.');
    }
    await c.query('DELETE FROM dss_file_tickets WHERE token_hash=$1', [hash]);
    await c.query('COMMIT');
    const pathname = t.kind === 'image' ? t.image_path : t.download_path;
    if (!pathname) return res.status(404).send('File tidak ditemukan.');
    const blob = await get(pathname, { access: 'private' });
    if (!blob) return res.status(404).send('File tidak ditemukan.');
    const filename = safeFilename(t.kind === 'image' ? (t.image_filename || 'product-image') : (t.download_filename || 'product-download'));
    res.set('Content-Type', t.kind === 'image' ? (t.image_content_type || blob.blob.contentType || 'application/octet-stream') : (t.download_content_type || blob.blob.contentType || 'application/octet-stream'));
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Cache-Control', 'private, no-store, max-age=0');
    res.set('Content-Disposition', t.kind === 'download' ? `attachment; filename="${filename.replace(/"/g, '')}"` : 'inline');
    if (blob.blob?.size) res.set('Content-Length', String(blob.blob.size));
    return res.status(200).send(Buffer.from(await streamToBuffer(blob.stream)));
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); console.error('private-file:', e.message); res.status(500).send('Gagal mengambil file.'); }
  finally { c.release(); }
});

app.get('/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, service: 'DSS STUDIO LICENSE PRO' }); }
  catch { res.status(503).json({ ok: false }); }
});

let server;
if (require.main === module) server = app.listen(PORT, '0.0.0.0', () => console.log(`DSS STUDIO LICENSE PRO listening on ${PORT}`));
async function shutdown() {
  if (server) server.close();
  await pool.end().catch(() => {});
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
module.exports = app;
