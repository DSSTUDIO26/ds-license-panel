// DSS STUDIO LICENSE PRO — Node.js 20+ / PostgreSQL / Product Price & Auto-Experience Support
'use strict';
const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(express.json({ limit: '10mb' }));

const PORT = Number(process.env.PORT || 3000);
const API_SECRET = process.env.API_SECRET || '';
const OWNER_ROBLOX_USER_ID = String(process.env.OWNER_ROBLOX_USER_ID || '9262435668');
const DATABASE_URL = process.env.DATABASE_URL || '';
const COOKIE = 'dss_admin_session';
const SESSION_MS = 8 * 60 * 60 * 1000;

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
      price VARCHAR(64), image_url TEXT, download_url TEXT,
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
    ALTER TABLE products ADD COLUMN IF NOT EXISTS price VARCHAR(64);
    ALTER TABLE products ADD COLUMN IF NOT EXISTS image_url TEXT;
    ALTER TABLE products ADD COLUMN IF NOT EXISTS download_url TEXT;
    CREATE TABLE IF NOT EXISTS license_products(
      license_id BIGINT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
      product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
      PRIMARY KEY(license_id, product_id)
    );
    CREATE TABLE IF NOT EXISTS project_experiences (
      place_id VARCHAR(32) PRIMARY KEY,
      product_name VARCHAR(120),
      owner_id VARCHAR(32),
      last_ping TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log('DSS schema ready.');
}

async function listLicenseProducts(id) {
  const { rows } = await pool.query(`
    SELECT p.id,p.product_code,p.product_name,p.description,p.price,p.image_url,p.download_url,
      p.is_active product_active
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
        product_code: product.product_code, description: product.description, price: product.price,
        image_url: product.image_url, download_url: product.download_url,
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
      pool.query(`SELECT id,product_code,product_name,description,price,image_url,download_url,is_active
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
        description: p.description, price: p.price, image_url: p.image_url, download_url: p.download_url })),
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

app.post('/api/game-details', async (req, res) => {
  const placeId = cleanText(String(req.body?.place_id ?? ''), 24);
  if (!placeId) return res.status(400).json({ success: false, message: 'place_id wajib diisi.' });
  try {
    let name = `Experience #${placeId}`;
    let icon = 'https://github.com/DSSTUDIO26/ds-license-panel/blob/main/ds-license-panel/Image/dragonstellstudio.jpeg?raw=true';
    let creatorName = 'Dragon Stell Studio';
    let visits = 0;

    const universeRes = await robloxFetch(`https://apis.roblox.com/universes/v1/places/${encodeURIComponent(placeId)}/universe`);
    const universeId = universeRes?.universeId;

    if (universeId) {
      const gameRes = await robloxFetch(`https://games.roblox.com/v1/games?universeIds=${encodeURIComponent(universeId)}`);
      const gameData = gameRes?.data?.[0];
      if (gameData?.name) name = gameData.name;
      if (gameData?.creator?.name) creatorName = gameData.creator.name;
      if (gameData?.visits !== undefined) visits = gameData.visits;
    }

    try {
      const thumbRes = await robloxFetch(`https://thumbnails.roblox.com/v1/places/gameicons?placeIds=${encodeURIComponent(placeId)}&size=512x512&format=Png&isCircular=false`);
      const thumbUrl = thumbRes?.data?.[0]?.imageUrl;
      if (thumbUrl) icon = thumbUrl;
    } catch {}

    res.json({ success: true, name, icon, creatorName, visits });
  } catch (e) {
    console.error('game-details error:', e.message);
    res.json({ success: true, name: `Experience #${placeId}`, icon: 'https://github.com/DSSTUDIO26/ds-license-panel/blob/main/ds-license-panel/Image/dragonstellstudio.jpeg?raw=true', creatorName: 'Dragon Stell Studio', visits: 0 });
  }
});

// Endpoint Verifikasi Game Terbaru (Mendukung Game Private via Direct Payload dari Roblox Studio)
app.post('/api/game-verify', async (req, res) => {
  const placeId = cleanText(String(req.body?.place_id ?? ''), 24);
  const directCreatorId = cleanText(String(req.body?.creator_id ?? ''), 32);

  if (!placeId) return res.status(400).json({ success: false, message: 'place_id wajib diisi.' });

  try {
    let creatorId = directCreatorId || null;

    // Jika Studio tidak mengirimkan creator_id (atau game publik), coba ambil via API Publik Roblox
    if (!creatorId) {
      try {
        const creator = await getPlaceCreator(placeId);
        creatorId = creator.creatorId;
      } catch (apiErr) {
        console.warn(`[GAME-VERIFY] Place ID ${placeId} adalah Private Game atau belum terdaftar di Public API Roblox.`);
      }
    }

    // Jika creatorId tidak ditemukan baik dari payload maupun API
    if (!creatorId) {
      return res.json({ success: true, authorized: false, product_name: null, message: "Pemilik game tidak dapat diverifikasi." });
    }

    // QUERY UTAMA: Pencocokan Group ID atau Owner User ID dengan lisensi aktif
    const { rows } = await pool.query(`
      SELECT p.product_name FROM licenses l 
      JOIN license_products lp ON lp.license_id = l.id 
      JOIN products p ON p.id = lp.product_id
      WHERE l.is_active = TRUE AND p.is_active = TRUE
        AND (l.expires_at IS NULL OR l.expires_at > NOW()) 
        AND (
          (l.group_id IS NOT NULL AND l.group_id::text = $1::text)
          OR 
          (l.owner_user_id IS NOT NULL AND l.owner_user_id::text = $1::text)
        )
      LIMIT 1
    `, [String(creatorId)]);

    if (!rows.length) {
      return res.json({ success: true, authorized: false, product_name: null });
    }

    // OTOMATIS CATAT / UPDATE KE PROJECT EXPERIENCES
    await pool.query(`
      INSERT INTO project_experiences (place_id, product_name, owner_id, last_ping)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (place_id) DO UPDATE 
      SET last_ping = NOW(), product_name = EXCLUDED.product_name;
    `, [placeId, rows[0].product_name, creatorId]);

    res.json({ success: true, authorized: true, product_name: rows[0].product_name });
  } catch (e) {
    console.error('game-verify error:', e.message);
    res.status(500).json({ success: false, authorized: false, product_name: null });
  }
});

// Endpoint untuk mengambil daftar project experience yang otomatis terdaftar
app.get('/api/auto-projects', async (_req, res) => {
  try {
    const { rows } = await pool.query('SELECT place_id FROM project_experiences ORDER BY last_ping DESC');
    res.json({ success: true, projects: rows.map(r => r.place_id) });
  } catch {
    res.status(500).json({ success: false, projects: [] });
  }
});

// Endpoint untuk menghapus project experience otomatis
app.delete('/api/auto-projects/:pid', verifyAdmin, async (req, res) => {
  const pid = cleanText(req.params.pid, 24);
  try {
    await pool.query('DELETE FROM project_experiences WHERE place_id=$1', [pid]);
    res.json({ success: true, message: 'Project experience dihapus.' });
  } catch {
    res.status(500).json({ success: false, message: 'Gagal menghapus project.' });
  }
});

app.get('/api/products', verifyAdmin, async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id,product_code,product_name,description,price,image_url,download_url,is_active,created_at,updated_at
      FROM products ORDER BY product_name
    `);
    res.json({ success: true, products: rows });
  } catch (e) { console.error(e.message); res.status(500).json({ success: false, message: 'Gagal membaca katalog.' }); }
});

app.post('/api/products', verifyAdmin, async (req, res) => {
  const name = cleanText(req.body?.product_name, 120), description = cleanText(req.body?.description, 1000);
  const price = cleanText(req.body?.price, 64);
  const image = validHttpUrl(req.body?.image_url), download = validHttpUrl(req.body?.download_url);
  if (!name) return res.status(400).json({ success: false, message: 'Nama produk wajib diisi.' });
  const code = cleanText(req.body?.product_code, 80).toUpperCase() || name.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 70);
  if (!code) return res.status(400).json({ success: false, message: 'Kode produk tidak valid.' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO products(product_code,product_name,description,price,image_url,download_url) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',
      [code, name, description || null, price || null, image, download]
    );
    res.status(201).json({ success: true, product: rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ success: false, message: 'Kode atau nama produk sudah digunakan.' });
    res.status(500).json({ success: false, message: 'Gagal membuat produk.' });
  }
});

app.put('/api/products/:id', verifyAdmin, async (req, res) => {
  const id = cleanText(req.params.id, 20);
  const name = cleanText(req.body?.product_name, 120), description = cleanText(req.body?.description, 1000);
  const price = cleanText(req.body?.price, 64);
  const image = validHttpUrl(req.body?.image_url), download = validHttpUrl(req.body?.download_url);
  if (!/^\d+$/.test(id) || !name) return res.status(400).json({ success: false, message: 'ID atau nama produk tidak valid.' });
  const code = cleanText(req.body?.product_code, 80).toUpperCase() || name.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 70);
  try {
    const { rows } = await pool.query(
      'UPDATE products SET product_code=$1, product_name=$2, description=$3, price=$4, image_url=$5, download_url=$6, updated_at=NOW() WHERE id=$7 RETURNING *',
      [code, name, description || null, price || null, image, download, id]
    );
    if (!rows.length) return res.status(404).json({ success: false, message: 'Produk tidak ditemukan.' });
    res.json({ success: true, product: rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ success: false, message: 'Kode atau nama produk sudah digunakan.' });
    res.status(500).json({ success: false, message: 'Gagal memperbarui produk.' });
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
    res.json({ success: true, message: 'Produk dihapus.' });
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); console.error(e.message); res.status(500).json({ success: false, message: 'Gagal menghapus produk.' }); }
  finally { c.release(); }
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
    const directUrl = kind === 'image' ? p.image_url : p.download_url;
    if (!directUrl) return res.status(404).json({ success: false, message: 'URL Download belum tersedia.' });
    res.json({ success: true, url: directUrl });
  } catch (e) { console.error('file-ticket:', e.message); res.status(500).json({ success: false, message: 'Gagal membuat akses file.' }); }
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
