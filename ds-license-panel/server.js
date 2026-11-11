// DSS STUDIO LICENSE V5.1 (STRICT REVOCATION FIX)
// PostgreSQL + Private Vercel Blob
// Node.js 20+
// Compatible with DSS Roblox Server Loader V5

'use strict';

const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');
const { put, get, del } = require('@vercel/blob');

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(express.json({ limit: '3mb', strict: true }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=()'
  );

  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store');
  }

  next();
});

// ============================================================
// CONFIGURATION
// ============================================================

const PORT = Number(process.env.PORT || 3000);
const API_SECRET = process.env.API_SECRET || '';
const OWNER_ROBLOX_USER_ID = String(process.env.OWNER_ROBLOX_USER_ID || '9262435668');
const ADMIN_SESSION_COOKIE = 'dss_admin_session';
const ADMIN_SESSION_MS = 8 * 60 * 60 * 1000;
const DATABASE_URL = process.env.DATABASE_URL || '';

const MAX_FILE_SIZE = 50 * 1024 * 1024;
const CHUNK_SIZE = 2 * 1024 * 1024;

const IMAGE_TYPES = [
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/gif'
];

const DOWNLOAD_TYPES = [
  'application/zip',
  'application/x-zip-compressed',
  'application/octet-stream',
  'application/x-rbxm',
  'application/x-rbxl',
  'application/x-7z-compressed',
  'application/pdf',
  'text/plain',
  'application/json',
  'application/gzip',
  'application/x-tar'
];

if (API_SECRET.length < 32) {
  throw new Error('FATAL: API_SECRET wajib tersedia dan minimal 32 karakter.');
}

if (!/^\d{1,20}$/.test(OWNER_ROBLOX_USER_ID)) {
  throw new Error('FATAL: OWNER_ROBLOX_USER_ID tidak valid.');
}

if (!DATABASE_URL) {
  throw new Error('FATAL: DATABASE_URL wajib tersedia.');
}

// ============================================================
// DATABASE
// ============================================================

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

let dbInitPromise = null;

// ============================================================
// RATE LIMIT
// ============================================================

const rateBuckets = new Map();

function rateLimit({ windowMs = 60000, max = 30 } = {}) {
  return (req, res, next) => {
    const now = Date.now();
    const key = `${req.ip || req.socket.remoteAddress || 'unknown'}:${req.path}`;
    let item = rateBuckets.get(key);

    if (!item || item.resetAt <= now) {
      item = { count: 0, resetAt: now + windowMs };
    }

    item.count += 1;
    rateBuckets.set(key, item);

    if (rateBuckets.size > 5000) {
      for (const [k, v] of rateBuckets) {
        if (v.resetAt <= now) rateBuckets.delete(k);
      }
    }

    res.setHeader('RateLimit-Limit', String(max));
    res.setHeader('RateLimit-Remaining', String(Math.max(0, max - item.count)));

    if (item.count > max) {
      res.setHeader('Retry-After', String(Math.max(1, Math.ceil((item.resetAt - now) / 1000))));
      return res.status(429).json({
        success: false,
        code: 'RATE_LIMITED',
        message: 'Terlalu banyak permintaan. Coba lagi beberapa saat.'
      });
    }

    next();
  };
}

// ============================================================
// SECURITY HELPERS
// ============================================================

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && aa.length > 0 && crypto.timingSafeEqual(aa, bb);
}

function requireSameOrigin(req, res, next) {
  const origin = req.get('origin');
  if (!origin) {
    return res.status(403).json({ success: false, message: 'Origin wajib dikirim.' });
  }
  try {
    const u = new URL(origin);
    if (u.host !== req.get('host') && !['localhost', '127.0.0.1'].includes(u.hostname)) {
      return res.status(403).json({ success: false, message: 'Origin tidak diizinkan.' });
    }
  } catch {
    return res.status(403).json({ success: false, message: 'Origin tidak valid.' });
  }
  next();
}

function adminSessionSignature(expiresAt) {
  return crypto.createHmac('sha256', API_SECRET).update(`dss-admin:${OWNER_ROBLOX_USER_ID}:${expiresAt}`).digest('hex');
}

function readCookie(req, name) {
  try {
    const raw = req.headers.cookie || '';
    for (const part of raw.split(';')) {
      const i = part.indexOf('=');
      if (i < 0) continue;
      if (part.slice(0, i).trim() === name) {
        return decodeURIComponent(part.slice(i + 1).trim());
      }
    }
    return '';
  } catch {
    return '';
  }
}

function hasValidAdminSession(req) {
  const token = readCookie(req, ADMIN_SESSION_COOKIE);
  const dot = token.indexOf('.');
  if (dot < 1) return false;

  const expiresAt = token.slice(0, dot);
  const signature = token.slice(dot + 1);

  if (!/^\d{13}$/.test(expiresAt) || !/^[a-f0-9]{64}$/.test(signature)) return false;

  const expires = Number(expiresAt);
  const now = Date.now();

  if (!Number.isSafeInteger(expires) || expires <= now || expires > now + ADMIN_SESSION_MS + 60000) {
    return false;
  }

  return safeEqual(signature, adminSessionSignature(expiresAt));
}

function setAdminSessionCookie(req, res) {
  const expiresAt = String(Date.now() + ADMIN_SESSION_MS);
  const token = `${expiresAt}.${adminSessionSignature(expiresAt)}`;
  res.cookie(ADMIN_SESSION_COOKIE, token, {
    httpOnly: true,
    secure: req.secure || req.get('x-forwarded-proto') === 'https',
    sameSite: 'strict',
    path: '/',
    maxAge: ADMIN_SESSION_MS
  });
}

function verifyAdminSession(req, res, next) {
  if (!hasValidAdminSession(req)) {
    return res.status(401).json({ success: false, message: 'Sesi Admin tidak valid atau kedaluwarsa.' });
  }
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    return requireSameOrigin(req, res, next);
  }
  next();
}

function cleanText(v, max = 255) {
  return typeof v === 'string' ? v.trim().slice(0, max) : '';
}

function validHttpUrl(v) {
  if (v == null || v === '') return null;
  try {
    const u = new URL(v);
    return (u.protocol === 'https:' || u.protocol === 'http:') ? u.toString() : undefined;
  } catch {
    return undefined;
  }
}

function validExpiry(v) {
  if (v == null || v === '') return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

function safeFilename(v) {
  return path.basename(String(v || 'file')).replace(/[^a-zA-Z0-9._ -]/g, '_').slice(0, 140) || 'file';
}

// ============================================================
// ROBLOX API
// ============================================================

async function robloxFetch(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);

  try {
    const r = await fetch(url, { ...options, signal: controller.signal });
    if (!r.ok) {
      const error = new Error(`Roblox API HTTP ${r.status} (${new URL(url).hostname})`);
      error.statusCode = r.status;
      error.source = 'ROBLOX_API';
      throw error;
    }
    return await r.json();
  } catch (e) {
    if (e.name === 'AbortError') {
      const error = new Error(`Roblox API timeout setelah 8000ms: ${new URL(url).hostname}`);
      error.code = 'ROBLOX_TIMEOUT';
      error.source = 'ROBLOX_API';
      throw error;
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

async function getRobloxUserInfo(username) {
  const r = await robloxFetch('https://users.roblox.com/v1/usernames/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ usernames: [username], excludeBannedUsers: false })
  });

  const u = r?.data?.[0];
  if (!u || u.name.toLowerCase() !== username.toLowerCase()) return null;

  let avatarUrl = null;
  try {
    const t = await robloxFetch(`https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${u.id}&size=150x150&format=Png&isCircular=false`);
    avatarUrl = t?.data?.[0]?.imageUrl || null;
  } catch (e) {
    console.warn('[ROBLOX AVATAR] Avatar unavailable:', e.message);
  }

  return { userId: String(u.id), exactUsername: u.name, avatarUrl };
}

async function getPlaceCreator(placeId) {
  if (!/^\d{1,20}$/.test(String(placeId || ''))) {
    const e = new Error('place_id tidak valid');
    e.statusCode = 400;
    throw e;
  }

  let p;
  try {
    p = await robloxFetch(`https://apis.roblox.com/universes/v1/places/${encodeURIComponent(placeId)}/universe`);
  } catch (e) {
    throw new Error(`PLACE_TO_UNIVERSE_FAILED: ${e.message}`);
  }

  if (!p?.universeId || !/^\d{1,20}$/.test(String(p.universeId))) {
    throw new Error('UNIVERSE_ID_NOT_FOUND');
  }

  let g;
  try {
    g = await robloxFetch(`https://games.roblox.com/v1/games?universeIds=${encodeURIComponent(p.universeId)}`);
  } catch (e) {
    throw new Error(`UNIVERSE_OWNER_FAILED: ${e.message}`);
  }

  const c = g?.data?.[0]?.creator;
  const creatorType = String(c?.type || '');

  if (!c || !/^\d{1,20}$/.test(String(c.id || '')) || !['User', 'Group'].includes(creatorType)) {
    throw new Error('EXPERIENCE_CREATOR_NOT_FOUND');
  }

  return {
    placeId: String(placeId),
    universeId: String(p.universeId),
    creatorType,
    creatorId: String(c.id),
    creatorName: c.name || ''
  };
}

async function isUserInGroup(userId, groupId) {
  if (!/^\d{1,20}$/.test(String(userId)) || !/^\d{1,20}$/.test(String(groupId))) return false;
  const data = await robloxFetch(`https://groups.roblox.com/v2/users/${encodeURIComponent(userId)}/groups/roles`);
  return Array.isArray(data?.data) && data.data.some(x => String(x?.group?.id) === String(groupId));
}

// ============================================================
// DATABASE INITIALIZATION
// ============================================================

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS products(
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

    CREATE TABLE IF NOT EXISTS licenses(
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

    CREATE TABLE IF NOT EXISTS license_products(
      license_id BIGINT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
      product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
      PRIMARY KEY(license_id, product_id)
    );

    CREATE TABLE IF NOT EXISTS dss_upload_sessions(
      id VARCHAR(64) PRIMARY KEY,
      kind VARCHAR(16) NOT NULL,
      filename TEXT NOT NULL,
      content_type TEXT NOT NULL,
      total_size BIGINT NOT NULL,
      chunk_count INTEGER NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS dss_file_tickets(
      token_hash VARCHAR(64) PRIMARY KEY,
      product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
      kind VARCHAR(16) NOT NULL,
      owner_user_id VARCHAR(32),
      license_id BIGINT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS project_experiences(
      place_id VARCHAR(32) PRIMARY KEY,
      universe_id VARCHAR(32),
      product_id BIGINT REFERENCES products(id) ON DELETE SET NULL,
      product_name VARCHAR(120),
      owner_id VARCHAR(32),
      creator_type VARCHAR(16),
      creator_id VARCHAR(32),
      creator_name VARCHAR(120),
      license_id BIGINT REFERENCES licenses(id) ON DELETE SET NULL,
      last_ping TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  console.log('[DSS DATABASE] PostgreSQL schema ready.');
}

app.use(async (_req, res, next) => {
  try {
    if (!dbInitPromise) dbInitPromise = initDB();
    await dbInitPromise;
    next();
  } catch (err) {
    dbInitPromise = null;
    res.status(503).json({
      success: false,
      code: 'DATABASE_UNAVAILABLE',
      message: 'Database belum siap.'
    });
  }
});

// ============================================================
// HEALTH & HOME
// ============================================================

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'DSS STUDIO LICENSE' });
  } catch {
    res.status(503).json({ ok: false });
  }
});

// ============================================================
// LICENSE VALIDATION HELPERS
// ============================================================

async function findValidLicense(username, key) {
  const user = await getRobloxUserInfo(username);
  if (!user) return { error: 'Username Roblox tidak ditemukan.', status: 404 };

  const { rows } = await pool.query(
    `
    SELECT l.* FROM licenses l
    WHERE l.license_key=$1
      AND l.is_active=TRUE
      AND (l.expires_at IS NULL OR l.expires_at>NOW())
      AND ((l.group_id IS NULL AND l.owner_user_id=$2) OR l.group_id IS NOT NULL)
    LIMIT 1
    `,
    [key, user.userId]
  );

  if (!rows.length) {
    return { error: 'Key salah, tidak aktif, atau kedaluwarsa.', status: 401 };
  }

  const license = rows[0];
  if (license.group_id) {
    try {
      if (!await isUserInGroup(user.userId, license.group_id)) {
        return { error: 'Akun bukan anggota grup pemegang lisensi.', status: 403 };
      }
    } catch {
      return { error: 'Gagal memverifikasi grup.', status: 503 };
    }
  }

  return { user, license };
}

async function listLicenseProducts(id) {
  const { rows } = await pool.query(
    `
    SELECT p.id, p.product_code, p.product_name, p.description, p.image_url, p.download_url,
           p.image_path, p.download_path, p.is_active product_active
    FROM license_products lp
    JOIN products p ON p.id=lp.product_id
    WHERE lp.license_id=$1
    `,
    [id]
  );
  return rows;
}

// ============================================================
// CLIENT LOGIN / PORTAL
// ============================================================

async function clientLoginHandler(req, res) {
  const username = cleanText(req.body?.owner_name, 64);
  const key = cleanText(req.body?.license_key, 255);

  if (!username || !key) {
    return res.status(400).json({ success: false, message: 'Username dan Key wajib diisi.' });
  }

  try {
    const v = await findValidLicense(username, key);
    if (v.error) return res.status(v.status).json({ success: false, message: v.error });

    const products = await listLicenseProducts(v.license.id);
    res.json({
      success: true,
      avatar_url: v.user.avatarUrl,
      owner_name: v.user.exactUsername,
      owner_user_id: v.user.userId,
      license: { id: v.license.id, license_key: v.license.license_key, expires_at: v.license.expires_at, is_active: v.license.is_active },
      data: products.filter(p => p.product_active).map(p => ({
        id: p.id,
        product: p.product_name,
        product_code: p.product_code,
        is_active: v.license.is_active
      }))
    });
  } catch {
    res.status(502).json({ success: false, message: 'Gagal menghubungi server.' });
  }
}

app.post('/api/client-login', rateLimit({ windowMs: 60000, max: 10 }), clientLoginHandler);
app.post('/api/client-refresh', rateLimit({ windowMs: 60000, max: 20 }), clientLoginHandler);

// ============================================================
// GAME LICENSE VERIFICATION (LOADER V5 - FIXED REVOCATION CHECK)
// ============================================================

app.post(
  '/api/game-verify',
  rateLimit({ windowMs: 60000, max: 30 }),
  async (req, res) => {
    const placeId = cleanText(String(req.body?.place_id ?? ''), 20);
    const productName = cleanText(req.body?.product_name, 120);
    const claimedType = cleanText(req.body?.creator_type, 16);

    if (!/^\d{1,20}$/.test(placeId) || !productName) {
      return res.status(400).json({
        success: false,
        authorized: false,
        code: 'BAD_REQUEST',
        message: 'place_id dan product_name wajib valid.'
      });
    }

    try {
      // 1. Dapatkan data pembuat tempat dari Roblox API
      const creator = await getPlaceCreator(placeId);

      if (claimedType && claimedType.toLowerCase() !== creator.creatorType.toLowerCase()) {
        return res.json({
          success: true,
          authorized: false,
          code: 'CREATOR_TYPE_MISMATCH',
          message: 'Tipe pemilik experience tidak cocok.'
        });
      }

      const isGroup = creator.creatorType === 'Group';

      // 2. Kueri Database: Wajib memastikan is_active = TRUE baik di license maupun product.
      // Jika lisensi dihapus atau di-nonaktifkan, kueri ini otomatis mengembalikan rows kosong!
      const { rows } = await pool.query(
        `
        SELECT l.id AS license_id, l.is_active, p.product_name, p.product_code
        FROM licenses l
        JOIN license_products lp ON lp.license_id = l.id
        JOIN products p ON p.id = lp.product_id
        WHERE l.is_active = TRUE
          AND p.is_active = TRUE
          AND (l.expires_at IS NULL OR l.expires_at > NOW())
          AND LOWER(BTRIM(p.product_name)) = LOWER($1)
          AND (
            ($2::boolean = TRUE AND l.group_id = $3)
            OR
            ($2::boolean = FALSE AND l.group_id IS NULL AND l.owner_user_id = $3)
          )
        ORDER BY l.created_at DESC
        LIMIT 1
        `,
        [productName, isGroup, creator.creatorId]
      );

      // Jika lisensi sudah dicabut/dihapus, rows.length akan 0
      if (!rows.length) {
        // Hapus juga riwayat ping experience dari database agar sinkron
        await pool.query('DELETE FROM project_experiences WHERE place_id = $1', [placeId]).catch(() => {});

        return res.json({
          success: true,
          authorized: false, // <-- INI YANG MEMBUAT GAME LANGSUNG MATI DI STUDIO/PUBLIK
          code: 'NOT_LICENSED',
          message: 'Lisensi tidak aktif atau telah dicabut.'
        });
      }

      const lic = rows[0];

      // 3. Simpan atau perbarui status project aktif
      await pool.query(
        `
        INSERT INTO project_experiences(
          place_id, universe_id, product_id, product_name, owner_id, creator_type, creator_id, creator_name, license_id, last_ping, updated_at
        ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW(),NOW())
        ON CONFLICT(place_id) DO UPDATE SET
          universe_id = EXCLUDED.universe_id,
          product_id = EXCLUDED.product_id,
          product_name = EXCLUDED.product_name,
          owner_id = EXCLUDED.owner_id,
          creator_type = EXCLUDED.creator_type,
          creator_id = EXCLUDED.creator_id,
          creator_name = EXCLUDED.creator_name,
          license_id = EXCLUDED.license_id,
          last_ping = NOW(),
          updated_at = NOW()
        `,
        [
          creator.placeId,
          creator.universeId,
          lic.product_id,
          lic.product_name,
          creator.creatorId,
          creator.creatorType,
          creator.creatorId,
          creator.creatorName,
          lic.license_id
        ]
      ).catch(() => {});

      return res.json({
        success: true,
        authorized: true,
        code: 'AUTHORIZED',
        message: 'Lisensi valid.'
      });

    } catch (e) {
      return res.status(503).json({
        success: false,
        authorized: false,
        code: 'VERIFY_UNAVAILABLE',
        message: 'Gagal memverifikasi ke server.'
      });
    }
  }
);

// ============================================================
// ADMIN ENDPOINTS & OTHER ROUTINGS (DIPERTAHANKAN)
// ============================================================

app.get('/api/licenses', verifyAdminSession, async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT l.*, COALESCE(json_agg(json_build_object('id', p.id, 'product_name', p.product_name)) FILTER(WHERE p.id IS NOT NULL), '[]'::json) products
      FROM licenses l
      LEFT JOIN license_products lp ON lp.license_id = l.id
      LEFT JOIN products p ON p.id = lp.product_id
      GROUP BY l.id ORDER BY l.created_at DESC
    `);
    res.json({ success: true, licenses: rows });
  } catch {
    res.status(500).json({ success: false, message: 'Gagal mengambil data lisensi.' });
  }
});

app.patch('/api/licenses/:id/status', verifyAdminSession, async (req, res) => {
  const id = cleanText(req.params.id, 20);
  const isActive = req.body?.is_active;

  if (!/^\d+$/.test(id) || typeof isActive !== 'boolean') {
    return res.status(400).json({ success: false, message: 'Data tidak valid.' });
  }

  try {
    const { rows } = await pool.query(
      'UPDATE licenses SET is_active = $1 WHERE id = $2 RETURNING id, is_active',
      [isActive, id]
    );

    if (!rows.length) {
      return res.status(404).json({ success: false, message: 'Lisensi tidak ditemukan.' });
    }

    // Jika lisensi dimatikan, hapus data experience dari project_experiences agar langsung terblokir
    if (!isActive) {
      await pool.query('DELETE FROM project_experiences WHERE license_id = $1', [id]).catch(() => {});
    }

    res.json({ success: true, license: rows[0] });
  } catch {
    res.status(500).json({ success: false, message: 'Gagal mengubah status lisensi.' });
  }
});

// Middleware & Server Listener
let server;
if (require.main === module) {
  server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`DSS STUDIO LICENSE listening on port ${PORT}`);
  });
}

module.exports = app;
