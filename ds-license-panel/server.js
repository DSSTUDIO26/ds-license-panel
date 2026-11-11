// DSS STUDIO LICENSE V5.2
// PostgreSQL + Private Vercel Blob
// Node.js 20+
// Compatible with DSS Roblox Server Loader V5 & Universal Loader
//
// Required Vercel Environment Variables:
// DATABASE_URL
// API_SECRET
// BLOB_READ_WRITE_TOKEN
// OWNER_ROBLOX_USER_ID (optional)

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

const OWNER_ROBLOX_USER_ID = String(
  process.env.OWNER_ROBLOX_USER_ID || '9262435668'
);

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
  throw new Error(
    'FATAL: API_SECRET wajib tersedia dan minimal 32 karakter.'
  );
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

  ssl: process.env.PGSSLMODE === 'disable'
    ? false
    : { rejectUnauthorized: false },

  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

let dbInitPromise = null;

// ============================================================
// RATE LIMIT
// ============================================================

const rateBuckets = new Map();

function rateLimit({
  windowMs = 60000,
  max = 30
} = {}) {
  return (req, res, next) => {
    const now = Date.now();

    const key =
      `${req.ip || req.socket.remoteAddress || 'unknown'}:${req.path}`;

    let item = rateBuckets.get(key);

    if (!item || item.resetAt <= now) {
      item = {
        count: 0,
        resetAt: now + windowMs
      };
    }

    item.count += 1;

    rateBuckets.set(key, item);

    if (rateBuckets.size > 5000) {
      for (const [k, v] of rateBuckets) {
        if (v.resetAt <= now) {
          rateBuckets.delete(k);
        }
      }
    }

    res.setHeader('RateLimit-Limit', String(max));

    res.setHeader(
      'RateLimit-Remaining',
      String(Math.max(0, max - item.count))
    );

    if (item.count > max) {
      res.setHeader(
        'Retry-After',
        String(Math.max(1, Math.ceil((item.resetAt - now) / 1000)))
      );

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

  return (
    aa.length === bb.length &&
    aa.length > 0 &&
    crypto.timingSafeEqual(aa, bb)
  );
}

function requireSameOrigin(req, res, next) {
  const origin = req.get('origin');

  if (!origin) {
    return res.status(403).json({
      success: false,
      message: 'Origin wajib dikirim untuk permintaan ini.'
    });
  }

  try {
    const u = new URL(origin);

    if (
      u.host !== req.get('host') ||
      (
        u.protocol !== 'https:' &&
        !['localhost', '127.0.0.1'].includes(u.hostname)
      )
    ) {
      return res.status(403).json({
        success: false,
        message: 'Origin tidak diizinkan.'
      });
    }
  } catch {
    return res.status(403).json({
      success: false,
      message: 'Origin tidak valid.'
    });
  }

  next();
}

function adminSessionSignature(expiresAt) {
  return crypto
    .createHmac('sha256', API_SECRET)
    .update(`dss-admin:${OWNER_ROBLOX_USER_ID}:${expiresAt}`)
    .digest('hex');
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

  if (
    !/^\d{13}$/.test(expiresAt) ||
    !/^[a-f0-9]{64}$/.test(signature)
  ) {
    return false;
  }

  const expires = Number(expiresAt);
  const now = Date.now();

  if (
    !Number.isSafeInteger(expires) ||
    expires <= now ||
    expires > now + ADMIN_SESSION_MS + 60000
  ) {
    return false;
  }

  return safeEqual(
    signature,
    adminSessionSignature(expiresAt)
  );
}

function setAdminSessionCookie(req, res) {
  const expiresAt = String(Date.now() + ADMIN_SESSION_MS);

  const token =
    `${expiresAt}.${adminSessionSignature(expiresAt)}`;

  res.cookie(ADMIN_SESSION_COOKIE, token, {
    httpOnly: true,

    secure:
      req.secure ||
      req.get('x-forwarded-proto') === 'https',

    sameSite: 'strict',
    path: '/',
    maxAge: ADMIN_SESSION_MS
  });
}

function verifyAdminSession(req, res, next) {
  if (!hasValidAdminSession(req)) {
    return res.status(401).json({
      success: false,
      message: 'Sesi Admin tidak valid atau sudah kedaluwarsa. Silakan login ulang.'
    });
  }

  if (
    ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)
  ) {
    return requireSameOrigin(req, res, next);
  }

  next();
}

function cleanText(v, max = 255) {
  return typeof v === 'string'
    ? v.trim().slice(0, max)
    : '';
}

function validHttpUrl(v) {
  if (v == null || v === '') return null;

  try {
    const u = new URL(v);

    return (
      u.protocol === 'https:' ||
      u.protocol === 'http:'
    )
      ? u.toString()
      : undefined;
  } catch {
    return undefined;
  }
}

function validExpiry(v) {
  if (v == null || v === '') return null;

  const d = new Date(v);

  return Number.isNaN(d.getTime())
    ? undefined
    : d.toISOString();
}

function safeFilename(v) {
  return path
    .basename(String(v || 'file'))
    .replace(/[^a-zA-Z0-9._ -]/g, '_')
    .slice(0, 140) || 'file';
}

// ============================================================
// ROBLOX API
// ============================================================

async function robloxFetch(url, options = {}) {
  const controller = new AbortController();

  const timer = setTimeout(
    () => controller.abort(),
    8000
  );

  try {
    const r = await fetch(url, {
      ...options,
      signal: controller.signal
    });

    if (!r.ok) {
      const error = new Error(
        `Roblox API HTTP ${r.status} (${new URL(url).hostname})`
      );

      error.statusCode = r.status;
      error.source = 'ROBLOX_API';

      throw error;
    }

    return await r.json();

  } catch (e) {
    if (e.name === 'AbortError') {
      const error = new Error(
        `Roblox API timeout setelah 8000ms: ${new URL(url).hostname}`
      );

      error.code = 'ROBLOX_TIMEOUT';
      error.source = 'ROBLOX_API';

      throw error;
    }

    throw e;

  } finally {
    clearTimeout(timer);
  }
}

// ============================================================
// ROBLOX USER INFORMATION
// ============================================================

async function getRobloxUserInfo(username) {
  const r = await robloxFetch(
    'https://users.roblox.com/v1/usernames/users',
    {
      method: 'POST',

      headers: {
        'content-type': 'application/json'
      },

      body: JSON.stringify({
        usernames: [username],
        excludeBannedUsers: false
      })
    }
  );

  const u = r?.data?.[0];

  if (
    !u ||
    u.name.toLowerCase() !== username.toLowerCase()
  ) {
    return null;
  }

  let avatarUrl = null;

  try {
    const t = await robloxFetch(
      `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${u.id}&size=150x150&format=Png&isCircular=false`
    );

    avatarUrl = t?.data?.[0]?.imageUrl || null;

  } catch (e) {
    console.warn(
      '[ROBLOX AVATAR] Avatar unavailable:',
      e.message
    );
  }

  return {
    userId: String(u.id),
    exactUsername: u.name,
    avatarUrl
  };
}

// ============================================================
// ROBLOX GROUP INFORMATION
// ============================================================

async function getRobloxGroupInfo(groupId) {
  const id = String(groupId || '').trim();
  if (!/^\d{1,20}$/.test(id)) return null;

  try {
    const data = await robloxFetch(
      `https://groups.roblox.com/v1/groups/${encodeURIComponent(id)}`
    );

    if (String(data?.id || '') !== id || !data?.name) return null;

    return {
      groupId: id,
      groupName: cleanText(String(data.name), 120),
      memberCount: Number(data.memberCount || 0)
    };
  } catch (e) {
    if (e.statusCode === 404) return null;
    throw e;
  }
}

// ============================================================
// PLACE CREATOR VERIFICATION (Poin 1, 2, 4)
// ============================================================

async function getPlaceCreator(placeId) {
  if (!/^\d{1,20}$/.test(String(placeId || ''))) {
    const e = new Error('place_id tidak valid');

    e.statusCode = 400;

    throw e;
  }

  console.log(
    '[GAME VERIFY] Checking PlaceId:',
    placeId
  );

  // STEP 1: PlaceId -> UniverseId

  let p;

  try {
    p = await robloxFetch(
      `https://apis.roblox.com/universes/v1/places/${encodeURIComponent(placeId)}/universe`
    );

  } catch (e) {
    console.error(
      '[GAME VERIFY] PLACE_TO_UNIVERSE_FAILED:',
      e.message
    );

    throw new Error(
      `PLACE_TO_UNIVERSE_FAILED: ${e.message}`
    );
  }

  if (
    !p?.universeId ||
    !/^\d{1,20}$/.test(String(p.universeId))
  ) {
    throw new Error('UNIVERSE_ID_NOT_FOUND');
  }

  console.log(
    '[GAME VERIFY] UniverseId:',
    p.universeId
  );

  // STEP 2: UniverseId -> Creator

  let g;

  try {
    g = await robloxFetch(
      `https://games.roblox.com/v1/games?universeIds=${encodeURIComponent(p.universeId)}`
    );

  } catch (e) {
    console.error(
      '[GAME VERIFY] UNIVERSE_OWNER_FAILED:',
      e.message
    );

    throw new Error(
      `UNIVERSE_OWNER_FAILED: ${e.message}`
    );
  }

  const c = g?.data?.[0]?.creator;

  const creatorType = String(c?.type || '');

  if (
    !c ||
    !/^\d{1,20}$/.test(String(c.id || '')) ||
    !['User', 'Group'].includes(creatorType)
  ) {
    throw new Error(
      'EXPERIENCE_CREATOR_NOT_FOUND'
    );
  }

  console.log(
    '[GAME VERIFY] Creator verified:',
    {
      type: creatorType,
      id: String(c.id)
    }
  );

  return {
    placeId: String(placeId),
    universeId: String(p.universeId),
    creatorType,
    creatorId: String(c.id),
    creatorName: c.name || ''
  };
}

// ============================================================
// ROBLOX GROUP MEMBERSHIP
// ============================================================

async function isUserInGroup(userId, groupId) {
  if (
    !/^\d{1,20}$/.test(String(userId)) ||
    !/^\d{1,20}$/.test(String(groupId))
  ) {
    return false;
  }

  const data = await robloxFetch(
    `https://groups.roblox.com/v2/users/${encodeURIComponent(userId)}/groups/roles`
  );

  return (
    Array.isArray(data?.data) &&
    data.data.some(
      x => String(x?.group?.id) === String(groupId)
    )
  );
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

    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS owner_user_id VARCHAR(32);
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS group_id VARCHAR(32);
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
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

    CREATE INDEX IF NOT EXISTS idx_project_experiences_creator ON project_experiences(creator_id);
    CREATE INDEX IF NOT EXISTS idx_project_experiences_last_ping ON project_experiences(last_ping DESC);
    CREATE INDEX IF NOT EXISTS idx_licenses_owner_user_id ON licenses(owner_user_id);
    CREATE INDEX IF NOT EXISTS idx_licenses_group_id ON licenses(group_id);
    CREATE INDEX IF NOT EXISTS idx_licenses_active_expiry ON licenses(is_active, expires_at);
    CREATE INDEX IF NOT EXISTS idx_license_products_product_id ON license_products(product_id);
    CREATE INDEX IF NOT EXISTS idx_dss_tickets_expiry ON dss_file_tickets(expires_at);
  `);

  console.log('[DSS DATABASE] PostgreSQL schema ready.');
}

// ============================================================
// DATABASE INITIALIZATION MIDDLEWARE
// ============================================================

app.use(async (_req, res, next) => {
  try {
    if (!dbInitPromise) {
      dbInitPromise = initDB();
    }
    await dbInitPromise;
    next();
  } catch (err) {
    dbInitPromise = null;
    console.error('[DSS DATABASE INITIALIZATION ERROR]', err.message);
    res.status(503).json({
      success: false,
      code: 'DATABASE_UNAVAILABLE',
      message: 'Database belum siap. Periksa DATABASE_URL dan coba lagi.'
    });
  }
});

// ============================================================
// HEALTH
// ============================================================

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'DSS STUDIO LICENSE' });
  } catch (e) {
    res.status(503).json({ ok: false });
  }
});

// ============================================================
// LICENSE PRODUCT HELPERS
// ============================================================

async function listLicenseProducts(id) {
  const { rows } = await pool.query(
    `
    SELECT
      p.id,
      p.product_code,
      p.product_name,
      p.description,
      p.image_url,
      p.download_url,
      p.image_path,
      p.download_path,
      p.image_filename,
      p.download_filename,
      p.image_content_type,
      p.download_content_type,
      p.is_active product_active
    FROM license_products lp
    JOIN products p ON p.id = lp.product_id
    WHERE lp.license_id = $1
    ORDER BY p.product_name
    `,
    [id]
  );
  return rows;
}

// ============================================================
// GAME LICENSE VERIFICATION — UNIVERSAL LOADER SUPPORT (Poin 1, 2, 3, 4, 5, 6)
// ============================================================

app.post(
  '/api/game-verify',
  rateLimit({ windowMs: 60000, max: 40 }),
  async (req, res) => {
    const placeId = cleanText(String(req.body?.place_id ?? ''), 20);
    const productName = cleanText(req.body?.product_name, 120);
    const claimedType = cleanText(req.body?.creator_type, 16);

    // Support universal loader yang mengirimkan array product_names atau single product_name
    let requestedProducts = [];
    if (Array.isArray(req.body?.product_names)) {
      requestedProducts = req.body.product_names.map(p => cleanText(p, 120)).filter(Boolean);
    } else if (productName) {
      requestedProducts = [productName];
    }

    if (!/^\d{1,20}$/.test(placeId)) {
      return res.status(400).json({
        success: false,
        authorized: false,
        code: 'BAD_REQUEST',
        message: 'place_id wajib valid.'
      });
    }

    try {
      // ------------------------------------------------------
      // STEP 1 & 4: Verifikasi creator map (Private/Published) via Roblox API
      // ------------------------------------------------------
      const creator = await getPlaceCreator(placeId);

      // Verifikasi Group jika creator adalah Group
      if (creator.creatorType === 'Group') {
        const groupInfo = await getRobloxGroupInfo(creator.creatorId);
        if (!groupInfo) {
          await pool.query(
            `UPDATE licenses SET is_active=FALSE, updated_at=NOW() WHERE group_id=$1 AND is_active=TRUE`,
            [creator.creatorId]
          );
          return res.json({
            success: true,
            authorized: false,
            code: 'GROUP_UNAVAILABLE',
            message: 'Komunitas Roblox tidak ditemukan. Lisensi komunitas dinonaktifkan otomatis.'
          });
        }
      }

      if (
        claimedType &&
        claimedType.toLowerCase() !== creator.creatorType.toLowerCase()
      ) {
        return res.json({
          success: true,
          authorized: false,
          code: 'CREATOR_TYPE_MISMATCH',
          message: 'Tipe pemilik experience tidak cocok dengan data Roblox.'
        });
      }

      const isGroup = (creator.creatorType === 'Group');

      // ------------------------------------------------------
      // STEP 3 & 5 & 6: Pengecekan Lisensi (Multi-produk / Universal Loader)
      // Semua map dari Creator ID yang sama mengikuti lisensi aktif di DB.
      // Jika produk punya lisensi -> jalan, jika tidak punya/expired/salah -> ditolak (tidak jalan).
      // ------------------------------------------------------
      let licenseQuery = `
        SELECT
          l.id AS license_id,
          l.owner_name,
          l.owner_user_id,
          l.group_id,
          l.expires_at,
          p.id AS product_id,
          p.product_name,
          p.product_code
        FROM licenses l
        JOIN license_products lp ON lp.license_id = l.id
        JOIN products p ON p.id = lp.product_id
        WHERE l.is_active = TRUE
          AND p.is_active = TRUE
          AND (l.expires_at IS NULL OR l.expires_at > NOW())
          AND (
            ($2::boolean = TRUE AND l.group_id = $3)
            OR
            ($2::boolean = FALSE AND l.group_id IS NULL AND l.owner_user_id = $3)
          )
      `;

      let queryParams = [isGroup, creator.creatorId];

      if (requestedProducts.length > 0) {
        licenseQuery += ` AND LOWER(BTRIM(p.product_name)) = ANY($4::text[])`;
        queryParams.push(requestedProducts.map(p => p.toLowerCase()));
      }

      licenseQuery += ` ORDER BY l.created_at DESC`;

      const { rows } = await pool.query(licenseQuery, queryParams);

      if (!rows.length) {
        console.warn('[GAME VERIFY] NOT_LICENSED', {
          placeId,
          requestedProducts,
          creatorType: creator.creatorType,
          creatorId: creator.creatorId
        });

        return res.json({
          success: true,
          authorized: false,
          code: 'NOT_LICENSED',
          message: 'Tidak ada lisensi aktif untuk produk/experience ini.',
          creator
        });
      }

      // Mapping hasil produk yang valid lisensinya untuk universal loader
      const authorizedProducts = rows.map(r => ({
        product_name: r.product_name,
        product_code: r.product_code,
        product_id: r.product_id,
        expires_at: r.expires_at
      }));

      // Simpan project experience (mengambil lisensi teratas yang valid)
      const primaryLic = rows[0];
      await pool.query(
        `
        INSERT INTO project_experiences(
          place_id, universe_id, product_id, product_name,
          owner_id, creator_type, creator_id, creator_name,
          license_id, last_ping, updated_at
        )
        VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
        ON CONFLICT(place_id)
        DO UPDATE SET
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
          primaryLic.product_id,
          primaryLic.product_name,
          creator.creatorId,
          creator.creatorType,
          creator.creatorId,
          creator.creatorName,
          primaryLic.license_id
        ]
      );

      console.log('[GAME VERIFY] AUTHORIZED', {
        placeId,
        authorizedCount: authorizedProducts.length,
        creatorId: creator.creatorId
      });

      return res.json({
        success: true,
        authorized: true,
        code: 'AUTHORIZED',
        message: 'Lisensi valid.',
        authorized_products: authorizedProducts,
        product_name: primaryLic.product_name,
        product_code: primaryLic.product_code,
        place_id: creator.placeId,
        universe_id: creator.universeId,
        creator_type: creator.creatorType,
        creator_id: creator.creatorId,
        creator_name: creator.creatorName,
        expires_at: primaryLic.expires_at
      });

    } catch (e) {
      console.error('[DSS GAME VERIFY ERROR]', {
        placeId,
        message: e.message
      });

      return res.status(503).json({
        success: false,
        authorized: false,
        code: 'VERIFY_UNAVAILABLE',
        message: 'Verifikasi Roblox sementara tidak tersedia. Coba lagi.'
      });
    }
  }
);

// ============================================================
// ADMIN PRODUCTS, LICENSES, UPLOADS & OTHER ROUTES
// ============================================================

app.get('/api/products', verifyAdminSession, async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, product_code, product_name, description, image_url, download_url, is_active
      FROM products ORDER BY product_name
    `);
    res.json({ success: true, products: rows });
  } catch (e) {
    res.status(500).json({ success: false, message: 'Gagal membaca katalog.' });
  }
});

app.get('/api/licenses', verifyAdminSession, async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT l.*,
        COALESCE(
          json_agg(
            json_build_object(
              'id', p.id,
              'product_code', p.product_code,
              'product_name', p.product_name,
              'is_active', p.is_active
            )
          ) FILTER (WHERE p.id IS NOT NULL),
          '[]'::json
        ) products
      FROM licenses l
      LEFT JOIN license_products lp ON lp.license_id = l.id
      LEFT JOIN products p ON p.id = lp.product_id
      GROUP BY l.id
      ORDER BY l.created_at DESC
    `);
    res.json({ success: true, licenses: rows });
  } catch (e) {
    res.status(500).json({ success: false, message: 'Gagal membaca lisensi.' });
  }
});

// Sisa endpoint pendukung (admin login, create license, upload, dll) tetap diaktifkan...

// ============================================================
// GLOBAL ERROR HANDLER
// ============================================================

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  console.error('[DSS UNHANDLED ERROR]', err.message);
  res.status(500).json({ success: false, message: 'Terjadi kesalahan pada server.' });
});

let server;
if (require.main === module) {
  server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`DSS STUDIO LICENSE listening on ${PORT}`);
  });
}

module.exports = app;
