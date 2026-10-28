
 // DSS STUDIO LICENSE — PostgreSQL + private Vercel Blob
// Node.js 20+. Keep DATABASE_URL, API_SECRET, and BLOB_READ_WRITE_TOKEN in Vercel Environment Variables.

'use strict';

const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');
const { put, get, del } = require('@vercel/blob');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(express.json({ limit: '3mb' }));
app.use(express.static(__dirname, { index: false, maxAge: '1h' }));

let dbInitPromise;

// Initialize database schema once per warm serverless instance.
// IMPORTANT: This function must NOT create products from license names.
app.use(async (_req, res, next) => {
  try {
    if (!dbInitPromise) {
      dbInitPromise = initDB().catch((err) => {
        // Allow a later request to retry initialization after failure.
        dbInitPromise = null;
        throw err;
      });
    }

    await dbInitPromise;
    next();
  } catch (err) {
    console.error('Database initialization error:', err.message);
    res.status(503).json({
      success: false,
      message: 'Database belum siap. Periksa DATABASE_URL dan coba lagi.'
    });
  }
});

const PORT = Number(process.env.PORT || 3000);
const API_SECRET = process.env.API_SECRET || '';
const OWNER_ROBLOX_USER_ID = String(
  process.env.OWNER_ROBLOX_USER_ID || '9262435668'
);

const ADMIN_SESSION_COOKIE = 'dss_admin_session';
const ADMIN_SESSION_MS = 8 * 60 * 60 * 1000;
const DATABASE_URL = process.env.DATABASE_URL || '';

if (API_SECRET.length < 32) {
  console.error('FATAL: API_SECRET must be at least 32 characters.');
  if (require.main === module) process.exit(1);
}

if (!DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is required.');
  if (require.main === module) process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === 'disable'
    ? false
    : { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

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

// ------------------------------------------------------------
// Basic routes
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Security helpers
// ------------------------------------------------------------

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));

  return aa.length === bb.length &&
    aa.length > 0 &&
    crypto.timingSafeEqual(aa, bb);
}

function adminSessionSignature(expiresAt) {
  return crypto
    .createHmac('sha256', API_SECRET)
    .update(`dss-admin:${OWNER_ROBLOX_USER_ID}:${expiresAt}`)
    .digest('hex');
}

function readCookie(req, name) {
  const raw = req.headers.cookie || '';

  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;

    if (part.slice(0, i).trim() === name) {
      try {
        return decodeURIComponent(part.slice(i + 1).trim());
      } catch {
        return '';
      }
    }
  }

  return '';
}

function hasValidAdminSession(req) {
  const token = readCookie(req, ADMIN_SESSION_COOKIE);
  const dot = token.indexOf('.');

  if (dot < 1) return false;

  const expiresAt = token.slice(0, dot);
  const signature = token.slice(dot + 1);

  if (!/^\d{13}$/.test(expiresAt)) return false;
  if (!/^[a-f0-9]{64}$/.test(signature)) return false;

  const expires = Number(expiresAt);
  const now = Date.now();

  if (!Number.isSafeInteger(expires)) return false;
  if (expires <= now) return false;
  if (expires > now + ADMIN_SESSION_MS + 60000) return false;

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
    return res.status(401).json({
      success: false,
      message: 'Sesi Admin tidak valid atau sudah kedaluwarsa. Silakan login ulang.'
    });
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

    return u.protocol === 'https:' || u.protocol === 'http:'
      ? u.toString()
      : undefined;
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
  return path.basename(String(v || 'file'))
    .replace(/[^a-zA-Z0-9._ -]/g, '_')
    .slice(0, 140) || 'file';
}

async function robloxFetch(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);

  try {
    const r = await fetch(url, {
      ...options,
      signal: controller.signal
    });

    if (!r.ok) {
      throw new Error(`Roblox API HTTP ${r.status}`);
    }

    return await r.json();
  } finally {
    clearTimeout(timer);
  }
}

async function getRobloxUserInfo(username) {
  const r = await robloxFetch(
    'https://users.roblox.com/v1/usernames/users',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        usernames: [username],
        excludeBannedUsers: false
      })
    }
  );

  const u = r?.data?.[0];

  if (!u || u.name.toLowerCase() !== username.toLowerCase()) {
    return null;
  }

  let avatarUrl = null;

  try {
    const t = await robloxFetch(
      `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${u.id}&size=150x150&format=Png&isCircular=false`
    );

    avatarUrl = t?.data?.[0]?.imageUrl || null;
  } catch {
    // Avatar is optional; login can still succeed.
  }

  return {
    userId: String(u.id),
    exactUsername: u.name,
    avatarUrl
  };
}

async function getPlaceCreator(placeId) {
  if (!/^\d{1,20}$/.test(String(placeId || ''))) {
    const e = new Error('place_id tidak valid');
    e.statusCode = 400;
    throw e;
  }

  const p = await robloxFetch(
    `https://apis.roblox.com/universes/v1/places/${encodeURIComponent(placeId)}/universe`
  );

  if (!p?.universeId) {
    throw new Error('Universe ID tidak ditemukan.');
  }

  const g = await robloxFetch(
    `https://games.roblox.com/v1/games?universeIds=${encodeURIComponent(p.universeId)}`
  );

  const c = g?.data?.[0]?.creator;

  if (!c) {
    throw new Error('Pemilik game tidak ditemukan.');
  }

  return {
    placeId: String(placeId),
    universeId: String(p.universeId),
    creatorType: c.type,
    creatorId: String(c.id),
    creatorName: c.name || ''
  };
}

// ------------------------------------------------------------
// Database initialization
// ------------------------------------------------------------

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

    ALTER TABLE licenses
      ADD COLUMN IF NOT EXISTS owner_user_id VARCHAR(32);

    ALTER TABLE licenses
      ADD COLUMN IF NOT EXISTS group_id VARCHAR(32);

    ALTER TABLE licenses
      ADD COLUMN IF NOT EXISTS product_name VARCHAR(120)
      DEFAULT 'General Product';

    ALTER TABLE licenses
      ADD COLUMN IF NOT EXISTS image_url TEXT;

    ALTER TABLE licenses
      ADD COLUMN IF NOT EXISTS download_url TEXT;

    ALTER TABLE licenses
      ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;

    ALTER TABLE licenses
      ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

    ALTER TABLE products
      ADD COLUMN IF NOT EXISTS image_path TEXT;

    ALTER TABLE products
      ADD COLUMN IF NOT EXISTS download_path TEXT;

    ALTER TABLE products
      ADD COLUMN IF NOT EXISTS image_filename TEXT;

    ALTER TABLE products
      ADD COLUMN IF NOT EXISTS download_filename TEXT;

    ALTER TABLE products
      ADD COLUMN IF NOT EXISTS image_content_type TEXT;

    ALTER TABLE products
      ADD COLUMN IF NOT EXISTS download_content_type TEXT;

    CREATE TABLE IF NOT EXISTS license_products (
      license_id BIGINT NOT NULL
        REFERENCES licenses(id) ON DELETE CASCADE,
      product_id BIGINT NOT NULL
        REFERENCES products(id) ON DELETE RESTRICT,
      PRIMARY KEY (license_id, product_id)
    );

    CREATE TABLE IF NOT EXISTS dss_upload_sessions (
      id VARCHAR(64) PRIMARY KEY,
      kind VARCHAR(16) NOT NULL,
      filename TEXT NOT NULL,
      content_type TEXT NOT NULL,
      total_size BIGINT NOT NULL,
      chunk_count INTEGER NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS dss_file_tickets (
      token_hash VARCHAR(64) PRIMARY KEY,
      product_id BIGINT NOT NULL
        REFERENCES products(id) ON DELETE CASCADE,
      kind VARCHAR(16) NOT NULL,
      owner_user_id VARCHAR(32),
      license_id BIGINT NOT NULL
        REFERENCES licenses(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_licenses_owner_user_id
      ON licenses(owner_user_id);

    CREATE INDEX IF NOT EXISTS idx_licenses_group_id
      ON licenses(group_id);

    CREATE INDEX IF NOT EXISTS idx_licenses_active_expiry
      ON licenses(is_active, expires_at);

    CREATE INDEX IF NOT EXISTS idx_license_products_product_id
      ON license_products(product_id);

    CREATE INDEX IF NOT EXISTS idx_dss_tickets_expiry
      ON dss_file_tickets(expires_at);
  `);

  // FIX: Do NOT automatically create catalog products from licenses.product_name.
  // FIX: Do NOT automatically link licenses to products by product_name.
  //
  // Products and their license relationships are managed explicitly through
  // POST /api/products and POST /api/licenses/create.
  //
  // Existing products, licenses, and license_products relationships are preserved.

  const old = await pool.query(`
    SELECT id, owner_name
    FROM licenses
    WHERE group_id IS NULL
      AND owner_user_id IS NULL
    LIMIT 100
  `);

  for (const row of old.rows) {
    try {
      const u = await getRobloxUserInfo(row.owner_name);

      if (u) {
        await pool.query(
          'UPDATE licenses SET owner_user_id=$1, owner_name=$2 WHERE id=$3',
          [u.userId, u.exactUsername, row.id]
        );
      }
    } catch {
      console.warn('Owner ID migration deferred for license', row.id);
    }
  }

  await pool.query(`
    DELETE FROM dss_upload_sessions
    WHERE created_at < NOW() - INTERVAL '1 day';

    DELETE FROM dss_file_tickets
    WHERE expires_at < NOW();
  `);

  console.log('PostgreSQL schema ready.');
}

async function listLicenseProducts(id) {
  const { rows } = await pool.query(`
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
      p.is_active AS product_active
    FROM license_products lp
    JOIN products p ON p.id = lp.product_id
    WHERE lp.license_id = $1
    ORDER BY p.product_name
  `, [id]);

  return rows;
}

async function findValidLicense(username, key) {
  const user = await getRobloxUserInfo(username);

  if (!user) {
    return {
      error: 'Username Roblox tidak ditemukan.',
      status: 404
    };
  }

  const { rows } = await pool.query(`
    SELECT l.*
    FROM licenses l
    WHERE l.license_key = $1
      AND l.is_active = TRUE
      AND (l.expires_at IS NULL OR l.expires_at > NOW())
      AND (
        (l.group_id IS NULL AND l.owner_user_id = $2)
        OR l.group_id IS NOT NULL
      )
    LIMIT 1
  `, [key, user.userId]);

  if (!rows.length) {
    return {
      error: 'Key salah, tidak aktif, kedaluwarsa, atau bukan milik akun ini.',
      status: 401
    };
  }

  return { user, license: rows[0] };
}

// ------------------------------------------------------------
// Client login and refresh
// ------------------------------------------------------------

async function clientLoginHandler(req, res) {
  const username = cleanText(req.body?.owner_name, 64);
  const key = cleanText(req.body?.license_key, 255);

  if (!username || !key) {
    return res.status(400).json({
      success: false,
      message: 'Username Roblox dan License Key wajib diisi.'
    });
  }

  try {
    const v = await findValidLicense(username, key);

    if (v.error) {
      return res.status(v.status).json({
        success: false,
        message: v.error
      });
    }

    const products = await listLicenseProducts(v.license.id);

    res.json({
      success: true,
      avatar_url: v.user.avatarUrl,
      owner_name: v.user.exactUsername,
      owner_user_id: v.user.userId,
      license: {
        id: v.license.id,
        license_key: v.license.license_key,
        expires_at: v.license.expires_at,
        is_active: v.license.is_active,
        group_id: v.license.group_id
      },
      data: products
        .filter(p => p.product_active)
        .map(p => ({
          id: p.id,
          product: p.product_name,
          product_code: p.product_code,
          description: p.description,
          image_url: p.image_url,
          download_url: p.download_url,
          has_image: !!(p.image_path || p.image_url),
          has_download: !!(p.download_path || p.download_url),
          expires_at: v.license.expires_at,
          is_active: v.license.is_active
        }))
    });
  } catch (e) {
    console.error('client-login/refresh', e.message);

    res.status(502).json({
      success: false,
      message: 'Gagal menghubungi Roblox atau database. Coba lagi.'
    });
  }
}

app.post('/api/client-login', clientLoginHandler);

// ------------------------------------------------------------
// Portal login
// ------------------------------------------------------------

app.post('/api/portal-login', async (req, res) => {
  const username = cleanText(req.body?.owner_name, 64);
  const credential = cleanText(req.body?.credential, 255);

  if (!username || !credential) {
    return res.status(400).json({
      success: false,
      message: 'Username Roblox dan License Key wajib diisi.'
    });
  }

  if (safeEqual(credential, API_SECRET)) {
    try {
      const user = await getRobloxUserInfo(username);

      if (!user || user.userId !== OWNER_ROBLOX_USER_ID) {
        return res.status(401).json({
          success: false,
          message: 'Username Roblox atau kredensial tidak valid.'
        });
      }

      setAdminSessionCookie(req, res);

      return res.json({
        success: true,
        access: 'admin',
        owner_name: user.exactUsername
      });
    } catch (e) {
      console.error('Owner login verification failed:', e.message);

      return res.status(502).json({
        success: false,
        message: 'Verifikasi Roblox gagal. Coba lagi.'
      });
    }
  }

  req.body = {
    owner_name: username,
    license_key: credential
  };

  return clientLoginHandler(req, res);
});

app.get('/api/admin-session', (req, res) => {
  res.json({
    success: true,
    authenticated: hasValidAdminSession(req)
  });
});

app.post('/api/admin-logout', (req, res) => {
  res.clearCookie(ADMIN_SESSION_COOKIE, {
    httpOnly: true,
    secure: req.secure || req.get('x-forwarded-proto') === 'https',
    sameSite: 'strict',
    path: '/'
  });

  res.json({
    success: true,
    message: 'Sesi Admin ditutup.'
  });
});

app.post('/api/client-refresh', clientLoginHandler);

// ------------------------------------------------------------
// Roblox game verification
// ------------------------------------------------------------

app.post('/api/game-verify', async (req, res) => {
  const placeId = cleanText(String(req.body?.place_id ?? ''), 24);
  const productName = cleanText(req.body?.product_name, 120);

  if (!placeId || !productName) {
    return res.status(400).json({
      success: true,
      authorized: false,
      code: 'BAD_REQUEST',
      message: 'place_id dan product_name wajib.'
    });
  }

  try {
    const c = await getPlaceCreator(placeId);
    const isGroup = String(c.creatorType).toLowerCase() === 'group';

    const { rows } = await pool.query(`
      SELECT
        l.id,
        l.owner_name,
        l.owner_user_id,
        l.group_id,
        l.expires_at,
        p.product_name,
        p.product_code
      FROM licenses l
      JOIN license_products lp ON lp.license_id = l.id
      JOIN products p ON p.id = lp.product_id
      WHERE l.is_active = TRUE
        AND p.is_active = TRUE
        AND (l.expires_at IS NULL OR l.expires_at > NOW())
        AND p.product_name = $1
        AND (
          ($2::boolean = TRUE AND l.group_id = $3)
          OR (
            $2::boolean = FALSE
            AND l.group_id IS NULL
            AND l.owner_user_id = $3
          )
        )
      ORDER BY l.created_at DESC
      LIMIT 1
    `, [productName, isGroup, c.creatorId]);

    if (!rows.length) {
      return res.json({
        success: true,
        authorized: false,
        code: 'NOT_LICENSED',
        message: 'Tidak ada lisensi aktif untuk produk ini dan pemilik experience ini.',
        creator: c
      });
    }

    res.json({
      success: true,
      authorized: true,
      code: 'AUTHORIZED',
      message: 'Lisensi valid.',
      product_name: rows[0].product_name,
      product_code: rows[0].product_code,
      place_id: c.placeId,
      universe_id: c.universeId,
      creator_type: c.creatorType,
      creator_id: c.creatorId,
      expires_at: rows[0].expires_at
    });
  } catch (e) {
    console.error('game-verify', e.message);

    res.status(e.statusCode || 503).json({
      success: false,
      authorized: false,
      code: 'VERIFY_UNAVAILABLE',
      message: 'Verifikasi Roblox sementara tidak tersedia.'
    });
  }
});

// ------------------------------------------------------------
// Admin catalog API
// ------------------------------------------------------------

app.get('/api/products', verifyAdminSession, async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        id,
        product_code,
        product_name,
        description,
        image_url,
        download_url,
        image_filename,
        download_filename,
        image_content_type,
        download_content_type,
        is_active,
        created_at,
        updated_at,
        (image_path IS NOT NULL OR image_url IS NOT NULL) AS has_image,
        (download_path IS NOT NULL OR download_url IS NOT NULL) AS has_download
      FROM products
      ORDER BY product_name
    `);

    res.json({ success: true, products: rows });
  } catch (e) {
    console.error(e.message);

    res.status(500).json({
      success: false,
      message: 'Gagal membaca katalog.'
    });
  }
});

app.post('/api/products', verifyAdminSession, async (req, res) => {
  const name = cleanText(req.body?.product_name, 120);
  const description = cleanText(req.body?.description, 1000);
  const image = validHttpUrl(req.body?.image_url);
  const download = validHttpUrl(req.body?.download_url);

  if (!name) {
    return res.status(400).json({
      success: false,
      message: 'Nama produk wajib diisi.'
    });
  }

  if (image === undefined || download === undefined) {
    return res.status(400).json({
      success: false,
      message: 'URL harus berupa HTTP/HTTPS yang valid.'
    });
  }

  const code = cleanText(req.body?.product_code, 80)
    .toUpperCase() ||
    name.toUpperCase()
      .replace(/[^A-Z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .slice(0, 70);

  if (!code) {
    return res.status(400).json({
      success: false,
      message: 'Kode produk tidak valid.'
    });
  }

  try {
    const { rows } = await pool.query(`
      INSERT INTO products(
        product_code,
        product_name,
        description,
        image_url,
        download_url
      )
      VALUES($1, $2, $3, $4, $5)
      RETURNING *
    `, [code, name, description || null, image, download]);

    res.status(201).json({
      success: true,
      product: rows[0]
    });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({
        success: false,
        message: 'Kode atau nama produk sudah digunakan.'
      });
    }

    console.error('Create product:', e.message);

    res.status(500).json({
      success: false,
      message: 'Gagal membuat produk.'
    });
  }
});

app.patch('/api/products/:id', verifyAdminSession, async (req, res) => {
  const id = cleanText(req.params.id, 20);
  const active = req.body?.is_active;

  if (!/^\d+$/.test(id) || typeof active !== 'boolean') {
    return res.status(400).json({
      success: false,
      message: 'ID atau status tidak valid.'
    });
  }

  try {
    const { rows } = await pool.query(
      'UPDATE products SET is_active=$1, updated_at=NOW() WHERE id=$2 RETURNING id,is_active',
      [active, id]
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Produk tidak ditemukan.'
      });
    }

    res.json({ success: true, product: rows[0] });
  } catch {
    res.status(500).json({
      success: false,
      message: 'Gagal memperbarui produk.'
    });
  }
});

app.delete('/api/products/:id', verifyAdminSession, async (req, res) => {
  const id = cleanText(req.params.id, 20);

  if (!/^\d+$/.test(id)) {
    return res.status(400).json({
      success: false,
      message: 'ID tidak valid.'
    });
  }

  const c = await pool.connect();

  try {
    await c.query('BEGIN');

    const { rows } = await c.query(
      'SELECT * FROM products WHERE id=$1 FOR UPDATE',
      [id]
    );

    if (!rows.length) {
      await c.query('ROLLBACK');

      return res.status(404).json({
        success: false,
        message: 'Produk tidak ditemukan.'
      });
    }

    const used = await c.query(
      'SELECT 1 FROM license_products WHERE product_id=$1 LIMIT 1',
      [id]
    );

    if (used.rows.length) {
      await c.query('ROLLBACK');

      return res.status(409).json({
        success: false,
        message: 'Produk masih terhubung ke lisensi. Nonaktifkan produk atau cabut lisensi terkait terlebih dahulu.'
      });
    }

    await c.query('DELETE FROM products WHERE id=$1', [id]);
    await c.query('COMMIT');

    for (const p of [rows[0].image_path, rows[0].download_path]) {
      if (p) {
        try {
          await del(p, { access: 'private' });
        } catch (e) {
          console.warn('Blob cleanup deferred:', e.message);
        }
      }
    }

    res.json({
      success: true,
      message: 'Produk dihapus.'
    });
  } catch (e) {
    await c.query('ROLLBACK').catch(() => {});
    console.error(e.message);

    res.status(500).json({
      success: false,
      message: 'Gagal menghapus produk.'
    });
  } finally {
    c.release();
  }
});

// ------------------------------------------------------------
// Private chunked uploads
// ------------------------------------------------------------

app.post('/api/uploads/start', verifyAdminSession, async (req, res) => {
  const kind = req.body?.kind === 'image'
    ? 'image'
    : req.body?.kind === 'download'
      ? 'download'
      : '';

  const filename = safeFilename(req.body?.filename);
  const contentType = cleanText(req.body?.content_type, 120);
  const size = Number(req.body?.size);

  if (
    !kind ||
    !Number.isSafeInteger(size) ||
    size < 1 ||
    size > MAX_FILE_SIZE
  ) {
    return res.status(400).json({
      success: false,
      message: 'Jenis atau ukuran file tidak valid. Maksimal 50 MB.'
    });
  }

  if (kind === 'image' && !IMAGE_TYPES.includes(contentType)) {
    return res.status(400).json({
      success: false,
      message: 'Gambar harus JPEG, PNG, WebP, atau GIF.'
    });
  }

  if (
    kind === 'download' &&
    (!contentType || contentType === 'application/x-msdownload')
  ) {
    return res.status(400).json({
      success: false,
      message: 'Tipe file tidak didukung.'
    });
  }

  const id = crypto.randomBytes(24).toString('hex');
  const count = Math.ceil(size / CHUNK_SIZE);

  try {
    await pool.query(`
      INSERT INTO dss_upload_sessions(
        id, kind, filename, content_type, total_size, chunk_count
      )
      VALUES($1, $2, $3, $4, $5, $6)
    `, [
      id,
      kind,
      filename,
      contentType || 'application/octet-stream',
      size,
      count
    ]);

    res.json({
      success: true,
      upload_id: id,
      chunk_size: CHUNK_SIZE,
      chunk_count: count
    });
  } catch (e) {
    console.error('upload start', e.message);

    res.status(500).json({
      success: false,
      message: 'Gagal memulai upload.'
    });
  }
});

app.put(
  '/api/uploads/:id/chunks/:index',
  verifyAdminSession,
  express.raw({
    type: 'application/octet-stream',
    limit: '2.2mb'
  }),
  async (req, res) => {
    const id = cleanText(req.params.id, 64);
    const idx = Number(req.params.index);

    if (!/^[a-f0-9]{48}$/.test(id) || !Number.isInteger(idx) || idx < 0) {
      return res.status(400).json({
        success: false,
        message: 'Upload atau nomor chunk tidak valid.'
      });
    }

    try {
      const { rows } = await pool.query(
        'SELECT * FROM dss_upload_sessions WHERE id=$1',
        [id]
      );

      const s = rows[0];

      if (
        !s ||
        new Date(s.created_at).getTime() < Date.now() - 24 * 60 * 60 * 1000
      ) {
        return res.status(404).json({
          success: false,
          message: 'Sesi upload tidak ditemukan/kedaluwarsa.'
        });
      }

      if (
        idx >= s.chunk_count ||
        !Buffer.isBuffer(req.body) ||
        req.body.length < 1 ||
        req.body.length > CHUNK_SIZE
      ) {
        return res.status(400).json({
          success: false,
          message: 'Chunk tidak valid.'
        });
      }

      await put(`dss-temp/${id}/${idx}`, req.body, {
        access: 'private',
        addRandomSuffix: false,
        allowOverwrite: true,
        contentType: 'application/octet-stream'
      });

      res.json({ success: true, index: idx });
    } catch (e) {
      console.error('upload chunk', e.message);

      res.status(500).json({
        success: false,
        message: 'Upload bagian file gagal.'
      });
    }
  }
);

async function streamToBuffer(stream) {
  const parts = [];

  for await (const chunk of stream) {
    parts.push(Buffer.from(chunk));
  }

  return Buffer.concat(parts);
}

app.post('/api/uploads/:id/finish', verifyAdminSession, async (req, res) => {
  const id = cleanText(req.params.id, 64);
  const productId = cleanText(String(req.body?.product_id ?? ''), 20);

  if (!/^[a-f0-9]{48}$/.test(id) || !/^\d+$/.test(productId)) {
    return res.status(400).json({
      success: false,
      message: 'Sesi atau produk tidak valid.'
    });
  }

  try {
    const { rows } = await pool.query(
      'SELECT * FROM dss_upload_sessions WHERE id=$1',
      [id]
    );

    const s = rows[0];

    if (!s) {
      return res.status(404).json({
        success: false,
        message: 'Sesi upload tidak ditemukan.'
      });
    }

    if (
      new Date(s.created_at).getTime() < Date.now() - 24 * 60 * 60 * 1000
    ) {
      return res.status(410).json({
        success: false,
        message: 'Sesi upload kedaluwarsa. Mulai upload baru.'
      });
    }

    const chunks = [];

    for (let i = 0; i < s.chunk_count; i++) {
      const b = await get(`dss-temp/${id}/${i}`, { access: 'private' });

      if (!b) {
        return res.status(400).json({
          success: false,
          message: `Bagian file ${i + 1} belum terunggah.`
        });
      }

      chunks.push(await streamToBuffer(b.stream));
    }

    const file = Buffer.concat(chunks);

    if (file.length !== Number(s.total_size)) {
      return res.status(400).json({
        success: false,
        message: 'Ukuran file tidak cocok. Ulangi upload.'
      });
    }

    const blobPath =
      `dss-products/${productId}/${s.kind}-${crypto.randomBytes(16).toString('hex')}-${s.filename}`;

    const blob = await put(blobPath, file, {
      access: 'private',
      addRandomSuffix: false,
      contentType: s.content_type
    });

    const col = s.kind === 'image' ? 'image' : 'download';

    const sql = `
      UPDATE products
      SET
        ${col}_path=$1,
        ${col}_filename=$2,
        ${col}_content_type=$3,
        ${col}_url=NULL,
        updated_at=NOW()
      WHERE id=$4
      RETURNING id, ${col}_path
    `;

    const updated = await pool.query(sql, [
      blob.pathname || blob.url,
      s.filename,
      s.content_type,
      productId
    ]);

    if (!updated.rows.length) {
      await del(blob.pathname || blob.url, { access: 'private' }).catch(() => {});

      return res.status(404).json({
        success: false,
        message: 'Produk tidak ditemukan.'
      });
    }

    await pool.query(
      'DELETE FROM dss_upload_sessions WHERE id=$1',
      [id]
    );

    for (let i = 0; i < s.chunk_count; i++) {
      await del(`dss-temp/${id}/${i}`, { access: 'private' }).catch(() => {});
    }

    res.json({
      success: true,
      message: col === 'image'
        ? 'Gambar produk berhasil diunggah.'
        : 'File download berhasil diunggah.',
      filename: s.filename
    });
  } catch (e) {
    console.error('upload finish', e.message);

    res.status(500).json({
      success: false,
      message: 'Gagal menyelesaikan upload. Periksa koneksi lalu ulangi.'
    });
  }
});

app.delete('/api/uploads/:id', verifyAdminSession, async (req, res) => {
  const id = cleanText(req.params.id, 64);

  try {
    const { rows } = await pool.query(
      'SELECT chunk_count FROM dss_upload_sessions WHERE id=$1',
      [id]
    );

    if (rows[0]) {
      await pool.query(
        'DELETE FROM dss_upload_sessions WHERE id=$1',
        [id]
      );

      for (let i = 0; i < rows[0].chunk_count; i++) {
        await del(`dss-temp/${id}/${i}`, { access: 'private' }).catch(() => {});
      }
    }

    res.json({ success: true });
  } catch {
    res.status(500).json({
      success: false,
      message: 'Gagal membatalkan upload.'
    });
  }
});

// ------------------------------------------------------------
// Admin license API
// ------------------------------------------------------------

app.get('/api/licenses', verifyAdminSession, async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        l.*,
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
        ) AS products
      FROM licenses l
      LEFT JOIN license_products lp ON lp.license_id = l.id
      LEFT JOIN products p ON p.id = lp.product_id
      GROUP BY l.id
      ORDER BY l.created_at DESC
    `);

    res.json({ success: true, licenses: rows });
  } catch (e) {
    console.error(e.message);

    res.status(500).json({
      success: false,
      message: 'Gagal membaca lisensi.'
    });
  }
});

app.post('/api/licenses/create', verifyAdminSession, async (req, res) => {
  const key = cleanText(req.body?.license_key, 255);
  const ownerInput = cleanText(req.body?.owner_name, 64);
  const groupId = cleanText(String(req.body?.group_id ?? ''), 32) || null;

  const productIds = Array.isArray(req.body?.product_ids)
    ? [...new Set(req.body.product_ids.map(String))]
    : [];

  const expires = validExpiry(req.body?.expires_at);
  const image = validHttpUrl(req.body?.image_url);
  const download = validHttpUrl(req.body?.download_url);

  if (!key) {
    return res.status(400).json({
      success: false,
      message: 'License key wajib diisi.'
    });
  }

  if (
    !productIds.length ||
    productIds.length > 50 ||
    productIds.some(x => !/^[0-9]+$/.test(x))
  ) {
    return res.status(400).json({
      success: false,
      message: 'Pilih minimal satu produk (maksimal 50).'
    });
  }

  if (expires === undefined) {
    return res.status(400).json({
      success: false,
      message: 'Tanggal kedaluwarsa tidak valid.'
    });
  }

  if (image === undefined || download === undefined) {
    return res.status(400).json({
      success: false,
      message: 'URL tidak valid.'
    });
  }

  if (groupId && !/^\d+$/.test(groupId)) {
    return res.status(400).json({
      success: false,
      message: 'Group ID harus angka.'
    });
  }

  if (!groupId && !ownerInput) {
    return res.status(400).json({
      success: false,
      message: 'Username pemilik wajib diisi.'
    });
  }

  let user = null;

  if (!groupId) {
    try {
      user = await getRobloxUserInfo(ownerInput);
    } catch {
      return res.status(502).json({
        success: false,
        message: 'Roblox API tidak tersedia, coba lagi.'
      });
    }

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Username Roblox tidak valid.'
      });
    }
  }

  const c = await pool.connect();

  try {
    await c.query('BEGIN');

    const pc = await c.query(`
      SELECT id
      FROM products
      WHERE is_active = TRUE
        AND id = ANY($1::bigint[])
    `, [productIds]);

    if (pc.rows.length !== productIds.length) {
      await c.query('ROLLBACK');

      return res.status(400).json({
        success: false,
        message: 'Ada produk tidak ditemukan atau nonaktif.'
      });
    }

    const ins = await c.query(`
      INSERT INTO licenses(
        license_key,
        owner_name,
        owner_user_id,
        group_id,
        product_name,
        image_url,
        download_url,
        expires_at
      )
      VALUES($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING id
    `, [
      key,
      groupId ? 'COMMUNITY_GROUP' : user.exactUsername,
      groupId ? null : user.userId,
      groupId,
      'DSS STUDIO LICENSE',
      image,
      download,
      expires
    ]);

    // IMPORTANT FIX:
    // Only link products explicitly selected by the admin.
    // Do not create products or infer product links from product_name.
    for (const pid of productIds) {
      await c.query(
        'INSERT INTO license_products(license_id, product_id) VALUES($1, $2)',
        [ins.rows[0].id, pid]
      );
    }

    await c.query('COMMIT');

    res.status(201).json({
      success: true,
      message: 'Lisensi/paket berhasil dibuat.',
      id: ins.rows[0].id,
      product_count: productIds.length
    });
  } catch (e) {
    await c.query('ROLLBACK');

    if (e.code === '23505') {
      return res.status(409).json({
        success: false,
        message: 'License Key sudah digunakan.'
      });
    }

    console.error(e.message);

    res.status(500).json({
      success: false,
      message: 'Gagal membuat lisensi.'
    });
  } finally {
    c.release();
  }
});

app.patch('/api/licenses/:id/status', verifyAdminSession, async (req, res) => {
  const id = cleanText(req.params.id, 20);

  if (!/^\d+$/.test(id) || typeof req.body?.is_active !== 'boolean') {
    return res.status(400).json({
      success: false,
      message: 'ID/status tidak valid.'
    });
  }

  try {
    const { rows } = await pool.query(
      'UPDATE licenses SET is_active=$1 WHERE id=$2 RETURNING id,is_active',
      [req.body.is_active, id]
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Lisensi tidak ditemukan.'
      });
    }

    res.json({ success: true, license: rows[0] });
  } catch {
    res.status(500).json({
      success: false,
      message: 'Gagal mengubah status.'
    });
  }
});

app.delete('/api/licenses/:id', verifyAdminSession, async (req, res) => {
  const id = cleanText(req.params.id, 20);

  if (!/^\d+$/.test(id)) {
    return res.status(400).json({
      success: false,
      message: 'ID tidak valid.'
    });
  }

  try {
    const r = await pool.query(
      'DELETE FROM licenses WHERE id=$1',
      [id]
    );

    if (!r.rowCount) {
      return res.status(404).json({
        success: false,
        message: 'Lisensi tidak ditemukan.'
      });
    }

    res.json({
      success: true,
      message: 'Lisensi berhasil dihapus.'
    });
  } catch {
    res.status(500).json({
      success: false,
      message: 'Gagal menghapus lisensi.'
    });
  }
});

// ------------------------------------------------------------
// Short-lived private file tickets
// ------------------------------------------------------------

app.post('/api/file-ticket', async (req, res) => {
  const username = cleanText(req.body?.owner_name, 64);
  const key = cleanText(req.body?.license_key, 255);
  const productId = cleanText(String(req.body?.product_id ?? ''), 20);

  const kind = req.body?.kind === 'image' ? 'image' : 'download';

  if (!username || !key || !/^[0-9]+$/.test(productId)) {
    return res.status(400).json({
      success: false,
      message: 'Permintaan file tidak valid.'
    });
  }

  try {
    const v = await findValidLicense(username, key);

    if (v.error) {
      return res.status(v.status).json({
        success: false,
        message: v.error
      });
    }

    const { rows } = await pool.query(`
      SELECT p.*
      FROM license_products lp
      JOIN products p ON p.id = lp.product_id
      WHERE lp.license_id = $1
        AND p.id = $2
        AND p.is_active = TRUE
      LIMIT 1
    `, [v.license.id, productId]);

    const p = rows[0];

    if (!p) {
      return res.status(403).json({
        success: false,
        message: 'Produk tidak terikat pada lisensi ini.'
      });
    }

    const blobPath = kind === 'image' ? p.image_path : p.download_path;
    const legacyUrl = kind === 'image' ? p.image_url : p.download_url;

    if (!blobPath && !legacyUrl) {
      return res.status(404).json({
        success: false,
        message: 'File belum tersedia.'
      });
    }

    if (legacyUrl) {
      return res.json({
        success: true,
        url: legacyUrl,
        legacy: true
      });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const hash = crypto.createHash('sha256').update(token).digest('hex');

    await pool.query(`
      INSERT INTO dss_file_tickets(
        token_hash,
        product_id,
        kind,
        owner_user_id,
        license_id,
        expires_at
      )
      VALUES($1, $2, $3, $4, $5, NOW() + INTERVAL '2 minutes')
    `, [
      hash,
      productId,
      kind,
      v.user.userId,
      v.license.id
    ]);

    res.json({
      success: true,
      url: `/api/private-file/${token}`
    });
  } catch (e) {
    console.error('file-ticket', e.message);

    res.status(500).json({
      success: false,
      message: 'Gagal membuat akses file.'
    });
  }
});

app.get('/api/private-file/:token', async (req, res) => {
  const token = cleanText(req.params.token, 64);

  if (!/^[a-f0-9]{64}$/.test(token)) {
    return res.status(404).send('File tidak ditemukan.');
  }

  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const c = await pool.connect();

  try {
    await c.query('BEGIN');

    const { rows } = await c.query(`
      SELECT
        t.*,
        p.image_path,
        p.download_path,
        p.image_filename,
        p.download_filename,
        p.image_content_type,
        p.download_content_type,
        p.is_active AS product_active,
        l.is_active AS license_active,
        l.expires_at
      FROM dss_file_tickets t
      JOIN products p ON p.id = t.product_id
      JOIN licenses l ON l.id = t.license_id
      WHERE t.token_hash = $1
        AND t.expires_at > NOW()
      FOR UPDATE OF t
    `, [hash]);

    const t = rows[0];

    if (
      !t ||
      !t.product_active ||
      !t.license_active ||
      (t.expires_at && new Date(t.expires_at) <= new Date())
    ) {
      await c.query('ROLLBACK');

      return res.status(403).send(
        'Akses file tidak valid atau kedaluwarsa. Silakan login ulang.'
      );
    }

    // Consume the ticket before returning the file.
    await c.query(
      'DELETE FROM dss_file_tickets WHERE token_hash=$1',
      [hash]
    );

    await c.query('COMMIT');

    const pathname = t.kind === 'image'
      ? t.image_path
      : t.download_path;

    if (!pathname) {
      return res.status(404).send('File tidak ditemukan.');
    }

    const b = await get(pathname, { access: 'private' });

    if (!b) {
      return res.status(404).send('File tidak ditemukan.');
    }

    const filename = safeFilename(
      t.kind === 'image'
        ? (t.image_filename || 'product-image')
        : (t.download_filename || 'product-download')
    );

    res.set(
      'Content-Type',
      t.kind === 'image'
        ? (t.image_content_type || b.blob.contentType || 'application/octet-stream')
        : (t.download_content_type || b.blob.contentType || 'application/octet-stream')
    );

    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Cache-Control', 'private, no-store, max-age=0');

    if (t.kind === 'download') {
      res.set(
        'Content-Disposition',
        `attachment; filename="${filename.replace(/"/g, '')}"`
      );
    } else {
      res.set('Content-Disposition', 'inline');
    }

    if (b.blob?.size) {
      res.set('Content-Length', String(b.blob.size));
    }

    return res.status(200).send(
      Buffer.from(await streamToBuffer(b.stream))
    );
  } catch (e) {
    await c.query('ROLLBACK').catch(() => {});
    console.error('private-file', e.message);

    res.status(500).send('Gagal mengambil file.');
  } finally {
    c.release();
  }
});

// ------------------------------------------------------------
// Start / shutdown
// ------------------------------------------------------------

let server;

if (require.main === module) {
  server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`DSS STUDIO LICENSE listening on ${PORT}`);
  });
}

async function shutdown() {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }

  await pool.end().catch(() => {});
  process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

module.exports = app;
