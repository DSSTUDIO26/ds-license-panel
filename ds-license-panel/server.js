// DSS STUDIO LICENSE V5.4 - SERVER BACKEND
// PostgreSQL + Private Vercel Blob
// Node.js 20+

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
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
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

if (API_SECRET.length < 32) {
  throw new Error('FATAL: API_SECRET wajib tersedia dan minimal 32 karakter.');
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

function rateLimit({ windowMs = 60000, max = 60 } = {}) {
  return (req, res, next) => {
    const now = Date.now();
    const key = `${req.ip || 'unknown'}:${req.path}`;
    let item = rateBuckets.get(key);

    if (!item || item.resetAt <= now) {
      item = { count: 0, resetAt: now + windowMs };
    }

    item.count += 1;
    rateBuckets.set(key, item);

    if (item.count > max) {
      return res.status(429).json({
        success: false,
        code: 'RATE_LIMITED',
        message: 'Terlalu banyak permintaan.'
      });
    }

    next();
  };
}

// ============================================================
// SECURITY & HELPERS
// ============================================================

function cleanText(v, max = 255) {
  return typeof v === 'string' ? v.trim().slice(0, max) : '';
}

// ============================================================
// ROBLOX API HELPERS
// ============================================================

async function robloxFetch(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);

  try {
    const r = await fetch(url, { ...options, signal: controller.signal });
    if (!r.ok) {
      const error = new Error(`Roblox API HTTP ${r.status}`);
      error.statusCode = r.status;
      throw error;
    }
    return await r.json();
  } catch (e) {
    if (e.name === 'AbortError') {
      throw new Error('Roblox API timeout');
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

async function getPlaceCreator(placeId) {
  if (!/^\d{1,20}$/.test(String(placeId || ''))) {
    const e = new Error('place_id tidak valid');
    e.statusCode = 400;
    throw e;
  }

  let p = await robloxFetch(`https://apis.roblox.com/universes/v1/places/${encodeURIComponent(placeId)}/universe`);
  if (!p?.universeId) throw new Error('UNIVERSE_ID_NOT_FOUND');

  let g = await robloxFetch(`https://games.roblox.com/v1/games?universeIds=${encodeURIComponent(p.universeId)}`);
  const c = g?.data?.[0]?.creator;

  if (!c || !['User', 'Group'].includes(String(c?.type || ''))) {
    throw new Error('EXPERIENCE_CREATOR_NOT_FOUND');
  }

  return {
    placeId: String(placeId),
    universeId: String(p.universeId),
    creatorType: String(c.type),
    creatorId: String(c.id),
    creatorName: c.name || ''
  };
}

// ============================================================
// DATABASE INIT
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
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS license_products(
      license_id BIGINT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
      product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
      PRIMARY KEY(license_id, product_id)
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
}

app.use(async (_req, res, next) => {
  try {
    if (!dbInitPromise) dbInitPromise = initDB();
    await dbInitPromise;
    next();
  } catch (err) {
    dbInitPromise = null;
    res.status(503).json({ success: false, code: 'DATABASE_UNAVAILABLE', message: 'Database belum siap.' });
  }
});

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch {
    res.status(503).json({ ok: false });
  }
});

// ============================================================
// GAME LICENSE VERIFICATION (STRICT REAL-TIME ENDPOINT)
// ============================================================

app.post(
  '/api/game-verify',
  rateLimit({ windowMs: 60000, max: 60 }),
  async (req, res) => {
    const placeId = cleanText(String(req.body?.place_id ?? ''), 20);
    const productName = cleanText(req.body?.product_name, 120);

    if (!/^\d{1,20}$/.test(placeId) || !productName) {
      return res.status(400).json({
        success: false,
        authorized: false,
        code: 'BAD_REQUEST',
        message: 'place_id dan product_name wajib valid.'
      });
    }

    try {
      // 1. Ambil data kreator asli dari Roblox API secara langsung
      const creator = await getPlaceCreator(placeId);
      const isGroup = creator.creatorType === 'Group';

      // 2. Kueri Database: Memastikan lisensi benar-benar aktif (is_active = TRUE)[cite: 1]
      const { rows } = await pool.query(
        `
        SELECT l.id AS license_id, l.is_active, p.product_name
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

      // Jika lisensi sudah dicabut, dihapus, atau tidak ada -> Wajib balas authorized: false[cite: 1]
      if (!rows.length) {
        await pool.query('DELETE FROM project_experiences WHERE place_id = $1', [placeId]).catch(() => {});
        
        return res.json({
          success: true,
          authorized: false, -- Respon mutlak untuk memicu kill-switch di Roblox
          code: 'NOT_LICENSED',
          message: 'Lisensi tidak aktif atau telah dicabut.'
        });
      }

      // Jika valid, simpan jejak experience aktif
      await pool.query(
        `
        INSERT INTO project_experiences(
          place_id, universe_id, product_id, product_name, owner_id, creator_type, creator_id, creator_name, license_id, last_ping, updated_at
        ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW(),NOW())
        ON CONFLICT(place_id) DO UPDATE SET
          last_ping = NOW(),
          updated_at = NOW()
        `,
        [
          creator.placeId,
          creator.universeId,
          rows[0].product_id,
          rows[0].product_name,
          creator.creatorId,
          creator.creatorType,
          creator.creatorId,
          creator.creatorName,
          rows[0].license_id
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
// SERVER LISTENER
// ============================================================

let server;
if (require.main === module) {
  server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`DSS STUDIO LICENSE backend listening on port ${PORT}`);
  });
}

module.exports = app;
