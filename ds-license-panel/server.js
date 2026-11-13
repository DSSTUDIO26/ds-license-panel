// ============================================================
// DSS STUDIO LICENSE PRO V5 CREATOR ROOT
// DRAGON STELL STUDIO
//
// Node.js 20+
// PostgreSQL
// Creator ID Root Verification
//
// COMPATIBLE:
// DSS Roblox Server Loader
//
// ENVIRONMENT VARIABLES:
// DATABASE_URL
// API_SECRET
// LOADER_SECRET (minimal 32 karakter, sama dengan DSSLicenseLoader)
// OWNER_ROBLOX_USER_ID
// ============================================================

'use strict';

const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');
const dns = require('node:dns').promises;
const net = require('node:net');
const https = require('node:https');
const multer = require('multer');

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(express.json({ limit: '1mb', strict: true }));

app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Cache-Control', 'no-store');
    next();
});

const rateBuckets = new Map();

function rateLimit({ windowMs = 60_000, max = 30 } = {}) {
    return (req, res, next) => {
        const key = `${req.ip || req.socket.remoteAddress}:${req.path}`;
        const now = Date.now();

        let bucket = rateBuckets.get(key);

        if (!bucket || bucket.resetAt <= now) {
            bucket = {
                count: 0,
                resetAt: now + windowMs
            };
        }

        bucket.count += 1;
        rateBuckets.set(key, bucket);

        if (rateBuckets.size > 5000) {
            for (const [k, v] of rateBuckets) {
                if (v.resetAt <= now) rateBuckets.delete(k);
            }
        }

        res.setHeader('RateLimit-Limit', String(max));
        res.setHeader(
            'RateLimit-Remaining',
            String(Math.max(0, max - bucket.count))
        );

        if (bucket.count > max) {
            res.setHeader(
                'Retry-After',
                String(Math.ceil((bucket.resetAt - now) / 1000))
            );

            return sendError(
                res,
                429,
                'Terlalu banyak permintaan. Coba lagi beberapa saat.'
            );
        }

        next();
    };
}

// ============================================================
// CONFIGURATION
// ============================================================

const PORT = Number(process.env.PORT || 3000);
const API_SECRET = process.env.API_SECRET || '';
// Secret khusus komunikasi ServerScriptService -> backend.
// Isi sama persis dengan LOADER_SECRET di DSSLicenseLoader.
const LOADER_SECRET = process.env.LOADER_SECRET || '';

const OWNER_ROBLOX_USER_ID = String(
    process.env.OWNER_ROBLOX_USER_ID || '9262435668'
);

const DATABASE_URL = process.env.DATABASE_URL || '';

const COOKIE = 'dss_admin_session';
const SESSION_MS = 8 * 60 * 60 * 1000;

const DEFAULT_IMAGE =
    'https://github.com/DSSTUDIO26/ds-license-panel/blob/main/ds-license-panel/Image/dragonstellstudio.jpeg?raw=true';

if (API_SECRET.length < 32) {
    console.error('FATAL: API_SECRET harus minimal 32 karakter.');

    if (require.main === module) {
        process.exit(1);
    }
}

if (LOADER_SECRET.length < 32) {
    console.error('WARNING: LOADER_SECRET belum diatur atau kurang dari 32 karakter. Endpoint game-verify akan menolak verifikasi.');
}

if (!DATABASE_URL) {
    console.error('FATAL: DATABASE_URL wajib diisi.');

    if (require.main === module) {
        process.exit(1);
    }
}

// ============================================================
// DATABASE
// ============================================================

const pool = new Pool({
    connectionString: DATABASE_URL,

    ssl: process.env.PGSSLMODE === 'disable'
        ? false
        : {
            rejectUnauthorized:
                process.env.PGSSL_REJECT_UNAUTHORIZED !== 'false'
        },

    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
});

let dbInitPromise;

app.use(async (_req, res, next) => {
    try {
        if (!dbInitPromise) {
            dbInitPromise = initDB();
        }

        await dbInitPromise;
        next();
    } catch (error) {
        console.error('[DATABASE INIT]', error.message);

        dbInitPromise = null;

        res.status(503).json({
            success: false,
            message: 'Database belum siap. Periksa DATABASE_URL.'
        });
    }
});

// ============================================================
// STATIC WEBSITE
// ============================================================

app.use(express.static(__dirname, {
    index: false,
    maxAge: '1h'
}));

app.get('/', (_req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ============================================================
// GENERAL HELPERS
// ============================================================

function safeEqual(a, b) {
    const aa = Buffer.from(String(a || ''));
    const bb = Buffer.from(String(b || ''));

    return aa.length > 0
        && aa.length === bb.length
        && crypto.timingSafeEqual(aa, bb);
}

function cleanText(value, max = 255) {
    return typeof value === 'string'
        ? value.trim().slice(0, max)
        : '';
}

function validExpiry(value) {
    if (value == null || value === '') return null;

    const date = new Date(value);

    return Number.isNaN(date.getTime())
        ? undefined
        : date.toISOString();
}

function validHttpUrl(value) {
    if (value == null || value === '') return null;

    try {
        const url = new URL(value);

        return ['https:', 'http:'].includes(url.protocol)
            ? url.toString()
            : undefined;
    } catch {
        return undefined;
    }
}

function validNumericId(value, maxLength = 32) {
    const id = String(value ?? '').trim();

    return new RegExp(`^\\d{1,${maxLength}}$`).test(id)
        ? id
        : null;
}

function sendError(res, status, message, extra = {}) {
    return res.status(status).json({
        success: false,
        message,
        ...extra
    });
}

// ============================================================
// ADMIN SESSION
// ============================================================

function sessionSig(exp) {
    return crypto
        .createHmac('sha256', API_SECRET)
        .update(`dss-admin:${OWNER_ROBLOX_USER_ID}:${exp}`)
        .digest('hex');
}

function readCookie(req, name) {
    for (const part of (req.headers.cookie || '').split(';')) {
        const index = part.indexOf('=');

        if (index > -1 && part.slice(0, index).trim() === name) {
            try {
                return decodeURIComponent(
                    part.slice(index + 1).trim()
                );
            } catch {
                return '';
            }
        }
    }

    return '';
}

function hasAdmin(req) {
    const token = readCookie(req, COOKIE);
    const dot = token.indexOf('.');

    if (dot < 1) return false;

    const exp = token.slice(0, dot);
    const sig = token.slice(dot + 1);

    if (!/^\d{13}$/.test(exp)) return false;
    if (!/^[a-f0-9]{64}$/.test(sig)) return false;

    const expiry = Number(exp);

    return Number.isSafeInteger(expiry)
        && expiry > Date.now()
        && expiry <= Date.now() + SESSION_MS + 60000
        && safeEqual(sig, sessionSig(exp));
}

function setAdminCookie(req, res) {
    const exp = String(Date.now() + SESSION_MS);

    res.cookie(COOKIE, `${exp}.${sessionSig(exp)}`, {
        httpOnly: true,
        secure:
            req.secure ||
            req.get('x-forwarded-proto') === 'https',
        sameSite: 'strict',
        path: '/',
        maxAge: SESSION_MS
    });
}

function verifyAdmin(req, res, next) {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        const origin = req.get('origin');
        const host = req.get('host');

        if (origin) {
            try {
                if (new URL(origin).host !== host) {
                    return sendError(
                        res,
                        403,
                        'Origin request tidak diizinkan.'
                    );
                }
            } catch {
                return sendError(
                    res,
                    403,
                    'Origin request tidak valid.'
                );
            }
        }
    }

    if (!hasAdmin(req)) {
        return sendError(
            res,
            401,
            'Sesi admin tidak valid. Silakan login ulang.'
        );
    }

    next();
}

// ============================================================
// ROBLOX API
// ============================================================

async function robloxFetch(url, options = {}) {
    const controller = new AbortController();

    const timer = setTimeout(() => {
        controller.abort();
    }, 8000);

    try {
        const response = await fetch(url, {
            ...options,
            signal: controller.signal
        });

        if (!response.ok) {
            throw new Error(`Roblox API HTTP ${response.status}`);
        }

        return await response.json();
    } finally {
        clearTimeout(timer);
    }
}

// ============================================================
// ROBLOX USER
// ============================================================

async function getRobloxUserInfo(username) {
    const result = await robloxFetch(
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

    const user = result?.data?.[0];

    if (
        !user ||
        user.name.toLowerCase() !== username.toLowerCase()
    ) {
        return null;
    }

    let avatarUrl = null;
    let displayName = user.displayName || user.name;

    try {
        const [profile, thumbnail] = await Promise.all([
            robloxFetch(
                `https://users.roblox.com/v1/users/${encodeURIComponent(user.id)}`
            ).catch(() => null),

            robloxFetch(
                `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${user.id}&size=150x150&format=Png&isCircular=false`
            ).catch(() => null)
        ]);

        displayName = profile?.displayName || displayName;
        avatarUrl = thumbnail?.data?.[0]?.imageUrl || null;
    } catch {}

    return {
        userId: String(user.id),
        exactUsername: user.name,
        displayName,
        avatarUrl
    };
}

// ============================================================
// ROBLOX GROUP
// ============================================================

const groupCache = new Map();

async function getRobloxGroupInfo(groupId) {
    const id = validNumericId(groupId);

    if (!id) {
        return {
            groupId: String(groupId || ''),
            groupName: null,
            groupIconUrl: null,
            ownerUserId: null,
            ownerUsername: null
        };
    }

    const cached = groupCache.get(id);

    if (cached && cached.until > Date.now()) {
        return cached.value;
    }

    const value = {
        groupId: id,
        groupName: null,
        groupIconUrl: null,
        ownerUserId: null,
        ownerUsername: null
    };

    try {
        const group = await robloxFetch(
            `https://groups.roblox.com/v1/groups/${encodeURIComponent(id)}`
        );

        value.groupName = group?.name || null;

        value.ownerUserId =
            group?.owner?.userId != null
                ? String(group.owner.userId)
                : null;

        value.ownerUsername = group?.owner?.username || null;
    } catch (error) {
        console.warn('[GROUP LOOKUP]', id, error.message);
    }

    try {
        const thumbnail = await robloxFetch(
            `https://thumbnails.roblox.com/v1/groups/icons?groupIds=${encodeURIComponent(id)}&size=150x150&format=Png&isCircular=false`
        );

        value.groupIconUrl =
            thumbnail?.data?.[0]?.imageUrl || null;
    } catch {}

    groupCache.set(id, {
        value,
        until: Date.now() + 10 * 60 * 1000
    });

    return value;
}

// ============================================================
// OWNED ROBLOX COMMUNITIES
// ============================================================

const ownedCommunityCache = new Map();

async function getOwnedRobloxCommunities(userId) {
    const id = validNumericId(userId, 20);

    if (!id) return [];

    const cached = ownedCommunityCache.get(id);

    if (cached && cached.until > Date.now()) {
        return cached.value;
    }

    try {
        const result = await robloxFetch(
            `https://groups.roblox.com/v2/users/${encodeURIComponent(id)}/groups/roles`
        );

        const candidates = (result?.data || []).filter(item => {
            const groupId = String(item?.group?.id || '');
            const rank = Number(item?.role?.rank || 0);

            return /^\d+$/.test(groupId) && (
                rank === 255 ||
                String(item?.group?.owner?.userId || '') === id
            );
        });

        const communities = candidates.map(item => ({
            group_id: String(item.group.id),
            name: String(
                item.group.name ||
                `Community ${item.group.id}`
            ),
            role_name: String(item.role?.name || 'Owner'),
            rank: Number(item.role?.rank || 255)
        }));

        ownedCommunityCache.set(id, {
            value: communities,
            until: Date.now() + 10 * 60 * 1000
        });

        return communities;
    } catch (error) {
        console.warn('[OWNED COMMUNITIES]', error.message);
        return cached?.value || [];
    }
}

// ============================================================
// PLACE CREATOR
// ============================================================

async function getPlaceCreator(placeId) {
    const id = validNumericId(placeId, 20);

    if (!id) {
        const error = new Error('place_id tidak valid.');
        error.statusCode = 400;
        throw error;
    }

    const universe = await robloxFetch(
        `https://apis.roblox.com/universes/v1/places/${encodeURIComponent(id)}/universe`
    );

    if (!universe?.universeId) {
        throw new Error('Universe ID tidak ditemukan.');
    }

    const game = await robloxFetch(
        `https://games.roblox.com/v1/games?universeIds=${encodeURIComponent(universe.universeId)}`
    );

    const creator = game?.data?.[0]?.creator;

    if (!creator) {
        throw new Error('Pemilik game tidak ditemukan.');
    }

    return {
        placeId: id,
        universeId: String(universe.universeId),
        creatorType: creator.type,
        creatorId: String(creator.id),
        creatorName: creator.name || '',
        experienceName:
            game?.data?.[0]?.name || `Experience #${id}`,
        visits: Number(game?.data?.[0]?.visits || 0)
    };
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
            price VARCHAR(64),
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
            creator_user_id VARCHAR(32),
            product_name VARCHAR(120) DEFAULT 'General Product',
            image_url TEXT,
            download_url TEXT,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            expires_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

            CONSTRAINT license_exactly_one_owner CHECK (
                (owner_user_id IS NOT NULL AND group_id IS NULL)
                OR
                (owner_user_id IS NULL AND group_id IS NOT NULL)
            )
        );

        ALTER TABLE licenses
            ADD COLUMN IF NOT EXISTS creator_user_id VARCHAR(32);

        UPDATE licenses
        SET creator_user_id = owner_user_id
        WHERE creator_user_id IS NULL
            AND owner_user_id IS NOT NULL;

        ALTER TABLE products
            ADD COLUMN IF NOT EXISTS price VARCHAR(64);

        ALTER TABLE products
            ADD COLUMN IF NOT EXISTS image_url TEXT;

        ALTER TABLE products
            ADD COLUMN IF NOT EXISTS download_url TEXT;

        CREATE TABLE IF NOT EXISTS license_products(
            license_id BIGINT NOT NULL
                REFERENCES licenses(id) ON DELETE CASCADE,

            product_id BIGINT NOT NULL
                REFERENCES products(id) ON DELETE RESTRICT,

            PRIMARY KEY(license_id, product_id)
        );

        -- BACKFILL LISENSI LAMA: sebelum license_products tersedia,
        -- hubungan produk hanya tersimpan di licenses.product_name.
        -- Hubungkan otomatis agar lisensi lama tetap dapat diverifikasi.
        INSERT INTO license_products(license_id, product_id)
        SELECT
            l.id,
            p.id
        FROM licenses l
        INNER JOIN products p
            ON LOWER(BTRIM(p.product_name)) = LOWER(BTRIM(l.product_name))
        WHERE
            l.product_name IS NOT NULL
            AND BTRIM(l.product_name) <> ''
        ON CONFLICT (license_id, product_id) DO NOTHING;

        CREATE TABLE IF NOT EXISTS project_experiences(
            place_id VARCHAR(32) PRIMARY KEY,
            product_name VARCHAR(120),
            owner_id VARCHAR(32),
            license_id BIGINT REFERENCES licenses(id) ON DELETE SET NULL,
            creator_type VARCHAR(10),
            universe_id VARCHAR(32),
            experience_name VARCHAR(255),
            icon_url TEXT,
            visits BIGINT NOT NULL DEFAULT 0,
            last_ping TIMESTAMPTZ DEFAULT NOW()
        );

        ALTER TABLE project_experiences
            ADD COLUMN IF NOT EXISTS license_id BIGINT
            REFERENCES licenses(id) ON DELETE SET NULL;

        ALTER TABLE project_experiences
            ADD COLUMN IF NOT EXISTS creator_type VARCHAR(10);

        ALTER TABLE project_experiences
            ADD COLUMN IF NOT EXISTS universe_id VARCHAR(32);

        ALTER TABLE project_experiences
            ADD COLUMN IF NOT EXISTS experience_name VARCHAR(255);

        ALTER TABLE project_experiences
            ADD COLUMN IF NOT EXISTS icon_url TEXT;

        ALTER TABLE project_experiences
            ADD COLUMN IF NOT EXISTS visits BIGINT NOT NULL DEFAULT 0;

        UPDATE project_experiences pe
        SET license_id = matched.license_id
        FROM (
            SELECT DISTINCT ON (old_pe.place_id)
                old_pe.place_id,
                l.id AS license_id
            FROM project_experiences old_pe
            INNER JOIN licenses l
                ON (
                    (
                        old_pe.creator_type = 'User'
                        AND l.owner_user_id = old_pe.owner_id
                    )
                    OR (
                        old_pe.creator_type = 'Group'
                        AND l.group_id = old_pe.owner_id
                    )
                    OR (
                        old_pe.creator_type IS NULL
                        AND (
                            l.owner_user_id = old_pe.owner_id
                            OR l.group_id = old_pe.owner_id
                        )
                    )
                )
            INNER JOIN license_products lp
                ON lp.license_id = l.id
            INNER JOIN products p
                ON p.id = lp.product_id
            WHERE old_pe.license_id IS NULL
                AND LOWER(p.product_name) = LOWER(old_pe.product_name)
                AND l.is_active = TRUE
                AND p.is_active = TRUE
                AND (
                    l.expires_at IS NULL
                    OR l.expires_at > NOW()
                )
            ORDER BY old_pe.place_id, l.created_at DESC
        ) matched
        WHERE pe.place_id = matched.place_id
            AND pe.license_id IS NULL;

        CREATE INDEX IF NOT EXISTS idx_licenses_owner_user
            ON licenses(owner_user_id);

        CREATE INDEX IF NOT EXISTS idx_licenses_group
            ON licenses(group_id);

        CREATE INDEX IF NOT EXISTS idx_licenses_creator_user
            ON licenses(creator_user_id);

        CREATE INDEX IF NOT EXISTS idx_license_products_product
            ON license_products(product_id);

        CREATE INDEX IF NOT EXISTS idx_project_experiences_ping
            ON project_experiences(last_ping);

        CREATE INDEX IF NOT EXISTS idx_project_experiences_license
            ON project_experiences(license_id);

        CREATE TABLE IF NOT EXISTS audio_accounts(
            user_id VARCHAR(32) PRIMARY KEY,
            username VARCHAR(64) NOT NULL,
            credit_balance INTEGER NOT NULL DEFAULT 0,
            credit_expires_at TIMESTAMPTZ,
            daily_date DATE,
            daily_used INTEGER NOT NULL DEFAULT 0,
            total_converted BIGINT NOT NULL DEFAULT 0,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS audio_jobs(
            id BIGSERIAL PRIMARY KEY,
            user_id VARCHAR(32) NOT NULL,
            username VARCHAR(64) NOT NULL,
            source_name VARCHAR(255) NOT NULL,
            output_name VARCHAR(255) NOT NULL,
            speed NUMERIC(4,2) NOT NULL,
            gain_db NUMERIC(5,2) NOT NULL,
            output_bytes BIGINT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS audio_settings(
            setting_key VARCHAR(80) PRIMARY KEY,
            setting_value TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        INSERT INTO audio_settings(setting_key,setting_value)
        VALUES
            ('price_7d','Rp 15.000'),
            ('price_30d','Rp 45.000'),
            ('credits_7d','30'),
            ('credits_30d','150'),
            ('discord_url','https://discord.gg/XkuKuv23bH')
        ON CONFLICT(setting_key) DO NOTHING;

        CREATE TABLE IF NOT EXISTS audio_subscription_requests(
            id BIGSERIAL PRIMARY KEY,
            user_id VARCHAR(32) NOT NULL,
            username VARCHAR(64) NOT NULL,
            package_code VARCHAR(20) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

    `);

    console.log('[DSS] Database schema ready.');
}

// ============================================================
// LICENSE PRODUCT HELPERS
// ============================================================

async function listLicenseProducts(licenseId) {
    const { rows } = await pool.query(`
        SELECT
            p.id,
            p.product_code,
            p.product_name,
            p.description,
            p.price,
            p.image_url,
            p.download_url,
            p.is_active AS product_active

        FROM license_products lp

        JOIN products p
            ON p.id = lp.product_id

        WHERE lp.license_id = $1

        ORDER BY p.product_name
    `, [licenseId]);

    return rows;
}

// ============================================================
// OWNED PORTAL LICENSES
// ============================================================

async function listOwnedPortalLicenses(user) {
    const { rows } = await pool.query(`
        SELECT l.*
        FROM licenses l
        WHERE
            l.owner_user_id = $1
            OR l.creator_user_id = $1
            OR l.group_id IS NOT NULL
        ORDER BY l.created_at DESC
    `, [user.userId]);

    const owned = [];

    for (const license of rows) {
        let group = null;

        if (license.group_id) {
            group = await getRobloxGroupInfo(license.group_id);

            if (
                !group?.ownerUserId ||
                String(group.ownerUserId) !== String(user.userId)
            ) {
                continue;
            }
        } else if (
            String(license.owner_user_id || '') !== String(user.userId) &&
            String(license.creator_user_id || '') !== String(user.userId)
        ) {
            // Lisensi User boleh ditampilkan jika akun login adalah
            // owner_user_id ATAU creator_user_id yang terverifikasi.
            continue;
        }

        const productRows = await listLicenseProducts(license.id);
        const product = productRows[0] || null;

        owned.push({
            id: license.id,
            license_key: license.license_key,
            is_active: license.is_active,
            expires_at: license.expires_at,

            owner_type: group ? 'group' : 'user',

            owner_display_name:
                user.displayName || user.exactUsername,

            owner_username: user.exactUsername,
            owner_avatar_url: user.avatarUrl,

            creator_user_id:
                license.creator_user_id ||
                license.owner_user_id ||
                group?.ownerUserId ||
                null,

            group_name: group?.groupName || null,
            group_icon_url: group?.groupIconUrl || null,
            group_id: license.group_id || null,

            product: product ? {
                id: product.id,
                product_name: product.product_name,
                product_code: product.product_code,
                description: product.description,
                price: product.price,
                image_url: product.image_url,
                download_url: product.download_url,
                product_active: !!product.product_active
            } : null
        });
    }

    return owned;
}

// ============================================================
// FIND VALID PORTAL LICENSE
// ============================================================

async function findValidPortalLicense(username, key) {
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
        WHERE
            l.license_key = $1
            AND l.is_active = TRUE
            AND (
                l.expires_at IS NULL
                OR l.expires_at > NOW()
            )
            AND (
                l.owner_user_id = $2
                OR l.creator_user_id = $2
                OR l.group_id IS NOT NULL
            )
        ORDER BY
            CASE
                WHEN l.owner_user_id = $2 THEN 0
                ELSE 1
            END
        LIMIT 1
    `, [key, user.userId]);

    if (!rows.length) {
        return {
            error: 'Key salah, tidak aktif, atau kedaluwarsa.',
            status: 401
        };
    }

    const license = rows[0];

    if (license.group_id) {
        const group = await getRobloxGroupInfo(license.group_id);

        if (!group?.ownerUserId) {
            return {
                error: 'Pemilik grup tidak dapat diverifikasi dari Roblox.',
                status: 502
            };
        }

        if (String(group.ownerUserId) !== String(user.userId)) {
            return {
                error: 'Lisensi ini bukan milik Creator ID akun Roblox tersebut.',
                status: 403
            };
        }

        return {
            user,
            license,
            group
        };
    }

    if (
        String(license.owner_user_id) !== String(user.userId) &&
        String(license.creator_user_id) !== String(user.userId)
    ) {
        return {
            error: 'Lisensi ini bukan milik Creator ID akun Roblox tersebut.',
            status: 401
        };
    }

    return {
        user,
        license,
        group: null
    };
}

// ============================================================
// CLIENT LOGIN
// ============================================================

async function clientLoginHandler(req, res) {
    const username = cleanText(req.body?.owner_name, 64);
    const key = cleanText(req.body?.license_key, 255);

    if (!username || !key) {
        return sendError(
            res,
            400,
            'Username Roblox dan License Key wajib diisi.'
        );
    }

    try {
        const verification = await findValidPortalLicense(
            username,
            key
        );

        if (verification.error) {
            return sendError(
                res,
                verification.status,
                verification.error
            );
        }

        const [
            catalog,
            ownedLicenses,
            ownedCommunities
        ] = await Promise.all([
            pool.query(`
                SELECT
                    id,
                    product_code,
                    product_name,
                    description,
                    price,
                    image_url,
                    download_url,
                    is_active
                FROM products
                WHERE is_active = TRUE
                ORDER BY created_at DESC, product_name ASC
            `),

            listOwnedPortalLicenses(verification.user),

            getOwnedRobloxCommunities(
                verification.user.userId
            )
        ]);

        const displayName =
            verification.user.displayName ||
            verification.user.exactUsername;

        // PROJECT EXPERIENCE PUBLIC CATALOG
        // Semua pengguna Portal Client dapat melihat semua Experience
        // yang pernah terdaftar, dari seluruh pemilik lisensi.
        // Hanya metadata Experience yang dipublikasikan; informasi
        // privat seperti license_key dan detail lisensi tidak dikirim.
        const projectResult = await pool.query(`
            SELECT DISTINCT
                pe.place_id,
                pe.product_name,
                pe.owner_id,
                pe.creator_type,
                pe.universe_id,
                pe.experience_name,
                pe.icon_url,
                pe.visits,
                pe.last_ping
            FROM project_experiences pe
            ORDER BY pe.last_ping DESC
        `);

        const licensedProjects = projectResult.rows;

        return res.json({
            success: true,

            avatar_url: verification.user.avatarUrl,

            owner_name: verification.user.exactUsername,
            owner_username: verification.user.exactUsername,
            owner_display_name: displayName,
            owner_user_id: verification.user.userId,

            owner_type: 'user',

            license_owner_type:
                verification.group ? 'group' : 'user',

            owned_communities: ownedCommunities,

            license: {
                id: verification.license.id,
                license_key: verification.license.license_key,
                expires_at: verification.license.expires_at,
                is_active: verification.license.is_active,
                group_id: verification.license.group_id || null,
                creator_user_id:
                    verification.license.creator_user_id ||
                    verification.license.owner_user_id ||
                    verification.group?.ownerUserId ||
                    null
            },

            data: catalog.rows.map(product => ({
                id: product.id,
                product: product.product_name,
                product_code: product.product_code,
                description: product.description,
                price: product.price,
                image_url: product.image_url,
                download_url: product.download_url
            })),

            owned_licenses: ownedLicenses,
            projects: licensedProjects
        });
    } catch (error) {
        console.error('[CLIENT LOGIN]', error.message);

        return sendError(
            res,
            502,
            'Gagal menghubungi Roblox atau database. Coba lagi.'
        );
    }
}

app.post(
    '/api/client-login',
    rateLimit({ windowMs: 60_000, max: 12 }),
    clientLoginHandler
);

app.post(
    '/api/client-refresh',
    rateLimit({ windowMs: 60_000, max: 20 }),
    clientLoginHandler
);
// ============================================================
// PORTAL LOGIN
// ============================================================

app.post(
    '/api/portal-login',
    rateLimit({ windowMs: 60_000, max: 8 }),
    async (req, res) => {
        const username = cleanText(req.body?.owner_name, 64);
        const credential = cleanText(req.body?.credential, 255);

        if (!username || !credential) {
            return sendError(
                res,
                400,
                'Username Roblox dan kredensial wajib diisi.'
            );
        }

        if (safeEqual(credential, API_SECRET)) {
            try {
                const user = await getRobloxUserInfo(username);

                if (!user || user.userId !== OWNER_ROBLOX_USER_ID) {
                    return sendError(
                        res,
                        401,
                        'Username Roblox atau kredensial tidak valid.'
                    );
                }

                setAdminCookie(req, res);

                return res.json({
                    success: true,
                    access: 'admin',
                    owner_name: user.exactUsername
                });
            } catch (error) {
                console.error('[OWNER LOGIN]', error.message);

                return sendError(
                    res,
                    502,
                    'Verifikasi Roblox gagal. Coba lagi.'
                );
            }
        }

        req.body = {
            owner_name: username,
            license_key: credential
        };

        return clientLoginHandler(req, res);
    }
);

// ============================================================
// ADMIN SESSION
// ============================================================

app.get('/api/admin-session', (req, res) => {
    res.json({
        success: true,
        authenticated: hasAdmin(req)
    });
});

app.post('/api/admin-logout', (req, res) => {
    res.clearCookie(COOKIE, {
        httpOnly: true,
        secure:
            req.secure ||
            req.get('x-forwarded-proto') === 'https',
        sameSite: 'strict',
        path: '/'
    });

    res.json({
        success: true,
        message: 'Sesi Admin ditutup.'
    });
});

// ============================================================
// GAME DETAILS
// ============================================================

app.post(
    '/api/game-details',
    rateLimit({ windowMs: 60_000, max: 40 }),
    async (req, res) => {
        const placeId = validNumericId(req.body?.place_id, 20);

        if (!placeId) {
            return sendError(res, 400, 'place_id tidak valid.');
        }

        try {
            let name = `Experience #${placeId}`;
            let icon = DEFAULT_IMAGE;
            let creatorName = 'Unknown Creator';
            let visits = 0;
            let universeId = null;
            let creatorId = null;
            let creatorType = null;

            const universe = await robloxFetch(
                `https://apis.roblox.com/universes/v1/places/${encodeURIComponent(placeId)}/universe`
            );

            universeId = universe?.universeId
                ? String(universe.universeId)
                : null;

            if (universeId) {
                const game = await robloxFetch(
                    `https://games.roblox.com/v1/games?universeIds=${encodeURIComponent(universeId)}`
                );

                const data = game?.data?.[0];

                if (data?.name) name = data.name;
                if (data?.creator?.name) creatorName = data.creator.name;
                if (data?.creator?.id != null) {
                    creatorId = String(data.creator.id);
                }
                if (data?.creator?.type) {
                    creatorType = data.creator.type;
                }
                if (data?.visits !== undefined) {
                    visits = data.visits;
                }
            }

            try {
                const thumbnail = await robloxFetch(
                    `https://thumbnails.roblox.com/v1/places/gameicons?placeIds=${encodeURIComponent(placeId)}&size=512x512&format=Png&isCircular=false`
                );

                const imageUrl = thumbnail?.data?.[0]?.imageUrl;

                if (imageUrl) icon = imageUrl;
            } catch {}

            return res.json({
                success: true,
                place_id: placeId,
                universe_id: universeId,
                name,
                icon,
                creatorName,
                creator_id: creatorId,
                creator_type: creatorType,
                visits
            });
        } catch (error) {
            console.error('[GAME DETAILS]', error.message);

            return res.json({
                success: true,
                place_id: placeId,
                name: `Experience #${placeId}`,
                icon: DEFAULT_IMAGE,
                creatorName: 'Unknown Creator',
                creator_id: null,
                creator_type: null,
                visits: 0
            });
        }
    }
);

// ============================================================
// GAME VERIFY V5 — CREATOR ROOT + SERVER IDENTITY
//
// Request wajib dari ServerScriptService:
// place_id, universe_id, creator_id, creator_type, product_name
// Header: x-dss-loader-key
//
// Untuk experience publik, identitas server dicocokkan dengan Roblox API.
// Jika Roblox API tidak dapat membaca experience private/unlisted, identitas
// engine dari server Roblox dipakai setelah LOADER_SECRET tervalidasi.
// Creator Group selalu dipetakan ke UserId pemilik Group.
// ============================================================

app.post(
    '/api/game-verify',
    rateLimit({ windowMs: 60_000, max: 60 }),
    async (req, res) => {
        if (!LOADER_SECRET || LOADER_SECRET.length < 32) {
            return sendError(
                res,
                503,
                'Verifikasi loader belum dikonfigurasi.',
                { authorized: false }
            );
        }

        const suppliedSecret = String(req.get('x-dss-loader-key') || '');

        if (!safeEqual(suppliedSecret, LOADER_SECRET)) {
            return sendError(
                res,
                401,
                'Loader authentication gagal.',
                { authorized: false }
            );
        }

        const placeId = validNumericId(req.body?.place_id, 20);
        const universeId = validNumericId(req.body?.universe_id, 20);
        const runtimeCreatorId = validNumericId(req.body?.creator_id, 20);
        const runtimeCreatorType = cleanText(req.body?.creator_type, 10);
        const requestedProductName = cleanText(req.body?.product_name, 120);

        if (
            !placeId || placeId === '0' ||
            !universeId || universeId === '0' ||
            !runtimeCreatorId || runtimeCreatorId === '0' ||
            !['User', 'Group'].includes(runtimeCreatorType) ||
            !requestedProductName
        ) {
            return sendError(
                res,
                400,
                'Identitas experience tidak lengkap atau tidak valid.',
                { authorized: false }
            );
        }

        try {
            let creator = {
                placeId,
                universeId,
                creatorType: runtimeCreatorType,
                creatorId: runtimeCreatorId,
                creatorName: '',
                experienceName: `Experience #${placeId}`,
                visits: 0
            };

            let robloxLookup = 'runtime';

            // Jika API Roblox berhasil membaca place, hasilnya wajib cocok
            // dengan identitas engine yang dikirim server Roblox.
            try {
                const publicCreator = await getPlaceCreator(placeId);

                const matches =
                    String(publicCreator.universeId) === universeId &&
                    String(publicCreator.creatorId) === runtimeCreatorId &&
                    String(publicCreator.creatorType) === runtimeCreatorType;

                if (matches) {
                    // Gunakan metadata publik hanya jika seluruh identitas cocok.
                    // Identitas runtime Roblox tetap menjadi sumber utama.
                    creator = publicCreator;
                    robloxLookup = 'roblox-api';
                } else {
                    // Data publik yang berbeda/tidak sinkron tidak boleh
                    // menggantikan identitas runtime yang dikirim Roblox.
                    // Lisensi tetap divalidasi terhadap runtime Creator dan
                    // pemilik Group yang diverifikasi langsung dari Roblox.
                    robloxLookup = 'runtime-public-mismatch';
                    console.warn(
                        '[GAME VERIFY] Public metadata mismatch; using runtime identity.',
                        { placeId, universeId, runtimeCreatorId, runtimeCreatorType }
                    );
                }
            } catch {
                // Roblox API terkadang tidak mengembalikan data experience
                // private/unlisted. Fallback hanya boleh terjadi setelah
                // shared loader secret lolos dan data engine valid.
            }

            const creatorId = validNumericId(creator.creatorId, 20);
            const creatorType = creator.creatorType;

            if (
                !creatorId ||
                !['User', 'Group'].includes(creatorType) ||
                creatorId !== runtimeCreatorId ||
                creatorType !== runtimeCreatorType ||
                String(creator.universeId) !== universeId
            ) {
                return res.json({
                    success: true,
                    authorized: false,
                    place_id: placeId,
                    message: 'Identitas Creator dari server tidak valid.'
                });
            }

            let canonicalCreatorUserId = null;
            let groupInfo = null;

            if (creatorType === 'User') {
                canonicalCreatorUserId = creatorId;
            } else {
                groupInfo = await getRobloxGroupInfo(creatorId);

                canonicalCreatorUserId = validNumericId(
                    groupInfo?.ownerUserId,
                    20
                );

                if (!canonicalCreatorUserId) {
                    return res.json({
                        success: true,
                        authorized: false,
                        place_id: placeId,
                        creator_id: creatorId,
                        creator_type: creatorType,
                        message: 'Pemilik komunitas tidak dapat diverifikasi dari Roblox.'
                    });
                }
            }

            const { rows } = await pool.query(`
                SELECT
                    p.product_name,
                    l.id AS license_id,
                    l.owner_user_id,
                    l.group_id,
                    l.creator_user_id,
                    l.is_active,
                    l.expires_at
                FROM licenses l
                INNER JOIN license_products lp
                    ON lp.license_id = l.id
                INNER JOIN products p
                    ON p.id = lp.product_id
                WHERE
                    l.is_active = TRUE
                    AND p.is_active = TRUE
                    AND LOWER(p.product_name) = LOWER($1)
                    AND (
                        l.expires_at IS NULL
                        OR l.expires_at > NOW()
                    )
                    AND (
                        (
                            $3 = 'Group'
                            AND l.group_id = $4
                        )
                        OR (
                            $3 = 'User'
                            AND l.group_id IS NULL
                            AND (
                                l.creator_user_id = $2
                                OR l.owner_user_id = $2
                            )
                        )
                    )
                ORDER BY l.created_at DESC
            `, [
                requestedProductName,
                canonicalCreatorUserId,
                creatorType,
                creatorType === 'Group' ? creatorId : null
            ]);

            let authorizedProduct = null;

            for (const candidate of rows) {
                if (creatorType === 'Group') {
                    // Group license wajib menunjuk ke Group ID experience ini,
                    // bukan sekadar Group lain yang kebetulan punya owner sama.
                    if (
                        String(candidate.group_id || '') !== creatorId
                    ) {
                        continue;
                    }

                    const verifiedGroup = await getRobloxGroupInfo(creatorId);
                    if (
                        String(verifiedGroup?.ownerUserId || '') !==
                        canonicalCreatorUserId
                    ) {
                        continue;
                    }

                    if (
                        candidate.creator_user_id &&
                        String(candidate.creator_user_id) !== canonicalCreatorUserId
                    ) {
                        continue;
                    }

                    authorizedProduct = candidate;

                    if (!candidate.creator_user_id) {
                        await pool.query(`
                            UPDATE licenses
                            SET creator_user_id = $1
                            WHERE id = $2
                                AND creator_user_id IS NULL
                                AND group_id = $3
                        `, [
                            canonicalCreatorUserId,
                            candidate.license_id,
                            creatorId
                        ]);
                    }

                    break;
                }

                if (
                    creatorType === 'User' &&
                    !candidate.group_id &&
                    (
                        String(candidate.creator_user_id || '') === canonicalCreatorUserId ||
                        String(candidate.owner_user_id || '') === canonicalCreatorUserId
                    )
                ) {
                    authorizedProduct = candidate;
                    break;
                }
            }

            if (!authorizedProduct) {
                return res.json({
                    success: true,
                    authorized: false,
                    place_id: placeId,
                    universe_id: universeId,
                    creator_id: creatorId,
                    creator_type: creatorType,
                    creator_user_id: canonicalCreatorUserId,
                    product_name: requestedProductName,
                    message: 'Tidak ditemukan lisensi aktif untuk Creator ID ini.'
                });
            }

            let iconUrl = null;

            try {
                const thumbnail = await robloxFetch(
                    `https://thumbnails.roblox.com/v1/places/gameicons?placeIds=${encodeURIComponent(placeId)}&size=512x512&format=Png&isCircular=false`
                );

                iconUrl = thumbnail?.data?.[0]?.imageUrl || null;
            } catch {}

            await pool.query(`
                INSERT INTO project_experiences(
                    place_id,
                    product_name,
                    owner_id,
                    license_id,
                    creator_type,
                    universe_id,
                    experience_name,
                    icon_url,
                    visits,
                    last_ping
                )
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
                ON CONFLICT(place_id) DO UPDATE SET
                    product_name = EXCLUDED.product_name,
                    owner_id = EXCLUDED.owner_id,
                    license_id = EXCLUDED.license_id,
                    creator_type = EXCLUDED.creator_type,
                    universe_id = EXCLUDED.universe_id,
                    experience_name = EXCLUDED.experience_name,
                    icon_url = COALESCE(
                        EXCLUDED.icon_url,
                        project_experiences.icon_url
                    ),
                    visits = EXCLUDED.visits,
                    last_ping = NOW()
            `, [
                placeId,
                authorizedProduct.product_name,
                creatorId,
                authorizedProduct.license_id,
                creatorType,
                universeId,
                creator.experienceName,
                iconUrl,
                Number(creator.visits || 0)
            ]);

            return res.json({
                success: true,
                authorized: true,
                product_name: authorizedProduct.product_name,
                place_id: placeId,
                universe_id: universeId,
                experience_name: creator.experienceName,
                creator_id: creatorId,
                creator_type: creatorType,
                creator_user_id: canonicalCreatorUserId,
                group_id: creatorType === 'Group' ? creatorId : null,
                group_name: groupInfo?.groupName || null,
                identity_source: robloxLookup,
                message: 'Experience terverifikasi melalui Creator ID utama.'
            });
        } catch (error) {
            console.error('[GAME VERIFY]', error.message);

            return res.status(error.statusCode || 502).json({
                success: false,
                authorized: false,
                message: 'Verifikasi lisensi gagal sementara. Coba lagi.'
            });
        }
    }
);

// ============================================================
// AUTO PROJECTS
// ============================================================

app.get('/api/auto-projects', verifyAdmin, async (_req, res) => {
    try {
        const { rows } = await pool.query(`
            SELECT
                pe.place_id,
                pe.product_name,
                pe.owner_id,
                pe.license_id,
                pe.creator_type,
                pe.universe_id,
                pe.experience_name,
                pe.icon_url,
                pe.visits,
                pe.last_ping,

                l.owner_name,
                l.owner_user_id,
                l.group_id,
                l.creator_user_id,
                l.is_active AS license_active,
                l.expires_at

            FROM project_experiences pe

            INNER JOIN licenses l
                ON l.id = pe.license_id

            WHERE l.is_active = TRUE
                AND (
                    l.expires_at IS NULL
                    OR l.expires_at > NOW()
                )

            ORDER BY pe.last_ping DESC
        `);

        return res.json({
            success: true,
            projects: rows.map(row => row.place_id),
            data: rows
        });
    } catch (error) {
        console.error('[AUTO PROJECTS]', error.message);

        return sendError(
            res,
            500,
            'Gagal membaca project experience.'
        );
    }
});

app.delete(
    '/api/auto-projects/:pid',
    verifyAdmin,
    async (req, res) => {
        const placeId = validNumericId(
            req.params.pid,
            20
        );

        if (!placeId) {
            return sendError(
                res,
                400,
                'Place ID tidak valid.'
            );
        }

        try {
            await pool.query(
                'DELETE FROM project_experiences WHERE place_id=$1',
                [placeId]
            );

            return res.json({
                success: true,
                message: 'Project experience dihapus.'
            });
        } catch (error) {
            console.error('[DELETE PROJECT]', error.message);

            return sendError(
                res,
                500,
                'Gagal menghapus project.'
            );
        }
    }
);
// ============================================================
// PRODUCTS - GET
// ============================================================

app.get('/api/products', verifyAdmin, async (_req, res) => {
    try {
        const { rows } = await pool.query(`
            SELECT
                id,
                product_code,
                product_name,
                description,
                price,
                image_url,
                download_url,
                is_active,
                created_at,
                updated_at
            FROM products
            ORDER BY product_name
        `);

        return res.json({
            success: true,
            products: rows
        });
    } catch (error) {
        console.error('[PRODUCTS GET]', error.message);

        return sendError(
            res,
            500,
            'Gagal membaca katalog.'
        );
    }
});

// ============================================================
// PRODUCTS - CREATE
// ============================================================

app.post('/api/products', verifyAdmin, async (req, res) => {
    const name = cleanText(req.body?.product_name, 120);
    const description = cleanText(req.body?.description, 1000);
    const price = cleanText(req.body?.price, 64);

    const image = validHttpUrl(req.body?.image_url);
    const download = validHttpUrl(req.body?.download_url);

    if (!name) {
        return sendError(
            res,
            400,
            'Nama produk wajib diisi.'
        );
    }

    if (image === undefined || download === undefined) {
        return sendError(
            res,
            400,
            'URL tidak valid.'
        );
    }

    const code = cleanText(
        req.body?.product_code,
        80
    ).toUpperCase() || name
        .toUpperCase()
        .replace(/[^A-Z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '')
        .slice(0, 70);

    if (!code) {
        return sendError(
            res,
            400,
            'Kode produk tidak valid.'
        );
    }

    try {
        const { rows } = await pool.query(`
            INSERT INTO products(
                product_code,
                product_name,
                description,
                price,
                image_url,
                download_url
            )
            VALUES($1,$2,$3,$4,$5,$6)
            RETURNING *
        `, [
            code,
            name,
            description || null,
            price || null,
            image,
            download
        ]);

        return res.status(201).json({
            success: true,
            product: rows[0]
        });
    } catch (error) {
        if (error.code === '23505') {
            return sendError(
                res,
                409,
                'Kode atau nama produk sudah digunakan.'
            );
        }

        console.error('[PRODUCT CREATE]', error.message);

        return sendError(
            res,
            500,
            'Gagal membuat produk.'
        );
    }
});

// ============================================================
// PRODUCTS - UPDATE
// ============================================================

app.put('/api/products/:id', verifyAdmin, async (req, res) => {
    const id = validNumericId(req.params.id, 20);

    const name = cleanText(req.body?.product_name, 120);
    const description = cleanText(req.body?.description, 1000);
    const price = cleanText(req.body?.price, 64);

    const image = validHttpUrl(req.body?.image_url);
    const download = validHttpUrl(req.body?.download_url);

    if (!id || !name) {
        return sendError(
            res,
            400,
            'ID atau nama produk tidak valid.'
        );
    }

    if (image === undefined || download === undefined) {
        return sendError(
            res,
            400,
            'URL tidak valid.'
        );
    }

    const code = cleanText(
        req.body?.product_code,
        80
    ).toUpperCase() || name
        .toUpperCase()
        .replace(/[^A-Z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '')
        .slice(0, 70);

    try {
        const { rows } = await pool.query(`
            UPDATE products SET
                product_code=$1,
                product_name=$2,
                description=$3,
                price=$4,
                image_url=$5,
                download_url=$6,
                updated_at=NOW()
            WHERE id=$7
            RETURNING *
        `, [
            code,
            name,
            description || null,
            price || null,
            image,
            download,
            id
        ]);

        if (!rows.length) {
            return sendError(
                res,
                404,
                'Produk tidak ditemukan.'
            );
        }

        return res.json({
            success: true,
            product: rows[0]
        });
    } catch (error) {
        if (error.code === '23505') {
            return sendError(
                res,
                409,
                'Kode atau nama produk sudah digunakan.'
            );
        }

        console.error('[PRODUCT UPDATE]', error.message);

        return sendError(
            res,
            500,
            'Gagal memperbarui produk.'
        );
    }
});

// ============================================================
// PRODUCTS - ACTIVE STATUS
// ============================================================

app.patch('/api/products/:id', verifyAdmin, async (req, res) => {
    const id = validNumericId(req.params.id, 20);
    const active = req.body?.is_active;

    if (!id || typeof active !== 'boolean') {
        return sendError(
            res,
            400,
            'ID atau status tidak valid.'
        );
    }

    try {
        const { rows } = await pool.query(`
            UPDATE products
            SET is_active=$1, updated_at=NOW()
            WHERE id=$2
            RETURNING id,is_active
        `, [active, id]);

        if (!rows.length) {
            return sendError(
                res,
                404,
                'Produk tidak ditemukan.'
            );
        }

        return res.json({
            success: true,
            product: rows[0]
        });
    } catch (error) {
        console.error('[PRODUCT STATUS]', error.message);

        return sendError(
            res,
            500,
            'Gagal memperbarui status.'
        );
    }
});

// ============================================================
// PRODUCTS - DELETE
// ============================================================

app.delete('/api/products/:id', verifyAdmin, async (req, res) => {
    const id = validNumericId(req.params.id, 20);

    if (!id) {
        return sendError(res, 400, 'ID tidak valid.');
    }

    const connection = await pool.connect();

    try {
        await connection.query('BEGIN');

        const found = await connection.query(
            'SELECT id FROM products WHERE id=$1 FOR UPDATE',
            [id]
        );

        if (!found.rows.length) {
            await connection.query('ROLLBACK');

            return sendError(
                res,
                404,
                'Produk tidak ditemukan.'
            );
        }

        const used = await connection.query(
            'SELECT 1 FROM license_products WHERE product_id=$1 LIMIT 1',
            [id]
        );

        if (used.rows.length) {
            await connection.query('ROLLBACK');

            return sendError(
                res,
                409,
                'Produk masih terikat lisensi. Cabut lisensi terlebih dahulu.'
            );
        }

        await connection.query(
            'DELETE FROM products WHERE id=$1',
            [id]
        );

        await connection.query('COMMIT');

        return res.json({
            success: true,
            message: 'Produk dihapus.'
        });
    } catch (error) {
        await connection.query('ROLLBACK').catch(() => {});

        console.error('[PRODUCT DELETE]', error.message);

        return sendError(
            res,
            500,
            'Gagal menghapus produk.'
        );
    } finally {
        connection.release();
    }
});

// ============================================================
// LICENSES - GET
// ============================================================

app.get('/api/licenses', verifyAdmin, async (_req, res) => {
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

            LEFT JOIN license_products lp
                ON lp.license_id = l.id

            LEFT JOIN products p
                ON p.id = lp.product_id

            GROUP BY l.id
            ORDER BY l.created_at DESC
        `);

        const enhanced = await Promise.all(
            rows.map(async license => {
                if (license.group_id) {
                    const group = await getRobloxGroupInfo(
                        license.group_id
                    );

                    return {
                        ...license,

                        owner_type: 'group',

                        owner_display_name:
                            group.groupName ||
                            `Grup Roblox ${license.group_id}`,

                        owner_avatar_url: group.groupIconUrl,
                        group_name: group.groupName,
                        group_icon_url: group.groupIconUrl,

                        creator_user_id:
                            license.creator_user_id ||
                            group.ownerUserId ||
                            null
                    };
                }

                let avatar = null;
                let displayName = license.owner_name;

                if (license.owner_user_id) {
                    try {
                        const [profile, thumbnail] =
                            await Promise.all([
                                robloxFetch(
                                    `https://users.roblox.com/v1/users/${encodeURIComponent(license.owner_user_id)}`
                                ).catch(() => null),

                                robloxFetch(
                                    `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${encodeURIComponent(license.owner_user_id)}&size=150x150&format=Png&isCircular=false`
                                ).catch(() => null)
                            ]);

                        displayName =
                            profile?.displayName || displayName;

                        avatar =
                            thumbnail?.data?.[0]?.imageUrl || null;
                    } catch {}
                }

                return {
                    ...license,

                    owner_type: 'user',
                    owner_display_name: displayName,
                    owner_avatar_url: avatar,

                    creator_user_id:
                        license.creator_user_id ||
                        license.owner_user_id ||
                        null
                };
            })
        );

        return res.json({
            success: true,
            licenses: enhanced
        });
    } catch (error) {
        console.error('[LICENSES GET]', error.message);

        return sendError(
            res,
            500,
            'Gagal membaca lisensi.'
        );
    }
});

// ============================================================
// LICENSES - CREATE
// ============================================================

app.post('/api/licenses/create', verifyAdmin, async (req, res) => {
    const key = cleanText(req.body?.license_key, 255);
    const ownerInput = cleanText(req.body?.owner_name, 64);

    const groupId = cleanText(
        String(req.body?.group_id ?? ''),
        32
    ) || null;

    const ids = Array.isArray(req.body?.product_ids)
        ? req.body.product_ids
        : [];

    const expires = validExpiry(req.body?.expires_at);
    const image = validHttpUrl(req.body?.image_url);
    const download = validHttpUrl(req.body?.download_url);

    if (!key) {
        return sendError(
            res,
            400,
            'License key wajib diisi.'
        );
    }

    if (
        ids.length !== 1 ||
        !/^\d+$/.test(String(ids[0]))
    ) {
        return sendError(
            res,
            400,
            'Satu lisensi hanya boleh untuk tepat satu produk.'
        );
    }

    if (
        expires === undefined ||
        image === undefined ||
        download === undefined
    ) {
        return sendError(
            res,
            400,
            'Tanggal atau URL tidak valid.'
        );
    }

    if (groupId && !/^\d+$/.test(groupId)) {
        return sendError(
            res,
            400,
            'Group ID harus angka.'
        );
    }

    if (groupId && ownerInput) {
        return sendError(
            res,
            400,
            'Isi pemilik akun atau Group ID saja, jangan keduanya.'
        );
    }

    if (!groupId && !ownerInput) {
        return sendError(
            res,
            400,
            'Username pemilik wajib diisi.'
        );
    }

    let user = null;
    let group = null;

    if (!groupId) {
        try {
            user = await getRobloxUserInfo(ownerInput);
        } catch {
            return sendError(
                res,
                502,
                'Roblox API tidak tersedia.'
            );
        }

        if (!user) {
            return sendError(
                res,
                400,
                'Username Roblox tidak valid.'
            );
        }
    } else {
        group = await getRobloxGroupInfo(groupId);

        if (!group?.groupName || !group?.ownerUserId) {
            return sendError(
                res,
                400,
                'Group ID atau pemilik komunitas tidak dapat diverifikasi.'
            );
        }
    }

    const connection = await pool.connect();

    try {
        await connection.query('BEGIN');

        const productResult = await connection.query(`
            SELECT id, product_name
            FROM products
            WHERE is_active=TRUE AND id=$1
            FOR UPDATE
        `, [String(ids[0])]);

        if (!productResult.rows.length) {
            await connection.query('ROLLBACK');

            return sendError(
                res,
                400,
                'Produk tidak ditemukan atau nonaktif.'
            );
        }

        const product = productResult.rows[0];

        // Creator ID utama:
        // - Lisensi User: User ID akun tersebut.
        // - Lisensi Group: User ID pemilik Group yang diverifikasi Roblox.
        const canonicalCreatorUserId = groupId
            ? validNumericId(group.ownerUserId, 20)
            : user.userId;

        if (!canonicalCreatorUserId) {
            await connection.query('ROLLBACK');

            return sendError(
                res,
                400,
                'Creator ID utama tidak dapat diverifikasi dari Roblox.'
            );
        }

        const inserted = await connection.query(`
            INSERT INTO licenses(
                license_key,
                owner_name,
                owner_user_id,
                group_id,
                creator_user_id,
                product_name,
                image_url,
                download_url,
                expires_at
            )

            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)

            RETURNING id
        `, [
            key,
            groupId ? group.groupName : user.exactUsername,
            groupId ? null : user.userId,
            groupId,
            canonicalCreatorUserId,
            product.product_name,
            image,
            download,
            expires
        ]);

        await connection.query(
            `INSERT INTO license_products(
                license_id,
                product_id
            ) VALUES($1,$2)`,
            [
                inserted.rows[0].id,
                product.id
            ]
        );

        await connection.query('COMMIT');

        return res.status(201).json({
            success: true,
            message: 'Lisensi berhasil dibuat.',
            id: inserted.rows[0].id,
            product_count: 1,
            product_name: product.product_name,
            creator_user_id: canonicalCreatorUserId
        });
    } catch (error) {
        await connection.query('ROLLBACK').catch(() => {});

        if (error.code === '23505') {
            return sendError(
                res,
                409,
                'License Key sudah digunakan.'
            );
        }

        console.error('[LICENSE CREATE]', error.message);

        return sendError(
            res,
            500,
            'Gagal membuat lisensi.'
        );
    } finally {
        connection.release();
    }
});

// ============================================================
// LICENSES - ACTIVE STATUS
// ============================================================

app.patch(
    '/api/licenses/:id/status',
    verifyAdmin,
    async (req, res) => {
        const id = validNumericId(req.params.id, 20);
        const active = req.body?.is_active;

        if (!id || typeof active !== 'boolean') {
            return sendError(
                res,
                400,
                'ID/status tidak valid.'
            );
        }

        try {
            const { rows } = await pool.query(`
                UPDATE licenses
                SET is_active=$1
                WHERE id=$2
                RETURNING id,is_active
            `, [active, id]);

            if (!rows.length) {
                return sendError(
                    res,
                    404,
                    'Lisensi tidak ditemukan.'
                );
            }

            return res.json({
                success: true,
                license: rows[0]
            });
        } catch (error) {
            console.error('[LICENSE STATUS]', error.message);

            return sendError(
                res,
                500,
                'Gagal mengubah status.'
            );
        }
    }
);

// ============================================================
// LICENSES - DELETE
// ============================================================

app.delete('/api/licenses/:id', verifyAdmin, async (req, res) => {
    const id = validNumericId(req.params.id, 20);

    if (!id) {
        return sendError(res, 400, 'ID tidak valid.');
    }

    try {
        const result = await pool.query(
            'DELETE FROM licenses WHERE id=$1',
            [id]
        );

        if (!result.rowCount) {
            return sendError(
                res,
                404,
                'Lisensi tidak ditemukan.'
            );
        }

        return res.json({
            success: true,
            message: 'Lisensi dihapus.'
        });
    } catch (error) {
        console.error('[LICENSE DELETE]', error.message);

        return sendError(
            res,
            500,
            'Gagal menghapus lisensi.'
        );
    }
});

// ============================================================
// FILE TICKET
// ============================================================

app.post(
    '/api/file-ticket',
    rateLimit({ windowMs: 60_000, max: 15 }),
    async (req, res) => {
        const username = cleanText(req.body?.owner_name, 64);
        const key = cleanText(req.body?.license_key, 255);

        const productId = validNumericId(
            req.body?.product_id,
            20
        );

        const kind = req.body?.kind === 'image'
            ? 'image'
            : 'download';

        if (!username || !key || !productId) {
            return sendError(
                res,
                400,
                'Permintaan file tidak valid.'
            );
        }

        try {
            const verification = await findValidPortalLicense(
                username,
                key
            );

            if (verification.error) {
                return sendError(
                    res,
                    verification.status,
                    verification.error
                );
            }

            const { rows } = await pool.query(`
                SELECT p.*
                FROM license_products lp
                JOIN products p
                    ON p.id = lp.product_id
                WHERE
                    lp.license_id = $1
                    AND p.id = $2
                    AND p.is_active = TRUE
                LIMIT 1
            `, [
                verification.license.id,
                productId
            ]);

            const product = rows[0];

            if (!product) {
                return sendError(
                    res,
                    403,
                    'Produk tidak terikat pada lisensi ini.'
                );
            }

            const directUrl = kind === 'image'
                ? product.image_url
                : product.download_url;

            if (!directUrl) {
                return sendError(
                    res,
                    404,
                    'URL file belum tersedia.'
                );
            }

            return res.json({
                success: true,
                url: directUrl
            });
        } catch (error) {
            console.error('[FILE TICKET]', error.message);

            return sendError(
                res,
                500,
                'Gagal membuat akses file.'
            );
        }
    }
);


// ============================================================
// DSS AUDIO CONVERT — AUTHORIZED FILE + DIRECT MEDIA URL CONVERSION
// Accepts user uploads and HTTPS direct-media files from admin-allowlisted
// domains. Platform webpage URLs (including YouTube/TikTok) are deliberately
// rejected: this service does not extract streams or bypass access controls.
// Requires FFmpeg + multer.
// ============================================================

const audioUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 50 * 1024 * 1024, files: 1 },
    fileFilter: (_req, file, cb) => {
        const ext = path.extname(file.originalname || '').toLowerCase();
        const allowed = ['.mp3','.wav','.ogg','.oga','.m4a','.aac','.flac','.opus','.mp4','.m4v','.webm','.mov','.mkv'];
        if (!allowed.includes(ext)) return cb(new Error('Format file tidak didukung.'));
        cb(null, true);
    }
});

async function verifyAudioUser(username, key) {
    const verification = await findValidPortalLicense(username, key);
    if (verification.error) {
        const e = new Error(verification.error);
        e.statusCode = verification.status || 401;
        throw e;
    }
    return verification.user;
}

async function getAudioAccount(user) {
    const owner = String(user.userId) === OWNER_ROBLOX_USER_ID;
    await pool.query(`
        INSERT INTO audio_accounts(user_id,username)
        VALUES($1,$2)
        ON CONFLICT(user_id) DO UPDATE SET username=EXCLUDED.username,updated_at=NOW()
    `, [user.userId, user.exactUsername]);

    const { rows } = await pool.query(`
        SELECT *, (daily_date = CURRENT_DATE) AS daily_current
        FROM audio_accounts WHERE user_id=$1
    `, [user.userId]);
    const row = rows[0];

    const paidActive = row.credit_expires_at && new Date(row.credit_expires_at) > new Date();
    const bonusAvailable = !row.daily_current || Number(row.daily_used) < 2;
    return {
        owner,
        balance: Number(row.credit_balance || 0),
        expiresAt: row.credit_expires_at,
        dailyUsed: row.daily_current ? Number(row.daily_used || 0) : 0,
        dailyRemaining: owner ? -1 : (bonusAvailable ? 2 - (row.daily_current ? Number(row.daily_used || 0) : 0) : 0),
        totalConverted: Number(row.total_converted || 0),
        paidActive: !!paidActive
    };
}

app.get('/api/audio/status', rateLimit({windowMs:60000,max:40}), async (req,res) => {
    try {
        const user = await verifyAudioUser(req.query.username, req.query.key);
        const account = await getAudioAccount(user);
        const settings = await pool.query(`SELECT setting_key,setting_value FROM audio_settings`);
        const cfg = Object.fromEntries(settings.rows.map(x => [x.setting_key,x.setting_value]));
        const history = await pool.query(`
            SELECT id,source_name,output_name,speed,gain_db,output_bytes,created_at
            FROM audio_jobs WHERE user_id=$1 ORDER BY created_at DESC LIMIT 20
        `,[user.userId]);
        return res.json({success:true,account,history:history.rows,packages:{
            days7:{price:cfg.price_7d,credits:Number(cfg.credits_7d||30)},
            days30:{price:cfg.price_30d,credits:Number(cfg.credits_30d||150)}
        },discordUrl:cfg.discord_url || 'https://discord.gg/XkuKuv23bH'});
    } catch(e) { return sendError(res,e.statusCode||401,e.message||'Gagal membaca akun audio.'); }
});


const AUDIO_MAX_BYTES = 50 * 1024 * 1024;
const AUDIO_ALLOWED_EXTENSIONS = new Set([
    '.mp3','.wav','.ogg','.oga','.m4a','.aac','.flac','.opus',
    '.mp4','.m4v','.webm','.mov','.mkv'
]);
const AUDIO_PLATFORM_HOSTS = new Set([
    'youtube.com','www.youtube.com','m.youtube.com','youtu.be',
    'youtube-nocookie.com','www.youtube-nocookie.com',
    'tiktok.com','www.tiktok.com','m.tiktok.com','vm.tiktok.com','vt.tiktok.com'
]);

function isPublicAddress(address) {
    const family = net.isIP(address);
    if (family === 4) {
        const p = address.split('.').map(Number);
        const [a,b] = p;
        if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
        if (a === 100 && b >= 64 && b <= 127) return false;
        if (a === 169 && b === 254) return false;
        if (a === 172 && b >= 16 && b <= 31) return false;
        if (a === 192 && (b === 0 || b === 168)) return false;
        if (a === 198 && (b === 18 || b === 19 || b === 51)) return false;
        if (a === 203 && b === 0) return false;
        return true;
    }
    if (family === 6) {
        const ip = address.toLowerCase();
        if (ip === '::' || ip === '::1' || ip.startsWith('fc') ||
            ip.startsWith('fd') || ip.startsWith('fe8') ||
            ip.startsWith('fe9') || ip.startsWith('fea') ||
            ip.startsWith('feb') || ip.startsWith('ff') ||
            ip.startsWith('2001:db8:')) return false;
        const mapped = ip.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
        if (mapped) return isPublicAddress(mapped[1]);
        return true;
    }
    return false;
}

function allowedAudioSourceHost(hostname) {
    const host = String(hostname || '').toLowerCase().replace(/\.$/, '');
    if (!host || AUDIO_PLATFORM_HOSTS.has(host)) return false;
    if ([...AUDIO_PLATFORM_HOSTS].some(root => host.endsWith('.' + root))) return false;
    const allowlist = String(process.env.AUDIO_SOURCE_ALLOWED_HOSTS || '')
        .split(',')
        .map(x => x.trim().toLowerCase().replace(/\.$/, ''))
        .filter(Boolean);
    return allowlist.includes(host);
}

async function resolvePublicHost(hostname) {
    const records = await dns.lookup(hostname, { all: true, family: 4, verbatim: true });
    if (!records.length || records.some(record => !isPublicAddress(record.address))) {
        throw new Error('Alamat server sumber tidak aman atau tidak publik.');
    }
    return records[0];
}

function requestAllowedMedia(url, redirects = 0) {
    return new Promise(async (resolve, reject) => {
        let parsed;
        try {
            parsed = new URL(url);
            if (parsed.protocol !== 'https:' || parsed.username || parsed.password ||
                (parsed.port && parsed.port !== '443') ||
                !allowedAudioSourceHost(parsed.hostname)) {
                throw new Error('URL harus HTTPS dan domain harus masuk allowlist admin. Link halaman YouTube/TikTok tidak didukung.');
            }
            if (redirects > 2) throw new Error('Terlalu banyak pengalihan URL.');
            const record = await resolvePublicHost(parsed.hostname);
            const req = https.request({
                protocol: 'https:',
                hostname: parsed.hostname,
                port: 443,
                method: 'GET',
                path: parsed.pathname + parsed.search,
                headers: { 'User-Agent': 'DSS-AudioConvert/1.0', 'Accept': 'audio/*,video/*,application/octet-stream;q=0.8' },
                lookup: (_hostname, _options, callback) => callback(null, record.address, record.family),
                timeout: 15000
            }, response => {
                const status = response.statusCode || 0;
                if ([301,302,303,307,308].includes(status)) {
                    const location = response.headers.location;
                    response.resume();
                    if (!location) return reject(new Error('Redirect sumber tidak valid.'));
                    let next;
                    try { next = new URL(location, parsed).toString(); }
                    catch { return reject(new Error('Redirect URL tidak valid.')); }
                    return requestAllowedMedia(next, redirects + 1).then(resolve, reject);
                }
                if (status !== 200) {
                    response.resume();
                    return reject(new Error(`Sumber media menolak permintaan (HTTP ${status}).`));
                }
                const contentType = String(response.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
                const isMedia = contentType.startsWith('audio/') || contentType.startsWith('video/') || contentType === 'application/octet-stream' || contentType === 'binary/octet-stream';
                if (!isMedia) {
                    response.resume();
                    return reject(new Error('URL tidak mengarah ke file audio/video langsung.'));
                }
                const length = Number(response.headers['content-length'] || 0);
                if (length > AUDIO_MAX_BYTES) {
                    response.resume();
                    return reject(new Error('File dari URL melebihi batas 50 MB.'));
                }
                const chunks = [];
                let total = 0;
                response.on('data', chunk => {
                    total += chunk.length;
                    if (total > AUDIO_MAX_BYTES) {
                        response.destroy(new Error('File dari URL melebihi batas 50 MB.'));
                        return;
                    }
                    chunks.push(chunk);
                });
                response.on('end', () => resolve({
                    buffer: Buffer.concat(chunks),
                    contentType,
                    finalUrl: parsed.toString()
                }));
                response.on('error', reject);
            });
            req.on('timeout', () => req.destroy(new Error('Sumber media terlalu lama merespons.')));
            req.on('error', reject);
            req.end();
        } catch (error) {
            reject(error);
        }
    });
}

async function handleAudioConversion(req, res) {
    let tempDir;
    try {
        const username = cleanText(req.body?.username, 64);
        const key = cleanText(req.body?.key, 255);
        if (!req.file?.buffer?.length) return sendError(res, 400, 'Pilih file atau direct media URL terlebih dahulu.');
        const user = await verifyAudioUser(username, key);
        const speed = Number(req.body?.speed ?? 1);
        const gain = Number(req.body?.gainDb ?? 0);
        if (!Number.isFinite(speed) || speed < 0.5 || speed > 3) return sendError(res, 400, 'Speed harus antara 0.5x sampai 3.0x.');
        if (!Number.isFinite(gain) || gain < -24 || gain > 12) return sendError(res, 400, 'Amplifier harus antara -24 dB sampai +12 dB.');
        if (req.file.buffer.length > AUDIO_MAX_BYTES) return sendError(res, 413, 'Ukuran file maksimal 50 MB.');

        const account = await getAudioAccount(user);
        const hasPaidCredit = account.balance > 0 && (!account.expiresAt || new Date(account.expiresAt) > new Date());
        const hasDaily = account.dailyRemaining > 0;
        if (!account.owner && !hasPaidCredit && !hasDaily) {
            return sendError(res, 403, 'Kredit harian habis. Silakan gunakan paket kredit melalui menu Langganan.');
        }

        const originalName = path.basename(String(req.file.originalname || 'audio.mp4')).slice(0, 180);
        const ext = path.extname(originalName).toLowerCase();
        if (!AUDIO_ALLOWED_EXTENSIONS.has(ext)) return sendError(res, 400, 'Format media tidak didukung.');
        tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'dss-audio-'));
        const inputPath = path.join(tempDir, 'input' + ext);
        const outputPath = path.join(tempDir, 'output.ogg');
        await fs.promises.writeFile(inputPath, req.file.buffer, { mode: 0o600 });

        const atempo = [];
        let remaining = speed;
        while (remaining > 2) { atempo.push('atempo=2'); remaining /= 2; }
        while (remaining < 0.5) { atempo.push('atempo=0.5'); remaining /= 0.5; }
        atempo.push(`atempo=${remaining.toFixed(4)}`);
        const filter = `${atempo.join(',')},volume=${gain}dB`;

        await new Promise((resolve, reject) => {
            const ff = spawn(process.env.FFMPEG_PATH || 'ffmpeg', [
                '-nostdin','-hide_banner','-loglevel','error','-y',
                '-i',inputPath,'-t','600','-vn','-map_metadata','-1',
                '-threads','2','-af',filter,'-c:a','libvorbis','-q:a','5',outputPath
            ], { stdio: ['ignore','ignore','pipe'] });
            let err = '';
            const timer = setTimeout(() => {
                ff.kill('SIGKILL');
                reject(new Error('Konversi melewati batas waktu 120 detik.'));
            }, 120000);
            ff.stderr.on('data', data => { if (err.length < 4000) err += data.toString(); });
            ff.on('error', error => { clearTimeout(timer); reject(error); });
            ff.on('close', code => {
                clearTimeout(timer);
                if (code === 0) resolve();
                else reject(new Error(err || `FFmpeg berhenti dengan kode ${code}.`));
            });
        });

        const output = await fs.promises.readFile(outputPath);
        if (!output.length || output.length > 100 * 1024 * 1024) throw new Error('Hasil konversi kosong atau melebihi batas ukuran.');
        const safeBase = path.basename(originalName, ext).replace(/[^a-z0-9_-]/gi, '_').slice(0, 80) || 'audio';
        const outputName = safeBase + '.ogg';

        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            const latest = await client.query(`
                SELECT credit_balance,credit_expires_at,daily_date,daily_used,
                       (daily_date = CURRENT_DATE) AS daily_current
                FROM audio_accounts WHERE user_id=$1 FOR UPDATE
            `, [user.userId]);
            const a = latest.rows[0];
            const creditValid = Number(a.credit_balance) > 0 && (!a.credit_expires_at || new Date(a.credit_expires_at) > new Date());
            const dailyCount = a.daily_current ? Number(a.daily_used || 0) : 0;
            if (!account.owner) {
                if (creditValid) {
                    await client.query(`UPDATE audio_accounts SET credit_balance=GREATEST(0,credit_balance-1),updated_at=NOW() WHERE user_id=$1`, [user.userId]);
                } else if (dailyCount < 2) {
                    await client.query(`UPDATE audio_accounts SET daily_date=CURRENT_DATE,daily_used=$2,updated_at=NOW() WHERE user_id=$1`, [user.userId, dailyCount + 1]);
                } else {
                    throw new Error('Kredit tidak tersedia. Muat ulang status akun lalu coba lagi.');
                }
            }
            await client.query(`UPDATE audio_accounts SET total_converted=total_converted+1,updated_at=NOW() WHERE user_id=$1`, [user.userId]);
            await client.query(`
                INSERT INTO audio_jobs(user_id,username,source_name,output_name,speed,gain_db,output_bytes)
                VALUES($1,$2,$3,$4,$5,$6,$7)
            `, [user.userId, user.exactUsername, originalName, outputName, speed, gain, output.length]);
            await client.query('COMMIT');
        } catch (error) {
            await client.query('ROLLBACK').catch(() => {});
            throw error;
        } finally {
            client.release();
        }

        res.setHeader('Content-Type', 'audio/ogg');
        res.setHeader('Content-Disposition', `attachment; filename="${outputName}"`);
        res.setHeader('X-DSS-Converted', '1');
        return res.send(output);
    } catch (error) {
        console.error('[AUDIO CONVERT]', error.message);
        return sendError(res, error.statusCode || 400, error.message || 'Konversi gagal. Pastikan FFmpeg tersedia.');
    } finally {
        if (tempDir) await fs.promises.rm(tempDir, { recursive: true, force: true }).catch(() => {});
    }
}

app.post('/api/audio/convert',
    rateLimit({ windowMs: 60000, max: 10 }),
    (req, res, next) => audioUpload.single('audio')(req, res, error => {
        if (error) return sendError(res, 400, error.message || 'Upload gagal.');
        next();
    }),
    handleAudioConversion
);

app.post('/api/audio/convert-url',
    rateLimit({ windowMs: 60000, max: 5 }),
    (req, res, next) => audioUpload.none()(req, res, error => {
        if (error) return sendError(res, 400, error.message || 'Form URL tidak valid.');
        next();
    }),
    async (req, res) => {
        try {
            const sourceUrl = String(req.body?.sourceUrl || '').trim();
            if (!sourceUrl || sourceUrl.length > 2048) return sendError(res, 400, 'Tautan HTTPS wajib diisi dan maksimal 2048 karakter.');
            let submittedUrl;
            try { submittedUrl = new URL(sourceUrl); }
            catch { return sendError(res, 400, 'Format tautan tidak valid. Masukkan URL HTTPS yang benar.'); }
            const submittedHost = submittedUrl.hostname.toLowerCase().replace(/^www\./, '').replace(/^m\./, '');
            const isPlatformPage = submittedUrl.protocol === 'https:' && (
                submittedHost === 'youtube.com' || submittedHost === 'youtu.be' ||
                submittedHost.endsWith('.youtube.com') || submittedHost === 'youtube-nocookie.com' ||
                submittedHost.endsWith('.youtube-nocookie.com') || submittedHost === 'tiktok.com' ||
                submittedHost.endsWith('.tiktok.com')
            );
            if (isPlatformPage) {
                return res.status(409).json({
                    success: false,
                    code: 'PLATFORM_DOWNLOAD_REQUIRED',
                    message: 'Link ini adalah halaman platform, bukan file media langsung. DSS hanya menerima file milik Anda atau tautan HTTPS langsung ke file audio/video dari domain yang telah diizinkan admin. Gunakan fitur unduh resmi yang disediakan pemilik/platform bila tersedia, lalu upload file tersebut ke DSS. DSS tidak mengambil stream tersembunyi atau melewati DRM maupun pembatasan unduhan.'
                });
            }
            const downloaded = await requestAllowedMedia(sourceUrl);
            const parsed = new URL(downloaded.finalUrl);
            let ext = path.extname(parsed.pathname).toLowerCase();
            const allowedVideoExt = new Set(['.mp4','.m4v','.webm','.mov','.mkv']);
            if (!AUDIO_ALLOWED_EXTENSIONS.has(ext)) {
                if (downloaded.contentType.startsWith('audio/')) {
                    const map = { 'audio/mpeg':'.mp3','audio/wav':'.wav','audio/ogg':'.ogg','audio/mp4':'.m4a','audio/aac':'.aac','audio/flac':'.flac','audio/opus':'.opus' };
                    ext = map[downloaded.contentType] || '.mp3';
                } else if (downloaded.contentType.startsWith('video/')) {
                    ext = downloaded.contentType.includes('webm') ? '.webm' : '.mp4';
                } else {
                    return sendError(res, 400, 'Ekstensi atau format media dari URL tidak dikenali.');
                }
            }
            if (!AUDIO_ALLOWED_EXTENSIONS.has(ext)) return sendError(res, 400, 'Ekstensi media tidak didukung.');
            const baseName = path.basename(parsed.pathname, path.extname(parsed.pathname))
                .replace(/[^a-z0-9_-]/gi, '_').slice(0, 80) || 'remote_media';
            req.file = { buffer: downloaded.buffer, originalname: baseName + ext };
            return handleAudioConversion(req, res);
        } catch (error) {
            console.error('[AUDIO URL]', error.message);
            return sendError(res, 400, error.message || 'Gagal mengambil direct media URL.');
        }
    }
);

app.post('/api/audio/request-package', rateLimit({windowMs:60000,max:5}), async(req,res)=>{
    try {
        const user=await verifyAudioUser(cleanText(req.body?.username,64),cleanText(req.body?.key,255));
        const code=req.body?.package_code;
        if(!['7d','30d'].includes(code)) return sendError(res,400,'Paket tidak valid.');
        await pool.query(`INSERT INTO audio_subscription_requests(user_id,username,package_code) VALUES($1,$2,$3)`,[user.userId,user.exactUsername,code]);
        const {rows}=await pool.query(`SELECT setting_value FROM audio_settings WHERE setting_key='discord_url'`);
        return res.json({success:true,discordUrl:rows[0]?.setting_value||'https://discord.gg/XkuKuv23bH',message:'Permintaan paket dicatat. Hubungi Discord untuk pembayaran dan aktivasi.'});
    } catch(e) { return sendError(res,e.statusCode||401,e.message||'Permintaan gagal.'); }
});

app.get('/api/admin/audio', verifyAdmin, async(_req,res)=>{
    const settings=await pool.query(`SELECT setting_key,setting_value FROM audio_settings`);
    const users=await pool.query(`SELECT user_id,username,credit_balance,credit_expires_at,daily_used,total_converted FROM audio_accounts ORDER BY updated_at DESC LIMIT 100`);
    const requests=await pool.query(`SELECT * FROM audio_subscription_requests ORDER BY created_at DESC LIMIT 50`);
    return res.json({success:true,settings:Object.fromEntries(settings.rows.map(x=>[x.setting_key,x.setting_value])),users:users.rows,requests:requests.rows});
});

app.put('/api/admin/audio/settings', verifyAdmin, async(req,res)=>{
    const fields={price_7d:cleanText(req.body?.price_7d,64),price_30d:cleanText(req.body?.price_30d,64),
        credits_7d:String(Math.max(1,Math.min(100000,Number(req.body?.credits_7d)||30))),
        credits_30d:String(Math.max(1,Math.min(100000,Number(req.body?.credits_30d)||150))),
        discord_url:validHttpUrl(req.body?.discord_url)};
    if(!fields.price_7d || !fields.price_30d || !fields.discord_url) return sendError(res,400,'Harga dan URL Discord wajib valid.');
    for(const [k,v] of Object.entries(fields)) await pool.query(`INSERT INTO audio_settings(setting_key,setting_value) VALUES($1,$2) ON CONFLICT(setting_key) DO UPDATE SET setting_value=EXCLUDED.setting_value,updated_at=NOW()`,[k,v]);
    return res.json({success:true,message:'Pengaturan Audio Convert disimpan.'});
});

app.post('/api/admin/audio/grant', verifyAdmin, async(req,res)=>{
    try {
        const username=cleanText(req.body?.username,64);
        const credits=Math.max(0,Math.min(100000,Math.floor(Number(req.body?.credits)||0)));
        const days=Math.max(0,Math.min(3650,Math.floor(Number(req.body?.days)||0)));
        if(!username || (!credits && !days)) return sendError(res,400,'Username dan kredit atau masa aktif wajib diisi.');
        const user=await getRobloxUserInfo(username);
        if(!user) return sendError(res,404,'Username Roblox tidak ditemukan.');
        await pool.query(`
            INSERT INTO audio_accounts(user_id,username,credit_balance,credit_expires_at)
            VALUES($1,$2,$3,CASE WHEN $4>0 THEN NOW()+($4||' days')::interval ELSE NULL END)
            ON CONFLICT(user_id) DO UPDATE SET
                username=EXCLUDED.username,
                credit_balance=audio_accounts.credit_balance+EXCLUDED.credit_balance,
                credit_expires_at=CASE WHEN $4>0 THEN GREATEST(COALESCE(audio_accounts.credit_expires_at,NOW()),NOW())+($4||' days')::interval ELSE audio_accounts.credit_expires_at END,
                updated_at=NOW()
        `,[user.userId,user.exactUsername,credits,days]);
        return res.json({success:true,message:`Akses Audio Convert diperbarui untuk @${user.exactUsername}.`,user_id:user.userId});
    } catch(e) { return sendError(res,500,e.message||'Gagal memberikan kredit.'); }
});


// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/health', async (_req, res) => {
    try {
        await pool.query('SELECT 1');

        return res.json({
            ok: true,
            service: 'DSS STUDIO LICENSE PRO V5 CREATOR ROOT',
            database: 'connected',
            uptime_seconds: Math.floor(process.uptime())
        });
    } catch {
        return res.status(503).json({
            ok: false,
            service: 'DSS STUDIO LICENSE PRO V5 CREATOR ROOT',
            database: 'disconnected'
        });
    }
});

// ============================================================
// SERVER START
// ============================================================

let server;

if (require.main === module) {
    server = app.listen(PORT, '0.0.0.0', () => {
        console.log('============================================');
        console.log('DRAGON STELL STUDIO');
        console.log('DSS STUDIO LICENSE PRO V5 CREATOR ROOT');
        console.log('============================================');
        console.log(`Listening on port ${PORT}`);
        console.log('PostgreSQL: ENABLED');
        console.log('Creator ID Root Verification: ENABLED');
        console.log('Personal Experience Verification: ENABLED');
        console.log('Owned Community Verification: ENABLED');
        console.log('License Expiry Check: ENABLED');
        console.log('Admin Session: ENABLED');
        console.log('Auto Project Tracking: ENABLED');
        console.log('============================================');
    });
}

// ============================================================
// SHUTDOWN
// ============================================================

async function shutdown() {
    if (server) {
        await new Promise(resolve => server.close(resolve));
    }

    await pool.end().catch(() => {});

    process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

module.exports = app;
