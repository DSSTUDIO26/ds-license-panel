
// ============================================================
// DSS STUDIO LICENSE PRO V3
// DRAGON STELL STUDIO
//
// Node.js 20+
// PostgreSQL
// Strict Product + Creator Verification
//
// COMPATIBLE:
// DSS Roblox Server Loader
//
// ENVIRONMENT VARIABLES:
// DATABASE_URL
// API_SECRET
// OWNER_ROBLOX_USER_ID
// ============================================================

'use strict';

const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');

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
        if (!bucket || bucket.resetAt <= now) bucket = { count: 0, resetAt: now + windowMs };
        bucket.count += 1;
        rateBuckets.set(key, bucket);
        if (rateBuckets.size > 5000) {
            for (const [k, v] of rateBuckets) if (v.resetAt <= now) rateBuckets.delete(k);
        }
        res.setHeader('RateLimit-Limit', String(max));
        res.setHeader('RateLimit-Remaining', String(Math.max(0, max - bucket.count)));
        if (bucket.count > max) {
            res.setHeader('Retry-After', String(Math.ceil((bucket.resetAt - now) / 1000)));
            return sendError(res, 429, 'Terlalu banyak permintaan. Coba lagi beberapa saat.');
        }
        next();
    };
}

// ============================================================
// CONFIGURATION
// ============================================================

const PORT = Number(process.env.PORT || 3000);
const API_SECRET = process.env.API_SECRET || '';

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
    if (require.main === module) process.exit(1);
}

if (!DATABASE_URL) {
    console.error('FATAL: DATABASE_URL wajib diisi.');
    if (require.main === module) process.exit(1);
}

// ============================================================
// DATABASE
// ============================================================

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: process.env.PGSSLMODE === 'disable'
        ? false
        : { rejectUnauthorized: process.env.PGSSL_REJECT_UNAUTHORIZED !== 'false' },
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
                return decodeURIComponent(part.slice(index + 1).trim());
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
        secure: req.secure || req.get('x-forwarded-proto') === 'https',
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
                if (new URL(origin).host !== host) return sendError(res, 403, 'Origin request tidak diizinkan.');
            } catch {
                return sendError(res, 403, 'Origin request tidak valid.');
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
        !user
        || user.name.toLowerCase() !== username.toLowerCase()
    ) {
        return null;
    }

    let avatarUrl = null;

    try {
        const thumbnail = await robloxFetch(
            `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${user.id}&size=150x150&format=Png&isCircular=false`
        );

        avatarUrl = thumbnail?.data?.[0]?.imageUrl || null;
    } catch {}

    return {
        userId: String(user.id),
        exactUsername: user.name,
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
        experienceName: game?.data?.[0]?.name || `Experience #${id}`,
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

        ALTER TABLE project_experiences ADD COLUMN IF NOT EXISTS license_id BIGINT REFERENCES licenses(id) ON DELETE SET NULL;
        ALTER TABLE project_experiences ADD COLUMN IF NOT EXISTS creator_type VARCHAR(10);
        ALTER TABLE project_experiences ADD COLUMN IF NOT EXISTS universe_id VARCHAR(32);
        ALTER TABLE project_experiences ADD COLUMN IF NOT EXISTS experience_name VARCHAR(255);
        ALTER TABLE project_experiences ADD COLUMN IF NOT EXISTS icon_url TEXT;
        ALTER TABLE project_experiences ADD COLUMN IF NOT EXISTS visits BIGINT NOT NULL DEFAULT 0;

        -- Backfill project rows created by the previous server version.
        UPDATE project_experiences pe
        SET license_id = matched.license_id
        FROM (
            SELECT DISTINCT ON (old_pe.place_id)
                old_pe.place_id,
                l.id AS license_id
            FROM project_experiences old_pe
            INNER JOIN licenses l
                ON (
                    (old_pe.creator_type = 'User' AND l.owner_user_id = old_pe.owner_id)
                    OR (old_pe.creator_type = 'Group' AND l.group_id = old_pe.owner_id)
                    OR (old_pe.creator_type IS NULL AND (
                        l.owner_user_id = old_pe.owner_id OR l.group_id = old_pe.owner_id
                    ))
                )
            INNER JOIN license_products lp ON lp.license_id = l.id
            INNER JOIN products p ON p.id = lp.product_id
            WHERE old_pe.license_id IS NULL
                AND LOWER(p.product_name) = LOWER(old_pe.product_name)
                AND l.is_active = TRUE
                AND p.is_active = TRUE
                AND (l.expires_at IS NULL OR l.expires_at > NOW())
            ORDER BY old_pe.place_id, l.created_at DESC
        ) matched
        WHERE pe.place_id = matched.place_id
            AND pe.license_id IS NULL;
        CREATE INDEX IF NOT EXISTS idx_licenses_owner_user
            ON licenses(owner_user_id);

        CREATE INDEX IF NOT EXISTS idx_licenses_group
            ON licenses(group_id);

        CREATE INDEX IF NOT EXISTS idx_license_products_product
            ON license_products(product_id);

        CREATE INDEX IF NOT EXISTS idx_project_experiences_ping ON project_experiences(last_ping);
        CREATE INDEX IF NOT EXISTS idx_project_experiences_license ON project_experiences(license_id);
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
            OR l.group_id IS NOT NULL
        ORDER BY l.created_at DESC
    `, [user.userId]);

    const owned = [];

    for (const license of rows) {
        let group = null;

        if (license.group_id) {
            group = await getRobloxGroupInfo(license.group_id);

            if (
                !group?.ownerUserId
                || String(group.ownerUserId) !== String(user.userId)
            ) {
                continue;
            }
        } else if (
            String(license.owner_user_id) !== String(user.userId)
        ) {
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
                group?.groupName || user.exactUsername,

            owner_avatar_url:
                group?.groupIconUrl || user.avatarUrl,

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
                error: 'Lisensi ini milik komunitas Roblox. Login dengan akun pemilik komunitas tersebut.',
                status: 403
            };
        }

        return {
            user,
            license,
            group
        };
    }

    if (String(license.owner_user_id) !== String(user.userId)) {
        return {
            error: 'Lisensi ini bukan milik akun Roblox tersebut.',
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
        const verification = await findValidPortalLicense(username, key);

        if (verification.error) {
            return sendError(
                res,
                verification.status,
                verification.error
            );
        }

        const [catalog, ownedLicenses] = await Promise.all([
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

            listOwnedPortalLicenses(verification.user)
        ]);

        const displayName =
            verification.group?.groupName
            || verification.user.exactUsername;

        const ownedLicenseIds = ownedLicenses.map(item => String(item.id));
        let licensedProjects = [];
        if (ownedLicenseIds.length) {
            const projectResult = await pool.query(`
                SELECT DISTINCT pe.place_id, pe.product_name, pe.owner_id,
                    pe.creator_type, pe.universe_id, pe.experience_name,
                    pe.icon_url, pe.visits, pe.last_ping
                FROM project_experiences pe
                INNER JOIN licenses active_license ON active_license.id = pe.license_id
                WHERE pe.license_id = ANY($1::bigint[])
                    AND active_license.is_active = TRUE
                    AND (active_license.expires_at IS NULL OR active_license.expires_at > NOW())
                ORDER BY pe.last_ping DESC
            `, [ownedLicenseIds]);
            licensedProjects = projectResult.rows;
        }

        return res.json({
            success: true,

            avatar_url:
                verification.group?.groupIconUrl
                || verification.user.avatarUrl,

            owner_name: verification.user.exactUsername,
            owner_display_name: displayName,
            owner_user_id: verification.user.userId,
            owner_type: verification.group ? 'group' : 'user',

            license: {
                id: verification.license.id,
                license_key: verification.license.license_key,
                expires_at: verification.license.expires_at,
                is_active: verification.license.is_active,
                group_id: verification.license.group_id || null
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

app.post('/api/client-login', rateLimit({ windowMs: 60_000, max: 12 }), clientLoginHandler);
app.post('/api/client-refresh', rateLimit({ windowMs: 60_000, max: 20 }), clientLoginHandler);

// ============================================================
// PORTAL LOGIN
// ============================================================

app.post('/api/portal-login', rateLimit({ windowMs: 60_000, max: 8 }), async (req, res) => {
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
});

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
        secure: req.secure || req.get('x-forwarded-proto') === 'https',
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

app.post('/api/game-details', rateLimit({ windowMs: 60_000, max: 40 }), async (req, res) => {
    const placeId = validNumericId(req.body?.place_id, 20);

    if (!placeId) {
        return sendError(res, 400, 'place_id tidak valid.');
    }

    try {
        let name = `Experience #${placeId}`;
        let icon = DEFAULT_IMAGE;
        let creatorName = 'Unknown Creator';
        let visits = 0;

        const universe = await robloxFetch(
            `https://apis.roblox.com/universes/v1/places/${encodeURIComponent(placeId)}/universe`
        );

        const universeId = universe?.universeId;

        if (universeId) {
            const game = await robloxFetch(
                `https://games.roblox.com/v1/games?universeIds=${encodeURIComponent(universeId)}`
            );

            const data = game?.data?.[0];

            if (data?.name) name = data.name;
            if (data?.creator?.name) creatorName = data.creator.name;
            if (data?.visits !== undefined) visits = data.visits;
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
            name,
            icon,
            creatorName,
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
            visits: 0
        });
    }
});

// ============================================================
// GAME VERIFY V3
//
// STRICT MATCH:
// - Product Name
// - Creator Type
// - Creator ID
// - Active License
// - Active Product
// - License Expiry
//
// REQUEST:
// {
//   place_id: "123",
//   product_name: "DSS-SYSTEM",
//   creator_id: "123456",
//   creator_type: "User"
// }
//
// creator_type:
// User / Group
// ============================================================

app.post('/api/game-verify', async (req, res) => {
    const placeId = validNumericId(req.body?.place_id, 20);
    const requestedProductName = cleanText(req.body?.product_name, 120);

    if (!placeId) return sendError(res, 400, 'Place ID tidak valid.', { authorized: false });

    try {
        // Creator is always resolved from Roblox, never trusted from client payload.
        const creator = await getPlaceCreator(placeId);
        const creatorId = validNumericId(creator.creatorId, 32);
        const creatorType = creator.creatorType;

        if (!creatorId || !['User', 'Group'].includes(creatorType)) {
            return res.json({ success: true, authorized: false, place_id: placeId,
                message: 'Creator experience tidak dapat diverifikasi.' });
        }

        const { rows } = await pool.query(`
            SELECT p.product_name, l.id AS license_id, l.owner_user_id, l.group_id
            FROM licenses l
            INNER JOIN license_products lp ON lp.license_id = l.id
            INNER JOIN products p ON p.id = lp.product_id
            WHERE l.is_active = TRUE
                AND p.is_active = TRUE
                AND ($1::text = '' OR LOWER(p.product_name) = LOWER($1))
                AND (l.expires_at IS NULL OR l.expires_at > NOW())
                AND (
                    ($2 = 'User' AND l.owner_user_id = $3)
                    OR ($2 = 'Group' AND l.group_id = $3)
                )
            ORDER BY l.created_at DESC
            LIMIT 1
        `, [requestedProductName, creatorType, creatorId]);

        if (!rows.length) {
            return res.json({ success: true, authorized: false, place_id: placeId,
                creator_id: creatorId, creator_type: creatorType,
                product_name: requestedProductName || null,
                message: 'Tidak ditemukan lisensi aktif yang cocok dengan pemilik experience.' });
        }

        const authorizedProduct = rows[0];
        let iconUrl = null;
        try {
            const thumbnail = await robloxFetch(
                `https://thumbnails.roblox.com/v1/places/gameicons?placeIds=${encodeURIComponent(placeId)}&size=512x512&format=Png&isCircular=false`
            );
            iconUrl = thumbnail?.data?.[0]?.imageUrl || null;
        } catch {}

        await pool.query(`
            INSERT INTO project_experiences(
                place_id, product_name, owner_id, license_id, creator_type,
                universe_id, experience_name, icon_url, visits, last_ping
            )
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
            ON CONFLICT(place_id) DO UPDATE SET
                product_name = EXCLUDED.product_name,
                owner_id = EXCLUDED.owner_id,
                license_id = EXCLUDED.license_id,
                creator_type = EXCLUDED.creator_type,
                universe_id = EXCLUDED.universe_id,
                experience_name = EXCLUDED.experience_name,
                icon_url = COALESCE(EXCLUDED.icon_url, project_experiences.icon_url),
                visits = EXCLUDED.visits,
                last_ping = NOW()
        `, [placeId, authorizedProduct.product_name, creatorId, authorizedProduct.license_id,
            creatorType, creator.universeId, creator.experienceName, iconUrl, creator.visits]);

        return res.json({
            success: true, authorized: true,
            product_name: authorizedProduct.product_name,
            place_id: placeId,
            universe_id: creator.universeId,
            experience_name: creator.experienceName,
            creator_id: creatorId,
            creator_type: creatorType,
            message: 'Experience terverifikasi dan tersinkron otomatis.'
        });
    } catch (error) {
        console.error('[GAME VERIFY]', error.message);
        return res.status(error.statusCode || 502).json({
            success: false, authorized: false,
            message: 'Verifikasi Roblox gagal. Coba lagi.'
        });
    }
});

// ============================================================
// AUTO PROJECTS
// ============================================================

app.get('/api/auto-projects', verifyAdmin, async (_req, res) => {
    try {
        const { rows } = await pool.query(`
            SELECT pe.place_id, pe.product_name, pe.owner_id, pe.license_id,
                pe.creator_type, pe.universe_id, pe.experience_name,
                pe.icon_url, pe.visits, pe.last_ping,
                l.owner_name, l.owner_user_id, l.group_id,
                l.is_active AS license_active, l.expires_at
            FROM project_experiences pe
            INNER JOIN licenses l ON l.id = pe.license_id
            WHERE l.is_active = TRUE
                AND (l.expires_at IS NULL OR l.expires_at > NOW())
            ORDER BY pe.last_ping DESC
        `);
        return res.json({ success: true, projects: rows.map(row => row.place_id), data: rows });
    } catch (error) {
        console.error('[AUTO PROJECTS]', error.message);
        return sendError(res, 500, 'Gagal membaca project experience.');
    }
});

app.delete(
    '/api/auto-projects/:pid',
    verifyAdmin,
    async (req, res) => {
        const placeId = validNumericId(req.params.pid, 20);

        if (!placeId) {
            return sendError(res, 400, 'Place ID tidak valid.');
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
        return sendError(res, 400, 'Nama produk wajib diisi.');
    }

    if (image === undefined || download === undefined) {
        return sendError(res, 400, 'URL tidak valid.');
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
        return sendError(res, 400, 'Kode produk tidak valid.');
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
        return sendError(res, 400, 'URL tidak valid.');
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
                            group.groupName
                            || `Grup Roblox ${license.group_id}`,
                        owner_avatar_url: group.groupIconUrl,
                        group_name: group.groupName,
                        group_icon_url: group.groupIconUrl
                    };
                }

                let avatar = null;

                if (license.owner_user_id) {
                    try {
                        const thumbnail = await robloxFetch(
                            `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${encodeURIComponent(license.owner_user_id)}&size=150x150&format=Png&isCircular=false`
                        );

                        avatar =
                            thumbnail?.data?.[0]?.imageUrl || null;
                    } catch {}
                }

                return {
                    ...license,
                    owner_type: 'user',
                    owner_display_name: license.owner_name,
                    owner_avatar_url: avatar
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
        return sendError(res, 400, 'License key wajib diisi.');
    }

    if (
        ids.length !== 1
        || !/^\d+$/.test(String(ids[0]))
    ) {
        return sendError(
            res,
            400,
            'Satu lisensi hanya boleh untuk tepat satu produk.'
        );
    }

    if (
        expires === undefined
        || image === undefined
        || download === undefined
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

        if (!group?.groupName) {
            return sendError(
                res,
                400,
                'Group ID tidak ditemukan atau Roblox API tidak tersedia.'
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

        const inserted = await connection.query(`
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

            VALUES($1,$2,$3,$4,$5,$6,$7,$8)

            RETURNING id
        `, [
            key,
            groupId ? group.groupName : user.exactUsername,
            groupId ? null : user.userId,
            groupId,
            product.product_name,
            image,
            download,
            expires
        ]);

        await connection.query(
            'INSERT INTO license_products(license_id,product_id) VALUES($1,$2)',
            [inserted.rows[0].id, product.id]
        );

        await connection.query('COMMIT');

        return res.status(201).json({
            success: true,
            message: 'Lisensi berhasil dibuat.',
            id: inserted.rows[0].id,
            product_count: 1,
            product_name: product.product_name
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

app.post('/api/file-ticket', rateLimit({ windowMs: 60_000, max: 15 }), async (req, res) => {
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
});

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/health', async (_req, res) => {
    try {
        await pool.query('SELECT 1');

        return res.json({
            ok: true,
            service: 'DSS STUDIO LICENSE PRO V3',
            database: 'connected',
            uptime_seconds: Math.floor(process.uptime())
        });
    } catch {
        return res.status(503).json({
            ok: false,
            service: 'DSS STUDIO LICENSE PRO V3',
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
        console.log('DSS STUDIO LICENSE PRO V3');
        console.log('============================================');
        console.log(`Listening on port ${PORT}`);
        console.log('PostgreSQL: ENABLED');
        console.log('Strict Product Verification: ENABLED');
        console.log('Creator ID Verification: ENABLED');
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
