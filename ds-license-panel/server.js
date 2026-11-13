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

async function getRobloxUserInfo(username) {
    const result = await robloxFetch(
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
    `);

    console.log('[DSS] Database schema ready.');
}

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
        JOIN products p ON p.id = lp.product_id
        WHERE lp.license_id = $1
        ORDER BY p.product_name
    `, [licenseId]);

    return rows;
}

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
            owner_display_name: user.displayName || user.exactUsername,
            owner_username: user.exactUsername,
            owner_avatar_url: user.avatarUrl,
            creator_user_id: license.creator_user_id || license.owner_user_id || group?.ownerUserId || null,
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

        return { user, license, group };
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

    return { user, license, group: null };
}

async function clientLoginHandler(req, res) {
    const username = cleanText(req.body?.owner_name, 64);
    const key = cleanText(req.body?.license_key, 255);

    if (!username || !key) {
        return sendError(res, 400, 'Username Roblox dan License Key wajib diisi.');
    }

    try {
        const verification = await findValidPortalLicense(username, key);

        if (verification.error) {
            return sendError(res, verification.status, verification.error);
        }

        const [catalog, ownedLicenses, ownedCommunities] = await Promise.all([
            pool.query(`
                SELECT id, product_code, product_name, description, price, image_url, download_url, is_active
                FROM products
                WHERE is_active = TRUE
                ORDER BY created_at DESC, product_name ASC
            `),
            listOwnedPortalLicenses(verification.user),
            getOwnedRobloxCommunities(verification.user.userId)
        ]);

        const displayName = verification.user.displayName || verification.user.exactUsername;

        const projectResult = await pool.query(`
            SELECT DISTINCT place_id, product_name, owner_id, creator_type, universe_id, experience_name, icon_url, visits, last_ping
            FROM project_experiences
            ORDER BY last_ping DESC
        `);

        return res.json({
            success: true,
            avatar_url: verification.user.avatarUrl,
            owner_name: verification.user.exactUsername,
            owner_username: verification.user.exactUsername,
            owner_display_name: displayName,
            owner_user_id: verification.user.userId,
            owner_type: 'user',
            license_owner_type: verification.group ? 'group' : 'user',
            owned_communities: ownedCommunities,
            license: {
                id: verification.license.id,
                license_key: verification.license.license_key,
                expires_at: verification.license.expires_at,
                is_active: verification.license.is_active,
                group_id: verification.license.group_id || null,
                creator_user_id: verification.license.creator_user_id || verification.license.owner_user_id || verification.group?.ownerUserId || null
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
            projects: projectResult.rows
        });
    } catch (error) {
        console.error('[CLIENT LOGIN]', error.message);
        return sendError(res, 502, 'Gagal menghubungi Roblox atau database. Coba lagi.');
    }
}

app.post('/api/client-login', rateLimit({ windowMs: 60_000, max: 12 }), clientLoginHandler);
app.post('/api/client-refresh', rateLimit({ windowMs: 60_000, max: 20 }), clientLoginHandler);

app.post('/api/portal-login', rateLimit({ windowMs: 60_000, max: 8 }), async (req, res) => {
    const username = cleanText(req.body?.owner_name, 64);
    const credential = cleanText(req.body?.credential, 255);

    if (!username || !credential) {
        return sendError(res, 400, 'Username Roblox dan kredensial wajib diisi.');
    }

    if (safeEqual(credential, API_SECRET)) {
        try {
            const user = await getRobloxUserInfo(username);
            if (!user || user.userId !== OWNER_ROBLOX_USER_ID) {
                return sendError(res, 401, 'Username Roblox atau kredensial tidak valid.');
            }
            setAdminCookie(req, res);
            return res.json({ success: true, access: 'admin', owner_name: user.exactUsername });
        } catch (error) {
            return sendError(res, 502, 'Verifikasi Roblox gagal. Coba lagi.');
        }
    }

    req.body = { owner_name: username, license_key: credential };
    return clientLoginHandler(req, res);
});

app.get('/api/admin-session', (req, res) => {
    res.json({ success: true, authenticated: hasAdmin(req) });
});

app.post('/api/admin-logout', (req, res) => {
    res.clearCookie(COOKIE, {
        httpOnly: true,
        secure: req.secure || req.get('x-forwarded-proto') === 'https',
        sameSite: 'strict',
        path: '/'
    });
    res.json({ success: true, message: 'Sesi Admin ditutup.' });
});

app.post('/api/game-details', rateLimit({ windowMs: 60_000, max: 40 }), async (req, res) => {
    const placeId = validNumericId(req.body?.place_id, 20);
    if (!placeId) return sendError(res, 400, 'place_id tidak valid.');

    try {
        let name = `Experience #${placeId}`;
        let icon = DEFAULT_IMAGE;
        let creatorName = 'Unknown Creator';
        let visits = 0;
        let universeId = null;

        const universe = await robloxFetch(`https://apis.roblox.com/universes/v1/places/${encodeURIComponent(placeId)}/universe`);
        universeId = universe?.universeId ? String(universe.universeId) : null;

        if (universeId) {
            const game = await robloxFetch(`https://games.roblox.com/v1/games?universeIds=${encodeURIComponent(universeId)}`);
            const data = game?.data?.[0];
            if (data?.name) name = data.name;
            if (data?.creator?.name) creatorName = data.creator.name;
            if (data?.visits !== undefined) visits = data.visits;
        }

        try {
            const thumbnail = await robloxFetch(`https://thumbnails.roblox.com/v1/places/gameicons?placeIds=${encodeURIComponent(placeId)}&size=512x512&format=Png&isCircular=false`);
            const imageUrl = thumbnail?.data?.[0]?.imageUrl;
            if (imageUrl) icon = imageUrl;
        } catch {}

        return res.json({ success: true, place_id: placeId, universe_id: universeId, name, icon, creatorName, visits });
    } catch {
        return res.json({ success: true, place_id: placeId, name: `Experience #${placeId}`, icon: DEFAULT_IMAGE, creatorName: 'Unknown Creator', visits: 0 });
    }
});

app.get('/api/products', verifyAdmin, async (_req, res) => {
    try {
        const { rows } = await pool.query(`SELECT * FROM products ORDER BY product_name`);
        return res.json({ success: true, products: rows });
    } catch {
        return sendError(res, 500, 'Gagal membaca katalog.');
    }
});

app.post('/api/products', verifyAdmin, async (req, res) => {
    const name = cleanText(req.body?.product_name, 120);
    const description = cleanText(req.body?.description, 1000);
    const price = cleanText(req.body?.price, 64);
    const image = validHttpUrl(req.body?.image_url);
    const download = validHttpUrl(req.body?.download_url);

    if (!name) return sendError(res, 400, 'Nama produk wajib diisi.');
    const code = cleanText(req.body?.product_code, 80).toUpperCase() || name.toUpperCase().replace(/[^A-Z0-9]+/g, '_').slice(0, 70);

    try {
        const { rows } = await pool.query(`
            INSERT INTO products(product_code, product_name, description, price, image_url, download_url)
            VALUES($1, $2, $3, $4, $5, $6) RETURNING *
        `, [code, name, description || null, price || null, image, download]);

        return res.status(201).json({ success: true, product: rows[0] });
    } catch (error) {
        if (error.code === '23505') return sendError(res, 409, 'Kode atau nama produk sudah digunakan.');
        return sendError(res, 500, 'Gagal membuat produk.');
    }
});

app.get('/api/licenses', verifyAdmin, async (_req, res) => {
    try {
        const { rows } = await pool.query(`
            SELECT l.*, COALESCE(json_agg(json_build_object('id', p.id, 'product_code', p.product_code, 'product_name', p.product_name, 'is_active', p.is_active)) FILTER (WHERE p.id IS NOT NULL), '[]'::json) AS products
            FROM licenses l
            LEFT JOIN license_products lp ON lp.license_id = l.id
            LEFT JOIN products p ON p.id = lp.product_id
            GROUP BY l.id ORDER BY l.created_at DESC
        `);
        return res.json({ success: true, licenses: rows });
    } catch {
        return sendError(res, 500, 'Gagal membaca lisensi.');
    }
});

app.get('/api/health', async (_req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'ONLINE', version: '5.0.0-CREATOR-ROOT', timestamp: new Date().toISOString() });
    } catch {
        res.status(503).json({ status: 'DB_ERROR' });
    }
});

app.use((err, _req, res, _next) => {
    console.error('[SERVER ERROR]', err);
    return sendError(res, 500, 'Terjadi kesalahan server.');
});

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`[DSS STUDIO] Creator Root Server active on port ${PORT}`);
    });
}

module.exports = app;
