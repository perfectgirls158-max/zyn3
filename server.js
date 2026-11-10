require('dotenv').config();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { createServer } = require('http');
const { Server } = require('socket.io');
const { MongoClient } = require('mongodb');

const ACTIVATOR_SECRET_KEY = process.env.ACTIVATOR_SECRET_KEY || 'ZYN_ACTIVATOR_SECRET_KEY_2026';
const CLOUD_RESPONSE_SECRET = 'ZYN_CLOUD_CHALLENGE_SIGN_2026_' + ACTIVATOR_SECRET_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'geo123';
const ADMIN_TOKEN = crypto.createHmac('sha256', CLOUD_RESPONSE_SECRET).update('ADMIN_SESSION_' + ADMIN_PASSWORD).digest('hex');

function computeCloudResponseSignature({ deviceId, code, active, status, expiresAt, serverTime, nonce }) {
    const payload = [
        String(deviceId || ''),
        String(code || ''),
        active === false ? '0' : '1',
        String(status || ''),
        String(expiresAt || '0'),
        String(serverTime || '0'),
        String(nonce || '')
    ].join('|');
    return crypto.createHmac('sha256', CLOUD_RESPONSE_SECRET).update(payload).digest('hex');
}

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
    cors: { origin: '*' }
});

const PORT = process.env.PORT || process.env.ACTIVATOR_PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'licenses.json');

// Ensure data folder exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ---------------------------------------------------------------------------
// Cloud MongoDB Atlas Integration (Permanent 24/7 Storage for Render)
// ---------------------------------------------------------------------------
const MONGODB_URI = process.env.MONGODB_URI || process.env.MONGO_URI || null;
let mongoClient = null;
let mongoCollection = null;
let isMongoConnected = false;
let inMemoryDb = null;

function loadLocalDatabaseFile() {
    try {
        if (fs.existsSync(DB_FILE)) {
            const raw = fs.readFileSync(DB_FILE, 'utf8');
            const parsed = JSON.parse(raw);
            return {
                licenses: Array.isArray(parsed.licenses) ? parsed.licenses : [],
                boundDevices: (parsed.boundDevices && typeof parsed.boundDevices === 'object') ? parsed.boundDevices : {},
                clients: Array.isArray(parsed.clients) ? parsed.clients : []
            };
        }
    } catch (e) {}
    return { licenses: [], boundDevices: {}, clients: [] };
}

function loadDatabase() {
    if (!inMemoryDb) {
        inMemoryDb = loadLocalDatabaseFile();
    }
    if (!Array.isArray(inMemoryDb.licenses)) inMemoryDb.licenses = [];
    if (!inMemoryDb.boundDevices || typeof inMemoryDb.boundDevices !== 'object') inMemoryDb.boundDevices = {};
    if (!Array.isArray(inMemoryDb.clients)) inMemoryDb.clients = [];
    return inMemoryDb;
}

function saveDatabase(db) {
    inMemoryDb = db;
    // Local JSON write
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
    } catch (e) {}

    // Cloud MongoDB write
    if (isMongoConnected && mongoCollection) {
        mongoCollection.updateOne(
            { _id: 'global_state' },
            { $set: { licenses: db.licenses, boundDevices: db.boundDevices, clients: db.clients, updatedAt: Date.now() } },
            { upsert: true }
        ).catch(err => {
            console.error('[Database] Error saving to MongoDB:', err.message);
        });
    }
}

let mongoInitPromise = null;

async function initMongoDB() {
    if (!MONGODB_URI) {
        console.info('[Database] No MONGODB_URI set. Running in local JSON storage mode.');
        return;
    }
    try {
        console.info('[Database] Connecting to MongoDB Atlas...');
        mongoClient = new MongoClient(MONGODB_URI, {
            serverSelectionTimeoutMS: 8000
        });
        await mongoClient.connect();
        const db = mongoClient.db('zyn_activator');
        mongoCollection = db.collection('cloud_storage');
        isMongoConnected = true;
        console.info('[Database] ✓ Connected to MongoDB Atlas permanently!');

        // Load cloud state
        const doc = await mongoCollection.findOne({ _id: 'global_state' });
        if (doc && Array.isArray(doc.licenses)) {
            inMemoryDb = {
                licenses: doc.licenses,
                boundDevices: doc.boundDevices || {},
                clients: Array.isArray(doc.clients) ? doc.clients : []
            };
            console.info(`[Database] ✓ Restored ${doc.licenses.length} licenses & ${inMemoryDb.clients.length} clients from MongoDB Atlas!`);
            broadcastAdminUpdate();
        } else {
            // Seed local into cloud
            const local = loadLocalDatabaseFile();
            if (local.licenses.length > 0 || local.clients.length > 0) {
                await mongoCollection.updateOne(
                    { _id: 'global_state' },
                    { $set: { licenses: local.licenses, boundDevices: local.boundDevices, clients: local.clients, updatedAt: Date.now() } },
                    { upsert: true }
                );
                inMemoryDb = local;
                console.info(`[Database] ✓ Seeded ${local.licenses.length} existing licenses & ${local.clients.length} clients into MongoDB Atlas!`);
            }
        }
    } catch (err) {
        console.error('[Database] MongoDB connection failed:', err.message);
        isMongoConnected = false;
    }
}
mongoInitPromise = initMongoDB();

async function ensureDbReady() {
    if (mongoInitPromise) {
        try { await mongoInitPromise; } catch (e) {}
    }
}

// Generate random unique 8-digit numeric code
function generateUnique8DigitCode(db) {
    let code = '';
    let exists = true;
    while (exists) {
        code = String(Math.floor(10000000 + Math.random() * 90000000));
        exists = db.licenses.some(l => l.code === code);
    }
    return code;
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

app.get(['/', '/admin'], (req, res) => {
    const pubFile = path.join(__dirname, 'public', 'index.html');
    if (fs.existsSync(pubFile)) return res.sendFile(pubFile);
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ---------------------------------------------------------------------------
// Multi-Tier Client & Super Admin Authentication Helpers
// ---------------------------------------------------------------------------
function generateClientToken(client) {
    if (!client || !client.id) return '';
    const raw = `CLIENT_${client.username}_${client.id}_${ACTIVATOR_SECRET_KEY}`;
    return crypto.createHmac('sha256', CLOUD_RESPONSE_SECRET).update(raw).digest('hex');
}

function getClientByToken(token) {
    if (!token) return null;
    const db = loadDatabase();
    return db.clients.find(c => generateClientToken(c) === token && c.status !== 'disabled') || null;
}

function getClientUsedQuota(db, username) {
    if (!username) return 0;
    return db.licenses.filter(l => l.createdBy === username).length;
}

function sanitizeClient(c, db) {
    const used = getClientUsedQuota(db, c.username);
    const limit = Number(c.maxLimit) || 0;
    return {
        id: c.id,
        username: c.username,
        password: c.password || '', // Visible to Super Admin in client management
        name: c.name || c.username,
        maxLimit: limit,
        usedCount: used,
        usedQuota: used,
        remainingSlots: Math.max(0, limit - used),
        status: c.status || 'active',
        createdAt: c.createdAt || Date.now(),
        lastSeenAt: c.lastSeenAt || null,
        isOnline: !!c.isOnline
    };
}

const onlineSockets = new Map(); // socket.id -> { username, name, role }

function broadcastAdminUpdate() {
    const db = loadDatabase();
    // Super admins see ALL licenses
    io.to('authorized_superadmins').emit('licenses_updated', db.licenses);
    io.to('authorized_admins').emit('licenses_updated', db.licenses);

    // Filter and broadcast to each active client their own licenses & quota
    db.clients.forEach(client => {
        const clientLicenses = db.licenses.filter(l => l.createdBy === client.username);
        const used = clientLicenses.length;
        const limit = Number(client.maxLimit) || 0;
        io.to(`client_${client.username}`).emit('client_licenses_updated', {
            licenses: clientLicenses,
            quota: {
                maxLimit: limit,
                usedCount: used,
                remainingSlots: Math.max(0, limit - used)
            }
        });
    });
}

function broadcastClientsToSuperAdmin() {
    const db = loadDatabase();
    const sanitized = db.clients.map(c => sanitizeClient(c, db));
    io.to('authorized_superadmins').emit('clients_updated', sanitized);
}

// Socket.io connection handling with real-time presence tracking
io.on('connection', (socket) => {
    const authenticateSocket = (clientToken) => {
        if (!clientToken) return;
        const db = loadDatabase();

        if (clientToken === ADMIN_TOKEN) {
            socket.join('authorized_superadmins');
            socket.join('authorized_admins');
            socket.emit('auth_success', { role: 'superadmin', name: 'Master Super Admin' });
            socket.emit('licenses_updated', db.licenses);
            socket.emit('clients_updated', db.clients.map(c => sanitizeClient(c, db)));
            return;
        }

        const client = db.clients.find(c => generateClientToken(c) === clientToken);
        if (client && client.status !== 'disabled') {
            socket.join(`client_${client.username}`);
            onlineSockets.set(socket.id, { username: client.username, name: client.name, role: 'client' });

            // Mark client as online
            client.isOnline = true;
            client.lastSeenAt = Date.now();
            saveDatabase(db);
            broadcastClientsToSuperAdmin();

            const clientLicenses = db.licenses.filter(l => l.createdBy === client.username);
            const used = clientLicenses.length;
            const limit = Number(client.maxLimit) || 0;
            socket.emit('auth_success', {
                role: 'client',
                username: client.username,
                name: client.name,
                maxLimit: limit,
                usedCount: used,
                remainingSlots: Math.max(0, limit - used)
            });
            socket.emit('client_licenses_updated', {
                licenses: clientLicenses,
                quota: {
                    maxLimit: limit,
                    usedCount: used,
                    remainingSlots: Math.max(0, limit - used)
                }
            });
        }
    };

    const initialToken = socket.handshake?.auth?.token || socket.handshake?.query?.token;
    if (initialToken) authenticateSocket(initialToken);

    socket.on('admin_auth', (token) => authenticateSocket(token));
    socket.on('client_auth', (token) => authenticateSocket(token));

    socket.on('disconnect', () => {
        if (onlineSockets.has(socket.id)) {
            const { username } = onlineSockets.get(socket.id);
            onlineSockets.delete(socket.id);

            // Check if any other socket is still open for this client
            const stillOnline = Array.from(onlineSockets.values()).some(s => s.username === username);
            const db = loadDatabase();
            const client = db.clients.find(c => c.username === username);
            if (client) {
                client.isOnline = stillOnline;
                client.lastSeenAt = Date.now();
                saveDatabase(db);
                broadcastClientsToSuperAdmin();
            }
        }
    });
});

// Unified Login Endpoint (Supports both Super Admin and Reseller Clients)
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body || {};
    const u = String(username || '').trim().toLowerCase();
    const p = String(password || '').trim();

    // 1. Check Super Admin
    if ((u === 'admin' || !u) && p === ADMIN_PASSWORD) {
        return res.json({
            ok: true,
            role: 'superadmin',
            token: ADMIN_TOKEN,
            name: 'Master Super Admin'
        });
    }

    // 2. Check Reseller / Client account
    const db = loadDatabase();
    const client = db.clients.find(c => c.username.toLowerCase() === u && c.password === p);

    if (client) {
        if (client.status === 'disabled') {
            return res.status(403).json({ ok: false, error: 'Ang account na ito ay naka-DISABLE ng Super Admin. Makipag-ugnayan sa provider.' });
        }
        client.lastSeenAt = Date.now();
        client.isOnline = true;
        saveDatabase(db);
        broadcastClientsToSuperAdmin();

        const token = generateClientToken(client);
        return res.json({
            ok: true,
            role: 'client',
            token,
            client: sanitizeClient(client, db)
        });
    }

    return res.status(401).json({ ok: false, error: 'Maling Username o Password!' });
});

// Backward-compatible Admin Login Endpoint
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body || {};
    const u = String(username || '').trim().toLowerCase();
    const p = String(password || '').trim();

    if (p === ADMIN_PASSWORD && (!u || u === 'admin')) {
        return res.json({ ok: true, role: 'superadmin', token: ADMIN_TOKEN, name: 'Master Super Admin' });
    }
    // Also allow client if they logged in with client password
    const db = loadDatabase();
    const client = db.clients.find(c => (u ? c.username.toLowerCase() === u : true) && c.password === p);
    if (client) {
        if (client.status === 'disabled') {
            return res.status(403).json({ ok: false, error: 'Ang account na ito ay naka-DISABLE ng Super Admin.' });
        }
        const token = generateClientToken(client);
        return res.json({ ok: true, role: 'client', token, client: sanitizeClient(client, db) });
    }
    return res.status(401).json({ ok: false, error: 'Maling Admin Password!' });
});

// Middleware to protect /api/admin/* endpoints from unauthorized access
function requireAdminAuth(req, res, next) {
    if (req.path === '/login') return next();
    const token = req.headers['x-admin-token'] || req.query.token || '';
    if (!token) {
        return res.status(401).json({ ok: false, unauthorized: true, error: 'Unauthorized: Login required.' });
    }

    if (token === ADMIN_TOKEN) {
        req.authRole = 'superadmin';
        req.authUser = 'admin';
        return next();
    }

    // Check if valid client token
    const client = getClientByToken(token);
    if (client) {
        req.authRole = 'client';
        req.authClient = client;
        req.authUser = client.username;
        return next();
    }

    return res.status(401).json({ ok: false, unauthorized: true, error: 'Unauthorized: Invalid token.' });
}

function requireSuperAdmin(req, res, next) {
    const token = req.headers['x-admin-token'] || req.query.token || '';
    if (token !== ADMIN_TOKEN) {
        return res.status(403).json({ ok: false, error: 'Access denied: Super Admin master access only.' });
    }
    req.authRole = 'superadmin';
    req.authUser = 'admin';
    next();
}

app.use('/api/admin', requireAdminAuth);

// ---------------------------------------------------------------------------
// REST API FOR DESKTOP APPLICATION
// ---------------------------------------------------------------------------

/**
 * 1. ACTIVATE LICENSE (Called by Desktop App when entering 8-digit code)
 * POST /api/license/activate
 * Body: { deviceId: string, code: string }
 */
app.post('/api/license/activate', async (req, res) => {
    await ensureDbReady();
    const { deviceId, code, nonce } = req.body || {};
    const cleanCode = String(code || '').replace(/\D/g, '').trim();
    const cleanDevice = String(deviceId || '').trim();
    const now = Date.now();

    if (!cleanDevice || cleanCode.length !== 8) {
        return res.status(400).json({ ok: false, serverTime: now, error: 'Valid Device ID and 8-digit code are required.' });
    }

    const db = loadDatabase();
    const lic = db.licenses.find(l => l.code === cleanCode);

    if (!lic) {
        return res.status(404).json({ ok: false, serverTime: now, error: 'Hindi nahanap ang activation code na ito. Paki-check sa administrator.' });
    }

    if (lic.status === 'disabled') {
        return res.status(403).json({ ok: false, serverTime: now, error: 'Ang license na ito ay kasalukuyang naka-DISABLE ng administrator.' });
    }

    // Ensure durationDays always has a concrete expiresAt timestamp
    if (!lic.expiresAt && Number(lic.durationDays) > 0) {
        const baseTs = Number(lic.activatedAt) || Number(lic.createdAt) || now;
        lic.expiresAt = baseTs + Number(lic.durationDays) * 24 * 60 * 60 * 1000;
    }

    // Strict expiration check (both status === 'expired' and timestamp check)
    if (lic.status === 'expired' || (lic.expiresAt && now > Number(lic.expiresAt))) {
        lic.status = 'expired';
        lic.isLive = false;
        lic.currentTiktokUser = null;
        saveDatabase(db);
        broadcastAdminUpdate();
        return res.status(403).json({
            ok: false,
            serverTime: now,
            error: 'Nag-expire na ang activation code na ito. Hindi na ito pwedeng gamitin ulit. Makipag-ugnayan sa administrator para mag-renew.'
        });
    }

    // Check if license is already bound to another PC
    if (lic.boundDeviceId && lic.boundDeviceId !== cleanDevice) {
        return res.status(409).json({
            ok: false,
            serverTime: now,
            error: `Ang code na ito ay naka-bind na sa ibang PC (${lic.boundDeviceId}). 1 PC per license lang po.`
        });
    }

    // Check if this PC is locked to a DIFFERENT license
    const existingBinding = db.boundDevices[cleanDevice];
    if (existingBinding && existingBinding.licenseCode !== cleanCode && existingBinding.deviceLocked) {
        return res.status(423).json({
            ok: false,
            serverTime: now,
            error: `Ang PC na ito ay naka-lock sa dating lisensya (#${existingBinding.licenseCode}). Bawal gumamit ng ibang code nang walang pahintulot. Paki-renew o i-pa-unlock sa administrator.`
        });
    }

    // ONE-TIME ACTIVATION LOCK: Prevent reusing an existing activated code after uninstall/reinstall unless Admin clicks "Unlock PC" or "Renew"
    if (lic.deviceLocked && lic.boundDeviceId === cleanDevice && lic.activatedAt) {
        return res.status(403).json({
            ok: false,
            serverTime: now,
            error: 'Ang activation code na ito ay nagamit at naka-lock na sa unang install. Para mag-reinstall, ipapindot muna ang "🔓 Unlock PC" sa administrator.'
        });
    }

    // Bind device & activate (First-time or Admin-unlocked activation)
    lic.boundDeviceId = cleanDevice;
    lic.deviceLocked = true;
    lic.activatedAt = lic.activatedAt || now;
    lic.activationCount = (Number(lic.activationCount) || 0) + 1;
    lic.lastSeenAt = now;
    lic.status = 'active';

    // Save device lock record
    db.boundDevices[cleanDevice] = {
        licenseCode: cleanCode,
        deviceLocked: true,
        boundAt: now
    };

    saveDatabase(db);
    broadcastAdminUpdate();

    const serverSig = computeCloudResponseSignature({
        deviceId: cleanDevice,
        code: lic.code,
        active: true,
        status: lic.status,
        expiresAt: lic.expiresAt,
        serverTime: now,
        nonce
    });

    return res.json({
        ok: true,
        serverTime: now,
        serverSig,
        message: 'Matagumpay na na-activate ang iyong device sa cloud server!',
        license: {
            code: lic.code,
            clientName: lic.clientName,
            expiresAt: lic.expiresAt,
            status: lic.status
        }
    });
});

/**
 * 2. REAL-TIME HEARTBEAT & LIVE STREAM TRACKING
 * POST /api/license/heartbeat
 * Body: { deviceId, code, nonce, currentTiktokUser, tiktokHistory, appVersion, osPlatform, hostname }
 */
app.post('/api/license/heartbeat', async (req, res) => {
    await ensureDbReady();
    const { deviceId, code, nonce, currentTiktokUser, tiktokHistory, appVersion, osPlatform, hostname } = req.body || {};
    const cleanCode = String(code || '').replace(/\D/g, '').trim();
    const cleanDevice = String(deviceId || '').trim();
    const now = Date.now();

    const sendSignedHeartbeatResponse = (payload) => {
        const sig = computeCloudResponseSignature({
            deviceId: cleanDevice,
            code: cleanCode,
            active: payload.active,
            status: payload.status,
            expiresAt: payload.expiresAt,
            serverTime: now,
            nonce
        });
        return res.json(Object.assign({}, payload, { serverTime: now, serverSig: sig }));
    };

    if (!cleanDevice || !cleanCode) {
        return res.status(400).json({ ok: false, serverTime: now, error: 'Missing deviceId or code' });
    }

    const db = loadDatabase();
    const lic = db.licenses.find(l => l.code === cleanCode);

    if (!lic) {
        return sendSignedHeartbeatResponse({ ok: false, active: false, status: 'not_found', error: 'License does not exist in cloud' });
    }

    // Verify PC matches bound device
    if (lic.boundDeviceId && lic.boundDeviceId !== cleanDevice) {
        return sendSignedHeartbeatResponse({ ok: false, active: false, status: 'mismatch', error: 'Device mismatch' });
    }

    // Check if disabled by Admin
    if (lic.status === 'disabled') {
        lic.isLive = false;
        lic.currentTiktokUser = null;
        return sendSignedHeartbeatResponse({ ok: false, active: false, status: 'disabled', error: 'License disabled by administrator' });
    }

    // Ensure durationDays always has a concrete expiresAt timestamp
    if (!lic.expiresAt && Number(lic.durationDays) > 0) {
        const baseTs = Number(lic.activatedAt) || Number(lic.createdAt) || now;
        lic.expiresAt = baseTs + Number(lic.durationDays) * 24 * 60 * 60 * 1000;
    }

    // Check expiration
    if (lic.status === 'expired' || (lic.expiresAt && now > Number(lic.expiresAt))) {
        lic.status = 'expired';
        lic.isLive = false;
        lic.currentTiktokUser = null;
        saveDatabase(db);
        broadcastAdminUpdate();
        return sendSignedHeartbeatResponse({ ok: false, active: false, status: 'expired', expiresAt: lic.expiresAt, error: 'Nag-expire na ang iyong activation code.' });
    }

    // Update Live Tracking details
    lic.lastSeenAt = Date.now();
    lic.ip = req.ip || req.headers['x-forwarded-for'] || '127.0.0.1';
    lic.appVersion = appVersion || lic.appVersion || 'v3.6.0 Pro Edition';
    if (osPlatform) lic.osPlatform = osPlatform;
    if (hostname) lic.hostname = hostname;

    // Track currently connected live TikTok user
    const wasLive = lic.isLive;
    if (typeof currentTiktokUser !== 'undefined') {
        lic.currentTiktokUser = currentTiktokUser ? String(currentTiktokUser).trim().replace(/^@/, '') : null;
        lic.isLive = !!lic.currentTiktokUser;

        if (!wasLive && lic.isLive) {
            lic.totalLiveSessions = (lic.totalLiveSessions || 0) + 1;
            lic.liveStartedAt = Date.now();
        } else if (!lic.isLive) {
            lic.liveStartedAt = null;
        }
    }

    // Track historical list of all TikTok users connected from this PC
    if (Array.isArray(tiktokHistory)) {
        if (!Array.isArray(lic.tiktokHistory)) lic.tiktokHistory = [];
        tiktokHistory.forEach(u => {
            const cleanUser = String(u || '').trim().replace(/^@/, '');
            if (cleanUser && !lic.tiktokHistory.includes(cleanUser)) {
                lic.tiktokHistory.push(cleanUser);
            }
        });
    } else if (lic.currentTiktokUser) {
        if (!Array.isArray(lic.tiktokHistory)) lic.tiktokHistory = [];
        if (!lic.tiktokHistory.includes(lic.currentTiktokUser)) {
            lic.tiktokHistory.push(lic.currentTiktokUser);
        }
    }

    saveDatabase(db);
    broadcastAdminUpdate();

    return sendSignedHeartbeatResponse({
        ok: true,
        active: true,
        clientName: lic.clientName,
        status: lic.status,
        expiresAt: lic.expiresAt
    });
});

// ---------------------------------------------------------------------------
// ADMIN DASHBOARD REST APIs
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// SUPER ADMIN RESELLER / CLIENT MANAGEMENT REST APIs
// ---------------------------------------------------------------------------

// 1. Get all client accounts with real-time online status and quota (Super Admin only)
app.get('/api/superadmin/clients', requireSuperAdmin, async (req, res) => {
    await ensureDbReady();
    const db = loadDatabase();
    return res.json({
        ok: true,
        count: db.clients.length,
        clients: db.clients.map(c => sanitizeClient(c, db))
    });
});

// 2. Create new client / reseller account
app.post('/api/superadmin/clients/create', requireSuperAdmin, async (req, res) => {
    await ensureDbReady();
    const { username, password, name, maxLimit } = req.body || {};
    const cleanUsername = String(username || '').trim().toLowerCase();
    const cleanPass = String(password || '').trim();

    if (!cleanUsername || cleanUsername.length < 3) {
        return res.status(400).json({ ok: false, error: 'Ang username ay dapat hindi bababa sa 3 characters.' });
    }
    if (!/^[a-z0-9_-]+$/i.test(cleanUsername)) {
        return res.status(400).json({ ok: false, error: 'Ang username ay letters, numbers, dash (-) at underscore (_) lamang.' });
    }
    if (!cleanPass || cleanPass.length < 4) {
        return res.status(400).json({ ok: false, error: 'Ang password ay dapat hindi bababa sa 4 characters.' });
    }

    const db = loadDatabase();
    if (db.clients.some(c => c.username.toLowerCase() === cleanUsername) || cleanUsername === 'admin') {
        return res.status(400).json({ ok: false, error: `Mayroon nang account na may username na "${cleanUsername}". Pumili ng iba.` });
    }

    const limit = Math.max(1, parseInt(maxLimit, 10) || 10);
    const newClient = {
        id: 'cli_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
        username: cleanUsername,
        password: cleanPass,
        name: String(name || cleanUsername).trim(),
        maxLimit: limit,
        status: 'active',
        createdAt: Date.now(),
        lastSeenAt: null,
        isOnline: false
    };

    db.clients.unshift(newClient);
    saveDatabase(db);
    broadcastClientsToSuperAdmin();

    return res.json({
        ok: true,
        message: `Matagumpay na nagawa ang client account para kay "${newClient.name}"!`,
        client: sanitizeClient(newClient, db)
    });
});

// 3. Edit client account (update limit, password, or name)
app.post('/api/superadmin/clients/:id/edit', requireSuperAdmin, async (req, res) => {
    await ensureDbReady();
    const { id } = req.params;
    const { name, password, maxLimit } = req.body || {};
    const db = loadDatabase();
    const client = db.clients.find(c => c.id === id || c.username === id);

    if (!client) {
        return res.status(404).json({ ok: false, error: 'Client account not found.' });
    }

    if (name) client.name = String(name).trim();
    if (password && String(password).trim().length >= 4) {
        client.password = String(password).trim();
    }
    if (typeof maxLimit !== 'undefined') {
        client.maxLimit = Math.max(1, parseInt(maxLimit, 10) || 1);
    }

    saveDatabase(db);
    broadcastClientsToSuperAdmin();
    broadcastAdminUpdate();

    return res.json({
        ok: true,
        message: `Na-update ang client account ni "${client.name}"!`,
        client: sanitizeClient(client, db)
    });
});

// 4. Toggle Disable / Enable client account
app.post('/api/superadmin/clients/:id/toggle-status', requireSuperAdmin, async (req, res) => {
    await ensureDbReady();
    const { id } = req.params;
    const db = loadDatabase();
    const client = db.clients.find(c => c.id === id || c.username === id);

    if (!client) {
        return res.status(404).json({ ok: false, error: 'Client account not found.' });
    }

    client.status = (client.status === 'disabled') ? 'active' : 'disabled';
    if (client.status === 'disabled') {
        client.isOnline = false;
        io.in(`client_${client.username}`).disconnectSockets(true);
    }

    saveDatabase(db);
    broadcastClientsToSuperAdmin();
    broadcastAdminUpdate();

    return res.json({
        ok: true,
        status: client.status,
        message: client.status === 'active' ? `Naka-enable na ang account ni "${client.name}".` : `Naka-disable na ang account ni "${client.name}".`
    });
});

// 5. Delete client account
app.delete('/api/superadmin/clients/:id', requireSuperAdmin, async (req, res) => {
    await ensureDbReady();
    const { id } = req.params;
    const db = loadDatabase();
    const idx = db.clients.findIndex(c => c.id === id || c.username === id);

    if (idx === -1) {
        return res.status(404).json({ ok: false, error: 'Client account not found.' });
    }

    const removed = db.clients.splice(idx, 1)[0];
    io.in(`client_${removed.username}`).disconnectSockets(true);

    saveDatabase(db);
    broadcastClientsToSuperAdmin();

    return res.json({
        ok: true,
        message: `Na-delete ang account ni "${removed.name}".`
    });
});

// ---------------------------------------------------------------------------
// ADMIN / CLIENT DASHBOARD REST APIs
// ---------------------------------------------------------------------------

// Get licenses (Role-filtered: Client sees only their licenses; Super Admin sees all)
app.get('/api/admin/licenses', async (req, res) => {
    await ensureDbReady();
    const db = loadDatabase();
    const now = Date.now();
    let changed = false;

    db.licenses.forEach(lic => {
        if (!lic.expiresAt && Number(lic.durationDays) > 0) {
            const baseTs = Number(lic.activatedAt) || Number(lic.createdAt) || now;
            lic.expiresAt = baseTs + Number(lic.durationDays) * 24 * 60 * 60 * 1000;
            changed = true;
        }
        if (lic.expiresAt && now > Number(lic.expiresAt) && lic.status === 'active') {
            lic.status = 'expired';
            lic.isLive = false;
            lic.currentTiktokUser = null;
            changed = true;
        }
    });

    if (changed) {
        saveDatabase(db);
    }

    // Role: Reseller Client
    if (req.authRole === 'client') {
        const client = req.authClient;
        const myLicenses = db.licenses.filter(l => l.createdBy === client.username);
        const used = myLicenses.length;
        const limit = Number(client.maxLimit) || 0;

        return res.json({
            ok: true,
            role: 'client',
            serverTime: now,
            count: myLicenses.length,
            licenses: myLicenses,
            quota: {
                maxLimit: limit,
                usedCount: used,
                remainingSlots: Math.max(0, limit - used)
            },
            client: sanitizeClient(client, db)
        });
    }

    // Role: Super Admin (Master View)
    res.json({
        ok: true,
        role: 'superadmin',
        serverTime: now,
        count: db.licenses.length,
        licenses: db.licenses,
        clientsCount: db.clients.length,
        clients: db.clients.map(c => sanitizeClient(c, db)),
        boundDevices: db.boundDevices || {},
        database: isMongoConnected ? 'mongodb' : 'local',
        mongoConnected: isMongoConnected
    });
});

// Sync & restore licenses from browser localStorage or backup file (Preserves data when Render Free sleeps)
app.post('/api/admin/licenses/sync-backup', requireSuperAdmin, async (req, res) => {
    await ensureDbReady();
    const { licenses, boundDevices, clients } = req.body || {};
    if (!Array.isArray(licenses)) {
        return res.status(400).json({ ok: false, error: 'Invalid licenses data' });
    }
    const db = loadDatabase();
    const now = Date.now();
    let restoredCount = 0;

    licenses.forEach(incoming => {
        if (!incoming || !incoming.code) return;
        if (incoming.expiresAt && now > Number(incoming.expiresAt) && incoming.status === 'active') {
            incoming.status = 'expired';
        }
        const idx = db.licenses.findIndex(l => l.code === incoming.code);
        if (idx === -1) {
            db.licenses.push(incoming);
            restoredCount++;
        } else {
            const existing = db.licenses[idx];
            const preserveStatus = (existing.status === 'disabled' || existing.status === 'expired')
                ? existing.status
                : (incoming.status || existing.status);
            db.licenses[idx] = Object.assign({}, incoming, existing, { status: preserveStatus });
        }
    });

    if (boundDevices && typeof boundDevices === 'object') {
        db.boundDevices = Object.assign({}, boundDevices, db.boundDevices);
    }

    if (Array.isArray(clients)) {
        clients.forEach(c => {
            if (!c || !c.username) return;
            const exIdx = db.clients.findIndex(x => x.username === c.username);
            if (exIdx === -1) {
                db.clients.push(c);
            }
        });
    }

    saveDatabase(db);
    broadcastAdminUpdate();
    broadcastClientsToSuperAdmin();

    return res.json({
        ok: true,
        message: `Matagumpay na na-sync/na-restore ang ${restoredCount} licenses!`,
        count: db.licenses.length,
        licenses: db.licenses
    });
});

// Create new license (Enforces quota limit for Clients)
app.post('/api/admin/licenses/create', async (req, res) => {
    await ensureDbReady();
    const { clientName, durationDays, customCode, assignedClient } = req.body || {};
    const db = loadDatabase();
    const now = Date.now();

    let createdBy = 'superadmin';
    let createdByName = 'Master Super Admin';

    if (req.authRole === 'client') {
        const client = req.authClient;
        if (client.status === 'disabled') {
            return res.status(403).json({ ok: false, error: 'Naka-disable ang iyong account. Makipag-ugnayan sa Super Admin.' });
        }

        const used = getClientUsedQuota(db, client.username);
        const limit = Number(client.maxLimit) || 0;
        if (limit > 0 && used >= limit) {
            return res.status(403).json({
                ok: false,
                error: `Naabot mo na ang iyong limitasyon (${used}/${limit} activations). Makipag-ugnayan sa Super Admin upang mag-request ng karagdagang quota.`
            });
        }
        createdBy = client.username;
        createdByName = client.name || client.username;
    } else if (req.authRole === 'superadmin' && assignedClient) {
        const targetClient = db.clients.find(c => c.username === assignedClient || c.id === assignedClient);
        if (targetClient) {
            createdBy = targetClient.username;
            createdByName = targetClient.name || targetClient.username;
        }
    }

    let code = String(customCode || '').replace(/\D/g, '').trim();
    if (code.length === 8) {
        if (db.licenses.some(l => l.code === code)) {
            return res.status(400).json({ ok: false, error: 'Mayroon nang umiiral na license na may parehong 8-digit code.' });
        }
    } else {
        code = generateUnique8DigitCode(db);
    }

    const days = parseInt(durationDays, 10);
    const expiresAt = (days && days > 0) ? (now + days * 24 * 60 * 60 * 1000) : null;

    const newLic = {
        code,
        clientName: String(clientName || 'Valued Customer').trim(),
        createdBy,
        createdByName,
        createdAt: now,
        durationDays: days || 0, // 0 = Lifetime
        expiresAt,
        status: 'active',
        boundDeviceId: null,
        deviceLocked: false,
        activatedAt: null,
        lastSeenAt: null,
        currentTiktokUser: null,
        isLive: false,
        tiktokHistory: [],
        appVersion: null,
        ip: null
    };

    db.licenses.unshift(newLic);
    saveDatabase(db);
    broadcastAdminUpdate();

    return res.json({
        ok: true,
        license: newLic,
        client: req.authRole === 'client' ? sanitizeClient(req.authClient, db) : null,
        message: `Matagumpay na nagenerate ang activation code #${newLic.code}!`
    });
});

// Toggle Disable / Enable license
app.post('/api/admin/licenses/:code/toggle-status', async (req, res) => {
    await ensureDbReady();
    const { code } = req.params;
    const db = loadDatabase();
    const lic = db.licenses.find(l => l.code === code);

    if (!lic) {
        return res.status(404).json({ ok: false, error: 'License not found' });
    }

    // If client, verify ownership
    if (req.authRole === 'client' && lic.createdBy !== req.authUser) {
        return res.status(403).json({ ok: false, error: 'Wala kang permiso sa lisensyang ito.' });
    }

    if (lic.status === 'disabled') {
        if (lic.expiresAt && Date.now() > Number(lic.expiresAt)) {
            lic.status = 'expired';
        } else {
            lic.status = 'active';
        }
    } else {
        lic.status = 'disabled';
        lic.isLive = false;
        lic.currentTiktokUser = null;
    }
    saveDatabase(db);
    broadcastAdminUpdate();

    return res.json({ ok: true, status: lic.status });
});

// Unlock hardware / reset device lock
app.post('/api/admin/licenses/:code/unlock-device', async (req, res) => {
    await ensureDbReady();
    const { code } = req.params;
    const db = loadDatabase();
    const lic = db.licenses.find(l => l.code === code);

    if (!lic) {
        return res.status(404).json({ ok: false, error: 'License not found' });
    }

    if (req.authRole === 'client' && lic.createdBy !== req.authUser) {
        return res.status(403).json({ ok: false, error: 'Wala kang permiso sa lisensyang ito.' });
    }

    const previousDevice = lic.boundDeviceId;
    lic.deviceLocked = false;
    lic.boundDeviceId = null;
    lic.currentTiktokUser = null;
    lic.isLive = false;

    if (previousDevice && db.boundDevices[previousDevice]) {
        delete db.boundDevices[previousDevice];
    }

    saveDatabase(db);
    broadcastAdminUpdate();

    return res.json({ ok: true, message: 'Device lock successfully removed. Ang PC ay pwede na ulit mag-activate o mag-bind.' });
});

// Renew / Extend license expiration
app.post('/api/admin/licenses/:code/renew', async (req, res) => {
    await ensureDbReady();
    const { code } = req.params;
    const { extendDays } = req.body || {};
    const parsedDays = parseInt(extendDays, 10);
    const days = isNaN(parsedDays) ? 30 : parsedDays;

    const db = loadDatabase();
    const lic = db.licenses.find(l => l.code === code);

    if (!lic) {
        return res.status(404).json({ ok: false, error: 'License not found' });
    }

    if (req.authRole === 'client' && lic.createdBy !== req.authUser) {
        return res.status(403).json({ ok: false, error: 'Wala kang permiso sa lisensyang ito.' });
    }

    if (days === 0) {
        lic.expiresAt = null;
        lic.durationDays = 0;
    } else {
        const baseTime = (lic.expiresAt && lic.expiresAt > Date.now()) ? lic.expiresAt : Date.now();
        lic.expiresAt = baseTime + days * 24 * 60 * 60 * 1000;
        lic.durationDays = days;
    }
    lic.status = 'active';
    lic.deviceLocked = false;

    saveDatabase(db);
    broadcastAdminUpdate();

    return res.json({
        ok: true,
        expiresAt: lic.expiresAt,
        message: days === 0 ? 'Ginawang Lifetime Access ang lisensya!' : `Na-extend ng +${days} days ang lisensya.`
    });
});

// Delete license (Super Admin only)
app.delete('/api/admin/licenses/:code', requireSuperAdmin, async (req, res) => {
    await ensureDbReady();
    const { code } = req.params;
    const db = loadDatabase();
    const idx = db.licenses.findIndex(l => l.code === code);

    if (idx === -1) {
        return res.status(404).json({ ok: false, error: 'License not found' });
    }

    const lic = db.licenses[idx];
    if (lic.boundDeviceId && db.boundDevices[lic.boundDeviceId]) {
        delete db.boundDevices[lic.boundDeviceId];
    }

    db.licenses.splice(idx, 1);
    saveDatabase(db);
    broadcastAdminUpdate();

    return res.json({ ok: true, message: 'License deleted.' });
});

// Edit customer details / note
app.post('/api/admin/licenses/:code/edit', async (req, res) => {
    await ensureDbReady();
    const { code } = req.params;
    const { clientName, notes, contactInfo } = req.body || {};
    const db = loadDatabase();
    const lic = db.licenses.find(l => l.code === code);
    if (!lic) return res.status(404).json({ ok: false, error: 'License not found' });

    if (req.authRole === 'client' && lic.createdBy !== req.authUser) {
        return res.status(403).json({ ok: false, error: 'Wala kang permiso sa lisensyang ito.' });
    }

    if (clientName) lic.clientName = String(clientName).trim();
    if (typeof notes !== 'undefined') lic.notes = String(notes).trim();
    if (typeof contactInfo !== 'undefined') lic.contactInfo = String(contactInfo).trim();

    saveDatabase(db);
    broadcastAdminUpdate();
    return res.json({ ok: true, license: lic });
});

// Clear stream history
app.post('/api/admin/licenses/:code/clear-history', async (req, res) => {
    await ensureDbReady();
    const { code } = req.params;
    const db = loadDatabase();
    const lic = db.licenses.find(l => l.code === code);
    if (!lic) return res.status(404).json({ ok: false, error: 'License not found' });

    if (req.authRole === 'client' && lic.createdBy !== req.authUser) {
        return res.status(403).json({ ok: false, error: 'Wala kang permiso sa lisensyang ito.' });
    }

    lic.tiktokHistory = [];
    saveDatabase(db);
    broadcastAdminUpdate();
    return res.json({ ok: true, message: 'Stream history cleared.' });
});

// Start listener
httpServer.listen(PORT, () => {
    console.info(`=======================================================`);
    console.info(`  TIKTOK LIVE REAL-TIME CLOUD ACTIVATOR SERVER RUNNING `);
    console.info(`  Admin Dashboard: http://localhost:${PORT}             `);
    console.info(`=======================================================`);
});

module.exports = { app, httpServer, PORT };

