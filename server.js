require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const { createServer } = require('http');
const { Server } = require('socket.io');
const { MongoClient } = require('mongodb');

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
            return JSON.parse(raw);
        }
    } catch (e) {}
    return { licenses: [], boundDevices: {} };
}

function loadDatabase() {
    if (inMemoryDb) {
        return inMemoryDb;
    }
    inMemoryDb = loadLocalDatabaseFile();
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
            { $set: { licenses: db.licenses, boundDevices: db.boundDevices, updatedAt: Date.now() } },
            { upsert: true }
        ).catch(err => {
            console.error('[Database] Error saving to MongoDB:', err.message);
        });
    }
}

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
                boundDevices: doc.boundDevices || {}
            };
            console.info(`[Database] ✓ Restored ${doc.licenses.length} licenses from MongoDB Atlas!`);
            broadcastAdminUpdate();
        } else {
            // Seed local into cloud
            const local = loadLocalDatabaseFile();
            if (local.licenses.length > 0) {
                await mongoCollection.updateOne(
                    { _id: 'global_state' },
                    { $set: { licenses: local.licenses, boundDevices: local.boundDevices, updatedAt: Date.now() } },
                    { upsert: true }
                );
                inMemoryDb = local;
                console.info(`[Database] ✓ Seeded ${local.licenses.length} existing licenses into MongoDB Atlas!`);
            }
        }
    } catch (err) {
        console.error('[Database] MongoDB connection failed:', err.message);
        isMongoConnected = false;
    }
}
initMongoDB();

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

// Broadcast updates to Admin Dashboard clients via WebSocket
function broadcastAdminUpdate() {
    const db = loadDatabase();
    io.emit('licenses_updated', db.licenses);
}

// ---------------------------------------------------------------------------
// REST API FOR DESKTOP APPLICATION
// ---------------------------------------------------------------------------

/**
 * 1. ACTIVATE LICENSE (Called by Desktop App when entering 8-digit code)
 * POST /api/license/activate
 * Body: { deviceId: string, code: string }
 */
app.post('/api/license/activate', (req, res) => {
    const { deviceId, code } = req.body || {};
    const cleanCode = String(code || '').replace(/\D/g, '').trim();
    const cleanDevice = String(deviceId || '').trim();

    if (!cleanDevice || cleanCode.length !== 8) {
        return res.status(400).json({ ok: false, error: 'Valid Device ID and 8-digit code are required.' });
    }

    const db = loadDatabase();
    const lic = db.licenses.find(l => l.code === cleanCode);

    if (!lic) {
        return res.status(404).json({ ok: false, error: 'Hindi nahanap ang activation code na ito. Paki-check sa administrator.' });
    }

    if (lic.status === 'disabled') {
        return res.status(403).json({ ok: false, error: 'Ang license na ito ay kasalukuyang naka-DISABLE ng administrator.' });
    }

    // Check expiration
    if (lic.expiresAt && Date.now() > lic.expiresAt) {
        lic.status = 'expired';
        saveDatabase(db);
        broadcastAdminUpdate();
        return res.status(403).json({ ok: false, error: 'Nag-expire na ang activation code na ito. Makipag-ugnayan sa administrator para mag-renew.' });
    }

    // Check if license is already bound to another PC
    if (lic.boundDeviceId && lic.boundDeviceId !== cleanDevice) {
        return res.status(409).json({
            ok: false,
            error: `Ang code na ito ay naka-bind na sa ibang PC (${lic.boundDeviceId}). 1 PC per license lang po.`
        });
    }

    // Check if this PC is locked to a DIFFERENT active license
    const existingBinding = db.boundDevices[cleanDevice];
    if (existingBinding && existingBinding.licenseCode !== cleanCode && existingBinding.deviceLocked) {
        const oldLic = db.licenses.find(l => l.code === existingBinding.licenseCode);
        const oldStatus = oldLic ? oldLic.status : 'locked';
        return res.status(423).json({
            ok: false,
            error: `Ang PC na ito ay naka-lock sa dating lisensya (#${existingBinding.licenseCode}). Bawal gumamit ng bagong code nang walang pahintulot. Paki-renew o i-pa-unlock sa administrator.`
        });
    }

    // Bind device & activate
    lic.boundDeviceId = cleanDevice;
    lic.deviceLocked = true;
    lic.activatedAt = lic.activatedAt || Date.now();
    lic.lastSeenAt = Date.now();
    lic.status = 'active';

    // Save device lock record
    db.boundDevices[cleanDevice] = {
        licenseCode: cleanCode,
        deviceLocked: true,
        boundAt: Date.now()
    };

    saveDatabase(db);
    broadcastAdminUpdate();

    return res.json({
        ok: true,
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
 * Body: { deviceId, code, currentTiktokUser, tiktokHistory, appVersion, osPlatform, hostname }
 */
app.post('/api/license/heartbeat', (req, res) => {
    const { deviceId, code, currentTiktokUser, tiktokHistory, appVersion, osPlatform, hostname } = req.body || {};
    const cleanCode = String(code || '').replace(/\D/g, '').trim();
    const cleanDevice = String(deviceId || '').trim();

    if (!cleanDevice || !cleanCode) {
        return res.status(400).json({ ok: false, error: 'Missing deviceId or code' });
    }

    const db = loadDatabase();
    const lic = db.licenses.find(l => l.code === cleanCode);

    if (!lic) {
        return res.json({ ok: false, active: false, status: 'not_found', error: 'License does not exist in cloud' });
    }

    // Verify PC matches bound device
    if (lic.boundDeviceId && lic.boundDeviceId !== cleanDevice) {
        return res.json({ ok: false, active: false, status: 'mismatch', error: 'Device mismatch' });
    }

    // Check if disabled by Admin
    if (lic.status === 'disabled') {
        return res.json({ ok: false, active: false, status: 'disabled', error: 'License disabled by administrator' });
    }

    // Check expiration
    if (lic.expiresAt && Date.now() > lic.expiresAt) {
        lic.status = 'expired';
        saveDatabase(db);
        broadcastAdminUpdate();
        return res.json({ ok: false, active: false, status: 'expired', error: 'License has expired' });
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

    return res.json({
        ok: true,
        active: true,
        status: lic.status,
        expiresAt: lic.expiresAt
    });
});

// ---------------------------------------------------------------------------
// ADMIN DASHBOARD REST APIs
// ---------------------------------------------------------------------------

// Get all licenses
app.get('/api/admin/licenses', (req, res) => {
    const db = loadDatabase();
    res.json({
        ok: true,
        count: db.licenses.length,
        licenses: db.licenses,
        boundDevices: db.boundDevices || {},
        database: isMongoConnected ? 'mongodb' : 'local',
        mongoConnected: isMongoConnected
    });
});

// Sync & restore licenses from browser localStorage or backup file (Preserves data when Render Free sleeps)
app.post('/api/admin/licenses/sync-backup', (req, res) => {
    const { licenses, boundDevices } = req.body || {};
    if (!Array.isArray(licenses)) {
        return res.status(400).json({ ok: false, error: 'Invalid licenses data' });
    }
    const db = loadDatabase();
    let restoredCount = 0;

    licenses.forEach(incoming => {
        if (!incoming || !incoming.code) return;
        const idx = db.licenses.findIndex(l => l.code === incoming.code);
        if (idx === -1) {
            db.licenses.push(incoming);
            restoredCount++;
        } else {
            db.licenses[idx] = Object.assign({}, incoming, db.licenses[idx]);
        }
    });

    if (boundDevices && typeof boundDevices === 'object') {
        db.boundDevices = Object.assign({}, boundDevices, db.boundDevices);
    }

    saveDatabase(db);
    broadcastAdminUpdate();

    return res.json({
        ok: true,
        message: `Matagumpay na na-sync/na-restore ang ${restoredCount} licenses!`,
        count: db.licenses.length,
        licenses: db.licenses
    });
});

// Create new license
app.post('/api/admin/licenses/create', (req, res) => {
    const { clientName, durationDays, customCode } = req.body || {};
    const db = loadDatabase();

    let code = String(customCode || '').replace(/\D/g, '').trim();
    if (code.length === 8) {
        if (db.licenses.some(l => l.code === code)) {
            return res.status(400).json({ ok: false, error: 'Mayroon nang umiiral na license na may parehong 8-digit code.' });
        }
    } else {
        code = generateUnique8DigitCode(db);
    }

    const days = parseInt(durationDays, 10);
    const expiresAt = (days && days > 0) ? (Date.now() + days * 24 * 60 * 60 * 1000) : null;

    const newLic = {
        code,
        clientName: String(clientName || 'Valued Customer').trim(),
        createdAt: Date.now(),
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

    return res.json({ ok: true, license: newLic });
});

// Toggle Disable / Enable license
app.post('/api/admin/licenses/:code/toggle-status', (req, res) => {
    const { code } = req.params;
    const db = loadDatabase();
    const lic = db.licenses.find(l => l.code === code);

    if (!lic) {
        return res.status(404).json({ ok: false, error: 'License not found' });
    }

    lic.status = (lic.status === 'disabled') ? 'active' : 'disabled';
    saveDatabase(db);
    broadcastAdminUpdate();

    return res.json({ ok: true, status: lic.status });
});

// Unlock hardware / reset device lock
// (Allows the user to re-bind or use a new code if authorized by admin)
app.post('/api/admin/licenses/:code/unlock-device', (req, res) => {
    const { code } = req.params;
    const db = loadDatabase();
    const lic = db.licenses.find(l => l.code === code);

    if (!lic) {
        return res.status(404).json({ ok: false, error: 'License not found' });
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
app.post('/api/admin/licenses/:code/renew', (req, res) => {
    const { code } = req.params;
    const { extendDays } = req.body || {};
    const days = parseInt(extendDays, 10) || 30;

    const db = loadDatabase();
    const lic = db.licenses.find(l => l.code === code);

    if (!lic) {
        return res.status(404).json({ ok: false, error: 'License not found' });
    }

    const baseTime = (lic.expiresAt && lic.expiresAt > Date.now()) ? lic.expiresAt : Date.now();
    lic.expiresAt = baseTime + days * 24 * 60 * 60 * 1000;
    lic.status = 'active';

    saveDatabase(db);
    broadcastAdminUpdate();

    return res.json({ ok: true, expiresAt: lic.expiresAt, message: `Na-extend ng +${days} days ang lisensya.` });
});

// Delete license
app.delete('/api/admin/licenses/:code', (req, res) => {
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
app.post('/api/admin/licenses/:code/edit', (req, res) => {
    const { code } = req.params;
    const { clientName, notes, contactInfo } = req.body || {};
    const db = loadDatabase();
    const lic = db.licenses.find(l => l.code === code);
    if (!lic) return res.status(404).json({ ok: false, error: 'License not found' });

    if (clientName) lic.clientName = String(clientName).trim();
    if (typeof notes !== 'undefined') lic.notes = String(notes).trim();
    if (typeof contactInfo !== 'undefined') lic.contactInfo = String(contactInfo).trim();

    saveDatabase(db);
    broadcastAdminUpdate();
    return res.json({ ok: true, license: lic });
});

// Clear stream history
app.post('/api/admin/licenses/:code/clear-history', (req, res) => {
    const { code } = req.params;
    const db = loadDatabase();
    const lic = db.licenses.find(l => l.code === code);
    if (!lic) return res.status(404).json({ ok: false, error: 'License not found' });

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

