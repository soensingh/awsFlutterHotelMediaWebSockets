/**
 * Hotel Media – Production WebSocket Server
 *
 * Responsibilities:
 *  - Authenticate clients via JWT (same secret as Next.js)
 *  - Route messages between connected users with zero polling
 *  - Persist messages to MongoDB
 *  - Broadcast typing indicators with server-side auto-stop safety
 *  - Mark messages as seen
 *  - Heartbeat every 30 s to evict zombie connections
 *  - Health-check endpoint at GET /health
 *
 * WS Protocol (JSON frames):
 *   Client → Server                     Server → Client
 *   ─────────────────────────────────── ────────────────────────────────────
 *   { type:'auth', token }              { type:'auth_ok', userId }
 *   { type:'ping' }                     { type:'pong' }
 *   { type:'message', to, message,      { type:'message', message:{…} }
 *     tempId }                          { type:'message_ack', tempId,
 *                                          message:{…} }
 *   { type:'typing_start', to }         { type:'typing_start', from }
 *   { type:'typing_stop',  to }         { type:'typing_stop',  from }
 *   { type:'mark_seen', partnerId }     { type:'seen', by }
 *                                       { type:'replaced' }  (dupe conn)
 *                                       { type:'error', message }
 */

import { createServer }     from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import jwt                   from 'jsonwebtoken';
import mongoose              from 'mongoose';
import dotenv                from 'dotenv';
import path                  from 'path';
import { fileURLToPath }     from 'url';
import admin                 from 'firebase-admin';
import apn                   from '@parse/node-apn';

// ── Config ────────────────────────────────────────────────────────────────────
const __dirname = path.dirname(fileURLToPath(import.meta.url));
import { existsSync } from 'fs';

// Load .env from own directory first (production), fall back to sibling hotelmedia/ (local dev)
const localEnv   = path.join(__dirname, '.env');
const siblingEnv = path.join(__dirname, '../hotelmedia/.env');
dotenv.config({ path: existsSync(localEnv) ? localEnv : siblingEnv });

const {
  JWT_SECRET_MOBILE:  JWT_SECRET,
  JWT_ISSUER_MOBILE:  JWT_ISSUER,
  JWT_AUDIENCE_MOBILE: JWT_AUDIENCE,
  // Admin (web) JWT — different keyspace from mobile
  JWT_SECRET:  ADMIN_JWT_SECRET,
  JWT_ISSUER:  ADMIN_JWT_ISSUER,
  JWT_AUDIENCE: ADMIN_JWT_AUDIENCE,
  MONGODB_URI,
  MONGODB_DB,
  WS_PORT = '3001',
  WS_NOTIFY_SECRET,
  FIREBASE_SERVICE_ACCOUNT_B64,
  FIREBASE_SERVICE_ACCOUNT,
  VOIP_CERT_B64,
  VOIP_KEY_B64,
} = process.env;

if (!JWT_SECRET) { console.error('[WS] JWT_SECRET_MOBILE missing'); process.exit(1); }
if (!MONGODB_URI) { console.error('[WS] MONGODB_URI missing');        process.exit(1); }
if (!MONGODB_DB)  { console.error('[WS] MONGODB_DB missing');         process.exit(1); }
if (!ADMIN_JWT_SECRET) { console.warn('[WS] JWT_SECRET (admin) missing — admin sockets disabled'); }

// ── Firebase Admin (FCM) ──────────────────────────────────────────────────────
let _fcmReady = false;
try {
  let serviceAccount = null;
  if (FIREBASE_SERVICE_ACCOUNT_B64) {
    serviceAccount = JSON.parse(
      Buffer.from(FIREBASE_SERVICE_ACCOUNT_B64, 'base64').toString('utf8')
    );
  } else if (FIREBASE_SERVICE_ACCOUNT) {
    serviceAccount = JSON.parse(FIREBASE_SERVICE_ACCOUNT);
  }

  if (serviceAccount) {
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    _fcmReady = true;
    console.log('[WS] Firebase Admin initialised — FCM enabled');
  } else {
    console.warn('[WS] FIREBASE_SERVICE_ACCOUNT_B64/FIREBASE_SERVICE_ACCOUNT not set — FCM disabled');
  }
} catch (e) {
  console.warn('[WS] Firebase Admin init failed — FCM disabled:', e.message);
}

// ── APNs VoIP ─────────────────────────────────────────────────────────────────
let _apnProvider = null;
try {
  if (VOIP_CERT_B64 && VOIP_KEY_B64) {
    const cert = Buffer.from(VOIP_CERT_B64, 'base64').toString('utf8');
    const key  = Buffer.from(VOIP_KEY_B64,  'base64').toString('utf8');
    _apnProvider = new apn.Provider({ cert, key, production: true });
    console.log('[WS] APNs VoIP provider initialised');
  } else {
    console.warn('[WS] VOIP_CERT_B64/VOIP_KEY_B64 not set — VoIP push disabled');
  }
} catch (e) {
  console.warn('[WS] APNs VoIP init failed:', e.message);
}

// ── MongoDB ───────────────────────────────────────────────────────────────────
let _db    = null;
let _model = null;

async function getMessageModel() {
  if (_model) return _model;

  if (!_db) {
    await mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
    _db = mongoose.connection.useDb(MONGODB_DB, { useCache: true });
    console.log('[WS] MongoDB connected →', MONGODB_DB);
  }

  const schema = new mongoose.Schema(
    {
      message:          { type: String,  default: '' },
      isSeen:           { type: Boolean, default: false },
      deletedByID:      [mongoose.Schema.Types.ObjectId],
      userID:           { type: mongoose.Schema.Types.ObjectId, required: true },
      targetUserID:     { type: mongoose.Schema.Types.ObjectId, required: true },
      type:             { type: String,  default: 'text' },
      isEdited:         { type: Boolean, default: false },
      isDeleted:        { type: Boolean, default: false },
      starredBy:        [mongoose.Schema.Types.ObjectId],
      pinnedBy:         [mongoose.Schema.Types.ObjectId],
      replyToId:        { type: mongoose.Schema.Types.ObjectId, default: null },
      replyToText:      { type: String,  default: null },
      forwardedFromId:  { type: mongoose.Schema.Types.ObjectId, default: null },
      reactions:        { type: Map, of: [mongoose.Schema.Types.ObjectId], default: new Map() },
    },
    { timestamps: true, collection: 'messages' }
  );

  _model =
    (_db.models && _db.models.Message) ||
    _db.model('Message', schema);

  return _model;
}

// Pre-connect at startup (non-fatal — server still starts if DB is slow)
getMessageModel().catch((err) =>
  console.error('[WS] Initial DB connection failed:', err.message)
);

// ── FCM token model ───────────────────────────────────────────────────────────────────
let _fcmTokenModel = null;
async function getFcmTokenModel() {
  if (_fcmTokenModel) return _fcmTokenModel;
  // Reuse the same DB connection opened by getMessageModel
  if (!_db) await getMessageModel().catch(() => {});
  if (!_db) throw new Error('DB not ready');
  const schema = new mongoose.Schema(
    { userId: { type: String, required: true, unique: true }, token: { type: String, required: true } },
    { timestamps: true, collection: 'fcm_tokens' }
  );
  _fcmTokenModel = (_db.models?.FcmToken) || _db.model('FcmToken', schema);
  return _fcmTokenModel;
}

// ── VoIP token model ─────────────────────────────────────────────────────────────────
let _voipTokenModel = null;
async function getVoipTokenModel() {
  if (_voipTokenModel) return _voipTokenModel;
  if (!_db) await getMessageModel().catch(() => {});
  if (!_db) throw new Error('DB not ready');
  const schema = new mongoose.Schema(
    { userId: { type: String, required: true, unique: true }, token: { type: String, required: true } },
    { timestamps: true, collection: 'voip_tokens' }
  );
  _voipTokenModel = (_db.models?.VoipToken) || _db.model('VoipToken', schema);
  return _voipTokenModel;
}

// ── Pending-call buffer ───────────────────────────────────────────────────────────────
// Stores the latest call offer data for each callee during the ring window.
// This is used for both offline callees and stale-socket scenarios so that,
// after push wake-up + WS reconnect, the app can always recover the full SDP.
// Entry shape: { offer, callerSocketId, expiresAt }
/**
 * @type {Map<string, { offer: object, callerId: string, expiresAt: number }>}
 */
const pendingCalls = new Map();

/**
 * callId -> fallback timer. If the callee doesn't ACK call_offer quickly,
 * we send FCM as a backup wake-up for "swiped from recents" scenarios.
 * @type {Map<string, ReturnType<typeof setTimeout>>}
 */
const offerAckTimers = new Map();

function clearOfferAckFallback(callId) {
  if (!callId) return;
  const t = offerAckTimers.get(callId);
  if (t) {
    clearTimeout(t);
    offerAckTimers.delete(callId);
  }
}

function clearPendingOffer(calleeId, { callId, callerId } = {}) {
  if (!calleeId) return;
  const entry = pendingCalls.get(calleeId);
  if (!entry) return;

  if (callerId && entry.callerId !== callerId) return;

  if (callId) {
    const pendingCallId = entry.offer?.callId?.toString();
    if (!pendingCallId || pendingCallId !== callId.toString()) return;
  }

  pendingCalls.delete(calleeId);
}

function scheduleOfferAckFallback(calleeId, offerPayload) {
  const callId = offerPayload.callId?.toString();
  if (!callId) {
    sendVoipPushOrFcm(calleeId, offerPayload);
    return;
  }

  clearOfferAckFallback(callId);
  const t = setTimeout(async () => {
    offerAckTimers.delete(callId);
    // No ACK received in time; send VoIP push (iOS) or FCM (Android) backup.
    await sendVoipPushOrFcm(calleeId, offerPayload);
  }, 1200);
  offerAckTimers.set(callId, t);
}

// Expire pending calls that were never answered (ring window = 60 s)
setInterval(() => {
  const now = Date.now();
  for (const [calleeId, entry] of pendingCalls) {
    if (now >= entry.expiresAt) {
      pendingCalls.delete(calleeId);
    }
  }
}, 10_000);

// ── State ─────────────────────────────────────────────────────────────────────

/**
 * userId → WebSocket  (one active connection per user)
 * @type {Map<string, import('ws').WebSocket & { isAlive: boolean, userId: string }>}
 */
const users = new Map();

/**
 * Typing cleanup timers: `${fromId}:${toId}` → NodeJS.Timeout
 * Auto-stops typing after 6 s even if client forgets to send typing_stop.
 * @type {Map<string, ReturnType<typeof setTimeout>>}
 */
const typingTimers = new Map();

/**
 * Admin sockets keyed by admin userId. Each entry is a Set of connected
 * sockets for that user (multiple browser tabs / devices). Each socket
 * carries the `sid` from its admin JWT so we can target stale sessions
 * when a fresh login rotates `adminSessionTokenId`.
 * @type {Map<string, Set<import('ws').WebSocket & { adminUserId: string, sid: string }>>}
 */
const adminSockets = new Map();

function registerAdminSocket(ws) {
  if (!ws.adminUserId) return;
  let set = adminSockets.get(ws.adminUserId);
  if (!set) { set = new Set(); adminSockets.set(ws.adminUserId, set); }
  set.add(ws);
}

function unregisterAdminSocket(ws) {
  if (!ws.adminUserId) return;
  const set = adminSockets.get(ws.adminUserId);
  if (!set) return;
  set.delete(ws);
  if (set.size === 0) adminSockets.delete(ws.adminUserId);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function trySend(ws, payload) {
  if (ws?.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(payload));
  }
}

function sendToUser(userId, payload) {
  trySend(users.get(userId), payload);
}

function verifyJwt(rawToken) {
  // Accept with or without "Bearer " prefix
  const token = rawToken?.replace(/^Bearer\s+/i, '') ?? '';
  try {
    const opts = {};
    if (JWT_ISSUER)   opts.issuer   = JWT_ISSUER;
    if (JWT_AUDIENCE) opts.audience = JWT_AUDIENCE;
    const p = jwt.verify(token, JWT_SECRET, opts);
    return (p.sub ?? p.id ?? p.userId)?.toString() ?? null;
  } catch {
    return null;
  }
}

/**
 * Verify an admin (web) JWT and return { sub, sid } or null.
 */
function verifyAdminJwt(rawToken) {
  if (!ADMIN_JWT_SECRET) return null;
  const token = rawToken?.replace(/^Bearer\s+/i, '') ?? '';
  try {
    const opts = {};
    if (ADMIN_JWT_ISSUER)   opts.issuer   = ADMIN_JWT_ISSUER;
    if (ADMIN_JWT_AUDIENCE) opts.audience = ADMIN_JWT_AUDIENCE;
    const p = jwt.verify(token, ADMIN_JWT_SECRET, opts);
    const sub = (p.sub ?? p.id ?? p.userId)?.toString();
    const sid = p.sid?.toString();
    if (!sub || !sid) return null;
    return { sub, sid };
  } catch {
    return null;
  }
}

/**
 * Builds a reaction_updated payload for a specific viewer.
 * reactions map: emoji → array of userIds, with viewer's id replaced by 'me'.
 */
function buildReactionPayload(doc, viewerUserId) {
  const reactionsRaw = doc.reactions;
  const reactions = {};
  if (reactionsRaw) {
    const entries = reactionsRaw instanceof Map
      ? Array.from(reactionsRaw.entries())
      : Object.entries(reactionsRaw);
    for (const [emoji, ids] of entries) {
      if (!Array.isArray(ids) || ids.length === 0) continue;
      reactions[emoji] = ids.map(id => id.toString() === viewerUserId ? 'me' : id.toString());
    }
  }
  return { type: 'reaction_updated', messageId: doc._id.toString(), reactions };
}

/**
 * Serializes a Mongoose doc for a specific viewer so isFromMe is correct.
 */
function serializeMsg(doc, viewerUserId) {
  // Serialize reactions: replace viewer's id with the sentinel 'me'
  const reactionsRaw = doc.reactions;
  const reactions = {};
  if (reactionsRaw) {
    const entries = reactionsRaw instanceof Map
      ? Array.from(reactionsRaw.entries())
      : Object.entries(reactionsRaw);
    for (const [emoji, ids] of entries) {
      if (!Array.isArray(ids) || ids.length === 0) continue;
      reactions[emoji] = ids.map(id => id.toString() === viewerUserId ? 'me' : id.toString());
    }
  }
  return {
    id:          doc._id.toString(),
    senderId:    doc.userID.toString(),
    targetId:    doc.targetUserID.toString(),
    message:     doc.message,
    type:        doc.type ?? 'text',
    isSeen:      doc.isSeen ?? false,
    isFromMe:    doc.userID.toString() === viewerUserId,
    createdAt:   (doc.createdAt ?? new Date()).toISOString(),
    replyToId:   doc.replyToId?.toString() ?? null,
    replyToText: doc.replyToText ?? null,
    reactions,
  };
}

function isValidOid(id) {
  return mongoose.Types.ObjectId.isValid(id);
}

// ── FCM helpers ─────────────────────────────────────────────────────────────────────
async function getStoredFcmToken(userId) {
  try {
    const FcmToken = await getFcmTokenModel();
    const doc = await FcmToken.findOne({ userId }).lean();
    return doc?.token ?? null;
  } catch { return null; }
}

async function sendCallFcm(calleeId, offerPayload) {
  if (!_fcmReady) return;
  const token = await getStoredFcmToken(calleeId);
  if (!token) return;
  try {
    await admin.messaging().send({
      token,
      data: {
        type:           'incoming_call',
        callId:         offerPayload.callId      ?? '',
        fromUserId:     offerPayload.from        ?? '',
        // SDP omitted — too large for FCM 4 KB limit. Android wakes up and
        // gets the full offer over WebSocket via the pendingCalls buffer.
        isVideo:        String(offerPayload.isVideo ?? false),
        callerName:     offerPayload.callerName  ?? '',
        callerUsername: offerPayload.callerUsername ?? '',
        callerPic:      offerPayload.callerPic   ?? '',
      },
      android: {
        priority: 'high',
        ttl: 30_000,
      },
      apns: {
        headers: {
          'apns-push-type': 'background',
          'apns-priority': '5',
        },
        payload: { aps: { contentAvailable: true } },
      },
    });
    console.log(`[WS] FCM call push → ${calleeId}`);
  } catch (e) {
    console.warn(`[WS] FCM send failed for ${calleeId}:`, e.message);
  }
}

async function sendCancelCallFcm(calleeId) {
  if (!_fcmReady) return;
  const token = await getStoredFcmToken(calleeId);
  if (!token) return;
  try {
    await admin.messaging().send({
      token,
      data: { type: 'call_cancelled' },
      android: {
        priority: 'high',
        ttl: 30_000,
      },
      apns: {
        headers: {
          'apns-push-type': 'background',
          'apns-priority': '5',
        },
        payload: { aps: { contentAvailable: true } },
      },
    });
  } catch { /* best-effort */ }
}

async function getStoredVoipToken(userId) {
  try {
    const VoipToken = await getVoipTokenModel();
    const doc = await VoipToken.findOne({ userId }).lean();
    return doc?.token ?? null;
  } catch { return null; }
}

async function sendVoipPush(calleeId, offerPayload) {
  if (!_apnProvider) return false;
  const token = await getStoredVoipToken(calleeId);
  if (!token) return false;
  try {
    const notification = new apn.Notification();
    notification.topic    = 'com.thehotelmedia.mobile.voip';
    notification.priority = 10;
    notification.pushType = 'voip';
    notification.expiry   = Math.floor(Date.now() / 1000) + 60;
    notification.payload  = {
      callId:         offerPayload.callId          ?? '',
      from:           offerPayload.from            ?? '',
      sdp:            offerPayload.sdp             ?? '',
      isVideo:        String(offerPayload.isVideo  ?? false),
      callerName:     offerPayload.callerName      ?? '',
      callerUsername: offerPayload.callerUsername  ?? '',
      callerPic:      offerPayload.callerPic       ?? '',
    };
    const result = await _apnProvider.send(notification, token);
    if (result.failed.length > 0) {
      console.warn(`[WS] APNs VoIP failed for ${calleeId}:`, result.failed[0].response);
      return false;
    }
    console.log(`[WS] APNs VoIP push → ${calleeId}`);
    return true;
  } catch (e) {
    console.warn(`[WS] APNs VoIP error for ${calleeId}:`, e.message);
    return false;
  }
}

/** Try VoIP push first; fall back to FCM for Android / no-VoIP-token devices. */
async function sendVoipPushOrFcm(calleeId, offerPayload) {
  const sentVoip = await sendVoipPush(calleeId, offerPayload);
  if (!sentVoip) await sendCallFcm(calleeId, offerPayload);
}

// ── HTTP server (health + WS upgrade) ────────────────────────────────────────
const http = createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, connections: users.size }));
    return;
  }

  // ── Internal notify endpoint ────────────────────────────────────────────
  // POST /notify  { userId, type }
  // Protected by WS_NOTIFY_SECRET (shared with Next.js via env).
  // type is one of: profile_posts_changed | profile_reels_changed | profile_reviews_changed
  if (req.method === 'POST' && req.url === '/notify') {
    const secret = req.headers['x-notify-secret'];
    if (!WS_NOTIFY_SECRET || secret !== WS_NOTIFY_SECRET) {
      res.writeHead(401);
      res.end('Unauthorized');
      return;
    }
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      try {
        const { userId, type } = JSON.parse(body);
        if (!userId || !type) { res.writeHead(400); res.end('Missing userId or type'); return; }
        sendToUser(userId, { type });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400);
        res.end('Invalid JSON');
      }
    });
    return;
  }

  res.writeHead(404);
  res.end();
});

const wss = new WebSocketServer({ server: http });

// ── Connection handler ────────────────────────────────────────────────────────
wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.userId  = null;

  // Require authentication within 5 seconds
  const authTimeout = setTimeout(() => {
    if (!ws.userId) {
      trySend(ws, { type: 'error', message: 'Auth timeout' });
      ws.terminate();
    }
  }, 5000);

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', async (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    switch (msg.type) {

      // ── auth ───────────────────────────────────────────────────────────
      case 'auth': {
        const uid = verifyJwt(msg.token);
        if (!uid) {
          trySend(ws, { type: 'error', message: 'Unauthorized' });
          ws.terminate();
          return;
        }
        clearTimeout(authTimeout);

        // Replace any existing connection for this user
        const existing = users.get(uid);
        if (existing && existing !== ws) {
          trySend(existing, { type: 'replaced' });
          existing.terminate();
        }

        ws.userId = uid;
        users.set(uid, ws);

        // Ensure model is ready (fast path once initialized)
        await getMessageModel().catch(() => {});
        trySend(ws, { type: 'auth_ok', userId: uid });

        // Notify all other connected users that this user came online
        for (const [otherId, otherWs] of users) {
          if (otherId !== uid) {
            trySend(otherWs, { type: 'user_online', userId: uid });
          }
        }

        // Deliver a buffered pending call if the caller is still online
        const pending = pendingCalls.get(uid);
        if (pending && Date.now() < pending.expiresAt && users.has(pending.callerId)) {
          pendingCalls.delete(uid);
          trySend(ws, pending.offer);
        } else if (pending) {
          pendingCalls.delete(uid);
        }

        console.log(`[WS] +${uid} (${users.size} online)`);
        break;
      }

      // ── ping ───────────────────────────────────────────────────────────
      case 'ping': {
        trySend(ws, { type: 'pong' });
        break;
      }
      // ── auth_admin ──────────────────────────────────────
      // Authenticates an admin (web) socket. Verified with the admin JWT
      // secret — separate from chat. Indexed by userId+sid so a fresh
      // login can target the stale (old-sid) sockets.
      case 'auth_admin': {
        const ident = verifyAdminJwt(msg.token);
        if (!ident) {
          trySend(ws, { type: 'error', message: 'Unauthorized (admin)' });
          ws.terminate();
          return;
        }
        clearTimeout(authTimeout);
        ws.adminUserId = ident.sub;
        ws.sid         = ident.sid;
        registerAdminSocket(ws);
        trySend(ws, { type: 'admin_auth_ok', userId: ident.sub, sid: ident.sid });
        console.log(`[WS] +admin ${ident.sub} sid=${ident.sid.slice(0, 8)}…`);
        break;
      }
      // ── message ────────────────────────────────────────────────────────
      case 'message': {
        const { to, message: text, tempId, replyToId, replyToText } = msg;
        if (!ws.userId || !to || !text?.trim()) return;
        if (!isValidOid(to)) return;

        try {
          const Message = await getMessageModel();
          const createData = {
            userID:       new mongoose.Types.ObjectId(ws.userId),
            targetUserID: new mongoose.Types.ObjectId(to),
            message:      text.trim(),
            type:         text.trim().startsWith('AUDIO\u00a7') ? 'audio' : 'text',
            isSeen:       false,
          };
          if (replyToId && isValidOid(replyToId)) {
            createData.replyToId = new mongoose.Types.ObjectId(replyToId);
          }
          if (replyToText && typeof replyToText === 'string') {
            createData.replyToText = replyToText.slice(0, 500);
          }
          const doc = await Message.create(createData);

          // ACK to sender with the confirmed message
          trySend(ws, {
            type:    'message_ack',
            tempId:  tempId ?? null,
            message: serializeMsg(doc, ws.userId),
          });

          // Forward to recipient if they're online
          sendToUser(to, {
            type:    'message',
            message: serializeMsg(doc, to),
          });
        } catch (err) {
          console.error('[WS] message error:', err.message);
          trySend(ws, {
            type:    'error',
            tempId:  tempId ?? null,
            message: 'Failed to send message',
          });
        }
        break;
      }

      // ── typing_start ───────────────────────────────────────────────────
      case 'typing_start': {
        if (!ws.userId || !msg.to) return;
        const key = `${ws.userId}:${msg.to}`;

        // Refresh auto-stop timer
        const old = typingTimers.get(key);
        if (old) clearTimeout(old);

        sendToUser(msg.to, { type: 'typing_start', from: ws.userId });

        // Safety: auto-stop after 6 s in case client forgets
        typingTimers.set(key, setTimeout(() => {
          sendToUser(msg.to, { type: 'typing_stop', from: ws.userId });
          typingTimers.delete(key);
        }, 6000));
        break;
      }

      // ── typing_stop ────────────────────────────────────────────────────
      case 'typing_stop': {
        if (!ws.userId || !msg.to) return;
        const key = `${ws.userId}:${msg.to}`;
        const t = typingTimers.get(key);
        if (t) { clearTimeout(t); typingTimers.delete(key); }
        sendToUser(msg.to, { type: 'typing_stop', from: ws.userId });
        break;
      }

      // ── mark_seen ──────────────────────────────────────────────────────
      case 'mark_seen': {
        const { partnerId } = msg;
        if (!ws.userId || !partnerId) return;
        if (!isValidOid(partnerId)) return;

        try {
          const Message = await getMessageModel();
          await Message.updateMany(
            {
              userID:       new mongoose.Types.ObjectId(partnerId),
              targetUserID: new mongoose.Types.ObjectId(ws.userId),
              isSeen:       false,
            },
            { $set: { isSeen: true } }
          );
          // Notify the partner that their messages were read
          sendToUser(partnerId, { type: 'seen', by: ws.userId });
        } catch (err) {
          console.error('[WS] mark_seen error:', err.message);
        }
        break;
      }

      // ── reaction ───────────────────────────────────────────────────────
      // Client sends: { type:'reaction', messageId, emoji }
      // Server toggles the emoji, persists, and broadcasts reaction_updated
      // to both sender and the other participant.
      case 'reaction': {
        const { messageId, emoji } = msg;
        if (!ws.userId || !messageId || !emoji?.trim()) return;
        if (!isValidOid(messageId)) return;

        try {
          const Message = await getMessageModel();
          const msgObjId  = new mongoose.Types.ObjectId(messageId);
          const userObjId = new mongoose.Types.ObjectId(ws.userId);

          // Verify the caller is a participant
          const doc = await Message.findOne({
            _id: msgObjId,
            $or: [{ userID: userObjId }, { targetUserID: userObjId }],
          });
          if (!doc) return;

          const reactionField = `reactions.${emoji}`;
          const currentList   = doc.reactions?.get?.(emoji) ?? [];
          const alreadyReacted = currentList.some(id => id.toString() === ws.userId);

          if (alreadyReacted) {
            await Message.updateOne({ _id: msgObjId }, { $pull: { [reactionField]: userObjId } });
          } else {
            await Message.updateOne({ _id: msgObjId }, { $push: { [reactionField]: userObjId } });
          }

          const updated = await Message.findById(msgObjId).lean();
          if (!updated) return;

          const senderId = updated.userID.toString();
          const targetId = updated.targetUserID.toString();
          const otherId  = ws.userId === senderId ? targetId : senderId;

          trySend(ws,           buildReactionPayload(updated, ws.userId));
          sendToUser(otherId,   buildReactionPayload(updated, otherId));
        } catch (err) {
          console.error('[WS] reaction error:', err.message);
        }
        break;
      }

      // ── edit_message ───────────────────────────────────────────────────
      // Client sends: { type:'edit_message', id, message }
      // Server updates DB, acks sender, notifies recipient.
      case 'edit_message': {
        const { id: editId, message: newText } = msg;
        if (!ws.userId || !editId || !newText?.trim()) return;
        if (!isValidOid(editId)) return;

        try {
          const Message = await getMessageModel();
          const doc = await Message.findOne({
            _id:     new mongoose.Types.ObjectId(editId),
            userID:  new mongoose.Types.ObjectId(ws.userId),
            isDeleted: { $ne: true },
          }).lean();

          if (!doc) {
            trySend(ws, { type: 'error', message: 'Message not found or not yours' });
            return;
          }

          const age = Date.now() - new Date(doc.createdAt).getTime();
          if (age > 60_000) {
            trySend(ws, { type: 'error', message: 'Edit window expired (1 minute)' });
            return;
          }

          await Message.findByIdAndUpdate(editId, {
            $set: { message: newText.trim(), isEdited: true },
          });

          const payload = { type: 'message_edited', id: editId, message: newText.trim() };
          trySend(ws, payload);  // ack to sender
          sendToUser(doc.targetUserID.toString(), payload);  // notify recipient
        } catch (err) {
          console.error('[WS] edit_message error:', err.message);
        }
        break;
      }

      // ── WebRTC call signaling ───────────────────────────────────────────
      // All call signals are pure relay: server just forwards to the target user.
      // call_offer  : { type, to, sdp, callId }
      // call_answer : { type, to, sdp, callId }
      // call_ice    : { type, to, candidate:{candidate,sdpMid,sdpMLineIndex}, callId }
      // call_reject : { type, to, callId }
      // call_end    : { type, to, callId }
      case 'call_offer': {
        const { to, sdp, callId, isVideo, callerName, callerUsername, callerPic } = msg;
        if (!ws.userId || !to || !sdp) return;
        const offerPayload = {
          type: 'call_offer',
          from: ws.userId,
          sdp,
          callId:         callId ?? null,
          isVideo:        isVideo === true,
          ...(callerName     ? { callerName }     : {}),
          ...(callerUsername ? { callerUsername } : {}),
          ...(callerPic      ? { callerPic }      : {}),
        };

        // Always retain latest offer during ring window so reconnecting
        // callees can recover SDP after push wake-up.
        pendingCalls.set(to, {
          offer:    offerPayload,
          callerId: ws.userId,
          expiresAt: Date.now() + 60_000,
        });

        if (users.has(to)) {
          // Callee is online — deliver directly over WebSocket
          sendToUser(to, offerPayload);
          // If callee app was just swiped, socket may be stale; FCM fallback
          // will fire unless callee ACKs receipt quickly.
          scheduleOfferAckFallback(to, offerPayload);
        } else {
          // Callee is offline — wake their device now.
          await sendVoipPushOrFcm(to, offerPayload);
        }
        break;
      }
      case 'call_offer_ack': {
        const { callId } = msg;
        if (!ws.userId || !callId) return;
        const cid = callId.toString();
        clearOfferAckFallback(cid);
        clearPendingOffer(ws.userId, { callId: cid });
        break;
      }
      case 'call_answer': {
        const { to, sdp, callId } = msg;
        if (!ws.userId || !to || !sdp) return;
        const cid = callId?.toString();
        clearOfferAckFallback(cid);
        clearPendingOffer(ws.userId, { callId: cid, callerId: to });
        sendToUser(to, { type: 'call_answer', from: ws.userId, sdp, callId: callId ?? null });
        break;
      }
      case 'call_ice': {
        const { to, candidate, callId } = msg;
        if (!ws.userId || !to || !candidate) return;
        sendToUser(to, { type: 'call_ice',    from: ws.userId, candidate, callId: callId ?? null });
        break;
      }
      case 'call_reject': {
        const { to, callId } = msg;
        if (!ws.userId || !to) return;
        const cid = callId?.toString();
        clearOfferAckFallback(cid);
        clearPendingOffer(to, { callId: cid, callerId: ws.userId });

        const myPending = pendingCalls.get(ws.userId);
        if (
          myPending &&
          myPending.callerId === to &&
          (!cid || myPending.offer?.callId?.toString() === cid)
        ) {
          pendingCalls.delete(ws.userId);
          sendCancelCallFcm(to); // tell caller device the call was rejected
        }
        sendToUser(to, { type: 'call_reject', from: ws.userId, callId: callId ?? null });
        break;
      }
      case 'call_end': {
        const { to, callId } = msg;
        if (!ws.userId || !to) return;
        const cid = callId?.toString();
        clearOfferAckFallback(cid);
        // If callee was offline and caller hung up, cancel the FCM notification
        const theirPending = pendingCalls.get(to);
        if (
          theirPending &&
          theirPending.callerId === ws.userId &&
          (!cid || theirPending.offer?.callId?.toString() === cid)
        ) {
          pendingCalls.delete(to);
          sendCancelCallFcm(to);
        }
        sendToUser(to, { type: 'call_end', from: ws.userId, callId: callId ?? null });
        break;
      }

      // ── register_voip_token ────────────────────────────────────────────────
      // Client sends: { type:'register_voip_token', token }
      // iOS only. Persists the PushKit VoIP token so the server can send an
      // APNs VoIP push to wake the app when it is killed.
      case 'register_voip_token': {
        const { token: voipToken } = msg;
        if (!ws.userId || !voipToken || typeof voipToken !== 'string') return;
        getVoipTokenModel()
          .then((VoipToken) =>
            VoipToken.findOneAndUpdate(
              { userId: ws.userId },
              { token: voipToken },
              { upsert: true, new: true }
            )
          )
          .then(() => console.log(`[WS] VoIP token saved for ${ws.userId}`))
          .catch((e) => console.warn('[WS] VoIP token save failed:', e.message));
        break;
      }

      // ── register_fcm_token ─────────────────────────────────────────────────
      // Client sends: { type:'register_fcm_token', token }
      // Persists or updates the FCM token for this user so the server can push
      // an incoming-call notification when the user is offline.
      case 'register_fcm_token': {
        const { token: fcmToken } = msg;
        if (!ws.userId || !fcmToken || typeof fcmToken !== 'string') return;
        getFcmTokenModel()
          .then((FcmToken) =>
            FcmToken.findOneAndUpdate(
              { userId: ws.userId },
              { token: fcmToken },
              { upsert: true, new: true }
            )
          )
          .then(() => console.log(`[WS] FCM token saved for ${ws.userId}`))
          .catch((e) => console.warn('[WS] FCM token save failed:', e.message));
        break;
      }

      // ── delete_message ─────────────────────────────────────────────────
      // Client sends: { type:'delete_message', id, everyone: bool }
      case 'delete_message': {
        const { id: delId, everyone } = msg;
        if (!ws.userId || !delId) return;
        if (!isValidOid(delId)) return;

        try {
          const Message = await getMessageModel();
          const myOid = new mongoose.Types.ObjectId(ws.userId);
          const doc = await Message.findOne({
            _id: new mongoose.Types.ObjectId(delId),
            $or: [{ userID: myOid }, { targetUserID: myOid }],
          }).lean();

          if (!doc) return;

          const partnerId = doc.userID.toString() === ws.userId
            ? doc.targetUserID.toString()
            : doc.userID.toString();

          if (everyone) {
            if (doc.userID.toString() !== ws.userId) {
              trySend(ws, { type: 'error', message: 'Only sender can delete for everyone' });
              return;
            }
            await Message.findByIdAndUpdate(delId, {
              $set: { isDeleted: true, message: 'This message was deleted' },
            });
            const payload = { type: 'message_deleted', id: delId, everyone: true };
            trySend(ws, payload);
            sendToUser(partnerId, payload);
          } else {
            await Message.findByIdAndUpdate(delId, {
              $addToSet: { deletedByID: myOid },
            });
            trySend(ws, { type: 'message_deleted', id: delId, everyone: false });
          }
        } catch (err) {
          console.error('[WS] delete_message error:', err.message);
        }
        break;
      }
    }
  });

  ws.on('close', () => {
    clearTimeout(authTimeout);
    // Admin socket cleanup
    unregisterAdminSocket(ws);
    // Only evict if this socket is still the active one for this user
    if (ws.userId && users.get(ws.userId) === ws) {
      users.delete(ws.userId);
      console.log(`[WS] -${ws.userId} (${users.size} online)`);
      // Notify remaining connected users that this user went offline
      const offlineId = ws.userId;
      for (const otherWs of users.values()) {
        trySend(otherWs, { type: 'user_offline', userId: offlineId });
      }
    }
    // Clean up typing timers originating from this user
    if (ws.userId) {
      for (const [key, timer] of typingTimers) {
        if (key.startsWith(`${ws.userId}:`)) {
          clearTimeout(timer);
          typingTimers.delete(key);
        }
      }
    }
  });

  ws.on('error', (err) => console.error('[WS] socket error:', err.message));
});

// ── Heartbeat — evict zombie connections ──────────────────────────────────────
const heartbeatInterval = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) {
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    ws.ping();
  }
}, 30_000);

wss.on('close', () => clearInterval(heartbeatInterval));

// ── Start ─────────────────────────────────────────────────────────────────────
http.listen(parseInt(WS_PORT, 10), () => {
  console.log(`[WS] ✓ Server started`);
  console.log(`[WS] ✓ Listening on port ${WS_PORT} → ws://0.0.0.0:${WS_PORT}`);
  console.log(`[WS] ✓ Health: http://localhost:${WS_PORT}/health`);
});

// ── Graceful shutdown ─────────────────────────────────────────────────────────
async function shutdown(signal) {
  console.log(`[WS] ${signal} received — shutting down gracefully`);
  clearInterval(heartbeatInterval);
  for (const ws of wss.clients) {
    trySend(ws, { type: 'error', message: 'Server shutting down' });
    ws.terminate();
  }
  wss.close();
  await mongoose.disconnect().catch(() => {});
  process.exit(0);
}

process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
