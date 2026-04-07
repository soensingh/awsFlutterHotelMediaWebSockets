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

// ── Config ────────────────────────────────────────────────────────────────────
const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, '../hotelmedia/.env') });

const {
  JWT_SECRET_MOBILE:  JWT_SECRET,
  JWT_ISSUER_MOBILE:  JWT_ISSUER,
  JWT_AUDIENCE_MOBILE: JWT_AUDIENCE,
  MONGODB_URI,
  MONGODB_DB,
  WS_PORT = '3001',
  WS_NOTIFY_SECRET,
} = process.env;

if (!JWT_SECRET) { console.error('[WS] JWT_SECRET_MOBILE missing'); process.exit(1); }
if (!MONGODB_URI) { console.error('[WS] MONGODB_URI missing');        process.exit(1); }
if (!MONGODB_DB)  { console.error('[WS] MONGODB_DB missing');         process.exit(1); }

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
      message:      { type: String,  default: '' },
      isSeen:       { type: Boolean, default: false },
      deletedByID:  [mongoose.Schema.Types.ObjectId],
      userID:       { type: mongoose.Schema.Types.ObjectId, required: true },
      targetUserID: { type: mongoose.Schema.Types.ObjectId, required: true },
      type:         { type: String,  default: 'text' },
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
 * Serializes a Mongoose doc for a specific viewer so isFromMe is correct.
 */
function serializeMsg(doc, viewerUserId) {
  return {
    id:        doc._id.toString(),
    senderId:  doc.userID.toString(),
    targetId:  doc.targetUserID.toString(),
    message:   doc.message,
    type:      doc.type ?? 'text',
    isSeen:    doc.isSeen ?? false,
    isFromMe:  doc.userID.toString() === viewerUserId,
    createdAt: (doc.createdAt ?? new Date()).toISOString(),
  };
}

function isValidOid(id) {
  return mongoose.Types.ObjectId.isValid(id);
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

        console.log(`[WS] +${uid} (${users.size} online)`);
        break;
      }

      // ── ping ───────────────────────────────────────────────────────────
      case 'ping': {
        trySend(ws, { type: 'pong' });
        break;
      }

      // ── message ────────────────────────────────────────────────────────
      case 'message': {
        const { to, message: text, tempId } = msg;
        if (!ws.userId || !to || !text?.trim()) return;
        if (!isValidOid(to)) return;

        try {
          const Message = await getMessageModel();
          const doc = await Message.create({
            userID:       new mongoose.Types.ObjectId(ws.userId),
            targetUserID: new mongoose.Types.ObjectId(to),
            message:      text.trim(),
            type:         'text',
            isSeen:       false,
          });

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
