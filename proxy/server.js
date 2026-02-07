const path = require("path");
const http = require("http");
const https = require("https");
const net = require("net");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const WebSocket = require("ws");

const HTTP_PORT = process.env.HTTP_PORT || 3000;
const WS_PORT = process.env.WS_PORT || 8080;
const CERT_PATH = process.env.CERT_PATH;
const KEY_PATH = process.env.KEY_PATH;
const TCP_HOST = process.env.TCP_HOST || "127.0.0.1";
const TCP_PORT = Number(process.env.TCP_PORT || 9000);

const MAX_PAYLOAD = 12 * 1024 * 1024; // 12MB
const MAX_WS_QUEUE = 16 * 1024 * 1024; // 16MB
const WS_BACKPRESSURE_HIGH = 2 * 1024 * 1024;
const WS_BACKPRESSURE_LOW = 512 * 1024;
const DATA_DIR = path.join(__dirname, "..", "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const PASSWORD_ITERATIONS = 100000;
const PASSWORD_MIN_LENGTH = 8;

const app = express();// --- TURN REST config endpoint ---

function buildTurnConfig() {
  const secret = process.env.TURN_SECRET || "";
  if (!secret) return null;

  // TTL для кредов (сек). Обычно 1-6 часов.
  const ttlSeconds = 6 * 60 * 60;
  const username = `${Math.floor(Date.now() / 1000) + ttlSeconds}:coroutine-chat`;
  const credential = crypto.createHmac("sha1", secret).update(username).digest("base64");

  return {
    urls: [
      "turn:coroutine-chat.ru:3478?transport=udp",
      "turn:coroutine-chat.ru:3478?transport=tcp",
      "turns:coroutine-chat.ru:5349?transport=tcp",
    ],
    username,
    credential,
  };
}

// Вернём весь __APP_CONFIG__ как JSON
app.get("/config.json", (req, res) => {
  const turn = buildTurnConfig();
  res.setHeader("Cache-Control", "no-store");
  res.json({
    turn, // если secret не задан, будет null
  });
});

app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

app.get("/config.js", (req, res) => {
  res.type("application/javascript");
  const config = {
    turn: process.env.TURN_URL
      ? {
          urls: process.env.TURN_URL,
          username: process.env.TURN_USER || "",
          credential: process.env.TURN_PASS || "",
        }
      : null,
    voiceLimit: Number(process.env.VOICE_LIMIT || 6),
  };
  res.send(`window.__APP_CONFIG__ = ${JSON.stringify(config)};`);
});

fs.mkdirSync(DATA_DIR, { recursive: true });

const loadJson = (file, fallback) => {
  try {
    const raw = fs.readFileSync(file, "utf8");
    return JSON.parse(raw);
  } catch (_) {
    return fallback;
  }
};

let users = loadJson(USERS_FILE, {});
let sessions = loadJson(SESSIONS_FILE, {});
let writeQueue = Promise.resolve();

const queueWrite = (file, data) => {
  writeQueue = writeQueue
    .then(() => fs.promises.writeFile(file, JSON.stringify(data, null, 2)))
    .catch((err) => console.error(`[store] write error: ${err.message}`));
};

const now = Date.now();
let sessionsChanged = false;
Object.keys(sessions).forEach((token) => {
  if (!sessions[token] || sessions[token].expiresAt < now) {
    delete sessions[token];
    sessionsChanged = true;
  }
});
if (sessionsChanged) {
  queueWrite(SESSIONS_FILE, sessions);
}

const isValidUsername = (username) => {
  if (!username || typeof username !== "string") return false;
  if (username.length < 3 || username.length > 24) return false;
  return /^[A-Za-z0-9_-]+$/.test(username);
};

const passwordMeetsPolicy = (password) => {
  if (!password || typeof password !== "string") return false;
  if (password.length < PASSWORD_MIN_LENGTH) return false;
  if (!/[a-z]/.test(password)) return false;
  if (!/[A-Z]/.test(password)) return false;
  if (!/[0-9]/.test(password)) return false;
  return true;
};

const hashPassword = (password, salt) => {
  const hash = crypto.pbkdf2Sync(password, salt, PASSWORD_ITERATIONS, 32, "sha256");
  return hash.toString("hex");
};

const createSession = (username) => {
  const token = crypto.randomBytes(24).toString("hex");
  sessions[token] = {
    username,
    expiresAt: Date.now() + SESSION_TTL_MS,
  };
  queueWrite(SESSIONS_FILE, sessions);
  return token;
};

const getToken = (req) => {
  const auth = req.headers.authorization || "";
  if (auth.startsWith("Bearer ")) {
    return auth.slice(7).trim();
  }
  return req.headers["x-auth-token"];
};

const requireAuth = (req, res, next) => {
  const token = getToken(req);
  if (!token || !sessions[token]) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  const session = sessions[token];
  if (session.expiresAt < Date.now()) {
    delete sessions[token];
    queueWrite(SESSIONS_FILE, sessions);
    res.status(401).json({ error: "expired" });
    return;
  }
  req.user = session.username;
  req.token = token;
  next();
};

app.post("/api/register", (req, res) => {
  const { username, password } = req.body || {};
  if (!isValidUsername(username)) {
    res.status(400).json({ error: "invalid_username" });
    return;
  }
  if (!passwordMeetsPolicy(password)) {
    res.status(400).json({ error: "weak_password" });
    return;
  }
  if (users[username]) {
    res.status(409).json({ error: "user_exists" });
    return;
  }
  const salt = crypto.randomBytes(16).toString("hex");
  users[username] = {
    salt,
    hash: hashPassword(password, salt),
    iterations: PASSWORD_ITERATIONS,
    createdAt: Date.now(),
  };
  queueWrite(USERS_FILE, users);
  const token = createSession(username);
  res.json({ token, username });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  const record = users[username];
  if (!record) {
    res.status(401).json({ error: "invalid_credentials" });
    return;
  }
  const hash = hashPassword(password, record.salt);
  if (hash !== record.hash) {
    res.status(401).json({ error: "invalid_credentials" });
    return;
  }
  const token = createSession(username);
  res.json({ token, username });
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ username: req.user });
});

app.post("/api/logout", requireAuth, (req, res) => {
  delete sessions[req.token];
  queueWrite(SESSIONS_FILE, sessions);
  res.json({ ok: true });
});

const isHttps = Boolean(CERT_PATH && KEY_PATH);
const serverOptions = isHttps
  ? {
      cert: fs.readFileSync(CERT_PATH),
      key: fs.readFileSync(KEY_PATH),
    }
  : null;
const httpServer = isHttps ? https.createServer(serverOptions, app) : http.createServer(app);
httpServer.listen(HTTP_PORT, () => {
  const proto = isHttps ? "https" : "http";
  console.log(`[http] listening on ${proto}://localhost:${HTTP_PORT}`);
});

const wss = isHttps
  ? new WebSocket.Server({ server: httpServer, maxPayload: MAX_PAYLOAD })
  : new WebSocket.Server({ port: WS_PORT, maxPayload: MAX_PAYLOAD });
if (isHttps) {
  console.log(`[ws] listening on wss://localhost:${HTTP_PORT}`);
} else {
  console.log(`[ws] listening on ws://localhost:${WS_PORT}`);
}

const DEFAULT_ROOM = "global";
const SIGNAL_TYPES = new Set([
  "voice:join",
  "voice:leave",
  "voice:who",
  "voice:state",
  "webrtc:offer",
  "webrtc:answer",
  "webrtc:ice",
  "call:invite",
  "call:ringing",
  "call:accept",
  "call:reject",
  "call:cancel",
  "call:hangup",
  "e2ee:pubkey",
  "e2ee:key",
  "e2ee:ready",
  "e2ee:go",
  "e2ee:go_ack",
  "e2ee:enabled",
  "e2ee:disabled",
]);

const clientsById = new Map();
const clientInfo = new WeakMap();
const voiceRooms = new Map();
const callSessions = new Map();
const inviteRate = new Map();

const ensureRoom = (room) => {
  if (!voiceRooms.has(room)) {
    voiceRooms.set(room, new Map());
  }
  return voiceRooms.get(room);
};

const sendJson = (ws, payload) => {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify(payload));
};

const broadcastRoom = (room, payload, excludeId = null) => {
  const roster = voiceRooms.get(room);
  if (!roster) return;
  for (const [id] of roster) {
    if (excludeId && id === excludeId) continue;
    const peer = clientsById.get(id);
    if (peer) sendJson(peer, payload);
  }
};

const validateSignal = (msg, wsId) => {
  if (!msg || typeof msg !== "object") return { ok: false, reason: "invalid" };
  if (!SIGNAL_TYPES.has(msg.type)) return { ok: false, reason: "unknown_type" };
  if (!msg.from || typeof msg.from !== "string") return { ok: false, reason: "missing_from" };
  if (wsId && msg.from !== wsId) return { ok: false, reason: "spoofed_from" };
  if (msg.to && typeof msg.to !== "string") return { ok: false, reason: "invalid_to" };
  if (msg.room && typeof msg.room !== "string") return { ok: false, reason: "invalid_room" };
  if (msg.payload && typeof msg.payload !== "object") return { ok: false, reason: "invalid_payload" };
  return { ok: true };
};

const rateLimitInvite = (id) => {
  const now = Date.now();
  let state = inviteRate.get(id);
  if (!state) {
    state = { last: 0, window: [] };
    inviteRate.set(id, state);
  }
  if (now - state.last < 2000) return false;
  state.window = state.window.filter((ts) => now - ts < 10000);
  if (state.window.length >= 3) return false;
  state.last = now;
  state.window.push(now);
  return true;
};

const sendReject = (fromId, toId, callId, reason) => {
  const to = clientsById.get(toId);
  if (!to) return;
  sendJson(to, {
    type: "call:reject",
    from: fromId,
    to: toId,
    payload: { callId, reason },
  });
};

wss.on("connection", (ws, req) => {
  const remote = req.socket.remoteAddress;
  console.log(`[ws] connected from ${remote}`);

  const tcp = net.connect({ host: TCP_HOST, port: TCP_PORT });
  const info = {
    id: null,
    room: DEFAULT_ROOM,
    voice: false,
  };
  clientInfo.set(ws, info);
  let tcpBuffer = Buffer.alloc(0);
  let wsQueue = [];
  let wsQueueBytes = 0;
  let tcpClosed = false;
  let wsPaused = false;
  let wsPausedOutgoing = false;

  const closeBoth = (reason, wsCode = null) => {
    if (reason) console.log(`[bridge] closing: ${reason}`);
    if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
      try {
        if (wsCode) {
          ws.close(wsCode, reason ? String(reason).slice(0, 120) : "");
        } else {
          ws.close();
        }
      } catch (_) {}
    }
    if (!tcpClosed) {
      tcpClosed = true;
      try {
        tcp.destroy();
      } catch (_) {}
    }
  };

  tcp.on("connect", () => {
    console.log(`[tcp] connected to ${TCP_HOST}:${TCP_PORT}`);
  });

  tcp.on("data", (chunk) => {
    tcpBuffer = Buffer.concat([tcpBuffer, chunk]);

    while (tcpBuffer.length >= 4) {
      const frameLen = tcpBuffer.readUInt32BE(0);
      if (frameLen > MAX_PAYLOAD) {
        closeBoth(`tcp frame too large (${frameLen})`, 1009);
        return;
      }
      if (tcpBuffer.length < 4 + frameLen) {
        break;
      }

      const payload = tcpBuffer.slice(4, 4 + frameLen);
      tcpBuffer = tcpBuffer.slice(4 + frameLen);

      if (ws.readyState !== WebSocket.OPEN) {
        closeBoth("ws not open");
        return;
      }

      ws.send(payload.toString("utf8"), (err) => {
        if (err) {
          closeBoth(`ws send error: ${err.message}`);
        }
      });

      if (!wsPaused && ws.bufferedAmount > WS_BACKPRESSURE_HIGH) {
        wsPaused = true;
        tcp.pause();
      }
    }
  });

  const resumeIfPossible = () => {
    if (wsPaused && ws.bufferedAmount < WS_BACKPRESSURE_LOW) {
      wsPaused = false;
      tcp.resume();
    }
  };

  const resumeTimer = setInterval(resumeIfPossible, 200);

  const flushWsQueue = () => {
    while (wsQueue.length > 0) {
      const { buffer } = wsQueue[0];
      const ok = tcp.write(buffer);
      wsQueueBytes -= buffer.length;
      wsQueue.shift();
      if (!ok) return;
    }
    if (wsPausedOutgoing && wsQueueBytes < MAX_WS_QUEUE / 2) {
      wsPausedOutgoing = false;
      ws.resume();
    }
  };

  tcp.on("drain", flushWsQueue);

  tcp.on("error", (err) => {
    console.log(`[tcp] error: ${err.message}`);
    closeBoth("tcp error", 1011);
  });

  tcp.on("close", () => {
    tcpClosed = true;
    console.log("[tcp] disconnected");
    closeBoth("tcp closed", 1011);
  });

  ws.on("message", (data) => {
    const payload = Buffer.isBuffer(data) ? data : Buffer.from(String(data), "utf8");

    if (payload.length > MAX_PAYLOAD) {
      closeBoth(`ws message too large (${payload.length})`, 1009);
      return;
    }

    const text = payload.toString("utf8");
    let parsed = null;
    if (text && text[0] === "{") {
      try {
        parsed = JSON.parse(text);
      } catch (_) {
        parsed = null;
      }
    }

    if (parsed && SIGNAL_TYPES.has(parsed.type)) {
      const wsId = info.id;
      if (!wsId) {
        console.log("[signal] message before identity");
        return;
      }
      const validation = validateSignal(parsed, wsId);
      if (!validation.ok) {
        console.log(`[signal] invalid: ${validation.reason}`);
        return;
      }
      const type = parsed.type;
      const room = parsed.room || DEFAULT_ROOM;
      const from = parsed.from;
      const to = parsed.to;

      if (type === "voice:who") {
        const roster = voiceRooms.get(room);
        const participants = roster
          ? Array.from(roster.entries()).map(([id, state]) => ({
              id,
              muted: Boolean(state.muted),
              speaking: Boolean(state.speaking),
            }))
          : [];
        sendJson(ws, {
          type: "voice:state",
          room,
          from: "server",
          payload: { participants },
        });
        return;
      }

      if (type === "voice:join") {
        const roster = ensureRoom(room);
        roster.set(from, {
          muted: Boolean(parsed.payload && parsed.payload.muted),
          speaking: Boolean(parsed.payload && parsed.payload.speaking),
        });
        info.voice = true;
        info.room = room;
        sendJson(ws, {
          type: "voice:state",
          room,
          from: "server",
          payload: {
            participants: Array.from(roster.entries()).map(([id, state]) => ({
              id,
              muted: Boolean(state.muted),
              speaking: Boolean(state.speaking),
            })),
          },
        });
        broadcastRoom(room, { type: "voice:join", room, from }, from);
        return;
      }

      if (type === "voice:leave") {
        const roster = voiceRooms.get(room);
        if (roster) {
          roster.delete(from);
          if (roster.size === 0) voiceRooms.delete(room);
        }
        info.voice = false;
        broadcastRoom(room, { type: "voice:leave", room, from }, from);
        return;
      }

      if (type === "voice:state") {
        const roster = voiceRooms.get(room);
        if (!roster || !roster.has(from)) return;
        const state = roster.get(from);
        state.muted = Boolean(parsed.payload && parsed.payload.muted);
        state.speaking = Boolean(parsed.payload && parsed.payload.speaking);
        broadcastRoom(room, { type: "voice:state", room, from, payload: state }, from);
        return;
      }

      if (type === "call:invite") {
        if (!rateLimitInvite(from)) {
          sendReject("server", from, parsed.payload && parsed.payload.callId, "rate_limited");
          return;
        }
        if (!to || !clientsById.has(to)) {
          sendReject("server", from, parsed.payload && parsed.payload.callId, "offline");
          return;
        }
        const callId = parsed.payload && parsed.payload.callId;
        if (!callId) return;
        callSessions.set(callId, { from, to, state: "outgoing" });
        sendJson(clientsById.get(to), parsed);
        return;
      }

      if (type === "call:ringing" || type === "call:accept") {
        if (!to || !clientsById.has(to)) return;
        const callId = parsed.payload && parsed.payload.callId;
        if (!callId) return;
        if (callId && callSessions.has(callId)) {
          const call = callSessions.get(callId);
          call.state = type === "call:accept" ? "in_call" : "ringing";
        }
        sendJson(clientsById.get(to), parsed);
        return;
      }

      if (type === "call:reject" || type === "call:cancel" || type === "call:hangup") {
        if (!to || !clientsById.has(to)) {
          if (parsed.payload && parsed.payload.callId) {
            callSessions.delete(parsed.payload.callId);
          }
          return;
        }
        if (!parsed.payload || !parsed.payload.callId) return;
        if (parsed.payload && parsed.payload.callId) {
          callSessions.delete(parsed.payload.callId);
        }
        sendJson(clientsById.get(to), parsed);
        return;
      }

      if (type.startsWith("webrtc:") || type.startsWith("e2ee:")) {
        if (!to || !clientsById.has(to)) return;
        if (!parsed.payload) return;
        if (type === "webrtc:offer" || type === "webrtc:answer") {
          if (!parsed.payload.sdp) return;
        }
        if (type === "webrtc:ice" && !parsed.payload.candidate) return;
        if (type.startsWith("e2ee:") && !parsed.payload.callId) return;
        const payloadSize = JSON.stringify(parsed.payload || {}).length;
        if (type.startsWith("e2ee:") && payloadSize > 8 * 1024) {
          console.log("[signal] e2ee payload too large");
          closeBoth("e2ee payload too large", 1009);
          return;
        }
        sendJson(clientsById.get(to), parsed);
        return;
      }
    }

    if (!info.id && text && text[0] !== "{") {
      info.id = text.trim();
      if (info.id) {
        clientsById.set(info.id, ws);
      }
    }

    const frame = Buffer.allocUnsafe(4 + payload.length);
    frame.writeUInt32BE(payload.length, 0);
    payload.copy(frame, 4);

    const ok = tcp.write(frame);
    if (!ok) {
      wsQueueBytes += frame.length;
      wsQueue.push({ buffer: frame });
      if (!wsPausedOutgoing && wsQueueBytes > MAX_WS_QUEUE / 2) {
        wsPausedOutgoing = true;
        ws.pause();
      }
      if (wsQueueBytes > MAX_WS_QUEUE) {
        closeBoth("ws->tcp queue overflow", 1013);
      }
    }
  });

  ws.on("close", () => {
    console.log("[ws] disconnected");
    closeBoth("ws closed");
  });

  ws.on("error", (err) => {
    console.log(`[ws] error: ${err.message}`);
    closeBoth("ws error", 1011);
  });

  ws.on("pong", resumeIfPossible);

  ws.on("ping", () => {
    try {
      ws.pong();
    } catch (_) {}
  });

  ws.on("open", resumeIfPossible);

  ws.once("close", () => clearInterval(resumeTimer));
  ws.once("close", () => {
    const wsInfo = clientInfo.get(ws);
    if (!wsInfo || !wsInfo.id) return;
    clientsById.delete(wsInfo.id);
    if (wsInfo.voice) {
      const roster = voiceRooms.get(wsInfo.room);
      if (roster) {
        roster.delete(wsInfo.id);
        if (roster.size === 0) voiceRooms.delete(wsInfo.room);
        broadcastRoom(wsInfo.room, { type: "voice:leave", room: wsInfo.room, from: wsInfo.id }, wsInfo.id);
      }
    }
    const toHangup = [];
    for (const [callId, call] of callSessions.entries()) {
      if (call.from === wsInfo.id || call.to === wsInfo.id) {
        toHangup.push({ callId, call });
      }
    }
    toHangup.forEach(({ callId, call }) => {
      const otherId = call.from === wsInfo.id ? call.to : call.from;
      sendJson(clientsById.get(otherId), {
        type: "call:hangup",
        from: wsInfo.id,
        to: otherId,
        payload: { callId, reason: "disconnect" },
      });
      callSessions.delete(callId);
    });
  });
});

process.on("SIGINT", () => {
  console.log("\n[system] shutting down");
  httpServer.close();
  wss.close();
  process.exit(0);
});
