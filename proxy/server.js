const path = require("path");
const http = require("http");
const net = require("net");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const WebSocket = require("ws");

const HTTP_PORT = process.env.HTTP_PORT || 3000;
const WS_PORT = process.env.WS_PORT || 8080;
const TCP_HOST = process.env.TCP_HOST || "127.0.0.1";
const TCP_PORT = Number(process.env.TCP_PORT || 9000);

const MAX_PAYLOAD = 1024 * 1024; // 1MB
const MAX_WS_QUEUE = 2 * 1024 * 1024; // 2MB
const WS_BACKPRESSURE_HIGH = 2 * 1024 * 1024;
const WS_BACKPRESSURE_LOW = 512 * 1024;
const DATA_DIR = path.join(__dirname, "..", "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const PASSWORD_ITERATIONS = 100000;
const PASSWORD_MIN_LENGTH = 8;

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

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

const httpServer = http.createServer(app);
httpServer.listen(HTTP_PORT, () => {
  console.log(`[http] listening on http://localhost:${HTTP_PORT}`);
});

const wss = new WebSocket.Server({ port: WS_PORT });
console.log(`[ws] listening on ws://localhost:${WS_PORT}`);

wss.on("connection", (ws, req) => {
  const remote = req.socket.remoteAddress;
  console.log(`[ws] connected from ${remote}`);

  const tcp = net.connect({ host: TCP_HOST, port: TCP_PORT });
  let tcpBuffer = Buffer.alloc(0);
  let wsQueue = [];
  let wsQueueBytes = 0;
  let tcpClosed = false;
  let wsPaused = false;

  const closeBoth = (reason) => {
    if (reason) console.log(`[bridge] closing: ${reason}`);
    if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
      try {
        ws.close();
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
        closeBoth(`tcp frame too large (${frameLen})`);
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
  };

  tcp.on("drain", flushWsQueue);

  tcp.on("error", (err) => {
    console.log(`[tcp] error: ${err.message}`);
    closeBoth("tcp error");
  });

  tcp.on("close", () => {
    tcpClosed = true;
    console.log("[tcp] disconnected");
    closeBoth("tcp closed");
  });

  ws.on("message", (data) => {
    const payload = Buffer.isBuffer(data) ? data : Buffer.from(String(data), "utf8");

    if (payload.length > MAX_PAYLOAD) {
      closeBoth(`ws message too large (${payload.length})`);
      return;
    }

    const frame = Buffer.allocUnsafe(4 + payload.length);
    frame.writeUInt32BE(payload.length, 0);
    payload.copy(frame, 4);

    const ok = tcp.write(frame);
    if (!ok) {
      wsQueueBytes += frame.length;
      wsQueue.push({ buffer: frame });
      if (wsQueueBytes > MAX_WS_QUEUE) {
        closeBoth("ws->tcp queue overflow");
      }
    }
  });

  ws.on("close", () => {
    console.log("[ws] disconnected");
    closeBoth("ws closed");
  });

  ws.on("error", (err) => {
    console.log(`[ws] error: ${err.message}`);
    closeBoth("ws error");
  });

  ws.on("pong", resumeIfPossible);

  ws.on("ping", () => {
    try {
      ws.pong();
    } catch (_) {}
  });

  ws.on("open", resumeIfPossible);

  ws.once("close", () => clearInterval(resumeTimer));
});

process.on("SIGINT", () => {
  console.log("\n[system] shutting down");
  httpServer.close();
  wss.close();
  process.exit(0);
});
