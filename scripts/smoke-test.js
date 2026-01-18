const fs = require("fs");
const path = require("path");
const net = require("net");
const WebSocket = require("ws");

const root = path.resolve(__dirname, "..");

const requiredFiles = [
  "proxy/server.js",
  "public/app.js",
  "public/index.html",
  "public/style.css",
  "public/js/protocol/signaling.js",
  "public/js/audio_alerts.js",
  "public/js/call_fsm.js",
  "public/js/webrtc_call.js",
  "public/js/crypto/key-exchange.js",
  "public/js/e2ee/e2ee.js",
  "public/js/e2ee/transform-worker.js",
];

const checks = [];
const warnings = [];

const checkFileExists = (relPath) => {
  const fullPath = path.join(root, relPath);
  const ok = fs.existsSync(fullPath);
  checks.push({ ok, label: `exists: ${relPath}` });
  return ok;
};

const checkContains = (relPath, needle, label) => {
  const fullPath = path.join(root, relPath);
  if (!fs.existsSync(fullPath)) {
    checks.push({ ok: false, label: `missing: ${relPath}` });
    return;
  }
  const text = fs.readFileSync(fullPath, "utf8");
  checks.push({ ok: text.includes(needle), label });
};

const warn = (label) => {
  warnings.push(label);
};

const checkEnv = () => {
  const certPath = process.env.CERT_PATH;
  const keyPath = process.env.KEY_PATH;
  if ((certPath && !keyPath) || (!certPath && keyPath)) {
    checks.push({ ok: false, label: "CERT_PATH and KEY_PATH must be set together" });
  }
  if (certPath && keyPath) {
    checks.push({ ok: fs.existsSync(certPath), label: `CERT_PATH exists: ${certPath}` });
    checks.push({ ok: fs.existsSync(keyPath), label: `KEY_PATH exists: ${keyPath}` });
  }

  const turnUrl = process.env.TURN_URL;
  const turnUser = process.env.TURN_USER;
  const turnPass = process.env.TURN_PASS;
  if (turnUrl) {
    checks.push({ ok: Boolean(turnUser), label: "TURN_USER is set when TURN_URL is set" });
    checks.push({ ok: Boolean(turnPass), label: "TURN_PASS is set when TURN_URL is set" });
  }

  const voiceLimit = process.env.VOICE_LIMIT;
  if (voiceLimit) {
    const num = Number(voiceLimit);
    const ok = Number.isFinite(num) && num >= 2 && num <= 20;
    checks.push({ ok, label: "VOICE_LIMIT is a number between 2 and 20" });
  }

  const wsPort = process.env.WS_PORT;
  if (wsPort) {
    const num = Number(wsPort);
    const ok = Number.isFinite(num) && num > 0 && num <= 65535;
    checks.push({ ok, label: "WS_PORT is a valid port" });
  }

  const httpPort = process.env.HTTP_PORT;
  if (httpPort) {
    const num = Number(httpPort);
    const ok = Number.isFinite(num) && num > 0 && num <= 65535;
    checks.push({ ok, label: "HTTP_PORT is a valid port" });
  }

  if (!turnUrl) {
    warn("TURN_URL not set (TURN optional for NAT traversal).");
  }
  if (!certPath && !keyPath) {
    warn("CERT_PATH/KEY_PATH not set (HTTPS optional in local dev).");
  }
};

requiredFiles.forEach(checkFileExists);
checkEnv();

checkContains("proxy/server.js", "voice:join", "proxy has voice signaling types");
checkContains("proxy/server.js", "call:invite", "proxy has call signaling types");
checkContains("proxy/server.js", "/config.js", "proxy serves /config.js");
checkContains("public/index.html", "/js/audio_alerts.js", "index loads audio_alerts.js");
checkContains("public/index.html", "/js/e2ee/e2ee.js", "index loads e2ee.js");
checkContains("public/app.js", "handleSignal", "client has handleSignal");
checkContains("public/app.js", "CallFSM.create", "client uses call FSM");

const checkTcpReachability = async () => {
  if (process.env.SMOKE_CHECK_TCP !== "1") return;
  const host = process.env.TCP_HOST || "127.0.0.1";
  const port = Number(process.env.TCP_PORT || 9000);
  if (!Number.isFinite(port)) {
    checks.push({ ok: false, label: "TCP_PORT is a valid port" });
    return;
  }
  const label = `TCP reachable: ${host}:${port}`;
  await new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      checks.push({ ok: false, label });
      resolve();
    }, 2000);
    socket.on("connect", () => {
      clearTimeout(timer);
      socket.end();
      checks.push({ ok: true, label });
      resolve();
    });
    socket.on("error", () => {
      clearTimeout(timer);
      checks.push({ ok: false, label });
      resolve();
    });
  });
};

const checkWsReachability = async () => {
  if (process.env.SMOKE_CHECK_WS !== "1") return;
  const host = process.env.SMOKE_WS_HOST || process.env.WS_HOST || "127.0.0.1";
  let port = Number(process.env.SMOKE_WS_PORT || process.env.WS_PORT || 8080);
  if (process.env.CERT_PATH && process.env.KEY_PATH) {
    port = Number(process.env.HTTP_PORT || 3000);
  }
  if (!Number.isFinite(port)) {
    checks.push({ ok: false, label: "WS_PORT is a valid port" });
    return;
  }
  const label = `WS port reachable: ${host}:${port}`;
  await new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      checks.push({ ok: false, label });
      resolve();
    }, 2000);
    socket.on("connect", () => {
      clearTimeout(timer);
      socket.end();
      checks.push({ ok: true, label });
      resolve();
    });
    socket.on("error", () => {
      clearTimeout(timer);
      checks.push({ ok: false, label });
      resolve();
    });
  });
};

const checkWsHandshake = async () => {
  if (process.env.SMOKE_CHECK_WS_HANDSHAKE !== "1") return;
  const host = process.env.SMOKE_WS_HOST || process.env.WS_HOST || "127.0.0.1";
  let port = Number(process.env.SMOKE_WS_PORT || process.env.WS_PORT || 8080);
  const isSecure = Boolean(process.env.CERT_PATH && process.env.KEY_PATH);
  if (isSecure) {
    port = Number(process.env.HTTP_PORT || 3000);
  }
  if (!Number.isFinite(port)) {
    checks.push({ ok: false, label: "WS_PORT is a valid port" });
    return;
  }
  const proto = isSecure ? "wss" : "ws";
  const url = `${proto}://${host}:${port}`;
  const label = `WS handshake: ${url}`;
  await new Promise((resolve) => {
    const ws = new WebSocket(url, { handshakeTimeout: 2000 });
    const timer = setTimeout(() => {
      ws.terminate();
      checks.push({ ok: false, label });
      resolve();
    }, 2500);
    ws.on("open", () => {
      clearTimeout(timer);
      ws.close();
      checks.push({ ok: true, label });
      resolve();
    });
    ws.on("error", () => {
      clearTimeout(timer);
      checks.push({ ok: false, label });
      resolve();
    });
  });
};

const main = async () => {
  await checkTcpReachability();
  await checkWsReachability();
  await checkWsHandshake();
  const strict = process.env.SMOKE_STRICT === "1";
  let failures = checks.filter((c) => !c.ok);
  checks.forEach((check) => {
    const mark = check.ok ? "OK " : "FAIL";
    console.log(`${mark} ${check.label}`);
  });

  if (warnings.length) {
    console.log("");
    warnings.forEach((warning) => console.log(`WARN ${warning}`));
  }

  if (strict && warnings.length) {
    failures = failures.concat(warnings.map((label) => ({ ok: false, label: `WARN as error: ${label}` })));
  }

  if (failures.length) {
    console.error(`\nSmoke test failed: ${failures.length} issue(s).`);
    process.exit(1);
  }

  console.log("\nSmoke test passed.");
};

main();
