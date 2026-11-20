const test = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const net = require("node:net");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const WS = require("ws");
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
const listen = async (server) => { server.listen(0, "127.0.0.1"); await once(server, "listening"); return server.address().port; };
const freePort = async () => { const server = net.createServer(); const port = await listen(server); await new Promise((r) => server.close(r)); return port; };
const waitFor = async (predicate) => {
  for (let i = 0; i < 100; i++) { const result = predicate(); if (result) return result; await delay(20); }
  throw new Error("Timed out waiting for signaling state");
};

test("real proxy: config parity, contested floor, stale membership, leave and disconnect", { timeout: 15000 }, async (t) => {
  fs.mkdirSync(".tmp", { recursive: true });
  const data = fs.mkdtempSync(path.resolve(".tmp", "proxy-test-"));
  const tcpSockets = new Set();
  const tcp = net.createServer((socket) => { tcpSockets.add(socket); socket.on("data", () => {}); });
  const tcpPort = await listen(tcp), httpPort = await freePort(), wsPort = await freePort();
  const child = spawn(process.execPath, ["proxy/server.js"], { env: { ...process.env,
    CHAT_DATA_DIR: data, HTTP_PORT: String(httpPort), WS_PORT: String(wsPort), TCP_PORT: String(tcpPort), TCP_HOST: "127.0.0.1",
    CERT_PATH: "", KEY_PATH: "", TURN_URL: "turn:localhost", TURN_SECRET: "synthetic-test-secret", VOICE_LIMIT: "7", ICE_TRANSPORT_POLICY: "relay", WS_HEARTBEAT_MS: "100" }, stdio: "ignore" });
  const clients = [];
  t.after(async () => { for (const c of clients) c.ws.terminate(); child.kill(); for (const s of tcpSockets) s.destroy(); tcp.close(); });
  const url = `http://localhost:${httpPort}`;
  for (let i = 0; i < 100; i++) { try { if ((await fetch(url)).ok) break; } catch (_) {} await delay(30); }
  const jsonResponse = await fetch(`${url}/config.json`);
  const config = await jsonResponse.json();
  const jsResponse = await fetch(`${url}/config.js`);
  const sandbox = { window: {} }; vm.runInNewContext(await jsResponse.text(), sandbox);
  assert.equal(jsonResponse.headers.get("cache-control"), "no-store");
  assert.equal(jsResponse.headers.get("cache-control"), "no-store");
  assert.deepEqual(JSON.parse(JSON.stringify(sandbox.window.__APP_CONFIG__)), config);
  assert.equal(config.voiceLimit, 7);
  const connect = async (id, membershipId = id + "-1", autoPong = true) => {
    // Exercise the same-origin HTTP /ws upgrade, not only the legacy port.
    const ws = new WS(`ws://localhost:${httpPort}/ws`, { autoPong });
    const messages = [];
    ws.on("message", (data) => { try { messages.push(JSON.parse(data.toString())); } catch (_) {} });
    await once(ws, "open");
    ws.send(id);
    const c = { ws, messages, id, membershipId, room: "room-a" };
    c.send = (type, payload = {}, room = c.room, member = c.membershipId) => ws.send(JSON.stringify({ type, from: id, room, membershipId: member, payload }));
    c.last = () => messages.filter((m) => m.payload?.participants).at(-1);
    clients.push(c); return c;
  };
  const join = async (c) => { c.send("voice:join", { membershipId: c.membershipId }); await waitFor(() => c.last()); };
  const a = await connect("alice"), b = await connect("bob");
  await join(a); await join(b);
  a.send("voice:floor:take"); b.send("voice:floor:take");
  await waitFor(() => a.last()?.payload.floorOwner && b.last()?.payload.floorOwner);
  assert.equal(a.last().payload.floorOwner, b.last().payload.floorOwner);
  assert.ok(a.last().payload.floorRemainingMs > 0 && a.last().payload.floorRemainingMs <= 60000);
  const expiresAt = a.last().payload.floorExpiresAt;
  assert.equal(expiresAt, b.last().payload.floorExpiresAt);
  const owner = a.last().payload.floorOwner === "alice" ? a : b;
  const listener = owner === a ? b : a;
  assert.equal(listener.last().payload.participants.find((p) => p.id === listener.id).muted, true);
  const beforeContestedTake = listener.messages.length;
  listener.send("voice:floor:take");
  await waitFor(() => listener.messages.length > beforeContestedTake);
  assert.equal(listener.last().payload.floorOwner, owner.id, "loser receives authoritative state");
  assert.equal(listener.last().payload.floorExpiresAt, expiresAt, "contested take cannot restart the timer");
  const previous = listener.messages.length;
  listener.send("voice:floor:release");
  await waitFor(() => listener.messages.length > previous);
  assert.equal(listener.last().payload.floorOwner, owner.id);
  owner.send("voice:floor:release", {}, "room-other");
  owner.send("voice:floor:release", {}, owner.room, "previous-membership");
  const beforeWho = owner.messages.length;
  owner.send("voice:who"); await waitFor(() => owner.messages.length > beforeWho);
  assert.equal(owner.last().payload.floorOwner, owner.id);
  owner.send("voice:leave");
  await waitFor(() => listener.last()?.payload.floorOwner === null);
  assert.equal(listener.last().payload.floorExpiresAt, null);
  owner.membershipId += "-new"; owner.messages.length = 0; await join(owner);
  owner.send("voice:floor:take"); await waitFor(() => listener.last()?.payload.floorOwner === owner.id);
  owner.ws.close(); await once(owner.ws, "close");
  await waitFor(() => listener.last()?.payload.floorOwner === null);
  const again = await connect(owner.id, "reconnected"); await join(again);
  assert.equal(again.last().payload.floorOwner, null);
  assert.equal(again.last().membershipId, "reconnected");
  const ghost = await connect("lost-network", "ghost-1", false);
  await join(ghost); ghost.send("voice:floor:take");
  await waitFor(() => listener.last()?.payload.floorOwner === ghost.id);
  await waitFor(() => ghost.ws.readyState === WS.CLOSED);
  await waitFor(() => listener.last()?.payload.floorOwner === null);
});
