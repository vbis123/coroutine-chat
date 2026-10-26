const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { buildConfig } = require("../proxy/config");
const source = (name) => fs.readFileSync(`public/js/${name}.js`, "utf8");

test("TURN REST and static configuration retain voiceLimit and relay policy", () => {
  const config = buildConfig({ TURN_SECRET: "test-only", TURN_URL: "turn:localhost", VOICE_LIMIT: "9", ICE_TRANSPORT_POLICY: "relay" }, 0);
  assert.equal(config.voiceLimit, 9);
  assert.equal(config.iceTransportPolicy, "relay");
  assert.equal(config.turn.username, "21600:coroutine-chat");
  assert.ok(config.turn.credential);
  assert.equal(buildConfig({ TURN_URL: "turn:localhost", TURN_USER: "test", TURN_PASS: "test" }).turn.username, "test");
  assert.throws(() => buildConfig({ ICE_TRANSPORT_POLICY: "relay" }));
  assert.throws(() => buildConfig({ VOICE_LIMIT: "bad" }));
});

test("config readiness waits for network, handles HTTP errors visibly and never logs credentials", async () => {
  let resolve;
  let requests = 0;
  let alerts = 0;
  const sandbox = { window: {}, fetch: () => { requests++; return new Promise((r) => { resolve = r; }); },
    document: { createElement: () => ({ setAttribute() {} }), body: { prepend() { alerts++; } } } };
  vm.runInNewContext(source("config"), sandbox);
  assert.equal(sandbox.window.__APP_CONFIG__, undefined);
  resolve({ ok: true, json: async () => buildConfig({ VOICE_LIMIT: "8" }) });
  assert.equal((await sandbox.window.appConfigReady).voiceLimit, 8);
  assert.equal(requests, 1);
  vm.runInNewContext(source("config"), sandbox);
  resolve({ ok: false });
  await assert.rejects(sandbox.window.appConfigReady);
  assert.equal(alerts, 1);
});

test("floor transitions preserve explicit mute, cancel PTT and never auto-unmute listeners", () => {
  const sandbox = { window: {} };
  vm.runInNewContext(source("voice_state"), sandbox);
  const f = sandbox.window.VoiceState;
  const state = { joined: true, floorKnown: false, muted: false, room: "a", membershipId: "new" };
  assert.equal(f.muted(state, "alice"), true);
  f.setFloor(state, null, "alice");
  assert.equal(f.muted(state, "alice"), false);
  state.muted = true;
  state.pttActive = true;
  assert.equal(f.muted(state, "alice"), false);
  f.setFloor(state, "bob", "alice");
  assert.equal(state.pttActive, false);
  assert.equal(state.muted, true);
  f.setFloor(state, null, "alice");
  assert.equal(f.muted(state, "alice"), true);
  state.muted = false;
  assert.equal(f.muted(state, "alice"), true); // suppression remains until explicit action
  state.floorSuppressed = false;
  assert.equal(f.muted(state, "alice"), false);
  assert.equal(f.accepts(state, { room: "b", membershipId: "new" }), false);
  assert.equal(f.accepts(state, { room: "a", membershipId: "old" }), false);
  state.joined = false;
  assert.equal(f.accepts(state, { room: "a", membershipId: "new" }), false);
});

test("WebRTC queues early ICE, orders remote SDP before candidates, handles streamless tracks and closes", async () => {
  const events = [];
  class PC {
    constructor(config) { this.config = config; }
    async setRemoteDescription() { events.push("sdp"); }
    async addIceCandidate(candidate) { events.push(candidate); }
    close() { events.push("close"); }
  }
  const sandbox = { window: { __APP_CONFIG__: buildConfig({}) }, RTCPeerConnection: PC,
    MediaStream: class { constructor(tracks) { this.tracks = tracks; } } };
  vm.runInNewContext(source("webrtc_call"), sandbox);
  let stream;
  const connection = sandbox.window.WebRTCCall.createConnection({ onTrack: (s) => { stream = s; } });
  await connection.addIceCandidate("first");
  assert.deepEqual(events, []);
  await Promise.all([connection.setRemoteDescription({}), connection.addIceCandidate("second")]);
  assert.deepEqual(events, ["sdp", "first", "second"]);
  connection.pc.ontrack({ streams: [], track: "audio" });
  assert.equal(stream.tracks[0], "audio");
  connection.close();
  await assert.rejects(connection.setRemoteDescription({}));
});

test("E2EE frame roundtrip authenticates and rejects plaintext, corruption and wrong keys", async () => {
  const sandbox = { crypto: require("node:crypto").webcrypto, Uint8Array, self: {} };
  vm.runInNewContext(source("e2ee/transform-worker") + "\nself.codec = {importKey, encryptFrame, decryptFrame};", sandbox);
  const { importKey, encryptFrame, decryptFrame } = sandbox.self.codec;
  const key = await importKey(new Uint8Array(32));
  const wrong = await importKey(new Uint8Array(32).fill(1));
  const original = new Uint8Array([1, 2, 3, 4]).buffer;
  const encrypted = (await encryptFrame({ data: original }, key)).data;
  const decrypted = await decryptFrame({ data: encrypted }, key);
  assert.deepEqual(new Uint8Array(decrypted.data), new Uint8Array(original));
  await assert.rejects(decryptFrame({ data: original }, key));
  await assert.rejects(decryptFrame({ data: encrypted }, wrong));
  const corrupt = encrypted.slice(0); new Uint8Array(corrupt)[20] ^= 1;
  await assert.rejects(decryptFrame({ data: corrupt }, key));
  assert.equal(new Uint8Array(encrypted)[0], new Uint8Array(original)[0], "Opus TOC is preserved");
  const badHeader = encrypted.slice(0); new Uint8Array(badHeader)[0] ^= 1;
  await assert.rejects(decryptFrame({ data: badHeader }, key), "visible TOC is authenticated");
});

test("blocked playback exposes a retry, successful retry is observable", async () => {
  const sandbox = { window: {}, console: { warn() {} }, document: { createElement: () => ({}) } };
  vm.runInNewContext(source("remote_audio"), sandbox);
  let retry;
  const audio = { dataset: {}, play: async () => { throw new Error("blocked"); }, before(button) { retry = button; } };
  assert.equal(await sandbox.window.RemoteAudio.play(audio), false);
  assert.equal(audio.controls, true);
  assert.ok(retry.onclick);
  audio.play = async () => {};
  assert.equal(await sandbox.window.RemoteAudio.play(audio), true);
  assert.equal(audio.dataset.playback, "playing");
});

test("E2EE capability serializes as boolean; transforms are installed once before keys and updated by port", () => {
  const transforms = [], messages = [];
  class Endpoint {}
  Endpoint.prototype.transform = null;
  const sandbox = { window: { RTCRtpSender: Endpoint, RTCRtpReceiver: Endpoint, RTCRtpScriptTransform: class {} },
    RTCRtpSender: Endpoint, RTCRtpReceiver: Endpoint,
    RTCRtpScriptTransform: class { constructor(worker, options) { transforms.push(options.role); } },
    Worker: class { addEventListener() {} terminate() {} },
    MessageChannel: class { constructor() { this.port1 = { postMessage: (message) => messages.push(message) }; this.port2 = {}; } } };
  vm.runInNewContext(source("e2ee/e2ee"), sandbox);
  const e2ee = sandbox.window.E2EE;
  assert.equal(JSON.stringify({ enabled: e2ee.supports }), '{"enabled":true}');
  const sender = new Endpoint(), receiver = new Endpoint();
  e2ee.attachSenderTransform(sender, null); e2ee.attachReceiverTransform(receiver, null);
  assert.deepEqual(transforms, ["encrypt", "decrypt"]);
  assert.equal(messages.length, 0);
  const key = new Uint8Array(32);
  e2ee.attachSenderTransform(sender, key); e2ee.attachReceiverTransform(receiver, key);
  e2ee.attachReceiverTransform(receiver, key);
  assert.equal(transforms.length, 2, "existing streams must not be replaced");
  assert.equal(messages.length, 2, "each endpoint receives one key");
});

test("sender and paired receiver hooks run synchronously before SDP", () => {
  const events = [];
  const receiver = {};
  class PC {
    addTrack(track) { this.sender = { track }; events.push("track"); return this.sender; }
    getTransceivers() { return [{ sender: this.sender, receiver }]; }
  }
  const sandbox = { window: { __APP_CONFIG__: buildConfig({}) }, RTCPeerConnection: PC };
  vm.runInNewContext(source("webrtc_call"), sandbox);
  const c = sandbox.window.WebRTCCall.createConnection({ onSender: () => events.push("encrypt"),
    onReceiver: (r) => { assert.equal(r, receiver); events.push("decrypt"); } });
  c.addLocalStream({ getTracks: () => [{ kind: "audio" }] });
  assert.deepEqual(events, ["track", "encrypt", "decrypt"]);
});

test("VPS room derivation preserves opaque IDs, key separation and verification code", async () => {
  const sandbox = { window: {}, crypto: require("node:crypto").webcrypto, TextEncoder, Uint8Array, btoa };
  vm.runInNewContext(source("crypto/voice-room"), sandbox);
  const derive = sandbox.window.VoiceRoomCrypto.derive;
  const a = await derive({ roomName: " room ", secret: "test passphrase", e2ee: true });
  const b = await derive({ roomName: "room", secret: "test passphrase", e2ee: true });
  const c = await derive({ roomName: "room", secret: "other passphrase", e2ee: true });
  const plain = await derive({ roomName: "room", e2ee: false });
  assert.equal(a.roomId, b.roomId); assert.equal(a.verificationCode, b.verificationCode);
  assert.notEqual(a.roomId, c.roomId); assert.notEqual(a.roomId, plain.roomId);
  assert.notDeepEqual(a.audioKey, c.audioKey);
  assert.equal(plain.audioKey, null);
  assert.ok(!a.roomId.includes("passphrase"));
});

test("ending a personal call does not terminate the encrypted room worker", () => {
  const workers = [];
  class Endpoint {}
  Endpoint.prototype.transform = null;
  const sandbox = { window: { RTCRtpSender: Endpoint, RTCRtpReceiver: Endpoint, RTCRtpScriptTransform: class {} },
    RTCRtpSender: Endpoint, RTCRtpReceiver: Endpoint, RTCRtpScriptTransform: class {},
    Worker: class { constructor() { workers.push(this); } addEventListener() {} terminate() { this.ended = true; } },
    MessageChannel: class { constructor() { this.port1 = { postMessage() {} }; this.port2 = {}; } } };
  vm.runInNewContext(source("e2ee/e2ee"), sandbox);
  const e = sandbox.window.E2EE;
  e.attachSenderTransform(new Endpoint(), new Uint8Array(32), "room");
  e.attachSenderTransform(new Endpoint(), new Uint8Array(32));
  e.reset();
  assert.equal(workers[0].ended, undefined); assert.equal(workers[1].ended, true);
  e.reset("room"); assert.equal(workers[0].ended, true);
});


test("floor countdown counts down without changing ownership or mute", () => {
  const sandbox = { window: {} };
  vm.runInNewContext(source("voice_state"), sandbox);
  const f = sandbox.window.VoiceState;
  const state = { floorOwner: "alice", floorDeadlineAt: 61000, muted: true };
  assert.equal(f.floorSecondsLeft(state, 1000), 60);
  assert.equal(f.floorSecondsLeft(state, 2000), 59);
  assert.equal(f.floorSecondsLeft(state, 60000), 1);
  assert.equal(f.floorSecondsLeft(state, 61000), 0);
  assert.equal(f.floorSecondsLeft(state, 70000), 0);
  assert.equal(state.floorOwner, "alice");
  assert.equal(state.muted, true);
  state.floorOwner = null;
  assert.equal(f.floorSecondsLeft(state, 70000), null);
});
