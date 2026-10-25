// Optional real Chromium integration: PLAYWRIGHT_MODULE may point to a bundled
// Playwright installation. All accounts/media/data in this test are synthetic.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const net = require("node:net");
const assert = require("node:assert/strict");
const { once } = require("node:events");

const root = path.resolve(__dirname, "..");
fs.mkdirSync(path.join(root, ".tmp"), { recursive: true });
const temp = fs.mkdtempSync(path.join(root, ".tmp", "voice-"));
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
const listen = async (server) => { server.listen(0, "127.0.0.1"); await once(server, "listening"); return server.address().port; };
const freePort = async () => { const server = net.createServer(); const port = await listen(server); await new Promise((r) => server.close(r)); return port; };

async function main() {
  const sockets = new Set();
  const broadcast = (text) => {
    const body = Buffer.from(text); const frame = Buffer.alloc(4 + body.length);
    frame.writeUInt32BE(body.length); body.copy(frame, 4);
    for (const peer of sockets) peer.write(frame);
  };
  const tcp = net.createServer((socket) => {
    sockets.add(socket);
    let buffer = Buffer.alloc(0), name;
    socket.on("data", (data) => {
      buffer = Buffer.concat([buffer, data]);
      while (buffer.length >= 4 && buffer.length >= 4 + buffer.readUInt32BE()) {
        const length = buffer.readUInt32BE();
        const body = buffer.subarray(4, 4 + length).toString(); buffer = buffer.subarray(4 + length);
        if (!name) { name = body; broadcast(`* ${name} joined *`); }
        else broadcast(`[${name}] ${body}`);
      }
    });
    socket.on("close", () => sockets.delete(socket));
  });
  const tcpPort = await listen(tcp);
  const httpPort = await freePort();
  const wsPort = await freePort();
  let serverRoot = root;
  if (process.env.BASELINE_REF) {
    serverRoot = path.join(temp, "baseline");
    const files = execFileSync("git", ["ls-tree", "-r", "--name-only", process.env.BASELINE_REF], { cwd: root, encoding: "utf8" }).trim().split("\n");
    for (const file of files.filter((f) => f.startsWith("public/") || f.startsWith("proxy/"))) {
      const target = path.join(serverRoot, file);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, execFileSync("git", ["show", `${process.env.BASELINE_REF}:${file}`], { cwd: root }));
    }
  }
  // 440Hz PCM verifies non-silent delivery, rather than RTP counters alone.
  const rate = 48000, samples = rate * 5;
  const wav = Buffer.alloc(44 + samples * 2);
  wav.write("RIFF"); wav.writeUInt32LE(wav.length - 8, 4); wav.write("WAVEfmt ", 8);
  wav.writeUInt32LE(16, 16); wav.writeUInt16LE(1, 20); wav.writeUInt16LE(1, 22);
  wav.writeUInt32LE(rate, 24); wav.writeUInt32LE(rate * 2, 28); wav.writeUInt16LE(2, 32); wav.writeUInt16LE(16, 34);
  wav.write("data", 36); wav.writeUInt32LE(samples * 2, 40);
  for (let i = 0; i < samples; i++) wav.writeInt16LE(Math.round(8000 * Math.sin(2 * Math.PI * 440 * i / rate)), 44 + i * 2);
  const wavPath = path.join(temp, "tone.wav"); fs.writeFileSync(wavPath, wav);
  const child = spawn(process.execPath, [path.join(serverRoot, "proxy/server.js")], { cwd: serverRoot,
    env: { ...process.env, NODE_PATH: path.join(root, "node_modules"), CHAT_DATA_DIR: path.join(temp, "data"),
      HTTP_PORT: String(httpPort), WS_PORT: String(wsPort), TCP_PORT: String(tcpPort), TCP_HOST: "127.0.0.1",
      CERT_PATH: "", KEY_PATH: "", TURN_SECRET: "", TURN_URL: "", ICE_TRANSPORT_POLICY: "all" }, stdio: "ignore" });
  let browser;
  try {
    const url = `http://localhost:${httpPort}`;
    for (let i = 0; i < 100; i++) { try { if ((await fetch(url)).ok) break; } catch (_) {} await delay(100); }
    browser = await chromium.launch({ headless: true, executablePath: process.env.BROWSER_EXECUTABLE || undefined,
      args: ["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream", `--use-file-for-fake-audio-capture=${wavPath}`, "--autoplay-policy=no-user-gesture-required"] });
    const pages = [];
    const errors = [];
    for (const name of ["alice", "bob"]) {
      const context = await browser.newContext({ permissions: ["microphone"] });
      await context.addInitScript(({ name, wsPort }) => {
        localStorage.setItem("authToken", "synthetic-test-session");
        const NativeWS = window.WebSocket;
        window.WebSocket = class extends NativeWS { constructor(url, ...args) { super(url.replace(/:\d+\/ws$/, `:${wsPort}`), ...args); } };
        window.testPCs = [];
        const PC = window.RTCPeerConnection;
        window.RTCPeerConnection = class extends PC { constructor(...args) { super(...args); window.testPCs.push(this); } };
        if (name === "bob") {
          const get = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
          navigator.mediaDevices.getUserMedia = async (...args) => { await new Promise((r) => setTimeout(r, 1500)); return get(...args); };
        }
      }, { name, wsPort });
      await context.route("**/api/me", (route) => route.fulfill({ json: { username: name } }));
      if (process.env.DEBUG_TEST && !process.env.BASELINE_REF) await context.route("**/app.js", async (route) => {
        await route.fulfill({ contentType: "application/javascript", body: fs.readFileSync(path.join(root, "public/app.js"), "utf8").replace("const DEBUG_E2EE = false", "const DEBUG_E2EE = true") });
      });
      const page = await context.newPage();
      page.setDefaultTimeout(12000);
      page.on("pageerror", (error) => errors.push(error.name + ": " + error.message));
      page.on("console", (message) => { if (message.text().startsWith("[e2ee]") || message.type() === "warning") console.log(name, message.text()); });
      await page.goto(url);
      await page.waitForFunction(() => document.querySelector("#status").dataset.state === "connected");
      pages.push(page);
    }
    const [a, b] = pages;
    const report = async (label) => {
      const results = await Promise.all(pages.map((page) => page.evaluate(async () => {
        const live = window.testPCs.filter((pc) => pc.connectionState !== "closed");
        const summaries = [];
        for (const pc of live) {
          const stats = await pc.getStats();
          const audio = [];
          stats.forEach((s) => { if (["inbound-rtp", "outbound-rtp"].includes(s.type) && s.kind === "audio") audio.push({ type: s.type, packets: s.packetsReceived ?? s.packetsSent, energy: s.totalAudioEnergy }); });
          summaries.push({ state: pc.connectionState, audio });
        }
        const playback = [];
        for (const el of Array.from(document.querySelectorAll("audio")).filter((el) => el.srcObject)) {
          const ctx = new AudioContext();
          const analyser = ctx.createAnalyser(); analyser.fftSize = 8192;
          ctx.createMediaStreamSource(el.srcObject).connect(analyser).connect(ctx.destination);
          await ctx.resume(); await new Promise((r) => setTimeout(r, 300));
          const bins = new Float32Array(analyser.frequencyBinCount); analyser.getFloatFrequencyData(bins);
          let peak = 0; for (let i = 1; i < bins.length; i++) if (bins[i] > bins[peak]) peak = i;
          playback.push({ paused: el.paused, time: el.currentTime, ready: el.readyState,
            peakHz: peak * ctx.sampleRate / analyser.fftSize, peakDb: bins[peak] });
          await ctx.close();
        }
        return { live: live.length, summaries, playback, e2ee: window.E2EE.diagnostics?.() };
      })));
      console.log(label, JSON.stringify(results));
      assert.equal(errors.length, 0, errors.join("\n"));
      for (const result of results) {
        assert.equal(result.live, 1, "one live peer per client");
        assert.equal(result.summaries[0].state, "connected");
        assert.ok(result.summaries[0].audio.some((s) => s.type === "outbound-rtp" && s.packets > 10));
        assert.ok(result.summaries[0].audio.some((s) => s.type === "inbound-rtp" && s.packets > 10 && s.energy > 0), "decoded non-silent audio");
        assert.ok(result.playback.some((p) => !p.paused && p.time > 0 && p.ready >= 2), "remote audio is playing");
        assert.ok(result.playback.some((p) => p.peakHz > 400 && p.peakHz < 480 && p.peakDb > -70), "440Hz tone is decoded in the remote stream");
      }
    };
    for (const page of pages) {
      await page.locator("#secret").fill("synthetic-room");
      await page.locator("#menu-voice").click();
      await page.locator("#voice-join").click();
    }
    await delay(5000); await report("room");
    if (!process.env.BASELINE_REF) {
      await b.evaluate(async () => {
        const audio = document.querySelector("#voice-remote-audio audio");
        const play = audio.play.bind(audio);
        audio.play = async () => { throw new DOMException("Synthetic autoplay block", "NotAllowedError"); };
        await RemoteAudio.play(audio);
        audio.play = play;
      });
      await b.getByRole("button", { name: "Включить звук собеседника", exact: true }).click();
      await b.waitForFunction(() => !document.querySelector("#voice-remote-audio").classList.contains("playback-blocked"));
      console.log("playback-retry visible and functional");
      const trackEnabled = (page) => page.evaluate(() => window.testPCs.filter((pc) => pc.connectionState !== "closed")[0].getSenders()[0].track.enabled);
      await a.locator("#voice-mute").click();
      await a.locator("#voice-floor").click();
      await b.waitForFunction(() => document.querySelector("#voice-floor-status").textContent.includes("alice"));
      assert.equal(await trackEnabled(a), false, "claim preserves explicit mute");
      assert.equal(await trackEnabled(b), false, "listener track disabled");
      await a.locator("#voice-floor").click();
      await b.waitForFunction(() => document.querySelector("#voice-floor-status").textContent.includes("свободен"));
      assert.equal(await trackEnabled(a), false, "release preserves mute");
      assert.equal(await trackEnabled(b), false, "release does not surprise listener with live mic");
      await b.locator("#voice-ptt").dispatchEvent("mousedown");
      assert.equal(await trackEnabled(b), true);
      await b.locator("#voice-ptt").dispatchEvent("mouseup");
      assert.equal(await trackEnabled(b), false, "PTT restores prior listener state");
      console.log("floor-mute-ptt passed");
    }
    for (const page of pages) await page.locator("#voice-leave").click();
    for (const settings of (process.env.ONLY_E2EE ? [[true, true]] : [[false, false], [true, false], [false, true], [false, false]])) {
      const encrypted = settings.some(Boolean);
      for (let i = 0; i < pages.length; i++) { await pages[i].locator("#menu-calls").click(); await pages[i].locator("#e2ee-toggle").setChecked(settings[i]); }
      await a.locator(".user-row").filter({ hasText: "bob" }).getByRole("button", { name: "Позвонить", exact: true }).click();
      await b.locator("#call-accept").click();
      await delay(6000);
      if (encrypted) for (const page of pages) await page.locator("#e2ee-status").filter({ hasText: "E2EE включено" }).waitFor();
      await report(encrypted ? "call-e2ee" : "call-plain");
      if (encrypted && !process.env.BASELINE_REF) for (const page of pages) {
        const counters = await page.evaluate(() => E2EE.diagnostics());
        assert.ok(counters.encrypt >= 100 && counters.decrypt >= 100, "both encryption directions process frames");
      }
      await a.locator("#call-hangup").click();
      // Respect the application's 10-second per-peer invite cooldown.
      await delay(10500);
    }
    // Close and reopen an owner's WebSocket through the actual client UI.
    for (const page of pages) { await page.locator("#menu-voice").click(); await page.locator("#voice-join").click(); }
    await a.locator("#voice-floor").click();
    await b.waitForFunction(() => document.querySelector("#voice-floor-status").textContent.includes("alice"));
    await a.locator("#connect-btn").click();
    await b.waitForFunction(() => document.querySelector("#voice-floor-status").textContent.includes("свободен"));
    await a.locator("#connect-btn").click();
    await a.waitForFunction(() => document.querySelector("#status").dataset.state === "connected");
    await a.locator("#voice-join").click();
    assert.equal(await a.locator("#voice-floor-status").textContent(), "Общий микрофон: свободен");
    // Re-enable only by explicit action; never on the remote owner's departure.
    await a.locator("#voice-mute").click(); await b.locator("#voice-mute").click();
    await delay(5000); await report("room-after-reconnect");
    console.log("Browser voice checks passed (synthetic media; physical speakers not assessed).");
  } finally {
    if (browser) await browser.close();
    child.kill();
    for (const socket of sockets) socket.destroy();
    tcp.close();
    // Retain isolated ignored test artifacts for local debugging.
  }
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
