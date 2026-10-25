(() => {
  const supports = Boolean(
    window.RTCRtpSender &&
    "transform" in RTCRtpSender.prototype &&
    window.RTCRtpReceiver &&
    "transform" in RTCRtpReceiver.prototype &&
    window.RTCRtpScriptTransform);

  let worker = null;
  const attached = new WeakMap();
  const counters = { encrypt: 0, decrypt: 0 };

  const ensureWorker = () => {
    if (worker) return worker;
    worker = new Worker("/js/e2ee/transform-worker.js");
    const instance = worker;
    worker.addEventListener("message", (event) => {
      if (worker !== instance) return;
      if (event.data?.type === "e2ee:stats") counters[event.data.role] = event.data.frames;
      if (event.data && event.data.type === "e2ee:error") {
        console.warn("[e2ee] media transform failed");
        window.dispatchEvent(new Event("e2ee-error"));
      }
    });
    return worker;
  };

  // Install synchronously when the sender/receiver is created, before its first
  // encoded frame. Pass the negotiated key over a port without replacing streams.
  const attach = (endpoint, role, keyBytes) => {
    if (!supports || !endpoint) return false;
    let state = attached.get(endpoint);
    if (!state) {
      const channel = new MessageChannel();
      endpoint.transform = new RTCRtpScriptTransform(ensureWorker(),
        { role, port: channel.port2 }, [channel.port2]);
      state = { port: channel.port1, keySent: false };
      attached.set(endpoint, state);
    }
    if (keyBytes && !state.keySent) {
      const key = keyBytes.slice(0).buffer;
      state.port.postMessage({ key }, [key]);
      state.keySent = true;
    }
    return true;
  };
  const attachSenderTransform = (sender, key) => attach(sender, "encrypt", key);
  const attachReceiverTransform = (receiver, key) => attach(receiver, "decrypt", key);

  window.E2EE = {
    supports,
    attachSenderTransform,
    attachReceiverTransform,
    diagnostics: () => ({ ...counters }),
    reset: () => { if (worker) worker.terminate(); worker = null; counters.encrypt = counters.decrypt = 0; },
  };
})();
