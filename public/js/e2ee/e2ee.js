(() => {
  const supports = Boolean(
    window.RTCRtpSender &&
    "transform" in RTCRtpSender.prototype &&
    window.RTCRtpReceiver &&
    "transform" in RTCRtpReceiver.prototype &&
    window.RTCRtpScriptTransform);

  const scopes = new Map();
  const attached = new WeakMap();


  const ensureScope = (scope) => {
    if (scopes.has(scope)) return scopes.get(scope);
    const worker = new Worker("/js/e2ee/transform-worker.js");
    const state = { worker, counters: { encrypt: 0, decrypt: 0 } };
    scopes.set(scope, state);
    worker.addEventListener("message", (event) => {
      if (scopes.get(scope) !== state) return;
      if (event.data?.type === "e2ee:stats") state.counters[event.data.role] = event.data.frames;
      if (event.data?.type === "e2ee:error") {
        console.warn("[e2ee] media transform failed");
        window.dispatchEvent(new CustomEvent("e2ee-error", { detail: { scope } }));
      }
    });
    return state;
  };

  // Install synchronously when the sender/receiver is created, before its first
  // encoded frame. Pass the negotiated key over a port without replacing streams.
  const attach = (endpoint, role, keyBytes, scope) => {
    if (!supports || !endpoint) return false;
    let state = attached.get(endpoint);
    if (!state) {
      const channel = new MessageChannel();
      endpoint.transform = new RTCRtpScriptTransform(ensureScope(scope).worker,
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
  const attachSenderTransform = (sender, key, scope = "call") => attach(sender, "encrypt", key, scope);
  const attachReceiverTransform = (receiver, key, scope = "call") => attach(receiver, "decrypt", key, scope);

  window.E2EE = {
    supports,
    attachSenderTransform,
    attachReceiverTransform,
    diagnostics: (scope = "call") => ({ ...(scopes.get(scope)?.counters || { encrypt: 0, decrypt: 0 }) }),
    reset: (scope = "call") => { scopes.get(scope)?.worker.terminate(); scopes.delete(scope); },
  };
})();
