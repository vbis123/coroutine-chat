(() => {
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
    "e2ee:enabled",
    "e2ee:disabled",
  ]);

  const parseSignal = (text) => {
    if (!text || text[0] !== "{") return null;
    try {
      const parsed = JSON.parse(text);
      if (parsed && SIGNAL_TYPES.has(parsed.type)) return parsed;
    } catch (_) {}
    return null;
  };

  window.Signaling = {
    SIGNAL_TYPES,
    parseSignal,
  };
})();
