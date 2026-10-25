const crypto = require("node:crypto");

// Both endpoints must describe the same configuration. REST credentials take
// precedence over static credentials when a shared TURN secret is configured.
function buildConfig(env = process.env, now = Date.now()) {
  let turn = null;
  if (env.TURN_SECRET) {
    const username = `${Math.floor(now / 1000) + 21600}:coroutine-chat`;
    turn = {
      urls: env.TURN_URL || [
        "turn:coroutine-chat.ru:3478?transport=udp",
        "turn:coroutine-chat.ru:3478?transport=tcp",
        "turns:coroutine-chat.ru:5349?transport=tcp",
      ],
      username,
      credential: crypto.createHmac("sha1", env.TURN_SECRET).update(username).digest("base64"),
    };
  } else if (env.TURN_URL) {
    turn = { urls: env.TURN_URL, username: env.TURN_USER || "", credential: env.TURN_PASS || "" };
  }
  const voiceLimit = Number(env.VOICE_LIMIT || 6);
  if (!Number.isInteger(voiceLimit) || voiceLimit < 2 || voiceLimit > 20) {
    throw new Error("VOICE_LIMIT must be an integer between 2 and 20");
  }
  const iceTransportPolicy = env.ICE_TRANSPORT_POLICY || "all";
  if (!["all", "relay"].includes(iceTransportPolicy)) throw new Error("Invalid ICE_TRANSPORT_POLICY");
  if (iceTransportPolicy === "relay" && !turn) throw new Error("Relay requires TURN");
  return { turn, voiceLimit, iceTransportPolicy };
}
module.exports = { buildConfig };
