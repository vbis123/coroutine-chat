(() => {
  const encoder = new TextEncoder();
  const ITERATIONS = 210000;

  const normalize = (value) => String(value || "").normalize("NFKC").trim();

  const toBase64Url = (bytes) => {
    let binary = "";
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };

  const sha256 = async (text) =>
    new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text)));

  const deriveBits = async (secret, saltLabel) => {
    const material = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const salt = await sha256(saltLabel);
    return new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", iterations: ITERATIONS, salt },
        material,
        256
      )
    );
  };

  const verificationCode = async (audioKey) => {
    const label = encoder.encode("coroutine-chat/voice-check/v1");
    const input = new Uint8Array(label.length + audioKey.length);
    input.set(label, 0);
    input.set(audioKey, label.length);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
    const hex = Array.from(digest.slice(0, 8), (byte) => byte.toString(16).padStart(2, "0")).join("");
    return hex.match(/.{1,4}/g).join("-").toUpperCase();
  };

  const derive = async ({ roomName, secret, e2ee }) => {
    const room = normalize(roomName);
    const passphrase = normalize(secret);
    if (!room) throw new Error("room_required");

    if (!e2ee) {
      const roomDigest = await sha256(`coroutine-chat/voice-room/v1\0plain\0${room}`);
      return { roomId: `v1-p-${toBase64Url(roomDigest)}`, audioKey: null, verificationCode: null };
    }
    if (!passphrase) throw new Error("secret_required");

    const roomKey = await deriveBits(
      passphrase,
      `coroutine-chat/voice-room-id/v1\0${room}`
    );
    const audioKey = await deriveBits(
      passphrase,
      `coroutine-chat/voice-audio-key/v1\0${room}`
    );
    return {
      roomId: `v1-e-${toBase64Url(roomKey)}`,
      audioKey,
      verificationCode: await verificationCode(audioKey),
    };
  };

  window.VoiceRoomCrypto = { derive, normalize };
})();
