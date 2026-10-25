const MAGIC = new Uint8Array([0x45, 0x32, 0x45, 0x45]); // "E2EE"

const importKey = async (raw) =>
  crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

const encryptFrame = async (frame, key) => {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, frame.data);
  const encrypted = new Uint8Array(MAGIC.byteLength + iv.byteLength + ciphertext.byteLength);
  encrypted.set(MAGIC, 0);
  encrypted.set(iv, MAGIC.byteLength);
  encrypted.set(new Uint8Array(ciphertext), MAGIC.byteLength + iv.byteLength);
  frame.data = encrypted.buffer;
  return frame;
};

const decryptFrame = async (frame, key) => {
  const data = new Uint8Array(frame.data);
  if (data.byteLength <= MAGIC.byteLength + 12) {
    throw new Error("Unencrypted E2EE frame");
  }
  for (let i = 0; i < MAGIC.byteLength; i += 1) {
    if (data[i] !== MAGIC[i]) {
      throw new Error("Unencrypted E2EE frame");
    }
  }
  const iv = data.slice(MAGIC.byteLength, MAGIC.byteLength + 12);
  const ciphertext = data.slice(MAGIC.byteLength + 12);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  frame.data = plaintext;
  return frame;
};

self.onrtctransform = (event) => {
  const transformer = event.transformer;
  const { role, port } = transformer.options;
  let cryptoKey = null;
  let failureCount = 0;
  let frames = 0;
  port.onmessage = async (message) => {
    try { cryptoKey = await importKey(message.data.key); }
    catch (_) { self.postMessage({ type: "e2ee:error" }); }
  };

  const transformStream = new TransformStream({
    async transform(encodedFrame, controller) {
      if (!cryptoKey) return; // Fail closed while the handshake is pending.
      try {
        if (role === "encrypt") {
          const output = await encryptFrame(encodedFrame, cryptoKey);
          if (output) controller.enqueue(output);
        } else {
          const output = await decryptFrame(encodedFrame, cryptoKey);
          if (output) controller.enqueue(output);
        }
        failureCount = 0;
        frames++;
        if (frames % 50 === 0) self.postMessage({ type: "e2ee:stats", role, frames });
      } catch (err) {
        failureCount += 1;
        if (failureCount === 4) {
          self.postMessage({ type: "e2ee:error", error: err.message || String(err) });
        }
      }
    },
  });

  transformer.readable
    .pipeThrough(transformStream)
    .pipeTo(transformer.writable)
    .catch((err) => {
      self.postMessage({ type: "e2ee:error", error: err.message || String(err) });
    });
};
