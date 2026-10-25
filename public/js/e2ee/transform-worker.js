const MAGIC = new Uint8Array([0x45, 0x32, 0x45, 0x45]); // "E2EE"

const importKey = async (raw) =>
  crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

// Preserve and authenticate the Opus TOC byte required by the RTP packetizer.
// Audio content remains AES-GCM encrypted; plaintext is never accepted.
const encryptFrame = async (frame, key) => {
  const data = new Uint8Array(frame.data);
  if (!data.length) throw new Error("Empty audio frame");
  const header = data.slice(0, 1);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: header }, key, data.slice(1));
  const output = new Uint8Array(1 + MAGIC.length + iv.length + encrypted.byteLength);
  output.set(header); output.set(MAGIC, 1); output.set(iv, 5); output.set(new Uint8Array(encrypted), 17);
  frame.data = output.buffer;
  return frame;
};

const decryptFrame = async (frame, key) => {
  const data = new Uint8Array(frame.data);
  if (data.length < 33 || !MAGIC.every((byte, i) => data[i + 1] === byte)) throw new Error("Unencrypted E2EE frame");
  const header = data.slice(0, 1);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: data.slice(5, 17), additionalData: header }, key, data.slice(17));
  const output = new Uint8Array(1 + decrypted.byteLength);
  output.set(header); output.set(new Uint8Array(decrypted), 1);
  frame.data = output.buffer;
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
