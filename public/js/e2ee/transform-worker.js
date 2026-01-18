let failureCount = 0;

const importKey = async (raw) =>
  crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

const encryptFrame = async (frame, key) => {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, frame.data);
  const encrypted = new Uint8Array(iv.byteLength + ciphertext.byteLength);
  encrypted.set(iv, 0);
  encrypted.set(new Uint8Array(ciphertext), iv.byteLength);
  frame.data = encrypted.buffer;
  return frame;
};

const decryptFrame = async (frame, key) => {
  const data = new Uint8Array(frame.data);
  if (data.byteLength <= 12) {
    return null;
  }
  const iv = data.slice(0, 12);
  const ciphertext = data.slice(12);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  frame.data = plaintext;
  return frame;
};

self.onrtctransform = async (event) => {
  const transformer = event.transformer;
  const { role, key } = transformer.options;
  const cryptoKey = await importKey(key);

  const transformStream = new TransformStream({
    async transform(encodedFrame, controller) {
      try {
        if (role === "encrypt") {
          const output = await encryptFrame(encodedFrame, cryptoKey);
          if (output) controller.enqueue(output);
        } else {
          const output = await decryptFrame(encodedFrame, cryptoKey);
          if (output) controller.enqueue(output);
        }
        failureCount = 0;
      } catch (err) {
        failureCount += 1;
        if (failureCount > 3) {
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
