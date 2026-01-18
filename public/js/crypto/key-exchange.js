(() => {
  const toB64 = (bytes) => {
    let binary = "";
    bytes.forEach((b) => {
      binary += String.fromCharCode(b);
    });
    return btoa(binary);
  };

  const fromB64 = (text) => {
    const binary = atob(text);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  };

  const generateKeyPair = async () =>
    crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);

  const exportPublicKey = async (keyPair) => crypto.subtle.exportKey("jwk", keyPair.publicKey);

  const importPublicKey = async (jwk) =>
    crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, []);

  const deriveWrappingKey = async (privateKey, publicKey) =>
    crypto.subtle.deriveKey(
      { name: "ECDH", public: publicKey },
      privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

  const wrapCallKey = async (wrappingKey, callKey) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrappingKey, callKey);
    return {
      ivB64: toB64(iv),
      encryptedKeyB64: toB64(new Uint8Array(encrypted)),
    };
  };

  const unwrapCallKey = async (wrappingKey, ivB64, encryptedKeyB64) => {
    const iv = fromB64(ivB64);
    const encrypted = fromB64(encryptedKeyB64);
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, wrappingKey, encrypted);
    return new Uint8Array(plaintext);
  };

  const randomCallKey = () => crypto.getRandomValues(new Uint8Array(32));

  window.KeyExchange = {
    generateKeyPair,
    exportPublicKey,
    importPublicKey,
    deriveWrappingKey,
    wrapCallKey,
    unwrapCallKey,
    randomCallKey,
    toB64,
    fromB64,
  };
})();
