(() => {
  const statusEl = document.getElementById("status");
  const chatEl = document.getElementById("chat");
  const formEl = document.getElementById("form");
  const messageEl = document.getElementById("message");
  const nicknameEl = document.getElementById("nickname");
  const connectBtn = document.getElementById("connect-btn");
  const recipientEl = document.getElementById("recipient");
  const secretEl = document.getElementById("secret");
  const nicknamesEl = document.getElementById("nicknames");
  const showEncryptedEl = document.getElementById("show-encrypted");
  const authPanel = document.getElementById("auth-panel");
  const chatPanel = document.getElementById("chat-panel");
  const tabLogin = document.getElementById("tab-login");
  const tabRegister = document.getElementById("tab-register");
  const loginForm = document.getElementById("login-form");
  const registerForm = document.getElementById("register-form");
  const loginUsername = document.getElementById("login-username");
  const loginPassword = document.getElementById("login-password");
  const registerUsername = document.getElementById("register-username");
  const registerPassword = document.getElementById("register-password");
  const registerConfirm = document.getElementById("register-confirm");
  const loginError = document.getElementById("login-error");
  const registerError = document.getElementById("register-error");
  const logoutBtn = document.getElementById("logout-btn");
  const ruleLength = document.getElementById("rule-length");
  const ruleLower = document.getElementById("rule-lower");
  const ruleUpper = document.getElementById("rule-upper");
  const ruleDigit = document.getElementById("rule-digit");
  const logoutModal = document.getElementById("logout-modal");
  const logoutCancel = document.getElementById("logout-cancel");
  const logoutConfirm = document.getElementById("logout-confirm");

  let ws = null;
  let reconnectAttempts = 0;
  let reconnectTimer = null;
  let openedAt = 0;
  let registeredName = "";
  let manualDisconnect = false;

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const knownNicknames = new Set();
  const backoffDelays = [500, 1000, 2000, 5000, 10000];
  const WHO_MSG = "::who::";
  const IAM_PREFIX = "::iam::";
  const AUTH_TOKEN_KEY = "authToken";
  const AUTH_TAB_KEY = "authTab";

  const STATUS_TEXT = {
    disconnected: "Отключено",
    connecting: "Подключение",
    connected: "Подключено",
    reconnecting: "Переподключение",
  };

  const setStatus = (state) => {
    statusEl.textContent = STATUS_TEXT[state] || state;
    statusEl.dataset.state = state;
  };

  const getNickname = () => nicknameEl.value.trim();
  const hasNickname = () => Boolean(getNickname());
  const getRecipient = () => {
    const raw = recipientEl.value.trim();
    if (!raw) return "all";
    if (raw.toLowerCase() === "all" || raw.toLowerCase() === "все" || raw.toLowerCase() === "всем") {
      return "all";
    }
    return raw;
  };
  const getSecret = () => secretEl.value.trim();

  const connect = () => {
    if (!hasNickname()) return;
    const url = location.protocol === "https:" ? "wss://" : "ws://";
    const wsUrl = `${url}${location.hostname}:8080`;

    setStatus("connecting");
    ws = new WebSocket(wsUrl);

    ws.addEventListener("open", () => {
      openedAt = Date.now();
      reconnectAttempts = 0;
      setStatus("connected");
      sendNickname();
      sendWho();
      nicknameEl.disabled = true;
      connectBtn.textContent = "Отключиться";
    });

    ws.addEventListener("message", (event) => {
      const text = typeof event.data === "string" ? event.data : "";
      handleIncoming(text);
    });

    ws.addEventListener("close", () => {
      setStatus("disconnected");
      nicknameEl.disabled = false;
      connectBtn.textContent = "Подключиться";
      registeredName = "";
      if (manualDisconnect) {
        manualDisconnect = false;
        return;
      }
      const fastClose = Date.now() - openedAt < 1000;
      if (fastClose) return;
      scheduleReconnect();
    });

    ws.addEventListener("error", () => {
      setStatus("disconnected");
    });
  };

  const scheduleReconnect = () => {
    if (!hasNickname()) return;
    if (reconnectTimer) return;
    reconnectAttempts += 1;
    setStatus("reconnecting");

    const delay = backoffDelays[Math.min(reconnectAttempts - 1, backoffDelays.length - 1)];
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connect();
    }, delay);
  };

  const updateNicknames = (name) => {
    if (!name) return;
    if (knownNicknames.has(name)) return;
    knownNicknames.add(name);
    nicknamesEl.innerHTML = "";
    Array.from(knownNicknames)
      .sort((a, b) => a.localeCompare(b))
      .forEach((nickname) => {
        const option = document.createElement("option");
        option.value = nickname;
        nicknamesEl.appendChild(option);
      });
  };

  const parseIncoming = (text) => {
    if (!text) return null;

    const joinMatch = text.match(/^\*\s+(.+?)\s+joined\s+\*$/);
    if (joinMatch) {
      return { kind: "system", body: text, name: joinMatch[1] };
    }

    const leaveMatch = text.match(/^\*\s+(.+?)\s+left\s+\*$/);
    if (leaveMatch) {
      return { kind: "system", body: text, name: leaveMatch[1] };
    }

    if (text.startsWith("system:")) {
      return { kind: "system", body: text };
    }

    let match = text.match(/^\[from\s+([^\]]+)\]\s*(.*)$/);
    if (match) {
      return { kind: "chat", from: match[1], body: match[2], direct: true };
    }

    match = text.match(/^\[([^\]]+)\]\s*(.*)$/);
    if (match) {
      return { kind: "chat", from: match[1], body: match[2], direct: false };
    }

    return { kind: "system", body: text };
  };

  const parseEncryptedBody = (body) => {
    if (!body || !body.startsWith("{")) return null;
    try {
      const parsed = JSON.parse(body);
      if (parsed && parsed.enc === "aes-gcm") {
        return {
          enc: "aes-gcm",
          salt: String(parsed.salt || ""),
          iv: String(parsed.iv || ""),
          body: String(parsed.body || ""),
        };
      }
    } catch (_) {}
    return null;
  };

  const b64Encode = (bytes) => {
    let binary = "";
    bytes.forEach((b) => {
      binary += String.fromCharCode(b);
    });
    return btoa(binary);
  };

  const b64Decode = (text) => {
    const binary = atob(text);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  };

  const deriveKey = async (secret, salt) => {
    const baseKey = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  };

  const encryptBody = async (body, secret) => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(secret, salt);
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      encoder.encode(body)
    );

    return JSON.stringify({
      enc: "aes-gcm",
      salt: b64Encode(salt),
      iv: b64Encode(iv),
      body: b64Encode(new Uint8Array(ciphertext)),
    });
  };

  const decryptBody = async ({ body, salt, iv }, secret) => {
    const saltBytes = b64Decode(salt);
    const ivBytes = b64Decode(iv);
    const dataBytes = b64Decode(body);
    const key = await deriveKey(secret, saltBytes);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes },
      key,
      dataBytes
    );
    return decoder.decode(plaintext);
  };

  const renderMessage = ({ kind, from, to, body, encrypted, decrypted, encryptedPayload, status }) => {
    const nickname = getNickname();
    const isMe = from && from === nickname;
    const time = new Date().toLocaleTimeString("ru-RU", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });

    const wrapper = document.createElement("div");
    wrapper.className = `msg ${kind === "system" ? "system" : isMe ? "me" : "other"}`;
    if (encrypted) {
      wrapper.dataset.encrypted = "1";
      wrapper.dataset.decrypted = decrypted ? "1" : "0";
      if (encryptedPayload) {
        wrapper.dataset.encryptedPayload = JSON.stringify(encryptedPayload);
      }
    }

    const meta = document.createElement("div");
    meta.className = "meta";

    if (kind === "system") {
      meta.textContent = `система • ${time}`;
    } else {
      const toLabel = to && to !== "all" ? ` → ${to}` : "";
      const encLabel = encrypted ? " [encrypted]" : "";
      meta.textContent = `${from || "anon"}${toLabel}${encLabel} • ${time}`;
      if (status) {
        const tag = document.createElement("span");
        tag.className = `tag ${status === "sent" ? "ok" : status === "failed" ? "fail" : ""}`;
        tag.textContent = status === "pending" ? "отправляется" : status === "sent" ? "отправлено" : "ошибка";
        meta.appendChild(tag);
      }
    }

    const content = document.createElement("div");
    content.className = "content";
    content.textContent = body;

    wrapper.appendChild(meta);
    wrapper.appendChild(content);
    chatEl.appendChild(wrapper);
    chatEl.scrollTop = chatEl.scrollHeight;
    return wrapper;
  };

  const handleIncoming = async (text) => {
    const parsed = parseIncoming(text);
    if (!parsed) return;

    if (parsed.kind === "system") {
      if (parsed.name) updateNicknames(parsed.name);
      renderMessage({ kind: "system", body: parsed.body });
      return;
    }

    updateNicknames(parsed.from);

    if (parsed.body === WHO_MSG) {
      sendIam();
      return;
    }

    if (parsed.body.startsWith(IAM_PREFIX)) {
      const name = parsed.body.slice(IAM_PREFIX.length).trim();
      updateNicknames(name);
      return;
    }

    let body = parsed.body;
    let encrypted = false;
    let decrypted = false;
    let encryptedPayload = null;
    const parsedEncrypted = parseEncryptedBody(parsed.body);
    if (parsedEncrypted) {
      encryptedPayload = parsedEncrypted;
      encrypted = true;
      const secret = getSecret();
      if (!secret) {
        body = showEncryptedEl.checked ? "[encrypted message]" : "••••••";
      } else {
        try {
          body = await decryptBody(parsedEncrypted, secret);
          decrypted = true;
        } catch (_) {
          body = showEncryptedEl.checked ? "[encrypted message]" : "••••••";
        }
      }
    }

    const to = parsed.direct ? getNickname() : "all";
    renderMessage({
      kind: "chat",
      from: parsed.from,
      to,
      body,
      encrypted,
      decrypted,
      encryptedPayload,
    });
  };

  const sendNickname = () => {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const nickname = getNickname();
    if (!nickname) return;
    updateNicknames(nickname);
    ws.send(nickname);
    registeredName = nickname;
  };

  const sendWho = () => {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    if (!registeredName) return;
    ws.send(WHO_MSG);
  };

  const sendIam = () => {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    if (!registeredName) return;
    ws.send(`${IAM_PREFIX}${registeredName}`);
  };

  const sendMessage = async () => {
    const body = messageEl.value.trim();
    if (!body) return;

    if (!hasNickname()) {
      setStatus("disconnected");
      return;
    }

    if (!ws || ws.readyState !== WebSocket.OPEN) {
      setStatus("disconnected");
      return;
    }

    const nickname = getNickname();
    const to = getRecipient();
    const secret = getSecret();

    updateNicknames(nickname);

    let payload = body;
    const isDirect = to !== "all";
    let encryptedPayload = null;
    if (secret) {
      payload = await encryptBody(body, secret);
      encryptedPayload = parseEncryptedBody(payload);
    }

    if (isDirect) {
      payload = `@${to} ${payload}`;
    }

    const localNode = renderMessage({
      kind: "chat",
      from: nickname,
      to: isDirect ? to : "all",
      body,
      encrypted: Boolean(encryptedPayload),
      decrypted: Boolean(encryptedPayload),
      encryptedPayload,
      status: "pending",
    });
    ws.send(payload);
    if (localNode) {
      const tag = localNode.querySelector(".tag");
      if (tag) {
        const markFailed = () => {
          tag.textContent = "ошибка";
          tag.classList.remove("ok");
          tag.classList.add("fail");
        };
        if (!ws || ws.readyState !== WebSocket.OPEN) {
          markFailed();
        } else {
          tag.textContent = "отправлено";
          tag.classList.add("ok");
        }
      }
    }
    messageEl.value = "";
  };

  formEl.addEventListener("submit", (event) => {
    event.preventDefault();
    sendMessage();
  });

  messageEl.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      sendMessage();
    }
  });

  connectBtn.addEventListener("click", () => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      manualDisconnect = true;
      ws.close();
      return;
    }
    if (!hasNickname()) {
      nicknameEl.focus();
      return;
    }
    connect();
  });

  const handleRecipientFocus = () => {
    if (recipientEl.value) {
      recipientEl.dataset.prev = recipientEl.value;
      recipientEl.value = "";
    }
  };

  const handleRecipientBlur = () => {
    if (!recipientEl.value && recipientEl.dataset.prev) {
      recipientEl.value = recipientEl.dataset.prev;
    }
    delete recipientEl.dataset.prev;
  };

  recipientEl.addEventListener("focus", handleRecipientFocus);
  recipientEl.addEventListener("blur", handleRecipientBlur);

  const getToken = () => localStorage.getItem(AUTH_TOKEN_KEY);
  const setToken = (token) => localStorage.setItem(AUTH_TOKEN_KEY, token);
  const clearToken = () => localStorage.removeItem(AUTH_TOKEN_KEY);

  const apiRequest = async (path, options = {}) => {
    const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
    const response = await fetch(path, { ...options, headers });
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok, data };
  };

  const isPasswordStrong = (password) => {
    if (password.length < 8) return false;
    if (!/[a-z]/.test(password)) return false;
    if (!/[A-Z]/.test(password)) return false;
    if (!/[0-9]/.test(password)) return false;
    return true;
  };

  const isValidUsername = (username) => /^[A-Za-z0-9_-]{3,24}$/.test(username);

  const updatePasswordRules = (password) => {
    ruleLength.classList.toggle("ok", password.length >= 8);
    ruleLower.classList.toggle("ok", /[a-z]/.test(password));
    ruleUpper.classList.toggle("ok", /[A-Z]/.test(password));
    ruleDigit.classList.toggle("ok", /[0-9]/.test(password));
  };

  const switchTab = (tab, persist = true) => {
    const isLogin = tab === "login";
    tabLogin.classList.toggle("active", isLogin);
    tabRegister.classList.toggle("active", !isLogin);
    loginForm.classList.toggle("hidden", !isLogin);
    registerForm.classList.toggle("hidden", isLogin);
    loginError.textContent = "";
    registerError.textContent = "";
    if (persist) {
      localStorage.setItem(AUTH_TAB_KEY, tab);
      history.replaceState(null, "", tab === "register" ? "#register" : "#login");
    }
  };

  tabLogin.addEventListener("click", () => switchTab("login"));
  tabRegister.addEventListener("click", () => switchTab("register"));

  const showChat = (username, autoConnect = false) => {
    nicknameEl.value = username;
    authPanel.classList.add("hidden");
    chatPanel.classList.remove("hidden");
    connectBtn.textContent = "Подключиться";
    logoutBtn.classList.remove("hidden");
    setStatus("disconnected");
    if (autoConnect) {
      setTimeout(() => connect(), 0);
    }
  };

  const showAuth = () => {
    authPanel.classList.remove("hidden");
    chatPanel.classList.add("hidden");
    logoutBtn.classList.add("hidden");
    nicknameEl.value = "";
    setStatus("disconnected");
  };

  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const username = loginUsername.value.trim();
    const password = loginPassword.value;
    if (!username || !password) {
      loginError.textContent = "Введите логин и пароль.";
      return;
    }
    const { ok, data } = await apiRequest("/api/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    if (!ok) {
      loginError.textContent = "Неверный логин или пароль.";
      return;
    }
    setToken(data.token);
    loginError.textContent = "";
    showChat(data.username, true);
  });

  registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const username = registerUsername.value.trim();
    const password = registerPassword.value;
    const confirm = registerConfirm.value;
    if (!username || !password || !confirm) {
      registerError.textContent = "Заполните все поля.";
      return;
    }
    if (!isValidUsername(username)) {
      registerError.textContent =
        "Логин должен быть 3-24 символа (латиница, цифры, _ или -).";
      return;
    }
    if (password !== confirm) {
      registerError.textContent = "Пароли не совпадают.";
      return;
    }
    if (!isPasswordStrong(password)) {
      registerError.textContent =
        "Пароль должен быть минимум 8 символов и содержать строчные, заглавные буквы и цифры.";
      return;
    }
    const { ok, data } = await apiRequest("/api/register", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    if (!ok) {
      registerError.textContent =
        data.error === "user_exists"
          ? "Такой логин уже существует."
          : "Логин должен быть 3-24 символа (латиница, цифры, _ или -).";
      return;
    }
    setToken(data.token);
    registerError.textContent = "";
    showChat(data.username, true);
  });

  const openLogoutModal = () => {
    logoutModal.classList.remove("hidden");
  };

  const closeLogoutModal = () => {
    logoutModal.classList.add("hidden");
  };

  logoutBtn.addEventListener("click", () => {
    openLogoutModal();
  });

  logoutCancel.addEventListener("click", () => {
    closeLogoutModal();
  });

  logoutModal.addEventListener("click", (event) => {
    if (event.target === logoutModal) {
      closeLogoutModal();
    }
  });

  logoutConfirm.addEventListener("click", async () => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      manualDisconnect = true;
      ws.close();
    }
    await apiRequest("/api/logout", { method: "POST" });
    clearToken();
    closeLogoutModal();
    showAuth();
  });

  registerPassword.addEventListener("input", () => {
    updatePasswordRules(registerPassword.value);
  });

  const updateEncryptedPlaceholders = () => {
    const text = showEncryptedEl.checked ? "[encrypted message]" : "••••••";
    document.querySelectorAll(".msg[data-encrypted=\"1\"][data-decrypted=\"0\"] .content").forEach((el) => {
      el.textContent = text;
    });
  };

  const tryDecryptStoredMessages = async () => {
    const secret = getSecret();
    if (!secret) return;
    const nodes = document.querySelectorAll(".msg[data-encrypted=\"1\"][data-decrypted=\"0\"]");
    for (const node of nodes) {
      const raw = node.dataset.encryptedPayload;
      if (!raw) continue;
      let payload = null;
      try {
        payload = JSON.parse(raw);
      } catch (_) {
        continue;
      }
      try {
        const body = await decryptBody(payload, secret);
        const content = node.querySelector(".content");
        if (content) content.textContent = body;
        node.dataset.decrypted = "1";
      } catch (_) {}
    }
  };

  showEncryptedEl.addEventListener("change", updateEncryptedPlaceholders);
  const lockEncryptedMessages = () => {
    const text = showEncryptedEl.checked ? "[encrypted message]" : "••••••";
    document.querySelectorAll(".msg[data-encrypted=\"1\"] .content").forEach((el) => {
      el.textContent = text;
    });
    document.querySelectorAll(".msg[data-encrypted=\"1\"]").forEach((node) => {
      node.dataset.decrypted = "0";
    });
  };

  secretEl.addEventListener("input", () => {
    lockEncryptedMessages();
    if (getSecret()) {
      tryDecryptStoredMessages();
    }
  });
  secretEl.addEventListener("focus", () => {
    if (secretEl.value) {
      secretEl.value = "";
      lockEncryptedMessages();
    }
  });

  const initTab = () => {
    const hash = window.location.hash.replace("#", "");
    if (hash === "register" || hash === "login") {
      switchTab(hash, false);
      return;
    }
    const saved = localStorage.getItem(AUTH_TAB_KEY);
    if (saved === "register" || saved === "login") {
      switchTab(saved, false);
      return;
    }
    switchTab("login", false);
  };

  initTab();
  showAuth();
  updatePasswordRules("");
  const bootstrap = async () => {
    const token = getToken();
    if (!token) return;
    const { ok, data } = await apiRequest("/api/me");
    if (!ok) {
      clearToken();
      return;
    }
    showChat(data.username, true);
  };
  bootstrap();
  setStatus("disconnected");
})();
