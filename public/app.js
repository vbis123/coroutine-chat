(async () => {
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
  const menuChatBtn = document.getElementById("menu-chat");
  const menuVoiceBtn = document.getElementById("menu-voice");
  const menuCallsBtn = document.getElementById("menu-calls");
  const panelChat = document.getElementById("panel-chat");
  const panelVoice = document.getElementById("panel-voice");
  const panelCalls = document.getElementById("panel-calls");
  const voiceJoinBtn = document.getElementById("voice-join");
  const voiceLeaveBtn = document.getElementById("voice-leave");
  const voiceMuteBtn = document.getElementById("voice-mute");
  const voicePttBtn = document.getElementById("voice-ptt");
  const voiceMicStatus = document.getElementById("voice-mic-status");
  const voiceWarning = document.getElementById("voice-warning");
  const voiceSecretHint = document.getElementById("voice-secret-hint");
  const voiceParticipantsEl = document.getElementById("voice-participants");
  const voiceRemoteAudioEl = document.getElementById("voice-remote-audio");
  const dndToggle = document.getElementById("dnd-toggle");
  const callStatusEl = document.getElementById("call-status");
  const callDebugEl = document.getElementById("call-debug");
  const callMuteBtn = document.getElementById("call-mute");
  const callHangupBtn = document.getElementById("call-hangup");
  const callCancelBtn = document.getElementById("call-cancel");
  const callAcceptBtn = document.getElementById("call-accept");
  const callRejectBtn = document.getElementById("call-reject");
  const incomingCallEl = document.getElementById("incoming-call");
  const outgoingCallEl = document.getElementById("outgoing-call");
  const incomingTextEl = document.getElementById("incoming-text");
  const outgoingTextEl = document.getElementById("outgoing-text");
  const callRemoteAudioEl = document.getElementById("call-remote-audio");
  const callMicMeterEl = document.getElementById("call-mic-meter");
  const userListEl = document.getElementById("user-list");
  const soundUnlockEl = document.getElementById("sound-unlock");
  const soundUnlockBtn = document.getElementById("sound-unlock-btn");
  const e2eeToggle = document.getElementById("e2ee-toggle");
  const e2eeStatus = document.getElementById("e2ee-status");

  let ws = null;
  let reconnectAttempts = 0;
  let reconnectTimer = null;
  let openedAt = 0;
  let registeredName = "";
  let manualDisconnect = false;
  let lastVoiceSecretNoticeAt = 0;

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const knownNicknames = new Set();
  const backoffDelays = [500, 1000, 2000, 5000, 10000];
  const WHO_MSG = "::who::";
  const IAM_PREFIX = "::iam::";
  const AUTH_TOKEN_KEY = "authToken";
  const AUTH_TAB_KEY = "authTab";
  const DND_KEY = "callDnd";
  const BLOCKED_KEY = "callBlocked";
  const loadAppConfig = async () => {
    if (window.__APP_CONFIG__) return window.__APP_CONFIG__;
    try {
      const r = await fetch("/config.json", { cache: "no-store" });
      if (r.ok) window.__APP_CONFIG__ = await r.json();
    } catch (_) {}
    return window.__APP_CONFIG__ || {};
  };

  const appConfig = await loadAppConfig();
  const VOICE_LIMIT = Number(appConfig.voiceLimit || 6);
  const CALL_TIMEOUT_MS = 30000;
  const DEBUG_E2EE = true;

  const STATUS_TEXT = {
    disconnected: "Отключено",
    connecting: "Подключение",
    connected: "Подключено",
    reconnecting: "Переподключение",
  };

  const voice = {
    joined: false,
    muted: false,
    localStream: null,
    peers: new Map(),
    roster: new Map(),
    speaking: new Map(),
    analyserTimers: new Map(),
    remoteAudioEls: new Map(),
    pttActive: false,
    pttRestoreMuted: true,
    audioCtx: null,
  };
  let voiceLocalSpeaking = false;

  const call = {
    fsm: null,
    connection: null,
    localStream: null,
    remoteStream: null,
    localAnalyser: null,
    analyserTimer: null,
    audioCtx: null,
    iceQueue: [],
    callId: null,
    peerId: null,
    e2eeEnabled: false,
    e2eeReady: false,
    e2eeKeyPair: null,
    e2eeWrappingKey: null,
    e2eeCallKey: null,
    e2eeTimeout: null,
    inviteTimeout: null,
    e2eeRequestedByPeer: false,
    e2eePendingGo: false,
    e2eePubkeyRetry: null,
    e2eeReadyRetry: null,
    e2eeGoRetry: null,
    e2eeGoAcked: false,
    e2eeHandshakeStarting: false,
    e2eeKeyRequested: false,
    e2eeSentPubkey: false,
  };

  const inviteCooldowns = new Map();
  let blockedUsers = new Set();
  let lastVoiceState = { muted: true, speaking: false };
  let lastVoiceStateAt = 0;

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
  const getVoiceRoom = () => getSecret();
  const hasVoiceSecret = () => Boolean(getVoiceRoom());
  const getActiveVoiceRoom = () => voice.room || getVoiceRoom();

  const connect = () => {
    if (!hasNickname()) return;
      const wsProto = location.protocol === "https:" ? "wss://" : "ws://";
      const wsUrl = `${wsProto}${location.host}/ws`;

    setStatus("connecting");
    ws = new WebSocket(wsUrl);

    ws.addEventListener("open", () => {
      openedAt = Date.now();
      reconnectAttempts = 0;
      setStatus("connected");
      sendNickname();
      sendWho();
      sendVoiceWho();
      nicknameEl.disabled = true;
      connectBtn.textContent = "Отключиться";
      updateVoiceUI();
    });

    ws.addEventListener("message", (event) => {
      const text = typeof event.data === "string" ? event.data : "";
      const signal = window.Signaling ? window.Signaling.parseSignal(text) : null;
      if (signal) {
        handleSignal(signal);
        return;
      }
      handleIncoming(text);
    });

    ws.addEventListener("close", () => {
      setStatus("disconnected");
      nicknameEl.disabled = false;
      connectBtn.textContent = "Подключиться";
      registeredName = "";
      cleanupVoice("ws_closed");
      cleanupCall("disconnect");
      updateVoiceUI();
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
      updateVoiceUI();
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

  const renderNicknames = () => {
    nicknamesEl.innerHTML = "";
    Array.from(knownNicknames)
      .sort((a, b) => a.localeCompare(b))
      .forEach((nickname) => {
        const option = document.createElement("option");
        option.value = nickname;
        nicknamesEl.appendChild(option);
      });
    renderUserList();
  };

  const addNickname = (name) => {
    if (!name) return;
    if (knownNicknames.has(name)) return;
    knownNicknames.add(name);
    renderNicknames();
  };

  const removeNickname = (name) => {
    if (!name) return;
    if (!knownNicknames.has(name)) return;
    knownNicknames.delete(name);
    renderNicknames();
  };

  const loadBlocked = () => {
    try {
      const raw = localStorage.getItem(BLOCKED_KEY);
      if (!raw) return new Set();
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return new Set(parsed.filter((name) => typeof name === "string"));
    } catch (_) {}
    return new Set();
  };

  const saveBlocked = () => {
    localStorage.setItem(BLOCKED_KEY, JSON.stringify(Array.from(blockedUsers)));
  };

  const isBlocked = (name) => blockedUsers.has(name);

  const loadDnd = () => localStorage.getItem(DND_KEY) === "1";

  const saveDnd = (value) => {
    localStorage.setItem(DND_KEY, value ? "1" : "0");
  };

  const canPlaceCall = () => call.fsm.state === "idle";

  const renderUserList = () => {
    if (!userListEl) return;
    userListEl.innerHTML = "";
    const me = getNickname();
    const names = Array.from(knownNicknames).filter((name) => name && name !== me);
    if (names.length === 0) {
      const empty = document.createElement("div");
      empty.className = "muted";
      empty.textContent = "Нет онлайн пользователей.";
      userListEl.appendChild(empty);
      return;
    }
    names
      .sort((a, b) => a.localeCompare(b))
      .forEach((name) => {
        const row = document.createElement("div");
        row.className = `user-row${isBlocked(name) ? " blocked" : ""}`;
        const label = document.createElement("div");
        label.textContent = name;
        const callBtn = document.createElement("button");
        callBtn.textContent = "Позвонить";
        callBtn.disabled = !canPlaceCall() || isBlocked(name);
        callBtn.addEventListener("click", () => {
          startOutgoingCall(name);
        });
        const blockBtn = document.createElement("button");
        blockBtn.textContent = isBlocked(name) ? "Разблокировать" : "Блок";
        blockBtn.className = "danger";
        blockBtn.addEventListener("click", () => {
          if (isBlocked(name)) {
            blockedUsers.delete(name);
          } else {
            blockedUsers.add(name);
          }
          saveBlocked();
          renderUserList();
        });
        row.appendChild(label);
        row.appendChild(callBtn);
        row.appendChild(blockBtn);
        userListEl.appendChild(row);
      });
  };

  const parseIncoming = (text) => {
    if (!text) return null;

    const joinMatch = text.match(/^\*\s+(.+?)\s+joined\s+\*$/);
    if (joinMatch) {
      return { kind: "system", body: text, name: joinMatch[1], action: "join" };
    }

    const leaveMatch = text.match(/^\*\s+(.+?)\s+left\s+\*$/);
    if (leaveMatch) {
      return { kind: "system", body: text, name: leaveMatch[1], action: "leave" };
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
      if (parsed.name && parsed.action === "join") addNickname(parsed.name);
      if (parsed.name && parsed.action === "leave") removeNickname(parsed.name);
      renderMessage({ kind: "system", body: parsed.body });
      return;
    }

    addNickname(parsed.from);

    if (parsed.body === WHO_MSG) {
      sendIam();
      return;
    }

    if (parsed.body.startsWith(IAM_PREFIX)) {
      const name = parsed.body.slice(IAM_PREFIX.length).trim();
      addNickname(name);
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
    addNickname(nickname);
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

  const isVoiceSignal = (message) => {
    if (!message || !message.type) return false;
    if (message.type.startsWith("voice:")) return true;
    if (message.type.startsWith("webrtc:")) {
      return !(message.payload && message.payload.callId);
    }
    return false;
  };

  const sendSignal = (message) => {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    if (!message || !message.type) return;
    const id = getNickname();
    if (!id) return;
    const payload = { from: id, ...message };
    if (isVoiceSignal(message)) {
      const room = message.room || getActiveVoiceRoom();
      if (room) payload.room = room;
    }
    ws.send(JSON.stringify(payload));
  };

  const sendVoiceWho = () => {
    const room = getVoiceRoom();
    if (!room) return;
    sendSignal({ type: "voice:who", room });
  };

  const updateVoiceUI = () => {
    const hasSecret = hasVoiceSecret();
    voiceJoinBtn.classList.toggle("hidden", voice.joined);
    voiceLeaveBtn.classList.toggle("hidden", !voice.joined);
    voiceJoinBtn.disabled = !hasSecret || !ws || ws.readyState !== WebSocket.OPEN;
    voiceLeaveBtn.disabled = !voice.joined;
    voiceMuteBtn.disabled = !voice.joined;
    voicePttBtn.disabled = !voice.joined;
    voiceSecretHint.classList.toggle("hidden", hasSecret);
    voiceMuteBtn.textContent = voice.muted ? "Включить" : "Выключить";
    voiceMicStatus.textContent = voice.joined
      ? `Микрофон: ${voice.muted ? "мут" : "живой"}`
      : "Микрофон: выкл";
  };

  const setVoiceWarning = (show) => {
    voiceWarning.classList.toggle("hidden", !show);
  };

  const renderVoiceParticipants = () => {
    voiceParticipantsEl.innerHTML = "";
    const entries = Array.from(voice.roster.entries()).sort((a, b) => a[0].localeCompare(b[0]));
    entries.forEach(([id, state]) => {
      const row = document.createElement("div");
      const speaking = Boolean(state.speaking);
      row.className = `voice-participant${speaking ? " speaking" : ""}`;
      const label = document.createElement("span");
      label.textContent = id;
      const status = document.createElement("span");
      status.className = "state";
      status.textContent = state.muted ? "muted" : speaking ? "speaking" : "listening";
      row.appendChild(label);
      row.appendChild(status);
      voiceParticipantsEl.appendChild(row);
    });
  };

  const ensureVoiceAudioCtx = async () => {
    if (!voice.audioCtx) {
      voice.audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
    if (voice.audioCtx.state === "suspended") {
      await voice.audioCtx.resume();
    }
  };

  const monitorSpeaking = async (stream, id, onChange) => {
    if (!stream) return;
    await ensureVoiceAudioCtx();
    const source = voice.audioCtx.createMediaStreamSource(stream);
    const analyser = voice.audioCtx.createAnalyser();
    analyser.fftSize = 512;
    source.connect(analyser);
    const data = new Uint8Array(analyser.frequencyBinCount);
    let speaking = false;
    const interval = setInterval(() => {
      analyser.getByteTimeDomainData(data);
      let sum = 0;
      for (let i = 0; i < data.length; i += 1) {
        const v = (data[i] - 128) / 128;
        sum += v * v;
      }
      const rms = Math.sqrt(sum / data.length);
      const nextSpeaking = rms > 0.05;
      if (nextSpeaking !== speaking) {
        speaking = nextSpeaking;
        onChange(speaking);
      }
    }, 200);
    voice.analyserTimers.set(id, interval);
  };

  const stopSpeakingMonitor = (id) => {
    const timer = voice.analyserTimers.get(id);
    if (timer) clearInterval(timer);
    voice.analyserTimers.delete(id);
  };

  const attachVoiceAudio = (peerId, stream) => {
    if (!voiceRemoteAudioEl || !stream) return;
    let audio = voice.remoteAudioEls.get(peerId);
    if (!audio) {
      audio = document.createElement("audio");
      audio.autoplay = true;
      audio.playsInline = true;
      audio.controls = false;
      audio.preload = "auto";
      audio.setAttribute("playsinline", "");
      audio.setAttribute("webkit-playsinline", "");
      audio.dataset.peerId = peerId;
      voiceRemoteAudioEl.appendChild(audio);
      voice.remoteAudioEls.set(peerId, audio);
    }
    if (audio.srcObject !== stream) {
      audio.srcObject = stream;
    }
  };

  const detachVoiceAudio = (peerId) => {
    const audio = voice.remoteAudioEls.get(peerId);
    if (!audio) return;
    audio.srcObject = null;
    audio.remove();
    voice.remoteAudioEls.delete(peerId);
  };

  const clearVoiceAudio = () => {
    for (const peerId of Array.from(voice.remoteAudioEls.keys())) {
      detachVoiceAudio(peerId);
    }
  };

  const sendVoiceState = (muted, speaking) => {
    if (!voice.joined) return;
    const now = Date.now();
    const changed = muted !== lastVoiceState.muted || speaking !== lastVoiceState.speaking;
    if (!changed && now - lastVoiceStateAt < 1000) return;
    lastVoiceState = { muted, speaking };
    lastVoiceStateAt = now;
    sendSignal({
      type: "voice:state",
      payload: { muted, speaking },
    });
  };

  const setupVoicePeer = (peerId) => {
    if (voice.peers.has(peerId)) return voice.peers.get(peerId);
    const connection = WebRTCCall.createConnection({
      onIceCandidate: (candidate) => {
        sendSignal({
          type: "webrtc:ice",
          to: peerId,
          payload: { candidate },
        });
      },
      onTrack: (stream) => {
        const peer = voice.peers.get(peerId);
        if (peer) {
          peer.remoteStream = stream;
        }
        attachVoiceAudio(peerId, stream);
        monitorSpeaking(stream, peerId, (speaking) => {
          const existing = voice.roster.get(peerId) || {};
          voice.roster.set(peerId, { ...existing, speaking });
          renderVoiceParticipants();
        });
      },
    });
    if (voice.localStream) {
      connection.addLocalStream(voice.localStream);
    }
    const peer = {
      pc: connection,
      iceQueue: [],
      remoteStream: null,
      readyForCandidates: false,
    };
    voice.peers.set(peerId, peer);
    console.log("[voice] peer created:", peerId);
    return peer;
  };

  const closeVoicePeer = (peerId) => {
    const peer = voice.peers.get(peerId);
    if (!peer) return;
    try {
      peer.pc.close();
    } catch (_) {}
    voice.peers.delete(peerId);
    stopSpeakingMonitor(peerId);
    detachVoiceAudio(peerId);
  };

  const shouldCreateOffer = (localId, remoteId) => localId.localeCompare(remoteId) < 0;

  const joinVoice = async () => {
    setVoiceWarning(false);
    if (voice.joined) return;
    const room = getVoiceRoom();
    if (!room) {
      updateVoiceUI();
      const now = Date.now();
      if (now - lastVoiceSecretNoticeAt > 4000) {
        lastVoiceSecretNoticeAt = now;
        renderMessage({
          kind: "system",
          body: "Для голосового чата заполните поле «Секрет» одинаковым кодовым словом.",
        });
      }
      return;
    }
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      setVoiceWarning(true);
      return;
    }
    if (voice.roster.size >= VOICE_LIMIT) {
      setVoiceWarning(true);
      return;
    }
    try {
      voice.room = room;
      voice.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
      voice.joined = true;
      voice.muted = false;
      voiceJoinBtn.blur();
      updateVoiceUI();
      console.log("[voice] joined");
      sendSignal({
        type: "voice:join",
        payload: { muted: false, speaking: false },
      });
      monitorSpeaking(voice.localStream, "local", (speaking) => {
        voiceLocalSpeaking = speaking;
        const selfState = voice.roster.get(getNickname()) || {};
        voice.roster.set(getNickname(), { ...selfState, speaking });
        renderVoiceParticipants();
        sendVoiceState(voice.muted, voiceLocalSpeaking);
      });
      voice.roster.set(getNickname(), { muted: voice.muted, speaking: false });
      renderVoiceParticipants();
      for (const peerId of voice.roster.keys()) {
        if (peerId === getNickname()) continue;
        const peer = setupVoicePeer(peerId);
        if (shouldCreateOffer(getNickname(), peerId)) {
          const offer = await peer.pc.createOffer();
          sendSignal({
            type: "webrtc:offer",
            to: peerId,
            payload: { sdp: offer },
          });
        }
      }
    } catch (err) {
      console.error("[voice] getUserMedia error:", err);
      setVoiceWarning(true);
    }
  };

  const leaveVoice = () => {
    if (!voice.joined) return;
    sendSignal({ type: "voice:leave" });
    cleanupVoice("leave");
  };

  const cleanupVoice = (reason) => {
    if (reason) console.log("[voice] cleanup:", reason);
    voice.joined = false;
    voice.muted = false;
    voiceLocalSpeaking = false;
    voice.room = null;
    stopSpeakingMonitor("local");
    for (const peerId of Array.from(voice.peers.keys())) {
      closeVoicePeer(peerId);
    }
    if (voice.localStream) {
      voice.localStream.getTracks().forEach((track) => track.stop());
      voice.localStream = null;
    }
    voice.roster.clear();
    renderVoiceParticipants();
    setVoiceWarning(false);
    clearVoiceAudio();
    updateVoiceUI();
  };

  const toggleVoiceMute = () => {
    if (!voice.joined || !voice.localStream) return;
    voice.muted = !voice.muted;
    voice.localStream.getAudioTracks().forEach((track) => {
      track.enabled = !voice.muted;
    });
    sendVoiceState(voice.muted, voiceLocalSpeaking);
    const selfState = voice.roster.get(getNickname()) || {};
    voice.roster.set(getNickname(), { ...selfState, muted: voice.muted });
    renderVoiceParticipants();
    updateVoiceUI();
  };

  const pttDown = () => {
    if (!voice.joined || !voice.localStream) return;
    if (voice.pttActive) return;
    voice.pttActive = true;
    voice.pttRestoreMuted = voice.muted;
    voice.muted = false;
    voice.localStream.getAudioTracks().forEach((track) => {
      track.enabled = true;
    });
    sendVoiceState(voice.muted, voiceLocalSpeaking);
    updateVoiceUI();
  };

  const pttUp = () => {
    if (!voice.joined || !voice.localStream) return;
    if (!voice.pttActive) return;
    voice.pttActive = false;
    voice.muted = voice.pttRestoreMuted;
    voice.localStream.getAudioTracks().forEach((track) => {
      track.enabled = !voice.muted;
    });
    sendVoiceState(voice.muted, voiceLocalSpeaking);
    updateVoiceUI();
  };

  const handleVoiceOffer = async (from, sdp) => {
    if (!voice.joined) return;
    const peer = setupVoicePeer(from);
    try {
      await peer.pc.setRemoteDescription(new RTCSessionDescription(sdp));
    } catch (err) {
      console.error("[voice] setRemoteDescription error:", err);
      return;
    }
    peer.readyForCandidates = true;
    while (peer.iceQueue.length > 0) {
      try {
        await peer.pc.addIceCandidate(peer.iceQueue.shift());
      } catch (err) {
        console.error("[voice] addIceCandidate error:", err);
      }
    }
    const answer = await peer.pc.createAnswer();
    sendSignal({
      type: "webrtc:answer",
      to: from,
      payload: { sdp: answer },
    });
  };

  const handleVoiceAnswer = async (from, sdp) => {
    const peer = voice.peers.get(from);
    if (!peer) return;
    try {
      await peer.pc.setRemoteDescription(new RTCSessionDescription(sdp));
    } catch (err) {
      console.error("[voice] setRemoteDescription error:", err);
      return;
    }
    peer.readyForCandidates = true;
    while (peer.iceQueue.length > 0) {
      try {
        await peer.pc.addIceCandidate(peer.iceQueue.shift());
      } catch (err) {
        console.error("[voice] addIceCandidate error:", err);
      }
    }
  };

  const handleVoiceIce = async (from, candidate) => {
    const peer = setupVoicePeer(from);
    if (peer.readyForCandidates) {
      try {
        await peer.pc.addIceCandidate(candidate);
      } catch (err) {
        console.error("[voice] addIceCandidate error:", err);
      }
    } else {
      peer.iceQueue.push(candidate);
    }
  };

  const createCallId = () => {
    if (crypto.randomUUID) return crypto.randomUUID();
    return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  };

  const updateE2eeStatus = (text) => {
    e2eeStatus.textContent = text;
  };

  const resetCallDebug = (title) => {
    if (!DEBUG_E2EE || !callDebugEl) return;
    callDebugEl.classList.remove("hidden");
    callDebugEl.innerHTML = "";
    if (title) {
      const header = document.createElement("div");
      header.textContent = title;
      callDebugEl.appendChild(header);
    }
  };

  const e2eeDebug = (text) => {
    if (!DEBUG_E2EE) return;
    if (callDebugEl) {
      callDebugEl.classList.remove("hidden");
      const line = document.createElement("div");
      const ts = new Date().toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
      line.textContent = `[${ts}] ${text}`;
      callDebugEl.appendChild(line);
      while (callDebugEl.childNodes.length > 80) {
        callDebugEl.removeChild(callDebugEl.firstChild);
      }
    } else {
      renderMessage({ kind: "system", body: text });
    }
    console.log(`[e2ee] ${text}`);
  };

  if (DEBUG_E2EE && callDebugEl) {
    callDebugEl.classList.remove("hidden");
    callDebugEl.textContent = "E2EE debug on";
  }

  const updateCallUI = () => {
    const state = call.fsm.state;
    callMuteBtn.disabled = state !== "in_call";
    callHangupBtn.disabled = state !== "in_call";
    outgoingCallEl.classList.toggle("hidden", state !== "outgoing");
    incomingCallEl.classList.toggle("hidden", state !== "incoming");
    if (state === "idle") {
      callStatusEl.textContent = "Звонков нет.";
    } else if (state === "outgoing") {
      callStatusEl.textContent = `Звонок ${call.peerId}...`;
    } else if (state === "incoming") {
      callStatusEl.textContent = `Входящий от ${call.peerId}.`;
    } else if (state === "in_call") {
      callStatusEl.textContent = `Разговор с ${call.peerId}.`;
    } else {
      callStatusEl.textContent = "Завершаем звонок...";
    }
    if (state === "in_call" && call.localStream) {
      const track = call.localStream.getAudioTracks()[0];
      if (track) {
        callMuteBtn.textContent = track.enabled ? "Выключить" : "Включить";
      }
    } else {
      callMuteBtn.textContent = "Выключить";
    }
    renderUserList();
  };

  const setupCallAudio = () => {
    callRemoteAudioEl.innerHTML = "";
    if (!call.remoteStream) return;
    const audio = document.createElement("audio");
    audio.autoplay = true;
    audio.srcObject = call.remoteStream;
    callRemoteAudioEl.appendChild(audio);
  };

  const startCallMeter = async () => {
    if (!call.localStream) return;
    if (!call.audioCtx) {
      call.audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
    if (call.audioCtx.state === "suspended") {
      await call.audioCtx.resume();
    }
    const source = call.audioCtx.createMediaStreamSource(call.localStream);
    const analyser = call.audioCtx.createAnalyser();
    analyser.fftSize = 512;
    source.connect(analyser);
    call.localAnalyser = analyser;
    const data = new Uint8Array(analyser.frequencyBinCount);
    call.analyserTimer = setInterval(() => {
      analyser.getByteTimeDomainData(data);
      let sum = 0;
      for (let i = 0; i < data.length; i += 1) {
        const v = (data[i] - 128) / 128;
        sum += v * v;
      }
      const rms = Math.sqrt(sum / data.length);
      const pct = Math.min(100, Math.round(rms * 200));
      callMicMeterEl.style.width = `${pct}%`;
    }, 200);
  };

  const stopCallMeter = () => {
    if (call.analyserTimer) clearInterval(call.analyserTimer);
    call.analyserTimer = null;
    callMicMeterEl.style.width = "0%";
  };

  const updateSoundUnlock = () => {
    if (AudioAlerts.isUnlocked()) {
      soundUnlockEl.classList.add("hidden");
    } else if (call.fsm.state === "incoming" || call.fsm.state === "outgoing") {
      soundUnlockEl.classList.remove("hidden");
    } else {
      soundUnlockEl.classList.add("hidden");
    }
  };

  const cleanupCall = (reason) => {
    if (reason) console.log("[call] cleanup:", reason);
    AudioAlerts.stopAllTones();
    if (call.connection) {
      call.connection.close();
      call.connection = null;
    }
    if (call.localStream) {
      call.localStream.getTracks().forEach((track) => track.stop());
      call.localStream = null;
    }
    call.remoteStream = null;
    callRemoteAudioEl.innerHTML = "";
    call.peerId = null;
    call.callId = null;
    call.iceQueue = [];
    call.e2eeKeyPair = null;
    call.e2eeWrappingKey = null;
    call.e2eeCallKey = null;
    call.e2eeReady = false;
    call.e2eeRequestedByPeer = false;
    call.e2eePendingGo = false;
    call.e2eeGoAcked = false;
    call.e2eeHandshakeStarting = false;
    call.e2eeKeyRequested = false;
    call.e2eeSentPubkey = false;
    if (call.e2eePubkeyRetry) clearInterval(call.e2eePubkeyRetry);
    call.e2eePubkeyRetry = null;
    if (call.e2eeReadyRetry) clearInterval(call.e2eeReadyRetry);
    call.e2eeReadyRetry = null;
    if (call.e2eeGoRetry) clearInterval(call.e2eeGoRetry);
    call.e2eeGoRetry = null;
    if (call.e2eeTimeout) clearTimeout(call.e2eeTimeout);
    call.e2eeTimeout = null;
    if (call.inviteTimeout) clearTimeout(call.inviteTimeout);
    call.inviteTimeout = null;
    stopCallMeter();
    updateE2eeStatus("E2EE выключено");
    call.fsm.reset();
    updateSoundUnlock();
  };

  const createCallConnection = (peerId) => {
    call.connection = WebRTCCall.createConnection({
      onIceCandidate: (candidate) => {
        sendSignal({
          type: "webrtc:ice",
          to: peerId,
          payload: { callId: call.callId, candidate },
        });
      },
      onTrack: (stream) => {
        call.remoteStream = stream;
        setupCallAudio();
      },
      onSender: (sender) => {
        if (call.e2eeReady && call.e2eeCallKey && E2EE.supports) {
          E2EE.attachSenderTransform(sender, call.e2eeCallKey);
        }
      },
      onReceiver: (receiver) => {
        if (call.e2eeReady && call.e2eeCallKey && E2EE.supports) {
          E2EE.attachReceiverTransform(receiver, call.e2eeCallKey);
        }
      },
      onConnectionState: (state) => {
        if (state === "failed" || state === "disconnected") {
          sendSignal({ type: "call:hangup", to: peerId, payload: { callId: call.callId } });
          cleanupCall("connection_failed");
        }
      },
    });
    if (call.localStream) {
      call.connection.addLocalStream(call.localStream);
    }
    console.log("[call] peer created:", peerId);
    tryEnableE2EE();
  };

  const prepareLocalCallStream = async () => {
    if (call.localStream) return;
    call.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
  };

  const startOutgoingCall = async (peerId) => {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    if (!peerId || !canPlaceCall()) return;
    if (inviteCooldowns.has(peerId) && Date.now() - inviteCooldowns.get(peerId) < 10000) {
      renderMessage({ kind: "system", body: `Слишком частые звонки пользователю ${peerId}.` });
      return;
    }
    inviteCooldowns.set(peerId, Date.now());
    await AudioAlerts.ensureAudioUnlocked();
    call.peerId = peerId;
    call.callId = createCallId();
    resetCallDebug(`E2EE debug on (call ${call.callId.slice(0, 6)})`);
    call.e2eeEnabled = e2eeToggle.checked && E2EE.supports;
    e2eeDebug(
      `E2EE: исходящий, supports=${E2EE.supports ? "yes" : "no"}, toggle=${e2eeToggle.checked ? "on" : "off"}`
    );
    updateE2eeStatus(
      call.e2eeEnabled ? "E2EE: подключение..." : E2EE.supports ? "E2EE выключено" : "E2EE не поддерживается"
    );
    call.fsm.transition("outgoing", { callId: call.callId, peerId });
    updateCallUI();
    outgoingTextEl.textContent = `Звоним ${peerId}...`;
    sendSignal({
      type: "call:invite",
      to: peerId,
      payload: {
        callId: call.callId,
        e2ee: { enabled: call.e2eeEnabled, supported: E2EE.supports },
      },
    });
    if (!(await AudioAlerts.playRingbackLoop())) {
      updateSoundUnlock();
    }
    call.inviteTimeout = setTimeout(() => {
      call.fsm.transition("timeout");
      sendSignal({ type: "call:hangup", to: peerId, payload: { callId: call.callId } });
      cleanupCall("timeout");
      renderMessage({ kind: "system", body: "Звонок отменен по таймауту." });
    }, CALL_TIMEOUT_MS);
  };

  const handleIncomingInvite = async (msg) => {
    const from = msg.from;
    const callId = msg.payload && msg.payload.callId;
    if (!from || !callId) return;
    if (isBlocked(from)) {
      sendSignal({ type: "call:reject", to: from, payload: { callId, reason: "blocked" } });
      return;
    }
    if (dndToggle.checked) {
      sendSignal({ type: "call:reject", to: from, payload: { callId, reason: "dnd" } });
      renderMessage({ kind: "system", body: `Пропущенный звонок от ${from} (DND).` });
      return;
    }
    if (!canPlaceCall()) {
      sendSignal({ type: "call:reject", to: from, payload: { callId, reason: "busy" } });
      return;
    }
    call.peerId = from;
    call.callId = callId;
    resetCallDebug(`E2EE debug on (call ${call.callId.slice(0, 6)})`);
    const remoteE2ee = Boolean(msg.payload && msg.payload.e2ee && msg.payload.e2ee.enabled);
    call.e2eeRequestedByPeer = remoteE2ee;
    call.e2eeEnabled = Boolean(E2EE.supports && (remoteE2ee || e2eeToggle.checked));
    e2eeDebug(
      `E2EE: входящий, supports=${E2EE.supports ? "yes" : "no"}, remote=${remoteE2ee ? "on" : "off"}, toggle=${
        e2eeToggle.checked ? "on" : "off"
      }`
    );
    e2eeToggle.checked = call.e2eeEnabled;
    updateE2eeStatus(
      call.e2eeEnabled ? "E2EE: подключение..." : E2EE.supports ? "E2EE выключено" : "E2EE не поддерживается"
    );
    if (call.e2eeEnabled) {
      if (call.e2eeRequestedByPeer) {
        renderMessage({ kind: "system", body: "E2EE включено по запросу звонящего." });
      }
    }
    call.fsm.transition("incoming", { callId, peerId: from });
    updateCallUI();
    incomingTextEl.textContent = `Входящий от ${from}`;
    sendSignal({ type: "call:ringing", to: from, payload: { callId } });
    if (!(await AudioAlerts.playRingtoneLoop())) {
      updateSoundUnlock();
    }
  };

  const acceptIncomingCall = async () => {
    if (call.fsm.state !== "incoming") return;
    await AudioAlerts.ensureAudioUnlocked();
    AudioAlerts.stopAllTones();
    sendSignal({ type: "call:accept", to: call.peerId, payload: { callId: call.callId } });
    e2eeDebug(
      `E2EE: accept, enabled=${call.e2eeEnabled ? "yes" : "no"}, supports=${E2EE.supports ? "yes" : "no"}`
    );
    if (call.e2eeEnabled && !call.e2eeRequestedByPeer) {
      sendSignal({ type: "e2ee:enabled", to: call.peerId, payload: { callId: call.callId } });
    }
    call.fsm.transition("accepted");
    updateCallUI();
    await prepareLocalCallStream();
    createCallConnection(call.peerId);
    startCallMeter();
    if (call.e2eeEnabled) {
      startE2EEHandshake();
    }
  };

  const rejectIncomingCall = (reason = "rejected") => {
    if (call.fsm.state !== "incoming") return;
    AudioAlerts.stopAllTones();
    sendSignal({ type: "call:reject", to: call.peerId, payload: { callId: call.callId, reason } });
    call.fsm.transition("rejected");
    cleanupCall("rejected");
  };

  const cancelOutgoingCall = () => {
    if (call.fsm.state !== "outgoing") return;
    AudioAlerts.stopAllTones();
    sendSignal({ type: "call:cancel", to: call.peerId, payload: { callId: call.callId } });
    call.fsm.transition("canceled");
    cleanupCall("canceled");
  };

  const hangupCall = () => {
    if (call.fsm.state !== "in_call") return;
    sendSignal({ type: "call:hangup", to: call.peerId, payload: { callId: call.callId } });
    call.fsm.transition("hangup");
    cleanupCall("hangup");
  };

  const setCallMute = () => {
    if (!call.localStream) return;
    const track = call.localStream.getAudioTracks()[0];
    if (!track) return;
    track.enabled = !track.enabled;
    callMuteBtn.textContent = track.enabled ? "Выключить" : "Включить";
  };

  const handleCallOffer = async (msg) => {
    if (!call.peerId || msg.from !== call.peerId) return;
    if (msg.payload.callId !== call.callId) return;
    if (!call.connection) {
      await prepareLocalCallStream();
      createCallConnection(call.peerId);
      startCallMeter();
      if (call.e2eeEnabled) {
        startE2EEHandshake();
      }
    }
    try {
      await call.connection.setRemoteDescription(new RTCSessionDescription(msg.payload.sdp));
    } catch (err) {
      console.error("[call] setRemoteDescription error:", err);
      return;
    }
    const answer = await call.connection.createAnswer();
    sendSignal({
      type: "webrtc:answer",
      to: call.peerId,
      payload: { callId: call.callId, sdp: answer },
    });
    for (const candidate of call.iceQueue) {
      try {
        await call.connection.addIceCandidate(candidate);
      } catch (err) {
        console.error("[call] addIceCandidate error:", err);
      }
    }
    call.iceQueue = [];
  };

  const handleCallAnswer = async (msg) => {
    if (!call.connection) return;
    if (msg.payload.callId !== call.callId) return;
    try {
      await call.connection.setRemoteDescription(new RTCSessionDescription(msg.payload.sdp));
    } catch (err) {
      console.error("[call] setRemoteDescription error:", err);
      return;
    }
    for (const candidate of call.iceQueue) {
      try {
        await call.connection.addIceCandidate(candidate);
      } catch (err) {
        console.error("[call] addIceCandidate error:", err);
      }
    }
    call.iceQueue = [];
  };

  const handleCallIce = async (msg) => {
    if (msg.payload.callId !== call.callId) return;
    if (!call.connection || !call.connection.pc.remoteDescription) {
      call.iceQueue.push(msg.payload.candidate);
      return;
    }
    try {
      await call.connection.addIceCandidate(msg.payload.candidate);
    } catch (err) {
      console.error("[call] addIceCandidate error:", err);
    }
  };

  const startE2EEHandshake = async () => {
    if (!call.e2eeEnabled || !E2EE.supports || call.e2eeReady) return;
    if (call.e2eeHandshakeStarting || call.e2eeKeyPair) {
      e2eeDebug("E2EE: рукопожатие уже запущено");
      return;
    }
    call.e2eeHandshakeStarting = true;
    call.e2eePendingGo = false;
    call.e2eeGoAcked = false;
    e2eeDebug("E2EE: старт рукопожатия");
    call.e2eeKeyPair = await KeyExchange.generateKeyPair();
    call.e2eeHandshakeStarting = false;
    call.e2eeKeyRequested = false;
    call.e2eeSentPubkey = false;
    const publicKeyJwk = await KeyExchange.exportPublicKey(call.e2eeKeyPair);
    e2eeDebug("E2EE: отправляем pubkey");
    const sendPubkey = () => {
      sendSignal({
        type: "e2ee:pubkey",
        to: call.peerId,
        payload: { callId: call.callId, publicKeyJwk },
      });
      call.e2eeSentPubkey = true;
    };
    sendPubkey();
    if (call.e2eePubkeyRetry) clearInterval(call.e2eePubkeyRetry);
    let pubkeyAttempts = 0;
    call.e2eePubkeyRetry = setInterval(() => {
      if (call.e2eeWrappingKey || call.e2eeReady || pubkeyAttempts >= 5) {
        clearInterval(call.e2eePubkeyRetry);
        call.e2eePubkeyRetry = null;
        return;
      }
      pubkeyAttempts += 1;
      e2eeDebug(`E2EE: повтор pubkey (${pubkeyAttempts})`);
      sendPubkey();
    }, 1000);
    if (call.e2eeTimeout) clearTimeout(call.e2eeTimeout);
    call.e2eeTimeout = setTimeout(() => {
      if (!call.e2eeReady) {
        call.e2eeEnabled = false;
        updateE2eeStatus("E2EE таймаут, используем DTLS-SRTP");
        sendSignal({ type: "e2ee:disabled", to: call.peerId, payload: { callId: call.callId } });
      }
    }, 10000);
  };

  const handleE2eePubkey = async (msg) => {
    if (msg.payload.callId !== call.callId) return;
    if (!E2EE.supports) return;
    if (!call.e2eeEnabled) {
      call.e2eeEnabled = true;
      e2eeToggle.checked = true;
      updateE2eeStatus("E2EE: подключение...");
      e2eeDebug("E2EE: авто-включение по pubkey");
    }
    if (!call.e2eeKeyPair) {
      e2eeDebug("E2EE: создаем ключи по pubkey");
      call.e2eeKeyPair = await KeyExchange.generateKeyPair();
      call.e2eeSentPubkey = false;
    }
    e2eeDebug("E2EE: получили pubkey");
    if (!call.fsm.context.initiator && !call.e2eeSentPubkey) {
      const selfPub = await KeyExchange.exportPublicKey(call.e2eeKeyPair);
      sendSignal({
        type: "e2ee:pubkey",
        to: call.peerId,
        payload: { callId: call.callId, publicKeyJwk: selfPub },
      });
      call.e2eeSentPubkey = true;
      e2eeDebug("E2EE: ответили pubkey");
    }
    const remoteKey = await KeyExchange.importPublicKey(msg.payload.publicKeyJwk);
    const wrappingKey = await KeyExchange.deriveWrappingKey(call.e2eeKeyPair.privateKey, remoteKey);
    call.e2eeWrappingKey = wrappingKey;
    if (!call.fsm.context.initiator) {
      call.e2eeCallKey = null;
    }
    if (call.fsm.context.initiator) {
      call.e2eeCallKey = KeyExchange.randomCallKey();
      const wrapped = await KeyExchange.wrapCallKey(wrappingKey, call.e2eeCallKey);
      e2eeDebug("E2EE: отправляем key");
      sendSignal({
        type: "e2ee:key",
        to: call.peerId,
        payload: { callId: call.callId, ivB64: wrapped.ivB64, encryptedKeyB64: wrapped.encryptedKeyB64 },
      });
      call.e2eePendingGo = true;
    } else {
      if (!call.e2eeKeyRequested) {
        call.e2eeKeyRequested = true;
        e2eeDebug("E2EE: ждем key от инициатора");
      }
    }
  };

  const handleE2eeKey = async (msg) => {
    if (msg.payload.callId !== call.callId) return;
    if (!call.e2eeEnabled || !call.e2eeWrappingKey) return;
    e2eeDebug("E2EE: получили key");
    call.e2eeCallKey = await KeyExchange.unwrapCallKey(
      call.e2eeWrappingKey,
      msg.payload.ivB64,
      msg.payload.encryptedKeyB64
    );
    call.e2eeKeyRequested = false;
    tryEnableE2EE();
    const sendReady = (ack = "") =>
      sendSignal({ type: "e2ee:ready", to: call.peerId, payload: { callId: call.callId, ack } });
    e2eeDebug("E2EE: отправляем ready");
    sendReady();
    if (call.e2eeReadyRetry) clearInterval(call.e2eeReadyRetry);
    let readyAttempts = 0;
    call.e2eeReadyRetry = setInterval(() => {
      if (call.e2eeReady || readyAttempts >= 5) {
        clearInterval(call.e2eeReadyRetry);
        call.e2eeReadyRetry = null;
        return;
      }
      readyAttempts += 1;
      e2eeDebug(`E2EE: повтор ready (${readyAttempts})`);
      sendReady();
    }, 1000);
  };

  const enableE2EETransforms = () => {
    if (!call.connection || !call.e2eeCallKey || call.e2eeReady) return;
    call.e2eeReady = true;
    if (call.e2eeTimeout) {
      clearTimeout(call.e2eeTimeout);
      call.e2eeTimeout = null;
    }
    updateE2eeStatus("E2EE включено");
    e2eeDebug("E2EE: трансформы включены");
    if (call.connection.pc) {
      call.connection.pc.getSenders().forEach((sender) => {
        if (sender.track && sender.track.kind === "audio") {
          E2EE.attachSenderTransform(sender, call.e2eeCallKey);
        }
      });
      call.connection.pc.getReceivers().forEach((receiver) => {
        if (receiver.track && receiver.track.kind === "audio") {
          E2EE.attachReceiverTransform(receiver, call.e2eeCallKey);
        }
      });
    }
  };

  const tryEnableE2EE = () => {
    if (!call.e2eeEnabled) return;
    if (!call.e2eeCallKey) return;
    if (!call.connection) return;
    enableE2EETransforms();
  };

  const handleSignal = async (msg) => {
    if (!msg || !msg.type) return;
    if (msg.type.startsWith("e2ee:")) {
      const msgCallId = msg.payload && msg.payload.callId ? msg.payload.callId : "none";
      e2eeDebug(`E2EE: recv ${msg.type} (callId=${msgCallId})`);
    }
    if (msg.type === "voice:state") {
      if (msg.payload && Array.isArray(msg.payload.participants)) {
        voice.roster = new Map(
          msg.payload.participants.map((p) => [p.id, { muted: p.muted, speaking: p.speaking }])
        );
        setVoiceWarning(voice.roster.size >= VOICE_LIMIT);
        renderVoiceParticipants();
        if (voice.joined) {
          for (const peerId of voice.roster.keys()) {
            if (peerId === getNickname()) continue;
            if (!voice.peers.has(peerId)) {
              setupVoicePeer(peerId);
              if (shouldCreateOffer(getNickname(), peerId)) {
                const peer = voice.peers.get(peerId);
                const offer = await peer.pc.createOffer();
                sendSignal({
                  type: "webrtc:offer",
                  to: peerId,
                  payload: { sdp: offer },
                });
              }
            }
          }
        }
      } else if (msg.from) {
        const existing = voice.roster.get(msg.from) || {};
        voice.roster.set(msg.from, { ...existing, ...msg.payload });
        renderVoiceParticipants();
      }
      return;
    }

    if (msg.type === "voice:join") {
      if (!msg.from) return;
      const existing = voice.roster.get(msg.from) || {};
      voice.roster.set(msg.from, { ...existing, muted: false, speaking: false });
      setVoiceWarning(voice.roster.size >= VOICE_LIMIT);
      renderVoiceParticipants();
      if (voice.joined && msg.from !== getNickname()) {
        setupVoicePeer(msg.from);
        if (shouldCreateOffer(getNickname(), msg.from)) {
          const peer = voice.peers.get(msg.from);
          const offer = await peer.pc.createOffer();
          sendSignal({
            type: "webrtc:offer",
            to: msg.from,
            payload: { sdp: offer },
          });
        }
      }
      return;
    }

    if (msg.type === "voice:leave") {
      if (!msg.from) return;
      voice.roster.delete(msg.from);
      closeVoicePeer(msg.from);
      setVoiceWarning(voice.roster.size >= VOICE_LIMIT);
      renderVoiceParticipants();
      return;
    }

    if (msg.type === "webrtc:offer") {
      if (!msg.payload || !msg.payload.sdp) return;
      if (msg.payload && msg.payload.callId) {
        await handleCallOffer(msg);
      } else {
        await handleVoiceOffer(msg.from, msg.payload.sdp);
      }
      return;
    }

    if (msg.type === "webrtc:answer") {
      if (!msg.payload || !msg.payload.sdp) return;
      if (msg.payload && msg.payload.callId) {
        await handleCallAnswer(msg);
      } else {
        await handleVoiceAnswer(msg.from, msg.payload.sdp);
      }
      return;
    }

    if (msg.type === "webrtc:ice") {
      if (!msg.payload || !msg.payload.candidate) return;
      if (msg.payload && msg.payload.callId) {
        await handleCallIce(msg);
      } else {
        await handleVoiceIce(msg.from, msg.payload.candidate);
      }
      return;
    }

    if (msg.type === "call:invite") {
      await handleIncomingInvite(msg);
      updateSoundUnlock();
      return;
    }

    if (msg.type === "call:ringing") {
      if (call.fsm.state === "outgoing") {
        if (msg.payload && msg.payload.callId !== call.callId) return;
        outgoingTextEl.textContent = `Звоним ${call.peerId}... (гудки)`;
      }
      return;
    }

    if (msg.type === "call:accept") {
      if (call.fsm.state !== "outgoing") return;
      if (msg.payload && msg.payload.callId !== call.callId) return;
      AudioAlerts.stopAllTones();
      if (call.inviteTimeout) clearTimeout(call.inviteTimeout);
      call.inviteTimeout = null;
      call.fsm.transition("accepted");
      updateCallUI();
      e2eeDebug(
        `E2EE: outgoing accept, enabled=${call.e2eeEnabled ? "yes" : "no"}, supports=${
          E2EE.supports ? "yes" : "no"
        }`
      );
      await prepareLocalCallStream();
      createCallConnection(call.peerId);
      startCallMeter();
      if (call.e2eeEnabled) {
        startE2EEHandshake();
      }
      const offer = await call.connection.createOffer();
      sendSignal({
        type: "webrtc:offer",
        to: call.peerId,
        payload: { callId: call.callId, sdp: offer },
      });
      AudioAlerts.playBeep("connect");
      return;
    }

    if (msg.type === "call:reject") {
      if (call.fsm.state === "outgoing" || call.fsm.state === "incoming") {
        if (msg.payload && msg.payload.callId !== call.callId) return;
        AudioAlerts.stopAllTones();
        const reason = (msg.payload && msg.payload.reason) || "rejected";
        renderMessage({ kind: "system", body: `Звонок отклонен (${reason}).` });
        call.fsm.transition("rejected");
        cleanupCall("rejected");
      }
      return;
    }

    if (msg.type === "call:cancel") {
      if (call.fsm.state === "incoming") {
        if (msg.payload && msg.payload.callId !== call.callId) return;
        AudioAlerts.stopAllTones();
        renderMessage({ kind: "system", body: "Вызов отменен." });
        call.fsm.transition("canceled");
        cleanupCall("canceled");
      }
      return;
    }

    if (msg.type === "call:hangup") {
      if (call.fsm.state !== "idle") {
        if (msg.payload && msg.payload.callId !== call.callId) return;
        AudioAlerts.stopAllTones();
        renderMessage({ kind: "system", body: "Звонок завершен." });
        call.fsm.transition("remote_hangup");
        cleanupCall("hangup");
      }
      return;
    }

    if (msg.type === "e2ee:pubkey") {
      await handleE2eePubkey(msg);
      return;
    }

    if (msg.type === "e2ee:key") {
      await handleE2eeKey(msg);
      return;
    }

    if (msg.type === "e2ee:ready") {
      if (msg.payload && msg.payload.callId !== call.callId) return;
      if (msg.payload && msg.payload.ack === "go") {
        e2eeDebug("E2EE: получили ack go");
        call.e2eeGoAcked = true;
        if (call.e2eeGoRetry) {
          clearInterval(call.e2eeGoRetry);
          call.e2eeGoRetry = null;
        }
        return;
      }
      if (!call.e2eeEnabled || !call.fsm.context.initiator || !call.e2eePendingGo) return;
      call.e2eePendingGo = false;
      const sendGo = () => {
        sendSignal({ type: "e2ee:go", to: call.peerId, payload: { callId: call.callId } });
      };
      e2eeDebug("E2EE: отправляем go");
      sendGo();
      enableE2EETransforms();
      if (call.e2eeGoRetry) clearInterval(call.e2eeGoRetry);
      let goAttempts = 0;
      call.e2eeGoRetry = setInterval(() => {
      if (call.e2eeGoAcked || goAttempts >= 5) {
        clearInterval(call.e2eeGoRetry);
        call.e2eeGoRetry = null;
        return;
      }
      goAttempts += 1;
      e2eeDebug(`E2EE: повтор go (${goAttempts})`);
      sendGo();
    }, 1000);
      return;
    }

    if (msg.type === "e2ee:go") {
      if (msg.payload && msg.payload.callId !== call.callId) return;
      if (!call.e2eeEnabled) return;
      e2eeDebug("E2EE: получили go");
      tryEnableE2EE();
      e2eeDebug("E2EE: отправляем ack go");
      sendSignal({ type: "e2ee:ready", to: call.peerId, payload: { callId: call.callId, ack: "go" } });
      if (call.e2eeReadyRetry) {
        clearInterval(call.e2eeReadyRetry);
        call.e2eeReadyRetry = null;
      }
      return;
    }

    if (msg.type === "e2ee:enabled") {
      if (msg.payload && msg.payload.callId !== call.callId) return;
      if (!E2EE.supports) {
        updateE2eeStatus("E2EE не поддерживается");
        return;
      }
      if (call.e2eeEnabled) {
        e2eeDebug("E2EE: сигнал enabled игнорирован (уже включено)");
        return;
      }
      e2eeDebug("E2EE: включено по сигналу");
      call.e2eeEnabled = true;
      e2eeToggle.checked = true;
      updateE2eeStatus("E2EE: подключение...");
      if (call.fsm.state === "in_call" || call.connection) {
        startE2EEHandshake();
      }
      return;
    }

    if (msg.type === "e2ee:disabled") {
      if (msg.payload && msg.payload.callId !== call.callId) return;
      e2eeDebug("E2EE: отключено по сигналу");
      call.e2eeEnabled = false;
      call.e2eePendingGo = false;
      updateE2eeStatus("E2EE выключено");
      return;
    }
  };

  const handleCallStateChange = (state, ctx, prev, meta) => {
    updateCallUI();
    if (state === "ending") {
      AudioAlerts.playBeep("end");
    }
    if (state === "idle" && meta && meta.reason === "timeout") {
      renderMessage({ kind: "system", body: "Звонок завершен (таймаут)." });
    }
  };

  call.fsm = CallFSM.create({ onStateChange: handleCallStateChange });

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

    addNickname(nickname);

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

  voiceJoinBtn.addEventListener("click", () => {
    setMainTab("voice");
    joinVoice();
  });

  voiceLeaveBtn.addEventListener("click", () => {
    leaveVoice();
  });

  voiceMuteBtn.addEventListener("click", () => {
    toggleVoiceMute();
  });

  voicePttBtn.addEventListener("mousedown", (event) => {
    event.preventDefault();
    pttDown();
  });

  voicePttBtn.addEventListener("mouseup", (event) => {
    event.preventDefault();
    pttUp();
  });

  voicePttBtn.addEventListener("mouseleave", () => {
    pttUp();
  });

  voicePttBtn.addEventListener("touchstart", (event) => {
    event.preventDefault();
    pttDown();
  });

  voicePttBtn.addEventListener("touchend", (event) => {
    event.preventDefault();
    pttUp();
  });

  const isTypingTarget = () => {
    const el = document.activeElement;
    if (!el) return false;
    return el.tagName === "INPUT" || el.tagName === "TEXTAREA";
  };

  document.addEventListener("keydown", (event) => {
    if (event.code !== "Space") return;
    if (isTypingTarget()) return;
    if (event.repeat) return;
    pttDown();
  });

  document.addEventListener("keyup", (event) => {
    if (event.code !== "Space") return;
    if (isTypingTarget()) return;
    pttUp();
  });

  callCancelBtn.addEventListener("click", () => {
    cancelOutgoingCall();
  });

  callAcceptBtn.addEventListener("click", () => {
    acceptIncomingCall();
  });

  callRejectBtn.addEventListener("click", () => {
    rejectIncomingCall();
  });

  callHangupBtn.addEventListener("click", () => {
    hangupCall();
  });

  callMuteBtn.addEventListener("click", () => {
    setCallMute();
  });

  soundUnlockBtn.addEventListener("click", async () => {
    await AudioAlerts.ensureAudioUnlocked();
    updateSoundUnlock();
  });

  dndToggle.addEventListener("change", () => {
    saveDnd(dndToggle.checked);
  });

  e2eeToggle.addEventListener("change", () => {
    if (!E2EE.supports) {
      e2eeToggle.checked = false;
      updateE2eeStatus("E2EE не поддерживается");
      return;
    }
    e2eeDebug(`E2EE: toggle ${e2eeToggle.checked ? "on" : "off"}`);
    updateE2eeStatus(e2eeToggle.checked ? "E2EE готово" : "E2EE выключено");
  });

  window.addEventListener("beforeunload", () => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      if (voice.joined) {
        sendSignal({ type: "voice:leave" });
      }
      if (call.fsm && call.fsm.state !== "idle" && call.peerId && call.callId) {
        sendSignal({ type: "call:hangup", to: call.peerId, payload: { callId: call.callId } });
      }
    }
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
    setMainTab("chat");
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

  const handleSecretChange = () => {
    const previousRoom = voice.room;
    lockEncryptedMessages();
    if (getSecret()) {
      tryDecryptStoredMessages();
    }
    updateVoiceUI();
    if (voice.joined && previousRoom && previousRoom !== getVoiceRoom()) {
      leaveVoice();
    }
    if (!voice.joined && previousRoom !== getVoiceRoom()) {
      voice.roster.clear();
      renderVoiceParticipants();
      setVoiceWarning(false);
    }
    if (menuVoiceBtn.classList.contains("active")) {
      sendVoiceWho();
    }
  };

  secretEl.addEventListener("input", handleSecretChange);
  secretEl.addEventListener("focus", () => {
    if (secretEl.value) {
      secretEl.value = "";
      lockEncryptedMessages();
      updateVoiceUI();
    }
  });

  const setMainTab = (tab) => {
    menuChatBtn.classList.toggle("active", tab === "chat");
    menuVoiceBtn.classList.toggle("active", tab === "voice");
    menuCallsBtn.classList.toggle("active", tab === "calls");
    menuChatBtn.setAttribute("aria-selected", tab === "chat" ? "true" : "false");
    menuVoiceBtn.setAttribute("aria-selected", tab === "voice" ? "true" : "false");
    menuCallsBtn.setAttribute("aria-selected", tab === "calls" ? "true" : "false");
    panelChat.classList.toggle("hidden", tab !== "chat");
    panelVoice.classList.toggle("hidden", tab !== "voice");
    panelCalls.classList.toggle("hidden", tab !== "calls");
    if (tab === "voice") {
      sendVoiceWho();
    }
  };

  menuChatBtn.addEventListener("click", () => setMainTab("chat"));
  menuVoiceBtn.addEventListener("click", () => setMainTab("voice"));
  menuCallsBtn.addEventListener("click", () => setMainTab("calls"));

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
  blockedUsers = loadBlocked();
  dndToggle.checked = loadDnd();
  if (!E2EE.supports) {
    e2eeToggle.disabled = true;
  }
  updateE2eeStatus(E2EE.supports ? "E2EE выключено" : "E2EE не поддерживается");
  updateVoiceUI();
  updateCallUI();
  renderUserList();
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
