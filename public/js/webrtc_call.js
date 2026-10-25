(() => {
  const connections = new Set();
  const buildIceServers = () => {
    const servers = [{ urls: "stun:stun.l.google.com:19302" }];
    const config = window.__APP_CONFIG__;
    if (!config) throw new Error("Configuration must be loaded before WebRTC");
    if (config.turn && config.turn.urls) {
      servers.push({
        urls: config.turn.urls,
        username: config.turn.username || "",
        credential: config.turn.credential || "",
      });
    }
    return servers;
  };

  const createConnection = (handlers = {}) => {
    const pc = new RTCPeerConnection({
      iceServers: buildIceServers(),
      iceTransportPolicy: window.__APP_CONFIG__.iceTransportPolicy || "all",
    });
    connections.add(pc);
    let remoteReady = false;
    let closed = false;
    const pendingIce = [];
    let operations = Promise.resolve();
    const serialize = (operation) => {
      const result = operations.then(() => {
        if (closed) throw new Error("Connection closed");
        return operation();
      });
      operations = result.catch(() => {});
      return result;
    };

    pc.onicecandidate = (event) => {
      if (event.candidate && handlers.onIceCandidate) {
        handlers.onIceCandidate(event.candidate);
      }
    };

    pc.ontrack = (event) => {
      if (handlers.onReceiver) handlers.onReceiver(event.receiver);
      if (handlers.onTrack) handlers.onTrack(event.streams[0] || new MediaStream([event.track]), event);
    };

    pc.onconnectionstatechange = () => {
      console.info("[voice] connection", pc.connectionState, "ice", pc.iceConnectionState);
      handlers.onConnectionState && handlers.onConnectionState(pc.connectionState);
    };

    const addLocalStream = (stream) => {
      stream.getTracks().forEach((track) => {
        const sender = pc.addTrack(track, stream);
        handlers.onSender && handlers.onSender(sender);
        const receiver = pc.getTransceivers().find((item) => item.sender === sender)?.receiver;
        if (receiver && handlers.onReceiver) handlers.onReceiver(receiver);
      });
    };

    const createOffer = async () => {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      return offer;
    };

    const createAnswer = async () => {
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      return answer;
    };

    const setRemoteDescription = (desc) => serialize(async () => {
      await pc.setRemoteDescription(desc);
      remoteReady = true;
      while (pendingIce.length) await pc.addIceCandidate(pendingIce.shift());
    });

    const addIceCandidate = (candidate) => {
      if (!remoteReady) {
        pendingIce.push(candidate);
        return Promise.resolve();
      }
      return serialize(() => pc.addIceCandidate(candidate));
    };

    const close = () => {
      closed = true;
      pendingIce.length = 0;
      connections.delete(pc);
      pc.close();
    };

    return {
      pc,
      addLocalStream,
      createOffer,
      createAnswer,
      setRemoteDescription,
      addIceCandidate,
      close,
    };
  };

  window.WebRTCCall = {
    buildIceServers,
    createConnection,
    // Explicit opt-in snapshot. No SDP, ICE addresses, identities or credentials.
    diagnostics: async () => Promise.all(Array.from(connections, async (pc) => {
      const stats = await pc.getStats();
      const audio = [];
      let candidateType = null;
      stats.forEach((item) => {
        if (["inbound-rtp", "outbound-rtp"].includes(item.type) && (item.kind || item.mediaType) === "audio") {
          audio.push({ direction: item.type, packets: item.packetsReceived ?? item.packetsSent,
            bytes: item.bytesReceived ?? item.bytesSent, totalAudioEnergy: item.totalAudioEnergy,
            concealedSamples: item.concealedSamples });
        }
        if (item.type === "transport" && item.selectedCandidatePairId) {
          const pair = stats.get(item.selectedCandidatePairId);
          candidateType = stats.get(pair?.localCandidateId)?.candidateType;
        }
      });
      return { connection: pc.connectionState, ice: pc.iceConnectionState, candidateType,
        localTracks: pc.getSenders().filter((s) => s.track).map((s) => ({
          kind: s.track.kind, enabled: s.track.enabled, readyState: s.track.readyState })), audio };
    })),
  };
})();
