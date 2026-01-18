(() => {
  const buildIceServers = () => {
    const servers = [{ urls: "stun:stun.l.google.com:19302" }];
    const config = window.__APP_CONFIG__ || {};
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
    const pc = new RTCPeerConnection({ iceServers: buildIceServers() });

    pc.onicecandidate = (event) => {
      if (event.candidate && handlers.onIceCandidate) {
        handlers.onIceCandidate(event.candidate);
      }
    };

    pc.ontrack = (event) => {
      if (handlers.onTrack) {
        handlers.onTrack(event.streams[0], event);
      }
      if (handlers.onReceiver) {
        handlers.onReceiver(event.receiver);
      }
    };

    pc.onconnectionstatechange = () => {
      handlers.onConnectionState && handlers.onConnectionState(pc.connectionState);
    };

    const addLocalStream = (stream) => {
      stream.getTracks().forEach((track) => {
        const sender = pc.addTrack(track, stream);
        handlers.onSender && handlers.onSender(sender);
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

    const setRemoteDescription = async (desc) => {
      await pc.setRemoteDescription(desc);
    };

    const addIceCandidate = async (candidate) => {
      await pc.addIceCandidate(candidate);
    };

    const close = () => {
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
  };
})();
