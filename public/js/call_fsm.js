(() => {
  const STATES = ["idle", "outgoing", "incoming", "in_call", "ending"];

  const createFSM = (handlers = {}) => {
    let state = "idle";
    const context = {
      callId: null,
      peerId: null,
      initiator: false,
    };

    const setState = (next, meta = {}) => {
      if (!STATES.includes(next)) return;
      const prev = state;
      state = next;
      handlers.onStateChange && handlers.onStateChange(state, { ...context }, prev, meta);
    };

    const reset = () => {
      context.callId = null;
      context.peerId = null;
      context.initiator = false;
      setState("idle");
    };

    const transition = (action, data = {}) => {
      switch (state) {
        case "idle":
          if (action === "outgoing") {
            context.callId = data.callId;
            context.peerId = data.peerId;
            context.initiator = true;
            setState("outgoing");
          } else if (action === "incoming") {
            context.callId = data.callId;
            context.peerId = data.peerId;
            context.initiator = false;
            setState("incoming");
          }
          break;
        case "outgoing":
          if (action === "accepted") {
            setState("in_call");
          } else if (action === "rejected" || action === "canceled" || action === "timeout") {
            setState("ending", { reason: action });
          }
          break;
        case "incoming":
          if (action === "accepted") {
            setState("in_call");
          } else if (action === "rejected" || action === "canceled") {
            setState("ending", { reason: action });
          }
          break;
        case "in_call":
          if (action === "hangup" || action === "remote_hangup") {
            setState("ending", { reason: action });
          }
          break;
        case "ending":
          if (action === "reset") {
            reset();
          }
          break;
        default:
          break;
      }
    };

    return {
      get state() {
        return state;
      },
      context,
      transition,
      reset,
      setState,
    };
  };

  window.CallFSM = { create: createFSM };
})();
