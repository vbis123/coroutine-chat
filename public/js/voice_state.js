(() => {
  const canSpeak = (state, id) => state.joined && state.floorKnown &&
    (!state.floorOwner || state.floorOwner === id);
  const muted = (state, id) => Boolean(!canSpeak(state, id) ||
    (!(state.pttActive) && (state.muted || state.floorSuppressed)));
  const setFloor = (state, owner, id) => {
    if (state.floorOwner !== owner) state.pttActive = false;
    state.floorOwner = owner;
    state.floorKnown = true;
    state.floorSuppressed = Boolean(owner && owner !== id);
  };
  const accepts = (state, message) => state.joined && message.room === state.room &&
    message.membershipId === state.membershipId;
  const floorSecondsLeft = (state, now = Date.now()) => {
    if (!state.floorOwner || !Number.isFinite(state.floorDeadlineAt)) return null;
    return Math.max(0, Math.ceil((state.floorDeadlineAt - now) / 1000));
  };
  window.VoiceState = { canSpeak, muted, setFloor, accepts, floorSecondsLeft };
})();
