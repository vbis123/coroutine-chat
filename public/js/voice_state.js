(() => {
  const canSpeak = (state, id) => state.joined && state.floorKnown &&
    (!state.floorOwner || state.floorOwner === id);
  const muted = (state, id) => Boolean(!canSpeak(state, id) ||
    (!(state.pttActive) && (state.muted || state.floorSuppressed)));
  const setFloor = (state, owner, id) => {
    if (state.floorOwner !== owner) state.pttActive = false;
    state.floorOwner = owner;
    state.floorKnown = true;
    if (owner && owner !== id) state.floorSuppressed = true;
  };
  const accepts = (state, message) => state.joined && message.room === state.room &&
    message.membershipId === state.membershipId;
  window.VoiceState = { canSpeak, muted, setFloor, accepts };
})();
