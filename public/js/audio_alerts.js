(() => {
  const AudioContextClass = window.AudioContext || window.webkitAudioContext;
  const ctx = AudioContextClass ? new AudioContextClass() : null;
  let unlocked = false;
  let ringtoneTimer = null;
  let ringbackTimer = null;

  const resumeIfNeeded = async () => {
    if (!ctx) return false;
    if (ctx.state === "suspended") {
      await ctx.resume();
    }
    unlocked = ctx.state === "running";
    return unlocked;
  };

  const playTone = (freq, duration, volume = 0.15) => {
    if (!ctx) return;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.frequency.value = freq;
    osc.type = "sine";
    gain.gain.value = 0;
    osc.connect(gain).connect(ctx.destination);
    const now = ctx.currentTime;
    gain.gain.setValueAtTime(0.0001, now);
    gain.gain.exponentialRampToValueAtTime(volume, now + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + duration);
    osc.start(now);
    osc.stop(now + duration + 0.05);
  };

  const stopTimer = (timer) => {
    if (timer) clearInterval(timer);
    return null;
  };

  const playRingtoneLoop = async () => {
    if (!(await resumeIfNeeded())) return false;
    ringtoneTimer = stopTimer(ringtoneTimer);
    const loop = () => {
      playTone(880, 0.25, 0.18);
      setTimeout(() => playTone(660, 0.25, 0.12), 500);
    };
    loop();
    ringtoneTimer = setInterval(loop, 1500);
    return true;
  };

  const playRingbackLoop = async () => {
    if (!(await resumeIfNeeded())) return false;
    ringbackTimer = stopTimer(ringbackTimer);
    const loop = () => {
      playTone(440, 0.35, 0.12);
    };
    loop();
    ringbackTimer = setInterval(loop, 1200);
    return true;
  };

  const stopAllTones = () => {
    ringtoneTimer = stopTimer(ringtoneTimer);
    ringbackTimer = stopTimer(ringbackTimer);
  };

  const playBeep = async (type) => {
    if (!(await resumeIfNeeded())) return false;
    if (type === "connect") {
      playTone(880, 0.12, 0.12);
      setTimeout(() => playTone(1320, 0.12, 0.12), 120);
    } else if (type === "end") {
      playTone(330, 0.2, 0.12);
    }
    return true;
  };

  window.AudioAlerts = {
    ensureAudioUnlocked: resumeIfNeeded,
    isUnlocked: () => unlocked,
    playRingtoneLoop,
    playRingbackLoop,
    stopAllTones,
    playBeep,
  };
})();
