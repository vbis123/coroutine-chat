(() => {
  const play = async (audio) => {
    try {
      await audio.play();
      audio.dataset.playback = "playing";
      if (!audio.parentElement?.querySelector('audio[data-playback="blocked"]')) {
        audio.parentElement?.classList.remove("playback-blocked");
      }
      return true;
    } catch (error) {
      audio.dataset.playback = "blocked";
      audio.parentElement?.classList.add("playback-blocked");
      audio.controls = true;
      console.warn("[voice] playback blocked", error.name);
      if (!audio.previousElementSibling?.classList.contains("audio-retry")) {
        const retry = document.createElement("button");
        retry.className = "audio-retry";
        retry.textContent = "Включить звук собеседника";
        retry.onclick = async () => { if (await play(audio)) retry.remove(); };
        audio.before(retry);
      }
      return false;
    }
  };
  window.RemoteAudio = { play };
})();
