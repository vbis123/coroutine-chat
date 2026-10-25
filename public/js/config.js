(() => {
  // One request, one writer, one readiness barrier. Never log credentials.
  window.appConfigReady = (async () => {
    try {
      const response = await fetch("/config.json", { cache: "no-store" });
      if (!response.ok) throw new Error("config HTTP failure");
      const config = await response.json();
      if (!Number.isInteger(config.voiceLimit) || config.voiceLimit < 2 || config.voiceLimit > 20 ||
          !["all", "relay"].includes(config.iceTransportPolicy) ||
          (config.turn && !config.turn.urls) || (config.iceTransportPolicy === "relay" && !config.turn)) {
        throw new Error("Invalid config");
      }
      window.__APP_CONFIG__ = config;
      return config;
    } catch (_) {
      const error = document.createElement("p");
      error.setAttribute("role", "alert");
      error.textContent = "Не удалось загрузить конфигурацию. Обновите страницу; голос недоступен.";
      document.body.prepend(error);
      throw new Error("Application configuration unavailable");
    }
  })();
  window.appConfigReady.catch(() => {});
})();
