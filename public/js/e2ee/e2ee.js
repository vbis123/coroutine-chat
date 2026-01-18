(() => {
  const supports =
    window.RTCRtpSender &&
    "transform" in RTCRtpSender.prototype &&
    window.RTCRtpReceiver &&
    "transform" in RTCRtpReceiver.prototype &&
    window.RTCRtpScriptTransform;

  let worker = null;

  const ensureWorker = () => {
    if (worker) return worker;
    worker = new Worker("/js/e2ee/transform-worker.js");
    worker.addEventListener("message", (event) => {
      if (event.data && event.data.type === "e2ee:error") {
        console.warn("[e2ee] worker error:", event.data.error);
      }
    });
    return worker;
  };

  const attachSenderTransform = (sender, keyBytes) => {
    if (!supports || !sender) return false;
    const workerInstance = ensureWorker();
    const key = keyBytes.slice(0).buffer;
    sender.transform = new RTCRtpScriptTransform(workerInstance, { role: "encrypt", key }, [key]);
    return true;
  };

  const attachReceiverTransform = (receiver, keyBytes) => {
    if (!supports || !receiver) return false;
    const workerInstance = ensureWorker();
    const key = keyBytes.slice(0).buffer;
    receiver.transform = new RTCRtpScriptTransform(workerInstance, { role: "decrypt", key }, [key]);
    return true;
  };

  window.E2EE = {
    supports,
    attachSenderTransform,
    attachReceiverTransform,
  };
})();
