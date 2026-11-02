// NWEA mock env, isolated world, document_start (design §4.9): page.js's kioskChromiumExit() posts exactly
// {type: "MASTERSOS_MOCK_EXIT"} to this window's own origin; turn that, and only that, into the background's
// {cmd:"exit"} (the same path as the exit button, §4.7). Messages from frames, other origins or of any other shape
// are ignored.
(() => {
  "use strict";
  window.addEventListener("message", (e) => {
    if (e.source !== window || e.origin !== window.location.origin) return;
    const d = e.data;
    if (d === null || typeof d !== "object" || Array.isArray(d)) return;
    if (Object.keys(d).length !== 1 || d.type !== "MASTERSOS_MOCK_EXIT") return;
    try {
      chrome.runtime.sendMessage({ cmd: "exit" }, () => void chrome.runtime.lastError);
    } catch {
      // Extension gone (reloaded or removed): the exit button is still there, and Alt+F4 ×5 (design §4.4).
    }
  });
})();
