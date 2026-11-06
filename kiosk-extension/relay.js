// The way out for kiosk inject scripts, isolated world, document_start (design
// docs/specs/2026-11-06-kiosk-platform-inject-design.md §6). Registered by background.js for a kiosk app with inject, on
// that app's hosts only. A script in the page's world posts exactly {type: "MASTERSOS_MOCK_EXIT"} to this window's own
// origin; turn that, and only that, into the background's {cmd:"exit"} (the same path as the Exit button). Messages
// from frames, other origins or of any other shape are ignored. It can do nothing but end the student's own session.
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
      // Extension gone (reloaded or removed): the Exit button is still there, and Alt+F4 x5 (kiosk design §4.4).
    }
  });
})();
