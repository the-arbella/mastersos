// The way out for kiosk inject scripts, isolated world, document_start, top frame (design
// docs/specs/2026-11-06-kiosk-platform-inject-design.md §6). A static content script of the app's platform extension,
// on the app's hosts only, beside inject.js (the agent's wrapper around the IT script, MAIN world, document_start).
//
// Only the inject script may end the session, not any script of the page: the wrapper runs before every page script
// and posts exactly {type: "MASTERSOS_EXIT_PORT"} with one MessagePort to this window; the wrapper keeps the other end
// of the channel to itself and hands the IT script mastersos.exit(), which sends "exit" on it. This script takes the
// first such message of the document and no other, hides it from the page's own listeners, and turns "exit" on that
// port, and only that, into the background's {cmd:"exit"} (the same path as the Exit button). A page script can post
// the same message only later, and it is ignored then; it never holds the wrapper's end of the channel.
(() => {
  "use strict";
  const TYPE = "MASTERSOS_EXIT_PORT";
  let taken = false;
  window.addEventListener(
    "message",
    (e) => {
      const d = e.data;
      if (d === null || typeof d !== "object" || Array.isArray(d)) return;
      if (Object.keys(d).length !== 1 || d.type !== TYPE) return;
      // Ours or a copy: the page does not need to see either.
      e.stopImmediatePropagation();
      if (taken) return;
      taken = true;
      if (e.source !== window || e.origin !== window.location.origin || !e.ports || e.ports.length !== 1) return;
      const port = e.ports[0];
      port.onmessage = (m) => {
        if (m.data !== "exit") return;
        try {
          chrome.runtime.sendMessage({ cmd: "exit" }, () => void chrome.runtime.lastError);
        } catch {
          // Extension gone (reloaded or removed): the Exit button is still there, and Alt+F4 x5 (kiosk design §4.4).
        }
      };
    },
    true,
  );
})();
