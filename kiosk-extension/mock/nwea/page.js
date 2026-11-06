// NWEA mock env, MAIN world, document_start (design §4.9, ruling K9).
// Deprecated (docs/specs/2026-11-06-kiosk-platform-inject-design.md §5): new settings use inject = "files/nwea.js"
// with examples/kiosk-inject/nwea.js, which does the same. Kept until the schools using it have moved.
// On a ChromeOS kiosk, NWEA's extension (acmpckmfpahllclpjpollppelfoafcmh 1.0.0, content-main.js + content.js) puts
// these into the page, and the test pages (test.mapnwea.org login, /growth/ player) read only these:
//   window.isKioskChromium, window.extVersion  -> Lockdown / wrcCheck: identity NWEA_CHROME_PWA, version >= 1.0.0
//   window.kioskChromiumExit()                 -> called to close the test window
// NWEA's extension answers isKioskChromium asynchronously (it asks its background whether chrome.audio exists);
// ours are constants, written synchronously before any page script runs. Exit goes to relay.js by postMessage and
// from there to the background's {cmd:"exit"} path; this script never touches chrome.runtime.
(() => {
  "use strict";
  const MARK = Symbol.for("mastersos.mock.nwea");
  if (window[MARK]) return;
  Object.defineProperty(window, MARK, { value: true });

  const EXIT = { type: "MASTERSOS_MOCK_EXIT" };
  const origin = window.location.origin;
  const constant = (name, value) =>
    Object.defineProperty(window, name, { value, writable: false, configurable: false, enumerable: false });
  constant("isKioskChromium", true);
  constant("extVersion", "1.0.0");
  constant("kioskChromiumExit", function kioskChromiumExit() {
    window.postMessage({ ...EXIT }, origin);
  });

  // Same as NWEA's extension: the page sees " NWEAChromePWA" at the end of navigator.userAgent. Its DNR rule that
  // appends the same to the request header is rejected by Chrome (User-Agent cannot be appended), so we have none.
  const ua = navigator.userAgent;
  Object.defineProperty(navigator, "userAgent", { get: () => `${ua} NWEAChromePWA`, configurable: true });

  // Keys NWEA's extension blocks (minus the Ctrl+Search ones: those are ChromeOS system features, handled by the
  // locked session's system keys, design §4.6).
  const CTRL_KEYS = new Set(["w", "n", "t", "0"]);
  function blockShortcut(e) {
    const k = typeof e.key === "string" ? e.key.toLowerCase() : "";
    if (k === "f5" || (e.ctrlKey && CTRL_KEYS.has(k))) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  }
  window.addEventListener("keydown", blockShortcut, true);
  document.addEventListener("keydown", blockShortcut, true);

  // No overscroll and no horizontal swipe from the left/right edge (back/forward navigation), as NWEA's extension.
  const style = document.createElement("style");
  style.textContent =
    "html, body { overscroll-behavior: none !important; overscroll-behavior-x: none !important; touch-action: pan-y pinch-zoom !important; }";
  if (document.head) document.head.appendChild(style);
  else document.addEventListener("DOMContentLoaded", () => document.head.appendChild(style));

  const THRESHOLD = 50;
  const EDGE = 50;
  let startX = 0;
  let startY = 0;
  document.addEventListener(
    "touchstart",
    (e) => {
      startX = e.touches[0].clientX;
      startY = e.touches[0].clientY;
    },
    { passive: false, capture: true },
  );
  document.addEventListener(
    "touchmove",
    (e) => {
      if (!startX) return;
      const dx = startX - e.touches[0].clientX;
      const dy = startY - e.touches[0].clientY;
      const horizontal = Math.abs(dx) > Math.abs(dy) && Math.abs(dx) > THRESHOLD;
      if (horizontal && (startX < EDGE || startX > window.innerWidth - EDGE)) {
        e.preventDefault();
        e.stopImmediatePropagation();
      }
    },
    { passive: false, capture: true },
  );
  document.addEventListener(
    "touchend",
    () => {
      startX = 0;
      startY = 0;
    },
    { passive: true, capture: true },
  );
})();
