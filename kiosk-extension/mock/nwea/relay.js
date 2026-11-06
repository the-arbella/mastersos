// NWEA mock env, isolated world, document_start (design §4.9). page.js runs before any page script and posts exactly
// {type: "MASTERSOS_NWEA_EXIT_PORT"} with one MessagePort to this window; take the first such message of the document
// and no other, hide it from the page's listeners, and turn "exit" on that port, and only that, into the background's
// {cmd:"exit"} (the same path as the exit button, §4.7). page.js holds the other end and sends "exit" only from
// kioskChromiumExit(); a page script can post the same message only later, and it is ignored then.
(() => {
  "use strict";
  const TYPE = "MASTERSOS_NWEA_EXIT_PORT";
  let taken = false;
  window.addEventListener(
    "message",
    (e) => {
      const d = e.data;
      if (d === null || typeof d !== "object" || Array.isArray(d)) return;
      if (Object.keys(d).length !== 1 || d.type !== TYPE) return;
      e.stopImmediatePropagation();
      if (taken) return;
      taken = true;
      if (e.source !== window || e.origin !== window.location.origin || !e.ports || e.ports.length !== 1) return;
      e.ports[0].onmessage = (m) => {
        if (m.data !== "exit") return;
        try {
          chrome.runtime.sendMessage({ cmd: "exit" }, () => void chrome.runtime.lastError);
        } catch {
          // Extension gone (reloaded or removed): the exit button is still there, and Alt+F4 ×5 (design §4.4).
        }
      };
    },
    true,
  );
})();
