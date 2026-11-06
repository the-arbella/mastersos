// MastersOS kiosk inject script (design docs/specs/2026-11-06-kiosk-platform-inject-design.md §3.4, §6). The agent
// puts the school's inject file where the marker line is and this whole file becomes the platform extension's inject.js:
// MAIN world, document_start, every frame on the app's hosts, before any page script.
//
// The school's script runs inside a function: its top-level var and function declarations are not globals (write
// window.name = ... for that). It gets one parameter, mastersos, frozen:
//   mastersos.exit()  ends the kiosk session, as the Exit button does but without asking (top frame only; in a frame
//                     it does nothing). Only code that holds mastersos can do this: relay.js takes the first channel
//                     of the document, which is this one, and no page script ever has its other end.
// The captured functions below are taken before any page script can replace them.
(() => {
  const apply = Reflect.apply;
  let send = null;
  let port = null;
  if (window === window.top) {
    try {
      send = MessagePort.prototype.postMessage;
      const channel = new MessageChannel();
      port = channel.port1;
      window.postMessage({ type: "MASTERSOS_EXIT_PORT" }, window.location.origin, [channel.port2]);
    } catch {
      port = null;
    }
  }
  const mastersos = Object.freeze({
    exit() {
      if (port && send) apply(send, port, ["exit"]);
    },
  });
  (function (mastersos) {
// @@MASTERSOS_INJECT@@
  }).call(window, mastersos);
})();
