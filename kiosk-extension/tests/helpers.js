// Shared by the tests (not a test file itself). jsdom has no MessageChannel and does not transfer ports with
// postMessage: channels() puts a small synchronous stand-in into a JSDOM window, enough for the exit handshake
// (kiosk-platform/inject-wrapper.js and relay.js, mock/nwea/page.js and relay.js). The real ordering and transfer are
// checked in Chromium (design docs/specs/2026-11-06-kiosk-platform-inject-design.md §6).
import { readFileSync } from "node:fs";
import { join } from "node:path";

/** A file of the repository, as text (paths outside kiosk-extension/ cannot be ?raw imports). */
export function repoFile(path) {
  return readFileSync(join(__dirname, "../..", path), "utf8");
}

/** The agent's inject.js for `script` (platform_ext.rs `wrap`: the script on lines of its own at the marker). */
export function wrapInject(script) {
  const wrapper = repoFile("kiosk-platform/inject-wrapper.js");
  const marker = "// @@MASTERSOS_INJECT@@\n";
  const [head, tail] = wrapper.split(marker);
  if (tail === undefined) throw new Error("no marker in inject-wrapper.js");
  return `${head}${script}${script.endsWith("\n") ? "" : "\n"}${tail}`;
}

/** MessageChannel, MessagePort and a postMessage that dispatches synchronously with ports, in window `w`. */
export function channels(w) {
  class MessagePort {
    constructor() {
      this.other = null;
      this.onmessage = null;
    }
    postMessage(data) {
      const o = this.other;
      if (o && typeof o.onmessage === "function") o.onmessage({ data });
    }
  }
  class MessageChannel {
    constructor() {
      this.port1 = new MessagePort();
      this.port2 = new MessagePort();
      this.port1.other = this.port2;
      this.port2.other = this.port1;
    }
  }
  w.MessagePort = MessagePort;
  w.MessageChannel = MessageChannel;
  const posted = [];
  w.postMessage = (data, origin, transfer = []) => {
    posted.push({ data, origin, transfer });
    dispatch(w, data, { ports: transfer });
  };
  return { posted, MessageChannel };
}

/** A message event on `w` as Chrome would deliver it (source, origin and ports can be set). */
export function dispatch(w, data, { source = w, origin = w.location.origin, ports = [] } = {}) {
  const e = new w.Event("message");
  Object.defineProperties(e, {
    data: { value: data },
    source: { value: source },
    origin: { value: origin },
    ports: { value: ports },
  });
  w.dispatchEvent(e);
  return e;
}
