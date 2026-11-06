// The inject script's way out (kiosk-platform/relay.js and inject-wrapper.js, design
// docs/specs/2026-11-06-kiosk-platform-inject-design.md §6): only the code the wrapper hands mastersos to can end the
// session. The wrapper posts its channel before any page script; relay.js takes the first channel of the document and
// no other, hides it from the page, and turns "exit" on it into the background's {cmd:"exit"}. Each case is a fresh
// JSDOM window with a stand-in MessageChannel (helpers.js); the real ordering is checked in Chromium (design §6).
import { createRequire } from "node:module";
import { channels, dispatch, repoFile, wrapInject } from "./helpers.js";

const { JSDOM } = createRequire(`${process.cwd()}/`)("jsdom");
const RELAY = repoFile("kiosk-platform/relay.js");

function page({ throws = false } = {}) {
  const dom = new JSDOM("<!doctype html><html><head></head><body></body></html>", {
    url: "https://home.testnav.com/",
    runScripts: "outside-only",
  });
  const w = dom.window;
  const sendMessage = vi.fn(() => {
    if (throws) throw new Error("Extension context invalidated.");
  });
  w.chrome = { runtime: { sendMessage, lastError: undefined } };
  const ch = channels(w);
  // In Chrome: relay.js (isolated world) and inject.js (MAIN world) at document_start, before any page script.
  const start = (script = "window.__mastersos = mastersos;") => {
    w.eval(RELAY);
    w.eval(wrapInject(script));
  };
  return { w, sendMessage, ch, start };
}

describe("relay.js + inject wrapper", () => {
  it("mastersos.exit() of the inject script ends the session", () => {
    const { w, sendMessage, start } = page();
    start();
    expect(sendMessage).not.toHaveBeenCalled();
    w.__mastersos.exit();
    expect(sendMessage).toHaveBeenCalledTimes(1);
    expect(sendMessage.mock.calls[0][0]).toEqual({ cmd: "exit" });
    expect(Object.isFrozen(w.__mastersos)).toBe(true);
  });

  it("the wrapper's channel is hidden from the page's own listeners", () => {
    const { w, start } = page();
    const seen = vi.fn();
    // A page listener added before the message is delivered (in Chrome the delivery is a later task).
    w.addEventListener("message", seen);
    start();
    expect(seen).not.toHaveBeenCalled();
  });

  it("a page script cannot end the session: later channels and plain messages are ignored", () => {
    const { w, sendMessage, ch, start } = page();
    start("/* the school's script does not exit */");
    const seen = vi.fn();
    w.addEventListener("message", seen);
    const forged = new ch.MessageChannel();
    dispatch(w, { type: "MASTERSOS_EXIT_PORT" }, { ports: [forged.port2] });
    forged.port1.postMessage("exit");
    dispatch(w, { type: "MASTERSOS_MOCK_EXIT" });
    dispatch(w, { cmd: "exit" });
    expect(sendMessage).not.toHaveBeenCalled();
    expect(forged.port2.onmessage).toBeNull();
    // the channel message is hidden from other listeners, the plain ones are not relay.js's business
    expect(seen.mock.calls.map((c) => c[0].data)).toEqual([{ type: "MASTERSOS_MOCK_EXIT" }, { cmd: "exit" }]);
  });

  it("replacing MessagePort.prototype.postMessage after the start does not reach the port", () => {
    const { w, sendMessage, start } = page();
    start();
    w.eval("MessagePort.prototype.postMessage = function () { window.__stolen = this; };");
    w.__mastersos.exit();
    expect(w.__stolen).toBeUndefined();
    expect(sendMessage).toHaveBeenCalledTimes(1);
  });

  it("the first channel is the only one, even a bad one (wrong source or two ports): fails closed", () => {
    const { w, sendMessage, ch } = page();
    w.eval(RELAY);
    const frame = w.document.createElement("iframe");
    w.document.body.appendChild(frame);
    const a = new ch.MessageChannel();
    dispatch(w, { type: "MASTERSOS_EXIT_PORT" }, { source: frame.contentWindow, ports: [a.port2] });
    w.eval(wrapInject("window.__mastersos = mastersos;"));
    w.__mastersos.exit();
    a.port1.postMessage("exit");
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("only \"exit\" on the port; other shapes of the channel message are not taken", () => {
    const { w, sendMessage, ch } = page();
    w.eval(RELAY);
    const a = new ch.MessageChannel();
    for (const d of [{ type: "MASTERSOS_EXIT_PORT", x: 1 }, "MASTERSOS_EXIT_PORT", null, ["MASTERSOS_EXIT_PORT"]]) {
      dispatch(w, d, { ports: [a.port2] });
    }
    expect(a.port2.onmessage).toBeNull();
    w.eval(wrapInject("window.__mastersos = mastersos;"));
    const port = ch.posted[0].transfer[0];
    port.other.postMessage("Exit");
    port.other.postMessage({ cmd: "exit" });
    expect(sendMessage).not.toHaveBeenCalled();
    w.__mastersos.exit();
    expect(sendMessage).toHaveBeenCalledTimes(1);
  });

  it("survives a missing runtime", () => {
    const { w, start } = page({ throws: true });
    start();
    expect(() => w.__mastersos.exit()).not.toThrow();
  });
});

describe("inject wrapper", () => {
  it("the school's script runs once, in a function, with this = window", () => {
    const { w, start } = page();
    start("var local = 1; window.__ran = (window.__ran || 0) + 1; window.__this = this === window; // last line comment");
    expect(w.__ran).toBe(1);
    expect(w.__this).toBe(true);
    expect(w.local).toBeUndefined();
  });

  it("\"use strict\" at the top of the school's script applies to it", () => {
    const { w, start } = page();
    start('"use strict";\nwindow.__strict = (function () { return this; })() === undefined;');
    expect(w.__strict).toBe(true);
  });

  it("in a frame mastersos.exit() does nothing", () => {
    const { w, sendMessage } = page();
    w.eval(RELAY);
    const frame = w.document.createElement("iframe");
    w.document.body.appendChild(frame);
    const f = frame.contentWindow;
    f.eval(wrapInject("window.__mastersos = mastersos;"));
    expect(() => f.__mastersos.exit()).not.toThrow();
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("without MessageChannel the school's script still runs", () => {
    const { w } = page();
    delete w.MessageChannel;
    w.eval(wrapInject("window.__ran = true; window.__mastersos = mastersos;"));
    expect(w.__ran).toBe(true);
    expect(() => w.__mastersos.exit()).not.toThrow();
  });
});
