// Tests for the NWEA mock env's exit (design §4.9; docs/specs/2026-11-06-kiosk-platform-inject-design.md §6): page.js
// posts its channel before any page script, relay.js takes the first channel of the document and no other, and only
// kioskChromiumExit() (page.js's, which holds the other end) ends the session. NWEA's page calls kioskChromiumExit()
// as before; a page script posting a message of its own does nothing. Each case is a fresh JSDOM window with a
// stand-in MessageChannel (helpers.js).
import { createRequire } from "node:module";
import PAGE from "../mock/nwea/page.js?raw";
import RELAY from "../mock/nwea/relay.js?raw";
import { channels, dispatch } from "./helpers.js";

const { JSDOM } = createRequire(`${process.cwd()}/`)("jsdom");

function page({ throws = false } = {}) {
  const dom = new JSDOM("<!doctype html><html><head></head><body></body></html>", {
    url: "https://test.mapnwea.org/",
    runScripts: "outside-only",
  });
  const w = dom.window;
  const sendMessage = vi.fn(() => {
    if (throws) throw new Error("Extension context invalidated.");
  });
  w.chrome = { runtime: { sendMessage, lastError: undefined } };
  const ch = channels(w);
  // In Chrome: both at document_start (manifest order: page.js, then relay.js), before any page script; the channel
  // message is delivered in a later task, when both are there. The stand-in delivers at once, so relay.js goes first.
  const start = () => {
    w.eval(RELAY);
    w.eval(PAGE);
  };
  return { w, sendMessage, ch, start };
}

describe("NWEA mock env: exit", () => {
  it("kioskChromiumExit() ends the session", () => {
    const { w, sendMessage, ch, start } = page();
    start();
    expect(ch.posted).toHaveLength(1);
    expect(ch.posted[0].data).toEqual({ type: "MASTERSOS_NWEA_EXIT_PORT" });
    expect(ch.posted[0].origin).toBe("https://test.mapnwea.org");
    expect(sendMessage).not.toHaveBeenCalled();
    w.kioskChromiumExit();
    expect(sendMessage).toHaveBeenCalledTimes(1);
    expect(sendMessage.mock.calls[0][0]).toEqual({ cmd: "exit" });
  });

  it("a page script's own message or channel does nothing", () => {
    const { w, sendMessage, ch, start } = page();
    start();
    const seen = vi.fn();
    w.addEventListener("message", seen);
    const forged = new ch.MessageChannel();
    dispatch(w, { type: "MASTERSOS_NWEA_EXIT_PORT" }, { ports: [forged.port2] });
    forged.port1.postMessage("exit");
    for (const d of [{ type: "MASTERSOS_MOCK_EXIT" }, { cmd: "exit" }, "exit"]) dispatch(w, d);
    expect(sendMessage).not.toHaveBeenCalled();
    expect(seen).toHaveBeenCalledTimes(3); // the channel message is hidden from the page
  });

  it("the platform extension's channel type is not taken here (and the other way round)", () => {
    const { w, sendMessage, ch } = page();
    w.eval(RELAY);
    const a = new ch.MessageChannel();
    dispatch(w, { type: "MASTERSOS_EXIT_PORT" }, { ports: [a.port2] });
    expect(a.port2.onmessage).toBeNull();
    w.eval(PAGE);
    w.kioskChromiumExit();
    expect(sendMessage).toHaveBeenCalledTimes(1);
  });

  it("the first channel is the only one: a bad first one (from a frame) fails closed", () => {
    const { w, sendMessage, ch } = page();
    w.eval(RELAY);
    const frame = w.document.createElement("iframe");
    w.document.body.appendChild(frame);
    const a = new ch.MessageChannel();
    dispatch(w, { type: "MASTERSOS_NWEA_EXIT_PORT" }, { source: frame.contentWindow, ports: [a.port2] });
    w.eval(PAGE);
    w.kioskChromiumExit();
    a.port1.postMessage("exit");
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("survives a missing runtime", () => {
    const { w, start } = page({ throws: true });
    start();
    expect(() => w.kioskChromiumExit()).not.toThrow();
  });
});
