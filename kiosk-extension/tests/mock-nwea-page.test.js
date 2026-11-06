// Tests for the NWEA mock env's MAIN-world script (design §4.9). Each case runs the script in a fresh JSDOM window:
// the signals are non-configurable properties, so one window per case keeps the cases independent.
// ?raw: vite hands over the source as a string (not executed as a module), the way Chrome injects it.
import { createRequire } from "node:module";
import SRC from "../mock/nwea/page.js?raw";
import { channels } from "./helpers.js";

// This directory has no package of its own: resolve jsdom from the web package vitest runs in.
const { JSDOM } = createRequire(`${process.cwd()}/`)("jsdom");

const ORIGIN = "https://test.mapnwea.org";

function page() {
  const dom = new JSDOM("<!doctype html><html><head></head><body></body></html>", {
    url: `${ORIGIN}/`,
    runScripts: "outside-only",
  });
  const w = dom.window;
  const ua = w.navigator.userAgent;
  return { w, ua, run: () => w.eval(SRC) };
}

function key(w, init) {
  const e = new w.KeyboardEvent("keydown", { bubbles: true, cancelable: true, ...init });
  w.document.dispatchEvent(e);
  return e;
}

function touch(w, type, x, y) {
  const e = new w.Event(type, { bubbles: true, cancelable: true });
  Object.defineProperty(e, "touches", { value: [{ clientX: x, clientY: y }] });
  w.document.dispatchEvent(e);
  return e;
}

describe("NWEA mock env: page.js", () => {
  it("sets the NWEA kiosk signals", () => {
    const { w, ua, run } = page();
    run();
    expect(w.isKioskChromium).toBe(true);
    expect(w.extVersion).toBe("1.0.0");
    expect(typeof w.kioskChromiumExit).toBe("function");
    expect(w.navigator.userAgent).toBe(`${ua} NWEAChromePWA`);
  });

  it("constants cannot be overwritten or deleted", () => {
    const { w, run } = page();
    run();
    const exit = w.kioskChromiumExit;
    w.eval('isKioskChromium = false; extVersion = "0"; delete window.isKioskChromium; kioskChromiumExit = null;');
    expect(w.isKioskChromium).toBe(true);
    expect(w.extVersion).toBe("1.0.0");
    expect(w.kioskChromiumExit).toBe(exit);
  });

  it("posts its channel once, to its own origin; kioskChromiumExit sends exit on it", () => {
    const { w, run } = page();
    const { posted } = channels(w);
    run();
    expect(posted).toHaveLength(1);
    expect(posted[0].data).toEqual({ type: "MASTERSOS_NWEA_EXIT_PORT" });
    expect(posted[0].origin).toBe(ORIGIN);
    expect(posted[0].transfer).toHaveLength(1);
    const got = vi.fn();
    posted[0].transfer[0].onmessage = got;
    w.kioskChromiumExit();
    expect(got).toHaveBeenCalledTimes(1);
    expect(got.mock.calls[0][0].data).toBe("exit");
  });

  it("without MessageChannel the signals are still there and exit does nothing", () => {
    const { w, run } = page();
    delete w.MessageChannel;
    run();
    expect(w.isKioskChromium).toBe(true);
    expect(() => w.kioskChromiumExit()).not.toThrow();
  });

  it("blocks F5 and Ctrl+W/N/T/0", () => {
    const { w, run } = page();
    run();
    expect(key(w, { key: "F5" }).defaultPrevented).toBe(true);
    for (const k of ["w", "W", "n", "t", "0"]) expect(key(w, { key: k, ctrlKey: true }).defaultPrevented, k).toBe(true);
    expect(key(w, { key: "a" }).defaultPrevented).toBe(false);
    expect(key(w, { key: "c", ctrlKey: true }).defaultPrevented).toBe(false);
    expect(key(w, { key: "w" }).defaultPrevented).toBe(false);
  });

  it("blocks horizontal edge swipes only", () => {
    const { w, run } = page();
    Object.defineProperty(w, "innerWidth", { value: 1024, configurable: true });
    run();
    touch(w, "touchstart", 10, 300);
    expect(touch(w, "touchmove", 120, 300).defaultPrevented).toBe(true);
    touch(w, "touchend", 120, 300);
    touch(w, "touchstart", 300, 300);
    expect(touch(w, "touchmove", 450, 300).defaultPrevented).toBe(false);
    touch(w, "touchend", 450, 300);
    touch(w, "touchstart", 10, 300);
    expect(touch(w, "touchmove", 70, 500).defaultPrevented).toBe(false);
  });

  it("adds overscroll-behavior none", () => {
    const { w, run } = page();
    run();
    const css = [...w.document.head.querySelectorAll("style")].map((s) => s.textContent).join("\n");
    expect(css).toContain("overscroll-behavior: none");
  });

  it("idempotent when run twice", () => {
    const { w, ua, run } = page();
    run();
    run();
    expect(w.navigator.userAgent).toBe(`${ua} NWEAChromePWA`);
    expect(w.document.head.querySelectorAll("style")).toHaveLength(1);
    const e = new w.KeyboardEvent("keydown", { key: "F5", bubbles: true, cancelable: true });
    const prevent = vi.spyOn(e, "preventDefault");
    w.document.dispatchEvent(e);
    expect(prevent).toHaveBeenCalledTimes(1);
  });
});
