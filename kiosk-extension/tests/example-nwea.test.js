// Tests for the NWEA example inject script (examples/kiosk-inject/nwea.js), the same cases as the built-in mock env's
// (mock-nwea-page.test.js) plus: the UA suffix follows Navigator.prototype, and the built-in's marker is shared.
// Each case runs the script in a fresh JSDOM window:
// the signals are non-configurable properties, so one window per case keeps the cases independent.
// ?raw: vite hands over the source as a string (not executed as a module), the way Chrome injects it.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import BUILTIN from "../mock/nwea/page.js?raw";

// Outside the extension directory (not packed, and outside vite's allowed files): read it as text.
const SRC = readFileSync(join(__dirname, "../../examples/kiosk-inject/nwea.js"), "utf8");

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

describe("NWEA example inject script", () => {
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

  it("kioskChromiumExit posts exactly the exit message to its own origin", () => {
    const { w, run } = page();
    const post = vi.fn();
    w.postMessage = post;
    run();
    w.kioskChromiumExit();
    expect(post).toHaveBeenCalledTimes(1);
    const [msg, target] = post.mock.calls[0];
    expect(msg).toEqual({ type: "MASTERSOS_MOCK_EXIT" });
    expect(Object.keys(msg)).toEqual(["type"]);
    expect(target).toBe(ORIGIN);
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

  it("the UA suffix follows a ChromeOS UA on Navigator.prototype", () => {
    const { w, run } = page();
    run();
    const cros = "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36";
    Object.defineProperty(w.Navigator.prototype, "userAgent", { get: () => cros, configurable: true });
    expect(w.navigator.userAgent).toBe(`${cros} NWEAChromePWA`);
  });

  it("does nothing after the built-in mock env, and the built-in does nothing after it", () => {
    for (const [first, second] of [
      [BUILTIN, SRC],
      [SRC, BUILTIN],
    ]) {
      const { w, ua } = page();
      w.eval(first);
      expect(() => w.eval(second)).not.toThrow();
      expect(w.navigator.userAgent).toBe(`${ua} NWEAChromePWA`);
    }
  });
});
