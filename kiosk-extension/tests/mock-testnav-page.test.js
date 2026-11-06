// Tests for the TestNav mock env's MAIN-world script (design docs/specs/2026-11-06-testnav-chromeos-mock.md). Each case
// runs the script in a fresh JSDOM window: the UA and chrome.runtime are non-configurable, so one window per case.
// ?raw: vite hands over the source as a string (not executed as a module), the way Chrome injects it.
import { createRequire } from "node:module";
import SRC from "../mock/testnav/page.js?raw";

// This directory has no package of its own: resolve jsdom from the web package vitest runs in.
const { JSDOM } = createRequire(`${process.cwd()}/`)("jsdom");

const ORIGIN = "https://home.testnav.com";
const EXT = "gjhfdhjfmmgldldpmfdmbddbegbachgo";
const LINUX_UA =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";
const CROS_UA =
  "Mozilla/5.0 (X11; CrOS x86_64 16181.61.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 TestNavPWAKiosk/1.15.7";

function page({ ua = LINUX_UA, runtime } = {}) {
  const dom = new JSDOM("<!doctype html><html><head></head><body></body></html>", {
    url: `${ORIGIN}/`,
    runScripts: "outside-only",
  });
  const w = dom.window;
  // Chrome's own UA (jsdom's is "Mozilla/5.0 (linux) … jsdom/…"); configurable, as Navigator.prototype's is.
  Object.defineProperty(w.navigator, "userAgent", { get: () => ua, configurable: true });
  Object.defineProperty(w.navigator, "appVersion", { get: () => ua.replace(/^Mozilla\//, ""), configurable: true });
  // Chrome always has window.chrome; chrome.runtime only when an installed extension is externally connectable.
  w.chrome = runtime ? { app: {}, runtime } : { app: {} };
  return { w, run: () => w.eval(SRC) };
}

// What the App API does (api.js class cs): sendMessage(id, {method, data}, {}, callback), then reads lastError.
function ask(w, method, data = {}) {
  return new Promise((resolve) => {
    w.chrome.runtime.sendMessage(EXT, { method, data }, {}, (r) => resolve({ r, lastError: w.chrome.runtime.lastError }));
  });
}

// TestNav's own extension, as seen from the page (only the methods the page uses).
function realRuntime() {
  const rt = {
    lastError: undefined,
    sendMessage: vi.fn((id, msg, ...rest) => {
      const cb = rest.find((a) => typeof a === "function");
      setTimeout(() => cb({ success: true, data: { forwarded: msg.method } }), 0);
    }),
  };
  return rt;
}

describe("TestNav mock env: page.js", () => {
  it("navigator.userAgent is ChromeOS with the kiosk app suffix", () => {
    const { w, run } = page();
    run();
    expect(w.navigator.userAgent).toBe(CROS_UA);
    expect(w.navigator.userAgent).not.toMatch(/Linux/);
    expect(w.navigator.appVersion).toBe(CROS_UA.replace(/^Mozilla\//, ""));
  });

  it("App API's checks pass on that UA", () => {
    const { w, run } = page();
    run();
    const u = w.navigator.userAgent;
    // ua-parser-js's Chromium OS rule, App API getAppVersion and isChromeExtensionInstalled (api.js class Qt)
    expect(/(cros) [\w]+(?:\)| ([\w.]+)\b)/i.test(u)).toBe(true);
    expect(u.match(/TestNav.*(App|iOS|PWA|PWAKiosk|TakeATest|TakeATestKiosk)\/(?<version>\S+)/).groups.version).toBe("1.15.7");
    expect(u.includes("TestNavPWA")).toBe(true);
    // home.testnav.com startpage.js: registers its service worker only on CrOS + Chrome
    expect(/Chrome/.test(u) && u.indexOf("CrOS") !== -1).toBe(true);
    // test client isLinux (X11 in appVersion) is true on a real Chromebook too
    expect(w.navigator.appVersion.indexOf("X11")).not.toBe(-1);
  });

  it("a UA that is already ChromeOS (kiosk user_agent) is kept, suffix added once", () => {
    const set = "Mozilla/5.0 (X11; CrOS x86_64 15000.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
    const a = page({ ua: set });
    a.run();
    expect(a.w.navigator.userAgent).toBe(`${set} TestNavPWAKiosk/1.15.7`);
    const b = page({ ua: `${set} TestNavPWAKiosk/1.15.7` });
    b.run();
    expect(b.w.navigator.userAgent).toBe(`${set} TestNavPWAKiosk/1.15.7`);
  });

  it("the UA cannot be replaced afterwards (TestNav extension's late append)", () => {
    const { w, run } = page();
    run();
    expect(() =>
      w.eval('Object.defineProperty(navigator, "userAgent", { get: () => navigator.userAgent + " TestNavPWA/1.15.7" })'),
    ).toThrow();
    expect(w.navigator.userAgent).toBe(CROS_UA);
  });

  it("answers checkKioskModeStatus with kioskMode true, without an extension", async () => {
    const { w, run } = page();
    run();
    expect(typeof w.chrome.runtime.sendMessage).toBe("function");
    const { r, lastError } = await ask(w, "checkKioskModeStatus");
    expect(r).toEqual({ success: true, data: { kioskMode: true } });
    expect(lastError).toBeUndefined();
  });

  it("answers the ChromeOS-only methods locally and never forwards them", async () => {
    const rt = realRuntime();
    const { w, run } = page({ runtime: rt });
    run();
    expect((await ask(w, "checkKioskModeStatus")).r).toEqual({ success: true, data: { kioskMode: true } });
    expect((await ask(w, "disableAccessibilityFeatures", { exclusions: [] })).r).toEqual({ success: true });
    expect((await ask(w, "resetAccessibilityFeatures")).r).toEqual({ success: true });
    for (const m of ["generateAppValidityCheckToken", "checkAudioLevel", "setAudioLevel"]) {
      const { r } = await ask(w, m, { audioLevel: 50 });
      expect(r.success, m).toBe(false);
      expect(r.data.errors[0], m).toMatch(/not supported on this platform/);
    }
    expect(rt.sendMessage).not.toHaveBeenCalled();
  });

  it("forwards everything else to TestNav's extension", async () => {
    const rt = realRuntime();
    const { w, run } = page({ runtime: rt });
    run();
    for (const m of ["setZoomLevel", "setAllowedNavigationDomains", "setProxy", "proxyFetch", "clearBrowsingData"]) {
      const { r } = await ask(w, m);
      expect(r).toEqual({ success: true, data: { forwarded: m } });
    }
    expect(rt.sendMessage).toHaveBeenCalledTimes(5);
    expect(rt.sendMessage.mock.calls[0][0]).toBe(EXT);
    // other extension ids too, untouched
    w.chrome.runtime.sendMessage("aaaabbbbccccddddeeeeffffgggghhhh", { method: "checkKioskModeStatus" }, () => {});
    expect(rt.sendMessage.mock.calls[5][0]).toBe("aaaabbbbccccddddeeeeffffgggghhhh");
  });

  it("without TestNav's extension, other methods fail like a missing extension", async () => {
    const { w, run } = page();
    run();
    const { r, lastError } = await ask(w, "setZoomLevel", { zoomLevel: 1 });
    expect(r).toBeUndefined();
    expect(lastError.message).toMatch(/Receiving end does not exist/);
    // lastError is only set inside the callback
    expect(w.chrome.runtime.lastError).toBeUndefined();
  });

  it("closeApp posts exactly the exit message to its own origin", async () => {
    const { w, run } = page({ runtime: realRuntime() });
    const post = vi.fn();
    w.postMessage = post;
    run();
    const { r } = await ask(w, "closeApp");
    expect(r).toEqual({ success: true });
    expect(post).toHaveBeenCalledTimes(1);
    const [msg, target] = post.mock.calls[0];
    expect(msg).toEqual({ type: "MASTERSOS_MOCK_EXIT" });
    expect(Object.keys(msg)).toEqual(["type"]);
    expect(target).toBe(ORIGIN);
  });

  it("method names from the prototype are not handlers", async () => {
    const rt = realRuntime();
    const { w, run } = page({ runtime: rt });
    run();
    await ask(w, "toString");
    await ask(w, "__proto__");
    expect(rt.sendMessage).toHaveBeenCalledTimes(2);
  });

  it("promise form (no callback)", async () => {
    const { w, run } = page();
    run();
    await expect(w.chrome.runtime.sendMessage(EXT, { method: "checkKioskModeStatus" })).resolves.toEqual({
      success: true,
      data: { kioskMode: true },
    });
    await expect(w.chrome.runtime.sendMessage(EXT, { method: "setZoomLevel" })).rejects.toThrow();
  });

  it("chrome.runtime cannot be swapped out by the page", async () => {
    const { w, run } = page();
    run();
    const rt = w.chrome.runtime;
    w.eval("chrome.runtime = { sendMessage() { throw new Error('page'); } };");
    expect(w.chrome.runtime).toBe(rt);
  });

  it("idempotent when run twice", async () => {
    const rt = realRuntime();
    const { w, run } = page({ runtime: rt });
    run();
    run();
    expect(w.navigator.userAgent).toBe(CROS_UA);
    const post = vi.fn();
    w.postMessage = post;
    await ask(w, "closeApp");
    expect(post).toHaveBeenCalledTimes(1);
  });
});
