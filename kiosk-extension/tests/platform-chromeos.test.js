// Tests for the ChromeOS disguise (kiosk-platform/chromeos.js, docs/specs/2026-11-06-kiosk-platform-inject-design.md
// §4). Each case runs the script in a fresh JSDOM window with Chrome's shapes put in: userAgent / appVersion getters on
// Navigator.prototype and a NavigatorUAData class (jsdom has none). The values must equal the platform extension's
// background.js DNR rule.
import { createRequire } from "node:module";
import { repoFile } from "./helpers.js";

const SRC = repoFile("kiosk-platform/chromeos.js");
const BG = repoFile("kiosk-platform/background.js");

const { JSDOM } = createRequire(`${process.cwd()}/`)("jsdom");

const LINUX_UA =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36";
const CROS_UA =
  "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36";
const BRANDS = [
  { brand: "Not:A-Brand", version: "8" },
  { brand: "Google Chrome", version: "156" },
  { brand: "Chromium", version: "156" },
];
const HIGH = {
  architecture: "x86",
  bitness: "64",
  brands: BRANDS,
  fullVersionList: [{ brand: "Google Chrome", version: "156.0.8078.79" }],
  mobile: false,
  model: "",
  platform: "Linux",
  platformVersion: "6.8.0",
  uaFullVersion: "156.0.8078.79",
  wow64: false,
};

function page({ ua = LINUX_UA, uad = true } = {}) {
  const dom = new JSDOM("<!doctype html><html><head></head><body></body></html>", {
    url: "https://home.testnav.com/",
    runScripts: "outside-only",
  });
  const w = dom.window;
  // Chrome's own shapes, as native getters (configurable, on the prototype).
  w.eval(`
    Object.defineProperty(Navigator.prototype, "userAgent", { get() { return ${JSON.stringify(ua)}; }, configurable: true, enumerable: true });
    Object.defineProperty(Navigator.prototype, "appVersion", { get() { return ${JSON.stringify(ua.replace(/^Mozilla\//, ""))}; }, configurable: true, enumerable: true });
  `);
  if (uad) {
    w.eval(`
      class NavigatorUAData {}
      Object.defineProperty(NavigatorUAData.prototype, "platform", { get() { return "Linux"; }, configurable: true, enumerable: true });
      Object.defineProperty(NavigatorUAData.prototype, "brands", { get() { return ${JSON.stringify(BRANDS)}; }, configurable: true, enumerable: true });
      Object.defineProperty(NavigatorUAData.prototype, "mobile", { get() { return false; }, configurable: true, enumerable: true });
      NavigatorUAData.prototype.getHighEntropyValues = function getHighEntropyValues(hints) {
        const all = ${JSON.stringify(HIGH)};
        const out = { brands: all.brands, mobile: false, platform: "Linux" };
        for (const h of hints) if (h in all) out[h] = all[h];
        return Promise.resolve(out);
      };
      NavigatorUAData.prototype.toJSON = function toJSON() { return { brands: this.brands, mobile: false, platform: this.platform }; };
      window.NavigatorUAData = NavigatorUAData;
      const data = new NavigatorUAData();
      Object.defineProperty(Navigator.prototype, "userAgentData", { get() { return data; }, configurable: true, enumerable: true });
    `);
  }
  return { w, run: () => w.eval(SRC) };
}

describe("platform/chromeos.js", () => {
  it("userAgent and appVersion are ChromeOS's, with the real Chrome version", () => {
    const { w, run } = page();
    run();
    expect(w.navigator.userAgent).toBe(CROS_UA);
    expect(w.navigator.appVersion).toBe(CROS_UA.replace(/^Mozilla\//, ""));
    expect(w.navigator.userAgent).not.toMatch(/Linux/);
  });

  it("aarch64 keeps its architecture", () => {
    const { w, run } = page({ ua: LINUX_UA.replace("x86_64", "aarch64") });
    run();
    expect(w.navigator.userAgent).toBe(CROS_UA.replace("x86_64", "aarch64"));
  });

  it("navigator.platform is untouched, nothing new on navigator itself", () => {
    const { w, run } = page();
    const before = w.navigator.platform;
    run();
    expect(w.navigator.platform).toBe(before);
    for (const k of ["userAgent", "appVersion", "userAgentData", "platform"]) {
      expect(Object.getOwnPropertyDescriptor(w.navigator, k), k).toBeUndefined();
    }
  });

  it("userAgentData says Chrome OS; high-entropy values keep everything else real", async () => {
    const { w, run } = page();
    run();
    const d = w.navigator.userAgentData;
    expect(d.platform).toBe("Chrome OS");
    const h = await d.getHighEntropyValues(["platform", "platformVersion", "architecture", "bitness", "model", "fullVersionList", "uaFullVersion"]);
    expect(h).toEqual({
      brands: BRANDS,
      mobile: false,
      platform: "Chrome OS",
      platformVersion: "17005.0.0",
      architecture: "x86",
      bitness: "64",
      model: "",
      fullVersionList: HIGH.fullVersionList,
      uaFullVersion: "156.0.8078.79",
    });
    // without platformVersion asked for, none is added
    expect(await d.getHighEntropyValues(["model"])).toEqual({ brands: BRANDS, mobile: false, platform: "Chrome OS", model: "" });
    expect(d.toJSON()).toEqual({ brands: BRANDS, mobile: false, platform: "Chrome OS" });
  });

  it("the replaced getters and methods read like native code", () => {
    const { w, run } = page();
    const before = (o, k, part) => w.Function.prototype.toString.call(Object.getOwnPropertyDescriptor(o, k)[part]);
    const nav = w.Navigator.prototype;
    const uad = w.NavigatorUAData.prototype;
    const want = [
      [nav, "userAgent", "get"],
      [nav, "appVersion", "get"],
      [uad, "platform", "get"],
      [uad, "getHighEntropyValues", "value"],
      [uad, "toJSON", "value"],
    ].map(([o, k, p]) => before(o, k, p));
    run();
    const got = [
      Object.getOwnPropertyDescriptor(nav, "userAgent").get,
      Object.getOwnPropertyDescriptor(nav, "appVersion").get,
      Object.getOwnPropertyDescriptor(uad, "platform").get,
      uad.getHighEntropyValues,
      uad.toJSON,
    ].map((f) => w.Function.prototype.toString.call(f));
    expect(got).toEqual(want);
    expect(String(w.Function.prototype.toString)).toBe("function toString() { [native code] }");
    expect(Object.getOwnPropertyDescriptor(nav, "userAgent").get.name).toBe("get userAgent");
    expect(uad.getHighEntropyValues.name).toBe("getHighEntropyValues");
  });

  it("a UA that is not Linux's is left alone; running twice changes nothing", () => {
    const a = page({ ua: CROS_UA });
    a.run();
    expect(a.w.navigator.userAgent).toBe(CROS_UA);
    expect(a.w.navigator.userAgentData.platform).toBe("Linux");
    const b = page();
    b.run();
    b.run();
    expect(b.w.navigator.userAgent).toBe(CROS_UA);
  });

  it("without userAgentData (not a secure context) the UA is still changed", () => {
    const { w, run } = page({ uad: false });
    run();
    expect(w.navigator.userAgent).toBe(CROS_UA);
  });

  it("the same values as background.js's request header rule", async () => {
    let rule;
    const id = "abcdefghijklmnopabcdefghijklmnop";
    const chrome = {
      tabs: { query: vi.fn(), reload: vi.fn(), update: vi.fn(async () => ({})) },
      declarativeNetRequest: {
        updateSessionRules: vi.fn(async (r) => {
          rule = r.addRules[0];
        }),
      },
      runtime: {
        id,
        onMessage: { addListener: (f) => (chrome.listener = f) },
        onInstalled: { addListener: () => {} },
        getURL: (p) => `chrome-extension://${id}/${p}`,
      },
    };
    const self = {};
    const importScripts = () => {
      self.MASTERSOS_PLATFORM = { v: 1, url: "https://a.org/", hosts: ["a.org"], platform: "chromeos", inject: false, exam: "ponmlkjihgfedcbaponmlkjihgfedcba" };
    };
    new Function("chrome", "navigator", "self", "importScripts", BG)(
      chrome,
      { userAgent: LINUX_UA, userAgentData: { brands: BRANDS } },
      self,
      importScripts,
    );
    const reply = vi.fn();
    chrome.listener({ cmd: "launch" }, { id, url: chrome.runtime.getURL("start.html"), tab: { id: 1 } }, reply);
    await vi.waitFor(() => expect(reply).toHaveBeenCalledWith({ ok: true }));
    const { w, run } = page();
    run();
    const h = await w.navigator.userAgentData.getHighEntropyValues(["platformVersion"]);
    const headers = Object.fromEntries(rule.action.requestHeaders.map((x) => [x.header, x.value]));
    expect(headers["user-agent"]).toBe(w.navigator.userAgent);
    expect(headers["sec-ch-ua-platform"]).toBe(JSON.stringify(w.navigator.userAgentData.platform));
    expect(headers["sec-ch-ua-platform-version"]).toBe(JSON.stringify(h.platformVersion));
  });
});
