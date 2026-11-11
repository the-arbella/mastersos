// Tests for kiosk-platform/managed.js (docs/specs/2026-11-10-kiosk-managed-apis-design.md §1, §4). Each case runs the
// script in a fresh JSDOM window with Chrome's shapes put in (NavigatorManagedData with the native
// getManagedConfiguration, navigator.managed); the marker line is replaced the way the agent does it.
import { createRequire } from "node:module";
import { repoFile } from "./helpers.js";

const SRC = repoFile("kiosk-platform/managed.js");
const MARKER = "// @@MASTERSOS_MANAGED@@\n";

const { JSDOM } = createRequire(`${process.cwd()}/`)("jsdom");

const DEVICE = {
  asset_id: "A-100",
  location: "Room 4",
  directory_id: "dir-1",
  hostname: "lab-pc-7",
  serial: "SN123",
};
const METHODS = {
  getDirectoryId: "directory_id",
  getHostname: "hostname",
  getSerialNumber: "serial",
  getAnnotatedAssetId: "asset_id",
  getAnnotatedLocation: "location",
};
const UNKNOWN =
  "The current origin cannot use this web API because it was not granted the 'device-attributes' permission.";

function source(data) {
  const parts = SRC.split(MARKER);
  if (parts.length !== 2) throw new Error("the marker line must occur exactly once");
  return `${parts[0]}const DATA = ${JSON.stringify(data)};\n${parts[1]}`;
}

/** Chrome's shapes in window `w`. */
function shapes(w) {
  w.eval(`
    class NavigatorManagedData extends EventTarget {}
    NavigatorManagedData.prototype.getManagedConfiguration = function getManagedConfiguration(keys) {
      return Promise.reject(new DOMException("Managed configuration is empty. This API is available only for managed apps.", "NotAllowedError"));
    };
    window.NavigatorManagedData = NavigatorManagedData;
    const instance = new NavigatorManagedData();
    Object.defineProperty(Navigator.prototype, "managed", { get() { return instance; }, configurable: true, enumerable: true });
    window.__nativeGMC = NavigatorManagedData.prototype.getManagedConfiguration;
  `);
}

function page(data, { shape = true } = {}) {
  const dom = new JSDOM("<!doctype html><html><head></head><body></body></html>", {
    url: "https://home.testnav.com/",
    runScripts: "outside-only",
  });
  const w = dom.window;
  if (shape) shapes(w);
  return { w, run: () => w.eval(source(data)) };
}

const on = (data) => {
  const p = page(data);
  p.run();
  return { ...p, managed: p.w.navigator.managed };
};

const settle = async (promise) => {
  try {
    return { ok: await promise };
  } catch (e) {
    return { err: e };
  }
};

describe("device attribute methods", () => {
  for (const [method, field] of Object.entries(METHODS)) {
    it(`${method}() resolves the value, null when it has none`, async () => {
      const { managed } = on({ v: 1, device_methods: true, device: DEVICE });
      await expect(managed[method]()).resolves.toBe(DEVICE[field]);
      const none = on({ v: 1, device_methods: true, device: { ...DEVICE, [field]: null } });
      await expect(none.managed[method]()).resolves.toBeNull();
    });

    it(`${method}() rejects UnknownError without a device`, async () => {
      const { managed } = on({ v: 1, device_methods: true });
      const r = await settle(managed[method]());
      expect(r.err.name).toBe("UnknownError");
      expect(r.err.message).toBe(UNKNOWN);
    });
  }

  it("rejects NotAllowedError in a subframe", async () => {
    const p = page({ v: 1, device_methods: true, device: DEVICE });
    const frame = p.w.document.createElement("iframe");
    p.w.document.body.appendChild(frame);
    const fw = frame.contentWindow;
    shapes(fw);
    expect(fw.top).not.toBe(fw);
    fw.eval(source({ v: 1, device_methods: true, device: DEVICE }));
    const r = await settle(fw.navigator.managed.getHostname());
    expect(r.err.name).toBe("NotAllowedError");
    expect(r.err.message).toBe("This API is allowed only in top level frames.");
  });

  it("honours Permissions-Policy when the browser knows the feature", async () => {
    const data = { v: 1, device_methods: true, device: DEVICE };
    const off = page(data);
    off.w.eval(`Object.defineProperty(document, "featurePolicy", { value: {
      features() { return ["camera", "device-attributes"]; }, allowsFeature() { return false; } }, configurable: true });`);
    off.run();
    const r = await settle(off.w.navigator.managed.getHostname());
    expect(r.err.name).toBe("NotAllowedError");
    expect(r.err.message).toBe("Permissions-Policy: device-attributes are disabled.");

    const unknown = page(data);
    unknown.w.eval(`Object.defineProperty(document, "featurePolicy", { value: {
      features() { return ["camera"]; }, allowsFeature() { return false; } }, configurable: true });`);
    unknown.run();
    await expect(unknown.w.navigator.managed.getHostname()).resolves.toBe("lab-pc-7");
  });

  it("returns a promise (never throws) when the checks fail, and rejects TypeError on a wrong this", async () => {
    const { w, managed } = on({ v: 1, device_methods: true });
    const proto = w.NavigatorManagedData.prototype;
    const p = managed.getSerialNumber();
    expect(p).toBeInstanceOf(w.Promise);
    await settle(p);
    for (const m of Object.keys(METHODS)) {
      const bad = proto[m].call({});
      expect(bad).toBeInstanceOf(w.Promise);
      expect((await settle(bad)).err).toBeInstanceOf(w.TypeError);
    }
  });

  it("are not installed when device_methods is false", () => {
    const { w } = on({ v: 1, device_methods: false });
    for (const m of Object.keys(METHODS)) expect(m in w.NavigatorManagedData.prototype).toBe(false);
  });
});

describe("getManagedConfiguration", () => {
  const data = { v: 1, device_methods: false, managed: { a: { b: 1 }, c: 2 } };

  it("resolves only the requested keys that exist, as a fresh copy each time", async () => {
    const { managed } = on(data);
    const first = await managed.getManagedConfiguration(["a", "zzz"]);
    expect(first).toEqual({ a: { b: 1 } });
    first.a.b = 99;
    first.x = 1;
    await expect(managed.getManagedConfiguration(["a", "zzz"])).resolves.toEqual({ a: { b: 1 } });
  });

  it("accepts any iterable of strings", async () => {
    const { managed } = on(data);
    await expect(managed.getManagedConfiguration(new Set(["c"]))).resolves.toEqual({ c: 2 });
  });

  it("rejects TypeError without arguments or with a non-sequence", async () => {
    const { w, managed } = on(data);
    for (const call of [
      () => managed.getManagedConfiguration(),
      () => managed.getManagedConfiguration(5),
      () => managed.getManagedConfiguration(null),
      () => managed.getManagedConfiguration("ab"),
      () => managed.getManagedConfiguration({}),
    ]) {
      const p = call();
      expect(p).toBeInstanceOf(w.Promise);
      expect((await settle(p)).err).toBeInstanceOf(w.TypeError);
    }
    const bad = w.NavigatorManagedData.prototype.getManagedConfiguration.call({}, ["a"]);
    expect((await settle(bad)).err).toBeInstanceOf(w.TypeError);
  });

  it("leaves the native method alone without a managed configuration", async () => {
    const p = page({ v: 1, device_methods: true, device: DEVICE });
    p.run();
    expect(p.w.NavigatorManagedData.prototype.getManagedConfiguration).toBe(p.w.__nativeGMC);
    const r = await settle(p.w.navigator.managed.getManagedConfiguration(["a"]));
    expect(r.err.name).toBe("NotAllowedError");
  });
});

describe("looks native", () => {
  it("length, descriptors and toString match native methods", () => {
    const { w } = on({ v: 1, device_methods: true, device: DEVICE, managed: { a: 1 } });
    const proto = w.NavigatorManagedData.prototype;
    const names = [...Object.keys(METHODS), "getManagedConfiguration"];
    for (const name of names) {
      const fn = proto[name];
      expect(fn.length).toBe(name === "getManagedConfiguration" ? 1 : 0);
      expect(fn.name).toBe(name);
      expect(Object.getOwnPropertyDescriptor(proto, name)).toMatchObject({
        writable: true,
        enumerable: true,
        configurable: true,
      });
      expect(w.Function.prototype.toString.call(fn)).toBe(`function ${name}() { [native code] }`);
      expect("prototype" in fn).toBe(false);
    }
  });

  it("touches nothing else on navigator", () => {
    const { w } = on({ v: 1, device_methods: true, device: DEVICE });
    expect(Object.getOwnPropertyNames(w.navigator)).toEqual([]);
  });
});

describe("leaves the page alone", () => {
  const data = { v: 1, device_methods: true, device: DEVICE, managed: { a: 1 } };

  it("without NavigatorManagedData", () => {
    const { w, run } = page(data, { shape: false });
    expect(() => run()).not.toThrow();
    expect("NavigatorManagedData" in w).toBe(false);
  });

  it("without navigator.managed", () => {
    const { w, run } = page(data);
    w.eval(`delete Navigator.prototype.managed;`);
    expect(() => run()).not.toThrow();
    expect("getHostname" in w.NavigatorManagedData.prototype).toBe(false);
    expect(w.NavigatorManagedData.prototype.getManagedConfiguration).toBe(w.__nativeGMC);
  });

  it("in an insecure context", () => {
    const { w, run } = page(data);
    Object.defineProperty(w, "isSecureContext", { value: false, configurable: true });
    expect(() => run()).not.toThrow();
    expect("getHostname" in w.NavigatorManagedData.prototype).toBe(false);
    expect(w.NavigatorManagedData.prototype.getManagedConfiguration).toBe(w.__nativeGMC);
  });

  it("running twice changes nothing more", () => {
    const { w, run } = page(data);
    run();
    const fn = w.NavigatorManagedData.prototype.getHostname;
    run();
    expect(w.NavigatorManagedData.prototype.getHostname).toBe(fn);
  });
});

describe("source", () => {
  it("has the marker line exactly once, no CJK text, and nothing about tokens or attestation", () => {
    expect(SRC.split(MARKER).length).toBe(2);
    expect(SRC).not.toMatch(/[⺀-鿿가-힯豈-﫿＀-￯]/u);
    expect(SRC.replace(/^\s*\/\/.*$/gm, "")).not.toMatch(/attest|token/i);
  });
});
