// ChromeOS disguise, MAIN world, document_start (design docs/specs/2026-11-06-kiosk-platform-inject-design.md §4).
// Registered by background.js for a kiosk app with platform = "chromeos", on that app's hosts only. The pages see what
// Chrome on a Chromebook shows them; the request headers are changed to match by background.js's DNR session rule
// (same formulas: chromeOsUa / chromeOsVersion there and here, kept equal by tests/platform-chromeos.test.js).
//   - navigator.userAgent / appVersion: "(X11; Linux <arch>)" -> "(X11; CrOS <arch> 14541.0.0)", the frozen ChromeOS
//     platform part of Chrome's reduced user agent; the Chrome version stays the real one.
//   - navigator.platform: unchanged ("Linux x86_64" on a Chromebook too).
//   - navigator.userAgentData: platform "Chrome OS"; getHighEntropyValues() and toJSON() say "Chrome OS" and a ChromeOS
//     platformVersion; brands, fullVersionList, architecture, bitness, model... are the real ones (the same on ChromeOS).
// The getters stay on the prototypes (nothing new on navigator itself) and their toString() reads like native code.
// Never anything about attestation or tokens: only what the platform looks like (design, bottom line).
(() => {
  "use strict";
  const MARK = Symbol.for("mastersos.platform.chromeos");
  if (window[MARK]) return;
  Object.defineProperty(window, MARK, { value: true });

  // --- the values (the same functions are in background.js) ------------------------------------------------------
  const CROS_FROZEN = "14541.0.0";
  function chromeOsUa(ua) {
    return ua.replace(/\(X11; Linux ([^)]+)\)/, (_, arch) => `(X11; CrOS ${arch} ${CROS_FROZEN})`);
  }
  // M120 shipped with ChromeOS 15662; about 37 builds per milestone since. An approximation (design §4).
  function chromeOsVersion(major) {
    const m = Number.isFinite(major) && major > 0 ? major : 120;
    return `${15662 + Math.round((m - 120) * 37.3)}.0.0`;
  }
  function chromeMajor(brands, ua) {
    const b = Array.isArray(brands) ? brands.find((x) => x && /^(Google Chrome|Chromium)$/.test(x.brand)) : null;
    const n = b ? parseInt(b.version, 10) : NaN;
    if (Number.isFinite(n)) return n;
    const m = /Chrome\/(\d+)/.exec(ua);
    return m ? parseInt(m[1], 10) : NaN;
  }

  const NavProto = window.Navigator && window.Navigator.prototype;
  if (!NavProto) return;
  const uaDesc = Object.getOwnPropertyDescriptor(NavProto, "userAgent");
  if (!uaDesc || typeof uaDesc.get !== "function") return;
  const realUa = uaDesc.get.call(navigator);
  const ua = chromeOsUa(realUa);
  if (ua === realUa) return; // not Chrome on Linux (already CrOS, or something else): leave it alone

  // --- native-looking toString ---------------------------------------------------------------------------------
  const nativeToString = Function.prototype.toString;
  const disguised = new WeakMap();
  const toString = {
    toString() {
      return disguised.has(this) ? disguised.get(this) : nativeToString.call(this);
    },
  }.toString;
  disguised.set(toString, nativeToString.call(nativeToString));
  Object.defineProperty(Function.prototype, "toString", {
    value: toString,
    writable: true,
    configurable: true,
    enumerable: false,
  });
  const as = (fn, original) => {
    disguised.set(fn, nativeToString.call(original));
    return fn;
  };
  // obj is an object literal with the new getter under the same name (so the function's name is "get <name>")
  const replaceGetter = (proto, name, desc, obj) => {
    const get = Object.getOwnPropertyDescriptor(obj, name).get;
    Object.defineProperty(proto, name, { ...desc, get: as(get, desc.get) });
  };

  // --- navigator.userAgent / appVersion --------------------------------------------------------------------------
  replaceGetter(NavProto, "userAgent", uaDesc, {
    get userAgent() {
      return ua;
    },
  });
  const avDesc = Object.getOwnPropertyDescriptor(NavProto, "appVersion");
  if (avDesc && typeof avDesc.get === "function") {
    const av = chromeOsUa(avDesc.get.call(navigator));
    replaceGetter(NavProto, "appVersion", avDesc, {
      get appVersion() {
        return av;
      },
    });
  }

  // --- navigator.userAgentData ---------------------------------------------------------------------------------
  const UAData = window.NavigatorUAData;
  const uadProto = UAData && UAData.prototype;
  if (!uadProto) return;
  const PLATFORM = "Chrome OS";
  const uad = navigator.userAgentData;
  const version = chromeOsVersion(chromeMajor(uad && uad.brands, realUa));

  const pDesc = Object.getOwnPropertyDescriptor(uadProto, "platform");
  if (pDesc && typeof pDesc.get === "function") {
    replaceGetter(uadProto, "platform", pDesc, {
      get platform() {
        return PLATFORM;
      },
    });
  }
  const fix = (r) => {
    if (r && typeof r === "object") {
      if ("platform" in r) r.platform = PLATFORM;
      if ("platformVersion" in r) r.platformVersion = version;
    }
    return r;
  };
  const realHigh = uadProto.getHighEntropyValues;
  if (typeof realHigh === "function") {
    const getHighEntropyValues = {
      getHighEntropyValues(hints) {
        return realHigh.call(this, hints).then(fix);
      },
    }.getHighEntropyValues;
    Object.defineProperty(uadProto, "getHighEntropyValues", {
      ...Object.getOwnPropertyDescriptor(uadProto, "getHighEntropyValues"),
      value: as(getHighEntropyValues, realHigh),
    });
  }
  const realToJSON = uadProto.toJSON;
  if (typeof realToJSON === "function") {
    const toJSON = {
      toJSON() {
        return fix(realToJSON.call(this));
      },
    }.toJSON;
    Object.defineProperty(uadProto, "toJSON", {
      ...Object.getOwnPropertyDescriptor(uadProto, "toJSON"),
      value: as(toJSON, realToJSON),
    });
  }
})();
