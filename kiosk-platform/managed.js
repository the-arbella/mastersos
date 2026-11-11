// Managed APIs, MAIN world, document_start (design docs/specs/2026-11-10-kiosk-managed-apis-design.md §1 and §4).
// A static content script of the app's platform extension (built by the agent for a kiosk app that writes platform,
// device_attributes or managed_config), on that app's hosts only. It makes navigator.managed behave as it does in a
// ChromeOS kiosk, following Chromium's implementation (blink modules/managed_device, chrome/browser/device_api):
//   - five device attribute methods on NavigatorManagedData.prototype (they do not exist on Linux Chrome):
//     getDirectoryId(), getHostname(), getSerialNumber(), getAnnotatedAssetId(), getAnnotatedLocation(); each resolves
//     a string, or null when there is no value. Preflight failures are rejected promises, never synchronous throws:
//     not top level, Permissions-Policy off, origin not granted (UnknownError).
//   - getManagedConfiguration(keys), replaced only when the app has a managed configuration: resolves a fresh copy of
//     the requested keys that exist. Without one the native method stays (it rejects the same NotAllowedError).
// The values are embedded by the agent in place of the marker line below. Only the prototype is touched; descriptors,
// length and toString() match native methods. Nothing here is about attestation or tokens (design, bottom line).
(() => {
  "use strict";
  const MARK = Symbol.for("mastersos.platform.managed");
  if (window[MARK]) return;
  Object.defineProperty(window, MARK, { value: true });

  // @@MASTERSOS_MANAGED@@

  const Managed = window.NavigatorManagedData;
  const proto = Managed && Managed.prototype;
  if (!proto) return;
  if (window.isSecureContext === false) return; // [SecureContext]
  if (!navigator.managed) return; // Chrome changed: do not invent it
  const DOMEx = window.DOMException;

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
  const as = (fn) => {
    disguised.set(fn, `function ${fn.name}() { [native code] }`);
    return fn;
  };
  // Same descriptor as a native WebIDL operation.
  const install = (name, fn) =>
    Object.defineProperty(proto, name, { value: as(fn), writable: true, enumerable: true, configurable: true });

  const rejected = (name, message) => Promise.reject(new DOMEx(message, name));
  const typeError = (message) => Promise.reject(new TypeError(message));
  const isManaged = (self) => self instanceof Managed;

  // --- device attributes -----------------------------------------------------------------------------------------
  if (DATA.device_methods) {
    const attribute = (self, field) => {
      if (!isManaged(self)) return typeError("Illegal invocation");
      if (window.top !== window) return rejected("NotAllowedError", "This API is allowed only in top level frames.");
      const fp = document.featurePolicy;
      if (
        fp &&
        typeof fp.features === "function" &&
        fp.features().includes("device-attributes") &&
        !fp.allowsFeature("device-attributes")
      ) {
        return rejected("NotAllowedError", "Permissions-Policy: device-attributes are disabled.");
      }
      const device = DATA.device;
      if (!device) {
        return rejected(
          "UnknownError",
          "The current origin cannot use this web API because it was not granted the 'device-attributes' permission.",
        );
      }
      const v = device[field];
      return Promise.resolve(typeof v === "string" ? v : null);
    };
    install("getDirectoryId", {
      getDirectoryId() {
        return attribute(this, "directory_id");
      },
    }.getDirectoryId);
    install("getHostname", {
      getHostname() {
        return attribute(this, "hostname");
      },
    }.getHostname);
    install("getSerialNumber", {
      getSerialNumber() {
        return attribute(this, "serial");
      },
    }.getSerialNumber);
    install("getAnnotatedAssetId", {
      getAnnotatedAssetId() {
        return attribute(this, "asset_id");
      },
    }.getAnnotatedAssetId);
    install("getAnnotatedLocation", {
      getAnnotatedLocation() {
        return attribute(this, "location");
      },
    }.getAnnotatedLocation);
  }

  // --- managed configuration ---------------------------------------------------------------------------------------
  const managed = DATA.managed;
  if (managed && typeof managed === "object" && typeof proto.getManagedConfiguration === "function") {
    const hasOwn = Object.prototype.hasOwnProperty;
    install("getManagedConfiguration", {
      getManagedConfiguration(keys) {
        if (!isManaged(this)) return typeError("Illegal invocation");
        if (arguments.length < 1) {
          return typeError("Failed to execute 'getManagedConfiguration' on 'NavigatorManagedData': 1 argument required, but only 0 present.");
        }
        // WebIDL sequence<DOMString>: an object with Symbol.iterator, each item converted with String().
        let list;
        try {
          if (keys === null || (typeof keys !== "object" && typeof keys !== "function") || typeof keys[Symbol.iterator] !== "function") {
            return typeError("Failed to execute 'getManagedConfiguration' on 'NavigatorManagedData': The provided value cannot be converted to a sequence.");
          }
          list = Array.from(keys, (k) => String(k));
        } catch (e) {
          return Promise.reject(e);
        }
        const out = {};
        for (const k of list) {
          if (!hasOwn.call(managed, k)) continue;
          const value = JSON.parse(JSON.stringify(managed[k])); // a fresh copy each call (the data came from JSON)
          Object.defineProperty(out, k, { value, writable: true, enumerable: true, configurable: true });
        }
        return Promise.resolve(out);
      },
    }.getManagedConfiguration);
  }
})();
