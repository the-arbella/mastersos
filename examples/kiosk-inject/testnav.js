// Example kiosk inject script for Pearson TestNav (docs/specs/2026-11-06-kiosk-platform-inject-design.md §10; the
// analysis is in docs/specs/2026-11-06-testnav-chromeos-mock.md §2). Put it in the settings bundle as files/testnav.js
// and write, in the kiosk app: platform = "chromeos" and inject = "files/testnav.js". It runs in the page's world at
// document_start on the app's hosts; platform = "chromeos" already makes the UA (and userAgentData, request headers)
// ChromeOS, this script only adds what is TestNav's own.
// On a ChromeOS kiosk, TestNav's App API (app.testnav.com/api.js, loaded by home.testnav.com and every customer
// site) decides it is the "ChromeOS PWA" client from navigator.userAgent alone:
//   - ua-parser must see "CrOS" (OS "Chromium OS"), and the UA must contain "TestNavPWA…/<version>" with
//     version >= 1.14 (checkClientContext: clientContextSupported, chromeExtensionInstalled);
//   - kiosk / locked status is chrome.runtime.sendMessage(<TestNav extension id>, {method: "checkKioskModeStatus"})
//     answered {success: true, data: {kioskMode}}; the extension says true only where chrome.audio works (ChromeOS).
// TestNav's own extension (force-installed next to ours) appends " TestNavPWAKiosk/<v>" or " TestNavPWA/<v>" itself,
// but on Linux it would always say unlocked. Here: the UA gets the kiosk suffix, fixed before any page script runs;
// and calls to that extension id go through a wrapper that answers the ChromeOS-only methods and forwards the rest to
// the real extension (or reports an error when it is not installed). closeApp ends the locked session with
// mastersos.exit() (the inject wrapper's, kiosk-platform/inject-wrapper.js) instead of closing every Chrome window.
// Bottom line: generateAppValidityCheckToken (Verified Access) is never forged and never forwarded.
(() => {
  "use strict";
  const MARK = Symbol.for("mastersos.mock.testnav");
  if (window[MARK]) return;
  Object.defineProperty(window, MARK, { value: true });

  const EXT_ID = "gjhfdhjfmmgldldpmfdmbddbegbachgo";
  // The version TestNav's extension 1.15.7 puts in the UA (App API v3.5.14 accepts >= 1.14).
  const APP_VERSION = "1.15.7";
  // Only when platform = "chromeos" is missing: the frozen ChromeOS part of Chrome's reduced UA.
  const CROS_BUILD = "14541.0.0";

  // --- navigator.userAgent -------------------------------------------------------------------------------------
  // The kiosk app suffix on the UA. It is read from Navigator.prototype at each access, so the ChromeOS UA of
  // platform = "chromeos" shows whichever script runs first. Without platform (not recommended) the "(X11; Linux …)"
  // part is made CrOS here: no "Linux" may remain (the test client's detectBrowser calls any UA with "Linux" a Linux
  // browser). Own non-configurable properties on navigator, so TestNav extension's own asynchronous append (which on
  // Linux would say unlocked) cannot replace them.
  function kioskUa(ua) {
    let out = ua;
    if (!/\bCrOS\b/.test(out)) {
      out = out.replace(/\(X11; Linux ([^)]+)\)/, (_, arch) => `(X11; CrOS ${arch} ${CROS_BUILD})`);
    }
    if (!/TestNavPWA/.test(out)) out = `${out} TestNavPWAKiosk/${APP_VERSION}`;
    return out;
  }
  const proto = Object.getPrototypeOf(navigator);
  const fallback = String(navigator.userAgent);
  const readUa = () => {
    const d = Object.getOwnPropertyDescriptor(proto, "userAgent");
    return d && typeof d.get === "function" ? d.get.call(navigator) : fallback;
  };
  Object.defineProperty(navigator, "userAgent", { get: () => kioskUa(readUa()), configurable: false, enumerable: true });
  if (typeof navigator.appVersion === "string") {
    Object.defineProperty(navigator, "appVersion", {
      get: () => kioskUa(readUa()).replace(/^Mozilla\//, ""),
      configurable: false,
      enumerable: true,
    });
  }

  // --- chrome.runtime.sendMessage to TestNav's extension --------------------------------------------------------
  const ok = (data) => (data === undefined ? { success: true } : { success: true, data });
  const fail = (msg) => ({ success: false, data: { errors: [msg] } });
  const UNSUPPORTED = "is not supported on this platform";
  // Answered here whether or not TestNav's extension is installed.
  const LOCAL = {
    // ChromeOS: chrome.audio.getMute resolves only in a kiosk session. Ours is a locked session (design §4).
    checkKioskModeStatus: () => ok({ kioskMode: true }),
    // ChromeOS accessibility features (ChromeVox, floating menu…) do not exist here; the locked session sets its own.
    disableAccessibilityFeatures: () => ok(),
    resetAccessibilityFeatures: () => ok(),
    // Verified Access (chrome.enterprise.platformKeys.challengeKey) cannot be produced off a managed Chromebook. The
    // App API does not ask for it on the ChromeOS PWA path; if anything does, say what TestNav's extension says on
    // any non-ChromeOS platform. Never forward it.
    generateAppValidityCheckToken: () => fail(`generateAppValidityCheckToken ${UNSUPPORTED}`),
    // TestNav's extension closes every Chrome window; the locked session would restart Chrome. End the session.
    closeApp: () => {
      mastersos.exit();
      return ok();
    },
  };
  // chrome.audio is ChromeOS-only: TestNav's extension fails these on Linux too; say so without the round trip.
  for (const m of ["checkAudioLevel", "setAudioLevel"]) LOCAL[m] = () => fail(`${m} ${UNSUPPORTED}`);

  const chromeObj = window.chrome && typeof window.chrome === "object" ? window.chrome : {};
  if (chromeObj !== window.chrome) {
    try {
      Object.defineProperty(window, "chrome", { value: chromeObj, writable: true, configurable: true });
    } catch {
      return;
    }
  }
  const real = chromeObj.runtime && typeof chromeObj.runtime.sendMessage === "function" ? chromeObj.runtime : null;
  const realSend = real ? real.sendMessage.bind(real) : null;
  let localError; // chrome.runtime.lastError while one of our own callbacks runs

  function deliver(callback, response, error) {
    if (typeof callback !== "function") return;
    setTimeout(() => {
      localError = error;
      try {
        callback(response);
      } finally {
        localError = undefined;
      }
    }, 0);
  }

  // chrome.runtime.sendMessage([extensionId,] message [, options] [, callback]); pages always pass the id.
  function sendMessage(...args) {
    const callback = typeof args[args.length - 1] === "function" ? args.pop() : undefined;
    const [extensionId, message] = args;
    if (extensionId === EXT_ID && message !== null && typeof message === "object") {
      const handler = Object.prototype.hasOwnProperty.call(LOCAL, message.method) ? LOCAL[message.method] : null;
      if (handler) {
        const response = handler(message.data);
        if (callback) {
          deliver(callback, response, undefined);
          return undefined;
        }
        return Promise.resolve(response);
      }
    }
    if (realSend) return callback ? realSend(...args, callback) : realSend(...args);
    const error = { message: "Could not establish connection. Receiving end does not exist." };
    if (callback) {
      deliver(callback, undefined, error);
      return undefined;
    }
    return Promise.reject(new Error(error.message));
  }

  const runtime = Object.create(real || null, {
    sendMessage: { value: sendMessage, enumerable: true },
    lastError: { get: () => localError || (real ? real.lastError : undefined), enumerable: true },
  });
  try {
    Object.defineProperty(chromeObj, "runtime", { value: runtime, writable: false, configurable: false, enumerable: true });
  } catch {
    // chrome.runtime cannot be replaced: wrap the method on the real object instead (lastError stays Chrome's).
    try {
      if (real) real.sendMessage = sendMessage;
    } catch {
      console.warn("MastersOS: TestNav mock env could not wrap chrome.runtime.sendMessage");
    }
  }
})();
