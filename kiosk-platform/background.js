// The platform extension's service worker (design docs/specs/2026-11-06-kiosk-platform-inject-design.md §3). The agent
// builds one platform extension per kiosk app with platform or inject, signs it with the app's own key and force-installs
// it in that app's sessions only; config.js (written by the agent) says which app. Only this extension has the
// declarativeNetRequest and tabs permissions and host permissions, and only on the app's hosts: the exam extension
// keeps nativeMessaging, storage and NWEA's hosts.
//   - {cmd:"launch"} from this extension's own start page: put the DNR session rule for the ChromeOS request headers in
//     place (platform only), then send that tab to the app's url. The content scripts (platform/chromeos.js, relay.js,
//     inject.js) are static: they are there as soon as the extension is.
//   - {cmd:"exit"} from the start page's Exit button or from relay.js (the inject script's mastersos.exit()): passed on
//     to the exam extension, which checks that it comes from this app's platform extension (its managed storage says
//     which) and asks the exit host. The answer goes back unchanged.
//   - On install: reload the start page tab, opened before this extension existed.
"use strict";

importScripts("config.js");
const CFG = self.MASTERSOS_PLATFORM;

const START_PAGE = "start.html";
const PLATFORM_RULE = 1;
// Every request type, main_frame included (DNR leaves main_frame out when resourceTypes is not given).
const RESOURCE_TYPES = [
  "main_frame",
  "sub_frame",
  "stylesheet",
  "script",
  "image",
  "font",
  "object",
  "xmlhttprequest",
  "ping",
  "csp_report",
  "media",
  "websocket",
  "webtransport",
  "webbundle",
  "other",
];

// --- ChromeOS values (the same functions are in chromeos.js) -------------------------------------------------------
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

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const only = (msg, cmd) => isObj(msg) && Object.keys(msg).length === 1 && msg.cmd === cmd;

/** The DNR session rule for the ChromeOS request headers on the app's hosts. */
function platformRule(hosts) {
  const realUa = navigator.userAgent;
  const uad = navigator.userAgentData;
  const version = chromeOsVersion(chromeMajor(uad && uad.brands, realUa));
  return {
    id: PLATFORM_RULE,
    priority: 1,
    action: {
      type: "modifyHeaders",
      requestHeaders: [
        { header: "user-agent", operation: "set", value: chromeOsUa(realUa) },
        { header: "sec-ch-ua-platform", operation: "set", value: '"Chrome OS"' },
        { header: "sec-ch-ua-platform-version", operation: "set", value: `"${version}"` },
      ],
    },
    condition: { requestDomains: hosts, resourceTypes: RESOURCE_TYPES },
  };
}

/** This extension's start page, in a tab. */
function fromStartPage(sender) {
  if (!sender || sender.id !== chrome.runtime.id || !sender.tab || typeof sender.tab.id !== "number") return false;
  const page = chrome.runtime.getURL(START_PAGE);
  return typeof sender.url === "string" && (sender.url === page || sender.url.startsWith(`${page}#`));
}

/** relay.js (a content script of this extension, top frame of a page on the app's hosts) or the start page. */
function mayExit(sender) {
  if (fromStartPage(sender)) return true;
  if (!sender || sender.id !== chrome.runtime.id || !sender.tab || sender.frameId !== 0) return false;
  let host;
  try {
    const u = new URL(sender.url);
    if (u.protocol !== "https:") return false;
    host = u.hostname;
  } catch {
    return false;
  }
  return CFG.hosts.some((h) => host === h || host.endsWith(`.${h}`));
}

async function launch(tabId) {
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [PLATFORM_RULE],
    addRules: CFG.platform === "chromeos" ? [platformRule(CFG.hosts)] : [],
  });
  await chrome.tabs.update(tabId, { url: CFG.url });
}

function forwardExit(respond) {
  try {
    chrome.runtime.sendMessage(CFG.exam, { cmd: "exit" }, (r) => {
      if (chrome.runtime.lastError) respond({ ok: false });
      else respond({ ok: isObj(r) && r.ok === true });
    });
  } catch {
    respond({ ok: false });
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (only(msg, "launch") && fromStartPage(sender)) {
    launch(sender.tab.id).then(
      () => sendResponse({ ok: true }),
      () => sendResponse({ ok: false }),
    );
    return true;
  }
  if (only(msg, "exit") && mayExit(sender)) {
    forwardExit(sendResponse);
    return true;
  }
  return false;
});

chrome.runtime.onInstalled.addListener((details) => {
  if (!details || details.reason !== "install") return;
  // The start page opened before this extension was installed shows Chrome's error page; its address is still ours.
  const page = chrome.runtime.getURL(START_PAGE);
  chrome.tabs.query({}, (tabs) => {
    void chrome.runtime.lastError;
    for (const t of tabs || []) {
      const u = t.url || t.pendingUrl || "";
      if ((u === page || u.startsWith(`${page}#`)) && typeof t.id === "number") {
        chrome.tabs.reload(t.id, () => void chrome.runtime.lastError);
      }
    }
  });
});
