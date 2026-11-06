// MastersOS 考试扩展的后台（MV3 service worker，计划 9 Task 7）。
// 只做一件事：自己的内容脚本发来恰好 {cmd:"exit"} 时，经 native messaging 连 org.mastersos.kiosk_exit
// （镜像里的 /usr/lib/mastersos/mastersos-kiosk-exit → mastersos-agent kiosk exit-host）请它结束锁定会话。
// 宿主回 {"ok":true} 的意思是「已请求」：会话随即结束，之后什么都等不到；其余（{"ok":false}、没回就断开、
// 连不上）一律回内容脚本 {ok:false}，由它请学生找老师。
// Also (per-app mock env, design §4.9; deprecated, only NWEA's is left): on install, reload the tabs of every mock env's
// hosts — each locked session is a fresh profile and downloads the extension again, so the first page may have loaded
// before the mock env existed. Never on update: reloading in the middle of a test is worse than a missing signal.
// Start page (docs/specs/2026-11-06-kiosk-platform-inject-design.md §3.3): a kiosk app with platform or inject starts at
// start.html, which sends {cmd:"launch", config}. Only from that page of this extension: check the config, put the
// ChromeOS disguise in place (a DNR session rule for the request headers, the MAIN-world platform/chromeos.js), register
// relay.js and wait for the app's inject helper extension to answer a ping, then send the tab to the app's url. On
// install, reload start page tabs that were opened before the extension existed.
// Get help (plan 2026-11-05 Task 7): the content script's {cmd:"help-enabled" | "help-submit" | "help-status"} become
// one native message each to org.mastersos.support (/usr/lib/mastersos/mastersos-support-host → mastersos-agent
// support native-host, which forwards one JSON line to /run/mastersos-support/support.sock and answers one line). The host
// decides who is asking and fills in the real kiosk:<app id> session; "kiosk" here is only a placeholder. No
// screenshot in kiosk (Ruling P1): screenshot_png_b64 is always null. Only known fields go either way.
"use strict";

const EXIT_HOST = "org.mastersos.kiosk_exit";
const SUPPORT_HOST = "org.mastersos.support";
// SupportCategory's wire names (mastersos-bundle diag.rs)
const CATEGORIES = ["wifi", "sign_in", "app", "hardware", "battery", "other"];
const TEXT_MAX = 1000; // UTF-16 units: never more characters than that
const ID_MAX = 128;
const CODE_RE = /^[a-z_]{1,32}$/;
// Every mock env's hosts (its content scripts' `matches` in manifest.json). Deprecated: new apps use inject instead.
const MOCK_TAB_PATTERNS = ["https://*.nwea.org/*", "https://*.mapnwea.org/*"];
const START_PAGE = "start.html";
const PLATFORM_SCRIPT = "mastersos-platform";
const RELAY_SCRIPT = "mastersos-relay";
const PLATFORM_RULE = 1;
const HELPER_TRIES = 150; // ping the inject helper every HELPER_EVERY_MS for up to 15 s
const HELPER_EVERY_MS = 100;
const MAX_HOSTS = 64;
const HOST_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
const EXT_ID_RE = /^[a-p]{32}$/;
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

// --- ChromeOS values (the same functions are in platform/chromeos.js) -------------------------------------------
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

/** 恰好 {cmd:"exit"}，不多一个键（与 exit-host 的 read_request 同一条规则）。 */
function isExit(msg) {
  return (
    msg !== null &&
    typeof msg === "object" &&
    !Array.isArray(msg) &&
    Object.keys(msg).length === 1 &&
    msg.cmd === "exit"
  );
}

function requestExit(respond) {
  let answered = false;
  const finish = (ok) => {
    if (answered) return;
    answered = true;
    respond({ ok });
  };
  let port;
  try {
    port = chrome.runtime.connectNative(EXIT_HOST);
  } catch {
    finish(false);
    return;
  }
  port.onMessage.addListener((reply) => {
    finish(reply !== null && typeof reply === "object" && reply.ok === true);
  });
  port.onDisconnect.addListener(() => {
    // 读一下 lastError，免得 Chrome 记一条「未检查的错误」
    void chrome.runtime.lastError;
    finish(false);
  });
  try {
    port.postMessage({ cmd: "exit" });
  } catch {
    finish(false);
  }
}

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const hasKeys = (o, keys) => Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));

/** The native request for a well-formed help message, or null (then it is ignored). */
function helpRequest(msg) {
  if (!isObj(msg)) return null;
  if (msg.cmd === "help-enabled" && hasKeys(msg, ["cmd"])) return { op: "enabled" };
  if (msg.cmd === "help-submit" && hasKeys(msg, ["cmd", "category", "text"])) {
    if (!CATEGORIES.includes(msg.category) || typeof msg.text !== "string" || msg.text.length > TEXT_MAX) return null;
    return { op: "submit", category: msg.category, text: msg.text, session: "kiosk", screenshot_png_b64: null };
  }
  if (msg.cmd === "help-status" && hasKeys(msg, ["cmd", "client_id"])) {
    const id = msg.client_id;
    if (typeof id !== "string" || id.length === 0 || id.length > ID_MAX) return null;
    return { op: "status", client_id: id };
  }
  return null;
}

/** Only the fields the content script uses, with the right types. */
function helpReply(r) {
  if (!isObj(r) || typeof r.ok !== "boolean") return { ok: false, error: "unreachable" };
  const out = { ok: r.ok };
  if (!r.ok) {
    if (typeof r.error === "string" && CODE_RE.test(r.error)) out.error = r.error;
    return out;
  }
  if (typeof r.enabled === "boolean") out.enabled = r.enabled;
  if (typeof r.client_id === "string" && r.client_id.length > 0 && r.client_id.length <= ID_MAX) {
    out.client_id = r.client_id;
  }
  if (typeof r.state === "string" && CODE_RE.test(r.state)) out.state = r.state;
  if ((typeof r.ticket === "string" && /^[A-Za-z0-9-]{1,32}$/.test(r.ticket)) || Number.isSafeInteger(r.ticket)) {
    out.ticket = String(r.ticket);
  }
  return out;
}

function askSupport(req, respond) {
  try {
    chrome.runtime.sendNativeMessage(SUPPORT_HOST, req, (reply) => {
      // host not installed, forbidden by policy, crashed or exited without answering
      if (chrome.runtime.lastError) respond({ ok: false, error: "unreachable" });
      else respond(helpReply(reply));
    });
  } catch {
    respond({ ok: false, error: "unreachable" });
  }
}

/** The start page's configuration, checked; null when anything is off (design §3.3). */
function launchConfig(c) {
  if (!isObj(c) || !hasKeys(c, ["v", "url", "hosts", "platform", "helper"]) || c.v !== 1) return null;
  if (typeof c.url !== "string" || !c.url.startsWith("https://")) return null;
  try {
    if (new URL(c.url).protocol !== "https:") return null;
  } catch {
    return null;
  }
  if (!Array.isArray(c.hosts) || c.hosts.length === 0 || c.hosts.length > MAX_HOSTS) return null;
  if (!c.hosts.every((h) => typeof h === "string" && h.length <= 253 && HOST_RE.test(h))) return null;
  if (c.platform !== null && c.platform !== "chromeos") return null;
  if (c.helper !== null && !(typeof c.helper === "string" && EXT_ID_RE.test(c.helper))) return null;
  if (c.platform === null && c.helper === null) return null;
  return { url: c.url, hosts: c.hosts.slice(), platform: c.platform, helper: c.helper };
}

/** Only this extension's own start page, in a tab. */
function fromStartPage(sender) {
  const page = chrome.runtime.getURL(START_PAGE);
  return (
    sender &&
    sender.id === chrome.runtime.id &&
    typeof sender.url === "string" &&
    (sender.url === page || sender.url.startsWith(`${page}#`)) &&
    sender.tab &&
    typeof sender.tab.id === "number"
  );
}

const matchesOf = (hosts) => hosts.flatMap((h) => [`https://${h}/*`, `https://*.${h}/*`]);

/** The DNR session rule for the ChromeOS request headers on `hosts`. */
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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Whether the inject helper extension `id` answers {cmd:"ping"} within the time allowed. */
async function helperReady(id) {
  for (let i = 0; i < HELPER_TRIES; i++) {
    const ok = await new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(id, { cmd: "ping" }, (r) => {
          void chrome.runtime.lastError;
          resolve(isObj(r) && r.ok === true);
        });
      } catch {
        resolve(false);
      }
    });
    if (ok) return true;
    await sleep(HELPER_EVERY_MS);
  }
  return false;
}

/** Put the disguise and the script in place for `cfg`, then send `tabId` to the app. */
async function launch(cfg, tabId) {
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [PLATFORM_RULE],
    addRules: cfg.platform === "chromeos" ? [platformRule(cfg.hosts)] : [],
  });
  const old = await chrome.scripting.getRegisteredContentScripts({ ids: [PLATFORM_SCRIPT, RELAY_SCRIPT] });
  if (old.length) await chrome.scripting.unregisterContentScripts({ ids: old.map((s) => s.id) });
  const scripts = [];
  const common = {
    matches: matchesOf(cfg.hosts),
    runAt: "document_start",
    allFrames: true,
    matchOriginAsFallback: true,
    persistAcrossSessions: false,
  };
  if (cfg.platform === "chromeos") scripts.push({ ...common, id: PLATFORM_SCRIPT, js: ["platform/chromeos.js"], world: "MAIN" });
  if (cfg.helper) scripts.push({ ...common, id: RELAY_SCRIPT, js: ["relay.js"], allFrames: false });
  if (scripts.length) await chrome.scripting.registerContentScripts(scripts);
  if (cfg.helper && !(await helperReady(cfg.helper))) throw new Error("helper");
  await chrome.tabs.update(tabId, { url: cfg.url });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!sender || sender.id !== chrome.runtime.id) return false;
  if (isObj(msg) && msg.cmd === "launch" && hasKeys(msg, ["cmd", "config"])) {
    const cfg = fromStartPage(sender) ? launchConfig(msg.config) : null;
    if (!cfg) {
      sendResponse({ ok: false });
      return false;
    }
    launch(cfg, sender.tab.id).then(
      () => sendResponse({ ok: true }),
      () => sendResponse({ ok: false }),
    );
    return true;
  }
  if (isExit(msg)) {
    requestExit(sendResponse);
    return true; // 异步回答
  }
  const req = helpRequest(msg);
  if (!req) return false;
  askSupport(req, sendResponse);
  return true;
});

chrome.runtime.onInstalled.addListener((details) => {
  if (!details || details.reason !== "install") return;
  const reload = (t) => {
    if (typeof t.id === "number") chrome.tabs.reload(t.id, () => void chrome.runtime.lastError);
  };
  chrome.tabs.query({ url: MOCK_TAB_PATTERNS }, (tabs) => {
    void chrome.runtime.lastError;
    for (const t of tabs || []) reload(t);
  });
  // A start page opened before this extension was installed shows Chrome's error page; its address is still ours.
  const page = chrome.runtime.getURL(START_PAGE);
  chrome.tabs.query({}, (tabs) => {
    void chrome.runtime.lastError;
    for (const t of tabs || []) {
      const u = t.url || t.pendingUrl || "";
      if (u === page || u.startsWith(`${page}#`)) reload(t);
    }
  });
});
