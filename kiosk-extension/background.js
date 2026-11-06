// MastersOS 考试扩展的后台（MV3 service worker，计划 9 Task 7）。
// 只做一件事：自己的内容脚本发来恰好 {cmd:"exit"} 时，经 native messaging 连 org.mastersos.kiosk_exit
// （镜像里的 /usr/lib/mastersos/mastersos-kiosk-exit → mastersos-agent kiosk exit-host）请它结束锁定会话。
// 宿主回 {"ok":true} 的意思是「已请求」：会话随即结束，之后什么都等不到；其余（{"ok":false}、没回就断开、
// 连不上）一律回内容脚本 {ok:false}，由它请学生找老师。
// Also (per-app mock env, design §4.9): on install, reload the tabs of every mock env's hosts — each locked session is a
// fresh profile and downloads the extension again, so the first page may have loaded before the mock env existed.
// Never on update: reloading in the middle of a test is worse than a missing signal.
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
// Every mock env's hosts (its content scripts' `matches` in manifest.json); add the next app's here too.
const MOCK_TAB_PATTERNS = [
  "https://*.nwea.org/*",
  "https://*.mapnwea.org/*",
  "https://*.testnav.com/*",
  "https://*.adamexam.com/*",
  "https://*.act.org/*",
  "https://*.actaspire.org/*",
];

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

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!sender || sender.id !== chrome.runtime.id) return false;
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
  chrome.tabs.query({ url: MOCK_TAB_PATTERNS }, (tabs) => {
    void chrome.runtime.lastError;
    for (const t of tabs || []) {
      if (typeof t.id === "number") chrome.tabs.reload(t.id, () => void chrome.runtime.lastError);
    }
  });
});
