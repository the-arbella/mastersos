// MastersOS 考试扩展的后台（MV3 service worker，计划 9 Task 7）。
// 只做一件事：自己的内容脚本发来恰好 {cmd:"exit"} 时，经 native messaging 连 org.mastersos.kiosk_exit
// （镜像里的 /usr/lib/mastersos/mastersos-kiosk-exit → mastersos-agent kiosk exit-host）请它结束锁定会话。
// 宿主回 {"ok":true} 的意思是「已请求」：会话随即结束，之后什么都等不到；其余（{"ok":false}、没回就断开、
// 连不上）一律回内容脚本 {ok:false}，由它请学生找老师。
// Also (per-app mock env, design §4.9): on install, reload the tabs of every mock env's hosts — each locked session is a
// fresh profile and downloads the extension again, so the first page may have loaded before the mock env existed.
// Never on update: reloading in the middle of a test is worse than a missing signal.
"use strict";

const EXIT_HOST = "org.mastersos.kiosk_exit";
// Every mock env's hosts (its content scripts' `matches` in manifest.json); add the next app's here too.
const MOCK_TAB_PATTERNS = ["https://*.nwea.org/*", "https://*.mapnwea.org/*"];

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

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!sender || sender.id !== chrome.runtime.id || !isExit(msg)) return false;
  requestExit(sendResponse);
  return true; // 异步回答
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
