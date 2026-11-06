// 考试扩展后台（service worker）的测试（计划 9 Task 7）：只认自己内容脚本的 {cmd:"exit"}，
// 经 connectNative("org.mastersos.kiosk_exit") 转给 mastersos-kiosk exit-host；宿主回 {"ok":true} 就是「已请求」
// （会话可能随即结束，别的什么都等不到了），其余一律算失败。
// ?raw：vite 把源码当字符串给出（不当模块执行）。
import SRC from "../background.js?raw";

const EXT_ID = "abcdefghijklmnopabcdefghijklmnop";

function event() {
  const ls = [];
  return { addListener: (f) => ls.push(f), fire: (...a) => ls.forEach((f) => f(...a)), ls };
}

const PLATFORM = "aaaabbbbccccddddaaaabbbbccccdddd";

/**
 * `native(host, msg, cb, chrome)` answers chrome.runtime.sendNativeMessage (the Get help host). `managed` is the
 * managed storage at start (the agent's policy: {platform_extension}); `later` arrives through onChanged afterwards.
 */
function load({ connectThrows = false, native = () => {}, managed = { platform_extension: PLATFORM } } = {}) {
  const ports = [];
  const onMessage = event();
  const onMessageExternal = event();
  const onInstalled = event();
  const onChanged = event();
  onChanged.removeListener = (f) => onChanged.ls.splice(onChanged.ls.indexOf(f), 1);
  const store = { ...managed };
  const chrome = {
    tabs: {
      query: vi.fn((q, cb) => cb([{ id: 3 }, { id: 4 }])),
      reload: vi.fn(),
    },
    storage: {
      managed: { get: vi.fn((key, cb) => setTimeout(() => cb(key in store ? { [key]: store[key] } : {}), 0)) },
      onChanged,
    },
    runtime: {
      id: EXT_ID,
      lastError: undefined,
      onMessage,
      onMessageExternal,
      onInstalled,
      sendNativeMessage: vi.fn((host, msg, cb) => native(host, msg, cb, chrome)),
      connectNative: vi.fn((name) => {
        if (connectThrows) throw new Error("Specified native messaging host not found.");
        const port = { name, onMessage: event(), onDisconnect: event(), postMessage: vi.fn(), disconnect: vi.fn() };
        ports.push(port);
        return port;
      }),
    },
  };
  new Function("chrome", SRC)(chrome);
  expect(onMessage.ls).toHaveLength(1);
  const send = (msg, sender = { id: EXT_ID, tab: { id: 1 }, frameId: 0 }) => {
    const sendResponse = vi.fn();
    const keep = onMessage.ls[0](msg, sender, sendResponse);
    return { keep, sendResponse };
  };
  const external = (msg, sender = { id: PLATFORM, url: `chrome-extension://${PLATFORM}/background.js` }) => {
    const sendResponse = vi.fn();
    const keep = onMessageExternal.ls[0](msg, sender, sendResponse);
    return { keep, sendResponse };
  };
  return { chrome, ports, send, external, store };
}

describe("后台", () => {
  it("exit：connectNative 用 EXIT_HOST、发 {cmd:\"exit\"}；回 {ok:true} 就当已请求", () => {
    const { chrome, ports, send } = load();
    const { keep, sendResponse } = send({ cmd: "exit" });
    expect(keep).toBe(true); // 异步回答
    expect(chrome.runtime.connectNative).toHaveBeenCalledWith("org.mastersos.kiosk_exit");
    expect(ports[0].postMessage).toHaveBeenCalledWith({ cmd: "exit" });
    ports[0].onMessage.fire({ ok: true });
    expect(sendResponse).toHaveBeenCalledWith({ ok: true });
    // 之后会话结束、宿主断开：不再回第二次
    ports[0].onDisconnect.fire();
    expect(sendResponse).toHaveBeenCalledTimes(1);
  });

  it("宿主回 {ok:false} 或别的形状：失败", () => {
    for (const r of [{ ok: false }, { ok: "true" }, {}, null, "ok"]) {
      const { ports, send } = load();
      const { sendResponse } = send({ cmd: "exit" });
      ports[0].onMessage.fire(r);
      expect(sendResponse).toHaveBeenCalledWith({ ok: false });
    }
  });

  it("宿主没回就断开（没装、被策略挡、崩了）：失败", () => {
    const { chrome, ports, send } = load();
    const { sendResponse } = send({ cmd: "exit" });
    chrome.runtime.lastError = { message: "Native host has exited." };
    ports[0].onDisconnect.fire();
    expect(sendResponse).toHaveBeenCalledWith({ ok: false });
  });

  it("connectNative 抛错：失败", () => {
    const { send } = load({ connectThrows: true });
    const { sendResponse } = send({ cmd: "exit" });
    expect(sendResponse).toHaveBeenCalledWith({ ok: false });
  });

  it("不是恰好 {cmd:\"exit\"} 的消息不理，也不连宿主", () => {
    const { chrome, send } = load();
    for (const m of [{ cmd: "Exit" }, { cmd: "exit", x: 1 }, ["exit"], "exit", null, {}]) {
      const { keep, sendResponse } = send(m);
      expect(keep).toBe(false);
      expect(sendResponse).not.toHaveBeenCalled();
    }
    expect(chrome.runtime.connectNative).not.toHaveBeenCalled();
  });

  it("别的扩展发来的不理", () => {
    const { chrome, send } = load();
    const { keep } = send({ cmd: "exit" }, { id: "pppppppppppppppppppppppppppppppp", tab: { id: 1 } });
    expect(keep).toBe(false);
    expect(chrome.runtime.connectNative).not.toHaveBeenCalled();
  });

  // Mock env (design §4.9): a fresh profile per locked session, so the first page may load before the extension is
  // installed; reload the mock env hosts' tabs once on install, never on update (no refresh in the middle of a test).
  it("reloads mock env tabs on install", () => {
    const { chrome } = load();
    expect(chrome.runtime.onInstalled.ls).toHaveLength(1);
    chrome.runtime.onInstalled.fire({ reason: "install" });
    expect(chrome.tabs.query).toHaveBeenCalledTimes(1);
    expect(chrome.tabs.query.mock.calls[0][0]).toEqual({
      url: ["https://*.nwea.org/*", "https://*.mapnwea.org/*"],
    });
    expect(chrome.tabs.reload.mock.calls.map((c) => c[0])).toEqual([3, 4]);
  });

  it("does not reload on update", () => {
    for (const reason of ["update", "chrome_update", "shared_module_update"]) {
      const { chrome } = load();
      chrome.runtime.onInstalled.fire({ reason });
      expect(chrome.tabs.query, reason).not.toHaveBeenCalled();
    }
  });
});

// Get help (plan 2026-11-05 Task 7): the content script's {cmd:"help-…"} messages become one native message each to
// org.mastersos.support (mastersos-agent support native-host, which forwards to /run/mastersos-support/support.sock and fills
// in the real kiosk:<app id> session). No screenshot in kiosk (Ruling P1). Only known fields go either way.
describe("Get help", () => {
  const HOST = "org.mastersos.support";
  const answer = (reply) => (_h, _m, cb) => cb(reply);

  it("help-enabled asks the host {op:\"enabled\"} and passes a boolean back", () => {
    const { chrome, send } = load({ native: answer({ ok: true, enabled: true, extra: 1 }) });
    const { keep, sendResponse } = send({ cmd: "help-enabled" });
    expect(keep).toBe(true);
    expect(chrome.runtime.sendNativeMessage).toHaveBeenCalledTimes(1);
    expect(chrome.runtime.sendNativeMessage.mock.calls[0].slice(0, 2)).toEqual([HOST, { op: "enabled" }]);
    expect(sendResponse).toHaveBeenCalledWith({ ok: true, enabled: true });
    expect(chrome.runtime.connectNative).not.toHaveBeenCalled();
  });

  it("sends_native_message_shape: submit carries session \"kiosk\" and screenshot_png_b64 null", () => {
    const { chrome, send } = load({
      native: answer({ ok: true, client_id: "0b0c-1", state: "queued", user: "x" }),
    });
    const { keep, sendResponse } = send({ cmd: "help-submit", category: "hardware", text: "no sound" });
    expect(keep).toBe(true);
    const [h, m] = chrome.runtime.sendNativeMessage.mock.calls[0];
    expect(h).toBe(HOST);
    expect(m).toEqual({ op: "submit", category: "hardware", text: "no sound", session: "kiosk", screenshot_png_b64: null });
    expect(Object.keys(m)).toEqual(["op", "category", "text", "session", "screenshot_png_b64"]);
    expect(sendResponse).toHaveBeenCalledWith({ ok: true, client_id: "0b0c-1", state: "queued" });
  });

  it("submit errors pass through as a short code", () => {
    for (const e of ["rate_limited", "disabled", "invalid"]) {
      const { send } = load({ native: answer({ ok: false, error: e }) });
      const { sendResponse } = send({ cmd: "help-submit", category: "wifi", text: "" });
      expect(sendResponse).toHaveBeenCalledWith({ ok: false, error: e });
    }
    const { send } = load({ native: answer({ ok: false, error: "<b>not a code</b>" }) });
    const { sendResponse } = send({ cmd: "help-submit", category: "wifi", text: "" });
    expect(sendResponse).toHaveBeenCalledWith({ ok: false });
  });

  it("status asks {op:\"status\",client_id} and passes state and ticket back", () => {
    for (const [ticket, want] of [
      ["1042", "1042"],
      [1042, "1042"],
    ]) {
      const { chrome, send } = load({ native: answer({ ok: true, state: "sent", ticket }) });
      const { sendResponse } = send({ cmd: "help-status", client_id: "c1" });
      expect(chrome.runtime.sendNativeMessage.mock.calls[0][1]).toEqual({ op: "status", client_id: "c1" });
      expect(sendResponse).toHaveBeenCalledWith({ ok: true, state: "sent", ticket: want });
    }
    const { send } = load({ native: answer({ ok: true, state: "queued" }) });
    const { sendResponse } = send({ cmd: "help-status", client_id: "c1" });
    expect(sendResponse).toHaveBeenCalledWith({ ok: true, state: "queued" });
  });

  it("host missing, crashed or answering garbage: {ok:false, error:\"unreachable\"}", () => {
    const cases = [
      (_h, _m, cb, chrome) => {
        chrome.runtime.lastError = { message: "Specified native messaging host not found." };
        cb(undefined);
        chrome.runtime.lastError = undefined;
      },
      () => {
        throw new Error("Access to the specified native messaging host is forbidden.");
      },
      answer(undefined),
      answer("ok"),
      answer([1]),
    ];
    for (const native of cases) {
      const { send } = load({ native });
      const { sendResponse } = send({ cmd: "help-enabled" });
      expect(sendResponse).toHaveBeenCalledWith({ ok: false, error: "unreachable" });
    }
  });

  it("malformed messages are ignored and reach no host", () => {
    const { chrome, send } = load({ native: answer({ ok: true }) });
    const bad = [
      { cmd: "help-enabled", x: 1 },
      { cmd: "help-submit", category: "printer", text: "" },
      { cmd: "help-submit", category: "wifi" },
      { cmd: "help-submit", category: "wifi", text: 3 },
      { cmd: "help-submit", category: "wifi", text: "x".repeat(1001) },
      { cmd: "help-submit", category: "wifi", text: "", session: "login" },
      { cmd: "help-submit", category: "wifi", text: "", screenshot_png_b64: "iVBOR" },
      { cmd: "help-submit", category: "wifi", text: "", user: "teacher" },
      { cmd: "help-status" },
      { cmd: "help-status", client_id: "" },
      { cmd: "help-status", client_id: 5 },
      { cmd: "help-status", client_id: "x".repeat(200) },
      { cmd: "help" },
    ];
    for (const m of bad) {
      const { keep, sendResponse } = send(m);
      expect(keep, JSON.stringify(m)).toBe(false);
      expect(sendResponse).not.toHaveBeenCalled();
    }
    expect(chrome.runtime.sendNativeMessage).not.toHaveBeenCalled();
    // 1000 characters is still fine
    const { keep } = send({ cmd: "help-submit", category: "wifi", text: "x".repeat(1000) });
    expect(keep).toBe(true);
  });

  it("help messages from another extension are ignored", () => {
    const { chrome, send } = load({ native: answer({ ok: true, enabled: true }) });
    const { keep } = send({ cmd: "help-enabled" }, { id: "pppppppppppppppppppppppppppppppp", tab: { id: 1 } });
    expect(keep).toBe(false);
    expect(chrome.runtime.sendNativeMessage).not.toHaveBeenCalled();
  });
});

// The platform extension's exit (docs/specs/2026-11-06-kiosk-platform-inject-design.md §6): taken from the id in managed
// storage only.
describe("exit from the platform extension", () => {
  const answered = (sendResponse) => vi.waitFor(() => expect(sendResponse).toHaveBeenCalled(), { timeout: 3000 });

  it("from the id in managed storage: asks the exit host, the answer goes back", async () => {
    const { chrome, ports, external } = load();
    const { keep, sendResponse } = external({ cmd: "exit" });
    expect(keep).toBe(true);
    await vi.waitFor(() => expect(ports).toHaveLength(1));
    expect(chrome.runtime.connectNative).toHaveBeenCalledWith("org.mastersos.kiosk_exit");
    expect(ports[0].postMessage).toHaveBeenCalledWith({ cmd: "exit" });
    ports[0].onMessage.fire({ ok: true });
    expect(sendResponse).toHaveBeenCalledWith({ ok: true });
  });

  it("from any other extension (a vendor's): refused, no host", async () => {
    const { chrome, external } = load();
    const { keep, sendResponse } = external({ cmd: "exit" }, { id: "pppppppppppppppppppppppppppppppp" });
    expect(keep).toBe(true);
    await answered(sendResponse);
    expect(sendResponse).toHaveBeenCalledWith({ ok: false });
    expect(chrome.runtime.connectNative).not.toHaveBeenCalled();
  });

  it("a managed value that is not an extension id counts as none", async () => {
    vi.useFakeTimers();
    try {
      const { chrome, external } = load({ managed: { platform_extension: "not-an-id" } });
      const { sendResponse } = external({ cmd: "exit" }, { id: "pppppppppppppppppppppppppppppppp" });
      await vi.advanceTimersByTimeAsync(15000);
      expect(sendResponse).toHaveBeenCalledWith({ ok: false });
      expect(chrome.runtime.connectNative).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("nothing in managed storage yet (fresh profile): waits for it to arrive", async () => {
    const { chrome, ports, external } = load({ managed: {} });
    const { sendResponse } = external({ cmd: "exit" });
    await vi.waitFor(() => expect(chrome.storage.managed.get).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 5));
    expect(ports).toHaveLength(0);
    // another key, or the local area: still waiting
    chrome.storage.onChanged.fire({ other: { newValue: 1 } }, "managed");
    chrome.storage.onChanged.fire({ platform_extension: { newValue: PLATFORM } }, "local");
    expect(ports).toHaveLength(0);
    chrome.storage.onChanged.fire({ platform_extension: { newValue: PLATFORM } }, "managed");
    await vi.waitFor(() => expect(ports).toHaveLength(1));
    ports[0].onMessage.fire({ ok: true });
    expect(sendResponse).toHaveBeenCalledWith({ ok: true });
    expect(chrome.storage.onChanged.ls).toHaveLength(0);
  });

  it("never arrives: refused after the wait", async () => {
    vi.useFakeTimers();
    try {
      const { chrome, external } = load({ managed: {} });
      const { sendResponse } = external({ cmd: "exit" });
      await vi.advanceTimersByTimeAsync(15000);
      expect(sendResponse).toHaveBeenCalledWith({ ok: false });
      expect(chrome.runtime.connectNative).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("only exactly {cmd:\"exit\"}; help and anything else from outside is ignored", () => {
    const { chrome, external } = load();
    for (const m of [{ cmd: "exit", x: 1 }, { cmd: "help-enabled" }, { cmd: "launch" }, "exit", null]) {
      const { keep, sendResponse } = external(m);
      expect(keep).toBe(false);
      expect(sendResponse).not.toHaveBeenCalled();
    }
    expect(external({ cmd: "exit" }, {}).keep).toBe(false);
    expect(chrome.storage.managed.get).not.toHaveBeenCalled();
    expect(chrome.runtime.sendNativeMessage).not.toHaveBeenCalled();
  });
});
