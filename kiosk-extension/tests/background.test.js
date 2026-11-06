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

/** `native(host, msg, cb, chrome)` answers chrome.runtime.sendNativeMessage (the Get help host). */
const LINUX_UA =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36";
// The service worker's navigator (real Chrome on Linux).
const SW_NAV = {
  userAgent: LINUX_UA,
  userAgentData: { brands: [{ brand: "Not:A-Brand", version: "8" }, { brand: "Google Chrome", version: "156" }] },
};

function load({ connectThrows = false, native = () => {}, helper = () => ({ ok: true }) } = {}) {
  const ports = [];
  const onMessage = event();
  const onInstalled = event();
  const registered = [];
  const chrome = {
    tabs: {
      query: vi.fn((q, cb) =>
        cb(
          q.url
            ? [{ id: 3 }, { id: 4 }]
            : [
                { id: 7, url: `chrome-extension://${EXT_ID}/start.html#%7B%7D` },
                { id: 8, url: "https://x.example/" },
                { id: 9, pendingUrl: `chrome-extension://${EXT_ID}/start.html#x` },
                { id: 10, url: `chrome-extension://${EXT_ID}/start.htmlx` },
              ],
        ),
      ),
      reload: vi.fn(),
      update: vi.fn(async () => ({})),
    },
    declarativeNetRequest: { updateSessionRules: vi.fn(async () => {}) },
    scripting: {
      getRegisteredContentScripts: vi.fn(async ({ ids }) => registered.filter((r) => ids.includes(r.id))),
      unregisterContentScripts: vi.fn(async ({ ids }) => {
        for (const id of ids) registered.splice(registered.findIndex((r) => r.id === id), 1);
      }),
      registerContentScripts: vi.fn(async (list) => {
        registered.push(...list);
      }),
    },
    runtime: {
      id: EXT_ID,
      lastError: undefined,
      onMessage,
      onInstalled,
      getURL: (path) => `chrome-extension://${EXT_ID}/${path}`,
      // only the inject helper ping goes through here
      sendMessage: vi.fn((id, msg, cb) => setTimeout(() => cb(helper(id, msg)), 0)),
      sendNativeMessage: vi.fn((host, msg, cb) => native(host, msg, cb, chrome)),
      connectNative: vi.fn((name) => {
        if (connectThrows) throw new Error("Specified native messaging host not found.");
        const port = { name, onMessage: event(), onDisconnect: event(), postMessage: vi.fn(), disconnect: vi.fn() };
        ports.push(port);
        return port;
      }),
    },
  };
  new Function("chrome", "navigator", SRC)(chrome, SW_NAV);
  expect(onMessage.ls).toHaveLength(1);
  const send = (msg, sender = { id: EXT_ID, tab: { id: 1 }, frameId: 0 }) => {
    const sendResponse = vi.fn();
    const keep = onMessage.ls[0](msg, sender, sendResponse);
    return { keep, sendResponse };
  };
  return { chrome, ports, send, registered };
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
    expect(chrome.tabs.query).toHaveBeenCalledTimes(2);
    expect(chrome.tabs.query.mock.calls[0][0]).toEqual({
      url: ["https://*.nwea.org/*", "https://*.mapnwea.org/*"],
    });
    // and this extension's start page tabs (opened before it was installed), nothing else
    expect(chrome.tabs.query.mock.calls[1][0]).toEqual({});
    expect(chrome.tabs.reload.mock.calls.map((c) => c[0])).toEqual([3, 4, 7, 9]);
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

// Start page (docs/specs/2026-11-06-kiosk-platform-inject-design.md §3.3).
describe("launch from the start page", () => {
  const HELPER = "aaaabbbbccccddddaaaabbbbccccdddd";
  const START = { id: EXT_ID, url: `chrome-extension://${EXT_ID}/start.html#x`, tab: { id: 5 }, frameId: 0 };
  const cfg = (extra = {}) => ({
    v: 1,
    url: "https://home.testnav.com/",
    hosts: ["testnav.com", "home.testnav.com"],
    platform: "chromeos",
    helper: HELPER,
    ...extra,
  });
  const done = (sendResponse) => vi.waitFor(() => expect(sendResponse).toHaveBeenCalled(), { timeout: 3000 });

  it("puts the disguise, the relay and the helper in place, then opens the app", async () => {
    const { chrome, send, registered } = load();
    const { keep, sendResponse } = send({ cmd: "launch", config: cfg() }, START);
    expect(keep).toBe(true);
    await done(sendResponse);
    expect(sendResponse).toHaveBeenCalledWith({ ok: true });
    const rules = chrome.declarativeNetRequest.updateSessionRules.mock.calls[0][0];
    expect(rules.removeRuleIds).toEqual([1]);
    expect(rules.addRules).toHaveLength(1);
    const r = rules.addRules[0];
    expect(r.action.requestHeaders).toEqual([
      {
        header: "user-agent",
        operation: "set",
        value: "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
      },
      { header: "sec-ch-ua-platform", operation: "set", value: '"Chrome OS"' },
      { header: "sec-ch-ua-platform-version", operation: "set", value: '"17005.0.0"' },
    ]);
    expect(r.condition.requestDomains).toEqual(["testnav.com", "home.testnav.com"]);
    expect(r.condition.resourceTypes).toContain("main_frame");
    expect(r.condition.resourceTypes).toContain("sub_frame");
    expect(registered.map((x) => [x.id, x.js, x.world || "ISOLATED", x.runAt])).toEqual([
      ["mastersos-platform", ["platform/chromeos.js"], "MAIN", "document_start"],
      ["mastersos-relay", ["relay.js"], "ISOLATED", "document_start"],
    ]);
    expect(registered[0].matches).toEqual([
      "https://testnav.com/*",
      "https://*.testnav.com/*",
      "https://home.testnav.com/*",
      "https://*.home.testnav.com/*",
    ]);
    expect(registered.every((x) => x.persistAcrossSessions === false)).toBe(true);
    expect(chrome.runtime.sendMessage).toHaveBeenCalledWith(HELPER, { cmd: "ping" }, expect.any(Function));
    expect(chrome.tabs.update).toHaveBeenCalledWith(5, { url: "https://home.testnav.com/" });
  });

  it("a second launch (Chrome restarted) replaces what the first registered", async () => {
    const { chrome, send, registered } = load();
    await done(send({ cmd: "launch", config: cfg() }, START).sendResponse);
    await done(send({ cmd: "launch", config: cfg({ platform: null }) }, START).sendResponse);
    expect(registered.map((x) => x.id)).toEqual(["mastersos-relay"]);
    expect(chrome.declarativeNetRequest.updateSessionRules.mock.calls[1][0]).toEqual({ removeRuleIds: [1], addRules: [] });
  });

  it("platform only: no relay, no helper ping", async () => {
    const { chrome, send, registered } = load();
    await done(send({ cmd: "launch", config: cfg({ helper: null }) }, START).sendResponse);
    expect(registered.map((x) => x.id)).toEqual(["mastersos-platform"]);
    expect(chrome.runtime.sendMessage).not.toHaveBeenCalled();
    expect(chrome.tabs.update).toHaveBeenCalledTimes(1);
  });

  it("the helper never answers: the app is not opened", async () => {
    vi.useFakeTimers();
    try {
      const { chrome, send } = load({ helper: () => undefined });
      const { sendResponse } = send({ cmd: "launch", config: cfg() }, START);
      await vi.advanceTimersByTimeAsync(20000);
      expect(sendResponse).toHaveBeenCalledWith({ ok: false });
      expect(chrome.tabs.update).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("only from this extension's start page in a tab", () => {
    for (const sender of [
      { ...START, url: `chrome-extension://${EXT_ID}/other.html` },
      { ...START, url: "https://home.testnav.com/" },
      { ...START, tab: undefined },
      { ...START, id: "pppppppppppppppppppppppppppppppp" },
    ]) {
      const { chrome, send } = load();
      const { sendResponse } = send({ cmd: "launch", config: cfg() }, sender);
      if (sender.id === EXT_ID) expect(sendResponse).toHaveBeenCalledWith({ ok: false });
      expect(chrome.declarativeNetRequest.updateSessionRules).not.toHaveBeenCalled();
      expect(chrome.tabs.update).not.toHaveBeenCalled();
    }
  });

  it("malformed configurations are refused", () => {
    for (const c of [
      null,
      "x",
      cfg({ v: 2 }),
      cfg({ url: "http://home.testnav.com/" }),
      cfg({ url: "javascript:alert(1)" }),
      cfg({ hosts: [] }),
      cfg({ hosts: ["*.testnav.com"] }),
      cfg({ hosts: ["Testnav.com"] }),
      cfg({ hosts: ["localhost"] }),
      cfg({ platform: "windows" }),
      cfg({ helper: "nope" }),
      cfg({ platform: null, helper: null }),
      { ...cfg(), extra: 1 },
    ]) {
      const { chrome, send } = load();
      const { keep, sendResponse } = send({ cmd: "launch", config: c }, START);
      expect(keep, JSON.stringify(c)).toBe(false);
      expect(sendResponse).toHaveBeenCalledWith({ ok: false });
      expect(chrome.tabs.update).not.toHaveBeenCalled();
    }
  });
});
