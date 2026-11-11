// Tests for the platform extension's service worker (kiosk-platform/background.js, design
// docs/specs/2026-11-06-kiosk-platform-inject-design.md §3): launch only from its own start page (request header rule
// first, then the app's url), exit from the start page or relay.js passed on to the exam extension, and the start page
// reloaded on install. config.js is what the agent writes (kiosk::platform_config).
import { repoFile } from "./helpers.js";

const SRC = repoFile("kiosk-platform/background.js");
const ID = "aaaabbbbccccddddaaaabbbbccccdddd";
const EXAM = "ponmlkjihgfedcbaponmlkjihgfedcba";
const LINUX_UA =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36";
const START = { id: ID, url: `chrome-extension://${ID}/start.html`, tab: { id: 5 }, frameId: 0 };
const RELAY = { id: ID, url: "https://home.testnav.com/client/", tab: { id: 5 }, frameId: 0 };

function event() {
  const ls = [];
  return { addListener: (f) => ls.push(f), fire: (...a) => ls.forEach((f) => f(...a)), ls };
}

function load({ platform = "chromeos", exam = () => ({ ok: true }), updateFails = false, noDnr = false } = {}) {
  const order = [];
  const chrome = {
    tabs: {
      query: vi.fn((q, cb) =>
        cb([
          { id: 7, url: `chrome-extension://${ID}/start.html` },
          { id: 8, url: "https://x.example/" },
          { id: 9, pendingUrl: `chrome-extension://${ID}/start.html#x` },
          { id: 10, url: `chrome-extension://${ID}/start.htmlx` },
          { id: 11, url: `chrome-extension://${EXAM}/start.html` },
        ]),
      ),
      reload: vi.fn(),
      update: vi.fn(async (id, p) => {
        order.push(["update", id, p.url]);
        return {};
      }),
    },
    declarativeNetRequest: {
      updateSessionRules: vi.fn(async (r) => {
        order.push(["rules", r]);
        if (updateFails) throw new Error("rule");
      }),
    },
    runtime: {
      id: ID,
      lastError: undefined,
      onMessage: event(),
      onInstalled: event(),
      getURL: (p) => `chrome-extension://${ID}/${p}`,
      sendMessage: vi.fn((id, msg, cb) => setTimeout(() => cb(exam(id, msg)), 0)),
    },
  };
  if (noDnr) delete chrome.declarativeNetRequest;
  const self = {};
  const importScripts = vi.fn((f) => {
    expect(f).toBe("config.js");
    self.MASTERSOS_PLATFORM = {
      v: 1,
      url: "https://home.testnav.com/",
      hosts: ["testnav.com", "act.org"],
      platform,
      inject: true,
      exam: EXAM,
    };
  });
  const nav = { userAgent: LINUX_UA, userAgentData: { brands: [{ brand: "Google Chrome", version: "156" }] } };
  new Function("chrome", "navigator", "self", "importScripts", SRC)(chrome, nav, self, importScripts);
  expect(importScripts).toHaveBeenCalledTimes(1);
  const send = (msg, sender) => {
    const sendResponse = vi.fn();
    const keep = chrome.runtime.onMessage.ls[0](msg, sender, sendResponse);
    return { keep, sendResponse };
  };
  return { chrome, send, order };
}

const answered = (r) => vi.waitFor(() => expect(r).toHaveBeenCalled(), { timeout: 3000 });

describe("platform extension: launch", () => {
  it("from the start page: the header rule on the app's hosts first, then the app's url", async () => {
    const { send, order } = load();
    const { keep, sendResponse } = send({ cmd: "launch" }, START);
    expect(keep).toBe(true);
    await answered(sendResponse);
    expect(sendResponse).toHaveBeenCalledWith({ ok: true });
    expect(order.map((o) => o[0])).toEqual(["rules", "update"]);
    const r = order[0][1];
    expect(r.removeRuleIds).toEqual([1]);
    const rule = r.addRules[0];
    expect(rule.condition.requestDomains).toEqual(["testnav.com", "act.org"]);
    expect(rule.condition.resourceTypes).toContain("main_frame");
    expect(Object.fromEntries(rule.action.requestHeaders.map((h) => [h.header, [h.operation, h.value]]))).toEqual({
      "user-agent": ["set", LINUX_UA.replace("(X11; Linux x86_64)", "(X11; CrOS x86_64 14541.0.0)")],
      "sec-ch-ua-platform": ["set", '"Chrome OS"'],
      "sec-ch-ua-platform-version": ["set", '"17005.0.0"'],
    });
    expect(order[1]).toEqual(["update", 5, "https://home.testnav.com/"]);
  });

  it("no platform and no declarativeNetRequest permission: the app is still opened", async () => {
    const { chrome, send, order } = load({ platform: null, noDnr: true });
    expect(chrome.declarativeNetRequest).toBeUndefined();
    const { sendResponse } = send({ cmd: "launch" }, START);
    await answered(sendResponse);
    expect(sendResponse).toHaveBeenCalledWith({ ok: true });
    expect(order).toEqual([["update", 5, "https://home.testnav.com/"]]);
  });

  it("the rule cannot be set: the app is not opened", async () => {
    const { chrome, send } = load({ updateFails: true });
    const { sendResponse } = send({ cmd: "launch" }, START);
    await answered(sendResponse);
    expect(sendResponse).toHaveBeenCalledWith({ ok: false });
    expect(chrome.tabs.update).not.toHaveBeenCalled();
  });

  it("only from this extension's start page in a tab, only exactly {cmd:\"launch\"}", () => {
    const { chrome, send } = load();
    for (const sender of [
      RELAY,
      { ...START, id: EXAM },
      { ...START, url: `chrome-extension://${ID}/other.html` },
      { ...START, url: `chrome-extension://${ID}/start.htmlx` },
      { ...START, tab: undefined },
      undefined,
    ]) {
      expect(send({ cmd: "launch" }, sender).keep).toBe(false);
    }
    for (const m of [{ cmd: "launch", url: "https://evil.example/" }, { cmd: "Launch" }, "launch"]) {
      expect(send(m, START).keep).toBe(false);
    }
    expect(chrome.declarativeNetRequest.updateSessionRules).not.toHaveBeenCalled();
    expect(chrome.tabs.update).not.toHaveBeenCalled();
  });
});

describe("platform extension: exit", () => {
  it("from relay.js on the app's hosts or from the start page: passed on to the exam extension", async () => {
    for (const sender of [RELAY, { ...RELAY, url: "https://act.org/" }, START]) {
      const { chrome, send } = load();
      const { keep, sendResponse } = send({ cmd: "exit" }, sender);
      expect(keep).toBe(true);
      await answered(sendResponse);
      expect(chrome.runtime.sendMessage).toHaveBeenCalledWith(EXAM, { cmd: "exit" }, expect.any(Function));
      expect(sendResponse).toHaveBeenCalledWith({ ok: true });
    }
  });

  it("the exam extension's refusal or silence: {ok:false}", async () => {
    for (const exam of [() => ({ ok: false }), () => undefined, () => "ok"]) {
      const { send } = load({ exam });
      const { sendResponse } = send({ cmd: "exit" }, RELAY);
      await answered(sendResponse);
      expect(sendResponse).toHaveBeenCalledWith({ ok: false });
    }
  });

  it("not from a frame, another host, http, another extension, or of another shape", () => {
    const { chrome, send } = load();
    for (const sender of [
      { ...RELAY, frameId: 3 },
      { ...RELAY, url: "https://evil.example/" },
      { ...RELAY, url: "https://nottestnav.com/" },
      { ...RELAY, url: "http://home.testnav.com/" },
      { ...RELAY, id: EXAM },
      { ...RELAY, tab: undefined },
    ]) {
      expect(send({ cmd: "exit" }, sender).keep).toBe(false);
    }
    expect(send({ cmd: "exit", x: 1 }, RELAY).keep).toBe(false);
    expect(chrome.runtime.sendMessage).not.toHaveBeenCalled();
  });
});

describe("platform extension: install", () => {
  it("reloads its own start page tabs on install only", () => {
    const { chrome } = load();
    chrome.runtime.onInstalled.fire({ reason: "update" });
    expect(chrome.tabs.query).not.toHaveBeenCalled();
    chrome.runtime.onInstalled.fire({ reason: "install" });
    expect(chrome.tabs.reload.mock.calls.map((c) => c[0])).toEqual([7, 9]);
  });
});
