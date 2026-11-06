// Tests for the start page (start.html + start.js, docs/specs/2026-11-06-kiosk-platform-inject-design.md §3.3): it hands
// the configuration from its #fragment to the background and never opens the app itself; on failure it offers Try again
// and Exit. Each case loads start.html in a fresh JSDOM window with a stub chrome.runtime.
import { createRequire } from "node:module";
import HTML from "../start.html?raw";
import SRC from "../start.js?raw";

const { JSDOM } = createRequire(`${process.cwd()}/`)("jsdom");

const CFG = { v: 1, url: "https://home.testnav.com/", hosts: ["testnav.com"], platform: "chromeos", helper: null };

function page({ hash = encodeURIComponent(JSON.stringify(CFG)), answer = () => undefined } = {}) {
  const dom = new JSDOM(HTML.replace('<script src="start.js"></script>', ""), {
    url: `https://ext.invalid/start.html#${hash}`,
    runScripts: "outside-only",
  });
  const w = dom.window;
  const sent = [];
  w.chrome = {
    runtime: {
      lastError: undefined,
      sendMessage: (msg, cb) => {
        sent.push(msg);
        const r = answer(msg);
        if (r !== undefined) setTimeout(() => cb(r), 0);
      },
    },
  };
  const $ = (id) => w.document.getElementById(id);
  return { w, sent, $, run: () => w.eval(SRC) };
}

const tick = () => new Promise((r) => setTimeout(r, 5));

describe("start page", () => {
  it("sends the decoded configuration to the background and waits", async () => {
    const { sent, $, run } = page({ answer: () => ({ ok: true }) });
    run();
    expect(sent).toEqual([{ cmd: "launch", config: CFG }]);
    await tick();
    expect($("title").textContent).toBe("Starting…");
    expect($("actions").hidden).toBe(true);
  });

  it("a refusal shows the failure with Try again and Exit; Try again asks again", async () => {
    const { sent, $, run } = page({ answer: (m) => (m.cmd === "launch" ? { ok: false } : undefined) });
    run();
    await tick();
    expect($("title").textContent).toBe("This app could not start.");
    expect($("body").textContent).toBe("Please ask a teacher.");
    expect($("actions").hidden).toBe(false);
    $("retry").click();
    expect(sent.map((m) => m.cmd)).toEqual(["launch", "launch"]);
  });

  it("Exit asks the background to end the session", async () => {
    const { sent, $, run } = page({ answer: (m) => (m.cmd === "launch" ? { ok: false } : { ok: false }) });
    run();
    await tick();
    $("exit").click();
    expect(sent[1]).toEqual({ cmd: "exit" });
    await tick();
    expect($("body").textContent).toBe("Could not leave. Please ask a teacher.");
  });

  it("a broken fragment still asks (the background refuses null) and shows the failure", async () => {
    const { sent, $, run } = page({ hash: "%7Bnot-json", answer: () => ({ ok: false }) });
    run();
    expect(sent).toEqual([{ cmd: "launch", config: null }]);
    await tick();
    expect($("actions").hidden).toBe(false);
  });

  it("no answer at all: the failure after the timeout", () => {
    const { w, $, run } = page();
    const timers = [];
    w.setTimeout = (fn, ms) => timers.push([fn, ms]);
    run();
    expect(timers.map((t) => t[1])).toEqual([20000]);
    expect($("actions").hidden).toBe(true);
    timers[0][0]();
    expect($("actions").hidden).toBe(false);
  });

  it("only English text, no inline script", () => {
    expect(HTML + SRC).not.toMatch(/[\u3000-\u303f\u4e00-\u9fff\uff00-\uffef]/);
    expect(HTML).not.toMatch(/<script>(?!<\/script>)/);
    expect(HTML).toContain('<script src="start.js"></script>');
  });
});
