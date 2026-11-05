// Tests for the exam extension's content script (plan 9 Task 7). Run with vitest + jsdom (globals); this directory has
// no package of its own (see ../README.md "Tests").
// The content script is a plain script (not an ES module): the source is read as a string and run with `chrome` passed
// in, once, the way Chrome injects it.
// jsdom has no Popover API, :modal or top layer: the "top layer" group stubs them and only checks the order of calls
// and where the host is attached; really painting above the page's modal dialogs, popovers and fullscreen (and being
// clickable there) is checked on a VM (see ../README.md).
// ?raw: vite hands over the source as a string (not executed as a module).
import SRC from "../content.js?raw";

const KEY = "mastersos-exit-pos";
const tick = () => new Promise((r) => setTimeout(r, 0));

// Observers and document listeners each injection leaves behind: torn down between tests so an earlier instance does
// not reattach its host.
const cleanups = [];

/**
 * Run the content script once; returns the attached host, the peeked closed shadow root and the chrome stub.
 * `reply` answers the Exit message; `help` answers the Get help messages ({cmd:"help-…"}), by default
 * "turned off" (so the menu shows only Exit). `sendMessage` records only the Exit messages, `help` the others.
 */
function inject(reply = { ok: true }, { help: helpReply } = {}) {
  const exitSend = vi.fn((_msg, cb) => {
    if (typeof reply === "function") reply(cb);
    else cb(reply);
  });
  const help = vi.fn(
    helpReply || ((msg, cb) => cb(msg.cmd === "help-enabled" ? { ok: true, enabled: false } : { ok: false })),
  );
  const route = (msg, cb) =>
    (msg && typeof msg.cmd === "string" && msg.cmd.startsWith("help-") ? help : exitSend)(msg, cb);
  const sendMessage = exitSend;
  const chrome = { runtime: { sendMessage: route, lastError: undefined } };
  let root = null;
  let host = null;
  const orig = Element.prototype.attachShadow;
  const spy = vi.spyOn(Element.prototype, "attachShadow").mockImplementation(function (init) {
    host = this;
    root = orig.call(this, init);
    return root;
  });
  const RealMO = window.MutationObserver;
  window.MutationObserver = class extends RealMO {
    constructor(cb) {
      super(cb);
      cleanups.push(() => this.disconnect());
    }
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = function (...a) {
    const id = realSetInterval.apply(this, a);
    cleanups.push(() => clearInterval(id));
    return id;
  };
  const realAdd = document.addEventListener;
  document.addEventListener = function (type, fn, opts) {
    cleanups.push(() => document.removeEventListener(type, fn, opts));
    return realAdd.call(this, type, fn, opts);
  };
  try {
    new Function("chrome", SRC)(chrome);
  } finally {
    spy.mockRestore();
    window.MutationObserver = RealMO;
    globalThis.setInterval = realSetInterval;
    document.addEventListener = realAdd;
  }
  return { host, root, chrome, sendMessage, help };
}

/** Stubs for jsdom's missing Popover API and :popover-open / :modal. */
function stubTopLayer() {
  const open = new WeakSet();
  const calls = [];
  HTMLElement.prototype.showPopover = function () {
    calls.push(["show", this.localName]);
    open.add(this);
  };
  HTMLElement.prototype.hidePopover = function () {
    calls.push(["hide", this.localName]);
    open.delete(this);
  };
  const origMatches = Element.prototype.matches;
  const m = vi.spyOn(Element.prototype, "matches").mockImplementation(function (sel) {
    if (sel === ":popover-open") return open.has(this);
    if (sel === ":modal") return this.localName === "dialog" && this.hasAttribute("open") && this.dataset.modal === "1";
    return origMatches.call(this, sel);
  });
  cleanups.push(() => {
    delete HTMLElement.prototype.showPopover;
    delete HTMLElement.prototype.hidePopover;
    m.mockRestore();
  });
  return { open, calls };
}

afterEach(() => {
  while (cleanups.length) cleanups.pop()();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const fab = (root) => root.querySelector("button.fab");
const dock = (root) => root.querySelector(".dock");
const menu = (root) => root.querySelector("[role=menu]");
const items = (root) => [...root.querySelectorAll("[role=menuitem]:not([hidden])")];
const dialog = (root) => root.querySelector("[role=dialog]");
const overlay = (root) => root.querySelector(".overlay");
const title = (root) => root.querySelector(".title").textContent;
const body = (root) => root.querySelector(".body").textContent;
const y = (root) => parseFloat(dock(root).style.getPropertyValue("--y"));

/** Dispatch a keydown on `el`; returns the event (to check defaultPrevented). */
function key(el, k, init = {}) {
  const e = new KeyboardEvent("keydown", { key: k, bubbles: true, composed: true, cancelable: true, ...init });
  el.dispatchEvent(e);
  return e;
}
/** Pointer-ish event on `el` (jsdom has no PointerEvent: a MouseEvent with the pointer type does). */
function pointer(el, type, x, y) {
  el.dispatchEvent(new MouseEvent(type, { bubbles: true, composed: true, clientX: x, clientY: y, button: 0 }));
}
/** Open the menu and pick Exit. */
function chooseExit(root) {
  fab(root).click();
  items(root)[0].click();
}

beforeEach(() => {
  document.documentElement.querySelectorAll("mastersos-exit").forEach((e) => e.remove());
  document.head.innerHTML = "";
  document.body.innerHTML = "<p>exam page</p>";
  sessionStorage.clear();
});

describe("source", () => {
  it("has no Chinese (or other CJK) text: English only", () => {
    expect(SRC).not.toMatch(/[⺀-鿿가-힯豈-﫿＀-￯]/u);
  });

  it("our focus ring is a 2px brand-orange focus-visible ring, not the browser default", () => {
    const { root } = inject();
    const css = root.querySelector("style").textContent;
    expect(css).toMatch(/:focus-visible\s*\{[^}]*outline:\s*2px solid #d9653b/);
    expect(css).not.toMatch(/outline:\s*3px/);
  });
});

describe("floating handle", () => {
  it("is attached to documentElement; the closed shadow root holds an icon-only Options handle", () => {
    const { host, root } = inject();
    expect(host).not.toBeNull();
    expect(host.parentNode).toBe(document.documentElement);
    expect(root).not.toBeNull();
    expect(root.mode).toBe("closed");
    const btn = fab(root);
    expect(btn.textContent.trim()).toBe(""); // no text label
    expect(btn.querySelector("svg")).not.toBeNull();
    expect(btn.getAttribute("aria-label")).toBe("Options");
    expect(btn.getAttribute("title")).toBe("Options");
    expect(btn.getAttribute("aria-haspopup")).toBe("menu");
    expect(btn.getAttribute("aria-expanded")).toBe("false");
    expect(menu(root).hidden).toBe(true);
  });

  it("by default docks to the middle of the right edge (not on the page's bottom-right Next button)", () => {
    const { root } = inject();
    expect(dock(root).dataset.side).toBe("r");
    expect(y(root)).toBe(0.5);
  });

  it("page scripts cannot reach the shadow root or find the button", () => {
    const { host } = inject();
    expect(host.shadowRoot).toBeNull();
    expect(document.querySelector("button")).toBeNull();
    expect(document.body.contains(host)).toBe(false);
  });

  it("page styles button { display:none } and styles aimed at the host do not affect it", () => {
    const style = document.createElement("style");
    style.textContent =
      "button { display: none !important; } mastersos-exit { display: none !important; visibility: hidden !important; }";
    document.head.append(style);
    const { host, root } = inject();
    expect(getComputedStyle(host).display).not.toBe("none");
    expect(getComputedStyle(host).visibility).not.toBe("hidden");
    // Style sheets outside the shadow root do not reach the shadow tree (the browser guarantees it): the button's
    // styles come only from the <style> inside the shadow root. jsdom's getComputedStyle wrongly applies the
    // document's sheets to shadow-tree elements (display is "none" there too), so this only checks that the button is
    // in the shadow tree and the styles are in the shadow root.
    const btn = fab(root);
    expect(btn.isConnected).toBe(true);
    expect(btn.getRootNode()).toBe(root);
    expect(document.querySelectorAll("button")).toHaveLength(0);
    expect(root.querySelector("style").textContent).toContain(".fab");
    expect(btn.hasAttribute("hidden")).toBe(false);
  });

  it("reattaches itself after the page removes it", async () => {
    const { host } = inject();
    host.remove();
    await tick();
    expect(host.parentNode).toBe(document.documentElement);
  });

  it("page keeps removing it: reattached 10 times, then no more and one warning (no endless tug of war)", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { host } = inject();
    for (let i = 0; i < 10; i++) {
      host.remove();
      await tick();
      expect(host.isConnected).toBe(true);
    }
    host.remove();
    await tick();
    expect(host.isConnected).toBe(false);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain("mastersos-exit");
    // stopped means stopped: later changes to <html> do not reattach it
    document.documentElement.append(document.createElement("div"));
    await tick();
    expect(host.isConnected).toBe(false);
  });

  it("no Popover API: an element the page later appends to <html> does not cover it (host moves last)", async () => {
    const { host } = inject();
    expect(host.hasAttribute("popover")).toBe(false);
    const cover = document.createElement("div");
    document.documentElement.append(cover);
    await tick();
    expect(document.documentElement.lastElementChild).toBe(host);
  });

  it("touch: no click after a drag; the next tap still opens the menu", async () => {
    const { root } = inject();
    const btn = fab(root);
    pointer(btn, "pointerdown", 1000, 384);
    pointer(btn, "pointermove", 20, 20);
    pointer(btn, "pointerup", 20, 20);
    await tick();
    btn.click();
    expect(menu(root).hidden).toBe(false);
  });

  it("pointercancel mid-drag: position unchanged, the next tap still opens the menu", () => {
    const { root } = inject();
    const btn = fab(root);
    pointer(btn, "pointerdown", 1000, 384);
    pointer(btn, "pointermove", 20, 20);
    pointer(btn, "pointercancel", 20, 20);
    expect(dock(root).dataset.side).toBe("r");
    expect(y(root)).toBe(0.5);
    expect(sessionStorage.getItem(KEY)).toBeNull();
    btn.click();
    expect(menu(root).hidden).toBe(false);
  });

  it("position comes from the side and height saved in sessionStorage", () => {
    sessionStorage.setItem(KEY, JSON.stringify({ side: "l", y: 0.25 }));
    const { root } = inject();
    expect(dock(root).dataset.side).toBe("l");
    expect(y(root)).toBe(0.25);
  });

  it("an unknown or malformed saved value falls back to the middle of the right edge", () => {
    for (const bad of ["middle", "{", JSON.stringify({ side: "x", y: 0.2 }), JSON.stringify({ side: "l", y: 7 })]) {
      document.documentElement.querySelectorAll("mastersos-exit").forEach((e) => e.remove());
      sessionStorage.setItem(KEY, bad);
      const { root } = inject();
      expect(dock(root).dataset.side).toBe("r");
      expect(y(root)).toBe(0.5);
    }
  });

  it("the old corner value of the previous version is ignored", () => {
    sessionStorage.setItem("mastersos-exit-corner", "tl");
    const { root } = inject();
    expect(dock(root).dataset.side).toBe("r");
    expect(y(root)).toBe(0.5);
  });

  it("the stored height is a fraction of the viewport, so the handle stays inside it on resize", () => {
    const { root } = inject();
    expect(root.querySelector("style").textContent).toMatch(/top:\s*calc\(\(100vh - 48px\) \* var\(--y/);
  });

  it("drag to the top left and release: snaps to the left edge at the top, saved, no menu", () => {
    const { root, sendMessage } = inject();
    const btn = fab(root);
    pointer(btn, "pointerdown", 1000, 384);
    pointer(btn, "pointermove", 500, 300);
    pointer(btn, "pointermove", 20, 20);
    pointer(btn, "pointerup", 20, 20);
    btn.click(); // the browser follows a mouse drag with a click: not a press of the button
    expect(dock(root).dataset.side).toBe("l");
    expect(y(root)).toBe(0);
    expect(JSON.parse(sessionStorage.getItem(KEY))).toEqual({ side: "l", y: 0 });
    expect(menu(root).hidden).toBe(true);
    expect(overlay(root).hidden).toBe(true);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("drag along the right edge: keeps the right side, height follows the pointer (clamped to the viewport)", () => {
    const { root } = inject();
    const btn = fab(root);
    const h = window.innerHeight;
    pointer(btn, "pointerdown", 1000, h / 2);
    pointer(btn, "pointermove", 990, (h - 48) * 0.75 + 24);
    pointer(btn, "pointerup", 990, (h - 48) * 0.75 + 24);
    expect(dock(root).dataset.side).toBe("r");
    expect(y(root)).toBeCloseTo(0.75, 5);
    pointer(btn, "pointerdown", 990, 600);
    pointer(btn, "pointermove", 990, h + 500);
    pointer(btn, "pointerup", 990, h + 500);
    expect(y(root)).toBe(1);
    // inline drag coordinates are gone after release: the stored fraction places it
    expect(dock(root).style.top).toBe("");
    expect(dock(root).style.left).toBe("");
  });

  it("a move under the drag threshold is a click: opens the menu, position unchanged", () => {
    const { root } = inject();
    const btn = fab(root);
    pointer(btn, "pointerdown", 1000, 384);
    pointer(btn, "pointermove", 1003, 386);
    pointer(btn, "pointerup", 1003, 386);
    btn.click();
    expect(menu(root).hidden).toBe(false);
    expect(dock(root).dataset.side).toBe("r");
    expect(sessionStorage.getItem(KEY)).toBeNull();
  });

  it("dragging while the menu is open closes the menu", () => {
    const { root } = inject();
    const btn = fab(root);
    btn.click();
    expect(menu(root).hidden).toBe(false);
    pointer(btn, "pointerdown", 1000, 384);
    pointer(btn, "pointermove", 20, 20);
    pointer(btn, "pointerup", 20, 20);
    btn.click();
    expect(menu(root).hidden).toBe(true);
    expect(dock(root).dataset.side).toBe("l");
  });
});

describe("menu", () => {
  it("clicking the button opens a menu with exactly one action, Exit, focused; nothing is sent", () => {
    const { root, sendMessage } = inject();
    fab(root).click();
    expect(menu(root).hidden).toBe(false);
    expect(fab(root).getAttribute("aria-expanded")).toBe("true");
    expect(items(root).map((i) => i.textContent.trim())).toEqual(["Exit"]);
    expect(root.activeElement).toBe(items(root)[0]);
    expect(overlay(root).hidden).toBe(true);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("clicking the button again closes the menu", () => {
    const { root } = inject();
    fab(root).click();
    fab(root).click();
    expect(menu(root).hidden).toBe(true);
    expect(fab(root).getAttribute("aria-expanded")).toBe("false");
  });

  it("the button is focusable; ArrowDown on it opens the menu with the first action focused", () => {
    const { root } = inject();
    fab(root).focus();
    expect(root.activeElement).toBe(fab(root));
    const e = key(fab(root), "ArrowDown");
    expect(e.defaultPrevented).toBe(true);
    expect(menu(root).hidden).toBe(false);
    expect(root.activeElement).toBe(items(root)[0]);
  });

  it("ArrowUp on the button opens the menu with the last action focused", () => {
    const { root } = inject();
    key(fab(root), "ArrowUp");
    expect(menu(root).hidden).toBe(false);
    expect(root.activeElement).toBe(items(root).at(-1));
  });

  it("Escape closes the menu and gives focus back to the button", () => {
    const { root } = inject();
    fab(root).click();
    const e = key(items(root)[0], "Escape");
    expect(e.defaultPrevented).toBe(true);
    expect(menu(root).hidden).toBe(true);
    expect(root.activeElement).toBe(fab(root));
  });

  it("arrow keys, Home/End and Tab move within the menu (focus stays in it)", () => {
    const { root } = inject();
    fab(root).click();
    const only = items(root)[0];
    for (const [k, init] of [
      ["ArrowDown", {}],
      ["ArrowUp", {}],
      ["Home", {}],
      ["End", {}],
      ["Tab", {}],
      ["Tab", { shiftKey: true }],
    ]) {
      const e = key(root.activeElement, k, init);
      expect(e.defaultPrevented).toBe(true);
      expect(root.activeElement).toBe(only);
      expect(menu(root).hidden).toBe(false);
    }
  });

  it("a press outside closes the menu, and the page still gets that event", () => {
    const seen = [];
    const onPage = (e) => seen.push(e.type);
    document.addEventListener("pointerdown", onPage);
    try {
      const { root } = inject();
      fab(root).click();
      pointer(document.body.querySelector("p"), "pointerdown", 10, 10);
      expect(menu(root).hidden).toBe(true);
      expect(seen).toEqual(["pointerdown"]);
    } finally {
      document.removeEventListener("pointerdown", onPage);
    }
  });

  it("a press inside the menu does not close it", () => {
    const { root } = inject();
    fab(root).click();
    pointer(items(root)[0], "pointerdown", 10, 10);
    expect(menu(root).hidden).toBe(false);
  });

  it("clicks and keys in the menu do not bubble to the page", () => {
    const seen = [];
    const onPage = (e) => seen.push(e.type);
    document.addEventListener("click", onPage);
    document.addEventListener("keydown", onPage);
    try {
      const { root } = inject();
      fab(root).click();
      key(items(root)[0], "ArrowDown");
      key(items(root)[0], "Escape");
      expect(seen).toEqual([]);
    } finally {
      document.removeEventListener("click", onPage);
      document.removeEventListener("keydown", onPage);
    }
  });
});

describe("Exit confirmation", () => {
  const btns = (root) => ({
    cancel: root.querySelector("button.cancel"),
    confirm: root.querySelector("button.confirm"),
    ok: root.querySelector("button.ok"),
  });

  it("the Exit item has an icon and the label Exit", () => {
    const { root } = inject();
    const exit = items(root)[0];
    expect(exit.querySelector("svg")).not.toBeNull();
    expect(exit.textContent.trim()).toBe("Exit");
  });

  it("Exit asks to confirm first, in English, and closes the menu", () => {
    const { root, sendMessage } = inject();
    expect(overlay(root).hidden).toBe(true);
    chooseExit(root);
    expect(menu(root).hidden).toBe(true);
    expect(overlay(root).hidden).toBe(false);
    expect(title(root)).toBe("Exit this app?");
    expect(body(root)).toBe("You will need to open it again from the sign-in screen.");
    const b = btns(root);
    expect(b.cancel.textContent).toBe("Cancel");
    expect(b.confirm.textContent).toBe("Exit");
    expect(b.cancel.hidden).toBe(false);
    expect(b.confirm.hidden).toBe(false);
    expect(b.ok.hidden).toBe(true);
    expect(dialog(root).getAttribute("aria-modal")).toBe("true");
    expect(root.activeElement).toBe(b.cancel);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("Cancel closes the dialog without sending anything; focus back on the handle", () => {
    const { root, sendMessage } = inject();
    chooseExit(root);
    btns(root).cancel.click();
    expect(overlay(root).hidden).toBe(true);
    expect(root.activeElement).toBe(fab(root));
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("Escape cancels too", () => {
    const { root, sendMessage } = inject();
    chooseExit(root);
    key(dialog(root), "Escape");
    expect(overlay(root).hidden).toBe(true);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('confirm sends {cmd:"exit"}; on ok:true the same dialog shows a spinner and Exiting, no buttons', () => {
    const { root, sendMessage } = inject({ ok: true });
    const spinner = () => root.querySelector(".spinner");
    const row = () => root.querySelector(".actions");
    chooseExit(root);
    expect(spinner().hidden).toBe(true);
    expect(row().hidden).toBe(false);
    btns(root).confirm.click();
    expect(sendMessage).toHaveBeenCalledTimes(1);
    expect(sendMessage.mock.calls[0][0]).toEqual({ cmd: "exit" });
    expect(overlay(root).hidden).toBe(false);
    expect(title(root)).toBe("Exiting…");
    expect(body(root)).toBe("Closing this app.");
    // the spinner sits before the title, in the same row
    expect(spinner().hidden).toBe(false);
    expect(spinner().nextElementSibling).toBe(root.querySelector(".title"));
    expect(spinner().getAttribute("aria-hidden")).toBe("true");
    // no stuck-looking disabled buttons: the button row is hidden (its space kept so the card does not jump)
    expect(row().hidden).toBe(true);
    expect(btns(root).confirm.disabled).toBe(true);
    expect(btns(root).cancel.disabled).toBe(true);
    const css = root.querySelector("style").textContent;
    expect(css).toMatch(/\.actions\[hidden\]\s*\{[^}]*visibility:\s*hidden/);
    expect(css).toMatch(/\.spinner\s*\{[^}]*border[^}]*#eee[^}]*#d9653b|\.spinner\s*\{[^}]*#d9653b[^}]*#eee/);
    expect(css).toMatch(/@media \(prefers-reduced-motion: reduce\)\s*\{[^@]*\.spinner\s*\{[^}]*animation:\s*none/);
    // Escape does nothing while exiting
    key(dialog(root), "Escape");
    expect(overlay(root).hidden).toBe(false);
  });

  it("session still there 20 s after ok:true: failure in the same dialog with a single OK", () => {
    vi.useFakeTimers();
    const { root } = inject({ ok: true });
    chooseExit(root);
    btns(root).confirm.click();
    vi.advanceTimersByTime(19999);
    expect(title(root)).toBe("Exiting…");
    vi.advanceTimersByTime(1);
    expectFailed(root);
  });

  function expectFailed(root) {
    expect(overlay(root).hidden).toBe(false);
    expect(title(root)).toBe("Could not exit");
    expect(body(root)).toBe("Could not leave. Please ask a teacher.");
    expect(root.querySelector(".spinner").hidden).toBe(true);
    expect(root.querySelector(".actions").hidden).toBe(false);
    const b = btns(root);
    expect(b.cancel.hidden).toBe(true);
    expect(b.confirm.hidden).toBe(true);
    expect(b.ok.hidden).toBe(false);
    expect(b.ok.disabled).toBe(false);
    expect(b.ok.textContent).toBe("OK");
    expect(root.activeElement).toBe(b.ok);
  }

  it("ok:false: failure with OK; OK closes it and Exit can be tried again from the menu", () => {
    const { root, sendMessage } = inject({ ok: false });
    chooseExit(root);
    btns(root).confirm.click();
    expectFailed(root);
    btns(root).ok.click();
    expect(overlay(root).hidden).toBe(true);
    expect(root.activeElement).toBe(fab(root));
    chooseExit(root);
    expect(title(root)).toBe("Exit this app?");
    expect(btns(root).ok.hidden).toBe(true);
    expect(btns(root).confirm.disabled).toBe(false);
    btns(root).confirm.click();
    expect(sendMessage).toHaveBeenCalledTimes(2);
  });

  it("no reply (background error, lastError) is a failure too", () => {
    const { root, chrome } = inject((cb) => {
      chrome.runtime.lastError = { message: "Could not establish connection" };
      cb(undefined);
      chrome.runtime.lastError = undefined;
    });
    chooseExit(root);
    btns(root).confirm.click();
    expectFailed(root);
  });

  it("Tab stays on the dialog's visible buttons", () => {
    const { root } = inject();
    chooseExit(root);
    const b = btns(root);
    key(b.cancel, "Tab");
    expect(root.activeElement).toBe(b.confirm);
    key(b.confirm, "Tab");
    expect(root.activeElement).toBe(b.cancel);
    key(b.cancel, "Tab", { shiftKey: true });
    expect(root.activeElement).toBe(b.confirm);
  });

  it("clicks and keys in the dialog do not bubble to the page; the page's own events still arrive", () => {
    const seen = [];
    const onPage = (e) => seen.push(e.type);
    document.addEventListener("click", onPage);
    document.addEventListener("keydown", onPage);
    try {
      const { root } = inject();
      chooseExit(root);
      btns(root).cancel.click();
      chooseExit(root);
      key(dialog(root), "Tab");
      expect(seen).toEqual([]);
      // the page's own events reach the page: no global listener swallows them
      document.body.querySelector("p").click();
      expect(seen).toEqual(["click"]);
    } finally {
      document.removeEventListener("click", onPage);
      document.removeEventListener("keydown", onPage);
    }
  });
});

describe("Get help", () => {
  const CATS = ["Wi-Fi", "Can't sign in", "An app", "Screen, keys or sound", "Battery", "Other"];
  const PLACEHOLDER = "What happened? Please don't include passwords or personal details.";
  const SENT = "Sent. Ticket #1042. IT has been told.";
  const QUEUED = "Saved. It will be sent when this computer is online.";
  const LIMITED = "You've sent 3 requests this hour. Please try again later.";
  const OFF = "Help requests are turned off at this school.";
  const FAILED = "Couldn't send. Please tell a teacher.";

  const hd = (root) => root.querySelector(".help-dialog");
  const hOverlay = (root) => hd(root).parentNode;
  const pills = (root) => [...hd(root).querySelectorAll("[role=radio]")];
  const area = (root) => hd(root).querySelector("textarea");
  const send = (root) => hd(root).querySelector("button.send");
  const hCancel = (root) => hd(root).querySelector("button.help-cancel");
  const hOk = (root) => hd(root).querySelector("button.help-ok");
  const hTitle = (root) => hd(root).querySelector(".title").textContent;
  const hBody = (root) => hd(root).querySelector(".body").textContent;
  const hError = (root) => hd(root).querySelector(".error");
  const shown = (e) => {
    for (let n = e; n && n.nodeType === 1; n = n.parentNode) if (n.hidden) return false;
    return true;
  };
  const visible = (root) =>
    [...hd(root).querySelectorAll("button, textarea, input")].filter((e) => shown(e) && !e.disabled);
  const visibleButtons = (root) =>
    visible(root)
      .filter((b) => b.localName === "button" && !b.getAttribute("role"))
      .map((b) => b.textContent);
  const calls = (help, cmd) => help.mock.calls.map((c) => c[0]).filter((m) => m.cmd === cmd);
  // promise callbacks only (works with fake timers too)
  const flush = async () => {
    for (let i = 0; i < 10; i++) await Promise.resolve();
  };
  /** Tear down one injection inside a test that injects several times. */
  const reset = () => {
    while (cleanups.length) cleanups.pop()();
    document.documentElement.querySelectorAll("mastersos-exit").forEach((e) => e.remove());
  };

  /** A support host that is on and answers submit and each status poll from the lists given. */
  function host({ enabled = true, submit = { ok: true, client_id: "c1", state: "queued" }, status = [] } = {}) {
    const left = [...status];
    return (msg, cb) => {
      if (msg.cmd === "help-enabled") cb({ ok: true, enabled });
      else if (msg.cmd === "help-submit") {
        if (submit !== null) cb(submit); // null: never answers
      } else if (msg.cmd === "help-status") cb(left.length ? left.shift() : { ok: true, state: "queued" });
    };
  }
  async function openHelp(root) {
    fab(root).click();
    await flush();
    expect(items(root)[0].textContent.trim()).toBe("Get help");
    items(root)[0].click();
  }
  async function fillAndSend(root, cat = 0, text = "") {
    pills(root)[cat].click();
    area(root).value = text;
    send(root).click();
    await flush();
  }

  it("menu_has_get_help_before_exit: neutral item with an icon, the enabled query is made once", async () => {
    const { root, help } = inject(undefined, { help: host() });
    expect(help).not.toHaveBeenCalled(); // asked only when the menu first opens
    fab(root).click();
    await flush();
    expect(items(root).map((i) => i.textContent.trim())).toEqual(["Get help", "Exit"]);
    const g = items(root)[0];
    expect(g.querySelector("svg")).not.toBeNull();
    expect(g.classList.contains("danger")).toBe(false);
    expect(items(root)[1].classList.contains("danger")).toBe(true);
    // arrow keys now move between the two
    key(root.activeElement, "Home");
    expect(root.activeElement).toBe(g);
    key(g, "ArrowDown");
    expect(root.activeElement).toBe(items(root)[1]);
    fab(root).click();
    fab(root).click();
    await flush();
    expect(calls(help, "help-enabled")).toEqual([{ cmd: "help-enabled" }]);
  });

  it("hidden_when_disabled: turned off, an error, no host or no answer all keep Get help hidden", async () => {
    const answers = [
      (_m, cb) => cb({ ok: true, enabled: false }),
      (_m, cb) => cb({ ok: false }),
      (_m, cb) => cb({ ok: true, enabled: "yes" }),
      (_m, cb) => cb(undefined),
      () => {
        throw new Error("Extension context invalidated.");
      },
      () => {}, // never answers
    ];
    for (const a of answers) {
      const { root } = inject(undefined, { help: a });
      fab(root).click();
      await flush();
      expect(items(root).map((i) => i.textContent.trim())).toEqual(["Exit"]);
      reset();
    }
    // lastError (the background is gone)
    const { root, chrome } = inject(undefined, {
      help: (_m, cb) => {
        chrome.runtime.lastError = { message: "Could not establish connection." };
        cb({ ok: true, enabled: true });
        chrome.runtime.lastError = undefined;
      },
    });
    fab(root).click();
    await flush();
    expect(items(root).map((i) => i.textContent.trim())).toEqual(["Exit"]);
  });

  it("opens a dialog in English: title, six topics, the placeholder, Cancel / Send; menu closed", async () => {
    const { root } = inject(undefined, { help: host() });
    await openHelp(root);
    expect(menu(root).hidden).toBe(true);
    expect(hOverlay(root).hidden).toBe(false);
    expect(hd(root).getAttribute("role")).toBe("dialog");
    expect(hd(root).getAttribute("aria-modal")).toBe("true");
    expect(hTitle(root)).toBe("Get help from IT");
    expect(hd(root).querySelector("[role=radiogroup]")).not.toBeNull();
    expect(pills(root).map((p) => p.textContent)).toEqual(CATS);
    expect(pills(root).map((p) => p.getAttribute("aria-checked"))).toEqual(Array(6).fill("false"));
    expect(area(root).placeholder).toBe(PLACEHOLDER);
    expect(area(root).maxLength).toBe(1000);
    expect(visibleButtons(root)).toEqual(["Cancel", "Send"]);
    expect(root.activeElement).toBe(pills(root)[0]);
    // the Exit dialog stays closed
    expect(overlay(root).hidden).toBe(true);
  });

  it("no_screenshot_option_in_kiosk: no checkbox, no screenshot wording, nothing about it in the message", async () => {
    const { root, help } = inject(undefined, { help: host() });
    await openHelp(root);
    expect(hd(root).querySelector("input")).toBeNull();
    expect(hd(root).textContent).not.toMatch(/screenshot/i);
    await fillAndSend(root, 0, "");
    const [m] = calls(help, "help-submit");
    expect(Object.keys(m).sort()).toEqual(["category", "cmd", "text"]);
  });

  it("dialog_requires_category: Send without a topic sends nothing and says so; picking one clears it", async () => {
    const { root, help } = inject(undefined, { help: host() });
    await openHelp(root);
    expect(shown(hError(root))).toBe(false);
    area(root).value = "no wifi";
    send(root).click();
    await flush();
    expect(calls(help, "help-submit")).toEqual([]);
    expect(shown(hError(root))).toBe(true);
    expect(hError(root).textContent).toBe("Choose a topic first.");
    expect(root.activeElement).toBe(pills(root)[0]);
    pills(root)[1].click();
    expect(shown(hError(root))).toBe(false);
    expect(pills(root)[1].getAttribute("aria-checked")).toBe("true");
    // one topic at a time
    pills(root)[2].click();
    expect(pills(root).map((p) => p.getAttribute("aria-checked"))).toEqual([
      "false",
      "false",
      "true",
      "false",
      "false",
      "false",
    ]);
    send(root).click();
    await flush();
    expect(calls(help, "help-submit")).toHaveLength(1);
  });

  it("sends_native_message_shape: the topic's wire id and the trimmed text; an empty description is fine", async () => {
    const ids = ["wifi", "sign_in", "app", "hardware", "battery", "other"];
    for (let i = 0; i < 6; i++) {
      const { root, help } = inject(undefined, { help: host() });
      await openHelp(root);
      await fillAndSend(root, i, i === 3 ? "  the screen is black \n" : "");
      expect(calls(help, "help-submit")).toEqual([
        { cmd: "help-submit", category: ids[i], text: i === 3 ? "the screen is black" : "" },
      ]);
      reset();
    }
  });

  it("shows_ticket_or_queued_text: polls every 3 s; a ticket shows the Sent text, then polling stops", async () => {
    vi.useFakeTimers();
    const { root, help } = inject(undefined, {
      help: host({ status: [{ ok: true, state: "queued" }, { ok: true, state: "sent", ticket: "1042" }] }),
    });
    await openHelp(root);
    await fillAndSend(root, 0, "");
    // waiting: a spinner, the form gone
    expect(shown(hd(root).querySelector(".spinner"))).toBe(true);
    expect(shown(area(root))).toBe(false);
    expect(calls(help, "help-status")).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(3000);
    expect(calls(help, "help-status")).toEqual([{ cmd: "help-status", client_id: "c1" }]);
    await vi.advanceTimersByTimeAsync(3000);
    expect(calls(help, "help-status")).toHaveLength(2);
    expect(hBody(root)).toBe(SENT);
    expect(shown(hd(root).querySelector(".spinner"))).toBe(false);
    expect(visibleButtons(root)).toEqual(["OK"]);
    expect(root.activeElement).toBe(hOk(root));
    await vi.advanceTimersByTimeAsync(30000);
    expect(calls(help, "help-status")).toHaveLength(2);
    hOk(root).click();
    expect(hOverlay(root).hidden).toBe(true);
    expect(root.activeElement).toBe(fab(root));
  });

  it("shows_ticket_or_queued_text: no ticket within 60 s shows the Saved text and stops polling", async () => {
    vi.useFakeTimers();
    const { root, help } = inject(undefined, { help: host() });
    await openHelp(root);
    await fillAndSend(root, 5, "x");
    await vi.advanceTimersByTimeAsync(57000);
    expect(shown(hd(root).querySelector(".spinner"))).toBe(true);
    await vi.advanceTimersByTimeAsync(3000);
    expect(hBody(root)).toBe(QUEUED);
    const n = calls(help, "help-status").length;
    expect(n).toBe(20);
    await vi.advanceTimersByTimeAsync(30000);
    expect(calls(help, "help-status")).toHaveLength(n);
  });

  it("status answers that fail on the way are retried; a later ticket still shows", async () => {
    vi.useFakeTimers();
    const { root } = inject(undefined, {
      help: host({ status: [{ ok: false }, { ok: false, error: "unreachable" }, { ok: true, state: "sent", ticket: "7" }] }),
    });
    await openHelp(root);
    await fillAndSend(root, 0, "");
    await vi.advanceTimersByTimeAsync(9000);
    expect(hBody(root)).toBe("Sent. Ticket #7. IT has been told.");
  });

  it("errors map to their texts: rate limited, turned off, refused, host unreachable, turned off later", async () => {
    vi.useFakeTimers();
    const cases = [
      [{ submit: { ok: false, error: "rate_limited" } }, LIMITED, 0],
      [{ submit: { ok: false, error: "disabled" } }, OFF, 0],
      [{ submit: { ok: false, error: "invalid" } }, FAILED, 0],
      [{ submit: { ok: false, error: "unreachable" } }, FAILED, 0],
      [{ submit: { ok: false } }, FAILED, 0],
      [{ submit: { ok: true, state: "queued" } }, FAILED, 0], // no client_id
      [{ status: [{ ok: true, state: "disabled" }] }, OFF, 3000],
      [{ status: [{ ok: true, state: "failed" }] }, FAILED, 3000],
      [{ submit: null }, FAILED, 20000], // never answers: not a spinner forever
    ];
    for (const [h, text, wait] of cases) {
      const { root } = inject(undefined, { help: host(h) });
      await openHelp(root);
      await fillAndSend(root, 0, "");
      await vi.advanceTimersByTimeAsync(wait);
      expect(hBody(root), JSON.stringify(h)).toBe(text);
      expect(visibleButtons(root)).toEqual(["OK"]);
      reset();
    }
  });

  it("keyboard: Esc closes and focus goes back to the handle; Tab is trapped in the dialog", async () => {
    const { root, help } = inject(undefined, { help: host() });
    await openHelp(root);
    // the topics are one Tab stop (a radio group); arrows move and pick
    const e = key(pills(root)[0], "ArrowRight");
    expect(e.defaultPrevented).toBe(true);
    expect(root.activeElement).toBe(pills(root)[1]);
    expect(pills(root)[1].getAttribute("aria-checked")).toBe("true");
    key(pills(root)[1], "ArrowLeft");
    key(pills(root)[0], "ArrowLeft");
    expect(root.activeElement).toBe(pills(root)[5]);
    expect(pills(root).filter((p) => p.tabIndex === 0)).toEqual([pills(root)[5]]);
    // Tab: topic -> text -> Cancel -> Send -> topic
    const order = [];
    for (let i = 0; i < 4; i++) {
      const t = key(root.activeElement, "Tab");
      expect(t.defaultPrevented).toBe(true);
      order.push(root.activeElement);
    }
    expect(order).toEqual([area(root), hCancel(root), send(root), pills(root)[5]]);
    key(root.activeElement, "Tab", { shiftKey: true });
    expect(root.activeElement).toBe(send(root));
    // typing in the text does not reach the page and does not close the dialog
    const seen = [];
    const onPage = (ev) => seen.push(ev.type);
    document.addEventListener("keydown", onPage);
    try {
      key(area(root), "a");
      key(area(root), "Enter");
    } finally {
      document.removeEventListener("keydown", onPage);
    }
    expect(seen).toEqual([]);
    expect(hOverlay(root).hidden).toBe(false);
    const esc = key(area(root), "Escape");
    expect(esc.defaultPrevented).toBe(true);
    expect(hOverlay(root).hidden).toBe(true);
    expect(root.activeElement).toBe(fab(root));
    expect(calls(help, "help-submit")).toEqual([]);
  });

  it("Cancel closes without sending; opening again starts from an empty form", async () => {
    const { root, help } = inject(undefined, { help: host() });
    await openHelp(root);
    pills(root)[2].click();
    area(root).value = "abc";
    hCancel(root).click();
    expect(hOverlay(root).hidden).toBe(true);
    expect(root.activeElement).toBe(fab(root));
    await openHelp(root);
    expect(pills(root).every((p) => p.getAttribute("aria-checked") === "false")).toBe(true);
    expect(area(root).value).toBe("");
    expect(shown(area(root))).toBe(true);
    expect(calls(help, "help-submit")).toEqual([]);
  });

  it("closing while waiting stops polling; a late answer does not reopen anything", async () => {
    vi.useFakeTimers();
    const { root, help } = inject(undefined, { help: host() });
    await openHelp(root);
    await fillAndSend(root, 0, "");
    expect(visibleButtons(root)).toEqual(["Close"]);
    key(hd(root), "Escape");
    expect(hOverlay(root).hidden).toBe(true);
    expect(root.activeElement).toBe(fab(root));
    await vi.advanceTimersByTimeAsync(60000);
    expect(calls(help, "help-status")).toEqual([]);
    expect(hOverlay(root).hidden).toBe(true);
  });
});

describe("top layer (page modal dialogs, popovers, fullscreen, transform on <html>)", () => {
  it("with the Popover API: the host is popover=manual and showPopover runs on attach", () => {
    const { open } = stubTopLayer();
    const { host } = inject();
    expect(host.getAttribute("popover")).toBe("manual");
    expect(open.has(host)).toBe(true);
  });

  it("page opens a popover (toggle event): hide then show, back on top of the top layer", async () => {
    const { calls } = stubTopLayer();
    inject();
    const pop = document.createElement("div");
    document.body.append(pop);
    calls.length = 0;
    pop.dispatchEvent(new Event("toggle"));
    expect(calls).toEqual([
      ["hide", "mastersos-exit"],
      ["show", "mastersos-exit"],
    ]);
  });

  it("page showModal: the host moves into that modal dialog (not inert), still in the top layer; back to <html> after", async () => {
    const { open } = stubTopLayer();
    const { host } = inject();
    const dlg = document.createElement("dialog");
    dlg.dataset.modal = "1";
    document.body.append(dlg);
    dlg.setAttribute("open", "");
    await tick();
    expect(host.parentNode).toBe(dlg);
    expect(open.has(host)).toBe(true);
    dlg.removeAttribute("open");
    await tick();
    expect(host.parentNode).toBe(document.documentElement);
    expect(open.has(host)).toBe(true);
  });

  it("raised to the top again after a fullscreen change", () => {
    const { calls } = stubTopLayer();
    inject();
    calls.length = 0;
    document.dispatchEvent(new Event("fullscreenchange"));
    expect(calls.at(-1)).toEqual(["show", "mastersos-exit"]);
  });

  it("page calls hidePopover on the host: shown again", () => {
    const { open } = stubTopLayer();
    const { host } = inject();
    host.hidePopover();
    host.dispatchEvent(new Event("toggle"));
    expect(open.has(host)).toBe(true);
  });

  it("raises triggered by every page toggle are capped: no endless tug of war", () => {
    const { calls } = stubTopLayer();
    vi.spyOn(console, "warn").mockImplementation(() => {});
    inject();
    const pop = document.createElement("div");
    document.body.append(pop);
    calls.length = 0;
    for (let i = 0; i < 100; i++) pop.dispatchEvent(new Event("toggle"));
    const shows = calls.filter((c) => c[0] === "show").length;
    expect(shows).toBeGreaterThan(0);
    expect(shows).toBeLessThanOrEqual(30);
  });
});

describe("watchdog (once a second, touches the DOM only when something is wrong)", () => {
  const flush = () => vi.advanceTimersByTimeAsync(0);

  function modalIn(parent) {
    const dlg = document.createElement("dialog");
    dlg.dataset.modal = "1";
    parent.append(dlg);
    dlg.setAttribute("open", "");
    return dlg;
  }

  it("page remove()s the open modal dialog: within 1 s the host is back on <html> and shown", async () => {
    vi.useFakeTimers();
    const { open } = stubTopLayer();
    const { host } = inject();
    const dlg = modalIn(document.body);
    await flush();
    expect(host.parentNode).toBe(dlg);
    dlg.remove(); // open not removed first: no attribute change, and <html>'s children did not change
    await flush();
    expect(host.isConnected).toBe(false);
    await vi.advanceTimersByTimeAsync(1000);
    expect(host.parentNode).toBe(document.documentElement);
    expect(open.has(host)).toBe(true);
  });

  it("page removes the dialog's container: back on <html> within 1 s as well", async () => {
    vi.useFakeTimers();
    stubTopLayer();
    const { host } = inject();
    const box = document.createElement("div");
    document.body.append(box);
    const dlg = modalIn(box);
    await flush();
    expect(host.parentNode).toBe(dlg);
    box.remove();
    await vi.advanceTimersByTimeAsync(1000);
    expect(host.parentNode).toBe(document.documentElement);
  });

  it("reattaching after a removed dialog does not count against the removal cap: the page can still remove it 10 times", async () => {
    vi.useFakeTimers();
    vi.spyOn(console, "warn").mockImplementation(() => {});
    stubTopLayer();
    const { host } = inject();
    for (let i = 0; i < 12; i++) {
      const dlg = modalIn(document.body);
      await flush();
      dlg.remove();
      await vi.advanceTimersByTimeAsync(1000);
      expect(host.parentNode).toBe(document.documentElement);
    }
    for (let i = 0; i < 10; i++) {
      host.remove();
      await flush();
      expect(host.isConnected).toBe(true);
    }
    expect(console.warn).not.toHaveBeenCalledWith(expect.stringContaining("no longer reattaching"));
  });

  it("quiet page: the per-second check neither writes the DOM nor touches the popover", async () => {
    vi.useFakeTimers();
    const { calls } = stubTopLayer();
    inject();
    calls.length = 0;
    const append = vi.spyOn(Node.prototype, "appendChild");
    const insert = vi.spyOn(Node.prototype, "insertBefore");
    await vi.advanceTimersByTimeAsync(5000);
    expect(calls).toEqual([]);
    expect(append).not.toHaveBeenCalled();
    expect(insert).not.toHaveBeenCalled();
  });

  it("after the M6 stop the watchdog stops too: no reattaching", async () => {
    vi.useFakeTimers();
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const { host } = inject();
    for (let i = 0; i < 11; i++) {
      host.remove();
      await flush();
    }
    expect(host.isConnected).toBe(false);
    expect(console.warn).toHaveBeenCalledWith(expect.stringContaining("no longer reattaching"));
    await vi.advanceTimersByTimeAsync(5000);
    expect(host.isConnected).toBe(false);
  });

  it("raises over the cap are not lost: one more when the window ends (hide then show)", async () => {
    vi.useFakeTimers();
    const { calls } = stubTopLayer();
    vi.spyOn(console, "warn").mockImplementation(() => {});
    inject();
    const pop = document.createElement("div");
    document.body.append(pop);
    for (let i = 0; i < 100; i++) pop.dispatchEvent(new Event("toggle"));
    calls.length = 0;
    await vi.advanceTimersByTimeAsync(10000);
    expect(calls).toEqual([
      ["hide", "mastersos-exit"],
      ["show", "mastersos-exit"],
    ]);
  });

  it("<html> replaced: the host moves to the new <html>, and showModal there is still followed", async () => {
    stubTopLayer();
    const { host } = inject();
    const old = document.documentElement;
    const html = document.createElement("html");
    const body = document.createElement("body");
    html.append(body);
    try {
      document.replaceChild(html, old);
      await tick();
      expect(host.parentNode).toBe(html);
      const dlg = modalIn(body);
      await tick();
      expect(host.parentNode).toBe(dlg);
    } finally {
      document.replaceChild(old, document.documentElement);
    }
  });
});
