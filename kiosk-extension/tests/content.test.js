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

/** Run the content script once; returns the attached host, the peeked closed shadow root and the chrome stub. */
function inject(reply = { ok: true }) {
  const sendMessage = vi.fn((_msg, cb) => {
    if (typeof reply === "function") reply(cb);
    else cb(reply);
  });
  const chrome = { runtime: { sendMessage, lastError: undefined } };
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
  return { host, root, chrome, sendMessage };
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
const items = (root) => [...root.querySelectorAll("[role=menuitem]")];
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

  it('confirm sends {cmd:"exit"}; on ok:true the same dialog shows Exiting with its buttons disabled', () => {
    const { root, sendMessage } = inject({ ok: true });
    chooseExit(root);
    btns(root).confirm.click();
    expect(sendMessage).toHaveBeenCalledTimes(1);
    expect(sendMessage.mock.calls[0][0]).toEqual({ cmd: "exit" });
    expect(overlay(root).hidden).toBe(false);
    expect(title(root)).toBe("Exiting…");
    expect(btns(root).confirm.disabled).toBe(true);
    expect(btns(root).cancel.disabled).toBe(true);
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
    expect(body(root)).toBe("Could not leave. Please ask a teacher.");
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
