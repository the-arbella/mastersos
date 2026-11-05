// Content script of the MastersOS exam extension (plan 9 Task 7, design §4.7): every page of a locked session gets a
// floating "Menu" button in a corner. It opens a small menu of actions (today only "Exit"); Exit asks to confirm in a
// dialog, then asks the background (background.js) to end the locked session over native messaging.
// Actions are the ACTIONS list below: adding one is one more entry there.
//
// It must not break the exam page:
//   - The button, menu and dialog live in a closed shadow root (page scripts cannot reach it, page style sheets do not
//     get in) with all their styles inside it. The host element's own styles are inline with !important (inline
//     !important beats !important in the page's style sheets).
//   - The content script runs in the extension's isolated world and injects nothing into the page's JS world.
//   - It does not swallow page events: clicks and keys on its own elements stop at the shadow root and never bubble to
//     the page. On document there are only listeners that look and never intercept (toggle in capture,
//     fullscreenchange) to raise the button again after the page opens a top-layer element, plus, only while the menu
//     is open, a capturing pointerdown that closes the menu on a press outside it (and lets the event through).
//   - When the page removes the host (or replaces <html>'s children) it is put back; at most 10 times in 10 seconds,
//     then it stops and logs one warning instead of fighting the page forever.
// Top layer: the host is popover="manual" and showPopover() puts it in the top layer, out of reach of the page's
// z-index and of transform / filter / contain on <html>. Modal dialogs, popovers and fullscreen elements the page opens
// later stack above it, so as soon as the page opens one (toggle event, a dialog's open attribute, fullscreenchange)
// the host is hidden and shown again to go back on top. While the page has a modal dialog open everything under
// <html> is inert (not clickable), so the host moves into that dialog (its descendants are not inert) and back to
// <html> when it closes. Raising is capped at 30 times in 10 seconds; raises over the cap are not lost, one more runs
// when the window ends. A once-a-second watchdog puts the button back where it belongs when the page removes an open
// modal dialog directly or replaces <html>.
// Without the Popover API (old Chrome) it falls back to the largest z-index and stays <html>'s last child.
// The button can be dragged to one of the four corners (a move under DRAG_PX is still a click and opens the menu);
// the corner is kept in the page's sessionStorage (same corner after navigating in the same tab).
(function mastersosExamExit() {
  "use strict";

  const KEY = "mastersos-exit-corner";
  const CORNERS = ["br", "bl", "tr", "tl"];
  const DRAG_PX = 6; // a press only becomes a drag after moving this far
  const EXIT_TIMEOUT_MS = 20000; // session still there this long after "requested": treat as not exited

  const TEXT = {
    fab: "Menu",
    exit: "Exit",
    question: "Leave this app? You will need to open it again.",
    cancel: "Cancel",
    confirm: "Exit",
    exiting: "Exiting…",
    failed: "Could not leave. Please ask a teacher.",
  };

  const STYLE = `
:host { all: initial; }
.dock {
  position: fixed; z-index: 2147483647; margin: 0; padding: 0; display: flex; gap: 8px;
  visibility: visible; width: auto; height: auto;
}
.dock[data-corner="br"] { right: 16px; bottom: 16px; flex-direction: column-reverse; align-items: flex-end; }
.dock[data-corner="bl"] { left: 16px; bottom: 16px; flex-direction: column-reverse; align-items: flex-start; }
.dock[data-corner="tr"] { right: 16px; top: 16px; flex-direction: column; align-items: flex-end; }
.dock[data-corner="tl"] { left: 16px; top: 16px; flex-direction: column; align-items: flex-start; }
.fab {
  box-sizing: border-box; display: inline-flex; align-items: center; gap: 8px; margin: 0;
  min-width: 44px; min-height: 44px; width: auto; height: auto; padding: 0 16px 0 14px;
  font: 600 15px/1 system-ui, "Noto Sans", sans-serif; color: #fff; background: #111827;
  border: 2px solid #fff; border-radius: 999px; box-shadow: 0 2px 10px rgba(0, 0, 0, .4);
  cursor: pointer; touch-action: none; user-select: none; opacity: .94; visibility: visible;
}
.fab:hover, .fab:focus-visible, .fab[aria-expanded="true"] { opacity: 1; }
.fab:focus-visible { outline: 3px solid #fbbf24; outline-offset: 2px; }
.dock.dragging .fab { cursor: grabbing; }
.icon {
  display: block; width: 16px; height: 2px; margin: 5px 0; border-radius: 1px;
  background: currentColor; box-shadow: 0 -5px 0 currentColor, 0 5px 0 currentColor;
}
.menu {
  box-sizing: border-box; min-width: 10rem; margin: 0; padding: 6px; display: block;
  background: #fff; color: #111; border-radius: 12px; box-shadow: 0 6px 24px rgba(0, 0, 0, .35);
}
.menu[hidden] { display: none; }
.menu button {
  box-sizing: border-box; display: block; width: 100%; margin: 0; padding: 10px 14px; text-align: left;
  font: 600 15px/1.2 system-ui, "Noto Sans", sans-serif; color: #111; background: transparent;
  border: 0; border-radius: 8px; cursor: pointer;
}
.menu button.danger { color: #b91c1c; }
.menu button:hover, .menu button:focus { background: #f3f4f6; }
.menu button:focus-visible { outline: 3px solid #2563eb; outline-offset: -3px; }
.overlay {
  position: fixed; inset: 0; z-index: 2147483647; display: flex; align-items: center; justify-content: center;
  background: rgba(0, 0, 0, .55); visibility: visible;
}
.overlay[hidden] { display: none; }
.dialog {
  box-sizing: border-box; max-width: min(28rem, calc(100vw - 32px)); margin: 16px; padding: 20px 24px;
  background: #fff; color: #111; border-radius: 12px; box-shadow: 0 8px 32px rgba(0, 0, 0, .4);
  font: 16px/1.5 system-ui, "Noto Sans", sans-serif; text-align: left;
}
.dialog p { margin: 0 0 4px; }
.status { min-height: 1.5em; margin-top: 8px; color: #b91c1c; font-size: 14px; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; margin-top: 16px; }
.actions button {
  margin: 0; padding: 8px 16px; font: 600 15px/1.2 inherit; font-family: inherit; border-radius: 8px; cursor: pointer;
  border: 1px solid #9ca3af; background: #f3f4f6; color: #111;
}
.actions button.confirm { border-color: #b91c1c; background: #b91c1c; color: #fff; }
.actions button:disabled { opacity: .5; cursor: default; }
.actions button:focus-visible { outline: 3px solid #2563eb; outline-offset: 2px; }
`;

  const doc = document;
  if (!doc.documentElement) return;

  function readCorner() {
    try {
      const c = sessionStorage.getItem(KEY);
      return CORNERS.includes(c) ? c : "br";
    } catch {
      return "br"; // sandboxed page or storage disabled: still shown, the corner just is not remembered
    }
  }
  function saveCorner(c) {
    try {
      sessionStorage.setItem(KEY, c);
    } catch {
      // cannot remember it: fine
    }
  }

  // Host: a custom element name (no clash with the page's button / div selectors); inline !important beats page
  // styles aimed at it.
  const host = doc.createElement("mastersos-exit");
  const hostStyle = {
    all: "initial",
    display: "block",
    visibility: "visible",
    opacity: "1",
    position: "fixed",
    top: "0",
    left: "0",
    right: "auto",
    bottom: "auto",
    margin: "0",
    padding: "0",
    border: "0",
    background: "transparent",
    width: "0",
    height: "0",
    overflow: "visible",
    "z-index": "2147483647",
    "pointer-events": "auto",
  };
  for (const [k, v] of Object.entries(hostStyle)) host.style.setProperty(k, v, "important");
  const hasPopover = typeof host.showPopover === "function" && typeof host.hidePopover === "function";
  if (hasPopover) host.setAttribute("popover", "manual");
  const root = host.attachShadow({ mode: "closed" });

  const style = doc.createElement("style");
  style.textContent = STYLE;

  function el(tag, className, text) {
    const e = doc.createElement(tag);
    if (className) e.className = className;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function button(className, text) {
    const b = el("button", className, text);
    b.type = "button";
    return b;
  }

  // ---- floating button and its menu -------------------------------------------
  const dock = el("div", "dock");
  dock.dataset.corner = readCorner();

  const fab = button("fab");
  const icon = el("span", "icon");
  icon.setAttribute("aria-hidden", "true");
  fab.append(icon, el("span", "label", TEXT.fab));
  fab.setAttribute("aria-haspopup", "menu");
  fab.setAttribute("aria-expanded", "false");
  fab.setAttribute("aria-controls", "mastersos-menu");

  const menu = el("div", "menu");
  menu.id = "mastersos-menu";
  menu.setAttribute("role", "menu");
  menu.setAttribute("aria-label", TEXT.fab);
  menu.hidden = true;
  dock.append(fab, menu);

  // ---- Exit confirmation dialog -----------------------------------------------
  const overlay = el("div", "overlay");
  overlay.hidden = true;
  const dialog = el("div", "dialog");
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-labelledby", "mastersos-exit-q");
  const q = el("p", "", TEXT.question);
  q.id = "mastersos-exit-q";
  const status = el("div", "status");
  status.setAttribute("role", "status");
  const actions = el("div", "actions");
  const cancel = button("cancel", TEXT.cancel);
  const confirm = button("confirm", TEXT.confirm);
  actions.append(cancel, confirm);
  dialog.append(q, status, actions);
  overlay.append(dialog);
  root.append(style, dock, overlay);

  // Events on our own elements end at the shadow root and are not seen by page handlers (only ours are stopped; the
  // page's events are left alone).
  for (const type of [
    "click",
    "dblclick",
    "mousedown",
    "mouseup",
    "pointerdown",
    "pointerup",
    "pointermove",
    "touchstart",
    "touchend",
    "keydown",
    "keyup",
    "keypress",
  ]) {
    root.addEventListener(type, (e) => e.stopPropagation());
  }

  // ---- menu -------------------------------------------------------------------
  /** The menu's actions, in order. `danger` paints the item red. */
  const ACTIONS = [{ id: "exit", label: TEXT.exit, danger: true, run: openConfirm }];

  const menuItems = ACTIONS.map((a) => {
    const b = button(a.danger ? "danger" : "", a.label);
    b.setAttribute("role", "menuitem");
    b.dataset.action = a.id;
    b.tabIndex = -1;
    b.addEventListener("click", () => {
      closeMenu(false);
      a.run();
    });
    return b;
  });
  menu.append(...menuItems);

  const menuOpen = () => !menu.hidden;

  /** A press anywhere outside our host closes the menu. Looks only: the page still gets the event. */
  function onOutsidePress(e) {
    if (e.target !== host) closeMenu(false);
  }
  function openMenu(focusIndex = 0) {
    if (!menuOpen()) {
      menu.hidden = false;
      fab.setAttribute("aria-expanded", "true");
      doc.addEventListener("pointerdown", onOutsidePress, true);
    }
    const i = (focusIndex + menuItems.length) % menuItems.length;
    menuItems[i].focus();
  }
  function closeMenu(refocus) {
    if (!menuOpen()) return;
    menu.hidden = true;
    fab.setAttribute("aria-expanded", "false");
    doc.removeEventListener("pointerdown", onOutsidePress, true);
    if (refocus) fab.focus();
  }

  fab.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      openMenu(e.key === "ArrowDown" ? 0 : -1);
    } else if (e.key === "Escape" && menuOpen()) {
      e.preventDefault();
      closeMenu(true);
    }
    // Enter and Space: the native button turns them into a click
  });
  menu.addEventListener("keydown", (e) => {
    const i = menuItems.indexOf(root.activeElement);
    let next = null;
    if (e.key === "Escape") {
      e.preventDefault();
      closeMenu(true);
      return;
    } else if (e.key === "ArrowDown" || (e.key === "Tab" && !e.shiftKey)) {
      next = i + 1;
    } else if (e.key === "ArrowUp" || (e.key === "Tab" && e.shiftKey)) {
      next = i < 0 ? -1 : i - 1;
    } else if (e.key === "Home") {
      next = 0;
    } else if (e.key === "End") {
      next = -1;
    }
    if (next === null) return;
    e.preventDefault(); // focus stays within the menu
    menuItems[(next + menuItems.length) % menuItems.length].focus();
  });

  // ---- drag to a corner -------------------------------------------------------
  let drag = null; // {x, y, id, moved}
  let swallowClick = false;

  fab.addEventListener("pointerdown", (e) => {
    swallowClick = false; // a new press: stop waiting for a click a previous drag never got
    if (e.button !== 0) return;
    drag = { x: e.clientX, y: e.clientY, id: e.pointerId, moved: false };
    try {
      if (e.pointerId !== undefined) fab.setPointerCapture(e.pointerId);
    } catch {
      // dragging works without pointer capture, it just breaks when the pointer leaves the button
    }
  });
  fab.addEventListener("pointermove", (e) => {
    if (!drag) return;
    if (!drag.moved && Math.hypot(e.clientX - drag.x, e.clientY - drag.y) < DRAG_PX) return;
    if (!drag.moved) closeMenu(false);
    drag.moved = true;
    dock.classList.add("dragging");
    dock.style.right = "auto";
    dock.style.bottom = "auto";
    dock.style.left = `${Math.max(0, e.clientX - fab.offsetWidth / 2)}px`;
    dock.style.top = `${Math.max(0, e.clientY - fab.offsetHeight / 2)}px`;
  });
  function endDrag(e, commit) {
    if (!drag) return;
    const moved = drag.moved;
    drag = null;
    dock.classList.remove("dragging");
    for (const p of ["left", "top", "right", "bottom"]) dock.style.removeProperty(p);
    if (!moved || !commit) return; // no click follows a pointercancel, nothing to swallow
    // After a mouse drag the browser sends a click in the same task: swallow it. After a touch drag it often sends
    // none, so stop swallowing from the next task on.
    swallowClick = true;
    setTimeout(() => {
      swallowClick = false;
    }, 0);
    const w = window.innerWidth || doc.documentElement.clientWidth || 0;
    const h = window.innerHeight || doc.documentElement.clientHeight || 0;
    const corner = (e.clientY < h / 2 ? "t" : "b") + (e.clientX < w / 2 ? "l" : "r");
    dock.dataset.corner = corner;
    saveCorner(corner);
  }
  fab.addEventListener("pointerup", (e) => endDrag(e, true));
  fab.addEventListener("pointercancel", (e) => endDrag(e, false));

  fab.addEventListener("click", () => {
    if (swallowClick) {
      swallowClick = false;
      return;
    }
    if (menuOpen()) closeMenu(true);
    else openMenu(0);
  });

  // ---- confirm and exit -------------------------------------------------------
  let timer = null;

  function setBusy(busy, text) {
    confirm.disabled = busy;
    cancel.disabled = busy;
    status.textContent = text;
  }
  function openConfirm() {
    setBusy(false, "");
    overlay.hidden = false;
    cancel.focus();
  }
  function closeConfirm() {
    if (confirm.disabled) return; // already exiting
    overlay.hidden = true;
    fab.focus();
  }
  function failed() {
    if (timer !== null) clearTimeout(timer);
    timer = null;
    setBusy(false, TEXT.failed);
    confirm.focus();
  }

  cancel.addEventListener("click", closeConfirm);
  dialog.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      closeConfirm();
    } else if (e.key === "Tab") {
      // focus stays on the dialog's two buttons
      const items = [cancel, confirm].filter((b) => !b.disabled);
      if (items.length === 0) return;
      const i = items.indexOf(root.activeElement);
      const next = items[(i + (e.shiftKey ? items.length - 1 : 1)) % items.length] || items[0];
      e.preventDefault();
      next.focus();
    }
  });
  confirm.addEventListener("click", () => {
    setBusy(true, TEXT.exiting);
    try {
      chrome.runtime.sendMessage({ cmd: "exit" }, (reply) => {
        const err = chrome.runtime.lastError;
        if (!err && reply && reply.ok === true) {
          // requested: the session ends right away. Still here after this long means it did not.
          timer = setTimeout(failed, EXIT_TIMEOUT_MS);
        } else {
          failed();
        }
      });
    } catch {
      failed(); // after the extension is reloaded, chrome.runtime no longer works in old pages
    }
  });

  // ---- attach, stay on top, reattach when removed -----------------------------
  /** Lets at most `max` calls through per `ms` window; `left()` is how many ms remain in the current window. */
  function limiter(max, ms) {
    let start = -Infinity;
    let n = 0;
    const ok = () => {
      const now = Date.now();
      if (now - start >= ms) {
        start = now;
        n = 0;
      }
      n += 1;
      return n <= max;
    };
    ok.left = () => Math.max(0, start + ms - Date.now());
    return ok;
  }
  const reattachOk = limiter(10, 10000);
  const raiseOk = limiter(30, 10000);
  let stopped = false;
  let raiseWarned = false;
  let trailing = null; // the one raise run when the window ends, after going over the cap
  let parentObs = null;
  let openObs = null;
  let watchdog = null;
  let boundRoot = null; // the <html> openObs watches

  /** The page's open modal dialog (the last in the document): while open, the rest under <html> is inert. */
  function topModal() {
    let found = null;
    for (const d of doc.querySelectorAll("dialog[open]")) {
      try {
        if (d.matches(":modal")) found = d;
      } catch {
        // a browser without :modal has no top layer either
      }
    }
    return found;
  }
  function wantedParent() {
    return topModal() || doc.documentElement;
  }
  function misplaced(parent) {
    return host.parentNode !== parent || (!hasPopover && parent.lastElementChild !== host);
  }
  function isShown() {
    try {
      return host.matches(":popover-open");
    } catch {
      return false;
    }
  }
  function show() {
    if (!hasPopover || !host.isConnected) return;
    try {
      if (isShown()) host.hidePopover(); // hide first, then show: back on top of the top layer
      host.showPopover();
    } catch {
      // fall back to z-index
    }
  }
  function put(parent) {
    parent.appendChild(host);
    if (parentObs) {
      parentObs.disconnect();
      parentObs.observe(parent, { childList: true });
      if (parent !== doc.documentElement) parentObs.observe(doc.documentElement, { childList: true });
    }
  }
  function stop() {
    stopped = true;
    for (const o of observers) o.disconnect();
    clearInterval(watchdog);
    clearTimeout(trailing);
    doc.removeEventListener("toggle", onPageToggle, true);
    doc.removeEventListener("fullscreenchange", raise);
    doc.removeEventListener("pointerdown", onOutsidePress, true);
    console.warn(
      "mastersos-exit: the page keeps removing the menu button; no longer reattaching it (on this page use Alt+F4 or reopen the app)",
    );
  }

  /** The page opened or closed a top-layer element: move to where we belong, then go back on top. */
  function raise() {
    if (stopped) return;
    if (!raiseOk()) {
      if (!raiseWarned) {
        console.warn("mastersos-exit: the page keeps toggling top-layer elements; raising the menu button is deferred");
      }
      raiseWarned = true;
      // not lost: one more when the window ends (only one queued)
      if (trailing === null) {
        trailing = setTimeout(() => {
          trailing = null;
          raise();
        }, raiseOk.left()); // a little early is fine: if still refused it queues again
      }
      return;
    }
    raiseWarned = false;
    const parent = wantedParent();
    if (parent && misplaced(parent)) put(parent);
    show();
  }
  /** The host's parent's children changed: reattach if removed (capped); without the Popover API stay last. */
  function onChildList() {
    if (stopped) return;
    const parent = wantedParent();
    if (!parent) return;
    if (host.parentNode === parent) {
      if (misplaced(parent)) raise(); // no Popover API: the page appended something after us
      return;
    }
    if (!reattachOk()) {
      stop();
      return;
    }
    put(parent);
    show();
  }
  function onPageToggle(e) {
    if (e.target !== host) raise();
  }
  /** <html> was replaced: the open-attribute observer follows the new <html>. */
  function bindRoot() {
    const el = doc.documentElement;
    if (!openObs || !el || el === boundRoot) return;
    boundRoot = el;
    openObs.disconnect();
    openObs.observe(el, { subtree: true, attributes: true, attributeFilter: ["open"] });
  }
  /**
   * Watchdog, once a second: when the page removes an open modal dialog (or its container) directly there is no
   * attribute change, so the host leaves the document unseen by the observers; when <html> is replaced openObs still
   * watches the old one. Each run only does cheap checks (one dialog[open] query, a parent comparison, :popover-open)
   * and touches the DOM only when something is wrong. Its reattaching does not count against the page-removal cap
   * (M6); it is capped at once a second by itself. It stops too once M6 has stopped.
   */
  function check() {
    if (stopped) {
      clearInterval(watchdog);
      return;
    }
    bindRoot();
    const parent = wantedParent();
    if (!parent) return;
    if (misplaced(parent)) {
      put(parent);
      show();
    } else if (hasPopover && !isShown()) {
      show();
    }
  }

  const observers = [];
  put(wantedParent()); // the page may already have a modal dialog open when we are injected
  show();
  parentObs = new MutationObserver(onChildList);
  parentObs.observe(host.parentNode, { childList: true });
  if (host.parentNode !== doc.documentElement) parentObs.observe(doc.documentElement, { childList: true });
  observers.push(parentObs);
  // <html> replaced
  const docObs = new MutationObserver(() => {
    bindRoot();
    onChildList();
  });
  docObs.observe(doc, { childList: true });
  observers.push(docObs);
  // showModal / close change the open attribute (older Chrome dialogs fire no toggle)
  openObs = new MutationObserver(raise);
  bindRoot();
  observers.push(openObs);
  watchdog = setInterval(check, 1000);
  // look, never intercept: no stopPropagation, no preventDefault
  doc.addEventListener("toggle", onPageToggle, true);
  doc.addEventListener("fullscreenchange", raise);
  // the page called hidePopover on the host: show it again
  host.addEventListener("toggle", () => {
    if (hasPopover && !isShown()) raise();
  });
})();
