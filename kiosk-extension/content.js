// Content script of the MastersOS exam extension (plan 9 Task 7, design §4.7): every page of a locked session gets a
// small icon-only "Options" handle docked to the middle of the right edge (exam pages keep Next / Submit bottom right
// and status top right). It opens a small menu of actions ("Get help", "Exit"); Exit asks to confirm in a dialog, then
// asks the background (background.js) to end the locked session over native messaging. Exiting and failure show in
// that same dialog. Actions are the ACTIONS list below: adding one is one more entry there.
// Get help (plan 2026-11-05 Task 7) opens a second dialog: a topic (required), an optional description, Send. The
// background passes it to the local support service, which queues it and sends it to the school's IT; this script
// then asks for its status every 3 s for up to 60 s and shows the ticket number, or that it is saved for later. No
// screenshot here (Ruling P1). The item is shown only after the service says help requests are on (asked once, when
// the menu first opens; any error keeps it hidden).
//
// It must not break the exam page:
//   - The handle, menu and dialog live in a closed shadow root (page scripts cannot reach it, page style sheets do not
//     get in) with all their styles inside it. The host element's own styles are inline with !important (inline
//     !important beats !important in the page's style sheets).
//   - The content script runs in the extension's isolated world and injects nothing into the page's JS world.
//   - It does not swallow page events: clicks and keys on its own elements stop at the shadow root and never bubble to
//     the page. On document there are only listeners that look and never intercept (toggle in capture,
//     fullscreenchange) to raise the handle again after the page opens a top-layer element, plus, only while the menu
//     is open, a capturing pointerdown that closes the menu on a press outside it (and lets the event through).
//   - When the page removes the host (or replaces <html>'s children) it is put back; at most 10 times in 10 seconds,
//     then it stops and logs one warning instead of fighting the page forever.
// Top layer: the host is popover="manual" and showPopover() puts it in the top layer, out of reach of the page's
// z-index and of transform / filter / contain on <html>. Modal dialogs, popovers and fullscreen elements the page opens
// later stack above it, so as soon as the page opens one (toggle event, a dialog's open attribute, fullscreenchange)
// the host is hidden and shown again to go back on top. While the page has a modal dialog open everything under
// <html> is inert (not clickable), so the host moves into that dialog (its descendants are not inert) and back to
// <html> when it closes. Raising is capped at 30 times in 10 seconds; raises over the cap are not lost, one more runs
// when the window ends. A once-a-second watchdog puts the handle back where it belongs when the page removes an open
// modal dialog directly or replaces <html>.
// Without the Popover API (old Chrome) it falls back to the largest z-index and stays <html>'s last child.
// The handle can be dragged anywhere and snaps to the nearer side edge on release (a move under DRAG_PX is still a
// click and opens the menu). Side and height (a fraction of the free viewport height, so it stays inside the viewport
// on resize) are kept in the page's sessionStorage (same place after navigating in the same tab).
(function mastersosExamExit() {
  "use strict";

  const KEY = "mastersos-exit-pos"; // {"side": "l" | "r", "y": 0..1}; the old corner key is ignored
  const HANDLE_H = 48; // px, keep in step with .fab in STYLE
  const DRAG_PX = 6; // a press only becomes a drag after moving this far
  const EXIT_TIMEOUT_MS = 20000; // session still there this long after "requested": treat as not exited
  const ASK_TIMEOUT_MS = 15000; // a help message the background never answers counts as failed
  const POLL_MS = 3000; // help status: every 3 s ...
  const POLL_FOR_MS = 60000; // ... for up to 60 s, then "saved, sent later"
  const TEXT_MAX = 1000; // the support service's limit on the description

  const TEXT = {
    handle: "Options",
    exit: "Exit",
    confirmTitle: "Exit this app?",
    confirmBody: "You will need to open it again from the sign-in screen.",
    cancel: "Cancel",
    confirm: "Exit",
    exitingTitle: "Exiting…",
    exitingBody: "Closing this app.",
    failedTitle: "Could not exit",
    failedBody: "Could not leave. Please ask a teacher.",
    ok: "OK",
    help: "Get help",
    helpTitle: "Get help from IT",
    helpTopic: "What is it about?",
    helpDetails: "Details (optional)",
    helpPlaceholder: "What happened? Please don't include passwords or personal details.",
    helpNeedTopic: "Choose a topic first.",
    send: "Send",
    close: "Close",
    sendingTitle: "Sending…",
    sendingBody: "Telling IT. This can take up to a minute.",
    // the ticket part is bold: [before, bold, after]
    helpSent: (ticket) => ["Sent. ", `Ticket #${ticket}`, ". IT has been told."],
    helpQueued: "Saved. It will be sent when this computer is online.",
    helpLimited: "You've sent 3 requests this hour. Please try again later.",
    helpOff: "Help requests are turned off at this school.",
    helpFailed: "Couldn't send. Please tell a teacher.",
  };

  /** Help topics: [wire id (SupportCategory in mastersos-bundle), label]. */
  const TOPICS = [
    ["wifi", "Wi-Fi"],
    ["sign_in", "Can't sign in"],
    ["app", "An app"],
    ["hardware", "Screen, keys or sound"],
    ["battery", "Battery"],
    ["other", "Other"],
  ];

  // Icons as [tag, attributes] lists, drawn on a 24x24 grid (built with createElementNS: no innerHTML).
  const ICONS = {
    dots: [
      ["circle", { cx: 12, cy: 5, r: 2, fill: "currentColor" }],
      ["circle", { cx: 12, cy: 12, r: 2, fill: "currentColor" }],
      ["circle", { cx: 12, cy: 19, r: 2, fill: "currentColor" }],
    ],
    // a door with an arrow leaving it
    exit: [
      ["path", { d: "M10 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h4" }],
      ["path", { d: "M15 8l4 4-4 4" }],
      ["path", { d: "M19 12H9" }],
    ],
    // result states of Get help, each a circle with a mark
    statusSent: [
      ["circle", { cx: 12, cy: 12, r: 9 }],
      ["path", { d: "M8 12.4l2.7 2.7L16 9.6" }],
    ],
    statusQueued: [
      ["circle", { cx: 12, cy: 12, r: 9 }],
      ["path", { d: "M12 7.5V12l3 2" }],
    ],
    statusInfo: [
      ["circle", { cx: 12, cy: 12, r: 9 }],
      ["path", { d: "M12 11.2V16" }],
      ["path", { d: "M12 8h.01" }],
    ],
    statusFailed: [
      ["circle", { cx: 12, cy: 12, r: 9 }],
      ["path", { d: "M12 7.6v5" }],
      ["path", { d: "M12 16.2h.01" }],
    ],
    // a question mark in a circle
    help: [
      ["circle", { cx: 12, cy: 12, r: 9 }],
      ["path", { d: "M9.6 9.2a2.5 2.5 0 0 1 4.85.8c0 1.7-2.45 2.2-2.45 3.6" }],
      ["path", { d: "M12 17.2h.01" }],
    ],
  };

  const FONT = `system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", sans-serif`;
  const STYLE = `
:host { all: initial; }
button { font-family: ${FONT}; -webkit-tap-highlight-color: transparent; }
button:focus { outline: none; }
button:focus-visible { outline: 2px solid #d9653b; outline-offset: 2px; }
button::-moz-focus-inner { border: 0; }
.dock {
  position: fixed; z-index: 2147483647; margin: 0; padding: 0; width: auto; height: ${HANDLE_H}px;
  top: calc((100vh - ${HANDLE_H}px) * var(--y, .5)); visibility: visible;
}
.dock[data-side="r"] { right: 0; }
.dock[data-side="l"] { left: 0; }
.fab {
  box-sizing: border-box; display: flex; align-items: center; justify-content: center; margin: 0; padding: 0;
  width: 40px; height: ${HANDLE_H}px; min-width: 40px; color: #fff; background: rgba(27, 29, 42, .85);
  border: 1px solid rgba(255, 255, 255, .55); box-shadow: 0 2px 10px rgba(0, 0, 0, .3);
  cursor: pointer; touch-action: none; user-select: none; visibility: visible;
  transition: width .12s ease, background-color .12s ease;
}
.dock[data-side="r"] .fab { border-right: 0; border-radius: 12px 0 0 12px; }
.dock[data-side="l"] .fab { border-left: 0; border-radius: 0 12px 12px 0; }
.fab:hover, .fab:focus-visible, .fab[aria-expanded="true"] { width: 44px; background: #1b1d2a; }
.dock.dragging .fab { cursor: grabbing; border-radius: 12px; }
.fab svg { width: 20px; height: 20px; display: block; pointer-events: none; }
.menu {
  position: absolute; top: 50%; transform: translateY(-50%); box-sizing: border-box; min-width: 11rem; margin: 0;
  padding: 6px; display: block; background: #fff; color: #1b1d2a; border-radius: 12px;
  box-shadow: 0 8px 28px rgba(16, 18, 27, .22), 0 1px 3px rgba(16, 18, 27, .12);
}
.dock[data-side="r"] .menu { right: calc(100% + 8px); }
.dock[data-side="l"] .menu { left: calc(100% + 8px); }
.menu[hidden] { display: none; }
.menu button {
  box-sizing: border-box; display: flex; align-items: center; gap: 12px; width: 100%; height: 44px; margin: 0;
  padding: 0 14px; text-align: left; font: 500 15px/1.2 ${FONT}; color: #1b1d2a; background: transparent;
  border: 0; border-radius: 8px; cursor: pointer; white-space: nowrap;
}
.menu button svg { width: 18px; height: 18px; flex: none; display: block; }
.menu button.danger { color: #b3261e; }
.menu button:hover, .menu button:focus { background: #f1f2f6; }
.menu button:focus-visible { outline-offset: -2px; }
.overlay {
  position: fixed; inset: 0; z-index: 2147483647; display: flex; align-items: center; justify-content: center;
  background: rgba(0, 0, 0, .55); visibility: visible;
}
.overlay[hidden] { display: none; }
.dialog {
  box-sizing: border-box; width: calc(100vw - 32px); max-width: 420px; margin: 16px; padding: 24px;
  display: flex; flex-direction: column; gap: 20px; background: #fff; color: #1b1d2a; border-radius: 16px;
  box-shadow: 0 16px 48px rgba(16, 18, 27, .35); font: 15px/1.5 ${FONT}; text-align: left;
}
.text { display: flex; flex-direction: column; gap: 8px; }
.head { display: flex; align-items: center; gap: 10px; }
.title { margin: 0; font: 600 18px/1.3 ${FONT}; color: #1b1d2a; }
.spinner {
  box-sizing: border-box; flex: none; width: 18px; height: 18px; border-radius: 50%;
  border: 2px solid #eee; border-top-color: #d9653b; animation: mastersos-spin .8s linear infinite;
}
.spinner[hidden] { display: none; }
@keyframes mastersos-spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) {
  .spinner { animation: none; border-color: #d9653b #eee; }
}
.body { margin: 0; font: 400 15px/1.5 ${FONT}; color: #444; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; }
.actions button {
  box-sizing: border-box; height: 40px; margin: 0; padding: 0 18px; font: 600 15px/1 ${FONT}; border-radius: 8px;
  cursor: pointer; border: 1px solid #c9ccd6; background: #fff; color: #1b1d2a;
}
.actions button:hover { background: #f1f2f6; }
.actions button.confirm { border-color: #b3261e; background: #b3261e; color: #fff; }
.actions button.confirm:hover { background: #9c2019; }
.actions[hidden] { display: flex; visibility: hidden; } /* keeps its height: the card does not jump */
.actions button[hidden] { display: none; }
.actions button:disabled { opacity: .5; cursor: default; }
.actions button.send { border-color: #1b1d2a; background: #1b1d2a; color: #fff; }
.actions button.send:hover { background: #33364a; }
.help-dialog { max-width: 480px; max-height: calc(100vh - 32px); overflow-y: auto; }
.body[hidden], .form[hidden], .error[hidden] { display: none; }
.form { display: flex; flex-direction: column; gap: 8px; margin: 0; }
.field-label { display: block; margin: 0; font: 600 14px/1.3 ${FONT}; color: #1b1d2a; }
.field-label.next { margin-top: 10px; }
.pills { display: flex; flex-wrap: wrap; gap: 8px; }
.pills button {
  box-sizing: border-box; height: 36px; margin: 0; padding: 0 14px; font: 500 14px/1 ${FONT}; color: #1b1d2a;
  background: #fff; border: 1px solid #c9ccd6; border-radius: 18px; cursor: pointer; white-space: nowrap;
}
.pills button:hover { background: #f1f2f6; }
.pills button[aria-checked="true"] { background: #1b1d2a; border-color: #1b1d2a; color: #fff; }
.error { margin: 0; font: 500 14px/1.4 ${FONT}; color: #b3261e; }
textarea {
  box-sizing: border-box; display: block; width: 100%; height: 104px; min-height: 64px; max-height: 40vh; margin: 0;
  padding: 10px 12px; resize: vertical; font: 400 15px/1.45 ${FONT}; color: #1b1d2a; background: #fff;
  border: 1px solid #c9ccd6; border-radius: 8px;
}
textarea::placeholder { color: #6b6f7b; }
textarea:focus { outline: none; border-color: #1b1d2a; }
textarea:focus-visible { outline: 2px solid #d9653b; outline-offset: 2px; }
.body.result { display: flex; align-items: center; gap: 12px; margin-top: 4px; font-size: 15px; }
.result .status { flex: none; width: 24px; height: 24px; display: block; color: #5b6170; }
.result .status[data-status="sent"] { color: #1e7d45; }
.result .status[data-status="failed"] { color: #b3261e; }
.result strong { font-weight: 700; }
`;

  const doc = document;
  if (!doc.documentElement) return;

  const DEFAULT_POS = { side: "r", y: 0.5 };
  function readPos() {
    try {
      const p = JSON.parse(sessionStorage.getItem(KEY));
      if (p && (p.side === "l" || p.side === "r") && typeof p.y === "number" && p.y >= 0 && p.y <= 1) {
        return { side: p.side, y: p.y };
      }
    } catch {
      // sandboxed page, storage disabled or a malformed value: still shown at the default place
    }
    return DEFAULT_POS;
  }
  function savePos(p) {
    try {
      sessionStorage.setItem(KEY, JSON.stringify(p));
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
  const SVG_NS = "http://www.w3.org/2000/svg";
  function svgIcon(parts) {
    const svg = doc.createElementNS(SVG_NS, "svg");
    const attrs = { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "2" };
    Object.assign(attrs, { "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" });
    for (const [k, v] of Object.entries(attrs)) svg.setAttribute(k, v);
    svg.setAttribute("focusable", "false");
    for (const [tag, a] of parts) {
      const n = doc.createElementNS(SVG_NS, tag);
      for (const [k, v] of Object.entries(a)) n.setAttribute(k, String(v));
      svg.append(n);
    }
    return svg;
  }

  // ---- floating handle and its menu -------------------------------------------
  const dock = el("div", "dock");
  function place(p) {
    dock.dataset.side = p.side;
    dock.style.setProperty("--y", String(p.y));
  }
  place(readPos());

  const fab = button("fab");
  const dots = svgIcon(ICONS.dots);
  dots.setAttribute("stroke", "none");
  fab.append(dots);
  fab.setAttribute("aria-label", TEXT.handle);
  fab.title = TEXT.handle;
  fab.setAttribute("aria-haspopup", "menu");
  fab.setAttribute("aria-expanded", "false");
  fab.setAttribute("aria-controls", "mastersos-menu");

  const menu = el("div", "menu");
  menu.id = "mastersos-menu";
  menu.setAttribute("role", "menu");
  menu.setAttribute("aria-label", TEXT.handle);
  menu.hidden = true;
  dock.append(fab, menu);

  // ---- Exit dialog: confirm, then exiting / failed in the same card ------------
  const overlay = el("div", "overlay");
  overlay.hidden = true;
  const dialog = el("div", "dialog");
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-labelledby", "mastersos-exit-title");
  dialog.setAttribute("aria-describedby", "mastersos-exit-body");
  const text = el("div", "text");
  text.setAttribute("aria-live", "polite");
  const head = el("div", "head");
  const spinner = el("span", "spinner");
  spinner.setAttribute("aria-hidden", "true");
  spinner.hidden = true;
  const title = el("h2", "title");
  title.id = "mastersos-exit-title";
  head.append(spinner, title);
  const body = el("p", "body");
  body.id = "mastersos-exit-body";
  text.append(head, body);
  const actions = el("div", "actions");
  const cancel = button("cancel", TEXT.cancel);
  const confirm = button("confirm", TEXT.confirm);
  const ok = button("ok", TEXT.ok);
  actions.append(cancel, confirm, ok);
  dialog.append(text, actions);
  overlay.append(dialog);

  // ---- Get help dialog: form, then sending / result in the same card ----------
  const helpOverlay = el("div", "overlay");
  helpOverlay.hidden = true;
  const helpDialog = el("div", "dialog help-dialog");
  helpDialog.setAttribute("role", "dialog");
  helpDialog.setAttribute("aria-modal", "true");
  helpDialog.setAttribute("aria-labelledby", "mastersos-help-title");
  helpDialog.setAttribute("aria-describedby", "mastersos-help-body");
  const helpText = el("div", "text");
  helpText.setAttribute("aria-live", "polite");
  const helpHead = el("div", "head");
  const helpSpinner = el("span", "spinner");
  helpSpinner.setAttribute("aria-hidden", "true");
  helpSpinner.hidden = true;
  const helpTitle = el("h2", "title", TEXT.helpTitle);
  helpTitle.id = "mastersos-help-title";
  helpHead.append(helpSpinner, helpTitle);
  const helpBody = el("p", "body");
  helpBody.id = "mastersos-help-body";
  helpBody.hidden = true;
  helpText.append(helpHead, helpBody);
  const form = el("div", "form");
  const topicLabel = el("p", "field-label", TEXT.helpTopic);
  topicLabel.id = "mastersos-help-topic";
  const pillBox = el("div", "pills");
  pillBox.setAttribute("role", "radiogroup");
  pillBox.setAttribute("aria-labelledby", "mastersos-help-topic");
  pillBox.setAttribute("aria-required", "true");
  const pills = TOPICS.map(([id, label]) => {
    const b = button("", label);
    b.setAttribute("role", "radio");
    b.setAttribute("aria-checked", "false");
    b.dataset.topic = id;
    return b;
  });
  pillBox.append(...pills);
  const helpError = el("p", "error", TEXT.helpNeedTopic);
  helpError.setAttribute("role", "alert");
  helpError.hidden = true;
  const detailsLabel = el("label", "field-label next", TEXT.helpDetails);
  detailsLabel.htmlFor = "mastersos-help-text";
  const area = doc.createElement("textarea");
  area.id = "mastersos-help-text";
  area.maxLength = TEXT_MAX;
  area.rows = 4;
  area.placeholder = TEXT.helpPlaceholder;
  area.spellcheck = true;
  form.append(topicLabel, pillBox, helpError, detailsLabel, area);
  const helpActions = el("div", "actions");
  const helpCancel = button("help-cancel", TEXT.cancel);
  const helpSend = button("send", TEXT.send);
  const helpClose = button("help-close", TEXT.close);
  const helpOk = button("help-ok", TEXT.ok);
  const helpButtons = [helpCancel, helpSend, helpClose, helpOk];
  helpActions.append(...helpButtons);
  helpDialog.append(helpText, form, helpActions);
  helpOverlay.append(helpDialog);
  root.append(style, dock, overlay, helpOverlay);

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
  /**
   * The menu's actions, in order. `icon` is a key of ICONS; `danger` paints the item red; `hidden` keeps it out of the
   * menu until something shows it (Get help: when the support service says it is on).
   */
  const ACTIONS = [
    { id: "help", label: TEXT.help, icon: "help", hidden: true, run: openHelp },
    { id: "exit", label: TEXT.exit, icon: "exit", danger: true, run: openConfirm },
  ];

  const allItems = ACTIONS.map((a) => {
    const b = button(a.danger ? "danger" : "");
    b.append(svgIcon(ICONS[a.icon]), el("span", "label", a.label));
    b.setAttribute("role", "menuitem");
    b.dataset.action = a.id;
    b.tabIndex = -1;
    b.hidden = a.hidden === true;
    b.addEventListener("click", () => {
      closeMenu(false);
      a.run();
    });
    return b;
  });
  menu.append(...allItems);
  const helpItem = allItems[0];
  /** The items shown right now (keyboard moves only between these). */
  const visibleItems = () => allItems.filter((b) => !b.hidden);

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
      askHelpEnabled();
    }
    const items = visibleItems();
    items[(focusIndex + items.length) % items.length].focus();
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
    const menuItems = visibleItems();
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

  // ---- drag along the side edges ----------------------------------------------
  let drag = null; // {x, y, id, moved}
  let swallowClick = false;

  const viewport = () => ({
    w: window.innerWidth || doc.documentElement.clientWidth || 0,
    h: window.innerHeight || doc.documentElement.clientHeight || 0,
  });
  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));

  fab.addEventListener("pointerdown", (e) => {
    swallowClick = false; // a new press: stop waiting for a click a previous drag never got
    if (e.button !== 0) return;
    drag = { x: e.clientX, y: e.clientY, id: e.pointerId, moved: false };
    try {
      if (e.pointerId !== undefined) fab.setPointerCapture(e.pointerId);
    } catch {
      // dragging works without pointer capture, it just breaks when the pointer leaves the handle
    }
  });
  fab.addEventListener("pointermove", (e) => {
    if (!drag) return;
    if (!drag.moved && Math.hypot(e.clientX - drag.x, e.clientY - drag.y) < DRAG_PX) return;
    if (!drag.moved) closeMenu(false);
    drag.moved = true;
    const { w, h } = viewport();
    const fw = fab.offsetWidth || 40;
    dock.classList.add("dragging");
    dock.style.right = "auto";
    dock.style.left = `${clamp(e.clientX - fw / 2, 0, Math.max(0, w - fw))}px`;
    dock.style.top = `${clamp(e.clientY - HANDLE_H / 2, 0, Math.max(0, h - HANDLE_H))}px`;
  });
  function endDrag(e, commit) {
    if (!drag) return;
    const moved = drag.moved;
    drag = null;
    dock.classList.remove("dragging");
    for (const p of ["left", "top", "right"]) dock.style.removeProperty(p);
    if (!moved || !commit) return; // no click follows a pointercancel, nothing to swallow
    // After a mouse drag the browser sends a click in the same task: swallow it. After a touch drag it often sends
    // none, so stop swallowing from the next task on.
    swallowClick = true;
    setTimeout(() => {
      swallowClick = false;
    }, 0);
    const { w, h } = viewport();
    const free = h - HANDLE_H;
    const p = {
      side: e.clientX < w / 2 ? "l" : "r",
      y: free > 0 ? clamp((e.clientY - HANDLE_H / 2) / free, 0, 1) : 0.5,
    };
    place(p);
    savePos(p);
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
  let state = "closed"; // closed | confirm | exiting | failed

  /** Show one state of the dialog: its title, body and buttons; focus goes to `focus`. */
  function setState(next) {
    state = next;
    const v = {
      confirm: [TEXT.confirmTitle, TEXT.confirmBody, [cancel, confirm], cancel],
      exiting: [TEXT.exitingTitle, TEXT.exitingBody, [cancel, confirm], null],
      failed: [TEXT.failedTitle, TEXT.failedBody, [ok], ok],
    }[next];
    if (!v) return;
    const [t, b, shown, focus] = v;
    title.textContent = t;
    body.textContent = b;
    // exiting: a spinner instead of disabled buttons that would look stuck
    spinner.hidden = next !== "exiting";
    actions.hidden = next === "exiting";
    for (const btn of [cancel, confirm, ok]) {
      btn.hidden = !shown.includes(btn);
      btn.disabled = next === "exiting";
    }
    if (focus) focus.focus();
  }
  function openConfirm() {
    overlay.hidden = false;
    setState("confirm");
  }
  function closeDialog() {
    if (state === "exiting") return; // already exiting
    state = "closed";
    overlay.hidden = true;
    fab.focus();
  }
  function failed() {
    if (timer !== null) clearTimeout(timer);
    timer = null;
    setState("failed");
  }

  cancel.addEventListener("click", closeDialog);
  ok.addEventListener("click", closeDialog);
  dialog.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      closeDialog();
    } else if (e.key === "Tab") {
      // focus stays on the dialog's visible buttons
      const items = [cancel, confirm, ok].filter((b) => !b.hidden && !b.disabled);
      e.preventDefault();
      if (items.length === 0) return;
      const i = items.indexOf(root.activeElement);
      const next = items[(i + (e.shiftKey ? items.length - 1 : 1)) % items.length] || items[0];
      next.focus();
    }
  });
  confirm.addEventListener("click", () => {
    setState("exiting");
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

  // ---- Get help -----------------------------------------------------------------
  /**
   * One message to the background; resolves with its answer (an object) or null when there is none: no background,
   * lastError, not an object, or no answer within ASK_TIMEOUT_MS.
   */
  function ask(msg) {
    return new Promise((resolve) => {
      let done = false;
      const finish = (r) => {
        if (done) return;
        done = true;
        clearTimeout(t);
        resolve(r);
      };
      const t = setTimeout(() => finish(null), ASK_TIMEOUT_MS);
      try {
        chrome.runtime.sendMessage(msg, (reply) => {
          const err = chrome.runtime.lastError;
          finish(!err && reply !== null && typeof reply === "object" ? reply : null);
        });
      } catch {
        finish(null); // after the extension is reloaded, chrome.runtime no longer works in old pages
      }
    });
  }

  let helpAsked = false;
  /** Once per page, when the menu first opens: show Get help only on a clear "on". */
  function askHelpEnabled() {
    if (helpAsked) return;
    helpAsked = true;
    ask({ cmd: "help-enabled" }).then((r) => {
      if (r && r.ok === true && r.enabled === true) helpItem.hidden = false;
    });
  }

  let helpState = "closed"; // closed | form | sending | result
  let helpRun = 0; // bumped on every send and close: answers for an older run are dropped
  let pollTimer = null;
  let picked = -1;

  function pick(i, focus) {
    picked = i;
    pills.forEach((p, j) => {
      p.setAttribute("aria-checked", String(j === i));
      p.tabIndex = j === (i < 0 ? 0 : i) ? 0 : -1; // the group is one Tab stop
    });
    if (i >= 0) helpError.hidden = true;
    if (focus) pills[i < 0 ? 0 : i].focus();
  }
  /** Show one state of the help card: title, spinner, body text, form and which buttons. */
  function helpView(next, bodyText) {
    helpState = next;
    const shown = { form: [helpCancel, helpSend], sending: [helpClose], result: [helpOk] }[next];
    helpTitle.textContent = next === "sending" ? TEXT.sendingTitle : TEXT.helpTitle;
    helpSpinner.hidden = next !== "sending";
    helpBody.hidden = next === "form";
    helpBody.classList.remove("result");
    helpBody.textContent = bodyText || "";
    form.hidden = next !== "form";
    for (const b of helpButtons) b.hidden = !shown.includes(b);
  }
  function stopPolling() {
    if (pollTimer !== null) clearTimeout(pollTimer);
    pollTimer = null;
  }
  function openHelp() {
    helpRun += 1;
    stopPolling();
    area.value = "";
    helpError.hidden = true;
    pick(-1, false);
    helpOverlay.hidden = false;
    helpView("form");
    pills[0].focus();
  }
  function closeHelp() {
    helpRun += 1;
    stopPolling();
    helpState = "closed";
    helpOverlay.hidden = true;
    fab.focus();
  }
  const STATUS_ICON = { sent: "statusSent", queued: "statusQueued", info: "statusInfo", failed: "statusFailed" };
  /**
   * The result card: a status icon (sent | queued | info | failed) left of the message. `text` is a string, or
   * [before, bold, after] (the Sent text with its ticket in <strong>); built from DOM nodes only.
   */
  function helpResult(status, text) {
    stopPolling();
    helpView("result");
    const icon = svgIcon(ICONS[STATUS_ICON[status]]);
    icon.classList.add("status");
    icon.dataset.status = status;
    const msg = el("span", "message");
    if (Array.isArray(text)) msg.append(text[0], el("strong", "", text[1]), text[2]);
    else msg.textContent = text;
    helpBody.classList.add("result");
    helpBody.replaceChildren(icon, msg);
    helpOk.focus();
  }
  const ERROR_RESULT = { rate_limited: ["info", TEXT.helpLimited], disabled: ["info", TEXT.helpOff] };

  function sendHelp() {
    if (picked < 0) {
      helpError.hidden = false;
      pills[0].focus();
      return;
    }
    const run = ++helpRun;
    const msg = { cmd: "help-submit", category: TOPICS[picked][0], text: area.value.trim().slice(0, TEXT_MAX) };
    helpView("sending", TEXT.sendingBody);
    helpClose.focus();
    ask(msg).then((r) => {
      if (run !== helpRun) return;
      if (!r || r.ok !== true || typeof r.client_id !== "string" || r.client_id === "") {
        helpResult(...((r && ERROR_RESULT[r.error]) || ["failed", TEXT.helpFailed]));
        return;
      }
      const id = r.client_id;
      const until = Date.now() + POLL_FOR_MS;
      const poll = () => {
        pollTimer = null;
        ask({ cmd: "help-status", client_id: id }).then((st) => {
          if (run !== helpRun) return;
          if (st && st.ok === true && st.state === "sent" && typeof st.ticket === "string" && st.ticket !== "") {
            helpResult("sent", TEXT.helpSent(st.ticket));
          } else if (st && st.ok === true && st.state === "disabled") {
            helpResult("info", TEXT.helpOff);
          } else if (st && st.ok === true && st.state === "failed") {
            helpResult("failed", TEXT.helpFailed);
          } else if (Date.now() >= until) {
            helpResult("queued", TEXT.helpQueued); // it is in the service's queue: sent when online
          } else {
            pollTimer = setTimeout(poll, POLL_MS); // still queued, or this one answer got lost: ask again
          }
        });
      };
      pollTimer = setTimeout(poll, POLL_MS);
    });
  }

  pills.forEach((p, i) => p.addEventListener("click", () => pick(i, true)));
  pillBox.addEventListener("keydown", (e) => {
    const i = pills.indexOf(root.activeElement);
    if (i < 0) return;
    const n = pills.length;
    const next = {
      ArrowRight: i + 1,
      ArrowDown: i + 1,
      ArrowLeft: i - 1 + n,
      ArrowUp: i - 1 + n,
      Home: 0,
      End: n - 1,
    }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    pick(next % n, true);
  });
  helpSend.addEventListener("click", sendHelp);
  helpCancel.addEventListener("click", closeHelp);
  helpClose.addEventListener("click", closeHelp); // the request is already with the service: closing loses nothing
  helpOk.addEventListener("click", closeHelp);
  helpDialog.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      closeHelp();
    } else if (e.key === "Tab") {
      // focus stays in the card: the topic group (one stop), the text, the visible buttons
      const stops = [...helpDialog.querySelectorAll("button, textarea")].filter(
        (x) => x.tabIndex >= 0 && !x.disabled && !x.closest("[hidden]"),
      );
      e.preventDefault();
      if (stops.length === 0) return;
      const i = stops.indexOf(root.activeElement);
      const next = i < 0 ? 0 : (i + (e.shiftKey ? stops.length - 1 : 1)) % stops.length;
      stops[next].focus();
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
      "mastersos-exit: the page keeps removing the Options handle; no longer reattaching it (on this page use Alt+F4 or reopen the app)",
    );
  }

  /** The page opened or closed a top-layer element: move to where we belong, then go back on top. */
  function raise() {
    if (stopped) return;
    if (!raiseOk()) {
      if (!raiseWarned) {
        console.warn("mastersos-exit: the page keeps toggling top-layer elements; raising the Options handle is deferred");
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
