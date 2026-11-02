// MastersOS 考试扩展的内容脚本（计划 9 Task 7，设计 §4.7）：锁定会话里每个页面的右下角有一个「退出 / Exit」按钮，
// 点了先在同一处确认，确认后请后台（background.js）经 native messaging 结束锁定会话。
//
// 不能弄坏考试页面：
//   - 按钮与对话框都在一个 closed shadow root 里（页面的脚本拿不到它，页面的样式表进不去），样式全在里面；
//     宿主元素自己的样式写在 style 属性上并带 !important（行内的 !important 比页面样式表里的 !important 优先）。
//   - 内容脚本跑在扩展的隔离环境里，不往页面的 JS 环境注入任何东西。
//   - 不吞页面的事件：自己元素上的点击与按键不冒泡给页面；document 上只有三个只看不拦的监听（toggle 的捕获、
//     fullscreenchange），用来在页面开了顶层元素之后把按钮重新提到最上面。
//   - 页面把宿主元素移走（换掉 <html> 的子节点）就挂回去；10 秒内最多 10 次，再多就停下、记一条警告，不与页面无限拉锯。
// 顶层：宿主是 popover="manual"，showPopover() 进顶层——页面的 z-index、<html> 上的 transform / filter / contain
// 都管不到它。页面之后开的模态对话框、popover、全屏元素会排在它上面，所以页面一开（toggle 事件、对话框的 open 属性、
// fullscreenchange）就先 hide 再 show，重新排到最上面；页面开着模态对话框时，<html> 下的一切都是 inert（点不到），
// 宿主就挪进那个对话框里（对话框的子孙不 inert），对话框关了再挪回 <html>。提升 10 秒内最多 30 次。
// 提升超过上限时不丢，窗口结束时补一次。每秒一次的看门狗兜底：页面直接移走开着的模态对话框、换掉 <html> 时把按钮放回该在的地方。
// 没有 Popover API（旧版 Chrome）时退回到最大的 z-index，并保持是 <html> 的最后一个子元素。
// 按钮可以拖到四角之一，位置记在页面的 sessionStorage（同一标签页里换页还在那个角）。
(function mastersosExamExit() {
  "use strict";

  const KEY = "mastersos-exit-corner";
  const CORNERS = ["br", "bl", "tr", "tl"];
  const DRAG_PX = 6; // 移动超过这么多才算拖，不算点
  const EXIT_TIMEOUT_MS = 20000; // 回了「已请求」之后这么久会话还在，就当没退成

  const TEXT = {
    button: "退出 / Exit",
    zh: "确定离开吗？离开后要重新进入。",
    en: "Leave this app? You will need to open it again.",
    cancel: "取消 / Cancel",
    confirm: "离开 / Leave",
    exiting: "正在退出… / Exiting…",
    failed: "没能退出，请举手找老师。/ Could not leave. Please ask a teacher.",
  };

  const STYLE = `
:host { all: initial; }
.exit {
  position: fixed; z-index: 2147483647; margin: 0; padding: 8px 16px;
  font: 600 14px/1.2 system-ui, "Noto Sans CJK SC", "Noto Sans Thai", sans-serif;
  color: #fff; background: #b91c1c; border: 2px solid #fff; border-radius: 999px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, .35); cursor: pointer; touch-action: none; user-select: none;
  opacity: .92; min-width: 0; min-height: 0; width: auto; height: auto; display: block; visibility: visible;
}
.exit:hover, .exit:focus-visible { opacity: 1; }
.exit:focus-visible { outline: 3px solid #fbbf24; outline-offset: 2px; }
.exit.dragging { cursor: grabbing; }
.exit[data-corner="br"] { right: 16px; bottom: 16px; }
.exit[data-corner="bl"] { left: 16px; bottom: 16px; }
.exit[data-corner="tr"] { right: 16px; top: 16px; }
.exit[data-corner="tl"] { left: 16px; top: 16px; }
.overlay {
  position: fixed; inset: 0; z-index: 2147483647; display: flex; align-items: center; justify-content: center;
  background: rgba(0, 0, 0, .55); visibility: visible;
}
.overlay[hidden] { display: none; }
.dialog {
  box-sizing: border-box; max-width: min(28rem, calc(100vw - 32px)); margin: 16px; padding: 20px 24px;
  background: #fff; color: #111; border-radius: 12px; box-shadow: 0 8px 32px rgba(0, 0, 0, .4);
  font: 16px/1.5 system-ui, "Noto Sans CJK SC", "Noto Sans Thai", sans-serif; text-align: left;
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
      return "br"; // 沙箱页面、关了存储：照样显示，只是不记位置
    }
  }
  function saveCorner(c) {
    try {
      sessionStorage.setItem(KEY, c);
    } catch {
      // 记不下就算了
    }
  }

  // 宿主：自定义元素名（不撞页面的 button / div 选择器），行内 !important 压住页面针对它的样式
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

  const btn = doc.createElement("button");
  btn.type = "button";
  btn.className = "exit";
  btn.textContent = TEXT.button;
  btn.dataset.corner = readCorner();

  const overlay = doc.createElement("div");
  overlay.className = "overlay";
  overlay.hidden = true;
  const dialog = doc.createElement("div");
  dialog.className = "dialog";
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-labelledby", "mastersos-exit-q");
  const q = doc.createElement("div");
  q.id = "mastersos-exit-q";
  const zh = doc.createElement("p");
  zh.textContent = TEXT.zh;
  const en = doc.createElement("p");
  en.lang = "en";
  en.textContent = TEXT.en;
  q.append(zh, en);
  const status = doc.createElement("div");
  status.className = "status";
  status.setAttribute("role", "status");
  const actions = doc.createElement("div");
  actions.className = "actions";
  const cancel = doc.createElement("button");
  cancel.type = "button";
  cancel.className = "cancel";
  cancel.textContent = TEXT.cancel;
  const confirm = doc.createElement("button");
  confirm.type = "button";
  confirm.className = "confirm";
  confirm.textContent = TEXT.confirm;
  actions.append(cancel, confirm);
  dialog.append(q, status, actions);
  overlay.append(dialog);
  root.append(style, btn, overlay);

  // 自己元素上的事件到 shadow root 为止，不让页面的处理函数看到（只拦我们自己的，不碰页面的事件）
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

  // ---- 拖到四角 -------------------------------------------------------------
  let drag = null; // {x, y, id, moved}
  let swallowClick = false;

  btn.addEventListener("pointerdown", (e) => {
    swallowClick = false; // 新的一次按下：上一次拖完没等到的 click 不再等
    if (e.button !== 0) return;
    drag = { x: e.clientX, y: e.clientY, id: e.pointerId, moved: false };
    try {
      if (e.pointerId !== undefined) btn.setPointerCapture(e.pointerId);
    } catch {
      // 没有指针捕获也能拖，只是指针移出按钮时会断
    }
  });
  btn.addEventListener("pointermove", (e) => {
    if (!drag) return;
    if (!drag.moved && Math.hypot(e.clientX - drag.x, e.clientY - drag.y) < DRAG_PX) return;
    drag.moved = true;
    btn.classList.add("dragging");
    btn.style.right = "auto";
    btn.style.bottom = "auto";
    btn.style.left = `${Math.max(0, e.clientX - btn.offsetWidth / 2)}px`;
    btn.style.top = `${Math.max(0, e.clientY - btn.offsetHeight / 2)}px`;
  });
  function endDrag(e, commit) {
    if (!drag) return;
    const moved = drag.moved;
    drag = null;
    btn.classList.remove("dragging");
    btn.style.removeProperty("left");
    btn.style.removeProperty("top");
    btn.style.removeProperty("right");
    btn.style.removeProperty("bottom");
    if (!moved || !commit) return; // pointercancel 之后浏览器不补 click，不用吞
    // 鼠标拖完，浏览器在同一个任务里补一个 click，吞掉它；触屏拖完常常不补，下一个任务就不再吞
    swallowClick = true;
    setTimeout(() => {
      swallowClick = false;
    }, 0);
    const w = window.innerWidth || doc.documentElement.clientWidth || 0;
    const h = window.innerHeight || doc.documentElement.clientHeight || 0;
    const corner = (e.clientY < h / 2 ? "t" : "b") + (e.clientX < w / 2 ? "l" : "r");
    btn.dataset.corner = corner;
    saveCorner(corner);
  }
  btn.addEventListener("pointerup", (e) => endDrag(e, true));
  btn.addEventListener("pointercancel", (e) => endDrag(e, false));

  // ---- 确认与退出 -----------------------------------------------------------
  let timer = null;

  function setBusy(busy, text) {
    confirm.disabled = busy;
    cancel.disabled = busy;
    status.textContent = text;
  }
  function open() {
    setBusy(false, "");
    overlay.hidden = false;
    cancel.focus();
  }
  function close() {
    if (confirm.disabled) return; // 已经在退出了
    overlay.hidden = true;
    btn.focus();
  }
  function failed() {
    if (timer !== null) clearTimeout(timer);
    timer = null;
    setBusy(false, TEXT.failed);
    confirm.focus();
  }

  btn.addEventListener("click", () => {
    if (swallowClick) {
      swallowClick = false;
      return;
    }
    open();
  });
  cancel.addEventListener("click", close);
  dialog.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      close();
    } else if (e.key === "Tab") {
      // 焦点留在对话框的两个按钮之间
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
          // 已请求：会话随即结束。过了这么久还在，就当没退成
          timer = setTimeout(failed, EXIT_TIMEOUT_MS);
        } else {
          failed();
        }
      });
    } catch {
      failed(); // 扩展被重载之后旧页面里的 chrome.runtime 不能用了
    }
  });

  // ---- 挂上、留在最上面、被移走就挂回去 --------------------------------------
  /** 每 ms 毫秒的窗口里最多放行 max 次；`left()` 是当前窗口还剩多少毫秒。 */
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
  let trailing = null; // 超过提升上限时，窗口结束补的那一次
  let parentObs = null;
  let openObs = null;
  let watchdog = null;
  let boundRoot = null; // openObs 盯着的 <html>

  /** 页面开着的模态对话框（文档里最后一个）：开着时 <html> 下的其余部分都是 inert。 */
  function topModal() {
    let found = null;
    for (const d of doc.querySelectorAll("dialog[open]")) {
      try {
        if (d.matches(":modal")) found = d;
      } catch {
        // 不认得 :modal 的浏览器也没有顶层
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
      if (isShown()) host.hidePopover(); // 先 hide 再 show：排到顶层的最上面
      host.showPopover();
    } catch {
      // 退回到 z-index
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
    console.warn("mastersos-exit: 页面一再移走退出按钮，不再挂回（这一页里用 Alt+F4 或重新打开应用）");
  }

  /** 页面开关了顶层元素：挪到该在的地方，再排到最上面。 */
  function raise() {
    if (stopped) return;
    if (!raiseOk()) {
      if (!raiseWarned) console.warn("mastersos-exit: 页面频繁开关顶层元素，提升退出按钮推迟到这一阵之后");
      raiseWarned = true;
      // 不丢：窗口结束时补一次（只排一个）
      if (trailing === null) {
        trailing = setTimeout(() => {
          trailing = null;
          raise();
        }, raiseOk.left()); // 早到了一点也不要紧：仍被拒就再排一次
      }
      return;
    }
    raiseWarned = false;
    const parent = wantedParent();
    if (parent && misplaced(parent)) put(parent);
    show();
  }
  /** 宿主所在的父元素的子节点变了：被移走就挂回（有上限），没有 Popover API 时保持在最后。 */
  function onChildList() {
    if (stopped) return;
    const parent = wantedParent();
    if (!parent) return;
    if (host.parentNode === parent) {
      if (misplaced(parent)) raise(); // 没有 Popover API：页面在后面又挂了东西
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
  /** <html> 换了：open 属性的观察者跟到新的 <html>。 */
  function bindRoot() {
    const el = doc.documentElement;
    if (!openObs || !el || el === boundRoot) return;
    boundRoot = el;
    openObs.disconnect();
    openObs.observe(el, { subtree: true, attributes: true, attributeFilter: ["open"] });
  }
  /**
   * 看门狗，每秒一次：页面直接移走开着的模态对话框（或它的容器）时没有属性变化，宿主跟着离开文档而观察者看不到；
   * <html> 被换掉时 openObs 还盯着旧的。每次只做便宜的检查（一次 dialog[open] 查询、比较父节点、:popover-open），
   * 不对时才动 DOM。这里的挂回不算进页面移走的上限（M6），它本身就限在每秒最多一次。M6 停下之后它也停。
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
  put(wantedParent()); // 注入时页面可能已开着模态对话框
  show();
  parentObs = new MutationObserver(onChildList);
  parentObs.observe(host.parentNode, { childList: true });
  if (host.parentNode !== doc.documentElement) parentObs.observe(doc.documentElement, { childList: true });
  observers.push(parentObs);
  // <html> 被换掉
  const docObs = new MutationObserver(() => {
    bindRoot();
    onChildList();
  });
  docObs.observe(doc, { childList: true });
  observers.push(docObs);
  // showModal / close 改 open 属性（较旧的 Chrome 对话框不发 toggle）
  openObs = new MutationObserver(raise);
  bindRoot();
  observers.push(openObs);
  watchdog = setInterval(check, 1000);
  // 只看不拦：不 stopPropagation、不 preventDefault
  doc.addEventListener("toggle", onPageToggle, true);
  doc.addEventListener("fullscreenchange", raise);
  // 页面对宿主 hidePopover：再显示回来
  host.addEventListener("toggle", () => {
    if (hasPopover && !isShown()) raise();
  });
})();
