// 考试扩展内容脚本的测试（计划 9 Task 7）。由 mastersos-server/web 的 vitest 跑（jsdom、globals），
// 不另起 package：`cd core/mastersos-server/web && pnpm exec vitest run kiosk-extension`。
// 内容脚本是普通脚本（不是 ES 模块），这里读出源码、把 chrome 当参数传进去执行，与 Chrome 注入时一样只跑一次。
// jsdom 没有 Popover API、:modal 与顶层：「顶层」一组测试用桩模拟它们，只核对调用的顺序与宿主挂在哪里；
// 真的画在页面的模态对话框、popover、全屏之上（并且点得到）要在 VM 上验（见 ../README.md）。
// ?raw：vite 把源码当字符串给出（不当模块执行）。
import SRC from "../content.js?raw";

const KEY = "mastersos-exit-corner";
const tick = () => new Promise((r) => setTimeout(r, 0));

// 每次注入留下的观察者与 document 上的监听：测试之间拆掉，免得上一个实例把它的宿主挂回来
const cleanups = [];

/** 跑一次内容脚本；返回挂上的宿主元素、偷看到的 closed shadow root 与 chrome 桩。 */
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

/** jsdom 没有的 Popover API 与 :popover-open / :modal 的桩。 */
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

const exitButton = (root) => root.querySelector("button.exit");
const dialog = (root) => root.querySelector("[role=dialog]");
const overlay = (root) => root.querySelector(".overlay");

beforeEach(() => {
  document.documentElement.querySelectorAll("mastersos-exit").forEach((e) => e.remove());
  document.head.innerHTML = "";
  document.body.innerHTML = "<p>考试页面</p>";
  sessionStorage.clear();
});

describe("退出按钮", () => {
  it("挂在 documentElement 上，closed shadow root 里有「退出 / Exit」", () => {
    const { host, root } = inject();
    expect(host).not.toBeNull();
    expect(host.parentNode).toBe(document.documentElement);
    expect(root).not.toBeNull();
    expect(root.mode).toBe("closed");
    expect(exitButton(root).textContent).toBe("退出 / Exit");
    // 缺省在右下角
    expect(exitButton(root).dataset.corner).toBe("br");
  });

  it("页面里的脚本拿不到 shadow root，也找不到按钮", () => {
    const { host } = inject();
    expect(host.shadowRoot).toBeNull();
    expect(document.querySelector("button")).toBeNull();
    expect(document.body.contains(host)).toBe(false);
  });

  it("页面样式 button { display:none } 与针对宿主的样式都不影响它", () => {
    const style = document.createElement("style");
    style.textContent =
      "button { display: none !important; } mastersos-exit { display: none !important; visibility: hidden !important; }";
    document.head.append(style);
    const { host, root } = inject();
    expect(getComputedStyle(host).display).not.toBe("none");
    expect(getComputedStyle(host).visibility).not.toBe("hidden");
    // shadow root 外的样式表不进 shadow 树（浏览器保证）：按钮自己的样式只来自 shadow root 里的 <style>。
    // jsdom 的 getComputedStyle 会把文档的样式表错误地套到 shadow 树里的元素上（实测 display 也是 none），
    // 所以这里不看按钮的计算样式，只核对它在 shadow 树里、样式在 shadow root 里。
    const btn = exitButton(root);
    expect(btn.isConnected).toBe(true);
    expect(btn.getRootNode()).toBe(root);
    expect(document.querySelectorAll("button")).toHaveLength(0);
    expect(root.querySelector("style").textContent).toContain(".exit");
    expect(btn.hasAttribute("hidden")).toBe(false);
  });

  it("被页面移走之后自己挂回去", async () => {
    const { host } = inject();
    host.remove();
    await tick();
    expect(host.parentNode).toBe(document.documentElement);
  });

  it("页面一再移走：10 次之内挂回，之后不再挂回、记一条警告（不与页面无限拉锯）", async () => {
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
    // 停了就是停了：之后页面再动 <html> 也不挂回
    document.documentElement.append(document.createElement("div"));
    await tick();
    expect(host.isConnected).toBe(false);
  });

  it("没有 Popover API：页面后来挂在 <html> 末尾的元素压不住它（宿主挪到最后）", async () => {
    const { host } = inject();
    expect(host.hasAttribute("popover")).toBe(false);
    const cover = document.createElement("div");
    document.documentElement.append(cover);
    await tick();
    expect(document.documentElement.lastElementChild).toBe(host);
  });

  it("触屏：拖完没有补 click，下一次点照样出确认", async () => {
    const { root } = inject();
    const btn = exitButton(root);
    const ev = (type, x, y) =>
      btn.dispatchEvent(new MouseEvent(type, { bubbles: true, composed: true, clientX: x, clientY: y, button: 0 }));
    ev("pointerdown", 1000, 700);
    ev("pointermove", 20, 20);
    ev("pointerup", 20, 20);
    await tick();
    btn.click();
    expect(overlay(root).hidden).toBe(false);
  });

  it("拖到一半 pointercancel：位置不变，下一次点照样出确认", () => {
    const { root } = inject();
    const btn = exitButton(root);
    const ev = (type, x, y) =>
      btn.dispatchEvent(new MouseEvent(type, { bubbles: true, composed: true, clientX: x, clientY: y, button: 0 }));
    ev("pointerdown", 1000, 700);
    ev("pointermove", 20, 20);
    ev("pointercancel", 20, 20);
    expect(btn.dataset.corner).toBe("br");
    btn.click();
    expect(overlay(root).hidden).toBe(false);
  });

  it("位置取自 sessionStorage 里记下的角", () => {
    sessionStorage.setItem(KEY, "tl");
    const { root } = inject();
    expect(exitButton(root).dataset.corner).toBe("tl");
  });

  it("记下的值不认得就回右下角", () => {
    sessionStorage.setItem(KEY, "middle");
    const { root } = inject();
    expect(exitButton(root).dataset.corner).toBe("br");
  });

  it("拖到左上角松手：吸附到那个角、记进 sessionStorage，不弹确认", () => {
    const { root, sendMessage } = inject();
    const btn = exitButton(root);
    const ev = (type, x, y) =>
      btn.dispatchEvent(new MouseEvent(type, { bubbles: true, composed: true, clientX: x, clientY: y, button: 0 }));
    ev("pointerdown", 1000, 700);
    ev("pointermove", 500, 400);
    ev("pointermove", 20, 20);
    ev("pointerup", 20, 20);
    btn.click(); // 拖完之后浏览器还会补一个 click：不算点按钮
    expect(btn.dataset.corner).toBe("tl");
    expect(sessionStorage.getItem(KEY)).toBe("tl");
    expect(overlay(root).hidden).toBe(true);
    expect(sendMessage).not.toHaveBeenCalled();
  });
});

describe("确认对话框", () => {
  it("点按钮先出确认，文字中英双语", () => {
    const { root, sendMessage } = inject();
    expect(overlay(root).hidden).toBe(true);
    exitButton(root).click();
    expect(overlay(root).hidden).toBe(false);
    expect(dialog(root).textContent).toContain("确定离开吗？离开后要重新进入。");
    expect(dialog(root).textContent).toContain("Leave this app? You will need to open it again.");
    expect(dialog(root).getAttribute("aria-modal")).toBe("true");
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("取消：关掉对话框，不发消息", () => {
    const { root, sendMessage } = inject();
    exitButton(root).click();
    root.querySelector("button.cancel").click();
    expect(overlay(root).hidden).toBe(true);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("Esc 也是取消", () => {
    const { root, sendMessage } = inject();
    exitButton(root).click();
    dialog(root).dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, composed: true }));
    expect(overlay(root).hidden).toBe(true);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("确认：发 {cmd:\"exit\"}，回 ok:true 就显示正在退出", () => {
    const { root, sendMessage } = inject({ ok: true });
    exitButton(root).click();
    root.querySelector("button.confirm").click();
    expect(sendMessage).toHaveBeenCalledTimes(1);
    expect(sendMessage.mock.calls[0][0]).toEqual({ cmd: "exit" });
    expect(root.querySelector(".status").textContent).toContain("正在退出");
    expect(root.querySelector("button.confirm").disabled).toBe(true);
  });

  it("回 ok:true 之后 20 秒会话还在：当没退成，显示找老师、按钮可以再点", () => {
    vi.useFakeTimers();
    const { root } = inject({ ok: true });
    exitButton(root).click();
    root.querySelector("button.confirm").click();
    vi.advanceTimersByTime(19999);
    expect(root.querySelector(".status").textContent).toContain("正在退出");
    vi.advanceTimersByTime(1);
    expect(root.querySelector(".status").textContent).toContain("Please ask a teacher");
    expect(root.querySelector("button.confirm").disabled).toBe(false);
  });

  it("回 ok:false：显示找老师，按钮可以再点", () => {
    const { root } = inject({ ok: false });
    exitButton(root).click();
    root.querySelector("button.confirm").click();
    expect(root.querySelector(".status").textContent).toContain("Please ask a teacher");
    expect(root.querySelector("button.confirm").disabled).toBe(false);
  });

  it("没有回答（后台出错、lastError）也按失败处理", () => {
    const { root, chrome } = inject((cb) => {
      chrome.runtime.lastError = { message: "Could not establish connection" };
      cb(undefined);
      chrome.runtime.lastError = undefined;
    });
    exitButton(root).click();
    root.querySelector("button.confirm").click();
    expect(root.querySelector(".status").textContent).toContain("请举手找老师");
  });

  it("对话框里的点击与按键不冒泡到页面", () => {
    const seen = [];
    const onPage = (e) => seen.push(e.type);
    document.addEventListener("click", onPage);
    document.addEventListener("keydown", onPage);
    try {
      const { root } = inject();
      exitButton(root).click();
      root.querySelector("button.cancel").click();
      exitButton(root).click();
      dialog(root).dispatchEvent(new KeyboardEvent("keydown", { key: "Tab", bubbles: true, composed: true }));
      expect(seen).toEqual([]);
      // 页面自己的事件照常到达页面：没有全局监听吞掉它们
      document.body.querySelector("p").click();
      expect(seen).toEqual(["click"]);
    } finally {
      document.removeEventListener("click", onPage);
      document.removeEventListener("keydown", onPage);
    }
  });
});

describe("顶层（页面的模态对话框、popover、全屏、<html> 上的 transform）", () => {
  it("有 Popover API：宿主是 popover=manual，挂上就 showPopover", () => {
    const { open } = stubTopLayer();
    const { host } = inject();
    expect(host.getAttribute("popover")).toBe("manual");
    expect(open.has(host)).toBe(true);
  });

  it("页面开了 popover（toggle 事件）：先 hide 再 show，回到顶层的最上面", async () => {
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

  it("页面 showModal：宿主挪进那个模态对话框（不被 inert）、仍在顶层；关掉后回到 <html>", async () => {
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

  it("全屏切换之后重新提到最上面", () => {
    const { calls } = stubTopLayer();
    inject();
    calls.length = 0;
    document.dispatchEvent(new Event("fullscreenchange"));
    expect(calls.at(-1)).toEqual(["show", "mastersos-exit"]);
  });

  it("页面对宿主 hidePopover：再显示回来", () => {
    const { open } = stubTopLayer();
    const { host } = inject();
    host.hidePopover();
    host.dispatchEvent(new Event("toggle"));
    expect(open.has(host)).toBe(true);
  });

  it("页面每次 toggle 都触发的提升有上限：不与页面无限拉锯", () => {
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

describe("看门狗（每秒一次，只在不对时动 DOM）", () => {
  const flush = () => vi.advanceTimersByTimeAsync(0);

  function modalIn(parent) {
    const dlg = document.createElement("dialog");
    dlg.dataset.modal = "1";
    parent.append(dlg);
    dlg.setAttribute("open", "");
    return dlg;
  }

  it("页面直接 remove() 开着的模态对话框：1 秒内宿主回到 <html> 并显示", async () => {
    vi.useFakeTimers();
    const { open } = stubTopLayer();
    const { host } = inject();
    const dlg = modalIn(document.body);
    await flush();
    expect(host.parentNode).toBe(dlg);
    dlg.remove(); // 没先去掉 open：没有属性变化，<html> 的直接子节点也没变
    await flush();
    expect(host.isConnected).toBe(false);
    await vi.advanceTimersByTimeAsync(1000);
    expect(host.parentNode).toBe(document.documentElement);
    expect(open.has(host)).toBe(true);
  });

  it("页面移走对话框所在的容器：同样 1 秒内回到 <html>", async () => {
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

  it("对话框被移走的挂回不算进页面移走的上限：之后页面移走按钮照样挂回 10 次", async () => {
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
    expect(console.warn).not.toHaveBeenCalledWith(expect.stringContaining("不再挂回"));
  });

  it("安静的页面：每秒的检查不写 DOM、不碰 popover", async () => {
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

  it("M6 停下之后看门狗也停：不再挂回", async () => {
    vi.useFakeTimers();
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const { host } = inject();
    for (let i = 0; i < 11; i++) {
      host.remove();
      await flush();
    }
    expect(host.isConnected).toBe(false);
    await vi.advanceTimersByTimeAsync(5000);
    expect(host.isConnected).toBe(false);
  });

  it("提升超过上限时不丢：窗口结束时补一次（先 hide 再 show）", async () => {
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

  it("<html> 被换掉：宿主挂到新的 <html>，新 <html> 里的 showModal 照样跟进", async () => {
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
