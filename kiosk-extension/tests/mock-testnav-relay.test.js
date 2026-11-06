// Tests for the TestNav mock env's isolated-world relay: page.js's closeApp becomes the background's {cmd:"exit"};
// any other message is ignored. Runs in vitest's jsdom window (origin http://localhost:3000).
// ?raw: vite hands over the source as a string, the script runs once with a stub chrome, as Chrome injects it.
import SRC from "../mock/testnav/relay.js?raw";

const added = [];

function load({ throws = false } = {}) {
  const sendMessage = vi.fn(() => {
    if (throws) throw new Error("Extension context invalidated.");
  });
  const chrome = { runtime: { sendMessage, lastError: undefined } };
  const real = window.addEventListener.bind(window);
  const spy = vi.spyOn(window, "addEventListener").mockImplementation((type, fn, opts) => {
    added.push([type, fn, opts]);
    real(type, fn, opts);
  });
  try {
    new Function("chrome", SRC)(chrome);
  } finally {
    spy.mockRestore();
  }
  return { sendMessage };
}

function post(data, { origin = window.location.origin, source = window } = {}) {
  window.dispatchEvent(new MessageEvent("message", { data, origin, source }));
}

afterEach(() => {
  for (const [type, fn, opts] of added.splice(0)) window.removeEventListener(type, fn, opts);
  document.body.innerHTML = "";
});

describe("TestNav mock env: relay.js", () => {
  it("relays the exit message", () => {
    const { sendMessage } = load();
    post({ type: "MASTERSOS_MOCK_EXIT" });
    expect(sendMessage).toHaveBeenCalledTimes(1);
    expect(sendMessage.mock.calls[0][0]).toEqual({ cmd: "exit" });
  });

  it("ignores TestNav's own window messages and foreign ones", () => {
    const { sendMessage } = load();
    const frame = document.createElement("iframe");
    document.body.appendChild(frame);
    post({ type: "MASTERSOS_MOCK_EXIT" }, { source: frame.contentWindow });
    post({ type: "MASTERSOS_MOCK_EXIT" }, { origin: "https://evil.example" });
    for (const d of [
      // TestNav extension's messenger.js events and the App API's own messages
      { name: "com.pearson.testnav.app.AudioLevelChanged", data: { level: 0 } },
      { name: "com.pearson.testnav.request.getUserAgent" },
      { type: "MASTERSOS_MOCK_EXIT", name: "x" },
      "MASTERSOS_MOCK_EXIT",
      null,
      {},
    ])
      post(d);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("survives a missing runtime", () => {
    load({ throws: true });
    expect(() => post({ type: "MASTERSOS_MOCK_EXIT" })).not.toThrow();
  });
});
