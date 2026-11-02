// Tests for the NWEA mock env's isolated-world relay (design §4.9): page.js's exit request becomes the background's
// {cmd:"exit"}; any other message is ignored. Runs in vitest's jsdom window (origin http://localhost:3000).
// ?raw: vite hands over the source as a string, the script runs once with a stub chrome, as Chrome injects it.
import SRC from "../mock/nwea/relay.js?raw";

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

describe("NWEA mock env: relay.js", () => {
  it("relays the exit message", () => {
    const { sendMessage } = load();
    post({ type: "MASTERSOS_MOCK_EXIT" });
    expect(sendMessage).toHaveBeenCalledTimes(1);
    expect(sendMessage.mock.calls[0][0]).toEqual({ cmd: "exit" });
  });

  it("relay ignores foreign messages", () => {
    const { sendMessage } = load();
    const frame = document.createElement("iframe");
    document.body.appendChild(frame);
    post({ type: "MASTERSOS_MOCK_EXIT" }, { source: frame.contentWindow });
    post({ type: "MASTERSOS_MOCK_EXIT" }, { source: null });
    post({ type: "MASTERSOS_MOCK_EXIT" }, { origin: "https://evil.example" });
    for (const d of [
      { type: "MASTERSOS_MOCK_EXIT", x: 1 },
      { type: "MASTERSOS_MOCK_EXITX" },
      "MASTERSOS_MOCK_EXIT",
      ["MASTERSOS_MOCK_EXIT"],
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
