// The exam extension's manifest (design §4.7, §4.9): the exit button stays as it was, the mock env only reaches NWEA's
// hosts, and the background's reload list matches those hosts.
import M from "../manifest.json";
import BG from "../background.js?raw";

const NWEA = ["https://*.nwea.org/*", "https://*.mapnwea.org/*"];

describe("manifest", () => {
  it("version is 1.2.0", () => {
    expect(M.version).toBe("1.2.0");
    expect(M.manifest_version).toBe(3);
    expect(M.minimum_chrome_version).toBe("120");
    expect(M.permissions).toEqual(["nativeMessaging"]);
    expect(M.host_permissions).toEqual(NWEA);
  });

  it("exit button content script is unchanged", () => {
    expect(M.content_scripts[0]).toEqual({
      matches: ["<all_urls>"],
      js: ["content.js"],
      run_at: "document_idle",
      all_frames: false,
    });
  });

  it("NWEA mock env scripts", () => {
    const nwea = M.content_scripts.filter((c) => JSON.stringify(c.matches) === JSON.stringify(NWEA));
    expect(nwea).toEqual([
      { matches: NWEA, js: ["mock/nwea/page.js"], run_at: "document_start", world: "MAIN", all_frames: false },
      { matches: NWEA, js: ["mock/nwea/relay.js"], run_at: "document_start", all_frames: false },
    ]);
    expect(M.content_scripts).toHaveLength(3);
    expect(M.content_scripts.filter((c) => c.world === "MAIN")).toHaveLength(1);
  });

  it("no request header rules", () => {
    // Chrome rejects a DNR "append" to User-Agent (unpacked: the extension fails to load; packed: the rule is dropped),
    // so NWEA's own rule never reaches the request on ChromeOS either — only navigator.userAgent carries the suffix.
    expect(M.declarative_net_request).toBeUndefined();
  });

  it("background tab patterns match the content script hosts", () => {
    const m = /const MOCK_TAB_PATTERNS = (\[[^\]]*\]);/.exec(BG);
    expect(m).not.toBeNull();
    expect(JSON.parse(m[1])).toEqual(NWEA);
  });
});
