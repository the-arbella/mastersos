// The exam extension's manifest (design §4.7, §4.9; docs/specs/2026-11-06-kiosk-platform-inject-design.md): the exit
// button stays as it was, the deprecated NWEA mock env only reaches NWEA's hosts, there is no vendor-specific mock env
// any more, and the start page needs scripting, DNR and tabs.
import M from "../manifest.json";
import BG from "../background.js?raw";

const NWEA = ["https://*.nwea.org/*", "https://*.mapnwea.org/*"];
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

describe("manifest", () => {
  it("version is 1.4.0", () => {
    expect(M.version).toBe("1.4.0");
    expect(M.manifest_version).toBe(3);
    expect(M.minimum_chrome_version).toBe("120");
    expect(M.permissions).toEqual(["nativeMessaging", "scripting", "declarativeNetRequest", "tabs"]);
    expect(M.host_permissions).toEqual(["<all_urls>"]);
  });

  it("exit button content script is unchanged", () => {
    expect(M.content_scripts[0]).toEqual({
      matches: ["<all_urls>"],
      js: ["content.js"],
      run_at: "document_idle",
      all_frames: false,
    });
  });

  it("NWEA mock env scripts (deprecated) and nothing vendor-specific beside them", () => {
    const nwea = M.content_scripts.filter((c) => same(c.matches, NWEA));
    expect(nwea).toEqual([
      { matches: NWEA, js: ["mock/nwea/page.js"], run_at: "document_start", world: "MAIN", all_frames: false },
      { matches: NWEA, js: ["mock/nwea/relay.js"], run_at: "document_start", all_frames: false },
    ]);
    expect(M.content_scripts).toHaveLength(3);
    expect(JSON.stringify(M)).not.toMatch(/testnav/i);
  });

  it("the start page and the platform script are not reachable from web pages", () => {
    expect(M.web_accessible_resources).toBeUndefined();
    expect(M.externally_connectable).toBeUndefined();
  });

  it("no static request header rules (the platform rule is a session rule)", () => {
    expect(M.declarative_net_request).toBeUndefined();
  });

  it("background tab patterns match the content script hosts", () => {
    const m = /const MOCK_TAB_PATTERNS = (\[[^\]]*\]);/.exec(BG);
    expect(m).not.toBeNull();
    expect(JSON.parse(m[1].replace(/,\s*\]$/, "]"))).toEqual(NWEA);
  });
});
