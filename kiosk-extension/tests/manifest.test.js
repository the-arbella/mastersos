// The exam extension's manifest (design §4.7, §4.9; docs/specs/2026-11-06-kiosk-platform-inject-design.md §3.1): it is in
// every web kiosk session, so it has 1.2.0's permissions (nativeMessaging, NWEA's hosts) plus storage for its managed
// configuration; scripting, declarativeNetRequest, tabs and <all_urls> are only in the platform extension of the apps
// that use platform or inject. The deprecated NWEA mock env only reaches NWEA's hosts.
import M from "../manifest.json";
import SCHEMA from "../schema.json";
import BG from "../background.js?raw";

const NWEA = ["https://*.nwea.org/*", "https://*.mapnwea.org/*"];
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

describe("manifest", () => {
  it("version 1.5.0, with 1.2.0's permissions and storage", () => {
    expect(M.version).toBe("1.5.0");
    expect(M.manifest_version).toBe(3);
    expect(M.minimum_chrome_version).toBe("120");
    expect(M.permissions).toEqual(["nativeMessaging", "storage"]);
    expect(M.host_permissions).toEqual(NWEA);
    expect(M.optional_permissions).toBeUndefined();
    expect(M.optional_host_permissions).toBeUndefined();
    expect(JSON.stringify(M)).not.toMatch(/scripting|declarativeNetRequest|"tabs"/);
  });

  it("managed storage holds the platform extension's id and nothing else", () => {
    expect(M.storage).toEqual({ managed_schema: "schema.json" });
    expect(SCHEMA.type).toBe("object");
    expect(Object.keys(SCHEMA.properties)).toEqual(["platform_extension"]);
    expect(SCHEMA.properties.platform_extension.type).toBe("string");
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

  it("nothing reachable from web pages, no request header rules", () => {
    expect(M.web_accessible_resources).toBeUndefined();
    expect(M.externally_connectable).toBeUndefined();
    expect(M.declarative_net_request).toBeUndefined();
  });

  it("background tab patterns match the content script hosts", () => {
    const m = /const MOCK_TAB_PATTERNS = (\[[^\]]*\]);/.exec(BG);
    expect(m).not.toBeNull();
    expect(JSON.parse(m[1].replace(/,\s*\]$/, "]"))).toEqual(NWEA);
  });
});
