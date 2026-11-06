// The exam extension's manifest (design §4.7, §4.9): the exit button stays as it was, each mock env only reaches its
// app's hosts, and the background's reload list matches those hosts.
import M from "../manifest.json";
import BG from "../background.js?raw";

const NWEA = ["https://*.nwea.org/*", "https://*.mapnwea.org/*"];
const TESTNAV = ["https://*.testnav.com/*", "https://*.adamexam.com/*", "https://*.act.org/*", "https://*.actaspire.org/*"];
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

describe("manifest", () => {
  it("version is 1.3.0", () => {
    expect(M.version).toBe("1.3.0");
    expect(M.manifest_version).toBe(3);
    expect(M.minimum_chrome_version).toBe("120");
    expect(M.permissions).toEqual(["nativeMessaging"]);
    expect(M.host_permissions).toEqual([...NWEA, ...TESTNAV]);
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
    const nwea = M.content_scripts.filter((c) => same(c.matches, NWEA));
    expect(nwea).toEqual([
      { matches: NWEA, js: ["mock/nwea/page.js"], run_at: "document_start", world: "MAIN", all_frames: false },
      { matches: NWEA, js: ["mock/nwea/relay.js"], run_at: "document_start", all_frames: false },
    ]);
    expect(M.content_scripts).toHaveLength(5);
    expect(M.content_scripts.filter((c) => c.world === "MAIN")).toHaveLength(2);
  });

  it("TestNav mock env scripts", () => {
    const tn = M.content_scripts.filter((c) => same(c.matches, TESTNAV));
    expect(tn).toEqual([
      { matches: TESTNAV, js: ["mock/testnav/page.js"], run_at: "document_start", world: "MAIN", all_frames: false },
      { matches: TESTNAV, js: ["mock/testnav/relay.js"], run_at: "document_start", all_frames: false },
    ]);
  });

  it("no extra permissions for TestNav", () => {
    // The mock env needs no chrome.* API of its own: it answers the page in the page's world.
    expect(M.permissions).toEqual(["nativeMessaging"]);
    expect(M.externally_connectable).toBeUndefined();
  });

  it("no request header rules", () => {
    // Chrome rejects a DNR "append" to User-Agent (unpacked: the extension fails to load; packed: the rule is dropped),
    // so NWEA's own rule never reaches the request on ChromeOS either — only navigator.userAgent carries the suffix.
    expect(M.declarative_net_request).toBeUndefined();
  });

  it("background tab patterns match the content script hosts", () => {
    const m = /const MOCK_TAB_PATTERNS = (\[[^\]]*\]);/.exec(BG);
    expect(m).not.toBeNull();
    expect(JSON.parse(m[1].replace(/,\s*\]$/, "]"))).toEqual([...NWEA, ...TESTNAV]);
  });
});
