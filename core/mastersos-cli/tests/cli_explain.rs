//! `mastersos explain user`, `mastersos explain device` and `mastersos migrate`: offline
//! commands on the local settings directory (user layer design §6).

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use mastersos_bundle::testutil::{defaults_example, legacy_spec_example, spec_example_v3};
use mastersos_cli::workdir::{Meta, Workdir};
use serde_json::{json, Value};

const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const SCHOOL: &str = "0193a0c2-0000-7000-8000-0000000000aa";

/// A temporary home folder and a settings directory in it holding `text`, nothing published.
fn settings(text: &str) -> (tempfile::TempDir, PathBuf) {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("settings");
    let meta = Meta {
        server: "https://example.invalid/org/alpha/devices".into(),
        school_id: SCHOOL.into(),
        base_version: 0,
    };
    Workdir::init(&dir, meta, text).unwrap();
    (home, dir)
}

fn mastersos(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mastersos"))
        .args(args)
        .env("HOME", home)
        .env("APPDATA", home)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn text(o: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// The 1-based line of the `nth` (0-based) `[[assign]]` header in `text`.
fn assign_line(text: &str, nth: usize) -> usize {
    text.lines()
        .enumerate()
        .filter(|(_, l)| l.trim() == "[[assign]]")
        .nth(nth)
        .map(|(i, _)| i + 1)
        .unwrap()
}

/// The spec example with `mastersos_claims = true`: Devices receive issuer facts.
fn v3_with_claims() -> String {
    let text = spec_example_v3();
    let out = text.replacen(
        "client_id = \"mastersos\" }",
        "client_id = \"mastersos\", mastersos_claims = true }",
        1,
    );
    assert_ne!(out, text);
    out
}

/// The spec example plus Group `lab` (Device ABC123 is in it) and a Flatpak and a .deb app in
/// user config `teacher`.
fn v3_with_lab() -> String {
    spec_example_v3()
        .replacen(
            "config = \"classroom\"\n",
            "config = \"classroom\"\n\n[[group]]\nid = \"lab\"\nname = \"Lab\"\nconfig = \"classroom\"\n\n\
             [[device]]\nserial = \"ABC123\"\ngroup = \"lab\"\n",
            1,
        )
        .replacen(
            "drop.chrome_policy = [\"URLBlocklist\"]\n",
            "drop.chrome_policy = [\"URLBlocklist\"]\napps.flatpak = [\"org.gimp.GIMP\"]\n\
             apps.deb.zoom = { name = \"Zoom\", url = \"https://example.com/zoom.deb\" }\n",
            1,
        )
}

/// A format 2 text that checks clean: two Configs, two Groups.
fn clean_v2() -> String {
    format!(
        r#"format = 2
version = 1

# The school's keys.
[[trust]]
id = "school-2026"
alg = "ed25519"
public_key = "{KEY}"

[school]
id = "{SCHOOL}"

[defaults]
interface = "learning"
login_methods = ["guest"]
apps.flatpak = ["org.libreoffice.LibreOffice"]

[[config]]
id = "teacher"
name = "Teacher"
# Teachers get the full desktop.
interface = "full"
apps.flatpak = ["org.gimp.GIMP"]

[[config]]
id = "student"
name = "Student"

[[group]]
id = "staff"
name = "Staff"
config = "teacher"

[[group]]
id = "default"
name = "Ungrouped"
config = "student"
"#
    )
}

#[test]
fn explain_user_prints_rule_and_line() {
    let manifest = v3_with_claims();
    let (home, dir) = settings(&manifest);
    let d = dir.to_str().unwrap();
    let o = mastersos(
        home.path(),
        &[
            "explain",
            "user",
            "--dir",
            d,
            "--kind",
            "sso",
            "--class-role",
            "teacher",
        ],
    );
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let n = assign_line(&manifest, 1);
    assert_eq!(
        out.trim(),
        format!("group default: teacher (rule assign[1], manifest.toml:{n})"),
        "{err}"
    );
}

#[test]
fn explain_user_json_shape() {
    let manifest = spec_example_v3();
    let (home, dir) = settings(&manifest);
    let d = dir.to_str().unwrap();
    let o = mastersos(
        home.path(),
        &[
            "--json", "explain", "user", "--dir", d, "--kind", "local", "--admin",
        ],
    );
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        v,
        json!([{
            "group": "default",
            "user_config": "teacher",
            "rule": 0,
            "line": assign_line(&manifest, 0),
        }])
    );
    // No rule matches a student without facts: the fallback, no rule, no line.
    let o = mastersos(
        home.path(),
        &[
            "--json",
            "explain",
            "user",
            "--dir",
            d,
            "--kind",
            "sso",
            "--device-group",
            "default",
        ],
    );
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        v,
        json!([{ "group": "default", "user_config": "primary", "rule": null, "line": null }])
    );
}

#[test]
fn explain_user_org_node_and_class_facts() {
    let manifest = v3_with_claims();
    let (home, dir) = settings(&manifest);
    let d = dir.to_str().unwrap();
    let o = mastersos(
        home.path(),
        &[
            "explain",
            "user",
            "--dir",
            d,
            "--kind",
            "sso",
            "--org-node",
            "0193a0c2-0000-7000-8000-000000000001",
            "--class",
            "0193a0c2-0000-7000-8000-0000000000c1",
            "--class-role",
            "student",
        ],
    );
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let n = assign_line(&manifest, 2);
    assert_eq!(
        out.trim(),
        format!("group default: primary (rule assign[2], manifest.toml:{n})")
    );
    // Facts count only for sso accounts: a local account falls back.
    let o = mastersos(
        home.path(),
        &[
            "explain",
            "user",
            "--dir",
            d,
            "--kind",
            "local",
            "--class-role",
            "teacher",
        ],
    );
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert_eq!(out.trim(), "group default: primary (fallback)");
}

#[test]
fn explain_user_guest_gets_the_fallback() {
    let (home, dir) = settings(&v3_with_lab());
    let o = mastersos(
        home.path(),
        &[
            "explain",
            "user",
            "--dir",
            dir.to_str().unwrap(),
            "--kind",
            "guest",
        ],
    );
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    // Every Group, in Group order.
    assert_eq!(
        out.trim(),
        "group default: primary (fallback)\ngroup lab: primary (fallback)"
    );
}

#[test]
fn explain_user_guest_is_user_guest_and_never_admin() {
    // A rule for the login name `guest`: a Device signs the guest session in under that name.
    let t = v3_with_lab().replacen(
        "[user]\nfallback",
        "[[assign]]\nuser_config = \"teacher\"\nuser = [\"guest\"]\ndevice_group = [\"lab\"]\n\n[user]\nfallback",
        1,
    );
    let (home, dir) = settings(&t);
    let d = dir.to_str().unwrap();
    let o = mastersos(
        home.path(),
        &["explain", "user", "--dir", d, "--kind", "guest"],
    );
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let l = assign_line(&t, 3);
    assert_eq!(
        out.trim(),
        format!("group default: primary (fallback)\ngroup lab: teacher (rule assign[3], manifest.toml:{l})")
    );
    let o = mastersos(
        home.path(),
        &["explain", "user", "--dir", d, "--kind", "guest", "--admin"],
    );
    let (out, err) = text(&o);
    assert!(!o.status.success(), "{out}{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("--admin") && err.contains("guest"), "{err}");
}

#[test]
fn explain_user_on_format2_uses_the_implied_layer() {
    let (home, dir) = settings(&defaults_example());
    let d = dir.to_str().unwrap();
    let o = mastersos(
        home.path(),
        &["explain", "user", "--dir", d, "--kind", "sso"],
    );
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert_eq!(
        out.trim(),
        "group staff: teacher (implied: format 2)\ngroup default: student (implied: format 2)"
    );
    let o = mastersos(
        home.path(),
        &[
            "--json",
            "explain",
            "user",
            "--dir",
            d,
            "--kind",
            "guest",
            "--device-group",
            "staff",
        ],
    );
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        v,
        json!([{ "group": "staff", "user_config": "teacher", "rule": null, "line": null }])
    );
}

#[test]
fn explain_user_unknown_group_fails() {
    let (home, dir) = settings(&spec_example_v3());
    let o = mastersos(
        home.path(),
        &[
            "explain",
            "user",
            "--dir",
            dir.to_str().unwrap(),
            "--kind",
            "sso",
            "--device-group",
            "nope",
        ],
    );
    let (out, err) = text(&o);
    assert!(!o.status.success(), "{out}{err}");
    assert!(err.contains("\"nope\""), "{err}");
}

#[test]
fn explain_user_without_fallback_prints_the_check_error() {
    let manifest = spec_example_v3().replacen("[user]\nfallback = \"primary\"\n", "", 1);
    assert!(!manifest.contains("fallback ="));
    let (home, dir) = settings(&manifest);
    let o = mastersos(
        home.path(),
        &[
            "explain",
            "user",
            "--dir",
            dir.to_str().unwrap(),
            "--kind",
            "sso",
        ],
    );
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(2), "{out}{err}");
    assert!(out.contains("user_fallback_missing"), "{out}{err}");
    assert!(!err.contains("panicked"), "{err}");
}

#[test]
fn explain_device_lists_install_set() {
    let (home, dir) = settings(&v3_with_lab());
    let d = dir.to_str().unwrap();
    let o = mastersos(
        home.path(),
        &["--json", "explain", "device", "abc123", "--dir", d],
    );
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        v,
        json!({
            "group": "lab",
            "device_config": "classroom",
            "user_configs": ["teacher", "primary"],
            "flatpak": ["org.gimp.GIMP"],
            "deb": ["zoom"],
        })
    );
    let o = mastersos(home.path(), &["explain", "device", "ABC123", "--dir", d]);
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    for want in [
        "group: lab",
        "device config: classroom",
        "user configs: teacher, primary",
        "flatpak: org.gimp.GIMP",
        "deb: zoom",
    ] {
        assert!(out.contains(want), "{want}: {out}");
    }
}

#[test]
fn explain_device_unknown_serial_gets_the_default_group() {
    let (home, dir) = settings(&v3_with_lab());
    let o = mastersos(
        home.path(),
        &[
            "--json",
            "explain",
            "device",
            "NOPE-1",
            "--dir",
            dir.to_str().unwrap(),
        ],
    );
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["group"], "default");
    assert_eq!(v["device_config"], "classroom");
    assert_eq!(v["user_configs"], json!(["teacher", "primary"]));
}

#[test]
fn migrate_writes_format3_and_checks_clean() {
    let (home, dir) = settings(&clean_v2());
    let d = dir.to_str().unwrap();
    let o = mastersos(home.path(), &["check", d]);
    let (out, err) = text(&o);
    assert!(o.status.success(), "the input checks clean: {out}{err}");

    // Default: the text on stdout, manifest.toml untouched.
    let o = mastersos(home.path(), &["migrate", "--dir", d]);
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(out.starts_with("format = 3\n"), "{out}");
    assert!(out.contains("[[user_config]]"), "{out}");
    assert_eq!(
        std::fs::read_to_string(dir.join("manifest.toml")).unwrap(),
        clean_v2()
    );
    assert!(err.contains("0 error(s)"), "{err}");
    assert!(err.contains("lose their comments"), "{err}");
    assert!(err.contains("format_3"), "{err}");
    assert!(err.contains("fallback user config"), "{err}");
    assert!(!err.contains("--allow-reroute"), "{err}");

    let o = mastersos(home.path(), &["migrate", "--dir", d, "--write"]);
    let (out2, err) = text(&o);
    assert!(o.status.success(), "{out2}{err}");
    let written = std::fs::read_to_string(dir.join("manifest.toml")).unwrap();
    assert_eq!(written, out);
    assert!(out2.contains("0 error(s)"), "{out2}");

    let o = mastersos(home.path(), &["check", d]);
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(out.contains("0 error(s)"), "{out}");

    // Migrating again is refused.
    let o = mastersos(home.path(), &["migrate", "--dir", d]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn migrate_legacy_shape_mentions_allow_reroute() {
    // A draft: no `version` line (the server stamps it on publish).
    let draft = legacy_spec_example().replacen("version = 42\n", "", 1);
    assert!(!draft.contains("version ="));
    for manifest in [legacy_spec_example(), draft] {
        let (home, dir) = settings(&manifest);
        let o = mastersos(home.path(), &["migrate", "--dir", dir.to_str().unwrap()]);
        let (out, err) = text(&o);
        assert!(out.starts_with("format = 3\n"), "{out}{err}");
        assert!(err.contains("--allow-reroute"), "{err}");
    }
}

#[test]
fn migrate_refuses_format3() {
    let (home, dir) = settings(&spec_example_v3());
    let o = mastersos(home.path(), &["migrate", "--dir", dir.to_str().unwrap()]);
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(2), "{out}{err}");
    assert!(err.contains("already format 3"), "{err}");
    assert_eq!(
        std::fs::read_to_string(dir.join("manifest.toml")).unwrap(),
        spec_example_v3()
    );
}

#[test]
fn explain_user_ignores_facts_without_mastersos_claims() {
    let (home, dir) = settings(&spec_example_v3());
    let o = mastersos(
        home.path(),
        &[
            "explain",
            "user",
            "--dir",
            dir.to_str().unwrap(),
            "--kind",
            "sso",
            "--class-role",
            "teacher",
        ],
    );
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert_eq!(out.trim(), "group default: primary (fallback)");
    assert!(
        err.contains(
            "fact flags ignored: school.oidc.mastersos_claims is not true, so Devices receive no facts"
        ),
        "{err}"
    );
}

#[test]
fn explain_user_class_without_role_fails() {
    let (home, dir) = settings(&v3_with_claims());
    let d = dir.to_str().unwrap();
    let a = "0193a0c2-0000-7000-8000-0000000000c1";
    let b = "0193a0c2-0000-7000-8000-0000000000c2";
    let c = "0193a0c2-0000-7000-8000-0000000000c3";
    for args in [
        vec!["--class", a],
        vec![
            "--class",
            a,
            "--class",
            b,
            "--class",
            c,
            "--class-role",
            "student",
            "--class-role",
            "teacher",
        ],
    ] {
        let mut all = vec!["explain", "user", "--dir", d, "--kind", "sso"];
        all.extend(args);
        let o = mastersos(home.path(), &all);
        let (out, err) = text(&o);
        assert_eq!(o.status.code(), Some(1), "{out}{err}");
        assert!(err.contains("has no --class-role"), "{err}");
    }
}

#[test]
fn explain_device_on_format2() {
    let (home, dir) = settings(&defaults_example());
    let o = mastersos(
        home.path(),
        &[
            "--json",
            "explain",
            "device",
            "NOPE-1",
            "--dir",
            dir.to_str().unwrap(),
        ],
    );
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        v,
        json!({
            "group": "default",
            "device_config": "student",
            "user_configs": ["student"],
            "flatpak": ["org.libreoffice.LibreOffice"],
            "deb": [],
        })
    );
}

#[test]
fn migrate_json_shape() {
    let (home, dir) = settings(&clean_v2());
    let d = dir.to_str().unwrap();
    let o = mastersos(home.path(), &["--json", "migrate", "--dir", d]);
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["check", "text", "written"]);
    assert_eq!(v["written"], false);
    assert!(v["text"].as_str().unwrap().starts_with("format = 3\n"));
    assert_eq!(v["check"]["publishable"], true);
    assert!(v["check"]["issues"].is_array());
    assert_eq!(v["check"]["rerouted_secrets"], json!([]));
    assert!(err.contains("lose their comments"), "{err}");

    let o = mastersos(home.path(), &["--json", "migrate", "--dir", d, "--write"]);
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["check", "written"]);
    assert_eq!(v["written"], true);
}
