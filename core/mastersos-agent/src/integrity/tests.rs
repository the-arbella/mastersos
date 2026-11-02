use std::fs;

use super::*;

fn with(json: &str) -> ItemResult {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join(INTEGRITY_STATUS), json).unwrap();
    integrity_item(d.path())
}

const GOOD: &str =
    r#""has_golden":true,"active_ok":true,"golden_ok":true,"gave_up":null,"error":null,"notes":[]"#;

#[test]
fn missing_file_is_ok() {
    let d = tempfile::tempdir().unwrap();
    let i = integrity_item(d.path());
    assert_eq!(i.item, "system:integrity");
    assert!(i.ok, "{i:?}");
    assert_eq!(i.detail.as_deref(), Some("integrity not checked yet"));
}

#[test]
fn unreadable_is_failure() {
    let i = with("not json");
    assert!(!i.ok, "{i:?}");
    // a directory where the file should be: the read fails with something other than NotFound
    let d = tempfile::tempdir().unwrap();
    fs::create_dir(d.path().join(INTEGRITY_STATUS)).unwrap();
    assert!(!integrity_item(d.path()).ok);
}

#[test]
fn missing_active_ok_is_failure() {
    assert!(!with(r#"{"has_golden":true}"#).ok);
}

#[test]
fn error_is_failure_and_beats_gave_up() {
    let i = with(r#"{"active_ok":true,"gave_up":"abc","error":"cannot locate the active slot"}"#);
    assert!(!i.ok, "{i:?}");
    assert_eq!(
        i.detail.as_deref(),
        Some("check failed: cannot locate the active slot")
    );
}

#[test]
fn gave_up_is_failure() {
    let i = with(r#"{"active_ok":false,"gave_up":"abc123","error":null}"#);
    assert!(!i.ok, "{i:?}");
    assert!(i.detail.unwrap().contains("gave up"));
}

#[test]
fn active_bad_is_repair_pending() {
    let i = with(
        r#"{"has_golden":true,"active_ok":false,"golden_ok":true,"gave_up":null,"error":null}"#,
    );
    assert!(!i.ok, "{i:?}");
    assert!(i.detail.unwrap().contains("repair pending"));
}

#[test]
fn active_bad_with_latest_repair_request_still_pending() {
    let i = with(
        r#"{"has_golden":true,"active_ok":false,"golden_ok":true,"gave_up":null,"error":null,
        "repaired":[{"at":"2026-10-27T01:00:00Z","what":"repair-request","from":"golden"}]}"#,
    );
    assert!(!i.ok, "{i:?}");
    assert!(i.detail.unwrap().contains("repair pending"));
}

#[test]
fn no_golden_is_ok() {
    let i = with(
        r#"{"has_golden":false,"active_ok":true,"golden_ok":false,"gave_up":null,"error":null}"#,
    );
    assert!(i.ok, "{i:?}");
    assert!(i.detail.unwrap().contains("no golden copy"));
}

#[test]
fn no_golden_shape_written_by_the_script_is_ok() {
    // check_main never reads the active slot without a golden copy: active_ok=false, has_golden=false
    let i = with(
        r#"{"has_golden":false,"active_ok":false,"golden_ok":false,"gave_up":null,"error":null}"#,
    );
    assert!(i.ok, "{i:?}");
    assert!(i.detail.unwrap().contains("no golden copy"));
}

#[test]
fn golden_invalid_is_ok_with_refresh_pending() {
    let i = with(
        r#"{"has_golden":true,"active_ok":true,"golden_ok":false,"gave_up":null,"error":null}"#,
    );
    assert!(i.ok, "{i:?}");
    assert!(i.detail.unwrap().contains("golden copy invalid"));
}

#[test]
fn latest_completed_repair_is_reported() {
    let i = with(&format!(
        r#"{{{GOOD},"repaired":[{{"at":"2026-10-26T01:00:00Z","what":"golden","from":"active"}},
        {{"at":"2026-10-27T01:00:00Z","what":"inactive","from":"golden"}}]}}"#
    ));
    assert!(i.ok, "{i:?}");
    let d = i.detail.unwrap();
    assert!(
        d.contains("inactive") && d.contains("2026-10-27T01:00:00Z"),
        "{d}"
    );
}

#[test]
fn repair_request_is_skipped_when_choosing_latest() {
    let i = with(&format!(
        r#"{{{GOOD},"repaired":[{{"at":"2026-10-26T01:00:00Z","what":"uki","from":"golden"}},
        {{"at":"2026-10-27T01:00:00Z","what":"repair-request","from":"golden"}}]}}"#
    ));
    assert!(i.ok, "{i:?}");
    let d = i.detail.unwrap();
    assert!(d.contains("uki") && !d.contains("repair-request"), "{d}");
}

#[test]
fn only_repair_request_reads_as_plain_ok() {
    let i = with(&format!(
        r#"{{{GOOD},"repaired":[{{"at":"2026-10-27T01:00:00Z","what":"repair-request","from":"golden"}}]}}"#
    ));
    assert!(i.ok);
    assert_eq!(i.detail.as_deref(), Some("ok"));
}

#[test]
fn notes_do_not_change_the_result() {
    let i = with(
        r#"{"has_golden":true,"active_ok":true,"golden_ok":true,"gave_up":null,"error":null,
        "notes":["keyring cannot verify, trusting roothash only","network fetch started"]}"#,
    );
    assert!(i.ok);
    assert_eq!(i.detail.as_deref(), Some("ok"));
}
