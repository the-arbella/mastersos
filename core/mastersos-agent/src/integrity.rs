//! `system:integrity`: report the state of the on-device /usr integrity checker (`integrity.json`).

use std::io::ErrorKind;
use std::path::Path;

use mastersos_bundle::ItemResult;

pub const INTEGRITY_STATUS: &str = "integrity.json";
pub const INTEGRITY_ITEM: &str = "system:integrity";

/// `system:integrity`: read the file `/usr/lib/mastersos/integrity` writes. Precedence: missing file (ok), unreadable (fail),
/// `error` (fail), no golden copy (ok), `gave_up` (fail), active slot bad (fail), golden copy invalid (ok, refresh pending),
/// latest completed repair, otherwise "ok". `notes` are informational and never change the result.
pub fn integrity_item(var_dir: &Path) -> ItemResult {
    let p = var_dir.join(INTEGRITY_STATUS);
    let item = |ok: bool, detail: String| ItemResult {
        item: INTEGRITY_ITEM.into(),
        ok,
        detail: Some(detail),
    };
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return item(true, "integrity not checked yet".into());
        }
        Err(e) => return item(false, format!("cannot read {}: {e}", p.display())),
    };
    let v: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => return item(false, format!("cannot parse {}: {e}", p.display())),
    };
    let flag = |k: &str| v.get(k).and_then(serde_json::Value::as_bool);

    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        let text = err.as_str().map_or_else(|| err.to_string(), str::to_owned);
        return item(false, format!("check failed: {text}"));
    }
    // Without a golden copy the script never reads the active slot and writes active_ok=false: that is "not checked", not damage.
    if flag("has_golden") == Some(false) {
        return item(true, "no golden copy".into());
    }
    let gave_up = v
        .get("gave_up")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| !s.is_empty());
    if gave_up {
        return item(
            false,
            "gave up repairing /usr after repeated attempts".into(),
        );
    }
    let Some(active_ok) = flag("active_ok") else {
        return item(false, format!("no active_ok in {}", p.display()));
    };
    if !active_ok {
        return item(false, "active /usr slot is damaged, repair pending".into());
    }
    if flag("golden_ok") == Some(false) {
        return item(true, "golden copy invalid, refresh pending".into());
    }
    // A repair-request is a request for the next boot, not a completed repair.
    let latest = v
        .get("repaired")
        .and_then(serde_json::Value::as_array)
        .and_then(|a| {
            a.iter().rev().find(|r| {
                r.get("what").and_then(serde_json::Value::as_str) != Some("repair-request")
            })
        });
    match latest {
        Some(r) => {
            let f = |k: &str| r.get(k).and_then(serde_json::Value::as_str).unwrap_or("?");
            item(
                true,
                format!(
                    "ok, last repair: {} from {} at {}",
                    f("what"),
                    f("from"),
                    f("at")
                ),
            )
        }
        None => item(true, "ok".into()),
    }
}

#[cfg(test)]
mod tests;
