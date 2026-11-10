//! Is an app in use (spec §4.5)? A replaced or removed extension is swapped only when nobody runs it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::round::{blocking, RoundEnv, RoundState};
use super::status::Wanted;
use crate::runner::Cmd;

/// Is any of `ext_paths` (extension trees) in use: does a kiosk account in `kiosk_users` have a session that is not
/// closing (`sessions_json` is `loginctl --json=short list-sessions`; unreadable counts as yes), or does a process run a
/// program one of the trees provides (`/proc/<pid>/exe`, or `argv[0]` when the link cannot be read: the unit lacks
/// `CAP_SYS_PTRACE` for other users' processes)?
pub fn in_use(
    proc_root: &Path,
    ext_paths: &[PathBuf],
    kiosk_users: &[String],
    sessions_json: &str,
) -> bool {
    if !kiosk_users.is_empty() {
        let Ok(serde_json::Value::Array(rows)) =
            serde_json::from_str::<serde_json::Value>(sessions_json.trim())
        else {
            log::warn!("deb-apps: cannot read the session list; treating the app as in use");
            return true;
        };
        let session = rows.iter().any(|r| {
            r.get("user")
                .and_then(|u| u.as_str())
                .is_some_and(|u| kiosk_users.iter().any(|k| k == u))
                && r.get("state").and_then(|s| s.as_str()) != Some("closing")
        });
        if session {
            return true;
        }
    }
    let entries = match std::fs::read_dir(proc_root) {
        Ok(e) => e,
        Err(e) => {
            log::warn!(
                "deb-apps: cannot list {}: {e}; treating the app as in use",
                proc_root.display()
            );
            return true;
        }
    };
    for e in entries.flatten() {
        let name = e.file_name();
        if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let p = e.path();
        let program = match std::fs::read_link(p.join("exe")) {
            Ok(t) => t.to_string_lossy().into_owned(),
            Err(_) => std::fs::read(p.join("cmdline"))
                .ok()
                .and_then(|c| {
                    c.split(|b| *b == 0)
                        .next()
                        .map(|a| String::from_utf8_lossy(a).into_owned())
                })
                .unwrap_or_default(),
        };
        let program = program.strip_suffix(" (deleted)").unwrap_or(&program);
        if !(program.starts_with("/opt/") || program.starts_with("/usr/"))
            || program.split('/').any(|c| c == "..")
        {
            continue;
        }
        let rel = &program[1..];
        if ext_paths
            .iter()
            .any(|x| std::fs::symlink_metadata(x.join(rel)).is_ok())
        {
            log::info!(
                "deb-apps: {program} is running (pid {})",
                name.to_string_lossy()
            );
            return true;
        }
    }
    false
}

/// `loginctl --json=short list-sessions`, once per round; empty when it fails (then [`in_use`] says yes for kiosk apps).
pub(super) async fn sessions_json(env: &RoundEnv, cache: &mut Option<String>) -> String {
    if let Some(s) = cache {
        return s.clone();
    }
    let s = blocking(env, |r| {
        crate::runner::run_ok(
            r,
            Cmd::new("loginctl", &["--json=short", "list-sessions"])
                .timeout(Duration::from_secs(5)),
        )
    })
    .await
    .unwrap_or_else(|e| {
        log::warn!("deb-apps: loginctl failed: {e:#}");
        String::new()
    });
    *cache = Some(s.clone());
    s
}

/// The kiosk account of app `id`, when it is (or was installed as) a kiosk app.
pub(super) fn kiosk_of(wanted: &Wanted, st: &RoundState, id: &str) -> Vec<String> {
    let k =
        wanted.apps.get(id).is_some_and(|a| a.kiosk) || st.apps.get(id).is_some_and(|i| i.kiosk);
    if k {
        vec![mastersos_bundle::kiosk::account_name(id)]
    } else {
        vec![]
    }
}
