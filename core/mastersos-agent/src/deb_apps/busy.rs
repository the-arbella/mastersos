//! Is an app in use (spec §4.5)? A replaced or removed extension is swapped only when nobody runs it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::round::{blocking, RoundEnv, RoundState};
use super::status::Wanted;
use crate::runner::Cmd;

/// Why an extension counts as in use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    /// A kiosk account has a session that is not closing (or the session list cannot be read). Authoritative.
    Session,
    /// A process runs a program the tree provides, from its readable `/proc/<pid>/exe` (or `/proc` cannot be listed).
    /// Authoritative.
    Program(String),
    /// Only a process's arguments name a program the tree provides (its `exe` link was unreadable: the unit has no
    /// `CAP_SYS_PTRACE` for other users' processes, on purpose). A student can name a process after the app, so this
    /// defers a replacement or removal for a limited time only (the round's 24-hour cap).
    Argv(String),
}

/// Is any of `ext_paths` (extension trees) in use? See [`in_use_why`].
pub fn in_use(
    proc_root: &Path,
    ext_paths: &[PathBuf],
    kiosk_users: &[String],
    sessions_json: &str,
) -> bool {
    in_use_why(proc_root, ext_paths, kiosk_users, sessions_json).is_some()
}

/// The strongest [`Evidence`] that one of `ext_paths` is in use: a session of an account in `kiosk_users` that is not
/// closing (`sessions_json` is `loginctl --json=short list-sessions`; unreadable counts as yes), a process whose
/// `/proc/<pid>/exe` is a program a tree provides, or, when that link cannot be read, one of the first two absolute
/// paths among its arguments (interpreter and script).
pub fn in_use_why(
    proc_root: &Path,
    ext_paths: &[PathBuf],
    kiosk_users: &[String],
    sessions_json: &str,
) -> Option<Evidence> {
    if !kiosk_users.is_empty() {
        let Ok(serde_json::Value::Array(rows)) =
            serde_json::from_str::<serde_json::Value>(sessions_json.trim())
        else {
            log::warn!("deb-apps: cannot read the session list; treating the app as in use");
            return Some(Evidence::Session);
        };
        let session = rows.iter().any(|r| {
            r.get("user")
                .and_then(|u| u.as_str())
                .is_some_and(|u| kiosk_users.iter().any(|k| k == u))
                && r.get("state").and_then(|s| s.as_str()) != Some("closing")
        });
        if session {
            return Some(Evidence::Session);
        }
    }
    let entries = match std::fs::read_dir(proc_root) {
        Ok(e) => e,
        Err(e) => {
            log::warn!(
                "deb-apps: cannot list {}: {e}; treating the app as in use",
                proc_root.display()
            );
            return Some(Evidence::Program(proc_root.display().to_string()));
        }
    };
    let provided = |program: &str| {
        let program = program.strip_suffix(" (deleted)").unwrap_or(program);
        (program.starts_with("/opt/") || program.starts_with("/usr/"))
            && !program.split('/').any(|c| c == "..")
            && ext_paths
                .iter()
                .any(|x| std::fs::symlink_metadata(x.join(&program[1..])).is_ok())
    };
    let mut argv = None;
    for e in entries.flatten() {
        let name = e.file_name();
        if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let p = e.path();
        match std::fs::read_link(p.join("exe")) {
            Ok(t) => {
                let t = t.to_string_lossy();
                if provided(&t) {
                    log::info!("deb-apps: {t} is running (pid {})", name.to_string_lossy());
                    return Some(Evidence::Program(t.into_owned()));
                }
            }
            Err(_) if argv.is_none() => {
                let cmdline = std::fs::read(p.join("cmdline")).unwrap_or_default();
                argv = cmdline
                    .split(|b| *b == 0)
                    .map(|a| String::from_utf8_lossy(a).into_owned())
                    .filter(|a| a.starts_with('/'))
                    .take(2)
                    .find(|a| provided(a));
            }
            Err(_) => {}
        }
    }
    argv.map(Evidence::Argv)
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
