//! The hand-over of the issuer facts at login.
//!
//! The login broker (Plan C, authd patch 0007) writes `/run/mastersos/facts/<login name>.json` after the issuer granted
//! the login: the directory is root 0700, the file root 0600, written by rename. The content is one of
//!
//! ```text
//! {"version":1,"user":"<login name>","granted_at":<unix seconds>,"facts":{...}}
//! {"version":1,"user":"<login name>","granted_at":<unix seconds>,"error":"<text>"}
//! ```
//!
//! `pam-session` calls [`take_facts`], which reads the file and deletes it in every case. This runs inside PAM: it is
//! synchronous, spawns nothing, uses no network and never panics. Facts that are missing, in error or stale only disable
//! the rules with fact conditions (design §5); the caller decides what to do with each [`FactsOutcome`].

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use mastersos_bundle::IssuerFacts;
use serde::Deserialize;

use super::{FACTS_DIR, FACTS_MAX_AGE};
use crate::safefs;
use crate::system::login::user_name_ok;

/// A hand-over file is a few hundred bytes; this only bounds a broken writer.
const MAX_FILE: u64 = 64 * 1024;
/// How far in the future `granted_at` may be (clock skew between the broker and this process).
const MAX_FUTURE_SECS: u64 = 5;

/// What the hand-over held for one login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactsOutcome {
    /// Fresh facts the issuer granted.
    Facts(IssuerFacts),
    /// No file for this user.
    Missing,
    /// The broker recorded an error, or the file or the directory cannot be trusted. The text is for the log.
    Error(String),
    /// A well-formed file that is too old (or dated in the future).
    Stale,
}

#[derive(Deserialize)]
struct Record {
    version: u64,
    user: String,
    granted_at: u64,
    #[serde(default)]
    facts: Option<IssuerFacts>,
    #[serde(default)]
    error: Option<String>,
}

/// The facts directory under `root`, only if it is owned by this process (root in the agent) with no group or other
/// access.
fn open_facts_dir(root: &Path) -> anyhow::Result<Option<OwnedFd>> {
    let dir = match safefs::open_dir(root, Path::new(FACTS_DIR), false) {
        Ok(d) => d,
        Err(e) => {
            return match e.downcast_ref::<std::io::Error>() {
                Some(io) if io.kind() == std::io::ErrorKind::NotFound => Ok(None),
                _ => Err(e),
            }
        }
    };
    let st = rustix::fs::fstat(&dir).map_err(std::io::Error::from)?;
    let me = rustix::process::geteuid().as_raw();
    if st.st_uid != me || st.st_mode as u32 & 0o077 != 0 {
        anyhow::bail!(
            "facts directory: owner {}, mode {:o} (expected owner {me}, 0700)",
            st.st_uid,
            st.st_mode as u32 & 0o7777
        );
    }
    Ok(Some(dir))
}

/// Read and delete the facts file of `user` under `root`.
///
/// Whenever the file for this user exists it is removed, whatever it holds. A file of another user is never touched, and
/// a name that is not safe as a file name touches nothing.
pub fn take_facts(root: &Path, user: &str, now: SystemTime) -> FactsOutcome {
    if !user_name_ok(user) || user.contains('/') || user.starts_with('.') {
        return FactsOutcome::Error("the login name is not usable as a facts file name".into());
    }
    let dir = match open_facts_dir(root) {
        Ok(Some(d)) => d,
        Ok(None) => return FactsOutcome::Missing,
        Err(e) => return FactsOutcome::Error(format!("{e:#}")),
    };
    let name = format!("{user}.json");
    let bytes = match read_bounded(&dir, &name) {
        Ok(Some(b)) => b,
        Ok(None) => return FactsOutcome::Missing,
        Err(e) => {
            // Unreadable (a symlink, not a regular file, ...): still remove it, so nothing lingers.
            let _ = safefs::remove_at(&dir, &name);
            return FactsOutcome::Error(format!("{e:#}"));
        }
    };
    // Single use: a failed removal must not turn good facts into an error, and the age limit bounds a leftover.
    let _ = safefs::remove_at(&dir, &name);
    interpret(&bytes, user, now)
}

fn read_bounded(dir: &OwnedFd, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(f) = safefs::open_file_at(dir, name)? else {
        return Ok(None);
    };
    let mut buf = Vec::new();
    f.take(MAX_FILE + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_FILE {
        anyhow::bail!("{name} is larger than {MAX_FILE} bytes");
    }
    Ok(Some(buf))
}

fn interpret(bytes: &[u8], user: &str, now: SystemTime) -> FactsOutcome {
    let rec: Record = match serde_json::from_slice(bytes) {
        Ok(r) => r,
        Err(e) => return FactsOutcome::Error(format!("malformed facts file: {e}")),
    };
    if rec.version != 1 {
        return FactsOutcome::Error(format!("unsupported facts file version {}", rec.version));
    }
    if rec.user != user {
        return FactsOutcome::Error("the facts file is for another user".into());
    }
    let now_secs = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    if rec.granted_at > now_secs.saturating_add(MAX_FUTURE_SECS)
        || now_secs.saturating_sub(rec.granted_at) > FACTS_MAX_AGE.as_secs()
    {
        return FactsOutcome::Stale;
    }
    match (rec.facts, rec.error) {
        (Some(f), None) => FactsOutcome::Facts(f),
        (None, Some(e)) => FactsOutcome::Error(format!("the login broker reported: {e}")),
        _ => FactsOutcome::Error("the facts file must hold exactly one of facts and error".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    const NOW: u64 = 1_800_000_000;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn facts_json(user: &str, granted: u64) -> String {
        format!(
            r#"{{"version":1,"user":"{user}","granted_at":{granted},"facts":{{"sub":"s1","org":"o1","org_role":"member","org_nodes":["n1"],"classes":[{{"id":"c1","role":"student"}}],"extra":1}}}}"#
        )
    }

    fn setup() -> (tempfile::TempDir, std::path::PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join(FACTS_DIR);
        fs::create_dir_all(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        (t, d)
    }

    fn put(d: &Path, name: &str, body: &str) {
        fs::write(d.join(name), body).unwrap();
    }

    #[test]
    fn fresh_facts_are_returned_and_deleted() {
        let (t, d) = setup();
        put(&d, "ann.json", &facts_json("ann", NOW - 10));
        let FactsOutcome::Facts(f) = take_facts(t.path(), "ann", at(NOW)) else {
            panic!("expected facts");
        };
        assert_eq!(f.sub, "s1");
        assert_eq!(f.org, "o1");
        assert_eq!(f.classes.len(), 1);
        assert!(!d.join("ann.json").exists());
        assert_eq!(take_facts(t.path(), "ann", at(NOW)), FactsOutcome::Missing);
    }

    #[test]
    fn stale_facts_are_ignored_and_deleted() {
        let (t, d) = setup();
        put(&d, "ann.json", &facts_json("ann", NOW - 121));
        assert_eq!(take_facts(t.path(), "ann", at(NOW)), FactsOutcome::Stale);
        assert!(!d.join("ann.json").exists());
        put(&d, "bob.json", &facts_json("bob", NOW + 6));
        assert_eq!(take_facts(t.path(), "bob", at(NOW)), FactsOutcome::Stale);
        assert!(!d.join("bob.json").exists());
        put(&d, "cy.json", &facts_json("cy", NOW + 5));
        assert!(matches!(
            take_facts(t.path(), "cy", at(NOW)),
            FactsOutcome::Facts(_)
        ));
    }

    #[test]
    fn error_record_is_error() {
        let (t, d) = setup();
        put(
            &d,
            "ann.json",
            &format!(r#"{{"version":1,"user":"ann","granted_at":{NOW},"error":"issuer down"}}"#),
        );
        let FactsOutcome::Error(e) = take_facts(t.path(), "ann", at(NOW)) else {
            panic!("expected error");
        };
        assert!(e.contains("issuer down"));
        assert!(!d.join("ann.json").exists());
    }

    #[test]
    fn wrong_version_is_error() {
        let (t, d) = setup();
        put(
            &d,
            "ann.json",
            &facts_json("ann", NOW).replace("\"version\":1", "\"version\":2"),
        );
        assert!(matches!(
            take_facts(t.path(), "ann", at(NOW)),
            FactsOutcome::Error(_)
        ));
        assert!(!d.join("ann.json").exists());
    }

    #[test]
    fn user_mismatch_is_error() {
        let (t, d) = setup();
        put(&d, "ann.json", &facts_json("bob", NOW));
        assert!(matches!(
            take_facts(t.path(), "ann", at(NOW)),
            FactsOutcome::Error(_)
        ));
        assert!(!d.join("ann.json").exists());
    }

    #[test]
    fn facts_and_error_both_is_error() {
        let (t, d) = setup();
        let both = facts_json("ann", NOW).replace("\"facts\":", "\"error\":\"x\",\"facts\":");
        put(&d, "ann.json", &both);
        assert!(matches!(
            take_facts(t.path(), "ann", at(NOW)),
            FactsOutcome::Error(_)
        ));
        put(
            &d,
            "bob.json",
            &format!(r#"{{"version":1,"user":"bob","granted_at":{NOW}}}"#),
        );
        assert!(matches!(
            take_facts(t.path(), "bob", at(NOW)),
            FactsOutcome::Error(_)
        ));
    }

    #[test]
    fn malformed_json_is_error_and_deleted() {
        let (t, d) = setup();
        put(&d, "ann.json", "not json");
        assert!(matches!(
            take_facts(t.path(), "ann", at(NOW)),
            FactsOutcome::Error(_)
        ));
        assert!(!d.join("ann.json").exists());
    }

    #[test]
    fn missing_is_missing() {
        let (t, _d) = setup();
        assert_eq!(take_facts(t.path(), "ann", at(NOW)), FactsOutcome::Missing);
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            take_facts(empty.path(), "ann", at(NOW)),
            FactsOutcome::Missing
        );
    }

    #[test]
    fn facts_for_other_user_untouched() {
        let (t, d) = setup();
        put(&d, "bob.json", &facts_json("bob", NOW));
        put(&d, "ann.json", &facts_json("ann", NOW));
        assert!(matches!(
            take_facts(t.path(), "ann", at(NOW)),
            FactsOutcome::Facts(_)
        ));
        assert!(d.join("bob.json").exists());
    }

    #[test]
    fn facts_path_rejects_unsafe_names() {
        let (t, d) = setup();
        fs::write(t.path().join("x.json"), facts_json("../x", NOW)).unwrap();
        put(&d, ".hidden.json", &facts_json(".hidden", NOW));
        for bad in ["../x", "a/b", ".hidden", "", "-x", "a\nb"] {
            assert!(
                matches!(take_facts(t.path(), bad, at(NOW)), FactsOutcome::Error(_)),
                "{bad:?}"
            );
        }
        assert!(t.path().join("x.json").exists());
        assert!(d.join(".hidden.json").exists());
    }

    #[test]
    fn world_readable_dir_is_error() {
        let (t, d) = setup();
        put(&d, "ann.json", &facts_json("ann", NOW));
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            take_facts(t.path(), "ann", at(NOW)),
            FactsOutcome::Error(_)
        ));
        assert!(d.join("ann.json").exists());
    }

    #[test]
    fn symlink_file_is_error_and_unlinked() {
        let (t, d) = setup();
        let target = t.path().join("secret");
        fs::write(&target, "x").unwrap();
        std::os::unix::fs::symlink(&target, d.join("ann.json")).unwrap();
        assert!(matches!(
            take_facts(t.path(), "ann", at(NOW)),
            FactsOutcome::Error(_)
        ));
        assert!(target.exists());
    }
}
