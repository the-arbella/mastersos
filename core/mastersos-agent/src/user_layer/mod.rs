//! The per-person layer of the settings: what the agent applies to one person at login (design
//! `docs/specs/2026-11-19-user-layer-design.md`). This module holds the paths shared by its parts.

pub mod facts;
pub mod render;

use std::path::Path;
use std::time::Duration;

use mastersos_bundle::Caps;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The issuer facts the login broker leaves for the PAM session, relative to the system root. One file
/// `<login name>.json` per login; see [`facts`].
pub const FACTS_DIR: &str = "run/mastersos/facts";
/// A facts file older than this is not trusted.
pub const FACTS_MAX_AGE: Duration = Duration::from_secs(120);
/// The agent's per-session state of this layer, relative to the system root (root 0700).
pub const RUN_DIR: &str = "run/mastersos/user-layer";
/// The marker of the active session of this layer inside [`RUN_DIR`].
pub const ACTIVE_FILE: &str = "active.json";
/// The directory name of the configuration used when a person has no user config.
pub const NEUTRAL_DIR: &str = "neutral";

/// The directory name of a user config on disk: `u-` and the first 16 hex digits of the SHA-256 of its id.
/// Ids have no character rule, so an id is never used as a path component itself.
pub fn config_dir_name(id: &str) -> String {
    let digest = Sha256::digest(id.as_bytes());
    let mut out = String::from("u-");
    for b in &digest[..8] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The marker of the session this layer switched in ([`RUN_DIR`]/[`ACTIVE_FILE`], root 0600): who is signed in and
/// which pre-rendered config dir their session uses. Written at login, removed once the session is back to neutral.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Active {
    pub uid: u32,
    pub user: String,
    /// The user config id.
    pub user_config: String,
    /// The pre-rendered config dir ([`config_dir_name`] or [`NEUTRAL_DIR`]).
    pub dir: String,
    /// The capabilities of that config.
    pub caps: Caps,
    pub state: ActiveState,
    /// Why the session got the fallback config, when it did.
    #[serde(default)]
    pub reason: Option<String>,
    /// When the session was opened (unix seconds).
    #[serde(default)]
    pub opened_at: u64,
    /// The agent has seen a logind session of `uid`.
    #[serde(default)]
    pub seen: bool,
}

/// Whether the session of an [`Active`] marker is still open or is being closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActiveState {
    Open,
    Closing,
}

/// The marker under `root` (the system root); `None` when it is missing or cannot be read or parsed.
pub fn read_active(root: &Path) -> Option<Active> {
    let dir = crate::safefs::open_dir(root, Path::new(RUN_DIR), false).ok()?;
    let bytes = crate::safefs::read_at(&dir, ACTIVE_FILE).ok()??;
    serde_json::from_slice(&bytes).ok()
}

/// Whether `name` is a config dir name this layer writes: [`NEUTRAL_DIR`] or the shape of [`config_dir_name`].
pub fn is_config_dir(name: &str) -> bool {
    name == NEUTRAL_DIR
        || name.strip_prefix("u-").is_some_and(|h| {
            h.len() == 16
                && h.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_dir_name_is_fixed_width_hex_and_stable() {
        let a = config_dir_name("../etc");
        assert_eq!(a.len(), 18);
        assert!(a.starts_with("u-"));
        assert!(a[2..].bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(a, config_dir_name("../etc"));
        assert_ne!(a, config_dir_name("../etd"));
        // sha256("abc") = ba7816bf8f01cfea...
        assert_eq!(config_dir_name("abc"), "u-ba7816bf8f01cfea");
    }

    #[test]
    fn config_dir_shape() {
        assert!(is_config_dir(NEUTRAL_DIR));
        assert!(is_config_dir(&config_dir_name("x")));
        for bad in [
            "",
            "u-",
            "u-BA7816BF8F01CFEA",
            "u-ba7816bf8f01cfe",
            "mastersos",
            "../u-ba7816bf8f01cfea",
        ] {
            assert!(!is_config_dir(bad), "{bad}");
        }
    }
}
