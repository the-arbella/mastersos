//! The per-person layer of the settings: what the agent applies to one person at login (design
//! `docs/specs/2026-11-19-user-layer-design.md`). This module holds the paths shared by its parts.

pub mod facts;

use std::time::Duration;

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
}
