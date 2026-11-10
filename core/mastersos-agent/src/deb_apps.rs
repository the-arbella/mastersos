//! Third-party Ubuntu .deb apps (`[config.apps.deb.<id>]`) as systemd-sysext extensions
//! (docs/specs/2026-11-10-deb-apps-design.md).
//!
//! - [`apt`]: the private apt run that computes and downloads the dependencies missing from the image (§4.2), and the
//!   offline cache source used first after an image change (§4.6).

/// The agent's private work directory (0700 root, created by tmpfiles; `mastersos-deb-apps.service` may write it).
pub const WORK_DIR: &str = "/var/lib/mastersos/deb-apps";
/// What the image was built from: `SNAPSHOT=`, `CODENAME=`, `COMPONENTS=` (written by `mkosi.finalize`).
pub const UBUNTU_SOURCE: &str = "/usr/lib/mastersos/ubuntu-source";
/// The image's dpkg status as built (read-only, matches the image exactly); apt resolves against it.
pub const FACTORY_STATUS: &str = "/usr/share/factory/var/lib/dpkg/status";
/// The only keys apt trusts: the image's Ubuntu archive keyring (package `ubuntu-keyring`).
pub const UBUNTU_KEYRING: &str = "/usr/share/keyrings/ubuntu-archive-keyring.gpg";
pub const SNAPSHOT_BASE: &str = "https://snapshot.ubuntu.com/ubuntu";
pub const ARCHIVE_URL: &str = "http://archive.ubuntu.com/ubuntu";
pub const SECURITY_URL: &str = "http://security.ubuntu.com/ubuntu";

pub mod apt;

#[cfg(test)]
mod tests_apt;
