//! Code shared by everything that installs systemd-sysext extensions into `/var/lib/extensions`: Chrome
//! ([`crate::chrome_sysext`]) and the third-party .deb apps (`app-<id>`, `app-deps`).
//!
//! - [`download`]: streams a file into a private directory with a timeout and a size cap, hashing while downloading,
//!   optionally as a conditional GET (`ETag` / `Last-Modified`).
//! - [`swap_in`] / [`swap_in_all`] / [`remove_ext`] / [`recover_leftover`]: change what is merged and let PID 1 re-merge ([`refresh_cmd`]),
//!   rolling back when the merge fails.
//!
//! **One merger at a time.** A refresh replaces the whole `/usr` overlay, which every extension shares, so whoever changes
//! the merged entries of `/var/lib/extensions` and refreshes holds [`MERGE_LOCK`] (an `flock`) for the whole
//! change-and-refresh. The swap functions take it themselves. Lock order: a job first takes its own work-directory lock
//! (Chrome: `/var/lib/mastersos/chrome`), and takes `MERGE_LOCK` only inside these functions, never the other way round,
//! so two jobs cannot deadlock.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::runner::Cmd;
use crate::safefs;

mod download;
mod swap;

pub use download::{download, download_with, FetchOutcome, Fetched};
pub use swap::{recover_leftover, remove_ext, swap_in, swap_in_all};

/// The merge lock; `/run/mastersos` is created 0700 root by tmpfiles (and the initrd) and is writable for
/// `mastersos-chrome.service` and `mastersos-deb-apps.service`.
pub const MERGE_LOCK: &str = "/run/mastersos/sysext.lock";

/// How long the swap functions wait for [`MERGE_LOCK`]. The other holder only renames entries and runs one or two
/// bounded refreshes (and removes a tree), so minutes are plenty; a background job that gives up retries next round.
pub const MERGE_LOCK_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Re-merges the extensions. Not `systemd-sysext refresh` itself: the agent's units have `PrivateTmp=yes` and run in their
/// own mount namespace, where a merge is visible only to the agent (VM 165: the agent reported Chrome installed, the system had
/// no `/opt/google`). PID 1's `systemd-sysext.service` does it: `reload` (= `systemd-sysext refresh`) when it runs, `start`
/// (also a refresh) when it does not (at boot `/var/lib/extensions` was empty and its condition failed).
pub fn refresh_cmd() -> Cmd {
    Cmd::new(
        "systemctl",
        &["reload-or-restart", "systemd-sysext.service"],
    )
}

/// Takes [`MERGE_LOCK`] (exclusive `flock`, waiting up to `timeout`); released when the returned fd is dropped.
pub fn lock_merge(timeout: Duration) -> Result<OwnedFd> {
    lock_file(&merge_lock_path(), timeout)
}

#[cfg(not(test))]
fn merge_lock_path() -> PathBuf {
    PathBuf::from(MERGE_LOCK)
}

/// Unit tests do not touch `/run/mastersos`: one lock per test process, so the tests still serialize on it.
#[cfg(test)]
fn merge_lock_path() -> PathBuf {
    std::env::temp_dir().join(format!("mastersos-test-sysext-{}.lock", std::process::id()))
}

/// Exclusive `flock` on `path` (created 0600 when missing; the directory must exist), polling until `timeout`.
pub(crate) fn lock_file(path: &Path, timeout: Duration) -> Result<OwnedFd> {
    use rustix::fs::{flock, openat, FlockOperation, Mode, OFlags};
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        bail!("malformed lock path {}", path.display());
    };
    let dir = safefs::open_abs_dir(parent, false)?;
    let fd = openat(
        &dir,
        name,
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("opening the sysext merge lock {}", path.display()))?;
    let start = Instant::now();
    let mut pause = Duration::from_millis(50);
    loop {
        match flock(&fd, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(fd),
            Err(e) if e == rustix::io::Errno::WOULDBLOCK => {}
            Err(e) => {
                return Err(std::io::Error::from(e))
                    .with_context(|| format!("locking the sysext merge lock {}", path.display()))
            }
        }
        let waited = start.elapsed();
        if waited >= timeout {
            bail!(
                "timed out after {} s waiting for the sysext merge lock {} (another job is merging extensions); retrying next round",
                timeout.as_secs(),
                path.display()
            );
        }
        std::thread::sleep(pause.min(timeout - waited));
        pause = (pause * 2).min(Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests;
