//! Changing what is merged (spec §4.3 last paragraph, §4.5): every function here holds [`super::MERGE_LOCK`] from the first
//! change in the extension directory until the merge (and its rollback) is done.
//!
//! A tree renamed away (`<name>.new` after a swap, `<name>.old` on removal) may still be the merged layer until a refresh
//! succeeds, so it is deleted only after one did; a leftover from an interrupted round is merged away first, then deleted.

use std::os::fd::OwnedFd;

use anyhow::Result;

use super::{lock_merge, refresh_cmd, MERGE_LOCK_TIMEOUT};
use crate::runner::{run_ok, Runner};
use crate::safefs;

fn refresh(runner: &dyn Runner) -> Result<()> {
    run_ok(runner, refresh_cmd()).map(drop)
}

/// Puts the assembled `<ext_dir>/<new_name>` in place of `<name>`: a plain rename on first install, otherwise an atomic
/// `renameat2(RENAME_EXCHANGE)`; then re-merges. When the merge fails, switches back and merges again (the failed one may
/// already have unmounted the old tree); only if that succeeds is `<new_name>` removed, otherwise it stays for
/// [`recover_leftover`]. Returns the merge error as is (callers add their own context). On success the replaced tree (now
/// `<new_name>`) is removed; failing that is only logged (the next round's [`recover_leftover`] does it).
pub fn swap_in(runner: &dyn Runner, ext_dir: &OwnedFd, name: &str, new_name: &str) -> Result<()> {
    swap_in_all(runner, ext_dir, &[(name, new_name)])
}

/// [`swap_in`] for several extensions as one change: every `(name, new_name)` is put in place, then **one** refresh; when
/// it fails all of them are switched back and merged again. So the .deb apps' shared dependencies and the apps resolved
/// with them are merged together or not at all.
pub fn swap_in_all(runner: &dyn Runner, ext_dir: &OwnedFd, pairs: &[(&str, &str)]) -> Result<()> {
    let _lock = lock_merge(MERGE_LOCK_TIMEOUT)?;
    // Look at every pair before moving anything, so a pair that cannot be read leaves all of them as they were.
    // (name, new_name, first install)
    let mut plan: Vec<(&str, &str, bool)> = vec![];
    for (name, new_name) in pairs {
        if safefs::open_child_dir(ext_dir, new_name)?.is_none() {
            anyhow::bail!("{new_name} is missing");
        }
        let first = safefs::open_child_dir(ext_dir, name)?.is_none();
        plan.push((name, new_name, first));
    }
    // Best effort over all of them; the first error is returned, every one is logged.
    let back = |done: &[(&str, &str, bool)]| -> Result<()> {
        let mut first_err = None;
        for (name, new_name, first) in done.iter().rev() {
            let r = if *first {
                safefs::rename_at(ext_dir, name, new_name)
            } else {
                safefs::exchange_at(ext_dir, name, new_name)
            };
            if let Err(e) = r {
                log::warn!("sysext: switching {name} back failed: {e:#}");
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    };
    let mut done: Vec<(&str, &str, bool)> = vec![];
    for (name, new_name, first) in plan {
        let r = if first {
            safefs::rename_at(ext_dir, new_name, name)
        } else {
            safefs::exchange_at(ext_dir, name, new_name)
        };
        if let Err(e) = r {
            // nothing refreshed yet: putting back what was moved is enough
            if let Err(b) = back(&done) {
                log::warn!(
                    "sysext: putting the extensions back after a failed rename also failed: {b:#}"
                );
            }
            return Err(e);
        }
        done.push((name, new_name, first));
    }
    let names: Vec<&str> = pairs.iter().map(|(n, _)| *n).collect();
    let names = names.join(", ");
    if let Err(e) = refresh(runner) {
        match back(&done) {
            Err(b) => log::warn!(
                "sysext: merging the new {names} failed and switching back to the old versions also failed: {b:#}"
            ),
            Ok(()) => match refresh(runner) {
                Ok(()) => {
                    for (_, new_name) in pairs {
                        let _ = safefs::remove_tree_at(ext_dir, new_name);
                    }
                }
                Err(r) => log::warn!(
                    "sysext: re-merging after switching {names} back to the old versions also failed (retrying next round): {r:#}"
                ),
            },
        }
        return Err(e);
    }
    for (name, new_name) in pairs {
        if let Err(e) = safefs::remove_tree_at(ext_dir, new_name) {
            log::warn!(
                "sysext: removing the replaced old {name} failed (retrying next round): {e:#}"
            );
        }
    }
    Ok(())
}

/// A `<leftover>` tree from an interrupted round (e.g. cut between the swap and the merge, when it is the merged layer):
/// merge first, then delete it. Returns whether there was one.
pub fn recover_leftover(runner: &dyn Runner, ext_dir: &OwnedFd, leftover: &str) -> Result<bool> {
    if safefs::open_child_dir(ext_dir, leftover)?.is_none() {
        return Ok(false);
    }
    let _lock = lock_merge(MERGE_LOCK_TIMEOUT)?;
    log::warn!("sysext: a previous round left {leftover}; re-merging before removing it");
    refresh(runner)?;
    safefs::remove_tree_at(ext_dir, leftover)?;
    Ok(true)
}

/// Uninstalls `<ext_dir>/<name>`: renames it to `<name>.old`, re-merges, then deletes it. When the merge fails it is renamed
/// back and merged again (best effort), and the error is returned. Nothing installed: nothing to do.
pub fn remove_ext(runner: &dyn Runner, ext_dir: &OwnedFd, name: &str) -> Result<()> {
    let old = format!("{name}.old");
    if safefs::open_child_dir(ext_dir, &old)?.is_some() {
        recover_leftover(runner, ext_dir, &old)?;
    }
    if safefs::open_child_dir(ext_dir, name)?.is_none() {
        return Ok(());
    }
    let _lock = lock_merge(MERGE_LOCK_TIMEOUT)?;
    safefs::rename_at(ext_dir, name, &old)?;
    if let Err(e) = refresh(runner) {
        match safefs::rename_at(ext_dir, &old, name) {
            Err(b) => log::warn!(
                "sysext: merging without {name} failed and putting it back also failed: {b:#}"
            ),
            Ok(()) => {
                if let Err(r) = refresh(runner) {
                    log::warn!("sysext: re-merging after putting {name} back also failed (retrying next round): {r:#}");
                }
            }
        }
        return Err(e.context(format!("merging without {name} failed; it stays installed")));
    }
    if let Err(e) = safefs::remove_tree_at(ext_dir, &old) {
        log::warn!("sysext: removing {old} failed (retrying next time): {e:#}");
    }
    Ok(())
}
