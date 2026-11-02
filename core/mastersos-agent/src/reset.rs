//! Factory reset (MQTT push spec §6.3): the steps the inbox's `factory-reset` command runs
//! ([`crate::inbox`] owns the order, the acks and the de-duplication).
//!
//! - [`precheck`]: the seed partition is mounted and writable (the command's `seq` must be
//!   recorded there to report `done` after the reset), and `tpm::probe` is `Usable` (without a
//!   usable TPM repart cannot create the new data partition after deleting the old one).
//! - [`request`]: `systemd-factory-reset request` (sets the `FactoryResetRequest` EFI variable;
//!   the initrd's confirmation unit only looks at the kernel command line, it does not ask).
//! - [`reboot`]: `systemctl reboot`.
//!
//! The old bundle path (`[[device]].reset`, `reset-done`, `requested_at`) is gone: the server
//! stops handing a command out once the machine acked it `running`.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::runner::{Cmd, Runner};
use crate::safefs;
use crate::tpm::{self, ProbeEnv, TpmVerdict};

/// Report item name.
pub const ITEM: &str = "reset";
/// The start of the report detail while a factory reset is under way.
pub const RESETTING: &str = "factory resetting";
/// Sets the `FactoryResetRequest` EFI variable (systemd 258 and later).
pub const FACTORY_RESET: &str = "/usr/lib/systemd/systemd-factory-reset";
/// Name of the file written to check that the seed partition is writable (deleted at once).
const PROBE: &str = ".inbox-reset-seq.probe";

pub struct ResetCtx<'a> {
    /// The seed partition's mount point.
    pub seed_dir: &'a Path,
    /// The seed partition must be a mount point (true in production; a test's temporary
    /// directory is not one).
    pub seed_requires_mount: bool,
    pub runner: Arc<dyn Runner>,
    /// `/sys` and `/dev` for the TPM probe.
    pub sysfs: PathBuf,
    pub dev: PathBuf,
}

/// The preconditions (see the module docs). Ok: the opened seed partition. Err: why not, for
/// the `failed` ack.
pub async fn precheck(cx: &ResetCtx<'_>) -> Result<OwnedFd, String> {
    let dir = seed_dir(cx)?;
    let probe =
        safefs::write_at(&dir, PROBE, b"", 0o600).and_then(|_| safefs::remove_at(&dir, PROBE));
    if let Err(e) = probe {
        return Err(format!(
            "the seed partition is not writable, the command could not be recorded: {e:#}"
        ));
    }
    match probe_tpm(cx).await {
        TpmVerdict::Usable => Ok(dir),
        TpmVerdict::Unusable(u) => Err(format!(
            "the TPM is unusable ({}), no new data partition could be created after the reset",
            u.text()
        )),
        TpmVerdict::Undecided(why) => Err(format!(
            "could not tell whether the TPM is usable ({why}), a new data partition might not be created after the reset"
        )),
    }
}

/// `systemd-factory-reset request`. Err: what failed, for the `failed` ack.
pub async fn request(cx: &ResetCtx<'_>) -> Result<(), String> {
    step(
        cx,
        Cmd::new(FACTORY_RESET, &["request"]),
        "systemd-factory-reset request",
    )
    .await
}

/// `systemctl reboot`. Err: what failed, for the `failed` ack.
pub async fn reboot(cx: &ResetCtx<'_>) -> Result<(), String> {
    step(cx, Cmd::new("systemctl", &["reboot"]), "systemctl reboot").await
}

async fn step(cx: &ResetCtx<'_>, c: Cmd, what: &str) -> Result<(), String> {
    let r = cx.runner.clone();
    let out = tokio::task::spawn_blocking(move || r.run(&c))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .and_then(|r| r);
    match out {
        Ok(o) if o.code == 0 => Ok(()),
        Ok(o) => Err(format!(
            "{what} failed (exit code {}): {}",
            o.code,
            crate::runner::last_lines(&o.stderr, 3)
        )),
        Err(e) => Err(format!("{what} could not be run: {e:#}")),
    }
}

/// Opens the seed partition (checking first that it is mounted, when required).
pub fn seed_dir(cx: &ResetCtx<'_>) -> Result<OwnedFd, String> {
    open_seed(cx.seed_dir, cx.seed_requires_mount)
}

/// Opens the seed partition at `dir` (checking first that it is mounted, when `requires_mount`).
pub fn open_seed(dir: &Path, requires_mount: bool) -> Result<OwnedFd, String> {
    if requires_mount {
        match crate::seedpart::is_mount_point(dir) {
            Ok(true) => {}
            Ok(false) => {
                return Err(format!(
                    "the seed partition is not mounted ({} is not a mount point)",
                    dir.display()
                ))
            }
            Err(e) => return Err(format!("checking the seed partition failed: {e:#}")),
        }
    }
    safefs::open_abs_dir(dir, false)
        .map_err(|e| format!("opening the seed partition failed: {e:#}"))
}

/// `tpm::probe` is synchronous and may take over 30 s: run it on a blocking thread.
async fn probe_tpm(cx: &ResetCtx<'_>) -> TpmVerdict {
    let (runner, sysfs, dev) = (cx.runner.clone(), cx.sysfs.clone(), cx.dev.clone());
    tokio::task::spawn_blocking(move || {
        tpm::probe(&ProbeEnv {
            runner: runner.as_ref(),
            sysfs: &sysfs,
            dev: &dev,
            sleep: &std::thread::sleep,
        })
    })
    .await
    .unwrap_or_else(|e| TpmVerdict::Undecided(format!("the probe panicked: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::{FakeRunner, Output};
    use std::fs;

    struct Box_ {
        _tmp: tempfile::TempDir,
        seed: PathBuf,
        sysfs: PathBuf,
        dev: PathBuf,
    }

    fn machine(tpm: bool) -> Box_ {
        let tmp = tempfile::tempdir().unwrap();
        let seed = tmp.path().join("seed");
        let sysfs = tmp.path().join("sys");
        let dev = tmp.path().join("dev");
        for d in [&seed, &sysfs, &dev] {
            fs::create_dir_all(d).unwrap();
        }
        if tpm {
            fs::create_dir_all(sysfs.join("class/tpm/tpm0/pcr-sha256")).unwrap();
            fs::write(dev.join("tpmrm0"), "").unwrap();
        }
        Box_ {
            _tmp: tmp,
            seed,
            sysfs,
            dev,
        }
    }

    fn fake(tpm: bool) -> Arc<FakeRunner> {
        let f = FakeRunner::new();
        let has = if tpm {
            "yes\n+firmware\n+driver\n+system\n+subsystem\n+libraries\n"
        } else {
            "no\n-firmware\n-driver\n+system\n+subsystem\n+libraries\n"
        };
        f.respond("systemd-analyze has-tpm2", Output::fail(1, has));
        Arc::new(f)
    }

    fn cx<'a>(m: &'a Box_, runner: Arc<FakeRunner>, requires_mount: bool) -> ResetCtx<'a> {
        ResetCtx {
            seed_dir: &m.seed,
            seed_requires_mount: requires_mount,
            runner,
            sysfs: m.sysfs.clone(),
            dev: m.dev.clone(),
        }
    }

    #[tokio::test]
    async fn precheck_passes_with_seed_and_tpm() {
        let m = machine(true);
        assert!(precheck(&cx(&m, fake(true), false)).await.is_ok());
        assert!(!m.seed.join(PROBE).exists(), "the probe file is deleted");
    }

    #[tokio::test]
    async fn precheck_refuses_without_usable_tpm() {
        let m = machine(false);
        let why = precheck(&cx(&m, fake(false), false)).await.unwrap_err();
        assert!(why.contains("TPM"), "{why}");
    }

    #[tokio::test]
    async fn precheck_refuses_readonly_seed_partition() {
        use std::os::unix::fs::PermissionsExt;
        let m = machine(true);
        fs::set_permissions(&m.seed, fs::Permissions::from_mode(0o500)).unwrap();
        // root ignores the mode bits: skip when it can write (CI and dev boxes are not root).
        let writable = fs::write(m.seed.join("x"), "").is_ok();
        let f = fake(true);
        let r = precheck(&cx(&m, f.clone(), false)).await;
        fs::set_permissions(&m.seed, fs::Permissions::from_mode(0o700)).unwrap();
        if writable {
            return;
        }
        let why = r.unwrap_err();
        assert!(why.contains("seed partition"), "{why}");
        assert!(
            !f.calls().iter().any(|c| c.starts_with("systemd-creds")),
            "no TPM probe once the seed partition fails: {:?}",
            f.calls()
        );
    }

    #[tokio::test]
    async fn precheck_refuses_unmounted_seed_partition() {
        let m = machine(true);
        let why = precheck(&cx(&m, fake(true), true)).await.unwrap_err();
        assert!(why.contains("not mounted"), "{why}");
    }

    #[tokio::test]
    async fn request_failure_names_the_step() {
        let m = machine(true);
        let f = fake(true);
        f.respond(
            "/usr/lib/systemd/systemd-factory-reset request",
            Output::fail(1, "Failed to set EFI variable"),
        );
        let why = request(&cx(&m, f.clone(), false)).await.unwrap_err();
        assert!(why.contains("systemd-factory-reset request"), "{why}");
        assert!(why.contains("Failed to set EFI variable"), "{why}");
        assert!(reboot(&cx(&m, f, false)).await.is_ok());
    }
}
