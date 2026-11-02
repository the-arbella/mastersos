//! Whether this machine's TPM 2.0 is usable (Ruling 17: a TPM 2.0 with a SHA-256 PCR bank is required). The installer uses it
//! before the confirm screen to decide whether to refuse; the initrd's `tpm-probe` is a shell version of the same rules.
//!
//! Three verdicts: [`TpmVerdict::Usable`], [`TpmVerdict::Unusable`] (certainly none, no SHA-256 bank, lockout,
//! owner password), [`TpmVerdict::Undecided`] (a command or library is missing, the device never shows up, an unknown error). Only `Usable` counts as usable.
//!
//! Synchronous, waits 30-odd seconds at worst (for `/dev/tpmrm0`, three trial seals): call it through `spawn_blocking` from async code.

use std::path::Path;
use std::time::Duration;

use crate::runner::{Cmd, Runner};

/// Why the TPM is certainly unusable. The installer's `tpm_refusal_text` picks the BIOS advice by this value, not by the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unusable {
    /// Certainly no TPM 2.0 (neither firmware nor kernel has one; machines with only a TPM 1.2 count too).
    NoTpm,
    /// A TPM, but no SHA-256 PCR bank (only SHA-1 enabled, or only SHA-384 and the like): the UKI signs PCR policies for SHA-256 only,
    /// so the first boot would reboot-loop (4a §6.12).
    NoSha256Bank,
    /// All three trial seals report `0x921` (TPM_RC_LOCKOUT).
    Lockout,
    /// All three trial seals report `0x9a2` / `0x98e`: the owner hierarchy has a password.
    OwnerAuth,
}

impl Unusable {
    /// The reason in one English line (the console font has no CJK glyphs); the initrd's `tpm-probe` prints the same text.
    pub fn text(self) -> &'static str {
        match self {
            Unusable::NoTpm => "No TPM 2.0",
            Unusable::NoSha256Bank => "The TPM has no SHA-256 PCR bank",
            Unusable::Lockout => "The TPM is in dictionary-attack lockout (0x921)",
            Unusable::OwnerAuth => "The TPM has an owner password set (0x9a2 / 0x98e)",
        }
    }
}

/// When the firmware or the kernel reports a TPM, wait at most this many seconds for `/dev/tpmrm0` (as the 4a initrd probe did).
const WAIT_DEV_SECS: u32 = 30;
const SEAL_ATTEMPTS: u32 = 3;
const SEAL_GAP: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpmVerdict {
    Usable,
    Unusable(Unusable),
    Undecided(String),
}

pub struct ProbeEnv<'a> {
    pub runner: &'a dyn Runner,
    /// Usually `/sys`.
    pub sysfs: &'a Path,
    /// Usually `/dev`.
    pub dev: &'a Path,
    pub sleep: &'a dyn Fn(Duration),
}

/// Decided in this order (Ruling 17):
///
/// 1. `udevadm settle --timeout=10`: let the coldplug events finish (the TPM driver loads there); a failure only logs a line and goes on.
/// 2. `systemd-analyze has-tpm2` reports `-libraries` / `-libtss2` missing -> cannot tell.
/// 3. No `<dev>/tpmrm0`: `has-tpm2` reports `-firmware` and `-driver` -> certainly none; otherwise look once a second, up to 30 times,
///    still none -> cannot tell.
/// 4. `<sysfs>/class/tpm/tpm0` without its `pcr-sha256` -> no SHA-256 bank (only SHA-1, or only SHA-384 and the like).
/// 5. `systemd-creds encrypt --with-key=tpm2` trial seal, up to three times, 2 seconds apart: one success -> usable; when all three fail,
///    `0x00000921` -> lockout, `0x000009a2` / `0x0000098e` -> owner password, anything else -> cannot tell.
pub fn probe(env: &ProbeEnv) -> TpmVerdict {
    let undecided = |why: String| TpmVerdict::Undecided(why);
    match env
        .runner
        .run(&Cmd::new("udevadm", &["settle", "--timeout=10"]).timeout(Duration::from_secs(20)))
    {
        Ok(o) if o.code == 0 => {}
        // stderr: the installer has no logger and this line must show on its screen; the agent's stderr goes to the journal
        Ok(o) => eprintln!(
            "udevadm settle exited with {}, going on with the TPM check",
            o.code
        ),
        Err(e) => eprintln!("udevadm settle did not run ({e:#}), going on with the TPM check"),
    }
    let has = match env.runner.run(&Cmd::new("systemd-analyze", &["has-tpm2"])) {
        // Exits non-zero when support is partial: read the output, not the exit code
        Ok(o) if o.code == 126 || o.code == 127 => {
            return undecided(format!(
                "systemd-analyze could not run (exit code {})",
                o.code
            ))
        }
        Ok(o) => format!("{} {}", o.stdout, o.stderr)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" "),
        Err(e) => return undecided(format!("systemd-analyze could not run: {e:#}")),
    };
    if has.contains("-libraries") || has.contains("-libtss2") {
        return undecided(format!(
            "systemd-analyze has-tpm2 reports missing libraries: {has}"
        ));
    }
    let rm = env.dev.join("tpmrm0");
    if !rm.exists() {
        if has.contains("-firmware") && has.contains("-driver") {
            return TpmVerdict::Unusable(Unusable::NoTpm);
        }
        // The firmware or the kernel says there is one: wait for the device (the driver may not be bound yet; not waiting would turn a usable TPM into "cannot tell")
        for _ in 0..WAIT_DEV_SECS {
            if rm.exists() {
                break;
            }
            (env.sleep)(Duration::from_secs(1));
        }
        if !rm.exists() {
            return undecided(format!(
                "the firmware or the kernel reports a TPM, but /dev/tpmrm0 did not appear within {WAIT_DEV_SECS} seconds"
            ));
        }
    }
    let tpm0 = env.sysfs.join("class/tpm/tpm0");
    if tpm0.exists() && !tpm0.join("pcr-sha256").exists() {
        return TpmVerdict::Unusable(Unusable::NoSha256Bank);
    }
    // Trial seal (with the SRK under the owner hierarchy, as repart does). stdin is empty, the ciphertext goes to stdout and is dropped.
    let seal = Cmd::new(
        "systemd-creds",
        &["encrypt", "--with-key=tpm2", "--name=probe", "-", "-"],
    );
    let mut last = String::new();
    for attempt in 1..=SEAL_ATTEMPTS {
        if attempt > 1 {
            (env.sleep)(SEAL_GAP);
        }
        match env.runner.run(&seal) {
            Ok(o) if o.code == 0 => return TpmVerdict::Usable,
            Ok(o) if o.code == 126 || o.code == 127 => {
                return undecided(format!(
                    "systemd-creds could not run (exit code {})",
                    o.code
                ))
            }
            Ok(o) => last = o.stderr.split_whitespace().collect::<Vec<_>>().join(" "),
            Err(e) => return undecided(format!("systemd-creds could not run: {e:#}")),
        }
    }
    // All three failed: only known TPM return codes mean "certainly unusable"
    //   0x921  TPM_RC_LOCKOUT: DA lockout (creating an object under the SRK goes through DA)
    //   0x9a2  TPM_RC_BAD_AUTH (session 1), 0x98e TPM_RC_AUTH_FAIL (session 1): the owner hierarchy has a password
    if last.contains("0x00000921") {
        TpmVerdict::Unusable(Unusable::Lockout)
    } else if last.contains("0x000009a2") || last.contains("0x0000098e") {
        TpmVerdict::Unusable(Unusable::OwnerAuth)
    } else {
        undecided(format!(
            "three trial seals failed with an unknown error: {last}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::{FakeRunner, Output};
    use std::cell::Cell;

    const CREDS: &str = "systemd-creds encrypt --with-key=tpm2 --name=probe - -";
    const HAS_ALL: &str = "yes\n+firmware\n+driver\n+system\n+subsystem\n+libraries\n";
    const HAS_NONE: &str = "no\n-firmware\n-driver\n+system\n+subsystem\n+libraries\n";

    /// A fake machine: sysfs and dev are temporary directories. With `tpm`, there is a tpm0 (with a SHA-256 bank) and tpmrm0.
    struct Machine {
        _tmp: tempfile::TempDir,
        sysfs: std::path::PathBuf,
        dev: std::path::PathBuf,
        fake: FakeRunner,
        sleeps: Cell<u32>,
    }

    fn machine(tpm: bool) -> Machine {
        let tmp = tempfile::tempdir().unwrap();
        let sysfs = tmp.path().join("sys");
        let dev = tmp.path().join("dev");
        std::fs::create_dir_all(&sysfs).unwrap();
        std::fs::create_dir_all(&dev).unwrap();
        if tpm {
            std::fs::create_dir_all(sysfs.join("class/tpm/tpm0/pcr-sha256")).unwrap();
            std::fs::write(dev.join("tpmrm0"), "").unwrap();
        }
        Machine {
            _tmp: tmp,
            sysfs,
            dev,
            fake: FakeRunner::new(),
            sleeps: Cell::new(0),
        }
    }

    impl Machine {
        fn probe_with(&self, on_sleep: &dyn Fn(u32)) -> TpmVerdict {
            let sleep = |_d: Duration| {
                self.sleeps.set(self.sleeps.get() + 1);
                on_sleep(self.sleeps.get());
            };
            probe(&ProbeEnv {
                runner: &self.fake,
                sysfs: &self.sysfs,
                dev: &self.dev,
                sleep: &sleep,
            })
        }

        fn probe(&self) -> TpmVerdict {
            self.probe_with(&|_| {})
        }

        fn has(&self, out: &str) {
            self.fake
                .respond("systemd-analyze has-tpm2", Output::ok(out));
        }

        fn creds(&self, out: Output) {
            self.fake.respond(CREDS, out);
        }

        fn creds_calls(&self) -> usize {
            self.fake.calls().iter().filter(|c| *c == CREDS).count()
        }
    }

    fn tpm_err(code: &str) -> Output {
        Output::fail(
            1,
            &format!("WARNING:esys:src/tss2-esys/api/Esys_CreatePrimary.c:401:Esys_CreatePrimary_Finish() Received TPM Error\nERROR:esys:… ErrorCode ({code})\nFailed to generate primary key in TPM: Unknown error\n"),
        )
    }

    #[test]
    fn no_tpm2_is_unusable() {
        let m = machine(false);
        m.has(HAS_NONE);
        assert_eq!(m.probe(), TpmVerdict::Unusable(Unusable::NoTpm));
        assert_eq!(m.creds_calls(), 0);
        assert_eq!(
            m.sleeps.get(),
            0,
            "certainly none: no waiting for the device"
        );
        // udevadm settle first (coldplug events done), then has-tpm2
        let calls = m.fake.calls();
        assert_eq!(calls[0], "udevadm settle --timeout=10", "{calls:?}");
        assert_eq!(calls[1], "systemd-analyze has-tpm2", "{calls:?}");
    }

    #[test]
    fn sha1_only_bank_is_unusable() {
        // Only SHA-1 enabled, or only SHA-384: both are "no SHA-256 bank", and the reason does not say "only SHA-1"
        for bank in ["pcr-sha1", "pcr-sha384"] {
            let m = machine(true);
            std::fs::remove_dir(m.sysfs.join("class/tpm/tpm0/pcr-sha256")).unwrap();
            std::fs::create_dir_all(m.sysfs.join("class/tpm/tpm0").join(bank)).unwrap();
            m.has(HAS_ALL);
            assert_eq!(
                m.probe(),
                TpmVerdict::Unusable(Unusable::NoSha256Bank),
                "{bank}"
            );
            assert_eq!(m.creds_calls(), 0);
        }
        let t = Unusable::NoSha256Bank.text();
        assert!(
            t.contains("no SHA-256 PCR bank") && !t.contains("SHA-1"),
            "{t}"
        );
    }

    #[test]
    fn lockout_is_unusable() {
        let m = machine(true);
        m.has(HAS_ALL);
        for _ in 0..3 {
            m.creds(tpm_err("0x00000921"));
        }
        assert_eq!(m.probe(), TpmVerdict::Unusable(Unusable::Lockout));
        assert_eq!(m.creds_calls(), 3);
    }

    #[test]
    fn owner_password_is_unusable() {
        for code in ["0x000009a2", "0x0000098e"] {
            let m = machine(true);
            m.has(HAS_ALL);
            for _ in 0..3 {
                m.creds(tpm_err(code));
            }
            assert_eq!(
                m.probe(),
                TpmVerdict::Unusable(Unusable::OwnerAuth),
                "{code}"
            );
            assert_eq!(m.creds_calls(), 3);
        }
    }

    #[test]
    fn unknown_error_is_undecided() {
        let m = machine(true);
        m.has(HAS_ALL);
        for _ in 0..3 {
            m.creds(tpm_err("0x00000101"));
        }
        assert!(matches!(m.probe(), TpmVerdict::Undecided(_)));
        assert_eq!(m.creds_calls(), 3);
        // A one-off error does not end it either: 2 seconds between two trial seals
        assert_eq!(m.sleeps.get(), 2);
    }

    #[test]
    fn missing_libs_is_undecided() {
        for out in [
            "partial\n+firmware\n+driver\n+system\n+subsystem\n-libraries\n",
            "partial\n+firmware\n+driver\n+system\n+subsystem\n-libraries\n-libtss2-esys.so.0\n",
        ] {
            let m = machine(true);
            m.has(out);
            assert!(matches!(m.probe(), TpmVerdict::Undecided(_)), "{out}");
            assert_eq!(m.creds_calls(), 0);
        }
        // has-tpm2 that cannot run is "cannot tell" too (FakeRunner can only give an exit code: 127 = no such command)
        let m = machine(true);
        m.fake
            .respond("systemd-analyze has-tpm2", Output::fail(127, ""));
        m.creds(Output::fail(127, ""));
        m.creds(Output::fail(127, ""));
        m.creds(Output::fail(127, ""));
        assert!(matches!(m.probe(), TpmVerdict::Undecided(_)));
    }

    #[test]
    fn healthy_tpm_is_usable() {
        let m = machine(true);
        m.has(HAS_ALL);
        assert_eq!(m.probe(), TpmVerdict::Usable);
        assert_eq!(m.creds_calls(), 1);
        // Succeeding on the second trial seal counts too
        let m = machine(true);
        m.has(HAS_ALL);
        m.creds(tpm_err("0x00000922"));
        m.creds(Output::ok("ciphertext"));
        assert_eq!(m.probe(), TpmVerdict::Usable);
        assert_eq!(m.creds_calls(), 2);
        // A failed udevadm settle only logs a line and goes on
        let m = machine(true);
        m.fake.respond("udevadm settle", Output::fail(1, "timeout"));
        m.has(HAS_ALL);
        assert_eq!(m.probe(), TpmVerdict::Usable);
    }

    #[test]
    fn probe_waits_for_tpmrm0() {
        // has-tpm2 lacks only -driver (driver not bound yet); tpmrm0 shows up after 3 tries
        let m = machine(true);
        std::fs::remove_file(m.dev.join("tpmrm0")).unwrap();
        m.has("partial\n+firmware\n-driver\n+system\n+subsystem\n+libraries\n");
        let dev = m.dev.clone();
        let v = m.probe_with(&|n| {
            if n == 3 {
                std::fs::write(dev.join("tpmrm0"), "").unwrap();
            }
        });
        assert_eq!(v, TpmVerdict::Usable);
        assert_eq!(m.sleeps.get(), 3);
        // Never shows up: waits all 30 times, cannot tell
        let m = machine(true);
        std::fs::remove_file(m.dev.join("tpmrm0")).unwrap();
        m.has("partial\n+firmware\n-driver\n+system\n+subsystem\n+libraries\n");
        assert_eq!(
            m.probe(),
            TpmVerdict::Undecided("the firmware or the kernel reports a TPM, but /dev/tpmrm0 did not appear within 30 seconds".into())
        );
        assert_eq!(m.sleeps.get(), 30);
        assert_eq!(m.creds_calls(), 0);
    }
}
