//! mastersos-installer: the decision logic of the installer (`mastersos-installer`) and of the first-boot program for
//! unmanaged machines (`mastersos-firstrun`). The two binaries only do I/O; choosing the disk, reading the seed and
//! ordering the commands all happen here, testable on the host.
//!
//! Everything the installer shows is English only: the console font has no CJK glyphs.
#![forbid(unsafe_code)]

pub mod disk;
pub mod firstrun;
pub mod mode;
pub mod plan;
pub mod precheck;
pub mod seed;
pub mod tty;

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Result};
use mastersos_agent::runner::{run_ok, Cmd, Runner};
use mastersos_agent::tpm::{self, ProbeEnv};

use disk::{choose_target, installer_disk, mark_ventoy_disk, parse_lsblk, Disk, Target};
use mode::{mode_from_cmdline, Mode, VENTOY_FOLDER, VENTOY_MOUNT, VENTOY_PART_FILE};
use plan::{
    confirm_text, finish_text, is_best_effort, missing_sources, mok_hash_cmd, mok_step, plan,
    tpm_refusal_text, write_mok_hash, Facts, MokStep, MOK_HASH_FILE, SEED_DIR, USB_SEED_DIR,
};
use precheck::{precheck, Level, PrecheckEnv, Profile};
use seed::{
    choose_seed, debug_flag_present, locate_seeds, refuse_if_all_invalid, write_debug_flag,
    write_seed_dir, SeedFile, SeedSource,
};
use tty::Tty;

/// The error text when the technician answers anything but `y`.
pub const CANCELLED: &str = "Cancelled";

/// The line the failure screen ends with; Enter then reboots.
pub const RESTART_PROMPT: &str = "Press Enter to restart.";

/// The external state the install flow reads (tests swap in temporary directories and fake seeds).
pub struct InstallEnv<'a> {
    /// Usually `/sys`.
    pub sysfs: &'a Path,
    /// Usually `/dev`.
    pub dev: &'a Path,
    /// Usually `/proc` (mounts and swaps for the disk report before and after `systemd-repart`).
    pub proc_dir: &'a Path,
    pub sleep: &'a dyn Fn(Duration),
    /// Reads the seeds on the stick; the arguments are the seed folder and the partition it must be mounted from (usually
    /// [`locate_seeds`], which first checks that the folder really is that partition's mount). `Err` is a refusal reason.
    pub locate_seeds: &'a dyn Fn(&SeedSource) -> Result<Vec<SeedFile>, String>,
    /// Stick (whole-stick installer) or Ventoy, from the kernel command line.
    pub mode: Mode,
    /// Ventoy mode: file the initrd wrote with the exFAT partition's device (usually [`VENTOY_PART_FILE`]).
    pub ventoy_part_file: &'a Path,
    /// Ventoy mode: where the initrd mounted that partition (usually [`VENTOY_MOUNT`]).
    pub ventoy_mount: &'a Path,
    /// Release or lab (the pre-install Secure Boot certificate check: release refuses, lab warns).
    pub profile: Profile,
    /// The shim to be installed (usually [`precheck::SHIM`]).
    pub shim: &'a Path,
    /// Where the pre-install check writes temporary PEMs (usually `/run`).
    pub tmp: &'a Path,
    /// How to restart after the finish screen (usually [`Restart::system`]).
    pub restart: Restart<'a>,
}

/// An install step failed after the target disk had been changed: the failure screen must not say the disk is untouched.
#[derive(Debug)]
pub struct DiskWritten {
    /// The target disk, e.g. `/dev/nvme0n1`.
    pub disk: String,
    /// The system was fully copied (the failure came in the steps after: boot entry, MOK, sync).
    pub copied: bool,
    pub error: anyhow::Error,
}

impl std::fmt::Display for DiskWritten {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.error)
    }
}

impl std::error::Error for DiskWritten {}

/// The text of the failure screen: the reason, then what happened to the disk. Without a [`DiskWritten`] in the error
/// nothing was written to any internal disk (every refusal and every failure before the old partition table is released).
pub fn failure_text(e: &anyhow::Error) -> String {
    if let Some(w) = e.downcast_ref::<DiskWritten>() {
        let disk = if w.copied {
            format!(
                "MastersOS was copied to {}, but the setup did not finish.\nRun the installer again to be safe.",
                w.disk
            )
        } else {
            format!(
                "The disk {} was erased and MastersOS is not installed on it.\nRun the installer again.",
                w.disk
            )
        };
        return format!("\nInstallation failed\nReason: {:#}\n\n{disk}\n", w.error);
    }
    let head = if e.chain().count() == 1 && e.to_string() == CANCELLED {
        "\nInstallation cancelled\n".to_string()
    } else {
        format!("\nInstallation failed\nReason: {e:#}\n")
    };
    format!("{head}\nThe disk has not been touched.\n")
}

/// How the installer restarts the machine.
#[derive(Clone, Copy)]
pub struct Restart<'a> {
    /// Usually `/proc/sysrq-trigger`: the fallback when `systemctl reboot` fails (the stick holding /usr was pulled, ...).
    pub sysrq: &'a Path,
    pub sleep: &'a dyn Fn(Duration),
}

impl Restart<'static> {
    pub fn system() -> Restart<'static> {
        Restart {
            sysrq: Path::new("/proc/sysrq-trigger"),
            sleep: &std::thread::sleep,
        }
    }
}

/// Shows the failure screen and waits for Enter, then reboots. Never an emergency shell: when the input is closed the screen
/// simply stays. Input typed before the question (an Enter during the copy) is dropped first, so the reason is read.
pub fn fail_and_restart(r: &dyn Runner, tty: &mut dyn Tty, e: &anyhow::Error, restart: Restart) {
    tty.say(&failure_text(e));
    ask_and_restart(r, tty, RESTART_PROMPT, restart);
}

/// Drops input typed earlier, shows `prompt`, and reboots once a line is read (an unreadable answer: no reboot).
pub fn ask_and_restart(r: &dyn Runner, tty: &mut dyn Tty, prompt: &str, restart: Restart) {
    tty.flush_input();
    if tty.prompt(prompt).is_ok() {
        reboot(r, tty, restart);
    }
}

/// `systemctl reboot`; when that fails (no /usr any more, ...), the kernel's sysrq trigger: sync, remount read-only, reboot.
/// Writing to /proc needs no binary from /usr.
pub fn reboot(r: &dyn Runner, tty: &mut dyn Tty, restart: Restart) {
    let why = match r.run(&Cmd::new("systemctl", &["reboot"])) {
        Ok(o) if o.code == 0 => return,
        Ok(o) => format!("systemctl reboot exited with {}", o.code),
        Err(e) => format!("{e:#}"),
    };
    tty.say(&format!(
        "Could not restart ({why}); restarting through the kernel ..."
    ));
    for k in ["s", "u", "b"] {
        if let Err(e) = std::fs::write(restart.sysrq, k) {
            tty.say(&format!(
                "Could not restart ({e}): hold the power button to turn the computer off."
            ));
            return;
        }
        if k != "b" {
            (restart.sleep)(Duration::from_secs(1));
        }
    }
}

/// The screen after a panic (a bug): nothing is known about the disk, so it says so, then waits for Enter and restarts.
pub fn panic_text(info: &str) -> String {
    format!(
        "\nInstallation failed\nReason: internal error: {info}\n\n\
         If the installer had started writing the disk, MastersOS is not installed on it.\nRun the installer again.\n"
    )
}

/// The installer's whole flow (`main` only wires it up).
pub fn run_install(r: &dyn Runner, tty: &mut dyn Tty, sysfs: &Path, dev: &Path) -> Result<()> {
    run_install_with(
        r,
        tty,
        &InstallEnv {
            sysfs,
            dev,
            proc_dir: Path::new("/proc"),
            sleep: &std::thread::sleep,
            locate_seeds: &|src| locate_seeds(&src.dir, src.part.as_deref()),
            // An unreadable /proc/cmdline falls back to Stick mode.
            mode: mode_from_cmdline(&std::fs::read_to_string("/proc/cmdline").unwrap_or_default()),
            ventoy_part_file: Path::new(VENTOY_PART_FILE),
            ventoy_mount: Path::new(VENTOY_MOUNT),
            profile: Profile::detect(Path::new("/")),
            shim: Path::new(precheck::SHIM),
            tmp: Path::new("/run"),
            restart: Restart::system(),
        },
    )
}

fn pick(tty: &mut dyn Tty, disks: Vec<Disk>) -> Result<Disk> {
    tty.say("Several disks available:");
    for (i, d) in disks.iter().enumerate() {
        tty.say(&format!(
            "  {}) {} {} ({} GiB)",
            i + 1,
            d.path,
            d.model.as_deref().unwrap_or("?"),
            d.size / (1024 * 1024 * 1024)
        ));
    }
    loop {
        let n = tty.prompt("Number: ")?;
        if let Some(d) = n
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|i| disks.get(i.wrapping_sub(1)))
        {
            return Ok(d.clone());
        }
    }
}

pub fn run_install_with(r: &dyn Runner, tty: &mut dyn Tty, env: &InstallEnv) -> Result<()> {
    let lsblk = run_ok(
        r,
        Cmd::new(
            "lsblk",
            &[
                "-J",
                "-b",
                "-o",
                "NAME,PATH,TYPE,SIZE,RM,TRAN,MODEL,PARTLABEL",
            ],
        ),
    )?;
    let mut disks = parse_lsblk(&lsblk)?;
    // The seed must come from this installer stick's seed partition; when it is not mounted the install is refused, never treated as "no seed".
    let source = match &env.mode {
        Mode::Stick => SeedSource {
            dir: USB_SEED_DIR.into(),
            part: installer_disk(&disks)?.seed_part.clone(),
        },
        // Ventoy: the initrd recorded the exFAT partition it attached; the seed folder must be its mount.
        Mode::Ventoy { .. } => {
            let part = std::fs::read_to_string(env.ventoy_part_file)
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            if part.is_empty() {
                bail!("MastersOS folder on the Ventoy stick not found\nUnzip the download to the root of the Ventoy stick");
            }
            mark_ventoy_disk(&mut disks, &part)?;
            SeedSource {
                dir: env.ventoy_mount.join(VENTOY_FOLDER),
                part: Some(part),
            }
        }
    };
    // Read and validate early: a stick with only bad seeds refuses before anything else. Which seed to use is asked later.
    let seeds = (env.locate_seeds)(&source)
        .map_err(|why| anyhow::anyhow!("The seed is invalid, refusing to install: {why}"))?;
    refuse_if_all_invalid(&seeds)?;
    // A TPM 2.0 (with a SHA-256 PCR bank) is required (Ruling 17): before choosing the disk, the confirm screen and any command that writes a disk, seed or not.
    tty.say("Checking TPM 2.0 ...");
    let verdict = tpm::probe(&ProbeEnv {
        runner: r,
        sysfs: env.sysfs,
        dev: env.dev,
        sleep: env.sleep,
    });
    if let Some(why) = tpm_refusal_text(&verdict) {
        bail!("{why}");
    }
    // Hardware and Secure Boot certificates (4b Task 22, spec §6.3): also before choosing the disk. Every refusal is listed and the disk is left alone; warnings only continue after y
    tty.say("Checking hardware and Secure Boot certificates ...");
    let findings = precheck(&PrecheckEnv {
        runner: r,
        sysfs: env.sysfs,
        profile: env.profile,
        shim: env.shim,
        tmp: env.tmp,
    });
    let refusals: Vec<&str> = findings
        .iter()
        .filter(|f| f.level == Level::Refuse)
        .map(|f| f.text.as_str())
        .collect();
    let warns: Vec<&str> = findings
        .iter()
        .filter(|f| f.level == Level::Warn)
        .map(|f| f.text.as_str())
        .collect();
    let advice = precheck::advice(&findings, env.profile);
    if !refusals.is_empty() {
        let mut msg = refusals.join("\n\n");
        if let Some(a) = &advice {
            msg.push('\n');
            msg.push_str(a);
        }
        if !warns.is_empty() {
            msg.push_str("\n\nAlso:\n");
            msg.push_str(&warns.join("\n"));
        }
        bail!("{msg}");
    }
    if !warns.is_empty() {
        tty.say("Warnings:");
        for w in &warns {
            tty.say(&format!("- {w}"));
        }
        if let Some(a) = &advice {
            tty.say(a);
        }
        if tty
            .prompt("There are warnings above, type y to continue: ")?
            .trim()
            != "y"
        {
            bail!(CANCELLED);
        }
    }
    // After the TPM and hardware checks, before the disk: several seeds are chosen from a list (one valid seed is used silently).
    let seed = choose_seed(&seeds, tty)?;
    // The disk is chosen after the TPM check: a machine without a TPM should not have someone pick a disk only to be refused
    let target = match choose_target(&disks) {
        Target::One(d) => d,
        Target::Choose(v) => pick(tty, v)?,
        Target::None => bail!("No suitable internal disk (>= 48 GiB, not USB)"),
    };
    if tty.prompt(&confirm_text(&target, &seed))?.trim() != "y" {
        bail!(CANCELLED);
    }
    let mut facts = Facts::detect(r)?;
    facts.ventoy = matches!(env.mode, Mode::Ventoy { .. });
    // Before erasing the disk, make sure every source to copy is there.
    let missing = missing_sources(&facts, &|p| Path::new(p).exists());
    if !missing.is_empty() {
        bail!("Missing install files: {}", missing.join(", "));
    }
    if mok_step(&facts) == MokStep::Import {
        let hash = run_ok(r, mok_hash_cmd())?;
        write_mok_hash(Path::new(MOK_HASH_FILE), &hash)?;
    }
    write_seed_dir(Path::new(SEED_DIR), &seed)?;
    // Developer diagnostics: repart's CopyFiles= copies the whole folder into the seed partition
    if debug_flag_present(&source.dir) {
        write_debug_flag(Path::new(SEED_DIR))?;
    }
    run_plan(
        r,
        tty,
        plan(&target, &seed, &facts)?,
        &target,
        env.sysfs,
        env.proc_dir,
        env.sleep,
    )?;
    // The install worked: an unreadable answer only means no reboot (the finish screen stays).
    ask_and_restart(r, tty, &finish_text(mok_step(&facts)), env.restart);
    Ok(())
}

/// Inside `udevadm lock` (udev neither starts nor runs a probe of the disk meanwhile): wipe the signatures of every old
/// partition, then the disk's own partition table signatures, then have the kernel re-read the now empty table.
/// Arguments: the disk, then its old partitions; a partition node that is gone already (an earlier try, a probe) is skipped,
/// so it is not mistaken for one still in use.
pub const RELEASE_SCRIPT: &str =
    "d=$1; shift; for p in \"$@\"; do [ -b \"$p\" ] || continue; wipefs --all --force \"$p\" || exit 1; done; \
                                  wipefs --all --force \"$d\" && blockdev --rereadpt \"$d\"";

/// How many times [`release_disk`] tries before giving up, and how long it waits between tries.
pub const RELEASE_TRIES: u32 = 5;
pub const RELEASE_WAIT: Duration = Duration::from_secs(2);

/// `udevadm settle` with a bound: a stuck event must not hang the release (5 tries x 30 s at worst).
pub fn settle_cmd() -> Cmd {
    Cmd::new("udevadm", &["settle", "--timeout=30"])
}

/// The command of one [`release_disk`] try (the lock waits at most 30 s for udev to let go of the disk).
pub fn release_cmd(disk: &str, parts: &[String]) -> Cmd {
    let mut args = vec![
        "lock".to_string(),
        format!("--device={disk}"),
        "--timeout=30".to_string(),
        "sh".to_string(),
        "-c".to_string(),
        RELEASE_SCRIPT.to_string(),
        "sh".to_string(),
        disk.to_string(),
    ];
    args.extend(parts.iter().cloned());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    Cmd::new("udevadm", &args)
}

/// Makes the target disk empty from the kernel's point of view before `systemd-repart` writes the new table.
///
/// Found on a laptop that had run ChromeOS Flex (12 partitions, a layout unlike ours): `systemd-repart` wrote the table and
/// then failed with "Failed to reread partition table: Device or resource busy". The kernel must delete the old partitions
/// that differ from the new table, and something (a udev probe) had one of them open at that moment. A disk that already
/// carries our layout, or a blank one, has nothing to delete, which is why reinstalls always worked.
///
/// So: `udevadm settle`, then under `udevadm lock` wipe the old partitions' and the disk's signatures and re-read the
/// (now empty) table, up to [`RELEASE_TRIES`] times with `udevadm settle` in between. When the kernel still cannot drop the
/// old partitions, the full disk report goes to the screen and the error names the busy partitions.
#[allow(clippy::too_many_arguments)]
pub fn release_disk(
    r: &dyn Runner,
    tty: &mut dyn Tty,
    disk: &str,
    parts: &[String],
    sysfs: &Path,
    proc_dir: &Path,
    sleep: &dyn Fn(Duration),
) -> Result<()> {
    tty.say(&format!(
        "Releasing {disk}: removing the old partition table ..."
    ));
    let mut last = String::new();
    for i in 1..=RELEASE_TRIES {
        // Let udev finish what it is doing with the disk (a probe holds a partition open while it runs).
        tty.say(&format!("Releasing {disk}: try {i} of {RELEASE_TRIES} ..."));
        let _ = r.run(&settle_cmd());
        let c = release_cmd(disk, parts);
        if i == 1 {
            tty.say(&format!("-> {}", c.line()));
        }
        match run_ok(r, c) {
            Ok(_) => {
                let _ = r.run(&settle_cmd());
                return Ok(());
            }
            Err(e) => {
                last = format!("{e:#}");
                tty.say(&format!(
                    "Try {i} of {RELEASE_TRIES}: the kernel did not drop the old partitions ({last})"
                ));
            }
        }
        if i < RELEASE_TRIES {
            sleep(RELEASE_WAIT);
        }
    }
    tty.say("What holds the disk:");
    for l in disk_report(r, sysfs, proc_dir, disk, true) {
        tty.say(&l);
    }
    let busy = disk_holds(sysfs, proc_dir, disk).busy();
    let busy = if busy.is_empty() {
        "no holder, mount or swap found, something else has a partition open".to_string()
    } else {
        format!("busy: {}", busy.join(", "))
    };
    bail!("The disk {disk} could not be released: an old partition is still in use ({busy}; last error: {last})")
}

/// Runs the install commands. Right before `systemd-repart`: a short report of what holds the target disk, then
/// [`release_disk`]; when `systemd-repart` fails, the full report (lsblk, holders, mounts, swaps, device-mapper). From
/// the release on the disk counts as written: any error is wrapped in [`DiskWritten`].
pub fn run_plan(
    r: &dyn Runner,
    tty: &mut dyn Tty,
    cmds: Vec<Cmd>,
    target: &Disk,
    sysfs: &Path,
    proc_dir: &Path,
    sleep: &dyn Fn(Duration),
) -> Result<()> {
    let disk = target.path.as_str();
    let written_err = |e: anyhow::Error, copied: bool| -> anyhow::Error {
        DiskWritten {
            disk: disk.to_string(),
            copied,
            error: e,
        }
        .into()
    };
    let mut written = false;
    // Everything before the boot entry (repart with the /usr copy, the ESP files) succeeded: MastersOS is on the disk.
    let mut copied = false;
    for c in cmds {
        let repart = c.program == "systemd-repart";
        if c.program == "efibootmgr" {
            copied = true;
        }
        if repart {
            for l in disk_report(r, sysfs, proc_dir, disk, false) {
                tty.say(&l);
            }
            written = true;
            release_disk(r, tty, disk, &target.parts, sysfs, proc_dir, sleep)
                .map_err(|e| written_err(e, false))?;
        }
        tty.say(&format!("-> {}", c.line()));
        if is_best_effort(&c) {
            // The disk is already written: warn and carry on to the finish screen.
            match r.run(&c) {
                Ok(o) if o.code == 0 => {}
                Ok(o) => tty.say(&format!(
                    "Warning: {} exited with {}; continuing",
                    c.program, o.code
                )),
                Err(e) => tty.say(&format!(
                    "Warning: {} failed ({e:#}); continuing",
                    c.program
                )),
            }
            continue;
        }
        if let Err(e) = run_ok(r, c) {
            if repart {
                tty.say("systemd-repart failed. What holds the disk:");
                for l in disk_report(r, sysfs, proc_dir, disk, true) {
                    tty.say(&l);
                }
            }
            return Err(if written { written_err(e, copied) } else { e });
        }
    }
    Ok(())
}

/// The kernel name of a disk or partition path (`/dev/nvme0n1` -> `nvme0n1`).
fn kname(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Names of the entries of a directory, sorted; empty when it cannot be read.
fn dir_names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|it| {
            it.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Lines of `<proc_dir>/<file>` whose first field is one of `devs`; `None` when the file cannot be read.
fn proc_lines(proc_dir: &Path, file: &str, devs: &BTreeSet<String>) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(proc_dir.join(file)).ok()?;
    Some(
        text.lines()
            .filter(|l| {
                l.split_whitespace()
                    .next()
                    .is_some_and(|d| devs.contains(d))
            })
            .map(str::to_string)
            .collect(),
    )
}

/// What holds a disk, from sysfs and /proc.
pub struct DiskHolds {
    /// The disk's kernel name, then its partitions' (sub-directories of the disk's sysfs directory with a `partition` file).
    pub nodes: Vec<String>,
    /// (node, holder kernel name, device-mapper name if any).
    pub holders: Vec<(String, String, Option<String>)>,
    /// Lines of /proc/mounts for the disk, its partitions and their holders; `None` when unreadable.
    pub mounts: Option<Vec<String>>,
    /// Lines of /proc/swaps, the same way.
    pub swaps: Option<Vec<String>>,
}

impl DiskHolds {
    /// `/dev/<node>` of every node that has a holder, or whose device (or a holder's) is mounted or used as swap.
    pub fn busy(&self) -> Vec<String> {
        let first = |l: &String| l.split_whitespace().next().unwrap_or("").to_string();
        let used: BTreeSet<String> = self
            .mounts
            .iter()
            .chain(self.swaps.iter())
            .flatten()
            .map(first)
            .collect();
        self.nodes
            .iter()
            .filter(|n| {
                used.contains(&format!("/dev/{n}"))
                    || self.holders.iter().any(|(node, _, _)| node == *n)
            })
            .map(|n| format!("/dev/{n}"))
            .collect()
    }
}

pub fn disk_holds(sysfs: &Path, proc_dir: &Path, disk: &str) -> DiskHolds {
    let name = kname(disk);
    let block = sysfs.join("class/block");
    let mut nodes = vec![name.to_string()];
    nodes.extend(
        dir_names(&block.join(name))
            .into_iter()
            .filter(|p| block.join(name).join(p).join("partition").exists()),
    );
    let mut devs: BTreeSet<String> = nodes.iter().map(|n| format!("/dev/{n}")).collect();
    let mut holders = Vec::new();
    for n in &nodes {
        for h in dir_names(&block.join(n).join("holders")) {
            let dm = std::fs::read_to_string(block.join(&h).join("dm/name"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            devs.insert(format!("/dev/{h}"));
            if let Some(dm) = &dm {
                devs.insert(format!("/dev/mapper/{dm}"));
            }
            holders.push((n.clone(), h, dm));
        }
    }
    DiskHolds {
        mounts: proc_lines(proc_dir, "mounts", &devs),
        swaps: proc_lines(proc_dir, "swaps", &devs),
        nodes,
        holders,
    }
}

/// What holds the target disk, as screen lines: its partitions' holders (device-mapper and the like, from sysfs), and the
/// lines of /proc/mounts and /proc/swaps for the disk, its partitions and their holders. `full` adds `lsblk` and
/// `dmsetup ls` (both through the runner; a missing tool is reported, never an error).
pub fn disk_report(
    r: &dyn Runner,
    sysfs: &Path,
    proc_dir: &Path,
    disk: &str,
    full: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    let h = disk_holds(sysfs, proc_dir, disk);
    if full {
        out.push(format!(
            "lsblk -o NAME,SIZE,FSTYPE,PARTLABEL,MOUNTPOINTS {disk}:"
        ));
        match run_ok(
            r,
            Cmd::new(
                "lsblk",
                &["-o", "NAME,SIZE,FSTYPE,PARTLABEL,MOUNTPOINTS", disk],
            ),
        ) {
            Ok(s) => out.extend(s.lines().map(|l| format!("  {l}"))),
            Err(e) => out.push(format!("  lsblk failed: {e:#}")),
        }
    }
    let holders: Vec<String> = h
        .holders
        .iter()
        .map(|(n, k, dm)| match dm {
            Some(dm) => format!("{n} -> {k} (/dev/mapper/{dm})"),
            None => format!("{n} -> {k}"),
        })
        .collect();
    let list = |v: &[String]| {
        if v.is_empty() {
            "none".to_string()
        } else {
            v.join(", ")
        }
    };
    out.push(format!(
        "Disk {disk}: partitions {}; holders {}",
        list(&h.nodes[1..]),
        list(&holders)
    ));
    for (title, v) in [("mounted", h.mounts), ("swap", h.swaps)] {
        match v {
            None => out.push(format!("  {title}: cannot read")),
            Some(v) if v.is_empty() => out.push(format!("  {title}: none")),
            Some(v) => {
                out.push(format!("  {title}:"));
                out.extend(v.into_iter().map(|l| format!("    {l}")));
            }
        }
    }
    if full {
        match r.run(&Cmd::new("dmsetup", &["ls"])) {
            Ok(o) if o.code == 0 => {
                out.push("  dmsetup ls:".to_string());
                out.extend(o.stdout.lines().map(|l| format!("    {l}")));
            }
            Ok(o) => out.push(format!(
                "  dmsetup ls: not available (exit code {})",
                o.code
            )),
            Err(e) => out.push(format!("  dmsetup ls: not available ({e:#})")),
        }
    }
    out
}
