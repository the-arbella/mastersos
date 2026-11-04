//! Reads the seeds in `MASTERSOS-SEED` on the stick: `seed.toml` and `seed-<name>.toml`. A stick whose seeds are all invalid
//! refuses the install, never falling back to an unmanaged install (Ruling 11); one valid seed is used without a question,
//! several are chosen from a numbered list. The chosen one is installed as `seed.toml`. Reason texts never carry seed content
//! (it holds the `fetch_token` and Wi-Fi passwords); the few fields shown (school, server, SSID, file name) are ASCII-sanitized.

use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use anyhow::{bail, Context, Result};
use mastersos_bundle::Seed;

use crate::tty::Tty;

/// Where to read the seed from and which partition that directory must be the mount of.
#[derive(Debug, Clone)]
pub struct SeedSource {
    pub dir: std::path::PathBuf,
    /// Device path of the partition `dir` must be mounted from; `None` = none expected.
    pub part: Option<String>,
}

pub const MAX_SEED_BYTES: u64 = mastersos_bundle::MAX_SEED_BYTES as u64;

#[derive(Debug, Clone)]
pub enum SeedFound {
    None,
    Valid { text: String, seed: Box<Seed> },
    Invalid(String),
}

fn invalid(why: &str) -> SeedFound {
    SeedFound::Invalid(why.to_string())
}

/// Line N (from 1); toml's error message quotes the offending line, which may be a token, so only the line number is used.
fn toml_error_line(text: &str) -> Option<usize> {
    let e = toml::from_str::<toml::Table>(text).err()?;
    let at = e.span()?.start.min(text.len());
    Some(
        text.as_bytes()[..at]
            .iter()
            .filter(|b| **b == b'\n')
            .count()
            + 1,
    )
}

/// Whether the seed folder is the mount of the expected partition: the folder's device number (`stat(dir).st_dev`) must equal
/// the partition device node's `st_rdev`. No check when no seed partition is expected (`expected_part` is `None`).
/// A missing folder, nothing mounted, or something else mounted all return a reason.
pub fn check_seed_mount(
    expected_part: Option<&str>,
    dir_dev: Option<u64>,
    part_rdev: Option<u64>,
) -> Result<(), String> {
    let Some(part) = expected_part else {
        return Ok(());
    };
    let Some(dir_dev) = dir_dev else {
        return Err("the stick's seed partition is not mounted (the folder does not exist)".into());
    };
    let Some(part_rdev) = part_rdev else {
        return Err(format!("cannot stat the seed partition {part}"));
    };
    if dir_dev != part_rdev {
        return Err(
            "the stick's seed partition is not mounted (the folder is not its mount point)".into(),
        );
    }
    Ok(())
}

/// One seed file found on the stick.
#[derive(Debug, Clone)]
pub struct SeedFile {
    /// The file name as it is on the stick (lossy UTF-8).
    pub name: String,
    pub found: SeedFound,
}

const NAMING_RULE: &str =
    "seed files are named seed.toml or seed-<name>.toml (<name>: lowercase letters, digits, -)";

/// Replaces control and non-ASCII characters with `?`: the console font has no CJK glyphs and the text may come from a
/// hand-edited file.
pub fn ascii_display(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// [`ascii_display`], cut to at most `max` columns (the end becomes `...`).
pub fn display_fit(text: &str, max: usize) -> String {
    let t = ascii_display(text);
    if t.len() <= max {
        return t;
    }
    if max < 4 {
        return t[..max].to_string();
    }
    format!("{}...", &t[..max - 3])
}

/// [`ascii_display`], cut to at most `max` columns from the start (the start becomes `...`), so
/// the end stays visible: seed names often differ only at the end (`eis-primary-a`, `eis-primary-b`).
pub fn display_fit_tail(text: &str, max: usize) -> String {
    let t = ascii_display(text);
    if t.len() <= max {
        return t;
    }
    if max < 4 {
        return t[t.len() - max..].to_string();
    }
    format!("...{}", &t[t.len() - (max - 3)..])
}

/// The seed file name as the menu shows it: without the `seed-` prefix and `.toml` suffix (any
/// case), so `seed-eis-primary-a.toml` is `eis-primary-a` and `seed.toml` is `seed`.
pub fn seed_label(file_name: &str) -> &str {
    let mut name = file_name;
    if name.len() > 5 && name.is_char_boundary(name.len() - 5) {
        let (stem, ext) = name.split_at(name.len() - 5);
        if ext.eq_ignore_ascii_case(".toml") {
            name = stem;
        }
    }
    if name.len() > 5 && name.is_char_boundary(5) {
        let (prefix, rest) = name.split_at(5);
        if prefix.eq_ignore_ascii_case("seed-") {
            name = rest;
        }
    }
    name
}

/// The Wi-Fi summary of a seed: the first SSID, then ` +N` for the others, or `none`. Display-safe.
pub fn wifi_summary(seed: &Seed, max: usize) -> String {
    match seed.wifi.split_first() {
        None => "none".to_string(),
        Some((first, [])) => display_fit(&first.ssid, max),
        Some((first, rest)) => format!("{} +{}", display_fit(&first.ssid, max), rest.len()),
    }
}

/// Checks the mount first, then reads the seeds: a stick with a seed partition that is not mounted never counts as "no seed" (Ruling 11).
pub fn locate_seeds(dir: &Path, expected_part: Option<&str>) -> Result<Vec<SeedFile>, String> {
    use std::os::unix::fs::MetadataExt;
    let dir_dev = fs::metadata(dir).ok().map(|m| m.dev());
    let part_rdev = expected_part.and_then(|p| fs::metadata(p).ok().map(|m| m.rdev()));
    check_seed_mount(expected_part, dir_dev, part_rdev)?;
    read_seeds(dir)
}

/// `seed.toml` or `seed-<name>.toml` (already lowercased), `<name>` being lowercase letters, digits and `-`.
fn is_seed_name(lower: &str) -> bool {
    if lower == "seed.toml" {
        return true;
    }
    lower
        .strip_prefix("seed-")
        .and_then(|r| r.strip_suffix(".toml"))
        .is_some_and(|n| {
            !n.is_empty()
                && n.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Lists the seeds in the folder, sorted by file name. Every `.toml` is listed: one that is not named like a seed counts as
/// invalid (that is how a typo is caught). Files starting with `._` (macOS) are ignored. A missing folder is no seeds
/// (the caller checked the mount when one is expected).
pub fn read_seeds(dir: &Path) -> Result<Vec<SeedFile>, String> {
    const CANNOT_READ: &str = "cannot read the seed folder on the stick";
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(_) => return Err(CANNOT_READ.into()),
    };
    let mut files = Vec::new();
    for e in entries {
        let e = e.map_err(|_| CANNOT_READ.to_string())?;
        let name = e.file_name().to_string_lossy().into_owned();
        let lower = name.to_lowercase();
        if name.starts_with("._") || !lower.ends_with(".toml") {
            continue;
        }
        let found = if is_seed_name(&lower) {
            parse_seed_file(&dir.join(e.file_name()))
        } else {
            SeedFound::Invalid(format!("{}: {NAMING_RULE}", ascii_display(&name)))
        };
        files.push(SeedFile { name, found });
    }
    files.sort_by_key(|f| (f.name.to_lowercase(), f.name.clone()));
    Ok(files)
}

/// Reads and checks one seed file. Reasons name the file and never carry seed content.
pub fn parse_seed_file(path: &Path) -> SeedFound {
    let shown = ascii_display(
        &path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
    );
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => {}
        _ => return invalid(&format!("{shown} is not a regular file")),
    }
    let mut buf = Vec::new();
    let read = fs::File::open(path).and_then(|f| f.take(MAX_SEED_BYTES + 1).read_to_end(&mut buf));
    if read.is_err() {
        return invalid(&format!("cannot read {shown}"));
    }
    if buf.len() as u64 > MAX_SEED_BYTES {
        return invalid(&format!("{shown} is larger than 64 KiB"));
    }
    let Ok(text) = String::from_utf8(buf) else {
        return invalid(&format!("{shown} is not UTF-8 text"));
    };
    let seed = match Seed::parse(&text) {
        Ok(s) => s,
        // A well-formed seed the bundle crate refuses on its meaning (e.g. a cloud seed without
        // its fetch_token): its message says what to do and never echoes a secret.
        Err(mastersos_bundle::BundleError::Invalid(why)) => {
            return SeedFound::Invalid(format!("{shown} is invalid: {}", ascii_display(&why)))
        }
        Err(_) => {
            return SeedFound::Invalid(match toml_error_line(&text) {
                Some(n) => format!("{shown} is not valid TOML near line {n}"),
                None => format!("{shown} has missing or unknown fields"),
            })
        }
    };
    if seed.trust.is_empty() {
        return invalid(&format!(
            "{shown} has an empty trust list (the machine could never accept settings)"
        ));
    }
    // The strict checks parsing leaves out (a Wi-Fi entry the rules refuse, an SSID twice): the
    // message names the entry and its SSID, never a secret.
    if let Err(e) = seed.validate() {
        let why = match e {
            mastersos_bundle::BundleError::Invalid(why) => why,
            other => other.to_string(),
        };
        return SeedFound::Invalid(format!("{shown} is invalid: {}", ascii_display(&why)));
    }
    SeedFound::Valid {
        text,
        seed: Box::new(seed),
    }
}

/// Refuses when the stick has seeds and none is usable (the disk has not been touched). No seeds, or at least one valid: fine.
pub fn refuse_if_all_invalid(files: &[SeedFile]) -> Result<()> {
    if files.is_empty()
        || files
            .iter()
            .any(|f| matches!(f.found, SeedFound::Valid { .. }))
    {
        return Ok(());
    }
    let why: Vec<&str> = files
        .iter()
        .filter_map(|f| match &f.found {
            SeedFound::Invalid(why) => Some(why.as_str()),
            _ => None,
        })
        .collect();
    bail!(
        "The seed is invalid, refusing to install: {}",
        why.join("; ")
    )
}

const MENU_COLS: usize = 79;

/// One menu line for a valid seed; every field is display-safe and the line fits in [`MENU_COLS`].
fn menu_line(n: usize, file: &SeedFile, seed: &Seed) -> String {
    let head = format!("  {n}) ");
    let tail = format!(
        "  Wi-Fi: {}  ({})",
        wifi_summary(seed, 16),
        display_fit_tail(seed_label(&file.name), 20)
    );
    let who = seed.school_name.as_deref().unwrap_or(&seed.server_url);
    let room = MENU_COLS.saturating_sub(head.len() + tail.len()).max(4);
    let line = format!("{head}{}{tail}", display_fit(who, room));
    line.chars().take(MENU_COLS).collect()
}

/// Picks the seed to install with. No seeds: [`SeedFound::None`]. Seeds but none valid: refuses. Exactly one seed and it is
/// valid: used without a question. Otherwise a numbered list (valid seeds only get numbers; an invalid one is listed with its
/// reason) and a number is asked until it is one of them.
pub fn choose_seed(files: &[SeedFile], tty: &mut dyn Tty) -> Result<SeedFound> {
    refuse_if_all_invalid(files)?;
    if files.is_empty() {
        return Ok(SeedFound::None);
    }
    if let [only] = files {
        return Ok(only.found.clone());
    }
    tty.say("Seeds on the stick:");
    let mut valid: Vec<&SeedFound> = Vec::new();
    for f in files {
        match &f.found {
            SeedFound::Valid { seed, .. } => {
                valid.push(&f.found);
                tty.say(&menu_line(valid.len(), f, seed));
            }
            SeedFound::Invalid(why) => {
                let line = format!("  -  {why}");
                tty.say(&line.chars().take(MENU_COLS).collect::<String>());
            }
            SeedFound::None => {}
        }
    }
    loop {
        tty.flush_input();
        let answer = tty.prompt("Choose a seed (number): ")?;
        if let Some(found) = answer
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|i| valid.get(i.wrapping_sub(1)))
        {
            return Ok((*found).clone());
        }
    }
}

/// Lays the seed out as repart's `CopyFiles=` source: folder 0700, `seed.toml` 0600; without a seed the folder is empty.
/// An existing folder is emptied first. `Invalid` never gets here.
pub fn write_seed_dir(dir: &Path, seed: &SeedFound) -> Result<()> {
    if matches!(seed, SeedFound::Invalid(_)) {
        bail!("invalid seed, not writing it");
    }
    if dir.exists() {
        fs::remove_dir_all(dir).context("removing the old seed folder")?;
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .context("creating the seed folder")?;
    // recursive creates the intermediate folders with the same mode; tighten the last one explicitly (umask and the like must not loosen it).
    fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    if let SeedFound::Valid { text, .. } = seed {
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join("seed.toml"))
            .context("writing seed.toml")?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    Ok(())
}

/// The developer diagnostics marker (docs/specs/2026-11-03-diagnostics-design.md): the installer writes it into the seed
/// folder when d was held in the hidden window ([`crate::tty::sniff_debug`]). The first boot moves it into the encrypted root
/// (mastersos-diag-adopt.service); a marker found on the seed partition on any later boot is deleted, never trusted.
pub const DEBUG_MARKER: &str = "debug-install";

/// Creates the empty marker (0644) in `dir`, the seed folder `write_seed_dir` just made.
pub fn write_debug_marker(dir: &Path) -> Result<()> {
    let p = dir.join(DEBUG_MARKER);
    let f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&p)
        .context("writing the diagnostics marker")?;
    // umask must not tighten it
    fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
    f.sync_all()?;
    Ok(())
}
