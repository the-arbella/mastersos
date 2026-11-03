//! The local settings directory behind `mastersos init|pull|check|diff`.
//!
//! ```text
//! <dir>/mastersos.toml     server, school id and the version the directory was last synced with
//! <dir>/manifest.toml      the settings, with secrets as "secret:<name>" references
//! <dir>/secrets.toml       name = "value" (mode 0600, git-ignored)
//! <dir>/files/ scripts/    the bundle's members
//! <dir>/.mastersos/base/   the same four, as of the last pull / publish (what `diff` compares to)
//! ```
//!
//! This module holds all the file logic and works offline; the network parts live in [`crate::cli`].

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use mastersos_bundle::{secret_ref, Contents, Lint};
use serde::{Deserialize, Serialize};

const META: &str = "mastersos.toml";
const MANIFEST: &str = "manifest.toml";
const SECRETS: &str = "secrets.toml";
const GITIGNORE: &str = ".gitignore";
const STATE: &str = ".mastersos";
const UPLOAD_INFO: &str = "upload.toml";
const MEMBER_DIRS: [&str; 2] = ["files", "scripts"];

/// A new school's settings: `{school_id}` is filled in by [`template`].
const TEMPLATE: &str = include_str!("template.toml");

/// `mastersos.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    pub server: String,
    pub school_id: String,
    /// The version `manifest.toml` was pulled from or published as (0: never synced).
    pub base_version: u64,
}

/// A settings directory.
#[derive(Debug, Clone)]
pub struct Workdir {
    pub root: PathBuf,
}

/// The settings text of a new school.
pub fn template(school_id: &str) -> Result<String> {
    let ok = !school_id.is_empty()
        && school_id.len() <= 64
        && school_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'-');
    if !ok {
        bail!("the school id from the server is not a UUID");
    }
    Ok(TEMPLATE.replace("{school_id}", school_id))
}

/// Everything in a directory that belongs to a settings snapshot.
pub struct Snapshot {
    pub manifest: String,
    pub secrets: BTreeMap<String, String>,
    /// `secrets.toml` as it is on disk (a copy keeps it byte for byte).
    secrets_raw: String,
    pub files: BTreeMap<String, Vec<u8>>,
}

impl Snapshot {
    fn same_content(&self, other: &Snapshot) -> bool {
        self.manifest == other.manifest
            && self.secrets == other.secrets
            && self.files == other.files
    }
}

/// What was uploaded as a pending bundle: kept in `.mastersos/uploaded/` until it is known to be
/// published (or discarded by a pull).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadInfo {
    pub version: u64,
    /// The server's content digest of the pending bundle (hex); `digest` in older records.
    #[serde(alias = "digest")]
    pub digest_hex: String,
}

/// A snapshot directory's own links: `.mastersos` and `.mastersos/<x>` (when `dir` is one of the
/// state directories) and its `files`/`scripts` are never symbolic links. The settings directory
/// itself may be reached by one.
fn refuse_snapshot_links(dir: &Path) -> Result<()> {
    refuse_state_links(dir)?;
    for d in MEMBER_DIRS {
        refuse_link(&dir.join(d))?;
    }
    Ok(())
}

/// When `dir` is `<root>/.mastersos/<x>`: neither `.mastersos` nor `<x>` may be a link.
fn refuse_state_links(dir: &Path) -> Result<()> {
    if let Some(parent) = dir
        .parent()
        .filter(|p| p.file_name().is_some_and(|n| n == STATE))
    {
        refuse_link(parent)?;
        refuse_link(dir)?;
    }
    Ok(())
}

fn read_snapshot(dir: &Path) -> Result<Snapshot> {
    refuse_snapshot_links(dir)?;
    let manifest = read_text(&dir.join(MANIFEST))?;
    let secrets_raw = read_text(&dir.join(SECRETS))?;
    let secrets = parse_secrets(&secrets_raw)
        .with_context(|| format!("{} is not valid", dir.join(SECRETS).display()))?;
    let mut files = BTreeMap::new();
    for d in MEMBER_DIRS {
        read_members(&dir.join(d), d, &mut files)?;
    }
    Ok(Snapshot {
        manifest,
        secrets,
        secrets_raw,
        files,
    })
}

/// Refuse a symlink (it could point at any file the user can read). A missing path is fine.
fn refuse_link(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            bail!("{} is a symbolic link, which is refused", path.display())
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("could not read {}", path.display())),
    }
}

/// Refuse anything but a regular file (or nothing at all).
fn refuse_irregular(path: &Path) -> Result<()> {
    refuse_link(path)?;
    match fs::symlink_metadata(path) {
        Ok(m) if !m.is_file() => bail!("{} is not a regular file", path.display()),
        _ => Ok(()),
    }
}

/// A missing file reads as empty.
fn read_text(path: &Path) -> Result<String> {
    refuse_irregular(path)?;
    match fs::read_to_string(path) {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).with_context(|| format!("could not read {}", path.display())),
    }
}

fn parse_secrets(text: &str) -> Result<BTreeMap<String, String>> {
    let table: toml::Table = text.parse().map_err(|e: toml::de::Error| {
        // The parser error quotes the line: it must not reach the output.
        let _ = e;
        anyhow::anyhow!("not valid TOML (expected `name = \"value\"` lines)")
    })?;
    let mut out = BTreeMap::new();
    for (k, v) in table {
        match v {
            toml::Value::String(s) => {
                out.insert(k, s);
            }
            _ => bail!("secret `{k}` is not a string"),
        }
    }
    Ok(out)
}

fn secrets_text(secrets: &BTreeMap<String, String>) -> Result<String> {
    if secrets.is_empty() {
        return Ok(String::new());
    }
    toml::to_string(secrets).context("could not write the secrets")
}

fn read_members(dir: &Path, prefix: &str, out: &mut BTreeMap<String, Vec<u8>>) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("could not read {}", dir.display())),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name
            .to_str()
            .with_context(|| format!("{} has a name that is not UTF-8", path.display()))?;
        let key = format!("{prefix}/{name}");
        let kind = entry.file_type()?;
        if kind.is_dir() {
            read_members(&path, &key, out)?;
        } else if kind.is_file() {
            let data =
                fs::read(&path).with_context(|| format!("could not read {}", path.display()))?;
            out.insert(key, data);
        } else {
            bail!("{} is not a regular file or directory", path.display());
        }
    }
    Ok(())
}

/// Write a file that only the owner can read.
fn write_private(path: &Path, text: &str) -> Result<()> {
    use std::io::Write as _;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("could not write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(text.as_bytes())?;
    Ok(())
}

/// Replace the snapshot in `dir` (and nothing else in it) with the given content.
fn write_snapshot(
    dir: &Path,
    manifest: &str,
    secrets_raw: &str,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    for key in files.keys() {
        check_key(key)?;
    }
    // Nothing is written or removed through a link.
    refuse_snapshot_links(dir)?;
    refuse_link(&dir.join(MANIFEST))?;
    fs::create_dir_all(dir).with_context(|| format!("could not create {}", dir.display()))?;
    for d in MEMBER_DIRS {
        remove_if_exists(&dir.join(d))?;
    }
    remove_if_exists(&dir.join(SECRETS))?;
    fs::write(dir.join(MANIFEST), manifest)?;
    write_private(&dir.join(SECRETS), secrets_raw)?;
    for (key, data) in files {
        let path = dir.join(key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, data).with_context(|| format!("could not write {}", path.display()))?;
    }
    Ok(())
}

/// Bundle member paths are `files/...` or `scripts/...` with no way out of the directory.
fn check_key(key: &str) -> Result<()> {
    mastersos_bundle::check_member_path(key).map_err(|e| anyhow::anyhow!("{e}"))?;
    let top = key.split('/').next().unwrap_or_default();
    if !MEMBER_DIRS.contains(&top) || key.contains('\\') {
        bail!("`{key}` is not a files/ or scripts/ path");
    }
    Ok(())
}

/// Remove a file or directory; a link (or a state directory reached through one) is refused,
/// never followed or removed.
fn remove_if_exists(path: &Path) -> Result<()> {
    refuse_state_links(path)?;
    refuse_link(path)?;
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(path)?,
        Ok(_) => fs::remove_file(path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("could not remove {}", path.display())),
    }
    Ok(())
}

/// Make sure `.gitignore` lists the secrets and the state directory.
fn ensure_gitignore(root: &Path) -> Result<()> {
    let path = root.join(GITIGNORE);
    let mut text = read_text(&path)?;
    for line in ["secrets.toml", ".mastersos/"] {
        if !text.lines().any(|l| l.trim() == line) {
            if !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(line);
            text.push('\n');
        }
    }
    fs::write(&path, text)?;
    Ok(())
}

fn write_meta(root: &Path, meta: &Meta) -> Result<()> {
    refuse_irregular(&root.join(META))?;
    let text = toml::to_string(meta).context("could not write mastersos.toml")?;
    fs::write(root.join(META), text)?;
    Ok(())
}

impl Workdir {
    fn base_dir(&self) -> PathBuf {
        self.root.join(STATE).join("base")
    }

    fn uploaded_dir(root: &Path) -> PathBuf {
        root.join(STATE).join("uploaded")
    }

    /// Read manifest, secrets and files once, as one consistent snapshot.
    pub fn freeze(&self) -> Result<Snapshot> {
        read_snapshot(&self.root)
    }

    /// Keep exactly what was uploaded (`snap`) with the pending's version and digest. `mark_published`
    /// and a later `pull` work from this, not from the directory as it is by then.
    pub fn save_uploaded(&self, snap: &Snapshot, info: &UploadInfo) -> Result<()> {
        let dir = Workdir::uploaded_dir(&self.root);
        write_snapshot(&dir, &snap.manifest, &snap.secrets_raw, &snap.files)?;
        let text = toml::to_string(info).context("could not write the upload record")?;
        refuse_irregular(&dir.join(UPLOAD_INFO))?;
        fs::write(dir.join(UPLOAD_INFO), text)?;
        Ok(())
    }

    /// The upload record, when the directory still holds exactly what was uploaded (offline).
    pub fn uploaded_unchanged(root: &Path) -> Result<Option<UploadInfo>> {
        let dir = Workdir::uploaded_dir(root);
        // The links first: the record is read only from the real `.mastersos/uploaded`.
        refuse_snapshot_links(&dir)?;
        refuse_irregular(&dir.join(UPLOAD_INFO))?;
        let Ok(text) = fs::read_to_string(dir.join(UPLOAD_INFO)) else {
            return Ok(None);
        };
        let info: UploadInfo = toml::from_str(&text).context("the upload record is not valid")?;
        let same = read_snapshot(root)?.same_content(&read_snapshot(&dir)?);
        Ok(same.then_some(info))
    }

    /// Whether the directory is the upload of exactly this published version and digest: then a
    /// pull may replace it without `--force`.
    pub fn is_published_upload(root: &Path, version: u64, digest_hex: &str) -> Result<bool> {
        Ok(Workdir::uploaded_unchanged(root)?
            .is_some_and(|i| i.version == version && i.digest_hex.eq_ignore_ascii_case(digest_hex)))
    }

    /// Open an existing settings directory.
    pub fn open(root: &Path) -> Result<Workdir> {
        refuse_irregular(&root.join(META))?;
        if !root.join(META).is_file() {
            bail!(
                "{} is not a settings directory (no {META}): run `mastersos init` or `mastersos pull` first",
                root.display()
            );
        }
        Ok(Workdir {
            root: root.to_path_buf(),
        })
    }

    /// Start a directory for a school that has nothing published: `manifest_text` (the
    /// [`template`]) is the only content and there is no base.
    pub fn init(root: &Path, meta: Meta, manifest_text: &str) -> Result<Workdir> {
        if dir_has_entries(root)? {
            bail!("{} is not empty", root.display());
        }
        refuse_write_links(root)?;
        fs::create_dir_all(root)?;
        ensure_gitignore(root)?;
        write_snapshot(root, manifest_text, "", &BTreeMap::new())?;
        write_snapshot(&root.join(STATE).join("base"), "", "", &BTreeMap::new())?;
        write_meta(root, &meta)?;
        Ok(Workdir {
            root: root.to_path_buf(),
        })
    }

    /// Fail unless `root` may be written by a pull: empty or missing, or a settings directory
    /// without unpublished changes; `force` allows anything. Call it before any network use.
    pub fn ensure_pullable(root: &Path, force: bool) -> Result<()> {
        if force || !dir_has_entries(root)? {
            return Ok(());
        }
        match Workdir::open(root) {
            // Dirty only because it was uploaded: the pull decides, after verifying, whether that
            // upload was published.
            Ok(w) if w.is_dirty()? && Workdir::uploaded_unchanged(root)?.is_none() => bail!(
                "{} has changes that are not published (see `mastersos diff`); pull again with --force to throw them away",
                root.display()
            ),
            Ok(_) => Ok(()),
            Err(_) => bail!(
                "{} is not empty and is not a settings directory; use an empty directory or --force",
                root.display()
            ),
        }
    }

    /// Write a pulled version: secrets are split out of the manifest into `secrets.toml`, and the
    /// result is also kept as the base. Refuses a directory that is not empty and not a clean
    /// settings directory unless `force`.
    pub fn write_pulled(
        root: &Path,
        meta: Meta,
        contents: &Contents,
        force: bool,
    ) -> Result<Workdir> {
        Workdir::ensure_pullable(root, force)?;
        // Everything that can fail on the content fails before a file changes.
        let (manifest, secrets) = secret_ref::split(&contents.manifest_text)
            .map_err(|e| anyhow::anyhow!("the manifest cannot be split: {e}"))?;
        let secrets_raw = secrets_text(&secrets)?;
        for key in contents.files.keys() {
            check_key(key)?;
        }
        refuse_write_links(root)?;
        // The ignore file comes before the first secret is written.
        fs::create_dir_all(root)?;
        ensure_gitignore(root)?;
        write_snapshot(root, &manifest, &secrets_raw, &contents.files)?;
        write_snapshot(
            &root.join(STATE).join("base"),
            &manifest,
            &secrets_raw,
            &contents.files,
        )?;
        write_meta(root, &meta)?;
        remove_if_exists(&Workdir::uploaded_dir(root))?;
        Ok(Workdir {
            root: root.to_path_buf(),
        })
    }

    pub fn meta(&self) -> Result<Meta> {
        let path = self.root.join(META);
        refuse_irregular(&path)?;
        let text = fs::read_to_string(&path)
            .with_context(|| format!("could not read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("{} is not valid", path.display()))
    }

    pub fn manifest(&self) -> Result<String> {
        read_text(&self.root.join(MANIFEST))
    }

    pub fn secrets(&self) -> Result<BTreeMap<String, String>> {
        read_snapshot(&self.root).map(|s| s.secrets)
    }

    pub fn files(&self) -> Result<BTreeMap<String, Vec<u8>>> {
        read_snapshot(&self.root).map(|s| s.files)
    }

    /// The manifest, secrets and files as of the last pull or publish.
    #[allow(clippy::type_complexity)]
    pub fn base(&self) -> Result<(String, BTreeMap<String, String>, BTreeMap<String, Vec<u8>>)> {
        let s = read_snapshot(&self.base_dir())?;
        Ok((s.manifest, s.secrets, s.files))
    }

    /// Whether `snap` is exactly the base (manifest and files byte for byte, secrets by name and
    /// value): then there is nothing to publish.
    pub fn equals_base(&self, snap: &Snapshot) -> Result<bool> {
        Ok(snap.same_content(&read_snapshot(&self.base_dir())?))
    }

    /// Whether the directory differs from its base: manifest and files byte for byte, secrets by
    /// name and value (re-formatting `secrets.toml` is not a change).
    pub fn is_dirty(&self) -> Result<bool> {
        let (cur, base) = (read_snapshot(&self.root)?, read_snapshot(&self.base_dir())?);
        Ok(cur.manifest != base.manifest || cur.secrets != base.secrets || cur.files != base.files)
    }

    /// What was uploaded is now version `version`: make the uploaded snapshot (not the directory
    /// as it is now, which may have been edited meanwhile) the base.
    pub fn mark_published(&self, version: u64) -> Result<()> {
        let dir = Workdir::uploaded_dir(&self.root);
        refuse_snapshot_links(&dir)?;
        let info: UploadInfo = toml::from_str(&read_text(&dir.join(UPLOAD_INFO))?)
            .context("there is no record of an upload to mark as published")?;
        if info.version != version {
            bail!("the upload was for version {}, not {version}", info.version);
        }
        let up = read_snapshot(&dir)?;
        write_snapshot(&self.base_dir(), &up.manifest, &up.secrets_raw, &up.files)?;
        let mut meta = self.meta()?;
        meta.base_version = version;
        write_meta(&self.root, &meta)?;
        remove_if_exists(&dir)
    }
}

/// Before a pull or init writes anything: none of the paths it writes or removes is a link.
fn refuse_write_links(root: &Path) -> Result<()> {
    refuse_link(&root.join(STATE))?;
    for dir in [
        root.to_path_buf(),
        root.join(STATE).join("base"),
        Workdir::uploaded_dir(root),
    ] {
        refuse_snapshot_links(&dir)?;
        refuse_link(&dir.join(MANIFEST))?;
        refuse_link(&dir.join(SECRETS))?;
    }
    refuse_irregular(&root.join(META))?;
    refuse_link(&root.join(GITIGNORE))
}

fn dir_has_entries(root: &Path) -> Result<bool> {
    match fs::read_dir(root) {
        Ok(mut it) => Ok(it.next().is_some()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("could not read {}", root.display())),
    }
}

/// Check the directory the way publishing would, minus the checks that need the server's fleet.
/// Secrets are filled in first (some fields have formats a reference cannot satisfy); no message
/// leaves this function with a secret value in it.
pub fn check(w: &Workdir) -> Result<Vec<Lint>> {
    check_snapshot(w, &read_snapshot(&w.root)?)
}

/// [`check`] on a snapshot already read ([`Workdir::freeze`]): what is checked is exactly what
/// is then uploaded.
pub fn check_snapshot(w: &Workdir, cur: &Snapshot) -> Result<Vec<Lint>> {
    check_at(w, cur, chrono::Utc::now().date_naive())
}

fn check_at(w: &Workdir, cur: &Snapshot, today: chrono::NaiveDate) -> Result<Vec<Lint>> {
    let base = read_snapshot(&w.base_dir())?;
    let base_text = (!base.manifest.is_empty()).then_some(base.manifest.as_str());
    let present: BTreeSet<String> = cur.files.keys().cloned().collect();

    let mut out: Vec<Lint> = Vec::new();
    match secret_ref::fill(&cur.manifest, &cur.secrets) {
        Err(unknown) => out.extend(unknown),
        Ok(filled) => {
            let checked = mastersos_bundle::check::check_text(&filled, &present, today);
            out.extend(checked.issues);
            if checked.manifest.is_some_and(|m| m.trust.is_empty())
                && !out.iter().any(|l| l.code == "trust_empty")
            {
                out.push(mastersos_bundle::trust_empty_lint());
            }
        }
    }
    for l in secret_ref::lints(&cur.manifest, &cur.secrets, base_text) {
        if !out.contains(&l) {
            out.push(l);
        }
    }
    Ok(scrub(out, &cur.secrets))
}

/// Replace every secret value in `s` with `secret:<name>`.
///
/// Every occurrence of every value is found (overlapping ones too); ranges that overlap or touch
/// are merged and each merged range becomes the references of the secrets in it
/// (`secret:a+secret:b`), so no part of a value survives next to another one.
pub fn redact(s: &str, secrets: &BTreeMap<String, String>) -> String {
    let values: Vec<(&String, &String)> = secrets.iter().filter(|(_, v)| !v.is_empty()).collect();
    // (start, end, name) of every occurrence.
    let mut hits: Vec<(usize, usize, &str)> = Vec::new();
    for (name, value) in &values {
        let mut from = 0;
        while let Some(at) = s[from..].find(value.as_str()) {
            let start = from + at;
            hits.push((start, start + value.len(), name.as_str()));
            // The next search starts one char later, so overlapping occurrences are found.
            from = start + s[start..].chars().next().map_or(1, char::len_utf8);
        }
    }
    hits.sort();
    let mut out = String::with_capacity(s.len());
    let mut pos = 0;
    let mut i = 0;
    while i < hits.len() {
        let (start, mut end, _) = hits[i];
        let mut names: Vec<&str> = Vec::new();
        while i < hits.len() && hits[i].0 <= end {
            end = end.max(hits[i].1);
            if !names.contains(&hits[i].2) {
                names.push(hits[i].2);
            }
            i += 1;
        }
        out.push_str(&s[pos..start]);
        let refs: Vec<String> = names.iter().map(|n| format!("secret:{n}")).collect();
        out.push_str(&refs.join("+"));
        pos = end;
    }
    out.push_str(&s[pos..]);
    out
}

/// Replace every secret value in the lints' messages and params with `secret:<name>`.
fn scrub(mut lints: Vec<Lint>, secrets: &BTreeMap<String, String>) -> Vec<Lint> {
    let clean = |s: &str| redact(s, secrets);
    for l in &mut lints {
        l.message = clean(&l.message);
        for v in l.params.values_mut() {
            *v = clean(v);
        }
    }
    lints
}

/// What changed since the base: a unified diff of the manifest (secrets are references there),
/// then one line per changed secret (name and `added`/`removed`/`changed`, never the value) and
/// per changed file.
pub fn diff(w: &Workdir) -> Result<String> {
    let cur = read_snapshot(&w.root)?;
    let base = read_snapshot(&w.base_dir())?;
    let mut out = String::new();
    if cur.manifest != base.manifest {
        out.push_str(
            &similar::TextDiff::from_lines(&base.manifest, &cur.manifest)
                .unified_diff()
                .context_radius(3)
                .header("base/manifest.toml", "manifest.toml")
                .to_string(),
        );
    }
    for (kind, lines) in [
        ("secret", changes(&base.secrets, &cur.secrets)),
        ("file", changes(&base.files, &cur.files)),
    ] {
        for (name, what) in lines {
            out.push_str(&format!("{kind} {name}: {what}\n"));
        }
    }
    if out.is_empty() {
        out.push_str("No changes.\n");
    }
    Ok(out)
}

fn changes<V: PartialEq>(
    base: &BTreeMap<String, V>,
    cur: &BTreeMap<String, V>,
) -> Vec<(String, &'static str)> {
    let names: BTreeSet<&String> = base.keys().chain(cur.keys()).collect();
    names
        .into_iter()
        .filter_map(|n| match (base.get(n), cur.get(n)) {
            (None, Some(_)) => Some((n.clone(), "added")),
            (Some(_), None) => Some((n.clone(), "removed")),
            (Some(a), Some(b)) if a != b => Some((n.clone(), "changed")),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mastersos_bundle::LintLevel;

    const SAMPLE: &str = "format = 2\n[school]\nid = \"11111111-1111-1111-1111-111111111111\"\n\n[defaults]\nwifi = [{ ssid = \"Guest\", psk = \"guestpass1\" }]\n\n[[config]]\nid = \"default\"\nname = \"Default\"\ninterface = \"learning\"\nlogin_methods = [\"local\"]\n\n[[group]]\nid = \"default\"\nname = \"Ungrouped\"\nconfig = \"default\"\n";

    fn meta(v: u64) -> Meta {
        Meta {
            server: "https://school.example".into(),
            school_id: "11111111-1111-1111-1111-111111111111".into(),
            base_version: v,
        }
    }

    fn contents() -> Contents {
        let mut files = BTreeMap::new();
        files.insert("files/a.txt".to_string(), b"hello".to_vec());
        Contents {
            manifest_text: SAMPLE.to_string(),
            files,
        }
    }

    fn pulled(dir: &Path) -> Workdir {
        Workdir::write_pulled(dir, meta(3), &contents(), false).unwrap()
    }

    fn codes(l: &[Lint]) -> Vec<&'static str> {
        l.iter().map(|l| l.code).collect()
    }

    #[cfg(unix)]
    #[test]
    fn manifest_symlink_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let w = pulled(&t.path().join("school"));
        let target = t.path().join("target.txt");
        std::fs::write(&target, "TOPSECRET-KEY").unwrap();
        std::fs::remove_file(w.root.join("manifest.toml")).unwrap();
        std::os::unix::fs::symlink(&target, w.root.join("manifest.toml")).unwrap();
        let e = format!("{:#}", w.manifest().unwrap_err());
        assert!(
            e.contains("manifest.toml") && !e.contains("TOPSECRET"),
            "{e}"
        );
        assert!(check(&w).is_err() && diff(&w).is_err() && w.freeze().is_err());
        let e =
            crate::tools::call_local(&w.root, "read_manifest", serde_json::json!({})).unwrap_err();
        assert!(!e.contains("TOPSECRET"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn secrets_symlink_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let w = pulled(&t.path().join("school"));
        let target = t.path().join("target.txt");
        std::fs::write(&target, "x = \"TOPSECRET-KEY\"\n").unwrap();
        std::fs::remove_file(w.root.join("secrets.toml")).unwrap();
        std::os::unix::fs::symlink(&target, w.root.join("secrets.toml")).unwrap();
        let e = format!("{:#}", w.secrets().unwrap_err());
        assert!(
            e.contains("secrets.toml") && !e.contains("TOPSECRET"),
            "{e}"
        );
        let e =
            crate::tools::call_local(&w.root, "read_manifest", serde_json::json!({})).unwrap_err();
        assert!(!e.contains("TOPSECRET"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn base_dir_symlink_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let w = pulled(&t.path().join("school"));
        let moved = t.path().join("moved-base");
        std::fs::rename(w.root.join(".mastersos/base"), &moved).unwrap();
        std::os::unix::fs::symlink(&moved, w.root.join(".mastersos/base")).unwrap();
        let e = format!("{:#}", diff(&w).unwrap_err());
        assert!(e.contains("base") && e.contains("symbolic link"), "{e}");
        assert!(w.is_dirty().is_err());
        // The state directory itself.
        std::fs::remove_file(w.root.join(".mastersos/base")).unwrap();
        std::fs::rename(&moved, w.root.join(".mastersos/base")).unwrap();
        let state = t.path().join("moved-state");
        std::fs::rename(w.root.join(".mastersos"), &state).unwrap();
        std::os::unix::fs::symlink(&state, w.root.join(".mastersos")).unwrap();
        assert!(diff(&w).is_err());
    }

    #[test]
    fn pull_writes_split_layout() {
        let t = tempfile::tempdir().unwrap();
        let w = pulled(&t.path().join("school"));
        let manifest = w.manifest().unwrap();
        assert!(!manifest.contains("guestpass1"), "{manifest}");
        assert!(manifest.contains("secret:"), "{manifest}");
        assert_eq!(w.secrets().unwrap().values().next().unwrap(), "guestpass1");
        assert_eq!(w.files().unwrap()["files/a.txt"], b"hello");
        assert_eq!(w.meta().unwrap(), meta(3));
        let gi = std::fs::read_to_string(w.root.join(".gitignore")).unwrap();
        assert!(gi.lines().any(|l| l == "secrets.toml"), "{gi}");
        assert!(gi.lines().any(|l| l == ".mastersos/"), "{gi}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for p in ["secrets.toml", ".mastersos/base/secrets.toml"] {
                let mode = std::fs::metadata(w.root.join(p))
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o600, "{p}");
            }
        }
        assert!(!w.is_dirty().unwrap());
        // The base keeps the split form: no secret value anywhere under .mastersos/.
        let (bm, bs, bf) = w.base().unwrap();
        assert_eq!(bm, manifest);
        assert_eq!(bs, w.secrets().unwrap());
        assert_eq!(bf, w.files().unwrap());
    }

    #[test]
    fn pull_refuses_dirty_dir() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("school");
        let w = pulled(&dir);
        let edited = format!("{}# mine\n", w.manifest().unwrap());
        std::fs::write(dir.join("manifest.toml"), &edited).unwrap();
        assert!(w.is_dirty().unwrap());
        assert!(Workdir::write_pulled(&dir, meta(4), &contents(), false).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.join("manifest.toml")).unwrap(),
            edited
        );
        let w = Workdir::write_pulled(&dir, meta(4), &contents(), true).unwrap();
        assert!(!w.is_dirty().unwrap());
        assert_eq!(w.meta().unwrap().base_version, 4);
        // A directory with files that are not a settings directory is not overwritten either.
        let other = t.path().join("other");
        std::fs::create_dir(&other).unwrap();
        std::fs::write(other.join("x"), "x").unwrap();
        assert!(Workdir::write_pulled(&other, meta(1), &contents(), false).is_err());
        // An empty directory is fine.
        let empty = t.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        Workdir::write_pulled(&empty, meta(1), &contents(), false).unwrap();
    }

    #[test]
    fn pull_removes_files_gone_upstream() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("school");
        pulled(&dir);
        let mut c = contents();
        c.files.clear();
        let w = Workdir::write_pulled(&dir, meta(4), &c, true).unwrap();
        assert!(w.files().unwrap().is_empty());
        assert!(!dir.join("files/a.txt").exists());
    }

    #[test]
    fn check_flags_unknown_secret() {
        let t = tempfile::tempdir().unwrap();
        let w = pulled(&t.path().join("school"));
        let text = w.manifest().unwrap().replace("secret:", "secret:x-");
        std::fs::write(w.root.join("manifest.toml"), text).unwrap();
        let lints = check(&w).unwrap();
        assert!(codes(&lints).contains(&"secret_unknown"), "{lints:?}");
    }

    #[test]
    fn check_clean_pull_has_no_errors() {
        let t = tempfile::tempdir().unwrap();
        let w = pulled(&t.path().join("school"));
        let lints = check(&w).unwrap();
        // The sample has no trust, which publishing needs: that is the only error.
        let errors: Vec<_> = lints
            .iter()
            .filter(|l| l.level == LintLevel::Error)
            .map(|l| l.code)
            .collect();
        assert_eq!(errors, ["trust_empty"], "{lints:?}");
    }

    #[test]
    fn check_messages_never_contain_secret_values() {
        let t = tempfile::tempdir().unwrap();
        let w = pulled(&t.path().join("school"));
        // A psk that is too short, and equal to the ssid the message quotes: the message must
        // carry the reference where the value would have been.
        let name = w.secrets().unwrap().keys().next().unwrap().clone();
        let bad = "Guest";
        let mut s = BTreeMap::new();
        s.insert(name.clone(), bad.to_string());
        std::fs::write(w.root.join("secrets.toml"), toml::to_string(&s).unwrap()).unwrap();
        let lints = check(&w).unwrap();
        let hit = lints.iter().find(|l| l.code == "wifi_invalid");
        let hit = hit.unwrap_or_else(|| panic!("no wifi_invalid lint: {lints:?}"));
        assert!(hit.message.contains(&format!("secret:{name}")), "{hit:?}");
        for l in &lints {
            assert!(!l.message.contains(bad), "{l:?}");
            assert!(l.params.values().all(|v| !v.contains(bad)), "{l:?}");
        }
        // The scrubber itself replaces every occurrence with the reference.
        let l = Lint::new(
            LintLevel::Error,
            "x",
            format!("bad value \"{bad}\" and {bad}"),
        );
        let out = scrub(vec![l], &s);
        assert_eq!(
            out[0].message,
            format!("bad value \"secret:{name}\" and secret:{name}")
        );
    }

    #[test]
    fn mark_published_moves_base() {
        let t = tempfile::tempdir().unwrap();
        let w = Workdir::init(&t.path().join("school"), meta(0), SAMPLE).unwrap();
        assert!(w.is_dirty().unwrap());
        w.save_uploaded(&w.freeze().unwrap(), &info(4)).unwrap();
        w.mark_published(4).unwrap();
        assert_eq!(w.meta().unwrap().base_version, 4);
        assert!(!w.is_dirty().unwrap());
        assert!(w.mark_published(4).is_err(), "the record is consumed");
    }

    fn info(v: u64) -> UploadInfo {
        UploadInfo {
            version: v,
            digest_hex: "ab".repeat(32),
        }
    }

    #[test]
    fn mark_published_uses_uploaded_snapshot() {
        let t = tempfile::tempdir().unwrap();
        let w = pulled(&t.path().join("school"));
        std::fs::write(w.root.join("files/a.txt"), "uploaded").unwrap();
        w.save_uploaded(&w.freeze().unwrap(), &info(4)).unwrap();
        // Edited while the signing prompt was open.
        std::fs::write(w.root.join("files/a.txt"), "edited later").unwrap();
        assert!(w.mark_published(5).is_err(), "wrong version");
        w.mark_published(4).unwrap();
        let (_, _, files) = w.base().unwrap();
        assert_eq!(files["files/a.txt"], b"uploaded");
        assert!(w.is_dirty().unwrap(), "the later edit is still unpublished");
    }

    #[test]
    fn pull_after_passkey_publish_is_clean() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("school");
        let w = pulled(&dir);
        std::fs::write(dir.join("files/a.txt"), "changed").unwrap();
        // Not uploaded: dirty, refused.
        assert!(Workdir::ensure_pullable(&dir, false).is_err());
        assert!(Workdir::uploaded_unchanged(&dir).unwrap().is_none());
        w.save_uploaded(&w.freeze().unwrap(), &info(4)).unwrap();
        // Dirty but equal to the upload: the offline pre-check lets it through.
        Workdir::ensure_pullable(&dir, false).unwrap();
        let digest = "ab".repeat(32);
        assert!(Workdir::is_published_upload(&dir, 4, &digest).unwrap());
        assert!(Workdir::is_published_upload(&dir, 4, &digest.to_uppercase()).unwrap());
        // Another version or digest was published: not this upload.
        assert!(!Workdir::is_published_upload(&dir, 5, &digest).unwrap());
        assert!(!Workdir::is_published_upload(&dir, 4, &"cd".repeat(32)).unwrap());
        // Edited after the upload: dirty again and refused.
        std::fs::write(dir.join("files/a.txt"), "more").unwrap();
        assert!(Workdir::ensure_pullable(&dir, false).is_err());
        assert!(!Workdir::is_published_upload(&dir, 4, &digest).unwrap());
        // A pull clears the record.
        Workdir::write_pulled(&dir, meta(4), &contents(), true).unwrap();
        assert!(Workdir::uploaded_unchanged(&dir).unwrap().is_none());
        assert!(!dir.join(".mastersos/uploaded").exists());
    }

    #[test]
    fn diff_never_prints_secret_values() {
        let t = tempfile::tempdir().unwrap();
        let w = pulled(&t.path().join("school"));
        assert_eq!(diff(&w).unwrap(), "No changes.\n");
        let name = w.secrets().unwrap().keys().next().unwrap().clone();
        let mut s = w.secrets().unwrap();
        s.insert(name.clone(), "newsecret99".into());
        s.insert("extra".into(), "extravalue1".into());
        std::fs::write(w.root.join("secrets.toml"), toml::to_string(&s).unwrap()).unwrap();
        std::fs::write(w.root.join("files/a.txt"), "changed").unwrap();
        std::fs::write(w.root.join("files/b.txt"), "new").unwrap();
        let text = format!("{}# note\n", w.manifest().unwrap());
        std::fs::write(w.root.join("manifest.toml"), text).unwrap();
        let d = diff(&w).unwrap();
        for v in ["newsecret99", "extravalue1", "guestpass1"] {
            assert!(!d.contains(v), "{d}");
        }
        assert!(d.contains(&format!("secret {name}: changed")), "{d}");
        assert!(d.contains("secret extra: added"), "{d}");
        assert!(d.contains("file files/a.txt: changed"), "{d}");
        assert!(d.contains("file files/b.txt: added"), "{d}");
        assert!(d.contains("+# note"), "{d}");
    }

    #[test]
    fn init_writes_template_for_school() {
        let t = tempfile::tempdir().unwrap();
        let text = template("11111111-1111-1111-1111-111111111111").unwrap();
        let w = Workdir::init(&t.path().join("s"), meta(0), &text).unwrap();
        assert!(w
            .manifest()
            .unwrap()
            .contains("id = \"11111111-1111-1111-1111-111111111111\""));
        assert!(template("x\"; evil").is_err());
        let lints = check(&w).unwrap();
        assert!(!codes(&lints).contains(&"toml_syntax"), "{lints:?}");
    }

    #[test]
    fn scrub_is_one_pass() {
        let mut s = BTreeMap::new();
        s.insert("a".to_string(), "x".to_string());
        s.insert("b".to_string(), "secret:a".to_string());
        // The reference inserted for "x" is not scanned again, and the longer value wins.
        let l = Lint::new(LintLevel::Error, "c", "x secret:a x");
        assert_eq!(scrub(vec![l], &s)[0].message, "secret:a secret:b secret:a");
        // Short values are still scrubbed.
        let l = Lint::new(LintLevel::Error, "c", "ü x ü");
        assert_eq!(scrub(vec![l], &s)[0].message, "ü secret:a ü");
    }

    #[test]
    fn scrub_overlapping_values() {
        let mut s = BTreeMap::new();
        s.insert("a".to_string(), "abcd".to_string());
        s.insert("b".to_string(), "cdef".to_string());
        let l = Lint::new(LintLevel::Error, "c", "xxabcdefyy and abcd");
        let out = scrub(vec![l], &s)[0].message.clone();
        assert_eq!(out, "xxsecret:a+secret:byy and secret:a");
        // Adjacent values merge too; a value inside another does not leave a remainder.
        s.insert("c".to_string(), "ab".to_string());
        let l = Lint::new(LintLevel::Error, "c", "abab");
        assert_eq!(scrub(vec![l], &s)[0].message, "secret:c");
    }

    #[test]
    fn write_pulled_rejects_unsafe_paths() {
        let t = tempfile::tempdir().unwrap();
        for bad in ["files/../x", "/etc/x", "other/x", "files/a\\b"] {
            let dir = t.path().join("school");
            let mut c = contents();
            c.files.insert(bad.to_string(), b"x".to_vec());
            assert!(
                Workdir::write_pulled(&dir, meta(1), &c, false).is_err(),
                "{bad}"
            );
            assert!(
                !dir.exists() || std::fs::read_dir(&dir).unwrap().next().is_none(),
                "{bad}"
            );
            assert!(!t.path().join("x").exists());
        }
    }

    #[test]
    fn gitignore_exists_before_secrets() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("school");
        // Pre-existing user ignore file keeps its lines.
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join(".gitignore"), "target\n").unwrap();
        let w = Workdir::write_pulled(&dir, meta(3), &contents(), true).unwrap();
        let gi = std::fs::read_to_string(w.root.join(".gitignore")).unwrap();
        assert!(
            gi.starts_with("target\n") && gi.contains("secrets.toml"),
            "{gi}"
        );
    }

    #[test]
    fn gitignore_is_written_before_the_snapshot() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("school");
        // manifest.toml is a directory, so the snapshot write fails.
        std::fs::create_dir_all(dir.join("manifest.toml/x")).unwrap();
        assert!(Workdir::write_pulled(&dir, meta(3), &contents(), true).is_err());
        let gi = std::fs::read_to_string(dir.join(".gitignore")).unwrap();
        assert!(gi.contains("secrets.toml"), "{gi}");
    }

    #[test]
    fn ensure_pullable_is_offline_dirty_check() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("school");
        Workdir::ensure_pullable(&dir, false).unwrap();
        let w = pulled(&dir);
        Workdir::ensure_pullable(&dir, false).unwrap();
        std::fs::write(w.root.join("manifest.toml"), "# mine\n").unwrap();
        assert!(Workdir::ensure_pullable(&dir, false).is_err());
        Workdir::ensure_pullable(&dir, true).unwrap();
    }

    #[test]
    fn check_snapshot_checks_the_frozen_bytes() {
        let t = tempfile::tempdir().unwrap();
        let w = pulled(&t.path().join("school"));
        let snap = w.freeze().unwrap();
        // Broken on disk after the freeze: the snapshot's check does not see it.
        let text = w.manifest().unwrap().replace("secret:", "secret:x-");
        std::fs::write(w.root.join("manifest.toml"), text).unwrap();
        assert!(!codes(&check_snapshot(&w, &snap).unwrap()).contains(&"secret_unknown"));
        assert!(codes(&check(&w).unwrap()).contains(&"secret_unknown"));
    }

    #[test]
    fn equals_base_after_pull_only() {
        let t = tempfile::tempdir().unwrap();
        let w = pulled(&t.path().join("school"));
        assert!(w.equals_base(&w.freeze().unwrap()).unwrap());
        std::fs::write(w.root.join("files/a.txt"), "changed").unwrap();
        assert!(!w.equals_base(&w.freeze().unwrap()).unwrap());
    }

    #[test]
    fn upload_record_reads_old_digest_field() {
        let i: UploadInfo = toml::from_str("version = 3\ndigest = \"ab\"\n").unwrap();
        assert_eq!(i.digest_hex, "ab");
        let i: UploadInfo = toml::from_str("version = 3\ndigest_hex = \"cd\"\n").unwrap();
        assert_eq!(i.digest_hex, "cd");
    }

    /// A directory outside the settings directory that must not change.
    #[cfg(unix)]
    fn outside(t: &Path, name: &str) -> PathBuf {
        let d = t.join(name);
        std::fs::create_dir_all(d.join("base/files")).unwrap();
        std::fs::create_dir_all(d.join("uploaded/files")).unwrap();
        std::fs::create_dir_all(d.join("files")).unwrap();
        std::fs::write(d.join("keep.txt"), "keep").unwrap();
        std::fs::write(d.join("base/files/keep.txt"), "keep").unwrap();
        std::fs::write(d.join("uploaded/files/keep.txt"), "keep").unwrap();
        std::fs::write(
            d.join("uploaded/upload.toml"),
            "version = 4\ndigest_hex = \"ab\"\n",
        )
        .unwrap();
        std::fs::write(d.join("files/keep.txt"), "keep").unwrap();
        d
    }

    #[cfg(unix)]
    fn untouched(d: &Path) {
        for p in [
            "keep.txt",
            "base/files/keep.txt",
            "uploaded/files/keep.txt",
            "files/keep.txt",
        ] {
            assert_eq!(std::fs::read_to_string(d.join(p)).unwrap(), "keep", "{p}");
        }
        assert!(d.join("uploaded/upload.toml").exists());
    }

    #[cfg(unix)]
    #[test]
    fn writes_never_go_through_links() {
        use std::os::unix::fs::symlink;
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("school");

        // `.mastersos` is a link: pull --force, mark_published and the upload record are refused.
        let w = pulled(&dir);
        w.save_uploaded(&w.freeze().unwrap(), &info(4)).unwrap();
        let out = outside(t.path(), "state");
        std::fs::remove_dir_all(dir.join(".mastersos")).unwrap();
        symlink(&out, dir.join(".mastersos")).unwrap();
        assert!(Workdir::write_pulled(&dir, meta(4), &contents(), true).is_err());
        assert!(w.mark_published(4).is_err());
        assert!(Workdir::uploaded_unchanged(&dir).is_err());
        assert!(w.save_uploaded(&w.freeze().unwrap(), &info(4)).is_err());
        untouched(&out);
        std::fs::remove_file(dir.join(".mastersos")).unwrap();

        // `.mastersos/base` and `.mastersos/uploaded` are links.
        let w = pulled(&t.path().join("school2"));
        let dir = w.root.clone();
        w.save_uploaded(&w.freeze().unwrap(), &info(4)).unwrap();
        for (sub, name) in [("base", "b"), ("uploaded", "u")] {
            let out = outside(t.path(), name);
            let real = t.path().join(format!("real-{name}"));
            std::fs::rename(dir.join(".mastersos").join(sub), &real).unwrap();
            symlink(out.join(sub), dir.join(".mastersos").join(sub)).unwrap();
            assert!(
                Workdir::write_pulled(&dir, meta(4), &contents(), true).is_err(),
                "{sub}"
            );
            assert!(w.mark_published(4).is_err(), "{sub}");
            if sub == "uploaded" {
                // The record is not read from behind the link.
                assert!(Workdir::uploaded_unchanged(&dir).is_err());
            }
            untouched(&out);
            std::fs::remove_file(dir.join(".mastersos").join(sub)).unwrap();
            std::fs::rename(&real, dir.join(".mastersos").join(sub)).unwrap();
        }

        // `files` is a link: a pull does not remove or write through it.
        let out = outside(t.path(), "f");
        std::fs::remove_dir_all(dir.join("files")).unwrap();
        symlink(out.join("files"), dir.join("files")).unwrap();
        assert!(Workdir::write_pulled(&dir, meta(4), &contents(), true).is_err());
        untouched(&out);
        assert!(std::fs::symlink_metadata(dir.join("files"))
            .unwrap()
            .file_type()
            .is_symlink());

        // `scripts` and mastersos.toml as links.
        std::fs::remove_file(dir.join("files")).unwrap();
        symlink(out.join("files"), dir.join("scripts")).unwrap();
        assert!(Workdir::write_pulled(&dir, meta(4), &contents(), true).is_err());
        untouched(&out);
        std::fs::remove_file(dir.join("scripts")).unwrap();
        let target = t.path().join("meta-target");
        std::fs::write(&target, "keep").unwrap();
        std::fs::remove_file(dir.join("mastersos.toml")).unwrap();
        symlink(&target, dir.join("mastersos.toml")).unwrap();
        assert!(Workdir::write_pulled(&dir, meta(4), &contents(), true).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    }
}
