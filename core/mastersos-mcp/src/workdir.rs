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
struct Snapshot {
    manifest: String,
    secrets: BTreeMap<String, String>,
    /// `secrets.toml` as it is on disk (a copy keeps it byte for byte).
    secrets_raw: String,
    files: BTreeMap<String, Vec<u8>>,
}

fn read_snapshot(dir: &Path) -> Result<Snapshot> {
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

/// A missing file reads as empty.
fn read_text(path: &Path) -> Result<String> {
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

fn remove_if_exists(path: &Path) -> Result<()> {
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
    let text = toml::to_string(meta).context("could not write mastersos.toml")?;
    fs::write(root.join(META), text)?;
    Ok(())
}

impl Workdir {
    fn base_dir(&self) -> PathBuf {
        self.root.join(STATE).join("base")
    }

    /// Open an existing settings directory.
    pub fn open(root: &Path) -> Result<Workdir> {
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
        fs::create_dir_all(root)?;
        ensure_gitignore(root)?;
        write_snapshot(root, manifest_text, "", &BTreeMap::new())?;
        write_snapshot(&root.join(STATE).join("base"), "", "", &BTreeMap::new())?;
        write_meta(root, &meta)?;
        ensure_gitignore(root)?;
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
            Ok(w) if w.is_dirty()? => bail!(
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
        write_snapshot(root, &manifest, &secrets_raw, &contents.files)?;
        write_snapshot(
            &root.join(STATE).join("base"),
            &manifest,
            &secrets_raw,
            &contents.files,
        )?;
        write_meta(root, &meta)?;
        ensure_gitignore(root)?;
        Ok(Workdir {
            root: root.to_path_buf(),
        })
    }

    pub fn meta(&self) -> Result<Meta> {
        let path = self.root.join(META);
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

    /// Whether the directory differs from its base: manifest and files byte for byte, secrets by
    /// name and value (re-formatting `secrets.toml` is not a change).
    pub fn is_dirty(&self) -> Result<bool> {
        let (cur, base) = (read_snapshot(&self.root)?, read_snapshot(&self.base_dir())?);
        Ok(cur.manifest != base.manifest || cur.secrets != base.secrets || cur.files != base.files)
    }

    /// The directory is now what version `version` holds: record it and make it the base.
    pub fn mark_published(&self, version: u64) -> Result<()> {
        let mut meta = self.meta()?;
        meta.base_version = version;
        let cur = read_snapshot(&self.root)?;
        write_snapshot(
            &self.base_dir(),
            &cur.manifest,
            &cur.secrets_raw,
            &cur.files,
        )?;
        write_meta(&self.root, &meta)
    }
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
    check_at(w, chrono::Utc::now().date_naive())
}

fn check_at(w: &Workdir, today: chrono::NaiveDate) -> Result<Vec<Lint>> {
    let cur = read_snapshot(&w.root)?;
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

/// Replace every secret value in the lints' messages and params with `secret:<name>`.
fn scrub(mut lints: Vec<Lint>, secrets: &BTreeMap<String, String>) -> Vec<Lint> {
    // Longest values first, so a value that contains another is replaced whole.
    let mut pairs: Vec<(&String, &String)> =
        secrets.iter().filter(|(_, v)| !v.is_empty()).collect();
    pairs.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
    // One pass: at each position the longest value that starts there is replaced, and the
    // inserted reference is never scanned again.
    let clean = |s: &str| {
        let mut out = String::with_capacity(s.len());
        let mut i = 0;
        while i < s.len() {
            if let Some((name, value)) = pairs.iter().find(|(_, v)| s[i..].starts_with(v.as_str()))
            {
                out.push_str("secret:");
                out.push_str(name);
                i += value.len();
            } else {
                let c = s[i..].chars().next().unwrap_or_default();
                out.push(c);
                i += c.len_utf8().max(1);
            }
        }
        out
    };
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
        w.mark_published(4).unwrap();
        assert_eq!(w.meta().unwrap().base_version, 4);
        assert!(!w.is_dirty().unwrap());
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
}
