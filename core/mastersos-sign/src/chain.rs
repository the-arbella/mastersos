//! 本地验链：像 agent 一样从 pin 住的那一版逐版验到最新（Ruling 15）。
//!
//! pin 存在 `<pin_dir>/<主机>.toml`，记上次验证过的版本号、它的内容摘要与 trust。
//! - **没有 pin**（首次使用，TOFU）：打印最新版 trust 里每把钥匙的指纹，要人输入 `yes`
//!   确认与钥匙页、种子开头的指纹对照无误，再以包自己的 trust 自洽检查，记 pin。
//! - **有 pin**：先确认 pin 住的那一版内容没被换（摘要相同），再对之后的每一版
//!   `accept(包, 当前 trust, Some(当前版本))`，任何一版不过 → 报「历史版本验不过」，pin 不动。
//!
//! A chain is identified by the pin on disk: (host, version, content digest, trust). A new pin
//! replaces it only when the caller verified forward from exactly that pin and the version is
//! strictly higher ([`save_pin`]). Anything else (a lower or equal version, a pin that came from
//! another chain, a pin that changed meanwhile) is refused; there is no override flag, the
//! operator deletes the pin file to start over.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use mastersos_bundle::{
    accept, accept_signed, check_recovery_signed, content_digest, read_archive, recipients_changed,
    BundleError, Contents, KitChange, Manifest, TrustKey,
};
use serde::{Deserialize, Serialize};

use crate::{ask, hex, print_trust, Api, TrustDelta};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    /// `主机[:端口]`。
    pub host: String,
    pub version: u64,
    /// 这一版的 `content_digest`（小写十六进制）：再验时确认服务端没有换掉 pin 住的那一版。
    pub digest_hex: String,
    pub trust: Vec<TrustKey>,
    /// Every version this computer verified, with its content digest, in order. The only record
    /// of history that can be trusted later: the manifests link to no earlier digest, so a past
    /// version cannot be authenticated from the pin alone. Pin files from before this field read
    /// as empty (see [`load_pin`], which adds the pinned version).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified: Vec<VerifiedVersion>,
}

impl Pin {
    /// The pinned version itself is always a verified one (pin files from before the list
    /// existed have none): add it.
    fn normalized(mut self) -> Pin {
        let digest = self.digest_hex.clone();
        record_verified(&mut self.verified, self.version, &digest);
        self
    }
}

/// A version this computer verified and the `content_digest` (lower-case hex) it had.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedVersion {
    pub version: u64,
    pub digest_hex: String,
}

/// Add `version` to a verified list (once; the list stays ordered by version).
pub fn record_verified(list: &mut Vec<VerifiedVersion>, version: u64, digest_hex: &str) {
    if !list.iter().any(|e| e.version == version) {
        list.push(VerifiedVersion {
            version,
            digest_hex: digest_hex.to_owned(),
        });
        list.sort_by_key(|e| e.version);
    }
}

/// The contents of an old version, taken only if this computer verified it before: `archive` must
/// hold exactly the digest recorded for `want`. A version that is not recorded (published before
/// the first use here, or refused by machines) cannot be checked and is an error.
pub fn recorded_contents(
    verified: &[VerifiedVersion],
    want: u64,
    archive: &[u8],
) -> Result<Contents> {
    let rec = recorded_version(verified, want)?;
    let contents = read_archive(archive)
        .map_err(|e| tampered(want, e))?
        .contents;
    if hex(&content_digest(&contents)) != rec.digest_hex {
        return Err(tampered(want, "的内容与本机验证过的不同"));
    }
    Ok(contents)
}

/// The record of `want`, or the error [`recorded_contents`] gives when there is none.
pub fn recorded_version(verified: &[VerifiedVersion], want: u64) -> Result<&VerifiedVersion> {
    verified
        .iter()
        .find(|e| e.version == want)
        .with_context(|| {
            format!(
                "version {want} was published before this computer started verifying this school; \
             it cannot be checked"
            )
        })
}

/// 验证过的最新版。
///
/// `version`, `digest_hex`, `trust` and `contents` are the last version machines accept: the base
/// the next signature is checked and diffed against, and what the pin records. `latest` is the
/// newest version on the server's chain. They differ only after the operator confirmed past a
/// version that violates R7/R8 (machines refuse it and stay on the version before it; Task 24c
/// fix round 1, I2): the next version is `latest + 1`, but its trust and recipient changes are
/// still shown against what machines actually run.
#[derive(Debug, Clone)]
pub struct Verified {
    pub version: u64,
    pub digest_hex: String,
    pub trust: Vec<TrustKey>,
    /// 最新已验证版本的清单与文件。
    pub contents: Contents,
    /// The newest version on the chain (`>= version`).
    pub latest: u64,
    /// Every version verified so far on this computer (the pin's [`Pin::verified`]).
    pub history: Vec<VerifiedVersion>,
}

pub fn pin_path(pin_dir: &Path, api: &Api) -> PathBuf {
    pin_dir.join(format!("{}.toml", api.pin_name()))
}

pub(crate) fn load_pin(path: &Path) -> Result<Option<Pin>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let pin: Pin = toml::from_str(&text)
                .with_context(|| format!("pin 文件 {} 读不懂", path.display()))?;
            Ok(Some(pin.normalized()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("读 pin 文件 {} 失败", path.display())),
    }
}

/// Write `pin`, which the caller derived by verifying forward from `prev` (the pin on disk when
/// it started; `None` when there was none). Refused when the pin on disk is not `prev` (another
/// chain, or it changed meanwhile), when `pin` would not move forward, or when the host differs.
///
/// The compare and the write happen under an exclusive `flock` on `<pin>.lock`, so two
/// `mastersos-sign` runs against the same server cannot both pass the compare and overwrite each
/// other. The new pin goes to a fresh temporary file (created exclusively, so it never follows a
/// planted symlink), is fsynced, renamed over the pin, and the directory is fsynced: a crash
/// leaves the old pin or the new one, never half of one.
pub fn save_pin(path: &Path, prev: Option<&Pin>, pin: &Pin) -> Result<()> {
    let dir = path.parent().context("the pin path has no directory")?;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("cannot create the directory {}", dir.display()))?;
    let _lock = lock_pin(path)?;
    let prev = prev.cloned().map(Pin::normalized);
    let prev = prev.as_ref();
    let pin = &pin.clone().normalized();
    match (load_pin(path)?, prev) {
        (None, None) => {}
        (Some(cur), Some(prev)) if cur == *prev => {
            if pin.host != cur.host {
                bail!(
                    "refusing to replace the pin in {}: it is for {}, the new one for {}",
                    path.display(),
                    cur.host,
                    pin.host
                );
            }
            if pin.version <= cur.version {
                bail!(
                    "refusing to move the pin in {} backwards from version {} to {}: possible rollback",
                    path.display(),
                    cur.version,
                    pin.version
                );
            }
        }
        (Some(cur), _) => bail!(
            "refusing to replace the pin in {} (version {}): the new pin was not verified forward \
             from it (another chain, or the pin changed meanwhile). Delete that file only if you are \
             sure the server was reset on purpose",
            path.display(),
            cur.version
        ),
        (None, Some(_)) => bail!(
            "the pin {} disappeared while verifying; run mastersos-sign verify again",
            path.display()
        ),
    }
    let text = toml::to_string(pin).context("pin 序列化失败")?;
    write_replace(dir, path, text.as_bytes())
}

/// Hold an exclusive advisory lock on `<pin>.lock` until the guard drops. The lock file is
/// opened without following a symlink.
#[cfg(unix)]
fn lock_pin(path: &Path) -> Result<nix::fcntl::Flock<std::fs::File>> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    let lock_path = PathBuf::from(name);
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(&lock_path)
        .with_context(|| format!("cannot open the pin lock {}", lock_path.display()))?;
    nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusive)
        .map_err(|(_, e)| anyhow::anyhow!("cannot lock {}: {e}", lock_path.display()))
}

#[cfg(not(unix))]
fn lock_pin(_path: &Path) -> Result<()> {
    Ok(())
}

/// Replace `path` with `data`: a new uniquely named temporary file in `dir` (O_EXCL), fsync,
/// rename, fsync the directory. The temporary file is removed when anything fails.
fn write_replace(dir: &Path, path: &Path, data: &[u8]) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let file_name = path
        .file_name()
        .context("the pin path has no file name")?
        .to_string_lossy()
        .into_owned();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let tmp = dir.join(format!(
        ".{file_name}.{}.{}.{nanos}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let written = opts.open(&tmp).and_then(|mut f| {
        f.write_all(data)?;
        f.sync_all()
    });
    let renamed = written.and_then(|()| std::fs::rename(&tmp, path));
    if let Err(e) = renamed {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("cannot write the pin {}", path.display()));
    }
    #[cfg(unix)]
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| {
            format!(
                "the pin {} was written, but syncing its directory {} failed: it may not survive a \
                 power loss",
                path.display(),
                dir.display()
            )
        })?;
    Ok(())
}

fn tampered(v: u64, why: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!(
        "历史版本验不过，服务端可能被篡改：第 {v} 版 {}",
        crate::safe::field(&why.to_string())
    )
}

/// 从 pin 验到服务端的最新版，更新 pin，返回最新已验证的版本。见模块文档。
pub async fn verify_chain(
    api: &Api,
    pin_dir: &Path,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Verified> {
    let mut out = crate::safe::SafeWriter::new(out);
    let out: &mut dyn Write = &mut out;
    let path = pin_path(pin_dir, api);
    let latest = api.latest_version().await?;
    let Some(pin) = load_pin(&path)? else {
        return first_use(api, &path, latest, confirm, out).await;
    };
    if pin.host != api.host() {
        bail!(
            "pin 文件 {} 记的是 {}，不是 {}",
            path.display(),
            pin.host,
            api.host()
        );
    }
    if latest < pin.version {
        bail!(
            "服务端说最新是第 {latest} 版，而本地已验证过第 {} 版：版本回退，服务端可能被篡改",
            pin.version
        );
    }

    // pin 住的那一版：内容必须还是当时验证过的那一份。
    let archive = api.version_archive(pin.version).await?;
    let contents = read_archive(&archive)
        .map_err(|e| tampered(pin.version, e))?
        .contents;
    if hex(&content_digest(&contents)) != pin.digest_hex {
        return Err(tampered(pin.version, "的内容与上次验证过的不同"));
    }

    let mut cur = Verified {
        version: pin.version,
        digest_hex: pin.digest_hex.clone(),
        trust: pin.trust.clone(),
        contents,
        latest: pin.version,
        history: pin.verified.clone(),
    };
    for v in pin.version + 1..=latest {
        let archive = api.version_archive(v).await?;
        let (b, signer) =
            accept_signed(&archive, &cur.trust, Some(cur.version)).map_err(|e| tampered(v, e))?;
        if b.manifest.version != v {
            return Err(tampered(
                v,
                format!("的包里写的是第 {} 版", b.manifest.version),
            ));
        }
        let delta = TrustDelta::between(&cur.trust, &b.manifest.trust);
        if !delta.is_empty() {
            writeln!(
                out,
                "第 {v} 版改了 trust（已用第 {} 版的 trust 验过签名）：",
                cur.version
            )?;
            delta.print(out)?;
        }
        let old_recipients = Manifest::parse(&cur.contents.manifest_text)
            .map_err(|e| tampered(cur.version, e))?
            .school
            .escrow_recipients;
        if recipients_changed(&old_recipients, &b.manifest.school.escrow_recipients) {
            writeln!(
                out,
                "Version {v} changes the escrow recipients (machines seal their LUKS recovery keys \
                 to them):"
            )?;
            for r in &old_recipients {
                if !b.manifest.school.escrow_recipients.contains(r) {
                    writeln!(out, "  - {}", crate::safe::field(r))?;
                }
            }
            for r in &b.manifest.school.escrow_recipients {
                if !old_recipients.contains(r) {
                    writeln!(out, "  + {}", crate::safe::field(r))?;
                }
            }
        }
        // R7/R8: a trust or escrow-recipient change needs a recovery-kit signature. Machines
        // check this themselves (mastersos_bundle::check_recovery_signed, the same function) and
        // refuse such a version, staying on the one before it; an honest server never publishes
        // one. It showing up here means the server or the signing page was compromised. Make the
        // operator look and confirm before going on; once confirmed, go on as machines do: the
        // base (trust, contents, pin) stays at the version they accept, only `latest` moves, so
        // a later kit signature is never shown the forged additions as already present.
        if let Err(BundleError::KitRequired(what)) =
            check_recovery_signed(&cur.trust, &old_recipients, &b.manifest, &signer)
        {
            let rules = match what {
                KitChange::Trust => "R7",
                KitChange::Recipients => "R8",
                KitChange::TrustAndRecipients => "R7 and R8",
            };
            writeln!(
                out,
                "!!! WARNING: version {v} changes {} but is signed by a passkey, not a recovery kit \
                 (publishing rule {rules}).\n\
                 !!! An honest server never accepts this, and machines refuse it (they stay on version {}).\n\
                 !!! The server or the signing page may be compromised. Check every added or changed key\n\
                 !!! and recipient above; one you do not know means someone tried to take over the machines\n\
                 !!! or their recovery keys. Sign a corrected version with a recovery kit and check the server.",
                what.as_str(),
                cur.version
            )?;
            let typed = ask(
                confirm,
                out,
                &format!("Checked version {v}'s change and still continue from it? Type yes: "),
            )
            // 没有输入（seed-check 等非交互调用）同样算没有确认。
            .unwrap_or_default();
            if typed != "yes" {
                bail!(
                    "version {v} changes {} with a passkey signature (violates {rules}); not \
                     confirmed, cancelled, pin unchanged",
                    what.as_str()
                );
            }
            cur.latest = v;
            continue;
        }
        let digest_hex = hex(&content_digest(&b.contents));
        let mut history = std::mem::take(&mut cur.history);
        record_verified(&mut history, v, &digest_hex);
        cur = Verified {
            version: v,
            digest_hex,
            trust: b.manifest.trust,
            contents: b.contents,
            latest: v,
            history,
        };
    }
    if cur.latest != pin.version {
        writeln!(
            out,
            "已在本地逐版验证第 {} 版到第 {} 版。",
            pin.version + 1,
            cur.latest
        )?;
    }
    if cur.version != cur.latest {
        writeln!(
            out,
            "Machines stay on version {}: the versions after it that change trust or escrow \
             recipients without a recovery-kit signature are refused. The pin and the base for the \
             next signature stay at version {}; the next version is {}.",
            cur.version,
            cur.version,
            cur.latest + 1
        )?;
    }
    if cur.version != pin.version {
        save_pin(&path, Some(&pin), &pin_of(api, &cur))?;
    }
    Ok(cur)
}

pub(crate) fn pin_of(api: &Api, v: &Verified) -> Pin {
    Pin {
        host: api.host(),
        version: v.version,
        digest_hex: v.digest_hex.clone(),
        trust: v.trust.clone(),
        verified: v.history.clone(),
    }
}

/// 首次使用：没有可以往前验的锚，只能由人对照指纹确认最新版的 trust。
async fn first_use(
    api: &Api,
    path: &Path,
    latest: u64,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Verified> {
    if latest == 0 {
        bail!(
            "the server has not published any version yet: nothing to verify. The first version is \
             signed with a registered recovery key listed in its own trust (R1g): `mastersos-sign sign`"
        );
    }
    let archive = api.version_archive(latest).await?;
    let unpacked = read_archive(&archive).context("最新版的包解不开")?;
    let m = Manifest::parse(&unpacked.contents.manifest_text).context("最新版的清单读不懂")?;
    writeln!(
        out,
        "首次使用：本机还没有 {} 的验证记录（pin）。服务端最新是第 {latest} 版，它信任这些钥匙：",
        api.host()
    )?;
    print_trust(out, &m.trust)?;
    writeln!(
        out,
        "请逐把与管理网页「钥匙」页、种子开头注释里的指纹对照。之后的每一版都从这里往下验。"
    )?;
    let typed = ask(
        confirm,
        out,
        "与钥匙页、种子开头的指纹对照无误，请输入 yes：",
    )?;
    if typed != "yes" {
        bail!("没有确认首次信任的 trust，已取消");
    }
    let b = accept(&archive, &m.trust, None)
        .context("最新版的签名用它自己的 trust 都验不过：不信任这台服务端")?;
    if b.manifest.version != latest {
        bail!(
            "服务端说最新是第 {latest} 版，包里写的是第 {} 版",
            b.manifest.version
        );
    }
    let digest_hex = hex(&content_digest(&b.contents));
    let mut history = Vec::new();
    record_verified(&mut history, latest, &digest_hex);
    let v = Verified {
        version: latest,
        digest_hex,
        trust: b.manifest.trust,
        contents: b.contents,
        latest,
        history,
    };
    save_pin(path, None, &pin_of(api, &v))?;
    writeln!(out, "已记下第 {latest} 版的 trust（{}）。", path.display())?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(host: &str, version: u64, digest: &str) -> Pin {
        Pin {
            host: host.to_owned(),
            version,
            digest_hex: digest.to_owned(),
            trust: Vec::new(),
            verified: Vec::new(),
        }
        .normalized()
    }

    #[test]
    fn save_pin_refuses_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.toml");
        let p3 = pin("h", 3, "aa");
        save_pin(&path, None, &p3).unwrap();
        for v in [3, 2, 1] {
            let err = save_pin(&path, Some(&p3), &pin("h", v, "bb"))
                .unwrap_err()
                .to_string();
            assert!(err.contains("backwards"), "{err}");
        }
        assert_eq!(load_pin(&path).unwrap(), Some(p3.clone()));
        // Forward from exactly the pin on disk is fine.
        save_pin(&path, Some(&p3), &pin("h", 4, "cc")).unwrap();
        assert_eq!(load_pin(&path).unwrap().unwrap().version, 4);
    }

    /// The temporary file is unique and created exclusively: a symlink planted at the old fixed
    /// `.toml.tmp` name is neither followed nor needed, and nothing is left behind.
    #[cfg(unix)]
    #[test]
    fn save_pin_writes_through_a_fresh_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.toml");
        let target = dir.path().join("elsewhere");
        std::os::unix::fs::symlink(&target, dir.path().join("h.toml.tmp")).unwrap();
        save_pin(&path, None, &pin("h", 1, "aa")).unwrap();
        save_pin(&path, Some(&pin("h", 1, "aa")), &pin("h", 2, "bb")).unwrap();
        assert!(!target.exists(), "followed the planted symlink");
        assert_eq!(load_pin(&path).unwrap().unwrap().version, 2);
        let mut names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["h.toml", "h.toml.lock", "h.toml.tmp"]);
    }

    #[test]
    fn save_pin_refuses_other_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.toml");
        let p3 = pin("h", 3, "aa");
        save_pin(&path, None, &p3).unwrap();
        // A first-use or genesis pin (no previous pin) over an existing one.
        let err = save_pin(&path, None, &pin("h", 9, "bb"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not verified forward"), "{err}");
        assert!(err.contains(&path.display().to_string()), "{err}");
        // Verified from some other version-3 pin (different content): another chain.
        let other = pin("h", 3, "ff");
        let err = save_pin(&path, Some(&other), &pin("h", 4, "bb"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not verified forward"), "{err}");
        let err = save_pin(&path, Some(&p3), &pin("other", 4, "bb"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("is for h"), "{err}");
        assert_eq!(load_pin(&path).unwrap(), Some(p3));
        // A pin that vanished while verifying.
        let gone = dir.path().join("gone.toml");
        assert!(save_pin(&gone, Some(&pin("h", 1, "aa")), &pin("h", 2, "bb")).is_err());
    }

    mod history {
        use super::super::*;
        use mastersos_bundle::{pack, Ed25519Signer};

        fn archive(v: u64, note: &str) -> Vec<u8> {
            let k = Ed25519Signer::from_seed("key-1", &[1; 32]);
            let t = k.trust_key();
            let text = format!(
                "version = {v}\nissued_at = \"2026-11-03T00:00:00Z\"\n\n[[trust]]\nid = \"{}\"\nalg = \"ed25519\"\npublic_key = \"{}\"\n\n[school]\nid = \"11111111-1111-1111-1111-111111111111\"\n\n[[config]]\nid = \"default\"\nname = \"Default {note}\"\ninterface = \"learning\"\nlogin_methods = [\"local\"]\n\n[[group]]\nid = \"default\"\nname = \"Ungrouped\"\nconfig = \"default\"\n",
                t.id, t.public_key
            );
            pack(
                &Contents {
                    manifest_text: text,
                    files: Default::default(),
                },
                &k,
            )
            .unwrap()
        }

        fn digest(a: &[u8]) -> String {
            hex(&content_digest(&read_archive(a).unwrap().contents))
        }

        #[test]
        fn pinned_history_records_each_verified_version() {
            let mut list = Vec::new();
            for v in [3, 4, 4, 5] {
                record_verified(&mut list, v, &format!("d{v}"));
            }
            assert_eq!(
                list.iter().map(|e| e.version).collect::<Vec<_>>(),
                [3, 4, 5]
            );
            // It survives the pin file, and a pin file without the field still loads, with the
            // pinned version recorded.
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("h.toml");
            let mut p = super::pin("h", 5, "d5");
            p.verified = list.clone();
            save_pin(&path, None, &p).unwrap();
            assert_eq!(load_pin(&path).unwrap().unwrap().verified, list);
            let old = dir.path().join("old.toml");
            std::fs::write(
                &old,
                "host = \"h\"\nversion = 2\ndigest_hex = \"d2\"\ntrust = []\n",
            )
            .unwrap();
            let loaded = load_pin(&old).unwrap().unwrap();
            assert_eq!(
                loaded.verified,
                [VerifiedVersion {
                    version: 2,
                    digest_hex: "d2".into()
                }]
            );
        }

        #[test]
        fn pull_version_requires_recorded_digest() {
            let (a2, a3) = (archive(2, "real"), archive(2, "forged"));
            let mut list = Vec::new();
            record_verified(&mut list, 2, &digest(&a2));
            assert!(recorded_contents(&list, 2, &a2)
                .unwrap()
                .manifest_text
                .contains("real"));
            assert!(recorded_contents(&list, 2, &a3).is_err());
        }

        #[test]
        fn pull_version_before_first_use_refused() {
            let a = archive(1, "x");
            let mut list = Vec::new();
            record_verified(&mut list, 2, &digest(&archive(2, "y")));
            let err = recorded_contents(&list, 1, &a).unwrap_err().to_string();
            assert!(
                err.contains("before this computer started verifying"),
                "{err}"
            );
        }
    }
}
