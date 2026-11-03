//! 状态目录（加密根分区上的 `/var/lib/mastersos`，0700）：文件写入都经 [`safefs`]（同目录临时
//! 文件 → fsync → `renameat`），断电不会留下写了一半的文件。`current/` 的整目录换新仍是
//! 目录级的 `rename`，只发生在这个 root 0700 的目录里。
//!
//! 恢复出厂清空加密根分区，这里随之消失：脚本记录、托管路径自然清零，不需要别的办法识别
//! 「这是恢复出厂后的机器」（Ruling 16）；种子与缓存包由 [`crate::seedpart`] 从种子分区导入。

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use mastersos_bundle::{
    accept_for_school, accept_update_for_school, check_member_path, check_school, content_digest,
    Bundle, BundleError, Seed, TrustKey,
};
use serde::{Deserialize, Serialize};

use crate::safefs;

const SEED_FILE: &str = "seed.toml";
const STATE_FILE: &str = "state.json";
const STATE_CORRUPT: &str = "state.json.corrupt";
const BUNDLE_FILE: &str = "current.bundle";
const CURRENT: &str = "current";
/// 旧布局（`current/` 是真实目录）中途断电留下的，见到就删。
const CURRENT_NEW: &str = "current.new";
const CURRENT_OLD: &str = "current.old";
/// 每个接受过的包解到自己的 `versions/<v>-<摘要>/`，解好之后不再改动；`current` 是指向其中
/// 一个的符号链接，原子地切换。应用任务一轮从头到尾只用它开始时的那个目录，新包落盘不会让
/// 正在跑的一轮读到新包的文件。
const VERSIONS: &str = "versions";
/// 执行 apply 脚本用的私有目录（0700）：脚本先从包里读出、算哈希，再把同一份字节写到这里执行。
const RUN_DIR: &str = "run";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub device_id: Option<String>,
    /// 当前已应用设置包的版本。
    #[serde(default)]
    pub version: Option<u64>,
    /// 机器当前信任的公钥；只在 `accept` 成功之后才会变。
    #[serde(default)]
    pub trust: Vec<TrustKey>,
    /// 验过 `current.bundle` 的那组公钥（接受它之前的 `trust`）。轮换后 `trust`
    /// 已换成新包列出的钥匙，而 `current.bundle` 仍是旧钥匙签的：开机复验用这一组。
    /// 与 `trust` 在同一次 `save` 里写入。
    #[serde(default)]
    pub bundle_trust: Vec<TrustKey>,
    /// 最近一次拒收的包的 sha256。只认内容、不认它自称的版本号：
    /// 同一个包再送来时直接拒收，而它的版本号不会影响下一次去拿什么。
    #[serde(default)]
    pub rejected_sha256: Option<String>,
    /// The agent build ([`agent_build`]) that refused `rejected_sha256`. A refusal recorded by
    /// another build (or by one from before this field, `None`) is not honoured: an older agent
    /// refuses a bundle whose `format` it cannot read, and the updated OS must look at it again.
    /// The same build still refuses the same bytes without unpacking them.
    #[serde(default)]
    pub rejected_by: Option<String>,
    #[serde(default)]
    pub last_fetch_ok: Option<DateTime<Utc>>,
    /// 接受当前这一版的时刻。旧 state 没有它：启动时用 `last_fetch_ok` 补。
    #[serde(default)]
    pub accepted_at: Option<DateTime<Utc>>,
    /// 验过的心跳说当前这一版到这个时刻都是最新的（只往后推，不往前拉）。
    #[serde(default)]
    pub fresh_until: Option<DateTime<Utc>>,
    /// 验过的心跳说有这一版，立即再拉一次仍拿不到：更新可能被扣住了。
    /// 接受了不低于它的版本就清掉。
    #[serde(default)]
    pub newer_withheld: Option<u64>,
    /// 上次取心跳的时刻。
    #[serde(default)]
    pub heartbeat_checked_at: Option<DateTime<Utc>>,
    /// 脚本路径 → 上次成功（退出码 0）运行时的内容哈希。
    #[serde(default)]
    pub script_hashes: BTreeMap<String, String>,
    /// 目标路径 → agent 写入时的 sha256。
    #[serde(default)]
    pub managed_paths: BTreeMap<String, String>,
    /// `"<uid>:<脚本路径>"` → 这个用户上次成功（退出码 0）跑这个 `login` 脚本时的内容哈希（Task 18）。uid 只在本机
    /// state 里，不进回报；恢复出厂后 uid 会重新分配，但 state.json 随加密根分区一起清空（4a Ruling 16）。
    #[serde(default)]
    pub login_script_hashes: BTreeMap<String, String>,
    /// 这份状态是从种子分区导入的（新装或恢复出厂）：何时、种子里有哪些 trust 钥匙。
    /// 回报给服务端对照，发现被离线改过的种子分区（检测，不是防御）。
    #[serde(default)]
    pub seed_import: Option<SeedImport>,
    /// The school id of the last accepted bundle that named one (plan 6 Task 10b review M1).
    /// Once set, every later bundle must name this school, whatever the seed says: the seed
    /// partition is not encrypted, and stripping its `school_id` must not let the machine take
    /// another school's bundles. Never set on machines that only ever saw bundles without an id.
    #[serde(default)]
    pub school_id: Option<String>,
    /// The `[school].escrow_recipients` of the accepted bundle (`version`), kept beside `trust`
    /// so that rules R7/R8 ([`Prior::Accepted`]) still know them when `current.bundle` fails its
    /// boot re-check (Task 24c fix round 1, m1). `None` in a state.json written before.
    #[serde(default)]
    pub accepted_recipients: Option<Vec<String>>,
    /// The highest inbox `seq` handled (MQTT push spec §6.3); the main loop is its only writer.
    #[serde(default)]
    pub inbox_after: u64,
    /// This state was imported fresh after an inbox factory reset whose `seq` the seed partition
    /// named ([`crate::inbox::RESET_SEQ`]): ack it `done`, then clear this. Kept here so that a
    /// failed ack is retried, across reboots too.
    #[serde(default)]
    pub reset_done_seq: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedImport {
    pub at: DateTime<Utc>,
    /// 每把 trust 钥匙的指纹（`mastersos_bundle::trust_fingerprint`，与 `mastersos-sign seed-check` 相同）。
    pub trust_fingerprints: Vec<String>,
}

/// This agent build, as recorded beside a refusal: the crate version and the highest bundle
/// `format` it reads.
pub fn agent_build() -> String {
    format!(
        "{}/format-{}",
        env!("CARGO_PKG_VERSION"),
        mastersos_bundle::MAX_FORMAT
    )
}

impl State {
    /// `sha` is the bundle this agent build refused before (see [`State::rejected_by`]).
    pub fn refused_before(&self, sha: &str) -> bool {
        self.rejected_sha256.as_deref() == Some(sha)
            && self.rejected_by.as_deref() == Some(agent_build().as_str())
    }

    /// Records that this agent build refused `sha`.
    pub fn record_refusal(&mut self, sha: String) {
        self.rejected_sha256 = Some(sha);
        self.rejected_by = Some(agent_build());
    }

    /// Forgets the recorded refusal.
    pub fn clear_refusal(&mut self) {
        self.rejected_sha256 = None;
        self.rejected_by = None;
    }
}

fn fsync_dir(dir: &Path) -> Result<()> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("fsync of directory {}", dir.display()))
}

/// 经 [`safefs`] 写：同目录临时文件 → fchmod(mode) → fsync → `renameat` 到 `name` → fsync 目录。
fn write_in(dir: &OwnedFd, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
    let mut t = safefs::TmpFile::create(dir, name, mode)?;
    t.write_all(bytes)
        .with_context(|| format!("writing the temporary file for {name}"))?;
    t.commit()
}

/// 写 `path`（父目录必须已存在）：见 [`write_in`]。测试里模拟断电用。
#[cfg(test)]
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("the path has no parent directory")?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("the file name is not UTF-8")?;
    let dir = safefs::open_dir(parent, Path::new(""), false)?;
    write_in(&dir, name, bytes, mode)
}

/// 打开（必要时建出）状态目录并收紧到 0700（Global Constraints）。
pub fn ensure_state_dir(dir: &Path) -> Result<OwnedFd> {
    let fd = safefs::open_abs_dir(dir, true)?;
    safefs::set_mode(&fd, 0o700)?;
    Ok(fd)
}

/// 读种子（`<dir>/seed.toml`）与状态。
///
/// 信任只能来自 state.json 或种子，不会是空的：state.json 不存在、解析不了
/// （改名为 `state.json.corrupt` 留证后从种子重建），或其中 `trust` 为空，都退回种子的钥匙。
pub fn load(dir: &Path) -> Result<(Seed, State)> {
    let seed_text = fs::read_to_string(dir.join(SEED_FILE))
        .with_context(|| format!("reading {}", dir.join(SEED_FILE).display()))?;
    let seed = Seed::parse(&seed_text).context("parsing the seed failed")?;
    if seed.trust.is_empty() {
        anyhow::bail!("the seed has no trusted public keys");
    }
    let path = dir.join(STATE_FILE);
    let mut state = match fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<State>(&bytes) {
            Ok(s) => s,
            Err(e) => {
                log::error!("parsing state.json failed ({e}); renaming it as evidence and rebuilding from the seed");
                let _ = fs::rename(&path, dir.join(STATE_CORRUPT));
                State::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
        Err(e) => return Err(e).context("reading state.json"),
    };
    if state.trust.is_empty() {
        state.trust = seed.trust.clone();
    }
    Ok((seed, state))
}

/// 指向当前设置包的符号链接（`<dir>/current` → `versions/<名字>`）。应用任务不经它，
/// 用 [`version_dir`]。
pub fn current_dir(dir: &Path) -> PathBuf {
    dir.join(CURRENT)
}

/// 一个包的目录名：`v<版本>-<内容摘要前 16 位>`。
pub fn version_name(bundle: &Bundle) -> String {
    let d = crate::apply::hex(&content_digest(&bundle.contents));
    format!("v{}-{}", bundle.manifest.version, &d[..16])
}

/// 这个包解开后的目录（`<dir>/versions/<名字>`），解好之后不再改动。
pub fn version_dir(dir: &Path, bundle: &Bundle) -> PathBuf {
    dir.join(VERSIONS).join(version_name(bundle))
}

/// `current` 现在指向的包目录名。
pub fn current_version_name(dir: &Path) -> Option<String> {
    let fd = safefs::open_dir(dir, Path::new(""), false).ok()?;
    let t = safefs::read_link_at(&fd, CURRENT)?;
    t.strip_prefix(&format!("{VERSIONS}/")).map(str::to_owned)
}

/// 执行 apply 脚本的私有目录：建出来（0700）并清掉上次留下的文件。
pub fn run_dir(dir: &Path) -> Result<PathBuf> {
    ensure_state_dir(dir)?;
    let p = dir.join(RUN_DIR);
    let fd = safefs::open_abs_dir(&p, true)?;
    safefs::set_mode(&fd, 0o700)?;
    for name in safefs::list_at(&fd)? {
        let _ = safefs::remove_at(&fd, &name);
    }
    Ok(p)
}

/// 留下 `current` 指向的与 `extra`，删掉 `versions/` 里别的目录。读不出 `current` 指向哪里
/// 时什么都不删（宁可多留，也不删掉当前包的目录）。
pub fn gc_keep_current(dir: &Path, extra: Option<String>) {
    let Some(cur) = current_version_name(dir) else {
        if dir.join(VERSIONS).exists() {
            log::warn!(
                "cannot tell which bundle directory current points to; not cleaning up this time"
            );
        }
        return;
    };
    let keep: Vec<String> = std::iter::once(cur).chain(extra).collect();
    gc_versions(dir, &keep);
}

/// 删掉 `versions/` 里不在 `keep` 中的目录（包括没解完的临时目录）。
pub fn gc_versions(dir: &Path, keep: &[String]) {
    let vers = dir.join(VERSIONS);
    let Ok(rd) = fs::read_dir(&vers) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if keep.contains(&name) {
            continue;
        }
        if let Err(e) = fs::remove_dir_all(e.path()) {
            log::warn!("removing the old bundle directory {name} failed: {e}");
        }
    }
}

pub fn save(dir: &Path, state: &State) -> Result<()> {
    let fd = ensure_state_dir(dir)?;
    let json = serde_json::to_vec_pretty(state)?;
    write_in(&fd, STATE_FILE, &json, 0o600)
}

/// 把验过的包落盘：`current.bundle` 原子写入，`files/`、`scripts/` 解到 `versions/<名字>/`
/// （已有就不动），再把 `current` 原子地指过去。脚本 0755，其余 0644。
pub fn store_bundle(dir: &Path, archive: &[u8], bundle: &Bundle) -> Result<()> {
    let fd = ensure_state_dir(dir)?;
    write_in(&fd, BUNDLE_FILE, archive, 0o600)?;
    unpack_current(dir, bundle)
}

/// 把包解到它自己的目录并让 `current` 指向它；清掉旧布局留下的 `current.new/`、`current.old/`
/// 与真实目录的 `current/`。无论现在是什么样子，结果都与 `bundle` 一致。
fn unpack_current(dir: &Path, bundle: &Bundle) -> Result<()> {
    let name = version_name(bundle);
    let vers = dir.join(VERSIONS);
    let vfd = safefs::open_abs_dir(&vers, true)?;
    safefs::set_mode(&vfd, 0o700)?;
    let fin = vers.join(&name);
    if !fin.is_dir() {
        let new = vers.join(format!(".new-{name}"));
        if new.exists() {
            fs::remove_dir_all(&new)?;
        }
        fs::create_dir(&new)?;
        for (rel, bytes) in &bundle.contents.files {
            // accept 已校验过；这里仍只经由校验后的相对路径拼接。
            check_member_path(rel).map_err(|e| anyhow::anyhow!("{e}"))?;
            let (parent, file) = match rel.rsplit_once('/') {
                Some((p, n)) => (p, n),
                None => ("", rel.as_str()),
            };
            let d = safefs::open_dir(&new, Path::new(parent), true)?;
            let mode = if rel.starts_with("scripts/") {
                0o755
            } else {
                0o644
            };
            write_in(&d, file, bytes, mode)?;
        }
        fsync_dir(&new)?;
        fs::rename(&new, &fin)?;
        fsync_dir(&vers)?;
    }
    let state = safefs::open_dir(dir, Path::new(""), false)?;
    let cur = dir.join(CURRENT);
    if fs::symlink_metadata(&cur).is_ok_and(|m| m.is_dir()) {
        fs::remove_dir_all(&cur)?;
    }
    safefs::replace_symlink_at(&state, CURRENT, &format!("{VERSIONS}/{name}"))?;
    // current 已经切过去了：之后清旧布局的残留失败不能让调用方以为没换成（否则内存里还是
    // 旧包、current 却指向新包，下一次清理会删掉旧包的目录），只记日志，下次再清。
    for leftover in [CURRENT_NEW, CURRENT_OLD] {
        let p = dir.join(leftover);
        if fs::symlink_metadata(&p).is_ok() {
            if let Err(e) = fs::remove_dir_all(&p) {
                log::warn!("cleaning up {leftover} failed: {e}");
            }
        }
    }
    Ok(())
}

/// What this machine accepted before the bundle being checked, for rules R7/R8
/// ([`mastersos_bundle::check_recovery_signed`], plan 6 Task 24c).
#[derive(Debug, Clone, Copy)]
pub enum Prior<'a> {
    /// Nothing since the seed (genesis), or re-checking the accepted bundle itself at boot:
    /// the trust passed in decides alone.
    Nothing,
    /// A bundle was accepted and `trust` is its trust. Its escrow recipients: from the bundle
    /// itself, or from [`State::accepted_recipients`] when the local copy failed its boot
    /// re-check. `None` only when neither is known (a state.json from before that field and a
    /// broken `current.bundle`): then only a recovery-kit signature is accepted (fail closed).
    ///
    /// Not covered: when state.json itself is lost or corrupt and `current.bundle` no longer
    /// verifies with the seed's trust, the machine has no accepted version and is back at genesis
    /// ([`Prior::Nothing`]), like a freshly installed one. That needs local tampering with the
    /// encrypted root, not anything the server can do.
    Accepted(Option<&'a [String]>),
}

/// [`accept_for_school`] with the seed's school id, then the school this machine remembered
/// ([`State::school_id`]): a bundle naming another school, or none, is refused once one is
/// remembered (`BundleError::OtherSchool`). After an accepted bundle ([`Prior::Accepted`]) a
/// change of trust or escrow recipients must also be signed by a recovery kit of the current
/// trust (`BundleError::KitRequired`): the server is not trusted to enforce R7/R8.
pub fn accept_bundle(
    archive: &[u8],
    trust: &[TrustKey],
    floor: Option<u64>,
    seed_school: Option<&str>,
    remembered: Option<&str>,
    prior: Prior<'_>,
) -> Result<Bundle, BundleError> {
    let b = match prior {
        Prior::Nothing => accept_for_school(archive, trust, floor, seed_school)?,
        Prior::Accepted(recipients) => {
            accept_update_for_school(archive, trust, recipients, floor, seed_school)?
        }
    };
    check_school(&b.manifest, remembered)?;
    Ok(b)
}

/// 开机时重读本地的包：仍然验签、校验清单，但不检查版本。任何错误都返回 None。
/// 返回 Some 之前会确保这个包的 `versions/<名字>/` 解好、`current` 指向它（并清掉旧布局的
/// 残留），修复 `store_bundle` 中途断电留下的「包是新的、目录是旧的或缺失」。
/// `school`: the seed's school id; a bundle naming another school (or none) is refused, as in
/// `take_new` (plan 6 Task 10b).
pub fn load_current(dir: &Path, trust: &[TrustKey], school: Option<&str>) -> Option<Bundle> {
    load_current_with(dir, &[trust], school, None).map(|(b, _)| b)
}

/// 同 `load_current`，但依次用 `candidates` 里的每组公钥复验（跳过空的），
/// 返回包和验过它的那一组。`remembered`: [`State::school_id`] ([`accept_bundle`]).
pub fn load_current_with(
    dir: &Path,
    candidates: &[&[TrustKey]],
    school: Option<&str>,
    remembered: Option<&str>,
) -> Option<(Bundle, Vec<TrustKey>)> {
    let bytes = match fs::read(dir.join(BUNDLE_FILE)) {
        Ok(b) => b,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                log::warn!("reading current.bundle failed: {:?}", e.kind());
            }
            return None;
        }
    };
    let mut last_err = None;
    for trust in candidates.iter().filter(|t| !t.is_empty()) {
        match accept_bundle(&bytes, trust, None, school, remembered, Prior::Nothing) {
            Ok(b) => {
                return match unpack_current(dir, &b) {
                    Ok(()) => Some((b, trust.to_vec())),
                    Err(e) => {
                        log::warn!("rebuilding current/ from the local bundle failed: {:#}", e);
                        None
                    }
                };
            }
            Err(e) => last_err = Some(e),
        }
    }
    // 只记错误种类，不带包内容。
    if let Some(e) = last_err {
        log::warn!("the local bundle failed verification: {}", e);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use mastersos_bundle::{pack, Contents, Ed25519Signer};
    use std::os::unix::fs::PermissionsExt;

    fn signer() -> Ed25519Signer {
        Ed25519Signer::from_pkcs8("k1", &Ed25519Signer::generate_pkcs8()).unwrap()
    }

    fn make(s: &Ed25519Signer, version: u64, files: &[(&str, &[u8])]) -> (Vec<u8>, Bundle) {
        let k = s.trust_key();
        let manifest_text = format!(
            "version = {version}\n\n[[trust]]\nid = \"{}\"\nalg = \"ed25519\"\npublic_key = \"{}\"\n\n[[group]]\nid = \"default\"\nname = \"x\"\n",
            k.id, k.public_key
        );
        let c = Contents {
            manifest_text,
            files: files
                .iter()
                .map(|(p, b)| (p.to_string(), b.to_vec()))
                .collect(),
        };
        let archive = pack(&c, s).unwrap();
        let bundle = mastersos_bundle::accept(&archive, &[k], None).unwrap();
        (archive, bundle)
    }

    #[test]
    fn refusal_by_another_agent_build_is_not_honoured() {
        let sha = "ab".repeat(32);
        // A state.json written before `rejected_by` existed (a pre-Phase-B agent) still loads.
        let old: State =
            serde_json::from_str(&format!(r#"{{"version":3,"rejected_sha256":"{sha}"}}"#)).unwrap();
        assert_eq!(old.rejected_sha256.as_deref(), Some(sha.as_str()));
        assert_eq!(old.rejected_by, None);
        assert!(
            !old.refused_before(&sha),
            "an old agent's refusal is looked at again"
        );

        let mut other = old.clone();
        other.rejected_by = Some("0.1.0/format-1".into());
        assert!(!other.refused_before(&sha));

        let mut st = old;
        st.record_refusal(sha.clone());
        assert_eq!(st.rejected_by, Some(agent_build()));
        assert!(
            st.refused_before(&sha),
            "the same build keeps refusing the same bytes"
        );
        assert!(!st.refused_before(&"cd".repeat(32)));
        st.clear_refusal();
        assert!(!st.refused_before(&sha));
        assert_eq!((st.rejected_sha256, st.rejected_by), (None, None));
    }

    #[test]
    fn load_derives_trust_from_seed_without_state() {
        let d = tempfile::tempdir().unwrap();
        let s = signer();
        let seed = Seed {
            server_url: "http://x".into(),
            trust: vec![s.trust_key()],
            fetch_token: None,
            group: None,
            oidc: None,
            min_version: None,
            school_id: None,
            wifi: vec![],
            school_name: None,
            it_account: None,
        };
        fs::write(d.path().join("seed.toml"), seed.to_toml()).unwrap();
        let (seed2, st) = load(d.path()).unwrap();
        assert_eq!(seed2, seed);
        assert_eq!(st.trust, seed.trust);
        assert_eq!(st.version, None);

        let mut st = st;
        st.version = Some(7);
        save(d.path(), &st).unwrap();
        let (_, back) = load(d.path()).unwrap();
        assert_eq!(back, st);

        // state.json 里的 trust 被清空：不会变成「谁的钥匙都不认」或「什么都认」，退回种子。
        st.trust.clear();
        save(d.path(), &st).unwrap();
        let (_, back) = load(d.path()).unwrap();
        assert_eq!(back.trust, seed.trust);
        assert_eq!(back.version, Some(7));
    }

    #[test]
    fn corrupt_state_falls_back_to_seed_trust() {
        let d = tempfile::tempdir().unwrap();
        let s = signer();
        let seed = Seed {
            server_url: "http://x".into(),
            trust: vec![s.trust_key()],
            fetch_token: None,
            group: None,
            oidc: None,
            min_version: None,
            school_id: None,
            wifi: vec![],
            school_name: None,
            it_account: None,
        };
        fs::write(d.path().join("seed.toml"), seed.to_toml()).unwrap();
        fs::write(d.path().join("state.json"), b"{\"trust\": 12, garbage").unwrap();
        let (_, st) = load(d.path()).unwrap();
        assert_eq!(st.trust, seed.trust);
        assert_eq!(st.version, None);
        assert!(
            d.path().join("state.json.corrupt").exists(),
            "the damaged file is kept as evidence"
        );
        assert!(!d.path().join("state.json").exists());

        // 种子里没有钥匙：不启动，而不是带着空的信任列表跑。
        let empty = Seed {
            trust: vec![],
            ..seed
        };
        fs::write(d.path().join("seed.toml"), empty.to_toml()).unwrap();
        assert!(load(d.path()).is_err());
    }

    #[test]
    fn state_save_is_atomic() {
        let d = tempfile::tempdir().unwrap();
        let seed = Seed {
            server_url: "http://x".into(),
            trust: vec![signer().trust_key()],
            fetch_token: None,
            group: None,
            oidc: None,
            min_version: None,
            school_id: None,
            wifi: vec![],
            school_name: None,
            it_account: None,
        };
        fs::write(d.path().join("seed.toml"), seed.to_toml()).unwrap();
        let good = State {
            version: Some(3),
            trust: seed.trust.clone(),
            ..State::default()
        };
        save(d.path(), &good).unwrap();
        // 模拟断电：下一次写到一半，只留下半截临时文件。
        fs::write(d.path().join("state.json.tmp"), b"{\"version\": 9, \"tr").unwrap();
        let (_, st) = load(d.path()).unwrap();
        assert_eq!(st, good);
        // 残留不会挡住下一次保存。
        let next = State {
            version: Some(4),
            trust: seed.trust.clone(),
            ..State::default()
        };
        save(d.path(), &next).unwrap();
        assert_eq!(load(d.path()).unwrap().1, next);
    }

    #[test]
    fn store_bundle_replaces_unpacked_dir() {
        let d = tempfile::tempdir().unwrap();
        let s = signer();
        let (a1, b1) = make(
            &s,
            1,
            &[
                ("files/a.jpg", b"jpg"),
                ("files/b.txt", b"b"),
                ("scripts/x.sh", b"#!/bin/sh\n"),
            ],
        );
        store_bundle(d.path(), &a1, &b1).unwrap();
        let cur = d.path().join("current");
        assert_eq!(fs::read(cur.join("files/a.jpg")).unwrap(), b"jpg");
        let mode = |p: &str| fs::metadata(cur.join(p)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode("scripts/x.sh"), 0o755);
        assert_eq!(mode("files/b.txt"), 0o644);

        let (a2, b2) = make(&s, 2, &[("files/b.txt", b"b2")]);
        store_bundle(d.path(), &a2, &b2).unwrap();
        assert!(!cur.join("files/a.jpg").exists());
        assert!(!cur.join("scripts/x.sh").exists());
        assert_eq!(fs::read(cur.join("files/b.txt")).unwrap(), b"b2");
        assert_eq!(fs::read(d.path().join("current.bundle")).unwrap(), a2);
        assert!(!d.path().join("current.new").exists());
        assert!(!d.path().join("current.old").exists());
    }

    fn assert_current_is(d: &Path, files: &[(&str, &[u8])]) {
        let cur = d.join("current");
        let mut found = vec![];
        for sub in ["files", "scripts"] {
            if let Ok(rd) = fs::read_dir(cur.join(sub)) {
                for e in rd {
                    let e = e.unwrap();
                    found.push(format!("{sub}/{}", e.file_name().to_string_lossy()));
                }
            }
        }
        found.sort();
        let mut want: Vec<String> = files.iter().map(|(p, _)| p.to_string()).collect();
        want.sort();
        assert_eq!(found, want);
        for (p, b) in files {
            assert_eq!(fs::read(cur.join(p)).unwrap(), *b);
        }
        assert!(!d.join("current.new").exists());
        assert!(!d.join("current.old").exists());
    }

    #[test]
    fn load_current_repairs_stale_dir_after_crash_before_swap() {
        let d = tempfile::tempdir().unwrap();
        let s = signer();
        let (a1, b1) = make(&s, 1, &[("files/a.txt", b"v1")]);
        store_bundle(d.path(), &a1, &b1).unwrap();
        // 断电：current.bundle 已是 v2，current/ 仍是 v1 的文件，current.new/ 写了一半。
        let sh: &[u8] = b"#!/bin/sh\n";
        let (a2, _) = make(&s, 2, &[("files/b.txt", b"v2"), ("scripts/x.sh", sh)]);
        write_atomic(&d.path().join("current.bundle"), &a2, 0o600).unwrap();
        fs::create_dir_all(d.path().join("current.new/files")).unwrap();
        fs::write(d.path().join("current.new/files/half"), b"x").unwrap();

        let got = load_current(d.path(), &[s.trust_key()], None).unwrap();
        assert_eq!(got.manifest.version, 2);
        assert_current_is(d.path(), &[("files/b.txt", b"v2"), ("scripts/x.sh", sh)]);
        let m = fs::metadata(d.path().join("current/scripts/x.sh")).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o755);
    }

    #[test]
    fn load_current_repairs_missing_dir_between_renames() {
        let d = tempfile::tempdir().unwrap();
        let s = signer();
        let (a1, b1) = make(&s, 1, &[("files/a.txt", b"v1")]);
        store_bundle(d.path(), &a1, &b1).unwrap();
        let (a2, _) = make(&s, 2, &[("files/b.txt", b"v2")]);
        write_atomic(&d.path().join("current.bundle"), &a2, 0o600).unwrap();
        // 断电发生在两次 rename 之间：current/ 不见了，只剩 current.old/ 和写满的 current.new/。
        fs::rename(d.path().join("current"), d.path().join("current.old")).unwrap();
        fs::create_dir_all(d.path().join("current.new/files")).unwrap();
        fs::write(d.path().join("current.new/files/b.txt"), b"v2").unwrap();

        assert!(load_current(d.path(), &[s.trust_key()], None).is_some());
        assert_current_is(d.path(), &[("files/b.txt", b"v2")]);
    }

    #[test]
    fn load_current_cleans_leftovers_when_dir_already_matches() {
        let d = tempfile::tempdir().unwrap();
        let s = signer();
        let (a, b) = make(&s, 3, &[("files/a.txt", b"ok")]);
        store_bundle(d.path(), &a, &b).unwrap();
        fs::create_dir_all(d.path().join("current.old/files")).unwrap();
        fs::create_dir_all(d.path().join("current.new")).unwrap();
        assert!(load_current(d.path(), &[s.trust_key()], None).is_some());
        assert_current_is(d.path(), &[("files/a.txt", b"ok")]);
    }

    /// Plan 6 Task 10b: the bundle reloaded at boot passes the same school check as a new one.
    #[test]
    fn load_current_refuses_bundle_for_another_school() {
        const A: &str = "0192f3a4-5b6c-7d8e-9f00-00000000000a";
        const B: &str = "0192f3a4-5b6c-7d8e-9f00-00000000000b";
        let d = tempfile::tempdir().unwrap();
        let s = signer();
        let (a, b) = make(&s, 3, &[("files/a.txt", b"ok")]);
        store_bundle(d.path(), &a, &b).unwrap();
        // It names no school: a seed naming one refuses it.
        assert!(load_current(d.path(), &[s.trust_key()], Some(A)).is_none());
        let k = s.trust_key();
        let c = Contents {
            manifest_text: format!(
                "version = 4\n\n[school]\nid = \"{A}\"\n\n[[trust]]\nid = \"{}\"\nalg = \"ed25519\"\npublic_key = \"{}\"\n\n[[group]]\nid = \"default\"\nname = \"x\"\n",
                k.id, k.public_key
            ),
            files: Default::default(),
        };
        let archive = pack(&c, &s).unwrap();
        let bundle = mastersos_bundle::accept(&archive, std::slice::from_ref(&k), None).unwrap();
        store_bundle(d.path(), &archive, &bundle).unwrap();
        assert!(load_current(d.path(), std::slice::from_ref(&k), Some(B)).is_none());
        assert_eq!(
            load_current(d.path(), std::slice::from_ref(&k), Some(A))
                .unwrap()
                .manifest
                .version,
            4
        );
        assert!(load_current(d.path(), &[k], None).is_some());
    }

    /// Review M1 of Task 10b: once a school is remembered, a bundle (new or reloaded) naming
    /// another school or none is refused even when the seed names none (its id stripped from the
    /// unencrypted seed partition) or another; a machine that never remembered one takes a
    /// bundle without an id as before.
    #[test]
    fn remembered_school_refuses_other_or_missing() {
        const A: &str = "0192f3a4-5b6c-7d8e-9f00-00000000000a";
        const B: &str = "0192f3a4-5b6c-7d8e-9f00-00000000000b";
        let s = signer();
        let k = s.trust_key();
        let named = |school: Option<&str>| {
            let id = school
                .map(|i| format!("id = \"{i}\"\n"))
                .unwrap_or_default();
            let c = Contents {
                manifest_text: format!(
                    "version = 4\n\n[school]\n{id}\n[[trust]]\nid = \"{}\"\nalg = \"ed25519\"\npublic_key = \"{}\"\n\n[[group]]\nid = \"default\"\nname = \"x\"\n",
                    k.id, k.public_key
                ),
                files: Default::default(),
            };
            pack(&c, &s).unwrap()
        };
        let trust = std::slice::from_ref(&k);
        let (for_a, for_b, unnamed) = (named(Some(A)), named(Some(B)), named(None));
        // Remembered A: only A, whatever the seed says.
        for seed in [None, Some(A)] {
            accept_bundle(&for_a, trust, None, seed, Some(A), Prior::Nothing).unwrap();
        }
        for seed in [None, Some(B)] {
            assert!(matches!(
                accept_bundle(&for_b, trust, None, seed, Some(A), Prior::Nothing),
                Err(BundleError::OtherSchool)
            ));
        }
        assert!(matches!(
            accept_bundle(&unnamed, trust, None, None, Some(A), Prior::Nothing),
            Err(BundleError::OtherSchool)
        ));
        // Nothing remembered, no school in the seed: pre-6 lab seeds keep working.
        accept_bundle(&unnamed, trust, None, None, None, Prior::Nothing).unwrap();
        accept_bundle(&for_b, trust, None, None, None, Prior::Nothing).unwrap();
        // The bundle reloaded at boot is held to the remembered school as well.
        let d = tempfile::tempdir().unwrap();
        let b = mastersos_bundle::accept(&for_b, trust, None).unwrap();
        store_bundle(d.path(), &for_b, &b).unwrap();
        assert!(load_current_with(d.path(), &[trust], None, Some(A)).is_none());
        assert!(load_current_with(d.path(), &[trust], None, Some(B)).is_some());
        // An old state.json has no school_id.
        let st: State = serde_json::from_str("{}").unwrap();
        assert_eq!(st.school_id, None);
    }

    /// Plan 6 Task 24c: after an accepted bundle, a passkey-signed change of trust or escrow
    /// recipients is refused (the server is not trusted to enforce R7/R8); the same change signed
    /// by the recovery kit in the current trust, or a passkey-signed version that changes
    /// neither, is accepted. Genesis (`Prior::Nothing`) is not checked.
    #[test]
    fn accepted_bundle_needs_kit_for_trust_or_recipient_change() {
        use mastersos_bundle::kit::Kit;
        use mastersos_bundle::testutil::FakePasskey;
        use mastersos_bundle::webauthn::{FLAG_UP, FLAG_UV};
        let kit = Kit::from_master(&[1; 32]);
        let phone = FakePasskey::new("sign.test.invalid", "https://sign.test.invalid")
            .with_key_id("it-phone");
        let trust = vec![kit.trust_key(), phone.trust_key("it-phone")];
        let ours = vec![kit.escrow_recipient()];
        let theirs = Kit::from_master(&[9; 32]).escrow_recipient();
        let bundle = |recipients: &[String], by_kit: bool| {
            let mut text = format!(
                "version = 2\n\n[school]\nescrow_recipients = [{}]\n",
                recipients
                    .iter()
                    .map(|r| format!("\"{r}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            for k in &trust {
                text += &format!(
                    "\n[[trust]]\nid = \"{}\"\nalg = \"{}\"\npublic_key = \"{}\"\n",
                    k.id,
                    k.alg.as_str(),
                    k.public_key
                );
                if let Some(rp) = &k.rp_id {
                    text += &format!("rp_id = \"{rp}\"\n");
                }
            }
            text += "\n[[group]]\nid = \"default\"\nname = \"x\"\n";
            let c = Contents {
                manifest_text: text,
                files: Default::default(),
            };
            if by_kit {
                pack(&c, &kit.signer()).unwrap()
            } else {
                let sig = phone.sign(&mastersos_bundle::signed_message(&c), FLAG_UP | FLAG_UV);
                mastersos_bundle::assemble(&c, &sig).unwrap()
            }
        };
        let after = Prior::Accepted(Some(&ours));
        let added = [ours[0].clone(), theirs];
        assert!(matches!(
            accept_bundle(&bundle(&added, false), &trust, Some(1), None, None, after),
            Err(BundleError::KitRequired(_))
        ));
        accept_bundle(&bundle(&added, true), &trust, Some(1), None, None, after).unwrap();
        accept_bundle(&bundle(&ours, false), &trust, Some(1), None, None, after).unwrap();
        // Recipients unknown (no bundle, no remembered list): only the kit.
        let unknown = Prior::Accepted(None);
        assert!(matches!(
            accept_bundle(&bundle(&ours, false), &trust, Some(1), None, None, unknown),
            Err(BundleError::KitRequired(_))
        ));
        accept_bundle(&bundle(&ours, true), &trust, Some(1), None, None, unknown).unwrap();
        // An old state.json has no remembered recipients.
        let st: State = serde_json::from_str("{}").unwrap();
        assert_eq!(st.accepted_recipients, None);
        // Genesis: the seed's trust alone decides.
        accept_bundle(
            &bundle(&added, false),
            &trust,
            None,
            None,
            None,
            Prior::Nothing,
        )
        .unwrap();
    }

    #[test]
    fn load_current_rejected_bundle_leaves_dir_untouched() {
        let d = tempfile::tempdir().unwrap();
        let s = signer();
        let (a, b) = make(&s, 3, &[("files/a.txt", b"ok")]);
        store_bundle(d.path(), &a, &b).unwrap();
        assert!(load_current(d.path(), &[signer().trust_key()], None).is_none());
        assert_current_is(d.path(), &[("files/a.txt", b"ok")]);
    }

    #[test]
    fn each_bundle_has_its_own_immutable_dir() {
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::tempdir().unwrap();
        let s = signer();
        let (a1, b1) = make(&s, 1, &[("files/a.txt", b"v1")]);
        store_bundle(d.path(), &a1, &b1).unwrap();
        let v1 = version_dir(d.path(), &b1);
        let ino = fs::metadata(v1.join("files/a.txt")).unwrap().ino();
        let (a2, b2) = make(&s, 2, &[("files/a.txt", b"v2")]);
        store_bundle(d.path(), &a2, &b2).unwrap();
        // v1 的目录原样还在（正在跑的一轮还能读它），current 指向 v2。
        assert_eq!(fs::read(v1.join("files/a.txt")).unwrap(), b"v1");
        assert_eq!(fs::metadata(v1.join("files/a.txt")).unwrap().ino(), ino);
        assert_eq!(
            fs::read(d.path().join("current/files/a.txt")).unwrap(),
            b"v2"
        );
        assert!(fs::symlink_metadata(d.path().join("current"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(current_version_name(d.path()), Some(version_name(&b2)));
        // 再存一次同一个包：目录不重写。
        let ino2 = fs::metadata(version_dir(d.path(), &b2).join("files/a.txt"))
            .unwrap()
            .ino();
        store_bundle(d.path(), &a2, &b2).unwrap();
        assert_eq!(
            fs::metadata(version_dir(d.path(), &b2).join("files/a.txt"))
                .unwrap()
                .ino(),
            ino2
        );
        // 读不出 current：什么都不删。
        let link = d.path().join("current");
        let target = fs::read_link(&link).unwrap();
        fs::remove_file(&link).unwrap();
        gc_keep_current(d.path(), None);
        assert!(v1.exists() && version_dir(d.path(), &b2).exists());
        std::os::unix::fs::symlink(target, &link).unwrap();
        // 清理只留下 current 指向的。
        gc_keep_current(d.path(), None);
        assert!(!v1.exists());
        assert!(version_dir(d.path(), &b2).exists());
    }

    #[test]
    fn old_layout_current_dir_is_migrated() {
        let d = tempfile::tempdir().unwrap();
        let s = signer();
        // 旧布局：current/ 是真实目录。
        fs::create_dir_all(d.path().join("current/files")).unwrap();
        fs::write(d.path().join("current/files/old.txt"), b"x").unwrap();
        let (a, b) = make(&s, 3, &[("files/a.txt", b"ok")]);
        store_bundle(d.path(), &a, &b).unwrap();
        assert_current_is(d.path(), &[("files/a.txt", b"ok")]);
        assert!(fs::symlink_metadata(d.path().join("current"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn load_current_reverifies() {
        let d = tempfile::tempdir().unwrap();
        let s = signer();
        let (a, b) = make(&s, 5, &[("files/a.txt", b"hello")]);
        store_bundle(d.path(), &a, &b).unwrap();
        let trust = [s.trust_key()];
        let got = load_current(d.path(), &trust, None).unwrap();
        assert_eq!(got.manifest.version, 5);

        // 换一把信任的钥匙：拒绝。
        assert!(load_current(d.path(), &[signer().trust_key()], None).is_none());

        // 改一个字节：拒绝（gzip 校验或验签都会挡住）。
        let mut bad = a.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 1;
        fs::write(d.path().join("current.bundle"), bad).unwrap();
        assert!(load_current(d.path(), &trust, None).is_none());

        // 没有文件：None。
        fs::remove_file(d.path().join("current.bundle")).unwrap();
        assert!(load_current(d.path(), &trust, None).is_none());
    }
}
