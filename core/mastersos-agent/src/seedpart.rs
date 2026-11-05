//! 种子分区（Ruling 10、16）：不加密、恢复出厂时保留，放种子、最近一次验过的包的缓存、
//! `identity.json` 与执行过的远程恢复出厂请求的 id（`reset-done`，[`crate::reset`]，Ruling 22）。它**不是权威**：agent 的信任、版本下限与脚本记录都在加密根分区的
//! `/var/lib/mastersos`；种子分区只在那里没有状态（新装、恢复出厂）时被读取，读到的缓存包
//! 照常按种子的 `trust` 与 `min_version` 验签。所有写入都经 [`safefs`]，文件 0600。

use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::Engine;
use mastersos_bundle::Seed;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::safefs;

pub const SEED_PART_DIR: &str = "/var/lib/mastersos-seed";
pub const CACHE_BUNDLE: &str = "cache/current.bundle";
pub const IDENTITY: &str = "identity.json";
/// 从种子分区导入的缓存包，在 `state_dir` 里等待验签（验过或验不过都删掉）。
pub const INCOMING: &str = "incoming.bundle";

const SEED_FILE: &str = "seed.toml";
const STATE_FILE: &str = "state.json";
const CACHE_DIR: &str = "cache";
const CACHE_FILE: &str = "current.bundle";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub device_id: String,
    /// base64url（无填充）的 32 字节随机数：托管恢复密钥用的这台机器自己的凭据（Ruling 9）。
    pub escrow_secret: String,
}

/// 不打印 `escrow_secret`。
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("device_id", &self.device_id)
            .field("escrow_secret", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Imported {
    /// `state_dir` 里已有状态：种子分区一个字节都没读。
    Existing,
    /// 新装或恢复出厂：种子已复制进 `state_dir`；`cached_bundle` 时 `state_dir/incoming.bundle`
    /// 是种子分区里缓存的包，等着按种子验签。
    Fresh { cached_bundle: bool },
    /// 两边都没有种子：这是一台未受管的机器。
    Unmanaged,
}

/// 只有「不存在」算不存在；读不了（EIO、EACCES……）报错——这条路决定要不要从种子分区导入
/// 信任，不能把读错当成「状态目录是空的」。
fn exists(p: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(p) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("checking {}", p.display())),
    }
}

/// `dir` 是不是一个挂载点（与父目录不在同一个设备上）。种子分区的挂载带 `nofail`，挂不上时
/// `/var/lib/mastersos-seed` 只是根分区上的空目录：往里写 identity.json 或缓存，下次恢复出厂就丢了。
pub fn is_mount_point(dir: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let me =
        std::fs::symlink_metadata(dir).with_context(|| format!("checking {}", dir.display()))?;
    if !me.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    let parent = std::fs::metadata(dir.join(".."))
        .with_context(|| format!("checking the parent directory of {}", dir.display()))?;
    Ok(me.dev() != parent.dev())
}

/// `state_dir` 里已有 `state.json` 或 `seed.toml` → `Existing`，**不读种子分区**。否则把种子
/// 分区的 `seed.toml` 经 `safefs` 复制进 `state_dir`（0600），缓存包存在时先复制为
/// `incoming.bundle`（先包后种子：中途断电时 `state_dir` 里没有种子，下次开机重新导入）。
/// `state_dir` 不存在时以 0700 建出来。种子分区里的种子解析不了时报错，不复制。
pub fn import_if_fresh(state_dir: &Path, seed_dir: &Path) -> Result<Imported> {
    if exists(&state_dir.join(STATE_FILE))? || exists(&state_dir.join(SEED_FILE))? {
        return Ok(Imported::Existing);
    }
    let seed_fd = match safefs::open_abs_dir(seed_dir, false) {
        Ok(fd) => fd,
        Err(e) if crate::apply::is_not_found(&e) => return Ok(Imported::Unmanaged),
        Err(e) => return Err(e.context("opening the seed partition")),
    };
    let Some(seed_bytes) = safefs::read_at(&seed_fd, SEED_FILE)? else {
        return Ok(Imported::Unmanaged);
    };
    let text =
        std::str::from_utf8(&seed_bytes).context("seed.toml on the seed partition is not UTF-8")?;
    Seed::parse(text).context("parsing seed.toml on the seed partition failed")?;

    let cached = match safefs::open_dir(seed_dir, Path::new(CACHE_DIR), false) {
        Ok(cache) => safefs::read_at(&cache, CACHE_FILE)?,
        Err(e) if crate::apply::is_not_found(&e) => None,
        Err(e) => {
            // 缓存读不了不挡导入：没有缓存的包照样能连上网去拉。
            log::warn!("reading the cached bundle on the seed partition failed: {e:#}");
            None
        }
    };
    let state = safefs::open_abs_dir(state_dir, true)?;
    safefs::set_mode(&state, 0o700)?;
    if let Some(b) = &cached {
        safefs::write_at(&state, INCOMING, b, 0o600)?;
    }
    safefs::write_at(&state, SEED_FILE, &seed_bytes, 0o600)?;
    log::info!(
        "imported the seed{} from the seed partition",
        if cached.is_some() {
            " and the cached bundle"
        } else {
            ""
        }
    );
    Ok(Imported::Fresh {
        cached_bundle: cached.is_some(),
    })
}

/// 读 `identity.json`；没有就生成并写入（0600）：`device_id` 取 `existing_device_id`（机器已有
/// `state.json` 里的 ID——计划 1 时代装的机器第一次建 identity.json 时不能换 ID，否则恢复出厂后
/// 面板上成了另一台），没有才用新的 UUID v4；`escrow_secret` 为 32 字节随机数。已有但解析不了时
/// 报错、不覆盖——覆盖等于换了一台机器、也换了托管凭据。
pub fn load_or_create_identity(
    seed_dir: &Path,
    existing_device_id: Option<&str>,
) -> Result<Identity> {
    let dir = safefs::open_abs_dir(seed_dir, false).context("opening the seed partition")?;
    if let Some(b) = safefs::read_at(&dir, IDENTITY)? {
        let id: Identity = serde_json::from_slice(&b).context("parsing identity.json failed")?;
        if id.device_id.is_empty() {
            bail!("device_id in identity.json is empty");
        }
        return Ok(id);
    }
    let mut secret = [0u8; 32];
    SystemRandom::new()
        .fill(&mut secret)
        .map_err(|_| anyhow::anyhow!("getting random bytes failed"))?;
    let id = Identity {
        device_id: existing_device_id
            .filter(|d| !d.is_empty())
            .map_or_else(|| uuid::Uuid::new_v4().to_string(), str::to_string),
        escrow_secret: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret),
    };
    safefs::write_at(&dir, IDENTITY, &serde_json::to_vec_pretty(&id)?, 0o600)?;
    log::debug!("generated identity.json (device_id {})", id.device_id);
    Ok(id)
}

/// Reads `identity.json` without ever creating it (the upload drain: only the resident agent
/// creates the identity). Missing: `None`.
pub fn load_identity(seed_dir: &Path) -> Result<Option<Identity>> {
    let dir = safefs::open_abs_dir(seed_dir, false).context("opening the seed partition")?;
    let Some(b) = safefs::read_at(&dir, IDENTITY)? else {
        return Ok(None);
    };
    let id: Identity = serde_json::from_slice(&b).context("parsing identity.json failed")?;
    if id.device_id.is_empty() {
        bail!("device_id in identity.json is empty");
    }
    Ok(Some(id))
}

/// 接受新包之后写 `cache/current.bundle`（同目录临时文件 + `renameat`，0600；`cache/` 0700）。
pub fn store_cache(seed_dir: &Path, bundle: &[u8]) -> Result<()> {
    // 种子分区本身不建：它是挂载点，不在就是没挂上。
    safefs::open_abs_dir(seed_dir, false).context("opening the seed partition")?;
    let cache = safefs::open_dir(seed_dir, Path::new(CACHE_DIR), true)?;
    safefs::set_mode(&cache, 0o700)?;
    safefs::write_at(&cache, CACHE_FILE, bundle, 0o600)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn seed_text(key: &str) -> String {
        format!(
            "server_url = \"https://mdm.example\"\n\n[[trust]]\nid = \"k\"\nalg = \"ed25519\"\npublic_key = \"{key}\"\n"
        )
    }

    fn dirs() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        let seed = d.path().join("seed");
        fs::create_dir_all(&seed).unwrap();
        (d, state, seed)
    }

    #[test]
    fn existing_state_ignores_seed_partition() {
        let (_d, state, seed) = dirs();
        fs::create_dir_all(&state).unwrap();
        let mine = seed_text("MINE");
        fs::write(state.join("seed.toml"), &mine).unwrap();
        fs::write(state.join("state.json"), b"{}").unwrap();
        // 拆盘改了种子分区的 trust，还放了一个缓存包。
        fs::write(seed.join("seed.toml"), seed_text("EVIL")).unwrap();
        fs::create_dir_all(seed.join("cache")).unwrap();
        fs::write(seed.join("cache/current.bundle"), b"evil").unwrap();
        assert_eq!(import_if_fresh(&state, &seed).unwrap(), Imported::Existing);
        assert_eq!(fs::read_to_string(state.join("seed.toml")).unwrap(), mine);
        assert!(!state.join(INCOMING).exists());

        // 只有 state.json（种子副本丢了）也算已有状态。
        fs::remove_file(state.join("seed.toml")).unwrap();
        assert_eq!(import_if_fresh(&state, &seed).unwrap(), Imported::Existing);
        assert!(!state.join("seed.toml").exists());
    }

    #[test]
    fn fresh_state_imports_seed_0600() {
        let (_d, state, seed) = dirs();
        let text = seed_text("AAAA");
        fs::write(seed.join("seed.toml"), &text).unwrap();
        assert_eq!(
            import_if_fresh(&state, &seed).unwrap(),
            Imported::Fresh {
                cached_bundle: false
            }
        );
        assert_eq!(fs::read_to_string(state.join("seed.toml")).unwrap(), text);
        assert_eq!(mode(&state.join("seed.toml")), 0o600);
        assert_eq!(mode(&state), 0o700);
        assert!(!state.join(INCOMING).exists());

        // 带缓存包。
        let (_d2, state2, seed2) = dirs();
        fs::write(seed2.join("seed.toml"), &text).unwrap();
        store_cache(&seed2, b"bundle-bytes").unwrap();
        assert_eq!(mode(&seed2.join("cache")), 0o700);
        assert_eq!(mode(&seed2.join(CACHE_BUNDLE)), 0o600);
        assert_eq!(
            import_if_fresh(&state2, &seed2).unwrap(),
            Imported::Fresh {
                cached_bundle: true
            }
        );
        assert_eq!(fs::read(state2.join(INCOMING)).unwrap(), b"bundle-bytes");
        assert_eq!(mode(&state2.join(INCOMING)), 0o600);
    }

    #[test]
    fn no_seed_anywhere_is_unmanaged_and_bad_seed_is_error() {
        let (d, state, seed) = dirs();
        assert_eq!(import_if_fresh(&state, &seed).unwrap(), Imported::Unmanaged);
        assert_eq!(
            import_if_fresh(&state, &d.path().join("no-such-mount")).unwrap(),
            Imported::Unmanaged
        );
        fs::write(seed.join("seed.toml"), b"server_url = 12").unwrap();
        assert!(import_if_fresh(&state, &seed).is_err());
        assert!(
            !state.join("seed.toml").exists(),
            "a bad seed is not copied"
        );
    }

    #[test]
    fn identity_is_created_once_and_0600() {
        let (_d, _state, seed) = dirs();
        let a = load_or_create_identity(&seed, None).unwrap();
        assert_eq!(a.device_id.len(), 36);
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&a.escrow_secret)
            .unwrap();
        assert_eq!(raw.len(), 32);
        assert_eq!(mode(&seed.join(IDENTITY)), 0o600);
        let b = load_or_create_identity(&seed, Some("ignored-when-file-exists")).unwrap();
        assert_eq!(a, b);
        // 坏了不覆盖。
        fs::write(seed.join(IDENTITY), b"{oops").unwrap();
        assert!(load_or_create_identity(&seed, None).is_err());
        assert_eq!(fs::read(seed.join(IDENTITY)).unwrap(), b"{oops");
    }

    /// 已有 state.json 的老机器第一次建 identity.json：沿用它的 device_id（progress.md Carry → T8）。
    #[test]
    fn identity_takes_existing_device_id_when_created() {
        let (_d, _state, seed) = dirs();
        let id = load_or_create_identity(&seed, Some("dev-from-state")).unwrap();
        assert_eq!(id.device_id, "dev-from-state");
        assert_eq!(
            load_or_create_identity(&seed, None).unwrap().device_id,
            "dev-from-state"
        );
    }

    #[test]
    fn identity_debug_hides_secret() {
        let id = Identity {
            device_id: "dev".into(),
            escrow_secret: "TOP-SECRET".into(),
        };
        let d = format!("{id:?}");
        assert!(d.contains("dev") && !d.contains("TOP-SECRET"), "{d}");
    }

    #[test]
    fn unreadable_state_dir_refuses_import() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, state, seed) = dirs();
        fs::write(seed.join("seed.toml"), seed_text("AAAA")).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o000)).unwrap();
        // root 无视权限位：探测到读得了就跳过。
        let probe = fs::symlink_metadata(state.join("state.json"));
        let r = import_if_fresh(&state, &seed);
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        if matches!(probe, Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied) {
            assert!(
                r.is_err(),
                "no import when the state directory cannot be read: {r:?}"
            );
            assert!(!state.join("seed.toml").exists());
        }
    }

    #[test]
    fn mount_point_detection() {
        let d = tempfile::tempdir().unwrap();
        assert!(
            !is_mount_point(d.path()).unwrap(),
            "the temporary directory is not a mount point"
        );
        // /dev 在 Linux 与 macOS 上都是单独挂载的 devfs / devtmpfs。
        assert!(is_mount_point(Path::new("/dev")).unwrap());
        assert!(is_mount_point(&d.path().join("absent")).is_err());
    }

    #[test]
    fn store_cache_requires_mounted_seed_dir() {
        let (d, _state, _seed) = dirs();
        assert!(store_cache(&d.path().join("absent"), b"x").is_err());
        assert!(!d.path().join("absent").exists());
    }
}
