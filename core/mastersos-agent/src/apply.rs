//! 应用设置：系统层的改动藏在 `Applier` 后面（`system::SystemApplier`），
//! 这里只做与系统无关的部分——把包里的文件和清单里的下载放到目标路径。

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

use anyhow::{anyhow, bail, Context, Result};
use mastersos_bundle::{Config, Group, ItemResult, Lock, School, Seed};
use sha2::{Digest, Sha256};

use crate::safefs;
use crate::state::State;

/// 哪一种应用：开机在 GDM 之前（`apply-local`）只跑快速步骤，常驻的 `run` 跑全部。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Boot,
    Full,
}

pub struct ApplyContext<'a> {
    /// The seed this Device was installed with (server address, school name before the first settings).
    pub seed: &'a Seed,
    pub school: &'a School,
    /// The Device's Group (its id is what the status reports).
    pub group: &'a Group,
    /// The Config the Group names: everything the steps apply comes from here.
    pub config: &'a Config,
    pub lock: Option<&'a Lock>,
    /// 解开的当前设置包（`<state_dir>/current`），下面有 `files/`、`scripts/`。
    pub bundle_dir: &'a Path,
    pub phase: Phase,
    /// 应用任务收到了更新的请求：applier 在步骤之间看它，置位了就停下（应用任务会从第一步重来）。
    pub superseded: &'a AtomicBool,
}

pub trait Applier: Send + Sync {
    fn apply(&self, ctx: &ApplyContext) -> Vec<ItemResult>;

    /// 还没有包时由 agent 调用（只有种子；4b 的登录策略用它）。
    fn apply_without_bundle(&self, _seed: &Seed, _phase: Phase) -> Vec<ItemResult> {
        vec![]
    }
}

/// 测试用：记下每次调用时的分组 id、是否锁定与阶段，以及没有包时的调用。
#[derive(Default)]
pub struct RecordingApplier {
    pub calls: Mutex<Vec<(String, bool)>>,
    pub phases: Mutex<Vec<Phase>>,
    pub without_bundle: Mutex<Vec<Phase>>,
}

impl RecordingApplier {
    pub fn calls(&self) -> Vec<(String, bool)> {
        self.calls.lock().expect("锁没有中毒").clone()
    }

    /// 每次 `apply` 的阶段，与 `calls()` 一一对应。
    pub fn phases(&self) -> Vec<Phase> {
        self.phases.lock().expect("锁没有中毒").clone()
    }

    /// 每次 `apply_without_bundle` 的阶段。
    pub fn without_bundle_calls(&self) -> Vec<Phase> {
        self.without_bundle.lock().expect("锁没有中毒").clone()
    }
}

impl Applier for RecordingApplier {
    fn apply(&self, ctx: &ApplyContext) -> Vec<ItemResult> {
        self.calls
            .lock()
            .expect("锁没有中毒")
            .push((ctx.group.id.clone(), ctx.lock.is_some()));
        self.phases.lock().expect("锁没有中毒").push(ctx.phase);
        vec![]
    }

    fn apply_without_bundle(&self, _seed: &Seed, phase: Phase) -> Vec<ItemResult> {
        self.without_bundle.lock().expect("锁没有中毒").push(phase);
        vec![]
    }
}

/// 系统层什么都不改（测试与开发用）。
pub struct NullApplier;

impl Applier for NullApplier {
    fn apply(&self, _ctx: &ApplyContext) -> Vec<ItemResult> {
        vec![]
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// 经目录 fd 算 `dir/name` 的 sha256。不存在为 `None`；是符号链接或不是普通文件报错。
fn sha256_at(dir: &OwnedFd, name: &str) -> Result<Option<String>> {
    let Some(mut f) = safefs::open_file_at(dir, name)? else {
        return Ok(None);
    };
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match f.read(&mut buf).with_context(|| format!("读取 {name}"))? {
            0 => return Ok(Some(hex(&h.finalize()))),
            n => h.update(&buf[..n]),
        }
    }
}

pub(crate) fn is_not_found(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
    })
}

/// 下载到同目录的临时文件（经父目录的 fd），sha256 对得上才 rename 到 `name`。
/// 父目录在拿到成功的响应之后才打开（不存在就建）。
async fn download(
    http: &reqwest::Client,
    url: &str,
    root: &Path,
    parent: &Path,
    name: &str,
    want: &str,
) -> Result<()> {
    let mut resp = http
        .get(url)
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .context("下载请求失败")?
        .error_for_status()
        .map_err(reqwest::Error::without_url)
        .context("下载被服务器拒绝")?;
    let dir = safefs::open_dir(root, parent, true)?;
    // 出错返回时 TmpFile 被丢弃，临时文件随之删掉。
    let mut tmp = safefs::TmpFile::create(&dir, name, 0o644)?;
    let mut h = Sha256::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(reqwest::Error::without_url)
        .context("下载中断")?
    {
        h.update(&chunk);
        tmp.write_all(&chunk)?;
    }
    let got = hex(&h.finalize());
    if got != want {
        bail!("sha256 不符：期望 {want}，实际 {got}");
    }
    tmp.commit()
}

fn result(item: String, r: Result<()>) -> ItemResult {
    match r {
        Ok(()) => ItemResult {
            item,
            ok: true,
            detail: None,
        },
        Err(e) => ItemResult {
            item,
            ok: false,
            detail: Some(format!("{e:#}")),
        },
    }
}

/// 处理配置的 `files` 与 `downloads`：目标已是期望内容就跳过；写入一律经 [`safefs`]
/// （逐级 `openat` 不跟随链接，同目录临时文件 + `renameat`）。上一次放置过、这一次清单里已经没有的路径会被删掉。
/// `state.managed_paths` 记录「目标路径 → 期望的 sha256」，由调用方落盘。
pub async fn place(
    config: &Config,
    bundle_dir: &Path,
    root: &Path,
    state: &mut State,
    http: &reqwest::Client,
) -> Vec<ItemResult> {
    let mut results = Vec::new();
    let mut managed = BTreeMap::new();
    let mut wanted: BTreeSet<String> = BTreeSet::new();

    for f in &config.files {
        wanted.insert(f.dest.clone());
        let src = bundle_dir.join(&f.src);
        let r = (|| -> Result<String> {
            let bytes = fs::read(&src).map_err(|_| anyhow!("包里没有 {}", f.src))?;
            let want = sha256_hex(&bytes);
            let (parent, name) = safefs::split_abs(&f.dest)?;
            let dir = safefs::open_dir(root, &parent, true)?;
            // 内容、权限（0644）与属主都一致才不动；权限被放宽了也会被收回来。
            safefs::write_at(&dir, &name, &bytes, 0o644)?;
            Ok(want)
        })();
        let r = r.map(|want| {
            managed.insert(f.dest.clone(), want);
        });
        results.push(result(format!("file:{}", f.dest), r));
    }

    for d in &config.downloads {
        wanted.insert(d.dest.clone());
        let r = async {
            let (parent, name) = safefs::split_abs(&d.dest)?;
            // 先不建目录：已有的就核对哈希（顺带在发请求之前查出链接）；不存在的等拿到
            // 成功的响应再建，免得下载失败留下没人管的空目录。
            match safefs::open_dir(root, &parent, false) {
                Ok(dir) => {
                    if sha256_at(&dir, &name)?.as_deref() == Some(d.sha256.as_str()) {
                        return Ok(());
                    }
                }
                Err(e) if is_not_found(&e) => {}
                Err(e) => return Err(e),
            }
            download(http, &d.url, root, &parent, &name, &d.sha256).await
        }
        .await;
        if r.is_ok() {
            managed.insert(d.dest.clone(), d.sha256.clone());
        }
        results.push(result(format!("download:{}", d.dest), r));
    }

    // 清单里还在、这次失败了的路径：沿用旧记录，下次删除时还认得它。
    for (dest, hash) in &state.managed_paths {
        if wanted.contains(dest) {
            managed.entry(dest.clone()).or_insert_with(|| hash.clone());
        }
    }
    for dest in state.managed_paths.keys() {
        if wanted.contains(dest) {
            continue;
        }
        let r = safefs::split_abs(dest).and_then(|(parent, name)| {
            match safefs::open_dir(root, &parent, false) {
                Ok(dir) => safefs::remove_at(&dir, &name),
                // 父目录都不在了，文件自然也不在。
                Err(e) if is_not_found(&e) => Ok(()),
                Err(e) => Err(e),
            }
        });
        if let Err(e) = r {
            // 删不掉就留在记录里，下次再试。
            managed.insert(dest.clone(), state.managed_paths[dest].clone());
            results.push(result(format!("remove:{dest}"), Err(e)));
        }
    }
    state.managed_paths = managed;
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use mastersos_bundle::Manifest;
    use std::os::unix::fs::MetadataExt;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config(files: &[(&str, &str)], downloads: &[(&str, &str, &str)]) -> Config {
        let mut s = String::from("version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n");
        for (src, dest) in files {
            s += &format!("[[group.files]]\nsrc = \"{src}\"\ndest = \"{dest}\"\n");
        }
        for (url, sha, dest) in downloads {
            s += &format!(
                "[[group.downloads]]\nurl = \"{url}\"\nsha256 = \"{sha}\"\ndest = \"{dest}\"\n"
            );
        }
        let m = Manifest::parse(&s).unwrap();
        mastersos_bundle::effective_config(&m, &m.configs[0])
    }

    fn bundle_with(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for (p, b) in files {
            let path = d.path().join(p);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b).unwrap();
        }
        d
    }

    #[tokio::test]
    async fn place_skips_matching_file() {
        let bundle = bundle_with(&[("files/a.txt", b"hello")]);
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("etc/mastersos/a.txt");
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::write(&dest, b"hello").unwrap();
        fs::set_permissions(&dest, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
        let ino = fs::metadata(&dest).unwrap().ino();

        let g = config(&[("files/a.txt", "/etc/mastersos/a.txt")], &[]);
        let mut st = State::default();
        let r = place(
            &g,
            bundle.path(),
            root.path(),
            &mut st,
            &reqwest::Client::new(),
        )
        .await;
        assert_eq!(r.len(), 1);
        assert!(r[0].ok, "{r:?}");
        assert_eq!(
            fs::metadata(&dest).unwrap().ino(),
            ino,
            "内容一致时不应重写"
        );
        assert_eq!(
            st.managed_paths
                .get("/etc/mastersos/a.txt")
                .map(String::as_str),
            Some(sha256_hex(b"hello").as_str())
        );

        // 内容不同则替换，且不留临时文件。
        fs::write(&dest, b"old").unwrap();
        let r = place(
            &g,
            bundle.path(),
            root.path(),
            &mut st,
            &reqwest::Client::new(),
        )
        .await;
        assert!(r[0].ok);
        assert_eq!(fs::read(&dest).unwrap(), b"hello");
        assert!(!dest.with_file_name(".a.txt.mastersos-tmp").exists());
    }

    #[tokio::test]
    async fn place_removes_dropped_paths() {
        let bundle = bundle_with(&[("files/a.txt", b"a"), ("files/b.txt", b"b")]);
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("unrelated"), b"x").unwrap();
        let http = reqwest::Client::new();
        let mut st = State::default();

        let g1 = config(
            &[("files/a.txt", "/opt/a.txt"), ("files/b.txt", "/opt/b.txt")],
            &[],
        );
        let r = place(&g1, bundle.path(), root.path(), &mut st, &http).await;
        assert!(r.iter().all(|r| r.ok), "{r:?}");
        assert!(root.path().join("opt/b.txt").exists());

        let g2 = config(&[("files/a.txt", "/opt/a.txt")], &[]);
        let r = place(&g2, bundle.path(), root.path(), &mut st, &http).await;
        assert!(r.iter().all(|r| r.ok), "{r:?}");
        assert!(root.path().join("opt/a.txt").exists());
        assert!(!root.path().join("opt/b.txt").exists());
        assert!(root.path().join("unrelated").exists());
        assert_eq!(
            st.managed_paths.keys().collect::<Vec<_>>(),
            vec!["/opt/a.txt"]
        );
    }

    #[tokio::test]
    async fn download_rejects_wrong_sha256() {
        let srv = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"evil".to_vec()))
            .mount(&srv)
            .await;
        let bundle = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let http = reqwest::Client::new();
        let mut st = State::default();

        let url = format!("{}/a.deb", srv.uri());
        let g = config(&[], &[(&url, &sha256_hex(b"good"), "/opt/a.deb")]);
        let r = place(&g, bundle.path(), root.path(), &mut st, &http).await;
        assert_eq!(r.len(), 1);
        assert!(!r[0].ok);
        assert!(r[0].detail.as_deref().unwrap().contains("sha256"), "{r:?}");
        assert!(!root.path().join("opt/a.deb").exists());
        assert!(!root.path().join("opt/.a.deb.mastersos-tmp").exists());
        assert!(st.managed_paths.is_empty());

        // 内容对得上就落盘。
        let g = config(&[], &[(&url, &sha256_hex(b"evil"), "/opt/a.deb")]);
        let r = place(&g, bundle.path(), root.path(), &mut st, &http).await;
        assert!(r[0].ok, "{r:?}");
        assert_eq!(fs::read(root.path().join("opt/a.deb")).unwrap(), b"evil");
        // 已经一致：不再下载。
        place(&g, bundle.path(), root.path(), &mut st, &http).await;
        assert_eq!(srv.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn place_refuses_symlinked_destinations() {
        let bundle = bundle_with(&[("files/a.txt", b"new")]);
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("a.txt"), b"keep").unwrap();
        fs::write(outside.path().join("victim"), b"keep").unwrap();
        // 父目录是链接：/opt → outside
        std::os::unix::fs::symlink(outside.path(), root.path().join("opt")).unwrap();
        // 最后一级是链接：/etc/x → outside/victim
        fs::create_dir_all(root.path().join("etc")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("victim"), root.path().join("etc/x"))
            .unwrap();
        let http = reqwest::Client::new();
        let mut st = State::default();
        let g = config(
            &[("files/a.txt", "/opt/a.txt"), ("files/a.txt", "/etc/x")],
            &[("http://127.0.0.1:9/never", &sha256_hex(b"z"), "/opt/dl.bin")],
        );
        let r = place(&g, bundle.path(), root.path(), &mut st, &http).await;
        assert_eq!(r.len(), 3);
        for item in &r {
            assert!(!item.ok, "{item:?}");
            assert!(
                item.detail.as_deref().unwrap().contains("symlink"),
                "{item:?}"
            );
        }
        assert_eq!(fs::read(outside.path().join("a.txt")).unwrap(), b"keep");
        assert_eq!(fs::read(outside.path().join("victim")).unwrap(), b"keep");
        assert!(!outside.path().join("dl.bin").exists());
        assert!(fs::symlink_metadata(root.path().join("etc/x"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(st.managed_paths.is_empty());
    }

    #[tokio::test]
    async fn removal_refuses_symlinked_paths() {
        let bundle = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("b.txt"), b"keep").unwrap();
        fs::write(outside.path().join("victim"), b"keep").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("opt")).unwrap();
        fs::create_dir_all(root.path().join("etc")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("victim"), root.path().join("etc/y"))
            .unwrap();
        let mut st = State::default();
        st.managed_paths
            .insert("/opt/b.txt".into(), sha256_hex(b"keep"));
        st.managed_paths
            .insert("/etc/y".into(), sha256_hex(b"keep"));
        let r = place(
            &config(&[], &[]),
            bundle.path(),
            root.path(),
            &mut st,
            &reqwest::Client::new(),
        )
        .await;
        assert_eq!(r.len(), 2, "{r:?}");
        for item in &r {
            assert!(!item.ok && item.item.starts_with("remove:"), "{item:?}");
            assert!(
                item.detail.as_deref().unwrap().contains("symlink"),
                "{item:?}"
            );
        }
        assert!(outside.path().join("b.txt").exists());
        assert!(outside.path().join("victim").exists());
        assert!(fs::symlink_metadata(root.path().join("etc/y")).is_ok());
        assert_eq!(st.managed_paths.len(), 2, "删不掉的仍留在记录里");
    }

    #[tokio::test]
    async fn download_errors_do_not_carry_url() {
        let srv = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&srv)
            .await;
        let bundle = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let url = format!("{}/a.deb?token=s3cret", srv.uri());
        let g = config(&[], &[(&url, &sha256_hex(b"x"), "/opt/a.deb")]);
        let r = place(
            &g,
            bundle.path(),
            root.path(),
            &mut State::default(),
            &reqwest::Client::new(),
        )
        .await;
        assert!(!r[0].ok);
        let detail = r[0].detail.as_deref().unwrap();
        assert!(
            !detail.contains("s3cret") && !detail.contains("127.0.0.1"),
            "{detail}"
        );

        // 连不上的情况也一样。
        let g = config(
            &[],
            &[(
                "http://127.0.0.1:9/x?token=s3cret",
                &sha256_hex(b"x"),
                "/opt/b.deb",
            )],
        );
        let r = place(
            &g,
            bundle.path(),
            root.path(),
            &mut State::default(),
            &reqwest::Client::new(),
        )
        .await;
        assert!(!r[0].ok);
        assert!(!r[0].detail.as_deref().unwrap().contains("s3cret"), "{r:?}");
    }

    #[tokio::test]
    async fn place_restores_mode_and_failed_download_creates_no_dir() {
        use std::os::unix::fs::PermissionsExt;
        let bundle = bundle_with(&[("files/a.txt", b"hello")]);
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("etc/a.txt");
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::write(&dest, b"hello").unwrap();
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o666)).unwrap();
        let g = config(
            &[("files/a.txt", "/etc/a.txt")],
            &[("http://127.0.0.1:9/x", &sha256_hex(b"x"), "/srv/new/x.bin")],
        );
        let r = place(
            &g,
            bundle.path(),
            root.path(),
            &mut State::default(),
            &reqwest::Client::new(),
        )
        .await;
        assert!(r[0].ok, "{r:?}");
        assert_eq!(
            fs::metadata(&dest).unwrap().permissions().mode() & 0o7777,
            0o644,
            "内容一致但权限被放宽：收回 0644"
        );
        assert!(!r[1].ok, "{r:?}");
        assert!(!root.path().join("srv").exists(), "下载失败不留空目录");
    }
}
