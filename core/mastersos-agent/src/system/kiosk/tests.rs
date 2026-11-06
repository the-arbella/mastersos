#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::super::ephemeral::{self, cleanup, EphemeralEnv, ProcMounts, SystemdProcs, CMD_TIMEOUT};
use super::super::tests::{group, paths, tmp_root};
use super::super::SysState;
use super::*;
use crate::apply::Phase;
use crate::runner::{Cmd, FakeRunner, Output};
use mastersos_bundle::{Manifest, School};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

const EXAM_ID: &str = "abcdefghijklmnopabcdefghijklmnop";
const EXAM_URL: &str = "https://os.khundavid.com/chrome/updates.xml";

/// 配置：`kiosk` 是 `[group.apps.kiosk.*]` 的 TOML（旧形状）。
fn grp(kiosk: &str) -> mastersos_bundle::Config {
    Manifest::parse(&format!(
        "version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n{kiosk}"
    ))
    .unwrap()
    .effective_of_group("default")
    .unwrap()
}

fn web_app(id: &str, name: &str) -> String {
    format!(
        "[group.apps.kiosk.{id}]\nname = {}\nurl = \"https://{id}.example.org/\"\n",
        q(name)
    )
}

/// TOML 的字符串字面量。
fn q(s: &str) -> String {
    toml::Value::String(s.into()).to_string()
}

/// 临时系统根，镜像里有合规的 `kiosk-ext.json`。
fn root() -> tempfile::TempDir {
    let d = tmp_root();
    write_exam(
        d.path(),
        &format!(r#"{{"id": "{EXAM_ID}", "update_url": "{EXAM_URL}"}}"#),
    );
    fs::create_dir_all(d.path().join("home")).unwrap();
    fs::set_permissions(d.path().join("home"), fs::Permissions::from_mode(0o755)).unwrap();
    d
}

fn write_exam(root: &Path, text: &str) {
    let p = root.join(EXAM_EXT_FILE);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, text).unwrap();
}

fn exam() -> ExamExtension {
    ExamExtension {
        id: EXAM_ID.into(),
        update_url: EXAM_URL.into(),
    }
}

/// 记下每次调用的参数（`FakeRunner` 只记连起来的一行，带空格的参数分不清）。
#[derive(Default)]
struct ArgRunner {
    fake: FakeRunner,
    args: Mutex<Vec<Vec<String>>>,
}

impl Runner for ArgRunner {
    fn run(&self, cmd: &Cmd) -> anyhow::Result<Output> {
        let mut a = vec![cmd.program.clone()];
        a.extend(cmd.args.iter().cloned());
        self.args.lock().unwrap().push(a);
        self.fake.run(cmd)
    }
}

/// 每次调用时看一眼 `watch` 这个文件（不存在为 `None`）：断言「某条命令跑的时候文件已经是什么样」。
struct HookRunner {
    fake: FakeRunner,
    watch: std::path::PathBuf,
    seen: Mutex<Vec<(String, Option<String>)>>,
}

impl HookRunner {
    fn new(watch: std::path::PathBuf) -> HookRunner {
        HookRunner {
            fake: FakeRunner::new(),
            watch,
            seen: Mutex::new(Vec::new()),
        }
    }
    /// 第一条以 `prefix` 开头的命令跑的时候文件的内容。
    fn at(&self, prefix: &str) -> Option<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .find(|(l, _)| l.starts_with(prefix))
            .unwrap_or_else(|| panic!("没有 {prefix}"))
            .1
            .clone()
    }
}

impl Runner for HookRunner {
    fn run(&self, cmd: &Cmd) -> anyhow::Result<Output> {
        let now = fs::read_to_string(&self.watch).ok();
        self.seen.lock().unwrap().push((cmd.line(), now));
        self.fake.run(cmd)
    }
}

fn run_with(
    r: &dyn Runner,
    root: &Path,
    sys: &mut SysState,
    g: &mastersos_bundle::Config,
    phase: Phase,
    bundle: &Path,
) -> Vec<ItemResult> {
    let p = paths(root);
    let mut env = Env {
        paths: &p,
        runner: r,
        sys,
    };
    let flag = AtomicBool::new(false);
    let school = School::default();
    let ctx = ApplyContext {
        seed: &crate::system::tests::test_seed(),
        school: &school,
        group: &group(),
        config: g,
        lock: None,
        bundle_dir: bundle,
        phase,
        superseded: &flag,
    };
    (step().run)(&ctx, &mut env)
}

fn run_step(
    r: &FakeRunner,
    root: &Path,
    sys: &mut SysState,
    g: &mastersos_bundle::Config,
    phase: Phase,
) -> Vec<ItemResult> {
    let bundle = tempfile::tempdir().unwrap();
    run_with(r, root, sys, g, phase, bundle.path())
}

fn absent(r: &FakeRunner, key: &str) {
    r.respond(&format!("getent passwd {key}"), Output::fail(2, ""));
}

fn present(r: &FakeRunner, user: &str, uid: u32, name: &str) {
    r.respond(
        &format!("getent passwd {user}"),
        Output::ok(&format!(
            "{user}:x:{uid}:{uid}:{name}:/home/{user}:/bin/bash\n"
        )),
    );
}

fn idx(calls: &[String], prefix: &str) -> usize {
    calls
        .iter()
        .position(|c| c.starts_with(prefix))
        .unwrap_or_else(|| panic!("没有 {prefix}：{calls:?}"))
}

fn count(calls: &[String], prefix: &str) -> usize {
    calls.iter().filter(|c| c.starts_with(prefix)).count()
}

fn st(uid: u32, name: &str) -> KioskAccountState {
    KioskAccountState {
        uid,
        name: name.into(),
        initialized: true,
    }
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

fn ok_item(id: &str) -> ItemResult {
    super::super::ok(&format!("kiosk:{id}"))
}

/// 删掉一个账号要的回答：slice 两次不 active（结束会话之后一次、清理里一次）、账号在（userdel 之前查）、之后
/// uid 与账号都查不到（清理里）。
fn removal_answers(r: &FakeRunner, user: &str, uid: u32) {
    for _ in 0..2 {
        r.respond(
            &format!("systemctl is-active user-{uid}.slice"),
            Output::ok("inactive\n"),
        );
    }
    present(r, user, uid, "x");
    absent(r, &uid.to_string());
    absent(r, user);
}

#[test]
fn creates_account_with_fixed_uid_and_no_password() {
    let root = root();
    let r = FakeRunner::new();
    absent(&r, "kiosk-nwea");
    absent(&r, "1900");
    let mut sys = SysState::default();
    let out = run_step(
        &r,
        root.path(),
        &mut sys,
        &grp(&web_app("nwea", "NWEA MAP")),
        Phase::Full,
    );
    assert_eq!(out, vec![ok_item("nwea")]);
    let calls = r.calls();
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let ua = idx(
        &calls,
        "useradd --uid 1900 --user-group --no-create-home --home-dir /home/kiosk-nwea --shell /bin/bash --comment NWEA MAP kiosk-nwea",
    );
    let pw = idx(&calls, "passwd -d kiosk-nwea");
    let ch = idx(&calls, &format!("chage -m 99999 -d {today} kiosk-nwea"));
    let reload = idx(&calls, "systemctl daemon-reload");
    let kick = idx(
        &calls,
        "systemctl start --no-block mastersos-ephemeral-cleanup@kiosk-nwea.service",
    );
    // 第一份 tmpfs 由清理备好；它在 drop-in 生效（daemon-reload）之后才拉起
    assert!(
        ua < pw && pw < ch && ch < kick && reload < kick,
        "{calls:?}"
    );
    assert_eq!(
        sys.kiosk_accounts,
        BTreeMap::from([("nwea".to_string(), st(1900, "NWEA MAP"))])
    );
    // 第二轮：账号在、名字没变，什么都不建
    let r = FakeRunner::new();
    present(&r, "kiosk-nwea", 1900, "NWEA MAP");
    let out = run_step(
        &r,
        root.path(),
        &mut sys,
        &grp(&web_app("nwea", "NWEA MAP")),
        Phase::Full,
    );
    assert_eq!(out, vec![ok_item("nwea")]);
    let calls = r.calls();
    assert!(
        calls.iter().all(|c| !c.starts_with("useradd")
            && !c.starts_with("usermod")
            && !c.starts_with("systemctl")),
        "{calls:?}"
    );
}

#[test]
fn uid_stable_across_runs_and_lowest_free() {
    let root = root();
    // 1900 已是别人的：取 1901
    let r = FakeRunner::new();
    absent(&r, "kiosk-b");
    present(&r, "1900", 1900, "someone");
    absent(&r, "1901");
    let mut sys = SysState::default();
    run_step(
        &r,
        root.path(),
        &mut sys,
        &grp(&web_app("b", "B")),
        Phase::Full,
    );
    idx(&r.calls(), "useradd --uid 1901 ");
    assert_eq!(sys.kiosk_accounts["b"], st(1901, "B"));
    // 第二轮再加一个：b 沿用 1901（不再查 uid），a 取最小的空闲值 1900（这回空出来了）
    let r = FakeRunner::new();
    absent(&r, "kiosk-a");
    absent(&r, "1900");
    present(&r, "kiosk-b", 1901, "B");
    let g = grp(&format!("{}{}", web_app("a", "A"), web_app("b", "B")));
    let out = run_step(&r, root.path(), &mut sys, &g, Phase::Full);
    assert_eq!(out, vec![ok_item("a"), ok_item("b")]);
    let calls = r.calls();
    idx(&calls, "useradd --uid 1900 ");
    assert_eq!(count(&calls, "useradd"), 1, "{calls:?}");
    assert_eq!(count(&calls, "getent passwd 1901"), 0, "{calls:?}");
    assert_eq!(sys.kiosk_accounts["a"], st(1900, "A"));
    assert_eq!(sys.kiosk_accounts["b"], st(1901, "B"));
    // 记着的 uid 不会给别的应用
    let r = FakeRunner::new();
    absent(&r, "1900");
    absent(&r, "1901");
    absent(&r, "1902");
    assert_eq!(uid_for(&r, &sys.kiosk_accounts, "c").unwrap(), Some(1902));
    assert_eq!(uid_for(&r, &sys.kiosk_accounts, "b").unwrap(), Some(1901));
}

#[test]
fn writes_accountsservice_file() {
    let root = root();
    let hr = HookRunner::new(root.path().join(ACCOUNTS_DIR).join("kiosk-a"));
    let r = &hr.fake;
    absent(r, "kiosk-a");
    absent(r, "1900");
    absent(r, "kiosk-b");
    absent(r, "1901");
    let g = grp(&format!(
        "{}{}login_screen = false\n",
        web_app("a", "A"),
        web_app("b", "B")
    ));
    let mut sys = SysState::default();
    let bundle = tempfile::tempdir().unwrap();
    run_with(&hr, root.path(), &mut sys, &g, Phase::Full, bundle.path());
    let users = root.path().join(ACCOUNTS_DIR);
    let a = fs::read_to_string(users.join("kiosk-a")).unwrap();
    assert_eq!(
        a,
        "[User]\nRealName=A\nSession=mastersos-kiosk\nSystemAccount=false\n"
    );
    assert_eq!(mode(&users.join("kiosk-a")), 0o600);
    let b = fs::read_to_string(users.join("kiosk-b")).unwrap();
    assert_eq!(
        b,
        "[User]\nRealName=B\nSession=mastersos-kiosk\nSystemAccount=true\n"
    );
    // 清理照它恢复的模板与它一字不差
    let tpl = root
        .path()
        .join(PUBLIC_DIR)
        .join("a")
        .join(ACCOUNTS_TEMPLATE);
    assert_eq!(fs::read_to_string(&tpl).unwrap(), a);
    assert_eq!(mode(&tpl), 0o644);
    // AccountsService 的记录写在 useradd 之前：accounts-daemon 看到新账号时就读得到它
    assert_eq!(hr.at("useradd --uid 1900 ").as_deref(), Some(a.as_str()));
}

/// 带图标的：图标缓存进 `PUBLIC_DIR/<id>/icon`，AccountsService 的 `Icon` 指着它（真机上的绝对路径）。
#[test]
fn bundle_icon_is_cached_and_referenced() {
    let root = root();
    let bundle = tempfile::tempdir().unwrap();
    fs::create_dir_all(bundle.path().join("files")).unwrap();
    let png = b"\x89PNG\r\n\x1a\nrest";
    fs::write(bundle.path().join("files/n.png"), png).unwrap();
    let r = FakeRunner::new();
    absent(&r, "kiosk-nwea");
    absent(&r, "1900");
    let g = grp(&format!(
        "{}icon = \"files/n.png\"\n",
        web_app("nwea", "NWEA MAP")
    ));
    let mut sys = SysState::default();
    let out = run_with(&r, root.path(), &mut sys, &g, Phase::Full, bundle.path());
    assert_eq!(out, vec![ok_item("nwea")]);
    let dir = root.path().join(PUBLIC_DIR).join("nwea");
    assert_eq!(fs::read(dir.join(ICON_FILE)).unwrap(), png);
    let a = fs::read_to_string(root.path().join(ACCOUNTS_DIR).join("kiosk-nwea")).unwrap();
    assert!(
        a.contains("\nIcon=/var/lib/mastersos-public/kiosk/nwea/icon\n"),
        "{a}"
    );
    // 图标拿掉了：缓存删掉，记录里不再有 Icon
    let r = FakeRunner::new();
    present(&r, "kiosk-nwea", 1900, "NWEA MAP");
    run_with(
        &r,
        root.path(),
        &mut sys,
        &grp(&web_app("nwea", "NWEA MAP")),
        Phase::Full,
        bundle.path(),
    );
    assert!(!dir.join(ICON_FILE).exists());
    let a = fs::read_to_string(root.path().join(ACCOUNTS_DIR).join("kiosk-nwea")).unwrap();
    assert!(!a.contains("Icon="), "{a}");
}

/// Review Focus：名称是泰文、带引号与反斜杠——GECOS 是 `usermod -c` / `useradd --comment` 的一个参数，原样；
/// AccountsService 的 keyfile 按 GKeyFile 转义、GLib 读回原样；`launch.json` 读回原样。
#[test]
fn realname_escapes_thai_and_quotes() {
    let name = "สอบ \"MAP\" \\";
    let renamed = " ห้อง 'B' \\n";
    let root = root();
    let r = ArgRunner::default();
    absent(&r.fake, "kiosk-nwea");
    absent(&r.fake, "1900");
    let bundle = tempfile::tempdir().unwrap();
    let mut sys = SysState::default();
    run_with(
        &r,
        root.path(),
        &mut sys,
        &grp(&web_app("nwea", name)),
        Phase::Full,
        bundle.path(),
    );
    let args = r.args.lock().unwrap().clone();
    let ua = args.iter().find(|a| a[0] == "useradd").unwrap();
    let c = ua.iter().position(|a| a == "--comment").unwrap();
    assert_eq!(ua[c + 1], name);
    assert_eq!(ua.last().unwrap(), "kiosk-nwea");
    assert_eq!(sys.kiosk_accounts["nwea"].name, name);

    let keyfile = root.path().join(ACCOUNTS_DIR).join("kiosk-nwea");
    let text = fs::read_to_string(&keyfile).unwrap();
    assert!(text.contains("RealName=สอบ \"MAP\" \\\\\n"), "{text}");
    #[cfg(target_os = "linux")]
    {
        let kf = glib::KeyFile::new();
        kf.load_from_data(&text, glib::KeyFileFlags::NONE).unwrap();
        assert_eq!(kf.string("User", "RealName").unwrap().as_str(), name);
        assert_eq!(kf.string("User", "Session").unwrap().as_str(), SESSION);
    }
    let launch: Launch = serde_json::from_slice(
        &fs::read(root.path().join(PUBLIC_DIR).join("nwea").join(LAUNCH_FILE)).unwrap(),
    )
    .unwrap();
    assert_eq!(launch.name, name);

    // 改名：账号在，usermod -c 新名字（一个参数，原样），状态跟着改
    let r = ArgRunner::default();
    present(&r.fake, "kiosk-nwea", 1900, name);
    run_with(
        &r,
        root.path(),
        &mut sys,
        &grp(&web_app("nwea", renamed)),
        Phase::Full,
        bundle.path(),
    );
    let args = r.args.lock().unwrap().clone();
    let um = args.iter().find(|a| a[0] == "usermod").unwrap();
    assert_eq!(um, &vec!["usermod", "-c", renamed, "kiosk-nwea"]);
    assert_eq!(sys.kiosk_accounts["nwea"].name, renamed);
    let text = fs::read_to_string(&keyfile).unwrap();
    assert!(text.contains("RealName=\\s"), "行首空格要写成 \\s：{text}");
    #[cfg(target_os = "linux")]
    {
        let kf = glib::KeyFile::new();
        kf.load_from_data(&text, glib::KeyFileFlags::NONE).unwrap();
        assert_eq!(kf.string("User", "RealName").unwrap().as_str(), renamed);
    }
}

#[test]
fn writes_launch_and_policy() {
    let root = root();
    let r = FakeRunner::new();
    for (u, uid) in [("kiosk-calc", "1900"), ("kiosk-map", "1901")] {
        absent(&r, u);
        absent(&r, uid);
    }
    let g = grp(
        "[group.apps.kiosk.map]\nname = \"MAP\"\nurl = \"https://test.mapnwea.org/\"\npwa = true\n\
         user_agent = \"UA/1\"\nallow = [\"nwea.org\"]\n\
         [group.apps.kiosk.calc]\nname = \"Calc\"\nexec = \"org.gnome.Calculator\"\n",
    );
    let mut sys = SysState::default();
    let out = run_step(&r, root.path(), &mut sys, &g, Phase::Full);
    assert_eq!(out, vec![ok_item("calc"), ok_item("map")]);
    let base = root.path().join(PUBLIC_DIR);
    let read_launch = |id: &str| -> Launch {
        serde_json::from_slice(&fs::read(base.join(id).join(LAUNCH_FILE)).unwrap()).unwrap()
    };
    assert_eq!(
        read_launch("map"),
        Launch {
            id: "map".into(),
            name: "MAP".into(),
            kind: LaunchKind::Pwa {
                url: "https://test.mapnwea.org/".into()
            },
            user_agent: Some("UA/1".into()),
            start: None,
        }
    );
    assert_eq!(
        read_launch("calc"),
        Launch {
            id: "calc".into(),
            name: "Calc".into(),
            kind: LaunchKind::Exec {
                target: "org.gnome.Calculator".into()
            },
            user_agent: None,
            start: None,
        }
    );
    // 策略文件就是 Task 2 合成的那份，别的什么都没有
    let pol = base.join("map").join(POLICIES_DIR).join(POLICY_FILE);
    let got: serde_json::Value = serde_json::from_slice(&fs::read(&pol).unwrap()).unwrap();
    let want = kiosk::chrome_policy(&g.apps.kiosk["map"], &exam(), None).unwrap();
    assert_eq!(got, serde_json::Value::Object(want));
    assert_eq!(
        fs::read_dir(base.join("map").join(POLICIES_DIR))
            .unwrap()
            .count(),
        1
    );
    for p in [&pol, &base.join("map").join(LAUNCH_FILE)] {
        assert_eq!(mode(p), 0o644, "{}", p.display());
    }
    for d in [
        &base,
        &base.join("map"),
        &base.join("map").join(POLICIES_DIR),
    ] {
        assert_eq!(mode(d), 0o755, "{}", d.display());
    }
    // 本地程序也写一份禁止一切的策略（终审 I1：程序里的链接会起 Chrome）
    let exec_policy = |id: &str| -> serde_json::Value {
        serde_json::from_slice(
            &fs::read(base.join(id).join(POLICIES_DIR).join(POLICY_FILE)).unwrap(),
        )
        .unwrap()
    };
    let calc = exec_policy("calc");
    assert_eq!(calc["URLBlocklist"], serde_json::json!(["*"]));
    assert_eq!(calc["URLAllowlist"], serde_json::json!([kiosk::ERROR_PAGE]));
    assert_eq!(calc["ExtensionInstallForcelist"], serde_json::json!([]));
    assert_eq!(calc["DeveloperToolsAvailability"], serde_json::json!(2));
    assert_eq!(
        mode(&base.join("calc").join(POLICIES_DIR).join(POLICY_FILE)),
        0o644
    );
    // 网页改成本地程序：策略换成本地程序的那份
    let r = FakeRunner::new();
    present(&r, "kiosk-calc", 1900, "Calc");
    present(&r, "kiosk-map", 1901, "MAP");
    let g = grp(
        "[group.apps.kiosk.map]\nname = \"MAP\"\nexec = \"/usr/bin/map\"\n\
         [group.apps.kiosk.calc]\nname = \"Calc\"\nexec = \"org.gnome.Calculator\"\n",
    );
    run_step(&r, root.path(), &mut sys, &g, Phase::Full);
    let map = exec_policy("map");
    assert_eq!(map["URLAllowlist"], serde_json::json!([kiosk::ERROR_PAGE]));
    assert!(map.get("WebAppInstallForceList").is_none());
    assert_eq!(map, calc);
    assert_eq!(
        read_launch("map").kind,
        LaunchKind::Exec {
            target: "/usr/bin/map".into()
        }
    );
}

#[test]
fn writes_namespace_conf_listing_kiosk_users() {
    let root = root();
    let r = FakeRunner::new();
    for (u, uid) in [("kiosk-a", "1900"), ("kiosk-b", "1901")] {
        absent(&r, u);
        absent(&r, uid);
    }
    let g = grp(&format!("{}{}", web_app("b", "B"), web_app("a", "A")));
    let mut sys = SysState::default();
    run_step(&r, root.path(), &mut sys, &g, Phase::Full);
    let conf = root.path().join(NAMESPACE_CONF);
    let text = fs::read_to_string(&conf).unwrap();
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(
        lines,
        vec!["/etc/opt/chrome/policies/managed  /var/lib/mastersos-kiosk-ns/  user  ~kiosk-a,kiosk-b"]
    );
    assert_eq!(mode(&conf), 0o644);
    // 一个都不剩：文件删掉
    let r = FakeRunner::new();
    removal_answers(&r, "kiosk-a", 1900);
    removal_answers(&r, "kiosk-b", 1901);
    let out = run_step(&r, root.path(), &mut sys, &grp(""), Phase::Full);
    assert!(out.iter().all(|i| i.ok), "{out:?}");
    assert!(!conf.exists());
    assert!(sys.kiosk_accounts.is_empty());
}

#[test]
fn writes_user_unit_dropin_and_reloads_once() {
    let root = root();
    let r = FakeRunner::new();
    for (u, uid) in [("kiosk-a", "1900"), ("kiosk-b", "1901")] {
        absent(&r, u);
        absent(&r, uid);
    }
    let g = grp(&format!("{}{}", web_app("a", "A"), web_app("b", "B")));
    let mut sys = SysState::default();
    run_step(&r, root.path(), &mut sys, &g, Phase::Full);
    let dropin = root
        .path()
        .join(UNIT_DIR)
        .join("user@1900.service.d")
        .join(DROPIN_FILE);
    let text = fs::read_to_string(&dropin).unwrap();
    let body: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
    assert_eq!(
        body,
        vec![
            "[Unit]",
            "OnSuccess=mastersos-ephemeral-cleanup@kiosk-a.service",
            "OnFailure=mastersos-ephemeral-cleanup@kiosk-a.service",
        ]
    );
    assert_eq!(mode(&dropin), 0o644);
    assert!(root
        .path()
        .join(UNIT_DIR)
        .join("user@1901.service.d")
        .join(DROPIN_FILE)
        .exists());
    assert_eq!(count(&r.calls(), "systemctl daemon-reload"), 1);
    assert!(!sys.kiosk_reload_pending);
    // 内容没变：不 reload
    let r = FakeRunner::new();
    present(&r, "kiosk-a", 1900, "A");
    present(&r, "kiosk-b", 1901, "B");
    run_step(&r, root.path(), &mut sys, &g, Phase::Full);
    assert_eq!(count(&r.calls(), "systemctl daemon-reload"), 0);
    // reload 失败：记着，下一轮内容没变也再 reload
    fs::remove_file(&dropin).unwrap();
    let r = FakeRunner::new();
    present(&r, "kiosk-a", 1900, "A");
    present(&r, "kiosk-b", 1901, "B");
    r.respond("systemctl daemon-reload", Output::fail(1, "boom"));
    let out = run_step(&r, root.path(), &mut sys, &g, Phase::Full);
    assert!(out.iter().any(|i| i.item == ITEM && !i.ok), "{out:?}");
    assert!(sys.kiosk_reload_pending);
    let r = FakeRunner::new();
    present(&r, "kiosk-a", 1900, "A");
    present(&r, "kiosk-b", 1901, "B");
    run_step(&r, root.path(), &mut sys, &g, Phase::Full);
    assert_eq!(count(&r.calls(), "systemctl daemon-reload"), 1);
    assert!(!sys.kiosk_reload_pending);
}

/// Review Focus：应用被删时会话还开着——先从 namespace.conf 拿掉、结束它的会话、等 slice 停下、userdel、在本进程里
/// 清理（不经单元：登录策略已没有它，单元会什么都不做），最后删 AccountsService 的记录、目录与 drop-in。
#[test]
fn removes_account_after_ending_session() {
    let root = root();
    let p = root.path();
    // 上一轮建好的 kiosk-old（uid 1950）：各处的文件都在
    let mut sys = SysState::default();
    sys.kiosk_accounts.insert("old".into(), st(1950, "Old"));
    let users = p.join(ACCOUNTS_DIR);
    fs::create_dir_all(&users).unwrap();
    fs::write(users.join("kiosk-old"), "[User]\n").unwrap();
    fs::write(users.join("alice"), "[User]\n").unwrap();
    let pub_dir = p.join(PUBLIC_DIR).join("old");
    fs::create_dir_all(pub_dir.join(POLICIES_DIR)).unwrap();
    fs::write(pub_dir.join(LAUNCH_FILE), "{}").unwrap();
    let unit_dir = p.join(UNIT_DIR).join("user@1950.service.d");
    fs::create_dir_all(&unit_dir).unwrap();
    fs::write(unit_dir.join(DROPIN_FILE), "x").unwrap();
    let linger = p.join("var/lib/systemd/linger");
    fs::create_dir_all(&linger).unwrap();
    fs::write(linger.join("kiosk-old"), "").unwrap();
    let run = p.join("run/mastersos");
    fs::create_dir_all(&run).unwrap();
    fs::write(run.join("kiosk-old-ready"), "").unwrap();
    let ns = p.join(NAMESPACE_CONF);
    fs::create_dir_all(ns.parent().unwrap()).unwrap();
    fs::write(&ns, "x  y  user  ~kiosk-old\n").unwrap();

    let hr = HookRunner::new(ns.clone());
    let r = &hr.fake;
    absent(r, "kiosk-new");
    absent(r, "1900");
    // 会话还开着：结束之后 slice 先 active 两次再停下
    for a in ["active\n", "active\n"] {
        r.respond("systemctl is-active user-1950.slice", Output::ok(a));
    }
    removal_answers(r, "kiosk-old", 1950);
    let bundle = tempfile::tempdir().unwrap();
    let out = run_with(
        &hr,
        p,
        &mut sys,
        &grp(&web_app("new", "New")),
        Phase::Full,
        bundle.path(),
    );
    assert!(out.iter().all(|i| i.ok), "{out:?}");
    // 删的时候先从 namespace.conf 拿掉，才结束会话
    let at_term = hr.at("loginctl terminate-user kiosk-old").unwrap();
    assert!(
        at_term.contains("~kiosk-new\n") && !at_term.contains("kiosk-old"),
        "{at_term}"
    );
    let calls = r.calls();
    let term = idx(&calls, "loginctl terminate-user kiosk-old");
    let polls: Vec<usize> = calls
        .iter()
        .enumerate()
        .filter(|(_, c)| c.starts_with("systemctl is-active user-1950.slice"))
        .map(|(i, _)| i)
        .collect();
    let del = idx(&calls, "userdel kiosk-old");
    let reload = idx(&calls, "systemctl daemon-reload");
    assert!(term < polls[0], "{calls:?}");
    // 第三次看才停下：userdel 在它之后
    assert!(polls[2] < del && del < reload, "{calls:?}");
    // 清理在本进程里跑（userdel 之后又看了一次 slice），没有经单元
    assert!(polls[3] > del, "{calls:?}");
    assert_eq!(
        count(
            &calls,
            "systemctl start --no-block mastersos-ephemeral-cleanup@kiosk-old"
        ),
        0,
        "{calls:?}"
    );
    assert!(!users.join("kiosk-old").exists());
    assert!(users.join("alice").exists());
    assert!(!pub_dir.exists());
    assert!(!unit_dir.exists(), "空了的 drop-in 目录也删掉");
    assert!(!linger.join("kiosk-old").exists());
    assert!(!run.join("kiosk-old-ready").exists());
    assert_eq!(
        sys.kiosk_accounts,
        BTreeMap::from([("new".to_string(), st(1900, "New"))])
    );
    let text = fs::read_to_string(&ns).unwrap();
    assert!(
        text.contains("~kiosk-new\n") && !text.contains("old"),
        "{text}"
    );
}

/// 删不掉（账号的 uid 对不上，不是我们建的那个）：状态留着、回报失败，下一轮再来；不 userdel。
#[test]
fn removal_refuses_account_with_other_uid() {
    let root = root();
    let mut sys = SysState::default();
    sys.kiosk_accounts.insert("old".into(), st(1950, "Old"));
    let r = FakeRunner::new();
    r.respond(
        "systemctl is-active user-1950.slice",
        Output::ok("inactive\n"),
    );
    present(&r, "kiosk-old", 1960, "Old");
    let out = run_step(&r, root.path(), &mut sys, &grp(""), Phase::Full);
    assert!(
        out.iter().any(|i| i.item == "kiosk:old" && !i.ok),
        "{out:?}"
    );
    assert_eq!(count(&r.calls(), "userdel"), 0);
    assert!(sys.kiosk_accounts.contains_key("old"));
}

/// Review Focus：断电时有人在锁定会话里——开机快速应用对每个 kiosk 账号拉起一次清理；平时的应用不拉起。
#[test]
fn boot_kicks_cleanup_for_every_kiosk_account() {
    let root = root();
    let g = grp(&format!(
        "{}[group.apps.kiosk.calc]\nname = \"Calc\"\nexec = \"org.gnome.Calculator\"\n",
        web_app("a", "A")
    ));
    let mut sys = SysState::default();
    let r = FakeRunner::new();
    for (u, uid) in [("kiosk-a", "1900"), ("kiosk-calc", "1901")] {
        absent(&r, u);
        absent(&r, uid);
    }
    run_step(&r, root.path(), &mut sys, &g, Phase::Full);
    // 平时：账号都在，不拉起
    let r = FakeRunner::new();
    present(&r, "kiosk-a", 1900, "A");
    present(&r, "kiosk-calc", 1901, "Calc");
    run_step(&r, root.path(), &mut sys, &g, Phase::Full);
    assert_eq!(count(&r.calls(), "systemctl start"), 0, "{:?}", r.calls());
    // 开机：每个账号一次
    let r = FakeRunner::new();
    present(&r, "kiosk-a", 1900, "A");
    present(&r, "kiosk-calc", 1901, "Calc");
    let out = run_step(&r, root.path(), &mut sys, &g, Phase::Boot);
    assert_eq!(out, vec![ok_item("a"), ok_item("calc")]);
    let calls = r.calls();
    for u in ["kiosk-a", "kiosk-calc"] {
        assert_eq!(
            count(
                &calls,
                &format!("systemctl start --no-block mastersos-ephemeral-cleanup@{u}.service")
            ),
            1,
            "{calls:?}"
        );
    }
    // 开机时刚建的账号也只拉起一次
    let mut sys = SysState::default();
    let root = super::super::tests::tmp_root();
    write_exam(
        root.path(),
        &format!(r#"{{"id": "{EXAM_ID}", "update_url": "{EXAM_URL}"}}"#),
    );
    let r = FakeRunner::new();
    absent(&r, "kiosk-a");
    absent(&r, "1900");
    run_step(
        &r,
        root.path(),
        &mut sys,
        &grp(&web_app("a", "A")),
        Phase::Boot,
    );
    assert_eq!(
        count(
            &r.calls(),
            "systemctl start --no-block mastersos-ephemeral-cleanup@kiosk-a.service"
        ),
        1
    );
}

#[test]
fn invalid_app_skipped_and_reported() {
    let root = root();
    let r = FakeRunner::new();
    absent(&r, "kiosk-good");
    absent(&r, "1900");
    let g = grp(&format!(
        "[group.apps.kiosk.bad]\nname = \"Bad\"\nurl = \"http://insecure.example.org/\"\n{}",
        web_app("good", "Good")
    ));
    let mut sys = SysState::default();
    let out = run_step(&r, root.path(), &mut sys, &g, Phase::Full);
    assert_eq!(out.len(), 2, "{out:?}");
    assert_eq!(out[0].item, "kiosk:bad");
    assert!(!out[0].ok);
    assert!(
        out[0].detail.as_deref().unwrap().contains("https"),
        "{out:?}"
    );
    assert_eq!(out[1], ok_item("good"));
    let calls = r.calls();
    assert!(calls.iter().all(|c| !c.contains("kiosk-bad")), "{calls:?}");
    assert!(!root.path().join(PUBLIC_DIR).join("bad").exists());
    assert!(!sys.kiosk_accounts.contains_key("bad"));
    let text = fs::read_to_string(root.path().join(NAMESPACE_CONF)).unwrap();
    assert!(text.contains("~kiosk-good\n"), "{text}");
    // 已经建过的应用改坏了：上一次的账号与文件原样留着，回报失败
    let r = FakeRunner::new();
    let g = grp("[group.apps.kiosk.good]\nname = \"Good\"\nurl = \"http://x.example.org/\"\n");
    let out = run_step(&r, root.path(), &mut sys, &g, Phase::Full);
    assert!(!out[0].ok && out[0].item == "kiosk:good", "{out:?}");
    assert_eq!(count(&r.calls(), "userdel"), 0);
    assert!(sys.kiosk_accounts.contains_key("good"));
    assert!(root
        .path()
        .join(PUBLIC_DIR)
        .join("good")
        .join(LAUNCH_FILE)
        .exists());
}

/// 裁定 R1：考试扩展的文件没有或不合规——网页 / PWA 应用跳过、回报失败；本地程序照常。
#[test]
fn exam_extension_missing_skips_web_apps_only() {
    for bad in [
        None,
        Some("not json"),
        Some(r#"{"id": "short", "update_url": "https://os.khundavid.com/u.xml"}"#),
        Some(
            &format!(r#"{{"id": "{EXAM_ID}", "update_url": "http://os.khundavid.com/u.xml"}}"#)[..],
        ),
        Some(&format!(r#"{{"id": "{EXAM_ID}", "update_url": "file:///var/tmp/updates.xml"}}"#)[..]),
    ] {
        let root = tmp_root();
        match bad {
            None => {}
            Some(t) => write_exam(root.path(), t),
        }
        fs::create_dir_all(root.path().join("home")).unwrap();
        let r = FakeRunner::new();
        absent(&r, "kiosk-calc");
        absent(&r, "1900");
        let g = grp(&format!(
            "{}[group.apps.kiosk.calc]\nname = \"Calc\"\nexec = \"org.gnome.Calculator\"\n",
            web_app("web", "Web")
        ));
        let mut sys = SysState::default();
        let out = run_step(&r, root.path(), &mut sys, &g, Phase::Full);
        assert_eq!(out[0], ok_item("calc"), "{bad:?}");
        assert_eq!(out[1].item, "kiosk:web");
        assert!(!out[1].ok);
        assert!(
            out[1].detail.as_deref().unwrap().contains("kiosk-ext.json"),
            "{out:?}"
        );
        assert!(r.calls().iter().all(|c| !c.contains("kiosk-web")));
        assert!(sys.kiosk_accounts.contains_key("calc"));
        // 本地程序的禁止一切的策略不靠考试扩展
        assert!(root
            .path()
            .join(PUBLIC_DIR)
            .join("calc")
            .join(POLICIES_DIR)
            .join(POLICY_FILE)
            .is_file());
        assert!(!sys.kiosk_accounts.contains_key("web"));
    }
}

/// 不在状态里的 drop-in 与目录（状态丢过、或删到一半）：清掉。
#[test]
fn stale_dropins_and_dirs_are_swept() {
    let root = root();
    let p = root.path();
    let stale_unit = p.join(UNIT_DIR).join("user@1955.service.d");
    fs::create_dir_all(&stale_unit).unwrap();
    fs::write(stale_unit.join(DROPIN_FILE), "x").unwrap();
    fs::write(stale_unit.join("10-admin.conf"), "keep").unwrap();
    let guest_unit = p.join(UNIT_DIR).join("user@1999.service.d");
    fs::create_dir_all(&guest_unit).unwrap();
    fs::write(guest_unit.join(DROPIN_FILE), "not ours").unwrap();
    let stale_dir = p.join(PUBLIC_DIR).join("gone");
    fs::create_dir_all(&stale_dir).unwrap();
    fs::write(stale_dir.join(LAUNCH_FILE), "{}").unwrap();
    let r = FakeRunner::new();
    let mut sys = SysState::default();
    let out = run_step(&r, p, &mut sys, &grp(""), Phase::Full);
    assert!(out.iter().all(|i| i.ok), "{out:?}");
    assert!(!stale_unit.join(DROPIN_FILE).exists());
    assert!(stale_unit.join("10-admin.conf").exists());
    assert!(
        guest_unit.join(DROPIN_FILE).exists(),
        "1900–1989 以外的不碰"
    );
    assert!(!stale_dir.exists());
    assert_eq!(count(&r.calls(), "systemctl daemon-reload"), 1);
}

/// 清理（会话结束后、开机时）删掉 AccountsService 里按名字存的一切（上一位在登录界面选过的会话等）之后，照 kiosk
/// 步骤写下的模板恢复：没有它 GDM 会用默认会话起这个无口令账号。头像经 accounts-daemon 设回模板里的那个。
#[test]
fn cleanup_restores_accountsservice_from_template() {
    let root = root();
    let p = root.path();
    let r = FakeRunner::new();
    absent(&r, "kiosk-nwea");
    absent(&r, "1900");
    let bundle = tempfile::tempdir().unwrap();
    fs::create_dir_all(bundle.path().join("files")).unwrap();
    fs::write(bundle.path().join("files/n.png"), b"\x89PNG\r\n\x1a\nx").unwrap();
    let g = grp(&format!(
        "{}icon = \"files/n.png\"\n",
        web_app("nwea", "NWEA MAP")
    ));
    let mut sys = SysState::default();
    run_with(&r, p, &mut sys, &g, Phase::Full, bundle.path());
    let keyfile = p.join(ACCOUNTS_DIR).join("kiosk-nwea");
    let want = fs::read_to_string(&keyfile).unwrap();
    // 上一位在登录界面换了会话
    fs::write(&keyfile, "[User]\nSession=ubuntu\n").unwrap();

    let me = rustix::process::geteuid().as_raw();
    let acct = ephemeral::kiosk("nwea", me, "NWEA MAP");
    let r = FakeRunner::new();
    let line = format!("kiosk-nwea:x:{me}:{me}:NWEA MAP:/home/kiosk-nwea:/bin/bash\n");
    r.respond(&format!("getent passwd {me}"), Output::ok(&line));
    r.respond("getent passwd kiosk-nwea", Output::ok(&line));
    r.respond("getent passwd kiosk-nwea", Output::ok(&line));
    r.respond(
        &format!("systemctl is-active user-{me}.slice"),
        Output::ok("inactive\n"),
    );
    let procs = SystemdProcs {
        runner: &r,
        timeout: CMD_TIMEOUT,
    };
    cleanup(&EphemeralEnv {
        runner: &r,
        procs: &procs,
        root: p,
        uid: me,
        mounts: &ProcMounts,
        acct: &acct,
    })
    .unwrap();
    assert_eq!(fs::read_to_string(&keyfile).unwrap(), want);
    assert_eq!(mode(&keyfile), 0o600);
    let calls = r.calls();
    let icon = idx(&calls, "busctl call org.freedesktop.Accounts");
    assert!(
        calls[icon].ends_with("SetIconFile s /var/lib/mastersos-public/kiosk/nwea/icon"),
        "{calls:?}"
    );
    // accounts-daemon 内存里上一位选的会话也经它的接口改回来（GDM 经 D-Bus 读，不读文件）
    let user_obj = format!(
        "busctl call org.freedesktop.Accounts /org/freedesktop/Accounts/User{me} org.freedesktop.Accounts.User"
    );
    for m in ["SetSession", "SetXSession"] {
        let i = idx(&calls, &format!("{user_obj} {m} s mastersos-kiosk"));
        assert_eq!(calls[i], format!("{user_obj} {m} s mastersos-kiosk"));
    }
    assert!(p.join("run/mastersos/kiosk-nwea-ready").exists());

    // 模板没了（kiosk 步骤还没写）：不写就绪标记，往拒绝的方向落
    fs::remove_file(p.join(PUBLIC_DIR).join("nwea").join(ACCOUNTS_TEMPLATE)).unwrap();
    let r = FakeRunner::new();
    r.respond(&format!("getent passwd {me}"), Output::ok(&line));
    r.respond("getent passwd kiosk-nwea", Output::ok(&line));
    r.respond("getent passwd kiosk-nwea", Output::ok(&line));
    r.respond(
        &format!("systemctl is-active user-{me}.slice"),
        Output::ok("inactive\n"),
    );
    let procs = SystemdProcs {
        runner: &r,
        timeout: CMD_TIMEOUT,
    };
    let e = cleanup(&EphemeralEnv {
        runner: &r,
        procs: &procs,
        root: p,
        uid: me,
        mounts: &ProcMounts,
        acct: &acct,
    })
    .unwrap_err();
    assert!(format!("{e:#}").contains(ACCOUNTS_TEMPLATE), "{e:#}");
    assert!(!p.join("run/mastersos/kiosk-nwea-ready").exists());
}

#[test]
fn kiosk_step_is_fast_and_after_guest() {
    let s = step();
    assert!(s.fast);
    assert!(s.without_bundle.is_none());
    let names: Vec<&str> = super::super::steps().iter().map(|s| s.name).collect();
    let g = names.iter().position(|n| *n == "guest").unwrap();
    let l = names.iter().position(|n| *n == "login").unwrap();
    let k = names.iter().position(|n| *n == "kiosk").unwrap();
    assert!(l < k && g < k, "{names:?}");
}

/// 复审 Important 1：useradd 成功而 `passwd -d`/`chage` 失败（或之后的清理没拉起来）的账号是锁着口令、没有 tmpfs 的；
/// 状态里的 `initialized` 是 false，之后每轮重做恢复口令与第一次清理，两样都成功才记 true，之后不再做。
#[test]
fn reset_password_retried_until_initialized() {
    let root = root();
    let g = grp(&web_app("nwea", "NWEA MAP"));
    let mut sys = SysState::default();
    // 第一轮：useradd 成功，passwd -d 失败
    let r = FakeRunner::new();
    absent(&r, "kiosk-nwea");
    absent(&r, "1900");
    r.respond("passwd -d kiosk-nwea", Output::fail(1, "shadow locked"));
    let out = run_step(&r, root.path(), &mut sys, &g, Phase::Full);
    assert!(!out[0].ok && out[0].item == "kiosk:nwea", "{out:?}");
    assert_eq!(count(&r.calls(), "systemctl start"), 0, "{:?}", r.calls());
    assert!(!sys.kiosk_accounts["nwea"].initialized);
    // 第二轮：账号在、名字没变，照样重做口令；清理拉起失败 → 仍未完成
    let r = FakeRunner::new();
    present(&r, "kiosk-nwea", 1900, "NWEA MAP");
    r.respond(
        "systemctl start --no-block mastersos-ephemeral-cleanup@kiosk-nwea.service",
        Output::fail(1, "no"),
    );
    run_step(&r, root.path(), &mut sys, &g, Phase::Full);
    let calls = r.calls();
    assert_eq!(count(&calls, "useradd"), 0);
    idx(&calls, "passwd -d kiosk-nwea");
    assert!(!sys.kiosk_accounts["nwea"].initialized);
    // 第三轮：两样都成功 → 记下完成
    let r = FakeRunner::new();
    present(&r, "kiosk-nwea", 1900, "NWEA MAP");
    let out = run_step(&r, root.path(), &mut sys, &g, Phase::Full);
    assert_eq!(out, vec![ok_item("nwea")]);
    let calls = r.calls();
    let pw = idx(&calls, "passwd -d kiosk-nwea");
    let ch = idx(&calls, "chage -m 99999 ");
    let kick = idx(
        &calls,
        "systemctl start --no-block mastersos-ephemeral-cleanup@kiosk-nwea.service",
    );
    assert!(pw < ch && ch < kick, "{calls:?}");
    assert!(sys.kiosk_accounts["nwea"].initialized);
    // 第四轮：什么都不做
    let r = FakeRunner::new();
    present(&r, "kiosk-nwea", 1900, "NWEA MAP");
    run_step(&r, root.path(), &mut sys, &g, Phase::Full);
    assert!(
        r.calls()
            .iter()
            .all(|c| !c.starts_with("passwd") && !c.starts_with("systemctl")),
        "{:?}",
        r.calls()
    );
}

/// Design 2026-11-06-kiosk-platform-inject §3: an app with platform and inject starts at the exam extension's start page,
/// its policy allows that page and force-installs the helper built from the bundle's script; the key is kept in var_dir.
#[test]
fn platform_and_inject_build_the_start_page_and_helper() {
    let root = root();
    let r = FakeRunner::new();
    absent(&r, "kiosk-tn");
    absent(&r, "1900");
    let bundle = tempfile::tempdir().unwrap();
    fs::create_dir_all(bundle.path().join("files")).unwrap();
    fs::write(bundle.path().join("files/tn.js"), "window.tn = 1;\n").unwrap();
    let g = grp(
        "[group.apps.kiosk.tn]\nname = \"TN\"\nurl = \"https://home.testnav.com/\"\n\
         allow = [\"testnav.com\"]\nplatform = \"chromeos\"\ninject = \"files/tn.js\"\n",
    );
    let mut sys = SysState::default();
    let out = run_with(&r, root.path(), &mut sys, &g, Phase::Full, bundle.path());
    assert_eq!(out, vec![ok_item("tn")]);
    let dir = root.path().join(PUBLIC_DIR).join("tn");
    let l: Launch = serde_json::from_slice(&fs::read(dir.join(LAUNCH_FILE)).unwrap()).unwrap();
    let start = l.start.clone().unwrap();
    let prefix = format!("chrome-extension://{EXAM_ID}/start.html#");
    assert!(start.starts_with(&prefix), "{start}");
    let key = fs::read(
        root.path()
            .join("var/lib/mastersos-system")
            .join(inject::KEY_DIR)
            .join("tn.p8"),
    )
    .unwrap();
    assert!(!key.is_empty());
    let pol: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join(POLICIES_DIR).join(POLICY_FILE)).unwrap())
            .unwrap();
    let forced = pol["ExtensionInstallForcelist"].as_array().unwrap();
    assert_eq!(forced.len(), 2, "{forced:?}");
    let helper = forced[1]
        .as_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(mastersos_bundle::kiosk::extension_id_ok(&helper));
    assert!(pol["URLAllowlist"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!(format!("chrome-extension://{EXAM_ID}"))));
    // the start page's configuration names the helper and the platform
    let enc = &start[prefix.len()..];
    assert!(enc.contains(&helper), "{enc}");
    assert!(enc.contains("%22platform%22%3A%22chromeos%22"), "{enc}");
    assert!(dir
        .join(inject::INJECT_DIR)
        .join(inject::CRX_FILE)
        .is_file());
    let xml = fs::read_to_string(dir.join(inject::INJECT_DIR).join(inject::UPDATES_FILE)).unwrap();
    assert!(xml.contains(&format!("appid='{helper}'")), "{xml}");

    // without inject the helper goes away (the key stays: the id is the same if inject comes back)
    let g = grp(
        "[group.apps.kiosk.tn]\nname = \"TN\"\nurl = \"https://home.testnav.com/\"\nplatform = \"chromeos\"\n",
    );
    let out = run_with(&r, root.path(), &mut sys, &g, Phase::Full, bundle.path());
    assert_eq!(out, vec![ok_item("tn")]);
    assert!(!dir.join(inject::INJECT_DIR).exists());
    let l: Launch = serde_json::from_slice(&fs::read(dir.join(LAUNCH_FILE)).unwrap()).unwrap();
    assert!(l.start.unwrap().contains("%22helper%22%3Anull"));

    // a missing script skips the app with the reason
    let g = grp(
        "[group.apps.kiosk.tn]\nname = \"TN\"\nurl = \"https://home.testnav.com/\"\ninject = \"files/gone.js\"\n",
    );
    let out = run_with(&r, root.path(), &mut sys, &g, Phase::Full, bundle.path());
    assert_eq!(out.len(), 1);
    assert!(!out[0].ok);
    assert!(
        format!("{:?}", out[0].detail).contains("files/gone.js"),
        "{:?}",
        out[0].detail
    );
}

#[test]
fn plain_web_app_has_no_start_page() {
    let l = launch_of("x", &grp(&web_app("x", "X")).apps.kiosk["x"]).unwrap();
    assert_eq!(l.start, None);
    assert_eq!(
        percent_encode("{\"a\":\"b c/é\"}"),
        "%7B%22a%22%3A%22b%20c%2F%C3%A9%22%7D"
    );
}
