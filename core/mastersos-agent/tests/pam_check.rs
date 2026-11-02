//! `mastersos-agent pam-check` 的退出码与输出：跑编译出的二进制，用隐藏参数把路径指到临时目录。

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_mastersos-agent");

const SEED_OIDC: &str = r#"
server_url = "https://mastersos.school.ac.th"
trust = []
[oidc]
issuer = "https://sso.school.ac.th"
client_id = "laptops"
"#;

struct Dirs {
    _tmp: tempfile::TempDir,
    state: std::path::PathBuf,
    seed: std::path::PathBuf,
    policy: std::path::PathBuf,
}

fn dirs() -> Dirs {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    let seed = tmp.path().join("seed");
    let login = tmp.path().join("system/login");
    for d in [&state, &seed, &login] {
        fs::create_dir_all(d).unwrap();
    }
    Dirs {
        state,
        seed,
        policy: login.join("policy.json"),
        _tmp: tmp,
    }
}

fn pam_check(d: &Dirs, env: &[(&str, &str)], extra: &[&str]) -> Output {
    let mut c = Command::new(BIN);
    c.env_clear()
        .arg("pam-check")
        .arg("--state-dir")
        .arg(&d.state)
        .arg("--seed-dir")
        .arg(&d.seed)
        .arg("--policy")
        .arg(&d.policy)
        .args(extra);
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().unwrap()
}

fn login(d: &Dirs, user: &str) -> Output {
    pam_check(
        d,
        &[("PAM_USER", user), ("PAM_SERVICE", "gdm-password")],
        &[],
    )
}

fn assert_allowed(o: &Output) {
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert!(o.stdout.is_empty(), "{o:?}");
}

fn assert_denied(o: &Output) -> String {
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!err.contains("panicked"), "{err}");
    String::from_utf8(o.stdout.clone()).unwrap()
}

#[test]
fn pam_check_exit_codes() {
    // 未受管（两处都没有种子）：放行。
    let d = dirs();
    assert_allowed(&login(&d, "alice"));
    assert_allowed(&login(&d, "alice@school.ac.th"));
    // 访客在 tty 上：未受管也拒。
    let o = pam_check(&d, &[("PAM_USER", "guest"), ("PAM_SERVICE", "login")], &[]);
    assert!(assert_denied(&o).contains("访客"));

    // 受管、没有策略文件：按种子的默认值（种子分区里的也算）。
    fs::write(d.seed.join("seed.toml"), SEED_OIDC).unwrap();
    assert_allowed(&login(&d, "alice@school.ac.th"));
    let why = assert_denied(&login(&d, "alice"));
    assert!(
        why.contains("本机账号") && why.contains("Local accounts"),
        "{why}"
    );

    // 策略文件优先：锁定后只有管理员能进。
    let policy = r#"{"methods":["local","sso"],"allowed_domains":["school.ac.th"],
        "admin_users":["boss@school.ac.th"],"locked":true,"lock_message":"交给 IT"}"#;
    fs::write(&d.policy, policy).unwrap();
    assert_allowed(&login(&d, "Boss@School.ac.th"));
    assert!(assert_denied(&login(&d, "alice@school.ac.th")).contains("锁定"));
    // 不是登录的服务照常放行。
    assert_allowed(&pam_check(
        &d,
        &[("PAM_USER", "alice"), ("PAM_SERVICE", "cron")],
        &[],
    ));

    // 坏的策略文件：退回种子，不 panic。
    fs::write(&d.policy, b"{garbage").unwrap();
    assert_allowed(&login(&d, "alice@school.ac.th"));
    assert_denied(&login(&d, "alice"));

    // 没设 PAM_USER、用户名不合规、参数不认识：拒绝。
    assert_denied(&pam_check(&d, &[("PAM_SERVICE", "gdm-password")], &[]));
    for bad in ["", "-x", "--help", "a\nb", "a\tb"] {
        assert_denied(&login(&d, bad));
    }
    let o = pam_check(
        &d,
        &[
            ("PAM_USER", "alice@school.ac.th"),
            ("PAM_SERVICE", "gdm-password"),
        ],
        &["--allow-all"],
    );
    let why = assert_denied(&o);
    assert!(why.contains("参数") && !why.contains("用户名"), "{why}");
}

/// 受管（种子文件在但读不了）、策略也读不了：拒绝，退出 1，没有 panic 的输出。
#[test]
fn pam_check_unreadable_policy_and_seed_denies() {
    let d = dirs();
    // seed.toml 是个目录：存在（受管），但读不出种子。
    fs::create_dir(d.state.join("seed.toml")).unwrap();
    // 策略路径是个目录、所在目录还不可读。
    fs::create_dir(&d.policy).unwrap();
    let login_dir = d.policy.parent().unwrap().to_path_buf();
    fs::set_permissions(&login_dir, fs::Permissions::from_mode(0o000)).unwrap();
    let o = login(&d, "alice@school.ac.th");
    fs::set_permissions(&login_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let why = assert_denied(&o);
    assert!(why.contains("登录设置"), "{why}");
}

/// 其余子命令照旧走 clap 与 tokio 运行时。
#[test]
fn other_subcommands_still_parse() {
    let o = Command::new(BIN).arg("--version").output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert!(String::from_utf8_lossy(&o.stdout).contains("mastersos-agent"));
    let o = Command::new(BIN)
        .arg("no-such-subcommand")
        .output()
        .unwrap();
    assert_ne!(o.status.code(), Some(0));
    assert!(!Path::new(BIN).as_os_str().is_empty());
}

/// 计划 9 Task 4：锁定应用的账号经编译出的二进制——名单在策略文件里，只从 GDM 进，不看方式；名单外的 kiosk- 名字
/// 在受管机器上拒，未受管的机器上照旧放行。
#[test]
fn pam_check_kiosk_accounts() {
    let d = dirs();
    let gdm =
        |user: &str, svc: &str| pam_check(&d, &[("PAM_USER", user), ("PAM_SERVICE", svc)], &[]);
    // 未受管：kiosk-x 是普通的本机账号
    assert_allowed(&gdm("kiosk-x", "gdm-password"));
    fs::write(d.seed.join("seed.toml"), SEED_OIDC).unwrap();
    // 方式只有 sso，名单里有 kiosk-nwea
    let policy = r#"{"methods":["sso"],"locked":false,
        "kiosk_users":[{"user":"kiosk-nwea","name":"NWEA MAP"}]}"#;
    fs::write(&d.policy, policy).unwrap();
    assert_allowed(&gdm("kiosk-nwea", "gdm-password"));
    assert_allowed(&gdm("kiosk-nwea", "gdm-authd"));
    assert_allowed(&gdm("kiosk-nwea", "systemd-user"));
    for svc in ["login", "sshd", "su", "cron", "atd"] {
        assert!(
            assert_denied(&gdm("kiosk-nwea", svc)).contains("登录界面"),
            "{svc}"
        );
    }
    assert!(assert_denied(&gdm("kiosk-old", "gdm-password")).contains("不在这台电脑的设置里"));
    // 策略文件坏了、退回种子：种子里没有锁定应用
    fs::write(&d.policy, b"{garbage").unwrap();
    assert_denied(&gdm("kiosk-nwea", "gdm-password"));
    // 锁定
    let locked = r#"{"methods":["sso"],"locked":true,
        "kiosk_users":[{"user":"kiosk-nwea","name":"NWEA MAP"}]}"#;
    fs::write(&d.policy, locked).unwrap();
    assert!(assert_denied(&gdm("kiosk-nwea", "gdm-password")).contains("锁定"));
}

/// 复审：`kiosk-` 开头的 SSO 账号不是锁定应用——管理员照样能进，普通 SSO 账号照方式判。
#[test]
fn pam_check_kiosk_prefixed_sso_is_sso() {
    let d = dirs();
    fs::write(d.seed.join("seed.toml"), SEED_OIDC).unwrap();
    let policy = r#"{"methods":[],"locked":true,"admin_users":["kiosk-it@school.ac.th"],
        "kiosk_users":[{"user":"kiosk-nwea","name":"NWEA MAP"}]}"#;
    fs::write(&d.policy, policy).unwrap();
    assert_allowed(&login(&d, "kiosk-it@school.ac.th"));
    let policy = r#"{"methods":["sso"],"locked":false}"#;
    fs::write(&d.policy, policy).unwrap();
    assert_allowed(&login(&d, "kiosk-x@school.ac.th"));
    assert!(assert_denied(&login(&d, "kiosk-x")).contains("不在这台电脑的设置里"));
}
