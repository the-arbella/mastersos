//! `mastersos-agent pam-session` 的退出码：跑编译出的二进制（`main` 在建 tokio 运行时之前分出去）。
//! 只测不碰系统的路径。不是 root 时（开发机、CI）一律拒绝、什么都不做：PAM_* 环境变量谁都能伪造，只有 PAM 以 root
//! 调它才算数。是 root 时：访客不在 GDM 上（交给 pam-check 拒绝）、别的用户、不是 open_session 都放行；访客在 GDM 上
//! 而本机没有 `/run/mastersos/guest-ready` 时拒绝并打出原因。

use std::path::Path;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_mastersos-agent");

fn run(sub: &str, t: &str, service: &str, user: &str) -> Output {
    Command::new(BIN)
        .env_clear()
        .arg(sub)
        .env("PAM_TYPE", t)
        .env("PAM_SERVICE", service)
        .env("PAM_USER", user)
        .output()
        .unwrap()
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

#[test]
fn pam_session_exit_codes() {
    // (PAM_TYPE, PAM_SERVICE, PAM_USER, root 时的退出码)：访客在 GDM 以外的服务上拒绝（钩子是 requisite），
    // 访客的 close_session 与别的用户放行
    let cases = [
        ("open_session", "login", "guest", 1),
        ("open_session", "sshd", "guest", 1),
        ("close_session", "gdm-password", "guest", 0),
        ("open_session", "gdm-authd", "nobody-here-mastersos-test", 0),
        ("open_session", "gdm-authd", "a@school.ac.th", 0),
        ("open_session", "gdm-authd", "Guest", 0),
        ("", "", "", 0),
    ];
    for (t, svc, user, code) in cases {
        let o = run("pam-session", t, svc, user);
        assert!(!String::from_utf8_lossy(&o.stderr).contains("panicked"));
        if is_root() {
            assert_eq!(o.status.code(), Some(code), "{t} {svc} {user}");
        } else {
            assert_eq!(o.status.code(), Some(1), "非 root：{t} {svc} {user}");
            assert!(String::from_utf8_lossy(&o.stdout).contains("root"));
        }
    }
    for svc in ["gdm-password", "gdm-authd"] {
        let o = run("pam-session", "open_session", svc, "guest");
        assert_eq!(o.status.code(), Some(1), "{svc}");
        assert!(!String::from_utf8_lossy(&o.stderr).contains("panicked"));
        if is_root() && !Path::new("/run/mastersos/guest-ready").exists() {
            let out = String::from_utf8_lossy(&o.stdout);
            assert!(out.contains("上一位访客还没有完全退出"), "{out}");
        }
    }
}

/// 不是 root 跑 guest-cleanup：一样都不做，退出 1。
#[test]
fn guest_cleanup_refuses_non_root() {
    if is_root() {
        return;
    }
    let o = run("guest-cleanup", "", "", "");
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("root"));
}

/// `ephemeral-cleanup`：不是 root 时一样都不做、退出 1；是 root 时，不认的账号名（这一版只认 `guest`）退出 0、
/// 什么都不做（不去碰这台机器上的 /tmp 与挂载）。
#[test]
fn ephemeral_cleanup_ignores_unknown_user() {
    for user in ["nobody-here-mastersos-test", "kiosk-nwea", "Guest"] {
        let o = Command::new(BIN)
            .env_clear()
            .args(["ephemeral-cleanup", user])
            .output()
            .unwrap();
        assert!(!String::from_utf8_lossy(&o.stderr).contains("panicked"));
        if is_root() {
            assert_eq!(o.status.code(), Some(0), "{user}");
            assert!(String::from_utf8_lossy(&o.stderr).contains("doing nothing"));
        } else {
            assert_eq!(o.status.code(), Some(1), "{user}");
            assert!(String::from_utf8_lossy(&o.stderr).contains("root"));
        }
    }
}

/// `ephemeral-cleanup` 没给账号名：是 root 时退出 2（单元配错了），什么都不做；不是 root 时照样先拒绝、退出 1。
#[test]
fn ephemeral_cleanup_without_user_is_a_usage_error() {
    let o = Command::new(BIN)
        .env_clear()
        .arg("ephemeral-cleanup")
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&o.stderr).contains("panicked"));
    if is_root() {
        assert_eq!(o.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&o.stderr).contains("account name"));
    } else {
        assert_eq!(o.status.code(), Some(1));
    }
}
