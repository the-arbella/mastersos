use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Mutex, OnceLock};

/// 捕获本测试二进制的日志（只装一次；别的单元测试的日志也会进来，无害）。
struct Capture(Mutex<Vec<String>>);

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, r: &log::Record) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(r.args().to_string());
    }
    fn flush(&self) {}
}

fn logs() -> &'static Capture {
    static C: OnceLock<&'static Capture> = OnceLock::new();
    C.get_or_init(|| {
        let c: &'static Capture = Box::leak(Box::new(Capture(Mutex::new(vec![]))));
        let _ = log::set_logger(c);
        log::set_max_level(log::LevelFilter::Trace);
        c
    })
}

fn logged() -> String {
    logs()
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .join("\n")
}

fn seed(token: Option<&str>) -> Seed {
    Seed {
        server_url: "https://mastersos.example".into(),
        trust: vec![],
        fetch_token: token.map(String::from),
        group: None,
        oidc: None,
        min_version: None,
        school_id: None,
        wifi: vec![],
        school_name: None,
        it_account: None,
    }
}

struct Dirs {
    _d: tempfile::TempDir,
    state: std::path::PathBuf,
    seedp: std::path::PathBuf,
}

fn dirs() -> Dirs {
    let d = tempfile::tempdir().unwrap();
    let state = d.path().join("state");
    let seedp = d.path().join("seed");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::create_dir_all(&seedp).unwrap();
    Dirs {
        _d: d,
        state,
        seedp,
    }
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

#[test]
fn effective_token_prefers_state_then_seed_partition_then_seed() {
    let d = dirs();
    assert_eq!(effective(&d.state, &d.seedp, &seed(None)), None);
    assert_eq!(
        effective(&d.state, &d.seedp, &seed(Some("from-seed"))).as_deref(),
        Some("from-seed")
    );
    std::fs::write(d.seedp.join(TOKEN_FILE), "from-partition").unwrap();
    assert_eq!(
        effective(&d.state, &d.seedp, &seed(Some("from-seed"))).as_deref(),
        Some("from-partition")
    );
    std::fs::write(d.state.join(TOKEN_FILE), "from-state").unwrap();
    assert_eq!(
        effective(&d.state, &d.seedp, &seed(Some("from-seed"))).as_deref(),
        Some("from-state")
    );
    // 种子分区不存在（没挂上）也照常往下找。
    let gone = d.seedp.join("missing");
    std::fs::remove_file(d.state.join(TOKEN_FILE)).unwrap();
    assert_eq!(
        effective(&d.state, &gone, &seed(Some("from-seed"))).as_deref(),
        Some("from-seed")
    );
}

#[test]
fn bad_token_file_is_ignored() {
    logs();
    let d = dirs();
    let long = "L".repeat(300);
    for bad in [
        "",
        "   \n",
        &long,
        "tok-with\nnewline",
        "tok\u{7f}del",
        "tök",
    ] {
        std::fs::write(d.state.join(TOKEN_FILE), bad).unwrap();
        std::fs::write(d.seedp.join(TOKEN_FILE), "fallback-ok").unwrap();
        assert_eq!(
            effective(&d.state, &d.seedp, &seed(Some("from-seed"))).as_deref(),
            Some("fallback-ok"),
            "{bad:?}"
        );
        std::fs::write(d.seedp.join(TOKEN_FILE), bad).unwrap();
        assert_eq!(
            effective(&d.state, &d.seedp, &seed(Some("from-seed"))).as_deref(),
            Some("from-seed"),
            "{bad:?}"
        );
    }
    let text = logged();
    assert!(text.contains(TOKEN_FILE), "坏文件应记一行警告：{text}");
    for secret in [long.as_str(), "tok-with", "newline", "tok\u{7f}del", "tök"] {
        assert!(!text.contains(secret), "日志里不该有文件内容：{text}");
    }
}

#[test]
fn renew_due_once_per_hour() {
    let t0 = Instant::now();
    assert!(renew_due(true, true, None, t0));
    assert!(!renew_due(false, true, None, t0));
    assert!(!renew_due(true, false, None, t0));
    assert!(!renew_due(
        true,
        true,
        Some(t0),
        t0 + Duration::from_secs(59 * 60)
    ));
    assert!(renew_due(
        true,
        true,
        Some(t0),
        t0 + Duration::from_secs(60 * 60)
    ));
    assert!(!renew_due(
        true,
        false,
        Some(t0),
        t0 + Duration::from_secs(2 * 3600)
    ));
    // 上次的时刻在「现在」之后（调用方传错）：不算到期，也不 panic。
    assert!(!renew_due(
        true,
        true,
        Some(t0 + Duration::from_secs(10)),
        t0
    ));
}

#[test]
fn save_skips_unmounted_seed_partition() {
    let d = dirs();
    // 临时目录不是挂载点。
    let e = save(&d.state, &d.seedp, "new-token-1").unwrap_err();
    let msg = format!("{e:#}");
    assert!(e.downcast_ref::<SeedNotWritten>().is_some(), "{msg}");
    assert!(msg.contains("seed partition is not mounted"), "{msg}");
    assert!(!msg.contains("new-token-1"), "{msg}");
    assert_eq!(
        std::fs::read_to_string(d.state.join(TOKEN_FILE)).unwrap(),
        "new-token-1"
    );
    assert_eq!(mode(&d.state.join(TOKEN_FILE)), 0o600);
    assert!(!d.seedp.join(TOKEN_FILE).exists());
    // 不合格的令牌（服务端回了怪东西）不写。
    assert!(save_with(&d.state, &d.seedp, "bad\ntoken", false).is_err());
    assert_eq!(
        std::fs::read_to_string(d.state.join(TOKEN_FILE)).unwrap(),
        "new-token-1"
    );
}

#[test]
fn factory_reset_keeps_renewed_token() {
    let d = dirs();
    save_with(&d.state, &d.seedp, "renewed-token", false).unwrap();
    assert_eq!(mode(&d.state.join(TOKEN_FILE)), 0o600);
    assert_eq!(mode(&d.seedp.join(TOKEN_FILE)), 0o600);
    // 恢复出厂：state_dir 整个清空。
    std::fs::remove_dir_all(&d.state).unwrap();
    std::fs::create_dir_all(&d.state).unwrap();
    assert_eq!(
        effective(&d.state, &d.seedp, &seed(Some("old-seed-token"))).as_deref(),
        Some("renewed-token")
    );
}
