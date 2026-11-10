//! Chrome 的托管策略：[`BASELINE`] 叠上分组的 `chrome_policy`（TOML 表，原样转成 JSON，同名键以分组的为准），写进
//! `/etc/opt/chrome/policies/managed/mastersos.json`（0644）。不做二次抽象：键名与值的含义
//! 由 Chrome 定，这里只换格式。TOML 有而 JSON 没有的类型（日期时间）报错，旧文件保留不动（与 `admins` 一样，
//! 渲染失败不撤掉已生效的设置）。
//!
//! 锁定应用不受这份影响：`pam_namespace` 给它们换了自己的托管目录（`kiosk::NS_POLYDIR`）。
//!
//! 同一个模块里还有 `chrome_update` 步骤（Task 23）：分组的 `[chrome]`（更新时段、暂停到哪天）写进 [`SysState`]，
//! 由 `mastersos-agent chrome` 读。值不对时那一项不生效（不限制，宁可更新）并回报失败。

use std::path::Path;

use anyhow::{Context, Result};
use mastersos_bundle::ItemResult;

use super::{failed, ok, Env, Step, SysState};
use crate::apply::ApplyContext;
use crate::safefs;
use mastersos_bundle::{checks, ChromeUpdate};

/// 回报项的名字。
pub const ITEM: &str = "chrome-policy";
/// 托管策略目录（相对系统根）与我们的文件。
pub const POLICY_DIR: &str = "etc/opt/chrome/policies/managed";
pub const POLICY_FILE: &str = "mastersos.json";

/// What a school laptop needs before IT writes any policy; a Config's `chrome_policy` overrides any
/// of it by key. Shared machines with Guest on by default: no first-run prompts in every fresh home,
/// no personal Google profile or extensions, nothing sent to Google for usage statistics. Web sign-in
/// (Gmail in a tab) still works. Checked on Chrome 2026-10-31: all report OK in `chrome://policy`.
pub fn baseline() -> serde_json::Map<String, serde_json::Value> {
    let serde_json::Value::Object(map) = serde_json::json!({
        "BrowserAddPersonEnabled": false,
        "BrowserGuestModeEnabled": false,
        "BrowserSignin": 0,
        "DefaultBrowserSettingEnabled": false,
        "ExtensionInstallBlocklist": ["*"],
        "MetricsReportingEnabled": false,
        "PromotionalTabsEnabled": false,
        "RestoreOnStartup": 5,
    }) else {
        unreachable!("a JSON object literal")
    };
    map
}

pub fn step() -> Step {
    Step {
        name: "chrome_policy",
        fast: true,
        run,
        without_bundle: None,
    }
}

/// `chrome_update` 步骤的回报项。
pub const UPDATE_ITEM: &str = "chrome-update";

/// 开机在 GDM 之前也跑（快）：mastersos-chrome.timer 开机 2 分钟就跑一轮，要读到这次的设置。
pub fn update_step() -> Step {
    Step {
        name: "chrome_update",
        fast: true,
        run: run_update,
        without_bundle: Some(clear_update),
    }
}

fn run_update(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
    vec![settle(
        &ctx.config.chrome,
        chrono::Local::now().fixed_offset(),
        env.sys,
    )]
}

/// 没有设置包（复审 M2）：不留上一份包的时段与暂停（暂停会自己过期，时段不会）。不回报。
fn clear_update(_: &mastersos_bundle::Seed, env: &mut Env) -> Vec<ItemResult> {
    env.sys.chrome_window = None;
    env.sys.chrome_pause_until = None;
    vec![]
}

/// 把分组的 `[chrome]` 校一遍写进 `sys`。暂停在机器上按本机日期再校一次 14 天，留 1 天余量
/// （[`checks::chrome_pause_on_machine`]：lint 按 UTC 的发布日算，UTC 以西的时区里发布当晚本机还是前一天，复审 M3）；
/// 这里挡的是绕过 lint 的包。`now` 是本机时区的现在，detail 里写出时区偏移（复审 M9：时区不对时面板上看得出）。
pub fn settle(
    c: &ChromeUpdate,
    now: chrono::DateTime<chrono::FixedOffset>,
    sys: &mut SysState,
) -> ItemResult {
    let today = now.date_naive();
    let mut errs = vec![];
    sys.chrome_window = c
        .update_window
        .as_deref()
        .and_then(|w| match checks::chrome_window(w) {
            Ok(_) => Some(w.to_string()),
            Err(e) => {
                errs.push(e);
                None
            }
        });
    sys.chrome_pause_until =
        c.pause_until
            .as_deref()
            .and_then(|p| match checks::chrome_pause_on_machine(p, today) {
                Ok(()) => Some(p.to_string()),
                Err(e) => {
                    errs.push(e);
                    None
                }
            });
    if !errs.is_empty() {
        return failed(
            UPDATE_ITEM,
            format!(
                "{}; this item has no effect, updating as usual",
                errs.join("; ")
            ),
        );
    }
    let mut parts = vec![];
    if let Some(w) = &sys.chrome_window {
        let tz = checks::utc_offset_label(now.offset().local_minus_utc());
        parts.push(format!("update window {w} (local time {tz})"));
    }
    if let Some(p) = &sys.chrome_pause_until {
        parts.push(format!("paused until {p}"));
    }
    ItemResult {
        detail: Some(if parts.is_empty() {
            "unrestricted".into()
        } else {
            parts.join("; ")
        }),
        ..ok(UPDATE_ITEM)
    }
}

/// TOML 表 → JSON 对象：转换在 bundle 的 [`mastersos_bundle::kiosk::toml_table_to_json`]（锁定应用的策略也用它）。
/// A datetime is an error ("datetime is not supported in a Chrome policy"); so is a non-finite float (`nan`, `inf`), which JSON cannot represent.
pub fn to_json(t: &toml::Table) -> Result<serde_json::Map<String, serde_json::Value>> {
    mastersos_bundle::kiosk::toml_table_to_json(t).map_err(anyhow::Error::msg)
}

fn run(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
    vec![match apply(&env.paths.root, &ctx.config.chrome_policy) {
        Ok(()) => ok(ITEM),
        Err(e) => failed(ITEM, format!("{e:#}")),
    }]
}

fn apply(root: &Path, policy: &toml::Table) -> Result<()> {
    let mut merged = baseline();
    merged.extend(to_json(policy)?);
    let mut text = serde_json::to_string_pretty(&merged)?;
    text.push('\n');
    let dir = safefs::open_dir(root, Path::new(POLICY_DIR), true)?;
    safefs::write_at(&dir, POLICY_FILE, text.as_bytes(), 0o644)
        .with_context(|| format!("write /{POLICY_DIR}/{POLICY_FILE}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::{config, group, paths, tmp_root};
    use super::super::SysState;
    use super::*;
    use crate::apply::Phase;
    use crate::runner::FakeRunner;
    use mastersos_bundle::School;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicBool;

    fn table(s: &str) -> toml::Table {
        s.parse().unwrap()
    }

    fn run_with(root: &Path, policy: toml::Table) -> Vec<ItemResult> {
        let mut g = config();
        g.chrome_policy = policy;
        let school = School::default();
        let flag = AtomicBool::new(false);
        let bundle = tempfile::tempdir().unwrap();
        let ctx = ApplyContext {
            seed: &crate::system::tests::test_seed(),
            school: &school,
            group: &group(),
            config: &g,
            lock: None,
            bundle_dir: bundle.path(),
            phase: Phase::Full,
            superseded: &flag,
            quiet: &std::sync::atomic::AtomicBool::new(false),
        };
        let p = paths(root);
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let mut env = Env {
            paths: &p,
            runner: &r,
            sys: &mut sys,
        };
        run(&ctx, &mut env)
    }

    fn policy_path(root: &Path) -> std::path::PathBuf {
        root.join(POLICY_DIR).join(POLICY_FILE)
    }

    #[test]
    fn chrome_policy_roundtrip() {
        let root = tmp_root();
        let t = table(
            "URLBlocklist = [\"example.org\", \"*.bad.th\"]\nRestoreOnStartup = 4\n\
             HomepageLocation = \"https://school.th/\"\nIncognitoModeAvailability = 1\n\
             BookmarkBarEnabled = true\n[ExtensionSettings.\"*\"]\ninstallation_mode = \"blocked\"\n",
        );
        let out = run_with(root.path(), t);
        assert_eq!(out, vec![ok(ITEM)]);
        let p = policy_path(root.path());
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        let mut want = baseline();
        want.extend(
            serde_json::json!({
                "URLBlocklist": ["example.org", "*.bad.th"],
                "RestoreOnStartup": 4,
                "HomepageLocation": "https://school.th/",
                "IncognitoModeAvailability": 1,
                "BookmarkBarEnabled": true,
                "ExtensionSettings": {"*": {"installation_mode": "blocked"}},
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        assert_eq!(v, serde_json::Value::Object(want));
        assert!(v["RestoreOnStartup"].is_i64(), "整数不变成浮点数");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn chrome_policy_rejects_datetime() {
        let e = to_json(&table("A = 1\nWhen = 2026-10-16T08:00:00Z\n")).unwrap_err();
        assert!(
            format!("{e:#}").contains("datetime is not supported in a Chrome policy"),
            "{e:#}"
        );
        let e = to_json(&table("A = [{ b = 1979-05-27 }]\n")).unwrap_err();
        assert!(format!("{e:#}").contains("datetime"), "{e:#}");
        // 在步骤里：回报失败，旧文件不动。
        let root = tmp_root();
        assert_eq!(run_with(root.path(), table("A = 1\n")), vec![ok(ITEM)]);
        let before = std::fs::read(policy_path(root.path())).unwrap();
        let out = run_with(root.path(), table("When = 2026-10-16\n"));
        assert!(!out[0].ok && out[0].item == ITEM, "{out:?}");
        assert_eq!(std::fs::read(policy_path(root.path())).unwrap(), before);
    }

    fn written(root: &Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(policy_path(root)).unwrap()).unwrap()
    }

    /// No `chrome_policy`: the device still gets the baseline, and clearing a Config's policy goes
    /// back to exactly that.
    #[test]
    fn empty_chrome_policy_writes_the_baseline() {
        let root = tmp_root();
        let base = serde_json::Value::Object(baseline());
        assert_eq!(run_with(root.path(), toml::Table::new()), vec![ok(ITEM)]);
        assert_eq!(written(root.path()), base);
        assert_eq!(run_with(root.path(), table("A = 1\n")), vec![ok(ITEM)]);
        assert_eq!(written(root.path())["A"], 1);
        assert_eq!(run_with(root.path(), toml::Table::new()), vec![ok(ITEM)]);
        assert_eq!(written(root.path()), base);
    }

    /// IT can undo any baseline key: same key, Config wins; the others stay.
    #[test]
    fn config_overrides_the_baseline_by_key() {
        let root = tmp_root();
        let policy = table("BrowserSignin = 1\nExtensionInstallBlocklist = []\n");
        assert_eq!(run_with(root.path(), policy), vec![ok(ITEM)]);
        let got = written(root.path());
        assert_eq!(got["BrowserSignin"], 1);
        assert_eq!(got["ExtensionInstallBlocklist"], serde_json::json!([]));
        assert_eq!(got["PromotionalTabsEnabled"], false);
    }

    /// 本机时区 UTC+7 那天的中午。
    fn day(s: &str) -> chrono::DateTime<chrono::FixedOffset> {
        chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_local_timezone(chrono::FixedOffset::east_opt(7 * 3600).unwrap())
            .unwrap()
    }

    fn chrome(window: Option<&str>, pause: Option<&str>) -> mastersos_bundle::ChromeUpdate {
        mastersos_bundle::ChromeUpdate {
            update_window: window.map(Into::into),
            pause_until: pause.map(Into::into),
        }
    }

    /// Task 23：分组的 `[chrome]` 写进 SysState，`mastersos-agent chrome` 读它；值不对就不限制（宁可更新）并回报失败。
    #[test]
    fn update_settings_go_into_sys_state() {
        let today = day("2026-11-06");
        let mut sys = SysState::default();
        let r = settle(
            &chrome(Some("16:00-07:00"), Some("2026-11-20")),
            today,
            &mut sys,
        );
        assert!(r.ok && r.item == UPDATE_ITEM, "{r:?}");
        assert_eq!(sys.chrome_window.as_deref(), Some("16:00-07:00"));
        assert_eq!(sys.chrome_pause_until.as_deref(), Some("2026-11-20"));
        let d = r.detail.unwrap();
        assert!(d.contains("16:00-07:00") && d.contains("2026-11-20"), "{d}");
        assert!(d.contains("UTC+7"), "写出本机时区：{d}");

        // 去掉：两项都清掉
        let r = settle(&chrome(None, None), today, &mut sys);
        assert!(r.ok, "{r:?}");
        assert_eq!(
            (sys.chrome_window.clone(), sys.chrome_pause_until.clone()),
            (None, None)
        );

        // 时段不对：不限制时段，回报失败；暂停照样生效
        let r = settle(&chrome(Some("16:00"), Some("2026-11-10")), today, &mut sys);
        assert!(!r.ok, "{r:?}");
        assert!(r.detail.as_deref().unwrap().contains("16:00"), "{r:?}");
        assert_eq!(sys.chrome_window, None);
        assert_eq!(sys.chrome_pause_until.as_deref(), Some("2026-11-10"));

        // 暂停超过今天之后 14 天再加 1 天余量（lint 本该挡下）：机器上不暂停，回报失败；15 天还收
        let r = settle(&chrome(None, Some("2026-11-21")), today, &mut sys);
        assert!(r.ok, "{r:?}");
        let r = settle(&chrome(None, Some("2026-11-22")), today, &mut sys);
        assert!(!r.ok, "{r:?}");
        assert_eq!(sys.chrome_pause_until, None);
        let r = settle(&chrome(None, Some("2026-11-31")), today, &mut sys);
        assert!(!r.ok, "{r:?}");
        assert_eq!(sys.chrome_pause_until, None);
    }

    /// 复审 M8：`chrome_update` 在步骤表里、是快步骤（开机 2 分钟那一轮 Chrome 更新要读到这次的设置）；
    /// 复审 M2：没有设置包时清掉两项。
    #[test]
    fn update_step_is_fast_and_clears_without_bundle() {
        let steps = super::super::steps();
        let s = steps
            .iter()
            .find(|s| s.name == "chrome_update")
            .expect("steps() 里有 chrome_update");
        assert!(s.fast);
        let p = paths(tmp_root().path());
        let r = FakeRunner::new();
        let mut sys = SysState {
            chrome_window: Some("16:00-07:00".into()),
            chrome_pause_until: Some("2026-11-20".into()),
            ..SysState::default()
        };
        let seed = mastersos_bundle::Seed {
            server_url: "http://x".into(),
            trust: vec![],
            fetch_token: None,
            group: None,
            oidc: None,
            min_version: None,
            school_id: None,
            wifi: vec![],
            school_name: None,
            it_account: None,
        };
        let mut env = Env {
            paths: &p,
            runner: &r,
            sys: &mut sys,
        };
        assert!((s.without_bundle.unwrap())(&seed, &mut env).is_empty());
        assert_eq!((sys.chrome_window, sys.chrome_pause_until), (None, None));
    }
}
