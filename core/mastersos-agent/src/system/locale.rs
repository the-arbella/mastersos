//! 时区与语言跟着学校的设置走（`school.timezone`、`school.locale`）。两步都是 fast，没设就什么都不做、不回报。
//!
//! - `timezone`：过 `checks::timezone`、`/usr/share/zoneinfo/<tz>` 是普通文件（跟随链接；tzdata 里有些名字是链接）、
//!   与 `timedatectl show -p Timezone --value` 不同 → `timedatectl set-timezone`。`/etc/localtime` 在策略表里是 copy。
//! - `locale`：过 `checks::locale`、出现在 `locale -a` 里（`/usr` 只读，语言只能在构建时生成，4a Task 1；`locale -a`
//!   写的是 `th_TH.utf8` 这种形式，按规范化后的名字比较）——不在就回报「镜像里没有这个语言」；与 `localectl status`
//!   的 `LANG` 不同 → `localectl set-locale LANG=<locale>`。26.04 的 localed 写 `/etc/locale.conf`（先写临时文件再改名；
//!   GDM 的 pam_env 读的 `/etc/default/locale` 是指向 `../locale.conf` 的兼容链接），所以策略表里 `/etc/locale.conf`
//!   是 copy、`/etc/default` 是 dir（否则那个相对链接解析到 factory 里镜像的那份）。

use anyhow::{bail, Result};
use mastersos_bundle::{checks, ItemResult};

use super::{failed, ok, Env, Step};
use crate::apply::ApplyContext;
use crate::runner::{run_ok, Cmd};

pub const TIMEZONE_ITEM: &str = "timezone";
pub const LOCALE_ITEM: &str = "locale";
/// 时区文件的目录（相对系统根）。
const ZONEINFO: &str = "usr/share/zoneinfo";

pub fn timezone_step() -> Step {
    Step {
        name: "timezone",
        fast: true,
        run: run_timezone,
        without_bundle: None,
    }
}

pub fn locale_step() -> Step {
    Step {
        name: "locale",
        fast: true,
        run: run_locale,
        without_bundle: None,
    }
}

fn report(item: &str, r: Result<()>) -> Vec<ItemResult> {
    vec![match r {
        Ok(()) => ok(item),
        Err(e) => failed(item, format!("{e:#}")),
    }]
}

fn run_timezone(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
    match ctx.school.timezone.as_deref() {
        None => Vec::new(),
        Some(tz) => report(TIMEZONE_ITEM, apply_timezone(env, tz)),
    }
}

fn apply_timezone(env: &mut Env, tz: &str) -> Result<()> {
    if let Err(e) = checks::timezone(tz) {
        bail!("{e}；不设置");
    }
    let file = env.paths.root.join(ZONEINFO).join(tz);
    if !std::fs::metadata(&file).is_ok_and(|m| m.is_file()) {
        bail!("镜像里没有时区 {tz}（/{ZONEINFO}/{tz} 不是普通文件）；不设置");
    }
    let current = run_ok(
        env.runner,
        Cmd::new("timedatectl", &["show", "-p", "Timezone", "--value"]),
    )?;
    if current.trim() == tz {
        return Ok(());
    }
    run_ok(env.runner, Cmd::new("timedatectl", &["set-timezone", tz]))?;
    Ok(())
}

fn run_locale(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
    match ctx.school.locale.as_deref() {
        None => Vec::new(),
        Some(l) => report(LOCALE_ITEM, apply_locale(env, l)),
    }
}

/// glibc 的规范化名字：编码部分小写、去掉 `-`（`th_TH.UTF-8` 与 `locale -a` 的 `th_TH.utf8` 相同）。
pub fn normalize_locale(l: &str) -> String {
    match l.split_once('.') {
        Some((name, codeset)) => {
            let (codeset, modifier) = match codeset.split_once('@') {
                Some((c, m)) => (c, Some(m)),
                None => (codeset, None),
            };
            let mut out = format!("{name}.{}", codeset.to_ascii_lowercase().replace('-', ""));
            if let Some(m) = modifier {
                out.push('@');
                out.push_str(m);
            }
            out
        }
        None => l.to_string(),
    }
}

/// `localectl status` 里的 `LANG=`（第一行是 `System Locale: LANG=…`，其余 `LC_*` 各占一行）。
pub fn current_lang(status: &str) -> Option<&str> {
    status.lines().find_map(|line| {
        let line = line.trim();
        let line = line.strip_prefix("System Locale:").unwrap_or(line).trim();
        line.strip_prefix("LANG=")
    })
}

fn apply_locale(env: &mut Env, l: &str) -> Result<()> {
    if let Err(e) = checks::locale(l) {
        bail!("{e}；不设置");
    }
    let available = run_ok(env.runner, Cmd::new("locale", &["-a"]))?;
    let want = normalize_locale(l);
    if !available
        .lines()
        .any(|a| normalize_locale(a.trim()) == want)
    {
        bail!("镜像里没有这个语言 {l}（语言只能在构建镜像时生成）；不设置");
    }
    let status = run_ok(env.runner, Cmd::new("localectl", &["status"]))?;
    if current_lang(&status) == Some(l) {
        return Ok(());
    }
    run_ok(
        env.runner,
        Cmd::new("localectl", &["set-locale", &format!("LANG={l}")]),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::{paths, tmp_root, with_ctx};
    use super::super::{steps, SysState};
    use super::*;
    use crate::apply::Phase;
    use crate::runner::{FakeRunner, Output};
    use mastersos_bundle::School;
    use std::path::Path;
    use std::sync::atomic::AtomicBool;

    const LOCALES: &str = "C\nC.utf8\nPOSIX\nen_GB.utf8\nen_US.utf8\nth_TH.utf8\nzh_CN.utf8\n";
    const STATUS_EN: &str = "System Locale: LANG=en_US.UTF-8\n                LC_TIME=en_GB.UTF-8\n    VC Keymap: (unset)\n   X11 Layout: us\n";

    fn run_step(root: &Path, school: &School, runner: &FakeRunner, tz: bool) -> Vec<ItemResult> {
        let p = paths(root);
        let mut sys = SysState::default();
        let flag = AtomicBool::new(false);
        with_ctx(school, Phase::Boot, &flag, |ctx| {
            let mut env = Env {
                paths: &p,
                runner,
                sys: &mut sys,
            };
            if tz {
                run_timezone(ctx, &mut env)
            } else {
                run_locale(ctx, &mut env)
            }
        })
    }

    fn tz_school(tz: &str) -> School {
        School {
            timezone: Some(tz.into()),
            ..School::default()
        }
    }

    fn locale_school(l: &str) -> School {
        School {
            locale: Some(l.into()),
            ..School::default()
        }
    }

    /// 临时根里放一个 `usr/share/zoneinfo/Asia/Bangkok`。
    fn root_with_zone() -> tempfile::TempDir {
        let root = tmp_root();
        let d = root.path().join(ZONEINFO).join("Asia");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("Bangkok"), b"TZif2").unwrap();
        root
    }

    fn sets(r: &FakeRunner, prefix: &str) -> Vec<String> {
        r.calls()
            .into_iter()
            .filter(|c| c.starts_with(prefix))
            .collect()
    }

    #[test]
    fn unknown_timezone_is_reported_not_applied() {
        let root = root_with_zone();
        for tz in ["Mars/Olympus", "Asia", "../../etc/shadow"] {
            let r = FakeRunner::new();
            let out = run_step(root.path(), &tz_school(tz), &r, true);
            assert_eq!(out.len(), 1, "{tz}");
            assert_eq!(out[0].item, TIMEZONE_ITEM);
            assert!(!out[0].ok, "{tz}");
            assert!(sets(&r, "timedatectl set-timezone").is_empty(), "{tz}");
        }
    }

    #[test]
    fn timezone_unchanged_does_nothing() {
        let root = root_with_zone();
        let r = FakeRunner::new();
        r.respond(
            "timedatectl show -p Timezone --value",
            Output::ok("Asia/Bangkok\n"),
        );
        let out = run_step(root.path(), &tz_school("Asia/Bangkok"), &r, true);
        assert_eq!(out, vec![ok(TIMEZONE_ITEM)]);
        assert_eq!(r.calls(), vec!["timedatectl show -p Timezone --value"]);
    }

    #[test]
    fn timezone_changed_is_set() {
        let root = root_with_zone();
        let r = FakeRunner::new();
        r.respond("timedatectl show", Output::ok("Etc/UTC\n"));
        let out = run_step(root.path(), &tz_school("Asia/Bangkok"), &r, true);
        assert_eq!(out, vec![ok(TIMEZONE_ITEM)]);
        assert_eq!(
            sets(&r, "timedatectl set-timezone"),
            vec!["timedatectl set-timezone Asia/Bangkok"]
        );
        // 没设时区：什么都不做、不回报。
        let r = FakeRunner::new();
        assert!(run_step(root.path(), &School::default(), &r, true).is_empty());
        assert!(r.calls().is_empty());
    }

    #[test]
    fn missing_locale_is_reported_not_applied() {
        let root = tmp_root();
        let r = FakeRunner::new();
        r.respond("locale -a", Output::ok(LOCALES));
        r.respond("localectl status", Output::ok(STATUS_EN));
        let out = run_step(root.path(), &locale_school("fr_FR.UTF-8"), &r, false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].item, LOCALE_ITEM);
        assert!(!out[0].ok);
        assert!(
            out[0]
                .detail
                .as_deref()
                .unwrap()
                .contains("镜像里没有这个语言"),
            "{out:?}"
        );
        assert!(sets(&r, "localectl set-locale").is_empty());
        // 格式不对的也不设。
        let r = FakeRunner::new();
        let out = run_step(root.path(), &locale_school("th_TH"), &r, false);
        assert!(!out[0].ok);
        assert!(r.calls().is_empty());
    }

    #[test]
    fn locale_in_image_is_set_once() {
        let root = tmp_root();
        let r = FakeRunner::new();
        r.respond("locale -a", Output::ok(LOCALES));
        r.respond("localectl status", Output::ok(STATUS_EN));
        let out = run_step(root.path(), &locale_school("th_TH.UTF-8"), &r, false);
        assert_eq!(out, vec![ok(LOCALE_ITEM)]);
        assert_eq!(
            sets(&r, "localectl set-locale"),
            vec!["localectl set-locale LANG=th_TH.UTF-8"]
        );
        // 已经是它：不再设。
        let r = FakeRunner::new();
        r.respond("locale -a", Output::ok(LOCALES));
        r.respond(
            "localectl status",
            Output::ok("System Locale: LANG=th_TH.UTF-8\n    VC Keymap: (unset)\n"),
        );
        let out = run_step(root.path(), &locale_school("th_TH.UTF-8"), &r, false);
        assert_eq!(out, vec![ok(LOCALE_ITEM)]);
        assert!(sets(&r, "localectl set-locale").is_empty());
    }

    #[test]
    fn locale_names_normalize_like_glibc() {
        assert_eq!(normalize_locale("th_TH.UTF-8"), "th_TH.utf8");
        assert_eq!(normalize_locale("th_TH.utf8"), "th_TH.utf8");
        assert_eq!(normalize_locale("sr_RS.UTF-8@latin"), "sr_RS.utf8@latin");
        assert_eq!(normalize_locale("C"), "C");
        assert_eq!(current_lang(STATUS_EN), Some("en_US.UTF-8"));
        assert_eq!(current_lang("System Locale: n/a\n"), None);
    }

    #[test]
    fn timezone_and_locale_are_fast_steps() {
        let all = steps();
        for n in ["timezone", "locale"] {
            let s = all.iter().find(|s| s.name == n).unwrap();
            assert!(s.fast, "{n}");
        }
    }
}
