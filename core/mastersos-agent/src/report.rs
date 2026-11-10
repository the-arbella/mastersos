//! 组装状态回报。只有机器与设置本身的事实：不含用户、浏览记录、用户文件或位置（spec §6.6）。

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use mastersos_bundle::{DeviceIdent, GroupSource, ItemResult, StatusReport};

use crate::config::{AgentConfig, STALE_WARN_DAYS};
use crate::ident;
use crate::state::State;

/// 单条 `detail` 的上限（保留结尾）；服务端的请求体上限是 64 KiB。
const MAX_DETAIL_BYTES: usize = 2048;
/// 所有 `detail` 加起来的上限；超出的条目只保留 ok 与 item。
const MAX_DETAILS_TOTAL: usize = 32 * 1024;
/// 与服务端一致：最多回报这么多条。
const MAX_RESULTS: usize = 200;

/// The later-added manifest keys this agent understands (ruling 14; `mastersos_bundle::features_used`),
/// reported in every status so that publishing can refuse a version recently seen machines would
/// reject. A key is listed here in the same change that teaches the agent to parse and apply it:
/// `escrow_recipients` (plan 6 Task 13) is what the LUKS job seals the recovery key to;
/// `school_id` (plan 6 Task 10b) is checked against the seed in `accept_for_school`;
/// `kiosk`（计划 9 Task 6）：kiosk 步骤建账号与策略、`mastersos-kiosk` 在锁定会话里起应用，两半都在了才报告；
/// `config` (config profiles design §5): the new `[[config]]` shape and the `learning`/`full` modes.
/// `support` (remote diagnostics and help design): `[config.support]` is read into `Config::support_enabled`.
/// `config_update_channel`: `update_channel` of the Device's Config or the Defaults picks its update channel.
/// `kiosk_platform`, `kiosk_inject`: the kiosk step builds the app's platform extension (start page, ChromeOS disguise,
/// inject script) and the exam extension takes its exit (design docs/specs/2026-11-06-kiosk-platform-inject-design.md).
/// `oidc_idp_hint`: the `login` step hands `[school.oidc] idp_hint` to the sign-in card (`login-browser/card.json`).
pub const SUPPORTED_FEATURES: &[&str] = &[
    mastersos_bundle::FEATURE_UPDATE_MIRROR,
    mastersos_bundle::FEATURE_ESCROW_RECIPIENTS,
    mastersos_bundle::FEATURE_SCHOOL_ID,
    mastersos_bundle::FEATURE_KIOSK,
    mastersos_bundle::FEATURE_CONFIG,
    mastersos_bundle::FEATURE_WIFI_EXT,
    mastersos_bundle::FEATURE_OIDC_CARD,
    mastersos_bundle::FEATURE_FORMAT_2,
    mastersos_bundle::FEATURE_SUPPORT,
    mastersos_bundle::FEATURE_CONFIG_CHANNEL,
    mastersos_bundle::FEATURE_OIDC_IDP_HINT,
    mastersos_bundle::FEATURE_KIOSK_PLATFORM,
    mastersos_bundle::FEATURE_KIOSK_INJECT,
];

/// 机器的硬件与系统身份。
#[derive(Debug, Clone)]
pub struct Machine {
    pub ident: DeviceIdent,
    pub model: Option<String>,
    pub os_version: Option<String>,
}

impl Machine {
    /// 读 DMI 与 os-release；首次运行时生成的 `device_id` 记进 `state`（由调用方落盘）。
    pub fn read(cfg: &AgentConfig, state: &mut State) -> Machine {
        Machine {
            ident: ident::read(cfg, state),
            model: ident::model(cfg),
            os_version: ident::os_version(cfg),
        }
    }
}

/// 这台机器眼下用的是哪一版、哪个分组。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    pub bundle_version: Option<u64>,
    pub group: String,
    pub source: GroupSource,
    pub locked: bool,
}

/// 设置新不新的几项证据（都来自 state.json）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Freshness {
    pub last_fetch_ok: Option<DateTime<Utc>>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub fresh_until: Option<DateTime<Utc>>,
    pub newer_withheld: Option<u64>,
}

/// 设置可能过期了吗（spec §4.2）。两件事任一成立就算：
///
/// - 多久没联系上服务器：`last_fetch_ok` 早于 `now - STALE_WARN_DAYS`。
/// - 多久没有签名证据说明设置是最新的：`now` 晚于 `max(accepted_at + STALE_WARN_DAYS,
///   fresh_until)`。服务端一直回「没有新版本」不算证据——那正是扣更新的样子；
///   签名心跳才算。
///
/// `accepted_at` 为空（计划 1 的 state、还没接受过包）时照计划 1：只看 `last_fetch_ok`，
/// 从未拉取成功过不算过期（说的是「好久没更新」，不是「还没装好」）。
///
/// 已知限制：心跳的有效期就是「扣更新」最长的不可见时间。
pub fn is_stale(
    last_fetch_ok: Option<DateTime<Utc>>,
    accepted_at: Option<DateTime<Utc>>,
    fresh_until: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    let window = Duration::days(STALE_WARN_DAYS);
    let no_contact = last_fetch_ok.is_some_and(|t| now - t > window);
    let Some(accepted) = accepted_at else {
        return no_contact;
    };
    let evidence = match fresh_until {
        Some(f) => (accepted + window).max(f),
        None => accepted + window,
    };
    no_contact || now > evidence
}

fn tail_of(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut start = s.len() - max;
    while !s.is_char_boundary(start) {
        start += 1;
    }
    format!("…{}", &s[start..])
}

fn fit(mut results: Vec<ItemResult>) -> Vec<ItemResult> {
    results.truncate(MAX_RESULTS);
    let mut budget = MAX_DETAILS_TOTAL;
    for r in &mut results {
        if let Some(d) = r.detail.take() {
            let d = tail_of(&d, MAX_DETAIL_BYTES);
            if d.len() <= budget {
                budget -= d.len();
                r.detail = Some(d);
            }
        }
    }
    results
}

pub fn build(
    machine: &Machine,
    placement: &Placement,
    f: &Freshness,
    results: Vec<ItemResult>,
    now: DateTime<Utc>,
) -> StatusReport {
    let stamp = |t: DateTime<Utc>| t.to_rfc3339_opts(SecondsFormat::Secs, true);
    StatusReport {
        device_id: machine.ident.device_id.clone(),
        serial: machine.ident.serial.clone(),
        model: machine.model.clone(),
        os_version: machine.os_version.clone(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        bundle_version: placement.bundle_version,
        group: placement.group.clone(),
        group_source: placement.source,
        locked: placement.locked,
        stale: is_stale(f.last_fetch_ok, f.accepted_at, f.fresh_until, now),
        last_fetch_ok: f.last_fetch_ok.map(stamp),
        results: fit(results),
        fresh_until: f.fresh_until.map(stamp),
        newer_withheld: f.newer_withheld,
        seed_trust_fingerprints: vec![],
        imported_from_seed_at: None,
        manifest_features: SUPPORTED_FEATURES.iter().map(|f| (*f).to_owned()).collect(),
        os_pending_version: None,
        quiet_since: None,
    }
}

/// Where `update-run` (image/mkosi.extra/usr/lib/mastersos/update-run) leaves the version of an
/// installed OS update that waits for a restart, relative to the root. /run is emptied by the
/// reboot that applies it.
pub const UPDATE_PENDING_REL: &str = "run/mastersos-update-pending";
/// The file holds `YYYYMMDD.N\n`; anything longer is not ours.
const UPDATE_PENDING_MAX_BYTES: u64 = 64;

/// A release version `YYYYMMDD.N` as (date, N); None for anything else (N at most 9 digits, as
/// update-run accepts).
fn release_version(v: &str) -> Option<(u32, u64)> {
    let (d, n) = v.split_once('.')?;
    let digits = |s: &str, min: usize, max: usize| {
        (min..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
    };
    if !digits(d, 8, 8) || !digits(n, 1, 9) {
        return None;
    }
    Some((d.parse().ok()?, n.parse().ok()?))
}

/// The OS version installed and waiting for the next restart (`StatusReport::os_pending_version`):
/// what update-run wrote to [`UPDATE_PENDING_REL`] under `root`, when it is a release version
/// greater than the running `os_version`. None when the file is missing, too long or malformed,
/// or when the running version is not a release version to compare against.
pub fn os_pending_version(root: &std::path::Path, os_version: Option<&str>) -> Option<String> {
    use std::io::Read;
    let running = release_version(os_version?)?;
    let f = std::fs::File::open(root.join(UPDATE_PENDING_REL)).ok()?;
    let mut b = Vec::new();
    f.take(UPDATE_PENDING_MAX_BYTES + 1)
        .read_to_end(&mut b)
        .ok()?;
    if b.len() as u64 > UPDATE_PENDING_MAX_BYTES {
        return None;
    }
    let text = std::str::from_utf8(&b).ok()?;
    let v = text.strip_suffix('\n').unwrap_or(text);
    (release_version(v)? > running).then(|| v.to_owned())
}

/// The latest report built, in the state directory (0600): help requests carry it in their
/// snapshot (plan 2026-11-05 Task 5), and the sender is another process.
pub const LAST_REPORT_FILE: &str = "last-status-report.json";

/// Keeps `r` as the latest report. Best effort: a failure is logged.
pub fn save_last(state_dir: &std::path::Path, r: &StatusReport) {
    let save = || -> anyhow::Result<()> {
        let fd = crate::state::ensure_state_dir(state_dir)?;
        crate::safefs::write_at(&fd, LAST_REPORT_FILE, &serde_json::to_vec(r)?, 0o600)?;
        Ok(())
    };
    if let Err(e) = save() {
        log::warn!("keeping the latest status report failed: {e:#}");
    }
}

/// The latest report kept by [`save_last`], if there is one of at most `max_bytes`.
pub fn load_last(state_dir: &std::path::Path, max_bytes: u64) -> Option<StatusReport> {
    use std::io::Read;
    let f = std::fs::File::open(state_dir.join(LAST_REPORT_FILE)).ok()?;
    let mut b = Vec::new();
    f.take(max_bytes + 1).read_to_end(&mut b).ok()?;
    if b.len() as u64 > max_bytes {
        return None;
    }
    serde_json::from_slice(&b).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine() -> Machine {
        Machine {
            ident: DeviceIdent {
                serial: Some("PF1".into()),
                device_id: "dev".into(),
            },
            model: Some("ThinkPad".into()),
            os_version: Some("1".into()),
        }
    }

    fn placement() -> Placement {
        Placement {
            bundle_version: Some(3),
            group: "cart-g3".into(),
            source: GroupSource::Bundle,
            locked: true,
        }
    }

    fn fetched(t: DateTime<Utc>) -> Freshness {
        Freshness {
            last_fetch_ok: Some(t),
            ..Freshness::default()
        }
    }

    #[test]
    fn build_carries_machine_and_placement() {
        let now = Utc::now();
        let r = build(&machine(), &placement(), &fetched(now), vec![], now);
        assert_eq!(r.device_id, "dev");
        assert_eq!(r.serial.as_deref(), Some("PF1"));
        assert_eq!(r.bundle_version, Some(3));
        assert_eq!(r.group, "cart-g3");
        assert_eq!(r.group_source, GroupSource::Bundle);
        assert!(r.locked);
        assert!(!r.stale);
        assert_eq!(r.agent_version, env!("CARGO_PKG_VERSION"));
        assert!(r.last_fetch_ok.unwrap().ends_with('Z'));
        assert_eq!(r.fresh_until, None);
        assert_eq!(r.newer_withheld, None);
        assert_eq!(r.os_pending_version, None);
    }

    #[test]
    fn os_pending_version_reads_the_file_update_run_writes() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        let run = "20261105.9";
        assert_eq!(os_pending_version(root, Some(run)), None, "no file");
        std::fs::create_dir_all(root.join("run")).unwrap();
        let put = |s: &str| std::fs::write(root.join(UPDATE_PENDING_REL), s).unwrap();
        put("20261106.1\n");
        assert_eq!(
            os_pending_version(root, Some(run)).as_deref(),
            Some("20261106.1")
        );
        assert_eq!(os_pending_version(root, None), None, "no running version");
        assert_eq!(
            os_pending_version(root, Some("1.0")),
            None,
            "running version not comparable"
        );
        // N compares as a number
        put("20261105.10\n");
        assert_eq!(
            os_pending_version(root, Some(run)).as_deref(),
            Some("20261105.10")
        );
        assert_eq!(
            os_pending_version(root, Some("20261105.10")),
            None,
            "already running"
        );
        assert_eq!(
            os_pending_version(root, Some("20261105.11")),
            None,
            "older than running"
        );
        put("20261106.1");
        assert_eq!(
            os_pending_version(root, Some(run)).as_deref(),
            Some("20261106.1"),
            "no newline"
        );
        for bad in [
            "",
            "\n",
            "20261106\n",
            "20261106.\n",
            "2026110.1\n",
            "20261106.1\n\n",
            " 20261106.1\n",
            "20261106.1x\n",
            "20261106.1234567890\n",
            "20261106.-1\n",
            "２0261106.1\n",
        ] {
            put(bad);
            assert_eq!(os_pending_version(root, Some(run)), None, "{bad:?}");
        }
        put(&format!("20261106.1\n{}", " ".repeat(64)));
        assert_eq!(os_pending_version(root, Some(run)), None, "too long");
    }

    #[test]
    fn report_carries_supported_features() {
        let now = Utc::now();
        let r = build(&machine(), &placement(), &fetched(now), vec![], now);
        assert_eq!(
            r.manifest_features,
            [
                "update_mirror",
                "escrow_recipients",
                "school_id",
                "kiosk",
                "config",
                "wifi_ext",
                "oidc_card",
                "format_2",
                "support",
                "config_update_channel",
                "oidc_idp_hint",
                "kiosk_platform",
                "kiosk_inject"
            ]
        );
        assert_eq!(r.manifest_features, SUPPORTED_FEATURES);
        r.check_manifest_features().unwrap();
        // Every listed key is one the bundle knows as a later-added key.
        let all = [
            mastersos_bundle::FEATURE_UPDATE_MIRROR,
            mastersos_bundle::FEATURE_ESCROW_RECIPIENTS,
            mastersos_bundle::FEATURE_SCHOOL_ID,
            mastersos_bundle::FEATURE_KIOSK,
            mastersos_bundle::FEATURE_CONFIG,
            mastersos_bundle::FEATURE_WIFI_EXT,
            mastersos_bundle::FEATURE_OIDC_CARD,
            mastersos_bundle::FEATURE_FORMAT_2,
            mastersos_bundle::FEATURE_SUPPORT,
            mastersos_bundle::FEATURE_CONFIG_CHANNEL,
            mastersos_bundle::FEATURE_OIDC_IDP_HINT,
            mastersos_bundle::FEATURE_KIOSK_PLATFORM,
            mastersos_bundle::FEATURE_KIOSK_INJECT,
        ];
        assert!(SUPPORTED_FEATURES.iter().all(|f| all.contains(f)));
    }

    /// 计划 9 Task 6：锁定应用由 kiosk 步骤解析并应用、由 `mastersos-kiosk` 在会话里起，这一版起报告认得 `kiosk`。
    #[test]
    fn supported_features_lists_kiosk() {
        assert!(SUPPORTED_FEATURES.contains(&mastersos_bundle::FEATURE_KIOSK));
    }

    /// Config profiles design §5 step 1: this agent reads the new shape and the learning/full modes.
    #[test]
    fn supported_features_include_config() {
        assert!(SUPPORTED_FEATURES.contains(&mastersos_bundle::FEATURE_CONFIG));
    }

    /// Wi-Fi and seeds design §4.5: this agent writes every network kind and the school's list.
    #[test]
    fn supported_features_include_wifi_ext() {
        assert!(SUPPORTED_FEATURES.contains(&mastersos_bundle::FEATURE_WIFI_EXT));
    }

    /// Remote diagnostics and help design: this agent reads `[config.support]`.
    #[test]
    fn supported_features_include_support() {
        assert!(SUPPORTED_FEATURES.contains(&mastersos_bundle::FEATURE_SUPPORT));
    }

    /// Defaults and IT account design §15: this agent reads every `format = 2` construct.
    #[test]
    fn supported_features_include_format_2() {
        assert!(SUPPORTED_FEATURES.contains(&mastersos_bundle::FEATURE_FORMAT_2));
        assert_eq!(
            mastersos_bundle::format_feature(mastersos_bundle::MAX_FORMAT),
            mastersos_bundle::FEATURE_FORMAT_2
        );
    }

    #[test]
    fn build_carries_heartbeat_state() {
        let now = Utc::now();
        let f = Freshness {
            last_fetch_ok: Some(now),
            accepted_at: Some(now - Duration::days(8)),
            fresh_until: Some(now + Duration::days(1)),
            newer_withheld: Some(5),
        };
        let r = build(&machine(), &placement(), &f, vec![], now);
        assert!(!r.stale);
        assert_eq!(r.newer_withheld, Some(5));
        let until = r.fresh_until.unwrap();
        assert!(until.ends_with('Z'), "{until}");
        assert_eq!(
            DateTime::parse_from_rfc3339(&until).unwrap().timestamp(),
            (now + Duration::days(1)).timestamp()
        );
    }

    /// 计划 1 的规则（还没有 accepted_at）：只看多久没拉取成功。
    #[test]
    fn stale_after_seven_days_without_fetch() {
        let now = Utc::now();
        assert!(!is_stale(None, None, None, now));
        assert!(!is_stale(Some(now - Duration::days(6)), None, None, now));
        assert!(is_stale(Some(now - Duration::days(8)), None, None, now));
        let r = build(
            &machine(),
            &placement(),
            &fetched(now - Duration::days(8)),
            vec![],
            now,
        );
        assert!(r.stale);
    }

    /// spec §4.2 的已知限制：服务端一直说「没有新版本」不算设置新的证据。
    #[test]
    fn stale_uses_accept_time_not_fetch_time() {
        let now = Utc::now();
        assert!(is_stale(
            Some(now),
            Some(now - Duration::days(8)),
            None,
            now
        ));
        // 刚接受 6 天、一直联系得上：不过期。
        assert!(!is_stale(
            Some(now),
            Some(now - Duration::days(6)),
            None,
            now
        ));
        // 一直联系不上 8 天，哪怕 accepted_at 很近也过期。
        assert!(is_stale(
            Some(now - Duration::days(8)),
            Some(now - Duration::days(1)),
            None,
            now
        ));
    }

    #[test]
    fn heartbeat_extends_freshness() {
        let now = Utc::now();
        assert!(!is_stale(
            Some(now),
            Some(now - Duration::days(8)),
            Some(now + Duration::days(1)),
            now
        ));
        // 心跳到期了：过期。
        assert!(is_stale(
            Some(now),
            Some(now - Duration::days(30)),
            Some(now - Duration::seconds(1)),
            now
        ));
        // 心跳比 accepted_at + 7 天还早：不会把它往前拉。
        assert!(!is_stale(
            Some(now),
            Some(now - Duration::days(1)),
            Some(now - Duration::days(5)),
            now
        ));
    }

    #[test]
    fn stale_when_no_contact_despite_heartbeat() {
        let now = Utc::now();
        assert!(is_stale(
            Some(now - Duration::days(8)),
            Some(now - Duration::days(8)),
            Some(now + Duration::days(20)),
            now
        ));
    }

    #[test]
    fn long_details_are_trimmed_to_fit_body_limit() {
        let big = "行".repeat(10_000);
        let results: Vec<ItemResult> = (0..300)
            .map(|i| ItemResult {
                item: format!("scripts/{i}.sh"),
                ok: false,
                detail: Some(big.clone()),
            })
            .collect();
        let now = Utc::now();
        let r = build(
            &machine(),
            &placement(),
            &Freshness::default(),
            results,
            now,
        );
        assert_eq!(r.results.len(), MAX_RESULTS);
        assert!(r.results[0].detail.as_ref().unwrap().len() <= MAX_DETAIL_BYTES + 3);
        assert!(r.results[199].detail.is_none());
        assert!(serde_json::to_vec(&r).unwrap().len() < 64 * 1024);
    }

    #[test]
    fn latest_report_is_kept_privately() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        assert!(load_last(d.path(), 1 << 20).is_none());
        let r = build(
            &machine(),
            &placement(),
            &Freshness::default(),
            vec![],
            Utc::now(),
        );
        save_last(d.path(), &r);
        assert_eq!(load_last(d.path(), 1 << 20), Some(r));
        let mode = std::fs::metadata(d.path().join(LAST_REPORT_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(load_last(d.path(), 10).is_none(), "over the cap");
    }
}
