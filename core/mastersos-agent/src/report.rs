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
pub const SUPPORTED_FEATURES: &[&str] = &[
    mastersos_bundle::FEATURE_UPDATE_MIRROR,
    mastersos_bundle::FEATURE_ESCROW_RECIPIENTS,
    mastersos_bundle::FEATURE_SCHOOL_ID,
    mastersos_bundle::FEATURE_KIOSK,
    mastersos_bundle::FEATURE_CONFIG,
    mastersos_bundle::FEATURE_WIFI_EXT,
    mastersos_bundle::FEATURE_OIDC_CARD,
    mastersos_bundle::FEATURE_FORMAT_2,
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
    }
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
                "format_2"
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
}
