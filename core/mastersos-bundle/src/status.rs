//! agent 每次拉取后回报给服务器的状态（spec §6.6）。
//! 不含用户名、邮箱、浏览记录、文件名或位置——只有机器与设置本身的事实。

use serde::{Deserialize, Serialize};

use crate::select::GroupSource;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ItemResult {
    pub item: String,
    pub ok: bool,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StatusReport {
    pub device_id: String,
    pub serial: Option<String>,
    pub model: Option<String>,
    pub os_version: Option<String>,
    pub agent_version: String,
    pub bundle_version: Option<u64>,
    pub group: String,
    pub group_source: GroupSource,
    pub locked: bool,
    pub stale: bool,
    pub last_fetch_ok: Option<String>,
    pub results: Vec<ItemResult>,
    /// 签名心跳说明设置一直到这个时刻都是最新的（RFC 3339）；没有采信过心跳时为空。
    #[serde(default)]
    pub fresh_until: Option<String>,
    /// 验过签名的心跳说有这一版，而立即再拉一次仍拿不到：更新可能被扣住了。
    #[serde(default)]
    pub newer_withheld: Option<u64>,
    /// 这台机器的状态是从种子分区导入的（新装或恢复出厂，计划 4a Ruling 10）：导入时种子里每把
    /// trust 钥匙的指纹（与 `mastersos-sign seed-check` 同一算法，`trust_fingerprint`）。服务端可以拿它
    /// 与自己发出的 trust 对照，发现被离线改过的种子分区。没有导入过时为空。
    #[serde(default)]
    pub seed_trust_fingerprints: Vec<String>,
    /// 从种子分区导入的时刻（RFC 3339）。
    #[serde(default)]
    pub imported_from_seed_at: Option<String>,
    /// The manifest keys added after machines were in the field (such as update_mirror) that this
    /// machine's agent understands. An agent too old to send this field understands none of them.
    /// At most 32 entries, each 1 to 64 bytes; the server refuses a report with more.
    #[serde(default)]
    pub manifest_features: Vec<String>,
}

/// `StatusReport::manifest_features` has at most this many entries.
pub const MAX_MANIFEST_FEATURES: usize = 32;
/// Each entry of `StatusReport::manifest_features` is at most this many bytes.
pub const MAX_MANIFEST_FEATURE_LEN: usize = 64;

impl StatusReport {
    /// Whether `manifest_features` is within its limits: at most [`MAX_MANIFEST_FEATURES`]
    /// entries, each 1..=[`MAX_MANIFEST_FEATURE_LEN`] bytes.
    pub fn check_manifest_features(&self) -> Result<(), String> {
        if self.manifest_features.len() > MAX_MANIFEST_FEATURES {
            return Err(format!(
                "manifest_features has {} entries, at most {MAX_MANIFEST_FEATURES}",
                self.manifest_features.len()
            ));
        }
        if self
            .manifest_features
            .iter()
            .any(|f| f.is_empty() || f.len() > MAX_MANIFEST_FEATURE_LEN)
        {
            return Err(format!(
                "every manifest_features entry is 1 to {MAX_MANIFEST_FEATURE_LEN} bytes"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> StatusReport {
        StatusReport {
            device_id: "dev-1".into(),
            serial: Some("ABC".into()),
            model: Some("Chromebook 11".into()),
            os_version: Some("1.0".into()),
            agent_version: "0.1.0".into(),
            bundle_version: Some(42),
            group: "teacher".into(),
            group_source: GroupSource::Seed,
            locked: false,
            stale: true,
            last_fetch_ok: Some("2026-10-10T07:00:00Z".into()),
            results: vec![ItemResult {
                item: "wifi".into(),
                ok: false,
                detail: Some("失败".into()),
            }],
            fresh_until: Some("2026-10-20T07:00:00Z".into()),
            newer_withheld: Some(43),
            seed_trust_fingerprints: vec!["f5a3-7e83-ee45-c6cc".into()],
            imported_from_seed_at: Some("2026-10-13T08:09:47Z".into()),
            manifest_features: vec!["update_mirror".into()],
        }
    }

    #[test]
    fn status_report_has_no_user_fields() {
        let v = serde_json::to_value(report()).unwrap();
        let mut keys = Vec::new();
        fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
            match v {
                serde_json::Value::Object(m) => {
                    for (k, v) in m {
                        out.push(k.clone());
                        walk(v, out);
                    }
                }
                serde_json::Value::Array(a) => a.iter().for_each(|v| walk(v, out)),
                _ => {}
            }
        }
        walk(&v, &mut keys);
        for banned in ["user", "username", "email"] {
            assert!(!keys.iter().any(|k| k == banned), "出现了 {banned}");
        }
        assert_eq!(v["group_source"], "seed");
    }

    #[test]
    fn status_report_json_roundtrip() {
        let r = report();
        let back: StatusReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }

    /// 旧版 agent 的回报没有心跳的两个字段：照样能读，读成 None。
    #[test]
    fn old_report_without_heartbeat_fields_parses() {
        let mut v = serde_json::to_value(report()).unwrap();
        let m = v.as_object_mut().unwrap();
        m.remove("fresh_until");
        m.remove("newer_withheld");
        m.remove("seed_trust_fingerprints");
        m.remove("imported_from_seed_at");
        let back: StatusReport = serde_json::from_value(v).unwrap();
        assert_eq!(back.fresh_until, None);
        assert_eq!(back.newer_withheld, None);
        assert!(back.seed_trust_fingerprints.is_empty());
        assert_eq!(back.imported_from_seed_at, None);
    }

    /// An agent that predates `manifest_features` sends none: it understands no later-added key.
    #[test]
    fn status_report_manifest_features_default_empty() {
        let mut v = serde_json::to_value(report()).unwrap();
        assert_eq!(v["manifest_features"], serde_json::json!(["update_mirror"]));
        v.as_object_mut().unwrap().remove("manifest_features");
        let back: StatusReport = serde_json::from_value(v).unwrap();
        assert!(back.manifest_features.is_empty());
        back.check_manifest_features().unwrap();
    }

    #[test]
    fn manifest_features_limits() {
        let mut r = report();
        r.manifest_features = (0..MAX_MANIFEST_FEATURES)
            .map(|i| format!("f{i}"))
            .collect();
        r.check_manifest_features().unwrap();
        r.manifest_features.push("one-more".into());
        assert!(r.check_manifest_features().is_err());
        r.manifest_features = vec!["x".repeat(MAX_MANIFEST_FEATURE_LEN)];
        r.check_manifest_features().unwrap();
        r.manifest_features = vec!["x".repeat(MAX_MANIFEST_FEATURE_LEN + 1)];
        assert!(r.check_manifest_features().is_err());
        r.manifest_features = vec![String::new()];
        assert!(r.check_manifest_features().is_err());
    }
}
