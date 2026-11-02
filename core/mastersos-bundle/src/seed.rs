//! 种子：刷机时写进镜像的第一份信任与服务器地址（spec §4）。

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::manifest::{BundleError, ItAccount, Oidc, TrustKey, Wifi};

/// The largest seed file the installer reads, in bytes; the server refuses to serve a larger one.
pub const MAX_SEED_BYTES: usize = 64 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seed {
    pub server_url: String,
    pub trust: Vec<TrustKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetch_token: Option<String>,
    /// The initial Group, written only by older seed downloads (config profiles design §6): the
    /// cloud now writes school-level seeds without it, and Devices still honour it when present
    /// and the Group exists (`select`), else they use `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<Oidc>,
    /// 新机器接受的第一个包的版本下限（含）：防止被攻破的服务端给还没接受过任何包的
    /// 机器回放一个旧的、`trust` 里还有已撤销钥匙的真包。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_version: Option<u64>,
    /// The school this machine belongs to (plan 6 Task 10b): the machine accepts only bundles
    /// whose `[school] id` is this ([`crate::check_school`]). The cloud server always writes it;
    /// a seed without it (written before plan 6) accepts bundles as before.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::manifest::school_id_opt"
    )]
    pub school_id: Option<String>,
    /// The Wi-Fi networks of the seed's Group as expanded in the latest published Version
    /// (`[defaults]`, the legacy `[[school.wifi]]` and the Config's, design 2026-10-30 §11), the
    /// same shape as in the settings: the Device joins them before it has any settings. [`Seed::validate`] checks each entry ([`crate::checks::wifi`], no SSID twice);
    /// [`Seed::parse`] does not.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wifi: Vec<Wifi>,
    /// The school's display name, shown only by the installer (seed list and confirmation screen);
    /// absent: the installer shows the server address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub school_name: Option<String>,
    /// The IT maintenance account of the seed's Group as expanded in the latest published
    /// Version, so that the Device creates it at the first boot, before any settings arrive.
    /// [`Seed::validate`] checks the hash ([`crate::checks::it_password_hash`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub it_account: Option<ItAccount>,
}

/// `fetch_token` is a credential: always redacted in debug output, so no log line carries it
/// (the Wi-Fi secrets and the IT password hash are redacted by their own `Debug`).
impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Seed")
            .field("server_url", &self.server_url)
            .field("trust", &self.trust)
            .field(
                "fetch_token",
                &self.fetch_token.as_ref().map(|_| "<redacted>"),
            )
            .field("group", &self.group)
            .field("oidc", &self.oidc)
            .field("min_version", &self.min_version)
            .field("school_id", &self.school_id)
            .field("wifi", &self.wifi)
            .field("school_name", &self.school_name)
            .field("it_account", &self.it_account)
            .finish()
    }
}

impl Seed {
    /// Parse a seed. A cloud seed — one naming its school (`school_id`, plan 6) — must carry a
    /// non-blank `fetch_token` (Task 2 review M3): without one the machine could never fetch. A
    /// seed written before plan 6 names no school and may lack the token (lab seeds; it still
    /// parses, as Task 10b kept them working).
    pub fn parse(text: &str) -> Result<Seed, BundleError> {
        let seed: Seed = toml::from_str(text).map_err(|e| BundleError::Parse(e.to_string()))?;
        if seed.school_id.is_some()
            && seed
                .fetch_token
                .as_deref()
                .is_none_or(|t| t.trim().is_empty())
        {
            return Err(BundleError::Invalid(
                "the seed names its school (school_id) but has no fetch_token: a cloud seed must \
                 carry the school's fetch_token; download the seed again from the admin page"
                    .into(),
            ));
        }
        Ok(seed)
    }

    /// The strict checks [`Seed::parse`] leaves out on purpose (like [`crate::checks`] stays out
    /// of manifest parsing): each Wi-Fi entry passes [`crate::checks::wifi`] and no SSID appears
    /// twice. The installer (an invalid seed in its menu), the server before serving a seed and
    /// `mastersos-sign seed-check` call it; an installed agent never does, so a later rule change
    /// cannot stop a machine from starting — its wifi step skips bad entries one at a time.
    /// Messages name the entry and its SSID, never a secret.
    pub fn validate(&self) -> Result<(), BundleError> {
        for (i, w) in self.wifi.iter().enumerate() {
            if let Err(e) = crate::checks::wifi(w) {
                return Err(BundleError::Invalid(format!("seed wifi[{i}]: {e}")));
            }
            if self.wifi[..i].iter().any(|o| o.ssid == w.ssid) {
                return Err(BundleError::Invalid(format!(
                    "seed wifi[{i}]: Wi-Fi name {:?} appears more than once; download the seed again from the admin page",
                    w.ssid
                )));
            }
        }
        if let Some(Err(e)) = self
            .it_account
            .as_ref()
            .map(|a| crate::checks::it_password_hash(&a.password_hash))
        {
            return Err(BundleError::Invalid(format!("seed it_account: {e}")));
        }
        Ok(())
    }

    pub fn to_toml(&self) -> String {
        toml::to_string(self).expect("Seed 只含字符串与表，必能序列化为 TOML")
    }

    /// 同 [`Seed::to_toml`]，开头加注释：每把 trust 钥匙一行 `# <id>  <alg>  <指纹>`，
    /// 再加一行提示去和管理网页上的指纹对照。种子是新机器的信任锚，IT 装机前要核对。
    pub fn to_toml_with_header(&self) -> String {
        let mut out = String::new();
        for k in &self.trust {
            // 注释只到行尾；id 里的换行会让后半截变成 TOML 正文。
            let id = k.id.replace(['\r', '\n'], " ");
            out.push_str(&format!(
                "# {id}  {}  {}\n",
                k.alg.as_str(),
                trust_fingerprint(k)
            ));
        }
        out.push_str("# 请与管理网页「钥匙」页上的指纹对照\n\n");
        out.push_str(&self.to_toml());
        out
    }
}

/// 钥匙指纹：`sha256(解码后的公钥字节)` 的前 16 位小写十六进制，每 4 位一组用 `-` 连接
/// （`xxxx-xxxx-xxxx-xxxx`）。服务端、`mastersos-sign`、网页都显示这一种格式。
/// 公钥不是合法 base64 时改为对原文取摘要：仍是确定的值，且不会与任何真钥匙相同。
pub fn trust_fingerprint(k: &TrustKey) -> String {
    let digest = match STANDARD.decode(&k.public_key) {
        Ok(raw) => Sha256::digest(&raw),
        Err(_) => Sha256::digest(k.public_key.as_bytes()),
    };
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("十六进制是 ASCII"))
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::KeyAlg;

    const SCHOOL: &str = "0192f3a4-5b6c-7d8e-9f00-112233445566";

    fn key() -> TrustKey {
        TrustKey {
            id: "school-2026".into(),
            alg: KeyAlg::Ed25519,
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            rp_id: None,
        }
    }

    #[test]
    fn seed_roundtrip() {
        let full = Seed {
            server_url: "https://mastersos.school.ac.th".into(),
            trust: vec![key()],
            fetch_token: Some("tok".into()),
            group: Some("teacher".into()),
            oidc: Some(Oidc {
                issuer: "https://sso.school.ac.th".into(),
                client_id: "mastersos".into(),
                ..Oidc::default()
            }),
            min_version: Some(7),
            school_id: Some(SCHOOL.into()),
            wifi: vec![],
            school_name: None,
            it_account: None,
        };
        assert_eq!(Seed::parse(&full.to_toml()).unwrap(), full);

        let minimal = Seed {
            fetch_token: None,
            group: None,
            oidc: None,
            min_version: None,
            school_id: None,
            ..full
        };
        assert_eq!(Seed::parse(&minimal.to_toml()).unwrap(), minimal);
    }

    #[test]
    fn debug_redacts_fetch_token() {
        let seed = Seed {
            server_url: "https://mastersos.school.ac.th".into(),
            trust: vec![key()],
            fetch_token: Some("s3cret-token".into()),
            group: None,
            oidc: None,
            min_version: None,
            school_id: None,
            wifi: vec![],
            school_name: None,
            it_account: None,
        };
        let out = format!("{seed:?} {seed:#?}");
        assert!(!out.contains("s3cret-token"));
        assert!(out.contains("<redacted>"));
        assert!(out.contains("https://mastersos.school.ac.th"));
    }

    #[test]
    fn seed_rejects_garbage_and_unknown_fields() {
        assert!(matches!(Seed::parse("nope"), Err(BundleError::Parse(_))));
        let text = format!(
            "{}\nbogus = 1\n",
            Seed {
                server_url: "u".into(),
                trust: vec![],
                fetch_token: None,
                group: None,
                oidc: None,
                min_version: None,
                school_id: None,
                wifi: vec![],
                school_name: None,
                it_account: None,
            }
            .to_toml()
        );
        assert!(matches!(Seed::parse(&text), Err(BundleError::Parse(_))));
    }

    #[test]
    fn fingerprint_format() {
        let fp = trust_fingerprint(&key());
        // 32 字节全 0 的 sha256 以 66687aad 开头。
        let raw = STANDARD.decode(&key().public_key).unwrap();
        let hex: String = Sha256::digest(&raw)[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(fp.len(), 19);
        let parts: Vec<_> = fp.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert!(parts.iter().all(|p| p.len() == 4
            && p.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))));
        assert_eq!(parts.concat(), hex);
        // 不同公钥不同指纹。
        let mut other = key();
        other.public_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into();
        assert_ne!(trust_fingerprint(&other), fp);
    }

    /// 固定向量：网页（web/src/lib/fingerprint.test.ts）用同样的两组输入，值必须一致。
    #[test]
    fn fingerprint_fixed_vectors() {
        let mut k = key();
        k.public_key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".into();
        assert_eq!(trust_fingerprint(&k), "630d-cd29-66c4-3366");
        // 不是合法 base64：对原文取摘要。
        k.public_key = "not base64!".into();
        assert_eq!(trust_fingerprint(&k), "f17f-1486-250c-2a7f");
    }

    #[test]
    fn seed_min_version_roundtrip() {
        let mut seed = Seed {
            server_url: "u".into(),
            trust: vec![key()],
            fetch_token: None,
            group: None,
            oidc: None,
            min_version: Some(3),
            school_id: None,
            wifi: vec![],
            school_name: None,
            it_account: None,
        };
        let text = seed.to_toml();
        assert!(text.contains("min_version = 3"));
        assert_eq!(Seed::parse(&text).unwrap(), seed);
        // 带头注释的写法同样能读回来，头里有指纹与对照提示。
        let with_header = seed.to_toml_with_header();
        assert!(with_header.starts_with(&format!(
            "# school-2026  ed25519  {}\n",
            trust_fingerprint(&key())
        )));
        assert!(with_header.contains("# 请与管理网页「钥匙」页上的指纹对照\n"));
        assert_eq!(Seed::parse(&with_header).unwrap(), seed);
        // 不写 min_version 就没有这个键。
        seed.min_version = None;
        assert!(!seed.to_toml().contains("min_version"));
    }

    /// Plan 6 Task 10b: the seed names its school; only a lowercase UUID is accepted.
    #[test]
    fn seed_school_id_roundtrip_and_format() {
        let mut seed = Seed {
            server_url: "u".into(),
            trust: vec![key()],
            fetch_token: Some("tok".into()),
            group: None,
            oidc: None,
            min_version: None,
            school_id: Some(SCHOOL.into()),
            wifi: vec![],
            school_name: None,
            it_account: None,
        };
        let text = seed.to_toml();
        assert!(
            text.contains(&format!("school_id = \"{SCHOOL}\"")),
            "{text}"
        );
        assert_eq!(Seed::parse(&text).unwrap(), seed);
        assert!(format!("{seed:?}").contains(SCHOOL));
        for bad in [
            "",
            "school-a",
            "0192F3A4-5B6C-7D8E-9F00-112233445566",
            "0192f3a45b6c7d8e9f00112233445566",
            "{0192f3a4-5b6c-7d8e-9f00-112233445566}",
            "0192f3a4-5b6c-7d8e-9f00-11223344556",
        ] {
            let text = text.replace(SCHOOL, bad);
            assert!(
                matches!(Seed::parse(&text), Err(BundleError::Parse(_))),
                "{bad:?}"
            );
        }
        seed.school_id = None;
        assert!(!seed.to_toml().contains("school_id"));
    }

    /// Task 2 review M3 (plan 6 Task 24b): a cloud seed (one naming its school) must carry the
    /// fetch_token — without it the machine could never fetch. A seed written before plan 6 names
    /// no school and may lack the token (lab seeds; Task 10b kept them working): it still parses.
    #[test]
    fn cloud_seed_requires_fetch_token() {
        let cloud = Seed {
            server_url: "https://alpha.os.khundavid.com".into(),
            trust: vec![key()],
            fetch_token: None,
            group: None,
            oidc: None,
            min_version: Some(3),
            school_id: Some(SCHOOL.into()),
            wifi: vec![],
            school_name: None,
            it_account: None,
        };
        for token in [None, Some(""), Some("  ")] {
            let mut s = cloud.clone();
            s.fetch_token = token.map(String::from);
            match Seed::parse(&s.to_toml()) {
                Err(BundleError::Invalid(m)) => {
                    assert!(m.contains("fetch_token") && m.contains("school_id"), "{m}")
                }
                other => panic!("{token:?}: wanted Invalid, got {other:?}"),
            }
        }
        let with = Seed {
            fetch_token: Some("tok".into()),
            ..cloud.clone()
        };
        assert_eq!(Seed::parse(&with.to_toml()).unwrap(), with);
        // A pre-6 lab seed: no school, no token.
        let lab = Seed {
            school_id: None,
            ..cloud
        };
        assert_eq!(Seed::parse(&lab.to_toml()).unwrap(), lab);
    }

    fn wifi(toml_text: &str) -> Wifi {
        toml::from_str(toml_text).unwrap()
    }

    #[test]
    fn seed_roundtrips_wifi_and_school_name() {
        let mut seed = Seed {
            server_url: "https://eis.os.khundavid.com".into(),
            trust: vec![key()],
            fetch_token: Some("tok".into()),
            group: None,
            oidc: None,
            min_version: Some(3),
            school_id: Some(SCHOOL.into()),
            wifi: vec![],
            school_name: None,
            it_account: None,
        };
        let text = seed.to_toml_with_header();
        assert!(
            !text.contains("wifi") && !text.contains("school_name"),
            "{text}"
        );
        assert_eq!(Seed::parse(&text).unwrap(), seed);
        seed.wifi = vec![
            wifi("ssid = \"EIS-Students\"\npsk = \"correct horse battery\""),
            wifi("ssid = \"EIS-Guest\"\nopen = true\nhidden = true"),
            wifi(
                "ssid = \"EIS-Staff\"\neap = \"peap\"\nidentity = \"d@eis\"\npassword = \"pw\"\n\
                 server_domain = \"radius.eis\"",
            ),
        ];
        seed.school_name = Some("Example International School".into());
        let text = seed.to_toml_with_header();
        assert!(text.contains("[[wifi]]"), "{text}");
        seed.validate().unwrap();
        assert!(
            text.contains("school_name = \"Example International School\""),
            "{text}"
        );
        assert_eq!(Seed::parse(&text).unwrap(), seed);
        // Debug shows the networks but not their passwords.
        let dbg = format!("{seed:?}");
        assert!(
            dbg.contains("EIS-Staff") && !dbg.contains("correct horse"),
            "{dbg}"
        );
    }

    #[test]
    fn seed_rejects_bad_wifi_without_echoing_secret() {
        let base = Seed {
            server_url: "u".into(),
            trust: vec![key()],
            fetch_token: None,
            group: None,
            oidc: None,
            min_version: None,
            school_id: None,
            wifi: vec![],
            school_name: None,
            it_account: None,
        };
        let bad = [
            wifi("ssid = \"A\"\npsk = \"SHORT-X\"\nopen = true"),
            wifi("ssid = \"A\"\npsk = \"SECRET!\""),
            wifi("ssid = \"A\"\neap = \"peap\"\nidentity = \"i\"\npassword = \"PW-SECRET\""),
        ];
        for w in bad {
            let s = Seed {
                wifi: vec![w.clone()],
                ..base.clone()
            };
            // Parsing stays lenient (an installed agent must start whatever the rules become);
            // validate() refuses.
            let parsed = Seed::parse(&s.to_toml()).expect("parse is lenient about Wi-Fi");
            assert_eq!(parsed, s);
            match parsed.validate() {
                Err(BundleError::Invalid(m)) => {
                    assert!(m.contains("\"A\""), "{m}");
                    for secret in [&w.psk, &w.password].into_iter().flatten() {
                        assert!(!m.contains(secret.as_str()), "{m}");
                    }
                }
                other => panic!("{w:?}: wanted Invalid, got {other:?}"),
            }
        }
        // The same SSID twice.
        let s = Seed {
            wifi: vec![
                wifi("ssid = \"A\"\npsk = \"password-one\""),
                wifi("ssid = \"A\"\npsk = \"password-two\""),
            ],
            ..base.clone()
        };
        let parsed = Seed::parse(&s.to_toml()).expect("parse is lenient about duplicates");
        match parsed.validate() {
            Err(BundleError::Invalid(m)) => {
                assert!(
                    m.contains("more than once") && !m.contains("password-"),
                    "{m}"
                )
            }
            other => panic!("wanted Invalid, got {other:?}"),
        }
    }

    #[test]
    fn seed_roundtrips_it_account_and_redacts() {
        let hash = "$y$j9T$saltsaltsalt$0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef./";
        let mut seed = Seed {
            server_url: "https://eis.os.khundavid.com".into(),
            trust: vec![key()],
            fetch_token: Some("tok".into()),
            group: Some("staff".into()),
            oidc: None,
            min_version: Some(3),
            school_id: Some(SCHOOL.into()),
            wifi: vec![],
            school_name: None,
            it_account: None,
        };
        assert!(!seed.to_toml().contains("it_account"));
        seed.it_account = Some(ItAccount {
            password_hash: hash.into(),
        });
        let text = seed.to_toml_with_header();
        assert!(text.contains("[it_account]"), "{text}");
        assert_eq!(Seed::parse(&text).unwrap(), seed);
        seed.validate().unwrap();
        let dbg = format!("{seed:?} {seed:#?}");
        assert!(!dbg.contains(hash) && dbg.contains("<redacted>"), "{dbg}");
        seed.it_account = Some(ItAccount {
            password_hash: "$6$x".into(),
        });
        match seed.validate() {
            Err(BundleError::Invalid(m)) => assert!(!m.contains("$6$x"), "{m}"),
            other => panic!("wanted Invalid, got {other:?}"),
        }
    }
}
