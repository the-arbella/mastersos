//! 签名心跳（Ruling 11、C3）：对「最新版仍是第 version 版、内容摘要是 X，在 not_after 之前都算数」
//! 的签名。机器靠它分辨「真的没有新设置」和「有人扣住了更新」。
//!
//! 消息：`b"mastersos-heartbeat-v1\n" || version(u64 大端) || 摘要(32 字节) || issued_at(i64 大端)
//! || not_after(i64 大端)`，时间都是 Unix 秒。前缀与设置包（`mastersos-bundle-v1\n`）、登记探针
//! （`mastersos-keyprobe-v1\n`）在第 8 个字节就不同，且都以唯一的 `\n` 结尾，谁也不是谁的前缀：
//! 一种用途的签名顶替不了另一种。
//!
//! 有效期写在签名内容里：`not_after <= issued_at` 或长于 [`MAX_HEARTBEAT_DAYS`] 天的心跳
//! 一律不收。这只看签名内容、不看机器时钟，所以 IT 被骗签下一个 2099 年到期的心跳，也不会让
//! 被攻破的服务端拿它无限续命。「`issued_at` 不晚于本机时间 1 天」由 agent 自己按时钟判断。
//!
//! 文件格式（TOML，服务端的 `/v1/heartbeat` 原样给）：
//!
//! ```toml
//! [statement]
//! version = 3
//! digest_hex = "…64 位小写十六进制…"
//! issued_at = 1791000000
//! not_after = 1793592000
//!
//! [signature]
//! key_id = "rk-…"
//! alg = "ed25519"
//! sig = "…"
//! ```

use serde::{Deserialize, Serialize};

use crate::{verify_signature, BundleError, SignatureFile, TrustKey};

/// 心跳所签消息的前缀。
const HEARTBEAT_PREFIX: &[u8] = b"mastersos-heartbeat-v1\n";

/// 心跳的有效期（`not_after - issued_at`）最长这么多天。
pub const MAX_HEARTBEAT_DAYS: i64 = 31;

/// 这么多天既没有拉取成功、也没有签名证据说明设置是最新的，机器就算「设置可能过期」。
/// agent 判断过期、服务端算概览里的到期时间都用它。
pub const STALE_WARN_DAYS: i64 = 7;

const DAY_SECS: i64 = 86_400;

/// 心跳声明的内容。时间都是 Unix 秒。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct HeartbeatStatement {
    /// 最新已发布的版本号。
    pub version: u64,
    /// 这一版的 `content_digest`，64 位小写十六进制。
    pub digest_hex: String,
    /// 签发时刻（Unix 秒）。
    pub issued_at: i64,
    /// 到期时刻（Unix 秒）；`issued_at < not_after <= issued_at + 31 天`。
    pub not_after: i64,
}

impl HeartbeatStatement {
    /// 只看内容本身的检查（不验签、不看时钟）：摘要是 64 位小写十六进制；
    /// `issued_at < not_after`，且有效期不超过 [`MAX_HEARTBEAT_DAYS`] 天。不满足 → `Invalid`。
    pub fn check(&self) -> Result<(), BundleError> {
        if decode_digest(&self.digest_hex).is_none() {
            return Err(BundleError::Invalid(
                "The heartbeat digest is not 64 lowercase hex digits".into(),
            ));
        }
        // 用 i128 相减：两个极端的 i64 相减会溢出。
        let span = i128::from(self.not_after) - i128::from(self.issued_at);
        if span <= 0 {
            return Err(BundleError::Invalid(
                "The heartbeat expiry is not after its issue time".into(),
            ));
        }
        if span > i128::from(MAX_HEARTBEAT_DAYS * DAY_SECS) {
            return Err(BundleError::Invalid(format!(
                "The heartbeat validity exceeds {MAX_HEARTBEAT_DAYS} days"
            )));
        }
        Ok(())
    }

    /// 有效期的整天数；不是整天时返回 `None`。
    pub fn days(&self) -> Option<i64> {
        let span = self.not_after.checked_sub(self.issued_at)?;
        (span > 0 && span % DAY_SECS == 0).then_some(span / DAY_SECS)
    }
}

/// 64 位小写十六进制 → 32 字节；其余一律 `None`（大写也不收，免得同一份摘要有两种写法）。
fn decode_digest(hex: &str) -> Option<[u8; 32]> {
    let b = hex.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, pair) in b.chunks(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

/// 心跳所签的消息（格式见模块文档）。
///
/// # Panics
///
/// `digest_hex` 不是 64 位小写十六进制时。外来的声明先过 [`HeartbeatStatement::check`]
/// （[`verify_statement`]、[`verify_heartbeat`] 都先查）；自己构造的声明摘要来自
/// `content_digest`，必然合法。
pub fn heartbeat_message(s: &HeartbeatStatement) -> Vec<u8> {
    let digest = decode_digest(&s.digest_hex)
        .expect("心跳的摘要必须是 64 位小写十六进制：外来的声明先调 check");
    let mut msg = Vec::with_capacity(HEARTBEAT_PREFIX.len() + 8 + 32 + 8 + 8);
    msg.extend_from_slice(HEARTBEAT_PREFIX);
    msg.extend_from_slice(&s.version.to_be_bytes());
    msg.extend_from_slice(&digest);
    msg.extend_from_slice(&s.issued_at.to_be_bytes());
    msg.extend_from_slice(&s.not_after.to_be_bytes());
    msg
}

/// 一份签过名的心跳。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    pub statement: HeartbeatStatement,
    pub signature: SignatureFile,
}

impl Heartbeat {
    pub fn to_toml(&self) -> String {
        toml::to_string(self).expect("心跳只含整数与字符串，必能序列化为 TOML")
    }

    pub fn parse(text: &str) -> Result<Heartbeat, BundleError> {
        toml::from_str(text)
            .map_err(|e| BundleError::Parse(format!("Cannot parse the heartbeat: {e}")))
    }
}

/// 先 [`HeartbeatStatement::check`]，再用 `trust` 验 `sig` 是不是对这份声明的签名，
/// 返回签名所用的钥匙。
pub fn verify_statement<'a>(
    s: &HeartbeatStatement,
    sig: &SignatureFile,
    trust: &'a [TrustKey],
) -> Result<&'a TrustKey, BundleError> {
    s.check()?;
    verify_signature(&heartbeat_message(s), sig, trust)
}

/// 解析心跳文件并验签，返回声明。有效期不合规（`not_after <= issued_at`、超过 31 天）
/// → `Invalid`。只看签名内容，不依赖时钟。
pub fn verify_heartbeat(text: &str, trust: &[TrustKey]) -> Result<HeartbeatStatement, BundleError> {
    let hb = Heartbeat::parse(text)?;
    verify_statement(&hb.statement, &hb.signature, trust)?;
    Ok(hb.statement)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    use super::*;
    use crate::keyid::keyprobe_message;
    use crate::testutil::FakePasskey;
    use crate::webauthn::{FLAG_UP, FLAG_UV};
    use crate::{
        accept, assemble, content_digest, pack, signed_message, Contents, Ed25519Signer, KeyAlg,
        Signer,
    };

    const UPUV: u8 = FLAG_UP | FLAG_UV;
    const T0: i64 = 1_790_000_000;

    fn signer(id: &str) -> Ed25519Signer {
        Ed25519Signer::from_pkcs8(id, &Ed25519Signer::generate_pkcs8()).unwrap()
    }

    fn ed_sig(s: &Ed25519Signer, msg: &[u8]) -> SignatureFile {
        SignatureFile {
            key_id: s.key_id().into(),
            alg: KeyAlg::Ed25519,
            sig: STANDARD.encode(Signer::sign(s, msg)),
            authenticator_data: None,
            client_data_json: None,
        }
    }

    fn contents(trust: &[TrustKey]) -> Contents {
        let mut text = "version = 3\n".to_string();
        for k in trust {
            text += &format!(
                "\n[[trust]]\nid = \"{}\"\nalg = \"{}\"\npublic_key = \"{}\"\n",
                k.id,
                k.alg.as_str(),
                k.public_key
            );
            if let Some(rp) = &k.rp_id {
                text += &format!("rp_id = \"{rp}\"\n");
            }
        }
        text += "\n[[group]]\nid = \"default\"\nname = \"未分组\"\n";
        let mut files = BTreeMap::new();
        files.insert("files/a.txt".to_string(), b"hello".to_vec());
        Contents {
            manifest_text: text,
            files,
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn statement(c: &Contents, days: i64) -> HeartbeatStatement {
        HeartbeatStatement {
            version: 3,
            digest_hex: hex(&content_digest(c)),
            issued_at: T0,
            not_after: T0 + days * DAY_SECS,
        }
    }

    fn toml_of(s: &HeartbeatStatement, sig: SignatureFile) -> String {
        Heartbeat {
            statement: s.clone(),
            signature: sig,
        }
        .to_toml()
    }

    #[test]
    fn heartbeat_roundtrip_ed25519_and_passkey() {
        let rk = signer("rk-1");
        let pk = FakePasskey::new("school.ac.th", "https://school.ac.th").with_key_id("pk-1");
        let trust = [rk.trust_key(), pk.trust_key("pk-1")];
        let s = statement(&contents(&trust), 30);

        let text = toml_of(&s, ed_sig(&rk, &heartbeat_message(&s)));
        assert!(
            text.contains("[statement]") && text.contains("[signature]"),
            "{text}"
        );
        assert_eq!(verify_heartbeat(&text, &trust).unwrap(), s);
        assert_eq!(Heartbeat::parse(&text).unwrap().to_toml(), text);

        let text = toml_of(&s, pk.sign(&heartbeat_message(&s), UPUV));
        assert_eq!(verify_heartbeat(&text, &trust).unwrap(), s);

        // 改了声明里的任何一项，签名都对不上。
        let edits: [fn(&mut HeartbeatStatement); 4] = [
            |s: &mut HeartbeatStatement| s.version += 1,
            |s: &mut HeartbeatStatement| s.issued_at -= 1,
            |s: &mut HeartbeatStatement| s.not_after += 1,
            |s: &mut HeartbeatStatement| s.digest_hex = "0".repeat(64),
        ];
        for edit in edits {
            let mut hb = Heartbeat::parse(&text).unwrap();
            edit(&mut hb.statement);
            assert_eq!(
                verify_heartbeat(&hb.to_toml(), &trust).unwrap_err(),
                BundleError::BadSignature
            );
        }
        // 不在 trust 里的钥匙。
        let stranger = signer("rk-1");
        let forged = toml_of(&s, ed_sig(&stranger, &heartbeat_message(&s)));
        assert_eq!(
            verify_heartbeat(&forged, &trust).unwrap_err(),
            BundleError::BadSignature
        );
        assert_eq!(
            verify_heartbeat(
                &toml_of(&s, ed_sig(&signer("x"), &heartbeat_message(&s))),
                &trust
            )
            .unwrap_err(),
            BundleError::UnknownKey("x".into())
        );
        // 多一个键、读不懂的文本 → Parse。
        assert!(matches!(
            verify_heartbeat(&format!("{text}\n[extra]\na = 1\n"), &trust),
            Err(BundleError::Parse(_))
        ));
        assert!(matches!(
            verify_heartbeat("not toml [", &trust),
            Err(BundleError::Parse(_))
        ));
    }

    #[test]
    fn message_layout() {
        let s = HeartbeatStatement {
            version: 0x0102_0304_0506_0708,
            digest_hex: "ab".repeat(32),
            issued_at: -2,
            not_after: 0x10,
        };
        let m = heartbeat_message(&s);
        assert_eq!(&m[..23], b"mastersos-heartbeat-v1\n");
        assert_eq!(&m[23..31], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&m[31..63], &[0xab; 32]);
        assert_eq!(&m[63..71], &(-2i64).to_be_bytes());
        assert_eq!(&m[71..79], &[0, 0, 0, 0, 0, 0, 0, 0x10]);
        assert_eq!(m.len(), 79);
    }

    #[test]
    fn heartbeat_longer_than_31_days_rejected_by_agent() {
        let rk = signer("rk-1");
        let trust = [rk.trust_key()];
        let c = contents(&trust);
        let signed = |s: &HeartbeatStatement| toml_of(s, ed_sig(&rk, &heartbeat_message(s)));

        verify_heartbeat(&signed(&statement(&c, 31)), &trust).unwrap();
        // 31 天零 1 秒、32 天、到期不晚于签发：签名再有效也不收。
        let mut s = statement(&c, 31);
        s.not_after += 1;
        assert!(matches!(
            verify_heartbeat(&signed(&s), &trust),
            Err(BundleError::Invalid(_))
        ));
        assert!(matches!(
            verify_heartbeat(&signed(&statement(&c, 32)), &trust),
            Err(BundleError::Invalid(_))
        ));
        let mut s = statement(&c, 1);
        s.not_after = s.issued_at;
        assert!(matches!(
            verify_heartbeat(&signed(&s), &trust),
            Err(BundleError::Invalid(_))
        ));
        s.not_after = s.issued_at - 1;
        assert!(matches!(
            verify_heartbeat(&signed(&s), &trust),
            Err(BundleError::Invalid(_))
        ));
        // 远期 not_after（2099 年）：只要跨度超过 31 天就不收。
        let mut s = statement(&c, 1);
        s.not_after = 4_070_908_800;
        assert!(matches!(
            verify_heartbeat(&signed(&s), &trust),
            Err(BundleError::Invalid(_))
        ));
        // 两个极端值相减不会溢出。
        let s = HeartbeatStatement {
            issued_at: i64::MIN,
            not_after: i64::MAX,
            ..statement(&c, 1)
        };
        assert!(matches!(s.check(), Err(BundleError::Invalid(_))));
    }

    #[test]
    fn bad_digest_rejected_before_signature() {
        let rk = signer("rk-1");
        let trust = [rk.trust_key()];
        let good = statement(&contents(&trust), 7);
        for bad in [
            "AB".repeat(32),
            "ab".repeat(31),
            "zz".repeat(32),
            String::new(),
        ] {
            let s = HeartbeatStatement {
                digest_hex: bad,
                ..good.clone()
            };
            // 签名随便放一个：check 在验签之前。
            let text = toml_of(&s, ed_sig(&rk, b"whatever"));
            assert!(matches!(
                verify_heartbeat(&text, &trust),
                Err(BundleError::Invalid(_))
            ));
        }
    }

    #[test]
    fn prefixes_are_distinct_and_not_prefixes_of_each_other() {
        let bundle = signed_message(&contents(&[]));
        let probe = keyprobe_message(&[]);
        let prefixes: [&[u8]; 3] = [HEARTBEAT_PREFIX, &bundle[..20], &probe];
        assert_eq!(prefixes[1], b"mastersos-bundle-v1\n");
        assert_eq!(prefixes[2], b"mastersos-keyprobe-v1\n");
        for (i, a) in prefixes.iter().enumerate() {
            for (j, b) in prefixes.iter().enumerate() {
                if i != j {
                    assert!(!a.starts_with(b), "{i} 以 {j} 开头");
                }
            }
        }
    }

    #[test]
    fn heartbeat_signature_not_valid_as_bundle_signature() {
        let rk = signer("rk-1");
        let pk = FakePasskey::new("school.ac.th", "https://school.ac.th").with_key_id("pk-1");
        let trust = [rk.trust_key(), pk.trust_key("pk-1")];
        let c = contents(&trust);
        let s = statement(&c, 30);
        let hb_msg = heartbeat_message(&s);
        let bundle_msg = signed_message(&c);

        for sig in [ed_sig(&rk, &hb_msg), pk.sign(&hb_msg, UPUV)] {
            // 心跳签名拼到同一份内容的包上 → 机器拒收。
            let archive = assemble(&c, &sig).unwrap();
            assert_eq!(
                accept(&archive, &trust, None).unwrap_err(),
                BundleError::BadSignature
            );
            // 当登记探针用：不管 nonce 是什么都验不过。
            assert_eq!(
                verify_signature(&keyprobe_message(&hb_msg[20..52]), &sig, &trust).unwrap_err(),
                BundleError::BadSignature
            );
        }
        // 反过来：设置包的签名、登记探针的签名当心跳签名 → 验不过。
        let archive = pack(&c, &rk).unwrap();
        accept(&archive, &trust, None).unwrap();
        let nonce = [7u8; 32];
        for sig in [
            ed_sig(&rk, &bundle_msg),
            pk.sign(&bundle_msg, UPUV),
            ed_sig(&rk, &keyprobe_message(&nonce)),
            pk.sign(&keyprobe_message(&nonce), UPUV),
        ] {
            assert_eq!(
                verify_heartbeat(&toml_of(&s, sig), &trust).unwrap_err(),
                BundleError::BadSignature
            );
        }
    }

    #[test]
    fn days_is_whole_days_only() {
        let c = contents(&[]);
        assert_eq!(statement(&c, 30).days(), Some(30));
        let mut s = statement(&c, 30);
        s.not_after += 1;
        assert_eq!(s.days(), None);
        s.not_after = s.issued_at;
        assert_eq!(s.days(), None);
    }

    /// 重新生成 `testdata/heartbeat-vectors.json`（网页本地重建心跳消息时对照）。
    /// 平时不跑：`cargo test -p mastersos-bundle regenerate_heartbeat_vectors -- --ignored`。
    #[test]
    #[ignore]
    fn regenerate_heartbeat_vectors() {
        #[derive(Serialize)]
        struct Vector {
            name: &'static str,
            statement: HeartbeatStatement,
            message_b64: String,
        }
        let cases = [
            (
                "typical-30-days",
                HeartbeatStatement {
                    version: 3,
                    digest_hex: "3f0c5b2a9d1e4f6a8b7c0d2e1f3a5b4c6d8e7f9a0b1c2d3e4f5a6b7c8d9e0f1a"
                        .into(),
                    issued_at: 1_791_000_000,
                    not_after: 1_791_000_000 + 30 * DAY_SECS,
                },
            ),
            (
                "big-version-1-day",
                HeartbeatStatement {
                    version: 4_294_967_301,
                    digest_hex: "ff".repeat(32),
                    issued_at: 1_800_000_123,
                    not_after: 1_800_000_123 + DAY_SECS,
                },
            ),
            (
                "max-31-days",
                HeartbeatStatement {
                    version: 1,
                    digest_hex: "00".repeat(32),
                    issued_at: 1_790_000_000,
                    not_after: 1_790_000_000 + 31 * DAY_SECS,
                },
            ),
        ];
        let out: Vec<Vector> = cases
            .into_iter()
            .map(|(name, statement)| Vector {
                name,
                message_b64: STANDARD.encode(heartbeat_message(&statement)),
                statement,
            })
            .collect();
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/testdata/heartbeat-vectors.json"
            ),
            serde_json::to_string_pretty(&out).unwrap() + "\n",
        )
        .unwrap();
    }
}
