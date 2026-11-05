//! 签名、验签与接收（spec §4.2、§5.2）。
//!
//! 设置包签名的消息是 `b"mastersos-bundle-v1\n"` 加上 `content_digest`。验签只用调用方
//! 传入的、机器**当前**信任的公钥；新包里的 `trust` 只有验证通过之后才由调用方
//! 采纳。`issued_at` 只用来显示，这里不看时钟。
//!
//! 两种钥匙：`ed25519`（恢复钥匙）和 `webauthn-es256`（IT 的 passkey，
//! 验法见 [`crate::webauthn`]）。设置包、心跳、登记探针都经 [`verify_signature`]，
//! 各自的消息前缀不同，一种用途的签名顶替不了另一种。
//!
//! passkey 的 ECDSA 签名可延展：有效包的签名字节与整包哈希不能拿来当标识，
//! 版本由 `version` 与内容摘要标识。

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use crate::{
    content_digest, read_archive, webauthn, write_archive, BundleError, Contents, KeyAlg, Manifest,
    TrustKey,
};

const MESSAGE_PREFIX: &[u8] = b"mastersos-bundle-v1\n";

pub trait Signer {
    fn key_id(&self) -> &str;
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
}

pub struct Ed25519Signer {
    id: String,
    pair: Ed25519KeyPair,
}

impl Ed25519Signer {
    pub fn generate_pkcs8() -> Vec<u8> {
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .expect("系统随机数源不可用")
            .as_ref()
            .to_vec()
    }

    pub fn from_pkcs8(id: &str, pkcs8: &[u8]) -> Result<Self, BundleError> {
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|e| {
            BundleError::Invalid(format!("The private key is not valid PKCS#8 Ed25519: {e}"))
        })?;
        Ok(Ed25519Signer {
            id: id.to_string(),
            pair,
        })
    }

    /// The key with this 32-byte Ed25519 seed (RFC 8032 private key), e.g. one derived from a
    /// recovery kit ([`crate::kit::Kit::signer`]).
    pub fn from_seed(id: &str, seed: &[u8; 32]) -> Self {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed)
            .expect("a 32-byte seed is always a valid Ed25519 private key");
        Ed25519Signer {
            id: id.to_string(),
            pair,
        }
    }

    pub fn trust_key(&self) -> TrustKey {
        TrustKey {
            id: self.id.clone(),
            alg: KeyAlg::Ed25519,
            public_key: STANDARD.encode(self.pair.public_key().as_ref()),
            rp_id: None,
        }
    }
}

impl Signer for Ed25519Signer {
    fn key_id(&self) -> &str {
        &self.id
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.pair.sign(msg).as_ref().to_vec()
    }
}

/// 包里 `signature` 文件的内容（TOML）；管理 API 里以同样的字段名用 JSON 传。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SignatureFile {
    pub key_id: String,
    pub alg: KeyAlg,
    /// 标准 base64。`ed25519` 是 64 字节签名；`webauthn-es256` 是 DER 编码的 ECDSA 签名。
    pub sig: String,
    /// 标准 base64。`webauthn-es256` 必填，`ed25519` 必须没有。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator_data: Option<String>,
    /// 标准 base64（浏览器给的原始字节，不重新序列化）。`webauthn-es256` 必填，
    /// `ed25519` 必须没有。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_data_json: Option<String>,
}

impl SignatureFile {
    pub fn to_toml(&self) -> String {
        toml::to_string(self).expect("SignatureFile 只含字符串，必能序列化为 TOML")
    }
}

/// 设置包签名所签的消息：`b"mastersos-bundle-v1\n" || content_digest(c)`。
pub fn signed_message(c: &Contents) -> Vec<u8> {
    let mut msg = MESSAGE_PREFIX.to_vec();
    msg.extend_from_slice(&content_digest(c));
    msg
}

/// 用 `signer` 对内容签名并打成 `.tar.gz`。
pub fn pack(c: &Contents, signer: &dyn Signer) -> Result<Vec<u8>, BundleError> {
    let sig = SignatureFile {
        key_id: signer.key_id().to_string(),
        alg: KeyAlg::Ed25519,
        sig: STANDARD.encode(signer.sign(&signed_message(c))),
        authenticator_data: None,
        client_data_json: None,
    };
    assemble(c, &sig)
}

/// 用外部做好的签名（passkey、`mastersos-sign`）打包。这里**不验签**：
/// 用哪组 trust 验由调用方决定。
pub fn assemble(c: &Contents, sig: &SignatureFile) -> Result<Vec<u8>, BundleError> {
    write_archive(c, &sig.to_toml())
}

/// 用 `trust` 里 `key_id` 对应的钥匙验 `sig` 是不是对 `msg` 的签名，返回那把钥匙。
/// 设置包、心跳、登记探针共用。
///
/// - 找不到 `key_id` → `UnknownKey`。
/// - 签名文件的 `alg` 必须等于钥匙的 `alg`，否则 `BadSignature`（不按签名文件自报的
///   算法去验，免得算法混淆）。
/// - `ed25519` 签名文件带了 webauthn 字段、`webauthn-es256` 缺字段 → `BadSignature`。
pub fn verify_signature<'a>(
    msg: &[u8],
    sig: &SignatureFile,
    trust: &'a [TrustKey],
) -> Result<&'a TrustKey, BundleError> {
    let key = trust
        .iter()
        .find(|k| k.id == sig.key_id)
        .ok_or_else(|| BundleError::UnknownKey(sig.key_id.clone()))?;
    if sig.alg != key.alg {
        return Err(BundleError::BadSignature);
    }
    let b64 = |s: &str| STANDARD.decode(s).map_err(|_| BundleError::BadSignature);
    let public = b64(&key.public_key)?;
    let raw_sig = b64(&sig.sig)?;
    match key.alg {
        KeyAlg::Ed25519 => {
            if sig.authenticator_data.is_some() || sig.client_data_json.is_some() {
                return Err(BundleError::BadSignature);
            }
            UnparsedPublicKey::new(&ED25519, public)
                .verify(msg, &raw_sig)
                .map_err(|_| BundleError::BadSignature)?;
        }
        KeyAlg::WebauthnEs256 => {
            let (Some(ad), Some(cd), Some(rp_id)) = (
                sig.authenticator_data.as_deref(),
                sig.client_data_json.as_deref(),
                key.rp_id.as_deref(),
            ) else {
                return Err(BundleError::BadSignature);
            };
            let point: [u8; 65] = public.try_into().map_err(|_| BundleError::BadSignature)?;
            webauthn::verify(msg, &point, rp_id, &b64(ad)?, &b64(cd)?, &raw_sig)?;
        }
    }
    Ok(key)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bundle {
    pub manifest: Manifest,
    pub contents: Contents,
}

/// 解包 → 用 `trust`（机器当前信任的公钥）验签 → 解析清单 → 校验 → 检查版本。
pub fn accept(
    archive: &[u8],
    trust: &[TrustKey],
    current_version: Option<u64>,
) -> Result<Bundle, BundleError> {
    accept_signed(archive, trust, current_version).map(|(b, _)| b)
}

/// [`accept`], also returning the key of `trust` whose signature was verified.
pub fn accept_signed(
    archive: &[u8],
    trust: &[TrustKey],
    current_version: Option<u64>,
) -> Result<(Bundle, TrustKey), BundleError> {
    let unpacked = read_archive(archive)?;
    let sig_file: SignatureFile =
        toml::from_str(&unpacked.signature_toml).map_err(|_| BundleError::BadSignature)?;
    let signer = verify_signature(&signed_message(&unpacked.contents), &sig_file, trust)?.clone();

    let contents = unpacked.contents;
    let manifest = Manifest::parse(&contents.manifest_text)?;
    let present: BTreeSet<String> = contents.files.keys().cloned().collect();
    manifest.validate(&present)?;
    if let Some(cur) = current_version {
        if manifest.version <= cur {
            return Err(BundleError::NotNewer {
                current: cur,
                offered: manifest.version,
            });
        }
    }
    Ok((Bundle { manifest, contents }, signer))
}

/// [`accept`], then the school binding (plan 6 Task 10b, [`crate::check_school`]): with
/// `seed_school` set the manifest must name exactly that school. Every bundle a machine takes
/// (from the server, from the seed partition's cache, or reloaded at boot) goes through this.
pub fn accept_for_school(
    archive: &[u8],
    trust: &[TrustKey],
    current_version: Option<u64>,
    seed_school: Option<&str>,
) -> Result<Bundle, BundleError> {
    let b = accept(archive, trust, current_version)?;
    crate::check_school(&b.manifest, seed_school)?;
    Ok(b)
}

/// Whether two trust lists differ, as publishing rule R7 counts it: a key added, removed, or
/// changed (same id, other public key, algorithm or rp_id). Order does not matter. The server's
/// R7 and machines ([`check_recovery_signed`]) use this same comparison.
pub fn trust_changed(old: &[TrustKey], new: &[TrustKey]) -> bool {
    let by_id = |t: &[TrustKey]| -> BTreeMap<String, TrustKey> {
        t.iter().map(|k| (k.id.clone(), k.clone())).collect()
    };
    by_id(old) != by_id(new)
}

/// Whether two `[school].escrow_recipients` lists differ, as publishing rule R8 counts it:
/// compared as sets, so order and repeats do not matter ([`crate::recipients_fp`]).
pub fn recipients_changed(old: &[String], new: &[String]) -> bool {
    let set = |r: &[String]| -> BTreeSet<String> { r.iter().cloned().collect() };
    set(old) != set(new)
}

/// What [`check_recovery_signed`] found changed without a recovery-kit signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KitChange {
    Trust,
    Recipients,
    TrustAndRecipients,
}

impl KitChange {
    pub fn as_str(self) -> &'static str {
        match self {
            KitChange::Trust => "trust",
            KitChange::Recipients => "escrow recipients",
            KitChange::TrustAndRecipients => "trust and escrow recipients",
        }
    }
}

/// Publishing rules R7 and R8 as a machine enforces them (plan 6 Task 24c, final review I1):
/// a new bundle whose `trust` ([`trust_changed`]) or `[school].escrow_recipients`
/// ([`recipients_changed`]) differs from the currently accepted bundle's is accepted only when
/// `signer` is an Ed25519 (recovery-kit) key of the current trust. A passkey alone cannot change
/// whom the machine trusts or to whom it seals its LUKS recovery key, whatever the server showed
/// the person approving.
///
/// `old_trust`/`old_recipients` are the accepted bundle's; `signer` is the key of `old_trust`
/// that verified `new` ([`accept_signed`]). The first bundle after a seed (genesis) has nothing
/// to compare with and is not checked here.
pub fn check_recovery_signed(
    old_trust: &[TrustKey],
    old_recipients: &[String],
    new: &Manifest,
    signer: &TrustKey,
) -> Result<(), BundleError> {
    let change = match (
        trust_changed(old_trust, &new.trust),
        recipients_changed(old_recipients, &new.school.escrow_recipients),
    ) {
        (false, false) => return Ok(()),
        (true, false) => KitChange::Trust,
        (false, true) => KitChange::Recipients,
        (true, true) => KitChange::TrustAndRecipients,
    };
    if signer.alg == KeyAlg::Ed25519 && old_trust.contains(signer) {
        return Ok(());
    }
    Err(BundleError::KitRequired(change))
}

/// [`accept_for_school`] for a machine that already accepted a bundle: `trust` and
/// `old_recipients` are that bundle's, and the new one must also pass [`check_recovery_signed`].
/// `old_recipients` is `None` when the machine does not know them (neither the accepted bundle
/// nor a remembered list survived): then it fails closed, and only a recovery-kit key of `trust`
/// may sign the new bundle, whatever it changes.
pub fn accept_update_for_school(
    archive: &[u8],
    trust: &[TrustKey],
    old_recipients: Option<&[String]>,
    current_version: Option<u64>,
    seed_school: Option<&str>,
) -> Result<Bundle, BundleError> {
    let (b, signer) = accept_signed(archive, trust, current_version)?;
    crate::check_school(&b.manifest, seed_school)?;
    match old_recipients {
        Some(old) => check_recovery_signed(trust, old, &b.manifest, &signer)?,
        None if signer.alg == KeyAlg::Ed25519 && trust.contains(&signer) => {}
        None => return Err(BundleError::KitRequired(KitChange::Recipients)),
    }
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest as _;

    fn signer(id: &str) -> Ed25519Signer {
        Ed25519Signer::from_pkcs8(id, &Ed25519Signer::generate_pkcs8()).unwrap()
    }

    fn manifest_text(version: u64, issued_at: &str, trust: &[TrustKey]) -> String {
        let mut s = format!("version = {version}\nissued_at = \"{issued_at}\"\n");
        for k in trust {
            s += &format!(
                "\n[[trust]]\nid = \"{}\"\nalg = \"{}\"\npublic_key = \"{}\"\n",
                k.id,
                k.alg.as_str(),
                k.public_key
            );
            if let Some(rp) = &k.rp_id {
                s += &format!("rp_id = \"{rp}\"\n");
            }
        }
        s += "\n[[group]]\nid = \"default\"\nname = \"未分组\"\n";
        s
    }

    fn contents(version: u64, trust: &[TrustKey]) -> Contents {
        let mut files = std::collections::BTreeMap::new();
        files.insert("files/a.txt".to_string(), b"hello".to_vec());
        Contents {
            manifest_text: manifest_text(version, "2026-10-10T07:00:00Z", trust),
            files,
        }
    }

    #[test]
    fn accepts_signed_bundle() {
        let s = signer("k1");
        let archive = pack(&contents(42, &[s.trust_key()]), &s).unwrap();
        let b = accept(&archive, &[s.trust_key()], Some(41)).unwrap();
        assert_eq!(b.manifest.version, 42);
        assert_eq!(b.contents.files["files/a.txt"], b"hello");
        accept(&archive, &[s.trust_key()], None).unwrap();
    }

    #[test]
    fn rejects_tampered_file() {
        let s = signer("k1");
        let c = contents(42, &[s.trust_key()]);
        let good = pack(&c, &s).unwrap();
        let sig = read_archive(&good).unwrap().signature_toml;
        let mut tampered = c.clone();
        tampered.files.get_mut("files/a.txt").unwrap()[0] ^= 1;
        let archive = write_archive(&tampered, &sig).unwrap();
        assert_eq!(
            accept(&archive, &[s.trust_key()], None).unwrap_err(),
            BundleError::BadSignature
        );
    }

    #[test]
    fn rejects_unknown_key_id() {
        let s = signer("k1");
        let other = signer("k2");
        let archive = pack(&contents(42, &[s.trust_key()]), &s).unwrap();
        assert_eq!(
            accept(&archive, &[other.trust_key()], None).unwrap_err(),
            BundleError::UnknownKey("k1".into())
        );
    }

    #[test]
    fn rejects_signature_from_other_key_with_same_id() {
        let real = signer("k1");
        let forger = signer("k1");
        let archive = pack(&contents(42, &[forger.trust_key()]), &forger).unwrap();
        assert_eq!(
            accept(&archive, &[real.trust_key()], None).unwrap_err(),
            BundleError::BadSignature
        );
    }

    #[test]
    fn rejects_malformed_signature_file() {
        let s = signer("k1");
        let archive = write_archive(&contents(42, &[s.trust_key()]), "not toml [").unwrap();
        assert_eq!(
            accept(&archive, &[s.trust_key()], None).unwrap_err(),
            BundleError::BadSignature
        );
    }

    #[test]
    fn rejects_replayed_old_version() {
        let s = signer("k1");
        let t = [s.trust_key()];
        for v in [42, 41] {
            let archive = pack(&contents(v, &t), &s).unwrap();
            assert_eq!(
                accept(&archive, &t, Some(42)).unwrap_err(),
                BundleError::NotNewer {
                    current: 42,
                    offered: v
                }
            );
        }
    }

    #[test]
    fn trust_rotation_needs_old_key() {
        let a = signer("A");
        let b = signer("B");
        // 包里只列新钥匙 B，且由 B 签：机器信任的是 A → UnknownKey。
        let by_b = pack(&contents(2, &[b.trust_key()]), &b).unwrap();
        assert_eq!(
            accept(&by_b, &[a.trust_key()], Some(1)).unwrap_err(),
            BundleError::UnknownKey("B".into())
        );
        // 同样的新 trust 由 A 签发 → 接受。
        let by_a = pack(&contents(2, &[b.trust_key()]), &a).unwrap();
        let accepted = accept(&by_a, &[a.trust_key()], Some(1)).unwrap();
        // 之后调用方改信 manifest.trust，B 签的下一版被接受。
        let next = pack(&contents(3, &[b.trust_key()]), &b).unwrap();
        let b3 = accept(&next, &accepted.manifest.trust, Some(2)).unwrap();
        assert_eq!(b3.manifest.version, 3);
    }

    // —— passkey（webauthn-es256）——

    use crate::testutil::FakePasskey;
    use crate::webauthn::{FLAG_UP, FLAG_UV};

    const RP: &str = "school.ac.th";
    const ORIGIN: &str = "https://school.ac.th";
    const UPUV: u8 = FLAG_UP | FLAG_UV;

    /// 用 passkey 对 `c` 签名并打包。
    fn pack_passkey(c: &Contents, p: &FakePasskey, flags: u8) -> Vec<u8> {
        assemble(c, &p.sign(&signed_message(c), flags)).unwrap()
    }

    #[test]
    fn accepts_passkey_signed_bundle() {
        let p = FakePasskey::new(RP, ORIGIN).with_key_id("it-phone");
        let t = [p.trust_key("it-phone")];
        let c = contents(42, &[signer("rec").trust_key()]);
        let archive = pack_passkey(&c, &p, UPUV);
        let b = accept(&archive, &t, Some(41)).unwrap();
        assert_eq!(b.manifest.version, 42);
        // 签名文件以 TOML 落在包里，读回来与签出来的一致。
        let sig: SignatureFile =
            toml::from_str(&read_archive(&archive).unwrap().signature_toml).unwrap();
        assert_eq!(sig.alg, KeyAlg::WebauthnEs256);
        assert!(sig.authenticator_data.is_some() && sig.client_data_json.is_some());
        // verify_signature 返回用到的那把钥匙。
        let msg = signed_message(&c);
        assert_eq!(verify_signature(&msg, &sig, &t).unwrap(), &t[0]);
    }

    /// Plan 6 Task 10b: one passkey in two schools' trust. A bundle naming school A, signed by
    /// it, is accepted by a machine seeded for A and refused by one seeded for B, as is one that
    /// names no school; a machine whose seed names no school (before plan 6) accepts both.
    #[test]
    fn shared_passkey_bundle_is_bound_to_its_school() {
        const A: &str = "0192f3a4-5b6c-7d8e-9f00-00000000000a";
        const B: &str = "0192f3a4-5b6c-7d8e-9f00-00000000000b";
        let p = FakePasskey::new(RP, ORIGIN).with_key_id("it-phone");
        let t = [p.trust_key("it-phone")];
        let mut c = contents(42, &t);
        c.manifest_text = c.manifest_text.replacen(
            "\n[[trust]]",
            &format!("\n[school]\nid = \"{A}\"\n\n[[trust]]"),
            1,
        );
        let for_a = pack_passkey(&c, &p, UPUV);
        let b = accept_for_school(&for_a, &t, Some(41), Some(A)).unwrap();
        assert_eq!(b.manifest.school.id.as_deref(), Some(A));
        assert_eq!(
            accept_for_school(&for_a, &t, Some(41), Some(B)).unwrap_err(),
            BundleError::OtherSchool
        );
        accept_for_school(&for_a, &t, Some(41), None).unwrap();
        let unnamed = pack_passkey(&contents(42, &t), &p, UPUV);
        assert_eq!(
            accept_for_school(&unnamed, &t, Some(41), Some(B)).unwrap_err(),
            BundleError::OtherSchool
        );
        accept_for_school(&unnamed, &t, Some(41), None).unwrap();
        // The signature and version checks still come first.
        assert_eq!(
            accept_for_school(&for_a, &t, Some(42), Some(B)).unwrap_err(),
            BundleError::NotNewer {
                current: 42,
                offered: 42
            }
        );
    }

    fn passkey_reject(p: &FakePasskey, sig: SignatureFile, c: &Contents) {
        let t = [p.trust_key(&p.key_id)];
        let archive = assemble(c, &sig).unwrap();
        assert_eq!(
            accept(&archive, &t, None).unwrap_err(),
            BundleError::BadSignature
        );
    }

    #[test]
    fn rejects_wrong_origin() {
        let c = contents(42, &[signer("rec").trust_key()]);
        let p = FakePasskey::new(RP, "https://evil.example");
        passkey_reject(&p, p.sign(&signed_message(&c), UPUV), &c);
    }

    #[test]
    fn rejects_wrong_rp_id_hash() {
        let c = contents(42, &[signer("rec").trust_key()]);
        // 钓鱼站点的断言：rpIdHash 是它自己的域名，签的是同一条消息。
        let p = FakePasskey::new(RP, ORIGIN);
        let mut ad = sha2::Sha256::digest(b"evil.example").to_vec();
        ad.push(UPUV);
        ad.extend_from_slice(&[0; 4]);
        let cd = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}"}}"#,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signed_message(&c))
        );
        passkey_reject(&p, p.sign_raw(&ad, cd.as_bytes()), &c);
    }

    #[test]
    fn rejects_missing_uv() {
        let c = contents(42, &[signer("rec").trust_key()]);
        let p = FakePasskey::new(RP, ORIGIN);
        passkey_reject(&p, p.sign(&signed_message(&c), FLAG_UP), &c);
    }

    #[test]
    fn rejects_at_flag_and_short_auth_data() {
        let c = contents(42, &[signer("rec").trust_key()]);
        let p = FakePasskey::new(RP, ORIGIN);
        passkey_reject(&p, p.sign(&signed_message(&c), UPUV | 0x40), &c);
        let mut short = p.sign(&signed_message(&c), UPUV);
        let mut ad = STANDARD.decode(short.authenticator_data.unwrap()).unwrap();
        ad.truncate(36);
        short.authenticator_data = Some(STANDARD.encode(ad));
        passkey_reject(&p, short, &c);
    }

    #[test]
    fn rejects_challenge_for_other_content() {
        let p = FakePasskey::new(RP, ORIGIN);
        let c = contents(42, &[signer("rec").trust_key()]);
        let mut other = c.clone();
        other.files.insert("files/b.txt".into(), b"x".to_vec());
        // 对另一份内容的消息签名，拼到这份包上。
        passkey_reject(&p, p.sign(&signed_message(&other), UPUV), &c);
    }

    #[test]
    fn rejects_get_vs_create_type() {
        let p = FakePasskey::new(RP, ORIGIN);
        let c = contents(42, &[signer("rec").trust_key()]);
        let cd = format!(
            r#"{{"type":"webauthn.create","challenge":"{}","origin":"{ORIGIN}"}}"#,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signed_message(&c))
        );
        passkey_reject(
            &p,
            p.sign_with_client_data(&signed_message(&c), UPUV, &cd),
            &c,
        );
    }

    /// Ruling 51: a subdomain of the RP ID, or a port, no longer signs.
    #[test]
    fn subdomain_or_port_origin_rejected() {
        let c = contents(42, &[signer("rec").trust_key()]);
        for origin in [
            "https://mastersos.school.ac.th",
            "https://school.ac.th:8443",
        ] {
            let p = FakePasskey::new(RP, origin);
            passkey_reject(&p, p.sign(&signed_message(&c), UPUV), &c);
        }
    }

    #[test]
    fn cross_origin_rejected() {
        let p = FakePasskey::new(RP, ORIGIN);
        let c = contents(42, &[signer("rec").trust_key()]);
        let ch = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signed_message(&c));
        for cd in [
            format!(
                r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"{ORIGIN}","crossOrigin":true}}"#
            ),
            format!(
                r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"{ORIGIN}","topOrigin":"https://evil.example"}}"#
            ),
        ] {
            passkey_reject(
                &p,
                p.sign_with_client_data(&signed_message(&c), UPUV, &cd),
                &c,
            );
        }
    }

    #[test]
    fn duplicate_challenge_key_rejected() {
        let p = FakePasskey::new(RP, ORIGIN);
        let c = contents(42, &[signer("rec").trust_key()]);
        let mut other = c.clone();
        other.manifest_text.push('\n');
        let enc = |m: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(m);
        let cd = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}","challenge":"{}"}}"#,
            enc(&signed_message(&other)),
            enc(&signed_message(&c))
        );
        passkey_reject(
            &p,
            p.sign_with_client_data(&signed_message(&c), UPUV, &cd),
            &c,
        );
    }

    #[test]
    fn localhost_http_only_for_localhost_rp() {
        let c = contents(42, &[signer("rec").trust_key()]);
        let p = FakePasskey::new("localhost", "http://localhost:5173");
        accept(&pack_passkey(&c, &p, UPUV), &[p.trust_key(&p.key_id)], None).unwrap();
        let p = FakePasskey::new(RP, "http://mastersos.school.ac.th");
        passkey_reject(&p, p.sign(&signed_message(&c), UPUV), &c);
    }

    #[test]
    fn suffix_trick_rejected() {
        let c = contents(42, &[signer("rec").trust_key()]);
        let p = FakePasskey::new(RP, "https://evilschool.ac.th");
        passkey_reject(&p, p.sign(&signed_message(&c), UPUV), &c);
    }

    #[test]
    fn alg_mismatch_rejected_both_directions() {
        let c = contents(42, &[signer("rec").trust_key()]);
        let msg = signed_message(&c);
        let ed = signer("k");
        let pk = FakePasskey::new(RP, ORIGIN).with_key_id("k");

        // trust 是 ed25519，签名文件写 webauthn-es256（passkey 的断言）→ 拒。
        let sig = pk.sign(&msg, UPUV);
        assert_eq!(
            verify_signature(&msg, &sig, &[ed.trust_key()]).unwrap_err(),
            BundleError::BadSignature
        );
        // trust 是 ed25519，签名是真 ed25519 签名但 alg 写成 webauthn-es256 → 拒。
        let mut sig = ed_sig(&ed, &msg);
        sig.alg = KeyAlg::WebauthnEs256;
        assert_eq!(
            verify_signature(&msg, &sig, &[ed.trust_key()]).unwrap_err(),
            BundleError::BadSignature
        );
        // 反过来：trust 是 webauthn-es256，签名文件写 ed25519 → 拒。
        let mut sig = pk.sign(&msg, UPUV);
        sig.alg = KeyAlg::Ed25519;
        assert_eq!(
            verify_signature(&msg, &sig, &[pk.trust_key("k")]).unwrap_err(),
            BundleError::BadSignature
        );
        // ed25519 签名文件带了 webauthn 字段 → 拒，哪怕签名本身是对的。
        let good = ed_sig(&ed, &msg);
        verify_signature(&msg, &good, &[ed.trust_key()]).unwrap();
        let webauthn = pk.sign(&msg, UPUV);
        for (ad, cd) in [
            (webauthn.authenticator_data.clone(), None),
            (None, webauthn.client_data_json.clone()),
        ] {
            let mut sig = good.clone();
            sig.authenticator_data = ad;
            sig.client_data_json = cd;
            assert_eq!(
                verify_signature(&msg, &sig, &[ed.trust_key()]).unwrap_err(),
                BundleError::BadSignature
            );
        }
        // webauthn 签名文件缺了任一字段 → 拒。
        for strip in [0, 1] {
            let mut sig = pk.sign(&msg, UPUV);
            if strip == 0 {
                sig.authenticator_data = None;
            } else {
                sig.client_data_json = None;
            }
            assert_eq!(
                verify_signature(&msg, &sig, &[pk.trust_key("k")]).unwrap_err(),
                BundleError::BadSignature
            );
        }
        // trust 里的 passkey 没有 rp_id（种子没过 validate）→ 拒。
        let mut tk = pk.trust_key("k");
        tk.rp_id = None;
        assert_eq!(
            verify_signature(&msg, &pk.sign(&msg, UPUV), &[tk]).unwrap_err(),
            BundleError::BadSignature
        );
        // 找不到 key_id 仍是 UnknownKey。
        assert_eq!(
            verify_signature(&msg, &pk.sign(&msg, UPUV), &[pk.trust_key("other")]).unwrap_err(),
            BundleError::UnknownKey("k".into())
        );
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

    #[test]
    fn rotation_from_ed25519_to_passkey() {
        // 恢复钥匙签一版把 passkey 加进 trust，之后 passkey 签的下一版被接受。
        let rec = signer("rec");
        let p = FakePasskey::new(RP, ORIGIN).with_key_id("it-phone");
        let trust2 = [rec.trust_key(), p.trust_key("it-phone")];
        let v2 = pack(&contents(2, &trust2), &rec).unwrap();
        let b2 = accept(&v2, &[rec.trust_key()], Some(1)).unwrap();
        assert_eq!(b2.manifest.trust[1].rp_id.as_deref(), Some(RP));
        let v3 = pack_passkey(&contents(3, &trust2), &p, UPUV);
        assert_eq!(
            accept(&v3, &b2.manifest.trust, Some(2))
                .unwrap()
                .manifest
                .version,
            3
        );
        // passkey 签的包在只信恢复钥匙的机器上 → UnknownKey。
        assert_eq!(
            accept(&v3, &[rec.trust_key()], Some(2)).unwrap_err(),
            BundleError::UnknownKey("it-phone".into())
        );
    }

    #[test]
    fn signature_file_json_and_toml_roundtrip() {
        let p = FakePasskey::new(RP, ORIGIN);
        let sig = p.sign(b"m", UPUV);
        let json = serde_json::to_string(&sig).unwrap();
        assert!(json.contains("\"alg\":\"webauthn-es256\""), "{json}");
        assert!(json.contains("\"authenticator_data\""), "{json}");
        assert_eq!(serde_json::from_str::<SignatureFile>(&json).unwrap(), sig);
        assert_eq!(
            toml::from_str::<SignatureFile>(&sig.to_toml()).unwrap(),
            sig
        );
        // ed25519 的签名文件不写这两个键，TOML 与计划 1 的写法一样。
        let ed = ed_sig(&signer("k1"), b"m");
        let text = ed.to_toml();
        assert!(!text.contains("authenticator_data") && !text.contains("client_data_json"));
        assert_eq!(
            text,
            format!("key_id = \"k1\"\nalg = \"ed25519\"\nsig = \"{}\"\n", ed.sig)
        );
        assert_eq!(toml::from_str::<SignatureFile>(&text).unwrap(), ed);
    }

    #[test]
    fn ignores_issued_at_in_future() {
        let s = signer("k1");
        let mut c = contents(42, &[s.trust_key()]);
        c.manifest_text = manifest_text(42, "2099-01-01T00:00:00Z", &[s.trust_key()]);
        let archive = pack(&c, &s).unwrap();
        accept(&archive, &[s.trust_key()], None).unwrap();
    }

    // —— R7/R8 on the machine (plan 6 Task 24c) ——

    use crate::kit::Kit;

    fn kit(n: u8) -> Kit {
        Kit::from_master(&[n; 32])
    }

    /// A bundle with this trust and these escrow recipients.
    fn with_recipients(version: u64, trust: &[TrustKey], recipients: &[String]) -> Contents {
        let mut c = contents(version, trust);
        let list = recipients
            .iter()
            .map(|r| format!("\"{r}\""))
            .collect::<Vec<_>>()
            .join(", ");
        c.manifest_text = c.manifest_text.replacen(
            "\n[[trust]]",
            &if recipients.is_empty() {
                // An empty list is written by leaving the key out.
                "\n[[trust]]".to_owned()
            } else {
                format!("\n[school]\nescrow_recipients = [{list}]\n\n[[trust]]")
            },
            1,
        );
        c
    }

    struct Fixture {
        kit: Kit,
        phone: FakePasskey,
        trust: Vec<TrustKey>,
        recipients: Vec<String>,
    }

    /// The accepted v1: trust = kit 1 + the IT passkey, recipients = kit 1's.
    fn fixture() -> Fixture {
        let kit = kit(1);
        let phone = FakePasskey::new(RP, ORIGIN).with_key_id("it-phone");
        let trust = vec![kit.trust_key(), phone.trust_key("it-phone")];
        let recipients = vec![kit.escrow_recipient()];
        Fixture {
            kit,
            phone,
            trust,
            recipients,
        }
    }

    impl Fixture {
        fn update(&self, archive: &[u8]) -> Result<Bundle, BundleError> {
            accept_update_for_school(archive, &self.trust, Some(&self.recipients), Some(1), None)
        }
        fn by_phone(&self, c: &Contents) -> Vec<u8> {
            pack_passkey(c, &self.phone, UPUV)
        }
        fn by_kit(&self, c: &Contents) -> Vec<u8> {
            pack(c, &self.kit.signer()).unwrap()
        }
    }

    #[test]
    fn passkey_cannot_add_escrow_recipient() {
        let f = fixture();
        let mut r = f.recipients.clone();
        r.push(kit(9).escrow_recipient());
        let c = with_recipients(2, &f.trust, &r);
        assert_eq!(
            f.update(&f.by_phone(&c)).unwrap_err(),
            BundleError::KitRequired(KitChange::Recipients)
        );
        // Removing one is a change too.
        let c = with_recipients(2, &f.trust, &[]);
        assert_eq!(
            f.update(&f.by_phone(&c)).unwrap_err(),
            BundleError::KitRequired(KitChange::Recipients)
        );
        // The same change signed by the kit in the current trust is accepted.
        let c = with_recipients(2, &f.trust, &r);
        assert_eq!(f.update(&f.by_kit(&c)).unwrap().manifest.version, 2);
    }

    #[test]
    fn passkey_cannot_change_trust() {
        let f = fixture();
        let mut t = f.trust.clone();
        t.push(kit(9).trust_key());
        let c = with_recipients(2, &t, &f.recipients);
        let err = f.update(&f.by_phone(&c)).unwrap_err();
        assert_eq!(err, BundleError::KitRequired(KitChange::Trust));
        assert!(
            err.to_string()
                .starts_with("trust change not signed by a recovery kit"),
            "{err}"
        );
        // A changed key under the same id counts as well.
        let mut t = f.trust.clone();
        t[0].public_key = kit(9).trust_key().public_key;
        let c = with_recipients(2, &t, &f.recipients);
        assert_eq!(
            f.update(&f.by_phone(&c)).unwrap_err(),
            BundleError::KitRequired(KitChange::Trust)
        );
        // Both at once.
        let mut t = f.trust.clone();
        t.push(kit(9).trust_key());
        let c = with_recipients(2, &t, &[kit(9).escrow_recipient()]);
        assert_eq!(
            f.update(&f.by_phone(&c)).unwrap_err(),
            BundleError::KitRequired(KitChange::TrustAndRecipients)
        );
        // Kit-signed → accepted.
        assert_eq!(f.update(&f.by_kit(&c)).unwrap().manifest.trust, t);
    }

    #[test]
    fn reorder_or_no_change_needs_no_kit() {
        let f = fixture();
        let extra = kit(2);
        let trust = vec![
            f.kit.trust_key(),
            f.phone.trust_key("it-phone"),
            extra.trust_key(),
        ];
        let recipients = vec![f.kit.escrow_recipient(), extra.escrow_recipient()];
        let accept_v2 = |t: &[TrustKey], r: &[String], archive: &[u8]| {
            accept_update_for_school(archive, t, Some(r), Some(1), None)
        };
        // Same sets in another order, signed by the passkey.
        let mut t2 = trust.clone();
        t2.reverse();
        let mut r2 = recipients.clone();
        r2.reverse();
        r2.push(r2[0].clone());
        let c = with_recipients(2, &t2, &r2);
        accept_v2(&trust, &recipients, &f.by_phone(&c)).unwrap();
        // Unchanged, signed by the passkey (the everyday publish).
        let c = with_recipients(2, &f.trust, &f.recipients);
        f.update(&f.by_phone(&c)).unwrap();
    }

    #[test]
    fn kit_outside_current_trust_cannot_change_trust() {
        let f = fixture();
        let stranger = kit(7);
        let mut t = f.trust.clone();
        t.push(stranger.trust_key());
        let c = with_recipients(2, &t, &[stranger.escrow_recipient()]);
        // Signature verification uses the current trust: the stranger's key is unknown.
        assert_eq!(
            f.update(&pack(&c, &stranger.signer()).unwrap())
                .unwrap_err(),
            BundleError::UnknownKey(stranger.key_id())
        );
        // And the rule itself requires the signer to be in the current trust.
        let m = Manifest::parse(&c.manifest_text).unwrap();
        assert_eq!(
            check_recovery_signed(&f.trust, &f.recipients, &m, &stranger.trust_key()),
            Err(BundleError::KitRequired(KitChange::TrustAndRecipients))
        );
        check_recovery_signed(&f.trust, &f.recipients, &m, &f.kit.trust_key()).unwrap();
    }

    /// Unknown old recipients (Task 24c fix round 1, m1): fail closed, only the kit can sign.
    #[test]
    fn unknown_old_recipients_need_kit() {
        let f = fixture();
        let c = with_recipients(2, &f.trust, &f.recipients);
        let update = |a: &[u8]| accept_update_for_school(a, &f.trust, None, Some(1), None);
        assert_eq!(
            update(&f.by_phone(&c)).unwrap_err(),
            BundleError::KitRequired(KitChange::Recipients)
        );
        update(&f.by_kit(&c)).unwrap();
    }

    #[test]
    fn change_helpers_ignore_order() {
        let (a, b) = (kit(1), kit(2));
        assert!(!trust_changed(
            &[a.trust_key(), b.trust_key()],
            &[b.trust_key(), a.trust_key()]
        ));
        assert!(trust_changed(
            &[a.trust_key()],
            &[a.trust_key(), b.trust_key()]
        ));
        assert!(trust_changed(
            &[a.trust_key(), b.trust_key()],
            &[a.trust_key()]
        ));
        let (ra, rb) = (a.escrow_recipient(), b.escrow_recipient());
        assert!(!recipients_changed(
            &[ra.clone(), rb.clone()],
            &[rb.clone(), ra.clone(), rb.clone()]
        ));
        assert!(recipients_changed(
            std::slice::from_ref(&ra),
            &[ra.clone(), rb.clone()]
        ));
        assert!(recipients_changed(&[ra], &[]));
    }
}
