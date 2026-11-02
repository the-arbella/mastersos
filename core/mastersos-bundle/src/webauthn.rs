//! 验 passkey（WebAuthn ES256）断言当作签名（spec §4.2；计划 2 Ruling 1）。
//!
//! IT 在网页上签名时，浏览器调 `navigator.credentials.get`，challenge 就是待签消息
//! 本身（设置包、心跳、登记探针各有自己的前缀，彼此不能顶替）。认证器签的是
//! `authenticator_data || sha256(client_data_json)`，所以验签之外还要核对这两段里
//! 说的是不是「这台认证器、为这个域名、对这条消息、在同源页面上」做的断言：
//!
//! 1. `authenticator_data` 至少 37 字节，`rpIdHash == sha256(rp_id)`——钓鱼站点
//!    拿到的断言绑的是它自己的 RP ID。
//! 2. flags 有 UP 与 UV（用户在场且验证过指纹或 PIN），没有 AT（那是登记时的
//!    `create`）；只有 ED 置位时 37 字节之后才允许有扩展数据。
//! 3. `client_data_json` 反序列化进一个结构体，不走 `Value`：重复的 `type`、
//!    `challenge` 等键会被 serde 拒绝，不会出现「验的是第一个、用的是第二个」。
//! 4. `type == "webauthn.get"`，`challenge` 按 base64url（无填充）解码后等于消息。
//! 5. `crossOrigin: true` 或带 `topOrigin`（被别的站点用 iframe 嵌入）一律拒。
//! 6. `origin` is exactly `https://<rp_id>` — no subdomain, no port (ruling 51: the cloud's
//!    signing origin, e.g. `https://sign.os.khundavid.com`, is the RP ID, so a page on any other
//!    host of the domain cannot sign for it). The one exception is `rp_id == "localhost"`: `http` or
//!    `https`, with or without a port, for tests and local demos.
//! 7. 用公钥验 ECDSA P-256 / SHA-256 的 DER 签名。
//!
//! 签名计数不检查：同步型 passkey 一直报 0，而机器离线验签也无处记账。
//!
//! **ECDSA 签名可延展**：`(r, s)` 与 `(r, n - s)` 对同一消息都有效（ring 不强制
//! low-S，认证器也不保证只出 low-S），任何人都能把一份有效包的签名换成另一种字节
//! 而不让它失效。所以**有效包的签名字节与整包的哈希都不能拿来当标识**；版本由
//! 清单里的 `version` 与内容摘要（`content_digest`）标识。DER 本身由 ring 严格
//! 解析，非最短编码一律拒。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::BundleError;

/// 用户在场（User Present）。
pub const FLAG_UP: u8 = 0x01;
/// 用户已验证（User Verified：指纹、PIN）。
pub const FLAG_UV: u8 = 0x04;
/// 可备份（Backup Eligible）：私钥可能同步到 Apple/Google 账号。
pub const FLAG_BE: u8 = 0x08;
/// 已备份（Backup State）。
pub const FLAG_BS: u8 = 0x10;
/// 带了凭据数据（Attested credential data）：只出现在登记（`create`）时。
pub const FLAG_AT: u8 = 0x40;
/// 带了扩展数据（Extension Data）。
pub const FLAG_ED: u8 = 0x80;

/// `rpIdHash`（32）+ flags（1）+ 签名计数（4）。
const AUTH_DATA_MIN: usize = 37;

/// P-256 SubjectPublicKeyInfo 的固定前缀：`SEQUENCE { SEQUENCE { id-ecPublicKey,
/// prime256v1 }, BIT STRING (未压缩点) }`，后面紧跟 65 字节的点。
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// 断言为什么不成立。对外一律是 [`BundleError::BadSignature`]，这里分开是为了
/// 测试能确认每个负例确实卡在它要测的那一步。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reject {
    RpIdSyntax,
    AuthDataShort,
    RpIdHash,
    NoUp,
    NoUv,
    AtFlag,
    TrailingAuthData,
    ClientDataJson,
    Type,
    Challenge,
    CrossOrigin,
    TopOrigin,
    Origin,
    Signature,
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    ty: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
    #[serde(rename = "topOrigin", default)]
    top_origin: Option<String>,
}

/// 验一份 passkey 断言是不是对 `msg` 的有效签名。见模块文档的逐项检查。
pub fn verify(
    msg: &[u8],
    public_key: &[u8; 65],
    rp_id: &str,
    authenticator_data: &[u8],
    client_data_json: &[u8],
    der_sig: &[u8],
) -> Result<(), BundleError> {
    check(
        msg,
        public_key,
        rp_id,
        authenticator_data,
        client_data_json,
        der_sig,
    )
    .map_err(|_| BundleError::BadSignature)
}

pub(crate) fn check(
    msg: &[u8],
    public_key: &[u8; 65],
    rp_id: &str,
    authenticator_data: &[u8],
    client_data_json: &[u8],
    der_sig: &[u8],
) -> Result<(), Reject> {
    // trust 可能来自没过 validate 的地方（种子）：rp_id 在这里再查一遍。
    if !valid_rp_id(rp_id) {
        return Err(Reject::RpIdSyntax);
    }

    // 1. authenticator_data
    if authenticator_data.len() < AUTH_DATA_MIN {
        return Err(Reject::AuthDataShort);
    }
    if authenticator_data[..32] != Sha256::digest(rp_id.as_bytes())[..] {
        return Err(Reject::RpIdHash);
    }
    // 2. flags
    let fl = authenticator_data[32];
    if fl & FLAG_UP == 0 {
        return Err(Reject::NoUp);
    }
    if fl & FLAG_UV == 0 {
        return Err(Reject::NoUv);
    }
    if fl & FLAG_AT != 0 {
        return Err(Reject::AtFlag);
    }
    if fl & FLAG_ED == 0 && authenticator_data.len() != AUTH_DATA_MIN {
        return Err(Reject::TrailingAuthData);
    }

    // 3. clientDataJSON
    let cd: ClientData =
        serde_json::from_slice(client_data_json).map_err(|_| Reject::ClientDataJson)?;
    // 4.
    if cd.ty != "webauthn.get" {
        return Err(Reject::Type);
    }
    match URL_SAFE_NO_PAD.decode(&cd.challenge) {
        Ok(c) if c == msg => {}
        _ => return Err(Reject::Challenge),
    }
    // 5.
    if cd.cross_origin == Some(true) {
        return Err(Reject::CrossOrigin);
    }
    if cd.top_origin.is_some() {
        return Err(Reject::TopOrigin);
    }
    // 6.
    if !origin_ok(&cd.origin, rp_id) {
        return Err(Reject::Origin);
    }

    // 7. 签名覆盖 authenticator_data || sha256(client_data_json)；ring 自己再做一次 SHA-256。
    let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
    signed.extend_from_slice(authenticator_data);
    signed.extend_from_slice(&Sha256::digest(client_data_json));
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(&signed, der_sig)
        .map_err(|_| Reject::Signature)
}

/// `authenticator_data` 的 flags 字节；不足 37 字节时为 `None`。登记时用它记下
/// BE、BS（同步型 passkey）。
pub fn flags(authenticator_data: &[u8]) -> Option<u8> {
    if authenticator_data.len() < AUTH_DATA_MIN {
        return None;
    }
    Some(authenticator_data[32])
}

/// 从 P-256 的 SubjectPublicKeyInfo（浏览器 `getPublicKey()` 给的 DER）取出
/// 65 字节的未压缩点。别的曲线、压缩点、多余字节一律拒。
pub fn spki_to_point(spki_der: &[u8]) -> Result<[u8; 65], BundleError> {
    let bad = || {
        BundleError::Invalid(
            "The public key is not a P-256 SubjectPublicKeyInfo (uncompressed point)".into(),
        )
    };
    let point = spki_der
        .strip_prefix(&P256_SPKI_PREFIX[..])
        .ok_or_else(bad)?;
    let point: [u8; 65] = point.try_into().map_err(|_| bad())?;
    if point[0] != 0x04 {
        return Err(bad());
    }
    Ok(point)
}

/// 65 字节的点 → P-256 SubjectPublicKeyInfo DER。
pub fn point_to_spki(point: &[u8; 65]) -> Vec<u8> {
    let mut out = P256_SPKI_PREFIX.to_vec();
    out.extend_from_slice(point);
    out
}

/// RP ID 只能是小写 ASCII 主机名：点分的标签，每段 1–63 个 `[a-z0-9-]`，不以 `-`
/// 开头或结尾，全长不超过 253；不带 scheme、端口、路径，也不以点结尾。
pub fn valid_rp_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// The browser serialises an origin as `scheme://host[:port]`, without path, userinfo or a
/// trailing slash, and leaves out the default port: an exact string comparison is the whole
/// check. Before plan 6 Task 10 subdomains of the RP ID (and any port) were accepted.
fn origin_ok(origin: &str, rp_id: &str) -> bool {
    if rp_id != "localhost" {
        return origin.strip_prefix("https://") == Some(rp_id);
    }
    let Some(authority) = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
    else {
        return false;
    };
    match authority.split_once(':') {
        None => authority == "localhost",
        Some((host, p)) => {
            host == "localhost"
                && !p.is_empty()
                && p.len() <= 5
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakePasskey;
    use base64::engine::general_purpose::STANDARD;

    const RP: &str = "school.ac.th";
    const ORIGIN: &str = "https://school.ac.th";
    const OK_FLAGS: u8 = FLAG_UP | FLAG_UV;

    fn msg() -> Vec<u8> {
        let mut m = b"mastersos-bundle-v1\n".to_vec();
        m.extend_from_slice(&[7u8; 32]);
        m
    }

    fn b64url(b: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(b)
    }

    /// 浏览器的写法：键的顺序与 Chrome 一致。
    fn client_data(ty: &str, challenge: &[u8], origin: &str) -> String {
        format!(
            r#"{{"type":"{ty}","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
            b64url(challenge)
        )
    }

    struct Parts {
        pk: [u8; 65],
        ad: Vec<u8>,
        cdj: Vec<u8>,
        sig: Vec<u8>,
    }

    fn parts(p: &FakePasskey, s: &crate::SignatureFile) -> Parts {
        let tk = p.trust_key("k");
        Parts {
            pk: STANDARD.decode(&tk.public_key).unwrap().try_into().unwrap(),
            ad: STANDARD
                .decode(s.authenticator_data.as_ref().unwrap())
                .unwrap(),
            cdj: STANDARD
                .decode(s.client_data_json.as_ref().unwrap())
                .unwrap(),
            sig: STANDARD.decode(&s.sig).unwrap(),
        }
    }

    fn run(p: &FakePasskey, rp_id: &str, s: &crate::SignatureFile, m: &[u8]) -> Result<(), Reject> {
        let x = parts(p, s);
        check(m, &x.pk, rp_id, &x.ad, &x.cdj, &x.sig)
    }

    fn auth_data(rp_id: &str, flags: u8) -> Vec<u8> {
        let mut ad = Sha256::digest(rp_id.as_bytes()).to_vec();
        ad.push(flags);
        ad.extend_from_slice(&0u32.to_be_bytes());
        ad
    }

    #[test]
    fn accepts_browser_shaped_assertion() {
        let p = FakePasskey::new(RP, ORIGIN);
        let s = p.sign(&msg(), OK_FLAGS);
        assert_eq!(run(&p, RP, &s, &msg()), Ok(()));
        // 对外的 verify 同样通过；BE/BS 置位（同步型）也照收。
        let s = p.sign(&msg(), OK_FLAGS | FLAG_BE | FLAG_BS);
        let x = parts(&p, &s);
        verify(&msg(), &x.pk, RP, &x.ad, &x.cdj, &x.sig).unwrap();
        assert_eq!(flags(&x.ad), Some(OK_FLAGS | FLAG_BE | FLAG_BS));
    }

    #[test]
    fn rejects_wrong_origin() {
        let p = FakePasskey::new(RP, "https://evil.example");
        assert_eq!(
            run(&p, RP, &p.sign(&msg(), OK_FLAGS), &msg()),
            Err(Reject::Origin)
        );
    }

    #[test]
    fn rejects_wrong_rp_id_hash() {
        let p = FakePasskey::new(RP, ORIGIN);
        let cdj = client_data("webauthn.get", &msg(), ORIGIN);
        let s = p.sign_raw(&auth_data("evil.example", OK_FLAGS), cdj.as_bytes());
        assert_eq!(run(&p, RP, &s, &msg()), Err(Reject::RpIdHash));
        // 钓鱼站点自己的 rp_id 与 origin 都对得上，但机器信任的 rp_id 是学校的。
        let phish = FakePasskey::new("evil.example", "https://evil.example");
        let s = phish.sign(&msg(), OK_FLAGS);
        assert_eq!(run(&phish, RP, &s, &msg()), Err(Reject::RpIdHash));
    }

    #[test]
    fn rejects_missing_uv() {
        let p = FakePasskey::new(RP, ORIGIN);
        assert_eq!(
            run(&p, RP, &p.sign(&msg(), FLAG_UP), &msg()),
            Err(Reject::NoUv)
        );
        assert_eq!(
            run(&p, RP, &p.sign(&msg(), FLAG_UV), &msg()),
            Err(Reject::NoUp)
        );
        assert_eq!(run(&p, RP, &p.sign(&msg(), 0), &msg()), Err(Reject::NoUp));
    }

    #[test]
    fn rejects_at_flag_and_short_auth_data() {
        let p = FakePasskey::new(RP, ORIGIN);
        assert_eq!(
            run(&p, RP, &p.sign(&msg(), OK_FLAGS | FLAG_AT), &msg()),
            Err(Reject::AtFlag)
        );
        let cdj = client_data("webauthn.get", &msg(), ORIGIN);
        let mut short = auth_data(RP, OK_FLAGS);
        short.pop();
        assert_eq!(short.len(), 36);
        let s = p.sign_raw(&short, cdj.as_bytes());
        assert_eq!(run(&p, RP, &s, &msg()), Err(Reject::AuthDataShort));
        assert_eq!(flags(&short), None);
    }

    #[test]
    fn trailing_auth_data_only_with_ed_flag() {
        let p = FakePasskey::new(RP, ORIGIN);
        let cdj = client_data("webauthn.get", &msg(), ORIGIN);
        // ED 没置位却多了字节 → 拒。
        let mut ad = auth_data(RP, OK_FLAGS);
        ad.extend_from_slice(&[0xa0]);
        let s = p.sign_raw(&ad, cdj.as_bytes());
        assert_eq!(run(&p, RP, &s, &msg()), Err(Reject::TrailingAuthData));
        // ED 置位、后面是扩展数据（CBOR 空 map）→ 收。
        let mut ad = auth_data(RP, OK_FLAGS | FLAG_ED);
        ad.extend_from_slice(&[0xa0]);
        let s = p.sign_raw(&ad, cdj.as_bytes());
        assert_eq!(run(&p, RP, &s, &msg()), Ok(()));
    }

    #[test]
    fn rejects_challenge_for_other_message() {
        let p = FakePasskey::new(RP, ORIGIN);
        let s = p.sign(&msg(), OK_FLAGS);
        let mut other = msg();
        *other.last_mut().unwrap() ^= 1;
        assert_eq!(run(&p, RP, &s, &other), Err(Reject::Challenge));
        // 同一份摘要换了用途前缀（心跳、探针）也对不上。
        let mut hb = b"mastersos-heartbeat-v1\n".to_vec();
        hb.extend_from_slice(&[7u8; 32]);
        assert_eq!(run(&p, RP, &s, &hb), Err(Reject::Challenge));
        // challenge 带填充、或用标准 base64 写 → 拒。
        let padded = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}"}}"#,
            URL_SAFE_NO_PAD.encode(msg()) + "="
        );
        let s = p.sign_with_client_data(&msg(), OK_FLAGS, &padded);
        assert_eq!(run(&p, RP, &s, &msg()), Err(Reject::Challenge));
    }

    #[test]
    fn rejects_get_vs_create_type() {
        let p = FakePasskey::new(RP, ORIGIN);
        for ty in ["webauthn.create", "payment.get", "WEBAUTHN.GET", ""] {
            let s = p.sign_with_client_data(&msg(), OK_FLAGS, &client_data(ty, &msg(), ORIGIN));
            assert_eq!(run(&p, RP, &s, &msg()), Err(Reject::Type), "{ty}");
        }
    }

    /// Ruling 51: the origin is exactly `https://<rp_id>`. A subdomain, a port (even 443, which a
    /// browser never writes) or another scheme is refused; only `localhost` takes a port or http.
    #[test]
    fn webauthn_origin_must_equal_rp_id() {
        let p = FakePasskey::new(RP, "https://school.ac.th");
        assert_eq!(run(&p, RP, &p.sign(&msg(), OK_FLAGS), &msg()), Ok(()));
        for origin in [
            "https://x.school.ac.th",
            "https://mastersos.school.ac.th",
            "https://a.b.school.ac.th",
            "https://school.ac.th:443",
            "https://school.ac.th:8443",
            "https://mastersos.school.ac.th:8443",
            "http://school.ac.th",
            "https://school.ac.th/",
            "https://school.ac.th.",
        ] {
            let p = FakePasskey::new(RP, origin);
            assert_eq!(
                run(&p, RP, &p.sign(&msg(), OK_FLAGS), &msg()),
                Err(Reject::Origin),
                "{origin}"
            );
        }
        for origin in [
            "http://localhost",
            "http://localhost:5173",
            "https://localhost",
            "https://localhost:8443",
        ] {
            let p = FakePasskey::new("localhost", origin);
            assert_eq!(
                run(&p, "localhost", &p.sign(&msg(), OK_FLAGS), &msg()),
                Ok(()),
                "{origin}"
            );
        }
        for origin in [
            "http://localhost:",
            "http://localhost:0",
            "http://localhost:65536",
            "http://x.localhost",
            "http://localhost/",
            "ftp://localhost",
        ] {
            let p = FakePasskey::new("localhost", origin);
            assert_eq!(
                run(&p, "localhost", &p.sign(&msg(), OK_FLAGS), &msg()),
                Err(Reject::Origin),
                "{origin}"
            );
        }
    }

    #[test]
    fn malformed_origins_rejected() {
        for origin in [
            "https://mastersos.school.ac.th/",
            "https://mastersos.school.ac.th/x",
            "https://mastersos.school.ac.th:",
            "https://mastersos.school.ac.th:0",
            "https://mastersos.school.ac.th:65536",
            "https://mastersos.school.ac.th:84a3",
            "https://mastersos.school.ac.th:8443:1",
            "https://user@mastersos.school.ac.th",
            "https://evil.example@school.ac.th",
            "https://evil.example#.school.ac.th",
            "https://evil.example?.school.ac.th",
            "https://evil.example/.school.ac.th",
            "https://MASTERSOS.school.ac.th",
            "https://school.ac.th.evil.example",
            "https://.school.ac.th",
            "https://ac.th",
            "ftp://mastersos.school.ac.th",
            "mastersos.school.ac.th",
            "android:apk-key-hash:abc",
            "null",
        ] {
            let p = FakePasskey::new(RP, origin);
            assert_eq!(
                run(&p, RP, &p.sign(&msg(), OK_FLAGS), &msg()),
                Err(Reject::Origin),
                "{origin}"
            );
        }
    }

    #[test]
    fn cross_origin_rejected() {
        let p = FakePasskey::new(RP, ORIGIN);
        let ch = b64url(&msg());
        let cross = format!(
            r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"{ORIGIN}","crossOrigin":true}}"#
        );
        let s = p.sign_with_client_data(&msg(), OK_FLAGS, &cross);
        assert_eq!(run(&p, RP, &s, &msg()), Err(Reject::CrossOrigin));
        let top = format!(
            r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"{ORIGIN}","crossOrigin":false,"topOrigin":"https://evil.example"}}"#
        );
        let s = p.sign_with_client_data(&msg(), OK_FLAGS, &top);
        assert_eq!(run(&p, RP, &s, &msg()), Err(Reject::TopOrigin));
        // 没有 crossOrigin 键（老浏览器）、或是 null → 收。
        for cd in [
            format!(r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"{ORIGIN}"}}"#),
            format!(
                r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"{ORIGIN}","crossOrigin":null}}"#
            ),
        ] {
            let s = p.sign_with_client_data(&msg(), OK_FLAGS, &cd);
            assert_eq!(run(&p, RP, &s, &msg()), Ok(()), "{cd}");
        }
    }

    #[test]
    fn duplicate_challenge_key_rejected() {
        let p = FakePasskey::new(RP, ORIGIN);
        let mut other = msg();
        other[0] ^= 1;
        let dup = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}","challenge":"{}"}}"#,
            b64url(&other),
            b64url(&msg())
        );
        let s = p.sign_with_client_data(&msg(), OK_FLAGS, &dup);
        assert_eq!(run(&p, RP, &s, &msg()), Err(Reject::ClientDataJson));
        // 两个 type、两个 origin 同样拒。
        let ch = b64url(&msg());
        for cd in [
            format!(
                r#"{{"type":"webauthn.create","type":"webauthn.get","challenge":"{ch}","origin":"{ORIGIN}"}}"#
            ),
            format!(
                r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"https://evil.example","origin":"{ORIGIN}"}}"#
            ),
        ] {
            let s = p.sign_with_client_data(&msg(), OK_FLAGS, &cd);
            assert_eq!(run(&p, RP, &s, &msg()), Err(Reject::ClientDataJson), "{cd}");
        }
        // 未知字段照常忽略；不是 JSON、缺 origin 都拒。
        let extra = format!(
            r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"{ORIGIN}","other_keys_can_be_added_here":"x"}}"#
        );
        let s = p.sign_with_client_data(&msg(), OK_FLAGS, &extra);
        assert_eq!(run(&p, RP, &s, &msg()), Ok(()));
        for cd in [
            "not json".to_string(),
            format!(r#"{{"type":"webauthn.get","challenge":"{ch}"}}"#),
            format!(r#"[{{"type":"webauthn.get","challenge":"{ch}","origin":"{ORIGIN}"}}]"#),
        ] {
            let s = p.sign_with_client_data(&msg(), OK_FLAGS, &cd);
            assert_eq!(run(&p, RP, &s, &msg()), Err(Reject::ClientDataJson), "{cd}");
        }
    }

    #[test]
    fn localhost_http_only_for_localhost_rp() {
        let p = FakePasskey::new("localhost", "http://localhost:5173");
        assert_eq!(
            run(&p, "localhost", &p.sign(&msg(), OK_FLAGS), &msg()),
            Ok(())
        );
        let p = FakePasskey::new("localhost", "https://localhost");
        assert_eq!(
            run(&p, "localhost", &p.sign(&msg(), OK_FLAGS), &msg()),
            Ok(())
        );
        let p = FakePasskey::new(RP, "http://mastersos.school.ac.th");
        assert_eq!(
            run(&p, RP, &p.sign(&msg(), OK_FLAGS), &msg()),
            Err(Reject::Origin)
        );
        // With rp_id localhost, only localhost itself.
        let p = FakePasskey::new("localhost", "http://evil.example");
        assert_eq!(
            run(&p, "localhost", &p.sign(&msg(), OK_FLAGS), &msg()),
            Err(Reject::Origin)
        );
    }

    #[test]
    fn suffix_trick_rejected() {
        let p = FakePasskey::new(RP, "https://evilschool.ac.th");
        assert_eq!(
            run(&p, RP, &p.sign(&msg(), OK_FLAGS), &msg()),
            Err(Reject::Origin)
        );
    }

    #[test]
    fn rejects_invalid_rp_id_argument() {
        // trust 来自种子时没过 validate：rp_id 在 verify 里再查。
        let p = FakePasskey::new("School.ac.th", "https://school.ac.th");
        assert_eq!(
            run(&p, "School.ac.th", &p.sign(&msg(), OK_FLAGS), &msg()),
            Err(Reject::RpIdSyntax)
        );
    }

    #[test]
    fn rejects_other_key_and_tampered_parts() {
        let p = FakePasskey::new(RP, ORIGIN);
        let q = FakePasskey::new(RP, ORIGIN);
        let s = p.sign(&msg(), OK_FLAGS);
        let x = parts(&p, &s);
        let y = parts(&q, &q.sign(&msg(), OK_FLAGS));
        assert_eq!(
            check(&msg(), &y.pk, RP, &x.ad, &x.cdj, &x.sig),
            Err(Reject::Signature)
        );
        // 签名计数改了 → 签名不再覆盖。
        let mut ad = x.ad.clone();
        ad[36] ^= 1;
        assert_eq!(
            check(&msg(), &x.pk, RP, &ad, &x.cdj, &x.sig),
            Err(Reject::Signature)
        );
        // clientDataJSON 末尾加空白：仍是同样的 JSON，但哈希变了。
        let mut cdj = x.cdj.clone();
        cdj.push(b' ');
        assert_eq!(
            check(&msg(), &x.pk, RP, &x.ad, &cdj, &x.sig),
            Err(Reject::Signature)
        );
        // 不在曲线上的点。
        let mut pk = x.pk;
        pk[64] ^= 1;
        assert_eq!(
            check(&msg(), &pk, RP, &x.ad, &x.cdj, &x.sig),
            Err(Reject::Signature)
        );
        // 原始 64 字节 r||s（不是 DER）→ 拒。
        let (r, s_) = der_to_rs(&x.sig);
        let raw: Vec<u8> = r.iter().chain(s_.iter()).copied().collect();
        assert_eq!(
            check(&msg(), &x.pk, RP, &x.ad, &x.cdj, &raw),
            Err(Reject::Signature)
        );
    }

    // —— DER 与 low-S ——

    /// P-256 的阶 n。
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];

    fn der_to_rs(der: &[u8]) -> ([u8; 32], [u8; 32]) {
        assert_eq!(der[0], 0x30);
        assert_eq!(der[1] as usize, der.len() - 2);
        let mut i = 2;
        let mut ints = Vec::new();
        for _ in 0..2 {
            assert_eq!(der[i], 0x02);
            let len = der[i + 1] as usize;
            let v = &der[i + 2..i + 2 + len];
            let v = if v.len() == 33 { &v[1..] } else { v };
            let mut out = [0u8; 32];
            out[32 - v.len()..].copy_from_slice(v);
            ints.push(out);
            i += 2 + len;
        }
        (ints[0], ints[1])
    }

    /// 最短 DER 整数；`pad` 额外多垫一个 0x00（非最短编码）。
    fn der_int(v: &[u8; 32], pad: bool) -> Vec<u8> {
        let mut b: Vec<u8> = v.iter().copied().skip_while(|&x| x == 0).collect();
        if b.is_empty() || b[0] & 0x80 != 0 {
            b.insert(0, 0);
        }
        if pad {
            b.insert(0, 0);
        }
        let mut out = vec![0x02, b.len() as u8];
        out.extend(b);
        out
    }

    fn rs_to_der(r: &[u8; 32], s: &[u8; 32], pad_r: bool) -> Vec<u8> {
        let body: Vec<u8> = der_int(r, pad_r)
            .into_iter()
            .chain(der_int(s, false))
            .collect();
        let mut out = vec![0x30, body.len() as u8];
        out.extend(body);
        out
    }

    fn n_minus(s: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let mut d = N[i] as i16 - s[i] as i16 - borrow;
            borrow = if d < 0 {
                d += 256;
                1
            } else {
                0
            };
            out[i] = d as u8;
        }
        assert_eq!(borrow, 0);
        out
    }

    #[test]
    fn der_must_be_canonical_and_high_s_is_malleable() {
        let p = FakePasskey::new(RP, ORIGIN);
        let s = p.sign(&msg(), OK_FLAGS);
        let x = parts(&p, &s);
        let (r, sv) = der_to_rs(&x.sig);
        // 自己重编码的最短 DER 与原签名一致，且验得过。
        assert_eq!(rs_to_der(&r, &sv, false), x.sig);
        // r 多垫一个 0x00 → 非最短编码，拒。
        let padded = rs_to_der(&r, &sv, true);
        assert_eq!(
            check(&msg(), &x.pk, RP, &x.ad, &x.cdj, &padded),
            Err(Reject::Signature)
        );
        // (r, n - s) 同样有效：签名可延展，所以签名字节不能当标识（见模块文档）。
        let flipped = rs_to_der(&r, &n_minus(&sv), false);
        assert_ne!(flipped, x.sig);
        assert_eq!(check(&msg(), &x.pk, RP, &x.ad, &x.cdj, &flipped), Ok(()));
    }

    #[test]
    fn spki_roundtrip() {
        let p = FakePasskey::new(RP, ORIGIN);
        let pk: [u8; 65] = STANDARD
            .decode(p.trust_key("k").public_key)
            .unwrap()
            .try_into()
            .unwrap();
        let spki = point_to_spki(&pk);
        assert_eq!(spki.len(), 91);
        assert_eq!(spki_to_point(&spki).unwrap(), pk);
        // 少一个字节、多一个字节、换了曲线 OID、压缩点 → 拒。
        let mut longer = spki.clone();
        longer.push(0);
        let mut other_curve = spki.clone();
        other_curve[22] ^= 1;
        let mut compressed = spki.clone();
        compressed[26] = 0x02;
        for bad in [
            &spki[..90],
            &longer[..],
            &other_curve[..],
            &compressed[..],
            &[][..],
        ] {
            assert!(matches!(spki_to_point(bad), Err(BundleError::Invalid(_))));
        }
    }

    #[test]
    fn rp_id_syntax() {
        for ok in ["school.ac.th", "localhost", "a-b.c1.d", "x", "123.example"] {
            assert!(valid_rp_id(ok), "{ok}");
        }
        for bad in [
            "",
            "School.ac.th",
            "school.ac.th.",
            "a..b",
            "-a.b",
            "a-.b",
            "a_b.c",
            "a b",
            "a:1",
            "a/b",
        ] {
            assert!(!valid_rp_id(bad), "{bad}");
        }
        assert!(valid_rp_id(&"a".repeat(63)));
        assert!(!valid_rp_id(&"a".repeat(64)));
    }

    // —— 固化的向量 ——

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Vector {
        name: String,
        rp_id: String,
        /// 标准 base64，65 字节点。
        public_key: String,
        /// 标准 base64。
        msg: String,
        authenticator_data: String,
        client_data_json: String,
        sig: String,
    }

    const VECTORS: &str = include_str!("../testdata/webauthn-vectors.json");

    fn decode(s: &str) -> Vec<u8> {
        STANDARD.decode(s).unwrap()
    }

    #[test]
    fn fixed_vectors_verify() {
        let vs: Vec<Vector> = serde_json::from_str(VECTORS).unwrap();
        assert!(vs.len() >= 4);
        for v in &vs {
            let pk: [u8; 65] = decode(&v.public_key).try_into().unwrap();
            let fields = [
                decode(&v.msg),
                pk.to_vec(),
                decode(&v.authenticator_data),
                decode(&v.client_data_json),
                decode(&v.sig),
            ];
            let go = |f: &[Vec<u8>; 5]| {
                let pk: [u8; 65] = f[1].clone().try_into().unwrap();
                verify(&f[0], &pk, &v.rp_id, &f[2], &f[3], &f[4])
            };
            go(&fields).unwrap_or_else(|e| panic!("{}：{e}", v.name));
            // 任何一段、任何一个字节改一位都验不过。
            for which in 0..5 {
                for i in 0..fields[which].len() {
                    let mut f = fields.clone();
                    f[which][i] ^= 0x01;
                    assert_eq!(
                        go(&f),
                        Err(BundleError::BadSignature),
                        "{} 第 {which} 段第 {i} 字节",
                        v.name
                    );
                }
            }
        }
    }

    /// 重新生成 `testdata/` 下的两份向量。平时不跑：`cargo test -p mastersos-bundle
    /// regenerate_vectors -- --ignored`。
    #[test]
    #[ignore]
    fn regenerate_vectors() {
        use std::collections::BTreeMap;

        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata");
        std::fs::create_dir_all(dir).unwrap();

        let mut out = Vec::new();
        let cases: [(&str, &str, &str, u8, Option<String>); 5] = [
            ("plain", RP, ORIGIN, OK_FLAGS, None),
            (
                "port",
                "localhost",
                "https://localhost:8443",
                OK_FLAGS,
                None,
            ),
            (
                "synced-passkey-be-bs",
                RP,
                ORIGIN,
                OK_FLAGS | FLAG_BE | FLAG_BS,
                None,
            ),
            (
                "localhost-http",
                "localhost",
                "http://localhost:5173",
                OK_FLAGS,
                None,
            ),
            (
                "extra-client-data-fields",
                RP,
                "https://school.ac.th",
                OK_FLAGS,
                Some(format!(
                    r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://school.ac.th","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}}"#,
                    b64url(&msg())
                )),
            ),
        ];
        for (name, rp, origin, fl, cd) in cases {
            let p = FakePasskey::new(rp, origin);
            let s = match cd {
                Some(cd) => p.sign_with_client_data(&msg(), fl, &cd),
                None => p.sign(&msg(), fl),
            };
            out.push(Vector {
                name: name.into(),
                rp_id: rp.into(),
                public_key: p.trust_key("k").public_key,
                msg: STANDARD.encode(msg()),
                authenticator_data: s.authenticator_data.unwrap(),
                client_data_json: s.client_data_json.unwrap(),
                sig: s.sig,
            });
        }
        std::fs::write(
            format!("{dir}/webauthn-vectors.json"),
            serde_json::to_string_pretty(&out).unwrap() + "\n",
        )
        .unwrap();

        // 内容摘要向量：网页与 mastersos-sign 自己重算摘要时对照用。
        let mut digests = Vec::new();
        let mut push = |name: &str, manifest_text: &str, files: Vec<(&str, Vec<u8>)>| {
            let mut c = crate::Contents {
                manifest_text: manifest_text.into(),
                files: BTreeMap::new(),
            };
            let mut json_files = serde_json::Map::new();
            for (path, data) in files {
                json_files.insert(path.into(), STANDARD.encode(&data).into());
                c.files.insert(path.into(), data);
            }
            let hex: String = crate::content_digest(&c)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            digests.push(serde_json::json!({
                "name": name,
                "manifest_text": manifest_text,
                "files": json_files,
                "digest_hex": hex,
            }));
        };
        push("manifest-only", "version = 1\n", vec![]);
        push(
            "cjk-and-control-chars",
            "version = 2\n# 教室\t设置\u{1}\u{7f}\r\n[[group]]\nid = \"default\"\nname = \"未分组\"\n",
            vec![("files/说明.txt", "你好\u{2}\n".as_bytes().to_vec())],
        );
        // 插入顺序与字节序不同；摘要按路径字节序排列，与插入顺序无关。
        push(
            "multi-file-unordered",
            "version = 3\n",
            vec![
                ("scripts/z.sh", b"#!/bin/sh\necho z\n".to_vec()),
                ("files/b/c.txt", b"c".to_vec()),
                ("files/a.txt", b"a".to_vec()),
                ("files/B.txt", vec![0, 255, 1, 254]),
            ],
        );
        push(
            "empty-file",
            "version = 4\n",
            vec![("files/empty", Vec::new())],
        );
        // UTF-16 码元序（😀 的 D83D 在前）与 UTF-8 字节序（ｚ 的 EF 在前）相反：
        // 网页用 JS 默认排序会算错，必须先编码再比字节。
        push(
            "non-ascii-paths-utf8-order",
            "version = 5\n",
            vec![
                ("files/😀.txt", b"smile".to_vec()),
                ("files/ｚ.txt", b"zed".to_vec()),
            ],
        );
        std::fs::write(
            format!("{dir}/digest-vectors.json"),
            serde_json::to_string_pretty(&digests).unwrap() + "\n",
        )
        .unwrap();
    }
}
