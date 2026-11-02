//! The escrow request body: the agent sends it, the server takes it (`POST /v1/escrow`).
//!
//! Escrow is sealed only (plan 6 design §6.2, rulings 11, 27): the machine encrypts its LUKS
//! recovery key with age to every recipient of `[school].escrow_recipients` ([`seal`]) and sends
//! the ASCII-armored ciphertext (`recovery_key_age`, at most [`SEALED_MAX`] bytes) with the
//! recipients' fingerprint ([`recipients_fp`]). A body that carries a plaintext `recovery_key`
//! is refused ([`EscrowRequest::from_json`]). `escrow_secret` is this machine's escrow
//! credential: it never reaches `Debug` or an error message.

use std::fmt;
use std::io::Write as _;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::BundleError;

/// The systemd recovery key alphabet (modhex).
const MODHEX: &[u8] = b"cbdefghijklnrtuv";
/// `device_id` 最长的字节数。
pub const DEVICE_ID_MAX: usize = 128;
/// `serial` 最长的字节数。
pub const SERIAL_MAX: usize = 128;
/// The largest sealed recovery key accepted (bytes of ASCII armor). Sealed to the most
/// recipients a manifest may list it stays well under this.
pub const SEALED_MAX: usize = 2 * 1024;
/// The first line of age's ASCII armor.
pub const AGE_ARMOR_BEGIN: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
/// The last line of age's ASCII armor.
pub const AGE_ARMOR_END: &str = "-----END AGE ENCRYPTED FILE-----";
/// Domain prefix of [`recipients_fp`].
const RECIPIENTS_FP_PREFIX: &[u8] = b"mastersos-escrow-recipients-v1\n";

/// What [`EscrowRequest::from_json`] says about a body with a plaintext recovery key.
pub const PLAINTEXT_ESCROW_REFUSED: &str =
    "plaintext escrow is refused: seal the recovery key with \
    age to the school's escrow recipients and send it as recovery_key_age with recipients_fp";
/// What [`EscrowRequest::from_json`] says about any other body it cannot read.
pub const ESCROW_BODY_INVALID: &str =
    "the body is not an escrow request (JSON: device_id, serial, \
    luks_uuid, recovery_key_age, recipients_fp, escrow_secret)";

/// `POST /v1/escrow` 的请求体。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct EscrowRequest {
    pub device_id: String,
    #[serde(default)]
    pub serial: Option<String>,
    /// 数据分区 LUKS 头的 UUID，小写带横线。
    pub luks_uuid: String,
    /// The systemd recovery key (8 groups of 8 modhex characters) encrypted with age to every
    /// escrow recipient of the latest accepted bundle, ASCII armor, at most 2 KiB.
    pub recovery_key_age: String,
    /// [`recipients_fp`] of the recipients it was sealed to: 64 lowercase hex digits.
    pub recipients_fp: String,
    /// 这台机器的托管凭据：32 字节随机数的 base64url（无填充）。
    pub escrow_secret: String,
}

impl fmt::Debug for EscrowRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EscrowRequest")
            .field("device_id", &self.device_id)
            .field("serial", &self.serial)
            .field("luks_uuid", &self.luks_uuid)
            .field(
                "recovery_key_age",
                &format_args!("<{} bytes sealed>", self.recovery_key_age.len()),
            )
            .field("recipients_fp", &self.recipients_fp)
            .field("escrow_secret", &"<redacted>")
            .finish()
    }
}

/// 8 组、每组 8 个 modhex 字符、`-` 连接。
pub fn is_recovery_key(s: &str) -> bool {
    s.len() == 8 * 8 + 7
        && s.split('-').count() == 8
        && s.split('-')
            .all(|g| g.len() == 8 && g.bytes().all(|b| MODHEX.contains(&b)))
}

/// 小写、带横线的 8-4-4-4-12 UUID。
pub fn is_luks_uuid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && g.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// The fingerprint of a set of escrow recipients: sha256 over
/// `"mastersos-escrow-recipients-v1\n"` and the recipients sorted and deduplicated, one per line,
/// as 64 lowercase hex digits. The order the manifest lists them in does not matter.
pub fn recipients_fp(recipients: &[String]) -> String {
    let set: std::collections::BTreeSet<&str> = recipients.iter().map(String::as_str).collect();
    let mut h = Sha256::new();
    h.update(RECIPIENTS_FP_PREFIX);
    for (i, r) in set.iter().enumerate() {
        if i > 0 {
            h.update(b"\n");
        }
        h.update(r.as_bytes());
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether `s` looks like a [`recipients_fp`]: 64 lowercase hex digits.
pub fn is_recipients_fp(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Encrypt `recovery_key` with age to every one of `recipients` (age X25519, `age1…`, as
/// [`checks::escrow_recipients`](crate::checks::escrow_recipients) requires them, at least one)
/// and return the ASCII armor. Errors never carry the key.
pub fn seal(recovery_key: &str, recipients: &[String]) -> Result<String, BundleError> {
    if recipients.is_empty() {
        return bad("no escrow recipients to seal to");
    }
    crate::checks::escrow_recipients(recipients).map_err(BundleError::Invalid)?;
    let parsed: Vec<age::x25519::Recipient> = recipients
        .iter()
        .map(|r| {
            r.parse()
                .map_err(|_| BundleError::Invalid("bad escrow recipient".into()))
        })
        .collect::<Result<_, _>>()?;
    let encryptor =
        age::Encryptor::with_recipients(parsed.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|_| BundleError::Invalid("cannot seal to these recipients".into()))?;
    let io = |_| BundleError::Io("sealing the recovery key failed".into());
    let mut out = Vec::with_capacity(SEALED_MAX);
    let armor = age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor)
        .map_err(io)?;
    let mut w = encryptor.wrap_output(armor).map_err(io)?;
    w.write_all(recovery_key.as_bytes()).map_err(io)?;
    w.finish().map_err(io)?.finish().map_err(io)?;
    let text =
        String::from_utf8(out).map_err(|_| BundleError::Io("age armor is not text".into()))?;
    if text.len() > SEALED_MAX {
        return bad("the sealed recovery key is larger than 2 KiB");
    }
    Ok(text)
}

/// Whether `s` is an age file in ASCII armor of at most [`SEALED_MAX`] bytes whose header
/// parses and names recipients (not a passphrase). It is not decrypted: the server cannot.
pub fn is_sealed(s: &str) -> bool {
    if s.len() > SEALED_MAX
        || !s.starts_with(AGE_ARMOR_BEGIN)
        || !s.trim_end().ends_with(AGE_ARMOR_END)
        || !s
            .bytes()
            .all(|b| b.is_ascii_graphic() || matches!(b, b' ' | b'\n' | b'\r'))
    {
        return false;
    }
    age::Decryptor::new(age::armor::ArmoredReader::new(s.as_bytes())).is_ok_and(|d| !d.is_scrypt())
}

/// How many X25519 recipient stanzas the header of an armored age file has. `None` when it is not
/// an armored age file, or a stanza has another type; grease stanzas (`<random>-grease`, which age
/// writes to keep parsers honest) are skipped. The stanzas do not name their recipients, so this
/// can only tell how many recipients a file was sealed to, not which.
pub fn x25519_stanza_count(armor: &str) -> Option<usize> {
    let body: String = armor
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(body)
        .ok()?;
    let end = bytes.windows(4).position(|w| w == b"\n---")?;
    let header = std::str::from_utf8(&bytes[..end]).ok()?;
    let mut lines = header.split('\n');
    if lines.next()? != "age-encryption.org/v1" {
        return None;
    }
    let mut n = 0;
    for line in lines {
        if let Some(rest) = line.strip_prefix("-> ") {
            match rest.split(' ').next()? {
                "X25519" => n += 1,
                tag if tag.ends_with("-grease") => {}
                _ => return None,
            }
        }
    }
    Some(n)
}

fn bad<T>(m: &str) -> Result<T, BundleError> {
    Err(BundleError::Invalid(m.to_owned()))
}

/// `device_id`：不空、不超过 [`DEVICE_ID_MAX`] 字节、没有控制字符。
fn check_device_id(device_id: &str) -> Result<(), BundleError> {
    if device_id.trim().is_empty() || device_id.len() > DEVICE_ID_MAX {
        return bad("device_id must not be empty and at most 128 bytes");
    }
    if device_id.chars().any(char::is_control) {
        return bad("device_id must not contain control characters");
    }
    Ok(())
}

/// Whether `secret` has the form of an escrow secret (also the push secret): 32 bytes of
/// base64url without padding.
pub fn is_escrow_secret(secret: &str) -> bool {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(secret)
        .is_ok_and(|b| b.len() == 32)
}

/// 托管凭据：32 字节的 base64url（无填充）。
fn check_escrow_secret(secret: &str) -> Result<(), BundleError> {
    if !is_escrow_secret(secret) {
        return bad("escrow_secret must be 32 bytes of base64url without padding");
    }
    Ok(())
}

impl EscrowRequest {
    /// Read a request body. Errors are fixed English texts that never echo the body (serde's
    /// errors would quote field values): [`PLAINTEXT_ESCROW_REFUSED`] when it carries a
    /// plaintext `recovery_key`, [`ESCROW_BODY_INVALID`] for anything else that does not parse.
    /// The caller still runs [`EscrowRequest::validate`].
    pub fn from_json(body: &[u8]) -> Result<EscrowRequest, BundleError> {
        match serde_json::from_slice::<EscrowRequest>(body) {
            Ok(r) => Ok(r),
            Err(_) => {
                let plaintext = serde_json::from_slice::<serde_json::Value>(body)
                    .ok()
                    .is_some_and(|v| v.get("recovery_key").is_some());
                bad(if plaintext {
                    PLAINTEXT_ESCROW_REFUSED
                } else {
                    ESCROW_BODY_INVALID
                })
            }
        }
    }

    /// Check every field's format. Errors name the field, **never its value**.
    pub fn validate(&self) -> Result<(), BundleError> {
        check_device_id(&self.device_id)?;
        if let Some(s) = &self.serial {
            if s.len() > SERIAL_MAX || s.chars().any(char::is_control) {
                return bad("serial must be at most 128 bytes without control characters");
            }
        }
        if !is_luks_uuid(&self.luks_uuid) {
            return bad("luks_uuid must be a lowercase UUID with dashes");
        }
        if !is_sealed(&self.recovery_key_age) {
            return bad(
                "recovery_key_age must be an age file in ASCII armor sealed to recipients, at most 2 KiB",
            );
        }
        if !is_recipients_fp(&self.recipients_fp) {
            return bad("recipients_fp must be 64 lowercase hex digits");
        }
        check_escrow_secret(&self.escrow_secret)
    }
}

/// `POST /v1/fetch-token` 的请求体（计划 4b Task 2，Ruling 20）：机器凭自己的托管凭据换领当前的
/// `fetch_token`。`escrow_secret` 不进 `Debug`、不进任何错误信息。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct FetchTokenRequest {
    pub device_id: String,
    /// 这台机器的托管凭据（`identity.json`），与 [`EscrowRequest::escrow_secret`] 同一个。
    pub escrow_secret: String,
}

impl fmt::Debug for FetchTokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchTokenRequest")
            .field("device_id", &self.device_id)
            .field("escrow_secret", &"<redacted>")
            .finish()
    }
}

impl FetchTokenRequest {
    /// 与 [`EscrowRequest::validate`] 同样的规则；错误信息不带字段的值。
    pub fn validate(&self) -> Result<(), BundleError> {
        check_device_id(&self.device_id)?;
        check_escrow_secret(&self.escrow_secret)
    }
}

/// `POST /v1/fetch-token` 的 200 响应：服务端当前的 `fetch_token`。不进 `Debug`。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FetchTokenResponse {
    pub fetch_token: String,
}

impl fmt::Debug for FetchTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchTokenResponse")
            .field("fetch_token", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kit::Kit;

    const KEY: &str = "cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv";
    const UUID: &str = "0b9e3c1a-5d2f-4e6a-9c1b-2f3e4d5c6b7a";

    fn kit(b: u8) -> Kit {
        Kit::from_master(&[b; 32])
    }

    fn req() -> EscrowRequest {
        let recipients = vec![kit(1).escrow_recipient()];
        EscrowRequest {
            device_id: "dev-1".into(),
            serial: Some("SN1".into()),
            luks_uuid: UUID.into(),
            recovery_key_age: seal(KEY, &recipients).unwrap(),
            recipients_fp: recipients_fp(&recipients),
            escrow_secret: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
        }
    }

    #[test]
    fn recovery_key_format() {
        assert!(is_recovery_key(KEY));
        for k in [
            "",
            "cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi",
            "abdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv",
            "CBDEFGHI-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv",
            "cbdefgh-ijklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv",
        ] {
            assert!(!is_recovery_key(k), "{k:?}");
        }
    }

    /// The body carries only the sealed form: a plaintext `recovery_key` is refused with a fixed
    /// English text that never echoes the key, and so is a body with both.
    #[test]
    fn escrow_request_sealed_only() {
        let r = req();
        r.validate().unwrap();
        let body = serde_json::to_vec(&r).unwrap();
        assert_eq!(EscrowRequest::from_json(&body).unwrap(), r);

        let plain = serde_json::json!({
            "device_id": "dev-1", "luks_uuid": UUID, "recovery_key": KEY,
            "escrow_secret": r.escrow_secret,
        });
        let mut both = serde_json::to_value(&r).unwrap();
        both["recovery_key"] = KEY.into();
        for v in [plain, both] {
            let e = EscrowRequest::from_json(&serde_json::to_vec(&v).unwrap()).unwrap_err();
            let msg = e.to_string();
            assert!(msg.contains(PLAINTEXT_ESCROW_REFUSED), "{msg}");
            assert!(!msg.contains(KEY), "{msg}");
        }
        // Anything else unreadable gets the other fixed text, without the values.
        let mut wrong = serde_json::to_value(&r).unwrap();
        wrong["luks_uuid"] = 5.into();
        wrong["device_id"] = "zz-secret-zz".into();
        let msg = EscrowRequest::from_json(&serde_json::to_vec(&wrong).unwrap())
            .unwrap_err()
            .to_string();
        assert!(msg.contains(ESCROW_BODY_INVALID), "{msg}");
        assert!(!msg.contains("zz-secret-zz"), "{msg}");
        assert!(EscrowRequest::from_json(b"not json").is_err());

        // A plaintext key in the sealed field is not sealed.
        let r2 = EscrowRequest {
            recovery_key_age: KEY.into(),
            ..req()
        };
        let msg = r2.validate().unwrap_err().to_string();
        assert!(msg.contains("recovery_key_age"), "{msg}");
        assert!(!msg.contains(KEY), "{msg}");
        // Armor around something that is not an age file, a passphrase file, too large.
        let junk = format!("{AGE_ARMOR_BEGIN}\nAAAA\n{AGE_ARMOR_END}\n");
        let scrypt = {
            let e = age::Encryptor::with_user_passphrase(age::secrecy::SecretString::from(
                "pass".to_owned(),
            ));
            let mut out = Vec::new();
            let a =
                age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor)
                    .unwrap();
            let mut w = e.wrap_output(a).unwrap();
            w.write_all(KEY.as_bytes()).unwrap();
            w.finish().unwrap().finish().unwrap();
            String::from_utf8(out).unwrap()
        };
        let big = {
            let s = req().recovery_key_age;
            let pad = "A".repeat(SEALED_MAX);
            s.replacen('\n', &format!("\n{pad}\n"), 1)
        };
        for s in [junk, scrypt, big, String::new()] {
            assert!(!is_sealed(&s), "{s:?}");
        }
        for fp in ["", "ABC", &"g".repeat(64), &"a".repeat(63), &"A".repeat(64)] {
            let r = EscrowRequest {
                recipients_fp: fp.to_string(),
                ..req()
            };
            assert!(r.validate().is_err(), "fp {fp:?}");
        }
        for u in [
            "0B9E3C1A-5D2F-4E6A-9C1B-2F3E4D5C6B7A",
            "0b9e3c1a5d2f4e6a9c1b2f3e4d5c6b7a",
            "",
        ] {
            let r = EscrowRequest {
                luks_uuid: u.into(),
                ..req()
            };
            assert!(r.validate().is_err(), "uuid {u:?}");
        }
        for d in ["", "  ", &"x".repeat(129), "a\nb"] {
            let r = EscrowRequest {
                device_id: d.to_string(),
                ..req()
            };
            assert!(r.validate().is_err(), "device_id {d:?}");
        }
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        for s in [
            b64.encode([1u8; 31]),
            base64::engine::general_purpose::URL_SAFE.encode([1u8; 32]),
            String::new(),
        ] {
            let r = EscrowRequest {
                escrow_secret: s.clone(),
                ..req()
            };
            let msg = r.validate().unwrap_err().to_string();
            assert!(s.is_empty() || !msg.contains(&s), "{msg}");
        }
    }

    #[test]
    fn recipients_fp_order_independent() {
        let (a, b, c) = (
            kit(1).escrow_recipient(),
            kit(2).escrow_recipient(),
            kit(3).escrow_recipient(),
        );
        let fp = recipients_fp(&[a.clone(), b.clone(), c.clone()]);
        assert!(is_recipients_fp(&fp), "{fp}");
        assert_eq!(fp, recipients_fp(&[c.clone(), a.clone(), b.clone()]));
        assert_eq!(
            fp,
            recipients_fp(&[b.clone(), a.clone(), c.clone(), a.clone()])
        );
        assert_ne!(fp, recipients_fp(&[a.clone(), b.clone()]));
        assert_ne!(
            recipients_fp(std::slice::from_ref(&a)),
            recipients_fp(std::slice::from_ref(&b))
        );
        // One recipient cannot pose as the concatenation of two: the hash joins the sorted
        // recipients with line breaks, so it relies on a valid recipient never holding one.
        // (Comparing the two hashes only held while the derived keys happened to sort b < a.)
        assert!(crate::checks::escrow_recipients(&[format!("{a}\n{b}")]).is_err());
    }

    #[test]
    fn seal_then_open_with_kit() {
        let recipients: Vec<String> = (1..=8).map(|i| kit(i).escrow_recipient()).collect();
        let sealed = seal(KEY, &recipients).unwrap();
        assert!(sealed.starts_with(AGE_ARMOR_BEGIN), "{sealed}");
        assert!(sealed.len() <= SEALED_MAX, "{}", sealed.len());
        assert!(is_sealed(&sealed));
        assert!(!sealed.contains(KEY));
        for i in 1..=8 {
            let opened = age::decrypt(&kit(i).escrow_identity(), sealed.as_bytes()).unwrap();
            assert_eq!(opened, KEY.as_bytes());
        }
        assert!(age::decrypt(&kit(9).escrow_identity(), sealed.as_bytes()).is_err());
        // Sealing twice gives different ciphertexts (fresh file key and ephemeral shares).
        assert_ne!(
            seal(KEY, &recipients[..1]).unwrap(),
            seal(KEY, &recipients[..1]).unwrap()
        );
        // No recipients, a bad one, nine: refused, without the key in the error.
        for list in [
            vec![],
            vec!["age1nope".to_owned()],
            (1..=9).map(|i| kit(i).escrow_recipient()).collect(),
        ] {
            let msg = seal(KEY, &list).unwrap_err().to_string();
            assert!(!msg.contains(KEY), "{msg}");
        }
    }

    #[test]
    fn x25519_stanzas_counted() {
        for n in 1..=8u8 {
            let to: Vec<String> = (1..=n).map(|i| kit(i).escrow_recipient()).collect();
            assert_eq!(
                x25519_stanza_count(&seal(KEY, &to).unwrap()),
                Some(n as usize)
            );
        }
        let scrypt = {
            let e = age::Encryptor::with_user_passphrase(age::secrecy::SecretString::from(
                "pass".to_owned(),
            ));
            let mut out = Vec::new();
            let a =
                age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor)
                    .unwrap();
            let mut w = e.wrap_output(a).unwrap();
            w.write_all(KEY.as_bytes()).unwrap();
            w.finish().unwrap().finish().unwrap();
            String::from_utf8(out).unwrap()
        };
        assert_eq!(x25519_stanza_count(&scrypt), None);
        assert_eq!(x25519_stanza_count("not armor"), None);
        assert_eq!(
            x25519_stanza_count(&format!("{AGE_ARMOR_BEGIN}\nAAAA\n{AGE_ARMOR_END}\n")),
            None
        );
    }

    /// `testdata/escrow-vector.json`: test-only kits (the masters of `kit-vectors.json`), their
    /// recipients' fingerprint, and one fixed ciphertext each of them opens. age encryption is
    /// randomised, so the ciphertext was produced once and is kept; `MASTERSOS_REGEN_VECTORS=1`
    /// writes a fresh one.
    #[test]
    fn escrow_vector_matches() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Vector {
            note: String,
            kit_masters_hex: Vec<String>,
            recipients: Vec<String>,
            recipients_fp: String,
            recovery_key: String,
            recovery_key_age: String,
        }
        fn unhex(s: &str) -> [u8; 32] {
            let v: Vec<u8> = (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect();
            v.try_into().unwrap()
        }
        let masters = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ];
        let kits: Vec<Kit> = masters
            .iter()
            .map(|m| Kit::from_master(&unhex(m)))
            .collect();
        let recipients: Vec<String> = kits.iter().map(Kit::escrow_recipient).collect();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/escrow-vector.json");
        if std::env::var_os("MASTERSOS_REGEN_VECTORS").is_some_and(|v| v == "1") {
            let v = Vector {
                note: "TEST-ONLY: the kits are the fixed, public test masters of kit-vectors.json \
                       and the recovery key is made up. Never use them for a school."
                    .into(),
                kit_masters_hex: masters.iter().map(|m| (*m).to_owned()).collect(),
                recipients_fp: recipients_fp(&recipients),
                recovery_key_age: seal(KEY, &recipients).unwrap(),
                recipients: recipients.clone(),
                recovery_key: KEY.into(),
            };
            std::fs::write(path, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
            return;
        }
        let v: Vector = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert!(v.note.starts_with("TEST-ONLY"));
        assert_eq!(v.kit_masters_hex, masters);
        assert_eq!(v.recipients, recipients);
        assert_eq!(v.recipients_fp, recipients_fp(&recipients));
        let mut reversed = recipients.clone();
        reversed.reverse();
        assert_eq!(v.recipients_fp, recipients_fp(&reversed));
        assert!(is_sealed(&v.recovery_key_age));
        for k in &kits {
            let opened = age::decrypt(&k.escrow_identity(), v.recovery_key_age.as_bytes()).unwrap();
            assert_eq!(opened, v.recovery_key.as_bytes());
        }
    }

    #[test]
    fn debug_redacts_secret() {
        let r = req();
        for s in [format!("{r:?}"), format!("{r:#?}")] {
            assert!(!s.contains(&r.escrow_secret), "{s}");
            assert!(!s.contains(&r.recovery_key_age), "{s}");
            assert!(s.contains("<redacted>"));
            assert!(s.contains("dev-1") && s.contains(UUID) && s.contains(&r.recipients_fp));
        }
    }
}
