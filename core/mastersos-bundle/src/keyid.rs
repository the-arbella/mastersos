//! 学校钥匙的 key_id 与登记探针的消息。服务端、`mastersos-sign` 与网页按同一套规则算，
//! 所以 trust 里的 id 由公钥决定，调用方传来的 id 一律不用。

use sha2::{Digest, Sha256};

/// 钥匙登记探针所签消息的前缀。
const KEYPROBE_PREFIX: &[u8] = b"mastersos-keyprobe-v1\n";

/// slug 最长的字符数。
const SLUG_MAX: usize = 24;

fn hex8(public_key: &[u8]) -> String {
    Sha256::digest(public_key)
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// 恢复钥匙（ed25519）的 id：`rk-<sha256(公钥) 前 8 位十六进制>`。
pub fn recovery_key_id(public_key: &[u8]) -> String {
    format!("rk-{}", hex8(public_key))
}

/// passkey 的 id：`pk-<slug>-<sha256(公钥) 前 8 位>`；slug 为空时 `pk-<8 位>`。
///
/// slug：ASCII 字母转小写，`[a-z0-9-]` 以外的字符变 `-`，连续的 `-` 合并，首尾的 `-`
/// 去掉，最长 24 个字符（截断后再去一次结尾的 `-`）。泰文、中文标签的 slug 为空。
pub fn passkey_key_id(label: &str, public_key: &[u8]) -> String {
    let slug = slug(label);
    if slug.is_empty() {
        format!("pk-{}", hex8(public_key))
    } else {
        format!("pk-{slug}-{}", hex8(public_key))
    }
}

/// 标签两端的空白，网页与服务端必须一致：Rust 的 `trim` 不去 U+FEFF（BOM）、JS 的不去
/// U+0085，同一个标签两边会算出不同的结果。这里把两者都去掉，网页的 `trimLabel` 照此实现。
pub fn trim_label(label: &str) -> &str {
    label.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
}

fn slug(label: &str) -> String {
    let mut out = String::new();
    for c in label.chars() {
        let c = c.to_ascii_lowercase();
        let c = if c.is_ascii_lowercase() || c.is_ascii_digit() {
            c
        } else {
            '-'
        };
        if c == '-' && (out.is_empty() || out.ends_with('-')) {
            continue;
        }
        out.push(c);
    }
    // 只含 ASCII，按字节截断即按字符截断。
    out.truncate(SLUG_MAX);
    out.trim_end_matches('-').to_owned()
}

/// 登记探针所签的消息：`b"mastersos-keyprobe-v1\n" || nonce`。
pub fn keyprobe_message(nonce: &[u8]) -> Vec<u8> {
    let mut msg = KEYPROBE_PREFIX.to_vec();
    msg.extend_from_slice(nonce);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &[u8] = b"public-key-bytes";

    fn h() -> String {
        hex8(PK)
    }

    #[test]
    fn passkey_id_slug_fallback() {
        assert_eq!(passkey_key_id("ครูสมชาย", PK), format!("pk-{}", h()));
        assert_eq!(passkey_key_id("老师的手机", PK), format!("pk-{}", h()));
        assert_eq!(
            passkey_key_id("IT Phone", PK),
            format!("pk-it-phone-{}", h())
        );
    }

    #[test]
    fn trim_label_strips_bom_and_nel_like_the_web() {
        assert_eq!(trim_label("\u{feff} IT Phone\u{feff}\n"), "IT Phone");
        assert_eq!(trim_label("\u{85}IT\u{a0}"), "IT");
        assert_eq!(trim_label("\u{feff}\u{feff}"), "");
        // 内部的 BOM 不动。
        assert_eq!(trim_label("a\u{feff}b"), "a\u{feff}b");
        assert_eq!(
            passkey_key_id(trim_label("\u{feff}IT Phone\u{feff}"), PK),
            format!("pk-it-phone-{}", h())
        );
    }

    #[test]
    fn passkey_slug_rules() {
        assert_eq!(slug("  --IT__Phone!! 2 "), "it-phone-2");
        assert_eq!(slug("ครู Somchai"), "somchai");
        assert_eq!(
            slug("abcdefghijklmnopqrstuvwxyz0123"),
            "abcdefghijklmnopqrstuvwx"
        );
        // 截断落在 `-` 上：结尾的 `-` 再去掉。
        assert_eq!(
            slug("abcdefghijklmnopqrstuvw xyz"),
            "abcdefghijklmnopqrstuvw"
        );
        assert_eq!(slug(""), "");
    }

    #[test]
    fn recovery_id_is_hash_prefix() {
        let id = recovery_key_id(PK);
        assert_eq!(id, format!("rk-{}", h()));
        assert_eq!(id.len(), 3 + 8);
        assert_ne!(recovery_key_id(b"other"), id);
    }

    #[test]
    fn keyprobe_message_has_prefix() {
        let m = keyprobe_message(&[7; 32]);
        assert!(m.starts_with(b"mastersos-keyprobe-v1\n"));
        assert_eq!(&m[22..], &[7; 32]);
    }
}
