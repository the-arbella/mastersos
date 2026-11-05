//! Masks secrets in collected text (the second line of defence: the whitelist in [`super::collect`]
//! never reads the known secret files in the first place).
//!
//! Matching is ASCII case-insensitive and by pattern only, so it cannot be complete:
//! - `<key>=<value>` and `<key> = <value>` where the key ends in one of [`KEYS`]
//!   (`psk=`, `password=`, `fetch_token=`, `X-Amz-Signature=`, wpa_supplicant's `psk="…"`);
//! - JSON members `"<key>": "<value>"` with the same keys (`"token":"…"`, `"client_secret": "…"`);
//! - `Authorization: <scheme> <credential>` and `Bearer <credential>`;
//! - PEM private key blocks.
//!
//! Only the value is replaced by [`MASK`]; the key, quotes and the rest of the line stay.

use std::borrow::Cow;

pub const MASK: &str = "[redacted]";

/// Key suffixes whose values are masked (lower case).
const KEYS: &[&str] = &[
    "psk",
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "x-amz-signature",
    "x-amz-credential",
];

const PEM_BEGIN: &str = "-----begin ";
const PEM_PRIVATE: &str = "private key-----";
const PEM_END: &str = "-----end ";

/// `text` with every secret value replaced by [`MASK`]; borrowed when nothing matched.
pub fn redact(text: &str) -> Cow<'_, str> {
    let lower = text.to_ascii_lowercase();
    let b = lower.as_bytes();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for key in KEYS {
        for (at, _) in lower.match_indices(key) {
            if let Some(s) = key_value(b, at + key.len()) {
                spans.push(s);
            }
        }
    }
    for (at, _) in lower.match_indices("authorization") {
        if let Some(s) = authorization(b, at + "authorization".len()) {
            spans.push(s);
        }
    }
    for (at, _) in lower.match_indices("bearer") {
        let mut i = at + "bearer".len();
        let start = i;
        i = skip_blanks(b, i);
        if i > start {
            if let Some(s) = token(b, i) {
                spans.push(s);
            }
        }
    }
    pem_blocks(&lower, &mut spans);
    if spans.is_empty() {
        return Cow::Borrowed(text);
    }
    spans.sort_unstable();
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    for (s, e) in spans {
        if e <= pos {
            continue;
        }
        let s = s.max(pos);
        out.push_str(&text[pos..s]);
        out.push_str(MASK);
        pos = e;
    }
    out.push_str(&text[pos..]);
    Cow::Owned(out)
}

fn skip_blanks(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
        i += 1;
    }
    i
}

/// Ends an unquoted value.
fn is_delim(c: u8) -> bool {
    c.is_ascii_whitespace()
        || matches!(
            c,
            b'&' | b'"' | b'\'' | b',' | b';' | b')' | b']' | b'}' | b'<' | b'>'
        )
}

/// An unquoted run starting at `i` (non-empty).
fn token(b: &[u8], i: usize) -> Option<(usize, usize)> {
    let mut e = i;
    while e < b.len() && !is_delim(b[e]) {
        e += 1;
    }
    (e > i).then_some((i, e))
}

/// The inside of a quoted string whose opening quote is at `i`: up to the unescaped closing quote,
/// or the end of the line when there is none.
fn quoted(b: &[u8], i: usize) -> Option<(usize, usize)> {
    let q = b[i];
    let start = i + 1;
    let mut e = start;
    while e < b.len() && b[e] != q && b[e] != b'\n' {
        if b[e] == b'\\' && e + 1 < b.len() && b[e + 1] != b'\n' {
            e += 1;
        }
        e += 1;
    }
    (e > start).then_some((start, e))
}

/// After a key ending at `i`: `= value`, `="value"`, or (JSON) `": "value"`.
fn key_value(b: &[u8], i: usize) -> Option<(usize, usize)> {
    // JSON: the key's closing quote, a colon, then a string value
    if b.get(i) == Some(&b'"') {
        let j = skip_blanks(b, i + 1);
        if b.get(j) != Some(&b':') {
            return None;
        }
        let j = skip_blanks(b, j + 1);
        return (b.get(j) == Some(&b'"')).then(|| quoted(b, j)).flatten();
    }
    let j = skip_blanks(b, i);
    if b.get(j) != Some(&b'=') {
        return None;
    }
    let j = skip_blanks(b, j + 1);
    match b.get(j) {
        Some(b'"') | Some(b'\'') => quoted(b, j),
        Some(_) => token(b, j),
        None => None,
    }
}

/// After `authorization`: `: <scheme> <credential>` or `: <credential>`.
fn authorization(b: &[u8], i: usize) -> Option<(usize, usize)> {
    let mut j = i;
    if b.get(j) == Some(&b'"') {
        j += 1;
    }
    j = skip_blanks(b, j);
    if !matches!(b.get(j), Some(b':') | Some(b'=')) {
        return None;
    }
    j = skip_blanks(b, j + 1);
    if b.get(j) == Some(&b'"') {
        j += 1;
    }
    let (s, e) = token(b, j)?;
    let k = skip_blanks(b, e);
    let scheme = b[s..e].iter().all(u8::is_ascii_alphabetic);
    if scheme && k > e {
        if let Some(cred) = token(b, k) {
            return Some(cred);
        }
    }
    Some((s, e))
}

/// The body of every `-----BEGIN … PRIVATE KEY-----` block (to its END line, or the end of the text).
fn pem_blocks(lower: &str, spans: &mut Vec<(usize, usize)>) {
    let mut from = 0;
    while let Some(at) = lower[from..].find(PEM_BEGIN) {
        let begin = from + at;
        let line_end = lower[begin..].find('\n').map_or(lower.len(), |n| begin + n);
        if !lower[begin..line_end].ends_with(PEM_PRIVATE) {
            from = begin + PEM_BEGIN.len();
            continue;
        }
        let body = (line_end + 1).min(lower.len());
        let end = lower[body..]
            .find(PEM_END)
            .map_or(lower.len(), |n| body + n);
        if end > body {
            spans.push((body, end));
        }
        from = end.max(begin + PEM_BEGIN.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_masks_secrets() {
        let cases = [
            ("psk=abc", "psk=[redacted]"),
            ("PSK=abc rest", "PSK=[redacted] rest"),
            (
                "wpa_supplicant: network 0 psk=\"my wifi pass\" ok",
                "wpa_supplicant: network 0 psk=\"[redacted]\" ok",
            ),
            ("Password=hunter2", "Password=[redacted]"),
            ("passwd = 'x y'", "passwd = '[redacted]'"),
            ("SECRET=s3;next", "SECRET=[redacted];next"),
            ("url?a=1&token=abc&b=2", "url?a=1&token=[redacted]&b=2"),
            ("fetch_token = \"t\"", "fetch_token = \"[redacted]\""),
            (
                "GET /x?X-Amz-Credential=AK%2F1&X-Amz-Signature=deadbeef HTTP/1.1",
                "GET /x?X-Amz-Credential=[redacted]&X-Amz-Signature=[redacted] HTTP/1.1",
            ),
            (
                "Authorization: Bearer abc.def",
                "Authorization: Bearer [redacted]",
            ),
            ("authorization: xyz", "authorization: [redacted]"),
            ("got bearer  tok123, retry", "got bearer  [redacted], retry"),
            (r#"{"token":"x","n":1}"#, r#"{"token":"[redacted]","n":1}"#),
            (
                r#"{"Secret": "a\"b", "client_secret":"c"}"#,
                r#"{"Secret": "[redacted]", "client_secret":"[redacted]"}"#,
            ),
            (
                "-----BEGIN PRIVATE KEY-----\nMIIE\nabcd\n-----END PRIVATE KEY-----\nafter",
                "-----BEGIN PRIVATE KEY-----\n[redacted]-----END PRIVATE KEY-----\nafter",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(redact(input), want, "{input}");
        }
        // Ordinary lines stay as they are (and are not copied).
        for plain in [
            "NetworkManager[812]: <info> device (wlan0): state change: activated",
            "token count 3, tokens=5, secretary=no",
            "password: prompt shown",
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            "naïve ünïcode line = ok",
            "",
        ] {
            assert!(matches!(redact(plain), Cow::Borrowed(_)), "{plain}");
        }
        // Several on one line, and multi-byte text around them.
        assert_eq!(
            redact("é psk=1 é password=2\n"),
            "é psk=[redacted] é password=[redacted]\n"
        );
    }
}
