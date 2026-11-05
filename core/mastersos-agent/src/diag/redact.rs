//! Masks secrets in collected text (the second line of defence: the whitelist in [`super::collect`]
//! never reads the known secret files in the first place).
//!
//! Matching is ASCII case-insensitive and by pattern only, so it cannot be complete:
//! - `<key>=<value>` and `<key> = <value>` where the key ends in one of [`KEYS`]
//!   (`psk=`, `password=`, `fetch_token=`, `X-Amz-Signature=`, wpa_supplicant's `psk="…"`);
//! - JSON members `"<key>": "<value>"` with the same keys (`"token":"…"`, `"client_secret": "…"`);
//!   and the same with `\"` (JSON quoted inside a log line);
//! - bare keys with a colon (Rust Debug, YAML): `token: "…"`, `password: Some("…")`, and
//!   `secret: value` when the value is one token (prose such as `password: please enter it` stays);
//! - `Authorization: <scheme> <credential>` and `Bearer <credential>`;
//! - `Cookie:` and `Set-Cookie:`, the whole value;
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
    for (at, _) in lower.match_indices("cookie") {
        if let Some(s) = cookie(b, at + "cookie".len()) {
            spans.push(s);
        }
    }
    pem_blocks(&lower, &mut spans);
    if spans.is_empty() {
        return Cow::Borrowed(text);
    }
    spans.sort_unstable();
    // overlapping spans become one mask
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (s, e) in spans {
        match merged.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    for (s, e) in merged {
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

/// An unquoted run starting at `i` (non-empty); also ends before a `\"`.
fn token(b: &[u8], i: usize) -> Option<(usize, usize)> {
    let mut e = i;
    while e < b.len() && !is_delim(b[e]) && !esc_quote(b, e) {
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

/// The inside of a string quoted with `\"` (JSON inside a log line) whose content starts at `i`:
/// up to the next `\"`, or the end of the line.
fn quoted_escaped(b: &[u8], i: usize) -> Option<(usize, usize)> {
    let mut e = i;
    while e < b.len() && b[e] != b'\n' && !(b[e] == b'\\' && b.get(e + 1) == Some(&b'"')) {
        e += 1;
    }
    (e > i).then_some((i, e))
}

/// `\"` at `i`.
fn esc_quote(b: &[u8], i: usize) -> bool {
    b.get(i) == Some(&b'\\') && b.get(i + 1) == Some(&b'"')
}

/// After a key ending at `i`:
/// - `= value`, `="value"`, `='value'`;
/// - a quoted key (JSON, also with `\"` inside a log line): `": <anything>`;
/// - a bare key (Rust Debug, YAML, headers): `: "value"`, `: Some("value")`, or `: value` when the
///   value is a single token ending the line or followed by `,;)]}` (prose like
///   `password: please enter it` stays).
fn key_value(b: &[u8], i: usize) -> Option<(usize, usize)> {
    let mut j = i;
    let quoted_key = if esc_quote(b, j) {
        j += 2;
        true
    } else if b.get(j) == Some(&b'"') {
        j += 1;
        true
    } else {
        false
    };
    j = skip_blanks(b, j);
    let sep = *b.get(j)?;
    if sep != b'=' && sep != b':' {
        return None;
    }
    j = skip_blanks(b, j + 1);
    if sep == b':' && b[j..].starts_with(b"some(") {
        j += 5;
    }
    if esc_quote(b, j) {
        return quoted_escaped(b, j + 2);
    }
    match b.get(j) {
        Some(b'"') | Some(b'\'') => return quoted(b, j),
        None => return None,
        Some(_) => {}
    }
    let (s, e) = token(b, j)?;
    if sep == b'=' || quoted_key {
        return Some((s, e));
    }
    let k = skip_blanks(b, e);
    match b.get(k) {
        None | Some(b'\n' | b'\r' | b',' | b';' | b')' | b']' | b'}') => Some((s, e)),
        _ => None,
    }
}

/// After `cookie` (also `set-cookie`): `: <value>` or `= <value>`, masked to the end of the line.
fn cookie(b: &[u8], i: usize) -> Option<(usize, usize)> {
    let mut j = i;
    if esc_quote(b, j) {
        j += 2;
    } else if b.get(j) == Some(&b'"') {
        j += 1;
    }
    j = skip_blanks(b, j);
    if !matches!(b.get(j), Some(b':') | Some(b'=')) {
        return None;
    }
    let s = skip_blanks(b, j + 1);
    let mut e = s;
    while e < b.len() && b[e] != b'\n' && b[e] != b'\r' {
        e += 1;
    }
    (e > s).then_some((s, e))
}

/// After `authorization`: `: <scheme> <credential>` or `: <credential>`.
fn authorization(b: &[u8], i: usize) -> Option<(usize, usize)> {
    let mut j = i;
    if esc_quote(b, j) {
        j += 2;
    } else if b.get(j) == Some(&b'"') {
        j += 1;
    }
    j = skip_blanks(b, j);
    if !matches!(b.get(j), Some(b':') | Some(b'=')) {
        return None;
    }
    j = skip_blanks(b, j + 1);
    if esc_quote(b, j) {
        j += 2;
    } else if b.get(j) == Some(&b'"') {
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
        // Escaped JSON inside a log line, Rust Debug output, cookies.
        let cases = [
            (
                r#"agent: body={\"token\":\"abc\",\"n\":1}"#,
                r#"agent: body={\"token\":\"[redacted]\",\"n\":1}"#,
            ),
            (
                r#"msg="{\"psk\": \"x y\"}""#,
                r#"msg="{\"psk\": \"[redacted]\"}""#,
            ),
            (
                r#"{\"Authorization\":\"Bearer abc\"}"#,
                r#"{\"Authorization\":\"Bearer [redacted]\"}"#,
            ),
            (
                r#"Config { token: "abc", n: 1 }"#,
                r#"Config { token: "[redacted]", n: 1 }"#,
            ),
            (
                r#"Wifi { password: Some("x"), ssid: "s" }"#,
                r#"Wifi { password: Some("[redacted]"), ssid: "s" }"#,
            ),
            ("secret: \"x\"", "secret: \"[redacted]\""),
            ("client_secret: abc123", "client_secret: [redacted]"),
            ("X { token: abc, n: 1 }", "X { token: [redacted], n: 1 }"),
            ("token: abc\nnext", "token: [redacted]\nnext"),
            (
                "Cookie: session=abc; theme=dark\nnext",
                "Cookie: [redacted]\nnext",
            ),
            (
                "set-cookie: sid=1; Path=/; HttpOnly\r\n",
                "set-cookie: [redacted]\r\n",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(redact(input), want, "{input}");
        }
        for plain in [
            "password: please enter it",
            "gdm: secret: agent not running yet",
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
