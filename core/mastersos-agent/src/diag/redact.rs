//! Masks secrets in collected text (the second line of defence: the whitelist in [`super::collect`]
//! never reads the known secret files in the first place).
//!
//! The rule fails closed instead of parsing values: wherever a sensitive key ([`KEYS`], ASCII
//! case-insensitive, also as the end of a longer name such as `fetch_token`) is used as a key,
//! that is followed (after optional `\`, `"`, `'` and blanks) by `=` or `:`, everything after the
//! separator up to the end of the line becomes [`MASK`]. The key and the separator stay visible;
//! the rest of such a line is lost (over-masking is accepted). Line breaks may stand between
//! the key, the separator and the value (pretty-printed JSON): then the line where the value
//! starts is masked instead. Prose where the word is not
//! followed by `=` or `:` ("wrong password for user") stays as it is.
//!
//! Also masked to the end of the line: whatever follows `Bearer `, and the value after a
//! space-separated `--password`, `--passphrase`, `--psk`, `--secret` or `--token` flag. Masked
//! too: the userinfo of a URL (`scheme://user:pass@host` → `scheme://[redacted]@host`), the
//! body of PEM private key blocks, and the base64 lines right above an `-----END … PRIVATE
//! KEY-----` line even without its BEGIN line (output cut for size may start inside a key).

use std::borrow::Cow;

pub const MASK: &str = "[redacted]";

/// Sensitive keys (lower case). Longer names ending in one of them (`client_secret`,
/// `x-amz-security-token`, `set-cookie`) match too.
const KEYS: &[&str] = &[
    "psk",
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "x-amz-signature",
    "x-amz-credential",
    "private_key",
    "wep-key0",
    "wep-key1",
    "wep-key2",
    "wep-key3",
];

const PEM_BEGIN: &str = "-----begin ";
const PEM_PRIVATE: &str = "private key-----";
const PEM_END: &str = "-----end ";
/// Flags whose value is the next argument (`--password x`).
const FLAGS: &[&str] = &["--password", "--passphrase", "--psk", "--secret", "--token"];

/// `text` with every secret value replaced by [`MASK`]; borrowed when nothing matched.
pub fn redact(text: &str) -> Cow<'_, str> {
    let lower = text.to_ascii_lowercase();
    let b = lower.as_bytes();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for key in KEYS {
        for (at, _) in lower.match_indices(key) {
            if let Some(s) = after_separator(b, at + key.len()) {
                spans.push((s, line_end(b, s)));
            }
        }
    }
    for (at, _) in lower.match_indices("bearer") {
        let i = at + "bearer".len();
        let s = skip_blanks(b, i);
        if s > i && s < b.len() && b[s] != b'\n' && b[s] != b'\r' {
            spans.push((s, line_end(b, s)));
        }
    }
    for flag in FLAGS {
        for (at, _) in lower.match_indices(flag) {
            let i = at + flag.len();
            let s = skip_blanks(b, i);
            if s > i && s < b.len() && b[s] != b'\n' && b[s] != b'\r' {
                spans.push((s, line_end(b, s)));
            }
        }
    }
    userinfo(b, &mut spans);
    pem_blocks(&lower, &mut spans);
    pem_tails(&lower, &mut spans);
    spans.retain(|(s, e)| e > s);
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

/// Where the line holding `i` ends (before `\r\n` or `\n`, or the end of the text).
fn line_end(b: &[u8], i: usize) -> usize {
    let mut e = i;
    while e < b.len() && b[e] != b'\n' {
        e += 1;
    }
    if e > i && b[e - 1] == b'\r' {
        e -= 1;
    }
    e
}

/// Blanks and line breaks from `i`.
fn skip_space(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

/// After a key ending at `i`: optional `\`, `"`, `'`, blanks, then `=` or `:`. Returns where the
/// value starts (after the separator and its blanks). Fails closed for pretty-printed text:
/// line breaks may stand between the key and the separator and between the separator and the
/// value, so a value on a following line is found (and that line masked).
fn after_separator(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i;
    while j < b.len() && matches!(b[j], b'\\' | b'"' | b'\'') {
        j += 1;
    }
    j = skip_space(b, j);
    matches!(b.get(j), Some(b'=') | Some(b':')).then(|| skip_space(b, j + 1))
}

/// The body of every `-----BEGIN … PRIVATE KEY-----` block (to its END line, or the end of the text).
fn pem_blocks(lower: &str, spans: &mut Vec<(usize, usize)>) {
    let mut from = 0;
    while let Some(at) = lower[from..].find(PEM_BEGIN) {
        let begin = from + at;
        let line_end = lower[begin..].find('\n').map_or(lower.len(), |n| begin + n);
        if !lower[begin..line_end]
            .trim_end_matches('\r')
            .ends_with(PEM_PRIVATE)
        {
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

/// `scheme://userinfo@`: the userinfo (up to the first `@` before any `/`, `?`, `#` or blank).
fn userinfo(b: &[u8], spans: &mut Vec<(usize, usize)>) {
    let mut from = 0;
    while let Some(at) = b[from..].windows(3).position(|w| w == b"://") {
        let s = from + at + 3;
        let mut e = s;
        while e < b.len()
            && !matches!(
                b[e],
                b'/' | b'?' | b'#' | b'@' | b' ' | b'\t' | b'\r' | b'\n'
            )
        {
            e += 1;
        }
        if e < b.len() && b[e] == b'@' && e > s {
            spans.push((s, e));
        }
        from = s;
    }
}

/// Base64 lines right above every `-----END … PRIVATE KEY-----` line (a block whose BEGIN line
/// is missing): from the first of them to the END line.
fn pem_tails(lower: &str, spans: &mut Vec<(usize, usize)>) {
    let b = lower.as_bytes();
    let mut from = 0;
    while let Some(at) = lower[from..].find(PEM_END) {
        let end = from + at;
        from = end + PEM_END.len();
        let eol = lower[end..].find('\n').map_or(lower.len(), |n| end + n);
        let is_line_start = end == 0 || b[end - 1] == b'\n';
        if !is_line_start
            || !lower[end..eol]
                .trim_end_matches('\r')
                .ends_with(PEM_PRIVATE)
        {
            continue;
        }
        let mut start = end;
        while start > 0 {
            // the line before `start`
            let prev_end = start - 1;
            let prev_start = lower[..prev_end].rfind('\n').map_or(0, |n| n + 1);
            let line = lower[prev_start..prev_end].trim_end_matches('\r');
            let base64 = !line.is_empty()
                && line
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'='));
            if !base64 {
                break;
            }
            start = prev_start;
        }
        if start < end {
            spans.push((start, end));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_masks_pem_userinfo_and_flags() {
        let cases = [
            // CRLF PEM
            (
                "-----BEGIN RSA PRIVATE KEY-----\r\nMIIE\r\n-----END RSA PRIVATE KEY-----\r\nafter",
                "-----BEGIN RSA PRIVATE KEY-----\r\n[redacted]-----END RSA PRIVATE KEY-----\r\nafter",
            ),
            // a cut that starts inside the body: no BEGIN line
            (
                "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----\nafter",
                "[redacted]-----END PRIVATE KEY-----\nafter",
            ),
            (
                "log line: ok\nAbCd+/09==\r\n-----END EC PRIVATE KEY-----\r\n",
                "log line: ok\n[redacted]-----END EC PRIVATE KEY-----\r\n",
            ),
            // URL userinfo
            (
                "fetching https://ana:hunter2@example.org/x ok",
                "fetching https://[redacted]@example.org/x ok",
            ),
            ("git remote ssh://deploy@host/repo", "git remote ssh://[redacted]@host/repo"),
            // space-separated flags
            ("nmcli --password hunter2 rest", "nmcli --password [redacted]"),
            ("x --PSK  abc", "x --PSK  [redacted]"),
            ("cli --token t --secret s", "cli --token [redacted]"),
            ("cli --passphrase 'a b'", "cli --passphrase [redacted]"),
            ("cli --secret\tv", "cli --secret\t[redacted]"),
        ];
        for (input, want) in cases {
            assert_eq!(redact(input), want, "{input}");
        }
        for plain in [
            "see https://example.org/a@b and mail ana@example.org",
            "cli --password-file /run/x",
            "cli --token",
            "-----END CERTIFICATE-----",
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END CERTIFICATE-----",
        ] {
            assert!(matches!(redact(plain), Cow::Borrowed(_)), "{plain}");
        }
    }

    #[test]
    fn redact_masks_secrets() {
        let cases = [
            ("psk=abc", "psk=[redacted]"),
            ("PSK=abc rest\nnext", "PSK=[redacted]\nnext"),
            (
                "wpa_supplicant: network 0 psk=\"my wifi pass\" ok",
                "wpa_supplicant: network 0 psk=[redacted]",
            ),
            ("Password=hunter2", "Password=[redacted]"),
            ("passwd = 'x y'", "passwd = [redacted]"),
            ("SECRET=s3;next", "SECRET=[redacted]"),
            ("url?a=1&token=abc&b=2", "url?a=1&token=[redacted]"),
            (
                "fetch_token = \"t\"\r\nnext",
                "fetch_token = [redacted]\r\nnext",
            ),
            (
                "GET /x?a=1&X-Amz-Signature=deadbeef HTTP/1.1",
                "GET /x?a=1&X-Amz-Signature=[redacted]",
            ),
            (
                "GET /x?X-Amz-Credential=AK%2F1&X-Amz-Security-Token=t&X-Amz-Signature=d",
                "GET /x?X-Amz-Credential=[redacted]",
            ),
            ("Authorization: Bearer abc.def", "Authorization: [redacted]"),
            ("got bearer  tok123, retry", "got bearer  [redacted]"),
            (r#"{"token":"x","n":1}"#, r#"{"token":[redacted]"#),
            (r#"{"Secret": "a\"b\\c"}"#, r#"{"Secret": [redacted]"#),
            // escaped JSON inside a log line, with an escaped quote and backslash in the secret
            (
                r#"agent: body={\"n\":1,\"token\":\"ab\\\"c\\\\d\"}"#,
                r#"agent: body={\"n\":1,\"token\":[redacted]"#,
            ),
            (
                r#"msg="{\"psk\": \"x y\"}""#,
                r#"msg="{\"psk\": [redacted]"#,
            ),
            // bare keys: what follows the value does not matter
            ("token: abc # note", "token: [redacted]"),
            ("token: abc (x)", "token: [redacted]"),
            ("password: please enter it", "password: [redacted]"),
            // Rust Debug output
            (
                r#"Config { n: 1, token: "abc", m: 2 }"#,
                r#"Config { n: 1, token: [redacted]"#,
            ),
            (
                r#"Wifi { password: Some("x"), ssid: "s" }"#,
                r#"Wifi { password: [redacted]"#,
            ),
            // cookies, keys in other forms
            (
                "Cookie: session=abc; theme=dark\nnext",
                "Cookie: [redacted]\nnext",
            ),
            (
                "set-cookie: sid=1; HttpOnly\r\n",
                "set-cookie: [redacted]\r\n",
            ),
            ("'api_key': 'k'", "'api_key': [redacted]"),
            ("apikey=k", "apikey=[redacted]"),
            ("private_key = abc", "private_key = [redacted]"),
            ("wep-key0=abc", "wep-key0=[redacted]"),
            // several keys on one line: masked from the first
            (
                "user=a password=b token=c tail",
                "user=a password=[redacted]",
            ),
            (
                "-----BEGIN PRIVATE KEY-----\nMIIE\nabcd\n-----END PRIVATE KEY-----\nafter",
                "-----BEGIN PRIVATE KEY-----\n[redacted]-----END PRIVATE KEY-----\nafter",
            ),
            // multi-byte text before the key, the next line untouched
            ("é psk=1 é\nplain é", "é psk=[redacted]\nplain é"),
            // pretty-printed JSON: the value on the next line
            (
                "{\n  \"password\":\n    \"x\",\n  \"n\": 1\n}",
                "{\n  \"password\":\n    [redacted]\n  \"n\": 1\n}",
            ),
            (
                "\"token\": \r\n\r\n  \"abc\"\r\nnext",
                "\"token\": \r\n\r\n  [redacted]\r\nnext",
            ),
            // the separator and the value start the following line
            (
                "\"secret\"\n  : \"x\"\nnext",
                "\"secret\"\n  : [redacted]\nnext",
            ),
            ("psk=\nabc\nnext", "psk=\n[redacted]\nnext"),
        ];
        for (input, want) in cases {
            assert_eq!(redact(input), want, "{input}");
        }
        // Prose and ordinary lines stay as they are (and are not copied).
        for plain in [
            "wrong password for user alice",
            "NetworkManager[812]: <info> device (wlan0): state change: activated",
            "token count 3, tokens=5, secretary=no",
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            "naïve ünïcode line = ok",
            "psk=",
            "",
        ] {
            assert!(matches!(redact(plain), Cow::Borrowed(_)), "{plain}");
        }
    }
}
