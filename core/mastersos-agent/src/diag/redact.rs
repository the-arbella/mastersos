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
//! too: the userinfo of a URL (`scheme://user:pass@host` → `scheme://[redacted]@host`, up to the
//! last `@` of the authority); everything after a `-----BEGIN … PRIVATE KEY-----` (found
//! anywhere in a line, so journal prefixes and indents do not matter) up to its END, or to the
//! end of the text without one; and the base64 lines right above an `-----END … PRIVATE
//! KEY-----` without a BEGIN (output cut for size may start inside a key), each line read after
//! any indent or log prefix.

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
        if !lower[begin..line_end].trim_end().ends_with(PEM_PRIVATE) {
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

/// `scheme://userinfo@`: the authority runs to the first `/`, `?`, `#` or blank after `://`; when
/// it holds an `@`, everything up to its **last** `@` is the userinfo (a password may itself hold
/// `@` and `:`).
fn userinfo(b: &[u8], spans: &mut Vec<(usize, usize)>) {
    let mut from = 0;
    while let Some(at) = b[from..].windows(3).position(|w| w == b"://") {
        let s = from + at + 3;
        let mut e = s;
        while e < b.len() && !matches!(b[e], b'/' | b'?' | b'#' | b' ' | b'\t' | b'\r' | b'\n') {
            e += 1;
        }
        if let Some(last) = b[s..e].iter().rposition(|&c| c == b'@') {
            if last > 0 {
                spans.push((s, s + last));
            }
        }
        from = s;
    }
}

/// The key material of a PEM body line: without leading blanks (an indented config body) and
/// without a log prefix up to the first `": "` (`journalctl` lines: `<time> <host>
/// <ident>[<pid>]: `), which base64 never contains.
fn pem_payload(line: &str) -> &str {
    let line = line.trim();
    match line.find(": ") {
        Some(i) => line[i + 2..].trim(),
        None => line,
    }
}

fn is_base64(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'='))
}

/// A key's body lines are this long (64 in PEM, 70 in OpenSSH keys) except the last one, right
/// above the END line.
const PEM_BODY_LINE_MIN: usize = 32;

/// The body above every `-----END … PRIVATE KEY-----` (anywhere in its line) whose BEGIN line is
/// missing (output cut for size may start inside a key): the base64 lines above it, each taken
/// after any indent or log prefix ([`pem_payload`]), are masked from the first of them up to the
/// END. The line right above the END may be short; the others must look like full body lines.
fn pem_tails(lower: &str, spans: &mut Vec<(usize, usize)>) {
    let mut from = 0;
    while let Some(at) = lower[from..].find(PEM_END) {
        let end = from + at;
        from = end + PEM_END.len();
        let eol = lower[end..].find('\n').map_or(lower.len(), |n| end + n);
        if !lower[end..eol].trim_end().ends_with(PEM_PRIVATE) {
            continue;
        }
        let end_line = lower[..end].rfind('\n').map_or(0, |n| n + 1);
        let mut start = end_line;
        let mut first = true;
        while start > 0 {
            let prev_end = start - 1;
            let prev_start = lower[..prev_end].rfind('\n').map_or(0, |n| n + 1);
            let payload = pem_payload(&lower[prev_start..prev_end]);
            if !is_base64(payload) || (!first && payload.len() < PEM_BODY_LINE_MIN) {
                break;
            }
            first = false;
            start = prev_start;
        }
        if start < end_line {
            spans.push((start, end));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The collector's journal format (`journalctl -o short-iso-precise`): every line carries a
    /// `<timestamp> <host> <ident>[<pid>]: ` prefix.
    const J: &str = "2026-11-05T08:00:00.123456+00:00 laptop app[812]: ";

    #[test]
    fn redact_masks_pem_in_journal_and_indented_lines() {
        // a key logged line by line, BEGIN and END included
        let journal = format!(
            "{J}loading key\n{J}-----BEG\x49N PRIVATE KEY-----\n{J}MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n{J}AbCd+/09==\n{J}-----END PRIVATE KEY-----\n{J}done\n"
        );
        let out = redact(&journal);
        assert!(!out.contains("MIIE") && !out.contains("AbCd"), "{out}");
        assert!(out.ends_with(&format!("{J}done\n")), "{out}");
        assert!(out.starts_with(&format!("{J}loading key\n")), "{out}");
        // indented (a config body)
        let indented = "key: |\n    -----BEG\x49N EC PRIVATE KEY-----\n    MHcCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVJk5oVXYEhuJeqkVoAoGCCqG\n    AbCd+/09==\n    -----END EC PRIVATE KEY-----\nnext: 1\n";
        let out = redact(indented);
        assert!(!out.contains("MHcC") && !out.contains("AbCd"), "{out}");
        assert!(out.ends_with("next: 1\n"), "{out}");
        // a cut journal that starts inside the key: only the END is left
        let cut = format!(
            "{J}MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n{J}AbCd+/09==\n{J}-----END RSA PRIVATE KEY-----\n{J}after\n"
        );
        let out = redact(&cut);
        assert!(!out.contains("MIIE") && !out.contains("AbCd"), "{out}");
        assert!(out.ends_with(&format!("{J}after\n")), "{out}");
        let cut = "    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n    AbCd+/09==\n    -----END PRIVATE KEY-----\n";
        let out = redact(cut);
        assert!(!out.contains("MIIE") && !out.contains("AbCd"), "{out}");
        // BEGIN without an END: masked to the end of the text
        let open = format!("{J}-----BEG\x49N PRIVATE KEY-----\n{J}MIIEvQIBADAN\n");
        let out = redact(&open);
        assert!(!out.contains("MIIEvQ"), "{out}");
        // secrets in journal lines in general
        assert_eq!(
            redact(&format!("{J}network 0 psk=\"x\"\n{J}ok")),
            format!("{J}network 0 psk=[redacted]\n{J}ok")
        );
    }

    #[test]
    fn redact_masks_userinfo_with_at_and_colon_in_the_password() {
        let cases = [
            (
                "get https://u:p@ss@host/x ok",
                "get https://[redacted]@host/x ok",
            ),
            (
                "get https://user:p@ss:x@host/ ok",
                "get https://[redacted]@host/ ok",
            ),
            ("smb://a:b:c@srv", "smb://[redacted]@srv"),
            ("x https://u:p@h?q=a@b", "x https://[redacted]@h?q=a@b"),
        ];
        for (input, want) in cases {
            assert_eq!(redact(input), want, "{input}");
        }
    }

    #[test]
    fn redact_masks_pem_userinfo_and_flags() {
        let cases = [
            // CRLF PEM
            (
                "-----BEG\x49N RSA PRIVATE KEY-----\r\nMIIE\r\n-----END RSA PRIVATE KEY-----\r\nafter",
                "-----BEG\x49N RSA PRIVATE KEY-----\r\n[redacted]-----END RSA PRIVATE KEY-----\r\nafter",
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
                "-----BEG\x49N PRIVATE KEY-----\nMIIE\nabcd\n-----END PRIVATE KEY-----\nafter",
                "-----BEG\x49N PRIVATE KEY-----\n[redacted]-----END PRIVATE KEY-----\nafter",
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
            "-----BEG\x49N CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            "naïve ünïcode line = ok",
            "psk=",
            "",
        ] {
            assert!(matches!(redact(plain), Cow::Borrowed(_)), "{plain}");
        }
    }
}
