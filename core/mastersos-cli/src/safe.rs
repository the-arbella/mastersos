//! Cleaning before printing: any string from the server (key_id, rp_id, paths, manifest text,
//! lints, error messages) may carry terminal control sequences. A compromised server could use
//! cursor moves, line clears or OSC to hide or forge lines on the confirmation screen, so these
//! characters are always printed in a visible escaped form.
//!
//! - [`field`]: one field (newlines escaped too), cut when too long.
//! - [`text`]: multi-line text (only `\n` kept), each line cut when too long.
//! - [`SafeWriter`]: everything printed goes through it as the last line of defence: a string that
//!   missed [`field`] still cannot send control characters to the terminal.

use std::io::{self, Write};

/// The most characters shown of one field.
pub const FIELD_MAX: usize = 200;
/// The most characters shown of each line of multi-line text.
pub const LINE_MAX: usize = 400;

/// Whether this character is shown escaped. `\n` is not: callers handle it as they need.
///
/// Besides control characters, every Unicode Cf (format) character counts: they take no width or
/// change the display order, and can make two different ids look the same. The Cf code points are
/// fixed (Unicode 17) and listed range by range here, without a dependency for the category table.
fn hidden(c: char) -> bool {
    let u = c as u32;
    (c.is_control() && c != '\n')            // C0、DEL、C1（U+0080–U+009F）
        || u == 0x00AD                       // soft hyphen
        || (0x0600..=0x0605).contains(&u)    // Arabic number marks
        || u == 0x061C                       // Arabic letter mark
        || u == 0x06DD || u == 0x070F        // Arabic / Syriac abbreviation marks
        || (0x0890..=0x0891).contains(&u) || u == 0x08E2
        || u == 0x180E                       // Mongolian vowel separator
        || (0x200B..=0x200F).contains(&u)    // zero-width characters, LRM / RLM
        || (0x2028..=0x202E).contains(&u)    // line / paragraph separators, bidi embeddings and overrides
        || (0x2060..=0x206F).contains(&u)    // word joiner, invisible operators, deprecated format controls
        || u == 0xFEFF                       // BOM / zero-width no-break space
        || (0xFFF9..=0xFFFB).contains(&u)    // interlinear annotation anchors
        || u == 0x110BD || u == 0x110CD
        || (0x13430..=0x1343F).contains(&u)  // Egyptian hieroglyph format controls
        || (0x1BCA0..=0x1BCA3).contains(&u)  // shorthand format controls
        || (0x1D173..=0x1D17A).contains(&u)  // musical symbol format controls
        || (0xE0000..=0xE007F).contains(&u) // tag characters
}

fn push_escaped(out: &mut String, c: char) {
    let u = c as u32;
    if u < 0x80 {
        match c {
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            _ => out.push_str(&format!("\\x{u:02x}")),
        }
    } else {
        out.push_str(&format!("\\u{{{u:x}}}"));
    }
}

/// `escape_backslash`: write `\` as `\\`, so an escaped `\u{202e}` and a literal `\u{202e}` stay
/// apart. Only [`field`] / [`text`] / [`escape_lines`], which clean the server's strings, turn it
/// on; [`SafeWriter`] handles output that is already clean and carries our own escapes, which a
/// second pass would break.
fn escape_into(out: &mut String, s: &str, keep_newline: bool, escape_backslash: bool) {
    for c in s.chars() {
        if c == '\\' && escape_backslash {
            out.push_str("\\\\");
        } else if hidden(c) || (c == '\n' && !keep_newline) {
            push_escaped(out, c);
        } else {
            out.push(c);
        }
    }
}

fn capped(s: &str, max: usize) -> (&str, Option<usize>) {
    match s.char_indices().nth(max) {
        Some((i, _)) => (&s[..i], Some(s.chars().count())),
        None => (s, None),
    }
}

/// One field: every control and invisible format character (newlines too) escaped, cut after
/// [`FIELD_MAX`] characters.
pub fn field(s: &str) -> String {
    let (head, total) = capped(s, FIELD_MAX);
    let mut out = String::new();
    escape_into(&mut out, head, false, true);
    if let Some(n) = total {
        out.push_str(&format!("... (cut; {n} characters)"));
    }
    out
}

/// Multi-line text escaped but not cut: escape first, then diff by line (`similar` takes a lone
/// `\r` as a line break; after escaping, the lines shown are the lines diffed; nothing is cut, so a
/// change only in the second half of a long line is not lost).
pub fn escape_lines(s: &str) -> String {
    let mut out = String::new();
    escape_into(&mut out, s, true, true);
    out
}

/// Multi-line text: `\n` kept, the rest escaped as in [`field`], each line cut after [`LINE_MAX`]
/// characters.
pub fn text(s: &str) -> String {
    lines(s, true)
}

/// Only cut by line, no escaping: for text that went through [`escape_lines`] (a second pass
/// would turn `\` into `\\\\`).
pub fn cap_lines(s: &str) -> String {
    lines(s, false)
}

fn lines(s: &str, escape: bool) -> String {
    let mut out = String::new();
    for (i, line) in s.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let (head, total) = capped(line, LINE_MAX);
        if escape {
            escape_into(&mut out, head, false, true);
        } else {
            out.push_str(head);
        }
        if let Some(n) = total {
            out.push_str(&format!("... (line cut; {n} characters)"));
        }
    }
    out
}

/// Escapes everything written to it before passing it on: only `\n` goes through as it is.
pub struct SafeWriter<'a> {
    inner: &'a mut dyn Write,
    /// Half a UTF-8 character split across two writes.
    tail: Vec<u8>,
}

impl<'a> SafeWriter<'a> {
    pub fn new(inner: &'a mut dyn Write) -> Self {
        SafeWriter {
            inner,
            tail: Vec::new(),
        }
    }
}

impl Write for SafeWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tail.extend_from_slice(buf);
        let mut out = String::new();
        let mut rest: &[u8] = &self.tail;
        loop {
            match std::str::from_utf8(rest) {
                Ok(s) => {
                    escape_into(&mut out, s, true, false);
                    rest = &[];
                    break;
                }
                Err(e) => {
                    let (ok, bad) = rest.split_at(e.valid_up_to());
                    escape_into(
                        &mut out,
                        std::str::from_utf8(ok)
                            .expect("the bytes before valid_up_to are valid UTF-8"),
                        true,
                        false,
                    );
                    match e.error_len() {
                        Some(n) => {
                            for b in &bad[..n] {
                                out.push_str(&format!("\\x{b:02x}"));
                            }
                            rest = &bad[n..];
                        }
                        // It ends in half a character: keep it for the next write.
                        None => {
                            rest = bad;
                            break;
                        }
                    }
                }
            }
        }
        self.tail = rest.to_vec();
        self.inner.write_all(out.as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Drop for SafeWriter<'_> {
    fn drop(&mut self) {
        // Half a character never completed is escaped byte by byte.
        if !self.tail.is_empty() {
            let s: String = self.tail.iter().map(|b| format!("\\x{b:02x}")).collect();
            let _ = self.inner.write_all(s.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVIL: &str = "rk-1\x1b[2K\rfake\u{202e}gnp.exe\u{200b}\x07\x7f\u{9b}\u{2066}";

    fn has_raw(s: &str) -> bool {
        s.chars().any(hidden)
    }

    #[test]
    fn field_escapes_everything_visible() {
        let f = field(EVIL);
        assert!(!has_raw(&f), "{f:?}");
        assert!(!f.contains('\n'));
        assert_eq!(
            f,
            "rk-1\\x1b[2K\\rfake\\u{202e}gnp.exe\\u{200b}\\x07\\x7f\\u{9b}\\u{2066}"
        );
        assert_eq!(field("a\nb"), "a\\nb");
        assert_eq!(field("ครู 老师 ok"), "ครู 老师 ok");
    }

    #[test]
    fn backslash_is_escaped_so_literal_and_real_differ() {
        // A literal escape and the real character must not give the same text.
        let real = field("a\u{202e}b");
        let literal = field("a\\u{202e}b");
        assert_eq!(real, "a\\u{202e}b");
        assert_eq!(literal, "a\\\\u{202e}b");
        assert_ne!(real, literal);
        assert_ne!(escape_lines("a\u{202e}b"), escape_lines("a\\u{202e}b"));
        assert_ne!(escape_lines("a\tb"), escape_lines("a\\tb"));
        assert_eq!(text("x\\y\nz"), "x\\\\y\nz");
    }

    #[test]
    fn every_format_char_is_escaped() {
        for c in [
            '\u{ad}',
            '\u{600}',
            '\u{180e}',
            '\u{2060}',
            '\u{2064}',
            '\u{206a}',
            '\u{206f}',
            '\u{fff9}',
            '\u{fffb}',
            '\u{e0001}',
            '\u{e0041}',
            '\u{e007f}',
            '\u{1d173}',
            '\u{110bd}',
        ] {
            let f = field(&format!("a{c}b"));
            assert_eq!(f, format!("a\\u{{{:x}}}b", c as u32), "{c:?}");
        }
        // E0080 is not Cf: kept as it is.
        assert_eq!(field("a\u{e0080}b"), "a\u{e0080}b");
    }

    #[test]
    fn writer_does_not_double_escape() {
        let mut sink = Vec::new();
        SafeWriter::new(&mut sink)
            .write_all(b"a\\u{202e}b\n")
            .unwrap();
        assert_eq!(String::from_utf8(sink).unwrap(), "a\\u{202e}b\n");
    }

    #[test]
    fn field_and_text_cap_length() {
        let long = "x".repeat(FIELD_MAX + 50);
        let f = field(&long);
        assert!(f.starts_with(&"x".repeat(FIELD_MAX)));
        assert!(
            f.contains(&format!("(cut; {} characters)", FIELD_MAX + 50)),
            "{f}"
        );
        let t = text(&format!("short\n{}\nend", "y".repeat(LINE_MAX + 1)));
        assert!(t.starts_with("short\n"));
        assert!(t.ends_with("\nend"), "{t}");
        assert!(t.contains("(line cut; "));
    }

    #[test]
    fn text_keeps_newlines_only() {
        let t = text(&format!("a\n{EVIL}\nb"));
        assert!(!has_raw(&t), "{t:?}");
        assert_eq!(t.lines().count(), 3);
    }

    #[test]
    fn writer_escapes_split_utf8_and_controls() {
        let mut sink = Vec::new();
        {
            let mut w = SafeWriter::new(&mut sink);
            let bytes = format!("ok\n{EVIL}\n").into_bytes();
            // Written one byte at a time: half a character across writes is put back together.
            for b in &bytes {
                w.write_all(std::slice::from_ref(b)).unwrap();
            }
            w.write_all(b"\xff\n").unwrap();
        }
        let s = String::from_utf8(sink).unwrap();
        assert!(!has_raw(&s), "{s:?}");
        assert!(s.starts_with("ok\nrk-1\\x1b[2K\\rfake\\u{202e}"), "{s}");
        assert!(s.ends_with("\\xff\n"), "{s}");
    }
}
