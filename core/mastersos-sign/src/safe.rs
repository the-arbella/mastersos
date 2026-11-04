//! 打印前的清洗：服务端给的任何字符串（key_id、rp_id、路径、清单原文、lint、错误消息）
//! 都可能带终端控制序列。被攻破的服务端可以借光标移动、清行、OSC 在确认界面上藏行或
//! 伪造行，所以这些字符一律以可见的转义形式打出来。
//!
//! - [`field`]：单个字段（换行也转义），超长截断。
//! - [`text`]：多行正文（只保留 `\n`），每行超长截断。
//! - [`SafeWriter`]：库里所有打印都经过它，作为最后一道：漏掉 [`field`] 的字符串也不会
//!   把控制字符送到终端。

use std::io::{self, Write};

/// 单个字段最多显示的字符数。
pub const FIELD_MAX: usize = 200;
/// 多行正文里每行最多显示的字符数。
pub const LINE_MAX: usize = 400;

/// 这个字符要不要以转义形式显示。`\n` 不在此列：调用方按需单独处理。
///
/// 控制字符之外，Unicode 的 Cf（格式）类一律算：它们不占宽度或改变显示顺序，能让两个不同的
/// id 看起来一样。Cf 的码位表是固定的（Unicode 17），这里逐段列出，没有引入类别表的依赖。
fn hidden(c: char) -> bool {
    let u = c as u32;
    (c.is_control() && c != '\n')            // C0、DEL、C1（U+0080–U+009F）
        || u == 0x00AD                       // 软连字符
        || (0x0600..=0x0605).contains(&u)    // 阿拉伯数字标记
        || u == 0x061C                       // 阿拉伯字母标记
        || u == 0x06DD || u == 0x070F        // 阿拉伯 / 叙利亚缩写标记
        || (0x0890..=0x0891).contains(&u) || u == 0x08E2
        || u == 0x180E                       // 蒙古文元音分隔符
        || (0x200B..=0x200F).contains(&u)    // 零宽字符、LRM / RLM
        || (0x2028..=0x202E).contains(&u)    // 行 / 段分隔符、双向嵌入与覆盖
        || (0x2060..=0x206F).contains(&u)    // 词连接符、不可见运算符、废弃的格式控制
        || u == 0xFEFF                       // BOM / 零宽不换行空格
        || (0xFFF9..=0xFFFB).contains(&u)    // 注音锚点
        || u == 0x110BD || u == 0x110CD
        || (0x13430..=0x1343F).contains(&u)  // 埃及象形文字格式控制
        || (0x1BCA0..=0x1BCA3).contains(&u)  // 速记格式控制
        || (0x1D173..=0x1D17A).contains(&u)  // 乐谱格式控制
        || (0xE0000..=0xE007F).contains(&u) // 标签字符
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

/// `escape_backslash`：把 `\` 写成 `\\`，让转义出来的 `\u{202e}` 与字面上的 `\u{202e}` 分得开。
/// 只有清洗服务端字符串的 [`field`] / [`text`] / [`escape_lines`] 要开；[`SafeWriter`] 处理的
/// 是已经清洗过、带着我们自己转义序列的输出，再转一次会把它们改坏。
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

/// 单个字段：所有控制与不可见格式字符（含换行）转义，超过 [`FIELD_MAX`] 个字符截断。
pub fn field(s: &str) -> String {
    let (head, total) = capped(s, FIELD_MAX);
    let mut out = String::new();
    escape_into(&mut out, head, false, true);
    if let Some(n) = total {
        out.push_str(&format!("... (cut; {n} characters)"));
    }
    out
}

/// 多行正文转义但不截断：先转义再按行比对（`similar` 会把单独的 `\r` 当换行，转义后
/// 显示的行就是比对的行；不截断，免得只差在长行后半截的改动被比没了）。
pub fn escape_lines(s: &str) -> String {
    let mut out = String::new();
    escape_into(&mut out, s, true, true);
    out
}

/// 多行正文：保留 `\n`，其余照 [`field`] 转义，每行超过 [`LINE_MAX`] 个字符截断。
pub fn text(s: &str) -> String {
    lines(s, true)
}

/// 只按行截断，不再转义：给已经过 [`escape_lines`] 的文字用（再转一次，`\` 会变成 `\\\\`）。
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

/// 把写进来的一切转义后再交给内层：只有 `\n` 原样通过。
pub struct SafeWriter<'a> {
    inner: &'a mut dyn Write,
    /// 跨两次 write 的半个 UTF-8 字符。
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
                        std::str::from_utf8(ok).expect("valid_up_to 之前是合法 UTF-8"),
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
                        // 结尾是半个字符：留到下一次 write。
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
        // 到最后也没补全的半个字符按字节转义输出。
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
        // 字面上的转义写法与真字符不能转成同一段文字。
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
        // E0080 不是 Cf，保持原样。
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
            // 一个字节一个字节地写，半个字符跨 write 也要拼回来。
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
