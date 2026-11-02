//! 生成的系统文件里的文本：稳定的文件名、GKeyFile 字符串、desktop entry 的 Exec 参数。
//!
//! 测试对着参考实现读回（Ruling 15）：GLib 的 `KeyFile` 与 `shell_parse_argv`（只在 Linux 上跑，`glib` 是
//! 那边的测试依赖），不自己写解析器来测自己写的转义器。

use sha2::{Digest, Sha256};

/// `sha256(s)` 的前 12 位十六进制：文件名、队列名、UUID 的稳定来源，不依赖 `s` 里有什么字符。
pub fn slug(s: &str) -> String {
    let mut h = crate::apply::hex(&Sha256::digest(s.as_bytes()));
    h.truncate(12);
    h
}

/// GKeyFile 的字符串值：`\` → `\\`，换行 → `\n`，回车 → `\r`，制表 → `\t`，行首空格 → `\s`
/// （GLib 读值时会去掉行首空白）。
pub fn keyfile_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.chars().enumerate() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ' ' if i == 0 => out.push_str("\\s"),
            c => out.push(c),
        }
    }
    out
}

/// desktop entry 的 `Exec` 里的一个参数（整个参数加引号，desktop entry 规范只认整段引起来的参数）。
/// `Exec` 的值先按 GKeyFile 字符串反转义、再展开 `%` 字段码、再按引号规则拆参数，所以写的时候反过来两层：
/// 先按引号规则——双引号包起，`"`、`` ` ``、`$`、`\` 前加 `\`，`%` → `%%`；再对整个结果做 GKeyFile 转义。
/// 结果里 `$` 是 `\\$`，`\` 是 `\\\\`。
pub fn desktop_exec_arg(s: &str) -> String {
    let mut q = String::with_capacity(s.len() + 2);
    q.push('"');
    for c in s.chars() {
        match c {
            '"' | '`' | '$' | '\\' => {
                q.push('\\');
                q.push(c);
            }
            '%' => q.push_str("%%"),
            c => q.push(c),
        }
    }
    q.push('"');
    keyfile_escape(&q)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_is_12_hex_and_stable() {
        let a = slug("https://x.th/a?b=1");
        assert_eq!(a.len(), 12);
        assert!(a
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert_eq!(a, slug("https://x.th/a?b=1"));
        assert_ne!(a, slug("https://x.th/a?b=2"));
        // sha256("abc") = ba7816bf8f01…
        assert_eq!(slug("abc"), "ba7816bf8f01");
    }

    #[test]
    fn keyfile_escape_rules() {
        assert_eq!(keyfile_escape("a\\b"), "a\\\\b");
        assert_eq!(keyfile_escape("a\nb\tc"), "a\\nb\\tc");
        assert_eq!(keyfile_escape(" lead"), "\\slead");
        assert_eq!(keyfile_escape("mid dle "), "mid dle ");
        assert_eq!(keyfile_escape("ห้องเรียน \"A\"; 1"), "ห้องเรียน \"A\"; 1");
    }

    #[test]
    fn desktop_exec_arg_two_layers() {
        assert_eq!(desktop_exec_arg("a$b"), "\"a\\\\$b\"");
        assert_eq!(desktop_exec_arg("a\\b"), "\"a\\\\\\\\b\"");
        assert_eq!(desktop_exec_arg("50%"), "\"50%%\"");
        assert_eq!(desktop_exec_arg("q\"`"), "\"q\\\\\"\\\\`\"");
    }
}
