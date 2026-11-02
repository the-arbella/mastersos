//! Check arbitrary settings text: parse and structure errors become [`Lint`]s with source positions.

use std::collections::BTreeSet;
use std::ops::Range;

use crate::manifest::ShapeError;
use crate::{Lint, LintLevel, Manifest, Span};

/// Byte range in `text` to a [`Span`]: 1-based line and column counted in chars;
/// `\r\n` is one line break; a leading BOM is not a column.
pub fn span_of(text: &str, range: Range<usize>) -> Span {
    LineIndex::new(text).span(text, range)
}

/// The byte offset where each line of a text starts, so that a [`Span`] costs a binary search plus
/// the chars of one line instead of a scan from the start of the text.
struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    fn new(text: &str) -> Self {
        let starts = std::iter::once(0)
            .chain(text.match_indices('\n').map(|(i, _)| i + 1))
            .collect();
        LineIndex { starts }
    }

    /// 1-based (line, column) of `offset` in `text`, the text this index was built from.
    fn pos(&self, text: &str, offset: usize) -> (u32, u32) {
        let offset = offset.min(text.len());
        let line = self.starts.partition_point(|&s| s <= offset) - 1;
        let start = self.starts[line];
        let mut column = 1u32;
        for (i, c) in text[start..].char_indices() {
            let i = start + i;
            if i >= offset {
                break;
            }
            match c {
                '\u{feff}' if i == 0 => {}
                '\r' if text[i + 1..].starts_with('\n') => {}
                _ => column += 1,
            }
        }
        (line as u32 + 1, column)
    }

    fn span(&self, text: &str, range: Range<usize>) -> Span {
        let (line, column) = self.pos(text, range.start);
        let (end_line, end_column) = self.pos(text, range.end.max(range.start));
        Span {
            line,
            column,
            end_line,
            end_column,
        }
    }
}

/// The first backtick-quoted name in a serde/toml message.
fn quoted_name(message: &str) -> Option<&str> {
    let rest = &message[message.find('`')? + 1..];
    Some(&rest[..rest.find('`')?])
}

/// Parse `text` into a [`Manifest`]; on failure one error-level [`Lint`] with a span.
///
/// Never uses the error's `Display`: it echoes the offending source line, which may hold a secret.
pub fn parse_issue(text: &str) -> Result<Manifest, Lint> {
    parse_ranged(text).map_err(|e| {
        let (mut lint, range) = *e;
        lint.span = range.map(|r| span_of(text, r));
        lint
    })
}

/// A parse failure with its byte range in the parsed text (boxed: a `Lint` is large).
type RangedIssue = Box<(Lint, Option<Range<usize>>)>;

/// [`parse_issue`] with the error's byte range in `text` instead of a span.
fn parse_ranged(text: &str) -> Result<Manifest, RangedIssue> {
    let doc = match toml_edit::Document::parse(text) {
        Ok(doc) => doc,
        Err(e) => {
            let lint = Lint::new(
                LintLevel::Error,
                "toml_syntax",
                "This is not valid TOML here. Check quotes, brackets and the = sign on this line.",
            );
            return Err(Box::new((lint, e.span())));
        }
    };
    let e = match crate::manifest::parse_shapes(text) {
        Ok(m) => return Ok(m),
        Err(ShapeError::Toml(e)) => e,
        // A wrong `format`, or a key that needs a newer one: placed at `format`.
        Err(err @ ShapeError::Format(_)) => {
            let lint = Lint::new(LintLevel::Error, "invalid_value", err.message()).at("format");
            let range = doc.get("format").and_then(|i| i.span());
            return Err(Box::new((lint, range)));
        }
        // A `format` newer than this code reads: nothing else in the text is checked.
        Err(err @ ShapeError::TooNew { found }) => {
            let lint = Lint::new(LintLevel::Error, "format_unsupported", err.message())
                .at("format")
                .param("found", found);
            let range = doc.get("format").and_then(|i| i.span());
            return Err(Box::new((lint, range)));
        }
        Err(err @ ShapeError::Mixed { .. }) => {
            let ShapeError::Mixed { index, ref group } = err else {
                unreachable!("matched as Mixed")
            };
            let path = if group.is_empty() {
                "group".to_string()
            } else {
                format!("group.{group}")
            };
            let lint = Lint::new(LintLevel::Error, "config_shape_mixed", err.message())
                .at(path)
                .param("group", group);
            let range = doc
                .get("group")
                .and_then(|g| g.as_array_of_tables())
                .and_then(|a| a.get(index))
                .and_then(|t| t.span())
                .map(|r| {
                    let line = text[r.clone()].split('\n').next().unwrap_or("").trim_end();
                    r.start..r.start + line.len()
                });
            return Err(Box::new((lint, range)));
        }
    };
    let msg = e.message();
    let name = quoted_name(msg).map(str::to_owned);
    let lint = if msg.starts_with("unknown field") {
        let field = name.unwrap_or_default();
        Lint::new(
            LintLevel::Error,
            "unknown_field",
            format!(
                "Unknown key \"{field}\" here. Check the spelling against the settings reference."
            ),
        )
        .param("field", field)
    } else if msg.starts_with("missing field") {
        let field = name.unwrap_or_default();
        Lint::new(
            LintLevel::Error,
            "missing_field",
            format!("The required key \"{field}\" is missing here. Add it as described in the settings reference."),
        )
        .param("field", field)
    } else if msg.starts_with("invalid type") {
        Lint::new(
            LintLevel::Error,
            "wrong_type",
            "This value has the wrong type. Check the settings reference for what this key expects.",
        )
    } else {
        Lint::new(
            LintLevel::Error,
            "invalid_value",
            "This value is not allowed here. Check the settings reference for the accepted values.",
        )
    };
    Err(Box::new((lint, e.span())))
}

/// Span of the key (or table header) a lint path names, in the original text.
/// Paths: `trust`, `school.<key>`, `config.<id>[.<key>|[i]…]`, `group.<id>[.<key>…]`,
/// `device[i][.<key>…]`; `config.<id>` / `group.<id>` pick the first table with that id. In a
/// legacy text (no `[[config]]`) `config.<id>` is looked up among the `[[group]]`s, where those
/// settings are written.
///
/// A key that holds a `[table]` or a `[[table]]` element maps to its header; any other key to the
/// key itself; an inline array element to the element. When a later segment is absent the span of
/// the nearest existing ancestor is returned; `None` when the first segment is absent or the text
/// is not TOML. A segment matches the longest key it starts with, so keys containing dots work.
///
/// Parses `text` each time: to place many paths in one text, build a [`Locator`] once.
pub fn locate(text: &str, path: &str) -> Option<Span> {
    Locator::new(text)?.locate(path)
}

/// One parsed text, to place any number of lint paths in it without parsing it again: each
/// [`Locator::locate`] costs the depth of the path and the length of one line, not the text.
pub struct Locator {
    doc: toml_edit::Document<String>,
    lines: LineIndex,
    /// Indices into the `[[group]]` array by `id`, in order (a repeated id has several).
    groups: IdIndex,
    /// The same for `[[config]]`.
    configs: IdIndex,
}

/// Indices into an array of tables by the tables' `id`, in order.
type IdIndex = std::collections::HashMap<String, Vec<usize>>;

/// The [`IdIndex`] of the array of tables `key`.
fn ids_of(doc: &toml_edit::Document<String>, key: &str) -> IdIndex {
    let mut out = IdIndex::default();
    if let Some(aot) = doc.get(key).and_then(|g| g.as_array_of_tables()) {
        for (i, t) in aot.iter().enumerate() {
            if let Some(id) = t.get("id").and_then(|v| v.as_str()) {
                out.entry(id.to_owned()).or_default().push(i);
            }
        }
    }
    out
}

impl Locator {
    /// `None` when `text` is not TOML.
    pub fn new(text: &str) -> Option<Self> {
        let doc = toml_edit::Document::parse(text.to_owned()).ok()?;
        let groups = ids_of(&doc, "group");
        let configs = ids_of(&doc, "config");
        Some(Locator {
            lines: LineIndex::new(doc.raw()),
            doc,
            groups,
            configs,
        })
    }

    /// The text this locator was built from.
    pub fn text(&self) -> &str {
        self.doc.raw()
    }

    /// Whether the document has this root key.
    fn has_root_key(&self, key: &str) -> bool {
        self.doc.contains_key(key)
    }

    /// Byte range in the text to a [`Span`], as [`span_of`] counts.
    pub fn span(&self, range: Range<usize>) -> Span {
        self.lines.span(self.text(), range)
    }

    /// [`locate`] in this locator's text.
    pub fn locate(&self, path: &str) -> Option<Span> {
        self.locate_nth(path, 0)
    }

    /// [`locate`] where `group.<id>` / `config.<id>` picks the `nth` (0-based) table with that id.
    fn locate_nth(&self, path: &str, nth: usize) -> Option<Span> {
        let text = self.text();
        let mut node = Node::Table(self.doc.as_table());
        let mut rest = path;
        let mut best: Option<Range<usize>> = None;
        let mut first = true;
        loop {
            if !first {
                rest = rest.strip_prefix('.').unwrap_or(rest);
            }
            if rest.is_empty() {
                break;
            }
            let step = if let Some(r) = rest.strip_prefix('[') {
                let Some((index, r)) = r.split_once(']') else {
                    break;
                };
                rest = r;
                index.parse().ok().and_then(|i| node.element(i))
            } else if let Some((root, after, index)) =
                first.then(|| self.table_list(rest)).flatten()
            {
                let Some((key, tables)) = self.doc.get_key_value(root) else {
                    break;
                };
                best = key.span();
                tables.as_array_of_tables().and_then(|groups| {
                    // The longest id that `after` starts with, then the `nth` table with it.
                    let (len, at) = segment_lens(after)
                        .find_map(|len| Some((len, index.get(&after[..len])?)))?;
                    let t = groups.get(*at.get(nth)?)?;
                    rest = &after[len..];
                    Some((Node::Table(t), t.span()))
                })
            } else {
                node.child(&mut rest)
            };
            let Some((next, span)) = step else {
                break;
            };
            first = false;
            node = next;
            best = span.or(best);
        }
        // A table's span runs to its last key; keep the first line (its header).
        best.map(|r| {
            let line = &text[r.clone()];
            let line = line.split('\n').next().unwrap_or(line).trim_end();
            self.span(r.start..r.start + line.len())
        })
    }

    /// For a path starting `group.` or `config.`: the root key to look in, the rest of the path
    /// after the prefix, and the id index of that key. A `config.` path in a text without
    /// `[[config]]` (the legacy shape) looks among the `[[group]]`s.
    fn table_list<'p>(&self, path: &'p str) -> Option<(&'static str, &'p str, &IdIndex)> {
        if let Some(after) = path.strip_prefix("group.") {
            return Some(("group", after, &self.groups));
        }
        let after = path.strip_prefix("config.")?;
        if self.has_root_key("config") {
            Some(("config", after, &self.configs))
        } else {
            Some(("group", after, &self.groups))
        }
    }
}

/// The lengths of the keys `path` can start with (each followed by the end, `.` or `[`), longest
/// first: looking each up beats scanning every key of a large table.
fn segment_lens(path: &str) -> impl Iterator<Item = usize> + '_ {
    std::iter::once(path.len()).chain(
        path.char_indices()
            .rev()
            .filter(|&(_, c)| c == '.' || c == '[')
            .map(|(i, _)| i),
    )
}

/// A place in a parsed document that a path segment can step into.
#[derive(Clone, Copy)]
enum Node<'a> {
    Item(&'a toml_edit::Item),
    Table(&'a toml_edit::Table),
    Value(&'a toml_edit::Value),
}

type Step<'a> = Option<(Node<'a>, Option<Range<usize>>)>;

impl<'a> Node<'a> {
    fn table_like(self) -> Option<&'a dyn toml_edit::TableLike> {
        match self {
            Node::Item(i) => i.as_table_like(),
            Node::Table(t) => Some(t),
            Node::Value(v) => v.as_inline_table().map(|t| t as &dyn toml_edit::TableLike),
        }
    }

    /// The longest key `rest` starts with, consumed from `rest`. Its span is the `[table]`
    /// header when the key holds a standard table that has one, otherwise the key.
    fn child(self, rest: &mut &str) -> Step<'a> {
        let table = self.table_like()?;
        let (key, child) = segment_lens(rest).find_map(|len| table.get_key_value(&rest[..len]))?;
        *rest = &rest[key.get().len()..];
        let header = child.as_table().and_then(|t| t.span());
        Some((Node::Item(child), header.or(key.span())))
    }

    /// Element `index` of an array of tables (span: its header) or of an array value (the value).
    fn element(self, index: usize) -> Step<'a> {
        let value = match self {
            Node::Item(toml_edit::Item::ArrayOfTables(a)) => {
                let t = a.get(index)?;
                return Some((Node::Table(t), t.span()));
            }
            Node::Item(toml_edit::Item::Value(v)) | Node::Value(v) => v,
            _ => return None,
        };
        let v = value.as_array()?.get(index)?;
        Some((Node::Value(v), v.span()))
    }
}

/// Result of [`check_text`]: the manifest when the text parses, and every issue found.
#[derive(Debug, Clone)]
pub struct Checked {
    pub manifest: Option<Manifest>,
    pub issues: Vec<Lint>,
}

/// Root keys a draft may leave out (the server stamps them on save), with the text that fills them.
const STAMPS: [(&str, &str); 2] = [
    ("version", "version = 1\n"),
    ("issued_at", "issued_at = \"1970-01-01T00:00:00Z\"\n"),
];

/// The most issues [`check_text`] returns; past it the list ends with one `issues_truncated`.
pub const MAX_ISSUES: usize = 1000;

/// Keep the first [`MAX_ISSUES`] of `issues` in order and, when some were dropped, append one
/// info-level `issues_truncated` saying how many there were.
pub fn cap_issues(issues: &mut Vec<Lint>) {
    let total = issues.len();
    if total <= MAX_ISSUES {
        return;
    }
    issues.truncate(MAX_ISSUES);
    issues.push(
        Lint::new(
            LintLevel::Info,
            "issues_truncated",
            format!(
                "Only the first {MAX_ISSUES} of {total} issues are shown. Fix these and check again to see the rest."
            ),
        )
        .param("shown", MAX_ISSUES)
        .param("total", total),
    );
}

/// Parse a draft's text the way [`check_text`] does: `version` and `issued_at` may be left out
/// (they are filled in a copy without shifting spans); on failure one error-level [`Lint`] with a
/// span in `text`.
pub fn parse_draft(text: &str) -> Result<Manifest, Lint> {
    parse_stamped(text, Locator::new(text).as_ref())
}

/// [`parse_draft`] with `text` already parsed by `loc` (`None` when it is not TOML).
fn parse_stamped(text: &str, loc: Option<&Locator>) -> Result<Manifest, Lint> {
    let bom = if text.starts_with('\u{feff}') { 3 } else { 0 };
    let prefix: String = match loc {
        Some(loc) => STAMPS
            .iter()
            .filter(|(key, _)| !loc.has_root_key(key))
            .map(|(_, line)| *line)
            .collect(),
        None => String::new(),
    };
    let stamped = format!("{}{prefix}{}", &text[..bom], &text[bom..]);
    parse_ranged(&stamped).map_err(|e| {
        let (mut lint, range) = *e;
        let unshift = |r: Range<usize>| -> Option<Range<usize>> {
            let end = bom + prefix.len();
            match r.start {
                s if s < bom => Some(r),
                s if s < end => None,
                s => Some(s - prefix.len()..r.end.max(s) - prefix.len()),
            }
        };
        lint.span = range.and_then(unshift).map(|r| match loc {
            Some(loc) => loc.span(r),
            None => span_of(text, r),
        });
        lint
    })
}

/// Parse (adding `version`/`issued_at` when absent, without shifting spans), validate_all, lint_at, then fill spans by `locate`.
///
/// A parse failure is the only issue. Otherwise [`Manifest::validate_all`]'s issues come first,
/// then [`crate::lint_at`]'s, each in its own order; a path that [`locate`] cannot place keeps
/// `span: None`. `group_duplicate_id` (`config_duplicate_id`) points at the repeated `[[group]]`
/// (`[[config]]`), not the first one.
/// At most [`MAX_ISSUES`] issues, then `issues_truncated` ([`cap_issues`]).
pub fn check_text(text: &str, present: &BTreeSet<String>, today: chrono::NaiveDate) -> Checked {
    let (mut checked, _) = check_text_located(text, present, today);
    cap_issues(&mut checked.issues);
    checked
}

/// [`check_text`] without the cap, and with the [`Locator`] it parsed `text` into (`None` when
/// `text` is not TOML), so that a caller adding issues of its own can place them without parsing
/// again and cap the whole list once.
pub fn check_text_located(
    text: &str,
    present: &BTreeSet<String>,
    today: chrono::NaiveDate,
) -> (Checked, Option<Locator>) {
    let loc = Locator::new(text);
    let manifest = match parse_stamped(text, loc.as_ref()) {
        Ok(m) => m,
        Err(lint) => {
            let checked = Checked {
                manifest: None,
                issues: vec![lint],
            };
            return (checked, loc);
        }
    };
    let mut issues = manifest.validate_all(present);
    issues.extend(crate::lint_at(&manifest, present, today));
    if let Some(loc) = &loc {
        let mut repeats: std::collections::HashMap<String, usize> = Default::default();
        for lint in &mut issues {
            let (Some(path), None) = (&lint.path, lint.span) else {
                continue;
            };
            let nth = if matches!(lint.code, "group_duplicate_id" | "config_duplicate_id") {
                let n = repeats.entry(path.clone()).or_default();
                *n += 1;
                *n
            } else {
                0
            };
            lint.span = loc.locate_nth(path, nth);
        }
    }
    let checked = Checked {
        manifest: Some(manifest),
        issues,
    };
    (checked, loc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syntax_error_has_line_and_column() {
        let e = parse_issue("[school]\nid = \"x\n").unwrap_err();
        assert_eq!(e.code, "toml_syntax");
        assert_eq!(e.span.unwrap().line, 2);
    }

    #[test]
    fn syntax_error_column_counts_chars() {
        let e = parse_issue("# 中文注释\n[school]\nname = = 1\n").unwrap_err();
        assert_eq!(e.code, "toml_syntax");
        let s = e.span.unwrap();
        assert_eq!((s.line, s.column), (3, 8));
    }

    #[test]
    fn unknown_field_is_named() {
        let e = parse_issue("version = 1\n[[group]]\nid = \"default\"\ncolour = 1\n").unwrap_err();
        assert_eq!(e.code, "unknown_field");
        assert_eq!(e.params["field"], "colour");
        assert_eq!(e.span.unwrap().line, 4);
    }

    #[test]
    fn missing_field_is_named() {
        let e = parse_issue("version = 1\n[[group]]\nname = \"d\"\n").unwrap_err();
        assert_eq!(e.code, "missing_field");
        assert_eq!(e.params["field"], "id");
    }

    #[test]
    fn wrong_type_and_invalid_value() {
        let e = parse_issue("version = \"x\"\n").unwrap_err();
        assert_eq!(e.code, "wrong_type");
        assert_eq!(e.span.unwrap().line, 1);
        let e = parse_issue("version = 1\n[school]\nid = \"NOT-UUID\"\n").unwrap_err();
        assert_eq!(e.code, "invalid_value");
        assert_eq!(e.span.unwrap().line, 3);
    }

    #[test]
    fn newer_format_is_format_unsupported() {
        let e = parse_issue("format = 3\nversion = 1\n[school]\ncolour = 1\n").unwrap_err();
        assert_eq!(e.code, "format_unsupported");
        assert_eq!(e.params["found"], "3");
        assert_eq!(e.span.unwrap().line, 1);
        // A wrong value is still an invalid value.
        let e = parse_issue("format = \"x\"\nversion = 1\n").unwrap_err();
        assert_eq!(e.code, "invalid_value");
    }

    #[test]
    fn parse_issue_never_echoes_source_line() {
        let secret = "hunter2-wifi-psk";
        for text in [
            format!("version = 1\n[[group]]\nid = \"default\"\npsk = \"{secret}\"\n"),
            format!("version = \"{secret}\"\n"),
            format!("psk = = \"{secret}\"\n"),
            format!("version = 1\n[school]\nid = \"{secret}\"\n"),
        ] {
            let e = parse_issue(&text).unwrap_err();
            assert!(!e.message.contains(secret), "{}", e.message);
            assert!(e.params.values().all(|v| !v.contains(secret)));
        }
    }

    #[test]
    fn span_of_handles_crlf_and_bom() {
        let t = "\u{feff}a = 1\r\nbb = 2\r\n";
        let s = span_of(t, 3 + 1..3 + 2);
        assert_eq!((s.line, s.column), (1, 2));
        let off = t.find("bb").unwrap();
        let s = span_of(t, off..off + 2);
        assert_eq!((s.line, s.column, s.end_line, s.end_column), (2, 1, 2, 3));
    }

    fn today() -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(2026, 10, 28).unwrap()
    }

    fn check(text: &str) -> Checked {
        check_text(text, &BTreeSet::new(), today())
    }

    fn issue<'a>(c: &'a Checked, code: &str) -> &'a Lint {
        c.issues
            .iter()
            .find(|l| l.code == code)
            .unwrap_or_else(|| panic!("no {code} in {:?}", c.issues))
    }

    fn line_col(s: Option<Span>) -> (u32, u32) {
        let s = s.expect("span");
        (s.line, s.column)
    }

    #[test]
    fn invalid_value_never_echoes_source_line() {
        let e = parse_issue("version = 1\n[school]\nid = \"hunter2-wifi-psk\"\n").unwrap_err();
        assert_eq!(e.code, "invalid_value");
        assert!(!e.message.contains("hunter2"));
    }

    #[test]
    fn parse_issue_agrees_with_manifest_parse() {
        for t in [
            "version = 1\n",
            "version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n",
            "version = 1\n[school]\nupdate_channel = \"beta\"\n",
            "",
            "version = \"x\"\n",
            "version = 1\n[school]\nid = \"NOT-UUID\"\n",
            "version = 1\n[[group]]\nname = \"d\"\n",
            "version = 1\ncolour = 2\n",
            "version = 1\n[school]\nid = \"x\n",
            "version = 1\nversion = 2\n",
            "version = 1\n[[group]]\nid = \"a\"\nname = \"a\"\n[group.apps]\n[group.apps]\n",
        ] {
            assert_eq!(
                parse_issue(t).is_ok(),
                Manifest::parse(t).is_ok(),
                "disagree on {t:?}"
            );
        }
    }

    const NESTED: &str = "version = 1
[school]
allowed_domains = []
update_channel = \"beta\"
[[group]]
id = \"default\"
name = \"d\"
[[group]]
id = \"cart-g3\"
name = \"c\"
[[group.apps.web]]
name = \"a\"
url = \"https://a.example\"
[[group.apps.web]]
name = \"b\"
url = \"https://b.example\"
icon = \"x.png\"
[[device]]
serial = \"S1\"
group = \"default\"
[[device]]
serial = \"S2\"
group = \"cart-g3\"
";

    #[test]
    fn locate_school_key() {
        assert_eq!(line_col(locate(NESTED, "school.update_channel")), (4, 1));
        assert_eq!(line_col(locate(NESTED, "school")), (2, 1));
    }

    #[test]
    fn locate_group_nested_web_icon() {
        let s = locate(NESTED, "group.cart-g3.apps.web[1].icon").unwrap();
        assert_eq!((s.line, s.column, s.end_line, s.end_column), (17, 1, 17, 5));
        assert_eq!(
            line_col(locate(NESTED, "group.cart-g3.apps.web[1]")),
            (14, 1)
        );
        let s = locate(NESTED, "group.cart-g3").unwrap();
        assert_eq!((s.line, s.column, s.end_line, s.end_column), (8, 1, 8, 10));
        assert_eq!(line_col(locate(NESTED, "group.default.name")), (7, 1));
    }

    #[test]
    fn locate_device_index() {
        assert_eq!(line_col(locate(NESTED, "device[1]")), (21, 1));
        assert_eq!(line_col(locate(NESTED, "device[1].group")), (23, 1));
        assert_eq!(line_col(locate(NESTED, "device[0].serial")), (19, 1));
    }

    #[test]
    fn locate_missing_returns_none() {
        assert_eq!(locate(NESTED, "trust"), None);
        // Group `nope` does not exist: the `group` key itself.
        assert_eq!(line_col(locate(NESTED, "group.nope.name")), (5, 3));
        assert_eq!(locate("[school\n", "school"), None);
        // A missing leaf falls back to its nearest existing ancestor.
        assert_eq!(line_col(locate(NESTED, "school.locale")), (2, 1));
        assert_eq!(
            line_col(locate(NESTED, "group.cart-g3.apps.web[7].icon")),
            (11, 14)
        );
        assert_eq!(line_col(locate(NESTED, "device[1].reset.id")), (21, 1));
    }

    #[test]
    fn locate_inline_tables_and_arrays() {
        let t = "version = 1\n[[group]]\nid = \"g\"\nname = \"g\"\n\
                 wifi = [\n  { ssid = \"a\" },\n  { ssid = \"b\", psk = \"p\" },\n]\n\
                 [group.apps.kiosk]\ncalc = { name = \"c\", exec = \"x\" }\n";
        assert_eq!(line_col(locate(t, "group.g.wifi[1]")), (7, 3));
        assert_eq!(line_col(locate(t, "group.g.wifi[1].psk")), (7, 17));
        assert_eq!(
            line_col(locate(t, "group.g.apps.kiosk.calc.exec")),
            (10, 22)
        );
        assert_eq!(line_col(locate(t, "group.g.apps.kiosk")), (9, 1));
    }

    #[test]
    fn locate_duplicate_group() {
        let t = "version = 1\n[[group]]\nid = \"default\"\nname = \"a\"\n\
                 [[group]]\nid = \"default\"\nname = \"b\"\n";
        assert_eq!(line_col(locate(t, "group.default")), (2, 1));
        let c = check(t);
        assert_eq!(line_col(issue(&c, "group_duplicate_id").span), (5, 1));
    }

    #[test]
    fn locate_config_paths_and_duplicate_config() {
        let t = "version = 1\n[[config]]\nid = \"s\"\nname = \"s\"\n\
                 [[config.apps.web]]\nname = \"a\"\nurl = \"http://a\"\n\
                 [[config]]\nid = \"s\"\nname = \"t\"\n\
                 [[group]]\nid = \"default\"\nname = \"d\"\nconfig = \"s\"\n";
        assert_eq!(line_col(locate(t, "config.s.apps.web[0].url")), (7, 1));
        assert_eq!(line_col(locate(t, "config.s")), (2, 1));
        assert_eq!(line_col(locate(t, "group.default.config")), (14, 1));
        let c = check(t);
        assert_eq!(line_col(issue(&c, "config_duplicate_id").span), (8, 1));
        assert_eq!(line_col(issue(&c, "web_app_not_https").span), (7, 1));
    }

    const NO_VERSION: &str = "[school]
allowed_domains = []
[[group]]
id = \"default\"
login_methods = [\"sso\"]
name = \"d\"
";

    #[test]
    fn spans_unshifted_without_version() {
        let c = check(NO_VERSION);
        assert!(c.manifest.is_some(), "{:?}", c.issues);
        assert_eq!(issue(&c, "sso_without_oidc").span.unwrap().line, 5);
        assert!(c.issues.iter().all(|l| l.code != "missing_field"));
        // Parse errors are shifted back too.
        let c = check("[school]\nallowed_domains = []\ncolour = 1\n");
        assert_eq!(c.issues.len(), 1);
        assert_eq!(c.issues[0].code, "unknown_field");
        assert_eq!(line_col(c.issues[0].span), (3, 1));
    }

    #[test]
    fn spans_with_explicit_version() {
        let text = format!("version = 1\nissued_at = \"2026-10-28T00:00:00Z\"\n{NO_VERSION}");
        let c = check(&text);
        assert_eq!(issue(&c, "sso_without_oidc").span.unwrap().line, 7);
        assert_eq!(
            c.manifest.unwrap().issued_at.as_deref(),
            Some("2026-10-28T00:00:00Z")
        );
        let c = check("version = \"x\"\n");
        assert_eq!(c.issues[0].code, "wrong_type");
        assert_eq!(c.issues[0].span.unwrap().line, 1);
        // Only `issued_at` is missing: still no shift.
        let c = check(&format!("version = 1\n{NO_VERSION}"));
        assert_eq!(issue(&c, "sso_without_oidc").span.unwrap().line, 6);
    }

    #[test]
    fn span_crlf_and_bom() {
        let bad = "[school]\nallowed_domains = []\ncolour = 1\n";
        for base in [NO_VERSION, NESTED, bad] {
            let want: Vec<_> = check(base)
                .issues
                .iter()
                .map(|l| (l.code, l.span))
                .collect();
            assert!(want.iter().any(|(_, s)| s.is_some()), "{want:?}");
            let crlf = base.replace('\n', "\r\n");
            for text in [
                crlf.clone(),
                format!("\u{feff}{crlf}"),
                format!("\u{feff}{base}"),
            ] {
                let got: Vec<_> = check(&text)
                    .issues
                    .iter()
                    .map(|l| (l.code, l.span))
                    .collect();
                assert_eq!(got, want, "{text:?}");
            }
        }
    }

    #[test]
    fn check_text_parse_failure_has_one_issue() {
        let c = check("[school]\nname = \"S\n");
        assert!(c.manifest.is_none());
        assert_eq!(c.issues.len(), 1);
        assert_eq!(c.issues[0].code, "toml_syntax");
        assert_eq!(c.issues[0].span.unwrap().line, 2);
    }

    #[test]
    fn check_text_orders_validate_before_lint() {
        let c = check(NO_VERSION);
        let first_lint = c
            .issues
            .iter()
            .position(|l| l.code == "sso_without_oidc")
            .unwrap();
        let trust = c
            .issues
            .iter()
            .position(|l| l.code == "trust_empty")
            .unwrap();
        assert!(trust < first_lint);
        assert_eq!(c.issues[trust].span, None);
    }

    /// `n` `[[device]]` entries that all name the missing group `gone`, after one default group.
    fn many_devices(n: usize) -> String {
        let mut t = String::from("version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n");
        for i in 0..n {
            t.push_str(&format!(
                "[[device]]\nserial = \"S{i}\"\ngroup = \"gone\"\n"
            ));
        }
        t
    }

    #[test]
    fn many_issues_are_located_once_and_capped() {
        let text = many_devices(5000);
        let started = std::time::Instant::now();
        let (full, loc) = check_text_located(&text, &BTreeSet::new(), today());
        let c = check(&text);
        // Two checks take under a second in debug; re-parsing the text per issue took minutes.
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert!(loc.is_some());
        let unknown: Vec<&Lint> = full
            .issues
            .iter()
            .filter(|l| l.code == "device_unknown_group")
            .collect();
        assert_eq!(unknown.len(), 5000);
        // `[[device]]` i starts at line 5 + 3i; its `group` key two lines below.
        for i in [0usize, 1, 2500, 4999] {
            let l = unknown
                .iter()
                .find(|l| l.path.as_deref() == Some(&format!("device[{i}].group")))
                .unwrap_or_else(|| panic!("no issue for device[{i}]: {:?}", unknown[0]));
            let line = 5 + 3 * i as u32 + 2;
            let s = l.span.expect("span");
            assert_eq!(
                (s.line, s.column, s.end_line, s.end_column),
                (line, 1, line, 6)
            );
        }
        // Capped: the first MAX_ISSUES in order, then one info-level `issues_truncated`.
        assert_eq!(c.issues.len(), MAX_ISSUES + 1);
        assert_eq!(c.issues[..MAX_ISSUES], full.issues[..MAX_ISSUES]);
        let last = c.issues.last().unwrap();
        assert_eq!(last.code, "issues_truncated");
        assert_eq!(last.level, LintLevel::Info);
        assert_eq!(last.params["shown"], MAX_ISSUES.to_string());
        assert_eq!(last.params["total"], full.issues.len().to_string());
        // At the cap nothing is dropped and nothing is appended.
        let mut exact = full.issues[..MAX_ISSUES].to_vec();
        cap_issues(&mut exact);
        assert_eq!(exact.len(), MAX_ISSUES);
        assert!(exact.iter().all(|l| l.code != "issues_truncated"));
    }

    #[test]
    fn locator_agrees_with_span_of_and_locate() {
        let text = format!("\u{feff}{}", NESTED.replace('\n', "\r\n"));
        let loc = Locator::new(&text).unwrap();
        for path in [
            "school.update_channel",
            "group.cart-g3.apps.web[1].icon",
            "group.nope.name",
            "device[1].group",
            "trust",
        ] {
            assert_eq!(loc.locate(path), locate(&text, path), "{path}");
        }
        // The line index against a plain scan from the start, at every offset (even inside a
        // char, past a `\r` and past the end).
        let scan = |offset: usize| -> (u32, u32) {
            let offset = offset.min(text.len());
            let (mut line, mut column) = (1u32, 1u32);
            for (i, c) in text.char_indices() {
                if i >= offset {
                    break;
                }
                match c {
                    '\u{feff}' if i == 0 => {}
                    '\n' => {
                        line += 1;
                        column = 1;
                    }
                    '\r' if text[i + 1..].starts_with('\n') => {}
                    _ => column += 1,
                }
            }
            (line, column)
        };
        for off in 0..text.len() + 3 {
            let s = loc.span(off..off + 2);
            assert_eq!((s.line, s.column), scan(off), "{off}");
            assert_eq!((s.end_line, s.end_column), scan(off + 2), "{off}");
            assert_eq!(span_of(&text, off..off + 2), s, "{off}");
        }
    }

    #[test]
    fn parse_draft_is_stamping_aware() {
        assert!(parse_draft(NO_VERSION).is_ok());
        let e = parse_draft("[school]\nallowed_domains = []\ncolour = 1\n").unwrap_err();
        assert_eq!(e.code, "unknown_field");
        assert_eq!(line_col(e.span), (3, 1));
    }
}
