//! The settings reference (`docs/manifest-spec.md`), the list of issue codes, and the JSON Schema
//! of the settings file. Tests keep the three consistent with the code: every schema field and
//! every issue code is documented, and every labeled example checks as labeled.

/// The settings reference in English Markdown: fields, issue codes, recipes, glossary.
pub const MANIFEST_SPEC: &str = include_str!("../docs/manifest-spec.md");

/// Opens a part of the reference the prompt version leaves out (a line of its own).
const OMIT_OPEN: &str = "<!-- prompt:omit -->";
/// Closes it. Markers do not nest and must pair up (a test checks).
const OMIT_CLOSE: &str = "<!-- /prompt:omit -->";

/// The reference without the markers, everything between them kept.
fn without_markers() -> String {
    MANIFEST_SPEC
        .split_inclusive('\n')
        .filter(|l| !matches!(l.trim_end(), OMIT_OPEN | OMIT_CLOSE))
        .collect()
}

/// The reference for pasting into an AI chat: the parts wrapped in `<!-- prompt:omit -->` markers
/// (long examples, the TOML primer, recipes, the "Why" of each issue) and the markers themselves
/// are left out, and runs of blank lines become one. Every field and every issue code stays.
pub fn prompt_spec() -> String {
    let mut out = String::with_capacity(MANIFEST_SPEC.len() / 2);
    let mut omitting = false;
    let mut blank = false;
    for line in MANIFEST_SPEC.split_inclusive('\n') {
        match line.trim_end() {
            OMIT_OPEN => omitting = true,
            OMIT_CLOSE => omitting = false,
            _ if omitting => {}
            "" => {
                if !blank && !out.is_empty() {
                    out.push_str(line);
                }
                blank = true;
            }
            _ => {
                out.push_str(line);
                blank = false;
            }
        }
    }
    out
}

/// The id of a `### ` heading line: an issue code (`icon_invalid`), a table name without its
/// brackets (`[[config.apps.web]]` is `config.apps.web`), or `top-level` for the top-level keys.
fn heading_id(line: &str) -> Option<String> {
    let text = line.strip_prefix("### ")?.trim();
    if text == "Top-level keys" {
        return Some("top-level".to_string());
    }
    let inner = text.strip_prefix('`')?.strip_suffix('`')?;
    Some(inner.trim_matches(['[', ']']).to_string())
}

/// The `###` section named `id` (see [`section_ids`]), heading included, up to the next heading
/// of level 2 or 3; markers are dropped but what they wrap is kept.
pub fn section(id: &str) -> Option<String> {
    let text = without_markers();
    let mut start = None;
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let heading = line.starts_with("## ") || line.starts_with("### ");
        if let Some(s) = start {
            if heading {
                return Some(text[s..offset].trim_end().to_string());
            }
        } else if heading && heading_id(line.trim_end()).as_deref() == Some(id) {
            start = Some(offset);
        }
        offset += line.len();
    }
    start.map(|s| text[s..].trim_end().to_string())
}

/// Every id [`section`] accepts, in document order.
pub fn section_ids() -> Vec<String> {
    MANIFEST_SPEC.lines().filter_map(heading_id).collect()
}

/// Every code check_text, validate_all, lint_at and the server's fleet lints can produce, sorted.
pub const ISSUE_CODES: &[&str] = &[
    "admin_user_invalid",
    "admin_users_too_many",
    "admins_without_sso",
    "allowed_domain_invalid",
    "allowed_domains_too_many",
    "chrome_pause_invalid",
    "chrome_pause_too_long",
    "chrome_paused",
    "chrome_window_invalid",
    "config_duplicate_id",
    "config_shape_mixed",
    "config_unused",
    "default_group_missing",
    "dest_not_absolute",
    "device_duplicate_id",
    "device_name_duplicate",
    "device_no_identity",
    "device_reset_id_invalid",
    "device_reset_requested",
    "device_unknown_group",
    "download_sha256_invalid",
    "drop_conflict",
    "drop_unknown",
    "escrow_recipient_unregistered",
    "escrow_recipients_invalid",
    "escrow_recipients_missing",
    "feature_unsupported",
    "feature_unsupported_in_use",
    "few_recovery_keys",
    "file_missing",
    "file_outside_dir",
    "flatpak_id_invalid",
    "flatpak_now_installed",
    "format_raised_on_save",
    "format_unsupported",
    "format_unsupported_in_use",
    "group_duplicate_id",
    "group_name_duplicate",
    "group_unknown_config",
    "icon_invalid",
    "invalid_value",
    "issues_truncated",
    "it_account_invalid",
    "kiosk_allow_invalid",
    "kiosk_exec_invalid",
    "kiosk_extension_invalid",
    "kiosk_flatpak_missing",
    "kiosk_id_invalid",
    "kiosk_in_session_only",
    "kiosk_launch_invalid",
    "kiosk_name_invalid",
    "kiosk_no_entry",
    "kiosk_policy_invalid",
    "kiosk_policy_locked",
    "kiosk_too_many",
    "kiosk_url_not_https",
    "kiosk_user_agent",
    "kiosk_user_agent_invalid",
    "legacy_shape",
    "locale_invalid",
    "lock_message_too_long",
    "logo_incomplete",
    "logo_sha256_invalid",
    "logo_unknown",
    "missing_field",
    "no_admins",
    "oidc_invalid",
    "oidc_issuer_google",
    "path_file_and_dir",
    "printer_invalid",
    "scanner_invalid",
    "school_id_mismatch",
    "school_name_invalid",
    "school_wifi_moved",
    "script_timeout_too_long",
    "secret_name_invalid",
    "secret_rerouted",
    "secret_unknown",
    "secret_unused",
    "sso_without_oidc",
    "timezone_invalid",
    "toml_syntax",
    "trust_changed",
    "trust_duplicate_id",
    "trust_empty",
    "trust_key_invalid",
    "trust_rp_id_forbidden",
    "trust_rp_id_invalid",
    "unknown_field",
    "update_channel_unknown",
    "update_mirror_invalid",
    "update_mirror_not_https",
    "web_app_invalid",
    "web_app_not_https",
    "wifi_invalid",
    "wifi_open_implicit",
    "wifi_server_unchecked",
    "wifi_ssid_duplicate",
    "wrong_type",
];

/// The JSON Schema (draft 2020-12) of the settings file as a school writes it.
///
/// Derived from [`crate::Manifest`]; descriptions are the fields' doc comments. `version` is not
/// required: the server writes it on Publish, and a Draft leaves it out.
#[cfg(feature = "schema")]
pub fn manifest_schema() -> serde_json::Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(crate::Manifest))
        .expect("a JSON Schema serializes to JSON");
    if let Some(required) = schema
        .get_mut("required")
        .and_then(serde_json::Value::as_array_mut)
    {
        required.retain(|k| k != "version");
    }
    schema
}

#[cfg(all(test, feature = "schema"))]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::Value;

    use super::*;

    /// A valid school id the example check adds when an example has none.
    const SCHOOL_ID: &str = "0192f3a4-5b6c-7d8e-9f00-112233445566";
    /// The publish day the examples are checked against (Chrome pause rules look at it).
    const TODAY: (i32, u32, u32) = (2026, 11, 2);

    /// The text of the `### ` / `## ` section whose heading line satisfies `is_heading`, up to
    /// the next heading of level 2 or 3.
    fn section<'a>(is_heading: impl Fn(&str) -> bool) -> Option<&'a str> {
        let mut start = None;
        let mut offset = 0;
        for line in MANIFEST_SPEC.split_inclusive('\n') {
            let heading = line.starts_with("## ") || line.starts_with("### ");
            if let Some(s) = start {
                if heading {
                    return Some(&MANIFEST_SPEC[s..offset]);
                }
            } else if heading && is_heading(line.trim_end()) {
                start = Some(offset);
            }
            offset += line.len();
        }
        start.map(|s| &MANIFEST_SPEC[s..])
    }

    /// Follows `$ref` into `$defs` and `anyOf`/`oneOf`/`allOf` (an `Option` or a described
    /// reference) to the schemas that can describe a value.
    fn resolve<'a>(root: &'a Value, s: &'a Value) -> Vec<&'a Value> {
        if let Some(r) = s.get("$ref").and_then(Value::as_str) {
            let name = r.strip_prefix("#/$defs/").expect("local reference");
            return resolve(root, &root["$defs"][name]);
        }
        let mut out = Vec::new();
        for k in ["anyOf", "oneOf", "allOf"] {
            for sub in s.get(k).and_then(Value::as_array).into_iter().flatten() {
                out.extend(resolve(root, sub));
            }
        }
        if out.is_empty() {
            out.push(s);
        }
        out
    }

    /// Every (TOML table header, key) pair of the schema: `("", "version")`,
    /// `("[school.oidc]", "issuer")`, `("[[config.wifi]]", "ssid")`,
    /// `("[config.apps.kiosk.<id>]", "name")` and so on.
    fn fields(root: &Value, s: &Value, table: &str, out: &mut Vec<(String, String)>) {
        let dotted = table.trim_matches(['[', ']']);
        for s in resolve(root, s) {
            let Some(props) = s.get("properties").and_then(Value::as_object) else {
                continue;
            };
            for (key, sub) in props {
                out.push((table.to_string(), key.clone()));
                let path = if dotted.is_empty() {
                    key.clone()
                } else {
                    format!("{dotted}.{key}")
                };
                for v in resolve(root, sub) {
                    if v.get("properties").is_some() {
                        fields(root, v, &format!("[{path}]"), out);
                    }
                    if let Some(items) = v.get("items") {
                        fields(root, items, &format!("[[{path}]]"), out);
                    }
                    if let Some(map) = v.get("additionalProperties").filter(|m| m.is_object()) {
                        fields(root, map, &format!("[{path}.<id>]"), out);
                    }
                }
            }
        }
    }

    /// A markdown list marker at the start of a line: `+ `, `- `, `* ` or `1. `.
    fn is_list_start(line: &str) -> bool {
        let rest = line.trim_start_matches(|c: char| c.is_ascii_digit());
        let digits = line.len() - rest.len();
        line.starts_with(['+', '-', '*']) && line[1..].starts_with(' ')
            || digits > 0 && rest.starts_with(". ")
    }

    #[test]
    fn no_wrapped_line_opens_a_list() {
        // A paragraph line that starts with `+ `, `- `, `* ` or `1. ` is a list item to
        // Markdown and breaks any code span it continues; only real lists may have them.
        let mut fenced = false;
        let mut para_is_list = false;
        let mut prev_blank = true;
        for (n, line) in MANIFEST_SPEC.lines().enumerate() {
            if line.trim_start().starts_with("```") {
                fenced = !fenced;
                prev_blank = true;
                continue;
            }
            if fenced {
                continue;
            }
            if line.trim().is_empty() {
                prev_blank = true;
                continue;
            }
            if prev_blank {
                para_is_list = is_list_start(line);
            } else if is_list_start(line) && !para_is_list && !line.starts_with('|') {
                panic!("line {}: a wrapped line opens a list: {line}", n + 1);
            }
            prev_blank = false;
        }
    }

    #[test]
    fn no_heading_lookalike_inside_a_fence() {
        // `section()` cuts at lines starting with `## ` or `### `; a TOML comment such as
        // `# note` is fine, but those two prefixes inside a fence would split a section.
        let mut fenced = false;
        for (n, line) in MANIFEST_SPEC.lines().enumerate() {
            if line.trim_start().starts_with("```") {
                fenced = !fenced;
            } else if fenced {
                assert!(
                    !(line.starts_with("# ")
                        || line.starts_with("## ")
                        || line.starts_with("### ")),
                    "line {}: a heading-looking line inside a fenced block: {line}",
                    n + 1
                );
            }
        }
    }

    #[test]
    fn prompt_markers_pair_up() {
        let mut open = false;
        for (n, line) in MANIFEST_SPEC.lines().enumerate() {
            match line.trim_end() {
                OMIT_OPEN => {
                    assert!(!open, "line {}: nested or repeated open marker", n + 1);
                    open = true;
                }
                OMIT_CLOSE => {
                    assert!(open, "line {}: close marker without an open one", n + 1);
                    open = false;
                }
                other => assert!(
                    !other.contains("prompt:omit"),
                    "line {}: a marker must be on a line of its own",
                    n + 1
                ),
            }
        }
        assert!(!open, "a marker is still open at the end of the file");
    }

    #[test]
    fn prompt_spec_is_shorter_and_keeps_every_code() {
        let p = prompt_spec();
        // 65%, not the planned 60%: the recipes stay in because they help an AI most.
        assert!(
            p.len() * 100 < MANIFEST_SPEC.len() * 65,
            "prompt spec is {} of {} bytes",
            p.len(),
            MANIFEST_SPEC.len()
        );
        assert!(!p.contains("prompt:omit"));
        assert!(!p.contains("\n\n\n"), "runs of blank lines remain");
        for code in ISSUE_CODES {
            assert!(
                p.contains(&format!("\n### `{code}`\n")),
                "{code} is missing from the prompt spec"
            );
        }
        // Every settings table keeps its section too.
        for h in [
            "### `[school]`",
            "### `[[config.apps.web]]`",
            "### `[[config]]`",
            "### `[[group]]`",
            "### Top-level keys",
        ] {
            assert!(p.contains(h), "{h} is missing from the prompt spec");
        }
    }

    #[test]
    fn section_finds_codes_and_tables() {
        let s = super::section("icon_invalid").expect("icon_invalid");
        assert!(s.starts_with("### `icon_invalid`\n"), "{s}");
        assert!(!s.contains("### `invalid_value`"), "{s}");
        assert!(s.contains("**Why:**"), "the full section keeps the Why");
        assert!(!s.contains("prompt:omit"));
        assert!(super::section("config.apps.web").is_some());
        assert!(super::section("school.oidc").is_some());
        assert!(super::section("config.apps.kiosk.<id>").is_some());
        assert!(super::section("config").is_some());
        assert!(super::section("group").is_some());
        assert!(super::section("top-level").is_some());
        assert!(super::section("nope").is_none());
        assert!(super::section("").is_none());
    }

    #[test]
    fn section_ids_cover_codes_and_tables() {
        let ids = section_ids();
        for code in ISSUE_CODES {
            assert!(ids.iter().any(|i| i == code), "no id for {code}");
        }
        assert!(ids.iter().any(|i| i == "config.apps.web"));
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "duplicate section ids");
        for id in &ids {
            assert!(super::section(id).is_some(), "{id} has no section");
        }
    }

    #[test]
    fn spec_documents_every_field() {
        let schema = manifest_schema();
        let mut all = Vec::new();
        fields(&schema, &schema, "", &mut all);
        assert!(
            all.len() > 50,
            "the schema walk found too few fields: {all:?}"
        );
        let mut missing = BTreeSet::new();
        for (table, key) in &all {
            let text = if table.is_empty() {
                section(|h| h.starts_with("### ") && h.contains("Top-level keys"))
            } else {
                // `[defaults]` has the keys of `[[config]]`: its sub-tables (`[[defaults.wifi]]`,
                // `[defaults.apps]`, …) are documented by the Config ones.
                let want = format!("`{}`", table.replacen("[defaults.", "[config.", 1));
                section(|h| h.starts_with("### ") && h.contains(&want))
            };
            match text {
                Some(t) if t.contains(&format!("| `{key}` |")) => {}
                Some(_) => {
                    missing.insert(format!("{table} {key}: has no table row in its section"));
                }
                None => {
                    missing.insert(format!("{table}: no section"));
                }
            }
        }
        let missing: Vec<_> = missing.into_iter().collect();
        assert!(
            missing.is_empty(),
            "undocumented fields:\n{}",
            missing.join("\n")
        );
    }

    #[test]
    fn issue_codes_sorted_and_unique() {
        let mut sorted = ISSUE_CODES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, ISSUE_CODES);
    }

    /// Codes named by `### `code`` headings in the spec.
    fn documented_codes() -> BTreeSet<&'static str> {
        MANIFEST_SPEC
            .lines()
            .filter_map(|l| l.strip_prefix("### `")?.strip_suffix('`'))
            .filter(|c| {
                c.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            })
            .collect()
    }

    #[test]
    fn spec_documents_every_issue_code() {
        let documented = documented_codes();
        let known: BTreeSet<&str> = ISSUE_CODES.iter().copied().collect();
        let missing: Vec<_> = known.difference(&documented).collect();
        let extra: Vec<_> = documented.difference(&known).collect();
        assert!(missing.is_empty(), "codes without a section: {missing:?}");
        assert!(extra.is_empty(), "sections for unknown codes: {extra:?}");
        // The `## Issues` part runs to the next level-2 heading.
        let start = MANIFEST_SPEC
            .find("\n## Issues\n")
            .expect("an ## Issues section");
        let issues = &MANIFEST_SPEC[start + 1..];
        let issues = &issues[..issues.find("\n## ").unwrap_or(issues.len())];
        for code in ISSUE_CODES {
            let heading = format!("### `{code}`");
            assert!(
                issues.contains(&format!("\n{heading}\n")),
                "{code} is not under ## Issues"
            );
            let body = section(|h| h == heading).unwrap();
            for part in ["**Level:**", "**Meaning:**", "**Why:**", "**How to fix:**"] {
                assert!(body.contains(part), "{code}: no {part}");
            }
        }
    }

    /// The string literal at the start of `src`, skipping whitespace and a `LintLevel::X,`.
    fn literal_after(src: &str) -> Option<&str> {
        let mut s = src.trim_start();
        if let Some(rest) = s.strip_prefix("LintLevel::") {
            s = rest.split_once(',')?.1.trim_start();
        }
        let s = s.strip_prefix('"')?;
        let end = s.find('"')?;
        let code = &s[..end];
        (!code.is_empty() && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
            .then_some(code)
    }

    /// Issue codes in this crate's sources (test modules excluded): the first string argument of
    /// `Lint::new`, `problem`, `err`, `fail`, `bad`, and `code:` / `CODE: &str =` literals.
    fn codes_in_source() -> BTreeSet<String> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = BTreeSet::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "rs") || path.ends_with("spec.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let src = text
                .split("\n#[cfg(test)]\nmod tests")
                .next()
                .unwrap_or_default();
            for marker in [
                "Lint::new(",
                "problem(",
                " err(",
                "(err(",
                " fail(",
                "bad(",
                "code: ",
                "CODE: &str = ",
            ] {
                for (i, _) in src.match_indices(marker) {
                    if let Some(code) = literal_after(&src[i + marker.len()..]) {
                        out.insert(code.to_string());
                    }
                }
            }
        }
        out
    }

    #[test]
    fn issue_codes_is_complete() {
        let found = codes_in_source();
        // Spot checks that the scan sees each way a code is written.
        for code in [
            "toml_syntax",
            "trust_empty",
            "dest_not_absolute",
            "kiosk_launch_invalid",
            "kiosk_extension_invalid",
            "wifi_invalid",
            "feature_unsupported",
            "device_reset_requested",
        ] {
            assert!(
                found.contains(code),
                "the source scan missed {code}: {found:?}"
            );
        }
        let missing: Vec<_> = found
            .iter()
            .filter(|c| !ISSUE_CODES.contains(&c.as_str()))
            .collect();
        assert!(missing.is_empty(), "codes not in ISSUE_CODES: {missing:?}");
    }

    /// A ```` ```toml check=… ```` block: its label, the files it says are in the bundle, its text.
    struct Example {
        line: usize,
        label: String,
        files: BTreeSet<String>,
        text: String,
    }

    fn examples() -> Vec<Example> {
        examples_in(MANIFEST_SPEC)
    }

    fn examples_in(doc: &str) -> Vec<Example> {
        let mut out = Vec::new();
        let mut cur: Option<Example> = None;
        for (n, line) in doc.lines().enumerate() {
            if let Some(ex) = cur.as_mut() {
                if line.trim_start().starts_with("```") {
                    out.push(cur.take().unwrap());
                } else {
                    ex.text.push_str(line);
                    ex.text.push('\n');
                }
                continue;
            }
            let Some(info) = line.trim_start().strip_prefix("```toml") else {
                continue;
            };
            let mut label = None;
            let mut files = BTreeSet::new();
            for word in info.split_whitespace() {
                if let Some(l) = word.strip_prefix("check=") {
                    label = Some(l.to_string());
                } else if let Some(f) = word.strip_prefix("files=") {
                    files.extend(f.split(',').map(String::from));
                }
            }
            if let Some(label) = label {
                cur = Some(Example {
                    line: n + 1,
                    label,
                    files,
                    text: String::new(),
                });
            }
        }
        assert!(cur.is_none(), "an unterminated example");
        out
    }

    /// The example with a valid trust and `[school] id` added where it has none (the Keys page
    /// and the server write those in real drafts). Text that is not TOML is left as is.
    fn completed(text: &str) -> String {
        let Ok(mut doc) = text.parse::<toml_edit::DocumentMut>() else {
            return text.to_string();
        };
        if !doc.contains_key("trust") {
            let mut key = toml_edit::Table::new();
            key["id"] = toml_edit::value("recovery-2026");
            key["alg"] = toml_edit::value("ed25519");
            key["public_key"] = toml_edit::value("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
            let mut aot = toml_edit::ArrayOfTables::new();
            aot.push(key);
            doc.insert("trust", toml_edit::Item::ArrayOfTables(aot));
        }
        let school = doc
            .entry("school")
            .or_insert_with(toml_edit::table)
            .as_table_like_mut();
        if let Some(school) = school {
            if !school.contains_key("id") {
                school.insert("id", toml_edit::value(SCHOOL_ID));
            }
        }
        doc.to_string()
    }

    /// The skill's reference copy is the spec itself, markers included.
    #[test]
    fn skill_reference_matches_spec() {
        let copy = include_str!("../../../skills/mastersos-admin/reference/settings-reference.md");
        assert!(
            copy == MANIFEST_SPEC,
            "skills/mastersos-admin/reference/settings-reference.md differs from docs/manifest-spec.md; \
             copy it again: cp core/mastersos-bundle/docs/manifest-spec.md skills/mastersos-admin/reference/settings-reference.md"
        );
    }

    /// Every TOML block of the skill's recipes, put into a minimal valid draft, has no error.
    #[test]
    fn skill_recipes_parse() {
        let recipes = include_str!("../../../skills/mastersos-admin/reference/recipes.md");
        let today = chrono::NaiveDate::from_ymd_opt(TODAY.0, TODAY.1, TODAY.2).unwrap();
        let all = examples_in(recipes);
        assert!(all.len() >= 6, "too few recipe blocks: {}", all.len());
        let mut failures = Vec::new();
        for ex in &all {
            assert_eq!(
                ex.label, "ok",
                "line {}: recipes are check=ok blocks",
                ex.line
            );
            let checked = crate::check::check_text(&completed(&ex.text), &ex.files, today);
            let errors: Vec<_> = checked
                .issues
                .iter()
                .filter(|l| l.level == crate::LintLevel::Error)
                .map(|l| format!("{}: {}", l.code, l.message))
                .collect();
            if !errors.is_empty() {
                failures.push(format!("line {}: {errors:?}", ex.line));
            }
        }
        assert!(
            failures.is_empty(),
            "recipe blocks with errors:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn spec_examples_check_as_labeled() {
        let today = chrono::NaiveDate::from_ymd_opt(TODAY.0, TODAY.1, TODAY.2).unwrap();
        let all = examples();
        assert!(all.len() > 40, "too few checked examples: {}", all.len());
        let mut failures = Vec::new();
        let mut labeled = BTreeSet::new();
        for ex in &all {
            let checked = crate::check::check_text(&completed(&ex.text), &ex.files, today);
            let errors: BTreeSet<&str> = checked
                .issues
                .iter()
                .filter(|l| l.level == crate::LintLevel::Error)
                .map(|l| l.code)
                .collect();
            let codes: BTreeSet<&str> = checked.issues.iter().map(|l| l.code).collect();
            let ok = if ex.label == "ok" {
                errors.is_empty()
            } else {
                labeled.insert(ex.label.clone());
                assert!(
                    ISSUE_CODES.contains(&ex.label.as_str()),
                    "line {}: unknown label {}",
                    ex.line,
                    ex.label
                );
                codes.contains(ex.label.as_str()) && errors.iter().all(|c| *c == ex.label.as_str())
            };
            if !ok {
                failures.push(format!(
                    "line {} (check={}): {:?}",
                    ex.line,
                    ex.label,
                    checked
                        .issues
                        .iter()
                        .map(|l| format!("{:?} {}: {}", l.level, l.code, l.message))
                        .collect::<Vec<_>>()
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "examples that do not check as labeled:\n{}",
            failures.join("\n")
        );
        // Every code that check_text can produce has a triggering example.
        let missing: Vec<_> = ISSUE_CODES
            .iter()
            .filter(|c| {
                !SERVER_ONLY.contains(c) && !COUNT_CAPS.contains(c) && !labeled.contains(**c)
            })
            .collect();
        assert!(
            missing.is_empty(),
            "codes without a check= example: {missing:?}"
        );
    }

    /// Codes for a list longer than 200 entries (or, for `issues_truncated`, more than 1000
    /// issues): an example would be thousands of characters of filler in a reference that is
    /// pasted whole into AI chats; the spec describes the trigger.
    const COUNT_CAPS: &[&str] = &[
        "admin_users_too_many",
        "allowed_domains_too_many",
        "issues_truncated",
    ];

    /// Codes that need the server's state (registered keys, the school's id, the fleet, the
    /// latest version): check_text never reports them, so the spec gives no check= example.
    const SERVER_ONLY: &[&str] = &[
        // Raised by `secret_ref::lints` against secrets.toml, which check_text never sees.
        "secret_name_invalid",
        "secret_rerouted",
        "secret_unknown",
        "secret_unused",
        "escrow_recipient_unregistered",
        "escrow_recipients_missing",
        "feature_unsupported",
        "feature_unsupported_in_use",
        "few_recovery_keys",
        "flatpak_now_installed",
        "format_raised_on_save",
        "format_unsupported_in_use",
        "logo_unknown",
        "school_id_mismatch",
        "trust_changed",
    ];
}
