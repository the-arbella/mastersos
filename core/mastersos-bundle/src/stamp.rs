//! Fields the publish step writes into a settings text: `version`, `issued_at` and `[school] name`.

use toml_edit::{value, DocumentMut};

use crate::BundleError;

/// The `format` a text writes (absent, or not a positive integer that fits: 1).
pub fn text_format(text: &str) -> u32 {
    text.parse::<toml::Table>()
        .ok()
        .and_then(|d| d.get("format").and_then(toml::Value::as_integer))
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1)
}

/// Write `version` and `issued_at` into a copy of the draft, and `[school] name` when
/// `school_name` is given (replacing one written by hand; see [`school_name_to_write`]). The trust
/// is taken as written: the server never fills it in. The draft itself is not changed.
pub fn stamp(
    draft: &str,
    version: u64,
    issued_at: &str,
    school_name: Option<&str>,
) -> Result<String, BundleError> {
    let mut doc: DocumentMut = draft
        .parse()
        .map_err(|e: toml_edit::TomlError| BundleError::Parse(e.to_string()))?;
    doc["version"] = value(version as i64);
    doc["issued_at"] = value(issued_at);
    if let Some(name) = school_name {
        doc["school"]["name"] = value(name);
    }
    Ok(doc.to_string())
}

/// The `[school] name` publishing writes (phase B §15): the school's display name, only when the
/// draft is already format 2 and the name passes [`crate::checks::school_name`]. The name never
/// raises the format by itself: a format 1 draft is published without it, so old Devices keep
/// accepting it.
pub fn school_name_to_write<'a>(text: &str, display_name: &'a str) -> Option<&'a str> {
    (text_format(text) == 2 && crate::checks::school_name(display_name).is_ok())
        .then_some(display_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_writes_version_and_time() {
        // Comments in the draft stay where they are.
        let draft = "format = 2\n# keep me\nversion = 1\n[school]\n# a comment\nname = \"old\"\n";
        let out = stamp(draft, 7, "2026-11-03T00:00:00Z", Some("New School")).unwrap();
        let doc: toml::Table = out.parse().unwrap();
        assert_eq!(doc["version"].as_integer(), Some(7));
        assert_eq!(doc["issued_at"].as_str(), Some("2026-11-03T00:00:00Z"));
        assert_eq!(doc["school"]["name"].as_str(), Some("New School"));
        assert!(out.contains("# keep me"));
        assert!(out.contains("# a comment"));
    }

    #[test]
    fn school_name_only_for_format_2() {
        assert_eq!(school_name_to_write("version = 1\n", "Name"), None);
        assert_eq!(school_name_to_write("format = 1\n", "Name"), None);
        assert_eq!(school_name_to_write("format = 2\n", "Name"), Some("Name"));
    }
}
