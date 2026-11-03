//! Secrets kept out of the settings text: `split` swaps each secret field's value for a
//! `"secret:<name>"` reference, `fill` puts the values back, `lints` checks the pairing.
//!
//! The layers and fields walked are those of the private server's `mask_toml`: `[school]`,
//! `[defaults]`, each `[[config]]` and each legacy `[[group]]`, their `wifi` entries and
//! `it_account`.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use toml_edit::{DocumentMut, Item, TableLike, Value};

use crate::{BundleError, ItAccount, Lint, LintLevel, Wifi};

const PREFIX: &str = "secret:";

/// Fields that decide where a secret is sent; a reference whose network changes any of them
/// since the base is flagged.
const ROUTING_FIELDS: [&str; 7] = [
    "eap",
    "phase2",
    "identity",
    "anonymous_identity",
    "server_domain",
    "ca_cert",
    "check_server",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Wifi,
    ItAccount,
}

type Visit<'f> = dyn FnMut(Kind, &str, &mut dyn TableLike) + 'f;
/// Called with the layer for a `wifi` / `it_account` value that is not a table (or list of them).
type Odd<'f> = dyn FnMut(&str) + 'f;

/// Replace `item` with the string `s`, keeping the value's surrounding whitespace and comment.
fn set_str(item: &mut Item, s: &str) {
    match item {
        Item::Value(v) => {
            let decor = v.decor().clone();
            let mut n = Value::from(s);
            *n.decor_mut() = decor;
            *v = n;
        }
        other => *other = Item::Value(Value::from(s)),
    }
}

fn visit_wifi(item: &mut Item, layer: &str, f: &mut Visit<'_>, odd: &mut Odd<'_>) {
    match item {
        Item::ArrayOfTables(a) => a.iter_mut().for_each(|t| f(Kind::Wifi, layer, t)),
        Item::Table(t) => f(Kind::Wifi, layer, t),
        Item::Value(Value::InlineTable(t)) => f(Kind::Wifi, layer, t),
        Item::Value(Value::Array(arr)) => {
            for v in arr.iter_mut() {
                match v {
                    Value::InlineTable(t) => f(Kind::Wifi, layer, t),
                    _ => odd(layer),
                }
            }
        }
        _ => odd(layer),
    }
}

fn visit_it(item: &mut Item, layer: &str, f: &mut Visit<'_>, odd: &mut Odd<'_>) {
    match item {
        Item::Table(t) => f(Kind::ItAccount, layer, t),
        Item::Value(Value::InlineTable(t)) => f(Kind::ItAccount, layer, t),
        _ => odd(layer),
    }
}

/// The layer name of the table `elem` found under `key` (dotted `path`, `root` = in the document root).
fn layer_for(root: bool, key: &str, elem: &dyn TableLike, path: &str) -> String {
    let id = elem.get("id").and_then(Item::as_str).map(slug);
    let id = id.filter(|s| !s.is_empty());
    match (root, key) {
        (true, "school") => "school".into(),
        (true, "defaults") => "defaults".into(),
        (true, "config") => id.unwrap_or_else(|| "config".into()),
        (true, "group") => format!("group-{}", id.unwrap_or_default())
            .trim_end_matches('-')
            .to_owned(),
        _ => format!("other-{}", slug(path)),
    }
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

fn walk_table(
    t: &mut dyn TableLike,
    root: bool,
    path: &str,
    layer: &str,
    f: &mut Visit<'_>,
    odd: &mut Odd<'_>,
) {
    for (k, item) in t.iter_mut() {
        let key = k.get().to_owned();
        // `drop` lists names only: nothing secret in it.
        if key == "drop" {
            continue;
        }
        if key == "wifi" {
            visit_wifi(item, layer, f, odd);
            continue;
        }
        if key == "it_account" {
            visit_it(item, layer, f, odd);
            continue;
        }
        let child = join(path, &key);
        match item {
            Item::Table(sub) => {
                let l = layer_for(root, &key, &*sub, &child);
                walk_table(sub, false, &child, &l, f, odd);
            }
            Item::ArrayOfTables(a) => {
                for sub in a.iter_mut() {
                    let l = layer_for(root, &key, &*sub, &child);
                    walk_table(sub, false, &child, &l, f, odd);
                }
            }
            Item::Value(v) => walk_value(v, root, &key, &child, f, odd),
            Item::None => {}
        }
    }
}

fn walk_value(
    v: &mut Value,
    root: bool,
    key: &str,
    path: &str,
    f: &mut Visit<'_>,
    odd: &mut Odd<'_>,
) {
    match v {
        Value::InlineTable(t) => {
            let l = layer_for(root, key, &*t, path);
            walk_table(t, false, path, &l, f, odd);
        }
        Value::Array(a) => {
            for x in a.iter_mut() {
                walk_value(x, root, key, path, f, odd);
            }
        }
        _ => {}
    }
}

/// Calls `f` on every Wi-Fi entry and `it_account` table anywhere in the document (as the
/// server's `mask_toml` does) with its layer name: `school`, `defaults`, a config's id,
/// `group-<id>`, or `other-<dotted path>` elsewhere. `odd` is called for a `wifi` or
/// `it_account` value of the wrong shape.
fn walk(doc: &mut DocumentMut, f: &mut Visit<'_>, odd: &mut Odd<'_>) {
    walk_table(doc.as_table_mut(), true, "", "other", f, odd);
}

fn secret_fields(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::Wifi => &Wifi::SECRET_FIELDS,
        Kind::ItAccount => &ItAccount::SECRET_FIELDS,
    }
}

/// The reference name in `item`, when it is a `"secret:<name>"` string.
fn reference(item: &Item) -> Option<&str> {
    item.as_str()?.strip_prefix(PREFIX)
}

fn slug(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn parse(text: &str) -> Result<DocumentMut, BundleError> {
    text.parse::<DocumentMut>()
        .map_err(|e| BundleError::Parse(e.to_string()))
}

/// Longest generated name (global constraint `[a-z0-9-]{1,64}`).
const MAX_NAME: usize = 64;

/// Replaces every secret field's value with `"secret:<name>"`; returns the new text and
/// `name -> value`. Existing references stay as they are (their names are reserved).
/// Names are `<layer>-<ssid slug>-<field>` (`<layer>-it-account` for the IT account), with
/// `-2`, `-3`, ... appended on a clash, and never longer than 64 characters.
/// A secret field that is not a string is an error: no secret may be left in the text.
pub fn split(manifest_text: &str) -> Result<(String, BTreeMap<String, String>), BundleError> {
    let mut doc = parse(manifest_text)?;
    let mut taken: BTreeSet<String> = BTreeSet::new();
    walk(
        &mut doc,
        &mut |kind, _, t| {
            for field in secret_fields(kind) {
                if let Some(name) = t.get(field).and_then(reference) {
                    taken.insert(name.to_owned());
                }
            }
        },
        &mut |_| {},
    );
    let mut out = BTreeMap::new();
    let mut changed = false;
    let failure: RefCell<Option<BundleError>> = RefCell::new(None);
    let refuse = |msg: String| {
        failure
            .borrow_mut()
            .get_or_insert(BundleError::Invalid(msg));
    };
    walk(
        &mut doc,
        &mut |kind, layer, t| {
            let ssid = t.get("ssid").and_then(Item::as_str).map(slug);
            for field in secret_fields(kind) {
                let Some(item) = t.get_mut(field) else {
                    continue;
                };
                let Some(value) = item.as_str() else {
                    refuse(format!("{layer}: {field} must be a string"));
                    continue;
                };
                if value.starts_with(PREFIX) {
                    continue;
                }
                let value = value.to_owned();
                let base = match kind {
                    Kind::ItAccount => format!("{layer}-it-account"),
                    Kind::Wifi => {
                        format!("{layer}-{}-{field}", ssid.as_deref().unwrap_or("network"))
                    }
                };
                let mut n = 1;
                let name = loop {
                    let suffix = if n == 1 {
                        String::new()
                    } else {
                        format!("-{n}")
                    };
                    let keep = MAX_NAME - suffix.len();
                    let cand = format!("{}{suffix}", &base[..base.len().min(keep)]);
                    if !taken.contains(&cand) {
                        break cand;
                    }
                    n += 1;
                };
                taken.insert(name.clone());
                set_str(item, &format!("{PREFIX}{name}"));
                out.insert(name, value);
                changed = true;
            }
        },
        &mut |layer| refuse(format!("{layer}: wifi or it_account must be a table")),
    );
    if let Some(e) = failure.into_inner() {
        return Err(e);
    }
    let text = if changed {
        doc.to_string()
    } else {
        manifest_text.to_owned()
    };
    Ok((text, out))
}

fn unknown(name: &str, layer: &str, field: &str) -> Lint {
    Lint::new(
        LintLevel::Error,
        "secret_unknown",
        format!(
            "{layer}: {field} refers to secret \"{name}\", which is not in secrets.toml; ask IT to add `{name}` to secrets.toml."
        ),
    )
    .at(format!("{layer}.{field}"))
    .param("name", name)
    .param("layer", layer)
    .param("field", field)
}

/// Replaces every `"secret:<name>"` with its value. Every reference with no entry in `secrets`
/// is reported (as `secret_unknown`), not only the first.
pub fn fill(manifest_text: &str, secrets: &BTreeMap<String, String>) -> Result<String, Vec<Lint>> {
    let mut doc = parse(manifest_text)
        .map_err(|e| vec![Lint::new(LintLevel::Error, "toml_syntax", e.to_string())])?;
    let mut errors = Vec::new();
    let mut changed = false;
    walk(
        &mut doc,
        &mut |kind, layer, t| {
            for field in secret_fields(kind) {
                let Some(item) = t.get_mut(field) else {
                    continue;
                };
                let Some(name) = reference(item).map(str::to_owned) else {
                    continue;
                };
                match secrets.get(&name) {
                    Some(v) => {
                        set_str(item, v);
                        changed = true;
                    }
                    None => errors.push(unknown(&name, layer, field)),
                }
            }
        },
        &mut |_| {},
    );
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(if changed {
        doc.to_string()
    } else {
        manifest_text.to_owned()
    })
}

/// One place a reference is used: layer, ssid, referencing field and the routing fields.
type Occurrence = Vec<(&'static str, Option<String>)>;

/// For each reference name in the text, every place that uses it.
fn occurrences(doc: &mut DocumentMut) -> BTreeMap<String, Vec<Occurrence>> {
    let mut out: BTreeMap<String, Vec<Occurrence>> = BTreeMap::new();
    walk(
        doc,
        &mut |kind, layer, t| {
            for field in secret_fields(kind) {
                if let Some(name) = t.get(field).and_then(reference) {
                    let mut occ: Occurrence = vec![
                        ("layer", Some(layer.to_owned())),
                        (
                            "ssid",
                            t.get("ssid").map(|i| i.to_string().trim().to_owned()),
                        ),
                        ("field", Some((*field).to_owned())),
                    ];
                    occ.extend(
                        ROUTING_FIELDS
                            .iter()
                            .map(|f| (*f, t.get(f).map(|i| i.to_string().trim().to_owned()))),
                    );
                    out.entry(name.to_owned()).or_default().push(occ);
                }
            }
        },
        &mut |_| {},
    );
    out
}

/// `secret_unknown` (error): a reference with no entry in `secrets`. `secret_unused` (warning):
/// an entry nothing refers to. `secret_rerouted` (warning): a referenced secret's network changed
/// a routing field (`eap`, `server_domain`, ...) since `base_text`. Text that does not parse
/// gives no lints here; the syntax check reports it.
pub fn lints(
    manifest_text: &str,
    secrets: &BTreeMap<String, String>,
    base_text: Option<&str>,
) -> Vec<Lint> {
    let Ok(mut doc) = manifest_text.parse::<DocumentMut>() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut used = BTreeSet::new();
    walk(
        &mut doc,
        &mut |kind, layer, t| {
            for field in secret_fields(kind) {
                if let Some(name) = t.get(field).and_then(reference) {
                    used.insert(name.to_owned());
                    if !secrets.contains_key(name) {
                        out.push(unknown(name, layer, field));
                    }
                }
            }
        },
        &mut |_| {},
    );
    for name in secrets.keys().filter(|n| !used.contains(*n)) {
        out.push(
            Lint::new(
                LintLevel::Warning,
                "secret_unused",
                format!("secrets.toml has \"{name}\", which no setting refers to; remove it."),
            )
            .param("name", name),
        );
    }
    if let Some(mut base) = base_text.and_then(|b| b.parse::<DocumentMut>().ok()) {
        let before = occurrences(&mut base);
        for (name, now) in occurrences(&mut doc) {
            let Some(was) = before.get(&name) else {
                continue;
            };
            for occ in &now {
                if was.contains(occ) {
                    continue;
                }
                // Report the differences against the closest place the base used it.
                let changed: Vec<&str> = was
                    .iter()
                    .map(|w| {
                        occ.iter()
                            .zip(w)
                            .filter(|(a, b)| a.1 != b.1)
                            .map(|(a, _)| a.0)
                            .collect::<Vec<_>>()
                    })
                    .min_by_key(Vec::len)
                    .unwrap_or_default();
                out.push(
                    Lint::new(
                        LintLevel::Warning,
                        "secret_rerouted",
                        format!(
                            "The network using secret \"{name}\" changed {}; check the secret still belongs there.",
                            changed.join(", ")
                        ),
                    )
                    .param("name", &name)
                    .param("fields", changed.join(", ")),
                );
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"# keep me
[defaults]
wifi = [
  { ssid = "Guest", psk = "guestpass" },
]

[defaults.it_account]
password_hash = "$y$hash"

[[config]]
id = "lab"

[[config.wifi]]
ssid = "Corp"
eap = "peap"
server_domain = "a.example"
password = "eappass"
"#;

    fn codes(l: &[Lint]) -> Vec<&'static str> {
        l.iter().map(|l| l.code).collect()
    }

    #[test]
    fn split_then_fill_round_trips() {
        let (text, secrets) = split(SAMPLE).unwrap();
        assert!(
            !text.contains("guestpass") && !text.contains("eappass") && !text.contains("$y$hash")
        );
        assert_eq!(secrets["defaults-guest-psk"], "guestpass");
        assert_eq!(secrets["lab-corp-password"], "eappass");
        assert_eq!(secrets["defaults-it-account"], "$y$hash");
        assert_eq!(fill(&text, &secrets).unwrap(), SAMPLE);
    }

    #[test]
    fn split_keeps_comments() {
        let (text, _) = split(SAMPLE).unwrap();
        assert!(text.starts_with("# keep me\n[defaults]"), "{text}");
        assert!(text.contains("\n\n[[config]]"), "{text}");
    }

    #[test]
    fn names_unique_when_ssids_collide() {
        let t = "[defaults]\nwifi = [{ ssid = \"Guest!\", psk = \"a\" }, { ssid = \"guest?\", psk = \"b\" }]\n";
        let (_, s) = split(t).unwrap();
        assert_eq!(s["defaults-guest--psk"], "a");
        assert_eq!(s["defaults-guest--psk-2"], "b");
        // An existing reference reserves its name.
        let t = "[defaults]\nwifi = [{ ssid = \"Guest!\", psk = \"secret:defaults-guest--psk\" }, { ssid = \"guest?\", psk = \"b\" }]\n";
        let (text, s) = split(t).unwrap();
        assert!(text.contains("secret:defaults-guest--psk\""));
        assert_eq!(s.keys().collect::<Vec<_>>(), ["defaults-guest--psk-2"]);
    }

    #[test]
    fn fill_reports_unknown() {
        let t = "[defaults]\nwifi = [{ ssid = \"A\", psk = \"secret:nope\" }, { ssid = \"B\", psk = \"secret:nope2\" }]\n";
        let errs = fill(t, &BTreeMap::new()).unwrap_err();
        assert_eq!(codes(&errs), ["secret_unknown", "secret_unknown"]);
    }

    #[test]
    fn lints_unused_and_rerouted() {
        let (text, mut secrets) = split(SAMPLE).unwrap();
        assert!(lints(&text, &secrets, Some(&text)).is_empty());
        secrets.insert("extra".into(), "x".into());
        let now = text.replace("a.example", "b.example");
        let l = lints(&now, &secrets, Some(&text));
        assert_eq!(codes(&l), ["secret_unused", "secret_rerouted"]);
        assert_eq!(l[1].level, LintLevel::Warning);
        assert_eq!(l[1].params["fields"], "server_domain");
        secrets.remove("lab-corp-password");
        assert!(codes(&lints(&now, &secrets, None)).contains(&"secret_unknown"));
    }

    fn plain_free(text: &str, secrets: &[&str]) {
        let (out, map) = split(text).unwrap();
        for s in secrets {
            assert!(!out.contains(s), "{s} survived split:\n{out}");
            assert!(map.values().any(|v| v == s), "{s} not collected");
        }
        assert_eq!(fill(&out, &map).unwrap(), text);
    }

    #[test]
    fn school_wifi_is_split() {
        plain_free(
            "[school]\nname = \"S\"\n[[school.wifi]]\nssid = \"A\"\npsk = \"plainA\"\n",
            &["plainA"],
        );
        let (_, m) = split("[school]\nwifi = [{ ssid = \"A\", psk = \"p\" }]\n").unwrap();
        assert!(m.contains_key("school-a-psk"));
    }

    #[test]
    fn legacy_group_wifi_is_split() {
        let t = "[[group]]\nid = \"Old\"\nwifi = [{ ssid = \"G\", psk = \"plainG\" }]\n";
        plain_free(t, &["plainG"]);
        let (_, m) = split(t).unwrap();
        assert!(m.contains_key("group-old-g-psk"), "{m:?}");
    }

    #[test]
    fn it_account_table_and_inline_are_split() {
        plain_free(
            "[defaults.it_account]\npassword_hash = \"plainH\"\n",
            &["plainH"],
        );
        plain_free(
            "[defaults]\nit_account = { password_hash = \"plainI\" }\n",
            &["plainI"],
        );
        plain_free(
            "[[config]]\nid = \"c\"\nit_account = { password_hash = \"plainJ\" }\n",
            &["plainJ"],
        );
    }

    #[test]
    fn odd_placements_are_split() {
        let t = "wifi = [{ ssid = \"R\", psk = \"plainR\" }]\n[it_account]\npassword_hash = \"plainT\"\n[[config]]\nid = \"c\"\n[config.apps]\nwifi = [{ ssid = \"N\", psk = \"plainN\" }]\n";
        plain_free(t, &["plainR", "plainT", "plainN"]);
        let (_, m) = split(t).unwrap();
        assert!(m.contains_key("other-r-psk"), "{m:?}");
        assert!(m.contains_key("other-config-apps-n-psk"), "{m:?}");
    }

    #[test]
    fn non_string_secret_is_refused() {
        assert!(split("[defaults]\nwifi = [{ ssid = \"A\", psk = 12345 }]\n").is_err());
        assert!(split("[defaults]\nit_account = { password_hash = 7 }\n").is_err());
        assert!(split("[defaults]\nwifi = \"oops\"\n").is_err());
    }

    #[test]
    fn names_are_valid_and_short() {
        let (_, m) = split("[[config]]\nid = \"\"\nwifi = [{ ssid = \"A\", psk = \"p\" }]\n[[group]]\nwifi = [{ ssid = \"A\", psk = \"p\" }]\n").unwrap();
        assert!(
            m.contains_key("config-a-psk") && m.contains_key("group-a-psk"),
            "{m:?}"
        );
        let long = "x".repeat(100);
        let t = format!("[defaults]\nwifi = [{{ ssid = \"{long}\", psk = \"a\" }}, {{ ssid = \"{long}\", psk = \"b\" }}]\n");
        let (_, m) = split(&t).unwrap();
        assert_eq!(m.len(), 2);
        for k in m.keys() {
            assert!(k.len() <= 64 && !k.is_empty(), "{k}");
            assert!(k
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
        }
    }

    #[test]
    fn rerouted_when_second_network_reuses_secret() {
        let (base, secrets) = split(SAMPLE).unwrap();
        let now = format!("{base}\n[[config]]\nid = \"evil\"\nwifi = [{{ ssid = \"Evil\", psk = \"secret:defaults-guest-psk\" }}]\n");
        let l = lints(&now, &secrets, Some(&base));
        assert_eq!(codes(&l), ["secret_rerouted"], "{l:?}");
    }

    #[test]
    fn rerouted_when_ssid_changes() {
        let (base, secrets) = split(SAMPLE).unwrap();
        let now = base.replace("\"Guest\"", "\"Other\"");
        let l = lints(&now, &secrets, Some(&base));
        assert_eq!(codes(&l), ["secret_rerouted"], "{l:?}");
        assert_eq!(l[0].params["fields"], "ssid");
        let moved = base.replace(
            "psk = \"secret:defaults-guest-psk\"",
            "password = \"secret:defaults-guest-psk\"",
        );
        assert_eq!(
            codes(&lints(&moved, &secrets, Some(&base))),
            ["secret_rerouted"]
        );
    }

    #[test]
    fn not_rerouted_when_unchanged() {
        let (base, secrets) = split(SAMPLE).unwrap();
        assert!(lints(&base, &secrets, Some(&base)).is_empty());
    }
}
