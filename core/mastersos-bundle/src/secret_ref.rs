//! Secrets kept out of the settings text: `split` swaps each secret field's value for a
//! `"secret:<name>"` reference, `fill` puts the values back, `lints` checks the pairing.
//!
//! The layers and fields walked are those of the private server's `mask_toml`: `[school]`,
//! `[defaults]`, each `[[config]]` and each legacy `[[group]]`, their `wifi` entries and
//! `it_account`.

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

fn visit_wifi(item: &mut Item, layer: &str, f: &mut Visit<'_>) {
    match item {
        Item::ArrayOfTables(a) => a.iter_mut().for_each(|t| f(Kind::Wifi, layer, t)),
        Item::Table(t) => f(Kind::Wifi, layer, t),
        Item::Value(Value::InlineTable(t)) => f(Kind::Wifi, layer, t),
        Item::Value(Value::Array(arr)) => {
            for v in arr.iter_mut() {
                if let Value::InlineTable(t) = v {
                    f(Kind::Wifi, layer, t);
                }
            }
        }
        _ => {}
    }
}

fn visit_layer(t: &mut dyn TableLike, layer: &str, f: &mut Visit<'_>) {
    if let Some(item) = t.get_mut("wifi") {
        visit_wifi(item, layer, f);
    }
    match t.get_mut("it_account") {
        Some(Item::Table(it)) => f(Kind::ItAccount, layer, it),
        Some(Item::Value(Value::InlineTable(it))) => f(Kind::ItAccount, layer, it),
        _ => {}
    }
}

/// Calls `f` on every Wi-Fi entry and `it_account` table with its layer name.
fn walk(doc: &mut DocumentMut, f: &mut Visit<'_>) {
    let root = doc.as_table_mut();
    if let Some(Item::Table(t)) = root.get_mut("school") {
        visit_layer(t, "school", f);
    }
    if let Some(Item::Table(t)) = root.get_mut("defaults") {
        visit_layer(t, "defaults", f);
    }
    for (key, prefix) in [("config", ""), ("group", "group-")] {
        let id_of = |t: &dyn TableLike| {
            format!(
                "{prefix}{}",
                t.get("id").and_then(Item::as_str).unwrap_or_default()
            )
        };
        match root.get_mut(key) {
            Some(Item::ArrayOfTables(a)) => {
                for t in a.iter_mut() {
                    let layer = id_of(t);
                    visit_layer(t, &layer, f);
                }
            }
            Some(Item::Value(Value::Array(arr))) => {
                for v in arr.iter_mut() {
                    if let Value::InlineTable(t) = v {
                        let layer = id_of(t);
                        visit_layer(t, &layer, f);
                    }
                }
            }
            _ => {}
        }
    }
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

/// Replaces every secret field's value with `"secret:<name>"`; returns the new text and
/// `name -> value`. Existing references stay as they are (their names are reserved).
/// Names are `<layer>-<ssid slug>-<field>` (`<layer>-it-account` for the IT account), with
/// `-2`, `-3`, ... appended on a clash.
pub fn split(manifest_text: &str) -> Result<(String, BTreeMap<String, String>), BundleError> {
    let mut doc = parse(manifest_text)?;
    let mut taken: BTreeSet<String> = BTreeSet::new();
    walk(&mut doc, &mut |kind, _, t| {
        for field in secret_fields(kind) {
            if let Some(name) = t.get(field).and_then(reference) {
                taken.insert(name.to_owned());
            }
        }
    });
    let mut out = BTreeMap::new();
    let mut changed = false;
    walk(&mut doc, &mut |kind, layer, t| {
        let ssid = t.get("ssid").and_then(Item::as_str).map(slug);
        for field in secret_fields(kind) {
            let Some(item) = t.get_mut(field) else {
                continue;
            };
            let Some(value) = item.as_str() else {
                continue;
            };
            if value.starts_with(PREFIX) {
                continue;
            }
            let value = value.to_owned();
            let base = match kind {
                Kind::ItAccount => format!("{layer}-it-account"),
                Kind::Wifi => format!("{layer}-{}-{field}", ssid.as_deref().unwrap_or("network")),
            };
            let mut name = base.clone();
            let mut n = 2;
            while taken.contains(&name) {
                name = format!("{base}-{n}");
                n += 1;
            }
            taken.insert(name.clone());
            set_str(item, &format!("{PREFIX}{name}"));
            out.insert(name, value);
            changed = true;
        }
    });
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
            "{layer}: {field} refers to secret \"{name}\", which is not in secrets.toml; add it or enter the value."
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
    walk(&mut doc, &mut |kind, layer, t| {
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
    });
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(if changed {
        doc.to_string()
    } else {
        manifest_text.to_owned()
    })
}

type Routing = Vec<(&'static str, Option<String>)>;

/// For each reference name in the text, the routing fields of the network holding it.
fn routing_by_name(doc: &mut DocumentMut) -> BTreeMap<String, Routing> {
    let mut out = BTreeMap::new();
    walk(doc, &mut |kind, _, t| {
        let routing: Routing = ROUTING_FIELDS
            .iter()
            .map(|f| (*f, t.get(f).map(|i| i.to_string().trim().to_owned())))
            .collect();
        for field in secret_fields(kind) {
            if let Some(name) = t.get(field).and_then(reference) {
                out.insert(name.to_owned(), routing.clone());
            }
        }
    });
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
    walk(&mut doc, &mut |kind, layer, t| {
        for field in secret_fields(kind) {
            if let Some(name) = t.get(field).and_then(reference) {
                used.insert(name.to_owned());
                if !secrets.contains_key(name) {
                    out.push(unknown(name, layer, field));
                }
            }
        }
    });
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
        let before = routing_by_name(&mut base);
        for (name, now) in routing_by_name(&mut doc) {
            let Some(was) = before.get(&name) else {
                continue;
            };
            let changed: Vec<&str> = now
                .iter()
                .zip(was)
                .filter(|(a, b)| a.1 != b.1)
                .map(|(a, _)| a.0)
                .collect();
            if !changed.is_empty() {
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
}
