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

/// Where a secret field sends its value: layer, ssid, the field and the routing fields.
type Occurrence = Vec<(&'static str, Option<String>)>;

/// The SHA-256 of a secret value. Not `Debug`, never printed: it would let a weak password be
/// guessed offline.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct ValueHash([u8; 32]);

impl ValueHash {
    fn of(value: &str) -> ValueHash {
        use sha2::Digest as _;
        ValueHash(sha2::Sha256::digest(value.as_bytes()).into())
    }
}

/// One secret field in use.
struct Use {
    /// The reference name; `None` for a value written in place (as in a published version).
    name: Option<String>,
    value: ValueHash,
    route: Occurrence,
}

/// A field's text: the string itself, or the TOML of another value.
fn text_of(item: &Item) -> String {
    item.as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| item.to_string().trim().to_owned())
}

/// Every secret field with a value: a reference is filled from `secrets` (an unknown one is
/// skipped: `secret_unknown` reports it), a value written in place is taken as it is.
fn uses(doc: &mut DocumentMut, secrets: &BTreeMap<String, String>) -> Vec<Use> {
    let mut out = Vec::new();
    walk(
        doc,
        &mut |kind, layer, t| {
            for field in secret_fields(kind) {
                let Some(text) = t.get(field).and_then(Item::as_str) else {
                    continue;
                };
                let (name, value) = match text.strip_prefix(PREFIX) {
                    Some(n) => match secrets.get(n) {
                        Some(v) => (Some(n.to_owned()), v.as_str()),
                        None => continue,
                    },
                    None => (None, text),
                };
                let mut route: Occurrence = vec![
                    ("layer", Some(layer.to_owned())),
                    ("ssid", t.get("ssid").map(text_of)),
                    ("field", Some((*field).to_owned())),
                ];
                route.extend(ROUTING_FIELDS.iter().map(|f| (*f, t.get(f).map(text_of))));
                out.push(Use {
                    name,
                    value: ValueHash::of(value),
                    route,
                });
            }
        },
        &mut |_| {},
    );
    out
}

/// `secret_unknown` (error): a reference with no entry in `secrets`. `secret_unused` (warning):
/// an entry nothing refers to. Both go by name.
///
/// `secret_rerouted` (warning) goes by value, against `base_filled`: the published version with
/// its secret values in (the caller has checked it is the version this computer verified). Each
/// secret field of `manifest_text` that is a reference with a value in `secrets` has a value v
/// and a route t (layer, `ssid`, the field, and `eap`, `phase2`, `identity`,
/// `anonymous_identity`, `server_domain`, `ca_cert`, `check_server`):
///
/// - v was in the base under t: fine;
/// - v was in the base, only under other routes: rerouted (an existing secret goes somewhere new);
/// - v was not in the base, but t was (with any value): fine, a password change;
/// - v was not in the base and neither was t: rerouted (a new network).
///
/// The lint names the working copy's reference, which `--allow-reroute` takes. Values are
/// compared as SHA-256 hashes and never leave this function. Without a base (the first version)
/// nothing is rerouted. It stays a warning (the settings are valid), but `mastersos publish`
/// refuses while one exists unless IT approves that secret by name ([`unapproved_reroutes`]).
/// Text that does not parse gives no lints here; the syntax check reports it.
pub fn lints(
    manifest_text: &str,
    secrets: &BTreeMap<String, String>,
    base_filled: Option<&str>,
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
    if let Some(mut base) = base_filled.and_then(|b| b.parse::<DocumentMut>().ok()) {
        // By value, never by name: the base's reference names live in a file anyone can edit,
        // but the filled base is the published version (its digest is checked against the pin).
        let before = uses(&mut base, &BTreeMap::new());
        let mut routes_of: BTreeMap<&ValueHash, Vec<&Occurrence>> = BTreeMap::new();
        for u in &before {
            routes_of.entry(&u.value).or_default().push(&u.route);
        }
        let known: BTreeSet<&Occurrence> = before.iter().map(|u| &u.route).collect();
        for u in uses(&mut doc, secrets) {
            let Some(name) = u.name else {
                continue;
            };
            match routes_of.get(&u.value) {
                // The same value where the base sent it.
                Some(was) if was.contains(&&u.route) => {}
                // A value the base sent elsewhere now goes here.
                Some(was) => {
                    // Report the differences against the closest place the base used it.
                    let changed: Vec<&str> = was
                        .iter()
                        .map(|w| {
                            u.route
                                .iter()
                                .zip(w.iter())
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
                                "Secret \"{name}\" was sent to another network in the published version; here {} differ, so it would be sent somewhere new. `mastersos publish` refuses this until IT checks `mastersos diff`, confirms the secret belongs there and passes --allow-reroute {name}.",
                                changed.join(", ")
                            ),
                        )
                        .param("name", &name)
                        .param("fields", changed.join(", ")),
                    );
                }
                // A value the base never had, on a network the base had: a password change.
                None if known.contains(&u.route) => {}
                // A value the base never had, on a network the base did not have.
                None => out.push(
                    Lint::new(
                        LintLevel::Warning,
                        "secret_rerouted",
                        format!(
                            "Secret \"{name}\" goes to a network the published version did not have, so it would be sent somewhere new. `mastersos publish` refuses this until IT checks `mastersos diff` and passes --allow-reroute {name}."
                        ),
                    )
                    .param("name", &name)
                    .param("fields", "new network"),
                ),
            }
        }
    }
    out
}

/// The secret names that `secret_rerouted` lints in `lints` report, each once.
pub fn rerouted_names(lints: &[Lint]) -> BTreeSet<String> {
    lints
        .iter()
        .filter(|l| l.code == "secret_rerouted")
        .filter_map(|l| l.params.get("name").cloned())
        .collect()
}

/// The rerouted secrets ([`rerouted_names`]) that IT has not approved by name in `allowed`
/// (`mastersos publish --allow-reroute <name>`), sorted. Publishing goes ahead only when this is
/// empty; an approval names one secret, so approving another name approves nothing here.
pub fn unapproved_reroutes(lints: &[Lint], allowed: &[String]) -> Vec<String> {
    rerouted_names(lints)
        .into_iter()
        .filter(|n| !allowed.iter().any(|a| a == n))
        .collect()
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
        assert!(lints(&text, &secrets, Some(SAMPLE)).is_empty());
        secrets.insert("extra".into(), "x".into());
        let now = text.replace("a.example", "b.example");
        let l = lints(&now, &secrets, Some(SAMPLE));
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
        let l = lints(&now, &secrets, Some(SAMPLE));
        assert_eq!(codes(&l), ["secret_rerouted"], "{l:?}");
    }

    #[test]
    fn rerouted_when_ssid_changes() {
        let (base, secrets) = split(SAMPLE).unwrap();
        let now = base.replace("\"Guest\"", "\"Other\"");
        let l = lints(&now, &secrets, Some(SAMPLE));
        assert_eq!(codes(&l), ["secret_rerouted"], "{l:?}");
        assert_eq!(l[0].params["fields"], "ssid");
        let moved = base.replace(
            "psk = \"secret:defaults-guest-psk\"",
            "password = \"secret:defaults-guest-psk\"",
        );
        assert_eq!(
            codes(&lints(&moved, &secrets, Some(SAMPLE))),
            ["secret_rerouted"]
        );
    }

    #[test]
    fn reroutes_need_approval_by_name() {
        let (base, secrets) = split(SAMPLE).unwrap();
        let now = base
            .replace("a.example", "b.example")
            .replace("\"Guest\"", "\"Other\"");
        let l = lints(&now, &secrets, Some(SAMPLE));
        assert_eq!(codes(&l), ["secret_rerouted", "secret_rerouted"], "{l:?}");
        assert!(l[0].message.contains("--allow-reroute"), "{}", l[0].message);
        let all = ["defaults-guest-psk", "lab-corp-password"];
        assert_eq!(rerouted_names(&l).into_iter().collect::<Vec<_>>(), all);
        assert_eq!(unapproved_reroutes(&l, &[]), all);
        assert_eq!(
            unapproved_reroutes(&l, &["defaults-guest-psk".into()]),
            ["lab-corp-password"]
        );
        // A wrong name approves nothing.
        assert_eq!(unapproved_reroutes(&l, &["nope".into()]), all);
        let both: Vec<String> = all.iter().map(|s| s.to_string()).collect();
        assert!(unapproved_reroutes(&l, &both).is_empty());
        assert!(unapproved_reroutes(&lints(&base, &secrets, Some(SAMPLE)), &[]).is_empty());
    }

    #[test]
    fn stale_secret_on_a_new_network_is_rerouted() {
        // secrets.toml still holds a value nothing in the base refers to; a new network that
        // points at it (here with a server of its choosing) must not pass silently.
        let (base, mut secrets) = split(SAMPLE).unwrap();
        secrets.insert("old-corp".into(), "oldpass".into());
        let now = format!("{base}\n[[config]]\nid = \"evil\"\n[[config.wifi]]\nssid = \"Corp\"\neap = \"peap\"\nserver_domain = \"evil.example\"\npassword = \"secret:old-corp\"\n");
        let l = lints(&now, &secrets, Some(SAMPLE));
        assert_eq!(codes(&l), ["secret_rerouted"], "{l:?}");
        assert_eq!(l[0].params["name"], "old-corp");
        assert_eq!(unapproved_reroutes(&l, &[]), ["old-corp"]);
    }

    #[test]
    fn new_secret_needs_approval_unless_there_is_no_base() {
        let (base, mut secrets) = split(SAMPLE).unwrap();
        let now = format!("{base}\n[[config]]\nid = \"lab2\"\nwifi = [{{ ssid = \"Lab2\", psk = \"secret:lab2-psk\" }}]\n");
        secrets.insert("lab2-psk".into(), "lab2pass".into());
        let l = lints(&now, &secrets, Some(SAMPLE));
        assert_eq!(codes(&l), ["secret_rerouted"], "{l:?}");
        assert_eq!(unapproved_reroutes(&l, &[]), ["lab2-psk"]);
        assert!(unapproved_reroutes(&l, &["lab2-psk".into()]).is_empty());
        // No published base (the first version): nothing is rerouted.
        assert!(lints(&now, &secrets, None).is_empty());
    }

    #[test]
    fn reroute_goes_by_value_not_by_name() {
        // The working copy may name its references anything: a reference whose value the
        // published version sent to Guest now on Corp is rerouted, whatever its name says.
        let (base, mut secrets) = split(SAMPLE).unwrap();
        secrets.insert("lab-corp-password".into(), "guestpass".into());
        let l = lints(&base, &secrets, Some(SAMPLE));
        assert_eq!(codes(&l), ["secret_rerouted"], "{l:?}");
        assert_eq!(l[0].params["name"], "lab-corp-password");
        // Two references swapped consistently with their values: both values move.
        let (base, mut secrets) = split(SAMPLE).unwrap();
        secrets.insert("lab-corp-password".into(), "guestpass".into());
        secrets.insert("defaults-guest-psk".into(), "eappass".into());
        let l = lints(&base, &secrets, Some(SAMPLE));
        assert_eq!(
            unapproved_reroutes(&l, &[]),
            ["defaults-guest-psk", "lab-corp-password"]
        );
        // No message or param holds a value.
        for x in &l {
            let all = format!("{} {:?}", x.message, x.params);
            assert!(
                !all.contains("guestpass") && !all.contains("eappass"),
                "{all}"
            );
        }
    }

    #[test]
    fn password_change_on_the_same_network_is_not_a_reroute() {
        let (base, mut secrets) = split(SAMPLE).unwrap();
        secrets.insert("lab-corp-password".into(), "a-new-password".into());
        assert!(lints(&base, &secrets, Some(SAMPLE)).is_empty());
        // Renamed in the working copy, same value, same network: not a reroute either.
        let renamed = base.replace("secret:defaults-guest-psk", "secret:guest");
        let v = secrets.remove("defaults-guest-psk").unwrap();
        secrets.insert("guest".into(), v);
        assert!(lints(&renamed, &secrets, Some(SAMPLE)).is_empty());
    }

    #[test]
    fn existing_value_moved_to_another_existing_network_is_rerouted() {
        // Corp existed in the base, but with another value: Guest's password now goes there.
        let (base, mut secrets) = split(SAMPLE).unwrap();
        secrets.insert("lab-corp-password".into(), "guestpass".into());
        let l = lints(&base, &secrets, Some(SAMPLE));
        assert_eq!(codes(&l), ["secret_rerouted"]);
        assert_ne!(l[0].params["fields"], "new network");
    }

    #[test]
    fn not_rerouted_when_unchanged() {
        let (base, secrets) = split(SAMPLE).unwrap();
        assert!(lints(&base, &secrets, Some(SAMPLE)).is_empty());
    }
}
