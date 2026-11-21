//! Signing with the school key on this computer: the bundle signature and the monthly check-in
//! (built here, never from the server's words) and the local diff shown before a publish
//! (Ruling 1, 2, 15). Seeds are made and checked in [`crate::seed`].
//!
//! It is the trust anchor for trust changes, so it **does not trust the server**:
//! - The chain is verified here one version at a time, as the agent does ([`chain`]);
//!   differences, digests and trust additions and removals are computed here from verified
//!   content.
//! - Only bytes built or verified here are signed: the bundle signature's message is computed from
//!   the content ([`sign_bundle`]); a message the server sends is never signed.
//! - The school key is never printed to the terminal or written to a log.
//! - Every string from the server is escaped by [`safe`] before it is printed: control sequences
//!   can neither hide a line nor forge one.
pub mod chain;
pub mod kit;

use crate::safe;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Write};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use mastersos_bundle::{
    heartbeat_message, signed_message, trust_fingerprint, verify_heartbeat, Contents, Heartbeat,
    HeartbeatStatement, KeyAlg, SignatureFile, Signer, TrustKey, MAX_HEARTBEAT_DAYS,
};

use chain::Verified;

// —— Printing and confirmation ——

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One trusted key for people: the school key's key code (or the id of another kind of key) and
/// its full fingerprint.
pub fn key_line(k: &TrustKey) -> String {
    let name = match mastersos_bundle::keyid::key_code(&k.id) {
        Some(code) => format!("school key {code}"),
        None => format!("key {}", safe::field(&k.id)),
    };
    // The site is part of what a computer checks, so a change to it must show on the screen.
    let site = match &k.rp_id {
        Some(rp) => format!(" (site {})", safe::field(rp)),
        None => String::new(),
    };
    format!("{name}  fingerprint {}{site}", trust_fingerprint(k))
}

pub(crate) fn print_trust(out: &mut dyn Write, trust: &[TrustKey]) -> Result<()> {
    for k in trust {
        writeln!(out, "    {}", key_line(k))?;
    }
    Ok(())
}

/// What changed between two trusts: keys added, removed and changed (paired by id; a key with
/// the same id and any other field different is changed).
pub(crate) struct TrustDelta<'a> {
    pub added: Vec<&'a TrustKey>,
    pub removed: Vec<&'a TrustKey>,
    pub modified: Vec<(&'a TrustKey, &'a TrustKey)>,
}

impl<'a> TrustDelta<'a> {
    pub fn between(old: &'a [TrustKey], new: &'a [TrustKey]) -> Self {
        let o: BTreeMap<&str, &TrustKey> = old.iter().map(|k| (k.id.as_str(), k)).collect();
        let n: BTreeMap<&str, &TrustKey> = new.iter().map(|k| (k.id.as_str(), k)).collect();
        TrustDelta {
            added: new
                .iter()
                .filter(|k| !o.contains_key(k.id.as_str()))
                .collect(),
            removed: old
                .iter()
                .filter(|k| !n.contains_key(k.id.as_str()))
                .collect(),
            modified: new
                .iter()
                .filter_map(|k| {
                    o.get(k.id.as_str())
                        .filter(|ok| **ok != k)
                        .map(|ok| (*ok, k))
                })
                .collect(),
        }
    }

    /// Nothing added, removed or changed. Key order does not matter to machines, so a new order
    /// alone is no change.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }

    pub fn print(&self, out: &mut dyn Write) -> Result<()> {
        for k in &self.added {
            writeln!(out, "    + added    {}", key_line(k))?;
        }
        for k in &self.removed {
            writeln!(out, "    - removed  {}", key_line(k))?;
        }
        for (o, n) in &self.modified {
            writeln!(out, "    ~ changed  {}", key_line(o))?;
            writeln!(out, "           ->  {}", key_line(n))?;
        }
        Ok(())
    }
}

/// Print the prompt and read one line (surrounding whitespace removed). End of input (nothing
/// typed) cancels.
pub(crate) fn ask(confirm: &mut dyn BufRead, out: &mut dyn Write, prompt: &str) -> Result<String> {
    write!(out, "{prompt}")?;
    out.flush()?;
    let mut line = String::new();
    if confirm.read_line(&mut line)? == 0 {
        bail!("No input was read; cancelled");
    }
    Ok(line.trim().to_owned())
}

// —— Publishing ——

/// The secret values of both sides, longest first; `None` when a side's secrets could not be
/// separated.
type SecretValues = Option<Vec<String>>;

/// The local diff. Secret values are never printed: both manifests are split into references
/// first ([`mastersos_bundle::secret_ref::split`]), the split texts are diffed, and each secret
/// whose value differs gets one line with its name only.
pub(crate) fn print_local_diff(
    out: &mut dyn Write,
    old: &Verified,
    new_version: u64,
    new: &Contents,
) -> Result<SecretValues> {
    use mastersos_bundle::secret_ref::split;
    let old_v = format!("v{}", old.version);
    let new_v = format!("v{new_version} (to publish)");
    writeln!(
        out,
        "\n== Differences computed on this computer (version {} -> version {new_version}) ==",
        old.version
    )?;
    let mut values = None;
    match (
        split(&old.contents.manifest_text),
        split(&new.manifest_text),
    ) {
        (Ok((old_split, old_secrets)), Ok((new_split, new_secrets))) => {
            let (old_text, new_text) = (
                safe::escape_lines(&old_split),
                safe::escape_lines(&new_split),
            );
            let text = similar::TextDiff::from_lines(&old_text, &new_text)
                .unified_diff()
                .header(&old_v, &new_v)
                .to_string();
            if text.is_empty() {
                writeln!(out, "manifest.toml: no changes")?;
            } else {
                writeln!(out, "manifest.toml:")?;
                write!(out, "{}", safe::cap_lines(&text))?;
            }
            let names: BTreeSet<&String> = old_secrets.keys().chain(new_secrets.keys()).collect();
            for name in names {
                let what = match (old_secrets.get(name), new_secrets.get(name)) {
                    (None, Some(_)) => "added",
                    (Some(_), None) => "removed",
                    (Some(a), Some(b)) if a != b => "changed",
                    _ => continue,
                };
                writeln!(out, "secret {}: {what}", safe::field(name))?;
            }
            let mut v: Vec<String> = old_secrets
                .into_values()
                .chain(new_secrets.into_values())
                .filter(|v| !v.is_empty())
                .collect();
            v.sort_by_key(|s| std::cmp::Reverse(s.len()));
            v.dedup();
            values = Some(v);
        }
        _ if old.contents.manifest_text == new.manifest_text => {
            writeln!(out, "manifest.toml: no changes")?;
        }
        _ => writeln!(
            out,
            "manifest changed (diff hidden: could not separate secrets)"
        )?,
    }
    let short = |b: &[u8]| hex(&<sha2::Sha256 as sha2::Digest>::digest(b))[..16].to_owned();
    let (of, nf) = (&old.contents.files, &new.files);
    let mut any = false;
    for (path, b) in nf {
        let p = safe::field(path);
        match of.get(path) {
            None => writeln!(
                out,
                "  + added file {p} ({} bytes, sha256 {}...)",
                b.len(),
                short(b)
            )?,
            Some(o) if o != b => writeln!(
                out,
                "  ~ changed file {p} ({} -> {} bytes, sha256 {}... -> {}...)",
                o.len(),
                b.len(),
                short(o),
                short(b)
            )?,
            Some(_) => continue,
        }
        any = true;
    }
    for (path, b) in of {
        if !nf.contains_key(path) {
            writeln!(
                out,
                "  - removed file {} ({} bytes)",
                safe::field(path),
                b.len()
            )?;
            any = true;
        }
    }
    if !any {
        writeln!(out, "Files: no changes")?;
    }
    Ok(values)
}

// —— Signing here, without the server ——

/// The bundle signature over `contents`, made here: the message is computed from the content on
/// this computer (`b"mastersos-bundle-v1\n" || content_digest`), never taken from the server.
pub fn sign_bundle(signer: &dyn Signer, contents: &Contents) -> SignatureFile {
    SignatureFile {
        key_id: signer.key_id().to_owned(),
        alg: KeyAlg::Ed25519,
        sig: STANDARD.encode(signer.sign(&signed_message(contents))),
        authenticator_data: None,
        client_data_json: None,
    }
}

/// The monthly check-in for `version` with content digest `digest_hex` (from what was verified or
/// signed here), issued at `issued_at` (Unix seconds) and lasting `days` days, signed here and read
/// back the way a Device reads it with `trust`. Returns the TOML text `POST heartbeat` carries and
/// the statement. Nothing is fetched to decide what is signed.
pub fn sign_heartbeat(
    signer: &dyn Signer,
    version: u64,
    digest_hex: &str,
    issued_at: i64,
    days: i64,
    trust: &[TrustKey],
) -> Result<(String, HeartbeatStatement)> {
    if !(1..=MAX_HEARTBEAT_DAYS).contains(&days) {
        bail!("a monthly check-in lasts 1 to {MAX_HEARTBEAT_DAYS} days, not {days}");
    }
    let not_after = days
        .checked_mul(86_400)
        .and_then(|s| issued_at.checked_add(s))
        .context("the check-in's end is out of range")?;
    let statement = HeartbeatStatement {
        version,
        digest_hex: digest_hex.to_owned(),
        issued_at,
        not_after,
    };
    statement.check()?;
    let signature = SignatureFile {
        key_id: signer.key_id().to_owned(),
        alg: KeyAlg::Ed25519,
        sig: STANDARD.encode(signer.sign(&heartbeat_message(&statement))),
        authenticator_data: None,
        client_data_json: None,
    };
    let text = Heartbeat {
        statement: statement.clone(),
        signature,
    }
    .to_toml();
    let checked = verify_heartbeat(&text, trust).context(
        "The signed check-in fails the local self-check: computers would reject it; not submitting",
    )?;
    if checked != statement {
        bail!("The check-in read back differs from the one signed; not submitting");
    }
    Ok((text, statement))
}

#[cfg(test)]
mod tests {
    #[test]
    fn key_line_shows_the_site_of_a_key() {
        let mk = |rp: Option<&str>| TrustKey {
            id: "pk-1".into(),
            alg: mastersos_bundle::KeyAlg::WebauthnEs256,
            public_key: "AAAA".into(),
            rp_id: rp.map(str::to_owned),
        };
        let (a, b, none) = (
            key_line(&mk(Some("one.example"))),
            key_line(&mk(Some("two.example"))),
            key_line(&mk(None)),
        );
        assert_ne!(a, b);
        assert_ne!(a, none);
        assert!(a.ends_with(" (site one.example)"), "{a}");
        assert!(!none.contains("site"), "{none}");
        assert!(!a.to_lowercase().contains("passkey"), "{a}");
    }

    use super::*;

    fn verified(text: &str) -> Verified {
        Verified {
            version: 1,
            digest_hex: String::new(),
            trust: Vec::new(),
            contents: Contents {
                manifest_text: text.into(),
                files: BTreeMap::new(),
            },
            latest: 1,
            history: Vec::new(),
        }
    }

    #[test]
    fn an_old_host_only_pin_records_no_digest_offline() {
        use super::chain::recorded_digest;
        const SCHOOL: &str = "0192f3a4-5b6c-7d8e-9f00-112233445566";
        let dir = tempfile::tempdir().unwrap();
        // A pin of the old admin API: file `<host>.toml`, `host = "<host>"`. Offline, only a
        // protocol v1 pin (origin and school) records a digest; the chain loader alone takes the
        // old one over, by verifying forward from it.
        let old = "host = \"cloud.example\"\nversion = 3\ndigest_hex = \"d3\"\ntrust = []\n";
        let old_file = dir.path().join("cloud.example.toml");
        std::fs::write(&old_file, old).unwrap();
        assert_eq!(
            recorded_digest(dir.path(), "https://cloud.example", SCHOOL, 3).unwrap(),
            None
        );
        assert_eq!(std::fs::read_to_string(&old_file).unwrap(), old);
    }

    #[test]
    fn sign_diff_never_prints_secret_values() {
        let old = verified(
            "version = 1\n[defaults]\nwifi = [{ ssid = \"Staff\", psk = \"oldpass-111\" }, { ssid = \"Lab\", psk = \"labpass-333\" }]\n",
        );
        let new = Contents {
            manifest_text: "version = 2\n[defaults]\nwifi = [{ ssid = \"Staff\", psk = \"newpass-222\" }, { ssid = \"Guest\", psk = \"guestpass-444\" }]\n".into(),
            files: BTreeMap::new(),
        };
        let mut out = Vec::new();
        let values = print_local_diff(&mut out, &old, 2, &new).unwrap();
        assert!(values.is_some());
        let text = String::from_utf8(out).unwrap();
        for v in ["oldpass-111", "newpass-222", "labpass-333", "guestpass-444"] {
            assert!(!text.contains(v), "{text}");
        }
        assert!(
            text.contains("secret defaults-staff-psk: changed"),
            "{text}"
        );
        assert!(text.contains("secret defaults-guest-psk: added"), "{text}");
        assert!(text.contains("secret defaults-lab-psk: removed"), "{text}");
        assert!(text.contains("+version = 2"), "{text}");

        // A side whose secrets cannot be separated: no text diff at all.
        let bad = Contents {
            manifest_text: "version = 2\n[defaults]\nwifi = [{ ssid = \"Staff\", psk = 12345678 }]\n# newpass-222\n".into(),
            files: BTreeMap::new(),
        };
        let mut out = Vec::new();
        let values = print_local_diff(&mut out, &old, 2, &bad).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(values.is_none());
        assert!(
            text.contains("manifest changed (diff hidden: could not separate secrets)"),
            "{text}"
        );
        assert!(
            !text.contains("oldpass-111") && !text.contains("newpass-222"),
            "{text}"
        );
    }

    #[test]
    fn local_diff_escapes_control_chars() {
        let old = Verified {
            version: 1,
            digest_hex: String::new(),
            trust: Vec::new(),
            contents: Contents {
                manifest_text: "version = 1\n".into(),
                files: BTreeMap::new(),
            },
            latest: 1,
            history: Vec::new(),
        };
        let mut files = BTreeMap::new();
        files.insert("files/a\u{1b}[2K\r.txt".to_owned(), b"x".to_vec());
        let new = Contents {
            // TOML refuses raw control characters even in comments (such a manifest never reaches
            // the diff: it is parsed first), so the manifest side carries only a bidi override.
            manifest_text: "version = 2\n# 伪造的一行\u{202e}\n".into(),
            files,
        };
        let mut out = Vec::new();
        print_local_diff(&mut out, &old, 2, &new).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            !out.chars()
                .any(|c| (c.is_control() && c != '\n') || c == '\u{202e}'),
            "{out:?}"
        );
        assert!(out.contains("+# 伪造的一行\\u{202e}"), "{out}");
        assert!(out.contains("files/a\\x1b[2K\\r.txt"), "{out}");
    }
}
