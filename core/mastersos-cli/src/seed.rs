//! `mastersos seed make` and `mastersos seed check`. A seed is a Device's root of trust: the
//! first trusted keys, the lowest version it accepts, its server and school, and the school's
//! fetch token (protocol §3.8, §4.9).
//!
//! - Trust, `min_version` and everything else in a seed come only from the latest version the
//!   chain verified here ([`crate::sign::chain::verify_chain`], the single chain loader). The
//!   server gives only `server_url`, `school_id` and the fetch token, each checked before use.
//! - The Group is resolved locally before `POST seed`: an unknown Group asks the server for no
//!   fetch token.
//! - The fetch token, the Wi-Fi keys and the IT password hash are written into the seed file
//!   (owner-only) and nowhere else: never printed, in `--json`, in an error or a problem.

use std::io::Read as _;
use std::path::Path;

use mastersos_bundle::{
    select, trust_fingerprint, Config, DeviceIdent, ItAccount, LoginMethod, Manifest, Oidc, Seed,
    TrustKey, Wifi, DEFAULT_GROUP, MAX_SEED_BYTES,
};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::safe;
use crate::server::{CliError, Server};
use crate::sign::chain::{recorded_contents, recorded_version, to_cli_error, Verified};
use crate::sign::key_line;

/// The longest fetch token, in bytes (protocol §3.1).
pub const MAX_FETCH_TOKEN_BYTES: usize = 256;

fn invalid(message: &str) -> CliError {
    CliError::new("seed_invalid", message)
}

fn bad_answer(message: &str) -> CliError {
    CliError::new("invalid_answer", message)
}

/// The shape of a fetch token (protocol §3.1): 1 to 256 bytes of printable ASCII without spaces
/// (0x21-0x7e). The token itself is opaque.
pub fn fetch_token_shape_ok(t: &str) -> bool {
    (1..=MAX_FETCH_TOKEN_BYTES).contains(&t.len()) && t.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// The Device config the seed's Devices get: the Group's (the default Group without one), after
/// checking that `m` is school `school_id`'s and that the Group exists.
fn group_config(m: &Manifest, group: Option<&str>, school_id: &str) -> Result<Config, CliError> {
    if m.school.id.as_deref() != Some(school_id) {
        return Err(invalid(&format!(
            "the verified version does not belong to school {school_id}"
        )));
    }
    let id = group.unwrap_or(DEFAULT_GROUP);
    // `select` assumes a validated manifest; a missing Group or Config is refused here first.
    if m.effective_of_group(id).is_none() {
        return Err(invalid(&format!(
            "Group {} does not exist in the verified version",
            safe::field(id)
        )));
    }
    let ident = DeviceIdent {
        serial: None,
        device_id: String::new(),
    };
    Ok(select(m, &ident, group).config)
}

/// What a seed takes from a verified version for its Group, besides trust and `min_version`:
/// built by the same code for `seed make` and `seed check`.
struct Content {
    oidc: Option<Oidc>,
    wifi: Vec<Wifi>,
    school_name: Option<String>,
    it_account: Option<ItAccount>,
}

/// [`Content`] of `m` for `group` (the default Group without one): `oidc` only when the Group's
/// Device config allows SSO.
fn content_of(m: &Manifest, group: Option<&str>, school_id: &str) -> Result<Content, CliError> {
    let config = group_config(m, group, school_id)?;
    let oidc = if config.login_methods.contains(&LoginMethod::Sso) {
        m.school.oidc.clone()
    } else {
        None
    };
    Ok(Content {
        oidc,
        wifi: config.wifi,
        school_name: m.school.name.clone(),
        it_account: config.it_account,
    })
}

/// The seed of `version` (the latest verified version, `m` its manifest) for `group`: trust,
/// school name, the Group's Wi-Fi and IT account from `m`, `oidc` only when the Group's Device
/// config allows SSO (the `[school.oidc]` table as it is: `mastersos_claims` included, no
/// `login_domain`, Erratum 2). It must pass [`Seed::validate`].
pub fn seed_from_version(
    m: &Manifest,
    version: u64,
    group: Option<&str>,
    server_url: &str,
    school_id: &str,
    fetch_token: &str,
) -> Result<Seed, CliError> {
    let c = content_of(m, group, school_id)?;
    if !fetch_token_shape_ok(fetch_token) {
        return Err(invalid(
            "the fetch token is not 1-256 printable ASCII characters without spaces",
        ));
    }
    let seed = Seed {
        server_url: server_url.to_owned(),
        trust: m.trust.clone(),
        fetch_token: Some(fetch_token.to_owned()),
        group: group.map(str::to_owned),
        oidc: c.oidc,
        min_version: Some(version),
        school_id: Some(school_id.to_owned()),
        wifi: c.wifi,
        school_name: c.school_name,
        it_account: c.it_account,
    };
    // The messages name the field and the SSID, never a secret.
    seed.validate().map_err(|e| {
        invalid(&format!(
            "the seed would not pass its checks: {}",
            safe::field(&e.to_string())
        ))
    })?;
    Ok(seed)
}

/// The answer of `POST seed`; unknown fields are ignored. No `Debug`: it holds the token.
#[derive(Deserialize)]
struct SeedAnswer {
    server_url: String,
    school_id: String,
    fetch_token: String,
}

impl Drop for SeedAnswer {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.fetch_token.zeroize();
    }
}

/// `origin` without one trailing `/`.
fn trim_slash(s: &str) -> &str {
    s.strip_suffix('/').unwrap_or(s)
}

/// The answer must name the server in use and our school, and carry a token of the right shape.
fn check_answer(a: &SeedAnswer, origin: &str, school_id: &str) -> Result<(), CliError> {
    if mastersos_bundle::checks::server_origin(&a.server_url).is_err()
        || trim_slash(&a.server_url) != origin
    {
        return Err(bad_answer(&format!(
            "the server's seed answer names the server {}, not {origin}; nothing was written",
            safe::field(&a.server_url)
        )));
    }
    if a.school_id != school_id {
        return Err(bad_answer(&format!(
            "the server's seed answer names school {}, not {school_id}; nothing was written",
            safe::field(&a.school_id)
        )));
    }
    if !fetch_token_shape_ok(&a.fetch_token) {
        return Err(bad_answer(
            "the server's fetch token is not 1-256 printable ASCII characters without spaces; nothing was written",
        ));
    }
    Ok(())
}

/// The message for a school that published nothing yet (`no_published_version`, from the
/// chain or the server); other errors pass unchanged.
pub fn nothing_published(mut e: CliError) -> CliError {
    if e.code == "no_published_version" {
        e.message = "nothing is published for this school yet: publish the first version first \
                     (`mastersos publish --key-file <FILE>`), then make the seed"
            .into();
    }
    e
}

/// `seed make` after the chain was verified (`verified`): resolve the Group locally, then
/// `POST seed` (step-up, no body), check the answer, build the seed and write it to `out`
/// ([`crate::platform::write_out_file`], 0600; an existing file only with `replace`). Gives
/// the seed written.
pub async fn make(
    server: &Server,
    origin: &str,
    school_id: &str,
    verified: &Verified,
    group: Option<&str>,
    out: &Path,
    replace: bool,
) -> Result<Seed, CliError> {
    if verified.version == 0 {
        return Err(nothing_published(CliError::new("no_published_version", "")));
    }
    let m = manifest_of(verified.version, &verified.contents.manifest_text)?;
    // Before the server is asked for anything: no fetch token is handed out for nothing.
    group_config(&m, group, school_id)?;
    let answer: SeedAnswer = server.post_empty("seed").await.map_err(nothing_published)?;
    check_answer(&answer, origin, school_id)?;
    let seed = seed_from_version(
        &m,
        verified.version,
        group,
        origin,
        school_id,
        &answer.fetch_token,
    )?;
    let text = Zeroizing::new(seed.to_toml_with_header());
    crate::platform::write_out_file(out, text.as_bytes(), replace)
        .map_err(|e| CliError::new("local_file", &safe::text(&format!("{e:#}"))))?;
    Ok(seed)
}

// —— seed check ——

/// Read a seed file for `seed check`, before the network: a regular file (a link is read
/// where it points; a seed made by someone else need not be 0600), at most
/// [`MAX_SEED_BYTES`], UTF-8. The text is wiped when dropped.
pub fn read_seed_file(path: &Path) -> Result<Zeroizing<String>, CliError> {
    let local = |what: String| CliError::new("local_file", &safe::text(&what));
    let meta = std::fs::metadata(path)
        .map_err(|e| local(format!("cannot read {}: {e}", path.display())))?;
    if !meta.is_file() {
        return Err(local(format!("{} is not a regular file", path.display())));
    }
    let f = std::fs::File::open(path)
        .map_err(|e| local(format!("cannot read {}: {e}", path.display())))?;
    let mut bytes = Zeroizing::new(Vec::new());
    f.take(MAX_SEED_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| local(format!("cannot read {}: {e}", path.display())))?;
    if bytes.len() > MAX_SEED_BYTES {
        return Err(local(format!(
            "{} is larger than {MAX_SEED_BYTES} bytes: not a seed",
            path.display()
        )));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| local(format!("{} is not UTF-8 text: not a seed", path.display())))?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// The fingerprint comments at the top of a seed: `# <id>  <alg>  <xxxx-xxxx-xxxx-xxxx>`, up to
/// the first line that is neither blank nor a comment.
pub fn seed_header(seed_text: &str) -> Vec<(String, String)> {
    let is_fp = |s: &str| {
        s.len() == 19
            && s.split('-').count() == 4
            && s.split('-')
                .all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    seed_text
        .lines()
        .take_while(|l| l.trim().is_empty() || l.trim_start().starts_with('#'))
        .filter_map(|l| {
            let words: Vec<&str> = l
                .trim_start()
                .strip_prefix('#')?
                .split_whitespace()
                .collect();
            match words.as_slice() {
                [id @ .., _alg, fp] if !id.is_empty() && is_fp(fp) => {
                    Some((id.join(" "), (*fp).to_owned()))
                }
                _ => None,
            }
        })
        .collect()
}

/// Parse a seed without ever echoing its text: a TOML error quotes the line it is on, which may
/// hold the fetch token or a Wi-Fi key, so only the line number is kept.
fn parse_quietly(text: &str) -> Result<Seed, String> {
    if let Err(e) = toml::from_str::<Seed>(text) {
        let line = e
            .span()
            .map(|s| text[..s.start.min(text.len())].matches('\n').count() + 1);
        return Err(match line {
            Some(n) => format!(
                "the file is not a valid seed (not TOML, or a key that is missing, unknown or of the wrong type) at line {n}"
            ),
            None => "the file is not a valid seed (not TOML, or a key that is missing, unknown or of the wrong type)".into(),
        });
    }
    // The rules parsing adds (a seed naming its school carries a fetch token): fixed texts.
    Seed::parse(text).map_err(|e| match e {
        mastersos_bundle::BundleError::Invalid(m) => safe::field(&m),
        _ => "the file is not a valid seed".into(),
    })
}

/// What `seed check` found.
pub struct CheckReport {
    /// The latest version verified here.
    pub version: u64,
    /// The seed's trusted keys (empty when it cannot be read).
    pub trust: Vec<TrustKey>,
    /// Each makes the seed unusable; never a secret.
    pub problems: Vec<String>,
    /// Facts that do not (an older seed).
    pub notes: Vec<String>,
}

impl CheckReport {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// The same trusted keys, as a set: every entry (id, algorithm, public key, site) equal. A
/// fingerprint is a short hash for people to compare; it never decides.
fn same_trust(a: &[TrustKey], b: &[TrustKey]) -> bool {
    a.iter().all(|k| b.contains(k)) && b.iter().all(|k| a.contains(k))
}

/// The entries of `seed` not in `chain` (`+`) and of `chain` not in `seed` (`-`), shown with
/// their fingerprints.
fn trust_difference(seed: &[TrustKey], chain: &[TrustKey]) -> String {
    let mut lines = Vec::new();
    for k in seed.iter().filter(|k| !chain.contains(k)) {
        lines.push(format!("+ {} (only in the seed)", key_line(k)));
    }
    for k in chain.iter().filter(|k| !seed.contains(k)) {
        lines.push(format!("- {} (missing from the seed)", key_line(k)));
    }
    lines.join("; ")
}

fn manifest_of(n: u64, text: &str) -> Result<Manifest, CliError> {
    Manifest::parse(text).map_err(|e| {
        CliError::new(
            "chain_tampered",
            &format!(
                "version {n}: the manifest cannot be read: {}",
                safe::field(&e.to_string())
            ),
        )
    })
}

/// The manifest of version `n`, which this computer verified before: its archive must have the
/// digest `verify_chain` recorded (as `pull --version` does); not a second chain loader. `None`
/// when `n` was not verified here.
async fn earlier_manifest(
    server: &Server,
    verified: &Verified,
    n: u64,
) -> Result<Option<Manifest>, CliError> {
    if recorded_version(&verified.history, n).is_err() {
        return Ok(None);
    }
    let archive = server.version_archive(n).await?;
    let contents = recorded_contents(&verified.history, n, &archive).map_err(to_cli_error)?;
    Ok(Some(manifest_of(n, &contents.manifest_text)?))
}

/// One problem per field of `seed` that differs from `want`, naming the field only (the values
/// hold Wi-Fi keys, the IT password hash and the client secret).
fn content_problems(seed: &Seed, want: &Content, base: u64) -> Vec<String> {
    let group = safe::field(seed.group.as_deref().unwrap_or(DEFAULT_GROUP));
    let differs = |field: &str| {
        format!("{field} differs from what version {base} verified here gives Group {group}")
    };
    let mut p = Vec::new();
    if seed.wifi != want.wifi {
        p.push(differs("wifi"));
    }
    if seed.it_account != want.it_account {
        p.push(differs("it_account"));
    }
    if seed.oidc != want.oidc {
        p.push(differs("oidc"));
    }
    if seed.school_name != want.school_name {
        p.push(differs("school_name"));
    }
    p
}

/// `seed check` after the chain was verified. The seed is compared with the verified version it
/// claims, `min_version` (the latest when it claims none, or one that is not a verified earlier
/// version): its trust as whole entries, and its Group's Wi-Fi, IT account, oidc and school name
/// rebuilt by the code `seed make` uses. A seed that matches an earlier verified version exactly
/// is an older seed (a note: Devices will update); one that matches neither is a problem, even when
/// it matches the latest version (the latest trust with an older `min_version` would let a Device
/// accept the older version and its trust). Also: the seed's checks, its server and school, the
/// fetch token's shape (opaque), and the header fingerprints against its keys.
pub async fn check(
    server: &Server,
    origin: &str,
    school_id: &str,
    verified: &Verified,
    text: &str,
) -> Result<CheckReport, CliError> {
    let mut r = CheckReport {
        version: verified.version,
        trust: Vec::new(),
        problems: Vec::new(),
        notes: Vec::new(),
    };
    let seed = match parse_quietly(text) {
        Ok(s) => s,
        Err(p) => {
            r.problems.push(p);
            return Ok(r);
        }
    };
    let p = &mut r.problems;
    if let Err(e) = seed.validate() {
        p.push(format!(
            "the seed does not pass its checks: {}",
            safe::field(&e.to_string())
        ));
    }
    if trim_slash(&seed.server_url) != origin {
        p.push(format!(
            "server_url is {}, not the server in use {origin}",
            safe::field(&seed.server_url)
        ));
    }
    match seed.school_id.as_deref() {
        Some(s) if s == school_id => {}
        Some(s) => p.push(format!("school_id is {}, not {school_id}", safe::field(s))),
        None => p.push(format!(
            "the seed names no school (school_id); it should be {school_id}"
        )),
    }
    match seed.fetch_token.as_deref() {
        Some(t) if fetch_token_shape_ok(t) => {}
        Some(_) => {
            p.push("fetch_token is not 1-256 printable ASCII characters without spaces".into())
        }
        None => p.push("the seed has no fetch_token: Devices could not fetch settings".into()),
    }
    let latest = verified.version;
    match seed.min_version {
        None | Some(0) => p.push(format!(
            "the seed has no min_version: it should be a verified version, at most {latest}"
        )),
        Some(n) if n > latest => p.push(format!(
            "min_version is {n}, after the latest version verified here ({latest})"
        )),
        Some(_) => {}
    }
    let base = match seed.min_version {
        Some(n) if (1..latest).contains(&n) => n,
        _ => latest,
    };
    let m = if base == latest {
        Some(manifest_of(latest, &verified.contents.manifest_text)?)
    } else {
        earlier_manifest(server, verified, base).await?
    };
    match m {
        None => r.problems.push(format!(
            "min_version is {base}, but version {base} was not verified on this computer, so the seed cannot be checked against it; make a new seed"
        )),
        Some(m) => {
            let before = r.problems.len();
            if !same_trust(&seed.trust, &m.trust) {
                r.problems.push(format!(
                    "the trusted keys differ from version {base} verified here: {}",
                    trust_difference(&seed.trust, &m.trust)
                ));
            }
            match content_of(&m, seed.group.as_deref(), school_id) {
                Ok(want) => r.problems.extend(content_problems(&seed, &want, base)),
                Err(e) => r.problems.push(format!("group: {}", e.message)),
            }
            if base < latest && r.problems.len() == before {
                r.notes.push(format!(
                    "older seed: Devices will update (it matches version {base}; the latest version verified here is {latest})"
                ));
            }
        }
    }
    let header = seed_header(text);
    let expected: Vec<(String, String)> = seed
        .trust
        .iter()
        .map(|k| (k.id.replace(['\r', '\n'], " "), trust_fingerprint(k)))
        .collect();
    if header != expected {
        let shown = |v: &[(String, String)]| {
            v.iter()
                .map(|(id, fp)| format!("{} {}", safe::field(id), safe::field(fp)))
                .collect::<Vec<_>>()
                .join(", ")
        };
        r.problems.push(format!(
            "the fingerprints in the header comment do not match the seed's trusted keys: header [{}], keys [{}]",
            shown(&header),
            shown(&expected)
        ));
    }
    r.trust = seed.trust;
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mastersos_bundle::{trust_fingerprint, LoginMethod};

    const SID: &str = "0192f3a4-5b6c-7d8e-9f00-112233445566";
    const OTHER: &str = "0192f3a4-5b6c-7d8e-9f00-aabbccddeeff";
    const SERVER: &str = "https://server.example";

    fn manifest() -> Manifest {
        let text = format!(
            "format = 2\nversion = 4\nissued_at = \"2026-11-03T00:00:00Z\"\n\n\
             [[trust]]\nid = \"key-1\"\nalg = \"ed25519\"\npublic_key = \"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\"\n\n\
             [school]\nid = \"{SID}\"\nname = \"Alpha School\"\n\n\
             [school.oidc]\nissuer = \"https://issuer.example\"\nclient_id = \"mastersos\"\nmastersos_claims = true\n\n\
             [defaults]\nwifi = [{{ ssid = \"Staff\", psk = \"staff-psk-123\" }}]\n\n\
             [defaults.it_account]\npassword_hash = \"$y$j9T$HASH\"\n\n\
             [[config]]\nid = \"default\"\nname = \"Default\"\ninterface = \"learning\"\nlogin_methods = [\"local\"]\n\n\
             [[config]]\nid = \"staff\"\nname = \"Staff\"\ninterface = \"full\"\nlogin_methods = [\"sso\", \"local\"]\n\
             wifi = [{{ ssid = \"Office\", psk = \"office-psk-123\" }}]\n\n\
             [[group]]\nid = \"default\"\nname = \"Ungrouped\"\nconfig = \"default\"\n\n\
             [[group]]\nid = \"staff\"\nname = \"Staff\"\nconfig = \"staff\"\n"
        );
        Manifest::parse(&text).unwrap()
    }

    #[test]
    fn seed_takes_the_group_wifi_and_it_account() {
        let m = manifest();
        let staff = m.effective_of_group("staff").unwrap();
        assert!(staff.login_methods.contains(&LoginMethod::Sso));
        let s = seed_from_version(&m, 4, Some("staff"), SERVER, SID, "tok").unwrap();
        let ssids: Vec<&str> = s.wifi.iter().map(|w| w.ssid.as_str()).collect();
        assert!(
            ssids.contains(&"Staff") && ssids.contains(&"Office"),
            "{ssids:?}"
        );
        assert_eq!(s.wifi, staff.wifi);
        assert_eq!(s.it_account, staff.it_account);
        assert!(s.it_account.is_some());
        assert_eq!(s.group.as_deref(), Some("staff"));
        assert_eq!(s.trust, m.trust);
        assert_eq!(s.min_version, Some(4));
        assert_eq!(s.school_id.as_deref(), Some(SID));
        assert_eq!(s.server_url, SERVER);
        assert_eq!(s.fetch_token.as_deref(), Some("tok"));
        assert_eq!(s.school_name.as_deref(), Some("Alpha School"));
        // The default Group has only the school-wide network.
        let d = seed_from_version(&m, 4, None, SERVER, SID, "tok").unwrap();
        assert_eq!(d.wifi.len(), 1);
        assert_eq!(d.group, None);
    }

    #[test]
    fn seed_without_sso_has_no_oidc() {
        let m = manifest();
        let s = seed_from_version(&m, 4, None, SERVER, SID, "tok").unwrap();
        assert!(s.oidc.is_none());
        assert!(!s.to_toml().contains("oidc"));
        let s = seed_from_version(&m, 4, Some("default"), SERVER, SID, "tok").unwrap();
        assert!(s.oidc.is_none());
    }

    #[test]
    fn seed_with_sso_has_oidc_without_login_domain() {
        let m = manifest();
        let s = seed_from_version(&m, 4, Some("staff"), SERVER, SID, "tok").unwrap();
        let o = s.oidc.as_ref().unwrap();
        assert_eq!(o.issuer, "https://issuer.example");
        assert!(o.mastersos_claims);
        let text = s.to_toml_with_header();
        assert!(text.contains("mastersos_claims = true"), "{text}");
        assert!(!text.contains("login_domain"), "{text}");
        assert_eq!(Seed::parse(&text).unwrap(), s);
    }

    #[test]
    fn seed_from_version_refuses_another_school_an_unknown_group_and_bad_values() {
        let m = manifest();
        for (group, school, server, token) in [
            (None, OTHER, SERVER, "tok"),
            (Some("nope"), SID, SERVER, "tok"),
            (None, SID, "https://server.example/devices", "tok"),
            (None, SID, SERVER, "two words"),
        ] {
            let e = seed_from_version(&m, 4, group, server, school, token).unwrap_err();
            assert_eq!(e.code, "seed_invalid", "{group:?} {school} {server}");
            assert!(!e.message.contains("two words"), "{}", e.message);
        }
    }

    #[test]
    fn fetch_token_shape_is_printable_ascii_without_spaces() {
        for ok in ["a", "tok-123_ABC.~!", &"x".repeat(256)] {
            assert!(fetch_token_shape_ok(ok), "{ok}");
        }
        for bad in ["", "a b", "a\tb", "a\nb", "é", "\u{7f}", &"x".repeat(257)] {
            assert!(!fetch_token_shape_ok(bad), "{bad:?}");
        }
    }

    #[test]
    fn header_fingerprints_are_read_back() {
        let m = manifest();
        let s = seed_from_version(&m, 4, None, SERVER, SID, "tok").unwrap();
        let header = seed_header(&s.to_toml_with_header());
        let want: Vec<(String, String)> = m
            .trust
            .iter()
            .map(|k| (k.id.clone(), trust_fingerprint(k)))
            .collect();
        assert_eq!(header, want);
    }
}
