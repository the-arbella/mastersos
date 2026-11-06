//! The platform extension of a kiosk app (design docs/specs/2026-11-06-kiosk-platform-inject-design.md §3.4).
//!
//! A web kiosk app with `platform` or `inject` gets one more extension, built here on the Device and force-installed in
//! that app's sessions only. It holds everything those two settings need, so the exam extension (in every web kiosk
//! session) keeps only `nativeMessaging`, `storage` and NWEA's hosts:
//!
//! - `manifest.json`: MV3; `tabs` (reload the start page after install), and with `platform` also
//!   `declarativeNetRequest` and host permissions on the app's hosts (the request header rule); static content scripts
//!   on the app's hosts, all `document_start`: `chromeos.js` (MAIN, all frames) with `platform`; `relay.js` (isolated,
//!   top frame) and `inject.js` (MAIN, all frames) with `inject`. Static content scripts are the only ones sure to run
//!   before the page's scripts. No web-accessible resources: pages cannot open the start page.
//! - `background.js`, `start.html`, `start.js`, `relay.js`, `chromeos.js`: `kiosk-platform/` of this repository, built
//!   into the agent; `config.js`: [`kiosk::platform_config`]; `inject.js`: the bundle's script inside
//!   `kiosk-platform/inject-wrapper.js` (it gets `mastersos.exit()`).
//! - CRX3 with a stored (uncompressed) zip, signed with ECDSA P-256 (`sha256_with_ecdsa`). The key is per app, made on
//!   first use and kept in `<var_dir>/`[`KEY_DIR`]`/<id>.p8` (root 0600, `var_dir` is 0700), so the extension id stays the
//!   same. It only lets Chrome check that the CRX is whole: the script comes from the signed bundle, and whoever can
//!   change the public directory is already root.
//!
//! [`prepare`] builds it in memory (and makes the key); [`place`] writes `platform.crx`, `updates.xml` and
//! `source.sha256` into `PUBLIC_DIR/<id>/`[`EXT_DIR`] when the content changed. ECDSA signatures differ every time, so
//! the content is compared by the digest of what goes in, not by the CRX. All of it is 0644 and world-readable on the
//! Device, the inject script included (manifest-spec: no secrets in it).

use std::os::fd::OwnedFd;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use mastersos_bundle::kiosk::{self, PlatformExtension};
use mastersos_bundle::KioskApp;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use sha2::{Digest, Sha256};

use super::{desktop, PUBLIC_DIR};
use crate::safefs;

/// Keys, one per app (below `var_dir`).
pub const KEY_DIR: &str = "kiosk-platform";
/// Where the keys were before the platform extension took over from the inject helper: removed.
pub const LEGACY_KEY_DIR: &str = "kiosk-inject";
/// The extension's files below `PUBLIC_DIR/<id>/`.
pub const EXT_DIR: &str = "platform";
/// The inject helper's directory of earlier images: removed.
pub const LEGACY_DIR: &str = "inject";
pub const CRX_FILE: &str = "platform.crx";
pub const UPDATES_FILE: &str = "updates.xml";
pub const DIGEST_FILE: &str = "source.sha256";
/// The extension's version: every kiosk session is a fresh profile that installs it anew.
pub const VERSION: &str = "1.0.0";

const BACKGROUND_JS: &str = include_str!("../../../../../kiosk-platform/background.js");
const START_HTML: &str = include_str!("../../../../../kiosk-platform/start.html");
const START_JS: &str = include_str!("../../../../../kiosk-platform/start.js");
const RELAY_JS: &str = include_str!("../../../../../kiosk-platform/relay.js");
const CHROMEOS_JS: &str = include_str!("../../../../../kiosk-platform/chromeos.js");
const INJECT_WRAPPER: &str = include_str!("../../../../../kiosk-platform/inject-wrapper.js");
/// The line of [`INJECT_WRAPPER`] the school's script replaces.
const INJECT_MARKER: &str = "// @@MASTERSOS_INJECT@@\n";

/// The DER prefix of a P-256 SubjectPublicKeyInfo (id-ecPublicKey, prime256v1, BIT STRING of 66 bytes).
const P256_SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const CRX3_SIGN_PREFIX: &[u8] = b"CRX3 SignedData\x00";

/// A built platform extension: what the policy needs and what [`place`] writes.
pub struct Prepared {
    pub ext: PlatformExtension,
    pub crx: Vec<u8>,
    pub updates_xml: String,
    pub digest: String,
}

/// `file:///var/lib/mastersos-public/kiosk/<id>/platform/<name>` (the Device's public directory, read by the kiosk
/// account's Chrome).
fn local_url(id: &str, name: &str) -> String {
    format!("file:///{PUBLIC_DIR}/{id}/{EXT_DIR}/{name}")
}

/// The start page of the extension `ext_id`: what Chrome opens instead of the app's `url`.
pub fn start_url(ext_id: &str) -> String {
    format!("chrome-extension://{ext_id}/start.html")
}

/// Reads the app's inject script (if any) from the bundle, checks it ([`kiosk::check_inject_source`]) and builds the
/// platform extension that sends `{cmd:"exit"}` to the exam extension `exam_id`. Makes the app's key on first use.
pub fn prepare(
    bundle_dir: &Path,
    var_dir: &Path,
    id: &str,
    app: &KioskApp,
    exam_id: &str,
) -> Result<Prepared> {
    let script = match app.inject.as_deref() {
        Some(file) => {
            let b = desktop::read_bundle_file(bundle_dir, file)
                .with_context(|| format!("cannot read inject script {file} from the bundle"))?;
            kiosk::check_inject_source(&b).map_err(|why| anyhow!("inject script {file} {why}"))?;
            Some(b)
        }
        None => None,
    };
    let config = kiosk::platform_config(app, exam_id).map_err(|e| anyhow!(e.message))?;
    let (_, hosts) = kiosk::start_hosts(app).map_err(|e| anyhow!(e.message))?;
    let key = app_key(var_dir, id)?;
    build(&Parts {
        key: &key,
        id,
        hosts: &hosts,
        platform: app.platform.is_some(),
        exam_id,
        config: &config,
        script: script.as_deref(),
    })
}

/// What goes into one platform extension.
pub struct Parts<'a> {
    pub key: &'a EcdsaKeyPair,
    pub id: &'a str,
    pub hosts: &'a [String],
    /// `platform = "chromeos"`: the request header rule and `chromeos.js`.
    pub platform: bool,
    pub exam_id: &'a str,
    /// [`kiosk::platform_config`], as `config.js`.
    pub config: &'a serde_json::Value,
    /// The inject script, byte for byte (UTF-8, checked).
    pub script: Option<&'a [u8]>,
}

/// The platform extension for `parts`.
pub fn build(parts: &Parts) -> Result<Prepared> {
    if !kiosk::extension_id_ok(parts.exam_id) {
        bail!(
            "exam extension id {:?} is not an extension id",
            parts.exam_id
        );
    }
    if !parts.platform && parts.script.is_none() {
        bail!("an app without platform or inject has no platform extension");
    }
    let manifest = manifest_json(parts)?;
    let config = format!("self.MASTERSOS_PLATFORM = {};\n", parts.config);
    let inject = match parts.script {
        Some(s) => {
            Some(wrap(std::str::from_utf8(s).map_err(|_| {
                anyhow!("the inject script is not UTF-8 text")
            })?)?)
        }
        None => None,
    };
    // Sorted by name: the zip and the digest do not depend on the order things are added.
    let mut files: Vec<(&str, &[u8])> = vec![
        ("background.js", BACKGROUND_JS.as_bytes()),
        ("config.js", config.as_bytes()),
        ("manifest.json", manifest.as_slice()),
        ("start.html", START_HTML.as_bytes()),
        ("start.js", START_JS.as_bytes()),
    ];
    if parts.platform {
        files.push(("chromeos.js", CHROMEOS_JS.as_bytes()));
    }
    if let Some(i) = &inject {
        files.push(("inject.js", i.as_bytes()));
        files.push(("relay.js", RELAY_JS.as_bytes()));
    }
    files.sort_by(|a, b| a.0.cmp(b.0));
    let mut h = Sha256::new();
    for (name, data) in &files {
        for part in [name.as_bytes(), data] {
            h.update((part.len() as u64).to_le_bytes());
            h.update(part);
        }
    }
    let digest = hex(&h.finalize());
    let zip = zip_stored(&files)?;
    let (crx, ext_id) = crx3(parts.key, &zip)?;
    let update_url = local_url(parts.id, UPDATES_FILE);
    let updates_xml = format!(
        "<?xml version='1.0' encoding='UTF-8'?>\n\
         <gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>\n  \
         <app appid='{ext_id}'>\n    <updatecheck codebase='{}' version='{VERSION}' />\n  </app>\n</gupdate>\n",
        local_url(parts.id, CRX_FILE)
    );
    Ok(Prepared {
        ext: PlatformExtension {
            id: ext_id,
            update_url,
        },
        crx,
        updates_xml,
        digest,
    })
}

/// The school's script in [`INJECT_WRAPPER`] (on a line of its own: a last line comment cannot swallow the end).
fn wrap(script: &str) -> Result<String> {
    let (head, tail) = INJECT_WRAPPER
        .split_once(INJECT_MARKER)
        .ok_or_else(|| anyhow!("inject-wrapper.js has no marker line"))?;
    let nl = if script.ends_with('\n') { "" } else { "\n" };
    Ok(format!("{head}{script}{nl}{tail}"))
}

/// Writes the extension into `app_dir/platform/` unless `source.sha256` says it is already there; removes the inject
/// helper of earlier images.
pub fn place(app_dir: &OwnedFd, p: &Prepared) -> Result<()> {
    safefs::remove_tree_at(app_dir, LEGACY_DIR)?;
    let d = safefs::open_dir_at(app_dir, Path::new(EXT_DIR), true)?;
    safefs::set_mode(&d, 0o755)?;
    let same = safefs::read_at(&d, DIGEST_FILE)?.as_deref() == Some(p.digest.as_bytes())
        && safefs::read_at(&d, UPDATES_FILE)?.as_deref() == Some(p.updates_xml.as_bytes())
        && safefs::open_file_at(&d, CRX_FILE)?.is_some();
    if same {
        return Ok(());
    }
    // The digest last: a write that stops half way is redone next round.
    safefs::remove_at(&d, DIGEST_FILE)?;
    safefs::write_at(&d, CRX_FILE, &p.crx, 0o644).context("write platform.crx")?;
    safefs::write_at(&d, UPDATES_FILE, p.updates_xml.as_bytes(), 0o644)
        .context("write updates.xml")?;
    safefs::write_at(&d, DIGEST_FILE, p.digest.as_bytes(), 0o644).context("write source.sha256")?;
    Ok(())
}

/// Removes `app_dir/platform/` (and an earlier image's `inject/`): the app has neither `platform` nor `inject` now.
pub fn unplace(app_dir: &OwnedFd) -> Result<()> {
    safefs::remove_tree_at(app_dir, LEGACY_DIR)?;
    safefs::remove_tree_at(app_dir, EXT_DIR)
}

/// The app's key (PKCS#8), made on first use.
fn app_key(var_dir: &Path, id: &str) -> Result<EcdsaKeyPair> {
    kiosk::check_id(id).map_err(|e| anyhow!(e.message))?;
    let dir = key_dir(var_dir)?;
    let name = format!("{id}.p8");
    let rng = SystemRandom::new();
    let pkcs8 = match safefs::read_at(&dir, &name)? {
        Some(b) => b,
        None => {
            let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                .map_err(|_| anyhow!("cannot generate the platform extension key"))?;
            safefs::write_at(&dir, &name, doc.as_ref(), 0o600)
                .with_context(|| format!("write {KEY_DIR}/{name}"))?;
            doc.as_ref().to_vec()
        }
    };
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &rng)
        .map_err(|e| anyhow!("the platform extension key {KEY_DIR}/{name} is not usable: {e}"))
}

fn key_dir(var_dir: &Path) -> Result<OwnedFd> {
    let base = safefs::open_abs_dir(var_dir, true)?;
    let d = safefs::open_dir_at(&base, Path::new(KEY_DIR), true)?;
    safefs::set_mode(&d, 0o700)?;
    Ok(d)
}

/// Deletes the keys of apps not in `keep` (removed apps), and the inject helper keys of earlier images.
pub fn remove_keys_except(var_dir: &Path, keep: &dyn Fn(&str) -> bool) -> Result<()> {
    let base = match safefs::open_abs_dir(var_dir, false) {
        Ok(b) => b,
        Err(e) if crate::apply::is_not_found(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    safefs::remove_tree_at(&base, LEGACY_KEY_DIR)?;
    let Some(d) = safefs::open_child_dir(&base, KEY_DIR)? else {
        return Ok(());
    };
    for name in safefs::list_at(&d)? {
        let id = name.strip_suffix(".p8").unwrap_or(&name);
        if !keep(id) {
            safefs::remove_at(&d, &name)?;
        }
    }
    Ok(())
}

/// The extension's manifest (module docs).
fn manifest_json(parts: &Parts) -> Result<Vec<u8>> {
    if parts.hosts.is_empty() {
        bail!("the app has no hosts for the platform extension");
    }
    let matches: Vec<String> = parts
        .hosts
        .iter()
        .flat_map(|h| [format!("https://{h}/*"), format!("https://*.{h}/*")])
        .collect();
    let main = |js: &str| {
        serde_json::json!({
            "matches": matches,
            "js": [js],
            "run_at": "document_start",
            "world": "MAIN",
            "all_frames": true,
            "match_origin_as_fallback": true,
        })
    };
    let mut scripts = Vec::new();
    let mut m = serde_json::json!({
        "manifest_version": 3,
        "name": format!("MastersOS kiosk platform ({})", parts.id),
        "version": VERSION,
        "minimum_chrome_version": "120",
        "permissions": ["tabs"],
        "background": { "service_worker": "background.js" },
    });
    if parts.platform {
        m["permissions"] = serde_json::json!(["declarativeNetRequest", "tabs"]);
        m["host_permissions"] = serde_json::json!(matches);
        scripts.push(main("chromeos.js"));
    }
    if parts.script.is_some() {
        // relay.js first: it must be listening when the wrapper in inject.js posts its channel
        scripts.push(serde_json::json!({
            "matches": matches,
            "js": ["relay.js"],
            "run_at": "document_start",
            "all_frames": false,
        }));
        scripts.push(main("inject.js"));
    }
    m["content_scripts"] = serde_json::Value::Array(scripts);
    Ok(serde_json::to_vec_pretty(&m)?)
}

/// The extension id of a public key: the first 16 bytes of sha256(SPKI DER), each hex digit 0-f as a-p.
pub fn extension_id(spki: &[u8]) -> String {
    Sha256::digest(spki)[..16]
        .iter()
        .flat_map(|b| [b >> 4, b & 0x0f])
        .map(|n| char::from(b'a' + n))
        .collect()
}

/// The SubjectPublicKeyInfo of a P-256 key pair.
pub fn spki(key: &EcdsaKeyPair) -> Vec<u8> {
    let mut v = P256_SPKI_PREFIX.to_vec();
    v.extend_from_slice(key.public_key().as_ref());
    v
}

/// CRX3: `Cr24`, version 3, header length, `CrxFileHeader` {sha256_with_ecdsa (3) = {public_key (1), signature (2)},
/// signed_header_data (10000) = SignedData {crx_id (1)}}, then the zip. The signature covers
/// `"CRX3 SignedData\0"` + u32 LE length of signed_header_data + signed_header_data + zip.
pub fn crx3(key: &EcdsaKeyPair, zip: &[u8]) -> Result<(Vec<u8>, String)> {
    let spki = spki(key);
    let crx_id = &Sha256::digest(&spki)[..16];
    let signed = pb_bytes(1, crx_id);
    let mut msg = CRX3_SIGN_PREFIX.to_vec();
    msg.extend_from_slice(&u32::try_from(signed.len())?.to_le_bytes());
    msg.extend_from_slice(&signed);
    msg.extend_from_slice(zip);
    let sig = key
        .sign(&SystemRandom::new(), &msg)
        .map_err(|_| anyhow!("cannot sign the platform extension"))?;
    let mut proof = pb_bytes(1, &spki);
    proof.extend(pb_bytes(2, sig.as_ref()));
    let mut header = pb_bytes(3, &proof);
    header.extend(pb_bytes(10000, &signed));
    let mut out = b"Cr24".to_vec();
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&u32::try_from(header.len())?.to_le_bytes());
    out.extend(header);
    out.extend_from_slice(zip);
    Ok((out, extension_id(&spki)))
}

fn varint(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// A protobuf length-delimited field (wire type 2).
fn pb_bytes(field: u64, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    varint((field << 3) | 2, &mut out);
    varint(value.len() as u64, &mut out);
    out.extend_from_slice(value);
    out
}

/// CRC-32 (IEEE, as zip uses).
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xedb8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// A zip of `files` (name, bytes), stored without compression, dated 1980-01-01, mode 0644.
pub fn zip_stored(files: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    const DOS_DATE: u16 = 0x0021; // 1980-01-01
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        let offset = u32::try_from(out.len())?;
        let size = u32::try_from(data.len())?;
        let name_len = u16::try_from(name.len())?;
        let crc = crc32(data);
        let mut common = Vec::new();
        common.extend_from_slice(&20u16.to_le_bytes()); // version needed
        common.extend_from_slice(&0u16.to_le_bytes()); // flags
        common.extend_from_slice(&0u16.to_le_bytes()); // stored
        common.extend_from_slice(&0u16.to_le_bytes()); // time
        common.extend_from_slice(&DOS_DATE.to_le_bytes());
        common.extend_from_slice(&crc.to_le_bytes());
        common.extend_from_slice(&size.to_le_bytes());
        common.extend_from_slice(&size.to_le_bytes());
        common.extend_from_slice(&name_len.to_le_bytes());
        common.extend_from_slice(&0u16.to_le_bytes()); // extra
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&common);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&0x031eu16.to_le_bytes()); // made by: Unix, 3.0
        central.extend_from_slice(&common);
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        central.extend_from_slice(&(0o100_644u32 << 16).to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = u32::try_from(out.len())?;
    let cd_size = u32::try_from(central.len())?;
    let n = u16::try_from(files.len())?;
    out.extend(central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    Ok(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};

    const EXAM: &str = "ponmlkjihgfedcbaponmlkjihgfedcba";

    fn key() -> EcdsaKeyPair {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, doc.as_ref(), &rng).unwrap()
    }

    /// Reads a protobuf length-delimited field list (only wire type 2, as CrxFileHeader uses).
    fn fields(mut b: &[u8]) -> Vec<(u64, Vec<u8>)> {
        fn read_varint(b: &mut &[u8]) -> u64 {
            let mut n = 0u64;
            let mut shift = 0;
            loop {
                let x = b[0];
                *b = &b[1..];
                n |= u64::from(x & 0x7f) << shift;
                if x & 0x80 == 0 {
                    return n;
                }
                shift += 7;
            }
        }
        let mut out = Vec::new();
        while !b.is_empty() {
            let tag = read_varint(&mut b);
            assert_eq!(tag & 7, 2);
            let len = read_varint(&mut b) as usize;
            out.push((tag >> 3, b[..len].to_vec()));
            b = &b[len..];
        }
        out
    }

    fn u32_at(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }
    fn u16_at(b: &[u8], at: usize) -> u16 {
        u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
    }

    /// The zip's entries (name → data), read through the central directory as Chrome's unzipper does.
    fn unzip(z: &[u8]) -> Vec<(String, Vec<u8>)> {
        let eocd = z.len() - 22;
        assert_eq!(u32_at(z, eocd), 0x0605_4b50);
        let n = u16_at(z, eocd + 10) as usize;
        let mut at = u32_at(z, eocd + 16) as usize;
        let mut out = Vec::new();
        for _ in 0..n {
            assert_eq!(u32_at(z, at), 0x0201_4b50);
            assert_eq!(u16_at(z, at + 10), 0, "stored");
            let crc = u32_at(z, at + 16);
            let size = u32_at(z, at + 20) as usize;
            let name_len = u16_at(z, at + 28) as usize;
            let local = u32_at(z, at + 42) as usize;
            let name = String::from_utf8(z[at + 46..at + 46 + name_len].to_vec()).unwrap();
            assert_eq!(u32_at(z, local), 0x0403_4b50);
            let lname = u16_at(z, local + 26) as usize;
            let extra = u16_at(z, local + 28) as usize;
            let start = local + 30 + lname + extra;
            let data = z[start..start + size].to_vec();
            assert_eq!(crc32(&data), crc, "{name}");
            out.push((name, data));
            at += 46 + name_len;
        }
        out
    }

    #[test]
    fn crc32_matches_the_reference() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn extension_id_is_a_to_p() {
        let id = extension_id(b"x");
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|b| (b'a'..=b'p').contains(&b)));
        assert!(kiosk::extension_id_ok(&id));
    }

    fn config() -> serde_json::Value {
        serde_json::json!({"v": 1, "url": "https://home.testnav.com/", "hosts": ["testnav.com", "act.org"],
            "platform": "chromeos", "inject": true, "exam": EXAM})
    }

    fn parts<'a>(
        k: &'a EcdsaKeyPair,
        hosts: &'a [String],
        cfg: &'a serde_json::Value,
        platform: bool,
        script: Option<&'a [u8]>,
    ) -> Parts<'a> {
        Parts {
            key: k,
            id: "testnav",
            hosts,
            platform,
            exam_id: EXAM,
            config: cfg,
            script,
        }
    }

    fn manifest_of(p: &Prepared) -> (Vec<(String, Vec<u8>)>, serde_json::Value) {
        let hlen = u32_at(&p.crx, 8) as usize;
        let files = unzip(&p.crx[12 + hlen..]);
        let m = files.iter().find(|(n, _)| n == "manifest.json").unwrap();
        let m = serde_json::from_slice(&m.1).unwrap();
        (files, m)
    }

    #[test]
    fn crx_is_signed_and_holds_the_platform_and_the_script() {
        let k = key();
        let hosts = vec!["testnav.com".to_string(), "act.org".to_string()];
        let cfg = config();
        let script = b"window.x = 1; // no newline at the end";
        let p = build(&parts(&k, &hosts, &cfg, true, Some(script))).unwrap();
        let crx = &p.crx;
        assert_eq!(&crx[..4], b"Cr24");
        assert_eq!(u32_at(crx, 4), 3);
        let hlen = u32_at(crx, 8) as usize;
        let header = &crx[12..12 + hlen];
        let zip = &crx[12 + hlen..];
        let f = fields(header);
        assert_eq!(f.iter().map(|(n, _)| *n).collect::<Vec<_>>(), [3, 10000]);
        let proof = fields(&f[0].1);
        let (spki_b, sig) = (&proof[0].1, &proof[1].1);
        assert_eq!(spki_b, &spki(&k));
        let signed = &f[1].1;
        let crx_id = &fields(signed)[0].1;
        assert_eq!(crx_id.as_slice(), &Sha256::digest(spki_b)[..16]);
        assert_eq!(p.ext.id, extension_id(spki_b));
        let mut msg = CRX3_SIGN_PREFIX.to_vec();
        msg.extend_from_slice(&(signed.len() as u32).to_le_bytes());
        msg.extend_from_slice(signed);
        msg.extend_from_slice(zip);
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, k.public_key().as_ref())
            .verify(&msg, sig)
            .unwrap();

        let (files, m) = manifest_of(&p);
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "background.js",
                "chromeos.js",
                "config.js",
                "inject.js",
                "manifest.json",
                "relay.js",
                "start.html",
                "start.js"
            ]
        );
        let file = |n: &str| {
            String::from_utf8(files.iter().find(|(x, _)| x == n).unwrap().1.clone()).unwrap()
        };
        assert_eq!(file("background.js"), BACKGROUND_JS);
        assert_eq!(file("chromeos.js"), CHROMEOS_JS);
        assert_eq!(file("relay.js"), RELAY_JS);
        assert_eq!(
            file("config.js"),
            format!("self.MASTERSOS_PLATFORM = {cfg};\n")
        );
        // the script sits in the wrapper on lines of its own, the marker gone
        let inject = file("inject.js");
        let (head, tail) = INJECT_WRAPPER.split_once(INJECT_MARKER).unwrap();
        assert_eq!(
            inject,
            format!("{head}window.x = 1; // no newline at the end\n{tail}")
        );
        assert!(!inject.contains("@@MASTERSOS_INJECT@@"));
        assert!(head.contains("MASTERSOS_EXIT_PORT"));

        assert_eq!(m["manifest_version"], 3);
        assert_eq!(m["version"], VERSION);
        assert_eq!(
            m["permissions"],
            serde_json::json!(["declarativeNetRequest", "tabs"])
        );
        let matches = serde_json::json!([
            "https://testnav.com/*",
            "https://*.testnav.com/*",
            "https://act.org/*",
            "https://*.act.org/*"
        ]);
        // only the app's hosts, never <all_urls>, and no scripting
        assert_eq!(m["host_permissions"], matches);
        assert!(m.get("web_accessible_resources").is_none());
        assert!(m.get("externally_connectable").is_none());
        let cs = m["content_scripts"].as_array().unwrap();
        let js: Vec<&str> = cs.iter().map(|c| c["js"][0].as_str().unwrap()).collect();
        assert_eq!(js, ["chromeos.js", "relay.js", "inject.js"]);
        for c in cs {
            assert_eq!(c["matches"], matches);
            assert_eq!(c["run_at"], "document_start");
        }
        assert_eq!(cs[0]["world"], "MAIN");
        assert!(cs[1].get("world").is_none(), "relay.js is isolated");
        assert_eq!(cs[1]["all_frames"], false);
        assert_eq!(cs[2]["world"], "MAIN");

        assert_eq!(
            p.ext.update_url,
            "file:///var/lib/mastersos-public/kiosk/testnav/platform/updates.xml"
        );
        assert!(p.updates_xml.contains(&format!("appid='{}'", p.ext.id)));
        assert!(p.updates_xml.contains(
            "codebase='file:///var/lib/mastersos-public/kiosk/testnav/platform/platform.crx'"
        ));
        assert_eq!(
            start_url(&p.ext.id),
            format!("chrome-extension://{}/start.html", p.ext.id)
        );
        // Same input, same digest (the signature differs, the digest does not); another script, another digest.
        let again = build(&parts(&k, &hosts, &cfg, true, Some(script))).unwrap();
        assert_eq!(again.digest, p.digest);
        assert_eq!(again.ext, p.ext);
        let other = build(&parts(&k, &hosts, &cfg, true, Some(b"window.y = 2;"))).unwrap();
        assert_ne!(other.digest, p.digest);
    }

    #[test]
    fn only_what_the_app_uses() {
        let k = key();
        let hosts = vec!["testnav.com".to_string()];
        let cfg = config();
        // platform only: no relay, no inject
        let p = build(&parts(&k, &hosts, &cfg, true, None)).unwrap();
        let (files, m) = manifest_of(&p);
        assert!(files
            .iter()
            .all(|(n, _)| n != "inject.js" && n != "relay.js"));
        let cs = m["content_scripts"].as_array().unwrap();
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0]["js"][0], "chromeos.js");
        // inject only: no request header rule, so no declarativeNetRequest and no host permissions
        let p = build(&parts(&k, &hosts, &cfg, false, Some(b"1;\n"))).unwrap();
        let (files, m) = manifest_of(&p);
        assert!(files.iter().all(|(n, _)| n != "chromeos.js"));
        assert_eq!(m["permissions"], serde_json::json!(["tabs"]));
        assert!(m.get("host_permissions").is_none());
        let js: Vec<&str> = m["content_scripts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["js"][0].as_str().unwrap())
            .collect();
        assert_eq!(js, ["relay.js", "inject.js"]);
    }

    #[test]
    fn wrapper_has_one_marker_line() {
        assert_eq!(INJECT_WRAPPER.matches(INJECT_MARKER).count(), 1);
        assert_eq!(wrap("a;\n").unwrap(), wrap("a;").unwrap());
    }

    #[test]
    fn bad_input_is_refused() {
        let k = key();
        let cfg = config();
        let hosts = vec!["a.org".to_string()];
        let mut bad = parts(&k, &hosts, &cfg, true, None);
        bad.exam_id = "nope";
        assert!(build(&bad).is_err());
        assert!(build(&parts(&k, &[], &cfg, true, None)).is_err());
        assert!(build(&parts(&k, &hosts, &cfg, false, None)).is_err());
        assert!(build(&parts(&k, &hosts, &cfg, false, Some(b"\xff"))).is_err());
    }

    #[test]
    fn key_is_kept_and_place_skips_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let var = tmp.path().join("var");
        let k1 = app_key(&var, "testnav").unwrap();
        let k2 = app_key(&var, "testnav").unwrap();
        assert_eq!(k1.public_key().as_ref(), k2.public_key().as_ref());
        let key_file = var.join(KEY_DIR).join("testnav.p8");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(app_key(&var, "../x").is_err());

        let pubd = tmp.path().join("pub");
        std::fs::create_dir_all(pubd.join(LEGACY_DIR)).unwrap();
        let dir = safefs::open_abs_dir(&pubd, false).unwrap();
        let cfg = config();
        let hosts = vec!["a.org".to_string()];
        let p = build(&parts(&k1, &hosts, &cfg, false, Some(b"1;"))).unwrap();
        place(&dir, &p).unwrap();
        assert!(!pubd.join(LEGACY_DIR).exists());
        let crx_path = pubd.join(EXT_DIR).join(CRX_FILE);
        let first = std::fs::read(&crx_path).unwrap();
        assert_eq!(first, p.crx);
        for f in [CRX_FILE, UPDATES_FILE, DIGEST_FILE] {
            let mode = std::fs::metadata(pubd.join(EXT_DIR).join(f))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o644, "{f}");
        }
        // a new signature over the same content is not written again
        let p2 = build(&parts(&k1, &hosts, &cfg, false, Some(b"1;"))).unwrap();
        place(&dir, &p2).unwrap();
        assert_eq!(std::fs::read(&crx_path).unwrap(), first);
        let p3 = build(&parts(&k1, &hosts, &cfg, false, Some(b"2;"))).unwrap();
        place(&dir, &p3).unwrap();
        assert_eq!(std::fs::read(&crx_path).unwrap(), p3.crx);
        std::fs::create_dir_all(pubd.join(LEGACY_DIR)).unwrap();
        unplace(&dir).unwrap();
        assert!(!pubd.join(EXT_DIR).exists());
        assert!(!pubd.join(LEGACY_DIR).exists());

        std::fs::create_dir_all(var.join(LEGACY_KEY_DIR)).unwrap();
        std::fs::write(var.join(LEGACY_KEY_DIR).join("old.p8"), b"x").unwrap();
        remove_keys_except(&var, &|id| id == "other").unwrap();
        assert!(!key_file.exists());
        assert!(!var.join(LEGACY_KEY_DIR).exists());
    }
}
