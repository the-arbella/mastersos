//! Wi-Fi: the expanded Config's `wifi` list (school, Defaults and Config merged by
//! `effective_config`) is written as NetworkManager
//! system connections (`/etc/NetworkManager/system-connections/mastersos-<slug(ssid)>.nmconnection`,
//! root 0600, empty `permissions=` so every user may use them), so the machine connects already at
//! the login screen. Before the first settings bundle the seed's list is used (`without_bundle`).
//! That seed mode only adds and updates: it never removes a connection or a key directory, and an
//! empty seed list does nothing at all (not even a reload). The no-bundle path also runs when the
//! local bundle is lost or fails re-verification, and seeds issued before school Wi-Fi carry no
//! networks: removing there would cut a Wi-Fi-only machine off the school network it needs to
//! recover. Once a bundle is applied its list replaces everything, and the networks it does not
//! name (seed ones included) are removed (design 2026-10-29 §5.1).
//!
//! - Three kinds, inferred by [`Wifi::kind`]: open (no `[wifi-security]`), personal
//!   (`key-mgmt=wpa-psk`, or `sae` for `wpa3_only`) and enterprise (`key-mgmt=wpa-eap` plus an
//!   `[802-1x]` section). The CA and client certificates (public) are inline keyfile blobs
//!   (`data:;base64,<base64 of the PEM>`). The `tls` private key is **not** inline: NetworkManager
//!   does not treat `802-1x.private-key` as a secret, so with `permissions=` empty any local user
//!   could read an inline key over D-Bus (`GetSettings`, `nmcli connection show`). It goes to
//!   `/etc/mastersos/wifi/<uuid>/client-key.pem` (root 0700 directory, 0600 file) and the keyfile
//!   holds only that path; `private-key-password` stays in the keyfile, where NM treats it as a
//!   secret. With a bundle, a key directory whose network is gone (or no longer has a key) is
//!   removed; one whose entry failed its check is kept, like its connection file.
//! - TTLS inner methods: `pap`/`mschapv2` are `phase2-auth`; `gtc`/`md5` are EAP methods and go in
//!   `phase2-autheap` (wpa_supplicant's TTLS `auth=` takes only PAP, CHAP, MSCHAP, MSCHAPV2). PEAP
//!   always uses `phase2-auth`.
//! - Only `mastersos-*.nmconnection` files are ours: connections IT added on the machine (other
//!   file names) are left alone.
//! - An entry that fails `checks::wifi` is skipped and reported; a file an earlier round wrote for
//!   it is **kept** — a broken password edit must not kick the machine off the network it is on
//!   (like `admins`: a render failure does not undo settings already in effect).
//! - Any file change (or an earlier failed `nmcli connection reload`, or an unreadable state)
//!   triggers a reload: NetworkManager does not watch this directory. At boot,
//!   `mastersos-agent-local` runs after `NetworkManager.service`, so the reload reaches it.
//! - When an administrator edits one of our connections on the machine, Ubuntu's NM moves it to
//!   `/etc/netplan/90-NM-<uuid>.yaml` and deletes our file; from then on that UUID follows the
//!   netplan copy. Our UUID derives from the SSID, so the next round deletes that yaml, writes our
//!   file back and reloads (NM's reload regenerates netplan connections): the school's networks
//!   follow the settings. Other netplan files (connections IT added) are left alone.
//! - Secrets (`psk`, `password`, `client_key`, `client_key_password`) appear only in the 0600
//!   files (the connection file, and the key file for `client_key`): never in reports, logs,
//!   command lines or `SysState`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine;
use mastersos_bundle::{checks, EapMethod, ItemResult, Phase2, Seed, Wifi, WifiKind};
use sha2::{Digest, Sha256};

use super::text::{keyfile_escape, slug};
use super::{failed, ok, Env, Step};
use crate::apply::{is_not_found, ApplyContext};
use crate::runner::{run_ok, Cmd};
use crate::safefs;

/// The connection directory (relative to the system root).
pub const CONN_DIR: &str = "etc/NetworkManager/system-connections";
/// Our file name prefix and suffix; other files are not ours.
pub const PREFIX: &str = "mastersos-";
pub const SUFFIX: &str = ".nmconnection";
/// Where Ubuntu's NM writes netplan connections (relative to the system root); a connection it
/// moves there is named `90-NM-<uuid>.yaml`.
pub const NETPLAN_DIR: &str = "etc/netplan";
/// Where `tls` private keys go (relative to the system root): one root 0700 directory per
/// connection UUID. Everything under it is ours.
pub const KEY_DIR: &str = "etc/mastersos/wifi";
/// The private key's file name inside its UUID directory (0600).
pub const KEY_FILE: &str = "client-key.pem";
/// The report item for step-level failures (directory unopenable, removal or reload failed).
pub const ITEM: &str = "wifi";

pub fn step() -> Step {
    Step {
        name: "wifi",
        fast: true,
        run,
        without_bundle: Some(run_seed),
    }
}

fn item(ssid: &str) -> String {
    format!("wifi:{ssid}")
}

/// The file name: `mastersos-<slug(ssid)>.nmconnection`.
pub fn file_name(ssid: &str) -> String {
    format!("{PREFIX}{}{SUFFIX}", slug(ssid))
}

/// The first 16 bytes of `sha256("mastersos-wifi:" + ssid)` with the UUIDv4 version and variant
/// bits set. The same SSID always gets the same UUID.
pub fn uuid(ssid: &str) -> String {
    let d = Sha256::digest(format!("mastersos-wifi:{ssid}").as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = crate::apply::hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// `id` is for people only: control characters other than `\t`, `\n`, `\r` (such as NUL, `\v`,
/// `\f`, DEL) become `?` — NUL truncates or breaks the whole file, and GLib strips a leading `\v`
/// or `\f` as whitespace. The connection matches on `ssid` (a byte list, verbatim), unaffected.
fn display_id(ssid: &str) -> String {
    ssid.chars()
        .map(|c| match c {
            '\t' | '\n' | '\r' => c,
            c if c.is_control() => '?',
            c => c,
        })
        .collect()
}

/// Renders one connection: (file name, keyfile text). `ssid` is always a byte list (`104;105;`):
/// NetworkManager may read a string value containing `;` as a byte list, and a byte list is
/// unambiguous. The caller has run `checks::wifi`, which keeps every text value on one line; values
/// still go through `keyfile_escape`.
pub fn render_keyfile(w: &Wifi) -> (String, String) {
    let mut ssid_bytes = String::new();
    for b in w.ssid.as_bytes() {
        ssid_bytes.push_str(&format!("{b};"));
    }
    let mut t = format!(
        "[connection]\nid={}\nuuid={}\ntype=wifi\nautoconnect=true\npermissions=\n\n\
         [wifi]\nmode=infrastructure\nssid={ssid_bytes}\nhidden={}\n\n",
        keyfile_escape(&display_id(&w.ssid)),
        uuid(&w.ssid),
        w.hidden,
    );
    match w.kind() {
        WifiKind::Open => {}
        WifiKind::Personal { sae_only } => {
            let mgmt = if sae_only { "sae" } else { "wpa-psk" };
            let psk = w.psk.as_deref().unwrap_or_default();
            t.push_str(&format!(
                "[wifi-security]\nkey-mgmt={mgmt}\npsk={}\n\n",
                keyfile_escape(psk)
            ));
        }
        WifiKind::Enterprise(eap) => {
            t.push_str("[wifi-security]\nkey-mgmt=wpa-eap\n\n");
            t.push_str(&render_8021x(w, eap));
        }
    }
    t.push_str("[ipv4]\nmethod=auto\n\n[ipv6]\nmethod=auto\n");
    (file_name(&w.ssid), t)
}

/// The `[802-1x]` section of an enterprise network.
fn render_8021x(w: &Wifi, eap: EapMethod) -> String {
    let mut t = format!("[802-1x]\neap={};\n", eap.as_str());
    let mut line = |key: &str, value: &str| {
        t.push_str(&format!("{key}={}\n", keyfile_escape(value)));
    };
    if let Some(v) = &w.identity {
        line("identity", v);
    }
    if let Some(v) = &w.anonymous_identity {
        line("anonymous-identity", v);
    }
    if eap != EapMethod::Tls {
        if let Some(v) = &w.password {
            line("password", v);
        }
    }
    if let Some(p) = w.phase2_or_default() {
        // TTLS's non-EAP inner methods are `phase2-auth`; GTC and MD5 are EAP methods.
        let key = if eap == EapMethod::Ttls && matches!(p, Phase2::Gtc | Phase2::Md5) {
            "phase2-autheap"
        } else {
            "phase2-auth"
        };
        line(key, p.as_str());
    }
    // EAP-pwd proves both sides with the password and uses no certificates: no server-check
    // lines at all (`checks::wifi` refuses those fields with pwd).
    if eap != EapMethod::Pwd {
        if let Some(v) = &w.server_domain {
            line("domain-suffix-match", v);
        }
        match &w.ca_cert {
            Some(pem) => line("ca-cert", &blob(pem)),
            // A server domain without a CA certificate: trust the system's CAs.
            None if w.server_domain.is_some() => line("system-ca-certs", "true"),
            None => {}
        }
    }
    if eap == EapMethod::Tls {
        if let Some(pem) = &w.client_cert {
            line("client-cert", &blob(pem));
        }
        if w.client_key.is_some() {
            // Only the path: NM shows `private-key` to every user, the file is root-only.
            line("private-key", &key_path(&w.ssid));
        }
        if let Some(v) = &w.client_key_password {
            line("private-key-password", v);
        }
    }
    t.push('\n');
    t
}

/// The absolute path of a network's private key file: `/etc/mastersos/wifi/<uuid>/client-key.pem`.
pub fn key_path(ssid: &str) -> String {
    format!("/{KEY_DIR}/{}/{KEY_FILE}", uuid(ssid))
}

/// Writes one private key: the UUID directory is forced to 0700, the file is 0600. Returns whether
/// anything changed. Errors name paths only, never the key.
fn write_key(key_dir: &std::os::fd::OwnedFd, uuid: &str, pem: &str) -> Result<bool> {
    let shown = format!("/{KEY_DIR}/{uuid}/{KEY_FILE}");
    let d = safefs::open_dir_at(key_dir, Path::new(uuid), true)
        .with_context(|| format!("opening /{KEY_DIR}/{uuid}"))?;
    safefs::set_mode(&d, 0o700).with_context(|| format!("securing /{KEY_DIR}/{uuid}"))?;
    safefs::write_at(&d, KEY_FILE, pem.as_bytes(), 0o600)
        .with_context(|| format!("writing {shown}"))
}

/// Removes the key directories not in `keep`, going on past a failure. Returns (whether any was
/// removed, errors).
fn remove_stale_keys(
    key_dir: &std::os::fd::OwnedFd,
    keep: &BTreeSet<String>,
) -> (bool, Vec<String>) {
    let names = match safefs::list_at(key_dir) {
        Ok(n) => n,
        Err(e) => {
            return (
                false,
                vec![format!("{:#}", e.context(format!("listing /{KEY_DIR}")))],
            )
        }
    };
    let mut removed = false;
    let mut errors = Vec::new();
    for name in names {
        if keep.contains(&name) {
            continue;
        }
        match safefs::remove_tree_at(key_dir, &name) {
            Ok(()) => removed = true,
            Err(e) => errors.push(format!(
                "{:#}",
                e.context(format!("removing /{KEY_DIR}/{name}"))
            )),
        }
    }
    (removed, errors)
}

/// A NetworkManager keyfile inline blob: `data:;base64,` and the PEM bytes in standard base64
/// (padded, no line breaks — NM's reader rejects anything else).
fn blob(pem: &str) -> String {
    format!(
        "data:;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(pem.as_bytes())
    )
}

/// With a bundle: the expanded Config's networks (the school's and the Defaults', overridden by
/// SSID and extended by the Config's); every other `mastersos-*` connection and key directory is
/// removed.
fn run(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
    apply(&env.paths.root, env, &ctx.config.wifi, Mode::Replace)
}

/// Without a bundle (before the first one, or after the local one was lost or failed its
/// re-verification): the seed's networks are added or updated so the machine can get online for
/// its fetch; nothing is removed. No networks in the seed: nothing to do.
fn run_seed(seed: &Seed, env: &mut Env) -> Vec<ItemResult> {
    if seed.wifi.is_empty() {
        return Vec::new();
    }
    apply(&env.paths.root, env, &seed.wifi, Mode::AddOnly)
}

/// Whether a round may remove what it does not list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// A bundle's list: the full set of our networks.
    Replace,
    /// The seed's list: added to what is there.
    AddOnly,
}

fn apply(root: &Path, env: &mut Env, list: &[Wifi], mode: Mode) -> Vec<ItemResult> {
    let prune = mode == Mode::Replace;
    let mut out = Vec::new();
    // File name -> (report item, text); an invalid entry's file name only goes into `keep`.
    let mut want: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut keep = BTreeSet::new();
    // The UUIDs still ours this round (valid entries and kept invalid ones).
    let mut uuids = BTreeSet::new();
    // File name -> (UUID, private key PEM) of valid `tls` entries.
    let mut keys: BTreeMap<String, (String, String)> = BTreeMap::new();
    // Key directories to keep: those of `keys` and of invalid entries.
    let mut keep_keys = BTreeSet::new();
    for w in list {
        let name = file_name(&w.ssid);
        uuids.insert(uuid(&w.ssid));
        if let Err(e) = checks::wifi(w) {
            out.push(failed(&item(&w.ssid), e));
            keep.insert(name);
            keep_keys.insert(uuid(&w.ssid));
            continue;
        }
        if want.contains_key(&name) {
            out.push(failed(
                &item(&w.ssid),
                format!(
                    "Wi-Fi name {:?} is listed twice; only the first is used",
                    w.ssid
                ),
            ));
            continue;
        }
        if let Some(pem) = &w.client_key {
            keep_keys.insert(uuid(&w.ssid));
            keys.insert(name.clone(), (uuid(&w.ssid), pem.clone()));
        }
        let (_, text) = render_keyfile(w);
        want.insert(name, (item(&w.ssid), text));
    }

    let dir = match safefs::open_dir(root, Path::new(CONN_DIR), true) {
        Ok(d) => d,
        Err(e) => {
            out.extend(
                want.values()
                    .map(|(it, _)| failed(it, format!("cannot open /{CONN_DIR}: {e:#}"))),
            );
            return out;
        }
    };

    // Created only when a key is to be written; otherwise a missing directory is left missing.
    let key_dir = match safefs::open_dir(root, Path::new(KEY_DIR), !keys.is_empty()) {
        Ok(d) => Ok(Some(d)),
        Err(e) if keys.is_empty() && is_not_found(&e) => Ok(None),
        Err(e) => Err(format!("cannot open /{KEY_DIR}: {e:#}")),
    };

    let mut changed = false;
    for (name, (it, text)) in &want {
        // The key first: a connection must not point at a key that is not there. If it cannot be
        // written, the connection file is not written either (an earlier one stays).
        if let Some((u, pem)) = keys.get(name) {
            let written = match &key_dir {
                Ok(Some(kd)) => write_key(kd, u, pem).map_err(|e| format!("{e:#}")),
                Ok(None) => Err(format!("cannot open /{KEY_DIR}")),
                Err(e) => Err(e.clone()),
            };
            match written {
                Ok(c) => changed |= c,
                Err(e) => {
                    out.push(failed(it, e));
                    continue;
                }
            }
        }
        match safefs::write_at(&dir, name, text.as_bytes(), 0o600)
            .with_context(|| format!("writing /{CONN_DIR}/{name}"))
        {
            Ok(c) => {
                changed |= c;
                out.push(ok(it));
            }
            Err(e) => out.push(failed(it, format!("{e:#}"))),
        }
    }

    match &key_dir {
        // Seed mode removes nothing; a key it had to write reported its own failure.
        _ if !prune => {}
        Ok(Some(kd)) => {
            let (removed, errors) = remove_stale_keys(kd, &keep_keys);
            changed |= removed;
            out.extend(errors.into_iter().map(|e| failed(ITEM, e)));
        }
        Ok(None) => {}
        // With keys to write, each of their items already reported it.
        Err(e) if keys.is_empty() => out.push(failed(ITEM, e.clone())),
        Err(_) => {}
    }

    // Each old file that cannot be removed is reported; the rest are still removed.
    if prune {
        let (removed, errors) = remove_stale(&dir, &want, &keep);
        changed |= removed;
        out.extend(errors.into_iter().map(|e| failed(ITEM, e)));
    }
    // Record the `mastersos-*` files really on disk (including failed writes and removals); if
    // the directory cannot be listed, the record stays as it was.
    match ours_on_disk(&dir) {
        Ok(names) => env.sys.wifi = names,
        Err(e) => out.push(failed(ITEM, format!("{e:#}"))),
    }

    // Our connections NM moved into netplan: reclaim this round's UUIDs and the recorded ones. A
    // UUID leaves the record only once netplan is confirmed not to have its yaml (removed, never
    // there, or no /etc/netplan); when that cannot be confirmed the record is kept whole and the
    // next round tries again.
    // In seed mode only this round's networks are reclaimed (each gets our file back); a recorded
    // network the seed does not list stays in netplan and in the record, since removing its yaml
    // would remove the connection.
    let ours: BTreeSet<String> = uuids.union(&env.sys.wifi_uuids).cloned().collect();
    let reclaim = take_back_from_netplan(root, if prune { &ours } else { &uuids });
    changed |= reclaim.removed;
    out.extend(reclaim.errors.into_iter().map(|e| failed(ITEM, e)));
    env.sys.wifi_uuids = match reclaim.left {
        Some(left) if prune => uuids.union(&left).cloned().collect(),
        _ => ours,
    };

    if changed {
        env.sys.wifi_reload_pending = true;
    }
    if env.sys.wifi_reload_pending || env.sys.load_failed {
        match run_ok(env.runner, Cmd::new("nmcli", &["connection", "reload"])) {
            Ok(_) => env.sys.wifi_reload_pending = false,
            Err(e) => out.push(failed(ITEM, format!("{e:#}"))),
        }
    }
    out
}

/// The result of [`take_back_from_netplan`].
struct Reclaim {
    /// At least one was removed.
    removed: bool,
    /// The UUIDs still in netplan (removal failed); `None`: the directory is unreadable, so which
    /// remain is unknown.
    left: Option<BTreeSet<String>>,
    errors: Vec<String>,
}

/// Removes `/etc/netplan/90-NM-<uuid>.yaml` for each of `uuids`, going on past a failure. A
/// missing directory is left missing.
fn take_back_from_netplan(root: &Path, uuids: &BTreeSet<String>) -> Reclaim {
    let unknown = |e: anyhow::Error| Reclaim {
        removed: false,
        left: None,
        errors: vec![format!("{e:#}")],
    };
    let dir = match safefs::open_dir(root, Path::new(NETPLAN_DIR), false) {
        Ok(d) => d,
        Err(e) if is_not_found(&e) => {
            return Reclaim {
                removed: false,
                left: Some(BTreeSet::new()),
                errors: vec![],
            }
        }
        Err(e) => return unknown(e.context(format!("opening /{NETPLAN_DIR}"))),
    };
    let present: BTreeSet<String> = match safefs::list_at(&dir) {
        Ok(v) => v.into_iter().collect(),
        Err(e) => return unknown(e.context(format!("listing /{NETPLAN_DIR}"))),
    };
    let mut r = Reclaim {
        removed: false,
        left: Some(BTreeSet::new()),
        errors: vec![],
    };
    for u in uuids {
        let name = format!("90-NM-{u}.yaml");
        if !present.contains(&name) {
            continue;
        }
        match safefs::remove_at(&dir, &name) {
            Ok(()) => r.removed = true,
            Err(e) => {
                r.errors.push(format!(
                    "{:#}",
                    e.context(format!("removing /{NETPLAN_DIR}/{name}"))
                ));
                if let Some(l) = r.left.as_mut() {
                    l.insert(u.clone());
                }
            }
        }
    }
    r
}

/// Our files in the directory (`mastersos-*.nmconnection`).
fn ours_on_disk(dir: &std::os::fd::OwnedFd) -> Result<BTreeSet<String>> {
    Ok(safefs::list_at(dir)
        .with_context(|| format!("listing /{CONN_DIR}"))?
        .into_iter()
        .filter(|n| n.starts_with(PREFIX) && n.ends_with(SUFFIX))
        .collect())
}

/// Removes the `mastersos-*.nmconnection` files in neither `want` nor `keep`, going on past a
/// failure. Returns (whether any was removed, errors).
fn remove_stale(
    dir: &std::os::fd::OwnedFd,
    want: &BTreeMap<String, (String, String)>,
    keep: &BTreeSet<String>,
) -> (bool, Vec<String>) {
    let names = match ours_on_disk(dir) {
        Ok(n) => n,
        Err(e) => return (false, vec![format!("{e:#}")]),
    };
    let mut removed = false;
    let mut errors = Vec::new();
    for name in names {
        if want.contains_key(&name) || keep.contains(&name) {
            continue;
        }
        match safefs::remove_at(dir, &name) {
            Ok(()) => removed = true,
            Err(e) => errors.push(format!(
                "{:#}",
                e.context(format!("removing /{CONN_DIR}/{name}"))
            )),
        }
    }
    (removed, errors)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{paths, tmp_root};
    use super::super::SysState;
    use super::*;
    use crate::runner::{FakeRunner, Output};
    use mastersos_bundle::{EapMethod, Phase2, School, Seed};
    use std::os::unix::fs::PermissionsExt;

    fn w(ssid: &str, psk: Option<&str>, hidden: bool) -> Wifi {
        Wifi {
            ssid: ssid.into(),
            psk: psk.map(Into::into),
            hidden,
            ..Wifi::default()
        }
    }

    fn run_with(root: &Path, r: &FakeRunner, sys: &mut SysState, list: &[Wifi]) -> Vec<ItemResult> {
        let p = paths(root);
        let mut env = Env {
            paths: &p,
            runner: r,
            sys,
        };
        apply(root, &mut env, list, Mode::Replace)
    }

    fn conn(root: &Path) -> std::path::PathBuf {
        root.join(CONN_DIR)
    }

    fn names(root: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(conn(root))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    /// Review Focus 1: read back with GLib's KeyFile, id equals the original and the ssid integer
    /// list decodes to the original bytes.
    #[cfg(target_os = "linux")]
    #[test]
    fn ssid_with_quotes_semicolon_and_thai() {
        for ssid in [
            "ห้องเรียน \"A\"; 1",
            "a;b;c",
            " lead\\trail ",
            "123",
            "ห้องสมุด",
        ] {
            let (file, text) = render_keyfile(&w(ssid, Some("secret123"), false));
            assert_eq!(file, file_name(ssid));
            let kf = glib::KeyFile::new();
            kf.load_from_data(&text, glib::KeyFileFlags::NONE).unwrap();
            assert_eq!(kf.string("connection", "id").unwrap().as_str(), ssid);
            let bytes: Vec<u8> = kf
                .integer_list("wifi", "ssid")
                .unwrap()
                .iter()
                .map(|&i| u8::try_from(i).unwrap())
                .collect();
            assert_eq!(bytes, ssid.as_bytes(), "{ssid:?}");
            assert_eq!(kf.string("connection", "type").unwrap().as_str(), "wifi");
            assert_eq!(kf.string("connection", "permissions").unwrap().as_str(), "");
            assert!(!kf.boolean("wifi", "hidden").unwrap());
        }
        let (_, text) = render_keyfile(&w("h", None, true));
        let kf = glib::KeyFile::new();
        kf.load_from_data(&text, glib::KeyFileFlags::NONE).unwrap();
        assert!(kf.boolean("wifi", "hidden").unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn psk_with_backslash_and_spaces_roundtrips() {
        let psk = " a\\b c ";
        let (_, text) = render_keyfile(&w("staff", Some(psk), false));
        let kf = glib::KeyFile::new();
        kf.load_from_data(&text, glib::KeyFileFlags::NONE).unwrap();
        assert_eq!(kf.string("wifi-security", "psk").unwrap().as_str(), psk);
        assert_eq!(
            kf.string("wifi-security", "key-mgmt").unwrap().as_str(),
            "wpa-psk"
        );
    }

    #[test]
    fn open_network_has_no_security_section() {
        let (_, text) = render_keyfile(&w("guest", None, false));
        assert!(!text.contains("[wifi-security]"), "{text}");
        assert!(!text.contains("psk"), "{text}");
        assert!(text.contains("[ipv4]\nmethod=auto\n"));
        assert!(text.contains("[ipv6]\nmethod=auto\n"));
        let (_, text) = render_keyfile(&w("staff", Some("secret123"), false));
        assert!(text.contains("[wifi-security]\nkey-mgmt=wpa-psk\npsk=secret123\n"));
    }

    #[test]
    fn ssid_is_written_as_byte_list() {
        let (_, text) = render_keyfile(&w("a;b", None, true));
        assert!(text.contains("\nssid=97;59;98;\nhidden=true\n"), "{text}");
        assert!(text.contains("\nid=a;b\n"), "{text}");
    }

    #[test]
    fn file_is_0600() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let out = run_with(
            root.path(),
            &r,
            &mut sys,
            &[w("staff", Some("secret123"), false)],
        );
        assert_eq!(out, vec![ok("wifi:staff")]);
        let f = conn(root.path()).join(file_name("staff"));
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600);
        assert!(file_name("staff").starts_with("mastersos-"));
        assert_eq!(r.calls(), vec!["nmcli connection reload"]);
        assert_eq!(sys.wifi, BTreeSet::from([file_name("staff")]));
        // Second round, same content: no write, no reload.
        let out = run_with(
            root.path(),
            &r,
            &mut sys,
            &[w("staff", Some("secret123"), false)],
        );
        assert_eq!(out, vec![ok("wifi:staff")]);
        assert_eq!(r.calls().len(), 1, "{:?}", r.calls());
    }

    /// Review Focus 2: connections IT added by hand are left alone.
    #[test]
    fn removes_only_mastersos_connections() {
        let root = tmp_root();
        let d = conn(root.path());
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("Home.nmconnection"), "x").unwrap();
        std::fs::write(d.join("mastersos-notes.txt"), "x").unwrap();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        run_with(
            root.path(),
            &r,
            &mut sys,
            &[w("a", None, false), w("b", None, false)],
        );
        let mut want = vec![
            "Home.nmconnection".to_string(),
            "mastersos-notes.txt".to_string(),
            file_name("a"),
            file_name("b"),
        ];
        want.sort();
        assert_eq!(names(root.path()), want);
        // Only a left in the list: b's file is removed, the rest stays, and NM reloads.
        let out = run_with(root.path(), &r, &mut sys, &[w("a", None, false)]);
        assert_eq!(out, vec![ok("wifi:a")]);
        let mut want = vec![
            "Home.nmconnection".to_string(),
            "mastersos-notes.txt".to_string(),
            file_name("a"),
        ];
        want.sort();
        assert_eq!(names(root.path()), want);
        assert_eq!(r.calls().len(), 2);
        assert_eq!(sys.wifi, BTreeSet::from([file_name("a")]));
        // Empty list: only ours are removed.
        run_with(root.path(), &r, &mut sys, &[]);
        assert_eq!(
            names(root.path()),
            vec![
                "Home.nmconnection".to_string(),
                "mastersos-notes.txt".to_string()
            ]
        );
        assert!(sys.wifi.is_empty());
    }

    #[test]
    fn psk_never_in_results_or_cmdline() {
        let root = tmp_root();
        let r = FakeRunner::new();
        r.respond("nmcli", Output::fail(1, "Error: boom"));
        let psk = "Sup3rSecretPsk";
        let mut sys = SysState::default();
        let out = run_with(
            root.path(),
            &r,
            &mut sys,
            &[w("staff", Some(psk), false), w("bad", Some("1234"), false)],
        );
        assert!(
            out.iter().any(|i| !i.ok),
            "a failed reload is reported: {out:?}"
        );
        let dump = format!("{out:?}");
        assert!(!dump.contains(psk) && !dump.contains("1234"), "{dump}");
        for (line, stdin) in r.calls().iter().map(|l| (l.clone(), r.stdin_of(l))) {
            assert!(!line.contains(psk), "{line}");
            assert!(stdin.is_none());
        }
        let state = serde_json::to_string(&sys).unwrap();
        assert!(!state.contains(psk), "{state}");
        // It is in the file (its only place).
        let text = std::fs::read_to_string(conn(root.path()).join(file_name("staff"))).unwrap();
        assert!(text.contains(psk));
        // Reload failed: the next round reloads even with unchanged content.
        assert!(sys.wifi_reload_pending);
        run_with(root.path(), &r, &mut sys, &[w("staff", Some(psk), false)]);
        assert_eq!(r.calls().len(), 2);
        assert!(!sys.wifi_reload_pending);
    }

    #[test]
    fn bad_wifi_item_is_skipped_not_fatal() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let out = run_with(
            root.path(),
            &r,
            &mut sys,
            &[
                w("bad", Some("12345"), false),
                w("good", Some("secret123"), false),
            ],
        );
        assert_eq!(out.len(), 2, "{out:?}");
        assert_eq!(out[0].item, "wifi:bad");
        assert!(!out[0].ok);
        assert!(!out[0].detail.as_deref().unwrap().contains("12345"));
        assert_eq!(out[1], ok("wifi:good"));
        assert_eq!(names(root.path()), vec![file_name("good")]);
        // Valid last round, broken now: the old file stays, so the machine keeps this network.
        let out = run_with(
            root.path(),
            &r,
            &mut sys,
            &[w("good", Some("short"), false)],
        );
        assert!(!out[0].ok);
        assert_eq!(names(root.path()), vec![file_name("good")]);
        let text = std::fs::read_to_string(conn(root.path()).join(file_name("good"))).unwrap();
        assert!(text.contains("psk=secret123"));
    }

    #[test]
    fn duplicate_ssid_keeps_first() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let out = run_with(
            root.path(),
            &r,
            &mut sys,
            &[
                w("x", Some("first123"), false),
                w("x", Some("second12"), false),
            ],
        );
        assert_eq!(out.len(), 2);
        assert!(!out[0].ok, "{out:?}");
        assert!(!format!("{out:?}").contains("second12"));
        assert_eq!(out[1], ok("wifi:x"));
        let text = std::fs::read_to_string(conn(root.path()).join(file_name("x"))).unwrap();
        assert!(text.contains("psk=first123"));
    }

    /// An administrator edited our connection on the machine (nmcli modify, Settings): Ubuntu's NM
    /// moves it to /etc/netplan/90-NM-<uuid>.yaml and deletes our keyfile; from then on that UUID
    /// follows netplan and the machine ignores list changes. Our UUID is fixed: remove that yaml,
    /// write our file back and reload (NM's reload regenerates netplan connections). Other yaml
    /// files stay.
    #[test]
    fn our_connection_moved_to_netplan_is_taken_back() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let np = root.path().join(NETPLAN_DIR);
        let yaml = |ssid: &str| format!("90-NM-{}.yaml", uuid(ssid));
        run_with(
            root.path(),
            &r,
            &mut sys,
            &[w("a", None, false), w("b", None, false)],
        );
        assert_eq!(r.calls().len(), 1);
        // The admin edited a and b: NM deletes our keyfiles and writes netplan; IT's own Home is in netplan too.
        std::fs::create_dir_all(&np).unwrap();
        for s in ["a", "b"] {
            std::fs::remove_file(conn(root.path()).join(file_name(s))).unwrap();
            std::fs::write(np.join(yaml(s)), "network: {}\n").unwrap();
        }
        std::fs::write(
            np.join("90-NM-1c6c25e8-832d-487c-84df-a3c7ac38ea53.yaml"),
            "x",
        )
        .unwrap();
        std::fs::write(np.join("01-netcfg.yaml"), "x").unwrap();
        // Only a left: a is reclaimed (yaml removed, file written back); b was ours and is no longer listed, so its yaml goes too.
        let out = run_with(root.path(), &r, &mut sys, &[w("a", None, false)]);
        assert_eq!(out, vec![ok("wifi:a")]);
        let mut left: Vec<String> = std::fs::read_dir(&np)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec![
                "01-netcfg.yaml".to_string(),
                "90-NM-1c6c25e8-832d-487c-84df-a3c7ac38ea53.yaml".to_string()
            ]
        );
        assert_eq!(names(root.path()), vec![file_name("a")]);
        assert_eq!(r.calls().len(), 2, "must reload: {:?}", r.calls());
        assert_eq!(sys.wifi_uuids, BTreeSet::from([uuid("a")]));
        // Only the yaml appeared and our file is still there: reclaimed and reloaded all the same.
        std::fs::write(np.join(yaml("a")), "x").unwrap();
        run_with(root.path(), &r, &mut sys, &[w("a", None, false)]);
        assert!(!np.join(yaml("a")).exists());
        assert_eq!(r.calls().len(), 3);
        // No /etc/netplan: not created, no error.
        let root2 = tmp_root();
        let out = run_with(
            root2.path(),
            &r,
            &mut SysState::default(),
            &[w("a", None, false)],
        );
        assert_eq!(out, vec![ok("wifi:a")]);
        assert!(!root2.path().join(NETPLAN_DIR).exists());
        assert!(super::super::WRITE_ROOTS.contains(&"/etc/netplan"));
    }

    fn yaml(ssid: &str) -> String {
        format!("90-NM-{}.yaml", uuid(ssid))
    }

    /// Review M1 + N3: when one yaml cannot be removed the others still are; the failed UUID stays
    /// recorded and is retried every round until it is gone.
    #[test]
    fn failed_netplan_reclaim_keeps_uuid_until_removed() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let np = root.path().join(NETPLAN_DIR);
        run_with(
            root.path(),
            &r,
            &mut sys,
            &[w("a", None, false), w("b", None, false)],
        );
        std::fs::create_dir_all(&np).unwrap();
        // b's "yaml" is a directory: unlink fails. a's is a plain file. Order does not matter (no stop at the first failure).
        std::fs::create_dir(np.join(yaml("b"))).unwrap();
        std::fs::write(np.join(yaml("a")), "x").unwrap();
        let out = run_with(root.path(), &r, &mut sys, &[w("a", None, false)]);
        assert!(out.contains(&ok("wifi:a")), "{out:?}");
        assert!(
            out.iter().any(|i| i.item == ITEM && !i.ok),
            "a failed removal is reported: {out:?}"
        );
        assert!(!np.join(yaml("a")).exists(), "a is still removed");
        assert_eq!(
            sys.wifi_uuids,
            BTreeSet::from([uuid("a"), uuid("b")]),
            "b is not removed yet and must not be forgotten"
        );
        // Obstacle replaced by a real yaml: the next round removes it and only then forgets b.
        std::fs::remove_dir(np.join(yaml("b"))).unwrap();
        std::fs::write(np.join(yaml("b")), "x").unwrap();
        let out = run_with(root.path(), &r, &mut sys, &[w("a", None, false)]);
        assert_eq!(out, vec![ok("wifi:a")]);
        assert!(!np.join(yaml("b")).exists());
        assert_eq!(sys.wifi_uuids, BTreeSet::from([uuid("a")]));
    }

    /// Review M2: when /etc/netplan is unreadable (here a plain file) nothing can be confirmed gone —
    /// the record takes the union and loses nothing; once readable, only confirmed ones are dropped.
    #[test]
    fn wifi_uuids_are_kept_until_netplan_confirms() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let np = root.path().join(NETPLAN_DIR);
        run_with(
            root.path(),
            &r,
            &mut sys,
            &[w("a", None, false), w("b", None, false)],
        );
        std::fs::create_dir_all(np.parent().unwrap()).unwrap();
        std::fs::write(&np, "not a dir").unwrap();
        let out = run_with(root.path(), &r, &mut sys, &[w("c", None, false)]);
        assert!(out.iter().any(|i| i.item == ITEM && !i.ok), "{out:?}");
        assert_eq!(
            sys.wifi_uuids,
            BTreeSet::from([uuid("a"), uuid("b"), uuid("c")])
        );
        // Same on a machine that lost its record (state unreadable, defaults): this round's are recorded.
        std::fs::remove_file(&np).unwrap();
        std::fs::create_dir(&np).unwrap();
        std::fs::write(np.join(yaml("a")), "x").unwrap();
        run_with(root.path(), &r, &mut sys, &[w("c", None, false)]);
        assert!(!np.join(yaml("a")).exists(), "the recorded a is reclaimed");
        assert_eq!(sys.wifi_uuids, BTreeSet::from([uuid("c")]));
    }

    /// Review M3 + N3: when one old file cannot be removed the later ones still are; `sys.wifi`
    /// records the `mastersos-*` files really on disk (including the one that stayed).
    #[test]
    fn failed_stale_removal_is_recorded_and_others_continue() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let d = conn(root.path());
        std::fs::create_dir_all(&d).unwrap();
        // First in order and unremovable (a directory); a plain old file after it.
        std::fs::create_dir(d.join("mastersos-000000000000.nmconnection")).unwrap();
        std::fs::write(d.join("mastersos-ffffffffffff.nmconnection"), "x").unwrap();
        let out = run_with(
            root.path(),
            &r,
            &mut sys,
            &[w("a", None, false), w("bad", Some("123"), false)],
        );
        assert!(out.contains(&ok("wifi:a")), "{out:?}");
        assert!(out.iter().any(|i| i.item == ITEM && !i.ok), "{out:?}");
        assert!(
            !d.join("mastersos-ffffffffffff.nmconnection").exists(),
            "later ones are still removed"
        );
        assert_eq!(
            sys.wifi,
            BTreeSet::from([
                "mastersos-000000000000.nmconnection".to_string(),
                file_name("a"),
            ])
        );
        // The file an invalid entry had from an earlier round is kept and recorded.
        run_with(
            root.path(),
            &r,
            &mut sys,
            &[w("bad", Some("secret123"), false)],
        );
        std::fs::remove_dir(d.join("mastersos-000000000000.nmconnection")).unwrap();
        run_with(root.path(), &r, &mut sys, &[w("bad", Some("123"), false)]);
        assert_eq!(sys.wifi, BTreeSet::from([file_name("bad")]));
    }

    /// Review N1: control characters in `id` (NUL, \v, \f, ...; \t \n \r are escaped) become `?`;
    /// the `ssid` byte list is verbatim.
    #[test]
    fn control_chars_in_id_are_replaced() {
        let ssid = "\u{0}a\u{b}b\u{c}\u{1f}\u{7f}\tc";
        let (_, text) = render_keyfile(&w(ssid, None, false));
        assert!(text.contains("\nid=?a?b???\\tc\n"), "{text}");
        let bytes: Vec<String> = ssid.bytes().map(|b| format!("{b};")).collect();
        assert!(
            text.contains(&format!("\nssid={}\n", bytes.concat())),
            "{text}"
        );
        assert!(!text.contains('\u{0}') && !text.contains('\u{b}') && !text.contains('\u{c}'));
    }

    #[test]
    fn uuid_is_stable_across_runs() {
        let a = uuid("ห้องเรียน");
        assert_eq!(a, uuid("ห้องเรียน"));
        assert_ne!(a, uuid("ห้องเรียน2"));
        let parts: Vec<&str> = a.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(parts[2].starts_with('4'), "{a}");
        assert!(matches!(&parts[3][..1], "8" | "9" | "a" | "b"), "{a}");
        // The first 16 bytes of sha256("mastersos-wifi:abc"), bits set.
        let d = Sha256::digest(b"mastersos-wifi:abc");
        let h = crate::apply::hex(&d[..16]);
        let u = uuid("abc").replace('-', "");
        assert_eq!(&u[..12], &h[..12]);
        assert_eq!(&u[13..16], &h[13..16]);
        assert_eq!(&u[18..], &h[18..32]);
        let (_, t1) = render_keyfile(&w("abc", None, false));
        let (_, t2) = render_keyfile(&w("abc", Some("secret123"), true));
        assert!(t1.contains(&format!("uuid={}\n", uuid("abc"))));
        assert!(t2.contains(&format!("uuid={}\n", uuid("abc"))));
    }

    #[test]
    fn wifi_step_is_fast_and_uses_the_seed_without_bundle() {
        let s = step();
        assert!(s.fast);
        assert!(s.without_bundle.is_some());
        assert!(super::super::steps().iter().any(|s| s.name == "wifi"));
        assert!(super::super::WRITE_ROOTS.contains(&"/etc/NetworkManager/system-connections"));
    }

    const CA: &str = "-----BEGIN CERTIFICATE-----\nQ0FDRVJU\n-----END CERTIFICATE-----\n";
    const CLIENT: &str = "-----BEGIN CERTIFICATE-----\nQ0xJRU5U\n-----END CERTIFICATE-----\n";
    const KEY: &str = "-----BEGIN PRIVATE KEY-----\nS2V5S2V5U2VjcmV0\n-----END PRIVATE KEY-----\n";

    fn b64(s: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    }

    fn peap(ssid: &str) -> Wifi {
        Wifi {
            ssid: ssid.into(),
            eap: Some(EapMethod::Peap),
            identity: Some("devices@eis".into()),
            password: Some("EapPassw0rd".into()),
            server_domain: Some("radius.eis.ac.th".into()),
            ..Wifi::default()
        }
    }

    fn tls(ssid: &str) -> Wifi {
        Wifi {
            ssid: ssid.into(),
            eap: Some(EapMethod::Tls),
            identity: Some("device".into()),
            ca_cert: Some(CA.into()),
            client_cert: Some(CLIENT.into()),
            client_key: Some(KEY.into()),
            client_key_password: Some("KeyPassphrase".into()),
            ..Wifi::default()
        }
    }

    #[test]
    fn renders_sae_only() {
        let mut n = w("wpa3", Some("secret123"), false);
        n.wpa3_only = Some(true);
        checks::wifi(&n).unwrap();
        let (_, text) = render_keyfile(&n);
        assert!(
            text.contains("[wifi-security]\nkey-mgmt=sae\npsk=secret123\n"),
            "{text}"
        );
        assert!(!text.contains("wpa-psk"), "{text}");
        let (_, text) = render_keyfile(&w("wpa2", Some("secret123"), false));
        assert!(text.contains("key-mgmt=wpa-psk\n"), "{text}");
    }

    #[test]
    fn renders_peap_defaults_mschapv2_and_system_ca() {
        let n = peap("staff");
        checks::wifi(&n).unwrap();
        let (_, text) = render_keyfile(&n);
        assert!(
            text.contains("[wifi-security]\nkey-mgmt=wpa-eap\n"),
            "{text}"
        );
        assert!(text.contains("[802-1x]\neap=peap;\n"), "{text}");
        assert!(text.contains("\nidentity=devices@eis\n"), "{text}");
        assert!(text.contains("\npassword=EapPassw0rd\n"), "{text}");
        assert!(text.contains("\nphase2-auth=mschapv2\n"), "{text}");
        assert!(
            text.contains("\ndomain-suffix-match=radius.eis.ac.th\n"),
            "{text}"
        );
        assert!(text.contains("\nsystem-ca-certs=true\n"), "{text}");
        assert!(!text.contains("ca-cert="), "{text}");
        assert!(!text.contains("anonymous-identity"), "{text}");
        // An explicit phase2 and an anonymous identity are written as given.
        let mut n = peap("staff");
        n.eap = Some(EapMethod::Ttls);
        n.phase2 = Some(Phase2::Pap);
        n.anonymous_identity = Some("anon@eis".into());
        let (_, text) = render_keyfile(&n);
        assert!(text.contains("eap=ttls;\n"), "{text}");
        assert!(text.contains("\nphase2-auth=pap\n"), "{text}");
        assert!(text.contains("\nanonymous-identity=anon@eis\n"), "{text}");
        // pwd: no inner authentication.
        let mut n = peap("staff");
        n.eap = Some(EapMethod::Pwd);
        let (_, text) = render_keyfile(&n);
        assert!(text.contains("eap=pwd;\n"), "{text}");
        assert!(!text.contains("phase2-auth"), "{text}");
    }

    #[test]
    fn renders_tls_cert_blobs_and_key_path() {
        let n = tls("secure");
        checks::wifi(&n).unwrap();
        let (_, text) = render_keyfile(&n);
        assert!(text.contains("[802-1x]\neap=tls;\n"), "{text}");
        assert!(
            text.contains(&format!("\nca-cert=data:;base64,{}\n", b64(CA))),
            "{text}"
        );
        assert!(
            text.contains(&format!("\nclient-cert=data:;base64,{}\n", b64(CLIENT))),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "\nprivate-key=/etc/mastersos/wifi/{}/client-key.pem\n",
                uuid("secure")
            )),
            "{text}"
        );
        assert_eq!(
            key_path("secure"),
            format!("/etc/mastersos/wifi/{}/client-key.pem", uuid("secure"))
        );
        // No private key body, neither as PEM nor as base64.
        assert!(!text.contains("S2V5S2V5U2VjcmV0"), "{text}");
        assert!(!text.contains(&b64(KEY)), "{text}");
        assert!(!text.contains("PRIVATE KEY"), "{text}");
        assert!(
            text.contains("\nprivate-key-password=KeyPassphrase\n"),
            "{text}"
        );
        assert!(!text.contains("\npassword="), "{text}");
        assert!(!text.contains("phase2-auth"), "{text}");
        assert!(!text.contains("system-ca-certs"), "{text}");
        // The PEM text itself never appears unencoded.
        assert!(!text.contains("BEGIN"), "{text}");
    }

    #[test]
    fn renders_pwd_without_certificate_lines() {
        let mut n = peap("P");
        n.eap = Some(EapMethod::Pwd);
        n.phase2 = None;
        n.server_domain = None;
        n.ca_cert = None;
        assert_eq!(checks::wifi(&n), Ok(()));
        let (_, t) = render_keyfile(&n);
        assert!(t.contains("eap=pwd;\n"), "{t}");
        for absent in [
            "domain-suffix-match",
            "ca-cert",
            "system-ca-certs",
            "phase2",
        ] {
            assert!(!t.contains(absent), "{absent}: {t}");
        }
        // Even fields the check refuses are never rendered for pwd.
        n.server_domain = Some("radius.school.ac.th".into());
        n.ca_cert = Some(CA.into());
        let (_, t) = render_keyfile(&n);
        assert!(
            !t.contains("domain-suffix-match") && !t.contains("ca-cert"),
            "{t}"
        );
    }

    #[test]
    fn renders_unchecked_server_without_ca_lines() {
        let mut n = peap("byod");
        n.server_domain = None;
        n.check_server = Some(false);
        checks::wifi(&n).unwrap();
        let (_, text) = render_keyfile(&n);
        assert!(text.contains("key-mgmt=wpa-eap\n"), "{text}");
        assert!(!text.contains("domain-suffix-match"), "{text}");
        assert!(!text.contains("ca-cert"), "{text}");
        assert!(!text.contains("system-ca-certs"), "{text}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn enterprise_keyfile_parses_with_glib() {
        for n in [peap("staff"), tls("secure")] {
            let (_, text) = render_keyfile(&n);
            let kf = glib::KeyFile::new();
            kf.load_from_data(&text, glib::KeyFileFlags::NONE).unwrap();
            assert_eq!(
                kf.string("wifi-security", "key-mgmt").unwrap().as_str(),
                "wpa-eap"
            );
            assert!(kf.string("802-1x", "identity").is_ok());
        }
        // The CA certificate blob decodes back to the original PEM.
        use base64::Engine;
        let (_, text) = render_keyfile(&tls("secure"));
        let kf = glib::KeyFile::new();
        kf.load_from_data(&text, glib::KeyFileFlags::NONE).unwrap();
        let ca = kf.string("802-1x", "ca-cert").unwrap();
        let encoded = ca.as_str().strip_prefix("data:;base64,").unwrap();
        let pem = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(pem, CA.as_bytes());
        assert_eq!(
            kf.string("802-1x", "private-key").unwrap().as_str(),
            key_path("secure")
        );
    }

    #[test]
    fn renders_ttls_eap_inner_methods_as_autheap() {
        let with = |eap: EapMethod, p: Phase2| {
            let mut n = peap("staff");
            n.eap = Some(eap);
            n.phase2 = Some(p);
            checks::wifi(&n).unwrap();
            render_keyfile(&n).1
        };
        for (p, name) in [(Phase2::Gtc, "gtc"), (Phase2::Md5, "md5")] {
            let text = with(EapMethod::Ttls, p);
            assert!(
                text.contains(&format!("\nphase2-autheap={name}\n")),
                "{text}"
            );
            assert!(!text.contains("phase2-auth="), "{text}");
            // PEAP's inner method is always phase2-auth.
            let text = with(EapMethod::Peap, p);
            assert!(text.contains(&format!("\nphase2-auth={name}\n")), "{text}");
            assert!(!text.contains("phase2-autheap"), "{text}");
        }
        for (p, name) in [(Phase2::Pap, "pap"), (Phase2::Mschapv2, "mschapv2")] {
            let text = with(EapMethod::Ttls, p);
            assert!(text.contains(&format!("\nphase2-auth={name}\n")), "{text}");
            assert!(!text.contains("phase2-autheap"), "{text}");
        }
    }

    fn mode_of(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn key_dir_names(root: &Path) -> Vec<String> {
        let mut v: Vec<String> = match std::fs::read_dir(root.join(KEY_DIR)) {
            Ok(d) => d
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect(),
            Err(_) => vec![],
        };
        v.sort();
        v
    }

    #[test]
    fn tls_private_key_goes_to_a_root_only_file() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let out = run_with(root.path(), &r, &mut sys, &[tls("secure")]);
        assert_eq!(out, vec![ok("wifi:secure")]);
        let dir = root.path().join(KEY_DIR).join(uuid("secure"));
        let key = dir.join(KEY_FILE);
        assert_eq!(mode_of(&dir), 0o700);
        assert_eq!(mode_of(&key), 0o600);
        assert_eq!(std::fs::read_to_string(&key).unwrap(), KEY);
        let text = std::fs::read_to_string(conn(root.path()).join(file_name("secure"))).unwrap();
        assert!(text.contains(&format!("\nprivate-key={}\n", key_path("secure"))));
        assert!(!text.contains("S2V5S2V5U2VjcmV0") && !text.contains("PRIVATE KEY"));
        assert_eq!(r.calls(), vec!["nmcli connection reload"]);
        // Same again: nothing changes, no reload. A loosened directory is tightened back.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        run_with(root.path(), &r, &mut sys, &[tls("secure")]);
        assert_eq!(mode_of(&dir), 0o700);
        assert_eq!(r.calls().len(), 1, "{:?}", r.calls());
        // A changed key alone is a change: reload.
        let mut n = tls("secure");
        n.client_key = Some(KEY.replace("S2V5", "TmV3"));
        run_with(root.path(), &r, &mut sys, &[n]);
        assert_eq!(r.calls().len(), 2, "{:?}", r.calls());
        assert!(std::fs::read_to_string(&key).unwrap().contains("TmV3"));
    }

    #[test]
    fn stale_key_directories_are_removed() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        run_with(root.path(), &r, &mut sys, &[tls("a"), tls("b")]);
        let mut both = vec![uuid("a"), uuid("b")];
        both.sort();
        assert_eq!(key_dir_names(root.path()), both);
        // A stray directory under the key directory is ours too and goes.
        std::fs::create_dir(root.path().join(KEY_DIR).join("stray")).unwrap();
        // b's entry is broken this round: its key directory stays, like its connection file.
        let mut bad_b = tls("b");
        bad_b.password = Some("EapPassw0rd".into());
        let out = run_with(root.path(), &r, &mut sys, &[tls("a"), bad_b]);
        assert!(out.contains(&ok("wifi:a")), "{out:?}");
        assert_eq!(key_dir_names(root.path()), both);
        // a becomes a PEAP network (no key): its key directory goes; b is gone: its directory goes.
        let out = run_with(root.path(), &r, &mut sys, &[peap("a")]);
        assert_eq!(out, vec![ok("wifi:a")]);
        assert!(key_dir_names(root.path()).is_empty());
        assert_eq!(names(root.path()), vec![file_name("a")]);
        // No key anywhere and no key directory: nothing is created.
        let root2 = tmp_root();
        run_with(root2.path(), &r, &mut SysState::default(), &[peap("a")]);
        assert!(!root2.path().join("etc/mastersos").exists());
        assert!(super::super::WRITE_ROOTS.contains(&"/etc/mastersos/wifi"));
    }

    #[test]
    fn failure_detail_never_contains_secret() {
        let secrets = [
            "EapPassw0rd",
            "KeyPassphrase",
            "S2V5S2V5U2VjcmV0",
            "PRIVATE KEY",
            "secret123",
        ];
        let assert_clean = |out: &[ItemResult]| {
            let dump = format!("{out:?}");
            for s in secrets {
                assert!(!dump.contains(s), "{s} in {dump}");
            }
        };
        // Invalid entries carrying every secret.
        let mut bad_peap = peap("bad-peap");
        bad_peap.server_domain = None;
        let mut bad_tls = tls("bad-tls");
        bad_tls.password = Some("EapPassw0rd".into());
        let mut bad_psk = w("bad-psk", Some("secret123"), false);
        bad_psk.eap = Some(EapMethod::Peap);
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let out = run_with(root.path(), &r, &mut sys, &[bad_peap, bad_tls, bad_psk]);
        assert_eq!(out.iter().filter(|i| !i.ok).count(), 3, "{out:?}");
        assert_clean(&out);
        // A write that fails: the target is a directory.
        let d = conn(root.path());
        std::fs::create_dir_all(d.join(file_name("secure"))).unwrap();
        let out = run_with(root.path(), &r, &mut sys, &[tls("secure"), peap("staff")]);
        assert!(
            out.iter().any(|i| i.item == "wifi:secure" && !i.ok),
            "{out:?}"
        );
        assert_clean(&out);
        // The key cannot be written (its UUID directory is a plain file): the connection file is
        // not written either, and the detail names only the path.
        let root_k = tmp_root();
        let kd = root_k.path().join(KEY_DIR);
        std::fs::create_dir_all(&kd).unwrap();
        std::fs::write(kd.join(uuid("secure")), "x").unwrap();
        let out = run_with(root_k.path(), &r, &mut sys, &[tls("secure")]);
        assert!(
            out.iter().any(|i| i.item == "wifi:secure" && !i.ok),
            "{out:?}"
        );
        assert!(!conn(root_k.path()).join(file_name("secure")).exists());
        assert_clean(&out);
        // The directory cannot be opened.
        let root = tmp_root();
        let parent = root.path().join(CONN_DIR).parent().unwrap().to_path_buf();
        std::fs::create_dir_all(parent.parent().unwrap()).unwrap();
        std::fs::write(&parent, "not a dir").unwrap();
        let out = run_with(root.path(), &r, &mut sys, &[tls("secure"), peap("staff")]);
        assert!(out.iter().all(|i| !i.ok), "{out:?}");
        assert_clean(&out);
        for line in r.calls() {
            assert_clean(&[failed("cmd", line)]);
        }
        assert_clean(&[failed("sys", serde_json::to_string(&sys).unwrap())]);
    }

    fn seed(wifi: Vec<Wifi>) -> Seed {
        Seed {
            server_url: "http://x".into(),
            trust: vec![],
            fetch_token: None,
            group: None,
            oidc: None,
            min_version: None,
            school_id: None,
            wifi,
            school_name: None,
            it_account: None,
        }
    }

    fn applier(root: &Path) -> (super::super::SystemApplier, std::sync::Arc<FakeRunner>) {
        let r = std::sync::Arc::new(FakeRunner::new());
        (
            super::super::SystemApplier::with_steps(paths(root), r.clone(), vec![step()]),
            r,
        )
    }

    fn apply_bundle(
        a: &super::super::SystemApplier,
        school_wifi: Vec<Wifi>,
        config_wifi: Vec<Wifi>,
    ) -> Vec<ItemResult> {
        use crate::apply::Applier;
        let school = School {
            wifi: school_wifi,
            ..School::default()
        };
        let mut m = mastersos_bundle::Manifest::parse(
            "version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n",
        )
        .unwrap();
        m.school = school.clone();
        m.configs[0].wifi = config_wifi;
        let c = mastersos_bundle::effective_config(&m, &m.configs[0]);
        let g = super::super::tests::group();
        let flag = std::sync::atomic::AtomicBool::new(false);
        let dir = tempfile::tempdir().unwrap();
        a.apply(&ApplyContext {
            seed: &crate::system::tests::test_seed(),
            school: &school,
            group: &g,
            config: &c,
            lock: None,
            bundle_dir: dir.path(),
            phase: crate::apply::Phase::Full,
            superseded: &flag,
            quiet: &std::sync::atomic::AtomicBool::new(false),
        })
    }

    #[test]
    fn seed_networks_written_without_bundle() {
        use crate::apply::Applier;
        let root = tmp_root();
        let (a, r) = applier(root.path());
        let out = a.apply_without_bundle(
            &seed(vec![w("A", Some("secret123"), false)]),
            crate::apply::Phase::Boot,
        );
        assert_eq!(out, vec![ok("wifi:A")]);
        let f = conn(root.path()).join(file_name("A"));
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600);
        assert!(std::fs::read_to_string(&f)
            .unwrap()
            .contains("psk=secret123"));
        assert_eq!(r.calls(), vec!["nmcli connection reload"]);
    }

    #[test]
    fn bundle_replaces_seed_networks() {
        use crate::apply::Applier;
        let root = tmp_root();
        let (a, r) = applier(root.path());
        a.apply_without_bundle(
            &seed(vec![w("A", None, false), w("B", None, false)]),
            crate::apply::Phase::Boot,
        );
        assert_eq!(names(root.path()), {
            let mut v = vec![file_name("A"), file_name("B")];
            v.sort();
            v
        });
        let out = apply_bundle(&a, vec![w("B", None, false)], vec![]);
        assert_eq!(out, vec![ok("wifi:B")]);
        assert_eq!(names(root.path()), vec![file_name("B")]);
        let out = apply_bundle(&a, vec![], vec![]);
        assert!(out.is_empty(), "{out:?}");
        assert!(names(root.path()).is_empty());
        assert_eq!(r.calls().len(), 3, "{:?}", r.calls());
    }

    /// Final review I2: seeds issued so far carry no Wi-Fi, and the no-bundle path also runs when
    /// the local bundle is lost: an empty seed list must leave the machine's networks alone.
    #[test]
    fn empty_seed_wifi_keeps_existing_networks_and_does_nothing() {
        use crate::apply::Applier;
        let root = tmp_root();
        let (a, r) = applier(root.path());
        let out = apply_bundle(&a, vec![w("A", None, false), tls("T")], vec![]);
        assert!(out.iter().all(|i| i.ok), "{out:?}");
        let before = names(root.path());
        let keys_before = key_dir_names(root.path());
        assert_eq!(before.len(), 2);
        assert_eq!(keys_before.len(), 1);
        let calls = r.calls().len();
        let out = a.apply_without_bundle(&seed(vec![]), crate::apply::Phase::Boot);
        assert!(out.is_empty(), "{out:?}");
        assert_eq!(names(root.path()), before);
        assert_eq!(key_dir_names(root.path()), keys_before);
        assert_eq!(r.calls().len(), calls, "no reload: {:?}", r.calls());
    }

    /// Final review I2: a seed with [A] on a machine holding B adds A and keeps B (and B's key);
    /// the next bundle that does not name B removes it.
    #[test]
    fn seed_adds_without_removing_until_a_bundle_arrives() {
        use crate::apply::Applier;
        let root = tmp_root();
        let (a, _) = applier(root.path());
        apply_bundle(&a, vec![tls("B")], vec![]);
        assert_eq!(names(root.path()), vec![file_name("B")]);
        let out = a.apply_without_bundle(
            &seed(vec![w("A", Some("secret123"), false)]),
            crate::apply::Phase::Boot,
        );
        assert_eq!(out, vec![ok("wifi:A")]);
        let mut both = vec![file_name("A"), file_name("B")];
        both.sort();
        assert_eq!(names(root.path()), both);
        assert_eq!(key_dir_names(root.path()), vec![uuid("B")]);
        let out = apply_bundle(&a, vec![w("A", Some("secret123"), false)], vec![]);
        assert!(out.iter().all(|i| i.ok), "{out:?}");
        assert_eq!(names(root.path()), vec![file_name("A")]);
        assert!(key_dir_names(root.path()).is_empty());
    }

    /// Seed mode reclaims only its own networks from netplan: a recorded network the seed does
    /// not list keeps its netplan copy (removing it would remove the connection).
    #[test]
    fn seed_mode_leaves_other_netplan_copies() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        run_with(root.path(), &r, &mut sys, &[w("B", None, false)]);
        // NM moved B into netplan and deleted our file.
        std::fs::remove_file(conn(root.path()).join(file_name("B"))).unwrap();
        let np = root.path().join(NETPLAN_DIR);
        std::fs::create_dir_all(&np).unwrap();
        let b_yaml = np.join(format!("90-NM-{}.yaml", uuid("B")));
        std::fs::write(&b_yaml, "network: {}\n").unwrap();
        let p = paths(root.path());
        let mut env = Env {
            paths: &p,
            runner: &r,
            sys: &mut sys,
        };
        let out = run_seed(&seed(vec![w("A", None, false)]), &mut env);
        assert_eq!(out, vec![ok("wifi:A")]);
        assert!(b_yaml.exists());
        assert!(sys.wifi_uuids.contains(&uuid("B")), "{:?}", sys.wifi_uuids);
    }

    #[test]
    fn config_overrides_school_network_by_ssid() {
        let root = tmp_root();
        let (a, _) = applier(root.path());
        let out = apply_bundle(
            &a,
            vec![w("A", Some("aaaaaaaa"), false), w("S", None, false)],
            vec![w("A", Some("zzzzzzzz"), false)],
        );
        assert!(out.iter().all(|i| i.ok), "{out:?}");
        let text = std::fs::read_to_string(conn(root.path()).join(file_name("A"))).unwrap();
        assert!(text.contains("psk=zzzzzzzz"), "{text}");
        assert!(!text.contains("aaaaaaaa"), "{text}");
        assert!(conn(root.path()).join(file_name("S")).exists());
    }
}
