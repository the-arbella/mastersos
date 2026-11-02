//! This machine's Secure Boot certificates (the active db) and "does the shim to be installed / swapped in chain to them" (4b Task 22, spec §6.2, §6.3).
//!
//! Shared by the installer's precheck, `mastersos-agent shim-check` (called by `bootloader-update` before it swaps the shim) and the agent's `system:shim-ca` report.
//! No X.509 parsing dependency: certificates are recognised only by the sha256 of their DER ([`MS_UEFI_CA_2011_SHA256`], [`MS_UEFI_CA_2023_SHA256`],
//! checked byte for byte against the two files in the repository's `image/keys/microsoft/`, guarded by tests).
//!
//! **How "chains" is decided** ([`shim_chains`]): take every Authenticode signature from the PE signature table ([`pe_signatures`]); for every
//! db certificate and every signature:
//! 1. `openssl smime -verify -nosigs -partial_chain -no_check_time -purpose any`, `-CAfile` holding only this db certificate (the system
//!    trust store is not read): the signer certificate chains to it through the intermediates carried in the signature. `-no_check_time`: firmware ignores validity periods, and the 2011 CA expired on 2026-06-27.
//!    `-nosigs`: the content Authenticode signs is not in a format PKCS#7 knows, so openssl cannot verify the signature itself (step 2 does).
//! 2. When it chains, `sbverify --cert <this one> --detached <this signature> <image>`: the image hash and the signature itself.
//!
//! **`sbverify --cert` alone is not enough** (seen on VM 161 and the development machine, sbsigntool 0.9.4, OpenSSL 3.0 / 3.5): when the signature carries intermediates
//! (every Microsoft-signed shim does: signer Windows UEFI Driver Publisher + Microsoft Corporation UEFI CA 2011),
//! `sbverify --cert <any certificate>` reports OK - even a self-signed one whose CN pretends to be "Microsoft UEFI CA 2023". Its `x509_verify_cb`
//! plus `X509_V_FLAG_PARTIAL_CHAIN` lets such a signature through; it is only right when the signer is issued directly by the --cert one and the signature carries no intermediates.
//! So sbverify only checks the hash, and openssl checks the chain.

use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use mastersos_bundle::ItemResult;
use sha2::{Digest, Sha256};

use crate::runner::{Cmd, Runner};

/// Active db (relative to sysfs, usually `/sys`): 4 bytes of attributes, then one EFI_SIGNATURE_LIST after another.
pub const DB_VAR: &str = "firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f";
/// Active dbx (revocation list, relative to sysfs): same format as db.
pub const DBX_VAR: &str = "firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f";
/// MOK list (shim's MokListRT, relative to sysfs): 4 bytes of attributes, then EFI_SIGNATURE_LISTs, same format as db.
pub const MOK_LIST_VAR: &str =
    "firmware/efi/efivars/MokListRT-605dab50-e046-4300-abb6-3dd810dd8b23";
/// MastersOS certificates that must not stay in MokList (sha256 of the DER and a name for people): the machine would boot images signed with that key set, and the lab root password is public.
/// One entry per file in the image's `usr/share/mastersos/untrusted-mok/{lab,lab-2026-11,lab-2026-10,pre-release}.der` ([`UNTRUSTED_MOK_FILES`]),
/// checked by `check-tree.sh` item 28 and by tests. `lab-2026-10` is the retired lab certificate: its private key still sits on a disk we cannot wipe, so it stays listed next to the current `lab`. The pre-release certificate moved to `keys/retired/` after Task 7; its sha256 is unchanged.
pub const UNTRUSTED_MOK_SHA256: &[([u8; 32], &str)] = &[
    (
        [
            0x31, 0x1c, 0x8e, 0xbd, 0x3d, 0xb1, 0x4e, 0x8e, 0x3d, 0x40, 0xde, 0x1b, 0x08, 0xc0,
            0xf5, 0xe0, 0x6e, 0xf1, 0x65, 0x57, 0x6d, 0x09, 0xcd, 0xd8, 0xa0, 0x9c, 0xa4, 0x62,
            0xb1, 0x55, 0x62, 0x16,
        ],
        "MastersOS lab",
    ),
    (
        [
            0xb9, 0xde, 0x7b, 0x22, 0xb7, 0x61, 0x25, 0xa4, 0x0c, 0x23, 0xf2, 0x8e, 0x56, 0xf4,
            0x92, 0x8c, 0x4b, 0x08, 0xa9, 0xe6, 0x3b, 0xc4, 0x59, 0x11, 0x40, 0x1b, 0xe1, 0x76,
            0x6a, 0x52, 0xa0, 0x4d,
        ],
        "MastersOS lab (2026-11, retired)",
    ),
    (
        [
            0x33, 0xdd, 0x43, 0xa0, 0xd8, 0xca, 0x42, 0x24, 0xf5, 0x5b, 0x1a, 0xbe, 0x0b, 0xa2,
            0x54, 0x15, 0x6b, 0xe1, 0x35, 0x40, 0xd9, 0x45, 0xb2, 0x1c, 0x8c, 0x2a, 0xc2, 0xea,
            0x7e, 0x3b, 0xd0, 0x6f,
        ],
        "MastersOS lab (2026-10, retired)",
    ),
    (
        [
            0x7c, 0x84, 0x11, 0xf5, 0x62, 0x92, 0xb6, 0x47, 0x27, 0x9a, 0x37, 0xdc, 0xb7, 0xea,
            0xb4, 0x8a, 0xac, 0x17, 0x26, 0x87, 0x20, 0xe3, 0x3a, 0x5f, 0x28, 0xfc, 0x9d, 0x46,
            0xbb, 0xd8, 0x8e, 0x4b,
        ],
        "MastersOS pre-release",
    ),
];
/// The file name of each [`UNTRUSTED_MOK_SHA256`] entry (`/usr/share/mastersos/untrusted-mok/<name>.der`, for `mokutil --delete`).
pub const UNTRUSTED_MOK_FILES: [&str; 4] = ["lab", "lab-2026-11", "lab-2026-10", "pre-release"];
/// `SecureBoot` variable (relative to sysfs): 4 bytes of attributes + 1 byte value, 1 means on.
pub const SECURE_BOOT_VAR: &str =
    "firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
/// The result `bootloader-update` writes in `/var/lib/mastersos-system/` (`SysPaths::var_dir`); the agent reports `system:shim-ca` from it.
pub const SHIM_CA_STATUS: &str = "shim-ca.json";
/// What to do about a revoked shim (shared by the installer and the panel): use a newer image, not a change to the BIOS keys.
pub const REVOKED_ADVICE: &str = "This shim is revoked; use a newer installer image";
/// The marker in shim-check's output when the shim is revoked (bootloader-update writes that line into shim-ca.json's reason, and the panel text is chosen by it).
pub const REVOKED_MARK: &str = "is revoked by this machine's dbx";
/// The marker shim-check wrote before 2026-10-29 (Chinese text, spelled with escapes): a shim-ca.json written then stays until
/// the shim changes, so it must still be recognised (or the panel would advise Reset All Keys for a revoked shim).
const LEGACY_REVOKED_MARK: &str = "\u{88ab}\u{672c}\u{673a}\u{7684} dbx \u{540a}\u{9500}";
/// Name of the report item.
pub const SHIM_CA_ITEM: &str = "system:shim-ca";

/// sha256 of `keys/microsoft/MicCorUEFCA2011_2011-06-27.der` (Microsoft Corporation UEFI CA 2011).
pub const MS_UEFI_CA_2011_SHA256: [u8; 32] = [
    0x48, 0xe9, 0x9b, 0x99, 0x1f, 0x57, 0xfc, 0x52, 0xf7, 0x61, 0x49, 0x59, 0x9b, 0xff, 0x0a, 0x58,
    0xc4, 0x71, 0x54, 0x22, 0x9b, 0x9f, 0x8d, 0x60, 0x3a, 0xc4, 0x0d, 0x35, 0x00, 0x24, 0x85, 0x07,
];
/// sha256 of `keys/microsoft/microsoft-uefi-ca-2023.der` (Microsoft UEFI CA 2023).
pub const MS_UEFI_CA_2023_SHA256: [u8; 32] = [
    0xf6, 0x12, 0x4e, 0x34, 0x12, 0x5b, 0xee, 0x3f, 0xe6, 0xd7, 0x9a, 0x57, 0x4e, 0xaa, 0x7b, 0x91,
    0xc0, 0xe7, 0xbd, 0x9d, 0x92, 0x9c, 0x1a, 0x32, 0x11, 0x78, 0xef, 0xd6, 0x11, 0xda, 0xd9, 0x01,
];

/// EFI_CERT_X509_GUID (a5c059a1-94e4-4aa7-87b5-ab155c2bf072) in the byte order of the variable (first three fields little-endian).
const EFI_CERT_X509_GUID: [u8; 16] = [
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
];
/// EFI_CERT_SHA256_GUID (c1c41626-504c-4092-aca9-41f936934328): each entry is an image's Authenticode SHA-256.
const EFI_CERT_SHA256_GUID: [u8; 16] = [
    0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28,
];
/// EFI_CERT_X509_SHA256/384/512_GUID (EDK2 `ImageAuthentication.h`): each entry is the hash of a certificate's TBSCertificate + 16 bytes of revocation time.
const EFI_CERT_X509_SHA256_GUID: [u8; 16] = [
    0x92, 0xa4, 0xd2, 0x3b, 0xc0, 0x96, 0x79, 0x40, 0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed,
];
const EFI_CERT_X509_SHA384_GUID: [u8; 16] = [
    0x6e, 0x87, 0x76, 0x70, 0xc2, 0x80, 0xe6, 0x4e, 0xaa, 0xd2, 0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b,
];
const EFI_CERT_X509_SHA512_GUID: [u8; 16] = [
    0x63, 0xbf, 0x6d, 0x44, 0x02, 0x25, 0xda, 0x4c, 0xbc, 0xfa, 0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d,
];
/// EFI_TIME: the revocation time after the hash in X509_SHA* entries. A shim has no timestamp, EDK2 refuses it whatever the time, and we ignore it too.
const EFI_TIME: usize = 16;
/// Header of an EFI_SIGNATURE_LIST: SignatureType (16) + ListSize, HeaderSize, SignatureSize (u32 each).
const LIST_HEADER: usize = 28;
/// The SignatureOwner GUID at the start of every entry.
const OWNER: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbCert {
    pub sha256: [u8; 32],
    pub der: Vec<u8>,
}

/// The two kinds of entries we read from a signature database variable (db or dbx): X.509 certificates and Authenticode SHA-256. Other types (SHA-1, ...) are skipped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SigDb {
    pub certs: Vec<DbCert>,
    pub sha256: Vec<[u8; 32]>,
    /// EFI_CERT_X509_SHA256/384/512: TBSCertificate hashes of revoked certificates (length 32 / 48 / 64 tells the algorithm).
    pub tbs: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbRead {
    Certs(Vec<DbCert>),
    /// The variable exists but holds no X.509 certificate (only attributes, or only hash entries): most likely Setup Mode / cleared.
    Empty,
    /// The variable does not exist (not a UEFI boot, or db was deleted).
    Missing,
    /// Cannot be read or has the wrong format; the text says why.
    Malformed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsCa {
    /// Microsoft Corporation UEFI CA 2011: signs today's Ubuntu shim. Expired on 2026-06-27 (firmware ignores validity periods).
    Uefi2011,
    /// Microsoft UEFI CA 2023: needed by Canonical's shims from 2026 Q4.
    Uefi2023,
}

impl MsCa {
    pub fn sha256(self) -> [u8; 32] {
        match self {
            MsCa::Uefi2011 => MS_UEFI_CA_2011_SHA256,
            MsCa::Uefi2023 => MS_UEFI_CA_2023_SHA256,
        }
    }

    /// The certificate's CN.
    pub fn name(self) -> &'static str {
        match self {
            MsCa::Uefi2011 => "Microsoft Corporation UEFI CA 2011",
            MsCa::Uefi2023 => "Microsoft UEFI CA 2023",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShimVerdict {
    /// A db certificate verified one of the shim's signatures.
    Chains { cert_sha256: [u8; 32] },
    /// Every one was tried and none verified.
    NoChain,
    /// Revoked by dbx (a signature chains to a certificate in dbx, or the image's Authenticode hash is in dbx): the firmware refuses it even when another signature chains to db.
    /// Same exit code as "does not chain" (1).
    Revoked(String),
    /// Cannot tell (`sbverify` missing, the shim cannot be read, a temporary file cannot be written).
    CantCheck(String),
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Parses the content of the db variable (including the leading 4 bytes of attributes), X.509 entries only (the `certs` of [`parse_sig_db`]).
pub fn parse_db(var: &[u8]) -> Result<Vec<DbCert>, String> {
    parse_sig_db(var).map(|d| d.certs)
}

/// Parses a db / dbx variable (including the leading 4 bytes of attributes): checks the sizes of every EFI_SIGNATURE_LIST, takes the DER of X.509 entries and the hashes of SHA-256 entries,
/// and skips other types. The SignatureSize of a SHA-256 list must be 16 + 32.
pub fn parse_sig_db(var: &[u8]) -> Result<SigDb, String> {
    if var.len() < 4 {
        return Err(format!(
            "the variable has only {} bytes, less than the 4 bytes of attributes",
            var.len()
        ));
    }
    let b = &var[4..];
    let mut certs = Vec::new();
    let mut hashes = Vec::new();
    let mut tbs = Vec::new();
    let mut off = 0usize;
    while off < b.len() {
        if b.len() - off < LIST_HEADER {
            return Err(format!("list header truncated at offset {off}"));
        }
        let ty = &b[off..off + 16];
        let list = le32(b, off + 16) as usize;
        let header = le32(b, off + 20) as usize;
        let size = le32(b, off + 24) as usize;
        let body = LIST_HEADER
            .checked_add(header)
            .filter(|&min| list >= min)
            .map(|min| list - min)
            .ok_or_else(|| {
                format!(
                    "SignatureListSize {list} at offset {off} is less than 28 + SignatureHeaderSize {header}"
                )
            })?;
        if size < OWNER {
            return Err(format!(
                "SignatureSize {size} at offset {off} is less than 16"
            ));
        }
        if body % size != 0 {
            return Err(format!(
                "signature area of {body} bytes at offset {off} is not a multiple of SignatureSize {size}"
            ));
        }
        if list > b.len() - off {
            return Err(format!(
                "SignatureListSize {list} at offset {off} goes past the variable ({} bytes left)",
                b.len() - off
            ));
        }
        if ty == EFI_CERT_X509_GUID {
            let start = off + LIST_HEADER + header;
            for item in b[start..off + list].chunks_exact(size) {
                let der = item[OWNER..].to_vec();
                certs.push(DbCert {
                    sha256: Sha256::digest(&der).into(),
                    der,
                });
            }
        } else if ty == EFI_CERT_SHA256_GUID {
            if size != OWNER + 32 {
                return Err(format!(
                    "SignatureSize of the SHA-256 list at offset {off} is {size}, should be 48"
                ));
            }
            let start = off + LIST_HEADER + header;
            for item in b[start..off + list].chunks_exact(size) {
                let mut h = [0u8; 32];
                h.copy_from_slice(&item[OWNER..]);
                hashes.push(h);
            }
        } else if let Some(n) = [
            (EFI_CERT_X509_SHA256_GUID, 32),
            (EFI_CERT_X509_SHA384_GUID, 48),
            (EFI_CERT_X509_SHA512_GUID, 64),
        ]
        .iter()
        .find(|(g, _)| ty == g)
        .map(|&(_, n)| n)
        {
            if size != OWNER + n + EFI_TIME {
                return Err(format!(
                    "SignatureSize of the X509_SHA{} list at offset {off} is {size}, should be {}",
                    n * 8,
                    OWNER + n + EFI_TIME
                ));
            }
            let start = off + LIST_HEADER + header;
            for item in b[start..off + list].chunks_exact(size) {
                tbs.push(item[OWNER..OWNER + n].to_vec());
            }
        }
        off += list;
    }
    Ok(SigDb {
        certs,
        sha256: hashes,
        tbs,
    })
}

/// Reads `<sysfs>/`[`DBX_VAR`]. Missing, or only attributes -> empty (nothing revoked, normal); unreadable or malformed -> `Err` (cannot tell, treated as a failure).
pub fn read_dbx(sysfs: &Path) -> Result<SigDb, String> {
    let p = sysfs.join(DBX_VAR);
    match std::fs::read(&p) {
        Ok(b) => parse_sig_db(&b).map_err(|e| format!("dbx cannot be parsed: {e}")),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(SigDb::default()),
        Err(e) => Err(format!("cannot read {}: {e}", p.display())),
    }
}

/// Reads `<sysfs>/`[`MOK_LIST_VAR`]. Missing -> empty (no MOK ever enrolled, normal); unreadable or malformed -> `Err`.
pub fn read_mok_list(sysfs: &Path) -> Result<Vec<DbCert>, String> {
    let p = sysfs.join(MOK_LIST_VAR);
    match std::fs::read(&p) {
        Ok(b) => parse_db(&b).map_err(|e| format!("MokList cannot be parsed: {e}")),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("cannot read {}: {e}", p.display())),
    }
}

/// An EFI_SIGNATURE_LIST of EFI_CERT_SHA256 (owner all zero). For tests and tools building dbx variables.
pub fn sha256_signature_list(hashes: &[[u8; 32]]) -> Vec<u8> {
    let size = OWNER + 32;
    let mut l = Vec::with_capacity(LIST_HEADER + hashes.len() * size);
    l.extend_from_slice(&EFI_CERT_SHA256_GUID);
    l.extend_from_slice(&((LIST_HEADER + hashes.len() * size) as u32).to_le_bytes());
    l.extend_from_slice(&0u32.to_le_bytes());
    l.extend_from_slice(&(size as u32).to_le_bytes());
    for h in hashes {
        l.extend_from_slice(&[0u8; OWNER]);
        l.extend_from_slice(h);
    }
    l
}

/// Reads `<sysfs>/`[`DB_VAR`].
pub fn read_db(sysfs: &Path) -> DbRead {
    let p = sysfs.join(DB_VAR);
    let b = match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) if e.kind() == ErrorKind::NotFound => return DbRead::Missing,
        Err(e) => return DbRead::Malformed(format!("cannot read {}: {e}", p.display())),
    };
    match parse_db(&b) {
        Ok(c) if c.is_empty() => DbRead::Empty,
        Ok(c) => DbRead::Certs(c),
        Err(e) => DbRead::Malformed(e),
    }
}

/// An EFI_SIGNATURE_LIST of EFI_CERT_X509 (one list per certificate, owner all zero; with several, SignatureSize is the first one's length,
/// so call it once per certificate of a different length). For tests and tools building db variables.
pub fn x509_signature_list(ders: &[&[u8]]) -> Vec<u8> {
    let size = OWNER + ders.first().map_or(0, |d| d.len());
    let mut l = Vec::with_capacity(LIST_HEADER + ders.len() * size);
    l.extend_from_slice(&EFI_CERT_X509_GUID);
    l.extend_from_slice(&((LIST_HEADER + ders.len() * size) as u32).to_le_bytes());
    l.extend_from_slice(&0u32.to_le_bytes());
    l.extend_from_slice(&(size as u32).to_le_bytes());
    for d in ders {
        l.extend_from_slice(&[0u8; OWNER]);
        l.extend_from_slice(d);
    }
    l
}

/// Whether db has this Microsoft CA: by the sha256 of the DER, never by CN (anyone can self-sign one with the same name).
pub fn has_ms_ca(certs: &[DbCert], ca: MsCa) -> bool {
    certs.iter().any(|c| c.sha256 == ca.sha256())
}

/// Whether this sha256 is one of the two Microsoft CAs.
pub fn ms_ca_of(sha: &[u8; 32]) -> Option<MsCa> {
    [MsCa::Uefi2011, MsCa::Uefi2023]
        .into_iter()
        .find(|c| &c.sha256() == sha)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Writes DER as PEM: 0600, `create_new` (fails when a file or symlink of that name exists, never writes through a link).
fn write_pem(p: &Path, der: &[u8]) -> std::io::Result<()> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(line).unwrap_or_default());
        s.push('\n');
    }
    s.push_str("-----END CERTIFICATE-----\n");
    write_private(p, s.as_bytes())
}

/// Every Authenticode signature in a PE image's signature table (PKCS#7 DER of `WIN_CERT_TYPE_PKCS_SIGNED_DATA`, without the padding to 8 bytes).
/// No signature table -> empty; not a PE, a table out of bounds or malformed -> `Err`. Parses only the PE headers and WIN_CERTIFICATE, never X.509.
pub fn pe_signatures(img: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let u16_at = |at: usize| -> Result<u16, String> {
        img.get(at..at + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .ok_or_else(|| {
                format!(
                    "offset {at} is past the end of the file ({} bytes)",
                    img.len()
                )
            })
    };
    let u32_at = |at: usize| -> Result<u32, String> {
        img.get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or_else(|| {
                format!(
                    "offset {at} is past the end of the file ({} bytes)",
                    img.len()
                )
            })
    };
    if img.get(..2) != Some(b"MZ") {
        return Err("not a PE (no MZ)".into());
    }
    let pe = u32_at(0x3c)? as usize;
    if img.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err("not a PE (no PE signature)".into());
    }
    let opt = pe + 24;
    let (count_at, dirs) = match u16_at(opt)? {
        0x10b => (opt + 92, opt + 96),
        0x20b => (opt + 108, opt + 112),
        m => return Err(format!("unknown optional header magic {m:#x}")),
    };
    if u32_at(count_at)? < 5 {
        return Ok(Vec::new());
    }
    let start = u32_at(dirs + 4 * 8)? as usize;
    let size = u32_at(dirs + 4 * 8 + 4)? as usize;
    if size == 0 {
        return Ok(Vec::new());
    }
    let end = start
        .checked_add(size)
        .filter(|&e| e <= img.len())
        .ok_or_else(|| {
            format!(
                "the signature table ({size} bytes from {start}) goes past the end of the file ({} bytes)",
                img.len()
            )
        })?;
    let mut sigs = Vec::new();
    let mut off = start;
    while off < end {
        if end - off < 8 {
            return Err(format!("WIN_CERTIFICATE header truncated at offset {off}"));
        }
        let len = u32_at(off)? as usize;
        let ty = u16_at(off + 6)?;
        if len < 8 || len > end - off {
            return Err(format!(
                "WIN_CERTIFICATE at offset {off} has a wrong dwLength {len}"
            ));
        }
        // Only WIN_CERT_TYPE_PKCS_SIGNED_DATA. EDK2 also accepts WIN_CERT_TYPE_EFI_GUID + EFI_CERT_TYPE_PKCS7_GUID,
        // which no real shim uses; for db missing it errs towards "does not chain", for dbx it would miss such a signature (review Nit 2, accepted)
        if ty == 0x0002 {
            let body = &img[off + 8..off + len];
            sigs.push(body[..der_len(body).unwrap_or(body.len())].to_vec());
        }
        off += len.div_ceil(8) * 8;
    }
    Ok(sigs)
}

/// An EFI_SIGNATURE_LIST of EFI_CERT_X509_SHA256/384/512 (type chosen by hash length 32 / 48 / 64, owner and revocation time all zero).
/// For tests and tools building dbx variables; all hashes in one list must have the same length.
pub fn tbs_signature_list(hashes: &[&[u8]]) -> Vec<u8> {
    let n = hashes.first().map_or(32, |h| h.len());
    let guid = match n {
        48 => EFI_CERT_X509_SHA384_GUID,
        64 => EFI_CERT_X509_SHA512_GUID,
        _ => EFI_CERT_X509_SHA256_GUID,
    };
    let size = OWNER + n + EFI_TIME;
    let mut l = Vec::with_capacity(LIST_HEADER + hashes.len() * size);
    l.extend_from_slice(&guid);
    l.extend_from_slice(&((LIST_HEADER + hashes.len() * size) as u32).to_le_bytes());
    l.extend_from_slice(&0u32.to_le_bytes());
    l.extend_from_slice(&(size as u32).to_le_bytes());
    for h in hashes {
        l.extend_from_slice(&[0u8; OWNER]);
        l.extend_from_slice(h);
        l.extend_from_slice(&[0u8; EFI_TIME]);
    }
    l
}

/// One DER TLV: (tag, start of the content, end of the content). Definite lengths only (Authenticode is DER).
fn der_tlv(b: &[u8], at: usize) -> Result<(u8, usize, usize), String> {
    let tag = *b.get(at).ok_or("DER truncated")?;
    let l0 = *b.get(at + 1).ok_or("DER truncated")? as usize;
    let (hdr, len) = if l0 < 0x80 {
        (2, l0)
    } else {
        let n = l0 & 0x7f;
        if n == 0 || n > 4 {
            return Err(format!("DER length at offset {at} not understood"));
        }
        let v = b
            .get(at + 2..at + 2 + n)
            .ok_or("DER truncated")?
            .iter()
            .fold(0usize, |a, &x| (a << 8) | x as usize);
        (2 + n, v)
    };
    let start = at + hdr;
    let end = start
        .checked_add(len)
        .filter(|&e| e <= b.len())
        .ok_or("DER out of bounds")?;
    Ok((tag, start, end))
}

/// The certificates carried in a PKCS#7 SignedData (`certificates [0] IMPLICIT`, the full DER of each). Walks only the outer ASN.1 structure, never parses the certificates.
pub fn pkcs7_certs(p7: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let (t, s, e) = der_tlv(p7, 0)?;
    if t != 0x30 {
        return Err("PKCS#7 is not a SEQUENCE".into());
    }
    let (t, _, oid_end) = der_tlv(p7, s)?;
    if t != 0x06 {
        return Err("PKCS#7 has no contentType".into());
    }
    let (t, s, _) = der_tlv(p7, oid_end)?;
    if t != 0xa0 || oid_end >= e {
        return Err("PKCS#7 has no [0] content".into());
    }
    let (t, s, sd_end) = der_tlv(p7, s)?;
    if t != 0x30 {
        return Err("SignedData is not a SEQUENCE".into());
    }
    // version, digestAlgorithms, contentInfo, then maybe [0] certificates
    let mut at = s;
    for want in [0x02u8, 0x31, 0x30] {
        let (t, _, end) = der_tlv(p7, at)?;
        if t != want {
            return Err(format!(
                "SignedData has the wrong structure ({t:#x}, should be {want:#x})"
            ));
        }
        at = end;
    }
    let mut certs = Vec::new();
    if at < sd_end {
        let (t, cs, ce) = der_tlv(p7, at)?;
        if t == 0xa0 {
            let mut c = cs;
            while c < ce {
                let (t, _, end) = der_tlv(p7, c)?;
                if t == 0x30 {
                    certs.push(p7[c..end].to_vec());
                }
                c = end;
            }
        }
    }
    Ok(certs)
}

/// The TBSCertificate (with its own tag and length) of a certificate (full DER) - the X509_SHA* entries of dbx compare its hash.
pub fn tbs_certificate(cert: &[u8]) -> Result<&[u8], String> {
    let (t, s, _) = der_tlv(cert, 0)?;
    if t != 0x30 {
        return Err("the certificate is not a SEQUENCE".into());
    }
    let (t, _, end) = der_tlv(cert, s)?;
    if t != 0x30 {
        return Err("TBSCertificate is not a SEQUENCE".into());
    }
    Ok(&cert[s..end])
}

/// The TBS hash of a certificate carried in a signature is in dbx's X509_SHA256/384/512 (EDK2 `IsCertHashFoundInDbx`).
fn tbs_revoked(sigs: &[Vec<u8>], tbs: &[Vec<u8>]) -> Result<Option<String>, String> {
    use sha2::{Sha384, Sha512};
    for sig in sigs {
        for cert in pkcs7_certs(sig)? {
            let t = tbs_certificate(&cert)?;
            let digests: [Vec<u8>; 3] = [
                Sha256::digest(t).to_vec(),
                Sha384::digest(t).to_vec(),
                Sha512::digest(t).to_vec(),
            ];
            if let Some(h) = tbs.iter().find(|h| digests.contains(h)) {
                return Ok(Some(format!(
                    "the TBS hash (X509_SHA{1}) of certificate {0} carried in the signature is in dbx",
                    hex(&Sha256::digest(&cert)),
                    h.len() * 8
                )));
            }
        }
    }
    Ok(None)
}

/// The image's Authenticode SHA-256, as EDK2 `DxeImageVerificationLib`'s `HashPeImage`: the headers (skipping CheckSum and the signature table
/// directory entry) up to SizeOfHeaders, then every section sorted by PointerToRawData, then the bytes left after the sections and before the signature table. dbx's SHA-256 entries compare exactly this.
pub fn authenticode_sha256(img: &[u8]) -> Result<[u8; 32], String> {
    let rd16 = |at: usize| -> Result<usize, String> {
        img.get(at..at + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
            .ok_or_else(|| format!("offset {at} is past the end of the file"))
    };
    let rd32 = |at: usize| -> Result<usize, String> {
        img.get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
            .ok_or_else(|| format!("offset {at} is past the end of the file"))
    };
    let range = |a: usize, b: usize| -> Result<&[u8], String> {
        img.get(a..b)
            .ok_or_else(|| format!("{a}..{b} is past the end of the file ({} bytes)", img.len()))
    };
    if img.get(..2) != Some(b"MZ") {
        return Err("not a PE (no MZ)".into());
    }
    let pe = rd32(0x3c)?;
    if img.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err("not a PE (no PE signature)".into());
    }
    let sections = rd16(pe + 6)?;
    let opt_size = rd16(pe + 20)?;
    let opt = pe + 24;
    let (count_at, dirs) = match rd16(opt)? {
        0x10b => (opt + 92, opt + 96),
        0x20b => (opt + 108, opt + 112),
        m => return Err(format!("unknown optional header magic {m:#x}")),
    };
    let checksum = opt + 64;
    let headers = rd32(opt + 60)?;
    let count = rd32(count_at)?;
    let mut h = Sha256::new();
    h.update(range(0, checksum)?);
    let cert_size = if count <= 4 {
        h.update(range(checksum + 4, headers)?);
        0
    } else {
        let sec = dirs + 4 * 8;
        h.update(range(checksum + 4, sec)?);
        h.update(range(sec + 8, headers)?);
        rd32(sec + 4)?
    };
    let mut sum = headers;
    let table = opt + opt_size;
    let mut secs = Vec::with_capacity(sections);
    for i in 0..sections {
        let at = table + i * 40;
        secs.push((rd32(at + 20)?, rd32(at + 16)?));
    }
    // EDK2 uses a stable insertion sort by PointerToRawData: sections at the same offset keep their order in the section table
    secs.sort_by_key(|&(ptr, _)| ptr);
    for (ptr, size) in secs.into_iter().filter(|&(_, size)| size != 0) {
        let end = ptr.checked_add(size).ok_or("section out of bounds")?;
        h.update(range(ptr, end)?);
        sum += size;
    }
    if img.len() > sum {
        let tail = img
            .len()
            .checked_sub(cert_size)
            .filter(|&e| e >= sum)
            .ok_or_else(|| format!("the signature table ({cert_size} bytes) is larger than what is left after the sections"))?;
        h.update(range(sum, tail)?);
    }
    Ok(h.finalize().into())
}

/// Total length of the outer DER TLV (dropping the zeros that pad a signature); None when not understood (the whole thing is used as is).
fn der_len(b: &[u8]) -> Option<usize> {
    let l = *b.get(1)? as usize;
    let (hdr, body) = if l < 0x80 {
        (2, l)
    } else {
        let n = l & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let v = b
            .get(2..2 + n)?
            .iter()
            .fold(0usize, |a, &x| (a << 8) | x as usize);
        (2 + n, v)
    };
    let total = hdr.checked_add(body)?;
    (total <= b.len()).then_some(total)
}

/// A minimal PE32+ image with only a signature table (for tests and tools: input for [`pe_signatures`], [`shim_chains`]).
pub fn pe_with_signatures(sigs: &[&[u8]]) -> Vec<u8> {
    const PE: usize = 0x40;
    const OPT: usize = PE + 24;
    const OPT_SIZE: usize = 240;
    let table = OPT + OPT_SIZE;
    let mut img = vec![0u8; table];
    img[..2].copy_from_slice(b"MZ");
    img[0x3c..0x40].copy_from_slice(&(PE as u32).to_le_bytes());
    img[PE..PE + 4].copy_from_slice(b"PE\0\0");
    img[PE + 4..PE + 6].copy_from_slice(&0x8664u16.to_le_bytes());
    img[PE + 20..PE + 22].copy_from_slice(&(OPT_SIZE as u16).to_le_bytes());
    img[OPT..OPT + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    img[OPT + 60..OPT + 64].copy_from_slice(&(table as u32).to_le_bytes());
    img[OPT + 108..OPT + 112].copy_from_slice(&16u32.to_le_bytes());
    for s in sigs {
        let len = 8 + s.len();
        img.extend_from_slice(&(len as u32).to_le_bytes());
        img.extend_from_slice(&0x0200u16.to_le_bytes());
        img.extend_from_slice(&0x0002u16.to_le_bytes());
        img.extend_from_slice(s);
        img.resize(img.len() + (len.div_ceil(8) * 8 - len), 0);
    }
    if !sigs.is_empty() {
        let dir = OPT + 112 + 4 * 8;
        img[dir..dir + 4].copy_from_slice(&(table as u32).to_le_bytes());
        let size = (img.len() - table) as u32;
        img[dir + 4..dir + 8].copy_from_slice(&size.to_le_bytes());
    }
    img
}

/// Writes `p` (0600, `create_new`).
fn write_private(p: &Path, b: &[u8]) -> std::io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)?;
    f.write_all(b)?;
    f.sync_all()
}

/// openssl checks only the chain: exit 0 **and** "Verification successful" in the output -> chains; exit 4 (verification failure) -> does not chain; anything else -> cannot tell.
/// The exit code alone is not enough: OpenSSL 3.0.13's `smime` takes an unknown option for a cipher name, reports "Unknown cipher" and still exits 0
/// (seen on the development machine), so an openssl without `-no-CAstore` would count as "chains".
fn chain_ok(r: &dyn Runner, sig: &str, pem: &str) -> Result<bool, String> {
    let cmd = Cmd::new(
        "openssl",
        &[
            "smime",
            "-verify",
            "-nosigs",
            "-inform",
            "DER",
            "-in",
            sig,
            "-CAfile",
            pem,
            "-no-CApath",
            "-no-CAstore",
            "-partial_chain",
            "-purpose",
            "any",
            "-no_check_time",
            "-out",
            "/dev/null",
        ],
    )
    .timeout(Duration::from_secs(60));
    match r.run(&cmd) {
        Err(e) => Err(format!("openssl could not run: {e:#}")),
        Ok(o)
            if o.code == 0
                && format!("{}{}", o.stdout, o.stderr).contains("Verification successful") =>
        {
            Ok(true)
        }
        Ok(o) if o.code == 4 => Ok(false),
        Ok(o) => Err(format!(
            "openssl smime -verify exited with {} without \"Verification successful\": {}",
            o.code,
            crate::runner::last_lines(&o.stderr, 2)
        )),
    }
}

/// sbverify checks the image hash and this signature itself: exit 0 -> passes; 126 / 127 or cannot start -> cannot tell; anything else -> fails.
fn hash_ok(r: &dyn Runner, pem: &str, sig: &str, shim: &str) -> Result<bool, String> {
    let cmd = Cmd::new("sbverify", &["--cert", pem, "--detached", sig, shim])
        .timeout(Duration::from_secs(60));
    match r.run(&cmd) {
        Err(e) => Err(format!("sbverify could not run: {e:#}")),
        Ok(o) if o.code == 126 || o.code == 127 => {
            Err(format!("sbverify could not run (exit code {})", o.code))
        }
        Ok(o) => Ok(o.code == 0),
    }
}

/// Whether the firmware of this machine would accept the shim (approach in the module comment):
/// 1. when dbx has SHA-256 entries and the image's Authenticode hash ([`authenticode_sha256`]) is among them -> `Revoked`;
/// 2. any signature chaining to any certificate in dbx (compared like db: openssl `-partial_chain`, the whole certificate as trust anchor) -> `Revoked` -
///    EDK2 refuses the whole image as soon as one signature is stopped by dbx, even when another one chains to db;
/// 3. for every db certificate and every signature: openssl checks the chain, then sbverify the hash; the first that passes both gives `Chains`.
///
/// Certificates are written as PEM and signatures as DER (all under `tmp`, 0600, deleted afterwards).
pub fn shim_chains(
    r: &dyn Runner,
    shim: &Path,
    certs: &[DbCert],
    dbx: &SigDb,
    tmp: &Path,
) -> ShimVerdict {
    // sbverify also exits 1 for a file it cannot read: read it first, so "cannot read" is not taken for "does not chain"
    let img = match std::fs::read(shim) {
        Ok(b) => b,
        Err(e) => {
            return ShimVerdict::CantCheck(format!("cannot read the shim {}: {e}", shim.display()))
        }
    };
    let sigs = match pe_signatures(&img) {
        Ok(s) => s,
        Err(e) => {
            return ShimVerdict::CantCheck(format!(
                "the signature table of {} cannot be parsed: {e}",
                shim.display()
            ))
        }
    };
    if !dbx.sha256.is_empty() {
        match authenticode_sha256(&img) {
            Ok(h) if dbx.sha256.contains(&h) => {
                return ShimVerdict::Revoked(format!(
                    "the image's Authenticode hash {} is in dbx",
                    hex(&h)
                ))
            }
            Ok(_) => {}
            Err(e) => {
                return ShimVerdict::CantCheck(format!(
                    "cannot compute the Authenticode hash of {}: {e}",
                    shim.display()
                ))
            }
        }
    }
    if !dbx.tbs.is_empty() {
        match tbs_revoked(&sigs, &dbx.tbs) {
            Ok(Some(why)) => return ShimVerdict::Revoked(why),
            Ok(None) => {}
            Err(e) => {
                return ShimVerdict::CantCheck(format!(
                    "cannot extract the certificates carried in the signatures of {}: {e}",
                    shim.display()
                ))
            }
        }
    }
    if sigs.is_empty() || (certs.is_empty() && dbx.certs.is_empty()) {
        return ShimVerdict::NoChain;
    }
    let base = tmp.join(format!("mastersos-shim-{}", std::process::id()));
    let mut written: Vec<PathBuf> = Vec::new();
    let verdict = (|| {
        let mut sig_paths = Vec::new();
        for (j, s) in sigs.iter().enumerate() {
            let p = PathBuf::from(format!("{}-sig{j}.p7", base.display()));
            write_private(&p, s).map_err(|e| format!("cannot write {}: {e}", p.display()))?;
            written.push(p.clone());
            sig_paths.push(p.to_string_lossy().into_owned());
        }
        let mut pem_of = |tag: &str, i: usize, c: &DbCert| -> Result<String, String> {
            let pem = PathBuf::from(format!("{}-{tag}{i}.pem", base.display()));
            write_pem(&pem, &c.der).map_err(|e| format!("cannot write {}: {e}", pem.display()))?;
            written.push(pem.clone());
            Ok(pem.to_string_lossy().into_owned())
        };
        for (i, c) in dbx.certs.iter().enumerate() {
            let pem = pem_of("dbx", i, c)?;
            for sig in &sig_paths {
                if chain_ok(r, sig, &pem)? {
                    return Ok(ShimVerdict::Revoked(format!(
                        "a signature chains to certificate {} in dbx",
                        hex(&c.sha256)
                    )));
                }
            }
        }
        let shim_s = shim.to_string_lossy();
        for (i, c) in certs.iter().enumerate() {
            let pem = pem_of("db", i, c)?;
            for sig in &sig_paths {
                if chain_ok(r, sig, &pem)? && hash_ok(r, &pem, sig, &shim_s)? {
                    return Ok(ShimVerdict::Chains {
                        cert_sha256: c.sha256,
                    });
                }
            }
        }
        Ok(ShimVerdict::NoChain)
    })();
    for p in &written {
        let _ = std::fs::remove_file(p);
    }
    verdict.unwrap_or_else(ShimVerdict::CantCheck)
}

/// Secure Boot state. Unreadable must not count as "off": shim-check does not check and lets the shim swap go ahead when it is off (review I2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecureBootState {
    /// The variable reads 0; or not a UEFI boot at all (no `<sysfs>/firmware/efi`).
    Off,
    On,
    /// efivars not mounted, the variable unreadable, the content not understood.
    Unknown(String),
}

/// Reads the `SecureBoot` variable: 4 bytes of attributes + 1 byte value.
/// - no `<sysfs>/firmware/efi` (legacy BIOS boot) -> Off;
/// - it exists but the `efivars` directory is missing or empty (efivarfs not mounted) -> Unknown;
/// - efivars mounted but no such variable (firmware without Secure Boot) -> Off;
/// - a read error (permissions, I/O, a directory) -> Unknown; length not 5 or value not 0 / 1 -> Unknown.
pub fn secure_boot_state(sysfs: &Path) -> SecureBootState {
    let efi = sysfs.join("firmware/efi");
    // Only "really does not exist" means a legacy boot; other stat errors (EACCES and the like) must not count as off (review N2)
    match std::fs::metadata(&efi) {
        Err(e) if e.kind() == ErrorKind::NotFound => return SecureBootState::Off,
        Err(e) => return SecureBootState::Unknown(format!("cannot read {}: {e}", efi.display())),
        Ok(_) => {}
    }
    let vars = efi.join("efivars");
    match std::fs::read_dir(&vars) {
        Ok(mut rd) => {
            if rd.next().is_none() {
                return SecureBootState::Unknown(format!(
                    "{} is empty (efivarfs not mounted?)",
                    vars.display()
                ));
            }
        }
        Err(e) => return SecureBootState::Unknown(format!("cannot read {}: {e}", vars.display())),
    }
    let p = sysfs.join(SECURE_BOOT_VAR);
    match std::fs::read(&p) {
        Err(e) if e.kind() == ErrorKind::NotFound => SecureBootState::Off,
        Err(e) => SecureBootState::Unknown(format!("cannot read {}: {e}", p.display())),
        Ok(b) if b.len() == 5 && b[4] == 0 => SecureBootState::Off,
        Ok(b) if b.len() == 5 && b[4] == 1 => SecureBootState::On,
        Ok(b) => SecureBootState::Unknown(format!(
            "the content of {} is not understood ({} bytes)",
            p.display(),
            b.len()
        )),
    }
}

/// Description of a db certificate: its sha256 and which Microsoft CA it is.
pub fn describe_cert(sha: &[u8; 32]) -> String {
    match ms_ca_of(sha) {
        Some(ca) => format!("{} ({})", hex(sha), ca.name()),
        None => format!("{} (not Microsoft's UEFI CA 2011 / 2023)", hex(sha)),
    }
}

/// All of `mastersos-agent shim-check <shim>`, returns the exit code: Secure Boot off -> 0 (nothing checked);
/// chains -> 0; does not chain, revoked by dbx -> 1; Secure Boot state unreadable, db unreadable, dbx not understood, cannot tell -> 2. The explanation goes to `out`.
pub fn shim_check(
    r: &dyn Runner,
    sysfs: &Path,
    shim: &Path,
    tmp: &Path,
    out: &mut dyn Write,
) -> u8 {
    match secure_boot_state(sysfs) {
        SecureBootState::Off => {
            let _ = writeln!(
                out,
                "Secure Boot is off, the shim's certificate chain is not checked"
            );
            return 0;
        }
        SecureBootState::Unknown(why) => {
            let _ = writeln!(out, "cannot tell whether Secure Boot is on: {why}");
            return 2;
        }
        SecureBootState::On => {}
    }
    let certs = match read_db(sysfs) {
        DbRead::Certs(c) => c,
        DbRead::Empty => {
            let _ = writeln!(
                out,
                "the active db has no certificates (Setup Mode?), cannot tell"
            );
            return 2;
        }
        DbRead::Missing => {
            let _ = writeln!(out, "there is no db variable, cannot tell");
            return 2;
        }
        DbRead::Malformed(why) => {
            let _ = writeln!(out, "the db variable cannot be parsed: {why}");
            return 2;
        }
    };
    let dbx = match read_dbx(sysfs) {
        Ok(d) => d,
        Err(why) => {
            let _ = writeln!(out, "cannot tell: {why}");
            return 2;
        }
    };
    match shim_chains(r, shim, &certs, &dbx, tmp) {
        ShimVerdict::Chains { cert_sha256 } => {
            let _ = writeln!(
                out,
                "{} chains to {} in db",
                shim.display(),
                describe_cert(&cert_sha256)
            );
            0
        }
        ShimVerdict::NoChain => {
            // One short line: bootloader-update writes the last line into shim-ca.json and that is what the panel shows (VM 165's db has 10 certificates, listing them all is too long)
            let ms: Vec<&str> = [MsCa::Uefi2011, MsCa::Uefi2023]
                .into_iter()
                .filter(|&ca| has_ms_ca(&certs, ca))
                .map(MsCa::name)
                .collect();
            let _ = writeln!(
                out,
                "{} does not chain to any certificate in the active db ({} in total; Microsoft's among them: {})",
                shim.display(),
                certs.len(),
                if ms.is_empty() {
                    "none".to_string()
                } else {
                    ms.join(", ")
                }
            );
            1
        }
        ShimVerdict::Revoked(why) => {
            let _ = writeln!(out, "{} {REVOKED_MARK}: {why}", shim.display());
            1
        }
        ShimVerdict::CantCheck(why) => {
            let _ = writeln!(out, "cannot tell: {why}");
            2
        }
    }
}

/// `mastersos-agent shim-check [--sysfs <dir>] <shim>`: the arguments are `argv[2..]`. The PEMs are written in a 0700 directory it creates under the temporary directory.
pub fn shim_check_main(args: impl Iterator<Item = std::ffi::OsString>) -> std::process::ExitCode {
    let mut sysfs = PathBuf::from("/sys");
    let mut shim = None;
    let mut args = args;
    while let Some(a) = args.next() {
        if a == "--sysfs" {
            match args.next() {
                Some(v) => sysfs = v.into(),
                None => return usage(),
            }
        } else if shim.is_none() {
            shim = Some(PathBuf::from(a));
        } else {
            return usage();
        }
    }
    let Some(shim) = shim else { return usage() };
    let tmp = std::env::temp_dir().join(format!("mastersos-shim-check.{}", std::process::id()));
    if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&tmp) {
        println!(
            "cannot tell: cannot create the temporary directory {}: {e}",
            tmp.display()
        );
        return std::process::ExitCode::from(2);
    }
    let code = shim_check(
        &crate::runner::RealRunner,
        &sysfs,
        &shim,
        &tmp,
        &mut std::io::stdout(),
    );
    let _ = std::fs::remove_dir_all(&tmp);
    std::process::ExitCode::from(code)
}

fn usage() -> std::process::ExitCode {
    eprintln!("usage: mastersos-agent shim-check [--sysfs <dir>] <shim.efi>");
    std::process::ExitCode::from(2)
}

/// `system:shim-ca`: reads the [`SHIM_CA_STATUS`] written by `bootloader-update`. `ok:false` -> failure (the boot loader stays at the old version);
/// no file -> success (never swapped yet); not understood -> failure.
pub fn shim_ca_item(var_dir: &Path) -> ItemResult {
    let p = var_dir.join(SHIM_CA_STATUS);
    let item = |ok: bool, detail: String| ItemResult {
        item: SHIM_CA_ITEM.into(),
        ok,
        detail: Some(detail),
    };
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return item(true, "the boot loader has not been swapped yet".into());
        }
        Err(e) => return item(false, format!("cannot read {}: {e}", p.display())),
    };
    let v: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => return item(false, format!("{} cannot be parsed: {e}", p.display())),
    };
    let field = |k: &str| match v.get(k) {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => "?".into(),
    };
    match v.get("ok").and_then(serde_json::Value::as_bool) {
        Some(true) => item(
            true,
            format!(
                "the boot loader matches the one MastersOS {} carries",
                field("image_version")
            ),
        ),
        // Three failures, three texts (review N3): a shim revoked by dbx must never lead to Reset All Keys - that would put back the factory dbx, which may predate this revocation
        Some(false) => {
            let (ver, exit, reason) = (field("image_version"), field("exit"), field("reason"));
            let detail = if reason.contains(REVOKED_MARK) || reason.contains(LEGACY_REVOKED_MARK) {
                format!(
                    "the shim in the new image (MastersOS {ver}) is revoked by this machine's dbx, the boot loader stays at the old version. {REVOKED_ADVICE} ({reason})"
                )
            } else if exit == "1" {
                format!(
                    "the shim in the new image (MastersOS {ver}) does not chain to this machine's Secure Boot db, the boot loader stays at the old version: update the BIOS and \
                     Reset All Keys as in §6.9 (shim-check exited 1: {reason})"
                )
            } else {
                format!(
                    "cannot check whether the shim in the new image (MastersOS {ver}) can start on this machine, the boot loader stays at the old version (shim-check exited {exit}: {reason})"
                )
            };
            item(false, detail)
        }
        None => item(false, format!("{} has no ok field", p.display())),
    }
}

#[cfg(test)]
mod tests;
