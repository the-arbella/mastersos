use std::fs;

use super::*;
use crate::runner::{FakeRunner, Output};

const MS_2011_DER: &[u8] =
    include_bytes!("../../../../image/keys/microsoft/MicCorUEFCA2011_2011-06-27.der");
const MS_2023_DER: &[u8] =
    include_bytes!("../../../../image/keys/microsoft/microsoft-uefi-ca-2023.der");
/// A self-signed openssl certificate whose subject copies Microsoft's 2023 one (`C=US, O=Microsoft Corporation, CN=Microsoft UEFI CA 2023`).
const FAKE_2023_DER: &[u8] = include_bytes!("fake-ms-uefi-ca-2023.der");

/// EFI_CERT_SHA256_GUID (c1c41626-504c-4092-aca9-41f936934328) in on-disk byte order.
const SHA256_GUID: [u8; 16] = [
    0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28,
];

/// openssl's output when the chain verifies (only exit 0 plus this sentence counts as chaining).
fn ssl_ok() -> Output {
    Output::ok("Verification successful\n")
}

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// 4 bytes of attributes (NV|BS|RT|TIME_BASED_AUTH = 0x27) plus some EFI_SIGNATURE_LISTs.
fn var(lists: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![0x27, 0, 0, 0];
    for l in lists {
        v.extend_from_slice(l);
    }
    v
}

/// A SHA256 list: two hash entries.
fn sha256_list() -> Vec<u8> {
    let mut l = Vec::new();
    l.extend_from_slice(&SHA256_GUID);
    let n = 2u32;
    let size = 16 + 32;
    l.extend_from_slice(&(28 + n * size).to_le_bytes());
    l.extend_from_slice(&0u32.to_le_bytes());
    l.extend_from_slice(&size.to_le_bytes());
    for i in 0..n {
        l.extend_from_slice(&[0xaa; 16]);
        l.extend_from_slice(&[i as u8; 32]);
    }
    l
}

fn sysfs_with_db(db: Option<&[u8]>, secure_boot: Option<u8>) -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let ev = d.path().join("firmware/efi/efivars");
    fs::create_dir_all(&ev).unwrap();
    if let Some(db) = db {
        fs::write(d.path().join(DB_VAR), db).unwrap();
    }
    if let Some(sb) = secure_boot {
        fs::write(d.path().join(SECURE_BOOT_VAR), [6, 0, 0, 0, sb]).unwrap();
    }
    d
}

#[test]
fn parse_db_reads_x509_entries() {
    // Two "certificates" of the same length in one X509 list (parse_db does not parse X.509, it only takes the DER bytes)
    let a = vec![0x30u8; 40];
    let b = vec![0x31u8; 40];
    let mut x = x509_signature_list(&[&a]);
    // Two entries built by hand: same SignatureSize, ListSize grows by one entry
    let size = 16 + 40u32;
    x[16..20].copy_from_slice(&(28 + 2 * size).to_le_bytes());
    x.extend_from_slice(&[0x11; 16]);
    x.extend_from_slice(&b);
    let certs = parse_db(&var(&[x, sha256_list()])).unwrap();
    assert_eq!(certs.len(), 2);
    assert_eq!(certs[0].der, a);
    assert_eq!(certs[1].der, b);
    assert_eq!(certs[0].sha256, sha(&a));
    assert_eq!(certs[1].sha256, sha(&b));
    // One list for each Microsoft CA (different lengths, as in a real db)
    let certs = parse_db(&var(&[
        x509_signature_list(&[MS_2011_DER]),
        sha256_list(),
        x509_signature_list(&[MS_2023_DER]),
    ]))
    .unwrap();
    assert!(has_ms_ca(&certs, MsCa::Uefi2011));
    assert!(has_ms_ca(&certs, MsCa::Uefi2023));
}

#[test]
fn parse_db_rejects_truncated_list() {
    let full = var(&[x509_signature_list(&[MS_2023_DER])]);
    for cut in [5, 4 + 27, full.len() - 1] {
        assert!(
            parse_db(&full[..cut]).is_err(),
            "cut at {cut} bytes should fail"
        );
    }
    assert!(
        parse_db(&[0x27, 0, 0]).is_err(),
        "less than 4 bytes of attributes"
    );
}

#[test]
fn parse_db_rejects_bad_sizes() {
    let good = x509_signature_list(&[MS_2023_DER]);
    // SignatureSize < 16
    let mut l = good.clone();
    l[24..28].copy_from_slice(&15u32.to_le_bytes());
    assert!(parse_db(&var(&[l])).is_err());
    // Remainder not 0: SignatureSize one byte short
    let mut l = good.clone();
    let s = u32::from_le_bytes(l[24..28].try_into().unwrap());
    l[24..28].copy_from_slice(&(s - 1).to_le_bytes());
    assert!(parse_db(&var(&[l])).is_err());
    // ListSize out of bounds
    let mut l = good.clone();
    let ls = u32::from_le_bytes(l[16..20].try_into().unwrap());
    l[16..20].copy_from_slice(&(ls + 64).to_le_bytes());
    assert!(parse_db(&var(&[l])).is_err());
    // ListSize < 28 + HeaderSize
    let mut l = good.clone();
    l[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(parse_db(&var(&[l])).is_err());
    let mut l = good;
    l[16..20].copy_from_slice(&20u32.to_le_bytes());
    assert!(parse_db(&var(&[l])).is_err());
}

#[test]
fn empty_var_is_empty() {
    let d = sysfs_with_db(Some(&[0x27, 0, 0, 0]), None);
    assert!(matches!(read_db(d.path()), DbRead::Empty));
    let d = sysfs_with_db(None, None);
    assert!(matches!(read_db(d.path()), DbRead::Missing));
    let d = sysfs_with_db(Some(&[0x27, 0, 0, 0, 1, 2, 3]), None);
    assert!(matches!(read_db(d.path()), DbRead::Malformed(_)));
    // Only hashes, no certificate: also counts as no certificates
    let d = sysfs_with_db(Some(&var(&[sha256_list()])), None);
    assert!(matches!(read_db(d.path()), DbRead::Empty));
    let d = sysfs_with_db(Some(&var(&[x509_signature_list(&[MS_2023_DER])])), None);
    match read_db(d.path()) {
        DbRead::Certs(c) => assert_eq!(c.len(), 1),
        other => panic!("{other:?}"),
    }
}

#[test]
fn ms_ca_constants_match_repo_files() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../image/keys/microsoft");
    let a = fs::read(dir.join("MicCorUEFCA2011_2011-06-27.der")).unwrap();
    let b = fs::read(dir.join("microsoft-uefi-ca-2023.der")).unwrap();
    assert_eq!(sha(&a), MS_UEFI_CA_2011_SHA256);
    assert_eq!(sha(&b), MS_UEFI_CA_2023_SHA256);
    assert_eq!(MsCa::Uefi2011.sha256(), MS_UEFI_CA_2011_SHA256);
    assert_eq!(MsCa::Uefi2023.sha256(), MS_UEFI_CA_2023_SHA256);
}

#[test]
fn has_ms_ca_by_fingerprint_not_cn() {
    let certs = parse_db(&var(&[x509_signature_list(&[FAKE_2023_DER])])).unwrap();
    assert!(!has_ms_ca(&certs, MsCa::Uefi2023));
    assert!(!has_ms_ca(&certs, MsCa::Uefi2011));
    assert_eq!(ms_ca_of(&certs[0].sha256), None);
    assert_eq!(ms_ca_of(&MS_UEFI_CA_2023_SHA256), Some(MsCa::Uefi2023));
}

fn certs(ders: &[&[u8]]) -> Vec<DbCert> {
    ders.iter()
        .map(|d| DbCert {
            sha256: sha(d),
            der: d.to_vec(),
        })
        .collect()
}

/// A "signature": a DER SEQUENCE (30 82 len) with arbitrary content; parsing only looks at the outer length.
fn fake_sig(fill: u8, len: usize) -> Vec<u8> {
    let mut v = vec![0x30, 0x82, (len >> 8) as u8, len as u8];
    v.extend(std::iter::repeat_n(fill, len));
    v
}

fn shim_file(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("BOOTX64.EFI");
    fs::write(&p, pe_with_signatures(&[&fake_sig(0x11, 300)])).unwrap();
    p
}

fn nothing_left(tmp: &std::path::Path) -> bool {
    fs::read_dir(tmp).unwrap().all(|e| {
        let n = e.unwrap().file_name().to_string_lossy().into_owned();
        !n.ends_with(".pem") && !n.ends_with(".p7")
    })
}

#[test]
fn pe_signatures_reads_every_entry() {
    let a = fake_sig(0xaa, 301); // 305 bytes: WIN_CERTIFICATE padded to a multiple of 8
    let b = fake_sig(0xbb, 40);
    let pe = pe_with_signatures(&[&a, &b]);
    assert_eq!(pe_signatures(&pe).unwrap(), vec![a.clone(), b.clone()]);
    // No signature table
    assert_eq!(
        pe_signatures(&pe_with_signatures(&[])).unwrap(),
        Vec::<Vec<u8>>::new()
    );
    // Not a PE
    assert!(pe_signatures(b"MZ fake shim").is_err());
    assert!(pe_signatures(b"").is_err());
    // Signature table truncated: the file is shorter than the directory entry says
    assert!(pe_signatures(&pe[..pe.len() - 10]).is_err());
    // dwLength less than 8
    let mut bad = pe.clone();
    let off = pe.windows(a.len()).position(|w| w == a.as_slice()).unwrap() - 8;
    bad[off..off + 4].copy_from_slice(&4u32.to_le_bytes());
    assert!(pe_signatures(&bad).is_err());
}

/// The first db certificate does not chain (openssl exits 1), the second one does and sbverify checks the hash -> Chains{the second}.
#[test]
fn shim_chains_tries_each_db_cert() {
    let d = tempfile::tempdir().unwrap();
    let shim = shim_file(d.path());
    let tmp = d.path().join("tmp");
    fs::create_dir(&tmp).unwrap();
    let r = FakeRunner::new();
    r.respond(
        "openssl smime -verify",
        Output::fail(4, "Verify error: unable to get local issuer certificate"),
    );
    r.respond("openssl smime -verify", ssl_ok());
    let v = shim_chains(
        &r,
        &shim,
        &certs(&[MS_2023_DER, MS_2011_DER]),
        &SigDb::default(),
        &tmp,
    );
    assert_eq!(
        v,
        ShimVerdict::Chains {
            cert_sha256: MS_UEFI_CA_2011_SHA256
        }
    );
    let calls = r.calls();
    assert_eq!(calls.len(), 3, "{calls:?}");
    let t = tmp.display();
    for c in &calls[..2] {
        assert!(
            c.starts_with(&format!(
                "openssl smime -verify -nosigs -inform DER -in {t}/"
            )) && c.contains(&format!("-CAfile {t}/"))
                && c.contains(
                    " -no-CApath -no-CAstore -partial_chain -purpose any -no_check_time "
                ),
            "{c}"
        );
    }
    assert!(
        calls[2].starts_with(&format!("sbverify --cert {t}/"))
            && calls[2].contains(" --detached ")
            && calls[2].ends_with(&format!(" {}", shim.display())),
        "{}",
        calls[2]
    );
    assert!(
        nothing_left(&tmp),
        "PEMs and signatures must be deleted after use"
    );
}

/// Dual-signed: the first signature does not chain to this db certificate, the second does -> Chains.
#[test]
fn shim_chains_tries_each_signature() {
    let d = tempfile::tempdir().unwrap();
    let shim = d.path().join("BOOTX64.EFI");
    fs::write(
        &shim,
        pe_with_signatures(&[&fake_sig(0x11, 300), &fake_sig(0x22, 200)]),
    )
    .unwrap();
    let r = FakeRunner::new();
    r.respond(
        "openssl smime -verify",
        Output::fail(4, "unable to get local issuer"),
    );
    r.respond("openssl smime -verify", ssl_ok());
    let v = shim_chains(
        &r,
        &shim,
        &certs(&[MS_2023_DER]),
        &SigDb::default(),
        d.path(),
    );
    assert_eq!(
        v,
        ShimVerdict::Chains {
            cert_sha256: MS_UEFI_CA_2023_SHA256
        }
    );
    assert_eq!(r.calls().len(), 3, "{:?}", r.calls());
    assert!(nothing_left(d.path()));
}

#[test]
fn pem_is_private_and_well_formed() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("x.pem");
    write_pem(&p, MS_2023_DER).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let s = fs::read_to_string(&p).unwrap();
    assert!(s.starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert!(s.ends_with("-----END CERTIFICATE-----\n"));
    assert!(s.lines().all(|l| l.len() <= 64));
    // A file (or symlink) of the same name already exists: nothing is written
    assert!(write_pem(&p, MS_2023_DER).is_err());
}

#[test]
fn shim_chains_none_is_no_chain() {
    let d = tempfile::tempdir().unwrap();
    let shim = shim_file(d.path());
    // No chain at all: only openssl runs, never sbverify
    let r = FakeRunner::new();
    for _ in 0..2 {
        r.respond("openssl", Output::fail(4, "unable to get local issuer"));
    }
    let v = shim_chains(
        &r,
        &shim,
        &certs(&[MS_2023_DER, MS_2011_DER]),
        &SigDb::default(),
        d.path(),
    );
    assert_eq!(v, ShimVerdict::NoChain);
    assert_eq!(r.calls().len(), 2);
    assert!(r.calls().iter().all(|c| c.starts_with("openssl ")));
    assert!(nothing_left(d.path()));
    // Chains, but the image hash or the signature fails (sbverify exits 1): does not count either
    let r = FakeRunner::new();
    r.respond("openssl", ssl_ok());
    r.respond("sbverify", Output::fail(1, "Image fails hash check"));
    let v = shim_chains(
        &r,
        &shim,
        &certs(&[MS_2011_DER]),
        &SigDb::default(),
        d.path(),
    );
    assert_eq!(v, ShimVerdict::NoChain);
    // An unsigned image
    let unsigned = d.path().join("unsigned.efi");
    fs::write(&unsigned, pe_with_signatures(&[])).unwrap();
    let r = FakeRunner::new();
    assert_eq!(
        shim_chains(
            &r,
            &unsigned,
            &certs(&[MS_2011_DER]),
            &SigDb::default(),
            d.path()
        ),
        ShimVerdict::NoChain
    );
    assert!(r.calls().is_empty());
    // No certificates in db: nothing can chain, no commands run
    let r = FakeRunner::new();
    assert_eq!(
        shim_chains(&r, &shim, &[], &SigDb::default(), d.path()),
        ShimVerdict::NoChain
    );
    assert!(r.calls().is_empty());
}

/// A Runner that cannot start anything (RealRunner returns Err when the command is not on PATH).
struct NoSbverify;
impl Runner for NoSbverify {
    fn run(&self, cmd: &Cmd) -> anyhow::Result<Output> {
        anyhow::bail!("{}: No such file or directory", cmd.program)
    }
}

#[test]
fn sbverify_missing_is_cant_check() {
    let d = tempfile::tempdir().unwrap();
    let shim = shim_file(d.path());
    let v = shim_chains(
        &NoSbverify,
        &shim,
        &certs(&[MS_2011_DER]),
        &SigDb::default(),
        d.path(),
    );
    assert!(
        matches!(v, ShimVerdict::CantCheck(ref w) if w.contains("openssl")),
        "{v:?}"
    );
    assert!(nothing_left(d.path()));
    // Exit code 127 (a shell wrapper cannot find the command) is "cannot tell" too: for openssl and for sbverify
    for prefix in ["openssl", "sbverify"] {
        let r = FakeRunner::new();
        r.respond(prefix, Output::fail(127, "not found"));
        r.respond("openssl", ssl_ok());
        let v = shim_chains(
            &r,
            &shim,
            &certs(&[MS_2011_DER]),
            &SigDb::default(),
            d.path(),
        );
        assert!(matches!(v, ShimVerdict::CantCheck(_)), "{prefix}: {v:?}");
    }
    // The shim cannot be read, or is not a PE: no commands run (sbverify also exits 1 for an unreadable file, which would look like "does not chain")
    for bad in [d.path().join("nope.efi"), {
        let p = d.path().join("notpe.efi");
        fs::write(&p, b"MZ fake shim").unwrap();
        p
    }] {
        let r = FakeRunner::new();
        let v = shim_chains(
            &r,
            &bad,
            &certs(&[MS_2011_DER]),
            &SigDb::default(),
            d.path(),
        );
        assert!(matches!(v, ShimVerdict::CantCheck(_)), "{v:?}");
        assert!(r.calls().is_empty());
    }
}

#[test]
fn shim_check_skips_when_secure_boot_off() {
    for sb in [Some(0), None] {
        let d = sysfs_with_db(Some(&var(&[x509_signature_list(&[MS_2011_DER])])), sb);
        let shim = shim_file(d.path());
        let r = FakeRunner::new();
        let mut out = Vec::new();
        assert_eq!(shim_check(&r, d.path(), &shim, d.path(), &mut out), 0);
        assert!(r.calls().is_empty(), "{:?}", r.calls());
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("Secure Boot is off"));
    }
}

#[test]
fn shim_check_exit_codes() {
    // Secure Boot on: chains -> 0 (prints the certificate and which Microsoft CA it is), does not chain -> 1, db unreadable -> 2, cannot tell -> 2
    let d = sysfs_with_db(Some(&var(&[x509_signature_list(&[MS_2011_DER])])), Some(1));
    let shim = shim_file(d.path());
    let r = FakeRunner::new();
    r.respond("openssl", ssl_ok());
    let mut out = Vec::new();
    assert_eq!(shim_check(&r, d.path(), &shim, d.path(), &mut out), 0);
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains(&hex(&MS_UEFI_CA_2011_SHA256)), "{out}");
    assert!(out.contains("Microsoft Corporation UEFI CA 2011"), "{out}");

    let r = FakeRunner::new();
    r.respond("openssl", Output::fail(4, "unable to get local issuer"));
    let mut out = Vec::new();
    assert_eq!(shim_check(&r, d.path(), &shim, d.path(), &mut out), 1);
    let out = String::from_utf8(out).unwrap();
    // One line saying how many there are and which Microsoft CAs are among them (no fingerprint per certificate: the panel shows this line)
    assert_eq!(out.lines().count(), 1, "{out}");
    assert!(
        out.contains("1 in total; Microsoft's among them: Microsoft Corporation UEFI CA 2011"),
        "{out}"
    );

    assert_eq!(
        shim_check(&NoSbverify, d.path(), &shim, d.path(), &mut Vec::new()),
        2
    );

    for db in [None, Some(vec![0x27, 0, 0, 0])] {
        let d = sysfs_with_db(db.as_deref(), Some(1));
        let r = FakeRunner::new();
        assert_eq!(
            shim_check(&r, d.path(), &shim, d.path(), &mut Vec::new()),
            2
        );
        assert!(r.calls().is_empty());
    }
}

#[test]
fn shim_ca_item_reports_status_file() {
    let d = tempfile::tempdir().unwrap();
    let i = shim_ca_item(d.path());
    assert_eq!(i.item, "system:shim-ca");
    assert!(i.ok, "{i:?}");
    assert!(
        i.detail
            .as_deref()
            .unwrap()
            .contains("not been swapped yet"),
        "{i:?}"
    );

    fs::write(
        d.path().join(SHIM_CA_STATUS),
        r#"{"ok":false,"exit":1,"image_version":"20261017.3","reason":"shim-check exited 1"}"#,
    )
    .unwrap();
    let i = shim_ca_item(d.path());
    assert!(!i.ok, "{i:?}");
    let detail = i.detail.unwrap();
    assert!(detail.contains("Reset All Keys"), "{detail}");
    assert!(detail.contains("20261017.3"), "{detail}");

    fs::write(
        d.path().join(SHIM_CA_STATUS),
        r#"{"ok":true,"exit":0,"image_version":"20261017.4","reason":"chains to db"}"#,
    )
    .unwrap();
    let i = shim_ca_item(d.path());
    assert!(i.ok, "{i:?}");

    fs::write(d.path().join(SHIM_CA_STATUS), "not json").unwrap();
    let i = shim_ca_item(d.path());
    assert!(
        !i.ok,
        "a status file that cannot be parsed must not report success: {i:?}"
    );
}

// ---------- dbx, Authenticode hash, openssl exit codes, the three Secure Boot states (review I1, I2, Minor 6) ----------

#[test]
fn parse_sig_db_reads_sha256_entries() {
    let h1 = [0x11u8; 32];
    let h2 = [0x22u8; 32];
    let d = parse_sig_db(&var(&[
        x509_signature_list(&[MS_2011_DER]),
        sha256_signature_list(&[h1, h2]),
    ]))
    .unwrap();
    assert_eq!(d.certs.len(), 1);
    assert_eq!(d.sha256, vec![h1, h2]);
    // SignatureSize of the SHA-256 list is not 48: malformed
    let mut l = sha256_signature_list(&[h1]);
    l[24..28].copy_from_slice(&40u32.to_le_bytes());
    l[16..20].copy_from_slice(&(28u32 + 40).to_le_bytes());
    l.truncate(28 + 40);
    assert!(parse_sig_db(&var(&[l])).is_err());
}

fn sysfs_with_dbx(dbx: Option<&[u8]>) -> tempfile::TempDir {
    let d = sysfs_with_db(Some(&var(&[x509_signature_list(&[MS_2011_DER])])), Some(1));
    if let Some(b) = dbx {
        fs::write(d.path().join(DBX_VAR), b).unwrap();
    }
    d
}

#[test]
fn dbx_missing_or_empty_is_no_revocation() {
    assert_eq!(read_dbx(sysfs_with_dbx(None).path()), Ok(SigDb::default()));
    assert_eq!(
        read_dbx(sysfs_with_dbx(Some(&[0x27, 0, 0, 0])).path()),
        Ok(SigDb::default())
    );
    let e = read_dbx(sysfs_with_dbx(Some(&[0x27, 0, 0, 0, 9, 9])).path()).unwrap_err();
    assert!(e.contains("dbx"), "{e}");
}

/// Two sections (deliberately in reverse order in the section table), 5 more bytes after the sections, then the signature table: the hash covers EDK2's ranges.
#[test]
fn authenticode_follows_edk2_ranges() {
    let mut img = pe_with_signatures(&[]);
    let pe = 0x40usize;
    let opt = pe + 24;
    let opt_size = 240usize;
    let table = opt + opt_size;
    // Two section headers (40 bytes each): section A at 0x280, 0x10 long; section B at 0x200, 0x20 long (0x220..0x280 in between is a gap)
    img[pe + 6..pe + 8].copy_from_slice(&2u16.to_le_bytes());
    let headers = 0x200usize;
    img[opt + 60..opt + 64].copy_from_slice(&(headers as u32).to_le_bytes());
    img.resize(table + 80, 0);
    for (i, (ptr, size)) in [(0x280u32, 0x10u32), (0x200, 0x20)].iter().enumerate() {
        let at = table + i * 40;
        img[at + 16..at + 20].copy_from_slice(&size.to_le_bytes());
        img[at + 20..at + 24].copy_from_slice(&ptr.to_le_bytes());
    }
    img.resize(0x290, 0);
    for (i, b) in img.iter_mut().enumerate().skip(0x200) {
        *b = i as u8;
    }
    img.extend_from_slice(b"TAIL!");
    let sig = fake_sig(0x33, 20);
    let cert_at = img.len();
    let len = 8 + sig.len();
    img.extend_from_slice(&(len as u32).to_le_bytes());
    img.extend_from_slice(&0x0200u16.to_le_bytes());
    img.extend_from_slice(&0x0002u16.to_le_bytes());
    img.extend_from_slice(&sig);
    img.resize(cert_at + len.div_ceil(8) * 8, 0);
    let dir = opt + 112 + 4 * 8;
    img[dir..dir + 4].copy_from_slice(&(cert_at as u32).to_le_bytes());
    let cert_size = (img.len() - cert_at) as u32;
    img[dir + 4..dir + 8].copy_from_slice(&cert_size.to_le_bytes());
    // Expected: 0..CheckSum, after CheckSum up to the signature table directory entry, after the entry up to SizeOfHeaders, section B (0x200), section A (0x280),
    // then the rest: EDK2 starts at "headers + the lengths of both sections" 0x230 (not at the end of the last section) and goes up to the signature table - the gap and section A count again; we copy that behaviour
    let mut h = Sha256::new();
    h.update(&img[..opt + 64]);
    h.update(&img[opt + 68..dir]);
    h.update(&img[dir + 8..headers]);
    h.update(&img[0x200..0x220]);
    h.update(&img[0x280..0x290]);
    h.update(&img[0x230..cert_at]);
    let want: [u8; 32] = h.finalize().into();
    assert_eq!(authenticode_sha256(&img).unwrap(), want);
    // A changed signature table (another signature) leaves the hash unchanged; changing one byte in a section changes it
    assert_eq!(pe_signatures(&img).unwrap(), vec![sig]);
    let mut other = img.clone();
    other[0x285] ^= 1;
    assert_ne!(authenticode_sha256(&other).unwrap(), want);
    assert!(authenticode_sha256(b"MZ nope").is_err());
}

/// The image hash is in dbx: revoked without running any command (exit 1).
#[test]
fn dbx_hash_revokes() {
    let d = sysfs_with_dbx(None);
    let shim = shim_file(d.path());
    let h = authenticode_sha256(&fs::read(&shim).unwrap()).unwrap();
    let dbx = SigDb {
        sha256: vec![[0u8; 32], h],
        ..Default::default()
    };
    let r = FakeRunner::new();
    let v = shim_chains(&r, &shim, &certs(&[MS_2011_DER]), &dbx, d.path());
    assert!(
        matches!(v, ShimVerdict::Revoked(ref w) if w.contains(&hex(&h))),
        "{v:?}"
    );
    assert!(r.calls().is_empty());
    // Through shim-check: this hash in the dbx variable -> exit 1
    fs::write(d.path().join(DBX_VAR), var(&[sha256_signature_list(&[h])])).unwrap();
    let mut out = Vec::new();
    assert_eq!(
        shim_check(&FakeRunner::new(), d.path(), &shim, d.path(), &mut out),
        1
    );
    assert!(String::from_utf8(out).unwrap().contains("dbx"));
}

/// Dual-signed: the first signature chains to a certificate in dbx, the second chains to db -> still revoked (EDK2 refuses the whole image when one signature is stopped by dbx).
#[test]
fn dbx_cert_on_any_signature_revokes() {
    let d = sysfs_with_dbx(None);
    let shim = d.path().join("BOOTX64.EFI");
    fs::write(
        &shim,
        pe_with_signatures(&[&fake_sig(0x11, 300), &fake_sig(0x22, 200)]),
    )
    .unwrap();
    let dbx = SigDb {
        certs: certs(&[FAKE_2023_DER]),
        ..Default::default()
    };
    let r = FakeRunner::new();
    // dbx certificate x signature 1: chains
    r.respond("openssl", ssl_ok());
    let v = shim_chains(&r, &shim, &certs(&[MS_2011_DER]), &dbx, d.path());
    assert!(matches!(v, ShimVerdict::Revoked(_)), "{v:?}");
    let calls = r.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(calls[0].contains("-dbx0.pem"), "{calls:?}");
    assert!(nothing_left(d.path()));
    // The dbx certificate chains to neither signature -> look at db
    let r = FakeRunner::new();
    r.respond("openssl", Output::fail(4, "unable to get local issuer"));
    r.respond("openssl", Output::fail(4, "unable to get local issuer"));
    r.respond("openssl", ssl_ok());
    let v = shim_chains(&r, &shim, &certs(&[MS_2011_DER]), &dbx, d.path());
    assert_eq!(
        v,
        ShimVerdict::Chains {
            cert_sha256: MS_UEFI_CA_2011_SHA256
        }
    );
    // Through shim-check: this certificate in the dbx variable -> exit 1
    fs::write(
        d.path().join(DBX_VAR),
        var(&[x509_signature_list(&[FAKE_2023_DER])]),
    )
    .unwrap();
    let r = FakeRunner::new();
    r.respond("openssl", ssl_ok());
    assert_eq!(
        shim_check(&r, d.path(), &shim, d.path(), &mut Vec::new()),
        1
    );
    // dbx cannot be parsed -> 2, no commands run
    fs::write(d.path().join(DBX_VAR), [0x27, 0, 0, 0, 1]).unwrap();
    let r = FakeRunner::new();
    assert_eq!(
        shim_check(&r, d.path(), &shim, d.path(), &mut Vec::new()),
        2
    );
    assert!(r.calls().is_empty());
}

/// openssl: exit 0 without "Verification successful" (what OpenSSL 3.0 does with an unknown option), exit 1, 2 -> cannot tell; exit 4 -> does not chain.
#[test]
fn openssl_exit_codes() {
    let d = tempfile::tempdir().unwrap();
    let shim = shim_file(d.path());
    for out in [
        Output::ok(""),
        Output {
            code: 0,
            stdout: String::new(),
            stderr: "smime: Unknown cipher: no-CAstore\n".into(),
        },
        Output::fail(1, "smime: Use -help for summary."),
        Output::fail(2, "Error reading S/MIME message"),
    ] {
        let r = FakeRunner::new();
        r.respond("openssl", out.clone());
        let v = shim_chains(
            &r,
            &shim,
            &certs(&[MS_2011_DER]),
            &SigDb::default(),
            d.path(),
        );
        assert!(matches!(v, ShimVerdict::CantCheck(_)), "{out:?} → {v:?}");
        assert!(!r.calls().iter().any(|c| c.starts_with("sbverify")));
    }
    let r = FakeRunner::new();
    r.respond("openssl", Output::fail(4, "certificate verify error"));
    assert_eq!(
        shim_chains(
            &r,
            &shim,
            &certs(&[MS_2011_DER]),
            &SigDb::default(),
            d.path()
        ),
        ShimVerdict::NoChain
    );
}

#[test]
fn secure_boot_state_is_tri_state() {
    let d = tempfile::tempdir().unwrap();
    // No firmware/efi: legacy boot -> off
    assert_eq!(secure_boot_state(d.path()), SecureBootState::Off);
    // firmware/efi exists, efivars missing or empty (not mounted) -> cannot tell
    fs::create_dir_all(d.path().join("firmware/efi")).unwrap();
    assert!(matches!(
        secure_boot_state(d.path()),
        SecureBootState::Unknown(_)
    ));
    fs::create_dir_all(d.path().join("firmware/efi/efivars")).unwrap();
    assert!(matches!(
        secure_boot_state(d.path()),
        SecureBootState::Unknown(_)
    ));
    // Mounted, no SecureBoot variable (firmware without it) -> off
    fs::write(d.path().join(DB_VAR), [0x27, 0, 0, 0]).unwrap();
    assert_eq!(secure_boot_state(d.path()), SecureBootState::Off);
    let sb = d.path().join(SECURE_BOOT_VAR);
    for (bytes, want) in [
        (vec![6u8, 0, 0, 0, 0], Some(SecureBootState::Off)),
        (vec![6, 0, 0, 0, 1], Some(SecureBootState::On)),
        (vec![6, 0, 0, 0, 2], None),
        (vec![6, 0, 0, 0], None),
        (vec![6, 0, 0, 0, 1, 1], None),
    ] {
        fs::write(&sb, &bytes).unwrap();
        let got = secure_boot_state(d.path());
        match want {
            Some(w) => assert_eq!(got, w, "{bytes:?}"),
            None => assert!(
                matches!(got, SecureBootState::Unknown(_)),
                "{bytes:?} → {got:?}"
            ),
        }
    }
    // A read error (here: a directory) -> cannot tell
    fs::remove_file(&sb).unwrap();
    fs::create_dir(&sb).unwrap();
    assert!(matches!(
        secure_boot_state(d.path()),
        SecureBootState::Unknown(_)
    ));
}

/// Secure Boot state unknown: shim-check exits 2 (bootloader-update does not swap), no commands run.
#[test]
fn shim_check_unknown_secure_boot_is_exit_2() {
    let d = sysfs_with_db(Some(&var(&[x509_signature_list(&[MS_2011_DER])])), None);
    let shim = shim_file(d.path());
    fs::create_dir(d.path().join(SECURE_BOOT_VAR)).unwrap();
    let r = FakeRunner::new();
    let mut out = Vec::new();
    assert_eq!(shim_check(&r, d.path(), &shim, d.path(), &mut out), 2);
    assert!(r.calls().is_empty());
    assert!(String::from_utf8(out)
        .unwrap()
        .contains("cannot tell whether Secure Boot"));
    // efivars not mounted (firmware/efi exists, efivars empty)
    let e = tempfile::tempdir().unwrap();
    fs::create_dir_all(e.path().join("firmware/efi/efivars")).unwrap();
    assert_eq!(
        shim_check(&r, e.path(), &shim, e.path(), &mut Vec::new()),
        2
    );
}

// ---------- second review round: dbx X509_SHA256/384/512, an unreadable efi directory, the revoked wording ----------

/// One DER TLV (long length form with two bytes, enough for tests).
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag, 0x82, (body.len() >> 8) as u8, body.len() as u8];
    v.extend_from_slice(body);
    v
}

/// A minimal PKCS#7 SignedData: contentType, version, empty digestAlgorithms, contentInfo, these certificates in [0], empty signerInfos.
fn fake_p7(certs: &[&[u8]]) -> Vec<u8> {
    let oid = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
    ];
    let mut sd = vec![0x02, 0x01, 0x01];
    sd.extend(tlv(0x31, &[]));
    sd.extend(tlv(0x30, &[0x06, 0x01, 0x00]));
    sd.extend(tlv(0xa0, &certs.concat()));
    sd.extend(tlv(0x31, &[]));
    let mut ci = oid.to_vec();
    ci.extend(tlv(0xa0, &tlv(0x30, &sd)));
    tlv(0x30, &ci)
}

#[test]
fn pkcs7_certs_and_tbs() {
    let p7 = fake_p7(&[MS_2011_DER, MS_2023_DER]);
    let cs = pkcs7_certs(&p7).unwrap();
    assert_eq!(cs, vec![MS_2011_DER.to_vec(), MS_2023_DER.to_vec()]);
    // TBSCertificate: the first member of the certificate's outer SEQUENCE, with its own header; signature algorithm and signature follow
    let t = tbs_certificate(MS_2011_DER).unwrap();
    assert_eq!(t[0], 0x30);
    assert!(t.len() < MS_2011_DER.len() - 200);
    assert_eq!(&MS_2011_DER[4..4 + t.len()], t);
    // A signature carrying no certificate: empty
    assert!(pkcs7_certs(&fake_p7(&[])).unwrap().is_empty());
    assert!(pkcs7_certs(&[0x30, 0x03, 1, 2, 3]).is_err());
}

#[test]
fn parse_sig_db_reads_x509_sha_entries() {
    let a = [0xaau8; 32];
    let b = [0xbbu8; 48];
    let c = [0xccu8; 64];
    let d = parse_sig_db(&var(&[
        tbs_signature_list(&[&a]),
        tbs_signature_list(&[&b]),
        tbs_signature_list(&[&c]),
    ]))
    .unwrap();
    assert_eq!(d.tbs, vec![a.to_vec(), b.to_vec(), c.to_vec()]);
    // Wrong SignatureSize (X509_SHA256 should be 16 + 32 + 16)
    let mut l = tbs_signature_list(&[&a]);
    l[24..28].copy_from_slice(&48u32.to_le_bytes());
    l[16..20].copy_from_slice(&(28u32 + 48).to_le_bytes());
    l.truncate(28 + 48);
    assert!(parse_sig_db(&var(&[l])).is_err());
}

/// The TBS hash (SHA-256/384/512) of a certificate carried in the signature is in dbx -> revoked, no commands run; no certificate can be taken from the signature -> cannot tell.
#[test]
fn dbx_tbs_hash_revokes() {
    use sha2::{Sha384, Sha512};
    let d = tempfile::tempdir().unwrap();
    let shim = d.path().join("BOOTX64.EFI");
    fs::write(
        &shim,
        pe_with_signatures(&[&fake_p7(&[FAKE_2023_DER]), &fake_p7(&[MS_2011_DER])]),
    )
    .unwrap();
    let t = tbs_certificate(MS_2011_DER).unwrap();
    for h in [
        Sha256::digest(t).to_vec(),
        Sha384::digest(t).to_vec(),
        Sha512::digest(t).to_vec(),
    ] {
        let dbx = SigDb {
            tbs: vec![vec![0u8; h.len()], h.clone()],
            ..Default::default()
        };
        let r = FakeRunner::new();
        let v = shim_chains(&r, &shim, &certs(&[MS_2011_DER]), &dbx, d.path());
        assert!(
            matches!(v, ShimVerdict::Revoked(ref w) if w.contains(&format!("X509_SHA{}", h.len() * 8))),
            "{v:?}"
        );
        assert!(r.calls().is_empty());
    }
    // Another certificate's TBS hash: does not count, carries on (openssl checks the chain)
    let other = Sha256::digest(tbs_certificate(MS_2023_DER).unwrap()).to_vec();
    let dbx = SigDb {
        tbs: vec![other],
        ..Default::default()
    };
    let r = FakeRunner::new();
    r.respond("openssl", ssl_ok());
    assert_eq!(
        shim_chains(&r, &shim, &certs(&[MS_2011_DER]), &dbx, d.path()),
        ShimVerdict::Chains {
            cert_sha256: MS_UEFI_CA_2011_SHA256
        }
    );
    // A signature that is not readable PKCS#7: cannot tell when dbx has X509_SHA* entries
    let bad = d.path().join("bad.efi");
    fs::write(&bad, pe_with_signatures(&[&fake_sig(0x11, 40)])).unwrap();
    let v = shim_chains(
        &FakeRunner::new(),
        &bad,
        &certs(&[MS_2011_DER]),
        &dbx,
        d.path(),
    );
    assert!(matches!(v, ShimVerdict::CantCheck(_)), "{v:?}");
    // Through shim-check: X509_SHA384 in the dbx variable -> exit 1, the output carries the revoked marker
    let s = sysfs_with_dbx(None);
    let h = Sha384::digest(t).to_vec();
    fs::write(s.path().join(DBX_VAR), var(&[tbs_signature_list(&[&h])])).unwrap();
    let mut out = Vec::new();
    assert_eq!(
        shim_check(&FakeRunner::new(), s.path(), &shim, s.path(), &mut out),
        1
    );
    assert!(String::from_utf8(out).unwrap().contains(REVOKED_MARK));
}

/// firmware/efi stat fails (not "does not exist") -> cannot tell, never a legacy boot (review N2). root can read a 000 directory, so skipped there.
#[test]
fn efi_dir_unreadable_is_unknown() {
    use std::os::unix::fs::PermissionsExt;
    if rustix::process::geteuid().is_root() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let fw = d.path().join("firmware");
    fs::create_dir_all(fw.join("efi/efivars")).unwrap();
    fs::set_permissions(&fw, fs::Permissions::from_mode(0o000)).unwrap();
    let got = secure_boot_state(d.path());
    fs::set_permissions(&fw, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(got, SecureBootState::Unknown(_)), "{got:?}");
}

/// The panel text is chosen by the reason: revoked -> use a newer image, no Reset All Keys; does not chain (exit 1) -> Reset All Keys; exit 2 -> cannot check.
#[test]
fn shim_ca_item_text_by_reason() {
    let d = tempfile::tempdir().unwrap();
    let write = |exit: u8, reason: &str| {
        fs::write(
            d.path().join(SHIM_CA_STATUS),
            format!(
                r#"{{"ok":false,"exit":{exit},"image_version":"20261017.20","reason":"{reason}"}}"#
            ),
        )
        .unwrap();
        shim_ca_item(d.path()).detail.unwrap()
    };
    let t = write(
        1,
        "/usr/lib/mastersos/esp/BOOTX64.EFI is revoked by this machine's dbx: the image's Authenticode hash ... is in dbx",
    );
    assert!(t.contains(REVOKED_ADVICE), "{t}");
    assert!(!t.contains("Reset All Keys"), "{t}");
    let t = write(
        1,
        "/usr/lib/mastersos/esp/BOOTX64.EFI does not chain to any certificate in the active db (1 in total)",
    );
    assert!(t.contains("Reset All Keys"), "{t}");
    // A status file written by an older image carries the old Chinese revoked marker: still no Reset All Keys
    let t = write(
        1,
        "x \u{88ab}\u{672c}\u{673a}\u{7684} dbx \u{540a}\u{9500}: y",
    );
    assert!(
        t.contains(REVOKED_ADVICE) && !t.contains("Reset All Keys"),
        "{t}"
    );
    let t = write(2, "cannot tell: dbx cannot be parsed");
    assert!(
        t.contains("cannot check") && !t.contains("Reset All Keys"),
        "{t}"
    );
}

fn sysfs_with_mok(mok: Option<&[u8]>) -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    fs::create_dir_all(d.path().join("firmware/efi/efivars")).unwrap();
    if let Some(m) = mok {
        fs::write(d.path().join(MOK_LIST_VAR), m).unwrap();
    }
    d
}

#[test]
fn read_mok_list_absent_is_empty() {
    let d = sysfs_with_mok(None);
    assert_eq!(read_mok_list(d.path()), Ok(vec![]));
}

#[test]
fn read_mok_list_parses_two_certs() {
    let a = fake_sig(1, 40);
    let b = fake_sig(2, 50);
    let d = sysfs_with_mok(Some(&var(&[
        x509_signature_list(&[&a]),
        x509_signature_list(&[&b]),
    ])));
    let c = read_mok_list(d.path()).unwrap();
    assert_eq!(c.len(), 2);
    assert_eq!(c[0].sha256, sha(&a));
    assert_eq!(c[1].sha256, sha(&b));
}

#[test]
fn read_mok_list_truncated_is_err() {
    let d = sysfs_with_mok(Some(&[0x27, 0, 0, 0, 1, 2, 3]));
    assert!(read_mok_list(d.path()).is_err());
}

#[test]
fn untrusted_mok_constants_match_files() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../image/mkosi.extra/usr/share/mastersos/untrusted-mok");
    assert_eq!(UNTRUSTED_MOK_SHA256.len(), UNTRUSTED_MOK_FILES.len());
    for ((want, _), stem) in UNTRUSTED_MOK_SHA256.iter().zip(UNTRUSTED_MOK_FILES) {
        let der = fs::read(dir.join(format!("{stem}.der"))).unwrap();
        assert_eq!(&sha(&der), want, "{stem}.der");
    }
}
