//! The device's requests against the server team's wire table ("Device side" of
//! `docs/plans/2026-11-21-protocol-v1-wire-table.md`): each test captures the bytes the agent
//! really sends and decodes them from the table's definitions, never through the agent's types.

use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use mastersos_agent::fetch::{DeviceCred, RenewOutcome};
use mastersos_agent::luks::{escrow_request, parse_luks_dump, SealedKey};
use mastersos_agent::protocol_check::{run_check, CheckInput};
use mastersos_agent::{seedpart, token, FetchOutcome, Fetcher};
use mastersos_bundle::kit::Kit;
use mastersos_bundle::{
    accept_for_school, pack, Contents, Ed25519Signer, GroupSource, Heartbeat, Seed, StatusReport,
    TrustKey,
};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const SCHOOL: &str = "0b6c1a52-3d1e-4f7a-9c2b-1a2b3c4d5e6f";
const LUKS_UUID_UPPER: &str = "F9FD9985-7280-4C3D-BAB4-F132AC2336F2";
const LUKS_UUID: &str = "f9fd9985-7280-4c3d-bab4-f132ac2336f2";
const ARMOR_BEGIN: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
const ARMOR_END: &str = "-----END AGE ENCRYPTED FILE-----";
const ESCROW_KEYS: [&str; 6] = [
    "device_id",
    "escrow_secret",
    "luks_uuid",
    "recipients_fp",
    "recovery_key_age",
    "serial",
];

/// A token shaped like the ones the server mints: 32 random bytes, url-nopad.
fn server_token() -> String {
    let mut raw = [0u8; 32];
    SystemRandom::new().fill(&mut raw).unwrap();
    URL_SAFE_NO_PAD.encode(raw)
}

/// A throwaway recovery key: 8 groups of 8 random modhex characters.
fn recovery_key() -> String {
    const MODHEX: &[u8] = b"cbdefghijklnrtuv";
    let mut raw = [0u8; 64];
    SystemRandom::new().fill(&mut raw).unwrap();
    let chars: Vec<char> = raw
        .iter()
        .map(|b| MODHEX[usize::from(b & 0x0f)] as char)
        .collect();
    chars
        .chunks(8)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

fn seed(url: &str, token: &str, trust: Vec<TrustKey>, min_version: Option<u64>) -> Seed {
    Seed {
        server_url: url.into(),
        trust,
        fetch_token: Some(token.into()),
        group: None,
        oidc: None,
        min_version,
        school_id: Some(SCHOOL.into()),
        wifi: vec![],
        school_name: None,
        it_account: None,
    }
}

fn manifest(version: &str, trust: &[TrustKey], recipients: &[String]) -> String {
    let mut text = format!("version = {version}\n\n[school]\nid = \"{SCHOOL}\"\n");
    if !recipients.is_empty() {
        let list: Vec<String> = recipients.iter().map(|r| format!("\"{r}\"")).collect();
        text += &format!("escrow_recipients = [{}]\n", list.join(", "));
    }
    for k in trust {
        text += &format!(
            "\n[[trust]]\nid = \"{}\"\nalg = \"{}\"\npublic_key = \"{}\"\n",
            k.id,
            k.alg.as_str(),
            k.public_key
        );
    }
    text += "\n[[group]]\nid = \"default\"\nname = \"x\"\n";
    text
}

fn archive(
    version: &str,
    trust: &[TrustKey],
    recipients: &[String],
    by: &Ed25519Signer,
) -> Vec<u8> {
    let c = Contents {
        manifest_text: manifest(version, trust, recipients),
        files: Default::default(),
    };
    pack(&c, by).unwrap()
}

fn status_report(device_id: &str, bundle_version: Option<u64>) -> StatusReport {
    StatusReport {
        device_id: device_id.into(),
        serial: None,
        model: None,
        os_version: None,
        agent_version: "0.1.0".into(),
        bundle_version,
        group: "default".into(),
        group_source: GroupSource::Default,
        locked: false,
        stale: false,
        last_fetch_ok: None,
        results: vec![],
        fresh_until: None,
        newer_withheld: None,
        seed_trust_fingerprints: vec![],
        imported_from_seed_at: None,
        manifest_features: vec![],
        os_pending_version: None,
        quiet_since: None,
        user_config: None,
    }
}

/// The table's url-nopad, strictly: the URL-safe alphabet only (no `=`, `+`, `/` or
/// whitespace), canonical, decoding to exactly 32 bytes.
fn assert_url_nopad_32(s: &str, what: &str) {
    assert_eq!(s.len(), 43, "{what}: 32 bytes url-nopad are 43 characters");
    assert!(
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "{what}: only the URL-safe alphabet, no padding or whitespace"
    );
    let raw = URL_SAFE_NO_PAD.decode(s).expect(what);
    assert_eq!(raw.len(), 32, "{what}");
    assert_eq!(URL_SAFE_NO_PAD.encode(&raw), s, "{what}: canonical");
}

/// The table's lowercase 8-4-4-4-12.
fn is_lower_uuid(s: &str) -> bool {
    let g: Vec<&str> = s.split('-').collect();
    g.len() == 5
        && g.iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && g.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// `recipients_fp` from the table's definition: sha256 hex (lowercase) of
/// `"mastersos-escrow-recipients-v1\n"` + the recipients sorted bytewise, deduplicated, joined
/// with `"\n"`.
fn table_fp(recipients: &[String]) -> String {
    let mut v: Vec<&[u8]> = recipients.iter().map(|r| r.as_bytes()).collect();
    v.sort();
    v.dedup();
    let mut msg = b"mastersos-escrow-recipients-v1\n".to_vec();
    msg.extend_from_slice(&v.join(&b"\n"[..]));
    Sha256::digest(&msg)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn one<'a>(reqs: &'a [Request], p: &str) -> &'a Request {
    let found: Vec<&Request> = reqs.iter().filter(|r| r.url.path() == p).collect();
    assert_eq!(found.len(), 1, "requests to {p}");
    found[0]
}

fn header_bytes<'a>(r: &'a Request, name: &str) -> &'a [u8] {
    let all: Vec<_> = r.headers.get_all(name).iter().collect();
    assert_eq!(all.len(), 1, "exactly one {name} header");
    all[0].as_bytes()
}

/// `Authorization: Bearer <token>`, the token printable ASCII 0x21-0x7e, 1-256 bytes.
fn assert_bearer(r: &Request, want: &str) {
    let v = header_bytes(r, "authorization");
    let t = v.strip_prefix(b"Bearer ").expect("Bearer scheme");
    assert!((1..=256).contains(&t.len()), "token length");
    assert!(t.iter().all(|b| (0x21..=0x7e).contains(b)), "token bytes");
    assert_eq!(t, want.as_bytes());
}

/// An identity as the agent creates it, and the token it would use, from a seed in `dir`.
fn device(dir: &Path, s: &Seed) -> (seedpart::Identity, Option<String>) {
    let (part, state) = (dir.join("seed-partition"), dir.join("state"));
    std::fs::create_dir(&part).unwrap();
    std::fs::create_dir(&state).unwrap();
    let id = seedpart::load_or_create_identity(&part, None).unwrap();
    (id, token::effective(&state, &part, s))
}

#[tokio::test]
async fn status_device_headers_match_the_wire_table() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/device/v1/status"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&srv)
        .await;
    let tok = server_token();
    let s = seed(&srv.uri(), &tok, vec![], None);
    let tmp = tempfile::tempdir().unwrap();
    let (id, used) = device(tmp.path(), &s);
    let f = Fetcher::new(&s, used);
    let cred = DeviceCred {
        device_id: id.device_id.clone(),
        secret: id.escrow_secret.clone(),
    };
    f.report(&status_report(&id.device_id, Some(1)), &cred, true)
        .await
        .unwrap();

    let reqs = srv.received_requests().await.unwrap();
    let r = one(&reqs, "/api/device/v1/status");
    assert_bearer(r, &tok);
    let secret = std::str::from_utf8(header_bytes(r, "x-mastersos-device-secret")).unwrap();
    assert_url_nopad_32(secret, "X-Mastersos-Device-Secret");
    assert_eq!(secret, id.escrow_secret);
    let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    let device_id = body["device_id"].as_str().unwrap();
    assert_eq!(
        header_bytes(r, "x-mastersos-device"),
        device_id.as_bytes(),
        "X-Mastersos-Device equals the body's device_id byte for byte"
    );
}

#[tokio::test]
async fn status_bundle_version_fits_i64() {
    let (signer, trust) = {
        let k = Kit::generate();
        (k.signer(), vec![k.trust_key()])
    };
    // A verified manifest's version comes from TOML, whose integers are i64: the agent's
    // verification cannot yield a larger one.
    for over in [(i64::MAX as u64 + 1).to_string(), u64::MAX.to_string()] {
        let a = archive(&over, &trust, &[], &signer);
        assert!(
            accept_for_school(&a, &trust, None, Some(SCHOOL)).is_err(),
            "version {over} accepted"
        );
    }
    // Nor can a heartbeat (the source of `newer_withheld`).
    let hb = |v: &str| {
        format!(
            "[statement]\nversion = {v}\ndigest_hex = \"{}\"\nissued_at = 0\nnot_after = 1\n\n\
             [signature]\nkey_id = \"rk-1\"\nalg = \"ed25519\"\nsig = \"AA==\"\n",
            "0".repeat(64)
        )
    };
    assert!(Heartbeat::parse(&hb(&i64::MAX.to_string())).is_ok());
    assert!(Heartbeat::parse(&hb(&(i64::MAX as u64 + 1).to_string())).is_err());

    // The largest version a manifest can carry goes out as a JSON integer <= i64::MAX.
    let a = archive(&i64::MAX.to_string(), &trust, &[], &signer);
    let b = accept_for_school(&a, &trust, None, Some(SCHOOL)).unwrap();
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/device/v1/status"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), &server_token(), vec![], None));
    let cred = DeviceCred {
        device_id: "dev-1".into(),
        secret: server_token(),
    };
    let r = status_report("dev-1", Some(b.manifest.version));
    f.report(&r, &cred, true).await.unwrap();
    let reqs = srv.received_requests().await.unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&one(&reqs, "/api/device/v1/status").body).unwrap();
    let v = &body["bundle_version"];
    assert!(v.is_u64(), "a JSON integer: {v}");
    assert_eq!(v.as_i64(), Some(i64::MAX));
}

/// The escrow body as the table defines it; `recipients` is the list the key was sealed to.
fn check_escrow_body(body: &[u8], recipients: &[String], secret: &str, serial: Option<&str>) {
    let v: serde_json::Value = serde_json::from_slice(body).unwrap();
    let obj = v.as_object().expect("a JSON object");
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ESCROW_KEYS, "exactly the six keys");

    let device_id = obj["device_id"].as_str().unwrap();
    assert!((1..=128).contains(&device_id.len()));
    assert!(!device_id.chars().any(char::is_control));
    match serial {
        Some(s) => assert_eq!(obj["serial"], s),
        None => assert!(obj["serial"].is_null(), "serial is present and null"),
    }
    assert_eq!(obj["luks_uuid"], LUKS_UUID);
    assert!(is_lower_uuid(obj["luks_uuid"].as_str().unwrap()));

    let armor = obj["recovery_key_age"].as_str().expect("a JSON string");
    assert!(armor.starts_with(ARMOR_BEGIN), "the armor text itself");
    assert!(armor.trim_end().ends_with(ARMOR_END));
    assert!(armor.len() <= 2048, "{} bytes", armor.len());
    for line in armor.lines() {
        assert!(line.len() <= 64, "line of {} columns", line.len());
    }
    // Sealed to each distinct recipient.
    let distinct = {
        let mut d = recipients.to_vec();
        d.sort();
        d.dedup();
        d.len()
    };
    assert_eq!(mastersos_bundle::x25519_stanza_count(armor), Some(distinct));

    let fp = obj["recipients_fp"].as_str().unwrap();
    assert_eq!(fp, table_fp(recipients));
    assert!(fp.len() == 64 && fp.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));

    let s = obj["escrow_secret"].as_str().unwrap();
    assert_url_nopad_32(s, "escrow_secret");
    assert_eq!(s, secret);
}

/// Three recipients, listed in descending order (so not sorted).
fn unsorted_recipients() -> Vec<String> {
    let mut r: Vec<String> = (0..3).map(|_| Kit::generate().escrow_recipient()).collect();
    r.sort();
    r.reverse();
    r
}

#[tokio::test]
async fn escrow_body_matches_the_wire_table() {
    let recipients = unsorted_recipients();
    let trust_kit = Kit::generate();

    // The fingerprint's dedup: the agent seals only to a list without repeats (the bundle
    // checks refuse one), so the duplicate is fed to the fingerprint function it uses.
    let dup = vec![
        recipients[1].clone(),
        recipients[0].clone(),
        recipients[1].clone(),
        recipients[2].clone(),
    ];
    assert_eq!(mastersos_bundle::recipients_fp(&dup), table_fp(&dup));
    assert_eq!(table_fp(&dup), table_fp(&recipients));

    // The LUKS job: the UUID read from the disk in capitals, the shared builder, Fetcher::escrow.
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/device/v1/escrow"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&srv)
        .await;
    let tok = server_token();
    let s = seed(&srv.uri(), &tok, vec![trust_kit.trust_key()], None);
    let tmp = tempfile::tempdir().unwrap();
    let (id, used) = device(tmp.path(), &s);
    let info = parse_luks_dump(r#"{"tokens":{},"keyslots":{}}"#, LUKS_UUID_UPPER, None).unwrap();
    let sealed = SealedKey::seal(&recovery_key(), &recipients).unwrap();
    let f = Fetcher::new(&s, used);
    for serial in [Some("SN-0042"), None] {
        let req = escrow_request(
            &id.device_id,
            serial.map(str::to_string),
            &info.uuid,
            &sealed,
            &id.escrow_secret,
        )
        .unwrap();
        f.escrow(&req, true).await.unwrap();
    }
    let reqs = srv.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 2);
    for (r, serial) in reqs.iter().zip([Some("SN-0042"), None]) {
        assert_bearer(r, &tok);
        check_escrow_body(&r.body, &recipients, &id.escrow_secret, serial);
    }

    // protocol-check with `--luks-uuid` in capitals.
    let srv = MockServer::start().await;
    let signer = trust_kit.signer();
    let v3 = archive("3", &[trust_kit.trust_key()], &recipients, &signer);
    Mock::given(method("GET"))
        .and(path("/api/device/v1/bundle"))
        .and(query_param("after", "2"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Mastersos-Version", "3")
                .set_body_bytes(v3),
        )
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/device/v1/bundle"))
        .and(query_param("after", "3"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/device/v1/heartbeat"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&srv)
        .await;
    for route in ["status", "escrow"] {
        Mock::given(method("POST"))
            .and(path(format!("/api/device/v1/{route}")))
            .respond_with(ResponseTemplate::new(204))
            .mount(&srv)
            .await;
    }
    let tmp = tempfile::tempdir().unwrap();
    let files = tmp.path().join("in");
    std::fs::create_dir(&files).unwrap();
    let s = seed(&srv.uri(), &tok, vec![trust_kit.trust_key()], Some(3));
    std::fs::write(files.join("seed.toml"), s.to_toml()).unwrap();
    std::fs::write(files.join("recovery-key"), format!("{}\n", recovery_key())).unwrap();
    let input = CheckInput {
        seed: files.join("seed.toml"),
        dir: tmp.path().join("dir"),
        recovery_key: Some(files.join("recovery-key")),
        luks_uuid: Some(LUKS_UUID_UPPER.into()),
    };
    let report = run_check(&input, Utc::now()).await;
    assert!(report.ok, "{report:#?}");
    let reqs = srv.received_requests().await.unwrap();
    let r = one(&reqs, "/api/device/v1/escrow");
    assert_bearer(r, &tok);
    let secret = {
        let id: serde_json::Value = serde_json::from_slice(
            &std::fs::read(input.dir.join("seed-partition").join("identity.json")).unwrap(),
        )
        .unwrap();
        id["escrow_secret"].as_str().unwrap().to_string()
    };
    check_escrow_body(&r.body, &recipients, &secret, None);
}

#[tokio::test]
async fn fetch_token_request_matches_the_wire_table() {
    let srv = MockServer::start().await;
    let new = server_token();
    Mock::given(method("POST"))
        .and(path("/api/device/v1/fetch-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "fetch_token": new, "expires_hint": 7 })),
        )
        .mount(&srv)
        .await;
    let tok = server_token();
    let s = seed(&srv.uri(), &tok, vec![], None);
    let tmp = tempfile::tempdir().unwrap();
    let (id, used) = device(tmp.path(), &s);
    let f = Fetcher::new(&s, used);
    match f.renew_token(&id, true).await.unwrap() {
        RenewOutcome::New(t) => assert_eq!(t, new),
        other => panic!("{other:?}"),
    }
    let reqs = srv.received_requests().await.unwrap();
    let r = one(&reqs, "/api/device/v1/fetch-token");
    assert_bearer(r, &tok);
    let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    let obj = v.as_object().unwrap();
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["device_id", "escrow_secret"]);
    assert_eq!(obj["device_id"], id.device_id.as_str());
    let secret = obj["escrow_secret"].as_str().unwrap();
    assert_url_nopad_32(secret, "escrow_secret");
    assert_eq!(secret, id.escrow_secret);
}

#[tokio::test]
async fn bundle_and_stale_headers_match_the_wire_table() {
    let srv = MockServer::start().await;
    let bundle = |after: u64, version: &str| {
        Mock::given(method("GET"))
            .and(path("/api/device/v1/bundle"))
            .and(query_param("after", after.to_string()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("x-mastersos-version", version)
                    .insert_header("content-type", "application/gzip")
                    .insert_header("x-mastersos-fetch-token", "stale")
                    .set_body_bytes(b"gz".to_vec()),
            )
    };
    bundle(1, "7").mount(&srv).await;
    // Only the exact bytes `stale` mark the token: another case is no marker (and clears it).
    for (after, marker) in [(4, "STALE"), (5, "Stale"), (6, "stale-")] {
        Mock::given(method("GET"))
            .and(path("/api/device/v1/bundle"))
            .and(query_param("after", after.to_string()))
            .respond_with(
                ResponseTemplate::new(204).insert_header("x-mastersos-fetch-token", marker),
            )
            .mount(&srv)
            .await;
    }
    bundle(2, "18446744073709551615").mount(&srv).await;
    Mock::given(method("GET"))
        .and(path("/api/device/v1/bundle"))
        .and(query_param("after", "3"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&srv)
        .await;
    let refused = [
        "+7",
        "-1",
        "0x10",
        "7.0",
        "1e3",
        "",
        "abc",
        "18446744073709551616",
    ];
    for (i, v) in refused.iter().enumerate() {
        bundle(100 + i as u64, v).mount(&srv).await;
    }
    let f = Fetcher::from_seed(&seed(&srv.uri(), &server_token(), vec![], None));

    let got = f.fetch_now(1).await.unwrap();
    assert_eq!(
        got,
        FetchOutcome::New {
            archive: b"gz".to_vec(),
            version: 7
        }
    );
    assert!(f.token_is_stale(), "the literal `stale` marks the token");
    assert_eq!(f.fetch_now(3).await.unwrap(), FetchOutcome::NoChange);
    assert!(
        !f.token_is_stale(),
        "an answer without the marker clears it"
    );
    for after in [4, 5, 6] {
        f.fetch_now(1).await.unwrap();
        assert!(f.token_is_stale());
        assert_eq!(f.fetch_now(after).await.unwrap(), FetchOutcome::NoChange);
        assert!(
            !f.token_is_stale(),
            "only the literal `stale` marks the token"
        );
    }
    match f.fetch_now(2).await.unwrap() {
        FetchOutcome::New { version, .. } => assert_eq!(version, u64::MAX),
        other => panic!("{other:?}"),
    }
    for (i, v) in refused.iter().enumerate() {
        assert!(
            f.fetch_now(100 + i as u64).await.is_err(),
            "X-Mastersos-Version {v:?} accepted"
        );
    }
}
