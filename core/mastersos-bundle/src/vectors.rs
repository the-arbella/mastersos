//! The shared vector files of protocol §8 (`testdata/{digest,heartbeat,escrow,kit}-vectors.json`)
//! and the wire vectors (`testdata/wire-vectors.json`): how each file is built and checked. The
//! server team copies these files byte for byte into its tests. This crate's tests and the
//! integration test that loads the files by their protocol names share these checks.
//!
//! Every value here is a fixed, public test value. Never use one for a school.

use std::collections::BTreeMap;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::frame::{frame_of, Frame, FrameKey};
use crate::kit::{derive, recipient_binding_message, Kit, INFO_SIGN};
use crate::{
    content_digest, heartbeat_message, is_escrow_secret, is_luks_uuid, is_sealed, keyid,
    recipients_fp, seal, signed_message, trust_fingerprint, verify_heartbeat, verify_signature,
    Contents, FetchTokenRequest, Heartbeat, HeartbeatStatement, KeyAlg, SignatureFile, Signer as _,
    TrustKey,
};

/// `MASTERSOS_REGEN_VECTORS=1` makes the vector tests rewrite their files instead of comparing.
pub fn regen() -> bool {
    std::env::var_os("MASTERSOS_REGEN_VECTORS").is_some_and(|v| v == "1")
}

/// The pretty JSON text of a vector file: 2-space indent, fields in declaration order, trailing
/// newline.
pub fn file_text<T: Serialize>(v: &T) -> String {
    serde_json::to_string_pretty(v).expect("vector files serialize") + "\n"
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect();
    v.try_into().expect("32 bytes")
}

fn counting() -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = i as u8;
    }
    b
}

/// The test-only kit masters of `kit-vectors.json`, by name.
const KIT_MASTERS: [(&str, &str); 3] = [
    (
        "test-only-zero",
        "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "test-only-counting",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ),
    (
        "test-only-ff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
];

fn test_kit(name: &str) -> Kit {
    let (_, m) = KIT_MASTERS
        .iter()
        .find(|(n, _)| *n == name)
        .expect("a kit of kit-vectors.json");
    Kit::from_master(&unhex32(m))
}

fn content_hex(c: &Contents) -> String {
    hex(&content_digest(c))
}

// ---------------------------------------------------------------------------------------------
// digest-vectors.json

#[derive(Deserialize)]
struct DigestVector {
    name: String,
    manifest_text: String,
    files: BTreeMap<String, String>,
    digest_hex: String,
}

/// Recomputes every vector of `digest-vectors.json`; returns how many there are.
pub fn check_digest_vectors(text: &str) -> usize {
    let vs: Vec<DigestVector> = serde_json::from_str(text).expect("digest-vectors.json parses");
    for v in &vs {
        let files = v
            .files
            .iter()
            .map(|(p, b)| (p.clone(), STANDARD.decode(b).expect("std-pad file bytes")))
            .collect();
        let c = Contents {
            manifest_text: v.manifest_text.clone(),
            files,
        };
        assert_eq!(content_hex(&c), v.digest_hex, "{}", v.name);
    }
    vs.len()
}

// ---------------------------------------------------------------------------------------------
// heartbeat-vectors.json

#[derive(Deserialize)]
struct HeartbeatVector {
    name: String,
    statement: HeartbeatStatement,
    message_b64: String,
}

/// Checks and re-encodes every statement of `heartbeat-vectors.json`; returns how many there are.
pub fn check_heartbeat_vectors(text: &str) -> usize {
    let vs: Vec<HeartbeatVector> =
        serde_json::from_str(text).expect("heartbeat-vectors.json parses");
    for v in &vs {
        v.statement.check().unwrap();
        assert_eq!(
            STANDARD.encode(heartbeat_message(&v.statement)),
            v.message_b64,
            "{}",
            v.name
        );
    }
    vs.len()
}

// ---------------------------------------------------------------------------------------------
// kit-vectors.json

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct KitVector {
    pub name: String,
    pub master_hex: String,
    pub text: String,
    pub display: String,
    pub ed25519_seed_hex: String,
    pub key_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub escrow_identity: String,
    pub escrow_recipient: String,
    pub binding_nonce_b64: String,
    pub binding_message_b64: String,
    pub binding_sig_b64: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct KitVectorFile {
    pub note: String,
    pub vectors: Vec<KitVector>,
}

fn kit_vector(name: &str, master: [u8; 32]) -> KitVector {
    use age::secrecy::ExposeSecret as _;
    let k = Kit::from_master(&master);
    let tk = k.trust_key();
    let nonce = [0x5au8; 32];
    let recipient = k.escrow_recipient();
    let msg = recipient_binding_message(&recipient, &nonce);
    KitVector {
        name: name.into(),
        master_hex: hex(&master),
        text: k.to_text().to_string(),
        display: k.to_display().to_string(),
        ed25519_seed_hex: hex(&derive(&master, INFO_SIGN)[..]),
        key_id: k.key_id(),
        fingerprint: trust_fingerprint(&tk),
        public_key: tk.public_key,
        escrow_identity: k.escrow_identity().to_string().expose_secret().to_owned(),
        escrow_recipient: recipient,
        binding_nonce_b64: STANDARD.encode(nonce),
        binding_sig_b64: STANDARD.encode(k.signer().sign(&msg)),
        binding_message_b64: STANDARD.encode(msg),
    }
}

/// `kit-vectors.json` as this crate computes it.
pub fn kit_vectors() -> KitVectorFile {
    KitVectorFile {
        note: "TEST-ONLY masters: fixed, public values. Never use these kits for a school.".into(),
        vectors: KIT_MASTERS
            .iter()
            .map(|(n, m)| kit_vector(n, unhex32(m)))
            .collect(),
    }
}

/// Compares `kit-vectors.json` with [`kit_vectors`] and parses each stored kit text back;
/// returns how many vectors there are.
pub fn check_kit_vectors(text: &str) -> usize {
    let stored: KitVectorFile = serde_json::from_str(text).expect("kit-vectors.json parses");
    assert_eq!(stored, kit_vectors());
    for v in &stored.vectors {
        // Parsing the stored text gives the same master back.
        let k = Kit::parse(&v.text).unwrap();
        assert_eq!(hex(&k.master_bytes()[..]), v.master_hex);
        assert!(v.escrow_identity.starts_with("AGE-SECRET-KEY-1"));
        assert!(v.escrow_recipient.starts_with("age1"));
    }
    stored.vectors.len()
}

// ---------------------------------------------------------------------------------------------
// escrow-vectors.json

/// The made-up recovery key sealed in `escrow-vectors.json`.
pub const ESCROW_VECTOR_KEY: &str =
    "cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv";

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EscrowVector {
    pub note: String,
    pub kit_masters_hex: Vec<String>,
    pub recipients: Vec<String>,
    pub recipients_fp: String,
    pub recovery_key: String,
    pub recovery_key_age: String,
}

fn escrow_kits() -> Vec<Kit> {
    ["test-only-zero", "test-only-counting"]
        .iter()
        .map(|n| test_kit(n))
        .collect()
}

/// A fresh `escrow-vectors.json` (age encryption is randomised: a new ciphertext each time).
pub fn fresh_escrow_vector() -> EscrowVector {
    let kits = escrow_kits();
    let recipients: Vec<String> = kits.iter().map(Kit::escrow_recipient).collect();
    EscrowVector {
        note: "TEST-ONLY: the kits are the fixed, public test masters of kit-vectors.json \
               and the recovery key is made up. Never use them for a school."
            .into(),
        kit_masters_hex: kits.iter().map(|k| hex(&k.master_bytes()[..])).collect(),
        recipients_fp: recipients_fp(&recipients),
        recovery_key_age: seal(ESCROW_VECTOR_KEY, &recipients).unwrap(),
        recipients,
        recovery_key: ESCROW_VECTOR_KEY.into(),
    }
}

/// Checks `escrow-vectors.json`: the recipients and their fingerprint recomputed from the kits,
/// and the ciphertext opened by every kit; returns 1 (the file holds one vector).
pub fn check_escrow_vectors(text: &str) -> usize {
    let v: EscrowVector = serde_json::from_str(text).expect("escrow-vectors.json parses");
    let kits = escrow_kits();
    let recipients: Vec<String> = kits.iter().map(Kit::escrow_recipient).collect();
    assert!(v.note.starts_with("TEST-ONLY"));
    let masters: Vec<String> = kits.iter().map(|k| hex(&k.master_bytes()[..])).collect();
    assert_eq!(v.kit_masters_hex, masters);
    assert_eq!(v.recipients, recipients);
    assert_eq!(v.recipients_fp, recipients_fp(&recipients));
    let mut reversed = recipients.clone();
    reversed.reverse();
    assert_eq!(v.recipients_fp, recipients_fp(&reversed));
    assert!(is_sealed(&v.recovery_key_age));
    for k in &kits {
        let opened = age::decrypt(&k.escrow_identity(), v.recovery_key_age.as_bytes()).unwrap();
        assert_eq!(opened, v.recovery_key.as_bytes());
    }
    1
}

// ---------------------------------------------------------------------------------------------
// wire-vectors.json

/// A device secret (`X-Mastersos-Device-Secret`) or an `escrow_secret`: url-nopad of 32 bytes.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SecretVector {
    pub name: String,
    pub field: String,
    pub bytes_hex: String,
    pub encoded: String,
}

/// A fetch token. `minted_from_hex`: the 32 random bytes a server-minted token encodes
/// (url-nopad); absent for other valid shapes.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenVector {
    pub name: String,
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minted_from_hex: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct NamedValue {
    pub name: String,
    pub value: String,
}

/// `POST keys/probe` and the registration's signature over its message.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbeVector {
    pub name: String,
    pub kit: String,
    pub key_id: String,
    pub public_key: String,
    pub nonce_hex: String,
    pub nonce_b64: String,
    pub message_b64: String,
    pub sig_b64: String,
}

/// `POST escrow-recipients`: the recipient bound to a school key.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct BindingVector {
    pub name: String,
    pub kit: String,
    pub key_id: String,
    pub public_key: String,
    pub recipient: String,
    pub nonce_b64: String,
    pub message_b64: String,
    pub sig_b64: String,
}

/// The archive's `signature` member as wire text, over `"mastersos-bundle-v1\n" || digest`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct BundleSignatureVector {
    pub name: String,
    pub kit: String,
    pub public_key: String,
    pub digest_hex: String,
    pub message_b64: String,
    pub signature_toml: String,
}

/// A heartbeat as wire text (`[statement]` and `[signature]`).
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct HeartbeatWireVector {
    pub name: String,
    pub kit: String,
    pub public_key: String,
    pub statement: HeartbeatStatement,
    pub message_b64: String,
    pub heartbeat_toml: String,
}

/// `seed_trust_fingerprints` of a seed's trust keys, in trust order.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct FingerprintVector {
    pub name: String,
    pub trust: Vec<FrameKey>,
    pub fingerprints: Vec<String>,
}

/// `POST publish/pending` for a stamped settings text without files: the frame, the digest, the
/// pending answer's `message_b64`, and the `signature` member the commit's archive carries.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct PublishVector {
    pub name: String,
    pub kit: String,
    pub manifest_text: String,
    pub frame: Frame,
    pub digest_hex: String,
    pub message_b64: String,
    pub signature_toml: String,
}

/// A value a reader must refuse: `field` names the field, `rule` the rule it breaks.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct InvalidVector {
    pub name: String,
    pub field: String,
    pub value: String,
    pub valid: bool,
    pub rule: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct WireVectors {
    pub about: String,
    pub note: String,
    pub secrets: Vec<SecretVector>,
    pub fetch_tokens: Vec<TokenVector>,
    pub luks_uuids: Vec<NamedValue>,
    pub key_probes: Vec<ProbeVector>,
    pub recipient_bindings: Vec<BindingVector>,
    pub bundle_signatures: Vec<BundleSignatureVector>,
    pub heartbeats: Vec<HeartbeatWireVector>,
    pub seed_trust_fingerprints: Vec<FingerprintVector>,
    pub publish: Vec<PublishVector>,
    pub invalid: Vec<InvalidVector>,
}

/// The `field` names [`InvalidVector`] uses.
pub const INVALID_FIELDS: [&str; 6] = [
    "secret",
    "fetch_token",
    "luks_uuid",
    "nonce_b64",
    "sig",
    "digest_hex",
];

const SCHOOL_ID: &str = "0192f3a4-5b6c-7d8e-9f00-112233445566";
const LUKS_UUID: &str = "0b9e3c1a-5d2f-4e6a-9c1b-2f3e4d5c6b7a";

/// Bytes whose url-nopad encoding has both `-` and `_` (and whose std encoding has `+` and `/`).
fn dash_underscore_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = [0xfb, 0xff, 0xbf][i % 3];
    }
    b
}

fn secret(name: &str, field: &str, bytes: &[u8]) -> SecretVector {
    SecretVector {
        name: name.into(),
        field: field.into(),
        bytes_hex: hex(bytes),
        encoded: URL_SAFE_NO_PAD.encode(bytes),
    }
}

fn probe(name: &str, kit: &str, nonce: [u8; 32]) -> ProbeVector {
    let k = test_kit(kit);
    let msg = keyid::keyprobe_message(&nonce);
    ProbeVector {
        name: name.into(),
        kit: kit.into(),
        key_id: k.key_id(),
        public_key: k.trust_key().public_key,
        nonce_hex: hex(&nonce),
        nonce_b64: STANDARD.encode(nonce),
        message_b64: STANDARD.encode(&msg),
        sig_b64: STANDARD.encode(k.signer().sign(&msg)),
    }
}

fn binding(name: &str, kit: &str, nonce: [u8; 32]) -> BindingVector {
    let k = test_kit(kit);
    let recipient = k.escrow_recipient();
    let msg = recipient_binding_message(&recipient, &nonce);
    BindingVector {
        name: name.into(),
        kit: kit.into(),
        key_id: k.key_id(),
        public_key: k.trust_key().public_key,
        recipient,
        nonce_b64: STANDARD.encode(nonce),
        message_b64: STANDARD.encode(&msg),
        sig_b64: STANDARD.encode(k.signer().sign(&msg)),
    }
}

fn ed25519_signature(k: &Kit, msg: &[u8]) -> SignatureFile {
    SignatureFile {
        key_id: k.key_id(),
        alg: KeyAlg::Ed25519,
        sig: STANDARD.encode(k.signer().sign(msg)),
        authenticator_data: None,
        client_data_json: None,
    }
}

fn bundle_signature(name: &str, kit: &str, c: &Contents) -> BundleSignatureVector {
    let k = test_kit(kit);
    let msg = signed_message(c);
    BundleSignatureVector {
        name: name.into(),
        kit: kit.into(),
        public_key: k.trust_key().public_key,
        digest_hex: content_hex(c),
        message_b64: STANDARD.encode(&msg),
        signature_toml: ed25519_signature(&k, &msg).to_toml(),
    }
}

fn heartbeat(name: &str, kit: &str, statement: HeartbeatStatement) -> HeartbeatWireVector {
    let k = test_kit(kit);
    let msg = heartbeat_message(&statement);
    HeartbeatWireVector {
        name: name.into(),
        kit: kit.into(),
        public_key: k.trust_key().public_key,
        message_b64: STANDARD.encode(&msg),
        heartbeat_toml: Heartbeat {
            statement: statement.clone(),
            signature: ed25519_signature(&k, &msg),
        }
        .to_toml(),
        statement,
    }
}

fn frame_key(k: &Kit) -> FrameKey {
    let tk = k.trust_key();
    FrameKey {
        id: tk.id,
        alg: tk.alg.as_str().to_owned(),
        public_key: tk.public_key,
    }
}

/// A stamped settings text of school [`SCHOOL_ID`] trusting `kit`, with the escrow recipients of
/// the two kits of `escrow-vectors.json`.
fn publish_manifest(kit: &Kit) -> String {
    let tk = kit.trust_key();
    let recipients: Vec<String> = escrow_kits()
        .iter()
        .map(|k| format!("\"{}\"", k.escrow_recipient()))
        .collect();
    format!(
        "format = 2\nversion = 7\nissued_at = \"2026-11-21T00:00:00Z\"\n\n\
         [[trust]]\nid = \"{}\"\nalg = \"ed25519\"\npublic_key = \"{}\"\n\n\
         [school]\nid = \"{SCHOOL_ID}\"\nescrow_recipients = [{}]\n\n\
         [[group]]\nid = \"default\"\nname = \"Default\"\n",
        tk.id,
        tk.public_key,
        recipients.join(", ")
    )
}

fn publish(name: &str, kit: &str) -> PublishVector {
    let k = test_kit(kit);
    let manifest_text = publish_manifest(&k);
    let c = Contents {
        manifest_text: manifest_text.clone(),
        files: BTreeMap::new(),
    };
    let msg = signed_message(&c);
    PublishVector {
        name: name.into(),
        kit: kit.into(),
        frame: frame_of(&manifest_text).expect("the publish vector's text has a frame"),
        manifest_text,
        digest_hex: content_hex(&c),
        message_b64: STANDARD.encode(&msg),
        signature_toml: ed25519_signature(&k, &msg).to_toml(),
    }
}

fn invalid(name: &str, field: &str, value: String, rule: &str) -> InvalidVector {
    InvalidVector {
        name: name.into(),
        field: field.into(),
        value,
        valid: false,
        rule: rule.into(),
    }
}

/// Changes the last data character of std-pad text so the encoded value's trailing bits are not
/// zero; a lenient decoder still reads the same bytes.
fn non_canonical(b64: &str) -> String {
    let data = b64.trim_end_matches('=');
    let pad = &b64[data.len()..];
    let last = data.chars().last().expect("not empty");
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let i = alphabet.find(last).expect("std alphabet");
    let bumped = alphabet.as_bytes()[i | 1] as char;
    assert_ne!(bumped, last, "the trailing bits were zero");
    format!("{}{bumped}{pad}", &data[..data.len() - 1])
}

fn with_line_break(b64: &str) -> String {
    format!("{}\n{}", &b64[..b64.len() / 2], &b64[b64.len() / 2..])
}

fn invalid_vectors(
    probe: &ProbeVector,
    hb: &HeartbeatWireVector,
    publish: &PublishVector,
) -> Vec<InvalidVector> {
    let du = dash_underscore_bytes();
    let probe_nonce = unhex32(&probe.nonce_hex);
    let sig = Heartbeat::parse(&hb.heartbeat_toml)
        .expect("the heartbeat vector parses")
        .signature
        .sig;
    let raw_sig = STANDARD.decode(&sig).expect("std-pad");
    let printable: String = (0x21u8..=0x7e).map(char::from).collect();
    vec![
        invalid(
            "secret-url-nopad-with-padding",
            "secret",
            URL_SAFE.encode(du),
            "url-nopad: padding is not allowed",
        ),
        invalid(
            "secret-url-nopad-with-std-alphabet",
            "secret",
            STANDARD_NO_PAD.encode(du),
            "url-nopad: '+' and '/' are not in the URL-safe alphabet",
        ),
        invalid(
            "secret-31-bytes",
            "secret",
            URL_SAFE_NO_PAD.encode(&du[..31]),
            "secret: exactly 32 bytes",
        ),
        invalid(
            "fetch-token-with-space",
            "fetch_token",
            "tok en".into(),
            "fetch token: printable ASCII 0x21-0x7e only (no space)",
        ),
        invalid(
            "fetch-token-257-bytes",
            "fetch_token",
            printable.repeat(3)[..257].to_owned(),
            "fetch token: 1 to 256 bytes",
        ),
        invalid(
            "fetch-token-empty",
            "fetch_token",
            String::new(),
            "fetch token: 1 to 256 bytes",
        ),
        invalid(
            "luks-uuid-uppercase",
            "luks_uuid",
            LUKS_UUID.to_ascii_uppercase(),
            "luks_uuid: lowercase 8-4-4-4-12",
        ),
        invalid(
            "nonce-std-pad-without-padding",
            "nonce_b64",
            STANDARD_NO_PAD.encode(probe_nonce),
            "std-pad: padding is required",
        ),
        invalid(
            "nonce-std-pad-non-canonical-trailing-bits",
            "nonce_b64",
            non_canonical(&probe.nonce_b64),
            "std-pad: the unused trailing bits must be zero",
        ),
        invalid(
            "nonce-with-line-break",
            "nonce_b64",
            with_line_break(&probe.nonce_b64),
            "std-pad: no line breaks",
        ),
        invalid(
            "sig-std-pad-without-padding",
            "sig",
            STANDARD_NO_PAD.encode(&raw_sig),
            "std-pad: padding is required",
        ),
        invalid(
            "sig-std-pad-non-canonical-trailing-bits",
            "sig",
            non_canonical(&sig),
            "std-pad: the unused trailing bits must be zero",
        ),
        invalid(
            "sig-with-line-break",
            "sig",
            with_line_break(&sig),
            "std-pad: no line breaks",
        ),
        invalid(
            "digest-hex-uppercase",
            "digest_hex",
            publish.digest_hex.to_ascii_uppercase(),
            "hex: lowercase only",
        ),
    ]
}

/// `wire-vectors.json` as this crate computes it.
pub fn wire_vectors() -> WireVectors {
    let printable: String = (0x21u8..=0x7e).map(char::from).collect();
    let du = dash_underscore_bytes();
    let probes = vec![
        probe("probe-counting-nonce", "test-only-zero", counting()),
        probe("probe-ff-nonce", "test-only-ff", [0xff; 32]),
    ];
    let first_publish = publish("format-2-two-recipients", "test-only-zero");
    let manifest_only = Contents {
        manifest_text: "version = 1\n".into(),
        files: BTreeMap::new(),
    };
    let heartbeats = vec![
        heartbeat(
            "typical-30-days",
            "test-only-zero",
            HeartbeatStatement {
                version: 3,
                digest_hex: "3f0c5b2a9d1e4f6a8b7c0d2e1f3a5b4c6d8e7f9a0b1c2d3e4f5a6b7c8d9e0f1a"
                    .into(),
                issued_at: 1_791_000_000,
                not_after: 1_793_592_000,
            },
        ),
        heartbeat(
            "publish-digest-7-days",
            "test-only-counting",
            HeartbeatStatement {
                version: first_publish.frame.version,
                digest_hex: first_publish.digest_hex.clone(),
                issued_at: 1_795_219_200,
                not_after: 1_795_824_000,
            },
        ),
    ];
    let invalid = invalid_vectors(&probes[0], &heartbeats[0], &first_publish);
    let all_kits: Vec<Kit> = KIT_MASTERS.iter().map(|(n, _)| test_kit(n)).collect();
    WireVectors {
        about: "Protocol v1 wire encodings, generated by mastersos-bundle tests \
                (vectors::wire_vectors). std-pad: standard base64 with padding, strict (no line \
                breaks, canonical trailing bits, padding required). url-nopad: URL-safe base64 \
                without padding, same strictness. hex: lowercase only. secret: \
                X-Mastersos-Device-Secret and escrow_secret (url-nopad of exactly 32 bytes). \
                Every entry of invalid must be refused."
            .into(),
        note: "TEST-ONLY: the keys are the fixed, public test kits of kit-vectors.json. Never \
               use them for a school."
            .into(),
        secrets: vec![
            secret("device-secret-zero", "device_secret", &[0u8; 32]),
            secret("device-secret-dash-underscore", "device_secret", &du),
            secret("escrow-secret-counting", "escrow_secret", &counting()),
            secret("escrow-secret-ff", "escrow_secret", &[0xff; 32]),
        ],
        fetch_tokens: vec![
            TokenVector {
                name: "server-minted".into(),
                token: URL_SAFE_NO_PAD.encode(du),
                minted_from_hex: Some(hex(&du)),
            },
            TokenVector {
                name: "one-byte".into(),
                token: "a".into(),
                minted_from_hex: None,
            },
            TokenVector {
                name: "every-printable-byte".into(),
                token: printable.clone(),
                minted_from_hex: None,
            },
            TokenVector {
                name: "256-bytes".into(),
                token: printable.repeat(3)[..256].to_owned(),
                minted_from_hex: None,
            },
        ],
        luks_uuids: vec![NamedValue {
            name: "lowercase".into(),
            value: LUKS_UUID.into(),
        }],
        recipient_bindings: vec![
            binding("binding-counting-nonce", "test-only-zero", counting()),
            binding("binding-zero-nonce", "test-only-counting", [0u8; 32]),
        ],
        key_probes: probes,
        bundle_signatures: vec![
            bundle_signature("manifest-only", "test-only-counting", &manifest_only),
            bundle_signature(
                "publish-vector",
                "test-only-zero",
                &Contents {
                    manifest_text: first_publish.manifest_text.clone(),
                    files: BTreeMap::new(),
                },
            ),
        ],
        heartbeats,
        seed_trust_fingerprints: vec![FingerprintVector {
            name: "three-test-kits".into(),
            trust: all_kits.iter().map(frame_key).collect(),
            fingerprints: all_kits
                .iter()
                .map(|k| trust_fingerprint(&k.trust_key()))
                .collect(),
        }],
        publish: vec![first_publish],
        invalid,
    }
}

fn trust_of(public_key: &str, key_id: &str) -> TrustKey {
    TrustKey {
        id: key_id.into(),
        alg: KeyAlg::Ed25519,
        public_key: public_key.into(),
        rp_id: None,
    }
}

fn verify_ed25519(msg: &[u8], key_id: &str, public_key: &str, sig_b64: &str) {
    let sig = SignatureFile {
        key_id: key_id.into(),
        alg: KeyAlg::Ed25519,
        sig: sig_b64.into(),
        authenticator_data: None,
        client_data_json: None,
    };
    verify_signature(msg, &sig, &[trust_of(public_key, key_id)]).expect("the signature verifies");
}

/// Checks `wire-vectors.json`: the text equals [`wire_vectors`] byte for byte, every valid entry
/// reads back and verifies with this crate's readers, and every invalid entry is refused by the
/// reader this crate has for its field (`fetch_token` has none here: the agent's
/// `token::is_valid` and the CLI's `fetch_token_shape_ok` check those).
pub fn check_wire_vectors(text: &str) {
    let expected = file_text(&wire_vectors());
    if text != expected {
        // Printed line by line with a prefix and a line number so it can be read back from a test log.
        for (i, line) in expected.lines().enumerate() {
            println!("WIREVEC|{:04}|{line}", i + 1);
        }
        panic!("testdata/wire-vectors.json is not what this crate computes (see WIREVEC lines)");
    }
    let w: WireVectors = serde_json::from_str(text).expect("wire-vectors.json parses");

    for s in &w.secrets {
        assert!(is_escrow_secret(&s.encoded), "{}", s.name);
        assert_eq!(
            hex(&URL_SAFE_NO_PAD.decode(&s.encoded).unwrap()),
            s.bytes_hex
        );
    }
    for u in &w.luks_uuids {
        assert!(is_luks_uuid(&u.value), "{}", u.name);
    }
    for p in &w.key_probes {
        let nonce = STANDARD.decode(&p.nonce_b64).unwrap();
        assert_eq!(hex(&nonce), p.nonce_hex);
        let msg = keyid::keyprobe_message(&nonce);
        assert_eq!(STANDARD.encode(&msg), p.message_b64, "{}", p.name);
        verify_ed25519(&msg, &p.key_id, &p.public_key, &p.sig_b64);
    }
    for b in &w.recipient_bindings {
        let nonce = STANDARD.decode(&b.nonce_b64).unwrap();
        let msg = recipient_binding_message(&b.recipient, &nonce);
        assert_eq!(STANDARD.encode(&msg), b.message_b64, "{}", b.name);
        verify_ed25519(&msg, &b.key_id, &b.public_key, &b.sig_b64);
    }
    for b in &w.bundle_signatures {
        let sig: SignatureFile = toml::from_str(&b.signature_toml).unwrap();
        let msg = STANDARD.decode(&b.message_b64).unwrap();
        assert_eq!(&msg[..20], b"mastersos-bundle-v1\n");
        assert_eq!(hex(&msg[20..]), b.digest_hex);
        verify_signature(&msg, &sig, &[trust_of(&b.public_key, &sig.key_id)]).unwrap();
    }
    for h in &w.heartbeats {
        let key_id = Heartbeat::parse(&h.heartbeat_toml)
            .unwrap()
            .signature
            .key_id;
        let s = verify_heartbeat(&h.heartbeat_toml, &[trust_of(&h.public_key, &key_id)]).unwrap();
        assert_eq!(s, h.statement, "{}", h.name);
        assert_eq!(STANDARD.encode(heartbeat_message(&s)), h.message_b64);
    }
    for f in &w.seed_trust_fingerprints {
        let got: Vec<String> = f
            .trust
            .iter()
            .map(|k| trust_fingerprint(&trust_of(&k.public_key, &k.id)))
            .collect();
        assert_eq!(got, f.fingerprints, "{}", f.name);
    }
    for p in &w.publish {
        assert_eq!(frame_of(&p.manifest_text).unwrap(), p.frame, "{}", p.name);
        let c = Contents {
            manifest_text: p.manifest_text.clone(),
            files: BTreeMap::new(),
        };
        assert_eq!(content_hex(&c), p.digest_hex);
        assert_eq!(STANDARD.encode(signed_message(&c)), p.message_b64);
        let sig: SignatureFile = toml::from_str(&p.signature_toml).unwrap();
        let tk = &p.frame.trust[0];
        verify_signature(
            &signed_message(&c),
            &sig,
            &[trust_of(&tk.public_key, &tk.id)],
        )
        .unwrap();
    }

    let probe = &w.key_probes[0];
    let hb = &w.heartbeats[0];
    let hb_parsed = Heartbeat::parse(&hb.heartbeat_toml).unwrap();
    let hb_trust = [trust_of(&hb.public_key, &hb_parsed.signature.key_id)];
    assert!(!w.invalid.is_empty());
    for v in &w.invalid {
        assert!(!v.valid, "{}", v.name);
        assert!(INVALID_FIELDS.contains(&v.field.as_str()), "{}", v.name);
        match v.field.as_str() {
            "secret" => {
                assert!(!is_escrow_secret(&v.value), "{}", v.name);
                let r = FetchTokenRequest {
                    device_id: "dev-1".into(),
                    escrow_secret: v.value.clone(),
                };
                assert!(r.validate().is_err(), "{}", v.name);
            }
            // Checked by the agent (`token::is_valid`) and the CLI (`fetch_token_shape_ok`).
            "fetch_token" => {}
            "luks_uuid" => assert!(!is_luks_uuid(&v.value), "{}", v.name),
            "nonce_b64" => {
                assert!(STANDARD.decode(&v.value).is_err(), "{}", v.name);
                assert_ne!(v.value, probe.nonce_b64);
            }
            "sig" => {
                let mut bad = hb_parsed.clone();
                bad.signature.sig = v.value.clone();
                let text = bad.to_toml();
                assert!(verify_heartbeat(&text, &hb_trust).is_err(), "{}", v.name);
                // The same check as the bundle's `signature` member.
                assert!(
                    verify_signature(
                        &heartbeat_message(&hb_parsed.statement),
                        &bad.signature,
                        &hb_trust
                    )
                    .is_err(),
                    "{}",
                    v.name
                );
            }
            "digest_hex" => {
                let s = HeartbeatStatement {
                    digest_hex: v.value.clone(),
                    ..hb.statement.clone()
                };
                assert!(s.check().is_err(), "{}", v.name);
            }
            other => panic!("no check for field {other}"),
        }
    }
}
