//! The school's recovery kit (plan 6 design §5.2, ruling 10).
//!
//! A kit is one 32-byte master secret `m`. Everything else is derived from it with
//! HKDF-SHA256 (`salt = "mastersos-kit-v1"`, `L = 32`):
//! - `info = "ed25519-sign"`: the Ed25519 seed of the school's recovery key (the `rk-…` key in
//!   the manifest's `trust`);
//! - `info = "x25519-escrow"`: the age X25519 identity the machines' LUKS recovery keys are
//!   sealed to (`AGE-SECRET-KEY-1…`, recipient `age1…` in `[school].escrow_recipients`).
//!
//! Text form: bech32m with HRP [`KIT_HRP`], upper case, shown in groups of four. Parsing drops
//! whitespace and `-`, takes all upper or all lower case only, and refuses a bad checksum, a
//! plain bech32 checksum, another HRP, a length other than 32 bytes and non-zero padding bits:
//! a mistyped kit never turns into another valid key.
//!
//! The master and every derived secret live in [`Zeroizing`] buffers and never reach `Debug`
//! or an error message. (ring's key pair and age's identity keep their own copies; those are
//! outside this crate's control.)

use std::fmt;
use std::str::FromStr as _;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use bech32::primitives::decode::{
    CharError, ChecksumError, UncheckedHrpstring, UncheckedHrpstringError,
};
use bech32::{Bech32, Bech32m, Hrp};
use hkdf::Hkdf;
use ring::rand::{SecureRandom as _, SystemRandom};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{keyid, Ed25519Signer, Signer as _, TrustKey};

/// The kit text's human-readable part.
pub const KIT_HRP: &str = "masterskit";
const HKDF_SALT: &[u8] = b"mastersos-kit-v1";
const INFO_SIGN: &[u8] = b"ed25519-sign";
const INFO_ESCROW: &[u8] = b"x25519-escrow";
/// age's secret key HRP (`AGE-SECRET-KEY-1…`, plain bech32).
const AGE_SECRET_HRP: &str = "age-secret-key-";
/// Prefix of the message a kit signs to bind an escrow recipient to its recovery key.
const RECIPIENT_BINDING_PREFIX: &[u8] = b"mastersos-escrow-recipient-v1\n";
/// 32 bytes in 5-bit groups: 52 characters, the last one carrying 4 padding bits.
const DATA_CHARS: usize = 52;
/// Characters per group in [`Kit::to_display`].
const DISPLAY_GROUP: usize = 4;

/// Why a kit text was refused. The messages never contain the text itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KitError {
    #[error("the recovery kit text is not well formed (unexpected character or no separator)")]
    Malformed,
    #[error("the recovery kit text mixes upper and lower case")]
    MixedCase,
    #[error("the recovery kit text's checksum does not match: a character was mistyped")]
    Checksum,
    #[error("this is not a recovery kit (its prefix is not MASTERSKIT)")]
    WrongHrp,
    #[error("the recovery kit text has the wrong length")]
    Length,
    #[error("the recovery kit text is not canonical (non-zero padding bits)")]
    NonCanonical,
}

/// A school's recovery kit: the 32-byte master secret. `Debug` shows only the key id.
pub struct Kit {
    master: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for Kit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kit")
            .field("key_id", &self.key_id())
            .field("master", &"<redacted>")
            .finish()
    }
}

/// HKDF-SHA256 of the master with the kit salt and `info`, 32 bytes.
fn derive(master: &[u8; 32], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut okm = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(HKDF_SALT), master)
        .expand(info, &mut okm[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

impl Kit {
    /// A new kit from the system's random source.
    pub fn generate() -> Kit {
        let mut m = Zeroizing::new([0u8; 32]);
        SystemRandom::new()
            .fill(&mut m[..])
            .expect("system random source unavailable");
        Kit { master: m }
    }

    /// The kit with this master secret (test vectors). The bytes are copied straight into the
    /// wiped buffer; the caller's copy is the caller's to wipe.
    pub fn from_master(master: &[u8; 32]) -> Kit {
        let mut m = Zeroizing::new([0u8; 32]);
        m.copy_from_slice(master);
        Kit { master: m }
    }

    /// Parse a kit text: whitespace and `-` are dropped; the rest must be all upper or all lower
    /// case bech32m with HRP [`KIT_HRP`] carrying exactly 32 bytes with zero padding bits.
    pub fn parse(text: &str) -> Result<Kit, KitError> {
        // Sized up front so it never reallocates (and leaves a copy behind) while filling.
        let mut clean = Zeroizing::new(String::with_capacity(text.len()));
        clean.extend(text.chars().filter(|c| !c.is_whitespace() && *c != '-'));
        let unchecked = UncheckedHrpstring::new(&clean).map_err(|e| match e {
            // Case is checked over the whole text (HRP included) before the HRP is parsed.
            UncheckedHrpstringError::Char(CharError::MixedCase) => KitError::MixedCase,
            _ => KitError::Malformed,
        })?;
        // Only a bech32m checksum is accepted: a valid plain bech32 checksum is refused like a
        // bad one. Bech32m's code length (1023 characters) only stops texts far longer than a
        // kit, so it is reported as a wrong length.
        unchecked
            .validate_checksum::<Bech32m>()
            .map_err(|e| match e {
                ChecksumError::InvalidLength => KitError::Malformed,
                ChecksumError::CodeLength(_) => KitError::Length,
                _ => KitError::Checksum,
            })?;
        if unchecked.hrp() != Hrp::parse_unchecked(KIT_HRP) {
            return Err(KitError::WrongHrp);
        }
        let checked = unchecked.remove_checksum::<Bech32m>();
        if checked.data_part_ascii_no_checksum().len() != DATA_CHARS {
            return Err(KitError::Length);
        }
        // BIP-173's padding rule (at most 4 bits, all zero); the "segwit" in the name is only
        // where the library keeps it.
        checked
            .validate_segwit_padding()
            .map_err(|_| KitError::NonCanonical)?;
        let mut master = Zeroizing::new([0u8; 32]);
        let mut bytes = checked.byte_iter();
        for b in master.iter_mut() {
            *b = bytes.next().ok_or(KitError::Length)?;
        }
        if bytes.next().is_some() {
            return Err(KitError::Length);
        }
        Ok(Kit { master })
    }

    /// The canonical text: bech32m, upper case, no separators (69 characters).
    pub fn to_text(&self) -> Zeroizing<String> {
        Zeroizing::new(
            bech32::encode_upper::<Bech32m>(Hrp::parse_unchecked(KIT_HRP), &self.master[..])
                .expect("a 32-byte kit is far below the bech32m code length"),
        )
    }

    /// [`Kit::to_text`] in groups of four separated by spaces, for printing.
    pub fn to_display(&self) -> Zeroizing<String> {
        let text = self.to_text();
        let mut out = Zeroizing::new(String::with_capacity(text.len() * 5 / 4 + 1));
        for (i, c) in text.chars().enumerate() {
            if i > 0 && i % DISPLAY_GROUP == 0 {
                out.push(' ');
            }
            out.push(c);
        }
        out
    }

    /// The recovery key's signer; its id is [`Kit::key_id`].
    pub fn signer(&self) -> Ed25519Signer {
        let seed = derive(&self.master, INFO_SIGN);
        let probe = Ed25519Signer::from_seed("", &seed);
        Ed25519Signer::from_seed(&keyid::recovery_key_id(&public_key(&probe)), &seed)
    }

    /// The recovery key as it appears in `trust`.
    pub fn trust_key(&self) -> TrustKey {
        self.signer().trust_key()
    }

    /// The recovery key's id (`rk-…`, from its public key).
    pub fn key_id(&self) -> String {
        self.signer().key_id().to_owned()
    }

    /// The age X25519 identity the escrowed LUKS recovery keys are sealed to.
    pub fn escrow_identity(&self) -> age::x25519::Identity {
        let scalar = derive(&self.master, INFO_ESCROW);
        let upper = Zeroizing::new(
            bech32::encode_upper::<Bech32>(Hrp::parse_unchecked(AGE_SECRET_HRP), &scalar[..])
                .expect("a 32-byte age key is far below the bech32 code length"),
        );
        age::x25519::Identity::from_str(&upper).expect("a 32-byte age secret key always parses")
    }

    /// The escrow recipient (`age1…`) for `[school].escrow_recipients`.
    pub fn escrow_recipient(&self) -> String {
        self.escrow_identity().to_public().to_string()
    }
}

fn public_key(s: &Ed25519Signer) -> Vec<u8> {
    STANDARD
        .decode(s.trust_key().public_key)
        .expect("trust_key's public key is this crate's base64")
}

/// The message a kit's recovery key signs to bind `recipient` to itself when registering it:
/// `b"mastersos-escrow-recipient-v1\n" || recipient || b"\n" || nonce`. Its prefix differs from
/// the bundle, heartbeat and key-probe messages, so none of those signatures can stand in.
pub fn recipient_binding_message(recipient: &str, nonce: &[u8]) -> Vec<u8> {
    let mut msg = RECIPIENT_BINDING_PREFIX.to_vec();
    msg.extend_from_slice(recipient.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(nonce);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{trust_fingerprint, verify_signature, KeyAlg, SignatureFile};
    use bech32::{ByteIterExt as _, Fe32, Fe32IterExt as _};
    use serde::{Deserialize, Serialize};

    const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    fn kit(b: u8) -> Kit {
        Kit::from_master(&[b; 32])
    }

    #[test]
    fn kit_text_roundtrip() {
        for _ in 0..20 {
            let k = Kit::generate();
            let text = k.to_text();
            assert_eq!(text.len(), KIT_HRP.len() + 1 + DATA_CHARS + 6);
            assert!(text.starts_with("MASTERSKIT1"), "{}", text.as_str());
            assert_eq!(text.to_uppercase(), *text);
            let back = Kit::parse(&text).unwrap();
            assert_eq!(*back.master, *k.master);
            let shown = k.to_display();
            assert!(shown.split(' ').all(|g| (1..=4).contains(&g.len())));
            assert_eq!(shown.replace(' ', ""), *text);
            assert_eq!(*Kit::parse(&shown).unwrap().master, *k.master);
        }
    }

    /// Cross-language vectors (`testdata/kit-vectors.json`); the masters are fixed test-only
    /// values. `MASTERSOS_REGEN_VECTORS=1` rewrites the file instead of comparing.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Vector {
        name: String,
        master_hex: String,
        text: String,
        display: String,
        ed25519_seed_hex: String,
        key_id: String,
        public_key: String,
        fingerprint: String,
        escrow_identity: String,
        escrow_recipient: String,
        binding_nonce_b64: String,
        binding_message_b64: String,
        binding_sig_b64: String,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct VectorFile {
        note: String,
        vectors: Vec<Vector>,
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn vector(name: &str, master: [u8; 32]) -> Vector {
        use age::secrecy::ExposeSecret as _;
        let k = Kit::from_master(&master);
        let tk = k.trust_key();
        let nonce = [0x5au8; 32];
        let recipient = k.escrow_recipient();
        let msg = recipient_binding_message(&recipient, &nonce);
        Vector {
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

    #[test]
    fn kit_vectors_match() {
        let mut counting = [0u8; 32];
        for (i, b) in counting.iter_mut().enumerate() {
            *b = i as u8;
        }
        let file = VectorFile {
            note: "TEST-ONLY masters: fixed, public values. Never use these kits for a school."
                .into(),
            vectors: vec![
                vector("test-only-zero", [0u8; 32]),
                vector("test-only-counting", counting),
                vector("test-only-ff", [0xffu8; 32]),
            ],
        };
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/kit-vectors.json");
        if std::env::var_os("MASTERSOS_REGEN_VECTORS").is_some_and(|v| v == "1") {
            std::fs::write(path, serde_json::to_string_pretty(&file).unwrap() + "\n").unwrap();
            return;
        }
        let stored: VectorFile =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(stored, file);
        assert_eq!(stored.vectors.len(), 3);
        for v in &stored.vectors {
            // Parsing the stored text gives the same master back.
            let k = Kit::parse(&v.text).unwrap();
            assert_eq!(hex(&k.master[..]), v.master_hex);
            assert!(v.escrow_identity.starts_with("AGE-SECRET-KEY-1"));
            assert!(v.escrow_recipient.starts_with("age1"));
        }
    }

    #[test]
    fn kit_parse_tolerates_spacing_dashes_and_lowercase() {
        let k = kit(7);
        let text = k.to_text();
        let lower = text.to_lowercase();
        let dashed: String = text
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                (i > 0 && i % 5 == 0)
                    .then_some('-')
                    .into_iter()
                    .chain(std::iter::once(c))
            })
            .collect();
        let messy = format!("  {}\n\t{} \r\n", &text[..20], &text[20..]);
        let shown = k.to_display();
        let newline = format!("{}\n", text.as_str());
        for t in [
            lower.as_str(),
            dashed.as_str(),
            messy.as_str(),
            shown.as_str(),
            newline.as_str(),
        ] {
            assert_eq!(*Kit::parse(t).unwrap().master, [7u8; 32], "{t:?}");
        }
    }

    #[test]
    fn kit_rejects_mixed_case() {
        let text = kit(9).to_text();
        // One lower-case letter in the data part, and a lower-case HRP with upper-case data.
        let pos = (KIT_HRP.len() + 1..text.len())
            .find(|&i| text.as_bytes()[i].is_ascii_uppercase())
            .unwrap();
        let mut one = text.to_string();
        one.replace_range(pos..pos + 1, &text[pos..pos + 1].to_lowercase());
        let hrp_lower = format!("masterskit{}", &text[KIT_HRP.len()..]);
        for t in [one, hrp_lower] {
            assert_eq!(Kit::parse(&t).unwrap_err(), KitError::MixedCase, "{t}");
        }
    }

    #[test]
    fn kit_rejects_any_single_char_change() {
        let text = kit(3).to_text();
        let upper_set = CHARSET.to_uppercase();
        let hrp_set = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        for (i, orig) in text.char_indices() {
            if i == KIT_HRP.len() {
                continue; // the separator
            }
            let set = if i < KIT_HRP.len() {
                hrp_set
            } else {
                upper_set.as_str()
            };
            for c in set.chars().filter(|c| *c != orig) {
                let mut t = text.to_string();
                t.replace_range(i..i + 1, &c.to_string());
                assert!(
                    Kit::parse(&t).is_err(),
                    "position {i} changed to {c} still parses"
                );
            }
        }
        // Dropping or doubling a character fails too.
        for i in KIT_HRP.len() + 1..text.len() {
            let mut shorter = text.to_string();
            shorter.remove(i);
            assert!(Kit::parse(&shorter).is_err(), "dropped {i}");
            let mut longer = text.to_string();
            longer.insert(i, text.as_bytes()[i] as char);
            assert!(Kit::parse(&longer).is_err(), "doubled {i}");
        }
    }

    #[test]
    fn kit_rejects_bech32_non_m_checksum() {
        let k = kit(5);
        let plain = bech32::encode::<Bech32>(Hrp::parse(KIT_HRP).unwrap(), &k.master[..]).unwrap();
        assert_eq!(Kit::parse(&plain).unwrap_err(), KitError::Checksum);
        assert_eq!(
            Kit::parse(&plain.to_uppercase()).unwrap_err(),
            KitError::Checksum
        );
    }

    #[test]
    fn kit_rejects_noncanonical_padding() {
        let hrp = Hrp::parse(KIT_HRP).unwrap();
        let mut data: Vec<Fe32> = kit(1).master.iter().copied().bytes_to_fes().collect();
        assert_eq!(data.len(), DATA_CHARS);
        // The last character holds 1 data bit and 4 padding bits: set a padding bit.
        let last = data[DATA_CHARS - 1].to_u8();
        data[DATA_CHARS - 1] = Fe32::try_from(last | 0b0001).unwrap();
        let t: String = data
            .into_iter()
            .with_checksum::<Bech32m>(&hrp)
            .chars()
            .collect();
        assert_eq!(Kit::parse(&t).unwrap_err(), KitError::NonCanonical);
        // 33 bytes, 31 bytes: wrong length.
        for n in [31usize, 33] {
            let t = bech32::encode::<Bech32m>(hrp, &vec![1u8; n]).unwrap();
            assert_eq!(Kit::parse(&t).unwrap_err(), KitError::Length, "{n}");
        }
    }

    #[test]
    fn kit_wrong_hrp_rejected() {
        let k = kit(2);
        for hrp in ["masterskid", "age", "mastersoskit"] {
            let t = bech32::encode::<Bech32m>(Hrp::parse(hrp).unwrap(), &k.master[..]).unwrap();
            assert_eq!(Kit::parse(&t).unwrap_err(), KitError::WrongHrp, "{hrp}");
        }
        assert_eq!(Kit::parse("").unwrap_err(), KitError::Malformed);
        assert_eq!(Kit::parse("MASTERSKIT").unwrap_err(), KitError::Malformed);
    }

    #[test]
    fn kit_two_keys_are_independent() {
        let k = kit(4);
        let sign = derive(&k.master, INFO_SIGN);
        let escrow = derive(&k.master, INFO_ESCROW);
        assert_ne!(*sign, *escrow);
        assert_ne!(*sign, *k.master);
        assert_ne!(*escrow, *k.master);
        // Neither public key reveals the other: the signing public key is not the escrow
        // recipient's key.
        let tk = k.trust_key();
        assert!(!k.escrow_recipient().contains(&tk.public_key));
        // Two kits share nothing.
        let other = kit(6);
        assert_ne!(other.key_id(), k.key_id());
        assert_ne!(other.escrow_recipient(), k.escrow_recipient());
        // Same kit, same keys every time.
        assert_eq!(kit(4).key_id(), k.key_id());
        assert_eq!(kit(4).escrow_recipient(), k.escrow_recipient());
    }

    #[test]
    fn kit_signer_verifies_with_recovery_trust_key() {
        let k = kit(8);
        let s = k.signer();
        let tk = k.trust_key();
        assert_eq!(tk.alg, KeyAlg::Ed25519);
        let raw = STANDARD.decode(&tk.public_key).unwrap();
        assert_eq!(tk.id, keyid::recovery_key_id(&raw));
        assert_eq!(s.key_id(), tk.id);
        assert_eq!(k.key_id(), tk.id);
        let msg = recipient_binding_message(&k.escrow_recipient(), &[1; 32]);
        assert!(msg.starts_with(RECIPIENT_BINDING_PREFIX));
        let sig = SignatureFile {
            key_id: tk.id.clone(),
            alg: KeyAlg::Ed25519,
            sig: STANDARD.encode(s.sign(&msg)),
            authenticator_data: None,
            client_data_json: None,
        };
        assert_eq!(
            verify_signature(&msg, &sig, std::slice::from_ref(&tk)).unwrap(),
            &tk
        );
        // A signature over another nonce does not verify for this one.
        let other = recipient_binding_message(&k.escrow_recipient(), &[2; 32]);
        assert!(verify_signature(&other, &sig, &[tk]).is_err());
        // from_seed with the same seed is the same key.
        let again = Ed25519Signer::from_seed("x", &derive(&k.master, INFO_SIGN));
        assert_eq!(again.sign(b"m"), s.sign(b"m"));
    }

    #[test]
    fn kit_escrow_roundtrip() {
        let k = kit(10);
        let recipient: age::x25519::Recipient = k.escrow_recipient().parse().unwrap();
        let secret = b"cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv";
        let sealed = age::encrypt_and_armor(&recipient, secret).unwrap();
        assert!(sealed.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
        let opened = age::decrypt(&k.escrow_identity(), sealed.as_bytes()).unwrap();
        assert_eq!(opened, secret);
        // Another kit cannot open it.
        assert!(age::decrypt(&kit(11).escrow_identity(), sealed.as_bytes()).is_err());
    }

    #[test]
    fn kit_debug_redacted() {
        let k = kit(12);
        for s in [format!("{k:?}"), format!("{k:#?}")] {
            assert!(!s.contains(k.to_text().as_str()), "{s}");
            assert!(!s.to_uppercase().contains(&k.to_text()[11..30]), "{s}");
            assert!(!s.contains(&hex(&k.master[..])), "{s}");
            assert!(!s.contains("12, 12, 12"), "{s}");
            assert!(s.contains("<redacted>") && s.contains(&k.key_id()), "{s}");
        }
        // Error messages never carry the text either.
        let mut bad = k.to_text().to_string();
        bad.pop();
        let e = Kit::parse(&bad).unwrap_err().to_string();
        assert!(!e.contains(&bad[11..30]), "{e}");
    }
}
