//! The publish frame (protocol §4.3): what `POST publish/pending` carries beside the digest.
//! The CLI computes it from the text it is about to upload, with the same parser Devices run,
//! so the server's gate checks (trust, recipients, feature gate) see what a Device would see.

use serde::{Deserialize, Serialize};

use crate::{features_used, BundleError, KeyAlg, Manifest};

/// The frame, with the JSON field names of protocol §4.3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    pub format: u32,
    pub version: u64,
    pub issued_at: String,
    pub school_id: String,
    pub trust: Vec<FrameKey>,
    pub escrow_recipients: Vec<String>,
    pub features_used: Vec<String>,
}

/// A trust key in a frame. `public_key` is standard padded base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameKey {
    pub id: String,
    pub alg: String,
    pub public_key: String,
}

/// The frame of a stamped settings text (`version` and `issued_at` written), computed by
/// [`Manifest::parse`].
pub fn frame_of(manifest_text: &str) -> Result<Frame, BundleError> {
    let m = Manifest::parse(manifest_text)?;
    let issued_at = m
        .issued_at
        .clone()
        .ok_or_else(|| BundleError::Invalid("the frame needs a stamped issued_at".into()))?;
    let school_id = m
        .school
        .id
        .clone()
        .ok_or_else(|| BundleError::Invalid("the frame needs [school] id".into()))?;
    let trust = m
        .trust
        .iter()
        .map(|k| {
            if k.alg != KeyAlg::Ed25519 {
                return Err(BundleError::Invalid(
                    "only school keys (ed25519) can be in trust".into(),
                ));
            }
            Ok(FrameKey {
                id: k.id.clone(),
                alg: k.alg.as_str().to_owned(),
                public_key: k.public_key.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut features: Vec<String> = features_used(&m).into_iter().map(str::to_owned).collect();
    if m.format >= 2 {
        features.push(format!("format_{}", m.format));
    }
    features.sort();
    features.dedup();
    Ok(Frame {
        format: m.format,
        version: m.version,
        issued_at,
        school_id,
        trust,
        escrow_recipients: m.school.escrow_recipients.clone(),
        features_used: features,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{legacy_spec_example, spec_example, spec_example_v3, FakePasskey};

    const SCHOOL: &str = "0192f3a4-5b6c-7d8e-9f00-112233445566";

    /// `text` with `[school] id` written and `version` 7.
    fn stamped(text: &str) -> String {
        text.replacen("version = 42", "version = 7", 1).replacen(
            "[school]\n",
            &format!("[school]\nid = \"{SCHOOL}\"\n"),
            1,
        )
    }

    fn format_2_text() -> String {
        format!("format = 2\n{}", stamped(&spec_example()))
    }

    #[test]
    fn frame_of_format_2_text() {
        let f = frame_of(&format_2_text()).unwrap();
        assert_eq!(f.format, 2);
        assert_eq!(f.version, 7);
        assert_eq!(f.issued_at, "2026-10-10T07:00:00Z");
        assert_eq!(f.school_id, SCHOOL);
        assert_eq!(f.trust.len(), 1);
        assert_eq!(f.trust[0].id, "school-2026");
        assert_eq!(f.trust[0].alg, "ed25519");
        assert_eq!(
            f.trust[0].public_key,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
        assert!(f.features_used.contains(&"format_2".to_owned()));
        assert!(f.features_used.contains(&"config".to_owned()));
        let mut sorted = f.features_used.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(f.features_used, sorted);
    }

    #[test]
    fn frame_of_format_3_lists_format_3_and_claims() {
        let text = spec_example_v3().replacen(
            "client_id = \"mastersos\" }",
            "client_id = \"mastersos\", mastersos_claims = true }",
            1,
        );
        let f = frame_of(&text).unwrap();
        assert_eq!(f.format, 3);
        assert!(f.features_used.contains(&"format_3".to_owned()));
        assert!(f
            .features_used
            .contains(&"oidc_mastersos_claims".to_owned()));
        assert!(!f.features_used.contains(&"format_2".to_owned()));
        // `format_3` comes from both the feature list and the format: listed once.
        assert_eq!(
            f.features_used.iter().filter(|s| *s == "format_3").count(),
            1
        );
    }

    #[test]
    fn frame_of_format_1_has_no_format_feature() {
        let f = frame_of(&stamped(&legacy_spec_example())).unwrap();
        assert_eq!(f.format, 1);
        assert!(!f.features_used.iter().any(|s| s.starts_with("format_")));
    }

    #[test]
    fn frame_refuses_passkey_trust() {
        let key = FakePasskey::new("sign.school.ac.th", "https://sign.school.ac.th")
            .trust_key("school-2026");
        let text = format_2_text()
            .replacen(
                "alg = \"ed25519\"",
                &format!(
                    "alg = \"webauthn-es256\"\nrp_id = \"{}\"",
                    key.rp_id.as_deref().unwrap()
                ),
                1,
            )
            .replacen(
                "public_key = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"",
                &format!("public_key = \"{}\"", key.public_key),
                1,
            );
        match frame_of(&text) {
            Err(BundleError::Invalid(m)) => {
                assert_eq!(m, "only school keys (ed25519) can be in trust")
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn frame_needs_school_id() {
        let text = format_2_text().replacen(&format!("id = \"{SCHOOL}\"\n"), "", 1);
        match frame_of(&text) {
            Err(BundleError::Invalid(m)) => assert_eq!(m, "the frame needs [school] id"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn frame_needs_a_stamped_version() {
        let no_version = format_2_text().replacen("version = 7\n", "", 1);
        assert!(frame_of(&no_version).is_err());
        let no_issued_at =
            format_2_text().replacen("issued_at = \"2026-10-10T07:00:00Z\"\n", "", 1);
        assert!(frame_of(&no_issued_at).is_err());
    }

    #[test]
    fn frame_json_field_names() {
        let f = frame_of(&format_2_text()).unwrap();
        let v = serde_json::to_value(&f).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "escrow_recipients",
                "features_used",
                "format",
                "issued_at",
                "school_id",
                "trust",
                "version"
            ]
        );
        let mut tk: Vec<&str> = v["trust"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        tk.sort_unstable();
        assert_eq!(tk, ["alg", "id", "public_key"]);
    }

    #[test]
    fn escrow_vectors_file_has_the_protocol_name() {
        let text = include_str!("../testdata/escrow-vectors.json");
        serde_json::from_str::<serde_json::Value>(text).unwrap();
    }
}
