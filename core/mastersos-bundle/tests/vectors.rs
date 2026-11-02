//! 固化的内容摘要向量：网页（Task 16）与 `mastersos-sign` 自己重算摘要时对照同一份文件。
//! 由 `webauthn::tests::regenerate_vectors`（`--ignored`）生成。

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use mastersos_bundle::{content_digest, Contents};
use serde::Deserialize;

#[derive(Deserialize)]
struct DigestVector {
    name: String,
    manifest_text: String,
    files: BTreeMap<String, String>,
    digest_hex: String,
}

#[test]
fn digest_vectors_match() {
    let vs: Vec<DigestVector> =
        serde_json::from_str(include_str!("../testdata/digest-vectors.json")).unwrap();
    assert!(vs.len() >= 5);
    for v in vs {
        let files = v
            .files
            .iter()
            .map(|(p, b)| (p.clone(), STANDARD.decode(b).unwrap()))
            .collect();
        let c = Contents {
            manifest_text: v.manifest_text,
            files,
        };
        let hex: String = content_digest(&c)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hex, v.digest_hex, "{}", v.name);
    }
}

#[derive(Deserialize)]
struct HeartbeatVector {
    name: String,
    statement: mastersos_bundle::HeartbeatStatement,
    message_b64: String,
}

/// 心跳消息向量：网页本地重建 heartbeat_message 时对照同一份文件。
/// 由 `heartbeat::tests::regenerate_heartbeat_vectors`（`--ignored`）生成。
#[test]
fn heartbeat_vectors_match() {
    let vs: Vec<HeartbeatVector> =
        serde_json::from_str(include_str!("../testdata/heartbeat-vectors.json")).unwrap();
    assert!(vs.len() >= 3);
    for v in vs {
        v.statement.check().unwrap();
        assert_eq!(
            STANDARD.encode(mastersos_bundle::heartbeat_message(&v.statement)),
            v.message_b64,
            "{}",
            v.name
        );
    }
}
