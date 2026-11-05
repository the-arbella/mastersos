//! The three-step diagnostics upload (`POST /v1/diagnostics` → presigned `PUT` → complete)
//! against a local mock server that plays both the cloud and S3.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use mastersos_agent::diag::upload::{upload, DiagUploadError, MAX_ROUNDS};
use mastersos_agent::fetch::DeviceCred;
use mastersos_agent::Fetcher;
use mastersos_bundle::diag::{DiagUploadRequest, ErrorAction};
use mastersos_bundle::Seed;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const TOKEN: &str = "fetch-token-value";
const SIG: &str = "deadbeefsignaturevalue";
const BODY: &[u8] = b"pretend this is a tar.zst diagnostics archive";
const CHECKSUM: &str = "q83vEjRWeJA=";

fn seed(url: &str) -> Seed {
    Seed {
        server_url: url.into(),
        trust: vec![],
        fetch_token: Some(TOKEN.into()),
        group: None,
        oidc: None,
        min_version: None,
        school_id: None,
        wifi: vec![],
        school_name: None,
        it_account: None,
    }
}

fn cred() -> DeviceCred {
    DeviceCred {
        device_id: "dev-1".into(),
        secret: "S".repeat(43),
    }
}

fn req() -> DiagUploadRequest {
    DiagUploadRequest::Inbox {
        inbox_seq: 7,
        bytes: BODY.len() as u64,
        sha256: "a".repeat(64),
    }
}

struct Env {
    srv: MockServer,
    f: Fetcher,
    _dir: tempfile::TempDir,
    file: PathBuf,
}

async fn env() -> Env {
    let srv = MockServer::start().await;
    let f = Fetcher::from_seed(&seed(&srv.uri()));
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("diag.tar.zst");
    std::fs::write(&file, BODY).unwrap();
    Env {
        srv,
        f,
        _dir: dir,
        file,
    }
}

fn signed_headers() -> serde_json::Value {
    serde_json::json!({
        "Content-Length": BODY.len().to_string(),
        "x-amz-checksum-sha256": CHECKSUM,
        "x-amz-sdk-checksum-algorithm": "SHA256",
        "x-amz-tagging": "state=pending",
    })
}

/// A 201 answer whose presigned URL points at `/s3/<object>` on the same mock server.
fn presigned(srv: &MockServer, object: &str, expires_in: u64) -> ResponseTemplate {
    ResponseTemplate::new(201).set_body_json(serde_json::json!({
        "id": "abc123",
        "upload": {
            "method": "PUT",
            "url": format!(
                "{}/s3/{object}?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=900&X-Amz-Signature={SIG}",
                srv.uri()
            ),
            "headers": signed_headers(),
            "expires_at": "2026-11-05T12:15:00Z",
            "expires_in": expires_in,
        }
    }))
}

async fn mount_step1(srv: &MockServer, t: ResponseTemplate, times: Option<u64>) {
    let m = Mock::given(method("POST")).and(path("/v1/diagnostics"));
    let m = m.respond_with(t);
    let m = match times {
        Some(n) => m.up_to_n_times(n),
        None => m,
    };
    m.mount(srv).await;
}

async fn mount_put(srv: &MockServer, object: &str, t: ResponseTemplate) {
    Mock::given(method("PUT"))
        .and(path(format!("/s3/{object}")))
        .respond_with(t)
        .mount(srv)
        .await;
}

async fn mount_complete(srv: &MockServer, t: ResponseTemplate, times: Option<u64>) {
    let m = Mock::given(method("POST"))
        .and(path("/v1/diagnostics/abc123/complete"))
        .respond_with(t);
    let m = match times {
        Some(n) => m.up_to_n_times(n),
        None => m,
    };
    m.mount(srv).await;
}

async fn requests(srv: &MockServer, m: &str, p: &str) -> Vec<Request> {
    srv.received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.method.as_str() == m && r.url.path() == p)
        .collect()
}

fn api_error(status: u16, code: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(serde_json::json!({
        "error": { "code": code, "message": "from the cloud" }
    }))
}

fn assert_clean(e: &DiagUploadError) {
    let text = format!("{e} {e:?}");
    assert!(text.starts_with("upload: "), "{text}");
    for bad in ["X-Amz-Signature", SIG, TOKEN, &"S".repeat(43)] {
        assert!(!text.contains(bad), "error leaks {bad:?}: {text}");
    }
}

#[tokio::test]
async fn upload_happy_path_sends_headers_verbatim() {
    let e = env().await;
    Mock::given(method("POST"))
        .and(path("/v1/diagnostics"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .and(header("x-mastersos-device", "dev-1"))
        .and(header("x-mastersos-device-secret", "S".repeat(43).as_str()))
        .and(body_json(serde_json::json!({
            "kind": "inbox", "inbox_seq": 7, "bytes": BODY.len(), "sha256": "a".repeat(64)
        })))
        .respond_with(presigned(&e.srv, "obj1", 900))
        .expect(1)
        .mount(&e.srv)
        .await;
    mount_put(&e.srv, "obj1", ResponseTemplate::new(200)).await;
    Mock::given(method("POST"))
        .and(path("/v1/diagnostics/abc123/complete"))
        .and(header("x-mastersos-device", "dev-1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&e.srv)
        .await;

    let id = upload(&e.f, &cred(), req(), &e.file, true).await.unwrap();
    assert_eq!(id, "abc123");

    let puts = requests(&e.srv, "PUT", "/s3/obj1").await;
    assert_eq!(puts.len(), 1);
    let put = &puts[0];
    assert_eq!(put.body, BODY);
    let h = |n: &str| put.headers.get(n).map(|v| v.to_str().unwrap().to_string());
    assert_eq!(
        h("content-length").as_deref(),
        Some(&*BODY.len().to_string())
    );
    assert_eq!(h("x-amz-checksum-sha256").as_deref(), Some(CHECKSUM));
    assert_eq!(h("x-amz-sdk-checksum-algorithm").as_deref(), Some("SHA256"));
    assert_eq!(h("x-amz-tagging").as_deref(), Some("state=pending"));
    // The signed query string went to S3 unchanged.
    assert!(put
        .url
        .query()
        .unwrap()
        .contains(&format!("X-Amz-Signature={SIG}")));
}

#[tokio::test]
async fn already_complete_skips_put() {
    let e = env().await;
    mount_step1(
        &e.srv,
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({"id": "abc123", "complete": true})),
        None,
    )
    .await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&e.srv)
        .await;
    mount_complete(&e.srv, ResponseTemplate::new(204), None).await;
    let id = upload(&e.f, &cred(), req(), &e.file, true).await.unwrap();
    assert_eq!(id, "abc123");
    assert!(requests(&e.srv, "POST", "/v1/diagnostics/abc123/complete")
        .await
        .is_empty());
}

#[tokio::test]
async fn upload_mismatch_restarts_from_step_one() {
    let e = env().await;
    mount_step1(&e.srv, presigned(&e.srv, "obj1", 900), None).await;
    mount_put(&e.srv, "obj1", ResponseTemplate::new(200)).await;
    mount_complete(&e.srv, api_error(409, "upload_mismatch"), Some(1)).await;
    mount_complete(&e.srv, ResponseTemplate::new(204), None).await;
    let id = upload(&e.f, &cred(), req(), &e.file, true).await.unwrap();
    assert_eq!(id, "abc123");
    assert_eq!(requests(&e.srv, "POST", "/v1/diagnostics").await.len(), 2);
    assert_eq!(requests(&e.srv, "PUT", "/s3/obj1").await.len(), 2);
}

#[tokio::test]
async fn expires_in_elapsed_restarts() {
    let e = env().await;
    // The first URL is already used up when it arrives: no PUT to it, a new one is asked for.
    mount_step1(&e.srv, presigned(&e.srv, "obj1", 0), Some(1)).await;
    mount_step1(&e.srv, presigned(&e.srv, "obj2", 900), None).await;
    mount_put(&e.srv, "obj1", ResponseTemplate::new(200)).await;
    mount_put(&e.srv, "obj2", ResponseTemplate::new(200)).await;
    mount_complete(&e.srv, ResponseTemplate::new(204), None).await;
    let id = upload(&e.f, &cred(), req(), &e.file, true).await.unwrap();
    assert_eq!(id, "abc123");
    assert_eq!(requests(&e.srv, "POST", "/v1/diagnostics").await.len(), 2);
    assert!(requests(&e.srv, "PUT", "/s3/obj1").await.is_empty());
    assert_eq!(requests(&e.srv, "PUT", "/s3/obj2").await.len(), 1);
}

#[tokio::test]
async fn s3_request_expired_restarts() {
    let e = env().await;
    mount_step1(&e.srv, presigned(&e.srv, "obj1", 900), Some(1)).await;
    mount_step1(&e.srv, presigned(&e.srv, "obj2", 900), None).await;
    mount_put(
        &e.srv,
        "obj1",
        ResponseTemplate::new(403).set_body_string(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>AccessDenied</Code>\
             <Message>Request has expired</Message><X-Amz-Expires>900</X-Amz-Expires></Error>",
        ),
    )
    .await;
    mount_put(&e.srv, "obj2", ResponseTemplate::new(200)).await;
    mount_complete(&e.srv, ResponseTemplate::new(204), None).await;
    let id = upload(&e.f, &cred(), req(), &e.file, true).await.unwrap();
    assert_eq!(id, "abc123");
    assert_eq!(requests(&e.srv, "POST", "/v1/diagnostics").await.len(), 2);
    assert_eq!(requests(&e.srv, "PUT", "/s3/obj2").await.len(), 1);
}

#[tokio::test]
async fn not_yours_and_expired_give_up() {
    for (status, code) in [(409u16, "not_yours"), (410, "expired")] {
        let e = env().await;
        mount_step1(&e.srv, api_error(status, code), None).await;
        let err = upload(&e.f, &cred(), req(), &e.file, true)
            .await
            .unwrap_err();
        assert_eq!(err.action, ErrorAction::GiveUp, "{code}: {err}");
        assert!(err.detail.contains(code), "{err}");
        assert_clean(&err);
        assert_eq!(
            requests(&e.srv, "POST", "/v1/diagnostics").await.len(),
            1,
            "{code}: no retry"
        );
    }
    // The same codes from the complete call give up too.
    let e = env().await;
    mount_step1(&e.srv, presigned(&e.srv, "obj1", 900), None).await;
    mount_put(&e.srv, "obj1", ResponseTemplate::new(200)).await;
    mount_complete(&e.srv, api_error(410, "expired"), None).await;
    let err = upload(&e.f, &cred(), req(), &e.file, true)
        .await
        .unwrap_err();
    assert_eq!(err.action, ErrorAction::GiveUp, "{err}");
    assert_eq!(requests(&e.srv, "POST", "/v1/diagnostics").await.len(), 1);
}

#[tokio::test]
async fn no_extra_headers_on_put() {
    let e = env().await;
    mount_step1(&e.srv, presigned(&e.srv, "obj1", 900), None).await;
    mount_put(&e.srv, "obj1", ResponseTemplate::new(200)).await;
    mount_complete(&e.srv, ResponseTemplate::new(204), None).await;
    upload(&e.f, &cred(), req(), &e.file, true).await.unwrap();
    let puts = requests(&e.srv, "PUT", "/s3/obj1").await;
    let put = &puts[0];
    for banned in [
        "content-md5",
        "content-type",
        "authorization",
        "x-mastersos-device",
        "x-mastersos-device-secret",
        "transfer-encoding",
    ] {
        assert!(put.headers.get(banned).is_none(), "PUT carries {banned}");
    }
    assert_exact_headers(put, &signed_headers());
}

/// The PUT carries exactly the given headers with the given values, no more and no fewer,
/// besides `host` (HTTP needs it) and reqwest's `accept: */*` (not signed, ignored by S3).
fn assert_exact_headers(put: &Request, given: &serde_json::Value) {
    let given = given.as_object().unwrap();
    let mut want: BTreeSet<(String, String)> = given
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.as_str().unwrap().to_string()))
        .collect();
    want.insert(("accept".into(), "*/*".into()));
    let sent: BTreeSet<(String, String)> = put
        .headers
        .iter()
        .filter(|(k, _)| k.as_str() != "host")
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap().to_string()))
        .collect();
    assert_eq!(sent, want, "PUT headers differ from the presigned ones");
}

/// Whatever header set the cloud signs is what goes out: a set without tagging and with an
/// extra signed header is sent as is.
#[tokio::test]
async fn put_sends_exactly_a_different_header_set() {
    let e = env().await;
    let given = serde_json::json!({
        "content-length": BODY.len().to_string(),
        "X-Amz-Checksum-Sha256": CHECKSUM,
        "x-amz-sdk-checksum-algorithm": "SHA256",
        "x-amz-server-side-encryption": "AES256",
    });
    mount_step1(
        &e.srv,
        ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "abc123",
            "upload": {
                "method": "PUT",
                "url": format!("{}/s3/obj1?X-Amz-Signature={SIG}", e.srv.uri()),
                "headers": given,
                "expires_at": "2026-11-05T12:15:00Z", "expires_in": 900
            }
        })),
        None,
    )
    .await;
    mount_put(&e.srv, "obj1", ResponseTemplate::new(200)).await;
    mount_complete(&e.srv, ResponseTemplate::new(204), None).await;
    upload(&e.f, &cred(), req(), &e.file, true).await.unwrap();
    let puts = requests(&e.srv, "PUT", "/s3/obj1").await;
    assert_exact_headers(&puts[0], &given);
}

/// Every row of the spec's error table (and the fallbacks by status), from step 1: the action
/// is the one `error_action` gives, and only `upload_mismatch` starts another round.
#[tokio::test]
async fn every_error_table_row_is_handled() {
    use ErrorAction::*;
    let rows: &[(u16, Option<&str>, ErrorAction)] = &[
        (422, Some("invalid"), Drop),
        (403, Some("support_disabled"), DropSupportDisabled),
        (429, Some("too_many"), RetryAfter),
        (429, Some("too_many_keys"), RetryAfter),
        (503, Some("diagnostics_unavailable"), Backoff),
        (409, Some("not_yours"), GiveUp),
        (410, Some("expired"), GiveUp),
        (403, Some("forbidden"), Backoff),
        (401, Some("unauthorized"), Backoff),
        (401, Some("device_auth_missing"), Backoff),
        (403, Some("school_suspended"), Backoff),
        (503, Some("not_ready"), Backoff),
        // No code: 5xx, 404, an empty 401 back off.
        (500, None, Backoff),
        (502, None, Backoff),
        (404, None, Backoff),
        (401, None, Backoff),
        // Unknown code: 400, 413, 422 drop; anything else backs off.
        (400, Some("something_new"), Drop),
        (413, None, Drop),
        (422, None, Drop),
        (409, Some("something_new"), Backoff),
    ];
    let e = env().await;
    for &(status, code, want) in rows {
        e.srv.reset().await;
        let t = match code {
            Some(c) => api_error(status, c),
            None => ResponseTemplate::new(status),
        };
        mount_step1(&e.srv, t, None).await;
        let err = upload(&e.f, &cred(), req(), &e.file, true)
            .await
            .unwrap_err();
        assert_eq!(err.action, want, "{status} {code:?}: {err}");
        assert_clean(&err);
        assert_eq!(
            requests(&e.srv, "POST", "/v1/diagnostics").await.len(),
            1,
            "{status} {code:?}: one request, the caller decides when to retry"
        );
        assert!(e
            .srv
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() != "PUT"));
    }
    // `upload_mismatch` from step 1 starts another round, up to MAX_ROUNDS.
    let e = env().await;
    mount_step1(&e.srv, api_error(409, "upload_mismatch"), None).await;
    let err = upload(&e.f, &cred(), req(), &e.file, true)
        .await
        .unwrap_err();
    assert_eq!(err.action, Backoff, "{err}");
    assert_eq!(
        requests(&e.srv, "POST", "/v1/diagnostics").await.len(),
        MAX_ROUNDS as usize
    );
    // The flat `{"error": "<code>"}` form is read too.
    let e = env().await;
    mount_step1(
        &e.srv,
        ResponseTemplate::new(409).set_body_json(serde_json::json!({"error": "not_yours"})),
        None,
    )
    .await;
    let err = upload(&e.f, &cred(), req(), &e.file, true)
        .await
        .unwrap_err();
    assert_eq!(err.action, GiveUp, "{err}");
}

#[tokio::test]
async fn gives_up_after_three_rounds() {
    let e = env().await;
    mount_step1(&e.srv, presigned(&e.srv, "obj1", 900), None).await;
    mount_put(&e.srv, "obj1", ResponseTemplate::new(200)).await;
    mount_complete(&e.srv, api_error(409, "upload_mismatch"), None).await;
    let err = upload(&e.f, &cred(), req(), &e.file, true)
        .await
        .unwrap_err();
    assert_eq!(MAX_ROUNDS, 3);
    assert_eq!(err.action, ErrorAction::Backoff, "{err}");
    assert_clean(&err);
    assert_eq!(requests(&e.srv, "POST", "/v1/diagnostics").await.len(), 3);
    assert_eq!(requests(&e.srv, "PUT", "/s3/obj1").await.len(), 3);
}

#[tokio::test]
async fn error_text_has_no_query_string() {
    // S3's own error body can echo the canonical request, query string included.
    let e = env().await;
    mount_step1(&e.srv, presigned(&e.srv, "obj1", 900), None).await;
    mount_put(
        &e.srv,
        "obj1",
        ResponseTemplate::new(403).set_body_string(format!(
            "<Error><Code>SignatureDoesNotMatch</Code><CanonicalRequest>PUT /s3/obj1 \
             X-Amz-Signature={SIG}</CanonicalRequest></Error>"
        )),
    )
    .await;
    let err = upload(&e.f, &cred(), req(), &e.file, true)
        .await
        .unwrap_err();
    assert_clean(&err);
    assert!(err.detail.contains("403"), "{err}");

    // A connection failure to S3 does not name the URL either.
    let e = env().await;
    let url = format!("http://127.0.0.1:1/s3/obj1?X-Amz-Expires=900&X-Amz-Signature={SIG}");
    mount_step1(
        &e.srv,
        ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "abc123",
            "upload": {
                "method": "PUT", "url": url, "headers": signed_headers(),
                "expires_at": "2026-11-05T12:15:00Z", "expires_in": 900
            }
        })),
        None,
    )
    .await;
    let err = upload(&e.f, &cred(), req(), &e.file, true)
        .await
        .unwrap_err();
    assert_eq!(err.action, ErrorAction::Backoff, "{err}");
    assert_clean(&err);
    assert!(!err.to_string().contains("127.0.0.1:1"), "{err}");
}

#[tokio::test]
async fn too_many_carries_retry_after() {
    let e = env().await;
    mount_step1(
        &e.srv,
        api_error(429, "too_many").insert_header("retry-after", "120"),
        None,
    )
    .await;
    let err = upload(&e.f, &cred(), req(), &e.file, true)
        .await
        .unwrap_err();
    assert_eq!(err.action, ErrorAction::RetryAfter, "{err}");
    assert_eq!(err.retry_after, Some(Duration::from_secs(120)));
    assert_clean(&err);
}

/// S3 `RequestTimeout` (400: the body came in too slowly) is a slow link, not a bad request.
#[tokio::test]
async fn s3_request_timeout_backs_off() {
    let e = env().await;
    mount_step1(&e.srv, presigned(&e.srv, "obj1", 900), None).await;
    mount_put(
        &e.srv,
        "obj1",
        ResponseTemplate::new(400)
            .set_body_string("<Error><Code>RequestTimeout</Code><Message>x</Message></Error>"),
    )
    .await;
    let err = upload(&e.f, &cred(), req(), &e.file, true)
        .await
        .unwrap_err();
    assert_eq!(err.action, ErrorAction::Backoff, "{err}");
    assert!(err.detail.contains("RequestTimeout"), "{err}");
}

/// The presigned URL carries the grant: never sent over http on a release image.
#[tokio::test]
async fn release_image_refuses_http() {
    let e = env().await;
    mount_step1(&e.srv, presigned(&e.srv, "obj1", 900), None).await;
    let err = upload(&e.f, &cred(), req(), &e.file, false)
        .await
        .unwrap_err();
    assert_clean(&err);
    assert!(e.srv.received_requests().await.unwrap().is_empty());
}
