use mastersos_agent::{FetchOutcome, Fetcher};
use mastersos_bundle::{GroupSource, Seed, StatusReport, MAX_BUNDLE_BYTES};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn seed(url: &str, token: Option<&str>) -> Seed {
    Seed {
        server_url: url.into(),
        trust: vec![],
        fetch_token: token.map(String::from),
        group: None,
        oidc: None,
        min_version: None,
        school_id: None,
        wifi: vec![],
        school_name: None,
        it_account: None,
    }
}

#[tokio::test]
async fn fetch_without_token_sends_no_auth() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/bundle"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&format!("{}/", srv.uri()), None));
    assert_eq!(f.fetch_now(0).await.unwrap(), FetchOutcome::NoChange);
    let reqs = srv.received_requests().await.unwrap();
    assert_eq!(reqs[0].url.path(), "/v1/bundle");
    assert!(reqs[0].headers.get("authorization").is_none());
}

#[tokio::test]
async fn fetch_204_is_no_change() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), None));
    assert_eq!(f.fetch_now(9).await.unwrap(), FetchOutcome::NoChange);
}

#[tokio::test]
async fn fetch_errors() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(query_param("after", "1"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(query_param("after", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"x".to_vec()))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(query_param("after", "3"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Mastersos-Version", "abc")
                .set_body_bytes(b"x".to_vec()),
        )
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), None));
    for after in [1, 2, 3] {
        assert!(f.fetch_now(after).await.is_err(), "after={after}");
    }
}

#[tokio::test]
async fn fetch_aborts_oversized_body() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Mastersos-Version", "2")
                .set_body_bytes(vec![0u8; MAX_BUNDLE_BYTES + 1]),
        )
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), None));
    let err = f.fetch_now(0).await.unwrap_err();
    assert!(err.to_string().contains("上限"), "{err}");
}

#[tokio::test]
async fn report_posts_json_with_token() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/status"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    let r = StatusReport {
        device_id: "d".into(),
        serial: None,
        model: None,
        os_version: None,
        agent_version: "0.1.0".into(),
        bundle_version: Some(1),
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
    };
    f.report(&r).await.unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&srv.received_requests().await.unwrap()[0].body).unwrap();
    assert_eq!(body["device_id"], "d");
}

#[tokio::test]
async fn report_rejection_is_error() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), None));
    let r = StatusReport {
        device_id: "d".into(),
        serial: None,
        model: None,
        os_version: None,
        agent_version: "0.1.0".into(),
        bundle_version: None,
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
    };
    assert!(f.report(&r).await.is_err());
}

#[tokio::test]
async fn heartbeat_fetch_outcomes() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/heartbeat"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(200).set_body_string("[statement]\n"))
        .up_to_n_times(1)
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/heartbeat"))
        .respond_with(ResponseTemplate::new(204))
        .up_to_n_times(1)
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/heartbeat"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'a'; 17 * 1024]))
        .up_to_n_times(1)
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/heartbeat"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    assert_eq!(
        f.heartbeat().await.unwrap().as_deref(),
        Some("[statement]\n")
    );
    assert_eq!(f.heartbeat().await.unwrap(), None);
    let big = f.heartbeat().await.unwrap_err().to_string();
    assert!(big.contains("大小上限"), "{big}");
    assert!(f.heartbeat().await.is_err());
}

/// A sealed escrow request (to a test-only kit's recipient).
fn escrow_req() -> mastersos_bundle::EscrowRequest {
    let to = [mastersos_bundle::kit::Kit::from_master(&[3; 32]).escrow_recipient()];
    mastersos_bundle::EscrowRequest {
        device_id: "dev-1".into(),
        serial: Some("PF-1".into()),
        luks_uuid: "f9fd9985-7280-4c3d-bab4-f132ac2336f2".into(),
        recovery_key_age: mastersos_bundle::seal(
            "fhkebvrd-cgvhkfrb-jinlnrtu-vbcdefgh-ijklnrtu-vbcdefgh-ijklnrtu-vbcdefgh",
            &to,
        )
        .unwrap(),
        recipients_fp: mastersos_bundle::recipients_fp(&to),
        escrow_secret: "A".repeat(43),
    }
}

/// 204 成功；403 / 429 的错误带状态码与服务端的 message；错误里没有 URL、没有请求体。
#[tokio::test]
async fn escrow_posts_with_token_and_reports_rejections() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/escrow"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(204))
        .up_to_n_times(1)
        .mount(&srv)
        .await;
    for (code, msg) in [
        (403u16, "这台机器的托管凭据与登记的不同"),
        (429, "已到上限"),
    ] {
        Mock::given(method("POST"))
            .and(path("/v1/escrow"))
            .respond_with(
                ResponseTemplate::new(code).set_body_json(serde_json::json!({
                    "error": {"code": "x", "message": msg}
                })),
            )
            .up_to_n_times(1)
            .mount(&srv)
            .await;
    }
    Mock::given(method("POST"))
        .and(path("/v1/escrow"))
        .respond_with(ResponseTemplate::new(500).set_body_string("<html>oops</html>"))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    let req = escrow_req();
    f.escrow(&req, true).await.unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&srv.received_requests().await.unwrap()[0].body).unwrap();
    assert_eq!(body["recovery_key_age"], req.recovery_key_age);
    for want in [
        "托管被拒（403）：这台机器的托管凭据与登记的不同",
        "托管被拒（429）：已到上限",
        "托管被拒（500）",
    ] {
        let e = format!("{:#}", f.escrow(&req, true).await.unwrap_err());
        assert_eq!(e, want);
    }
    // 连不上：错误里没有 URL，也没有密钥与凭据
    let f = Fetcher::from_seed(&seed("http://127.0.0.1:9/secret-path", Some("tok")));
    let e = format!("{:#}", f.escrow(&req, true).await.unwrap_err());
    assert!(
        !e.contains("secret-path") && !e.contains("127.0.0.1"),
        "{e}"
    );
    assert!(
        !e.contains(&req.recovery_key_age) && !e.contains(&req.escrow_secret),
        "{e}"
    );
}

/// 托管只走 https（终审 I4）：正式镜像上明文的 `http://` 服务端一个字节也不发，错误说明原因；
/// 只有 lab 镜像例外（Ruling 27：本机回环不再例外）。
#[tokio::test]
async fn escrow_refuses_cleartext_server_url_on_release_image() {
    let req = escrow_req();
    for url in [
        "http://192.0.2.1:8080",
        "http://mastersos.school.ac.th",
        "ftp://mastersos.school.ac.th",
        "not a url",
    ] {
        let f = Fetcher::from_seed(&seed(url, Some("tok")));
        let e = format!("{:#}", f.escrow(&req, false).await.unwrap_err());
        assert!(
            e.starts_with("托管被拒（本机）") && e.contains("https"),
            "{url}: {e}"
        );
        assert!(
            !e.contains(&req.recovery_key_age) && !e.contains(&req.escrow_secret),
            "{e}"
        );
    }
}

#[test]
fn escrow_transport_table() {
    use mastersos_agent::fetch::escrow_transport_ok;
    for (url, lab, ok) in [
        ("https://mastersos.school.ac.th", false, true),
        ("HTTPS://mastersos.school.ac.th/base/", false, true),
        ("http://mastersos.school.ac.th", false, false),
        ("http://192.0.2.1:8080", false, false),
        ("http://192.0.2.1:8080", true, true),
        // Ruling 27：回环不再例外，只有 lab 镜像放行 http
        ("http://127.0.0.1:40123", false, false),
        ("http://localhost:8480", false, false),
        ("http://[::1]:8480", false, false),
        ("http://127.0.0.1:40123", true, true),
        // 主机名里带 127.0.0.1 不算回环
        ("http://127.0.0.1.evil.example", false, false),
        ("http://user@127.0.0.1.evil.example", false, false),
        // userinfo 里的 localhost / 127.0.0.1 不是主机
        ("http://localhost@evil.example", false, false),
        ("http://127.0.0.1:80@evil.example", false, false),
        ("http://localhost.evil.example", false, false),
        ("http://evil.example/127.0.0.1", false, false),
        ("http://evil.example?h=localhost", false, false),
        ("ftp://mastersos.school.ac.th", true, false),
        ("not a url", true, false),
    ] {
        assert_eq!(escrow_transport_ok(url, lab).is_ok(), ok, "{url} lab={lab}");
    }
}

/// 托管请求不跟随重定向（终审 I4 的安全复审）：307/308 会带着请求体（恢复密钥与托管凭据）重发到 Location，
/// https 的服务端一个重定向就能把它们送到明文的 http 或别的主机。3xx 当作被拒，Location 那边收不到任何请求。
#[tokio::test]
async fn escrow_does_not_follow_redirects() {
    let srv = MockServer::start().await;
    for code in [301u16, 302, 307, 308] {
        Mock::given(method("POST"))
            .and(path("/v1/escrow"))
            .respond_with(
                ResponseTemplate::new(code)
                    .insert_header("location", format!("{}/elsewhere", srv.uri())),
            )
            .up_to_n_times(1)
            .mount(&srv)
            .await;
    }
    Mock::given(path("/elsewhere"))
        .respond_with(ResponseTemplate::new(204))
        .expect(0)
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    let req = escrow_req();
    for code in [301u16, 302, 307, 308] {
        let e = format!("{:#}", f.escrow(&req, true).await.unwrap_err());
        assert_eq!(e, format!("托管被拒（{code}）"));
    }
}

/// 拉包、心跳、回报的重定向：一旦走过 https 就不许降到别的协议（带着 fetch_token 与设置包）。
#[test]
fn redirects_never_downgrade_from_https() {
    use mastersos_agent::fetch::redirect_allowed;
    let u = |s: &str| reqwest::Url::parse(s).unwrap();
    for (prev, next, ok) in [
        (
            vec!["https://a.example/v1/bundle"],
            "https://b.example/x",
            true,
        ),
        (
            vec!["https://a.example/v1/bundle"],
            "http://a.example/x",
            false,
        ),
        (
            vec!["https://a.example/v1/bundle", "https://a.example/y"],
            "http://127.0.0.1/x",
            false,
        ),
        (
            vec!["http://127.0.0.1:1/v1/bundle"],
            "http://127.0.0.1:1/x",
            true,
        ),
        (
            vec!["http://127.0.0.1:1/v1/bundle"],
            "https://a.example/x",
            true,
        ),
        (
            vec!["https://a.example/v1/bundle"],
            "ftp://a.example/x",
            false,
        ),
    ] {
        let prev: Vec<_> = prev.into_iter().map(u).collect();
        assert_eq!(redirect_allowed(&prev, &u(next)), ok, "{prev:?} → {next}");
    }
    // 次数上限与默认策略相同（10 次）
    let many: Vec<_> = (0..10)
        .map(|i| u(&format!("https://a.example/{i}")))
        .collect();
    assert!(!redirect_allowed(&many, &u("https://a.example/z")));
}

// ---------- fetch_token 换领（计划 4b Task 2） ----------

fn identity() -> mastersos_agent::seedpart::Identity {
    mastersos_agent::seedpart::Identity {
        device_id: "dev-1".into(),
        escrow_secret: "B".repeat(43),
    }
}

/// m4（Ruling 27）：正式镜像上回环的 http 也不托管、不换领。
#[tokio::test]
async fn release_image_refuses_loopback_http_escrow() {
    use mastersos_agent::fetch::escrow_transport_ok;
    assert!(escrow_transport_ok("http://127.0.0.1:8480", false).is_err());
    assert!(escrow_transport_ok("http://127.0.0.1:8480", true).is_ok());
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(204))
        .expect(0)
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    let e = format!("{:#}", f.escrow(&escrow_req(), false).await.unwrap_err());
    assert!(e.starts_with("托管被拒（本机）"), "{e}");
    let e = format!("{:#}", f.renew_token(&identity(), false).await.unwrap_err());
    assert!(e.contains("https"), "{e}");
}

/// Fetcher 的克隆共用同一个令牌与同一个旧令牌标记。
#[tokio::test]
async fn clone_sees_set_token_and_stale() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/heartbeat"))
        .and(header("authorization", "Bearer old"))
        .respond_with(ResponseTemplate::new(204).insert_header("x-mastersos-fetch-token", "stale"))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/heartbeat"))
        .and(header("authorization", "Bearer new"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&srv)
        .await;
    let a = Fetcher::new(&seed(&srv.uri(), Some("seed-tok")), Some("old".into()));
    let b = a.clone();
    assert!(!a.token_is_stale() && !b.token_is_stale());
    assert_eq!(b.heartbeat().await.unwrap(), None);
    assert!(a.token_is_stale(), "克隆收到的 stale 原件也看得到");
    a.set_token("new".into());
    assert!(!b.token_is_stale(), "set_token 清掉标记，克隆也看得到");
    // 克隆发出去的请求带的是原件上换的新令牌（只有 Bearer new 的 mock 不带 stale）。
    assert_eq!(b.heartbeat().await.unwrap(), None);
    assert!(!a.token_is_stale());
    let auths: Vec<String> = srv
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.headers["authorization"].to_str().unwrap().to_string())
        .collect();
    assert_eq!(auths, ["Bearer old", "Bearer new"]);
}

/// 200 → New；403 → Refused（带服务端的说明）；其余 → 错误。请求体是 device_id 与托管凭据，
/// 不跟随重定向；错误里没有令牌、凭据与 URL。
#[tokio::test]
async fn renew_token_outcomes() {
    use mastersos_agent::fetch::RenewOutcome;
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/fetch-token"))
        .and(header("authorization", "Bearer old"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"fetch_token": "brand-new"})),
        )
        .up_to_n_times(1)
        .mount(&srv)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/fetch-token"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": {"code": "forbidden", "message": "这台机器不能换领新令牌"}
        })))
        .up_to_n_times(1)
        .mount(&srv)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/fetch-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"fetch_token": "bad token\n"})),
        )
        .up_to_n_times(1)
        .mount(&srv)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/fetch-token"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/elsewhere", srv.uri())),
        )
        .up_to_n_times(1)
        .mount(&srv)
        .await;
    Mock::given(path("/elsewhere"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&srv)
        .await;
    let f = Fetcher::new(&seed(&srv.uri(), None), Some("old".into()));
    let id = identity();
    match f.renew_token(&id, true).await.unwrap() {
        RenewOutcome::New(t) => assert_eq!(t, "brand-new"),
        other => panic!("{other:?}"),
    }
    let body: serde_json::Value =
        serde_json::from_slice(&srv.received_requests().await.unwrap()[0].body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"device_id": "dev-1", "escrow_secret": id.escrow_secret})
    );
    match f.renew_token(&id, true).await.unwrap() {
        RenewOutcome::Refused(m) => assert_eq!(m, "这台机器不能换领新令牌"),
        other => panic!("{other:?}"),
    }
    for _ in 0..2 {
        let e = format!("{:#}", f.renew_token(&id, true).await.unwrap_err());
        assert!(
            !e.contains("bad token") && !e.contains(&id.escrow_secret) && !e.contains("127.0.0.1"),
            "{e}"
        );
    }
    // RenewOutcome 的 Debug 不打印令牌。
    assert!(!format!("{:?}", RenewOutcome::New("brand-new".into())).contains("brand-new"));
}

/// 当前令牌被拒（401）：错误能认出来（主循环据此换用别的来源的令牌）。
#[tokio::test]
async fn fetch_401_is_recognizable() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&srv)
        .await;
    let f = Fetcher::new(&seed(&srv.uri(), None), Some("t".into()));
    let e = f.fetch_now(1).await.unwrap_err();
    assert!(
        e.downcast_ref::<mastersos_agent::fetch::Unauthorized>()
            .is_some(),
        "{e:#}"
    );
}

/// m4: a stale mark carried back by a request sent before the token was switched (still in
/// flight) speaks of the old token and is ignored.
#[tokio::test]
async fn stale_header_for_superseded_token_is_ignored() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/bundle"))
        .and(header("authorization", "Bearer old"))
        .respond_with(
            ResponseTemplate::new(204)
                .insert_header("x-mastersos-fetch-token", "stale")
                .set_delay(std::time::Duration::from_millis(1500)),
        )
        .mount(&srv)
        .await;
    let f = Fetcher::new(&seed(&srv.uri(), None), Some("old".into()));
    let g = f.clone();
    let pending = tokio::spawn(async move { g.fetch_now(1).await });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    f.set_token("new".into());
    assert_eq!(pending.await.unwrap().unwrap(), FetchOutcome::NoChange);
    assert!(
        !f.token_is_stale(),
        "旧令牌请求带回的 stale 不该把新令牌标成旧的"
    );
}

// ---------- MQTT push calls ----------

use mastersos_agent::fetch::{CredRejected, DeviceAuthMissing, DeviceCred, Unauthorized};
use mastersos_bundle::{InboxResult, InboxResultState};

fn cred() -> DeviceCred {
    DeviceCred {
        device_id: "dev-1".into(),
        secret: "S".repeat(43),
    }
}

#[tokio::test]
async fn fetch_now_sends_wait0() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/bundle"))
        .and(query_param("after", "5"))
        .and(query_param("wait", "0"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(204).insert_header("x-mastersos-fetch-token", "stale"))
        .expect(1)
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    assert_eq!(f.fetch_now(5).await.unwrap(), FetchOutcome::NoChange);
    assert!(f.token_is_stale());
}

#[tokio::test]
async fn fetch_now_200_and_401() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/bundle"))
        .and(header("authorization", "Bearer good"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Mastersos-Version", "9")
                .set_body_bytes(b"A".to_vec()),
        )
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/bundle"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("good")));
    assert_eq!(
        f.fetch_now(0).await.unwrap(),
        FetchOutcome::New {
            archive: b"A".to_vec(),
            version: 9
        }
    );
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("bad")));
    let e = f.fetch_now(0).await.unwrap_err();
    assert!(e.downcast_ref::<Unauthorized>().is_some(), "{e:#}");
}

#[tokio::test]
async fn push_token_sends_cred_and_parses() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/push-token"))
        .and(header("authorization", "Bearer tok"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "device_id": "dev-1", "secret": "S".repeat(43)
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "jwt", "broker": "mqtts://b:8883", "client_id": "c1",
            "topics": ["t/settings", "t/inbox"], "expires_at": "2026-10-28T00:00:00Z"
        })))
        .expect(1)
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    let r = f.push_token(&cred(), true).await.unwrap();
    assert_eq!(r.client_id, "c1");
    assert_eq!(r.topics.len(), 2);
    assert!(!format!("{r:?}").contains("jwt"));
}

#[tokio::test]
async fn push_token_error_statuses() {
    for (code, rejected) in [(403u16, true), (429, false), (503, false), (400, false)] {
        let srv = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(code))
            .mount(&srv)
            .await;
        let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
        let e = f.push_token(&cred(), true).await.unwrap_err();
        assert_eq!(
            e.downcast_ref::<CredRejected>().is_some(),
            rejected,
            "{code}: {e:#}"
        );
        assert!(
            e.to_string().contains(&code.to_string()) || rejected,
            "{e:#}"
        );
    }
}

#[tokio::test]
async fn inbox_sends_device_headers() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/inbox"))
        .and(query_param("after", "2"))
        .and(header("authorization", "Bearer tok"))
        .and(header("x-mastersos-device", "dev-1"))
        .and(header("x-mastersos-device-secret", "S".repeat(43).as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "messages": [{
                "seq": 3, "class": "command", "kind": "factory-reset", "payload": {},
                "created_at": "2026-10-27T00:00:00Z", "expires_at": null
            }],
            "last_seq": 3
        })))
        .expect(1)
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    let p = f.inbox(&cred(), 2, true).await.unwrap();
    assert_eq!(p.last_seq, 3);
    assert_eq!(p.messages[0].kind, "factory-reset");
}

#[tokio::test]
async fn inbox_401_variants_are_distinguishable() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": {"code": "device_auth_missing", "message": "x"}
        })))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    let e = f.inbox(&cred(), 0, true).await.unwrap_err();
    assert!(e.downcast_ref::<DeviceAuthMissing>().is_some(), "{e:#}");
    assert!(e.downcast_ref::<Unauthorized>().is_none());
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("wrong")));
    let e = f.inbox(&cred(), 0, true).await.unwrap_err();
    assert!(e.downcast_ref::<Unauthorized>().is_some(), "{e:#}");
}

#[tokio::test]
async fn inbox_result_posts_and_409_is_ok() {
    use mastersos_agent::fetch::{InboxSeqUnknown, ResultAck};
    let r = InboxResult {
        state: InboxResultState::Done,
        detail: Some("ok".into()),
    };
    for (code, want) in [
        (204u16, Some(ResultAck::Recorded)),
        (409, Some(ResultAck::Refused)),
        (404, None),
        (500, None),
    ] {
        let srv = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/inbox/7/result"))
            .and(header("authorization", "Bearer tok"))
            .and(header("x-mastersos-device", "dev-1"))
            .and(header("x-mastersos-device-secret", "S".repeat(43).as_str()))
            .and(wiremock::matchers::body_json(
                serde_json::json!({"state": "done", "detail": "ok"}),
            ))
            .respond_with(ResponseTemplate::new(code))
            .expect(1)
            .mount(&srv)
            .await;
        let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
        let got = f.inbox_result(&cred(), 7, &r, true).await;
        match want {
            Some(w) => assert_eq!(got.unwrap(), w, "{code}"),
            None => {
                let e = got.unwrap_err();
                // 404: the server has no such message (purged or never): a typed error.
                assert_eq!(
                    e.downcast_ref::<InboxSeqUnknown>().is_some(),
                    code == 404,
                    "{code}: {e:#}"
                );
            }
        }
    }
}

#[tokio::test]
async fn cred_not_in_logs_or_errors() {
    let secret = "S".repeat(43);
    assert!(!format!("{:?}", cred()).contains(&secret));
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": {"code": "forbidden", "message": "secret mismatch"}
        })))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    let e = f.push_token(&cred(), true).await.unwrap_err();
    assert!(!format!("{e:#} {e:?}").contains(&secret));
    let e = f.inbox(&cred(), 0, true).await.unwrap_err();
    assert!(!format!("{e:#} {e:?}").contains(&secret));
    // A connect failure must not leak the secret or URL either.
    let f = Fetcher::from_seed(&seed("http://127.0.0.1:1", Some("tok")));
    let e = f
        .inbox_result(
            &cred(),
            1,
            &InboxResult {
                state: InboxResultState::Running,
                detail: None,
            },
            true,
        )
        .await
        .unwrap_err();
    assert!(!format!("{e:#} {e:?}").contains(&secret));
}

/// Ruling R7: the device secret is never sent over http on a release image; nothing reaches the server.
#[tokio::test]
async fn device_secret_refused_over_http_on_release_image() {
    let srv = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    let r = InboxResult {
        state: InboxResultState::Done,
        detail: None,
    };
    let e1 = f.push_token(&cred(), false).await.unwrap_err();
    let e2 = f.inbox(&cred(), 0, false).await.unwrap_err();
    let e3 = f.inbox_result(&cred(), 1, &r, false).await.unwrap_err();
    for e in [e1, e2, e3] {
        assert!(!format!("{e:#}").contains(&"S".repeat(43)));
        assert!(e.downcast_ref::<Unauthorized>().is_none());
    }
    assert!(srv.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn device_secret_allowed_over_http_on_lab_image() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/inbox/1/result"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    let r = InboxResult {
        state: InboxResultState::Done,
        detail: None,
    };
    f.inbox_result(&cred(), 1, &r, true).await.unwrap();
}

// ---------- bundle download timeouts ----------

/// A bundle is up to 20 MiB and a doorbell sends a whole school at once: its download has its own
/// generous bounds, not the 30 s of the heartbeat and status calls.
#[test]
fn bundle_download_bounds_are_pinned() {
    use mastersos_agent::fetch::{
        bundle_opts, short_opts, BUNDLE_READ_TIMEOUT, BUNDLE_TOTAL_TIMEOUT, CONNECT_TIMEOUT,
    };
    use std::time::Duration;
    assert_eq!(BUNDLE_TOTAL_TIMEOUT, Duration::from_secs(300));
    assert_eq!(BUNDLE_READ_TIMEOUT, Duration::from_secs(60));
    assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(30));
    let b = bundle_opts();
    assert_eq!(b.connect, CONNECT_TIMEOUT);
    assert_eq!(b.read, Some(BUNDLE_READ_TIMEOUT));
    assert_eq!(b.total, Some(BUNDLE_TOTAL_TIMEOUT));
    let s = short_opts();
    assert_eq!(s.total, Some(Duration::from_secs(30)));
}

/// `fetch_now` goes through the download client: a bundle whose answer takes longer than the
/// 30 s of the small calls still arrives.
#[tokio::test]
async fn fetch_now_outlasts_the_short_timeout() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/bundle"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Mastersos-Version", "2")
                .set_body_bytes(b"ARCHIVE".to_vec())
                .set_delay(std::time::Duration::from_secs(32)),
        )
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), None));
    assert_eq!(
        f.fetch_now(1).await.unwrap(),
        FetchOutcome::New {
            archive: b"ARCHIVE".to_vec(),
            version: 2
        }
    );
}
