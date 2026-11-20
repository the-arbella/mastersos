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
        .and(path("/api/device/v1/bundle"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&format!("{}/", srv.uri()), None));
    assert_eq!(f.fetch_now(0).await.unwrap(), FetchOutcome::NoChange);
    let reqs = srv.received_requests().await.unwrap();
    assert_eq!(reqs[0].url.path(), "/api/device/v1/bundle");
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
    assert!(err.to_string().contains("size limit"), "{err}");
}

async fn status_mock(srv: &MockServer, status: u16, expect: u64) {
    Mock::given(method("POST"))
        .and(path("/api/device/v1/status"))
        .respond_with(ResponseTemplate::new(status))
        .expect(expect)
        .mount(srv)
        .await;
}

#[tokio::test]
async fn status_always_carries_the_device_headers() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/device/v1/status"))
        .and(header("authorization", "Bearer tok"))
        .and(header("x-mastersos-device", "dev-1"))
        .and(header("x-mastersos-device-secret", "S".repeat(43).as_str()))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    f.report(&status_report(), &cred(), true).await.unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&srv.received_requests().await.unwrap()[0].body).unwrap();
    assert_eq!(body["device_id"], "dev-1");
}

#[tokio::test]
async fn status_over_http_on_a_release_image_is_not_sent() {
    let srv = MockServer::start().await;
    status_mock(&srv, 204, 0).await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    let e = f
        .report(&status_report(), &cred(), false)
        .await
        .unwrap_err();
    assert_eq!(
        e.downcast_ref::<StatusNotSent>(),
        Some(&StatusNotSent::Transport)
    );
    assert!(srv.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn status_over_http_on_a_lab_image_is_sent() {
    let srv = MockServer::start().await;
    status_mock(&srv, 204, 1).await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    f.report(&status_report(), &cred(), true).await.unwrap();
}

#[tokio::test]
async fn status_for_another_device_is_not_sent() {
    let srv = MockServer::start().await;
    status_mock(&srv, 204, 0).await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    let other = DeviceCred {
        device_id: "dev-2".into(),
        secret: "S".repeat(43),
    };
    let e = f.report(&status_report(), &other, true).await.unwrap_err();
    assert_eq!(
        e.downcast_ref::<StatusNotSent>(),
        Some(&StatusNotSent::OtherDevice)
    );
    assert!(srv.received_requests().await.unwrap().is_empty());
}

/// A report carrying the device secret never follows a redirect: the secret stays with the
/// configured server.
#[tokio::test]
async fn status_does_not_follow_redirects() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/device/v1/status"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", "/elsewhere"))
        .mount(&srv)
        .await;
    Mock::given(method("POST"))
        .and(path("/elsewhere"))
        .respond_with(ResponseTemplate::new(204))
        .expect(0)
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    assert!(f.report(&status_report(), &cred(), true).await.is_err());
}

#[tokio::test]
async fn status_rejection_is_error() {
    let srv = MockServer::start().await;
    status_mock(&srv, 401, 1).await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), None));
    let e = f.report(&status_report(), &cred(), true).await.unwrap_err();
    assert!(e.downcast_ref::<StatusNotSent>().is_none(), "{e:#}");
}

#[tokio::test]
async fn heartbeat_fetch_outcomes() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/device/v1/heartbeat"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(200).set_body_string("[statement]\n"))
        .up_to_n_times(1)
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/device/v1/heartbeat"))
        .respond_with(ResponseTemplate::new(204))
        .up_to_n_times(1)
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/device/v1/heartbeat"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'a'; 17 * 1024]))
        .up_to_n_times(1)
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/device/v1/heartbeat"))
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
    assert!(big.contains("size limit"), "{big}");
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
        .and(path("/api/device/v1/escrow"))
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
            .and(path("/api/device/v1/escrow"))
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
        .and(path("/api/device/v1/escrow"))
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
        "escrow refused (403): 这台机器的托管凭据与登记的不同",
        "escrow refused (429): 已到上限",
        "escrow refused (500)",
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
            e.starts_with("escrow refused (locally)") && e.contains("https"),
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
            .and(path("/api/device/v1/escrow"))
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
        assert_eq!(e, format!("escrow refused ({code})"));
    }
}

/// 拉包、心跳、回报的重定向：一旦走过 https 就不许降到别的协议（带着 fetch_token 与设置包）。
#[test]
fn redirects_never_downgrade_from_https() {
    use mastersos_agent::fetch::redirect_allowed;
    let u = |s: &str| reqwest::Url::parse(s).unwrap();
    for (prev, next, ok) in [
        (
            vec!["https://a.example/api/device/v1/bundle"],
            "https://b.example/x",
            true,
        ),
        (
            vec!["https://a.example/api/device/v1/bundle"],
            "http://a.example/x",
            false,
        ),
        (
            vec![
                "https://a.example/api/device/v1/bundle",
                "https://a.example/y",
            ],
            "http://127.0.0.1/x",
            false,
        ),
        (
            vec!["http://127.0.0.1:1/api/device/v1/bundle"],
            "http://127.0.0.1:1/x",
            true,
        ),
        (
            vec!["http://127.0.0.1:1/api/device/v1/bundle"],
            "https://a.example/x",
            true,
        ),
        (
            vec!["https://a.example/api/device/v1/bundle"],
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
    assert!(e.starts_with("escrow refused (locally)"), "{e}");
    let e = format!("{:#}", f.renew_token(&identity(), false).await.unwrap_err());
    assert!(e.contains("https"), "{e}");
}

/// Fetcher 的克隆共用同一个令牌与同一个旧令牌标记。
#[tokio::test]
async fn clone_sees_set_token_and_stale() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/device/v1/heartbeat"))
        .and(header("authorization", "Bearer old"))
        .respond_with(ResponseTemplate::new(204).insert_header("x-mastersos-fetch-token", "stale"))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/device/v1/heartbeat"))
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
        .and(path("/api/device/v1/fetch-token"))
        .and(header("authorization", "Bearer old"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"fetch_token": "brand-new"})),
        )
        .up_to_n_times(1)
        .mount(&srv)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/device/v1/fetch-token"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": {"code": "forbidden", "message": "这台机器不能换领新令牌"}
        })))
        .up_to_n_times(1)
        .mount(&srv)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/device/v1/fetch-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"fetch_token": "bad token\n"})),
        )
        .up_to_n_times(1)
        .mount(&srv)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/device/v1/fetch-token"))
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
        RenewOutcome::Refused(m) => assert_eq!(m.to_string(), "这台机器不能换领新令牌"),
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
        .and(path("/api/device/v1/bundle"))
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

use mastersos_agent::fetch::{
    CredRejected, DeviceAuthMissing, DeviceCred, StatusNotSent, Unauthorized,
};
use mastersos_bundle::{InboxResult, InboxResultState};

fn cred() -> DeviceCred {
    DeviceCred {
        device_id: "dev-1".into(),
        secret: "S".repeat(43),
    }
}

#[tokio::test]
async fn fetch_now_reads_the_stale_header() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/device/v1/bundle"))
        .and(query_param("after", "5"))
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
        .and(path("/api/device/v1/bundle"))
        .and(header("authorization", "Bearer good"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Mastersos-Version", "9")
                .set_body_bytes(b"A".to_vec()),
        )
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/device/v1/bundle"))
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
        .and(path("/api/device/v1/push-token"))
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
        .and(path("/api/device/v1/inbox"))
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
            .and(path("/api/device/v1/inbox/7/result"))
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
        .and(path("/api/device/v1/inbox/1/result"))
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
        .and(path("/api/device/v1/bundle"))
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

fn status_report() -> StatusReport {
    StatusReport {
        device_id: "dev-1".into(),
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
        os_pending_version: None,
        quiet_since: None,
        user_config: None,
    }
}

#[test]
fn device_base_keeps_only_the_origin() {
    use mastersos_agent::fetch::device_base;
    for (url, want) in [
        (
            "https://server.example",
            "https://server.example/api/device/v1/",
        ),
        (
            "https://server.example/",
            "https://server.example/api/device/v1/",
        ),
        (
            "http://127.0.0.1:8480",
            "http://127.0.0.1:8480/api/device/v1/",
        ),
        (
            "https://server.example/org/x/devices",
            "https://server.example/api/device/v1/",
        ),
        (
            "https://server.example:8443/a?b=1#c",
            "https://server.example:8443/api/device/v1/",
        ),
        ("not a url/", "not a url/api/device/v1/"),
    ] {
        assert_eq!(device_base(url), want, "{url}");
    }
}

#[tokio::test]
async fn bundle_request_has_no_wait_parameter() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), None));
    f.fetch_now(4).await.unwrap();
    let reqs = srv.received_requests().await.unwrap();
    assert_eq!(reqs[0].url.path(), "/api/device/v1/bundle");
    assert_eq!(reqs[0].url.query(), Some("after=4"));
}

#[tokio::test]
async fn every_route_is_under_the_device_prefix() {
    use mastersos_bundle::diag::{DiagUploadRequest, SupportRequest};
    let srv = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(204))
        .mount(&srv)
        .await;
    // An older seed may still carry a path: it is dropped.
    let f = Fetcher::from_seed(&seed(&format!("{}/org/x/devices/", srv.uri()), Some("tok")));
    // Answers are not the point here (204 is no valid body for some calls); the routes are.
    let _ = f.fetch_now(1).await;
    let _ = f.heartbeat().await;
    let _ = f.report(&status_report(), &cred(), true).await;
    let _ = f.escrow(&escrow_req(), true).await;
    let _ = f.renew_token(&identity(), true).await;
    let _ = f.push_token(&cred(), true).await;
    let _ = f.inbox(&cred(), 0, true).await;
    let done = InboxResult {
        state: InboxResultState::Done,
        detail: None,
    };
    let _ = f.inbox_result(&cred(), 7, &done, true).await;
    let up = DiagUploadRequest::Inbox {
        inbox_seq: 7,
        bytes: 1,
        sha256: "a".repeat(64),
    };
    let _ = f.diag_upload_url(&cred(), &up, true).await;
    let _ = f.diag_complete(&cred(), "d1", true).await;
    let support: SupportRequest = serde_json::from_value(serde_json::json!({
        "client_id": "0192f3a4-5b6c-7d8e-9f00-112233445566", "category": "wifi", "text": "",
        "user": {"kind": "none"}, "session": "login", "created_at": "2026-11-05T00:00:00Z",
        "snapshot": {"os_version": "1"}, "screenshot": false,
    }))
    .unwrap();
    let _ = f.support(&cred(), &support, true).await;

    let mut got: Vec<String> = srv
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    assert!(
        got.iter().all(|p| p.starts_with("/api/device/v1/")),
        "{got:?}"
    );
    got.sort();
    got.dedup();
    let mut want: Vec<String> = [
        "bundle",
        "heartbeat",
        "status",
        "escrow",
        "fetch-token",
        "push-token",
        "inbox",
        "inbox/7/result",
        "diagnostics",
        "diagnostics/d1/complete",
        "support",
    ]
    .iter()
    .map(|r| format!("/api/device/v1/{r}"))
    .collect();
    want.sort();
    assert_eq!(got, want);
}

fn err_json(code: &str) -> serde_json::Value {
    serde_json::json!({"error": {"code": code, "message": "x"}})
}

async fn push_token_error(t: ResponseTemplate) -> anyhow::Error {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/device/v1/push-token"))
        .respond_with(t)
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    f.push_token(&cred(), true).await.unwrap_err()
}

#[tokio::test]
async fn not_available_is_recognised_only_by_its_code() {
    use mastersos_agent::fetch::{NotAvailable, ServerRefused};
    let e =
        push_token_error(ResponseTemplate::new(404).set_body_json(err_json("not_available"))).await;
    assert!(e.downcast_ref::<NotAvailable>().is_some(), "{e:#}");
    for t in [
        ResponseTemplate::new(404).set_body_json(err_json("not_found")),
        ResponseTemplate::new(404).set_body_string("not_available"),
        ResponseTemplate::new(404).set_body_string("<html>not_available</html>"),
    ] {
        let e = push_token_error(t).await;
        assert!(e.downcast_ref::<NotAvailable>().is_none(), "{e:#}");
        assert_eq!(e.downcast_ref::<ServerRefused>().unwrap().status, 404);
    }
    // The code alone is not enough: the status must be 404.
    let e =
        push_token_error(ResponseTemplate::new(503).set_body_json(err_json("not_available"))).await;
    assert!(e.downcast_ref::<NotAvailable>().is_none(), "{e:#}");
}

#[tokio::test]
async fn error_body_with_details_is_parsed() {
    use mastersos_agent::fetch::NotAvailable;
    let e = push_token_error(ResponseTemplate::new(404).set_body_json(serde_json::json!({
        "error": {"code": "not_available", "message": "x", "details": {"a": 1}}
    })))
    .await;
    assert!(e.downcast_ref::<NotAvailable>().is_some(), "{e:#}");
}

#[test]
fn parse_error_body_sanitises() {
    use mastersos_agent::fetch::parse_error_body;
    let long = "a".repeat(400);
    let b = parse_error_body(
        serde_json::json!({"error": {"code": "c-1_x", "message": format!("h\u{7}i\n{long}")}})
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    assert_eq!(b.code, "c-1_x");
    assert!(b.message.starts_with("hia"));
    assert_eq!(b.message.chars().count(), 300);
    for bad in [
        r#"{"error":{"code":"a b","message":"m"}}"#,
        r#"{"error":{"code":"","message":"m"}}"#,
        r#"{"error":"flat"}"#,
        r#"{"message":"m"}"#,
        "<html></html>",
        "",
    ] {
        assert!(parse_error_body(bad.as_bytes()).is_none(), "{bad}");
    }
    let code65 = format!(
        r#"{{"error":{{"code":"{}","message":"m"}}}}"#,
        "a".repeat(65)
    );
    assert!(parse_error_body(code65.as_bytes()).is_none());
}

#[tokio::test]
async fn inbox_404_not_available_is_not_available() {
    use mastersos_agent::fetch::NotAvailable;
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/device/v1/inbox"))
        .respond_with(ResponseTemplate::new(404).set_body_json(err_json("not_available")))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    let e = f.inbox(&cred(), 0, true).await.unwrap_err();
    assert!(e.downcast_ref::<NotAvailable>().is_some(), "{e:#}");
}

async fn inbox_result_404(t: ResponseTemplate) -> anyhow::Error {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/device/v1/inbox/7/result"))
        .respond_with(t)
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    let r = InboxResult {
        state: InboxResultState::Done,
        detail: None,
    };
    f.inbox_result(&cred(), 7, &r, true).await.unwrap_err()
}

#[tokio::test]
async fn inbox_result_404_not_available_is_not_available() {
    use mastersos_agent::fetch::NotAvailable;
    let e =
        inbox_result_404(ResponseTemplate::new(404).set_body_json(err_json("not_available"))).await;
    assert!(e.downcast_ref::<NotAvailable>().is_some(), "{e:#}");
}

#[tokio::test]
async fn inbox_result_404_other_code_is_seq_unknown() {
    use mastersos_agent::fetch::InboxSeqUnknown;
    let e = inbox_result_404(ResponseTemplate::new(404).set_body_json(err_json("not_found"))).await;
    assert!(e.downcast_ref::<InboxSeqUnknown>().is_some(), "{e:#}");
}

#[tokio::test]
async fn escrow_refusal_ignores_a_plain_text_body() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_string("secret mismatch"))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    let e = f.escrow(&escrow_req(), true).await.unwrap_err();
    assert_eq!(format!("{e:#}"), "escrow refused (403)");
}

#[tokio::test]
async fn escrow_refusal_carries_the_json_message() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": {"code": "secret_mismatch", "message": "Secret does not match"}
        })))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    let e = f.escrow(&escrow_req(), true).await.unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "escrow refused (403): Secret does not match"
    );
}

#[tokio::test]
async fn bundle_error_names_status_and_code() {
    use mastersos_agent::fetch::ServerRefused;
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503).set_body_json(err_json("unavailable")))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), None));
    let e = f.fetch_now(0).await.unwrap_err();
    assert_eq!(
        e.downcast_ref::<ServerRefused>(),
        Some(&ServerRefused {
            status: 503,
            code: Some("unavailable".into())
        })
    );
    assert_eq!(e.to_string(), "the server answered 503 unavailable");
}

#[tokio::test]
async fn escrow_refusal_is_typed() {
    use mastersos_agent::fetch::{EscrowRefused, ServerRefused};
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": {"code": "secret_mismatch", "message": "Secret does not match"}
        })))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    let e = f.escrow(&escrow_req(), true).await.unwrap_err();
    let r = e.downcast_ref::<EscrowRefused>().unwrap();
    assert_eq!(
        r.refused,
        ServerRefused {
            status: 403,
            code: Some("secret_mismatch".into())
        }
    );
    assert_eq!(r.message.as_deref(), Some("Secret does not match"));
}

#[tokio::test]
async fn renewal_refusals_are_typed() {
    use mastersos_agent::fetch::{RenewFailed, RenewOutcome, ServerRefused};
    let id = mastersos_agent::seedpart::Identity {
        device_id: "dev-1".into(),
        escrow_secret: "A".repeat(43),
    };
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_json(err_json("not_enrolled")))
        .up_to_n_times(1)
        .mount(&srv)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503).set_body_json(err_json("unavailable")))
        .mount(&srv)
        .await;
    let f = Fetcher::from_seed(&seed(&srv.uri(), Some("tok")));
    match f.renew_token(&id, true).await.unwrap() {
        RenewOutcome::Refused(r) => {
            assert_eq!(r.refused.status, 403);
            assert_eq!(r.refused.code.as_deref(), Some("not_enrolled"));
            assert_eq!(r.to_string(), "x");
        }
        other => panic!("{other:?}"),
    }
    let e = f.renew_token(&id, true).await.unwrap_err();
    let r = e.downcast_ref::<RenewFailed>().unwrap();
    assert_eq!(
        r.refused,
        ServerRefused {
            status: 503,
            code: Some("unavailable".into())
        }
    );
    assert_eq!(e.to_string(), "token renewal failed (503): x");
}

#[test]
fn error_body_without_a_usable_message_is_still_parsed() {
    use mastersos_agent::fetch::parse_error_body;
    for body in [
        r#"{"error":{"code":"not_available","message":null}}"#,
        r#"{"error":{"code":"not_available"}}"#,
        r#"{"error":{"code":"not_available","message":7}}"#,
    ] {
        let b = parse_error_body(body.as_bytes()).expect(body);
        assert_eq!((b.code.as_str(), b.message.as_str()), ("not_available", ""));
    }
}
