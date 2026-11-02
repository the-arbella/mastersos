//! m6（Ruling 27）：agent 的每个 HTTP 客户端都由 `fetch.rs` 的两个函数构造，跟随重定向的那个
//! 一律带不降级的重定向策略。

use std::path::{Path, PathBuf};
use std::time::Duration;

use mastersos_agent::fetch::{http_client, HttpOpts};
use wiremock::matchers::path_regex;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// `src` 里 `name` 这个函数体的字节范围（从签名起到配对的右花括号）。
fn fn_body(src: &str, sig: &str) -> std::ops::Range<usize> {
    let start = src
        .find(sig)
        .unwrap_or_else(|| panic!("fetch.rs 里没有 {sig}"));
    let open = start + src[start..].find('{').unwrap();
    let mut depth = 0;
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return start..open + i + 1;
                }
            }
            _ => {}
        }
    }
    panic!("{sig} 的花括号不配对");
}

/// 第一个测试模块（`#[cfg(test)]` 之后、跳过空白紧跟 `mod `）的起点；没有就是文件末尾。
fn test_mod_start(text: &str) -> usize {
    let mut from = 0;
    while let Some(i) = text[from..].find("#[cfg(test)]") {
        let at = from + i;
        let rest = text[at + "#[cfg(test)]".len()..].trim_start();
        if rest.starts_with("mod ")
            || rest.starts_with("pub mod ")
            || rest.starts_with("pub(crate) mod ")
        {
            return at;
        }
        from = at + 1;
    }
    text.len()
}

#[test]
fn test_mod_start_skips_single_cfg_test_items() {
    let src = "a\n#[cfg(test)]\nfn helper() {}\nb\n#[cfg(test)]\nmod tests;\n";
    assert_eq!(
        &src[..test_mod_start(src)],
        "a\n#[cfg(test)]\nfn helper() {}\nb\n"
    );
    assert_eq!(test_mod_start("x"), 1);
}

#[test]
fn only_fetch_rs_builds_http_clients() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = vec![];
    rust_files(&src_dir, &mut files);
    files.sort();
    let mut bad = vec![];
    let mut allowed_hits = 0;
    for f in files {
        if f.file_name().is_some_and(|n| n == "tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&f).unwrap();
        // 只截掉测试模块（`#[cfg(test)]` 后面紧跟 `mod `）；`#[cfg(test)] fn …` 之类的单个条目之后
        // 仍是生产代码（例如 state.rs），照样要扫。
        let prod = &text[..test_mod_start(&text)];
        let is_fetch = f == src_dir.join("fetch.rs");
        let allowed: Vec<std::ops::Range<usize>> = if is_fetch {
            vec![
                fn_body(prod, "pub fn http_client("),
                fn_body(prod, "fn no_redirect_client("),
            ]
        } else {
            vec![]
        };
        for needle in [
            "Client::builder(",
            "Client::new(",
            "ClientBuilder",
            "reqwest::get(",
        ] {
            for (at, _) in prod.match_indices(needle) {
                // Part of a longer name (rumqttc's `AsyncClient::new`, the MQTT client): not reqwest.
                if prod[..at]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
                {
                    continue;
                }
                if allowed.iter().any(|r| r.contains(&at)) {
                    allowed_hits += 1;
                    continue;
                }
                let line = prod[..at].lines().count();
                bad.push(format!("{}:{line}: {needle}", f.display()));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "只有 fetch.rs 的 http_client / no_redirect_client 能构造客户端：\n{}",
        bad.join("\n")
    );
    assert_eq!(allowed_hits, 2, "两个构造函数各构造一次");
}

/// 每次都 302 到下一个路径。
struct Loop;

impl Respond for Loop {
    fn respond(&self, r: &Request) -> ResponseTemplate {
        let n: u32 = r.url.path().trim_start_matches("/r/").parse().unwrap_or(0);
        ResponseTemplate::new(302).insert_header("location", format!("/r/{}", n + 1))
    }
}

#[tokio::test]
async fn http_client_uses_custom_redirect_policy() {
    let srv = MockServer::start().await;
    Mock::given(path_regex("^/r/"))
        .respond_with(Loop)
        .mount(&srv)
        .await;
    let c = http_client(HttpOpts {
        connect: Duration::from_secs(5),
        read: None,
        total: Some(Duration::from_secs(20)),
    });
    let e = c
        .get(format!("{}/r/0", srv.uri()))
        .send()
        .await
        .unwrap_err();
    let mut chain = format!("{e}");
    let mut src = std::error::Error::source(&e);
    while let Some(s) = src {
        chain.push_str(&format!(" / {s}"));
        src = s.source();
    }
    assert!(chain.contains("重定向被拒"), "{chain}");
    // 跟随 MAX_REDIRECTS - 1 = 9 次之后再遇到重定向就停（reqwest 默认是 10 次、报错文字不同）。
    assert_eq!(srv.received_requests().await.unwrap().len(), 10);
}
