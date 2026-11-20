# Protocol v1 A: the agent network layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `mastersos-agent` talks protocol v1 to the server: every device route under one prefix, status always authenticated, `404 not_available` understood, help and diagnostics off in phase 1, and a non-root `protocol-check` subcommand plus a Linux build target the other team uses for the end-to-end run.

**Architecture:** `core/mastersos-agent/src/fetch.rs` stays the only place that builds device URLs and HTTP clients. One constant `DEVICE_PREFIX` and one function `device_base` turn `seed.server_url` (an origin) into the base; every route, the logo URL included, is joined onto it. Error bodies are parsed by one JSON reader that yields the code; `not_available` becomes its own error type that push, inbox and the logo turn into a 6 h wait. `protocol-check` reuses `Fetcher`, `seedpart`, `token` and the bundle verifiers on a directory the caller names, and prints one pinned JSON object.

**Tech Stack:** Rust 2021 (`mastersos-agent`, `mastersos-bundle`), reqwest, tokio, wiremock, clap; `.labtest.yml` builds.

**Spec:** protocol v1 (draft 2 + Erratum 1 and 2, frozen; the server team's copy at commit 4a1a6ab), §2, §3, §8. Its §0 is private: never quote or copy it.

## Blocking questions

None for this plan. Ambiguities to send to the server team (we do not work around them; the plan states what the agent does):

1. §3.9 `GET logos/{file}`: does the route answer `404 not_available` to a request **without** `Authorization`? The logo step runs in the apply worker, which has no fetch token; today the logo is fetched without credentials. If the server answers `401` first, the logo step reports a failure every round until phase 4. (Task 5 assumes 404.)
2. §3.4 `POST status` answers `204`; the agent accepts any `2xx`. Confirm no other success code is used.
3. §3.2 The agent no longer sends `wait=0` (the server ignores `wait`). Confirm `after` is the only query parameter.

## Global Constraints

- Files, comments, errors and script output in English; end-user text only through gettext domain `mastersos-system` (`core/mastersos-agent/src/i18n.rs`, every catalogue in `image/system-i18n/*.po`). This plan adds no end-user text.
- No AI attribution in commits. `python3 -I tools/check-private.py` before every commit. Never write private names: no hostnames other than `server.example` / `*.example` / loopback / `192.0.2.x`, no organisation ids. Say "the remote build runner".
- This Mac cannot build the Rust workspace and local Docker is forbidden: every build and test runs on the remote build runner through the labtest MCP tools (`test_run(path, suites="core", args="-p mastersos-agent <filter>")`; `suites="image-tests", args="check-tree"` for `image/tests/check-tree.sh`). Release the runner with `env_release` when the branch is done.
- `image/patches/authd-oidc/*.patch` are never edited.
- `bash image/tests/check-tree.sh` stays green. No assertion in it names a route or `fetch.rs`; the `support/mod.rs` constants it greps (`SOCKET_PATH`, `QUEUE_DIR`, `SUPPORT_JSON`, `UPLOAD_UNIT`) and `main.rs`'s `Some(OsStr::new("support"))` must stay byte-identical.
- TDD: each task writes failing tests first.
- No compatibility burden: after this plan no code for the old `/v1/...` device paths remains, no token-only status, no plain-text error reading.
- Test fixtures use `https://server.example` (or the wiremock URI) as `server_url`.
- Parallel work: plan B (`docs/plans/2026-11-21-protocol-v1-b-cli-rename.md`) runs at the same time in another worktree. This plan owns `core/mastersos-agent/**`, `core/mastersos-bundle/src/{seed.rs,checks.rs}`, `core/mastersos-installer/tests/**`, `.labtest.yml`, `image/docs/keys.md` lines 202–208. It must not touch `core/Cargo.toml`, `core/Cargo.lock`, `core/mastersos-mcp/**`, `core/mastersos-sign/**`, `README*`, `skills/**`, `tools/**`, `.github/**`, `.gitleaks.toml`, or the other `mastersos-bundle` files (plan B edits comments there). It adds no dependency. Build targets use `--bin` names, not package names, so plan B's crate rename does not break them.
- Worktree branch `feat/protocol-v1-a-agent`; commit per task; do not push.

## Review Focus

1. A reverse proxy in front of the server answers `404` with an HTML or plain body on `push-token`: that is an ordinary failure with the normal backoff, never `not_available` → Task 3 (`not_available_is_recognised_only_by_its_code`).
2. The machine's clock jumps back after the logo step recorded a 6 h wait: the step must not wait for days → Task 5 (`logo_retry_survives_a_clock_jump_back`).
3. A Device whose `identity.json` cannot be read reports every 10 s: no status goes out and the log gets one line per cause, not one per attempt → Task 4 (`no_status_without_device_identity_logs_once`).
4. A seed on an installed Device still has a path (made before this plan): the agent must use the origin with the prefix, not `<path>/api/device/v1/` → Task 2 (`device_base_keeps_only_the_origin`).
5. `protocol-check` run twice on the same DIR must reuse the identity (the server's secret check), and must not write outside DIR → Task 7 (`rerun_reuses_the_identity`, `writes_nothing_outside_dir`).

---

### Task 1: A seed's `server_url` is an origin

**Files:**
- Modify: `core/mastersos-bundle/src/checks.rs` (new fn after `update_mirror`, `:345`)
- Modify: `core/mastersos-bundle/src/seed.rs:100-128` (`validate`, its doc comment: `mastersos seed check` instead of `mastersos-sign seed-check`, and `:153`), test fixtures at `:187,218,366,407,511` (`https://server.example`)
- Modify: `core/mastersos-agent/src/state.rs:117` (doc comment: `mastersos seed check`)
- Modify: `core/mastersos-installer/tests/decisions.rs` fixtures whose seed reaches `validate` with a non-origin `server_url`
- Test: `checks.rs` tests, `seed.rs` tests

**Interfaces:**
- Produces: `pub fn server_origin(url: &str) -> Result<(), String>` in `checks.rs`: `http://` or `https://`, then a host (`is_dns_name`, a dotted IPv4, or `[IPv6]`), optional `:port` (1–65535), optional single trailing `/`; nothing else (no userinfo, path, query or fragment). Hand-parsed like `update_mirror` (the bundle has no URL crate).
- `Seed::validate` calls it first and fails with `BundleError::Invalid("seed server_url: <reason>")`; the reason for a path is `"must be the server origin (scheme, host, optional port), without a path"`.

- [ ] **Step 1: Write the failing tests**
  - `server_origin_accepts_scheme_host_port`: `https://server.example`, `https://server.example/`, `https://server.example:8443`, `http://127.0.0.1:8480`, `http://[::1]:9000` are `Ok`.
  - `server_origin_refuses_path_query_userinfo`: `https://server.example/org/x/devices`, `https://server.example/api/device/v1/`, `https://server.example//`, `https://server.example?x=1`, `https://server.example#f`, `https://u@server.example`, `ftp://server.example`, `server.example`, `https://`, `https://server.example:0`, `https://server.example:65536` are `Err`.
  - `validate_refuses_server_url_with_path` (seed.rs): a seed with `https://server.example/org/x/devices` → `Err`, message contains `server_url` and `without a path`.
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-bundle server_origin validate_refuses")`. Expected: FAIL (function missing).
- [ ] **Step 3: Implement** `server_origin` and the call in `Seed::validate`; update the fixtures listed above and the two doc comments.
- [ ] **Step 4: Run** `test_run(suites="core", args="-p mastersos-bundle -p mastersos-installer")`. Expected: PASS (fix any installer fixture the run names).
- [ ] **Step 5: Commit** `feat(bundle): a seed's server_url is the server origin`.

### Task 2: Every device route under `/api/device/v1/`

**Files:**
- Modify: `core/mastersos-agent/src/fetch.rs` (module doc `:1-7`; `Fetcher::new` `:263-275`; `base` `:316-318`; every `format!("{}/v1/…")`: `fetch_now` `:340`, `heartbeat` `:384`, `escrow` `:419`, `renew_token` `:460`, `push_token` `:510`, `inbox` `:532`, `inbox_result` `:557`, `device_request` `:597`, `report` `:623`, `diag_upload_url` `:668`, `diag_complete` `:738`, `support` `:775`; the `const STEP` texts)
- Modify: `core/mastersos-agent/src/system/branding.rs:15,281` (the logo URL comes from `fetch::logo_url`)
- Modify (route strings in tests and doc comments only): `core/mastersos-agent/tests/fetch.rs`, `tests/diag_upload.rs`, `src/inbox.rs:694-726`, `src/push.rs`, `src/run.rs`, `src/luks.rs`, `src/luks/tests.rs`, `src/status/tests.rs`, `src/support/{mod.rs,send.rs,send/tests.rs,store.rs}`, `src/upload/{drain.rs,drain/tests.rs}`, `src/diag/upload.rs`, `src/system/branding.rs` tests `:627,716-717`
- Modify: `image/docs/keys.md:202,208` (`POST /api/device/v1/escrow`, `POST /api/device/v1/fetch-token`)

**Interfaces:**
- Produces (fetch.rs):
  - `pub const DEVICE_PREFIX: &str = "/api/device/v1/";`
  - `pub fn device_base(server_url: &str) -> String`: `scheme://host[:port]` of `server_url` (path, query and fragment dropped, via `reqwest::Url`) + `DEVICE_PREFIX`. An unparsable URL gives `server_url` trimmed of `/` + `DEVICE_PREFIX` (requests then fail as today).
  - `Fetcher::base(&self) -> &str` returns that base (ends with `/`); a private `fn url(&self, route: &str) -> String` joins a route without a leading slash (`"bundle"`, `"inbox/7/result"`, `"diagnostics/{id}/complete"`).
  - `pub fn logo_url(server_url: &str, sha256: &str) -> String` = `device_base(server_url)` + `logos/<sha256>.png`.
  - `fetch_now(after)` sends `GET bundle?after=N` only (no `wait`).
  - Error and context texts name the route without the prefix: `"request to bundle failed"`.
- `escrow_transport_ok(self.base(), lab)` keeps working (the base is still a full URL).

- [ ] **Step 1: Write the failing tests** (tests/fetch.rs unless named)
  - `device_base_keeps_only_the_origin`: `https://server.example` and `https://server.example/` → `https://server.example/api/device/v1/`; `http://127.0.0.1:8480` → `http://127.0.0.1:8480/api/device/v1/`; `https://server.example/org/x/devices` → `https://server.example/api/device/v1/`.
  - `every_route_is_under_the_device_prefix`: one call of each `Fetcher` method against one wiremock server that answers `204`/`200` to everything; every received path starts with `/api/device/v1/`, and the set of paths equals `{bundle, heartbeat, status, escrow, fetch-token, push-token, inbox, inbox/7/result, diagnostics, diagnostics/d1/complete, support}` under the prefix.
  - `bundle_request_has_no_wait_parameter`: the query of `GET bundle` is exactly `after=4`.
  - `inbox_requests_use_the_device_prefix` (inbox.rs, replaces `requests_are_joined_under_a_server_url_with_a_path`).
  - branding: `logo_url_is_under_the_device_prefix` (`logo_url("https://mdm.example", H)` = `https://mdm.example/api/device/v1/logos/H.png`).
  - Every existing `path("/v1/…")` matcher becomes `path("/api/device/v1/…")`.
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-agent")`. Expected: FAIL on the new tests and the moved matchers.
- [ ] **Step 3: Implement** the constant, `device_base`, `url`, `logo_url`, and move every route; update `keys.md`.
- [ ] **Step 4: Run** `test_run(suites="core", args="-p mastersos-agent")`. Expected: PASS. `git grep -n '"/v1/\|/v1/' core/mastersos-agent` shows nothing.
- [ ] **Step 5: Commit** `feat(agent): device routes under /api/device/v1/`.

### Task 3: JSON error bodies and `not_available`

**Files:**
- Modify: `core/mastersos-agent/src/fetch.rs` (`read_error_message` `:1048-1065` and `unauthorized_kind` `:1068-1085` are replaced; `escrow`, `renew_token`, `push_token`, `inbox`, `inbox_result`, `fetch_bundle`, `heartbeat`, `report`, `api_failure` use the new reader)
- Test: `core/mastersos-agent/tests/fetch.rs`

**Interfaces:**
- Produces (fetch.rs):
  - `pub const NOT_AVAILABLE: &str = "not_available";`
  - `pub struct ErrorBody { pub code: String, pub message: String }`; `pub fn parse_error_body(body: &[u8]) -> Option<ErrorBody>`: only `{"error":{"code":<string>,"message":<string>}}` (unknown fields ignored); `code` kept only if it matches `[A-Za-z0-9_-]{1,64}`, `message` with control characters removed, at most 300 characters. Anything else (HTML, text, other JSON) is `None`: no body text ever reaches a message.
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub struct NotAvailable;` (`Display`: `the server does not offer this yet (404 not_available)`), returned exactly when the status is `404` **and** the parsed code is `not_available`.
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct ServerRefused { pub status: u16, pub code: Option<String> }` (`Display`: `the server answered <status>` + ` <code>` when present): the error of every non-success answer that is not one of the typed errors (`Unauthorized`, `DeviceAuthMissing`, `CredRejected`, `InboxSeqUnknown`, `NotAvailable`). Task 7 reads `status`/`code` from it.
  - Escrow and renewal refusals keep their sentence and append the JSON `message` when there is one: `escrow refused (403): <message>`; without a JSON body: `escrow refused (403)`.
  - Classification: `push_token` 404+`not_available` → `NotAvailable`; `inbox` the same, 401 `device_auth_missing` → `DeviceAuthMissing`, other 401 → `Unauthorized`; `inbox_result` 404+`not_available` → `NotAvailable`, any other 404 → `InboxSeqUnknown` (unchanged meaning), 409 → `ResultAck::Refused`; `api_failure` (diagnostics, support) maps 404+`not_available` to `ErrorAction::Backoff` with detail `"<step>: not available on this server"`.

- [ ] **Step 1: Write the failing tests**
  - `not_available_is_recognised_only_by_its_code`: `push-token` answering 404 with `{"error":{"code":"not_available","message":"x"}}` → `downcast_ref::<NotAvailable>()` is `Some`; 404 with `{"error":{"code":"not_found","message":"x"}}`, 404 with text body `not_available`, 404 with `<html>not_available</html>` → `None` (and `ServerRefused { status: 404, .. }`).
  - `inbox_404_not_available_is_not_available`; `inbox_result_404_not_available_is_not_available`; `inbox_result_404_other_code_is_seq_unknown` (code `not_found` → `InboxSeqUnknown`).
  - `escrow_refusal_ignores_a_plain_text_body`: 403 with body `secret mismatch` → error text exactly `escrow refused (403)`.
  - `escrow_refusal_carries_the_json_message`: 403 `{"error":{"code":"secret_mismatch","message":"Secret does not match"}}` → `escrow refused (403): Secret does not match`.
  - `bundle_error_names_status_and_code`: 503 `{"error":{"code":"unavailable","message":"m"}}` → `ServerRefused { status: 503, code: Some("unavailable") }`.
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-agent --test fetch")`. Expected: FAIL.
- [ ] **Step 3: Implement**; delete `read_error_message` and `unauthorized_kind`.
- [ ] **Step 4: Run** `test_run(suites="core", args="-p mastersos-agent")`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): JSON error bodies and not_available`.

### Task 4: Status always carries the device credential

**Files:**
- Modify: `core/mastersos-agent/src/fetch.rs:609-633` (`report`)
- Modify: `core/mastersos-agent/src/run.rs:1436-1451` (`Agent::report`), `Agent` fields near `:835`
- Test: `core/mastersos-agent/tests/fetch.rs` (replace the token-only status tests around `:95-200`), `run.rs` tests

**Interfaces:**
- Produces:
  - `pub async fn report(&self, r: &StatusReport, cred: &DeviceCred, lab: bool) -> Result<()>` in fetch.rs: always through `device_request` (no redirects, both device headers); refused locally, before any request, with `StatusNotSent::Transport` when `secret_transport(lab)` fails, and with `StatusNotSent::OtherDevice` when `r.device_id != cred.device_id`.
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum StatusNotSent { NoIdentity, Transport, OtherDevice }` (an `Error`; `Display`: `no status sent: no device identity` / `… the device secret may not travel over this transport (https only; http on lab images)` / `… the report names another device`).
  - `Agent::report`: without `device_cred()` returns `Err(StatusNotSent::NoIdentity)` with no request; logs a `warn` line only when the cause differs from the last logged one (field `status_not_sent: Option<StatusNotSent>`, cleared after a report is sent).

- [ ] **Step 1: Write the failing tests**
  - `status_always_carries_the_device_headers`: the mock receives `x-mastersos-device: dev-1`, `x-mastersos-device-secret: <secret>`, `authorization: Bearer <token>`.
  - `status_over_http_on_a_release_image_is_not_sent`: `http://127.0.0.1:<port>` with `lab = false` → 0 requests reach the mock; error downcasts to `StatusNotSent::Transport`.
  - `status_over_http_on_a_lab_image_is_sent`.
  - `status_for_another_device_is_not_sent`.
  - run.rs: `no_status_without_device_identity_logs_once`: an agent without identity calls `report()` three times → 0 requests, `status_not_sent == Some(NoIdentity)`, and the logged-once flag set after the first call.
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-agent status")`. Expected: FAIL (signature).
- [ ] **Step 3: Implement**; remove the token-only branch.
- [ ] **Step 4: Run** `test_run(suites="core", args="-p mastersos-agent")`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): status is always sent with the device credential`.

### Task 5: `not_available` waits 6 h (push, inbox, logo)

**Files:**
- Modify: `core/mastersos-agent/src/fetch.rs` (constant; `pub async fn fetch_logo`), `core/mastersos-agent/src/push.rs:478-503` (token error branch), `core/mastersos-agent/src/run.rs:1341-1360` (`maybe_sync_inbox` error branch)
- Modify: `core/mastersos-agent/src/system/branding.rs` (`LogoFetcher`, `HttpFetcher`, `Image::sync`, `apply`, `sync_files`), `core/mastersos-agent/src/system/mod.rs:116` (`SysState`)
- Test: `push.rs`, `run.rs`, `branding.rs` tests

**Interfaces:**
- Produces:
  - `pub const NOT_AVAILABLE_RETRY: Duration = Duration::from_secs(6 * 3600);` waits are `backoff::jittered(NOT_AVAILABLE_RETRY, jitter.unit())` (factor 0.8–1.2 = ±20 %).
  - `pub enum LogoFetch { Png(Vec<u8>), NotAvailable }`; `pub async fn fetch_logo(url: &str) -> Result<LogoFetch>` in fetch.rs (the code of today's `HttpFetcher`, plus the `not_available` check; 128 KiB cap, 20 s). `LogoFetcher::fetch(&self, url: &str) -> Result<LogoFetch>`.
  - `SysState`: `#[serde(default)] pub logo_retry_after: Option<chrono::DateTime<chrono::Utc>>`.
- Behaviour:
  - push: `NotAvailable` → status event `passed("not offered by the server yet")` (the existing `passed` helper), `failures` unchanged, `log::info`, wait as above.
  - inbox: `NotAvailable` → `inbox_retry = later(wait)`, `inbox_attempt` unchanged, `log::info` (no `warn`), `sync_inbox = true`.
  - logo: before a download, `now < logo_retry_after` and `logo_retry_after - now <= 7.2 h` → no download, no problem pushed, the cached file is kept if it matches, else no logo. `NotAvailable` → `logo_retry_after = now + wait`, no problem pushed. A `Png` that matches clears `logo_retry_after`. Any other failure keeps today's behaviour (problem pushed). `apply` takes `now: DateTime<Utc>` (callers pass `Utc::now()`).

- [ ] **Step 1: Write the failing tests**
  - push.rs `push_token_not_available_waits_six_hours_without_failure` (tokio paused time, `Jitter::fixed(0.5)`): first status is ok with detail `not offered by the server yet`; after `6h - 1s` the mock saw 1 request; after `6h + 1s` it saw 2.
  - run.rs `inbox_not_available_retries_in_six_hours`: with `Jitter::fixed(0.5)`, `inbox_retry` is within 1 s of now + 6 h and `inbox_attempt == 0`.
  - branding `logo_not_available_keeps_cache_and_reports_ok` (cached PNG matching the hash stays, item ok); `logo_not_available_without_cache_shows_no_logo` (`branding.json` `logo: null`, item ok); `logo_not_available_waits_before_retrying` (second `apply` 1 h later: fetcher not called); `logo_retry_survives_a_clock_jump_back` (`logo_retry_after` 3 days ahead of `now` → fetcher called); `logo_other_404_is_a_failure` (fetcher `Err` → item failed, as today).
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-agent not_available logo_")`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `test_run(suites="core", args="-p mastersos-agent")`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): wait 6 h when the server does not offer push, inbox or logos yet`.

### Task 6: Phase 1 hides "Get help" and sends no help request or diagnostics

**Files:**
- Modify: `core/mastersos-agent/src/support/mod.rs:69-85` (the step), new constant after `:44`
- Modify: `core/mastersos-agent/src/upload/drain.rs:581` (`drain_main`)
- Modify: `core/mastersos-agent/src/inbox.rs` (`InboxCtx` gains `help_available: bool`; `collect_diagnostics` `:283`), `core/mastersos-agent/src/run.rs:1365-1386` (`inbox_ctx` passes the constant)
- Test: `support/tests.rs`, `upload/drain/tests.rs`, `inbox.rs` tests

**Interfaces:**
- Produces: `pub const HELP_AVAILABLE: bool = false;` in `support/mod.rs`, doc: protocol v1 phase 1 offers no help requests or diagnostics (§3.9); the release that implements phase 3 sets it to `true`. `pub fn support_enabled(config_enabled: bool, help_available: bool) -> bool` (logical and); the step writes `{"enabled": support_enabled(ctx.config.support_enabled, HELP_AVAILABLE)}`.
- `drain_main`: with `!HELP_AVAILABLE` logs one `info` line and returns `Ok(())` before reading the identity; nothing is sent, the queue stays. (`drain`/`drain_once` unchanged, so their tests keep running.)
- `collect_diagnostics` with `!cx.help_available` acks `failed` with detail `diagnostics are not available in this release` and runs nothing. Existing collect tests set `help_available: true`.

- [ ] **Step 1: Write the failing tests:** `support_json_is_off_in_phase_1_even_when_enabled` (Config with `support_enabled = true` → file says `{"enabled":false}`), `support_enabled_is_both`, `drain_main_sends_nothing_in_phase_1` (queue with a `support` item, mock server gets 0 requests, item still listed), `collect_is_refused_when_help_is_unavailable`.
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-agent support drain collect")`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `test_run(suites="core", args="-p mastersos-agent")` and `test_run(suites="image-tests", args="check-tree")`. Expected: PASS (check-tree §69/§70 unchanged).
- [ ] **Step 5: Commit** `feat(agent): phase 1 hides Get help and sends no diagnostics`.

### Task 7: The `protocol-check` engine

**Files:**
- Create: `core/mastersos-agent/src/protocol_check.rs` (+ `pub mod protocol_check;` in `src/lib.rs`)
- Modify: `core/mastersos-agent/src/fetch.rs` (exchange recorder)
- Test: `core/mastersos-agent/tests/protocol_check.rs` (uses `mastersos_bundle::testutil` to sign bundles and heartbeats)

**Interfaces:**
- Consumes: `device_base`, `NotAvailable`, `ServerRefused`, `StatusNotSent` (Tasks 2–4); `seedpart::{import_if_fresh, load_or_create_identity}`; `token::save`; `mastersos_bundle::{Seed, accept_for_school, accept_update_for_school, verify_heartbeat, seal, recipients_fp, is_recovery_key, is_luks_uuid, EscrowRequest}`; `report::SUPPORTED_FEATURES`.
- Produces (fetch.rs): `pub struct Exchange { pub method: &'static str, pub route: String, pub status: Option<u16> }` and `Fetcher::with_recorder(self, rec: Arc<Mutex<Vec<Exchange>>>) -> Fetcher`; every request goes through one private `send` helper that appends `(method, path-and-query after the host, status or None)` when a recorder is set. The production agent never sets one.
- Produces (protocol_check.rs):
  - `pub struct CheckInput { pub seed: PathBuf, pub dir: PathBuf, pub recovery_key: Option<PathBuf>, pub luks_uuid: Option<String> }`
  - `pub async fn run_check(input: &CheckInput, now: DateTime<Utc>) -> CheckReport`
  - `#[derive(Serialize)] pub struct CheckReport` and `pub struct Call`, serialised exactly as below (keys always present, in this order).
- Layout, the only paths written: `DIR/seed-partition/` (0700; `seed.toml` copied from `--seed` on the first run, `identity.json`, `fetch-token`) and `DIR/state/` (0700; `seed.toml` from the import, `fetch-token` after a renewal). DIR is created 0700 if missing. Re-runs reuse both.
- Transport: `lab` = `server_url` is `http://` to `127.0.0.1`, `::1` or `localhost` (§2); any other `http://` refuses status, escrow and renewal locally like a release image.
- Steps, in order (one `Call` per HTTP exchange):
  1. `seed_import`: `Seed::parse` + `Seed::validate`, copy, `import_if_fresh`, `load_or_create_identity(seed-partition, None)`. Failure ends the run.
  2. `bundle`: `after = min_version - 1` (0 without `min_version`); `GET bundle?after=N` until `204`, a failure, or 1000 rounds. The first archive verifies with `accept_for_school(archive, seed.trust, None, seed.school_id)` and must have `version >= min_version`; later ones with `accept_update_for_school(archive, trust, Some(recipients), Some(cur), school)`; `X-Mastersos-Version` must equal the manifest's `version`.
  3. `heartbeat`: `GET heartbeat`; `200` → `verify_heartbeat` with the latest verified trust (seed trust when none), statement `version` and `digest_hex` must equal the latest verified bundle; `204` is ok with detail `no heartbeat`.
  4. `status`: a `StatusReport` with `device_id`, `agent_version = env!("CARGO_PKG_VERSION")`, `bundle_version` = latest verified, `group` = `select(...)` of that bundle (else seed group or `default`), `manifest_features = SUPPORTED_FEATURES`, `seed_trust_fingerprints`, `results = [ok("protocol-check")]`, other fields empty/false; sent with the credential.
  5. `escrow`: skipped without `--recovery-key`; else key (`is_recovery_key`) and `--luks-uuid` (`is_luks_uuid`) sealed to the latest verified `[school].escrow_recipients` (none → `ok: false`, `error_code: "verify_failed"`, detail `the settings name no escrow recipients`), `EscrowRequest` built as `luks.rs` builds it.
  6. `fetch_token`: skipped unless `token_is_stale()`; else `renew_token`; `New(t)` → `token::save(state, seed-partition, t)`, `set_token`.
  7. `fetch_token_check`: only after a renewal: one `GET heartbeat`; ok iff the answer is 2xx and the token is no longer stale.
- JSON (pinned; the other team consumes it):

```json
{
  "protocol_check": 1,
  "agent_version": "0.2.0",
  "server_url": "https://server.example",
  "device_id": "5b1e…",
  "ok": true,
  "calls": [
    {"step": "seed_import", "route": null, "status": null, "ok": true, "skipped": false, "error_code": null, "version": null, "detail": "imported; trust rk-1a2b3c4d; min_version 3"},
    {"step": "bundle", "route": "GET /api/device/v1/bundle?after=2", "status": 200, "ok": true, "skipped": false, "error_code": null, "version": 3, "detail": "verified; signed by rk-1a2b3c4d"},
    {"step": "bundle", "route": "GET /api/device/v1/bundle?after=3", "status": 204, "ok": true, "skipped": false, "error_code": null, "version": null, "detail": "no newer version"},
    {"step": "heartbeat", "route": "GET /api/device/v1/heartbeat", "status": 200, "ok": true, "skipped": false, "error_code": null, "version": 3, "detail": "verified; not_after 2026-12-20T09:00:00Z"},
    {"step": "status", "route": "POST /api/device/v1/status", "status": 204, "ok": true, "skipped": false, "error_code": null, "version": null, "detail": ""},
    {"step": "escrow", "route": "POST /api/device/v1/escrow", "status": 204, "ok": true, "skipped": false, "error_code": null, "version": null, "detail": ""},
    {"step": "fetch_token", "route": null, "status": null, "ok": true, "skipped": true, "error_code": null, "version": null, "detail": "the token is not stale"}
  ]
}
```

  - `route`: method, space, path and query exactly as sent (no scheme or host); `null` when no request was made. `status`: the HTTP status, `null` without an answer. `error_code`: the server's `error.code`, else one local code: `network` (no answer), `local_refused` (`StatusNotSent`, transport), `verify_failed` (signature, school, version, heartbeat), `invalid_answer` (missing header, bad JSON), `bad_input` (seed, recovery key or LUKS UUID). `version`: the settings version the entry is about, else `null`. Top-level `ok`: every entry `ok`. `device_id`: `null` when `seed_import` failed.

- [ ] **Step 1: Write the failing tests** (tests/protocol_check.rs, wiremock)
  - `full_cycle_against_a_mock_server`: versions 3 and 4 (4 rotates trust, signed by a key of 3), heartbeat for 4 with `X-Mastersos-Fetch-Token: stale`, status 204, escrow 204, fetch-token 200, then heartbeat without the stale header → `calls` as `(step, route, status, ok)` exactly: seed_import, bundle `?after=2` 200, bundle `?after=3` 200, bundle `?after=4` 204, heartbeat 200, status 204, escrow 204, fetch_token 200, fetch_token_check 200; `ok == true`; the status request carried both device headers and `manifest_features` equal to `SUPPORTED_FEATURES`.
  - `json_shape_is_pinned`: a fixed `CheckReport` serialises to exactly the keys and order above (compare `serde_json::to_value` with a literal).
  - `bundle_signed_by_an_unknown_key_fails_the_bundle_step`: entry `ok: false`, `error_code: "verify_failed"`; heartbeat and status entries still present; top-level `ok: false`.
  - `escrow_skipped_without_a_recovery_key`; `escrow_without_recipients_is_not_ok`.
  - `not_available_and_server_errors_carry_the_code`: status answers 401 `device_auth_missing` → `error_code: "device_auth_missing"`, `status: 401`.
  - `rerun_reuses_the_identity`: two runs on one DIR send the same `x-mastersos-device` and secret.
  - `writes_nothing_outside_dir`: HOME and TMPDIR pointed at an empty temp dir stay empty; DIR holds only `seed-partition/` and `state/`.
  - `plain_http_to_a_non_loopback_host_is_refused_locally`: seed `http://192.0.2.1:8480` (unreachable) → status entry `error_code: "local_refused"`, `route: null`.
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-agent --test protocol_check")`. Expected: FAIL (module missing).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `test_run(suites="core", args="-p mastersos-agent")`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): protocol-check runs one network cycle and reports each call`.

### Task 8: The subcommand and the Linux build target

**Files:**
- Modify: `core/mastersos-agent/src/main.rs:35-62` (`Cmd::ProtocolCheck`) and the dispatch
- Modify: `.labtest.yml` (new top-level `builds:`)
- Test: `core/mastersos-agent/tests/cli_protocol_check.rs`

**Interfaces:**
- Consumes: Task 7 `run_check`, `CheckReport`.
- Produces: `mastersos-agent protocol-check --seed FILE --state DIR [--json] [--recovery-key FILE --luks-uuid UUID]` (clap: `--luks-uuid` `requires = "recovery_key"` and vice versa). It never reads the global `--state-dir`/`--seed-dir`, needs no root, logs to stderr, prints the JSON (with `--json`) or one line per call (`<step> <route|-> <status|-> ok|FAIL|skipped <detail>`) on stdout. Exit 0 when `ok`, 1 otherwise, 2 on usage errors (clap).
- `.labtest.yml`:

```yaml
builds:
  linux-bins:
    setup: rustup toolchain install 1.98 --profile minimal
    setup_key: [.labtest.yml, core/rust-toolchain.toml]
    run: cd core && cargo build --locked --release --bin mastersos --bin mastersos-agent
    artifacts: [core/target/release/mastersos, core/target/release/mastersos-agent]
    mem: 6G
    cpus: 8
    timeout: 40m
```

- [ ] **Step 1: Write the failing tests:** `protocol_check_prints_one_json_object_and_exits_0` (binary `env!("CARGO_BIN_EXE_mastersos-agent")` against a wiremock serving one version: stdout is one JSON object with `"protocol_check": 1`, exit 0); `protocol_check_exits_1_when_a_call_fails` (status 500); `luks_uuid_without_recovery_key_is_a_usage_error` (exit 2).
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-agent --test cli_protocol_check")`. Expected: FAIL.
- [ ] **Step 3: Implement** the subcommand; add `builds:` to `.labtest.yml`.
- [ ] **Step 4: Run** `test_run(suites="core")` (whole workspace, fmt, clippy), `test_run(suites="image-tests", args="check-tree")`, then `build_run(path, targets="linux-bins", wait_s=…)`. Expected: PASS; `.labtest-out/linux-bins/core/target/release/{mastersos,mastersos-agent}` exist and `file` reports `ELF 64-bit LSB … x86-64`.
- [ ] **Step 5: Commit** `feat(agent): mastersos-agent protocol-check and the linux-bins build`.

---

## Self-review notes

- §3.7 prefix → Task 2; `Seed::validate` → Task 1; status credential → Task 4; JSON errors → Task 3; §3.9 6 h and help gate → Tasks 5–6; §8 agent `Fetcher` run → Tasks 7–8.
- Reserved routes per the server team: push-token, inbox, inbox result, diagnostics, diagnostics complete, support, logos — all covered by Tasks 3 and 5 (diagnostics and support are also gated off by Task 6).
- After merge of plans A and B, the end-to-end list of protocol §8 runs from plan C, using `linux-bins`.
