# Protocol v1 C: the `mastersos` command line speaks protocol v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every server command of `mastersos` uses the CLI API of protocol v1 (`/api/cli/v1/`): credentials from `arbella` or `mastersos login`, the frame computed by the Devices' parser, two-step publish signed locally, heartbeats, recovery keys, and seeds made and checked from the verified chain; plus the lab acceptance scripts, the skill, the docs and the cross-language end-to-end list.

**Architecture:** One new client module (`server.rs`) replaces both old API clients: it joins routes onto `<origin>/api/cli/v1/schools/{school}/mastersos/`, reads the JSON error envelope, and retries once with a step-up token on `401 step_up_required`. Credentials come from `auth/` (the `arbella` helper, or a stored login made with the device grant and a loopback PKCE step-up). The frame lives in `mastersos-bundle` beside `features_used`, so it is computed by the same code Devices run. The chain verifier, publish, heartbeat, recovery and seed code keep their local checks and change only their transport and routes.

**Tech Stack:** Rust 2021 (`mastersos-cli`, `mastersos-bundle`), reqwest, tokio, clap, wiremock, ring (PKCE, state), serde_json; bash for the lab scripts and the end-to-end script.

**Spec:** protocol v1 (frozen; draft 2 + Erratum 1 and 2; the server team's copy at commit 4a1a6ab), §1, §2, §4, §6, §8. Its §0 is private: never quote or copy it. Builds on plans A and B (`docs/plans/2026-11-21-protocol-v1-a-agent.md`, `…-b-cli-rename.md`): start after both are merged.

## Blocking questions

Parts marked **BLOCKED (B1)** or **BLOCKED (B2)** below are not implemented until the server team answers; everything else proceeds.

- **B1 (§6 "school name", §4.1 phase 0 rules).** The response shape of `GET /api/cli/v1/schools` is not in the protocol text (which fields carry the organisation id and its name; a list or an object). Without it the CLI cannot stamp `[school] name` at publish (Task 6 Step 3b) or offer a school choice at `init`. Until answered, `init` requires `--school <uuid>` (the id is needed anyway) and publish leaves `[school] name` as written.
- **B2 (§6 `auth-config`, `audience`).** The text says the device grant runs "with `client_id`, `audience` and `scopes`" but not which request parameter carries `audience` (an `audience=` form parameter, RFC 8707 `resource=`, or none because the client is bound to it), nor whether the loopback authorization request carries it too. Stops: the standalone `mastersos login` device grant and loopback step-up (Task 3 Steps 3b–3c). The `arbella` path is not affected.

Ambiguities found (the plan's choice in brackets; the server team confirms, we do not work around a different answer):

1. §4.3 `features_used` and `format_<n>` for a `format = 1` text [no `format_1` is sent; `format_2`/`format_3` are added for formats 2 and 3, since agents report only those].
2. §4.2 `POST keys/probe` and §4.9 `POST seed` request bodies [no body, `Content-Length: 0`].
3. §4.1 CLI error envelope [`{"error":{"code","message","details"?}}`; `details` is read when present, as §4.4 and §4.5 show].
4. §4.2 `trust_key.public_key` and `signature.sig` encoding [standard base64 with padding, as in `TrustKey` and `SignatureFile`].
5. §4.3/§4.4 `issued_at` with `Z` as the offset [`2026-11-20T02:00:00Z`].
6. §6 `arbella auth token --step-up --json` output shape [same three fields as without `--step-up`]; `expires_at` format [RFC 3339].
7. §3.1/§4.9 exact fetch-token format: **open item, ask the server team**. `seed check` validates only the §3.1 shape (printable ASCII without spaces, 1–256 bytes) and treats the token as opaque.

Server-team answers used here (2026-11-20): `POST seed` returns exactly `{"server_url","school_id","fetch_token"}`; production `auth-config` has `client_id`, `scopes ["openid","email","offline_access"]` and `step_up_acr: ""` (empty is the main path; tokens carry `auth_time`, no `acr`); feature names are opaque to the server; their e2e wants the non-interactive mode pinned in Task 9.

## Global Constraints

- Files, comments, errors and script output in English; end-user (Device) text only through gettext (`image/system-i18n/*.po`, every catalogue). CLI output is English (school IT tool, not localised).
- No AI attribution in commits. `python3 -I tools/check-private.py` before every commit. No private names in files: tests and docs use `https://server.example` and `https://issuer.example`; no organisation ids (use `0192f3a4-5b6c-7d8e-9f00-112233445566`, already in `seed.rs` tests); say "the remote build runner"; never write the private section's content.
- This Mac cannot build the Rust workspace and local Docker is forbidden: every build and test runs on the remote build runner through the labtest MCP tools (`test_run(path, suites="core", args="-p mastersos-cli <filter>")`, `suites="image-tests", args="check-tree"`, `build_run(path, targets="linux-bins")` from plan A). Release the runner with `env_release` at the end.
- `image/patches/authd-oidc/*.patch` are never edited.
- `bash image/tests/check-tree.sh` stays green; before each task grep it for the files the task edits (`grep -n '<file>' image/tests/check-tree.sh`) and update exact-line assertions in the same commit. Today none names `core/mastersos-cli`, the skill or `image/lab/accept-*.sh`.
- `core/mastersos-bundle/docs/manifest-spec.md` and `skills/mastersos-admin/reference/settings-reference.md` stay byte-identical (`spec.rs:749` test); edit both or neither.
- TDD: each task writes failing tests first.
- No compatibility burden: after this plan no code calls `/v1/admin/...`, `/v1/auth/config` or `/v1/spec`; `connect`, `logo upload`, `--token-file`, `config.toml` and the token file are gone.
- Credentials file `~/.config/mastersos/credentials.json` (`%APPDATA%\mastersos\credentials.json` on Windows), written only with `platform::write_private` (0600 / owner-only DACL). Tokens never appear in errors, logs, `--json` output or `Debug`.
- Worktree branch `feat/protocol-v1-c-cli`; commit per task; do not push.

## Review Focus

1. The server answers `201` to `publish/pending` with a `digest_hex` or `message_b64` that differs from the local digest: nothing is signed, the pending upload is deleted, the error says the server does not hold what was uploaded → Task 6 (`echoed_digest_mismatch_signs_nothing`, `echoed_message_mismatch_signs_nothing`).
2. A second `401 step_up_required` right after the step-up retry must not loop or ask again → Task 2 (`step_up_is_retried_once`).
3. The loopback callback gets a request with a wrong `state`, an `error=` parameter, or a request to another path (a browser's `/favicon.ico`): the first two end the login with an error, the third is answered 404 and ignored → Task 3 (`loopback_refuses_wrong_state`, `loopback_ignores_other_paths`).
4. `seed make` for a Group whose device config does not allow `sso` must leave `oidc` out, and `--group` naming a Group that does not exist in the latest verified version is refused before `POST seed` (no fetch token handed out for nothing) → Task 8 (`seed_without_sso_has_no_oidc`, `unknown_group_is_refused_before_post_seed`).
5. The feature gate refusal must list the Devices that are too old (device id, serial, OS version, last seen) in both the table and `--json` `problems` → Task 6 (`feature_unsupported_lists_devices`).

---

### Task 1: The frame, and the shared vector names

**Files:**
- Create: `core/mastersos-bundle/src/frame.rs` (+ `pub mod frame; pub use frame::{Frame, FrameKey, frame_of};` in `src/lib.rs`)
- Move: `core/mastersos-bundle/testdata/escrow-vector.json` → `escrow-vectors.json` (protocol §8's name); update its `include_str!` in `src/escrow.rs` and any test that names it (`git grep -n escrow-vector`)
- Test: `frame.rs` tests

**Interfaces:**
- Produces:
  - `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] pub struct Frame { pub format: u32, pub version: u64, pub issued_at: String, pub school_id: String, pub trust: Vec<FrameKey>, pub escrow_recipients: Vec<String>, pub features_used: Vec<String> }` and `pub struct FrameKey { pub id: String, pub alg: String, pub public_key: String }` — JSON field names exactly as protocol §4.3.
  - `pub fn frame_of(manifest_text: &str) -> Result<Frame, BundleError>`: `Manifest::parse` (the Devices' parser); `version` and `issued_at` must be present (a stamped text); `school_id` = `[school] id` (absent → `Invalid("the frame needs [school] id")`); every trust key must be `KeyAlg::Ed25519` (`alg: "ed25519"`), else `Invalid("only school keys (ed25519) can be in trust")`; `escrow_recipients` as written; `features_used` = `features_used(&m)` plus `format_<n>` when `n >= 2`, sorted and without repeats.

- [ ] **Step 1: Write the failing tests:** `frame_of_format_2_text` (`testutil` format 2 example stamped with version 7: `format 2`, `features_used` contains `format_2`, `config`, sorted); `frame_of_format_3_lists_format_3_and_claims` (`testutil::spec_example_v3` with `mastersos_claims = true`: contains `format_3` and `oidc_mastersos_claims`, no `format_2`); `frame_of_format_1_has_no_format_feature`; `frame_refuses_passkey_trust`; `frame_needs_school_id`; `frame_needs_a_stamped_version`; `frame_json_field_names` (`serde_json::to_value` has exactly the seven keys, trust items exactly `id`, `alg`, `public_key`); `escrow_vectors_file_has_the_protocol_name` (`include_str!("../testdata/escrow-vectors.json")` parses).
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-bundle frame escrow")`. Expected: FAIL.
- [ ] **Step 3: Implement**; `git mv` the vector file.
- [ ] **Step 4: Run** `test_run(suites="core", args="-p mastersos-bundle")`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(bundle): the publish frame, computed by the Devices' parser`.

### Task 2: The CLI API client and the error envelope

**Files:**
- Create: `core/mastersos-cli/src/server.rs`
- Delete: the old clients — `Api`, `Exchange`, `check_server`, `api_error`, `render`, `call`, `whoami` in `src/lib.rs`; `src/tools.rs`; `Api`, `ServerError`, `pin_file_name`, `server_key`, `host_of` in `src/sign/mod.rs` (their callers move to `server.rs` in Tasks 4–8)
- Test: `server.rs` tests (wiremock)

**Interfaces:**
- Consumes: `checks::server_origin` (plan A); `auth::Credentials` (Task 3; until then tests use `Credentials::fixed(token)`).
- Produces:
  - `pub struct Server` with `pub fn new(origin: &str, school: Option<&str>, creds: Credentials) -> Result<Server, CliError>`: origin must pass `server_origin`; `https`, or `http` only to `127.0.0.1`, `::1` or `localhost`; school a lowercase UUID.
  - `pub fn origin(&self) -> &Url`, `pub fn school(&self) -> Result<&str, CliError>` (`not_configured` when none).
  - Routes: `pub fn school_url(&self, route: &str) -> Url` = `<origin>/api/cli/v1/schools/<school>/mastersos/<route>`; `pub fn cli_url(&self, route: &str) -> Url` = `<origin>/api/cli/v1/<route>` (`auth-config`, `schools`). Path segments percent-encoded (`device_id`, recipients).
  - `pub async fn get_json<T: DeserializeOwned>(&self, route: &str) -> Result<T, CliError>`, `post_json<B: Serialize, T>(…)`, `post_empty<T>(…)`, `post_bytes<T>(route, bytes, "application/gzip")`, `delete(route) -> Result<(), CliError>`, `get_bytes(route) -> Result<(Vec<u8>, Option<u64>), CliError>` (`X-Mastersos-Version`).
  - `pub async fn auth_config(origin: &Url) -> Result<AuthConfig, CliError>`, `#[derive(Deserialize)] pub struct AuthConfig { pub issuer: String, pub client_id: String, pub audience: String, pub scopes: Vec<String>, pub step_up_acr: String }` (unauthenticated; unknown fields ignored).
  - Step-up: on `401` with code `step_up_required`, `creds.step_up().await` once, retry once with that token, and keep it in memory for later calls of the same process while it is younger than 4 minutes. A second `step_up_required` is returned as an error.
  - `#[derive(Debug, Clone, Serialize)] pub struct CliError { pub code: String, pub message: String, #[serde(skip)] pub status: Option<u16>, #[serde(skip)] pub details: Value, pub problems: Vec<Value> }`. Server errors: `code` and `message` from the envelope (control characters removed, 300 characters), `details` kept; a non-JSON error body gives `code: "invalid_answer"` and no body text. Local codes: `usage`, `not_logged_in`, `not_configured`, `network`, `invalid_answer`, `check_failed`, `reroute_refused`, `nothing_to_publish`, `digest_mismatch`, `chain_tampered`, `key_not_trusted`, `key_file_invalid`, `seed_invalid`, `cancelled`.
  - `pub fn print_error(e: &CliError, json: bool)`: with `--json` prints `{"error":{"code","message","problems"}}` on stdout; otherwise `mastersos: <message>` on stderr plus a table of `problems`. Exit code: 2 for `check_failed`/`reroute_refused`, else 1.

- [ ] **Step 1: Write the failing tests:** `school_routes_are_under_the_cli_prefix` (`school_url("publish/pending")` = `https://server.example/api/cli/v1/schools/0192f3a4-…/mastersos/publish/pending`); `device_id_segment_is_encoded` (`devices/a%2F..%2Fb/recovery-keys`); `origin_with_a_path_is_refused`; `plain_http_only_to_loopback`; `error_envelope_is_parsed` (409 `version_conflict` with `details.latest_version` 8 → `code`, `details`); `non_json_error_body_is_invalid_answer_without_text`; `step_up_is_retried_once` (first 401 `step_up_required`, `step_up()` called once, retry carries the step-up token, a second 401 `step_up_required` returns that error, 3 requests in all); `step_up_token_is_reused_within_four_minutes`; `json_error_shape` (`print_error` output parses to exactly `{"error":{"code","message","problems"}}`); `token_never_in_error_text`.
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-cli server::")`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `test_run(suites="core", args="-p mastersos-cli server::")`. Expected: PASS (other modules still compile against the old names until Tasks 4–8: do Task 2's deletions together with Task 4 if the crate does not build in between, and commit them together).
- [ ] **Step 5: Commit** `feat(cli): protocol v1 CLI API client`.

### Task 3: Credentials: `arbella`, `login`, `logout`

**Files:**
- Create: `core/mastersos-cli/src/auth/mod.rs`, `auth/arbella.rs`, `auth/store.rs`, `auth/oidc.rs`
- Modify: `core/mastersos-cli/Cargo.toml` (no new crate: `ring` for random bytes and SHA-256, `base64`, `reqwest`, `tokio` net are already there)
- Test: unit tests per file; `core/mastersos-cli/tests/cli_login.rs`

**Interfaces:**
- Produces:
  - `pub enum Credentials { Arbella(PathBuf), Stored(StoredLogin), Fixed(String) }` with `pub async fn token(&self) -> Result<String, CliError>` and `pub async fn step_up(&self) -> Result<String, CliError>`; `pub fn resolve(server_flag: Option<&str>) -> Result<(Credentials, Option<String>), CliError>` returns the credentials and the server origin they name: `arbella` on `PATH` (`auth::arbella::find()`, `arbella.exe` on Windows) wins; else `credentials.json`; else `not_logged_in` ("run `mastersos login --server <URL>`, or install arbella").
  - arbella: runs `arbella auth token --json` (`--step-up` added for `step_up`), 60 s timeout, stdin closed; parses `#[derive(Deserialize)] struct ArbellaToken { #[serde(rename = "fleet_url")] server_url: String, access_token: String, expires_at: String }` (the wire names of §6; unknown fields ignored). A non-zero exit or bad JSON → `not_logged_in` with arbella's stderr first line (control characters removed). The `server_url` is used when no `--server` and no work directory names one.
  - store: `#[derive(Serialize, Deserialize)] pub struct StoredLogin { pub version: u32 /* 1 */, pub server_url: String, pub issuer: String, pub client_id: String, pub audience: String, pub scopes: Vec<String>, pub step_up_acr: String, pub access_token: String, pub expires_at: String, pub refresh_token: Option<String> }`; `Debug` redacts both tokens. `pub fn load() -> Result<Option<StoredLogin>, CliError>`, `pub fn save(&StoredLogin)`, `pub fn remove()`. A token expiring within 60 s is refreshed (`grant_type=refresh_token`) and saved; failure → `not_logged_in`.
  - oidc: `pub async fn discover(issuer: &str) -> Result<Discovery, CliError>` (`<issuer>/.well-known/openid-configuration`: `device_authorization_endpoint`, `token_endpoint`, `authorization_endpoint`; `issuer` must equal the configured one); `pub async fn device_grant(cfg: &AuthConfig, d: &Discovery, out: &mut dyn Write) -> Result<TokenSet, CliError>` (RFC 8628: prints `verification_uri_complete` or `verification_uri` + `user_code`, polls with `interval`, `slow_down` adds 5 s, `expired_token`/`access_denied` end it); `pub async fn loopback_step_up(cfg: &AuthConfig, d: &Discovery, open_browser: bool) -> Result<TokenSet, CliError>`.
  - Loopback: listener on `127.0.0.1:0`; redirect `http://127.0.0.1:<port>/callback`; PKCE S256 (verifier 32 random bytes base64url, challenge `base64url(sha256(verifier))`); `state` 32 random bytes base64url; parameters `response_type=code`, `client_id`, `redirect_uri`, `scope` (space-joined `scopes`), `state`, `code_challenge`, `code_challenge_method=S256`, `prompt=login`, `max_age=0`, and `acr_values=<step_up_acr>` only when it is non-empty (Erratum 1). Waits at most 5 minutes; only `GET /callback` counts (other paths get 404 and are ignored); wrong `state` or an `error` parameter ends it; the browser gets a short English page `Signed in. You can close this window.`; the code is exchanged with `code_verifier` at `token_endpoint`. The browser is opened with `open` / `xdg-open` / `cmd /c start`; the URL is always printed too.
  - Commands: `mastersos login --server URL [--no-browser]` (stores a `StoredLogin`; works even when `arbella` is installed, but `resolve` prefers `arbella`, and `login` says so); `mastersos logout` (removes the file; says nothing about `arbella`).

- [ ] **Step 1: Write the failing tests**
  - `arbella_token_is_parsed` and `arbella_step_up_passes_the_flag` (a fake `arbella` script on a temp `PATH` that records its arguments and prints `{"fleet_url":"https://server.example","access_token":"t","expires_at":"2026-11-20T10:00:00Z"}`; unix only, the Windows twin in CI); `arbella_failure_is_not_logged_in`.
  - `credentials_file_is_owner_only` (unix: mode 0600 after `save`); `stored_login_debug_redacts_tokens`; `expiring_token_is_refreshed_and_saved` (wiremock token endpoint).
  - `loopback_step_up_sends_prompt_login_and_max_age_zero` (wiremock authorization endpoint that answers 302 to the `redirect_uri` with the `state` it received and `code=c1`; the test follows it with reqwest; asserts `prompt=login`, `max_age=0`, no `acr_values` when `step_up_acr` is empty, `code_challenge` equals S256 of the `code_verifier` the token request sent); `loopback_sends_acr_values_when_set`; `loopback_refuses_wrong_state`; `loopback_refuses_an_error_answer`; `loopback_ignores_other_paths`.
  - `device_grant_polls_until_approved` (`authorization_pending` twice, then a token; `slow_down` raises the interval).
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-cli auth::")`. Expected: FAIL.
- [ ] **Step 3a: Implement** `arbella.rs`, `store.rs`, `resolve`, `logout`.
- [ ] **Step 3b: BLOCKED (B2)** Implement `device_grant` and `login` once the audience parameter is known (add it to the request then, with a test asserting it).
- [ ] **Step 3c: BLOCKED (B2)** Implement `loopback_step_up` the same way; the PKCE, state and parameter tests above are written now and kept `#[ignore = "B2"]` until then.
- [ ] **Step 4: Run** `test_run(suites="core", args="-p mastersos-cli auth:: --test cli_login")`. Expected: PASS (ignored tests reported as ignored).
- [ ] **Step 5: Commit** `feat(cli): credentials from arbella or mastersos login`.

### Task 4: Versions, the verified chain, `init`, `pull`, `verify`

**Files:**
- Modify: `core/mastersos-cli/src/sign/chain.rs` (`verify_chain`, `first_use`, `pin_path`, `recorded_digest` take `&Server`; pins keyed by origin and school), `src/workdir.rs` (`Meta`), `src/cli.rs` (`init_dir`, `pull_dir`, `verify`)
- Test: `chain.rs` tests, `core/mastersos-cli/tests/cli_init_pull.rs` (replaces `cli_init_keys.rs` init parts and `cli_connect.rs`)

**Interfaces:**
- Consumes: Task 2 `Server`.
- Produces:
  - `Server::latest_version(&self) -> Result<u64, CliError>` (`GET versions`, max `version`, 0 when empty) and `Server::version_archive(&self, v: u64) -> Result<Vec<u8>, CliError>` (`GET versions/{v}/archive`; `X-Mastersos-Version` must equal `v`).
  - Pin file `<pin dir>/<host>[_<port>]+<school>.toml`; `verify_chain(server: &Server, pin_dir: &Path, yes: bool, confirm: &mut dyn BufRead, out: &mut dyn Write) -> Result<Verified>` (first use asks to confirm the fingerprints unless `yes`; `--yes` accepts them and prints them).
  - `Meta { server: String /* origin */, school_id: String, base_version: u64 }`.
  - `init DIR --school UUID --key-file PATH… [--server URL]`: `GET keys` must list each key with the same fingerprint, else `key_not_trusted` naming `mastersos key register`; writes `mastersos.toml` and the template with the trust and recipients.
  - `pull [DIR] [--version N] [--force] [--school UUID] [--server URL]` (school and server from `mastersos.toml` when present).

- [ ] **Step 1: Write the failing tests:** `chain_reads_versions_from_the_cli_routes`; `pins_are_per_origin_and_school` (two schools on one origin → two files); `first_use_with_yes_accepts_and_prints_fingerprints`; `tampered_archive_stops_the_chain` (`chain_tampered`); `init_refuses_an_unregistered_key`; `init_needs_school`; `pull_writes_meta_with_origin_and_school`.
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-cli chain init pull")`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `test_run(suites="core", args="-p mastersos-cli")`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(cli): versions, chain, init and pull over protocol v1`.

### Task 5: `key new|register|list|add|remove`

**Files:**
- Modify: `core/mastersos-cli/src/sign/kit.rs` (`ensure_registered`, `register_escrow_recipient`), `src/sign/mod.rs` (`register`), `src/cli.rs` (`key_*` handlers)
- Test: `core/mastersos-cli/tests/cli_keys.rs`

**Interfaces:**
- `key register --key-file PATH --label TEXT`: `POST keys/probe` (no body) → `{nonce_b64, message_b64}`; nonce must be 32 bytes and `message_b64` must equal base64 of `keyprobe_message(nonce)`; `POST keys` (step-up) `{"label","trust_key":{"id","alg":"ed25519","public_key"},"nonce_b64","signature":{"key_id","alg","sig"}}` → `201 {key_id, fingerprint}`, both compared with the kit's; `409 key_exists` → "already registered", continue. Then a fresh probe and `POST escrow-recipients` (step-up) `{"recipient","bound_key_id","nonce_b64","sig_b64","label"}` with `recipient_binding_message`; `409 recipient_exists` → "already registered".
- `key list [--dir DIR]`: `GET keys` + `GET escrow-recipients`; columns key code, label, registered, in latest trust, in this directory, last used; `--json` prints `{"keys":[…],"escrow_recipients":[…]}` as the server sent them plus `"in_directory": bool` per key.
- `key add FILE [--dir]`: as today (local edit), after `GET keys` shows the kit registered with the same fingerprint.
- `key remove CODE [--key-file PATH] [--dir] [--unregister]`: local edit as today; with `--unregister` instead: `DELETE keys/{key_id}` (step-up; `409 key_still_trusted` → "publish a version without it first").

- [ ] **Step 1: Write the failing tests:** `register_signs_the_local_probe_message` (signature verifies over `keyprobe_message(nonce)` with the kit's key); `register_refuses_a_wrong_probe_message` (server `message_b64` differs → nothing posted to `keys`); `register_then_binds_the_recipient_with_a_fresh_probe` (two probes, binding message verified); `already_registered_key_still_registers_the_recipient`; `key_list_json_shape`; `unregister_still_trusted_explains`.
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-cli --test cli_keys")`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `test_run(suites="core", args="-p mastersos-cli")`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(cli): school keys over protocol v1`.

### Task 6: Two-step `publish` and `heartbeat`

**Files:**
- Modify: `core/mastersos-cli/src/publish.rs` (`publish`, `precheck_signer`, `checkin`; `AuthConfig`, `Prepared`, `lint_failed` handling and `print_server_lints` go), `src/sign/mod.rs` (`sign_pending*`, `sign_heartbeat*`, `checkin_after_publish*` become local helpers without server calls), `src/cli.rs` (`publish_dir`, `heartbeat`)
- Test: `publish.rs` tests, `core/mastersos-cli/tests/cli_publish.rs` (replaces `cli_publish_plain.rs`)

**Interfaces:**
- Consumes: Task 1 `frame_of`; Task 4 `verify_chain`; `archive::{content_digest, write_archive}`, `sign::{signed_message, SignatureFile}`, `heartbeat::{HeartbeatStatement, heartbeat_message, Heartbeat}`.
- Produces `pub async fn publish(server: &Server, w: &Workdir, kit: &Kit, opts: PublishOpts<'_>, now: DateTime<Utc>, confirm: &mut dyn BufRead, out: &mut dyn Write) -> Result<PublishOutcome, CliError>`, `pub struct PublishOpts<'a> { pub allow_reroute: &'a [String], pub yes: bool, pub pin_dir: &'a Path }`, `PublishOutcome::Published { version: u64, digest_hex: String, checkin: CheckIn }`.
- Order (stop at the first failure; nothing on the server is left pending after a local refusal):
  1. Local check, reroute approval, secret fill (unchanged).
  2. `verify_chain`; `latest` must equal `base_version` (else the existing "someone published vN" message, code `version_conflict`); the kit's key must be in the latest verified trust (version 1: in the new text's trust), else `key_not_trusted`.
  3. Stamp `version = base_version + 1`, `issued_at = now` (RFC 3339, seconds, `Z`). **3b BLOCKED (B1):** `[school] name` from `GET /api/cli/v1/schools` via `school_name_to_write`.
  4. Contents (stamped text + `files/`, `scripts/`), `digest = content_digest`, `frame = frame_of(stamped)`; `frame.school_id` must equal `meta.school_id`.
  5. `POST publish/pending {"frame":…, "digest_hex"}` → `201`; `version`, `digest_hex` (lowercase hex, equal) and `message_b64` (= base64 of `b"mastersos-bundle-v1\n" || digest`) are checked; any mismatch → `DELETE publish/pending/{id}`, `digest_mismatch`, nothing signed.
  6. Print `trust_change` (added/removed key codes) and `warnings`; ask to type the version number unless `--yes`.
  7. Sign `signed_message(contents)` with the kit → `SignatureFile`; archive = `write_archive(contents, sig.to_toml())`; save as uploaded (`w.save_uploaded`).
  8. `POST publish/pending/{id}/commit` (`application/gzip`) → `200 {version}` equal to ours.
  9. Heartbeat: `HeartbeatStatement { version, digest_hex, issued_at: now, not_after: now + 30 days }`, signed, `POST heartbeat {"heartbeat": <toml>}` → `204`; failure is `CheckIn::Failed` (publish still succeeded).
  10. `w.mark_published`.
- Server refusals map to messages: `version_conflict`, `clock_skew` ("this computer's clock is off by more than 10 minutes"), `school_mismatch`, `trust_key_unregistered` (names the key code and `mastersos key register`), `recipient_unregistered`, `feature_unsupported` (`problems` = `details.devices`, table columns device id, serial, OS version, last seen; message names `details.feature`), `pending_expired`, `archive_invalid`, `digest_mismatch`, `signature_invalid`, `trust_rule`. `--json` success: `{"version","digest_hex","heartbeat_not_after"|null,"trust_change","warnings"}`.
- `heartbeat --key-file PATH [--days 1..=31]`: verified chain → statement for the latest version (its digest from the chain) → `POST heartbeat`; prints the end date; `409 not_latest` → "someone published meanwhile; run it again".

- [ ] **Step 1: Write the failing tests:** `publish_posts_frame_then_commits_signed_archive` (wiremock: pending body has `frame` equal to `frame_of(stamped)` and `digest_hex`; commit body read with `read_archive` has a `signature` verifying over the digest with the kit; heartbeat body parses as `Heartbeat` for that version and digest with `not_after - issued_at == 30 days`); `echoed_digest_mismatch_signs_nothing`; `echoed_message_mismatch_signs_nothing` (both: no commit request, one `DELETE publish/pending/p1`); `version_conflict_names_the_newer_version`; `feature_unsupported_lists_devices` (table and `--json` `problems`); `clock_skew_is_explained`; `kit_not_in_latest_trust_uploads_nothing`; `heartbeat_failure_still_publishes`; `heartbeat_command_signs_the_latest_verified_version`; `yes_skips_the_confirmation`.
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-cli publish heartbeat")`. Expected: FAIL.
- [ ] **Step 3: Implement** (Step 3b stays BLOCKED (B1): leave a single call site `stamp_school_name(…)` returning `None` with a `// BLOCKED (B1)` comment and an `#[ignore = "B1"]` test `publish_stamps_the_organisation_name`).
- [ ] **Step 4: Run** `test_run(suites="core", args="-p mastersos-cli")`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(cli): two-step publish and heartbeat over protocol v1`.

### Task 7: `recovery read` and `devices`

**Files:**
- Modify: `core/mastersos-cli/src/sign/kit.rs` (`escrow_read` → `recovery_read`), `src/cli.rs` (`devices`)
- Test: `core/mastersos-cli/tests/cli_recovery_devices.rs`

**Interfaces:**
- `recovery read <DEVICE> --key-file PATH`: kit registered (`GET keys`); `GET devices/{device}/recovery-keys` (step-up) → rows `{luks_uuid, recovery_key_age, recipients_fp, received_at, serial, first_for_luks}`, newest first; each opened with the kit's age identity as today (the "not the first row: suspicious" note kept). `--json`: `[{"luks_uuid","received_at","serial","first_for_luks","recovery_key"|null,"note"}]`.
- `devices list [--group G]` → `GET devices`; `devices show <ID or serial>` → `GET devices/{device_id}` (a serial is resolved through the list). `--json` prints the server's JSON.

- [ ] **Step 1: Write the failing tests:** `recovery_read_opens_rows_sealed_to_the_kit` (rows made with `mastersos_bundle::seal` to the kit's recipient); `recovery_read_marks_rows_not_first_for_luks`; `recovery_read_needs_step_up` (first 401 `step_up_required`, then rows); `devices_show_by_serial`.
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-cli --test cli_recovery_devices")`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `test_run(suites="core", args="-p mastersos-cli")`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(cli): recovery read and devices over protocol v1`.

### Task 8: `seed make` and `seed check`

**Files:**
- Create: `core/mastersos-cli/src/seed.rs`
- Modify: `core/mastersos-cli/src/sign/mod.rs` (old `seed_check`, `seed_header` move here), `src/cli.rs`
- Test: `seed.rs` tests, `core/mastersos-cli/tests/cli_seed.rs`

**Interfaces:**
- Produces:
  - `pub fn seed_from_version(m: &Manifest, version: u64, group: Option<&str>, server_url: &str, school_id: &str, fetch_token: &str) -> Result<Seed, CliError>`: `m.school.id` must equal `school_id` (else `seed_invalid`); a given `group` must exist in `m.groups` (else `seed_invalid`); the Config = `select(m, &DeviceIdent { serial: None, device_id: String::new() }, group).config`; `trust = m.trust`, `min_version = Some(version)`, `school_id`, `fetch_token`, `group` as given, `school_name = m.school.name`, `wifi = config.wifi`, `it_account = config.it_account`, `oidc = m.school.oidc` only when `config.login_methods` contains `LoginMethod::Sso`; then `Seed::validate`.
  - `seed make [--group G] --out FILE [--dir DIR | --school UUID --server URL] [--yes]`: verify the chain first and resolve the Group locally (unknown Group refused before anything is posted); then `POST seed` (step-up, no body) → `{server_url, school_id, fetch_token}`; `server_url` must pass `server_origin` and equal the origin in use, `school_id` must equal ours; write `to_toml_with_header()` with `platform::write_private` (0600; refuses to replace an existing file unless `--yes`); `409 no_published_version` → "publish the first version first". Prints the fingerprints.
  - `seed check FILE [--dir DIR | --school UUID --server URL]`: parse + `validate`; `server_url` equals the origin in use; `school_id` equals ours; `fetch_token` has the §3.1 shape (printable ASCII without spaces, 1–256 bytes; checked in this crate, not through the agent); `trust` equals the latest verified version's trust (by fingerprint) or a verified earlier one at `min_version` (reported as "older seed: Devices will update"); `min_version` ≤ latest verified; header fingerprints match the body. Exit 0 / 1, `--json` `{"ok", "problems": [...]}`.
  - The seed header comment line is English: `# Compare these fingerprints with the ones IT verified (mastersos verify).` (changing `Seed::to_toml_with_header` in `mastersos-bundle/src/seed.rs`, and its tests).

- [ ] **Step 1: Write the failing tests:** `seed_takes_trust_and_min_version_from_the_latest_verified_version`; `seed_takes_the_group_wifi_and_it_account`; `seed_without_sso_has_no_oidc`; `seed_with_sso_has_oidc_without_login_domain` (Erratum 2: the `oidc` table has `mastersos_claims` when set and no `login_domain`); `unknown_group_is_refused_before_post_seed` (0 requests to `seed`); `school_id_mismatch_is_refused`; `seed_file_is_owner_only_with_header`; `seed_check_accepts_a_fresh_seed`; `seed_check_flags_wrong_server_school_and_token_shape`; `seed_check_flags_trust_not_in_the_chain`.
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-cli seed")`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `test_run(suites="core", args="-p mastersos-cli -p mastersos-bundle")`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(cli): seed make and seed check from the verified chain`.

### Task 9: The command surface and the non-interactive mode

**Files:**
- Modify: `core/mastersos-cli/src/cli.rs` (clap tree; remove `connect`, `logo upload`, `--token-file`, `ConfigFile`/`config.toml`, `connect_school`, `check_private` token checks; `spec` reads `mastersos_bundle::spec` locally: `spec [SECTION]`, `spec --full`), delete `src/logo.rs`
- Test: `core/mastersos-cli/tests/cli_surface.rs`

**Interfaces (pinned for the server team's end-to-end run):**
- Commands: `init`, `pull`, `check`, `diff`, `publish`, `key new|register|list|add|remove`, `heartbeat`, `verify`, `recovery read <device>`, `seed make|check`, `spec [section]`, `login`, `logout`, and the local or listing helpers `explain`, `migrate`, `hash-password`, `devices list|show`.
- Global flags: `--json`, `--yes`, `--server URL`, `--school UUID`, `--pin-dir DIR`. School key: `--key-file PATH` on the commands that sign or open (`init`, `publish`, `heartbeat`, `key register|add|remove`, `recovery read`).
- Non-interactive run: with `--yes` and `--key-file`, no command reads stdin; credentials come from `arbella auth token --json` (and `--step-up`) on `PATH`; `--json` prints one JSON value on stdout per command and errors as `{"error":{"code","message","problems"}}`; exit 0 success, 1 failure, 2 local check errors or usage.

- [ ] **Step 1: Write the failing tests:** `help_lists_exactly_the_commands` (`mastersos --help` subcommand names equal the list above); `connect_logo_and_token_file_are_gone`; `spec_works_offline` (`mastersos spec school.oidc` with no network and no credentials prints the section); `json_error_for_not_logged_in` (empty `PATH`, no credentials file: stdout `{"error":{"code":"not_logged_in",…}}`, exit 1); `yes_and_key_file_never_read_stdin` (stdin closed: `publish --yes --key-file` against wiremock succeeds).
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-cli --test cli_surface")`. Expected: FAIL.
- [ ] **Step 3: Implement**; `git grep -n '"v1", "admin"\|/v1/admin\|/v1/auth\|/v1/spec' core` must be empty.
- [ ] **Step 4: Run** `test_run(suites="core")`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(cli): protocol v1 command surface and non-interactive mode`.

### Task 10: Shared vectors and the cross-language end-to-end script

**Files:**
- Create: `tools/protocol-e2e.sh`
- Modify: `core/mastersos-bundle/tests/vectors.rs` (one test per vector file names the four §8 files and checks each parses and verifies)
- Test: the vector tests; the script's own `--self-test` against wiremock is not possible in bash, so it is exercised by the server team's run and by a dry run (`--dry-run` prints the command list)

**Interfaces:**
- `tools/protocol-e2e.sh --server URL --school UUID --cli PATH --agent PATH --work DIR --rotate-cmd 'CMD'` (`arbella` stub on `PATH` supplied by the caller; `CMD` rotates the fetch token on the server). Runs, in order, each line printing `PASS <name>` or `FAIL <name>: <reason>`, exit 1 on any FAIL: `key new` ×2, `key register` ×2, `init` (key 1), `publish` (v1), `publish` (v2 rotating trust to key 2, signed by key 1), `heartbeat`, `pull` into a second directory, `verify`, `seed make` + `seed check`, `mastersos-agent protocol-check --seed … --state … --json --recovery-key … --luks-uuid …` (all calls ok), `CMD`, protocol-check again (expects `fetch_token` 200 and `fetch_token_check` ok), `recovery read` (opens the escrowed key), failure cases: publish signed with an unregistered key (`trust_key_unregistered`), publish from a stale base (`version_conflict`), `--key-file` of a key not in trust (`key_not_trusted`, local), a frame using a feature no Device reports (`feature_unsupported`, after protocol-check reported without it). Every CLI call uses `--json --yes --key-file`.

- [ ] **Step 1: Write the failing checks:** `shared_vectors_are_the_protocol_files` in `tests/vectors.rs` (loads `../testdata/{digest,heartbeat,escrow,kit}-vectors.json` by those names and runs every vector); and `bash tools/protocol-e2e.sh --dry-run --server https://server.example --school 0192f3a4-5b6c-7d8e-9f00-112233445566 --cli x --agent x --work /tmp/x --rotate-cmd true` must print one line per step named above.
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-bundle --test vectors")` and the dry run. Expected: FAIL (test and script missing).
- [ ] **Step 3: Implement** the test and the script (`set -euo pipefail`, `shellcheck`-clean, English output, no hostnames).
- [ ] **Step 4: Run** the vector test (PASS), `bash -n tools/protocol-e2e.sh`, `tools/protocol-e2e.sh --dry-run …` (prints the plan), `test_run(suites="image-tests", args="check-tree")`.
- [ ] **Step 5: Commit** `test: protocol v1 shared vectors and the end-to-end script`. **Depends on the server team** for the run itself (who starts the server and the test issuer, the `arbella` stub that mints tokens, the rotate command): they confirm the interface above.

### Task 11: Lab acceptance scripts on protocol v1

**Files:**
- Modify: `image/lab/accept-common.sh:154-260` (`api`, `publish_manifest`, `device_json`, `recovery_rows`, `ensure_bundle`, `make_stick`), `image/lab/accept-4a.sh:207`, `image/lab/accept-4b.sh:21,238-331,934-990,1454,1537-1560,1678-1820`, `image/lab/accept-5.sh:178-260,453`
- Test: `bash -n` and `shellcheck` on the four files; a dry run is not possible without the lab

**Interfaces / decisions:**
- `api` is replaced by `cli()`: runs `mastersos --json --yes` on the lab build VM in a work directory `~/accept-cli/<school>` with the lab school key file (0600, copied once from the Mac's lab config directory over stdin) and the lab credentials (`arbella` stub or `mastersos login`, per the server team's lab setup); every secret still travels only over stdin.
- `publish_manifest <file> [path=file…]`: copy the manifest and files into the work directory, `cli publish --key-file …`; log the version from the JSON.
- `device_json` → `cli devices show <id>`; `recovery_rows`/recovery key → `cli recovery read <id> --key-file …` (count and `recovery_key` from the JSON); `ensure_bundle` → `cli pull` then publish when `base_version` is 0; `make_stick` → `cli seed make --out` (step-up through the lab credentials).
- accept-4b panel actions (`PUT devices/<id>/group|lock|reset`) become `[[device]]` edits (`group`, `locked = { message }`, `reset`) published with `publish_manifest`.
- Sections that need what phase 1 does not offer print `SKIP <name>: <reason>` and do not count as failures: §6.9 item 4 "version within 10 s of publishing" (push, phase 2) and its held-connection fallback (no long poll in v1: removed). Token rotation (`:1684-1755`) uses the server's operator command (`fetch-token rotate`, `drop-retired`) instead of editing the old server's config. The tamper check (`:1760-1820`) serves the changed archive from a small proxy on the build VM in front of the server for `GET /api/device/v1/bundle`, instead of editing the old server's database.
- Every `/v1/bundle` string in comments and the nginx snippet becomes `/api/device/v1/bundle` or is removed with the fallback section.

- [ ] **Step 1: Failing check:** `git grep -n '/v1/admin\|mastersos-server\.bin\|commit-server' image/lab` prints lines.
- [ ] **Step 2: Rewrite** the helpers and call sites as above.
- [ ] **Step 3: Run** the check (empty), `bash -n image/lab/accept-*.sh`, `shellcheck image/lab/accept-*.sh` (in the `image-tests` suite if not installed on the Mac), `test_run(suites="image-tests", args="check-tree")`.
- [ ] **Step 4: Commit** `test(lab): acceptance scripts on protocol v1`. **Depends on the server team**: how the lab server and its issuer run on the lab build VM and how operator commands are invoked there. The VM runs themselves go to the heavy-verification list (not in this plan).

### Task 12: Skill, README and reference docs

**Files:**
- Modify: `skills/mastersos-admin/SKILL.md` (setup: install, then `mastersos login --server <URL>` or `arbella`; no token files; IT runs `init`, `publish`, `key …`, `seed make`; the AI runs `check`, `diff`, `explain`, `spec`, `--json devices list|show`; `logo upload` gone; step-up explained in one line), `skills/mastersos-admin/reference/recipes.md` (any `connect`, `logo upload` or token-file step)
- Modify: `README.md`, `README.en.md` (getting started, credentials, the command table, `GET /v1/admin/seed` at `README.md:382` → `mastersos seed make`), `image/docs/keys.md:364-368` (device reset through `[[device]].reset` only), `docs/glossary.md` if a term changed
- Modify both identically only if a line names a removed command: `core/mastersos-bundle/docs/manifest-spec.md`, `skills/mastersos-admin/reference/settings-reference.md` (check with `git grep -n 'logo upload\|connect\|token' -- <both>`; `logo_sha256`'s "upload with `mastersos logo upload`" style lines become "the server does not host logos yet (phase 4)" in both)

- [ ] **Step 1: Failing check:** `git grep -nE 'mastersos (connect|logo upload)|--token-file|config\.toml|/v1/admin' -- README.md README.en.md skills docs/glossary.md image/docs core/mastersos-bundle/docs` prints lines.
- [ ] **Step 2: Edit.**
- [ ] **Step 3: Run** the check (empty), `test_run(suites="core", args="-p mastersos-bundle spec")` (byte identity and recipes tests), `test_run(suites="image-tests", args="check-tree")`, `python3 -I tools/check-private.py`.
- [ ] **Step 4: Commit** `docs: the mastersos command line on protocol v1`.

### Task 13: Public `docs/protocol.md` (ask the owner before committing)

**Files:**
- Create: `docs/protocol.md`

**Decisions to put to the owner (the file is written, not committed, until the owner confirms):**
- Content: the frozen text without §0 and without any reference to private documents, meaning unchanged; Erratum 1's text verbatim. Erratum 1's parenthesised attribution names a person, and the document's header says the public copy names no person: ask whether the attribution becomes "(owner, 2026-11-19; …)".
- Generic roles for product names: the settings server, the identity provider, "the umbrella CLI `arbella`" kept as the optional credential helper; the wire field `fleet_url` of §6 stays as it is (a wire name); §5's operator commands are described as "server operator commands"; §8's last bullet names a school and becomes "then the first school's Devices are reflashed"; the rewrite-design and phase-0 references are dropped or described in one generic phrase.
- [ ] **Step 1: Failing check:** `test -f docs/protocol.md` fails.
- [ ] **Step 2: Write** the file (untracked). `tools/check-private.py` only scans tracked files, so run its patterns on the file directly: `grep -n -i -E -f ~/.config/mastersos/denylist.txt docs/protocol.md` prints nothing; then read it once for hosts, ids and names.
- [ ] **Step 3: Ask the owner**, with the diff of decisions above. Only after the owner's yes: `git add docs/protocol.md` and commit `docs: publish protocol v1`.

---

## Self-review notes

- §6 commands → Tasks 3–9; frame §4.3 → Task 1; two-step publish §4.4 → Task 6; heartbeat §4.7 → Task 6; keys §4.2 → Task 5; devices/recovery §4.8 → Task 7; seeds §4.9 → Task 8; credentials §6 + Erratum 1 → Task 3; non-interactive mode → Task 9; §8 vectors and end-to-end → Task 10; lab → Task 11; docs → Tasks 12–13.
- Not used by any command (server routes exist): `DELETE escrow-recipients/{recipient}`, `GET heartbeat` (CLI side), `DELETE devices/{id}`, `POST devices/{id}/restore`, `DELETE …/recovery-keys`, `DELETE …/escrow-secret`, `GET escrow-registrations`. §6 does not list commands for them; IT reaches them through the umbrella CLI. Add commands only if the coordinator asks.
