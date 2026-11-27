# MastersOS ↔ settings server protocol, version 1 (phase 1)

Status: **agreed and frozen** (2026-11-19, draft 2), signed by both parties and implemented exactly as written.
Parties: **the settings server** and **mastersos** (agent, `mastersos` CLI, seed, Rust). Each party signed off
only when it was sure it could implement its side; since both signed, the text is frozen. Until the
protocol's first release the text is edited in place; from then on a change is made only as an erratum.

This is the public copy. The frozen text is kept with the settings server; this copy leaves out its section 0
(the server operator's own notes) and names the server-side products by their roles: "the settings server",
"the identity provider", and `arbella`, the optional credential helper. The meaning is identical. Names on the
wire that contain the word `fleet` (the field `fleet_url`) are part of the protocol and are written as they are.

Erratum 1 (2026-11-19; clarifies §4.1 and §6, no wire change): the identity provider decides the sign-in
factors, and the server trusts it. "Step-up" means a fresh sign-in: a token whose `auth_time` is at most 5 minutes
old, obtained by the loopback flow with `prompt=login` and `max_age=0`. `step_up_acr` in `auth-config` may be the
empty string; when it is empty, the CLI sends no `acr_values`.

Erratum 2 (2026-11-19; follows Erratum 2 of the user-layer contract, no wire change): `school.oidc.login_domain`
is removed, so a seed's `oidc` table no longer has it (§3.8).

Erratum 3 (2026-11-23; no wire change): the settings server and the identity provider are now one service. The
operator commands of §5 keep their arguments and meaning and are subcommands of that service's operator tool:
`mastersos enable <school>`, `mastersos fetch-token rotate <school> [--compromised-at TIME]` and
`mastersos fetch-token drop-retired <school>`.

Erratum 4 (2026-11-23; no wire change): nothing on the wire is renamed by Erratum 3: paths under `/api/cli/v1/`
and `/api/device/v1/`, the field `fleet_url` of `arbella auth token --json`,
the error envelope and codes, and `schools/{school}` (the identity provider's organisation id) stay as written.
`arbella fleet devices ...` in §4 and §7 is `arbella devices ...`; the old name remains an alias. The `arbella`
command line and the cross-language harness of §8 are kept with the settings server.

Erratum 6 (2026-11-27; no wire change): Erratum 4's sentence "the old name remains an alias" is withdrawn.
`arbella fleet ...` is not a command, and neither are `devices` and `device` as old names for `list` and `show`
inside the `arbella devices` group: each is a usage error (exit 2). Reason: every operator installs the `arbella`
command line again at the cutover, so no installed command line survives that would need the old names. Where §4
and §7 write `arbella fleet devices ...`, read `arbella devices ...`. Nothing on the wire changes.

Scope: phase 1 of the server rewrite: keys, two-step publish, versions, heartbeat, bundle delivery, fetch
token, device secret, status, escrow, fetch-token renewal, seeds, and the `mastersos` CLI's use of the server.
Inbox/push (phase 2), diagnostics and help requests (phase 3) and logos (phase 4) are only reserved here (§3.9).

## 1. Principles

1. **The server never parses the settings text** (`manifest.toml`). Everything it needs from a version is sent
   by the CLI as a **frame** (§4.3), computed with the same Rust code devices run. The server verifies what it
   can (digest, signatures, registered keys, order) and trusts the frame for the rest; devices verify
   everything themselves, so a wrong frame can stall a rollout but never make a device accept a bad version.
2. **The server never signs** settings or heartbeats and never sees a private key or a recovery key.
3. **One origin, two prefixes**: devices use `/api/device/v1/`, the CLI uses `/api/cli/v1/`, both on the server
   origin (`server_url`). The school is identified by the credential, never by the URL path for devices. The
   issuer is a separate origin: the server names it in `auth-config` (§6), and a school's settings name it in
   `[school.oidc] issuer`. Nothing derives one origin from the other.
4. **Formats are byte-exact and shared**: archive, content digest, signed messages, heartbeat, key ids,
   fingerprints, escrow envelope and `recipients_fp` are defined in `mastersos-bundle` and its `testdata/`
   vectors; the server reimplements them and runs the same vectors.
5. **Old server flaws not carried over**: status reports must be authenticated by the device secret, and a
   device IT removed stays removed until IT restores it, so a forged device found in a feature-gate refusal
   can be removed for good (anyone with the fetch token can still register new device ids, within the rate
   limits); "latest version" is read from the database, never from process memory; the heartbeat served is the
   one that lives longest; one length limit per field; every error is JSON.
6. **The CLI builds every archive** with `archive.rs`; the server only reads archives (limits, member paths,
   digest, signature) and stores the bytes it received.

## 2. Common rules

- TLS only, except `http://` to loopback for tests and to lab images (existing agent rule).
- Every response carries `Cache-Control: no-store` (archives too) and, on errors, a JSON body
  `{"error":{"code":"<code>","message":"<text>"}}`. Codes are listed per call; clients act on `code`, never on
  `message`. A `429` carries `Retry-After` (seconds).
- Identifiers: `device_id` 1–128 bytes, UTF-8, no control characters; `serial`, `model`, `os_version`,
  `agent_version`, `group`, `user_config`, result `item` 1–128 bytes, no control characters; result
  `detail` ≤ 2048 bytes (the server truncates longer text at a UTF-8 boundary); a longer or invalid
  identifier is `400 invalid`.
- Time values: RFC 3339 with offset in JSON; Unix seconds where the shared format says so (heartbeat).
- Unknown JSON fields: the **server** ignores unknown fields in `status`, refuses them (`400 invalid`) in
  every other request; the **agent and CLI** ignore unknown fields in every response.

## 3. Device API (`/api/device/v1/`)

### 3.1 Credentials

- **Fetch token** (school-wide, in the seed): `Authorization: Bearer <token>`; printable ASCII without spaces,
  ≤ 256 bytes. The server finds the school by `sha256(token)` among current and retired tokens of all
  schools. Missing → `401 unauthorized`; unknown or dropped → `401 unauthorized`.
- **Retired token**: accepted; every response then carries `X-Mastersos-Fetch-Token: stale` (agent renews,
  §3.6).
- **Device credential**: headers `X-Mastersos-Device: <device_id>` and `X-Mastersos-Device-Secret: <secret>`
  (secret = 32 random bytes, base64url without padding, created once on the device as today). Required on
  `status`; the secret travels in the body on `escrow` and `fetch-token` (unchanged bodies).
- **Registration (first use)**: the first request of a `device_id` carrying a secret registers
  `HMAC-SHA256(server key, secret)` with `registered_at = now` for that school. Limits on new registrations:
  200 per school per hour, 5000 per server per hour (`429 too_many`). Later requests must present the same
  secret (`403 secret_mismatch`). An IT reset (§5.6) clears the secret; the next request registers again
  with a new `registered_at`.
- Secrets at rest are HMAC-SHA256 with a versioned server key (`v<n>:<hex>`), re-hashed under the newest key on
  successful verification.

### 3.2 `GET bundle?after=N`

- `after` (u64) = the version the device has (`min_version - 1` for a seed device). Absent → latest.
- `204` when nothing is published or `after ≥ latest`.
- Otherwise the **rotation step** rule (unchanged): let `base` = trust of version `max(after,1)`; serve the first
  version `v` in `after+1..=latest` whose trust differs from `base` (full key compare), else latest. An `after`
  the school never published → latest.
- `200`: body = the archive bytes exactly as stored, `Content-Type: application/gzip`,
  `X-Mastersos-Version: <v>`. No long poll: a `wait` parameter is ignored.

### 3.3 `GET heartbeat`

- `200 text/plain; charset=utf-8`: the stored heartbeat TOML for the **latest** version with the greatest
  `not_after` (ties: the latest stored). `204` when there is none.

### 3.4 `POST status` (device credential required)

- Body: `StatusReport` as defined in `mastersos-bundle` (`status.rs`), plus the optional field `user_config`
  (string; the status report of `docs/specs/2026-11-19-user-layer-design.md` §4). `X-Mastersos-Device` must equal `device_id` (`400 invalid`).
- `results` beyond 200 entries are dropped; `manifest_features` ≤ 32 entries of 1–64 bytes (`400 invalid`).
- Stored per (school, device_id): every report field, `last_seen = now`, `fetch_token_stale` when a retired
  token was used. A removed device's report is still stored but it stays removed (§4.8).
- A status without both device headers → `401 device_auth_missing`.
- `204`. Errors: `400 invalid`, `401 unauthorized`, `401 device_auth_missing`, `403 secret_mismatch`,
  `413 too_large` (body > 64 KiB), `429 too_many`.

### 3.5 `POST escrow`

Body and validation exactly `EscrowRequest` (`escrow.rs`; plaintext refused). Rules, in one transaction:
1. Register or verify the secret (§3.1).
2. When `recipients_fp` equals the latest frame's recipients fingerprint, the number of X25519 stanzas must
   equal the number of recipients (`400 invalid`).
3. Same (device, luks_uuid, sha256(ciphertext)) already stored: same fp → `204`; other fp → `400 invalid`.
4. Caps: 3 rows per (device, luks_uuid, fp); 20 rows per device in 30 days (`429 too_many`).
5. Insert. When fp equals the latest frame's fp and the secret was not registered by this request, delete
   that device's rows for the same `luks_uuid` with another fp received after `registered_at`.
Responses: `204`, `400 invalid`, `401`, `403 secret_mismatch`, `413 too_large` (> 4 KiB), `429 too_many`.

### 3.6 `POST fetch-token`

- Body `{device_id, escrow_secret}`. Allowed iff the school has a token cutoff (set by a rotation), the
  device's secret is registered and verifies, and `registered_at < cutoff`. (The old permanent block after an IT
  reset is dropped: a reset device registers again with a new `registered_at`, which is after the cutoff.)
- `200 {"fetch_token":"<current token>"}`; otherwise `403 renew_refused`. Agent behaviour unchanged (renews when
  the stale header was seen, at most hourly).

### 3.7 Agent behaviour changes

- Base URL = `seed.server_url` (an origin, no path) + `/api/device/v1/`; one prefix constant in `Fetcher`.
- `status` always sends the device credential. The agent sends no status when it has no device identity or
  the transport is not allowed for the secret (https, or http on lab images); it logs this locally.
- Every server error body is JSON; plain-text handling can go.

### 3.8 Seed

`Seed` as defined in `mastersos-bundle` (`seed.rs`); its `oidc` is the `[school.oidc]` table, including the
user-layer key `mastersos_claims` (`login_domain` was removed, Erratum 2). `server_url` is the server origin (scheme, host,
optional port, no path); `Seed::validate` refuses a path. A seed is made for the agent version of the image
it goes with. Made by `mastersos seed make` (§4.9).

### 3.9 Reserved (later phases)

`POST push-token`, `GET inbox`, `POST inbox/{seq}/result`, `POST diagnostics`,
`POST diagnostics/{id}/complete`, `POST support`, `GET logos/{sha256}.png` (the logo moves under the prefix,
built by `Fetcher`). In phase 1 they answer `404 not_available`. The agent treats `not_available` as 'this server does not offer
it yet': push-token, inbox and the logo retry after 6 h (± 20 % jitter) with no user-visible error; the logo
step keeps the cached or no logo. A phase-1 agent hides 'Get help' and sends no help request or diagnostics,
whatever `support.enabled` says; the agent release that implements phase 3 turns them back on.
Every `not_available` answer is `404` with body code `not_available`; the agent recognises it only by that
code. A 404 with any other code keeps its current meaning.

## 4. CLI API (`/api/cli/v1/schools/{school}/mastersos/`)

### 4.1 Auth

- `Authorization: Bearer <access token>` from the identity provider (audience `devices`, as `auth-config` states it); the caller must be an admin of
  `{school}` (the server's rules for people). `{school}` is the identity provider's organisation id (lowercase UUID); a school that has
  not been enabled for MastersOS (§5.1) answers `404 not_found` on every path below.
- **Step-up** (fresh sign-in, Erratum 1; `401 step_up_required` with the RFC 9470 challenge)
  is required for: registering a key or an escrow recipient, deleting either, reading or deleting recovery
  keys, resetting a device secret, listing escrow registrations, removing a device, and `seed` (it returns the
  fetch token).
- Error envelope as in §2, with the server's general codes (`unauthenticated`, `forbidden`, `not_found`, `invalid`,
  `conflict`, `step_up_required`, `unavailable`), plus the codes named below.

### 4.2 Keys and escrow recipients

- `POST keys/probe` → `{"nonce_b64","message_b64"}`; message = `b"mastersos-keyprobe-v1\n" || nonce` (32 random
  bytes); a probe is valid 5 minutes and usable once (shared by keys and recipients).
- `POST keys` (step-up) `{"label","trust_key":{"id","alg":"ed25519","public_key"},"nonce_b64","signature":
  {"key_id","alg","sig"}}`: label 1–64 characters after trimming; the probe is spent before verification; the id
  must equal `rk-` + first 4 bytes hex of sha256(public key); signature over the probe message. `201
  {"key_id","fingerprint"}`; `409 key_exists`; `422 signature_invalid`; `422 key_invalid`; `410 probe_expired`.
- `GET keys` → `[{"key_id","alg","public_key","fingerprint","label","created_at","in_latest_trust",
  "last_used_at"}]` (`last_used_at` = latest version or heartbeat it signed).
- `DELETE keys/{key_id}` (step-up): `409 key_still_trusted` if the latest frame's trust has it or a recipient
  bound to it is in the latest frame's recipients; otherwise deletes the key and its recipients. `204`.
- `POST escrow-recipients` (step-up) `{"recipient","bound_key_id","nonce_b64","sig_b64","label"}`: `recipient`
  canonical `age1…`; bound key registered; signature over `b"mastersos-escrow-recipient-v1\n" || recipient ||
  "\n" || nonce`. `201`; `409 recipient_exists`; `422 signature_invalid`.
- `GET escrow-recipients` → `[{"recipient","bound_key_id","label","created_at","in_latest"}]`.
- `DELETE escrow-recipients/{recipient}` (step-up): `409 recipient_in_use` if the latest frame lists it.

### 4.3 Frame

Sent with every upload; computed by the CLI from the text it uploads:

```json
{
  "format": 2,
  "version": 7,
  "issued_at": "2026-11-20T09:00:00+07:00",
  "school_id": "0193…",
  "trust": [{"id":"rk-1a2b3c4d","alg":"ed25519","public_key":"<base64>"}],
  "escrow_recipients": ["age1…"],
  "features_used": ["format_2","config","kiosk"]
}
```

`features_used` uses the strings of `manifest.rs` `features_used` and `format_<n>`; the user-layer
`format = 3` adds `format_3`.

### 4.4 Two-step publish

- `POST publish/pending` `{"frame":{…},"digest_hex"}`. The CLI computes the content digest of what it is about
  to sign (`archive.rs` `content_digest`). Checks, first failure wins:
  1. `frame.version == latest + 1` (`409 version_conflict`, `details.latest_version`).
  2. `frame.issued_at` within ±10 minutes of server time (`422 clock_skew`).
  3. `frame.school_id == {school}` (`422 school_mismatch`).
  4. Trust: non-empty; every key equal (id, alg, public key) to a registered key (`422 trust_key_unregistered`).
  5. Recipients: each registered and bound to a key in `frame.trust` (`422 recipient_unregistered`).
  6. Feature gate (§4.5).
  Stored for 30 minutes (at most 5 per person, the oldest dropped). `201 {"pending_id","version","digest_hex",
  "message_b64","expires_at","trust_change":{"added":[ids],"removed":[ids]},"warnings":[{"code","message"}]}`,
  `message_b64` = base64 of `b"mastersos-bundle-v1\n" || content_digest` (the 32 raw bytes); `digest_hex` =
  the same 32 bytes as 64 lowercase hex digits. The CLI checks the echoed digest and message before
  signing.
- `GET publish/pending/{id}` → the same object plus `"frame"`; `410 pending_expired`.
- `DELETE publish/pending/{id}` → `204`.
- `POST publish/pending/{id}/commit`, body = the **signed archive** built by the CLI with `archive.rs`
  (`Content-Type: application/gzip`, ≤ 20 MiB):
  1. Pending live (`404`/`410 pending_expired`).
  2. Read the archive with the shared limits (20 MiB compressed, 64 MiB unpacked, member paths, no duplicates,
     only `manifest.toml`, `signature`, `files/…`, `scripts/…` and their directory entries)
     (`422 archive_invalid`); recompute the content digest; it must equal the pending digest
     (`422 digest_mismatch`).
  3. Latest still `version - 1` (`409 version_conflict`).
  4. The `signature` member (shared `SignatureFile` TOML) verifies over the message with a key of the **latest**
     frame's trust (version 1: of its own trust) (`422 signature_invalid`).
  5. The signer is in the new frame's trust (R5) (`422 trust_rule`).
  6. Gate re-run (§4.5).
  7. Store the received bytes unchanged with frame, digest, signer, publisher and time; delete the pending.
  → `200 {"version"}`. Audited.
- R7/R8 reduce to the above because only Ed25519 keys exist and every registered key is a school key.

### 4.5 Feature gate

For each string in `frame.features_used` not in the latest frame's `features_used`, count devices of the
school that sent an **authenticated** status in the last 30 days, are not removed, and do not report the
string in `manifest_features`. Any such device → `422 feature_unsupported`
`details:{"feature","devices":[{"device_id","serial","os_version","last_seen"}]}`. IT updates those devices, or
removes devices that are not real (§4.8), and publishes again. A string the latest version
already uses is only a warning (`feature_unsupported_in_use`) in `warnings`.

### 4.6 Versions

- `GET versions` → `[{"version","published_at","published_by","signed_by","digest_hex"}]`.
- `GET versions/{v}/archive` → the archive (`application/gzip`, `X-Mastersos-Version`).

### 4.7 Heartbeat

- `POST heartbeat` `{"heartbeat":"<heartbeat TOML>"}` (the CLI builds and signs the statement locally from
  its verified chain). Checks: parses as the shared heartbeat format (`422 invalid`); `version` and
  `digest_hex` equal the latest (`409 not_latest`); `issued_at` within ±10 minutes (`422 clock_skew`);
  `1 day ≤ not_after − issued_at ≤ 31 days` (`422 invalid`); signature verifies with the latest frame's trust
  (`422 signature_invalid`). Stored verbatim. `204`. Audited.
- `GET heartbeat` → `{"version","not_after","signed_by"}` of the heartbeat devices receive, or `null`.

### 4.8 Devices and recovery

- `GET devices` → `[{status fields…, "last_seen","fetch_token_stale","behind","has_errors","removed_at"}]`;
  `GET devices/{device_id}` → one, plus `"results"`. Also listed by `arbella fleet devices --platform
  mastersos`.
- `DELETE devices/{device_id}` (step-up): sets `removed_at`. A removed device is left out of lists, counts and
  the feature gate; its reports are stored but do not restore it. `POST devices/{device_id}/restore` clears
  `removed_at`. Rows of devices removed more than 90 days are purged by a daily job.
- `GET devices/{device_id}/recovery-keys` (step-up) → `[{"luks_uuid","recovery_key_age","recipients_fp",
  "received_at","serial","first_for_luks"}]`, newest first; an audit row is written in the same transaction
  (no audit, no data).
- `DELETE devices/{device_id}/recovery-keys?luks_uuid=` (step-up), `DELETE devices/{device_id}/escrow-secret`
  (step-up), `GET escrow-registrations?registered_since=` (step-up) → `[{"device_id","registered_at",
  "serial","last_seen"}]`. All audited.

### 4.9 Seeds

- `POST seed` (step-up) → `{"server_url","school_id","fetch_token"}` (`409 no_published_version` before
  version 1). Audited (without the token).
- `mastersos seed make [--group G] --out FILE` calls it, then downloads and verifies the published chain itself
  and takes `trust`, `min_version` (= the latest verified version), `school_name`, `group`, the group's
  effective Wi-Fi, the IT account and (when the group's device config allows `sso`) `oidc` from the latest
  verified version, refusing when its `[school] id` differs from `school_id`; then it runs `Seed::validate`
  and writes the seed with the fingerprint header, 0600. `seed check` verifies a seed against the verified chain and checks
  `server_url`, `school_id` and the fetch token's shape too.

## 5. Server operations (operator commands)

(Erratum 3: the three commands below are subcommands of the server's operator tool.)

1. `mastersos enable <school>`: the school id must be a lowercase UUID (the identity provider's organisation id); creates the
   first fetch token. Until then the school has no MastersOS API.
2. `mastersos fetch-token rotate <school> [--compromised-at TIME]`: new current token; the old one becomes
   retired; cutoff = `min(old cutoff, compromised-at or now)`.
3. `mastersos fetch-token drop-retired <school>`: retired tokens stop working; cutoff cleared.
4. Daily job: purge pending uploads, probes and devices removed more than 90 days ago.
5. Retention: versions, heartbeats and audit rows are never deleted.
6. Device secret reset (§4.8) keeps the recovery-key rows.

## 6. CLI (`mastersos`) obligations

- Commands: `init|pull|check|diff|publish`, `key new|register|list|add|remove`, `heartbeat`, `verify`,
  `recovery read <device>`, `seed make|check`, `spec [section]`, `login|logout`. `mastersos-sign` merges in;
  crate `mastersos-mcp` becomes `mastersos-cli`; removed: `mcp`, AI tokens, PKCS#8 keys, `keygen`,
  `restore-from-paper`, `setup`, `--key`, purpose tokens, WebAuthn keys.
- **Credentials**: when `arbella` is on `PATH`, `mastersos` runs `arbella auth token [--step-up] --json` and
  uses `{"fleet_url","access_token","expires_at"}`; `arbella` handles refresh and the browser step-up. Without
  `arbella`, `mastersos login --server URL` does the same itself (device grant and loopback step-up against the
  issuer from `GET /api/cli/v1/auth-config` (unauthenticated; `200 {"issuer","client_id","audience","scopes":[…],
  "step_up_acr"}`: the CLI runs the device grant against `issuer` with `client_id`, `audience` and `scopes`, and
  a step-up as an authorization-code + PKCE flow on a loopback redirect with `acr_values=<step_up_acr>`,
  `max_age=0` and `prompt=login`)) and keeps its own `~/.config/mastersos/credentials.json` (0600).
  On `401 step_up_required` the CLI asks for a step-up token once and retries once.
- `publish` = build frame + upload + verify the answer's digest locally + sign with the school key file +
  commit + sign and post a 30-day heartbeat.
- `school name`: `[school] name` is stamped from `GET /api/cli/v1/schools` (the organisation's name).

## 7. Obligations of the server's side beyond the server

- `arbella auth token [--step-up] --json` (kept with the settings server).
- `arbella fleet devices list --platform mastersos` shows MastersOS devices with `user_config`.

## 8. Verification (both parties)

- Shared vectors: the server's tests run `mastersos-bundle/testdata/{digest,heartbeat,escrow,kit}-vectors.json`
  (copied into the server's testdata with their source commit).
- Archive reading: the server's reader accepts every archive in mastersos's archive tests (incl. long and non-ASCII
  member paths) and refuses the invalid ones.
- Cross-language end to end on the remote build runner: build the server and the `mastersos` CLI, start the server with a test issuer,
  and run: key new/register, init, publish (twice, the second rotating trust), heartbeat, pull, verify, seed
  make + seed check, an agent `Fetcher` run (bundle, heartbeat, status, escrow, fetch-token renewal after a
  rotation), recovery read; plus failure cases (wrong key, stale version, unregistered key, feature gate).
- Lab VM: the lab image installed from a `seed make` seed, accepting versions from the server, escrowing its key,
  reporting status; then the reflash of the first school's laptops.

## 9. Open questions (closed at sign-off)

- M1. Agent: is `not_available` back-off of 6 h (§3.9) acceptable for push/inbox/diagnostics/support/logo?
- M2. CLI: is calling `arbella auth token` acceptable, and the standalone `mastersos login` with device grant +
  loopback step-up in Rust?
- M3. Anything in §3 that the agent cannot do without touching OS-integration code?
- M4. Frame: can the CLI compute every field from the same parser devices use, including `features_used` for
  format 3?
- M5. Sequencing with the user-layer plans A–C in the same repo (CLI crate rename vs plan A Task 6).
