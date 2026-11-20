# Protocol v1: field encodings as the server reads them

Given by the server team on 2026-11-20 from their code, compared with our vector files
(`core/mastersos-bundle/testdata/{digest,heartbeat,kit}-vectors.json`, `escrow-vector.json`): no mismatch, and their tests
consume byte-identical copies. Read from code, not yet run against our binaries: the cross-language end to end proves it.
Plans A and C take every encoding from this table; a difference found while implementing is reported, not worked around.

Terms. **std-pad**: standard base64 with padding, strict (no line breaks, canonical trailing bits, padding required).
**url-nopad**: URL-safe base64 without padding, same strictness. **hex**: lowercase only.

## Device side

- `Authorization: Bearer <fetch token>`: printable ASCII 0x21-0x7e, 1-256 bytes. Tokens the server mints are 32 random
  bytes url-nopad; clients treat the token as opaque.
- `X-Mastersos-Device` (status only): equals the body's `device_id` byte for byte.
- `X-Mastersos-Device-Secret` (status only): url-nopad of exactly 32 bytes; absent → `401 device_auth_missing`.
- Answers: `X-Mastersos-Version` (bundle `200`): decimal u64. `X-Mastersos-Fetch-Token`: the literal `stale`.
- Every device route checks the fetch token first: without a valid one, `401 unauthorized`, the reserved routes included.
  With a valid one the reserved routes answer `404 not_available`; `GET logos/{file}` does so only for a name ending in
  `.png`, any other name is `404 not_found`.
- `POST escrow`, strict JSON with exactly `device_id, serial, luks_uuid, recovery_key_age, recipients_fp, escrow_secret`:
  - `device_id`: 1-128 bytes, no control characters. `serial`: at most 128, may be absent or null.
  - `luks_uuid`: lowercase 8-4-4-4-12.
  - `recovery_key_age`: the age ASCII armor text itself as a JSON string (not wrapped in base64), at most 2048 bytes,
    64-column lines, LF or CRLF; scrypt-only is refused; the stanza count equals the number of distinct latest recipients
    when `recipients_fp` is the latest.
  - `recipients_fp`: 64 hex = sha256(`"mastersos-escrow-recipients-v1\n"` + the recipients sorted bytewise, deduplicated,
    joined with `"\n"`).
  - `escrow_secret`: url-nopad of exactly 32 bytes, in the body (status carries the secret in the header).
- `POST status`: no binary field; `seed_trust_fingerprints` is a list of strings the server does not validate;
  `bundle_version` is a u64 no larger than the i64 maximum; unknown keys are ignored.
- `POST fetch-token`: request exactly `{device_id, escrow_secret}` (same rules); answer `{"fetch_token":"…"}`.
- `GET bundle`: the raw `.tar.gz`, `application/gzip`; `204` when there is nothing newer.
- `GET heartbeat`: `text/plain`, the TOML exactly as posted; `204` when none. Inside: `digest_hex` 64 hex, `[signature] sig`
  std-pad (64 bytes).

## Command line side

- `POST keys/probe` answer: `nonce_b64` (32 bytes) and `message_b64`, both std-pad; message =
  `"mastersos-keyprobe-v1\n" || nonce`. A probe lives 5 minutes and is used once.
- `POST keys`, strict JSON `{label, trust_key{id,alg,public_key}, nonce_b64, signature{key_id,alg,sig}}`: `public_key`
  (32 bytes), `sig` (64) and `nonce_b64` are std-pad; `alg` is `ed25519` only; `label` 1-64 characters. Key id = `rk-` +
  hex(sha256(public key)[:4]); the answer also has `fingerprint`, the first 8 bytes as `xxxx-xxxx-xxxx-xxxx`.
- `POST publish/pending`: JSON `{frame, digest_hex}` (not the archive). Frame keys: `format, version, issued_at, school_id,
  trust, escrow_recipients, features_used`; `trust` entries `{id, alg, public_key}` std-pad; `escrow_recipients` are `age1…`
  strings. Answer: `pending_id` (a UUID), `digest_hex`, `message_b64` = std-pad of `"mastersos-bundle-v1\n" || digest`
  (the 32 raw bytes).
- `POST publish/pending/{id}/commit`: the body is the raw `.tar.gz` (at most 20 MiB). No JSON, no key id, no separate
  signature: the signature is the archive's `signature` member (TOML `key_id, alg, sig`; `sig` std-pad).
- `POST heartbeat`: `{"heartbeat":"<TOML text>"}`; statement `version, digest_hex, issued_at, not_after` plus
  `[signature]`; at most 16 KiB; `issued_at` within 10 minutes of the server's time; validity 1 to 31 days; the digest equals
  the latest version's. `GET heartbeat` on the command line API: JSON `{version, not_after, signed_by}` or `null`.
- `POST escrow-recipients`: `{recipient, bound_key_id, nonce_b64, sig_b64, label}`; `recipient` is canonical lowercase
  Bech32 `age1…`, 62 characters; `nonce_b64` and `sig_b64` std-pad. `sig_b64` is a bare string here, while key registration
  uses the object `signature{key_id,alg,sig}`.
- `GET devices/{id}/recovery-keys`: an array of `{luks_uuid, recovery_key_age, recipients_fp, received_at, serial,
  first_for_luks}`; `recovery_key_age` is the armor string as received.
- `GET /api/cli/v1/schools`: an array of `{id, name, time_zone}`.
- Errors: `{"error":{"code","message","details"?}}`; branch on `code` only.

## Signatures

Pure Ed25519 over raw bytes (no pre-hash, no SSH signature format, no namespace). Messages are a text prefix plus raw
bytes, never canonical JSON:

- key probe: `"mastersos-keyprobe-v1\n" || nonce(32)`;
- bundle: `"mastersos-bundle-v1\n" || digest(32)`;
- heartbeat: `"mastersos-heartbeat-v1\n" || version u64 BE || digest(32) || issued_at i64 BE || not_after i64 BE`;
- escrow recipient: `"mastersos-escrow-recipient-v1\n" || recipient text || "\n" || nonce(32)`.

Content digest: sha256 over the sorted paths, each `path 0x00 lowercase-hex-sha256(content) \n`; `manifest.toml` included,
`signature` excluded. `webauthn-es256` never verifies on the server.

## Not covered by a shared vector yet

The device secret and `escrow_secret`, the fetch token, `luks_uuid`, the key-probe nonce and message, the bundle
`signature` TOML and the heartbeat `[signature]` as wire text, `seed_trust_fingerprints`. Plan C adds vectors for these to
`core/mastersos-bundle/testdata`; the server team copies them and pins them in its tests.
