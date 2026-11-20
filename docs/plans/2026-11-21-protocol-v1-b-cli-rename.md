# Protocol v1 B: `mastersos-cli` replaces `mastersos-mcp` and `mastersos-sign` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One crate `core/mastersos-cli` builds the one program `mastersos`, which has absorbed `mastersos-sign`; the MCP server, AI tokens, purpose tokens, PKCS#8 keys, `keygen`, `restore-from-paper`, `setup`, `--key` and WebAuthn keys are gone from the command line (protocol v1 §6).

**Architecture:** A mechanical change. The crate directory and package are renamed, the `mastersos-sign` library moves into `core/mastersos-cli/src/sign/` (plus `platform.rs`, `safe.rs`), and its subcommands become `mastersos` subcommands under their final protocol v1 names. The network calls keep the old transport with one token file until plan C replaces the transport; no command of the old names survives this plan. Release workflows, installers, the skill and the docs follow.

**Tech Stack:** Rust 2021, clap, cargo workspaces; GitHub Actions; bash and PowerShell installers.

**Spec:** protocol v1 (frozen, draft 2 + Erratum 1 and 2) §6 first bullet. Its §0 is private: never quote or copy it.

## Blocking questions

None. Decisions made here (the coordinator may overrule before execution):

1. Kept: the offline commands `check`, `diff`, `explain`, `migrate`, `hash-password`, `spec`, and the server commands `init`, `pull`, `publish`, `devices`, `logo upload`, `connect` (the last two disappear in plan C with the old transport; `devices` stays, on `GET devices`).
2. `mastersos-bundle` keeps `Ed25519Signer::{generate_pkcs8, from_pkcs8}` and `webauthn.rs`: agent tests and Devices use them, and plan A owns the agent. Removing them is a follow-up after A and B merge.
3. Command names from now on: `key new|register|list|add|remove`, `verify`, `heartbeat`, `recovery read <device>`, `seed check`; the school key file is `--key-file PATH` (`-` = first line of stdin) everywhere; `--school-key`, `--kit` and `--key` are gone, no aliases. `mastersos-sign sign --pending` has no successor (`publish` signs).
4. Pins move to one directory, `<config dir>/mastersos/pins` (`--pin-dir` overrides); `~/.config/mastersos-sign/` is no longer read.

## Global Constraints

- Files, comments, errors and script output in English; end-user (Device) text only through gettext (`image/system-i18n/*.po`); this plan adds none.
- No AI attribution in commits. `python3 -I tools/check-private.py` before every commit. No private names: no hostnames other than `*.example`, loopback or `192.0.2.x`, no organisation ids; say "the remote build runner".
- This Mac cannot build the Rust workspace and local Docker is forbidden: builds and tests run on the remote build runner through the labtest MCP tools (`test_run(path, suites="core", args="-p mastersos-cli")`, `suites="image-tests", args="check-tree"`). Resolution-only cargo commands that compile nothing (`cargo metadata`, `cargo update --workspace`) may run on the Mac. Release the runner with `env_release` at the end.
- `image/patches/authd-oidc/*.patch` are never edited.
- `bash image/tests/check-tree.sh` stays green. Today no assertion names `mastersos-mcp`, `mastersos-sign`, `mcp` or the install scripts (checked with `grep -n 'mastersos.sign\|mastersos.mcp\|mcp' image/tests/check-tree.sh`: only `mastersos-signin` lines); run it anyway after every task that edits docs or skills.
- `core/mastersos-bundle/docs/manifest-spec.md` and `skills/mastersos-admin/reference/settings-reference.md` are byte-identical today (`spec.rs:749` test); any edit is made to both, identically.
- TDD: each task writes the failing test or check first.
- No compatibility burden: no aliases, no hidden old commands, no fallback for old pin locations.
- Parallel work: plan A (`docs/plans/2026-11-21-protocol-v1-a-agent.md`) runs at the same time. This plan owns `core/Cargo.toml`, `core/Cargo.lock`, `core/Cross.toml`, `core/mastersos-mcp/**` → `core/mastersos-cli/**`, `core/mastersos-sign/**` (deleted), `.github/workflows/{cli-release.yml,mastersos.yml}`, `.gitleaks.toml`, `tools/install/*`, `skills/**`, `README.md`, `README.en.md`, `docs/glossary.md`, `image/docs/keys.md:368`, and comment lines in `core/mastersos-bundle/src/{keyid.rs,sign.rs,status.rs,webauthn.rs}` and `core/mastersos-bundle/tests/vectors.rs`. It must not touch `core/mastersos-agent/**`, `core/mastersos-bundle/src/{seed.rs,checks.rs}` (plan A edits their `mastersos-sign` comments), `.labtest.yml` or `image/docs/keys.md:200-210`. Plan A adds no dependency and does not edit `Cargo.lock`, so the lock merges cleanly.
- Worktree branch `feat/protocol-v1-b-cli-rename`; commit per task; do not push.

## Review Focus

1. A school key file given to `--key-file` that is a PEM PKCS#8 key (an old `keygen` output) must be refused with a message that names what it is, not parsed or half-used → Task 3 (`pkcs8_file_is_refused_as_key_file`).
2. A school key file that is readable by others is still refused (owner-only rule kept through the move) → Task 3 (`loose_key_file_is_refused`, ported).
3. The paper kit text (as printed) still opens recovery keys after the move → Task 3 (`kit_vectors_still_parse`).
4. An install over an earlier one must not leave a `mastersos` that is older than the archive (archives now hold one program) → Task 4 (`test-install.sh` asserts the version of the installed `mastersos`).
5. The settings reference copy and the bundle spec drift apart when only one is edited → Task 5 (existing `spec.rs` identity test runs).

---

### Task 1: Rename the crate to `mastersos-cli`

**Files:**
- Move: `core/mastersos-mcp/` → `core/mastersos-cli/` (`git mv`)
- Modify: `core/mastersos-cli/Cargo.toml` (`name = "mastersos-cli"`, the `[[bin]] name = "mastersos"` comment), `core/Cargo.toml:3` (members), `core/Cross.toml:6` (comment), `core/Cargo.lock` (regenerated)
- Modify: `.github/workflows/cli-release.yml:101,106` (`-p mastersos-cli`)

**Interfaces:**
- Produces: package `mastersos-cli`, binary `mastersos`, library crate `mastersos_cli` (integration tests `use mastersos_cli::…`).

- [ ] **Step 1: Failing check** on the Mac: `cd core && cargo metadata --format-version 1 --no-deps | python3 -I -c 'import json,sys; n={p["name"] for p in json.load(sys.stdin)["packages"]}; sys.exit(0 if "mastersos-cli" in n and "mastersos-mcp" not in n else 1)'`. Expected: exit 1.
- [ ] **Step 2: Rename**: `git mv`, edit the manifests, replace `mastersos_mcp` with `mastersos_cli` in `core/mastersos-cli/tests/*.rs` and `src/main.rs`; `cd core && cargo update --workspace` (resolution only).
- [ ] **Step 3: Run** the check from Step 1 (exit 0) and `test_run(suites="core", args="-p mastersos-cli")`. Expected: PASS.
- [ ] **Step 4: Commit** `refactor(cli): rename crate mastersos-mcp to mastersos-cli`.

### Task 2: Remove the MCP server, AI tokens, purpose tokens and `setup`

**Files:**
- Modify: `core/mastersos-cli/src/lib.rs` (remove `rmcp` imports `:30-35`, `Router`, `router`, `serve_stdio` `:470-535`, `TokenUse`, `connect`'s kind/scope checks, `is_ai_token`, `default_ai_token_file`, `check_kind`, `check_scopes` `:265-370`, `OpError::to_tool_text`; tests `token_kind_matches_the_command`, `scope_refusal_names_ai_only_for_the_ai_path`, `connect_checks_the_token_kind` go)
- Modify: `core/mastersos-cli/src/tools.rs` (keep `Req`, `Body`, `build`, `device_wanted`; remove `Kind`, `Tool`, the schema structs, `schema`, `input_schema`, `mcp_tools`, `call_local`, `run_local`, `check_result`, `read_member` and their tests)
- Modify: `core/mastersos-cli/src/cli.rs` (remove `--ai-token-file`, `Cmd::Setup`, `Cmd::Mcp`, `setup()`, the AI branches in `run`; `ConfigFile` loses `ai_token_file`; `connect` saves the server and token without checking its purpose)
- Modify: `core/mastersos-cli/Cargo.toml` (drop `rmcp`, `schemars`; dev-deps drop `rmcp`), `core/Cargo.toml` (drop the `# MCP` block with `rmcp`; `schemars` stays, the bundle uses it), `core/Cargo.lock`
- Test: `core/mastersos-cli/tests/cli_surface.rs` (new)

**Interfaces:**
- `connect(server: &str, token_file: &Path) -> Result<Api, StartError>` (no `TokenUse`): reads the token file, checks the owner-only rule, calls `whoami` only to fail early.

- [ ] **Step 1: Write the failing tests** in `cli_surface.rs` (run the binary `env!("CARGO_BIN_EXE_mastersos")`): `mcp_and_setup_are_unknown_commands` (`mastersos mcp`, `mastersos setup` → exit 2, stderr contains `unrecognized subcommand`); `ai_token_option_is_gone` (`mastersos --ai-token-file x check` → exit 2); `help_mentions_no_mcp_or_ai_token` (`mastersos --help` text has none of `mcp`, `MCP`, `AI token`, `ai-token`).
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-cli --test cli_surface")`. Expected: FAIL.
- [ ] **Step 3: Implement** the removals; `cargo update --workspace`; `git grep -n rmcp core` is then empty (`Cargo.lock` included).
- [ ] **Step 4: Run** `test_run(suites="core", args="-p mastersos-cli")`. Expected: PASS.
- [ ] **Step 5: Commit** `refactor(cli): drop the MCP server, AI tokens, purpose tokens and setup`.

### Task 3: Absorb `mastersos-sign`

**Files:**
- Move: `core/mastersos-sign/src/chain.rs` → `core/mastersos-cli/src/sign/chain.rs`; `kit.rs` → `src/sign/kit.rs`; `lib.rs` → `src/sign/mod.rs`; `platform.rs` → `src/platform.rs`; `safe.rs` → `src/safe.rs`; their unit tests move with them; `core/mastersos-sign/tests/cli_help.rs` → merged into `core/mastersos-cli/tests/cli_surface.rs`
- Delete: `core/mastersos-sign/` (Cargo.toml, `src/main.rs`)
- Modify: `core/mastersos-cli/Cargo.toml` (add `sha2`, `age`, unix `nix` (`user`, `fs`) and `rustix`, windows `windows-sys` with the same features as `mastersos-sign`; drop the `mastersos-sign` path dependency), `core/Cargo.toml` (members), `core/Cargo.lock`
- Modify: `core/mastersos-cli/src/lib.rs` (`pub mod sign; pub mod platform; pub mod safe;`), `src/cli.rs` (subcommands), `src/publish.rs` (`SignWith` keeps only the kit), `src/workdir.rs:832-870` (no passkey wording; `trust_table` writes no `rp_id`)
- Modify: `.gitleaks.toml:8` (the `core/mastersos-sign/src/lib.rs` entry is removed: the PEM code it allowed is deleted)

**Interfaces:**
- Removed from the moved code: `keygen`, `KeygenOutput`, `restore_from_paper`, `write_paper`, `paper`, `pem`, `PEM_*`, `PAPER_*`, `load_key`, `key_from_pkcs8`, `write_secret`, `SigningKey::File` (`SigningKey` becomes the kit only, or is replaced by `&Kit` everywhere), `SignWith::KeyFile`, `key_line`'s passkey suffix, `Api::from_token_file`'s "key token"/"recovery token" wording.
- Produces (clap, in `cli.rs`):
  - `key new --out PATH [--school NAME]` (was `mastersos-sign school-key new`; output lines unchanged except the next-step hint: `mastersos key register --key-file <file>`)
  - `key register --key-file PATH --label TEXT` (was `mastersos-sign register`; registers the key, then its escrow recipient)
  - `key list|add FILE|remove CODE [--key-file PATH]` (was `keys …`)
  - `verify [--pin-dir DIR]`, `heartbeat --key-file PATH [--days 1..=31]`, `recovery read <DEVICE> --key-file PATH`, `seed check <FILE>`
  - `init DIR --key-file PATH…`, `publish [DIR] --key-file PATH [--allow-reroute NAME…]`
  - global `--pin-dir DIR` (default `<config dir>/mastersos/pins`, via `platform::config_dir("mastersos")`)
  - A key file must parse as `mastersos_bundle::kit::Kit` (`sign::kit::load_kit`, owner-only check kept); a file starting with `-----BEGIN` is refused with `"<path> is a PEM key, not a school key file; school keys are made with mastersos key new"`.

- [ ] **Step 1: Write the failing tests** (`cli_surface.rs` unless named)
  - `old_names_are_unknown`: `school-key`, `keygen`, `restore-from-paper`, `escrow-read`, `seed-check`, `register`, `sign`, `keys` → exit 2; `publish --school-key x`, `publish --kit x`, `publish --key x` → exit 2.
  - `key_new_names_file_in_dir`, `key_new_prints_an_absolute_path` (ported from `cli_help.rs`).
  - `publish_without_key_file_says_so`: stderr contains `--key-file`.
  - `pkcs8_file_is_refused_as_key_file`: a 0600 file whose text is `concat!("-----BEGIN ", "PRIVATE KEY-----\n…")` (split so gitleaks does not flag the test) → exit 1, message as above.
  - `loose_key_file_is_refused` (ported `loose_kit_file_loads_but_loose_key_file_is_refused`, kit part only, unix).
  - `kit_vectors_still_parse` (in `src/sign/kit.rs` tests): every kit text of `mastersos-bundle/testdata/kit-vectors.json` loads through `load_kit` from a 0600 file and yields the vector's key id and recipient.
  - `recovery_read_takes_the_device_as_argument`: `mastersos recovery read --help` shows `<DEVICE>`.
- [ ] **Step 2: Run** `test_run(suites="core", args="-p mastersos-cli")`. Expected: FAIL.
- [ ] **Step 3: Implement** the move (`git mv` to keep history), the removals, the new clap tree; port `mastersos-sign/src/main.rs` handlers into `cli.rs` functions (`key_new`, `key_register`, `verify`, `heartbeat`, `recovery_read`, `seed_check`) with unchanged bodies apart from the removed key kinds; replace every `mastersos_sign::` path with `crate::sign::`, `crate::platform::`, `crate::safe::`; `cargo update --workspace`.
- [ ] **Step 4: Run** `test_run(suites="core")` (fmt, clippy, all tests). Expected: PASS. `git grep -nP 'mastersos[-_]sign(?!in)' core -- ':!core/mastersos-agent' ':!core/mastersos-bundle/src/seed.rs'` lists only bundle comment lines (Task 5).
- [ ] **Step 5: Commit** `refactor(cli): mastersos absorbs mastersos-sign; PKCS#8, keygen and passkeys removed`.

### Task 4: Release workflow and installers ship one program

**Files:**
- Modify: `.github/workflows/cli-release.yml:2,101,106,114,116,235` (header comment; `cargo test --locked -p mastersos-bundle -p mastersos-cli`; `build … -p mastersos-cli`; package only `mastersos` / `mastersos.exe`; release notes `MastersOS command line (mastersos)`)
- Modify: `.github/workflows/mastersos.yml:58` (comment)
- Modify: `tools/install/install.sh:2,26,166,174,178,184` (only `mastersos`), `tools/install/install.ps1:3,121,137,156` (only `mastersos.exe`; the `mastersos mcp` rename comment goes), `tools/install/test-install.sh:42,47,108,134`, `tools/install/test-install.ps1:129`

**Interfaces:** archives `mastersos-<target>.tar.gz` / `.zip` contain exactly `mastersos` / `mastersos.exe`.

- [ ] **Step 1: Write the failing test:** in `test-install.sh` the stub archive holds only `mastersos`, and the script asserts after install that `~/.local/bin/mastersos` exists, prints the stub's version, and that the installer's output names no `mastersos-sign`; same in `test-install.ps1`.
- [ ] **Step 2: Run** `bash tools/install/test-install.sh` on the Mac (it runs on macOS in CI and needs no GNU tools). Expected: FAIL (installer still wants `mastersos-sign`).
- [ ] **Step 3: Implement** the installer and workflow edits.
- [ ] **Step 4: Run** `bash tools/install/test-install.sh` (PASS) and `shellcheck tools/install/*.sh` if installed; the PowerShell test runs in CI only (`cli-release` on a branch push, done by the coordinator).
- [ ] **Step 5: Commit** `build(cli): release and install one program, mastersos`.

### Task 5: Docs, skill and comments

**Files:**
- Modify: `README.md:12-13,25,65,72,113,120,167-168,182,338-413` (the `mastersos-sign` section becomes the `mastersos key|verify|heartbeat|recovery|seed` commands; `mastersos mcp` lines go; new text in English), `README.en.md:31-36`
- Modify: `docs/glossary.md:20,39` (`mastersos key new`; drop `mastersos-sign` from the Latin-letters list)
- Modify: `skills/mastersos-admin/SKILL.md:24-36,75,92-97` (no AI token, no MCP section; the AI runs only `check`, `diff`, `explain`, `spec` and `--json devices list|show` with IT's own login; school keys: `mastersos key new`, `mastersos key register`; `keys` → `key`, `--school-key` → `--key-file`)
- Modify (both, identically): `core/mastersos-bundle/docs/manifest-spec.md:3036` and `skills/mastersos-admin/reference/settings-reference.md:3036`: `register the school key it belongs to (\`mastersos key register --key-file\`), or remove it with \`mastersos key remove\``
- Modify (comments only): `core/mastersos-bundle/src/keyid.rs:1`, `sign.rs:130`, `status.rs:38`, `webauthn.rs:925`, `core/mastersos-bundle/tests/vectors.rs:1` (`the mastersos command line` instead of `mastersos-sign`)
- Modify: `image/docs/keys.md:368` (`mastersos mcp` removed from the sentence)
- Not changed: `docs/plans/**`, `docs/specs/**` (history).

- [ ] **Step 1: Failing check:** `git grep -nP 'mastersos[-_]sign(?!in)|mastersos[-_]mcp|mastersos mcp|ai-token|AI token|--school-key|keys (list|add|remove)' -- ':!docs/plans' ':!docs/specs' ':!core/Cargo.lock' ':!core/mastersos-agent' ':!core/mastersos-bundle/src/seed.rs'` prints lines. Expected: non-empty.
- [ ] **Step 2: Edit** the files above.
- [ ] **Step 3: Run** the check (empty), `test_run(suites="core", args="-p mastersos-bundle spec")` (the byte-identity test), `test_run(suites="image-tests", args="check-tree")`, `python3 -I tools/check-private.py`. Expected: PASS.
- [ ] **Step 4: Commit** `docs: one mastersos command line, no MCP or AI token`.

---

## Self-review notes

- §6 removals: `mcp`, AI tokens, purpose tokens, `setup` → Task 2; PKCS#8, `keygen`, `restore-from-paper`, `--key`, WebAuthn → Task 3; crate rename → Task 1; `mastersos-sign` merged → Task 3. Kit readable for `recovery read` and `key add` → Task 3 (`kit_vectors_still_parse`).
- Every reference the coordinator listed: workflows (Task 4), `tools/install/*` (Task 4), skill (Task 5), docs (Task 5), check-tree (no assertion; run each task), `.labtest.yml` (no crate name: `core` suite uses `--workspace`, plan A's build uses `--bin`), `deny.toml` (names no crate; the CI `deps` job re-checks after `rmcp` leaves), dependabot (`.github/dependabot.yml` has no crate rule; unchanged).
- Plan C replaces the transport of every server command (`init`, `pull`, `publish`, `key register|list`, `verify`, `heartbeat`, `recovery read`, `seed check`, `devices`) and removes `connect`, `logo upload` and the token file.
