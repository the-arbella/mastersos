# School key CLI and macOS / Linux / Windows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** IT runs `mastersos connect` → `init --school-key` → `publish --school-key` on macOS, Linux or Windows, in plain words, with no copy-and-paste and no heartbeat concept.

**Architecture:** A small `platform` module in `mastersos-sign` (which `mastersos-mcp` already depends on) owns config dirs, owner-only files, the no-echo prompt and the key-file permission note on all three OSes. The CLI derives trust and disk-unlocking recipients locally from school key files, and `publish --school-key` signs a heartbeat silently after the version. CI adds macOS and Windows test runs and a release with per-target binaries and install scripts.

**Tech Stack:** Rust 1.98 (clap, tokio, reqwest, rustix on Unix, `windows-sys` on Windows), GitHub Actions, POSIX sh, PowerShell.

**Spec:** `docs/specs/2026-11-04-school-key-cli-design.md`

## Global Constraints

- User-facing words exactly per spec §3: **school key**, **key code** (`11d9-03eb` = first 8 hex digits of the key id, grouped 4-4), **check code** (first 8 hex digits of the content digest), **install file**; "heartbeat"/"kit"/"trust"/"escrow"/"digest" never in normal output or help (spec §4.5, §4.7). Errors may name the file and command, not the cryptography.
- All help, prompts, errors and output in English, `mastersos-sign` included. Every printed path absolute and native.
- `--school-key <FILE>` everywhere a school key is read; `--kit` stays as a hidden alias; `--key` (PKCS#8) stays hidden.
- School key file with group/other permissions: print `Make sure no other user can read this school key file. Keep it on a USB stick whenever you can.` and continue. Token files and `secrets.toml` stay strict (refuse).
- Config: Unix `$XDG_CONFIG_HOME/mastersos/` else `~/.config/mastersos/` (and `mastersos-sign`); Windows `%APPDATA%\mastersos\` (`%APPDATA%\mastersos-sign\`). A missing `HOME` on Windows is not an error.
- No change to wire formats, `MASTERSKIT1`, key derivation, chain rules or the heartbeat statement.
- Commits `<type>(<scope>): <中文说明>`; code comments in English; `python3 tools/check-private.py` clean before each commit (no private names, hosts or lab names in this repo).
- Tests run in the `.labtest.yml` suite `core` (remote runner); Windows/macOS behaviour is proven in GitHub Actions (Task 5). Heavy local builds on the Mac are blocked.

## Review Focus

- A school key on an exFAT USB stick (mode 0777, owner = current user) → works with the note; on Unix a key file owned by another uid is still refused. → Task 1 `school_key_broad_mode_warns_not_refuses`.
- `init --school-key` with a kit that is not registered for this school → refuses before writing anything, says where to make keys. → Task 3 `init_refuses_unregistered_key`.
- `publish --school-key` where the heartbeat commit fails (server 5xx) → the version stays published, exit code 0, one plain sentence, no "heartbeat" word. → Task 4 `publish_heartbeat_failure_keeps_version`.
- `connect` given an `ai:` token, or a token without `draft` → refuses and writes nothing. → Task 2 `connect_refuses_ai_token`.
- Windows: token file created by `connect` has a DACL readable only by the current user; a token file readable by `Users` is refused. → Task 1 `windows_private_file_acl` (cfg windows, runs in GitHub Actions).

---

### Task 1: `platform` module — dirs, owner-only files, prompt, key-file note

**Files:**
- Create: `core/mastersos-sign/src/platform.rs` (+ `pub mod platform;` in `lib.rs`)
- Modify: `core/mastersos-sign/Cargo.toml` (`[target.'cfg(windows)'.dependencies] windows-sys` with the Security/Authorization, Storage/FileSystem, System/Console features needed), `core/mastersos-sign/src/lib.rs:343-370` (`open_private` → `platform`), `core/mastersos-sign/src/main.rs:57` (pin dir), `core/mastersos-mcp/src/cli.rs:156` (`config_dir`), `cli.rs:414` (`check_private`), `cli.rs:~854` (no-echo read), `core/mastersos-mcp/src/workdir.rs:240-250`, `core/mastersos-mcp/src/publish.rs:1506`
- Test: unit tests in `platform.rs`

**Interfaces:**
- Produces (all in `mastersos_sign::platform`):
  - `pub fn config_dir(app: &str) -> anyhow::Result<PathBuf>` — `app` is `"mastersos"` or `"mastersos-sign"`.
  - `pub fn create_private(path: &Path) -> anyhow::Result<std::fs::File>` — new file, owner-only (0600 / current-user DACL), refuses an existing file.
  - `pub fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()>` — create-or-replace owner-only (temp file + rename).
  - `pub fn check_private(path: &Path) -> anyhow::Result<()>` — refuse group/other-readable (Unix mode & 0o077; Windows DACL granting read to Everyone, Users or Authenticated Users) and, on Unix, another owner.
  - `pub fn open_school_key(path: &Path) -> anyhow::Result<(std::fs::File, Option<&'static str>)>` — Unix: refuse another owner; broad mode → `Some(KEY_FILE_NOTE)`; Windows: broad DACL → `Some(KEY_FILE_NOTE)`.
  - `pub const KEY_FILE_NOTE: &str = "Make sure no other user can read this school key file. Keep it on a USB stick whenever you can.";`
  - `pub fn read_hidden_line(prompt: &str) -> anyhow::Result<zeroize::Zeroizing<String>>` — no echo on a terminal (rustix termios on Unix, console mode on Windows), plain line when stdin is not a terminal.

- [ ] **Step 1: Write the failing tests** in `platform.rs`:
  - `config_dir_uses_xdg_then_home` (Unix): with `XDG_CONFIG_HOME=/x` → `/x/mastersos`; unset + `HOME=/h` → `/h/.config/mastersos`.
  - `config_dir_uses_appdata` (`#[cfg(windows)]`): `APPDATA=C:\A`, no `HOME` → `C:\A\mastersos`.
  - `create_private_is_owner_only` (Unix: mode `0o600`; Windows: `check_private` passes).
  - `check_private_refuses_group_readable` (Unix 0o640 → Err mentioning the path).
  - `school_key_broad_mode_warns_not_refuses` (Unix 0o777 → `Ok((_, Some(KEY_FILE_NOTE)))`; 0o600 → `Ok((_, None))`).
  - `workdir_refuses_reparse_point` (`#[cfg(windows)]`): a junction or symlink in place of `manifest.toml` or `.mastersos` is refused like a Unix symlink (spec §5.4; `workdir.rs` symlink checks use `symlink_metadata` + `FILE_ATTRIBUTE_REPARSE_POINT` on Windows).
  - `windows_private_file_acl` (`#[cfg(windows)]`): `create_private` file passes `check_private`; after granting `BUILTIN\Users` read via `icacls` → `check_private` is Err.
- [ ] **Step 2: Run** the `core` suite with `-p mastersos-sign platform` → FAIL (module missing).
- [ ] **Step 3: Implement** `platform.rs`; switch the call sites listed above to it (`mastersos-sign` `open_private` → `check_private` + open; `load_kit` → `open_school_key`, printing the note to stderr once; mcp `config_dir()` → `platform::config_dir("mastersos")`; mcp token/`config.toml` writes → `write_private`; the termios prompt → `read_hidden_line`). Remove the remaining `#[cfg(unix)]`-only permission code from mcp.
- [ ] **Step 4: Run** the `core` suite, `core` suite full → PASS; also `cargo check --target x86_64-pc-windows-msvc -p mastersos-sign -p mastersos-mcp` on the `core` suite, (add the target in the suite setup if missing) → no errors.
- [ ] **Step 5: Commit** `feat(sign): 跨平台的配置目录、仅本人可读的文件与无回显输入`

### Task 2: one flag, `connect`, English `mastersos-sign`

**Files:**
- Modify: `core/mastersos-mcp/src/cli.rs` (flags, new `Cmd::Connect`, hide `Setup` from help), `core/mastersos-sign/src/main.rs` (flags, English help/prompts, hide `Keygen`/`RestoreFromPaper`, `kit new` naming), `core/mastersos-sign/src/lib.rs` (Chinese prompt strings → English), `core/mastersos-bundle/src/keyid.rs` (key code)
- Test: `core/mastersos-mcp/tests/cli_connect.rs` (wiremock server), unit tests in `keyid.rs`, `core/mastersos-sign/tests/` existing CLI tests updated

**Interfaces:**
- Produces: `mastersos_bundle::key_code(key_id: &str) -> Option<String>` (`"rk-11d903eb…"` → `Some("11d9-03eb")`; not an `rk-` id → `None`).
- Flags: `--school-key <FILE>` with `#[arg(alias = "kit", ...)]` hidden alias `--kit` on `mastersos publish`, `mastersos-sign sign|heartbeat|register|escrow-read`; `mastersos-sign kit new --out <FILE|DIR> [--school <slug>]` writes `<slug>-school-key-<code8>.kit` (or `school-key-<code8>.kit`) when `--out` is a directory, where `<code8>` is the key code without the dash.
- `mastersos connect <SERVER_URL> [--token-file <F>]`: reads the token with `platform::read_hidden_line("Paste the token from the Command line page: ")`; `whoami`; refuses a label starting `ai:` and scopes lacking `read` or `draft`; then `write_private` token (default `<config_dir>/token`) and `config.toml` (`server`, `token_file`). Output, three lines: `Connected to <school>.` (`<school>` = whoami's optional `school_name`, else the server's host name; the server adds that field separately) / `Token saved in <abs path>` / `Settings saved in <abs path>`.

- [ ] **Step 1: Failing tests:** `key_code_groups_first_eight` (`"rk-11d903eb"` → `"11d9-03eb"`, `"pk-x"` → None); `connect_saves_token_and_config` (stdin token, mock `whoami` `{label:"cli:IT", kind:"token", scopes:["read","draft"], school_name:"Alpha School"}` → `Connected to Alpha School.`; without `school_name` → `Connected to <host>.` → files exist, stdout has the three lines with absolute paths); `connect_refuses_ai_token` (`label:"ai:bot"` → exit≠0, no files written); `kit_kit_alias_still_works` (`publish --kit f` parses as `--school-key f`); `kit_new_names_file_in_dir`.
- [ ] **Step 2: Run** the `core` suite, `-p mastersos-mcp -p mastersos-bundle -p mastersos-sign` → FAIL.
- [ ] **Step 3: Implement.** Translate every Chinese user-facing string in `mastersos-sign` (help, prompts, output; `docs`/comments may stay). Hide `setup`, `keygen`, `restore-from-paper` with `#[command(hide = true)]`; their behaviour is unchanged.
- [ ] **Step 4: Run** → PASS; `grep -nP '[\x{4e00}-\x{9fff}]' core/mastersos-sign/src/main.rs` finds nothing in strings shown to users.
- [ ] **Step 5: Commit** `feat(mastersos): connect 命令、--school-key 与英文的 mastersos-sign`

### Task 3: `init --school-key` and `keys add|remove|list`

**Files:**
- Modify: `core/mastersos-mcp/src/cli.rs` (`Cmd::Init { dir, school_key: Vec<PathBuf> }`, `KeysCmd::{Add{file}, Remove{code}, List}`, `init_dir` at `cli.rs:673`), `core/mastersos-mcp/src/workdir.rs` (trust/recipient editing), `core/mastersos-mcp/src/template.toml` (a commented `[[trust]]` block the code fills)
- Test: `core/mastersos-mcp/tests/cli_init_keys.rs`

**Interfaces:**
- Consumes: `mastersos_sign::kit::load_kit`, `Kit::trust_key()`, `Kit::escrow_recipient()`, `Kit::key_id()`, `key_code` (Task 2), `Api` `GET /v1/admin/signing-keys`, `GET /v1/admin/escrow-recipients`.
- Produces: `workdir::set_trusted_keys(manifest_text: &str, keys: &[(TrustKey, String /*recipient*/)]) -> Result<String>` (replaces `[[trust]]` and `[school].escrow_recipients`, preserving comments elsewhere), `workdir::add_trusted_key(...)`, `workdir::remove_trusted_key(manifest_text: &str, code: &str) -> Result<String>` (Err `"cannot remove the last school key"` when it would leave no Ed25519 key).

- [ ] **Step 1: Failing tests:**
  - `init_writes_trust_from_school_keys`: two kits registered on the mock server → `manifest.toml` parses; `trust` equals `[kitA.trust_key(), kitB.trust_key()]`; `escrow_recipients` equals both recipients; stdout contains `Trusted keys: <codeA>, <codeB>` and the absolute folder path.
  - `init_refuses_unregistered_key`: kit not in `signing-keys` → exit≠0, message contains `is not registered for` and `signing page`, directory not created.
  - `init_requires_school_key`: no flag → clap error mentioning `--school-key`.
  - `keys_add_then_remove_round_trip`: add kitB to a folder trusting kitA → both present; `keys remove <codeB>` → only kitA.
  - `keys_remove_refuses_last_key`.
  - `keys_list_marks_local_trust`: output rows `code  label  registered  in this folder: yes|no`.
- [ ] **Step 2: Run** the `core` suite, `-p mastersos-mcp --test cli_init_keys` → FAIL.
- [ ] **Step 3: Implement.** Registered check compares by `trust_key` public key and by recipient string (not by label). Trust comes only from the files, never from server data.
- [ ] **Step 4: Run** → PASS (whole `core` suite).
- [ ] **Step 5: Commit** `feat(mastersos): init 与 keys 从学校钥匙文件写出受信钥匙，不再复制粘贴`

### Task 4: `publish` in plain words, silent check-in

**Files:**
- Modify: `core/mastersos-sign/src/lib.rs` (new fn), `core/mastersos-mcp/src/publish.rs` (outcome printing, call after commit), `core/mastersos-mcp/src/cli.rs` (`publish_dir` output)
- Test: `core/mastersos-mcp/tests/cli_publish_plain.rs` (wiremock), existing `publish` tests updated for wording

**Interfaces:**
- Produces: `pub async fn checkin_after_publish(api: &Api, key: &SigningKey<'_>, version: u64, digest: &[u8; 32], days: i64) -> anyhow::Result<chrono::DateTime<chrono::Utc>>` in `mastersos-sign` — builds the heartbeat statement for exactly that version/digest (no prompt; the caller has just verified and signed it), signs, verifies locally like a machine, `POST /v1/admin/heartbeat/commit`; returns `not_after`. `days = 30`.
- Output (spec §4.4): `Checked: no problems` / `Check code: <8 hex>` / `Published version N`; without a key: `Waiting for approval: open <link>` / `Compare the check code on that page with <8 hex>.` On check-in failure, after `Published version N`: `Computers may soon show "settings may be out of date". Open the admin site to fix it.` (stderr), exit 0. `--json` output unchanged in shape (adds `"checkin_until"` or `"checkin_error"`).

- [ ] **Step 1: Failing tests:** `publish_with_school_key_signs_checkin` (mock records one `heartbeat/commit` whose statement version == published version and digest == upload digest; stdout has no `heartbeat`/`digest`/`kit` words, case-insensitive); `publish_heartbeat_failure_keeps_version` (commit → 500: exit 0, stdout `Published version 1`, stderr the sentence); `publish_without_key_prints_link_and_check_code`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the `core` suite, `core` → PASS.
- [ ] **Step 5: Commit** `feat(mastersos): publish 用白话输出，并顺带完成每月确认`

### Task 5: CI on macOS and Windows, release binaries, install scripts, English docs

**Files:**
- Modify: `.github/workflows/mastersos.yml` (job `cli-tests` matrix `macos-latest`, `windows-latest`: `cargo test -p mastersos-bundle -p mastersos-sign -p mastersos-mcp`), create `.github/workflows/cli-release.yml`
- Create: `tools/install/install.sh`, `tools/install/install.ps1`
- Modify: `README.md` (getting started per OS), `docs/glossary.md` (spec §3 table, English + 中文 web terms), `core/mastersos-mcp` skills/docs that mention `--kit`, trust pasting, `setup`, passkeys or heartbeats
- Test: `tools/install/test-install.sh` (shellcheck + dry run against a local fake release dir)

**Interfaces:**
- Release: workflow on manual dispatch with input `ref`; builds `mastersos` and `mastersos-sign` for `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-pc-windows-msvc`; assets `mastersos-<target>.tar.gz` (`.zip` on Windows) + `SHA256SUMS`; tag `cli-<12-char sha>`; GitHub release named the same.
- `install.sh [--version cli-<sha>]` / `install.ps1 [-Version cli-<sha>]`: detect target, download asset + `SHA256SUMS`, verify, install to `~/.local/bin` / `%LOCALAPPDATA%\Programs\mastersos` (add to user PATH on Windows), print the installed path and `mastersos --version`. Default: newest `cli-*` release. No admin rights, no `sudo`.

- [ ] **Step 1: Write** `test-install.sh`: serves a fake release dir over `python3 -m http.server`, runs `install.sh --version cli-test` with `MASTERSOS_RELEASE_BASE` pointing at it → binary installed into a temp HOME; tampered `SHA256SUMS` → exit≠0 and nothing installed.
- [ ] **Step 2: Run** it → FAIL (no script).
- [ ] **Step 3: Implement** scripts and workflows; update docs to the new commands and words (no "kit", "trust text", "heartbeat", "passkey" in IT-facing docs).
- [ ] **Step 4: Verify:** `shellcheck tools/install/*.sh`; `test-install.sh` PASS; push the branch and run `cli-tests` + `cli-release` (dispatch with `ref` = branch head) in GitHub Actions → green, release assets present, `SHA256SUMS` matches.
- [ ] **Step 5: Commit** `ci(mastersos): macOS 与 Windows 测试、三平台发布包与安装脚本；文档改用新词汇`
