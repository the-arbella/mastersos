# User layer B: the agent and the image apply user configs per session Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On a Device with a `format = 3` bundle, every login gets the user config its rules choose (from the signed bundle and the issuer's facts), switched in by `pam-session` before the session starts and reverted to a fully blocked neutral state at logout; format 1/2 bundles behave exactly as today.

**Architecture:** At apply time a new step `user-layer` pre-renders, for every user config reachable on the Device plus a neutral one, the whole session state into per-config directories (Chrome policy file, compiled dconf DB, xdg dir, login scripts) and writes the root-only rules file. Switching is file swaps only: rename the Chrome policy file, rename a compiled dconf DB (`mastersos-session`, a second system DB in the dconf profile), re-point the symlink `/var/lib/mastersos-public/session` (first in `XDG_DATA_DIRS`), rewrite `session-mode`. `pam-session` does the switch at login (tightening and same-strength changes only); the agent then lifts exec-block stubs asynchronously, watches logind, and switches back to neutral and stops the user manager at logout. `pam-check` refuses a second human session. With a format 1/2 bundle the new step does nothing and every existing step runs unchanged.

**Tech Stack:** Rust 2021 (mastersos-agent, sync code in PAM paths, tokio in the resident agent), bash (image scripts), GNOME Shell JS (login extension), gettext catalogues.

**Spec:** `docs/specs/2026-11-19-user-layer-design.md`. Consumes Plan A (`docs/plans/2026-11-19-user-layer-a-bundle.md`); start only after Plan A is merged.

## Global Constraints

- Everything written into files is English; user-facing text goes through gettext domain `mastersos-system` (`core/mastersos-agent/src/i18n.rs`, `image/system-i18n/*.po`) with translations in every `.po` (all language packs, not only zh/th/en). File system paths are English. No AI attribution in commits.
- `python3 -I tools/check-private.py` before every commit; do not edit `image/patches/authd-oidc/0001-0006`.
- Format 1/2 bundles: every existing agent and image test stays green unchanged; no new file appears on a format 1/2 Device except empty directories created by tmpfiles.
- PAM paths (`pam-check`, `pam-session`) stay synchronous: no tokio, no network, no `dconf update`, no bundle parsing; they never panic (`deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)` outside tests, as `i18n.rs` does). `pam-session` keeps its 5 s budget (`PAM_CMD_TIMEOUT`, `system/ephemeral.rs:125`): the switch spawns no command.
- Fail closed: any read error in the switch path gives the fallback config; a fallback that cannot be switched in refuses the login; a late or failed exec-block lift leaves the stubs in place.
- Facts file (Plan C's contract, `docs/plans/2026-11-19-user-layer-c-broker.md`, read exactly this shape): `/run/mastersos/facts/<login_name>.json`, directory root 0700, file 0600, written by rename; content is either
  `{"version":1,"user":"<login_name>","granted_at":<unix seconds>,"facts":{…}}` or
  `{"version":1,"user":"<login_name>","granted_at":<unix seconds>,"error":"<text>"}`; `facts` keeps only `sub`, `org`, `org_role`, `org_nodes`, `classes`, `age_band`. Any other `version`, or `user` different from the PAM user, is an error.
- Facts are read only when `school.oidc.mastersos_claims = true` (written into the login policy); otherwise SSO logins resolve with no facts and no file is looked at.
- Plan A names used here, exactly: `UserConfig`, `Caps`, `Capability`, `ALL_CAPS`, `HomeMode`, `Kind`, `DeviceFacts`, `IssuerFacts`, `Resolution`, `UserRules` (`from_manifest`, `resolve`), `reachable_user_configs`, `user_config`, `guest_user_config`, `effective_device_config`, `FEATURE_FORMAT_3`, `Oidc::login_domain`, `Oidc::mastersos_claims`, `testutil::spec_example_v3`.
- Verification: `cd core && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace` on the remote build runner (Rust does not build on the Mac); `bash image/tests/check-tree.sh` and the touched shell tests in an `ubuntu:24.04` amd64 container under `$HOME` (colima); `node` tests for the login extension as `image/tests/login-people-test.sh` runs them. Release the build runner with `env_release` when the branch is done.
- Worktree branch `feat/user-layer-b`. Commit per task; do not push. VM checks are not run here: Task 11 hands them over.

## Review Focus

1. A login while the previous person's revert is still running (agent slow or dead) must be refused with the busy message, not get a half-switched state → Task 5 (`busy_while_active_marker_present`) and Task 6 (`revert_clears_marker_last`).
2. A facts file written by an earlier authentication (an unlock, a failed login) must never be used for a later login → Task 2 (`stale_facts_are_ignored_and_deleted`, `facts_for_other_user_untouched`).
3. A format 3 bundle that arrives while a person is signed in must not reset their session to neutral or to the device config; it re-renders and keeps the active config (or that config's new content) → Task 7 (`reapply_keeps_active_session`).
4. A user name with `/`, `..` or a leading dot in `PAM_USER` must not let the facts reader or the marker escape their directories → Task 2 (`facts_path_rejects_unsafe_names`).
5. A Chrome update (sysext refresh → `exec-block` sync) during a session with lifted capabilities must converge to that session's lifted set, not to "all blocked" or "all lifted" → Task 6 (`sync_uses_recorded_lifted_set`).

---

### Task 1: Per-capability exec-block

**Files:**
- Modify: `core/mastersos-agent/src/system/exec_block.rs:38-53` (group `TARGETS`), `:94-140` (`ensure`), `:163`, `:220-330` (`write_mode`, `read_mode`, `apply`, `sync_with`)
- Test: `exec_block.rs` tests (style of `:420-610`)

**Interfaces:**
- Produces:
  - `pub const TERMINAL_TARGETS`, `FILE_MANAGER_TARGETS`, `SETTINGS_TARGETS: &[&str]` (today's `TARGETS` split: terminals; `/usr/bin/nautilus`; `/usr/bin/gnome-control-center`); `TARGETS` stays as their concatenation.
  - `pub fn targets_for(lifted: &Caps) -> Vec<&'static str>` — the targets to block: all minus the groups whose capability is in `lifted`.
  - `pub fn apply_lifted(paths: &SysPaths, runner: &dyn Runner, lifted: &Caps) -> Result<()>` — under the lock: write the mode, then `ensure_set`.
  - `pub fn read_lifted(paths: &SysPaths) -> Result<Option<Caps>>` — `MODE_FILE` content: old values `block`/`browser` = empty set, `unblock`/`desktop` = `ALL_CAPS`; new form `lifted:<cap>,<cap>` (empty list allowed). Unknown content = `Some(empty)` (block everything).
  - `apply(paths, runner, block)` stays as a wrapper (`block` → empty set, else all) so `desktop.rs:472` is unchanged for format 1/2.
- [ ] **Step 1: Failing tests:** `lifting_file_manager_unblocks_only_nautilus`, `old_mode_values_still_read` (`block`, `unblock`, `browser`, `desktop`), `garbage_mode_blocks_everything`, `sync_uses_recorded_lifted_set` (mode `lifted:terminal` → terminals unblocked, nautilus and control-center stubs present), `unlocked_sync_never_lifts` (no lock + recorded lift → only blocking ensured, same rule as `:310-317`).
- [ ] **Step 2: Run** `cargo test -p mastersos-agent exec_block` on the remote build runner. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test -p mastersos-agent`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): exec-block per capability`.

### Task 2: Facts hand-off reader and the session paths

**Files:**
- Create: `core/mastersos-agent/src/user_layer/mod.rs` (+ `pub mod user_layer;` in `lib.rs`), `core/mastersos-agent/src/user_layer/facts.rs`
- Modify: `image/mkosi.extra/usr/lib/tmpfiles.d/mastersos.conf` (add `d /run/mastersos/facts 0700 root root -` and `d /run/mastersos/user-layer 0700 root root -`)
- Test: `user_layer/facts.rs` tests; `image/tests/check-tree.sh` (the tmpfiles lines)

**Interfaces:**
- Produces (`user_layer/mod.rs`):
  - `pub const FACTS_DIR: &str = "run/mastersos/facts";` (relative to root), `pub const FACTS_MAX_AGE: Duration = Duration::from_secs(120);`
  - `pub const RUN_DIR: &str = "run/mastersos/user-layer";`, `pub const ACTIVE_FILE: &str = "active.json";` (marker, Task 4).
  - `pub fn config_dir_name(id: &str) -> String` — `"u-"` + first 16 hex of sha256(id) (ids have no charset rule); `pub const NEUTRAL_DIR: &str = "neutral";`.
- Produces (`facts.rs`):
  - `pub enum FactsOutcome { Facts(IssuerFacts), Missing, Error(String), Stale }`.
  - `pub fn take_facts(root: &Path, user: &str, now: SystemTime) -> FactsOutcome` — opens `<root>/<FACTS_DIR>` with `safefs` (must be root-owned 0700, else `Error`), reads `<user>.json` (name must pass `login::user_name_ok` and contain no `/`; else `Error`), deletes it in every case, parses the Global Constraints shape (`version` must be 1, `user` must equal `user`, then `facts` → `IssuerFacts` or `error`; both or neither → `Error`); older than `FACTS_MAX_AGE` or in the future by more than 5 s → `Stale`.
  - The shape is Plan C's (patch 0007); document it in `facts.rs`'s module comment with a pointer to Plan C.
- [ ] **Step 1: Failing tests:** `fresh_facts_are_returned_and_deleted`, `stale_facts_are_ignored_and_deleted`, `error_record_is_error`, `wrong_version_is_error`, `user_mismatch_is_error`, `facts_and_error_both_is_error`, `missing_is_missing`, `facts_for_other_user_untouched`, `facts_path_rejects_unsafe_names` (`../x`, `a/b`, `.hidden`), `world_readable_dir_is_error`.
- [ ] **Step 2: Run** `cargo test -p mastersos-agent user_layer::facts` on the remote build runner. Expected: FAIL.
- [ ] **Step 3: Implement**; add the tmpfiles lines; in `check-tree.sh` extend the tmpfiles assertions with the two directories.
- [ ] **Step 4: Run** the agent tests on the remote build runner and `bash image/tests/check-tree.sh` in the container. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): read the issuer facts handed over at login`.

### Task 3: Pre-render every reachable user config (step `user-layer`)

**Files:**
- Create: `core/mastersos-agent/src/user_layer/render.rs`
- Modify: `core/mastersos-agent/src/system/desktop.rs:240-303` (`render_dconf` takes the session part), `:416-490` (`run`), `:534-612` (`webapps` writes into a given dir), `:360-386` (`hidden_overrides`)
- Modify: `core/mastersos-agent/src/system/chrome_policy.rs:147-163` (`render_policy(policy: &toml::Table) -> Result<String>` split out of `apply`)
- Modify: `core/mastersos-agent/src/login_queue.rs:282-345` (`export_list` takes a target dir)
- Modify: `core/mastersos-agent/src/system/mod.rs:46-77` (WRITE_ROOTS: `/etc/dconf/db`), `:249-278` (add `crate::user_layer::render::step()` right after `desktop::step()`)
- Modify: `image/etc-policy.conf` only if check-tree's WRITE_ROOTS cross-check asks for `/etc/dconf/db` (it is already `dir /etc/dconf/db`, line 48)
- Test: `user_layer/render.rs` tests (use `super::super::system::tests::{paths, tmp_root}` helpers and `mastersos_bundle::testutil::spec_example_v3`)

**Interfaces:**
- Consumes: `reachable_user_configs`, `user_config`, `UserRules::from_manifest`, Task 1 `targets_for`.
- Produces:
  - `pub fn neutral() -> UserConfig` — id `""`, preset learning, no caps, `Tidy`, nothing else.
  - `pub struct Rendered { pub dir: String, pub caps: Caps, pub home: HomeMode }` and the root-only index `<var_dir>/user-layer/index.json`: `{ "group": .., "rules": UserRules, "configs": { "<id>": Rendered }, "neutral": Rendered }` (0600).
  - Layout per config dir `d` (`config_dir_name(id)` or `NEUTRAL_DIR`):
    - `<var_dir>/user-layer/<d>/chrome.json` (0644 content, the file Task 4 renames into `/etc/opt/chrome/policies/managed/mastersos.json`; a copy is made in the staging directory `/etc/opt/chrome/policies/.mastersos-staging/<d>.json` (root 0700, same file system) so the rename is atomic; never stage inside `managed/`, which Chrome reads in full);
    - `/etc/dconf/db/mastersos-<d>.d/50-mastersos` + `locks/50-mastersos` (compiled by one `dconf update` per apply into `/etc/dconf/db/mastersos-<d>`);
    - `/var/lib/mastersos-public/user-layer/<d>/xdg/` (web-app launchers + icons, `Hidden=true` overrides, D-Bus overrides) and `/var/lib/mastersos-public/user-layer/<d>/login-scripts/` (+ `index.json`).
  - Rendering rules for one `UserConfig`, all from the existing renderers:
    - dconf: `render_dconf` with the config's web apps, Flatpak/deb dock entries filtered to that config's lists; the locked keys are `LOCKED_KEYS` minus the keys of lifted capabilities (`terminal` → `disable-command-line`, media-keys `terminal`; `settings` → `user-administration-disabled`; `extensions` → `disable-user-extensions`, `enabled-extensions`, `allow-extension-installation`, `disabled-extensions`); the remaining keys (`favorite-apps`, `custom-keybindings`) are locked unless `caps == ALL_CAPS` (today's `full` locks nothing; see the spec gap note in the plan report); `dock_files` = `file_manager` lifted.
    - xdg: `Hidden=true` over every app not in the Dash unless `all_apps` is lifted; D-Bus overrides: Nautilus + FileManager1 unless `file_manager`; `org.gnome.Settings` unless `settings`.
    - Chrome: `baseline()` + `chrome_policy`.
  - Dirs of configs no longer reachable are deleted (never the one named by the active marker, Task 4).
  - For format 1/2 bundles the step returns no item and removes nothing it did not create (`<var_dir>/user-layer` absent → nothing to do).
  - For format 3 the `desktop` step keeps only device-level work (kiosk launchers in `/var/lib/mastersos-public/xdg`, empty `mastersos.d` keyfile, no overrides, no exec-block, no session-mode) and `chrome_policy` / `login-scripts-export` write nothing; Task 4/6 own those files.
- [ ] **Step 1: Failing tests:** `renders_every_reachable_config_and_neutral` (spec example on group `default`: dirs for teacher, primary and neutral; index lists them), `teacher_full_has_no_locks_and_no_overrides`, `file_manager_lift_removes_nautilus_override_and_adds_files_to_dash`, `neutral_blocks_everything`, `unreachable_dirs_are_removed_but_active_is_kept`, `format2_bundle_renders_nothing` (and the existing `desktop`/`chrome_policy`/`login_queue` tests unchanged), `index_is_root_only` (0600).
- [ ] **Step 2: Run** `cargo test -p mastersos-agent user_layer::render` on the remote build runner. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test -p mastersos-agent`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): pre-render user configs at apply time`.

### Task 4: The switch, and `pam-session` choosing the config

**Files:**
- Create: `core/mastersos-agent/src/user_layer/switch.rs`
- Modify: `core/mastersos-agent/src/system/guest.rs:505-519` (`Enqueue` branch), `:245-295` (`close_session` of a normal account becomes `SessionAction::Close(user)` when the policy says format 3)
- Modify: `core/mastersos-agent/src/system/login.rs:158-188` (`LoginPolicy` gains `#[serde(default)] local_users_admin: bool`, `#[serde(default)] user_layer: bool` and `#[serde(default)] mastersos_claims: bool`, written by the login step from the bundle), `:796-916` (write them)
- Modify: `core/mastersos-agent/src/system/home_tidy.rs:1013-1030` (`on_login` takes `tidy: Option<bool>`; `None` = today's `tidy_decision`)
- Modify: `image/mkosi.extra/usr/share/dconf/profile/user` → `user-db:user`, `system-db:mastersos-session`, `system-db:mastersos`; `image/mkosi.extra/usr/lib/environment.d/40-mastersos.conf` → `XDG_DATA_DIRS=/var/lib/mastersos-public/session/xdg:/var/lib/mastersos-public/xdg:${XDG_DATA_DIRS:-…}`; `image/tests/check-tree.sh:843-850` (the two expected texts)
- Test: `user_layer/switch.rs` tests, `guest.rs` tests, `image/tests/user-env-test.sh`

**Interfaces:**
- Consumes: Task 2 `take_facts`, Task 3 index and layout, `login::classify`, `login::is_admin`, `LoginPolicy`.
- Produces:
  - `pub struct Active { pub uid: u32, pub user: String, pub user_config: String, pub dir: String, pub caps: Caps, pub state: ActiveState }`, `pub enum ActiveState { Open, Closing }` — `<root>/<RUN_DIR>/<ACTIVE_FILE>` (0600).
  - `pub fn device_facts<'a>(policy: &LoginPolicy, user: &'a str, uid: u32, group: &'a str) -> DeviceFacts<'a>` — `kind` from `classify` (Sso/Local/Guest; kiosk never reaches here); `admin` = SSO in `admin_users`, or `itadmin` with `uid == it_account_uid`, or local with `local_users_admin`.
  - `pub fn switch_to(root: &Path, public: &Path, var: &Path, r: &Rendered) -> Result<()>` — in this order: Chrome policy (re-make the staging copy `.mastersos-staging/<d>.json` from `chrome.json`, then rename it over `managed/mastersos.json`), dconf (copy `/etc/dconf/db/mastersos-<d>` to `mastersos-session.tmp`, rename to `mastersos-session`), `session` symlink (`symlink user-layer/<d>` as `session.tmp`, rename over `session`), `session-mode` (`full` iff `user_apps` is lifted, else `learning`, via `exec_block::write_session_mode`). No command is spawned.
  - `pub fn on_open(root: &Path, paths: &SysPaths, policy: &LoginPolicy, user: &str, uid: u32) -> OpenOutcome` with `pub enum OpenOutcome { NotUserLayer, Switched { user_config: String, fallback_reason: Option<String>, home: HomeMode }, Refused }` — reads the index; `take_facts` for SSO users only when `policy.mastersos_claims`; `UserRules::resolve`; on switch error retries with the fallback; second error → `Refused`; writes `Active { state: Open }` before returning `Switched`; refuses (`Refused`) when an `Active` for another uid exists (backstop of Task 5).
  - `pam-session` `Enqueue` branch: when `policy.user_layer`, call `on_open` first; `Refused` → exit 1 printing the busy message (Task 5's text); `Switched` → `home_tidy::on_login(.., Some(home == Tidy))`, then the existing `claim_from_pam` and `enqueue`. Guest (`EphemeralOpen` with guest) runs `on_open` too, after `session_open`.
  - `pam-session` `close_session` for a human account with `policy.user_layer`: set `Active.state = Closing` and send SIGUSR1 to the agent (same call as `login_queue::enqueue_at` uses); never fails.
- [ ] **Step 1: Failing tests:** `switch_renames_all_four_in_order` (fake root; asserts the four targets and that no runner call happened), `admin_rule_wins_for_itadmin`, `sso_without_facts_gets_fallback_with_reason`, `plain_oidc_never_reads_facts` (`mastersos_claims = false`: the facts file is neither read nor deleted), `broken_config_dir_falls_back`, `broken_fallback_refuses`, `other_uid_active_refuses`, `format2_policy_is_not_user_layer` (no file touched), `close_marks_closing_and_signals`, `guest_resolves_with_kind_guest`; in `user-env-test.sh`: the generators still read `session-mode` and `XDG_DATA_DIRS` starts with `/var/lib/mastersos-public/session/xdg`.
- [ ] **Step 2: Run** `cargo test -p mastersos-agent user_layer::switch system::guest` on the remote build runner and `bash image/tests/user-env-test.sh` in the container. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the full verification (the remote build runner + `check-tree.sh` + `user-env-test.sh` + `pam-hooks-test.sh`). Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent,image): switch the session to the user's config at login`.

### Task 5: One human session at a time (`pam-check`)

**Files:**
- Modify: `core/mastersos-agent/src/system/login.rs:228-260` (new `DENY_SESSION_BUSY` msgid), `:337-411` (`decide` gains the busy check), `:1303-1322` (`pam_check_main` reads the marker and translates the message)
- Modify: `image/system-i18n/mastersos-system.pot` and every `image/system-i18n/*.po`
- Test: `login.rs` `decide` tests; `image/tests/notice-lib-test.sh` if it lists msgids

**Interfaces:**
- Produces: `pub const DENY_SESSION_BUSY: &str = "Someone is still signed in on this device. They need to sign out first, or restart the device.";` (English msgid; `pam_check_main` passes it through `i18n::text` with the system language, like the agent's notices). `decide(..)` gains `active: Option<&Active>`: when `policy.user_layer` and `active` names another uid (any state) → `Deny(DENY_SESSION_BUSY)`; the same uid with `Open` → allowed (unlock, reauth); kiosk accounts keep today's rules (`decide_kiosk`); `PASSTHROUGH_SERVICES` unchanged. Never names the other person.
- [ ] **Step 1: Failing tests:** `busy_while_active_marker_present` (other uid, Open and Closing), `same_uid_allowed`, `format2_policy_ignores_marker`, `admin_has_no_override`, `kiosk_rules_unchanged`.
- [ ] **Step 2: Run** `cargo test -p mastersos-agent system::login` on the remote build runner. Expected: FAIL.
- [ ] **Step 3: Implement**; add the msgid to the pot and a translation to every `.po` (msgfmt-check them as `mkosi.build` does: `msgfmt --check -o /dev/null <po>` in the container).
- [ ] **Step 4: Run** agent tests and the msgfmt check. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): refuse a second session while one is signed in`.

### Task 6: Agent: lift after login, revert after logout

**Files:**
- Create: `core/mastersos-agent/src/user_layer/session.rs`
- Modify: `core/mastersos-agent/src/run.rs:962-990` (`take_logins` → after draining, `session::after_login`), main loop poll timer (reuse `quiet::POLL` = 5 s cadence) → `session::watch`
- Modify: `core/mastersos-agent/src/system/home_tidy.rs:877-893` (`linger_off_for_students`: with the user layer, linger off for every human uid)
- Test: `user_layer/session.rs` tests

**Interfaces:**
- Consumes: `Active`, `switch_to`, index (`Rendered`), `exec_block::apply_lifted`, `guest::seat_sessions_busy`-style logind read.
- Produces:
  - `pub fn after_login(paths: &SysPaths, runner: &dyn Runner) -> Result<()>` — if `Active{state: Open}`: `exec_block::apply_lifted(paths, runner, &active.caps)`.
  - `pub fn watch(paths: &SysPaths, runner: &dyn Runner) -> Result<WatchOutcome>`, `pub enum WatchOutcome { Idle, StillOpen, Reverted { user_config: String } }` — `Closing`, or `Open` with no logind session of that uid (`loginctl --json=short list-sessions`, class `user*`, state not `closing`): switch to neutral (`switch_to(.., neutral)`), `exec_block::apply_lifted(empty)`, `loginctl disable-linger <uid>` and `systemctl stop user@<uid>.service` (timeouts as `SYSTEMCTL_TIMEOUT`), then delete the marker **last**. Any step failing keeps the marker (logins stay refused) and returns the error for the report item `user-layer:revert`.
  - At agent start (and in `apply-local` before GDM): no marker → `switch_to(neutral)` + `apply_lifted(empty)` when the bundle is format 3 (boot always neutral, spec §4.8).
- [ ] **Step 1: Failing tests:** `lift_follows_active_caps`, `revert_on_closing`, `revert_when_logind_has_no_session`, `revert_clears_marker_last` (a failing `systemctl stop` keeps the marker), `boot_without_marker_switches_to_neutral`, `still_open_does_nothing`.
- [ ] **Step 2: Run** `cargo test -p mastersos-agent user_layer::session` on the remote build runner. Expected: FAIL.
- [ ] **Step 3: Implement**; wire `after_login` into `take_logins` (spawn_blocking) and `watch` into the 5 s poll.
- [ ] **Step 4: Run** `cargo test -p mastersos-agent`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): lift capabilities after login, revert to neutral after logout`.

### Task 7: Reapply, sysext hook and boot render from the active session

**Files:**
- Modify: `core/mastersos-agent/src/user_layer/render.rs` (end of the step), `core/mastersos-agent/src/system/exec_block.rs:328` (`sync_main` unchanged in shape: it reads the recorded lifted set of Task 1)
- Test: `user_layer/render.rs` tests

**Interfaces:**
- Produces: at the end of the `user-layer` step: marker `Open` whose config is still reachable → re-render then `switch_to(that config)` (new content applies immediately; capabilities only via the agent's `after_login`, so a newly *removed* capability is blocked at once and a newly added one is lifted by `after_login`); marker `Open` whose config is no longer reachable → switch to the fallback's dir and block everything (`apply_lifted(empty)`), report `user-layer:active` failed with "the signed-in person's user config was removed; they get it at their next login"; no marker → `switch_to(neutral)`.
- [ ] **Step 1: Failing tests:** `reapply_keeps_active_session`, `reapply_tightens_removed_capability_now`, `removed_config_falls_back_blocked`, `no_marker_reapply_is_neutral`.
- [ ] **Step 2: Run** `cargo test -p mastersos-agent user_layer::render` on the remote build runner. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test -p mastersos-agent`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): reapply keeps the signed-in person's user config`.

### Task 8: Install union, login card block list

**Files:**
- Modify: `core/mastersos-agent/src/system/flatpak.rs:226-229` and `core/mastersos-agent/src/deb_apps/status.rs:222-230` (`install_mode`/`shown`: with a format 3 bundle install always; the device Config already carries the union from Plan A's `effective_device_config`)
- Modify: `core/mastersos-agent/src/system/kiosk.rs:145`, `core/mastersos-agent/src/system/login.rs:483-494` (`profile(..).flatpaks` gate: true for format 3)
- Modify: `core/mastersos-agent/src/system/login.rs:699-714, 1064` (card block list from `guest_user_config`'s `chrome_policy`)
- Test: `flatpak.rs`, `deb_apps/status.rs`, `login.rs` tests
- Not here: `login_domain` (agent → `branding.json`, greeter expansion) is Plan C Tasks 4–5 only.

**Interfaces:**
- Consumes: `guest_user_config`, `user_config`.
- Produces: `card_device_blocks` input = the guest config's `chrome_policy` for format 3 (format 1/2 unchanged: the Config's).
- [ ] **Step 1: Failing tests:** `format3_installs_union_regardless_of_mode`, `card_blocks_come_from_guest_config`, `card_policy_dir_has_no_staging_files` (after a switch `managed/` holds only `mastersos.json`).
- [ ] **Step 2: Run** the agent tests on the remote build runner. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the same. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): install union, card block list from the guest config`.

### Task 9: Status field, `format_3` support, spec update

**Files:**
- Modify: `core/mastersos-bundle/src/status.rs:17-60` (`#[serde(default)] pub user_config: Option<String>` on `StatusReport`)
- Modify: `core/mastersos-agent/src/report.rs:35-54` (add `FEATURE_FORMAT_3`, `FEATURE_OIDC_LOGIN_DOMAIN`), `:160-176` (fill `user_config` from the marker's `user_config` when `Open`), `:437-441` (assertion back to `format_feature(MAX_FORMAT) == FEATURE_FORMAT_3`)
- Modify: `docs/specs/2026-11-10-learning-session-integrity-design.md:21,35` (per-account mode now exists: point to `2026-11-19-user-layer-design.md`)
- Test: `report.rs` tests

- [ ] **Step 1: Failing tests:** `report_carries_active_user_config`, `report_has_no_user_config_without_session`, `supported_features_include_format3`.
- [ ] **Step 2: Run** `cargo test -p mastersos-agent report` on the remote build runner. Expected: FAIL.
- [ ] **Step 3: Implement**; update the integrity spec lines.
- [ ] **Step 4: Run** the full verification of Global Constraints. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): report the session's user config; agents read format 3`.

### Task 10: Whole-branch review

- [ ] **Step 1:** Dispatch one fresh reviewer (most capable model) over `git diff master...feat/user-layer-b` with this plan and the spec; fix confirmed findings with tests; rerun the full verification.
- [ ] **Step 2: Commit** fixes `fix(agent): review findings for the user layer`.

### Task 11: VM verification checklist (hand over, do not run here)

Write `lab/results/2026-11-19-user-layer/checklist.md` and send it to the session that runs image builds and VMs. Each item: steps, expected result, screenshot names (kept, new numbers, never overwritten).

1. Format 2 bundle on a fresh image: learning and full Groups look exactly as before (terminal blocked/unblocked, Dash, Chrome policy in `chrome://policy`, home tidy).
2. Format 3 spec example: teacher (class role via facts fixture), primary (org node), admin (itadmin), guest; each gets its Dash, Chrome policy, locks; `dconf read /org/gnome/desktop/lockdown/disable-command-line` per config.
3. `allow = ["file_manager"]`: Nautilus opens, terminal still the stub; after a Chrome sysext refresh during the session the same holds.
4. Logout → greeter → second person: neutral first (stubs back, `session` symlink → neutral, `user@<uid>` stopped, no linger).
5. Locked screen of person A, "switch user" to B: refused with the busy message in the system language; A unlocks normally.
6. Agent killed during a session, then logout: next login refused until the agent restarts and reverts; reboot clears it.
7. New bundle published during a session: content updates, a removed capability blocks at once, the session is not reset.
8. Facts: no facts file → fallback (report item says why); facts file older than 120 s → fallback; an unlock does not change the session's config.
9. Login card in open mode blocks the guest config's `URLBlocklist`; `login_domain`: typing a bare username signs in as `<name>@<domain>`.
10. dconf: after an apply that runs `dconf update`, `/etc/dconf/db/mastersos-session` (no `.d` directory) is untouched and still the active person's DB; `gsettings` in the session reads the session DB's values and locks.
11. Timing: `pam-session` duration in the journal under 1 s for a switch (budget 5 s).

- [ ] **Step 1:** Write the checklist file and commit `docs(lab): user layer VM checklist`.
- [ ] **Step 2:** Send it to the VM session (SendMessage) and report its path.
