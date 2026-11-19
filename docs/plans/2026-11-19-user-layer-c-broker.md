# User layer, Plan C: broker patch 0007, facts hand-off, login domain — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The OIDC broker takes the local user name from `login_name`, refuses other organisations before grant, and
hands the person's facts to `pam-session` through a consume-once file. The login screen turns a bare username into
`<username>@<login_domain>`.

**Architecture:** All broker changes are in one new carried patch,
`image/patches/authd-oidc/0007-mastersos-issuer-profile.patch`. It is switched on per school by a file the agent writes,
`/etc/authd/oidc/mastersos-expected-org`, with the same fail-closed marker scheme as patch 0006. With the profile off,
the broker behaves exactly as today. The image adds the facts directory and lets the broker write to it. The agent writes
the expected-org file and puts `login_domain` into `branding.json`. The greeter extension expands a bare name. Plan B
(agent session switch) reads the facts files; this plan only writes them.

**Tech Stack:** Go (authd-oidc at the tag pinned in `image/mkosi.build`), Rust (`mastersos-agent`), GJS (GNOME Shell
extension, pure helpers tested under node), bash (`check-tree.sh`), systemd units and tmpfiles.

**Spec:** `docs/specs/2026-11-19-user-layer-design.md` §2.5 and §5. Contract it implements:
`fleet/docs/specs/2026-11-19-mastersos-user-layer-contract.md` draft 5 (agreed).

## Global Constraints

- `image/patches/authd-oidc/0001`–`0006` are checked byte for byte: never edit them. 0007 is a git patch against the
  authd repository root that changes only `authd-oidc-brokers/` and brings `func TestMastersOS…` tests
  (`image/tests/check-tree.sh` §32). `mkosi.build` applies `*.patch` in name order and runs `go test -run '^TestMastersOS' ./internal/broker/`.
- Make 0007 in a clone of `TAG`/`COMMIT` from `image/mkosi.build` with 0001–0006 applied and committed as the base, then
  run `git diff <base> -- authd-oidc-brokers > image/patches/authd-oidc/0007-mastersos-issuer-profile.patch`.
- Rust and Go builds and tests run on the remote build runner (`mcp__labtest__test_run`), never on the Mac (Docker there
  has 1 GB). Shell tests (`check-tree.sh`, `login-people-test.sh`) run in an `ubuntu:24.04` amd64 container, mounted from under `$HOME`.
- Comments, errors, logs and docs are in English. Text a person sees on the login screen goes through the extension's
  `strings.js`/`login-i18n` catalogues.
- `login_name` shape (spec §5): lowercase, exactly one `@`, local part `[a-z0-9._-]{1,64}`, domain `[a-z0-9.-]{1,253}`.
- Facts file: `/run/mastersos/facts/<login_name>.json`, directory root 0700, file 0600, written by rename. Content is one of:
  `{"version":1,"user":"<login_name>","granted_at":<unix seconds>,"facts":{…}}` or
  `{"version":1,"user":"<login_name>","granted_at":<unix seconds>,"error":"<text>"}`. `facts` keeps only `sub`, `org`, `org_role`, `org_nodes`,
  `classes`, `age_band`. Plan B's reader uses exactly this shape.
- Profile marker line (in the broker drop-in): `# mastersos: issuer profile required (patch 0007)`. Expected-org file:
  `/etc/authd/oidc/mastersos-expected-org`, one lowercase UUID line plus `#` comments.
- **Interface assumed from Plan A** (`mastersos-bundle`): `Oidc.login_domain: Option<String>` (`school.oidc.login_domain`)
  and `Oidc.mastersos_claims: bool` (`school.oidc.mastersos_claims`, default false; see "Spec gap" at the end). Plan A
  validates both: `login_domain` must be in `allowed_domains`, and `mastersos_claims = true` needs `[school] id`.
- The end-to-end login against the real issuer waits until the issuer's plan is approved. It is the last item of Task 6
  and goes to a separate VM session (memory: heavy verification is batched for another session).

## Review Focus

1. **A failed userinfo must not reuse an earlier login's facts.** The broker deletes `<login_name>.json` at `NewSession`,
   including unlocks, and on any failure writes the `error` form. Test: `TestMastersOSFactsDeletedAtNewSession` and
   `TestMastersOSUserinfoFailureWritesError` (Task 3).
2. **Profile on, but the expected-org file is missing or unreadable.** Every SSO login must be denied before grant, so
   authd registers nobody. A broker without the profile must never fall back to email names. Test:
   `TestMastersOSMissingExpectedOrgDeniesEveryone` (Task 2). Agent side: `expected_org_write_failure_keeps_the_marker`
   (Task 4).
3. **A `login_name` with a path character or the wrong shape.** It must never become a file name or a user name.
   Test: `TestMastersOSBadLoginNameIsDenied` (Task 2) and `TestMastersOSFactsNeverLeaveTheDirectory` (Task 3).
4. **Userinfo whose `sub` or `org` differs from the ID token.** The broker must write the `error` form, never another
   person's facts. Test: `TestMastersOSUserinfoSubjectMismatchWritesError` (Task 3).
5. **A child types "Alice" where a local account `alice` exists.** The local account keeps precedence. Typing "Alice"
   with no such account gives `alice@<login_domain>`. Test: `expandLoginName` cases in `login-people-test.mjs` (Task 5).

---

### Task 1: Image — facts directory and broker write access

**Files:**
- Modify: `image/mkosi.extra/usr/lib/tmpfiles.d/mastersos.conf` (after the `d /run/mastersos/login-queue` line)
- Create: `image/mkosi.extra/usr/lib/systemd/system/authd-oidc.service.d/50-mastersos-facts.conf`
- Modify: `image/tests/check-tree.sh` (§17 around lines 765-777; new §81 after §80)

**Interfaces:**
- Produces: directory `/run/mastersos/facts` (root 0700) at boot. The broker may write there, and nowhere else outside `/var/lib/authd-oidc`.

- [ ] **Step 1: Write the failing check.** Add §81 to `check-tree.sh` in the style of §80 (`ok 81`/`bad 81`). It asserts:
  - `tmpfiles.d/mastersos.conf` has the exact line `d /run/mastersos/facts 0700 root root -`.
  - The drop-in has exactly `[Service]` and `ReadWritePaths=-/run/mastersos/facts`, nothing else besides comments.
  - No other `authd-oidc.service.d/*.conf` has a `ReadWritePaths=` line.

  Leave §17's "only one `ReadWritePaths=` in the unit" check as it is: it reads the unit file only.
- [ ] **Step 2: Run** `bash image/tests/check-tree.sh` in the ubuntu:24.04 container. Expected: `bad 81 …` and a non-zero exit.
- [ ] **Step 3: Add the tmpfiles line and the drop-in.** The drop-in comment says why the path has a `-` prefix: a missing
  directory must not stop the broker, so school sign-in keeps working and the person just gets the fallback config.
- [ ] **Step 4: Run** check-tree again. Expected: `ok 81 …`, exit 0.
- [ ] **Step 5: Commit**
  `git add image/mkosi.extra/usr/lib/tmpfiles.d/mastersos.conf image/mkosi.extra/usr/lib/systemd/system/authd-oidc.service.d/50-mastersos-facts.conf image/tests/check-tree.sh`
  `git commit -m "feat(image): facts directory for the broker's login hand-off"`

### Task 2: Patch 0007 part 1 — profile switch, scopes, `login_name`, organisation check

**Files:**
- Create: `image/patches/authd-oidc/0007-mastersos-issuer-profile.patch`. Inside the authd tree it adds
  `authd-oidc-brokers/internal/broker/mastersos_profile.go`, `mastersos_profile_test.go` (package `broker_test`),
  `mastersos_profile_internal_test.go`, and an export_test helper. It also adds small hunks in `broker.go` and `config.go`.
- Create: `image/tests/authd-oidc-patch-test.sh`. It reads `TAG`, `COMMIT`, `GO_VERSION` and `GO_SHA256` from
  `image/mkosi.build` with `sed`, clones and checks the commit, applies every `image/patches/authd-oidc/*.patch` in name
  order, downloads and verifies Go the way `mkosi.build` does, and runs
  `go test -count=1 -v -run '^TestMastersOS' ./internal/broker/` as an ordinary user. Run it on the remote build runner.

**Interfaces:**
- Consumes (upstream, read them at the pinned commit before writing):
  - `broker.go`: `NewSession`, where `session.oauth2Config` and its `Scopes` are built.
  - The user-info step in `finishDeviceAuth`, which calls the provider's `GetUserInfo(idToken)`.
  - The "requested username does not match the authenticated user" check.
  - `internal/providers/genericprovider/genericprovider.go` `GetUserInfo`: the fields it fills.
  - Patch 0006's `mastersosRequired`/`GetDropInDir` pattern; patch 0004's test helpers `signInOnCard` and `cardOnlyAddress`.
- Produces (package `broker`):
  - `const mastersosExpectedOrgFile = "mastersos-expected-org"`
  - `const mastersosProfileMarker = "# mastersos: issuer profile required (patch 0007)"`
  - `type mastersosProfile struct { active bool; org string }`. Active with an empty `org` means "deny every SSO login".
  - `func mastersosLoadProfile(cfgPath string) mastersosProfile`. Called beside `mastersosLoadDomains` in the config load (`broker.go`, the 0006 hunk).
  - `func mastersosScopes(p mastersosProfile) []string` → `["mastersos.facts", "org:<org>"]` when active, else nil. Appended to `oauth2Config.Scopes`.
  - `func mastersosUserInfo(p mastersosProfile, idToken *oidc.IDToken) (info.User, mastersosIDClaims, error)` where
    `type mastersosIDClaims struct { Sub, Org, LoginName string }`. It is used instead of the provider's `GetUserInfo` when `p.active`.

- [ ] **Step 1: Write the failing tests** (unit tests in the `_internal_test.go` file, broker tests in the
  `broker_test` file, built on patch 0004's `cardOnlyBroker`/`signInOnCard` pattern with
  `IDTokenClaims: {"sub", "org", "login_name"}` and no `email`):
  - `TestMastersOSNoProfileKeepsEmailNames`: no file, no marker. A login with `email` is granted under the email; requested scopes have neither `mastersos.facts` nor `org:`.
  - `TestMastersOSLoginNameIsTheUserName`: profile with org `0193…01`, claims `login_name=alice@school.example`, `org` equal, no `email`/`email_verified`. Result: `AuthGranted`, data contains `alice@school.example`.
  - `TestMastersOSScopesCarryTheOrganisation`: the card URL's `scope` query contains `mastersos.facts` and `org:0193…01`.
  - `TestMastersOSOtherOrganisationIsDeniedBeforeGrant`: claim `org` differs. Result: `AuthDenied`, data contains `not a member of this school`, no token file. This is the same assertion style as `TestMastersOSOtherDomainIsDeniedBeforeGrant` in 0006.
  - `TestMastersOSMissingExpectedOrgDeniesEveryone`: marker in a drop-in, file absent → `AuthDenied`. Also file present but unreadable, empty, or not a UUID → `AuthDenied`.
  - `TestMastersOSBadLoginNameIsDenied`: `login_name` values `"Alice@school.example"`, `"a/b@school.example"`, `"a@b@c"`, `""`, and a 65-character local part → `AuthDenied`.
  - `TestMastersOSWrongAccountComparesLoginName`: session requested `bob@school.example`, token says `alice@school.example` → denied with upstream's "does not match the authenticated user" text, which `people.js` `refusalKind` matches.
- [ ] **Step 2: Run** `bash image/tests/authd-oidc-patch-test.sh` on the remote build runner. Expected: the new tests fail (undefined symbols / wrong user name).
- [ ] **Step 3: Implement** `mastersos_profile.go` and the hunks.
  - Reading: the file is at most 4 KiB, comments and blank lines are skipped, and exactly one lowercase UUID line must
    remain; anything else means active with an empty org.
  - `mastersosUserInfo` fills the same `info.User` fields `genericprovider.GetUserInfo` fills, except `Name` = `login_name`.
    It requires no `email`/`email_verified`.
  - Org check: `Org == p.org`, else the error text `Authentication failure: this account is not a member of this school`.
  - Map every error to `AuthDenied` before `finishAuth`, so authd registers nobody.
  - Regenerate the patch from the clone.
- [ ] **Step 4: Run** the patch test on the remote build runner. Expected: every `TestMastersOS*` passes, 0001–0006 included. Then run `bash image/tests/check-tree.sh` (§32 counts 7 patches).
- [ ] **Step 5: Commit**
  `git add image/patches/authd-oidc/0007-mastersos-issuer-profile.patch image/tests/authd-oidc-patch-test.sh`
  `git commit -m "feat(image): broker patch 0007 takes login_name and checks the organisation before grant"`

### Task 3: Patch 0007 part 2 — facts hand-off

**Files:**
- Modify: `image/patches/authd-oidc/0007-mastersos-issuer-profile.patch`, regenerated. It adds `authd-oidc-brokers/internal/broker/mastersos_facts.go` and `mastersos_facts_test.go`, plus hunks in `NewSession` and in `finishCardLogin` (`mastersos_cardonly.go` from 0004: the hunk goes in 0007, the 0004 file stays byte-identical).

**Interfaces:**
- Consumes: `mastersosProfile`, `mastersosIDClaims` (Task 2); `authInfo.Token` (upstream `token.AuthCachedInfo`); `session.oidcServer.UserInfo`.
- Produces:
  - `var mastersosFactsDir = "/run/mastersos/facts"` (a var so tests point it at `t.TempDir()`)
  - `func mastersosForgetFacts(userName string)`
  - `func (b *Broker) mastersosWriteFacts(ctx context.Context, session *session, claims mastersosIDClaims, t *oauth2.Token)`.
    It never fails the login.

- [ ] **Step 1: Write the failing tests** (the test userinfo endpoint comes from `customHandlers["/userinfo"]`):
  - `TestMastersOSFactsWrittenAfterGrant`: the file `<login_name>.json` has mode 0600. It holds `version` 1, `user`, `granted_at` within 5 s of now, and `facts` equal to the endpoint's six keys. An extra endpoint key `name` is absent from the file.
  - `TestMastersOSFactsDeletedAtNewSession`: a file left from a previous login is gone right after `NewSession` for that user. A file of another user stays.
  - `TestMastersOSUserinfoFailureWritesError`: endpoint 500, timeout over 5 s, or a body over 64 KiB → `AuthGranted` and the file has `error` and no `facts`.
  - `TestMastersOSUserinfoSubjectMismatchWritesError`: userinfo `sub` or `org` differs from the ID token → `error` form.
  - `TestMastersOSFactsNeverLeaveTheDirectory`: the directory is a symlink, owned by another uid, or not 0700 → nothing is written anywhere and the login is still granted.
  - `TestMastersOSNoProfileWritesNoFacts`: profile off → no file, no userinfo request.
- [ ] **Step 2: Run** the patch test on the remote build runner. Expected: the new tests fail.
- [ ] **Step 3: Implement** `mastersos_facts.go`.
  - Before writing, `Lstat` the directory: it must be a real directory with uid 0 and mode 0700.
  - Create the temp file with `os.CreateTemp(dir, ".facts-*")`, then chmod 0600, write, `Sync`, and `Rename` it to `<login_name>.json`.
  - Userinfo context timeout: 5 s; body cap: 64 KiB.
  - Call `mastersosForgetFacts` at the top of `NewSession` when the profile is active. Call `mastersosWriteFacts` in
    `finishCardLogin` only after `finishAuth` returned `AuthGranted`.
  - Regenerate the patch.
- [ ] **Step 4: Run** the patch test on the remote build runner. Expected: all `TestMastersOS*` pass.
- [ ] **Step 5: Commit**
  `git add image/patches/authd-oidc/0007-mastersos-issuer-profile.patch`
  `git commit -m "feat(image): broker patch 0007 hands the person's facts to pam-session, consumed once"`

### Task 4: Agent — expected-org file, profile marker, `login_domain` in branding

**Files:**
- Modify: `core/mastersos-agent/src/system/login.rs`:
  - constants after `DOMAINS_MARKER` (:83)
  - `broker_conf` (:624-645), `render_broker_conf` (:600-607), `render_broker_conf_admins_only` (:612-622)
  - `run`/`run_seed` (:900-920), `apply` (:925-1016)
  - new `sync_expected_org` beside `sync_domains` (:1042)
  - module doc (:13-19)
  - tests module
- Modify: `core/mastersos-agent/src/system/branding.rs`: `Branding` struct (~:107-113), `Want` (~:116-126), `run` (~:128-140), `run_seed`.

**Interfaces:**
- Consumes: `Oidc.mastersos_claims`, `Oidc.login_domain` (Plan A); `School.id: String`; `Seed.school_id: Option<String>`.
- Produces:
  - `pub const EXPECTED_ORG_FILE: &str = "mastersos-expected-org";` (in `DOMAINS_DIR`)
  - `pub const PROFILE_MARKER: &str = "# mastersos: issuer profile required (patch 0007)";`
  - `pub fn render_expected_org(oidc: &Oidc, school_id: Option<&str>) -> Option<String>`. It returns `None` when `!oidc.mastersos_claims`. When the profile is on and `school_id` is `None`, it returns `Some` with comments only: the broker then denies everyone, and a problem is reported.
  - `branding.json` gains `"login_domain": "<domain>"`, written only when `login_domain` is lowercase, passes `checks::allowed_domain` and is in `allowed_domains`. Otherwise the key is absent.

- [ ] **Step 1: Write the failing tests** (in the `login.rs` and `branding.rs` test modules, using the existing helpers `run_bundle`, `school_with`, `domains_file`):
  - `expected_org_written_before_the_drop_in_with_the_marker`: `mastersos_claims = true`, school id `0193…01`. The file holds that id, mode 0644. The drop-in's second marker line equals `PROFILE_MARKER`. The broker restarts once.
  - `no_profile_writes_no_expected_org_and_no_marker`: removes a leftover file; the drop-in has no `PROFILE_MARKER`.
  - `expected_org_write_failure_keeps_the_marker`: the file cannot be written. The drop-in still carries `PROFILE_MARKER`, the item fails with `school sign-in is off until it is written`, and there is no drop-in without the marker.
  - `seed_profile_without_school_id_reports_and_denies`: seed `oidc.mastersos_claims = true` without `school_id` → a file with comments only and a reported problem.
  - `sso_removed_deletes_the_expected_org_file`: removal happens after the drop-in is removed (same order test as `sso_removed_deletes_the_domain_file`).
  - `broker_conf_has_only_keys_an_unpatched_broker_knows` still passes with both markers present.
  - `branding_carries_a_valid_login_domain`: present in `allowed_domains` → the key is written. Not in `allowed_domains`, upper case, or invalid → the key is absent. Seed path → absent.
- [ ] **Step 2: Run** on the remote build runner: `cargo test -p mastersos-agent system::login system::branding`. Expected: the new tests fail.
- [ ] **Step 3: Implement.**
  - `broker_conf` takes `profile: bool` and writes `PROFILE_MARKER` on its own line after the domains marker.
  - `apply` takes `school_id: Option<&str>`. Order: write the expected-org file, then the drop-in. On removal: drop-in first, then the file.
  - On a write failure, keep the marker drop-in (fail closed, unlike the domains admins-only fallback: the org check covers administrators too).
- [ ] **Step 4: Run** the same tests, then `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace` on the remote build runner. Expected: all pass.
- [ ] **Step 5: Commit**
  `git add core/mastersos-agent/src/system/login.rs core/mastersos-agent/src/system/branding.rs`
  `git commit -m "feat(agent): expected-org file and profile marker for broker patch 0007; login_domain in branding.json"`

### Task 5: Greeter — a bare username becomes `<username>@<login_domain>`

**Files:**
- Modify: `image/mkosi.extra/usr/share/gnome-shell/extensions/mastersos-login@mastersos.org/people.js`: new export, plus a `REFUSALS` entry.
- Modify: `…/mastersos-login@mastersos.org/extension.js`: `domainList` neighbour `loginDomain(b)` (:112-118), `enable`/`_settingsChanged` (:165, :199), `_takeUsernameStep` (:797-817), header comment (:1-19).
- Test: `image/tests/login-people-test.mjs` (run by `image/tests/login-people-test.sh`).

**Interfaces:**
- Consumes: `branding.json` `login_domain` (Task 4).
- Produces: `export function expandLoginName(typed, loginDomain, localNames) → string | null`. It returns
  `` `${typed.trim().toLowerCase()}@${loginDomain}` `` when all of these hold:
  - the trimmed text has no `@`;
  - lowercased, it matches `^[a-z0-9._-]{1,64}$`;
  - `loginDomain` is a non-empty string;
  - the text is not `HIDDEN`;
  - no name in `localNames` equals the trimmed text exactly.

  Otherwise it returns `null`.

- [ ] **Step 1: Write the failing tests** in `login-people-test.mjs`:
  - `('Alice', 'school.example', [])` → `'alice@school.example'`
  - `('alice', 'school.example', ['alice'])` → `null`
  - `('alice', null, [])` → `null`
  - `('itadmin', 'school.example', [])` → `null`
  - `('a@b', …)` → `null`
  - `('a b', …)` → `null`
  - a 65-character name → `null`
  - `refusalKind('Authentication failure: this account is not a member of this school') === 'not-allowed'`
- [ ] **Step 2: Run** `bash image/tests/login-people-test.sh` in the container (with node). Expected: FAIL, `expandLoginName` is not exported.
- [ ] **Step 3: Implement.**
  - `people.js`: add the function, and add `not a member of this school` to the `not-allowed` regex.
  - `extension.js`: keep `this._loginDomain` from `branding.json` (validated like `domainList`).
  - In `_takeUsernameStep`, use `answer = this._picked ?? this._defaultPick(typed) ?? expandLoginName(typed, this._loginDomain, localNames) ?? typed`, where `localNames` comes from `dlg._userManager.list_users()`.
- [ ] **Step 4: Run** the node test (PASS) and `check-tree.sh` (PASS).
- [ ] **Step 5: Commit**
  `git add image/mkosi.extra/usr/share/gnome-shell/extensions/mastersos-login@mastersos.org/people.js image/mkosi.extra/usr/share/gnome-shell/extensions/mastersos-login@mastersos.org/extension.js image/tests/login-people-test.mjs`
  `git commit -m "feat(image): the login screen completes a bare username with the school's login domain"`

### Task 6: Documentation and the VM verification list

**Files:**
- Modify: `image/docs/idp.md`. Add an English section "Issuer profile (patch 0007)" covering:
  - the `school.oidc.mastersos_claims` switch;
  - the required claims (`login_name`, `org`) and scopes (`mastersos.facts`, `org:<school id>`);
  - the expected-org file and the marker;
  - the facts file and its consume-once rule (the reader is Plan B);
  - `login_domain`.

  Also add a row for 0007 to the patch table (:183 onward) and a line to the requirements table: `email_verified` is not needed with the profile.

- [ ] **Step 1: Write the section and the table row.**
- [ ] **Step 2: Run** `python3 -I tools/check-private.py` and `bash image/tests/check-tree.sh`. Expected: both pass.
- [ ] **Step 3: Commit**
  `git add image/docs/idp.md`
  `git commit -m "docs(image): issuer profile, facts hand-off and login domain"`
- [ ] **Step 4 (blocked until the issuer's plan is approved; hand to a separate VM session):** On an image built with
  this branch and a test school with `mastersos_claims = true`:
  - A username-only account typed as a bare name signs in as `<name>@<login_domain>`.
  - An account of another organisation is refused before grant: `getent passwd` has no entry.
  - The facts file appears, and Plan B's `pam-session` consumes it.
  - An unlock deletes and rewrites it.
  - A school with the profile off still signs in by email.

  Save screenshots under new numbers and list their paths.

---

Spec gaps found while planning (for the parent):
- The spec (§5) makes `login_name`, `org` and the scopes unconditional. Today's schools use other issuers (Google, a
  Zitadel lab), which send neither claim and reject unknown scopes, so an unconditional 0007 would break their sign-in.
  This plan assumes a switch `school.oidc.mastersos_claims` (Plan A, device layer, default false). The spec and contract
  should name it.
- The facts file's exact JSON (`version`, `user`, `granted_at`) is not pinned by the spec. This plan pins it in Global
  Constraints; Plan B must read the same shape.
- In open mode the login card's block list still comes from the device config (`login.rs:907-913`, `Some(&ctx.config.chrome_policy)`). Moving it to the guest user config is Plan B's job, not this plan's.
