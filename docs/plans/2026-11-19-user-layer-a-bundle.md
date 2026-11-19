# User layer A: settings format 3 and the offline CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `mastersos-bundle` reads, merges, resolves and checks `format = 3` settings (device layer, user layer, rules), and the `mastersos` CLI gains `explain user`, `explain device` and `migrate`, without changing anything for format 1/2 texts.

**Architecture:** A format 3 text is deserialized into its own raw structs (`device_defaults`, `[[device_config]]`, `[user_defaults]`, `[[user_config]]`, `[[assign]]`, `[user]`) and converted into the existing `Manifest` (device layer → `defaults`/`configs`, so every existing reader keeps working) plus a new `Manifest::user_layer`. A new module `user_layer.rs` holds the user-layer types, the merge, the capability arithmetic, the pure rule resolver and the reachable/install-union computations; format 1/2 texts get an *implied* user layer of one user config per Config so that Plan B has one code path. The device Config of a format 3 Group carries the install union in `apps.flatpak`/`apps.deb`, so the Flatpak and .deb jobs need no change of input.

**Tech Stack:** Rust 2021, serde + toml 0.8 + toml_edit 0.25 (workspace), schemars (feature `schema`), clap (mastersos-mcp).

**Spec:** `docs/specs/2026-11-19-user-layer-design.md` (agreed contract, for reference only: the settings server's `docs/specs/2026-11-19-mastersos-user-layer-contract.md`, draft 5).

## Global Constraints

- Everything written into files is English (code, comments, docs, messages, commit messages). No AI attribution lines in commits.
- Nothing private in the tree; run `python3 -I tools/check-private.py` before every commit.
- Format 1/2 texts parse, validate, select and lint exactly as today: every existing test in `core/mastersos-bundle` and `core/mastersos-mcp` stays green unchanged, except the one assertion in `core/mastersos-agent/src/report.rs:437-441` that Task 4 rewrites.
- `MAX_FORMAT` becomes 3; the feature string is `format_feature(3)` = `"format_3"` (`FEATURE_FORMAT_3`). The spec's §7 writes `format3`; the existing gate (`manifest.rs:27`, `report.rs:43`) uses `format_<n>`, so `format_3` is the value.
- The agent must NOT report `FEATURE_FORMAT_3` in this plan (`report.rs:35-54` unchanged); Plan B adds it as its last task.
- All new serde structs: `#[serde(deny_unknown_fields)]`, `#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]`, doc comments on every field (the settings reference is generated from them, `spec.rs`).
- Capability names, exactly: `terminal`, `file_manager`, `settings`, `extensions`, `all_apps`, `user_apps`. Preset names: `learning`, `full`. `home`: `tidy`, `keep`. Rule enums: `kind` = `sso|local|guest`; `org_role` = `owner|admin|member`; `class_role` = `teacher|assistant|student`; `age_band` = `under13|13-17|18+`.
- Verification: `cd core && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`. Rust does not build on the Mac (Docker has 1 GB): run it on the remote build runner through the labtest MCP (`test_run`/`build_run`), and release the environment with `env_release` when the branch is done.
- Work in a worktree on branch `feat/user-layer-a` (superpowers:using-git-worktrees). Commit per task; do not push.

## Review Focus

1. A format 2 text that happens to contain `[device_defaults]` or `[[assign]]` must fail to parse (unknown field), not be read as format 3 → test in Task 1 (`format2_rejects_v3_tables`).
2. A format 3 text that still writes `[defaults]`, `[[config]]`, `interface` in a device config or `user_config` in a `[[group]]` must fail with an unknown-field parse error naming the key → Task 1 (`format3_rejects_v2_tables`).
3. A rule list where facts are absent (`None`) must never match a fact condition, including `sub`, and must fall to the next rule or the fallback, never panic → Task 3 (`fact_conditions_need_facts`).
4. The same `.deb` id defined differently in two user configs reachable on one Group makes the install union ambiguous → Task 4 error `user_deb_conflict` and Task 2 test (`install_union_keeps_first_definition`).
5. `migrate` of a format 2 text must give, for every Group and every account kind, the same effective session as before (no silent loosening) → Task 5 (`migrate_preserves_every_group`).

---

### Task 1: Parse format 3 into `Manifest` + `UserLayer`

**Files:**
- Create: `core/mastersos-bundle/src/user_layer.rs`
- Modify: `core/mastersos-bundle/src/lib.rs` (add `pub mod user_layer; pub use user_layer::*;`)
- Modify: `core/mastersos-bundle/src/manifest.rs:22` (`MAX_FORMAT = 3`), `:83-125` (`Manifest` gets `user_layer`), `:240-270` (`check_format` accepts 3), `:316-330` (`parse_shapes` branches on format 3), `:1849-1853` (add `FEATURE_FORMAT_3`), `:4326-4331` (update the format-constant test)
- Test: `core/mastersos-bundle/src/user_layer.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces (all `pub`, in `user_layer.rs`):
  - `enum Capability { Terminal, FileManager, Settings, Extensions, AllApps, UserApps }` (serde `snake_case`, `Ord`), `type Caps = BTreeSet<Capability>`, `const ALL_CAPS: [Capability; 6]`.
  - `enum Preset { Learning, Full }` (default `Learning`), `enum HomeMode { Tidy, Keep }`.
  - `struct UserApps { web: Vec<WebApp>, flatpak: Vec<String>, deb: BTreeMap<String, DebApp> }`.
  - `struct UserDrop { apps: UserDropApps, chrome_policy: Vec<String>, scripts: Vec<String> }`, `struct UserDropApps { web, flatpak, deb: Vec<String> }`.
  - `struct UserDefaults { preset: Option<Preset>, allow: Vec<Capability>, deny: Vec<Capability>, apps: UserApps, chrome_policy: toml::Table, scripts: Vec<Script>, home: Option<HomeMode> }`.
  - `struct UserConfigLayer { id: String, name: String, preset, allow, deny, apps, chrome_policy, scripts, home (as above), drop: UserDrop }`.
  - `enum Kind { Sso, Local, Guest }`, `enum OrgRole { Owner, Admin, Member }`, `enum ClassRole { Teacher, Assistant, Student }`, `enum AgeBand { #[serde(rename="under13")] Under13, #[serde(rename="13-17")] Teen, #[serde(rename="18+")] Adult }` (all `Serialize + Deserialize + Copy + Eq`).
  - `struct Assign { user_config: String, kind: Option<Vec<Kind>>, admin: Option<bool>, user: Option<Vec<String>>, device_group: Option<Vec<String>>, org_role: Option<Vec<OrgRole>>, class_role: Option<Vec<ClassRole>>, class: Option<Vec<String>>, org_node: Option<Vec<String>>, age_band: Option<Vec<AgeBand>>, sub: Option<Vec<String>> }` (`Serialize + Deserialize`, `deny_unknown_fields`).
  - `struct UserSection { fallback: String }`.
  - `struct UserLayer { defaults: UserDefaults, configs: Vec<UserConfigLayer>, rules: Vec<Assign>, fallback: Option<String> }` (`fallback` is `None` when `[user]` is missing: a check error, Task 4, not a parse error, so `check` can point at it).
  - In `manifest.rs`: `Manifest.user_layer: Option<UserLayer>` (`#[serde(skip)]`; `Some` exactly for format 3), `pub const FEATURE_FORMAT_3: &str = "format_3";`.

- [ ] **Step 1: Write the failing tests** in `user_layer.rs`:

```rust
#[test]
fn parses_spec_example() {
    let m = Manifest::parse(&v3_example()).unwrap(); // the §2 example of the spec + version/trust/school.id
    assert_eq!(m.format, 3);
    assert_eq!(m.configs.len(), 1);              // [[device_config]] "classroom"
    assert_eq!(m.configs[0].interface, None);     // device configs carry no mode
    let u = m.user_layer.as_ref().unwrap();
    assert_eq!(u.configs.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), ["primary", "teacher"]);
    assert_eq!(u.rules.len(), 3);
    assert_eq!(u.rules[0].admin, Some(true));
    assert_eq!(u.fallback.as_deref(), Some("primary"));
}
#[test]
fn format2_rejects_v3_tables() {
    for t in ["[device_defaults]", "[[device_config]]\nid=\"a\"\nname=\"a\"", "[user_defaults]",
              "[[user_config]]\nid=\"a\"\nname=\"a\"", "[[assign]]\nuser_config=\"a\"", "[user]\nfallback=\"a\""] {
        let text = format!("format = 2\n{}\n{t}\n", v2_minimal_body());
        assert!(matches!(Manifest::parse(&text), Err(BundleError::Parse(_))), "{t}");
    }
}
#[test]
fn format3_rejects_v2_tables() {
    for (t, key) in [("[defaults]", "defaults"), ("[[config]]\nid=\"x\"\nname=\"x\"", "config"),
                     ("interface = \"full\"", "interface") /* inside the device_config */,
                     ("user_config = \"primary\"", "user_config") /* inside a [[group]] */,
                     ("apps.web = []", "web") /* inside the device_config */,
                     ("apps.flatpak = []", "flatpak") /* inside the device_config */] {
        let err = Manifest::parse(&v3_with(t)).unwrap_err().to_string();
        assert!(err.contains(key), "{t}: {err}");
    }
}
#[test]
fn format_4_is_too_new() {
    assert!(matches!(Manifest::parse("format = 4\nversion = 1"), Err(BundleError::FormatTooNew { found: 4, max: 3 })));
}
#[test]
fn v2_texts_have_no_user_layer() {
    assert!(Manifest::parse(&crate::testutil::spec_example()).unwrap().user_layer.is_none());
}
```

  (`v3_example`, `v3_with(t)` — `t` inserted into the right table by a marker comment — and `v2_minimal_body` are test helpers in the same module. Put `v3_example` in `core/mastersos-bundle/src/testutil.rs` as `pub fn spec_example_v3() -> String` next to `spec_example`, so Plan B's agent tests can use it with feature `test-util`.)

- [ ] **Step 2: Run** `cargo test -p mastersos-bundle user_layer` on the remote build runner. Expected: FAIL (module/fields missing).

- [ ] **Step 3: Implement.**
  - Raw format 3 structs, private to `user_layer.rs`: `V3Manifest { format, version, issued_at, trust, school, device_defaults: Option<DeviceDefaults>, device_config: Vec<DeviceConfigLayer> (rename "device_config"), groups (rename "group", type `Group` — unchanged, so `user_config` in a group is an unknown field), devices (rename "device"), user_defaults: Option<UserDefaults>, user_config: Vec<UserConfigLayer>, assign: Vec<Assign>, user: Option<UserSection> }`.
  - `DeviceDefaults` / `DeviceConfigLayer` = `Defaults` / `ConfigLayer` minus `interface`, `chrome_policy`, and with `apps: DeviceApps { kiosk: BTreeMap<String, KioskApp>, deb: BTreeMap<String, DebApp>, ubuntu_mirror: Option<String> }` (no `web`, no `flatpak`); `drop` = `Drop` minus `chrome_policy`, `apps.web`, `apps.flatpak`. `scripts` stays (a `when = "login"` here is a Task 4 error).
  - `pub(crate) fn parse_v3(text: &str) -> Result<Manifest, toml::de::Error>` converts: `defaults` ← device_defaults (user-layer fields empty), `configs` ← device configs (`interface: None`, empty `chrome_policy`, `apps.web`/`apps.flatpak` empty), `groups`, `devices` as is, `shape: Shape::New`, `user_layer: Some(UserLayer{..})`.
  - `check_format`: accept 1..=3; the format-1 key check unchanged. `parse_shapes`: when the parsed `format` is 3, call `parse_v3` (no legacy-shape detection for format 3).
  - Error texts for `ShapeError::Format` say "format must be the integer 1, 2 or 3".

- [ ] **Step 4: Run** the same command. Expected: PASS; then `cargo test -p mastersos-bundle` all green.

- [ ] **Step 5: Commit** `feat(bundle): parse settings format 3 (device layer, user layer, rules)`.

### Task 2: Effective user configs, capabilities, reachability, install union

**Files:**
- Modify: `core/mastersos-bundle/src/user_layer.rs`
- Modify: `core/mastersos-bundle/src/select.rs:43-79` (`find` builds the device Config with [`effective_device_config`])
- Modify: `core/mastersos-bundle/src/manifest.rs:2102-2104` (`effective_of_group` uses it too)
- Test: `user_layer.rs` tests, `select.rs` tests

**Interfaces:**
- Consumes: Task 1 types.
- Produces:
  - `struct UserConfig { id: String, name: String, preset: Preset, caps: Caps, home: HomeMode, web: Vec<WebApp>, flatpak: Vec<String>, deb: BTreeMap<String, DebApp>, chrome_policy: toml::Table, login_scripts: Vec<Script>, legacy_browser: bool }` (`Serialize + Deserialize + Clone + PartialEq`): what one session gets.
  - `fn effective_caps(preset: Preset, allow: &[Capability], deny: &[Capability]) -> Caps` — preset ∪ allow − deny.
  - `fn effective_user_config(u: &UserLayer, c: &UserConfigLayer) -> UserConfig` — today's merge rules (`merge_list`/`merge_map`, made `pub(crate)` in `manifest.rs:982-1017`); `allow`/`deny` are defaults' list + own list (no drop); `home` = own, else defaults', else `Tidy` for preset `Learning`, `Keep` for `Full`; `login_scripts` = merged `scripts` (all `when = "login"` after Task 4's check).
  - `impl UserConfig { fn implied(config: &Config) -> UserConfig }` — format 1/2: `id = config.id`; `preset/caps`: `Interface::Full` → `Full`/all caps, `Learning` → `Learning`/none; `home` from the preset; `web = config.apps.web`; `flatpak`/`deb` (non-kiosk only) = the Config's when `!legacy_browser`, else empty; `chrome_policy = config.chrome_policy`; `login_scripts` = `when = Login` scripts; `legacy_browser = config.legacy_browser`.
  - `fn user_config(m: &Manifest, id: &str) -> Option<UserConfig>` — format 3: the layer with that id, effective; format 1/2: `implied` of the Config with that id.
  - `fn reachable_user_configs(m: &Manifest, group_id: &str) -> Vec<String>` — format 3: ids named by rules whose `device_group` is `None` or contains `group_id`, then `fallback`, de-duplicated in first-seen order; format 1/2: `[group's config id]`.
  - `fn install_union(m: &Manifest, group_id: &str) -> (Vec<String>, BTreeMap<String, DebApp>)` — Flatpak ids and non-kiosk .deb apps over the reachable user configs, first definition of an id wins.
  - `fn effective_device_config(m: &Manifest, group: &Group) -> Option<Config>` — `effective_config` of the Group's Config; for format 3 also `apps.flatpak = union.0`, `apps.deb` = device kiosk debs ∪ `union.1` (device entry wins on id clash; Task 4 makes clashes an error).

- [ ] **Step 1: Write the failing tests:**

```rust
#[test] fn caps_deny_wins() {
    assert_eq!(effective_caps(Preset::Learning, &[Capability::Terminal], &[Capability::Terminal]), Caps::new());
    assert_eq!(effective_caps(Preset::Full, &[], &[Capability::Terminal]).len(), 5);
}
#[test] fn merge_follows_defaults_rules() {
    // user_defaults: web Classroom, chrome URLBlocklist, allow [file_manager]; user_config: web Starfall, drop.apps.web ["Classroom"], deny [file_manager], drop.chrome_policy ["URLBlocklist"]
    let u = user_config(&m, "x").unwrap();
    assert_eq!(names(&u.web), ["Starfall"]);
    assert!(u.caps.is_empty());
    assert!(u.chrome_policy.is_empty());
}
#[test] fn home_default_follows_preset() {
    // allow = ["file_manager"] with preset learning keeps Tidy; preset full gives Keep; home = "keep" overrides
}
#[test] fn implied_matches_todays_profiles() {
    // format 2 example: learning Config → caps empty, Tidy; full Config → all caps, Keep; legacy browser → flatpak/deb empty, legacy_browser true
}
#[test] fn reachable_respects_device_group_and_fallback() {
    // rules: teacher(admin), exam(device_group exam-room), primary(org_node); fallback primary
    assert_eq!(reachable_user_configs(&m, "default"), ["teacher", "primary"]);
    assert_eq!(reachable_user_configs(&m, "exam-room"), ["teacher", "exam", "primary"]);
}
#[test] fn install_union_keeps_first_definition() { /* same deb id in two configs: first config's DebApp */ }
#[test] fn device_config_carries_install_union() {
    let sel = select(&m, &ident_in("exam-room"), None);
    assert_eq!(sel.config.apps.flatpak, ["org.libreoffice.LibreOffice"]);
    assert!(sel.config.chrome_policy.is_empty());
}
```

  and in `select.rs` tests: `format2_selection_unchanged` (the existing example's `select(...)` equals `effective_config(...)` exactly, as before).

- [ ] **Step 2: Run** `cargo test -p mastersos-bundle user_layer select` on the remote build runner. Expected: FAIL.
- [ ] **Step 3: Implement** the functions above; `select.rs` `find` closure calls `effective_device_config`.
- [ ] **Step 4: Run** `cargo test -p mastersos-bundle`. Expected: PASS (all old tests too).
- [ ] **Step 5: Commit** `feat(bundle): effective user configs, capabilities and the install union`.

### Task 3: Rule resolution and the compact rules file

**Files:**
- Modify: `core/mastersos-bundle/src/user_layer.rs`
- Test: `user_layer.rs` tests

**Interfaces:**
- Produces:
  - `struct DeviceFacts<'a> { kind: Kind, admin: bool, user: &'a str, device_group: &'a str }`.
  - `struct IssuerFacts { sub: String, org: String, #[serde(default)] org_role: Option<OrgRole>, #[serde(default)] org_nodes: Vec<String>, #[serde(default)] classes: Vec<ClassFact>, #[serde(default)] age_band: Option<AgeBand> }`, `struct ClassFact { id: String, role: ClassRole }` — `Deserialize` from the userinfo JSON of spec §5; unknown fields ignored (no `deny_unknown_fields`: the issuer may add claims).
  - `struct Resolution { user_config: String, rule: Option<usize> }` (`rule` = index into the rules; `None` = fallback).
  - `fn resolve(rules: &[Assign], fallback: &str, device: &DeviceFacts, facts: Option<&IssuerFacts>) -> Resolution` — first rule whose every present condition holds; `user` compares case-insensitively with `device.user`; `kind`, `admin`, `device_group` from `device`; `org_role`, `class_role`, `class`, `org_node`, `age_band`, `sub` hold only when `facts` is `Some` and `device.kind == Kind::Sso`; `org_node` matches if any of `facts.org_nodes` is listed; `class_role` if any class has a listed role; `class` if any class id is listed.
  - `struct UserRules { group: String, fallback: String, rules: Vec<Assign>, configs: Vec<String> }` (`Serialize + Deserialize`): what the Device needs at login (Plan B writes it root-only).
  - `impl UserRules { fn from_manifest(m: &Manifest, group_id: &str) -> Option<UserRules>; fn resolve(&self, device: &DeviceFacts, facts: Option<&IssuerFacts>) -> Resolution }` — `from_manifest` is `None` for format 1/2; `rules` keeps only rules reachable on that Group (indices are re-numbered; `explain` uses `resolve` on the full list instead).
  - `fn guest_user_config(m: &Manifest, group_id: &str) -> Option<String>` — `resolve` with `DeviceFacts { kind: Guest, admin: false, user: "guest", device_group: group_id }`, no facts; format 1/2: the Group's config id.

- [ ] **Step 1: Write the failing tests** (a table test is the clearest):

```rust
#[test] fn resolves_spec_example() {
    let cases = [
        (sso("t@s.ac.th", false), Some(facts().class(TEACHER)), "teacher", Some(1)),
        (sso("a@s.ac.th", true),  None,                         "teacher", Some(0)),
        (sso("k@s.ac.th", false), Some(facts().node(PRIMARY_CHILD)), "primary", Some(2)),
        (guest(),                 None,                         "primary", None),
    ];
    for (dev, f, want, rule) in cases { let r = resolve(&rules, "primary", &dev, f.as_ref()); assert_eq!((r.user_config.as_str(), r.rule), (want, rule)); }
}
#[test] fn fact_conditions_need_facts() {
    // rule [sub = [S]] then fallback: sso with facts None → fallback; local with facts Some(sub=S) → fallback
}
#[test] fn user_condition_is_case_insensitive() { /* "Alice@S.ac.th" matches user = ["alice@s.ac.th"] */ }
#[test] fn and_of_conditions_or_within_lists() { /* kind=[sso,local] + admin=false */ }
#[test] fn rules_file_round_trips_and_filters_by_group() {
    let r = UserRules::from_manifest(&m, "default").unwrap();
    assert!(r.rules.iter().all(|a| a.device_group.as_ref().map_or(true, |g| g.iter().any(|x| x == "default"))));
    assert_eq!(serde_json::from_str::<UserRules>(&serde_json::to_string(&r).unwrap()).unwrap(), r);
}
#[test] fn guest_resolution() { assert_eq!(guest_user_config(&m, "default").as_deref(), Some("primary")); }
#[test] fn issuer_facts_ignore_unknown_claims() { /* JSON with "foo": 1 parses */ }
```

- [ ] **Step 2: Run** `cargo test -p mastersos-bundle user_layer::tests::resol` on the remote build runner. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run** `cargo test -p mastersos-bundle`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(bundle): resolve the user config from rules and facts`.

### Task 4: Checks, warnings, `login_domain`, features

**Files:**
- Modify: `core/mastersos-bundle/src/user_layer.rs` (`validate_user_layer`, `lint_user_layer`)
- Modify: `core/mastersos-bundle/src/manifest.rs:607-640` (`Oidc.login_domain`, `Oidc.mastersos_claims`), `:1846-1869` (`FEATURE_OIDC_LOGIN_DOMAIN`), `:1927-2010` (`features_used`), `:2119` (`validate_all` calls `validate_user_layer`)
- Modify: `core/mastersos-bundle/src/lint.rs:130` (`lint_at` appends `lint_user_layer`), `:482` (`feature_path` for the two new features)
- Modify: `core/mastersos-bundle/src/check.rs:172-300` (`Locator`: id indices for `[[device_config]]` and `[[user_config]]`, so `device_config.<id>` / `user_config.<id>` paths resolve like `config.<id>`; `assign[i]` and `user.fallback` already resolve as array/table paths — assert it in a test)
- Modify: `core/mastersos-agent/src/report.rs:437-441` (test only)
- Test: `user_layer.rs` tests, `manifest.rs` tests

**Interfaces:**
- Produces: `fn validate_user_layer(m: &Manifest, out: &mut Vec<Lint>)` (errors), `fn lint_user_layer(m: &Manifest) -> Vec<Lint>` (warnings), `Oidc.login_domain: Option<String>` (`#[serde(default, skip_serializing_if = "Option::is_none")]`), `Oidc.mastersos_claims: bool` (`#[serde(default, skip_serializing_if = "is_false")]`; false = a plain OIDC issuer: no org check, no facts, user name from `email` as today; true = the issuer profile of spec §5, used by Plan C's broker patch 0007), `FEATURE_OIDC_LOGIN_DOMAIN = "oidc_login_domain"`, `FEATURE_OIDC_MASTERSOS_CLAIMS = "oidc_mastersos_claims"`.
- Error codes (`Lint::new(LintLevel::Error, code, msg).at(path)`; paths as `assign[<i>]`, `user_config.<id>`, `device_config.<id>`, `user.fallback`, `school.oidc.login_domain`):
  `user_fallback_missing`, `user_config_unknown` (rule or fallback names a missing id), `user_config_duplicate_id`, `user_config_id_invalid` (empty or > 64 bytes), `assign_unreachable` (a rule after one without any condition), `assign_id_invalid` (`class`, `org_node`, `sub` entries not a lowercase UUID; reuse `valid_school_id` at `manifest.rs:1873`), `assign_device_group_unknown`, `assign_empty_list` (a condition written as `[]`), `script_apply_in_user_config`, `script_login_in_device_config`, `deb_kiosk_in_user_config`, `deb_not_kiosk_in_device_config`, `user_deb_conflict` (same .deb id, different definition, in two user configs reachable on one Group, or clashing with a device kiosk .deb), `login_domain_not_allowed` (`login_domain` not in `allowed_domains`; valid for every format), `mastersos_claims_without_school_id` (`mastersos_claims = true` and no `[school] id`).
- Warning codes: `facts_without_mastersos_claims` (a rule uses `org_role`, `class_role`, `class`, `org_node`, `age_band` or `sub` while `school.oidc.mastersos_claims` is false or there is no `[school.oidc]`: "this rule never matches: the issuer sends no facts unless school.oidc.mastersos_claims = true"), `user_config_unreached` (no rule and not the fallback), `user_config_terminal` with the message "terminal defeats every other lock (environment, user Flatpaks, .desktop files): the session is effectively full".
- `features_used`: `FEATURE_FORMAT_3` when `m.format == 3`; `FEATURE_OIDC_LOGIN_DOMAIN` when `login_domain` is written; `FEATURE_OIDC_MASTERSOS_CLAIMS` when `mastersos_claims` is true.

- [ ] **Step 1: Write the failing tests**: `locator_finds_v3_paths` (`check::locate(v3, "user_config.teacher")`, `"assign[1]"`, `"user.fallback"` each give the header/key line); one test per code, each built from `v3_with(...)` and asserting `codes(&m.validate_all(&files())) == [code]` (errors) or the code in `lint_at(...)` (warnings); plus

```rust
#[test] fn features_report_format3_login_domain_and_claims() {
    let f = features_used(&Manifest::parse(&v3_example_with_login_domain_and_claims()).unwrap());
    assert!(f.contains(&FEATURE_FORMAT_3) && f.contains(&FEATURE_OIDC_LOGIN_DOMAIN) && f.contains(&FEATURE_OIDC_MASTERSOS_CLAIMS));
}
#[test] fn mastersos_claims_defaults_false_and_is_omitted() { /* parse without the key → false; toml::to_string(&oidc) has no mastersos_claims */ }
#[test] fn v2_example_still_validates_clean() { assert!(Manifest::parse(&example()).unwrap().validate_all(&files()).is_empty()); }
```

  In `report.rs` replace the assertion `format_feature(MAX_FORMAT) == FEATURE_FORMAT_2` with `SUPPORTED_FEATURES.contains(&FEATURE_FORMAT_2) && !SUPPORTED_FEATURES.contains(&FEATURE_FORMAT_3)` and a comment "Plan B (user layer) adds FEATURE_FORMAT_3 once the agent applies user configs".
- [ ] **Step 2: Run** `cargo test --workspace` on the remote build runner. Expected: FAIL on the new tests only.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the full verification command of Global Constraints. Expected: PASS.
- [ ] **Step 5: Commit** `feat(bundle): check format 3 rules and user configs; school.oidc.login_domain and mastersos_claims`.

### Task 5: `migrate` format 2 → 3

**Files:**
- Create: `core/mastersos-bundle/src/migrate.rs` (+ `pub mod migrate;` in `lib.rs`)
- Test: `migrate.rs` tests

**Interfaces:**
- Produces: `fn to_format3(text: &str) -> Result<String, MigrateError>`; `enum MigrateError { Parse(String), AlreadyFormat3, Invalid(String) }` (`thiserror`).
- Rules (spec §6): each `[[config]]` (or each legacy Group's implied Config) → a `[[device_config]]` with the device keys and a `[[user_config]]` with the user keys, same `id` and `name`; `[defaults]` → `[device_defaults]` + `[user_defaults]` split the same way; `interface` → `preset`; `drop` split by key; non-kiosk `apps.deb` and `apps.flatpak` go to the user config, kiosk `.deb` and `apps.kiosk` stay in the device config; one `[[assign]] user_config = <config> device_group = [<group>]` per Group, in Group order; `[user] fallback` = the `default` Group's config; legacy `mode = "browser"` → preset `learning` with no `apps.flatpak`/non-kiosk `apps.deb`; `format = 3`; `version`, `trust`, `[school]`, `[[device]]` untouched. Uses `toml_edit` on the original document so comments on untouched tables survive; a moved key loses its comment (acceptable, say so in the CLI output).

- [ ] **Step 1: Write the failing tests:**

```rust
#[test] fn migrate_preserves_every_group() {
    for text in [example_v2(), example_v2_with_defaults_and_drop(), example_legacy_browser()] {
        let old = Manifest::parse(&text).unwrap();
        let new = Manifest::parse(&to_format3(&text).unwrap()).unwrap();
        assert!(new.validate_all(&files_of(&text)).is_empty());
        for g in &old.groups {
            let o = old.effective_of_group(&g.id).unwrap();
            let n = new.effective_of_group(&g.id).unwrap();
            assert_eq!(device_part(&o), device_part(&n), "{}", g.id);       // every device-layer field equal
            for kind in [Kind::Sso, Kind::Local, Kind::Guest] { for admin in [false, true] {
                let r = UserRules::from_manifest(&new, &g.id).unwrap().resolve(&dev(kind, admin, &g.id), None);
                assert_eq!(user_config(&new, &r.user_config).unwrap(), UserConfig::implied(&o), "{} {kind:?}", g.id);
            }}
        }
    }
}
#[test] fn refuses_format3() { assert!(matches!(to_format3(&v3_example()), Err(MigrateError::AlreadyFormat3))); }
#[test] fn keeps_comments_on_school() { assert!(to_format3(&with_school_comment()).unwrap().contains("# the school")); }
```

  (`device_part` compares every `Config` field except `interface`, `apps.web`, `apps.flatpak`, non-kiosk `apps.deb`, `chrome_policy`, login scripts; `UserConfig::implied(&o).id` equals the config id, so the comparison is exact.)
- [ ] **Step 2: Run** `cargo test -p mastersos-bundle migrate` on the remote build runner. Expected: FAIL.
- [ ] **Step 3: Implement** `to_format3`.
- [ ] **Step 4: Run** `cargo test -p mastersos-bundle`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(bundle): migrate settings format 2 to 3`.

### Task 6: CLI `explain user`, `explain device`, `migrate`

**Files:**
- Modify: `core/mastersos-mcp/src/cli.rs:71-150` (new `Cmd::Explain(ExplainCmd)` and `Cmd::Migrate`), `:280-283` (handled offline, next to `Check`/`Diff`)
- Create: `core/mastersos-mcp/src/explain.rs` (+ `mod explain;` in `lib.rs`)
- Test: `core/mastersos-mcp/tests/cli_explain.rs` (runs the built binary like `cli_init_keys.rs`)

**Interfaces:**
- Consumes: `resolve`, `UserRules`, `user_config`, `reachable_user_configs`, `install_union`, `select`, `to_format3`, `workdir` opening (`open_dir`, `cli.rs`).
- Produces:
  - `mastersos explain user [--dir D] --kind <sso|local|guest> [--admin] [--user <login_name>] [--org-role R] [--class-role R]... [--class ID]... [--org-node ID]... [--age-band B] [--sub ID] [--device-group G]`: for the given Group, or for every Group when absent, prints `group <id>: <user config id> (rule assign[<i>], manifest.toml:<line>)` or `(fallback)`; with `--json` an array of `{"group","user_config","rule","line"}`. The line comes from `check::Locator::locate(text, "assign[<i>]")`.
  - `mastersos explain device <serial> [--dir D]`: Group, device config, reachable user configs, install set (Flatpak ids, .deb ids); `--json` an object with those keys.
  - `mastersos migrate [--dir D] [--write]`: prints the migrated text (default) or writes `manifest.toml` (`--write`), then runs the local check and prints its issues; refuses format 3.
  - On a format 1/2 directory `explain` works through the implied layer (one user config per Group, `(implied: format 2)`).
  - `fn explain_user(m: &Manifest, text: &str, q: &UserQuery, group: Option<&str>) -> Vec<Explained>`, `struct Explained { group: String, user_config: String, rule: Option<usize>, line: Option<usize> }` in `explain.rs`.

- [ ] **Step 1: Write the failing tests** (`cli_explain.rs`): `explain_user_prints_rule_and_line` (a teacher class role on the spec example → `teacher (rule assign[1], manifest.toml:<n>)` with `<n>` the `[[assign]]` header line), `explain_user_json_shape`, `explain_device_lists_install_set`, `migrate_writes_format3_and_checks_clean`, `migrate_refuses_format3` (exit code 2, message "already format 3").
- [ ] **Step 2: Run** `cargo test -p mastersos-mcp --test cli_explain` on the remote build runner. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the full verification command. Expected: PASS.
- [ ] **Step 5: Commit** `feat(cli): mastersos explain and migrate`.

### Task 7: Settings reference

**Files:**
- Modify: `core/mastersos-bundle/docs/manifest-spec.md` and `skills/mastersos-admin/reference/settings-reference.md` (kept byte-identical; check with `cmp`)
- Modify: `skills/mastersos-admin/SKILL.md` only if it names `[[config]]` as the only shape (say format 3 exists and `mastersos migrate`)
- Test: `core/mastersos-bundle/src/spec.rs` consistency tests (they compare the schema with the reference)

- [ ] **Step 1: Run** `cargo test -p mastersos-bundle spec` on the remote build runner after Tasks 1–6. Expected: FAIL for every undocumented new table/key.
- [ ] **Step 2: Document** format 3: the tables of spec §2, the capability table §2.3, the layer table §3, the rule semantics §2.1 with every check code of Task 4, `school.oidc.login_domain`, `school.oidc.mastersos_claims` (facts conditions need it), `mastersos explain` and `mastersos migrate`, and the compatibility note of spec §7 (publishing format 3 waits until Devices report `format_3`).
- [ ] **Step 3: Run** `cargo test -p mastersos-bundle spec && cmp core/mastersos-bundle/docs/manifest-spec.md skills/mastersos-admin/reference/settings-reference.md`. Expected: PASS, no output from `cmp`.
- [ ] **Step 4: Commit** `docs(bundle): settings format 3 in the reference`.
