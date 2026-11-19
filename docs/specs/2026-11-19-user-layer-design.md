# Device layer and user layer (settings format 3)

Status: agreed 2026-11-19 by the three parties that touch it (the settings server, the identity issuer and
MastersOS). This document is the MastersOS side and is self-contained: it describes what the OS, the
`mastersos` CLI and the settings bundle do, and the interface they expect from any OIDC issuer and settings
server. Nothing here depends on a particular server implementation.

Out of scope: pushing password hashes for offline first login; file-hash checking of `/usr`.

Supersedes: the "per-account mode is a non-goal" lines of
`docs/specs/2026-11-10-learning-session-integrity-design.md` (:21, :35).

## 1. Intent

Today every setting is per Device: the Device's Group picks one Config, and whoever signs in gets that
Config's mode (`learning`/`full`), apps and Chrome policy. Schools need different settings for different
people on the same Device, and more than two kinds.

After this change:

- **Device layer**: what the institution owns about the machine (network, printers, who may sign in, OS
  updates, kiosk apps, installs). Applied at boot, before anyone signs in. Chosen by Group, as today.
- **User layer**: what the person sees and may do in their session (capabilities, visible apps, web
  apps, Chrome policy, login scripts, home clean-up). Chosen at login, for that person.
- **The OS is role-agnostic.** It knows no "student" or "teacher". At login it receives *facts* about the
  person from the issuer and evaluates *rules* written by IT in the signed document; a rule names a user
  config.
- **All settings content stays in the IT-signed document.** The issuer only supplies facts (ids). A
  misstated fact can only move a person to another user config that IT already signed. User configs can
  never grant administrator rights.

## 2. Document format (`format = 3`)

One signed `manifest.toml` holds Groups, device configs, user configs and rules.

```toml
format = 3

[school]                      # unchanged

# ---------- device layer ----------
[device_defaults]             # was [defaults]
login_methods = ["sso", "guest"]

[[device_config]]             # was [[config]], device keys only (§3)
id = "classroom"
name = "Classroom laptops"

[[group]]                     # unchanged: id, name, config (names a device_config)
id = "default"
name = "Unassigned"
config = "classroom"

# ---------- user layer ----------
[user_defaults]
preset = "learning"
chrome_policy = { URLBlocklist = ["tiktok.com"] }
apps.web = [{ name = "Classroom", url = "https://classroom.google.com" }]

[[user_config]]
id = "primary"
name = "Grade 1-6"

[[user_config]]
id = "teacher"
name = "Teachers"
preset = "full"
drop.chrome_policy = ["URLBlocklist"]

# ---------- who gets what (first match wins) ----------
[[assign]]
user_config = "teacher"
admin = true

[[assign]]
user_config = "teacher"
class_role = ["teacher", "assistant"]

[[assign]]
user_config = "primary"
org_node = ["0193a0c2-0000-7000-8000-000000000001"]

[user]
fallback = "primary"          # required
```

### 2.1 Rules (`[[assign]]`)

- Keys: `user_config` (required) and any conditions below. All present conditions must hold (AND); a list
  matches if any element matches (OR). File order; first match wins; no match → `[user] fallback`. Rules
  are the only place that decides who gets which user config.
- Conditions the Device evaluates from the signed document alone:
  - `kind`: `sso`, `local`, `guest` (the existing classification, `system/login.rs` `classify`).
  - `admin`: `true`/`false`; true for `[school] admin_users`, `itadmin`, and local accounts when
    `local_users_admin = true`.
  - `user`: local user names (the login name, §5). Entries are login names, which can differ from a
    person's current email.
  - `device_group`: Group ids of this Device.
- Conditions on issuer facts (§5); they never match for `local`/`guest`, nor when facts are missing,
  an error or stale:
  - `org_role`: `owner`, `admin`, `member`.
  - `class_role`: `teacher`, `assistant`, `student` (the role in at least one class).
  - `class`: class ids.
  - `org_node`: org-tree node ids. Every person sits in exactly one node; facts list that node and all
    its ancestors, so a rule on a node matches its sub-nodes.
  - `age_band`: `under13`, `13-17`, `18+`.
  - `sub`: issuer subject ids.
- `check` errors: unknown user config; a rule after an unconditional rule; an id (class, node, sub) that is
  not a lowercase UUID; an unknown value of an enumerated condition; an unknown key; `scripts` with
  `when = "apply"` in a user config; `scripts` with `when = "login"` in a device config; a missing
  `[user] fallback`; `school.oidc.mastersos_claims = true` without `[school] id`.
- `check` warnings: a user config that no rule or fallback reaches; a user config whose effective
  capabilities include `terminal` ("terminal defeats every other lock: environment, user Flatpaks,
  `.desktop` files; the session is effectively full").

### 2.2 User config keys

| Key | Meaning |
|---|---|
| `preset` | `learning` (default) or `full` |
| `allow`, `deny` | capabilities added to / removed from the preset (§2.3) |
| `apps.web` | web-app launchers |
| `apps.flatpak`, `apps.deb` (non-kiosk) | apps shown in the Dash; the Device installs the union over reachable user configs (§4.6) |
| `chrome_policy` | Chrome policies on top of the baseline |
| `scripts` (`when = "login"` only) | login scripts run as the person |
| `home` | `tidy` or `keep`; default follows `preset` (`learning` → `tidy`, `full` → `keep`) |
| `drop` | inherited entries to leave out |

`[user_defaults]` + `[[user_config]]` merge exactly like today's `[defaults]` + `[[config]]`: single values
replace; collection entries add, same name replaces; `drop` removes. `allow` and `deny` are collections.

### 2.3 Capabilities

Effective capabilities = preset ∪ `allow` − `deny` (deny wins). `learning` = none, `full` = all.

| Capability | Lifts (from today's learning lock) |
|---|---|
| `terminal` | the terminal exec stubs, `disable-command-line`, the terminal keybinding |
| `file_manager` | the Nautilus exec stub, the FileManager1 D-Bus override, the Files entry in the Dash |
| `settings` | the control-center exec stub, the org.gnome.Settings D-Bus override, `user-administration-disabled` |
| `extensions` | user GNOME extensions, `allow-extension-installation` |
| `all_apps` | `Hidden=true` over installed apps not in the Dash |
| `user_apps` | user Flatpaks exported, `~/.config/environment.d` honoured |

Locked dconf keys that belong to no capability (`favorite-apps`, `custom-keybindings`) stay locked unless every
capability is lifted, so preset `full` locks nothing, exactly as today; `screensaver lock-enabled` stays on
everywhere. Linger is not a capability (§4.5).

### 2.4 Device config keys

Today's `[[config]]` keys minus the user-layer keys of §3. `[[device]]`, `locked`, `[school]`, `[[trust]]`
unchanged.

### 2.5 `school.oidc.login_domain`

Removed by the owner on 2026-11-19: the login screen's domain suggestions (from `allowed_domains`) already let a person type only their user name and pick the school domain.

## 3. Layer of each format-2 setting

| Setting | Layer |
|---|---|
| `school.*`, `trust`, `[[device]]`, `locked` | device |
| `login_methods`, `local_users_admin`, `it_account` | device |
| `wifi`, `printers`, `scanners` | device |
| `update_channel`, `chrome.update_window`, `chrome.pause_until` | device |
| `support.enabled` | device |
| `apps.kiosk`, `apps.deb.<id>` with `kiosk = true` | device |
| `files`, `downloads`, `scripts` (`when = "apply"`) | device |
| `interface` | user (`preset` + `allow`/`deny`) |
| `apps.web`, `chrome_policy`, `scripts` (`when = "login"`) | user |
| `apps.flatpak`, `apps.deb` (non-kiosk) | user (visibility); device (install = union) |
| home tidy | user (`home`) |

The login card (open mode) takes its `URLBlocklist` from the user config that a `kind = "guest"` login
resolves to on this Device, keeping "the card opens no site this Device's guest could not".

## 4. Device behaviour

1. **Boot**: device layer from the Group's device config, as today; session state = neutral (everything
   blocked, no web apps, baseline Chrome policy).
2. **Apply time**: for every user config reachable on the Device the agent pre-renders its session state
   (Chrome policy file, dconf DB and locks, xdg override dir, login-script set) plus a compact rules
   file, all root-only. The 6 h reapply, the sysext hook and the boot apply render from "the active
   session's user config, or neutral", never from the device config alone.
3. **Login**: `pam-session` (root, before `pam_systemd`, 5 s budget) evaluates the rules from the
   pre-rendered rules file and the facts (§5), then switches to the chosen config's pre-rendered files by
   atomic rename/symlink. It never parses the bundle and never runs `dconf update`. Everything that can
   tighten happens here.
4. **Loosen later, never tighten later**: neutral is fully blocked, so exec-block changes at login only
   loosen; the agent applies them asynchronously after the session opens. A late or failed unblock leaves
   the session stricter, never looser.
5. **Logout**: on `pam close_session` and on logind session removal the agent reverts to neutral and stops
   the person's user manager (no linger for human sessions). Until neutral is confirmed the next login is
   refused in `pam-check`; `pam-session` re-checks as a backstop.
6. **Install set**: the union of `apps.flatpak`/`apps.deb` over the user configs reachable on the Device
   (named by rules whose `device_group` is absent or contains the Device's Group, plus `fallback`).
   Installs stay device-layer jobs; Flatpak removes only what it installed; `.deb` removal goes through
   the sysext refresh and exec-block re-assert.
7. **One human session at a time**: while a human session (SSO, local, guest, itadmin) is open another
   login is refused in `pam-check` with "Someone is still signed in on this device. They need to sign out
   first, or restart the device." (through i18n). Never names the person. No admin override. Lock/unlock
   is the same session. Kiosk sessions keep today's rules. That message is only for another person's
   session; every other refusal of the user layer (the marker cannot be read, the same person's session
   is still being closed, the session cannot be switched in, see 9) says "This device could not get your
   session ready. Try again in a moment, or restart the device." (through i18n).
8. **Crash / power loss**: boot always starts neutral; `/run` is tmpfs.
9. **Failure**: if the chosen config cannot be switched in, the session gets `fallback`; if that fails
   too, the login is refused. Reported.
10. **Status report** gains `user_config` of the current session (no facts, no names).

## 5. Issuer interface (what the Device expects)

Everything in this section applies only when `school.oidc.mastersos_claims = true` (device layer, default
`false`; needs `[school] id`). With `false` the issuer is a plain OIDC issuer (Google, a lab issuer): no
extra scopes, no org check, no facts, and the user name comes from `email` as today. Fact conditions then
never match, and `check` warns when a rule uses them.

- **Organisation**: the authorization request carries scope `org:<[school] id>`; the ID token carries
  `org`, which must equal `[school] id`. The broker checks it **before grant**, from an expected-org file
  the agent writes next to the allowed-domains file.
- **Login name**: the ID token carries `login_name` for every person: lowercase, exactly one `@`, local
  part `[a-z0-9._-]{1,64}`, domain in `allowed_domains`. It is admin-controlled, unique within the issuer
  and never reused. It is the Device's local user name. The broker takes the user name from
  `login_name` instead of `email`, drops the `email_verified` requirement for it, and its "returned
  account = requested account" check compares `login_name`. `login_hint=<login_name>`. Everything keyed
  on the name ("contains @" = SSO, allowed domains, `admin_users`, sign-in hand-off) is unchanged.
- **Facts**: from the userinfo endpoint with this login's access token, scope `mastersos.facts`:

```json
{ "sub": "...", "org": "<organisation id>", "org_role": "member",
  "org_nodes": ["<node id>", "..."], "classes": [{"id": "<class id>", "role": "student"}],
  "age_band": "13-17" }
```

  No facts (scope not granted, request failed): fact conditions never match; rules without fact conditions
  (`admin`, `device_group`, `kind`, `user`) still apply in order, and `[user] fallback` applies when none matches
  (David's ruling 2026-11-19 on the contract's wording).
- **Hand-off (consume once)**:
  1. At the start of every authentication (login or unlock) the broker deletes that user's facts file.
  2. On grant it writes `/run/mastersos/facts/<user name>.json` (root 0700 directory from tmpfiles; the
     broker unit gets a `ReadWritePaths=` drop-in), mode 0600, written by rename, one of:
     `{"version":1,"user":"<login_name>","granted_at":<unix seconds>,"facts":{...}}` or
     `{"version":1,"user":"<login_name>","granted_at":<unix seconds>,"error":"<text>"}`. `facts` keeps
     only `sub`, `org`, `org_role`, `org_nodes`, `classes`, `age_band`; userinfo `sub`/`org` must equal
     the ID token's, else the error form.
  3. `pam-session` reads and deletes it and ignores it when older than 120 s. Missing, error or stale →
     `[user] fallback` (reported).
- No other cache. There is no offline SSO login.

All of the broker's changes go in a new carried patch `image/patches/authd-oidc/0007-*.patch`; patches
0001–0006 stay byte-identical.

## 6. CLI

- `mastersos check`: §2.1 errors and warnings.
- `mastersos explain user --kind <k> [--admin] [--user <login_name>] [--org-role ..] [--class-role ..]
  [--class <id>] [--org-node <id>] [--age-band ..] [--sub <id>] [--device-group <id>]`: offline; prints the
  matching rule (file line) and the user config.
- `mastersos explain device <serial>`: Group, device config, reachable user configs, install set.
- `mastersos migrate`: format 2 → 3 with unchanged behaviour: each Config → a device config and a user
  config with the same id; one `device_group` rule per Group, in Group order; `fallback` = the `default`
  Group's; `interface` → `preset`; legacy `mode = "browser"` → `learning` with no Flatpak/`.deb` apps.
- Server-backed commands (`explain user <login_name|sub>`, `users list`, `org tree`, `classes list`) read
  names and facts through the settings server's directory API. They are a separate plan once that API is
  published.

## 7. Compatibility

- Agents report the feature `format_3` (the existing `format_<n>` naming); publishing a `format = 3` document is refused while a recently
  seen Device does not report it (existing gate, `manifest.rs` `features_used`).
- An agent that supports format 3 still accepts format 1/2 documents and behaves exactly as today with
  them (every login gets the Device's single Config). Changing a Device from a format 3 document to a format 1/2 one removes
  the user layer's files, but never while a person is signed in: then the removal waits and is done when
  that session ends (its revert, instead of switching to neutral).
