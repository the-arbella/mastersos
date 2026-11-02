# Recipes

Common changes. Each shows the TOML to add or change and the issue codes you may meet. Keep the rest of
the Draft as it is. A change inside one Config goes through `mastersos config show <id>` / `config set <id> <file>`;
anything else through `draft get` / `draft put`. Run `mastersos draft check` after every edit. Every block here is
checked by a test.

## Add a web app

Goal: a Config gets a web app in its launcher. Add `[[config.apps.web]]` under the Config. For `icon`, use an
`https://` link, a file IT uploaded in the web console (`files/...`), or leave it out.

```toml check=ok files=files/khan-academy.png
[[config]]
id = "standard"
name = "Standard"
login_methods = ["guest"]

[[config.apps.web]]
name = "Khan Academy"
url = "https://www.khanacademy.org/"
icon = "files/khan-academy.png"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

Issues: `web_app_invalid`, `web_app_not_https`, `icon_invalid`, `file_missing`.

## Give a Group its own Config

Goal: a Group's Devices get different apps or a different mode. Add a `[[config]]` (or copy an existing one with
`mastersos config show`, change `id` and `name`, then `mastersos config create <file>`), and point the Group at it:
`mastersos group set <group> --config <config>`. Other Groups keep theirs.

```toml check=ok
[[config]]
id = "standard"
name = "Standard"

[[config]]
id = "teacher"
name = "Teacher"
interface = "full"
login_methods = ["local"]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"

[[group]]
id = "staff"
name = "Staff laptops"
config = "teacher"
```

Issues: `group_unknown_config`, `config_duplicate_id`, `config_unused`. Deleting a Config a Group still uses
fails with `config_in_use`.

## Turn on SSO

Goal: school accounts can sign in. Add `[school.oidc]` (issuer and client id from the SSO provider), add
`"sso"` to each Config that should allow it, optionally limit to your domains.

```toml check=ok
[school]
allowed_domains = ["school.ac.th"]

[school.oidc]
issuer = "https://sso.school.ac.th"
client_id = "mastersos"

[[config]]
id = "standard"
name = "Standard"
login_methods = ["sso", "guest"]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

Issues: `sso_without_oidc`, `oidc_invalid`, `oidc_issuer_google`, `allowed_domain_invalid`.

## Add an administrator

Goal: a person administers Devices. Add their SSO account to `[school] admin_users`. SSO must be on for
the Config.

```toml check=ok
[school]
admin_users = ["it.admin@school.ac.th", "somchai.k@school.ac.th"]

[school.oidc]
issuer = "https://sso.school.ac.th"
client_id = "mastersos"

[[config]]
id = "standard"
name = "Standard"
login_methods = ["sso"]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

Issues: `admin_user_invalid`, `admins_without_sso`, `no_admins`, `admin_users_too_many`.

## Set up Wi-Fi

Goal: Devices of a Config join a network. Add it to that Config, or to `[defaults]` (`[[defaults.wifi]]`,
which every Config inherits) for a network every Config needs. Add school-wide networks through the forms or
`mastersos defaults wifi`, not by editing `[school]`: the server decides where they are stored (a setup whose
Defaults hold only Wi-Fi stays `format = 1`) and writes `format` itself.
From the command line: `mastersos defaults wifi list|add|remove` (it reads the whole Defaults table and
writes it back whole, so other networks and their passwords stay). You cannot enter the password: passwords and keys always read as
`"<kept>"` and the server refuses any other value from you (`secret_via_web`). You never create a WPA
password network: an entry with none of `open`, `psk` and `eap` is refused (`secret_via_web`), since
Devices would join it as open. Ask IT to create password networks in the admin web page; do not ask the
person to tell you the password. You can add an open network (`open = true`, below) or an enterprise
network without its password (next recipe):

```toml check=ok
[[config]]
id = "standard"
name = "Standard"

[[config.wifi]]
ssid = "School-Guest"
open = true

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

A network that already has a password shows `psk = "<kept>"`. Leave that line as it is when you change
something else (for example `hidden`): the server keeps the password. Renaming the `ssid` makes it a new
network whose password IT has to enter again, and so does changing where an enterprise password is sent
(`eap`, `phase2`, `identity`, `anonymous_identity`, `server_domain`, `ca_cert`, `check_server`).

Issues: `wifi_invalid`, `wifi_ssid_duplicate`, `wifi_open_implicit` (an older entry without `psk`, `eap` or
`open = true`: Devices join it as open; leave it to IT, who writes `open = true` or adds the password in
the web page).

## IT account, seeds per Group and the Install page

- The IT maintenance account (`it_account` in `[defaults]` or a Config) is created from a password hash.
  The password can only be set in the admin web page (Defaults, "IT maintenance account"): you cannot set
  it, there is no command for it, and you never ask the person for it. Do not write or change
  `password_hash`; read it as `"<kept>"` and leave it as it is.
- Seeds (the file a USB stick carries) are made on the admin web page, **Install**: one school seed by
  default, and more per Group when Devices of a Group should start in it. A seed carries the Wi-Fi and the
  IT account of the *latest published* version, so a draft change shows in new seeds only after IT
  publishes. You cannot download, create or revoke seeds; tell the person to use the Install page.
- A seed is a key (it holds a fetch key, Wi-Fi passwords and the IT account's password hash): say so when
  the person asks about USB sticks, and that a lost stick is revoked on the Install page.

## Add an enterprise Wi-Fi network

Goal: Devices sign in to an 802.1X (WPA enterprise) network with an account. You write everything but
the secret; IT fills it in on the web page.

1. Ask the person for the SSID, the method (usually `peap`), the account name, and the RADIUS server's
   domain (`server_domain`) or CA certificate. Not the password.
2. Add the entry without `password` (with `eap = "tls"`, also without `client_key` and
   `client_key_password`), with `mastersos defaults wifi add --ssid … --enterprise peap --identity …`
   (Defaults), `mastersos config set` or `draft put`:

   ```toml
   [[config.wifi]]
   ssid = "School-Staff"
   eap = "peap"
   identity = "staff-devices"
   server_domain = "radius.school.example"
   ```

3. `mastersos draft check` now reports `wifi_invalid` (`eap = "peap" needs password`): that is expected.
   Tell the person: "IT needs to open the Config in the admin web page and type the Wi-Fi password for
   School-Staff before this can be published."
4. Once IT has entered it, the entry reads `password = "<kept>"` for you, the check passes, and you can
   show the diff and leave the publish request.

Issues: `wifi_invalid`, `wifi_server_unchecked` (only with `check_server = false`), `wifi_ssid_duplicate`.

## Add a Kiosk app

Goal: a locked full-screen app for tests. Add `[config.apps.kiosk.<id>]` with a `name`, the `url`, and
the sites it may reach in `allow` (subdomains included).

```toml check=ok
[[config]]
id = "standard"
name = "Standard"
login_methods = ["guest"]

[config.apps.kiosk.nwea-map]
name = "NWEA MAP Growth"
url = "https://test.mapnwea.org/"
allow = ["nwea.org", "mapnwea.org"]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

Issues: `kiosk_id_invalid`, `kiosk_name_invalid`, `kiosk_url_not_https`, `kiosk_allow_invalid`,
`kiosk_no_entry`, `kiosk_too_many`.

## Pause Chrome updates

Goal: no Chrome update during exams. Set `pause_until` in the Config's `[config.chrome]` to a day at most
14 days after the publish day: use a date within 14 days of today. Remove it to end the pause.

```toml check=ok
[[config]]
id = "standard"
name = "Standard"

[config.chrome]
pause_until = 2026-11-10
update_window = "16:00-07:00"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

Issues: `chrome_pause_invalid`, `chrome_pause_too_long`, `chrome_paused`, `chrome_window_invalid`.
