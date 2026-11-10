# Recipes

Common changes. Each shows the TOML to add or change in `manifest.toml` and the issue codes you may meet.
Keep the rest of the file as it is. Run `mastersos check` after every edit. Every block here is checked by a test.

## Add a web app

Goal: a Config gets a web app in its launcher. Add `[[config.apps.web]]` under the Config. For `icon`, use an
`https://` link, a file in the directory (`files/...`), or leave it out.

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

Goal: a Group's Devices get different apps or a different mode. Add a `[[config]]` (or copy an existing one in `manifest.toml`, change `id` and `name`), and set the Group's
`config` to it. Other Groups keep theirs.

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

Issues: `group_unknown_config`, `config_duplicate_id`, `config_unused`. Removing a Config a Group still uses
gives `group_unknown_config`.

## Turn on SSO

Goal: school accounts can sign in. Add `[school.oidc]` (issuer and client id from the SSO provider), add
`"sso"` to each Config that should allow it, optionally limit to your domains. A school on Google
Workspace may use `issuer = "https://accounts.google.com"` (with its client id and secret); then
`allowed_domains` is required, or any Google account could sign in (publish refuses it with
`public_idp_without_allowed_domains`).

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

Issues: `sso_without_oidc`, `oidc_invalid`, `public_idp_without_allowed_domains`,
`allowed_domain_invalid`.

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
which every Config inherits) for a network every Config needs. You never see or write a password: in
`manifest.toml` it is a reference. For an open network (`open = true`, below) nothing more is needed. For a
network with a password, write `psk = "secret:<name>"` (a short unique name such as `guest-wifi`) and ask IT to
add `<name> = "<the password>"` to `secrets.toml`; do not ask the person to tell you the password.
Enterprise networks: next recipe.

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

A network that already has a password shows `psk = "secret:guest-wifi"`. Leave that line as it is when you change
something else (for example `hidden`). Renaming the `ssid` makes it a new network that needs its own secret, and so
does changing where an enterprise password is sent (`eap`, `phase2`, `identity`, `anonymous_identity`,
`server_domain`, `ca_cert`, `check_server`): `check` warns `secret_rerouted`, and `mastersos publish` refuses until
IT checks `mastersos diff` and approves that secret by name (`--allow-reroute=<name>`). A new network with a new
`secret:` name is reported the same way once the school has published. Tell IT which secret; never pass that flag yourself.

Issues: `wifi_invalid`, `wifi_ssid_duplicate`, `secret_unknown` (a `secret:` name missing from `secrets.toml`),
`secret_rerouted`, `wifi_open_implicit` (an older entry without `psk`, `eap` or `open = true`: Devices join it as
open; leave it to IT, who writes `open = true` or a `psk` reference).

## IT account, seeds per Group and the Install page

- The IT maintenance account (`it_account` in `[defaults]` or a Config) is created from a password hash.
  IT runs `mastersos hash-password` and puts the hash into `secrets.toml`; `password_hash` in `manifest.toml` stays
  a `secret:` reference. You never set it and never ask the person for the password.
- Seeds (the file a USB stick carries) are made on the admin web page, **Install**: one school seed by
  default, and more per Group when Devices of a Group should start in it. A seed carries the Wi-Fi and the
  IT account of the *latest published* version, so a local change shows in new seeds only after IT
  publishes. You cannot download, create or revoke seeds; tell the person to use the Install page.
- A seed is a key (it holds a fetch key, Wi-Fi passwords and the IT account's password hash): say so when
  the person asks about USB sticks, and that a lost stick is revoked on the Install page.

## Add an enterprise Wi-Fi network

Goal: Devices sign in to an 802.1X (WPA enterprise) network with an account. You write everything but
the secret; IT fills it in `secrets.toml`.

1. Ask the person for the SSID, the method (usually `peap`), the account name, and the RADIUS server's
   domain (`server_domain`) or CA certificate. Not the password.
2. Add the entry in `manifest.toml` with a reference for the secret (with `eap = "tls"`, references for
   `client_key` and `client_key_password` too):

   ```toml
   [[config.wifi]]
   ssid = "School-Staff"
   eap = "peap"
   identity = "staff-devices"
   password = "secret:school-staff"
   server_domain = "radius.school.example"
   ```

3. `mastersos check` now reports `secret_unknown` (`school-staff`): that is expected.
   Tell IT: "Put `school-staff = "<the Wi-Fi password>"` into `secrets.toml` before this can be published."
4. Once IT has added it, the check passes, and you can show the diff and ask IT to publish.

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

## Add a third-party .deb app (TestNav)

Goal: install a vendor's `.deb` from its https link and run it as a locked kiosk app. Add
`[config.apps.deb.<id>]` with a `name` and the `url`; `kiosk = true` puts it on the login screen.
Writing `sha256` pins the exact file (without it the app follows the link). `packages` lists Ubuntu
packages the program needs but the `.deb` does not declare. `exec` is only needed when the package has
no usable `.desktop` file. `ubuntu_mirror` is optional.

```toml check=ok
[[config]]
id = "standard"
name = "Standard"
login_methods = ["guest"]

[config.apps.deb.testnav]
name = "TestNav"
url = "https://download.testnav.com/_testnavinstallers/testnav-1.15.7.deb"
kiosk = true
packages = ["x11-utils"]
exec = "/opt/testnav/bin/testnav"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

Issues: `deb_id_invalid`, `deb_name_invalid`, `deb_url_invalid`, `deb_sha256_invalid`,
`deb_packages_invalid`, `deb_exec_invalid`, `deb_icon_invalid`, `deb_kiosk_id_conflict`,
`ubuntu_mirror_invalid`, `kiosk_too_many` (`.deb` apps with `kiosk = true` count).

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
