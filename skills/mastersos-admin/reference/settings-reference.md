# MastersOS settings reference

This is the complete reference for the MastersOS settings file. It is written for school IT staff
and for AI assistants helping them: every key, every issue the check can report, and recipes for
common tasks. Tests check it against the code, so the keys, values and examples here are the ones
the system accepts.

## Overview

### What the settings file is

A school's Devices are configured by one **settings file** (`manifest.toml`, written in TOML). It
has four layers:

- the settings for the whole school (`[school]`);
- the **Defaults** (`[defaults]`): what every Config starts from (Wi-Fi, apps, printers, the IT
  account and so on);
- the **Configs** (`[[config]]`): what a Device looks like, its **Mode**, who can sign in, Wi-Fi,
  apps, printers, Chrome and so on, on top of the Defaults;
- the **Groups** (`[[group]]`): a set of Devices and the one Config they use. Several Groups can
  share a Config.

`[[device]]` entries say which Device belongs to which Group. Every Device downloads the whole file,
finds its own Group and applies only that Group's Config (the Defaults with what the Config writes
laid over them). The same Config applies whoever signs in on the Device.

The settings file can also carry files (`files/…`, such as wallpapers or icons) and scripts
(`scripts/…`). The settings file plus these files is the **settings bundle**.

### Edit, check, Publish

1. The settings are a **local directory** that IT keeps: `mastersos pull <dir>` downloads the latest
   published Version into it (`mastersos init <dir>` starts one for a new school). You (or an AI
   assistant) edit `manifest.toml` there, and add files under `files/`. The server holds no draft.
2. `mastersos check` **checks** the directory on your computer and lists its **Issues**. An Issue has a level:
   - **error**: blocks Publish;
   - **warning**: shown, does not block (`secret_rerouted` blocks until IT approves it);
   - **info**: reports the current state (for example a Chrome update pause), not a problem.
3. When there are no errors, `mastersos publish` builds the next **Version** from the directory (it puts the
   secrets in) and uploads it; IT signs it with the **Recovery kit**, on the computer
   (`--kit <file>`) or on the signing page (a **Passkey** there is optional). Devices accept only Versions signed by a key in
   **trust**, and only Versions newer than the one they have. Afterwards `mastersos pull` takes the published
   Version as the new base.

Some keys are written for you; do not write them by hand:

| Key | Written by |
|---|---|
| `format` | `mastersos init` / `pull` (the lowest the text needs); leave it as it is |
| `version`, `issued_at` | `mastersos publish`, when it builds the Version |
| `[[trust]]` | you, from `mastersos keys list` (registered signing keys); IT changes it and signs with a recovery key |
| `[school] id` | `mastersos init` / `pull`: the school's id; do not change it |
| `[school] escrow_recipients` | the signing page, when recovery-kit escrow is set up |
| `[school] name` | `mastersos publish`, from the school's name |
| `[school] logo_sha256`, `logo_icon_sha256` | IT, pasted from the output of `mastersos logo upload` |
| `it_account` `password_hash` | a `secret:` reference; IT puts the hash (`mastersos hash-password`) in `secrets.toml` |

### How a Device finds its Group

1. A `[[device]]` entry whose `serial` (or `device_id`) matches the Device;
2. otherwise the Group named in the Device's installer seed, if it names one and that Group exists
   (a seed made on the Install page for a Group names it);
3. otherwise the Group with id `default`. There must always be exactly one `default` Group.

The Device then applies the Config its Group names. New Devices therefore start in `default`; move
them into their Group with `[[device]]` entries, written in `manifest.toml` like any other setting
(`mastersos devices list` shows each Device's serial number).

### The installer seed

The seed is the small file on the installer USB stick that lets a new Device find the school before
it has downloaded any settings. A seed made on the console's Install page is for one Group and
carries: the server address, the school id and name, the signing public keys, that Group's `group`,
the latest published `[school.oidc]`, the Wi-Fi of that Group's Config as it comes out of the
Defaults and the Config's own entries (the latest published Version, not your local changes), and the
Config's `it_account` hash, if it has one. A new Device therefore joins the school's networks, shows
the sign-in, and creates the IT account before its first settings download. The seed holds Wi-Fi
passwords and the IT password hash: keep the USB stick like a key.

### The settings format (`format`)

The first line of the file, `format = 2`, says which version of the settings syntax the text is
written in; a text without it is format 1 (every file before the Defaults). The number goes up only
when the meaning of what is written changes (for example with `[defaults]`, a Config's list now adds
to the Defaults' list instead of standing alone); a new key alone does not raise it, it goes through
the feature check (`feature_unsupported`). The server writes the lowest format the text needs: `2`
once it uses `[defaults]`, `drop`, `it_account` or `[school]` `name` / `logo_sha256` / `logo_icon_sha256`, and leaves `1`
when it uses none of them, so old files stay readable. A Device whose OS reads an older format does
not apply the Version, reports "the settings use a newer format than this OS; update the OS first",
and keeps the previous one; the server therefore refuses to publish a text whose format a Device
seen in the last 30 days does not read (`format_unsupported`). A `format` newer than 2 is reported
the same way. Leave `format` as the server wrote it.

<!-- prompt:omit -->
### TOML in one paragraph

A TOML file is `key = value` lines. Strings are in double quotes (`"Teachers"`), booleans are
`true`/`false`, numbers are bare (`300`), lists are `["a", "b"]`, and a small table can be written
inline: `{ ssid = "School-Staff", hidden = false }`. A header `[school]` starts a table: the lines
under it belong to it until the next header. A header `[[config]]` starts a *new element* of a list
of tables; a header such as `[config.apps]` or `[[config.wifi]]` after it belongs to the **most
recent** `[[config]]`. So `wifi = [{ ssid = "A" }]` inside a config and a `[[config.wifi]]` block
under that config mean the same thing. Lines starting with `#` are comments. Key names are
case-sensitive and must be spelled exactly as in this reference; an unknown key is an error.
<!-- /prompt:omit -->

<!-- prompt:omit -->
### About the examples

Blocks marked `check=ok` pass the check with no errors; blocks marked `check=<code>` report that
Issue (and no other error). `files=…` lists the files the example assumes are in the settings
bundle. The examples leave out `[[trust]]` and `[school] id`, which your directory already has; the
test that runs them adds a valid trust and school id.

A complete, small settings file:

```toml check=ok files=files/khan-academy.png
[school]
admin_users = ["it.admin@school.ac.th"]
allowed_domains = ["school.ac.th"]
timezone = "Asia/Bangkok"
locale = "th_TH.UTF-8"

[school.oidc]
issuer = "https://sso.school.ac.th"
client_id = "mastersos"

[[config]]
id = "standard"
name = "Standard"
login_methods = ["sso"]
interface = "learning"

[[config]]
id = "teachers"
name = "Teacher Devices"
login_methods = ["sso", "local"]
interface = "full"
wifi = [{ ssid = "School-Staff", psk = "secret:school-staff" }]

[config.apps]
web = [{ name = "Khan Academy", url = "https://www.khanacademy.org/", icon = "files/khan-academy.png" }]
flatpak = ["org.libreoffice.LibreOffice"]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"

[[group]]
id = "teachers"
name = "Teacher Devices"
config = "teachers"

[[device]]
serial = "7HX2KQ3"
group = "teachers"
```
<!-- /prompt:omit -->

## Settings reference

Columns: **Key**, **Type**, **Required / default** (what happens when the key is left out),
**Allowed values**, **Example**, **Notes**.

### Top-level keys

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `format` | integer | `1` when left out; written by `init`/`pull` | `1`, `2` | `format = 2` | The settings syntax version, on the first line. `init` and `pull` write the lowest one the text needs: `2` once `[defaults]`, `drop`, `it_account` or `[school]` `name` / `logo_sha256` / `logo_icon_sha256` are used (they are `invalid_value` under `1`). A Device whose OS reads an older format does not apply the Version and asks to update the OS first. Leave it as `init` or `pull` wrote it. |
| `version` | integer | written by `publish` | a positive integer, higher than the last Version | `version = 42` | `mastersos publish` writes it (the pulled version plus one). |
| `issued_at` | string | written by `publish` | RFC 3339 time | `issued_at = "2026-10-10T07:00:00Z"` | `mastersos publish` writes it. |
| `trust` | list of tables | required, at least one key | see [`[[trust]]`](#trust) | — | Listed in `manifest.toml` (see `mastersos keys list`); IT changes it. Empty is `trust_empty`. |
| `school` | table | optional; defaults below | see [`[school]`](#school) | — | Settings for every Device. |
| `defaults` | table | optional; nothing inherited | see [`[defaults]`](#defaults) | — | What every Config starts from (`format = 2`). |
| `config` | list of tables | required: at least the Config of the `default` Group | see [`[[config]]`](#config) | — | Each `[[config]]` header adds one Config. |
| `group` | list of tables | required: the `default` Group | see [`[[group]]`](#group) | — | Each `[[group]]` header adds one Group. |
| `device` | list of tables | optional, empty | see [`[[device]]`](#device) | — | Each `[[device]]` header adds one Device entry. |

### `[school]`

Settings shared by every Device, whatever its Group.

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `id` | string | written by the server | the school's id: a lowercase UUID | `id = "0192f3a4-5b6c-7d8e-9f00-112233445566"` | Binds the settings to the school: a Device accepts only settings naming its own school. Never change it. Wrong or missing is `school_id_mismatch`; a malformed id is `invalid_value`. |
| `oidc` | table | optional; no SSO | see [`[school.oidc]`](#schooloidc) | — | Needed for the `sso` login method. |
| `allowed_domains` | list of strings | optional; empty = any account the SSO provider accepts | lowercase domain names (letters, digits, `.`, `-`), no `@`, at most 254 bytes each, at most 200 | `allowed_domains = ["school.ac.th"]` | SSO accounts may sign in only when the part after the last `@` equals one of them exactly (subdomains are not included). Administrators in `admin_users` are not limited by it. |
| `admin_users` | list of strings | optional; empty = no SSO administrators | SSO account names like `name@school.ac.th` (letters, digits, `. _ % + -`, not starting with `%` or `+`), at most 254 bytes each, at most 200 | `admin_users = ["it.admin@school.ac.th"]` | These accounts are administrators (sudo, system settings) on every Device, and can sign in even on a locked Device even when their domain is not in `allowed_domains`. They sign in with SSO, so the Config needs `sso` in `login_methods`. Compared ignoring case. |
| `update_channel` | string | `"stable"` | `"stable"`, `"beta"` | `update_channel = "stable"` | The OS update channel. Going from `beta` back to `stable` does not downgrade: Devices stay on their version until `stable` has a higher one. |
| `update_mirror` | string | optional; Devices use the official update source | `http://` or `https://` plus a host (optional port) and an optional directory; no query, fragment, credentials, `%`, `@` or `..`; at most 254 bytes | `update_mirror = "https://cache.school.ac.th/mastersos"` | A school cache with the same layout as the official source. Devices try it first and fall back to the official source. Updates are signed, so the cache cannot change them. Devices whose OS predates this key reject the whole Version (see `feature_unsupported`). |
| `timezone` | string | optional; Devices keep their current time zone | an IANA time zone name | `timezone = "Asia/Bangkok"` | Removing the key does not reset Devices. A name not in the Device's time zone database is reported by the Device as a failure. |
| `locale` | string | optional; Devices keep their current language | `xx_YY.UTF-8`; the image provides `th_TH.UTF-8`, `en_US.UTF-8`, `en_GB.UTF-8`, `zh_CN.UTF-8` | `locale = "th_TH.UTF-8"` | Other well-formed languages pass the check, but Devices report that the image lacks them. |
| `wifi` | list of tables | optional; none | see [`[[school.wifi]]`](#schoolwifi); never an empty list | — | Moved to `[defaults] wifi` (written here in a `format = 2` text it is `school_wifi_moved`); versions that still carry it work as before: its networks come before the Defaults' ones. A Defaults or Config entry with the same `ssid` replaces the school's. Write entries or leave the key out: `wifi = []` is `invalid_value`. |
| `name` | string | written by the server | 1-100 characters | `name = "Example International School"` | The school's display name, shown on Devices ("Managed by …"). Do not write it by hand (`format = 2`); a name that is empty, over 100 characters or holds control characters is `school_name_invalid`. |
| `logo_sha256` | string | written by IT | 64 lowercase hex digits | — | The SHA-256 of the sign-in screen logo (a PNG 96 pixels high, at most 480 wide) Devices download from the school's server at `/logos/<sha256>.png` and show only when it matches; written, with `logo_icon_sha256`, when IT runs `mastersos logo upload` and pastes the lines it prints. Do not invent it (`format = 2`); anything else is `logo_sha256_invalid`, and one of the two keys without the other is `logo_incomplete`. |
| `logo_icon_sha256` | string | written by IT | 64 lowercase hex digits | — | The SHA-256 of the quick menu icon (a PNG of 40 x 40 pixels), downloaded and checked like `logo_sha256`. Written together with `logo_sha256`; do not write it by hand (`format = 2`). |
| `escrow_recipients` | list of strings | optional; no escrow | 1 to 8 age X25519 public keys (`age1…`) in canonical lowercase form, none twice; never an empty list | — | Devices encrypt their disk recovery key to these keys before sending it to the cloud. Written by the signing page; each must belong to a Recovery kit in trust (`escrow_recipient_unregistered`). Write the key with entries or leave it out: `escrow_recipients = []` is `invalid_value`. |

```toml check=ok
[school]
admin_users = ["it.admin@school.ac.th", "somchai.k@school.ac.th"]
allowed_domains = ["school.ac.th", "students.school.ac.th"]
update_channel = "stable"
update_mirror = "https://cache.school.ac.th/mastersos"
timezone = "Asia/Bangkok"
locale = "en_US.UTF-8"

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

### `[school.oidc]`

The school's single sign-on provider (OpenID Connect). Devices use it only to check who someone is;
they never read group membership from it. The provider must support the authorization code flow
with PKCE and the fixed redirect `http://127.0.0.1:48123/callback`. Google accounts are not used to
sign in on Devices.

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `issuer` | string | required in `[school.oidc]` | `https://` (or `http://`) URL; no spaces, control characters or any of ``# ; " ' ` \`` | `issuer = "https://sso.school.ac.th"` | Not `accounts.google.com` (`oidc_issuer_google`). |
| `client_id` | string | required in `[school.oidc]` | non-empty; same character limits as `issuer` | `client_id = "mastersos"` | The client registered with the provider for MastersOS Devices. |
| `client_secret` | string | optional; no secret | 1 to 512 printable ASCII characters; same character limits as `issuer`, and no `%` | — | Only for a provider that requires one even for a desktop app. Every Device holds it, so it protects nothing; do not reuse a real secret here. Devices whose OS predates this key reject the whole Version (see `feature_unsupported`, feature `oidc_card`). |
| `card_hosts` | list of strings | optional; only the issuer's host | lowercase hostnames with at least two labels; no scheme, port, path, wildcard or IP address; none twice; at most 20 | `card_hosts = ["cdn.school.ac.th"]` | Hosts the sign-in page may load from besides the issuer, for example a CDN or an upstream provider. Each is reached over `https` on port 443, and its subdomains are not included. Leave it out when the provider serves everything from the issuer. Feature `oidc_card`, like `client_secret`. |

```toml check=ok
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

The seed downloaded from the console also carries the latest published `[school.oidc]`, so a school
that uses SSO has it on a new Device before the first settings pull. If the `default` Config allows
`sso` but `[school.oidc]` is missing or invalid, downloading the seed fails with 409
`seed_sso_unset`.

### `[[trust]]`

The signing keys Devices trust. A Version is accepted only when signed by one of them. The Keys page
rewrites this list from the registered keys; do not type keys by hand, and never put a private key
here (only public keys). Changing trust needs a Recovery kit signature.

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `id` | string | required | any name, unique within trust | `id = "recovery-2026"` | Signatures name the key by it. |
| `alg` | string | required | `"ed25519"` (Recovery kit key), `"webauthn-es256"` (Passkey) | `alg = "webauthn-es256"` | |
| `public_key` | string | required | standard base64: 32 bytes for `ed25519`; 65 bytes starting with `0x04` (an uncompressed P-256 point) for `webauthn-es256` | `public_key = "AAAA…="` | |
| `rp_id` | string | required for `webauthn-es256`; not allowed for `ed25519` | a lowercase ASCII host name without scheme, port or path | `rp_id = "sign.os.khundavid.com"` | The host the Passkey was registered on (the signing page). |

The values below are format placeholders, not real keys:

```toml check=ok
[[trust]]
id = "recovery-2026"
alg = "ed25519"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

[[trust]]
id = "it-passkey"
alg = "webauthn-es256"
public_key = "BCoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio="
rp_id = "sign.os.khundavid.com"

[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

### `[defaults]`

What every Config starts from (`format = 2`): the same keys as [`[[config]]`](#config) without
`id`, `name` and `drop`, and its sub-tables are written like the Config ones (`[[defaults.wifi]]`
like [`[[config.wifi]]`](#configwifi), `[defaults.apps]` like [`[config.apps]`](#configapps), and so
on). Every Config starts from the Defaults; what a Config writes replaces "the same thing" in the
Defaults, and what it leaves out is taken as is:

- A single value (`interface`, `login_methods`, `local_users_admin`, `it_account`,
  `chrome.update_window`, `chrome.pause_until`): written in the Config, it replaces the Defaults'
  value as a whole (`login_methods = []` too); left out, the Defaults' value applies, else the
  default listed in `[[config]]`.
- A collection (entries with names): the Config's entries are added after the inherited ones; an
  entry with the same name replaces the inherited entry as a whole (no key-by-key merge). The name
  is `ssid` for `wifi`, `name` for `apps.web`, `printers` and `scanners`, the app id for
  `apps.flatpak`, the key for `apps.kiosk` and `chrome_policy`, `dest` for `files` and `downloads`,
  `path` for `scripts`. To leave an inherited entry out, name it in [`[config.drop]`](#configdrop).

A Config that writes nothing is exactly the Defaults.

**Why a Config's list is added, not replacing the Defaults' list:** if IT only wants one more app
and writes one entry, the rest of the Defaults' apps must not silently disappear. One rule covers
every collection (and Wi-Fi has always worked this way), so there are no exceptions to remember.
Entries are replaced as a whole, never merged key by key.

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `interface` | string | `"learning"` | as in `[[config]]` | `interface = "learning"` | |
| `login_methods` | list of strings | `[]`: guest only | as in `[[config]]` | `login_methods = ["sso", "guest"]` | |
| `local_users_admin` | boolean | `false` | as in `[[config]]` | — | |
| `it_account` | table | none: no IT account | see [`[config.it_account]`](#configit_account) | — | The IT maintenance account on every Device. |
| `wifi` | list of tables | `[]` | as `[[config.wifi]]` | — | After the legacy `[[school.wifi]]`. |
| `apps` | table | none | as `[config.apps]` | — | |
| `printers` | list of tables | `[]` | as `[[config.printers]]` | — | |
| `scanners` | list of tables | `[]` | as `[[config.scanners]]` | — | |
| `chrome_policy` | table | `{}` | as in `[[config]]` | — | |
| `chrome` | table | no limit | as `[config.chrome]` | — | |
| `files` | list of tables | `[]` | as `[[config.files]]` | — | |
| `downloads` | list of tables | `[]` | as `[[config.downloads]]` | — | |
| `scripts` | list of tables | `[]` | as `[[config.scripts]]` | — | |

```toml check=ok
format = 2

[defaults]
interface = "learning"
login_methods = ["guest"]
apps.flatpak = ["org.libreoffice.LibreOffice"]
printers = [{ name = "Library", uri = "ipp://lib.school.ac.th/ipp/print" }]

[[config]]
id = "teacher"
name = "Teacher"
interface = "full"
apps.flatpak = ["org.gimp.GIMP"]
drop.printers = ["Library"]

[[config]]
id = "student"
name = "Student"

[[group]]
id = "default"
name = "Unassigned"
config = "student"

[[group]]
id = "staff"
name = "Staff"
config = "teacher"
```

### `[[config]]`

A Config: what a Device looks like, whoever signs in. Groups name it by `id` (`[[group]] config`);
several Groups can share one Config. A Config no Group names is allowed (write it first, attach it
later) and reported as `config_unused`.

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `id` | string | required | unique among Configs | `id = "student"` | `[[group]]` entries refer to it. |
| `name` | string | required | any text | `name = "Student"` | Shown in the console. |
| `interface` | string | `"learning"` | `"learning"`, `"full"` | `interface = "full"` | The Mode, see [Modes](#modes). A third mode, `create` (a sandboxed Linux environment for computing classes), is coming soon and not accepted yet. |
| `login_methods` | list of strings | `[]`: guest only | any of `"guest"`, `"local"`, `"sso"` | `login_methods = ["sso", "guest"]` | `sso`: school accounts (needs `[school.oidc]`); `local`: local accounts on the Device; `guest`: a temporary session whose home folder is wiped at sign-out. Guest is always allowed (except on a locked Device), so writing `guest` or leaving it out are both valid and mean the same. Administrators sign in with SSO, so they also need `sso`. Kiosk apps start regardless. |
| `local_users_admin` | boolean | `false` | `true`, `false` | `local_users_admin = false` | Whether local accounts are administrators. With `false` and no `admin_users`, nobody on these Devices can administer them (`no_admins`). |
| `wifi` | list of tables | `[]` | see [`[[config.wifi]]`](#configwifi) | — | |
| `apps` | table | none | see [`[config.apps]`](#configapps) | — | |
| `printers` | list of tables | `[]` | see [`[[config.printers]]`](#configprinters) | — | |
| `scanners` | list of tables | `[]` | see [`[[config.scanners]]`](#configscanners) | — | |
| `chrome_policy` | table | `{}`: the baseline only | Chrome enterprise policy names and values | `chrome_policy = { URLBlocklist = ["facebook.com"] }` | Passed to Chrome as written (see Chrome's policy list for names and values), on top of a baseline every Device gets: `BrowserAddPersonEnabled` and `BrowserGuestModeEnabled` false, `BrowserSignin` 0, `DefaultBrowserSettingEnabled`, `MetricsReportingEnabled` and `PromotionalTabsEnabled` false, `ExtensionInstallBlocklist` `["*"]`, `RestoreOnStartup` 5. Write the same key here to override it, for example `BrowserSignin = 1` to allow signing in to Chrome or `ExtensionInstallBlocklist = []` to allow extensions. Date values are not allowed; the check does not catch them, and Devices report a failure at apply time. Not applied inside kiosk apps. |
| `chrome` | table | no limit | see [`[config.chrome]`](#configchrome) | — | When Chrome may update. |
| `files` | list of tables | `[]` | see [`[[config.files]]`](#configfiles) | — | |
| `downloads` | list of tables | `[]` | see [`[[config.downloads]]`](#configdownloads) | — | |
| `scripts` | list of tables | `[]` | see [`[[config.scripts]]`](#configscripts) | — | |
| `it_account` | table | the Defaults' account, else none | see [`[config.it_account]`](#configit_account) | — | Replaces the Defaults' IT account for this Config (`format = 2`). |
| `drop` | table | nothing dropped | see [`[config.drop]`](#configdrop) | `drop.printers = ["Library"]` | Inherited entries this Config leaves out (`format = 2`). |

With [`[defaults]`](#defaults), a key this table lists as defaulting is taken from the Defaults when
left out, and the collections add to the Defaults' entries.

#### Modes

Chrome is the system browser in every Mode, and kiosk apps (`apps.kiosk`) are listed in every Mode.

| Mode | For | What it offers |
|---|---|---|
| `learning` | students, carts | Like a ChromeOS student laptop: Chrome, the web apps, kiosk app entries and the Config's Flatpak apps (for example LibreOffice), in the Dock and the app grid. Files are opened and saved through each app's own file dialog. Controls for Wi-Fi, volume, brightness, power and keyboard layout. No terminal, file manager, system settings, desktop icons or extensions. |
| `full` | teachers, staff | The full desktop: files, terminal, settings, Flatpak apps, printing and scanning. Whether a user is an administrator still depends on `admin_users` and `local_users_admin`. |

```toml check=ok
[[config]]
id = "standard"
name = "Standard"
login_methods = ["guest"]

[[config]]
id = "grade-3-cart"
name = "Grade 3 cart"
login_methods = ["guest", "local"]
local_users_admin = false
interface = "learning"

[config.chrome_policy]
URLBlocklist = ["facebook.com", "tiktok.com"]
BookmarkBarEnabled = true

[[group]]
id = "default"
name = "Unassigned"
config = "standard"

[[group]]
id = "grade-3-cart"
name = "Grade 3 cart"
config = "grade-3-cart"
```

### `[config.it_account]`

The IT maintenance account (`format = 2`), in `[defaults]` or a Config. Its user name is always
`itadmin`. The password is at least 16 characters. IT runs `mastersos hash-password` (it reads the password
without echo) and puts the hash into `secrets.toml`; `password_hash` in `manifest.toml` is a `secret:`
reference, and nobody writes the hash into it (a malformed one is `it_account_invalid`). A Config's own `it_account` replaces the Defaults' one. Left out everywhere:
no IT account, and an account made earlier is locked (its home folder is kept).

On a Device the account is a local administrator that does not appear in the login screen's user
list: IT chooses "Not listed?" and types `itadmin` and the password. It can sign in whatever
`login_methods` says and whatever `local_users_admin` is, but not on a locked Device. Changing the
password (a new hash in `secrets.toml`) and publishing changes it on every Device at its next sync. The hash is in
the installer seed: the password must be long, and when a USB stick is lost, revoke that seed and
change the password.

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `password_hash` | string | required | a crypt hash starting `$y$` or `$6$rounds=500000$`, at most 256 characters | — | A secret: in `manifest.toml` it is a `"secret:<name>"` reference; IT computes the hash with `mastersos hash-password` and puts it in `secrets.toml`. |

### `[config.drop]`

Entries a Config inherits from [`[defaults]`](#defaults) but does not want, each named as in the
Defaults' collection (`format = 2`). Written as `drop.printers = ["Library"]` or, for apps,
`drop.apps.flatpak = ["org.gimp.GIMP"]`. A name the Defaults do not have is `drop_unknown`
(a warning: the Defaults may have been renamed); a name the Config also writes in its own list
is `drop_conflict` (an error).

| Collection | Dropped by |
|---|---|
| `wifi` | `ssid` |
| `apps.web`, `printers`, `scanners` | `name` |
| `apps.flatpak` | the app id |
| `apps.kiosk` | the key (app id) |
| `files`, `downloads` | `dest` |
| `scripts` | `path` |
| `chrome_policy` | the policy name |

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `wifi` | list of strings | `[]` | SSIDs | `drop.wifi = ["Campus-IoT"]` | |
| `apps` | table | none | see [`[config.drop.apps]`](#configdropapps) | — | |
| `printers` | list of strings | `[]` | printer names | `drop.printers = ["Library"]` | |
| `scanners` | list of strings | `[]` | scanner names | — | |
| `files` | list of strings | `[]` | `dest` paths | — | |
| `downloads` | list of strings | `[]` | `dest` paths | — | |
| `scripts` | list of strings | `[]` | script `path`s | — | |
| `chrome_policy` | list of strings | `[]` | policy names | — | |

### `[config.drop.apps]`

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `web` | list of strings | `[]` | web app names | — | |
| `flatpak` | list of strings | `[]` | Flatpak app ids | `drop.apps.flatpak = ["org.gimp.GIMP"]` | |
| `kiosk` | list of strings | `[]` | kiosk app ids | — | |

### `[[group]]`

A Group: a set of Devices and the Config they use. A Group has only these three keys; the settings
live in its Config. Exactly one Group has `id = "default"`: new Devices and Devices without an
assignment use it.

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `id` | string | required | unique among Groups | `id = "grade-3-cart"` | `[[device]]` entries refer to it. One Group must be `"default"`. |
| `name` | string | required | any text; unique among Groups, ignoring case and surrounding spaces | `name = "Grade 3 cart"` | Shown in the console. A name another Group already has is `group_name_duplicate`. |
| `config` | string | required | the `id` of a `[[config]]` | `config = "student"` | A missing Config is `group_unknown_config`. Several Groups may name the same Config. |

Two carts share the student Config; teachers get the full desktop:

```toml check=ok
[[config]]
id = "student"
name = "Student"
login_methods = ["guest"]

[config.apps]
flatpak = ["org.libreoffice.LibreOffice"]

[[config]]
id = "teacher"
name = "Teacher"
interface = "full"
login_methods = ["local"]

[[group]]
id = "cart-g3"
name = "Grade 3 cart"
config = "student"

[[group]]
id = "cart-g4"
name = "Grade 4 cart"
config = "student"

[[group]]
id = "staff"
name = "Staff laptops"
config = "teacher"

[[group]]
id = "default"
name = "Unassigned"
config = "student"
```

<!-- prompt:omit -->
#### Older settings files

Settings files written before Configs existed have no `[[config]]`: each `[[group]]` carries its
own settings and a `mode` key (`"browser"`, the default, or `"desktop"`). Devices and the console
still read Versions published in that shape: each such Group acts as a Config with the same id,
`desktop` as `full` and `browser` as the old browser mode (Devices keep it exactly as it was, and do
not install its Flatpak apps). A file in that shape is `legacy_shape`, and a file that mixes the
two shapes is `config_shape_mixed`. To convert one, move each Group's settings into a `[[config]]`
with the same id and name, write `interface = "full"` for `mode = "desktop"` and
`interface = "learning"` otherwise, and leave `id`, `name` and `config` in the `[[group]]`. A
Config converted from browser mode starts installing its `apps.flatpak` (`flatpak_now_installed`).
<!-- /prompt:omit -->

### `[[config.wifi]]`

A Wi-Fi network the Config's Devices join. It is a system connection: available to every user and
already on the login screen (needed for the first SSO sign-in). The Config's networks come after the
Defaults' ([`[defaults]`](#defaults) `wifi`, preceded by any legacy [`[[school.wifi]]`](#schoolwifi)); an
entry with the same `ssid` as an inherited entry replaces that entry as a whole, and
`drop.wifi = ["ssid"]` leaves one out. Passwords, keys and key passphrases are stored only on the Devices and are
never reported back.

The secrets (`psk`, `password`, `client_key`, `client_key_password`) are not written in `manifest.toml`.
There each one is a reference such as `psk = "secret:guest-wifi"`; the value lives in `secrets.toml` (mode
0600, kept out of git), which IT fills in (`guest-wifi = "…"`). `mastersos pull` moves existing values there;
`mastersos publish` puts them back when it builds the Version. An AI assistant never reads `secrets.toml`:
for a new password network it writes the reference and asks IT to add the value. `mastersos check` reports
`secret_unknown` (a reference with no value: error), `secret_unused` (a value nothing refers to: warning) and
`secret_rerouted` (a secret's network changed where the secret goes: warning, but `mastersos publish`
refuses it until IT passes `--allow-reroute <name>`). A renamed `ssid` is a new network and needs its own secret.

The kind of network follows from the keys written:

- `eap` written: **enterprise** (802.1X);
- else `psk` written: **WPA personal** (WPA2 and WPA2/WPA3 transition mode; add `wpa3_only = true`
  for a network that accepts only WPA3);
- else **open**. Write `open = true` for an open network: an entry with none of `open`, `psk` and
  `eap` is still joined as open (older settings wrote open networks that way) but is reported as
  `wifi_open_implicit`, since it is usually a forgotten password.

An enterprise network must check its RADIUS server: write `server_domain` (the domain on the
server's certificate) or `ca_cert`, or both. Only to connect without checking, write
`check_server = false` (reported as `wifi_server_unchecked`). `eap = "pwd"` is the exception: it
uses no certificates (the password proves both sides), so it takes none of `server_domain`,
`ca_cert` and `check_server`.

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `ssid` | string | required | 1-32 bytes, unique in its list | `ssid = "School-Staff"` | The network name, exactly as broadcast. |
| `hidden` | boolean | `false` | `true`, `false` | `hidden = true` | Set for a network that does not broadcast its name. |
| `open` | boolean | optional | only `true`; not with `psk` or `eap` | `open = true` | An open network (no password). |
| `psk` | string | optional | 8-63 printable ASCII characters, or 64 hex digits | `psk = "example-password-not-real"` | The WPA password; makes the network WPA personal. A secret. |
| `wpa3_only` | boolean | `false` | `true`, `false`; only with `psk` | `wpa3_only = true` | Only WPA3 (SAE). Leave it out for networks that also accept WPA2. |
| `eap` | string | optional | `"peap"`, `"ttls"`, `"tls"`, `"pwd"`; not with `psk` or `open` | `eap = "peap"` | Makes the network enterprise (802.1X). |
| `identity` | string | required with `eap` | at most 256 bytes, no control characters | `identity = "devices@school.ac.th"` | The account name. |
| `password` | string | required with `peap`, `ttls`, `pwd`; not allowed with `tls` | at most 256 bytes, no control characters | `password = "example-password-not-real"` | The account password. A secret. |
| `phase2` | string | `"mschapv2"` with `peap` and `ttls`; not allowed otherwise | `"mschapv2"`, `"pap"`, `"gtc"`, `"md5"` | `phase2 = "pap"` | The inner authentication. |
| `anonymous_identity` | string | optional; none sent | at most 256 bytes, no control characters; only with `eap` | `anonymous_identity = "anonymous@school.ac.th"` | The outer identity sent before the encrypted tunnel. |
| `server_domain` | string | `server_domain` or `ca_cert` is required with `eap` (unless `check_server = false`); not allowed with `pwd` | a domain name: letters, digits, `.`, `-` | `server_domain = "radius.school.ac.th"` | The RADIUS server's certificate must be for this domain or one under it. |
| `ca_cert` | string | optional; absent = the system's trusted CAs (needs `server_domain`); not allowed with `pwd` | PEM text (`-----BEGIN CERTIFICATE-----`), at most 16384 bytes; only with `eap` | `ca_cert = """-----BEGIN CERTIFICATE-----…"""` | The CA that signed the RADIUS server's certificate. |
| `check_server` | boolean | `true` | `true`, `false`; `false` not with `server_domain` or `ca_cert`; only with `eap`, not with `pwd` | `check_server = false` | `false` connects without checking the server (`wifi_server_unchecked`). |
| `client_cert` | string | required with `tls`; not allowed otherwise | PEM text, at most 16384 bytes | `client_cert = """-----BEGIN CERTIFICATE-----…"""` | The Device's certificate. |
| `client_key` | string | required with `tls`; not allowed otherwise | PEM private key (`-----BEGIN … PRIVATE KEY-----`), at most 16384 bytes | `client_key = """-----BEGIN PRIVATE KEY-----…"""` | The certificate's private key. A secret. |
| `client_key_password` | string | optional; only with `tls` | at most 256 bytes, no control characters | `client_key_password = "example-passphrase"` | The passphrase of an encrypted `client_key`. A secret. |

Devices whose OS predates full Wi-Fi support reject a Version that writes `open`, `wpa3_only`
(either value), `eap` or any of the enterprise keys, or has any `[[school.wifi]]` (see
`feature_unsupported`, feature `wifi_ext`). In `[school]`, a written `wifi` is never empty:
`wifi = []` is refused (leave the key out instead).

```toml check=ok
[[config]]
id = "standard"
name = "Standard"

[[config.wifi]]
ssid = "School-Staff"
psk = "example-password-not-real"

[[config.wifi]]
ssid = "School-Exam"
psk = "another-example-password"
hidden = true

[[config.wifi]]
ssid = "School-Guest"
open = true

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

<!-- prompt:omit -->
Enterprise networks: PEAP with an account, and certificate sign-in (`tls`). The certificate texts
below are placeholders.

```toml check=ok
[[config]]
id = "staff"
name = "Staff"

[[config.wifi]]
ssid = "School-Secure"
eap = "peap"
identity = "devices@school.ac.th"
password = "example-password-not-real"
server_domain = "radius.school.ac.th"

[[config.wifi]]
ssid = "School-Cert"
eap = "tls"
identity = "device"
ca_cert = """-----BEGIN CERTIFICATE-----
MIIBexampleCAcertificate
-----END CERTIFICATE-----"""
client_cert = """-----BEGIN CERTIFICATE-----
MIIBexampleDevicecertificate
-----END CERTIFICATE-----"""
client_key = """-----BEGIN PRIVATE KEY-----
MIIEexampleDevicekey
-----END PRIVATE KEY-----"""

[[group]]
id = "default"
name = "Unassigned"
config = "staff"
```
<!-- /prompt:omit -->

### `[[school.wifi]]`

**Moved to [`[defaults]`](#defaults) `wifi`** (`format = 2`): write new networks there. Versions that
still carry `[[school.wifi]]` work as before: a Device gets the school's networks first, minus those
whose `ssid` the Defaults also list, then the Defaults' networks, then its Config's own; an entry
with the same `ssid` later in that order replaces the earlier one as a whole (no key-by-key merge).
Writing it in a `format = 2` text is `school_wifi_moved` (a warning); a format-1 text keeps it
there without a warning, because a format-1 setup keeps Defaults-only Wi-Fi under `[school]` until
something else needs format 2. The same `ssid` twice in
`[[school.wifi]]` is `wifi_ssid_duplicate`. Entries are written like
[`[[config.wifi]]`](#configwifi). Any `[[school.wifi]]` needs feature `wifi_ext` (see
`feature_unsupported`).

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `ssid` | string | required | as in `[[config.wifi]]`, unique in `[[school.wifi]]` | `ssid = "School-Students"` | |
| `hidden` | boolean | `false` | as in `[[config.wifi]]` | — | |
| `open` | boolean | optional | as in `[[config.wifi]]` | — | |
| `psk` | string | optional | as in `[[config.wifi]]` | — | A secret. |
| `wpa3_only` | boolean | `false` | as in `[[config.wifi]]` | — | |
| `eap` | string | optional | as in `[[config.wifi]]` | — | |
| `identity` | string | required with `eap` | as in `[[config.wifi]]` | — | |
| `password` | string | as in `[[config.wifi]]` | as in `[[config.wifi]]` | — | A secret. |
| `phase2` | string | as in `[[config.wifi]]` | as in `[[config.wifi]]` | — | |
| `anonymous_identity` | string | optional | as in `[[config.wifi]]` | — | |
| `server_domain` | string | as in `[[config.wifi]]` | as in `[[config.wifi]]` | — | |
| `ca_cert` | string | optional | as in `[[config.wifi]]` | — | |
| `check_server` | boolean | `true` | as in `[[config.wifi]]` | — | |
| `client_cert` | string | as in `[[config.wifi]]` | as in `[[config.wifi]]` | — | |
| `client_key` | string | as in `[[config.wifi]]` | as in `[[config.wifi]]` | — | A secret. |
| `client_key_password` | string | optional | as in `[[config.wifi]]` | — | A secret. |

```toml check=ok
[school]

[[school.wifi]]
ssid = "School-Students"
psk = "example-password-not-real"

[[config]]
id = "standard"
name = "Standard"

[[config]]
id = "exam"
name = "Exam Devices"

[[config.wifi]]
ssid = "School-Students"
psk = "exam-day-password-not-real"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"

[[group]]
id = "exam"
name = "Exam Devices"
config = "exam"
```

### `[config.apps]`

The apps of a Config.

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `web` | list of tables | `[]` | see [`[[config.apps.web]]`](#configappsweb) | — | Web app launchers. |
| `flatpak` | list of strings | `[]` | Flatpak app ids: at least three dot-separated parts of letters, digits, `_` and `-`, starting with a letter | `flatpak = ["org.libreoffice.LibreOffice"]` | Installed from Flathub in both `full` and `learning` mode, and added to the Dock and the app grid. Apps removed from the list are uninstalled if MastersOS installed them. |
| `kiosk` | table of apps | `{}` | see [`[config.apps.kiosk.<id>]`](#configappskioskid) | — | Kiosk apps keyed by app id. |

### `[[config.apps.web]]`

A web app: a launcher (with icon) that opens a site in its own Chrome window. Students see the web
apps as soon as they sign in.

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `name` | string | required | non-empty, no control characters | `name = "Khan Academy"` | The launcher's name. |
| `url` | string | required | starts with `https://` or `http://`; no spaces or any of ``" ' ` \`` | `url = "https://www.khanacademy.org/"` | `http://` works but warns (`web_app_not_https`). |
| `icon` | string | optional; a generic browser icon | a `files/…` file in the bundle, or an `https://` link | `icon = "files/khan-academy.png"` | A file must be under `files/` in the directory. A downloaded icon that fails falls back to the generic icon. |

```toml check=ok files=files/khan-academy.png
[[config]]
id = "standard"
name = "Standard"

[[config.apps.web]]
name = "Khan Academy"
url = "https://www.khanacademy.org/"
icon = "files/khan-academy.png"

[[config.apps.web]]
name = "Google Classroom"
url = "https://classroom.google.com/"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

### `[config.apps.kiosk.<id>]`

A kiosk app: an app IT defines that runs alone in an isolated, disposable session (for example an
online test). Students start it from the login screen; nothing they do in it is kept. Each web or
PWA kiosk session force-installs the MastersOS exam extension, which provides the way out. `<id>` is
the app id: it starts with a lowercase letter, has only lowercase letters, digits and `-`, and is at
most 24 characters. At most 32 kiosk apps per Config.

Write exactly one of `url` (a web page or PWA) and `exec` (a local program).

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `name` | string | required | 1-64 characters; no `:`, `,` or control characters | `name = "NWEA MAP Growth"` | Shown on the login screen and in the Dock. |
| `icon` | string | optional; a generic icon | a `files/…` file in the bundle, or an `https://` link | `icon = "files/nwea.png"` | |
| `url` | string | one of `url` / `exec` | `https://` with a host name (port allowed); no credentials, spaces, quotes or backslash; at most 2048 bytes | `url = "https://test.mapnwea.org/"` | The page the session opens. |
| `pwa` | boolean | `false` | `true` only with `url` | `pwa = true` | Install and launch `url` as a PWA. |
| `allow` | list of strings | the host of `url` | host names (lowercase letters, digits, `.`, `-`; at least two labels; no `*`, scheme, path or port; non-ASCII as punycode) | `allow = ["nwea.org", "mapnwea.org"]` | Sites the session may open, subdomains included; everything else is blocked. The host of `url` is always allowed. Only for web apps. |
| `user_agent` | string | Chrome's own | at most 512 bytes, no control characters; only with `url` | `user_agent = "Mozilla/5.0 (X11; Linux x86_64) ExampleExamClient/1.0"` | For sites that detect browsers. Exam vendors' secure-client detection needs no change (`kiosk_user_agent`). |
| `extensions` | list of tables | `[]` | see [`[[config.apps.kiosk.<id>.extensions]]`](#configappskioskidextensions) | — | Extensions force-installed in the session. |
| `chrome_policy` | table | `{}` | Chrome policy names and values, except the locked keys | `chrome_policy = { PrintingEnabled = true }` | Laid over the kiosk session's default locks. The Config's `chrome_policy` is not inherited. Policies that are off by default and may be turned on here: `PrintingEnabled`, `TranslateEnabled`, `SpellcheckEnabled`, `LensOverlaySettings`, `GenAiDefaultSettings`, `UserFeedbackAllowed`. Locked keys (`kiosk_policy_locked`) cannot be set. |
| `exec` | string | one of `url` / `exec` | a Flatpak app id, or an absolute path under `/usr/` (no arguments, no `..`) | `exec = "org.geogebra.GeoGebra"` | A Flatpak app must also be in `apps.flatpak`. |
| `android` | any | reserved | — | — | Android apps are not supported; writing it is `kiosk_launch_invalid`. |
| `login_screen` | boolean | `true` | `true`, `false` | `login_screen = true` | Listed on the login screen, where the app is started. |
| `in_session` | boolean | `false` | `true` (needs `login_screen = true`), `false` | `in_session = true` | Also listed in the Dock of normal sessions; choosing it ends the session and returns to the login screen. |

```toml check=ok files=files/nwea.png
[[config]]
id = "standard"
name = "Standard"
login_methods = ["guest"]
interface = "full"

[config.apps]
flatpak = ["org.geogebra.GeoGebra"]

[config.apps.kiosk.nwea-map]
name = "NWEA MAP Growth"
url = "https://test.mapnwea.org/"
allow = ["nwea.org", "mapnwea.org"]
icon = "files/nwea.png"
in_session = true

[config.apps.kiosk.geogebra]
name = "GeoGebra"
exec = "org.geogebra.GeoGebra"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

### `[[config.apps.kiosk.<id>.extensions]]`

A Chrome extension a web or PWA kiosk app force-installs. All other extensions are blocked in the
session.

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `id` | string | required | 32 lowercase letters `a`-`p`, not listed twice, not the MastersOS exam extension | `id = "aaaabbbbccccddddeeeeffffgggghhhh"` | The Chrome Web Store id. |
| `update_url` | string | required | `https://` with a host name, same rules as `url` | `update_url = "https://clients2.google.com/service/update2/crx"` | Chrome Web Store extensions use this URL. |
| `config` | table | `{}` | any values except dates | `config = { mode = "exam" }` | The extension's managed configuration, passed as written. |

```toml check=ok
[[config]]
id = "standard"
name = "Standard"

[config.apps.kiosk.reading-test]
name = "Reading test"
url = "https://reading.example.org/"

[[config.apps.kiosk.reading-test.extensions]]
id = "aaaabbbbccccddddeeeeffffgggghhhh"
update_url = "https://clients2.google.com/service/update2/crx"
config = { mode = "exam" }

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

### `[[config.printers]]`

A network printer added as a driverless (IPP Everywhere) print queue. The queue name is the
printer's `name` with spaces and `/ \ ? ' " # @` replaced by `_`.

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `name` | string | required | 1-64 characters, no control characters; unique in the Config after the replacement above, ignoring case | `name = "Library Printer"` | What users see in the print dialog. |
| `uri` | string | required | starts with `ipp://`, `ipps://`, `http://` or `https://`; no spaces, no credentials (`user@`) | `uri = "ipp://10.0.0.5/ipp/print"` | |

### `[[config.scanners]]`

A network scanner (eSCL / AirScan).

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `name` | string | required | 1-64 characters, no control characters, unique in the Config | `name = "Office Scanner"` | |
| `uri` | string | required | starts with `http://` or `https://`; no spaces, no credentials (`user@`) | `uri = "http://10.0.0.6/eSCL"` | |

```toml check=ok
[[config]]
id = "standard"
name = "Standard"
interface = "full"
printers = [{ name = "Library Printer", uri = "ipp://10.0.0.5/ipp/print" }]
scanners = [{ name = "Office Scanner", uri = "http://10.0.0.6/eSCL" }]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

### `[config.chrome]`

When Chrome may change version on the Config's Devices. It only delays updates; it never downgrades,
and a Device without Chrome always installs it.

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `update_window` | string | optional; any time | `HH:MM-HH:MM` (24-hour, two digits each), Device local time, the two ends different, at least 2 hours long; may cross midnight | `update_window = "16:00-07:00"` | Chrome changes version only inside the window. Devices check once an hour. |
| `pause_until` | date or string | optional; no pause | `YYYY-MM-DD`, at most 14 days after the Publish day | `pause_until = 2026-11-10` | No Chrome version change until this day, inclusive (for example during exams). A quoted `"2026-11-10"` works too. A date in the past has no effect. |

```toml check=ok
[[config]]
id = "standard"
name = "Standard"

[config.chrome]
update_window = "16:00-07:00"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

### `[[config.files]]`

A file from the settings bundle placed on the Config's Devices. Files are kept as listed: a file
removed from the list is deleted from the Devices.

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `src` | string | required | starts with `files/` and is a file in the bundle | `src = "files/wallpaper.jpg"` | Put the file under `files/` in the directory first. |
| `dest` | string | required | an absolute path (starts with `/`) | `dest = "/var/lib/school/wallpaper.jpg"` | Must be in a writable place: `/usr` and `/opt` are read-only, and most of `/etc` cannot be written. A path through a symbolic link fails on the Device. |

```toml check=ok files=files/wallpaper.jpg
[[config]]
id = "standard"
name = "Standard"
files = [{ src = "files/wallpaper.jpg", dest = "/var/lib/school/wallpaper.jpg" }]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

### `[[config.downloads]]`

A large file the Devices download by URL instead of carrying it in the bundle (the bundle is limited
to 20 MB compressed). The SHA-256 is part of the signed settings, so the file can be hosted
anywhere.

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `url` | string | required | a download URL | `url = "https://downloads.school.ac.th/exam-browser.tar.gz"` | |
| `sha256` | string | required | 64 lowercase hex digits | `sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"` | A download that does not match is not used. |
| `dest` | string | required | an absolute path | `dest = "/var/lib/school/exam-browser.tar.gz"` | Same writable-place rules as `files`. |

```toml check=ok
[[config]]
id = "standard"
name = "Standard"

[[config.downloads]]
url = "https://downloads.school.ac.th/exam-browser.tar.gz"
sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
dest = "/var/lib/school/exam-browser.tar.gz"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

### `[[config.scripts]]`

A script from the bundle, for what the settings cannot express. A script runs once per content: it
runs again only when its content changes (or after a Factory reset), so write it to be safe to run
twice. A failed script (non-zero exit) is retried. The exit code and last lines of output are
reported to the console (for `apply` scripts).

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `path` | string | required | starts with `scripts/` and is a file in the bundle | `path = "scripts/setup-classroom.sh"` | |
| `when` | string | `"apply"` | `"apply"`, `"login"` | `when = "login"` | `apply`: as root when the Device applies new settings, in the unpacked bundle folder. `login`: as the user when they sign in, once per user per content (every time for guests). Every user can read `login` scripts: put no secrets in them. |
| `timeout_secs` | integer | `300` | at most 1800 | `timeout_secs = 600` | The script is stopped after this many seconds. |

```toml check=ok files=scripts/setup-classroom.sh,scripts/user-bookmarks.sh
[[config]]
id = "standard"
name = "Standard"

[[config.scripts]]
path = "scripts/setup-classroom.sh"
when = "apply"
timeout_secs = 600

[[config.scripts]]
path = "scripts/user-bookmarks.sh"
when = "login"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

### `[[device]]`

Assigns one Device to a Group, and can Lock it. Write `serial` or `device_id` (or both). A Device
without an entry uses its seed's Group or `default`.

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `serial` | string | `serial` or `device_id` | the hardware serial number (for Dell, the service tag) | `serial = "7HX2KQ3"` | Compared ignoring case and surrounding spaces. Each Device once. |
| `device_id` | string | `serial` or `device_id` | the device id shown in the console | `device_id = "4c1d5e2a-8f3b-4a6e-9d0c-2b7e1f9a3c55"` | For Devices without a readable serial number. |
| `group` | string | required | the id of an existing Group | `group = "teachers"` | |
| `locked` | table | optional; not locked | see [`[device.locked]`](#devicelocked) | — | Lock the Device. |
| `reset` | table | optional | see [`[device.reset]`](#devicereset) | — | Legacy; Devices ignore it. |

```toml check=ok
[[config]]
id = "standard"
name = "Standard"

[[config]]
id = "teachers"
name = "Teacher Devices"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"

[[group]]
id = "teachers"
name = "Teacher Devices"
config = "teachers"

[[device]]
serial = "7HX2KQ3"
group = "teachers"

[[device]]
device_id = "4c1d5e2a-8f3b-4a6e-9d0c-2b7e1f9a3c55"
group = "teachers"
```

### `[device.locked]`

A Lock, for a lost or stolen Device. When the Device receives the Version it ends the sessions of
everyone except administrators, refuses every sign-in except `admin_users`, and shows the message on
the login screen. Remove `locked` and Publish to unlock.

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `message` | string | required in `locked` | at most 500 characters | `message = "This Device was reported lost. Please bring it to the IT office."` | Shown on the login screen. |

```toml check=ok
[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"

[[device]]
serial = "9JK4LM2"
group = "default"
locked = { message = "This Device was reported lost. Please bring it to the IT office." }
```

### `[device.reset]`

**Legacy, do not use.** An old way to request a Factory reset through the settings. Current Devices
ignore it: a Factory reset is now an Inbox command sent from the Devices page. Old settings files
that carry it still parse, and the check still warns (`device_reset_requested`).

| Key | Type | Required / default | Allowed values | Example | Notes |
|---|---|---|---|---|---|
| `id` | string | required in `reset` | 1-64 letters, digits or `-` | `id = "3f1c2a9e-0b7d-4e2a-9c51-6a2f8d0e4b17"` | |
| `requested_at` | string | required in `reset` | a quoted RFC 3339 time (a bare TOML date-time is not accepted) | `requested_at = "2026-10-15T03:04:05Z"` | |

## Issues

Each Issue has a `level`, a stable `code`, an English `message`, a `path` (such as
`config.teachers.apps.web[0].icon`, or none), `params` (the values in the message) and a `span`
(line and column in the text, when known). A parse problem (`toml_syntax`, `unknown_field`,
`missing_field`, `wrong_type`, `invalid_value`, `config_shape_mixed`) stops the check: it is the only Issue until fixed.
Issues marked *server* need the school's state (registered keys, the school's id, the Devices, the
last Version), so only the server's check at `mastersos publish` reports them.

<!-- prompt:omit -->
| Code | Level | About |
|---|---|---|
| `admin_user_invalid` | error | `[school] admin_users` entry |
| `admin_users_too_many` | error | `[school] admin_users` count |
| `admins_without_sso` | warning | Config without `sso` while there are admins |
| `allowed_domain_invalid` | error | `[school] allowed_domains` entry |
| `allowed_domains_too_many` | error | `[school] allowed_domains` count |
| `chrome_pause_invalid` | error | `[config.chrome] pause_until` format |
| `chrome_pause_too_long` | error | `[config.chrome] pause_until` too far |
| `chrome_paused` | info | Chrome updates paused |
| `chrome_window_invalid` | error | `[config.chrome] update_window` |
| `config_duplicate_id` | error | two Configs with one id |
| `config_shape_mixed` | error | `[[config]]` and a `[[group]]` with settings (parse) |
| `config_unused` | info | no Group uses a Config |
| `default_group_missing` | error | no `default` Group |
| `dest_not_absolute` | error | `files` / `downloads` destination |
| `device_duplicate_id` | error | Device listed twice |
| `device_name_duplicate` | error | printer / scanner name repeated |
| `device_no_identity` | error | `[[device]]` without serial or device_id |
| `device_reset_id_invalid` | error | legacy `reset.id` |
| `device_reset_requested` | warning | legacy `reset` present |
| `device_unknown_group` | error | `[[device]]` names a missing Group |
| `download_sha256_invalid` | error | `downloads` checksum |
| `drop_conflict` | error | `drop` names an entry the Config also writes |
| `drop_unknown` | warning | `drop` names an entry the Defaults do not have |
| `escrow_recipient_unregistered` | error (server) | escrow key not bound to trust |
| `escrow_recipients_invalid` | error | `escrow_recipients` format |
| `escrow_recipients_missing` | error (server) | escrow keys dropped or not written |
| `feature_unsupported` | error (server) | Devices too old for a key |
| `feature_unsupported_in_use` | warning (server) | Devices too old, key already in use |
| `few_recovery_keys` | warning (server) | fewer than two Recovery kits in trust |
| `file_missing` | error | file not in the bundle |
| `file_outside_dir` | error | file outside `files/` / `scripts/` |
| `flatpak_id_invalid` | error | `apps.flatpak` entry |
| `flatpak_now_installed` | warning (server) | browser-mode Flatpak apps now installed |
| `format_raised_on_save` | info (server) | a save will write `format = 2` |
| `format_unsupported` | error | `format` newer than the OS reads, or Devices too old for it (*server*) |
| `format_unsupported_in_use` | warning (server) | Devices too old, format already in use |
| `group_duplicate_id` | error | two Groups with one id |
| `group_name_duplicate` | error | two Groups with one name |
| `group_unknown_config` | error | `[[group]]` names a missing Config |
| `icon_invalid` | error | web app or kiosk app icon |
| `invalid_value` | error | value not allowed (parse) |
| `issues_truncated` | info | more than 1000 Issues, the rest not shown |
| `it_account_invalid` | error | `it_account` password hash |
| `kiosk_allow_invalid` | error | kiosk `allow` entry |
| `kiosk_exec_invalid` | error | kiosk `exec` |
| `kiosk_extension_invalid` | error | kiosk `extensions` |
| `kiosk_flatpak_missing` | warning | kiosk Flatpak not installed |
| `kiosk_id_invalid` | error | kiosk app id |
| `kiosk_in_session_only` | error | kiosk app only in sessions |
| `kiosk_launch_invalid` | error | kiosk `url` / `exec` / `pwa` / `android` |
| `kiosk_name_invalid` | error | kiosk `name` |
| `kiosk_no_entry` | warning | kiosk app shown nowhere |
| `kiosk_policy_invalid` | error | kiosk `chrome_policy` value |
| `kiosk_policy_locked` | error | kiosk `chrome_policy` locked key |
| `kiosk_too_many` | error | more than 32 kiosk apps |
| `kiosk_url_not_https` | error | kiosk `url` |
| `kiosk_user_agent` | info | kiosk `user_agent` set |
| `kiosk_user_agent_invalid` | error | kiosk `user_agent` |
| `legacy_shape` | error | Settings in the older shape, without `[[config]]` |
| `locale_invalid` | error | `[school] locale` |
| `lock_message_too_long` | error | `locked.message` |
| `logo_incomplete` | error | only one of `[school] logo_sha256` / `logo_icon_sha256` |
| `logo_sha256_invalid` | error | `[school] logo_sha256` / `logo_icon_sha256` |
| `logo_unknown` | error (server) | `[school] logo_sha256` / `logo_icon_sha256` names no uploaded logo |
| `missing_field` | error | required key missing (parse) |
| `no_admins` | warning | nobody can administer a Config's Devices |
| `oidc_invalid` | error | `[school.oidc]` values |
| `oidc_issuer_google` | error | Google as SSO issuer |
| `path_file_and_dir` | error | bundle file is also a folder |
| `printer_invalid` | error | printer entry |
| `scanner_invalid` | error | scanner entry |
| `school_id_mismatch` | error (server) | `[school] id` wrong or missing |
| `school_name_invalid` | error | `[school] name` |
| `school_wifi_moved` | warning | `[[school.wifi]]` written in a `format = 2` text; use `[defaults] wifi` |
| `script_timeout_too_long` | error | `timeout_secs` over 1800 |
| `sso_without_oidc` | error | `sso` without `[school.oidc]` |
| `timezone_invalid` | error | `[school] timezone` |
| `toml_syntax` | error | not valid TOML (parse) |
| `trust_changed` | warning (server) | trust differs from the last Version |
| `trust_duplicate_id` | error | two trust keys with one id |
| `trust_empty` | error | no trust keys |
| `trust_key_invalid` | error | trust `public_key` |
| `trust_rp_id_forbidden` | error | `rp_id` on an `ed25519` key |
| `trust_rp_id_invalid` | error | Passkey `rp_id` |
| `unknown_field` | error | misspelled or unknown key (parse) |
| `update_channel_unknown` | error | `[school] update_channel` |
| `update_mirror_invalid` | error | `[school] update_mirror` |
| `update_mirror_not_https` | warning | `update_mirror` uses `http://` |
| `web_app_invalid` | error | web app entry |
| `web_app_not_https` | warning | web app uses `http://` |
| `wifi_invalid` | error | Wi-Fi entry |
| `wifi_open_implicit` | warning | Wi-Fi with no `psk`, `eap` or `open` |
| `wifi_server_unchecked` | warning | enterprise Wi-Fi with `check_server = false` |
| `wifi_ssid_duplicate` | error | Wi-Fi name repeated |
| `wrong_type` | error | value of the wrong type (parse) |
<!-- /prompt:omit -->

### `admin_user_invalid`

**Level:** error. **Meaning:** an entry of `[school] admin_users` is not an SSO account name.

<!-- prompt:omit -->
**Why:** the names are written into the Devices' sudo and permission rules; a malformed name would
not match anyone, or (starting with `%` or `+`) would mean a group instead of a person.
<!-- /prompt:omit -->

**How to fix:** write the full account, such as `it.admin@school.ac.th`: letters, digits and
`. _ % + -` before the `@`, not starting with `%` or `+`, at most 254 bytes.

<!-- prompt:omit -->
```toml check=admin_user_invalid
[school]
admin_users = ["it.admin"]

[[config]]
id = "standard"
name = "Standard"
login_methods = ["sso"]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"

[school.oidc]
issuer = "https://sso.school.ac.th"
client_id = "mastersos"
```
<!-- /prompt:omit -->

### `admin_users_too_many`

**Level:** error. **Meaning:** `[school] admin_users` has more than 200 entries.

<!-- prompt:omit -->
**Why:** the sign-in policy on each Device has a size limit; a larger list could not be read and the
Device would treat itself as locked.
<!-- /prompt:omit -->

**How to fix:** keep at most 200 administrators; most schools need a handful. Triggered by any list
of 201 or more names (no example, for length).

### `admins_without_sso`

**Level:** warning. **Meaning:** `[school] admin_users` is not empty, but a Config's `login_methods`
has no `sso`.

<!-- prompt:omit -->
**Why:** administrators sign in with their SSO account, so on that Config's Devices they cannot sign
in at all.
<!-- /prompt:omit -->

**How to fix:** add `"sso"` to the Config's `login_methods` if administrators need to work on those
Devices; otherwise ignore the warning.

<!-- prompt:omit -->
```toml check=admins_without_sso
[school]
admin_users = ["it.admin@school.ac.th"]

[[config]]
id = "standard"
name = "Standard"
login_methods = ["local"]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `allowed_domain_invalid`

**Level:** error. **Meaning:** an entry of `[school] allowed_domains` is not a lowercase domain.

<!-- prompt:omit -->
**Why:** Devices compare the part after `@` exactly; uppercase letters, `@` or other characters
would never match.
<!-- /prompt:omit -->

**How to fix:** write the bare domain in lowercase, such as `school.ac.th` (letters, digits, `.` and
`-`, at most 254 bytes).

<!-- prompt:omit -->
```toml check=allowed_domain_invalid
[school]
allowed_domains = ["@School.ac.th"]

[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `allowed_domains_too_many`

**Level:** error. **Meaning:** `[school] allowed_domains` has more than 200 entries.

<!-- prompt:omit -->
**Why:** as for `admin_users_too_many`, the sign-in policy on each Device has a size limit.
<!-- /prompt:omit -->

**How to fix:** keep at most 200 domains. Triggered by any list of 201 or more domains (no example,
for length).

### `chrome_pause_invalid`

**Level:** error. **Meaning:** `[config.chrome] pause_until` is not a real date in the form
`YYYY-MM-DD`.

<!-- prompt:omit -->
**Why:** Devices cannot tell when the pause ends.
<!-- /prompt:omit -->

**How to fix:** write a date such as `pause_until = 2026-11-10`.

<!-- prompt:omit -->
```toml check=chrome_pause_invalid
[[config]]
id = "standard"
name = "Standard"

[config.chrome]
pause_until = "2026-11-31"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `chrome_pause_too_long`

**Level:** error. **Meaning:** `pause_until` is more than 14 days after the Publish day.

<!-- prompt:omit -->
**Why:** a longer pause would keep Devices on a Chrome with known security holes.
<!-- /prompt:omit -->

**How to fix:** pick a date at most 14 days ahead; to keep pausing, Publish again with a new date
later.

<!-- prompt:omit -->
```toml check=chrome_pause_too_long
[[config]]
id = "standard"
name = "Standard"

[config.chrome]
pause_until = 2027-03-01

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `chrome_paused`

**Level:** info. **Meaning:** a Config pauses Chrome updates until the given day (inclusive). The
Issue names the Config and the Groups that use it.

<!-- prompt:omit -->
**Why:** a reminder, so the pause is not forgotten; Devices without Chrome still install it.
<!-- /prompt:omit -->

**How to fix:** nothing to fix. Remove `pause_until` to end the pause early.

<!-- prompt:omit -->
```toml check=chrome_paused
[[config]]
id = "standard"
name = "Standard"

[config.chrome]
pause_until = 2026-11-10

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `chrome_window_invalid`

**Level:** error. **Meaning:** `[config.chrome] update_window` is not `HH:MM-HH:MM`, its ends are
equal, or it is shorter than 2 hours.

<!-- prompt:omit -->
**Why:** Devices check for Chrome updates once an hour, so a shorter window might never be hit, and
equal ends are ambiguous.
<!-- /prompt:omit -->

**How to fix:** write a window of at least 2 hours in 24-hour time, such as `"16:00-07:00"`
(crossing midnight is fine).

<!-- prompt:omit -->
```toml check=chrome_window_invalid
[[config]]
id = "standard"
name = "Standard"

[config.chrome]
update_window = "16:00-17:00"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `config_duplicate_id`

**Level:** error. **Meaning:** two `[[config]]` entries have the same `id`.

<!-- prompt:omit -->
**Why:** Groups find their Config by id; with two, the Devices could not tell which one applies.
<!-- /prompt:omit -->

**How to fix:** give each Config its own id (the check points at the repeated one), and point each
Group's `config` at the one it should use.

<!-- prompt:omit -->
```toml check=config_duplicate_id
[[config]]
id = "student"
name = "Student"

[[config]]
id = "student"
name = "Student, exams"

[[group]]
id = "default"
name = "Unassigned"
config = "student"
```
<!-- /prompt:omit -->

### `config_shape_mixed`

**Level:** error (parse). **Meaning:** the file has `[[config]]` (or a `[[group]]` with `config`),
yet a `[[group]]` also carries settings such as `apps`, `wifi` or `mode`.

<!-- prompt:omit -->
**Why:** a file is either in the current shape or in the older one (see
[Older settings files](#older-settings-files)); a mix of both cannot be read either way.
<!-- /prompt:omit -->

**How to fix:** move that Group's settings into a `[[config]]` (a new one, or the one it should
share) and keep only `id`, `name` and `config` in the `[[group]]`.

<!-- prompt:omit -->
```toml check=config_shape_mixed
[[config]]
id = "student"
name = "Student"

[[group]]
id = "default"
name = "Unassigned"
config = "student"

[[group]]
id = "library"
name = "Library"
login_methods = ["guest"]
```
<!-- /prompt:omit -->

### `config_unused`

**Level:** info. **Meaning:** no Group names this Config.

<!-- prompt:omit -->
**Why:** a reminder: a Config applies to no Device until a Group uses it. Writing a Config first and
attaching it later is fine.
<!-- /prompt:omit -->

**How to fix:** nothing to fix. Set a Group's `config` to it when it should be used, or delete it.

<!-- prompt:omit -->
```toml check=config_unused
[[config]]
id = "student"
name = "Student"

[[config]]
id = "exam"
name = "Exam week"
login_methods = ["guest"]

[[group]]
id = "default"
name = "Unassigned"
config = "student"
```
<!-- /prompt:omit -->

### `default_group_missing`

**Level:** error. **Meaning:** no Group has `id = "default"`.

<!-- prompt:omit -->
**Why:** new Devices and Devices without an assignment use the `default` Group; without it they
would have no settings.
<!-- /prompt:omit -->

**How to fix:** add a `[[group]]` with `id = "default"` (or rename one Group's id to `default`).

<!-- prompt:omit -->
```toml check=default_group_missing
[[config]]
id = "teachers"
name = "Teacher Devices"

[[group]]
id = "teachers"
name = "Teacher Devices"
config = "teachers"
```
<!-- /prompt:omit -->

### `dest_not_absolute`

**Level:** error. **Meaning:** the `dest` of a `files` or `downloads` entry does not start with `/`.

<!-- prompt:omit -->
**Why:** Devices place files only at absolute paths.
<!-- /prompt:omit -->

**How to fix:** write the full path, such as `/var/lib/school/wallpaper.jpg`.

<!-- prompt:omit -->
```toml check=dest_not_absolute files=files/wallpaper.jpg
[[config]]
id = "standard"
name = "Standard"
files = [{ src = "files/wallpaper.jpg", dest = "var/lib/school/wallpaper.jpg" }]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `device_duplicate_id`

**Level:** error. **Meaning:** the same `serial` or `device_id` appears in two `[[device]]` entries
(compared ignoring case and surrounding spaces).

<!-- prompt:omit -->
**Why:** a Device must have one Group.
<!-- /prompt:omit -->

**How to fix:** keep one entry per Device.

<!-- prompt:omit -->
```toml check=device_duplicate_id
[[config]]
id = "standard"
name = "Standard"

[[config]]
id = "teachers"
name = "Teacher Devices"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"

[[group]]
id = "teachers"
name = "Teacher Devices"
config = "teachers"

[[device]]
serial = "7HX2KQ3"
group = "teachers"

[[device]]
serial = "7hx2kq3"
group = "default"
```
<!-- /prompt:omit -->

### `device_name_duplicate`

**Level:** error. **Meaning:** two printers in a Config have the same queue name (after replacing
spaces and `/ \ ? ' " # @` with `_`, ignoring case), or two scanners have the same name.

<!-- prompt:omit -->
**Why:** the second one would replace the first on the Device.
<!-- /prompt:omit -->

**How to fix:** give each printer or scanner a distinct name.

<!-- prompt:omit -->
```toml check=device_name_duplicate
[[config]]
id = "standard"
name = "Standard"
printers = [
  { name = "Library Printer", uri = "ipp://10.0.0.5/ipp/print" },
  { name = "Library printer", uri = "ipp://10.0.0.7/ipp/print" },
]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `device_no_identity`

**Level:** error. **Meaning:** a `[[device]]` entry has neither `serial` nor `device_id` (or only
blank ones).

<!-- prompt:omit -->
**Why:** no Device could match it.
<!-- /prompt:omit -->

**How to fix:** add the Device's serial number or its device id from the Devices page.

<!-- prompt:omit -->
```toml check=device_no_identity
[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"

[[device]]
group = "default"
```
<!-- /prompt:omit -->

### `device_reset_id_invalid`

**Level:** error. **Meaning:** the legacy `[device.reset] id` is not 1-64 letters, digits or `-`.

<!-- prompt:omit -->
**Why:** older Devices could not record such an id.
<!-- /prompt:omit -->

**How to fix:** remove `reset`: current Devices ignore it; send a Factory reset from the Devices
page instead.

<!-- prompt:omit -->
```toml check=device_reset_id_invalid
[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"

[[device]]
serial = "9JK4LM2"
group = "default"
reset = { id = "reset me please", requested_at = "2026-10-15T03:04:05Z" }
```
<!-- /prompt:omit -->

### `device_reset_requested`

**Level:** warning. **Meaning:** a `[[device]]` entry carries the legacy `reset` request. The
message says the key is legacy and ignored: current Devices do not factory-reset because of it.

<!-- prompt:omit -->
**Why:** kept so old settings files still parse.
<!-- /prompt:omit -->

**How to fix:** remove `reset`, and use the Devices page to send a Factory reset.

<!-- prompt:omit -->
```toml check=device_reset_requested
[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"

[[device]]
serial = "9JK4LM2"
group = "default"
reset = { id = "3f1c2a9e-0b7d-4e2a-9c51-6a2f8d0e4b17", requested_at = "2026-10-15T03:04:05Z" }
```
<!-- /prompt:omit -->

### `device_unknown_group`

**Level:** error. **Meaning:** a `[[device]]` entry's `group` is not the id of any Group.

<!-- prompt:omit -->
**Why:** the Device would not know which settings to apply.
<!-- /prompt:omit -->

**How to fix:** use an existing Group id, or add the Group.

<!-- prompt:omit -->
```toml check=device_unknown_group
[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"

[[device]]
serial = "7HX2KQ3"
group = "grade-3-cart"
```
<!-- /prompt:omit -->

### `download_sha256_invalid`

**Level:** error. **Meaning:** a `downloads` entry's `sha256` is not 64 lowercase hex digits.

<!-- prompt:omit -->
**Why:** Devices check every download against it; a malformed value can never match.
<!-- /prompt:omit -->

**How to fix:** compute the file's SHA-256 (for example `sha256sum file`) and paste it in lowercase.

<!-- prompt:omit -->
```toml check=download_sha256_invalid
[[config]]
id = "standard"
name = "Standard"

[[config.downloads]]
url = "https://downloads.school.ac.th/exam-browser.tar.gz"
sha256 = "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"
dest = "/var/lib/school/exam-browser.tar.gz"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `drop_conflict`

**Level:** error. **Meaning:** a Config names an entry in `drop` that it also writes in its own list (for example `drop.apps.flatpak` and `apps.flatpak` both name `org.gimp.GIMP`).

<!-- prompt:omit -->
**Why:** the Config would both remove and add the same entry, and it is unclear which was meant.
<!-- /prompt:omit -->

**How to fix:** keep the name in only one place: remove it from `drop` to use the Config's own entry, or from the Config's own list to leave the inherited one out. The Issue's `config`, `collection` and `name` params say which.

<!-- prompt:omit -->
```toml check=drop_conflict
format = 2

[defaults]
apps.flatpak = ["org.gimp.GIMP"]

[[config]]
id = "standard"
name = "Standard"
apps.flatpak = ["org.gimp.GIMP"]
drop.apps.flatpak = ["org.gimp.GIMP"]
[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `drop_unknown`

**Level:** warning. **Meaning:** a Config names an entry in `drop` that `[defaults]` (or the school's legacy Wi-Fi) does not have, so the drop does nothing.

<!-- prompt:omit -->
**Why:** the Defaults may have been renamed since; it is only a warning so that the settings can still be published.
<!-- /prompt:omit -->

**How to fix:** check the name against the Defaults' collection (an `ssid`, a `name`, an app id, a `dest`, a script `path` or a policy name, see [`[config.drop]`](#configdrop)), or remove the entry. The Issue's `config`, `collection` and `name` params say which.

<!-- prompt:omit -->
```toml check=drop_unknown
format = 2

[defaults]
printers = [{ name = "Library", uri = "ipp://lib.school.ac.th/ipp/print" }]

[[config]]
id = "standard"
name = "Standard"
drop.printers = ["Nope"]
[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `escrow_recipient_unregistered`

**Level:** error (server). **Meaning:** a key in `[school] escrow_recipients` is not registered with
a binding signature of a Recovery kit key in this trust.

<!-- prompt:omit -->
**Why:** Devices would encrypt their disk recovery keys to a key the school never proved it holds.
<!-- /prompt:omit -->

**How to fix:** register the recipient with the Recovery kit it belongs to (signing page, or
`mastersos-sign register --kit`), or remove it. Needs the school's registered keys, so there is no
standalone example.

### `escrow_recipients_invalid`

**Level:** error. **Meaning:** `[school] escrow_recipients` has an entry that is not an age X25519
public key in canonical form, an entry listed twice, or more than 8 entries.

<!-- prompt:omit -->
**Why:** Devices encrypt their recovery key to every entry and compare the list exactly.
<!-- /prompt:omit -->

**How to fix:** let the signing page write this key; if editing, paste each `age1…` key exactly as
given, once.

<!-- prompt:omit -->
```toml check=escrow_recipients_invalid
[school]
escrow_recipients = ["age1notarealrecipient"]

[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `escrow_recipients_missing`

**Level:** error (server). **Meaning:** `[school] escrow_recipients` is empty while the last Version
had recipients, or while the school registered recipients for the Recovery kits in this trust.

<!-- prompt:omit -->
**Why:** Devices would stop sending (or never send) their disk recovery keys, so a forgotten disk
password could not be recovered.
<!-- /prompt:omit -->

**How to fix:** put the recipients back (the signing page writes them). Needs the school's state, so
there is no standalone example.

### `feature_unsupported`

**Level:** error (server). **Meaning:** the settings use a key that was added later
(`update_mirror`, `escrow_recipients`, `[school] id`, kiosk apps, `[[config]]` itself: every file
with Configs counts as using it, `wifi_ext`: any `[[school.wifi]]`, or a Wi-Fi entry writing `open`,
`wpa3_only` (either value), `eap` or an enterprise key, or `oidc_card`: `client_secret` or
`card_hosts` in `[school.oidc]`), and some Devices seen in the last 30 days have not reported that
they understand it.

<!-- prompt:omit -->
**Why:** a Device whose OS predates a key rejects the whole Version.
<!-- /prompt:omit -->

**How to fix:** the message names the Devices (serial number, else the start of the device id), the
OS image each last reported, and the oldest OS image of this school known to understand the key.
Update them to that image or newer; or take them out of use and wait until they have been silent for
30 days (the message gives the date). The console's version carries the `devices`, `device_list`,
`more`, `until` and `supported_in` params. Needs the Device reports, so there is no standalone example.

### `feature_unsupported_in_use`

**Level:** warning (server). **Meaning:** as `feature_unsupported`, but the last Version already
uses the key.

<!-- prompt:omit -->
**Why:** those Devices already reject the current Version; publishing again changes nothing for
them, so it is not blocked.
<!-- /prompt:omit -->

**How to fix:** update those Devices' OS (named as for `feature_unsupported`). Needs the Device
reports, so there is no standalone example.

### `few_recovery_keys`

**Level:** warning (server). **Meaning:** trust has fewer than two registered Recovery kit keys.

<!-- prompt:omit -->
**Why:** only a Recovery kit can change trust; if the only one is lost, trust can never change again
(everyday Publish with a Passkey still works).
<!-- /prompt:omit -->

**How to fix:** register a second Recovery kit and keep it in a separate place. Needs the registered
keys, so there is no standalone example.

### `file_missing`

**Level:** error. **Meaning:** a `files` `src` or `scripts` `path` names a file that is not in the
settings bundle.

<!-- prompt:omit -->
**Why:** Devices would have nothing to place or run.
<!-- /prompt:omit -->

**How to fix:** put the file under `files/` in the directory, or correct the path (it is case-sensitive).

<!-- prompt:omit -->
```toml check=file_missing
[[config]]
id = "standard"
name = "Standard"
files = [{ src = "files/wallpaper.jpg", dest = "/var/lib/school/wallpaper.jpg" }]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `file_outside_dir`

**Level:** error. **Meaning:** a `files` `src` does not start with `files/`, or a `scripts` `path`
does not start with `scripts/`.

<!-- prompt:omit -->
**Why:** bundle files live in those two folders.
<!-- /prompt:omit -->

**How to fix:** move the file into the right folder and write the path with it.

<!-- prompt:omit -->
```toml check=file_outside_dir files=files/setup-classroom.sh
[[config]]
id = "standard"
name = "Standard"
scripts = [{ path = "files/setup-classroom.sh" }]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `flatpak_id_invalid`

**Level:** error. **Meaning:** an `apps.flatpak` entry is not a Flatpak app id.

<!-- prompt:omit -->
**Why:** Devices install by id from Flathub.
<!-- /prompt:omit -->

**How to fix:** use the id from the app's Flathub page, such as `org.libreoffice.LibreOffice` (at
least three dot-separated parts).

<!-- prompt:omit -->
```toml check=flatpak_id_invalid
[[config]]
id = "standard"
name = "Standard"
interface = "full"

[config.apps]
flatpak = ["libreoffice"]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `flatpak_now_installed`

**Level:** warning (server). **Meaning:** a Group was in the old browser mode in the last Version
(written before Configs existed), where Flatpak apps were never installed, and now uses a Config
that lists `apps.flatpak`. After this Version its Devices install those apps and show them in the
Dock. The Issue names the Config and the Groups.

<!-- prompt:omit -->
**Why:** converting an older settings file keeps every setting, so apps once listed but never
installed start to appear on student Devices; this makes that visible before signing.
<!-- /prompt:omit -->

**How to fix:** nothing to fix if the apps are wanted (`learning` installs them on purpose).
Otherwise remove them from that Config's `apps.flatpak`. Needs the last Version, so there is no
standalone example.

### `format_raised_on_save`

**Level:** info (server, the console's live check only). **Meaning:** the text leaves `format` out
but uses a key that needs format 2 (param `key`: `[defaults]`, `drop`, `it_account`, ...).

<!-- prompt:omit -->
**Why:** the server writes the lowest `format` a text needs on every save, so a missing line is not an
error; what matters is which Devices read format 2.
<!-- /prompt:omit -->

**How to fix:** nothing to fix: saving writes `format = 2` as the first line. The rest of the text is
checked as it will be saved, so a `format_unsupported` next to it names the Devices that would then
refuse new Versions.

### `format_unsupported`

**Level:** error. **Meaning:** the `format` is newer than this version of the settings code reads, or, from the console (*server*), Devices seen in the last 30 days do not read the format the text needs.

<!-- prompt:omit -->
**Why:** a Device whose OS reads an older format does not apply the Version at all, so they would all stay on the previous settings.
<!-- /prompt:omit -->

**How to fix:** for a `format` newer than 2, put back the value the server wrote. When Devices are too old, the console names them and the OS image each last reported: update them to an image that reads the format (the message says when no Device of the school runs one yet), or take them out of use and wait until they have been silent for 30 days (the message gives the date); texts that need only format 1 publish as before. The console's version of this Issue carries `found`, `devices`, `device_list`, `more`, `until` and `supported_in` params.

<!-- prompt:omit -->
```toml check=format_unsupported
format = 3
[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `format_unsupported_in_use`

**Level:** warning (server). **Meaning:** like `format_unsupported`, but the latest published Version already uses that format, so those Devices already reject the current Version.

<!-- prompt:omit -->
**Why:** publishing another Version in the same format changes nothing for them, so it is not blocked.
<!-- /prompt:omit -->

**How to fix:** update the OS of the Devices named by the console; until then they keep their last accepted settings.

### `group_duplicate_id`

**Level:** error. **Meaning:** two `[[group]]` entries have the same `id`.

<!-- prompt:omit -->
**Why:** Devices and `[[device]]` entries find their Group by id.
<!-- /prompt:omit -->

**How to fix:** give each Group its own id (the check points at the repeated one).

<!-- prompt:omit -->
```toml check=group_duplicate_id
[[config]]
id = "standard"
name = "Standard"

[[config]]
id = "teachers"
name = "Teacher Devices"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"

[[group]]
id = "teachers"
name = "Teacher Devices"
config = "teachers"

[[group]]
id = "teachers"
name = "Teacher laptops, second floor"
config = "teachers"
```
<!-- /prompt:omit -->

### `group_name_duplicate`

**Level:** error. **Meaning:** two `[[group]]` entries have the same `name` (ignoring case and
surrounding spaces).

<!-- prompt:omit -->
**Why:** the console lists Groups by name wherever one is picked (moving Devices, seeds, filters);
two with the same name cannot be told apart.
<!-- /prompt:omit -->

**How to fix:** rename one of them (the check points at the second one and names the first).

<!-- prompt:omit -->
```toml check=group_name_duplicate
[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Teachers"
config = "standard"

[[group]]
id = "teachers2"
name = "teachers"
config = "standard"
```
<!-- /prompt:omit -->

### `group_unknown_config`

**Level:** error. **Meaning:** a `[[group]]` entry's `config` is not the id of any Config.

<!-- prompt:omit -->
**Why:** the Group's Devices would not know which settings to apply.
<!-- /prompt:omit -->

**How to fix:** use an existing Config id, or add the Config.

<!-- prompt:omit -->
```toml check=group_unknown_config
[[config]]
id = "student"
name = "Student"

[[group]]
id = "default"
name = "Unassigned"
config = "students"
```
<!-- /prompt:omit -->

### `icon_invalid`

**Level:** error. **Meaning:** a web app's or kiosk app's `icon` is neither a `files/…` file in the
bundle nor an `https://` link.

<!-- prompt:omit -->
**Why:** Devices could not find the icon.
<!-- /prompt:omit -->

**How to fix:** put the image under `files/` in the directory and write `files/<name>`, or use an `https://`
link; or remove `icon` for the generic icon.

<!-- prompt:omit -->
```toml check=icon_invalid
[[config]]
id = "standard"
name = "Standard"

[[config.apps.web]]
name = "Khan Academy"
url = "https://www.khanacademy.org/"
icon = "files/khan-academy.png"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `invalid_value`

**Level:** error (parse). **Meaning:** a value has the right type but is not one of the accepted
values: an unknown `interface`, `when`, `alg` or login method, a malformed `[school] id`, an empty
`escrow_recipients = []`, or a `requested_at` string that is not RFC 3339.

<!-- prompt:omit -->
**Why:** the settings cannot be read.
<!-- /prompt:omit -->

**How to fix:** use a value listed for that key in this reference.

<!-- prompt:omit -->
```toml check=invalid_value
[[config]]
id = "standard"
name = "Standard"
interface = "tablet"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `issues_truncated`

**Level:** info. **Meaning:** the check found more than 1000 Issues; only the first 1000 are listed,
in their usual order, and this note (with `shown` and `total`) ends the list.

<!-- prompt:omit -->
**Why:** a list that long cannot be read anyway, and keeping it short keeps the check fast for
everyone. Whether the text can be published still counts every Issue, shown or not.
<!-- /prompt:omit -->

**How to fix:** fix the Issues shown (usually one mistake repeated, such as many `[[device]]`
entries naming a missing Group) and check again. Triggered only by more than 1000 Issues (no
example, for length).

### `it_account_invalid`

**Level:** error. **Meaning:** the `password_hash` of an `it_account` (in `[defaults]` or a Config; the `layer` param says which) is not a yescrypt (`$y$…`) or SHA-512 (`$6$rounds=500000$…`) crypt hash of at most 256 characters.

<!-- prompt:omit -->
**Why:** a Device would refuse the hash and have no usable IT account. The message never repeats the hash.
<!-- /prompt:omit -->

**How to fix:** ask IT to run `mastersos hash-password` again and put the new hash in `secrets.toml`; do not edit the hash by hand.

<!-- prompt:omit -->
```toml check=it_account_invalid
format = 2

[defaults]
it_account = { password_hash = "$1$abc" }

[[config]]
id = "standard"
name = "Standard"
[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `kiosk_allow_invalid`

**Level:** error. **Meaning:** an entry of a kiosk app's `allow` is not a plain host name.

<!-- prompt:omit -->
**Why:** the list becomes the session's address allowlist; wildcards, schemes, paths or single
labels would allow too much or nothing.
<!-- /prompt:omit -->

**How to fix:** write host names such as `nwea.org` (a host already includes its subdomains, so no
`*`).

<!-- prompt:omit -->
```toml check=kiosk_allow_invalid
[[config]]
id = "standard"
name = "Standard"

[config.apps.kiosk.nwea-map]
name = "NWEA MAP Growth"
url = "https://test.mapnwea.org/"
allow = ["*.mapnwea.org"]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `kiosk_exec_invalid`

**Level:** error. **Meaning:** a kiosk app's `exec` is neither a Flatpak app id nor an absolute path
under `/usr/`.

<!-- prompt:omit -->
**Why:** kiosk apps start one known program; arguments and shell commands are not accepted.
<!-- /prompt:omit -->

**How to fix:** use a Flatpak id (and list it in `apps.flatpak`) or a program path under `/usr/`,
without arguments.

<!-- prompt:omit -->
```toml check=kiosk_exec_invalid
[[config]]
id = "standard"
name = "Standard"

[config.apps.kiosk.exam-client]
name = "Exam client"
exec = "/opt/exam/start.sh"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `kiosk_extension_invalid`

**Level:** error. **Meaning:** a kiosk app's `extensions` entry has an id that is not 32 letters
`a`-`p`, repeats an id, names the MastersOS exam extension, has an `update_url` that is not
`https://` with a host, or has a `config` that cannot be converted to JSON (such as a date).

<!-- prompt:omit -->
**Why:** the session's Chrome could not install it as written.
<!-- /prompt:omit -->

**How to fix:** copy the id from the extension's Chrome Web Store page, list it once, and use an
`https://` update URL.

<!-- prompt:omit -->
```toml check=kiosk_extension_invalid
[[config]]
id = "standard"
name = "Standard"

[config.apps.kiosk.reading-test]
name = "Reading test"
url = "https://reading.example.org/"
extensions = [{ id = "reader-helper", update_url = "https://clients2.google.com/service/update2/crx" }]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `kiosk_flatpak_missing`

**Level:** warning. **Meaning:** a kiosk app's `exec` is a Flatpak id that is not in the Config's
`apps.flatpak`.

<!-- prompt:omit -->
**Why:** Devices install only listed Flatpak apps, so the kiosk app could not start.
<!-- /prompt:omit -->

**How to fix:** add the id to the same Config's `apps.flatpak` (both Modes install the listed apps).

<!-- prompt:omit -->
```toml check=kiosk_flatpak_missing
[[config]]
id = "standard"
name = "Standard"

[config.apps.kiosk.geogebra]
name = "GeoGebra"
exec = "org.geogebra.GeoGebra"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `kiosk_id_invalid`

**Level:** error. **Meaning:** a kiosk app id (the `<id>` in `[config.apps.kiosk.<id>]`) does not
start with a lowercase letter, has characters other than lowercase letters, digits and `-`, or is
longer than 24 characters.

<!-- prompt:omit -->
**Why:** the id names a system account on the Device.
<!-- /prompt:omit -->

**How to fix:** rename the app id, such as `nwea-map`.

<!-- prompt:omit -->
```toml check=kiosk_id_invalid
[[config]]
id = "standard"
name = "Standard"

[config.apps.kiosk.NWEA_MAP]
name = "NWEA MAP Growth"
url = "https://test.mapnwea.org/"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `kiosk_in_session_only`

**Level:** error. **Meaning:** a kiosk app has `in_session = true` and `login_screen = false`.

<!-- prompt:omit -->
**Why:** starting a kiosk app from a session ends the session and returns to the login screen, where
the app must be chosen; without `login_screen` it is not there.
<!-- /prompt:omit -->

**How to fix:** set `login_screen = true` (or leave it out; it defaults to `true`).

<!-- prompt:omit -->
```toml check=kiosk_in_session_only
[[config]]
id = "standard"
name = "Standard"

[config.apps.kiosk.nwea-map]
name = "NWEA MAP Growth"
url = "https://test.mapnwea.org/"
in_session = true
login_screen = false

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `kiosk_launch_invalid`

**Level:** error. **Meaning:** a kiosk app has both `url` and `exec`, neither, `pwa = true` without
`url`, or the reserved `android` key.

<!-- prompt:omit -->
**Why:** the Device must know exactly how to start the app.
<!-- /prompt:omit -->

**How to fix:** write `url` for a web page or PWA, or `exec` for a local program, not both; remove
`android`.

<!-- prompt:omit -->
```toml check=kiosk_launch_invalid
[[config]]
id = "standard"
name = "Standard"

[config.apps.kiosk.geogebra]
name = "GeoGebra"
url = "https://www.geogebra.org/classic"
exec = "org.geogebra.GeoGebra"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `kiosk_name_invalid`

**Level:** error. **Meaning:** a kiosk app's `name` is empty, longer than 64 characters, or contains
`:`, `,` or a control character.

<!-- prompt:omit -->
**Why:** the name becomes the account's display name, where `:` and `,` break it.
<!-- /prompt:omit -->

**How to fix:** shorten the name and drop those characters.

<!-- prompt:omit -->
```toml check=kiosk_name_invalid
[[config]]
id = "standard"
name = "Standard"

[config.apps.kiosk.nwea-map]
name = "NWEA: MAP Growth"
url = "https://test.mapnwea.org/"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `kiosk_no_entry`

**Level:** warning. **Meaning:** a kiosk app has `login_screen = false` and `in_session = false`.

<!-- prompt:omit -->
**Why:** it appears nowhere, so nobody can open it.
<!-- /prompt:omit -->

**How to fix:** set `login_screen = true` (the default), or remove the app.

<!-- prompt:omit -->
```toml check=kiosk_no_entry
[[config]]
id = "standard"
name = "Standard"

[config.apps.kiosk.nwea-map]
name = "NWEA MAP Growth"
url = "https://test.mapnwea.org/"
login_screen = false

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `kiosk_policy_invalid`

**Level:** error. **Meaning:** a kiosk app's `chrome_policy` has a value Chrome policies cannot
hold: a date, or a non-finite number.

<!-- prompt:omit -->
**Why:** the policy is converted to JSON for Chrome.
<!-- /prompt:omit -->

**How to fix:** write dates as strings, or remove the value.

<!-- prompt:omit -->
```toml check=kiosk_policy_invalid
[[config]]
id = "standard"
name = "Standard"

[config.apps.kiosk.reading-test]
name = "Reading test"
url = "https://reading.example.org/"
chrome_policy = { PrintingEnabled = true, ExamDay = 2026-11-10 }

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `kiosk_policy_locked`

**Level:** error. **Meaning:** a kiosk app's `chrome_policy` sets a key the kiosk session locks:
`URLBlocklist`, `URLAllowlist`, `DeveloperToolsAvailability`, `IncognitoModeAvailability`,
`BrowserGuestModeEnabled`, `BrowserAddPersonEnabled`, `BrowserSignin`, `SyncDisabled`,
`DownloadRestrictions`, `AllowFileSelectionDialogs`, `PasswordManagerEnabled`,
`AutofillAddressEnabled`, `AutofillCreditCardEnabled`, `TaskManagerEndProcessEnabled`,
`ScreenCaptureAllowed`, `ExtensionInstallBlocklist`, `DefaultBrowserSettingEnabled`,
`PromotionalTabsEnabled`, `BackgroundModeEnabled`, `ExtensionSettings`, `ExtensionInstallForcelist`,
`WebAppInstallForceList`, `3rdparty`, `ExtensionInstallAllowlist`, `ExtensionInstallSources`,
`ExtensionAllowedTypes`, `ExtensionInstallWhitelist`, `ExtensionInstallBlacklist`, `URLWhitelist`,
`URLBlacklist`, `NativeMessagingBlocklist`, `NativeMessagingAllowlist`,
`NativeMessagingUserLevelHosts`.

<!-- prompt:omit -->
**Why:** these keep the session locked; an app cannot override them.
<!-- /prompt:omit -->

**How to fix:** remove the key. Use `allow` for sites and `extensions` for extensions.

<!-- prompt:omit -->
```toml check=kiosk_policy_locked
[[config]]
id = "standard"
name = "Standard"

[config.apps.kiosk.nwea-map]
name = "NWEA MAP Growth"
url = "https://test.mapnwea.org/"
chrome_policy = { URLAllowlist = ["nwea.org"] }

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `kiosk_too_many`

**Level:** error. **Meaning:** a Config has more than 32 kiosk apps.

<!-- prompt:omit -->
**Why:** each kiosk app takes a system account from a fixed range.
<!-- /prompt:omit -->

**How to fix:** remove some, or split them across Configs.

<!-- prompt:omit -->
```toml check=kiosk_too_many
[[config]]
id = "standard"
name = "Standard"

[config.apps.kiosk]
app01 = { name = "App 01", url = "https://app01.example.org/" }
app02 = { name = "App 02", url = "https://app02.example.org/" }
app03 = { name = "App 03", url = "https://app03.example.org/" }
app04 = { name = "App 04", url = "https://app04.example.org/" }
app05 = { name = "App 05", url = "https://app05.example.org/" }
app06 = { name = "App 06", url = "https://app06.example.org/" }
app07 = { name = "App 07", url = "https://app07.example.org/" }
app08 = { name = "App 08", url = "https://app08.example.org/" }
app09 = { name = "App 09", url = "https://app09.example.org/" }
app10 = { name = "App 10", url = "https://app10.example.org/" }
app11 = { name = "App 11", url = "https://app11.example.org/" }
app12 = { name = "App 12", url = "https://app12.example.org/" }
app13 = { name = "App 13", url = "https://app13.example.org/" }
app14 = { name = "App 14", url = "https://app14.example.org/" }
app15 = { name = "App 15", url = "https://app15.example.org/" }
app16 = { name = "App 16", url = "https://app16.example.org/" }
app17 = { name = "App 17", url = "https://app17.example.org/" }
app18 = { name = "App 18", url = "https://app18.example.org/" }
app19 = { name = "App 19", url = "https://app19.example.org/" }
app20 = { name = "App 20", url = "https://app20.example.org/" }
app21 = { name = "App 21", url = "https://app21.example.org/" }
app22 = { name = "App 22", url = "https://app22.example.org/" }
app23 = { name = "App 23", url = "https://app23.example.org/" }
app24 = { name = "App 24", url = "https://app24.example.org/" }
app25 = { name = "App 25", url = "https://app25.example.org/" }
app26 = { name = "App 26", url = "https://app26.example.org/" }
app27 = { name = "App 27", url = "https://app27.example.org/" }
app28 = { name = "App 28", url = "https://app28.example.org/" }
app29 = { name = "App 29", url = "https://app29.example.org/" }
app30 = { name = "App 30", url = "https://app30.example.org/" }
app31 = { name = "App 31", url = "https://app31.example.org/" }
app32 = { name = "App 32", url = "https://app32.example.org/" }
app33 = { name = "App 33", url = "https://app33.example.org/" }

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `kiosk_url_not_https`

**Level:** error. **Meaning:** a kiosk app's `url` is not an `https://` address with a valid host
name, or contains spaces, quotes, a backslash or credentials.

<!-- prompt:omit -->
**Why:** the session opens only this address and the allowlist is built from its host.
<!-- /prompt:omit -->

**How to fix:** use the `https://` address of the test or app.

<!-- prompt:omit -->
```toml check=kiosk_url_not_https
[[config]]
id = "standard"
name = "Standard"

[config.apps.kiosk.nwea-map]
name = "NWEA MAP Growth"
url = "http://test.mapnwea.org/"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `kiosk_user_agent`

**Level:** info. **Meaning:** a web kiosk app overrides `user_agent`.

<!-- prompt:omit -->
**Why:** a reminder that it only affects sites that detect browsers; exam vendors' secure-client
detection is handled by the exam extension.
<!-- /prompt:omit -->

**How to fix:** nothing to fix; remove `user_agent` unless a site needs it.

<!-- prompt:omit -->
```toml check=kiosk_user_agent
[[config]]
id = "standard"
name = "Standard"

[config.apps.kiosk.reading-test]
name = "Reading test"
url = "https://reading.example.org/"
user_agent = "Mozilla/5.0 (X11; Linux x86_64) ExampleExamClient/1.0"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `kiosk_user_agent_invalid`

**Level:** error. **Meaning:** `user_agent` is set on a local program (`exec`), or is longer than
512 bytes or has control characters.

<!-- prompt:omit -->
**Why:** only Chrome sessions use a user agent.
<!-- /prompt:omit -->

**How to fix:** remove it from `exec` apps; shorten it otherwise.

<!-- prompt:omit -->
```toml check=kiosk_user_agent_invalid
[[config]]
id = "standard"
name = "Standard"
interface = "full"

[config.apps]
flatpak = ["org.geogebra.GeoGebra"]

[config.apps.kiosk.geogebra]
name = "GeoGebra"
exec = "org.geogebra.GeoGebra"
user_agent = "GeoGebraKiosk/1.0"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `legacy_shape`

**Level:** error. **Meaning:** the settings are in the older shape: there is no `[[config]]`, and each
`[[group]]` carries its own settings (and `mode`).

<!-- prompt:omit -->
**Why:** Devices still read Versions published in that shape, but new Versions are written with
Configs, so that several Groups can share one Config and the Mode is `learning` or `full`.
<!-- /prompt:omit -->

**How to fix:** move each Group's settings into a `[[config]]` with the same id and name, write
`interface = "full"` where it had `mode = "desktop"` (otherwise `interface = "learning"`), and keep
only `id`, `name` and `config = "<that id>"` in the `[[group]]`. See
[Older settings files](#older-settings-files).

<!-- prompt:omit -->
```toml check=legacy_shape
[[group]]
id = "default"
name = "Unassigned"
mode = "desktop"
login_methods = ["guest"]
```
<!-- /prompt:omit -->

### `locale_invalid`

**Level:** error. **Meaning:** `[school] locale` is not of the form `xx_YY.UTF-8`.

<!-- prompt:omit -->
**Why:** Devices could not set the language.
<!-- /prompt:omit -->

**How to fix:** use one of `th_TH.UTF-8`, `en_US.UTF-8`, `en_GB.UTF-8`, `zh_CN.UTF-8`.

<!-- prompt:omit -->
```toml check=locale_invalid
[school]
locale = "Thai"

[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `lock_message_too_long`

**Level:** error. **Meaning:** a `[device.locked]` `message` is longer than 500 characters.

<!-- prompt:omit -->
**Why:** the login screen shows it in a banner.
<!-- /prompt:omit -->

**How to fix:** shorten it, for example to who to contact.

<!-- prompt:omit -->
```toml check=lock_message_too_long
[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"

[[device]]
serial = "9JK4LM2"
group = "default"
locked = { message = "This Device was reported lost. Please bring it to the IT office in Building A. This Device was reported lost. Please bring it to the IT office in Building A. This Device was reported lost. Please bring it to the IT office in Building A. This Device was reported lost. Please bring it to the IT office in Building A. This Device was reported lost. Please bring it to the IT office in Building A. This Device was reported lost. Please bring it to the IT office in Building A. This Device was reported lost. Please bring it to the IT office in Building A." }
```
<!-- /prompt:omit -->

### `logo_incomplete`

**Level:** error. **Meaning:** `[school]` has one of `logo_sha256` (the sign-in screen logo) and `logo_icon_sha256` (the quick menu icon) but not the other.

<!-- prompt:omit -->
**Why:** `mastersos logo upload` uploads the two images together and prints both keys; one alone comes from a hand edit, and Devices would show the logo in one place but not the other.
<!-- /prompt:omit -->

**How to fix:** ask IT to run `mastersos logo upload` again and paste both lines; or remove the remaining key.

<!-- prompt:omit -->
```toml check=logo_incomplete
format = 2

[school]
logo_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[[config]]
id = "standard"
name = "Standard"
[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `logo_sha256_invalid`

**Level:** error. **Meaning:** `[school] logo_sha256` or `logo_icon_sha256` is not 64 lowercase hex digits.

<!-- prompt:omit -->
**Why:** Devices download the logo and show it only when its SHA-256 matches, so a malformed value can never match.
<!-- /prompt:omit -->

**How to fix:** do not write it by hand: ask IT to run `mastersos logo upload` and paste its output; or remove the key.

<!-- prompt:omit -->
```toml check=logo_sha256_invalid
format = 2

[school]
logo_sha256 = "ABC"
logo_icon_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[[config]]
id = "standard"
name = "Standard"
[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `logo_unknown`

**Level:** error (server). **Meaning:** `[school] logo_sha256` or `logo_icon_sha256` is well formed, but this school has no uploaded logo image with that SHA-256.

<!-- prompt:omit -->
**Why:** Devices download the logo from the school's server and show it only when its SHA-256 matches; a value that was written by hand or pasted from another school would name a logo the server cannot give.
<!-- /prompt:omit -->

**How to fix:** ask IT to run `mastersos logo upload` and paste its output; or remove the key. Needs the school's stored logos, so there is no standalone example.

### `missing_field`

**Level:** error (parse). **Meaning:** a required key is missing, such as a Config's `name`, a
`[[device]]` entry's `group`, or a Wi-Fi network's `ssid`.

<!-- prompt:omit -->
**Why:** the settings cannot be read without it.
<!-- /prompt:omit -->

**How to fix:** add the key named in the message, in the table the message points at.

<!-- prompt:omit -->
```toml check=missing_field
[[config]]
id = "standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `no_admins`

**Level:** warning. **Meaning:** the Config has no `it_account` (its own or the Defaults'),
`[school] admin_users` has no valid entry and the Config's `local_users_admin` is `false`.

<!-- prompt:omit -->
**Why:** nobody can use sudo or unlock system settings on that Config's Devices; managed Devices have
no hidden administrator account.
<!-- /prompt:omit -->

**How to fix:** ask IT to set up the IT account (a `secret:` reference for `password_hash`, the hash in `secrets.toml`), or add IT staff to
`admin_users` (with `sso` in the Config's `login_methods`), or accept it if intended.

<!-- prompt:omit -->
```toml check=no_admins
[[config]]
id = "standard"
name = "Standard"
login_methods = ["guest"]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `oidc_invalid`

**Level:** error. **Meaning:** `[school.oidc]` `issuer` does not start with `http://` or `https://`,
or `issuer` or `client_id` is empty or contains spaces, control characters or any of ``# ; " ' `
\``; or `client_secret` or `card_hosts` breaks the limits in the [`[school.oidc]`](#schooloidc) table.

<!-- prompt:omit -->
**Why:** these values are written into the Devices' sign-in configuration.
<!-- /prompt:omit -->

**How to fix:** copy the issuer URL, client id and client secret exactly from the SSO provider, and
write each `card_hosts` entry as a bare hostname.

<!-- prompt:omit -->
```toml check=oidc_invalid
[school.oidc]
issuer = "sso.school.ac.th"
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
<!-- /prompt:omit -->

### `oidc_issuer_google`

**Level:** error. **Meaning:** the SSO issuer is `accounts.google.com`.

<!-- prompt:omit -->
**Why:** Devices do not sign in with Google accounts. Schools on Google Workspace issue Device
accounts with Kanidm (with Dex) or Zitadel. Signing in to Google inside Chrome is unaffected.
<!-- /prompt:omit -->

**How to fix:** set `issuer` to the school's own OIDC provider.

<!-- prompt:omit -->
```toml check=oidc_issuer_google
[school.oidc]
issuer = "https://accounts.google.com"
client_id = "1234567890-example.apps.googleusercontent.com"

[[config]]
id = "standard"
name = "Standard"
login_methods = ["sso"]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `path_file_and_dir`

**Level:** error. **Meaning:** one file in the settings bundle has the same path as a folder of
another (such as `files/fonts` and `files/fonts/thai.ttf`).

<!-- prompt:omit -->
**Why:** Devices could not unpack both.
<!-- /prompt:omit -->

**How to fix:** rename one of them.

<!-- prompt:omit -->
```toml check=path_file_and_dir files=files/fonts,files/fonts/thai.ttf
[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `printer_invalid`

**Level:** error. **Meaning:** a printer's `uri` does not start with `ipp://`, `ipps://`, `http://`
or `https://`, contains spaces or credentials, or its `name` is empty, longer than 64 characters or
has control characters.

<!-- prompt:omit -->
**Why:** the Device could not add the printer.
<!-- /prompt:omit -->

**How to fix:** use the printer's IPP address, such as `ipp://10.0.0.5/ipp/print`, without a user
name or password.

<!-- prompt:omit -->
```toml check=printer_invalid
[[config]]
id = "standard"
name = "Standard"
printers = [{ name = "Library Printer", uri = "lpd://10.0.0.5/queue" }]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `scanner_invalid`

**Level:** error. **Meaning:** a scanner's `uri` does not start with `http://` or `https://`,
contains spaces or credentials, or its `name` is empty, longer than 64 characters or has control
characters.

<!-- prompt:omit -->
**Why:** the Device could not add the scanner.
<!-- /prompt:omit -->

**How to fix:** use the scanner's eSCL address, such as `http://10.0.0.6/eSCL`.

<!-- prompt:omit -->
```toml check=scanner_invalid
[[config]]
id = "standard"
name = "Standard"
scanners = [{ name = "Office Scanner", uri = "ipp://10.0.0.6/eSCL" }]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `school_id_mismatch`

**Level:** error (server). **Meaning:** `[school] id` is missing or is not this school's id.

<!-- prompt:omit -->
**Why:** Devices accept only settings naming their own school.
<!-- /prompt:omit -->

**How to fix:** write the id the message gives under `[school]` (`init` and `pull` already write it; do not
change it). Needs the school's id, so there is no standalone example.

### `school_name_invalid`

**Level:** error. **Meaning:** `[school] name` is empty, longer than 100 characters, or holds line breaks or other control characters.

<!-- prompt:omit -->
**Why:** Devices show it as "Managed by …" on the login screen.
<!-- /prompt:omit -->

**How to fix:** do not write it by hand: `mastersos publish` writes it; or remove the key.

<!-- prompt:omit -->
```toml check=school_name_invalid
format = 2

[school]
name = ""

[[config]]
id = "standard"
name = "Standard"
[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `school_wifi_moved`

**Level:** warning. **Meaning:** `[[school.wifi]]` is written in a `format = 2` text. Wi-Fi for every Config now belongs in `[defaults] wifi`. A format-1 text gets no warning: while Wi-Fi is the only thing that would need format 2, the console keeps it under `[school]` so that older Devices can still read the text.

<!-- prompt:omit -->
**Why:** the old place keeps working (its networks come before the Defaults' ones), so this is only a nudge; one place for shared settings is easier to read.
<!-- /prompt:omit -->

**How to fix:** move the networks into `[[defaults.wifi]]` (move them by hand) and delete `[[school.wifi]]`.

<!-- prompt:omit -->
```toml check=school_wifi_moved
format = 2

[[school.wifi]]
ssid = "School-Students"
open = true

[[config]]
id = "standard"
name = "Standard"
[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `script_timeout_too_long`

**Level:** error. **Meaning:** a script's `timeout_secs` is more than 1800 (30 minutes).

<!-- prompt:omit -->
**Why:** a stuck script could delay the Device's next settings update that long.
<!-- /prompt:omit -->

**How to fix:** lower `timeout_secs`, or move long work into a download.

<!-- prompt:omit -->
```toml check=script_timeout_too_long files=scripts/setup-classroom.sh
[[config]]
id = "standard"
name = "Standard"
scripts = [{ path = "scripts/setup-classroom.sh", timeout_secs = 3600 }]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `secret_rerouted`

**Level:** warning; `mastersos publish` refuses it. **Meaning:** a secret value goes where the pulled Version did not send it: another layer, `ssid`, secret field, `eap`, `phase2`, `identity`, `anonymous_identity`, `server_domain`, `ca_cert` or `check_server`, or a new network. Compared by value, so renaming a reference changes nothing; a new password on the same network is fine.

<!-- prompt:omit -->
**Why:** these fields decide where the secret is sent; pointing a saved password at a different network or server would hand it over.
<!-- /prompt:omit -->

**How to fix:** undo the change, or give the network a new secret. If it is intended, only IT approves it after `mastersos diff`: `mastersos publish --allow-reroute <name>` once per secret. An AI never passes that flag.

### `secret_unknown`

**Level:** error. **Meaning:** a Wi-Fi or IT account secret field refers to `secret:<name>` but `secrets.toml` has no `<name>`.

<!-- prompt:omit -->
**Why:** without the value the settings cannot be published.
<!-- /prompt:omit -->

**How to fix:** ask IT to add `<name>` to `secrets.toml`. Do not write the value into `manifest.toml`.

### `secret_unused`

**Level:** warning. **Meaning:** `secrets.toml` has a name that no setting refers to.

<!-- prompt:omit -->
**Why:** an unused secret is a leftover that is still kept on disk.
<!-- /prompt:omit -->

**How to fix:** remove the name from `secrets.toml`.

### `sso_without_oidc`

**Level:** error. **Meaning:** a Config allows `sso` but there is no `[school.oidc]`.

<!-- prompt:omit -->
**Why:** there is nowhere to sign in.
<!-- /prompt:omit -->

**How to fix:** add `[school.oidc]` (the MastersOS operator gives the issuer and client ID), or
remove `"sso"` from the Config's `login_methods`.

<!-- prompt:omit -->
```toml check=sso_without_oidc
[[config]]
id = "standard"
name = "Standard"
login_methods = ["sso"]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `timezone_invalid`

**Level:** error. **Meaning:** `[school] timezone` is not a time zone name.

<!-- prompt:omit -->
**Why:** Devices could not set it.
<!-- /prompt:omit -->

**How to fix:** use an IANA name such as `Asia/Bangkok`.

<!-- prompt:omit -->
```toml check=timezone_invalid
[school]
timezone = "Bangkok time"

[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `toml_syntax`

**Level:** error (parse). **Meaning:** the text is not valid TOML at the given line: a missing
quote, bracket or `=`, a repeated key, or a value written without quotes.

<!-- prompt:omit -->
**Why:** nothing can be read until it is valid.
<!-- /prompt:omit -->

**How to fix:** look at the reported line; string values need double quotes on both sides.

<!-- prompt:omit -->
```toml check=toml_syntax
[[config]]
id = "standard"
name = "Standard

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `trust_changed`

**Level:** warning (server). **Meaning:** this Version adds, removes or changes trust keys compared
with the last Version.

<!-- prompt:omit -->
**Why:** whoever holds a trusted key controls every Device.
<!-- /prompt:omit -->

**How to fix:** check each key's fingerprint on the Keys page before signing; a trust change must be
signed with a Recovery kit. Needs the last Version, so there is no standalone example.

### `trust_duplicate_id`

**Level:** error. **Meaning:** two trust keys have the same `id`.

<!-- prompt:omit -->
**Why:** signatures name the key by id.
<!-- /prompt:omit -->

**How to fix:** let the Keys page rewrite trust, or give each key its own id.

<!-- prompt:omit -->
```toml check=trust_duplicate_id
[[trust]]
id = "recovery-2026"
alg = "ed25519"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

[[trust]]
id = "recovery-2026"
alg = "ed25519"
public_key = "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio="

[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `trust_empty`

**Level:** error. **Meaning:** trust has no keys.

<!-- prompt:omit -->
**Why:** Devices would accept no signature, and the first Version needs a Recovery kit key.
<!-- /prompt:omit -->

**How to fix:** add the school's keys from the Keys page (at least one Recovery kit key; an IT Passkey
is optional).

<!-- prompt:omit -->
```toml check=trust_empty
trust = []

[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `trust_key_invalid`

**Level:** error. **Meaning:** a trust key's `public_key` is not standard base64 of the right size:
32 bytes for `ed25519`, 65 bytes starting with `0x04` for `webauthn-es256`.

<!-- prompt:omit -->
**Why:** no signature could be checked with it.
<!-- /prompt:omit -->

**How to fix:** let the Keys page rewrite trust; register the Passkey again if needed.

<!-- prompt:omit -->
```toml check=trust_key_invalid
[[trust]]
id = "recovery-2026"
alg = "ed25519"
public_key = "AAAA"

[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `trust_rp_id_forbidden`

**Level:** error. **Meaning:** an `ed25519` (Recovery kit) key has an `rp_id`.

<!-- prompt:omit -->
**Why:** only Passkeys belong to a site.
<!-- /prompt:omit -->

**How to fix:** remove `rp_id` from that key.

<!-- prompt:omit -->
```toml check=trust_rp_id_forbidden
[[trust]]
id = "recovery-2026"
alg = "ed25519"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
rp_id = "sign.os.khundavid.com"

[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `trust_rp_id_invalid`

**Level:** error. **Meaning:** a `webauthn-es256` (Passkey) key has no `rp_id`, or it is not a bare
lowercase host name.

<!-- prompt:omit -->
**Why:** Devices check that the Passkey signature came from that site.
<!-- /prompt:omit -->

**How to fix:** let the Keys page rewrite trust; the value is a host such as
`sign.os.khundavid.com`, without `https://`.

<!-- prompt:omit -->
```toml check=trust_rp_id_invalid
[[trust]]
id = "recovery-2026"
alg = "ed25519"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

[[trust]]
id = "it-passkey"
alg = "webauthn-es256"
public_key = "BCoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio="
rp_id = "https://sign.os.khundavid.com"

[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `unknown_field`

**Level:** error (parse). **Meaning:** a key is not part of the settings at that place: a typo, a
key in the wrong table, or a key from a newer reference.

<!-- prompt:omit -->
**Why:** Devices reject settings with unknown keys, so a typo is never silently ignored.
<!-- /prompt:omit -->

**How to fix:** check the spelling and the table against this reference.

<!-- prompt:omit -->
```toml check=unknown_field
[school]
update_chanel = "stable"

[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `update_channel_unknown`

**Level:** error. **Meaning:** `[school] update_channel` is not `stable` or `beta`.

<!-- prompt:omit -->
**Why:** Devices would fall back to `stable` and report a failure.
<!-- /prompt:omit -->

**How to fix:** use `"stable"` or `"beta"`.

<!-- prompt:omit -->
```toml check=update_channel_unknown
[school]
update_channel = "nightly"

[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `update_mirror_invalid`

**Level:** error. **Meaning:** `[school] update_mirror` is not an `http://` or `https://` address
with a host and optional folder, or it contains a query, fragment, credentials, `%`, `@`, `..`,
spaces or non-ASCII characters.

<!-- prompt:omit -->
**Why:** the address is written into the Devices' update configuration.
<!-- /prompt:omit -->

**How to fix:** write something like `https://cache.school.ac.th/mastersos`.

<!-- prompt:omit -->
```toml check=update_mirror_invalid
[school]
update_mirror = "ftp://cache.school.ac.th/mastersos"

[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `update_mirror_not_https`

**Level:** warning. **Meaning:** `[school] update_mirror` uses `http://`.

<!-- prompt:omit -->
**Why:** allowed, since updates are signed and cannot be altered, but `https://` is better where the
cache supports it.
<!-- /prompt:omit -->

**How to fix:** switch to `https://` if possible.

<!-- prompt:omit -->
```toml check=update_mirror_not_https
[school]
update_mirror = "http://cache.school.ac.th/mastersos"

[[config]]
id = "standard"
name = "Standard"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `web_app_invalid`

**Level:** error. **Meaning:** a web app's `url` does not start with `http://` or `https://` or
contains spaces or any of ``" ' ` \``, or its `name` is empty or has control characters.

<!-- prompt:omit -->
**Why:** the launcher could not be created.
<!-- /prompt:omit -->

**How to fix:** write the full address including `https://`.

<!-- prompt:omit -->
```toml check=web_app_invalid
[[config]]
id = "standard"
name = "Standard"

[[config.apps.web]]
name = "Khan Academy"
url = "www.khanacademy.org"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `web_app_not_https`

**Level:** warning. **Meaning:** a web app's `url` uses `http://`.

<!-- prompt:omit -->
**Why:** the connection is not encrypted.
<!-- /prompt:omit -->

**How to fix:** use the `https://` address if the site has one.

<!-- prompt:omit -->
```toml check=web_app_not_https
[[config]]
id = "standard"
name = "Standard"

[[config.apps.web]]
name = "Library catalogue"
url = "http://library.school.ac.th/"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `wifi_invalid`

**Level:** error. **Meaning:** a Wi-Fi network's keys are not valid or do not fit together: the
`ssid` is empty or longer than 32 bytes; the `psk` is not 8-63 printable ASCII characters or 64 hex
digits; `open` is `false` or written with `psk` or `eap`; `psk` and `eap` are both written;
`wpa3_only` has no `psk`; an enterprise key has no `eap`; an `eap` network lacks `identity`, its
`password` (or, for `tls`, `client_cert` and `client_key`), writes a key its method does not allow
(`server_domain`, `ca_cert` or `check_server` with `pwd`), or checks no server (no `server_domain`
or `ca_cert`, and no `check_server = false`; `pwd` excepted). The message
names the network and the key, never a password or key.

<!-- prompt:omit -->
**Why:** the Device could not join the network, or (without a server check) would give the account
password to any hotspot using the name.
<!-- /prompt:omit -->

**How to fix:** correct the key the message names; see [`[[config.wifi]]`](#configwifi) for which
keys each kind of network takes.

<!-- prompt:omit -->
```toml check=wifi_invalid
[[config]]
id = "standard"
name = "Standard"
wifi = [{ ssid = "School-Staff", psk = "short" }]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

```toml check=wifi_invalid
[[config]]
id = "staff"
name = "Staff"

[[config.wifi]]
ssid = "School-Secure"
eap = "peap"
identity = "devices@school.ac.th"
password = "example-password-not-real"

[[group]]
id = "default"
name = "Unassigned"
config = "staff"
```
<!-- /prompt:omit -->

### `wifi_open_implicit`

**Level:** warning. **Meaning:** a Wi-Fi network has none of `psk`, `eap` and `open`. Devices join it
as an open network.

<!-- prompt:omit -->
**Why:** older settings wrote open networks this way, so it still means open; but a new entry like
this is usually a forgotten password.
<!-- /prompt:omit -->

**How to fix:** write `open = true` if the network is open, otherwise add its `psk` (or `eap` and
the account keys). Writing `open = true` needs every Device to support the newer Wi-Fi settings
(feature `wifi_ext`, see `feature_unsupported`) before the Version can be published.

<!-- prompt:omit -->
```toml check=wifi_open_implicit
[[config]]
id = "standard"
name = "Standard"
wifi = [{ ssid = "School-Guest" }]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `wifi_server_unchecked`

**Level:** warning. **Meaning:** an enterprise Wi-Fi network writes `check_server = false`: Devices
connect without checking the RADIUS server.

<!-- prompt:omit -->
**Why:** a nearby hotspot with the same name can pose as the network and capture the account and
password the Devices send.
<!-- /prompt:omit -->

**How to fix:** remove `check_server = false` and write `server_domain` (the domain on the RADIUS
server's certificate) or `ca_cert`.

<!-- prompt:omit -->
```toml check=wifi_server_unchecked
[[config]]
id = "staff"
name = "Staff"

[[config.wifi]]
ssid = "School-Secure"
eap = "peap"
identity = "devices@school.ac.th"
password = "example-password-not-real"
check_server = false

[[group]]
id = "default"
name = "Unassigned"
config = "staff"
```
<!-- /prompt:omit -->

### `wifi_ssid_duplicate`

**Level:** error. **Meaning:** the same Wi-Fi name appears twice in one Config, or twice in
`[[school.wifi]]` (a Config entry with a school entry's name is not a repeat: it replaces it).

<!-- prompt:omit -->
**Why:** a Device keeps one connection per name.
<!-- /prompt:omit -->

**How to fix:** keep one entry per network.

<!-- prompt:omit -->
```toml check=wifi_ssid_duplicate
[[config]]
id = "standard"
name = "Standard"
wifi = [
  { ssid = "School-Staff", psk = "secret:school-staff" },
  { ssid = "School-Staff", psk = "another-example-password" },
]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

### `wrong_type`

**Level:** error (parse). **Meaning:** a value has the wrong type: text where a boolean, number,
list or table is expected, or the other way round.

<!-- prompt:omit -->
**Why:** the settings cannot be read.
<!-- /prompt:omit -->

**How to fix:** use the type this reference gives: `true`/`false` without quotes for booleans,
`[...]` for lists, quotes for text.

<!-- prompt:omit -->
```toml check=wrong_type
[[config]]
id = "standard"
name = "Standard"
local_users_admin = "yes"

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```
<!-- /prompt:omit -->

## Recipes

Each recipe shows the part of the settings file to add or change. Keep the rest of your `manifest.toml` as it
is.

### Add a web app

Add a `[[config.apps.web]]` block under the Config (after its `[[config]]` header, before the next
header that is not `[config.…]` or `[[config.…]]`). Put the icon under `files/` in the directory first, or use an `https://` link, or leave `icon` out.

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

### Turn on SSO

Add `[school.oidc]` with the issuer URL and client id from your SSO provider, add `"sso"` to each
Config that should allow school accounts, and optionally limit sign-in to your domains.

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

### Add an administrator

Add the person's SSO account to `[school] admin_users`. They are administrators on every Device whose
Config allows `sso`.

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

### Set up Wi-Fi

For a network every Device should join, write it under `[defaults]` (`[[defaults.wifi]]`).
For a network with a password, write a `secret:` reference (`psk = "secret:school-staff"`) and ask IT to add the
password to `secrets.toml`; never write the password itself. Open networks need nothing more.
Every Config inherits it. Do not add or change the `format` line by hand: a
setup whose Defaults hold only Wi-Fi stays `format = 1` (the networks sit under `[school] wifi`). For only one Config's Devices, write the network in that
Config. Write `open = true` for an open network.

```toml check=ok
[[config]]
id = "standard"
name = "Standard"
wifi = [
  { ssid = "School-Staff", psk = "secret:school-staff" },
  { ssid = "School-Guest", open = true },
]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"
```

### Add a kiosk app

Add `[config.apps.kiosk.<id>]` under the Config with a `name` and the test's `url`. List the sites the
test needs in `allow` (subdomains are included). Students start it from the login screen.

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

### Pause Chrome updates

Set `pause_until` in the Config's `[config.chrome]` to a day at most 14 days after you Publish (for
example the last exam day). Remove it to end the pause early.

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

### Share one Config between Groups

Write the Config once and point each Group's `config` at it. A change to the Config then reaches
every Group that uses it.

```toml check=ok
[[config]]
id = "student"
name = "Student"
login_methods = ["guest"]
wifi = [{ ssid = "School-Students", psk = "secret:school-staff" }]

[[group]]
id = "cart-g3"
name = "Grade 3 cart"
config = "student"

[[group]]
id = "cart-g4"
name = "Grade 4 cart"
config = "student"

[[group]]
id = "default"
name = "Unassigned"
config = "student"
```

### Put Devices in a Group

Add one `[[device]]` entry per Device with its serial number (from `mastersos devices list`) and
the Group id, then Publish. To move a Device, change its `group`.

```toml check=ok
[[config]]
id = "standard"
name = "Standard"

[[config]]
id = "student"
name = "Student"
login_methods = ["guest"]

[[group]]
id = "default"
name = "Unassigned"
config = "standard"

[[group]]
id = "grade-3-cart"
name = "Grade 3 cart"
config = "student"

[[device]]
serial = "7HX2KQ3"
group = "grade-3-cart"

[[device]]
serial = "5BN8TR1"
group = "grade-3-cart"
```

## Glossary

| Term | Meaning |
|---|---|
| Device | A MastersOS laptop managed by the school (not "machine", "laptop" or "computer"). |
| Config | What a Device looks like: its Mode, sign-in, Wi-Fi, apps, Chrome and so on (`[[config]]`). Several Groups can share one Config. |
| Group | A set of Devices that use the same Config (`[[group]]`). |
| Mode | What a session offers, set per Config by `interface`: Learning or Full (Create is coming soon). |
| Learning | The Mode for students: Chrome, web apps, kiosk apps and the Config's Flatpak apps, without system access (`interface = "learning"`). |
| Full | The Mode for teachers and staff: the full desktop (`interface = "full"`). |
| Settings | What Devices are told to do: the settings file (`manifest.toml`) and the files that come with it. The TOML key names stay as written in this reference. |
| Local directory | The settings on IT's computer (`manifest.toml`, `files/`, `secrets.toml`), edited and checked before Publish. It may have errors. |
| Publish | Turning the directory into a new, signed Version that Devices download (`mastersos publish`). |
| Version | One published state of the settings, numbered upward. |
| Issue | A finding of the check, with a level: error (blocks Publish), warning, or info. |
| Signing key | A key that can sign a Version: a Passkey or a Recovery kit key. |
| Passkey | A signing key kept on IT's phone or security key, used for everyday Publish. |
| Recovery kit | An offline signing key, needed for the first Version and for any change to trust. |
| Trust | The list of signing keys Devices accept (`[[trust]]`). |
| Lock | Blocking a lost or stolen Device: only administrators can sign in (`[device.locked]`). |
| Factory reset | Erasing a Device's data so it starts fresh with the school's settings; sent from the Devices page as an Inbox command. |
| Inbox command | A one-time command sent to one Device from the console, outside the settings. |
| Defaults | What every Config starts from (`[defaults]`); a Config's written values replace the Defaults' ones, its list entries are added. |

<!-- prompt:omit -->
## FAQ

### Why not YAML?

The settings stay TOML.
YAML guesses types (`no` becomes false, `0755` becomes an octal number), lets indentation decide
the structure (one space less and a network hangs under another Config), can be written in many
ways, which suits signing exact bytes badly, and its parsers have a long record of security bugs.
Changing the format would also mean rewriting the parser, the signing, the documents, the AI skill
and the Device side.
<!-- /prompt:omit -->
