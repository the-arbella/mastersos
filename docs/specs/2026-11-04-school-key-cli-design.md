# Design: the school key, plain words, and the CLI on macOS, Linux and Windows

Status: approved by the owner 2026-11-04 (from a clickable mockup). Companion: the private cloud repo has the web
side (`docs/specs/2026-11-04-it-guided-onboarding-design.md`); this document does not depend on it.

## 1. Why

The owner built the tool and still could not follow the signing flow. IT staff will understand it even less. Three
causes:

- **Too many words for few things.** "Recovery kit", "recovery package", "recovery key", "trust", "escrow
  recipient", "digest", "heartbeat", "seed", "pending" all reach IT.
- **A copy-and-paste step that matters most.** IT copies a `[[trust]]` text from the signing page into
  `manifest.toml` without knowing what it is.
- **Unclear where things are.** IT is told to "download once and move to a USB stick", but not the file name, nor
  how to match a file to what the server lists.

Also, the CLI only works on macOS and Linux today (config under `$HOME/.config`, Unix-only permission checks, CI
builds only on Ubuntu, no installers). IT uses Windows too.

## 2. Goals, non-goals, anti-goals

Goals
- IT can set up a school and change settings by following numbered steps, without knowing the cryptography.
- One required key type: the **school key** (today's recovery kit). One flag for it everywhere.
- Every command says in plain words what it did and **where** it put things.
- First-class macOS, Linux and Windows: same commands, platform-correct paths, owner-only files, installers.
- All user-facing text is English (UI translations live in the web app; the CLI is English only).

Non-goals
- No change to the signing rules machines enforce (chain, R1g, recovery-kit-only trust changes, heartbeat
  format). Wire formats, `MASTERSKIT1` encoding and key derivation stay as they are.
- Removing WebAuthn (passkey) verification from `mastersos-bundle`/the agent: later, separately. Nothing new will
  produce passkey signatures (§6).

Anti-goals
- A flow that only works if IT reads the glossary.
- Hiding where a secret lives ("magic" key storage, OS keychains): IT must always be able to point at the file.

## 3. Vocabulary (user-facing)

Code identifiers keep their names (`kit`, `trust`, `heartbeat`, `seed`); only what IT reads changes.

| Old (any of) | New | One-line explanation shown to IT |
|---|---|---|
| recovery kit, recovery package, recovery key, kit | **school key** | A small file (plus a printed copy) that approves settings for every computer and can unlock their disks. |
| fingerprint / key id, as shown to IT | **key code** | `11d9-03eb`: the first 8 hex digits of the key id, grouped 4-4. Printed on the paper copy, in the file name, and on the School keys page. Full fingerprints still appear wherever trust changes are reviewed. |
| digest, first 8 characters | **check code** | `a1b2c3d4`: printed by `mastersos publish` and shown on the approve page; equal means "this is what you uploaded". |
| heartbeat, heartbeat renewal | **monthly check-in** | Tells every computer "nothing new; what you have is current". |
| seed | **install file** | Goes on the installation USB stick so a new computer knows its school. |
| escrow recipient, escrow | (not shown) | When unavoidable: "disk unlocking" / "recovery code" for a machine's LUKS recovery key. |
| trust, `[[trust]]` | **trusted keys** | Only in `manifest.toml` comments and review screens. |
| pending | **upload** / "waiting for approval" | |

`docs/glossary.md` is updated to this table (English term, Chinese term for the web UI: 学校钥匙、钥匙码、核对码、
每月确认、装机文件).

## 4. CLI changes (`mastersos`)

### 4.1 One flag: `--school-key <FILE>`
- On `init`, `publish`, `keys add` (below). `--kit` stays as a hidden alias (old scripts and docs); `--key`
  (PKCS#8) stays hidden for compatibility and is no longer documented.
- `<FILE>` may be on a USB stick (exFAT/FAT32 have no permissions), see §5.3.

### 4.2 `mastersos connect <SERVER URL>` (new; `setup` stays unchanged for scripts, and is hidden from help)
- Asks "Paste the token from the Command line page:" without echo (or reads one line from stdin when not a
  terminal), calls `whoami`, refuses `ai:` tokens and tokens without `read`+`draft`, then writes the token file and
  `config.toml` owner-only (§5) and prints:
  `Connected to <school name>.` / `Token saved in <absolute path>` / `Settings saved in <absolute path>`.
- Never takes the token as an argument.

### 4.3 `mastersos init <DIR> --school-key <FILE> [--school-key <FILE>…]`
- Reads each school key locally, derives its trusted key (`rk-…`, Ed25519 public key) and its disk-unlocking
  recipient (age), and writes them into the new `manifest.toml` as `[[trust]]` and `[school].escrow_recipients`.
  **No copy and paste**; trust comes only from files IT holds, never from the server.
- Before writing, checks with `GET /v1/admin/signing-keys` and `GET /v1/admin/escrow-recipients` that each key and
  recipient is registered for this school; if not: "This school key (11d9-03eb) is not registered for <school>.
  Make keys on the signing page first." (Upload would refuse later anyway; this fails early with a clear message.)
- `--school-key` is required for `init` (a school with no key cannot publish v1). Without it: an error that says
  where to make one.
- Prints the folder's absolute path, the two files and their purpose, and `Trusted keys: 11d9-03eb, 7c42-a915`.

### 4.4 `mastersos publish [--school-key <FILE>]`
- Unchanged checks, upload and signing. Output in this order, plain words:
  `Checked: no problems` / `Check code: a1b2c3d4` / then either `Published version N`, or, without
  `--school-key`, `Waiting for approval: open <link>` and `Compare the check code on that page with a1b2c3d4.`
- **With `--school-key`, publish also signs a 30-day heartbeat** for the version it just published (the same
  statement `mastersos-sign heartbeat` signs; `POST /v1/admin/heartbeat/prepare` + `commit`), **silently**: the
  heartbeat is never mentioned on success (owner, 2026-11-04: IT should not need the concept). A heartbeat failure
  does not undo the publish and prints only: `Computers may soon show "settings may be out of date". Open the admin
  site to fix it.`

### 4.5 No heartbeat command in `mastersos`
- The monthly check-in for a school that has not published in a while is done on the admin site (a reminder on the
  home page, then the signing page with the school key file). `mastersos` has no `check-in` command and its help
  does not mention heartbeats; `mastersos-sign heartbeat` stays for advanced use and is not in IT's guide.

### 4.6 `mastersos keys add <FILE>` and `mastersos keys remove <KEY CODE>`
- Edit the local `manifest.toml`: add the trusted key and disk-unlocking recipient derived from a school key file
  (registered check as in §4.3), or remove the ones with that key code. They change nothing on the server; IT then
  runs `mastersos publish --school-key <a key already trusted>`. Machines accept the change only if signed by a
  school key in the current trust (unchanged rule).
- Refuse to remove the last trusted school key.
- After a published removal, the server-side registration is retired from the admin site (cloud's concern); the
  machines rotate their disk recovery code by themselves when the recipients change.
- `mastersos keys list` shows key code, label, registered date (server data) and whether each is in the local
  folder's trusted keys.

### 4.7 Output and help
- All help, prompts, errors and output in English (`mastersos-sign` too: its Chinese help and prompts are
  translated).
- Every path printed absolute and in the platform's native form (`C:\Users\…`, `/Users/…`).

### 4.8 `mastersos-sign`
- Keeps its commands for signing on another computer (`sign --pending`), `heartbeat`, `seed-check`, `escrow-read`,
  `register`, `kit new`. Adds `--school-key` with `--kit` as alias. `keygen` and `restore-from-paper` are hidden
  from help (kept for old PKCS#8 keys).
- `kit new` writes `<slug>-school-key-<keycode8>.kit` when `--out` is a directory.

## 5. macOS, Linux and Windows

### 5.1 Where things live
| | macOS, Linux | Windows |
|---|---|---|
| `mastersos` config, token, pins | `$XDG_CONFIG_HOME/mastersos/` else `~/.config/mastersos/` (unchanged) | `%APPDATA%\mastersos\` |
| `mastersos-sign` pins | `~/.config/mastersos-sign/` (unchanged) | `%APPDATA%\mastersos-sign\` |
| installed binaries | `~/.local/bin/` | `%LOCALAPPDATA%\Programs\mastersos\` (added to the user `PATH`) |

No `HOME` on Windows must not be an error. `--pin-dir`, `--token-file` keep overriding.

### 5.2 Owner-only files
- Unix: unchanged (create 0600, refuse a token file or `secrets.toml` readable by group/others).
- Windows: create with a DACL that grants only the current user (and SYSTEM/Administrators as the OS requires);
  on read, refuse a token file whose DACL grants read to `Everyone`, `Users` or `Authenticated Users`. The builder
  picks the crate (`windows-sys` preferred over a new high-level dependency).

### 5.3 School key files on removable media
Today a kit file must be mode 0600, which a USB stick formatted exFAT/FAT32 cannot express (macOS shows 0777).
Ruling (owner-approved direction "keep it on a USB stick"): **for school key files, broad permissions are a warning,
not a refusal**, worded as an instruction (owner's wording, 2026-11-04): `Make sure no other user can read this
school key file. Keep it on a USB stick whenever you can.` Token files and `secrets.toml` stay strict.

### 5.4 Paths in settings folders
`manifest.toml`/`secrets.toml` content never contains local paths. Folder handling (`.mastersos/base`, symlink
refusal) must hold on NTFS: on Windows, refuse reparse points where Unix refuses symlinks.

### 5.5 Release and install
- CI builds `mastersos` and `mastersos-sign` for `aarch64-apple-darwin`, `x86_64-apple-darwin`,
  `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-pc-windows-msvc`, and publishes them with
  SHA-256 sums on a GitHub release of this repo. Releases are tagged by commit (`cli-<short sha>`) so a
  deployment can pin the exact CLI that matches its server; `install.sh`/`install.ps1` take an optional version and
  default to the newest release.
- `install.sh` (macOS, Linux) and `install.ps1` (Windows): download the right binary for the machine, check its
  SHA-256 against the release's sums file, install to §5.1, and say where. No administrator rights.
- macOS binaries are not notarized in this phase (`curl` downloads carry no quarantine flag); a `.pkg` or Homebrew
  tap can come later.

### 5.6 Tests
- The `mastersos-mcp`, `mastersos-sign` and `mastersos-bundle` test suites run on Windows and macOS in CI
  (GitHub-hosted runners); Linux keeps running where it runs today.
- New tests: config dir per platform; Windows DACL write and refusal; a key file with 0777 warns but works;
  `init --school-key` writes trust equal to the kit's derivation; `publish --school-key` signs a heartbeat and says nothing about it;
  `connect` refuses `ai:` tokens; `keys remove` refuses the last key.

## 6. Passkeys

Passkeys are dropped from IT's flow (owner decision): they lock signing to one device, which is the opposite of
"take the key anywhere", and they added a second path to explain. This repo: CLI text no longer mentions passkeys;
`mastersos-bundle` keeps verifying `webauthn-es256` (no school in production has one; removal later).

## 7. Approaches considered

1. **Plain words + derive trust from the key file (chosen).** Removes the paste step, makes trust come only from
   files IT holds (stronger than today), small code change.
2. Keep the paste step, only rename words. Cheaper, but leaves the most error-prone step.
3. Server writes trust for IT. Easiest for IT, but lets a compromised server choose the keys machines trust;
   rejected.

## 8. Left to the builder
- Crate choices for Windows ACLs and config dirs (prefer no new dependency where std suffices).
- Exact English sentences, as long as they follow §3 and say where things are.
- Whether `keys add` also accepts a key code plus public key for a key whose file is elsewhere (not required).
