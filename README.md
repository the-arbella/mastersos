# mastersos

[English](README.en.md)

教育笔记本系统：不可变的 Ubuntu 镜像，加上设备端的设置 agent、安装器和签名工具。设备上只应用学校钥匙批准过的设置包。
管理这些设备的云服务不开源，这里没有它的代码。

`core/` 是 Rust workspace：

- `mastersos-bundle`：设置包的清单、打包、签名与验签（Ed25519；旧的 WebAuthn 签名只验不产）、每月确认（心跳）、发布前 lint。
- `mastersos-agent`：机器上拉取、验签、应用设置的服务；另有恢复密钥托管与 TPM 槽（`luks`）、Chrome sysext（`mastersos-agent chrome`）、开机快速应用（`apply-local`）。
- `mastersos-cli`: the `mastersos` command line (the only one). Settings are edited in a local directory; the command line pulls, checks, diffs and publishes, makes and registers school keys, verifies the published versions, renews the monthly check-in and reads a computer's disk recovery code. An AI assistant only edits files and cannot publish.
- `mastersos-installer`：U 盘安装器（tty 上的纯文本流程）与未受管机器的首次开机建用户（`mastersos-firstrun`）。

系统镜像在 `image/`（mkosi），见 `image/README.md`；给 IT 的装机说明在 `image/docs/install.md`。

## Getting started for school IT (macOS, Linux, Windows)

You need the address of your school's admin site, an admin account there, and a USB stick. The words used below
are explained in [docs/glossary.md](docs/glossary.md).

### 1. Install the command line

The installers put `mastersos` in your own user folder: no administrator rights, no `sudo`.
They check the download against the release's `SHA256SUMS` before installing anything, and print where they
installed.

**macOS and Linux** (Terminal):

```bash
curl -fsSL https://raw.githubusercontent.com/the-arbella/mastersos/master/tools/install/install.sh | sh
```

This installs into `~/.local/bin`. If that folder is not on your `PATH` yet, the installer prints the line to add;
then open a new terminal. A given release: `… | sh -s -- --version cli-0123456789ab`.

**Windows** (PowerShell, not as administrator):

```powershell
irm https://raw.githubusercontent.com/the-arbella/mastersos/master/tools/install/install.ps1 | iex
```

This installs into `%LOCALAPPDATA%\Programs\mastersos` and adds that folder to your user `PATH`; open a new
PowerShell window afterwards. A given release:
`& ([scriptblock]::Create((irm https://raw.githubusercontent.com/the-arbella/mastersos/master/tools/install/install.ps1))) -Version cli-0123456789ab`.

Check it with `mastersos --version`. Releases are tagged `cli-<commit>`; without a version the installers take the
newest one. macOS builds are not notarized yet; installed this way they run without a warning.

### 2. Connect to your school

On the admin site, open the **Command line** page and create a token. Then:

```bash
mastersos connect https://<your school's admin address>
```

Paste the token when asked (it is not shown, and never goes on the command line). `connect` checks it and prints
where it saved it:

| | macOS, Linux | Windows |
|---|---|---|
| token and settings (`config.toml`) | `~/.config/mastersos/` | `%APPDATA%\mastersos\` |
| what `mastersos` has verified of each server's versions (`--pin-dir`) | `~/.config/mastersos/pins/` | `%APPDATA%\mastersos\pins\` |

Only your user account can read these files.

### 3. Make two school keys

A **school key** is a small file, plus a printed copy, that approves settings for every computer and can unlock
their disks. Make two on the command line with `mastersos key new --out <folder> --school <name>`, register each with `mastersos key register --key-file <file> --label <text>` (it uses the token from `mastersos connect`), and save each file to a USB stick. The file name ends in
the key's **key code**, for example `myschool-school-key-11d903eb.kit`; the same code (`11d9-03eb`) is on the printed
copy and on the **School keys** page. Keep the printed copies and the second stick in separate safe places.

A USB stick formatted exFAT or FAT32 cannot keep the file private. `mastersos` then says: `Make sure no other user
can read this school key file. Keep it on a USB stick whenever you can.` Do that, and it works.

### 4. Start the settings folder

For a school that has published nothing yet, give both school keys:

```bash
# macOS
mastersos init ./school --key-file /Volumes/USB/myschool-school-key-11d903eb.kit --key-file /Volumes/USB2/myschool-school-key-7c42a915.kit
# Linux
mastersos init ./school --key-file /media/$USER/USB/myschool-school-key-11d903eb.kit --key-file /media/$USER/USB2/myschool-school-key-7c42a915.kit
```

```powershell
# Windows
mastersos init .\school --key-file E:\myschool-school-key-11d903eb.kit --key-file F:\myschool-school-key-7c42a915.kit
```

`init` prints the folder's full path and `Trusted keys: 11d9-03eb, 7c42-a915`: computers will accept settings
approved with either key. For a school that has published before, use `mastersos pull ./school` instead.

### 5. Change, check, publish

Edit `school/manifest.toml` (or let an AI assistant do it, see `skills/mastersos-admin/`), then:

```bash
mastersos check ./school      # on this computer, no network
mastersos diff ./school       # what changes since the last pull
mastersos publish ./school --key-file <school key file>
```

`publish` prints `Checked: no problems`, the **check code** (`Check code: a1b2c3d4`) and `Published version N`.
`publish` needs the school key file: without `--key-file` it stops before uploading anything and says so. Afterwards
run `mastersos pull ./school`.

Computers want a **monthly check-in** ("nothing new; what you have is current"). `publish --key-file` does it for
you; if you have not published for a while, the admin site reminds you. Publish again with `mastersos publish --key-file <file>`, or run `mastersos heartbeat --key-file <file>`.

### 6. Add or remove a school key

```bash
cd ./school                               # or add --dir ./school to key list, key add and key remove (the only commands that take --dir)
mastersos key list                        # key code, label, registered date, trusted here or not
mastersos key add <new school key file>   # make it with mastersos key new, register it with mastersos key register first
mastersos key remove 11d9-03eb            # never the last one
mastersos publish --key-file <a school key that is already trusted>
```

`key add` and `key remove` change only the local `manifest.toml`; computers take the change once you publish it.

### 7. Firewall

Computers upload diagnostics and help-request attachments straight to storage, not through the admin site. If your
network filters outbound traffic, allow the upload domain shown on the admin site's **Install** page.

## 测试

```bash
cd core && cargo fmt --check
cd core && cargo clippy --workspace --all-targets -- -D warnings
cd core && cargo test --workspace
```

工具链是 Rust 1.98（`core/rust-toolchain.toml`）。CI 见 `.github/workflows/mastersos.yml`。`image-lint` 对 `image/` 跑 shellcheck、`tests/check-tree.sh` 与几个不碰 VM 的脚本测试。

## The command line: editing settings in a local directory

The steps for IT (install, connect, school keys, the first version, publish) are in **Getting started for school IT**
above; the vocabulary is in `docs/glossary.md`. This section is implementation detail.

The server keeps no draft: IT pulls the published version into a local directory, a person or an AI assistant edits
`manifest.toml` there, checks and diffs it locally, and IT publishes.

```bash
mastersos connect https://server.example/org/<organisation>/devices     # paste the token from the Command line page: not echoed, checked, then saved with the address
mastersos init ./school --key-file <school key file> [--key-file <second key>]   # a new school; for one that has published, use pull
mastersos pull ./school          # download the latest published version, verified version by version, unpacked into a directory
$EDITOR ./school/manifest.toml   # or let an AI assistant do it; a new Wi-Fi password is psk = "secret:<name>", the value goes in secrets.toml
mastersos check ./school && mastersos diff ./school     # local, no network; check exits 2 on errors
mastersos publish ./school --key-file <school key file> # verify on this computer, approve and publish; also renews the monthly check-in
mastersos publish ./school       # without --key-file: refused, nothing is uploaded
```

The directory holds `mastersos.toml` (the school's host and `base_version`), `manifest.toml` (secrets only as references),
`secrets.toml` (readable only by its owner, ignored by git, the secret values), `files/` and `.mastersos/base/` (what was
pulled, byte for byte, used by `diff`). The base is an ordinary file tree anyone can edit, so `check`, `diff` and `publish`
verify it first: when `base_version > 0` the content digest of the base (secrets filled back in, files included) must equal the
digest this computer's pin (`<config dir>/mastersos/pins/<host>.toml`, outside the directory) recorded for that version;
when `base_version = 0` the base must be empty. A mismatch is refused, and the message suggests `mastersos pull --force`.
After this computer approves a publish, the base becomes the copy stamped with `version` and `issued_at`, and an unedited
`manifest.toml` is updated with it. `pull` refuses to overwrite unpublished changes unless `--force`; `--version N` takes only
an older version this computer has verified. `publish` runs `check`, synthesises locally (references replaced by values,
`version`, `issued_at` and the school name written), uploads the bundle for approval, and stops with the reason when the server
refuses it (someone published after the base, or a blocking check failed).

The config folder is `~/.config/mastersos/` on macOS and Linux (`XDG_CONFIG_HOME` is not read) and `%APPDATA%\mastersos\` on
Windows. It holds the one token file and `config.toml` (both written by `connect`) and the pins, in `pins/` (`--pin-dir`
changes it). Paths the command line prints are absolute, written the way the platform writes them. Pins kept by an earlier
install in its own separate folder are not read, so IT confirms the key fingerprints once after upgrading.

The trusted keys (`[[trust]]` and `[school].escrow_recipients`) come only from the school key files IT holds, never
by copy and paste or from the server:

- `init <dir> --key-file <file>` (repeatable, required): reads each school key file on this computer, derives its trusted
  key (`rk-...`) and its disk-unlocking recipient (age), confirms both are registered for this school, writes them into the new
  `manifest.toml` and prints `Trusted keys: 11d9-03eb, 7c42-a915`.
- `key add <file>` / `key remove <key code>`: change only the local `manifest.toml` (the server is not touched); then
  `publish` with a school key that is already trusted. The last key cannot be removed. `key list` shows key code, label and
  registered date, and whether the published version and the local directory trust each key.

`publish` arguments:

- `--key-file <file>`: the school key file (`MASTERSKIT1...`), or `-` for the first line of stdin. A file in PEM form is
  refused. On an exFAT or FAT32 USB stick permissions cannot be expressed, so a file others can read loads with only the note
  `Make sure no other user can read this school key file. Keep it on a USB stick whenever you can.`; the token file and
  `secrets.toml` stay strict. Before uploading, `publish` confirms the key is trusted and registered with the server and
  uploads nothing otherwise. It then verifies the chain on this computer, compares the digest it computed itself at upload,
  asks IT to type the version number, signs and commits; on success it quietly signs a 30-day monthly check-in (heartbeat). A
  failed check-in does not undo the publish; it prints `Computers may soon show "settings may be out of date". Open the admin site to fix it.`
  The output is `Checked: no problems`, `Check code: a1b2c3d4`, `Published version N`.
- `--allow-reroute=<secret name>` (repeatable): see `secret_rerouted` below. Only IT gives it, after running `mastersos diff`
  to see where the secret will be sent.

Other subcommands: `devices list|show`, `key new|register|list|add|remove`, `verify`, `heartbeat`, `recovery read`,
`seed check`, `hash-password` (reads a password twice without echo and prints the IT account's hash for `secrets.toml`),
`logo upload <login.png> <icon.png>`, `explain`, `migrate`, `spec`. `--json` is for scripts and AI assistants.

There is one token file (`token` in the config folder, or `--token-file`), written by `mastersos connect`: an API token
from the admin site's **Command line** page. It has no purposes or kinds. **Never hand IT's
token file to an AI assistant.**

- The token is read only from a file or from a prompt without echo, never from the command line. A token file others can read is refused.
- 退出码：0 成功；1 失败（网络、认证、服务端拒绝）；2 `check` 有 error。
- 秘密（Wi-Fi 的 `psk`、`password`、`client_key`、`client_key_password`，IT 账号的 `password_hash`）在 `manifest.toml` 里是 `secret:<名字>` 引用。
  `check`：引用了不存在的秘密是错误（`secret_unknown`）；没人用的秘密是警告；引用秘密的网络换了层、换了 `ssid`、秘密换了字段，
  或改了 `eap`、`phase2`、`identity`、`anonymous_identity`、`server_domain`、`ca_cert`、`check_server` 任一，警告 `secret_rerouted`
  （密码会被发到新的地方）。改道按值判断，对照已验证的 base（秘密填回后的已发布版本），不信本地的引用名：一个值在 base 里送到过这个网络（同一组
  层、`ssid`、字段与上面那些字段）就没事；送到过、但只在别的网络，算改道；base 里没有这个值、但有这个网络，是改密码，没事；
  值和网络都是 base 里没有的（新网络），算改道。只有还没发布过的第一版不比。`check` 末尾醒目列出这些秘密，
  `--json` 的结果里是 `rerouted_secrets`。`publish` 遇到它就拒绝、什么都不上传，除非 IT 先跑
  `mastersos diff` 核对，再对每个改道的秘密都给 `--allow-reroute=<名字>`（可重复；给错名字不算），
  例如 `mastersos publish ./school --key-file school.kit --allow-reroute=lab-corp-password`。
  Only IT makes this decision; an AI assistant never passes it for IT.
- `publish` 上传前先打印本地检查的全部警告。
- An AI assistant never edits the trusted keys: only IT writes them, with `init`, `key add` and `key remove` from the school key files, and approves with a school key at publish.

### 装命令行与 skill

`tools/install/install.sh`（macOS、Linux，装到 `~/.local/bin`）与 `tools/install/install.ps1`（Windows，装到
`%LOCALAPPDATA%\Programs\mastersos` 并加进用户 `PATH`）从本仓库的 GitHub release 下载本机的包，先对照 `SHA256SUMS` 核对
SHA-256 再安装，不要管理员权限。release 由 `.github/workflows/cli-release.yml` 手动构建（输入 `ref`；勾上 `publish` 才建
`cli-<12 位提交>` 的 tag 与 release），五个目标：`aarch64-apple-darwin`、`x86_64-apple-darwin`、`x86_64-unknown-linux-musl`、
`aarch64-unknown-linux-musl`、`x86_64-pc-windows-msvc`。每次运行都在三个系统上用刚构建的包、经本机假 release
（`MASTERSOS_RELEASE_BASE`）跑 `tools/install/test-install.sh` / `test-install.ps1`：装上的 `mastersos --version` 能跑，
篡改过的 `SHA256SUMS` 什么都不装。安装脚本的测试在本地也能跑：`bash tools/install/test-install.sh`（桩程序）。

skill 在 `skills/mastersos-admin/`（复制到 `~/.claude/skills/mastersos-admin/`）：在 IT 给的本地目录里改 `manifest.toml`、跑 `check` 与 `diff`、给人看差异，
不读 `secrets.toml` 与合成出的包，改完请 IT `mastersos publish`；红线写在 `SKILL.md`。`reference/settings-reference.md` 是 `core/mastersos-bundle/docs/manifest-spec.md` 的逐字副本，改了规范要重新复制
（`skill_reference_matches_spec` 测试会红）；`reference/recipes.md` 的每个 TOML 块由 `skill_recipes_parse` 检查。

## 锁定应用

设计：`docs/superpowers/specs/2026-10-26-mastersos-kiosk-apps-design.md`（计划 9）。镜像这一侧见 `image/README.md`「锁定应用」，
考试扩展见 `kiosk-extension/README.md`。**还没在 VM 上验过**：验收清单是 `image/lab/kiosk-acceptance.md`（V1–V9 与设计 §9 的五个细节）。

一个锁定应用是一个独立、临时、锁住的会话：没有 GNOME Shell，只有全屏的这一个应用（网页、PWA 或本地程序）；学生自己的东西
（Cookie、输入、下载）在会话结束时全部清掉。考试平台自己管登录、试卷与监考；MastersOS 只保证环境是锁住的，进出只写本机日志
（`journalctl MASTERSOS_KIOSK=<id>`），不上报、不截屏。

### 写法

写在配置里，`[config.apps.kiosk]` 下以 **id** 为键，一行一个应用（内联表），字段多的也可以写成完整的表，两种等价：

```toml
[config.apps.kiosk]
nwea  = { name = "NWEA MAP", url = "https://test.mapnwea.org/", allow = ["nwea.org", "mapnwea.org"], icon = "files/nwea.png" }
forms = { name = "期中考试", url = "https://docs.google.com/forms/d/e/…/viewform", allow = ["docs.google.com", "accounts.google.com", "gstatic.com"], in_session = true }
calc  = { name = "计算器", exec = "org.gnome.Calculator" }   # Flatpak id：不在本配置的 apps.flatpak 里时 lint 警告 kiosk_flatpak_missing

[config.apps.kiosk.map-pwa]
name = "NWEA MAP（PWA）"
url = "https://test.mapnwea.org/"
allow = ["nwea.org", "mapnwea.org"]
pwa = true

[config.apps.kiosk.map-pwa.chrome_policy]
PrintingEnabled = true
```

| 字段 | 缺省 | 说明 |
|---|---|---|
| id（键） | 必填 | `^[a-z][a-z0-9-]{0,23}$`。决定机器上的账号 `kiosk-<id>`、策略与日志；改 `name` 不改 id。一个配置最多 32 个 |
| `name` | 必填 | 登录界面与 Dock 上的名字：最多 64 个字符，不能有冒号 `:`、逗号 `,` 与控制字符（它进账号的 GECOS） |
| `icon` | 通用图标 | 包里的 `files/…` 或 `https://`，与网页应用相同 |
| `url` / `exec` | 二选一 | `url`：https 的入口。`exec`：Flatpak id，或 `/usr/` 下不含 `..` 的绝对路径；不收 shell 命令、不收 Chrome 命令行参数 |
| `pwa` | false | 只配 `url`：经 `WebAppInstallForceList` 装成 PWA，以 `--app=<url>` 打开 |
| `allow` | `url` 的主机名 | 放行的主机（含子域）；不许 `*`、只有顶级域、带路径或端口。平台用的静态资源域名也要列（Google 表单的 `gstatic.com`），lint 不替你猜。大写与结尾的点会规范化，泰文域名写 punycode（`xn--…`） |
| `user_agent` | 不改 | 只配网页 / PWA，≤ 512 字节。见下「`user_agent` 的立场」 |
| `extensions` | 无 | 另外强制安装的扩展：`id`（32 个 a–p）、`update_url`（https）、`config`（扩展的托管配置） |
| `chrome_policy` | 无 | 叠在默认锁之上；锁住的键（放行与阻止名单、开发者工具、下载、扩展安装、原生消息……）写了是 lint 错误 `kiosk_policy_locked`。**不继承**配置的 `chrome_policy` |
| `login_screen` | true | 出现在登录界面的用户列表里 |
| `in_session` | false | 出现在会话的 Dock 与应用列表里。写了 true 时 `login_screen` 不能是 false（lint 错误 `kiosk_in_session_only`，见下「入口」） |

- **只有网页 / PWA 用得上 Chrome 的字段**：`exec` 应用写 `user_agent` 是 lint 错误；`extensions` 与 `chrome_policy` 对它没有作用，
  管理网页保存时把它们去掉（换成「程序」类型、或保存一个没动过的程序应用时也一样）。
- **默认锁里关掉、应用可以在 `chrome_policy` 里打开的**：打印（`PrintingEnabled`）、页面翻译（`TranslateEnabled`）、拼写检查
  （`SpellcheckEnabled`）、Google Lens（`LensOverlaySettings = 1`）、生成式 AI 功能（`GenAiDefaultSettings = 2`）与「发送反馈」
  （`UserFeedbackAllowed`）。英文阅读考试里右键一下就能把整篇翻成泰文，所以默认关；确实要用的应用自己写
  `chrome_policy = { TranslateEnabled = true }`。
- **本地程序也有一份 Chrome 策略**：程序里的链接（帮助、「关于」、`xdg-open`）会在锁定会话里起 Chrome；它拿到的是同一套默认锁，
  什么网站都不放行、不装任何扩展——打开了也只是一页「被管理员阻止」。
- 新键 `kiosk` 进 `features_used`：最近 30 天见过、还不认识它的机器会让发布被 `feature_unsupported` 挡下，先升级那些机器的系统。
- 管理网页的配置页有「锁定应用」一块（`user_agent`、扩展与 Chrome 策略在「高级」里）；AI 助手也只能起草，不能发布。

**NWEA 的前提**：学区没有为本校打开「所有学生必须用安全测试」。NWEA 的安全测试只支持 Windows 11、macOS、ChromeOS 与 iPadOS，
打开了它的学区，任何 Linux 方案都进不去；没打开时 NWEA 允许普通浏览器测试，由锁定会话锁住。开考要监考在 NWEA 的控制台里确认，
中途离开、回来也要监考确认——这是 NWEA 自己的规矩，MastersOS 不另设老师的退出码。

### 入口

- **登录界面**（`login_screen = true`，缺省）：用户列表里以应用的名字与图标出现，点一下不问口令直接进入。
- **桌面**（`in_session = true`）：Dock 与应用列表里有它；点了先确认「将结束当前会话，进入 <名字> 锁定模式」，确认后**当前会话结束**
  （访客照常清空，SSO 与本机用户的文件照常保留），回到登录界面，**再在登录界面点一下那个应用**进去。一次性自动登录还没做（设计 §9.4，
  等 VM 验收定），所以只在桌面显示（`login_screen = false`）的应用没人进得去：发布前检查报错 `kiosk_in_session_only`，管理网页也挡保存。
  自动登录做好之后放宽这一条。
- **另一个会话还开着时不能进**：在桌面会话里用「切换用户」回到登录界面、再点锁定应用，会被拒绝并提示「请先回到那个会话注销」——
  否则锁定会话会开在还活着的桌面旁边，两边能来回切。座位上只要还有别的用户会话（活动或在后台），锁定应用就打不开；从桌面「进入」
  先结束了当前会话，不受影响。
- 上一位的清理还没做完时点同一个应用：拒绝，提示「上一位还没有完全退出」，等几秒再点。
- 机器被挂失锁定时锁定应用一样登不进去，正在跑的锁定会话被结束。应用从设置里删掉：先结束它的会话，再删账号与入口。

### 退出

- **网页 / PWA**：页面右边缘正中有 MastersOS 考试扩展的「Options」把手（三点图标，可拖到左右边缘的别处），菜单里选「Exit」并确认后会话结束、回到登录界面。
- **按钮不在的地方**：Chrome 自己的错误页与拦截页（「无法访问此网站」「被管理员阻止」）不跑扩展，**没有按钮**；没联网时扩展装不上，
  也没有按钮（锁定会话每次都从更新源重新装扩展）。这时：60 秒内按 5 次 Alt+F4 出本机错误页「这个应用无法启动，请举手找老师」，
  再按一次 Alt+F4 结束会话；或长按电源键。Alt+F4 关掉 Chrome 本身只会原地重开。
- **本地程序**：用程序自己的关闭（或 Alt+F4），程序一退出会话就结束；它没有考试扩展。
- 电源键照常；中途离开的后果由考试平台决定。

### `user_agent` 的立场

`user_agent` 只用于**兼容**：有的网站看到 Linux 就拒绝，改一下 UA 就能用。它改不到 UA Client Hints（lint 对每个写了它的应用给一条提示
`kiosk_user_agent`）。考试厂商要求的安全客户端不靠它：MastersOS 是 ChromeOS 的替代，有需要时由考试扩展模拟 ChromeOS 或其他厂商支持的设备（NWEA 按 ChromeOS
kiosk PWA），同时联系厂商取得长期支持（设计 `docs/superpowers/specs/2026-10-26-mastersos-kiosk-apps-design.md` §4.9、裁定 K9）。

### 考试扩展的版本

考试扩展（`kiosk-extension/`）每改一次都要调高 `manifest.json` 的 `version`：Chrome 只在版本变高时更新，`publish.sh <版本> chrome`
拒绝版本更旧、或同一版本字节不同的扩展。它用自己的钥匙签（正式的 `kiosk-ext.pem` 随钥匙仪式在两根 U 盘上，lab 的在构建机上），
扩展 id 由钥匙算出；换钥匙会换 id，见 `image/docs/keys.md` 钥匙表。`publish.sh <版本> chrome` 只收已经进了 beta 的构建，所以
`publish.sh <版本> beta` 之后要在同一次操作里接着发 `chrome` 并同步到 S3——否则 beta 机器重启进新镜像时更新源上还没有扩展，锁定会话没有
「退出」按钮（第一次正式发布尤其如此，见 `image/docs/update-channels.md`「第一次正式发布的顺序」）。

## 批准与学校钥匙

服务端没有签名钥匙（云端设计裁定 8）：每一版都由学校钥匙批准（签名），受信钥匙也由学校自己列，服务端从不替草稿写受信钥匙。

**学校钥匙是唯一的签名钥匙**（2026-11-04 起 IT 的流程里没有 passkey）：一个小文件加一份打印件，批准每台电脑的设置，
也能解开它们的磁盘。IT 在任何一台电脑上有这个文件就能批准：命令行 `mastersos publish --key-file <文件>`。
Make a school key with `mastersos key new --out <folder> --school <name>` and register it with
`mastersos key register --key-file <file> --label <text>` (it uses the token from `mastersos connect`). The file is named
`<school>-school-key-<key code>.kit` and the printed copy carries the same key code; keep each file on its own USB stick,
and make two, kept apart.
`mastersos-bundle` 与 agent 仍然验旧的 `webauthn-es256` 签名（没有在用的学校，以后再删），只是不再产生新的。

### Trust on this computer

- **`mastersos publish`, `verify`, `heartbeat`, `recovery read` and `seed check`** do not trust the server. Before approving,
  they fetch every published version's original bundle from the version pinned on this computer and verify each like an agent
  does. The diff, digests and trusted-key changes are computed locally; the server's diff and lint are advisory.

### Commands for school keys and verification

IT uses only `mastersos`. `--key-file` reads a school key file; `--key-file -` reads the first line of stdin (use a pipe or
a redirect: pasting into a terminal echoes it). The server comes from `connect` (or `--server`), the token from the one
token file (or `--token-file`).

```bash
# Make a school key offline: written to a new file only its owner can read (an existing file is refused); the terminal
# shows only the key code and fingerprint, never the key. When --out is a directory the file is <school>-school-key-<key code>.kit
mastersos key new --out /Volumes/USB --school myschool
# Register the school key and its disk-unlocking recipient; an already registered key only prints a note, and a run that failed midway can be repeated as is
mastersos key register --key-file /Volumes/USB/myschool-school-key-11d903eb.kit --label "IT first key"
# List the registered school keys, and add or remove one in the local settings directory
mastersos key list
# Verify every published version on this computer (the first time you confirm the key fingerprints)
mastersos verify
# Check an install file before using it: its trusted keys and min_version must equal the latest version verified here
mastersos seed check seed.toml
# Monthly check-in (heartbeat): version and digest come from the latest version verified here; --days is 1 to 31, default 30.
# This computer's clock must be right: a difference of more than 10 minutes from the server is refused.
# `mastersos publish` does it with every publish and the admin site reminds IT after a long gap, so this command is for special cases
mastersos heartbeat --key-file <file> --days 30
# Read a computer's escrowed disk recovery code: the ciphertext is fetched and opened on this computer with the school key (the server records every read)
mastersos recovery read <device_id> --key-file <file>
```

**学校钥匙文件**：一个 32 字节主密钥，导出 Ed25519 的受信钥匙（`rk-…`，进 `[[trust]]`）和 age 的磁盘解锁收件人
（`age1…`，进 `[school].escrow_recipients`）。文字形式是 `MASTERSKIT1…`（bech32m），抄错一个字符、混写大小写都会被拒，
不会悄悄变成另一把钥匙。钥匙码是 key id 的前 8 位十六进制，4-4 分组（`11d9-03eb`）。

- **第一版（R1g）**：还没发布过时没有链可验：`publish` 打印第一版自己的整份受信钥匙，要 IT 逐把对照钥匙码与指纹、键入版本号 `1`
  与 `yes`（旧的 `trust` 也收），再用学校钥匙签。**要与自己手里的对照**（打印件、`key new` / `key register` 打印的），不要与这台服务端的页面对照。
  签名的学校钥匙必须登记过、而且受信；服务端也用这一版自己的受信钥匙验。签完 pin 在第 1 版。
  本机已经有这台服务端的 pin 时，服务端却说什么都没发布过，拒绝签（可能是回滚或换了服务端），报出 pin 文件的路径；
  确知服务端是有意重建的，才删掉那个文件。pin 只会沿着验过的链往前走：版本不升、或不是从磁盘上那个 pin 验过来的，一律不写。
  发布第一版之前没有装机文件可下载（`GET /v1/admin/seed` 回 409 `no_published_version`）。
- **pin 与首次信任**：第一次对某台服务端批准时，本机还没有记录。它打印最新版受信钥匙的指纹，要求 IT 与自己的打印件对照后输入 `yes`，
  然后把 `(版本, trust)` 记进 `<配置目录>/mastersos/pins/` 下的 `<主机>.toml`（地址带端口时写成 `<主机>_<端口>.toml`；`--pin-dir` 可以改位置）。Pins kept by an earlier install in its own separate folder are not read, so IT confirms the key fingerprints once after upgrading.
  之后每一次都从这一版往下验，验过的最新版成为新的 pin。pin 按 `--server` 解析后的「主机[:端口]」命名：主机名转小写、默认端口去掉，
  路径不算。同一台服务端换一种写法（IP 与域名、别名主机名、显式写出非默认端口）会被当成另一台、重新走首次信任，所以每次都用同一个地址。
  写 pin 时先对 `<pin>.lock` 加独占锁，在锁里比对磁盘上的 pin 再写：两个进程同时对同一台服务端运行，后到的那个比对不过就拒绝。
  新 pin 先写进一个独占新建的临时文件、fsync、改名，再 fsync 目录。
- 批准时要键入版本号确认。这一版改了受信钥匙或磁盘解锁收件人时，先用白话说明哪些学校钥匙被接受、谁能解锁磁盘，再键入 `yes`。

服务端守着这几条规则：

- 第一版只收新受信钥匙里一把登记过的学校钥匙的签名，并用新受信钥匙本身验（R1g）。
- 新受信钥匙里的每把都必须在本服务端登记过（R2）。
- 签名所用的钥匙必须还在新的受信钥匙里（R5）。
- 受信钥匙里至少要有一把学校钥匙（R6）。
- 受信钥匙的变化不接受旧 passkey 的签名（R7）。

风险：

- 所有学校钥匙（文件与打印件）都丢失时，只能逐台重刷。
- 新电脑的装机文件是「首次信任」：服务器被攻破期间下载的装机文件，信任的是攻击者。用 `mastersos seed check` 核对。

### 每月确认

每月确认（心跳）是「第 v 版仍是最新，到 T 为止」的签名。下面任一条成立时，电脑显示「设置可能过期」：

- 7 天没联系上服务器。
- 现在已经过了「接受这一版 + 7 天」与「每月确认到期」两者中较晚的那个时刻。

每月确认说有更新的版本、而电脑立即重拉仍拿不到时，电脑回报「有更新被扣住」。**每月确认的有效期就是服务端扣住更新、
而电脑看不出来的最长时间。** 服务端从不自签，由 IT 的学校钥匙签，最长 31 天（按签发时刻算；电脑容许签发时刻比本机快 1 天，所以从电脑的角度看最多约 32 天）：
`mastersos publish --key-file` 每次发布都顺带签 30 天；长期没发布时，管理网站首页提醒，再发布一次 `mastersos publish --key-file <文件>`，或运行 `mastersos heartbeat --key-file <文件>`。
