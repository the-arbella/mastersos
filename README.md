# mastersos

[English](README.en.md)

教育笔记本系统：不可变的 Ubuntu 镜像，加上设备端的设置 agent、安装器和签名工具。设备上只应用学校钥匙签过的设置包。
管理这些设备的云服务不开源，这里没有它的代码。

`core/` 是 Rust workspace：

- `mastersos-bundle`：设置包的清单、打包、签名与验签（Ed25519 与 passkey 的 WebAuthn 断言）、心跳、发布前 lint。
- `mastersos-agent`：机器上拉取、验签、应用设置的服务；另有恢复密钥托管与 TPM 槽（`luks`）、Chrome sysext（`mastersos-agent chrome`）、开机快速应用（`apply-local`）。
- `mastersos-mcp`：给 AI 与人用的 `mastersos` 命令行（`mastersos mcp` 子命令是 stdio 的只读 MCP 服务）。设置在本地目录里编辑，命令行负责 pull、check、diff、publish；AI 只改文件，不能发布。
- `mastersos-sign`：学校恢复钥匙的命令行。它在本地验链后签名，trust 的变化只能经它签。
- `mastersos-installer`：U 盘安装器（tty 上的纯文本流程）与未受管机器的首次开机建用户（`mastersos-firstrun`）。

系统镜像在 `image/`（mkosi），见 `image/README.md`；给 IT 的装机说明在 `image/docs/install.md`。

## 测试

```bash
cd core && cargo fmt --check
cd core && cargo clippy --workspace --all-targets -- -D warnings
cd core && cargo test --workspace
```

工具链是 Rust 1.98（`core/rust-toolchain.toml`）。CI 见 `.github/workflows/mastersos.yml`。`image-lint` 对 `image/` 跑 shellcheck、`tests/check-tree.sh` 与几个不碰 VM 的脚本测试。

## 命令行与 MCP：本地目录里改设置

设置不在服务端存草稿：IT 把已发布的版本拉成一个本地目录，人或 AI 在里面改 `manifest.toml`，本地检查、看差异，最后由 IT 发布。

```bash
mastersos init ./school          # 新学校：用模板建目录（已发布过的学校用 pull）
mastersos pull ./school          # 下载最新已发布版本，沿版本链验签，拆成目录
$EDITOR ./school/manifest.toml   # 或让 AI 改；新密码网络写 psk = "secret:<名字>"，值由 IT 填进 secrets.toml
mastersos check ./school && mastersos diff ./school     # 本地，不联网；check 有错误退出码 2
mastersos publish ./school [--key rk.key]   # 有恢复钥匙文件就本机验证、签名并 commit；没有就打印签名页链接，
                                            # IT 在浏览器里用 passkey 签完后再跑 mastersos pull
```

目录里：`mastersos.toml`（学校主机与 `base_version`）、`manifest.toml`（秘密只写引用）、`secrets.toml`（0600，git 忽略，秘密的值）、
`files/`、`.mastersos/base/`（pull 下来的原样，`diff` 用）。`pull` 在目录有未发布改动时拒绝覆盖，除非 `--force`；
`--version N` 只取本机验证过的旧版本。`publish` 先 `check`，在本地合成（引用换成值，写 `version`、`issued_at`、学校名），
上传成待签名包；服务端拒收（base 之后已有人发布、阻断检查不过）就停并显示原因。

其他子命令：`mastersos devices list|show`、`keys list`（服务端的机器与已登记钥匙，供手写 `[[device]]` 与 `trust`）、
`hash-password`（不回显读口令，输出 IT 账号的哈希，写进 `secrets.toml`）、`logo upload <登录页.png> <图标.png>`、`spec`、`setup`。
`--json` 给脚本与 AI 用。

`mastersos mcp --dir <目录>` 是 stdio 的 MCP 服务，只读：`read_manifest`、`list_files`、`read_file`、`check`、`diff`、`devices_list`、
`device_show`、`keys_list`、`spec`。没有写工具，也不碰 `secrets.toml`、合成出的包和签名；AI 用自己的文件工具改 `manifest.toml` 与 `files/`。

`setup` 与服务端 token：两个 token 文件，分开放。

- **IT 自己的 token**（`token_file`，默认 `~/.config/mastersos/token`）：命令行的 `init`、`pull`、`publish`、`logo upload`、
  `keys list`、`devices` 用它。它是 read + draft 范围的 API token，向运营者要，或在管理页建。`init`、`pull`、`publish`、
  `logo upload` 拒绝 AI token（`whoami` 的 label 以 `ai:` 开头的）：AI token 读到的秘密是 `"<kept>"`，也不能签名。
- **AI token**（`ai_token_file`，默认 `~/.config/mastersos/ai-token`，`--ai-token-file` 可改）：只给 `mastersos mcp` 用，
  学校管理员在管理页「AI tools」建。`mastersos mcp` 拒绝不是 AI token 的 token（退出码 2）。**绝不要把 IT 的 token 文件交给 AI。**

```bash
mastersos setup --server https://mastersos.school.ac.th --token-file /path/to/it.token --ai-token-file /path/to/ai.token
```

`setup` 把地址与两个文件的路径存进 `~/.config/mastersos/config.toml`（两个文件权限都必须是 0600），已有的文件逐个试连。

- token 只从文件读，不接受命令行明文。AI 用的 token 只能读机器与状态，不能下载包，不能读待签名包。
- token 带 read、draft 以外的范围（`publish`、`keys` ……）时：`mastersos mcp` 以退出码 2 结束，其他子命令以 1 结束。
- 退出码：0 成功；1 失败（网络、认证、服务端拒绝）；2 `check` 有 error。
- 秘密（Wi-Fi 的 `psk`、`password`、`client_key`、`client_key_password`，IT 账号的 `password_hash`）在 `manifest.toml` 里是 `secret:<名字>` 引用。
  `check`：引用了不存在的秘密是错误（`secret_unknown`）；没人用的秘密是警告；引用秘密的网络换了层、换了 `ssid`、秘密换了字段，
  或改了 `eap`、`phase2`、`identity`、`anonymous_identity`、`server_domain`、`ca_cert`、`check_server` 任一，警告 `secret_rerouted`
  （密码会被发到新的地方），`check` 末尾醒目列出这些秘密。`publish` 遇到它就拒绝、什么都不上传，除非 IT 对每个改道的秘密都给
  `--allow-reroute <名字>`（可重复；给错名字不算）。只有 IT 能下这个决定：MCP 没有发布工具，也没有任何参数能传它，AI 从不替 IT 传。
- `publish` 上传前先打印本地检查的全部警告。
- AI 不改 trust：`trust` 照 `manifest.toml` 写的，发布不自动填；trust 的变化只能由 IT 用恢复钥匙经 `mastersos-sign` 签。

### 装命令行与 skill

运营者命令行（`cloud school …`）看不到也撤销不了 AI token（运营者角色只有 SELECT）。出了泄漏时的杠杆有两个：
把建 token 的人从该校 `admins` 里删掉（他建的所有 token 随之失效，加回来又生效），或者让管理员在管理页 `/ai` 撤销。

IT 把自己的 read + draft token 存进 `~/.config/mastersos/token`（权限 0600）。学校管理员在管理页「AI tools」建 AI token
（30/90/180 天过期，建它的人不再是管理员就失效；管理页会把这样的 token 标成「未生效」，但它仍占 10 个名额直到撤销或过期），存进
`~/.config/mastersos/ai-token`（权限 0600），只给 `mastersos mcp` 用。然后：

```bash
curl -fsSL https://os.khundavid.com/downloads/mastersos/install.sh | sh     # 装 mastersos 与 skill（删掉旧的 mastersos-mcp）
mastersos setup --server https://<school>.os.khundavid.com
claude mcp add mastersos -- mastersos mcp --dir ./school     # 可选：只给需要 MCP 的客户端
```

skill 在 `skills/mastersos-admin/`（装到 `~/.claude/skills/mastersos-admin/`）：在 IT 给的本地目录里改 `manifest.toml`、跑 `check` 与 `diff`、给人看差异，
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
- 管理网页的配置页有「锁定应用」一块（`user_agent`、扩展与 Chrome 策略在「高级」里）；MCP 也能起草，照旧只能起草、不能发布。

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

- **网页 / PWA**：页面右下角有 MastersOS 考试扩展的「退出 / Exit」按钮（可拖到别的角），确认后会话结束、回到登录界面。
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

## 签名：passkey 与恢复钥匙

服务端没有签名钥匙（云端设计裁定 8）：每一版都由学校的钥匙签，trust 也由学校自己列，服务端从不替草稿填 trust。

学校钥匙有两种，都写进 trust：

- **passkey**：只在云的签名页上登记和使用（管理页面的「钥匙」「发布」与心跳都只给打开签名页的链接，概览与钥匙页顶部常驻
  「Signing happens only on <签名源>」），私钥留在认证器里。passkey 绑在云的签名源（rp_id 是 `sign_origin` 的 host，各校共用）上，
  学校换管理域名不影响 passkey；只有签名源本身搬家时，才要在新签名源上登记 passkey，再用恢复钥匙签一版把它加进 trust。
  - 同步型 passkey 的私钥跟着 IT 的 Apple 或 Google 账号走。钥匙页会标出「同步型」。
  - 签名页在 https 的签名源上；只有本机演示用 `http://localhost`。
- **恢复钥匙**：Ed25519，用 `mastersos-sign` 生成、登记和签名。平时打印在纸上锁进柜子，电脑上不留私钥。
  trust 里至少要有一把恢复钥匙（R6）。

### 网页签名与 `mastersos-sign` 的分工

- **签名页的 passkey**：用于日常发布（trust 与托管收件人都没有变化的那些）和心跳续签。签名页下载待发布的每个文件、自己算摘要；
  从上一版的归档里读出 trust 与托管收件人自己比对，和服务端说的对不上就按变化处理；签名用的消息在本地重建，不签服务端给的字节。
  发布之后再按一次 passkey 续签 30 天心跳。trust 或收件人有变化（以及第一版）时只给「载入恢复钥匙包」
  （网页载入 kit 在计划 6 Task 18 落地，在那之前页面给出带 `--kit` 的 `mastersos-sign sign` 命令）。
  **网页签名信任的是发出签名页的云**（横幅写明构建号与签名源）：怀疑签名页被换过时，改用 `mastersos-sign`。
- **`mastersos-sign`**：不信任服务端。签名前，它从本机 pin 住的那一版起，逐版取回服务端发布过的每一版原始包，像 agent 一样验签。
  差异、摘要、trust 的增删都在本地算，服务端给的差异和 lint 只作参考。**trust 的任何变化都只能经它、用恢复钥匙签**
  （服务端拒收 passkey 签的 trust 变化）。

### `mastersos-sign` 命令

```bash
cd core && cargo build -p mastersos-sign && S=$PWD/target/debug/mastersos-sign

# 生成。私钥与纸面备份都是 0600，不覆盖已有文件，私钥不打印到终端
$S keygen --out rk.key                  # 另写 rk.key.paper.txt：打印出来锁进柜子，然后删掉这个文件

# 登记要 keys 范围：请运营者临时发一把（cloud school token create --scope keys），登记完让运营者删掉
# （cloud school token delete）。删掉之后一分钟内服务就不再认它。
$S register --server https://mastersos.school.ac.th --token-file keys.token --key rk.key --label "柜子里的恢复钥匙"
rm rk.key                               # 平时离线：电脑上不留私钥

# 要签名时从纸面备份临时还原，签完再删。sign / heartbeat / seed-check / verify 只要 read + draft 范围的 token
$S restore-from-paper --paper paper.txt --out rk.key
$S sign --server https://mastersos.school.ac.th --token-file draft.token --key rk.key --pending <id>   # <id>: printed by `mastersos publish`
rm rk.key

# 只验链，不签名
$S verify --server https://mastersos.school.ac.th --token-file draft.token

# 装机前核对种子：种子的 trust 与 min_version 要等于本地验证过的最新版
$S seed-check --server https://mastersos.school.ac.th --token-file draft.token seed.toml

# 续签心跳（每次发布之后，以及每个月一次）：版本与摘要取自本地验证过的最新版，
# issued_at 是本机现在的时间，--days 取 1 到 31，默认 30。本机时钟要准，与服务端差 10 分钟以上会被拒
$S heartbeat --server https://mastersos.school.ac.th --token-file draft.token --key rk.key --days 30
```

**恢复钥匙包（kit，计划 6）**：一个 32 字节主密钥，导出 Ed25519 恢复钥匙（`rk-…`，进 trust）和 age 的托管钥匙
（`age1…`，进 `[school].escrow_recipients`）。文字形式是 `MASTERSKIT1…`（bech32m），抄错一个字符、混写大小写都会被拒，
不会悄悄变成另一把钥匙。`sign`、`heartbeat`、`register` 都可以用 `--kit <文件>` 代替 `--key`（`--kit -` 从标准输入的第一行读）。
`--kit -` 要用管道或重定向喂进去（`--kit - < usb/school.kit`）：在终端里直接敲或粘贴，kit 会回显在屏幕上。

```bash
# 离线生成：kit 写进 0600 的新文件（已存在就拒绝），终端只打印 key id、指纹与托管收件人，不打印 kit 本身
$S kit new --out school.kit
# 登记恢复钥匙与它的托管收件人（keys 范围）：kit 对本校新发的探针 nonce 签名绑定收件人；已登记过的两样都只提示、不报错，
# 所以中途失败可以原样再跑一次
$S register --server https://<slug>.os.khundavid.com --token-file keys.token --kit school.kit --label "IT 的 kit"
# 签名、续签心跳：先核对这份 kit 是这一校登记过的恢复钥匙，不是就报
# "this kit is not a registered recovery key of <主机>" 并退出 1
$S sign --server https://<slug>.os.khundavid.com --token-file draft.token --kit school.kit
# 读一台机器托管的 LUKS 恢复密钥：取回密文、在本机用 kit 解开（token 要 read + recovery，服务端每次都留审计）
$S escrow-read --server https://<slug>.os.khundavid.com --token-file recovery.token --kit school.kit --device <device_id>
```

- **第一版（R1g）**：还没发布过时 `mastersos-sign sign` 没有链可验：它打印第一版自己的整份 trust，要 IT 逐把对照指纹、键入版本号 `1` 与 `trust`，
  再用恢复钥匙签。**指纹要与自己手里的对照**（`keygen` / `register` 打印的恢复钥匙指纹、纸面备份，登记 passkey 时设备上显示的指纹），
  不要与这台服务端的页面对照。签名的恢复钥匙必须登记过、而且在这一版的 trust 里；服务端也用这一版自己的 trust 验。签完 pin 在第 1 版。
  本机已经有这台服务端的 pin 时，服务端却说什么都没发布过，`mastersos-sign` 拒绝签（可能是回滚或换了服务端），报出 pin 文件的路径；
  确知服务端是有意重建的，才删掉那个文件。pin 只会沿着验过的链往前走：版本不升、或不是从磁盘上那个 pin 验过来的，一律不写。
- **pin 与首次信任**：第一次对某台服务端用 `mastersos-sign` 时，本机还没有记录。它打印最新版 trust 里每把钥匙的指纹，
  要求 IT 与钥匙页、种子开头的指纹对照后输入 `yes`，然后把 `(版本, trust)` 记进 `~/.config/mastersos-sign/<主机>.toml`（地址带端口时写成 `<主机>_<端口>.toml`）
  （用 `--pin-dir` 可以改位置）。之后每一次都从这一版往下验，验过的最新版成为新的 pin。
  pin 按 `--server` 解析后的「主机[:端口]」命名：主机名转小写、默认端口去掉，路径不算。同一台服务端换一种写法
  （IP 与域名、别名主机名、显式写出非默认端口）会被当成另一台、重新走首次信任，所以每次都用同一个地址。
  写 pin 时先对 `<pin>.lock` 加独占的 `flock`，在锁里比对磁盘上的 pin 再写：两个 `mastersos-sign` 同时对同一台服务端运行，
  后到的那个比对不过就拒绝，不会互相覆盖。新 pin 先写进一个独占新建的临时文件、fsync、改名，再 fsync 目录。
- 签名时要键入版本号确认。这一版改了 trust 时，还要再键入一行 `trust`。

### 第一版与 trust 的变化

1. 在网页登记 passkey，建议在不同设备上登记两把。用临时 `keys` token 经 `mastersos-sign register` 登记恢复钥匙，登记完删掉这个 token。
2. 在本地目录的 `manifest.toml` 里把 `[[trust]]` 写成登记过的钥匙（`mastersos keys list` 可查），`mastersos init <目录>` → 编辑（`[[trust]]` 列出这把恢复钥匙）→ `mastersos publish --key rk.key`：`base_version = 0` 时 `publish` 走 `mastersos_sign::sign_pending` 的第一版（R1g）分支，打印整份 trust，要 IT 对照指纹、键入版本号 `1` 与 `trust`，用恢复钥匙签并 commit（也可以单独用 `mastersos-sign sign --pending <id>`）。
   发布第一版之前没有种子可下载（`GET /v1/admin/seed` 回 409 `no_published_version`）。
3. 之后的日常发布可以用网页 passkey 签。每次发布之后续签一次心跳。trust 的变化只能用恢复钥匙经 `mastersos-sign` 签。

服务端守着这几条规则：

- 第一版只收新 trust 里一把登记过的恢复钥匙的签名，并用新 trust 本身验（R1g）。「必须是恢复钥匙」这一半只由服务端与
  `mastersos-sign` 守：机器只认种子里的 trust，分不出钥匙的种类，第一版由 trust 里的 passkey 签它也会收（这不多给任何能力：
  同一把 passkey 本来就能签第二版）。
- 新 trust 里的每把钥匙都必须在本服务端登记过（R2）。
- 签名所用的钥匙必须还在新 trust 里（R5）。
- trust 里至少要有一把恢复钥匙（R6）。
- trust 变化不接受 passkey 签名（R7）。

风险：

- 所有 passkey 与恢复钥匙都丢失时，只能逐台重刷。
- 新机器的种子是「首次信任」：服务器被攻破期间下载的种子，信任的是攻击者。种子开头的指纹用 `mastersos-sign seed-check` 核对。
- 网页签名信任发出页面的服务器，见上一节。

### 心跳

心跳是「第 v 版仍是最新，到 T 为止」的签名。下面任一条成立时，机器显示「设置可能过期」：

- 7 天没联系上服务器。
- 现在已经过了「接受这一版 + 7 天」与「心跳到期」两者中较晚的那个时刻。

心跳说有更新的版本、而机器立即重拉仍拿不到时，机器回报「有更新被扣住」。**心跳的有效期就是服务端扣住更新、
而机器看不出来的最长时间。** 服务端从不自签心跳，由 IT 签，最长 31 天（按签发时刻算；机器容许签发时刻比本机快 1 天，所以从机器的角度看最多约 32 天）：用网页的「用 passkey 续签」，或者用 `mastersos-sign heartbeat`。
