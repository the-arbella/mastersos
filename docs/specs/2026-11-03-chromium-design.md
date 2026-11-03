# 用 Debian 的 Chromium 取代 Google Chrome

2026-11-03 · 状态：待批准

## 1. 为什么

Dell 3420 实测（2026-11-02/03）：第一次开机没有网络，就没有浏览器。Chrome 不能随镜像分发（Google 条款），
只能由 agent 联网后从 Google 的 apt 源下载成 sysext；而登录页的学校账号卡片、桌面、考试模式全都用它。
没网 → 没浏览器 → 学生连登录都做不了，登录页还显示“正在安装浏览器”。

用户裁定（2026-11-03）：

- 换成 Chromium，**镜像自带**，开机即有；全面取代 Chrome（登录卡片、桌面、网页应用、考试模式），不并存。
- 来源：Debian 的 chromium 包（trixie-security），不用 snap、flatpak，不自己编译。
- **只随系统镜像更新**（A/B 更新），版本由我们定，不追求频繁更新；整套 Chrome 下载更新机制删除。
- 不要 Widevine（教育上几乎不用）、不要 Google 浏览器同步；Cast 以后另行实现。
- Google API 密钥（2026-11-03）：先**不带任何 Google 密钥**，接受没有 Safe Browsing、Google 定位等；同时开始申请我们自己的密钥（见 5.9），拿到后再接入。
- 首次启动**不强制联网**（不加“连不上网不能下一步”的页面）。

## 2. 目标、非目标、反目标

**目标**

- 全新安装后第一次开机，不联网也有浏览器：登录卡片能打开（登录本身仍要能到学校的 IdP），桌面有浏览器。
- 现有一切浏览器功能照旧：管理策略、网页应用启动器、考试模式（强制安装考试扩展、退出用的 native messaging、NWEA 模拟环境）、登录页卡片的 URL 白名单。
- 已装 Chrome 的机器升级到新镜像后，自动清掉 Chrome sysext 与它的状态，不留两个浏览器。
- 浏览器版本可追溯：镜像里装的是哪个 Debian 版本、哪个文件、什么 sha256，都记在仓库里。

**非目标**

- Wi-Fi 权限模型（登录页、学生、访客各自能加什么网络）：另一个设计，见对话中的 Chromebook 模型，待用户确认登录页加的网是否全机共享。
- 迁移用户的 Chrome 资料（`~/.config/google-chrome`）：现在的数据都是测试数据，不迁移，也不主动删除。
- 投屏、网页过滤等原计划借 Chrome 的功能。
- 浏览器的独立快速补丁通道（sysext）。以后若需要，再单独设计。

**反目标**（做到了也算失败）

- 镜像里混进锁文件以外的 Debian 包，或者 Debian 源影响 Ubuntu 包的选择（只许锁文件里的包来自 Debian）。
- 考试模式在 Chromium 下静默失效（扩展没装上、退出键不灵、NWEA 判定不支持），却没有被验收发现。
- 浏览器能被学生绕过沙箱或 AppArmor 限制（例如因为 Ubuntu 的 userns 限制而改成关掉沙箱运行）。

## 3. 约束

- 镜像：Ubuntu resolute（26.04），mkosi 构建，`/usr` 为只读 erofs + verity。每个 `/usr` 槽 8G，现用约 1.69 GiB，Chromium 约 380 MB，空间足够；代价是每次系统更新下载变大。
- 试验（2026-11-03，VM 121 上的 ubuntu:26.04 容器，Debian trixie-security 的 chromium 156.0.8078.79-1~deb13u1）：
  - 依赖只缺 `libjpeg62-turbo`（Debian 的 soname，Ubuntu 没有），带上 Debian 的这一个库即可；其余依赖 Ubuntu 26.04 都满足。
  - H.264、AAC、VP9、AV1 都支持；`/etc/chromium/policies/managed` 下的策略生效（`URLBlocklist` 返回 `ERR_BLOCKED_BY_ADMINISTRATOR`）；UA 是 `Chrome/156`。
  - 未验证：图形界面（Wayland，登录页与桌面）、AppArmor 与沙箱、扩展强制安装（含 `file://` 更新地址）、native messaging、NWEA。
- 公开仓库：不能有私有内容；高危安全修复走私有 advisory。
- 云端在私有仓库，钉公开仓库的提交（`os.rev`）；公开仓库不能依赖云端。

## 4. 考虑过的做法

| 做法 | 取舍 | 结论 |
|---|---|---|
| **Debian 的 chromium deb，装进镜像 `/usr`，随镜像更新** | 改动最小、有 Debian 安全团队维护、依赖只差一个库；每次升级浏览器都要发镜像 | **采用**（用户选 ① + 更新方式 A） |
| Debian 的 deb + 独立 sysext 更新通道 | 能单独快速打补丁；要保留并改造下载、校验、回滚和控制台“Chrome 更新”设置 | 不采用（用户选 A） |
| 自己编译 Chromium | 完全可控；一次编译数小时、需大机器，长期维护重 | 不采用 |
| Flathub 的 flatpak | 现成、编码齐全；沙箱与登录页 systemd 服务、AppArmor、策略目录、考试模式都冲突 | 不采用 |
| 学校制作 U 盘时下载 Chrome，安装时离线装 | 合规、保留 Chrome；仍依赖 Google、版本不由我们控制 | 不采用（用户要 Chromium） |
| Firefox / WebKit 等更轻的浏览器 | 考试扩展与策略都是 Chrome 体系，会失效 | 不采用 |

## 5. 设计

### 5.1 来源与构建

- 仓库新增锁文件（例如 `image/chromium.lock`），逐个列出 deb：`chromium`、`chromium-common`、`chromium-sandbox`、`chromium-l10n`（浏览器自身界面的多语言；没有它浏览器菜单只有英文），以及 Ubuntu 没有的依赖（现在只有 `libjpeg62-turbo`）。每个给出完整版本、文件名、sha256 和
  `snapshot.debian.org` 的永久下载地址（Debian 主站会删旧版本，snapshot 不会）。
- 〔我的决定〕下载源：锁定的 deb 同时作为附件放进公开仓库的一个 GitHub Release（例如 `chromium-<版本>`），构建先从这里取，取不到再用 snapshot.debian.org；两边都按锁文件的 sha256 核对。不依赖任何私有主机。
- 〔我的决定〕以后 Debian 的新版本若多出一个 Ubuntu 没有的依赖，升级脚本直接失败并列出它；由人审核后加进锁文件，不自动扩充。
- 构建时只按锁文件下载、核对 sha256 后装进镜像；镜像构建**不**添加 Debian 的 apt 源，所以 Ubuntu 包的解析不受影响（满足反目标第 1 条）。具体用 mkosi 的本地包目录还是 postinst 里 `dpkg -i`，由实现者定，要求是：依赖必须全部由 Ubuntu 包满足，缺任何一个就构建失败，不能用 `--force-depends`。
- 新增升级脚本（例如 `image/chromium-bump.sh`）：取 Debian trixie-security 的 InRelease，用 Debian 归档密钥（`debian-archive-keyring`）验签，按 Packages 的 sha256 定位锁文件里各包的当前版本，改写锁文件，并上传到对应的 GitHub Release。人跑这个脚本、提交，就是“升级浏览器”；CI 不自动升级。
- `check-tree.sh` 加检查：锁文件格式正确、chromium 自身的 4 个包齐全且同版本。
- 镜像的 `build-info.txt` 写入 Chromium 版本。
- 删除 Google 的签名密钥（`image/keys/google-chrome-keyring.gpg`、`check-google-keyring.sh`、check-tree 第 11 条、`keys.md` 相关段落），以及只为 Chrome deb 预装的依赖说明（`mkosi.conf` 里 Chrome 依赖那段按 Chromium 实际需要重写）。

### 5.2 路径

全仓库把 Chrome 的路径换成 Debian Chromium 的：

| 用途 | Chrome | Chromium（Debian） |
|---|---|---|
| 可执行 | `/usr/bin/google-chrome-stable` | `/usr/bin/chromium`（Debian 的包装脚本，读 `/etc/chromium.d/`） |
| 程序目录 | `/opt/google/chrome` | `/usr/lib/chromium` |
| 管理策略 | `/etc/opt/chrome/policies/managed` | `/etc/chromium/policies/managed` |
| native messaging | `/etc/opt/chrome/native-messaging-hosts` | `/etc/chromium/native-messaging-hosts` |
| 桌面文件 | `google-chrome.desktop` | `chromium.desktop` |

agent 里集中成一处常量（现在是 `system/desktop.rs` 的 `CHROME_BIN` / `CHROME_DESKTOP`，改名为与浏览器无关的名字），其余地方引用它。涉及：桌面收藏、网页应用启动器 `Exec=`、锁定会话保留的应用、考试模式、登录卡片、`browser-wait`、`etc-policy.conf`、`namespace.init`（`POLYDIR`）、`pam-hooks.sh` 注释、tmpfiles、gschema 收藏夹、`legacy_browser.snap`（快照按新名字更新，这是有意的变化）。

默认浏览器：现在靠 Chrome 自己的 `.desktop`，镜像里没有设置。改为镜像明确设置 Chromium 为 http/https 与 html 的默认程序（`/usr/share/applications/mimeapps.list` 或 `/etc/xdg/mimeapps.list`，实现者定）。

### 5.3 删掉的东西（Chrome 下载更新机制）

- agent：`chrome_sysext.rs` 与测试、fixtures；`chrome` 子命令；`ChromeStatus` 任务；`fetch.rs` 里为 Chrome apt 源服务的说明。
- 镜像：`mastersos-chrome.service` / `.timer` 及启用链接；NetworkManager dispatcher 里拉起 Chrome 下载的部分；tmpfiles 的 `/var/lib/mastersos/chrome`；`update-done` 等处只为 Chrome sysext 写的说明。`systemd-sysext` 本身与 exec-block 的 drop-in 保留（机制通用，以后可能用）。
- 状态与 banner：浏览器随镜像一定存在，删掉 `Browser` 状态、`MSG_CHROME`、`MSG_CHROME_FAILED`；`status.json` 去掉 `chrome` 字段；`BANNER_SENTENCES` 只剩网络与设置两句，`strings.js` 的 `BANNER`、`.pot` 和 84 个 `.po` 同步删掉这两句（check-tree 第 50 条会核对）。`browser-wait`（会话里等 Chrome 出现）整个删除，连同其用户服务与测试。
- 回报项：`chrome`（下载结果）与 `chrome-update` 删除；新增 `browser` 项，内容是 Chromium 版本（从镜像读，不是联网结果）。`chrome-policy` 项保留（见 5.4）。
- 配置格式：`[config.chrome]`（更新时段、暂停）不再有意义。为不让学校现有设置报错，解析时仍接受、忽略，lint 给一条 info（例如 `chrome_update_ignored`：“浏览器随系统更新，这项设置不再生效”）；规格文档标为已废弃。`chrome_pause_*`、`chrome_window_invalid` 等 lint 代码删除。云端的 issue-codes 随之更新。

### 5.4 策略

- 全机策略：`chrome_policy.rs` 改写到 `/etc/chromium/policies/managed/mastersos.json`，`BASELINE` 不变（`BrowserSignin=0` 等对 Chromium 一样适用）。配置里的 `chrome_policy` 键**不改名**：它是 Chrome 企业策略格式，Chromium 同样读；规格里写明“作用于 Chromium”。
- 登录卡片：`mastersos-login-browser@.service` 的 `BindReadOnlyPaths` 改绑到 `/etc/chromium/policies/managed`。
- 考试模式：`NS_POLYDIR` 改为 `/etc/chromium/policies/managed`，`namespace.init` 与 tmpfiles 同步；考试扩展的 native messaging 主机清单装到 `/etc/chromium/native-messaging-hosts/`。
- 首次运行与组件更新：Chromium 不需要 Chrome 的 `--disable-component-update` 以外的特殊参数时，参数统一放 `/etc/chromium.d/`（Debian 包装脚本会读），而不是散在各个启动处；登录卡片与考试模式仍各自加自己需要的参数。

### 5.4a Google API 密钥

- Debian 的 `chromium-common` 带有 Debian 自己的 Google API 密钥（`/etc/chromium.d/apikeys`），包装脚本会读。镜像里**删掉或清空**这个文件（构建时处理，check-tree 检查镜像树里没有它），不使用 Debian 的密钥。
- 后果（用户已接受）：Safe Browsing（恶意网站、钓鱼警告）、Google 定位、依赖 Google 服务的拼写检查与翻译不可用。恶意网站防护暂时靠学校网络的过滤。
- 为 5.9 留接口：密钥只在正式构建时从 CI 的 Secret 写进镜像（`/etc/chromium.d/` 下的一个文件），不进公开仓库，lab 镜像与本地构建不带。没有 Secret 时构建照常、等同于不带密钥。

### 5.5 AppArmor 与沙箱

- 登录卡片的 AppArmor 配置现在依赖 Ubuntu 自带的 `chrome` 配置文件标签（`peer=chrome//&mastersos-login-browser`），且 Ubuntu 26.04 限制非特权用户命名空间，Chrome 的沙箱靠 Ubuntu 为 `/opt/google/chrome/chrome` 提供的配置放行。
- Debian 的 Chromium 路径（`/usr/lib/chromium/chromium`）多半没有 Ubuntu 的现成配置。镜像要自带一份 Chromium 的 AppArmor 配置，放行它需要的 userns，并让登录卡片的叠加配置改用这个标签。
- 沙箱必须开着：不允许 `--no-sandbox`，也不允许通过关掉 `kernel.apparmor_restrict_unprivileged_userns` 来让它跑起来。验收看 `chrome://sandbox` 全绿。`chromium-sandbox`（setuid 辅助程序）随包装上，作为 userns 不可用时的后备。

### 5.6 已装机器的迁移

〔我的决定〕清理要等新系统被确认启动正常（A/B 更新把这次启动标为好之后）才做，重复执行无害。这样如果新系统出问题回滚到旧系统，Chrome sysext 还在，旧系统不会变成没有浏览器：

1. `/var/lib/extensions/google-chrome` 存在 → 删除，`systemctl reload-or-restart systemd-sysext.service`（与现在的刷新方式相同，交给 PID 1）。
2. 删除 `/var/lib/mastersos/chrome`。
3. 删除 `/etc/opt/chrome/policies/managed/mastersos.json` 及空的 `/etc/opt/chrome` 目录树（`etc-policy.conf` 不再声明它们）。
4. 用户资料 `~/.config/google-chrome` 不动。

已在用户会话里的 Chrome 进程不强杀，下次登录起用 Chromium。

### 5.7 云端（私有仓库）

- 控制台删除 Config 编辑页的“Chrome 更新”卡片及其字符串（英文、简体中文）；`config.ts` 里的 `withChrome` 等随之删除；考试模式的 `LOCKED_KEYS` 镜像与公开仓库保持一致。
- 草稿与发布：`chrome` 键按 5.3 处理为已废弃（接受、忽略）；`publish.rs` 里按发布日计算暂停上限的逻辑删除。
- 界面里提到 “Chrome” 的地方，指浏览器的改成 “browser/浏览器”，指策略格式的（`chrome_policy`）保留。
- 集成测试里的 `chrome` 任务桩删除。随 `os.rev` 升级一起改。

### 5.8 文档与技能

- `manifest-spec.md` 与 `skills/mastersos-admin/reference/settings-reference.md`（要求逐字节一致）、`SKILL.md`、`recipes.md`（删“暂停 Chrome 更新”）、`glossary.md`、MCP 的工具说明、`image/README.md`、`keys.md`、`update-channels.md`（考试扩展的 `chrome_base` 等旧 https 路径若已无用，一并清理）。

### 5.9 申请自己的 Google 密钥（与实现并行，由用户办理）

- Chromium 的 API 密钥按 chromium.org 的 “API Keys” 说明在 Google Cloud 项目里申请；但那种密钥只用于开发，不许随产品分发。
- 产品里要用 Safe Browsing：免费的 Safe Browsing API 只限非商业用途，商业用途对应 Google 的付费 Web Risk API。Chromium 内置的 Safe Browsing 客户端能否直接用 Web Risk、需要怎样的协议与额度，要和 Google（Chrome Enterprise / Web Risk 销售或合作渠道）确认。
- 拿到可分发的密钥与书面许可后，按 5.4a 的接口接入，另开一个小改动，不阻塞本设计。

## 6. 验收

〔我的决定〕开发时在 VM 上（lab 镜像）逐项实测；最终验收在 Dell 3420 真机上用 U 盘装正式镜像再做一遍（显卡加速、显示缩放下的 `--app` 标题栏高度只有真机能看出来）。截图全部保留：

1. 断网首次开机：登录页无“正在安装浏览器”；桌面 Dock 第一项是 Chromium，能打开。
2. 登录卡片：联网后学校账号登录走通；卡片只能访问白名单地址；卡片窗口的标题栏裁剪仍正确（`card.js` 的 `TITLE_BAR`，Chromium `--app` 窗口标题栏高度需实测）。
3. `chrome://sandbox` 全绿；`chrome://policy` 显示 mastersos 策略。
4. 网页应用启动器能打开 `--app` 窗口。
5. 考试模式：考试扩展从 `file://` 地址强制安装成功；退出键经 native messaging 生效；NWEA 模拟环境的页面判定通过（必要时联系 NWEA 确认 Chromium 的 UA 可接受）；`kiosk-acceptance.md` 全部项按新路径更新后通过。
6. 迁移：先装旧镜像并让 Chrome sysext 装好，再升级到新镜像：sysext 与 `/var/lib/mastersos/chrome` 被清掉，只剩 Chromium。
7. 控制台：旧设置里有 `[config.chrome]` 的学校，发布不报错，只给 info。

## 7. 留给实现者

- 锁文件格式、升级脚本的语言与细节；构建时用 mkosi 本地包目录还是 `dpkg -i`（须满足 5.1 的依赖要求）。
- 默认浏览器设置放哪个 mimeapps.list。
- `/etc/chromium.d/` 里放哪些参数。
- 新回报项 `browser` 的确切内容格式。
- `[config.chrome]` 废弃后的 lint 代码名与措辞（需进 glossary 与控制台 i18n）。
- 任务拆分与先后，但有一个硬性顺序〔我的决定〕：第一阶段做 5.1 + 5.2 + 5.5，并在删除任何 Chrome 代码之前，用真实网络验证 (a) 学校的 Google 登录在 Chromium 的登录卡片里能走通（Chromium 的 Client Hints 品牌是 “Chromium” 而不是 “Google Chrome”，`image/docs/idp.md` 已把 Google 是否接受受限浏览器列为未决问题），(b) 真实的 NWEA 页面接受 Chromium。任一不通过就停下来找用户，不继续删 Chrome。之后再做 5.3、5.6、考试模式与云端。
