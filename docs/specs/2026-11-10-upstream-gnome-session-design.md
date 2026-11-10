# 桌面会话改用上游 GNOME（去掉 Ubuntu 会话）设计

日期：2026-11-10　状态：待批准

## 意图

MastersOS 已经在完整地定制 GNOME。Ubuntu 在 GNOME 之上加的那一层（`ubuntu` 会话、ubuntu-dock、DING、tiling-assistant、
Yaru 主题、`[schema:ubuntu]` 默认值）对我们只是负担：触屏体验差，每项外观改动都要写两份（普通的与 `:ubuntu` 的）。
David 裁定：不做对照测试，直接换回上游 GNOME 会话，凭判断推进。目标不是查清触屏问题的根因，而是整体避开 Ubuntu 那一层。

## 目标

- 普通桌面（学生、老师、IT 账号）跑上游 GNOME 的会话与外观：Adwaita 主题、上游概览与 Dash、上游触屏手势。
- 不再装 `ubuntu-session` 与 Yaru；不再有 `:ubuntu` 双份 gschema 默认值。
- 已部署的设备经 A/B 更新后自动换过来，学生不用做任何事。
- 现有功能不退化：受管提示（quick settings 的 "managed by"）、锁住的会话的扩展锁定、Chrome 的文件选择框、登录页、锁定应用会话、
  更新提醒、浏览器登录交接。

## 非目标

- 不换外壳程序本身：mutter、gnome-shell、gdm3 仍用 Ubuntu 26.04 的包（方案 B 不做）。
- 不做常驻底栏。上游 GNOME 没有常驻 Dock，就不要（David 选 1）。触屏优先的自写底栏以后另立项目。
- 不改锁定应用会话（`mastersos-kiosk`，gnome-kiosk）。
- 不换底层发行版。

## 反目标（做到了也算失败）

- 锁住的会话（学习模式、旧的浏览器模式）因这次改动能加载用户自己的 shell 扩展（`~/.local/share/gnome-shell/extensions`），包括与系统扩展
  同 uuid 的冒名扩展。完全模式（`FULL`）今天就允许用户扩展，本设计不改它（实施者的判断，见末尾）。
- 登录后看不到受管提示，或 Chrome 上传、另存为弹不出文件选择框（VM 165 的老问题回来）。
- 已部署设备更新后登录进了错误的会话（比如进了锁定应用会话，或 GDM 找不到会话而失败）。

## 方案（已选 1）

| 方案 | 内容 | 取舍 |
|---|---|---|
| **1. 不要常驻底栏（选定）** | 纯上游：登录后进概览，从 Dash/应用网格启动；agent 写的 `favorite-apps` 照样出现在 Dash | 最小、最"原装"、触屏手势全是上游原生；外观不再是 ChromeOS 式底栏 |
| 2. 装上游 dash-to-dock | 保留现在的底栏外观 | 与 ubuntu-dock 同一份代码，等于把 Ubuntu 那层装回来，与意图相反 |
| 3. 自写触屏底栏扩展 | ChromeOS 式、触屏优先 | 1–2 周且每个 GNOME 版本都要跟；留作后续项目 |

会话层面另考虑过"直接用发行版的 `gnome` 会话"：它的会话模式是 gnome-shell 内置的 `user`，没有 JSON 可加 `enabledExtensions`，
锁住的会话（`disable-user-extensions=true`）就加载不了受管提示扩展；改成锁 `enabled-extensions` 而不关用户扩展，又会让同 uuid 的
用户扩展冒名顶替系统扩展（用户目录优先）。所以用自己的会话名与会话模式，做法与 Ubuntu 的 `ubuntu` 会话相同，只是内容是上游的。

## 设计

### 会话

- 新增 `/usr/share/wayland-sessions/mastersos.desktop`：
  `Exec=env GNOME_SHELL_SESSION_MODE=mastersos gnome-session --session=gnome`，`DesktopNames=MastersOS;GNOME;`。
  - `XDG_SESSION_DESKTOP=mastersos`，`XDG_CURRENT_DESKTOP=MastersOS:GNOME`（仍含 `GNOME`，按 GNOME 判断的应用不受影响）。
  - `--session=gnome` 让 systemd 用户实例走 `gnome-session@gnome.target`，现有的 `gnome-session@gnome.target.d/` 三个
    drop-in（browser-wait、signin-import、update-reminder）照用。
- 新增会话模式 `/usr/share/gnome-shell/modes/mastersos.json`：`parentMode: "user"`，`enabledExtensions` 列出受管提示扩展与
  AppIndicator 扩展。这份文件是我们的，放进 `mkosi.extra`，postinst 不再用 jq 改发行版的 `ubuntu.json`，只核对它。
- 删掉 `gnome-session@ubuntu.target.d/` 三个目录。
- GDM 只剩 `mastersos` 与 `mastersos-kiosk` 两个可选会话：发行版的 `gnome.desktop`、`gnome-xorg.desktop` 等由 postinst 删除，
  并核对删干净。GDM 的默认会话必须是 `mastersos`（不能按字母落到 `mastersos-kiosk`）；用 GDM 的 `[daemon] DefaultSession=`
  还是由 agent 写 AccountsService 记录，由实施者在 VM 上确认哪种在 gdm3 50 上可靠（见"留给实施者"）。

### 软件包

- 去掉：`ubuntu-session`、`ubuntu-settings`（Ubuntu 不带 `:ubuntu` 的那份默认值，指向 Yaru 的 GTK、图标、声音主题）、
  `yaru-theme-gnome-shell`、`yaru-theme-gtk`、`yaru-theme-icon`。若某个必需的包硬依赖 `ubuntu-settings` 去不掉，就在我们的 override
  里把这几个键改回上游值。postinst 断言 `gtk-theme`、`icon-theme`、`sound-theme` 的默认值都不含 Yaru。
- 加：`gnome-shell-ubuntu-extensions`。resolute 里 Ubuntu 的七个扩展（托盘 `ubuntu-appindicators@ubuntu.com`、ubuntu-dock、DING、
  tiling-assistant、两个 snapd、web-search-provider）在这同一个包里；我们只要托盘，postinst 删掉其余六个扩展目录并逐个断言不在，
  核对托盘扩展的 `shell-version`。

### 默认值（gschema override）

- 删掉所有 `:ubuntu` 段与 `dash-to-dock` 段；保留壁纸、`color-scheme`、`accent-color`、`favorite-apps`、登录页无用户列表。
- check-tree 第 51 项（`:ubuntu` 双份必须相同）改为：override 里不得出现 `:ubuntu` 段，不得出现 `dash-to-dock`。
- postinst 读回默认值时用 `XDG_CURRENT_DESKTOP=MastersOS:GNOME`；删掉 dash-to-dock 的读回。

### 文件选择框

- `ubuntu-portals.conf` 改名为 `mastersos-portals.conf`（`XDG_CURRENT_DESKTOP` 的第一项是 `MastersOS`，xdg-desktop-portal
  先找它），内容不变：照抄 `gnome-portals.conf`，多一行 `FileChooser=gtk`。`desktop.rs` 文件头的说明随之改。

### agent

- `desktop.rs`：
  - `LOCKED_EXTENSIONS` 改成 mastersos 会话模式里的那一组（AppIndicator、受管提示），与 `mastersos.json` 一致；加一条测试
    读镜像树里的 `mastersos.json` 比对（或由 check-tree 比对）。
  - 删掉 `DOCK_LAYOUT` 和 `LOCKED_KEYS` 里两个 `dash-to-dock` 键；`DING_EXTENSION` 及 `disabled-extensions` 里对它的处理一并删掉。
  - `favorite-apps` 照写（上游 Dash 读它）。`Profile::dock_files` 的含义不变（Nautilus 进不进收藏）。
  - 快照 `legacy_browser.snap` 与测试随之更新。
- 会话名：测试里当作"普通会话"的 `ubuntu` 换成 `mastersos`；保留一条 `ubuntu`（旧设备残留的记录）仍被当作非 kiosk 会话处理的测试。
- 迁移：**不改写** AccountsService 记录。A/B 更新可能回滚到旧槽，旧镜像没有 `mastersos.desktop`；改写了的记录在旧槽上反而会出问题。
  靠 GDM 的规则：记录里的会话不存在时用默认会话。新镜像上 `Session=ubuntu` 落到默认的 `mastersos`，回滚后旧镜像上
  `Session=mastersos` 落到它的默认 `ubuntu`。这一点两个方向都要在 VM 上验证；若 gdm3 50 不按此回退，再补一个只在新槽确认
  可用后才执行的迁移。

### 扩展

- `mastersos-managed`：注释与判断从 `ubuntu` 模式改成 `mastersos` 模式（第 1、198、226 行一带）；在 `parentMode: "user"` 的
  自有模式下仍能识别"普通桌面"与锁屏。
- `mastersos-managed` 的样式表里还有视觉设计 §5.3 的半透明顶栏，限定在 `ubuntu` 模式；保留它，改为限定在 `mastersos` 模式。
- `mastersos-login`：不依赖 Ubuntu 会话，不改；但 Yaru 去掉后 GDM 的 shell 主题会变成上游 Adwaita，登录页要重截图核对。

### 文档

- `docs/specs/2026-11-04-visual-identity-design.md` §5.3 的半透明底栏一节（只是 Dock 部分，顶栏保留）标注"已被本设计取代"。

## 约束

- 镜像只读、A/B 更新：`/usr` 下删改发行版文件可以在构建时做，但每一项都要在 postinst 里断言结果，不对就让构建失败（现有惯例）。
- 公开仓库：不写任何主机、账号、学校信息。
- 用户可见文字走 i18n（本设计预计不新增界面文字）。
- 登录扩展钉住 gnome-shell 版本，本设计不改版本。

## 验证

- 快检查：`cargo fmt/clippy/test`、`bash image/tests/check-tree.sh`、受影响的 shell 测试（ubuntu:24.04 容器）。
- 重验证（按惯例攒成清单交给另一个 session）：镜像构建；VM 上截图核对登录页、登录后的概览、Dash 收藏、受管提示、
  AppIndicator 托盘、Chrome 上传文件的选择框、锁定应用会话、学习模式下放进 `~/.local` 的扩展不加载；从旧镜像 A/B 更新到新镜像
  后已有账号能直接登录进 `mastersos` 会话，再回滚到旧槽仍能登录进 `ubuntu` 会话；半透明顶栏仍在；Dell 真机触屏试用。

## 留给实施者

- GDM 默认会话的落实方式（`DefaultSession=` 或 AccountsService），以 VM 上新账号首次登录进的是 `mastersos` 为准。
- AppIndicator 包的确切包名与 uuid，以 resolute 的包为准。
- 去掉 Yaru 后 gdm 的 shell 主题是否还经 `update-alternatives` 指向 Yaru 的 gresource；若是，postinst 指回上游并断言。
- 删除发行版会话文件的确切清单（`wayland-sessions/` 与 `xsessions/` 下除我们两个以外的全部）。

## 设计者的判断（未经 David 逐条确认）

- 不改写 AccountsService 记录，靠 GDM 回退到默认会话，以兼容 A/B 回滚。
- 去掉 `ubuntu-settings`，而不是保留后再覆盖。
- 完全模式下用户扩展维持现状（今天的 Ubuntu 会话也允许），不在本设计里收紧。
- 半透明顶栏保留，跟到 `mastersos` 模式。
- 自有会话名 `mastersos`，`XDG_CURRENT_DESKTOP=MastersOS:GNOME`。
