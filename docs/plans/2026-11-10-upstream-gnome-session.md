# 桌面会话改用上游 GNOME 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 普通桌面从 Ubuntu 的 `ubuntu` 会话换成我们自己的 `mastersos` 会话（内容是上游 GNOME），去掉 Yaru、Dock 与 `:ubuntu` 默认值。

**Architecture:** 新会话文件 `mastersos.desktop` 跑 `gnome-session --session=gnome`，gnome-shell 用自有模式 `mastersos.json`
（`parentMode: user`，只开受管提示与托盘两个扩展）。镜像构建时删掉发行版的其它会话文件与 Ubuntu 的其余扩展，并在 postinst 断言。
agent 的锁定扩展列表与 dconf 输出跟着改。

**Tech Stack:** mkosi（Ubuntu 26.04 resolute）、gnome-shell 50、bash、Rust（mastersos-agent）。

**Spec:** `docs/specs/2026-11-10-upstream-gnome-session-design.md`

## Global Constraints

- 工作目录：worktree `/Users/david/projects/arbella/mastersos-gnome`，分支 `feat/upstream-gnome`。
- 公开仓库：提交前跑 `python3 -I tools/check-private.py`；不写主机、账号、学校信息。
- 注释、报错、脚本输出用英文；提交信息用中文，结尾带 `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`。
- 不碰 `image/patches/authd-oidc/*.patch`。
- 会话名 `mastersos`；`XDG_CURRENT_DESKTOP=MastersOS:GNOME`；会话模式 `mastersos`。
- 托盘扩展 uuid：`ubuntu-appindicators@ubuntu.com`，来自包 `gnome-shell-ubuntu-extensions`（resolute 里 Ubuntu 的七个扩展在同一个包里）。
- 构建时删掉的扩展：`ubuntu-dock@ubuntu.com`、`ding@rastersoft.com`、`tiling-assistant@ubuntu.com`、`snapd-prompting@canonical.com`、
  `snapd-search-provider@canonical.com`、`web-search-provider@ubuntu.com`。
- postinst 里每个 `rm` 之后显式核对结果，不对就 `exit 1`（不靠 `set -e`）。
- 不改写 AccountsService 记录（spec：兼容 A/B 回滚）。
- Rust 快检查：`cd core && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`。
- shell 快检查在 colima 的 `ubuntu:24.04` amd64 容器里跑，挂载目录在 `$HOME` 下：`bash image/tests/check-tree.sh`。

## Review Focus

1. 已有账号的 AccountsService 记录写着 `Session=ubuntu`：新镜像上应进 `mastersos`，不能进 `mastersos-kiosk`，也不能登录失败。（GDM 行为，只能在 VM 上验证，见末尾重验证清单第 2、3 项。）
2. 学习模式下 `~/.local/share/gnome-shell/extensions/mastersos-managed@mastersos.org` 有冒名扩展：不加载。Task 3 的测试钉住 `disable-user-extensions=true` 仍被锁住。
3. Chrome 在 `mastersos` 会话里上传文件：文件选择框走 gtk。Task 2 的 check-tree 第 19 项钉住 `mastersos-portals.conf`。
4. 浏览器等待、登录导入、更新提醒三个用户单元在新会话里照常拉起，在锁定应用会话里不拉起。Task 1 的 check-tree 第 46 项及 3015、3223 行一带的循环钉住。
5. 锁住的会话里 agent 写的 `enabled-extensions` 与镜像的 `mastersos.json` 不一致（漏了托盘或受管提示）。Task 3 的 Rust 测试直接读镜像树里的 JSON 比对。

---

### Task 1: `mastersos` 会话与会话模式

**Files:**
- Create: `image/mkosi.extra/usr/share/wayland-sessions/mastersos.desktop`
- Create: `image/mkosi.extra/usr/share/gnome-shell/modes/mastersos.json`
- Delete: `image/mkosi.extra/usr/lib/systemd/user/gnome-session@ubuntu.target.d/`（三个文件）
- Modify: `image/mkosi.postinst.chroot:203-236`（ubuntu.json 的 jq 一段）
- Modify: `image/mkosi.extra/usr/lib/systemd/user/mastersos-{browser-wait,signin-import,update-reminder}.service` 的注释（去掉 ubuntu 会话）
- Modify: `image/mkosi.extra/usr/share/gnome-shell/extensions/mastersos-managed@mastersos.org/extension.js` 第 1、198、226 行一带的注释（`ubuntu.json` → `mastersos.json`；逻辑已认 `parentMode === 'user'`，不改）
- Test: `image/tests/check-tree.sh` 第 46、47、53 项与 3015、3223 行一带的 `for s in ubuntu gnome` 循环

**Interfaces:**
- Produces: 会话文件 `mastersos.desktop`；模式文件 `mastersos.json`，其 `enabledExtensions` 恰为
  `["ubuntu-appindicators@ubuntu.com", "mastersos-managed@mastersos.org"]`（Task 3 读它）。

- [ ] **Step 1: 改 check-tree（先红）**
  - 第 46 项及 3015、3223 行一带：`for s in ubuntu gnome` 改为 `for s in gnome`，并新增：`gnome-session@ubuntu.target.d` 目录存在即 `bad`。
    `grep -vE` 白名单里的 `(ubuntu|gnome)` 改为 `gnome`。
  - 第 47 项：去掉对 postinst 里 `ubuntu.json` jq 的检查，改为核对：
    `jq -e '.parentMode == "user" and .enabledExtensions == ["ubuntu-appindicators@ubuntu.com","mastersos-managed@mastersos.org"]' $gs/modes/mastersos.json`；
    `mastersos.desktop` 含这三行：`Exec=env GNOME_SHELL_SESSION_MODE=mastersos gnome-session --session=gnome`、`DesktopNames=MastersOS;GNOME;`、
    `TryExec=gnome-session`；postinst 含 `/usr/share/wayland-sessions` 的清理与核对（Step 3）。ok 文案相应改写。
  - 第 53 项注释里 "ubuntu session mode" 改为 "mastersos session mode"。

- [ ] **Step 2: 在容器里跑 check-tree，确认第 46、47 项失败**

  Run: `bash image/tests/check-tree.sh 2>&1 | grep -E '^(not ok|bad).*(46|47)'`
  Expected: 有 46、47 的失败行。

- [ ] **Step 3: 实现**
  - `mastersos.desktop`：`[Desktop Entry]`，`Name=MastersOS`，`Comment=This session logs you into MastersOS`，上面三行，`Type=Application`。
    开头注释（英文）说明：为何用自有会话名与模式（spec "方案"一节最后一段），以及 `--session=gnome` 让 `gnome-session@gnome.target.d` 生效。
  - `mastersos.json`：`{"parentMode": "user", "enabledExtensions": [<两个 uuid>]}`。
  - 删除 `gnome-session@ubuntu.target.d/`。
  - postinst：删掉改 `ubuntu.json` 的 jq 一段，改为 `jq -e` 核对 `mastersos.json`（同 check-tree 条件）；删掉
    `/usr/share/wayland-sessions/` 与 `/usr/share/xsessions/` 下除 `mastersos.desktop`、`mastersos-kiosk.desktop` 以外的全部 `.desktop`，
    之后用 `ls` 核对这两个目录里只剩这两个文件（xsessions 为空或不存在），不对就 `exit 1`。末尾 echo 改成 "mastersos.json"。

- [ ] **Step 4: 跑 check-tree，确认 46、47、53 通过，其余没有新增失败**

  Run: `bash image/tests/check-tree.sh`
  Expected: 46、47、53 为 ok；与 `master` 上跑的失败集合相比没有新增（第 51 项此时可能仍按旧规则通过）。

- [ ] **Step 5: 提交** `feat(image): 普通桌面改用自有的 mastersos 会话与会话模式`

### Task 2: 软件包、默认值与文件选择框

**Files:**
- Modify: `image/mkosi.conf:141-152`（GNOME 包段）
- Modify: `image/mkosi.postinst.chroot:162-188`（读回默认值）及 Task 1 那段之后
- Modify: `image/mkosi.extra/usr/share/glib-2.0/schemas/90_mastersos.gschema.override`
- Rename: `image/mkosi.extra/usr/share/xdg-desktop-portal/ubuntu-portals.conf` → `mastersos-portals.conf`
- Test: `image/tests/check-tree.sh` 第 19、51 项

- [ ] **Step 1: 改 check-tree（先红）**
  - 第 19 项：`pc` 改为 `mastersos-portals.conf`；`ubuntu-portals.conf` 存在即 `bad`。
  - 第 51 项：去掉 `:ubuntu` 双份检查与 dash-to-dock 四个 want（`transparency-mode`、`background-opacity`、`custom-background-color`、
    `background-color`）；改为：override 里出现 `:ubuntu]` 或 `dash-to-dock` 即 `bad`；postinst 必须含 `XDG_CURRENT_DESKTOP=MastersOS:GNOME`、
    不得含 `ubuntu:GNOME`。ok 文案去掉 "translucent Dock"。
  - 新增第 N 项（取下一个空号）：`mkosi.conf` 的包表不得有 `ubuntu-session`、`ubuntu-settings`、`yaru-theme-*`，必须有
    `gnome-shell-ubuntu-extensions`；postinst 必须对 Global Constraints 里六个 uuid 逐个删除并核对。

- [ ] **Step 2: 跑 check-tree，确认 19、51 与新项失败**

- [ ] **Step 3: 实现**
  - `mkosi.conf`：去掉 `ubuntu-session`、`yaru-theme-gnome-shell`、`yaru-theme-gtk`、`yaru-theme-icon`；加 `gnome-shell-ubuntu-extensions`
    （注释：只为托盘扩展，其余六个在 postinst 删掉）。
  - gschema override：删掉所有 `:ubuntu` 段与 `[org.gnome.shell.extensions.dash-to-dock]` 段，及描述 Dock 的注释；保留
    `favorite-apps`、壁纸、`color-scheme`、`accent-color`、`disable-user-list`。
  - postinst 读回：`dget` 与 dash-to-dock 的循环、`transparency-mode` 检查整段删掉；`gget` 的 `XDG_CURRENT_DESKTOP` 改为 `MastersOS:GNOME`；
    加三条：`org.gnome.desktop.interface gtk-theme`、`icon-theme`、`org.gnome.desktop.sound theme-name` 读回值不含 `Yaru`（不区分大小写）。
    结尾 echo 去掉 "Dock defaults"。
  - postinst 新段：对六个 uuid 逐个 `rm -rf "/usr/share/gnome-shell/extensions/$u"` 后 `[ ! -e … ] || exit 1`；核对
    `/usr/share/gnome-shell/extensions/ubuntu-appindicators@ubuntu.com/metadata.json` 的 `shell-version` 含 `$gsmajor`；
    `dpkg-query -W ubuntu-session ubuntu-settings yaru-theme-gtk yaru-theme-icon yaru-theme-gnome-shell` 任何一个已安装即 `exit 1`。
    若构建时发现 `ubuntu-settings` 被某个必需包硬依赖去不掉，按 spec 改为在 override 里把这三个键设回上游值（`Adwaita`、`Adwaita`、
    `freedesktop`），并把这条断言改为读回值断言。
  - portal：`git mv` 改名，开头注释的 `ubuntu:GNOME` 改为 `MastersOS:GNOME`，内容不变。

- [ ] **Step 4: 跑 check-tree，确认全部通过**

- [ ] **Step 5: 提交** `feat(image): 去掉 ubuntu-session、Yaru 与 Dock，默认值只剩一份`

### Task 3: agent 的锁定扩展与 dconf

**Files:**
- Modify: `core/mastersos-agent/src/system/desktop.rs:21, 120-160, 240-310`
- Modify: `core/mastersos-agent/src/system/desktop/tests.rs:160-230`
- Modify: `core/mastersos-agent/src/system/desktop/legacy_browser.snap`

**Interfaces:**
- Consumes: Task 1 的 `image/mkosi.extra/usr/share/gnome-shell/modes/mastersos.json`。
- Produces: `pub const LOCKED_EXTENSIONS: &[&str] = &["ubuntu-appindicators@ubuntu.com", MANAGED_EXTENSION];`；删除 `DING_EXTENSION`、`DOCK_LAYOUT`。

- [ ] **Step 1: 改测试（先红）**
  - 锁住的会话的测试（tests.rs 160 行一带）期望改为：
    `"disabled-extensions=@as []\n"`、`"disable-user-extensions=true\n"`、`"allow-extension-installation=false\n"`、
    `"enabled-extensions=['ubuntu-appindicators@ubuntu.com', 'mastersos-managed@mastersos.org']\n"`；去掉 dash-to-dock 那条 want；
    `locks` 集合去掉两个 `dash-to-dock` 键（`disabled-extensions` 仍锁）；断言 `k` 不含 `dash-to-dock` 与 `ding@`。
  - `desktop_mode_has_no_locks`：去掉 `dock-position` 与 `dash-max-icon-size…show-mounts` 两条正向断言，改为断言 `k` 不含 `dash-to-dock`。
  - 新测试 `locked_extensions_match_session_mode`：`include_str!` 读 `../../../../../image/mkosi.extra/usr/share/gnome-shell/modes/mastersos.json`
    （按 tests.rs 的实际相对层级），用 serde_json 取 `enabledExtensions`，断言等于 `LOCKED_EXTENSIONS`（顺序一致）。
  - `legacy_browser.snap`：按新输出手改（`disabled-extensions=@as []`、新的 `enabled-extensions`、删掉 dash-to-dock 段与两条锁）。

- [ ] **Step 2: 跑测试确认失败**

  Run: `cd core && cargo test -p mastersos-agent desktop`
  Expected: 上述测试 FAIL。

- [ ] **Step 3: 实现**
  - `LOCKED_EXTENSIONS` 如 Interfaces；doc 注释改为"mastersos 会话模式（`mastersos.json`）开的扩展，与之逐项一致（测试守着）"。
  - `render_dconf` 锁住时写 `disabled-extensions=@as []`（不再写 DING）；删掉 `DOCK_LAYOUT` 的拼接与两段 `show-trash`/`show-mounts`。
  - `LOCKED_KEYS` 删掉两个 `dash-to-dock` 键。文件头第 21 行的 portal 文件名改为 `mastersos-portals.conf`。
  - 其余提到 "Dock" 的注释改为 "Dash"（上游概览里的收藏栏）；`Profile::dock_files` 字段名不改（避免无关改动）。

- [ ] **Step 4: 跑 Rust 快检查（Global Constraints 那一行），全部通过**

- [ ] **Step 5: 提交** `feat(agent): 锁住的会话只开 mastersos 模式的两个扩展，不再写 Dock 设置`

### Task 4: 会话名在测试里的位置

**Files:**
- Modify: `core/mastersos-agent/src/system/guest.rs` 测试段（约 1700-1770、2040-2050）
- Modify: `core/mastersos-agent/src/kiosk_session/tests.rs`（约 330-350、1036、1105-1125）
- Modify: `core/mastersos-agent/src/system/it_account.rs:792`、`core/mastersos-agent/src/system/kiosk/tests.rs:970`

- [ ] **Step 1: 改测试**：把当作"普通会话"的 `ubuntu` 换成 `mastersos`；每处枚举非 kiosk 会话名的列表里同时保留 `ubuntu`
  （旧设备残留记录），并加入 `mastersos`。生产代码不改（它只认 `mastersos-kiosk`）。
- [ ] **Step 2: 跑 Rust 快检查，全部通过**（这些是行为不变的测试改名，预期直接通过；若有失败说明生产代码写死了 `ubuntu`，停下来报告）。
- [ ] **Step 3: 提交** `test(agent): 普通会话改叫 mastersos，保留旧名 ubuntu 的用例`

### Task 5: 文档与收尾

**Files:**
- Modify: `docs/specs/2026-11-04-visual-identity-design.md` §5.3
- Modify: `image/README.md`（若提到 Ubuntu 会话或 Dock）

- [ ] **Step 1**：§5.3 的半透明 Dock 一段前加一行"已被 `2026-11-10-upstream-gnome-session-design.md` 取代（顶栏保留）"；README 同步。
- [ ] **Step 2**：全仓 `git grep -nE 'ubuntu-dock|dash-to-dock|ubuntu\.json|ubuntu-portals|ubuntu:GNOME|gnome-session@ubuntu'`，
  除 `docs/` 下的历史文档与 `image/lab/results/` 外应无结果。
- [ ] **Step 3**：Rust 快检查、check-tree、`python3 -I tools/check-private.py` 全过。
- [ ] **Step 4: 提交** `docs: 视觉设计的 Dock 一节标为被上游 GNOME 会话取代`

## 重验证清单（交给另一个 session，不在本计划内执行）

1. 构建镜像；构建日志里 postinst 的新断言全过。
2. VM 全新安装：新账号首次登录进 `mastersos` 会话（`echo $XDG_SESSION_DESKTOP $XDG_CURRENT_DESKTOP` 为 `mastersos MastersOS:GNOME`）；
   若落到 `mastersos-kiosk` 或登录失败，按 spec 补 GDM 默认会话的落实方式。
3. 从当前正式镜像 A/B 更新到新镜像：已有账号（`Session=ubuntu`）直接登录进 `mastersos`；再回滚到旧槽，仍能登录进 `ubuntu`。
4. 截图（新编号，全留）：登录页、登录后的概览、Dash 收藏、半透明顶栏、受管提示、托盘图标、Chrome 上传文件的选择框、锁定应用会话。
5. 学习模式：放一个冒名 `mastersos-managed@mastersos.org` 到 `~/.local/share/gnome-shell/extensions`，确认不加载。
6. Dell 真机触屏试用：概览、Dash 启动、三指手势、屏幕键盘。
