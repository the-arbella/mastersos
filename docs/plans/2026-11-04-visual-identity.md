# MastersOS 外观 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 品牌素材进库；开机从 initrd 起是 MastersOS 的 Plymouth 画面；桌面默认浅色 + 白天壁纸，深色换夜间壁纸；登录页用夜间壁纸与毛玻璃卡片；Dock、顶栏半透明；关于页有 logo。

**Architecture:** 素材的母版与生成器在 `image/brand/`，开发者用 `render.sh`（无头 Chrome + Pillow）出图，产物提交进 `image/mkosi.extra`（Plymouth 主题另复制一份进 `image/mkosi.initrd.conf/mkosi.extra`，check-tree 比对两份一致）。
GNOME 的默认值全部走 `90_mastersos.gschema.override` 并在 postinst 读回；登录页、锁屏、顶栏只改两个现有扩展。构建时不渲染。

**Tech Stack:** SVG/HTML、无头 Chrome、Python（Pillow、fontTools，只在开发者机器上）、Plymouth two-step、GNOME Shell 50 扩展（GJS + St CSS）、mkosi、bash。

**Spec:** `docs/specs/2026-11-04-visual-identity-design.md`

## Global Constraints

- 品牌值以设计文档第 3 节为准（logo 几何、颜色）。效果图源文件：`.superpowers/brainstorm/81096-1793775885/sources/`（`wallpaper4.html`、`system.html`、`logo-final.html`）。
- 产物路径：`/usr/share/backgrounds/mastersos/mastersos-day.jpg`、`mastersos-night.jpg`（3840×2400）；`/usr/share/gnome-background-properties/mastersos.xml`；
  `/usr/share/icons/hicolor/<N>x<N>/apps/mastersos-logo.png`（N = 16 24 32 48 64 128 256 512）、`scalable/apps/mastersos-logo.svg`、`symbolic/apps/mastersos-logo-symbolic.svg`；
  `/usr/share/plymouth/themes/mastersos/`；`/usr/share/mastersos/brand/wordmark-light.svg`。全部产物合计 ≤ 15 MiB。
- 桌面默认 `color-scheme='default'`（浅色）。登录页背景用夜间壁纸。不新增任何需要翻译的字符串。
- 安装器 `plymouth.enable=0` 不变；安装与启动阶段的屏幕文字只用英文。
- 锁住模式（`legacy_browser.snap`）的 agent 输出逐字节不变；本计划不改 agent。
- 注释与脚本输出英文；提交信息中文；提交前 `python3 -I tools/check-private.py`；shell 测试在 `ubuntu:24.04` amd64 容器或远程测试机跑。
- 截图全部保留、新编号，不删不覆盖，汇报列路径。

## Review Focus

1. **TPM 解锁失败要输恢复密钥**：Plymouth 在 initrd 里接管 ask-password，必须出现密码框、输对能进系统。测试：Task 5 VM 验收（清掉 TPM 策略或换 PCR 后开机）。
2. **恢复出厂确认在 initrd 里读键盘**：Plymouth 盖着控制台时提示看不见。测试：Task 3 给 `mastersos-factory-reset-confirm.service` 加 `ExecStartPre=-/usr/bin/plymouth quit`，check-tree 断言这一行；Task 5 VM 上选恢复出厂，提示看得见、`ERASE` 有效。
3. **RTL 语言**：左下角标志在阿拉伯文下应在右下角，不压住底部按钮。测试：Task 4 按 `Clutter.get_default_text_direction()` 选角；Task 5 阿拉伯文截图。
4. **壁纸压缩后出色带**：JPEG 抹掉颗粒。测试：Task 1 `render.sh` 结束时对两张 JPEG 的天空区域算相邻行亮度差，出现 ≥ 3 级的阶跃且平坦段 ≥ 40 行就失败；Task 5 4K 截图目视。
5. **gschema 引用的路径不存在**（改名、漏提交）→ 灰背景或缺图标。测试：Task 2 check-tree 解析 override 与 XML 里的每个 `file://` 和图标名，逐个确认文件在树里。

---

### Task 1: 品牌母版、生成器与产物

**Files:**
- Create: `image/brand/README.md`、`image/brand/logo.svg`、`image/brand/logo-symbolic.svg`、`image/brand/wordmark.py`、`image/brand/wallpaper.html`、`image/brand/render.sh`、`image/brand/fonts/PlusJakartaSans-SemiBold.ttf`、`PlusJakartaSans-Medium.ttf`、`image/brand/fonts/OFL.txt`
- Create (产物): 上面 Global Constraints 里除 Plymouth 外的全部文件，加 `image/mkosi.extra/usr/share/gnome-background-properties/mastersos.xml`
- Test: `image/tests/check-tree.sh`（新第 51 条）

**Interfaces:**
- Produces: 产物路径（Global Constraints）；`render.sh` 也是 Task 3 的 Plymouth 图片的出处（Task 3 往里加）。

- [ ] **Step 1: 写 check-tree 第 51 条（先失败）**：`ok 51 "brand: wallpapers 3840x2400, logo at every size, background properties, total under 15 MiB"`。用内联 Python 读 PNG 的 IHDR 与 JPEG 的 SOF0/SOF2 取尺寸（不依赖 Pillow）；断言两张壁纸 3840×2400、8 个尺寸的 logo PNG 边长等于目录名、`scalable` 与 `symbolic` SVG 存在且是 XML、`mastersos.xml` 的 `filename` 指白天、`filename-dark` 指夜间且都在树里、`image/brand` 外的产物合计 ≤ 15 MiB。
- [ ] **Step 2: 在容器里跑 check-tree，确认第 51 条 bad。**
- [ ] **Step 3: 母版**：`logo.svg` 按设计文档第 3 节的几何（viewBox 100，含柔光与渐变）；`logo-symbolic.svg` 是单色版（`fill`/`stroke` 用 `#bebebe`，GNOME symbolic 约定，16×16 viewBox 等比缩放）。`wallpaper.html` 由 `sources/wallpaper4.html` 整理：参数 `?m=day|night`，注释英文。
- [ ] **Step 4: `wordmark.py`**：fontTools 把 “Masters”（SemiBold）+ “OS”（Medium，填充不透明度 0.55）转成路径，字距 -0.025em，输出 `wordmark-light.svg`（白字）。
- [ ] **Step 5: `render.sh`**：用 macOS 或 Linux 上的 Chrome/Chromium 无头渲染：壁纸 `--window-size=1920,1200 --force-device-scale-factor=2` → PNG → Pillow 存 JPEG（quality 92，4:4:4 采样）；logo 各尺寸从 `logo.svg` 渲染（每个尺寸单独渲染，不从大图缩）；结束时做 Review Focus 4 的色带检查；脚本 `set -euo pipefail`，缺 Chrome 或 Pillow 时报英文错误退出。
- [ ] **Step 6: 跑 `render.sh` 出全部产物；写 `mastersos.xml`；写 `README.md`（怎么重出、字体许可）。**
- [ ] **Step 7: check-tree 第 51 条 ok；`python3 -I tools/check-private.py` clean。**
- [ ] **Step 8: 提交** `feat(image): MastersOS 品牌素材（logo、文字标志、4K 白天与夜间壁纸）`

### Task 2: GNOME 默认值与关于页

**Files:**
- Modify: `image/mkosi.extra/usr/share/glib-2.0/schemas/90_mastersos.gschema.override`、`image/mkosi.postinst.chroot`（Dock 读回那一段、os-release）
- Test: `image/tests/check-tree.sh`（第 51 条加断言）

**Interfaces:**
- Consumes: Task 1 的壁纸与 logo 路径。

- [ ] **Step 1: check-tree 第 51 条加断言（先失败）**：override 里有 `[org.gnome.desktop.background]` 的 `picture-uri='file:///usr/share/backgrounds/mastersos/mastersos-day.jpg'`、`picture-uri-dark=…night.jpg`、`picture-options='zoom'`；`[org.gnome.desktop.interface]` 的 `color-scheme='default'` 与 `accent-color`；dash-to-dock 的 `transparency-mode='FIXED'`、`background-opacity`、`custom-background-color=true`、`background-color`；每个 `file://` 路径在 `mkosi.extra` 里存在（Review Focus 5）；postinst 的 os-release 有 `LOGO=mastersos-logo`。
- [ ] **Step 2: 确认 bad。**
- [ ] **Step 3: 改 override**：值按设计文档 5.3；`accent-color='orange'`（Task 5 在 VM 上比色后可改 `red`）；`background-opacity=0.45`，`background-color='#14122a'`。
- [ ] **Step 4: postinst**：os-release 加 `LOGO=mastersos-logo`；Dock 读回循环加 `transparency-mode`，另用同一个 `dget` 方式读回 `org.gnome.desktop.background picture-uri` 与 `org.gnome.desktop.interface color-scheme`（不对就 `exit 1`）。
- [ ] **Step 5: ubuntu:24.04 容器里装 `gnome-shell-extension-ubuntu-dock gsettings-desktop-schemas libglib2.0-bin`，放入 override、`glib-compile-schemas`，读回每个键与预期一致（24.04 的 schema 若没有 `accent-color`，这一键在容器里跳过，记下，Task 5 在镜像里核）。**
- [ ] **Step 6: check-tree ok；提交** `feat(image): 默认浅色、白天与夜间壁纸、半透明 Dock、关于页 logo`

### Task 3: Plymouth 开机画面（含 initrd）

**Files:**
- Create: `image/mkosi.extra/usr/share/plymouth/themes/mastersos/{mastersos.plymouth,watermark.png,throbber-0000.png…}`；同一套复制到 `image/mkosi.initrd.conf/mkosi.extra/usr/share/plymouth/themes/mastersos/`；`image/mkosi.initrd.conf/mkosi.extra/usr/share/plymouth/plymouthd.defaults`
- Modify: `image/brand/render.sh`（出 Plymouth 图片并写两份）、`image/mkosi.conf`（`KernelCommandLine` 加 `quiet` `splash`）、`image/mkosi.initrd.conf/mkosi.conf`（`Packages=plymouth`，以及 two-step 所在的包）、`image/mkosi.postinst.chroot`（设默认主题）、`image/mkosi.initrd.conf/mkosi.extra/usr/lib/systemd/system/mastersos-factory-reset-confirm.service`、`image/build.sh`（initrd 清单）
- Test: `image/tests/check-tree.sh`（新第 52 条）

**Interfaces:**
- Consumes: Task 1 的 `logo.svg`、`render.sh`。
- Produces: 主题名 `mastersos`。

- [ ] **Step 1: check-tree 第 52 条（先失败）**：`ok 52 "boot splash: mastersos two-step theme in the image and the initrd (identical), default theme, quiet splash, factory reset confirm quits plymouth, installer keeps plymouth off"`。断言：两份主题目录逐文件 `cmp` 相同；`mastersos.plymouth` 有 `ModuleName=two-step`、`ImageDir=/usr/share/plymouth/themes/mastersos`、`UseProgressBar=true`、`BackgroundStartColor=0x090a16`；`plymouthd.defaults` 是 `Theme=mastersos`；`mkosi.conf` 的命令行有 `quiet` 与 `splash`；恢复出厂确认单元有 `ExecStartPre=-/usr/bin/plymouth quit`；`image/installer/installer.cmdline` 仍有 `plymouth.enable=0`。
- [ ] **Step 2: 确认 bad。**
- [ ] **Step 3: `render.sh` 出 Plymouth 图片**：`watermark.png` 是 M 字形（无图块，白色笔画 + 光点，宽 160 px 的 1 倍图），`throbber-00NN.png` 若干帧是光点的柔光一呼一吸（帧数、节奏实施者定）；黑底透明 PNG；同时写进两棵树。
- [ ] **Step 4: 写 `mastersos.plymouth`**（two-step：水印居中略偏上、进度条在下方、前景色 `0xffb35c`、背景 `0x090a16`，`UseFirmwareBackground` 先设 false，Task 5 在 Dell 上看 BGRT 再定）与 `plymouthd.defaults`；postinst 设主题（resolute 的做法：`plymouth-set-default-theme mastersos` 若存在，否则写 `/usr/share/plymouth/plymouthd.defaults`），并 `test -f` 主题文件。
- [ ] **Step 5: initrd**：`mkosi.initrd.conf/mkosi.conf` 加 Plymouth 包（核对 resolute 里 two-step.so 与 label 插件所在的包名，写在注释里）；恢复出厂确认单元加 `ExecStartPre=-/usr/bin/plymouth quit`（注释：它读键盘，Plymouth 盖着控制台）；`build.sh` 的 initrd 清单加 `usr/sbin/plymouthd`、`usr/bin/plymouth`、two-step 模块、`usr/share/plymouth/themes/mastersos/mastersos.plymouth`、`systemd-ask-password-plymouth.path`。
- [ ] **Step 6: `mkosi.conf` 命令行加 `quiet` 与 `splash`**（注释：lab profile 的 `console=ttyS0` 照样有串口日志）。
- [ ] **Step 7: check-tree ok；shellcheck 过改动的脚本；提交** `feat(image): MastersOS 开机画面（Plymouth，从 initrd 起）`

### Task 4: 登录页、锁屏、顶栏与出错页

**Files:**
- Modify: `image/mkosi.extra/usr/share/gnome-shell/extensions/mastersos-login@mastersos.org/{stylesheet.css,extension.js}`、`image/mkosi.extra/usr/share/gnome-shell/extensions/mastersos-managed@mastersos.org/{stylesheet.css,extension.js}`、`image/mkosi.extra/usr/share/mastersos/kiosk-error.html`
- Test: `image/tests/check-tree.sh`（第 52 条之后新第 53 条）

**Interfaces:**
- Consumes: 夜间壁纸、`wordmark-light.svg`、`mastersos-logo`（Task 1）。
- Produces: CSS 类 `mastersos-brand-corner`（两个扩展共用名字）。

- [ ] **Step 1: check-tree 第 53 条（先失败）**：`ok 53 "login and lock: night wallpaper background, brand corner in both extensions, no blue focus left, kiosk error page uses brand colours"`。断言：login 样式表 `.mastersos-login-background` 有 `background-image: url("file:///usr/share/backgrounds/mastersos/mastersos-night.jpg")` 与 `background-size: cover`；两个扩展的 `extension.js` 都有 `mastersos-brand-corner`；两份样式表里不再有 `#8ab4f8`；`kiosk-error.html` 的底色是 `#090a16`。
- [ ] **Step 2: 确认 bad。**
- [ ] **Step 3: login 样式表**：背景图 + 上下渐暗遮罩（遮罩用 GNOME 登录框外层的半透明渐变实现）；用户名一步的提示区做毛玻璃卡片（半透明 `rgba(20,18,40,0.42)`、1px `rgba(255,255,255,0.12)` 描边、圆角 24、阴影）；输入框聚焦描边 `rgba(255,190,130,0.75)`；所有 `#8ab4f8` 焦点改成 `#ffb35c`；学校卡片保持白底，圆角改 20。具体选择器以 GNOME 50 的 `loginDialog.js` 为准，在 Task 5 的截图里核。
- [ ] **Step 4: 左下角标志**：`mastersos-login` 在登录页加一个 `St.BoxLayout`（类名 `mastersos-brand-corner`，`mastersos-logo` 图标 24 px + `wordmark-light.svg` 高 18 px，不透明度 85%），放在 `Main.layoutManager` 的登录层，贴底 36 px；RTL（`Clutter.get_default_text_direction() === Clutter.TextDirection.RTL`）时贴右；`disable()` 里销毁。`mastersos-managed` 在 unlock-dialog 模式下加同样的东西（只在锁屏模式显示，回到 user 模式隐藏）。
- [ ] **Step 5: 顶栏与快捷设置**：`mastersos-managed` 样式表在 user 模式给 `#panel` 半透明深色（`rgba(8,8,20,0.55)`，见设计 §5.5；概览与锁屏按 GNOME 原样，`currentMode === 'user'` 或 `parentMode === 'user'` 时才加类：桌面的模式是 ubuntu）；快捷设置那一行没有学校 icon 时用 `mastersos-logo-symbolic`。
- [ ] **Step 6: `kiosk-error.html` 底色 `#090a16`、强调色 `#ffb35c`（文字不改）。**
- [ ] **Step 7: check-tree ok；`gjs` 语法检查两个 `extension.js`（`gjs -m` 不可用时 `node --check` 退而求其次）；提交** `feat(image): 登录页与锁屏用夜间壁纸和毛玻璃卡片，角落加 MastersOS 标志`

### Task 5: lab 镜像、VM 逐屏验收与修正

**Files:** 视截图结果修改 Task 2–4 的文件；截图存 `image/lab/results/2026-11-04-visual-identity/`（编号 `NN-<screen>.png`，不覆盖）。

- [ ] **Step 1: 合并 master 后在构建机出 lab 镜像**（按 `image/README.md` 的 lab 流程），装进 PVE 上的测试 VM。
- [ ] **Step 2: 开机过程截图**：固件后到登录页至少 3 张（Plymouth 早期、进度、GDM 接管），确认没有文字闪现、没有长黑屏。
- [ ] **Step 3: 反目标逐项**（Review Focus 1、2）：恢复密钥提示（让 TPM 解锁失败）、恢复出厂确认（看得见、`ERASE` 有效、答错照常开机）、/usr 自修消息（`--broken userspace` 的镜像）、首次开机提示。
- [ ] **Step 4: 登录页**：英文、中文、泰文、阿拉伯文各一张；学校卡片一张；锁屏一张；完整桌面、学习模式、访客各一张；深色模式一张；设置 → 外观、关于页各一张。白天壁纸的桌面截图单独发给用户过目。
- [ ] **Step 5: 每张与效果图并排对比，列差异；修 Task 2–4 的文件（强调色 `orange`/`red` 的取舍、毛玻璃观感、标志位置），重出镜像、补截图，直到差异只剩设计文档第 3 节说明的示意项。**
- [ ] **Step 6: Dell 真机**：开机画面（定 `UseFirmwareBackground`）、高分屏壁纸清晰度、登录页；改动提交。
- [ ] **Step 7: 全仓检查**：`cd core && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`（远程测试机）、`bash image/tests/check-tree.sh`；提交** `test(image): 外观 VM 与真机验收截图`
