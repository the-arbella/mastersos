# 第三方 .deb 应用（`[config.apps.deb]`）

**状态：** 设计，待批准。

**裁定（David，2026-11-10）：**

1. .deb 应用是**第三方应用，不属于系统**：与 `apps.flatpak` 并列，一条记录写名字、.deb 下载链接、是否锁定模式。
2. **通用**，不为某个厂商写死；只收 **Ubuntu 的 .deb**（不收 rpm 等）。
3. **依赖走 Ubuntu 生态**：缺的包从 Ubuntu 软件源取，源的地址可在设置里指定。
4. 下载链接背后的文件：写了 `sha256` 就固定版本，没写就自动跟随（§4.1）。
5. 不先试跑，直接按本设计开发。

**首个用例：** Pearson TestNav 的 Linux 客户端（`testnav-1.15.7.deb`，分析见 `2026-11-06-testnav-chromeos-mock.md` §4 与本文 §9）。

**相关待办：** Chrome 的 Google apt 更新策略要变更或优化（任务板 #3）。本设计把 `chrome_sysext.rs` 里的下载、验签、
解包、原子互换抽成通用代码，届时一并重审；本设计**不改** Chrome 的行为。

## 1. 为什么

有的考试、教学软件只发 Linux 的 .deb（TestNav 就是），没有网页版，也没有 Flatpak；或者网页版不被厂商认可。
今天的 MastersOS 没法装 .deb：`/usr` 是只读的签名镜像，`apps.kiosk` 的 `exec` 只收 Flatpak id 或镜像 `/usr/` 下的路径。

## 2. 目标、非目标、反目标

**目标**

- IT 在设置里写一条记录，所有设备自己下载、补齐依赖、装好；删掉记录，设备上就卸掉。
- `kiosk = false`：在普通会话（`learning` 与 `full`）的应用列表与 Dock 里，和 Flatpak 应用一样。
- `kiosk = true`：出现在登录界面，从那里进锁定会话（gnome-kiosk，一次性的家目录），全屏只跑它。
- 每个应用的状态回报给 IT（版本、缺的依赖、失败原因）。

**非目标**

- 不运行任何包的安装脚本（`preinst`/`postinst`/…）。
- 不支持带系统服务、内核模块、PAM、polkit 规则等需要改系统的包（这些文件被剪掉，见 §4.3）。
- 不升级、不替换镜像里已有的包或文件。
- 不为某个厂商做特殊处理（TestNav 的 `~/.config/Pearson` 预置等留待以后，§10）。
- 不做 rpm、Snap、AppImage。

**反目标**（做到了也算失败）

- 第三方包能改到镜像里的任何文件，或让系统启动、登录、签名链出问题。
- 镜像升级之后，旧的依赖盖在新镜像的同名文件上。
- 学生正在用这个应用（例如正在考试）时，它被换版本或被卸掉。
- 一台设备换了 .deb 的版本，IT 却看不到。

## 3. 方案

| 方案 | 做法 | 取舍 | 结论 |
|---|---|---|---|
| A 私有目录 | 解到 `/var/lib/…/<id>/`，从那里运行 | 不动 `/usr`；但依赖必须在系统路径上可见（TestNav 直接调 `/usr/bin/xprop`、`/usr/bin/pactl`），私有目录做不到 | 不选 |
| **B sysext** | 应用加上它缺的依赖打成一个 systemd-sysext，合并到只读的 `/usr` 与 `/opt` 上 | 与官方"在 Ubuntu 上 apt install"效果相同；镜像不变、签名仍然有效；Chrome 已经在用同一机制。代价：每次合并都换整个 `/usr` 的 overlay（§4.5 处理时机） | **选这个** |
| C 打进镜像 | 构建时装进镜像 | 厂商条款一般不许再分发，镜像是公开的；每个厂商版本都要重发镜像 | 不可行 |
| Flatpak | 包成 Flatpak | 只适合本来就是 Flatpak 的应用；TestNav 这类要管整个桌面（`ps`、`xprop`、`gsettings`、`dbus-monitor`），沙箱要开太多口子 | 已有 `apps.flatpak`，不变 |

## 4. 设计

### 4.1 设置格式

```toml
[config.apps]
# 可选。缺省：镜像构建时用的 Ubuntu 快照（§4.2）
ubuntu_mirror = "http://th.archive.ubuntu.com/ubuntu"

[config.apps.deb.testnav]
name = "TestNav"
url = "https://download.testnav.com/_testnavinstallers/testnav-1.15.7.deb"
sha256 = "2e06d735…"          # 可选：写了就固定版本
kiosk = true                  # 可选，缺省 false
packages = ["x11-utils"]      # 可选：包没声明、但程序实际要用的 Ubuntu 包
# exec = "/opt/testnav/bin/testnav"   # 可选，见下
# icon = "files/testnav.png"          # 可选，与锁定应用的 icon 规则相同
```

| 键 | 必填 | 规则 |
|---|---|---|
| 表名 `<id>` | 是 | 与锁定应用的 id 规则相同（小写字母开头，只含小写字母、数字、`-`，至多 24 字符）。`kiosk = true` 时与 `apps.kiosk` 的 id 共用一个名字空间（账号都是 `kiosk-<id>`），重名报错；锁定应用的总数（两边合计）仍是至多 32 |
| `name` | 是 | 与锁定应用的 `name` 规则相同 |
| `url` | 是 | `https://`，至多 2048 字节 |
| `sha256` | 否 | 64 个小写十六进制。写了：只装哈希一致的文件，永不自动换版本。没写：自动跟随（§4.4） |
| `kiosk` | 否 | 布尔，缺省 `false` |
| `packages` | 否 | Ubuntu 包名列表，至多 32 个，与主包的依赖一起解析 |
| `exec` | 否 | 绝对路径，在 `/opt/` 或 `/usr/` 下，不含 `..`，不带参数。缺省从包里的 `.desktop` 读（§4.3）；包里没有或有多个可用的 `.desktop` 时必须写。agent 装好之后核对这个路径确实由这个应用的扩展提供 |
| `icon` | 否 | 与锁定应用相同；缺省用 `.desktop` 里的图标 |
| `ubuntu_mirror` | 否 | 在 `[config.apps]`（或 `[defaults]` 的 apps）下，每个分组可以不同；`http://` 或 `https://` 的 Ubuntu 归档根地址（下面要有 `dists/<镜像的发行代号>`）。源本身不需要可信：签名用镜像里的 Ubuntu 归档钥匙验 |

**旧设备兼容：** 新增 manifest feature `deb_apps`（`FEATURE_DEB_APPS`），用了 `apps.deb` 或 `ubuntu_mirror` 的版本，
在最近见过的设备还不认识它时拒绝发布（与 `kiosk_platform` 等一样）。

**合并规则：** 与 `apps.kiosk` 一样按 id 合并（Defaults 与 Config，`drop` 可去掉）；`ubuntu_mirror` 按普通标量继承。

**旧的浏览器模式（`legacy_browser`）：** 与 Flatpak 一样，不装、不显示，但照清单卸。

### 4.2 Ubuntu 源与依赖解析

- **默认源：** 镜像构建时用的 Ubuntu 快照（`snapshot.ubuntu.com` 上 `build.sh` 传给 mkosi 的那个时间点），版本与镜像里的包完全一致。
  镜像要记下这个时间点（新文件，例如 `/usr/lib/mastersos/ubuntu-snapshot`），以及发行代号与 `Repositories`（main、universe、restricted）。
  快照服务经常不可用（`build.sh` 注释），所以快照取不到时退到 `archive.ubuntu.com` 的 `<代号>`、`<代号>-updates`、`<代号>-security`。
  两者不混用：快照能用就只用快照。
- **IT 指定了 `ubuntu_mirror`：** 只用它（`<代号>`、`-updates`、`-security` 三个 suite）。它比镜像新时，偶尔会出现
  "依赖要求比镜像里更新的版本"，按下面的规则报失败。
- **解析用真的 apt，只做"算依赖与下载"：** agent 用一份私有配置跑 `apt-get install --download-only --no-install-recommends`，
  其中 `Dir::State::status` 指向镜像出厂时的 dpkg 记录（`/usr/share/factory/var/lib/dpkg/status`，只读、与镜像一致），
  源列表与 `Dir::Cache`、`Dir::State::lists` 都在 agent 的私有工作目录里，信任的钥匙**只有**镜像里的 Ubuntu 归档钥匙。
  主包作为本地文件传给 apt，`packages` 里的包一起传。
- **解析的结果：** apt 要下载的包 = 镜像里缺的包。**任何会升级、降级或删除镜像里已有包的方案都判失败**
  （`deb:<id>` 报"依赖 X 要求 ≥ v，镜像里是 u"），不装。
- **架构：** 只收 `amd64` 与 `all`。
- **所有 .deb 应用一起解析（我的决定）：** 全部应用的主包与 `packages` 放进**同一次** apt 解析，得到一组版本一致的依赖。
  这样两个应用不会各带一份不同版本的同一个包、在合并后的 overlay 里互相遮住。依赖不放进各应用的扩展，统一放进一个共享扩展
  `app-deps`（§4.3）。代价：改一个应用的记录可能让共享依赖变化，所以换 `app-deps` 时，任何一个 .deb 应用正在使用都要推迟（§4.5）。
  用默认源（冻结的快照）时依赖版本基本不动，实际很少发生。
- **缓存依赖包（我的决定）：** 下载过的依赖 .deb 留在工作目录里，按需清理（只留当前解析结果用得到的）。镜像升级后先用这份缓存
  作为本地源离线重新解析（§4.6），不必联网。

### 4.3 组装扩展

每个应用一个扩展目录 `/var/lib/extensions/app-<id>`，只放**主包**；所有应用共用的依赖放在一个扩展 `app-deps`（§4.2）。
名字与 Chrome 的 `google-chrome` 不冲突。内容：

1. 主包、依赖包分别用 `dpkg-deb -x` 解到各自的树（不跑安装脚本）。
2. **只留 `usr/` 与 `opt/`**，其余顶层（`etc/`、`var/`、`lib/` 之类）删掉。Ubuntu 的 usrmerge 包不应带 `lib/`；带了的话删掉并记一条。
3. **主包（厂商的，没有 Ubuntu 签名）用允许清单（我的决定）：** 只留 `opt/**`、`usr/bin/*`、`usr/share/{applications,icons,pixmaps,doc,man,metainfo,mime/packages}`、
   `usr/lib/<主包名>/**`；其余删掉并记一条。TestNav 全在 `/opt` 下，不受影响。
   **依赖包（Ubuntu 签名）用剪除清单：** `usr/lib/systemd`、`usr/lib/udev`、`usr/lib/sysusers.d`、`usr/lib/tmpfiles.d`、
   `usr/lib/modules`、`usr/lib/firmware`、`usr/lib/x86_64-linux-gnu/security`（PAM 模块）、`usr/lib/pam.d`、`usr/share/polkit-1`、
   `usr/share/dbus-1/system.d`、`usr/share/dbus-1/system-services`、`usr/lib/extension-release.d`（之后我们自己写）、`usr/sbin`，
   以及登录界面和 GNOME Shell 会加载的插件目录（GIO 模块、gdk-pixbuf 加载器、GTK 模块、GStreamer 插件等）。
   清单的最终形状交给实现者，原则是：会被系统服务、登录、权限路径或系统进程加载到的一律剪掉。
4. **不盖镜像的文件：** 树里任何一个文件或链接，镜像的 `/usr` 已有（以出厂 dpkg 记录的文件清单 `info/*.list` 为准，实现者也可直接读
   erofs 下层），或当前根分区的 `/opt` 里已有（`/opt` 不在签名镜像里，在可写的根分区上），就删掉并记一条。
   主包与 `app-deps` 之间、两个主包之间有同一路径：后组装的那个判失败。
5. **去掉 setuid/setgid 位**，并在回报里列出。
6. **`.desktop`：** 依赖包带的 `.desktop` 全部删掉。主包的 `.desktop` 先在 `usr/share/applications/` 找，没有再在整棵树里找
   （TestNav 的在 `/opt/testnav/lib/testnav-testnav.desktop`，由 `postinst` 注册）。只认 `Type=Application`、没有 `NoDisplay=true`
   与 `Hidden=true` 的。恰好一个就用它的 `Exec`（去掉 `%u` 一类的占位）、`Icon` 和 `MimeType`；零个或多个时必须写 `exec`。
   主包原来的 `.desktop` 也删掉，由我们写一份 `usr/share/applications/mastersos-app-<id>.desktop`：`Name` 是 `name`，
   `Exec` 与 `MimeType` 来自包（或 `exec`），`Icon` 来自 `icon` 或包。
   `kiosk = true` 时这份 `.desktop` 写 `NoDisplay=true`（普通会话的列表里不出现，但 `tnav:` 这类链接的关联保留）。
7. 写 `usr/lib/extension-release.d/extension-release.app-<id>`（§4.6 的版本绑定）。
8. 记下组装结果（主包版本、依赖包与版本、剪掉的路径、清掉的 setuid 位），写在工作目录里，回报用。

换版本沿用 Chrome 的做法：组装到 `<ext>.new`，`renameat2(RENAME_EXCHANGE)` 原子互换，合并，合并成功才删旧的，失败就换回去再合并。

### 4.4 获取 .deb 与更新

- **写了 `sha256`：** 下载、核对、存进工作目录（`/var/lib/mastersos/deb-apps/<id>/`，0700）。只要缓存还在、哈希一致，就不再下载。
  IT 改了 `url` 或 `sha256` 就重新下载。
- **没写 `sha256`：** 每天检查一次（启动后随机等 0–30 分钟，与 Flatpak 的每日更新一样错开），用 `ETag` / `Last-Modified`
  做条件请求；变了才下载、组装、换版本。https 的证书由系统 CA 验。
- 每个 .deb 至多 2 GiB。下载照 Chrome 的 `download_deb` 的写法（流式、超时、大小上限、边下边算 sha256），抽成共用代码；
  第一版**不做断点续传与限速**（agent 里目前没有这类代码），中断就整个重下。`ETag`/`Last-Modified` 的记录是新写的。
- 与 Flatpak 一样是**后台任务**，不挡住设置的应用、锁定与登录。
- **依赖的更新：** 以下任一变化就重新解析并组装：主包变了、`packages` 变了、`ubuntu_mirror` 变了、镜像版本变了（§4.6）。
  用默认源时依赖跟镜像一起冻结、跟镜像一起更新；IT 指定源时每天随主包的检查一起重新解析一次。

### 4.5 合并的时机

- **考试静默优先**（`2026-11-10-exam-quiet-design.md`）：任何锁定会话进行中，.deb 应用不下载、不组装、不合并，正在下载的停掉。
  下面的规则只用在没有静默的时候。

- 合并或刷新换掉的是整个 `/usr` 的 overlay，所有 sysext 共用。**同一时间只有一个合并者**：.deb 应用任务与 Chrome 任务
  持同一把合并锁（新增），刷新命令沿用 `chrome_sysext::refresh_cmd`。刷新之后 exec-block 照旧由 systemd 的 drop-in 重挂。
- **正在使用就不换：** 换版本或卸载之前，看有没有进程的可执行文件落在这个应用的扩展里（`/proc/*/exe` 指向 `/opt/<…>` 或扩展提供的
  `/usr` 文件），以及这个应用的锁定账号有没有会话。有就推迟到下一轮（每小时一轮），回报"等待应用关闭"。换共享的 `app-deps` 时，任何一个 .deb 应用在用都推迟。
  **第一次安装不受此限**（没有旧版本在用）。
- 普通会话里新装好的应用，Dock 与列表在下一次登录才出现（与 Chrome 相同，GNOME Shell 不重读合并后的 `/usr`）。

### 4.6 镜像升级

- 扩展绑定镜像版本：镜像的 `/usr/lib/os-release` 加 `SYSEXT_LEVEL=<镜像版本>`，应用扩展的 `extension-release` 写
  `ID=ubuntu` 与同一个 `SYSEXT_LEVEL`。A/B 升级重启后，systemd-sysext 自动不合并旧镜像时组装的应用扩展，旧的依赖不会盖到新镜像上。
  Chrome 扩展仍是 `ID=_any`，不受影响。（实现者须确认 systemd 当前版本对 `SYSEXT_LEVEL` 的匹配规则，不行就由 agent 在合并前挪走。）
- 新镜像上 agent 先**离线**重新解析：源只用缓存的主包与依赖包（§4.2），不联网。新镜像的出厂记录仍然满足这些依赖（通常如此），
  就直接组装、合并，几分钟内恢复，断网也行。离线解析不通过才联网解析。在此之前这个应用不可用：普通会话里没有图标，
  `kiosk = true` 的应用不在登录界面出现（§4.7）。
- 风险写给 IT：系统更新后的头几分钟到一小时里 .deb 应用可能还没就绪；考试日不要让系统更新（已有的更新时段机制）。

### 4.7 两种模式

**`kiosk = false`**
- 由 `desktop` 步骤把 `mastersos-app-<id>.desktop` 加进 Dock，与受管的 Flatpak 应用一样（`learning` 与 `full` 都加）。
- `learning` 模式放行它（与配置里的 Flatpak 一样）。依赖带来的程序没有 `.desktop`，只能经终端运行，而 `learning` 的终端已被 exec-block 堵住。

**`kiosk = true`**
- 复用现有锁定应用的全部机制：账号 `kiosk-<id>`、AccountsService 记录、`mastersos-kiosk` 会话（gnome-kiosk + gnome-session）、
  tmpfs 家目录、会话结束清理、`Get help`。内部把它当作 `LaunchKind::Exec`，目标是 §4.3 得出的路径。
- `exec` 的校验扩展为"Flatpak id、`/usr/` 下的路径，**或这个 .deb 应用的扩展提供的路径**（可在 `/opt/` 下）"；
  lint 只查形状，agent 装好之后查归属。
- **扩展还没合并好（首次安装中、镜像升级后、失败）时不建或停用登录界面上的入口**，免得学生点进去是一个黑屏。
  已有的"起不来就结束会话"的逻辑保留作为后备。
- Chrome 策略、考试扩展、URL 放行名单与它无关：这类应用自带锁定机制（TestNav 自己改 GNOME 的键位与锁定项），我们提供的是锁定会话本身。
- 会话里厂商程序自己下载的补丁（TestNav 的 `~/.config/Pearson`）随 tmpfs 家目录在会话结束时清掉，下次重新下载。第一版接受。

### 4.8 卸载

记录从设置里删掉：在 §4.5 允许时删扩展目录、刷新合并、删工作目录；`kiosk = true` 的同时删账号（与删锁定应用相同）。
回报项随之清掉。

### 4.9 回报

- `deb:<id>`：状态（就绪、安装中、等待应用关闭、失败）、主包的 `Package` 与 `Version`、补的依赖包列表、剪掉的路径数与
  setuid 清单的摘要、失败原因（下载、哈希不符、依赖冲突、找不到可启动的程序、合并失败……）。
- `deb-apps`：整体的错误（例如源取不到、合并锁拿不到）。
- IT 端（mastersos 命令行、MCP 的 schema 与 `mastersos-admin` 技能文档）同步加上 `apps.deb` 与 `ubuntu_mirror`。

## 5. 镜像改动

- 记录 Ubuntu 快照、发行代号、仓库组件（§4.2）。
- `/usr/lib/os-release` 加 `SYSEXT_LEVEL`（§4.6）。
- 确认镜像里有 Ubuntu 归档钥匙（`ubuntu-keyring`），供私有 apt 配置用。
- 不为 TestNav 加包：它缺的东西由 `packages` 与依赖解析补上。

## 6. 安全

- **信任链：** 主包 = 签名的设置（`sha256`）或 https（无 `sha256` 时，信任厂商的下载服务器）；依赖 = Ubuntu 归档签名（镜像里的钥匙）。
  回报里总有实际装的版本，IT 能看到。
- **第三方代码以用户身份运行**，但文件对全系统可见。§4.3 的剪除、不盖镜像文件、去 setuid、不跑安装脚本，保证它改不了系统的启动、登录与权限路径。
- 下载和解析都在 agent 的私有工作目录里，以 root 运行但不执行包里的任何东西（apt 只下载，`dpkg-deb -x` 只解包）。
- 已知的放宽：`kiosk = true` 的应用不受我们的 Chrome 策略约束（TestNav 内嵌自己的 Chromium）；锁定由厂商程序负责。

## 7. 测试

- 单元：设置的解析与 lint（各种非法值、id 与 `apps.kiosk` 重名、总数）、合并规则、`.desktop` 的挑选、剪除与"不盖镜像文件"、
  setuid 清除、`extension-release` 内容、正在使用的判断、各种失败的回报。apt 与下载用现有的 `Runner` 假实现。
- 容器（ubuntu 镜像，按 CLAUDE.md）：真的 apt 用私有配置对一份假的 dpkg status 解析一个小包；真的 `dpkg-deb -x` 与剪除。
- VM 验收（交给重验证批次）：TestNav 1.15.7 `kiosk = true` 装好、登录界面出现、开起来、App Check；一个 `kiosk = false` 的普通 .deb
  出现在 Dock；换 `sha256` 触发换版本；会话里不换；镜像升级后重新组装；删记录后卸干净。

## 8. 留给实现者

- 剪除清单的最终形状（§4.3 第 3 条的原则之内）。
- 合并锁的具体位置，以及从 `chrome_sysext.rs` 抽出多少共用代码（下载、验签以外的部分：解包、互换、刷新、回滚）。
- 私有 apt 配置的细节（`APT::Get::AllowUnauthenticated` 必须关、`Acquire::Languages=none` 之类）。
- "正在使用"判断的实现方式（`/proc` 扫描或 cgroup）。
- 回报项的具体字段名，与现有回报格式一致即可。

## 9. TestNav 1.15.7 对照

- jpackage 打的 Java 应用（自带 JRE 21、JavaFX、JxBrowser），全部在 `/opt/testnav`；`Depends: libfreetype6, pulseaudio-utils`；
  `postinst` 只跑 `xdg-desktop-menu install`；没有 setuid。`.desktop` 在 `/opt/testnav/lib/`，`Exec=/opt/testnav/bin/testnav %u`，
  `MimeType=x-scheme-handler/tnav`。
- 它启动时检查 `/usr/bin/` 下的 `pactl`、`gsettings`、`dconf`、`setsid`、`xprop`、`awk`、`dbus-monitor`，缺一个就报
  "Missing required system command(s)"。`xprop`（x11-utils）不在它的 `Depends` 里，所以样例写 `packages = ["x11-utils"]`。
- GNOME 检测：有 `gnome-shell` **或** `gnome-session` 进程即可（反汇编确认）；锁定会话由 gnome-session 起，预计能过，以 VM 验收为准。
- 它用 `gsettings set` 关键位，锁定会话的 dconf 已锁住这些键，写不进去时它的反应以 VM 验收为准。

## 10. 以后

- 厂商程序的用户目录预置或跨会话缓存（例如 TestNav 的 `~/.config/Pearson` 与 `default` 文件预选学区）。
- `kiosk = true` 的应用也从普通会话进入（锁定应用已有的 `in_session`）。
- Chrome 改用同一条通道或调整更新策略（任务板 #3）。
