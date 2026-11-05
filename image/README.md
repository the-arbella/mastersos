# image

MastersOS 的系统镜像：Ubuntu 26.04（`resolute`）+ GNOME，mkosi v27.1 构建。由试验
`spikes/s2/mkosi/` 提升而来（试验树原样保留作证据）。设计见
`docs/superpowers/specs/2026-10-10-mastersos-design.md` §6，实现计划见
`docs/superpowers/plans/2026-10-12-mastersos-4a-image-platform.md`。

## 形态

- 镜像里只有 ESP 和一套 `/usr`（erofs + dm-verity + 签名）、UKI、systemd-boot；ESP 上是微软签名的
  shim → 我们签名的 systemd-boot（`grubx64.efi`）→ UKI。每台机器第一次启动时在 MokManager 里登记一次我们的
  证书 `keys/mastersos-mok.der`（ESP 根目录有一份），shim、systemd-boot、MokManager 在被标好的开机之后由
  `mastersos-bootloader-update.service` 随镜像更新。详见 `docs/secure-boot.md`。
- 其余分区在首次开机时由 initrd 里的 systemd-repart 按 `/usr/lib/repart.d/` 建：B 槽三个分区、
  256 MiB 的 `mastersos-seed`（恢复出厂时保留；安装器建的盘上是 12 号分区，8–11 号是黄金副本，见「`/usr` 自动修复」）、`MastersOS-root`（LUKS2 + TPM2，放 `/etc`、`/var`、`/home`，
  恢复出厂时重建）。数据分区不绑字面 PCR：首次开机只绑 UKI 里签名的 PCR 11 策略（`.pcrpkey`），恢复密钥托管之后
  agent 再加上只锁 PCR 7 的 pcrlock。TPM 2.0（带 SHA-256 PCR bank）是前提：没有可用 TPM 的机器安装器拒装（Ruling 17）。
  恢复出厂由 IT 控制（Ruling 22）：主路径是面板远程发起（签名的设置包里这台的 `[[device]].reset`，每个请求只执行一次，
  TPM 用不了时不执行）；本机从启动菜单（主 UKI 的 profile 1）发起时，受管的机器先输这台的恢复密钥（对着 LUKS 头核对）
  再打 `ERASE`，未受管的只打 `ERASE`。
  详见 `docs/keys.md`「恢复出厂」。
- initrd 里出事就重启（`mkosi.initrd.conf/` 给 initrd 的 `emergency.service` 换成「10 秒后重启」，命令行带
  `systemd.crash_reboot=1`），带启动计数的版本因此能退回；`rd.emergency=reboot` 是 dracut 的参数，systemd 不认（Task 2 实测）。

## /etc：策略表

`/etc` 的每个顶层项默认是**链接**，指回 `/usr/share/factory/etc/…`，跟着镜像更新走。只有
`etc-policy.conf` 列出的路径例外（lab profile 追加 `etc-policy.lab.conf`）：

| kind | 生成的 tmpfiles | 含义 |
|---|---|---|
| （未列出） | `L /etc/x - - - - /usr/share/factory/etc/x` | 只读、跟镜像走。镜像里本来就是链接的（`os-release`、`localtime`）照抄原来的目标 |
| `copy` | `C /etc/x` | 首次开机拷一次，之后归这台机器（账号、cups、时区、语言、主机名、gdm3） |
| `dir` | `d /etc/x <factory 里的权限>` | 真实目录，子项再逐个按同一规则生成（agent 写的地方） |

`mkosi.finalize` 读策略表生成 `/usr/lib/tmpfiles.d/00-mastersos-factory-etc.conf`，构建日志里打印
三类各多少行。agent 写入的每个目录都必须落在 `copy` 或 `dir` 之下。

已装好的机器升级后某个路径从链接改成 `dir`：tmpfiles 的 `d` 不会替换已有的链接，而 tmpfiles 的
`r` 对非空的真实目录会报 `Directory not empty`（systemd 259 实测），所以改由
`mastersos-etc-migrate.service`（`Before=systemd-tmpfiles-setup.service`）对
`/usr/lib/mastersos/etc-dirs` 里的路径做「是链接就删」。它由 `/usr/lib` 里的
`sysinit.target.wants/` 链接启用，不靠 preset——preset 只在首次开机套用一次，镜像更新后新加的单元
要这样启用。路径从链接改成 `copy` 时同理（tmpfiles 的 `C` 只在目标不存在时才拷）：`/usr/lib/mastersos/etc-copies`
里的路径若是指回 `/usr/share/factory/etc` 同名项的链接（旧策略的 `L`）就删掉，接着 `C` 拷出真文件；指向别处的
链接（`timedatectl` 写的 `/etc/localtime`）不动。4b Task 20 在 VM 165 上发现：从 base-4b 升上来的机器
`/etc/locale.conf` 一直指回 factory，学校设的语言写不进去（`tests/etc-migrate-test.sh`）。

用户单元同理：Debian 的 postinst 与 mkosi 的 `systemctl --global preset-all` 把启用链接放在 `/etc/systemd/user`，而
那时（4b）机器上的 `/etc/systemd` 不跟 factory 走，gpg/ssh-agent 的 socket、`xdg-user-dirs`、用户级 tmpfiles、PipeWire 都不会启用
（4b Task 13、24）。计划 9 起 `/etc/systemd` 与 `/etc/systemd/system` 是策略表里的 `dir`（agent 往
`/etc/systemd/system/user@<uid>.service.d/` 写锁定应用账号的清理 drop-in）：两者的其余子项按同一规则逐项生成——机器上已有的
（首次开机 PID1 的 preset 建的 `*.wants` 等）照旧，机器上没有的成了指回 factory 的 `L`，包括 `/etc/systemd/user`。所以启用链接
仍按下面的办法放在 `/usr`；升级上来的机器上 `/etc/systemd` 下实际生成了哪些 `L` 待 VM 上核对（计划 9 Task 10）。`mkosi.finalize` 调 `user-units.sh`：`/etc/systemd/user` 里的每个链接按它的 `ALLOW` 清单在
`/usr/lib/systemd/user` 的同一路径建链接（`mkosi.extra` 已有的 PipeWire 链接不重复）；`dbus.service` 别名（用户会话总线由
dbus-broker 跑，与发行版相同）要换掉 dbus-user-session 的 dbus-daemon 单元文件，只在原文件是预期的那一个时才换。清单外的
链接、清单里有而包不再启用的、指向别处或悬空的，一律拒绝构建：包多启用一个用户单元时，先看清它、再加进清单。
这些启用链接在 `/usr` 里，`systemctl --global disable` 拿不掉（它只删配置目录里的链接）：要关掉其中一个，从 `ALLOW` 里去掉
（镜像里也就没有了），或者 mask（机器上的 `/etc/systemd/user` 不在策略表里，个人只能 mask 在 `~/.config/systemd/user`）。
浏览器模式的 D-Bus 激活覆盖（`/var/lib/mastersos-public/xdg/dbus-1/services`）由会话总线监视：dbus-broker 与 dbus-daemon 都只看
总线起来时已存在的目录，所以这个目录由 `mastersos.conf` 的 tmpfiles 开机就建，会话中途切模式即时生效（Task 24 复审 I1）。

别的包自己的 tmpfiles 也会在首次开机往 `/etc` 拷东西：Ubuntu systemd 的 `debian.conf` 用 `C!` 拷 `pam.d`、`nsswitch.conf`、
`issue`，先于我们的 `L` 生效，装好的机器上它们就不再跟着镜像更新（Task 12 在 VM 168 上复现）。`mkosi.finalize` 把包的
tmpfiles 里策略表不是 `copy` 的 `/etc` 拷贝行（`C` 加任意修饰）注释掉，注释之前核对 factory 里有这一项。**这条修正只对新装或
恢复出厂之后的机器生效**：之前装好的机器上这三项仍是首次开机拷出来的真实文件，没有迁移（4b）。

PAM 与口令（4a Task 12、4b Task 9；`mkosi.postinst.chroot` 调 `pam-password.sh`，测试 `tests/pam-password-test.sh`）：

- **口令段按用户名分流**。authd 的 Password 段原样留着时，`common-password` 里它是第一个 Primary、`default=die`，后面的
  `pam_unix` 又带 `use_authtok`，本机用户的 `passwd` 与 GNOME 设置里改口令都报 `Authentication token manipulation error`（4a）。
  所以 authd 的 profile 仍去掉 Password 段（`pam_unix` 成为第一个 Primary、不带 `use_authtok`、自己问新口令），pam-auth-update
  之后在它前面插两行：

  ```
  password  [success=1 default=ignore]  pam_succeed_if.so quiet user !~ *@*
  password  [success=2 ignore=ignore default=die authinfo_unavail=ignore]  pam_authd_exec.so --exec-env=CI=1 -- /usr/libexec/authd-pam
  password  [success=1 default=ignore]  pam_unix.so obscure yescrypt
  ```

  名字不含 `@` 的（本机用户、`guest`、root）跳过 authd、只走 `pam_unix`；含 `@` 的（SSO）经 authd 改「本机的离线口令」
  （设在这台机器上、离线登录用的那个，不在学校的身份系统里），authd 成功就落在 `pam_permit`，失败就是失败（`default=die`）。
  authd 那一行是上游 profile 的 Password 行原样，`success=end` 换成实际的跳转数 2。
- **authd 不查终端**。authd 的 auth / account / password 行都带 `--exec-env=CI=1`：authd-pam（Go）一启动，bubbletea 的 `init()`
  就向终端查背景色（`ESC]11;?`、`ESC[6n`），termenv 最多等 5 秒、等的时候读走终端里已有的输入；不回答查询的 pty 上每个
  authd-pam 进程都白等 5 秒（`su` 到 SSO 用户 auth + account 共 10 秒），先敲的字被吃掉。authd 0.6.1 的模块参数
  （`force_native_client` 等）都在这个 `init()` 之后才起作用；`pam_authd_exec.so` 的 `--exec-env` 给 authd-pam 设环境变量，
  termenv 见到非空的 `CI` 就不查（authd 与它的依赖里只有 termenv 读 `CI`）。代价：authd 的终端界面没有颜色。
  仍然会「挂住」的是 `script -qfc 'su …' /dev/null </dev/null` 这类：script 只在开头写一次 `^D`，提示出现之前有任何模块耽搁
  （authd-pam 启动要零点几秒），这个 `^D` 就被 libpam 关回显时的 `TCSAFLUSH` 清掉、提示一直等；去掉 authd、换成
  `pam_exec sleep 1` 也一样（Task 9 在 VM 165 对照过）：这不是 authd 独有的，authd 的参数也改不了。验收用的是「非 root 在
  不回答查询的 pty 里 `su`、给了口令，30 秒内完成」（实测 1.1 秒，改之前 11.2 秒）。
- GDM 发起的改口令（SSO 用户口令过期之类，`gdm-authd` 最后 `@include common-password`）对 SSO 用户同样经 authd 的口令模块
  （4a 时直接落到 `pam_unix`）；Task 9 没有在 VM 上走过这条路。
- 构建时 `pam-password.sh` 先核对装的 authd 恰好是 `AUTHD_VERSION`（现在 `0.6.1ubuntu0.1`，`dpkg-query`）、profile 与它的原文
  逐行相同——profile 的文本在 0.6.1、0.6.4、0.7.1 里一字不差，只核文本挡不住换版本，而 `CI=1` 管不管用取决于二进制。authd 或
  broker 要升版本就改这一处：先重验 `CI=1`、重读 profile，再改版本号与期望文本；不改就构建失败。然后
  核对生成的 `common-password` 与期望文本逐行相同、`common-auth` 与 `common-account` 里 authd 恰好一行且带 `--exec-env`；
  postinst 末尾再核对一次。
- cracklib 的字典在 `/usr/share/mastersos/cracklib/`（`pwquality.conf` 的 `dictpath` 指过去）：libpwquality 默认读
  `/var/cache/cracklib`，而 `/var` 不随镜像发，装好的机器上任何口令都报 `error loading dictionary`，GNOME 的「更改」一直是灰的。
  构建时核对强口令过得了、字典词过不了。

### 设置包的 `files[].dest` / `downloads[].dest` 能写到哪里

agent 放文件只经 `mastersos-agent/src/safefs.rs`：从 `/` 起逐级 `openat(O_DIRECTORY|O_NOFOLLOW)`，最后一级
同样 `O_NOFOLLOW`，**路径上任何一级是符号链接就报 `symlink` 失败**（不跟随、不替换那个链接）。所以
`/etc` 里默认的 `L` 项（指向只读的 `/usr/share/factory/etc/…`）一律写不进去，这是设计，不是 bug。
可写的根（按当前 `etc-policy.conf`）。Task 12（`lab/results/2026-10-14-4a/`）核的是**目录的形态**——哪些是真实目录、
哪些是链接——以及 agent 自己写的几处；**设置包的 `files[]` / `downloads[]` 写进这些位置没有在 VM 上验过**（4a 验收用的设置包
不带文件），那要等 4b 的设置项：

| 位置 | 能不能写 | 说明 |
|---|---|---|
| `dir` 列出的目录：`/etc/NetworkManager`、`/etc/NetworkManager/system-connections`、`/etc/dconf`、`/etc/dconf/db`、`/etc/opt`、`/etc/opt/chrome`、`/etc/opt/chrome/policies`、`/etc/opt/chrome/policies/managed`、`/etc/sudoers.d`、`/etc/polkit-1`、`/etc/polkit-1/rules.d`、`/etc/sane.d`、`/etc/sysupdate.d`、`/etc/authd`、`/etc/default`、`/etc/security`、`/etc/security/namespace.d`、`/etc/systemd`、`/etc/systemd/system`（后四个是计划 9 加的，未上 VM；lab 另有 `/etc/ssh`） | 能（T12：VM 165 的 `etc_policy` 核过 `/etc/NetworkManager/system-connections`、`/etc/opt/chrome/policies/managed` 是真实目录、不是链接；T6：VM 168 上 agent 经 safefs 往 `/etc/sysupdate.d` 写进、删掉四个 transfer）；其余目录只核了「`/etc` 顶层没有策略表之外的真实项」 | 目录本身是真实目录；但其中 factory 里已有的子项按同一规则是 `L`，写到它们下面照样失败（例如 factory 里有的 `/etc/dconf/db/<x>.d`），新名字可以 |
| `copy` 列出的：`/etc/cups`、`/etc/gdm3` 之下，以及 `/etc/passwd` 等文件本身 | 能（T12：`/etc/passwd` 是真实文件；VM 168 上 `mastersos-firstrun` 建用户、本机用户 `passwd` 与 GNOME 设置改口令都写成了账号文件）；`/etc/cups`、`/etc/gdm3` 之下没有单独写过 | 首次开机拷出来的真实文件/目录；账号文件别用设置包覆盖 |
| `/etc` 顶层上 factory 里不存在的新名字 | 没有验过（T12 只核了顶层的真实项都在策略表或已知的开机生成项里） | `/etc` 本身是根分区上的真实目录；包自己的 tmpfiles 建的真实目录同理（构建日志里「交给 … 建真实目录」那几行） |
| `/etc` 里其余已有的项 | 不能 | `L` 链接，报 `symlink` |
| `/var`、`/srv`、`/home` 之下 | 能（T6 / T12：agent 的状态 `/var/lib/mastersos*` 都写在这里，0700）；设置包往 `/var`、`/srv`、`/home` 放文件没有验过 | 加密根分区上的真实目录（`/var/lib/mastersos*` 是 agent 自己的 0700 状态目录，别往里放） |
| `/opt` 之下 | 不能 | Chrome 以 sysext 合并进来（Task 9），sysext 把 `/opt` 挂成只读的 overlay，写入报 `EROFS` |
| `/usr` 之下 | 一律不能 | erofs + dm-verity，只读 |

发布前的 lint（`dest_not_writable`，按这张表报错）留给计划 2 的 lint 一并补。

## 锁定应用（计划 9 Task 8，设计 `docs/superpowers/specs/2026-10-26-mastersos-kiosk-apps-design.md` §4、§5）

镜像这一侧；账号、策略与 `namespace.d` 由 agent 的 `kiosk` 步骤写，`mastersos-kiosk run` 在 agent 里。
写法、入口与退出见 `../README.md`「锁定应用」。**下面的一切还没在 VM 上验过**：验收清单 `lab/kiosk-acceptance.md`（前提里有 lab 的
https 扩展地址与 lab 扩展钥匙的生成），结果进 `lab/results/<日期>-9/`。

- **会话**：`/usr/share/wayland-sessions/mastersos-kiosk.desktop`（不带 `NoDisplay`——带了 gdm3 50 就不认 kiosk 账号记住的会话、改起 ubuntu；kiosk 账号的 AccountsService 记录指向它；GDM 按文件名设
  `XDG_SESSION_DESKTOP`，但要到会话启动时才设，pam-session 改读 AccountsService；会话里再由用户单元 `mastersos-kiosk-guard.service`
  在 `gnome-session-pre.target` 之前核对一次，kiosk 账号不在这个会话就结束它）起 `env DCONF_PROFILE=mastersos-kiosk gnome-session --session=mastersos-kiosk`。gnome-session 50 只靠 systemd：
  `.session` 文件只剩名字，组件写在 `/usr/lib/systemd/user/gnome-session@mastersos-kiosk.target.d/session.conf`——`org.gnome.Kiosk.target`
  （gnome-kiosk 包）与 `org.mastersos.KioskApp.service`（`mastersos-kiosk run`，退出就结束会话），形状照 gnome-kiosk 50 的
  gnome-kiosk-script 会话（resolute 的包里没有 `RequiredComponents`，那是 gnome-session 49 之前的写法）。不装 `gnome-kiosk-script-session`。
- **策略隔离**：`pam-hooks.sh` 往三个 PAM 栈里挨着插两行——守卫 `session [success=1 default=ignore] pam_succeed_if.so quiet user !~ kiosk-*`
  与 `session required pam_namespace.so`：`gdm-password`、`gdm-authd`（`pam-session` 之后、`@include common-session` 之前）与
  `systemd-user`（resolute 的 systemd 装在 `/usr/lib/pam.d`；`pam_limits` 之后、`@include common-session-noninteractive` 与 `pam_systemd`
  之前）。后者是关键（计划 9 Task 8 复审 C1）：gnome-session 50 把 gnome-kiosk 与 `org.mastersos.KioskApp.service`（→ Chrome）当
  `user@<uid>.service` 的单元起，它们在 user manager 的挂载命名空间里，不在 GDM 会话那一侧的。kiosk 账号的
  `/etc/opt/chrome/policies/managed` 换成 `/var/lib/mastersos-kiosk-ns/<账号>`：父目录 root 0000（pam_namespace 的硬性要求），tmpfiles 的
  `D` 每次开机清空；`/etc/security/namespace.init`（替换发行版的，发行版那一段原样保留，原文在 `tests/fixtures/namespace.init.distro`）每次
  把实例定成 root 0755、清空、拷进 `/var/lib/mastersos-public/kiosk/<id>/policies/` 的普通文件（0644）。agent 对每种应用都写这个目录——
  本地程序拿一份禁止一切的默认锁（程序里的链接会在同一个命名空间里起 Chrome，计划 9 终审 I1）；目录不在时 `namespace.init` 照旧留空实例、
  不报错。`mastersos-kiosk run` 再核对一次：网页、PWA 与本地程序都只在自己看到的托管目录里恰好是这个应用那一份策略（与 agent 的字节相同）
  时才起，否则弹中英错误框、结束会话（所以空实例也起不来）。
  **失败的模型**（pam_namespace 1.7.1，Ubuntu 1.7.0-5ubuntu3.2 带了它）：
  - 名单里查不到的名字：跳过（不出错）；名单全查不到：谁都不多实例化。
  - 配置坏了（namespace.conf 打不开、任何 `namespace.d/*.conf` 里有格式错的行）或登录的用户本身查不到（authd 的 NSS 一时出错）：
    pam_namespace 让会话失败——有守卫之后只落在 `kiosk-*` 账号上（守卫自己出错同样是 ignore，pam_namespace 照跑，不会漏）。
  - kiosk 账号的 polydir、实例父目录（不是 root 0000）、unshare、bind 出错：这个 kiosk 会话失败。
  - `namespace.init` 只有**被信号杀死**才让会话失败（实例已经 bind 上去之后才调它），正常退出不论退出码都放行：所以它的 kiosk 那一段
    每条失败路径（含 ERR trap）都 `kill -KILL` 自己（`tests/namespace-init-test.sh` 逐条核对退出码 137）。
  `/etc/security` 与 `/etc/opt/chrome` 是策略表里的 `dir`，`namespace.init` 与 `native-messaging-hosts/` 不在表里——指回 factory，跟着镜像走；
  `policies/managed` 是 `dir`，机器上本来就是真实目录（4a Task 12 在 VM 165 上核过），pam_namespace 绑得上去。
- **按键**：kiosk 会话的 dconf profile `/usr/share/dconf/profile/mastersos-kiosk` 是 `user-db:user` + `file-db:/usr/share/mastersos/dconf/mastersos-kiosk`
  （postinst 用 `dconf compile` 编、逐键核对读出 `@as []` 且不可写）：清空并锁住 Ctrl+Alt+F1…F12 与媒体键里起程序的快捷键。数据库在 `/usr`，
  不经 `/etc`、不靠机器上的 `dconf update`。`/usr/lib/sysctl.d/99-mastersos-kiosk.conf`：`kernel.sysrq = 0`（postinst 核对最后生效的是它）。
- **错误页** `/usr/share/mastersos/kiosk-error.html`（= mastersos-bundle 的 `ERROR_PAGE`）；**考试扩展**的 `kiosk-ext.json` 与宿主清单由
  `build.sh` 打包后经附加树装进镜像（见上「构建」与 `../kiosk-extension/README.md`）。
- 包：`gnome-kiosk`、`zenity`。两个包都没有 `[Install]` 的用户单元、没有 postinst，`user-units.sh` 的清单不用改（构建时它仍会拦下意外）。

## 登录页（设计 `docs/superpowers/specs/2026-11-01-mastersos-login-screen-design.md`，卡片部分见 `2026-10-31-mastersos-login-card-design.md`）

全在 `mastersos-login@` 扩展里（`extension.js` 改 GDM、`area.js` 绘制区域、`card.js` 卡片、`setup.js` 语言屏、`shelf.js` 底栏与提示、`strings.js` 文字），只是界面，不碰 PAM 与密码。

- **绘制区域**：语言屏、用户列表、邮箱输入、学校页面共用顶部栏与底栏之间居中的 76% x 80%（`area.js`）；底栏和提示（断网时带 Retry）在区域外。
- **语言与键盘**：是系统设置，`localectl` 存。第一次到登录页时，`branding.json` 的 `locale_managed` 不为真且 `/etc/locale.conf` 没有 `LANG` 才问；受管机器要等 `status.json` 的 `settings` 为 `ok` 才判断，种子刚装好时不会抢先弹出。语言列表来自镜像的语言包，布局来自 `evdev.xml`，打不出拉丁字母的布局自动加 `us` 第二布局。之后从顶部键盘菜单的 Language 改，学校管语言时这一项不显示。
- **只结束登录页会话**：写完调 `session/auto` 的 Terminate，GDM 用新语言重新拉起。绝不重启 gdm 服务，否则后台桌面一起死。新的登录页用户名可能是 `gdm-greeter-2`，所以卡片浏览器是模板单元 `mastersos-login-browser@<用户>.service`，polkit 规则只放行自己这一个实例。
- **Ubuntu 默认挡着 keymap**：`mkosi.conf` 删掉 `org.freedesktop.locale1.read-only.conf` 和 localed 的 x11-keyboard drop-in，`/etc/X11` 在策略表里可写。系统键盘不会自动进学生桌面，`mastersos-managed@` 的 `session.js` 登录时从 localed 写入 `input-sources`。
- **自己的文字**走 gettext（`login-i18n/`），英文回退；Ubuntu 的文字由全部语言包提供，所有 UTF-8 locale 都生成。`login-browser` 按系统语言给 Chrome 传 `--lang`。
- **学校账号锁屏**：账号在本机没有密码，系统锁屏没东西可比对。Super+L、闲置、合盖都走 `session.js` 的 `LockToGreeter`：黑幕盖住桌面，`Gdm.goto_login_session_sync` 到登录页，桌面留在后台。VT 切回锁定的桌面也回到这里。`unlock-dialog` 模式没有扩展名单，所以 `extension.js` 把自己留在名单里。走完卡片回到同一会话。没有离线解锁：断网时桌面等到联网后 Retry。本地 IT 账号保留系统锁屏。

- **底栏**：Shut down、Browse as Guest、Add person、Apps。访客与 `kiosk-*` 不进用户列表，`Not listed?` 取消。Apps 读
  `/var/lib/mastersos-public/kiosk/<id>/`（`launch.json` 的名字、`icon`，`accountsservice` 里 `SystemAccount=true` 的不列），没有应用就没有这个按钮；
  点一项等于以 `kiosk-<id>` 登录；网页 / PWA 应用先问 NetworkManager，没有网络就留在登录页显示提示（带 Retry），否则学生会停在 Chrome 的错误页上，那里没有 Exit 按钮。Add person 里的「IT 本机账号」链接只换提示文字：名字不带 `@` 就走本机账号。
- **卡片**：`card.js` 把登录对话框隐藏、放开 modal grab，顶栏还能用；Chrome 窗口放进卡片、裁掉它自己的标题栏，多开的窗口一律关掉。Cancel 随时可用，
  键盘是 **Ctrl+Esc**（焦点在 Chrome 里，只有合成器级的抓键收得到；抓键会吞掉按键，单独的 Esc 要留给网页的下拉框与对话框，所以不用它），按钮上写着。
  3 分钟没有操作（键盘鼠标）自动取消。连不上身份系统时卡片里是本地提示与重试。
- **页面不出滚动条**：卡片按屏幕长到放得下 640 CSS 像素高的页面（Zitadel 带语言与主题那一行），屏幕更矮时用 `--force-device-scale-factor` 缩小
  （`card.js` 算好，随网址一起写进运行目录）；再加 `--hide-scrollbars`，更长的页面仍能用滚轮或键盘滚动。
- **被拒的原因**：agent 的 `pam-check` 经 `pam_exec` 说话，到 shell 是 info 消息，而 `gdm-authd` 不算前台服务，上游直接丢掉，只剩一句 “Sorry, that didn’t work”。
  扩展在 `_onInfo` 接下这些（`中文 / English` 按语言取一半），回到邮箱页，把原因常驻在输入框下面；域名不在 `allowed_domains` 里的账号在这里看到要用哪种邮箱。
  这一步在 PAM 的 account 阶段，所以这样的账号是走完学校登录、设完本机密码才被拒的。broker 的提示没有翻译，`strings.js` 把它们列进 gettext，没收录的显示英文。
- **浏览器**：`mastersos-login-browser.service`（系统单元，`User=gdm-greeter`），因为 Chrome 没有按实例的策略，要靠 `BindReadOnlyPaths=` 换掉
  `/etc/opt/chrome/policies/managed`。网址放在 greeter 的运行目录里，`login-browser` 只接受 https；资料在单元的 `PrivateTmp` 里，停下就没了。
  只有这一个单元的启停经 polkit 放给 `gdm-greeter`（`49-mastersos-login-browser.rules`）。
- **AppArmor**：卡片的 Chrome 跑在专用配置 `/etc/apparmor.d/mastersos-login-browser` 里（强制模式），单元用 `AppArmorProfile=` 挂上，前面不带 `-`：配置没载入浏览器就不启动，
  不会退回不受限。只能执行 Chrome 与启动脚本用到的几个 coreutils，只读 Chrome 自己的文件、策略与字体，只写 Wayland 套接字与私有 `/tmp`。进程标签显示为
  `chrome//&mastersos-login-browser`：`User=` 之后的 change_onexec 被内核转成堆叠，再叠上发行版的 `chrome`（`flags=(unconfined)`，不限制任何东西），有效权限就是这份配置。
  其他 Chrome 不受影响。此外还有 `gdm-greeter` 的身份、systemd 的沙箱（`ProtectSystem=strict`、`InaccessiblePaths=`）与 Chrome 自己的沙箱。
  Chrome 或 coreutils 换了路径或多用了工具，这里要跟着改：`apparmor_parser -r -C` 用 complain 模式跑一遍，看 `aa-status` 里 `//null-` 子配置列出的新程序。
- **版本**：动的都是 gnome-shell 的私有接口（`Main.screenShield._dialog`、`_grab`、`AuthPrompt._openWebLoginDialog`、`AuthdSwitchableHandler`……），
  `build.sh` 的 `gnome_shell_pin` 卡住上游版本（Ubuntu 的 `-ubuntu` 修订不算）。换版本要在 VM 上重测再改它。
- 试验：`/usr` 只读，用 `mount --bind` 盖在扩展目录上，再 `systemctl restart gdm`。

## 学校名与 Logo（branding；设计 `docs/superpowers/specs/2026-10-30-mastersos-console-install-defaults-design.md` §14.1）

agent 的 `branding` 步骤（快步骤，开机 GDM 之前也跑，但开机时不联网）把要显示的东西写进公开目录 `/var/lib/mastersos-public/branding/`（0755，文件 0644，无秘密）：

- `branding.json`：`school_name`（`[school] name`，没有就用种子的 `school_name`；两样都没有就什么都不写）、`logo`、`logo_icon`（两张图的绝对路径或 `null`）、`domains`。
- `logo.png`：登录界面的 Logo，管理台在浏览器里做好的 PNG，高 96 px、宽 ≤ 480（GDM 按 48 px 高显示，高分屏 96 px）。GDM 的 dconf 片段
  `/etc/dconf/db/gdm.d/80-mastersos-branding` 只有 `[org/gnome/login-screen] logo=` 一个键，指向它；登录界面横幅只由 `90-mastersos-lock`（锁定提示）写。
- `logo-icon.png`：快捷菜单那一行的图标，40×40（按 20 px 显示）。用户会话里的 `mastersos-managed@` 扩展读 `logo_icon`；`mastersos-login@`
  只读 `school_name` 与 `domains`，「Managed by …」放在左下角那排按钮上方；在用户名那一步它也是 IT 维护账号（`itadmin`）的入口，
  平时看着是普通文字，鼠标移上去或键盘聚焦才显出可点。

两张图各自按设置包里的 `[school] logo_sha256` / `logo_icon_sha256` 从 `<服务端>/logos/<sha256>.png` 下载（≤ 128 KiB、20 秒），sha256 对得上才用；
缓存里已有对得上的就不再下载，设置里没有了就删掉文件。下载失败或不匹配：那一处不显示 Logo、本项报失败、下一轮再试。旧 agent 缓存的 `logo.webp` 见到就删。

## 种子分区

`mastersos-seed-generator`（systemd 生成器）从 EFI 变量 `LoaderDevicePartUUID` 找到启动所在的 ESP
（取不到时退到 `/dev/gpt-auto-root-luks`），只在**那块磁盘上**找 GPT 标签为 `mastersos-seed` 的分区，
按 PARTUUID 生成 `/var/lib/mastersos-seed` 的挂载（`nosuid,nodev,noexec,nofail`）。别的盘、U 盘上
同名的分区一律忽略，记一行到 `/run/mastersos/seed-generator.log`。找不到或分区坏了，机器照常开机。
任何地方都不按标签的 udev 链接找本机分区（`tests/check-tree.sh` 第 6 条）。

agent 的状态在加密根分区上的 `/var/lib/mastersos`（0700）；`/var/lib/mastersos-system` 同样 0700。

种子分区**不加密**：上面的 `fetch_token`、缓存的设置包（可能有 Wi‑Fi PSK）与 `identity.json` 里的托管凭据，拆下硬盘就读得到。
每样秘密放在哪里、机器丢了怎么处理，见 `README.md`「运维与安全」。agent 只在 `/var/lib/mastersos` 里没有状态时读它，
导入时把种子 trust 的指纹随回报上送（只做检测）；4a 留给 4b 与以后的缺口列在 spec §6.12。

## `/usr` 自动修复（黄金分区；设计 `docs/superpowers/specs/2026-10-27-mastersos-usr-self-repair-design.md`）

系统盘上多放一份「被标过好的最新版本」的黄金副本；活动槽坏了，下次开机在 initrd 里（`/usr` 还没挂上）从它逐块拷回去。

### 分区布局（安装器建，最小盘 48 GiB）

| 号 | 分区 | 大小 | 谁建 |
|---|---|---|---|
| 1 | ESP（FAT 卷标 `MASTERSOS`） | 1 GiB | 安装器 |
| 2–4 | A 槽（usr-verity-sig、usr-verity、usr） | 16 KiB、400 MiB、8 GiB | 安装器（从 U 盘逐块复制） |
| 5–7 | B 槽（同上） | 同上 | 首次开机的 repart |
| 8 | `mastersos-golden-sig` | 16 KiB | 安装器 `install.repart.d/25-golden-sig.conf` |
| 9 | `mastersos-golden-verity` | 400 MiB | `26-golden-verity.conf` |
| 10 | `mastersos-golden-usr` | 8 GiB | `27-golden-usr.conf` |
| 11 | `mastersos-golden-esp`（vfat，卷标 `MOS-GOLDEN`，`Flags=0x2` 目前不生效，见下；放当前版本的 UKI 与清单） | 512 MiB | `28-golden-esp.conf` |
| 12 | `mastersos-seed` | 256 MiB | `30-seed.conf` |
| 13 | `MastersOS-root`（LUKS2） | 余下 | 首次开机的 repart |

黄金分区只在安装器的定义里：首次开机的 `/usr/lib/repart.d/` 不认识它们、恢复出厂不碰它们。类型 UUID 是我们自己生成的固定值
（不是 `usr`/`esp`），gpt-auto、sysupdate 的 `MatchPartitionType=`、bootctl 都看不到。没有这四个分区的机器（试点机、安装 U 盘）
initrd 里什么都不做（不写开机标记、不核对），用户态只检测与上报。安装器把第 8 号（golden-sig）清零：`--empty=force` 只重写分区表，
旧安装留下的有效签名会原样留在同一扇区。新装机器的内置 ESP 与黄金 ESP 的 FAT 卷标由安装器在 repart 之后用 `fatlabel` 设（`MASTERSOS`、`MOS-GOLDEN`）：MokManager 的 “Enroll key from disk” 按 FAT 卷标列固件看得见的卷。
黄金 ESP 的定义里留着 `Flags=0x2`（GPT 属性第 1 位，No Block IO Protocol）表示意图，但 PVE 实测 systemd-repart v259 不写第 0–2 位，属性是 0，
MokManager 的列表里**照样有 `MOS-GOLDEN`**（排在 `MASTERSOS` 后面）。真正的防线是卷标 `MOS-GOLDEN` 加结束屏第 4 步的
`Choose MASTERSOS (not MOS-GOLDEN)`；帮助台的步骤也要写成「选 `MASTERSOS`」，不要写成「选唯一的一项」。黄金 ESP 按类型 UUID 找、用户态与 initrd 经 Linux 读，不经固件；旧机器不变。
`tests/check-tree.sh` 第 36、37 条核对分区定义与两份 `golden-lib` 逐字节相同。

### 单元与脚本

| 单元 | 在哪 | 做什么 |
|---|---|---|
| `mastersos-usr-repair.service` | initrd，每次开机，在 `systemd-veritysetup@usr.service` 与 `/usr` 挂载之前 | 脚本 `usr-repair`：没有黄金分区就退出 0；上一次开机没走到 boot-complete（`boot-pending` 还在）时把活动槽完整读一遍，坏了就修；有 `repair-usr` 请求时也先这样读一遍（槽好就只删请求），被打断的修复直接重做。任何意外都退出 0，绝不挡开机。只用 `golden-lib` 的 `INITRD_TOOLS` |
| `mastersos-boot-ok.service` | 用户态，`boot-complete.target` 之后 | `integrity --boot-ok`：删 ESP 上的 `boot-pending` |
| `mastersos-integrity.service` | 用户态，`boot-complete.target` 与 bootloader-update 之后 | `integrity`：核对活动槽、黄金副本，（起在比黄金副本旧的版本上时）UKI 与非活动槽；写 `integrity.json`；按需刷新黄金副本、补 UKI、补非活动槽、写 `repair-usr`、启动 golden-fetch。限速 150 MiB/s，`Nice=19`，超时 30 分钟 |
| `mastersos-golden-fetch.service` | 用户态，按需（不开机启用），等 `network-online` | `golden-fetch --booted`：从更新通道重下正在运行的版本写进黄金副本。超时 3 小时（同 `mastersos-update`）。成功后启动 integrity（它看到黄金副本完好就写 `repair-usr`），通道里已没有这个版本（退出 3）就启动 `mastersos-update` |

下载单独成单元，因为 1.66 GB 在慢网或开机时还没上网的 Wi‑Fi 上跑不完 integrity 的 30 分钟，也不该让本地核对等网络。
integrity 的 `network` 动作只 `--no-block` 启动它并记一条 note。下载有上限（`SHA256SUMS` 与 `.gpg` 各 1 MiB、每个文件 4 GiB），
四个文件先从签过的清单里挑齐再下载，缺一个就一个字节也不下；`SHA256SUMS` 过 `gpgv`、四个文件逐个对 sha256，签名的 rootHash 必须等于
运行中的 `usrhash`，UKI 必须是该版本且签给它；黄金副本是更新的版本就拒绝（只升不降）。

`mastersos-update.service` 仍在 `/run/mastersos-slots.lock` 下运行（最长 3 小时）；integrity 本身**不**包这把锁（否则会等到自己超时、
整次核对被跳过），只在 `restore-inactive`（写非活动槽）与 `restore-uki`（写 `EFI/Linux`）两处非阻塞地拿锁（sysupdate 也写这两处），
拿不到就跳过并记 note，下次开机再来。`restore-inactive` 排在 `restore-uki` 之前；`restore-uki` 只在启动盘上有该版本的槽时才把 UKI 放回去
（没有计数的 UKI 会被 systemd-boot 每次都选，槽已被后来的更新覆盖时它找不到 `/usr`，就成了重启循环）；槽在但坏了不要紧，initrd 会从黄金副本修。
`golden-fetch --booted` 下载成功后留下 `/run/mastersos-golden-fetched`，同一次开机里 integrity 不再启动第二次下载（只记 note）。

### ESP 上的状态文件（`EFI/MastersOS/`）

| 文件 | 内容 | 谁写、谁删 |
|---|---|---|
| `boot-pending` | 空文件 | initrd 每次开机在没有时创建；`mastersos-boot-ok` 在 boot-complete 之后删。开机时它还在，说明上一次开机没走完（常见原因：孩子长按电源强关），这次 initrd 先完整核对活动槽 |
| `repair-usr` | `<数据分区 PARTUUID> <64 位 usrhash>` | integrity 的 `request-repair` 写（也可手工写）。initrd 读到后先像强关后那样把活动槽完整读一遍（只认 `usrhash`）：读得通、签名区也与黄金的相同，就删掉请求、什么都不写、不计数（用户态误判时不会每次开机重写 1.8 GB）；坏了才修，修完删；写完核对不过时留着（下次开机再试）。名字对不上当前 usrhash 就删掉、不执行。integrity 读通该 usrhash 的活动槽后也删（否则 initrd 核对不过、用户态读得通的槽会每次开机重写一遍，Task 10 实测） |
| `repair-inprogress` | `<usrhash>` | initrd 开始写之前创建，修完删。留下来说明修复被打断（断电、单元超时） |
| `repair-interrupted` | `<usrhash> <k>` | 每次开机发现 `repair-inprogress` 就加 1；到 3 次不再重试，按放弃处理，免得一直写不完的修复每次开机重写整个槽 |
| `repair-count` | `<usrhash> <n>` | 只计「写完仍然核对不过」的修复，**上限 2 次**；到 2 就放弃（integrity 记 `gave_up`，不再自动修，回滚/换新版本才能出来）。`--boot-ok` 不碰它；只有 integrity 读通该 usrhash 的活动槽之后才删它，同时删同一 usrhash 的 `repair-usr`、`repair-inprogress`、`repair-interrupted` |
| `lab-fail-verify` | 空文件 | 只在 lab profile 的 initrd 里生效（initrd 里有 `usr/lib/mastersos/profile` = `lab`）：写完后的核对一律失败，用来试「修了仍坏」。正式 initrd 没有这个判断 |

写 ESP 都是先写 `<name>.new`、sync、再改名；initrd 只在读写状态文件时挂 ESP，长读长写时卸掉，一个 trap 保证每条退出路径都卸。

### `/var/lib/mastersos-system/integrity.json`

integrity 每次运行写两遍（动作前后），0644。字段：

- `checked_at`、`booted_version`、`has_golden`（盘上有没有黄金分区；没有就只上报：`active_ok:false`、`error:null`、`golden_*` 为空）；
- `golden_version`（黄金副本的版本，没有为 `null`）、`active_ok`、`golden_ok`、`golden_full_checked_at`（黄金副本上次被完整读过的时间；平时只开不读，写过之后或每 7 天读一次）；
- `actions`：决定要做的动作（`refresh-golden`、`restore-uki`、`restore-inactive`、`request-repair`、`network`、`report-only`）；`golden_ok` 等是动作做完之后的状态；
- `repaired`：最近 10 条 `{at, what, from}`。`what=repair-request` 只是**请求**，不是已经修好；
- `gave_up`：放弃的 usrhash（`repair-count` 到 2），否则 `null`；
- `notes`：字符串数组，只是提示，**不代表检查失败**：用户态降级（见下）、黄金签名区为空或无效、活动槽或黄金副本没通过、黄金 ESP 挂不上等；
- `error`：只有挡住了检查的失败才非空（找不到活动槽、读不到 IMAGE_VERSION、某个动作被打断、golden-fetch 起不来）。

agent 的 `system:integrity` 项只看 `active_ok`、`golden_ok`、`actions`、`error`、`gave_up`，不看 `notes`；没有黄金分区、或黄金副本待刷新，算健康（只是备份不全）。

Secure Boot 关着的 MOK 机器上内核钥匙环验不了签名（veritysetup 返回 1「Required key not available」，`verity_check` 退出 3），
用户态此时降级成只认根哈希（并记一条 note），但**只限正在运行的根哈希**（内核开机时已用同一份签名验过它）；别的根哈希（例如另一个版本的黄金副本）不信。initrd 里黄金副本的签名
用钥匙环验：钥匙环判断不了（退出 3）就一律不写。

### 手工触发一次修复

在机器上（root）把当前 usrhash 写进 ESP，然后重启：

```bash
h=$(tr ' ' '\n' </proc/cmdline | sed -n 's/^usrhash=//p')
u="${h:0:8}-${h:8:4}-${h:12:4}-${h:16:4}-${h:20:12}"      # 数据分区的 PARTUUID = 根哈希前 128 位
esp=$(bootctl --print-esp-path)                            # /efi 或 /boot
mkdir -p "$esp/EFI/MastersOS" && echo "$u $h" > "$esp/EFI/MastersOS/repair-usr"
systemctl reboot
```

initrd 先把活动槽完整读一遍：**槽是好的就只删掉请求、不写**（日志 `repair-usr dropped: the active slot reads clean`），手工请求不能强制重写好槽；
要试修复，先把槽改坏（lab 的做法见 `lab/results/2026-10-27-usr-repair/`）。槽坏了才修：控制台会出一行 `Repairing system files`，约 9 秒后继续（实测）。
别在 `mastersos-integrity` 还在跑（`systemctl is-active mastersos-integrity` 为 `activating`）时写请求：它读通活动槽之后会把这个 usrhash 的
`repair-usr` 一并删掉。要先看状态：`jq . /var/lib/mastersos-system/integrity.json`，
`journalctl -b -u mastersos-integrity`；initrd 的日志在 `journalctl -b -t usr-repair`。

### 强关之后下一次开机为什么多约 2 秒

开机时 `boot-pending` 还在，说明上一次没走到 boot-complete；initrd 因此把活动槽完整读一遍再放行（读 1.8 GB）。槽是好的就照常开机，
所以只多花约 2 秒：VM 165/170 实测 initrd 从正常的 3.33–3.48 s 变成 5.04–5.36 s，多 1.6–2.0 s（读通加挂 ESP 与等设备）。正常开机不核对。
带着 `repair-usr` 请求的那次开机也一样多花这一次读。

### 实测（VM 165，20261027.4，`lab/results/2026-10-27-usr-repair/`）

| 项 | 时间 |
|---|---|
| 用户态完整核对活动槽（限速 150 MiB/s） | 约 12 s（1.69 GiB ÷ 150 MiB/s） |
| 刷新黄金副本（usr 3.4 s、verity 0.9 s、UKI 0.6 s、读通 11.5 s） | 约 30 s |
| initrd 里修活动槽（读黄金 1.9 s、写 usr 3.1 s、verity 与签名 1.0 s、读通 1.5 s） | 约 9 s（整个单元 8.3 s） |
| 联网重下黄金副本（下载 1.66 GB，局域网） | 约 21 s，其中下载 3 s |

刷新黄金副本时的**写**不限速（每个版本一次、约 3 s 的突发）；限速只管后台的读。

### 构建闸门（`build.sh`）

- initrd：`golden-lib` 的 `INITRD_TOOLS` 里每个命令、`golden-lib`、`usr-repair`、单元与 `initrd.target.wants/` 的链接都必须在 `initrd.cpio.zst` 里；
  UKI 的 `.initrd` 第二段（内核模块）里要有 `vfat`、`nls_cp437`（内建）与 `nls_iso8859-1`（模块）；lab 构建的 initrd 还要有 `usr/lib/mastersos/profile`。
- 镜像：`/usr/bin/zstd`、`curl`、`gpgv` 必须存在（golden-fetch 要用；20261027.4 实测缺 zstd，这道闸会拦下）。

镜像新增的包：`zstd`（`mkosi.conf`，golden-fetch 自己解 `.raw.zst`；`systemd-sysupdate` 链着 libzstd 但镜像里原来没有命令）、`gpgv`、`curl`；
initrd 另有 `mkosi.initrd.conf/` 里的 `cryptsetup-bin`（`veritysetup`）。

## 构建（构建机或手动触发的 GitHub Actions）

`.github/workflows/mastersos-image.yml` 手动触发，在托管 runner 上跑同一份 `build.sh`。`profile=lab` 只在内部库，用 Secret `MASTERSOS_LAB_KEYS_B64`。`profile=release` 只在公开库，经环境 `release` 由所有者审批，用环境里的 `MASTERSOS_RELEASE_KEYS_AGE_B64` 与 `MASTERSOS_AGE_PASSPHRASE`。产物发到所在仓库的 GitHub Release（`image-<profile>-<版本>`，超过 2 GiB 的文件分段）。

> 2026-10-30：家里 PVE 的构建机 VM 161/164 与试验 VM 已删，构建机改在学校的 lab-pve 上重建（见仓库根 `CLAUDE.md`）。
> 下文写的「VM 161」「VM 164」都指这台构建机。

```bash
image/lab/sync.sh        # Mac → ~/mastersos-image、~/mastersos-core，并记下当前提交
ssh mastersos@198.51.100.21 'cd ~/mastersos-image && ./build.sh 20261012.1 --profile lab'
```

`build.sh <version> [--profile lab] [--broken userspace|initrd|bad-shim]`：

1. `cargo build --locked --release -p mastersos-agent [-p mastersos-installer]`（还没有的 crate 跳过），
   可执行文件放进 `build/extra/usr/bin/`，作为附加树进镜像；考试扩展用这一组的 `kiosk-ext.pem` 经 `kiosk-ext-pack.sh` 打包，
   `kiosk-ext.json` 与宿主清单放进 `build/kiosk-ext-tree/`（另一个附加树），crx 与 `updates.xml` 构建后放进 `mkosi.output/<v>/kiosk-ext/`，
   build-info 记 `kiosk_ext_id` 等几行（lab 跳过时是 `kiosk_ext=none`）；
2. `sudo mkosi -ff --image-version=<v> --snapshot=<快照> …  build`，产物在 `mkosi.output/<v>/`；
3. 查 `esp.raw`（mtools）：正式构建的 ESP 上不许有 `loader/keys/auto/`、`loader.conf` 必须 `secure-boot-enroll off`，
   根目录必须有与这个 profile 的 MOK 证书相同的 `mastersos-mok.der`（正式：`keys/mastersos-mok.der`；lab：`keys/lab/mastersos-mok.der`）；
   不符就 exit 1、不写 build-info；
4. ESP 上的 systemd-boot（`EFI/BOOT/grubx64.efi`）与镜像里 `/usr/lib/mastersos/esp/grubx64.efi`（`mastersos-bootloader-update`
   换到 ESP 的就是它）必须是同一份字节（`sudo systemd-dissect --copy-from` 读出来比 sha256，4a 终审复审 m7）；不等就 exit 1、
   不写 build-info——发布闸门比较的 `sdboot_sha256` 必须是机器上真正会换上的那份；
5. 写 `build-info.txt`：提交、`Snapshot=`、mkosi 版本、更新源、ESP 的两项（`esp_keys_auto`、`esp_secure_boot_enroll`，
   `lab=no` 的发布根只收 `absent` / `off`）、shim 与 systemd-boot 的 sha256（`shim_sha256`、`sdboot_sha256`，
   发布闸门据此拒绝悄悄换引导程序）、二进制的 sha256。

| 环境变量 | 作用 |
|---|---|
| `MASTERSOS_SNAPSHOT` | Ubuntu 快照（`snapshot.ubuntu.com`），默认当天 `YYYYMMDDT000000Z`。同一提交 + 同一快照 → 同一组包（`jq .packages` 一致；不要求字节一致） |
| `MASTERSOS_UPDATE_BASE` | 更新源的根，transfer 里的 `@BASE@` 换成它（通道目录 `stable/`、`beta/` 在它下面）。正式镜像默认 `https://os.khundavid.com`（Ruling 23），可覆盖，但必须是 `https://<域名>/…`（不收 http、IP、localhost），`build.sh` 与 `mkosi.finalize` 都拒绝；lab 默认构建机的 `http://192.0.2.99/mastersos`。`tests/check-tree.sh` 第 4、10 条保证仓库里进正式镜像的树不写死任何 URL |
| `MASTERSOS_BROKEN` | `userspace`（健康检查一直失败）/ `initrd`（initrd 里加一个必然失败的单元）/ `bad-shim`（`/usr/lib/mastersos/esp/BOOTX64.EFI` 换成测试 CA 重签的 shim，ESP 不动；4b Task 22），只给回滚与 shim 证书链试验做坏版本，只许 lab |
| `MASTERSOS_KIOSK_EXT_SRC` | 考试扩展的源码，默认仓库里的 `../kiosk-extension`，其次构建机上 `sync.sh` 同步的 `~/mastersos-kiosk-extension` |
| `MASTERSOS_KEYS` | lab 的钥匙目录，默认 `~/mastersos-keys`；`--profile lab` 用它下面的 `lab/`，`lab-local/` 也在这里（`keyset.sh`）。正式构建的私钥只从 tmpfs 读（`MASTERSOS_RELEASE_KEYS`，默认 `/run/mastersos-release-keys`，先 `keys-load.sh`，见下「钥匙」） |

构建机前提：mkosi v27.1（`~/mkosi`）、`systemd-boot-tools`、`tpm2-tools`（带进 libtss2——没有它
`systemd-measure sign` 报 `Could not calculate PolicyPCR digest: Operation not supported`）、rustup、jq、zip 与 unzip（Ventoy 包）。

### 钥匙（永不入库）

正式私钥平时只以 age 加密的一个文件存在 S3（2026-10-27 起，`ceremony/mac-ceremony.sh` 在 Mac 上生成；原来是两根 LUKS U 盘），签名会话才解密进 VM 161 的 tmpfs（计划 5 Task 4）：
`keys-load.sh --age <文件>`（口令由你在终端输入；核对 swap 为空、清单与仓库公钥）→ `build.sh` / `make-installer.sh` / `publish.sh` / `promote.sh` →
`sudo python3 -I key-leak-check.py /run/mastersos-release-keys <扫的路径…>`（0 干净、1 找到、3 有读不了的） → `keys-unload.sh`。`keyset_priv release` 不在 tmpfs、
不是 0700、属主不对或有 swap 一律拒绝（返回 2）。离线仪式（`ceremony/gen-release-keys.sh`）、保管、半年演练
（`keys-load.sh A --verify-only`）与丢盘见 `docs/key-ceremony.md`；`tests/keyset-test.sh` 进 CI，`tests/ceremony-test.sh`
要 root 与 loop 设备、只在本机跑。下表是 VM 161 `~/mastersos-keys/` 里的：lab 的一套、`lab-local/`，以及退役之前的预发布钥匙
（根目录下的 `db`、`pcr`、`gpg/`，裁定 11）。

| 文件 | 用途 |
|---|---|
| `db.key` / `db.crt` | Secure Boot（systemd-boot、UKI）与 `/usr` verity 签名；证书的 DER 就是 MOK `keys/mastersos-mok.der`（`mkosi.finalize` 核对 ESP 上的 systemd-boot 由它签） |
| `pcr.key` / `pcr.crt` | UKI 里的签名 PCR 11 策略（与 Secure Boot 钥匙分开）；公钥在 `keys/tpm2-pcr-public-key.pem`，镜像里是 `/usr/lib/systemd/tpm2-pcr-public-key.pem`，`publish.sh` 用它把关。丢了的后果见 `docs/keys.md` |
| 退役的 PCR 公钥 | `keys/retired/tpm2-pcr-public-key-4phase.pem`、`keys/lab/retired/tpm2-pcr-public-key-4phase.pem`（仓库里只有公钥）：4b Task 4 换签名阶段（只签 `enter-initrd`）时退役的旧 `pcr.crt` 公钥。它签过的四阶段 UKI 永远有效但发不出去——`channel-common.sh` 的 `check_uki` 拒收 `.pcrpkey` 等于它的构建。`keyset_retired lab\|release` 拼它的目录 |
| `gpg/` | 签更新源的 `SHA256SUMS`（ed25519，`MastersOS updates`）；公钥在 `keys/import-pubring.pgp`，镜像里是 `/usr/lib/systemd/import-pubring.pgp` |
| `lab/` | lab 镜像自己的一套：`db.{key,crt}`、`pcr.{key,crt}`、`gpg/`（`MastersOS lab updates`），公钥在 `keys/lab/`（`mastersos-mok.der`、`tpm2-pcr-public-key.pem`、`import-pubring.pgp`），与正式的三把都不同（`tests/check-tree.sh` 第 15 条）。生成方法见 `docs/keys.md`「lab 的钥匙」 |
| `keys/microsoft/`（仓库里，不在 `~/mastersos-keys/`） | 微软公开的 db 证书 UEFI CA 2011 与 2023（**公开证书、不是我们的钥匙**；来源与用途见下面一段） |
| `lab-local/` | lab 试验用户的口令哈希与 authorized_keys（明文口令在 Mac 的 `~/.config/testlab/mastersos/`） |
| `lab/kiosk-ext.pem` | 考试扩展的签名钥匙（RSA，不加密的 PEM；扩展 id 由它的公钥算出，见 `../kiosk-extension/README.md`）。`build.sh` 经 `keyset_priv` 的目录取它（正式的在 tmpfs 里的同名文件）：正式构建没有它就失败，lab 没有就警告、跳过考试扩展。正式的那把由钥匙仪式（`ceremony/gen-release-keys.sh generate`）随另外三把一起生成、写进两根 U 盘，`keys-load.sh` 按清单载入、对仓库的 `keys/kiosk-ext-public.pem` 核对（计划 9 Task 10）；仪式做完、公钥入库之前，正式构建过不去。lab 的这把在构建机上生成一次，命令见 `docs/keys.md`「lab 的钥匙」 |

钥匙路径只由 `keyset.sh` 拼（`keyset_priv` / `keyset_pub lab|release`），`build.sh`、`make-installer.sh`、`channel-common.sh`、
`mkosi.finalize` 都经它取。spec §6.12 的两个载体：

- **(b) 已修**（4b Task 1）：lab 镜像有已知口令、sshd 与自动登录，原来与正式共用全部签名钥匙；现在 lab 用 `~/mastersos-keys/lab/`，
  正式机器的 shim 不启动 lab 签的 systemd-boot，lab UKI 的 `.pcrpkey` 也不是正式的那把，TPM 不放行；`lab=yes` 的根只收 lab 构建。
- **(a) 已修**（4b Task 4，§6.12 (a) 出货前必须解决）：原来数据盘的 PCR 签名覆盖了离开 initrd 之后的阶段，不带种子的正式
  镜像装在另一块盘上（`mastersos-firstrun` 让装的人自己建管理员）进到用户态也能用 TPM 解开内置盘的数据分区。修法：数据盘只签
  `enter-initrd`，离开 initrd 之后 TPM 不放行；首次开机 / 恢复出厂用一把一次性临时钥匙，agent 在用户态（不靠 TPM）登记恢复
  密钥、换 TPM 槽、去掉临时钥匙槽；换签名阶段连 PCR 签名钥匙一起换新（旧钥匙退役，见上「退役的 PCR 公钥」）。
  BIOS 锁定不属于产品（用户 2026-10-14 决定），没有别的路线。VM 实测 `lab/results/2026-10-15-4b/t4-initrd-only.txt`。

见 spec §6.12 与 `docs/keys.md`「签名的阶段」。

仓库里只放公钥（`keys/`）。`tests/check-tree.sh` 拒绝任何含私钥的文件入库。`keys/google-chrome-keyring.gpg` 是 Google 的 apt 签名公钥（不是我们的钥匙），镜像里是 `/usr/share/mastersos/google-chrome-keyring.gpg`，来源、指纹与更新方法见 `docs/keys.md`「Chrome 的钥匙」。
`keys/microsoft/` 是微软公开的两张 db 证书（不是我们的钥匙）：`MicCorUEFCA2011_2011-06-27.der`（Microsoft Corporation UEFI CA 2011）与 `microsoft-uefi-ca-2023.der`（Microsoft UEFI CA 2023），取自 <https://github.com/microsoft/secureboot_objects> 的 `PreSignedObjects/DB/Certificates/`。agent 的 `secureboot.rs` 按它们的 sha256 认 db 里的证书，`publish.sh` / `promote.sh` 换 shim 时用它们验新 shim 的证书链（`docs/secure-boot.md`「2023 证书」）。
`keys/microsoft/dbx/` 是发布闸门用的微软 dbx（吊销的证书 `*.der` 与映像哈希 `sha256.txt`，`SOURCE.txt` 记来源与日期），由 `dbx-import` 从 `DBXUpdate.bin` 导入，怎么更新见 `docs/secure-boot.md`「闸门的 dbx 从哪来」。

## 安装 U 盘

`build.sh` 成功后自动调 `make-installer.sh <版本>`，产出 `mkosi.output/<版本>/MastersOS-installer_<版本>_x86-64.img.zst`
（`.raw` 加一个 Windows 与 Mac 都能写的 MASTERSOS-SEED 分区、ESP 上加安装器 UKI；只给正式构建做，lab 构建要
`--profile lab`）。同时产出 Ventoy 包 `MastersOS-ventoy_<版本>_x86-64.zip`：解压得 `MastersOS/`，里面是 Ventoy 版安装器 UKI
（`installer/ventoy.cmdline`：签名命令行带主 UKI 的 `usrhash=` 与系统文件的大小（不带 sha256：U 盘上的拷贝是信任的，拷坏了安装时发现不了，装好后表现为读 /usr 出 I/O 错，从新的拷贝重装即可），`/usr` 从 initrd attach 的 loop 盘挂）、
`MastersOS-system_<版本>_x86-64.raw`（就是这次的整盘 U 盘镜像，未压缩，脚本核对 zip 里的字节与刚做好的镜像逐字节相同）与 README.txt。
版本进了 `stable` 之后 `publish.sh <版本> installer` 把它放进 `<根>/installer/`。
给 IT 的装机说明（写 U 盘、放种子、MOK 五步、Secure Boot 关着时的口令路线、未受管机器建用户）见 `docs/install.md`。

## 更新：通道、发布、回滚

详见 `docs/update-channels.md`。要点：

- 更新源是静态目录 `<MASTERSOS_UPDATE_BASE>/{stable,beta}/`，根目录的 `mastersos-root.conf` 声明它对外的 `base=` 与 `lab=yes|no`；
  publish/promote 只发 `update_base` 与之相同的构建，`lab=no` 的根拒绝 lab 与 `--broken` 构建；`publish.sh <v> <通道>` 先核对 UKI 的 PCR 公钥与签名
  （不符 exit 1、什么都不发），再压缩、只留最近 3 个版本、gpg 签 `SHA256SUMS`；`promote.sh <v>` 把 beta 里的同一批
  字节放进 stable 并重签。两者都在 VM 161 上跑。
- 正式更新源是 S3 + CloudFront 上的镜像：正式根 `/srv/mastersos/release`（`lab=no`，带 `mirror_s3=`、`mirror_cdn=`）发完之后跑
  `sync-s3.sh [--dry-run]`（`MASTERSOS_AWS_PROFILE`，默认 `mastersos-publish`）：先本地验签，再传带版本号的文件、清单，CloudFront
  失效完成之后才删旧文件；同名对象字节不同就拒绝，中断重跑即可。测试 `tests/sync-s3-test.sh`（假 aws：`tests/fake-aws`）。
- 机器上 `mastersos-update.timer`（开机 15 分钟后、之后约每 6 小时）跑 `systemd-sysupdate update`，不重启，下次开机换版本。
- 考试扩展：`build.sh` 打包后 crx 与 `updates.xml` 进镜像的 `/usr/lib/mastersos/kiosk-ext/`，`kiosk-ext.json` 的 `update_url` 是这里的 `file://` 地址。锁定会话每次是新 profile，扩展从盘上装，断网也有 Exit 按钮，lab 不需要 https 地址；扩展随镜像走 beta / stable。带这种 URL 的构建 `publish.sh <版本> chrome` 什么都不做，`<根>/chrome/` 只留给还没更新的旧镜像。
- Chrome（sysext）由 `mastersos-chrome.timer` 每小时触发 `mastersos-agent chrome --scheduled`：配置设了更新时段 / 暂停时按它等
  （spec §6.2），没设时段的机器 6 小时内成功查过源就不联网。**要立刻查一次，在机器上以 root 跑 `mastersos-agent chrome`**——
  `systemctl start mastersos-chrome.service` 同样带 `--scheduled`，会被限流（日志里有一行说明）。
  上游的 `systemd-sysupdate{,-reboot}.timer` 在镜像里删掉了。
- **B 期（Defaults、IT 账号、`format = 2`）之后别把机器回滚到 B 期之前的镜像**：发布了 `format = 2` 的版本后，旧镜像的 agent 读不懂它，
  不应用这份设置包（B 期之前的 agent 把它当未知字段拒收，B 期及以后的 agent 遇到更新的 `format` 提示升级系统）；服务端也会在
  还有只支持 1 的机器时拦下 `format = 2` 的发布（`format_unsupported`）。
  回滚不只来自手动：新版本第一次开机健康检查过不了，启动计数用完（三次）就**自动**退回上一版，上一版可能正是 B 期之前的镜像。
  退回去的旧 agent 拒收 `format = 2` 的包、记下它的 sha256：B 期镜像还没应用过 `format = 2` 的包时，机器留在原来的设置上；
  已经应用过的，旧 agent 手上没有能用的包，按种子的默认值运行，直到再升级。之后机器再升到 B 期镜像时**不用管**：拒收记录
  带着记下它的 agent 构建，B 期 agent 不认旧构建记的拒收，会自己重新验这份包并应用（终审 I1）；同一个 agent 构建拒收的坏包仍不重试。
- Logo 改成两份 PNG（设计 §14.1）之前的 B 期 agent（9895f79）不认 `[school] logo_icon_sha256`，把带它的包当未知字段拒收；那一版镜像没有进 beta，
  进 beta 的镜像要含这次改动。
- **当前设置包读不出来时，IT 维修账号登不进去**：开机复验 `current.bundle` 失败、手上没有能用的设置包的机器按种子的默认值
  写登录策略，而应用过设置包的机器上种子不再开 IT 登录例外（`it_account::seed_gated`：防止装机时的旧口令哈希把换掉的口令带回来）。
  这时 `itadmin` 不能登录（访客照常，SSO 看种子带不带 `oidc`）；机器拉到并应用一份能读的设置包就恢复，必要时发布一个新版本。
  现场要进管理员桌面，先让机器联网拿到设置包。
- 回滚到早于离线状态（2026-10-30）的镜像、且机器上还没有设置包时，登录界面可能留着一条过时的状态横幅（旧 agent 没有包时不跑
  `lock` 步骤）：在机器上以 root `rm /etc/dconf/db/gdm.d/90-mastersos-lock && dconf update`。有包的机器下一次应用就自己清掉。
- 新版本的 UKI 带 `+3` 启动计数；`mastersos-health.service`（只看显示管理器、`/usr` 的 verity、agent 二进制）过了，
  systemd-bless-boot 才标「好」；失败三次退回上一版。没有计数或没有可退回的版本时健康检查不触发重启。

## profile

- **正式**（默认）：真机 Dell 用。`loader.conf` 为 `timeout 0`、`secure-boot-enroll off`，ESP 上没有
  `loader/keys/auto/`（在 Dell 上替换掉微软的钥匙会让显卡、网卡的 Option ROM 失效）。
- **lab**（`mkosi.profiles/lab.conf`）：PVE 的 VM 用。多 `qemu-guest-agent`、`openssh-server`
  （`/etc/ssh` 是 `dir`，主机钥匙首次开机生成）、串口控制台、试验用户 `student` 与 GDM 自动登录、
  S2 的 `loader.conf`，以及 setup mode 的 VM 自动导入我们的 Secure Boot 钥匙（`SecureBootAutoEnroll=yes` 只许
  出现在 lab profile，`tests/check-tree.sh` 第 8 条）。

## 试验网工具（`lab/`，在 Mac 上跑，经 ssh 到 lab-pve，`MASTERSOS_PVE` / `MASTERSOS_PVE_SSH_OPTS` 可改）

| 工具 | 用法 |
|---|---|
| `vm-create.sh <vmid> <name> [--no-tpm] [--setup-mode \| --own-db <crt>] [--disk <raw>] [--usb <raw>]` | q35 + OVMF + vTPM，网卡 VLAN 40。只许 121–129（106、110、120 与 101–105 拒绝）。默认预置微软钥匙（shim + MOK 路线）；`--own-db` 预置微软钥匙再把我们的证书**追加**进 db（Dell「追加 db」的备选路线，shim 直接认我们签的 systemd-boot）；`--setup-mode` 为空钥匙，systemd-boot 自动导入**只有我们的** PK/KEK/db——之后微软签名的 shim 过不了固件（Task 1 实测 `Access Denied`），所以带 shim 的镜像不能用这一条 |
| `gx.sh <vmid> <cmd…>` | 经 guest agent 以 root 跑命令（重启用 `qm reboot`，别在里面 `systemctl reboot`） |
| `shot.sh <vmid> <name>` | 截屏到 `lab/results/shots/<name>.png` |
| `keys.sh <vmid> <键…>` | `qm sendkey`，`wait:<秒>` 停顿，`wait:blue` 等 shim / MokManager 的蓝底；具名序列 `mok-enroll-from-disk[:N]`（默认路线，第一次开机）与 `mok-enroll`（`mokutil --import` 之后，要在开机后立刻调用） |
| `fw-vars.sh <vmid> secureboot on\|off \| print` | 关机状态下改 efidisk 的固件变量（等于在固件设置里开关 Secure Boot） |
| `serial.sh <vmid> <正则> [超时]` | 等串口出现某行（PVE 上常驻记录器，日志在 `/var/lib/vz/mastersos-lab/`） |
| `sync.sh` | 同步到构建机 |

VMID（lab-pve）：120 构建机；121–129 试验机（121 起默认是诊断机）；106 是 EIS 验收机、110 开发机、101–105 学校生产服务器，工具一律拒绝。
lab 的试验用户 `student`（与 root 口令、`authorized_keys`）**只在带种子的机器上建**：不带种子装的 lab 机器是未受管的
个人电脑，第一个用户由 `mastersos-firstrun` 在 tty1 上建（`keys.sh` 敲），之前没有 student、root 没有口令、ssh 进不去，
检查只能走 `gx.sh`（guest agent）。不带种子的 raw 镜像首次开机同样停在 firstrun 的提示上。
从 U 盘装：`vm-create.sh … --usb <img>`；盘上已有能启动的系统时，`qm set <vmid> --args` 里给 `usb-storage` 加
`bootindex=1` 让固件先试 U 盘（`lab/results/4a-t11-install.txt`）。
故意做坏的版本（`--broken`）只发到 lab 根的 `beta` 或一次性的 lab 根，**不发 lab 的 `stable`**（`docs/update-channels.md`）。
`publish.sh` / `promote.sh` 遇到 shim 与通道最新版本不同就拒绝，除非 `--allow-shim-change`；systemd-boot（`grubx64.efi`）
不同同样拒绝，除非 `--allow-bootloader-change`（通道最新的版本是这道闸门之前发的、没有 `sdboot_sha256=` 时放行并警告；去掉签名后与签名证书都相同的重签不算换，见 `sdboot_unsigned_sha256` / `sdboot_signer_sha256`）
（`docs/secure-boot.md`「引导程序更新与 TPM」）。

## 验收（计划 4a Task 12）

第一级是主机测试（`core` 的 `cargo test --workspace`、clippy `-D warnings`、`tests/check-tree.sh`），第二级是
`lab/accept-4a.sh` 在 PVE 的试验机上跑的 VM 验收；真机 Dell 在计划 4b 的最后一个任务。

```bash
image/lab/sync.sh                               # 构建机上的树与当前提交一致
image/lab/accept-4a.sh 165 all                  # install etc_policy seed_and_agent luks_sealed channel_beta update_interrupted
                                                       # rollback bad_bundle_no_rollback bootloader_update factory_reset tpm_matrix tamper chrome
image/lab/accept-4a.sh 166 no_tpm               # 166 没有 vTPM
image/lab/accept-4a.sh 168 offline_first_boot online_first_boot unmanaged local_password_change
```

- 每个 check 打印 `PASS <名字>` 或 `FAIL <名字>：<原因>`，输出与截图在 `lab/results/<日期>-4a/`（`<vmid>.txt`），退出码 = 失败个数。
  单个 check 也能单独跑（`accept-4a.sh 165 tpm_matrix`），但 165 的顺序有依赖：`bootloader_update` 读 `rollback` 记下的
  「坏版本开机时引导程序更新没跑」，`local_password_change` 要 `unmanaged` 建的 owner。
- 要的版本由脚本在 VM 161 上构建（`MASTERSOS_SNAPSHOT` 固定为 `A4_SNAPSHOT`，默认 `20261013T000000Z`），只发 lab 根的 **beta**
  （坏版本也只进 beta），发完删掉构建产物；版本号见脚本开头的 `A4_V_*`。U 盘镜像做在 PVE 的 `/var/lib/vz/mastersos-lab/a4-<版本>-{seeded,plain}.img`。
- 管理 API 的令牌从 Mac 的 `~/.config/testlab/mastersos/mastersos-lab-{ops,recovery}.token` 读、经 stdin 交给构建机上的 curl；
  恢复密钥只经 stdin（`qm guest exec --pass-stdin`、串口）。跨 check 的中间值（种子 sha256、试验口令）在仓库外的
  `~/.cache/mastersos-accept-4a/<日期>/`。lab 服务端是 VM 161 上的 mastersos-server（`:8480`，用之前要起好）。
- **不带种子的 lab 机器没有 `student`**（也没有 root 口令、ssh 进不去）：`unmanaged` 的第一个用户 `owner` 由 `mastersos-firstrun`
  在 tty1 上建（脚本用 `keys.sh` 敲），之后的检查都经 guest agent。
- 断网用 `qm set <vmid> --net0 …,link_down=1`；恢复密钥提示与恢复出厂的 `ERASE` 确认从串口读（lab 命令行最后是
  `console=ttyS0`），脚本往串口 socket 写之前先停掉 `serial.sh` 的记录器（QEMU 的串口 socket 只接一个客户端）。

## 检查

```bash
bash image/tests/check-tree.sh
bash image/tests/health-check-test.sh
bash image/tests/luks-bootstrap-test.sh
bash image/tests/update-done-test.sh       # /etc/.updated 在 sysext 合并之前记（mastersos-update-done），比 /usr 新的旧记录删掉
bash image/tests/update-run-test.sh        # update-run retries from the official source via the fallback dir when the school cache fails, and leaves a record (fake systemd-sysupdate)
bash image/tests/factory-reset-confirm-test.sh
bash image/tests/kiosk-ext-pack-test.sh   # 考试扩展的 crx3 打包：一次性钥匙，openssl 验签，不漏私钥（见 ../kiosk-extension/README.md）
bash image/tests/user-units-test.sh        # /etc/systemd/user 的启用链接按允许清单搬到 /usr，清单外的拒绝构建
bash image/tests/pam-hooks-test.sh         # pam-check / pam-session 钩子与锁定应用的 pam_namespace 的插行位置
bash image/tests/namespace-init-test.sh    # 锁定应用的 namespace.init：kiosk 账号的 Chrome 策略实例怎么填、哪些情形拒绝
bash image/tests/uki-check-test.sh        # make-installer 一段要构建机上的工具，缺了就跳过
bash image/tests/accept-4a-vacuous-test.sh   # accept-4a.sh 在 guest agent 失败或远端块没打印时必须 FAIL（不碰 VM）
bash image/tests/publish-test.sh        # 要 flock，macOS 上跳过
bash image/tests/sync-s3-test.sh        # sync-s3.sh 的顺序与拒绝，假 aws；要 flock，macOS 上跳过
sudo bash image/tests/bootloader-update-test.sh   # loop 挂载的 FAT32 上注入失败与断电；要 root、dosfstools、mtools
shellcheck -x image/*.sh image/lab/*.sh image/tests/*.sh image/mkosi.finalize image/mkosi.postinst.chroot image/mkosi.extra/usr/lib/mastersos/health-check image/mkosi.extra/usr/lib/mastersos/bootloader-update image/mkosi.extra/usr/lib/systemd/system-generators/mastersos-seed-generator image/mkosi.extra/usr/lib/mastersos/etc-migrate image/mkosi.extra/usr/lib/mastersos/update-done image/mkosi.extra/usr/lib/mastersos/update-run image/mkosi.extra/etc/security/namespace.init image/mkosi.profiles/lab.extra/usr/lib/mastersos/create-lab-user image/mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/tpm-probe image/mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/factory-reset-confirm image/mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/luks-bootstrap-key image/mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/luks-bootstrap-persist image/tests/fake-aws
```

CI 的 `image-lint` job 跑这几条。
