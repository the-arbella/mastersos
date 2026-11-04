# 诊断模式：插 U 盘导出日志（设计）

状态：第一版已合入（2026-11-04）；本次修订（开关改为安装时按 d、导出到安装盘的 seed 目录）待批准。

## 为什么要做

机器出问题时拿不到日志：Wi-Fi 连不上就没有网络出口，itadmin 登不进去就没有终端，镜像里也没有 sshd。
要一条不靠网络、不靠登录的路：装机时打开开关，之后任何时候（包括停在登录页、谁都没登录）插上安装 U 盘，系统就把日志写到盘上 seed 的目录里。

## 目标

- 收集范围要广：网络与 Wi-Fi、GDM 登录页、guest 与其他会话、登录认证、agent、内核与挂起唤醒都要有日志。
- 无网络、无人登录时也能导出；不用重启，当次开机的现场和之前几次开机的日志一起带上。
- 所有镜像都有这个功能，正式镜像也有。
- 开关只在装机时决定（用安装 U 盘启动时按住 d），线上设置不读、不写这个开关；装好之后从别的系统改 seed 分区也打不开它。

## 不做

- 不加开关以外的任何选项，现在和以后都只有这一个开关。
- 不要求 U 盘卷标，不加 agent 子命令，不做 UI 与 i18n，不上传，不加启动菜单项，不改 `seed.toml`；U 盘上不再有 `debug.conf`。

## 反目标

- 诊断包进入本仓库或任何公开的地方（包里有秘密，仓库是公开的）。
- 没开开关的机器插 U 盘后有任何东西被写出去。
- 装好的机器上，不经重装就能把开关打开（第一版的漏洞：往不加密的种子分区放一个文件就行）。
- 往不带 seed 的 U 盘（学生的盘）写东西。

## 取舍

- 第一版：U 盘上 seed 旁边的 `debug.conf` → 种子分区的标记文件，每次开机读。推送后的安全审查指出：种子分区不加密，
  从别的系统启动就能放一个标记、打开开关，不需要重装。废弃。
- 安装器问一句 `Enable developer diagnostics? [y/N]`：每台都要答，批量装机麻烦。不选。
- **选定（用户定）：** 用安装 U 盘启动时，安装器在第一屏之前有一个不显示任何东西的 1 秒窗口读键盘；这 1 秒里收到的输入只要含
  `d`（`d`、`dd`、`ssssdraf` 都算），这次安装就是 debug 模式。想要的人开机时一直按住 d。
- 开关存在哪：首次开机时移进加密的根分区，之后只认那里。种子分区上出现的标记一律删掉、不认。
- 导出到哪：第一版是任何 vfat/exfat U 盘的根目录。**选定（用户定）：** 只写到安装 U 盘上 seed 所在的目录（根目录与往下两层里找）；
  没有 seed 的盘不碰。

## 设计

1. **开关。**
   - 安装器（`mastersos-installer`，在 tty1 上）一启动、显示任何东西之前：把 tty 设成 raw、不回显，读 1 秒；收到的字节里有
     `d` 或 `D`（大写锁定时也算，我的取舍）就记为 debug。之后丢掉输入缓冲，并等到连续 0.5 秒没有输入（最多 10 秒）再显示
     第一屏：按住的 d 不能落进后面的选盘、确认等提示里。
   - 确认屏多一行 `Developer diagnostics: ON`（只在 debug 时显示）：装机的人看得到按 d 生效了（我的取舍；窗口本身不显示）。
   - 安装器在 `/run/mastersos-install/seed` 里写一个空的 `debug-install` 标记，随 seed 一起拷进种子分区。
   - 首次开机（`ConditionFirstBoot=yes` 的单元，在 `mastersos-diag-setup` 之前）：种子分区有 `debug-install` 就在加密根分区建
     `/var/lib/mastersos-diag/enabled`，然后删掉种子分区上的标记。
   - 每次开机：开关只看 `/var/lib/mastersos-diag/enabled`（普通文件，不跟随符号链接）。种子分区上若还有 `debug-install`
     （不是首次开机时出现的，即事后放上去的）就删掉，并在 journal 记一行警告，不打开开关。
   - 恢复出厂清掉根分区，开关随之关闭（要再开就重装）。
2. **开关在时，各组件都调到调试级别**（开机时在 `/run` 或可写的 `/etc` 下写 drop-in，开关不在就什么都不写）：
   - NetworkManager：`[logging] level=DEBUG`。
   - wpa_supplicant：调到 debug 级别（由 NM 的 D-Bus 设置或 drop-in）。`debug_show_keys` 保持关闭，不加 `-K`：
     wpa_supplicant 默认不在调试输出里打印密钥，打开 show_keys 才会。
   - GDM 与登录页：GDM 的 `[debug] Enable=true`；gnome-shell 的消息照常进 journal。
   - authd 与 authd-oidc（登录、OIDC）：调试级别。
   - mastersos-agent：调试级别（`RUST_LOG` 或它自己的日志级别设置）。
   - 具体每个组件用哪个配置项打开，留给实现查清。
3. **导出。** udev 规则：USB 块设备 `add`，文件系统为 vfat 或 exfat，且开关文件在，就拉起一个 root 服务。服务先再看一次开关：
   不在就直接退出，连 U 盘都不挂载。在的话：
   - 用 `blkid` 探到的类型（只许 vfat、exfat）显式 `mount -t`，选项 `nosuid,nodev,noexec,nosymfollow`，挂到 `/run` 下；
   - 找 seed：在分区根目录、以及往下两层的目录里找 `seed.toml` 或 `seed-*.toml`（不固定某个文件夹名，用户定；整盘安装盘的
     `MASTERSOS-SEED` 分区在根目录，Ventoy 盘在 `MastersOS/` 之类的文件夹里）。不跟随符号链接。找到几处时取最浅的一层，同一层
     按路径排序取第一个（我的取舍）。都没有就卸载、什么都不写（同一块盘的其它分区、学生的盘都这样）；
   - 在 seed 所在目录写 `mastersos-diag-<machine-id 前 8 位>-<UTC 时间>.tar.zst`，先用临时名写，写完再改名，有这个名字的
     文件就是写完整的。目标目录或同名文件是符号链接就不写；
   - `sync` 后卸载，然后可以直接拔。
   - 包的扩展名不是 `.toml`，安装器读 seed 时不会把它当 seed。
4. **包内容（只收白名单里的东西）。**
   - 日志：最近几次开机的完整 system journal（文本格式）。因为 `SplitMode=none`，GDM 登录页、gnome-shell、
     guest 与其他用户会话、authd、agent、内核（含挂起/唤醒）的消息都在里面，按开机分文件。
   - 崩溃：`coredumpctl list` 与每个崩溃的 `coredumpctl info`（只要文本，不要 core 文件本身）。
   - systemd：`systemctl --failed`、`systemctl list-units`、`loginctl list-sessions` 与每个会话的 `loginctl show-session`。
   - 网络：`nmcli general`、`nmcli device`、`nmcli connection show`（不带 `--show-secrets`），`ip addr`、`ip route`，
     `resolvectl status`、`rfkill list`、`iw dev`、`iw reg get`、`nmcli dev wifi list`。
   - 硬件与输入：`lspci -nnk`、`lsusb`、`/proc/cmdline`、`/proc/bus/input/devices`、`/sys/power/mem_sleep`、
     有 `libinput` 就加 `libinput list-devices`。
   - 系统与 MastersOS：`/etc/os-release`、`bootctl status`、ESP 上 `EFI/MastersOS/` 的状态文件、整个 `/var/lib/mastersos`
     与种子分区（含 `seed.toml`、`identity.json`、令牌）。
   - 配置：`/etc/NetworkManager/`（含 `system-connections/`）、`/etc/gdm3/`、`/etc/polkit-1/`、authd 的配置目录。
   - 敏感信息不排除：这是调试工具，用户定。不收用户主目录（量大，日志已在 journal 里）。
5. **测试。**
   - 安装器测试：1 秒内输入含 d / 不含 d / 没有输入；按住的 d 不落进后面的提示；debug 时写标记、确认屏有那一行。
   - 开机测试：首次开机有标记 → 建开关、删标记；非首次开机有标记 → 删标记、不建开关。
   - 导出测试：seed 在根目录、在一层子目录、在两层子目录、在三层（找不到，不写）、几处都有（取最浅）、没有 seed 的盘（不写）、
     非 vfat/exfat 的类型（不挂载）。
   - VM 实测：用安装盘启动按住 d 装机 → 登录页、无人登录时插安装盘，seed 目录里出现包；不按 d 装机 → 插盘什么都不写；
     装好后往种子分区放 `debug-install` 再重启 → 开关不开、标记被删。

## 风险

按 d 装的机器，谁拿一个带 seed 的 U 盘插上都能拿到日志与秘密（Wi-Fi 密码、令牌、用户名、网址）。开关只能在装机时打开，
只给开发机用，用户已认可。诊断包与其中内容不得提交到本仓库。

## 留给实现的

文件名与放置（参照 `image/mkosi.extra/usr/lib/mastersos/`）、带几次开机的日志、镜像里没有的命令（`iw`、`pciutils`、
`usbutils`）缺了就跳过。
