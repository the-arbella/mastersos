# 诊断模式：插 U 盘导出日志（设计）

状态：草稿，待批准。

## 为什么要做

机器出问题时拿不到日志：Wi-Fi 连不上就没有网络出口，itadmin 登不进去就没有终端，镜像里也没有 sshd。
要一条不靠网络、不靠登录的路：装机时打开开关，之后任何时候（包括停在登录页、谁都没登录）插 U 盘，系统就把日志写上去。

## 目标

- 收集范围要广：网络与 Wi-Fi、GDM 登录页、guest 与其他会话、登录认证、agent、内核与挂起唤醒都要有日志。
- 无网络、无人登录时也能导出；不用重启，当次开机的现场和之前几次开机的日志一起带上。
- 所有镜像都有这个功能，正式镜像也有。
- 开关只在装机时决定，线上设置不读、不写这个开关。

## 不做

- 不加开关以外的任何选项，现在和以后都只有这一个开关。
- 不要求 U 盘卷标，不加 agent 子命令，不做 UI 与 i18n，不上传，不加启动菜单项，不改 `seed.toml`。

## 反目标

- 诊断包进入本仓库或任何公开的地方（包里有秘密，仓库是公开的）。
- 没开开关的机器插 U 盘后有任何东西被写出去。

## 取舍

- 开关放 `seed.toml` 里：要改 seed 格式与验证，不选。
- **选定：** 和 seed 放在一起的单独文件 `debug.conf`，文件在就是打开，内容不读。不用 `.toml`，因为安装器把文件夹里的每个
  `.toml` 都当 seed 读。
- 启动菜单加诊断项：要重启，会丢掉当次现场，不选。
- **选定：** 开关打开时，插上任何 U 盘都自动导出。

## 设计

1. **开关。** 安装 U 盘上和 seed 放在一起的 `debug.conf`（整盘安装盘的 `MASTERSOS-SEED` 分区，或 Ventoy 盘的 `MastersOS` 文件夹）。
   安装器看到这个普通文件（不跟随符号链接），就在装好的机器的种子分区里建一个同名空文件
   `/var/lib/mastersos-seed/debug.conf`。种子分区在恢复出厂时保留，所以开关也一直在，直到重装。
   没有 seed 时也一样处理。
2. **开关在时，各组件都调到调试级别**（开机时在 `/run` 或可写的 `/etc` 下写 drop-in，开关不在就什么都不写）：
   - NetworkManager：`[logging] level=DEBUG`。
   - wpa_supplicant：调到 debug 级别（由 NM 的 D-Bus 设置或 drop-in）。`debug_show_keys` 保持关闭，不加 `-K`：
     wpa_supplicant 默认不在调试输出里打印密钥，打开 show_keys 才会。
   - GDM 与登录页：GDM 的 `[debug] Enable=true`；gnome-shell 的消息照常进 journal。
   - authd 与 authd-oidc（登录、OIDC）：调试级别。
   - mastersos-agent：调试级别（`RUST_LOG` 或它自己的日志级别设置）。
   - 具体每个组件用哪个配置项打开，留给实现查清。
3. **导出。** udev 规则：USB 块设备 `add`，文件系统为 vfat 或 exfat，就拉起一个 root 服务。服务先看开关文件：不在就直接退出，
   连 U 盘都不挂载。在的话：
   - 把 U 盘挂到 `/run` 下（`nosuid,nodev,noexec`）；
   - 在根目录写 `mastersos-diag-<machine-id 前 8 位>-<UTC 时间>.tar.zst`，先用临时名写，写完再改名，所以有这个名字的文件就是写完整的；
   - `sync` 后卸载，然后可以直接拔。
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
   - 安装器测试：有或没有 `debug.conf`，以及 `debug.conf` 是符号链接的情况。
   - VM 实测：在登录页、无人登录时插 U 盘，能得到包；没开开关时插 U 盘，什么都不写。

## 风险

装机时放了 `debug.conf` 的机器，谁插 U 盘都能拿到日志与秘密（Wi-Fi 密码、令牌、用户名、网址）。开关只能在装机时放进去，
只给开发机放，用户已认可。诊断包与其中内容不得提交到本仓库。

## 留给实现的

文件名与放置（参照 `image/mkosi.extra/usr/lib/mastersos/`）、带几次开机的日志、镜像里没有的命令（`iw`、`pciutils`、
`usbutils`）缺了就跳过。
