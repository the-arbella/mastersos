# Secure Boot：shim + MOK、引导程序随镜像更新、2023 证书

默认路线：**Ubuntu 已由微软签名的 shim + 每台机器登记一次我们的 MOK 证书**。备选：在 BIOS 里把同一张证书
**追加**进 db。不申请自有 shim 签名。（spec §6.2；计划 4a Task 4、Ruling 12、19；S2 的试验在
`spikes/s2/FINDINGS.md` §5。）验收记录在 `lab/results/4a-t4-secure-boot.txt`，截图在 `lab/results/shots/4a-t4-*.png`。

## 启动链与那一张证书

```
固件（微软的 KEK/db）→ EFI/BOOT/BOOTX64.EFI   Ubuntu 的 shim（微软 UEFI CA 2011 签）
                     → EFI/BOOT/grubx64.efi   我们签的 systemd-boot（shim 用 MokList 里的 mastersos-mok.der 验）
                     → EFI/Linux/MastersOS_<v>_x86-64*.efi   我们签的 UKI（systemd-boot 经 shim 的协议验，同一张证书）
                     → /usr（dm-verity，签名也是这把钥匙）
EFI/BOOT/mmx64.efi   MokManager（Ubuntu 签），shim 验不过 grubx64.efi 或有登记请求时启动它
```

- **MOK = `keys/mastersos-mok.der`**：构建机 `~/mastersos-keys/db.crt`（`CN=MastersOS Secure Boot db`，RSA 2048，20 年）的
  DER。私钥只在 VM 161。`mkosi.finalize` 用 `sbverify --cert` 核对 ESP 上的 systemd-boot 确实由它签，对不上就不构建——
  否则每台机器都会停在 `Security Violation`，登记了 MOK 也没用。
- 证书在镜像里两处：**ESP 根目录** `mastersos-mok.der`（MokManager「Enroll key from disk」选它；安装 U 盘的 ESP 上
  同样有一份，Task 11）与 `/usr/share/mastersos/mastersos-mok.der`（Secure Boot 关着时 `mokutil --import` 用）。
- **「BIOS 追加 db」的备选路线用的也是这同一张证书**：shim 先查 db 再查 MokList，db 里有它就不需要 MOK。
- **lab 镜像用另一张证书**（4b Task 1，Ruling 19）：`keys/lab/mastersos-mok.der` 是 `~/mastersos-keys/lab/db.crt`
  （`CN=MastersOS lab Secure Boot`）的 DER，lab 镜像的 systemd-boot、UKI、`/usr` verity 与安装器 UKI 都由它签，
  ESP 根目录与 `/usr/share/mastersos/` 放的也是它（`mkosi.finalize` 按 profile 取，核对 systemd-boot 同样按 profile 选证书）。
  正式机器只登记了正式的 MOK：从 lab U 盘启动，shim 拒绝 lab 签的 systemd-boot（`Security Violation`），进不了 lab 系统
  （实测 `lab/results/2026-10-14-4b/t1-build.txt`）。PVE 试验机登记的是 lab 的这张。
- 内核是 Ubuntu 签的、模块由 Canonical 签：shim 内置 Canonical 的证书，`mokutil --list-enrolled` 里那条
  `Canonical Ltd. Master Certificate Authority` 是它，不是我们加的。

## 默认路线：第一次从 U 盘启动时「Enroll key from disk」（五步）

第一次从 U 盘（或这块装好的盘）启动，shim 不认我们的 systemd-boot：

| # | 屏幕 | 操作 | 截图 |
|---|---|---|---|
| 0 | `ERROR — Verification failed: (0x1A) Security Violation`，[OK] | 回车 | `4a-t4-mok-1-security-violation.png` |
| 0 | `Shim UEFI key management — Press any key to perform MOK management`（**10 秒**倒数） | 任意键 | `4a-t4-mok-2-press-any-key.png` |
| 1 | `Perform MOK management`：Continue boot / **Enroll key from disk** / Enroll hash from disk | ↓ 回车 | `4a-t4-mok-3-menu.png` |
| 2 | `Select Key`：设备列表（`ESP`；插着 U 盘时选 U 盘那一个） | 回车 | `4a-t4-mok-4-select-device.png` |
| 3 | 文件列表：`EFI/`、`System.map…`、`config…`、`grub/`、**`mastersos-mok.der`**、`loader/`、`vmlinuz…` | 选 `mastersos-mok.der` 回车 | `4a-t4-mok-5-select-file.png` |
| 4 | `[Enroll MOK]`：View key 0 / **Continue** | ↓ 回车 | `4a-t4-mok-6-enroll-mok.png` |
| 5 | `Enroll the key(s)?`：No / **Yes** | ↓ 回车 | `4a-t4-mok-7-confirm.png` |
| — | 回到菜单，第一项变成 **Reboot** | 回车 | `4a-t4-mok-8-reboot.png` |

不需要口令（MokManager 本身要求有人在机器前）。之后：`mokutil --list-enrolled` 有 `CN=MastersOS Secure Boot db`，
`bootctl status` 为 `Secure Boot: enabled (user)`，首次开机 repart 照常把数据分区绑在签名的 PCR 11 上、不要输入
（Task 3 矩阵第 1 行在这条路线上同样成立，VM 167 实测）。

- 「Press any key」只等 10 秒；错过了，shim 再试一次启动、再报 `Security Violation`，回车又回到第 0 步，不会卡死。
- 文件列表的顺序是 FAT 目录的顺序，不是字母序；IT 照名字选，别照位置。
- 试验网：`lab/keys.sh <vmid> mok-enroll-from-disk[:N]`（N = 要按几次 ↓ 才到 `mastersos-mok.der`，装好的镜像是 4）。

## Secure Boot 关着时：`mokutil --import`

安装时 Secure Boot 关着的机器（安装器检测到时执行，Task 10/11），登记口令固定为 `mastersos`（只证明「有人在机器前」，
MokManager 本身就要求在场，公开它不降低安全性；印在安装完成屏与安装说明里）：

```bash
mokutil --generate-hash=mastersos > /run/mok.hash
mokutil --import /usr/share/mastersos/mastersos-mok.der --hash-file /run/mok.hash
```

然后在 BIOS 里打开 Secure Boot、重启：

| 屏幕 | 操作 | 截图 |
|---|---|---|
| `Press any key to perform MOK management`（10 秒） | 任意键 | `4a-t4-import-0-press-any-key.png` |
| 菜单：Continue boot / **Enroll MOK** / Enroll key from disk / … | ↓ 回车 | `4a-t4-import-1-menu.png` |
| `[Enroll MOK]`：View key 0 / **Continue** | ↓ 回车 | `4a-t4-import-2-enroll-mok.png` |
| `Enroll the key(s)?`：No / **Yes** | ↓ 回车 | `4a-t4-import-3-confirm.png` |
| `Password:` | 输入 `mastersos` 回车 | `4a-t4-import-4-password.png` |
| 菜单第一项 **Reboot** | 回车 | `4a-t4-import-5-reboot.png` |

**坑（VM 167 实测）**：这一次的「Press any key」没人按，**登记请求就作废了**——shim 照样清掉 `MokNew`，接着因为
Secure Boot 已经打开而报 `Security Violation`，回到菜单时已经没有「Enroll MOK」这一项
（`4a-t4-import-x-request-gone-after-timeout.png`）。这时走上面的「Enroll key from disk」即可（ESP 上有证书），
或者关掉 Secure Boot 重新 `mokutil --import`。安装说明里要写：**打开 Secure Boot 后的第一次开机守在屏幕前**。
试验网：`lab/keys.sh <vmid> mok-enroll`（以 `wait:blue` 开头，`qm start` 之后立刻调用）。

## 备选：BIOS 里追加 db（Dell「Expert Key Management」）

在 Dell BIOS 的 Secure Boot → Expert Key Management 里，对 **db** 选「Append from file」，选 U 盘上的
`mastersos-mok.der`。**只追加，不替换**微软的 PK/KEK/db：显卡、网卡的 Option ROM 是微软签的，换掉微软的钥匙它们就
起不来（S2）。这一条之后 shim 直接在 db 里认出我们签的 systemd-boot，不出 MokManager。试验网对应
`lab/vm-create.sh --own-db`（Task 1–3 的 VM 用的就是它）。

正式镜像因此**不带 `loader/keys/auto/`，`loader.conf` 写 `secure-boot-enroll off`**：setup mode 的真机上 systemd-boot
会把它们当成 PK/KEK/db 整套导入，替换掉微软的钥匙。**ESP 不走更新通道**（sysupdate 只换 `/usr` 与 UKI），它只随
安装 U 盘或 `.raw` 写到机器上，所以真正挡住它的是构建时的检查与安装器；发布脚本只是复核构建时的记录：

- `tests/check-tree.sh` 第 8 条：`mkosi.conf` 写 `SecureBootAutoEnroll=no`，`=yes` 只许出现在 `mkosi.profiles/lab.conf`；
  正式的 `loader.conf` 是 `secure-boot-enroll off`；`mkosi.extra` 下没有 `loader/keys/auto`。
- `build.sh`（**唯一真正看到 ESP 的关**）：构建完用 mtools 查 `esp.raw`，正式构建不符就 exit 1、不写 build-info——但
  `mkosi.output/<v>/` 里的 `.raw` 与 `esp.raw` 照样留着；结果记进 build-info（`esp_keys_auto=absent`、`esp_secure_boot_enroll=off`）。
- `publish.sh` / `promote.sh`（复核记录，不是 ESP 的关）：`lab=no` 的发布根只收 build-info 里这两行是 `absent` / `off` 的构建
  （没有这两行的旧构建也不收）——挡住的是「从一次没通过检查、或是 lab 的构建里发出正式的 `/usr` 与 UKI」。
- **Task 11 的义务**：做安装 U 盘（`make-installer.sh`）的脚本必须自己再查一遍——读这个版本的 build-info 要求
  `profile=release`、`esp_keys_auto=absent`、`esp_secure_boot_enroll=off`，并对它真正写进 U 盘的 ESP 重跑同样的 mtools 检查；
  没有 build-info、或 `build.sh` 没写完（exit 1）的产物一律不做成 U 盘。

lab profile 的 `SecureBootAutoEnroll=yes` 仍在，只对 setup mode 的 VM 起作用；带 shim 的镜像在 setup mode 里起不来
（Task 1），所以试验网实际都用预置微软钥匙的 VM。

## 引导程序随镜像更新（Ruling 19）

sysupdate 只换 `/usr` 与 UKI；ESP 上的 shim、systemd-boot、MokManager 装机后就不会变。Dell BIOS 更新或 Windows
Update 往 dbx 写进新的吊销、SbatLevel 抬高之后，留在旧版本的 shim / systemd-boot 会被固件或 shim 拒绝，整批机器就停在
开机第一屏。所以：

- 每个镜像在 `/usr/lib/mastersos/esp/` 带一份签好的 `BOOTX64.EFI`、`grubx64.efi`、`mmx64.efi`（`mkosi.finalize` 从 mkosi
  装好的 ESP 复制；`/usr` 有 verity 签名，这一份可信）。
- `mastersos-bootloader-update.service`（`Requisite=` + `After=boot-complete.target`，`After=systemd-bless-boot.service`；
  由 `/usr/lib` 的 `multi-user.target.wants` 链接启用）在**被标好的开机**之后跑 `/usr/lib/mastersos/bootloader-update`：
  逐个比 sha256，不同的换掉。坏版本的开机过不了健康检查，`boot-complete.target` 不到，它不跑——坏版本的引导程序
  永远不会落到 ESP 上（VM 167：`20261013.10` 的三次失败开机日志里一行都没有它，退回 `.9` 后才把旧的 systemd-boot 换掉）。
  用 `Requisite=` 而不是 `Requires=`：后者在有人手动 start 时会重新拉起已经失败的健康检查（Task 2 的裁定）。
- **怎么写才不会把 ESP 写坏**：
  - 顺序 `grubx64.efi` → `mmx64.efi` → `BOOTX64.EFI`，shim 最后：新 shim 可能抬高 SbatLevel、吊销旧的
    systemd-boot，不能让它先落盘。任何一个失败就停。
  - 每个文件：写 `<名字>.new` → `fsync` → 读回核对 sha256 → `rename` 覆盖 → `fsync` 文件与目录。
  - **为什么直接 rename 覆盖、不先把旧的改名成 `.old`**：Linux vfat 的 rename 覆盖已有文件时，是把**原文件那一条目录项**
    改指向新文件的簇（`fs/fat/namei_vfat.c` 的 `vfat_rename`：目标存在时 `fat_detach(new_inode)`、
    `fat_attach(old_inode, new_i_pos)`，然后删掉 `.new` 的目录项）。一条 32 字节的目录项在一个扇区里，断电时要么还是旧的、
    要么已是新的，**任何时刻 `BOOTX64.EFI` 都在**。「旧的先改名成 `.old`、`.new` 再改名过去、失败时从 `.old` 恢复」在两次
    改名之间没有 `BOOTX64.EFI`——断电断在那里，机器起不来，也就没有谁能去用 `.old` 恢复。所以不用它。
  - 断电留下的 `.new` 下次先删掉（固件不认这个名字）。
  - 测试：`tests/bootloader-update-test.sh`（loop 挂载的 FAT32、真的脚本，PATH 前面放 `cp`/`mv`/`sync` 的包装）：
    15 步里每一步失败、每一步前后断电（复制底层镜像文件——已写到块设备上的才算），30 份断电快照都满足「三个文件都完整
    （旧或新），shim 是新的则 systemd-boot 也是新的」，fsck 除了「没卸载的脏标记」没有别的问题，下一次运行都能换完。
    反例：直接 `cp` 覆盖、先改名成 `.old`、shim 先换，这三种写法都被它判红。另外实测：改名之后、`fsync` 之前断电，
    盘上是「旧文件 + `.new`」，`fsync` 之后才是新文件，fsck 都干净。
- **不降级**：ESP 的 `loader/mastersos-bootloader.version` 记最后一次写引导程序的镜像版本，本次开机的镜像比它旧（有人在启动
  菜单里手动选了旧版本）就不动——新 shim 抬高过的 SbatLevel 可能已经吊销了旧版本的 systemd-boot。
- `EFI/BOOT/` 下的其他文件（例如 `fbx64.efi`）、`EFI/systemd/`、`loader/` 都不动。

## 引导程序更新与 TPM（pcrlock 只锁 PCR 7）

数据分区的 TPM 槽要求「签名的 PCR 11」**且**「pcrlock 的 PCR 7」（`docs/keys.md`）。shim 往 PCR 7 里记的东西里有
**`SbatLevel` 变量**（`Authority: SbatLevel-605dab50-…`）与它用来验 systemd-boot 的 MOK。所以：

| 换了什么 | PCR 7 | 下次开机 | 实测 |
|---|---|---|---|
| 只换 systemd-boot（或 MokManager），同一张证书签 | 不变 | TPM 直接解开 | VM 168：`.8` 的 systemd-boot → `.9` 的，pcrlock 已绑，不要输入 |
| shim 换成会改写 `SbatLevel` 的新版本 | **变**（只有 `SbatLevel` 那一条） | **要恢复密钥** | VM 168：shim 15.7 → 15.8，`SbatLevel` 从 `sbat,1,2022052400 grub,2` 变成 `sbat,1,2023012900 shim,2 grub,3 grub.debian,4`，PCR 7 `b0359d90…` → `18972a5f…`，出现 `Please enter recovery key` |
| shim 换版本但 `SbatLevel` 不变 | 不变（shim 的二进制记在 PCR 4，不在 PCR 7） | TPM 直接解开 | 由上一行的事件日志推出：PCR 7 里只有那一条变了 |
| shim 换成会改写 `SbatLevel` 的新版本、换之前 agent 预测成功（计划 5 Task 8） | 变，但新值已在策略里 | **TPM 直接解开** | VM 170：15.7 → 15.8，`shim-prepare` 之后换 shim，开机不要输入，PCR 7 `cad70c85…` → `46a486ab…`（与预测相同；`lab/results/2026-10-19-5/t8-shim-update.txt`） |

**计划 5 Task 8 之后，换 shim 多数不再要恢复密钥**：换之前 agent 把新 shim 将写下的 `SbatLevel` 预测进 pcrlock 策略（下面
「agent 做的」第 1 条）。预测做不成的机器照样换 shim，那一次开机要恢复密钥，之后 agent 用自己的 PIN 改写 pcrlock 策略，
再下次开机无感（第 2 条，4a Task 8 在 VM 165 实测）。

**shim 不同的镜像要显式放行才能发布；`publish.sh` / `promote.sh` 把关。** `build.sh` 把 shim 的 sha256 与它的
`.sbatlevel` 段记进 build-info（`shim_sha256=`、`shim_sbatlevel=`）；发布时与目标通道里最新版本的 shim 比较，不同（升级、
降级都算——更新的镜像版本可能用的是更旧的快照）或任一边没有记录就拒绝，除非显式 `--allow-shim-change`，这时打印
警告（受管机器换 shim 前会先预测、多数不需要恢复密钥；预测失败的机器下次开机要输一次，面板上 `luks:pcrlock` 标出）。`MASTERSOS_SNAPSHOT` 默认是当天的快照，重建可能悄悄带进新的 `shim-signed`，
这道关就是为它设的，计划 5 Task 8 之后也保留：换 shim 仍要有人有意决定（预测失败的机器各要输一次恢复密钥）。用恢复密钥进来之后，
`systemd-pcrlock-make-policy.service` 失败（`None of the alternative values for PCR 7 … match`，同 Task 3 第 4 行），
**照 Task 3 的 PIN 做法**用 `/var/lib/mastersos/pcrlock-pin` 经凭据目录跑一次
`systemd-pcrlock make-policy --pcr=7 --recovery-pin=query`（`Written new policy … NV index 0x187ec43`，同一个索引），
再重启就恢复无感（VM 168 实测：`TPM2 token unlocks volume`，`Prediction is identical to current policy`）。

**systemd-boot 不同的镜像同样要显式放行（终审 I5）。** 它不改 PCR 7（上表第一行），但 ESP 上它只有一份、没有 A/B：
`mastersos-bootloader-update.service` 在一次被标为「好」的开机之后把新的换上去，而那次开机用的还是旧的，新的 systemd-boot
没有被任何一次开机验证过；它起不来，全体机器停在固件里，UKI 的启动计数救不回来。`build.sh` 把 ESP 上
`EFI/BOOT/grubx64.efi` 的 sha256 记进 build-info（`sdboot_sha256=`）；`publish.sh` / `promote.sh` 与目标通道里最新版本的
比较，不同（升级、降级都算）或本构建没有记录就拒绝，除非显式 `--allow-bootloader-change`（这时打印警告）。两道闸门各管各的，
`--allow-shim-change` 不放行换 systemd-boot。**终审 I5 之前发的构建没有这一行**：通道里最新的版本没有记录时没有基线，
放行并打印警告，不拒绝——第一次带记录的发布之后才开始比较。放行之前先在 lab 的 VM 或真机上装过、确认新的 systemd-boot
能启动。「等镜像有过 N 次好的开机再换引导程序」没做。
每次构建都重新签 systemd-boot，签名里的 PKCS#7 `signingTime` 让 `sdboot_sha256` 次次不同（2026-10-27 计划 9 验收：同一个
systemd-boot-efi 包的两次构建只差签名时间）。所以 build-info 另记去掉签名后的 sha256（`sdboot_unsigned_sha256=`，
`sbattach --remove`）与签名证书 DER 的 sha256（`sdboot_signer_sha256=`）；两边都有这两行、而且都相同时是同一份程序
同一把钥匙，闸门放行并打印「只是重新签了名」。缺一行照旧按签名后的字节比。
`build.sh` 还核对 ESP 上这份与镜像里 `/usr/lib/mastersos/esp/grubx64.efi`（`mastersos-bootloader-update` 换到 ESP 的就是它）
是同一份字节（`systemd-dissect --copy-from`），不等就退出、不写 build-info（4a 终审复审 m7）：闸门比较的 `sdboot_sha256`
必须是机器上真正会换上的那份。

agent 做的：

1. **换 shim 之前先预测（计划 5 Task 8，裁定 14；VM 170 实测，`lab/results/2026-10-19-5/t8-shim-update.txt`）。**
   `mastersos-bootloader-update` 在 `shim-check` 通过之后、写任何文件之前跑 `mastersos-agent shim-prepare <镜像里的 BOOTX64.EFI>`
   （`mastersos_agent::shim_predict`）：
   - 只对数据分区绑了 pcrlock、Secure Boot 开着的机器做；读新 shim 的 `.sbatlevel` 段（`previous` / `latest` 两套），按 shim 的
     默认策略（`previous` 的日期戳比当前 `SbatLevelRT` 的新才改写）算出它第一次开机将写下的值；不改写就什么都不做。
   - systemd 259 的签发者组件是 `/var/lib/pcrlock.d/620-secureboot-authority.pcrlock.d/generated.pcrlock`，由
     `systemd-pcrlock-secureboot-authority.service` **每次开机**按事件日志重写；同目录下的每个 `*.pcrlock` 都是一个变体，pcrlock
     对它们取「或」。agent 把 `generated.pcrlock` 里 `SbatLevel` 那一条（`EV_EFI_VARIABLE_AUTHORITY` 的 digest，即
     `UEFI_VARIABLE_DATA` 的 sha256，手算与事件日志逐字节相同）换成新值，写成同目录的 `400-mastersos-next-shim.pcrlock`。
   - 按事件日志（`systemd-pcrlock log --json=short`）重放 PCR 7：原样重放必须等于 TPM 里当前的 PCR 7，把那一条 digest 换掉
     重放得到换 shim 之后的预期值；用 PIN 重建策略（`make-policy --location=770 --pcr=7 --recovery-pin=query`，凭据目录），
     `predict --json=short` 列出的 PCR 7 候选值里必须**同时**有当前值与预期值。
   - 任何一步失败：删掉变体、用 PIN 再建一次策略（TPM 里的策略与文件重新一致），退出 1；`bootloader-update` **照样换 shim**
     （停在可能已被吊销的旧 shim 上更糟），日志写「prediction failed … the next boot needs the recovery key」。
   - 结果写 `/var/lib/mastersos-system/shim-prepare.json`（0600）。新 shim 开机之后（`generated.pcrlock` 已是新值，开机时的
     `make-policy` 自己就把旧值去掉了），agent 的 luks 任务核对 `SbatLevelRT` 等于预测值，删掉 `400-mastersos-next-shim.pcrlock`、
     用 PIN 重建策略，`luks:pcrlock` 在这次开机余下的回报里都写「shim update completed without the recovery key」（下次开机清掉记录）。
     `SbatLevel` 与预测相同、这次开机的策略服务却失败过（要了恢复密钥：PCR 7 里别的一条也变了，例如签 shim 的 CA 换了）时
     不算完成：回报失败「shim replaced, but the prediction did not hold: this boot needed the recovery key; …」。设了 shim 的
     `SbatPolicy` 变量（`mokutil --set-sbat-policy`）时不预测，按失败处理。预测失败的那次开机里
     `luks:pcrlock` 回报失败（「shim replaced, prediction failed (…); this machine needs the recovery key at its next boot」），
     IT 在面板上看得到。lab 镜像上 `/run/mastersos-test/shim-prepare-fail` 让它故意失败（只给 VM 验收）。
2. **兜底（4a Task 8 已做，VM 165 实测）**：`systemd-pcrlock-make-policy.service` 失败时用 PIN 重建策略。VM 165（own-db，vTPM，
   20261013.14）：agent 首次开机绑好 pcrlock → 关机把 ESP 上的 shim 与 MokManager 换成 15.7、`SbatLevel` 变量改回 15.7
   时代的 `sbat,1,2022052400 grub,2`、版本标记写成 `.99` → 开机要恢复密钥 → agent 用 PIN 改写 → 下次开机无感 → 删掉标记、
   `mastersos-bootloader-update` 换回 15.8（`SbatLevel` 变成 `sbat,1,2023012900 …`）→ 开机要恢复密钥 → agent 改写 → 下次
   开机无感。NV 索引始终是同一个（`lab/results/4a-t8-luks.txt`）。预测失败时 shim 更新的代价就是这**一次**恢复密钥。
3. Ubuntu 的 shim 不常更新，而更新 shim 往往正是为了 SBAT 吊销。第 2 条保证了最坏情况只是「这一次输恢复密钥」，不是砖。

## 2023 证书（4b Task 22，spec §6.2）

**事实**（2026-10-15 调研，来源见 spec §6.2）：

- 签第三方引导程序（含 Ubuntu 的 shim）的 **Microsoft Corporation UEFI CA 2011 于 2026-06-27 到期**，接替它的是
  **Microsoft UEFI CA 2023**。固件验签不看证书有效期：db 里只有 2011 的机器照样启动 2011 签的 shim。我们验链时同样不看
  有效期（`openssl … -no_check_time`；`sbverify` 也放行过期证书，`src/sbverify.c` 的 `x509_verify_cb`）。
- Canonical：2026 Q4 起的新版本与稳定版更新的 shim 要求 db 里有 2023 CA。我们镜像里的 shim 来自 `shim-signed` 1.59
  （shim 15.8），今天只有 2011 签名。
- Dell：BIOS 更新只换「默认」密钥库，开机用的是「活动」库；二手机抹掉了 Windows，没人写活动库。要在 BIOS 里
  Expert Key Management → Custom Mode → **Reset All Keys**（用默认库覆盖活动库）。改 db 会改 PCR 7，所以要在装 MastersOS **之前**做。
- **我们不签 shim。** 双签（2011 + 2023）的 shim 由 Canonical 发，是外部依赖；我们只保证「装不上就不装、换不上就不换」。

**两张证书**在 `keys/microsoft/`（公开证书，不是我们的钥匙），取自 <https://github.com/microsoft/secureboot_objects> 的
`PreSignedObjects/DB/Certificates/`（commit `daa32713651f2ffe97b18df5aaf93ffe238aa464`）：

| 文件 | subject | DER 的 sha256 |
|---|---|---|
| `MicCorUEFCA2011_2011-06-27.der` | `CN=Microsoft Corporation UEFI CA 2011`（签发者 Third Party Marketplace Root，2026-06-27 到期） | `48e99b991f57fc52f76149599bff0a58c47154229b9f8d603ac40d3500248507` |
| `microsoft-uefi-ca-2023.der` | `CN=Microsoft UEFI CA 2023`（签发者 Microsoft RSA Devices Root CA 2021，2038-06-13 到期） | `f6124e34125bee3fe6d79a574eaa7b91c0e7bd9d929c1a321178efd611dad901` |

agent（`mastersos_agent::secureboot`）认 db 里的证书**只按 DER 的 sha256**，不看 CN（谁都能自签一张同名的），两个常量由测试
逐字节对着这两个文件核对。

**「shim 链得到某张证书」怎么验**（agent 的 `shim_chains` 与发布闸门的 `keyset_shim_chains` 同一做法）：取出 shim 的每个
Authenticode 签名（PE 的签名表），对每张证书、每个签名先
`openssl smime -verify -nosigs -inform DER -in <签名> -CAfile <这张> -no-CApath -no-CAstore -partial_chain -purpose any -no_check_time`
（签名者证书经签名里带的中间证书链到这张），链得上再 `sbverify --cert <这张> --detached <这个签名> <shim>`（映像的哈希与
签名本身）。**不能只用 `sbverify --cert <证书> <shim>`**：签名里带着中间证书时——微软签的 shim 都带（签名者 Microsoft Windows
UEFI Driver Publisher + Microsoft Corporation UEFI CA 2011）——它对**任意一张**证书都报 OK，随手自签的、CN 冒充
「Microsoft UEFI CA 2023」的都算（VM 161 与开发机实测，sbsigntool 0.9.4、OpenSSL 3.0 / 3.5；`tests/shim-chain-test.sh`
的「S 签、带着 I」一例守着）。也就是说只用 sbverify 时，以后只有 2023 签名的 shim 在 db 只有 2011 的机器上会被判成「链得上」、
换上去开不了机——正是这道检查要拦的情形。
openssl 那一步要退出 0 **且**输出「Verification successful」才算链得上：OpenSSL 3.0.13 的 `smime` 遇到不认识的选项（例如没有
`-no-CAstore` 的老版本）报「Unknown cipher」之后照样退出 0。退出 4 是链不上，别的退出码是判断不了（失败处理）。

**dbx**（复审 I1、第二轮 N1）：照 EDK2 的做法先查吊销，查三类项——
- `EFI_CERT_X509`：映像的任何一个签名链到 dbx 里的某张证书（同一种比法）；
- `EFI_CERT_SHA256`：映像的 Authenticode SHA-256（照 EDK2 `DxeImageVerificationLib` 的 `HashPeImage` 算：头部去掉 CheckSum 与
  签名表目录项、按文件偏移排序的各节、节之后签名表之前剩下的）在 dbx 里；
- `EFI_CERT_X509_SHA256/384/512`：签名里带着的任何一张证书的 TBSCertificate 哈希在 dbx 里（不看吊销时间：shim 没有时间戳）。

命中就算吊销，**哪怕另一个签名链得到 db**：换上去固件会拒绝。shim-check 退出 1（与链不上相同），安装器给单独的 code
`shim_revoked`。**被吊销的 shim 的改法是「这个 shim 已被吊销，请用更新的安装镜像 / this shim is revoked; use a newer installer image」，
不是 Reset All Keys**：Reset All Keys 把 dbx 退回出厂的那份，可能把这次吊销也退掉，让被吊销的 shim 又能装、能启动（复审第二轮 N3）。
面板上的 `system:shim-ca` 同样按原因给话：吊销 → 用更新的镜像；链不到 → 升 BIOS、Reset All Keys；判断不了 → 核对不了。
不是逐行等同于 EDK2：SHA-1 之类别的类型不看；签名表里 `WIN_CERT_TYPE_EFI_GUID` 写法的签名不收（真的 shim 不用）；dbx 证书只验链、
不验那个签名本身（只会多拒）；EDK2 的 `X509VerifyCb` 对某些链错误比 `openssl smime` 宽，对 dbx 而言固件可能吊销一条我们放过的链——
微软正常的链两边一致（复审实测），没在别的链上复现过。dbx 不在或只有属性 = 没有吊销；读不懂 = 判断不了（退出 2、正式拒装）。哈希的算法对过 Ubuntu 的 shim：算出的 `98a7fb4d…`
就是它签名里记的那个。发布闸门（`keyset_shim_chains`）查 `keys/microsoft/dbx/`（`*.der` 与每行一个哈希的 `sha256.txt`；
目录在才查，数据怎么来见下面「闸门的 dbx 从哪来」），哈希取签名里记的那个（签名与映像对不上时只会多拒）；机器上按本机的 dbx 查，那才是权威的。

**闸门的 dbx 从哪来**（plan 5 Task 6）：`keys/microsoft/dbx/` 由 `image/dbx-import` 从微软 `secureboot_objects` 的
`PostSignedObjects/DBX/amd64/DBXUpdate.bin` 导入（`python3 -I image/dbx-import <DBXUpdate.bin> keys/microsoft/dbx`，
输入先放进自己的临时目录；来源 URL、输入文件的 sha256 与日期写在 `SOURCE.txt`，要手工更新）。`EFI_CERT_X509_GUID` 的项写成
`<sha256>.der`，`EFI_CERT_SHA256_GUID` 的项排序去重进 `sha256.txt`；`X509_SHA256/384/512` 等别的类型闸门的 shell 不读（它只认
`*.der` 与 `sha256.txt`），导入时只计数打印、不写文件。2026-10-17 的那份只有 443 个 `SHA256` 映像哈希，没有证书项，也没有别的类型，
所以现在没有被跳过的东西。结构不对（长度越界、列表尾部有残余）整份不写。更新频率：微软发新的 `DBXUpdate.bin` 时（不定期，一年几次），
**每次换 shim 之前**重取一次再跑闸门；`tests/check-tree.sh` 第 29 条守着这个目录的格式，`tests/dbx-import-test.sh` 守着导入。
闸门只是第一道：机器上的 `shim-check` 按本机固件里的 dbx 查，那才是权威的。

**Secure Boot 开没开判断不了**（复审 I2、第二轮 N2）：`/sys/firmware/efi` stat 出错（不是「不存在」）、`SecureBoot` 变量读不出、
efivars 没挂上（`/sys/firmware/efi` 在、`efivars` 空）、内容看不懂
→ shim-check 退出 2，不换。只有读到 0、没有 `/sys/firmware/efi`（传统启动）、或 efivars 挂着而固件没有这个变量，才算关着（退出 0，
不核对；bootloader-update 照样写 `ok:true`，原因写「Secure Boot 关着，不核对」，面板上看得到）。

**比固件严的两处，都往「不换 / 拒装」那边**：sbverify 的 PKCS7_verify 要求签名者证书的用途对（serverAuth 的签名者验不过），EDK2
验映像时不看 EKU——微软签的 shim 的签名者都是 codeSigning，不受影响；别为了「和固件一样」把 sbverify 那一步拿掉，它是唯一验映像哈希的
一步。db 里的 SHA-256 项（直接放行某个映像哈希）不认：这样被放行的 shim 判成链不到。

**三道检查**：

1. **安装前（`mastersos-installer`，TPM 之后、选盘之前）**：读 efivars 的活动 db（`db-d719b2cb-…`，逐个 EFI_SIGNATURE_LIST
   取 X.509 项），再按上面的做法逐张验要装的 shim（`/usr/lib/mastersos/esp/BOOTX64.EFI`）。三档：
   - db 读不到 / 是空的（Setup Mode）、db 里没有 2023 CA、shim 链不到 db 的任何一张：**正式版拒装**（盘不动），写原因与
     按顺序的改法——升 BIOS → Reset All Keys → 清 TPM → 重装；**lab 版只警告**，多一句 PVE 的说明
     （`ms-cert=2023k`、`virt-fw-vars --add-db`）。今天的 shim 只有 2011 签名，所以正式版等于同时要求 2011 与 2023 都在。
   - BIOS 设了管理员密码、无线网卡不在支持清单或用不了：**警告**，列出全部之后按一次 `y` 才继续（`docs/hardware.md`）。
   - 都没有：不提示。安装界面的样子见 `docs/install.md`「安装前的检查」。
2. **换 shim 之前（每台机器，`bootloader-update`）**：镜像里的 `BOOTX64.EFI` 与 ESP 上的不同时，在写任何文件之前跑
   `mastersos-agent shim-check /usr/lib/mastersos/esp/BOOTX64.EFI`：Secure Boot 关着 → 退出 0（不核对）；链到本机活动 db 的某张 →
   0；链不上 → 1；db 读不到、`openssl` / `sbverify` 不在 → 2。非 0 时**三个文件都不换**（新的 systemd-boot 可能要新 shim 的 SBAT），
   写 `/var/lib/mastersos-system/shim-ca.json`（`{"ok":false,"exit":…,"image_version":…,"reason":…}`，0600），脚本照样退出 0；
   agent 回报 **`system:shim-ca` 失败**，详情「新镜像带的 shim 链不到这台的 Secure Boot db，引导程序停在旧版本：按 §6.9 升 BIOS、
   Reset All Keys」。机器照常从 ESP 上的旧 shim 启动。shim 没变时不跑 shim-check；文件不在时回报成功「引导程序还没换过」。
3. **发布闸门（`publish.sh` / `promote.sh`，`channel-common.sh` 的 `check_shim_chain`）**：shim 与通道最新的不同、带了
   `--allow-shim-change` 时，用 `keys/microsoft/` 的两张（运行时 `openssl x509 -inform DER` 转 PEM）各验一次，打印链到
   哪一张：两张都链不上 → 拒发（lab 根可以再加 `--allow-unchained-shim`，只给做坏的 `bad-shim`
   版本用，`lab=no` 的根不认这个开关）；只链 2023 → 警告「db 只有 2011 的机器会停在旧 shim、回报 system:shim-ca」。
   `build.sh` 记的 `shim_sha256` 是镜像 `/usr/lib/mastersos/esp/BOOTX64.EFI` 那份（机器上真正会换上的），并把它作为
   `MastersOS_<v>_x86-64.shim.bin` 放进产物与通道（promote 时同样验；sysupdate 不下载它）。

**以后 Canonical 发了只有 2023 签名的 shim**：闸门放行并警告；装着它的 db 只有 2011 的机器 `system:shim-ca` 失败、停在旧 shim，
IT 照 `docs/hardware.md` 的出货步骤升 BIOS、Reset All Keys（之后那次开机要一次恢复密钥，见上面「引导程序更新与 TPM」），
下一次被标好的开机就换上。

## 翻新机出货

工厂里每台：插安装 U 盘开机 → 「Enroll key from disk」五步（或在 BIOS 里追加 db）→ 装好系统 → 关机出货。学校拿到的机器
开机即用，不再见到 MokManager。若 IT 之后在 BIOS 里「恢复出厂的 Secure Boot 钥匙」，MokList 不受影响（它是 shim 的变量，
不在 db 里）；若有人清空了 NVRAM，开机会再报 `Security Violation`，ESP 根目录的 `mastersos-mok.der` 就是为这种情况留的。

## 为什么不申请自有 shim（spec §6.2）

要做到「插 U 盘零操作」，只有让我们自己的 shim 过 shim-review、拿到微软签名：要 EV 代码签名证书、公开的 shim-review
提交、几个月的周期，之后每次 shim 安全更新都要重走。第一期每台机器本来就要有人装机（选盘、确认），多五步按键的代价小；
翻新机在工厂做掉。**以后的条件**：机器量大到 MokManager 这一步成为装机的主要人工成本，或者学校要求 IT 完全不碰开机屏，
再申请（spec §6.10 S2、§6.2「已定」）。
