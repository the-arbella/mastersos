# 用 U 盘装 MastersOS（给学校 IT）

一根 U 盘装一台机器，可以反复用。带上学校的种子（`seed.toml`），装出来就是受学校管理的电脑；不带种子，
装出来是一台普通的个人电脑。每台机器大约 5 分钟（不算第一次开机）。

验收记录在 `lab/results/4a-t11-install.txt`，截图在 `lab/results/shots/`（`4a-t11-*`、`4a-t4-*`）。

## 1. 下载 U 盘镜像

更新源的 `installer/` 目录里放着最近 3 个版本的 U 盘镜像（只发已经在 `stable` 通道里的版本）：

```
<更新源>/installer/MastersOS-installer_<版本>_x86-64.img.zst
<更新源>/installer/MastersOS-ventoy_<版本>_x86-64.zip          （用 Ventoy U 盘时下这个，见第 9 节）
<更新源>/installer/SHA256SUMS
<更新源>/installer/SHA256SUMS.gpg
```

下最新的那个。想核对的话，在 Linux 或 Mac 上：

```bash
gpgv --keyring import-pubring.pgp SHA256SUMS.gpg SHA256SUMS   # 公钥是仓库里的 image/keys/import-pubring.pgp
sha256sum -c --ignore-missing SHA256SUMS                       # Mac：shasum -a 256 -c --ignore-missing SHA256SUMS
```

整盘写入的 U 盘至少 8 GB，写入会抹掉 U 盘上原有的一切。已经有 Ventoy U 盘的话不用重写它，下 `.zip` 解压进去就行（第 9 节）。
**两种 U 盘不要混着用：** 输出目录里整盘用的 `MastersOS-installer_<版本>_x86-64.efi` 与 zip 里的同名 `.efi` 是**不同的文件**，
Ventoy 一定要用 zip 里解出来的那个。

## 2. 写进 U 盘

镜像是 zstd 压缩的（`.img.zst`）。写盘工具不认 `.zst` 时先解开成 `.img`：Windows 用 7-Zip（较新的版本能解 zstd）
或 PeaZip；Mac 用 `brew install zstd` 后 `unzstd MastersOS-installer_<版本>_x86-64.img.zst`。

- **Windows**：[Rufus](https://rufus.ie)，「选择」这个镜像，「开始」；问写入方式时选 **DD 镜像模式**。
- **Mac / Windows / Linux**：[balenaEtcher](https://etcher.balena.io)，选文件 → 选 U 盘 → Flash。
- **Linux**：

  ```bash
  zstd -dc MastersOS-installer_<版本>_x86-64.img.zst | sudo dd of=/dev/sdX bs=4M conv=fsync status=progress
  ```

  `/dev/sdX` 是整块 U 盘（不是 `sdX1`），先用 `lsblk` 认准，写错了会抹掉别的盘。

写好后拔下再插上，电脑上会出现一个叫 **MASTERSOS-SEED** 的盘（Windows 可能还会提示另一个分区「需要格式化」——
**点取消，千万别格式化**，那是系统分区）。

## 3. 放种子（受管理的电脑才要）

1. 在管理网页的 **Install** 页下载种子。默认一份全校的，文件名 `seed-<学校短名>.toml`（如 `seed-eis.toml`；旧的 `seed.toml` 照样认）；
   需要让某个分组的机器第一次开机就进那个分组时，在 Install 页「Add seed for a group」再加一份，
   文件名 `seed-<学校短名>-<分组 id>.toml`。种子带的 Wi-Fi 与 IT 账号是那个分组展开后（Defaults + 覆盖）、**最新已发布版本**里的，
   草稿里改了要发布后新下载的种子才带上。
2. 把它复制到 U 盘的 **MASTERSOS-SEED** 里，和 `README.txt` 放在一起。**一根盘可以放多份种子**：
   - 文件名只认 `seed.toml` 和 `seed-<名字>.toml`（`<名字>` 只许小写字母、数字、`-`）。浏览器存成 `seed (1).toml`、
     `seed(2).toml`、`seed_MIS.toml` 之类，改名后再用；MASTERSOS-SEED 里不合这个规矩的 `.toml` 会在安装器的清单里
     标成无效（写明命名规则），不能选。
   - 只有一份有效种子（且没有别的 `.toml`）：安装器直接用，不问。有多份（或有一份无效的）：安装器在 TPM 与硬件检查之后、
     选盘之前列出编号清单（学校名、Wi-Fi 名、文件名），输编号选一份；无效的列出原因、没有编号。全部无效则拒装，内置盘没动。
   - 选中的那份按原样复制到电脑上，名字统一成 `seed.toml`。
   - **设了 IT 账号（`it_account`）的种子必须用当前的 U 盘包**：旧安装器不认这个键，会把种子判为无效而拒装。
     设了 IT 账号之后，U 盘包与 U 盘上的种子要一起换成新的。
   - **新种子（带 Wi-Fi、学校名）需要 20261029.3 或更新的安装器**：旧安装器不认这些键，会把这份种子判为无效而拒装；
     同一根盘上的 `seed-<名字>.toml` 也要新安装器才会被当作种子。
   - 在 Mac 上，复制完先在 Finder 里「推出」再拔：Mac 会在 U 盘上留 `._seed-eis.toml` 这类隐藏文件。
     新安装器忽略 `._` 开头的文件；旧安装器会把它当成第二份种子而拒装，遇到时在 Mac 终端里
     `dot_clean /Volumes/MASTERSOS-SEED`，或在 Windows 上显示隐藏文件后删掉它。
3. 种子里有学校服务器的地址、拉取令牌、首次联网用的 Wi-Fi 密码，设了 IT 账号时还有它的口令哈希（丢了可能被离线猜口令，所以口令要长）：
   **种子就是钥匙，带种子的 U 盘要当钥匙保管**，装完一批机器就把种子文件删掉。
   丢了 U 盘：把全校钥匙轮换掉，改 Wi-Fi 密码与 IT 口令并发布（设计稿 §11「C 之前」那句；有了按种子撤销之后，改为撤销那份种子，其余同）。
   种子里的 Wi-Fi 是机器第一次开机时用来连上学校服务器的网络；没有 Wi-Fi 的种子，机器要接网线（或装完再设）。
4. 不放种子 = 装成不受管理的个人电脑（见第 7 节）。

一根 U 盘可以反复用：换分组就换种子文件，或多放几份、装机时选。

## 4. 从 U 盘启动

**装之前在 BIOS 里打开 TPM 2.0（SHA-256 PCR bank）**：MastersOS 用 TPM 加密数据分区，没有可用的 TPM 2.0 安装器拒装
（不管带不带种子）。Dell：开机按 **F2** 进 BIOS，Security → **TPM 2.0 Security** 打开「TPM On」，PCR bank 选 **SHA-256**
（较新的 Dell 默认就是这样；有的型号写作「SHA2」）。我们卖的翻新 Dell 出货时已经设好。

插上 U 盘，开机。

- **Dell**：开机看到 Dell 标志时连按 **F12**，在「One-Time Boot」菜单里选 `UEFI: <U 盘名字>`。
  （别的品牌：HP 是 F9，Lenovo 是 F12 或 Novo 按钮。）
- 机器必须是 **UEFI** 启动；BIOS 里如果开着「Legacy / CSM」，关掉。
- Secure Boot 开着最好（默认就是开的）。关着也能装，见第 6 节。

### 4.1 第一次从 U 盘启动：登记我们的证书（每台机器只做一次）

MastersOS 用微软签名的 shim 启动，再由 shim 认我们自己的证书。每台机器第一次从 U 盘启动时要把这张证书登记进去
（叫「MOK」），屏幕是蓝底的，**五步**，不需要口令：

| # | 屏幕 | 操作 | 截图 |
|---|---|---|---|
| 0 | `Verification failed: (0x1A) Security Violation`，[OK] | 回车 | `4a-t11-s2-shim-violation.png` |
| 0 | `Press any key to perform MOK management`（**10 秒**倒数） | 任意键（错过了没关系，见下） | `4a-t4-mok-2-press-any-key.png` |
| 1 | `Perform MOK management`：Continue boot / **Enroll key from disk** / … | ↓ 回车 | `4a-t4-mok-3-menu.png` |
| 2 | `Select Key`：磁盘列表 | 选 U 盘那一个（只有一项时直接回车；机器上还有 Windows 时会多出几项，选名字里带 USB 的） | `4a-t4-mok-4-select-device.png` |
| 3 | 文件列表：`EFI/`、`System.map…`、`config…`、`grub/`、**`mastersos-mok.der`**、`loader/`、`vmlinuz…` | 选 **`mastersos-mok.der`** 回车（照名字选，别照位置） | `4a-t11-s2-mok-filelist.png` |
| 4 | `[Enroll MOK]`：View key 0 / **Continue** | ↓ 回车 | `4a-t11-s2-mok-enroll.png` |
| 5 | `Enroll the key(s)?`：No / **Yes** | ↓ 回车 | `4a-t11-s2-mok-confirm.png` |
| — | 回到菜单，第一项是 **Reboot** | 回车 | `4a-t11-s2-mok-reboot.png` |

机器重启，再从 U 盘启动（Dell 再按一次 F12），这次直接进安装器。错过了第 0 步的 10 秒也没关系：shim 会再报一次
`Security Violation`，回车又回到第 0 步。

**翻新机**：出货前在工厂里做完这五步（并装好系统），学校拿到的机器不会再见到这些蓝屏。登记的证书存在机器的
NVRAM 里，重装系统不用再登记；只有有人清空了 NVRAM（BIOS 里「恢复出厂设置」一般**不会**清它）才要再做一次——
那时装好的系统盘上也有一份 `mastersos-mok.der`，第 3 步在内置盘里选它即可。

## 5. 安装器

U 盘的启动菜单只有 **MastersOS Installer** 一项，等 5 秒自动进入（`4a-t11-f1-usb-menu.png`）。安装器在黑底文字屏上
（只有英文：控制台字体没有中文字形）：

1. **确认屏**（`4a-t11-s2-confirm.png`）：要抹掉的盘（型号、容量），以及
   - 带种子：`Managed computer`、学校服务器地址、分组、`School:`（学校名）与 `Wi-Fi:`（第一个网络名，多个加 ` +N`；没有写 `none (connect a cable or set it up after install)`）。种子里的学校名、地址、网络名只显示 ASCII，其余字符显示成 `?`；
   - 不带种子：`No seed: will be installed as an unmanaged personal computer`（`4a-t11-s3-confirm.png`）。
   核对无误，敲 **`y`** 回车；别的任何输入都取消，什么都不写。
   有几块可装的内置盘时会先列出来让你选编号。U 盘本身、别的 U 盘与小于 48 GiB 的盘不会出现在列表里（系统盘上除了两套 `/usr` 还有一份 8.9 GiB 的黄金副本，用来在 `/usr` 被改坏时自动修复）。
2. 安装（一两分钟），屏幕上一行行列出它在做什么。写盘之前先清掉内置盘上的旧分区表（`Releasing /dev/…: removing the old
   partition table`：抹掉旧分区与分区表的签名，让内核放下旧分区；真机上从 ChromeOS Flex 的 12 个分区装过来时，不这样做
   `systemd-repart` 会报 `Failed to reread partition table: Device or resource busy`），再列出盘上有没有被占用的分区。
3. **结束屏**（`4a-t11-s2-finish.png`）：`Installation complete` → 回车，机器重启，**屏幕黑了再拔 U 盘**。不要先拔再按回车：
   安装器自己的 `/usr` 在 U 盘上，拔了之后重启命令都跑不起来（真机上见过 `systemctl: Input/output error`）。U 盘还插着也
   没关系：安装器把内置盘的 `MastersOS` 启动项排在第一；要是又看到 Ventoy 菜单或安装器，拔掉 U 盘再重启。

安装器出错时，屏幕上是 `Installation failed`、下一行 `Reason:` 是原因，然后说盘动没动过，最后一行 `Press Enter to restart.`，
回车就重启（不进命令行）。在清旧分区表之前出的错（下表全部），写的是 `The disk has not been touched.`；从清旧分区表起出的错
（例如 `The disk /dev/… could not be released: an old partition is still in use (busy: …)`，或 `systemd-repart` 失败），写的是
`The disk /dev/… may have been partly erased or written: MastersOS is not installed on it.` / `Run the installer again.`，
前面还会列出 `What holds the disk:`（lsblk、holders、挂载、swap、`dmsetup ls`），拍照发给我们。答 `y` 以外的都是
`Installation cancelled`，同样 `The disk has not been touched.`。

安装器拒装的情况（不会动内置盘）：

| 屏幕上 | 原因与处理 |
|---|---|
| `The seed is invalid, refusing to install: …`（`4a-t11-s4-invalid-seed.png`） | 所有种子都坏了（`trust` 是空的、TOML 写错、文件名不合 `seed-<名字>.toml`……）。有好的种子时坏的只在清单里标出、不能选。按提示改好 U 盘上的 MASTERSOS-SEED，重启再来 |
| `Cannot mount the installer stick` / `Installer stick not found` | 不是用 make-installer.sh 做的 U 盘，或插了两根安装 U 盘。只留一根，重写 U 盘 |
| `No MastersOS folder was found on any USB stick.`（Ventoy 盘，第 9 节） | 没在任何 U 盘上找到 `MastersOS` 文件夹。把 zip 解压到 Ventoy 数据分区根目录；数据分区须是 exFAT（或 FAT32）。`The disk has not been touched.` |
| `MastersOS folder on the Ventoy stick not found`（Ventoy 盘） | 同上一行（安装器这一层的说法）：zip 解压到 Ventoy 盘根目录 |
| `More than one MastersOS folder was found (…)` | 插着的盘里不止一个。拔掉别的 U 盘或删掉旧文件夹，只留一个 |
| `The MastersOS folder on /dev/… could not be opened.` | 拔下 U 盘重新插好再重启；还不行就换 USB 口或换一根盘 |
| `MastersOS-system_<版本>_x86-64.raw is missing from the MastersOS folder.` | 文件夹里缺系统文件。重新解压整个 zip |
| `More than one system file is in the MastersOS folder.` | 只留与安装器版本相符的那一份 |
| `The system file in the MastersOS folder is a different version (…); this installer is …` | 系统文件与安装器不是同一版。删掉 `MastersOS` 文件夹，重新解压**同一个** zip |
| `The system file is incomplete (copying did not finish).` | 大小不对，拷贝没完成。重新拷贝；Mac 上先「推出」再拔 |
| `The system file could not be opened as a disk.` | 重启再试；再不行重新拷贝一遍 |
| 种子问题（Ventoy 盘） | 同第一行种子的那条，只是位置是 `MastersOS` 文件夹而不是 MASTERSOS-SEED |
| `No suitable internal disk` | 没有至少 48 GiB 的内置盘（或 BIOS 里 SATA 是 RAID 模式：改成 AHCI） |
| `No usable TPM 2.0, cannot install MastersOS`（`lab/results/2026-10-15-4b/4b-t3-166-no-tpm-refused.png`） | 下一行 `Reason:` 是原因，再下一行是 BIOS 里的改法（见下表）。在确认屏之前就停了，`The disk has not been touched.` |

TPM 拒装的几种原因（检查在带不带种子都一样做，在确认屏之前，内置盘一个字节都不写；详见 `docs/keys.md`「TPM 2.0 是前提」）：

| `Reason:` | 改法（屏幕上那一行） |
|---|---|
| `No TPM 2.0` | `Turn on TPM 2.0 under Security → TPM 2.0 Security`；只有 TPM 1.2 的旧机器装不了 |
| `The TPM has no SHA-256 PCR bank`（只开了 SHA-1、或只有 SHA-384） | `Switch the TPM PCR bank to SHA-256 in BIOS` |
| `The TPM is in dictionary-attack lockout (0x921)` | `Clear the TPM in BIOS and try again`（Security → TPM 2.0 Security → Clear） |
| `The TPM has an owner password set (0x9a2 / 0x98e)`（`4b-t3-168-owner-refused.png`） | 同上：清除 TPM（会清掉别的系统存在 TPM 里的东西，例如 Windows 的 BitLocker——这台机器反正要抹盘重装） |
| 别的（判断不了） | `Could not tell whether this TPM works, please contact us`：把整屏拍照发给我们 |

### 安装前的检查（硬件与 Secure Boot 证书）

TPM 检查之后、选盘与确认屏之前，安装器先打一行 `Checking hardware and Secure Boot certificates …`，再按结果三档处理
（每条检查的依据见 `docs/hardware.md`「安装前的检查」，证书的来龙去脉见 `docs/secure-boot.md`「2023 证书」）：

- **都正常**：不提示，直接到选盘 / 确认屏。
- **只有警告**：先列出 `Warnings:` 与每一条，再问
  `There are warnings above, type y to continue:`——敲 **`y`** 回车才继续，别的任何输入都取消（`Cancelled`），盘不动。
  常见的警告：没有无线网卡或网卡用不了（`Wi-Fi will not work, only wired networking`；**VM 上每次都有这一条**）、网卡不在支持
  清单（`not on the support list`）、BIOS 设了管理员密码。截图：`lab/results/2026-10-17-4b/4b-t22-167-warn-wifi.png`
  （db 有 2023 的 VM：只有 Wi-Fi 这一条）、`4b-t22-167-warn-db-no-2023.png`（db 只有 2011 的 VM、lab 版：多一条证书的警告）。
- **拒装**（正式版）：屏幕停在 `Secure Boot certificates are not right, cannot install MastersOS`，下一行 `Reason:` 是原因，
  几条原因都列完之后是**按顺序**的四步改法（只出现一次），最后一行 `The disk has not been touched.`。原因有：活动 db 读不到或是空的
  （Setup Mode）、db 里没有 Microsoft UEFI CA 2023、要装的 shim 链不到 db 里的任何一张证书、被这台的 dbx 吊销（或 dbx 读不懂）。
  lab 版的警告也一样：列完警告，改法与 PVE 的说明只给一次。**例外：被吊销的 shim**（`shim_revoked`）只给
  `This shim is revoked; use a newer installer image`——不要 Reset All Keys，
  那会把 dbx 退回出厂的那份、可能把这次吊销也退掉。正式版的拒装没在 VM 上拍
  （VM 只装 lab 版，lab 版把它降为警告；Task 21 在真机上拍），屏幕上的文字与 lab 版警告里的这一段相同。

**`mok_untrusted`：机器上登记着 lab 或预发布的 MastersOS 证书**（只有正式安装器查，警告、不拒装）。这台机器的 MokList 里有试验用的
证书（`MastersOS lab`，其 root 口令是公开的；或 `MastersOS 预发布 / pre-release`）：它会启动那套钥匙签的镜像，所以**出货的机器上这条警告必须没有**。
不拒装，是因为拒装之后 IT 没有现成的路删它；装好之后删：以 root 运行
`mokutil --delete /usr/share/mastersos/untrusted-mok/lab.der`（上一套 lab 证书是 `lab-2026-10.der`，预发布的是 `pre-release.der`；镜像带着这三张公开证书），重启，
在蓝色的 MokManager 里选 Delete MOK 并确认（要输入 `mokutil` 提示设的一次性口令）。再装一次，警告应不再出现。
只有我们自己的试验机会遇到。读不到 MokList 时安装器不提示。

**缺 2023 证书时的四步**（顺序要紧：证书与 TPM 都要在装 MastersOS 之前弄好，装好之后再改 db，PCR 7 变，下次开机要恢复密钥）：

1. **升级 BIOS**（Dell 官网，或 Ubuntu live U 盘里 `fwupdmgr refresh && fwupdmgr update`），不低于 `docs/hardware.md`
   支持清单里「带 2023 证书的最低 BIOS」。
2. **Reset All Keys**：F2 → Secure Boot → Expert Key Management → 打开 Custom Mode → Reset All Keys → 保存重启；
   再进 F2 关掉 Custom Mode（Secure Boot 保持打开）。
3. **清除 TPM**：Security → TPM 2.0 Security → Clear。
4. **重新用 U 盘安装**。之前登记过的 MOK 照理不受 Reset All Keys 影响（MokList 是 shim 的变量，不在 db 里）；没在真机上核对过，
   开机又出现 `Security Violation` 就照第 4.1 节再登记一次（Task 21 在真机上确认）。

**装到一半断电、拔了 U 盘**：插好 U 盘重新开机、从 U 盘再装一次即可，安装器总是从头重新分区。中途断电时内置盘上
要么还没有分区表，要么只有一个空的 ESP（引导程序最后才复制），固件不会把它当成可启动的系统，照样从 U 盘启动
（VM 实测两个断点，见 `4a-t11-install.txt` Step 5）。万一机器开机进了内置盘却起不来，开机按 F12 选 U 盘再装。

### 装好后的第一次开机

- 第一次开机要多一点时间：建加密的数据分区（与这台机器的 TPM 绑定），然后
  - 受管理的电脑：连上网就拉学校的设置，然后出登录界面；没网最多等约 45 秒，按种子的默认值出登录界面，连上网后几秒内拿到设置；
    **访客总能登录**（锁定的机器除外）；用学校账号的学校，种子里带着学校的 `oidc`（下载种子时服务端取最新发布的
    `[school].oidc`；默认分组允许 `sso` 而 `oidc` 没配好，下载种子回 409 `seed_sso_unset`），所以第一次拉到设置之前
    就能用学校账号登录；已经拉到过设置的机器之后按缓存的设置走，不受影响。学校设置里的管理员（`admin_users`）不受登录方式、锁定与
    域名限制约束，但他们用学校账号登录，分组的登录方式里要有 `sso`（见 `docs/idp.md`）；
  - 不受管理的电脑：先在文字屏上建第一个用户（第 7 节）。
- 新装与恢复出厂的机器，首次开机时数据分区会多一个**一次性的临时钥匙槽**（4b Task 4：数据盘的 TPM 钥匙只在 initrd 放行，
  所以 agent 要靠它在用户态动 LUKS）。受管理的电脑上，agent 登记恢复密钥、托管成功、补上 pcrlock 之后（几分钟内，要连得上
  学校的服务端）就自动去掉这个临时钥匙槽；之后 `luks:tpm` 回报成功。用 `cryptsetup luksDump` 看到数据分区上一个 recovery
  槽 + 一个 TPM2 槽、没有别的，就是收尾好了。不受管理的电脑不跑 agent，这个临时钥匙槽会一直留着（无害）。
- 不会再出现蓝色的 MOK 屏（证书已经登记了），启动菜单默认不显示。开机按住**空格**才出菜单，里面有
  「恢复出厂（ERASE ALL DATA - factory reset, asks to confirm）」——会清空这台机器上的所有数据。菜单里没有安装器。
  恢复出厂怎么做见下面一节。

### 恢复出厂（给 IT）

恢复出厂会删掉这台机器的数据分区：本机的文件、账号都没了；种子分区留着，重新开机后分组与学校的设置自动回来，面板上还是
同一台。**TPM 用不了的机器上不会清数据**（恢复出厂后会装不上），屏幕上会说明原因——先在 BIOS 里把 TPM 弄好（第 4 节）。

- **主路径：面板上远程恢复出厂。** 「机器」页这台的那一行点「远程恢复出厂」，照着键入它的序列号确认，然后**发布**
  （只改草稿，发布才生效；发布页会以警告列出这次要恢复出厂的机器，发布前可以点「撤销恢复出厂」）。机器联网拿到新设置
  后一分钟内回报「正在恢复出厂」，重启，启动时不问任何东西就重建数据分区，回来后照常回报。面板显示「恢复出厂失败」时
  （原因写在提示里，例如种子分区没挂上、TPM 一时判断不了），重启那台机器或再发布一次，它会再检查一次。每个请求只执行一次；
  重装之前发起的请求重装后不执行。执行完可以在面板上撤掉这个请求（不撤也不会再执行）。
- **本机：启动菜单里的「恢复出厂」。** 受管理的电脑（装的时候带了种子）要先输**这台的恢复密钥**（在面板上按机器读取，
  读取会记审计；输入时空格、`-`、大小写都不要紧），对了再打 `ERASE`。输错三次、或者某一次 300 秒没人输，照常开机、数据不动；慢慢输不要紧，每次提示有完整的 300 秒，不会在输到一半时重启。
  这台还没托管过恢复密钥（装好后一直没连上学校的服务端）时，本机不能恢复出厂：用面板远程恢复出厂，或用 U 盘重装。
  不受管理的电脑只要打 `ERASE`。

## 6. 安装时 Secure Boot 关着

有的机器 BIOS 里 Secure Boot 是关的。照样从 U 盘装（不会出现第 4.1 节的蓝屏）。安装器发现 Secure Boot 关着，
会替你**预约**登记证书，结束屏多一行（`4a-t11-s2b-finish.png`）：

```
MOK password: mastersos
After enabling Secure Boot, enroll the key when prompted.
```

装好后：

1. 结束屏回车重启时，**马上进 BIOS**（Dell 连按 **F2**）**打开 Secure Boot**，保存——要在装好的系统第一次从内置盘
   启动**之前**打开。
2. **守在屏幕前**：接下来这次开机会出现蓝底的 `Press any key to perform MOK management`，**只等 10 秒**。
   按任意键 → **Enroll MOK** → Continue → Yes → 口令 **`mastersos`** → Reboot（截图 `4a-t4-import-*.png`、
   `4a-t11-s2b-mok-*.png`）。口令是公开的：它只证明有人在机器前，MokManager 本身就要求有人在场。
3. **10 秒内没人按键，这次预约就作废了**（不会再问）。**没来得及进 BIOS 也一样**：Secure Boot 关着的那次开机同样会
   出这个蓝屏（`4a-t11-f1-sboff-firstboot-mok-prompt.png`），没人按就作废，系统以 Secure Boot 关着的状态进去。
   这都不要紧，补救：
   - **任何机器**：进 BIOS 打开 Secure Boot、开机，会报 `Security Violation`；按第 4.1 节的五步「Enroll key from disk」，
     第 2 步选内置盘、第 3 步选 `mastersos-mok.der`（装好的系统盘上有一份，`4a-t11-f1-sbon-internal-filelist.png`）。
     VM 实测（Task 11 修复轮）：先以 Secure Boot 关着开过机、再打开，**不会要恢复密钥**——Secure Boot 关着时 agent
     不绑 pcrlock（数据分区只有签名的 PCR 11），打开之后它才补绑。
   - **只限不受管理的电脑**（受管理的机器上没有管理员账号）：回 BIOS 关掉 Secure Boot，开机用管理员账号在终端里
     重新预约，再打开 Secure Boot、守着屏幕重启：

     ```bash
     sudo mokutil --import /usr/share/mastersos/mastersos-mok.der   # 问两次口令：输入 mastersos
     ```

Secure Boot 关着的机器也能用，但数据分区的保护弱一档（TPM 不再锁 Secure Boot 状态，见 `docs/keys.md`）；交给学生之前要打开。

## 7. 不受管理的电脑：第一次开机建用户

没带种子装的机器，第一次开机在文字屏上问（`4a-t11-s3-firstrun.png`）：

1. 用户名（小写字母、数字、`-`、`_`，字母开头，不能是 `root`、`guest`）；
2. 口令，再输一次（输入时不显示）。

这个用户就是这台电脑的管理员（能用 `sudo`）。之后出登录界面，用它登录。系统里没有 Ubuntu 的「欢迎 / 初始设置」向导，
也没有任何预置账号。恢复出厂后没有用户时会再问一次。

| 情况 | 原因与处理 |
|---|---|
| 开机直接出登录界面，**一个用户都没有**，也没有问建用户 | 系统盘上的种子分区没挂上：判断不了这台是不是受管的，首次开机程序宁可不建账号（免得在学校的机器上建出管理员）。用 U 盘重装一次；重装后还这样，多半是硬盘有问题 |

**不受管理的电脑没有恢复密钥（终审 I3）。** 恢复密钥的登记、托管与 pcrlock 都是 agent 的后台任务，只在有种子的机器上跑；
不带种子装的机器数据分区一直只有首次开机绑的 TPM 槽（签名的 PCR 11），盘上没有恢复槽，哪里也没有存下恢复密钥。
所以**TPM 被清空或重置**（BIOS 里「Clear TPM」、换主板、fTPM 随固件更新重置）之后，这台电脑的数据就再也解不开，
只能恢复出厂。个人电脑的主人要自己备份 `/home`。这台也没有 pcrlock，所以**挡不住摸得到机器的人**：关掉 Secure Boot、
在启动菜单改内核命令行（`init=/bin/sh`），签名的 PCR 11 照样放行（`docs/keys.md` 矩阵第 5 行的「解不开」只在绑了 pcrlock 时成立）。
没设 BIOS 管理员密码的个人电脑一直如此。
更好的做法（首次开机程序在屏幕上给出一把本机生成的恢复密钥让主人抄下来，Secure Boot 开着时不带种子也补绑 pcrlock）
排在 4b（spec §6.12）。

## 8. 可选：防止学生自己重装

MastersOS 不阻止有人用 U 盘重装（spec §2.2：这一点不防）。共用机想防的话，是可选的运维做法，不属于产品功能：

- 在 Dell BIOS 里设**管理员密码**（Setup Password），
- 关掉 **USB 启动**（Boot Configuration → Enable USB Boot 取消），并把启动顺序锁定在内置盘。

之后要重装或修机器时，IT 输入 BIOS 密码临时打开 USB 启动。丢失的机器要当种子已泄露处理：换拉取令牌、换 Wi‑Fi 密码，
在管理网页上重置这台的托管凭据（`docs/keys.md`）。

## 9. 用 Ventoy U 盘

学校已经有 Ventoy U 盘（一根盘上放多个系统的那种）时，可以把 MastersOS 装进同一根盘，不用另备整盘 U 盘。
**测过的 Ventoy 版本：1.1.18**（MBR 与 GPT 两种分区表都测过，Secure Boot 开、只信微软证书的机器）；新版本出来前先别升级 Ventoy。
Ventoy 的数据分区须是 **exFAT**（或 FAT32；不支持 NTFS）。

### 9.1 拷什么

1. 下载 `MastersOS-ventoy_<版本>_x86-64.zip`（第 1 节；它和 `.img.zst` 在同一个目录、同一份 `SHA256SUMS` 里）。
2. 把 zip **解压到 Ventoy 数据分区的根目录**，得到一个 `MastersOS` 文件夹：

   ```
   MastersOS/
     MastersOS-installer_<版本>_x86-64.efi   Ventoy 菜单里唯一的一项
     MastersOS-system_<版本>_x86-64.raw      系统文件（约 3 GB），Ventoy 不认它、菜单里看不到
     README.txt
     seed.toml                               受管理的电脑才放（下一步）
   ```

   盘上**只放一个 `MastersOS` 文件夹**。升级 = 删掉旧文件夹、解压新 zip。
3. **放种子**（受管理的电脑才要）：从管理网页下载这个分组的种子，存成 **`seed-<学校短名>.toml`**（或 `seed.toml`），放进 `MastersOS` 文件夹。规矩同第 3 节
   （可以放多份 `seed-<名字>.toml`，装机时选；浏览器存成 `seed (1).toml` 要改名；Mac 复制完先「推出」再拔；种子是钥匙，装完就删）。**这根盘的种子在
   `MastersOS` 文件夹里，不在 MASTERSOS-SEED**——系统文件里自带的种子分区在 Ventoy 模式下不读。不放种子 = 装成不受管理的电脑。

### 9.2 第一次从 Ventoy 启动（每台机器两次蓝屏，各一次）

Secure Boot 开着时，要登记两张证书：先是 **Ventoy 自己的**，装完之后是 **MastersOS 的**。两次都是蓝底的 MokManager，**都不要口令**（只有第 9.5 节说的「去掉 Ventoy 的证书」才要口令）。

**第一次：登记 Ventoy 的证书**（这台机器第一次从任何 Ventoy 盘启动时都一样）：

| # | 屏幕 | 操作 |
|---|---|---|
| 1 | 从 Ventoy 盘启动，蓝屏 `ERROR` / `Verification failed: (0x1A) Security Violation` | 回车（`OK`） |
| 2 | `Shim UEFI key management`：`Press any key to perform MOK management`，左下角 `Booting in 10 seconds` 倒数 | **十秒内按任意键**（错过了就重启再来） |
| 3 | `Perform MOK management` 菜单：`Continue boot` / `Enroll key from disk` / `Enroll hash from disk` | 选 **Enroll key from disk** |
| 4 | `Select Key`：选盘 | 选 **VTOYEFI**（内置盘是空的时只有它一项） |
| 5 | 文件列表：`grub/`、`ventoy/`、`EFI/`、`ENROLL_THIS_KEY_IN_MOKMANAGER.cer`、`tool/` | 选 **`ENROLL_THIS_KEY_IN_MOKMANAGER.cer`** |
| 6 | `[Enroll MOK]`：`View key 0` / `Continue` | **Continue** |
| 7 | `Enroll the key(s)?`：`No` / `Yes` | **Yes**（不问口令） |
| 8 | 菜单第一项变成 `Reboot` | **Reboot** |

截图（PVE，Ventoy 1.1.18、MBR 盘）：1、
2、3、
4、5、
6、7、
8。

重启后再次从 Ventoy 盘启动（Dell 按 F12），这次进 Ventoy 菜单。**BIOS 设置：**保持 Ventoy 的 `VTOY_SECURE_BOOT_POLICY` 为默认的
`0`（不要改）；BIOS 里的 Secure Boot 要放行「微软第三方 UEFI CA」（Dell 一般叫 *Enable Microsoft UEFI CA*，默认是开的），否则
Ventoy 自己的 shim 连启动都不行。

### 9.3 装系统

1. 在 Ventoy 菜单里选 **`MastersOS-installer_<版本>_x86-64.efi`**（菜单里只有它一项，别的 `.raw` 不会出现）。
2. 安装器只核对系统文件的版本与大小（不再算整个文件的 sha256：U 盘上的拷贝是信任的。拷坏了安装时发现不了——安装器把
   `/usr` 分区逐块复制、不核对——装好后表现为读 `/usr` 出 I/O 错，从新的拷贝重装即可），然后同第 5 节：确认屏（`y`）、安装、结束屏。拒装时的屏幕与处理见第 5 节的表。

Ventoy 第一次启动安装器之后屏幕先黑十来秒（找 U 盘：最多等 30 秒，找到后再多看 5 秒有没有第二根带 `MastersOS` 文件夹的盘，合计约 35 秒；第二根盘若比第一根晚出现超过这 5 秒，不会被发现，安装器照第一根装），然后直接是安装器的检查与确认屏。

截图（PVE）：Ventoy 菜单、
确认屏、
结束屏。

拒装（initrd 里，在碰内置盘之前）时屏幕上是英文：原因、怎么做、`The disk has not been touched.`，最后一行
`Press Enter to restart.`：照着改好 U 盘后回车即重启（不进命令行）。下面的截图来自 PVE、是改版之前的（那时停在这一屏不动、
没有回车重启这一行），原因与怎么做两行的原句没变：

| 情况 | 屏幕上的英文（原句） |
|---|---|
| 没有 `MastersOS` 文件夹 | `No MastersOS folder was found on any USB stick.` / `Unzip the download into the root of the Ventoy stick so it has a MastersOS folder, then restart.` |
| 两根盘上都有 `MastersOS` 文件夹 | `More than one MastersOS folder was found (sdb1 sdc1).` / `Keep only one: unplug the other sticks or delete the old folder, then restart.` |
| 系统文件不在 | `MastersOS-system_<v>_x86-64.raw is missing from the MastersOS folder.` / `Unzip the whole download again, then restart.` |
| 版本不对 | `The system file in the MastersOS folder is a different version (<x>); this installer is <v>.` / `Delete the MastersOS folder, unzip the same download again, then restart.` |
| 不完整（大小不对） | `The system file is incomplete (copying did not finish).` / `Copy it again; on a Mac, eject the stick before unplugging. Then restart.` |

截图：没有文件夹、两个文件夹、
系统文件不在、版本不对、
不完整。
（lab 版安装器的控制台在串口上，屏幕是黑的；这几屏是用去掉了命令行末尾 `console=ttyS0` 的 lab 安装器拷贝截的。正式安装器的命令行只有 `console=tty0`，屏幕上预期就是这样，出货前要在真 U 盘、真机上再核对一次。）

种子的问题（两份、坏、`._` 文件）在安装器里拒装，见第 5 节的表；截图：
两份、坏种子、
`._seed.toml`。

### 9.4 装完：登记 MastersOS 的证书（蓝屏）

Secure Boot 开着、这台机器还没登记过 MastersOS 的证书（新机器都是）时，结束屏会多一段，开头是
`Next: one blue screen to approve MastersOS`。**按它说的六步做**：

1. 回车重启，**屏幕黑了再拔 U 盘**（不要先拔，理由见第 5 节的结束屏）；
2. 蓝屏 `ERROR` / `Verification failed: (0x1A) Security Violation` → 回车（`OK`）；
3. `Perform MOK management` 菜单（`Continue boot` / `Enroll key from disk` / `Enroll hash from disk`）→ 选 **Enroll key from disk**；
4. `Select Key` 的卷列表 → 选 **`MASTERSOS`**（机器内置盘上的 ESP，第一项）。列表里**还会有一项 `MOS-GOLDEN`**（内置盘上
   系统自修用的备份分区），**不要选它**；U 盘已拔掉，所以不会有别的；
5. 文件列表（`EFI/`、`mastersos-mok.der`、`loader/`）→ 选 **`mastersos-mok.der`**；
6. `[Enroll MOK]`（`View key 0` / `Continue`）→ **Continue**；`Enroll the key(s)?`（`No` / `Yes`）→ **Yes**；菜单第一项变成
   **`Reboot`** → 回车。**MokManager 不会自己重启**，要选 `Reboot`。

不要口令。安装器已经设了 `MokTimeout`，按完第 2 步的 `OK` **直接进**菜单，没有 10 秒倒数的 `Press any key to perform MOK management`
（PVE 上核对过：停在菜单上十几秒也不走）；个别固件没认这个设置，就会出现 10 秒倒数，**十秒内按任意键**即可。出了岔子（手滑选错、超时）
只要再重启，同一个蓝屏会回来。

截图（PVE）：结束屏、
Security Violation、
菜单、
卷列表：MASTERSOS 与 MOS-GOLDEN、
文件列表、
Continue、
Yes、
Reboot。

Secure Boot 开着且证书之前已登记过（重装、救机）：结束屏不提蓝屏。**Secure Boot 关着**：流程与口令 `mastersos` 都和第 6 节一样，没有变。

### 9.5 这条路径的安全性，要知道两件事

**完整性从哪来。** Ventoy 自己**不校验**我们的安装器：实验里一个签名被改坏的 UKI 在 Secure Boot 下照样启动了。所以这条路径
不能叫「被验证过的启动」。

- 系统文件的**版本与大小**写在安装器 UKI 被签名的命令行里，initrd 在用它之前先核对：只防拷错版本、拷不全。不算 sha256——
  它从来防不了攻击者（见下一段），U 盘上的拷贝是信任的。拷坏了的字节安装时发现不了（安装器把 `/usr` 分区逐块复制、不核对），
  装好后表现为读 `/usr` 出 I/O 错；从新的拷贝重装即可。
- 同一条命令行里的 **`usrhash=`** 钉住 `/usr` 的 verity 根：装好的机器读 `/usr` 时按它核对，所以坏字节读出来是 I/O 错，而不是被悄悄执行。
- MOK 证书 `mastersos-mok.der`（结束屏「Enroll key from disk」选的那份）在 Ventoy 模式下从安装器自己的 `/usr`（verity 保护）复制，
  不从 U 盘 ESP 上没有哈希的那份复制。

换句话说，能在这根盘上换文件的人，也能把安装器一起换掉——**Ventoy 盘要放在 IT 的控制之下**，同第 3 节「当钥匙保管」。

**Ventoy 的 CA 会留在这台电脑上。** 第一次登记之后，「Ventoy Secure Boot Root CA」留在这台电脑的 MOK 列表里。以后的开机都信它，
**包括装好的 MastersOS**（内核会把它读进机器钥匙环）。学生数据的保护不靠这个：数据分区由 TPM 策略锁着，只认我们签名的 UKI。
IT 想把它去掉也行，手动做。证书文件就是 Ventoy U 盘 **VTOYEFI** 分区根目录里的 `ENROLL_THIS_KEY_IN_MOKMANAGER.cer`（第 9.2 节第 4 步选的那个）；
装好的机器上没有它，要自己拷过去：

1. 在别的电脑上把 VTOYEFI 分区里的 `ENROLL_THIS_KEY_IN_MOKMANAGER.cer` 拷到 U 盘或其它地方，再放到装好的那台机器上（不受管理的电脑才有管理员账号可用）。
2. 在 root shell 里 `mokutil --delete ENROLL_THIS_KEY_IN_MOKMANAGER.cer`，按提示设一个**一次性口令**（问两次）。
3. 重启。蓝屏上选 **Delete MOK**，输入刚才的口令，确认（Yes），再 **Reboot**。

这一步要口令，我们**故意不自动做**：会多一个蓝屏和一个口令。

## 给构建的人：U 盘镜像怎么来的

- `build.sh <版本>` 成功后自动调用 `make-installer.sh <版本>`，产物 `mkosi.output/<版本>/MastersOS-installer_<版本>_x86-64.img.zst`。
  `make-installer.sh` 只给 `profile=release`、ESP 不带 `loader/keys/auto`、`secure-boot-enroll off` 的构建做 U 盘，
  并对写好的 U 盘 ESP 再查一遍；lab 构建要显式 `--profile lab`。
- 发布：版本先进 `stable`（`publish.sh <版本> stable` 或 `promote.sh`），再 `publish.sh <版本> installer`
  把 U 盘镜像放进 `<根>/installer/`（UKI 必须与 stable 里那份逐字节相同）。
- U 盘的分区：mkosi 的 `.raw`（ESP + A 槽的三个 `/usr` 分区）加末尾 64 MiB 的 MASTERSOS-SEED（FAT，GPT 类型
  Microsoft basic data，GPT 标签 `mastersos-usb-seed`）。ESP 上多了安装器 UKI（`EFI/Linux/MastersOS-installer_<版本>_x86-64.efi`，
  主 UKI 的内核与 initrd、`installer/installer.cmdline`：`root=tmpfs`、屏蔽 repart、进 `mastersos-installer.target`），
  `loader/loader.conf` 换成 `installer/usb-loader.conf`。主 UKI 挪到 `EFI/mastersos/`（安装器从那里复制到内置盘的
  `EFI/Linux/`）：U 盘的 `EFI/Linux/` 里只有安装器，启动菜单里没有主系统与「恢复出厂」——选了它们会在 U 盘上建分区。
- 安装器在内置盘上按 `installer/install.repart.d` 分区（与首次开机的 `/usr/lib/repart.d` 相同、去掉根分区，
  `tests/check-tree.sh` 第 5 条核对；另加 8–11 号四个空的黄金分区，种子是 12 号，黄金分区由第一次好的开机填上），A 槽从 U 盘逐块复制；根分区由目标机首次开机时 initrd 里的 repart 建。
