# 硬件

整机支持清单（型号 × 无线网卡，spec §6.9）、安装前的硬件检查与翻新出货步骤的骨架（4b Task 22）；真机结果由计划 4b Task 21 填。
后面是打印与扫描（Task 15）。

## 支持清单（按「型号 × 无线网卡」发布）

同一型号出厂就有几种网卡，所以清单按「型号 × 无线网卡」写，不只写型号。状态一列在 Task 21 真机验收之前一律是「待真机」。

| 型号 | 带 2023 证书的最低 BIOS（Dell KB 000347876） | 出厂无线网卡 | 状态 |
|---|---|---|---|
| Latitude 3420（11 代） | 1.44.0（2026-05 的 1.47.0 写明含 2023 证书） | Intel AX201 `8086:a0f0` → 支持；Qualcomm QCA61x4A、Realtek RTL8822CE → 警告 | 待真机（第一批，手上 10 台，Task 21） |
| Latitude 5420 | 1.49.0 | Intel AX201 / AX210 → 支持；MediaTek MT792x → 警告 | 待真机（第一批） |
| Latitude 3420（10 代 i3-1005G1，另一条 BIOS 线，LVFS 上最新 1.37.0） | 没核实 | — | **不在清单**：核实这条 BIOS 线带 2023 证书之前不收 |

**无线网卡的允许清单**（`mastersos_agent::hw::WIFI_ALLOW`）从已核实的 Intel PCI ID 起步（Ubuntu 认证页）：

| PCI ID | 网卡 |
|---|---|
| `8086:9df0` | Wireless-AC 9560（Cannon Point / Whiskey Lake） |
| `8086:02f0` | Wi-Fi 6 AX201 / 9560（Comet Lake） |
| `8086:a0f0` | Wi-Fi 6 AX201（Tiger Lake，3420 / 5420） |
| `8086:2723` | Wi-Fi 6 AX200 |
| `8086:2725` | Wi-Fi 6E AX210 |

加新 ID 要以镜像内核 iwlwifi 的设备表为准、并在真机上验过，同时改代码里的清单与这张表。备件统一用 **Intel AX210**
（PCIe，哪代机器都能插，约 US$20）。Wi-Fi also needs `wpasupplicant` in the image: NetworkManager only Recommends it and
mkosi installs no Recommends, so 20261029.1 showed the Wi-Fi switch but never found a network (Latitude 3420, AX201 `8086:a0f0`).
`mkosi.conf` lists it and `build.sh` refuses an image without `wpa_supplicant`（`check-tree.sh` 第 45 条核对这两处）。镜像里有 SOF 固件（`firmware-sof-signed`，Tiger Lake 的 3420/5420 没有它就没有声卡）
与 `thermald`（3420 会降频）；**第一期不支持指纹**（不装 `fprintd` / `libpam-fprintd`，5x20 的指纹多是 Broadcom ControlVault）。

## 安装前的检查（安装器，spec §6.3）

TPM 检查之后、选盘之前，带不带种子都一样。三档：**拒装**（盘不动）、**警告**（列出全部，按一次 `y` 才继续）、**通过**（不提示）。

| 检查 | 怎么看 | 结果 |
|---|---|---|
| 活动 db 读得到、不是空的 | efivars 的 `db-d719b2cb-…` | 正式版拒装（`db_unreadable`），lab 警告 |
| db 里有 Microsoft UEFI CA 2023 | 按 DER 的 sha256 对 `keys/microsoft/` | 正式版拒装（`db_no_2023`），lab 警告 |
| 要装的 shim 链得到 db 里的某张、没被 dbx 吊销 | 每个签名 × 每张 db 证书：`openssl smime -verify -nosigs -partial_chain` 验链、`sbverify --detached` 验哈希；先查 dbx 的证书与映像哈希（`docs/secure-boot.md`「2023 证书」） | 正式版拒装（`shim_no_chain`；被吊销、dbx 读不懂、判断不了时同样），lab 警告 |
| BIOS 管理员密码 | `/sys/class/firmware-attributes/*/authentication/*/` 里 `role` 为 `bios-admin` 的 `is_enabled`（Dell 由 `dell-wmi-sysman` 提供；没有这个目录就不判断） | 设了 → 警告（`bios_admin_password`） |
| 无线网卡 | `/sys/bus/pci/devices/*` 里 class `0x0280xx` 的设备与它的驱动 | 在允许清单 → 通过；不在清单、有驱动 → 警告（Intel：`wifi_unlisted`；别家：`wifi_non_intel`，「非 Intel 网卡」）；没驱动、Broadcom（`14e4:*`）、或者没有无线网卡 → 警告 `wifi_unusable`「Wi-Fi 不能用，只能用有线网络；可换 Intel AX210」 |

不查：有线网卡（3420 是 Realtek RTL8111H，主线 `r8169`）、型号、BIOS 版本、Absolute（Linux 读不到，出货步骤里在 BIOS 里看）。
拒装缺 2023 证书时给的改法与原因见 `docs/secure-boot.md`「2023 证书」，屏幕上的样子见 `docs/install.md`「安装前的检查」。

## 翻新机的出货步骤（骨架，Task 21 在真机上补全，写进 `docs/shipping.md`）

每台照做，**顺序不能乱**：证书与 TPM 都要在装 MastersOS、绑 LUKS 之前弄好，否则装完之后 PCR 7 变、要恢复密钥。

1. **记下型号与 BIOS 版本**：`dmidecode -s system-product-name`、`-s bios-version`、`-s system-serial-number`；`lscpu` 看是不是 11 代。
2. **升级 BIOS**：Ubuntu live U 盘 `fwupdmgr refresh && fwupdmgr update`，或 Dell 的 U 盘方法（F12 → BIOS Flash Update），
   不低于上表「带 2023 证书的最低 BIOS」。
3. **Reset All Keys**：F2 → Secure Boot → Expert Key Management → 打开 Custom Mode → Reset All Keys → 保存重启；再进 F2 关掉
   Custom Mode，打开 Secure Boot。**之后核对活动 db**（Ubuntu live U 盘里）：

   ```bash
   mokutil --db | grep -E "UEFI CA (2011|2023)"
   ```

   两行都要有（`Microsoft Corporation UEFI CA 2011` 与 `Microsoft UEFI CA 2023`）。只有 2011：BIOS 太旧或 Reset All Keys 没生效。
   （真机上 Reset All Keys 之后这一步要不要再来一次、各型号的表现，Task 21 填。）
4. **确认没有 BIOS 密码**：Admin、System、NVMe 都是 Not set；Admin Setup Lockout 与 Master Password Lockout 关着。有未知密码的退货。
   同时看 Security → Absolute：选项变灰改不了（被前任激活）的退货。
5. **TPM Clear**：Security → TPM 2.0 Security → Clear；确认 TPM 2.0 打开、SHA-256。
6. **装 MastersOS**：从带本校种子的 U 盘启动，登记 MOK；安装前检查没有拒装，警告逐条记下。
7. **核对**：装好的系统里 `mokutil --sb-state`、`mokutil --db`（2011 与 2023 都在）、`tpm2_getcap properties-variable`
   （`ownerAuthSet`、`lockoutAuthSet`、`inLockout` 都是 0）；面板上 `luks:*`、`system:secureboot`、`system:shim-ca` 全部成功。

## 试验网（PVE）上的 db

`pve-edk2-firmware` ≥ 4.2025.05-1 新建的 efidisk（`pre-enrolled-keys=1`）已带 2023 CA；旧 efidisk 用 PVE 的 `ms-cert=2023k`
更新，或 `virt-fw-vars --add-db 77fa9abd-0359-4d32-bd60-28f4e78f784b <Microsoft UEFI CA 2023.der>` 做一份 vars 模板。VM 上没有
无线网卡，所以**每次在 VM 上装机都有一条 `wifi_unusable` 的警告**，确认屏之前要多按一次 `y`。

## 打印机与扫描仪

设置文件里分组的 `printers` 与 `scanners`（`name` + `uri`）由 mastersos-agent 在每台机器上配好，不装任何厂商驱动：

- **打印机**：只支持 **IPP Everywhere**（免驱动）的网络打印机，地址以 `ipp://`、`ipps://`、`http://` 或 `https://` 开头，
  通常是 `ipp://<打印机地址>/ipp/print`。2014 年以后的网络打印机大多支持；打印机的网页管理界面里找 IPP / AirPrint /
  Mopria，开着它就行。agent 对每台执行（每台限时 60 秒，要能连上打印机）：

  ```bash
  env LC_ALL=C.UTF-8 lpadmin -p <队列名> -E -v <uri> -m everywhere -D <名称> -o printer-is-shared=false
  ```

  **队列名就是打印机名称**：空白、控制字符与 `/ \ ? ' " # @` 换成 `_`，最多 127 字节（泰文一个字 3 字节，约 42 个字）。
  打印对话框（Chrome 的打印预览、GTK 的系统对话框）里显示的是队列名，所以名称要起得让老师学生认得出。CUPS 的队列名
  不分大小写：整理之后相同的两台（`A/B` 与 `A#B`、`Office` 与 `office`）面板会报 `device_name_duplicate`，机器上只加前一台。
  地址里不能带账号口令（`ipps://user:pass@…`），面板同样拒收。

  清单第一台设为系统默认（`lpadmin -d`）。agent 只改、只删它自己加的队列（记在
  `/var/lib/mastersos-system/system-state.json`）：本机已有一个同名队列（IT 手工加的）时不动它，那台打印机回报失败——
  改个名字，或先在本机删掉那个队列。
  名称改了就是换一台：旧队列删掉、新队列加上（用户在旧队列上的选项不跟过去）。只改大小写（`office` → `Office`）在 CUPS 里
  是同一个队列，不重加，对话框里仍显示原来的写法。
- **CUPS 版本**：Ubuntu 26.04 的 CUPS 是 2.4.16，用上面的 `-m everywhere`。CUPS 2.5 把 `-m everywhere` 标为过时，
  将来换到 2.5 且它不再认时，等价的写法是 `-m driverless:<uri>`（cups-filters 的 driverless 生成 PPD；**未在 VM 上验证**）：

  ```bash
  env LC_ALL=C.UTF-8 lpadmin -p <队列名> -E -v <uri> -m driverless:<uri> -D <名称> -o printer-is-shared=false
  ```

- **扫描仪**：只支持 **eSCL**（AirScan）的网络扫描仪，地址以 `http://` 或 `https://` 开头，通常是 `http://<地址>/eSCL`。
  agent 写 `/etc/sane.d/airscan.d/mastersos.conf`（sane-airscan 0.99.36 读 `airscan.conf` 之后读这个目录），学生用
  「文档扫描仪」（simple-scan）扫描。地址里同样不能带账号口令（文件所有人可读）。

验证记录：`lab/results/2026-10-16-4b/t15-printing.txt`（VM 上用 `ippeveprinter` 当打印机；真的扫描仪与真打印机在
Dell 验收时测）。
