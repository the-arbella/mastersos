# 正式钥匙：仪式、保管与签名会话

计划 5 Task 4（裁定 8–11）。正式的四把私钥——db（Secure Boot 与 verity）、PCR（UKI 的签名 PCR 11 策略）、gpg（更新源的
`SHA256SUMS`）与考试扩展的 crx 签名钥匙 `kiosk-ext.pem`（计划 9 Task 10：锁定应用的 Chrome 扩展，扩展 id 由它的公钥算出）——
**平时只以 age 加密的一个文件存在 S3**（2026-10-27 起，见下「Mac 上的仪式与 S3」；原来是两根 LUKS U 盘），签名时才解密进构建机
VM 161 的 tmpfs，签完抹掉。明文从来不在任何磁盘上、不到 EIS 的开发机（198.51.100.20）。钥匙表与「丢了会怎样」见 `docs/keys.md`。

| 东西 | 做什么 |
|---|---|
| `ceremony/mac-ceremony.sh` | Mac 上跑：在 colima 的断网容器里依次 `generate`、`seal`、`export-public`、`wipe` |
| `ceremony/gen-release-keys.sh` | 断网环境里以 root 跑：`generate`、`seal`（age）、`write-stick`（LUKS U 盘，旧做法）、`export-public`、`wipe` |
| `keys-load.sh --age <文件>\|A\|B [--verify-only] [--no-repo-check]` | VM 161 上以 `mastersos` 用户跑：age 文件（或 U 盘）→ `/run/mastersos-release-keys`（tmpfs，0700） |
| `keys-unload.sh` | 停 gpg-agent、`shred -u`、删目录；重复跑不报错 |
| `key-leak-check.py <钥匙目录> <路径…>` | 在磁盘上找私钥片段（只报「路径：哪把钥匙」，不打印片段）；0 干净、1 找到、3 有读不了的 |
| `keyset.sh` 的 `keyset_priv release` | 目录不在、属主不对、不是 0700、不在 tmpfs/ramfs、或有 swap → 返回 2；`MASTERSOS_RELEASE_KEYS` 只给测试 |

U 盘上的布局（A、B 相同）：LUKS2（argon2id），头的标签 `MASTERSOS-KEYS-A` / `MASTERSOS-KEYS-B`，里面 ext4，根目录
`mastersos-release-keys/{db.key,db.crt,pcr.key,pcr.crt,kiosk-ext.pem,gpg/}`、`MANIFEST.sha256`（`mastersos-release-keys/` 下每个文件的
sha256）与 `FINGERPRINTS.txt`（四行：`mok-der-sha256`、`pcr-pkfp`、`gpg-fingerprint`、`kiosk-ext-id`）。私钥文件本身不加口令，gpg 钥匙同样
无口令：LUKS 是那一层（裁定 8）。`kiosk-ext.pem` 是 RSA 2048 的 PKCS#8 PEM（`kiosk-ext-pack.sh` 要 ≥ 2048 位、不加密）；
`kiosk-ext-id` 是 32 个 a–p 的字母：sha256(公钥的 SubjectPublicKeyInfo DER) 前 16 字节，每个十六进制位 0–f 映射成 a–p
（与 Chrome、`kiosk-ext-pack.py` 同一算法）。`build.sh` 正式构建取的就是 `/run/mastersos-release-keys/kiosk-ext.pem`，没有它就失败。

## Mac 上的仪式与 S3（2026-10-27 起的做法）

用户 2026-10-27 裁定，取代裁定 8（离线机器 + LUKS U 盘）与裁定 10 的「至少 7 个词、两根 U 盘分两处」：

- 仪式**在 Mac 上做**，不要独立的离线机器。防护是：colima 里一个 `--network none`、`--read-only` 的容器，私钥只在容器的 tmpfs
  （colima 的 VM 里没有 swap，`gen-release-keys.sh` 每步核对），出容器的只有加密文件与公钥。
- 四把钥匙打成一个 tar，用 **age 的口令模式（scrypt）**加密成 `mastersos-release-keys.age`，放进 S3 桶
  `mastersos-release-keys-111122223333-ap-northeast-1`（栈 `mastersos-release-keys`，`infra/cfn/release-keys.yaml`：版本控制、
  Object Lock 治理模式 10 年、桶策略拒绝 `KeyHolderArns` 以外的一切主体）。
- **口令只由用户输入、长度不限**，Claude 与任何程序都看不到：age 自己从终端读，不经参数、不进日志。保护全在口令上：S3 里的
  文件谁拿到都只能离线猜口令，所以口令越长越好（scrypt 让每次猜测很慢，但挡不住很短的口令）。
- 口令丢了等于钥匙丢了（见「两根都丢了」那一段的后果）：抄两份纸，分两处放。

### 做一次

```bash
image/ceremony/mac-ceremony.sh            # 在自己的终端里跑；输出到 ~/mastersos-ceremony-<UTC 时间>/
```

1. 它先建工具镜像（`ubuntu:24.04` 钉了摘要，装 age、gnupg、openssl；只有这一步联网），再起断网容器跑 `generate`，打印四行指纹。
2. `seal`：age 问两次口令（留空 age 会替你生成一个并显示）；再问第三次——**照纸上抄的输**，解密核对清单，抄错了在这里就发现、
   不写文件。
3. `export-public` 写公钥到 `<输出>/pub/`，`wipe` 抹掉 tmpfs，容器退出。
4. 上传（不覆盖已有的同名文件：桶开着版本控制，旧版本也留着）：

   ```bash
   aws s3api put-object --region ap-northeast-1 --bucket mastersos-release-keys-111122223333-ap-northeast-1 \
     --key 2026/mastersos-release-keys.age --body <输出>/mastersos-release-keys.age --checksum-algorithm SHA256
   ```

5. `<输出>/pub/` 的四份公钥拷进仓库的 `keys/`（见下「当场」最后一段），`FINGERPRINTS.txt` 与纸上抄的对一遍。
6. 本机的 `<输出>/mastersos-release-keys.age` 留一份离线副本也可以（它与 S3 里的一样，是密文）；`<输出>` 里没有私钥。

### 签名会话

把 age 文件取到 VM 161（密文，经 S3 或 scp 都行），在**自己的** ssh 终端里：

```bash
~/mastersos/image/keys-load.sh --age ~/mastersos-release-keys.age   # age 问口令 → 解密进 /dev/shm 的 0700 临时目录 → 核对清单与仓库公钥 → /run/mastersos-release-keys
```

之后与下面「签名会话」的第 4–6 步相同（构建、发布、`key-leak-check.py`、`keys-unload.sh`）。`/dev/shm` 的临时目录不论成败都
`shred` 掉。演练：`keys-load.sh --age <文件> --verify-only`。

### 测试

`tests/ceremony-test.sh` 覆盖 `seal`（写出的是 age scrypt 文件、核对时口令输错不写、不覆盖、有 swap 拒绝）与 `keys-load.sh --age`
（演练、载入、口令错、公钥不符、中途失败都不留 `/dev/shm` 的副本），age 的口令经 pty 喂给它。

下面「仪式（一次）」「签名会话」「丢了一根怎么办」是原来的 U 盘做法，`write-stick` 与 `keys-load.sh A|B` 仍可用。

## 仪式（一次，U 盘的做法）

### 准备

1. **离线机器**：一台不再联网用的笔记本（或拆掉网卡的旧机器），内存 ≥ 4 GiB。
2. **Ubuntu 26.04 live U 盘**：在 Mac 上下载 ISO 与 `SHA256SUMS`、`SHA256SUMS.gpg`，先用 Ubuntu 的 CD 镜像签名钥匙验
   `SHA256SUMS.gpg`，再 `shasum -a 256 -c SHA256SUMS --ignore-missing` 验 ISO，然后写盘。启动时在 GRUB 里给内核命令行加
   `noswap`（live 系统不去用盘上找到的 swap 分区），最好把离线机器的内置硬盘拆掉或在 BIOS 里关掉——这样私钥与口令无处落盘。
3. **脚本 U 盘**：本仓库某个提交的 `image/ceremony/` 目录，旁边放一份 `sha256sum gen-release-keys.sh` 的结果，并记下
   提交号。仪式上先在离线机器上重算 sha256、与记下的对一遍。
4. **两根钥匙 U 盘**（A、B）：新的、只做这件事的 USB 盘，容量随意（≥ 64 MiB）。
5. **第四根普通 U 盘**：带出公钥。
6. **口令**：diceware 至少 7 个词（裁定 10），由用户自己掷骰子，或在离线机器上生成；两根 U 盘同一个口令。准备两张纸、一支笔。

### 当场

```bash
# 断网：拔网线；BIOS 里关无线，或至少
sudo rfkill block all
ip -br link            # 只许有 lo（或其它都是 DOWN）
sudo -i
# 没有 swap、不写 core dump——在 generate 之前（generate 与 write-stick 也自己核对 swap，有或读不出就退出）
swapoff -a; swapon --show --noheadings   # 必须什么都不打印
ulimit -c 0; sysctl -w kernel.core_pattern='|/bin/false'
# 脚本 U 盘（只读挂上来），核对脚本
mount -o ro /dev/disk/by-label/<脚本盘> /mnt && cd /mnt/ceremony && sha256sum gen-release-keys.sh
# tmpfs 上的工作目录（live 系统的 / 是 overlay，不算；/run 是 tmpfs）
./gen-release-keys.sh generate /run/mastersos-ceremony
```

- `generate` 打印四行指纹（最后一行是考试扩展的 id）。**手抄到两张纸上**（抄完对读一遍）。
- 插 U 盘 A，`lsblk` 找到它（例如 `/dev/sdb`），然后：

```bash
./gen-release-keys.sh write-stick /run/mastersos-ceremony /dev/sdb A   # 核对型号与容量、输入 YES、输两次口令
# 拔 A，插 B
./gen-release-keys.sh write-stick /run/mastersos-ceremony /dev/sdb B
# 拔 B，插第四根普通 U 盘（挂在 /media/... 或手动 mount）
./gen-release-keys.sh export-public /run/mastersos-ceremony /mnt/pub
./gen-release-keys.sh wipe /run/mastersos-ceremony
poweroff
```

- `write-stick` 只收可移动的 USB 盘（`lsblk -dno TRAN,RM` 为 `usb 1`），口令从 stdin 读两次、不回显、不经参数；写完关闭、
  **重新打开**核对 `MANIFEST.sha256`，不符就退出 1（换一根盘重写）。
- 第四根 U 盘上的 `mastersos-mok.der`、`tpm2-pcr-public-key.pem`、`import-pubring.pgp`、`kiosk-ext-public.pem` 之后拷进仓库的
  `keys/`（前三个由计划 5 Task 7，`kiosk-ext-public.pem` 随计划 9 Task 10 的这次仪式）；`FINGERPRINTS.txt` 与纸上抄的对一遍，
  `kiosk-ext-id` 那一行写进 `docs/keys.md` 钥匙表「考试扩展」一行（`tests/check-tree.sh` 第 35 条核对 `keys/kiosk-ext-public.pem`
  是 RSA ≥ 2048 的 PEM 公钥）。`keys-load.sh` 从此对这四份公钥核对 U 盘，仓库里没有 `kiosk-ext-public.pem` 就拒绝载入（演练可用
  `--verify-only --no-repo-check`）。

### 之后的保管（裁定 10）

- U 盘 A 与一份口令放家里的保险柜，**不放同一个袋子**；U 盘 B 与另一份口令放第二个地点（办公室或银行保管箱）。
- 口令只在纸上，不进密码管理器、不进任何电脑。

## 签名会话（每次发版）

在 VM 161 上以 `mastersos` 用户：

0. 先在这个会话的 shell 里关掉 core dump：`ulimit -c 0`（之后的 build/publish 与它们起的 gpg-agent 都继承）；systemd-coredump
   也收不到：`old=$(sysctl -n kernel.core_pattern); sudo sysctl -w kernel.core_pattern='|/bin/false'`，会话结束
   `sudo sysctl -w kernel.core_pattern="$old"`。`keys-load.sh` 自己也 `ulimit -c 0`。
1. PVE 上把 U 盘直通给 VM 161：`qm set 161 -usb1 host=<vid:pid>`（`lsusb` 看 vid:pid）。
2. `~/mastersos/image/keys-load.sh A`：核对 swap 为空 → 等 `/dev/disk/by-label/MASTERSOS-KEYS-A`（最多 120 秒）→
   `cryptsetup open --readonly`（口令由 cryptsetup 自己从终端读）→ 只读挂载 → 核对 `MANIFEST.sha256` → 拷进
   `/run/mastersos-release-keys`（目录 0700、文件 0600）→ 与仓库的 `keys/mastersos-mok.der`、`keys/tpm2-pcr-public-key.pem`、
   `keys/import-pubring.pgp`、`keys/kiosk-ext-public.pem` 核对 → 卸载、关闭 →「可以拔掉 U 盘」。仓库公钥对不上、任何一步失败或被 Ctrl-C / SIGTERM / SIGHUP 打断都抹掉副本（抹不掉就说出来、退出非 0）。
   sudo 只用于 `cryptsetup`、`mount`/`umount` 与在 `/run` 下建、删这一个目录。
3. 拔出：`qm set 161 -delete usb1`。
4. 构建、发布、同步：`./build.sh <v>`、`./publish.sh <v> beta`、`./promote.sh <v>`、`sync-s3.sh`……（`keyset_priv release`
   每次都核对 tmpfs、0700、属主与 swap）。
5. 签完、抹掉之前，在磁盘上找片段（**用 sudo**：有读不了的文件时它退出 3，不算干净）：

   ```bash
   sudo python3 -I ~/mastersos/image/key-leak-check.py /run/mastersos-release-keys \
     ~/mastersos/image/mkosi.output /srv/mastersos/release /var/tmp /tmp /var/log /var/lib/systemd/coredump /root /home
   ```

   退出 0 才算干净；退出 1 时它列出「路径：哪把钥匙」，那些文件要 `shred -u`，并把这次会话当作可能泄露来评估。
   它查的是原样落盘（压缩、加密过的找不到），所以只是兜底。只扫这几处、不整盘走一遍 `/`：开发机实测约 24 秒/GiB
   （每把钥匙几十个片段，逐个 `bytes.find`），100 GB 的盘要四十分钟。
6. `keys-unload.sh`：停 gpg-agent、`shred -u` 每个文件、删目录，核对目录已不存在。

VM 161 没有 swap（2026-10-17 实测 `swapon --show` 为空），`keys-load.sh` 与 `keyset.sh` 每次都核对。签名期间私钥在 VM 161
的内存里：这段暴露是接受的（裁定 9），直到换 YubiKey（Task 10）。

## 半年演练

每半年对两根各做一次（裁定 10）：

```bash
keys-load.sh A --verify-only    # 载入、核对清单与仓库公钥，然后立刻抹掉副本
keys-load.sh B --verify-only
```

正式公钥入库（Task 7）之前，仓库里还是预发布公钥，用 `--verify-only --no-repo-check`：只核对 `MANIFEST.sha256`，打印
`FINGERPRINTS.txt`，与纸上抄的四行对一遍。`--no-repo-check` 不许单独用（没与仓库核对过的钥匙不留下来签名）。

## 丢了一根怎么办

用另一根再写一根新的，口令不变：

1. 离线机器、live U 盘照「准备」。把剩下那根（比如 B）的内容读进 tmpfs：
   `cryptsetup open --readonly /dev/sdX mastersos-keys-B && mount -o ro /dev/mapper/mastersos-keys-B /mnt/b`，
   `mkdir -m 0700 /run/mastersos-ceremony && cp -a /mnt/b/. /run/mastersos-ceremony/`，卸载、关闭、拔掉 B。
2. 插新盘：`./gen-release-keys.sh write-stick /run/mastersos-ceremony /dev/sdY A`（同一个口令；它先核对 tmpfs 里的清单）。
3. `./gen-release-keys.sh wipe /run/mastersos-ceremony`，关机；新 A 放回原来 A 的地点。丢的那根是 LUKS 加密的：只要口令没一起丢，
   它本身不泄露钥匙；口令也可能一起丢了时，按两根都丢了处理（换钥匙）。

## 两根都丢了

钥匙表的「丢了会怎样」一列（`docs/keys.md`）：db 丢了签不出新的 UKI 与 `/usr`，换钥匙要逐台重新登记 MOK；PCR 钥匙丢了，
新钥匙签的版本在每台机器上都要恢复密钥重绑；gpg 丢了，已装的机器再也收不到更新、只能重装；考试扩展的钥匙丢了，正式构建停下、直到
换新钥匙；新钥匙的扩展 id 不同，下一版镜像的 `kiosk-ext.json` 与宿主清单的 `allowed_origins` 跟着变，而锁定会话每次都从更新源
重新下载扩展，还停在旧镜像的机器要靠更新源同时提供旧、新两个 id 才有「退出」按钮（迁移步骤见 `docs/keys.md` 钥匙表；不用重装、
不碰 TPM）。所以两根分两处放。

## 测试

- `tests/check-tree.sh` 第 35 条（进 CI）：仪式的清单与 `keys-load.sh` 的清单是同一份名单、都有 `kiosk-ext.pem`，`keys-load.sh`
  核对 `kiosk-ext-public.pem`，`key-leak-check.py` 找 `kiosk-ext.pem`；仓库里的 `keys/kiosk-ext-public.pem` 是 RSA ≥ 2048 的 PEM 公钥。
- `tests/keyset-test.sh`（不要 root，进 CI）：`keyset_priv release` 在磁盘上、有 swap、权限 0755、符号链接时拒绝，
  `MASTERSOS_RELEASE_KEYS` 不带 `MASTERSOS_TEST=1` 不认，`MASTERSOS_TEST=1` 时警告并返回；lab 路径不变；`key-leak-check.py`
  找得到嵌在随机文件里的 DER、PEM 正文、PKCS#1 的 DER 与 PEM、76 列折行与不折行的 base64、gpg 私钥文件与导出的私钥包，
  公钥、证书、无关的钥匙不误报，输出里没有片段，读不了的文件退出 3；拷走的 `kiosk-ext.pem` 找得到，它导出的公钥不误报。
- `tests/ceremony-test.sh`（要 root 与 loop 设备，不在 CI）：两个 64 MiB 的 loop 文件当 A、B，走一遍 generate → write-stick
  A、B → export-public → keys-load.sh 的核对函数与整个 keys-load.sh / keys-unload.sh（含核对时意外失败、SIGINT/SIGTERM
  打断之后副本都抹掉）→ wipe → key-leak-check.py；swap 的拒绝经 `MASTERSOS_TEST_SWAP`。考试扩展：`kiosk-ext.pem` 是不加密的
  RSA 2048、0600，`kiosk-ext-id` 等于公钥算出的 id，`kiosk-ext-pack.sh` 收这把钥匙、打印同一个 id，`kiosk-ext-public.pem` 与它一对，
  `kl_repo_check` 对换了或缺了 `kiosk-ext-public.pem` 的公钥目录拒绝，拷走的 `kiosk-ext.pem` 被 key-leak-check.py 找到。
  盘的标签就是正式的那两个，别在插着真 U 盘的机器上跑。
