# 钥匙与数据分区的加密

签名私钥**永不入库**；仓库只放公钥（`keys/`）。正式的四把私钥（db、PCR、gpg 与考试扩展的 `kiosk-ext.pem`）平时只以 age 加密的一个文件存在 S3（2026-10-27 起；原来是两根 LUKS U 盘），
签名会话时由 `keys-load.sh --age` 解密进 VM 161 的 tmpfs `/run/mastersos-release-keys`、会话结束 `keys-unload.sh` 抹掉，
`keyset.sh` 拒绝从磁盘、权限不对或有 swap 的地方读（计划 5 Task 4，裁定 9）；生成、保管、签名会话与演练见
`docs/key-ceremony.md`。lab 的私钥仍在 VM 161 的 `~/mastersos-keys/lab/`。
验收记录在 `lab/results/4a-tpm-matrix.txt`（计划 4a Task 3）。

## 钥匙表

| 公钥（仓库） | 镜像里 | 私钥在哪 | 用途 | 丢了会怎样 |
|---|---|---|---|---|
| —（证书 `db.crt` 在机器的 db / MOK 里） | — | S3 上 age 文件里的 `mastersos-release-keys/db.key` + `db.crt`（RSA 2048，CN `MastersOS Secure Boot 2026`，20 年）；签名时在 `/run/mastersos-release-keys/` | Secure Boot：签 systemd-boot 与 UKI；`/usr` 的 verity 签名 | 签不出新的 UKI 与 `/usr`：已装的机器只认 db/MOK 里的这张证书，换钥匙就要逐台重新登记证书（MokManager 或 BIOS），已装的版本照常能用 |
| `keys/tpm2-pcr-public-key.pem` | `/usr/lib/systemd/tpm2-pcr-public-key.pem`，也是每个 UKI 的 `.pcrpkey` | age 文件里的 `pcr.key` + `pcr.crt`（RSA 2048，TPM 要求；与 db.key **分开**；CN `MastersOS PCR 2026`）；签名时在 tmpfs | UKI 里签名的 PCR 11 策略（`.pcrsig`）；数据分区的 TPM 槽绑这把公钥 | 已装机器的 TPM 槽只认这把钥匙签的 UKI：换了钥匙签的新版本在每台机器上都解不开数据分区（停在恢复密钥提示，见下「口令提示」，带计数的版本三次后退回旧版本），只能靠恢复密钥逐台重绑。`publish.sh` 的闸门拦住 `.pcrpkey` 不符的 UKI，所以这只会在**钥匙丢了、不得不换**时发生 |
| `keys/import-pubring.pgp` | `/usr/lib/systemd/import-pubring.pgp` | age 文件里的 `gpg/`（ed25519，`MastersOS updates 2026`，指纹 `060FD1FF…3FCC1851`，无口令——age 是那一层）；签名时在 tmpfs | 签更新源的 `SHA256SUMS`，sysupdate 用它验签 | 已装的机器再也收不到更新（只认镜像里带的公钥），要重装。轮换见下 |
| `keys/kiosk-ext-public.pem`（扩展 id `lpjoknahjpfoibdmnlkggcgchgojpofk`） | 镜像里没有公钥本身：`build.sh` 由私钥算出 id，写进 `/usr/lib/mastersos/kiosk-ext.json`（`{"id", "update_url"}`）与 `/etc/opt/chrome/native-messaging-hosts/org.mastersos.kiosk_exit.json` 的 `allowed_origins` | age 文件里的 `mastersos-release-keys/kiosk-ext.pem`（RSA 2048，PKCS#8 PEM，无口令）；签名时在 `/run/mastersos-release-keys/kiosk-ext.pem`，`build.sh` 正式构建取它，没有就失败（计划 9 Task 10） | 签锁定应用的考试扩展（crx3，`kiosk-ext-pack.sh`）：扩展 id = sha256(公钥 DER) 前 16 字节映射成 a–p；锁定会话的 Chrome 策略按这个 id 强制安装扩展、只许它连 `mastersos-kiosk-exit` | 不影响启动、数据分区与系统更新，但**正式构建停下**（`build.sh` 没有 `kiosk-ext.pem` 就失败），直到换一把新钥匙。新钥匙的扩展 id 不同：下一版镜像的 `kiosk-ext.json` 与宿主清单的 `allowed_origins` 跟着变（`build.sh` 每次由钥匙算），而还停在旧镜像的机器仍按旧 id 要扩展。锁定会话的 Chrome profile 在每次一新的 tmpfs 家目录里，**每次进入都从 `<更新源>/chrome/updates.xml` 重新下载扩展**——所以 `chrome/` 里只要换成新 id，旧镜像的机器下一次进锁定应用就装不上扩展（没有「退出」按钮）。`publish.sh <v> chrome` 因此拒绝发出与根里不同 id 的扩展。换钥匙要一次迁移（今天没有现成工具）：`updates.xml` 同时列旧、新两个 `<app>`（gupdate 格式允许多个）、旧 crx 留着，直到所有机器都装上新镜像，再撤掉旧的。丢了而没泄露：已发的 crx 照常服务，在迁移做完之前不改扩展。泄露了：别人能签出这个 id 的扩展，但强制安装只从 `kiosk-ext.json` 里的 https 地址取，要同时控制我们的更新源才有用——照上面迁移换钥匙 |
| `keys/lab/`：`mastersos-mok.der`、`tpm2-pcr-public-key.pem`、`import-pubring.pgp` | lab 镜像里同样三处（正式镜像里**没有**） | `~/mastersos-keys/lab/`：`db.{key,crt}`（RSA 2048，CN `MastersOS lab Secure Boot`）、`pcr.{key,crt}`（RSA 2048，CN `MastersOS lab PCR`）、`gpg/`（ed25519，`MastersOS lab updates`，`A31CE845…9951916E`，2026-11-02 随 VM 120 销毁后重新生成） | lab 镜像的整套签名：上面三行在 lab 里的对应物（下「lab 的钥匙」） | 只影响 PVE 的试验机：重新生成、重装试验机。正式机器从来不信它们 |

| `keys/google-chrome-keyring.gpg` | `/usr/share/mastersos/google-chrome-keyring.gpg` | 不是我们的：Google 持有 | `mastersos-agent chrome`（`mastersos-chrome.timer`，有没有种子都跑）用 `gpgv` 验 Google apt 源的 `InRelease`（Task 9，见下「Chrome 的钥匙」） | 不涉及我们的私钥；Google 换了主钥而镜像没跟上时，agent 回报 `chrome` 失败、停在已装的版本 |
| `mkosi.extra/usr/share/mastersos/flathub.flatpakrepo`（里面的 `GPGKey=`） | `/usr/share/mastersos/flathub.flatpakrepo` | 不是我们的：Flathub 持有 | agent 的 Flatpak 任务第一次装应用前 `flatpak remote-add --system --if-not-exists flathub` 用它加源（4b Task 16，见下「Flathub 的钥匙」） | 不涉及我们的私钥；**2027-06-14 到期**，见下 |

上面四行（正式的 db、PCR、gpg 与考试扩展）的「丢了」指 S3 里的 age 文件没了，或口令两份都丢了（S3 开着版本控制与 10 年的对象锁，
文件本身很难丢；口令只在用户的两张纸上）。2026-10-27 的仪式记录与四行指纹见 `docs/key-ceremony-record-2026.md`。
VM 161 `~/mastersos-keys/` 根目录下原来那套（db `CN=MastersOS Secure Boot db`、gpg `0D42FCDF…BD8F8C7A`）一直放在联网构建机的磁盘上，
称**预发布钥匙**：2026-10-27 正式公钥入库时退役，公钥挪到 `keys/retired/*-pre-ceremony.*`（预发布 PCR 公钥在 `keyset_retired release`
的目录里，它签的 UKI 从此发不出去），构建机上的私钥待销毁（裁定 11）。

四把钥匙互相独立：PCR 钥匙泄露只影响数据分区的 TPM 绑定（攻击者还得能让机器启动他签的 UKI，
那要 db.key）；db.key 泄露才是能启动任意内核的那把；`kiosk-ext.pem` 与启动链、数据分区和系统更新都无关，只签考试扩展（见上表）。

## lab 的钥匙（4b Task 1，Ruling 19；spec §6.12 (b)）

lab 镜像带 sshd、已知口令的试验用户与自动登录。它要是用正式的钥匙签，就是一个正式机器照样启动、TPM 照样放行的 root
（终审 I2）。所以 lab 有自己完整的一套，与正式的三把**都不同**（`tests/check-tree.sh` 第 15 条核对：DER 的 sha256、
PEM 的公钥、gpg 主钥指纹）：

- 构建：`build.sh --profile lab` 用 `~/mastersos-keys/lab/` 的 db/verity 与 PCR 钥匙，`mkosi.finalize` 把 `keys/lab/` 的
  三份公钥放进镜像（`/usr/lib/systemd/import-pubring.pgp`、`/usr/lib/systemd/tpm2-pcr-public-key.pem`、
  `/usr/share/mastersos/mastersos-mok.der` 与 ESP 根目录的 `mastersos-mok.der`），并核对 ESP 上的 systemd-boot 由 lab 的证书签；
  `make-installer.sh --profile lab` 用 lab 的 db 签安装器 UKI。钥匙路径只由 `keyset.sh`（`keyset_priv` / `keyset_pub`）拼。
- 发布：`lab=yes` 的根只收 lab 构建、用 `~/mastersos-keys/lab/gpg` 签、按 `keys/lab/tpm2-pcr-public-key.pem` 把关；
  `lab=no` 的根只收正式构建、用 `~/mastersos-keys/gpg`、按 `keys/` 的公钥（`docs/update-channels.md`「根与钥匙」）。
- 效果：正式机器的 MokList 里只有正式的 MOK，shim 拒绝 lab 签的 systemd-boot（Security Violation）；Secure Boot 被关掉时，
  lab UKI 的 `.pcrpkey` 也不是正式机器 TPM 槽绑的那把，TPM 不放行。实测：`lab/results/2026-10-14-4b/t1-build.txt`。
- PVE 试验机（VM 165–168）从 4b 起一律装 lab 钥匙签的镜像，MokManager「Enroll key from disk」登记的是 lab 的
  `mastersos-mok.der`；`vm-create.sh --own-db` 要 PEM，先 `openssl x509 -inform DER -in keys/lab/mastersos-mok.der -out mastersos-lab-db.crt`。

生成（VM 161，一次；私钥永不离开构建机）：

```bash
mkdir -m 0700 -p ~/mastersos-keys/lab && cd ~/mastersos-keys/lab
openssl req -new -x509 -newkey rsa:2048 -nodes -days 3650 -sha256 -subj "/CN=MastersOS lab Secure Boot/" -keyout db.key -out db.crt
openssl req -new -x509 -newkey rsa:2048 -nodes -days 3650 -sha256 -subj "/CN=MastersOS lab PCR/" -keyout pcr.key -out pcr.crt
mkdir -m 0700 gpg && gpg --homedir gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key 'MastersOS lab updates' ed25519 sign never
chmod 0600 db.key pcr.key
# 公钥拷回仓库的 image/keys/lab/（<img> 是仓库里的 image）
openssl x509 -in db.crt -outform DER -out <img>/keys/lab/mastersos-mok.der
openssl x509 -in pcr.crt -pubkey -noout > <img>/keys/lab/tpm2-pcr-public-key.pem
gpg --homedir gpg --export > <img>/keys/lab/import-pubring.pgp
# 考试扩展（计划 9）：lab 的 crx 签名钥匙，build.sh --profile lab 取 ~/mastersos-keys/lab/kiosk-ext.pem（没有就警告、跳过扩展）。
# 公钥不入库：lab 的扩展 id 每次构建由它算出、写进 build-info.txt 的 kiosk_ext_id
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out kiosk-ext.pem && chmod 0600 kiosk-ext.pem
openssl pkey -in kiosk-ext.pem -pubout -outform DER | sha256sum | cut -c1-32 | tr 0-9a-f a-p   # lab 的扩展 id
```

lab 的考试扩展钥匙只在 VM 164（`mastersos-build-b`）上：2026-10-26 生成，扩展 id **`kbgmpkcmikppnmecaigamibbafkckicf`**；
crx 与 `updates.xml` 放在 `https://oslab.khundavid.com/chrome/`（栈 `mastersos-lab-cert`、`mastersos-lab-origin`，`infra/stacks.conf`）。
VM 161 上还没有：在 VM 161 构建 lab 镜像前，从 VM 164 拷同一份过去（id 不变），或生成新的再把 id 记在这里。

`~/mastersos-keys/lab-local/`（试验用户的口令哈希与 authorized_keys）不是签名钥匙，仍在原处。

2026-11-02 起 lab 私钥的来源是 Mac 的 `~/mastersos-keys/`，打包成 Secret `MASTERSOS_LAB_KEYS_B64` 给 GitHub Actions 用；试验用户口令在 Mac 的 `~/.config/testlab/mastersos/lab-student-password`。旧的试验机要重装。

## Chrome 的钥匙（Google 的 apt 签名公钥）

- 来源：`https://dl.google.com/linux/linux_signing_key.pub`（2026-10-13 取），`gpg --dearmor` 成二进制 keyring 入库。
- 主钥指纹 `EB4C 1BFD 4F04 2F6D DDCC EC91 7721 F63B D38B 4796`（「Google Inc. (Linux Packages Signing Authority)」），
  与 Google 在 `https://www.google.com/linuxrepositories/` 公布的「Active (Primary)」一致。`check-google-keyring.sh`
  （`mkosi.finalize` 构建时与 `tests/check-tree.sh` 第 11 条都跑）要求文件里**恰好一把主钥**、指纹等于这个、子钥都只签名，
  不符就拒绝构建——gpgv 信任 keyring 里的每一把钥匙（也不看过期与吊销），多混进一把就多信任一把。那一页上的旧钥匙
  `4CCA 1EAF … 7FAC 5991` 标为 Obsolete，混进来也会被这一条拦下。
- 实际签 `InRelease` 的是子钥：2026-10-13 是 `0E22 5917 4146 70F4 442C 250D FD53 3C07 C264 648F`（2028-01 到期）。
  Google 发新子钥时会更新同一个公钥文件：**每次发镜像前重新取一次、核对主钥指纹不变后替换 `keys/google-chrome-keyring.gpg`**，
  否则旧镜像的机器在新子钥启用后验不过 `InRelease`，Chrome 停在已装的版本（回报 `chrome` 失败「签名验不过」）。
- 钥匙**固定在镜像里**，agent 不从网上取（S2 的试验脚本每次取一次，等于信任当时的 HTTPS 连接）。
- 源没有 `Valid-Until`：旧的、签名有效的索引可以被回放（能终止 `dl.google.com` TLS 的人，例如装了学校检查代理 CA 的网络）。
  两道下限：签名 Release 的 `Date:` 不得早于本机见过的最新一份（`/var/lib/mastersos/chrome/release-date`），已装的版本不降级。
  恢复出厂会清掉这个下限，之后第一次取到的签名索引照收（构建时预置下限没做）；一直回放同一份最新见过的索引只能让 Chrome
  停在当前版本、回报里的版本号不再变；没跑完一轮（被杀、定时器停了）超过 14 小时则 `chrome` 报失败。
- **CDN 的边缘节点不同步（接受）**：dl.google.com 是 CDN，刚发布新版本时，一轮可能取到新的 `InRelease`、下一轮又碰上还没同步的
  节点拿到旧的，这一轮按「比见过的旧」拒绝、`chrome` 报失败，节点同步后下一轮自己恢复。报错里写明了这种可能与恢复办法：
  一直这样且确认源没问题时，删掉 `/var/lib/mastersos/chrome/release-date`。没有为此放宽（例如差一天以内只当没变）：放宽的窗口
  就是能回放的窗口。

## Flathub 的钥匙（Flathub 仓库签名公钥，4b Task 16）

- 来源：`https://dl.flathub.org/repo/flathub.flatpakrepo`（2026-10-16 取），文件原样放进镜像；`GPGKey=` 是 base64 的公钥。
- 主钥指纹 `6E5C 05D9 79C7 6DAF 93C0 8135 4184 DD4D 907A 7CAE`（「Flathub Repo Signing Key <flathub@flathub.org>」），
  子钥 `54A6 CDDD 8919 FB20 4200 D8AC 5627 02E9 E3ED 7EE8`；**两者都在 2027-06-14 到期**。
- 只在机器上还没有 `flathub` 源时用一次（`--if-not-exists`）；之后 flatpak 用源配置里存的那份。Flathub 历来是延长同一把钥匙的
  有效期，并在仓库摘要里带上新的公钥，已经加过源的机器跟着摘要走；**镜像里这份要在 2027-06 之前换成延期后的版本**，
  否则那之后新装（或恢复出厂）的机器第一次加源就带着过期的钥匙，装应用失败（回报 `flatpak:<id>`「加 Flathub 源失败」或安装失败）。
- 更新：重新取上面的文件，`grep ^GPGKey= flathub.flatpakrepo | cut -d= -f2- | base64 -d | gpg --show-keys` 核对主钥指纹不变、
  到期日已延后，再替换 `mkosi.extra/usr/share/mastersos/flathub.flatpakrepo`，提交说明里写新的到期日；同时改这一节的日期。

## 数据分区：签名的 PCR 11 + pcrlock（只锁 PCR 7）

根分区 `MastersOS-root`（`/etc`、`/var`、`/home`）是 LUKS2。期望的状态（Task 8 的 agent 按它判断）：

- 一个 **recovery** 槽，且已托管到服务端；
- 一个 **TPM2** 槽，同时带签名公钥（`tpm2-pubkey-pcrs: 11`）与 pcrlock（`tpm2-pcrlock: true`），
  字面 PCR 为空（`tpm2-hash-pcrs:` 后面什么都没有）。任何地方都不写带值的字面 PCR（`tests/check-tree.sh` 第 2 条，查镜像树与 `core`）。

两半各管什么：

- **签名的 PCR 11，只签 `enter-initrd`**（4b Task 4，见下「签名的阶段」）：UKI（内核、initrd、命令行、os-release、profile）
  由我们签过。镜像更新换了 UKI 也不用重绑——新 UKI 自带新的签名（矩阵第 3 行）。别人签的 UKI 解不开（第 8 行）。
  **只签 `enter-initrd` 一个阶段**：离开 initrd 之后 PCR 11 不再满足策略，TPM 不放行——所以同一台机器上另一块盘
  （或 U 盘）上进到用户态、拿到 root 的 MastersOS **也**解不开这块数据分区（矩阵第 9 行，`lab/results/2026-10-15-4b/t4-initrd-only.txt`）。
- **pcrlock，只锁 PCR 7**（`systemd-pcrlock make-policy --pcr=7`，镜像里
  `systemd-pcrlock-make-policy.service.d/50-mastersos.conf`）：PCR 7 是 Secure Boot 的状态与 db/KEK/PK/dbx，
  以及「这次启动用 db 里哪张证书验过」。关掉 Secure Boot 再改内核命令行（`init=/bin/sh`）时 PCR 11 照样对得上，
  只有 PCR 7 拦得住（第 5 行）。**不锁** PCR 0–5（固件代码与配置、UKI 二进制）：否则每次 Dell BIOS 更新、
  每次镜像更新都要输恢复密钥（第 7 行实测 PCR 0、1 变了照样无感）。扩大到 PCR 0–5 要用户确认（Ruling 7）。
  shim 在 PCR 7 里记的 `SbatLevel` 与 db 签发者，pcrlock 都认得（`PCR 7 … fully consists of recognized measurements`）。

**pcrlock 在 systemd 259 里仍标为实验性。**

### 签名的阶段（4b Task 4，Ruling 28）

UKI 的 `.pcrsig` **只签 `enter-initrd` 一个阶段**：离开 initrd、进到用户态之后，PCR 11 已经扩展过，
不再满足这条签名策略，TPM 不再放行数据分区的钥匙。mkosi v27.1 没有对应设置、默认把 `--pcr-private-key`
交给 `systemd-measure` 的四个阶段（`enter-initrd`、`…:leave-initrd`、`…:sysinit`、`…:ready`），也不接受在
`ukify.conf` 里补 `Phases=`（它与命令行给的私钥不在同一个「组」，ukify 会报 `--phases` 必须与 `--pcr-private-key`
一一对应）。做法：`build.sh` 用 `ExtraSearchPaths=` 在 PATH 最前放一个名为 `ukify` 的 Python 包装脚本
（mkosi 以 `python3 <ukify> build …` 调它），在 `build` 子命令且有 `--pcr-private-key` 时注入一条
`--phases=enter-initrd`，再 exec 真正的 ukify；两个 profile（主系统、恢复出厂）一致生效。不改 mkosi 源码、
不在构建后重写 UKI（`lab/results/2026-10-15-4b/t4-initrd-only.txt` Step 1.1）。把关在 `uki-pcrsig-check`
（`keyset.sh` 的 `keyset_check_uki` 调它）：每个 profile 的 sha256 签名**恰好一条**（原来是四条），而且它的策略（`pol`）
等于照 systemd-stub 的量法重算出的 enter-initrd 阶段 PCR 11 的 PolicyPCR 摘要——签了一条、但签的是离开 initrd 之后的
阶段也拦得下。三处都用这一份：`build.sh`（mkosi 之后、写 build-info 之前，包装没生效就构建失败）、`make-installer.sh`
（放进 U 盘的主 UKI；安装器 UKI 另核对不带 `.pcrsig`/`.pcrpkey`）、`publish.sh`/`promote.sh` 的 `check_uki`。
测试 `tests/uki-check-test.sh`（含喂给真的 make-installer.sh 一个四阶段 UKI）。

**代价（终审 C1）已修——这是出货前必须解决的（§6.12 (a)），本任务修好**。原来四个阶段都签，PCR 11 策略在离开
initrd 之后、进到用户态仍然满足；pcrlock 只锁 PCR 7（Secure Boot 状态与 db/MOK），而所有 MastersOS 机器的启动链
（微软签的 shim、我们的 MOK、我们签的 systemd-boot 与 UKI）一模一样。所以在**同一台机器**上，任何一个带我们
PCR 签名、进到了用户态的 UKI——另一块装着 MastersOS 的盘、另一个版本——都能用这台机器的 TPM 解开这块数据分区的
钥匙，只要它给了攻击者一个 root。spec §6.12 列了两个载体，现在都堵上：

- **(b) lab 镜像（已修，4b Task 1）**：lab 原来与正式共用全部签名钥匙（终审 I2）。现在 lab 用自己的一套钥匙
  （上「lab 的钥匙」）：正式机器的 shim 不启动 lab 签的 systemd-boot，Secure Boot 被关掉时 lab UKI 的 `.pcrpkey`
  也不是正式的那把，TPM 不放行。
- **(a) 别的签名用户态（已修，4b Task 4）**：不带种子的**正式**镜像装在另一块盘上（或 U 盘启动），
  `mastersos-firstrun` 让装的人自己建 sudo 管理员——一个给了 root、带我们 PCR 签名、进到用户态的启动。原来四个阶段
  都签，TPM 照样放行（缺口）。修法：数据盘的 PCR 签名只签 `enter-initrd`（上一段），离开 initrd 之后 TPM 不再
  放行；首次开机 / 恢复出厂时 initrd 里的 repart 用一把一次性的临时钥匙再加一个钥匙槽，agent 在用户态用它
  （不靠 TPM）登记恢复密钥、换 TPM 槽，之后去掉临时钥匙槽（下「顺序」「agent 怎么做」）。换签名阶段要连 PCR
  签名钥匙一起换新（旧钥匙签过的四阶段 UKI 永远有效、堵不住缺口；旧钥匙退役，公钥存进 `keys/retired/`、
  `keys/lab/retired/`，`check_uki` 拒收 `.pcrpkey` 等于它的构建）。VM 实测见 `lab/results/2026-10-15-4b/t4-initrd-only.txt`
  （矩阵第 9 行：修之前另一块盘的用户态解得开内置盘，修之后解不开）。

**BIOS 锁定不做**（用户 2026-10-14 决定不管 BIOS）：spec §2.2 本就把「设 BIOS 管理员密码、关 U 盘启动」列为可选的
运维建议、不是产品功能。所以 (a) 只能靠上面的软件修法在出货前解决，没有「做了 BIOS 锁定就降为加固」的退路。

防护边界只到软件（Ruling 18）：拆盘、跳线或拔电池清 BIOS、换主板不在防护范围内，这里不为它们设防。

### 顺序（Ruling 7）

1. 首次开机 / 恢复出厂：initrd 里的 `systemd-repart` 按 `repart.d/40-root.conf` 的 `Encrypt=key-file+tpm2` 建 LUKS，
   建出**两个槽**：一个 TPM 槽只绑签名的 PCR 11（自动用 `/run/systemd/tpm2-pcr-public-key.pem`，即 UKI 的 `.pcrpkey`；
   这时还没有 pcrlock.json），以及一个**不属于任何 token 的临时钥匙槽**——`mastersos-luks-bootstrap-key`（repart 之前）
   生成一把 32 字节随机钥匙到 `/run/mastersos/luks-bootstrap-key`，`systemd-repart.service.d/50-mastersos-bootstrap-key.conf`
   以 `--key-file=` 交给 repart。切根之前 `mastersos-luks-bootstrap-persist` 把这把临时钥匙放进解开的根分区
   （`/var/lib/mastersos-system/luks-bootstrap-key`，0600），**只在 repart 真的建了新分区时才放**（根分区 LUKS UUID 变了）。
   不要输入。数据盘的 PCR 签名只覆盖 `enter-initrd`，离开 initrd 之后 TPM 不再放行——所以 agent 动 LUKS 不能靠 TPM，
   靠这把临时钥匙。
2. 同一次开机进入用户态后，镜像里的 `systemd-pcrlock-make-policy.service` 生成 `/var/lib/systemd/pcrlock.json` 与
   TPM 里的 NV 策略（preset 启用它与 `systemd-pcrlock-secureboot-{policy,authority}.service`）。它只碰 TPM 的 NV，
   不碰 LUKS 槽。
3. agent（**用临时钥匙解锁，不用 TPM**）：登记恢复密钥 → 托管到服务端并得到确认 → 把这把恢复密钥写成自己保管的
   `HeldKey`（`/var/lib/mastersos-system/luks-recovery-key.json`，0600）→ 把 TPM 槽换成「签名 PCR 11 + pcrlock」→ 去掉
   临时钥匙槽与临时钥匙文件。从首次开机到托管成功这段时间，数据分区由签名 PCR 11（只在 initrd 有效）加临时钥匙槽
   保护，换来的是「需要恢复密钥时，服务端一定有它」。

### agent 怎么做（Task 8：`mastersos-agent` 的 `luks.rs`；矩阵第 4 行的结论）

agent 的后台任务 `luks`（每小时一次，网络连上时也提前跑；只在受管的机器上，即有种子时）按 `cryptsetup luksDump` 与
`/var/lib/mastersos-system/luks-state.json`、`escrow-pending.json` 的现状一步步推：

   **用户态一律不用 TPM 解锁**（数据盘的 TPM 签名只覆盖 `enter-initrd`）：每一条 `systemd-cryptenroll` 都
   `--unlock-key-file=/dev/stdin` 并经 stdin 送钥匙。`unlock_key` 按序挑钥匙：先 `HeldKey`（UUID 对得上）、再这个分区的
   待托管密钥、再首次开机的 32 字节临时钥匙（`luks-bootstrap-key`，恰好 32 字节才用）；都没有就回报 `luks:recovery`
   失败「本机没有能解开数据分区的钥匙……请恢复出厂或重装」、什么都不动。钥匙文件读不出（不是「不存在」）时整轮不动分区。
   计划 6 起托管收件人变了要轮换恢复密钥（先于补 pcrlock）：4b 时托管、本机没有 `HeldKey` 的 lab 机器轮换不了，每轮都报这条，要恢复出厂。

1. 登记恢复密钥：`systemd-cryptenroll --unlock-key-file=/dev/stdin --recovery-key /dev/gpt-auto-root-luks`（解锁钥匙见上；
   盘上已有的恢复槽一律不先动，见下）。新密钥只在命令的 stdout 里（经管道读进内存，不落 /tmp），先经 stdin 用
   `cryptsetup open --test-passphrase --disable-external-tokens --key-file=-` 核对它真能解开分区——**不加
   `--disable-external-tokens` 时 cryptsetup 先试 TPM token，任何口令都「通过」**（VM 168 实测）——再写进
   `escrow-pending.json`（0600），然后才托管。服务器连不上时下一轮拿同一把重试，不会再登记一把。
2. 托管（`POST /v1/escrow`）。204 才记下 `escrowed_luks_uuid`、删待托管文件；403、429、连不上都回报 `luks:escrow` 失败
   （带状态码与服务端的说明），不往下走。第一份状态回报等这一步的第一轮跑完（最多 90 秒；拉取与应用不等）。
   **托管只走 https**（终审 I4）：种子的 `server_url` 不是 `https://` 时，正式镜像的 agent 连第 1 步都不做、已有的待托管
   密钥也不发，回报 `luks:escrow` 失败「托管被拒（本机）：…只经 https 发送…」，pcrlock 因此一直不绑。例外只有 lab 镜像
   （签名 `/usr` 里构建时写下的 `/usr/lib/mastersos/profile` 是 `lab`；读不到按正式镜像）。本机回环地址（`127.0.0.1`、`::1`、
   `localhost`）在 4b 起也不再例外（Ruling 27）：测试在临时 root 里写 `usr/lib/mastersos/profile = lab`。换领 `fetch_token`
   （`POST /v1/fetch-token`，请求体里有托管凭据）走同样的规则、同样不跟随重定向。mastersos-server 的 `public_url` 不是 https 时启动打一行警告（不拒绝：试验网就是 http）。
   托管请求**不跟随重定向**（3xx 当被拒：307/308 会带着请求体重发到 Location）；agent 别的 HTTP 请求（拉包、心跳、回报、
   设置包里的文件、Chrome 的源）跟随重定向，但一旦走过 https 就不许跳回 http。lab 的判断只看签名的 `/usr`，种子与 `/var`
   都改不了它。
3. 托管确认之后才补 pcrlock（下面第一条）。之后每一轮看策略服务有没有失败（下面第二条）。

**这两件事都只在本轮 `bootctl status` 说 Secure Boot 开着时做**（Task 8 修复轮 1）：Secure Boot 关着时按当前的 PCR 7
生成或改写策略，等于把「Secure Boot 关着」授权进去，关掉 Secure Boot 改内核命令行（矩阵第 5 行）就又能用 TPM 解开
数据分区。代价：**关着 Secure Boot 装的机器一直只有签名的 PCR 11 保护**（`luks:pcrlock` 报失败「Secure Boot 没有开启…」，
`system:secureboot` 同时报失败），直到 IT 打开 Secure Boot，agent 下一轮自动补上；已绑好的机器 Secure Boot 被关掉后，
每次开机都要恢复密钥，agent 不改写策略，直到 Secure Boot 重新打开。

另外（修复轮 1、2）：

- `luks-state.json` 或 `escrow-pending.json` 读不出（不是「不存在」）时整轮不动分区，回报 `luks:escrow` 失败。
- 换恢复密钥（例如 `luks-state.json` 丢了）**一律先登记新的、托管成功，再按 luksDump 里的编号去掉旧的恢复槽**，不论分区
  绑没绑 pcrlock（Secure Boot 关着的机器分区一直不绑，「没绑」不等于「没托管过」）：任何时刻服务端都有一把能用的。去掉
  旧槽时用刚托管、登记时已核对过的那把新密钥解锁（经 stdin，`--unlock-key-file=/dev/stdin`），不依赖 TPM——pcrlock 策略这时
  可能正坏着。没托管成功的孤儿槽留在盘上无害，下一次托管成功时一起去掉；盘上已有 4 个恢复槽时不再登记、回报失败。
- 恢复密钥那边（登记、托管、去旧槽）失败不挡用 PIN 改写 pcrlock 策略（改写只碰 TPM 的 NV，不碰 LUKS 槽）。
- 不属于任何 token 的口令槽（首次开机的临时钥匙槽、换 TPM 槽的 cryptenroll 半路断电留下的、IT 手工加的）：托管与 pcrlock
  都好了之后按编号去掉，解锁用 `unlock_key`（`HeldKey` / 待托管 / 临时钥匙，经 stdin，不用 TPM）。去完之后，首次开机的
  临时钥匙文件（`luks-bootstrap-key`）还在就删掉。回报上：**多余的槽只有首次开机的临时钥匙那一个、且本机还留着那把文件时
  `luks:tpm` 照样成功**（detail「首次开机的临时钥匙槽还在，托管与 pcrlock 好了之后去掉」）；别的多余口令槽让 `luks:tpm` 失败。
  **这一条也会去掉 IT 手工加的口令**（`cryptsetup luksAddKey`）：数据分区上只许有 TPM 槽、托管过的恢复槽、以及首次开机还没
  收尾的临时钥匙槽；手工口令下一轮就被去掉；要临时进机器请用托管的恢复密钥。
- TPM 槽绑的不是这个镜像的 PCR 公钥（换过签名钥匙，slot 绑着退役的那把）：`luks:tpm` 报失败「TPM 槽绑的是别的 PCR 公钥
  （换过签名钥匙），这次开机多半用了恢复密钥；托管好了会换槽」；托管好了之后 agent 用 `HeldKey` 把槽换成这个镜像的新钥匙。

回报项：`luks:tpm`、`luks:recovery`、`luks:escrow`（成功时带 LUKS UUID，供与托管的行对照）、`luks:pcrlock`，另有
`system:secureboot`（`bootctl status` 的 `Secure Boot:` 一行）。

上游的 `make-policy` 在第一次建 NV 策略时，会随机生成一个**恢复 PIN**、只把它封进 TPM（绑在当时的 PCR 7 上），不告诉
任何人。db/dbx 变了（BIOS 更新、dbx 吊销、IT 往 db 追加证书）之后，PCR 7 对不上，这个 PIN 就解不出来了：
`systemd-pcrlock-make-policy.service` 在用恢复密钥进来的那次开机里**失败**（`None of the alternative values for PCR 7
encoded in policy match the current TPM state`），下次开机照样要恢复密钥——brief 预期它会自己恢复，实测不会。

所以 agent 要自己掌握这个 PIN：

- **换 TPM 槽之前**（托管确认之后、`AddPcrlock` 这一步里）：生成 32 字节随机数、**编码成文本**（hex 或 base64，PIN 经
  ask-password 的凭据读入，是一行文本，不能是原始字节）写 `/var/lib/mastersos/pcrlock-pin`（0600），
  `systemd-pcrlock remove-policy`，再用这个 PIN 重建策略，然后才 `systemd-cryptenroll`：
  ```
  # PIN 经 0600 的凭据文件传入（不进命令行、不进环境变量）；agent 用的目录是 /run/mastersos-agent/pcrlock-cred（0700）
  d=/run/mastersos-agent/pcrlock-cred
  install -m 0600 /var/lib/mastersos/pcrlock-pin "$d/pcrlock.recovery-pin"
  /usr/lib/systemd/systemd-pcrlock remove-policy
  env CREDENTIALS_DIRECTORY=$d /usr/lib/systemd/systemd-pcrlock make-policy --location=770 --pcr=7 --recovery-pin=query </dev/null
  rm "$d/pcrlock.recovery-pin"
  # 解锁经 stdin（unlock_key 挑的钥匙：HeldKey / 待托管 / 首次开机的临时钥匙），不用 TPM
  systemd-cryptenroll --unlock-key-file=/dev/stdin --wipe-slot=tpm2 --tpm2-device=auto \
      --tpm2-public-key=/usr/lib/systemd/tpm2-pcr-public-key.pem --tpm2-public-key-pcrs=11 \
      --tpm2-pcrs= --tpm2-pcrlock=/var/lib/systemd/pcrlock.json /dev/gpt-auto-root-luks < <钥匙>
  ```
  `remove-policy` 要在 `cryptenroll` 之前：这时 TPM 槽还只绑 PCR 11，删掉旧的 NV 不影响解锁（它连 NV 索引一起删，
  实测 `Removed NV index`；没有策略时也退出 0）。`make-policy` 的参数与镜像里那个单元的 drop-in 相同（`--location=770
  --pcr=7`），之后它每次开机照常运行，预测相同就跳过（`Prediction is identical to current policy`，VM 165 实测），
  PIN 继续由它封着。`/var/lib/systemd/pcrlock.json` 还没有时（这次开机策略服务没成功）这一步等下一轮，回报
  「等 pcrlock 策略」。
- **`systemd-pcrlock-make-policy.service` 失败时**（典型：这次开机是用恢复密钥进来的）：同样把 PIN 放进凭据目录，跑
  `make-policy --location=770 --pcr=7 --recovery-pin=query`（不 `remove-policy`）。它用 PIN 授权改写**同一个** NV 索引，
  LUKS 槽不动，下次开机恢复无感（矩阵第 4 行：`Updated NV index`，随后的开机 TPM 直接解开）。PIN 错了它报
  `Failed to write to NV index` 并退出非 0。agent 改写成功后 `systemctl reset-failed` 那个单元，回报 `luks:pcrlock`
  成功并注明「已用 PIN 改写策略」；本机没有 PIN 时回报失败（下次开机仍要恢复密钥）。Task 8 在 VM 165 上用 agent 跑过
  三次：往 db 追加证书、shim 15.8 → 15.7（连同旧的 SbatLevel）、再由 `mastersos-bootloader-update` 换回 15.8——每次都是
  一次恢复密钥、agent 改写、下次开机无感，NV 索引始终是同一个（`lab/results/4a-t8-luks.txt`）。
- **换 shim 之前（计划 5 Task 8）**：`mastersos-agent shim-prepare` 同样经凭据目录（`/run/mastersos-agent/shim-prepare-cred`，与上面
  luks 任务的分开）把 PIN 交给 `make-policy --location=770 --pcr=7 --recovery-pin=query`，在 PCR 7 的签发者组件里多放一个
  「新 shim 的 `SbatLevel`」变体（`620-secureboot-authority.pcrlock.d/400-mastersos-next-shim.pcrlock`），新旧两种 PCR 7 都被接受；
  新 shim 开机之后 agent 删掉这个变体、再用 PIN 建一次。PIN 不进命令行、日志与回报。细节见 `docs/secure-boot.md`
  「引导程序更新与 TPM」。
- 恢复出厂会清掉 `/var`（`pcrlock.json` 与 PIN 文件一起没了），旧的 NV 索引留在 TPM 里（实测每次恢复出厂多一个），
  agent 照第一步重新来一遍（它自己的 `remove-policy` 删掉的是首次开机那个单元建的索引，不再多留）。**Task 8 的决定：不清理
  恢复出厂留下的旧索引。** 认出「哪个索引是 pcrlock 以前留下的」只能靠句柄范围（owner 范围 `0x01800000`–`0x01BFFFFF`）
  与属性去猜，别的软件（固件、别的系统）也可以在同一个范围里建索引，删错了的后果是别人的东西坏掉、而且无法恢复；
  每个 pcrlock 索引只占几十字节（一个摘要），一台机器一生恢复出厂的次数有限，NV 空间耗尽之前要恢复出厂几十上百次。
  真遇到 NV 满了（`make-policy` 报 `TPM_RC_NV_SPACE`，回报 `luks:pcrlock` 失败），IT 在 BIOS 里清 TPM 再恢复出厂。

PIN 放在加密的根分区上：能读它的人已经在一台解开了的机器上拿到 root，那时卷密钥本来就读得出来。

**PIN 加上能碰到机器，等于恢复密钥**：拿着 PIN 的人可以关掉 Secure Boot 启动任意系统，用 PIN 把 NV 策略改写成接受
「Secure Boot 关着」的 PCR 7，再启动我们的 UKI 加 `init=/bin/sh`——矩阵第 5 行拦下的那种攻击就成了。所以：

- PIN 按恢复密钥对待：不进状态回报、不进日志、不进任何备份；只在 `/var/lib/mastersos/pcrlock-pin`（0600）与临时的凭据目录里；
- 轮换 TPM 槽或恢复密钥时 PIN 一起换（`systemd-pcrlock remove-policy`，新 PIN 重建策略，再换 TPM 槽），旧 PIN 随旧策略作废；
- 以文本（hex 或 base64）存放，见上。

## 口令提示（恢复密钥）

`/usr/lib/systemd/system/systemd-cryptsetup@root.service.d/50-mastersos.conf`（只在 initrd 里）给根分区加了
`timeout=300`（不试空口令：没有 TPM 的机器装不上，数据分区一定有 TPM2 槽，见下一节）。**gpt-auto 生成器不读 `rd.luks.options=`**（只有 cryptsetup 生成器读，
它管 crypttab 与 `rd.luks.uuid=`；systemd 259 源码与实测），所以没用内核命令行，而是 drop-in 换掉生成的
`ExecStart`（前四段与生成的一模一样，`root=dissect` 时设备是 `/dev/disk/by-designator/root-luks`）。

另一个时限：initrd 等解开之后的根设备（`/dev/disk/by-designator/root`）默认只等 90 秒，从 initrd 一开始就算。
不改它的话，提示出现约 90 秒后就重启了（Task 3 第一轮实测 93–95 秒）。`dev-disk-by\x2ddesignator-root.device.d/50-mastersos.conf`
把它放宽到 330 秒，实测提示到重启 327–329 秒。

330 秒的代价：

- 从 **initrd 一开始**就算，不是每次提示重新算：前面花掉的时间（TPM 试解、第一次输错）都从里面扣，输错一次、
  在 250 秒左右重来的人可能输到一半就被切断重启。
- 根分区**真的找不到**的版本（initrd 坏了、分区定义错了）也要等满 330 秒才重启：带计数的新版本退回上一版要
  3 ×（330 + 10）秒 ≈ 17 分钟，原来是 3 × 100 秒 ≈ 5 分钟。正常开机不受影响（设备一出现任务就完成）；Task 2 的
  120 秒健康检查窗口在用户态、GDM 之后才开始，也不受影响。

行为：

- 提示 5 分钟没人输 → 失败 → initrd 的 emergency.service（Task 2 的 `50-mastersos-reboot`）10 秒后重启。
- **带启动计数的版本**（sysupdate 装进来的 `+3`）：三次后退回上一版本（矩阵第 8 行）。
- **不带计数的版本**（装好后的第一个，或已被标为好的版本）：每次开机都再提示一次。**不是砖**：输入恢复密钥照样进得去；
  只是没人在场时会每 5 分半钟重启一次。恢复密钥是 64 个字母（8 组），要在 5 分钟内输完。
- 提示从 `/dev/console` 读：正式镜像是屏幕和键盘；lab 镜像的 `console=ttyS0` 排在最后，提示从串口读（试验里用
  `socat` 往串口写，`qm sendkey` 敲的键到不了）。

## TPM 2.0 是前提（4b Ruling 17）

我们卖的翻新 Dell 都有 TPM 2.0。**没有可用 TPM 的机器安装器拒装**，带不带种子都一样；4a 的无 TPM 路径（initrd 里把根分区
建成空口令 LUKS 的单元、开机先试空口令、agent 在 TPM 后来能用时补绑）已经去掉，数据分区一定有 TPM2 槽。

「可用」的判断在 `mastersos_agent::tpm::probe`（安装器用它）；initrd 里的 `/usr/lib/mastersos/tpm-probe` 是同一套规则的 shell 版，
留给恢复出厂的确认（TPM 用不了时不清数据），退出码 0 = 可用、1 = 确认用不了（标准输出一行中英双语原因）、255 = 判断不了。
按序：

| 情况 | 判定 | 拒装时屏幕上的改法 |
|---|---|---|
| `udevadm settle --timeout=10` 之后（冷插拔事件处理完，TPM 驱动在里面加载；失败只记一行），`systemd-analyze has-tpm2` 报缺 `-libraries` / `-libtss2` | 判断不了 | 原因 + 请联系我们 |
| 没有 `/dev/tpmrm0`，且 `has-tpm2` 报 `-firmware` 与 `-driver` | 确认没有（只有 TPM 1.2 的机器也算）：「没有 TPM 2.0 / No TPM 2.0」 | 在 BIOS 的 Security → TPM 2.0 Security 里打开 TPM / Turn on TPM 2.0 under Security → TPM 2.0 Security |
| 没有 `/dev/tpmrm0`，但固件或内核说有：每秒看一次、最多 30 次 | 仍没有就判断不了 | 原因 + 请联系我们 |
| 有 `/sys/class/tpm/tpm0`，没有它的 `pcr-sha256/` | 没有 SHA-256 的 PCR bank：「TPM 没有 SHA-256 的 PCR bank / The TPM has no SHA-256 PCR bank」（只开了 SHA-1、或只有 SHA-384；UKI 只签 SHA-256 的 PCR 策略，首次开机会重启循环） | 在 BIOS 里把 PCR bank 改成 SHA-256 / Switch the TPM PCR bank to SHA-256 in BIOS |
| `systemd-creds encrypt --with-key=tpm2` 试封装三次（间隔 2 秒），有一次成功 | **可用**，照常装 | — |
| 三次都失败，TPM 返回 `0x00000921`（DA lockout） | 确认用不了 | 在 BIOS 里清除 TPM 后再试 / Clear the TPM in BIOS and try again |
| 三次都失败，TPM 返回 `0x000009a2` / `0x0000098e`（owner 层级设了口令） | 确认用不了 | 同上 |
| 三次都失败，错误码不认得；`systemd-analyze` / `systemd-creds` 跑不起来 | 判断不了 | 原因 + 请联系我们 |

只有「可用」才继续：别的都在**确认屏之前、任何写盘命令之前**拒装，屏幕上是「这台电脑没有可用的 TPM 2.0，不能安装 MastersOS /
No usable TPM 2.0, cannot install MastersOS」、原因一行、上表的改法与「磁盘没有改动 / The disk has not been touched.」。拒装之前
安装器只跑只读的命令（`lsblk`、`udevadm settle`、`systemd-analyze has-tpm2`、试封装的 `systemd-creds encrypt`）。

`build.sh` 在构建时检查 initrd 里有 `tpm-probe` 与恢复出厂确认要用的命令、`libtss2-{esys,rc,mu,tcti-device}.so.0` 与我们的单元
（查 mkosi 产出的 `initrd.cpio.zst`，并核对它就是 UKI `.initrd` 段的开头），缺了就拒绝构建。

装好之后 TPM 才坏的机器（被清、lockout）每次开机要恢复密钥，照旧。分区没有 TPM2 槽的机器（4a 按空口令装的，只有 lab 的
VM 166；或被人手工改过）agent 只回报 `luks:tpm` 失败「数据分区没有 TPM2 槽：这台不是按现在的安装器装的（没有 TPM 已不再支持），
请重装」，另三项是同一句的短版，什么都不动（不登记、不托管、不绑）。4a 按空口令装的系统在去掉开机试空口令之后开不了机，重装即可。

## 恢复出厂

恢复出厂由 IT 控制（4b Ruling 22，不依赖 BIOS 锁定）：**主路径是面板远程发起**；本机从启动菜单发起时，受管的机器要先输
**这台的恢复密钥**。两条路都在 TPM 用不了时不清数据——repart 会在删掉旧分区之后建不出新的，机器就开不了机了。
恢复出厂删掉并重建加密的根分区（`/etc`、`/var`、`/home`、本机账号都没了，新的 LUKS UUID，TPM 槽绑签名 PCR 11）；
种子分区（种子、缓存的设置包、`identity.json`、`reset-done`）保留，所以回来之后分组与设置按学校的回来、面板上还是同一台。

### 远程（面板）

机器列表上每台一个「远程恢复出厂」按钮，要照着键入这台的序列号才能确认；它调
`PUT /v1/admin/devices/{device_id}/reset`（请求体 `true`，`draft` 范围），在草稿里这台的 `[[device]]` 写
`reset = { id = "<UUIDv4>", requested_at = "<服务端此刻>" }`——与挂失锁定一样**只改草稿、发布才生效，签名覆盖它**。
发布页的 lint 以 `device_reset_requested` 警告列出每台要恢复出厂的机器；`reset.id` 不是 1–64 个字母、数字或 `-` 时是
`device_reset_id_invalid` 错误（带换行的 id 永远对不上 `reset-done` 里的行，会每次开机都恢复出厂）。发布前可以撤销
（请求体 `null`）。`mastersos` 命令行与 `mastersos mcp` 没有这个操作，整份写草稿与还原旧版本时也拒绝增加、改动或删除任何 `[[device]].reset`
（与 `trust` 一样的第二道防线，只在 MCP 进程里）：AI 经 MCP 不能增加、改动或删除 `reset`。这**不是**说 AI 排不了恢复出厂——
它照样能起草一个 `when = "apply"`（以 root 运行）的分组脚本，里面自己调 `systemd-factory-reset request`。真正的关口仍是
人看过再发布（发布要 publish 范围，MCP 拿不到；发布页列出 lint 与差异），所以发布时要细看脚本与 `[[device]]` 的改动。

agent 在接受新包之后、以及常驻启动时载入本地的包之后检查（`apply-local` 不检查：GDM 之前不做破坏性的事），按序：

1. `id` 不在种子分区的 `reset-done` 里，且 `requested_at` 晚于这块数据分区开始的时刻（`state.seed_import.at`，回报里的
   `imported_from_seed_at`；没有记录时只看 `reset-done`）。两道防重复：`reset-done` 挡住恢复出厂之后再执行（种子分区保留），
   `requested_at` 挡住重装之后再执行（重装重写种子分区）。重装时本机时钟比服务端慢，最多多执行一次，之后 `reset-done` 挡住；
   反过来本机时钟**快**（导入时刻记在将来）时，在真实时间追上之前发起的远程恢复出厂都回报「早于这次安装，不执行」——
   不清数据，面板上看得见；IT 等时钟走过那个时刻之后在面板上重新发起即可（每次重新发起都是新的 id 与新的 `requested_at`）。
2. 种子分区挂着、写得进（写不进就记不下这个 id、挡不住下一次，不执行）。
3. `tpm::probe` 是「能用」（判断不了也不执行）。
4. 立即回报 `reset`「正在恢复出厂（请求 <id>）」，最多等 10 秒，回报不出去也继续。
5. 把 id 追加进 `reset-done`（0600；临时文件 + `renameat` + fsync 文件与目录）。
6. `/usr/lib/systemd/systemd-factory-reset request`（设 `FactoryResetRequest` EFI 变量）→ `systemctl reboot`。initrd 的确认
   单元只看内核命令行，EFI 变量发起的恢复出厂**不问任何东西**，repart 直接重建。

第 1–3、5 步不成立时回报 `reset` 失败并写明哪一条，不重启。标记写在请求之前：请求设成了而重启失败时，下次重启照样恢复出厂；
`request` 本身失败时这个 id 已记为执行过、不再重试，要在面板上重新发起（新 id）。第 2、3 步失败（例如开机早期种子分区还没挂上、
TPM 一时判断不了）不会自己反复重试：同一个请求只在下一次接受新包、或 agent 重启（含机器重启）时再检查一次——IT 看到
「恢复出厂失败」后重启那台机器或再发布一次即可。面板上：草稿里有请求而回报还没说执行过这个
id 的显示「恢复出厂待发布」；回报里 `reset` 成功的显示「正在 / 已恢复出厂」与时间，失败的显示「恢复出厂失败」与原因。
旧的 agent（4a）不认 `reset` 字段会拒收整个包——只有 lab 的 4a 机器受影响，没有出过货的。

### 本机（启动菜单）

主 UKI 的 profile 1（`uki-profiles/factory-reset.conf`），菜单里是「MastersOS <版本> (Ubuntu 26.04) (ERASE ALL DATA - factory reset,
asks to confirm)」，命令行追加 `systemd.factory_reset=1`。正式镜像开机按空格出菜单。这个 profile 同样签了 PCR 11。

initrd 里的 `mastersos-factory-reset-confirm.service`（条件：命令行带 `systemd.factory_reset`；排在 `tpm2.target`、
`systemd-tpm2-setup-early.service` 与 `initrd-usr-fs.target` 之后、repart 之前；输出也上控制台）按序：

时间：问恢复密钥每次 300 秒、最多 3 次，`ERASE` 60 秒，最长约 16 分钟；每个提示超时都按「不清数据」处理。根设备的等待
（`dev-disk-by\x2ddesignator-root.device` 的 330 秒，加上加密根分区设备自己的等待）排在这个单元**之后**才开始计时
（`After=mastersos-factory-reset-confirm.service`，Task 5 复审 I1）：慢慢输入恢复密钥不会被它在中途打断、重启。

1. `tpm-probe` 不是 0（用不了，或判断不了）→ 打印「TPM 用不了，恢复出厂后会装不上，这次不清数据 / The TPM is unusable;
   factory reset would fail, keeping the data」，不清数据。
2. 受不受管：根分区（`/dev/disk/by-designator/root-luks-ignore-factory-reset`——恢复出厂模式下 udev 只建这个名字、
   不建 `root-luks`，VM 165 实测——其次 `root-luks`；都不在时用 `LoaderDevicePartUUID` 找到的 ESP）所在的磁盘上找 GPT
   标签 `mastersos-seed` 的分区，只读挂到 `/run/mastersos/seed-check`（`ro,nosuid,nodev,noexec`）看有没有 `seed.toml`，卸载。
   有 → 受管；分区在但挂不上、或找不到这块磁盘 → 按受管处理；没有这个分区或没有 `seed.toml` → 未受管。别的盘、U 盘上同名
   的分区不算。
3. 受管且根分区是 LUKS：LUKS 头里有 `systemd-recovery` token → 问恢复密钥（`systemd-ask-password`，300 秒、`--echo=masked`、
   最多 3 次）。输入去掉空白与 `-`、转小写，是 64 个 modhex 字母就每 8 个插回 `-`，经标准输入交给
   `cryptsetup open --test-passphrase --disable-external-tokens --key-file=- <root-luks>` 对着 LUKS 头核对——不加
   `--disable-external-tokens` 时任何口令都会经 TPM token「通过」（4a 实测）。密钥不进日志、不进任何命令行。三次都不对、或
   300 秒没人输 → 不清数据。**没有恢复 token**（托管还没成功过）→ 打印「这台机器还没有托管恢复密钥：请用面板远程恢复出厂
   或用 U 盘重装 / No escrowed recovery key yet: use remote reset or reinstall from USB」，不清数据。两个链接都没有时在
   启动盘上按 GPT 类型（x86-64 root）找根分区。确定盘上没有根分区、或 `cryptsetup isLuks` 说它不是 LUKS（退出 1）→ 没有
   可保护的数据，直接第 4 步；判断不了（找不到盘、列不出分区、有分区读不到类型、`isLuks` 退出 0/1 之外的值）→ 不清数据。
   未受管的机器跳过这一步。
4. 打 `ERASE`（不分大小写，60 秒）。

任何一步不对都跑 systemd 自己的 `systemd-factory-reset complete --retrigger`（写 `/run/systemd/factory-reset-complete`、
清 `FactoryResetRequest` EFI 变量、重新触发块设备），repart 看到「恢复出厂已完成」就不删任何分区，**照常开机进系统，数据不动**。
离不开恢复出厂模式时确认单元失败：`systemd-repart.service` 对它是 `Requires=`，repart 不跑、什么都不删，这次开机找不到根分区、
initrd 重启。

为什么还要 `ERASE`：systemd-boot 里**所有** UKI 条目的快捷键都是 `l`，`j`/`k` 上下移，`d` 设默认，回车启动——标题写什么都改变
不了这一点（systemd-boot 把 profile 的 TITLE 接在系统名后面，条目开头总是「MastersOS」）。输恢复密钥的人（modhex 字母，含 j、k、
l、d，最后一下是回车）在提示超时重启时还在打字，就可能在菜单里选中恢复出厂；Task 3 的 lab 里真的发生过。先问恢复密钥再问
`ERASE`：继续打进来的恢复密钥拼不出 `ERASE`（a、s 不是 modhex 字母）。万一 `d` 把恢复出厂设成了默认项：每次开机问一次、
照常开机，在菜单里对正常项按 `d` 改回来。

边界（Ruling 18，物理攻击不在防护范围）：知道恢复密钥的人本来就能解开数据；拆盘、改种子分区让机器「看起来未受管」的人
本来就能擦盘。这里挡的是坐在机器前、没有恢复密钥的学生。

## 照抄的 systemd 原文（systemd 259.5-0ubuntu3.4）

initrd 里**两处** drop-in 照抄了 systemd 生成 / 打包的命令行，只对上面这个版本核对过；`systemd-version.verified` 记着它，
镜像里的 systemd 包版本不同时 `mkosi.finalize` 拒绝构建。升级 systemd 时：重新生成下面这两段、与我们的 drop-in 比对，
跑矩阵第 1、3、5 行，再改 `systemd-version.verified`。

gpt-auto 生成器为根分区写的单元（`root=dissect`；在 VM 167 上 `SYSTEMD_IN_INITRD=1 systemd-gpt-auto-generator` 生成）的 ExecStart：

```
ExecStart=/usr/bin/systemd-cryptsetup attach 'root' '/dev/disk/by-designator/root-luks' '' 'tpm2-device=auto,tpm2-measure-pcr=yes,tpm2-measure-keyslot-nvpcr=cryptsetup'
```

我们的（`systemd-cryptsetup@root.service.d/50-mastersos.conf`）在第四段末尾加 `,timeout=300`，其余逐字相同。

`systemd-repart.service` 打包的 ExecStart（`systemctl cat systemd-repart.service`，也见构建出的 initrd）：

```
ExecStart=systemd-repart --dry-run=no
```

我们的（`systemd-repart.service.d/50-mastersos-bootstrap-key.conf`，4b Task 4）先 `ExecStart=` 清空，再写
`ExecStart=systemd-repart --dry-run=no --key-file=/run/mastersos/luks-bootstrap-key`，其余逐字相同——首次开机 /
恢复出厂时给新建的数据分区加一个临时钥匙槽（`Encrypt=key-file+tpm2`）。

## sysupdate 的 gpg 钥匙轮换

已装好的机器只认镜像里带的 `import-pubring.pgp`。换钥匙分三步，每步之间等全体机器都更新过：

1. 新旧两把公钥都进 `keys/import-pubring.pgp`，仍用旧钥匙签，发一版镜像；
2. 全体机器都装上之后，改用新钥匙签 `SHA256SUMS`；
3. 再发一版，`import-pubring.pgp` 去掉旧钥匙。

详见 `docs/update-channels.md`。
