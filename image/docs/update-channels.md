# 更新通道、发布与回滚

MastersOS 的系统更新是 systemd-sysupdate 从一个**纯静态目录**下载整套 `/usr` 与 UKI，装进另一个槽，
下次开机生效；新版本开机三次都过不了健康检查就自动退回上一版。本文是这套机制的操作手册与实测记录
（计划 4a Task 2，PVE 试验网，2026-10-12）。

## 通道目录

```
<MASTERSOS_UPDATE_BASE>/
├── stable/
│   ├── SHA256SUMS            # 本通道所有文件的 sha256
│   ├── SHA256SUMS.gpg        # 对 SHA256SUMS 的分离签名（ed25519，「MastersOS updates」）
│   ├── MastersOS_<v>_x86-64.usr-x86-64.<uuid>.raw.zst             # /usr（erofs）
│   ├── MastersOS_<v>_x86-64.usr-x86-64-verity.<uuid>.raw.zst      # dm-verity 哈希树
│   ├── MastersOS_<v>_x86-64.usr-x86-64-verity-sig.<uuid>.raw.zst  # roothash 的签名
│   └── MastersOS_<v>_x86-64.efi                                    # UKI
├── beta/                     # 同样的布局（每个版本另有 MastersOS_<v>_x86-64.build-info.txt，列在签过的 SHA256SUMS 里）
├── mastersos-root.conf          # 这棵根的声明：base=<对外地址>、lab=yes|no
├── installer/                # 安装 U 盘的镜像（Task 11）
└── chrome/                   # 考试扩展（计划 9 Task 8）：mastersos-kiosk-ext.crx、updates.xml，加签过的 SHA256SUMS
```

从 2026-11-01 起镜像自带扩展（`/usr/lib/mastersos/kiosk-ext/`，`update_url` 是 `file://`），这种构建 `publish.sh <版本> chrome` 什么都不做；下面说的只对之前的旧镜像还有效。

`chrome/` 不分通道：镜像里的 `/usr/lib/mastersos/kiosk-ext.json` 写着 `<base>/chrome/updates.xml`，每台机器的锁定会话里 Chrome
按它强制安装、更新考试扩展。`publish.sh <版本> chrome` 把这个构建打包的两个文件放进来（这个版本要已在这棵根的 beta 或 stable 里、UKI 字节相同；核对 build-info 记的 sha256、id 与版本；
根里已有的 id 不同——换了扩展钥匙——就拒绝；版本旧就拒绝；同一版本字节不同就拒绝，相同只重签），再签 `chrome/SHA256SUMS`。
试验网的根 `base` 是 http，Chrome 只从 https 装强制安装的扩展：lab 根在 `mastersos-root.conf` 里另写 `chrome_base=https://…/chrome`
（`<根>/chrome/` 对外的 https 地址，lab 构建用同一个 `MASTERSOS_KIOSK_EXT_BASE` 打包），`lab=no` 的根不许写它（固定 `<base>/chrome`）。

**每棵根先声明自己**（`publish.sh`/`promote.sh` 没有它就拒绝）：

```
base=https://os.khundavid.com              # 就是正式镜像构建时的 MASTERSOS_UPDATE_BASE（正式默认值，Ruling 23）
lab=no                                     # 只有试验网的根写 yes
```

发布与 promote 都核对构建的 `build-info.txt`：`update_base` 必须等于这里的 `base`（否则装上它的机器会去
别处找更新）；`lab=no` 的根拒绝 `profile=lab` 与 `broken=` 非空的构建——lab 构建带 sshd、自动登录的试验
用户和试验网的 http 源，发到正式通道就等于给全体机器开后门、并把它们永远困在试验网的源上。
VM 161 的试验网根 `/var/www/html/mastersos/mastersos-root.conf` 是 `base=http://192.0.2.99/mastersos`、`lab=yes`。

### 根与钥匙（4b Task 1，Ruling 19）

每棵根只对一套钥匙（`keyset.sh`；钥匙本身见 `docs/keys.md`「lab 的钥匙」）：

| 根 | 收的构建 | 签 `SHA256SUMS` | 验签（换上之前） | `check_uki` 的 PCR 公钥 |
|---|---|---|---|---|
| `lab=no` | 只收 `profile=release`、`broken=` 为空 | `~/mastersos-keys/gpg` | `keys/import-pubring.pgp` | `keys/tpm2-pcr-public-key.pem` |
| `lab=yes` | 只收 `profile=lab`（含 `--broken`） | `~/mastersos-keys/lab/gpg` | `keys/lab/import-pubring.pgp` | `keys/lab/tpm2-pcr-public-key.pem` |

`lab=yes` 的根拒绝正式构建是 4b 新加的：正式镜像只信正式的 gpg 公钥，lab 根用 lab 的钥匙签，正式镜像发进来也验不过、
装不上。lab 构建的 `.pcrpkey` 若是正式的那把（用错了钥匙）同样拒绝，反之亦然。4b 之前 lab 根上由正式 gpg 签的版本
已全部删掉（2026-10-14；试验机随即从 lab U 盘重装）。

正式更新源是 `https://os.khundavid.com`（S3，Ruling 23）：`build.sh` 正式 profile 的 `MASTERSOS_UPDATE_BASE` 默认就是它。
S3 的桶与 CDN 见 `infra/`（计划 5 Task 1），同步见下一节；校内缓存不在计划 5。

### 正式更新源：本地根镜像到 S3（计划 5 Task 3，裁定 4、5）

**本地根是唯一的真相，S3 是它的镜像。** 正式根在 VM 161 的 `/srv/mastersos/release`（`MASTERSOS_PUBLISH_ROOT`），
`mastersos-root.conf` 除 `base=https://os.khundavid.com`、`lab=no` 之外多两个键：

```
mirror_s3=s3://<桶>
mirror_cdn=<CloudFront DistributionId>
```

只许 `lab=no` 的根带，两个要么都有要么都没有，同一个键写两次照旧拒绝（`read_root_conf`）。`publish.sh` / `promote.sh` 不碰网络。
一次正式发布 = `publish.sh <版本> <通道>` → `sync-s3.sh`（promote 同理：`promote.sh <版本>` → `sync-s3.sh`）。
`sync-s3.sh --dry-run` 先看要传什么、要删什么（只调 `head-object` 与 `list-objects-v2`）。AWS 凭据取
`MASTERSOS_AWS_PROFILE`（默认 `mastersos-publish`，只能写这一个桶、给这一个分发做失效）。

`sync-s3.sh` 按这个顺序做，**CDN 上任何时刻都不会有指向不存在文件的清单**：

1. 本地自检：`stable`、`beta`、`installer`、`chrome` 里存在的每个目录，`SHA256SUMS` 用这棵根的公钥验得过、列着的文件都在且 sha256
   对得上；不过就退出，桶一个字节都不动。传的只有 `SHA256SUMS` 所列文件 + `SHA256SUMS` + `SHA256SUMS.gpg`
   （`mastersos-root.conf`、`.lock`、临时目录一概不传）。
2. 带版本号的文件：先把每个对象都 `head-object` 一遍。不存在才传（`Cache-Control: public, max-age=31536000, immutable`，
   metadata 记 `sha256`）；已有且 sha256 相同就跳过；已有而不同（或没有记录）**拒绝，此时还没传过任何东西**——边缘节点上一年的
   缓存会留着旧字节，换版本号重建。
   `chrome/` 的两个文件名字固定、每发一版都换字节，不走这一步：先 `mastersos-kiosk-ext.crx`、后 `updates.xml`，`max-age=300`，每次都传
   （`chrome/SHA256SUMS` 只许列这两个）。新 `updates.xml` 传上去到 `/chrome/*` 失效完成之间，边缘节点可能把新清单与缓存的旧 crx 一起给出：
   Chrome 发现版本或哈希不符就拒装、过几个小时再查，是暂时的。
3. 清单：每个目录先 `SHA256SUMS`、后 `SHA256SUMS.gpg`（`max-age=60`）。
4. 失效 `/stable/SHA256SUMS*` 等（`chrome/` 是整个 `/chrome/*`）并等它完成；失败就退出，**不删任何东西**。
5. 删除桶里 `stable/`、`beta/`、`installer/`、`chrome/` 下不在第 1 步集合里的对象（`publish.sh` 只留 3 个版本，旧版本在这里才真正从 CDN 源站消失）。
   本地没有的目录，桶里对应的前缀不碰；别的前缀（以及根上的对象）从不列、不碰。

**出错怎么办：重跑。** 每一步都可以重来：中断在第 2 步，桶里的清单还是上一次的（旧清单指向的文件都还在）；中断在第 3 步，
最坏是 `SHA256SUMS` 已换、`.gpg` 还是旧的，机器验签失败、下一轮再来，重跑即补上；失效或删除失败，多出来的旧文件留着无害，
重跑再删。「同名对象字节不同」不是重跑能解决的：说明本地换了字节而版本号没换，换版本号重新 publish。
桶开了版本化，非当前版本保留 30 天：误删、误覆盖用 `aws s3api list-object-versions --bucket <桶> --prefix <键>` 找回版本号，
再 `aws s3api copy-object`（或 `get-object --version-id`）放回去；超过 30 天的就只能从本地根重传。
- 失效完成后、删除之前再等 60 秒（`MASTERSOS_SYNC_SETTLE`，清单的 `max-age`；测试设 0）。
- 大文件传到一半被打断时，`s3 cp` 报的 multipart abort `AccessDenied` 无害：未完成的分片由桶的生命周期规则清理，重跑即可。
- 已删除的带版本号的名字**不要**用不同的字节重建（边缘节点上的一年缓存会留着旧的）；`publish.sh` 已拒绝比通道最新版本旧的版本。
- `wait invalidation-completed` 约 10 分钟放弃：此时什么都没删，重跑即可完成。
测试：`tests/sync-s3-test.sh`（`tests/fake-aws` 顶替 aws，不碰 AWS）。

- 每个通道只留**最近 3 个版本**（`publish.sh` / `promote.sh` 收尾时删旧的）。
- 镜像里的 `/usr/lib/sysupdate.d/*.transfer`（四个：三个分区 + UKI）指向 `<base>/stable/`；
  `/usr/lib/mastersos/sysupdate.d.in/` 是同一份模板，源是 `<base>/@CHANNEL@/`。清单选 `beta` 时 agent
  （Task 6）把模板渲染成 `beta`、写到 `/etc/sysupdate.d/` 同名文件覆盖；选回 `stable` 时删掉覆盖。
  覆盖机制在 VM 166 上手工验过：写入 `/etc/sysupdate.d/` 后 `mastersos-update` 从 `beta/` 下载并验签成功。
- `<base>` 是构建时的 `MASTERSOS_UPDATE_BASE`，由 `mkosi.finalize` 换进 transfer 的 `@BASE@`。
  **正式镜像只收 `https://<域名>/…`**（`build.sh` 与 `mkosi.finalize` 都拒绝 http、IP、localhost）；
  试验网（lab profile）默认是构建机 VM 161 的 nginx `http://192.0.2.99/mastersos`。仓库里进正式镜像
  的树不写死任何 URL（`tests/check-tree.sh` 第 4、10 条）。正式更新源是 `https://os.khundavid.com`
  （S3，Ruling 23；`build.sh` 正式 profile 的默认值）。脚本只产出目录树；往 S3 的同步见上面「正式更新源」（`sync-s3.sh`）；校内缓存见下面「校内缓存」一节。
- sysupdate 用 `/usr/lib/systemd/import-pubring.pgp`（仓库 `keys/import-pubring.pgp`，二进制 keyring；
  文件名写成 `.gpg` 会 `DOWNLOAD INVALID`）验 `SHA256SUMS.gpg`，再按 `SHA256SUMS` 验每个文件。
  分区内容另有 dm-verity 签名（Secure Boot 那把钥匙），UKI 另有 Secure Boot 签名。

## Publishing from CI (2026-11-05)

Release images are built by GitHub Actions, so the release root no longer lives on a build host: each job rebuilds the
part of it that it changes from the S3 mirror (`image/ci-publish.sh`), checks it, and runs the same `publish.sh` /
`promote.sh` / `sync-s3.sh` as above. The bucket stays a mirror of a root that only ever held signed content.

- **`mastersos-image`** (build): after the GitHub Release, `ci-publish.sh beta <v>` restores `beta/`, runs
  `publish.sh <v> beta` and `sync-s3.sh`. Input `beta` (default on) turns this off for a build that should not reach
  any machine.
- **`mastersos-promote`** (by hand, `version` = a version in beta): restores `beta/`, `stable/` and `installer/`, runs
  `promote.sh <v>` (inputs `allow_bootloader_change` / `allow_shim_change` pass the two gates), then takes the installer
  image and Ventoy package from the version's GitHub Release (`image-release-<v>`; its `build-info.txt` must be byte for
  byte the one beta signed) into `publish.sh <v> installer`, then one `sync-s3.sh`, then marks the GitHub Release as the
  latest non-prerelease one. Nothing is rebuilt: stable gets the bytes beta had.
- **Signed release assets**: the GitHub Release's `SHA256SUMS` is signed in the build job with the update source's gpg key
  (`ci-publish.sh sign-release`, `SHA256SUMS.gpg` among the assets); promote verifies it, every asset against it and that
  nothing unlisted is there before `publish.sh <v> installer` re-signs anything. Editing a Release cannot get other bytes
  into `installer/`. Releases made before 2026-11-05 have no signature and cannot be promoted: rebuild. Promote also
  refuses an empty `stable/` (no baseline for the shim and systemd-boot gates means a damaged bucket, not a first run).
- **Restore check**: `publish.sh` and `promote.sh` re-sign whatever a channel holds, so a restored directory must be
  exactly what its last manifest vouches for: `SHA256SUMS.gpg` verifies with the repository key, every listed file
  matches, nothing unlisted is there. Otherwise the job stops before any key is used (`tests/ci-publish-test.sh`).
- Both jobs run in the `release` environment (owner approval, master only) and share the `mastersos-image` concurrency
  group, so only one job at a time touches the update source. AWS access is the OIDC role of the cloud infra stack
  `mastersos-os-ci-publisher`: the origin's publisher policy (this bucket, this distribution's invalidations), assumable
  only by this repository's `release` environment. The bucket, distribution id and role ARN are secrets of that environment
  (`MASTERSOS_OS_BUCKET`, `MASTERSOS_OS_CDN`, `MASTERSOS_OS_PUBLISH_ROLE`); `sync-s3.sh` uses the environment's
  credentials when `MASTERSOS_AWS_PROFILE` is set to the empty string.
- **Build a commit that does not itself change `.github/workflows/`**: GitHub refuses `GITHUB_TOKEN` creating a tag (the
  GitHub Release) on such a commit (`HTTP 403: Resource not accessible by integration`, run 42053544318). After a workflow
  change, build the next commit on master instead.
- The usual flow: build (lands in beta) → machines on beta update and report healthy → `mastersos-promote` with that
  version. The version rules above still hold: never publish to beta a version that will not be promoted while a later
  stable version would be lower.

## School cache (plan 5 Task 12)

A school can run an HTTP cache of the update source. Any HTTP service that proxies or mirrors
`os.khundavid.com` works, as long as it keeps the same layout (`<root>/stable/`, `<root>/beta/`); for example
nginx with `proxy_cache`:

```nginx
proxy_cache_path /var/cache/mastersos-os levels=1:2 keys_zone=mastersos:10m max_size=20g inactive=30d;
server {
    listen 80;
    location /mastersos/ {
        proxy_pass https://os.khundavid.com/;
        proxy_cache mastersos;
        proxy_cache_valid 200 1h;
        proxy_ssl_server_name on;
    }
}
```

Set `update_mirror = "http://cache.school.ac.th/mastersos"` in the `[school]` table of the bundle manifest
(`http://` or `https://`, directory only; no query string, fragment or credentials, which the pre-publish lint
rejects). What happens on a machine:

- The agent (`system/update_channel.rs`) writes same-named transfers to `/etc/sysupdate.d/` (via safefs). They
  differ from the originals only in the root of the `[Source]` `Path=` line, so `Verify=yes` and every other
  setting are unchanged. Without `update_mirror` (and with channel `stable`) the overrides are removed.
- **The cache is not trusted.** `SHA256SUMS` is verified against `SHA256SUMS.gpg`, every file against its
  sha256, `/usr` by dm-verity and the UKI by Secure Boot. If a cached file is altered the machine refuses to
  install it (and falls back, see below); putting the file back makes updates work again.
- Fallback: with a cache set, the agent also writes the originals (channel filled in, official root) to
  `/var/lib/mastersos-system/sysupdate-fallback.d/`. `mastersos-update.service` runs `/usr/lib/mastersos/update-run`,
  which updates via the cache first; if that fails (unreachable, 404, timeout, failed verification) it retries
  once from the official source with `systemd-sysupdate --definitions=<fallback dir>`, and records the outcome
  in `/var/lib/mastersos-system/update-mirror-failed`. The agent reports it as a failed `update:mirror` item (shown
  in the admin panel). The next round tries the cache first again; the round in which it works deletes the record.
- The cache attempt is bounded: `timeout --kill-after=60 45m`; exit 124 counts as a cache failure and triggers
  the fallback. If the fallback also fails, the record says so neutrally ("both the school cache and the official
  source failed: ...") so IT does not chase only the cache.
- **A cache cannot alter or downgrade content, but it can delay updates** (for example by serving an old
  `SHA256SUMS` forever). After a successful cache round `update-run` asks the official source
  (`--definitions=<fallback dir> check-new`). The answer has three states: newer (exit 0 plus the version on
  stdout), none (exit 0 or 1, nothing on stdout or stderr) and unknown (a message on stderr, a timeout or any other
  exit code). The
  first time the official source is ahead, the time is stored in
  `/var/lib/mastersos-system/update-mirror-stale-since`; if it is still ahead 12 hours later (`grace` in
  `update-run`, one constant), the machine updates from the official source and records
  `school cache stale: official has <v>, cache offers <w>`, reported as a failed `update:mirror`. When the
  cache catches up (a definitive "none") the stale-since file and the stale record are deleted; until then the
  record is kept across rounds. An unknown answer touches neither (a flaky or blocked official source cannot reset
  the clock); it is tracked in `update-mirror-unknown-since`, and after 24 hours of unknown with a working cache
  the record `school cache: freshness unknown for over 24h (official source unreachable)` is written. Any
  definitive answer clears it. A timestamp file that is unparsable or in the future (clock set back) is rewritten
  with the current time.
- `http://` is allowed (school caches are often plain HTTP by IP); the pre-publish lint only warns
  (`update_mirror_not_https`).
- **Rollout order:** a machine whose agent predates this change rejects a bundle containing `update_mirror`
  (the `[school]` table uses `deny_unknown_fields`, so the whole bundle fails to parse). Check that the fleet
  agent versions include this change before publishing a bundle that sets it.

Test: `tests/update-run-test.sh` (fallback and staleness logic with a fake `systemd-sysupdate`) and the unit tests in
`update_channel.rs`. Lab procedure: nginx with `proxy_cache` on the build machine in front of the lab root, one lab
VM configured with it; check `/var/log/nginx` shows its requests; corrupt a cached file, expect the machine to
refuse it and report `update:mirror`; restore it; stop the cache, expect the update to succeed from the
original root and the panel to show `update:mirror`.

## 版本号

`IMAGE_VERSION` 形如 `20261012.1`：构建日期 + 当天序号（`build.sh` 只收这个形式）。sysupdate 与
systemd-boot 都按 systemd 的版本比较排序（`20261012.10` > `20261012.9`）。

- **同一版本号不能发两次**：已经装了这个版本的机器不会再下载它，改过的字节到不了它们。
  `publish.sh` 遇到通道里已有的版本直接拒绝；重建就换序号。
- agent 判断当前版本只看 `/etc/os-release` 的 `IMAGE_VERSION`：回滚之后 `systemd-sysupdate list`
  会把坏掉的新版本标成 `current`（S2 的发现，本次又见到一次）。

## 机器上：定时下载，下次开机生效

- `mastersos-update.service` 带 `Requisite=boot-complete.target` + `After=`：这次启动没过健康检查（没被标好）
  就不跑——否则 sysupdate 会先删掉另一个槽，也就是可退回的好版本。用 Requisite 而不是 Requires：Requires
  会在定时器触发时重新拉起已失败的 `mastersos-health.service`。`boot-complete.target` 由
  `multi-user.target.wants/` 的链接保证每次开机都被拉起。VM 166 上验过：boot-complete active 时照常跑；
  停掉它再触发（手动或定时器）→ `Job mastersos-update.service/start failed with result 'dependency'`，
  sysupdate 不运行，定时器本身保持 active、`mastersos-health` 不被重跑。
- `mastersos-update.timer`：开机 15 分钟后一次，之后约每 6 小时一次（`RandomizedDelaySec=1h`，免得全校
  同一刻下载），`Persistent=true`。触发 `mastersos-update.service` → `systemd-sysupdate update`，**不重启**。
- **断点续传（2026-11-05）**：sysupdate 自己下载时直接写进另一个槽，被打断（合盖、断电、断网）就从 0 重来，而且开始前已经删掉
  旧的另一个槽。所以 `update-run` 的每次更新都先走 `staged_update`：`check-new` 问出新版本 → 下载 `SHA256SUMS{,.gpg}`、用镜像的
  `import-pubring.pgp` 验签 → 按签过的清单逐个 `curl --continue-at -` 下载这个版本的 UKI 与三个分区文件到
  `/var/lib/mastersos-system/update-staging/<源地址的哈希>/`（`.part` 跨轮、跨重启保留，sha256 对上才改名）→ 都齐了，用同一组
  transfer 的副本（`[Source] Path=file://<暂存目录>/`，放在 `/run/mastersos-update/definitions/`）跑 `sysupdate --definitions=… update`：
  签名与每个文件的哈希由 systemd-pull 照 https 时一样再验一遍，写槽只用几分钟。装好就删暂存目录；装失败留着下一轮直接用。
  续出来的文件哈希不对就丢掉重下；签名不对什么都不下；新版本出来时旧版本的暂存文件删掉。transfer 不是同一个 url-file 源、
  `/var` 剩余空间不足 3 GiB（已暂存的算在内）、或 `check-new` 答不清楚时，照旧直接跑 sysupdate。
  测试：`tests/update-run-staged-test.sh`（file:// 通道 + 一次性 gpg 钥匙 + 假 sysupdate）；v259 的 `url-file` 源接受 `file://`
  （`sysupdate-transfer.c`），真机上的第一次实测见下面的实测记录。
- 上游的 `systemd-sysupdate.timer` 与 `systemd-sysupdate-reboot.timer`（后者装好后自动重启）在镜像里
  删掉了（`mkosi.conf` 的 `RemoveFiles=`，`mkosi.finalize` 删掉包留下的启用链接）。
- 本镜像新加的单元都由 `/usr/lib/systemd/system/*.wants|*.requires` 里的链接启用，不靠 preset：preset
  只在首次开机套用一次，已装好的机器更新到新镜像后靠 preset 起不来（`tests/check-tree.sh` 第 12 条）。
- sysupdate 把新 UKI 装成 `MastersOS_<v>_x86-64+3-0.efi`（三次机会），`InstancesMax=2`：ESP 上只有
  正在用的版本和新版本。装好后的第一个 UKI 不带计数（没有可退回的版本）。

## 发布（在构建机 VM 161 上）

```bash
image/lab/sync.sh                                   # Mac → VM 161
ssh -J lab-host mastersos@192.0.2.99
cd ~/mastersos-image
./build.sh 20261012.5 [--profile lab]                      # 正式镜像默认更新源 https://os.khundavid.com
./publish.sh 20261012.5 beta                               # 先发 beta
./publish.sh 20261012.5 chrome                             # 考试扩展变了（或第一次发）就紧跟着发，再 sync-s3（见下）
# …… beta 机器验过 ……
./promote.sh 20261012.5                                    # beta 里同一批字节进 stable
```

**第一次正式发布的顺序**（计划 9 终审 minor 4）：`publish.sh <v> chrome` 只收已经在 beta 或 stable 里的构建，所以第一次正式发布时
`chrome/` 一定晚于 `beta/` 出现。beta 机器下载新镜像、重启之后，锁定会话的 Chrome 就按 `kiosk-ext.json` 去
`https://os.khundavid.com/chrome/updates.xml` 要考试扩展——那时 `chrome/` 还不在，网页 / PWA 的锁定会话**没有「退出」按钮**
（只剩 Alt+F4 ×6 或电源键）。所以：`publish.sh <v> beta` 之后**同一次操作里**接着 `publish.sh <v> chrome` 与 `sync-s3.sh`，
在 beta 机器下一次重启之前让 `/chrome/updates.xml` 能取到（机器约 6 小时查一次更新、下次开机才生效，时间是够的，只是别隔天）；
发完 `curl -s https://os.khundavid.com/chrome/updates.xml` 核对 `appid` 是 `docs/keys.md` 里正式的扩展 id。之后扩展没变的版本不用再发
`chrome`；变了（`manifest.json` 的 `version` 调高了）也照这个顺序。

`publish.sh <version> <stable|beta>`：

0. **构建与根对得上**（见上面的 `mastersos-root.conf`）；版本比通道里最新的旧也拒绝（机器不降级，发了也装不上）。
1. **发布闸门**（在动任何文件之前）：从 UKI 的 PE 段表里读出所有 `.pcrpkey`，必须与这棵根的 PCR 公钥
   （上表）逐字节相同；每个 profile（没有 `.profile` 段时是整个 UKI，有的话是每个
   `.profile` 之后的一组段——ukify 把每个 profile 的 `.pcrsig` 放在它自己那组里，VM 161 上用
   `ukify build --join-profile` 实测过）都要有 `.pcrsig`，且其中每条签名的 `pkfp`（PKCS#1 公钥 DER 的
   sha256）都是这把钥匙、都覆盖 PCR 11。任何一条不符就 exit 1，通道目录一个字节都不动。
   为什么要拦：数据分区的 TPM 槽只认这把 PCR 钥匙签的策略，签错钥匙的 UKI 发出去，全体机器开机都会
   停在恢复密钥提示，启动计数救不回来（计数只管「启动失败」，不管「卡在提示」）。
2. 分区文件 `zstd` 压缩、UKI 原样，先写进通道目录里的临时目录，再逐个改名进去（分区先、UKI 最后）；
3. 只留最近 3 个版本，重写 `SHA256SUMS`，用这棵根的 gpg 钥匙（上表）分离签名；新签名先用仓库里对应的
   `import-pubring.pgp` 验过才换上去（防止签名钥匙与镜像信任的不是同一把），然后才删旧版本的文件。
   签名、验签或换上失败：退出非零，原来的 `SHA256SUMS{,.gpg}` 与旧版本都不动，刚放进去的文件撤掉，重跑不会被
   当成「已经发过」；旧版本只在新清单签好、换上之后才删（`tests/publish-test.sh` 用一个必然失败的 gpg 验过）。

`promote.sh <version>`：比 stable 最新的版本旧、beta 里没有这个版本、它的 build-info（已按签过的
`beta/SHA256SUMS` 核对）与根对不上，都失败；先用 `import-pubring.pgp` 验 `beta/SHA256SUMS.gpg`、
按它核对这几个文件，UKI 再过一次闸门，然后把**同一批字节**复制进 stable（不重建、不重新压缩），
stable 只留最近 3 个版本，重写并重签 `stable/SHA256SUMS`。stable 里已有同样字节的这个版本时只重签；
字节不同则拒绝。

`MASTERSOS_PUBRING` / `MASTERSOS_PUBRING_LAB`（换掉正式根 / lab 根验签用的公钥）只给测试：要同时 `MASTERSOS_TEST=1` 才生效并在 stderr 警告，单独设就拒绝运行。
`mastersos-root.conf` 里同一个键写两次也拒绝。

两个脚本共用 `channel-common.sh`，在 `<根>/.lock` 上 `flock`，同一时刻只有一个在动通道目录。
`SHA256SUMS.gpg` 与 `SHA256SUMS` 是两次 `rename`，中间有极短的窗口：这时来下载的机器验签失败，
下一轮（约 6 小时后）再来，不会装上任何东西。

### 实测（VM 161，2026-10-12）

- 闸门：`20261012.99` 用另一把临时生成的 RSA 钥匙作 PCR 钥匙构建（`MASTERSOS_KEYS` 指向只换了
  `pcr.key/crt` 的目录），`publish.sh 20261012.99 beta` → `check_uki: … .pcrpkey 不符`，exit 1，
  `beta/` 的目录列表与 `SHA256SUMS{,.gpg}` 的 sha256 前后相同。另外用改过段的 UKI 验了
  「`.pcrsig` 的 pkfp 不是这把钥匙」「没有 `.pcrsig`」「多 profile 的 UKI 最后一个 profile 没有
  `.pcrsig`」三种情况都 exit 1，真正的三 profile UKI（ukify 构建）通过。
- `publish.sh 20261012.5 beta && promote.sh 20261012.5`：beta 与 stable 里该版本四个文件的 sha256 相同；
  `gpgv --keyring keys/import-pubring.pgp stable/SHA256SUMS.gpg stable/SHA256SUMS` → Good signature；
  stable 只剩 `20261012.3 20261012.4 20261012.5`（`20261012.2` 被删）。VM 166 随后从 stable 更新到
  `20261012.5`、开机、`Marked boot as 'good'`。
- 同一版本再 `publish.sh` → 拒绝；`promote.sh` 一个 beta 没有的版本 → 拒绝；再 promote 同一版本 → 只重签。

## 回滚：健康检查与启动计数

- `mastersos-health.service`（`RequiredBy=boot-complete.target`，**不设** `FailureAction=`）跑
  `/usr/lib/mastersos/health-check`，**只看镜像本身**：`display-manager.service` active（最多等 2 分钟）、
  `veritysetup status usr` 是 `verified`、`/usr/bin/mastersos-agent --version` 退出 0（没有 agent 的镜像跳过）。
  **不看** `mastersos-agent-local`、agent 的应用结果与网络——设置包或网络的问题不是镜像的问题，坏的设置包
  绝不能让全体机器回滚镜像。
- 检查都过：`boot-complete.target` 到达，`systemd-bless-boot` 把 UKI 文件名里的计数去掉（标「好」）。
- 检查失败，且本次启动的 UKI 带计数（EFI 变量 `LoaderBootCountPath` 不空）、ESP 的 `EFI/Linux/` 上还有
  另一个计数没用完的 MastersOS UKI：脚本自己 `systemctl --no-block reboot`、exit 1。systemd-boot 每次启动前先减计数，三次后
  `+0-3` 的版本排到最后，启动旧版本。
- 检查失败，但没有计数（安装后的第一个版本）或 ESP 上没有别的可启动版本：只往 journal 记一行
  `health failed, no counter` / `health failed, no fallback`，exit 0——留在这个版本，**绝不进重启循环**。
- 读不懂 `LoaderBootCountPath`、找不到 ESP（`bootctl --print-esp-path` 带 20 秒超时）：记
  `health failed, unknown: <原因>`，exit 1 **但不重启**——不标好（坏版本不会被永久留下），也不让可能只有
  一个版本的机器循环；下次有人重启时计数照常往下走。单元超时（5 分钟）或脚本意外退出也是同样的结果：
  重启只在确认有回退版本时由脚本发出，所以单元上不放 `FailureAction=reboot`。
- ⚠ 本次启动的名字带 `+0`（例如 `+0-3`）**不等于**「没有回退」：systemd-boot 先减计数再启动，第三次
  尝试时文件名已经是 `+0-3`。第一版的健康检查（照计划的写法）把 `+0-*` 当成「计数用完、exit 0」，
  VM 166 实测结果是第三次失败时坏版本被 `systemd-bless-boot` 标成了「好」、永远留下。现在只看
  「ESP 上有没有别的可启动版本」（`tests/health-check-test.sh` 覆盖这几种情况）。
- **initrd 里的失败**：上游 initrd 的 `emergency.service` 会停在「Press Enter for system maintenance」，
  机器永远不重启、计数也就永远用不完（实测见下）；`rd.emergency=reboot` 是 dracut 的参数，systemd 不认。
  所以 `mkosi.initrd.conf/`（mkosi v27.1 给默认 initrd 的附加配置目录）往 initrd 里放了
  `emergency.service.d/50-mastersos-reboot.conf`：不跑 sulogin，打印一行说明、10 秒后重启
  （`SuccessAction=reboot`、`FailureAction=reboot`）。这样也去掉了 initrd 里的维护 shell。内核命令行
  另加 `systemd.crash_reboot=1`（PID 1 崩溃时重启而不是挂住）。
- **故意做坏的版本只发到 lab 根的 `beta` 或一棵一次性的 lab 根，永远不发 lab 的 `stable`**：lab 的 stable 是所有试验 VM 的
  默认通道，坏版本排在最新，任何一台跑 `mastersos-update` 的 VM 都会装上它、白白重启三次再退回，后面的更新试验就会被误读
  （Task 4 复审 M-4：`20261013.10` 曾这样留在 stable，之后发了好的 `20261013.12` 盖过去）。做回滚试验的 VM 用
  `/etc/sysupdate.d/` 的 beta 覆盖（同 agent 选 beta 时写的那一份）去拉 beta。
- 坏版本只在 lab 做：`build.sh <v> --profile lab --broken userspace`（`/usr/lib/mastersos/health-broken`
  让健康检查一直失败）或 `--broken initrd`（`mkosi.finalize` 往 `$ARTIFACTDIR/io.mkosi.initrd/` 追加一段
  cpio：一个 `RequiredBy=initrd.target`、必然失败的单元）。正式 profile 拒绝 `--broken`。

### 实测（VM 166，lab 镜像，Secure Boot + 我们的证书追加进 db）

| 场景 | 结果 |
|---|---|
| v1 → v2 走 stable | `20261012.1` 上 `systemctl start mastersos-update` → 从 `stable/` 下载、`Signature verification succeeded`，装成 `MastersOS_20261012.2_x86-64+3-0.efi`；`qm reboot` 后 `IMAGE_VERSION="20261012.2"`、`Marked boot as 'good'. (Boot attempt counter is at 1.)`、ESP 上是 `MastersOS_20261012.2_x86-64.efi` |
| 用户态坏版本 `20261012.3` | 串口三次 `Failed to start mastersos-health.service` + `Rebooting: unit mastersos-health.service failed`，journal 三次 `health failed: … 重启后由启动计数退回（fallback MastersOS_20261012.2_x86-64.efi）`，第四次开机回到 `20261012.2`，ESP 上 `MastersOS_20261012.3_x86-64+0-3.efi`（`tries: 0 left; 3 done`） |
| initrd 坏版本 `20261012.4`，**没有**上面的 drop-in | 停在 `You are in emergency mode … Press Enter for system maintenance`，5 分钟没有重启 |
| initrd 坏版本 `20261012.4`，有 drop-in | 每次 `mastersos-broken-initrd.service` 失败 → `MastersOS: 启动失败（initrd），10 秒后重启…` → `reboot: Restarting system`（启动后约 15 秒），三次后回到 `20261012.2`，ESP 上 `MastersOS_20261012.4_x86-64+0-3.efi` |
| 唯一的版本是坏的（Step 4b） | ESP 上只留 `MastersOS_20261012.3_x86-64+1.efi`（用户态坏版本），重启一次：`health failed, no fallback（MastersOS 20261012.3 是唯一可用的版本，留在这个版本、不重启）`，`Marked boot as 'good'`，之后不再重启（3 分钟后 GDM active、`is-system-running` 为 `degraded`——是 Task 1 记下的 `systemd-pcrlock-make-policy`，不是 `starting`） |

原始输出在 `lab/results/4a-t2-*.txt`。上表是第一轮（单元带 `FailureAction=reboot`）的结果；改成由脚本发重启
之后，用户态坏版本与 Step 4b 又在 VM 166 上各跑了一次，见 `lab/results/4a-t2-fix1.txt`。

已知的边界：

- 新镜像在 **switch-root 之后**进 emergency（例如 local-fs 失败）：主系统的 emergency 没改，root 锁着，
  机器停在那里，计数要等有人断电重启才往下走（只有 initrd 里的 emergency 改成了自动重启）。
- （2026-11-05 起下载先进 `/var` 的暂存目录，下面这个「删了旧槽再下载」的窗口只剩从本地写槽的几分钟。）
- 一次更新被打断（断电、断网）会不会留下「指向已被覆盖分区的回退 UKI」：VM 166 的日志里 sysupdate 先
  `Removing old` 另一个槽的三个分区**和**它的 UKI（如 `MastersOS_20261012.3_x86-64+0-3.efi`），再下载、写分区，
  最后才放新 UKI。所以打断后 ESP 上只剩正在运行的版本，不会有坏的回退项；下次更新从头再来。

## beta 切回 stable 不降级（Ruling 5）

机器从 beta 切回 stable 时 agent 只删掉 `/etc/sysupdate.d/` 的覆盖，**不降级**：sysupdate 只装比当前更新
的版本，机器停在 beta 的版本，直到 stable 出现更高的版本号（通常就是 promote 上来的同一版本或更新的）。
所以 beta 上发出去的版本号必须是「将来 stable 也能接受的」——不要在 beta 上发一个永远不会 promote、
版本号又比之后 stable 版本都高的构建。

## 每次 1.46 GB：第一期不做增量（Ruling 6）

（断点续传见上面「机器上」一节：打断后不再从头下载，但仍是整包。）

每次更新整包下载：`/usr` zstd 压缩后约 1.5 GB（`20261012.5` 实测 1 535 620 371 字节，spec 估 1.46 GB），加 UKI 约 80 MB。以后两条路：

1. **学校服务端做缓存**：transfer 的 `Path=` 指向校内地址。通道覆盖机制（`/etc/sysupdate.d/`）已经能
   承载——agent 写的覆盖文件可以换成校内源，校内源用同一套 `SHA256SUMS.gpg` 验签（缓存改不了内容）。
2. sysupdate 的增量格式成熟后改用。

## sysupdate 的 gpg 钥匙轮换

钥匙：正式钥匙的 `gpg/`（ed25519，`MastersOS updates 2026`，指纹
`060FD1FF6736E942A82F68A58B32893A3FCC1851`，无口令；平时在 S3 的 age 文件里，签名会话才经 `keys-load.sh --age` 解密进 VM 161 的 tmpfs，
见 `docs/key-ceremony.md`）；公钥 `keys/import-pubring.pgp`。2026-10-27 之前是 VM 161 磁盘上的预发布钥匙
`0D42FCDFE52820258E413671AEAC82F2BD8F8C7A`（已退役，公钥 `keys/retired/import-pubring-pre-ceremony.pgp`）。
已装好的机器只认镜像里带的公钥，所以换钥匙要分三步，每一步之间要等全体机器都更新过：

1. 生成新钥匙，把**新旧两把**的公钥都导出进 `keys/import-pubring.pgp`（`gpg --export <旧> <新>`），
   仍用**旧钥匙**签 `SHA256SUMS`，发一版镜像；
2. 等全体机器都装上这一版之后，改用**新钥匙**签 `SHA256SUMS`（`publish.sh`/`promote.sh` 用的
   `~/mastersos-keys/gpg` 换成新的）；
3. 再发一版镜像，`import-pubring.pgp` 里去掉旧钥匙。

跳过第 1 步直接换签名钥匙，所有机器都会 `DOWNLOAD INVALID`、再也收不到更新（只能重装）。
`docs/keys.md` 记有同一条。
