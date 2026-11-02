# /usr 自动修复的 VM 验收清单（Task 10）

**状态：2026-10-27 在家里 PVE 上跑完。** 清单是设计 `docs/superpowers/specs/2026-10-27-mastersos-usr-self-repair-design.md`
§5 的 1–11，加上前面任务留下的携带项 a–e。

- 构建：VM 164（`mastersos-build-b`）`--profile lab`，发布到 lab stable。N = `20261027.5`（装机与大部分条目），
  N+1 = `20261027.6`（第 7 条的升级、第 4 条、第 8b 条修复后重测、第 10 条）。两次构建的闸门都打印
  `/usr/bin/zstd, curl and gpgv are in the image`。
- 试验机：VM 165（48 GiB，从 N 的带种子 U 盘装，装好后快照 `t10-base`，每条之后回滚到它）；VM 170（没有黄金分区，
  快照 `pre-t3` = `20261026.1`）。盘只在 VM 关着时在 PVE 上直接写（`dd`/`mtools`），串口记录在
  `/var/lib/vz/mastersos-lab/serial-<vmid>.log`。
- 证据：`image/lab/results/2026-10-27-usr-repair/t10-*.txt`（命令输出原样）。
- 跑出一个产品缺陷（第 8b 条），修在 `a8db754`（integrity 读通活动槽后同时删掉该根哈希的 `repair-usr`），N+1 带着它，重测通过。
- lab 的云端是 10-17 的旧服务端：agent 拿不到设置包（响应缺 `X-Mastersos-Version`），GDM 自动登录被 pam_exec 拒，
  因此**没有图形会话**、没有恢复密钥托管、agent 的上报看不到。凡依赖这三者的部分都记「未测」。

## §5 清单

| 编号 | 结果 | 实测事实 | 证据 |
|---|---|---|---|
| 1 新装机 | PASS | 带种子装机 1 分钟；sda8/9/10 与 A 槽 sig/verity/usr 的 sha256 相同（usr 1 814 175 744 字节），PARTUUID 都不同；`/usr` 是 sda4 上的 dm-verity，黄金分区没挂、没被占用；黄金 ESP 里的 UKI 与 ESP 上的同一个 sha256；第一次 integrity 做 refresh-golden（写 usr 3.5 s、读核 11.5 s） | `t10-1-install.txt` |
| 2 活动 /usr 中间坏一块 | PASS（提示一步未测） | 关机改 sda4 第 221300 块 → integrity `active_ok=false`、request-repair；日志「no active graphical session, not notifying」（没有图形会话，通知没法看）→ 重启 initrd 修（读黄金 2.2 s、写 usr 4.5 s、verity+sig 1.8 s、读核 1.5 s，单元共 10.8 s）→ 该块回到原内容、再核对 `active_ok=true` | `t10-2-active-corrupt.txt` |
| 3 开机必读的块坏了 | PASS ×3 | 签名分区前 4 KiB：第一次开机 /usr 能挂，但等根设备 5 min 31 s 超时，343.8 s 重启；第二次「active slot does not verify: repairing」修好。哈希树第 1 块：「metadata block 1 is corrupted」，103.7 s 重启后修好。erofs 第 0 块：「data block 0 is corrupted」，103.4 s 重启后修好。到 boot-complete 共 435 / 182 / 199 s | `t10-3-sig.txt`、`t10-3-tree.txt`、`t10-3-erofs.txt` |
| 4 删最新 UKI | PASS | 在 .6 上删 .6 的 UKI → 起在 .5 → integrity restore-uki，补回的 UKI sha256 与原来的相同（28fc9ac7…）；黄金副本仍是 .6、没降级 → 下次开机回到 .6 | `t10-4-uki-restore.txt` |
| 5 活动槽与黄金副本同时坏 | PASS | 两边签名 blob 同一字节（DER 第 1207 字节）同样改坏 → initrd 见两边一样不动手、系统照常起（坏 blob 不影响开机）；integrity `active_ok=0 golden_ok=0` → network → golden-fetch 下 1 663 966 649 字节 9.0 s、全程 46 s → integrity 重跑并 request-repair → 重启 initrd 修好（8.4 s）→ `active_ok=true` | `t10-5-golden-fetch.txt` |
| 6 黄金副本坏了 | PASS | 6a 只改黄金签名 + boot-pending：initrd「differs… but the golden signature does not verify (rc 1): not writing」，0 扇区写入，integrity 用活动槽 refresh-golden。6b 改黄金 usr 一块 + repair-usr：initrd「golden copy does not verify: nothing written」；integrity 平时只 `--no-read`，报 `golden_ok=1`，直到 `golden_full_checked_at` 调回 8 天前才整读发现并 refresh-golden（见关注点 2） | `t10-6-golden-bad.txt` |
| 7 升级后黄金跟上、复制中断电 | PASS | .5 → .6（mastersos-update）；.6 第一次开机 integrity 写到「usr copied」/「verity copied」时 `qm stop`；离线看 golden-sig 是空的；再开机重新 refresh，黄金副本成 .6（rootHash b7a2904d…） | `t10-7-update-cut.txt` |
| 8 修复中断电与写不进去 | PASS（修了一个缺陷；上报一步未测） | 8a：出现修复字样 2 s 后断电 → 下次「interrupted (1 of 3): repairing again」修好。8b（N 上 FAIL）：`lab-fail-verify` + 对好槽的请求 → 每次开机都重写 1.8 GB 且总是「attempt 1 of 2」——integrity 删 repair-count 却留着 repair-usr，循环；`a8db754` 修后在 .6 重测：第一次失败后 integrity 删掉两者，第二次开机不再修。8c（每次尝试后断电并离线重新改坏）：计数 1、2 → 第三次「giving up … (limit 2); booting as is」0 扇区写入，integrity `gave_up=<哈希>`、只报告；第四次同样不写。agent 把 gave_up 上报到云端看不到（旧服务端） | `t10-8a-interrupted.txt`、`t10-8b-lab-fail-loop-bug.txt`、`t10-8b-fixed.txt`、`t10-8c-give-up.txt` |
| 9 正常开机不变慢 | PASS | 正常开机 initrd 3.33–3.48 s（usr-repair 单元 0.43–0.94 s，不核对）；boot-complete 之后强关：同样 3.33–3.48 s；boot-complete 之前强关：5.04–5.36 s（单元 2.37–2.73 s，「the active slot verifies」）。对照 VM 170：`20261026.1`（没有本功能）3.84 / 5.28 / 3.86 s，`20261027.6` 无黄金 3.59–3.62 s | `t10-9-initrd-time.txt`、`t10-10-no-golden.txt` |
| 10 没有黄金分区的机器 | PASS | VM 170 从 `20261026.1` 升到 .6：initrd「no golden copy on the boot disk, nothing to do」，ESP 没有 `EFI/MastersOS`，repart「No changes」且成功，没有失败的单元，integrity `has_golden=false`、report-only。从 N 的 U 盘（snapshot=on）起：「no usrhash= on the command line, nothing to do」，U 盘 ESP 上没有 boot-pending | `t10-10-no-golden.txt` |
| 11 恢复出厂 | PASS（托管路径未测） | 托管机器拒绝（「No escrowed recovery key yet」，旧服务端收不了托管）；测试时把 seed.toml 挪开当非托管 → 输入 ERASE → 重置，根的 LUKS UUID 82105a13 → 6fa8c825，sda8–11 的 sha256 前后相同；之后回滚 `t10-base` | `t10-11-factory-reset.txt` |

## 携带项

| 编号 | 结果 | 实测事实 | 证据 |
|---|---|---|---|
| a 修复时控制台文字 | PASS | 串口上有「Repairing system files, do not power off…」 | `t10-2-active-corrupt.txt`、`t10-8a-interrupted.txt` |
| b 真 initrd 里的签名黄金核对 | PASS | 槽的签名 DER 第 1207 字节改坏、rootHash 不动、离线放 boot-pending → initrd「signature partition differs from the golden copy's, whose signature verifies: repairing」→ 槽签名与黄金相同 | `t10-carry-b-signed-golden.txt` |
| c SB 开着时改签名字节 | PASS（记录） | 原签名 rc 0；DER 第 3 字节 rc 5「Bad message」；第 40 字节 rc 0（被接受）；第 613/1207/1225 字节 rc 5「Invalid argument」；`verity_check` 坏 blob 1、原 blob 0。改坏的 blob 从不给 rc 1，所以 ENOKEY 降级分支没被触发 | `t10-carry-c-sb-sig-flip.txt` |
| d 镜像里有 zstd、curl、gpgv | PASS | .5 与 .6 的构建日志都有闸门行「/usr/bin/zstd, curl and gpgv are in the image (golden-fetch)」；VM 165、VM 170（都在 .6）上三者都在：zstd 1.5.7、curl 8.18.0、gpgv 2.4.8；第 5 条的 golden-fetch 实际用它们下完并验签 | `t10-build-gate.txt` |
| e Dell 3420 实机 `read_through` 耗时 | 未测 | 本次只在 PVE 上跑 | — |

强关后与正常开机的 initrd 时间对比（brief Step 3）记在第 9 条，不另列携带项。

## 证据缺口（评审指出，不改结果文件，只在这里注明）

- 第 5 条的布置（两边签名 DER 第 1207 字节同样改坏）是离线在 PVE 上写盘做的，不在 `t10-5-golden-fetch.txt` 里，串口记录里也没有；同一种改法见 `t10-carry-b-signed-golden.txt`。
- 第 3 条的 5 min 31 s 与 103.7 / 103.4 s 是跑的时候从控制台读的，结果文件里没有。
- 第 1 条的 refresh-golden 3.5 s / 11.5 s、第 11 条引的「No escrowed recovery key yet」原话不在结果文件里（`t10-11-factory-reset.txt` 前半只有第一次尝试的前后对比：LUKS UUID 没变，没有拒绝的原话）。
- `t10-11-factory-reset.txt` 第 33 行的「identical before and after」属于第一次尝试，那次重置没有发生，不算数；以文件后半（第二次尝试）的 LUKS UUID 变化与 sda8–11 前后相同为准。
- `t10-9-initrd-time.txt` 的第一轮（13:14–13:24，initrd 一列是空的）作废，以后面带 initrd 时间的几轮为准。

## 收尾状态

VM 165 在 .6、黄金副本 .6、`active_ok`/`golden_ok` true、SB 开、`EFI/MastersOS` 空，快照只剩 `t10-base`（`pre-t6` 为给薄池腾地方
提前删了）；VM 170 在 .6、SB 开、boot-complete，快照 `pre-t3` 保留。lab stable 有 .5、.6。薄池收尾 87.90%。见 `t10-final-state.txt`。

## 关注点

1. 没有图形会话、旧服务端：通知（第 2 条）、agent 上报 gave_up（第 8 条）、托管机器的恢复出厂（第 11 条）未测，要换新的 lab 服务端再跑。
2. initrd 发现黄金副本坏了（6b）不传给用户态，integrity 平时只 `--no-read`，最长 7 天后才整读发现。
3. `integrity.json` 的 `repaired` 不记 initrd 完成的修复；golden-fetch 之后 `golden_full_checked_at` 没更新。
4. 开机必读的块坏了时，第一次开机要 1.7–5.7 分钟才 emergency 重启（现有超时）。
5. 签名 DER 第 40 字节改了仍被内核接受（carry c），属签名格式本身，不影响本功能的判定。
