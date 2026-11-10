# 考试静默（锁定会话期间的全局静默）

**状态：** 设计，待批准。先于 `2026-11-10-deb-apps-design.md` 开发。

**裁定（David，2026-11-10）：** 锁定会话（kiosk，考试）一开始，设备进入全局静默，**不做任何动作**，直到会话结束。理由：

1. 后台更新会占满学校的网络，考试页面打不开；
2. 任何中途的变化（换系统文件、改网络、删账号）都可能打断考试。

丢失锁定、远程抹除也不例外。小的、必要的东西（新的设置包、远程指令）**可以收下，但不执行**；大的下载**尽量不做**。

## 1. 静默期间

| 类别 | 例子 | 静默时 |
|---|---|---|
| 大下载 | 系统更新（sysupdate）、Chrome（`mastersos-chrome`）、Flatpak 安装与每日更新、.deb 应用 | 不开始；正在进行的立即停掉，静默结束后从头再来（各自本来就能中断：sysupdate 下次重下，Chrome 与 .deb 应用保留旧版本） |
| 改系统 | 应用设置包（Wi-Fi、策略、账号、锁定应用增删）、sysext 合并与刷新、LUKS 任务、家目录清理、重启类指令 | 不做。设置包照常**收下并校验**，排队，静默结束后应用 |
| 安全指令 | 丢失锁定（设置包里的 `locked`）、远程抹除（收件箱的 `factory-reset`）、收集诊断 | 丢失锁定随设置包排队；收件箱**静默期间不去取、不确认**（服务器一直保留到确认或 `expires_at`），静默结束立即取并执行 |
| 照常 | 状态回报、推送连接（MQTT） | 继续；数据很小。回报加上"考试中，已静默 N 分钟" |
| 照常 | 学生在锁定会话里点的 Get help | 继续（学生主动要的） |

不可分割的几秒步骤（`renameat2` 互换、正在进行的一次合并）做完再停，不在中间切断。

## 2. 进入与退出

- **判定"在考试"以 root 视角为准**：logind 里有锁定账号（uid 在 `KIOSK_UIDS` 段内）的会话。学生和应用都无法伪造或撤销。
- **进入要快**：锁定会话打开时，`pam-session`（root）立即启动 `mastersos-quiet.target`。agent 另外每 5 秒用 `loginctl --json=short list-sessions`
  对账一次（agent 里没有 D-Bus 客户端，不订阅 logind 信号），作为后备（PAM 钩子失败、agent 重启后都能收敛）。
- **退出**：最后一个锁定会话结束后，延迟约 1 分钟才停掉 `mastersos-quiet.target`，避免下一个学生接着登录时又被打断。
  会话异常结束（崩溃、断电）由 agent 的对账发现；开机时没有锁定会话，就不静默。
- 退出后，被推迟的动作接着做：先应用排队的设置包与安全指令，再按各自的节奏下载。

## 3. 实现方式（我的决定）

- 新增 `mastersos-quiet.target`，只作标记（root 才能启停）。**不用 `Conflicts=`**：systemd 的冲突是双向的，定时器拉起一次更新
  反而会停掉静默。改为两件事：
  1. 进入静默（PAM 钩子与 agent 对账）时 `systemctl stop --no-block` 停掉 `mastersos-update.service`、`mastersos-chrome.service`、
     `mastersos-golden-fetch.service` 与 agent 的 Flatpak 临时单元 `mastersos-flatpak.service`；
  2. 这些 systemd 单元加 `ExecCondition=/bin/sh -c '! systemctl is-active --quiet mastersos-quiet.target'`，静默期间定时器触发也起不来。
- agent 的长时间 Flatpak 命令（安装、每日更新）改在临时单元 `mastersos-flatpak.service`（`systemd-run --wait --collect`）里跑，
  这样进入静默时能被停掉。
- agent 里的任务（`FlatpakJob`、`FlatpakUpdateJob`、`LuksJob`、`HomeCleanupJob`、设置应用、.deb 应用）在每一步开始前查同一个状态
  （`mastersos-quiet.target` 是否 active，或 agent 内部的同一个标志）；长任务在下载循环里也查，查到就停。
- 设置应用里的 `lock` 步骤（今天永远排第一）在静默时同样推迟。
- 收件箱：静默期间 `maybe_sync_inbox` 不取、不确认，保留待取标记；退出静默时立即取。没有单独的远程锁定或重启指令。

## 4. 已知代价

- 设备一直停在锁定会话里，就一直不更新、收不到丢失锁定。**不设自动解除**；IT 端看到停留时长，由人处理。
- 考试开始前刚好在下载的大文件会被丢掉重下。

## 5. 测试

- 单元：每个任务在静默时不开始、运行中查到静默就停；设置包与指令在静默时只排队；退出后按顺序执行。
- 容器或 VM：开一个锁定会话，确认 `mastersos-update.service` 被停掉、定时器触发不起来；关会话 1 分钟后恢复。
- VM 验收（交给重验证批次）：网页考试与 TestNav 各开一次，期间推一个设置包和丢失锁定，确认都在会话结束后才生效。

## 6. 留给实现者

- PAM 钩子和 agent 对账的具体实现，以及"延迟 1 分钟"由谁计时（建议 agent）。
- 需要 `ExecCondition=` 的单元以 §3 的三个为准；实现时按镜像里实际的定时器再过一遍。
- 回报字段名。
