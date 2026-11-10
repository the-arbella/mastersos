# 考试静默 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 锁定会话（kiosk）进行中，设备不下载大文件、不改系统、不执行远程指令；会话结束 60 秒后恢复。

**Architecture:** agent 新模块 `quiet.rs` 判定静默（logind 里有 kiosk uid 的会话）并维护标记单元 `mastersos-quiet.target`，
结果经 `watch::Receiver<Option<DateTime<Utc>>>`（静默开始时刻，`None` = 不静默）分给后台任务循环、应用 worker、收件箱与回报。
PAM 钩子在 kiosk 会话打开时立即进入静默；镜像里的下载类 systemd 单元用 `ExecCondition=` 在静默时不启动。

**Tech Stack:** Rust（tokio、serde_json、chrono），systemd 单元，bash 测试。

**Spec:** `docs/specs/2026-11-10-exam-quiet-design.md`

## Global Constraints

- 代码注释、错误、输出用英文；提交信息用中文。路径一律英文。
- `KIOSK_UIDS` = `1900..=1989`（`system/ephemeral.rs:902`）；访客 uid 1999 **不**触发静默。
- 对账间隔 `POLL` = 5 s；退出延迟 `EXIT_DELAY` = 60 s。
- 标记单元名 `mastersos-quiet.target`；静默时停掉的单元 `STOP_UNITS` = `mastersos-update.service`、`mastersos-chrome.service`、
  `mastersos-golden-fetch.service`、`mastersos-flatpak.service`。**不用 `Conflicts=`**。
- 静默期间照常：`StatusJob`、`ChromeStatus`、状态回报、心跳、推送、上传（Get help）。
- PAM 钩子里静默失败只写 stderr，**绝不**拒绝登录。
- 验证：`cd core && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`；
  `bash image/tests/check-tree.sh`；shell 测试在 `ubuntu:24.04` amd64 容器里跑。提交前 `python3 -I tools/check-private.py`。

## Review Focus

1. loginctl 输出没有 `state` 字段（systemd 259）或 `closing` 状态的 kiosk 会话：`closing` 不算在场，缺 `state` 算在场（往静默方向落）。
2. agent 重启时 `mastersos-quiet.target` 已 active、但没有 kiosk 会话：60 秒后退出，不永久卡住。
3. 应用一轮跑到一半进入静默：这一轮停在步骤之间，退出静默后**自动重跑**，不丢请求。
4. 静默期间到达的新设置包：收下并校验（`take_new` 照常），只是不应用；退出时应用的是最新的一份。
5. 退出静默后收件箱立即同步（不等下一次门铃或退避）。

---

### Task 1: `quiet` 模块的判定逻辑

**Files:**
- Create: `core/mastersos-agent/src/quiet.rs`, `core/mastersos-agent/src/quiet/tests.rs`
- Modify: `core/mastersos-agent/src/lib.rs`（`pub mod quiet;`）

**Interfaces:**
- Produces:
  - `pub const TARGET: &str = "mastersos-quiet.target";`
  - `pub const STOP_UNITS: &[&str]`（见 Global Constraints，顺序如列）
  - `pub const POLL: Duration`（5 s），`pub const EXIT_DELAY: Duration`（60 s）
  - `pub fn kiosk_session_present(loginctl_json: &str) -> Result<bool>`
  - `pub enum Action { Enter, Exit, Nothing }`
  - `pub struct Tracker { since: Option<DateTime<Utc>>, last_seen: Option<Instant> }`，
    `impl Tracker { pub fn new(target_active: bool, now: Instant, wall: DateTime<Utc>) -> Self; pub fn step(&mut self, present: bool, target_active: bool, now: Instant, wall: DateTime<Utc>) -> Action; pub fn since(&self) -> Option<DateTime<Utc>> }`
  - `pub fn enter(runner: &dyn Runner) -> Result<()>`：`systemctl start --no-block mastersos-quiet.target`，然后
    `systemctl stop --no-block <STOP_UNITS…>`（一条命令）。
  - `pub fn exit(runner: &dyn Runner) -> Result<()>`：`systemctl stop --no-block mastersos-quiet.target`。
  - `pub fn target_active(runner: &dyn Runner) -> bool`：`systemctl is-active --quiet mastersos-quiet.target` 退出码 0。

- [ ] **Step 1: 写失败的测试**（`quiet/tests.rs`）
  - `present_for_kiosk_uid`：`[{"session":"3","uid":1900,"user":"kiosk-a","seat":"seat0","class":"user","state":"active"}]` → `true`
  - `guest_and_normal_users_do_not_count`：uid 1999 与 1000 → `false`
  - `closing_does_not_count`：uid 1950、`"state":"closing"` → `false`
  - `missing_state_counts`：uid 1989、没有 `state` 栏 → `true`
  - `bad_json_is_error`：`"not json"` → `Err`
  - `enter_when_present`：`Tracker::new(false,…)`，`step(true, false, t0, w0)` → `Enter`，`since() == Some(w0)`
  - `stays_quiet_until_delay`：`step(false, true, t0+59s, …)` → `Nothing`，`since()` 仍是 `Some(w0)`；`step(false, true, t0+60s, …)` → `Exit`，`since() == None`
  - `reenter_target_if_someone_stopped_it`：在场且 `target_active == false` → `Enter`（`since` 不变）
  - `stale_target_after_restart_exits`：`Tracker::new(true, t0, w0)` 后一直 `present == false`：`t0+60s` → `Exit`
  - `enter_issues_start_then_stop`：`FakeRunner` 的 `calls()` 依次是
    `systemctl start --no-block mastersos-quiet.target` 与
    `systemctl stop --no-block mastersos-update.service mastersos-chrome.service mastersos-golden-fetch.service mastersos-flatpak.service`

- [ ] **Step 2: 运行确认失败**：`cd core && cargo test -p mastersos-agent quiet::` → 编译失败（模块不存在）。

- [ ] **Step 3: 实现** 上面的接口。`kiosk_session_present` 解析 `loginctl --json=short list-sessions` 的数组：`uid` 是数字且在
  `KIOSK_UIDS` 内，`state` 缺失或不是 `"closing"` 即在场。`Tracker`：在场时 `last_seen = now`；`since` 为空就设为 `wall`；
  在场或 `now - last_seen < EXIT_DELAY` 时目标是静默；目标静默但 `target_active == false` → `Enter`；目标不静默但 `since` 非空或
  `target_active` → `Exit` 并清 `since`。`new(true, …)` 把 `last_seen` 设为 `now`、`since` 设为 `wall`。

- [ ] **Step 4: 运行确认通过**：`cargo test -p mastersos-agent quiet::` 全过。

- [ ] **Step 5: 提交** `feat(agent): 考试静默的判定逻辑（quiet 模块）`

### Task 2: 对账循环、`JobCtx` 接线与回报字段

**Files:**
- Modify: `core/mastersos-agent/src/quiet.rs`、`quiet/tests.rs`
- Modify: `core/mastersos-agent/src/jobs.rs:48`（`JobCtx`）、`run.rs:198-240`（`run_resident`）、`run.rs:1350-1380`（`status_report`）、
  `apply_worker.rs:555`（测试里的 `JobCtx`）
- Modify: `core/mastersos-bundle/src/status.rs:18-60`（`StatusReport`）、`core/mastersos-agent/src/report.rs:137-170`

**Interfaces:**
- Consumes: Task 1 全部。
- Produces:
  - `pub type QuietRx = watch::Receiver<Option<DateTime<Utc>>>;`
  - `pub async fn monitor(runner: Arc<dyn Runner>, tx: watch::Sender<Option<DateTime<Utc>>>, shutdown: CancellationToken)`：
    每 `POLL` 跑一次 `loginctl --json=short list-sessions`（超时 5 s）与 `target_active`，喂给 `Tracker::step`，
    `Enter` → `enter()`，`Exit` → `exit()`，然后 `tx.send_if_modified` 发布 `since()`。loginctl 失败：这一轮当作在场
    （宁可多静默），记 `log::warn!`。
  - `pub async fn wait_until_loud(rx: &mut QuietRx)`：当前不静默立即返回，否则等到值变成 `None`。
  - `JobCtx` 新字段 `pub quiet: QuietRx`；`Agent` 新字段 `quiet: QuietRx`。
  - `StatusReport` 末尾新字段 `#[serde(default)] pub quiet_since: Option<String>`（RFC 3339）。

- [ ] **Step 1: 写失败的测试**
  - `quiet/tests.rs` `monitor_publishes_since`：`#[tokio::test(start_paused = true)]`，`FakeRunner` 让 `loginctl` 先回一个 kiosk 会话、
    之后回 `[]`；推进时钟：第一轮后 `rx.borrow().is_some()`；再推进 65 s 后 `is_none()`，`calls()` 里出现 `systemctl stop --no-block mastersos-quiet.target`。
  - `quiet/tests.rs` `wait_until_loud_returns_after_exit`：先发 `Some(t)`，`spawn` 等待者，发 `None` 后它在 1 s 内完成。
  - `mastersos-bundle/src/status.rs` `quiet_since_is_optional_both_ways`：照 `os_pending_version_is_optional_both_ways` 的写法。

- [ ] **Step 2: 运行确认失败**：`cargo test --workspace quiet` → 编译失败。

- [ ] **Step 3: 实现** `monitor`、`wait_until_loud`，加字段；`run_resident` 里建 `watch::channel(None)`，`tokio::spawn(quiet::monitor(Arc::new(RealRunner), tx, shutdown.clone()))`，
  把接收端放进 `JobCtx` 与 `Agent`；`report::build` 把 `quiet_since` 设为 `None`，`Agent::status_report` 在 `os_pending_version` 那行之后填
  `self.quiet.borrow().map(|t| t.to_rfc3339())`。`Mode::Local`（`apply-local`）不起 monitor，接收端恒为 `None`。

- [ ] **Step 4: 运行确认通过**：`cargo test --workspace` 全过。

- [ ] **Step 5: 提交** `feat(agent): 静默对账循环，回报 quiet_since`

### Task 3: 后台任务在静默时不开始；Flatpak 长命令进临时单元

**Files:**
- Modify: `core/mastersos-agent/src/jobs.rs:64-160`、`status.rs:636`（`StatusJob`）、`chrome_sysext.rs:1234`（`ChromeStatus`）
- Modify: `core/mastersos-agent/src/system/flatpak.rs`（`340`、`368`、`398` 的 install，`~448` 的 update，`reconcile` 的取消闭包）
- Test: `jobs.rs` 内联 `mod tests`、`system/flatpak/tests.rs`

**Interfaces:**
- Consumes: `JobCtx::quiet`、`quiet::wait_until_loud`（Task 2）。
- Produces:
  - `Job` 新默认方法 `fn runs_in_quiet(&self) -> bool { false }`；`StatusJob`、`ChromeStatus` 返回 `true`。
  - `pub const FLATPAK_UNIT: &str = "mastersos-flatpak";`（`system/flatpak.rs`）
  - `fn flatpak_cmd(args: &[&str], timeout: Duration) -> Cmd`：`systemd-run --wait --collect --quiet --unit=mastersos-flatpak --property=RuntimeMaxSec=<timeout 秒> flatpak <args…>`，`Cmd` 的超时为 `timeout + 30 s`。

- [ ] **Step 1: 写失败的测试**
  - `jobs.rs` `quiet_holds_job_until_loud`：`start_paused`，`Counting` 任务，`JobCtx.quiet` 初值 `Some(t)`；推进 10 s 计数为 0；发 `None` 后计数为 1。
  - `jobs.rs` `runs_in_quiet_job_keeps_running`：同上但任务 `runs_in_quiet() == true`，静默中计数照常增加。
  - `system/flatpak/tests.rs` `install_runs_in_transient_unit`：`calls()` 里安装命令以
    `systemd-run --wait --collect --quiet --unit=mastersos-flatpak --property=RuntimeMaxSec=900 flatpak install --system --noninteractive -y flathub ` 开头。
  - `system/flatpak/tests.rs` `update_runs_in_transient_unit`：`… --property=RuntimeMaxSec=3600 flatpak update --system --noninteractive -y`。
  - `system/flatpak/tests.rs` `reconcile_stops_between_apps_when_quiet`：清单两个应用，第一个装完后静默为真 → 第二个不装，结果里它是未完成（不是失败）。
  - 现有 Flatpak 测试里的命令前缀随之更新。

- [ ] **Step 2: 运行确认失败**：`cargo test -p mastersos-agent jobs:: flatpak` → 新测试失败。

- [ ] **Step 3: 实现**：`spawn_all` 循环里 `job.run` 之前，`!job.runs_in_quiet()` 时 `select!` 等 `wait_until_loud` 或 `shutdown`；
  不中途丢弃正在跑的 future。Flatpak 的三处 install 与一处 update 改用 `flatpak_cmd`；`reconcile` 的取消闭包加上 `cx.quiet.borrow().is_some()`。

- [ ] **Step 4: 运行确认通过**：`cargo test --workspace`。

- [ ] **Step 5: 提交** `feat(agent): 静默时后台任务不开始，Flatpak 长命令进可停的临时单元`

### Task 4: 应用 worker 在静默时只收不用

**Files:**
- Modify: `core/mastersos-agent/src/apply_worker.rs:160-235`（`Worker::run`）、`apply_worker.rs` 里 `ApplyHandle` 的构造（加 `quiet: QuietRx` 参数）、`run.rs` 构造处
- Modify: `core/mastersos-agent/src/system/mod.rs:361`（`Applier::apply` 的 `stop` 闭包）、`apply.rs`（`ApplyContext` 加 `quiet: &AtomicBool` 或同义字段）
- Test: `apply_worker.rs` 内联 `mod tests`

**Interfaces:**
- Consumes: `QuietRx`、`wait_until_loud`。
- Produces: `ApplyHandle::spawn(...)` 多一个 `quiet: QuietRx` 参数（其余签名不变）。

- [ ] **Step 1: 写失败的测试**
  - `held_while_quiet_then_applied`：静默中 `request()` 一个包 → 10 s 内没有 `ApplyOutcome`；发 `None` → 收到这一个的结果。
  - `newest_request_wins_after_quiet`：静默中先后请求版本 5、6 → 退出后只应用 6。
  - `quiet_mid_round_stops_and_reruns`：`multi_thread`，applier 的第 2 步里把静默置为真 → 第 3 步不跑；退出静默后这个请求从第 1 步重跑并给出结果。

- [ ] **Step 2: 运行确认失败**：`cargo test -p mastersos-agent apply_worker::` → 新测试失败。

- [ ] **Step 3: 实现**：`Worker::run` 在 `apply_once` 之前 `wait_until_loud`（同时 `select!` `rx.changed()`，以便静默中只保留最新请求）；
  每轮建一个 `quiet_flag: Arc<AtomicBool>`，由一个小任务在静默开始时置真，`stop` 闭包看 `superseded || quiet_flag`；
  `apply_once` 返回 `None` 且原因是静默时 `rerun = Some(Duration::ZERO)`（回到循环顶部等静默结束再重跑同一请求）。`place()` 与 `run_apply` 在静默时同样不开始。

- [ ] **Step 4: 运行确认通过**：`cargo test --workspace`。

- [ ] **Step 5: 提交** `feat(agent): 静默时设置包只收下不应用，退出后应用最新一份`

### Task 5: 收件箱静默时不取，退出时立即取

**Files:**
- Modify: `core/mastersos-agent/src/run.rs:1180`（`maybe_sync_inbox`）、`run.rs:455`（`enum Wake`）、`run.rs:1512-1560`（`wait`）
- Test: `run.rs` 的测试模块（照现有 `inbox` 相关测试的写法）

**Interfaces:**
- Consumes: `Agent::quiet`。
- Produces: `Wake::QuietChanged`。

- [ ] **Step 1: 写失败的测试**
  - `inbox_not_synced_while_quiet`：`sync_inbox = true`、静默 → `maybe_sync_inbox` 后假服务器没收到 `GET /v1/inbox`，`sync_inbox` 仍为 `true`。
  - `inbox_synced_on_quiet_exit`：静默结束 → `wait` 返回 `Wake::QuietChanged`，处理后同步一次收件箱，并 `job_wake.notify_waiters()`。

- [ ] **Step 2: 运行确认失败**。

- [ ] **Step 3: 实现**：`maybe_sync_inbox` 开头静默就返回（不清 `sync_inbox`）；`wait` 的 `select!` 加 `self.quiet.changed()` 分支；
  `QuietChanged` 且变为 `None` 时 `sync_inbox = true` 并唤醒任务。

- [ ] **Step 4: 运行确认通过**：`cargo test --workspace`。

- [ ] **Step 5: 提交** `feat(agent): 静默期间不取远程指令，退出后立即取`

### Task 6: PAM 钩子在 kiosk 会话打开时立即进入静默

**Files:**
- Modify: `core/mastersos-agent/src/system/guest.rs:455-546`（`pam_session_main` 的 `EphemeralOpen` 分支，`session_open` 成功之后）
- Test: `system/guest.rs` 内联 `mod tests`

**Interfaces:**
- Consumes: `quiet::enter`。

- [ ] **Step 1: 写失败的测试**
  - `kiosk_open_enters_quiet`：kiosk 账号（uid 1900）的 `EphemeralOpen` 成功后，`FakeRunner.calls()` 含 `systemctl start --no-block mastersos-quiet.target`。
  - `guest_open_does_not_enter_quiet`：uid 1999 → 不含。
  - `quiet_failure_does_not_deny`：`systemctl start` 回失败 → 动作结果仍是放行（与 `session_open` 成功时相同），stderr 有一行 `quiet:`。

- [ ] **Step 2: 运行确认失败**。

- [ ] **Step 3: 实现**：按账号 uid 判断 `KIOSK_UIDS.contains`，调用 `quiet::enter`，`Err` 只 `eprintln!("mastersos-agent pam-session: quiet: {e:#}")`。
  如分支内不便注入 `Runner`，把这段抽成 `fn after_kiosk_open(runner: &dyn Runner, uid: u32)` 供测试。

- [ ] **Step 4: 运行确认通过**：`cargo test --workspace`；`bash image/tests/pam-hooks-test.sh`（容器）。

- [ ] **Step 5: 提交** `feat(agent): 锁定会话打开时立即进入静默`

### Task 7: 镜像：标记单元与 `ExecCondition=`

**Files:**
- Create: `image/mkosi.extra/usr/lib/systemd/system/mastersos-quiet.target`
- Modify: `image/mkosi.extra/usr/lib/systemd/system/mastersos-update.service`、`mastersos-chrome.service`、`mastersos-golden-fetch.service`
- Modify: `image/tests/check-tree.sh`
- Create: `image/tests/quiet-units-test.sh`；Modify: `.github/workflows/mastersos.yml`（把新测试加进 shell 测试列表）

**Interfaces:**
- Consumes: 单元名与 `STOP_UNITS`（Task 1）。

- [ ] **Step 1: 写失败的测试**
  - `check-tree.sh` 新检查：`mastersos-quiet.target` 存在、没有 `[Install]`、没有 `Conflicts=`；三个服务各有一行
    `ExecCondition=/bin/sh -c '! systemctl is-active --quiet mastersos-quiet.target'`；`quiet.rs` 的 `STOP_UNITS` 里除 `mastersos-flatpak.service`
    外每个都在镜像里有单元文件（用 grep 从 `quiet.rs` 取列表）。
  - `quiet-units-test.sh`：用 `MASTERSOS_SYSTEMCTL` 式的桩，验证 `ExecCondition` 的命令在桩返回 active 时退出码非 0、inactive 时为 0。

- [ ] **Step 2: 运行确认失败**：`bash image/tests/check-tree.sh` → 新检查失败。

- [ ] **Step 3: 实现**：target 文件 `[Unit] Description=MastersOS: a locked app session is running (no downloads or system changes)`，
  `RefuseManualStart=no`，无依赖；三个服务的 `[Service]` 各加上面那行（注释用英文说明为什么不用 `Conflicts=`）。

- [ ] **Step 4: 运行确认通过**：`bash image/tests/check-tree.sh`；容器里 `bash image/tests/quiet-units-test.sh`；`shellcheck`。

- [ ] **Step 5: 提交** `feat(image): 考试静默的标记单元，下载类服务在静默时不启动`

### Task 8: 收尾验证

- [ ] **Step 1**：`cd core && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace` 全过。
- [ ] **Step 2**：`bash image/tests/check-tree.sh`；容器里跑 `pam-hooks-test.sh`、`quiet-units-test.sh`、`update-run-test.sh`。
- [ ] **Step 3**：`python3 -I tools/check-private.py`。
- [ ] **Step 4**：把 VM 验收（spec §5 最后一条）加进重验证清单（交给另一个 session），不在本分支跑。
