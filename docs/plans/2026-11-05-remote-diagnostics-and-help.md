# 远程诊断与学生求助（系统侧）实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 删掉 U 盘诊断；机器能按 IT 指令收集诊断包并经 S3 presigned 上传；学生在登录页、桌面、Kiosk 三处能发求助单。

**Architecture:** 全在 `mastersos-agent` 里：`diag` 收集器（root，白名单 + 去密 + tar.zst）、`diag_upload`（三步上传）、inbox 新 kind、
`support` 本地 socket 服务（peercred 认人，本地队列）与发送器。三处界面只通过 `/run/mastersos/support.sock` 与 agent 说话。
接口类型已在 `mastersos_bundle::diag`（提交 2181dba1），本计划不改它们。

**Tech Stack:** Rust（tokio、reqwest、serde、zstd/tar）、GJS（GNOME Shell 50 扩展）、Chrome MV3 扩展（kiosk-extension）、systemd 单元、mkosi 树。

**Spec:** `docs/specs/2026-11-05-remote-diagnostics-and-help-design.md`

## 执行顺序（并行波次）

- 波次 A（互不依赖，同时跑）：Task 1、Task 2、Task 3、Task 6、Task 7（Task 6/7 只依赖本文定死的 socket 协议，用假 socket/假宿主测试）。
- 波次 B：Task 4（需 2、3）、Task 5（需 2、3）。
- 波次 C：Task 8。每个任务在自己的 worktree 分支上做，审查通过后由控制者合入 master。

## 计划裁定（自审后加入）

- Ruling P1：Kiosk 一期不带截图。`captureVisibleTab` 需要 `<all_urls>` 或 activeTab，kiosk 扩展现在只有考试站点的 host 权限，为截图放宽权限不值；登录页与桌面照常可截。代价：Kiosk 里的显示问题 IT 看不到画面，靠描述与日志。
- Ruling P2：收集器所有文件读取都经 `root: &Path` 前缀（生产为 `/`），测试用临时目录造假的文件树，「不读种子分区」这类断言才测得到。
- Ruling P3：对话框拆成纯逻辑 `help-model.js`（请求组装、校验、错误到文案的映射，node 下测，同 `people.js` 的做法）与界面 `help.js`（不做单测，靠 VM 截图自审）。
- Ruling P4：greeter 与 kiosk 会话的认定方式（logind `Class=greeter`、kiosk 账户命名）没有在真机上核实过；实现者先读 `kiosk_session.rs` 与 GDM 50 的 greeter 用户规则，写进代码注释；Task 8 在 VM 上逐一核对三种会话认定结果。

- Ruling P5：协议由云端定稿（用户定）。云端修订（ticket 附件按 `client_id` 认、`expires_in`、`boots`/`since_hours` 互斥、错误码表 `error_action`、
  服务端限 10 条/时、snapshot ≤64 KiB、上传头只带下发的、`diag::source` 固定名单）先由一个前置提交改进 `mastersos_bundle::diag`，波次 A 在它合入后开始。
  各任务一律用 `error_action(status, body)` 决定丢弃、退避、重来，不自己按状态码分支。

## Global Constraints

- 代码注释、错误、脚本输出英文；终端用户文字走 i18n，英文为主（登录扩展 `strings.js` + `image/login-i18n/*.po` 84 种；kiosk 扩展只英文）。提交信息中文。
- 不进公开库：域名（诊断子域名）、桶名、任何诊断包或其中内容。提交前 `python3 -I tools/check-private.py`。
- Rust 检查：`cd core && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`，在 CI 机器上跑（Mac 上重构建被拦）。shell 测试：`bash image/tests/check-tree.sh`，在 ubuntu:24.04 amd64 容器跑。
- 上限：IT 收集包 50 MiB（`DIAG_INBOX_MAX_BYTES`）、求助附件 10 MiB（`DIAG_TICKET_MAX_BYTES`）；描述 ≤1000 字符；每机每小时 3 条；附件 48 小时内传不成放弃；截图 PNG ≤5 MiB。
- 收集白名单不收：种子分区（seed、`identity.json`、令牌）、`/etc/NetworkManager/system-connections/`、私钥与令牌文件、用户主目录。
- 设备凭据、presigned URL 的 query、令牌永不进日志、错误或 ack detail。
- 截图默认不勾；勾选后先给预览；截的是打开对话框之前的画面。
- 收集开始时提示「IT is collecting diagnostic info from this computer.」。
- 求助文案（英文原文，逐字）：标题 `Get help from IT`；分类 `Wi-Fi` / `Can't sign in` / `An app` / `Screen, keys or sound` / `Battery` / `Other`；
  占位 `What happened? Please don't include passwords or personal details.`；勾选 `Attach a screenshot`；按钮 `Cancel` / `Send`；
  成功 `Sent. Ticket #<n>. IT has been told.`；关闭 `Help requests are turned off at this school.`；排队 `Saved. It will be sent when this computer is online.`；限流 `You've sent 3 requests this hour. Please try again later.`

## Review Focus

1. 学生发单后马上关机或断电：队列在 `/var/lib/mastersos/support-queue/`，下次开机联网补发，同一 `client_id` 拿同一单号（Task 5 测试 `queue_survives_restart_and_reuses_client_id`）。
2. agent 在上传中途重启：`collect-diagnostics` 已 ack running，重启后必须续上而不是丢掉（Task 4 测试 `resumes_pending_collect_after_restart`）。
3. journal 很大（多次开机共 >50 MiB）：截断从最早一次开机丢起，标 `truncated`，绝不发超限包（Task 2 测试 `truncates_oldest_boot_first`）。
4. 界面伪造身份：请求 JSON 里带 `user`/`name` 字段一律拒绝（未知字段），身份只来自 peercred（Task 5 测试 `rejects_client_supplied_identity`）。
5. 限流跨重启：计数存盘，重启后同一小时第 4 条仍被拒（Task 5 测试 `rate_limit_survives_restart`）。

---

### Task 1: 删除 U 盘诊断

**Files:**
- Modify: `core/mastersos-installer/src/{main.rs,lib.rs,plan.rs,tty.rs}`（去掉 `sniff_debug`、1 秒窗口、`Developer diagnostics: ON` 行、`debug-install` 标记及其测试）
- Delete: `image/mkosi.extra/usr/lib/mastersos/{diag-export,diag-setup}`、`.../systemd/system/mastersos-diag-{adopt,setup}.service`、`mastersos-diag-export@.service`、两处 `sysinit.target.wants/` 链接、4 个 `90-mastersos-diag.conf`、`usr/lib/udev/rules.d/91-mastersos-diag.rules`、`image/tests/diag-{export,setup}-test.sh`、`image/tests/fixtures/diag/`
- Create: `image/mkosi.extra/usr/lib/tmpfiles.d/mastersos-diag-cleanup.conf`（`R /var/lib/mastersos-diag`：已装成 debug 的机器清掉旧开关）
- Modify: `image/tests/check-tree.sh`（删 diag 相关项；新增一项断言上面那些路径都不存在、`tmpfiles` 行存在）、`image/check-execstart-copies.sh` 若引用 diag 则同步
- Modify: `docs/specs/2026-11-03-diagnostics-design.md`、两份旧计划头部加一行「已被 2026-11-05-remote-diagnostics-and-help-design 取代」

- [ ] Step 1: 先改 check-tree：新增断言「diag 文件不存在、cleanup tmpfiles 存在」，跑 check-tree，Expected: 该项 FAIL。
- [ ] Step 2: 删文件、改安装器（`MASTERSOS_LOG_LEVEL` 的读取保留：无害且以后二期 `diag-verbose` 会用）。
- [ ] Step 3: Rust 全量检查+ check-tree 全过；`grep -rn "diag-export\|debug-install\|sniff_debug" core image` 无结果。
- [ ] Step 4: 提交 `refactor: 删除 U 盘诊断（改为远程收集）`。U 盘上的 `diag.sh` 与 README 提到它的行由控制者手动删（不在仓库）。

### Task 2: 诊断收集器

**Files:**
- Create: `core/mastersos-agent/src/diag/{mod.rs,collect.rs,redact.rs}`
- Modify: `core/mastersos-agent/src/main.rs`（子命令 `diag collect`）、`core/mastersos-agent/Cargo.toml`（`tar`、`zstd`，先查 workspace 里是否已有）

**Interfaces:**
- Produces: `pub struct CollectOpts { pub root: PathBuf /* 生产 "/"，Ruling P2 */, pub kind: DiagKind, pub boots: u8, pub since_minutes: Option<u32>, pub screenshot: Option<PathBuf>, pub max_bytes: u64 }`；
  `pub struct Collected { pub path: PathBuf, pub bytes: u64, pub sha256: String, pub manifest: DiagManifest }`；
  `pub fn collect(o: &CollectOpts, device_id: &str, out_dir: &Path, runner: &dyn Runner, now: DateTime<Utc>) -> Result<Collected>`；
  `pub fn redact(text: &str) -> Cow<str>`。命令行：`mastersos-agent diag collect --out <file> (--boots N | --since-minutes M) [--screenshot <png>]`（IT 现场排错用，同一函数）。
- 来源清单：`source` 字段只能用 `mastersos_bundle::diag::source::ALL` 里的名字，每个 source 一个独立文件（云端按 source 丢弃 `wifi-scan`、`coredump-info`，按 source 换代号）。对应：spec「设计 2」逐条；journal 用 `journalctl -b <-k> -o short-iso-precise --no-pager`（每次开机一个文件 `journal/boot-<k>.txt`），轻量模式 `--since "-M min"` 写 `journal/recent.txt`；命令缺失或失败记 `skipped`。
- 包内布局：`manifest.json` 在根，文本文件 `type=text`，截图 `screenshot.png` `type=image`。

- [ ] Step 1: 测试（假 `Runner` 返回固定输出）：`manifest_lists_every_file_with_type_and_bytes`；`missing_command_goes_to_skipped`；
  `never_reads_seed_or_system_connections`（断言 runner 收到的命令与读取的路径里没有 `/var/lib/mastersos-seed`、`system-connections`、`identity.json`）；
  `redact_masks_secrets`（`psk=abc`→`psk=[redacted]`、`password=`、`Authorization: Bearer x`、`"token":"x"`、`secret=` 大小写不敏感；普通行原样）；
  `truncates_oldest_boot_first`（boots=3，每个 boot 文本大到总量超 `max_bytes`，结果丢 boot-2 起、`truncated=true`、`bytes<=max_bytes`）；
  `sha256_matches_file`。跑：Expected FAIL（模块不存在）。
- [ ] Step 2: 实现。写到 `out_dir` 下临时名再改名，0600；压缩 zstd 级别 9。截断算法：先全量打包，超限则去掉最早的 boot 文件重打，直到 ≤max 或只剩 manifest+非日志文件；仍超限返回错误（不发）。
- [ ] Step 3: 测试通过 + clippy；提交 `feat(agent): 诊断收集器（白名单、去密、超限截断）`。

### Task 3: 三步上传客户端

**Files:**
- Modify: `core/mastersos-agent/src/fetch.rs`
- Create: `core/mastersos-agent/src/diag/upload.rs`

**Interfaces:**
- Consumes: `Collected`（Task 2）、`DiagUploadRequest`/`DiagUploadResponse`/`PresignedUpload`（bundle）。
- Produces: `Fetcher::diag_upload_url(&self, cred: &DeviceCred, r: &DiagUploadRequest, lab: bool) -> Result<DiagUploadResponse>`（413/409 映射为错误类型 `DiagRefused { status }`）；
  `Fetcher::diag_put(&self, u: &PresignedUpload, file: &Path) -> Result<()>`（原样带 `headers`，流式 body，不跟随重定向）；
  `Fetcher::diag_complete(&self, cred: &DeviceCred, id: &str, lab: bool) -> Result<CompleteOutcome>`，`enum CompleteOutcome { Done, Rejected }`（204/409）；
  `pub async fn upload(f: &Fetcher, cred: &DeviceCred, req: DiagUploadRequest, file: &Path, lab: bool) -> Result<String /* id */>`：
  1 → (complete:true 直接返回 id) → 2 → 3；`upload_mismatch`、`expires_in` 已到（单调时钟，从收到回复起算）或 S3 回 `AccessDenied` 且含 `Request has expired` 时回到 1，最多 3 轮；
  其余错误按 `error_action`。PUT 只带 `headers` 里给的头（含 `x-amz-sdk-checksum-algorithm`），不加 Content-MD5、不加 Content-Type，可带 `Expect: 100-continue`。
  ticket 附件的请求是 `DiagUploadRequest::Ticket { client_id, .. }`。

- [ ] Step 1: 测试用现有 fetch 测试的本地 mock HTTP 服务器：`upload_happy_path_sends_headers_verbatim`（断言 PUT 带上下发的 `x-amz-checksum-sha256`、`x-amz-tagging`、`Content-Length`）；
  `already_complete_skips_put`；`upload_mismatch_restarts_from_step_one`；`expires_in_elapsed_restarts`；`s3_request_expired_restarts`；`not_yours_and_expired_give_up`；`no_extra_headers_on_put`；`gives_up_after_three_rounds`；
  `error_text_has_no_query_string`（错误信息里不出现 `X-Amz-Signature`）。Expected FAIL。
- [ ] Step 2: 实现；错误信息以 `upload: ` 开头，便于 inbox detail 直接用。
- [ ] Step 3: 通过；提交 `feat(agent): 诊断包三步上传（presigned PUT）`。

### Task 4: inbox `collect-diagnostics`

**Files:**
- Modify: `core/mastersos-agent/src/inbox.rs`、`core/mastersos-agent/src/state.rs`、`core/mastersos-agent/src/run.rs`
- Modify: `core/mastersos-agent/src/status.rs`（`status.json` 加 `diag_collecting_until: Option<DateTime>`，登录页显示提示用）

**Interfaces:**
- Consumes: `collect`（Task 2）、`upload`（Task 3）、`CollectDiagnostics`（bundle）。
- Produces: `State::diag_pending: Option<PendingDiag { seq: u64, expires_at: Option<DateTime<Utc>>, payload: CollectDiagnostics }>`；
  `pub fn notify_sessions(text: &str, runner: &dyn Runner)`（给每个活跃图形会话发 `notify-send`，复用 `login_queue::notify_with`）。
- 流程：payload `validate()` 不过 → ack failed `bad payload: …`；否则 ack `running` 并确认送达（同 factory-reset 的规则）→ 存 `diag_pending` → 推进 `inbox_after`，
  主循环外的任务做「提示 → collect → upload」→ ack `done` detail `diag:<id>` / `failed` `collect: …` / `upload: …`，清 `diag_pending`。
  上传失败按 `crate::backoff` 重试直到 `expires_at`。agent 启动时有 `diag_pending` 就续做。同一时间只跑一个，第二条等第一条结束。

- [ ] Step 1: 测试：`collect_acks_running_then_done_with_id`；`invalid_payload_is_failed_not_run`；`upload_failure_retries_until_expiry_then_failed_with_upload_prefix`；
  `resumes_pending_collect_after_restart`；`collect_does_not_block_next_inbox_message`；`notice_shown_when_collect_starts`（假 runner 收到 notify-send 且文本逐字）。Expected FAIL。
- [ ] Step 2: 实现。
- [ ] Step 3: 通过；提交 `feat(agent): inbox collect-diagnostics`。

### Task 5: 本地求助服务与发送器

**Files:**
- Create: `core/mastersos-agent/src/support/{mod.rs,host.rs,queue.rs,send.rs}`
- Create: `image/mkosi.extra/usr/lib/systemd/system/mastersos-support.socket`（`ListenStream=/run/mastersos/support.sock`、`SocketMode=0666`、`Accept=no`）、`mastersos-support.service`（`ExecStart=/usr/bin/mastersos-agent support host`，root，按 check-execstart-copies 的约定）、socket 的 `sockets.target.wants` 链接
- Modify: `core/mastersos-agent/src/main.rs`（子命令 `support host`、`support native-host`）、`run.rs`（主循环醒来时 `send::drain`）
- Modify: agent 写 `support.json`（0644，public dir）：`{"enabled": <Config.support_enabled>}`，在设置应用步骤里写

**Interfaces:**
- socket 协议：一行 JSON 请求、一行 JSON 回复，单个请求 ≤8 MiB。
  - `{"op":"submit","category":"wifi","text":"…","session":"login|desktop|kiosk:<id>","screenshot_png_b64":null|"…"}`（`deny_unknown_fields`）→ `{"ok":true,"client_id":"…","state":"queued"}` 或 `{"ok":false,"error":"rate_limited|invalid|disabled"}`
  - `{"op":"status","client_id":"…"}` → `{"ok":true,"state":"queued|sent|failed|disabled","ticket":"1042"?}`（只答本 uid 提交的）
  - `{"op":"enabled"}` → `{"ok":true,"enabled":bool}`
- 认人：`SO_PEERCRED` 取 uid/pid；pid 所在 logind 会话 `Class=greeter` → `none`；uid 1999 → `guest`；kiosk 会话（`kiosk_session.rs` 的账户规则）→ `none` 且 session 强制 `kiosk:<id>`；
  passwd 条目来自 authd → `sso`，其他 → `local`；`name` 取 passwd 名（`none` 时不填）。`session` 字段与认定冲突时以认定为准。
- 队列：`/var/lib/mastersos/support-queue/<client_id>.json`（0600，目录 0700）存 `SupportRequest` + `screenshot.png` + 状态 `{state, ticket, created_at, attach_done}`；计数文件 `rate.json` 记最近一小时的提交时间。
- `send::drain(f, cred, now)`：每条未发的 → `POST /v1/support`（`SupportRequest`，`snapshot` 由 `os-release`、NM 状态、电池、磁盘、最近一次 `StatusReport` 组成）→ 记 ticket → `collect(kind=Ticket, since_minutes=30, screenshot)` → `upload` → `attach_done`；
  错误按 `error_action`：`too_many` 按 Retry-After 稍后再发；`support_disabled` 丢弃队列里的单子、状态 `disabled`（界面显示 `Help requests are turned off at this school.`）；`invalid` 丢弃并记日志；
  `not_yours`/`expired` 放弃附件；附件 48 小时窗口以服务端为准（`expired` 即放弃），删附件，单子保持 `sent`；`sent` 且附件完成的 7 天后删。
- `support native-host`：Chrome native messaging（4 字节长度前缀 JSON）转发到 socket，`session` 由 host 按 kiosk 账户填。宿主清单 `org.mastersos.support.json`，`allowed_origins` 同 `org.mastersos.kiosk_exit.json`。

- [ ] Step 1: 测试：`rejects_client_supplied_identity`；`greeter_peer_is_none_guest_uid_is_guest`；`rate_limit_survives_restart`；`queue_survives_restart_and_reuses_client_id`；
  `text_over_1000_chars_invalid`；`disabled_config_refuses_submit`；`status_only_for_own_uid`；`drain_posts_then_uploads_ticket_attachment`；`too_many_retries_after`；`support_disabled_drops_queue`；
  `attachment_dropped_after_48h_ticket_kept`；`native_host_frames_roundtrip`。Expected FAIL。
- [ ] Step 2: 实现；check-tree 加一项：socket/service/链接/宿主清单存在，service 的 ExecStart 合 execstart 约定。
- [ ] Step 3: 通过；提交 `feat(agent): 本地求助服务、离线队列与发送`。

### Task 6: 求助对话框（登录页与桌面）

**Files:**
- Create: 登录扩展里 `help-model.js`（纯逻辑，Ruling P3）与 `help.js`（ModalDialog 界面），桌面扩展 `mastersos-managed@mastersos.org/` 里放**逐字节相同的两份副本**（check-tree 断言相同）
- Create: `image/tests/help-model-test.sh` + `help-model-test.mjs`（同 `login-people-test.sh` 的做法，node 下跑），并接入 CI 的 image 测试步骤
- Modify: 登录扩展 `shelf.js`（底部「Get help」，`support.json` enabled=false 时隐藏）、`strings.js`、`stylesheet.css`；桌面扩展 `extension.js`（系统菜单 Quick Settings 加「Get help」）、`stylesheet.css`
- Modify: `image/login-i18n/*.po`（全部新文案 84 种）；status 横幅：`diag_collecting_until` 未过期时登录页显示收集提示

**Interfaces:**
- Consumes: Task 5 socket 协议。
- Produces: `export class HelpDialog extends ModalDialog.ModalDialog`，`constructor({session, gettext})`；`open()` 前先 `Shell.Screenshot` 截全屏到内存（勾选时才用），预览为 160px 宽缩略图；发送后轮询 `status` 每 3 秒、最多 60 秒，拿到 ticket 显示成功文案，否则显示排队文案。

- [ ] Step 1: 测试（`help-model-test.mjs`）：`buildSubmit` 请求 JSON 形状、分类必选、空描述可发、截图未勾不带 `screenshot_png_b64`、限流错误映射到逐字文案）；check-tree 新项（两份 help.js 相同、84 个 .po 都有新 msgid）。Expected FAIL。
- [ ] Step 2: 实现；UI 对齐现有登录卡片的视觉（圆角、配色 token、焦点环）。
- [ ] Step 3: 通过；VM 里截图自审（登录页、桌面各：空表单、勾截图带预览、已发送、排队、限流），截图新编号保存；不满意就改到满意。
- [ ] Step 4: 提交 `feat(login,desktop): Get help 对话框`。

### Task 7: Kiosk 里的 Get help

**Files:**
- Modify: `kiosk-extension/content.js`（`ACTIONS` 在 Exit 前加 `Get help`；对话框在现有 shadow root 里，复用确认卡片样式）、`kiosk-extension/background.js`（`chrome.runtime.connectNative("org.mastersos.support")`；不截图，Ruling P1，对话框里没有截图勾选项）、`manifest.json`（版本 1.2.0、`nativeMessaging` 已有则不动）
- Test: `kiosk-extension/tests/`（vitest）

- [ ] Step 1: vitest：`menu_has_get_help_before_exit`；`dialog_requires_category`；`no_screenshot_option_in_kiosk`；`sends_native_message_shape`；`shows_ticket_or_queued_text`。Expected FAIL。
- [ ] Step 2: 实现；文案只英文（同 Exit）。
- [ ] Step 3: 74+ 个 vitest 全过；mock 页面里截图自审（菜单、对话框、预览、结果）。
- [ ] Step 4: 提交 `feat(kiosk): 浮动菜单加 Get help`。

### Task 8: 文档与整机验证

**Files:**
- Modify: `README.md`/`README.en.md`（防火墙一句：「诊断上传域名见学校管理网站的 Install 页」）、`core/mastersos-bundle/docs/manifest-spec.md` 无需动（2181dba1 已加 `config.support`）

- [ ] Step 1: README 改好，check-private 干净，提交。
- [ ] Step 2: 镜像构建（master，release 环境批准）→ 测试 VM：
  登录页、桌面、Kiosk 各发一条（一条勾截图），核对云端收到的 `user.kind`/`session` 分别是 `none`/`login`、`guest` 或 `sso`/`desktop`、`none`/`kiosk:<app id>`（Ruling P4）→ 云端测试学校看到单号与附件；断网发一条 → 联网后补发；
  云端发 `collect-diagnostics` → 屏幕出提示 → 云端拿到包，解开看白名单与去密（只在本机临时目录看，不留存、不进仓库）。云端未就绪的部分记为待验。
- [ ] Step 3: 截图新编号保存并列路径汇报。
