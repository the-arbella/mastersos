# 学习模式的会话完整性 实施计划（第一期：不变式 1、2、4）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 学习模式设备上，学生每次登录前由 root 按保留清单收拾家目录、结束遗留的用户管理器；模式的发布永远不比实际的锁更松；完全模式不变。

**Architecture:** agent 的 desktop 步骤改为"收紧先发布、放开后发布"`session-mode`，所有读模式的地方用同一条规则。登录钩子
`pam-session`（root，PAM 会话段最前）在 `Enqueue` 分支里：学习模式下先处理这个 uid 遗留的会话与 linger，再用"容器对调"收拾家目录，
出错照样放行并记录。新模块 `system/home_tidy.rs` 放保留清单与收拾算法。

**Tech Stack:** Rust（mastersos-agent，rustix、safefs）、bash（生成器、browser-wait）。

**Spec:** `docs/specs/2026-11-10-learning-session-integrity-design.md`

## Global Constraints

- worktree `/Users/david/projects/arbella/mastersos-lsi`，分支 `design/learning-session-integrity`。
- 公开仓库：提交前 `python3 -I tools/check-private.py`；注释、报错、输出英文；提交信息中文，结尾 `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`。
- 模式读取规则（所有读者统一）：`session-mode` 不在 → full；内容去空白、转小写后是 `full` → full；其余一律 learning。
- root 操作用户目录只经 `safefs`/rustix 的 `*at` 调用，`O_NOFOLLOW`，不跟随符号链接；不在登录路径上递归删除。
- 登录钩子里每条外部命令限时 `ephemeral::PAM_CMD_TIMEOUT`（5 秒）；收拾出错一律放行登录。
- 日志与回报不写学生的文件名、路径与 uid，只写计数与原因类别。
- 完全模式与 `session-mode` 不在时：钩子不碰家目录、不碰 linger、登录脚本照旧只跑一次。
- Rust 快检查在 测试机（labtest `core` 套件）；shell 测试与 check-tree 在 ubuntu:24.04 容器（非 root）。

## Review Focus

1. 收拾进行到一半时断电或进程被杀（保留项已挪进临时目录、还没对调）：下次登录不能把 Chrome 资料当垃圾丢掉。→ Task 3 `recovers_interrupted_swap`。
2. 学生把 `~/.config` 换成指向 `/etc` 的符号链接，或 `~/.profile` 是指向系统文件的链接：只挪走链接本身，`/etc` 毫发无损。→ Task 3 `symlinked_container_is_moved_not_followed`。
3. 老师的设备（full）或还没设置的设备：钩子完全不碰家目录。→ Task 5 `tidy_decision_by_mode`。
4. 学生退出后留着后台 Chrome（会话 `closing`）或开了 linger：先结束这些再收拾，而不是永远跳过。→ Task 4 `prepare_stops_leftovers`。
5. 容器目录本身是挂载点（`rename` 报 `EBUSY`）或属主不是这个用户：跳过这一项、照样放行、回报里有原因类别。→ Task 3 `foreign_container_is_skipped`（属主）；挂载点只能在 VM 上验，列入重验证清单。

---

### Task 1: 模式的发布次序（不变式 1）

**Files:**
- Modify: `core/mastersos-agent/src/system/exec_block.rs:164-222`（`SESSION_MODE_FILE` 文档、`write_mode`）
- Modify: `core/mastersos-agent/src/system/desktop.rs:387-432`（`run`）
- Test: `core/mastersos-agent/src/system/exec_block.rs` 内的 tests、`core/mastersos-agent/src/system/desktop/tests.rs`

**Interfaces:**
- Produces:
  - `pub fn write_session_mode(paths: &SysPaths, learning: bool) -> Result<()>`（exec_block.rs；写 `learning\n`/`full\n`，0644，经 `safefs::write_at`）
  - `pub fn session_mode_locked(public_dir: &Path) -> bool`（exec_block.rs；按 Global Constraints 的读取规则，读不出也算 learning，文件不在才 false）
  - `write_mode` 只写 `exec-block-mode`，不再写 `session-mode`。

- [ ] **Step 1: 写失败的测试**
  - exec_block tests `session_mode_rule`：不在 → false；`full\n`、` FULL ` → false；`learning\n`、`browser`、空文件、`\xff` → true。
  - exec_block tests `write_mode_leaves_session_mode`：`write_mode(paths, true)` 后 `session-mode` 不存在。
  - desktop tests `tightening_publishes_learning_first`：设备从 full 切到 learning，`dconf update` 的 runner 返回失败；断言 `session-mode` 内容是 `learning\n`。
  - desktop tests `loosening_publishes_full_last`：从 learning 切到 full，`dconf update` 失败 → `session-mode` 仍是 `learning\n`；再跑一轮且成功 → `full\n`。
  - desktop tests `unrelated_failure_does_not_block_full`：切到 full，网页应用图标下载失败（用现有测试里让 webapps 出错的办法）、锁相关步骤成功 → `full\n`，回报项 `desktop` 仍是失败。
- [ ] **Step 2: 在 测试机 跑 `core` 套件（args `-p mastersos-agent exec_block desktop`），确认这些测试失败**
- [ ] **Step 3: 实现**：`run` 开头 `if p.locked() { write_session_mode(paths, true) }`（失败记进 errs）；末尾 `if !p.locked() && 锁相关的 dconf、overrides、exec_block 三步都成功 { write_session_mode(paths, false) }`。`SESSION_MODE_FILE` 的文档改写为本次次序与读取规则。
- [ ] **Step 4: 测试机 跑完整 `core` 套件，全部通过**
- [ ] **Step 5: 提交** `feat(agent): session-mode 收紧先发布、放开后发布，读取规则统一`

### Task 2: 读模式的一方统一规则

**Files:**
- Modify: `image/mkosi.extra/usr/local/lib/systemd/user-environment-generators/{30-systemd-environment-d-generator,60-flatpak}`（删掉 `locks_file` 判断）
- Modify: `image/mkosi.extra/usr/lib/mastersos/browser-wait:67`
- Test: `image/tests/user-env-test.sh`、`image/tests/browser-wait-test.sh`、`image/tests/check-tree.sh` 第 76 项

- [ ] **Step 1: 改测试**：user-env-test 删掉 `locks_file` 相关的 sed 与四条"with dconf locks present"用例，加 `garbage`（写 `\xff\n`）→ 过滤的用例；browser-wait-test 加：`session-mode` 写 `garbage` → 走锁住会话的分支（与 `learning` 相同的期望），不在 → 通知一次（现有期望）。
- [ ] **Step 2: 容器里跑两个测试，确认新用例失败**（`rt.sh` 跑 `bash image/tests/user-env-test.sh; bash image/tests/browser-wait-test.sh`）
- [ ] **Step 3: 实现**：生成器去掉 `locks_file=` 与对应 `if`，注释改为"次序由 agent 保证（不变式 1）"；browser-wait 第 67 行改为：文件存在且内容不是 `full` 即锁住（同一条规则，去空白、转小写）。check-tree 第 76 项不再要求 `locks_file`，改为要求两个生成器都不含 `dconf/db`。
- [ ] **Step 4: 两个测试、check-tree、相关文件的 shellcheck 全过**
- [ ] **Step 5: 提交** `fix(image): 读 session-mode 的地方用同一条规则，生成器不再看锁文件`

### Task 3: 家目录收拾的核心（保留清单与容器对调）

**Files:**
- Create: `core/mastersos-agent/src/system/home_tidy.rs`、`core/mastersos-agent/src/system/home_tidy/tests.rs`
- Modify: `core/mastersos-agent/src/homes/trash.rs`（加 `to_trash_entry`）、`core/mastersos-agent/src/system/mod.rs`（`pub mod home_tidy;`）

**Interfaces:**
- Produces:
  - `pub fn to_trash_entry(dir: &OwnedFd, trash: &OwnedFd, name: &str) -> Result<bool>`（trash.rs）：`renameat` 进回收目录的新随机名（`fresh_name(FLAT_PREFIX)`），之后按 `to_trash` 的 `seal` 收成 root 0700；不论文件、目录还是链接，链接不跟随。返回值含义同 `to_trash`。
  - `pub const KEEP_TOP: &[&str] = &[".pki"];`
  - `pub const CONTAINERS: &[(&str, &[&str])] = &[(".config", &["google-chrome", "dconf", "user-dirs.dirs", "user-dirs.locale", "monitors.xml", "gtk-3.0/bookmarks"]), (".cache", &["google-chrome"]), (".local", &["share/keyrings", "state/wireplumber"]), (".var", &["app"])];` 每项一行英文注释说明为什么留（照 spec 表格）。
  - `pub const MAX_TOP_ENTRIES: usize = 10_000;`
  - `pub struct Tidy { pub moved: usize, pub skipped: Vec<SkipReason> }`；`pub enum SkipReason { ForeignContainer, ContainerBusy, TooManyEntries, Io }`
  - `pub fn tidy_home(home: &OwnedFd, trash: &OwnedFd, uid: u32) -> Tidy`（不返回 Err：每一项出错记一个 `SkipReason` 后继续下一项）

**算法（实施者照此，测试钉住）：**
1. 每个容器 `C`：临时目录名固定为 `.mastersos-tidy<C>`（如 `.mastersos-tidy.config`）。
   - 先恢复：若临时目录已存在（上次中断），对它里面每个保留项：`C` 里有同名的就先把 `C` 里那个 `to_trash_entry`，再把临时目录里的挪回 `C`；然后把临时目录 `to_trash_entry`。
   - `C` 不存在：跳过。`C` 是链接、不是目录：`to_trash_entry` 掉它（不跟随）。`C` 的属主不是 `uid`：`ForeignContainer`，跳过。
   - `mkdirat` 临时目录（属主 `uid`、权限同 `C`）；对每个保留项，必要时在临时目录里建中间目录（属主 `uid`、0700），`renameat` 叶子过去（叶子不存在就略过；叶子是链接就当普通条目挪）。
   - `safefs::exchange_at(home, C, 临时目录)`（`RENAME_EXCHANGE`，原子）；`EBUSY` → `ContainerBusy`：把保留项挪回 `C`、删掉空临时目录、跳过。
   - 对调后临时目录名下是旧内容：`to_trash_entry` 它。
2. 顶层：`safefs::list_at(home)`，名字以 `.` 开头、不在 `KEEP_TOP`、不是 `CONTAINERS` 的容器、不是 `.mastersos-tidy*`（第 1 步已处理）的，逐个 `to_trash_entry`；超过 `MAX_TOP_ENTRIES` 个就记 `TooManyEntries` 停止这一步。
3. 不以 `.` 开头的顶层条目一律不碰。

- [ ] **Step 1: 写失败的测试**（tempdir 当 `/home`，里面建一个家目录与回收目录；测试以普通用户跑，`uid` 用当前 euid；`seal` 的 chown 在非 root 下允许失败，返回 `Ok(false)` 也算挪走）
  - `keeps_only_the_keep_list`：家目录里有 `Documents/a.txt`、`.profile`、`.bashrc`、`.config/google-chrome/Default/Bookmarks`、`.config/autostart/x.desktop`、`.config/systemd/user/x.service`、`.config/environment.d/x.conf`、`.config/gtk-3.0/bookmarks`、`.config/gtk-3.0/settings.ini`、`.local/share/keyrings/login.keyring`、`.local/share/applications/x.desktop`、`.local/share/dbus-1/services/x.service`、`.local/share/gnome-shell/extensions/x/metadata.json`、`.local/share/flatpak/exports/share/x`、`.var/app/org.x/data`、`.pki/nssdb/cert9.db`。之后断言：保留的这些都在且内容不变——`Documents/a.txt`、`.config/google-chrome/Default/Bookmarks`、`.config/gtk-3.0/bookmarks`、`.local/share/keyrings/login.keyring`、`.var/app/org.x/data`、`.pki/nssdb/cert9.db`；其余列出的都不在家目录里；回收目录里多了条目；`moved > 0`，`skipped` 为空。
  - `recovers_interrupted_swap`：预先建 `.mastersos-tidy.config/google-chrome/Default/Bookmarks`（内容 "B"）与 `.config/autostart/x.desktop`，`.config` 里没有 `google-chrome`；跑完后 `.config/google-chrome/Default/Bookmarks` 内容是 "B"，`.config/autostart` 不在，`.mastersos-tidy.config` 不在。
  - `symlinked_container_is_moved_not_followed`：`.config` 是指向 tempdir 外一个目录 `outside/`（里面有 `keep.txt`）的链接，`.profile` 是指向 `outside/keep.txt` 的链接；跑完后 `outside/keep.txt` 仍在且内容不变，家目录里 `.config`、`.profile` 都不在（链接被挪走）。
  - `foreign_container_is_skipped`：用 `tidy_home(home, trash, euid + 1)`（属主对不上）→ `.config` 原样，`skipped` 含 `ForeignContainer`。
  - `too_many_top_entries_stops`：顶层建 `MAX_TOP_ENTRIES + 5` 个 `.f<n>` 文件 → `skipped` 含 `TooManyEntries`，`moved` 不超过 `MAX_TOP_ENTRIES + CONTAINERS.len()`，函数返回（不 panic、不报错）。
  - `idempotent`：连跑两次，第二次 `moved == 0`，保留项仍在。
  - trash tests `to_trash_entry_moves_file_dir_and_link`：三种条目各挪一次都离开原目录、出现在回收目录。
- [ ] **Step 2: 测试机 跑（args `-p mastersos-agent home_tidy trash`），确认失败**
- [ ] **Step 3: 实现** 上述接口与算法。
- [ ] **Step 4: 测试机 跑完整 `core` 套件，全部通过**
- [ ] **Step 5: 提交** `feat(agent): 家目录按保留清单收拾（容器对调，中断可恢复）`

### Task 4: 遗留会话与 linger

**Files:**
- Modify: `core/mastersos-agent/src/system/lock.rs`（`LoginUser` 加 `linger: bool`、`state: String`，`#[serde(default)]`）
- Modify: `core/mastersos-agent/src/system/home_tidy.rs`（加下面两个函数）
- Modify: `core/mastersos-agent/src/system/desktop.rs`（`run` 在 `p.locked()` 时调 `linger_off_for_students`，错误记进 errs）
- Test: `core/mastersos-agent/src/system/home_tidy/tests.rs`

**Interfaces:**
- Produces:
  - `pub enum Prep { Proceed, SkipActive, Failed }`
  - `pub fn prepare_user_manager(runner: &dyn Runner, uid: u32) -> Prep`：`loginctl show-user <uid> -p State --value`（限时 5 秒）。`active`/`online` → `SkipActive`；`closing`/`lingering` → 依次 `loginctl disable-linger <uid>`、`loginctl terminate-user <uid>`、`systemctl stop user@<uid>.service`，任一失败 → `Failed`，都成功 → `Proceed`；命令以"没有这个用户"失败（退出码非 0 且 stderr 含 `not logged in` 或 `No such`）或输出 `offline` → `Proceed`；其他失败 → `Failed`。
  - `pub fn linger_off_for_students(runner: &dyn Runner, admins: &[String]) -> Result<()>`：解析 `loginctl list-users --no-legend --json=short`，对 `linger == true`、`lock::is_person`、不在 `admins`（不区分大小写）的逐个 `loginctl disable-linger <uid>`。
- Consumes: `lock::list_users(runner)`、`lock::is_person`（改为 `pub(crate)`）。

- [ ] **Step 1: 写失败的测试**（FakeRunner）
  - `prepare_skips_active`：State 输出 `active\n` → `SkipActive`，之后没有别的调用；`online\n` 同。
  - `prepare_stops_leftovers`：`closing\n` → 调用序列恰为 `loginctl show-user 10001 -p State --value`、`loginctl disable-linger 10001`、`loginctl terminate-user 10001`、`systemctl stop user@10001.service`，返回 `Proceed`；`lingering\n` 同。
  - `prepare_offline_proceeds`：命令失败、stderr `Failed to get user: User ID 10001 is not logged in or lingering` → `Proceed`，无后续调用。
  - `prepare_failure`：`closing\n` 且 `terminate-user` 失败 → `Failed`。
  - `linger_off_skips_admins_and_system`：list-users 有学生（linger true）、管理员（linger true）、root、gdm、学生（linger false）→ 只对第一个学生 `disable-linger`。
  - desktop tests：learning 设备的 `run` 调到 `loginctl list-users`；full 设备不调。
- [ ] **Step 2: 测试机 确认失败** — [ ] **Step 3: 实现** — [ ] **Step 4: 测试机 完整 `core` 通过**
- [ ] **Step 5: 提交** `feat(agent): 学习模式下结束遗留会话、关掉学生的 linger`

### Task 5: 接进登录钩子

**Files:**
- Modify: `core/mastersos-agent/src/system/guest.rs:500-510`（`SessionAction::Enqueue` 分支）
- Modify: `core/mastersos-agent/src/system/home_tidy.rs`（加下面的函数）
- Modify: `core/mastersos-agent/src/system/desktop.rs`（回报项 `home-tidy`）
- Test: `core/mastersos-agent/src/system/home_tidy/tests.rs`、`desktop/tests.rs`

**Interfaces:**
- Produces:
  - `pub const RESULT_FILE: &str = "home-tidy.json";`（在 `var_dir` 下，0600）
  - `#[derive(Serialize, Deserialize)] pub struct LastTidy { pub at: u64, pub moved: usize, pub skipped: Vec<String>, pub outcome: String }`（`outcome`：`tidied`、`skipped-active`、`prepare-failed`、`not-a-home`；`skipped` 是 `SkipReason` 的 kebab 名）
  - `pub fn tidy_decision(public_dir: &Path) -> bool`（= `exec_block::session_mode_locked`）
  - `pub fn on_login(paths: &SysPaths, runner: &dyn Runner, user: &str, uid: u32)`：不返回结果、不 panic。`tidy_decision` 为假 → 立即返回、不写文件。否则 `prepare_user_manager` → `Proceed` 时打开 `/home`、`open_child_dir(home_root, <家目录名>)`（家目录取 passwd 记录，须正好是 `/home/<名字>`，否则 `not-a-home`）、`trash::open_trash(home_root, true)`、`tidy_home`；把 `LastTidy` 写进 `RESULT_FILE`（覆盖，只保留最近一次）。
- Consumes: Task 1 `session_mode_locked`；Task 3 `tidy_home`；Task 4 `prepare_user_manager`。

- [ ] **Step 1: 写失败的测试**
  - `tidy_decision_by_mode`：public_dir 里 `session-mode` 不在 / `full` → false；`learning` / 乱码 → true。
  - `on_login_full_mode_touches_nothing`：`session-mode = full`、家目录里有 `.profile` → 跑完 `.profile` 仍在、`RESULT_FILE` 不存在、FakeRunner 没有调用。
  - `on_login_learning_tidies`：`session-mode = learning`、FakeRunner 的 State 返回 `offline` 失败 → `.profile` 不在，`RESULT_FILE` 的 `outcome == "tidied"`、`moved >= 1`。
  - `on_login_active_skips`：State `active` → `.profile` 仍在，`outcome == "skipped-active"`。
  - desktop tests `home_tidy_report_item`：`RESULT_FILE` 里 `outcome == "tidied"` 且 `skipped` 空 → 回报项 `home-tidy` ok；有 `skipped` 或 `prepare-failed` → 回报项 failed，`detail` 只含计数与原因名（断言不含 `/`）；文件不在 → 不出这一项。
- [ ] **Step 2: 测试机 确认失败**
- [ ] **Step 3: 实现**：`Enqueue` 分支在 `claim_from_pam` 之前调 `home_tidy::on_login(&SysPaths::system(), &RealRunner, &user, uid)`（`SysPaths` 的取法照 guest.rs 里现有的系统路径用法）。测试用的 `/home` 根经 `paths.root` 拼出。
- [ ] **Step 4: 测试机 完整 `core` 通过**
- [ ] **Step 5: 提交** `feat(agent): 学习模式登录前收拾家目录，结果进回报`

### Task 6: 学习模式下登录脚本每次登录都跑

**Files:**
- Modify: `core/mastersos-agent/src/login_queue.rs:401-414`
- Test: `core/mastersos-agent/src/login_queue.rs` tests（约 750-790 一带）

- [ ] **Step 1: 写失败的测试** `learning_runs_scripts_every_login`：Config 的 interface 为 learning，同一 uid、同一脚本内容连跑两次 `run_login_scripts`，两次都执行（FakeRunner 两次调用）；`full_runs_scripts_once` 保持现有行为（第二次不执行）。
- [ ] **Step 2: 测试机 确认失败**
- [ ] **Step 3: 实现**：`let guest = uid == GUEST_UID;` 改为 `let every_login = uid == GUEST_UID || crate::system::desktop::profile(config).locked();`，跳过条件用 `every_login`；模块文档第 16 行一带补一句学习模式也是每次跑及原因（家目录每次回到已知状态）。
- [ ] **Step 4: 测试机 完整 `core` 通过**
- [ ] **Step 5: 提交** `feat(agent): 学习模式设备上登录脚本每次登录都跑`

### Task 7: 收尾

- [ ] **Step 1**：spec 状态改为"已批准（David 2026-11-10）"；`image/README.md` 若描述学习模式的锁，加一段指向本 spec。
- [ ] **Step 1b**：核对学习模式设备上没有 GDM 以外的登录入口（spec「留给实施者」最后一条）：`grep -nE 'openssh-server|getty|autovt' image/mkosi.conf image/mkosi.postinst.chroot` 与 `image/mkosi.extra` 下的 getty/logind 配置；有就把 `pam-session` 钩子也装进那个 PAM 服务（照 `image/pam-hooks.sh`）或在 spec 写明为什么不需要。
- [ ] **Step 2**：Rust 快检查（测试机 完整 `core`）、check-tree、`user-env-test.sh`、`browser-wait-test.sh`、`python3 -I tools/check-private.py` 全过。
- [ ] **Step 3: 提交** `docs: 学习模式会话完整性设计标为已批准`

## 重验证清单（交给另一个 session）

1. 学习模式 VM：放进 `~/.config/environment.d/x.conf`（DCONF_PROFILE）、`~/.profile`、`~/.config/autostart/x.desktop`、`~/.config/systemd/user/x.service`（WantedBy default.target）、`~/.local/share/dbus-1/services/x.service`、`~/.local/share/gnome-shell/extensions/<冒名 mastersos-managed>`，退出再登录：都不生效；`Documents`、Chrome 书签与登录状态、学校 Flatpak 的数据都在。
2. 同上，但退出前在后台留一个进程（会话 `closing`）、或 `loginctl enable-linger`：再登录时都被结束，收拾照样发生。
3. 同一账号在两个座位/VT 同时登录：第二次登录不收拾，回报 `skipped-active`。
4. 完全模式 VM：上面这些全部照常生效。
5. 模式 full → learning → full 来回切：`session-mode` 与 dconf 锁始终一致，切到 full 时网页应用图标下载失败也能切过去。
6. 学生把 `~/.config` 换成 FUSE 挂载点或指向 `/etc` 的链接后再登录：登录成功，`/etc` 无变化，回报有原因类别。
7. 根目录权限矩阵（Task 3–5）：root 用 chown/封存跑一遍，含被硬链接的点文件；容器目录属主是别人（`chown root .config`）时只跳过那一项。
8. `EBUSY` 的几种情形：同一文件系统的 bind mount 盖在 `.config` 上、`.cache` 上挂 tmpfs、保留清单叶子 `.config/google-chrome` 上有挂载点：都跳过并回报原因，登录成功。
9. 容器目录里面有挂载点，且 `empty_trash` 清空回收目录时不得越过它进到挂载的文件系统。
10. 收拾的每个阶段 `kill -9` 后重跑：profile、dconf、钥匙环完好，没有留下临时目录。
11. 耗时：约 1 万个点文件加约 100 万个非点条目，对照 `PAM_CMD_TIMEOUT`。
12. 最坏的登录延迟：getent 与 loginctl 各命令叠加最多约 25 秒，确认在可接受范围。
13. tty 上保持一个会话，再到 GDM 登录：应回报 `skipped-active`（已知缺口，确认行为与回报一致）。
