# 诊断模式（插 U 盘导出日志）实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 装机时带 `debug.conf` 的机器，各组件开调试日志；插上任何 vfat/exfat 的 USB 盘就把诊断包写上去，无需登录、无需网络。

**Architecture:** 安装器把 U 盘上的 `debug.conf` 变成种子分区里的空标记文件。开机时 `mastersos-diag-setup.service` 看到标记就写
`/run/mastersos/diag.env` 与 NM drop-in，并打开 GDM 调试；各服务的静态 drop-in 读这个 env 文件。udev 规则在标记存在时把 USB 盘交给
`mastersos-diag-export@.service`，由 `/usr/lib/mastersos/diag-export` 收集、打包、写盘、卸载。

**Tech Stack:** Rust（installer、agent），bash（脚本与测试），systemd units，udev。

**Spec:** `docs/specs/2026-11-03-diagnostics-design.md`

## Global Constraints

- 开关路径固定：`/var/lib/mastersos-seed/debug.conf`；文件在（普通文件，不跟随符号链接）即打开，内容不读。安装 U 盘上同名文件，与 seed 放在一起。
- 开关以外不加任何选项；不加 agent 子命令；线上设置不读不写开关；不要求 U 盘卷标；所有镜像（含正式）都带。
- 诊断包文件名：`mastersos-diag-<machine-id 前 8 位>-<UTC YYYYMMDDTHHMMSSZ>.tar.zst`，先写 `.partial` 再改名。
- 挂载选项 `nosuid,nodev,noexec`；挂载点在 `/run/mastersos-diag/<设备名>`。
- 敏感信息不排除；不收用户主目录；诊断包与其内容不得进本仓库。
- wpa_supplicant 调到 debug，`DebugShowKeys` 保持 false。
- 注释、脚本输出英文；提交信息中文；提交前 `python3 -I tools/check-private.py`。
- shell 测试在 `ubuntu:24.04` amd64 容器里跑（GNU 工具）。

## Review Focus

1. **NM 卡死时 `nmcli` 挂住**（正是 Wi-Fi 出问题的场景）→ 每条收集命令限时 20 s，超时记 `timeout` 继续。测试：Task 4 `collect_timeout`。
2. **U 盘满或只读，tar 中途失败** → 盘上不留最终文件名，只可能留 `.partial`（随即删掉），staging 删掉，单元失败并在 journal 说原因。测试：Task 4 `pack_failure`。
3. **导出中途拔盘** → 单元 `BindsTo=` 设备而被停，trap 删掉 staging 与挂载点。测试：Task 4 `staging_cleanup`（模拟收到 TERM）。
4. **开机时盘已插着**（coldplug 早于种子分区挂载，udev 的 `TEST` 看不到标记）→ 不导出、不报错，重插即可；导出脚本自己再查一次标记，不在就不挂载。测试：Task 4 `switch_off_no_mount`。
5. **时钟是 1970 或 machine-id 读不到，同名文件已存在** → 加 `-2`、`-3` 后缀，不覆盖；machine-id 读不到用 `unknown`。测试：Task 4 `name_collision`。

---

### Task 1: 安装器带上开关

**Files:**
- Modify: `core/mastersos-installer/src/seed.rs`（在 `write_seed_dir` 之后加两个函数）
- Modify: `core/mastersos-installer/src/lib.rs:344`（`write_seed_dir` 调用之后）
- Test: `core/mastersos-installer/tests/decisions.rs`

**Interfaces:**
- Produces: `pub const DEBUG_FLAG: &str = "debug.conf";`
  `pub fn debug_flag_present(src_dir: &Path) -> bool`（`symlink_metadata(...).is_file()`，读不到即 false）
  `pub fn write_debug_flag(dir: &Path) -> Result<()>`（在 `dir` 下 `create_new` 一个 0644 空文件并 `sync_all`）

- [ ] **Step 1: 写失败测试**（`decisions.rs`）
  - `debug_flag_regular_file_is_present`：tempdir 里建 `debug.conf`（有内容）→ `debug_flag_present == true`。
  - `debug_flag_missing_dir_or_symlink_is_absent`：不存在的目录 → false；`debug.conf` 是指向普通文件的符号链接 → false；`debug.conf` 是目录 → false。
  - `write_debug_flag_writes_empty_file`：`write_seed_dir(&d, &SeedFound::None)` 后 `write_debug_flag(&d)` → `d/debug.conf` 存在、长度 0、mode `0o644`。
- [ ] **Step 2:** `cd core && cargo test -p mastersos-installer --test decisions debug_flag` → 编译失败（函数未定义）。
- [ ] **Step 3:** 在 `seed.rs` 实现上面三项并从 `lib.rs` 的 `pub use` 导出；`lib.rs` 在 `write_seed_dir(...)?;` 之后加：
  `if debug_flag_present(&source.dir) { write_debug_flag(Path::new(SEED_DIR))?; }`
  （`SEED_DIR` 由 repart 的 `CopyFiles=` 整个拷进种子分区，不用改 repart。无 seed 时 `write_seed_dir` 也建目录，所以同样生效。）
- [ ] **Step 4:** `cd core && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p mastersos-installer` → 全过。
- [ ] **Step 5:** 提交 `feat(installer): U 盘上有 debug.conf 时在种子分区建诊断开关`

### Task 2: agent 的日志级别可由环境变量调到 debug

**Files:**
- Modify: `core/mastersos-agent/src/main.rs:105,137`
- Test: 同文件 `#[cfg(test)] mod tests`（没有就新建）

**Interfaces:**
- Produces: 环境变量 `MASTERSOS_LOG_LEVEL`；`fn level_from_env(v: Option<&str>) -> log::LevelFilter`：`Some("debug")` → `Debug`，`Some("trace")` → `Trace`，其余（含 `None`、空、`DEBUG` 以外的拼写）→ `Info`。

- [ ] **Step 1: 写失败测试** `level_from_env_values`：断言上面四种输入的返回值（`None`、`Some("")`、`Some("debug")`、`Some("trace")`、`Some("verbose")` → Info）。
- [ ] **Step 2:** `cargo test -p mastersos-agent level_from_env` → 失败。
- [ ] **Step 3:** 实现，两处 `set_max_level(LevelFilter::Info)` 改为 `set_max_level(level_from_env(std::env::var("MASTERSOS_LOG_LEVEL").ok().as_deref()))`。
- [ ] **Step 4:** fmt/clippy/test 全过。
- [ ] **Step 5:** 提交 `feat(agent): MASTERSOS_LOG_LEVEL=debug 打开调试日志`

### Task 3: 开机时按开关打开各组件的调试日志

**Files:**
- Create: `image/mkosi.extra/usr/lib/mastersos/diag-setup`
- Create: `image/mkosi.extra/usr/lib/systemd/system/mastersos-diag-setup.service`
- Create: `image/mkosi.extra/usr/lib/systemd/system/sysinit.target.wants/mastersos-diag-setup.service`（符号链接，同仓库现有写法）
- Create: drop-in `90-mastersos-diag.conf`，放在 `mastersos-agent.service.d/`、`mastersos-agent-local.service.d/`、`authd.service.d/` 下
- Modify: `image/mkosi.extra/usr/lib/systemd/system/authd-oidc.service`（`ExecStart` 末尾加 `$MASTERSOS_DIAG_AUTHD_ARGS`，加 `EnvironmentFile=-/run/mastersos/diag.env`）
- Test: `image/tests/diag-setup-test.sh`

**Interfaces:**
- Produces: `/run/mastersos/diag.env`（只在开关在时写），内容固定：
  ```
  MASTERSOS_LOG_LEVEL=debug
  MASTERSOS_DIAG_AUTHD_ARGS=<Step 1 查到的参数>
  ```
  `/run/NetworkManager/conf.d/90-mastersos-diag.conf`：`[logging]` / `level=DEBUG`。
  `/etc/gdm3/custom.conf` 的 `[debug]` 段里有 `Enable=true`。
  `diag-setup` 可被测试 source；根目录由 `MASTERSOS_DIAG_ROOT`（默认空）前缀，所有路径都经它。

- [ ] **Step 1: 在 VM122（或 lab 镜像 VM）上查清，记进脚本注释：**
  `authd --help`、`/usr/libexec/authd-oidc --help` 的调试参数（预期 cobra 的 `-v` 计数，取最高级）；`systemctl cat authd.service` 的 `ExecStart`（drop-in 要 `ExecStart=` 清空后照抄再加 `$MASTERSOS_DIAG_AUTHD_ARGS`）；
  在 NM `level=DEBUG` 下 `busctl get-property fi.w1.wpa_supplicant1 /fi/w1/wpa_supplicant1 fi.w1.wpa_supplicant1 DebugLevel` 是否已是 `debug`；
  `/etc/gdm3/custom.conf` 原样内容（拷一份作测试夹具，去掉任何学校信息）。
- [ ] **Step 2: 写失败测试** `diag-setup-test.sh`（照 `health-check-test.sh` 的写法，`MASTERSOS_DIAG_ROOT=$tmp`）：
  - `switch_off_writes_nothing`：无标记 → `run/mastersos/diag.env`、NM drop-in 都不存在，`custom.conf` 字节不变。
  - `switch_on_writes_env_and_nm`：有标记 → 两个文件内容与上面 Interfaces 一致。
  - `gdm_enable_from_package_conf`：用夹具 `custom.conf`（`#Enable=true` 被注释）→ 之后 `[debug]` 段恰有一行 `Enable=true`；再跑一遍仍只一行（幂等）。
  - `gdm_no_debug_section`：`custom.conf` 无 `[debug]` → 追加 `[debug]` 与 `Enable=true`；文件不存在 → 新建。
  - `symlink_switch_is_off`：标记是符号链接 → 当作关闭。
- [ ] **Step 3:** `bash image/tests/diag-setup-test.sh`（容器内）→ 失败。
- [ ] **Step 4: 实现** `diag-setup`：`main` 只在 `[ -f ] && [ ! -L ]` 时动作；写文件先临时名再 `mv`。若 Step 1 发现 NM 不会自己同步 wpa_supplicant 级别，则在 env 之外再装一个 `mastersos-diag-wpa.service`（`After=wpa_supplicant.service NetworkManager.service`，`ConditionPathExists=/run/mastersos/diag.env`，`busctl set-property ... DebugLevel s debug`），否则不加。
  `mastersos-diag-setup.service`：`Type=oneshot`、`DefaultDependencies=no`、`RequiresMountsFor=/var/lib/mastersos-seed`、`After=local-fs.target`、
  `Before=sysinit.target NetworkManager.service gdm.service authd.service authd-oidc.service mastersos-agent.service mastersos-agent-local.service`。
  各 drop-in：`[Unit] After=mastersos-diag-setup.service` + `[Service] EnvironmentFile=-/run/mastersos/diag.env`。
- [ ] **Step 5:** 测试全过；`shellcheck -x` 新脚本与测试无警告。
- [ ] **Step 6:** 提交 `feat(image): 诊断开关打开时各组件开调试日志`

### Task 4: 插 U 盘导出诊断包

**Files:**
- Create: `image/mkosi.extra/usr/lib/mastersos/diag-export`
- Create: `image/mkosi.extra/usr/lib/systemd/system/mastersos-diag-export@.service`
- Create: `image/mkosi.extra/usr/lib/udev/rules.d/91-mastersos-diag.rules`
- Test: `image/tests/diag-export-test.sh`

**Interfaces:**
- Consumes: 开关路径（Global Constraints）。
- Produces（供测试 source 的函数，路径都经 `MASTERSOS_DIAG_ROOT` 前缀）：
  `diag_enabled` → 0/1；
  `run_cmd <out-name> <cmd...>`：输出写 `$staging/<out-name>`，在 `$staging/commands.txt` 追加 `<out-name> <rc|missing|timeout>`，限时 `${DIAG_CMD_TIMEOUT:-20}` 秒；
  `pick_name <dir> <machine8> <stamp>` → 不冲突的文件名（`…-2`、`-3`）；
  `pack <staging> <dest-dir> <name>`：`tar --zstd` 写 `<name>.partial`，`sync` 后 `mv` 成 `<name>`；失败时删 `.partial` 并返回非 0；
  `main <kernel-device-name>`。

- [ ] **Step 1: 写失败测试**（`PATH` 前置一个放假命令的目录，假 `mount`/`umount` 只记录调用）：
  - `switch_off_no_mount`：无标记 → `main sdb1` 退出 0，假 `mount` 没被调用，目标目录无文件。
  - `collect_timeout`：假 `nmcli` `sleep 5`，`DIAG_CMD_TIMEOUT=1` → `commands.txt` 有 `nmcli-device.txt timeout`，后续命令照常有记录。
  - `collect_missing`：`iw` 不在 PATH → 记 `missing`。
  - `name_collision`：目录里已有 `mastersos-diag-abcd1234-19700101T000000Z.tar.zst` → `pick_name` 返回 `…-2.tar.zst`。
  - `pack_failure`：目标目录只读 → `pack` 返回非 0，目录里没有 `<name>` 也没有 `<name>.partial`。
  - `staging_cleanup`：`main` 在收集中收到 TERM → staging 目录与挂载点不在，假 `umount` 被调用。
  - `full_export`：开关在、假命令都成功 → 目标目录恰有一个 `.tar.zst`，`tar --zstd -tf` 列出 `commands.txt`、`journal/boot-0.txt`、`seed/seed.toml`、`etc/NetworkManager/`。
- [ ] **Step 2:** 容器内 `bash image/tests/diag-export-test.sh` → 失败。
- [ ] **Step 3: 实现 `diag-export`。** staging 用 `mktemp -d /var/tmp/mastersos-diag.XXXXXX`（放在根分区，不占 `/run`）。收集清单就是 spec「包内容」一节，逐条 `run_cmd`；journal 取 `journalctl --list-boots` 里最近 5 次，每次 `journalctl -b <n> -o short-precise --no-pager > journal/boot-<n>.txt`，另加 `journalctl -k -b 0`；`coredumpctl info` 对 list 里每个 PID；文件类（`/var/lib/mastersos`、`/var/lib/mastersos-seed`、`/etc/NetworkManager`、`/etc/gdm3`、`/etc/polkit-1`、`/etc/authd`、ESP 的 `EFI/MastersOS/`）用 `cp -a --no-preserve=ownership` 拷进 staging 对应路径，ESP 用 `bootctl --print-esp-path` 找。`trap` 在 EXIT/TERM 上删 staging、卸载、删挂载点。结束前 `logger -t mastersos-diag-export` 记结果与文件名。
- [ ] **Step 4: 单元与规则。**
  service：`[Unit] BindsTo=dev-%i.device After=dev-%i.device mastersos-diag-setup.service` / `[Service] Type=oneshot ExecStart=/usr/lib/mastersos/diag-export %i TimeoutStartSec=15min`。
  rules：
  ```
  ACTION=="add", SUBSYSTEM=="block", ENV{ID_BUS}=="usb", ENV{ID_FS_TYPE}=="vfat|exfat", TEST=="/var/lib/mastersos-seed/debug.conf", ENV{UDISKS_IGNORE}="1", TAG+="systemd", ENV{SYSTEMD_WANTS}+="mastersos-diag-export@%k.service"
  ```
  （`UDISKS_IGNORE` 只在开关在的机器上生效，免得 GNOME 同时挂载同一块盘。）
- [ ] **Step 5:** 测试全过；shellcheck 无警告。
- [ ] **Step 6:** 提交 `feat(image): 诊断开关打开时插 U 盘自动导出诊断包`

### Task 5: 接入 CI 并真机验收

**Files:**
- Modify: `.github/workflows/mastersos.yml`（shellcheck 列表加 `diag-setup`、`diag-export`；新增 `run: bash image/tests/diag-setup-test.sh`、`run: bash image/tests/diag-export-test.sh`）
- Modify: `image/tests/check-tree.sh`（若它枚举 `usr/lib/mastersos` 下的脚本或单元，照现有规则把新文件加进去；跑一遍看是否报错）
- Modify: `image/mkosi.conf`（若镜像缺 `iw`、`pciutils`、`usbutils`、`libinput-tools`，加进包清单，每个一行英文注释说明用途）

- [ ] **Step 1:** 容器内跑 `bash image/tests/check-tree.sh` 与两个新测试 → 全过。
- [ ] **Step 2:** 提交 `ci: 诊断模式的测试与静态检查`，推分支，开 PR，等 CI 绿。
- [ ] **Step 3: lab 镜像 VM 验收**（构建机 VM 121，装到 VM122，安装 U 盘镜像 seed 旁放 `debug.conf`）：
  - 装完 `ls -l /var/lib/mastersos-seed/debug.conf` → 空文件；`cat /run/mastersos/diag.env` 有两行；`journalctl -u NetworkManager -b` 有 `<debug>` 行；`busctl get-property … DebugLevel` → `"debug"`，`DebugShowKeys` → `false`。
  - 停在登录页、无人登录，给 VM 热插一个 vfat 的 USB 盘镜像，再插一个 exfat 的 → 各得一个 `.tar.zst`，解开能看到上面 `full_export` 列出的内容和 GDM 的 debug 行。
  - 不带 `debug.conf` 重装 → 插盘后盘上无新文件，GNOME 照常能挂载 U 盘。
  - 截图按编号保留，汇报列路径。
- [ ] **Step 4:** 把验收结果写进 PR 描述（不贴诊断包内容）。
