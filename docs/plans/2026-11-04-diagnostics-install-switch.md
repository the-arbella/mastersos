# 诊断开关改为安装时按 d、导出到安装盘的 seed 目录 实施计划

> 已被 docs/specs/2026-11-05-remote-diagnostics-and-help-design.md 取代，U 盘诊断已删除。

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 去掉 U 盘上的 `debug.conf`；安装器开头 1 秒内收到含 d 的输入即 debug 安装，首次开机把开关移进加密根分区；导出只写到 U 盘上 seed 所在目录（根目录与往下两层）。

**Architecture:** 安装器 `main` 在 `run_install` 之前调 `tty::sniff_debug`，结果经 `InstallEnv.debug` 进入流程：确认屏多一行、`SEED_DIR` 里写 `debug-install`。
`mastersos-diag-adopt.service`（`ConditionFirstBoot=yes`）把标记变成 `/var/lib/mastersos-diag/enabled`；`diag-setup` 每次开机删掉种子分区上残留的标记并以新路径为开关。
`diag-export` 按 `blkid` 类型挂载（`nosymfollow`），找 seed 目录，没有就不写。

**Tech Stack:** Rust（installer，rustix termios），bash，systemd，udev。

**Spec:** `docs/specs/2026-11-03-diagnostics-design.md`（2026-11-04 修订）

## Global Constraints

- 开关：`/var/lib/mastersos-diag/enabled`（普通文件，不跟随符号链接）。种子分区标记：`/var/lib/mastersos-seed/debug-install`。安装器标记名 `debug-install`。
- 窗口：1 秒；输入含 `d` 或 `D` 即 debug；之后 `tcflush` 并等连续 0.5 秒无输入（最多 10 秒）。窗口期间不显示任何东西。
- 确认屏行：`Developer diagnostics: ON`（只在 debug 时）。
- 导出：只挂 `blkid -p` 报 `vfat` 或 `exfat` 的分区，`mount -t <type> -o nosuid,nodev,noexec,nosymfollow`；seed 文件名 `seed.toml` / `seed-*.toml`（不分大小写），深度：分区根、往下一层、往下两层；取最浅，同层按路径排序第一个；目录是符号链接不用。
- 注释与输出英文；提交信息中文；提交前 `python3 -I tools/check-private.py`。

## Review Focus

1. **按住 d 的字符落进后续提示**（选盘、确认 `y`）→ 窗口后清缓冲并等按键松开。测试：Task 1 `quiet_wait_drops_held_keys` 不可单测（真 tty），改在 VM 验收里按住 d 装一次，确认屏照常等输入。
2. **窗口在没有 tty 时（测试、管道）** → 返回 false，不报错。测试：Task 1 `sniff_without_tty_is_off`。
3. **装好后往种子分区放 `debug-install`** → 不打开、被删掉。测试：Task 2 `planted_marker_removed_not_adopted`。
4. **U 盘上 seed 在第三层或通过符号链接目录才可达** → 不写。测试：Task 3 `seed_too_deep`、`seed_behind_symlink`。
5. **blkid 报 ext4 等其它类型** → 不挂载。测试：Task 3 `other_fs_not_mounted`。

---

### Task 1: 安装器的 1 秒窗口与标记

**Files:** Modify `core/mastersos-installer/src/tty.rs`、`seed.rs`、`plan.rs`（`confirm_text`）、`lib.rs`、`main.rs`；Test `core/mastersos-installer/tests/decisions.rs`

**Interfaces:**
- Produces: `tty::has_debug_key(input: &[u8]) -> bool`；`tty::sniff_debug() -> bool`（真 tty：raw、无回显、`VMIN=0 VTIME=1` 读 1 秒，再等安静，`tcflush`，恢复 termios；不是 tty 返回 false）；
  `seed::DEBUG_MARKER = "debug-install"`、`seed::write_debug_marker(dir: &Path) -> Result<()>`（空文件 0644）；
  `plan::confirm_text(target, seed, debug: bool) -> String`；`InstallEnv.debug: bool`；`run_install(r, tty, sysfs, dev, debug: bool)`。
- 删掉第一版的 `DEBUG_FLAG`、`debug_flag_present`、`write_debug_flag` 与它们的测试。

- [ ] Step 1: 测试（RED）：`has_debug_key_cases`（`b"d"`、`b"dddd"`、`b"ssssdraf"`、`b"D"` → true；`b""`、`b"sss\n"` → false）；`sniff_without_tty_is_off`（stdin 不是 tty 时 `sniff_debug() == false`，用 `/dev/null` 重定向不可行就在函数里先 `tcgetattr` 判定，测试直接调用：cargo test 的 stdin 不是 tty）；`write_debug_marker_writes_empty_file`；`confirm_shows_diagnostics_only_when_debug`（`true` 含 `Developer diagnostics: ON`，`false` 不含）；`debug_install_writes_marker`（`install()` 辅助加 debug 参数，完整成功流程后 `SEED_DIR` 的替身目录里有 `debug-install`——若 `SEED_DIR` 是常量路径不可替换，则只测 `write_debug_marker` 并在 lib 调用处保持一行）。
- [ ] Step 2: 远程测试机或 `LOCAL_OK=1 cargo test -p mastersos-installer` → 编译失败。
- [ ] Step 3: 实现；`main.rs` 在建 `RealTty` 之前 `let debug = tty::sniff_debug();`，传给 `run_install`。
- [ ] Step 4: fmt/clippy/test 全过（远程测试机跑 core）。
- [ ] Step 5: 提交 `feat(installer): 开头 1 秒按 d 即诊断安装，确认屏标出`

### Task 2: 首次开机收进加密根分区；残留标记删掉

**Files:** Modify `image/mkosi.extra/usr/lib/mastersos/diag-setup`、`mastersos-diag-setup.service`、各 `90-mastersos-diag.conf` 的注释；Create `mastersos-diag-adopt.service` 与 `sysinit.target.wants/` 链接；Test `image/tests/diag-setup-test.sh`

**Interfaces:**
- `diag-setup adopt`：种子分区标记是普通文件 → `mkdir -m 0700 -p /var/lib/mastersos-diag`、建 `enabled`、删标记。
- `diag-setup`（无参数）：种子分区还有标记 → 删、打一行 `warning`；之后开关看 `/var/lib/mastersos-diag/enabled`，其余照旧。
- `mastersos-diag-adopt.service`：`ConditionFirstBoot=yes`、`DefaultDependencies=no`、`RequiresMountsFor=/var/lib/mastersos-seed`、`After=local-fs.target`、`Before=mastersos-diag-setup.service first-boot-complete.target sysinit.target`。

- [ ] Step 1: 测试（RED）：已有用例改用新开关路径；新增 `adopt_moves_marker`、`adopt_without_marker_noop`、`adopt_symlink_marker_ignored`（不建开关、不跟随）、`planted_marker_removed_not_adopted`（无参数运行：标记被删、`enabled` 不存在、无 `diag.env`）。
- [ ] Step 2: 容器内运行 → 失败。
- [ ] Step 3: 实现脚本与单元。
- [ ] Step 4: 测试全过；shellcheck。
- [ ] Step 5: 提交 `fix(image): 诊断开关首次开机收进加密根分区，种子分区上的标记不再认`

### Task 3: 导出只写到安装盘的 seed 目录

**Files:** Modify `image/mkosi.extra/usr/lib/mastersos/diag-export`、`image/mkosi.extra/usr/lib/udev/rules.d/91-mastersos-diag.rules`、`mastersos-diag-export@.service` 注释；Test `image/tests/diag-export-test.sh`

**Interfaces:**
- `find_seed_dir <mnt>` → 打印 seed 所在目录（绝对路径），找不到返回 1。
- `fs_type <dev>` → `blkid -p -o value -s TYPE`。
- `main`：开关不在 → 退出；类型不是 vfat/exfat → 退出、不挂载；挂载后 `find_seed_dir` 失败 → 卸载、退出 0、不写；成功 → 照旧打包到该目录。

- [ ] Step 1: 测试（RED）：假 `blkid`；已有用例改用新开关路径并在“盘”上放 seed；新增 `seed_at_root`、`seed_one_level`、`seed_two_levels`、`seed_too_deep`（三层 → 不写）、`seed_shallowest_wins`、`seed_behind_symlink`（目录是链接 → 不写）、`no_seed_no_write`、`other_fs_not_mounted`（blkid 报 ext4 → 假 mount 没被调用）、`mount_options`（含 `-t vfat` 与 `nosymfollow`）。
- [ ] Step 2: 容器内运行 → 失败。
- [ ] Step 3: 实现；udev 规则 `TEST==` 改为 `/var/lib/mastersos-diag/enabled`。
- [ ] Step 4: 测试全过；shellcheck；容器内 check-tree 全过。
- [ ] Step 5: 提交 `fix(image): 诊断包只写进安装盘 seed 所在的目录，按探到的类型挂载`

### Task 4: 合并前验证

- [ ] Step 1: core 套件、容器内三个 shell 测试与 check-tree 全过。
- [ ] Step 2: 整个分支交给一个新的审阅代理；Critical/Important 一次修完。
- [ ] Step 3: 推送分支开 PR，CI 绿后合并（用户已说“推进”）。VM 验收（按住 d 装机、插安装盘导出、往种子分区放标记不生效）在下一版 lab 镜像上做，结果补进 PR。
