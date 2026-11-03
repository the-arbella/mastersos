# 设置在客户端编辑（公开库部分）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `mastersos` 命令行在本地目录里编辑设置（`init`、`pull`、`check`、`diff`、`publish`），秘密拆到 `secrets.toml`，MCP 只在本地目录上工作。

**Architecture:** 秘密引用与补字段是纯函数，放进 `mastersos-bundle`；本地目录与命令在 `mastersos-mcp` crate（二进制 `mastersos`）；验链与签名复用 `mastersos-sign` 库。服务端接口 `POST /v1/admin/publish/pending` 由云端计划实现，本计划只按约定调用它。

**Tech Stack:** Rust（`toml_edit`、`clap`、`reqwest`、`rmcp`），现有 crate。

**Spec:** `docs/specs/2026-11-03-client-config-design.md`

## Global Constraints

- 代码注释与输出用英文；提交信息 `<type>(<scope>): <中文说明>`。
- 公开库不依赖云端仓库；端到端测试在云端仓库的 `integration/`（云端计划），本计划只写不联网的单元测试。
- 秘密引用语法：字符串值 `"secret:<name>"`；`<name>` 为 `[a-z0-9-]{1,64}`。
- 秘密字段：`Wifi::SECRET_FIELDS` 与 `ItAccount::SECRET_FIELDS`（`mastersos-bundle/src/manifest.rs`），所在层：`[defaults]`、每个 `[[config]]`、旧的 `[[group]]` 的 `wifi` 与 `it_account`。
- 改道相关字段：`eap`、`phase2`、`identity`、`anonymous_identity`、`server_domain`、`ca_cert`、`check_server`。
- `secrets.toml` 权限 0600；`pull`/`init` 写 `.gitignore`，含 `secrets.toml` 与 `.mastersos/`。
- `mastersos` 的 token 仍只许 `read`、`draft` 范围。
- 签名页链接：`<signing_origin>/#school=<slug>&sid=<school id>&op=commit&pending=<id>`（`signing_origin`、`slug`、`school_id` 来自 `GET /v1/auth/config`）。
- 上传体（与云端计划约定）：`POST /v1/admin/publish/pending`，JSON `{"manifest_text": String, "files": {"<path>": "<标准 base64>"}}`；成功 200 返回与今天 `GET /v1/admin/publish/pending/{id}` 相同的 `Prepared` JSON（含 `pending_id`、`version`、`digest`、`lints`）；版本冲突 409 `version_conflict`；检查不过 422 `lint_failed`（`lints` 数组）或 `draft_invalid`。

## Review Focus

- `manifest.toml` 里注释与排版在 `pull` → 编辑 → `publish` 之后保留（`toml_edit`）。→ Task 1 测试 `split_keeps_comments`。
- 同一层两个 SSID 只差大小写或符号时，自动生成的秘密名不冲突。→ Task 1 测试 `names_unique_when_ssids_collide`。
- 目录里有未发布的改动时 `pull` 不覆盖。→ Task 3 测试 `pull_refuses_dirty_dir`。
- 有人在 base 之后发布：`publish` 得 409，本地 `base_version` 不变，提示重新 pull。→ Task 4 测试 `publish_conflict_keeps_base`。
- MCP 的任何输出里出现不了秘密的值，即使 AI 让 `diff` 去比一个改了秘密的目录。→ Task 5 测试 `diff_never_prints_secret_values`。

---

### Task 1: 秘密的拆分、填回与检查（`mastersos-bundle`）

**Files:**
- Create: `core/mastersos-bundle/src/secret_ref.rs`
- Modify: `core/mastersos-bundle/src/lib.rs`（`pub mod secret_ref;`）

**Interfaces:**
- Produces:
  - `pub fn split(manifest_text: &str) -> Result<(String, BTreeMap<String, String>), BundleError>`：把每个秘密字段的值换成 `"secret:<name>"`，返回新文本与 `name → value`。已经是引用的保持不变。名字：`<层>-<ssid 小写，非 [a-z0-9] 换成 ->-<字段>`，层是 `defaults`、config id 或 `group-<id>`；IT 账号是 `<层>-it-account`；冲突时追加 `-2`、`-3`。
  - `pub fn fill(manifest_text: &str, secrets: &BTreeMap<String, String>) -> Result<String, Vec<Lint>>`：引用换成值；有引用找不到名字时返回 `secret_unknown`（Error）。
  - `pub fn lints(manifest_text: &str, secrets: &BTreeMap<String, String>, base_text: Option<&str>) -> Vec<Lint>`：`secret_unknown`（Error）、`secret_unused`（Warning）、`secret_rerouted`（Warning：同名引用所在网络的改道字段与 base 不同）。

遍历各层的方式照搬云端 `secrets.rs` 的 `mask_toml` 那一段（同样的层、同样的字段），用 `toml_edit` 原地改值。

- [ ] **Step 1: 写失败的测试**（`secret_ref.rs` 里的 `#[cfg(test)]`）

```rust
#[test] fn split_then_fill_round_trips() { /* defaults 一个 psk 网络 + config "lab" 一个 eap 网络 + it_account；fill(split(t)) == t */ }
#[test] fn split_keeps_comments() { /* 原文的 `# keep me` 注释与空行在 split 后仍在 */ }
#[test] fn names_unique_when_ssids_collide() { /* "Guest!" 与 "guest?" 同层 → "defaults-guest--psk" 与 "defaults-guest--psk-2" 两个不同名字 */ }
#[test] fn fill_reports_unknown() { /* psk = "secret:nope" → Err，含 code "secret_unknown" */ }
#[test] fn lints_unused_and_rerouted() { /* secrets 多一个没被引用 → secret_unused；base 的 server_domain 为 a、现在为 b → secret_rerouted */ }
```

- [ ] **Step 2: 运行，确认失败**：`cd core && cargo test -p mastersos-bundle secret_ref` → 编译失败（模块不存在）。
- [ ] **Step 3: 实现上面三个函数。**
- [ ] **Step 4: 运行，确认通过**：同上命令 → 5 passed。
- [ ] **Step 5: 提交**：`git commit -m "feat(bundle): 设置里的秘密可以拆成引用并在合成时填回"`

### Task 2: 发布前补字段（`mastersos-bundle`）

**Files:**
- Create: `core/mastersos-bundle/src/stamp.rs`
- Modify: `core/mastersos-bundle/src/lib.rs`

**Interfaces:**
- Produces:
  - `pub fn text_format(text: &str) -> u32`（与云端 `draft::text_format` 相同：没有或无效时为 1）
  - `pub fn stamp(text: &str, version: u64, issued_at: &str, school_name: Option<&str>) -> Result<String, BundleError>`（照搬云端 `publish::stamp`）
  - `pub fn school_name_to_write<'a>(text: &str, display_name: &'a str) -> Option<&'a str>`（format 2 且 `checks::school_name` 通过时才写）

- [ ] **Step 1: 写失败的测试**：`stamp_writes_version_and_time`（结果里 `version = 7`、`issued_at = "2026-11-03T00:00:00Z"`，注释保留）、`school_name_only_for_format_2`（format 1 → `None`，format 2 → `Some`）。
- [ ] **Step 2: 运行确认失败**：`cargo test -p mastersos-bundle stamp`。
- [ ] **Step 3: 实现。**
- [ ] **Step 4: 运行确认通过。**
- [ ] **Step 5: 提交**：`feat(bundle): 发布前补 version、issued_at 与学校名的规则搬进公共库`

### Task 3: 本地目录与 `init`、`pull`、`check`、`diff`

**Files:**
- Create: `core/mastersos-mcp/src/workdir.rs`
- Modify: `core/mastersos-mcp/Cargo.toml`（依赖 `mastersos-sign`）、`core/mastersos-mcp/src/cli.rs`
- Create: `core/mastersos-mcp/src/template.toml`（新学校模板，取自云端 `draft::template`：`[school]` 只有 id 的占位、一个 config `standard`、`default` 分组）

**Interfaces:**
- Consumes: Task 1 `split`、`lints`；`mastersos_sign::chain::verify_chain(api, pin_dir, confirm, out) -> Result<Verified>`；`mastersos_sign::Api::from_token_file`。
- Produces:
  - `pub struct Meta { pub server: String, pub school_id: String, pub base_version: u64 }`（`mastersos.toml`）
  - `pub struct Workdir { pub root: PathBuf }`，方法：
    - `fn init(root, meta: Meta, manifest_text: &str) -> Result<Workdir>`
    - `fn write_pulled(root, meta: Meta, contents: &Contents, force: bool) -> Result<Workdir>`（拆秘密，写四样与 `.mastersos/base/`、`.gitignore`）
    - `fn open(root) -> Result<Workdir>`、`fn meta(&self) -> Result<Meta>`
    - `fn manifest(&self) -> Result<String>`、`fn secrets(&self) -> Result<BTreeMap<String,String>>`、`fn files(&self) -> Result<BTreeMap<String,Vec<u8>>>`
    - `fn base(&self) -> Result<(String, BTreeMap<String,String>, BTreeMap<String,Vec<u8>>)>`
    - `fn is_dirty(&self) -> Result<bool>`（与 base 逐字节比较）
    - `fn mark_published(&self, version: u64) -> Result<()>`（`base_version` 更新、当前内容复制成 base）
  - `pub fn check(w: &Workdir) -> Result<Vec<Lint>>`：`Manifest::parse` + `validate`（`version = 0` 补在副本里，同云端草稿检查）+ `lint_at` + Task 1 `lints`
  - `pub fn diff(w: &Workdir) -> Result<String>`：清单文本统一差异、文件增删改列表；秘密只列名字与 `changed`/`added`/`removed`

CLI：`mastersos init <dir>`（school id 取 `GET /v1/auth/config`，`base_version = 0`）、`mastersos pull [<dir>] [--version N] [--force]`、`mastersos check [<dir>]`（有 Error 时退出码 2）、`mastersos diff [<dir>]`。`pull` 先 `verify_chain`；`--version N` 时再下载 `versions/{N}/archive`，`read_archive` 后用它自己的 trust 验签、且要求 `N <= Verified.latest`。pin 目录 `~/.config/mastersos/pins/`。

- [ ] **Step 1: 写失败的测试**（`workdir.rs`，临时目录）：
  - `pull_writes_split_layout`：`secrets.toml` 权限 0600，`.gitignore` 含 `secrets.toml` 与 `.mastersos/`，`manifest.toml` 不含原 psk 值。
  - `pull_refuses_dirty_dir`：改 `manifest.toml` 后再 `write_pulled(force=false)` → Err，文件未变；`force=true` → Ok。
  - `check_flags_unknown_secret`：引用不存在的名字 → 有 `secret_unknown`。
  - `mark_published_moves_base`：`mark_published(4)` 后 `meta().base_version == 4`、`is_dirty() == false`。
- [ ] **Step 2: 运行确认失败**：`cargo test -p mastersos-mcp workdir`。
- [ ] **Step 3: 实现 `workdir.rs` 与四个子命令。**
- [ ] **Step 4: 运行确认通过。**
- [ ] **Step 5: 提交**：`feat(mastersos): 在本地目录里 init、pull、check、diff 设置`

### Task 4: `publish`、列表与辅助命令；删掉旧命令

**Files:**
- Modify: `core/mastersos-mcp/src/cli.rs`、`core/mastersos-mcp/src/lib.rs`
- Modify: `core/mastersos-sign/src/lib.rs`、`core/mastersos-sign/src/main.rs`（`sign_pending` 的 `pending` 改为必填 `&str`，删掉 prepare 分支；`sign --pending <id>` 必填）

**Interfaces:**
- Consumes: Task 1 `fill`；Task 2 `stamp`、`school_name_to_write`；Task 3 `Workdir`、`check`。
- Produces: `pub async fn publish(api: &Api, w: &Workdir, key: Option<&Path>, now: DateTime<Utc>, confirm, out) -> Result<PublishOutcome>`，`enum PublishOutcome { Published(u64), NeedsPasskey { url: String, pending_id: String } }`。

流程：`check` 有 Error 就停 → `fill` → `stamp(version = base_version + 1, issued_at = now RFC 3339 秒级 Z, school_name_to_write(text, auth_config.name))` → 上传（Global Constraints 的体）→ 409 时报 “Someone published v… after your base v…; run `mastersos pull` and redo your change” 并不改 `base_version` → 有 `--key` 时 `mastersos_sign::sign_pending(api, key, pin_dir, Some(id), …)`，成功后 `mark_published` → 否则返回签名页链接（IT 用 passkey 签完后跑 `mastersos pull` 更新 base）。

另加：`mastersos device list|show`（保留现有实现）、`mastersos keys list`（`GET /v1/admin/keys`，打印 id、算法、标签）、`mastersos hash-password`（不回显读两次，输出 IT 账号口令哈希，算法与网页现在用的相同——看云端 `api/configs.rs` 的 IT 账号接口怎么算），`mastersos logo upload <login.png> <icon.png>`（尺寸核对：登录页高 96、宽 1–480，图标 40×40；上传到现有 logo 接口，打印两个 sha256）。

删除：`draft`、`config`、`group`、`school`、`defaults`、`publish`（旧的发布请求）、`requests` 子命令，`devices assign`，`write_manifest`、`restore_version`、`draft_rev`、`check_before_write`、`guard_manifest`。

- [ ] **Step 1: 写失败的测试**（`lib.rs`，用 `wiremock` 或现有测试里假服务器的做法；没有就加 `wiremock` 为 dev-dependency）：
  - `publish_uploads_stamped_contents`：上传体的 `manifest_text` 含 `version = 5`（base 4）与填回的 psk 值，`files` 是 base64。
  - `publish_conflict_keeps_base`：假服务器回 409 `version_conflict` → Err 信息含 `mastersos pull`，`base_version` 仍是 4。
  - `publish_stops_on_check_error`：有 `secret_unknown` → 不发请求。
  - `publish_without_key_returns_sign_link`：返回的 URL 等于 `https://sign.example/#school=demo&sid=<id>&op=commit&pending=<id>`。
- [ ] **Step 2: 运行确认失败**：`cargo test -p mastersos-mcp publish_`。
- [ ] **Step 3: 实现并删除旧命令；`mastersos-sign` 的改动一起做。**
- [ ] **Step 4: 运行**：`cargo test -p mastersos-mcp -p mastersos-sign -p mastersos-bundle` → 全部通过；`cargo clippy --workspace -- -D warnings` 无告警。
- [ ] **Step 5: 提交**：`feat(mastersos): publish 在本地合成、上传待签名包并签名；删掉服务端草稿的命令`

### Task 5: MCP 工具改到本地目录

**Files:**
- Modify: `core/mastersos-mcp/src/tools.rs`、`core/mastersos-mcp/src/lib.rs`

**Interfaces:**
- Consumes: Task 3 `Workdir`、`check`、`diff`。
- Produces: MCP 工具（`mastersos mcp --dir <dir>`）：`read_manifest`、`list_files`、`read_file`（拒绝 `secrets.toml` 与 `.mastersos/` 下的路径）、`check`、`diff`、`devices_list`、`device_show`、`keys_list`、`spec`。不提供写、合成、上传、签名。

- [ ] **Step 1: 写失败的测试**：
  - `read_file_refuses_secrets`：`read_file("secrets.toml")`、`read_file("../secrets.toml")`、`read_file(".mastersos/base/secrets.toml")` 都 Err。
  - `diff_never_prints_secret_values`：把 `secrets.toml` 里一个值从 `oldpass1` 改为 `newpass2`，`call("diff")` 的输出不含 `oldpass1` 与 `newpass2`，含秘密名与 `changed`。
  - `tool_list_is_read_only`：`mcp_tools()` 的名字集合正好是上面 9 个。
- [ ] **Step 2: 运行确认失败。**
- [ ] **Step 3: 实现。**
- [ ] **Step 4: 运行确认通过。**
- [ ] **Step 5: 提交**：`feat(mcp): MCP 只读本地设置目录，不碰秘密`

### Task 6: 技能与文档

**Files:**
- Modify: `skills/mastersos-admin/`（SKILL.md 与引用文件）、`README.md` 里 `mastersos` 的用法段

- [ ] **Step 1:** 技能改成：在 IT 给的本地目录里直接编辑 `manifest.toml`、跑 `mastersos check` 与 `diff`；不读 `secrets.toml`，不读合成出的包；新密码网络写 `psk = "secret:<name>"` 并告诉 IT 用 `secrets.toml` 填值；改完请 IT `mastersos publish`。删掉一切“服务端草稿、rev、发布请求”的说法。
- [ ] **Step 2:** README：`init`/`pull` → 编辑 → `check`/`diff` → `publish`（恢复钥匙或签名页）的五行示例。
- [ ] **Step 3:** `grep -rn "draft put\|publish request\|requests list\|/v1/admin/draft" skills README.md docs --include=*.md` 只剩设计文档里的历史说明。
- [ ] **Step 4: 提交**：`docs(mastersos): 技能与 README 改成本地目录的流程`
