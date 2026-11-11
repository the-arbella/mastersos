# 锁定应用的托管设备接口（navigator.managed）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 写了 `device_attributes` / `managed_config` 的网页锁定应用，页面在 `navigator.managed` 上看到与 ChromeOS kiosk 相同的设备属性与托管配置。

**Architecture:** 设置格式加四个键（锁定应用两个、`[[device]]` 两个）与三个 feature；agent 在已有的平台扩展里多放一个 MAIN 世界脚本
`managed.js`，值由 agent 生成时嵌进脚本的标记行；脚本只动 `NavigatorManagedData.prototype`，行为与报错照 Chromium 源码。

**Tech Stack:** Rust（`mastersos-bundle`、`mastersos-agent`）、MV3 扩展的 JS、vitest + jsdom（仓库外装）。

**Spec:** `docs/specs/2026-11-10-kiosk-managed-apis-design.md`（下称「设计」）；它接在 `docs/specs/2026-11-06-kiosk-platform-inject-design.md`（「伪装设计」）之后。

## Global Constraints

- 注释、错误、脚本输出用英文；提交信息用中文；路径用英文。本仓库公开：不放主机、账号、学校数据、钥匙。提交前跑 `python3 -I tools/check-private.py`。
- 新键：锁定应用 `device_attributes`（布尔，缺省 `false`）、`managed_config`（`files/<名>.json`）；`[[device]]` 的 `asset_id`、`location`（可选字符串，1–128 个字符，不含控制字符）。
- `managed_config` 文件：UTF-8、JSON、顶层是对象、至多 64 KiB（`64 * 1024` 字节）。
- 新 feature 字符串：`kiosk_device_attributes`、`kiosk_managed_config`、`device_annotations`。
- 新 issue code：`kiosk_device_attributes_invalid`、`kiosk_managed_config_invalid`、`device_annotation_invalid`。
- 两个应用键只用于 `url` 应用、不与 `pwa = true` 同时写（与 `platform`、`inject` 同一规则）。
- 报错文案（照 Chromium，一字不改）：
  - `NotAllowedError` `"This API is allowed only in top level frames."`
  - `NotAllowedError` `"Permissions-Policy: device-attributes are disabled."`
  - `UnknownError` `"The current origin cannot use this web API because it was not granted the 'device-attributes' permission."`
  - `NotAllowedError` `"Managed configuration is empty. This API is available only for managed apps."`
- 设备属性没有值时 resolve `null`（不是 `undefined`）。所有方法前置检查不过时返回被 reject 的 Promise，不同步抛出。
- 底线：不伪造任何令牌或设备证明；`managed.js` 不留这种入口。
- Rust 在 Mac 上编不了 agent：cargo 在 Linux 构建机上跑。命令同 CLAUDE.md：
  `cd core && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`。
- JS 测试：仓库不带 JS 依赖。在仓库外（scratchpad）的目录里装 `vitest` 与 `jsdom`，写配置：root 指向 `kiosk-extension/`、
  `environment: "jsdom"`、`globals: true`、`include: ["tests/**/*.test.js"]`、cacheDir 在仓库外；跑
  `vitest run --no-experimental.fsModuleCache --config <配置>`（见 `kiosk-extension/README.md`「测试」）。

## 裁定（写计划时定的，设计没说死的地方）

- **什么时候放 `managed.js`、放哪些方法：** 平台扩展里有 `managed.js` 当且仅当 `platform`、`device_attributes`、`managed_config` 任一写了
  （只写 `inject` 的应用不放：页面看到的就是 Linux 上原样的 Chrome）。
  - 五个设备属性方法：在 `platform = "chromeos"` 或 `device_attributes = true` 时补上（像 ChromeOS 的 kiosk）。没开 `device_attributes` 时
    reject `UnknownError`（设计 §3.1）。
  - `getManagedConfiguration`：只在写了 `managed_config` 时替换；没写就留着 Chrome 原生的（它本来就 reject 那句 `NotAllowedError`）。
- **嵌值的标记行：** `managed.js` 里一行 `// @@MASTERSOS_MANAGED@@`，agent 换成 `const DATA = <JSON 字面量>;`。`DATA` 的形状：
  `{"v":1,"device_methods":bool,"device":{asset_id,location,directory_id,hostname,serial}|缺省,"managed":{…}|缺省}`；`device`
  只在 `device_attributes = true` 时有，五项都在、没有值的写 `null`。
- **主机名：** `<root>/etc/hostname` 的第一行去空白；读不到或为空就是 `null`。
- **ApplyContext 带上设备：** `Selection` 与 `ApplyContext` 各加 `device: Option<&DeviceEntry>`（命中的 `[[device]]`），`ApplyContext`
  再加 `ident: &DeviceIdent`。

## Review Focus

1. 页面在子框架里（考试题目常放在 iframe）调设备属性：reject「only in top level frames」，不能拿到值。→ Task 3 的测试。
2. 页面改了 `getManagedConfiguration` 拿到的对象，再调一次：拿到的是原样（每次新拷贝）。→ Task 3。
3. 托管配置里有 `</script>`、U+2028 这类字符：嵌进 `managed.js` 后脚本仍能解析，值原样。→ Task 4。
4. 改了某台设备的 `asset_id` 或托管配置文件：下一轮平台扩展重新打包（`source.sha256` 变）。→ Task 4。
5. 只写 `inject` 的旧应用：平台扩展与以前一字节不差（摘要不变），不多出 `managed.js`（写了 `platform` 的应用按裁定多出 `managed.js`，重打包一次）。→ Task 4。

---

### Task 1: `[[device]]` 的 `asset_id`、`location`

**Files:**
- Modify: `core/mastersos-bundle/src/manifest.rs`（`DeviceEntry`、feature 常量与收集）
- Modify: `core/mastersos-bundle/src/checks.rs`（新 `device_annotation`）
- Modify: `core/mastersos-bundle/src/lint.rs`（设备循环约 225 行；`feature_path`）
- Modify: `core/mastersos-bundle/src/spec.rs`（`ISSUE_CODES`，按字母序）
- Modify: `core/mastersos-bundle/docs/manifest-spec.md`，并 `cp` 到 `skills/mastersos-admin/reference/settings-reference.md`
- Modify: `core/mastersos-agent/src/report.rs`（agent 报的 feature 列表，约 42 行与 386 行）

**Interfaces:**
- Produces: `DeviceEntry { pub asset_id: Option<String>, pub location: Option<String>, … }`；`pub const FEATURE_DEVICE_ANNOTATIONS: &str = "device_annotations"`；
  `pub fn checks::device_annotation(s: &str) -> Result<(), String>`。

- [ ] **Step 1: 写失败的测试**（`checks.rs`、`lint.rs`、`manifest.rs` 的 tests 模块）

```rust
#[test]
fn device_annotation_rules() {
    assert!(device_annotation("A-1024").is_ok());
    assert!(device_annotation("教学楼 3 层 301").is_ok());
    assert!(device_annotation(&"x".repeat(128)).is_ok());
    assert!(device_annotation("").is_err());
    assert!(device_annotation(&"x".repeat(129)).is_err());
    assert!(device_annotation("a\nb").is_err());
}
// lint: [[device]] 的 asset_id = "a\tb" → 一条 device_annotation_invalid，at "device[0].asset_id"，param device = 序列号
// features: 只写 location 的 [[device]] → 含 "device_annotations"；feature_path 给 "device[<i>].asset_id"（先 asset_id 后 location）
// agent report.rs：报的 feature 里有 "device_annotations"
```

- [ ] **Step 2:** Linux 构建机上跑，确认这些测试失败（编不过或断言失败）。
- [ ] **Step 3: 实现。** 字段带 `#[serde(default, skip_serializing_if = "Option::is_none")]` 与 schemars 描述（英文），不参与选分组。
  `device_annotation` 按字符（`chars().count()`）数，控制字符用 `char::is_control`。issue 的英文消息照现有 lint 的写法。
  manifest-spec：`[[device]]` 表加两行；新 issue code 一节（`### \`device_annotation_invalid\``，含 `check=device_annotation_invalid` 示例块）；
  feature 表加一行。
- [ ] **Step 4:** Linux 构建机上全量（fmt、clippy、test）通过；`spec.rs` 的「每个 code 都有文档」「示例按标注检查」测试通过。
- [ ] **Step 5: 提交** `feat(bundle): [[device]] 加 asset_id 与 location（device_annotations）`

### Task 2: 锁定应用的 `device_attributes`、`managed_config`

**Files:**
- Modify: `core/mastersos-bundle/src/manifest.rs`（`KioskApp` 约 1530 行后；两个 feature 常量与收集）
- Modify: `core/mastersos-bundle/src/kiosk.rs`（`check` 约 340 行；新 `managed_config_path_ok`、`check_managed_config`、`MAX_MANAGED_CONFIG_BYTES`；`uses_start_page`）
- Modify: `core/mastersos-bundle/src/lint.rs`（文件在不在包里，同 `inject` 约 744 行；新 `lint_managed_config_sources`；`feature_path` 约 516 行）
- Modify: `lint_inject_sources` 的每一个调用处（`grep -rn lint_inject_sources core`）旁边加上 `lint_managed_config_sources`
- Modify: `core/mastersos-bundle/src/spec.rs`、`core/mastersos-bundle/docs/manifest-spec.md`（再 `cp` 到 skill）、`core/mastersos-agent/src/report.rs`

**Interfaces:**
- Produces: `KioskApp { pub device_attributes: bool, pub managed_config: Option<String>, … }`；
  `pub const FEATURE_KIOSK_DEVICE_ATTRIBUTES = "kiosk_device_attributes"`、`FEATURE_KIOSK_MANAGED_CONFIG = "kiosk_managed_config"`；
  `pub const MAX_MANAGED_CONFIG_BYTES: usize = 64 * 1024`；
  `pub fn check_managed_config(bytes: &[u8]) -> Result<serde_json::Map<String, serde_json::Value>, String>`（不过时给原因，接在文件名后读成一句英文，同 `check_inject_source`）；
  `pub fn managed_config_path_ok(f: &str) -> bool`（`files/` 下、`.json` 结尾，规则同 `inject_path_ok`）；
  `pub fn lint_managed_config_sources<'a>(m: &Manifest, file: impl Fn(&str) -> Option<&'a [u8]>) -> Vec<Lint>`；
  `uses_start_page(app)` = `platform || inject || device_attributes || managed_config`。

- [ ] **Step 1: 写失败的测试**

```rust
// kiosk::check：device_attributes = true 写在 exec 应用、pwa 应用上 → kiosk_device_attributes_invalid（field "device_attributes"）；
//   device_attributes = false 写在 exec 上 → 不报；managed_config = "files/x.js" / "x.json" / 写在 exec 上 → kiosk_managed_config_invalid
// check_managed_config：br#"{"a":1}"# → Ok(map 含 "a")；br"[1]" → Err；b"{" → Err；[0xff] → Err；
//   恰 64 KiB 的合法对象 → Ok；64 KiB + 1 → Err
// lint：managed_config 指向包里没有的文件 → kiosk_managed_config_invalid at "<层>.apps.kiosk.<id>.managed_config"
// lint_managed_config_sources：顶层是数组的文件 → 一条 kiosk_managed_config_invalid，param file
// uses_start_page：只写 device_attributes = true → true；只写 managed_config → true；都没写 → false
// features：两个新 feature 各自出现；feature_path 指到 ".device_attributes" / ".managed_config"；device_attributes = false 不算用到
// report.rs：agent 报两个新 feature
```

- [ ] **Step 2:** Linux 构建机上确认失败。
- [ ] **Step 3: 实现。** `device_attributes` 用 `#[serde(default, skip_serializing_if = "is_false")]`。manifest-spec：锁定应用表加两行
  （`managed_config` 一行写明 **No secrets**：每台设备上 0644、所有账号可读，同 `inject`；`device_attributes` 一行写明开了以后序列号、
  资产编号、位置、设备 id 对应用的网站可见、对本机账号可读），两个 issue code 小节带示例，feature 表两行，并给一个 `check=ok` 示例
  （TestNav 应用写 `device_attributes = true` 与 `managed_config`，`files=` 标注带上 JSON 文件）。
- [ ] **Step 4:** Linux 构建机上全量通过。
- [ ] **Step 5: 提交** `feat(bundle): 锁定应用加 device_attributes 与 managed_config`

### Task 3: `kiosk-platform/managed.js` 与 JS 测试

**Files:**
- Create: `kiosk-platform/managed.js`
- Create: `kiosk-extension/tests/platform-managed.test.js`
- Modify: `kiosk-extension/README.md`（测试表里提到新测试）

**Interfaces:**
- Consumes: 上面「裁定」里的 `DATA` 形状与标记行 `// @@MASTERSOS_MANAGED@@`（文件里恰有一行，独占一行，以 `\n` 结尾）。
- Produces: `managed.js`（Task 4 用 `include_str!` 编进 agent，并把标记行换成 `const DATA = …;`）。

- [ ] **Step 1: 写失败的测试。** 跑法同 `platform-chromeos.test.js`：每个用例新开 JSDOM（`url: "https://home.testnav.com/"`），先放进
  Chrome 的形状——`class NavigatorManagedData extends EventTarget`，原型上有一个像原生的 `getManagedConfiguration`（reject
  `NotAllowedError` 那句），`Navigator.prototype.managed` 的 getter 返回同一个实例——再把源码的标记行换成 `const DATA = ${JSON.stringify(data)};` 运行。用例：
  - 五个方法：`device` 有值 → resolve 那个字符串；值为 `null` → resolve `null`；`device_methods` 为 true 但没有 `device` → reject，`name === "UnknownError"`，`message` 为那句。
  - 子框架（让 `window.top !== window`）→ reject `NotAllowedError` / 「only in top level frames」。
  - `document.featurePolicy` 存在、`features()` 含 `"device-attributes"`、`allowsFeature` 回 false → reject「Permissions-Policy…」；`features()` 不含它 → 当允许。
  - `getManagedConfiguration(["a","zzz"])` 在 `managed = {a:{b:1}, c:2}` 时 resolve `{a:{b:1}}`；改了结果再调，第二次仍是 `{a:{b:1}}`；
    没有 `managed` → 原生那个没被换掉（`=== ` 先前存下的函数）；有 `managed` 时无参调用 / 传 `5` → reject `TypeError`。
  - 每个方法前置检查不过时返回 Promise（`instanceof Promise`），不同步抛；`this` 不是 `NavigatorManagedData` → reject `TypeError`。
  - `length`：`getManagedConfiguration` 为 1，其余为 0；属性描述符 `writable/enumerable/configurable` 都是 `true`；`Function.prototype.toString.call(fn)`
    是 `function <名>() { [native code] }`。
  - `device_methods` 为 false → 五个方法不出现在原型上。
  - 没有 `NavigatorManagedData` 或 `navigator.managed` / `window.isSecureContext === false` → 什么都不改，不抛。
  - 源码里没有 CJK 字符（同 `content.test.js` 的检查）。
- [ ] **Step 2:** 跑 vitest，确认新测试失败（文件不存在）。
- [ ] **Step 3: 实现 `managed.js`。** 结构仿 `chromeos.js`：IIFE、`Symbol.for("mastersos.platform.managed")` 防重入、开头注释（英文）
  说明出处（设计 §1、§4）与底线。「像原生」的 `toString` 做法照 `chromeos.js`（在本文件里各留一份，不跨文件共享）。
  `DOMException` 用页面的构造函数在脚本开头捕获。`keys` 按 WebIDL sequence 转：`null`/非对象或没有 `Symbol.iterator` → `TypeError`，每项 `String(x)`。
  结果用 `JSON.parse(JSON.stringify(v))` 拷贝（值来自 JSON，拷贝无损）。
- [ ] **Step 4:** vitest 全部通过（含原有测试）。
- [ ] **Step 5: 提交** `feat(kiosk-platform): managed.js，navigator.managed 的设备属性与托管配置`

### Task 4: agent 生成带 `managed.js` 的平台扩展

**Files:**
- Modify: `core/mastersos-bundle/src/kiosk.rs`（新 `DeviceValues`、`managed_values`）
- Modify: `core/mastersos-bundle/src/select.rs`（`Selection.device`）
- Modify: `core/mastersos-agent/src/apply.rs`（`ApplyContext.device`、`.ident`）及其构造处：`apply_worker.rs` 约 342 行、`run.rs` 约 1109 行、测试里的构造（`grep -rn "ApplyContext {" core/mastersos-agent`）
- Modify: `core/mastersos-agent/src/system/kiosk/platform_ext.rs`（`prepare`、`Parts`、`build`、`manifest_json`、模块文档）
- Modify: `core/mastersos-agent/src/system/kiosk.rs`（约 357 行调 `prepare` 处）

**Interfaces:**
- Consumes: Task 1/2 的字段与 `check_managed_config`；Task 3 的 `managed.js` 与标记行。
- Produces:
  - `pub struct DeviceValues { pub asset_id: Option<String>, pub location: Option<String>, pub directory_id: Option<String>, pub hostname: Option<String>, pub serial: Option<String> }`
  - `pub fn managed_values(app: &KioskApp, device: &DeviceValues, managed: Option<serde_json::Map<String, serde_json::Value>>) -> Option<serde_json::Value>`：
    三个键都没写时 `None`（不放 `managed.js`），否则「裁定」里的 `DATA`。
  - `platform_ext::prepare(bundle_dir, var_dir, root: &Path, id, app, exam_id, device: Option<&DeviceEntry>, ident: &DeviceIdent)`（`root` 用来读 `etc/hostname`）。
  - `Parts` 加 `managed: Option<&serde_json::Value>`；`build` 在有它时放 `managed.js`，内容 = 标记行换成 `const DATA = {js_literal};\n`，
    `js_literal` = `serde_json::to_string` 后把 `<` 换成 `<`、U+2028 换成 ` `、U+2029 换成 ` `。
  - `manifest_json`：有 `managed` 时在 `chromeos.js` 之后（没有 `chromeos.js` 就在最前）加一条 `main("managed.js")`；不加任何权限。
  - `build` 的「没有平台扩展」判断改成 `!platform && script.is_none() && managed.is_none()`。

- [ ] **Step 1: 写失败的测试**

```rust
// kiosk.rs：managed_values——四键都没写 → None；只写 platform → Some，device_methods true、没有 "device"、没有 "managed"；
//   device_attributes = true、serial None → device.serial 为 null，五个键都在；managed_config → "managed" 原样
// select.rs：命中 [[device]] 时 Selection.device 是那一条；走种子 / default 时为 None
// platform_ext.rs：
//   - 只有 inject 的应用：digest 与改动前相同（把改动前算出的 digest 写死在测试里，在改代码之前先跑一次拿到），没有 managed.js；
//     只有 platform 的应用：有 managed.js（DATA.device_methods 为 true、没有 device 与 managed）
//   - device_attributes = true：zip 里有 managed.js，不含标记行，含 "const DATA = "；content_scripts 顺序 chromeos.js、managed.js（有 platform 时），
//     managed.js 一条是 MAIN、all_frames、match_origin_as_fallback；permissions 与只写 platform 时相同
//   - 托管配置的值含 "</script>" 与 "\u{2028}"：managed.js 里出现的是 "</script>" 与 " "，原文不出现
//   - 换一个 asset_id → digest 变；同样的输入两次 → digest 相同
//   - etc/hostname 内容 " lab-07 \n" → hostname "lab-07"；文件不存在或为空 → null
```

- [ ] **Step 2:** Linux 构建机上确认失败（先跑一次拿到旧 digest 写进测试）。
- [ ] **Step 3: 实现。** `prepare` 读 `managed_config` 文件用 `desktop::read_bundle_file` 再 `check_managed_config`（不过就报错，这个应用跳过，同 `inject`）。
  `directory_id` = `ident.device_id`，`serial` = `ident.serial`，`asset_id`/`location` 来自 `device`。模块开头的文档注释补上 `managed.js` 一条
  与「开了 device_attributes 后这些值在 0644 的 CRX 里」。
- [ ] **Step 4:** Linux 构建机上全量通过。
- [ ] **Step 5: 提交** `feat(agent): 平台扩展带上 managed.js（设备属性与托管配置）`

### Task 5: 收尾检查与重验证清单

**Files:**
- Modify: 本计划末尾的「重验证清单」（如实现中发现新的要实测的点就补上）

- [ ] **Step 1:** Linux 构建机上 CLAUDE.md 的全套 cargo 命令通过；vitest 全部通过；Mac 上
  `PATH="/opt/homebrew/opt/findutils/libexec/gnubin:/opt/homebrew/opt/coreutils/libexec/gnubin:$PATH" bash image/tests/check-tree.sh` 通过；
  `python3 -I tools/check-private.py` 干净。
- [ ] **Step 2: 提交**（只有清单改动时）`docs(plan): 托管设备接口的重验证清单`

## 重验证清单（交给另一个 session，镜像 / 容器 / VM）

1. Chromium 容器（同伪装设计 §3.5 的实验）：不装平台扩展时，Linux 上 `typeof navigator.managed.getManagedConfiguration === "function"`、
   `"getSerialNumber" in NavigatorManagedData.prototype === false`、`getManagedConfiguration(["a"])` reject `NotAllowedError` 与那句文案。
2. 同一容器，平台扩展写 `device_attributes = true` 与 `managed_config`：顶层页面五个方法拿到值、子框架 reject、`getManagedConfiguration` 拿到配置；
   只写 `platform` 时五个方法 reject `UnknownError`。
3. 真镜像 VM 的锁定会话（TestNav 应用加上两个新键）：同第 2 条，并核对改了 `asset_id` 后下一次会话拿到新值。
