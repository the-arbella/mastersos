# 登录页只留一个输入框 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 登录页永远只有一个 “Name or school email” 输入框；打字时框下列出匹配的本机用户，回车或点击登录；没有匹配就按输入的邮箱走新人流程；“Add person” 删除。

**Architecture:** GNOME 自己的 `disable-user-list` 让 GDM 永远停在用户名一步；匹配与排序是纯函数（`people.js`，node 可测）；`extension.js` 在用户名输入框下放一个普通列表，拦截这一步的 `next` 信号，选中某人时走现有的 `_signInAs`。

**Tech Stack:** GNOME Shell 50.1 扩展（GJS、St、Clutter），node 18+（只用于测试纯函数），gettext `.po`。

**Spec:** `docs/specs/2026-11-03-login-single-field-design.md`

## Global Constraints

- 代码、注释、输出英文；提交信息 `<type>(login): <中文说明>`，结尾 `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`。
- 不打字时屏幕上不出现任何人的名字。
- 最多显示 5 个匹配；更多时最后一行显示 “Keep typing to narrow down”（不可点）。
- 隐藏的账号：`guest`、`kiosk-*`、`itadmin`。
- 密码或验证码输入框永远不读、不挂钩（`_isSecret`）。
- 新字符串 `Name or school email`、`Keep typing to narrow down` 进 `.pot` 与全部 84 个 `.po`；删除 `Add person`、`School email`（check-tree 第 50 条要每个 `.pot` 条目在每个 `.po` 里有译文）。
- 提交前 `python3 -I tools/check-private.py`；Mac 上不跑重活，Rust/shell 测试用测试机或 PVE docker（`docker --context pve`）。

## Review Focus

- 打一个字母立刻回车：必须登录第一个匹配的人，不能拿 “d” 当用户名。→ Task 3 VM 用例 2。
- 输入一个新的学校邮箱，而前几个字母和某个老用户相同：回车走新人，不被老用户劫走（带 `@` 时不默认选中）。→ Task 1 `preselect` 测试、Task 3 用例 4。
- 只有输入一个 `@`：域名弹出照旧，匹配列表收起，两者不同时出现。→ Task 3 用例 5。
- 密码输错、卡片取消、切 VT 回来：回到空输入框、列表收起、不残留上次的匹配。→ Task 3 用例 6、7。
- 名字是泰文、中文（无空格）：中间的字也能找到。→ Task 1 测试。

---

### Task 1: 匹配与排序（纯函数 + node 测试）

**Files:**
- Create: `image/mkosi.extra/usr/share/gnome-shell/extensions/mastersos-login@mastersos.org/people.js`
- Create: `image/tests/login-people-test.mjs`, `image/tests/login-people-test.sh`
- Modify: `.github/workflows/mastersos.yml`（image-lint job 加 `- run: bash image/tests/login-people-test.sh`，紧挨 check-tree 之后）
- Modify: `image/tests/check-tree.sh:2110`（第 49 条的文件表加 `people.js`）

**Interfaces:**
- Produces（`people.js`，不 import 任何 `gi://`，node 能直接 import）：
  - `export const HIDDEN = name => boolean`：`guest`、`kiosk-*`、`itadmin` 为 true。
  - `export const LIMIT = 5`
  - `export function matchPeople(people, query) -> {shown: Person[], more: boolean}`，`Person = {userName: string, realName: string, loginTime: number}`；`query` 去首尾空白后为空 → `{shown: [], more: false}`。
  - `export function preselect(query, shown) -> number`：`shown` 为空或 `query` 含 `@` → `-1`，否则 `0`。

- [ ] **Step 1: 写测试 `image/tests/login-people-test.mjs`**（`node:test` + `node:assert`），用例：
  - `empty query shows nobody`：`matchPeople(P, '  ').shown` 长度 0。
  - `prefix of any word in the real name`：`'li'` 匹配 `realName: 'Ann Lim'`。
  - `prefix of the user name / email`：`'ann@'` 匹配 `userName: 'ann@school.org'`；`'school'` 不匹配它（不是开头）。
  - `case-insensitive`：`'ANN'` 匹配 `'Ann Lim'`。
  - `substring for names without spaces`：`'ชาย'` 匹配 `'สมชาย'`；`'明'` 匹配 `'李小明'`。规则：显示名里含非拉丁字母（`/[^\u0000-ɏ]/`）时按子串匹配。
  - `hidden accounts never match`：`guest`、`kiosk-nwea`、`itadmin` 即使名字匹配也不出现。
  - `most recent first`：两人都匹配，`loginTime` 大的在前；相同时按 `realName` 的 `localeCompare`。
  - `at most five, then more`：7 人匹配 → `shown.length === 5 && more === true`；5 人 → `more === false`。
  - `preselect`：`preselect('d', [x]) === 0`；`preselect('d@', [x]) === -1`；`preselect('d', []) === -1`。
- [ ] **Step 2: 写 `login-people-test.sh`**：`set -euo pipefail`；`cd` 到仓库根；`node --test image/tests/login-people-test.mjs`。
- [ ] **Step 3: 跑，确认失败**（`people.js` 不存在）：在 PVE docker `node:20` 里跑该脚本，期望 `ERR_MODULE_NOT_FOUND`。
- [ ] **Step 4: 实现 `people.js`** 的四个导出；文件头注释说明它只做纯计算、被 `extension.js` 与测试共用。
- [ ] **Step 5: 跑测试，全部通过**；`shellcheck image/tests/login-people-test.sh` 无输出。
- [ ] **Step 6: 提交** `feat(login): 打字找人的匹配与排序，node 单测`。

### Task 2: 永远只有输入框；删掉 Add person；改提示文字与译文

**Files:**
- Modify: `image/mkosi.extra/usr/share/glib-2.0/schemas/90_mastersos.gschema.override`（加 `[org.gnome.login-screen]` `disable-user-list=true`，带一行中文注释：登录页只有输入框，设计 2026-11-03）
- Modify: `shelf.js:79,100`（删 Add person 按钮与 `addPerson` action；头注释同步）
- Modify: `extension.js`：删 `addPerson` action、`_addPerson()`；头注释第 2 行去掉 Add person、加 “one entry: type to find a person”。
- Modify: `strings.js`：删 `addPerson`；`email: _('Name or school email')`；加 `narrow: _('Keep typing to narrow down')`。
- Modify: `image/login-i18n/mastersos-login.pot` 与 84 个 `.po`：删 `Add person`、`School email` 两条；加两条新译文（每种语言人工质量的译法，`zh_CN` 用 “姓名或学校邮箱”/“继续输入以缩小范围”，`zh_TW` 用 “姓名或學校電子郵件”/“繼續輸入以縮小範圍”）。

**Interfaces:**
- Produces：`this._text.email`（新文案）、`this._text.narrow`（Task 3 用）。

- [ ] **Step 1: 改 gschema override、shelf、extension、strings。**
- [ ] **Step 2: 改 `.pot` 与 84 个 `.po`**（用一次性 python 脚本按语言表写入，脚本放 scratchpad，不进仓库）。
- [ ] **Step 3: 验证**：PVE docker `ubuntu:24.04` 装 `jq git python3 gettext file gnupg nodejs` 跑 `bash image/tests/check-tree.sh`，期望全部 ok（第 47、49、50 条尤其）；每个 `.po` 跑 `msgfmt -c -o /dev/null` 无错。
- [ ] **Step 4: 提交** `feat(login): 去掉 Add person，登录页只留一个输入框`。

### Task 3: 框下的匹配列表与回车拦截，并在 VM 上验证

**Files:**
- Modify: `extension.js`（`_tryHookEntry`、`_patchGreeter` 里的 `_askForUsernameAndBeginVerification` 补丁、新方法见下）
- Modify: `image/mkosi.extra/usr/share/gnome-shell/extensions/mastersos-login@mastersos.org/stylesheet.css`（若存在；否则同目录现有的样式文件）：`.mastersos-people`、`.mastersos-person`、`.mastersos-person:selected`/`:hover`、`.mastersos-person-more`

**Interfaces:**
- Consumes：`matchPeople`、`preselect`、`HIDDEN`（Task 1）；`this._text.narrow`（Task 2）；现有 `_signInAs(userName)`、`_isSecret(entry)`、`_showDomains`、`_scheduleClose`。
- Produces（extension 内部）：`_people()`（从 `this._dialog._userManager.list_users()` 映射成 `Person[]`，`loginTime = user.get_login_time()`，`realName = user.get_real_name() || userName`）、`_showMatches(entry, text)`、`_hideMatches()`、`_moveSelection(delta)`、`this._picked`（当前选中 userName 或 null）。

- [ ] **Step 1: 列表控件**：一个竖排 `St.BoxLayout`（`style_class: 'mastersos-people'`），插在 `prompt._inputWell` 里输入框之后、`_itLink` 之前；每行 `St.Button`（`can_focus: false`，键盘焦点始终在输入框）含 24px 头像（`user.get_icon_file()` 存在用它，否则 `avatar-default-symbolic`）、显示名、灰色用户名；`more` 时末行 `St.Label(this._text.narrow)`。点击行 → `_signInAs(userName)`。
- [ ] **Step 2: 挂钩**：`_tryHookEntry` 不再只在有域名时才跑（`_tick` 里去掉 `this._domains.length` 条件）；`text-changed` 里：秘密输入框 → 收起两种列表；以单个 `@` 结尾且有域名 → `_hideMatches()` 后 `_showDomains`；否则 `_showMatches(entry, text)`。输入框所在的 `clutter_text` 挂 `key-press-event`：Up/Down → `_moveSelection(∓1/±1)` 并 `EVENT_STOP`（仅列表可见时）；Escape → `_hideMatches()`。
- [ ] **Step 3: 回车拦截**：在已有的 `_askForUsernameAndBeginVerification` 补丁里，`original.call(this)` 之后断开 `this._nextSignalId`，连上自己的 `next` 处理：`ext._picked` 非空 → 断开信号、`ext._hideMatches()`、`ext._signInAs(ext._picked)`；否则照 GNOME 50.1 原样（`updateSensitivity(false)`、`getAnswer()`、`_userManager.get_user`、`clear()`、`begin({userName})`、`_updateCancelButton()`），并在注释里写明来源行 `loginDialog.js:1147-1157`。
- [ ] **Step 4: 收起时机**：`prompt` 的 `reset`、`_beginVerification` 补丁、`disable()` 里都 `_hideMatches()`，`this._picked = null`。
- [ ] **Step 5: 语法检查**：`node --check`（把各 `.js` 复制成 `.mjs`）全过；Task 1 测试仍过。
- [ ] **Step 6: VM 122 验证**（把分支推到 GitHub，VM 里 root shell 用 `curl` 从 `raw.githubusercontent.com` 取扩展文件，放进副本目录后 bind-mount 到 `/usr/share/gnome-shell/extensions/mastersos-login@mastersos.org`，`systemctl restart gdm`；gschema 用 `gsettings`/dconf 对 gdm 用户临时打开 `disable-user-list`）。截图编号接 r49 起，全留。用例：
  1. 开屏：只有输入框与 “Local manager”，没有名字、没有返回键、底部没有 Add person。
  2. 有 1 个本地用户：打首字母 → 列表 1 行且选中 → 回车 → 出密码框，标题是此人。
  3. 造 6 个本地用户（`useradd -m`，有不同的 `lastlog`）：打一个公共字母 → 5 行 + “Keep typing to narrow down”，顺序按最近登录；上下键移动选中。
  4. 输入一个不存在的完整学校邮箱回车 → 学校登录卡片打开。
  5. 输入 `abc@` → 域名弹出，匹配列表不见。
  6. 选人后密码输错 → 回到空输入框，列表收起。
  7. Ctrl+Alt+F3 再切回 → 空输入框。
  8. “Local manager” 照旧直达 itadmin 密码。
- [ ] **Step 7: 提交** `feat(login): 框下列出匹配的人，回车直接登录选中的人`；推分支、开 PR，正文列 VM 截图路径与用例结果。
