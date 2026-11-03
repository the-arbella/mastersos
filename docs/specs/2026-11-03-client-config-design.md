# 设置在客户端编辑：服务端不存草稿

2026-11-03 · 状态：已批准

## 1. 为什么

今天学校设置的“理解”分在两边：格式、`Manifest::validate`、lint、签名在 `mastersos-bundle`（客户端与 agent 共用），
而草稿、编辑表单、差异、发布前补字段、对 AI 遮蔽 Wi-Fi 秘密都在云端服务里。每加一个设置项，服务端、网页、命令行
三处都要改；服务端为了“让 AI 改草稿又看不到秘密”还要逐字段理解设置。

服务端本来就不持签名钥匙，每一版由学校的钥匙签。把草稿与编辑整个交给客户端，云端只做：收待签名的包、核对、存已签的
版本、分发给机器、管理机器与钥匙。格式只在一个地方演进：公开库里，与读它的 agent 放在一起。

用户裁定（2026-11-03）：

- IT 负责把设置写对，客户端有检查工具；服务端不存、不解析、不编辑草稿。草稿是 IT 电脑上的一个本地目录。
- 不做 WASM；管理网页不再编辑设置，编辑与秘密都只在命令行。
- 命令行留在公开库 `mastersos`；不放进云端仓库，不另开 `mastersos-config` 仓库。
- 服务端可以用 agent 同一套代码**读包**（待签名的与已发布的），用于收包核对与生成种子。
- AI 不读秘密靠规则与 MCP 过滤（尽力而为）；任何改动都要 IT 看过、签名才发布。
- 签名页只签已经上传的待签名包。
- 本次不加密设置（第 8 节）。
- 现在没有真实试用学校：一次切换，不保留旧接口、不迁移草稿。

签名不是加密：IT 的私钥签名，服务端与机器用公钥（trust）验签；包是明文，传输靠 HTTPS 与 `fetch_token`。
机器收到的新包验签、学校 id、版本、解包、`validate` 任何一步不过都拒收，继续用当前那一版（agent 现行行为，不变）。

## 2. 目标、非目标、反目标

**目标**

- 命令行只多四个动作：`pull`、`check`、`diff`、`publish`；加两个列表 `device list`、`keys list`。不移植任何表单编辑器：
  IT 与 AI 直接编辑 TOML，`check` 把关。
- 服务端只存待签名的包与已签名的版本（加上现有的机器、钥匙、种子等非设置数据）。
- 收包时服务端强制 agent 的检查与需要机器数据的阻断检查（第 5 节）。
- passkey（签名页）与恢复钥匙（`mastersos-sign`）两种签名都走同一条“上传 pending → 签 → commit”的路。
- 机器拿到的包格式不变，agent 不改。

**非目标**

- 设置加密、机器的非对称身份、客户端生成种子。
- 多个 IT 共享未完成的草稿（需要时自己用 git，`secrets.toml` 不进 git）。
- 三方合并。
- 另写一份云端接口规范文件：云端仓库的 `integration/` 用公开库的命令行与签名工具对真服务端跑测试，就是协议的约束。

**反目标**

- 服务端仍以任何形式持有草稿，或留着按字段编辑设置的代码。
- MCP 工具的输出里出现秘密的值。
- 两个 IT 先后发布时，后发布的人静默覆盖前一个人的改动。
- 公开库依赖云端仓库。

## 3. 方案

- **草稿只在本地（选定）。** 服务端只存包；冲突靠版本号。
- 服务端存不透明草稿：原为 WASM 网页与多人协作而选，去掉 WASM 后理由没了。
- 保留服务端草稿接口、换成调用公共 crate：服务端不变轻。

## 4. 本地目录与命令

```
<工作目录>/
  mastersos.toml       学校主机名、学校 id、base_version（pull 下来的版本）
  manifest.toml        设置；秘密字段写引用，如 psk = "secret:guest-wifi"
  secrets.toml         guest-wifi = "…"（0600；命令行写 .gitignore 排除它）
  files/...            包里的其它文件
  .mastersos/base/     pull 下来的原样（同样拆好秘密），diff 用
```

- **`mastersos pull [--version N]`**：下载已发布的包（缺省最新），沿版本链验签，拆成上面的目录。
  每个秘密字段（Wi-Fi 的密码与钥匙、IT 账号口令哈希）的值移进 `secrets.toml`，名字按所在层与 SSID 自动生成，
  `manifest.toml` 原位写引用（`toml_edit`，保留排版与注释）。目录有未发布的改动时拒绝覆盖，除非 `--force`。
- **`mastersos check`**：本地，不联网。`mastersos-bundle` 现有的 lint，加：
  - 引用了不存在的秘密 → 错误；`secrets.toml` 里没人用的秘密 → 警告；
  - 引用秘密的网络，相对 base 改了 `eap`、`phase2`、`identity`、`anonymous_identity`、`server_domain`、`ca_cert`、
    `check_server` 任一 → 警告（密码会被发到新的地方，请 IT 确认）。
- **`mastersos diff`**：与 `.mastersos/base/` 比，本地；秘密只显示名字与“值有变化”。
- **`mastersos publish`**：
  1. `check` 有错误就停。
  2. 合成：引用换成值，写 `version = base_version + 1`、`issued_at`、`[school] name`（规则从今天服务端的 prepare 搬来）。
     `trust` 照 `manifest.toml` 写的，不自动填。
  3. 上传成待签名包。服务端拒收（包括 base 之后已有人发布、阻断检查不过）就停并显示原因；版本被占用时提示重新 `pull`、
     重做改动。
  4. 本机配了恢复钥匙就用 `mastersos-sign` 签并 commit；否则打印签名页链接（带 pending id），IT 用 passkey 签。
  5. 成功后把 `base_version` 与 `.mastersos/base/` 更新为新版本。
- **`mastersos device list`、`mastersos keys list`**：从服务端取机器、已登记的钥匙，供手写 `[[device]]` 与 `trust`。
- **IT 账号口令**：`mastersos hash-password`（不回显）输出哈希，IT 写进 `secrets.toml`。
- **新学校**：`mastersos init` 用模板（今天服务端的草稿模板）建目录，`base_version = 0`；第一版用恢复钥匙签（R1g 不变）。
- **logo**：`mastersos logo upload <登录页 png> <图标 png>` 只核对尺寸并上传，打印两个 sha256，IT 写进 `[school]`。

### AI 与 MCP

- MCP 工具：读 `manifest.toml` 与 `files/`、`check`、`diff`、`device list`、`keys list`。不提供读写 `secrets.toml`、合成、
  上传、签名的工具；任何输出里秘密只以名字出现。AI 改文件用它自己的编辑工具。
- 规则（`mastersos-admin` 技能）：不读 `secrets.toml`，不读合成出的包；改完交给 IT 看 `diff` 并 `publish`。
- 服务端的 AI token 只能读机器与状态：不能下载包，不能读待签名包与摘要（摘要可被用来离线猜弱口令）。

## 5. 云端接口

**新增：** `POST /v1/admin/publish/pending`：上传合成的包。核对失败返回 422 并列出原因（英文消息加 code），不存：

- agent 的检查：`read_archive`、`Manifest::validate`、学校 id、`version` = 最新已发布 + 1（即 base 没过时；首版按 R1g）、
  trust 中的钥匙都已登记；
- 需要机器数据的阻断检查：今天 prepare 里的 `fleet_lints`（近 30 天机器的功能与 format 支持、托管收件人、logo 已上传、
  flatpak 等）。

通过后算摘要、存成待签名内容（上限与有效期沿用今天的 pending）。AI token 不能调用。

**保留：** `versions/{v}/archive`（`pull` 用，AI token 不能调用）、`publish/pending/{id}`、`…/files/{path}`、`…/commit`、
登录、机器接口、机器列表与移除、钥匙与托管收件人登记、种子、心跳签名、logo 上传、AI token 管理、概览。

**删除：** 一切 `draft/*`、`manifest/check`、`publish/prepare`、`publish-requests*`、`versions/{v}/diff`、
`versions/{v}/restore`、`devices/assign`、`devices/{id}/group`、`devices/{id}/lock`。

**签名页：** 只有 `pending=<id>` 一条路：取包、本地重算摘要、展示内容与 trust 相对上一版的变化（秘密显示为“已设置”）、
passkey 签名 commit。恢复包登记、换钥匙只在签名页登记钥匙；改 trust 在命令行，发布时回到签名页签。

**管理网页：** 只看——机器、版本、钥匙、种子、托管恢复、AI token；没有编辑设置的页面。

## 6. 公开库的改动

- `mastersos`（`mastersos-mcp` crate）：第 4 节的命令与 MCP 工具；去掉调用服务端草稿接口的旧工具。
- `mastersos-bundle`：加上第 4 节 `check` 的秘密引用规则（引用的语法只在草稿里，合成后的包里没有）；把今天服务端 prepare
  的补字段规则搬成一个函数，命令行调用。
- `mastersos-sign`：`publish` 调用它签已上传的 pending（与今天 `sign` 相同的路径）。
- `skills/mastersos-admin`：改成在本地目录工作，写明 AI 规则。

## 7. 发版顺序

1. 公开库发版。
2. 云端升 `os.rev`，部署新接口并删除旧接口、草稿与发布请求的表；签名页在 Mac 上重新发布。

现场机器、种子、已签的版本不受影响。

## 8. 以后：端到端加密的前提

设置加密只有在 (1) 种子在客户端生成，(2) 机器有非对称身份、登记由 IT 签名确认之后才有意义。分组映射始终在签名内容里，
不让服务端决定机器用哪个 config。

## 9. 留给实现者

- `mastersos.toml` 的字段名、秘密名字的生成规则、issue code 名字。
- `pull` 遇到旧版本里异常秘密值（例如 `"<kept>"`）的处理。
- logo 尺寸核对沿用服务端现有规则（登录页 96 高、1–480 宽；图标 40×40）。
