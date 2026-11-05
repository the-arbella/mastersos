# 远程诊断与学生求助（设计）

状态：已批准（2026-11-05，上传方式改为 S3 后用户批准）。接口已与云端会话协商定稿；本文只管系统侧，云端实现在私有仓库。

## 为什么要做

真实用户那里出问题时，要能系统地拿到诊断日志；学生遇到问题时，要能一键告诉 IT，IT 收到时已经带着设备、用户、状态和日志。
我们作为系统开发商也要看到去标识后的求助与日志，用来改进系统。

上一版的 U 盘诊断（安装时按 d、插安装盘导出）不系统：要提前装成 debug 机、要人到现场插盘。Wi-Fi 问题已解决，机器能联网，
改为远程收集，U 盘诊断整体删除（用户定）。

## 目标

- IT 在云端发指令，机器几秒内收集诊断包并上传到云端。
- 学生在登录页、桌面、Kiosk 应用里都能点「Get help」，选分类、写描述、可选附截图，发给 IT，马上看到单号。
- 没网时求助先存在本机，联网后自动发出。
- 开发商看到的是云端生成的去标识副本（云端负责）。

## 不做

- 一期不做远程调高日志级别（`diag-verbose`，云端提议放二期）。
- 一期不做单子的后续状态回传给学生。
- 不经 MQTT 发任何数据：MQTT 是公共 broker，只做门铃（用户定）。机器→云一律 HTTPS，带设备凭据。
- 不收用户主目录、不收浏览记录。

## 反目标

- 诊断包里有设备凭据、令牌、Wi-Fi 密码、seed 内容。
- 学生能冒充别人发求助（用户名由系统认定，不由界面填写）。
- 机器在没有开关、没有指令的情况下自己上传日志（求助附带的轻量日志除外，那是学生主动发的）。
- 截图在学生没勾选、没看过预览的情况下被发出。

## 取舍

- 往 MQTT 写：共用 broker 不应经过学生数据；日志包几 MB 到几十 MB；机器现在只订阅。不选。
- 上传经我们的服务器中转：占服务器带宽与长连接。不选。**选定（用户定）：** 用 S3 presigned PUT 直传，学校防火墙放行
  S3 区域主机名；S3 不通时不回落到中转，按退避重试，指令最终以 `upload: <错误>` 失败，IT 在控制台能看出是防火墙问题。
- 开发商可见：B 方案（默认去标识，学校可关），家长告知书与 DPA 由云端/运营侧准备（用户定）。
- 机器只发一份，去标识在云端做（云端定）；机器在包里放 `manifest.json` 标明每个文件的类型，方便云端按文件处理。

## 接口（类型放 `core/mastersos-bundle`，云端 pin 本仓库提交）

1. **IT 收诊断。** 复用 inbox：新 kind `collect-diagnostics`，class `command`，payload
   `{"boots": 1..5, "since_hours": null | 1..168}`，默认 TTL 24 小时。
   - 机器：ack `running` → 收集 → 上传 → ack `done`，detail `diag:<id>`；失败 ack `failed`，detail 写哪一步。
   - 上传分三步（见下面「上传」），`kind: "inbox"`、`inbox_seq: <seq>`；上限 50 MB。
   - 包超过 50 MB：从最早一次开机的日志开始丢，直到在上限内，manifest 写 `"truncated": true`。不发超限的包。
   - S3 一直失败：按退避重试到指令过期，ack `failed`，detail `upload: <错误>`。
2. **学生求助。** `POST /v1/support`，设备凭据，JSON（`SupportRequest`）：
   `client_id`（机器生成的 UUID，幂等、离线重发同一个）、`category`（`wifi|sign_in|app|hardware|battery|other`，
   服务端把未知值当 `other`）、`text`（≤1000 字符）、`user`（`kind: none|guest|local|sso`，`name`）、
   `session`（`login|desktop|kiosk:<app id>`）、`created_at`、`snapshot`（系统版本、网络、电量、磁盘、最近一次状态报告）、
   `screenshot`（布尔）。回 `201 {"ticket"}`；同一 `client_id` 回同一单号；超限 429。
   - 之后按「上传」三步传附件包（`kind: "ticket"`、`ticket: <单号>`）：最近 30 分钟的轻量日志，学生勾选时加截图；
     上限 10 MB；单号只接受本机建的、48 小时内。48 小时内传不成就放弃附件，单子照常。
3. **上传（S3，云端与系统协商定稿）。**
   1. `POST /v1/diagnostics`，设备凭据，JSON（`DiagUploadRequest`）：`{"kind":"inbox","inbox_seq":N}` 或
      `{"kind":"ticket","ticket":"1042"}`，加 `"bytes"` 与 `"sha256"`（hex）。
      - 回 `201 {"id","upload":{"method":"PUT","url","headers":{...},"expires_at"}}`：url 有效 15 分钟；headers 里有服务端签入的
        `Content-Length`、`x-amz-checksum-sha256`（base64）、`x-amz-tagging: state=pending`，机器原样带上，不自己换算。
      - 同一 seq/ticket 已完成：回 `200 {"id","complete":true}`，不带 `upload`，机器跳过后两步。
      - 没完成的：回同一 id、新 url。超限 413；seq 不是发给本机的 `collect-diagnostics`、或单号不是本机的：409。
   2. 机器把包 `PUT` 到 `upload.url`。url 过期就回到第 1 步。
   3. `POST /v1/diagnostics/{id}/complete`：服务端核对大小与 sha256，通过回 204（这时才算到达，才去标识与通知 IT）；
      不通过回 409 并删掉对象，机器回到第 1 步。
   - 桶在 ap-northeast-1，主机名形如 `<bucket>.s3.ap-northeast-1.amazonaws.com`。公开 README 的防火墙清单只写这个形式，
     加一句「确切主机名见学校管理网站的 Install 页」；桶名不进本仓库。`GET /v1/auth/config` 会带 `diagnostics_host`，
     机器的自检可以用它测连通。
   - 加密、过期都在桶上（SSE-S3、阻止公共访问、只许 TLS；按标签过期：pending 2 天、complete 90 天、开发商副本 180 天），
     机器不加额外的头。
4. **按钮开关。** 签名设置 `[config.support] enabled`，默认 `true`（云端定：没配 IT 邮箱单子也会出现在控制台）。
   schema、lint 与 spec 文本一起进 bundle。
5. **诊断包 `manifest.json`**（`DiagManifest`）：
   `{"format": 1, "created_at", "device_id", "kind": "inbox|ticket", "truncated": bool,
     "files": [{"path", "source", "type": "text|image|binary", "bytes"}]}`。

## 设计（系统侧）

1. **删除 U 盘诊断。** 安装器的按 d 窗口与确认屏那一行、`debug-install` 标记、`diag-setup`、`diag-adopt`、`diag-export`
   及其 udev 规则和服务、4 个 `90-mastersos-diag.conf` drop-in、相关测试与 check-tree 项、两份旧计划改为「已废弃」注记
   （旧 spec 头部注明被本文取代，不删历史）。已装成 debug 的机器：新版首次开机删除 `/var/lib/mastersos-diag/`（一次性清理）。
   U 盘上的 `diag.sh` 由我从 U 盘删掉。
2. **收集器。** `mastersos-agent diag collect --out <file> --boots N | --since-minutes M [--screenshot <png>]`，root 运行，
   只收白名单：
   - 日志：所选开机的 journal（文本，按开机分文件）；轻量模式只要最近 M 分钟。
   - 崩溃：`coredumpctl list` 与 `info`（不要 core 文件）。
   - systemd/会话：`systemctl --failed`、`list-units`、`loginctl` 会话。
   - 网络：`nmcli general/device`、`nmcli connection show`（不带 secrets）、`ip addr/route`、`resolvectl status`、`rfkill`、
     `iw dev`、`iw reg get`、Wi-Fi 扫描列表。
   - 硬件：`lspci -nnk`、`lsusb`、`/proc/cmdline`、输入设备、`mem_sleep`、电池。
   - 系统：`os-release`、`bootctl status`、agent 的 `state.json` 与最近状态报告（过一遍去密）。
   - **不收**：种子分区（seed、`identity.json`、令牌）、`/etc/NetworkManager/system-connections/`、任何私钥与令牌文件、
     用户主目录。收集后对文本做一遍去密（`psk=`、`password=`、`token`、`secret`、Bearer 头等模式替换为 `[redacted]`）。
   - 写 `manifest.json`，打 tar.zst，超限按上面的规则截断。缺少的命令跳过并在 manifest 里记 `source` 失败原因。
3. **inbox 处理。** `collect-diagnostics` 按现有 inbox 流程（时钟下限、过期、先 ack）。收集与上传在阻塞线程里做，不挡主循环；
   上传失败按退避重试同一个包，直到指令过期。收集开始时在当前会话（含登录页）显示一条通知
   「IT is collecting diagnostic info from this computer.」（i18n）。
4. **求助入口与本地通道。**
   - 本地 socket `/run/mastersos/support.sock`（systemd socket 激活，0666），服务端是 root 的 `mastersos-agent support-host`。
     用 `SO_PEERCRED` 取调用方 uid 认定用户：GDM 登录页 → `none`，访客 uid 1999 → `guest`，authd 用户 → `sso`，其他 → `local`；
     `name` 取自系统，不接受界面传来的名字。
   - 界面只传：分类、描述、是否附截图与截图文件（PNG，≤5 MB，从调用方给的 fd 读，不按路径读）。
   - helper 校验后写入 root 0700 的本地队列 `/var/lib/mastersos/support-queue/<client_id>.json`，叫醒 agent，立刻回界面
     「已排队」；agent 发送成功后把单号写回，界面轮询或订阅后显示单号。
   - 限流：本机每小时 3 条（helper 里数，跨重启算），超出界面显示「稍后再试」；服务端 429 同样处理。
   - 离线：队列里的单子联网后发出；界面说明「Will send when you're online」。
5. **界面（英文为主，全部走 i18n）。**
   - 登录页：底部 shelf 加「Get help」；桌面：右上系统菜单加「Get help」；Kiosk：浮动 Options 菜单在 Exit 上方加「Get help」
     （扩展经 native messaging 宿主 `mastersos-agent support-host --native` 转到同一个 socket）。
   - 对话框：标题「Get help from IT」；分类按钮（Wi-Fi / Can't sign in / An app / Screen, keys or sound / Battery / Other），
     必须选一个；描述框可选，占位提示「What happened? Please don't include passwords or personal details.」；
     「Attach a screenshot」默认不勾，勾选后显示缩略图预览（截的是打开对话框之前的画面）；Cancel / Send。
   - 发送后：「Sent. Ticket #1042. IT has been told.」；排队时：「Saved. It will be sent when this computer is online.」
   - `[config.support] enabled = false` 时三处入口都不显示。
6. **设置项。** bundle 加 `[config.support] enabled`（默认 true），spec 文本、lint、`mastersos spec --section config.support`。

## 测试

- bundle：新类型的序列化往返；`SupportRequest` 文本 1000 字符边界；`[config.support]` 缺省为 true。
- agent：inbox `collect-diagnostics` 的 ack 顺序、过期、上传重试与同 seq 幂等；包超限截断并标 `truncated`；去密模式；
  白名单里没有种子分区与 system-connections；support-host 由 peercred 认定用户（伪造 name 无效）、限流、离线排队后补发、
  `client_id` 重发不变。
- shell：check-tree 断言 diag 相关文件已不在镜像里、新 socket 与服务存在。
- 界面：登录页、桌面、Kiosk 三处的对话框截图自审（新编号保存），含勾选截图的预览、排队与单号状态。
- VM 实测：用测试云端（cloud 部分就绪后）从控制台发收诊断，看包到达；三处各发一条求助，看到单号；断网发一条，联网后补发。

## 风险

- 诊断包仍可能带出学生名字（journal 里的会话记录）：由云端去标识处理开发商副本，学校自己的副本按学校数据对待。
- 去密是模式匹配，不保证覆盖所有格式：白名单不收已知的秘密文件是第一道防线，模式替换是第二道。

## 留给实现的

文件布局、截图在三处的具体取法（gnome-shell `Shell.Screenshot`、Chrome `captureVisibleTab`）、通知怎么发到登录页、
队列文件格式细节。
