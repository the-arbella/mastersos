# 登录卡片的网页登录交给桌面浏览器（设计）

2026-11-05 · 状态：待批准 · 规模：中（卡片单元、pam-session、新的用户单元、agent 两个子命令）

## 为什么要做

学校账号在登录页的卡片里登录学校的身份系统（IdP）。登录成功后卡片的 Chrome 连同它的一次性配置一起消失，学生进了桌面，
打开学校的网站（同一个 IdP 的单点登录）还要再输一遍邮箱、密码、两步验证。卡片里那时已经有 IdP 的会话 cookie：把它们交给
这个学生自己的桌面 Chrome，桌面上用学校 IdP 的网站一打开就是登录好的。

只认标准 OIDC 的那一套：交的是卡片里 IdP 设下的 cookie，不看是哪一家（Zitadel、Google、Kanidm + Dex 都一样），
不写任何一家的专用逻辑。

## 已经实测的事实（2026-11-05，`image/lab/results/2026-11-05-browser-handoff/`，Chrome 157，容器与真机 VM + 学校的 Zitadel）

1. 卡片的 Chrome 每 30 秒左右才把 cookie 写进盘。默认的停止信号 SIGTERM 下，停止时卡片的 `Cookies` 是空的；
   `KillSignal=SIGINT` 时 Chrome 会先写盘（VM 上拿到 4 个）。
2. `ExecStopPost=+` 的命令（不进单元的命名空间）在 systemd 删掉之前读得到单元的私有 /tmp：
   `/tmp/systemd-private-<boot id>-mastersos-login-browser@<实例>.service-<随机>/tmp/profile/Default/Cookies`。
3. 镜像没有 gnome-keyring-daemon，桌面 Chrome 与卡片一样用固定的 `v10` 密钥加密 cookie，行可以原样复制，不用解密。
   cookie 库第 24 版的密文里含 SHA256(host_key)，host_key 不变就没事。
4. 合并：两边 `meta` 的 `version` 相同才合并；按 Chrome 的唯一索引
   （host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port）`INSERT OR REPLACE`，
   用户库里的其他行不动（实测别的网站的 cookie 都还在）。只能在用户的 Chrome 没在跑的时候做（Chrome 占着库）。
5. Zitadel v2 的登录状态是会话 cookie `sessions`（没有过期时间）。Chrome 启动时删掉所有非持久 cookie
   （基线策略 `RestoreOnStartup=5`）。只交持久 cookie 登录不上；把会话 cookie 改成持久的（8 小时后过期）就登录上了。
6. 第一次登录时用户还没有 Chrome 配置：只放一个按 Chrome 自己的表结构建的 `Default/Cookies`（第 24 版），Chrome 157
   第一次启动就带上了这些 cookie，第二次启动也还在（本设计实施时在容器里实测）。

## 目标

- 学校账号（authd / SSO）在登录页卡片里登录成功、进了桌面之后，桌面 Chrome 里有卡片里那次登录的 IdP cookie。
- 对任何 OIDC 身份系统都一样。
- 会话 cookie 改成持久的，**交接之后 12 小时过期**（一个上学日）；本来就持久的保留自己的期限，已过期的不交。
- 第一次登录（用户还没有 Chrome 配置）也交。
- 浏览器的可执行文件、配置目录的位置各在一处，换成 Chromium（`2026-11-03-chromium-design.md`）时只改那一处。

## 不做

- 不做「登录 Chrome 本身」（Google 账号同步）：基线策略仍是 `BrowserSignin: 0`。
- 不交给访客、锁定应用（`kiosk-<id>`）、本机账号（含 IT 维护账号 `itadmin`）：它们不走卡片，也没有 IdP 会话。
- 不在解锁时交：解锁不开新会话（PAM 不跑 open_session），也不经这条路。
- 不解密、不改写 cookie 的值。
- 用户的 Chrome 开着时不等它关，这次就不交了（只记一行日志）。

## 反目标（出现就算失败）

- 卡片用过任何用户的配置，或卡片开始时不是空配置。
- 一个人的 IdP 会话进了别人的桌面：输错的人、取消的人、登录被拒的人、之后登录的另一个人。
- 卡片里的 cookie 在交给本人之前除 root 以外谁都读得到。
- root 在用户（或登录页用户 gdm-greeter）还能改的目录里写东西，或跟着那里的符号链接走。
- 交接失败让登录失败或变慢。

## 流程

```
登录页扩展写 URL（带 login_hint=<邮箱>）到 greeter 的运行时目录，RestartUnit 卡片单元
  └─ ExecStartPre=+ mastersos-agent signin-handoff begin <实例>       （root）
       作废以前的一切：交接目录里除了锁之外全删；读 URL 里的 login_hint，记下 card.json
       {实例, INVOCATION_ID, 邮箱}
  └─ 卡片 Chrome（gdm-greeter，私有 /tmp，空配置）——学生在学校页面登录，broker 收到回调、验证邮箱
GDM：验证完成 → 扩展 StopUnit（SIGINT，Chrome 把 cookie 写盘、退出）
  └─ ExecStopPost=+ mastersos-agent signin-handoff stash <实例>       （root，单元的进程都已退出）
       card.json 的实例与 INVOCATION_ID 都对上才做：从私有 /tmp 读 Cookies（有上限），存成 pending.db，记下停止时刻
       → 尝试交付
同时：GDM 开会话 → PAM session 段最前面的 pam-session（root，open_session）
       gdm-authd、名字带 @（SSO）、uid 不是系统账号、card.json 的邮箱等于 PAM_USER（不分 ASCII 大小写）才做：
       记下 claim.json {用户, uid, 时刻}，放一个空的占位文件 /run/mastersos-signin/<uid>（root 0644）→ 尝试交付
尝试交付（两边谁后到谁做，持锁）：pending 与 claim 都在、邮箱相等、各自不超过 2 分钟
       → 写 /run/mastersos-signin/<uid>（临时文件 + fchown 给 uid、0600 + rename 盖掉占位），删掉 pending、claim、card.json
用户会话：mastersos-signin-import.service（用户单元，ConditionPathExists=/run/mastersos-signin/%U）
  └─ mastersos-agent signin-import（以用户本人身份）
       最多等 30 秒，等占位变成属于自己、非空的文件；读进来立刻截断（只用一次）
       → 只留 IdP 主机的 cookie，会话 cookie 改成 12 小时后过期，丢掉已过期的
       → Chrome 没在跑：合并进 ~/.config/google-chrome/Default/Cookies；还没有这个库就按 Chrome 的表结构新建
```

### 为什么由 root 在 ExecStopPost 里取，而不是卡片的启动脚本自己拷出来

- 启动脚本以 gdm-greeter 身份跑在 `ProtectSystem=strict`、私有 /tmp 与 AppArmor 之下，能写的只有私有 /tmp
  （它自己的配置所在之处），写不出去；要写出去就得放宽 AppArmor 与 `ReadWritePaths=`，卡片的沙箱就松了。
- 启动脚本 `exec` 了 Chrome；要在 Chrome 退出后再拷，就得留一个 shell 等它、转发 SIGINT，多一层容易出错的东西。
- 无论谁拷，内容都出自卡片里的 Chrome，一样不可信；可信的只有「什么时候、为谁」，那由 root 的三步与 PAM 定。
- `ExecStopPost` 跑的时候单元的进程已全部退出（`KillMode=control-group`），私有 /tmp 的外层是 root 0700，
  别的进程进不去：root 读的这几级目录这时没有人能改。照样逐级 `openat(O_NOFOLLOW)`、核对属主与文件类型。

### 为什么分成 claim 与 stash 两半

GDM 收到「验证完成」后开会话，扩展同时停卡片；Chrome 写盘、退出要一两秒，PAM 的 open_session 往往先到。
pam-session 不能等（会拖慢登录），所以两边各记一半，后到的那个交付；用户一侧的导入最多等 30 秒。

## 安全

| 情形 | 结果 |
|---|---|
| 卡片的配置 | 永远是单元私有 /tmp 里新建的 `/tmp/profile`，单元停下就没了；卡片从不碰任何用户的家目录（`InaccessiblePaths=-/home`） |
| A 输入 B 的邮箱，在学校页面登录成 A | broker 拒绝（邮箱不符），不开会话、没有 claim。pending 留着（标的是 B），2 分钟后作废；B 来登录时先开新卡片，begin 把它删掉。A 自己登录也一样先开新卡片 |
| 取消、登录失败、卡片超时 | 没有 claim，同上 |
| 之后的另一个人 | 每次开卡片 begin 先作废一切；claim 要邮箱等于 PAM_USER，且 2 分钟内 |
| 解锁 | 不跑 open_session，没有 claim；锁住的学校桌面也不会开卡片（managed 扩展的 `_onReset`） |
| 访客、kiosk、本机账号 | pam-session 只给 gdm-authd 上名字带 `@` 的 SSO 账号 claim |
| 卡片的 Chrome 被攻破 | 它能写的只有自己的 cookie 库：导入只收卡片策略放行的主机（issuer 与 `card_hosts`，含它们的上级域名的域 cookie，但不收没有点的名字），每一列的类型、大小、行数都有上限，表结构不对就不收 |
| 只给 root | `/run/mastersos-signin` root 0711（不能列目录），`private/` root 0700；交付的文件属于本人 0600 |
| root 不写用户能写的目录 | root 只在自己的 `/run/mastersos-signin` 里写；往 `~/.config/google-chrome` 写的是用户单元里本人身份的 `signin-import` |
| 有上限 | URL 4 KiB、card.json 等记录 4 KiB、cookie 库 4 MiB、1000 行、每个值 16 KiB |
| 失败 | begin 失败卡片不起（不作废旧的就不许开新的）；其余步骤出错只记日志，登录照常 |

同一个人在卡片里先后登录了两个账号（Google 允许）时，两个都会交过去：要做到这一步他得有第二个账号的口令，这不算泄露。

## 第一次登录

用户还没有 `~/.config/google-chrome/Default/Cookies` 时，`signin-import` 按 Chrome 自己的表结构（代码里写死第 24 版的
`CREATE TABLE`，与 Chrome 157 逐字相同）建一个新库再放进去，用 `rename` 的 NOREPLACE 放，万一 Chrome 刚建了就不盖。
卡片的库不是第 24 版时第一次登录不交（日志里有一行），下一次登录照常合并：Chrome 升级了 cookie 库的版本时，
要更新这份表结构（单元测试拿 Chrome 157 的表结构核对）。

## 浏览器的位置

- 桌面 Chrome 的可执行文件与配置目录：`core/mastersos-agent/src/system/desktop.rs` 的 `CHROME_BIN`、`CHROME_USER_DATA`。
- 卡片的配置目录：`login-browser` 的 `--user-data-dir=/tmp/profile`，agent 里是 `signin_handoff::CARD_PROFILE`，
  check-tree 核对两边一致。
- 换成 Chromium 时：改这两处常量与 `login-browser`（`~/.config/chromium`）。Chromium 在 Linux 上没有密钥环时同样用 `v10`，
  合并的办法不变；Chromium 的 cookie 库版本与 Chrome 不同时第一次登录不交，直到更新表结构。

## 实施

- 卡片单元：`KillSignal=SIGINT`、`ExecStartPre=+… begin %i`、`ExecStopPost=+… stash %i`。
- tmpfiles：`/run/mastersos-signin` 0711、`private` 0700（agent 也自己建、改权限，不靠 tmpfiles）。
- `mastersos-agent pam-session`：对 `Enqueue` 的那一类用户，gdm-authd 上的 SSO 账号先 claim。
- 用户单元 `mastersos-signin-import.service`：由 `gnome-session@ubuntu.target` 与 `gnome-session@gnome.target` 的 drop-in
  拉起（与 browser-wait 一样，锁定应用的会话不拉）。
- agent 链接 SQLite（rusqlite 的 bundled，与 sea-orm 带的 libsqlite3-sys 同一版）。
- `image/docs/idp.md` 加一节；check-tree 第 65 条。

## 在 VM 上验收

见实施时给出的步骤：同一 VM 上依次验证正常登录、首次登录、Chrome 已开着、输错邮箱再换人登录、取消后换人登录、访客。
