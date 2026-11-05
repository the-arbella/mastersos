# 身份系统（笔记本的 SSO 登录）

笔记本登录走 authd + 它的 OIDC broker（`/usr/libexec/authd-oidc`，镜像构建时从源码编，见 `mkosi.build`；不装 snapd，Ruling 1）。
镜像固定 `MASTERSOS_AUTH_CODE=1`（`authd-oidc.service.d/50-mastersos-auth-code.conf`），所以**学校账号只有一条路**：
登录页的绘制区域打开学校的登录页（卡片），授权码 + PKCE，回调到本机的 broker。

- 学校账号在本机**没有密码**，没有离线登录，也不用手机扫码或设备码。每次登录、每次解锁都走完整验证；学校开了两步验证就每次都要做。
- 卡片里的 Chrome 每次都是一次性配置，不留登录状态。
- 设计：`docs/superpowers/specs/2026-11-01-mastersos-login-screen-design.md`。

MastersOS 只认标准 OIDC，判断账号一律看 `email`，不写任何一家身份系统的专用逻辑。差异全部收在下面的配置项里。

早期以本机密码、离线、设备码、refresh token 为前提的说明与实测，已从这份文档删掉：要查旧行为看 git 历史、`spikes/s1/FINDINGS.md` 与 `lab/results/` 下的验收记录。

## 身份系统必须满足

| 要求 | 为什么 |
|---|---|
| **授权码 + PKCE，允许回环回调** `http://127.0.0.1:48123/callback` | 回调地址写死在补丁 0003，身份系统要逐字登记。broker 只在本机回环上监听 |
| **ID token 里有 `email` 与 `email_verified = true`** | broker 用 `email` 当本机用户名，`email_verified` 不是 `true` 就拒绝（authd-oidc 的 genericprovider）。**`admin_users` 按这个名字认**（Ruling 6）：身份系统若允许用户把邮箱改成别人的、又标成已验证，他就成了管理员。身份系统一侧必须保证 `email` 只能由管理员设，或改了之后要重新验证 |
| **返回的邮箱就是学校主邮箱** | 学校返回的邮箱必须等于请求的账号，否则拒绝。这条防止在学校页面换账号回到别人的桌面，代价是用别名登录也被拒：要告诉学生用学校主邮箱 |
| **公网信任的证书**（见下） | 镜像不带、agent 也不下发任何额外的 CA（Ruling 3） |
| **登录页能在卡片里打开** | 卡片的 Chrome 只放行 issuer 的主机和 `card_hosts`。页面要用别的主机（CDN、上游身份系统）就写进 `card_hosts` |

不需要的：

- **设备码端点**：卡片模式下 broker 不再检查 `device_authorization_endpoint`（补丁 0004）。
- **refresh token**：broker 配置不再申请 `offline_access`，没有刷新令牌时登录不受影响。升级前存在盘上的 refresh token 在下一次卡片登录时被新令牌覆盖。

用户名是全小写的邮箱；`admin_users`、`pam-check` 都按小写比。

域名限制在 broker 里做，`pam-check` 再查一遍：

- **为什么不能只靠 `pam-check`**：authd 在 broker 回 granted 的那一刻就把用户写进自己的数据库（用户名、uid、组），这发生在 PAM 的 account 阶段之前。`pam-check` 拒绝之后这条记录仍然留在机器上（20261105.15 实测：私人账号、别校账号都拿到了 uid）。
- **做法**：broker 的补丁 `0006-allowed-domains.patch` 在启动时读 `broker.conf` 旁边的普通文件 `/etc/authd/oidc/mastersos-allowed-domains`（每行一个域名，`#` 开头的行与空行跳过，不分大小写）。有这个文件时，只有 `allowed_users` 里点名的用户（不分大小写）和用户名最后一个 `@` 之后正好是其中一个域名的账号能通过；其他账号在 broker 回 granted 之前就被拒绝（`Authentication failure: user not allowed in broker configuration`），authd 不建用户、broker 也不留 token。没有这个文件时与上游一样，不过滤。文件在却读不了时 broker 不启动，不会放所有人过去。
- **agent 写什么**：学校的 `[school] allowed_domains` 不为空时，agent 先写域名文件（0644），再写 drop-in `broker.conf.d/10-mastersos.conf`，其中 `allowed_users = ALL, <每个管理员>`（`admin_users` 可以来自别的域名）；为空时不写域名文件，drop-in 照旧是 `allowed_users = ALL`。没有 SSO 时先删 drop-in、再删域名文件。drop-in 里只有上游这个 tag 认得的键（`issuer`、`client_id`、`client_secret`、`allowed_users`）。
- 不合规的域名与管理员名不写进去。域名全都不合规时，域名文件仍然写，只是没有域名：broker 只放点名的管理员（`pam-check` 本来也只放他们），绝不会因为没有文件而放开。
- 域名文件或 drop-in 变了，agent 重启 broker 与 authd（broker 只在启动时读它们）。`authd-oidc.service` 是 `ProtectSystem=strict`：`/etc` 只读、读得到，不需要另开路径。
- **没有选的办法**：把域名写成 drop-in 里的新键（上一版就这样做）：不带这个补丁的 broker 读到不认得的键会拒绝启动，回滚到旧镜像时学校账号登录不了，直到旧版 agent 重写 drop-in；authd-oidc 原生的 `allowed_users` 只认完整的用户名，不认 `*@school`；被拒之后再用 `authctl` 删记录：要在 PAM 拒绝的路径上以 root 再调一个命令，它失败、超时或机器在中途断电都会留下记录，镜像里的 authd 0.6.1 也没有删用户的命令（见下）；authd 自己没有按域名过滤的设置。
- **回滚**（例如 .19 → .18）：旧 broker 不读 `mastersos-allowed-domains`，drop-in 里也只有它认得的键，所以立刻启动，学校账号照常登录。这段时间域名限制只剩旧镜像的 `pam-check`：别的域名的账号又会在 authd 里留下记录，直到再升级。旧版 agent 的 `login` 步骤把 drop-in 改回 `allowed_users = ALL` 并重启一次 broker；域名文件留在原处，旧 broker 不理它。再升级回来时，新 agent 第一次跑 `login` 就重写它（这之前 broker 用的是回滚前留下的名单）。
- 在 143866c7 到这次修改之间从 master 构建的镜像把 `allowed_domains` 写进了 drop-in。新 broker 仍认得这个键（忽略它，只看域名文件），所以从那样的镜像升级也不会停；新 agent 第一次跑 `login` 时把它从 drop-in 去掉。

### 以前留下的记录（IT 手动处理）

修好之前被拒的账号仍在 authd 的数据库里（有 uid）。镜像里的 authd 是 0.6.1：`authctl user` 只有 `lock`、`unlock`、`set-uid`，**没有删除用户的命令**（`authctl user delete` 从 authd 0.7.0 起才有），所以 agent 不自动清理。不要手改 `/var/lib/authd/authd.sqlite3`。IT 在机器上（IT 账号，`sudo`）：

1. 找出 authd 的学校账号：`getent passwd | awk -F: '$1 ~ /@/ {print $1, $3, $6}'`。若列不出来（NSS 不枚举），按面板或学生报告的邮箱逐个查：`getent passwd <邮箱>`。
2. 只处理域名不在学校 `allowed_domains`、也不在 `admin_users` 里的账号。确认它没有登录：`loginctl list-users` 里没有它；确认家目录不存在或为空：`sudo ls -A <家目录>` 没有输出。有文件的不动，交给学校决定。
3. 锁定：`sudo authctl user lock <邮箱>`。锁定的账号即使 broker 放行，authd 也拒绝；记录和 uid 仍在。
4. 升级到带 authd 0.7 的镜像之后，再用 `sudo authctl user delete <邮箱>` 真正删掉。

只许哪几种登录方式、锁定、管理员豁免仍由 PAM 里的 `mastersos-agent pam-check` 决定（spec §6.10 S1）。身份系统一侧也限制（例如 Zitadel 的项目授权）会更干净，两边都做。

`admin_users` 里的管理员（Task 10 的 `pam-check`）：

- **不受登录方式、挂失锁定与域名限制约束**：账号是点名写进去的，例如 `allowed_domains = ["school.ac.th"]` 时 `it@vendor.th` 写进 `admin_users` 照样能登录。只把信得过的账号写进去。
- **管理员都是学校账号（SSO），分组的登录方式里必须有 `sso`**：方式里没有 `sso` 时 agent 删掉 broker 配置，登录界面上根本没有学校账号的入口，管理员也登录不了。发布时会有警告 `admins_without_sso`。
- 名单最多 200 个、`allowed_domains` 最多 200 个（发布时报错）。机器上的登录策略文件放不下时，机器按锁定处理、只放行管理员，面板上 `login` 回报失败。

## 设置里的 `[school.oidc]`

```toml
[school.oidc]
issuer = "https://auth.school.ac.th"
client_id = "394475630609104899"
# 下面两项可选，用到时机器要认得 oidc_card（feature_unsupported 会拦）
client_secret = "..."
card_hosts = ["cdn.school.ac.th"]
# 可选，用到时机器要认得 oidc_idp_hint
idp_hint = "school-sso"
```

| 键 | 说明 |
|---|---|
| `issuer`、`client_id` | 必填，agent 写进 `/etc/authd/oidc/broker.conf.d/10-mastersos.conf`（0600），broker 读镜像自带的骨架 `/etc/authd/oidc/broker.conf` 再叠这个 drop-in |
| `client_secret` | 只给桌面应用也要求带 secret 的身份系统。每台机器都有一份，它不算机密，不要拿真正的机密来填。1 到 512 个可打印 ASCII 字符，不含空格与 `% # ; " ' ` \` |
| `card_hosts` | issuer 之外登录页要用的主机，逐个写完整主机名，最多 20 个。没有通配符，子域名不算在内。留空表示只放行 issuer |
| `idp_hint` | 只在 issuer 是身份代理（例如 Rauthy）、背后接着学校自己的 SSO 时用：填代理里那个上游身份系统的 id，1 到 64 个 `A-Z a-z 0-9 _ -`。卡片在授权地址后加 `idp_hint=<值>`，代理直接跳到上游、不显示选择页；代理不认得的值照常显示选择页。上游的主机要写进 `card_hosts` |

写进机器的 broker 配置只有这几行（没有 `extra_scopes`）：

```ini
[oidc]
issuer = https://auth.school.ac.th
client_id = 394475630609104899

[users]
allowed_users = ALL
```

卡片 Chrome 的策略由 agent 写：`/var/lib/mastersos-public/login-browser/policies/mastersos-login.json`。名单是 issuer、`card_hosts` 和回调地址，其余全部挡掉。过滤器钉死协议、主机（前导点关掉子域名匹配）与端口，默认端口也写出来，例如 `https://.sso.school.ac.th:443`；`card_hosts` 一律是 `https` 的 443。没配 SSO 就删掉策略文件，单元（`ConditionPathExists=`）也就起不来。

`idp_hint` 不进 Chrome 的策略目录：agent 把它写到旁边的 `/var/lib/mastersos-public/login-browser/card.json`（`{"idp_hint": "..."}`，没有这个键或没配 SSO 就删掉），登录界面扩展的 `card.js` 每次打开卡片时读它，经 `card-url.js` 把参数加到 authd 给的授权地址末尾（只加给 `https` 地址、只加一次，`state`、PKCE、`login_hint` 原样不动），再写进 `mastersos-login-url`。authd 不用改。

种子（`seed.toml`）带同样的 `oidc`，新机器在第一个设置包到达前就能登录。**带这几个新键（`client_secret`、`card_hosts`、`idp_hint`）的种子，旧镜像解析不了**：用到它们的学校要用不早于这一版的安装盘。

## 证书：只认公网信任的

- 身份系统（以及前面的 Dex）必须用公网 CA 签的证书（Let's Encrypt 之类）。**镜像不带私有 CA**：正式 profile 的树里没有任何额外的 CA（`tests/check-tree.sh` 第 16 条）；只有 lab profile 带试验 CA。
- 只在校内网的服务器：在我们的域名下给每校一个子域，用 Let's Encrypt 的 **DNS-01** 签证书（不要求服务器能从公网访问）。每校的 `_acme-challenge.<学校>.<我们的域名>` 用 **CNAME 委派**到只能改这一条记录的地方（acme-dns 一类），学校的服务器拿不到我们整个域的改写权。
- `router/idm` 的 Kanidm 现在用 fleetd 自管的 CA 签证书：**换成公网证书之前不能给生产的 MastersOS 机器当身份系统**（换证书是单独的项目）。

## 接入：Zitadel

EIS 的实例 2026-10-31 按下面配置，VM 121 走通过卡片登录（当时 broker 还申请 `offline_access`，去掉之后的真实 Zitadel 登录尚未实测，只有 broker 的单元测试）。

1. 在 Zitadel 的项目里新建应用，类型 **Native**。
2. 授权方式（Grant Types）勾 **Authorization Code**；设备码和 Refresh Token 不需要。认证方式选 **None**（没有 client secret）。
3. Redirect URIs 加 `http://127.0.0.1:48123/callback`。回调是 http，Zitadel 要把应用的 **Development Mode** 打开才收。
4. **不要**开「用户同意」之类的确认页：卡片里看到的应当只有邮箱、密码与学校的两步验证。
5. 默认登录策略会在第一次登录时弹「2-Factor Setup」：在策略里关掉强制，或让用户事先设置好。
6. 用户要有邮箱且已验证；被停用的用户（Deactivate）下一次登录就进不来。
7. 记下 client id；issuer 是实例的根地址（例如 `https://auth.<学校域名>`）。在设置里填 `[school.oidc]` 的 `issuer` 与 `client_id`。`client_secret`、`card_hosts` 都留空：Zitadel 的登录页在 issuer 自己的主机上。配了外部身份提供商并且要跳过去时，把对方的主机写进 `card_hosts`。

待实测：Zitadel 收到 `login_hint` 后是否真的跳过邮箱输入。

## 接入：Google Workspace（未测）

> **这一节完全没有实测，不能照着给学校上线。** 裁定（2026-11-05，David）：笔记本**可以**用 Google 账号登录，`[school.oidc] issuer` 可以直接指向 `https://accounts.google.com`。2026-10-14 的「笔记本永不用 Google 账号登录」裁定作废（11-01 已部分撤销，11-05 完全撤销）。发布检查不再拒绝 `accounts.google.com` 本身（`oidc_issuer_google` 已删），配了 `allowed_domains` 就可以发布出去；`allowed_domains` 为空时发布检查报错 `public_idp_without_allowed_domains` 并拒绝发布（否则全世界任何 Google 账号都能登录）。但 Google 这条路在笔记本上一次都没有跑过：`card_hosts`、`login_hint`、`prompt` 的行为都还要实测。下面只来自对 Google 官方行为的了解。

长期计划：我们托管的服务以后由一个中心签发方（Rauthy）给笔记本发令牌，Google 作为它的上游登录方式之一。这不改变系统本身的中立：学校仍然可以把笔记本直接指向任何 OIDC 签发方，包括 Google、Zitadel、Dex 或自己的服务。

接入时要做的事：

1. 实测下面的待验证项，确定 `card_hosts`。
2. 走通验收后把这一节改成正式步骤。

预计的配置：

1. 在学校的 Google Cloud 项目里配 OAuth 同意屏幕，用户类型 **Internal**（只许本校账号）。
2. 新建 OAuth 客户端，类型 **桌面应用**（Desktop app）。
3. `issuer = "https://accounts.google.com"`，`client_id` 与 `client_secret` 都填。broker 走通用 OIDC，不启用 `withgoogle` 编译选项。
4. `card_hosts` 写实测得到的主机。

待验证：

- 是否必须带 client secret，桌面应用类型是否接受 `http://127.0.0.1:48123/callback` 这个固定端口的回环地址。
- `card_hosts` 到底要哪些主机（静态资源、两步验证、学校自己的 SAML 跳转都可能用到别的主机）。
- Google 是否接受卡片这个受策略限制的 Chrome，还是当作不安全的浏览器拒绝。
- `login_hint` 是否跳过邮箱输入，`ui_locales` 是否生效。
- 卡片发出的 `prompt` 在 Google 上的表现（会不会每次都弹账号选择或同意页）。
- 不带 `offline_access` 时 broker 的行为（Google 不接受这个 scope 写法；单元测试已覆盖没有刷新令牌的情形）。

`allowed_domains` 必须配（发布检查 `public_idp_without_allowed_domains` 强制）：Internal 只限制同意屏幕，机器上的域名限制由 `pam-check` 判。

后续（未做）：`pam-check` 现在只比对邮箱 `@` 之后的后缀。用 Google 时，笔记本还可以再核对 ID 令牌里的 `hd` 声明（Workspace 主域），只认 `hd` 属于 `allowed_domains` 的账号，比只看邮箱后缀更可靠。

Microsoft Entra 不在范围内：镜像编的是通用 provider，它要求 `email_verified`，Entra 默认不发这个声明，接入时要单独设计。

## Kanidm：前面放 Dex

Kanidm 经 Dex 的组合在设备码时代验过（Task 20，`lab/idp/dex/`）；**卡片的授权码回环没有在这个组合上验过**，`lab/idp/dex/config.yaml` 也还是设备码的配置。Kanidm 本身没有设备码端点（上游 kanidm#1523），现在这已不是直接接 Kanidm 的障碍，但直接接也没有验过。

结构不变：Dex 作笔记本面对的 OIDC 提供者，Kanidm 作 Dex 的上游 OIDC 连接器（Dex 在 Kanidm 那边是一个普通的 OAuth2 客户端，可以有 secret，它在服务器上）。broker 的 issuer 是 Dex 的地址，Dex 也必须是公网信任的证书。

1. **Kanidm 里给 Dex 建 OAuth2 客户端**：`kanidm system oauth2 create mastersos-dex "MastersOS Dex" https://<dex 的地址>/`，回调 `https://<dex 的地址>/callback`，scope 映射给允许登录的组：`openid profile email`。**PKCE 保持打开**。Dex 启动时读上游 discovery：要在 Kanidm 打开 PKCE 之后再重启 Dex，顺序反了 Kanidm 会拒绝授权（网页上 `Error Code: InvalidState`，试验网 10-20 实测）。
2. **Dex 的配置**：`issuer` 是笔记本看到的地址；连接器 `type: oidc`、`issuer` 是 Kanidm 的 `https://<kanidm>/oauth2/openid/mastersos-dex`、`insecureSkipEmailVerified: false`（Kanidm 的 `email_verified` 原样传下去）；静态客户端 `mastersos-authd`：`public: true`，`redirectURIs` 要有 `http://127.0.0.1:48123/callback`。
3. **设置**：`[school.oidc] issuer = "https://<dex 的地址>"`、`client_id = "mastersos-authd"`。Kanidm 的登录页在另一个主机上，所以要把 Kanidm 的主机写进 `card_hosts`。

### Dex 的版本

- **用 v2.45.1**。
- **不用 v2.46.x，直到上游 dexidp/dex#5017 修好**：用 SQLite 存储时刷新会把 `/token` 卡死。
- **永远不开 `DEX_SESSIONS_ENABLED`**（v2.46 起的功能开关）：开了之后 Dex 用缓存的身份、不再问 Kanidm，已停用的账号也能通过。

### 会话期限（已不适用于笔记本）

Kanidm 的 `authsession_expiry`、`oauth2_refresh_token_expiry`、Dex 的 `expiry.refreshTokens` 曾经决定笔记本多久要重新登录，因为 broker 每次登录都要刷新令牌。卡片模式下笔记本不用刷新令牌，这些期限不再影响笔记本登录。`lab/idp/` 下的实验脚本与当时的完整分析留在 git 历史里（2026-11-01 之前的这份文档），Kanidm 的行为本身没有变；router 一侧 fleetd 的设定不受影响。

## broker 的补丁

MastersOS 带六个补丁（`patches/authd-oidc/`，按文件名顺序打）。

| 补丁 | 内容 | 现状 |
|---|---|---|
| `0001-reauth-on-refresh-error.patch` | 刷新被拒时重新认证，而不是报错拒绝 | 只在本机密码路径上有用，镜像开着卡片模式时走不到。保留，内容按字节核对 |
| `0002-keep-local-password-after-reauth.patch` | 重新认证后保留本机密码 | 同上 |
| `0003-authorization-code-on-greeter.patch` | `MASTERSOS_AUTH_CODE=1` 时设备码的两个登录方式改走授权码 + PKCE，回调到 `127.0.0.1:48123`（只监听回环；校验 `state`；同时只有一个流程，新的顶掉旧的），带 `login_hint=<邮箱>`。方式的 id 不变；UI 层仍是 `qrcode`，`content` 是授权地址、`code` 为空 | 卡片的基础 |
| `0004-card-only-login.patch` | 见下 | 卡片的基础 |
| `0005-follow-reselected-sign-in.patch` | 同一会话再次选登录方式时，新流程接替旧流程：已经在等旧流程的 `IsAuthenticated` 改等新流程（用新流程的 PKCE verifier 换令牌）；被取消的等待不关掉它跟过去的新流程 | 修重新登录卡在「Signed in. Starting your session…」：authd 0.6.1 的 PAM 模块在 GDM 回显自己的选择时会再选一次（canonical/authd#1121，authd 0.7.0 修了），`IsAuthenticated` 落在两次选择之间就会一直等已关掉的旧监听，而卡片里的页面回调到新监听（VM 123，2026-11-05）。自带测试 `TestMastersOSAuthCodeWaitFollowsHandOver`、`TestMastersOSAuthCodeCancelledFollowerKeepsNewFlow`、`TestMastersOSAuthCodeHandOverOfNothing`、`TestMastersOSReselectedSignInIsFollowed`、`TestMastersOSCancelledWaitLeavesNewSignIn`。authd 升到带 #1623 的版本后仍无害 |
| `0006-allowed-domains.patch` | broker 启动时读 `broker.conf` 旁边的 `mastersos-allowed-domains`（不是 `broker.conf`、也不在 `broker.conf.d/`：不带补丁的 broker 永远不读它）。有这个文件时只有 `allowed_users` 里点名的用户（不分大小写）和用户名最后一个 `@` 之后正好是其中一个域名的账号能通过，`ALL`、`OWNER` 只对通过的人生效；没有文件时与上游一样；文件读不了时不启动。上游 `TestParseConfig` 的 golden 不含这个字段 | 别的域名的账号在授权之前被拒，authd 不建用户（见上面的「域名限制」）。自带测试 `TestMastersOSAllowedDomainsLimitAllUsers`、`TestMastersOSNoDomainFileKeepsAll`、`TestMastersOSEmptyDomainFileLetsOnlyListedUsers`、`TestMastersOSUnreadableDomainFileFails`、`TestMastersOSAllowedDomainsWithoutAll`、`TestMastersOSAllowedDomainsSurviveClone`、`TestMastersOSDomainFileIsOutsideTheConfig`、`TestMastersOSLegacyDomainsKeyIsIgnored`、`TestMastersOSOtherDomainIsDeniedBeforeGrant`、`TestMastersOSSchoolDomainIsGranted` |

`0004` 在 `MASTERSOS_AUTH_CODE=1` 时生效：

- 不提供本机密码方式（按名字选也被拒），卡片之后不问 `newpassword`。
- 连不上身份系统时 `NewSession` 直接报 `Error connecting to provider`，没有离线登录。登录页按这句话显示断网提示。
- 登录方式不再依赖 `device_authorization_endpoint`。
- 不依赖 refresh token：第二次登录看到缓存里没有刷新令牌，照常走卡片；缓存里过期或带着旧令牌也一样，不会停在「令牌过期」。
- 授权地址带 `ui_locales`：优先用系统语言：先 `/etc/locale.conf`，再 `/etc/default/locale`，最后是进程的 `LANG`；都没有时才用会话的语言（authd 传来的 `lang`）。读文件是因为登录页改语言时不重启，broker 的环境变量是开机时定的，GDM 的会话进程也还留着旧的 `LANG`（VM 121 从泰文切阿拉伯文时实测）。转成 `th-TH` 这样的标签，转不出来就不传。
- 旧的本机密码哈希在下一次卡片登录成功后删除。

它不能先于锁屏改动发布，否则学校账号解不了锁。

自带测试 `TestMastersOSCardOnly*`、`TestMastersOSBCP47Tags`、`TestMastersOSSystemLangFallsBackToEnvironment`。

怎么带：`mkosi.build` 核对固定的 commit 之后按文件名顺序对每个补丁先 `git apply --check` 再 `git apply`，不再适用就构建失败；`go build` 之前跑补丁自带的 `TestMastersOS*`（在 chroot 里以 root 跑，上游有几个只读目录的用例以 root 跑不过，所以只跑这些）；版本号记成 `0.5.2+mastersos`，`authd-oidc.build-info` 记 `authd_oidc_patches=<文件名>:<sha256> …`。`build.sh` 要求镜像里有这一行、而且与构建树里的 `patches/authd-oidc/` 逐个一致；`tests/check-tree.sh` 第 32 条管目录里只有 `NNNN-<名字>.patch`、每个只改 `authd-oidc-brokers/` 并自带 `TestMastersOS` 测试。换 tag 时补丁要重新做。

## 用户看到的流程

1. 登录页的用户列表点头像，或输入完整邮箱（打名字时框下就给出 “名字@学校域名”，选中即填好地址）。broker 由登录页扩展代选：有 `@` 走学校，没有走本机账号。
2. 绘制区域打开学校的登录页，邮箱已带上（`login_hint`），语言跟系统。验证方式由学校决定。
3. 验证通过进桌面，第一次登录时自动建账号。

取消或 3 分钟无操作回到用户列表。断网时提示连不上学校，带「重试」；Wi-Fi 在顶部可以连。本地 IT 账号从邮箱输入屏的 IT 入口进，密码照旧。

## 卡片的登录交给桌面浏览器

设计：`docs/specs/2026-11-05-browser-signin-handoff-design.md`。卡片里登录学校之后，身份系统设在卡片里的 cookie 交给这个人自己的
桌面 Chrome：桌面上用同一个身份系统单点登录的网站一打开就是登录好的。对哪一家身份系统都一样，学校不用配任何东西。

- 只交给刚用卡片登录的那个学校账号（`gdm-authd` 上名字带 `@`，邮箱等于卡片 URL 的 `login_hint`），并且只在两分钟内。
  每开一次卡片先作废上一次留下的一切；取消、登录被拒、换人、解锁、访客、锁定应用、本机账号都拿不到。
- 只交卡片策略放行的主机（issuer、`card_hosts` 以及往上到可注册域名为止的域 cookie，按公共后缀表，绝不收 `.ac.th`、`.co.th` 这类公共后缀）的 cookie。会话 cookie 改成**交接后 12 小时过期**，
  所以桌面上的学校登录最多维持一个上学日；持久 cookie 保留身份系统自己定的期限。学校想让桌面上的登录更短，在身份系统里缩短会话。
- 桌面 Chrome 已经开着时这次不交（Chrome 占着 cookie 库）：学生在桌面上照常登录一次即可。第一次登录（还没有 Chrome 配置）也交。
- 怎么查：卡片单元的日志 `journalctl -u 'mastersos-login-browser@*'`（`signin-handoff: handed to uid …`）、用户的
  `journalctl --user -u mastersos-signin-import`（`… cookies merged` / `in a new profile` / `nothing was handed over`）。
- 身份系统一侧要注意：卡片里的会话就是桌面上的会话。在身份系统里登出或停用账号，桌面上的单点登录也随之失效。

## 代价与边界

- **没有网就进不去**：学校账号没有离线登录。已经在用的桌面不受断网影响；屏幕回到登录页之后要联网才能回到桌面。
- **每次登录和解锁**都要走学校的验证，这正是公用电脑要的行为。
- **需要网页认证的网络**（酒店、机场）：登录页的 Chrome 打不开认证页，只能进 Guest 完成认证后再回来登录。
- **被停用的账号**下一次登录时被身份系统拒绝。已经开着的会话不会被踢出；挂失的机器用设置里的锁定（Ruling 11），不靠身份系统。
- **没有本机密码**：`passwd`、GNOME 设置都改不了学校账号的密码，改密码在学校的系统里做。
- 别的域名的账号由 broker 在授权之前拒绝，不留记录（补丁 0006；回滚到旧镜像期间除外）。只在 PAM 里被拒的人（锁定的机器上不是管理员的本校账号）仍会在 authd 的数据库里留下一条记录（S1）。

## 镜像里的东西

| 路径 | 内容 |
|---|---|
| `/usr/libexec/authd-oidc` | broker（authd 仓库 `authd-oidc-brokers/`，tag 与 commit 写死在 `mkosi.build`，带 `patches/authd-oidc/` 的补丁、`authd-oidc version` 报 `0.5.2+mastersos`；构建来源（含 `authd_oidc_patches=` 每个补丁的 sha256）在 `/usr/lib/mastersos/authd-oidc.build-info` 与 `build-info.txt`） |
| `/etc/authd/brokers.d/oidc.conf`（镜像里是 `/usr/lib/mastersos/authd/oidc-broker.conf`，agent 只在学校配好 SSO 时拷过去） | 向 authd 注册 broker（总线名 `com.ubuntu.authd.Oidc`、对象 `/com/ubuntu/authd/Oidc`，照上游 snap） |
| `/etc/authd/oidc/broker.conf` | 骨架（0600，跟着镜像走）：没有 issuer，`allowed_users = ALL` |
| `/etc/authd/oidc/broker.conf.d/` | 0700，agent 写 `10-mastersos.conf`（0600）。目录空时 broker 不启动（`ConditionDirectoryNotEmpty=`） |
| `/etc/authd/oidc/mastersos-allowed-domains` | 0644，agent 写学校的 `allowed_domains`（每行一个），学校没设域名或没有 SSO 时删掉。broker（补丁 0006）启动时读；不在 `broker.conf.d/` 里，不带补丁的 broker 不读它 |
| `/var/lib/authd-oidc/` | broker 的数据（token 缓存），0700 |
| `authd-oidc.service` | D-Bus 激活，`ProtectSystem=strict`、只能写自己的状态目录、没有任何 capability |
| `/usr/share/dbus-1/system.d/com.ubuntu.authd.Oidc.conf` | 系统总线策略：只有 root 能拥有这个名字、只有 root（authd）能调它 |
