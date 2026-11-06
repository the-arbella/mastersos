# 锁定应用的 ChromeOS 伪装（`platform`）与注入脚本（`inject`）

**状态：** 设计与实现在分支 `kiosk-testnav-mock`；VM 实测未做（VM 都被占着）。取代
`2026-11-06-testnav-chromeos-mock.md` 的 §3（按厂商写死在考试扩展里的 TestNav mock）；那份文档的检测分析（§2）仍然有效。

**裁定（David，2026-11-06）：** 考试扩展不再按厂商或应用写 mock，改成两件通用的东西：

1. 通用的 ChromeOS 伪装：锁定应用写 `platform = "chromeos"`，页面在 JS 层与 HTTP 层看到的平台都像 ChromeOS；
2. 通用的注入：锁定应用写 `inject = "files/<名>.js"`，IT 自己写的脚本（在签名的设置包里）在这个应用放行的网站上、
   页面任何脚本之前、在页面的 JS 世界里运行。

理由：我们本身就是真正的 kiosk（锁定会话、一次性 profile、URL 放行名单、系统键封锁），伪装只是因为考试厂商的生态里
还没有「MastersOS」这一项。

**底线：不伪造任何校验令牌或设备证明。** Verified Access（`enterprise.platformKeys.challengeKey`）、App Check 的令牌、
任何要 TPM 或 Google 签名的东西，我们不假造、不转发、不重放；考试扩展与样例脚本对这类请求一律回「本平台不支持」。
伪装只让页面**看到的平台**（UA、client hints、`userAgentData`）像 ChromeOS。注入脚本由 IT 写、IT 签名发布，
本文的样例遵守同一条底线；有人写违反它的脚本，是学校自己的事，扩展不替它把关，但我们不提供这类样例。

## 1. 设置格式

`[config.apps.kiosk.<id>]` 加两个键：

| 键 | 类型 | 缺省 | 允许的值 | 说明 |
|---|---|---|---|---|
| `platform` | 字符串 | 不伪装 | `"chromeos"` | 只用于 `url` 应用、不与 `pwa = true`、不与 `user_agent` 同时写 |
| `inject` | 字符串 | 不注入 | `files/…` 里一个 `.js` 文件，UTF-8，至多 64 KiB | 只用于 `url` 应用、不与 `pwa = true` 同时写 |

- **与 `user_agent` 的关系：** 互斥。`user_agent` 只是 Chrome 的 `--user-agent` 参数（§2：它改不了 `userAgentData` 与
  `Sec-CH-UA-Platform`，而且一改就把 `fullVersionList` 清空），留着给「只认 UA 串」的网站；要像 ChromeOS 就写
  `platform`，两个都写报 `kiosk_platform_invalid`。旧设置里已有的 `user_agent = "…CrOS…"` 照旧生效。
- **PWA：** 先不支持（`pwa = true` 时 Chrome 用 `--app=<url>` 直接开 PWA 窗口，第一页绕不过 §3 的起始页；要支持得另想
  启动方式）。写了报对应的 `*_invalid`。
- **本地程序（`exec`）：** 没有 Chrome，写了报对应的 `*_invalid`。

新的 issue code：

| code | 级别 | 什么时候 |
|---|---|---|
| `kiosk_platform_invalid` | error | `platform` 不是 `"chromeos"`；写在 `exec` 或 `pwa = true` 的应用上；与 `user_agent` 同时写 |
| `kiosk_inject_invalid` | error | 不是 `files/<名>.js`；文件不在包里；写在 `exec` 或 `pwa = true` 的应用上；（有文件内容时）超过 64 KiB、不是 UTF-8 或含 NUL |

文件内容的规则：`mastersos-bundle` 的 `kiosk::check_inject_source`。设置包检查（`check_text`、云端草稿检查）只看得到文件名，
所以「在包里、`.js`」在 lint 里查；大小与编码在有文件内容的地方查：CLI / MCP 的 `mastersos check`（工作目录里有文件）、
设备上的 agent（拒绝时这个应用跳过、回报失败，与其它校验不过一样），以及云端（后续，§9）。

新的 feature（裁定 14：旧 agent 遇到不认识的键会拒绝整份设置）：

| feature | 用到的键 | `feature_path` |
|---|---|---|
| `kiosk_platform` | 任何一层的任何锁定应用写了 `platform` | `<层>.apps.kiosk.<id>.platform` |
| `kiosk_inject` | 写了 `inject` | `<层>.apps.kiosk.<id>.inject` |

新 agent 在 `manifest_features` 里报这两个；云端照现有的 FleetGap 算法，对没报的机器出 `feature_unsupported`（错误，挡发布）
或 `feature_unsupported_in_use`（警告）。旧镜像不会悄悄忽略：它根本不收这份设置，云端发布前就报出来。

## 2. 实验：哪一层能改什么（2026-11-06，容器里的 Chromium 156，`debian:trixie`，`--headless=new`）

探测页把 `navigator.userAgent`、`appVersion`、`platform`、`userAgentData.platform`、`getHighEntropyValues(...)`、
专用 Worker 里的 `navigator`，以及服务器收到的主框架请求头与 `fetch` 请求头都回报给本机的回声服务器。扩展一律用策略
`ExtensionInstallForcelist` 从 `file://` 强制安装（与锁定会话同一条路；Chromium 156 的 `--load-extension` 已经不生效）。

| 做法 | JS `userAgent` / `appVersion` | JS `userAgentData` | HTTP `User-Agent` | `Sec-CH-UA-Platform` | 其它 |
|---|---|---|---|---|---|
| 什么都不做 | Linux | `Linux` | Linux | `"Linux"` | `fullVersionList` 是真的 |
| `--user-agent=<CrOS 串>` | CrOS | **仍是 `Linux`** | CrOS | **仍是 `"Linux"`** | **`fullVersionList` 变成 `[]`、`uaFullVersion` 变成 `""`**：页面一查就知道 UA 被改过 |
| DNR `modifyHeaders` `set`：`user-agent`、`sec-ch-ua-platform`、`sec-ch-ua-platform-version` | 不变 | 不变 | CrOS | `"Chrome OS"` | `Sec-CH-UA-Platform-Version` 也加上了。**`sec-ch-ua-*` 能改** |
| DNR 规则没写 `resourceTypes` | — | — | 只有子资源改了 | 只有子资源改了 | DNR 缺省**不匹配 `main_frame`**，要显式写上 |
| MAIN 世界内容脚本（改 `Navigator.prototype` 与 `NavigatorUAData.prototype`） | 改得了 | 改得了 | — | — | Worker 里的 `navigator` 改不到 |

结论：

1. 伪装**不靠 `--user-agent`**：它只改两样，还把高熵版本号清空，自相矛盾的样子比不改更显眼。
2. HTTP 层用考试扩展的 **DNR 会话规则**（`updateSessionRules`）改 `User-Agent`、`Sec-CH-UA-Platform`、
   `Sec-CH-UA-Platform-Version`，`resourceTypes` 列全（含 `main_frame`、`sub_frame`），`requestDomains` 是这个应用放行的主机。
3. JS 层用 MAIN 世界的内容脚本改 `navigator` 的几处 getter，数值与 DNR 规则同一个公式（§4），两层一致。
4. 两样都要在**第一页的第一个请求之前**就位（§3）。

## 3. 第一页的时序

### 3.1 现在锁定会话怎么起 Chrome

`mastersos-kiosk run <id>` 读 `PUBLIC_DIR/<id>/launch.json`，起
`google-chrome-stable --kiosk --no-first-run --user-data-dir=<家>/.kiosk-chrome [--user-agent=…] <url>`。家目录是每次会话
新建的 tmpfs，所以 profile 每次都是空的；策略目录由 `pam_namespace` 换成这个应用自己的
`PUBLIC_DIR/<id>/policies/`（`URLBlocklist ["*"]` + 放行名单、强制安装考试扩展与 `extensions`）。Chrome 退出就重开
（60 秒内 5 次改开错误页）。考试扩展从 `file:///usr/lib/mastersos/kiosk-ext/updates.xml` 安装，大约在 Chrome 起来 0.1–0.3 秒后
才装好——**第一页的导航早已发出**。NWEA 的内置 mock 靠「装上时重新加载已开的标签页」补救，页面已经加载过一次。

### 3.2 排除掉的做法

| 做法 | 为什么不行 |
|---|---|
| 静态内容脚本（manifest 里写死） | 平台脚本可以，但只能写死主机；IT 的脚本不在考试扩展的包里（扩展是镜像里签好名的 CRX） |
| `chrome.userScripts`（能注册任意代码） | Chrome 138 起每个扩展要用户在扩展详情页手动打开「Allow User Scripts」，没有策略能替强制安装的扩展打开 |
| `chrome.scripting.registerContentScripts` | 只收扩展包里的文件，不收代码字符串；而且是异步的，第一页早已开始 |
| `executeScript` + `webNavigation.onCommitted` | 不保证早于页面脚本；`new Function` 还受页面 CSP 管 |
| 隔离世界脚本往页面插 `<script>` | 受页面 CSP（`script-src` 没有 `unsafe-inline` 就不执行），而且拿脚本内容要异步 |
| `--user-agent` | §2 |
| 不加载第一页，等扩展装好再开 | 正是下面的做法；但「等」要有东西等，Chrome 本身不会等 |

### 3.3 做法：起始页 + 助手扩展

写了 `platform` 或 `inject` 的应用，Chrome 不直接开 `url`，而是开考试扩展里的**起始页**：

```
chrome-extension://<考试扩展 id>/start.html#<JSON>
```

JSON（agent 写进 `launch.json` 的 `start`）：`{"v":1,"url":"<url>","hosts":["<放行主机>",…],"platform":"chromeos"|null,"helper":"<助手 id>"|null}`。

1. **扩展还没装上时**，这一页打不开（Chrome 显示错误页，标签页的地址仍是它）。考试扩展装上时（`onInstalled`，`install`）
   找出地址是自己 `start.html` 的标签页并重新加载。实验里全新 profile 从启动到目标页加载约 0.1 秒。
2. `start.js` 把 hash 原样发给后台 `{cmd:"launch", config}`。后台只认自己扩展的 `start.html` 发来的（`sender.url`），
   逐项校验（`url` 是 https、`hosts` 是主机名、`helper` 是扩展 id……），然后：
   - `platform = "chromeos"`：写 DNR 会话规则（§2 结论 2），注册 MAIN 世界的 `platform/chromeos.js`
     （`registerContentScripts`，`persistAcrossSessions: false`、`allFrames`、`matchOriginAsFallback`、`document_start`，
     `matches` 是 `https://<主机>/*` 与 `https://*.<主机>/*`）；
   - 有 `helper`：注册隔离世界的通用 `relay.js`（§6），并每 100 毫秒问一次助手扩展 `{cmd:"ping"}`，最多 15 秒；
   - 都好了才 `chrome.tabs.update(tab, {url})`。
3. 任何一步失败（校验不过、注册失败、15 秒等不到助手），起始页显示「This app could not start. Please ask a teacher.」与
   「Try again」「Exit」两个按钮（Exit 走与菜单同一个 `{cmd:"exit"}`）。**失败就不开考试页**：IT 要求的伪装或脚本没就位时
   让考试页以为自己在 Linux 上，比停在这里更糟。
4. Chrome 在会话里重开（崩溃、关窗）时又从起始页走一遍；会话规则与注册的脚本只活在这一次浏览器会话里，正好重新写。

起始页不是 `web_accessible_resources`，网页打不开它、也伪造不了它的消息；`URLBlocklist ["*"]` 之下由策略的放行名单单独
放行 `chrome-extension://<考试扩展 id>`（只在应用写了 `platform` 或 `inject` 时加）。实验（同样的阻止名单）：全新 profile、
同一 profile 重开两种情况，主框架与 `fetch` 的请求头都是 ChromeOS 的，平台脚本与注入脚本都在页面第一行脚本之前跑过。

没写 `platform` 也没写 `inject` 的应用，启动方式与策略**一点不变**。

### 3.4 助手扩展：IT 的脚本怎么进 Chrome

IT 的脚本必须是某个扩展包里的文件、由 manifest 静态声明，才能保证 `document_start` 早于页面脚本（§3.2）。考试扩展的包
是镜像里签好的，加不了文件，所以 **agent 在设备上为每个写了 `inject` 的应用生成一个助手扩展**：

- 内容：`manifest.json`（MV3；`content_scripts` 一项：`js: ["inject.js"]`、`world: "MAIN"`、`run_at: "document_start"`、
  `all_frames: true`、`match_origin_as_fallback: true`，`matches` 同上；`background.service_worker: "ping.js"`；没有任何
  `permissions`、`host_permissions`、`web_accessible_resources`），`inject.js`（设置包里那个文件，一字不改），`ping.js`
  （只回答考试扩展 id 发来的 `{cmd:"ping"}`）。
- 打包：CRX3，zip 用 stored（不压缩），签名用 ECDSA P-256（`ring`；Chrome 的 CRX3 校验认 `sha256_with_ecdsa`，实验里装上了）。
  钥匙每个应用一把，第一次用到时生成，存在 `/var/lib/mastersos-system/kiosk-inject/<id>.p8`（root 0600，`var_dir` 本身 0700）；
  扩展 id 由公钥算出，所以同一个应用的 id 一直不变。钥匙只证明「这个 CRX 没被改过」，不是信任根：脚本的来源是签名的设置包，
  能改 `PUBLIC_DIR` 的已经是 root。删掉应用时钥匙一并删掉。
- 放在 `PUBLIC_DIR/<id>/inject/`：`helper.crx` 与 `updates.xml`（`codebase` 是 `file:///var/lib/mastersos-public/kiosk/<id>/inject/helper.crx`），
  root 0644；策略的 `ExtensionSettings` 与 `ExtensionInstallForcelist` 加上它（与考试扩展同样从 `file://` 强制安装）。
- 内容（脚本、主机、考试扩展 id）没变就不重写：`inject/source.sha256` 记着上一次的摘要。ECDSA 签名每次不同，不比较 CRX 本身。
- 不写 `inject` 的应用，`inject/` 整个删掉。

为什么不是「考试扩展注入」：讨论时的说法是「设备把 agent 解出来的文件交给考试扩展注入」。考试扩展做得到的只有
`registerContentScripts`（只收包里的文件）与 `userScripts`（要人手打开开关），都放不进任意脚本；所以交接改成「agent 把文件
包成助手扩展，考试扩展的起始页等它装好」。对 IT 与设置格式没有区别。

## 4. ChromeOS 伪装的内容

数值（JS 与 DNR 用同一套公式，`platform/chromeos.js` 与 `background.js` 各有一份，测试核对两份一致）：

- **UA**：真 UA 里的 `(X11; Linux <arch>)` 换成 `(X11; CrOS <arch> 14541.0.0)`，其余照旧（Chrome 的版本号就是真的）。
  `14541.0.0` 是 Chrome UA 精简（UA reduction）之后 ChromeOS 冻结的平台段，真 Chromebook 的 UA 里就是它。`<arch>` 沿用真 UA 的
  （`x86_64`、`aarch64`）。
- **`appVersion`**：同样替换。
- **`navigator.platform`**：不改，真 Chromebook 上也是 `Linux x86_64`。
- **`navigator.userAgentData`**：`platform` → `"Chrome OS"`；`getHighEntropyValues()` 的结果里 `platform` → `"Chrome OS"`、
  `platformVersion` → ChromeOS 版本（下一条），其余（`brands`、`fullVersionList`、`architecture`、`bitness`、`model`、
  `mobile`、`wow64`、`formFactors`）照真的——ChromeOS 上的 Chrome 这些值与 Linux 上相同；`toJSON()` 同样替换。
- **ChromeOS 版本（`platformVersion`）**：`<build>.0.0`，`build = 15662 + round((major − 120) × 37.3)`（M120 → 15662，大约每个里程碑
  多 37）。这是近似：真版本号的补丁位与里程碑的对应只在 Google 的发布表里，页面要是拿它逐一对照就会发现。
- **HTTP**：`User-Agent` = 上面的 UA，`Sec-CH-UA-Platform: "Chrome OS"`，`Sec-CH-UA-Platform-Version: "<build>.0.0"`。与真
  Chrome 的一点区别：真 Chrome 只在网站要过（`Accept-CH`）之后才发 `-Platform-Version`，DNR 不能按「请求里有没有这个头」
  决定，我们每个请求都发。不发更糟：网站要了，Linux 上的 Chrome 会发内核版本（如 `"6.8.0"`）。
- **不露痕迹**：改过的 getter 与函数的 `toString()` 返回与原生相同的 `function get userAgent() { [native code] }` 样子；
  属性仍在原型上（不在 `navigator` 实例上），`Object.getOwnPropertyDescriptor(navigator, "userAgent")` 仍是 `undefined`。

### 4.1 其它 ChromeOS 与 Linux 的差别

| 差别 | 页面看得到吗 | 处理 |
|---|---|---|
| Worker / SharedWorker / Service Worker 里的 `navigator.userAgent`、`userAgentData` | 看得到（实验确认没改） | **没补**：MAIN 世界脚本进不了 Worker。它们发的请求经过 DNR，请求头是对的。需要时 `inject` 可以自己包 `Worker` 构造函数 |
| `chrome.*` 的 ChromeOS 专属 API（`chrome.audio`、`enterprise.*`、`accessibilityFeatures`） | 只有扩展看得到 | 不补；厂商扩展问到的由 `inject` 截在页面这一侧回答（TestNav 样例），设备证明永远不伪造（底线） |
| 字体（ChromeOS 带 Roboto、Noto 全套） | 用 canvas / 字体探测看得到 | 不补；镜像里本来就有 Noto |
| `speechSynthesis.getVoices()`（ChromeOS 有 Google 的本地语音） | 看得到 | 不补 |
| WebGL 的 `UNMASKED_RENDERER`、`hardwareConcurrency`、`deviceMemory` | 看得到，但 Chromebook 本身就五花八门 | 不补 |
| 屏幕、触屏、`matchMedia` | 与硬件有关，Chromebook 本身就五花八门 | 不补 |
| 媒体编解码器（`MediaSource.isTypeSupported`） | 看得到，Google Chrome 在两边基本相同 | 不补 |
| `navigator.keyboard`、按键码 | ChromeOS 的搜索键、顶排键 | 不补 |
| 键盘快捷键、窗口（kiosk 全屏） | 锁定会话已经全屏、封住系统键 | 已有 |

## 5. 内置的 NWEA mock：保留、标为弃用

`mock/nwea/` 仍在考试扩展里、行为不变（学校明天要在 .15 上用）。README 与 `manifest.json` 的说明写明弃用：新设置请用
`inject = "files/nwea.js"`（`examples/kiosk-inject/nwea.js` 是等价的脚本，退出走 §6 的通用接口）。两个都写时 NWEA 的页面会被
两份脚本各改一次：样例脚本先看 `window.isKioskChromium` 是否已有，有就不再装。之后一个版本再删内置的。

TestNav 的内置 mock（考试扩展 1.3.0 的 `mock/testnav/`）**删掉**，改成 `examples/kiosk-inject/testnav.js`。

## 6. 通用的退出接口

`inject` 脚本跑在页面世界，没有扩展 API。要结束锁定会话（例如考试客户端的「关闭应用」）时：

```js
window.postMessage({ type: "MASTERSOS_MOCK_EXIT" }, location.origin);
```

考试扩展为写了 `inject` 的应用注册隔离世界的 `relay.js`（与 NWEA 的同一条规则）：只认同一个窗口发来、同源、恰好
`{type: "MASTERSOS_MOCK_EXIT"}` 一个键的消息，转成后台的 `{cmd:"exit"}`，与「Exit」按钮同一条路（native messaging →
`mastersos-agent kiosk exit-host`）。页面上的任何脚本都能用它——它能做的只是结束学生自己的锁定会话、回到登录界面，与学生
自己点 Exit 相同。没有别的接口：注入脚本拿不到求助、截图或任何设备信息。

## 7. 安全

- 注入脚本的权限 = 放行网站上页面自己的权限：它与页面同一个 JS 世界，不比页面多拿任何东西。助手扩展没有权限、没有可访问资源。
- 考试扩展新加的权限：`scripting`、`declarativeNetRequest`、`tabs`（读自己起始页的地址）、`host_permissions: ["<all_urls>"]`
  （注册脚本与 DNR 规则要对应的主机权限；实际只用在应用的放行主机上，会话里也只开得了这些）。它是强制安装、不弹权限提示。
- 起始页的配置只来自 Chrome 的命令行（`launch.json`，root 写）；网页打不开起始页，也发不了 `{cmd:"launch"}`（后台查 `sender.url`
  是自己的 `start.html`）。即使有人能改它，能做的也只是在放行名单里的主机上伪装平台。
- 底线见开头：不伪造令牌、证明；样例对 Verified Access 一律回「不支持」。

## 8. 改了的地方

- `core/mastersos-bundle`：`KioskApp.platform`、`KioskApp.inject`；`kiosk::check` 的规则、`chrome_policy` 加
  `chrome-extension://<考试扩展>` 放行与助手扩展的强制安装（`InjectHelper`）、`check_inject_source`、`gate_hosts`；
  lint 的「在包里」；`lint_inject_sources`（有文件内容时查大小与编码，CLI 用）；`FEATURE_KIOSK_PLATFORM`、`FEATURE_KIOSK_INJECT`、
  `features_used`、`feature_path`；`spec.rs` 的 issue code；`docs/manifest-spec.md`（字段表、两个 code 的段落与例子）与
  `skills/mastersos-admin/reference/settings-reference.md`（同一份）。
- `core/mastersos-agent`：`report.rs` 的 `SUPPORTED_FEATURES`；`system/kiosk.rs` 读包里的脚本、生成助手扩展、写 `launch.json`
  的 `start`；`system/kiosk_inject.rs`（CRX3、zip、钥匙）；`kiosk_session.rs` 有 `start` 时开起始页。
- `core/mastersos-mcp`：`mastersos check` 调 `lint_inject_sources`。
- `kiosk-extension`：1.4.0；删 `mock/testnav/`；加 `start.html`、`start.js`、`platform/chromeos.js`、`relay.js`；后台处理
  `launch`；`mock/nwea/` 标弃用。
- `examples/kiosk-inject/`：`testnav.js`、`nwea.js`（不打进扩展；`kiosk-extension/tests/` 里有它们的测试）。

## 9. 云端的后续（云端钉着本仓库的一个 commit）

1. 钉到包含本改动的 commit 之后，`mastersos spec` / schema 里就有 `platform`、`inject` 两个键与两个 code；设置编辑器的表单
   （如果有锁定应用的表单）加这两项，`platform` 是只有 `chromeos` 一项的选择。
2. 草稿检查：`check_text` 已经报「不是 `files/….js`、不在包里」。云端存着文件内容，请在上传 / 发布前对写了 `inject` 的文件调
   `mastersos_bundle::lint_inject_sources(&manifest, |name| 文件内容)`，把它返回的 `kiosk_inject_invalid` 一并显示（超过 64 KiB、
   不是 UTF-8）。
3. FleetGap：新 feature 名 `kiosk_platform`、`kiosk_inject`，机器报了才算懂；算法不用改（字符串从 `features_used` 来）。
4. 两个新 code 的界面文案与翻译：参数 `field`（与其它 `kiosk_*_invalid` 一样，消息由 `kiosk::check` 给）；`lint_inject_sources`
   的那条带 `app_id`、`file`。
5. 已发布到 .15 的 v5 里，`testnav` 写的是 `user_agent = "…CrOS…Chrome/157…"`：新镜像上照旧能用；要换成本文的做法，
   改成下面 §10 的样例并重新发布（需要机器已是新镜像，否则 `feature_unsupported` 会挡）。

## 10. 样例：TestNav

设置（`files/testnav.js` 就是 `examples/kiosk-inject/testnav.js`，原样放进设置包的 `files/`）：

```toml
[config.apps.kiosk.testnav]
name = "TestNav"
url = "https://home.testnav.com/"
allow = ["testnav.com", "adamexam.com", "act.org", "actaspire.org", "clever.com", "classlink.com", "schoology.com", "pearsontestcontent.com"]
platform = "chromeos"
inject = "files/testnav.js"

[[config.apps.kiosk.testnav.extensions]]
id = "gjhfdhjfmmgldldpmfdmbddbegbachgo"
update_url = "https://download.testnav.com/chrome-extension/update-manifest.xml"
```

`testnav.js` 做的事（与 1.3.0 内置 mock 相同，只是 UA 的 CrOS 部分改由 `platform` 给）：在 JS 的 UA 末尾加
` TestNavPWAKiosk/1.15.7`（只加在 `navigator` 实例上、不可改，挡住 Pearson 扩展自己的追加）；包装 `chrome.runtime.sendMessage`，
发给 TestNav 扩展的 `checkKioskModeStatus` 回 `kioskMode: true`、两个无障碍方法回成功、音量与 `generateAppValidityCheckToken`
回「not supported on this platform」（底线：不伪造、不转发令牌请求）、`closeApp` 走 §6 的退出，其余转给真的扩展。

NWEA：

```toml
[config.apps.kiosk.nwea-map]
name = "NWEA MAP Growth"
url = "https://test.mapnwea.org/"
allow = ["nwea.org", "mapnwea.org"]
inject = "files/nwea.js"
```

## 11. 没做 / 要实测的

- VM 实测（真的 Google Chrome、真的锁定会话、TestNav 与 NWEA 各开一次）：起始页在 `--kiosk` 下的样子、全新 tmpfs profile 上
  助手扩展与考试扩展谁先装好、`Sec-CH-UA-*` 在真 Google Chrome 上与 Chromium 是否一样。
- PWA 的伪装与注入。
- Worker 里的 `navigator`。
