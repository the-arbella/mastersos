# Pearson TestNav 的 ChromeOS 模拟环境（mock env）

**状态：** 阶段 1（离线分析）与阶段 2（`kiosk-extension/mock/testnav/`）完成；阶段 3（VM 124 实测）未做。

**2026-11-06 取代：** §3 的做法（`kiosk-extension/mock/testnav/` 写死在考试扩展里）已被通用的 `platform = "chromeos"` 与
`inject = "files/<名>.js"` 取代（设计 `docs/specs/2026-11-06-kiosk-platform-inject-design.md`，设置样例在它的 §10）。
`mock/testnav/` 已删，页面脚本改写成样例 `examples/kiosk-inject/testnav.js`。本文的 §1–§2（页面与 Pearson 扩展读什么）仍然有效。

**目标：** 让 Pearson TestNav（州考、ACT 等用的考试客户端）在 MastersOS 的锁定会话（`[config.apps.kiosk]` 的网页应用）里，
按「TestNav Web App for ChromeOS」的方式运行：页面认为自己在受管 Chromebook 的 kiosk 里。做法与 NWEA 一样（考试扩展
`kiosk-extension/README.md`「按应用的模拟环境」）：读页面与厂商扩展的源码，只给出页面实际读到的东西。

**来源（2026-11-06 抓取，只存不执行，Pearson 的代码不入库）：**

| 东西 | 版本 / 地址 |
|---|---|
| TestNav 扩展 | `gjhfdhjfmmgldldpmfdmbddbegbachgo` 1.15.7，`https://download.testnav.com/chrome-extension/update-manifest.xml` → `extension.crx`（CRX3，sha256 `8b5a9794…cd897`）。脚本经 javascript-obfuscator 混淆（字符串数组 + 旋转），用一个只做静态还原的 Python 脚本读，没有运行 |
| 首页 | `https://home.testnav.com/`（S3 + CloudFront）与 `javascripts/startpage.js`、`manifest.json`、`service-worker.js` |
| App API | `https://app.testnav.com/api.js`（`TestNav 8 App API v3.5.14`），首页与每个客户站点都加载它 |
| 考试客户端 | 练习站 `https://ref.testnav.com/client/`：`app.bundle.js` 与分块 `globals`、`TestEngine`、`es6_main` 等 |
| Linux 客户端 | `testnav-1.15.7.deb`（sha256 `2e06d735…612fc`），`ar` + `tar` 解开，没装、没运行 |
| Pearson 文档 | 「Set Up TestNav on ChromeOS」「TestNav - ChromeOS Managed Devices」「App Check」 |

下文的函数名：扩展里的类名被混淆，用它处理的消息名（`method`）指代；`api.js` 与客户端是压缩过的 webpack 包，用保留下来的
方法名指代。

## 1. 结论

**可行：是（待阶段 3 用一场真的安全考试确认服务器端）。** TestNav 在 ChromeOS 上判断「我是 kiosk 里的 ChromeOS PWA」只看两样：

1. `navigator.userAgent`：有 `CrOS`（ua-parser 认作「Chromium OS」），并带 `TestNavPWA…/<版本>`（版本 ≥ 1.14）；
2. 页面经 `chrome.runtime.sendMessage("gjhfdhjf…", {method: "checkKioskModeStatus"})` 问 TestNav 扩展，回 `{success: true, data: {kioskMode: true}}`。

两样都在页面的 JS 环境里，MAIN 世界的脚本都能给。**没有设备证明**：扩展里有 Verified Access（`enterprise.platformKeys.challengeKey`）
的代码，但 App API 在 ChromeOS PWA 这条路上从不调用它（见 §2.4）；Pearson 文档的「只支持受管 Chromebook」是人工核对托管图标，
不是程序检查（kiosk 应用本来就只在受管设备的登录界面出现）。

**唯一跑在 Pearson 扩展内部的检查**是 `checkKioskModeStatus` 的答案（它的 service worker 看 `chrome.audio.getMute` 能不能用，
只有 ChromeOS 的 kiosk 会话能），在 Linux 的 Chrome 上永远是 `false`。但页面问它要经过页面世界里的 `chrome.runtime.sendMessage`，
我们的 MAIN 世界脚本在消息出页面之前就截下、自己回答；扩展内部的检查我们碰不到，也不用碰。

## 2. 检测机制（逐项）

### 2.1 检查清单

| # | 位置 | 读什么 | `--user-agent`（应用的 `user_agent`）给一个 CrOS 串够不够 | 要不要 MAIN 世界的垫片 | 请求头 |
|---|---|---|---|---|---|
| C1 | 页面：`api.js` 的 client context 服务 `checkClientContext` → `getOsDetails` | ua-parser 解析 `navigator.userAgent` 的 OS：`CrOS <arch> <build>` → `Chromium OS` | 够 | 不要（若设了 `user_agent`）；没设时要，`page.js` 改写 | — |
| C2 | 页面：同上 `getAppVersion`、`isClientContextSupported` | UA 里 `TestNav…(PWA\|PWAKiosk\|…)/<版本>`，版本不低于 `supportedAppVersions.minVersion`（1.14） | 够，但要把 ` TestNavPWAKiosk/1.15.7` 写进 `user_agent` | 同上 | — |
| C3 | 页面：同上 `isChromeExtensionInstalled` | UA 里有 `TestNavPWA`（不是去问扩展在不在） | 同 C2 | 同上 | — |
| C4 | 页面：`deriveAppType` | 由 C1–C3 得 `chromeOsPwa`；之后 `getAppCommunicator` 选「ChromeOS 扩展」通信器 | — | — | — |
| C5 | 页面经扩展：ChromeOS 扩展通信器的 `checkKioskModeStatus` → 扩展 service worker 的 `checkKioskModeStatus` | 扩展回 `kioskMode`：`chrome.audio` 存在且 `getMute` 成功 | **不够**：答案在扩展里 | **要**：`page.js` 截下这条消息，回 `kioskMode: true` | — |
| C6 | 页面：首页 `startpage.js` 的 `DOMContentLoaded` | UA 有 `CrOS` 且是 Chrome 才注册首页的 service worker、插入 `manifest.json`（PWA 安装要它） | 够 | 同 C1 | — |
| C7 | 页面：客户端 `TestEngine.checkClientContext`、`isPWA`、`createNativeComponent` | C1–C3 的结果 → `NativePWA` 组件 | — | — | — |
| C8 | 页面：客户端 `TN8.utils.isProgressiveWebApp`、`registerServiceWorker` | C3 之后再问 C5；结果是「锁定」（`NativePWA.setLockedStatus`），App Check 的 Kiosk Mode 一项、缩放 / 音量 / 无障碍功能都看它 | 不够 | 要（同 C5） | — |
| C9 | 页面：客户端的版本检查（`checkCrOS`、`checkOSX`… `check`） | UA 有 `cros` 时 Chrome 主版本 ≥ 91（或配置的最小版本）且不是 97 | 够（写死的版本过旧也满足，但见 §6 R3） | 同 C1 | — |
| C10 | 页面：客户端 `detectBrowser`、`isLinux` | UA 里有 `Linux`（且无 `Android`）就当 Linux 浏览器；`navigator.appVersion` 有 `X11` 当 Linux（真 Chromebook 也是） | 够（CrOS 串里没有 `Linux`） | 没设 `user_agent` 时 `page.js` 同时改 `appVersion` | — |
| C11 | 服务器：登录 `POST /api/8.0/login/…` | 正文 `logMsg` = `navigator.userAgent`（`engineAuth` 传进 `Authentication.login`） | 够 | 同 C1 | 这是 JS 的 UA，不是请求头 |
| C12 | 服务器：每个请求 | HTTP `User-Agent` 头：真 Chromebook 上是带 `CrOS`、**不带** `TestNavPWAKiosk` 的 Chrome 串（TestNav 扩展只改 JS 的 UA） | 设了 `user_agent` 时头里是 CrOS；只靠 `page.js` 时头里仍是 `X11; Linux x86_64` | — | **未知**：客户端代码看不出服务器查不查。阶段 3 用安全考试对照（§7 T4） |
| C13 | 服务器：每个 https 请求 | `Sec-CH-UA-Platform`（低熵 client hint，缺省就发）：Chromebook 上是 `"Chrome OS"`，我们是 `"Linux"`；`--user-agent` 不改它 | 不够 | 改不了（请求头；DNR 能改，但没有证据需要） | **未知**，同 C12 |
| C14 | 页面：`navigator.userAgentData` | 只在 OS **不是** ChromeOS 时读（Windows 版本），首页的调试信息只在 Windows TakeATest 时读 | — | 不要 | — |
| C15 | 页面：`navigator.platform` | 只用来认 iPad / iPhone / Mac | — | 不要：Chromebook 上本来就是 `Linux x86_64` | — |

没有找到的东西：`chrome.runtime.getPlatformInfo`、`chrome.system.*`、`chrome.enterprise.deviceAttributes` / `networkingAttributes`、
kiosk 专有的 `chrome.app.runtime`、`getManifest` 检查、Firebase App Check / Play Integrity——扩展与页面里都没有。

### 2.2 页面与扩展怎么说话

- 页面 → 扩展：`api.js` 的扩展命令基类（`execute`）调 `chrome.runtime.sendMessage(<id>, {method, data}, {}, callback)`；扩展的
  `externally_connectable` 是 `<all_urls>`，service worker 的 `onMessageExternal` → `processMessage` → 按 `method` 分派
  （`MethodFactory.create` 的 switch）。回调里先看 `chrome.runtime.lastError`，再看 `response.success` 与 `response.data`。
- 方法全表：`checkKioskModeStatus`、`checkAudioLevel`、`setAudioLevel`、`checkZoomLevel`、`setZoomLevel`、`disableAccessibilityFeatures`、
  `resetAccessibilityFeatures`、`setAllowedNavigationDomains`、`setForbiddenNavigationUrls`、`setProxy`、`proxyFetch`、`clearBrowsingData`、
  `generateAppValidityCheckToken`、`closeApp`。
- 扩展 → 页面：service worker `chrome.tabs.sendMessage` → 隔离世界的 `messenger.js` → `window.postMessage({name: "com.pearson.testnav.app.<事件>", data})`，
  事件只有 `AudioLevelChanged` 与 `NavigationBlocked`。
- 扩展自己的 MAIN 世界脚本 `user-agent.js`：向自己问 `checkKioskModeStatus`，异步地把 ` TestNavPWAKiosk/1.15.7`（锁定）或 ` TestNavPWA/1.15.7`
  （未锁定）接到 `navigator.userAgent` 后面。它在 MAIN 世界，所以它的 `chrome.runtime` 就是页面的那个。

### 2.3 扩展在 Linux 的 Chrome 上哪些能用

| 能用（不依赖 ChromeOS） | 不能用（ChromeOS 专有 API） |
|---|---|
| `setAllowedNavigationDomains` / `setForbiddenNavigationUrls`（DNR 会话规则、`webRequest` 拦导航、新标签页被关）、`setZoomLevel` / `checkZoomLevel`（`tabs.setZoom`）、`setProxy`（`chrome.proxy`）、`proxyFetch`、`clearBrowsingData`、断网时的本地错误页、记住上次选的客户站点（`early-redirect.js`，在我们每次全新的 profile 里没用）、触屏与 SSO 弹窗的处理 | `checkKioskModeStatus`（永远 `false`）、`checkAudioLevel` / `setAudioLevel`（`chrome.audio`）、`disableAccessibilityFeatures` / `resetAccessibilityFeatures`（`chrome.accessibilityFeatures`）、`generateAppValidityCheckToken`（`enterprise.platformKeys`） |

`closeApp` 在 Linux 上能用，但做的是 `windows.remove` 关掉所有窗口：锁定会话会把 Chrome 当崩溃重开（Alt+F4 ×5 那条路），所以也要截下。

### 2.4 App Check 与 Verified Access

- Pearson 的「App Check」是**就绪诊断**（登录页菜单里跑：Kiosk Mode、连通、带宽、ProctorCache、进程黑名单、SRF），在 `api.js` 的
  App Check 服务里。Kiosk Mode 一项在 ChromeOS 扩展通信器上落到 `checkKioskModeStatus`（`runKioskDiagnostics` 对它不支持，退回去问 kiosk 状态）。
  客户端 `NativePWA.appCheckKioskMode` 看的是同一个「锁定」状态。都由 C5 的回答决定。
- Verified Access：扩展的 `generateAppValidityCheckToken` 向 Google 的 Verified Access API 要 challenge、用 `enterprise.platformKeys`
  的用户钥匙签名。`api.js` 只在**旧版 ChromeOS 应用**的通信器里、`checkKioskModeStatus(true)` 时调用它；ChromeOS 扩展通信器的
  `checkKioskModeStatus(true)` 固定回 `tokenGenerated: false, reasonForNoToken: "client-context-unsupported"`。客户端也不传
  `true`。**今天没有设备证明**；签名只有受管 Chromebook 的 TPM 钥匙能做，假造不了（§5）。

## 3. 我们的 mock env 给什么（`kiosk-extension/mock/testnav/`）

主机：`*.testnav.com`、`*.adamexam.com`、`*.act.org`、`*.actaspire.org`（首页、`app.testnav.com` 与所有客户站点；SSO 的
clever / classlink / schoology 不需要）。只在顶层框架。

`page.js`（MAIN 世界，`document_start`，早于页面任何脚本）：

1. **UA**：`navigator.userAgent` 里含 `Linux` 的括号段换成 `(X11; CrOS x86_64 16181.61.0)`（已有 `CrOS` 就不动），末尾加
   ` TestNavPWAKiosk/1.15.7`（已有 `TestNavPWA` 就不加）；`navigator.appVersion` 跟着改。两者 `configurable: false`：TestNav 扩展的
   `user-agent.js` 之后再追加会抛错、不生效，所以不会出现「未锁定」的后缀（C1–C3、C6、C9–C11）。Chrome 的版本号沿用真的。
2. **包装 `chrome.runtime.sendMessage`**（没有 `chrome.runtime` 时自己建一个）：发给 `gjhfdhjf…` 的
   - `checkKioskModeStatus` → `{success: true, data: {kioskMode: true}}`（C5、C8）；
   - `disableAccessibilityFeatures` / `resetAccessibilityFeatures` → 成功（ChromeOS 的无障碍功能这里不存在，锁定会话的 dconf 自己管）；
   - `checkAudioLevel` / `setAudioLevel`、`generateAppValidityCheckToken` → 与 TestNav 扩展在非 ChromeOS 上一样的「not supported on this platform」；
     Verified Access **从不转发、从不假造**；
   - `closeApp` → `window.postMessage({type: "MASTERSOS_MOCK_EXIT"})`，`relay.js` 转成后台的 `{cmd:"exit"}`，锁定会话结束（与「Exit」按钮同一条路）；
   - 其余方法与发给别的 id 的消息：转给真的扩展；没装时回调里给 `lastError`「Receiving end does not exist」（与没装扩展的 Chrome 一样）。
   `chrome.runtime` 换成我们的对象（原型指向真的，`lastError` 在我们自己的回调里给我们的，其余时候读真的）；页面换不掉它。
3. 不碰 `navigator.userAgentData`、`navigator.platform`（C14、C15），不拦按键（TestNav 的 ChromeOS 通信器自己拦浏览器的前进 / 后退 / 刷新与缩放键，
   其余是锁定会话的系统键，设计 §4.6）。

`relay.js`（隔离世界）：与 NWEA 的同一条规则，只认同窗口、同源、恰好 `{type: "MASTERSOS_MOCK_EXIT"}`。

后台：`MOCK_TAB_PATTERNS` 加这四个主机（扩展装上时重新加载已经开着的 TestNav 标签页）。不加任何权限。

### 3.1 要不要同时强制安装 Pearson 的扩展：要

不装时页面只拿得到我们的回答：缩放（放大镜等 PNP 工具）、考试中的导航封锁、ProctorCache 的代理（`setProxy` / `proxyFetch`）都失败。
装上之后这些由它在 Linux 上照常做，我们只截下它在 Linux 上答错或不该做的六个方法（§3 第 2 条）。它在 Linux 上的副作用：

- `user-agent.js` 的追加被我们的不可改 UA 挡掉（控制台一条 TypeError，无害）；它向自己问 kiosk 状态时问到的是我们的包装，所以如果它先跑完，追加的也是 `Kiosk`。
- manifest 里的 `audio`、`accessibilityFeatures.modify`、`enterprise.platformKeys` 在 Linux 上是不认识的权限，Chrome 给警告、照装（阶段 3 T1 核对）。
- 它请求的权限很大（`<all_urls>`、`webRequestBlocking`、`proxy`、`browsingData`），而且 `onMessageExternal` 不查发送方：**任何能在这个会话里打开的网页**
  都能让它改代理、`proxyFetch` 任意地址、清浏览数据。锁定会话的 `allow` 名单限住了能打开的网页，这是我们接受它的前提（§6 R1）。

### 3.2 设置样例

```toml
[config.apps.kiosk.testnav]
name = "TestNav"
url = "https://home.testnav.com/"
allow = ["testnav.com", "adamexam.com", "act.org", "actaspire.org", "clever.com", "classlink.com", "schoology.com", "pearsontestcontent.com"]

[[config.apps.kiosk.testnav.extensions]]
id = "gjhfdhjfmmgldldpmfdmbddbegbachgo"
update_url = "https://download.testnav.com/chrome-extension/update-manifest.xml"
```

- `allow` 是 Pearson 的「Additional URL origins」（我们的 `allow` 含子域，`act.org` 盖住 `actonline.act.org`），加上扩展里认作 TestNav 自己的
  内容主机 `pearsontestcontent.com`。扩展里还有 `chime.aws`、`rtpaas.pearson.com`（远程监考的音视频），只在用到时加；其余缺的主机阶段 3 补（V1.3 的做法）。
- `url` 可以直接写学校的客户站点（如 `https://tn.testnav.com/`）：ChromeOS 上扩展会记住上次选的站点，我们每次是新 profile，记不住。
- 先不写 `pwa = true`：首页的 manifest 是页面脚本在 UA 判成 CrOS 之后才插入的，强制安装 PWA 时 Chrome 抓不抓得到要实测（§7 T6）。
- 先不写 `user_agent`：`page.js` 已经给出 JS 看到的 CrOS UA，而且跟着 Chrome 的真版本走。只有 T4 证明服务器查 HTTP 头时，再写
  `user_agent = "Mozilla/5.0 (X11; CrOS x86_64 16181.61.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/<当前主版本>.0.0.0 Safari/537.36"`
  （不带 `TestNavPWAKiosk`：真 Chromebook 的请求头里也没有；`page.js` 照样加在 JS 的 UA 上）。

## 4. Linux 客户端（.deb）：只作对照

- **是什么**：jpackage 打的 Java 应用，自带 JRE 与 JavaFX，浏览器是 **JxBrowser**（TeamDev 的 Chromium 内核，`jxbrowser-linux64.jar` 120 MB）。
  装到 `/opt/testnav/`，入口 `/opt/testnav/bin/testnav`（jpackage 启动器 → `com.pearson.testnav.launch.Launcher`），
  `postinst` 只跑 `xdg-desktop-menu install /opt/testnav/lib/testnav-testnav.desktop`（注册 `tnav:` 协议）。依赖 `libfreetype6`、`pulseaudio-utils`。
  没有 setuid、没有 systemd 单元、不要 root。启动器自己检查更新、下载解到用户目录。
- **页面怎么认它**：UA 带 `TestNavDesktopApp/<版本>`，页面经 `jx_bridge` 调 Java（`jx_getForegroundProcess`、`jx_setBlocklist`、
  `jx_verifyFullScreen`、`jx_getSystemVolume`…），App API 判成 `jxBrowser` 类型。
- **怎么锁**（`LinuxKeyboardWrapper` 等类里的命令）：
  - 用 `gsettings set` 改 GNOME 的键位与锁定项（`org.gnome.desktop.wm.keybindings`、`org.gnome.mutter(.wayland).keybindings`、
    `org.gnome.shell.keybindings`、`settings-daemon.plugins.media-keys`、`desktop.lockdown`、dash-to-dock、tiling-assistant），结束时 `reset-recursively`；
  - 查 `gnome-session` / `gnome-shell` 进程，不在就记「GNOME desktop environment is not active」；
  - 前台进程：`xprop -root _NET_ACTIVE_WINDOW` + `_NET_WM_PID` + `ps`（只在 X11 / XWayland 有效）；进程黑名单；`dbus-monitor --system`（睡眠）；`pactl`（音量）；
  - 读 `/etc/os-release`（Ubuntu ≥ 16.04、Fedora ≥ 33）、`XDG_SESSION_TYPE`、`uname -a`；全屏并遮住副屏。
- **放进我们的锁定会话会怎样**：
  - `exec` 只收 Flatpak id 或 `/usr/` 下的路径，`/opt/testnav/bin/testnav` 是 `kiosk_exec_invalid`；镜像的 `/usr` 只读、不装 .deb，要么打进镜像（每版跟着 Pearson 更新），要么包成 Flatpak（JxBrowser 的沙箱与它的 `ps` / `xprop` / `dbus-monitor` 都要开口子）。
  - 锁定会话是 gnome-kiosk，不是 gnome-shell：它的「GNOME 是否在」检查失败；dconf 的键在 `mastersos-kiosk.d` 里锁着，`gsettings set` 写不进去（这本是好事，键位已经锁好，但它可能因此报错或拒绝开考）。
  - Wayland 下 `xprop` 拿不到前台窗口，前台进程检查可能误报「焦点丢失」。
  - 不需要 sudo，pam_namespace 与 AppArmor 不碍事；但它是一个 300 MB 的、带自己 Chromium 的第二个浏览器，绕过了我们的 Chrome 策略（`URLBlocklist`、扩展、打印等）。
  - 结论：比 mock env 难得多、风险大，只在 Pearson 拒绝 ChromeOS 模拟时考虑。

## 5. 假造不了的

- Verified Access（`enterprise.platformKeys.challengeKey`）：要受管 Chromebook 的 TPM 里、由 Google 认证的钥匙。今天的 PWA 路径不用它；
  哪天 Pearson 在 ChromeOS 扩展通信器里也要 token、服务器端核验，这条路就断了（§6 R2）。
- 请求头的 `Sec-CH-UA-Platform: "Linux"` 与（不设 `user_agent` 时）`User-Agent` 头：能用 DNR 改，但现在没有证据服务器看它们。
- ChromeOS 的系统音量（`chrome.audio`）：TestNav 的音量滑块在我们这里不起作用，学生用键盘的音量键。

## 6. 风险

- **R1 Pearson 扩展的权限面**：`externally_connectable` 是 `<all_urls>`、不查发送方，能改代理、跨域取数据、清数据。只装在 TestNav 的锁定会话里，
  会话只放行 §3.2 的主机；不要把它加进别的应用，也不要放宽这个应用的 `allow`。
- **R2 Pearson 加强检查**：例如在 PWA 路径要 Verified Access token、服务器查 `Sec-CH-UA-Platform`、或扩展改用 `getPlatformInfo` 回答页面。
  App API 每个客户站点在线加载，Pearson 改了我们当天就受影响。阶段 3 之后每学期考前在 lab 跑一次 §7 的清单。
- **R3 版本**：UA 里的 `TestNavPWAKiosk/1.15.7` 是写死的。Pearson 抬高 `supportedAppVersions.minVersion` 时页面会报「app outdated」，要跟着改 `APP_VERSION`。
  若改用 `user_agent`，Chrome 主版本也写死了，Chrome 升级后会落后。
- **R4 条款**：这是让厂商的软件以为自己在它支持的平台上。与 NWEA 一样（裁定 K9），同时联系 Pearson 取得 MastersOS 的正式支持；
  学区若要求只用受管 Chromebook，就按学区的要求办。
- **R5 包装 `chrome.runtime`**：真 Chrome 里 `chrome.runtime` 能不能被替换、原型转发的方法（`connect` 等）会不会「Illegal invocation」，jsdom 测不出（§7 T2）。
  替换失败时退而直接改 `sendMessage`；两者都失败只 `console.warn`，页面就是 Linux 浏览器的样子。

## 7. 阶段 3 要测的（VM 124，`image/lab/kiosk-acceptance.md` §5）

见验收清单 §5 的 T1–T10：扩展装上与权限警告、`chrome.runtime` 的替换、首页「PWA Detected」、App Check 全绿、练习考与一场安全考（`securityLevel` 1）、
HTTP 头对照、缩放 / 音量 / 导航封锁、closeApp 与 Exit、断网错误页、PWA 安装与否。
