# MastersOS 考试扩展

锁定会话（`[group.apps.kiosk]` 的网页 / PWA 应用，设计 `docs/superpowers/specs/2026-10-26-mastersos-kiosk-apps-design.md`
§4.5、§4.7、§4.9）里强制安装的 MV3 扩展。它做两件事：页面右边缘一个浮动的「Options」把手，菜单里「Get help」给学校 IT 发求助单、「Exit」确认后结束锁定会话；以及按应用的模拟环境
（mock env，下文），让只认 ChromeOS 等设备的考试页读到它要的信号。

| 文件 | 作用 |
|---|---|
| `manifest.json` | MV3；`permissions: ["nativeMessaging"]`，`host_permissions` 只有 mock env 的主机（后台按 URL 查这些标签页要用）；菜单按钮的内容脚本匹配 `<all_urls>`、`all_frames: false`、`document_idle`，mock env 的内容脚本只匹配各自应用的主机。不写 `update_url`：打包时按 `<base_url>` 加进 crx 里的那份 |
| `content.js` | 往 `document.documentElement` 挂 `<mastersos-exit>`，closed shadow root 里是浮动按钮、它的菜单与确认对话框 |
| `background.js` | service worker：收到自己内容脚本的恰好 `{cmd:"exit"}`，`chrome.runtime.connectNative("org.mastersos.kiosk_exit")` 发 `{"cmd":"exit"}`；`{cmd:"help-…"}` 各变成一条 `chrome.runtime.sendNativeMessage("org.mastersos.support", …)`（下「Get help」）；装上（`install`）时重新加载 `MOCK_TAB_PATTERNS` 的标签页 |
| `mock/nwea/page.js` | NWEA 的 mock env，MAIN 世界、`document_start`：`isKioskChromium`、`extVersion`、`kioskChromiumExit`、UA 后缀、拦 F5 等 |
| `mock/nwea/relay.js` | 隔离世界、`document_start`：把 `page.js` 的退出请求转成 `{cmd:"exit"}` |
| `tests/` | vitest + jsdom（`environment: "jsdom"`、`globals: true`），没有自己的 package，见下「测试」 |

## 行为

- 界面文字只有英文（扩展里不放中文；`tests/content.test.js` 核对源码里没有 CJK 字符）。
- 把手只有图标（竖排三点，40×48 px，深色 `#1b1d2a` 85% 不透明、白图标；悬停或聚焦时不透明并略变宽），
  `aria-label` 与 `title` 都是「Options」。缺省贴在右边缘的竖直正中、只有内侧是圆角——考试页的 Next / Submit 在右下、
  状态信息在右上，角上会挡住它们。
- 可以拖到任何地方，松手时吸附到较近的左 / 右边缘，高度跟着指针（移动不到 6 px 仍算点击，拖动时菜单收起，拖完不弹菜单）。
  边与高度记在页面的 `sessionStorage`（`mastersos-exit-pos`，`{"side":"l"|"r","y":0..1}`，`y` 是可用高度的比例，
  所以窗口变大变小都还在视口里）；上一版的 `mastersos-exit-corner` 不认。存储不可用（沙箱页面）时照样显示，只是不记。
- 点把手弹出一个小菜单（`role="menu"`，在把手旁边、朝屏幕内侧展开、与把手竖直居中；白底、12 px 圆角、每项 44 px 高，
  前面 18 px 图标），两项：「Get help」（圆圈问号的图标，深色字，求助开着才显示）与「Exit」（门与箭头的图标，红字）。菜单项是 `content.js` 里的 `ACTIONS` 列表，
  以后加一项就是加一条。
- 键盘：按钮能拿到焦点，Enter / Space 开关菜单，↓ / ↑ 打开并聚焦第一项 / 最后一项；菜单里 ↑ ↓ Home End Tab 在菜单项之间移动
  （焦点不出菜单），Esc 收起、焦点回到按钮。菜单开着时点页面别处就收起（`document` 上捕获阶段的 `pointerdown`，
  只在菜单开着时挂、只看不拦，页面照样收到这个事件）。
- 选「Exit」先在同一个 shadow root 里出一张居中的确认卡片：标题「Exit this app?」，正文「You will need to open it again
  from the sign-in screen.」，按钮「Cancel」（缺省焦点）/「Exit」（红底）。Cancel 或 Esc 关掉、不发任何消息；
  「Exit」发 `chrome.runtime.sendMessage({cmd:"exit"})`。
- 焦点环全部是 2 px 的 `#d9653b`（`:focus-visible`，外移 2 px），不用浏览器缺省的蓝色双环。
- 后台连 native messaging 宿主 `org.mastersos.kiosk_exit`（= `mastersos-bundle` 的 `EXIT_HOST`）。宿主是
  `/usr/lib/mastersos/mastersos-kiosk-exit` → `mastersos-agent kiosk exit-host`：4 字节小端长度 + JSON，只认恰好
  `{"cmd":"exit"}`，回 `{"ok":true}`（「已请求」：会话随即结束，之后什么都等不到）或 `{"ok":false}`。
- 回 `{"ok":true}` 时同一张卡片的标题变成「Exiting…」、前面一个 18 px 的转圈（`prefers-reduced-motion` 时不转），按钮行隐去但留着高度（Esc 也不关）；20 秒后会话还在，或回 `{"ok":false}`、
  宿主没回就断开、连不上，都在同一张卡片里显示「Could not leave. Please ask a teacher.」与一个「OK」按钮；OK 关掉，
  可以从菜单再试。

### Get help（计划 2026-11-05 Task 7）

- 菜单第一次打开时问一次 `{cmd:"help-enabled"}`；只有回 `{ok:true, enabled:true}` 才把「Get help」显示在 Exit 前面，出错、没回、15 秒没答都不显示。
- 对话框与 Exit 的确认卡片同一套样式，在同一个 shadow root 里：标题「Get help from IT」；话题六选一（必选，`role="radiogroup"`，
  一个 Tab 停点、方向键移动并选中）：Wi-Fi / Can't sign in / An app / Screen, keys or sound / Battery / Other（线上名
  `wifi` / `sign_in` / `app` / `hardware` / `battery` / `other`，同 `mastersos-bundle` 的 `SupportCategory`）；
  可选的描述（`maxlength` 1000，占位「What happened? Please don't include passwords or personal details.」）；Cancel / Send。
  没选话题按 Send：不发，提示「Choose a topic first.」、焦点回第一个话题。**没有截图选项**（Ruling P1：截图要放宽扩展的 host 权限）。
- Send 发 `{cmd:"help-submit", category, text}`（text 去掉首尾空白）；后台转成
  `{"op":"submit","category","text","session":"kiosk","screenshot_png_b64":null}`，真正的 `kiosk:<app id>` 与身份由宿主认定。
  拿到 `client_id` 后每 3 秒问一次 `{cmd:"help-status", client_id}`，最多 60 秒：
  有单号显示「Sent. Ticket #<n>. IT has been told.」，60 秒还在排队显示「Saved. It will be sent when this computer is online.」，
  `rate_limited`「You've sent 3 requests this hour. Please try again later.」，`disabled`「Help requests are turned off at this school.」，
  其余（宿主不在、拒收、没回）「Couldn't send. Please tell a teacher.」。等待时一个转圈与「Close」：关掉只是不再问，单子已在本机队列里。
- 键盘：Esc 关、焦点回把手；Tab 只在卡片里转（话题组、描述、看得见的按钮）。
- 后台只认这三种恰好的形状（多一个键、未知话题、超 1000 字、空的或过长的 `client_id` 一律不理），回内容脚本时也只留认得的字段。
  宿主是 `/usr/lib/mastersos/mastersos-support-host` → `mastersos-agent support native-host`（一条消息进、一条出，转给 `/run/mastersos-support/support.sock`）；
  锁定会话的 `NativeMessagingAllowlist` 是 `EXIT_HOST` 与 `SUPPORT_HOST` 两个。

### 不弄坏页面

- 按钮、菜单、对话框与它们的样式都在 closed shadow root 里：页面的脚本拿不到（`host.shadowRoot === null`），页面的样式表进不去。
  宿主元素自己的样式写在 `style` 属性上并带 `!important`（行内的 `!important` 压过页面样式表里的 `!important`），`z-index` 取最大值。
- 内容脚本跑在扩展的隔离环境里，不往页面的 JS 环境注入脚本。
- 不吞页面的事件：自己元素上的点击、指针与按键事件在 shadow root 处停止冒泡；`document` 上只有只看不拦的 `toggle`（捕获）
  与 `fullscreenchange`，以及只在菜单开着时挂上的 `pointerdown`（捕获，点在菜单外就收起菜单），都不 `stopPropagation`、不 `preventDefault`。
- 页面把宿主元素移走就挂回去（`MutationObserver`），10 秒内最多 10 次；再多就停下、`console.warn` 一条，不与一直移走它的页面
  无限拉锯（这一页就没有按钮了，Alt+F4 照样能退）。

### 留在最上面（顶层）

- 宿主是 `popover="manual"`，`showPopover()` 进顶层：页面的 `z-index`、`<html>` 上的 `transform` / `filter` / `contain`
  都管不到它（顶层元素的包含块是视口）。
- 页面之后开的模态对话框、popover、全屏元素排在它上面，所以页面一开（`toggle` 事件、对话框的 `open` 属性、`fullscreenchange`）
  就先 `hidePopover()` 再 `showPopover()`，重新排到最上面；页面对宿主 `hidePopover()` 也显示回来。
- 页面开着模态对话框（`showModal()`）时，对话框之外都是 inert、点不到：宿主挪进那个对话框（文档里最后一个 `:modal`），
  关了再挪回 `<html>`。
- 提升 10 秒内最多 30 次；超过的不丢，窗口结束时补一次。
- 看门狗每秒一次：页面直接移走开着的模态对话框（或它的容器）、换掉 `<html>` 时把按钮放回该在的地方（并让 `open` 属性的
  观察者跟到新的 `<html>`）。每次只做便宜的检查，不对时才动 DOM；它的挂回不算进上面「移走 10 次」的上限，本身限在每秒最多一次；
  那个上限触发、脚本停下之后它也停。
- 没有 Popover API（Chrome 114 之前；manifest 要求 120，只是兜底）时退回到最大的 `z-index`，并保持是 `<html>` 的最后一个子元素。
- jsdom 没有 Popover API、`:modal` 与顶层，测试用桩只核对调用顺序与宿主挂在哪里。

**VM 验收清单（计划 9 Task 8）：**

1. 页面 `dialog.showModal()` 开着时按钮在对话框之上、点得到，菜单与确认对话框能用；关掉对话框后按钮回到原处。
2. 页面的 popover（`popover="auto"` 与 `manual`）开着时按钮在其上。
3. 元素全屏（`requestFullscreen()`，如视频或考试平台的全屏模式）时按钮可见、点得到。
4. `<html style="transform: translateZ(0)">` 的长页面滚到底：把手仍在视口的右边缘正中。
5. 触屏把把手拖到左边缘、松手后再点一下：出菜单（不被吞）；拖动本身不弹菜单。键盘 Tab 到把手、Enter 开菜单、Esc 收起。
6. Chrome 的错误页与 `URLBlocklist` 的拦截页（`chrome-error://`）没有内容脚本、没有按钮：确认 Alt+F4 ×5 能退出（审阅 M2）。
- 只在顶层框架（`all_frames: false`）。

## 按应用的模拟环境（mock env）

设计 §4.9、裁定 K9。考试厂商只认 ChromeOS（kiosk PWA）等设备时，我们**不做通用的 ChromeOS 模拟**（专有接口太多、mock 不完），
而是一个应用一个 mock env：读那个应用的页面与厂商扩展的源码，只给出**它的页面实际读到的东西**。代码写死在这里、manifest 按应用的
主机匹配，不由设置打开、不在设置里收 JS；锁定会话只放行这个应用的主机，所以只有这个应用的会话有它的 mock env。

| 应用 | 目录 | 主机 | 给什么 |
|---|---|---|---|
| NWEA MAP Growth | `mock/nwea/` | `*.nwea.org`、`*.mapnwea.org` | `window.isKioskChromium = true`、`window.extVersion = "1.0.0"`（不可改）、`window.kioskChromiumExit()`；`navigator.userAgent` 末尾加 ` NWEAChromePWA`；拦 F5、Ctrl+W/N/T/0、左右边缘滑动 |

时序：`page.js` 在每个匹配页面的文档开始、早于页面任何脚本，同步写入常量，没有竞态；唯一的先后问题是扩展装上之前第一页已经在加载
（每个锁定会话都是新 profile、重新下载扩展）——后台在 `install` 时重新加载这些标签页，`update` 时不刷新。

加下一个应用：

1. 读它的页面与厂商扩展的源码，写清「页面读什么、什么时候读」（写进设计 §4.9）。
2. `mock/<应用>/` 下只实现那些：MAIN 世界的 `page.js`（常量用 `defineProperty` 写成不可改，幂等）；要退出或别的回调时加 `relay.js`
   （只认同窗口、同源、恰好那个形状的消息）；要改请求头时加 `rules.json`（DNR 静态规则）——先用解包加载核对 Chrome 收不收：`User-Agent` 不能 `append`，NWEA 扩展的那条规则就是被丢掉的。
3. `manifest.json` 加它的内容脚本与 `host_permissions`（有 `rules.json` 时另加 `declarativeNetRequest` 权限与 `rule_resources`）；`background.js` 的 `MOCK_TAB_PATTERNS` 加它的主机；
   调高 `version`；`image/tests/kiosk-ext-pack-test.sh` 的 zip 条目名单加新文件。
4. `tests/` 加它的测试（`tests/manifest.test.js` 照 NWEA 的写法加一组）；VM 上验收一次（`image/lab/kiosk-acceptance.md`）。

## 测试

```bash
# 这个仓库不带 JS 依赖，CI 也不跑这些测试：在仓库外装 vitest 与 jsdom 的目录里写一个配置，
# root 指向本目录、environment: "jsdom"、globals: true、include: ["tests/**/*.test.js"]，
# cacheDir 放在本目录以外（打包会把本目录里的文件都装进 crx；vitest 5 的模块缓存默认写进 root 下的
# node_modules/.vitest-cache，所以关掉它），然后：
vitest run --no-experimental.fsModuleCache --config <那个配置>
bash image/tests/kiosk-ext-pack-test.sh                                                # 打包（CI 的 image-lint）
```

jsdom 的 `getComputedStyle` 会把文档的样式表错误地套到 shadow 树里的元素上，所以「页面样式不影响按钮」在测试里核对的是
宿主的计算样式与按钮在 shadow 树里，不是按钮的计算样式。

## 打包与 id

```bash
bash image/kiosk-ext-pack.sh <钥匙.pem> <输出目录> <base_url>    # 打印 id
```

- `<钥匙.pem>`：不加密的 PEM RSA 私钥（≥ 2048 位）。lab 是构建机的 `~/mastersos-keys/lab/kiosk-ext.pem`（生成命令见 `image/docs/keys.md`「lab 的钥匙」），正式的由钥匙仪式生成、只在两根 LUKS U 盘上，签名会话时在 `/run/mastersos-release-keys/kiosk-ext.pem`（`image/docs/key-ceremony.md`）；仓库里不放任何扩展私钥（正式的公钥 `keys/kiosk-ext-public.pem` 仪式之后入库）
  （`tests/check-tree.sh` 第 1 条拒绝私钥入库）。私钥只经这个路径交给 `openssl`，不复制、不写进输出目录或日志；放在输出目录里的钥匙被拒。
- id = sha256(公钥 DER 的 SubjectPublicKeyInfo) 前 16 字节，每个十六进制位 0–f 映射成 a–p。lab 与正式钥匙不同，id 也不同，
  所以 id 不写死在仓库里。
- `<base_url>`：放 crx 与 `updates.xml` 的 https 目录（小写主机名，可带端口与路径，不带查询串与片段；结尾的 `/` 去掉）。
  不是 https 的拒绝：Chrome 只从 https 装强制安装的扩展。
- crx3 的拼法与签名在 `image/kiosk-ext-pack.py`（只用 python3 标准库与 `openssl`）；zip 条目排序、时间固定，
  同一把钥匙、同一份源码在同一台构建机上打出同样的字节。
- 打进 zip 的是本目录里除 `tests/`、`README.md` 与点开头的文件之外的**全部**文件（新加图标、弹出页不用改打包脚本）；
  manifest 里像相对文件路径的字符串（`service_worker`、`content_scripts`、`icons`、`default_popup`……）有一个不在其中就拒绝。改了扩展要把 `manifest.json` 的 `version` 调高，否则装好的机器不更新。

输出目录里五个文件：

| 文件 | 去处 |
|---|---|
| `mastersos-kiosk-ext.crx` | 放到 `<base_url>/mastersos-kiosk-ext.crx` |
| `updates.xml` | 放到 `<base_url>/updates.xml`（`appid` = id，`codebase` = 上一行，`version` 取 manifest） |
| `org.mastersos.kiosk_exit.json` | 宿主清单（`image/kiosk-ext/org.mastersos.kiosk_exit.json.in` 填上 id）：镜像的 `/etc/opt/chrome/native-messaging-hosts/` |
| `org.mastersos.support.json` | Get help 的宿主清单（`image/kiosk-ext/org.mastersos.support.json.in` 填上 id）：同上 |
| `kiosk-ext.json` | `{"id", "update_url": "<base_url>/updates.xml"}`：镜像的 `/usr/lib/mastersos/kiosk-ext.json`，agent 的 kiosk 步骤读它写进锁定会话的策略 |

**镜像怎么用这些输出（计划 9 Task 8）**：`build.sh` 按 lab / 正式选钥匙，`<base_url>` 固定为 `file:///usr/lib/mastersos/kiosk-ext`（断网时新 profile 也能装上，`ExamExtension::check` 只认这一个 file 地址）跑 `kiosk-ext-pack.sh`，把
两份宿主清单装进 `/etc/opt/chrome/native-messaging-hosts/`、`kiosk-ext.json` 装进 `/usr/lib/mastersos/`，
crx 与 `updates.xml` 装进 `/usr/lib/mastersos/kiosk-ext/`；产物目录的 `kiosk-ext/` 只留作核对，`publish.sh <版本> chrome` 对这样的构建什么都不做。宿主清单不是 `mkosi.extra` 里的静态文件，因为 `allowed_origins` 里的 id 随钥匙变。
宿主清单的 `path` 是已在镜像里的包装 `/usr/lib/mastersos/mastersos-kiosk-exit` 与 `mastersos-support-host`（native messaging 的 `path` 带不了参数）。
