# 锁定应用的托管设备接口（`navigator.managed`）

**状态：** 已批准（David，2026-11-11：「请你直接继续推进」）。接在 `2026-11-06-kiosk-platform-inject-design.md`（下称「伪装设计」）之后：伪装让页面**看到的平台**像
ChromeOS，本文让页面能问到 ChromeOS 托管设备才回答得了的东西（资产编号、位置、序列号、主机名、目录 id、托管配置）。

**裁定（David，2026-11-10）：** 照 Google 公开文档通用地补，不先查哪家厂商在用（「不管用不用，我们就直接补上…我们是通用的」）。
先做页面这一层（`navigator.managed`）；扩展这一层（`chrome.enterprise.*`）放进 §8「以后」。

**底线照旧（伪装设计开头）：** 不伪造任何校验令牌或设备证明。本文的接口只回答 IT 自己在设置里写的、或机器本来就有的值；
Verified Access、`enterprise.platformKeys` 不在本文，也不在「以后」。

## 1. 要补的接口（Google 文档）

都在 `navigator.managed`（`NavigatorManagedData : EventTarget`，`[SecureContext, Exposed=Window]`，不进 Worker）上：

| 方法 | 规范 | ChromeOS 的值从哪来 | 我们的值从哪来 |
|---|---|---|---|
| `getAnnotatedAssetId()` | Device Attributes | 管理控制台给设备填的资产编号 | `[[device]]` 新键 `asset_id` |
| `getAnnotatedLocation()` | Device Attributes | 管理控制台给设备填的位置 | `[[device]]` 新键 `location` |
| `getDirectoryId()` | Device Attributes | 设备在 Google 目录里的 id | 安装时生成的 `device_id`（控制台里显示的那个） |
| `getHostname()` | Device Attributes | `DeviceHostnameTemplate` 策略 | 本机主机名（`/etc/hostname`） |
| `getSerialNumber()` | Device Attributes | 硬件序列号 | DMI 序列号（`ident::read` 已读，占位值算没有） |
| `getManagedConfiguration(keys)` | Managed Configuration | `ManagedConfigurationPerOrigin` 下载的 JSON | 锁定应用新键 `managed_config` 指向的 JSON；同样只给 `url` 的确切源 |
| `onmanagedconfigurationchange` / 事件 `managedconfigurationchange` | Managed Configuration | 策略刷新时触发 | 定义好、可挂监听，但会话中不会触发（§4） |

**照 Chromium 的实现，不照规范文本**（两者有出入时页面看到的是实现）。出处：`third_party/blink/renderer/modules/managed_device/`
（`navigator_managed_data.idl` / `.cc`）、`chrome/browser/device_api/`（`device_service_impl.cc`、`device_attribute_api.cc`）、
`runtime_enabled_features.json5`，2026-11-11 的 main：

- **Linux 上的 Chrome 本来有什么：** `ManagedConfiguration` 是 `stable`（所有平台），所以 `navigator.managed`、
  `NavigatorManagedData`、`getManagedConfiguration`、`onmanagedconfigurationchange` 本来就在；`DeviceAttributes` 只在 ChromeOS
  上 `stable`、别处 `experimental`，所以五个设备属性方法**在 Linux 上不存在**。于是：托管配置是替换原型上已有的方法；设备属性是
  往 `NavigatorManagedData.prototype` 上补五个方法（不用造 `navigator.managed` 本身）。
- **设备属性方法**（IDL：`Promise<DOMString?>`）：
  - 有值 resolve 字符串；**没有值 resolve `null`**（规范文本写 `undefined`，实现是可空的 `DOMString?`）。
  - 不在顶层框架（或在 fenced frame 里）：reject `NotAllowedError`，`"This API is allowed only in top level frames."`。
  - Permissions Policy 关了 `device-attributes`：reject `NotAllowedError`，`"Permissions-Policy: device-attributes are disabled."`。
  - 不是 kiosk 应用的源（`IsTrustedContext` 不过）：服务连不上，reject `NotAllowedError`，`"Service connection error. This API is available only for managed apps."`。
  - 是 kiosk 应用的源、但没被 `DeviceAttributesAllowedForOrigins` 放行：reject **`UnknownError`**，`"The current origin cannot use this web API because it was not granted the 'device-attributes' permission."`。
- **`getManagedConfiguration(keys)`**（IDL：`Promise<record<DOMString, any>>`，`keys` 必填）：这个源没有配置时 reject `NotAllowedError`，
  `"Managed configuration is empty. This API is available only for managed apps."`；有配置时 resolve 一个对象，只含 `keys` 里在配置中
  存在的键（每个值是从 JSON 解析出来的新对象，不存在的键略去）。
- 都是异步的：前置检查不过时也是返回一个被 reject 的 Promise，不同步抛出（Blink 对返回 Promise 的方法就是这样处理异常的）。

## 2. 方案

| 做法 | 结论 |
|---|---|
| **A. 平台扩展里加一个 MAIN 世界脚本（`managed.js`），值由 agent 写进 `config.js`** | **采用**。与 `chromeos.js` 同一套：静态内容脚本、`document_start`、只在应用主机上；不加任何扩展权限 |
| B. 用 Chrome 自己的策略 | 设备属性做不到：`DeviceAttributesAllowedForOrigins` 只支持 `chrome_os`（Chromium 的策略定义，`supported_on: chrome_os:93-`）。托管配置在 Linux 上有（`ManagedConfigurationPerOrigin`，`chrome.*:89-`），但只给 `WebAppInstallForceList` 强制安装的 Web 应用，配置要从一个 URL 下载并核 hash；我们的网页锁定应用不是这样装的，也没有本机能给的 URL。两个接口一半原生一半模拟，行为不一致，不做 |
| C. 交给 IT 的 `inject` 脚本 | 现在就能做，但每个学校各写一份、不通用，违背裁定 |

## 3. 设置格式

### 3.1 锁定应用的两个新键

| 键 | 类型 | 缺省 | 说明 |
|---|---|---|---|
| `device_attributes` | 布尔 | `false` | 只有 `url` 的确切源（同主机同端口；不含子域，不含 `allow` 里的主机）上的页面能用五个设备属性方法（序列号、主机名、资产编号、位置、device_id；对应 ChromeOS 的 `DeviceAttributesAllowedForOrigins`）。`false` 时：写了 `platform = "chromeos"` 的应用上方法仍在、一律 reject `UnknownError` 加「没被授予 device-attributes 权限」的那句，与 ChromeOS kiosk 里没被放行的源一样（§1）；没写 `platform` 的应用上方法不存在，与 Linux 上原样的 Chrome 一样 |
| `managed_config` | 字符串 | 没有 | `files/<名>.json`：UTF-8 的 JSON，顶层是对象，至多 64 KiB（**我的取值**）。与 Google 管理控制台里贴的 JSON 同一格式 |

- 两个键与 `platform`、`inject` 一样，只用于 `url` 应用、不与 `pwa = true` 同时写（理由同伪装设计 §1）。
- 不要求同时写 `platform = "chromeos"`：`navigator.managed` 在 Linux 上的 Chrome 也有（托管配置是 `chrome.*` 都支持的），单独用也说得通。
- 新 issue code：`kiosk_device_attributes_invalid`（写在 `exec` / `pwa` 应用上）、`kiosk_managed_config_invalid`（不是 `files/<名>.json`、不在包里、写在 `exec` / `pwa` 应用上；有文件内容时：超过 64 KiB、不是 UTF-8、不是 JSON、顶层不是对象）。
  内容检查放在 `mastersos-bundle` 的 `kiosk::check_managed_config`，与 `check_inject_source` 同样的分工（lint 只看文件名，
  CLI / MCP / agent 看内容；agent 拒绝时这个应用跳过并回报）。
- 新 feature：`kiosk_device_attributes`、`kiosk_managed_config`（旧 agent 遇到不认识的键会拒绝整份设置，云端照 FleetGap 挡发布）。

### 3.2 `[[device]]` 的两个新键

| 键 | 类型 | 说明 |
|---|---|---|
| `asset_id` | 字符串，可选 | 资产编号；1–128 个字符、不含控制字符（**我的取值**，用 `checks` 里现成的写法） |
| `location` | 字符串，可选 | 位置；同上 |

- 只是给设备做的标注，别处不用（不参与选分组）。它们是学校数据，在签名的设置包里，不进本仓库。
- 新 feature：`device_annotations`；issue code `device_annotation_invalid`。

## 4. 设备上怎么做

- **平台扩展：** 伪装设计 §3.4 的生成条件从「写了 `platform` 或 `inject`」扩成「写了 `platform`、`inject`、`device_attributes`
  或 `managed_config`」。新文件 `kiosk-platform/managed.js`（编进 agent），内容脚本：MAIN 世界、`document_start`、所有框架、
  `match_origin_as_fallback`，`matches` **只有应用 `url` 自己的源**（`https://<url 的主机>/*`，不带 `*.` 子域名，不含 `allow` 里的其它主机）。不加权限：值在包里，不需要 `host_permissions`、
  `nativeMessaging` 或 `storage`。
- **值怎么到页面：** MAIN 世界的内容脚本读不到扩展里的 `config.js`（那是起始页与后台用的）。所以照 `inject-wrapper.js` 的做法：
  `managed.js` 里有一行标记，agent 生成平台扩展时把它换成一个 JSON 字面量（`serde_json` 序列化，再把 `<`、U+2028、U+2029
  转义，同 `inject` 的嵌法），内容：
  - `device`：`device_attributes = true` 时为 `{asset_id, location, directory_id, hostname, serial}`，没有的项写 `null`（页面拿到 `null`）；`false` 时整项没有（方法 reject `UnknownError`）。
  - `managed`：`managed_config` 的 JSON 对象；没写时没有这一项（方法 reject `NotAllowedError`，与 Linux 上真 Chrome 一样）。
  - 每次调用 `getManagedConfiguration` 返回的值都是重新从这份数据拷出来的（页面改了拿到的对象，不影响下一次）。
  生成这个字面量的函数放在 `mastersos-bundle` 的 `kiosk` 里（与 `platform_config` 并列，`managed_values`），参数是应用、这台机器的
  `DeviceIdent`、主机名与命中的 `[[device]]`；agent 在生成平台扩展时给。
- **值变了：** `source.sha256` 覆盖所有生成的文件（含 `managed.js`），资产编号、位置、托管配置一改，平台扩展就重打包；Chrome 下次开会话时更新。
  会话进行中不换：锁定会话期间设备本来就什么都不做（考试静默），所以 `managedconfigurationchange` 定义好、能挂监听，但不会触发。
  ChromeOS 上也只在策略刷新时触发，页面不能指望它，这样不算露馅。
- **不露痕迹（同伪装设计 §4）：** 只动 `NavigatorManagedData.prototype`（§1：Linux 上本来就有）：换掉 `getManagedConfiguration`，
  补上五个设备属性方法。属性描述符与原生方法一样（`writable`、`enumerable`、`configurable` 都是 `true`），`length` 是 IDL 的参数个数
  （`getManagedConfiguration` 为 1，其余为 0），`toString()` 像原生的，`this` 不是 `NavigatorManagedData` 时 reject `TypeError`
  （Blink 对返回 Promise 的方法就是这样）。`keys` 不是可迭代的字符串序列时 reject `TypeError`。`navigator.managed` 若不存在（Chrome
  哪天改了），`managed.js` 什么都不做，不去造它。
- **Permissions Policy：** 设备属性方法先查 `document.featurePolicy.allowsFeature("device-attributes")`；只有这个浏览器认得这个
  特性名（在 `features()` 里）时才查，认不得就当允许。
- **顶层框架：** `window !== window.top` 时设备属性方法 reject §1 的「only in top level frames」。
- **只在安全上下文：** 应用主机本来就只放行 `https://`；`managed.js` 在非安全上下文里什么都不做（与规范的 `[SecureContext]` 一致）。

## 5. 安全

- 不加扩展权限；脚本与页面同一个 JS 世界，页面拿到的只是 IT 写进设置、或机器本来就有的几个值。
- **序列号对本机所有账号可见。** 平台扩展的 CRX 是 0644（伪装设计 §3.4），生成的 `managed.js` 在里面。Linux 上 `product_serial` 本来只有
  root 读得到，开了 `device_attributes` 后，本机任何账号都能从 CRX 里的 `managed.js` 读到序列号（以及资产编号、位置、device_id）。我的判断：这些值
  贴在机器底面、也在控制台里，不是秘密，可以接受；manifest-spec 写明 `managed_config` 里不许放秘密（与 `inject` 同一条）。
- **值只给应用 `url` 自己的源**（照 ChromeOS：设备属性只给 kiosk 应用的源，Chromium 的 `IsEqualToKioskOrigin`）。`allow` 里的其它主机
  （CDN、统计、第三方服务）与子域名都拿不到，上面也没有这五个方法。两道关：`managed.js` 的 `matches` 只写这个源；`DATA`
  带着这个源（`"origin"`），`managed.js` 在 `location.origin` 不等于它时什么都不做。（2026-11-11 自动安全审查指出最初的实现用了
  整个放行名单加子域名，已改。）
- 不做任何证明：没有 `getDeviceToken`、`challengeKey` 这类东西，`managed.js` 也不留这种入口。

## 6. 测试

- `kiosk-extension/tests/` 加 `platform-managed.test.js`（同 `platform-chromeos.test.js` 的跑法）：五个方法有值 / 没值（`null`）/ 没开
  （`UnknownError` 与那句文案）/ 在子框架里（`NotAllowedError`）；`getManagedConfiguration` 只回请求的、存在的键，每次返回新对象，
  没配置时 reject `NotAllowedError`，`keys` 缺省或不是序列时 reject `TypeError`；前置检查不过也返回 Promise、不同步抛；
  `length` 与属性描述符同原生；`toString()` 像原生；没有 `navigator.managed` 时什么都不改。
- Chromium 容器：开了 `device_attributes` 的页面里调一遍，并核对没装平台扩展时 Linux 上本来就是「有 `getManagedConfiguration`、没有五个设备属性方法」。
- `mastersos-bundle`：两个应用键与两个 `[[device]]` 键的 lint、四个 feature、`check_managed_config`、`platform_config` 的新输出。
- `mastersos-agent`：平台扩展的生成条件、值写进 `managed.js`、改了资产编号或托管配置时重打包。

## 7. 没做 / 要实测的

- 不需要单独实测：Linux 上 Chrome 原本有什么，由 Chromium 源码定（§1，`RuntimeEnabled` 的状态与报错文案），Chromium 容器里的
  端到端（§6）顺带核对一次。Google Chrome 与 Chromium 用同一个 Blink，这部分没有品牌差别。
- PWA 应用（`pwa = true`）上都不支持，同伪装设计。
- Worker 里没有 `navigator.managed`，规范上本来就是 `Exposed=Window`，不用补。

## 8. 以后：扩展这一层（`chrome.enterprise.*`）

ChromeOS 上，强制安装的扩展能用 `chrome.enterprise.deviceAttributes`（同上五个值）、`chrome.enterprise.hardwarePlatform`
（厂商与型号）、`chrome.enterprise.networkingAttributes`（本机 IP 与 MAC）。考试厂商的扩展（TestNav 等）若问这些，在 Linux 的
Google Chrome 上根本没有这几个命名空间。三个障碍，都还没有好解法：

1. 改 Chrome 网上应用店里下载的扩展，Chrome 会标为已损坏（内容校验）并停用；
2. 品牌版 Google Chrome 已去掉 `--load-extension`，没法在启动时塞一个解包的改版；
3. 自己重新打包会换掉扩展 id，厂商的页面与后台按 id 认扩展，认不出来。

现在能做的是伪装设计里的办法：由 `inject` 在页面这一侧截住厂商扩展的问话（TestNav 样例）。换成自己编译的、兼容 Chrome
扩展生态的开源浏览器（任务板 #5，推测性的）可能把三个障碍一起去掉，到时再设计。设备证明（`enterprise.platformKeys`）永远不做。

## 9. 留给实现的

- `managed.js` 的代码组织、与 `chromeos.js` 共用「像原生」的工具函数（抽出来还是各留一份，看测试好不好写）。
- 主机名怎么取（`gethostname(2)` 还是读 `/etc/hostname`），取不到就省略。
- 文案：本文没有新的用户界面文字；issue 的说明是给 IT 的英文，照现有 lint 的写法。
