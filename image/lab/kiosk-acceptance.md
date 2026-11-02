# 锁定应用的 VM 验收清单（计划 9 Task 10）

**状态：清单已写，VM 还没跑。** 计划 9 的代码、镜像树与仪式脚本都在仓库里，但这一切还没在真的 GDM、gnome-kiosk 与 Chrome
里跑过（2026-10-26 的会话够不到家里的 PVE，见 `.superpowers/sdd/2026-10-26-mastersos-9-kiosk-apps/progress.md` 裁定 R4）。
这份清单是设计 `docs/superpowers/specs/2026-10-26-mastersos-kiosk-apps-design.md` §8 的 V1–V9、各任务报告与台账里攒下的
「要在 VM 上看」的每一项（去重之后），以及 §9 的五个待定细节。

怎么记：

- 结果放 `image/lab/results/<日期>-9/`：每个编号一份 `<编号>.txt`（命令与输出原样贴），截图放 `shots/<编号>-<n>.png`
  （`lab/shot.sh`）。表格的「结果」一列填「通过」或「不通过：看到了什么」，不通过的写明回到哪个任务修、修完重跑这一项。
- 「不通过时」一列是**事先**想好的去处，VM 上看到的事实与它不符时以事实为准，在结果文件里写清楚。
- 跑完把 §9 的结论写回设计 §9（见本文末节），总 spec 状态行里计划 9 那句改成「VM 165 上验过」。
- 下文 `<id>` 是应用的 id，`kiosk-<id>` 是它的账号；`$K` 指 `kiosk-nwea`。kiosk 会话里的命令从 VM 的串口 / ssh 以 root 跑
  （lab 镜像有 sshd 与试验用户，`lab/serial.sh`、`lab/gx.sh`），不在锁定会话里开终端——那本身就是要验证打不开的东西。

## 0. 前提

| 编号 | 操作 | 预期 | 结果 |
|---|---|---|---|
| P1 | **lab 的扩展钥匙**（构建机上一次；VM 161 与 VM 164 各一份，或拷同一份）：`cd ~/mastersos-keys/lab && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out kiosk-ext.pem && chmod 0600 kiosk-ext.pem`；`openssl pkey -in kiosk-ext.pem -pubout -outform DER \| sha256sum \| cut -c1-32 \| tr 0-9a-f a-p` 记下 lab 的扩展 id（`docs/keys.md`「lab 的钥匙」） | 32 个 a–p 的字母；私钥不出构建机 | |
| P2 | **lab 的 https 扩展地址**：试验网的更新源是 http，Chrome 只从 https 装强制安装的扩展。选一个 https 目录（例如更新源 S3 桶里一个 lab 前缀经 CloudFront：`https://<lab 的 CDN>/mastersos-lab/chrome`），在 lab 根的 `mastersos-root.conf` 写 `chrome_base=<它>`，构建时 `MASTERSOS_KIOSK_EXT_BASE=<它>` | 没有这一步：`build.sh` 打印「lab 构建不带考试扩展」，镜像里没有 `/usr/lib/mastersos/kiosk-ext.json`，agent 跳过网页 / PWA 应用并回报 `kiosk:<id>` 失败——只剩 V6 能跑 | |
| P3 | **构建与发布**：`lab/sync.sh`；VM 161 上 `MASTERSOS_KIOSK_EXT_BASE=<P2> ./build.sh <v> --profile lab`；`./publish.sh <v> beta`（lab 根）；`./publish.sh <v> chrome`；把 `<根>/chrome/` 的 `mastersos-kiosk-ext.crx`（先）与 `updates.xml`（后）放到 P2 的地址 | `build-info.txt` 有 `kiosk_ext_id=<P1 的 id>`、`kiosk_ext_update_url=<P2>/updates.xml`；`curl -sI <P2>/updates.xml` 是 200、`curl -s` 的 `appid` 是 P1 的 id | |
| P4 | **构建日志**（Task 8 报告的构建日志一项）：`grep -E 'user-units|dconf|sysrq|pam_namespace|kiosk' mkosi.output/build-<v>.log` | `user-units.sh` 通过（gnome-kiosk、zenity 没带进新的 `/etc/systemd/user` 链接）；postinst 打印 27 个 dconf 键的核对与 `kernel.sysrq` 0；guard + `pam_namespace` 的核对对 `gdm-password`、`gdm-authd` 与 `/usr/lib/pam.d/systemd-user` 都过；finalize 有 `L /etc/opt/chrome/native-messaging-hosts` 与 `L /etc/security/namespace.init` | |
| P5 | **装到 VM 165**：从上一版 lab 镜像经 sysupdate 升上来（不重装：要顺便看升级路径 M16），并保留一台没升级的旧镜像机器（VM 166）给 V8 | `cat /usr/lib/mastersos/kiosk-ext.json` 的 id 是 P1 的；`cat /etc/opt/chrome/native-messaging-hosts/org.mastersos.kiosk_exit.json` 的 `allowed_origins` 是 `chrome-extension://<id>/` | |
| P6 | **测试用的设置**：VM 165 所在分组的配置里发布下面这段（`icon` 换成包里真有的文件，或去掉），分组照常开访客、有一个本机老师账号与一个 SSO 学生账号 | agent 一轮之后回报里 `kiosk:nwea`、`kiosk:forms`、`kiosk:calc`、`kiosk:map-pwa`、`kiosk:exttest` 都成功；`getent passwd kiosk-nwea` 的 uid 在 1900–1989、shell `/bin/bash` | |
| P7 | **扩展测试页**（给 M12 用）：把本文末「附：扩展测试页」放到 P2 同一个 https 主机的 `…/kiosk-test/index.html` | 浏览器能打开 | |
| P8 | **NWEA 的前提**（设计 §1）：学区没有为本校打开「所有学生必须用安全测试」；准备一个测试场次（或 NWEA 的练习测试）和一个测试学生 | 普通浏览器里能开考 | |

P6 的配置设置（VM 165 所在分组用的 `[[config]]` 里）：

```toml
[config.apps.kiosk]
nwea    = { name = "NWEA MAP", url = "https://test.mapnwea.org/", allow = ["nwea.org", "mapnwea.org", "fonts.googleapis.com", "gstatic.com", "cdn.jsdelivr.net", "launchdarkly.com", "browser-intake-datadoghq.com", "datadoghq-browser-agent.com", "newrelic.com", "texthelp.com", "speechstream.net"] }
forms   = { name = "期中考试 สอบ \"กลางภาค\" \\", url = "https://docs.google.com/forms/d/e/<表单>/viewform", allow = ["docs.google.com", "accounts.google.com", "gstatic.com"], in_session = true }
calc    = { name = "计算器", exec = "/usr/bin/gnome-calculator" }   # 镜像里没有就换 Flatpak id，并在 apps.flatpak 里列上
exttest = { name = "扩展测试", url = "https://<P7 的主机>/kiosk-test/index.html", login_screen = true }

[config.apps.kiosk.nwea-sec]
name = "NWEA 安全版（PWA）"
url = "https://test.mapnwea.org/pwanopopup"
allow = ["nwea.org", "mapnwea.org", "fonts.googleapis.com", "gstatic.com", "cdn.jsdelivr.net", "launchdarkly.com", "browser-intake-datadoghq.com", "datadoghq-browser-agent.com", "newrelic.com", "texthelp.com", "speechstream.net"]
pwa = true

[[config.apps.kiosk.nwea-sec.extensions]]
id = "acmpckmfpahllclpjpollppelfoafcmh"
update_url = "https://testchrome.mapnwea.org/extension/updates.xml"

[config.apps.kiosk.map-pwa]
name = "NWEA MAP（PWA）"
url = "https://test.mapnwea.org/"
allow = ["nwea.org", "mapnwea.org"]
pwa = true
in_session = true
```

`nwea` 与 `nwea-sec` 的 `allow` 照 NWEA Help Center「System Requirements」的防火墙放行名单（MAP Growth 与读题工具两段，2026-10-26 抄）。
`forms` 的名字故意带泰文、引号与结尾的反斜杠（Review Focus 的转义一项，M20、M15）。

## 1. 设计 §8 的 V1–V9

### V1 登录界面进入，NWEA 与 Google 表单能登录、作答

| 编号 | 操作 | 预期 | 结果 | 不通过时 |
|---|---|---|---|---|
| V1.1 | 回到 GDM 的用户列表 | 看得到「NWEA MAP」「期中考试 …」「计算器」「扩展测试」「NWEA MAP（PWA）」，名字原样、图标是包里的（没写 `icon` 的是通用图标） | | 名字被截断或乱码：Task 5 的 AccountsService keyfile 转义；不出现：M1 |
| V1.2 | 点「NWEA MAP」 | 不问口令，直接进一个全屏的 Chrome，没有地址栏、标签栏、GNOME 顶栏与 Dock；右下角有「退出 / Exit」按钮 | | 要口令：Task 5 的 `passwd -d`；进了完整桌面：M2/M3；没有按钮：M12 |
| V1.3 | 用测试学生登录 NWEA、开考、答几题 | 页面能加载、能作答；被拦的资源（页面缺图、脚本报错）记下主机名 | | 缺的主机名补进 `allow`，并把常用平台的完整 `allow` 写进 `README.md`「锁定应用」的例子（设计 §3 说 V1 补齐） |
| V1.4 | 点「期中考试」：Google 表单登录（学校的 Google 账号若需要）、提交 | 能提交 | | 同上，补 `allow` |
| V1.6 | 点「NWEA 安全版（PWA）」（照 NWEA 给 Chromebook 的配置：`pwanopopup` + MAP Growth 扩展 `acmpckmfpahllclpjpollppelfoafcmh`），用测试学生开考；同时在宿主 `ls /home/kiosk-nwea-sec/.kiosk-chrome/Default/Extensions/` | 扩展装上了（目录里有 `acmpckmfpahllclpjpollppelfoafcmh`）；它在 Linux 上回答 `inKiosk: false`（没有 `chrome.audio`），记下 NWEA 的反应：照常开考 / 提示要用安全浏览器 / 拒绝。另记 User-Agent 末尾的 ` NWEAChromePWA` 有没有让「不支持的系统」提示出现或消失 | | 只记录：决定 README 里 NWEA 推荐用普通 url 还是 PWA + 扩展；学区若开了强制安全测试，两种都进不去（设计 §1） |
| V1.5 | 进入、退出各一次后在 VM 上 `journalctl -o verbose MASTERSOS_KIOSK=nwea` | 有「进入」「退出」两条，字段 `MASTERSOS_KIOSK=nwea`；`journalctl --since …` 里没有上报的痕迹 | | Task 6 的 journald 记录 |

### V2 逃逸逐项试（每个按键单独一行；都在「NWEA MAP」会话里）

通过的标准一律是：**没有离开这个应用的页面、没有出现能输入网址或命令的东西、没有出现文件窗口**。关掉 Chrome 本身是允许的
（会原地重开，V3）。

| 编号 | 操作 | 预期 | 结果 | 不通过时 |
|---|---|---|---|---|
| V2.1 | Alt+Tab | 没有窗口切换器 | | gnome-kiosk 的快捷键（§9.5、M10） |
| V2.2 | Super（单按）与 Super+A、Super+S | 没有概览、应用列表 | | 同上 |
| V2.3 | Alt+F4 | Chrome 关掉、几秒内原地重开同一页（计 1 次退出） | | Task 6 的守护 |
| V2.4 | Ctrl+N | 不出现新窗口，或出现的仍是全屏、同一套策略的 Chrome（没有地址栏） | | 记下行为；出现普通窗口就是 Chrome 的 `--kiosk` 没管住：加 `BrowserAddPersonEnabled` 之外的策略或改守护 |
| V2.5 | Ctrl+T | 不出现标签页 UI | | 同上 |
| V2.6 | Ctrl+Shift+N | 无痕窗口打不开（`IncognitoModeAvailability` = 1） | | Task 2 的默认锁 |
| V2.7 | Ctrl+Shift+Q | Chrome 退出、原地重开（计 1 次退出） | | Task 6 |
| V2.8 | Ctrl+Alt+F3（以及 F1、F2、F4…F6） | 不切到别的 VT / 登录界面 | | dconf 的 `switch-to-session-*`（Task 8）；gnome-kiosk 自己也去掉了 VT 键 |
| V2.9 | Ctrl+Alt+T | 不出终端 | | media-keys 的 `terminal` 锁（Task 8） |
| V2.10 | F12 | 不出开发者工具 | | `DeveloperToolsAvailability` = 2 |
| V2.11 | Ctrl+Shift+I、Ctrl+Shift+J、Ctrl+Shift+C、右键「检查」 | 不出开发者工具 | | 同上 |
| V2.12 | Ctrl+U（看源代码） | 打不开，或被拦（`view-source:` 不在放行名单） | | `URLBlocklist`；不通过就加 `view-source:*` 进阻止（它本来在 `*` 里，要核对） |
| V2.13 | 地址栏：Ctrl+L、F6、Alt+D，然后打字回车 | 没有地址栏，打字落在页面里 | | `--kiosk` |
| V2.14 | Ctrl+S（存盘） | 不出文件窗口 | | `AllowFileSelectionDialogs` = false |
| V2.15 | Ctrl+O（打开文件） | 不出文件窗口 | | 同上 |
| V2.16 | 页面里的 `<input type=file>`（P7 测试页有一个） | 点了不出文件窗口 | | 同上 |
| V2.17 | 下载：P7 测试页的下载链接 | 不下载，不出下载栏 | | `DownloadRestrictions` = 3 |
| V2.18 | Ctrl+P（打印） | 不出打印预览 | | `PrintingEnabled` = false（应用可在 `chrome_policy` 里打开） |
| V2.19 | Ctrl+H、Ctrl+J、Ctrl+Shift+Delete、Ctrl+Shift+B、Ctrl+Shift+O、Alt+F、Alt+E | 不出历史、下载、清除数据、书签管理、菜单；出了的话页面是 `chrome://` 而被拦 | | 记下哪个键出了什么；`chrome://` 能打开就是 V2.20 不通过 |
| V2.20 | `chrome://` 页面：P7 测试页里的 `chrome://settings`、`chrome://policy`、`chrome://extensions` 链接；Shift+Esc（任务管理器） | 链接被拦（「被管理员阻止」）；任务管理器即使出现也结束不了扩展进程（`TaskManagerEndProcessEnabled` = false） | | `URLBlocklist ["*"]` |
| V2.21 | `allow` 之外的域名：P7 测试页里到 `https://example.com/` 的链接、`window.open`、中键点链接、把链接拖到页面外 | 被拦，或新窗口同样被拦、仍全屏 | | `URLAllowlist` 合成（Task 2） |
| V2.22 | Alt+Space（窗口菜单）、Alt+F7 / Alt+F8（移动 / 缩放）、Super+L、Alt+F2 | 都没反应（锁屏不该出；出了也只回到同一账号） | | gnome-kiosk 的快捷键清单（§9.5） |
| V2.23 | Ctrl+Alt+Delete、Alt+SysRq+任意键 | 不注销、不重启；`cat /proc/sys/kernel/sysrq` 是 0 | | `99-mastersos-kiosk.conf` |
| V2.24 | XF86 键：计算器、主页、浏览器、邮件、搜索、设置、帮助（VM 里用 `xdotool`/虚拟键盘发不出来时在 Dell 上补测，记「VM 测不了」） | 都不起程序；音量键照常 | | media-keys 的锁（Task 8 M3，parked） |
| V2.25 | 页面里 `window.close()`、`location = "file:///etc/passwd"`（P7 测试页的按钮） | 窗口关掉就原地重开；`file://` 被拦（只放行错误页那一个文件） | | `ERROR_PAGE` 的前缀匹配（Task 6） |
| V2.26 | 屏幕共享：P7 测试页的 `getDisplayMedia` 按钮 | 被拒绝 | | `ScreenCaptureAllowed` = false |
| V2.27 | （终审 I3）P7 测试页的英文段落上右键：有没有「翻译成 中文 / ไทย」；地址栏右侧的翻译气泡（`--kiosk` 下看不到地址栏，记下是否另有气泡）。先记下 `--kiosk` 下右键菜单里到底有没有翻译这一项 | 没有翻译项，或点了不翻译（`TranslateEnabled` = false） | | `OPTIONAL_DEFAULTS`（mastersos-bundle `kiosk.rs`）；`--kiosk` 本来就没有这一项也照记 |
| V2.28 | （终审 I3）P7 测试页的文本框里打 `recieve teh`；右键拼写建议 | 没有红色波浪线，右键没有拼写建议 | | `SpellcheckEnabled` = false |
| V2.29 | （终审 I3）右键图片或页面：「用 Google 搜索图片」「用 Google Lens 搜索」；文本框右键「帮我写」之类的 AI 项；Alt+Shift+I（发送反馈） | 都没有，或点了不出东西（Lens 的导航也被 `URLBlocklist` 拦） | | `LensOverlaySettings` = 1、`GenAiDefaultSettings` = 2、`UserFeedbackAllowed` = false |
| V2.30 | F11、Esc（含元素全屏时按 Esc） | 不离开全屏、不露出标签栏或地址栏；元素全屏的 Esc 只回到 kiosk 的全屏页面 | | `--kiosk`；露出地址栏就是逃逸 |
| V2.31 | 链接上右键：「在新窗口中打开」「在新标签页中打开」「在无痕窗口中打开」「复制链接后粘到哪」 | 没有这些项，或打开的仍是全屏、同一策略的窗口（`allow` 之外的照样被拦）；无痕打不开 | | 同 V2.4 |
| V2.32 | （外部协议）P7 测试页的 `mailto:`、`zoommtg://`、`ms-word:` 链接 | 不起任何程序，不弹「要打开 xdg-open 吗？」 | | `URLBlocklist ["*"]` 预期也盖住自定义协议，未验证；不通过就在默认锁里显式阻止这些协议（`URLBlocklist` 加 `mailto:*` 一类，或另找关外部协议的策略），并把它加进 `LOCKED_KEYS` |
| V2.33 | （PWA）在「NWEA MAP（PWA）」会话里：窗口标题栏的应用菜单（⋮）有没有「在 Chrome 中打开」、「打开方式」、「卸载」 | 没有标题栏 / 菜单，或点了出的仍是同一策略的全屏窗口 | | §9.2；改 `chrome_argv`（加 `--kiosk`）或把 PWA 当网页起 |
| V2.34 | （反方向，终审 C1）锁定会话里试着回到登录界面：Super+L、Ctrl+Alt+F1、Alt+F2 后输入 `gdmflexiserver`、用户菜单 | 都回不到登录界面，也没有「切换用户」 | | V2.8、V2.22；gnome-kiosk 没有用户菜单 |

### V3 Chrome 连续退出 5 次 → 错误页 → 结束会话

| 编号 | 操作 | 预期 | 结果 | 不通过时 |
|---|---|---|---|---|
| V3.1 | 60 秒内按 5 次 Alt+F4（每次等 Chrome 重开） | 第 5 次之后不再重开 NWEA，出本机错误页 `kiosk-error.html`：中英两行「这个应用无法启动，请举手找老师」，中文字形正常 | | Task 6 的 `Supervisor`；页面被拦：`ERROR_PAGE` 不在 `URLAllowlist` |
| V3.2 | 错误页上再按一次 Alt+F4 | 会话结束、回到 GDM；journald 有一条「异常结束」 | | Task 6 |
| V3.3 | 错误页上有没有「退出」按钮（扩展的内容脚本对 `file://` 默认不生效） | 记下看到的；有没有都不算失败（Alt+F4 能退） | | 只记录，写进 README 的退出一节 |
| V3.4 | 隔 70 秒按一次 Alt+F4，共 6 次 | 每次都原地重开（窗口外的旧退出不计） | | Task 6 |

### V4 退出后家目录清空

| 编号 | 操作 | 预期 | 结果 | 不通过时 |
|---|---|---|---|---|
| V4.1 | 在「期中考试」里填一半表单、登录 Google，按「退出」确认 | 回到 GDM；`systemctl status mastersos-ephemeral-cleanup@$K` 跑过且成功；`findmnt /home/kiosk-forms` 是一份新的 tmpfs | | Task 3/4 的清理 |
| V4.2 | 再点「期中考试」 | 没有上一位的 Google 登录、Cookie、表单草稿、自动填充 | | 清理没换 tmpfs，或 Chrome profile 不在家目录 |
| V4.3 | 会话里 `ls -la /home/kiosk-forms`（从 root） | 只有 `.kiosk-chrome` 等本次会话的文件 | | 同上 |
| V4.4 | （Review Focus）会话还在清理时立刻再点同一个应用（清理慢时：先 `systemctl --user` 里起一个慢退出的进程拖住） | 拒绝并提示「上一位还没有完全退出」，不是用上一位的家目录进去 | | Task 4 的 `kiosk_open_denied_while_not_ready` 在真 GDM 上的样子 |
| V4.5 | （Review Focus）在 NWEA 会话里直接 `qm stop 165`（断电），再开机，点 NWEA | 第一位进来就是新的 tmpfs；`journalctl -b -u 'mastersos-ephemeral-cleanup@kiosk-*'` 开机时每个 kiosk 账号各一次 | | Task 5 的 `boot_kicks_cleanup_for_every_kiosk_account` |

### V5 平时的会话不受 kiosk 策略影响

| 编号 | 操作 | 预期 | 结果 | 不通过时 |
|---|---|---|---|---|
| V5.1 | NWEA 会话开着时，root 在宿主命名空间 `ls /etc/opt/chrome/policies/managed/` | 是整机那份（分组的策略），没有 `mastersos-kiosk.json` | | pam_namespace 漏到了宿主（M5） |
| V5.2 | 本机老师账号登录，Chrome 打开 `chrome://policy` | 只有分组的策略，没有 `URLBlocklist ["*"]` 等 kiosk 锁 | | 同上 |
| V5.3 | NWEA 会话里（root：`nsenter -t $(pgrep -u $K -o chrome) -m ls /etc/opt/chrome/policies/managed/`） | 只有 `mastersos-kiosk.json`，与 `/var/lib/mastersos-public/kiosk/nwea/policies/mastersos-kiosk.json` 字节相同；看不到整机的那份 | | Task 8 的 `namespace.init` |
| V5.4 | NWEA 会话**结束之后**（V4.1 之后）：宿主上 `findmnt /etc/opt/chrome/policies/managed`、`grep kiosk-ns /proc/self/mountinfo`；本机老师账号登录再看 `chrome://policy` | 宿主上没有残留的 bind（findmnt 为空或只是原本的目录）；老师的 `chrome://policy` 只有分组的策略 | | pam_namespace 对共享根的自动 private 处理没生效、bind 传播到了宿主：记下 mountinfo，改 `namespace.conf` 的选项 |

### V6 本地程序（`exec`）

| 编号 | 操作 | 预期 | 结果 | 不通过时 |
|---|---|---|---|---|
| V6.1 | 登录界面点「计算器」 | 程序全屏（gnome-kiosk 把它放满），没有顶栏、Dock | | gnome-kiosk 对普通窗口的处理；记下实际的样子 |
| V6.2 | 关掉程序（它自己的关闭 / Alt+F4） | 会话结束、回到 GDM（exec 不重开） | | Task 6 的 `run_exec_app_ends_on_exit` |
| V6.3 | 会话里托管策略目录（root：`nsenter -t $(pgrep -u kiosk-calc -o gnome-calculator) -m ls -la /etc/opt/chrome/policies/managed/`） | 只有 `mastersos-kiosk.json`（root 0644），与 `/var/lib/mastersos-public/kiosk/calc/policies/mastersos-kiosk.json` 字节相同；目录 root 0755；`URLAllowlist` 只有错误页、`ExtensionInstallForcelist` 为空（终审 I1） | | agent 的 kiosk 步骤（本地程序也写策略）与 `namespace.init` |
| V6.4 | 把 `calc` 的 `exec` 改成一个不存在的 Flatpak id，发布，点它 | 起不来就结束会话、回到 GDM，journald「异常结束」；lint 先有 `kiosk_flatpak_missing` 警告 | | Task 6 `run_exec_spawn_failure_ends_session` |
| V6.5 | （终审 I1）「计算器」会话里从程序打开一个链接：「关于」对话框里的网站链接、帮助菜单（换成别的带链接的程序也行，例如一个 Flatpak 的 LibreOffice / GeoGebra）；root 同时 `pgrep -u kiosk-calc -a chrome` | 要么什么都不开，要么开出的 Chrome 是锁住的：页面「被管理员阻止」、F12 / Ctrl+Shift+I 无效、`chrome://policy` 被拦、Ctrl+O 不出文件窗口、不能下载；绝不是一个普通浏览器 | | 本地程序的策略（mastersos-bundle `chrome_policy` 的 exec 分支）；Chrome 起在了命名空间外：M5 |
| V6.6 | （终审 I1）清空 `/var/lib/mastersos-public/kiosk/calc/policies/`，点「计算器」；等 agent 下一轮写回 | zenity 中英错误框 `POLICY_NOT_ISOLATED`，会话结束，程序没起 | | `mastersos-kiosk run` 对本地程序也核对托管策略 |

### V7 从会话里进入（`in_session`）

| 编号 | 操作 | 预期 | 结果 | 不通过时 |
|---|---|---|---|---|
| V7.1 | 访客会话里，Dock / 应用列表有「期中考试 …」与「NWEA MAP（PWA）」，没有 `in_session = false` 的 | 两个图标在；名字原样 | | Task 6 的启动器 |
| V7.2 | 点「期中考试」 | zenity 确认「将结束当前会话，进入 期中考试 … 锁定模式」，名字里的泰文、引号、反斜杠原样（`--no-markup` 不吃反斜杠） | | zenity 的反斜杠处理（Task 6 concern 5）：不原样就改 `ENTER` 文字的拼法 |
| V7.3 | 确认 | 访客会话结束并照常清理；回到 GDM 的用户列表（一次性自动登录**没有做**，§9.4），再点一下「期中考试」进去 | | 会话没结束：M13 的 `show-user -p Display`；结束了但弹「结束不了当前会话」：同上 |
| V7.4 | SSO 学生会话里同样进入 | SSO 会话结束，家目录保留（再登录文件都在） | | Task 6 |
| V7.5 | 本机老师账号里同样进入、再取消 | 取消什么都不做 | | Task 6 |
| V7.6 | （终审 C1）SSO 学生会话里在终端排好 `sleep 120; loginctl activate $XDG_SESSION_ID`，然后右上角菜单「切换用户…」，在登录界面点「NWEA MAP」 | 被拒，提示「这台电脑上还有别的会话没有注销，请先回到那个会话注销…」（中英）；SSO 会话照旧在后台；两分钟后切回的是 SSO 会话本身，没有锁定会话在旁边。回到 SSO 会话注销后再点 NWEA：进得去 | | `pam-session` 的 `seat_guard`；看 `journalctl -t mastersos-agent`（或 GDM 的日志）里「座位上还有会话 …」那一行；**进去了 = 安全问题，先下线锁定应用** |
| V7.7 | （终审 C1）SSO 会话锁屏（Super+L），在锁屏上选「切换用户」/「以其他用户登录」，点「期中考试」 | 同 V7.6，被拒 | | 同上 |
| V7.8 | （终审 C1，不误拒）V7.3 的路径：从访客 / SSO 会话「进入」期中考试，登录界面一出现就**立刻**点它；另做一次：普通注销之后立刻点 NWEA | 都进得去，不出「还有别的会话」（刚结束的会话在 logind 里是 `closing`）；被拒的话当场 root `loginctl list-sessions -o json` 贴进结果 | | 结束的会话不是马上 `closing`（state 还是 `online`）：`seat_sessions_busy` 在拒绝之前短时重试（例如 3 秒内每 0.5 秒再问一次），补测试 |

### V8 旧 agent 的机器挡住发布

| 编号 | 操作 | 预期 | 结果 | 不通过时 |
|---|---|---|---|---|
| V8.1 | VM 166 留在计划 9 之前的镜像，最近 30 天有回报；它所在分组的草稿加一个锁定应用，prepare / 发布 | 被 `feature_unsupported`（`kiosk`）挡下，提示先升级系统 | | 服务端的 `features_used` / `SUPPORTED_FEATURES`（Task 1、6） |
| V8.2 | VM 166 升到新镜像、回报一轮之后再发布 | 发布通过 | | 同上 |

### V9 删掉应用、挂失锁定

| 编号 | 操作 | 预期 | 结果 | 不通过时 |
|---|---|---|---|---|
| V9.1 | （Review Focus）有人在 `exttest` 会话里时，从设置里删掉 `exttest` 并发布 | agent 先结束会话、等 slice 停下，再删账号；之后 `getent passwd kiosk-exttest` 为空，`/var/lib/AccountsService/users/kiosk-exttest`、`/var/lib/mastersos-public/kiosk/exttest/`、`/etc/systemd/system/user@<uid>.service.d/50-mastersos-kiosk.conf` 都没了，`namespace.d/mastersos-kiosk.conf` 里没有它，登录界面不再显示；`findmnt /home/kiosk-exttest` 为空 | | Task 5 的删除顺序；留下空的 `/home/kiosk-exttest` 是已知的（台账 parked） |
| V9.2 | 把 `login_screen` 改成 false、`name` 改掉，发布 | 登录界面不再显示它（`SystemAccount=true`），不用重启 accounts-daemon；改名在下一次列表里生效 | | M14：accounts-daemon 不重读就加 `try-restart accounts-daemon` 或经 D-Bus 改 |
| V9.2b | （终审 I2）在管理网页把某个应用改成只勾「在桌面显示」、不勾「在登录界面显示」 | 表单当场提示「只在桌面显示还进不去…」并挡保存；直接改清单的话，发布前检查报错 `kiosk_in_session_only` | | mastersos-bundle 的 lint 与网页的 `entryProblem` |
| V9.3 | 设备挂失锁定（`[[device]].locked`），发布 | 正在跑的 kiosk 会话被结束；点任何锁定应用都被拒绝 | | Task 4 的 `pam-check`（K10）与 `lock` 步骤 |
| V9.4 | 解除锁定 | 照常能进 | | 同上 |

## 2. 各任务留下的 VM 核对项（去重）

「来源」是第一次提出它的地方（台账 = `progress.md`）。

| 编号 | 来源 | 操作 | 预期 | 结果 | 不通过时 |
|---|---|---|---|---|---|
| M1 | 设计 §4.1 | GDM 用户列表里 kiosk 账号的样子；清理之后（V4.1 之后）再看 | 名字、图标照 AccountsService 记录；清理照模板恢复记录后依然在（`login_screen = false` 的依然不在） | | Task 5 的 `accounts_template` |
| M2 | 台账 Task 8（NoDisplay） | 点 kiosk 账号后 `loginctl show-session <id> -p Desktop`、会话里 `systemctl --user show-environment \| grep XDG_SESSION_DESKTOP` | GDM 照 AccountsService 的 `Session=mastersos-kiosk` 起了 `NoDisplay=true` 的会话，`Desktop=mastersos-kiosk`；没有退回 `ubuntu` | | **去掉 `NoDisplay`**（`mkosi.extra/usr/share/wayland-sessions/mastersos-kiosk.desktop`）；非 kiosk 用户选了它由 `run` 结束自己的会话（M4） |
| M3 | Task 6 concern 1、台账 Task 6（PAM 守卫两个方向） | (a) 正常点 NWEA；(b) 在 GDM 的齿轮里给 NWEA 选「Ubuntu」再进 | (a) 进得去——说明 GDM 在 `open_session` 之前已把 `XDG_SESSION_DESKTOP` 放进 PAM 环境、pam_exec 传给了 pam-session；(b) 被拒绝，提示 `DENY_KIOSK_SESSION`（中英），没有进完整桌面 | | (a) 不通过 = **所有 kiosk 登录都被拒**：守卫的假设不成立，pam-session 改为从 AccountsService 记录 / logind 取会话名（Task 6）；(b) 不通过 = 安全问题，先下线锁定应用 |
| M3b | Task 6 concern 2、台账（I2） | M3(b) 之后看 `/var/lib/AccountsService/users/kiosk-nwea` 的 `Session=`，再不碰齿轮正常点 NWEA | 被拒那次之后记录仍是 `mastersos-kiosk`（pam-session 的 `SetSession` / `SetXSession` 生效）；下一位不用碰齿轮就进得去 | | accounts-daemon 在 GDM 登录途中不接受 `SetSession`：改为拒绝路径里拉起清理（只在 slice 不在时），见 Task 6 concern 2 |
| M4 | 台账 Task 6 M2 | 本机老师账号在 GDM 齿轮里看不看得到「mastersos-kiosk」会话；看得到就选它登录 | 看不到（`NoDisplay`）；M2 去掉了 `NoDisplay` 时：会话马上结束、回到 GDM，journald 一行（没有 `MASTERSOS_KIOSK` 字段），没有黑屏 | | Task 6 的 `run` 对非 kiosk 账号的处理 |
| M5 | Task 8 报告（更新后的第 2 项）、设计 §4.3 缺口 | NWEA 会话里：`grep policies/managed /proc/$(pgrep -u $K -f 'systemd --user')/mountinfo`、`grep policies/managed /proc/$(pgrep -u $K -o chrome)/mountinfo`、同一个进程里 `findmnt /home/$K`、`ls /run/user/$(id -u $K)`；`stat -c '%a %U' /var/lib/mastersos-kiosk-ns` | GDM 那一侧与 user manager（`user@<uid>.service`，PAM 栈 `systemd-user`）都在 kiosk 的命名空间里：`policies/managed` 绑的是 `/var/lib/mastersos-kiosk-ns/$K`；user manager 里看得到 tmpfs 家目录与 `/run/user/<uid>`；实例父目录 `0 root` | | user manager 不在命名空间里 = Chrome 读整机策略，但 `run` 的核对（M7b）会拦下、不起 Chrome；查 `/usr/lib/pam.d/systemd-user` 有没有那两行（`pam-hooks.sh`） |
| M6 | Task 8 报告第 3、6 项 | (a) 老师、SSO、访客各登录一次；(b) root 往 `/etc/security/namespace.d/` 放一个格式错的 `x.conf`，再各登录一次，然后删掉它；(c) 删掉全部锁定应用（没有 `mastersos-kiosk.conf`）再登录 | (a)(c) 都正常；(b) 非 kiosk 账号照常，kiosk 账号的会话失败 | | 守卫 `pam_succeed_if … user !~ kiosk-*` 没挨着 `pam_namespace`、或顺序反了（`pam-hooks.sh`） |
| M7 | Task 8 报告第 4 项 | (a) `chmod g+w /etc/opt/chrome/policies`，点 NWEA；改回。(b) 清空 `/var/lib/mastersos-public/kiosk/nwea/policies/`，点 NWEA；等 agent 下一轮写回 | (a) kiosk 登录失败（`namespace.init` 被 SIGKILL），journal 有「namespace.init: … 不安全」；(b) zenity 中英错误框 `POLICY_NOT_ISOLATED`，会话结束，没起 Chrome | | (a) `namespace.init` 的 kiosk 段；(b) `mastersos-kiosk run` 的 `check_managed_policy` |
| M8 | Task 8 报告第 5 项 | `ls -l /etc/security/namespace.init` | 是指回 factory 的符号链接，pam 1.7.0-5ubuntu3.2 照样执行它（M5、V5.3 已证明实例被填了） | | 链接不被接受：把它放进 `etc-policy.conf` 的 copy |
| M9 | Task 8 报告第 2、5 项 | NWEA 会话里 `systemctl --user -M $K@ show-environment`、`systemctl --user -M $K@ status org.gnome.Kiosk@wayland.service org.mastersos.KioskApp.service` | 环境里有 `DCONF_PROFILE=mastersos-kiosk` 与 `XDG_SESSION_DESKTOP=mastersos-kiosk`；两个单元 active；应用退出（V6.2、V3.2）触发 `gnome-session-shutdown.target` 回到 GDM | | gnome-session 50 的 systemd drop-in 形状（`gnome-session@mastersos-kiosk.target.d/session.conf`） |
| M10 | Task 8 报告第 3 项、台账（M3 parked） | 以 `$K` 跑 `gsettings get org.gnome.mutter.wayland.keybindings switch-to-session-3`、`gsettings writable …`、同样看 `org.gnome.settings-daemon.plugins.media-keys terminal` | `@as []`、false；V2.8、V2.9、V2.24 已核按键 | | dconf 的 file-db 没生效：看 `DCONF_PROFILE` 是否到了 gnome-settings-daemon |
| M11 | Task 8 报告第 7 项 | `cat /proc/sys/kernel/sysrq` | 0 | | `99-mastersos-kiosk.conf` 被别的 sysctl 盖了 |
| M12 | Task 7、Task 8 报告第 8 项；扩展 README 的 VM 清单 1–6 | 点「扩展测试」，在测试页上逐个按按钮 | (1) `dialog.showModal()` 开着时按钮在对话框之上、点得到，确认框能用，关掉后回原处；(2) popover（`auto` 与 `manual`）开着时按钮在其上；(3) 元素全屏时按钮可见、点得到；(4) `<html style="transform: translateZ(0)">` 的长页面滚到底按钮仍在视口角上；(5) 触屏拖到别的角、松手后再点：出确认；(6) 点「去一个被拦的网址」：Chrome 的拦截页没有按钮——60 秒内 Alt+F4 ×5 出错误页、再按一次结束会话，或长按电源键 | | (1)–(5)：`kiosk-extension/content.js`；(6) 是已知限制（台账 Task 7 M2），写进 README |
| M12b | Task 7、Task 6 裁定 | NWEA 会话里点「退出」→「离开」 | 对话框显示「正在退出…」，会话随即结束、回到 GDM；journald「退出」 | | 宿主没找到：`/etc/opt/chrome/native-messaging-hosts/org.mastersos.kiosk_exit.json`（L 链接）与 `NativeMessagingAllowlist`；找到了但会话没结束：M13 |
| M12c | Task 10（新）：kiosk 家目录每次是新的 tmpfs，强制安装的扩展每次进入都从 `updates.xml` 重新下载 | 点 NWEA，计时按钮出现要多久；断开 VM 的外网（`qm set 165 -net0 …,link_down=1`）再点 NWEA | 有网：几秒内出现按钮；断网：页面打不开、也没有按钮——Alt+F4 ×5 + 1 次退出。另外：在 NWEA 作答中途断网十几秒再接上，记下 NWEA 是否察觉（暂停、要监考确认、还是无感） | | 记下时间；断网没有按钮是预期之内，写进 README「退出」一节；若要离线也有按钮，另立任务把 crx 预置进镜像。NWEA 对断网的反应写进 README 的 NWEA 前提 |
| M13 | 台账 Task 6（I1、自我结束）、Task 6 concern 7 | (a) NWEA 会话里以 `$K` 看 Chrome 子进程的环境有没有 `XDG_SESSION_ID`（`tr '\0' '\n' < /proc/<宿主进程>/environ`，点一次「退出」时抓）；(b) 访客会话里从 gnome-shell 起的进程跑 `loginctl show-user $USER -p Display --value` | (a) 有就用它，没有走 `show-user -p Display`，再没有才 `terminate-user`；普通用户结束自己的会话 logind 允许；(b) 打印当前图形会话的 id | | (a)(b) 都拿不到会话：退出按钮与 `enter` 都结束不了会话（`ENTER_FAILED`）；查 logind 的 `Display` 属性 |
| M13c | Task 10 复审 minor 6（`terminate-user` 退路从没被逼出来过） | NWEA 会话开着时，root 做一个假的 `loginctl`：`/root/shim/loginctl` 对 `show-user` 打印空行、其余 `exec /usr/bin/loginctl "$@"`；然后 `printf '\x0e\x00\x00\x00{"cmd":"exit"}' \| sudo -u $K env -u XDG_SESSION_ID PATH=/root/shim:/usr/bin /usr/lib/mastersos/mastersos-kiosk-exit` | 回 `{"ok":true}`，`$K` 的会话结束（走的是 `terminate-user kiosk-nwea`）；journald「退出」 | | 包装或 agent 把 `PATH` 定死了、shim 不生效：记下，改由单元测试覆盖（`kiosk_session` 的 `terminate_target`）；会话没结束：logind 不许用户 `terminate-user` 自己 |
| M14 | Task 5 concern 2 | V9.2 | 见 V9.2 | | 见 V9.2 |
| M15 | Task 6 concern 5 | V7.2 | 见 V7.2 | | 见 V7.2 |
| M16 | Task 5 concern 6、Task 8 报告第 9 项 | 从计划 9 之前的镜像升上来的 VM 165 上：`ls -ld /etc/security /etc/security/namespace.d /etc/systemd /etc/systemd/system`；`ls -l /etc/opt/chrome/native-messaging-hosts /etc/security/namespace.init`；`ls -ld /var/lib/mastersos-kiosk-ns`；`/usr/lib/mastersos/etc-migrate` 的日志 | 前四个是真实目录（`etc-policy.conf` 的 `dir`），其余子项是指回 factory 的 `L`；`native-messaging-hosts` 与 `namespace.init` 是 `L`；实例父目录开机建好、root 0000 | | `etc-policy.conf` 与 `mastersos-etc-migrate`；README「可写的根」表里四行的「未上 VM」改成实测结果 |
| M17 | Review Focus（名称转义） | V1.1、V7.2 里 `forms` 的名字 | 登录界面、Dock、确认框都原样显示 `期中考试 สอบ "กลางภาค" \` | | Task 5 的 keyfile / `.desktop` / `launch.json` 转义 |
| M18 | 台账 Task 8 parked（策略被重写） | NWEA 会话开着时改它的 `allow` 并发布 | 正在跑的会话不受影响；下一次进入用新策略。agent 写策略恰好落在 PAM 填实例与 `run` 核对之间时，那一次登录被拒（fail closed，接受） | | 只记录 |
| M19 | 台账 Task 8 parked（`policies/recommended`） | `ls -la /etc/opt/chrome/policies/recommended` | 不存在或为空（kiosk 会话没有把它换掉，整机放进去的推荐策略 kiosk 的 Chrome 也会读） | | 不为空：把 `recommended` 也多实例化（`namespace.d` 加一行，`namespace.init` 照填空目录） |
| M20 | Task 8 concern 1（pam_namespace 跑两次） | M5 的两处挂载看到的实例内容 | 同一个目录、同一份字节；Chrome 起得来 | | `run` 只核对一次；两次填之间 Chrome 读到空目录时改 `namespace.init` 只在 `$3=1`（新建）时填 |
| M21 | 台账 Task 8 parked（旧 `/etc/pam.d`） | 有 4a Task 12 之前留下真实 `/etc/pam.d` 拷贝的机器（若 VM 168 还是）点 NWEA | 没有 kiosk 命名空间，`run` 弹 `POLICY_NOT_ISOLATED`、不起 Chrome（fail closed） | | 只记录；这种机器要重装或手动换回链接 |
| M22 | 设计 §4.4、台账 Task 6 | `mastersos-kiosk run` 在 kiosk 会话外（老师账号的终端）跑 | 拒绝（`DENY` 文字）并结束调用者自己的会话 | | Task 6 |
| M23 | 终审 C1（`seat_guard` 的前提） | (a) `loginctl --json=short list-sessions` 在登录界面、一个 SSO 会话开着、切换用户之后各跑一次；(b) 点 NWEA 时 pam-session 看到的 PAM 环境里有没有 `XDG_SEAT`（临时在 `gdm-password` 的 pam-session 行前加 `session optional pam_exec.so log=/run/pam-env.log /usr/bin/env`，看完删掉） | (a) 是 JSON 数组，每行有 `class` 与 `state`；登录界面的是 `greeter`，切换用户后 SSO 会话是 `user` / `online`；(b) 有 `XDG_SEAT=seat0` | | (a) 缺栏 = **所有 kiosk 登录都被拒**（`DENY_KIOSK_SEAT_UNKNOWN`，往拒绝的方向落）：改成 `busctl` 读 `ListSessionsEx` 或逐个 `show-session -p Class -p State`；(b) 没有：现在按任何座位算，单座位笔记本上结果相同，只记录 |
| M24 | Task 10 复审 minor 6（台账 Task 6 M8） | `stat -c '%a %U:%G' /usr/bin/mastersos-agent /usr/bin/mastersos-kiosk /usr/lib/mastersos/mastersos-kiosk-exit`；`sudo -u $K /usr/bin/mastersos-kiosk run x` 在会话外 | 三个都是 `755 root:root`（普通用户能执行、不能改）；`run` 能起来（再被 M22 的理由拒绝），不是「权限不够」 | | 镜像的权限：kiosk 账号执行不了 agent = 会话里什么都起不来（V1.2 也会失败） |
| M25 | 终审 minor 5(c)（XDG 自动启动） | NWEA 会话里 `systemctl --user -M $K@ list-units 'app-*' --all`；`ls /etc/xdg/autostart /usr/share/gnome/autostart 2>/dev/null` 里 `OnlyShowIn=GNOME` 的项；屏幕上有没有除 Chrome 以外的窗口 | 没有自动启动的 `app-*` 单元（或只有无窗口的、记下名字）；屏幕上只有 Chrome | | `DesktopNames=GNOME-Kiosk;GNOME;` 让 gnome-session 起了 GNOME 的自动启动项：会话的 drop-in 去掉 `xdg-desktop-autostart.target`，或 `DesktopNames` 不带 `GNOME` |
| M26 | systemd 升到 259.9-0ubuntu0.1（`systemd-version.verified`） | 照 `lab/results/4a-tpm-matrix.txt` 跑第 1 行（新 VM 首次开机：repart 建 LUKS、TPM 槽带 PCR 11 公钥、无需输入）、第 3 行（VM 170 从 .0 升到 .1 后重启无需输入，与 V8.2 同一次）、第 5 行（关 Secure Boot、菜单编辑命令行加 init=/bin/sh：解不开、只出口令提示） | 三行都成立 | | initrd 的两处 drop-in 照抄的 ExecStart 与 259.9 生成的不一样 |

## 3. 设计 §9 的五个细节（VM 上定，写回设计）

| 编号 | 要定的 | 怎么看 | 定下之后写回 | 结果 |
|---|---|---|---|---|
| §9.1 | `pam_namespace` 实例目录的实际名字；`namespace.init` 是否生效 | M5、V5.3、M7(a)、M20 | 实例目录（预期 `/var/lib/mastersos-kiosk-ns/kiosk-<id>`）、`namespace.init` 每次填 / 只在新建时填、user manager 里也生效，写进设计 §4.3 与 §9.1，标「VM 165 验过」 | |
| §9.2 | PWA 在 gnome-kiosk 里是否全屏；`--app=<url>` 打开的是不是装好的 PWA（裁定 R3） | 点「NWEA MAP（PWA）」：窗口是否占满、有没有标题栏；`$K` 的 profile 里 `Web Applications/` 有没有装上；`chrome://` 被拦，所以从宿主看 `ls /home/kiosk-map-pwa/.kiosk-chrome/Default/Web\ Applications` | 全屏、用装好的 PWA：写回「`--app=<url>` + `WebAppInstallForceList` 够了」；不全屏：加 `--start-fullscreen` 或把 PWA 当网页起（改 Task 6 的 `chrome_argv` 并补测试） | |
| §9.3 | 扩展的更新请求是否受 `URLBlocklist ["*"]` 影响 | 只由 `allow` 里**没有** P2 主机的应用定：NWEA 的 V1.2 与 M12c（有没有按钮、`ls /home/$K/.kiosk-chrome/Default/Extensions/`）。M12 定不了：`exttest` 的页面就在 P2 主机上，更新地址本来就在它的放行名单里（Task 10 复审 minor 2） | 装得上：写回「不受影响，更新源不用进放行名单」；装不上：`chrome_policy` 自动把考试扩展与 `extensions` 的 `update_url` 主机加进 `URLAllowlist`（mastersos-bundle `kiosk.rs`）并补测试，再重跑 M12 | |
| §9.4 | 一次性自动登录做不做得到 | 现在 `enter` 只结束当前会话，停在登录界面（V7.3）。试 GDM 的 `AutomaticLogin`：`/etc/gdm3/custom.conf` 里写 `[daemon] AutomaticLoginEnable=true`、`AutomaticLogin=kiosk-forms`，结束会话后 GDM 会不会不重启就自动登录、自动登录之后能不能撤掉 | 做得到且稳定：Task 6 的 `enter` 经 agent 记一次性自动登录（加测试）；做不到：设计 §4.8 与 README 写明「回到登录界面再点一下」（README 已按做不到写） | |
| §9.5 | gnome-kiosk 的全局快捷键清单 | `gsettings list-recursively org.gnome.mutter.keybindings`、`org.gnome.mutter.wayland.keybindings`、`org.gnome.desktop.wm.keybindings` 以 `$K` 跑；gnome-kiosk 50 自己处理的键（它会去掉 VT 键）；V2 全部按过 | 把实际生效的键列进设计 §4.6；有能逃出去的就加进 `usr/share/mastersos/dconf/mastersos-kiosk.d/` 并锁上（postinst 的核对跟着加） | |

## 4. 按应用的模拟环境（设计 §4.9）：NWEA

| # | 做什么 | 期望 | 结果 |
|---|---|---|---|
| N1 | 对照：没装考试扩展的 Chrome 打开 `https://test.mapnwea.org/pwanopopup` | 没有 `window.isKioskChromium`、没有页脚「Version:」、没有右上角关闭按钮 | 2026-10-27 Mac 的 Chrome：符合 |
| N2 | 点「NWEA MAP」 | 扩展 1.1.0 在 profile 里；登录页右上角有关闭按钮、页脚「Version: 1.0.0」 | 2026-10-27 VM 170 三次：符合 |
| N3 | 第一页与扩展谁先（§9.6） | 扩展先于第一页，或 install 时重新加载了 NWEA 的标签页 | VM 170：扩展先装好（差 0.25 秒） |
| N4 | 点 NWEA 的关闭按钮 | 会话结束、回到登录界面，journal `MASTERSOS_KIOSK=nwea` 有「进入」「退出」 | VM 170 三次：符合（有一次会话里头两下 QMP 点击没生效，原因未查，真机复核） |
| N5 | 学校给一个 `secureBrowserEnforcement=required` 的考试场次，进到作答 | 能开考 | 待学校 |

2026-10-27 VM 170（镜像 20261026.1，agent 与会话文件临时 bind mount 成本分支的版本）顺带核过：**M23(a)** 不成立（systemd 259 的
`list-sessions` JSON 没有 `state`，已改为逐个 `show-session`）；**M3(a)** 不成立（GDM 50 在 open_session 时 PAM 环境里没有
`XDG_SESSION_DESKTOP`，已改读 AccountsService）；**M2** 不成立（`NoDisplay=true` 时 GDM 起 `ubuntu`，镜像已去掉）；去掉之后 M3(a) 进得去、
M3(b) 的齿轮在无口令账号上不出现，改用 root 把记录设成 `ubuntu` 模拟：被拒、记录改回（M3b）、GDM 重试进的是 `mastersos-kiosk`。
细节在 `results/2026-10-27-mock-nwea/run.txt`。M4（非 kiosk 账号选 `mastersos-kiosk`）没测。

| # | 做什么 | 期望 | 结果 |
|---|---|---|---|
| G1 | 会话守卫：带 `NoDisplay=true` 的会话文件（GDM 给 kiosk 账号起 `ubuntu`、pam-session 放行），点 NWEA | journal `MASTERSOS_KIOSK=nwea` 一行「not the locked app session; ending it」，`org.gnome.Shell@ubuntu` 没起，回到登录界面 | 2026-10-27 VM 170：符合 |
| G2 | 守卫下 student 自动登录、点 NWEA | 桌面与锁定会话照常，`mastersos-kiosk-guard.service` Finished | 2026-10-27 VM 170：符合 |
| G3 | `grep -rn . /etc/pam.d/gdm-authd` 里没有会问 kiosk 账号的模块（authd 的 broker、MFA） | 没有；有的话齿轮会出现，靠 G1 的守卫兜底 | 待做 |

## 附：扩展测试页（P7）

放在 P2 的同一个 https 主机上（`exttest` 的 `allow` 缺省就是它）。只为验收用，不进镜像。

```html
<!doctype html>
<html lang="zh"><meta charset="utf-8"><title>kiosk 测试页</title>
<body style="min-height:300vh">
<h1>锁定应用测试页</h1>
<p><button onclick="document.getElementById('d').showModal()">模态对话框</button>
<button popovertarget="pa">popover auto</button> <button onclick="document.getElementById('pm').showPopover()">popover manual</button>
<button onclick="document.getElementById('v').requestFullscreen()">元素全屏</button>
<button onclick="document.documentElement.style.transform='translateZ(0)'">html transform</button></p>
<dialog id="d"><p>模态对话框</p><button onclick="this.closest('dialog').close()">关</button></dialog>
<div id="pa" popover>popover auto</div><div id="pm" popover="manual">popover manual <button onclick="this.parentNode.hidePopover()">关</button></div>
<div id="v" style="background:#ccd;height:200px">全屏的元素</div>
<p><input type="file"> <a href="data:text/plain,x" download="x.txt">下载</a>
<button onclick="navigator.mediaDevices.getDisplayMedia().then(()=>alert('共享成功'),e=>alert('被拒：'+e))">屏幕共享</button>
<button onclick="window.close()">window.close</button> <button onclick="location='file:///etc/passwd'">file://</button></p>
<p><a href="https://example.com/">去一个被拦的网址</a> <a href="https://example.com/" target="_blank">新窗口</a>
<button onclick="window.open('https://example.com/')">window.open</button>
<a href="chrome://settings">chrome://settings</a> <a href="chrome://policy">chrome://policy</a> <a href="chrome://extensions">chrome://extensions</a></p>
<p><a href="mailto:test@example.com">mailto:</a> <a href="zoommtg://zoom.us/join?confno=1">zoommtg://</a> <a href="ms-word:ofe|u|https://example.com/x.docx">ms-word:</a></p>
<p lang="en">Reading passage: The quick brown fox jumps over the lazy dog. Students read this paragraph and answer the questions below.</p>
<p><textarea lang="en" rows="3" cols="40"></textarea></p>
</body></html>
```
