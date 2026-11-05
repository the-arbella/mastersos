# MastersOS 外观：品牌、开机画面、壁纸、登录页与桌面

2026-11-04 · 状态：已批准（用户 2026-11-04：按学生微调后直接实施） · 规模：项目（镜像外观；agent 只碰 Dock 一行）

## 1. 为什么

底层（A/B 镜像、TPM、签名设置、只用学校账号登录）已经做扎实，但看得见的部分还是“Ubuntu 换了几个开关”：开机滚内核文字、
Ubuntu 转圈、Yaru 默认外观、登录页是一块深灰渐变、桌面没有壁纸，MastersOS 自己连 logo 都没有。用户要把它包装成一个
产品：从开机到桌面每一屏都细腻、统一，第一眼就显得专业。

品牌含义（用户 2026-11-04）：Master 是主；MastersOS 是“主的系统”，也是“发挥基督的影响力、影响世界”。系统不只给基督教
学校用，所以**外观要通俗**：看上去就是一个专业的科技产品，信仰放在含义里，不放在符号上（第一轮的灯、十字、经文被否，
理由是“宗教化太明显”）。

## 2. 目标、非目标、反目标

**目标**

- 一套 MastersOS 品牌：logo（彩色图块版、无底版、单色版）、文字标志、配色，源文件进库。
- 开机：从 initrd 起就是品牌开机画面（黑底、发光的 M、细进度条），不再滚文字。
- 壁纸：4K 白天（默认）与夜间两张，随深浅色切换，也出现在 设置 → 外观 里。
- 登录页与锁屏：用壁纸做背景，毛玻璃卡片，左下角 MastersOS 标志；结构与行为不变。
- 桌面：底部整宽半透明 Dock、半透明顶栏、强调色与品牌一致、默认浅色；关于页显示 MastersOS logo。

**用户是学生**（用户 2026-11-04 提醒）。据此的微调（我的取舍）：教室白天光线亮、投影仪上深色看不清，夜色桌面对低年级显得暗沉，
所以桌面默认**浅色模式 + 白天壁纸**（晨光，“新的一天”）；学生切到深色时换夜间壁纸。登录页仍用夜间壁纸，保留第一眼的产品质感。
logo 与开机画面简单、温暖、不说教，不改。
- 每一屏在 VM 上截图，与效果图对比，差的修到一致。

**非目标**

- 不自己维护整套 GNOME Shell 主题（方案 B，见第 4 节）：通知、快捷设置面板、弹出菜单保持 Yaru。
- 不改 U 盘安装器与首次开机的控制台文字界面（英文、无汉字字体的规矩不变；安装器 `plymouth.enable=0` 不变）。
- 不换界面字体：Noto 覆盖 85 种语言与中日韩泰，品牌字体只用在做成图形的 logo 与文字标志里。
- 不改登录页、锁屏、学校卡片、访客、Apps 的行为与文字（不新增需要翻译的字符串）。
- 不给学校换壁纸的设置项（以后另议）。

**反目标**（做出来就算失败）

- 开机画面挡住任何要人看或要人按键的东西：TPM 失败后的恢复密钥输入、恢复出厂的确认、/usr 自修的“不要关机”提示、
  首次开机的提示。
- 外观里出现宗教符号或经文。
- 某个语言（泰文、阿拉伯文、中文）在登录页或桌面上显示成方块或被截断。
- 学校 logo 被 MastersOS 品牌盖住：登录页上学校是主角，MastersOS 只在角落。
- 渐变出现色带；4K 屏上壁纸模糊。

## 3. 品牌（效果图已获批，2026-11-04）

效果图的源文件在本机 `.superpowers/brainstorm/81096-1793775885/sources/`（未进库）：`wallpaper4.html`（壁纸生成器，
`?m=night|day`，1920×1200 的 SVG，可按 2 倍设备像素比渲染出 3840×2400）、`system.html`（开机、登录、锁屏、桌面四屏效果图，
`?s=boot|login|lock|desktop`，含 logo 的 SVG symbol）、`logo-final.html`、`shots.sh`。实施时把它们整理进 `image/brand/`（5.1）。

**效果图与本文不一致时以本文为准**：效果图定的是视觉风格（颜色、材质、比例、标志的位置），不是界面结构。登录页效果图里的
“Wi-Fi” 按钮、右下角 “14:32 · English”、没有顶栏，桌面效果图里顶栏状态区的单色 M，都只是示意，不做、也不进截图对比（我的取舍：
做了就要新增界面文字与翻译，违背第 2 节；顶栏里点不了的标志只是占位）。

- **Logo**：深色圆角图块（`#262B42`→`#11131F` 竖向渐变，顶部 1px 高光描边），白色 M 的两笔在中间断开，指向交汇点上一颗
  暖色光点（中心 `#FFF1D6` → `#FFB35C` → `#F25A6A`，外围柔光）。几何（viewBox 100）：竖笔 x=23/77，y 30→74；
  斜笔到 (41,51) 与 (59,51)；笔宽 10，圆头圆角；光点 (50,62) r=8.5，柔光 r=13；图块圆角 23。
  单色版（顶栏、快捷设置、Plymouth 小图）：同样的 M 与实心点，`currentColor`，笔宽 12。
- **文字标志**：Plus Jakarta Sans（OFL），“Masters” 600、“OS” 500 半透明，字距 -0.025em；进库时转成路径，设备上不需要这个字体。
- **配色**：夜空 `#070818` / `#13113A` / `#3A1C4F`，地平线 `#7A2B55` → `#C4475A` → `#F07A55`，光 `#FFB35C` / `#F25A6A`。
  强调色取 GNOME 的 `orange`（最接近的一档；实施时在 VM 上比色，若 `red` 更接近渐变中段则改用它，记在提交里）。
- **壁纸**：夜色，山谷间升起一道光，三层山丘被光照亮的那一侧更亮，天空里几圈很淡的椭圆光环向外扩散（“影响世界”），
  细颗粒防色带。白天版同构图，天空蓝紫到暖杏，是桌面默认壁纸（2026-11-04 已放进效果图页；VM 截图时再请用户过目一次）。

## 4. 方案

| 方案 | 做法 | 取舍 |
|---|---|---|
| **A（选定，用户 2026-11-04）** | 在 Yaru 上加一层：自己的 Plymouth 主题、gschema 默认值（壁纸、深色、强调色、Dock 外观）、现有两个 Shell 扩展的样式表、os-release 的 LOGO | 全走 GNOME/Ubuntu 支持的设置与我们已有的扩展，Ubuntu 升级基本不坏；通知、快捷设置面板仍是 Yaru 的样子 |
| B | A 再加一整套自己的 GNOME Shell 主题（顶栏、通知、快捷设置、菜单全重画） | 每个角落都统一；GNOME 每个大版本改内部结构，主题要跟着修，出错时整个桌面样式会乱 |

选 A：日常看到的画面 A 已经覆盖九成，B 多出的部分不值得长期背维护；以后需要可在 A 上加。

## 5. 设计

### 5.1 源文件与产物

- `image/brand/`：logo 与文字标志的 SVG 母版、壁纸生成器（HTML/SVG，参数化夜间/白天）、`render.sh`（开发者在 Mac 或容器里
  用无头 Chromium 渲染、用 rsvg/ImageMagick 出各尺寸 PNG），以及 `README.md` 说明怎么重出。产物提交进 `mkosi.extra`，
  构建时不渲染（构建机不装浏览器）。
- 产物：
  - `/usr/share/backgrounds/mastersos/mastersos-night.jpg`、`mastersos-day.jpg`：3840×2400，JPEG 质量 ≥ 92（颗粒在压缩后仍防色带，
    VM 截图核对）；
  - `/usr/share/gnome-background-properties/mastersos.xml`：一项，`filename` 白天、`filename-dark` 夜间；
  - `/usr/share/icons/hicolor/{16,24,32,48,64,128,256,512}x…/apps/mastersos-logo.png` 与 `scalable/apps/mastersos-logo.svg`，
    以及单色 `symbolic/apps/mastersos-logo-symbolic.svg`；
  - Plymouth 主题目录 `/usr/share/plymouth/themes/mastersos/`（5.2）；
  - 登录页、锁屏用的文字标志 `/usr/share/mastersos/brand/wordmark-light.svg`。
- 体积：全部产物合计控制在 15 MiB 内（/usr 每个槽位是固定 8G 分区，余量不是问题，上限只为防止误放大图）。

### 5.2 开机画面（Plymouth）

- 主题用 `two-step` 模块（Ubuntu 的 spinner 主题就是它）：支持 BGRT（固件厂商 logo 留在上方，像 Windows）、进度条、
  密码与问答提示、`display-message`。我们的：黑底 `#090A16`，中间 M 标志带柔光（光点一呼一吸的几帧动画），底部一条
  细进度条（暖色渐变）。是否保留 BGRT 厂商 logo：实施者在 Dell 与 VM 上各看一次，取更干净的那个，记在提交里。
- 设为默认主题（`plymouth-set-default-theme` 或 `/usr/share/plymouth/plymouthd.defaults`，以 resolute 的做法为准），
  并进 initrd：`mkosi.initrd.conf` 加 `plymouth`、`plymouth-label` 等需要的包与主题文件，`build.sh` 检查 initrd 里有它。
- 内核命令行加 `quiet splash`（主 UKI）；`lab` profile 继续 `console=ttyS0,115200`，串口照样有日志。
- **必须继续能用的东西**（反目标第一条），逐项在 VM 上验证：
  - TPM 解锁失败 → 恢复密钥提示出现在 Plymouth 的密码框里，输对能进系统；
  - `mastersos-factory-reset-confirm`（initrd，读键盘）：确认提示看得见、按键有效；必要时它先 `plymouth hide-splash`
    或 `plymouth quit`，与首次开机服务的做法一致；
  - `usr-repair` 的 `plymouth display-message`：主题把消息显示在标志下方，看得清；
  - `mastersos-firstrun` 照旧 `plymouth quit` 后在 tty1 提示；
  - 正常开机：从固件 logo 到登录页之间没有文字闪现、没有黑屏超过一秒的空档（GDM 接管时 Plymouth 平滑退出）。

### 5.3 GNOME 默认值（`90_mastersos.gschema.override`）

- `org.gnome.desktop.background`：`picture-uri` 白天、`picture-uri-dark` 夜间，`picture-options='zoom'`。
- `org.gnome.desktop.interface`：`color-scheme='default'`（浅色，见第 2 节的学生取舍），`accent-color` 见第 3 节。
- `org.gnome.shell.extensions.dash-to-dock`：在已有的底部整宽布局上加 `transparency-mode='FIXED'`、
  `background-opacity` 约 0.45、`custom-background-color=true`、`background-color` 取夜空深色；agent 的
  `DOCK_LAYOUT`（`core/mastersos-agent/src/system/desktop.rs`）只写位置与尺寸，不写这些键，镜像默认值就生效。
  agent 若因此要改，锁住模式（旧浏览器模式快照）的输出必须逐字节不变。
- 构建时读回校验（与 Dock 位置的校验同一段，`mkosi.postinst.chroot`）。

### 5.4 登录页（`mastersos-login@mastersos.org`）与锁屏

- `.mastersos-login-background`：背景改成夜间壁纸（`background-image: url(file:///usr/share/backgrounds/mastersos/mastersos-night.jpg)`，
  `background-size: cover`），上面一层上下渐暗的遮罩，保证白字对比度。
- 用户名那一步的卡片区（头像、输入框；2026-11-05 起不再有 Local manager，IT 维护登录在左下角的 “Managed by”）：半透明深色毛玻璃（GNOME Shell 的 CSS 没有 backdrop-filter；用
  半透明底色加细描边与阴影做出效果图的观感，能用 Shell 的 blur effect 就用，实施者取舍）、圆角 24、输入框聚焦用暖色描边，
  `.mastersos-pill:focus` 等的 `#8ab4f8` 蓝色焦点一并改成品牌暖色。
  只画一层卡片（2026-11-05）：GNOME 50 给 AuthPrompt 与其内的输入区 `_inputWell` 同一个类 `login-dialog-prompt-layout`，
  所以样式只挂在 `.login-dialog > .login-dialog-prompt-layout`（对话框的直接子元素，即 AuthPrompt），输入区里不再套第二个框。
- 学校 logo 与名字仍在卡片顶部、是主角；左下角加 MastersOS 图块 + 文字标志（小、85% 不透明）。
- 学校登录卡片（白底、承载网页）保持白色，只改圆角与阴影使其与毛玻璃卡片协调。
- 锁屏（用户会话的 unlock dialog）：GNOME 50 用用户自己的桌面壁纸、模糊后做背景（默认就是夜间壁纸），`mastersos-login` 不在
  用户会话里运行，`.mastersos-login-background` 碰不到它。**接受 GNOME 的模糊壁纸**，不去覆盖 GNOME 内部的锁屏背景代码
  （那正是方案 A 要避开的维护负担；我的取舍，效果图里清晰的锁屏背景只是示意）。只做：`mastersos-managed` 在 unlock-dialog
  模式下加左下角标志、按需调时钟样式。
- RTL（阿拉伯文、希伯来文）：左下角标志在 RTL 下换到右下角；所有改动在 RTL 与泰文、中文下截图。

### 5.5 桌面

- 顶栏：`mastersos-managed` 的样式表把 `#panel` 背景改成半透明深色 `rgba(8,8,20,0.55)`（桌面的会话模式是 `ubuntu`，
  父模式 `user`；锁屏和概览按 GNOME 原样）。0.55 而不是计划里的 0.35：默认是浅色的白天壁纸，0.35 时顶栏白字对比不够（终审）。
- 快捷设置里“This device is managed by …”那一行：没有学校 logo 时用 `mastersos-logo-symbolic`。顶栏不加 MastersOS 标志（见第 3 节）。
- 关于页：`os-release` 加 `LOGO=mastersos-logo`。
- 锁定应用的出错页 `kiosk-error.html`：底色与强调色对齐品牌（不改文字）。

## 6. 测试

- `image/tests/check-tree.sh` 新增一条：产物齐全（壁纸两张且是 3840×2400、各尺寸 logo、Plymouth 主题文件、背景属性 XML），
  gschema 里引用的路径都存在，体积在 5.1 的上限内。
- `build.sh`：initrd 里有 Plymouth 与 mastersos 主题；默认主题是 mastersos。
- VM（PVE，正式外观的 lab 镜像）逐屏截图，全部保留、新编号：正常开机全过程（录几张或连拍）、恢复密钥提示、恢复出厂确认、
  /usr 自修消息、首次开机提示、登录页（英文、中文、泰文、阿拉伯文）、学校卡片、锁屏、完整桌面、学习模式桌面、访客、
  深浅色各一次、设置 → 外观与关于页。每张与效果图并排比，列出差异与处理。
- Dell 真机：开机画面（BGRT 取舍）、4K/高分屏下壁纸清晰度、登录页。

## 7. 留给实施者

- Plymouth 动画帧数与节奏、柔光的具体做法；BGRT 是否保留（5.2）。
- 毛玻璃在 Shell CSS 里的实现方式（5.4）。
- 强调色在 `orange` 与 `red` 之间的最终取舍（第 3 节）。
- 壁纸 JPEG 与 PNG 的取舍（只要不出色带、体积在上限内）。
