# 学校上线验证清单（2026-11-06）

学校第一次切到 MastersOS（或换一套登录方式）时照这份走。全部在 PVE 虚拟机上做（2026-11-06 David 定，不用真机）：
第 1 台虚拟机走完第 2 节，再用第 2 台虚拟机做第 3 节，两节都通过才切换（M4 切换的标准）。每一步写了**要看到什么**；看不到就停，
留证据（截图 + 下面「留证据」的命令输出）再查，不要往下走。虚拟机测不了的项目列在第 4 节「未覆盖」。

`<更新源>` 是 `build-info.txt` 里的 `update_base`。

## 0. 发版（运维在 CI 上做，不在笔记本上）

把一个 beta 版本推到 stable（`mastersos-promote`，docs/update-channels.md「Publishing from CI」）：

1. 先确认 beta 上这个版本在 lab 机器上跑过：OTA 升上去、`Marked boot as 'good'`、登录走通。
2. 比较两版的 `build-info.txt`（`<更新源>/stable/` 最新的和 `<更新源>/beta/` 要推的）：
   - `shim_sha256` 相同 → 不要勾 `allow_shim_change`；
   - `sdboot_unsigned_sha256` 与 `sdboot_signer_sha256` 都相同 → systemd-boot 只是重签，不要勾 `allow_bootloader_change`。
   - 有不同的，先读 docs/secure-boot.md「引导程序更新与 TPM」，在 lab 虚拟机（Secure Boot + vTPM）上装过、确认能启动再勾。
3. Actions → mastersos-promote → `version` 填版本号，运行，在 `release` 环境里批准。
4. 推完验证：
   - `curl -fsS <更新源>/stable/SHA256SUMS` 列出这个版本的文件；`SHA256SUMS.gpg` 能下载。
   - `curl -fsS <更新源>/installer/SHA256SUMS` 列出 `MastersOS-installer_<版本>_x86-64.img.zst` 与
     `MastersOS-ventoy_<版本>_x86-64.zip`；下载其中一个，`sha256sum` 与列表一致（docs/install.md 第 1 节的做法）。
   - 缺文件必须是 404 不是 403：`curl -s -o /dev/null -w '%{http_code}\n' <更新源>/stable/SHA256SUMS.sha256.asc` 应为 404
     （403 会让每台机器的 sysupdate 失败，见 docs/update-channels.md）。
   - 一台走 stable 的 lab 机器跑 `sudo systemctl start mastersos-update.service`，`journalctl -u mastersos-update` 里看到下载了这个
     版本；重启后 `grep IMAGE_VERSION /etc/os-release` 是它，`journalctl -b -u systemd-bless-boot` 有 `Marked boot as 'good'`。
   - GitHub Release `image-release-<版本>` 不再是 Pre-release。

## 1. 设置切换（在云端控制台做）

- 发布设置前，发布检查不能有 ERROR（例如 Google issuer 而 `allowed_domains` 为空会报 `public_idp_without_allowed_domains`）。
- 发布后在设备页看到测试机回报的设置版本号等于刚发布的版本（机器在线时几分钟内）。

## 2. 第 1 台虚拟机

虚拟机要和笔记本一样开 Secure Boot、带 vTPM、4 GB 内存，从 stable 最新版本的 U 盘镜像装（`image/lab/vm-create.sh`）。

| # | 做什么 | 要看到什么 |
|---|---|---|
| 2.1 | 开机 | 不要恢复密钥（vTPM 解开了磁盘）；进登录页；时间正确；有网 |
| 2.2 | 查版本与设置 | 设备页的系统版本 = 要上线的版本；设置版本 = 刚发布的 |
| 2.3 | Wi-Fi | PVE 上的 Intel AX200 直通给这台虚拟机，拔掉虚拟网卡：开机后自动连上设置里的 Wi-Fi，不用手动选 |
| 2.4 | 点登录卡片 | 打开的是学校设置里的 issuer（地址栏的主机名对）；设置了 `idp_hint` 的，不出现「选择登录方式」页，直接到学校的 SSO |
| 2.5 | 学生账号登录 | 进桌面，不弹钥匙环；桌面 Chrome 打开学校网站已是登录状态 |
| 2.6 | 不该进来的账号 | 学校域名外的个人账号、监护人账号登录被拒，提示里没有英文报错堆栈 |
| 2.7 | 在桌面放一个文件、Chrome 开几个网页，注销再登录 | 文件还在，Chrome 仍是登录状态 |
| 2.8 | 重启再登录 | 不要恢复密钥；文件和 Chrome 登录状态还在 |
| 2.9 | 断网后锁屏再解锁 | 按设计：断网时锁屏要联网才能回桌面；联网后能回 |
| 2.10 | 「获取帮助」 | 登录页和桌面各发一次，云端能看到这两条 |
| 2.11 | 开 10 个常用网页（YouTube、Classroom、Docs、Canva…） | 切换不卡；`free -m` 的 available 不低于 300 MB；`swapon --show` 有 `/dev/zram0` |

## 3. 第 2 台虚拟机：同一台机器上的多个账号

同样的装法（第 2 节 2.1、2.2 先过），然后：

| # | 做什么 | 要看到什么 |
|---|---|---|
| 3.1 | 账号 A 登录、注销，同一账号 A 再登录，重复 5 次 | 每次都进桌面（见「已知问题」的卡住现象；出现一次就记下第几次、留证据） |
| 3.2 | 注销 A，账号 B 登录 | 进的是 B 自己的桌面，看不到 A 的文件和 Chrome 登录状态 |
| 3.3 | 注销 B，A 再登录 | A 的文件和 Chrome 登录状态还在 |
| 3.4 | 重启后 B 登录 | 不要恢复密钥；B 的数据还在 |

## 4. 未覆盖（虚拟机测不了）

- 声音、摄像头、触摸板、亮度和音量键、合盖休眠再唤醒；
- 电池、续航与降频（thermald）；
- 真机固件上的 Secure Boot（MOK 登记、厂商固件的启动项）与真 TPM 芯片；
- 真机的显卡驱动与外接显示器。

这些靠之前 Dell Latitude 上的实测（docs/hardware.md），上线后出问题的机器用「获取帮助」带诊断包回报。

## 给老师的说明（20261105.15）

1. 学生用学校账号登录进桌面后，打开 Chrome 要**再登录一次学校账号**（这一版还不会自动带过去，下一版修好）。
2. 登录页的输入框按键没反应时：**按一下电源键**，电脑会正常关机；再按电源键开机即可，学生的文件不会丢。

## 留证据

每台每一步截图（编号接着排，不覆盖不删除），出问题时在 tty3 用 IT 账号收：

```bash
sudo journalctl -b -u gdm -u authd -u authd-oidc -u mastersos-agent --no-pager > /tmp/login.log
coredumpctl list
```

或者用「获取帮助」里勾上诊断包，云端直接收。

## 已知问题与恢复

- **同一账号注销后再登录，偶发卡在「Signed in. Starting your session...」**（2026-11-05 VM 123 首次见到，上个会话注销时
  gdm-session-worker 段错误）。复现条件与恢复办法见下面的复测记录。
  - 复测记录（2026-11-06，20261105.15，VM 123，学校的 Zitadel）：同一账号注销再登录 8/8、两个账号交替 4/4、重启后 1 次，
    13 次全部进桌面，没有复现，gdm-session-worker 没有崩。证据在 `image/lab/results/2026-11-06-sso-15/`。真出现时：按一下
    电源键（干净关机），再开机。
- **20261105.15 上桌面 Chrome 不会自动登录**：卡片的会话交给了用户（日志 `handed to uid …`），但用户这边导入时
  `signin-import: … mastersos-signin: Permission denied`。修复在 1b3ecb99，之后的镜像才有；.15 上学生进桌面后在 Chrome 里
  再登一次学校账号。
- 登录卡片 3 分钟超时之后，登录页的邮箱框偶尔不再接受输入（2026-11-06 见过 1 次，那个登录页已运行 2.5 小时，复现 0/1）：
  按一下电源键关机再开机。
- 从别的终端切回登录页时邮箱框没有焦点：先按一次 Tab。
- 上面两个登录页问题记在 issue #13，下一个镜像上复测。
- 20261105.15 之前的镜像没有 systemd-coredump：gdm 等崩溃默认不留 core。之后的镜像只收登录栈与 agent 的 core（只在本机）。
- 从 20261030.1 之前的版本升上来的机器，登录页会出一次「语言和键盘」首次设置页（旧版没写 `/etc/locale.conf` 的 LANG），
  选一次就不再出现。

## 内存（2026-11-06，VM 124，4 GB，20261105.15）

无界面 Chrome（headless，未登录），每次开完等 60 秒：

| 情况 | 已用 | 可用 | Chrome PSS | swap |
|---|---|---|---|---|
| 登录页空闲 | 0.73 GB | 3.1 GB | — | — |
| 10 个网页，无 zram | 2.3 GB | 1.5 GB | 1.6 GB | 无 |
| 20 个网页，无 zram | 3.4 GB | 0.42 GB | 2.6 GB | 无 |
| 20 个网页，zram（zstd） | 3.4 GB | 0.45 GB | 2.5 GB | 717 MB 进 zram，压成 224 MB（3.2:1） |

结论：4 GB 能开 10 个常用网页，余量充足；20 个已经接近上限，zram 多出约 0.5 GB 余量（压缩比约 3:1）。实际桌面加上有界面、
登录后的 Docs/Classroom 会更重。写对外数字时用「最低 4 GB，推荐 8 GB」。zram 从 20261105.15 之后的镜像开始默认开启
（`usr/lib/systemd/zram-generator.conf`）。
