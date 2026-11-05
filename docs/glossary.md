# MastersOS glossary

The console, the settings reference, MCP tool descriptions and skills all use these terms.
English is the source language; the Simplified Chinese column is what the zh-Hans interface says.
TOML keys, API paths and MCP tool names are never translated or renamed.

| English | 简体中文 | Definition | Do not say |
|---|---|---|---|
| Device | 设备 | A laptop running MastersOS that a school manages. | machine, laptop, computer, PC |
| Config | 配置 | What a device looks like: its mode, sign-in, Wi-Fi, apps, Chrome and so on (`[[config]]`). Several groups can share one config. | profile, policy, template |
| Group | 分组 | A set of devices that use the same config (`[[group]]`). | class, fleet, OU |
| Mode | 模式 | What a session on a device offers, chosen per config (`interface`): Learning or Full; Create (创造) is coming soon. | interface, desktop mode, browser mode |
| Learning | 学习 | The mode for students: Chrome, web apps, kiosk apps and the config's Flatpak apps, without system access (`interface = "learning"`). | browser mode, student mode, restricted |
| Full | 全功能 | The mode for teachers and staff: the full desktop (`interface = "full"`). | desktop mode, admin mode, unrestricted |
| Draft | 草稿 | The editable settings of a school that are not yet published. | working copy, WIP |
| Publish | 发布 | Turn the settings into a new version, approved with a school key, that devices pick up. | deploy, release, push |
| Version | 版本 | One published, signed, numbered snapshot of the settings (v1, v2, ...). | revision, build |
| Settings | 设置 | What a school configures for its devices (the TOML document). | manifest, bundle |
| Settings reference | 设置规范 | The public specification of every settings key. | manifest spec, schema page |
| School key | 学校钥匙 | A small file (plus a printed copy) that approves settings for every device and can unlock their disks. Made on the command line with `mastersos-sign school-key new`; keep it on a USB stick. | recovery kit, recovery package, recovery key, kit, signing key, master key |
| Key code | 钥匙码 | The first 8 hex digits of a school key's id, grouped 4-4 (`11d9-03eb`): on the printed copy, in the file name and on the School keys page. Full fingerprints still appear where trusted keys change. | fingerprint, key id |
| Check code | 核对码 | The first 8 hex digits of an upload's digest (`a1b2c3d4`), printed by `mastersos publish` and shown on the approve page; equal means "this is what you uploaded". | digest, hash |
| Trusted keys | 受信钥匙 | The school keys whose approval devices accept, carried in each version (`[[trust]]` in `manifest.toml`, written by `mastersos init` and `mastersos keys`). Shown only in `manifest.toml` comments and review screens. | trust, allow-list, key ring |
| Disk unlocking | 磁盘解锁 | What a school key does for a device's encrypted disk: the device stores its recovery code so that the school key can open it (`[school].escrow_recipients`). | escrow, escrow recipient, backup key |
| Monthly check-in | 每月确认 | Tells every device "nothing new; what you have is current". `mastersos publish --school-key` does it with every publish; otherwise the admin site reminds IT. | heartbeat, heartbeat renewal, keep-alive |
| Install file | 装机文件 | The file that goes on the installation USB stick so a new device knows its school. | seed |
| Issue | 问题 | One finding from checking settings, with a level: error, warning or info. | lint, diagnostic |
| Error / Warning / Info | 错误 / 警告 / 提示 | Issue levels. Errors block publishing; warnings and info do not. | fatal, note |
| Problems | 问题列表 | The panel that lists the issues of the settings being edited. | diagnostics, output |
| Ready to publish | 可以发布 | The state when the draft has no errors. | valid, green |
| Lock | 锁定 | Restrict a device to a single kiosk app or lock its screen. | freeze |
| Kiosk app | 锁定应用 | An app that a device is locked to in single-app (kiosk) mode, such as an exam. | exam app, locked app |
| Factory reset | 恢复出厂设置 | Wipe and recreate a device's data partition. | wipe, reimage, format |
| Inbox command | 收件箱命令 | A one-shot command a device fetches from its inbox (for example, factory reset). | job, task, remote command |
| School | 学校 | One tenant of the cloud service. | tenant, organisation, site |
| Admin | 管理员 | A person who signs in to a school's console. | operator (the operator runs the cloud), user |

Notes for Chinese: say 设备 for every device (never 机器 or 电脑); say 设置 for settings; keep product and tool names
(MastersOS, mastersos-sign, TOML, LUKS, TPM, X25519) in Latin letters.
