# MastersOS glossary

The console, the signing page, the settings reference, MCP tool descriptions and skills all use these terms.
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
| Publish | 发布 | Freeze the draft as a new signed version that devices pick up. | deploy, release, push |
| Version | 版本 | One published, signed, numbered snapshot of the settings (v1, v2, ...). | revision, build |
| Settings | 设置 | What a school configures for its devices (the TOML document). | manifest, bundle |
| Settings reference | 设置规范 | The public specification of every settings key. | manifest spec, schema page |
| Signing key | 签名钥匙 | A key that signs versions: a passkey or a recovery kit's key. | cert, token |
| Passkey | 通行密钥 | A signing key held on a phone or security key, bound to the signing page's host. | WebAuthn credential, FIDO key |
| Recovery kit | 恢复套件 | The printed or PDF kit holding the school's recovery signing key; the only thing that may change trust. | recovery file, master key |
| Trust | 信任 | The set of keys that devices accept signatures from, plus escrow recipients, carried in each version. | allow-list, key ring |
| Escrow recipient | 托管接收方 | A recovery kit's public key to which devices seal their disk recovery keys. | escrow key, backup key |
| Heartbeat | 心跳续期 | A signature stating that the latest version is still current; devices warn when it expires. | keep-alive, renewal token |
| Issue | 问题 | One finding from checking settings, with a level: error, warning or info. | lint, diagnostic |
| Error / Warning / Info | 错误 / 警告 / 提示 | Issue levels. Errors block publishing; warnings and info do not. | fatal, note |
| Problems | 问题列表 | The panel that lists the issues of the settings being edited. | diagnostics, output |
| Ready to publish | 可以发布 | The state when the draft has no errors. | valid, green |
| Publish request | 发布请求 | A pending version prepared for signing, valid for 30 minutes. | pending commit |
| Lock | 锁定 | Restrict a device to a single kiosk app or lock its screen. | freeze |
| Kiosk app | 锁定应用 | An app that a device is locked to in single-app (kiosk) mode, such as an exam. | exam app, locked app |
| Factory reset | 恢复出厂设置 | Wipe and recreate a device's data partition. | wipe, reimage, format |
| Inbox command | 收件箱命令 | A one-shot command a device fetches from its inbox (for example, factory reset). | job, task, remote command |
| School | 学校 | One tenant of the cloud service. | tenant, organisation, site |
| Admin | 管理员 | A person who signs in to a school's console. | operator (the operator runs the cloud), user |
| Signing page | 签名页 | The separate page on its own origin where passkeys and recovery kits are used. | sign app, signer |

Notes for Chinese: say 设备 for every device (never 机器 or 电脑); say 设置 for settings; keep product and tool names
(MastersOS, mastersos-sign, TOML, LUKS, TPM, X25519) in Latin letters.
