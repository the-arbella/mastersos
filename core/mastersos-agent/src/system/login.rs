//! 登录策略（Ruling 4、5、11）：谁能在这台机器上登录。
//!
//! - 判定在 PAM 的 account 阶段：`account requisite pam_exec.so quiet stdout /usr/bin/mastersos-agent pam-check`
//!   插在 `common-account` 最前面，GDM 的各个服务、tty 的 `login`、`sshd`、`su` 都经过它。
//!   [`pam_check_main`] 读 [`POLICY_PATH`] 与种子，交给纯函数 [`decide`]。
//! - 策略文件由 `login` 步骤（以及 Task 17 的 `lock` 步骤）用 [`write_policy`] 写；内容只由包决定。
//!   还没有包时按种子的默认值写（[`policy_from_seed`]：总开放访客；种子带 `oidc` 时再开放 SSO）。
//! - 访客对所有配置常开（只有锁定时 [`decide`] 才拒）：[`policy_from_bundle`] 与 [`policy_from_seed`] 的方式总含 `guest`。
//! - authd 的 broker 有两处要同步：drop-in（学校的 issuer 与 client_id）与注册文件
//!   （`/etc/authd/brokers.d/oidc.conf`，GDM 的 broker 列表读它）。只有学校配好 SSO 时两处都写，否则都删，
//!   这样没配 SSO 的机器上登录界面不会列出一个选了就报 "could not activate remote peer" 的 OIDC。
//!   注册文件的内容来自镜像里的 [`BROKER_DECL_SRC`]。
//! - The school's domain list is enforced in the broker too ([`render_domains_file`], patch 0006): authd registers a user
//!   the moment the broker grants access, before `pam-check` runs, so an account refused only here would stay behind as
//!   a local user. `pam-check` keeps the same check as the second line. The domains sit in a file of their own beside
//!   `broker.conf` ([`DOMAINS_FILE`]), never in the drop-in: an older broker (a rollback) never reads it, and the drop-in
//!   keeps only keys it knows, so it starts at once. Fail closed: with domains the drop-in carries [`DOMAINS_MARKER`] (the
//!   patched broker then lets only named users through while the file is missing), and when the file cannot be written
//!   the drop-in names only the administrators ([`render_broker_conf_admins_only`]), never `ALL`.
//! - The login screen's sign-in card (image: `mastersos-login-browser.service`) runs Chrome with a policy of its own:
//!   [`render_login_browser_policy`] allows only the issuer's origin, the signed `card_hosts` and the broker's redirect. It is written next to the
//!   broker drop-in and removed with it; the unit does not start without the file. With `[school.oidc] idp_hint` the step
//!   also writes [`LOGIN_CARD_FILE`] ([`render_login_card`]) for the login screen's extension, which adds the hint to the
//!   authorization URL.
//! - 策略文件缺失或坏了，`pam-check` 退回种子的默认值（[`effective_policy`]），而不是一律拒绝：
//!   否则 `admin_users` 也被锁在外面，机器上没有别的管理员能修。种子也读不了才拒绝。
//! - `pam-check` 不 panic、出错一律按「没有」处理并往拒绝的方向落（模块级 deny 守着 unwrap / expect / panic）。
//! - `admin_users` 里的账号不受登录方式、锁定**与域名限制**约束（账号是点名写进去的）。管理员都是 SSO 账号：
//!   分组的方式里没有 `sso` 时 broker 配置被删掉，管理员实际上也登录不了（lint 警告 `admins_without_sso`）。
//! - 锁定应用（计划 9 设计 §4.2、裁定 K10）：策略带分组的锁定应用的账号名单 `kiosk_users`。名单里的 `kiosk-<id>` 只从
//!   GDM 进（cron、at 在放行表之前就拒），不看登录方式与域名，锁定时拒；受管机器上 `kiosk-` 是保留的前缀，名单外的
//!   同名账号一律拒（不当本机账号放行）。`pam-session` 与 `ephemeral-cleanup` 经 [`installed_policy`] 读同一份名单。
//! - The IT maintenance account [`IT_ACCOUNT_USER`] (`itadmin`, phase B design §10.4): when the settings (or the seed)
//!   carry a valid `it_account`, the policy says so ([`LoginPolicy::it_account`]) and `itadmin` may sign in whatever
//!   `methods` and the domain list say; a locked device still denies it. Without it (old policy files included),
//!   `itadmin` is just a local account and follows the local-account rules.
//! - 策略文件不超过 [`MAX_POLICY_BYTES`]（写的一方拒绝更大的，读的一方读到更大的当作坏了）。写不下时
//!   `login` 步骤改写一份锁定的策略（方式清空、只放行管理员）并回报失败，而不是留一份会被当作「没有」、
//!   从而退回更宽松的种子默认值的文件。

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mastersos_bundle::{
    checks, kiosk, Config, ItemResult, Lock, LoginMethod, Oidc, School, Seed, IT_ACCOUNT_USER,
};
use serde::{Deserialize, Serialize};

use super::{failed, ok, public_dir, var_dir, Env, Step, SysPaths};
use crate::apply::{is_not_found, ApplyContext};
use crate::runner::{run_ok, Cmd};
use crate::safefs;

/// 回报项的名字。
pub const ITEM: &str = "login";

/// 策略文件（0644：PAM 以 root 读，内容不含秘密；父目录 `/var/lib/mastersos-system` 是 0700）。
pub const POLICY_PATH: &str = "/var/lib/mastersos-system/login/policy.json";
/// `POLICY_PATH` 在 `SysPaths::var_dir` 下的子目录与文件名。
const POLICY_SUBDIR: &str = "login";
const POLICY_FILE: &str = "policy.json";

/// authd 的 OIDC broker 的 drop-in 目录（相对系统根）与我们写的文件（0600：目录也是 0700）。
pub const BROKER_DIR: &str = "etc/authd/oidc/broker.conf.d";
pub const BROKER_FILE: &str = "10-mastersos.conf";
/// The broker's domain file (patch 0006): beside `broker.conf`, outside `broker.conf.d/`, so a broker without the patch
/// never reads it (it would refuse to start on an unknown configuration key). Relative to the system root.
pub const DOMAINS_DIR: &str = "etc/authd/oidc";
pub const DOMAINS_FILE: &str = "mastersos-allowed-domains";
/// A whole comment line of the drop-in that tells the patched broker the domain file is required: while it is missing or
/// unreadable that broker lets only the users named in `allowed_users` through, so a file that goes away never turns
/// `ALL` into everyone. A broker without patch 0006 reads it as a comment and starts as before. Must match
/// `mastersosRequiredMarker` in the patch.
pub const DOMAINS_MARKER: &str = "# mastersos: allowed domains required (patch 0006)";

/// The broker registration that ships in the image (not active there), relative to the system root.
/// The agent copies it to [`BROKER_DECL_DIR`]/[`BROKER_DECL_FILE`] only when the school has SSO configured.
pub const BROKER_DECL_SRC: &str = "usr/lib/mastersos/authd/oidc-broker.conf";
/// Where authd reads broker registrations (relative to the system root; a real directory, see etc-policy.conf).
pub const BROKER_DECL_DIR: &str = "etc/authd/brokers.d";
pub const BROKER_DECL_FILE: &str = "oidc.conf";

/// Where the sign-in card's Chrome policy lives, under [`SysPaths::public_dir`] (the greeter's browser reads it; it holds
/// only the identity provider's host). The image's unit binds the directory over `/etc/opt/chrome/policies/managed`.
pub const LOGIN_BROWSER_DIR: &str = "login-browser/policies";
pub const LOGIN_BROWSER_FILE: &str = "mastersos-login.json";
/// What the login screen's extension reads for the card itself (not Chrome: it sits beside the policy directory, not in it),
/// under [`SysPaths::public_dir`]: `{"idp_hint": "<value>"}`, there only when the valid `[school.oidc]` has an `idp_hint`.
/// card.js adds `idp_hint=<value>` to the authorization URL so an identity broker goes straight to the school's provider.
pub const LOGIN_CARD_DIR: &str = "login-browser";
pub const LOGIN_CARD_FILE: &str = "card.json";
/// The broker's redirect (`0003-authorization-code-on-greeter.patch`, `authCodeRedirect`) as a URL-filter entry.
pub const LOGIN_REDIRECT_FILTER: &str = "127.0.0.1:48123/callback";

/// broker 配置变了之后跑的命令。broker（`authd-oidc.service`）由 D-Bus 激活、启动时读配置、
/// 起来之后一直开着，所以只重启 authd 换不了它读到的配置；两个都 `try-restart`：没在跑的不拉起，
/// 下次被激活时自然读新配置（broker.conf.d 空了时 `ConditionDirectoryNotEmpty=` 让 broker 停下不再起）。
pub const RESTART_AUTHD: &[&str] = &["try-restart", "authd-oidc.service", "authd.service"];

/// 这些 PAM 服务不是「登录」，直接放行：定时任务、用户的 systemd 管理器、sudo、polkit，
/// 以及 GDM 自己的登录界面（`gdm-launch-environment`，用户 `gdm` 或动态的 `gdm-greeter*`；
/// 挡了它就没有登录界面。Task 8 Step 3 在 VM 上确认）。
pub const PASSTHROUGH_SERVICES: &[&str] = &[
    "cron",
    "systemd-user",
    "sudo",
    "sudo-i",
    "polkit-1",
    "gdm-launch-environment",
];

/// 访客只能从这些服务登录：GDM 的登录界面（Ruling 5）。装了 authd 之后 GDM 对用户列表里的每个人（本机用户、
/// 访客也一样）都走 `gdm-authd`（authd 对本机用户返回 ignore，由 `common-auth` 的 pam_unix 判；Task 8 在 VM 上
/// 看到），`gdm-password` 是没有 authd 时的那一个。两个服务的 session 段最前面都有 requisite 的 `pam-session`
/// （访客的 tmpfs 检查），tty 的 `login`、`sshd`、`su` 都不在其中。
pub const GUEST_SERVICES: &[&str] = &["gdm-password", "gdm-authd"];

/// 访客在这些服务上一律拒绝，哪怕服务在 [`PASSTHROUGH_SERVICES`] 里。
pub const GUEST_DENIED_SCHEDULERS: &[&str] = &["cron", "atd"];

/// 访客的账号名（Ruling 5）。
pub const GUEST_USER: &str = "guest";

/// 锁定应用的账号名的前缀（`kiosk-<id>`，与 `mastersos_bundle::kiosk::account_name` 一致）。受管机器上它是保留的。
pub const KIOSK_PREFIX: &str = "kiosk-";

/// 种子的两个位置，按序：agent 状态目录里的副本，再是种子分区。
pub const SEED_FILE: &str = "seed.toml";
const DEFAULT_STATE_DIR: &str = "/var/lib/mastersos";

/// 策略文件的大小上限：[`write_policy`] 拒绝写更大的，`pam-check` 读到更大的当作坏了。
/// 发布前 lint 限制管理员与域名的个数与长度，正常的策略远小于它（`policy_at_lint_caps_fits`）。
pub const MAX_POLICY_BYTES: usize = 1024 * 1024;
/// `pam-check` 读策略文件、种子与 getent 输出的上限。
const MAX_READ: u64 = MAX_POLICY_BYTES as u64;

/// 写不下时改写的锁定策略带的消息。
pub const OVERSIZE_LOCK_MESSAGE: &str =
    "这台电脑的登录设置太大，暂时锁定，请联系 IT / Login settings too large; this computer is locked, please contact IT";

/// `getent` 的绝对路径：pam_exec 给的环境里不一定有 `PATH`。
const GETENT: &str = "/usr/bin/getent";
/// `getent` 最多等这么久（authd 的用户也经 NSS 查，authd 卡住时不能把登录一起卡死）。
const GETENT_TIMEOUT: Duration = Duration::from_secs(5);

/// 策略文件的格式。**兼容约定**：只加带 `#[serde(default)]` 的字段，不改已有字段的类型——A/B 回滚到旧版
/// 之后，旧的 `pam-check` 解析不了新文件就退回种子的默认值（比包里的设置宽松），直到旧版的 `login` 步骤重写它。
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct LoginPolicy {
    /// `"guest"` / `"local"` / `"sso"`。
    pub methods: Vec<String>,
    /// SSO 账号 `@` 之后的部分（小写）须是其中之一；空 = 不限。
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// 小写；不受 `methods` 与锁定限制。
    #[serde(default)]
    pub admin_users: Vec<String>,
    pub locked: bool,
    #[serde(default)]
    pub lock_message: Option<String>,
    /// 由已接受的设置包写出（`admin_users` 是学校给的名单）；种子的默认值与旧版写的文件为 false。
    /// Task 19 的家目录清理只在它为 true 时动手：管理员名单未知时一个都不删。
    #[serde(default)]
    pub from_bundle: bool,
    /// 这台机器所在分组的锁定应用的账号（计划 9 设计 §4.2），按 `user` 排序。旧版写的文件没有它（= 空）；
    /// 旧版的 `pam-check` 读新文件时忽略它（`LoginPolicy` 不设 `deny_unknown_fields`，别加）。
    #[serde(default)]
    pub kiosk_users: Vec<KioskUser>,
    /// The settings (or the seed) keep the IT maintenance account [`IT_ACCOUNT_USER`]: it may sign in regardless of
    /// `methods` and the domain list, but not on a locked device. Old files lack it (= false: `itadmin` is a local account).
    #[serde(default)]
    pub it_account: bool,
    /// The uid of the `itadmin` the agent created ([`super::SysState::it_account_uid`]): the exception above applies only
    /// to an account with this uid, so an `itadmin` somebody else made follows the local-account rules. `None` (old files,
    /// or not created yet): no exception.
    #[serde(default)]
    pub it_account_uid: Option<u32>,
}

/// 一个锁定应用的账号：`pam-session` 与 `ephemeral-cleanup` 据此造 [`super::ephemeral::kiosk`]（`name` 是账号的名字，
/// 每次清理后恢复成它）；uid 不在这里，一律现查 `getent`。
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct KioskUser {
    /// `kiosk-<id>`。
    pub user: String,
    /// 应用的 `name`。
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserClass {
    Guest,
    Local,
    Sso,
    /// 锁定应用的账号：名字以 [`KIOSK_PREFIX`] 开头**且**在策略的 `kiosk_users` 里。
    Kiosk,
}

impl UserClass {
    /// `LoginPolicy::methods` 里对应的名字。
    pub fn method(self) -> &'static str {
        match self {
            UserClass::Guest => "guest",
            UserClass::Local => "local",
            UserClass::Sso => "sso",
            // 走不到 `methods` 的比较：kiosk 账号在 decide 里先由 decide_kiosk 判完，`methods` 也从不带 "kiosk"
            UserClass::Kiosk => "kiosk",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// 被拒的原因（中英双语），`pam-check` 打到 stdout，GDM 会显示它。
    Deny(&'static str),
}

pub const DENY_BAD_USER: &str = "用户名不合规，不能登录 / Invalid user name";
pub const DENY_BAD_ARGS: &str =
    "登录检查的参数不对（系统配置错误），请联系 IT / Login check misconfigured (bad arguments); please contact IT";
pub const DENY_GUEST_SERVICE: &str =
    "访客只能在登录界面登录 / Guest can only sign in from the login screen";
pub const DENY_NO_POLICY: &str = "这台电脑还没有拿到学校的登录设置，暂时不能登录；请连上网络稍后再试，或联系 IT / \
     This computer has no login settings from the school yet; connect to the network and try again, or contact IT";
pub const DENY_LOCKED: &str =
    "这台电脑已被学校锁定，请联系 IT / This computer has been locked by the school; please contact IT";
pub const DENY_GUEST: &str =
    "这台电脑不允许访客登录 / Guest sign-in is not allowed on this computer";
pub const DENY_LOCAL: &str =
    "这台电脑不允许本机账号登录 / Local accounts cannot sign in on this computer";
pub const DENY_SSO: &str =
    "这台电脑不允许学校账号登录 / School accounts cannot sign in on this computer";
pub const DENY_KIOSK: &str =
    "这个锁定应用只能从登录界面进入 / This app can only be opened from the sign-in screen";
/// kiosk 账号在登录界面的齿轮里换了会话（不是 `mastersos-kiosk`）：`pam-session` 拒绝（计划 9 Task 6，控制者裁定 4）。
pub const DENY_KIOSK_SESSION: &str =
    "这个锁定应用只能在它自己的会话里打开，请在登录界面的齿轮里改回原来的会话 / This app only opens in its own session: switch the session back in the gear menu at sign-in";
/// kiosk 账号开会话时同一个座位上还有别的用户会话（切换用户留下的桌面）：`pam-session` 拒绝（终审 C1）。
pub const DENY_KIOSK_OTHER_SESSION: &str =
    "这台电脑上还有别的会话没有注销，请先回到那个会话注销，再打开这个锁定应用；注销不了就举手找老师 / Another session is still open on this computer: sign out of it first, then open this app, or ask a teacher";
/// 同上，但问不到 logind（往拒绝的方向落）。
pub const DENY_KIOSK_SEAT_UNKNOWN: &str =
    "暂时查不到这台电脑上的其他会话，请稍候再试或举手找老师 / Could not check for other sessions on this computer; try again shortly or ask a teacher";
pub const DENY_KIOSK_UNKNOWN: &str =
    "这个锁定应用已不在这台电脑的设置里 / This app is no longer set up on this computer";
pub const DENY_DOMAIN: &str =
    "这个账号的域名不允许登录这台电脑 / Accounts from this domain cannot sign in on this computer";

/// 用户名等于 `guest` → 访客；含 `@` → SSO（与 `common-password` 的 `pam_succeed_if user !~ *@*` 分流一致）；
/// 以 [`KIOSK_PREFIX`] 开头且在 `policy` 的 `kiosk_users` 里 → 锁定应用（没有策略就不是）；其余 → 本机用户。
/// 名字都精确比较：Linux 的用户名区分大小写，`Guest`、`Kiosk-x` 是另外的本机账号。
pub fn classify(user: &str, policy: Option<&LoginPolicy>) -> UserClass {
    if user == GUEST_USER {
        UserClass::Guest
    } else if user.contains('@') {
        // 先于 kiosk：名单里混进带 @ 的名字也不会让 SSO 账号绕过方式、域名（清单的 id 本来就不许 @）
        UserClass::Sso
    } else if is_listed_kiosk(policy, user) {
        UserClass::Kiosk
    } else {
        UserClass::Local
    }
}

/// 受管机器上保留给锁定应用的名字：以 [`KIOSK_PREFIX`] 开头的**本机**账号名（不含 `@`；SSO 账号照 SSO 的规则判）。
pub fn is_reserved_kiosk_name(user: &str) -> bool {
    user.starts_with(KIOSK_PREFIX) && !user.contains('@')
}

/// 名字以 [`KIOSK_PREFIX`] 开头、且精确地在 `policy` 的名单里。
pub fn is_listed_kiosk(policy: Option<&LoginPolicy>, user: &str) -> bool {
    user.starts_with(KIOSK_PREFIX)
        && policy.is_some_and(|p| p.kiosk_users.iter().any(|k| k.user == user))
}

/// 系统账号与动态账号：uid < 1000 或 ≥ 60000（含 GDM 的 `gdm`、动态的 `gdm-greeter*`、`nobody` 65534）。
pub fn is_system_uid(uid: u32) -> bool {
    !(1000..60000).contains(&uid)
}

/// `PAM_USER` 能不能拿去判断（以及交给 `getent`）：非空、不以 `-` 开头、不含控制字符。
fn user_name_ok(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 256
        && !user.starts_with('-')
        && !user.chars().any(char::is_control)
}

/// 管理员比较不区分大小写，但只折叠 ASCII（与 `checks::admin_user` 一致；开尔文符号 K 不算 k）。
fn is_admin(p: &LoginPolicy, user: &str) -> bool {
    p.admin_users.iter().any(|a| a.eq_ignore_ascii_case(user))
}

/// SSO 账号最后一个 `@` 之后的部分（ASCII 小写）与 `allowed_domains` 之一精确相等；空列表不限。
fn domain_allowed(p: &LoginPolicy, user: &str) -> bool {
    if p.allowed_domains.is_empty() {
        return true;
    }
    match user.rsplit_once('@') {
        Some((_, domain)) => p
            .allowed_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(domain)),
        None => false,
    }
}

/// 按序（Ruling 4、5；计划 9 设计 §4.2、裁定 K10）：
/// 1. 用户名不合规 → 拒（空、以 `-` 开头、含控制字符）；
/// 2. 访客而服务是 cron / at（[`GUEST_DENIED_SCHEDULERS`]）→ 拒；
/// 3. 锁定应用的账号（名单里的 `kiosk-<id>`，或受管机器上任何以 `kiosk-` 开头、不含 `@` 的名字——
///    [`is_reserved_kiosk_name`]；`kiosk-x@school` 这样的 SSO 账号照 SSO 的规则判）而服务是 cron / at → 拒
///    （名单里的 [`DENY_KIOSK`]，名单外的 [`DENY_KIOSK_UNKNOWN`]）；
/// 4. 服务在 [`PASSTHROUGH_SERVICES`] → 放行（kiosk 会话的 `systemd-user` 走这里）；
/// 5. 锁定应用的账号（同第 3 条），**先于**系统账号的放行（uid 落在系统范围也不例外）：
///    受管而没有策略 → 拒（[`DENY_NO_POLICY`]）；不在名单里 → 拒（[`DENY_KIOSK_UNKNOWN`]，不当本机账号放行）；
///    服务不在 [`GUEST_SERVICES`] 里 → 拒（[`DENY_KIOSK`]）；锁定 → 拒；其余放行——不看 `methods` 与域名；
/// 6. 查到的 uid 是系统 / 动态账号、且名字里没有 `@` → 放行（查不到的 `None` 不放行，照三类规则判）；
/// 7. 访客而服务不在 [`GUEST_SERVICES`] 里 → 拒（不论是否受管）；
/// 8. 未受管 → 放行（未受管的机器不认得锁定应用：`kiosk-x` 是普通的本机账号）；
/// 9. 受管而没有策略 → 拒；
/// 10. `itadmin` while the policy has `it_account` and its resolved uid is the policy's `it_account_uid` → denied when
///     locked ([`DENY_LOCKED`]), otherwise allowed (no look at `methods` or domains); any other `itadmin` goes on as a
///     local account;
/// 11. `admin_users` 里的 SSO 账号 → 放行（不受方式、锁定与域名限制）；
/// 12. 锁定 → 拒；该类不在 `methods` 里 → 拒；SSO 账号的域名不在 `allowed_domains` 里 → 拒；其余放行。
pub fn decide(
    service: &str,
    managed: bool,
    policy: Option<&LoginPolicy>,
    user: &str,
    uid: Option<u32>,
) -> Decision {
    if !user_name_ok(user) {
        return Decision::Deny(DENY_BAD_USER);
    }
    // 访客的定时任务（cron、at）会留在下一位访客的会话里、在 user-1999.slice 之外跑：放行表之前就拒（复审 T11 M2）。
    // 镜像里没有 cron 与 at，/etc/cron.deny、/etc/at.deny 也列着 guest，这是第三道
    if user == GUEST_USER && GUEST_DENIED_SCHEDULERS.contains(&service) {
        return Decision::Deny(DENY_GUEST_SERVICE);
    }
    let class = classify(user, policy);
    // 受管机器上 `kiosk-` 是本机账号名的保留前缀：名单外的同名本机账号不能冒用锁定应用、也不能当本机账号放行。
    // 带 @ 的是 SSO 账号（classify 已分成 Sso），照 SSO 的规则判，管理员豁免照旧
    let kiosk = class == UserClass::Kiosk || (managed && is_reserved_kiosk_name(user));
    let listed = class == UserClass::Kiosk;
    // kiosk 账号的定时任务同访客：会在锁定会话之外、下一位进来时还在跑
    if kiosk && GUEST_DENIED_SCHEDULERS.contains(&service) {
        return Decision::Deny(if listed {
            DENY_KIOSK
        } else {
            DENY_KIOSK_UNKNOWN
        });
    }
    if PASSTHROUGH_SERVICES.contains(&service) {
        return Decision::Allow;
    }
    if kiosk {
        return decide_kiosk(service, policy, listed);
    }
    // 系统与动态账号的名字里没有 @；SSO 账号不走这条，免得 authd 的 uid 范围哪天配到 60000 以上时
    // 所有学校账号都绕过方式、域名与锁定（authd 0.6.1 实测从 10000 起分，S1 与 Task 8）。
    if class != UserClass::Sso && uid.is_some_and(is_system_uid) {
        return Decision::Allow;
    }
    if class == UserClass::Guest && !GUEST_SERVICES.contains(&service) {
        return Decision::Deny(DENY_GUEST_SERVICE);
    }
    if !managed {
        return Decision::Allow;
    }
    let Some(p) = policy else {
        return Decision::Deny(DENY_NO_POLICY);
    };
    if user == IT_ACCOUNT_USER && p.it_account && uid.is_some() && uid == p.it_account_uid {
        return if p.locked {
            Decision::Deny(DENY_LOCKED)
        } else {
            Decision::Allow
        };
    }
    if class == UserClass::Sso && is_admin(p, user) {
        return Decision::Allow;
    }
    if p.locked {
        return Decision::Deny(DENY_LOCKED);
    }
    if !p.methods.iter().any(|m| m == class.method()) {
        return Decision::Deny(match class {
            UserClass::Guest => DENY_GUEST,
            UserClass::Local => DENY_LOCAL,
            UserClass::Sso => DENY_SSO,
            // 走不到：kiosk 账号在前面由 decide_kiosk 判完；`methods` 从不带 "kiosk"
            UserClass::Kiosk => DENY_KIOSK,
        });
    }
    if class == UserClass::Sso && !domain_allowed(p, user) {
        return Decision::Deny(DENY_DOMAIN);
    }
    Decision::Allow
}

/// [`decide`] 的第 5 条：锁定应用的账号（服务已不是 cron / at、不在放行表里）。
fn decide_kiosk(service: &str, policy: Option<&LoginPolicy>, listed: bool) -> Decision {
    let Some(p) = policy else {
        return Decision::Deny(DENY_NO_POLICY);
    };
    if !listed {
        return Decision::Deny(DENY_KIOSK_UNKNOWN);
    }
    if !GUEST_SERVICES.contains(&service) {
        return Decision::Deny(DENY_KIOSK);
    }
    // 裁定 K10：挂失锁定的机器上一样登不进去（管理员的豁免不适用：kiosk 账号不是管理员）
    if p.locked {
        return Decision::Deny(DENY_LOCKED);
    }
    Decision::Allow
}

fn method_name(m: LoginMethod) -> &'static str {
    match m {
        LoginMethod::Guest => "guest",
        LoginMethod::Local => "local",
        LoginMethod::Sso => "sso",
    }
}

/// 包里的设置 → 策略。域名与管理员名转 ASCII 小写（与 `checks` 一致）。
/// 不合规的管理员名跳过（只会少放行；回报由 Task 12 的 `admins` 步骤做）；不合规的域名**保留**：
/// 跳过它可能让列表变空、变成不限域名，保留下来它只是匹配不到任何账号。
/// 锁定应用的账号名单来自配置的 `apps.kiosk`（`kiosk-<id>` 与应用的 `name`，按账号名排序）；id 不合规的跳过
/// （清单的校验本该挡住；跳过只会少放行）。锁定时名单照写（`decide` 照样拒）。
pub fn policy_from_bundle(school: &School, config: &Config, lock: Option<&Lock>) -> LoginPolicy {
    // Guest sign-in is always on; `decide` still denies it on a locked device.
    let mut methods: Vec<String> = vec![method_name(LoginMethod::Guest).into()];
    for m in &config.login_methods {
        let name = method_name(*m);
        if !methods.iter().any(|x| x == name) {
            methods.push(name.into());
        }
    }
    LoginPolicy {
        methods,
        allowed_domains: school
            .allowed_domains
            .iter()
            .map(|d| d.to_ascii_lowercase())
            .collect(),
        admin_users: school
            .admin_users
            .iter()
            .filter(|u| checks::admin_user(u).is_ok())
            .map(|u| u.to_ascii_lowercase())
            .collect(),
        locked: lock.is_some(),
        lock_message: lock.map(|l| l.message.clone()),
        from_bundle: true,
        kiosk_users: kiosk_users(config),
        it_account: super::it_account::wanted(config.it_account.as_ref()).is_some(),
        it_account_uid: None,
    }
}

fn kiosk_users(config: &Config) -> Vec<KioskUser> {
    let mut out: Vec<KioskUser> = config
        .apps
        .kiosk
        .iter()
        .filter(|(id, _)| kiosk::check_id(id).is_ok())
        .map(|(id, app)| KioskUser {
            user: kiosk::account_name(id),
            name: app.name.clone(),
        })
        .collect();
    out.sort_by(|a, b| a.user.cmp(&b.user));
    out
}

/// Seed defaults: guest, plus SSO when the seed carries `oidc`, plus the IT account when it carries a valid
/// `it_account`; no domain limit, no admins, not locked.
pub fn policy_from_seed(seed: &Seed) -> LoginPolicy {
    let mut methods = vec![method_name(LoginMethod::Guest).into()];
    if seed.oidc.is_some() {
        methods.push(method_name(LoginMethod::Sso).into());
    }
    LoginPolicy {
        methods,
        allowed_domains: Vec::new(),
        admin_users: Vec::new(),
        locked: false,
        lock_message: None,
        from_bundle: false,
        kiosk_users: Vec::new(),
        it_account: super::it_account::wanted(seed.it_account.as_ref()).is_some(),
        it_account_uid: None,
    }
}

/// 策略文件能解析就用它；否则种子能解析就用种子的默认值；都不行为 `None`（Ruling 4）。
pub fn effective_policy(
    policy_file: Option<&[u8]>,
    seed_text: Option<&str>,
) -> Option<LoginPolicy> {
    if let Some(p) = policy_file.and_then(|b| serde_json::from_slice::<LoginPolicy>(b).ok()) {
        return Some(p);
    }
    seed_text
        .and_then(|t| Seed::parse(t).ok())
        .map(|s| policy_from_seed(&s))
}

/// The `[users]` line of the broker drop-in: `allowed_users = ALL`, and with a domain list also the school's
/// administrators by name (`pam-check` lets them in from any domain, and the broker's domain file
/// ([`render_domains_file`]) lets through whoever `allowed_users` names). Upstream syntax only, which every broker of the
/// pinned tag accepts, patched or not: on a rollback the older broker reads it as `ALL` and starts at once.
/// Names that fail `checks::admin_user` stay out (the file is INI: no stray separators).
pub fn render_broker_users(policy: &LoginPolicy) -> String {
    let admins = if policy.allowed_domains.is_empty() {
        Vec::new()
    } else {
        broker_admins(policy)
    };
    let users: Vec<&str> = std::iter::once("ALL")
        .chain(admins.iter().map(String::as_str))
        .collect();
    format!("allowed_users = {}\n", users.join(", "))
}

/// The school's valid administrators, in lower case, as the broker lists them.
fn broker_admins(policy: &LoginPolicy) -> Vec<String> {
    policy
        .admin_users
        .iter()
        .filter(|u| checks::admin_user(u).is_ok())
        .map(|u| u.to_ascii_lowercase())
        .collect()
}

/// The broker's domain file ([`DOMAINS_FILE`], read by `patches/authd-oidc/0006-allowed-domains.patch`), one domain per
/// line; `None` (no file, no filter) when the school sets no domains.
///
/// authd registers a user (name, uid, groups) as soon as the broker grants access, before PAM's account stage, so a
/// school account that `pam-check` refuses for its domain would still be left on the device as a local user. With this
/// file the broker refuses such accounts before granting anything; `pam-check` keeps its own check as the second line.
/// The file is not part of the broker's configuration (not `broker.conf`, not `broker.conf.d/`): an older broker, which
/// would refuse to start on an unknown key, never reads it.
///
/// Domains that fail `checks::allowed_domain` stay out: they match no account in `pam-check` either. With none left the
/// file has no domain at all, and the broker lets only the administrators named in `allowed_users` through.
pub fn render_domains_file(policy: &LoginPolicy) -> Option<String> {
    if policy.allowed_domains.is_empty() {
        return None;
    }
    let mut out = String::from(
        "# Generated by mastersos-agent from the school's allowed_domains; do not edit.\n\
         # Read by the authd OIDC broker (MastersOS patch 0006) when it starts.\n",
    );
    for d in policy
        .allowed_domains
        .iter()
        .filter(|d| checks::allowed_domain(d).is_ok())
    {
        out.push_str(d);
        out.push('\n');
    }
    Some(out)
}

/// The authd OIDC broker drop-in. The caller has passed `oidc` through `checks::oidc`. No `offline_access`: a login goes
/// through the school's page every time, so nothing uses a refresh token and none should sit on disk.
///
/// With a domain list the drop-in carries [`DOMAINS_MARKER`], so the patched broker requires the domain file.
pub fn render_broker_conf(oidc: &Oidc, policy: &LoginPolicy) -> String {
    broker_conf(
        oidc,
        !policy.allowed_domains.is_empty(),
        &render_broker_users(policy),
    )
}

/// The drop-in written when the domain file is wanted but could not be written: the administrators by name, no `ALL`,
/// so neither a missing nor a stale domain file lets anyone else through, on a patched broker or an older one. `None`
/// when the school has no valid administrator (an empty `allowed_users` would mean the upstream default): then the
/// caller writes no drop-in at all and school sign-in is off until the file can be written.
pub fn render_broker_conf_admins_only(oidc: &Oidc, policy: &LoginPolicy) -> Option<String> {
    let admins = broker_admins(policy);
    if admins.is_empty() {
        return None;
    }
    Some(broker_conf(
        oidc,
        true,
        &format!("allowed_users = {}\n", admins.join(", ")),
    ))
}

fn broker_conf(oidc: &Oidc, marker: bool, users: &str) -> String {
    let marker = if marker {
        format!("{DOMAINS_MARKER}\n")
    } else {
        String::new()
    };
    let secret = oidc
        .client_secret
        .as_ref()
        .map(|s| format!("client_secret = {s}\n"))
        .unwrap_or_default();
    format!(
        "# Generated by mastersos-agent from the school's settings; do not edit.\n\
         {marker}\
         [oidc]\n\
         issuer = {}\n\
         client_id = {}\n\
         {secret}\
         \n\
         [users]\n\
         {users}",
        oidc.issuer, oidc.client_id
    )
}

/// The Chrome URL filter that matches the issuer's origin and nothing wider. A bare host would also match its subdomains
/// and every scheme and port, and a filter without a port matches any port, so the filter pins the scheme, starts the host
/// with a dot (Chrome: no subdomain matching) and always carries the port, the scheme's default included. An IP address
/// has no subdomains and takes no dot. `None` unless the issuer parses as an http(s) URL with a valid DNS name or IP and
/// no credentials.
pub fn issuer_url_filter(issuer: &str) -> Option<String> {
    let url = reqwest::Url::parse(issuer).ok()?;
    let scheme = url.scheme();
    // The parser repairs `https:///x`, `https:x` and backslashes into a host: the issuer has to name one as written.
    let rest = issuer.strip_prefix(scheme)?.strip_prefix("://")?;
    if rest.starts_with('/') || issuer.contains('\\') {
        return None;
    }
    if !matches!(scheme, "https" | "http") || !url.username().is_empty() || url.password().is_some()
    {
        return None;
    }
    let host = url.host_str()?;
    let port = url.port_or_known_default()?;
    let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    if unbracketed.parse::<std::net::IpAddr>().is_ok() {
        return Some(format!("{scheme}://{host}:{port}"));
    }
    checks::is_dns_name(host).then(|| format!("{scheme}://.{host}:{port}"))
}

/// The same pinned form for a `card_hosts` entry: https on 443, this host only. `None` for an invalid entry.
pub fn card_host_url_filter(host: &str) -> Option<String> {
    checks::card_host(host)
        .ok()
        .map(|()| format!("https://.{host}:443"))
}

/// The sign-in card's Chrome policy: everything is blocked except the identity provider, the signed `card_hosts` and the
/// redirect back to the broker, and nothing a website could use to leave the card (downloads, new windows, printing, file dialogs, developer
/// tools, extensions) is available. `None` when the issuer gives no filter ([`issuer_url_filter`]).
pub fn render_login_browser_policy(oidc: &Oidc) -> Option<String> {
    let mut allow = vec![issuer_url_filter(&oidc.issuer)?];
    for filter in oidc
        .card_hosts
        .iter()
        .filter_map(|h| card_host_url_filter(h))
    {
        if !allow.contains(&filter) {
            allow.push(filter);
        }
    }
    allow.push(LOGIN_REDIRECT_FILTER.into());
    let policy = serde_json::json!({
        "URLBlocklist": ["*"],
        "URLAllowlist": allow,
        "DownloadRestrictions": 3,
        "DeveloperToolsAvailability": 2,
        "PrintingEnabled": false,
        "ExtensionInstallBlocklist": ["*"],
        "IncognitoModeAvailability": 1,
        "BrowserSignin": 0,
        "SyncDisabled": true,
        "PasswordManagerEnabled": false,
        "AutofillAddressEnabled": false,
        "AutofillCreditCardEnabled": false,
        "AllowFileSelectionDialogs": false,
        "BrowserAddPersonEnabled": false,
        "BrowserGuestModeEnabled": false,
        "EditBookmarksEnabled": false,
        "DefaultPopupsSetting": 2,
        "DefaultNotificationsSetting": 2,
        "DefaultGeolocationSetting": 2,
        "AudioCaptureAllowed": false,
        "VideoCaptureAllowed": false,
        "ScreenCaptureAllowed": false,
        "TranslateEnabled": false,
        "MetricsReportingEnabled": false,
    });
    serde_json::to_string_pretty(&policy).ok()
}

/// [`LOGIN_CARD_FILE`]'s content for a provider that passed `checks::oidc`: `None` without an `idp_hint`.
pub fn render_login_card(oidc: &Oidc) -> Option<String> {
    let hint = oidc.idp_hint.as_deref()?;
    checks::idp_hint(hint).ok()?;
    serde_json::to_string_pretty(&serde_json::json!({ "idp_hint": hint })).ok()
}

/// 经 `safefs` 写 [`POLICY_PATH`]（`login/` 0755、文件 0644；`var_dir` 收紧到 0700）。返回内容是否变了。
/// 超过 [`MAX_POLICY_BYTES`] 时报错，不动原来的文件。
pub fn write_policy(paths: &SysPaths, p: &LoginPolicy) -> Result<bool> {
    let bytes = policy_json(p)?;
    let var = var_dir(paths)?;
    let dir = safefs::open_dir_at(&var, Path::new(POLICY_SUBDIR), true)?;
    safefs::set_mode(&dir, 0o755)?;
    safefs::write_at(&dir, POLICY_FILE, &bytes, 0o644)
        .with_context(|| format!("write {POLICY_PATH}"))
}

/// 策略文件的内容；超过 [`MAX_POLICY_BYTES`] 报错（`pam-check` 会把它当作没有）。
pub(super) fn policy_json(p: &LoginPolicy) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec_pretty(p)?;
    if bytes.len() > MAX_POLICY_BYTES {
        anyhow::bail!(
            "login policy is {} bytes, over the {MAX_POLICY_BYTES} limit (too many administrators or domains)",
            bytes.len()
        );
    }
    Ok(bytes)
}

/// 写不下 `p` 时的替代：锁定、方式清空、不限域名，只留管理员；管理员本身也放不下就连管理员也不留。
/// 锁定应用的名单留着（锁定时 `decide` 本来就拒）：`ephemeral-cleanup` 靠它认出写策略时还开着的 kiosk 会话、照常清理；
/// 放不下时先丢它，再丢管理员。
pub(super) fn fail_closed(p: &LoginPolicy) -> LoginPolicy {
    let mut f = LoginPolicy {
        methods: Vec::new(),
        allowed_domains: Vec::new(),
        admin_users: p.admin_users.clone(),
        locked: true,
        lock_message: Some(OVERSIZE_LOCK_MESSAGE.into()),
        from_bundle: p.from_bundle,
        kiosk_users: p.kiosk_users.clone(),
        it_account: p.it_account,
        it_account_uid: p.it_account_uid,
    };
    if policy_json(&f).is_err() {
        f.kiosk_users.clear();
    }
    if policy_json(&f).is_err() {
        // 名单没写进去：不能再说它是包里的管理员名单
        f.admin_users.clear();
        f.from_bundle = false;
    }
    f
}

pub fn step() -> Step {
    Step {
        name: "login",
        fast: true,
        run,
        without_bundle: Some(run_seed),
    }
}

/// [`policy_from_bundle`] with the device's own part: the recorded owner uid of `itadmin` (the `lock` step writes the same).
pub fn bundle_policy(ctx: &ApplyContext, env: &Env) -> LoginPolicy {
    let mut p = policy_from_bundle(ctx.school, ctx.config, ctx.lock);
    p.it_account_uid = owner_uid(env, p.it_account);
    p
}

/// [`policy_from_seed`] with the device's own part; the seed opens no IT exception once a bundle has been applied here
/// ([`super::it_account::seed_gated`]).
pub fn seed_policy(seed: &Seed, env: &Env) -> LoginPolicy {
    let mut p = policy_from_seed(seed);
    p.it_account &= !super::it_account::seed_gated(env.sys);
    p.it_account_uid = owner_uid(env, p.it_account);
    p
}

/// The uid the IT exception is for: the recorded one; in a round whose state could not be read, the one the installed
/// policy already names (so that round does not take IT's sign-in away).
fn owner_uid(env: &Env, it_account: bool) -> Option<u32> {
    if !it_account {
        return None;
    }
    if env.sys.load_failed {
        return read_policy_file(env.paths).and_then(|p| p.it_account_uid);
    }
    env.sys.it_account_uid
}

fn read_policy_file(paths: &SysPaths) -> Option<LoginPolicy> {
    let var = var_dir(paths).ok()?;
    let dir = safefs::open_dir_at(&var, Path::new(POLICY_SUBDIR), false).ok()?;
    let bytes = safefs::read_at(&dir, POLICY_FILE).ok()??;
    serde_json::from_slice(&bytes).ok()
}

/// After the `it_account` step created `itadmin` (this round's policy was written before it): put its uid into the
/// installed policy when that policy opens the IT exception. A missing or unreadable policy is left to the next round.
pub fn set_it_account_uid(paths: &SysPaths, uid: u32) -> Result<()> {
    let Some(mut p) = read_policy_file(paths) else {
        return Ok(());
    };
    if p.it_account && p.it_account_uid != Some(uid) {
        p.it_account_uid = Some(uid);
        write_policy(paths, &p)?;
    }
    Ok(())
}

fn run(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
    let mut problems = Vec::new();
    for d in &ctx.school.allowed_domains {
        if let Err(e) = checks::allowed_domain(&d.to_ascii_lowercase()) {
            problems.push(format!("{e} (this entry matches no account)"));
        }
    }
    let policy = bundle_policy(ctx, env);
    apply(env, &policy, ctx.school.oidc.as_ref(), problems)
}

fn run_seed(seed: &Seed, env: &mut Env) -> Vec<ItemResult> {
    let policy = seed_policy(seed, env);
    apply(env, &policy, seed.oidc.as_ref(), Vec::new())
}

/// 写策略、按需写或删 broker 配置、broker 配置变了（或上次重启没成）就重启 authd。
/// 回报里不带用户名与邮箱（只有域名与 OIDC 的格式错误）。
fn apply(
    env: &mut Env,
    policy: &LoginPolicy,
    oidc: Option<&Oidc>,
    mut problems: Vec<String>,
) -> Vec<ItemResult> {
    let written = match policy_json(policy) {
        Ok(_) => policy.clone(),
        Err(e) => {
            problems.push(format!(
                "{e:#}; settings too large, writing a locked policy instead (administrators only)"
            ));
            fail_closed(policy)
        }
    };
    if let Err(e) = write_policy(env.paths, &written) {
        problems.push(format!("writing the login policy failed: {e:#}"));
    }
    let sso = policy.methods.iter().any(|m| m == "sso");
    let valid_oidc = oidc.filter(|_| sso).and_then(|o| match checks::oidc(o) {
        Ok(()) => Some(o),
        Err(e) => {
            problems.push(format!("{e}; not writing the broker drop-in"));
            None
        }
    });
    let mut want = valid_oidc.map(|o| render_broker_conf(o, policy));
    // The domain file goes with the drop-in. Written before it and removed after it, so that a broker started in between
    // never runs the school's sign-in without the domains.
    let want_domains = want.as_ref().and_then(|_| render_domains_file(policy));
    if want_domains.is_some() {
        match sync_domains(&env.paths.root, want_domains.as_deref()) {
            Ok(changed) => env.sys.broker_restart_pending |= changed,
            Err(e) => {
                // Fail closed: never `ALL` with a missing or stale domain file. Only the administrators, by name; with
                // none, no school sign-in at all.
                want = valid_oidc.and_then(|o| render_broker_conf_admins_only(o, policy));
                let now = if want.is_some() {
                    "only the administrators may sign in with the school's provider until it is written"
                } else {
                    "school sign-in is off until it is written"
                };
                problems.push(format!("broker domain file: {e:#}; {now}"));
            }
        }
    }
    // The sign-in card goes with the drop-in.
    let valid_oidc = valid_oidc.filter(|_| want.is_some());
    match sync_broker(&env.paths.root, want.as_deref()) {
        Ok(changed) => env.sys.broker_restart_pending |= changed,
        Err(e) => problems.push(format!("broker drop-in: {e:#}")),
    }
    if want_domains.is_none() {
        match sync_domains(&env.paths.root, None) {
            Ok(changed) => env.sys.broker_restart_pending |= changed,
            Err(e) => problems.push(format!("broker domain file: {e:#}")),
        }
    }
    match sync_broker_decl(&env.paths.root, want.is_some()) {
        Ok(changed) => env.sys.broker_restart_pending |= changed,
        Err(e) => problems.push(format!("broker registration: {e:#}")),
    }
    let browser_policy = valid_oidc.and_then(render_login_browser_policy);
    if let Err(e) = sync_login_browser(env.paths, browser_policy.as_deref()) {
        problems.push(format!("sign-in card policy: {e:#}"));
    }
    let card = valid_oidc.and_then(render_login_card);
    if let Err(e) = sync_login_card(env.paths, card.as_deref()) {
        problems.push(format!("sign-in card settings: {e:#}"));
    }
    // 状态没读出来：上次「改了配置、重启没成」的记录可能丢了。配置在就再重启一次（M1）。
    if env.sys.load_failed && want.is_some() {
        env.sys.broker_restart_pending = true;
    }
    if env.sys.broker_restart_pending {
        match run_ok(env.runner, Cmd::new("systemctl", RESTART_AUTHD)) {
            Ok(_) => env.sys.broker_restart_pending = false,
            Err(e) => problems.push(format!("restarting authd failed: {e:#}")),
        }
    }
    vec![if problems.is_empty() {
        ok(ITEM)
    } else {
        failed(ITEM, problems.join("; "))
    }]
}

/// `want` 为 `Some` 时写 drop-in（目录 0700、文件 0600），否则删掉它。返回是否变了。
fn sync_broker(root: &Path, want: Option<&str>) -> Result<bool> {
    match want {
        Some(text) => {
            let dir = safefs::open_dir(root, Path::new(BROKER_DIR), true)?;
            safefs::set_mode(&dir, 0o700)?;
            safefs::write_at(&dir, BROKER_FILE, text.as_bytes(), 0o600)
        }
        None => {
            let dir = match safefs::open_dir(root, Path::new(BROKER_DIR), false) {
                Ok(d) => d,
                Err(e) if is_not_found(&e) => return Ok(false),
                Err(e) => return Err(e),
            };
            if safefs::open_file_at(&dir, BROKER_FILE)?.is_none() {
                return Ok(false);
            }
            safefs::remove_at(&dir, BROKER_FILE)?;
            Ok(true)
        }
    }
}

/// Write the broker's domain file (0644: it holds only the school's domains; its directory `/etc/authd/oidc` stays as the
/// image made it) or remove it. Returns whether it changed.
fn sync_domains(root: &Path, want: Option<&str>) -> Result<bool> {
    match want {
        Some(text) => {
            let dir = safefs::open_dir(root, Path::new(DOMAINS_DIR), true)?;
            safefs::write_at(&dir, DOMAINS_FILE, text.as_bytes(), 0o644)
        }
        None => {
            let dir = match safefs::open_dir(root, Path::new(DOMAINS_DIR), false) {
                Ok(d) => d,
                Err(e) if is_not_found(&e) => return Ok(false),
                Err(e) => return Err(e),
            };
            if safefs::open_file_at(&dir, DOMAINS_FILE)?.is_none() {
                return Ok(false);
            }
            safefs::remove_at(&dir, DOMAINS_FILE)?;
            Ok(true)
        }
    }
}

/// Write the sign-in card's policy (directories 0755, file 0644: the greeter's browser reads it) or remove it.
fn sync_login_browser(paths: &SysPaths, want: Option<&str>) -> Result<()> {
    sync_public_file(paths, LOGIN_BROWSER_DIR, LOGIN_BROWSER_FILE, want)
}

/// Write [`LOGIN_CARD_FILE`] (directory 0755, file 0644: the greeter reads it) or remove it.
fn sync_login_card(paths: &SysPaths, want: Option<&str>) -> Result<()> {
    sync_public_file(paths, LOGIN_CARD_DIR, LOGIN_CARD_FILE, want)
}

/// Write `rel/name` under the public directory (`rel` 0755, the file 0644) when `want` is `Some`, otherwise remove it.
fn sync_public_file(paths: &SysPaths, rel: &str, name: &str, want: Option<&str>) -> Result<()> {
    let public = public_dir(paths)?;
    match want {
        Some(text) => {
            let dir = safefs::open_dir_at(&public, Path::new(rel), true)?;
            safefs::set_mode(&dir, 0o755)?;
            safefs::write_at(&dir, name, text.as_bytes(), 0o644)?;
        }
        None => {
            let dir = match safefs::open_dir_at(&public, Path::new(rel), false) {
                Ok(d) => d,
                Err(e) if is_not_found(&e) => return Ok(()),
                Err(e) => return Err(e),
            };
            if safefs::open_file_at(&dir, name)?.is_some() {
                safefs::remove_at(&dir, name)?;
            }
        }
    }
    Ok(())
}

/// When `want` is true copy the image's registration file to `brokers.d/oidc.conf` (dir 0755, file 0644),
/// otherwise remove it. Returns whether anything changed. A missing source is an error and writes nothing.
fn sync_broker_decl(root: &Path, want: bool) -> Result<bool> {
    if want {
        let src_path = Path::new(BROKER_DECL_SRC);
        let src_name = src_path
            .file_name()
            .and_then(|n| n.to_str())
            .context("bad registration source path")?;
        let src_dir = src_path.parent().context("bad registration source path")?;
        let bytes = safefs::open_dir(root, src_dir, false)
            .and_then(|d| safefs::read_at(&d, src_name))
            .with_context(|| format!("cannot read /{BROKER_DECL_SRC}"))?
            .with_context(|| format!("/{BROKER_DECL_SRC} is missing from the image"))?;
        let dir = safefs::open_dir(root, Path::new(BROKER_DECL_DIR), true)?;
        safefs::set_mode(&dir, 0o755)?;
        safefs::write_at(&dir, BROKER_DECL_FILE, &bytes, 0o644)
    } else {
        let dir = match safefs::open_dir(root, Path::new(BROKER_DECL_DIR), false) {
            Ok(d) => d,
            Err(e) if is_not_found(&e) => return Ok(false),
            Err(e) => return Err(e),
        };
        if safefs::open_file_at(&dir, BROKER_DECL_FILE)?.is_none() {
            return Ok(false);
        }
        safefs::remove_at(&dir, BROKER_DECL_FILE)?;
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// `mastersos-agent pam-check`
// ---------------------------------------------------------------------------

/// `pam-check` 读的路径。默认值是真机上的位置；隐藏参数 `--state-dir`、`--seed-dir`、`--policy`
/// 只为测试把它们指到临时目录。
///
/// 这些参数**只能改路径**，不能改判定规则：PAM 以 root、固定的 argv（`/usr/bin/mastersos-agent pam-check`）
/// 调它，用户改不了参数；普通用户自己带参数跑它，得到的只是一个退出码，不影响任何人的登录。
struct PamPaths {
    policy: PathBuf,
    seeds: [PathBuf; 2],
}

impl PamPaths {
    /// 真机上的位置。
    fn defaults() -> PamPaths {
        PamPaths::from_dirs(
            PathBuf::from(POLICY_PATH),
            Path::new(DEFAULT_STATE_DIR),
            Path::new(crate::seedpart::SEED_PART_DIR),
        )
    }

    fn from_dirs(policy: PathBuf, state: &Path, seed: &Path) -> PamPaths {
        PamPaths {
            policy,
            seeds: [state.join(SEED_FILE), seed.join(SEED_FILE)],
        }
    }

    /// 不认识的参数、缺了值的参数 → `None`（调用方拒绝）。
    fn parse(args: impl Iterator<Item = OsString>) -> Option<PamPaths> {
        let mut policy = PathBuf::from(POLICY_PATH);
        let mut state = PathBuf::from(DEFAULT_STATE_DIR);
        let mut seed = PathBuf::from(crate::seedpart::SEED_PART_DIR);
        let mut args = args;
        while let Some(a) = args.next() {
            let slot = match a.to_str()? {
                "--policy" => &mut policy,
                "--state-dir" => &mut state,
                "--seed-dir" => &mut seed,
                _ => return None,
            };
            *slot = PathBuf::from(args.next()?);
        }
        Some(PamPaths::from_dirs(policy, &state, &seed))
    }
}

/// 是否受管（种子在或判断不了）与有效的策略（未受管为 `None`；受管而策略与种子都读不了也是 `None`）。
fn load_policy(paths: &PamPaths) -> (bool, Option<LoginPolicy>) {
    let managed = paths.seeds.iter().any(|p| may_exist(p));
    let policy = if managed {
        effective_policy(
            read_small(&paths.policy).as_deref(),
            read_seed(&paths.seeds).as_deref(),
        )
    } else {
        None
    };
    (managed, policy)
}

/// 真机位置上的 [`load_policy`]：`pam-session` 与 `ephemeral-cleanup` 读的与 `pam-check` 是同一份（锁定应用的名单）。
pub(crate) fn installed_policy() -> (bool, Option<LoginPolicy>) {
    load_policy(&PamPaths::defaults())
}

/// The effective policy under `paths` (the policy file in `var_dir`, else the seed in `state_dir` or on the seed
/// partition), read the way `pam-check` reads it. `None` when neither can be read.
pub(crate) fn policy_at(paths: &SysPaths) -> Option<LoginPolicy> {
    let file = paths.var_dir.join(POLICY_SUBDIR).join(POLICY_FILE);
    let seeds = [
        paths.state_dir.join(SEED_FILE),
        Path::new(crate::seedpart::SEED_PART_DIR).join(SEED_FILE),
    ];
    effective_policy(read_small(&file).as_deref(), read_seed(&seeds).as_deref())
}

/// 存在（或判断不了）→ `true`：只有确定「不存在」才算没有种子，免得一次 stat 失败把受管机器当成未受管而全放行。
fn may_exist(p: &Path) -> bool {
    match std::fs::symlink_metadata(p) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

/// 读普通文件（最后一级不跟随链接，`O_NONBLOCK` 免得碰上 FIFO 卡住），最多 [`MAX_READ`] 字节。
/// 任何错误、超长都是 `None`。
fn read_small(p: &Path) -> Option<Vec<u8>> {
    let (parent, name) = (p.parent()?, p.file_name()?.to_str()?);
    let dir = safefs::open_abs_dir(parent, false).ok()?;
    let f = safefs::open_file_at(&dir, name).ok()??;
    let mut buf = Vec::new();
    f.take(MAX_READ + 1).read_to_end(&mut buf).ok()?;
    (buf.len() as u64 <= MAX_READ).then_some(buf)
}

/// 两处种子里第一份能解析的。
fn read_seed(paths: &[PathBuf]) -> Option<String> {
    paths.iter().find_map(|p| {
        let text = String::from_utf8(read_small(p)?).ok()?;
        Seed::parse(&text).ok().map(|_| text)
    })
}

/// `getent passwd -- <user>` 的第 3 列（authd 的用户经 NSS 也查得到）。查不到、超时、输出对不上
/// （第 1 列不是这个名字：`getent passwd 0` 会按 uid 查到 root）都是 `None`。环境清空，限时。
fn lookup_uid(user: &str) -> Option<u32> {
    let mut child = Command::new(GETENT)
        .args(["passwd", "--", user])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + GETENT_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    if !status.success() {
        return None;
    }
    let mut out = Vec::new();
    child
        .stdout
        .take()?
        .take(MAX_READ)
        .read_to_end(&mut out)
        .ok()?;
    parse_getent(std::str::from_utf8(&out).ok()?, user)
}

/// `getent passwd` 输出的第一行：第 1 列必须就是 `user`（`getent passwd 0` 会按 uid 查到 root 那一行），
/// 取第 3 列的 uid。
fn parse_getent(out: &str, user: &str) -> Option<u32> {
    let mut fields = out.lines().next()?.split(':');
    if fields.next()? != user {
        return None;
    }
    fields.nth(1)?.parse().ok()
}

/// 名字合规才查（`pam-session` 给登录队列用）。
pub(crate) fn lookup_uid_checked(user: &str) -> Option<u32> {
    if user_name_ok(user) {
        lookup_uid(user)
    } else {
        None
    }
}

fn env_str(name: &str) -> Option<String> {
    std::env::var_os(name)?.into_string().ok()
}

/// 拒绝：原因打到 stdout（pam_exec 的 `stdout` 交给 GDM 显示），退出 1。写失败也照样拒绝。
fn deny(msg: &str) -> ExitCode {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{msg}");
    let _ = out.flush();
    ExitCode::FAILURE
}

/// `mastersos-agent pam-check` 的入口（`args` 是 `pam-check` 之后的参数）。不初始化日志、不碰网络、
/// 不建 tokio 运行时；放行退出 0，拒绝打印原因、退出 1。任何读文件的错误都当作「没有」，往拒绝的方向落。
pub fn pam_check_main(args: impl Iterator<Item = OsString>) -> ExitCode {
    let Some(paths) = PamPaths::parse(args) else {
        return deny(DENY_BAD_ARGS);
    };
    let Some(user) = env_str("PAM_USER") else {
        return deny(DENY_BAD_USER);
    };
    let service = env_str("PAM_SERVICE").unwrap_or_default();
    // 不合规的名字不交给 getent（decide 随后拒绝它）。
    let uid = if user_name_ok(&user) {
        lookup_uid(&user)
    } else {
        None
    };
    let (managed, policy) = load_policy(&paths);
    match decide(&service, managed, policy.as_ref(), &user, uid) {
        Decision::Allow => ExitCode::SUCCESS,
        Decision::Deny(msg) => deny(msg),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::tests::{config, group, paths, tmp_root};
    use super::super::{steps, SysState};
    use super::*;
    use crate::apply::Phase;
    use crate::runner::{FakeRunner, Output};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicBool;

    const GDM: &str = GUEST_SERVICES[0];
    const ADMIN: &str = "boss@school.ac.th";
    const RESTART: &str = "systemctl try-restart authd-oidc.service authd.service";

    const SEED_OIDC: &str = r#"
server_url = "https://mastersos.school.ac.th"
trust = []
[oidc]
issuer = "https://sso.school.ac.th"
client_id = "laptops"
"#;
    const SEED_PLAIN: &str = "server_url = \"https://mastersos.school.ac.th\"\ntrust = []\n";

    fn pol(methods: &[&str]) -> LoginPolicy {
        LoginPolicy {
            methods: methods.iter().map(|m| m.to_string()).collect(),
            allowed_domains: vec![],
            admin_users: vec![],
            locked: false,
            lock_message: None,
            from_bundle: false,
            kiosk_users: vec![],
            it_account: false,
            it_account_uid: None,
        }
    }

    fn all() -> LoginPolicy {
        pol(&["guest", "local", "sso"])
    }

    fn managed(service: &str, p: &LoginPolicy, user: &str) -> Decision {
        decide(service, true, Some(p), user, Some(1001))
    }

    fn oidc(issuer: &str) -> Oidc {
        Oidc {
            issuer: issuer.into(),
            client_id: "laptops".into(),
            ..Oidc::default()
        }
    }

    fn seed(text: &str) -> Seed {
        Seed::parse(text).unwrap()
    }

    #[test]
    fn classify_users() {
        assert_eq!(classify("guest", None), UserClass::Guest);
        assert_eq!(classify("alice", None), UserClass::Local);
        assert_eq!(classify("alice@school.ac.th", None), UserClass::Sso);
        // Linux 的用户名区分大小写：`Guest` 是另一个本机账号，不是访客。
        assert_eq!(classify("Guest", None), UserClass::Local);
        // 与 common-password 的分流（`pam_succeed_if user !~ *@*`）一致：含 @ 就是 SSO。
        assert_eq!(classify("a@b@c", None), UserClass::Sso);
    }

    #[test]
    fn unmanaged_allows_everyone() {
        for svc in [GDM, "gdm-authd", "login", "sshd", "su"] {
            for user in ["alice", "alice@school.ac.th", "bob@other.th"] {
                for uid in [Some(1001), None] {
                    assert_eq!(
                        decide(svc, false, None, user, uid),
                        Decision::Allow,
                        "{svc} {user}"
                    );
                }
            }
        }
        assert_eq!(
            decide(GDM, false, None, "guest", Some(1999)),
            Decision::Allow
        );
        // 访客在 GDM 以外的服务上不论是否受管都拒。
        assert_eq!(
            decide("login", false, None, "guest", Some(1999)),
            Decision::Deny(DENY_GUEST_SERVICE)
        );
    }

    #[test]
    fn greeter_and_system_users_pass_through() {
        let mut p = pol(&[]);
        p.locked = true;
        // GDM 的登录界面：服务本身放行，查不到 uid 也一样。
        assert_eq!(
            decide("gdm-launch-environment", true, Some(&p), "gdm", Some(120)),
            Decision::Allow
        );
        assert_eq!(
            decide("gdm-launch-environment", true, None, "gdm-greeter-3", None),
            Decision::Allow
        );
        for uid in [0, 120, 999, 60000, 60578, 60579, 65534] {
            assert!(is_system_uid(uid), "{uid}");
            assert_eq!(
                decide("sshd", true, Some(&p), "x", Some(uid)),
                Decision::Allow,
                "{uid}"
            );
            assert_eq!(
                decide("sshd", true, None, "x", Some(uid)),
                Decision::Allow,
                "{uid}"
            );
        }
        for uid in [1000, 1001, 1999, 59999] {
            assert!(!is_system_uid(uid), "{uid}");
        }
        // 含 @ 的名字是 SSO 账号，uid 落在系统范围也照规则判。
        for uid in [65534, 60001, 999] {
            assert_eq!(
                decide("sshd", true, Some(&p), "a@school.ac.th", Some(uid)),
                Decision::Deny(DENY_LOCKED),
                "{uid}"
            );
        }
        // 普通 uid 照规则判；查不到 uid 也不放行。
        assert_eq!(
            decide("sshd", true, Some(&p), "alice", Some(1001)),
            Decision::Deny(DENY_LOCKED)
        );
        assert_eq!(
            decide("sshd", true, Some(&p), "alice", None),
            Decision::Deny(DENY_LOCKED)
        );
        assert_eq!(
            decide("login", true, Some(&all()), "guest", Some(1999)),
            Decision::Deny(DENY_GUEST_SERVICE)
        );
    }

    #[test]
    fn managed_without_policy_or_seed_denies() {
        assert_eq!(effective_policy(None, None), None);
        assert_eq!(
            effective_policy(Some(b"{garbage"), Some("not = [toml")),
            None
        );
        assert_eq!(effective_policy(Some(b""), Some("server_url = 1")), None);
        for user in ["alice", ADMIN, "guest"] {
            assert_eq!(
                decide(GDM, true, None, user, Some(1001)),
                Decision::Deny(DENY_NO_POLICY),
                "{user}"
            );
        }
    }

    /// Review Focus 7：策略文件丢了或坏了，管理员（都是 SSO 账号）仍能登录，本机用户与访客按种子的默认值拒。
    #[test]
    fn missing_policy_falls_back_to_seed_policy() {
        let from_seed = policy_from_seed(&seed(SEED_OIDC));
        for file in [
            None,
            Some(&b"{garbage"[..]),
            Some(&b""[..]),
            Some(&b"[1,2]"[..]),
        ] {
            let p = effective_policy(file, Some(SEED_OIDC)).unwrap();
            assert_eq!(p, from_seed);
            assert_eq!(managed(GDM, &p, ADMIN), Decision::Allow);
            assert_eq!(managed("gdm-authd", &p, ADMIN), Decision::Allow);
            assert_eq!(managed(GDM, &p, "alice"), Decision::Deny(DENY_LOCAL));
            assert_eq!(managed(GDM, &p, "guest"), Decision::Allow);
        }
        // 能解析的策略文件优先于种子。
        let mut good = pol(&["local"]);
        good.locked = true;
        let bytes = serde_json::to_vec(&good).unwrap();
        assert_eq!(
            effective_policy(Some(&bytes), Some(SEED_OIDC)),
            Some(good.clone())
        );
        assert_eq!(effective_policy(Some(&bytes), None), Some(good));
    }

    /// Review Focus 6：tty 或 ssh 上的 `guest` 拿不到一个没有 tmpfs、不会被清理的会话。
    #[test]
    fn guest_denied_outside_gdm() {
        for svc in [
            "login",
            "sshd",
            "su",
            "su-l",
            "gdm-autologin",
            "gdm-fingerprint",
            "gdm-smartcard",
            "",
        ] {
            for m in [true, false] {
                assert_eq!(
                    decide(svc, m, Some(&all()), "guest", Some(1999)),
                    Decision::Deny(DENY_GUEST_SERVICE),
                    "{svc} managed={m}"
                );
            }
        }
        // cron 在放行表里，对访客却不放行（at 同样）；别人照旧放行
        for svc in GUEST_DENIED_SCHEDULERS {
            for m in [true, false] {
                assert_eq!(
                    decide(svc, m, Some(&all()), "guest", Some(1999)),
                    Decision::Deny(DENY_GUEST_SERVICE),
                    "{svc}"
                );
            }
        }
        assert_eq!(
            decide("cron", true, Some(&pol(&[])), "alice", Some(1001)),
            Decision::Allow
        );
        // 装了 authd 的 GDM 对用户列表里的人都走 gdm-authd（Task 11 在 VM 上确认访客也是）
        for svc in GUEST_SERVICES {
            assert_eq!(
                managed(svc, &pol(&["guest"]), "guest"),
                Decision::Allow,
                "{svc}"
            );
            assert_eq!(
                managed(svc, &pol(&["local", "sso"]), "guest"),
                Decision::Deny(DENY_GUEST),
                "{svc}"
            );
        }
    }

    #[test]
    fn passthrough_services_allow() {
        let mut p = pol(&[]);
        p.locked = true;
        for svc in PASSTHROUGH_SERVICES {
            for user in ["alice", "alice@other.th", "guest"] {
                if user == "guest" && GUEST_DENIED_SCHEDULERS.contains(svc) {
                    continue; // 访客的定时任务另拒（guest_denied_outside_gdm）
                }
                assert_eq!(
                    decide(svc, true, Some(&p), user, Some(1001)),
                    Decision::Allow,
                    "{svc}"
                );
                assert_eq!(
                    decide(svc, true, None, user, None),
                    Decision::Allow,
                    "{svc}"
                );
            }
        }
        for svc in ["cron", "systemd-user", "sudo", "sudo-i", "polkit-1"] {
            assert!(PASSTHROUGH_SERVICES.contains(&svc));
        }
    }

    #[test]
    fn methods_gate_each_class() {
        let cases = [
            ("guest", "guest", DENY_GUEST),
            ("alice", "local", DENY_LOCAL),
            ("alice@school.ac.th", "sso", DENY_SSO),
        ];
        for (user, method, deny) in cases {
            assert_eq!(
                managed(GDM, &pol(&[method]), user),
                Decision::Allow,
                "{user}"
            );
            let others: Vec<&str> = ["guest", "local", "sso"]
                .into_iter()
                .filter(|m| *m != method)
                .collect();
            assert_eq!(
                managed(GDM, &pol(&others), user),
                Decision::Deny(deny),
                "{user}"
            );
            assert_eq!(
                managed(GDM, &pol(&[]), user),
                Decision::Deny(deny),
                "{user}"
            );
        }
    }

    #[test]
    fn domain_restriction() {
        let mut p = pol(&["local", "sso"]);
        p.allowed_domains = vec!["school.ac.th".into()];
        assert_eq!(managed(GDM, &p, "a@school.ac.th"), Decision::Allow);
        assert_eq!(managed(GDM, &p, "a@SCHOOL.AC.TH"), Decision::Allow);
        assert_eq!(managed(GDM, &p, "a@other.th"), Decision::Deny(DENY_DOMAIN));
        assert_eq!(
            managed(GDM, &p, "a@evil.school.ac.th"),
            Decision::Deny(DENY_DOMAIN)
        );
        assert_eq!(
            managed(GDM, &p, "a@school.ac.th.evil.th"),
            Decision::Deny(DENY_DOMAIN)
        );
        // 比较的是最后一个 @ 之后的部分。
        assert_eq!(
            managed(GDM, &p, "a@school.ac.th@other.th"),
            Decision::Deny(DENY_DOMAIN)
        );
        assert_eq!(managed(GDM, &p, "a@other.th@school.ac.th"), Decision::Allow);
        // Unicode 的大小写折叠不算（K 与开尔文符号 K）。
        p.allowed_domains = vec!["k.th".into()];
        assert_eq!(
            managed(GDM, &p, "a@\u{212A}.th"),
            Decision::Deny(DENY_DOMAIN)
        );
        // 域名只限 SSO 账号；本机用户不受影响。
        assert_eq!(managed(GDM, &p, "alice"), Decision::Allow);
        // 空 = 不限域名。
        assert_eq!(managed(GDM, &pol(&["sso"]), "a@other.th"), Decision::Allow);
        // 包里写的大写域名在策略里转成小写。
        let school = School {
            allowed_domains: vec!["School.AC.th".into()],
            ..School::default()
        };
        let mut g = config();
        g.login_methods = vec![LoginMethod::Sso];
        let p = policy_from_bundle(&school, &g, None);
        assert_eq!(p.allowed_domains, ["school.ac.th"]);
        assert_eq!(managed(GDM, &p, "a@school.ac.th"), Decision::Allow);
    }

    #[test]
    fn admins_bypass_methods_and_lock() {
        let mut p = pol(&[]);
        p.locked = true;
        p.lock_message = Some("请把电脑交给 IT".into());
        p.allowed_domains = vec!["other.th".into()];
        p.admin_users = vec![ADMIN.into()];
        for user in [ADMIN, "Boss@School.AC.TH", "BOSS@SCHOOL.AC.TH"] {
            assert_eq!(managed(GDM, &p, user), Decision::Allow, "{user}");
            assert_eq!(managed("sshd", &p, user), Decision::Allow, "{user}");
        }
        assert_eq!(
            managed(GDM, &p, "x@school.ac.th"),
            Decision::Deny(DENY_LOCKED)
        );
        // 开尔文符号不按 Unicode 折叠成 k。
        p.admin_users = vec!["kboss@school.ac.th".into()];
        assert_eq!(
            managed(GDM, &p, "\u{212A}boss@school.ac.th"),
            Decision::Deny(DENY_LOCKED)
        );
        // 包里的管理员名转小写；不合规的名字跳过（只会少放行，不会多放行）。
        let school = School {
            admin_users: vec![
                "Boss@School.ac.th".into(),
                "a\"b@x.th".into(),
                "local".into(),
            ],
            ..School::default()
        };
        let p = policy_from_bundle(&school, &config(), None);
        assert_eq!(p.admin_users, [ADMIN]);
        // 名字跟本机用户一样（不含 @）的管理员不存在：本机用户不会因此绕过方式与锁定。
        assert_eq!(managed(GDM, &p, "local"), Decision::Deny(DENY_LOCAL));
    }

    #[test]
    fn locked_denies_non_admin_with_message() {
        let lock = Lock {
            message: "请把电脑交给 IT".into(),
        };
        let mut g = config();
        g.login_methods = vec![LoginMethod::Guest, LoginMethod::Local, LoginMethod::Sso];
        let school = School {
            admin_users: vec![ADMIN.into()],
            ..School::default()
        };
        let p = policy_from_bundle(&school, &g, Some(&lock));
        assert!(p.locked);
        assert_eq!(p.lock_message.as_deref(), Some("请把电脑交给 IT"));
        for user in ["alice", "x@school.ac.th", "guest"] {
            let d = managed(GDM, &p, user);
            assert_eq!(d, Decision::Deny(DENY_LOCKED), "{user}");
        }
        assert!(DENY_LOCKED.contains("锁定") && DENY_LOCKED.contains("locked"));
        assert_eq!(managed(GDM, &p, ADMIN), Decision::Allow);
        // 没有锁定时照方式放行。
        let p = policy_from_bundle(&school, &g, None);
        assert!(!p.locked);
        assert_eq!(p.lock_message, None);
        assert_eq!(p.methods, ["guest", "local", "sso"]);
        assert_eq!(managed(GDM, &p, "alice"), Decision::Allow);
    }

    /// Task 19：只有包写出的策略带 `from_bundle`（家目录清理据此知道管理员名单是学校给的）；
    /// 写不下而改写成锁定策略、连管理员也放不下时不再算。
    #[test]
    fn only_bundle_policy_is_marked_from_bundle() {
        assert!(!policy_from_seed(&seed(SEED_OIDC)).from_bundle);
        let m = mastersos_bundle::Manifest::parse(
            "version = 1\n[school]\nadmin_users = [\"A@x.th\"]\n[[group]]\nid = \"a\"\nname = \"a\"\n",
        )
        .unwrap();
        let p = policy_from_bundle(&m.school, &m.effective_of_group("a").unwrap(), None);
        assert!(p.from_bundle);
        assert!(fail_closed(&p).from_bundle, "管理员放得下：仍是包里的名单");
    }

    #[test]
    fn seed_with_oidc_allows_guest_and_sso() {
        let p = policy_from_seed(&seed(SEED_OIDC));
        assert_eq!(p, pol(&["guest", "sso"]));
        assert_eq!(managed(GDM, &p, "a@anything.th"), Decision::Allow);
        assert_eq!(managed(GDM, &p, "alice"), Decision::Deny(DENY_LOCAL));
        assert_eq!(managed(GDM, &p, "guest"), Decision::Allow);
        // Seed without oidc: guest only until the first bundle arrives.
        let p = policy_from_seed(&seed(SEED_PLAIN));
        assert_eq!(p, pol(&["guest"]));
        assert_eq!(managed(GDM, &p, "guest"), Decision::Allow);
        for user in ["a@anything.th", "alice"] {
            assert!(
                matches!(managed(GDM, &p, user), Decision::Deny(_)),
                "{user}"
            );
        }
    }

    #[test]
    fn bad_user_names_are_denied() {
        for user in ["", "-x", "--help", "a\nb", "a\u{7}b", "a\0b"] {
            for svc in [GDM, "sshd", "cron"] {
                assert_eq!(
                    decide(svc, false, None, user, Some(1001)),
                    Decision::Deny(DENY_BAD_USER),
                    "{user:?} {svc}"
                );
            }
        }
    }

    /// section → 键的集合。
    fn ini_keys(text: &str) -> BTreeMap<String, BTreeSet<String>> {
        let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut section = String::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = s.to_string();
                out.entry(section.clone()).or_default();
            } else {
                let (k, _) = line.split_once('=').unwrap();
                out.entry(section.clone())
                    .or_default()
                    .insert(k.trim().to_string());
            }
        }
        out
    }

    #[test]
    fn broker_conf_matches_s1_shape() {
        let s1 = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spikes/s1/broker-conf/10-zitadel.conf"
        ))
        .unwrap();
        let mine = render_broker_conf(&oidc("https://sso.school.ac.th"), &all());
        // S1 asked for a refresh token; the card logs in on the school's page every time.
        let mut s1_keys = ini_keys(&s1);
        s1_keys.get_mut("oidc").unwrap().remove("extra_scopes");
        assert_eq!(ini_keys(&mine), s1_keys);
        assert!(!mine.contains("offline_access"), "{mine}");
        assert!(!mine.contains("extra_scopes"), "{mine}");
        for line in [
            "issuer = https://sso.school.ac.th",
            "client_id = laptops",
            "allowed_users = ALL",
        ] {
            assert!(mine.lines().any(|l| l == line), "{line}\n{mine}");
        }
    }

    #[test]
    fn broker_conf_carries_the_client_secret_only_when_set() {
        let plain = render_broker_conf(&oidc("https://sso.school.ac.th"), &all());
        assert!(!plain.contains("client_secret"), "{plain}");
        let with = render_broker_conf(
            &Oidc {
                client_secret: Some("GOCSPX-abc".into()),
                ..oidc("https://sso.school.ac.th")
            },
            &all(),
        );
        let oidc_section = with.split("[users]").next().unwrap();
        assert!(
            oidc_section
                .lines()
                .any(|l| l == "client_secret = GOCSPX-abc"),
            "{with}"
        );
    }

    fn users_section(conf: &str) -> Vec<String> {
        conf.split("[users]\n")
            .nth(1)
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }

    /// Bug C (20261105.15): a refused account must not become an authd user. authd registers whoever the broker grants,
    /// so the broker itself gets the domains (patch 0006), in a file of their own; the drop-in names the administrators so
    /// they keep their exemption.
    #[test]
    fn broker_gets_the_school_domains_in_a_file_of_their_own() {
        let mut p = all();
        p.allowed_domains = vec!["school.ac.th".into(), "staff.school.ac.th".into()];
        p.admin_users = vec!["it@vendor.th".into(), "head@school.ac.th".into()];
        let conf = render_broker_conf(&oidc("https://sso.school.ac.th"), &p);
        assert_eq!(
            users_section(&conf),
            ["allowed_users = ALL, it@vendor.th, head@school.ac.th"],
            "{conf}"
        );
        let file = render_domains_file(&p).unwrap();
        let domains: Vec<&str> = file.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(domains, ["school.ac.th", "staff.school.ac.th"], "{file}");
        // No domain list: no file, everyone the school's provider signs in, as before.
        p.allowed_domains.clear();
        assert_eq!(render_domains_file(&p), None);
        assert_eq!(
            render_broker_users(&p),
            "allowed_users = ALL\n",
            "admins are not listed when nothing limits the others"
        );
    }

    /// On a rollback the older broker reads this drop-in: only the keys of the pinned upstream tag, never `allowed_domains`.
    #[test]
    fn broker_conf_has_only_keys_an_unpatched_broker_knows() {
        let mut p = all();
        p.allowed_domains = vec!["school.ac.th".into()];
        p.admin_users = vec!["it@vendor.th".into()];
        let conf = render_broker_conf(
            &Oidc {
                client_secret: Some("s".into()),
                ..oidc("https://sso.school.ac.th")
            },
            &p,
        );
        let keys = ini_keys(&conf);
        assert_eq!(
            keys.keys().map(String::as_str).collect::<Vec<_>>(),
            ["oidc", "users"]
        );
        for k in &keys["oidc"] {
            assert!(
                ["issuer", "client_id", "client_secret"].contains(&k.as_str()),
                "{k}"
            );
        }
        assert_eq!(keys["users"].iter().collect::<Vec<_>>(), ["allowed_users"]);
    }

    #[test]
    fn invalid_entries_stay_out_and_never_open_the_broker() {
        let mut p = all();
        p.allowed_domains = vec![
            "school.ac.th".into(),
            "bad,domain\nallowed_users = ALL".into(),
            "".into(),
        ];
        p.admin_users = vec!["it@vendor.th".into(), "x, y@z".into()];
        assert_eq!(
            render_broker_users(&p),
            "allowed_users = ALL, it@vendor.th\n"
        );
        let file = render_domains_file(&p).unwrap();
        assert_eq!(
            file.lines()
                .filter(|l| !l.starts_with('#'))
                .collect::<Vec<_>>(),
            ["school.ac.th"]
        );
        // Only invalid domains: the file is still there, with no domain, so the broker lets only the administrators through
        // (pam-check matches nobody else either). Never no file: that would be no filter at all.
        p.allowed_domains = vec!["Bad Domain".into()];
        let file = render_domains_file(&p).unwrap();
        assert!(file.lines().all(|l| l.starts_with('#')), "{file}");
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn broker(root: &Path) -> PathBuf {
        root.join(BROKER_DIR).join(BROKER_FILE)
    }

    fn policy_file(root: &Path) -> PathBuf {
        paths(root).var_dir.join(POLICY_SUBDIR).join(POLICY_FILE)
    }

    fn sso_group() -> Config {
        let mut g = config();
        g.login_methods = vec![LoginMethod::Sso, LoginMethod::Local];
        g
    }

    /// Like `run_bundle_no_src`, with the image's registration file in place (unless a test put its own).
    fn run_bundle(
        root: &Path,
        school: &School,
        g: &Config,
        runner: &FakeRunner,
        sys: &mut SysState,
    ) -> Vec<ItemResult> {
        if !root.join(BROKER_DECL_SRC).exists() {
            put_decl_src(root, "[authd]\nname = OIDC\n");
        }
        run_bundle_no_src(root, school, g, runner, sys)
    }

    fn run_bundle_no_src(
        root: &Path,
        school: &School,
        g: &Config,
        runner: &FakeRunner,
        sys: &mut SysState,
    ) -> Vec<ItemResult> {
        let p = paths(root);
        let flag = AtomicBool::new(false);
        let dir = tempfile::tempdir().unwrap();
        let ctx = ApplyContext {
            seed: &crate::system::tests::test_seed(),
            school,
            group: &group(),
            config: g,
            lock: None,
            bundle_dir: dir.path(),
            phase: Phase::Boot,
            superseded: &flag,
        };
        run(
            &ctx,
            &mut Env {
                paths: &p,
                runner,
                sys,
            },
        )
    }

    fn school_with(o: Option<Oidc>) -> School {
        School {
            oidc: o,
            ..School::default()
        }
    }

    #[test]
    fn step_writes_broker_conf_0600_and_restarts_authd_once() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let school = school_with(Some(oidc("https://sso.school.ac.th")));
        let g = sso_group();
        let out = run_bundle(root.path(), &school, &g, &r, &mut sys);
        assert_eq!(out, vec![ok(ITEM)]);
        let b = broker(root.path());
        assert_eq!(
            fs::read_to_string(&b).unwrap(),
            render_broker_conf(
                school.oidc.as_ref().unwrap(),
                &policy_from_bundle(&school, &g, None)
            )
        );
        // No school domains: no domain file (no filter, as upstream).
        assert!(!domains_file(root.path()).exists());
        assert_eq!(mode(&b), 0o600);
        assert_eq!(mode(b.parent().unwrap()), 0o700);
        // 策略文件 0644，login/ 0755，var_dir 仍是 0700。
        let pf = policy_file(root.path());
        let written: LoginPolicy = serde_json::from_slice(&fs::read(&pf).unwrap()).unwrap();
        assert_eq!(written, policy_from_bundle(&school, &g, None));
        assert_eq!(mode(&pf), 0o644);
        assert_eq!(mode(pf.parent().unwrap()), 0o755);
        assert_eq!(mode(&paths(root.path()).var_dir), 0o700);
        assert_eq!(r.calls(), vec![RESTART]);
        assert!(!sys.broker_restart_pending);
        // 内容不变：不再重启。
        assert_eq!(
            run_bundle(root.path(), &school, &g, &r, &mut sys),
            vec![ok(ITEM)]
        );
        assert_eq!(r.calls(), vec![RESTART]);
        // 只有策略变了（方式加了访客）：broker 配置没变，也不重启。
        let mut g2 = g.clone();
        g2.login_methods.push(LoginMethod::Guest);
        run_bundle(root.path(), &school, &g2, &r, &mut sys);
        assert_eq!(r.calls(), vec![RESTART]);
        // issuer 变了：重启一次。
        let school2 = school_with(Some(oidc("https://sso2.school.ac.th")));
        run_bundle(root.path(), &school2, &g, &r, &mut sys);
        assert_eq!(r.calls(), vec![RESTART, RESTART]);
    }

    /// 重启失败：回报失败，下一轮即使内容没变也再重启一次，直到成功。
    #[test]
    fn failed_restart_is_retried_next_run() {
        let root = tmp_root();
        let r = FakeRunner::new();
        r.respond("systemctl", Output::fail(1, "authd 起不来"));
        let mut sys = SysState::default();
        let school = school_with(Some(oidc("https://sso.school.ac.th")));
        let out = run_bundle(root.path(), &school, &sso_group(), &r, &mut sys);
        assert_eq!(out.len(), 1);
        assert!(!out[0].ok);
        assert!(sys.broker_restart_pending);
        assert_eq!(
            run_bundle(root.path(), &school, &sso_group(), &r, &mut sys),
            vec![ok(ITEM)]
        );
        assert_eq!(r.calls(), vec![RESTART, RESTART]);
        assert!(!sys.broker_restart_pending);
        run_bundle(root.path(), &school, &sso_group(), &r, &mut sys);
        assert_eq!(r.calls().len(), 2);
    }

    fn domains_file(root: &Path) -> PathBuf {
        root.join(DOMAINS_DIR).join(DOMAINS_FILE)
    }

    fn domain_lines(root: &Path) -> Vec<String> {
        fs::read_to_string(domains_file(root))
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(String::from)
            .collect()
    }

    /// The school's domains reach the broker's own file and the administrators its drop-in; a change to the domains
    /// restarts the broker (it reads the file only when it starts). The drop-in itself keeps only upstream keys.
    #[test]
    fn step_writes_the_domain_file_and_restarts_on_change() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let mut school = school_with(Some(oidc("https://sso.school.ac.th")));
        school.allowed_domains = vec!["School.ac.th".into(), "staff.school.ac.th".into()];
        school.admin_users = vec!["IT@vendor.th".into()];
        let g = sso_group();
        assert_eq!(
            run_bundle(root.path(), &school, &g, &r, &mut sys),
            vec![ok(ITEM)]
        );
        let text = fs::read_to_string(broker(root.path())).unwrap();
        assert_eq!(
            users_section(&text),
            ["allowed_users = ALL, it@vendor.th"],
            "{text}"
        );
        assert!(!text.contains("allowed_domains"), "{text}");
        assert_eq!(
            domain_lines(root.path()),
            ["school.ac.th", "staff.school.ac.th"]
        );
        assert_eq!(mode(&domains_file(root.path())), 0o644);
        assert_eq!(r.calls(), vec![RESTART]);
        // Same settings: nothing changes, no restart.
        run_bundle(root.path(), &school, &g, &r, &mut sys);
        assert_eq!(r.calls(), vec![RESTART]);
        // Only the domains change (the drop-in stays the same): the broker is restarted all the same.
        school.allowed_domains = vec!["school.ac.th".into(), "other.ac.th".into()];
        run_bundle(root.path(), &school, &g, &r, &mut sys);
        assert_eq!(r.calls(), vec![RESTART, RESTART]);
        assert_eq!(domain_lines(root.path()), ["school.ac.th", "other.ac.th"]);
        // No domains any more: the file goes (no filter), and the broker is restarted.
        school.allowed_domains.clear();
        run_bundle(root.path(), &school, &g, &r, &mut sys);
        assert!(!domains_file(root.path()).exists());
        assert_eq!(r.calls(), vec![RESTART, RESTART, RESTART]);
    }

    /// Only invalid domains: the file is written without any domain (only the administrators get through the broker),
    /// never left out, which would let everyone through to authd; the step reports the bad entries.
    #[test]
    fn step_with_only_invalid_domains_keeps_a_file_without_domains() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let mut school = school_with(Some(oidc("https://sso.school.ac.th")));
        school.allowed_domains = vec!["not a domain".into()];
        let out = run_bundle(root.path(), &school, &sso_group(), &r, &mut sys);
        assert_eq!(out.len(), 1);
        assert!(!out[0].ok);
        assert!(
            out[0]
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("matches no account"),
            "{out:?}"
        );
        assert!(broker(root.path()).exists());
        assert!(domain_lines(root.path()).is_empty());
    }

    /// The domain file cannot be written (here a directory sits where it goes, so it can be neither replaced nor read):
    /// fail closed. The drop-in names only the administrators, no `ALL`, so no domain gets through on a patched broker
    /// (whatever the file says) or an older one; the step reports it. A later run that can write the file restores `ALL`.
    #[test]
    fn domain_file_write_failure_lets_only_the_administrators_through() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let mut school = school_with(Some(oidc("https://sso.school.ac.th")));
        school.allowed_domains = vec!["school.ac.th".into()];
        school.admin_users = vec!["IT@vendor.th".into(), "head@school.ac.th".into()];
        let g = sso_group();
        // First a good run: ALL, with the marker and the file.
        assert_eq!(
            run_bundle(root.path(), &school, &g, &r, &mut sys),
            vec![ok(ITEM)]
        );
        let text = fs::read_to_string(broker(root.path())).unwrap();
        assert!(text.lines().any(|l| l == DOMAINS_MARKER), "{text}");
        assert_eq!(
            users_section(&text),
            ["allowed_users = ALL, it@vendor.th, head@school.ac.th"]
        );
        // The file can no longer be written.
        fs::remove_file(domains_file(root.path())).unwrap();
        fs::create_dir(domains_file(root.path())).unwrap();
        let out = run_bundle(root.path(), &school, &g, &r, &mut sys);
        assert_eq!(out.len(), 1);
        assert!(!out[0].ok);
        let detail = out[0].detail.as_deref().unwrap_or_default();
        assert!(detail.contains("broker domain file"), "{detail}");
        assert!(detail.contains("only the administrators"), "{detail}");
        let text = fs::read_to_string(broker(root.path())).unwrap();
        assert!(text.lines().any(|l| l == DOMAINS_MARKER), "{text}");
        assert_eq!(
            users_section(&text),
            ["allowed_users = it@vendor.th, head@school.ac.th"],
            "{text}"
        );
        assert!(!text.contains("ALL"), "{text}");
        // The drop-in changed: the broker is restarted so that the administrators-only list holds at once.
        assert_eq!(r.calls(), vec![RESTART, RESTART]);
        assert!(decl(root.path()).exists());
        // Fixed: ALL again.
        fs::remove_dir(domains_file(root.path())).unwrap();
        assert_eq!(
            run_bundle(root.path(), &school, &g, &r, &mut sys),
            vec![ok(ITEM)]
        );
        assert_eq!(
            users_section(&fs::read_to_string(broker(root.path())).unwrap()),
            ["allowed_users = ALL, it@vendor.th, head@school.ac.th"]
        );
        assert_eq!(domain_lines(root.path()), ["school.ac.th"]);
        assert_eq!(r.calls(), vec![RESTART, RESTART, RESTART]);
    }

    /// The same failure with no administrator to name: no drop-in, no registration, no sign-in card. School sign-in is off
    /// (reported), never open to every domain.
    #[test]
    fn domain_file_write_failure_without_administrators_turns_school_sign_in_off() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let mut school = school_with(Some(oidc("https://sso.school.ac.th")));
        school.allowed_domains = vec!["school.ac.th".into()];
        let g = sso_group();
        run_bundle(root.path(), &school, &g, &r, &mut sys);
        assert!(broker(root.path()).exists());
        assert!(card_policy(root.path()).exists());
        fs::remove_file(domains_file(root.path())).unwrap();
        fs::create_dir(domains_file(root.path())).unwrap();
        let out = run_bundle(root.path(), &school, &g, &r, &mut sys);
        assert_eq!(out.len(), 1);
        assert!(!out[0].ok);
        let detail = out[0].detail.as_deref().unwrap_or_default();
        assert!(detail.contains("school sign-in is off"), "{detail}");
        assert!(!broker(root.path()).exists());
        assert!(!decl(root.path()).exists());
        assert!(!card_policy(root.path()).exists());
        assert_eq!(r.calls(), vec![RESTART, RESTART]);
    }

    /// Only a drop-in with a domain list carries the marker; it is a comment, so the keys stay those of upstream.
    #[test]
    fn marker_only_with_domains() {
        let mut p = all();
        let conf = render_broker_conf(&oidc("https://sso.school.ac.th"), &p);
        assert!(!conf.contains(DOMAINS_MARKER), "{conf}");
        p.allowed_domains = vec!["school.ac.th".into()];
        let conf = render_broker_conf(&oidc("https://sso.school.ac.th"), &p);
        assert_eq!(conf.lines().nth(1), Some(DOMAINS_MARKER), "{conf}");
        assert!(DOMAINS_MARKER.starts_with('#') && !DOMAINS_MARKER.contains('\n'));
        p.admin_users = vec!["x, y@z".into()];
        assert_eq!(
            render_broker_conf_admins_only(&oidc("https://sso.school.ac.th"), &p),
            None,
            "an invalid administrator is no administrator"
        );
    }

    /// The domain file goes with the drop-in: no SSO, no file (and an unpatched broker never cared about it anyway).
    #[test]
    fn sso_removed_deletes_the_domain_file() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let mut school = school_with(Some(oidc("https://sso.school.ac.th")));
        school.allowed_domains = vec!["school.ac.th".into()];
        run_bundle(root.path(), &school, &sso_group(), &r, &mut sys);
        assert!(domains_file(root.path()).exists());
        let mut local = config();
        local.login_methods = vec![LoginMethod::Local];
        assert_eq!(
            run_bundle(root.path(), &school, &local, &r, &mut sys),
            vec![ok(ITEM)]
        );
        assert!(!domains_file(root.path()).exists());
        assert!(!broker(root.path()).exists());
    }

    #[test]
    fn sso_removed_deletes_broker_conf() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let school = school_with(Some(oidc("https://sso.school.ac.th")));
        run_bundle(root.path(), &school, &sso_group(), &r, &mut sys);
        assert!(broker(root.path()).exists());
        // 别人放的 drop-in 不动。
        fs::write(root.path().join(BROKER_DIR).join("20-other.conf"), b"x").unwrap();
        let mut local = config();
        local.login_methods = vec![LoginMethod::Local];
        assert_eq!(
            run_bundle(root.path(), &school, &local, &r, &mut sys),
            vec![ok(ITEM)]
        );
        assert!(!broker(root.path()).exists());
        assert!(root.path().join(BROKER_DIR).join("20-other.conf").exists());
        assert_eq!(r.calls(), vec![RESTART, RESTART]);
        // 已经没有了：不再重启。
        run_bundle(root.path(), &school, &local, &r, &mut sys);
        assert_eq!(r.calls().len(), 2);
        // 方式里有 sso 但学校没配 oidc：也不写。
        let fresh = tmp_root();
        let r2 = FakeRunner::new();
        let out = run_bundle(
            fresh.path(),
            &school_with(None),
            &sso_group(),
            &r2,
            &mut SysState::default(),
        );
        assert_eq!(out, vec![ok(ITEM)]);
        assert!(!broker(fresh.path()).exists());
        assert!(r2.calls().is_empty());
    }

    /// issuer / client_id 里的换行会往 broker 配置里注入别的键：不写、回报失败，已有的配置删掉。
    #[test]
    fn injected_oidc_is_not_rendered() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        run_bundle(
            root.path(),
            &school_with(Some(oidc("https://sso.school.ac.th"))),
            &sso_group(),
            &r,
            &mut sys,
        );
        let bad = school_with(Some(oidc(
            "https://sso.school.ac.th\n[users]\nallowed_users = OWNER",
        )));
        let out = run_bundle(root.path(), &bad, &sso_group(), &r, &mut sys);
        assert_eq!(out.len(), 1);
        assert!(!out[0].ok);
        assert!(!broker(root.path()).exists());
        // 策略照写（登录方式不因 oidc 坏了而丢）。
        assert!(policy_file(root.path()).exists());
    }

    #[test]
    fn seed_phase_writes_seed_defaults() {
        let root = tmp_root();
        put_decl_src(root.path(), "[authd]\nname = OIDC\n");
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let p = paths(root.path());
        let out = run_seed(
            &seed(SEED_OIDC),
            &mut Env {
                paths: &p,
                runner: &r,
                sys: &mut sys,
            },
        );
        assert_eq!(out, vec![ok(ITEM)]);
        let written: LoginPolicy =
            serde_json::from_slice(&fs::read(policy_file(root.path())).unwrap()).unwrap();
        assert_eq!(written, pol(&["guest", "sso"]));
        assert!(broker(root.path()).exists());
        assert_eq!(r.calls(), vec![RESTART]);
    }

    #[test]
    fn write_policy_reports_change() {
        let root = tmp_root();
        let p = paths(root.path());
        assert!(write_policy(&p, &pol(&["sso"])).unwrap());
        assert!(!write_policy(&p, &pol(&["sso"])).unwrap());
        assert!(write_policy(&p, &pol(&["local"])).unwrap());
        assert_eq!(
            Path::new(POLICY_PATH),
            SysPaths::default()
                .var_dir
                .join(POLICY_SUBDIR)
                .join(POLICY_FILE)
        );
    }

    fn read_policy(root: &Path) -> LoginPolicy {
        serde_json::from_slice(&fs::read(policy_file(root)).unwrap()).unwrap()
    }

    /// I1：写不进 pam-check 读得了的大小，就不写这一份；改写锁定的策略并回报失败，
    /// 而不是留一份 pam-check 会当作没有（退回更宽松的种子默认值）的文件。
    #[test]
    fn oversize_policy_is_refused_and_fails_closed() {
        let root = tmp_root();
        let p = paths(root.path());
        // write_policy 自己就拒绝超长的输出，原来的文件不动。
        write_policy(&p, &pol(&["sso"])).unwrap();
        let mut huge = pol(&["sso"]);
        huge.allowed_domains = (0..60_000).map(|i| format!("d{i}.school.ac.th")).collect();
        assert!(policy_json(&huge).is_err());
        assert!(write_policy(&p, &huge).is_err());
        assert_eq!(read_policy(root.path()), pol(&["sso"]));

        // 步骤：域名太多 → 锁定、方式清空，管理员照样放行；回报失败。
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let school = School {
            oidc: Some(oidc("https://sso.school.ac.th")),
            admin_users: vec![ADMIN.into()],
            allowed_domains: huge.allowed_domains.clone(),
            ..School::default()
        };
        let out = run_bundle(root.path(), &school, &sso_group(), &r, &mut sys);
        assert_eq!(out.len(), 1);
        assert!(!out[0].ok);
        assert!(
            out[0].detail.as_deref().unwrap().contains("too large"),
            "{out:?}"
        );
        let written = read_policy(root.path());
        assert!(written.locked);
        assert!(written.methods.is_empty());
        assert!(written
            .lock_message
            .as_deref()
            .unwrap()
            .contains("设置太大"));
        assert_eq!(written.admin_users, [ADMIN]);
        assert_eq!(managed(GDM, &written, ADMIN), Decision::Allow);
        assert_eq!(
            managed(GDM, &written, "a@school.ac.th"),
            Decision::Deny(DENY_LOCKED)
        );
        // 管理员还要登得进来：broker 配置照学校的 oidc 写。
        assert!(broker(root.path()).exists());

        // 管理员本身太多：锁定的那份连管理员也放不下，就不带管理员（仍然锁定）。
        let school = School {
            admin_users: (0..60_000)
                .map(|i| format!("admin{i}@school.ac.th"))
                .collect(),
            ..School::default()
        };
        let out = run_bundle(root.path(), &school, &sso_group(), &r, &mut sys);
        assert!(!out[0].ok);
        let written = read_policy(root.path());
        assert!(written.locked && written.methods.is_empty() && written.admin_users.is_empty());
    }

    /// lint 的上限（个数 × 每项长度）加上最长的锁屏消息，远在策略大小上限之内。
    #[test]
    fn policy_at_lint_caps_fits() {
        let long = |n: usize, suffix: &str| {
            let mut s = "a".repeat(checks::MAX_ENTRY_LEN - suffix.len() - 4);
            s.push_str(&format!("{n:04}"));
            s.push_str(suffix);
            s
        };
        let p = LoginPolicy {
            methods: vec!["guest".into(), "local".into(), "sso".into()],
            allowed_domains: (0..checks::MAX_ALLOWED_DOMAINS)
                .map(|i| long(i, ".th"))
                .collect(),
            admin_users: (0..checks::MAX_ADMIN_USERS)
                .map(|i| long(i, "@x.th"))
                .collect(),
            locked: true,
            lock_message: Some("锁".repeat(500)),
            from_bundle: true,
            kiosk_users: (0..mastersos_bundle::kiosk::MAX_KIOSK_APPS)
                .map(|i| KioskUser {
                    user: format!(
                        "kiosk-{}{i:04}",
                        "a".repeat(mastersos_bundle::kiosk::MAX_ID_LEN - 4)
                    ),
                    name: "名".repeat(200),
                })
                .collect(),
            it_account: true,
            it_account_uid: Some(59999),
        };
        assert!(p.admin_users.iter().all(|a| checks::admin_user(a).is_ok()));
        assert!(p
            .allowed_domains
            .iter()
            .all(|d| checks::allowed_domain(d).is_ok()));
        let n = policy_json(&p).unwrap().len();
        assert!(n * 4 < MAX_POLICY_BYTES, "{n}");
    }

    /// M1：`system-state.json` 读不出来时，`broker_restart_pending` 可能丢了；broker 配置在的话就当作要重启。
    #[test]
    fn lost_state_restarts_when_broker_conf_exists() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let school = school_with(Some(oidc("https://sso.school.ac.th")));
        run_bundle(
            root.path(),
            &school,
            &sso_group(),
            &r,
            &mut SysState::default(),
        );
        assert_eq!(r.calls(), vec![RESTART]);
        // 内容没变，但状态没读出来：再重启一次。
        let mut lost = SysState {
            load_failed: true,
            ..SysState::default()
        };
        assert_eq!(
            run_bundle(root.path(), &school, &sso_group(), &r, &mut lost),
            vec![ok(ITEM)]
        );
        assert_eq!(r.calls(), vec![RESTART, RESTART]);
        // 没有 SSO（broker 配置不在）：不重启。
        let fresh = tmp_root();
        let r2 = FakeRunner::new();
        let mut lost = SysState {
            load_failed: true,
            ..SysState::default()
        };
        let mut local = config();
        local.login_methods = vec![LoginMethod::Local];
        run_bundle(fresh.path(), &school, &local, &r2, &mut lost);
        assert!(r2.calls().is_empty());
    }

    /// 同上，经 `SystemApplier`：状态文件读失败时步骤看到的是 `load_failed`。
    #[test]
    fn unreadable_state_file_triggers_restart_via_applier() {
        use super::super::SystemApplier;
        use crate::apply::Applier;
        use std::sync::Arc;
        let root = tmp_root();
        let r = Arc::new(FakeRunner::new());
        let a = SystemApplier::with_steps(paths(root.path()), r.clone(), vec![step()]);
        let s = seed(SEED_OIDC);
        a.apply_without_bundle(&s, Phase::Boot);
        a.apply_without_bundle(&s, Phase::Boot);
        assert_eq!(r.calls(), vec![RESTART]);
        // system-state.json 换成目录：读失败。
        let state = paths(root.path()).var_dir.join("system-state.json");
        fs::remove_file(&state).ok();
        fs::create_dir(&state).unwrap();
        a.apply_without_bundle(&s, Phase::Boot);
        assert_eq!(r.calls(), vec![RESTART, RESTART]);
    }

    /// M5：`getent passwd -- <user>` 的输出只认第一行、第一列等于这个名字的那条。
    #[test]
    fn parse_getent_guards_user() {
        assert_eq!(
            parse_getent("alice:x:1001:1001:Alice:/home/alice:/bin/bash\n", "alice"),
            Some(1001)
        );
        // `getent passwd 0` 按 uid 查到 root：名字对不上，不认。
        assert_eq!(parse_getent("root:x:0:0:root:/root:/bin/bash\n", "0"), None);
        assert_eq!(
            parse_getent("bob:x:1002:1002::/home/bob:/bin/sh\n", "alice"),
            None
        );
        // 少字段、uid 不是数字、空输出。
        assert_eq!(parse_getent("alice:x\n", "alice"), None);
        assert_eq!(parse_getent("alice:x:abc:1:::\n", "alice"), None);
        assert_eq!(parse_getent("alice:x:-1:1:::\n", "alice"), None);
        assert_eq!(parse_getent("", "alice"), None);
        // 只看第一行。
        assert_eq!(
            parse_getent("bob:x:1002:1:::\nalice:x:1001:1:::\n", "alice"),
            None
        );
        assert_eq!(
            parse_getent(
                "a@school.ac.th:x:10000:10000::/home/a@school.ac.th:/bin/bash",
                "a@school.ac.th"
            ),
            Some(10000)
        );
    }

    #[test]
    fn login_is_fast_step_with_seed_fallback() {
        let all = steps();
        let s = all.iter().find(|s| s.name == "login").unwrap();
        assert!(s.fast);
        assert!(s.without_bundle.is_some());
    }

    // --- 锁定应用的账号 `kiosk-<id>`（计划 9 Task 4，设计 §4.2） ---

    const KIOSK: &str = "kiosk-nwea";
    const KIOSK_UID: Option<u32> = Some(1900);

    fn kiosk_user(user: &str, name: &str) -> KioskUser {
        KioskUser {
            user: user.into(),
            name: name.into(),
        }
    }

    /// 方式只有 `methods`，名单里有 `kiosk-nwea`。
    fn kpol(methods: &[&str]) -> LoginPolicy {
        let mut p = pol(methods);
        p.kiosk_users = vec![kiosk_user(KIOSK, "NWEA MAP")];
        p
    }

    fn kiosk_decide(service: &str, p: &LoginPolicy, user: &str) -> Decision {
        decide(service, true, Some(p), user, KIOSK_UID)
    }

    #[test]
    fn classify_kiosk_needs_prefix_and_list() {
        let p = kpol(&["sso"]);
        assert_eq!(classify(KIOSK, Some(&p)), UserClass::Kiosk);
        // 名单外的、没有策略的：按名字照旧分（受管机器上另由 decide 拒，见下）
        assert_eq!(classify("kiosk-old", Some(&p)), UserClass::Local);
        assert_eq!(classify(KIOSK, None), UserClass::Local);
        // 前缀与名单都要精确：大小写、前后空白不同的是别的账号
        for user in [
            "Kiosk-nwea",
            "KIOSK-NWEA",
            "kiosk-nwea ",
            " kiosk-nwea",
            "nwea",
        ] {
            assert_eq!(classify(user, Some(&p)), UserClass::Local, "{user:?}");
        }
        // 名单里混进来不带前缀的、带 @ 的名字，也不会让它们变成 kiosk
        let mut odd = kpol(&[]);
        odd.kiosk_users = vec![kiosk_user("alice", "x"), kiosk_user("kiosk-a@b.th", "x")];
        assert_eq!(classify("alice", Some(&odd)), UserClass::Local);
        assert_eq!(classify("kiosk-a@b.th", Some(&odd)), UserClass::Sso);
        assert_eq!(classify("guest", Some(&p)), UserClass::Guest);
    }

    /// 设计 §4.2：只从 GDM 的两个服务进（与访客同一张表），tty、ssh、su 一律拒。
    #[test]
    fn kiosk_allowed_only_via_gdm() {
        let p = kpol(&["guest", "local", "sso"]);
        for svc in GUEST_SERVICES {
            assert_eq!(kiosk_decide(svc, &p, KIOSK), Decision::Allow, "{svc}");
        }
        for svc in [
            "login",
            "sshd",
            "su",
            "su-l",
            "gdm-autologin",
            "gdm-fingerprint",
            "gdm-smartcard",
            "",
        ] {
            assert_eq!(
                kiosk_decide(svc, &p, KIOSK),
                Decision::Deny(DENY_KIOSK),
                "{svc}"
            );
        }
        assert!(DENY_KIOSK.contains("登录界面") && DENY_KIOSK.contains("sign-in screen"));
    }

    /// 定时任务在放行表之前就拒（与访客同理：会留在下一位的会话之外跑）。
    #[test]
    fn kiosk_denied_for_cron_and_at() {
        let p = kpol(&["guest", "local", "sso"]);
        for svc in GUEST_DENIED_SCHEDULERS {
            assert_eq!(
                kiosk_decide(svc, &p, KIOSK),
                Decision::Deny(DENY_KIOSK),
                "{svc}"
            );
            // 名单外的 kiosk- 名字在受管机器上同样拒
            assert_eq!(
                kiosk_decide(svc, &p, "kiosk-old"),
                Decision::Deny(DENY_KIOSK_UNKNOWN),
                "{svc}"
            );
        }
        // 别人的 cron 照旧放行
        assert_eq!(kiosk_decide("cron", &p, "alice"), Decision::Allow);
    }

    #[test]
    fn kiosk_not_in_list_denied() {
        let p = kpol(&["guest", "local", "sso"]);
        for svc in GUEST_SERVICES {
            assert_eq!(
                kiosk_decide(svc, &p, "kiosk-old"),
                Decision::Deny(DENY_KIOSK_UNKNOWN),
                "{svc}"
            );
        }
        // 策略文件坏了、退回种子的默认值：种子里没有锁定应用，一样拒
        let fallback = effective_policy(Some(b"{garbage"), Some(SEED_OIDC)).unwrap();
        assert!(fallback.kiosk_users.is_empty());
        assert_eq!(
            kiosk_decide(GDM, &fallback, KIOSK),
            Decision::Deny(DENY_KIOSK_UNKNOWN)
        );
        assert!(DENY_KIOSK_UNKNOWN.contains("不在") && DENY_KIOSK_UNKNOWN.contains("no longer"));
    }

    /// 锁定应用本身就是分组给的入口：不看 `methods`。
    #[test]
    fn kiosk_ignores_login_methods() {
        for methods in [&["sso"][..], &[], &["guest"], &["local"]] {
            assert_eq!(
                kiosk_decide(GDM, &kpol(methods), KIOSK),
                Decision::Allow,
                "{methods:?}"
            );
        }
        // 域名限制只管 SSO 账号
        let mut p = kpol(&["sso"]);
        p.allowed_domains = vec!["school.ac.th".into()];
        assert_eq!(kiosk_decide(GDM, &p, KIOSK), Decision::Allow);
    }

    /// 裁定 K10：挂失锁定的机器上 kiosk 账号一样登不进去。
    #[test]
    fn kiosk_denied_when_locked() {
        let mut p = kpol(&["guest", "local", "sso"]);
        p.locked = true;
        for svc in GUEST_SERVICES {
            assert_eq!(
                kiosk_decide(svc, &p, KIOSK),
                Decision::Deny(DENY_LOCKED),
                "{svc}"
            );
        }
        // 经 policy_from_bundle：锁定时名单照写，判定仍是拒
        let mut g = config();
        g.apps.kiosk = kiosk_apps(&["nwea"]);
        let lock = Lock {
            message: "请把电脑交给 IT".into(),
        };
        let p = policy_from_bundle(&School::default(), &g, Some(&lock));
        assert_eq!(p.kiosk_users.len(), 1);
        assert_eq!(kiosk_decide(GDM, &p, KIOSK), Decision::Deny(DENY_LOCKED));
    }

    /// 会话要起 user manager（`user@<uid>.service` 走 systemd-user）。
    #[test]
    fn kiosk_systemd_user_passthrough() {
        let mut p = kpol(&[]);
        assert_eq!(kiosk_decide("systemd-user", &p, KIOSK), Decision::Allow);
        // 锁定时也放行 user manager（与别人一样；会话本身已在 GDM 那一步被拒）
        p.locked = true;
        assert_eq!(kiosk_decide("systemd-user", &p, KIOSK), Decision::Allow);
    }

    /// 受管机器上 `kiosk-` 是保留的前缀：名单外的一律按锁定应用的规则拒，不当本机账号放行——免得有人建一个同名的
    /// 本机账号冒用（或应用删掉后账号还没删的那一会儿）。uid 落在系统范围也不例外。未受管的机器照旧（不认得锁定应用）。
    #[test]
    fn kiosk_prefixed_local_name_denied_on_managed() {
        let p = kpol(&["guest", "local", "sso"]);
        for uid in [Some(1001), Some(1950), Some(500), Some(65534), None] {
            for svc in [GDM, "gdm-authd", "login", "sshd"] {
                assert_eq!(
                    decide(svc, true, Some(&p), "kiosk-x", uid),
                    Decision::Deny(DENY_KIOSK_UNKNOWN),
                    "{svc} {uid:?}"
                );
            }
        }
        // 名单里的账号 uid 落在系统范围：不走系统账号的放行，仍只从 GDM 进
        assert_eq!(
            decide("sshd", true, Some(&p), KIOSK, Some(500)),
            Decision::Deny(DENY_KIOSK)
        );
        // 受管而没有策略：与别人一样拒
        assert_eq!(
            decide(GDM, true, None, "kiosk-x", Some(1001)),
            Decision::Deny(DENY_NO_POLICY)
        );
        // 未受管：不认得锁定应用，kiosk-x 是普通的本机账号（行为不变）
        for svc in [GDM, "login", "sshd", "cron"] {
            assert_eq!(
                decide(svc, false, None, "kiosk-x", Some(1001)),
                Decision::Allow,
                "{svc}"
            );
        }
    }

    /// 保留的是本机账号的 `kiosk-` 前缀：形如 `kiosk-it@school.ac.th` 的 SSO 账号照 SSO 的规则判（管理员豁免、方式、域名），
    /// 不被当成名单外的锁定应用拒掉。
    #[test]
    fn kiosk_prefixed_sso_names_are_sso() {
        let sso = "kiosk-it@school.ac.th";
        let mut p = kpol(&["sso"]);
        p.kiosk_users.push(kiosk_user(sso, "x"));
        assert_eq!(classify(sso, Some(&p)), UserClass::Sso);
        // 普通的 SSO 账号：方式里有 sso 就放行，cron 照放行表放行
        for svc in [GDM, "gdm-authd", "sshd"] {
            assert_eq!(
                decide(svc, true, Some(&p), sso, Some(10001)),
                Decision::Allow,
                "{svc}"
            );
        }
        assert_eq!(
            decide("cron", true, Some(&p), sso, Some(10001)),
            Decision::Allow
        );
        assert_eq!(
            decide(GDM, true, Some(&kpol(&["local"])), sso, Some(10001)),
            Decision::Deny(DENY_SSO)
        );
        // 管理员：锁定、方式空也放行
        let mut admin = kpol(&[]);
        admin.locked = true;
        admin.admin_users = vec![sso.into()];
        assert_eq!(
            decide(GDM, true, Some(&admin), sso, Some(10001)),
            Decision::Allow
        );
        assert_eq!(
            decide("sshd", true, Some(&admin), sso, Some(10001)),
            Decision::Allow
        );
        assert!(!is_reserved_kiosk_name(sso));
        assert!(is_reserved_kiosk_name("kiosk-x"));
    }

    fn kiosk_apps(ids: &[&str]) -> BTreeMap<String, mastersos_bundle::KioskApp> {
        let toml: String = ids
            .iter()
            .map(|id| {
                format!(
                    "[group.apps.kiosk.{id}]\nname = \"App {id}\"\nurl = \"https://{id}.example.org/\"\n"
                )
            })
            .collect();
        mastersos_bundle::Manifest::parse(&format!(
            "version = 1\n[[group]]\nid = \"a\"\nname = \"a\"\n{toml}"
        ))
        .unwrap()
        .effective_of_group("a")
        .unwrap()
        .apps
        .kiosk
    }

    #[test]
    fn policy_from_bundle_lists_kiosk_accounts() {
        let mut g = config();
        g.apps.kiosk = kiosk_apps(&["zz", "nwea", "a-1"]);
        // 不合规的 id（清单的校验本该挡住）跳过：只会少放行
        let bad = g.apps.kiosk["nwea"].clone();
        g.apps.kiosk.insert("Bad_Id".into(), bad.clone());
        g.apps.kiosk.insert("a@b".into(), bad);
        let p = policy_from_bundle(&School::default(), &g, None);
        assert_eq!(
            p.kiosk_users,
            vec![
                kiosk_user("kiosk-a-1", "App a-1"),
                kiosk_user("kiosk-nwea", "App nwea"),
                kiosk_user("kiosk-zz", "App zz"),
            ]
        );
        // 没有锁定应用：空
        assert!(policy_from_bundle(&School::default(), &config(), None)
            .kiosk_users
            .is_empty());
        assert!(policy_from_seed(&seed(SEED_OIDC)).kiosk_users.is_empty());
    }

    /// 兼容约定：旧文件（没有 kiosk_users）新代码读得了；新文件旧的 pam-check（没有 deny_unknown_fields）也读得了。
    #[test]
    fn kiosk_users_field_is_compatible_both_ways() {
        let old = br#"{"methods":["sso"],"allowed_domains":[],"admin_users":[],"locked":false,"lock_message":null,"from_bundle":true}"#;
        let p: LoginPolicy = serde_json::from_slice(old).unwrap();
        assert!(p.kiosk_users.is_empty());
        /// 上一版的格式（字段照抄，没有 kiosk_users）。
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct OldLoginPolicy {
            methods: Vec<String>,
            #[serde(default)]
            allowed_domains: Vec<String>,
            #[serde(default)]
            admin_users: Vec<String>,
            locked: bool,
            #[serde(default)]
            lock_message: Option<String>,
            #[serde(default)]
            from_bundle: bool,
        }
        let new = policy_json(&kpol(&["sso"])).unwrap();
        assert!(String::from_utf8_lossy(&new).contains("kiosk-nwea"));
        let o: OldLoginPolicy = serde_json::from_slice(&new).unwrap();
        assert_eq!(o.methods, ["sso"]);
    }

    /// 写不下而改写成锁定的策略：名单留着（清理要认得还开着的 kiosk 会话），登录照样拒；名单本身放不下才丢它，
    /// 管理员排在它后面丢。
    #[test]
    fn fail_closed_keeps_kiosk_users_unless_they_do_not_fit() {
        let mut p = kpol(&["sso"]);
        p.admin_users = vec![ADMIN.into()];
        let f = fail_closed(&p);
        assert!(f.locked);
        assert_eq!(f.kiosk_users, p.kiosk_users);
        assert_eq!(kiosk_decide(GDM, &f, KIOSK), Decision::Deny(DENY_LOCKED));
        // 名字大到放不下：丢名单，管理员留着
        p.kiosk_users[0].name = "x".repeat(MAX_POLICY_BYTES);
        let f = fail_closed(&p);
        assert!(f.kiosk_users.is_empty());
        assert_eq!(f.admin_users, [ADMIN]);
        assert!(f.from_bundle == p.from_bundle);
    }

    fn decl(root: &Path) -> PathBuf {
        root.join(BROKER_DECL_DIR).join(BROKER_DECL_FILE)
    }

    fn put_decl_src(root: &Path, text: &str) {
        let p = root.join(BROKER_DECL_SRC);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }

    #[test]
    fn broker_decl_written_with_sso() {
        let root = tmp_root();
        put_decl_src(root.path(), "[authd]\nname = OIDC\n");
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let school = school_with(Some(oidc("https://sso.school.ac.th")));
        let out = run_bundle(root.path(), &school, &sso_group(), &r, &mut sys);
        assert_eq!(out, vec![ok(ITEM)]);
        let d = decl(root.path());
        assert_eq!(fs::read(&d).unwrap(), b"[authd]\nname = OIDC\n");
        assert_eq!(mode(&d), 0o644);
        assert_eq!(mode(d.parent().unwrap()), 0o755);
        assert_eq!(r.calls(), vec![RESTART]);
        // Unchanged: no second restart.
        run_bundle(root.path(), &school, &sso_group(), &r, &mut sys);
        assert_eq!(r.calls(), vec![RESTART]);
    }

    fn card_policy(root: &Path) -> PathBuf {
        paths(root)
            .public_dir
            .join(LOGIN_BROWSER_DIR)
            .join(LOGIN_BROWSER_FILE)
    }

    #[test]
    fn issuer_filter_pins_scheme_host_and_port() {
        for (issuer, want) in [
            ("https://sso.school.ac.th", "https://.sso.school.ac.th:443"),
            (
                "https://sso.school.ac.th/oidc/v1",
                "https://.sso.school.ac.th:443",
            ),
            ("https://SSO.school.ac.th/", "https://.sso.school.ac.th:443"),
            (
                "https://sso.school.ac.th:443/",
                "https://.sso.school.ac.th:443",
            ),
            ("http://sso.lab", "http://.sso.lab:80"),
            ("https://198.51.100.5/x", "https://198.51.100.5:443"),
            (
                "https://sso.school.ac.th:8443/x",
                "https://.sso.school.ac.th:8443",
            ),
            ("http://sso.lab:8080", "http://.sso.lab:8080"),
            ("https://198.51.100.5:8443/x", "https://198.51.100.5:8443"),
            ("https://[fd00::5]:8443/x", "https://[fd00::5]:8443"),
        ] {
            assert_eq!(issuer_url_filter(issuer).as_deref(), Some(want), "{issuer}");
        }
        // These would widen the allowlist, or are not a host at all: never derive a filter from them.
        for bad in [
            "",
            "sso.school.ac.th",
            "https://",
            "https:///x",
            "https:x",
            "https:\\\\x",
            "https://*",
            "https://*.school.ac.th",
            "https://a@evil.org",
            "https://a:b@evil.org",
            "https://evil.org:port",
            "https://evil.org:99999",
            "https://-evil.org",
            "https://evil..org",
            "https://evil.org.",
            "https://ev_il.org",
            "https://ev%20il.org",
            "ftp://x",
            "file:///etc/passwd",
        ] {
            assert_eq!(issuer_url_filter(bad), None, "{bad}");
        }
    }

    #[test]
    fn card_policy_allows_only_the_idp_and_the_redirect() {
        let text = render_login_browser_policy(&oidc("https://sso.school.ac.th/x")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["URLBlocklist"], serde_json::json!(["*"]));
        assert_eq!(
            v["URLAllowlist"],
            serde_json::json!(["https://.sso.school.ac.th:443", "127.0.0.1:48123/callback"])
        );
        assert_eq!(v["DownloadRestrictions"], 3);
        assert_eq!(v["DeveloperToolsAvailability"], 2);
        assert_eq!(v["AllowFileSelectionDialogs"], false);
        assert_eq!(v["PrintingEnabled"], false);
        assert_eq!(v["ExtensionInstallBlocklist"], serde_json::json!(["*"]));
        assert_eq!(render_login_browser_policy(&oidc("https://*")), None);
    }

    #[test]
    fn card_policy_allows_each_card_host_pinned() {
        let o = Oidc {
            card_hosts: vec![
                "ssl.gstatic.com".into(),
                "sso.school.ac.th".into(),
                "not a host".into(),
                "https://evil.org".into(),
            ],
            ..oidc("https://sso.school.ac.th")
        };
        let text = render_login_browser_policy(&o).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v["URLAllowlist"],
            serde_json::json!([
                "https://.sso.school.ac.th:443",
                "https://.ssl.gstatic.com:443",
                "127.0.0.1:48123/callback"
            ]),
            "an entry equal to the issuer adds nothing, an invalid one is never turned into a filter"
        );
    }

    #[test]
    fn invalid_card_hosts_write_neither_broker_nor_card_policy() {
        let root = tmp_root();
        let bad = Oidc {
            card_hosts: vec!["*.school.ac.th".into()],
            ..oidc("https://sso.school.ac.th")
        };
        let school = school_with(Some(bad));
        let r = FakeRunner::new();
        let out = run_bundle(
            root.path(),
            &school,
            &sso_group(),
            &r,
            &mut SysState::default(),
        );
        assert!(!out[0].ok);
        assert!(!broker(root.path()).exists());
        assert!(!card_policy(root.path()).exists());
    }

    #[test]
    fn card_policy_follows_sso() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let school = school_with(Some(oidc("https://sso.school.ac.th")));
        let out = run_bundle(root.path(), &school, &sso_group(), &r, &mut sys);
        assert_eq!(out, vec![ok(ITEM)]);
        let f = card_policy(root.path());
        assert!(fs::read_to_string(&f).unwrap().contains("sso.school.ac.th"));
        assert_eq!(mode(&f), 0o644);
        assert_eq!(mode(f.parent().unwrap()), 0o755);

        let mut local = config();
        local.login_methods = vec![LoginMethod::Local];
        run_bundle(root.path(), &school_with(None), &local, &r, &mut sys);
        assert!(!f.exists());
    }

    fn card_settings(root: &Path) -> PathBuf {
        paths(root)
            .public_dir
            .join(LOGIN_CARD_DIR)
            .join(LOGIN_CARD_FILE)
    }

    fn with_hint(hint: &str) -> Oidc {
        Oidc {
            idp_hint: Some(hint.into()),
            ..oidc("https://sso.school.ac.th")
        }
    }

    #[test]
    fn card_settings_carry_the_idp_hint() {
        assert_eq!(render_login_card(&oidc("https://sso.school.ac.th")), None);
        let text = render_login_card(&with_hint("school-sso")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v, serde_json::json!({"idp_hint": "school-sso"}));
        assert_eq!(render_login_card(&with_hint("a&b")), None);
        // Not in the directory Chrome reads its policies from.
        assert_ne!(
            Path::new(LOGIN_CARD_DIR).join(LOGIN_CARD_FILE).parent(),
            Some(Path::new(LOGIN_BROWSER_DIR))
        );
    }

    #[test]
    fn card_settings_follow_the_hint_and_sso() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let f = card_settings(root.path());
        // SSO without a hint: the card policy, no card settings.
        let plain = school_with(Some(oidc("https://sso.school.ac.th")));
        assert_eq!(
            run_bundle(root.path(), &plain, &sso_group(), &r, &mut sys),
            vec![ok(ITEM)]
        );
        assert!(card_policy(root.path()).exists());
        assert!(!f.exists());

        let hinted = school_with(Some(with_hint("school-sso")));
        assert_eq!(
            run_bundle(root.path(), &hinted, &sso_group(), &r, &mut sys),
            vec![ok(ITEM)]
        );
        let v: serde_json::Value = serde_json::from_slice(&fs::read(&f).unwrap()).unwrap();
        assert_eq!(v["idp_hint"], "school-sso");
        assert_eq!(mode(&f), 0o644);
        assert_eq!(mode(f.parent().unwrap()), 0o755);

        // The hint taken out again: the file goes, the card policy stays.
        run_bundle(root.path(), &plain, &sso_group(), &r, &mut sys);
        assert!(!f.exists());
        assert!(card_policy(root.path()).exists());

        // No SSO on this Config: neither file, whatever the school's provider says.
        run_bundle(root.path(), &hinted, &sso_group(), &r, &mut sys);
        assert!(f.exists());
        let mut local = config();
        local.login_methods = vec![LoginMethod::Local];
        run_bundle(root.path(), &hinted, &local, &r, &mut sys);
        assert!(!f.exists());
        assert!(!card_policy(root.path()).exists());
    }

    #[test]
    fn invalid_idp_hint_writes_neither_broker_nor_card_files() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let school = school_with(Some(with_hint("a b")));
        let out = run_bundle(
            root.path(),
            &school,
            &sso_group(),
            &r,
            &mut SysState::default(),
        );
        assert!(!out[0].ok);
        assert!(
            out[0].detail.as_deref().unwrap_or("").contains("idp_hint"),
            "{out:?}"
        );
        assert!(!broker(root.path()).exists());
        assert!(!card_policy(root.path()).exists());
        assert!(!card_settings(root.path()).exists());
    }

    #[test]
    fn seed_idp_hint_reaches_the_card() {
        let root = tmp_root();
        put_decl_src(root.path(), "[authd]\nname = OIDC\n");
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let p = paths(root.path());
        let out = run_seed(
            &seed(&format!("{SEED_OIDC}idp_hint = \"school-sso\"\n")),
            &mut Env {
                paths: &p,
                runner: &r,
                sys: &mut sys,
            },
        );
        assert_eq!(out, vec![ok(ITEM)]);
        let v: serde_json::Value =
            serde_json::from_slice(&fs::read(card_settings(root.path())).unwrap()).unwrap();
        assert_eq!(v["idp_hint"], "school-sso");
    }

    #[test]
    fn broker_decl_removed_without_sso() {
        let root = tmp_root();
        let d = decl(root.path());
        fs::create_dir_all(d.parent().unwrap()).unwrap();
        fs::write(&d, "x").unwrap();
        fs::write(d.parent().unwrap().join("other.conf"), "y").unwrap();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let mut local = config();
        local.login_methods = vec![LoginMethod::Local];
        let out = run_bundle(root.path(), &school_with(None), &local, &r, &mut sys);
        assert_eq!(out, vec![ok(ITEM)]);
        assert!(!d.exists());
        assert!(d.parent().unwrap().join("other.conf").exists());
        assert_eq!(r.calls(), vec![RESTART]);
        run_bundle(root.path(), &school_with(None), &local, &r, &mut sys);
        assert_eq!(r.calls(), vec![RESTART]);
    }

    #[test]
    fn broker_decl_absent_when_oidc_invalid() {
        let root = tmp_root();
        put_decl_src(root.path(), "x");
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let bad = school_with(Some(oidc("https://sso.school.ac.th\n[users]")));
        let out = run_bundle(root.path(), &bad, &sso_group(), &r, &mut sys);
        assert_eq!(out.len(), 1);
        assert!(!out[0].ok);
        assert!(!decl(root.path()).exists());
        assert!(!broker(root.path()).exists());
    }

    #[test]
    fn broker_decl_source_missing_reports() {
        let root = tmp_root();
        let r = FakeRunner::new();
        let mut sys = SysState::default();
        let school = school_with(Some(oidc("https://sso.school.ac.th")));
        let out = run_bundle_no_src(root.path(), &school, &sso_group(), &r, &mut sys);
        assert_eq!(out.len(), 1);
        assert!(!out[0].ok);
        assert!(format!("{out:?}").contains(BROKER_DECL_SRC), "{out:?}");
        assert!(!decl(root.path()).exists());
        assert!(broker(root.path()).exists(), "drop-in is still written");
    }

    #[test]
    fn guest_always_in_bundle_policy() {
        let mut g = config();
        g.login_methods = vec![LoginMethod::Sso];
        let p = policy_from_bundle(&School::default(), &g, None);
        assert_eq!(p.methods, ["guest", "sso"]);
        g.login_methods = vec![];
        let p = policy_from_bundle(&School::default(), &g, None);
        assert_eq!(p.methods, ["guest"]);
        g.login_methods = vec![LoginMethod::Guest, LoginMethod::Guest];
        let p = policy_from_bundle(&School::default(), &g, None);
        assert_eq!(p.methods, ["guest"]);
    }

    #[test]
    fn guest_always_in_seed_policy() {
        assert_eq!(policy_from_seed(&seed(SEED_PLAIN)).methods, ["guest"]);
        assert_eq!(policy_from_seed(&seed(SEED_OIDC)).methods, ["guest", "sso"]);
    }

    #[test]
    fn locked_denies_guest() {
        let lock = Lock {
            message: "locked".into(),
        };
        let p = policy_from_bundle(&School::default(), &config(), Some(&lock));
        assert!(p.methods.iter().any(|m| m == "guest"));
        assert_eq!(managed(GDM, &p, "guest"), Decision::Deny(DENY_LOCKED));
    }

    const IT_HASH: &str = "$y$j9T$saltsaltsaltsalt$hashhashhashhashhashhashhashhash";

    fn it_acct(h: &str) -> mastersos_bundle::ItAccount {
        mastersos_bundle::ItAccount {
            password_hash: h.into(),
        }
    }

    #[test]
    fn itadmin_allowed_without_local_method() {
        let mut p = pol(&["guest"]);
        p.it_account = true;
        p.it_account_uid = Some(1001);
        assert_eq!(
            decide("gdm-password", true, Some(&p), "itadmin", Some(1001)),
            Decision::Allow
        );
        // Not limited by the method list nor by the domain list; other local accounts still are.
        p.allowed_domains = vec!["school.ac.th".into()];
        assert_eq!(managed(GDM, &p, "itadmin"), Decision::Allow);
        assert_eq!(managed("login", &p, "itadmin"), Decision::Allow);
        assert_eq!(managed(GDM, &p, "alice"), Decision::Deny(DENY_LOCAL));
        // Exact name only.
        assert_eq!(managed(GDM, &p, "ITADMIN"), Decision::Deny(DENY_LOCAL));
        p.it_account = false;
        assert_eq!(
            decide("gdm-password", true, Some(&p), "itadmin", Some(1001)),
            Decision::Deny(DENY_LOCAL)
        );
    }

    #[test]
    fn itadmin_denied_when_locked() {
        let mut p = pol(&["guest", "local"]);
        p.it_account = true;
        p.it_account_uid = Some(1001);
        p.locked = true;
        assert_eq!(managed(GDM, &p, "itadmin"), Decision::Deny(DENY_LOCKED));
        // The fail-closed policy (settings too large) keeps the flag but is locked.
        let mut q = pol(&["guest"]);
        q.it_account = true;
        q.it_account_uid = Some(1001);
        assert_eq!(
            managed(GDM, &fail_closed(&q), "itadmin"),
            Decision::Deny(DENY_LOCKED)
        );
    }

    /// An `itadmin` whose uid is not the one the agent recorded follows the local-account rules.
    #[test]
    fn foreign_itadmin_uid_follows_local_rules() {
        let mut p = pol(&["guest"]);
        p.it_account = true;
        p.it_account_uid = Some(1001);
        assert_eq!(
            decide(GDM, true, Some(&p), "itadmin", Some(1005)),
            Decision::Deny(DENY_LOCAL)
        );
        // Unresolved uid, or nothing recorded yet: no exception either.
        assert_eq!(
            decide(GDM, true, Some(&p), "itadmin", None),
            Decision::Deny(DENY_LOCAL)
        );
        p.it_account_uid = None;
        assert_eq!(managed(GDM, &p, "itadmin"), Decision::Deny(DENY_LOCAL));
        // With `local` allowed the foreign one gets in as a local account, nothing more.
        let mut q = pol(&["guest", "local"]);
        q.it_account = true;
        q.it_account_uid = Some(1001);
        assert_eq!(
            decide(GDM, true, Some(&q), "itadmin", Some(1005)),
            Decision::Allow
        );
        q.locked = true;
        assert_eq!(
            decide(GDM, true, Some(&q), "itadmin", Some(1005)),
            Decision::Deny(DENY_LOCKED)
        );
    }

    /// The written policy carries the recorded uid; the seed opens no IT exception after a bundle was applied.
    #[test]
    fn policies_carry_owner_uid_and_seed_is_gated() {
        let root = tmp_root();
        let p = paths(root.path());
        let r = FakeRunner::new();
        let mut s = seed(SEED_PLAIN);
        s.it_account = Some(it_acct(IT_HASH));
        let mut sys = SysState {
            it_account_uid: Some(1002),
            ..SysState::default()
        };
        {
            let env = Env {
                paths: &p,
                runner: &r,
                sys: &mut sys,
            };
            let sp = seed_policy(&s, &env);
            assert!(sp.it_account);
            assert_eq!(sp.it_account_uid, Some(1002));
        }
        sys.bundle_applied = true;
        {
            let env = Env {
                paths: &p,
                runner: &r,
                sys: &mut sys,
            };
            let sp = seed_policy(&s, &env);
            assert!(!sp.it_account);
            assert_eq!(sp.it_account_uid, None);
        }
        // Bundle policy: uid only when the IT account is wanted.
        let mut c = config();
        c.it_account = Some(it_acct(IT_HASH));
        let flag = AtomicBool::new(false);
        let dir = tempfile::tempdir().unwrap();
        let g = group();
        let school = School::default();
        let seed = crate::system::tests::test_seed();
        let ctx = ApplyContext {
            seed: &seed,
            school: &school,
            group: &g,
            config: &c,
            lock: None,
            bundle_dir: dir.path(),
            phase: Phase::Full,
            superseded: &flag,
        };
        let env = Env {
            paths: &p,
            runner: &r,
            sys: &mut sys,
        };
        assert_eq!(bundle_policy(&ctx, &env).it_account_uid, Some(1002));
        // In a round whose state could not be read, the installed policy's uid is kept.
        let mut installed = bundle_policy(&ctx, &env);
        installed.it_account_uid = Some(1003);
        write_policy(&p, &installed).unwrap();
        let mut lost = SysState {
            load_failed: true,
            ..SysState::default()
        };
        let env = Env {
            paths: &p,
            runner: &r,
            sys: &mut lost,
        };
        assert_eq!(bundle_policy(&ctx, &env).it_account_uid, Some(1003));
    }

    #[test]
    fn set_it_account_uid_refreshes_installed_policy() {
        let root = tmp_root();
        let p = paths(root.path());
        // No policy: nothing to do.
        set_it_account_uid(&p, 1002).unwrap();
        let mut pl = pol(&["guest"]);
        write_policy(&p, &pl).unwrap();
        set_it_account_uid(&p, 1002).unwrap();
        assert_eq!(read_policy(root.path()).it_account_uid, None);
        pl.it_account = true;
        write_policy(&p, &pl).unwrap();
        set_it_account_uid(&p, 1002).unwrap();
        assert_eq!(read_policy(root.path()).it_account_uid, Some(1002));
    }

    #[test]
    fn old_policy_file_without_field() {
        let p: LoginPolicy =
            serde_json::from_slice(br#"{"methods":["guest","local"],"locked":false}"#).unwrap();
        assert!(!p.it_account);
        assert_eq!(managed(GDM, &p, "itadmin"), Decision::Allow);
        let p: LoginPolicy =
            serde_json::from_slice(br#"{"methods":["guest"],"locked":false}"#).unwrap();
        assert_eq!(managed(GDM, &p, "itadmin"), Decision::Deny(DENY_LOCAL));
    }

    #[test]
    fn policy_from_seed_and_bundle_carry_it_account() {
        let mut s = seed(SEED_PLAIN);
        assert!(!policy_from_seed(&s).it_account);
        s.it_account = Some(it_acct(IT_HASH));
        let p = policy_from_seed(&s);
        assert!(p.it_account);
        assert_eq!(p.methods, ["guest"]);
        // A hash the agent will not use does not open the account either.
        s.it_account = Some(it_acct("not-a-hash"));
        assert!(!policy_from_seed(&s).it_account);

        let mut c = config();
        assert!(!policy_from_bundle(&School::default(), &c, None).it_account);
        c.it_account = Some(it_acct(IT_HASH));
        let p = policy_from_bundle(&School::default(), &c, None);
        assert!(p.it_account);
        // Written to the policy file and read back.
        let back: LoginPolicy = serde_json::from_slice(&policy_json(&p).unwrap()).unwrap();
        assert!(back.it_account);
        assert!(!String::from_utf8(policy_json(&p).unwrap())
            .unwrap()
            .contains("j9T"));
    }

    #[test]
    fn broker_dir_is_a_write_root() {
        assert!(super::super::WRITE_ROOTS.contains(&"/etc/authd/brokers.d"));
        assert_eq!(format!("/{BROKER_DECL_DIR}"), "/etc/authd/brokers.d");
        assert!(super::super::WRITE_ROOTS.contains(&"/etc/authd/oidc/broker.conf.d"));
        assert_eq!(format!("/{BROKER_DIR}"), "/etc/authd/oidc/broker.conf.d");
        assert!(super::super::WRITE_ROOTS.contains(&"/etc/authd/oidc"));
        assert_eq!(format!("/{DOMAINS_DIR}"), "/etc/authd/oidc");
    }

    /// Patch 0006 reads `mastersos-allowed-domains` beside `--config /etc/authd/oidc/broker.conf` (authd-oidc.service), never
    /// anything in broker.conf.d: the agent writes it there and nowhere else.
    #[test]
    fn domain_file_is_where_the_patched_broker_reads_it() {
        let patch = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../image/patches/authd-oidc/0006-allowed-domains.patch"
        ))
        .unwrap();
        assert!(
            patch.contains(&format!("+const mastersosDomainsFile = \"{DOMAINS_FILE}\"")),
            "the patch reads another file name"
        );
        assert!(
            patch.contains(&format!(
                "+const mastersosRequiredMarker = \"{DOMAINS_MARKER}\""
            )),
            "the patch looks for another marker"
        );
        let unit = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../image/mkosi.extra/usr/lib/systemd/system/authd-oidc.service"
        ))
        .unwrap();
        assert!(unit.lines().any(|l| l
            == format!("ExecStart=/usr/libexec/authd-oidc --config /{DOMAINS_DIR}/broker.conf")));
        assert!(!DOMAINS_DIR.starts_with(BROKER_DIR));
    }
}
