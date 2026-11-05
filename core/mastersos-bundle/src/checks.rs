//! 设置项的格式规则：纯函数，发布前 lint 与 agent 的各个 Step 共用。
//!
//! The messages name the value at fault, **except secrets** (`psk`, `password`, `client_key`,
//! `client_key_password`: only what is wrong with them, never their content).
//! 刻意不并进 `Manifest::validate`：机器开机复验本地的包时不能因新规则丢整份设置。

use crate::{EapMethod, Oidc, WebApp, Wifi};

pub(crate) fn has_control(s: &str) -> bool {
    s.chars().any(char::is_control)
}

/// The longest `identity`, `anonymous_identity`, `password`, `server_domain` or
/// `client_key_password` accepted, in bytes.
pub const MAX_WIFI_TEXT_LEN: usize = 256;
/// The longest PEM text (`ca_cert`, `client_cert`, `client_key`) accepted, in bytes: a few
/// certificates fit, and the seed (at most 64 KiB) still has room for several networks.
pub const MAX_WIFI_PEM_LEN: usize = 16 * 1024;

/// One network ([`Wifi`]): `ssid` 1-32 bytes; `psk` (when written) 8-63 printable ASCII or 64 hex
/// digits; the kind's fields fit together (design 2026-10-29 §4.1): `open` only `true` and alone,
/// `psk` and `eap` exclusive, `wpa3_only` (either value) only with `psk`, 802.1X fields only with
/// `eap`, and an `eap` network checks its server (`server_domain` or `ca_cert`) unless
/// `check_server = false` — except `pwd`, which uses no certificates and so takes none of
/// `server_domain`, `ca_cert` and `check_server`.
///
/// The message is one English sentence naming the network and the field; it never repeats a value
/// other than the SSID (secrets above all).
pub fn wifi(w: &Wifi) -> Result<(), String> {
    let n = &w.ssid;
    if n.is_empty() || n.len() > 32 {
        return Err(format!("Wi-Fi name {n:?} must be 1-32 bytes long"));
    }
    let fail = |what: &str| Err(format!("Wi-Fi {n:?}: {what}"));
    match w.open {
        Some(false) => {
            return fail("open can only be true; leave it out for a network with a password")
        }
        Some(true) if w.psk.is_some() || w.eap.is_some() => {
            return fail("an open network (open = true) cannot have psk or eap; remove one")
        }
        _ => {}
    }
    if w.psk.is_some() && w.eap.is_some() {
        return fail("write psk (a password network) or eap (an enterprise network), not both");
    }
    if let Some(p) = &w.psk {
        let printable = p.bytes().all(|b| (0x20..=0x7e).contains(&b));
        let ok = if p.len() == 64 {
            p.bytes().all(|b| b.is_ascii_hexdigit())
        } else {
            (8..=63).contains(&p.len()) && printable
        };
        if !ok {
            return Err(format!(
                "The password of Wi-Fi {n:?} must be 8-63 printable ASCII characters or 64 hex digits"
            ));
        }
    }
    if w.wpa3_only.is_some() && w.psk.is_none() {
        return fail("wpa3_only needs psk (it is for WPA3 password networks only)");
    }
    let Some(eap) = w.eap else {
        if w.has_8021x_fields() {
            return fail(
                "identity, password, phase2, anonymous_identity, server_domain, ca_cert, \
                 check_server and client_* are only for enterprise networks; add eap or remove them",
            );
        }
        return Ok(());
    };
    let m = eap.as_str();
    match w.identity.as_deref() {
        None | Some("") => {
            return fail(&format!("eap = \"{m}\" needs identity (the account name)"))
        }
        Some(_) => {}
    }
    let tls = eap == EapMethod::Tls;
    if tls && w.password.is_some() {
        return fail("eap = \"tls\" signs in with client_cert and client_key; remove password");
    }
    if !tls && w.password.as_deref().is_none_or(str::is_empty) {
        return fail(&format!(
            "eap = \"{m}\" needs password (the account password)"
        ));
    }
    if w.phase2.is_some() && !matches!(eap, EapMethod::Peap | EapMethod::Ttls) {
        return fail(&format!(
            "phase2 is only for eap = \"peap\" or \"ttls\", not \"{m}\""
        ));
    }
    if tls && (w.client_cert.is_none() || w.client_key.is_none()) {
        return fail("eap = \"tls\" needs client_cert and client_key");
    }
    if !tls
        && (w.client_cert.is_some() || w.client_key.is_some() || w.client_key_password.is_some())
    {
        return fail(&format!(
            "client_cert, client_key and client_key_password are only for eap = \"tls\", not \"{m}\""
        ));
    }
    // Text fields go into the NetworkManager connection file: one line each.
    for (field, v) in [
        ("identity", &w.identity),
        ("anonymous_identity", &w.anonymous_identity),
        ("password", &w.password),
        ("client_key_password", &w.client_key_password),
    ] {
        if let Some(v) = v {
            if v.len() > MAX_WIFI_TEXT_LEN || has_control(v) {
                return fail(&format!(
                    "{field} must be at most {MAX_WIFI_TEXT_LEN} bytes without control characters"
                ));
            }
        }
    }
    if eap == EapMethod::Pwd {
        if w.server_domain.is_some() || w.ca_cert.is_some() || w.check_server.is_some() {
            return fail(
                "eap = \"pwd\" uses no certificates (the password proves both sides); remove \
                 server_domain, ca_cert and check_server",
            );
        }
        return Ok(());
    }
    if let Some(d) = &w.server_domain {
        let ok = !d.is_empty()
            && d.len() <= MAX_WIFI_TEXT_LEN
            && d.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            && !d.starts_with('.')
            && !d.ends_with('.');
        if !ok {
            return fail(
                "server_domain must be a domain name such as radius.school.ac.th (letters, digits, . and -)",
            );
        }
    }
    for (field, v, marker) in [
        ("ca_cert", &w.ca_cert, "-----BEGIN CERTIFICATE-----"),
        ("client_cert", &w.client_cert, "-----BEGIN CERTIFICATE-----"),
        ("client_key", &w.client_key, "PRIVATE KEY-----"),
    ] {
        if let Some(v) = v {
            let ok = v.len() <= MAX_WIFI_PEM_LEN
                && v.trim_start().starts_with("-----BEGIN ")
                && v.contains(marker)
                && v.bytes()
                    .all(|b| b == b'\n' || b == b'\r' || (0x20..=0x7e).contains(&b));
            if !ok {
                return fail(&format!(
                    "{field} must be PEM text (-----BEGIN …) of at most {MAX_WIFI_PEM_LEN} bytes"
                ));
            }
        }
    }
    let checked = w.server_domain.is_some() || w.ca_cert.is_some();
    match w.check_server {
        Some(false) if checked => fail(
            "check_server = false contradicts server_domain or ca_cert; remove check_server to check the server",
        ),
        Some(false) => Ok(()),
        _ if !checked => fail(
            "an enterprise network must check its RADIUS server: add server_domain or ca_cert, \
             or write check_server = false to connect without checking (not recommended)",
        ),
        _ => Ok(()),
    }
}

/// `scheme://` 之后到第一个 `/`、`?`、`#` 之前是 authority；里面有 `@` 就是带了账号口令（userinfo）。
fn has_userinfo(u: &str) -> bool {
    let rest = u.split_once("://").map_or("", |(_, r)| r);
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    auth.contains('@')
}

/// 地址里不许带账号口令：cupsd 报回的 device-uri 不带口令，比不上就每轮重加，口令还会出现在 lpadmin 的命令行里。
pub fn printer_uri(u: &str) -> Result<(), String> {
    if ["ipp://", "ipps://", "http://", "https://"]
        .iter()
        .any(|p| u.starts_with(p))
        && !u.chars().any(|c| c.is_control() || c.is_whitespace())
        && !has_userinfo(u)
    {
        Ok(())
    } else {
        Err(format!(
            "Printer address {u:?} must start with ipp://, ipps://, http:// or https://, contain no whitespace, and carry no credentials (user@)"
        ))
    }
}

/// 同 [`printer_uri`]：扫描仪的地址会写进所有人都读得到的 sane-airscan 配置，不许带账号口令。
pub fn scanner_uri(u: &str) -> Result<(), String> {
    if (u.starts_with("http://") || u.starts_with("https://"))
        && !u.chars().any(|c| c.is_control() || c.is_whitespace())
        && !has_userinfo(u)
    {
        Ok(())
    } else {
        Err(format!(
            "Scanner address {u:?} must start with http:// or https://, contain no whitespace, and carry no credentials (user@)"
        ))
    }
}

/// CUPS 队列名的最大字节数（cupsd 与 lpadmin 的 `validate_name`：< 128）。
pub const PRINTER_QUEUE_MAX_BYTES: usize = 127;

/// 打印机名称对应的 CUPS 队列名：空白、控制字符与 `/ \ ? ' " # @` 换成 `_`（CUPS 拒收前几个；`@` 在 `lpadmin -p` 里
/// 表示「另一台服务器」），再按字符边界截到 127 字节以内。CUPS 的队列名不分大小写（ASCII），比较时用
/// `eq_ignore_ascii_case`。
pub fn printer_queue(name: &str) -> String {
    let mut q = String::with_capacity(name.len());
    for c in name.chars() {
        let c = if c.is_whitespace()
            || c.is_control()
            || matches!(c, '/' | '\\' | '?' | '\'' | '"' | '#' | '@')
        {
            '_'
        } else {
            c
        };
        if q.len() + c.len_utf8() > PRINTER_QUEUE_MAX_BYTES {
            break;
        }
        q.push(c);
    }
    q
}

pub fn device_name(n: &str) -> Result<(), String> {
    if n.is_empty() || n.chars().count() > 64 || has_control(n) {
        Err(format!(
            "Device name {n:?} must be 1-64 characters with no control characters"
        ))
    } else {
        Ok(())
    }
}

pub fn web_app(a: &WebApp) -> Result<(), String> {
    let u = &a.url;
    if !(u.starts_with("http://") || u.starts_with("https://"))
        || u.chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '`' | '\\'))
    {
        return Err(format!(
            "Web app {:?} has address {u:?}, which must start with http:// or https:// and contain no whitespace or any of \" ' ` \\",
            a.name
        ));
    }
    if a.name.is_empty() || has_control(&a.name) {
        return Err(format!(
            "Web app name {:?} must be non-empty with no control characters",
            a.name
        ));
    }
    Ok(())
}

/// `^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+){2,}$`
pub fn flatpak_id(id: &str) -> Result<(), String> {
    let seg_ok = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    };
    let parts: Vec<&str> = id.split('.').collect();
    let ok = parts.len() >= 3
        && parts[0].starts_with(|c: char| c.is_ascii_alphabetic())
        && parts.iter().all(|p| seg_ok(p));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "Flatpak app id {id:?} is invalid: expected the form org.example.App (at least three segments of letters, digits, _ and -)"
        ))
    }
}

/// `admin_users` 与 `allowed_domains` 每项最多这么多字节。
pub const MAX_ENTRY_LEN: usize = 254;
/// `admin_users` 最多这么多个（发布前 lint）。与 [`MAX_ALLOWED_DOMAINS`]、[`MAX_ENTRY_LEN`] 一起保证
/// 机器上的登录策略文件远小于 `pam-check` 读的上限（agent 的 `login::MAX_POLICY_BYTES`，有测试核对）。
pub const MAX_ADMIN_USERS: usize = 200;
/// `allowed_domains` 最多这么多个（发布前 lint）。
pub const MAX_ALLOWED_DOMAINS: usize = 200;

fn all_of(s: &str, f: impl Fn(u8) -> bool) -> bool {
    !s.is_empty() && s.bytes().all(f)
}

/// 转小写后 `^[a-z0-9._%+-]+@[a-z0-9.-]+$`，最多 [`MAX_ENTRY_LEN`] 字节；`@` 之前不以 `%` 或 `+` 开头
/// （sudoers 的词法把开头是 `%` 的引号串当组、`+` 当网络组，这样的名字写进 sudoers 就不再是这个用户）。
pub fn admin_user(u: &str) -> Result<(), String> {
    let l = u.to_ascii_lowercase();
    let ok = l.len() <= MAX_ENTRY_LEN
        && match l.split_once('@') {
            Some((local, host)) => {
                !local.starts_with(['%', '+'])
                    && all_of(local, |b| {
                        b.is_ascii_lowercase()
                            || b.is_ascii_digit()
                            || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
                    })
                    && all_of(host, |b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-')
                    })
            }
            None => false,
        };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "Admin account {u:?} must look like name@school.ac.th (letters, digits and . _ % + -, not starting with % or +, at most {MAX_ENTRY_LEN} bytes)"
        ))
    }
}

/// `^[a-z0-9.-]+$`：小写，不带 `@`，最多 [`MAX_ENTRY_LEN`] 字节。
pub fn allowed_domain(d: &str) -> Result<(), String> {
    if d.len() <= MAX_ENTRY_LEN
        && all_of(d, |b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-')
        })
    {
        Ok(())
    } else {
        Err(format!(
            "Allowed domain {d:?} must be lowercase letters, digits, . and - without @, at most {MAX_ENTRY_LEN} bytes"
        ))
    }
}

/// School cache address: `http://` or `https://` plus a host (optional port) and an optional directory path.
/// Other schemes (`file://`...), query strings, fragments, credentials (`user:pw@`), whitespace and control
/// characters are rejected; so are `%` (a systemd specifier) and `@` (a transfer match character), so the
/// address cannot be expanded into something else once written into a transfer under `/etc/sysupdate.d/`.
/// The cache itself is not trusted (updates are signed); this only keeps the spelling of the address from
/// changing the structure of the transfer file.
pub fn update_mirror(url: &str) -> Result<(), String> {
    let bad = |why: &str| {
        Err(format!(
            "update_mirror {url:?} {why} (expected http:// or https:// plus host and directory, e.g. https://cache.school.ac.th/mastersos)"
        ))
    };
    let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    else {
        return bad("is not http:// or https://");
    };
    if url.len() > MAX_ENTRY_LEN {
        return bad("is too long");
    }
    if !url.bytes().all(|b| b.is_ascii_graphic()) {
        return bad("contains whitespace, control or non-ASCII characters");
    }
    if url
        .bytes()
        .any(|b| matches!(b, b'?' | b'#' | b'@' | b'%' | b'\\'))
    {
        return bad("contains ? # @ % or a backslash: no query, fragment or credentials");
    }
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (name, port) = match host.rsplit_once(':') {
        Some((n, p)) if !host.ends_with(']') => (n, Some(p)),
        _ => (host, None),
    };
    if name.is_empty() || name.starts_with('.') || name.contains("..") {
        return bad("has an empty or malformed host");
    }
    if port.is_some_and(|p| p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit())) {
        return bad("has a bad port");
    }
    if path.split('/').any(|seg| seg == "." || seg == "..") {
        return bad("has . or .. in the path");
    }
    Ok(())
}

/// `[school].escrow_recipients` has at most this many entries.
pub const MAX_ESCROW_RECIPIENTS: usize = 8;

/// The school's escrow recipients (rulings 10, 27): at most [`MAX_ESCROW_RECIPIENTS`] age X25519
/// recipients (`age1…`), each written in its canonical (lowercase) form and none twice — a
/// machine seals its LUKS recovery key to every one of them, and compares the list to decide
/// whether to escrow again, so one recipient must have one spelling.
pub fn escrow_recipients(list: &[String]) -> Result<(), String> {
    if list.len() > MAX_ESCROW_RECIPIENTS {
        return Err(format!(
            "escrow_recipients has {} entries, at most {MAX_ESCROW_RECIPIENTS}",
            list.len()
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for r in list {
        let parsed = r.parse::<age::x25519::Recipient>().map_err(|e| {
            format!("escrow recipient {r:?} is not an age X25519 recipient (age1…): {e}")
        })?;
        if parsed.to_string() != *r {
            return Err(format!(
                "escrow recipient {r:?} is not in its canonical form {:?}",
                parsed.to_string()
            ));
        }
        if !seen.insert(r.as_str()) {
            return Err(format!("escrow recipient {r:?} is listed more than once"));
        }
    }
    Ok(())
}

/// `^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$`
pub fn timezone(tz: &str) -> Result<(), String> {
    let ok = tz.split('/').all(|s| {
        all_of(s, |b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'-')
        })
    });
    if ok {
        Ok(())
    } else {
        Err(format!("Time zone {tz:?} must look like Asia/Bangkok"))
    }
}

/// `^[a-z]{2,3}_[A-Z]{2}\.UTF-8$`
pub fn locale(l: &str) -> Result<(), String> {
    let ok = l.strip_suffix(".UTF-8").is_some_and(|b| {
        b.split_once('_').is_some_and(|(lang, region)| {
            (2..=3).contains(&lang.len())
                && lang.bytes().all(|c| c.is_ascii_lowercase())
                && region.len() == 2
                && region.bytes().all(|c| c.is_ascii_uppercase())
        })
    });
    if ok {
        Ok(())
    } else {
        Err(format!("Locale {l:?} must look like th_TH.UTF-8"))
    }
}

/// At most this many `[school.oidc] card_hosts`: each widens what the sign-in page may reach.
pub const MAX_CARD_HOSTS: usize = 20;
/// The longest `[school.oidc] client_secret`, in bytes.
pub const MAX_CLIENT_SECRET_BYTES: usize = 512;
/// The longest `[school.oidc] idp_hint`, in bytes.
pub const MAX_IDP_HINT_BYTES: usize = 64;

/// A `[school.oidc] idp_hint`: 1 to [`MAX_IDP_HINT_BYTES`] ASCII letters, digits, `_` or `-`. It goes into the
/// authorization URL's query; the login screen's extension checks the same rule before adding it.
pub fn idp_hint(h: &str) -> Result<(), String> {
    let ok = !h.is_empty()
        && h.len() <= MAX_IDP_HINT_BYTES
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "OIDC idp_hint {h:?} must be 1 to {MAX_IDP_HINT_BYTES} characters, each an ASCII letter, digit, _ or -"
        ))
    }
}

/// One DNS name: at most 253 bytes of 1-63 byte labels of letters, digits or hyphens, no label
/// starting or ending with a hyphen.
pub fn is_dns_name(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// One `[school.oidc] card_hosts` entry: an exact hostname, lowercase, with at least two labels,
/// and not an IP address. No scheme, port, path or wildcard: the entry becomes a Chrome URL filter.
pub fn card_host(h: &str) -> Result<(), String> {
    let lowercase = !h.bytes().any(|b| b.is_ascii_uppercase());
    let top = h.rsplit('.').next().unwrap_or("");
    if is_dns_name(h) && lowercase && h.contains('.') && !top.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(format!(
            "OIDC card_hosts entry {h:?} must be a lowercase hostname such as cdn.school.ac.th, with no scheme, port, path or wildcard"
        ))
    }
}

/// 写进 authd broker 配置（INI）的 `issuer` 与 `client_id`：非空、不含空白与控制字符（换行会注入
/// 别的键，例如把 `allowed_users` 改成 `OWNER`），不含 INI 的注释符 `#` `;` 与引号、反斜杠；
/// `issuer` 以 `http://` 或 `https://` 开头。`client_secret` follows the same rule, is printable
/// ASCII without `%` (the INI parser's interpolation) and is never echoed in an error;
/// `card_hosts` entries follow [`card_host`], none twice.
pub fn oidc(o: &Oidc) -> Result<(), String> {
    let clean = |v: &str| {
        !v.is_empty()
            && !v.chars().any(|c| {
                c.is_whitespace()
                    || c.is_control()
                    || matches!(c, '#' | ';' | '"' | '\'' | '`' | '\\')
            })
    };
    if !(o.issuer.starts_with("https://") || o.issuer.starts_with("http://")) || !clean(&o.issuer) {
        return Err(format!(
            "OIDC issuer {:?} must start with http:// or https:// and contain no whitespace, control characters or any of # ; \" ' ` \\",
            o.issuer
        ));
    }
    if !clean(&o.client_id) {
        return Err(format!(
            "OIDC client_id {:?} must be non-empty and contain no whitespace, control characters or any of # ; \" ' ` \\",
            o.client_id
        ));
    }
    if let Some(s) = &o.client_secret {
        let printable = s.bytes().all(|b| b.is_ascii_graphic() && b != b'%');
        if !clean(s) || !printable || s.len() > MAX_CLIENT_SECRET_BYTES {
            return Err(format!(
                "OIDC client_secret must be 1 to {MAX_CLIENT_SECRET_BYTES} printable ASCII characters and contain no spaces or any of % # ; \" ' ` \\"
            ));
        }
    }
    if o.card_hosts.len() > MAX_CARD_HOSTS {
        return Err(format!(
            "There are {} OIDC card_hosts, at most {MAX_CARD_HOSTS} are allowed",
            o.card_hosts.len()
        ));
    }
    for (i, h) in o.card_hosts.iter().enumerate() {
        card_host(h)?;
        if o.card_hosts[..i].contains(h) {
            return Err(format!("OIDC card_hosts lists {h:?} twice"));
        }
    }
    if let Some(h) = &o.idp_hint {
        idp_hint(h)?;
    }
    Ok(())
}

/// ≤ 500 字符。
pub fn lock_message(m: &str) -> Result<(), String> {
    let n = m.chars().count();
    if n > 500 {
        Err(format!(
            "The lock screen message has {n} characters, at most 500 are allowed"
        ))
    } else {
        Ok(())
    }
}

/// Chrome 暂停更新最多到发布日之后这么多天（含）。
pub const MAX_CHROME_PAUSE_DAYS: i64 = 14;
/// 更新时段至少这么多分钟：`mastersos-chrome.timer` 每小时一轮、落在整点后 20 分钟内（RandomizedDelaySec），
/// 太短的时段可能一次都碰不上（复审 I1）。
pub const MIN_CHROME_WINDOW_MINUTES: u16 = 120;

/// `HH:MM-HH:MM`（本机时区，24 小时制，两位数）→ 两端距午夜的分钟数 `(开始, 结束)`。两端相同报错
/// （是「全天」还是「从不」说不清）；开始晚于结束表示跨午夜。时段是 [开始, 结束)，见 [`chrome_in_window`]。
pub fn chrome_window(s: &str) -> Result<(u16, u16), String> {
    let hm = |t: &str| -> Option<u16> {
        let (h, m) = t.split_once(':')?;
        if h.len() != 2 || m.len() != 2 || !(h.bytes().chain(m.bytes())).all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let (h, m): (u16, u16) = (h.parse().ok()?, m.parse().ok()?);
        (h < 24 && m < 60).then_some(h * 60 + m)
    };
    let bad = || {
        format!("Chrome update window {s:?} must look like 16:00-07:00 (machine local time, two different ends, may cross midnight)")
    };
    let (a, b) = s.split_once('-').ok_or_else(bad)?;
    let (a, b) = (hm(a).ok_or_else(bad)?, hm(b).ok_or_else(bad)?);
    if a == b {
        return Err(bad());
    }
    if (b + 1440 - a) % 1440 < MIN_CHROME_WINDOW_MINUTES {
        return Err(format!(
            "Chrome update window {s:?} is too short: it must be at least 2 hours long, because machines check once an hour and a shorter window may never be hit"
        ));
    }
    Ok((a, b))
}

/// `minute`（距午夜的分钟数）是否落在 [`chrome_window`] 给出的时段里：含开始、不含结束，开始晚于结束时跨午夜。
pub fn chrome_in_window((start, end): (u16, u16), minute: u16) -> bool {
    if start < end {
        start <= minute && minute < end
    } else {
        minute >= start || minute < end
    }
}

/// `YYYY-MM-DD`。
pub fn chrome_date(s: &str) -> Result<chrono::NaiveDate, String> {
    let ok = s.len() == 10 && s.as_bytes()[4] == b'-' && s.as_bytes()[7] == b'-';
    ok.then(|| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
        .flatten()
        .ok_or_else(|| format!("Chrome pause date {s:?} must look like 2026-11-20"))
}

/// 暂停到 `date`（含）：距 `published_at` 不超过 [`MAX_CHROME_PAUSE_DAYS`] 天。已经过去的日期不算错（没有效果）。
pub fn chrome_pause(date: &str, published_at: chrono::NaiveDate) -> Result<(), String> {
    let d = chrome_date(date)?;
    let days = (d - published_at).num_days();
    if days > MAX_CHROME_PAUSE_DAYS {
        return Err(format!(
            "Chrome updates are paused until {date}, {days} days from today, but at most {MAX_CHROME_PAUSE_DAYS} days are allowed: pausing longer would miss security updates"
        ));
    }
    Ok(())
}

/// 机器上再校一次暂停（应用设置时、`mastersos-agent chrome` 每一轮）：按**本机**的日期算，留 1 天余量——lint 按 UTC 的发布日算，
/// UTC 以西的时区里，发布当晚本机的日期还是前一天（复审 M3）。
pub fn chrome_pause_on_machine(date: &str, local_today: chrono::NaiveDate) -> Result<(), String> {
    chrome_pause(date, local_today.succ_opt().unwrap_or(local_today))
}

/// 时区偏移的写法：`UTC+7`、`UTC+5:30`、`UTC-3`、`UTC`（面板上看得出机器的时区对不对，复审 M9）。
pub fn utc_offset_label(secs_east: i32) -> String {
    if secs_east == 0 {
        return "UTC".into();
    }
    let sign = if secs_east < 0 { '-' } else { '+' };
    let m = secs_east.unsigned_abs() / 60;
    match m % 60 {
        0 => format!("UTC{sign}{}", m / 60),
        r => format!("UTC{sign}{}:{r:02}", m / 60),
    }
}

/// The longest IT password hash accepted, in bytes.
pub const MAX_IT_PASSWORD_HASH: usize = 256;

/// An IT maintenance account password hash (`it_account.password_hash`): a crypt(3) hash starting
/// with `$y$` (yescrypt) or `$6$rounds=500000$` (SHA-512 crypt, the fallback), then only
/// `[./0-9A-Za-z$]` (at least one), at most 256 bytes in all. Messages never echo the hash.
pub fn it_password_hash(h: &str) -> Result<(), String> {
    let prefix = ["$y$", "$6$rounds=500000$"]
        .into_iter()
        .find(|p| h.starts_with(p));
    // The charset applies after the prefix: `rounds=` has the only `=` a hash may hold.
    let ok = h.len() <= MAX_IT_PASSWORD_HASH
        && prefix.is_some_and(|p| {
            all_of(&h[p.len()..], |b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'/' | b'$')
            })
        });
    if ok {
        Ok(())
    } else {
        Err(
            "the IT account password hash is not a yescrypt ($y$) or SHA-512 ($6$rounds=500000$) \
             crypt hash of at most 256 characters; set the IT password again on the console"
                .into(),
        )
    }
}

/// `[school] logo_sha256`: 64 lowercase hex digits.
pub fn logo_sha256(s: &str) -> Result<(), String> {
    if s.len() == 64 && all_of(s, |b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(
            "logo_sha256 must be 64 lowercase hex digits; upload the logo again on the console"
                .into(),
        )
    }
}

/// The longest school name, in characters.
pub const MAX_SCHOOL_NAME: usize = 100;

/// `[school] name`: 1 to 100 characters, no control characters.
pub fn school_name(s: &str) -> Result<(), String> {
    let n = s.chars().count();
    if (1..=MAX_SCHOOL_NAME).contains(&n) && !s.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(format!(
            "the school name must be 1-{MAX_SCHOOL_NAME} characters without line breaks or other control characters"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(ssid: &str, psk: Option<&str>) -> Wifi {
        Wifi {
            ssid: ssid.into(),
            psk: psk.map(Into::into),
            ..Wifi::default()
        }
    }

    const PEM_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    const PEM_KEY: &str =
        "-----BEGIN PRIVATE KEY-----\nKEY-SECRET-BODY\n-----END PRIVATE KEY-----\n";

    fn from_toml(t: &str) -> Wifi {
        toml::from_str(t).unwrap_or_else(|e| panic!("{t}: {e}"))
    }

    /// PEAP with an account; the server check is left to each case.
    fn peap() -> Wifi {
        from_toml("ssid = \"Staff\"\neap = \"peap\"\nidentity = \"devices@eis\"\npassword = \"PW-SECRET-1\"")
    }

    #[test]
    fn checks_eap_requires_server_check() {
        let e = wifi(&peap()).unwrap_err();
        assert!(
            e.contains("server_domain") && e.contains("check_server = false"),
            "{e}"
        );
        let mut w = peap();
        w.check_server = Some(false);
        assert!(wifi(&w).is_ok());
        let mut w = peap();
        w.server_domain = Some("radius.school.example".into());
        assert!(wifi(&w).is_ok());
        let mut w = peap();
        w.ca_cert = Some(PEM_CERT.into());
        assert!(wifi(&w).is_ok());
        w.check_server = Some(true);
        assert!(wifi(&w).is_ok());
    }

    /// Every combination the design forbids, each with a secret in every secret field it has.
    fn bad_combinations() -> Vec<(&'static str, Wifi)> {
        let tls = || {
            let mut w = peap();
            w.eap = Some(EapMethod::Tls);
            w.password = None;
            w.server_domain = Some("r.x".into());
            w.client_cert = Some(PEM_CERT.into());
            w.client_key = Some(PEM_KEY.into());
            w.client_key_password = Some("CKP-SECRET-1".into());
            w
        };
        let checked = || {
            let mut w = peap();
            w.server_domain = Some("r.x".into());
            w
        };
        // The bases each case breaks are themselves valid.
        assert_eq!(wifi(&tls()), Ok(()));
        assert_eq!(wifi(&checked()), Ok(()));
        let psk =
            |extra: &str| from_toml(&format!("ssid = \"S\"\npsk = \"PSK-SECRET-1\"\n{extra}"));
        let mut out: Vec<(&'static str, Wifi)> = vec![
            ("open = false", from_toml("ssid = \"S\"\nopen = false")),
            ("open + psk", psk("open = true")),
            ("open + eap", {
                let mut w = checked();
                w.open = Some(true);
                w
            }),
            ("psk + eap", {
                let mut w = checked();
                w.psk = Some("PSK-SECRET-1".into());
                w
            }),
            (
                "wpa3_only without psk",
                from_toml("ssid = \"S\"\nwpa3_only = true"),
            ),
            ("eap without identity", {
                let mut w = checked();
                w.identity = None;
                w
            }),
            ("tls with password", {
                let mut w = tls();
                w.password = Some("PW-SECRET-1".into());
                w
            }),
            ("tls without client_cert", {
                let mut w = tls();
                w.client_cert = None;
                w
            }),
            ("tls without client_key", {
                let mut w = tls();
                w.client_key = None;
                w
            }),
            ("phase2 with tls", {
                let mut w = tls();
                w.phase2 = Some(crate::Phase2::Mschapv2);
                w
            }),
            ("phase2 with pwd", {
                let mut w = checked();
                w.eap = Some(EapMethod::Pwd);
                w.phase2 = Some(crate::Phase2::Gtc);
                w
            }),
            ("client_cert with peap", {
                let mut w = checked();
                w.client_cert = Some(PEM_CERT.into());
                w
            }),
            ("client_key with ttls", {
                let mut w = checked();
                w.eap = Some(EapMethod::Ttls);
                w.client_key = Some(PEM_KEY.into());
                w
            }),
            ("check_server = false with server_domain", {
                let mut w = checked();
                w.check_server = Some(false);
                w
            }),
            (
                "802.1X field without eap",
                psk("identity = \"i\"\npassword = \"PW-SECRET-1\""),
            ),
            ("password with a newline", {
                let mut w = checked();
                w.password = Some("PW-SECRET-1\n[x]".into());
                w
            }),
            ("client_key not PEM", {
                let mut w = tls();
                w.client_key = Some("KEY-SECRET-BODY".into());
                w
            }),
            ("server_domain with a slash", {
                let mut w = checked();
                w.server_domain = Some("https://r.x/".into());
                w
            }),
        ];
        for m in [EapMethod::Peap, EapMethod::Ttls, EapMethod::Pwd] {
            let mut w = checked();
            w.eap = Some(m);
            w.password = None;
            if m == EapMethod::Pwd {
                w.server_domain = None;
            }
            out.push(("password-based eap without password", w));
        }
        // Final review M1: pwd takes no server-check field.
        let pwd = || {
            let mut w = peap();
            w.eap = Some(EapMethod::Pwd);
            w
        };
        assert_eq!(wifi(&pwd()), Ok(()));
        out.push(("pwd with server_domain", {
            let mut w = pwd();
            w.server_domain = Some("r.x".into());
            w
        }));
        out.push(("pwd with ca_cert", {
            let mut w = pwd();
            w.ca_cert = Some(PEM_CERT.into());
            w
        }));
        for v in [true, false] {
            out.push(("pwd with check_server", {
                let mut w = pwd();
                w.check_server = Some(v);
                w
            }));
        }
        out.push(("wpa3_only = false without psk", {
            let mut w = pwd();
            w.wpa3_only = Some(false);
            w
        }));
        out
    }

    #[test]
    fn checks_field_combinations() {
        for (what, w) in bad_combinations() {
            assert!(wifi(&w).is_err(), "{what}: {w:?}");
        }
        // The five examples of design §4.1.
        for ok in [
            "ssid = \"EIS-Students\"\npsk = \"correct horse battery\"",
            "ssid = \"EIS-WPA3\"\npsk = \"correct horse battery\"\nwpa3_only = true",
            "ssid = \"EIS-Staff\"\neap = \"peap\"\nidentity = \"devices@eis\"\npassword = \"pw\"\n\
             server_domain = \"radius.school.example\"",
            &format!(
                "ssid = \"EIS-Secure\"\neap = \"tls\"\nidentity = \"device\"\nclient_cert = \"\"\"{PEM_CERT}\"\"\"\n\
                 client_key = \"\"\"{PEM_KEY}\"\"\"\nca_cert = \"\"\"{PEM_CERT}\"\"\""
            ),
            "ssid = \"EIS-Guest\"\nopen = true",
        ] {
            let w = from_toml(ok);
            assert_eq!(wifi(&w), Ok(()), "{ok}");
        }
        // TTLS with an explicit inner method; PWD with no server-check field (it uses no
        // certificates); WPA personal with an explicit wpa3_only = false.
        let mut w = peap();
        w.eap = Some(EapMethod::Ttls);
        w.phase2 = Some(crate::Phase2::Pap);
        w.server_domain = Some("r.x".into());
        w.anonymous_identity = Some("anonymous@eis".into());
        assert_eq!(wifi(&w), Ok(()));
        w.eap = Some(EapMethod::Pwd);
        w.phase2 = None;
        w.server_domain = None;
        w.anonymous_identity = None;
        assert_eq!(wifi(&w), Ok(()));
        let w = from_toml("ssid = \"S\"\npsk = \"correct horse\"\nwpa3_only = false");
        assert_eq!(wifi(&w), Ok(()));
    }

    #[test]
    fn checks_errors_never_echo_secrets() {
        let mut bad = bad_combinations();
        let mut short = w("S", Some("PSK-1"));
        short.hidden = true;
        bad.push(("short psk", short));
        for (what, w) in bad {
            let e = wifi(&w).unwrap_err();
            for secret in [&w.psk, &w.password, &w.client_key, &w.client_key_password]
                .into_iter()
                .flatten()
            {
                assert!(!e.contains(secret.as_str()), "{what}: {e}");
            }
            assert!(!e.contains("SECRET") && !e.contains("PSK-1"), "{what}: {e}");
            assert!(e.contains(&w.ssid), "{what}: {e}");
        }
    }

    #[test]
    fn check_admin_and_domain_length() {
        let local = "a".repeat(MAX_ENTRY_LEN - "@x.th".len());
        assert!(admin_user(&format!("{local}@x.th")).is_ok());
        assert!(admin_user(&format!("{local}a@x.th")).is_err());
        let d = "d".repeat(MAX_ENTRY_LEN);
        assert!(allowed_domain(&d).is_ok());
        assert!(allowed_domain(&format!("{d}d")).is_err());
    }

    #[test]
    fn check_oidc_injection() {
        let o = |issuer: &str, client_id: &str| Oidc {
            issuer: issuer.into(),
            client_id: client_id.into(),
            ..Oidc::default()
        };
        assert!(oidc(&o("https://sso.school.ac.th", "laptops")).is_ok());
        assert!(oidc(&o("http://dex.lab:5556/dex", "394475630609104899")).is_ok());
        for bad in [
            o("https://a\n[users]\nallowed_users = OWNER", "c"),
            o("https://a", "c\nextra_scopes = x"),
            o("https://a b", "c"),
            o("https://a", "c#x"),
            o("https://a;x", "c"),
            o("https://a\"", "c"),
            o("", "c"),
            o("https://a", ""),
            o("ftp://a", "c"),
        ] {
            assert!(oidc(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn check_oidc_client_secret() {
        let o = |s: &str| Oidc {
            issuer: "https://a".into(),
            client_id: "c".into(),
            client_secret: Some(s.into()),
            ..Oidc::default()
        };
        assert!(oidc(&o("GOCSPX-abc_DEF.123")).is_ok());
        assert!(oidc(&o(&"s".repeat(MAX_CLIENT_SECRET_BYTES))).is_ok());
        let long = "s".repeat(MAX_CLIENT_SECRET_BYTES + 1);
        for bad in [
            "",
            "a b",
            "a\n[users]\nallowed_users = OWNER",
            "a#b",
            "a;b",
            "a%(x)s",
            "pässword",
            "a\"b",
            "a\\b",
            long.as_str(),
        ] {
            let e = oidc(&o(bad)).unwrap_err();
            assert!(
                bad.is_empty() || !e.contains(bad),
                "the error echoes the value: {e}"
            );
        }
    }

    #[test]
    fn check_oidc_card_hosts() {
        let o = |hosts: &[&str]| Oidc {
            issuer: "https://a".into(),
            client_id: "c".into(),
            card_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            ..Oidc::default()
        };
        assert!(oidc(&o(&[])).is_ok());
        assert!(oidc(&o(&["accounts.google.com", "ssl.gstatic.com"])).is_ok());
        assert!(oidc(&o(&["a-b.xn--o3cw4h"])).is_ok());
        for bad in [
            "",
            "localhost",
            "*.school.ac.th",
            ".school.ac.th",
            "school.ac.th.",
            "https://cdn.school.ac.th",
            "cdn.school.ac.th:443",
            "cdn.school.ac.th/x",
            "CDN.school.ac.th",
            "1.2.3.4",
            "-a.school.ac.th",
            "a b.school.ac.th",
            "a.school.ac.th\nx",
            "[::1]",
        ] {
            assert!(oidc(&o(&[bad])).is_err(), "{bad:?}");
        }
        assert!(oidc(&o(&["a.b.th", "a.b.th"])).is_err());
        let many: Vec<String> = (0..=MAX_CARD_HOSTS).map(|i| format!("h{i}.b.th")).collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(oidc(&o(&refs)).is_err());
        assert!(oidc(&o(&refs[..MAX_CARD_HOSTS])).is_ok());
    }

    #[test]
    fn check_oidc_idp_hint() {
        let o = |h: &str| Oidc {
            issuer: "https://a".into(),
            client_id: "c".into(),
            idp_hint: Some(h.into()),
            ..Oidc::default()
        };
        let longest = "a".repeat(MAX_IDP_HINT_BYTES);
        for good in ["school-sso", "Google_1", "x", "0", longest.as_str()] {
            assert!(oidc(&o(good)).is_ok(), "{good:?}");
        }
        let long = "a".repeat(MAX_IDP_HINT_BYTES + 1);
        for bad in [
            "",
            "a b",
            "a&b",
            "a=b",
            "a#b",
            "a/b",
            "a.b",
            "a%20b",
            "a\nb",
            "ไทย",
            long.as_str(),
        ] {
            let e = oidc(&o(bad)).unwrap_err();
            assert!(e.contains("idp_hint"), "{bad:?}: {e}");
        }
    }

    #[test]
    fn check_short_psk() {
        let e = wifi(&w("staff", Some("short"))).unwrap_err();
        assert!(!e.contains("short"), "{e}");
        assert!(e.contains("staff"));
        assert!(wifi(&w("staff", Some("secret123"))).is_ok());
        assert!(wifi(&w("open", None)).is_ok());
        assert!(wifi(&w("", None)).is_err());
        assert!(wifi(&w(&"x".repeat(33), None)).is_err());
        assert!(wifi(&w("staff", Some("密码密码密码密码"))).is_err());
    }

    #[test]
    fn check_64_hex_psk_ok() {
        assert!(wifi(&w("a", Some(&"ab".repeat(32)))).is_ok());
        assert!(wifi(&w("a", Some(&"zz".repeat(32)))).is_err());
        assert!(wifi(&w("a", Some(&"x".repeat(63)))).is_ok());
        assert!(wifi(&w("a", Some(&"x".repeat(65)))).is_err());
    }

    #[test]
    fn check_printer_file_uri() {
        assert!(printer_uri("file:///dev/null").is_err());
        for ok in ["ipp://a/p", "ipps://a", "http://a", "https://a"] {
            assert!(printer_uri(ok).is_ok(), "{ok}");
        }
        assert!(printer_uri("ipp://a b").is_err());
        assert!(printer_uri("ipp://a\u{7}b").is_err());
        assert!(printer_uri("ipp://a\nb").is_err());
        assert!(scanner_uri("ipp://a").is_err());
        assert!(scanner_uri("http://a/eSCL").is_ok());
        assert!(device_name("").is_err());
        assert!(device_name("办公室").is_ok());
        assert!(device_name("a\nb").is_err());
        assert!(device_name(&"n".repeat(65)).is_err());
    }

    /// 地址里带账号口令（userinfo）不收：cupsd 报回的 device-uri 去掉了口令，永远对不上、每轮重加，口令还在 lpadmin 的命令行里；
    /// 扫描仪的会落进 0644 的 airscan 配置。
    #[test]
    fn device_uri_rejects_userinfo() {
        for bad in [
            "ipps://u:p@h/ipp/print",
            "ipp://u@h",
            "http://u:p@10.0.0.6/eSCL",
        ] {
            assert!(printer_uri(bad).is_err(), "{bad}");
        }
        assert!(scanner_uri("https://u:p@s/eSCL").is_err());
        // 路径、查询、片段里的 @ 不是 userinfo。
        assert!(printer_uri("ipp://h/ipp/print@x").is_ok());
        assert!(printer_uri("ipp://h?a=@").is_ok());
        assert!(scanner_uri("http://h/eSCL#@").is_ok());
        assert!(printer_uri("ipp://[fe80::1]:631/ipp/print").is_ok());
    }

    /// CUPS 的队列名：空白、控制字符、/ \ ? ' " # @ 换成 _（@ 在 lpadmin -p 里是「另一台服务器」），最多 127 字节、按字符边界截。
    #[test]
    fn printer_queue_rules() {
        assert_eq!(
            printer_queue("ห้องพักครู 2/ชั้น #1 \"A\""),
            "ห้องพักครู_2_ชั้น__1__A_"
        );
        assert_eq!(printer_queue("a\\b?c'd@e\u{a0}f\tg"), "a_b_c_d_e_f_g");
        assert_eq!(printer_queue("Library"), "Library");
        let long = "ห".repeat(64); // 每个 3 字节，共 192 字节
        let q = printer_queue(&long);
        assert!(q.len() <= 127, "{}", q.len());
        assert_eq!(q, "ห".repeat(42));
        assert_eq!(printer_queue(&"n".repeat(64)), "n".repeat(64));
    }

    #[test]
    fn check_webapp_url_with_quote() {
        let a = |name: &str, url: &str| WebApp {
            name: name.into(),
            url: url.into(),
            icon: None,
        };
        assert!(web_app(&a("w", "https://a/b?c=d")).is_ok());
        for bad in [
            "https://a\"b",
            "https://a'b",
            "https://a`b",
            "https://a\\b",
            "https://a b",
            "ftp://a",
        ] {
            assert!(web_app(&a("w", bad)).is_err(), "{bad}");
        }
        assert!(web_app(&a("", "https://a")).is_err());
        assert!(web_app(&a("a\nb", "https://a")).is_err());
    }

    #[test]
    fn check_bad_flatpak_id() {
        assert!(flatpak_id("libreoffice").is_err());
        assert!(flatpak_id("org.gnome").is_err());
        assert!(flatpak_id("1org.a.B").is_err());
        assert!(flatpak_id("org..B").is_err());
        assert!(flatpak_id("org.a.B c").is_err());
        assert!(flatpak_id("org.libreoffice.LibreOffice").is_ok());
        assert!(flatpak_id("org.a-b.C_d.E").is_ok());
    }

    #[test]
    fn check_admin_user() {
        assert!(admin_user("a\"b@x.th").is_err());
        assert!(admin_user("IT@School.ac.th").is_ok());
        assert!(admin_user("it").is_err());
        assert!(admin_user("@x.th").is_err());
        assert!(admin_user("a@").is_err());
        assert!(admin_user("a@b@c").is_err());
        // 开尔文符号 U+212A 在 Unicode 小写下是 k，ASCII 小写下不是：必须拒绝。
        assert!(admin_user("\u{212A}@x.th").is_err());
        assert!(admin_user("a@\u{212A}.th").is_err());
        // sudoers 里开头的 % 是组、+ 是网络组（agent 的 Task 12）。
        assert!(admin_user("%sudo@x.th").is_err());
        assert!(admin_user("+ng@x.th").is_err());
        assert!(admin_user("a%b+c@x.th").is_ok());
    }

    #[test]
    fn check_uppercase_or_at_in_domain() {
        assert!(allowed_domain("school.ac.th").is_ok());
        assert!(allowed_domain("School.ac.th").is_err());
        assert!(allowed_domain("@school.ac.th").is_err());
        assert!(allowed_domain("").is_err());
    }

    #[test]
    fn update_mirror_accepts_and_rejects() {
        for ok in [
            "https://cache.school.ac.th/mastersos",
            "http://10.0.0.5",
            "http://10.0.0.5:8080/os/",
            "http://cache.lan:3142/a/b",
        ] {
            assert!(update_mirror(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "file:///srv/os",
            "ftp://x/y",
            "cache.lan/os",
            "https://",
            "https:///os",
            "https://u:pw@cache.lan/os",
            "https://cache.lan/os?x=1",
            "https://cache.lan/os#f",
            "https://cache.lan/%A",
            "https://cache.lan/a b",
            "https://cache.lan/a\nPath=x",
            "https://cache.lan:/os",
            "https://cache.lan:99x/os",
            "https://cache.lan/../x",
            "https://cache.lan/é",
        ] {
            assert!(update_mirror(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn check_timezone_with_dotdot() {
        assert!(timezone("../../etc/shadow").is_err());
        assert!(timezone("Asia/Bangkok").is_ok());
        assert!(timezone("Etc/GMT+7").is_ok());
        assert!(timezone("UTC").is_ok());
        assert!(timezone("/Asia").is_err());
        assert!(timezone("Asia//x").is_err());
    }

    #[test]
    fn check_locale_and_lock_message() {
        assert!(locale("th_TH.UTF-8").is_ok());
        assert!(locale("th_TH").is_err());
        assert!(locale("TH_th.UTF-8").is_err());
        assert!(locale("th_TH.UTF-8\n").is_err());
        assert!(lock_message(&"字".repeat(500)).is_ok());
        assert!(lock_message(&"字".repeat(501)).is_err());
    }

    /// `16:00-07:00` 跨午夜：06:59 在、07:00 不在、16:00 在；端点是 [开始, 结束)。
    #[test]
    fn window_crossing_midnight() {
        let w = chrome_window("16:00-07:00").unwrap();
        assert_eq!(w, (16 * 60, 7 * 60));
        assert!(chrome_in_window(w, 6 * 60 + 59));
        assert!(!chrome_in_window(w, 7 * 60));
        assert!(!chrome_in_window(w, 12 * 60));
        assert!(!chrome_in_window(w, 15 * 60 + 59));
        assert!(chrome_in_window(w, 16 * 60));
        assert!(chrome_in_window(w, 23 * 60 + 59));
        assert!(chrome_in_window(w, 0));
        // 不跨午夜
        let d = chrome_window("12:30-14:30").unwrap();
        assert!(!chrome_in_window(d, 12 * 60 + 29));
        assert!(chrome_in_window(d, 12 * 60 + 30));
        assert!(!chrome_in_window(d, 14 * 60 + 30));
        for bad in [
            "",
            "16:00",
            "16:00-16:00",
            "24:00-07:00",
            "16:60-07:00",
            "6:00-07:00",
            "16:00 - 07:00",
            "16:00-07:00\n",
            "16.00-07.00",
            "１6:00-07:00",
        ] {
            assert!(chrome_window(bad).is_err(), "{bad:?}");
        }
        assert!(chrome_window("00:00-23:59").is_ok());
    }

    /// 复审 I1：短于 2 小时的时段报错——每小时一轮落在整点后 20 分钟内，太短的时段可能一次都碰不上。
    #[test]
    fn window_shorter_than_two_hours_is_error() {
        for short in [
            "16:30-17:00",
            "23:59-00:00",
            "07:25-08:00",
            "23:00-00:59",
            "12:00-13:59",
        ] {
            let e = chrome_window(short).unwrap_err();
            assert!(e.contains("2 hours"), "{short}: {e}");
        }
        for ok in ["22:00-00:00", "12:00-14:00", "23:30-01:30", "16:00-07:00"] {
            assert!(chrome_window(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn pause_longer_than_14_days_is_error() {
        let day = |s: &str| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap();
        let published = day("2026-11-06");
        assert!(chrome_pause("2026-11-20", published).is_ok(), "正好 14 天");
        let e = chrome_pause("2026-11-21", published).unwrap_err();
        assert!(e.contains("14"), "{e}");
        assert!(
            chrome_pause("2026-11-01", published).is_ok(),
            "已经过去的日子不挡（没有效果）"
        );
        for bad in ["2026-11-31", "2026/11/20", "20261120", "2026-11-20 ", ""] {
            assert!(chrome_pause(bad, published).is_err(), "{bad:?}");
            assert!(chrome_date(bad).is_err(), "{bad:?}");
        }
        assert_eq!(chrome_date("2026-11-20").unwrap(), day("2026-11-20"));
    }

    #[test]
    fn pause_on_machine_allows_one_day_slack_and_offset_labels() {
        let day = |s: &str| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap();
        assert!(chrome_pause_on_machine("2026-11-21", day("2026-11-06")).is_ok());
        assert!(chrome_pause_on_machine("2026-11-22", day("2026-11-06")).is_err());
        assert_eq!(utc_offset_label(7 * 3600), "UTC+7");
        assert_eq!(utc_offset_label(19800), "UTC+5:30");
        assert_eq!(utc_offset_label(-3 * 3600), "UTC-3");
        assert_eq!(utc_offset_label(0), "UTC");
    }

    #[test]
    fn checks_it_password_hash_logo_sha256_school_name() {
        for ok in [
            "$y$j9T$saltsalt$0123456789abcdefABCDEF./",
            "$6$rounds=500000$saltsalt$0123456789abcdef./",
        ] {
            it_password_hash(ok).unwrap();
        }
        let long = format!("$y$j9T${}", "a".repeat(256));
        for bad in [
            "",
            "$y$",
            "$6$x",
            "$1$abc$def",
            "$6$rounds=5000$salt$hash",
            "y$j9T$salt$hash",
            "$y$j9T$salt hash",
            "$y$j9T$salt\nhash",
            "$y$j9T$sält$hash",
            long.as_str(),
        ] {
            let e = it_password_hash(bad).unwrap_err();
            // ("$y$" alone is the prefix the message names.)
            assert!(bad.len() < 4 || !e.contains(bad), "echoes {bad:?}: {e}");
        }
        logo_sha256(&"0123456789abcdef".repeat(4)).unwrap();
        for bad in [
            String::new(),
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
        ] {
            assert!(logo_sha256(&bad).is_err(), "{bad}");
        }
        for ok in [
            "Example International School".to_string(),
            "x".into(),
            "é".repeat(100),
        ] {
            school_name(&ok).unwrap();
        }
        for bad in [
            String::new(),
            "é".repeat(101),
            "a\nb".into(),
            "bell\u{7}".into(),
        ] {
            assert!(school_name(&bad).is_err(), "{bad:?}");
        }
    }
}
