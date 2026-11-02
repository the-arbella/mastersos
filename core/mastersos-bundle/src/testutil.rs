//! 测试辅助：软件实现的 passkey（feature `test-util`）。server、agent、mcp、sign
//! 的测试都用它当 IT 的 passkey。

use std::collections::BTreeSet;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use sha2::{Digest, Sha256};

use crate::{KeyAlg, SignatureFile, TrustKey};

/// 一把 P-256 passkey，签出来的断言与浏览器的形状一致：
/// `authenticator_data = sha256(rp_id) || flags || 签名计数 0`，
/// `client_data_json = {"type":"webauthn.get","challenge":…,"origin":…,"crossOrigin":false}`。
pub struct FakePasskey {
    pub rp_id: String,
    pub origin: String,
    /// 签名文件里写的 `key_id`，默认 `"passkey"`。`trust_key(id)` 不改它：
    /// 两边要对上，用 [`FakePasskey::with_key_id`] 或直接改这个字段。
    pub key_id: String,
    pair: EcdsaKeyPair,
}

impl FakePasskey {
    pub fn new(rp_id: &str, origin: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("系统随机数源不可用");
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("ring 刚生成的 PKCS#8 必能读回");
        FakePasskey {
            rp_id: rp_id.into(),
            origin: origin.into(),
            key_id: "passkey".into(),
            pair,
        }
    }

    pub fn with_key_id(mut self, id: &str) -> Self {
        self.key_id = id.into();
        self
    }

    /// 65 字节的未压缩点。
    pub fn public_point(&self) -> [u8; 65] {
        self.pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("P-256 未压缩点是 65 字节")
    }

    pub fn trust_key(&self, id: &str) -> TrustKey {
        TrustKey {
            id: id.into(),
            alg: KeyAlg::WebauthnEs256,
            public_key: STANDARD.encode(self.public_point()),
            rp_id: Some(self.rp_id.clone()),
        }
    }

    /// 像浏览器一样对 `msg` 做一次断言。
    pub fn sign(&self, msg: &[u8], flags: u8) -> SignatureFile {
        let cd = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
            URL_SAFE_NO_PAD.encode(msg),
            self.origin
        );
        self.sign_with_client_data(msg, flags, &cd)
    }

    /// 用调用方给的 `client_data_json`（可以是畸形的）做断言；challenge 由它自己写，
    /// `msg` 不参与，留着参数与 [`FakePasskey::sign`] 对称。
    pub fn sign_with_client_data(
        &self,
        msg: &[u8],
        flags: u8,
        client_data_json: &str,
    ) -> SignatureFile {
        let _ = msg;
        let mut ad = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        ad.push(flags);
        ad.extend_from_slice(&0u32.to_be_bytes());
        self.sign_raw(&ad, client_data_json.as_bytes())
    }

    /// 对任意 `authenticator_data` 与 `client_data_json` 签名（造错的 rpIdHash、
    /// 过短的 authenticator_data 之类）。
    pub fn sign_raw(&self, authenticator_data: &[u8], client_data_json: &[u8]) -> SignatureFile {
        let mut signed = authenticator_data.to_vec();
        signed.extend_from_slice(&Sha256::digest(client_data_json));
        let sig = self
            .pair
            .sign(&SystemRandom::new(), &signed)
            .expect("ECDSA 签名失败");
        SignatureFile {
            key_id: self.key_id.clone(),
            alg: KeyAlg::WebauthnEs256,
            sig: STANDARD.encode(sig.as_ref()),
            authenticator_data: Some(STANDARD.encode(authenticator_data)),
            client_data_json: Some(STANDARD.encode(client_data_json)),
        }
    }
}

const SPEC_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// The settings example of spec §5.3 in the new shape (config profiles design §3): valid, no
/// error-level lint; pair it with [`spec_example_present`]. Each group has its own config, the
/// same settings as [`legacy_spec_example`] gives it.
pub fn spec_example() -> String {
    format!(
        r#"
version = 42
issued_at = "2026-10-10T07:00:00Z"

[[trust]]
id = "school-2026"
alg = "ed25519"
public_key = "{SPEC_KEY}"

[school]
oidc = {{ issuer = "https://sso.school.ac.th", client_id = "mastersos" }}
allowed_domains = ["school.ac.th"]
admin_users = ["it@school.ac.th"]
update_channel = "stable"
timezone = "Asia/Bangkok"
locale = "th_TH.UTF-8"

[[config]]
id = "teacher"
name = "教师机"
interface = "full"
login_methods = ["sso", "local"]
local_users_admin = false
wifi = [{{ ssid = "staff", psk = "secret123" }}]
printers = [{{ name = "办公室", uri = "ipp://10.0.0.5/ipp/print" }}]
scanners = [{{ name = "扫描仪", uri = "http://10.0.0.6/eSCL" }}]
files = [{{ src = "files/wallpaper-teacher.jpg", dest = "/usr/share/backgrounds/school.jpg" }}]
scripts = [{{ path = "scripts/setup-scanner.sh", when = "login" }}]

[config.apps]
web = [{{ name = "Classroom", url = "https://classroom.google.com", icon = "files/classroom.png" }}]
flatpak = ["org.libreoffice.LibreOffice", "org.gnome.SimpleScan"]

[config.apps.kiosk]
nwea = {{ name = "NWEA MAP", url = "https://test.mapnwea.org/", allow = ["nwea.org", "mapnwea.org"], icon = "files/nwea.png" }}

[config.chrome_policy]
URLBlocklist = ["facebook.com"]

[config.chrome]
update_window = "16:00-07:00"

[[config]]
id = "cart"
name = "推车"
interface = "learning"
login_methods = ["sso", "guest"]
downloads = [{{ url = "https://example.com/a.deb", sha256 = "{sha}", dest = "/opt/a.deb" }}]

[[config]]
id = "standard"
name = "标准"

[[group]]
id = "teacher"
name = "教师机"
config = "teacher"

[[group]]
id = "cart-g3"
name = "三年级推车"
config = "cart"

[[group]]
id = "default"
name = "未分组"
config = "standard"

[[device]]
serial = "ABC1234"
group = "cart-g3"

[[device]]
serial = "XYZ9876"
group = "teacher"
locked = {{ message = "本机已挂失，请交回 IT 办公室" }}
"#,
        sha = "a".repeat(64)
    )
}

/// The same settings as [`spec_example`] in the legacy shape (`[[group]]`s carrying the
/// settings, `mode`), as Versions signed before config profiles are written.
pub fn legacy_spec_example() -> String {
    format!(
        r#"
version = 42
issued_at = "2026-10-10T07:00:00Z"

[[trust]]
id = "school-2026"
alg = "ed25519"
public_key = "{SPEC_KEY}"

[school]
oidc = {{ issuer = "https://sso.school.ac.th", client_id = "mastersos" }}
allowed_domains = ["school.ac.th"]
admin_users = ["it@school.ac.th"]
update_channel = "stable"
timezone = "Asia/Bangkok"
locale = "th_TH.UTF-8"

[[group]]
id = "teacher"
name = "教师机"
login_methods = ["sso", "local"]
local_users_admin = false
mode = "desktop"
wifi = [{{ ssid = "staff", psk = "secret123" }}]
printers = [{{ name = "办公室", uri = "ipp://10.0.0.5/ipp/print" }}]
scanners = [{{ name = "扫描仪", uri = "http://10.0.0.6/eSCL" }}]
files = [{{ src = "files/wallpaper-teacher.jpg", dest = "/usr/share/backgrounds/school.jpg" }}]
scripts = [{{ path = "scripts/setup-scanner.sh", when = "login" }}]

[group.apps]
web = [{{ name = "Classroom", url = "https://classroom.google.com", icon = "files/classroom.png" }}]
flatpak = ["org.libreoffice.LibreOffice", "org.gnome.SimpleScan"]

[group.apps.kiosk]
nwea = {{ name = "NWEA MAP", url = "https://test.mapnwea.org/", allow = ["nwea.org", "mapnwea.org"], icon = "files/nwea.png" }}

[group.chrome_policy]
URLBlocklist = ["facebook.com"]

[group.chrome]
update_window = "16:00-07:00"

[[group]]
id = "cart-g3"
name = "三年级推车"
login_methods = ["sso", "guest"]
mode = "browser"
downloads = [{{ url = "https://example.com/a.deb", sha256 = "{sha}", dest = "/opt/a.deb" }}]

[[group]]
id = "default"
name = "未分组"

[[device]]
serial = "ABC1234"
group = "cart-g3"

[[device]]
serial = "XYZ9876"
group = "teacher"
locked = {{ message = "本机已挂失，请交回 IT 办公室" }}
"#,
        sha = "a".repeat(64)
    )
}

/// The Defaults example of the phase B design §4.1 (`format = 2`): Defaults with a mode, login
/// methods, one network, one Flatpak app and one printer; Config `teacher` overrides the mode, adds
/// an app and drops the printer; Config `student` writes nothing. Group `staff` uses `teacher`,
/// `default` uses `student`.
pub fn defaults_example() -> String {
    r#"format = 2
version = 1

[defaults]
interface = "learning"
login_methods = ["sso", "guest"]
wifi = [{ ssid = "Campus-IoT", psk = "iot-pass-1" }]
apps.flatpak = ["org.libreoffice.LibreOffice"]
printers = [{ name = "Library", uri = "ipp://lib.eis.local/ipp/print" }]

[[config]]
id = "teacher"
name = "Teacher"
interface = "full"
apps.flatpak = ["org.gimp.GIMP"]
drop.printers = ["Library"]

[[config]]
id = "student"
name = "Student"

[[group]]
id = "staff"
name = "Staff"
config = "teacher"

[[group]]
id = "default"
name = "Ungrouped"
config = "student"
"#
    .to_string()
}

/// [`spec_example`] 对应的包内文件集合。
pub fn spec_example_present() -> BTreeSet<String> {
    [
        "files/wallpaper-teacher.jpg",
        "scripts/setup-scanner.sh",
        "files/classroom.png",
        "files/nwea.png",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}
