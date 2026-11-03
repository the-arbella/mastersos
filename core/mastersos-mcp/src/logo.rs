//! `mastersos logo upload`: the sign-in screen logo and the small icon are checked here, before
//! anything is sent, then uploaded to the school's logo store. The server answers with their
//! SHA-256, which IT pastes into `[school]` (Devices download `<server>/logos/<sha256>.png` and
//! show it only if the digest matches).

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// The sign-in logo is exactly this high.
pub const LOGO_HEIGHT: u32 = 96;
/// The sign-in logo is at most this wide.
pub const LOGO_MAX_WIDTH: u32 = 480;
/// The icon is this many pixels on both sides.
pub const ICON_SIDE: u32 = 40;

/// (width, height) from a PNG's signature and IHDR chunk. The image data is not decoded.
pub fn png_size(bytes: &[u8]) -> Result<(u32, u32), String> {
    if bytes.len() < 24 || bytes[..8] != PNG_SIGNATURE {
        return Err("not a PNG file".into());
    }
    // 8 signature bytes, then the first chunk: length (4), type (4), data.
    if bytes[8..12] != [0, 0, 0, 13] || &bytes[12..16] != b"IHDR" {
        return Err("not a PNG file (the first chunk is not IHDR)".into());
    }
    let be = |i: usize| u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
    Ok((be(16), be(20)))
}

/// The login-page logo: 96 pixels high, 1 to 480 wide.
pub fn check_login_logo(bytes: &[u8]) -> Result<(), String> {
    let (w, h) = png_size(bytes)?;
    if h != LOGO_HEIGHT || !(1..=LOGO_MAX_WIDTH).contains(&w) {
        return Err(format!(
            "the login logo must be {LOGO_HEIGHT} pixels high and 1 to {LOGO_MAX_WIDTH} wide, this one is {w}x{h}"
        ));
    }
    Ok(())
}

/// The icon: 40x40.
pub fn check_icon(bytes: &[u8]) -> Result<(), String> {
    let (w, h) = png_size(bytes)?;
    if (w, h) != (ICON_SIDE, ICON_SIDE) {
        return Err(format!(
            "the icon must be {ICON_SIDE}x{ICON_SIDE} pixels, this one is {w}x{h}"
        ));
    }
    Ok(())
}

/// The upload body, after both files passed their checks.
pub fn upload_body(login: &[u8], icon: &[u8]) -> Result<Value, String> {
    check_login_logo(login).map_err(|e| format!("login PNG: {e}"))?;
    check_icon(icon).map_err(|e| format!("icon PNG: {e}"))?;
    Ok(json!({ "logo_png": STANDARD.encode(login), "icon_png": STANDARD.encode(icon) }))
}

/// What to tell IT after the upload: the two digests and the two `[school]` lines.
pub fn report(resp: &Value) -> Result<String, String> {
    let get = |k: &str| {
        resp[k]
            .as_str()
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| format!("the server's answer has no valid {k}"))
    };
    let (logo, icon) = (get("logo_sha256")?, get("logo_icon_sha256")?);
    Ok(format!(
        "logo sha256: {logo}\nicon sha256: {icon}\nPaste these into [school] in manifest.toml:\nlogo_sha256 = \"{logo}\"\nlogo_icon_sha256 = \"{icon}\""
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PNG signature and IHDR claiming `w`x`h` (enough for the size checks).
    fn png(w: u32, h: u32) -> Vec<u8> {
        let mut v = PNG_SIGNATURE.to_vec();
        v.extend([0, 0, 0, 13]);
        v.extend(b"IHDR");
        v.extend(w.to_be_bytes());
        v.extend(h.to_be_bytes());
        v.extend([8, 6, 0, 0, 0]);
        v
    }

    #[test]
    fn login_logo_sizes() {
        assert!(check_login_logo(&png(480, 96)).is_ok());
        assert!(check_login_logo(&png(1, 96)).is_ok());
        assert!(check_login_logo(&png(481, 96)).is_err());
        assert!(check_login_logo(&png(0, 96)).is_err());
        assert!(check_login_logo(&png(200, 95)).is_err());
        assert!(check_login_logo(&png(200, 97)).is_err());
    }

    #[test]
    fn icon_sizes() {
        assert!(check_icon(&png(40, 40)).is_ok());
        assert!(check_icon(&png(40, 41)).is_err());
        assert!(check_icon(&png(39, 40)).is_err());
    }

    #[test]
    fn not_a_png_is_refused() {
        assert!(png_size(b"GIF89a....................").is_err());
        assert!(png_size(&png(1, 1)[..20]).is_err());
        let mut bad = png(40, 40);
        bad[12] = b'X';
        assert!(png_size(&bad).is_err());
    }

    #[test]
    fn body_is_standard_base64_and_checks_both() {
        let (l, i) = (png(100, 96), png(40, 40));
        let b = upload_body(&l, &i).unwrap();
        assert_eq!(b["logo_png"], STANDARD.encode(&l));
        assert_eq!(b["icon_png"], STANDARD.encode(&i));
        assert!(upload_body(&i, &i).unwrap_err().starts_with("login PNG"));
        assert!(upload_body(&l, &l).unwrap_err().starts_with("icon PNG"));
    }

    #[test]
    fn report_prints_the_school_lines() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let text = report(&json!({ "logo_sha256": a, "logo_icon_sha256": b })).unwrap();
        assert!(text.contains(&format!("logo_sha256 = \"{a}\"")));
        assert!(text.contains(&format!("logo_icon_sha256 = \"{b}\"")));
        assert!(report(&json!({ "logo_sha256": "zz" })).is_err());
    }
}
