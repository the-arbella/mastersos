//! What differs between macOS, Linux and Windows for the command lines: where settings live,
//! files only their owner can read, and reading a line without echo.

use std::ffi::OsString;
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

/// Said (not refused) when a school key file can be read by other users: a USB stick formatted
/// FAT32 or exFAT cannot keep a file private.
pub const KEY_FILE_NOTE: &str = "Make sure no other user can read this school key file. Keep it on a USB stick whenever you can.";

/// The settings directory of `app` (`mastersos` or `mastersos-sign`): `$XDG_CONFIG_HOME/<app>`,
/// else `~/.config/<app>` on macOS and Linux; `%APPDATA%\<app>` on Windows.
pub fn config_dir(app: &str) -> Result<PathBuf> {
    config_dir_from(app, |k| std::env::var_os(k))
}

#[cfg(not(windows))]
fn config_dir_from(app: &str, var: impl Fn(&str) -> Option<OsString>) -> Result<PathBuf> {
    // The XDG base directory spec: a relative value is ignored.
    if let Some(x) = var("XDG_CONFIG_HOME").filter(|x| Path::new(x).is_absolute()) {
        return Ok(PathBuf::from(x).join(app));
    }
    let home = var("HOME")
        .filter(|h| !h.is_empty())
        .context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config").join(app))
}

#[cfg(windows)]
fn config_dir_from(app: &str, var: impl Fn(&str) -> Option<OsString>) -> Result<PathBuf> {
    let base = var("APPDATA")
        .filter(|a| !a.is_empty())
        .context("APPDATA is not set")?;
    Ok(PathBuf::from(base).join(app))
}

/// Create a new file only the current user can read (mode 0600 on Unix; on Windows a DACL that
/// grants only the current user and SYSTEM). An existing file is refused.
pub fn create_private(path: &Path) -> Result<File> {
    sys::create_private(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!(
                "{} already exists; refusing to overwrite it",
                path.display()
            )
        } else {
            anyhow::anyhow!("cannot create {}: {e}", path.display())
        }
    })
}

/// Create or replace `path` with `bytes`, readable by the current user only: a new temporary
/// file next to it ([`create_private`]), then a rename over it.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let name = path
        .file_name()
        .with_context(|| format!("{} has no file name", path.display()))?;
    let mut tmp_name = OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = path.with_file_name(tmp_name);
    let mut f = create_private(&tmp)?;
    let written = f.write_all(bytes).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, path)) {
        let _ = std::fs::remove_file(&tmp);
        bail!("cannot write {}: {e}", path.display());
    }
    Ok(())
}

/// Refuse a file other users can read or change (Unix: any group/other mode bit, or another
/// owner; Windows: a DACL that grants read to Everyone, Users or Authenticated Users).
pub fn check_private(path: &Path) -> Result<()> {
    open_private(path).map(drop)
}

/// [`check_private`] on the opened file, so the file checked is the file read.
pub(crate) fn open_private(path: &Path) -> Result<File> {
    let f = open(path)?;
    if sys::others_can_read(&f, path)? {
        bail!("{}", sys::too_open(&f, path));
    }
    Ok(f)
}

/// Open a school key file. On Unix it must belong to the current user; access by other users
/// (which a FAT32 or exFAT USB stick cannot prevent) gives [`KEY_FILE_NOTE`] for the caller to
/// say, instead of a refusal.
pub fn open_school_key(path: &Path) -> Result<(File, Option<&'static str>)> {
    let f = open(path)?;
    let broad = sys::others_can_read(&f, path).unwrap_or(true);
    Ok((f, broad.then_some(KEY_FILE_NOTE)))
}

fn open(path: &Path) -> Result<File> {
    let f = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    sys::check_owner(&f, path)?;
    Ok(f)
}

/// A symbolic link, or on Windows any reparse point (junctions included): never followed in a
/// settings directory.
pub fn is_link(meta: &std::fs::Metadata) -> bool {
    sys::is_link(meta)
}

/// Read one line with echo off when stdin is a terminal; a plain line otherwise. The prompt goes
/// to stderr. The line ending is removed.
pub fn read_hidden_line(prompt: &str) -> Result<Zeroizing<String>> {
    use std::io::{BufRead as _, IsTerminal as _};
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let stdin = std::io::stdin();
    // Sized so a typed secret does not make the buffer reallocate (and leave a copy behind).
    let mut line = Zeroizing::new(String::with_capacity(1024));
    let read = if stdin.is_terminal() {
        let quiet = sys::EchoOff::new().context("cannot turn off echo on the terminal")?;
        let read = stdin.lock().read_line(&mut line);
        // Echo comes back whether or not the read worked.
        drop(quiet);
        eprintln!();
        read
    } else {
        stdin.lock().read_line(&mut line)
    };
    if read.context("cannot read the input")? == 0 {
        bail!("input closed");
    }
    while line.ends_with(['\n', '\r']) {
        line.pop();
    }
    Ok(line)
}

#[cfg(unix)]
mod sys {
    use std::fs::File;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;

    use anyhow::{bail, Context, Result};

    pub fn create_private(path: &Path) -> std::io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }

    fn meta(f: &File, path: &Path) -> Result<std::fs::Metadata> {
        f.metadata()
            .with_context(|| format!("cannot read the metadata of {}", path.display()))
    }

    /// Another account could swap or read the file: refused.
    pub fn check_owner(f: &File, path: &Path) -> Result<()> {
        let uid = meta(f, path)?.uid();
        let me = nix::unistd::getuid().as_raw();
        if uid != me {
            bail!(
                "{} belongs to uid {uid}, not to the current user (uid {me})",
                path.display()
            );
        }
        Ok(())
    }

    pub fn others_can_read(f: &File, path: &Path) -> Result<bool> {
        Ok(meta(f, path)?.mode() & 0o077 != 0)
    }

    pub fn too_open(f: &File, path: &Path) -> String {
        let mode = f.metadata().map_or(0, |m| m.mode() & 0o777);
        format!(
            "{p} has mode {mode:o}, so other users can read or change it; run: chmod 600 {p}",
            p = path.display()
        )
    }

    pub fn is_link(meta: &std::fs::Metadata) -> bool {
        meta.file_type().is_symlink()
    }

    /// Echo off on stdin until dropped.
    pub struct EchoOff(rustix::termios::Termios);

    impl EchoOff {
        pub fn new() -> std::io::Result<EchoOff> {
            use rustix::termios::{tcgetattr, tcsetattr, LocalModes, OptionalActions};
            let stdin = std::io::stdin();
            let saved = tcgetattr(&stdin)?;
            let mut quiet = saved.clone();
            quiet.local_modes.remove(LocalModes::ECHO);
            tcsetattr(&stdin, OptionalActions::Flush, &quiet)?;
            Ok(EchoOff(saved))
        }
    }

    impl Drop for EchoOff {
        fn drop(&mut self) {
            use rustix::termios::{tcsetattr, OptionalActions};
            let _ = tcsetattr(std::io::stdin(), OptionalActions::Flush, &self.0);
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod sys {
    use std::ffi::OsString;
    use std::fs::File;
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::windows::fs::MetadataExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use std::path::Path;
    use std::ptr::null_mut;

    use anyhow::Result;
    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, HANDLE,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, EqualSid, GetAce, GetTokenInformation, TokenUser,
        WinAuthenticatedUserSid, WinBuiltinUsersSid, WinWorldSid, ACCESS_ALLOWED_ACE, ACE_HEADER,
        ACL, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, PSECURITY_DESCRIPTOR, PSID,
        SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, WELL_KNOWN_SID_TYPE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, CONSOLE_MODE, ENABLE_ECHO_INPUT,
        STD_INPUT_HANDLE,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

    /// Memory the system allocated with LocalAlloc, freed on drop.
    struct Local(*mut core::ffi::c_void);

    impl Drop for Local {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from an API documented to allocate with LocalAlloc.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    fn check(ok: windows_sys::core::BOOL) -> std::io::Result<()> {
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// The current user's SID in string form (S-1-5-21-…).
    fn current_user_sid() -> std::io::Result<String> {
        // SAFETY: plain Win32 calls; the token handle is closed below, the buffer outlives every
        // pointer into it, and the string SID is freed by `Local`.
        unsafe {
            let mut token: HANDLE = null_mut();
            check(OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY,
                &mut token,
            ))?;
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
            // u64 elements: TOKEN_USER holds a pointer and must be aligned for it.
            let mut buf = vec![0u64; (len as usize).div_ceil(8)];
            let got = check(GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr().cast(),
                len,
                &mut len,
            ));
            CloseHandle(token);
            got?;
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut text: *mut u16 = null_mut();
            check(ConvertSidToStringSidW(user.User.Sid, &mut text))?;
            let _free = Local(text.cast());
            let n = (0..).take_while(|&i| *text.add(i) != 0).count();
            Ok(OsString::from_wide(std::slice::from_raw_parts(text, n))
                .to_string_lossy()
                .into_owned())
        }
    }

    pub fn create_private(path: &Path) -> std::io::Result<File> {
        // Protected (no inherited entries): full control for the current user and SYSTEM only.
        let sddl = format!("D:P(A;;FA;;;{})(A;;FA;;;SY)", current_user_sid()?);
        let sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: both strings are NUL-terminated and live across the calls; the descriptor is
        // freed by `Local` after CreateFileW copied it; the handle is owned by the returned File.
        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            check(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            ))?;
            let _free = Local(sd);
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            let h = CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &sa,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            );
            if h == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error());
            }
            Ok(File::from_raw_handle(h))
        }
    }

    /// Windows has no uid to compare: whoever can open the file is checked by its DACL.
    pub fn check_owner(_f: &File, _path: &Path) -> Result<()> {
        Ok(())
    }

    fn well_known(kind: WELL_KNOWN_SID_TYPE) -> std::io::Result<[u32; 17]> {
        const _: () = assert!(SECURITY_MAX_SID_SIZE as usize == 17 * 4);
        let mut sid = [0u32; 17];
        let mut size = SECURITY_MAX_SID_SIZE;
        // SAFETY: the buffer is SECURITY_MAX_SID_SIZE bytes and 4-byte aligned.
        check(unsafe { CreateWellKnownSid(kind, null_mut(), sid.as_mut_ptr().cast(), &mut size) })?;
        Ok(sid)
    }

    /// Whether the file's DACL lets Everyone, Users or Authenticated Users read it (a missing
    /// DACL lets everyone do everything).
    pub fn others_can_read(f: &File, path: &Path) -> Result<bool> {
        let broad = [WinWorldSid, WinBuiltinUsersSid, WinAuthenticatedUserSid]
            .map(well_known)
            .into_iter()
            .collect::<std::io::Result<Vec<_>>>()?;
        let read = FILE_READ_DATA | GENERIC_READ | GENERIC_ALL;
        // SAFETY: GetSecurityInfo gives a DACL pointer into the descriptor, which `Local` frees
        // after the loop; GetAce returns pointers into that DACL.
        unsafe {
            let mut dacl: *mut ACL = null_mut();
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            let rc = GetSecurityInfo(
                f.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            );
            if rc != 0 {
                return Err(
                    anyhow::Error::new(std::io::Error::from_raw_os_error(rc as i32))
                        .context(format!("cannot read who may open {}", path.display())),
                );
            }
            let _free = Local(sd);
            if dacl.is_null() {
                return Ok(true);
            }
            for i in 0..u32::from((*dacl).AceCount) {
                let mut ace: *mut core::ffi::c_void = null_mut();
                if GetAce(dacl, i, &mut ace) == 0 {
                    continue;
                }
                let header = &*(ace as *const ACE_HEADER);
                if header.AceType != ACCESS_ALLOWED_ACE_TYPE
                    || u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0
                {
                    continue;
                }
                let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                if allowed.Mask & read == 0 {
                    continue;
                }
                let sid = &allowed.SidStart as *const u32 as PSID;
                if broad.iter().any(|b| EqualSid(b.as_ptr() as PSID, sid) != 0) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }

    pub fn too_open(_f: &File, path: &Path) -> String {
        format!(
            "Other users can read {}; in the file's Properties > Security, remove every account but your own",
            path.display()
        )
    }

    pub fn is_link(meta: &std::fs::Metadata) -> bool {
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    /// Echo off on the console until dropped.
    pub struct EchoOff(HANDLE, CONSOLE_MODE);

    impl EchoOff {
        pub fn new() -> std::io::Result<EchoOff> {
            // SAFETY: the standard input handle is owned by the process and never closed here.
            unsafe {
                let h = GetStdHandle(STD_INPUT_HANDLE);
                let mut mode: CONSOLE_MODE = 0;
                check(GetConsoleMode(h, &mut mode))?;
                check(SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT))?;
                Ok(EchoOff(h, mode))
            }
        }
    }

    impl Drop for EchoOff {
        fn drop(&mut self) {
            // SAFETY: as in `new`.
            unsafe { SetConsoleMode(self.0, self.1) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |k| {
            vars.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| OsString::from(v))
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn config_dir_uses_xdg_then_home() {
        let both = [("XDG_CONFIG_HOME", "/x"), ("HOME", "/h")];
        assert_eq!(
            config_dir_from("mastersos", env(&both)).unwrap(),
            Path::new("/x/mastersos")
        );
        // Unset, empty or relative XDG_CONFIG_HOME: ~/.config.
        for xdg in [None, Some(""), Some("rel")] {
            let mut vars = vec![("HOME", "/h")];
            vars.extend(xdg.map(|x| ("XDG_CONFIG_HOME", x)));
            assert_eq!(
                config_dir_from("mastersos-sign", env(&vars)).unwrap(),
                Path::new("/h/.config/mastersos-sign")
            );
        }
        let e = config_dir_from("mastersos", env(&[])).unwrap_err();
        assert!(e.to_string().contains("HOME"), "{e}");
    }

    #[cfg(windows)]
    #[test]
    fn config_dir_uses_appdata() {
        assert_eq!(
            config_dir_from("mastersos", env(&[("APPDATA", r"C:\A")])).unwrap(),
            Path::new(r"C:\A\mastersos")
        );
        let e = config_dir_from("mastersos", env(&[("HOME", r"C:\h")])).unwrap_err();
        assert!(e.to_string().contains("APPDATA"), "{e}");
    }

    #[test]
    fn create_private_is_owner_only() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("token");
        {
            use std::io::Write as _;
            let mut f = create_private(&p).unwrap();
            f.write_all(b"secret").unwrap();
        }
        assert_eq!(std::fs::read(&p).unwrap(), b"secret");
        check_private(&p).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // An existing file is never overwritten.
        let e = create_private(&p).unwrap_err();
        assert!(e.to_string().contains("already exists"), "{e}");
        assert_eq!(std::fs::read(&p).unwrap(), b"secret");
    }

    #[test]
    fn write_private_replaces_and_stays_owner_only() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("config.toml");
        std::fs::write(&p, "old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        write_private(&p, b"new").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"new");
        check_private(&p).unwrap();
        // No temporary file left behind.
        assert_eq!(std::fs::read_dir(t.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn check_private_refuses_group_readable() {
        use std::os::unix::fs::PermissionsExt as _;
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("token");
        std::fs::write(&p, "x").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let e = check_private(&p).unwrap_err().to_string();
        assert!(e.contains(&p.display().to_string()), "{e}");
        assert!(e.contains("has mode 640") && e.contains("chmod 600"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn school_key_broad_mode_warns_not_refuses() {
        use std::io::Read as _;
        use std::os::unix::fs::PermissionsExt as _;
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("school.kit");
        std::fs::write(&p, "kit").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o777)).unwrap();
        let (mut f, note) = open_school_key(&p).unwrap();
        assert_eq!(note, Some(KEY_FILE_NOTE));
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        assert_eq!(s, "kit");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(open_school_key(&p).unwrap().1, None);
    }

    #[test]
    fn missing_school_key_names_the_file() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("none.kit");
        let e = open_school_key(&p).unwrap_err().to_string();
        assert!(e.contains(&p.display().to_string()), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_is_a_link() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(is_link(&std::fs::symlink_metadata(&link).unwrap()));
        assert!(!is_link(&std::fs::symlink_metadata(&target).unwrap()));
    }

    #[cfg(windows)]
    #[test]
    fn junction_is_a_link() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = t.path().join("link");
        mklink_junction(&link, &target);
        assert!(is_link(&std::fs::symlink_metadata(&link).unwrap()));
        assert!(!is_link(&std::fs::symlink_metadata(&target).unwrap()));
    }

    /// Grant `BUILTIN\Users` read on `path` (by SID, so the system language does not matter).
    #[cfg(windows)]
    fn grant_users_read(path: &Path) {
        let out = std::process::Command::new("icacls")
            .arg(path)
            .args(["/grant", "*S-1-5-32-545:(R)"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }

    #[cfg(windows)]
    fn mklink_junction(link: &Path, target: &Path) {
        let out = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }

    #[cfg(windows)]
    #[test]
    fn windows_private_file_acl() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("token");
        drop(create_private(&p).unwrap());
        check_private(&p).unwrap();
        assert_eq!(open_school_key(&p).unwrap().1, None);
        grant_users_read(&p);
        let e = check_private(&p).unwrap_err().to_string();
        assert!(e.contains(&p.display().to_string()), "{e}");
        // A school key file with the same access still opens, with the note.
        assert_eq!(open_school_key(&p).unwrap().1, Some(KEY_FILE_NOTE));
        // write_private puts the owner-only access back.
        write_private(&p, b"new").unwrap();
        check_private(&p).unwrap();
    }
}
