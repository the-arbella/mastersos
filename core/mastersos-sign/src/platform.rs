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

/// The settings directory of `app` (`mastersos` or `mastersos-sign`): `~/.config/<app>` on macOS
/// and Linux (XDG_CONFIG_HOME is ignored, so existing settings and pins never move);
/// `%APPDATA%\<app>` on Windows.
pub fn config_dir(app: &str) -> Result<PathBuf> {
    config_dir_from(app, |k| std::env::var_os(k))
}

#[cfg(not(windows))]
fn config_dir_from(app: &str, var: impl Fn(&str) -> Option<OsString>) -> Result<PathBuf> {
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

/// Create a new file only the current user can read or change (mode 0600 on Unix; on Windows a
/// protected DACL that grants only the current user and SYSTEM). An existing file is refused.
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

/// Refuse a file other accounts can read or change. Unix: another owner, or any group/other mode
/// bit. Windows: an owner other than the current user or Administrators, no DACL, or an allow
/// entry that grants read, write or control of the file to anyone but the current user, SYSTEM
/// and Administrators.
pub fn check_private(path: &Path) -> Result<()> {
    open_private(path).map(drop)
}

/// [`check_private`] on the opened file, so the file checked is the file read.
pub(crate) fn open_private(path: &Path) -> Result<File> {
    let f = open(path)?;
    if sys::not_private(&f, path)? {
        bail!("{}", sys::too_open(&f, path));
    }
    Ok(f)
}

/// Open a school key file. On Unix it must belong to the current user. A file that fails the
/// rest of [`check_private`] (which a FAT32 or exFAT USB stick cannot pass) gives
/// [`KEY_FILE_NOTE`] for the caller to say, instead of a refusal.
pub fn open_school_key(path: &Path) -> Result<(File, Option<&'static str>)> {
    let f = open(path)?;
    let broad = sys::not_private(&f, path).unwrap_or(true);
    Ok((f, broad.then_some(KEY_FILE_NOTE)))
}

fn open(path: &Path) -> Result<File> {
    let f = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    sys::check_owner(&f, path)?;
    Ok(f)
}

/// Whether `path`, whose [`std::fs::symlink_metadata`] is `meta`, is a link that a settings
/// directory never follows: a symbolic link; on Windows also a junction (mount point). Other
/// Windows reparse points (OneDrive cloud files, deduplicated files) are ordinary files. A
/// reparse point whose kind cannot be read counts as a link.
pub fn is_link(path: &Path, meta: &std::fs::Metadata) -> bool {
    sys::is_link(path, meta)
}

/// The terminal cannot turn off echo (on Windows: Git Bash and other terminals that are not a
/// console), so a secret is not read from it.
#[derive(Debug)]
pub struct CannotHideTyping;

impl std::fmt::Display for CannotHideTyping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(sys::CANNOT_HIDE_TYPING)
    }
}

impl std::error::Error for CannotHideTyping {}

/// Read one line with echo off when stdin is a terminal; a plain line otherwise. The prompt goes
/// to stderr. The line ending is removed. A terminal that cannot hide typing gives
/// [`CannotHideTyping`].
pub fn read_hidden_line(prompt: &str) -> Result<Zeroizing<String>> {
    use std::io::{BufRead as _, IsTerminal as _};
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let stdin = std::io::stdin();
    // Sized so a typed secret does not make the buffer reallocate (and leave a copy behind).
    let mut line = Zeroizing::new(String::with_capacity(1024));
    let read = if stdin.is_terminal() {
        let quiet = sys::EchoOff::new().map_err(|_| CannotHideTyping)?;
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

    pub const CANNOT_HIDE_TYPING: &str =
        "Cannot hide typing in this terminal. Run this in another terminal, or pipe the input in.";

    pub fn not_private(f: &File, path: &Path) -> Result<bool> {
        Ok(meta(f, path)?.mode() & 0o077 != 0)
    }

    pub fn too_open(f: &File, path: &Path) -> String {
        let mode = f.metadata().map_or(0, |m| m.mode() & 0o777);
        format!(
            "{p} has mode {mode:o}, so other users can read or change it; run: chmod 600 {p}",
            p = path.display()
        )
    }

    pub fn is_link(_path: &Path, meta: &std::fs::Metadata) -> bool {
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
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
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
        WinBuiltinAdministratorsSid, WinLocalSystemSid, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
        INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, WELL_KNOWN_SID_TYPE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FileAttributeTagInfo, GetFileInformationByHandleEx, CREATE_NEW,
        FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_WRITE_DATA, WRITE_DAC, WRITE_OWNER,
    };
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, CONSOLE_MODE, ENABLE_ECHO_INPUT,
        STD_INPUT_HANDLE,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub const CANNOT_HIDE_TYPING: &str = "Cannot hide typing in this terminal. Run this in PowerShell or Command Prompt, or pipe the token in.";

    // ACE types that allow access (winnt.h).
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x0;
    const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 0x4;
    const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x5;
    const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 0x9;
    const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0xB;
    // Object ACEs: which of the two GUIDs before the SID are present.
    const ACE_OBJECT_TYPE_PRESENT: u32 = 0x1;
    const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x2;
    // Reparse tags that are links (winnt.h).
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
    const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;

    /// Rights that let another account read, change or take over the file.
    const NOT_PRIVATE_RIGHTS: u32 = FILE_READ_DATA
        | FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | GENERIC_READ
        | GENERIC_WRITE
        | GENERIC_ALL
        | WRITE_DAC
        | WRITE_OWNER;

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

    /// The process's TOKEN_USER (u64 elements: it holds a pointer and must be aligned for it).
    struct CurrentUser(Vec<u64>);

    impl CurrentUser {
        fn get() -> std::io::Result<CurrentUser> {
            // SAFETY: plain Win32 calls; the token handle is closed before returning, and the
            // buffer is as large as GetTokenInformation asked for.
            unsafe {
                let mut token: HANDLE = null_mut();
                check(OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY,
                    &mut token,
                ))?;
                let mut len = 0u32;
                GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
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
                Ok(CurrentUser(buf))
            }
        }

        /// Valid while `self` lives.
        fn sid(&self) -> PSID {
            // SAFETY: the buffer holds a TOKEN_USER whose SID points into the same buffer.
            unsafe { (*(self.0.as_ptr() as *const TOKEN_USER)).User.Sid }
        }

        /// The SID in string form (S-1-5-21-…).
        fn sid_string(&self) -> std::io::Result<String> {
            // SAFETY: ConvertSidToStringSidW gives a NUL-terminated string, freed by `Local`.
            unsafe {
                let mut text: *mut u16 = null_mut();
                check(ConvertSidToStringSidW(self.sid(), &mut text))?;
                let _free = Local(text.cast());
                let n = (0..).take_while(|&i| *text.add(i) != 0).count();
                Ok(OsString::from_wide(std::slice::from_raw_parts(text, n))
                    .to_string_lossy()
                    .into_owned())
            }
        }
    }

    pub fn create_private(path: &Path) -> std::io::Result<File> {
        // Protected (no inherited entries): full control for the current user and SYSTEM only.
        let sddl = format!(
            "D:P(A;;FA;;;{})(A;;FA;;;SY)",
            CurrentUser::get()?.sid_string()?
        );
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

    /// The owner is judged with the DACL in [`not_private`].
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

    /// The SID of an allow ACE, or None for a layout this code does not read.
    ///
    /// # Safety
    /// `ace` points at a valid ACE of one of the allow types.
    unsafe fn allowed_sid(ace: *const u8, kind: u8) -> Option<PSID> {
        // Header (4 bytes), then the access mask (4 bytes).
        let mut offset = 8;
        match kind {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {}
            ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                let flags = std::ptr::read_unaligned(ace.add(8) as *const u32);
                offset += 4;
                if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
                    offset += 16;
                }
                if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
                    offset += 16;
                }
            }
            _ => return None,
        }
        Some(ace.add(offset) as PSID)
    }

    /// Whether the file is open to other accounts: its owner is not the current user or
    /// Administrators, it has no DACL, or an allow entry grants [`NOT_PRIVATE_RIGHTS`] to anyone
    /// but the current user, SYSTEM and Administrators.
    pub fn not_private(f: &File, path: &Path) -> Result<bool> {
        let user = CurrentUser::get()?;
        let system = well_known(WinLocalSystemSid)?;
        let admins = well_known(WinBuiltinAdministratorsSid)?;
        // SAFETY: EqualSid on valid SIDs: `user` and the arrays outlive every call.
        let is = |sid: PSID, of: PSID| unsafe { EqualSid(sid, of) != 0 };
        let may_own = |sid: PSID| is(sid, user.sid()) || is(sid, admins.as_ptr() as PSID);
        let may_access = |sid: PSID| may_own(sid) || is(sid, system.as_ptr() as PSID);
        // SAFETY: GetSecurityInfo gives owner and DACL pointers into the descriptor, which
        // `Local` frees after the loop; GetAce returns pointers into that DACL.
        unsafe {
            let mut owner: PSID = null_mut();
            let mut dacl: *mut ACL = null_mut();
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            let rc = GetSecurityInfo(
                f.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
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
            if owner.is_null() || !may_own(owner) || dacl.is_null() {
                return Ok(true);
            }
            for i in 0..u32::from((*dacl).AceCount) {
                let mut ace: *mut core::ffi::c_void = null_mut();
                if GetAce(dacl, i, &mut ace) == 0 {
                    return Ok(true);
                }
                let header = &*(ace as *const ACE_HEADER);
                if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
                    continue;
                }
                let kind = header.AceType;
                if !matches!(
                    kind,
                    ACCESS_ALLOWED_ACE_TYPE
                        | ACCESS_ALLOWED_COMPOUND_ACE_TYPE
                        | ACCESS_ALLOWED_OBJECT_ACE_TYPE
                        | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                        | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                ) {
                    continue;
                }
                let mask = std::ptr::read_unaligned((ace as *const u8).add(4) as *const u32);
                if mask & NOT_PRIVATE_RIGHTS == 0 {
                    continue;
                }
                match allowed_sid(ace as *const u8, kind) {
                    Some(sid) if may_access(sid) => {}
                    // Another account, or a compound ACE (impersonation) this code does not read.
                    _ => return Ok(true),
                }
            }
            Ok(false)
        }
    }

    pub fn too_open(_f: &File, path: &Path) -> String {
        format!(
            "{} can be read or changed by other accounts. Keep it readable only by you (SYSTEM and Administrators may stay).",
            path.display()
        )
    }

    /// A symbolic link or junction, by its reparse tag; other reparse points are files.
    pub fn is_link(path: &Path, meta: &std::fs::Metadata) -> bool {
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
            return false;
        }
        let Ok(f) = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
        else {
            return true;
        };
        let mut info = FILE_ATTRIBUTE_TAG_INFO {
            FileAttributes: 0,
            ReparseTag: 0,
        };
        // SAFETY: the buffer is a FILE_ATTRIBUTE_TAG_INFO of the size passed.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                f.as_raw_handle(),
                FileAttributeTagInfo,
                (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        };
        ok == 0
            || matches!(
                info.ReparseTag,
                IO_REPARSE_TAG_SYMLINK | IO_REPARSE_TAG_MOUNT_POINT
            )
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
    fn config_dir_uses_home_config() {
        // XDG_CONFIG_HOME never moves existing settings or pins (spec §5.1).
        for vars in [
            &[("HOME", "/h")][..],
            &[("XDG_CONFIG_HOME", "/x"), ("HOME", "/h")][..],
        ] {
            for app in ["mastersos", "mastersos-sign"] {
                assert_eq!(
                    config_dir_from(app, env(vars)).unwrap(),
                    Path::new("/h/.config").join(app)
                );
            }
        }
        for vars in [
            &[][..],
            &[("HOME", "")][..],
            &[("XDG_CONFIG_HOME", "/x")][..],
        ] {
            let e = config_dir_from("mastersos", env(vars)).unwrap_err();
            assert!(e.to_string().contains("HOME"), "{e}");
        }
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
        assert!(is_link(&link, &std::fs::symlink_metadata(&link).unwrap()));
        assert!(!is_link(
            &target,
            &std::fs::symlink_metadata(&target).unwrap()
        ));
    }

    #[cfg(windows)]
    #[test]
    fn junction_is_a_link() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = t.path().join("link");
        mklink_junction(&link, &target);
        assert!(is_link(&link, &std::fs::symlink_metadata(&link).unwrap()));
        assert!(!is_link(
            &target,
            &std::fs::symlink_metadata(&target).unwrap()
        ));
        // A plain file is not a link either.
        let file = t.path().join("file");
        std::fs::write(&file, "x").unwrap();
        assert!(!is_link(&file, &std::fs::symlink_metadata(&file).unwrap()));
    }

    #[cfg(windows)]
    #[test]
    fn windows_symlink_is_a_link() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("target.txt");
        std::fs::write(&target, "x").unwrap();
        let link = t.path().join("link.txt");
        if !symlink_file_or_skip(&target, &link) {
            return;
        }
        assert!(is_link(&link, &std::fs::symlink_metadata(&link).unwrap()));
    }

    /// Creating a symbolic link needs Developer Mode or administrator rights: without them the
    /// test says so and skips.
    #[cfg(windows)]
    fn symlink_file_or_skip(target: &Path, link: &Path) -> bool {
        const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;
        match std::os::windows::fs::symlink_file(target, link) {
            Ok(()) => true,
            Err(e) if e.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD) => {
                eprintln!("skipped: this account cannot create symbolic links");
                false
            }
            Err(e) => panic!("cannot create {}: {e}", link.display()),
        }
    }

    /// Grant `who` (a SID, so the system language does not matter) `rights` on `path`.
    #[cfg(windows)]
    fn icacls_grant(path: &Path, who: &str, rights: &str) {
        let out = std::process::Command::new("icacls")
            .arg(path)
            .arg("/grant")
            .arg(format!("*{who}:({rights})"))
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
        // Users read, Everyone write: each makes the file not private.
        for (who, rights) in [("S-1-5-32-545", "R"), ("S-1-1-0", "W")] {
            let p = t.path().join(format!("token-{rights}"));
            drop(create_private(&p).unwrap());
            check_private(&p).unwrap();
            assert_eq!(open_school_key(&p).unwrap().1, None);
            icacls_grant(&p, who, rights);
            let e = check_private(&p).unwrap_err().to_string();
            assert!(
                e.contains(&p.display().to_string()) && e.contains("other accounts"),
                "{e}"
            );
            // A school key file with the same access still opens, with the note.
            assert_eq!(open_school_key(&p).unwrap().1, Some(KEY_FILE_NOTE));
            // write_private puts the owner-only access back.
            write_private(&p, b"new").unwrap();
            check_private(&p).unwrap();
        }
        // SYSTEM and Administrators may stay.
        let p = t.path().join("admins");
        drop(create_private(&p).unwrap());
        icacls_grant(&p, "S-1-5-32-544", "F");
        check_private(&p).unwrap();
    }
}
