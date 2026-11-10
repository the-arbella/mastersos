use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use super::assemble::*;
use crate::safefs;

fn vendor(p: &str) -> Policy {
    Policy::VendorAllow { package: p.into() }
}

fn open(p: &Path) -> OwnedFd {
    safefs::open_dir(p, Path::new(""), false).unwrap()
}

/// Writes `rel` under `root` (parents created) with `mode`.
fn put(root: &Path, rel: &str, body: &str, mode: u32) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, body).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
}

fn link(root: &Path, rel: &str, target: &str) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    symlink(target, p).unwrap();
}

fn exists(root: &Path, rel: &str) -> bool {
    fs::symlink_metadata(root.join(rel)).is_ok()
}

fn err<T: std::fmt::Debug>(r: anyhow::Result<T>) -> String {
    format!("{:#}", r.unwrap_err())
}

const TESTNAV_DESKTOP: &str =
    "[Desktop Entry]\nName=TestNav\nComment=TestNav\nExec=/opt/testnav/bin/testnav %u\n\
Icon=/opt/testnav/lib/testnav.png\nTerminal=false\nType=Application\nCategories=Education\n\
MimeType=x-scheme-handler/tnav\n";

/// The shape of the TestNav 1.15.7 package (spec §9).
fn testnav_tree() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    put(r, "opt/testnav/bin/testnav", "#!/bin/sh\n", 0o755);
    put(
        r,
        "opt/testnav/lib/testnav-testnav.desktop",
        TESTNAV_DESKTOP,
        0o644,
    );
    put(r, "opt/testnav/lib/testnav.png", "png", 0o644);
    put(r, "opt/testnav/lib/runtime/lib/libjli.so", "elf", 0o644);
    link(r, "opt/testnav/lib/runtime/lib/libjli.so.1", "libjli.so");
    put(r, "usr/share/doc/testnav/copyright", "c", 0o644);
    t
}

#[test]
fn testnav_layout_keeps_opt() {
    let t = testnav_tree();
    let fd = open(t.path());
    assert_eq!(
        prune(&fd, &vendor("testnav")).unwrap(),
        Vec::<String>::new()
    );
    assert!(exists(t.path(), "opt/testnav/bin/testnav"));
    assert!(exists(t.path(), "opt/testnav/lib/runtime/lib/libjli.so.1"));
    assert!(exists(t.path(), "usr/share/doc/testnav/copyright"));
    let l = pick_launcher(&fd, None).unwrap();
    assert_eq!(l.exec, "/opt/testnav/bin/testnav");
    assert_eq!(l.mime.as_deref(), Some("x-scheme-handler/tnav;"));
    assert_eq!(l.icon.as_deref(), Some("/opt/testnav/lib/testnav.png"));
}

#[test]
fn vendor_usr_lib_systemd_removed() {
    let t = testnav_tree();
    let r = t.path();
    put(
        r,
        "usr/lib/systemd/system/evil.service",
        "[Service]\n",
        0o644,
    );
    put(r, "usr/lib/testnav/data.bin", "d", 0o644);
    put(r, "usr/lib/other/x.so", "x", 0o644);
    put(r, "etc/cron.d/testnav", "x", 0o644);
    put(r, "lib/udev/rules.d/99.rules", "x", 0o644);
    put(r, "usr/sbin/tool", "x", 0o755);
    put(r, "usr/bin/testnav-cli", "x", 0o755);
    fs::create_dir_all(r.join("usr/bin/subdir")).unwrap();
    put(r, "usr/share/fonts/x.ttf", "x", 0o644);
    put(
        r,
        "usr/share/applications/testnav.desktop",
        TESTNAV_DESKTOP,
        0o644,
    );
    put(
        r,
        "usr/share/icons/hicolor/48x48/apps/testnav.png",
        "p",
        0o644,
    );
    put(r, "usr/share/pixmaps/testnav.png", "p", 0o644);
    put(r, "usr/share/man/man1/testnav.1", "m", 0o644);
    put(r, "usr/share/metainfo/testnav.xml", "m", 0o644);
    put(r, "usr/share/mime/packages/testnav.xml", "m", 0o644);
    put(r, "usr/share/mime/mime.cache", "m", 0o644);
    put(r, "usr/share/polkit-1/actions/x.policy", "p", 0o644);
    let fd = open(r);
    let mut removed = prune(&fd, &vendor("testnav")).unwrap();
    removed.sort();
    assert_eq!(
        removed,
        vec![
            "etc",
            "lib",
            "usr/bin/subdir",
            "usr/lib/other",
            "usr/lib/systemd",
            "usr/sbin",
            "usr/share/fonts",
            "usr/share/mime/mime.cache",
            "usr/share/polkit-1",
        ]
    );
    for kept in [
        "usr/lib/testnav/data.bin",
        "usr/bin/testnav-cli",
        "usr/share/applications/testnav.desktop",
        "usr/share/icons/hicolor/48x48/apps/testnav.png",
        "usr/share/pixmaps/testnav.png",
        "usr/share/man/man1/testnav.1",
        "usr/share/metainfo/testnav.xml",
        "usr/share/mime/packages/testnav.xml",
        "opt/testnav/bin/testnav",
    ] {
        assert!(exists(r, kept), "{kept}");
    }
}

#[test]
fn vendor_package_named_like_a_system_dir_is_still_pruned() {
    // usr/lib/<package>/** is allowed, but the deny list still applies: a vendor package called `systemd` gets nothing
    // into /usr/lib/systemd.
    let t = tempfile::tempdir().unwrap();
    put(t.path(), "usr/lib/systemd/system/x.service", "x", 0o644);
    let fd = open(t.path());
    assert_eq!(
        prune(&fd, &vendor("systemd")).unwrap(),
        vec!["usr/lib/systemd"]
    );
    assert!(!exists(t.path(), "usr/lib/systemd"));
    // Package names follow Debian policy; anything else (a path, an empty name) is refused
    for bad in ["", "../etc", "a/b", "Upper", ".", "x"] {
        let e = prune(&fd, &vendor(bad));
        assert!(e.is_err(), "{bad:?}");
    }
}

#[test]
fn allowlisted_dir_with_wrong_type_rejected() {
    // usr/share as a link (or a file) would hide the image's whole /usr/share once merged
    let t = tempfile::tempdir().unwrap();
    fs::create_dir_all(t.path().join("usr")).unwrap();
    link(t.path(), "usr/share", "/usr/share");
    let e = err(prune(&open(t.path()), &vendor("foo")));
    assert!(e.contains("usr/share"), "{e}");
    let t = tempfile::tempdir().unwrap();
    put(t.path(), "opt", "x", 0o644);
    let e = err(prune(&open(t.path()), &Policy::UbuntuDeny));
    assert!(e.contains("opt"), "{e}");
    // A link in the middle of a denied path is refused, not followed
    let t = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    put(outside.path(), "gio/modules/libgiolibproxy.so", "x", 0o644);
    fs::create_dir_all(t.path().join("usr/lib")).unwrap();
    link(
        t.path(),
        "usr/lib/x86_64-linux-gnu",
        outside.path().to_str().unwrap(),
    );
    let e = err(prune(&open(t.path()), &Policy::UbuntuDeny));
    assert!(e.contains("usr/lib/x86_64-linux-gnu"), "{e}");
    assert!(outside
        .path()
        .join("gio/modules/libgiolibproxy.so")
        .exists());
}

#[test]
fn denied_path_that_is_a_link_is_removed_not_followed() {
    let t = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    put(outside.path(), "system/x.service", "x", 0o644);
    fs::create_dir_all(t.path().join("usr/lib")).unwrap();
    link(
        t.path(),
        "usr/lib/systemd",
        outside.path().to_str().unwrap(),
    );
    let fd = open(t.path());
    assert_eq!(
        prune(&fd, &Policy::UbuntuDeny).unwrap(),
        vec!["usr/lib/systemd"]
    );
    assert!(!exists(t.path(), "usr/lib/systemd"));
    assert!(outside.path().join("system/x.service").exists());
}

#[test]
fn ubuntu_gio_module_removed() {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    let lib = "usr/lib/x86_64-linux-gnu";
    for p in [
        "gio/modules/libgiognutls.so",
        "gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-x.so",
        "gtk-3.0/modules/libx.so",
        "gtk-4.0/4.0.0/media/libmedia-gstreamer.so",
        "gstreamer-1.0/libgstx.so",
        "security/pam_x.so",
        "libnss_mdns4_minimal.so.2",
    ] {
        put(r, &format!("{lib}/{p}"), "x", 0o644);
    }
    put(r, &format!("{lib}/libXmu.so.6"), "x", 0o644);
    put(r, &format!("{lib}/gio/other.txt"), "x", 0o644);
    put(r, "usr/bin/xprop", "x", 0o755);
    put(r, "usr/share/doc/x11-utils/copyright", "x", 0o644);
    put(r, "usr/share/applications/xev.desktop", "x", 0o644);
    put(r, "usr/share/dbus-1/system.d/x.conf", "x", 0o644);
    put(
        r,
        "usr/lib/extension-release.d/extension-release.x",
        "x",
        0o644,
    );
    put(r, "lib/systemd/system/x.service", "x", 0o644);
    put(r, "etc/X11/app-defaults/Xmu", "x", 0o644);
    put(r, "var/lib/x", "x", 0o644);
    let fd = open(r);
    let mut removed = prune(&fd, &Policy::UbuntuDeny).unwrap();
    removed.sort();
    assert_eq!(
        removed,
        vec![
            "etc".to_string(),
            "lib".into(),
            "usr/lib/extension-release.d".into(),
            format!("{lib}/gdk-pixbuf-2.0"),
            format!("{lib}/gio/modules"),
            format!("{lib}/gstreamer-1.0"),
            format!("{lib}/gtk-3.0"),
            format!("{lib}/gtk-4.0"),
            format!("{lib}/libnss_mdns4_minimal.so.2"),
            format!("{lib}/security"),
            "usr/share/applications".into(),
            "usr/share/dbus-1".into(),
            "var".into(),
        ]
    );
    assert!(exists(r, &format!("{lib}/libXmu.so.6")));
    assert!(exists(r, &format!("{lib}/gio/other.txt")));
    assert!(exists(r, "usr/bin/xprop"));
    assert!(exists(r, "usr/share/doc/x11-utils/copyright"));
    // Every entry of the deny list is a clean relative path below usr/
    for d in UBUNTU_DENY {
        assert!(
            d.starts_with("usr/") && !d.contains("..") && !d.ends_with('/'),
            "{d}"
        );
    }
}

#[test]
fn absolute_symlink_outside_rejected() {
    for (at, target) in [
        ("usr/bin/x", "/etc/shadow"),
        ("opt/foo/data", "/home/student/evil.so"),
        ("opt/foo/up", "/usr/../etc"),
        ("usr/bin/y", "../../../etc/passwd"),
        ("usr/bin/z", "../../etc/passwd"),
        ("opt/foo/w", "lib/../../../../etc"),
        ("opt/foo/u", "/usr"),
    ] {
        let t = tempfile::tempdir().unwrap();
        fs::create_dir_all(t.path().join("usr/bin")).unwrap();
        fs::create_dir_all(t.path().join("opt/foo/lib")).unwrap();
        link(t.path(), at, target);
        let e = err(prune(&open(t.path()), &vendor("foo")));
        assert!(e.contains(at), "{at} -> {target}: {e}");
    }
}

#[test]
fn links_into_usr_and_opt_accepted() {
    let t = testnav_tree();
    let r = t.path();
    // How vendors expose binaries, both absolute and relative
    link(r, "usr/bin/testnav", "/opt/testnav/bin/testnav");
    link(r, "usr/bin/testnav2", "../../opt/testnav/bin/testnav");
    // Into the image's /usr (signed) is fine too
    link(r, "opt/testnav/lib/sh", "/usr/bin/sh");
    link(r, "usr/lib/testnav/self", "../testnav");
    let fd = open(r);
    assert_eq!(
        prune(&fd, &vendor("testnav")).unwrap(),
        Vec::<String>::new()
    );
    assert!(exists(r, "usr/bin/testnav"));
}

#[test]
fn special_files_rejected() {
    use rustix::fs::{mknodat, FileType, Mode};
    let t = tempfile::tempdir().unwrap();
    fs::create_dir_all(t.path().join("opt/foo")).unwrap();
    let d = open(&t.path().join("opt/foo"));
    mknodat(&d, "pipe", FileType::Fifo, Mode::from_raw_mode(0o644), 0).unwrap();
    let e = err(prune(&open(t.path()), &Policy::UbuntuDeny));
    assert!(e.contains("opt/foo/pipe"), "{e}");
    let t = tempfile::tempdir().unwrap();
    fs::create_dir_all(t.path().join("usr/share")).unwrap();
    let _l = std::os::unix::net::UnixListener::bind(t.path().join("usr/share/sock")).unwrap();
    let e = err(prune(&open(t.path()), &Policy::UbuntuDeny));
    assert!(e.contains("usr/share/sock"), "{e}");
}

#[test]
fn setuid_bit_cleared() {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    put(r, "opt/foo/bin/helper", "x", 0o4755);
    put(r, "usr/bin/tool", "x", 0o2755);
    put(r, "usr/bin/plain", "x", 0o755);
    link(r, "usr/bin/link", "plain");
    let fd = open(r);
    let mut got = strip_setid(&fd).unwrap();
    got.sort();
    assert_eq!(got, vec!["opt/foo/bin/helper", "usr/bin/tool"]);
    for p in ["opt/foo/bin/helper", "usr/bin/tool", "usr/bin/plain"] {
        let m = fs::metadata(r.join(p)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(m, 0o755, "{p}");
    }
    // Nothing left to clear the second time
    assert_eq!(strip_setid(&fd).unwrap(), Vec::<String>::new());
}

/// The image's list of `/usr` next to the factory dir (`usr-paths`): the dpkg paths below plus what no package has.
const USR_PATHS: &str = "d usr\nd usr/bin\nl usr/bin/cat\nf usr/bin/ls\nf usr/bin/mastersos-agent\n\
f usr/bin/mastersos-kiosk\nd usr/lib\nd usr/lib/gcc\nd usr/lib/mastersos\nf usr/lib/mastersos/usr-paths\nd usr/lib/python3\n\
d usr/lib/repart.d\nf usr/lib/repart.d/10-root.conf\nd usr/share\nd usr/share/dconf\nd usr/share/doc\n\
d usr/share/doc/coreutils\nf usr/share/doc/coreutils/copyright\nl usr/share/doc/libfoo1\nd usr/share/empty\n";

fn owned_of(f: &tempfile::TempDir) -> ImageOwned {
    image_owned(&f.path().join("info"), &f.path().join("usr-paths")).unwrap()
}

/// A factory dpkg info dir: `info/*.list` plus the `diversions` file next to it, and `usr-paths`.
fn factory() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    fs::write(t.path().join("usr-paths"), USR_PATHS).unwrap();
    let info = t.path().join("info");
    fs::create_dir_all(&info).unwrap();
    fs::write(
        info.join("coreutils.list"),
        "/.\n/usr\n/usr/bin\n/usr/bin/ls\n/bin\n/bin/cat\n/usr/share\n/usr/share/doc\n/usr/share/doc/coreutils\n\
/usr/share/doc/coreutils/copyright\n",
    )
    .unwrap();
    fs::write(info.join("libfoo1:amd64.list"), "/usr/share/doc/libfoo1\n").unwrap();
    fs::write(info.join("libfoo1:amd64.md5sums"), "/usr/not/a/list\n").unwrap();
    fs::write(
        t.path().join("diversions"),
        "/usr/bin/gnome-session\n/usr/bin/gnome-session.distrib\nmastersos-session\n",
    )
    .unwrap();
    t
}

#[test]
fn image_file_dropped() {
    let f = factory();
    let owned = owned_of(&f);
    for p in [
        "usr/bin/ls",
        "usr/bin/cat",
        "usr/share/doc/libfoo1",
        "usr/bin/gnome-session.distrib",
    ] {
        assert!(owned.contains(p), "{p}: {owned:?}");
    }
    assert!(!owned.contains("usr/not/a/list"));
    assert!(owned.contains("usr/bin/mastersos-agent"), "from usr-paths");
    assert!(!owned.contains("") && !owned.contains("."));

    let opt = tempfile::tempdir().unwrap();
    put(opt.path(), "google/chrome/chrome", "x", 0o755);
    put(opt.path(), "plainfile", "x", 0o644);

    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    put(r, "usr/bin/ls", "x", 0o755);
    link(r, "usr/bin/cat", "ls");
    put(r, "usr/bin/gnome-session.distrib", "x", 0o755);
    put(r, "usr/bin/xprop", "x", 0o755);
    put(r, "usr/share/doc/coreutils/changelog.gz", "x", 0o644);
    put(r, "usr/share/doc/coreutils/copyright", "x", 0o644);
    // In the image this is a link (it has nothing below it in the lists): our directory would hide it
    put(r, "usr/share/doc/libfoo1/copyright", "x", 0o644);
    put(r, "opt/google/chrome/chrome", "x", 0o755);
    put(r, "opt/google/new/x", "x", 0o644);
    put(r, "opt/plainfile/x", "x", 0o644);
    let fd = open(r);
    let mut dropped = drop_image_files(&fd, &owned, opt.path()).unwrap();
    dropped.sort();
    assert_eq!(
        dropped,
        vec![
            "opt/google/chrome/chrome",
            "opt/plainfile",
            "usr/bin/cat",
            "usr/bin/gnome-session.distrib",
            "usr/bin/ls",
            "usr/share/doc/coreutils/copyright",
            "usr/share/doc/libfoo1",
        ]
    );
    for kept in [
        "usr/bin/xprop",
        "usr/share/doc/coreutils/changelog.gz",
        "opt/google/new/x",
    ] {
        assert!(exists(r, kept), "{kept}");
    }
    // A missing /opt is simply empty
    assert_eq!(
        drop_image_files(&fd, &owned, &opt.path().join("missing")).unwrap(),
        Vec::<String>::new()
    );
}

#[test]
fn image_owned_needs_the_lists() {
    let f = factory();
    let up = f.path().join("usr-paths");
    assert!(image_owned(&f.path().join("missing"), &up).is_err());
    // A dir with no .list at all is not a dpkg database
    let empty = tempfile::tempdir().unwrap();
    assert!(image_owned(empty.path(), &up).is_err());
}

#[test]
fn image_owned_needs_the_list_of_usr() {
    let f = factory();
    let info = f.path().join("info");
    let e = err(image_owned(&info, &f.path().join("missing")));
    assert!(
        e.contains("missing") && e.contains("no .deb app is assembled"),
        "{e}"
    );
    for bad in [
        "",
        "d usr\nf usr/bin/x y\nx\n",
        "d usr\nff usr/bin/x\n",
        "d usr\nf /usr/bin/x\n",
        "d usr\nf usr/../etc/shadow\n",
        "d usr\nf etc/passwd\n",
        "d usr\nf usr//bin\n",
        "f usr/bin/x\n",
    ] {
        fs::write(f.path().join("bad"), bad).unwrap();
        assert!(
            image_owned(&info, &f.path().join("bad")).is_err(),
            "{bad:?}"
        );
    }
    // a name with a space is fine: only the first space separates the type
    fs::write(f.path().join("ok"), "d usr\nd usr/share\nf usr/share/a b\n").unwrap();
    assert!(image_owned(&info, &f.path().join("ok"))
        .unwrap()
        .contains("usr/share/a b"));
}

#[test]
fn files_outside_dpkg_are_not_covered() {
    let f = factory();
    let owned = owned_of(&f);
    let opt = tempfile::tempdir().unwrap();
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    // run as root after every merge; in no dpkg list
    put(r, "usr/bin/mastersos-agent", "x", 0o755);
    // a directory where the image has a file (from mkosi.extra)
    put(r, "usr/bin/mastersos-kiosk/x", "x", 0o755);
    // a file where the image has a directory no package owns, and a file over one of its files
    put(r, "usr/share/dconf", "x", 0o644);
    put(r, "usr/lib/repart.d/10-root.conf", "x", 0o644);
    // new things inside image directories merge, also into an empty one
    put(r, "usr/lib/repart.d/99-new.conf", "x", 0o644);
    put(r, "usr/share/empty/new", "x", 0o644);
    put(r, "usr/bin/vendor-tool", "x", 0o755);
    let fd = open(r);
    let mut dropped = drop_image_files(&fd, &owned, opt.path()).unwrap();
    dropped.sort();
    assert_eq!(
        dropped,
        vec![
            "usr/bin/mastersos-agent",
            "usr/bin/mastersos-kiosk",
            "usr/lib/repart.d/10-root.conf",
            "usr/share/dconf",
        ]
    );
    for kept in [
        "usr/lib/repart.d/99-new.conf",
        "usr/share/empty/new",
        "usr/bin/vendor-tool",
    ] {
        assert!(exists(r, kept), "{kept}");
    }
}

#[test]
fn vendor_lib_dir_only_when_the_image_has_none() {
    let f = factory();
    let owned = owned_of(&f);
    // a name the image has but prune does not reserve (gcc): kept by prune, dropped here
    for (package, keeps) in [("gcc", false), ("testnav", true)] {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        put(r, &format!("usr/lib/{package}/x.py"), "x", 0o644);
        let fd = open(r);
        prune(&fd, &vendor(package)).unwrap();
        assert!(
            exists(r, &format!("usr/lib/{package}/x.py")),
            "{package}: kept by prune"
        );
        let got = drop_image_lib_dir(&fd, package, &owned).unwrap();
        assert_eq!(got.is_none(), keeps, "{package}");
        assert_eq!(exists(r, &format!("usr/lib/{package}")), keeps, "{package}");
    }
    // python3 is reserved: prune already removed it, nothing left to drop
    let t = tempfile::tempdir().unwrap();
    put(t.path(), "usr/lib/python3/x.py", "x", 0o644);
    let fd = open(t.path());
    assert_eq!(
        prune(&fd, &vendor("python3")).unwrap(),
        vec!["usr/lib/python3"]
    );
    assert_eq!(drop_image_lib_dir(&fd, "python3", &owned).unwrap(), None);
    // not a Debian package name: refused, never a directory name
    let t = tempfile::tempdir().unwrap();
    put(t.path(), "usr/lib/x86_64-linux-gnu/libevil.so", "x", 0o644);
    let fd = open(t.path());
    assert!(err(prune(&fd, &vendor("x86_64-linux-gnu"))).contains("malformed package name"));
    assert!(drop_image_lib_dir(&fd, "x86_64-linux-gnu", &owned).is_err());
}

#[test]
fn owners_and_write_bits_normalized() {
    use std::os::unix::fs::MetadataExt;
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    put(r, "opt/x/bin/x", "x", 0o777);
    put(r, "opt/x/data", "x", 0o666);
    put(r, "opt/x/keep", "x", 0o644);
    fs::create_dir_all(r.join("opt/x/shared")).unwrap();
    fs::set_permissions(r.join("opt/x/shared"), fs::Permissions::from_mode(0o777)).unwrap();
    link(r, "opt/x/link", "/etc/passwd");
    let root = rustix::process::geteuid().is_root();
    if root {
        // a vendor file owned by a local user (uid 1000), as dpkg-deb -x as root keeps it
        for p in ["opt/x/data", "opt/x/shared", "opt/x/link"] {
            std::os::unix::fs::lchown(r.join(p), Some(1000), Some(1000)).unwrap();
        }
    }
    let (uid, gid) = (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    let fd = open(r);
    assert!(normalize_owners(&fd, uid, gid).unwrap() >= 3);
    for (p, mode) in [
        ("opt/x/bin/x", 0o755),
        ("opt/x/data", 0o644),
        ("opt/x/keep", 0o644),
        ("opt/x/shared", 0o755),
    ] {
        let m = fs::symlink_metadata(r.join(p)).unwrap();
        assert_eq!(m.mode() & 0o7777, mode, "{p}");
        assert_eq!((m.uid(), m.gid()), (uid, gid), "{p}");
    }
    let l = fs::symlink_metadata(r.join("opt/x/link")).unwrap();
    assert!(l.file_type().is_symlink());
    assert_eq!((l.uid(), l.gid()), (uid, gid));
    // the link was not followed
    assert_ne!(fs::metadata("/etc/passwd").unwrap().uid(), 1000);
    // nothing left to change
    assert_eq!(normalize_owners(&fd, uid, gid).unwrap(), 0);
}

fn desktop(exec: &str) -> String {
    format!("[Desktop Entry]\nType=Application\nName=X\nExec={exec}\n")
}

#[test]
fn two_launchers_need_exec() {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    put(r, "opt/foo/bin/foo", "x", 0o755);
    put(r, "opt/foo/bin/bar", "x", 0o755);
    put(
        r,
        "usr/share/applications/foo.desktop",
        &desktop("/opt/foo/bin/foo %U"),
        0o644,
    );
    put(
        r,
        "usr/share/applications/bar.desktop",
        &desktop("/opt/foo/bin/bar"),
        0o644,
    );
    // Not counted: hidden, NoDisplay, not an application, another group, a link
    put(
        r,
        "usr/share/applications/h.desktop",
        &(desktop("/opt/foo/bin/foo") + "Hidden=true\n"),
        0o644,
    );
    put(
        r,
        "usr/share/applications/n.desktop",
        &(desktop("/opt/foo/bin/foo") + "NoDisplay=true\n"),
        0o644,
    );
    put(
        r,
        "usr/share/applications/l.desktop",
        "[Desktop Entry]\nType=Link\nName=L\nURL=https://example.org\n",
        0o644,
    );
    put(
        r,
        "usr/share/applications/g.desktop",
        "[Desktop Action x]\nType=Application\nName=G\nExec=/opt/foo/bin/foo\n",
        0o644,
    );
    link(r, "usr/share/applications/k.desktop", "foo.desktop");
    let fd = open(r);
    let e = err(pick_launcher(&fd, None));
    assert!(
        e.contains("no single launcher (found 2); write exec"),
        "{e}"
    );
    let l = pick_launcher(&fd, Some("/opt/foo/bin/bar")).unwrap();
    assert_eq!(
        l,
        Launcher {
            exec: "/opt/foo/bin/bar".into(),
            icon: None,
            mime: None
        }
    );
    // None at all
    let t = tempfile::tempdir().unwrap();
    put(t.path(), "opt/foo/bin/foo", "x", 0o755);
    let e = err(pick_launcher(&open(t.path()), None));
    assert!(
        e.contains("no single launcher (found 0); write exec"),
        "{e}"
    );
}

#[test]
fn launcher_exec_must_be_in_the_tree_and_executable() {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    put(r, "opt/foo/bin/foo", "x", 0o755);
    put(r, "opt/foo/lib/data", "x", 0o644);
    link(r, "usr/bin/foo", "../../opt/foo/bin/foo");
    link(r, "usr/bin/foo-abs", "/opt/foo/bin/foo");
    link(r, "usr/bin/away", "../../../../usr/bin/sh");
    link(r, "usr/bin/sys", "/usr/bin/sh");
    let fd = open(r);
    for ok in ["/opt/foo/bin/foo", "/usr/bin/foo", "/usr/bin/foo-abs"] {
        assert_eq!(pick_launcher(&fd, Some(ok)).unwrap().exec, ok);
    }
    for bad in [
        "/opt/foo/lib/data",
        "/opt/foo/bin/missing",
        "/opt/foo/bin",
        "/usr/bin/away",
        "/usr/bin/sys",
        "/opt/foo/../foo/bin/foo",
        "opt/foo/bin/foo",
        "/etc/foo",
        "/opt/foo/bin/foo --flag",
    ] {
        assert!(pick_launcher(&fd, Some(bad)).is_err(), "{bad}");
    }
    // The .desktop's Exec goes through the same check; a bare name means /usr/bin/<name>
    put(
        r,
        "usr/share/applications/foo.desktop",
        &desktop("foo %F"),
        0o644,
    );
    assert_eq!(pick_launcher(&fd, None).unwrap().exec, "/usr/bin/foo");
    put(
        r,
        "usr/share/applications/foo.desktop",
        &desktop("/opt/foo/lib/data"),
        0o644,
    );
    assert!(pick_launcher(&fd, None).is_err());
    put(
        r,
        "usr/share/applications/foo.desktop",
        &desktop("\"/opt/foo/bin/foo\" --private %u"),
        0o644,
    );
    assert_eq!(pick_launcher(&fd, None).unwrap().exec, "/opt/foo/bin/foo");
}

fn written(r: &Path, id: &str) -> String {
    fs::read_to_string(r.join(format!("usr/share/applications/mastersos-app-{id}.desktop")))
        .unwrap()
}

#[test]
fn desktop_written_and_original_removed() {
    let t = testnav_tree();
    let r = t.path();
    put(
        r,
        "usr/share/applications/testnav.desktop",
        TESTNAV_DESKTOP,
        0o644,
    );
    link(r, "usr/share/applications/alias.desktop", "testnav.desktop");
    put(r, "usr/share/applications/mimeinfo.cache", "x", 0o644);
    put(r, "usr/share/applications/mimeapps.list", "x", 0o644);
    put(
        r,
        "usr/share/applications/sub/x.desktop",
        TESTNAV_DESKTOP,
        0o644,
    );
    let fd = open(r);
    let l = pick_launcher(&fd, None).unwrap();
    write_desktop(&fd, "testnav", "TestNav", &l, None, true).unwrap();
    assert_eq!(
        written(r, "testnav"),
        "[Desktop Entry]\nType=Application\nName=TestNav\nExec=/opt/testnav/bin/testnav %U\n\
Icon=/opt/testnav/lib/testnav.png\nMimeType=x-scheme-handler/tnav;\nTerminal=false\nNoDisplay=true\n"
    );
    assert!(!exists(r, "usr/share/applications/testnav.desktop"));
    assert!(!exists(r, "usr/share/applications/alias.desktop"));
    // Only ours is left: no cache, no defaults list, no subdirectory GLib would turn into launchers
    assert_eq!(
        fs::read_dir(r.join("usr/share/applications"))
            .unwrap()
            .count(),
        1
    );
    // The vendor's own copy outside usr/share/applications is not shown by anyone: left alone
    assert!(exists(r, "opt/testnav/lib/testnav-testnav.desktop"));
    // IT's icon wins; not kiosk → no NoDisplay; no MimeType → no field code
    let l = Launcher {
        exec: "/opt/my app/run".into(),
        icon: Some("vendor".into()),
        mime: None,
    };
    write_desktop(
        &fd,
        "my-app",
        "My \\ App",
        &l,
        Some("/var/lib/mastersos/icons/my-app.png"),
        false,
    )
    .unwrap();
    assert_eq!(
        written(r, "my-app"),
        "[Desktop Entry]\nType=Application\nName=My \\\\ App\nExec=\"/opt/my app/run\"\n\
Icon=/var/lib/mastersos/icons/my-app.png\nTerminal=false\n"
    );
    // Writing again replaces our own file instead of counting it as the vendor's
    write_desktop(&fd, "my-app", "My App", &l, None, false).unwrap();
    assert!(written(r, "my-app").contains("Name=My App\n"));
}

#[test]
fn desktop_values_cannot_inject_lines() {
    let t = tempfile::tempdir().unwrap();
    let fd = open(t.path());
    let good = Launcher {
        exec: "/opt/foo/foo".into(),
        icon: Some("foo".into()),
        mime: Some("text/plain;".into()),
    };
    write_desktop(&fd, "foo", "Foo", &good, None, false).unwrap();
    let bad_launchers = [
        Launcher {
            exec: "/opt/foo/foo\nExec=/bin/sh".into(),
            ..good.clone()
        },
        Launcher {
            exec: "/opt/foo/foo%k".into(),
            ..good.clone()
        },
        Launcher {
            exec: "relative".into(),
            ..good.clone()
        },
        Launcher {
            icon: Some("foo\r\nHidden=false".into()),
            ..good.clone()
        },
        Launcher {
            mime: Some("text/plain\nX=1".into()),
            ..good.clone()
        },
        Launcher {
            mime: Some("text plain;".into()),
            ..good.clone()
        },
    ];
    for l in &bad_launchers {
        assert!(
            write_desktop(&fd, "foo", "Foo", l, None, false).is_err(),
            "{l:?}"
        );
    }
    for name in ["Foo\nExec=/bin/sh", "Foo\t", "", "Foo\u{7f}"] {
        assert!(
            write_desktop(&fd, "foo", name, &good, None, false).is_err(),
            "{name:?}"
        );
    }
    for id in ["Foo", "../x", "", "a/b"] {
        assert!(
            write_desktop(&fd, id, "Foo", &good, None, false).is_err(),
            "{id:?}"
        );
    }
    assert!(write_desktop(&fd, "foo", "Foo", &good, Some("x\ny"), false).is_err());
    // The good one is still what is on disk
    assert!(written(t.path(), "foo").contains("Exec=/opt/foo/foo %U\n"));
}

#[test]
fn release_content() {
    let t = tempfile::tempdir().unwrap();
    let fd = open(t.path());
    write_release(&fd, "app-testnav", "20261110.1").unwrap();
    assert_eq!(
        fs::read_to_string(
            t.path()
                .join("usr/lib/extension-release.d/extension-release.app-testnav")
        )
        .unwrap(),
        "ID=ubuntu\nSYSEXT_LEVEL=20261110.1\nSYSEXT_SCOPE=system\n"
    );
    for (name, level) in [
        ("app-testnav", "2026\n1"),
        ("app-testnav", ""),
        ("app-testnav", "a b"),
        ("../x", "1"),
        ("", "1"),
        ("app/x", "1"),
    ] {
        assert!(
            write_release(&fd, name, level).is_err(),
            "{name:?} {level:?}"
        );
    }
}

#[test]
fn overlap_between_app_and_deps_rejected() {
    let deps = tempfile::tempdir().unwrap();
    let app = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    put(deps.path(), "usr/bin/xprop", "x", 0o755);
    put(
        deps.path(),
        "usr/lib/x86_64-linux-gnu/libXmu.so.6",
        "x",
        0o644,
    );
    put(app.path(), "opt/testnav/bin/testnav", "x", 0o755);
    put(app.path(), "usr/bin/testnav", "x", 0o755);
    put(other.path(), "opt/other/bin/other", "x", 0o755);
    let (d, a, o) = (open(deps.path()), open(app.path()), open(other.path()));
    // Shared directories (usr, usr/bin, opt) merge
    check_overlaps(&[
        ("app-deps".into(), &d),
        ("app-testnav".into(), &a),
        ("app-other".into(), &o),
    ])
    .unwrap();
    put(app.path(), "usr/bin/xprop", "y", 0o755);
    let e = err(check_overlaps(&[
        ("app-deps".into(), &d),
        ("app-testnav".into(), &a),
    ]));
    assert!(
        e.contains("usr/bin/xprop") && e.contains("app-deps") && e.contains("app-testnav"),
        "{e}"
    );
    // A file in one tree where the other has a directory also overlaps
    put(other.path(), "opt/testnav", "x", 0o644);
    let e = err(check_overlaps(&[
        ("app-testnav".into(), &a),
        ("app-other".into(), &o),
    ]));
    assert!(e.contains("opt/testnav"), "{e}");
}

#[test]
fn deps_link_into_etc_accepted_vendor_refused() {
    let mk = || {
        let t = tempfile::tempdir().unwrap();
        link(t.path(), "usr/lib/ssl/openssl.cnf", "/etc/ssl/openssl.cnf");
        link(t.path(), "usr/lib/ssl/certs", "../../../etc/ssl/certs");
        t
    };
    let t = mk();
    assert_eq!(
        prune(&open(t.path()), &Policy::UbuntuDeny).unwrap(),
        Vec::<String>::new()
    );
    assert!(exists(t.path(), "usr/lib/ssl/openssl.cnf"));
    assert!(exists(t.path(), "usr/lib/ssl/certs"));
    // The same link from a vendor package (in its own usr/lib/<package>) refuses the package
    let t = tempfile::tempdir().unwrap();
    link(
        t.path(),
        "usr/lib/sslapp/openssl.cnf",
        "/etc/ssl/openssl.cnf",
    );
    let e = err(prune(&open(t.path()), &vendor("sslapp")));
    assert!(e.contains("usr/lib/sslapp/"), "{e}");
    // a vendor package called ssl gets no usr/lib/ssl at all (a reserved name)
    let t = mk();
    assert_eq!(
        prune(&open(t.path()), &vendor("ssl")).unwrap(),
        vec!["usr/lib/ssl"]
    );
}

#[test]
fn deps_link_outside_dropped() {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    link(r, "usr/lib/foo/tmp", "/tmp/x");
    link(r, "usr/lib/foo/home", "/home/student/evil.so");
    link(r, "usr/lib/foo/up", "../../../../etc");
    link(r, "usr/lib/foo/mid", "a/../../../../etc");
    link(r, "usr/lib/foo/ok", "/usr/lib/x86_64-linux-gnu/libfoo.so.1");
    put(r, "usr/lib/foo/data", "x", 0o644);
    let mut removed = prune(&open(r), &Policy::UbuntuDeny).unwrap();
    removed.sort();
    assert_eq!(
        removed,
        vec![
            "usr/lib/foo/home",
            "usr/lib/foo/mid",
            "usr/lib/foo/tmp",
            "usr/lib/foo/up"
        ]
    );
    assert!(exists(r, "usr/lib/foo/ok"));
    assert!(exists(r, "usr/lib/foo/data"));
    // Special files still refuse a dependency tree (special_files_rejected), links do not
}

#[test]
fn applications_dir_holds_only_launchers() {
    let fill = |r: &Path| {
        put(
            r,
            "usr/share/applications/foo.desktop",
            &desktop("/opt/foo/bin/foo"),
            0o644,
        );
        put(
            r,
            "usr/share/applications/sub/x.desktop",
            &desktop("/opt/foo/bin/foo"),
            0o644,
        );
        put(r, "usr/share/applications/mimeapps.list", "x", 0o644);
        put(r, "usr/share/applications/defaults.list", "x", 0o644);
        put(r, "opt/foo/bin/foo", "x", 0o755);
    };
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    fill(r);
    let fd = open(r);
    let mut removed = prune(&fd, &vendor("foo")).unwrap();
    removed.sort();
    assert_eq!(
        removed,
        vec![
            "usr/share/applications/defaults.list",
            "usr/share/applications/mimeapps.list",
            "usr/share/applications/sub",
        ]
    );
    assert!(exists(r, "usr/share/applications/foo.desktop"));
    // Whatever is there by the time we write ours goes too
    put(r, "usr/share/applications/late/y.desktop", "x", 0o644);
    put(r, "usr/share/applications/mimeapps.list", "x", 0o644);
    let l = pick_launcher(&fd, None).unwrap();
    write_desktop(&fd, "foo", "Foo", &l, None, true).unwrap();
    let left: Vec<String> = fs::read_dir(r.join("usr/share/applications"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(left, vec!["mastersos-app-foo.desktop"]);
    // Dependencies bring no launchers, lists or subdirectories at all
    let t = tempfile::tempdir().unwrap();
    fill(t.path());
    let removed = prune(&open(t.path()), &Policy::UbuntuDeny).unwrap();
    assert!(
        removed.contains(&"usr/share/applications".to_string()),
        "{removed:?}"
    );
    assert!(!exists(t.path(), "usr/share/applications"));
}

#[test]
fn generated_caches_dropped() {
    let fill = |r: &Path| {
        put(
            r,
            "usr/share/glib-2.0/schemas/gschemas.compiled",
            "x",
            0o644,
        );
        put(r, "usr/share/icons/hicolor/icon-theme.cache", "x", 0o644);
        put(r, "usr/share/icons/hicolor/48x48/apps/foo.png", "x", 0o644);
        put(r, "usr/share/icons/Adwaita/icon-theme.cache", "x", 0o644);
        put(r, "usr/share/mime/mime.cache", "x", 0o644);
        put(r, "usr/share/mime/globs2", "x", 0o644);
        put(r, "usr/share/mime/text/x-foo.xml", "x", 0o644);
        put(r, "usr/share/mime/packages/foo.xml", "x", 0o644);
        put(r, "usr/share/mime/packages/README", "x", 0o644);
        put(r, "usr/share/doc/foo/copyright", "x", 0o644);
    };
    // Dependencies
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    fill(r);
    put(r, "usr/lib/locale/locale-archive", "x", 0o644);
    put(r, "usr/lib/x86_64-linux-gnu/libfoo.so.1", "x", 0o644);
    put(r, "usr/share/fonts/truetype/foo/foo.ttf", "x", 0o644);
    put(r, "usr/share/fonts/truetype/foo/.uuid", "x", 0o644);
    put(r, "usr/share/fonts/truetype/fonts.cache-9", "x", 0o644);
    let mut removed = prune(&open(r), &Policy::UbuntuDeny).unwrap();
    removed.sort();
    assert_eq!(
        removed,
        vec![
            "usr/lib/locale/locale-archive",
            "usr/share/fonts/truetype/fonts.cache-9",
            "usr/share/fonts/truetype/foo/.uuid",
            "usr/share/glib-2.0/schemas",
            "usr/share/icons/Adwaita/icon-theme.cache",
            "usr/share/icons/hicolor/icon-theme.cache",
            "usr/share/mime/globs2",
            "usr/share/mime/mime.cache",
            "usr/share/mime/packages/README",
            "usr/share/mime/text",
        ]
    );
    for kept in [
        "usr/share/icons/hicolor/48x48/apps/foo.png",
        "usr/share/mime/packages/foo.xml",
        "usr/share/fonts/truetype/foo/foo.ttf",
        "usr/lib/x86_64-linux-gnu/libfoo.so.1",
        "usr/share/doc/foo/copyright",
    ] {
        assert!(exists(r, kept), "{kept}");
    }
    // Vendor package: glib-2.0 and the generated mime files are outside the allowlist, the icon caches go by name
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    fill(r);
    let mut removed = prune(&open(r), &vendor("foo")).unwrap();
    removed.sort();
    assert_eq!(
        removed,
        vec![
            "usr/share/glib-2.0",
            "usr/share/icons/Adwaita/icon-theme.cache",
            "usr/share/icons/hicolor/icon-theme.cache",
            "usr/share/mime/globs2",
            "usr/share/mime/mime.cache",
            "usr/share/mime/packages/README",
            "usr/share/mime/text",
        ]
    );
    assert!(!exists(r, "usr/share/glib-2.0/schemas/gschemas.compiled"));
    assert!(exists(r, "usr/share/mime/packages/foo.xml"));
    assert!(exists(r, "usr/share/icons/hicolor/48x48/apps/foo.png"));
}

#[test]
fn deny_list_has_the_review_additions() {
    for d in [
        "usr/share/thumbnailers",
        "usr/share/gvfs/mounts",
        "usr/share/ibus/component",
        "usr/share/gnome/applications",
        "usr/share/factory",
    ] {
        assert!(UBUNTU_DENY.contains(&d), "{d}");
    }
    let t = tempfile::tempdir().unwrap();
    put(
        t.path(),
        "usr/share/thumbnailers/foo.thumbnailer",
        "x",
        0o644,
    );
    put(t.path(), "usr/share/factory/etc/passwd", "x", 0o644);
    let mut removed = prune(&open(t.path()), &Policy::UbuntuDeny).unwrap();
    removed.sort();
    assert_eq!(removed, vec!["usr/share/factory", "usr/share/thumbnailers"]);
}

#[test]
fn vendor_named_like_a_systemd_search_dir_gets_no_lib_dir() {
    // systemd reads /usr/lib/userdb (user records), /usr/lib/credstore (credentials), /usr/lib/extensions (sysext
    // images) …: a vendor package picking such a Package: name must not fill it through usr/lib/<package>
    for (pkg, file) in [
        ("userdb", "evil.user"),
        ("credstore", "evil.cred"),
        ("credstore.encrypted", "evil.cred"),
        ("extensions", "evil.raw"),
        ("confexts", "evil.raw"),
        ("pcrlock.d", "evil.pcrlock"),
        ("repart.d", "00-evil.conf"),
    ] {
        let t = testnav_tree();
        let rel = format!("usr/lib/{pkg}/{file}");
        put(t.path(), &rel, "x", 0o644);
        let removed = prune(&open(t.path()), &vendor(pkg)).unwrap();
        assert_eq!(removed, vec![format!("usr/lib/{pkg}")], "{pkg}");
        assert!(!exists(t.path(), &format!("usr/lib/{pkg}")), "{pkg}");
        assert!(exists(t.path(), "opt/testnav/bin/testnav"), "{pkg}");
    }
}

#[test]
fn reserved_package_names_get_no_lib_dir() {
    // Names system programs load from, even where the deny list has no entry (python3.12, perl5, locale)
    for pkg in [
        "python3",
        "python3.12",
        "perl",
        "perl5",
        "locale",
        "systemd",
        "udev",
        "security",
        "modules",
        "firmware",
        "kernel",
        "os-release",
        "pam.d",
        "ssl",
        "apt",
        "dpkg",
        "gnupg",
        "gdm3",
        "openssh",
    ] {
        let t = tempfile::tempdir().unwrap();
        put(t.path(), &format!("usr/lib/{pkg}/x"), "x", 0o644);
        let removed = prune(&open(t.path()), &vendor(pkg)).unwrap();
        assert_eq!(removed, vec![format!("usr/lib/{pkg}")], "{pkg}");
        assert!(!exists(t.path(), &format!("usr/lib/{pkg}")), "{pkg}");
    }
    // an ordinary name keeps its directory
    let t = tempfile::tempdir().unwrap();
    put(t.path(), "usr/lib/testnav/data.bin", "d", 0o644);
    assert_eq!(
        prune(&open(t.path()), &vendor("testnav")).unwrap(),
        Vec::<String>::new()
    );
    assert!(exists(t.path(), "usr/lib/testnav/data.bin"));
}

#[test]
fn every_usr_lib_name_of_the_deny_list_is_reserved() {
    // derived from UBUNTU_DENY: the two lists cannot drift
    for d in UBUNTU_DENY {
        let Some(rest) = d.strip_prefix("usr/lib/") else {
            continue;
        };
        let first = rest.split('/').next().unwrap();
        let name = first.replace('*', "x");
        assert!(reserved_lib_name(&name), "{d}");
    }
    for name in [
        "x86_64-linux-gnu",
        "python3.12",
        "perl5",
        "systemd",
        "udev",
        "security",
        "pam.d",
        "modules",
        "firmware",
        "kernel",
        "os-release",
        "extension-release.d",
        "locale",
        "userdb",
        "credstore",
        "sysupdate.d",
        "ssl",
        "apt",
        "dpkg",
        "gnupg",
        "gdm3",
        "openssh",
    ] {
        assert!(reserved_lib_name(name), "{name}");
    }
    for name in ["testnav", "safeexambrowser", "google-chrome"] {
        assert!(!reserved_lib_name(name), "{name}");
    }
}

#[test]
fn deps_lose_systemd_search_dirs() {
    for d in [
        "usr/lib/userdb",
        "usr/lib/credstore",
        "usr/lib/credstore.encrypted",
        "usr/lib/extensions",
        "usr/lib/confexts",
        "usr/lib/portables",
        "usr/lib/machines",
        "usr/lib/repart.d",
        "usr/lib/sysupdate.d",
        "usr/lib/pcrlock.d",
        "usr/lib/clock-epoch",
        "usr/lib/motd.d",
        "usr/lib/issue.d",
    ] {
        let t = tempfile::tempdir().unwrap();
        put(t.path(), &format!("{d}/x"), "x", 0o644);
        put(
            t.path(),
            "usr/lib/x86_64-linux-gnu/libfoo.so.1",
            "elf",
            0o644,
        );
        let removed = prune(&open(t.path()), &Policy::UbuntuDeny).unwrap();
        assert_eq!(removed, vec![d.to_string()], "{d}");
        assert!(exists(t.path(), "usr/lib/x86_64-linux-gnu/libfoo.so.1"));
    }
    // a component's own sysupdate directory too (sysupdate.<component>.d)
    let t = tempfile::tempdir().unwrap();
    put(t.path(), "usr/lib/sysupdate.foo.d/x.transfer", "x", 0o644);
    assert_eq!(
        prune(&open(t.path()), &Policy::UbuntuDeny).unwrap(),
        vec!["usr/lib/sysupdate.foo.d"]
    );
}
