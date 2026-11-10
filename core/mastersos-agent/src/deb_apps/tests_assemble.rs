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
        let e = err(prune(&open(t.path()), &Policy::UbuntuDeny));
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

/// A factory dpkg info dir: `info/*.list` plus the `diversions` file next to it.
fn factory() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
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
    let owned = image_owned(&f.path().join("info")).unwrap();
    for p in [
        "usr/bin/ls",
        "usr/bin/cat",
        "usr/share/doc/libfoo1",
        "usr/bin/gnome-session.distrib",
    ] {
        assert!(owned.contains(p), "{p}: {owned:?}");
    }
    assert!(!owned.contains("usr/not/a/list"));
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
    let f = tempfile::tempdir().unwrap();
    assert!(image_owned(&f.path().join("missing")).is_err());
    // A dir with no .list at all is not a dpkg database
    assert!(image_owned(f.path()).is_err());
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
    assert!(exists(r, "usr/share/applications/mimeinfo.cache"));
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
