#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

const BOOT: &str = "0123456789abcdef0123456789abcdef";
const INV: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const INV2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const GREETER: &str = "gdm-greeter";
const VICTIM: &str = "victim@school.ac.th";
const ATTACKER: &str = "attacker@school.ac.th";

fn me() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn owners() -> Owners {
    Owners {
        root: me(),
        greeter: me(),
    }
}

fn url(email: &str) -> Vec<u8> {
    format!(
        "https://auth.school.ac.th/oauth/v2/authorize?client_id=1&login_hint={}&state=x\n",
        email.replace('@', "%40")
    )
    .into_bytes()
}

struct Root {
    _t: tempfile::TempDir,
    root: PathBuf,
}

impl Root {
    fn new() -> Root {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().to_path_buf();
        fs::create_dir_all(root.join("run/user")).unwrap();
        fs::create_dir_all(root.join("tmp")).unwrap();
        Root { _t: t, root }
    }

    /// The card's private /tmp with a Cookies file holding `content`.
    fn card(&self, instance: &str, content: &[u8]) -> PathBuf {
        let outer = self.root.join(format!(
            "tmp/systemd-private-{BOOT}-{CARD_UNIT}@{instance}.service-Ab12Cd"
        ));
        let default = outer.join("tmp").join(CARD_PROFILE).join("Default");
        fs::create_dir_all(&default).unwrap();
        fs::set_permissions(&outer, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(default.join("Cookies"), content).unwrap();
        outer
    }

    fn drop_card(&self, instance: &str) {
        let outer = self.root.join(format!(
            "tmp/systemd-private-{BOOT}-{CARD_UNIT}@{instance}.service-Ab12Cd"
        ));
        fs::remove_dir_all(outer).unwrap();
    }

    fn handoff(&self) -> PathBuf {
        self.root.join(HANDOFF_REL)
    }

    fn private(&self, name: &str) -> PathBuf {
        self.handoff().join(PRIVATE).join(name)
    }

    fn delivered(&self, uid: u32) -> PathBuf {
        self.handoff().join(uid.to_string())
    }

    fn begin(&self, email: &str, inv: &str) -> Option<String> {
        begin(&self.root, me(), GREETER, inv, Some(&url(email))).unwrap()
    }

    fn stash(&self, inv: &str, now: u64) -> Stashed {
        stash(&self.root, owners(), BOOT, GREETER, inv, now).unwrap()
    }

    fn claim(&self, user: &str, uid: u32, now: u64) -> Claimed {
        claim(&self.root, me(), user, uid, now).unwrap()
    }

    /// Everything but the lock and the private directory.
    fn leftovers(&self) -> Vec<String> {
        let mut out = Vec::new();
        for e in fs::read_dir(self.handoff()).unwrap() {
            let n = e.unwrap().file_name().into_string().unwrap();
            if n != PRIVATE {
                out.push(n);
            }
        }
        for e in fs::read_dir(self.handoff().join(PRIVATE)).unwrap() {
            let n = e.unwrap().file_name().into_string().unwrap();
            if n != "lock" {
                out.push(format!("private/{n}"));
            }
        }
        out.sort();
        out
    }
}

#[test]
fn instances_and_invocations() {
    assert!(valid_instance("gdm-greeter"));
    assert!(valid_instance("gdm-greeter-2"));
    assert!(valid_instance("gdm-greeter-12"));
    for bad in [
        "gdm-greeter-",
        "gdm-greeter-x",
        "gdm",
        "root",
        "gdm-greeter-2/..",
        "gdm-greeter-1234567",
    ] {
        assert!(!valid_instance(bad), "{bad}");
    }
    assert!(valid_invocation(INV));
    assert!(!valid_invocation("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    assert!(!valid_invocation(""));
    assert!(!valid_invocation("aaaa"));
}

#[test]
fn email_from_the_cards_url() {
    let u = |s: &str| email_from_url(s);
    assert_eq!(
        u("https://auth.school.ac.th/authorize?login_hint=Kim%40School.ac.th&x=1").as_deref(),
        Some("kim@school.ac.th")
    );
    assert_eq!(
        u("https://a.b/authorize?login_hint=kim@school.ac.th\n").as_deref(),
        Some("kim@school.ac.th")
    );
    assert_eq!(
        u("http://a.b/authorize?login_hint=kim%40school.ac.th"),
        None,
        "not https"
    );
    assert_eq!(u("https://a.b/authorize?client_id=1"), None, "no hint");
    assert_eq!(
        u("https://a.b/authorize?login_hint=kim"),
        None,
        "not an email"
    );
    assert_eq!(
        u("https://a.b/authorize?login_hint=a%40b%0ac"),
        None,
        "control character"
    );
    assert_eq!(
        u("https://a.b/authorize?login_hint=a%20b%40c"),
        None,
        "space"
    );
    assert_eq!(u("not a url"), None);
}

#[test]
fn stash_then_claim_hands_over() {
    let r = Root::new();
    assert_eq!(r.begin(VICTIM, INV).as_deref(), Some(VICTIM));
    r.card(GREETER, b"the card's cookies");
    assert_eq!(r.stash(INV, 100), Stashed::Stored);
    assert_eq!(fs::read(r.private(PENDING)).unwrap(), b"the card's cookies");
    assert_eq!(
        r.claim("Victim@School.ac.th", me(), 101),
        Claimed::Delivered
    );
    let d = r.delivered(me());
    assert_eq!(fs::read(&d).unwrap(), b"the card's cookies");
    let m = fs::metadata(&d).unwrap();
    assert_eq!(m.mode() & 0o7777, 0o600);
    assert_eq!(m.uid(), me());
    assert_eq!(
        r.leftovers(),
        [me().to_string()],
        "notes and the stash are gone"
    );
    let hm = fs::metadata(r.handoff()).unwrap().mode() & 0o7777;
    assert_eq!(hm, 0o711);
    let pm = fs::metadata(r.handoff().join(PRIVATE)).unwrap().mode() & 0o7777;
    assert_eq!(pm, 0o700);
}

#[test]
fn claim_then_stash_hands_over() {
    let r = Root::new();
    r.begin(VICTIM, INV);
    assert_eq!(r.claim(VICTIM, me(), 100), Claimed::Waiting);
    let placeholder = r.delivered(me());
    assert_eq!(fs::read(&placeholder).unwrap(), b"");
    assert_eq!(fs::metadata(&placeholder).unwrap().mode() & 0o7777, 0o644);
    r.card(GREETER, b"cookies");
    assert_eq!(r.stash(INV, 102), Stashed::Delivered(me()));
    assert_eq!(fs::read(&placeholder).unwrap(), b"cookies");
    assert_eq!(fs::metadata(&placeholder).unwrap().mode() & 0o7777, 0o600);
    assert_eq!(r.leftovers(), [me().to_string()]);
}

#[test]
fn another_user_gets_nothing() {
    let r = Root::new();
    r.begin(VICTIM, INV);
    r.card(GREETER, b"cookies");
    r.stash(INV, 100);
    assert_eq!(r.claim(ATTACKER, 5000, 101), Claimed::Mismatch);
    assert!(!r.delivered(5000).exists());
    assert_eq!(r.leftovers(), ["private/card.json", "private/pending.db"]);
}

/// The attacker types the victim's email and signs in as themselves on the school's page: the broker refuses, no session,
/// no claim. Whoever signs in next starts a new card, which forgets the attacker's cookies; the victim gets only their own.
#[test]
fn a_refused_sign_in_never_reaches_the_next_person() {
    let r = Root::new();
    r.begin(VICTIM, INV);
    r.card(GREETER, b"attacker's session");
    assert_eq!(r.stash(INV, 100), Stashed::Stored);
    r.drop_card(GREETER);
    // the victim comes along: a new card
    r.begin(VICTIM, INV2);
    assert_eq!(r.leftovers(), ["private/card.json"]);
    assert_eq!(r.claim(VICTIM, me(), 110), Claimed::Waiting);
    r.card(GREETER, b"victim's session");
    assert_eq!(r.stash(INV2, 111), Stashed::Delivered(me()));
    assert_eq!(fs::read(r.delivered(me())).unwrap(), b"victim's session");
}

#[test]
fn a_cancelled_card_expires() {
    let r = Root::new();
    r.begin(VICTIM, INV);
    r.card(GREETER, b"cookies");
    r.stash(INV, 100);
    // no new card, but far too late
    assert_eq!(r.claim(VICTIM, me(), 100 + TTL_SECS + 1), Claimed::Waiting);
    assert_eq!(
        r.leftovers(),
        Vec::<String>::new(),
        "expired: everything removed"
    );
}

#[test]
fn a_late_card_does_not_meet_an_old_claim() {
    let r = Root::new();
    r.begin(VICTIM, INV);
    r.claim(VICTIM, me(), 100);
    r.card(GREETER, b"cookies");
    assert_eq!(r.stash(INV, 100 + TTL_SECS + 1), Stashed::Stored);
    assert_eq!(r.leftovers(), Vec::<String>::new());
}

#[test]
fn every_card_start_forgets_the_last() {
    let r = Root::new();
    r.begin(VICTIM, INV);
    r.claim(VICTIM, me(), 100);
    r.card(GREETER, b"cookies");
    r.stash(INV, 101);
    assert!(r.delivered(me()).exists());
    // also when the new card's URL has no email
    assert_eq!(
        begin(&r.root, me(), GREETER, INV2, Some(b"https://a.b/x\n")).unwrap(),
        None
    );
    assert_eq!(r.leftovers(), Vec::<String>::new());
    assert_eq!(begin(&r.root, me(), GREETER, INV2, None).unwrap(), None);
}

#[test]
fn begin_needs_an_invocation_and_a_greeter() {
    let r = Root::new();
    assert_eq!(
        begin(&r.root, me(), GREETER, "", Some(&url(VICTIM))).unwrap(),
        None
    );
    assert_eq!(
        begin(&r.root, me(), "root", INV, Some(&url(VICTIM))).unwrap(),
        None
    );
    assert_eq!(r.leftovers(), Vec::<String>::new());
}

#[test]
fn stash_only_for_this_invocation_and_greeter() {
    let r = Root::new();
    r.begin(VICTIM, INV);
    r.card(GREETER, b"cookies");
    assert_eq!(r.stash(INV2, 100), Stashed::Stale);
    assert_eq!(
        stash(&r.root, owners(), BOOT, "gdm-greeter-2", INV, 100).unwrap(),
        Stashed::Stale
    );
    assert!(!r.private(PENDING).exists());
    assert_eq!(r.stash(INV, 100), Stashed::Stored);
    assert_eq!(r.stash(INV, 101), Stashed::Stale, "only once");
}

#[test]
fn no_cookies_removes_the_placeholder() {
    let r = Root::new();
    r.begin(VICTIM, INV);
    r.claim(VICTIM, me(), 100);
    assert!(r.delivered(me()).exists());
    assert_eq!(r.stash(INV, 101), Stashed::NoCookies);
    assert_eq!(r.leftovers(), Vec::<String>::new());
}

#[test]
fn the_cards_tmp_is_checked() {
    // two private /tmp directories for the same unit
    let r = Root::new();
    r.begin(VICTIM, INV);
    let outer = r.card(GREETER, b"c");
    let twin = outer.with_file_name(format!(
        "systemd-private-{BOOT}-{CARD_UNIT}@{GREETER}.service-Zz99Yy"
    ));
    fs::create_dir(&twin).unwrap();
    assert!(stash(&r.root, owners(), BOOT, GREETER, INV, 1).is_err());
    fs::remove_dir(&twin).unwrap();
    // another boot's directory is not this card's
    assert!(card_cookies(
        &r.root,
        owners(),
        "ffffffffffffffffffffffffffffffff",
        GREETER
    )
    .unwrap()
    .is_none());
    // not 0700
    fs::set_permissions(&outer, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(card_cookies(&r.root, owners(), BOOT, GREETER).is_err());
    fs::set_permissions(&outer, fs::Permissions::from_mode(0o700)).unwrap();
    // the profile is not the greeter's
    let other = Owners {
        root: me(),
        greeter: me() + 1,
    };
    assert!(card_cookies(&r.root, other, BOOT, GREETER).is_err());
    // a symlink on the way
    let default = outer.join("tmp").join(CARD_PROFILE).join("Default");
    fs::rename(&default, outer.join("elsewhere")).unwrap();
    std::os::unix::fs::symlink(outer.join("elsewhere"), &default).unwrap();
    assert!(card_cookies(&r.root, owners(), BOOT, GREETER).is_err());
    fs::remove_file(&default).unwrap();
    fs::rename(outer.join("elsewhere"), &default).unwrap();
    // Cookies a symlink
    let c = default.join("Cookies");
    fs::remove_file(&c).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", &c).unwrap();
    assert!(card_cookies(&r.root, owners(), BOOT, GREETER).is_err());
    fs::remove_file(&c).unwrap();
    // too large
    fs::write(&c, vec![0u8; MAX_DB_BYTES as usize + 1]).unwrap();
    assert!(stash(&r.root, owners(), BOOT, GREETER, INV, 1).is_err());
    assert!(!r.private(PENDING).exists());
}

#[test]
fn greeter_url_is_read_carefully() {
    let r = Root::new();
    let uid = me();
    assert_eq!(read_greeter_url(&r.root, uid).unwrap(), None);
    let dir = r.root.join(format!("run/user/{uid}"));
    fs::create_dir(&dir).unwrap();
    assert_eq!(read_greeter_url(&r.root, uid).unwrap(), None);
    fs::write(dir.join(URL_FILE), url(VICTIM)).unwrap();
    assert_eq!(read_greeter_url(&r.root, uid).unwrap(), Some(url(VICTIM)));
    assert!(read_greeter_url(&r.root, uid + 1).is_ok_and(|u| u.is_none()));
    fs::write(dir.join(URL_FILE), vec![b'a'; MAX_URL_BYTES as usize + 1]).unwrap();
    assert!(read_greeter_url(&r.root, uid).is_err());
    fs::remove_file(dir.join(URL_FILE)).unwrap();
    fs::write(dir.join("real"), url(VICTIM)).unwrap();
    std::os::unix::fs::symlink(dir.join("real"), dir.join(URL_FILE)).unwrap();
    assert!(read_greeter_url(&r.root, uid).is_err());
}

#[test]
fn greeter_url_owned_by_someone_else_is_refused() {
    let r = Root::new();
    let uid = me();
    let dir = r.root.join(format!("run/user/{}", uid + 1));
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join(URL_FILE), url(VICTIM)).unwrap();
    assert!(read_greeter_url(&r.root, uid + 1).is_err());
}

#[test]
fn the_handoff_directory_must_be_roots() {
    let r = Root::new();
    r.begin(VICTIM, INV);
    assert!(begin(&r.root, me() + 1, GREETER, INV, Some(&url(VICTIM))).is_err());
}

#[test]
fn claim_from_pam_ignores_others() {
    // only gdm-authd SSO accounts with a regular uid would touch /run (this would fail on a test machine otherwise)
    claim_from_pam("gdm-password", VICTIM, me());
    claim_from_pam(CLAIM_SERVICE, "itadmin", me());
    claim_from_pam(CLAIM_SERVICE, "guest", 1999);
    claim_from_pam(CLAIM_SERVICE, VICTIM, 120);
}
