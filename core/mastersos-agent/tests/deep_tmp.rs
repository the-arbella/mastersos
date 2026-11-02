//! 复审 T19 F1：访客临时目录里很深的链，在打开文件数软上限很低时也删得干净（原来的递归版每层占两个 fd，
//! 到上限就 EMFILE、在第一个错误处停下，访客从此登录不了）。单独一个测试程序：只有它把本进程的上限压低。

use std::path::Path;

use rustix::fs::{mkdirat, openat, Mode, OFlags};
use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};

/// 在 `dir` 下建一条 `depth` 层深的 d/d/…/d，最底下一个文件。
fn chain(dir: &Path, depth: usize) {
    let mut cur = openat(
        rustix::fs::CWD,
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .unwrap();
    for _ in 0..depth {
        mkdirat(&cur, "d", Mode::from_raw_mode(0o755)).unwrap();
        cur = openat(&cur, "d", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
    }
    openat(
        &cur,
        "leaf",
        OFlags::CREATE | OFlags::WRONLY,
        Mode::from_raw_mode(0o644),
    )
    .unwrap();
}

#[test]
fn deep_chain_under_low_fd_limit() {
    let lim = getrlimit(Resource::Nofile);
    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(128),
            maximum: lim.maximum,
        },
    )
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let tmp = root.path().join("var-tmp");
    std::fs::create_dir_all(tmp.join("a")).unwrap();
    std::fs::create_dir_all(tmp.join("b")).unwrap();
    // 2000 层（每层两个 fd 的递归版要 4000 个），两条：第一条之后还得接着删第二条
    chain(&tmp.join("a"), 2000);
    chain(&tmp.join("b"), 2000);
    let me = rustix::process::geteuid().as_raw();
    let n = mastersos_agent::safefs::remove_owned_tree_and_sticky(&tmp, me).unwrap();
    assert_eq!(n, 2);
    assert_eq!(
        std::fs::read_dir(&tmp).unwrap().count(),
        0,
        "删干净了，暂存目录也没留下"
    );
}
