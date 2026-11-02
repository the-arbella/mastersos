//! 设置包的打包、解包与内容摘要（spec §5.2）。
//!
//! 包是 `.tar.gz`，只允许 `manifest.toml`、`signature`、`files/` 与 `scripts/`
//! 下的普通文件，以及这两个目录条目本身。签名覆盖的是 [`content_digest`]，
//! 而不是 tar 的原始字节，所以 tar 头里的时间戳、属主不影响验签。

use std::cell::Cell;
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Component, Path};
use std::rc::Rc;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use tar::{Archive, Builder, EntryType, Header};

use crate::BundleError;

/// 压缩后的上限。
pub const MAX_BUNDLE_BYTES: usize = 20 * 1024 * 1024;
/// 解压后所有成员内容的总上限。
pub const MAX_UNPACKED_BYTES: u64 = 64 * 1024 * 1024;

const MANIFEST: &str = "manifest.toml";
const SIGNATURE: &str = "signature";

/// 解压流（含 tar 头与填充）的硬上限：内容上限的两倍，挡住海量空条目的炸弹。
const MAX_STREAM_BYTES: u64 = MAX_UNPACKED_BYTES * 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contents {
    pub manifest_text: String,
    /// 键是 `files/…` 与 `scripts/…` 路径。
    pub files: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unpacked {
    pub contents: Contents,
    pub signature_toml: String,
}

/// 签名所覆盖的摘要：`manifest.toml` 与 `files` 的每个键按路径字节序排列，
/// 每项拼成 `路径 \0 小写十六进制 sha256(内容) \n`，整段再做一次 sha256。
/// `signature` 不参与。
pub fn content_digest(c: &Contents) -> [u8; 32] {
    let mut entries: BTreeMap<&str, &[u8]> = BTreeMap::new();
    entries.insert(MANIFEST, c.manifest_text.as_bytes());
    for (path, data) in &c.files {
        entries.insert(path.as_str(), data.as_slice());
    }
    let mut outer = Sha256::new();
    for (path, data) in entries {
        outer.update(path.as_bytes());
        outer.update([0u8]);
        outer.update(hex(&Sha256::digest(data)).as_bytes());
        outer.update(b"\n");
    }
    outer.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}

fn top_name(path: &str) -> &str {
    path.split('/').next().unwrap_or("")
}

/// `files/…` 或 `scripts/…` 下的成员路径：只允许普通分量，且至少两层。
pub fn check_member_path(path: &str) -> Result<(), BundleError> {
    let unsafe_path = || BundleError::UnsafePath(path.to_string());
    let mut comps = Path::new(path).components();
    match comps.next() {
        Some(Component::Normal(top)) if top == "files" || top == "scripts" => {}
        _ => return Err(unsafe_path()),
    }
    let mut rest = 0;
    let mut canonical = String::from(top_name(path));
    for c in comps {
        match c {
            Component::Normal(n) => {
                rest += 1;
                canonical.push('/');
                canonical.push_str(&n.to_string_lossy());
            }
            _ => return Err(unsafe_path()),
        }
    }
    // components() 会悄悄吞掉 "."、空分量和结尾的 "/"；要求路径与规范形式逐字节相同，
    // 否则不同的键会指向磁盘上同一个文件。
    if rest == 0 || canonical != path || path.contains('\\') || path.contains('\0') {
        return Err(unsafe_path());
    }
    Ok(())
}

pub fn write_archive(c: &Contents, signature_toml: &str) -> Result<Vec<u8>, BundleError> {
    write_archive_with_mtime(c, signature_toml, 0)
}

fn write_archive_with_mtime(
    c: &Contents,
    signature_toml: &str,
    mtime: u64,
) -> Result<Vec<u8>, BundleError> {
    let io_err = |e: io::Error| BundleError::Io(e.to_string());
    let total: u64 = c.files.values().map(|v| v.len() as u64).sum::<u64>()
        + c.manifest_text.len() as u64
        + signature_toml.len() as u64;
    if total > MAX_UNPACKED_BYTES {
        return Err(BundleError::TooLarge);
    }
    for path in c.files.keys() {
        check_member_path(path)?;
    }
    let mut builder = Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
    let mut put = |path: &str, data: &[u8]| -> Result<(), BundleError> {
        let mut h = Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(mtime);
        h.set_uid(0);
        h.set_gid(0);
        builder.append_data(&mut h, path, data).map_err(io_err)
    };
    put(MANIFEST, c.manifest_text.as_bytes())?;
    for (path, data) in &c.files {
        put(path, data)?;
    }
    put(SIGNATURE, signature_toml.as_bytes())?;
    let gz = builder.into_inner().map_err(io_err)?;
    let out = gz.finish().map_err(io_err)?;
    if out.len() > MAX_BUNDLE_BYTES {
        return Err(BundleError::TooLarge);
    }
    Ok(out)
}

/// 限量的读取器：超过 `limit` 就报错并立起标志，供调用方把 tar 的 IO 错误翻译成 `TooLarge`。
struct Capped<R> {
    inner: R,
    seen: u64,
    limit: u64,
    tripped: Rc<Cell<bool>>,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.seen += n as u64;
        if self.seen > self.limit {
            self.tripped.set(true);
            return Err(io::Error::other("unpacked size limit exceeded"));
        }
        Ok(n)
    }
}

/// 解包并检查路径、类型与大小；不验签（见签名模块）。
pub fn read_archive(bytes: &[u8]) -> Result<Unpacked, BundleError> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(BundleError::TooLarge);
    }
    let tripped = Rc::new(Cell::new(false));
    let capped = Capped {
        inner: GzDecoder::new(bytes),
        seen: 0,
        limit: MAX_STREAM_BYTES,
        tripped: tripped.clone(),
    };
    let result = unpack(capped);
    match result {
        Err(_) if tripped.get() => Err(BundleError::TooLarge),
        other => other,
    }
}

fn unpack<R: Read>(reader: R) -> Result<Unpacked, BundleError> {
    let io_err = |e: io::Error| BundleError::Io(e.to_string());
    let mut archive = Archive::new(reader);
    let mut manifest: Option<String> = None;
    let mut signature: Option<String> = None;
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut seen_dirs: Vec<String> = Vec::new();
    let mut remaining = MAX_UNPACKED_BYTES;

    for entry in archive.entries().map_err(io_err)? {
        let entry = entry.map_err(io_err)?;
        let kind = entry.header().entry_type();
        let raw = entry.path().map_err(io_err)?.to_string_lossy().into_owned();

        match kind {
            EntryType::Directory => {
                let name = raw.strip_suffix('/').unwrap_or(&raw).to_string();
                if name != "files" && name != "scripts" {
                    return Err(BundleError::UnsafePath(raw));
                }
                if seen_dirs.contains(&name) {
                    return Err(BundleError::Invalid(format!("Duplicate entry: {name}")));
                }
                seen_dirs.push(name);
                continue;
            }
            EntryType::Regular => {}
            _ => return Err(BundleError::UnsafePath(raw)),
        }

        // 先看路径，再读内容：逃逸路径不该花任何读取。
        let name = raw.clone();
        let is_manifest = name == MANIFEST;
        let is_signature = name == SIGNATURE;
        if !is_manifest && !is_signature {
            check_member_path(&name)?;
        }
        let size = entry.size();
        if size > remaining {
            return Err(BundleError::TooLarge);
        }
        let mut data = Vec::with_capacity(size as usize);
        // 头里的 size 就是 tar 会交出的字节数；take 再兜一层底。
        entry
            .take(remaining + 1)
            .read_to_end(&mut data)
            .map_err(io_err)?;
        if data.len() as u64 > remaining {
            return Err(BundleError::TooLarge);
        }
        remaining -= data.len() as u64;

        if is_manifest || is_signature {
            let text = String::from_utf8(data)
                .map_err(|_| BundleError::Invalid(format!("{name} is not UTF-8")))?;
            let slot = if is_manifest {
                &mut manifest
            } else {
                &mut signature
            };
            if slot.replace(text).is_some() {
                return Err(BundleError::Invalid(format!("Duplicate entry: {name}")));
            }
        } else if files.insert(name.clone(), data).is_some() {
            return Err(BundleError::Invalid(format!("Duplicate entry: {name}")));
        }
    }

    let manifest_text =
        manifest.ok_or_else(|| BundleError::Invalid("The bundle has no manifest.toml".into()))?;
    let signature_toml = signature.ok_or(BundleError::BadSignature)?;
    Ok(Unpacked {
        contents: Contents {
            manifest_text,
            files,
        },
        signature_toml,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Contents {
        let mut files = BTreeMap::new();
        files.insert("files/a.conf".to_string(), b"alpha".to_vec());
        files.insert(
            "scripts/run.sh".to_string(),
            b"#!/bin/sh\necho hi\n".to_vec(),
        );
        Contents {
            manifest_text: "version = 1\n".into(),
            files,
        }
    }

    /// 手工拼一个 tar.gz，允许任意（含不安全的）条目。
    fn raw_archive(entries: &[(&str, EntryType, &[u8], Option<&str>)]) -> Vec<u8> {
        let mut b = Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (name, kind, data, link) in entries {
            let mut h = Header::new_gnu();
            h.set_entry_type(*kind);
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            let bytes = name.as_bytes();
            h.as_old_mut().name[..bytes.len()].copy_from_slice(bytes);
            if let Some(l) = link {
                let lb = l.as_bytes();
                h.as_old_mut().linkname[..lb.len()].copy_from_slice(lb);
            }
            h.set_cksum();
            b.append(&h, *data).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    fn reg(name: &'static str) -> (&'static str, EntryType, &'static [u8], Option<&'static str>) {
        (name, EntryType::Regular, b"x", None)
    }

    fn base() -> Vec<(&'static str, EntryType, &'static [u8], Option<&'static str>)> {
        vec![reg("manifest.toml"), reg("signature")]
    }

    #[test]
    fn roundtrip_preserves_contents() {
        let c = sample();
        let bytes = write_archive(&c, "sig-text").unwrap();
        let u = read_archive(&bytes).unwrap();
        assert_eq!(u.contents, c);
        assert_eq!(u.signature_toml, "sig-text");
    }

    #[test]
    fn digest_ignores_tar_metadata() {
        let c = sample();
        let a = write_archive_with_mtime(&c, "s", 1).unwrap();
        let b = write_archive_with_mtime(&c, "s", 1_700_000_000).unwrap();
        assert_ne!(a, b, "两次打包的字节本就不同");
        let da = content_digest(&read_archive(&a).unwrap().contents);
        let db = content_digest(&read_archive(&b).unwrap().contents);
        assert_eq!(da, db);
    }

    #[test]
    fn digest_changes_when_any_byte_changes() {
        let c = sample();
        let base = content_digest(&c);

        let mut m = c.clone();
        m.manifest_text = "version = 2\n".into();
        assert_ne!(content_digest(&m), base);

        let mut f = c.clone();
        f.files.get_mut("files/a.conf").unwrap()[0] ^= 1;
        assert_ne!(content_digest(&f), base);

        let mut n = c.clone();
        let v = n.files.remove("files/a.conf").unwrap();
        n.files.insert("files/b.conf".into(), v);
        assert_ne!(content_digest(&n), base);
    }

    #[test]
    fn digest_is_independent_of_signature_and_matches_ruling_format() {
        let c = Contents {
            manifest_text: "m".into(),
            files: BTreeMap::new(),
        };
        let line = format!("manifest.toml\0{}\n", hex(&Sha256::digest(b"m")));
        let expect: [u8; 32] = Sha256::digest(line.as_bytes()).into();
        assert_eq!(content_digest(&c), expect);
    }

    #[test]
    fn rejects_dotdot_path() {
        let mut e = base();
        e.push(reg("files/../etc/passwd"));
        let r = read_archive(&raw_archive(&e));
        assert!(matches!(r, Err(BundleError::UnsafePath(_))), "{r:?}");
    }

    #[test]
    fn rejects_absolute_path() {
        let mut e = base();
        e.push(reg("/etc/passwd"));
        let r = read_archive(&raw_archive(&e));
        assert!(matches!(r, Err(BundleError::UnsafePath(_))), "{r:?}");
    }

    #[test]
    fn rejects_symlink_entry() {
        let mut e = base();
        e.push(("files/link", EntryType::Symlink, b"", Some("/etc/passwd")));
        let r = read_archive(&raw_archive(&e));
        assert!(matches!(r, Err(BundleError::UnsafePath(_))), "{r:?}");
    }

    #[test]
    fn rejects_hardlink_entry() {
        let mut e = base();
        e.push(("files/link", EntryType::Link, b"", Some("manifest.toml")));
        let r = read_archive(&raw_archive(&e));
        assert!(matches!(r, Err(BundleError::UnsafePath(_))), "{r:?}");
    }

    #[test]
    fn rejects_unknown_top_level() {
        let mut e = base();
        e.push(reg("extra.txt"));
        let r = read_archive(&raw_archive(&e));
        assert!(matches!(r, Err(BundleError::UnsafePath(_))), "{r:?}");
    }

    #[test]
    fn rejects_non_canonical_paths() {
        for bad in [
            "files/./a",
            "files//a",
            "files/a/",
            "manifest.toml/",
            "signature/",
        ] {
            let mut e = base();
            e.push(reg(bad));
            let r = read_archive(&raw_archive(&e));
            assert!(matches!(r, Err(BundleError::UnsafePath(_))), "{bad}: {r:?}");
        }
        for bad in ["files/./a", "files//a", "files/a/"] {
            let mut c = sample();
            c.files.insert(bad.into(), vec![]);
            assert!(
                matches!(write_archive(&c, "s"), Err(BundleError::UnsafePath(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn stream_cap_stops_many_empty_entries() {
        // 每个空条目只占一个 512 字节的头，不消耗内容额度；只有整流上限能拦住它们。
        let mut b = Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        let n = (MAX_UNPACKED_BYTES * 2 / 512) as usize + 1000;
        for i in 0..n {
            let mut h = Header::new_gnu();
            h.set_size(0);
            h.set_mode(0o644);
            b.append_data(&mut h, format!("files/e{i}"), io::empty())
                .unwrap();
        }
        let bomb = b.into_inner().unwrap().finish().unwrap();
        assert!(
            bomb.len() < MAX_BUNDLE_BYTES,
            "炸弹压缩后 {} 字节",
            bomb.len()
        );
        assert_eq!(read_archive(&bomb), Err(BundleError::TooLarge));
    }

    #[test]
    fn allows_the_two_directory_entries() {
        let mut e = base();
        e.push(("files/", EntryType::Directory, b"", None));
        e.push(("scripts/", EntryType::Directory, b"", None));
        e.push(reg("files/a"));
        assert!(read_archive(&raw_archive(&e)).is_ok());
    }

    #[test]
    fn rejects_other_directory_and_duplicates() {
        let mut e = base();
        e.push(("files/sub/", EntryType::Directory, b"", None));
        assert!(matches!(
            read_archive(&raw_archive(&e)),
            Err(BundleError::UnsafePath(_))
        ));
        let mut d = base();
        d.push(reg("files/a"));
        d.push(reg("files/a"));
        assert!(matches!(
            read_archive(&raw_archive(&d)),
            Err(BundleError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_missing_manifest() {
        let r = read_archive(&raw_archive(&[reg("signature")]));
        assert!(matches!(r, Err(BundleError::Invalid(_))), "{r:?}");
    }

    #[test]
    fn rejects_missing_signature() {
        let r = read_archive(&raw_archive(&[reg("manifest.toml")]));
        assert_eq!(r, Err(BundleError::BadSignature));
    }

    #[test]
    fn write_rejects_unsafe_keys() {
        let mut c = sample();
        c.files.insert("../evil".into(), vec![]);
        assert!(matches!(
            write_archive(&c, "s"),
            Err(BundleError::UnsafePath(_))
        ));
    }

    #[test]
    fn rejects_oversized_compressed() {
        // 不是合法 gzip：若真去解压只会得到 Io 错误，TooLarge 说明没碰它。
        let junk = vec![0u8; MAX_BUNDLE_BYTES + 1];
        assert_eq!(read_archive(&junk), Err(BundleError::TooLarge));
    }

    /// `size` 字节的全零文件，流式压缩，不在内存里放原文。
    fn zero_bomb(sizes: &[u64]) -> Vec<u8> {
        let mut b = Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        for (i, size) in sizes.iter().enumerate() {
            let mut h = Header::new_gnu();
            h.set_size(*size);
            h.set_mode(0o644);
            b.append_data(&mut h, format!("files/zero{i}"), io::repeat(0).take(*size))
                .unwrap();
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    #[cfg(target_os = "linux")]
    fn rss_bytes() -> u64 {
        let s = std::fs::read_to_string("/proc/self/statm").unwrap();
        s.split_whitespace().nth(1).unwrap().parse::<u64>().unwrap() * 4096
    }

    #[test]
    fn stops_at_unpacked_limit() {
        let mb = 1024 * 1024;
        let bomb = zero_bomb(&[100 * mb]);
        assert!(bomb.len() < MAX_BUNDLE_BYTES, "炸弹压缩后应当很小");
        #[cfg(target_os = "linux")]
        let before = rss_bytes();
        assert_eq!(read_archive(&bomb), Err(BundleError::TooLarge));
        #[cfg(target_os = "linux")]
        {
            let grown = rss_bytes().saturating_sub(before);
            assert!(grown <= MAX_UNPACKED_BYTES + 8 * mb, "常驻内存增长 {grown}");
        }
    }

    #[test]
    fn stops_when_many_files_sum_past_limit() {
        let mb = 1024 * 1024;
        let bomb = zero_bomb(&[40 * mb, 40 * mb]);
        assert_eq!(read_archive(&bomb), Err(BundleError::TooLarge));
    }
}
