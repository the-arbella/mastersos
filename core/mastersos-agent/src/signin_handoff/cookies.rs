//! Chrome's cookie database for the sign-in handoff (docs/specs/2026-11-05-browser-signin-handoff-design.md): read the card's
//! rows, keep the identity provider's, turn session cookies into ones that last [`SESSION_LIFETIME`], and merge them into the
//! user's database or create one with Chrome's own schema. Runs as the user (`signin-import`), never as root.
//!
//! The card's database comes from the login screen's browser and is untrusted: it is opened read-only and immutable, with
//! SQLite's defensive settings; only the `cookies` table is read, by name, and only when it is a table; every value must have
//! its column's declared type and stay under [`MAX_VALUE_BYTES`]; at most [`MAX_ROWS`] rows. Rows are copied as they are
//! (`encrypted_value` included: both browsers use the same fixed `v10` key on this image, and the ciphertext binds only the
//! host_key, which does not change).

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use rusqlite::config::DbConfig;
use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags};

/// More rows than this and the card's database is refused (a sign-in sets a handful).
pub const MAX_ROWS: usize = 1000;
/// The largest text or blob value taken from the card (Chrome itself limits a cookie to 4096 bytes of name and value).
pub const MAX_VALUE_BYTES: usize = 16 * 1024;
/// A session cookie from the card lasts this long after the handoff: one school day. Chrome drops non-persistent cookies
/// when it starts (`RestoreOnStartup` 5), so they have to become persistent to sign the desktop in.
pub const SESSION_LIFETIME: Duration = Duration::from_secs(12 * 3600);
/// Seconds between 1601-01-01 (Chrome's time base, in microseconds) and the Unix epoch.
const CHROME_EPOCH_OFFSET_SECS: i64 = 11_644_473_600;

/// The cookie database version [`COOKIES_SCHEMA`] creates (Chrome 157).
pub const SCHEMA_VERSION: i64 = 24;
/// Chrome 157's schema of `Default/Cookies`, statement by statement as `sqlite3 .schema` prints it. A new database is created
/// from this only when the card's database has this same version; a newer Chrome means updating it (the test compares it
/// with the card fixture).
pub const COOKIES_SCHEMA: &[&str] = &[
    "CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)",
    "CREATE TABLE cookies(creation_utc INTEGER NOT NULL,host_key TEXT NOT NULL,top_frame_site_key TEXT NOT NULL,\
     name TEXT NOT NULL,value TEXT NOT NULL,encrypted_value BLOB NOT NULL,path TEXT NOT NULL,expires_utc INTEGER NOT NULL,\
     is_secure INTEGER NOT NULL,is_httponly INTEGER NOT NULL,last_access_utc INTEGER NOT NULL,has_expires INTEGER NOT NULL,\
     is_persistent INTEGER NOT NULL,priority INTEGER NOT NULL,samesite INTEGER NOT NULL,source_scheme INTEGER NOT NULL,\
     source_port INTEGER NOT NULL,last_update_utc INTEGER NOT NULL,source_type INTEGER NOT NULL,\
     has_cross_site_ancestor INTEGER NOT NULL)",
    "CREATE UNIQUE INDEX cookies_unique_index ON cookies(host_key, top_frame_site_key, has_cross_site_ancestor, name, path, \
     source_scheme, source_port)",
];
/// The `meta` rows Chrome 157 writes next to [`COOKIES_SCHEMA`].
const SCHEMA_META: &[(&str, &str)] = &[
    ("mmap_status", "-1"),
    ("version", "24"),
    ("last_compatible_version", "24"),
];

/// A column's declared type; anything else in a cookies table is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ColType {
    Integer,
    Text,
    Blob,
}

impl ColType {
    fn parse(decl: &str) -> Option<ColType> {
        match decl.to_ascii_uppercase().as_str() {
            "INTEGER" => Some(ColType::Integer),
            "TEXT" => Some(ColType::Text),
            "BLOB" => Some(ColType::Blob),
            _ => None,
        }
    }

    fn admits(self, v: &Value) -> bool {
        match (self, v) {
            (ColType::Integer, Value::Integer(_)) => true,
            (ColType::Text, Value::Text(s)) => s.len() <= MAX_VALUE_BYTES,
            (ColType::Blob, Value::Blob(b)) => b.len() <= MAX_VALUE_BYTES,
            _ => false,
        }
    }
}

/// The rows of a cookies table, every value checked against `columns`.
#[derive(Debug, Clone, PartialEq)]
pub struct Cookies {
    /// `meta.version`.
    pub version: i64,
    pub columns: Vec<(String, ColType)>,
    pub rows: Vec<Vec<Value>>,
}

/// What [`prepare`] kept and why it dropped the rest (for the log line).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Prepared {
    pub kept: usize,
    pub sessions: usize,
    pub foreign: usize,
    pub expired: usize,
}

fn uri_path(path: &Path) -> String {
    let mut out = String::from("file:");
    for c in path.to_string_lossy().chars() {
        match c {
            '%' => out.push_str("%25"),
            '?' => out.push_str("%3f"),
            '#' => out.push_str("%23"),
            c => out.push(c),
        }
    }
    out
}

fn harden(conn: &Connection) -> Result<()> {
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false)?;
    conn.pragma_update(None, "cell_size_check", true)?;
    Ok(())
}

fn version(conn: &Connection) -> Result<i64> {
    let v: String = conn
        .query_row("SELECT value FROM meta WHERE key = 'version'", [], |r| {
            r.get(0)
        })
        .context("the cookie database has no version")?;
    v.trim()
        .parse()
        .with_context(|| format!("the cookie database version is not a number: {v:?}"))
}

/// The `cookies` table's columns; refused unless it is a table and every column has a type [`ColType`] knows.
fn columns(conn: &Connection) -> Result<Vec<(String, ColType)>> {
    let kind: Option<String> = conn
        .query_row(
            "SELECT type FROM sqlite_master WHERE name = 'cookies'",
            [],
            |r| r.get(0),
        )
        .ok();
    ensure!(
        kind.as_deref() == Some("table"),
        "the cookie database has no cookies table"
    );
    let mut st = conn.prepare("SELECT name, type FROM pragma_table_info('cookies')")?;
    let cols = st
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        !cols.is_empty() && cols.len() <= 64,
        "the cookies table has {} columns",
        cols.len()
    );
    cols.into_iter()
        .map(|(name, decl)| {
            let t = ColType::parse(&decl)
                .with_context(|| format!("column {name} has an unknown type {decl:?}"))?;
            ensure!(
                name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "column name {name:?}"
            );
            Ok((name, t))
        })
        .collect()
}

fn select_list(cols: &[(String, ColType)]) -> String {
    cols.iter()
        .map(|(n, _)| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(",")
}

/// Reads the card's cookie database at `path` (opened read-only and immutable: nothing is written next to it).
pub fn read_card(path: &Path) -> Result<Cookies> {
    // immutable: no locks and no journal looked for next to it (the directory is root's)
    let conn = Connection::open_with_flags(
        format!("{}?immutable=1", uri_path(path)),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .context("opening the card's cookie database")?;
    harden(&conn)?;
    let version = version(&conn)?;
    let columns = columns(&conn)?;
    let n: i64 = conn.query_row("SELECT count(*) FROM cookies", [], |r| r.get(0))?;
    ensure!(
        usize::try_from(n).is_ok_and(|n| n <= MAX_ROWS),
        "the card's cookie database has {n} rows (at most {MAX_ROWS})"
    );
    let mut st = conn.prepare(&format!(
        "SELECT {} FROM cookies LIMIT {MAX_ROWS}",
        select_list(&columns)
    ))?;
    let width = columns.len();
    let rows = st
        .query_map([], |r| {
            (0..width)
                .map(|i| r.get::<_, Value>(i))
                .collect::<rusqlite::Result<Vec<_>>>()
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for row in &rows {
        for ((name, t), v) in columns.iter().zip(row) {
            ensure!(
                t.admits(v),
                "column {name} holds a value of the wrong type or size"
            );
        }
    }
    Ok(Cookies {
        version,
        columns,
        rows,
    })
}

/// The hosts the card's Chrome policy lets through (`URLAllowlist` of `mastersos-login.json`): the scheme-qualified
/// entries (`https://.auth.school.ac.th:443`, `http://10.0.0.5:5556`), lowercase, without the leading dot and the port.
/// The broker's redirect (no scheme) and anything unreadable is left out.
pub fn allowed_hosts(policy_json: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(policy_json) else {
        return Vec::new();
    };
    let Some(list) = v.get("URLAllowlist").and_then(|l| l.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in list.iter().filter_map(|e| e.as_str()) {
        let Some(rest) = e
            .strip_prefix("https://")
            .or_else(|| e.strip_prefix("http://"))
        else {
            continue;
        };
        let rest = rest.strip_prefix('.').unwrap_or(rest);
        let host = if let Some(r) = rest.strip_prefix('[') {
            match r.split_once(']') {
                Some((h, _)) => h,
                None => continue,
            }
        } else {
            rest.split([':', '/']).next().unwrap_or("")
        };
        let host = host.to_ascii_lowercase();
        if !host.is_empty() && !out.contains(&host) {
            out.push(host);
        }
    }
    out
}

fn is_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// Whether a cookie with this `host_key` belongs to one of `hosts`. A host-only cookie (`auth.school.ac.th`) must name the
/// host exactly; a domain cookie (`.school.ac.th`) may also be set for a parent domain of a host, as long as that domain
/// has a dot in it (Chrome refuses public suffixes when a site sets them). IP addresses match only themselves.
pub fn host_allowed(host_key: &str, hosts: &[String]) -> bool {
    let key = host_key.to_ascii_lowercase();
    let (domain, key) = match key.strip_prefix('.') {
        Some(k) => (true, k.to_string()),
        None => (false, key),
    };
    if key.is_empty() {
        return false;
    }
    hosts.iter().any(|h| {
        *h == key
            || (domain
                && key.contains('.')
                && !is_ip(h)
                && !is_ip(&key)
                && h.ends_with(&format!(".{key}")))
    })
}

fn chrome_time(unix_secs: i64) -> i64 {
    (unix_secs + CHROME_EPOCH_OFFSET_SECS).saturating_mul(1_000_000)
}

fn col(cookies: &Cookies, name: &str) -> Result<usize> {
    cookies
        .columns
        .iter()
        .position(|(n, _)| n == name)
        .with_context(|| format!("the cookies table has no {name} column"))
}

/// Keeps the rows of `hosts` ([`host_allowed`]) that have not expired at `now_unix` and makes session cookies persistent,
/// expiring [`SESSION_LIFETIME`] after `now_unix`.
pub fn prepare(cookies: &mut Cookies, hosts: &[String], now_unix: i64) -> Result<Prepared> {
    let host = col(cookies, "host_key")?;
    let persistent = col(cookies, "is_persistent")?;
    let has_expires = col(cookies, "has_expires")?;
    let expires = col(cookies, "expires_utc")?;
    let now = chrome_time(now_unix);
    let until = chrome_time(now_unix.saturating_add(SESSION_LIFETIME.as_secs() as i64));
    let mut p = Prepared::default();
    let rows = std::mem::take(&mut cookies.rows);
    for mut row in rows {
        let Value::Text(h) = &row[host] else {
            bail!("host_key is not text");
        };
        if !host_allowed(h, hosts) {
            p.foreign += 1;
            continue;
        }
        if row[persistent] == Value::Integer(0) {
            row[persistent] = Value::Integer(1);
            row[has_expires] = Value::Integer(1);
            row[expires] = Value::Integer(until);
            p.sessions += 1;
        } else if !matches!(row[expires], Value::Integer(t) if t > now) {
            p.expired += 1;
            continue;
        }
        cookies.rows.push(row);
    }
    p.kept = cookies.rows.len();
    Ok(p)
}

fn insert(conn: &Connection, cookies: &Cookies) -> Result<usize> {
    let names = select_list(&cookies.columns);
    let marks = vec!["?"; cookies.columns.len()].join(",");
    let mut st = conn.prepare(&format!(
        "INSERT OR REPLACE INTO cookies({names}) VALUES({marks})"
    ))?;
    let mut n = 0;
    for row in &cookies.rows {
        n += st.execute(rusqlite::params_from_iter(row.iter()))?;
    }
    Ok(n)
}

/// Merges `cookies` into the user's existing database at `path`: same version, same columns (by name and type), each row
/// replacing the one with the same unique key; every other row stays. One transaction.
pub fn merge_into(path: &Path, cookies: &Cookies) -> Result<usize> {
    let mut conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .context("opening the browser's cookie database")?;
    conn.busy_timeout(Duration::from_secs(1))?;
    let v = version(&conn)?;
    ensure!(
        v == cookies.version,
        "the browser's cookie database is version {v}, the card's {}",
        cookies.version
    );
    let mut mine = columns(&conn)?;
    let mut theirs = cookies.columns.clone();
    mine.sort();
    theirs.sort();
    ensure!(
        mine == theirs,
        "the cookies tables of the card and the browser differ"
    );
    let tx = conn.transaction()?;
    let n = insert(&tx, cookies)?;
    tx.commit()?;
    Ok(n)
}

/// The columns [`COOKIES_SCHEMA`] creates, in order.
pub fn schema_columns() -> Result<Vec<(String, ColType)>> {
    let conn = Connection::open_in_memory()?;
    for s in COOKIES_SCHEMA {
        conn.execute(s, [])?;
    }
    columns(&conn)
}

/// Creates the user's database at `dir/name` from [`COOKIES_SCHEMA`] with `cookies` in it, when there is none yet. Built in a
/// temporary file next to it and linked into place, so a browser that created its own meanwhile is never overwritten
/// (`Ok(false)`). Refused unless the card's database has [`SCHEMA_VERSION`] and exactly these columns.
pub fn create_new(dir: &Path, name: &str, cookies: &Cookies) -> Result<bool> {
    ensure!(
        cookies.version == SCHEMA_VERSION,
        "the card's cookie database is version {}, a new one can only be made for version {SCHEMA_VERSION}",
        cookies.version
    );
    ensure!(
        cookies.columns == schema_columns()?,
        "the card's cookies table is not Chrome's version {SCHEMA_VERSION} table"
    );
    let target = dir.join(name);
    let tmp = dir.join(format!(".{name}.mastersos-new"));
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("removing {}", tmp.display())),
    }
    let built = (|| -> Result<()> {
        let mut conn = Connection::open_with_flags(
            &tmp,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let tx = conn.transaction()?;
        for s in COOKIES_SCHEMA {
            tx.execute(s, [])?;
        }
        for (k, v) in SCHEMA_META {
            tx.execute("INSERT INTO meta(key, value) VALUES(?1, ?2)", [k, v])?;
        }
        insert(&tx, cookies)?;
        tx.commit()?;
        conn.close().map_err(|(_, e)| e)?;
        Ok(())
    })();
    let placed = built.and_then(|()| match std::fs::hard_link(&tmp, &target) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e).with_context(|| format!("placing {}", target.display())),
    });
    let _ = std::fs::remove_file(&tmp);
    placed
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod tests {
    use super::*;

    const HOSTS: &[&str] = &["auth.school.ac.th", "idp.example.org", "10.0.0.5"];

    fn hosts() -> Vec<String> {
        HOSTS.iter().map(|h| h.to_string()).collect()
    }

    /// A cookie database as Chrome 157 writes it (the schema text is the one `sqlite3 .schema` printed for Chrome 157 on
    /// 2026-11-05, typed out here independently of [`COOKIES_SCHEMA`]).
    pub(crate) fn chrome_db(path: &Path, rows: &[(&str, &str, bool, i64)]) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
             CREATE TABLE cookies(creation_utc INTEGER NOT NULL,host_key TEXT NOT NULL,top_frame_site_key TEXT NOT NULL,name TEXT NOT NULL,value TEXT NOT NULL,encrypted_value BLOB NOT NULL,path TEXT NOT NULL,expires_utc INTEGER NOT NULL,is_secure INTEGER NOT NULL,is_httponly INTEGER NOT NULL,last_access_utc INTEGER NOT NULL,has_expires INTEGER NOT NULL,is_persistent INTEGER NOT NULL,priority INTEGER NOT NULL,samesite INTEGER NOT NULL,source_scheme INTEGER NOT NULL,source_port INTEGER NOT NULL,last_update_utc INTEGER NOT NULL,source_type INTEGER NOT NULL,has_cross_site_ancestor INTEGER NOT NULL);
             CREATE UNIQUE INDEX cookies_unique_index ON cookies(host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port);
             INSERT INTO meta VALUES('mmap_status','-1'),('version','24'),('last_compatible_version','24');",
        )
        .unwrap();
        for (host, name, persistent, expires) in rows {
            add(&conn, host, name, *persistent, *expires, b"v10secret");
        }
    }

    fn add(conn: &Connection, host: &str, name: &str, persistent: bool, expires: i64, enc: &[u8]) {
        conn.execute(
            "INSERT OR REPLACE INTO cookies VALUES(1,?1,'',?2,'',?3,'/',?4,1,1,1,?5,?5,1,0,2,443,1,0,1)",
            rusqlite::params![host, name, enc, expires, persistent as i64],
        )
        .unwrap();
    }

    pub(crate) fn rows_of(path: &Path) -> Vec<(String, String, i64, i64, Vec<u8>)> {
        let conn = Connection::open(path).unwrap();
        let mut st = conn
            .prepare("SELECT host_key, name, is_persistent, expires_utc, encrypted_value FROM cookies ORDER BY host_key, name")
            .unwrap();
        st.query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
    }

    pub(crate) const NOW: i64 = 1_793_000_000; // 2026-10-27
    pub(crate) fn later() -> i64 {
        chrome_time(NOW + 86_400)
    }

    #[test]
    fn schema_is_chromes() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("Cookies");
        chrome_db(&p, &[]);
        let card = read_card(&p).unwrap();
        assert_eq!(card.version, SCHEMA_VERSION);
        assert_eq!(card.columns, schema_columns().unwrap());
        assert_eq!(card.columns.len(), 20);
    }

    #[test]
    fn allowed_hosts_from_the_card_policy() {
        let p = r#"{"URLBlocklist":["*"],"URLAllowlist":["https://.Auth.School.ac.th:443","https://.cdn.school.ac.th:443",
            "http://10.0.0.5:5556","https://[fd00::1]:443","127.0.0.1:48123/callback","https://.auth.school.ac.th:443"]}"#;
        assert_eq!(
            allowed_hosts(p),
            [
                "auth.school.ac.th",
                "cdn.school.ac.th",
                "10.0.0.5",
                "fd00::1"
            ]
        );
        assert!(allowed_hosts("not json").is_empty());
        assert!(allowed_hosts("{}").is_empty());
    }

    #[test]
    fn host_matching() {
        let h = hosts();
        assert!(host_allowed("auth.school.ac.th", &h));
        assert!(host_allowed(".auth.school.ac.th", &h));
        assert!(host_allowed(".school.ac.th", &h), "parent domain cookie");
        assert!(host_allowed("AUTH.school.ac.th", &h));
        assert!(
            !host_allowed("school.ac.th", &h),
            "host-only cookie of another host"
        );
        assert!(!host_allowed(".th", &h), "no dot: a public suffix");
        assert!(!host_allowed("evil.example", &h));
        assert!(
            !host_allowed(".hschool.ac.th", &h),
            "suffix without a dot boundary"
        );
        assert!(
            !host_allowed("x.auth.school.ac.th", &h),
            "subdomain of an allowed host"
        );
        assert!(host_allowed("10.0.0.5", &h));
        assert!(!host_allowed(".0.0.5", &h), "no domain matching on IPs");
        assert!(!host_allowed("", &h));
        assert!(!host_allowed(".", &h));
    }

    #[test]
    fn prepare_keeps_the_idp_and_converts_sessions() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("card");
        chrome_db(
            &p,
            &[
                ("auth.school.ac.th", "sessions", false, 0),
                ("auth.school.ac.th", "persist", true, later()),
                ("auth.school.ac.th", "old", true, chrome_time(NOW - 10)),
                ("tracker.example", "t", true, later()),
            ],
        );
        let mut c = read_card(&p).unwrap();
        let got = prepare(&mut c, &hosts(), NOW).unwrap();
        assert_eq!(
            got,
            Prepared {
                kept: 2,
                sessions: 1,
                foreign: 1,
                expired: 1
            }
        );
        let names: Vec<_> = c.rows.iter().map(|r| r[3].clone()).collect();
        assert_eq!(
            names,
            [
                Value::Text("sessions".into()),
                Value::Text("persist".into())
            ]
        );
        let s = &c.rows[0];
        assert_eq!(s[12], Value::Integer(1), "is_persistent");
        assert_eq!(s[11], Value::Integer(1), "has_expires");
        assert_eq!(s[7], Value::Integer(chrome_time(NOW + 12 * 3600)));
        assert_eq!(c.rows[1][7], Value::Integer(later()), "own expiry kept");
    }

    #[test]
    fn merge_replaces_same_key_and_keeps_the_rest() {
        let d = tempfile::tempdir().unwrap();
        let card = d.path().join("card");
        let user = d.path().join("Cookies");
        chrome_db(&card, &[("auth.school.ac.th", "sessions", false, 0)]);
        chrome_db(
            &user,
            &[
                ("auth.school.ac.th", "sessions", true, later()),
                ("news.example", "pref", true, later()),
            ],
        );
        // the card's value differs from the stale one in the user's database
        let conn = Connection::open(&card).unwrap();
        conn.execute("UPDATE cookies SET encrypted_value = x'763130aa'", [])
            .unwrap();
        drop(conn);
        let mut c = read_card(&card).unwrap();
        prepare(&mut c, &hosts(), NOW).unwrap();
        assert_eq!(merge_into(&user, &c).unwrap(), 1);
        let rows = rows_of(&user);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "auth.school.ac.th");
        assert_eq!(rows[0].4, vec![0x76, 0x31, 0x30, 0xaa], "replaced");
        assert_eq!(rows[0].3, chrome_time(NOW + 12 * 3600));
        assert_eq!(rows[1].0, "news.example", "other sites stay");
    }

    #[test]
    fn merge_refuses_another_version() {
        let d = tempfile::tempdir().unwrap();
        let card = d.path().join("card");
        let user = d.path().join("Cookies");
        chrome_db(&card, &[("auth.school.ac.th", "s", false, 0)]);
        chrome_db(&user, &[("news.example", "pref", true, later())]);
        Connection::open(&user)
            .unwrap()
            .execute("UPDATE meta SET value = '25' WHERE key = 'version'", [])
            .unwrap();
        let mut c = read_card(&card).unwrap();
        prepare(&mut c, &hosts(), NOW).unwrap();
        let e = merge_into(&user, &c).unwrap_err();
        assert!(format!("{e:#}").contains("version 25"), "{e:#}");
        assert_eq!(rows_of(&user).len(), 1, "untouched");
    }

    #[test]
    fn create_new_makes_chromes_database() {
        let d = tempfile::tempdir().unwrap();
        let card = d.path().join("card");
        chrome_db(&card, &[("auth.school.ac.th", "sessions", false, 0)]);
        let mut c = read_card(&card).unwrap();
        prepare(&mut c, &hosts(), NOW).unwrap();
        assert!(create_new(d.path(), "Cookies", &c).unwrap());
        let made = d.path().join("Cookies");
        let back = read_card(&made).unwrap();
        assert_eq!(back.version, 24);
        assert_eq!(back.columns, schema_columns().unwrap());
        assert_eq!(rows_of(&made).len(), 1);
        // the same statements as Chrome's database, and nothing else
        let sql = |p: &Path| -> Vec<String> {
            let conn = Connection::open(p).unwrap();
            let mut st = conn
                .prepare("SELECT type || ' ' || name || ' ' || coalesce(sql, '') FROM sqlite_master ORDER BY name")
                .unwrap();
            st.query_map([], |r| r.get(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        };
        assert_eq!(sql(&made), sql(&card));
        let meta = |p: &Path| -> Vec<(String, String)> {
            let conn = Connection::open(p).unwrap();
            let mut st = conn
                .prepare("SELECT key, value FROM meta ORDER BY key")
                .unwrap();
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        };
        assert_eq!(meta(&made), meta(&card));
        assert!(!d.path().join(".Cookies.mastersos-new").exists());
    }

    #[test]
    fn create_new_never_overwrites() {
        let d = tempfile::tempdir().unwrap();
        let card = d.path().join("card");
        chrome_db(&card, &[("auth.school.ac.th", "s", false, 0)]);
        std::fs::write(d.path().join("Cookies"), b"chrome made this").unwrap();
        let c = read_card(&card).unwrap();
        assert!(!create_new(d.path(), "Cookies", &c).unwrap());
        assert_eq!(
            std::fs::read(d.path().join("Cookies")).unwrap(),
            b"chrome made this"
        );
        assert!(!d.path().join(".Cookies.mastersos-new").exists());
    }

    #[test]
    fn create_new_only_for_the_known_version() {
        let d = tempfile::tempdir().unwrap();
        let card = d.path().join("card");
        chrome_db(&card, &[("auth.school.ac.th", "s", false, 0)]);
        Connection::open(&card)
            .unwrap()
            .execute("UPDATE meta SET value = '25' WHERE key = 'version'", [])
            .unwrap();
        let c = read_card(&card).unwrap();
        assert!(create_new(d.path(), "Cookies", &c).is_err());
        assert!(!d.path().join("Cookies").exists());
    }

    #[test]
    fn read_card_refuses_bad_databases() {
        let d = tempfile::tempdir().unwrap();
        // a view called cookies
        let p = d.path().join("view");
        let conn = Connection::open(&p).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta(key, value); INSERT INTO meta VALUES('version','24');
             CREATE TABLE t(host_key TEXT); CREATE VIEW cookies AS SELECT * FROM t;",
        )
        .unwrap();
        drop(conn);
        assert!(read_card(&p).is_err());
        // a value of the wrong type
        let p = d.path().join("type");
        chrome_db(&p, &[("auth.school.ac.th", "s", false, 0)]);
        Connection::open(&p)
            .unwrap()
            .execute("UPDATE cookies SET expires_utc = 'soon'", [])
            .unwrap();
        assert!(read_card(&p).is_err());
        // an oversized value
        let p = d.path().join("big");
        chrome_db(&p, &[]);
        let conn = Connection::open(&p).unwrap();
        add(
            &conn,
            "auth.school.ac.th",
            "s",
            false,
            0,
            &vec![0u8; MAX_VALUE_BYTES + 1],
        );
        drop(conn);
        assert!(read_card(&p).is_err());
        // too many rows
        let p = d.path().join("many");
        chrome_db(&p, &[]);
        let conn = Connection::open(&p).unwrap();
        for i in 0..=MAX_ROWS {
            add(
                &conn,
                "auth.school.ac.th",
                &format!("c{i}"),
                false,
                0,
                b"v10",
            );
        }
        drop(conn);
        assert!(read_card(&p).is_err());
        // not a database at all
        let p = d.path().join("junk");
        std::fs::write(&p, b"SQLite format 3\0 but not really").unwrap();
        assert!(read_card(&p).is_err());
    }
}
