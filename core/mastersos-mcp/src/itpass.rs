//! The IT maintenance account's password: `mastersos hash-password` turns what IT types into a
//! yescrypt hash in crypt(3) form (`$y$…`), the form libxcrypt (`chpasswd -e`, `/etc/shadow`)
//! reads. Same algorithm and cost as the admin server's. The plain password is never stored,
//! logged or put in a message.

use yescrypt::{PasswordHasher, PasswordVerifier, Yescrypt};

/// The fewest characters (Unicode scalar values) a password may have.
pub const MIN_CHARS: usize = 16;
/// The most characters a password may have.
pub const MAX_CHARS: usize = 256;

/// Whether `password`'s length is within [`MIN_CHARS`]..=[`MAX_CHARS`] characters.
pub fn length_ok(password: &str) -> bool {
    (MIN_CHARS..=MAX_CHARS).contains(&password.chars().count())
}

/// `password` hashed with yescrypt and a fresh random 16-byte salt, with libxcrypt's default
/// cost (`$y$j9T$…`: N = 4096, r = 32, 16 MiB, tens of milliseconds): run it off the async
/// threads.
pub fn hash(password: &str) -> String {
    let mut salt = [0u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut salt)
        .expect("the system random number generator works");
    PasswordHasher::<yescrypt::PasswordHash>::hash_password_with_salt(
        &Yescrypt::default(),
        password.as_bytes(),
        &salt,
    )
    .expect("the default yescrypt parameters are valid")
    .as_str()
    .to_owned()
}

/// Whether `password` matches the yescrypt hash `hash` (any yescrypt cost and salt length, as
/// libxcrypt writes them). Anything else, including a malformed hash, is `false`.
pub fn verify(password: &str, hash: &str) -> bool {
    Yescrypt::default()
        .verify_password(password.as_bytes(), hash)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Made on Ubuntu 24.04 with libxcrypt 1:4.4.36-4build1 (`crypt_gensalt("$y$", 0)` then
    /// `crypt`, what `mkpasswd -m yescrypt` calls) for the test password below.
    const FIXTURE: &str =
        "$y$j9T$riOnadgCTkdpz3xFR5nd8.$MEnfq6iz8q.9UetSL9HVmdUmsFamAldBPWcAeHnb0p1";
    const PASSWORD: &str = "correct horse battery staple";

    #[test]
    fn yescrypt_matches_libxcrypt_fixture() {
        assert!(verify(PASSWORD, FIXTURE));
        assert!(!verify("correct horse battery stapler", FIXTURE));
        assert!(!verify(PASSWORD, "$6$rounds=500000$abc$def"));
        assert!(!verify(PASSWORD, "not a hash"));
    }

    #[test]
    fn hash_is_salted_yescrypt_that_verifies() {
        let a = hash(PASSWORD);
        let b = hash(PASSWORD);
        assert!(a.starts_with("$y$j9T$"), "{a}");
        assert_ne!(a, b, "a fresh salt each time");
        assert!(verify(PASSWORD, &a));
        assert!(!verify("something else entirely", &a));
        assert!(!a.contains(PASSWORD));
        // What the bundle's own check (lint, agent, seed) accepts.
        mastersos_bundle::checks::it_password_hash(&a).unwrap();
    }

    #[test]
    fn length_counts_characters() {
        assert!(!length_ok(&"a".repeat(15)));
        assert!(length_ok(&"a".repeat(16)));
        assert!(length_ok(&"a".repeat(256)));
        assert!(!length_ok(&"a".repeat(257)));
        // 16 characters, 48 bytes.
        assert!(length_ok(&"密".repeat(16)));
        assert!(!length_ok(&"密".repeat(15)));
    }
}
