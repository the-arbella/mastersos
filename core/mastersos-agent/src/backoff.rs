//! How long the agent waits after a failed fetch (design ruling 59, `docs/cloud.md` §3):
//! a 503, a failed connection or a timeout is temporary, and so is any other failed fetch; the
//! wait starts at 5 s (`AgentConfig::backoff_start`), doubles after each consecutive failure up to
//! 15 min (`backoff_max`, `FALLBACK_SECS`), and each wait is then multiplied by a factor drawn
//! uniformly from [0.8, 1.2], so that hundreds of machines that lost the server at the same
//! moment do not all come back at the same moment.
//!
//! The cap applies **before** the factor, as the ruling words it ("up to 15 minutes, and each
//! wait is then multiplied by …"): at the cap the waits spread over 12–18 minutes instead of
//! piling up at exactly 15.
//!
//! The random source is injectable ([`Jitter`]) so tests are deterministic.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// The smallest factor a wait is multiplied by.
pub const JITTER_LOW: f64 = 0.8;
/// The largest factor a wait is multiplied by.
pub const JITTER_HIGH: f64 = 1.2;

/// `base` multiplied by the factor `unit` picks in [[`JITTER_LOW`], [`JITTER_HIGH`]]: `unit` 0
/// gives 0.8, 1 gives 1.2, linearly in between. A `unit` outside [0, 1] is clamped; a NaN counts
/// as 0.5 (factor 1).
pub fn jittered(base: Duration, unit: f64) -> Duration {
    let u = if unit.is_nan() {
        0.5
    } else {
        unit.clamp(0.0, 1.0)
    };
    base.mul_f64(JITTER_LOW + (JITTER_HIGH - JITTER_LOW) * u)
}

/// The wait after `attempt` consecutive failures (0: the first failure): `start` doubled
/// `attempt` times, capped at `max`, then [`jittered`] by `unit`.
pub fn backoff(attempt: u32, start: Duration, max: Duration, unit: f64) -> Duration {
    let doubled = start.saturating_mul(1u32 << attempt.min(31));
    jittered(doubled.min(max), unit)
}

/// The random source of the jitter: a number in [0, 1] per wait. [`Jitter::system`] (the
/// default) draws from the system's random source; tests use [`Jitter::fixed`] or
/// [`Jitter::from_fn`].
#[derive(Clone)]
pub struct Jitter(Arc<dyn Fn() -> f64 + Send + Sync>);

impl Jitter {
    /// Uniform in [0, 1) from the system's random source (53 random bits). If the source fails,
    /// 0.5 (factor 1): the wait is still bounded, only not spread.
    pub fn system() -> Jitter {
        Jitter(Arc::new(|| {
            use ring::rand::{SecureRandom, SystemRandom};
            let mut b = [0u8; 8];
            match SystemRandom::new().fill(&mut b) {
                Ok(()) => (u64::from_le_bytes(b) >> 11) as f64 / (1u64 << 53) as f64,
                Err(_) => 0.5,
            }
        }))
    }

    /// Always `unit`.
    pub fn fixed(unit: f64) -> Jitter {
        Jitter(Arc::new(move || unit))
    }

    /// Whatever `f` returns, called once per wait.
    pub fn from_fn(f: impl Fn() -> f64 + Send + Sync + 'static) -> Jitter {
        Jitter(Arc::new(f))
    }

    /// The next number in [0, 1] (as the source gives it; [`jittered`] clamps).
    pub fn unit(&self) -> f64 {
        (self.0)()
    }
}

impl Default for Jitter {
    fn default() -> Self {
        Jitter::system()
    }
}

impl fmt::Debug for Jitter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Jitter")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: Duration = Duration::from_secs(5);
    const MAX: Duration = Duration::from_secs(15 * 60);

    #[test]
    fn backoff_has_jitter_and_cap() {
        // Without jitter (factor 1): 5, 10, 20, … doubling, then 900 s for good.
        let plain: Vec<u64> = (0..12)
            .map(|a| backoff(a, START, MAX, 0.5).as_secs())
            .collect();
        assert_eq!(
            plain,
            [5, 10, 20, 40, 80, 160, 320, 640, 900, 900, 900, 900]
        );
        // The factor's bounds: 0 → ×0.8, 1 → ×1.2, on the first wait and at the cap (the cap is
        // applied before the factor, so a capped wait lies in 12–18 min).
        assert_eq!(backoff(0, START, MAX, 0.0), Duration::from_secs(4));
        assert_eq!(backoff(0, START, MAX, 1.0), Duration::from_secs(6));
        assert_eq!(backoff(20, START, MAX, 0.0), Duration::from_secs(720));
        assert_eq!(backoff(20, START, MAX, 1.0), Duration::from_secs(1080));
        // Every wait lies within [0.8, 1.2] × the capped doubling, for any unit.
        for a in 0..40 {
            let base = START.saturating_mul(1u32 << a.min(31)).min(MAX);
            for i in 0..=20 {
                let d = backoff(a, START, MAX, f64::from(i) / 20.0);
                assert!(
                    d >= base.mul_f64(0.8) && d <= base.mul_f64(1.2),
                    "{a} {i}: {d:?}"
                );
                assert!(d <= MAX.mul_f64(1.2), "{a} {i}: {d:?}");
            }
        }
        // Out-of-range and NaN units are clamped, never stretch the wait beyond the bounds.
        assert_eq!(backoff(0, START, MAX, -3.0), Duration::from_secs(4));
        assert_eq!(backoff(0, START, MAX, 7.0), Duration::from_secs(6));
        assert_eq!(backoff(0, START, MAX, f64::NAN), START);
        // Huge attempt counts do not overflow.
        assert_eq!(backoff(u32::MAX, START, MAX, 0.5), MAX);
    }

    #[test]
    fn system_jitter_is_in_range_and_varies() {
        let j = Jitter::system();
        let draws: Vec<f64> = (0..200).map(|_| j.unit()).collect();
        assert!(draws.iter().all(|u| (0.0..1.0).contains(u)), "{draws:?}");
        let lo = draws.iter().cloned().fold(f64::INFINITY, f64::min);
        let hi = draws.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        // 200 uniform draws all within 0.2 of each other: probability far below 1e-50.
        assert!(hi - lo > 0.2, "{lo} {hi}");
        assert_eq!(Jitter::fixed(0.25).unit(), 0.25);
        assert_eq!(format!("{:?}", Jitter::default()), "Jitter");
    }
}
