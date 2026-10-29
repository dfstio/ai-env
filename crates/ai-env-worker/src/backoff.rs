//! The wait before the next dial (WM-R16, WM-R17): `jitter(step)`, the step doubling to `backoff_max` and
//! back to `backoff_min` after a tunnel that stayed `reset_after` past `AuthOk`; a refused end waits at least
//! the refused floor; a sleep waits `backoff_min`.

use std::time::Duration;

use crate::worker::Tuning;

/// How a tunnel ended (WM-R15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    /// `run_until`'s future resolved.
    Shutdown,
    /// UNAUTHENTICATED, a refusal-class `Close`, an older relay, a signer's refusal.
    Refused,
    /// Everything else.
    Transient,
}

/// The backoff's state across tunnels.
#[derive(Debug, Clone)]
pub(crate) struct Backoff {
    step: Duration,
    min: Duration,
    max: Duration,
    reset_after: Duration,
    refused_floor: Duration,
}

impl Backoff {
    pub(crate) fn new(t: &Tuning) -> Backoff {
        Backoff { step: t.backoff_min, min: t.backoff_min, max: t.backoff_max, reset_after: t.reset_after, refused_floor: t.refused_floor }
    }

    /// The wait after a tunnel that ended as `class`, `lived` past its `AuthOk` (none when it never got
    /// there), ended by a sleep or not, with `r` a fresh random `u32`.
    pub(crate) fn after(&mut self, class: Class, lived: Option<Duration>, sleep: bool, r: u32) -> Duration {
        if sleep {
            // WM-R17: a sleep says nothing of the relay; the next dial waits `backoff_min`.
            self.step = self.min;
            return self.min;
        }
        if lived.is_some_and(|l| l >= self.reset_after) {
            self.step = self.min;
        }
        let wait = jitter(self.step, r);
        self.step = self.step.saturating_mul(2).min(self.max);
        match class {
            Class::Refused => wait.max(self.refused_floor),
            Class::Shutdown | Class::Transient => wait,
        }
    }
}

/// `d × (0.75 + 0.5 × r / 2^32)`: within a quarter of `d`, below `1.25 × d`. In whole nanoseconds, rounded
/// down, so `r = u32::MAX` stays under `1.25 × d` at every length.
pub(crate) fn jitter(d: Duration, r: u32) -> Duration {
    let scaled = d.as_nanos() * (3 * (1u128 << 32) + 2 * u128::from(r)) / (1u128 << 34);
    Duration::from_nanos(u64::try_from(scaled).unwrap_or(u64::MAX))
}

/// A fresh random `u32` from aws-lc-rs (the middle of the range if it fails, which is no jitter).
pub(crate) fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    aws_lc_rs::rand::fill(&mut b).map_or(1 << 31, |()| u32::from_be_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WM-T11.
    #[test]
    fn backoff_doubles_jitters_within_a_quarter_and_resets() {
        let s = Duration::from_secs;
        assert_eq!(jitter(s(4), 0), Duration::from_secs(3));
        let top = jitter(s(4), u32::MAX);
        assert!(top < s(5) && top > Duration::from_millis(4999), "{top:?}");
        assert_eq!(jitter(s(4), 1 << 31), s(4), "the middle is no jitter");

        let t = Tuning::default();
        let mut b = Backoff::new(&t);
        let mid = 1 << 31;
        let steps: Vec<u64> = (0..8).map(|_| b.after(Class::Transient, None, false, mid).as_secs()).collect();
        assert_eq!(steps, [1, 2, 4, 8, 16, 32, 60, 60]);

        let lived_long = Some(t.reset_after);
        assert_eq!(b.after(Class::Transient, lived_long, false, mid), s(1), "reset after a stable tunnel");
        assert_eq!(b.after(Class::Transient, Some(t.reset_after - Duration::from_millis(1)), false, mid), s(2), "no reset");
        assert_eq!(b.after(Class::Transient, None, false, mid), s(4));

        let mut fresh = Backoff::new(&t);
        assert_eq!(fresh.after(Class::Refused, None, false, 0), s(60), "a refused end waits the floor");
        assert_eq!(fresh.after(Class::Refused, lived_long, false, u32::MAX), s(60), "even after a reset");
        let mut grown = Backoff::new(&t);
        for _ in 0..7 {
            grown.after(Class::Transient, None, false, mid);
        }
        assert!(grown.after(Class::Refused, None, false, u32::MAX) > s(60), "the jittered step when it is longer");
        assert_eq!(grown.after(Class::Transient, None, true, mid), s(1), "a sleep waits backoff_min");
        assert_eq!(grown.after(Class::Transient, None, false, mid), s(1), "and starts the steps again");
        let jittered: Vec<Duration> = (0..64).map(|_| jitter(s(8), random_u32())).collect();
        assert!(jittered.iter().all(|d| *d >= s(6) && *d < s(10)));
        assert!(jittered.iter().any(|d| *d != jittered[0]), "random");
    }
}
