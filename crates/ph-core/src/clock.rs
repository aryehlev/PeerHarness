//! The [`Clock`] abstraction so time-dependent logic is testable.

use std::sync::atomic::{AtomicI64, Ordering};

use crate::timestamp::Timestamp;

/// A source of the current time.
pub trait Clock: Send + Sync {
    /// The current time.
    fn now(&self) -> Timestamp;
}

/// The real system clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

/// A manually controlled clock for tests. Interior mutability makes it shareable
/// behind `&` / `Arc`.
#[derive(Debug)]
pub struct FixedClock(AtomicI64);

impl FixedClock {
    /// A clock frozen at `t`.
    pub fn new(t: Timestamp) -> Self {
        Self(AtomicI64::new(t.unix_seconds()))
    }

    /// Sets the time.
    pub fn set(&self, t: Timestamp) {
        self.0.store(t.unix_seconds(), Ordering::SeqCst);
    }

    /// Moves the time forward (or backward, if negative) by `secs`, saturating.
    pub fn advance_secs(&self, secs: i64) {
        let next = self.now().plus_secs(secs);
        self.set(next);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_seconds(self.0.load(Ordering::SeqCst)).unwrap_or(Timestamp::MIN)
    }
}

impl<C: Clock + ?Sized> Clock for &C {
    fn now(&self) -> Timestamp {
        (**self).now()
    }
}

impl<C: Clock + ?Sized> Clock for std::sync::Arc<C> {
    fn now(&self) -> Timestamp {
        (**self).now()
    }
}

impl<C: Clock + ?Sized> Clock for Box<C> {
    fn now(&self) -> Timestamp {
        (**self).now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock() {
        let t: Timestamp = "2026-11-09T18:10:00Z".parse().unwrap();
        let c = FixedClock::new(t);
        assert_eq!(c.now(), t);
        c.advance_secs(60);
        assert_eq!(c.now().to_string(), "2026-11-09T18:11:00Z");
        let shared: std::sync::Arc<dyn Clock> = std::sync::Arc::new(FixedClock::new(t));
        assert_eq!(shared.now(), t);
        assert!(SystemClock.now() > t.minus_secs(10 * 365 * 86_400));
    }
}
