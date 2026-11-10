//! Per-peer inbound rate limiting (architecture section 7).
//!
//! Each remote peer gets a [`PeerLimiter`]: a token bucket on request count, a token
//! bucket on inbound bytes, and a semaphore bounding concurrent in-flight inbound
//! requests. The swarm consults it **before** the application handler runs; a request
//! over any limit is answered `error{rate_limited}` and never reaches the handler.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::RateLimits;

/// A classic token bucket with fractional refill.
#[derive(Clone, Debug)]
pub struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// A full bucket holding `capacity` tokens, refilled at `refill_per_sec`.
    pub fn new(capacity: u64, refill_per_sec: u64, now: Instant) -> Self {
        // u64 -> f64 is exact for every value used here (well below 2^53).
        let capacity = capacity as f64;
        Self {
            capacity,
            refill_per_sec: refill_per_sec as f64,
            tokens: capacity,
            last: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now.max(self.last);
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
    }

    /// Whether `cost` tokens are available at `now` (after refill), without taking them.
    pub fn check(&mut self, cost: u64, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= cost as f64
    }

    /// Takes `cost` tokens if available at `now`. Returns whether it succeeded.
    pub fn try_take(&mut self, cost: u64, now: Instant) -> bool {
        if self.check(cost, now) {
            self.tokens -= cost as f64;
            true
        } else {
            false
        }
    }

    /// Whether the bucket is full at `now`.
    pub fn is_full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= self.capacity
    }
}

/// Why a request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limited {
    /// Request-count bucket empty.
    Requests,
    /// Inbound byte bucket empty.
    Bytes,
    /// Too many concurrent inbound requests.
    Concurrency,
}

impl Limited {
    /// A stable label for logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Limited::Requests => "requests",
            Limited::Bytes => "bytes",
            Limited::Concurrency => "concurrency",
        }
    }
}

/// Minimum interval between two rate-limit warnings logged for the same peer.
pub const WARN_INTERVAL: Duration = Duration::from_secs(10);

/// Limits for one remote peer.
#[derive(Debug)]
pub struct PeerLimiter {
    requests: TokenBucket,
    bytes: TokenBucket,
    concurrency: Arc<Semaphore>,
    last_activity: Instant,
    last_warn: Option<Instant>,
    suppressed: u64,
}

impl PeerLimiter {
    /// A fresh limiter (full buckets) for the given limits.
    ///
    /// The byte bucket's capacity is `max(bytes_per_sec, one maximal frame)`, so a single
    /// 512 KiB frame is always admissible on an idle peer.
    pub fn new(limits: &RateLimits, now: Instant) -> Self {
        Self {
            requests: TokenBucket::new(
                u64::from(limits.burst),
                u64::from(limits.requests_per_sec),
                now,
            ),
            bytes: TokenBucket::new(limits.byte_capacity(), limits.bytes_per_sec, now),
            concurrency: Arc::new(Semaphore::new(limits.max_concurrent_inbound)),
            last_activity: now,
            last_warn: None,
            suppressed: 0,
        }
    }

    /// Records one refused request and decides whether to log a warning for it.
    ///
    /// Returns `Some(n)` at most once per [`WARN_INTERVAL`], where `n` is the number of
    /// refusals since the previous warning that were not logged; `None` otherwise. This
    /// keeps a flooding peer from flooding the log.
    pub fn note_limited(&mut self, now: Instant) -> Option<u64> {
        let due = self
            .last_warn
            .is_none_or(|t| now.saturating_duration_since(t) >= WARN_INTERVAL);
        if due {
            self.last_warn = Some(now);
            Some(std::mem::take(&mut self.suppressed))
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
            None
        }
    }

    /// Charges one request of `wire_bytes` bytes. Both buckets are charged only when both
    /// have room, so a refused request does not drain the other bucket.
    pub fn admit(&mut self, wire_bytes: usize, now: Instant) -> Result<(), Limited> {
        self.last_activity = now;
        let bytes = u64::try_from(wire_bytes).unwrap_or(u64::MAX);
        if !self.requests.check(1, now) {
            return Err(Limited::Requests);
        }
        if !self.bytes.try_take(bytes, now) {
            return Err(Limited::Bytes);
        }
        // `check` above guarantees this succeeds.
        let _ = self.requests.try_take(1, now);
        Ok(())
    }

    /// Takes a concurrency permit, held until the handler finishes.
    pub fn try_permit(&self) -> Result<OwnedSemaphorePermit, Limited> {
        self.concurrency
            .clone()
            .try_acquire_owned()
            .map_err(|_| Limited::Concurrency)
    }

    /// Whether this state carries no information worth keeping: buckets are full, no
    /// request is in flight and the peer has been quiet for `idle`.
    pub fn is_stale(&mut self, limits: &RateLimits, idle: Duration, now: Instant) -> bool {
        now.saturating_duration_since(self.last_activity) >= idle
            && self.concurrency.available_permits() == limits.max_concurrent_inbound
            && self.requests.is_full(now)
            && self.bytes.is_full(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> RateLimits {
        RateLimits {
            requests_per_sec: 2,
            burst: 3,
            bytes_per_sec: 1000,
            max_concurrent_inbound: 2,
        }
    }

    #[test]
    fn bucket_burst_then_refill() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(3, 2, t0);
        assert!(b.try_take(1, t0));
        assert!(b.try_take(1, t0));
        assert!(b.try_take(1, t0));
        assert!(!b.try_take(1, t0));
        assert!(!b.try_take(1, t0 + Duration::from_millis(400)));
        assert!(b.try_take(1, t0 + Duration::from_millis(500)));
        // Never exceeds capacity.
        let later = t0 + Duration::from_secs(100);
        assert!(b.is_full(later));
        assert!(b.try_take(3, later));
        assert!(!b.try_take(1, later));
    }

    #[test]
    fn bucket_tolerates_time_going_backwards() {
        let t0 = Instant::now() + Duration::from_secs(10);
        let mut b = TokenBucket::new(1, 1, t0);
        assert!(b.try_take(1, t0));
        assert!(!b.try_take(1, t0 - Duration::from_secs(5)));
    }

    #[test]
    fn request_count_limit() {
        let t0 = Instant::now();
        let mut l = PeerLimiter::new(&limits(), t0);
        for _ in 0..3 {
            assert_eq!(l.admit(10, t0), Ok(()));
        }
        assert_eq!(l.admit(10, t0), Err(Limited::Requests));
        assert_eq!(l.admit(10, t0 + Duration::from_millis(600)), Ok(()));
    }

    #[test]
    fn byte_budget_limit() {
        let t0 = Instant::now();
        let mut l = PeerLimiter::new(&limits(), t0);
        // Capacity is at least one maximal frame.
        let cap = usize::try_from(limits().byte_capacity()).unwrap();
        assert_eq!(l.admit(cap, t0), Ok(()));
        assert_eq!(l.admit(100, t0), Err(Limited::Bytes));
        // The refused request did not consume a request token: two more fit after the
        // byte bucket refills.
        let t1 = t0 + Duration::from_millis(300);
        assert_eq!(l.admit(100, t1), Ok(()));
        assert_eq!(l.admit(100, t1), Ok(()));
        assert_eq!(l.admit(100, t1), Err(Limited::Requests));
        // A frame larger than the capacity is never admitted.
        let mut l = PeerLimiter::new(&limits(), t0);
        assert_eq!(l.admit(cap + 1, t0), Err(Limited::Bytes));
    }

    #[test]
    fn concurrency_limit() {
        let t0 = Instant::now();
        let l = PeerLimiter::new(&limits(), t0);
        let a = l.try_permit().unwrap();
        let _b = l.try_permit().unwrap();
        assert_eq!(l.try_permit().err(), Some(Limited::Concurrency));
        drop(a);
        assert!(l.try_permit().is_ok());
    }

    #[test]
    fn staleness() {
        let t0 = Instant::now();
        let lim = limits();
        let mut l = PeerLimiter::new(&lim, t0);
        assert_eq!(l.admit(10, t0), Ok(()));
        assert!(!l.is_stale(&lim, Duration::from_secs(60), t0));
        let p = l.try_permit().unwrap();
        let t1 = t0 + Duration::from_secs(120);
        assert!(!l.is_stale(&lim, Duration::from_secs(60), t1));
        drop(p);
        assert!(l.is_stale(&lim, Duration::from_secs(60), t1));
    }

    #[test]
    fn warnings_are_throttled() {
        let t0 = Instant::now();
        let mut l = PeerLimiter::new(&limits(), t0);
        assert_eq!(l.note_limited(t0), Some(0));
        assert_eq!(l.note_limited(t0 + Duration::from_secs(1)), None);
        assert_eq!(l.note_limited(t0 + Duration::from_secs(2)), None);
        assert_eq!(l.note_limited(t0 + WARN_INTERVAL), Some(2));
        assert_eq!(l.note_limited(t0 + WARN_INTERVAL), None);
    }
}
