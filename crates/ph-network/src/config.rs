//! Network configuration.

use std::time::Duration;

use libp2p::Multiaddr;
use ph_protocol::wire::MAX_FRAME_BYTES;

use crate::codec::LENGTH_PREFIX_BYTES;
use crate::error::NetError;

/// Per-peer inbound limits, enforced before the application handler runs.
///
/// Defaults follow architecture section 7: 20 requests/s with a burst of 40, 512 KiB/s
/// inbound bytes, at most 8 concurrent inbound requests per peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimits {
    /// Sustained requests per second per peer (token refill rate). Must be > 0.
    pub requests_per_sec: u32,
    /// Request bucket capacity (burst). Must be > 0.
    pub burst: u32,
    /// Sustained inbound request bytes per second per peer, counting the 4-byte prefix.
    /// The byte bucket holds `max(bytes_per_sec, 512 KiB + 4)` so one maximal frame is
    /// always admissible on an idle peer. Must be > 0.
    pub bytes_per_sec: u64,
    /// Maximum concurrent inbound requests per peer being handled. Must be > 0.
    pub max_concurrent_inbound: usize,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            requests_per_sec: 20,
            burst: 40,
            bytes_per_sec: 512 * 1024,
            max_concurrent_inbound: 8,
        }
    }
}

impl RateLimits {
    /// Effective capacity of the byte bucket.
    pub fn byte_capacity(&self) -> u64 {
        // MAX_FRAME_BYTES + prefix is a small constant; the cast is lossless.
        let one_frame = (MAX_FRAME_BYTES + LENGTH_PREFIX_BYTES) as u64;
        self.bytes_per_sec.max(one_frame)
    }

    fn validate(&self) -> Result<(), NetError> {
        if self.requests_per_sec == 0
            || self.burst == 0
            || self.bytes_per_sec == 0
            || self.max_concurrent_inbound == 0
            || self.max_concurrent_inbound > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err(NetError::InvalidConfig);
        }
        Ok(())
    }
}

/// Configuration for [`crate::start`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkConfig {
    /// QUIC listen addresses, e.g. `/ip4/127.0.0.1/udp/0/quic-v1`. May be empty for a
    /// dial-only node. Port 0 picks an ephemeral port; use
    /// [`crate::NetworkHandle::listen_addrs`] to learn the bound address.
    pub listen_addrs: Vec<Multiaddr>,
    /// Time allowed for one request/response exchange, both outbound (surfacing as
    /// [`NetError::Timeout`]) and inbound (the handler future is abandoned after it).
    /// Default 20 s.
    pub request_timeout: Duration,
    /// Time allowed for a dial to complete (transport + QUIC/TLS handshake). Default 20 s.
    pub dial_timeout: Duration,
    /// A connection with no request in flight for this long is closed. Default 120 s.
    pub idle_timeout: Duration,
    /// Per-peer inbound rate limits.
    pub rate_limits: RateLimits,
    /// Upper bound on concurrent request/response streams per connection, inbound plus
    /// outbound (libp2p `max_concurrent_streams`). Streams over it are dropped by libp2p
    /// before the rate limiter sees them. Default 32.
    pub max_concurrent_streams: usize,
    /// Maximum established connections in total. Default 256.
    pub max_connections: usize,
    /// Maximum established connections per remote peer. Default 4.
    pub max_connections_per_peer: usize,
    /// Maximum inbound connections still in the QUIC/TLS handshake at once; further
    /// incoming connections are refused until handshakes finish. Default 64.
    pub max_pending_inbound: usize,
    /// Total inbound request body bytes that may be buffered and decoded at once,
    /// across all peers and connections (a memory bound against peers that open many
    /// streams and send large or stalled frames). A request that does not fit is not
    /// read and is answered `error{unavailable}` before reaching the rate limiter or the
    /// handler. Must be at least 512 KiB (one maximal frame). Default 32 MiB.
    pub max_inbound_buffer_bytes: usize,
    /// Capacity of the [`crate::NetEvent`] broadcast channel. Slow subscribers that fall
    /// further behind see `RecvError::Lagged`. Default 256.
    pub event_buffer: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addrs: Vec::new(),
            request_timeout: Duration::from_secs(20),
            dial_timeout: Duration::from_secs(20),
            idle_timeout: Duration::from_secs(120),
            rate_limits: RateLimits::default(),
            max_concurrent_streams: 32,
            max_connections: 256,
            max_connections_per_peer: 4,
            max_pending_inbound: 64,
            max_inbound_buffer_bytes: 32 * 1024 * 1024,
            event_buffer: 256,
        }
    }
}

impl NetworkConfig {
    /// A default configuration listening on `addrs`.
    pub fn listening_on(addrs: impl IntoIterator<Item = Multiaddr>) -> Self {
        Self {
            listen_addrs: addrs.into_iter().collect(),
            ..Self::default()
        }
    }

    /// Checks that every limit and timeout is non-zero and that
    /// `max_inbound_buffer_bytes` holds at least one maximal frame.
    pub fn validate(&self) -> Result<(), NetError> {
        self.rate_limits.validate()?;
        if self.request_timeout.is_zero()
            || self.dial_timeout.is_zero()
            || self.idle_timeout.is_zero()
            || self.max_concurrent_streams == 0
            || self.max_connections == 0
            || self.max_connections_per_peer == 0
            || self.max_pending_inbound == 0
            || self.max_inbound_buffer_bytes < MAX_FRAME_BYTES
            || self.max_inbound_buffer_bytes > tokio::sync::Semaphore::MAX_PERMITS
            || self.event_buffer == 0
        {
            return Err(NetError::InvalidConfig);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_match_architecture() {
        let c = NetworkConfig::default();
        c.validate().unwrap();
        assert_eq!(c.request_timeout, Duration::from_secs(20));
        assert_eq!(c.rate_limits.requests_per_sec, 20);
        assert_eq!(c.rate_limits.burst, 40);
        assert_eq!(c.rate_limits.bytes_per_sec, 512 * 1024);
        assert_eq!(c.rate_limits.max_concurrent_inbound, 8);
        assert_eq!(c.rate_limits.byte_capacity(), 512 * 1024 + 4);
    }

    #[test]
    fn zero_values_rejected() {
        let mut c = NetworkConfig::default();
        c.rate_limits.burst = 0;
        assert_eq!(c.validate(), Err(NetError::InvalidConfig));
        let c = NetworkConfig {
            request_timeout: Duration::ZERO,
            ..NetworkConfig::default()
        };
        assert_eq!(c.validate(), Err(NetError::InvalidConfig));
        let mut c = NetworkConfig::default();
        c.rate_limits.max_concurrent_inbound = 0;
        assert_eq!(c.validate(), Err(NetError::InvalidConfig));
        let c = NetworkConfig {
            max_pending_inbound: 0,
            ..NetworkConfig::default()
        };
        assert_eq!(c.validate(), Err(NetError::InvalidConfig));
        let c = NetworkConfig {
            max_inbound_buffer_bytes: MAX_FRAME_BYTES - 1,
            ..NetworkConfig::default()
        };
        assert_eq!(c.validate(), Err(NetError::InvalidConfig));
        let c = NetworkConfig {
            max_inbound_buffer_bytes: MAX_FRAME_BYTES,
            ..NetworkConfig::default()
        };
        assert_eq!(c.validate(), Ok(()));
    }
}
