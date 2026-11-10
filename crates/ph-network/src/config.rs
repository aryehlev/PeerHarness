//! Network configuration.

use std::time::Duration;

use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use ph_protocol::wire::MAX_FRAME_BYTES;

use crate::codec::LENGTH_PREFIX_BYTES;
use crate::error::NetError;
use crate::internet::{self, DEFAULT_RELAYS, MAX_BOOTSTRAP_ADDRS, MAX_RELAYS};

/// Configuration of the opt-in internet mode ([`crate::internet`]): finding and
/// reaching a peer by its key over the public libp2p network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InternetConfig {
    /// The peers to join the public network through, at most
    /// [`MAX_BOOTSTRAP_ADDRS`] addresses, each ending in `/p2p/<peer id>` and in one of
    /// the forms `/ip4|ip6/<address>/udp/<port>/quic-v1`,
    /// `/dns|dns4|dns6/<name>/udp/<port>/quic-v1` or `/dnsaddr/<name>`. Default:
    /// [`InternetConfig::public_bootstrap`], the bootstrap peers of the public libp2p
    /// (IPFS) network.
    pub bootstrap: Vec<Multiaddr>,
    /// How many relay reservations to hold while this node is not known to be publicly
    /// reachable. Default [`DEFAULT_RELAYS`], at most [`MAX_RELAYS`]. With 0 the node
    /// never asks a relay for anything: it can still find and dial others, and can be
    /// reached only at a public address of its own.
    pub max_relays: usize,
    /// Treat loopback, private and link-local addresses like public ones, and accept an
    /// own address on the word of a single peer. For a closed network of nodes that all
    /// set it (the tests of this crate run one on loopback). Default `false`; on the
    /// internet it would make the node announce and dial private addresses.
    pub allow_private_addresses: bool,
}

impl Default for InternetConfig {
    fn default() -> Self {
        Self {
            bootstrap: Self::public_bootstrap(),
            max_relays: DEFAULT_RELAYS,
            allow_private_addresses: false,
        }
    }
}

impl InternetConfig {
    /// The bootstrap peers of the public libp2p (IPFS) network, as its own software
    /// ships them: four names under `bootstrap.libp2p.io` that are resolved through DNS
    /// (`TXT _dnsaddr.<name>`), one more under `va1.bootstrap.libp2p.io`, and one fixed
    /// address that needs no DNS.
    pub fn public_bootstrap() -> Vec<Multiaddr> {
        internet::PUBLIC_BOOTSTRAP
            .iter()
            .filter_map(|a| a.parse().ok())
            .collect()
    }

    fn validate(&self) -> Result<(), NetError> {
        if self.max_relays > MAX_RELAYS
            || self.bootstrap.is_empty()
            || self.bootstrap.len() > MAX_BOOTSTRAP_ADDRS
            || !self.bootstrap.iter().all(internet::is_bootstrap_addr)
        {
            return Err(NetError::InvalidConfig);
        }
        Ok(())
    }
}

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
    /// Discovery of other nodes on the local network over mDNS ([`crate::discovery`]).
    /// Default `false`: no multicast socket is opened and nothing is announced.
    ///
    /// When `true` the node announces its peer id (the device public key) and its
    /// non-loopback IPv4 listen addresses to every host on the local network, and
    /// reports the nodes it hears as [`crate::NetEvent::PeerDiscovered`] and through
    /// [`crate::NetworkHandle::discovered`]. Discovered peers are never dialed by this
    /// crate.
    pub lan_discovery: bool,
    /// The internet mode ([`crate::internet`]). Default `None`: the node speaks its one
    /// protocol over QUIC to the addresses it is told to dial, as before, and nothing
    /// of the mode exists (no DHT, no identify, no relay client, no DNS lookup, no
    /// further protocol, socket or thread).
    ///
    /// When set, the node joins the public libp2p network as a client: it can look a
    /// peer up by its peer id ([`crate::NetworkHandle::find_peer`]), learns whether it
    /// is reachable itself, and while it is not, stays reachable through relays. Read
    /// [`crate::internet`] for what that tells whom.
    ///
    /// With the mode, listen on all interfaces (`/ip4/0.0.0.0/udp/<port>/quic-v1` and,
    /// for IPv6, `/ip6/::/udp/<port>/quic-v1`) or not at all. A loopback listen address
    /// is refused as an invalid configuration: the QUIC transport sends from the socket
    /// it listens on, and a socket bound to loopback reaches nobody on the internet. A
    /// node that does not listen is reached through relays only and cannot have a
    /// relayed connection to it upgraded.
    pub internet: Option<InternetConfig>,
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
            lan_discovery: false,
            internet: None,
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
        if let Some(internet) = &self.internet {
            internet.validate()?;
            let loopback = |addr: &Multiaddr| match addr.iter().next() {
                Some(Protocol::Ip4(ip)) => ip.is_loopback(),
                Some(Protocol::Ip6(ip)) => ip.is_loopback(),
                _ => false,
            };
            if !internet.allow_private_addresses && self.listen_addrs.iter().any(loopback) {
                return Err(NetError::InvalidConfig);
            }
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
    fn lan_discovery_is_off_unless_asked_for() {
        assert!(!NetworkConfig::default().lan_discovery);
        let addr: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        assert!(!NetworkConfig::listening_on([addr]).lan_discovery);
        // Turning it on is a choice, not a limit to validate: both values are valid.
        let on = NetworkConfig {
            lan_discovery: true,
            ..NetworkConfig::default()
        };
        assert_eq!(on.validate(), Ok(()));
    }

    #[test]
    fn internet_mode_is_off_unless_asked_for_and_its_defaults_are_valid() {
        assert_eq!(NetworkConfig::default().internet, None);
        let addr: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        assert_eq!(NetworkConfig::listening_on([addr]).internet, None);
        let on = NetworkConfig {
            internet: Some(InternetConfig::default()),
            ..NetworkConfig::default()
        };
        assert_eq!(on.validate(), Ok(()));
        let internet = on.internet.unwrap();
        assert_eq!(internet.max_relays, 2);
        assert!(!internet.allow_private_addresses);
        // Every default bootstrap address parsed.
        assert_eq!(internet.bootstrap.len(), internet::PUBLIC_BOOTSTRAP.len());
    }

    #[test]
    fn internet_mode_refuses_a_loopback_listen_address() {
        let listening = |addr: &str, internet: Option<InternetConfig>| NetworkConfig {
            internet,
            ..NetworkConfig::listening_on([addr.parse::<Multiaddr>().unwrap()])
        };
        let public = Some(InternetConfig::default());
        for loopback in ["/ip4/127.0.0.1/udp/0/quic-v1", "/ip6/::1/udp/4001/quic-v1"] {
            // Fine without the mode, as it always was.
            assert_eq!(listening(loopback, None).validate(), Ok(()));
            assert_eq!(
                listening(loopback, public.clone()).validate(),
                Err(NetError::InvalidConfig),
                "{loopback}"
            );
            // A closed network on loopback is what `allow_private_addresses` is for.
            let closed = Some(InternetConfig {
                allow_private_addresses: true,
                ..InternetConfig::default()
            });
            assert_eq!(listening(loopback, closed).validate(), Ok(()));
        }
        for fine in ["/ip4/0.0.0.0/udp/0/quic-v1", "/ip6/::/udp/0/quic-v1"] {
            assert_eq!(listening(fine, public.clone()).validate(), Ok(()), "{fine}");
        }
        // Not listening at all is fine, too: such a node is reached through relays.
        let dial_only = NetworkConfig {
            internet: public,
            ..NetworkConfig::default()
        };
        assert_eq!(dial_only.validate(), Ok(()));
    }

    #[test]
    fn internet_config_is_bounded() {
        let with = |internet: InternetConfig| NetworkConfig {
            internet: Some(internet),
            ..NetworkConfig::default()
        };
        let too_many_relays = InternetConfig {
            max_relays: MAX_RELAYS + 1,
            ..InternetConfig::default()
        };
        assert_eq!(
            with(too_many_relays).validate(),
            Err(NetError::InvalidConfig)
        );
        let none = InternetConfig {
            max_relays: 0,
            ..InternetConfig::default()
        };
        assert_eq!(with(none).validate(), Ok(()));
        let no_bootstrap = InternetConfig {
            bootstrap: Vec::new(),
            ..InternetConfig::default()
        };
        assert_eq!(with(no_bootstrap).validate(), Err(NetError::InvalidConfig));
        let one = InternetConfig::public_bootstrap()[0].clone();
        let too_many = InternetConfig {
            bootstrap: vec![one; MAX_BOOTSTRAP_ADDRS + 1],
            ..InternetConfig::default()
        };
        assert_eq!(with(too_many).validate(), Err(NetError::InvalidConfig));
        for bad in [
            // No peer id: whoever answers there would be taken for the bootstrap peer.
            "/ip4/203.0.113.7/udp/4001/quic-v1",
            "/dnsaddr/bootstrap.libp2p.io",
            // Not a transport of this crate.
            "/ip4/203.0.113.7/tcp/4001/p2p/12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8",
            // A relayed address is not a way into the network.
            "/ip4/203.0.113.7/udp/4001/quic-v1/p2p/12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8/p2p-circuit/p2p/12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8",
        ] {
            let c = InternetConfig {
                bootstrap: vec![bad.parse().unwrap()],
                ..InternetConfig::default()
            };
            assert_eq!(with(c).validate(), Err(NetError::InvalidConfig), "{bad}");
        }
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
