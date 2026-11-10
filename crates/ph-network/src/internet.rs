//! Opt-in internet mode: finding and reaching a peer by its key over the public libp2p
//! network.
//!
//! Off unless [`NetworkConfig::internet`](crate::NetworkConfig::internet) is set. When
//! off, nothing of this module runs: the swarm is built exactly as before, with the one
//! protocol of this crate over QUIC, and no DHT, identify, relay or hole-punching
//! protocol is spoken or answered, no DNS lookup is made and no thread is started.
//!
//! # What the mode does
//!
//! * **Joins the public network as a client.** The node connects to the configured
//!   bootstrap peers and speaks the Kademlia DHT of the public libp2p (IPFS) network,
//!   `/ipfs/kad/1.0.0`, in *client mode*: it asks, it never answers a DHT request, and
//!   it is in nobody's routing table.
//! * **Finds a peer by its peer id** ([`NetworkHandle::find_peer`](crate::NetworkHandle::find_peer)).
//!   The servers of that DHT answer a `FIND_NODE` for a peer id with the addresses they
//!   hold for that peer if it is, or recently was, connected to them (go-libp2p does;
//!   that is what almost all of them run). A node is therefore findable while it keeps
//!   visiting the servers closest to its own id, which it does when it starts, every
//!   [`REFRESH_INTERVAL`], and when its addresses change. Nothing is stored in the DHT.
//! * **Learns whether it can be reached.** Peers report the address they see the node
//!   at (identify). An address that [`OBSERVERS_NEEDED`] peers agree on is tested by
//!   asking a server to dial it back on a fresh connection (AutoNAT v2, client only).
//! * **Stays reachable through relays while it is not.** It asks up to
//!   [`InternetConfig::max_relays`](crate::InternetConfig::max_relays) servers that
//!   offer the circuit relay v2 service for a reservation, and is then reachable at
//!   `/…/p2p/<relay>/p2p-circuit/p2p/<self>`. This node relays for nobody.
//! * **Upgrades a relayed connection to a direct one** when the networks allow it
//!   (DCUtR hole punching), and then closes the relayed one.
//!
//! # Who is contacted, and what they learn
//!
//! The node contacts, on its own: the bootstrap peers; DHT servers that the bootstrap
//! peers and other servers name while a lookup runs (several dozen per lookup, of its
//! own id or of a peer's); the relays it chose; and, for the names in the bootstrap
//! list, the DNS resolvers of this system. It never dials a peer the application named
//! (the target of a `find_peer`, or of an earlier `dial`) except to upgrade a
//! connection that already exists with it.
//!
//! Every peer the node is connected to, whoever opened the connection, can ask for and
//! is sent its identify record, and is sent it again when the addresses change:
//!
//! * the public key of the node (the device key; the peer id says the same);
//! * the fixed strings [`AGENT_VERSION`] and [`PROTOCOL_VERSION`];
//! * the names of the protocols it speaks, which include `/peerharness/req/0.1.0`: a
//!   peer learns that this is a PeerHarness node;
//! * its *confirmed* addresses: public addresses a server dialed back, and the relay
//!   addresses it holds a reservation for. Listen addresses are not sent, so private,
//!   LAN and loopback addresses do not leave the node;
//! * the address the node sees that peer at.
//!
//! In addition: a DHT server that is asked `FIND_NODE` learns which peer id this node
//! is looking for, and sees the node's IP address; so does every server on the way to
//! the answer. A relay learns the peer ids of both ends of every circuit it carries,
//! their IP addresses, when they talk and how much. It does not learn what they say:
//! a relayed connection runs TLS 1.3 between the two ends, with the same certificates
//! as a direct one, so the handshake proves both device keys end to end and the relay
//! can neither read nor alter the stream nor stand in for either end. A peer that the
//! node holds a relayed connection with is told the node's observed public addresses
//! for the hole punch.
//!
//! Nothing here says anything about circles. This crate still knows nothing about
//! them, and still authorizes nothing: whoever connects is a stranger to the handler
//! until the application decides otherwise.
//!
//! The connections the node opens on its own are not the application's: they are not
//! reported as [`NetEvent::Connected`](crate::NetEvent::Connected), not listed by
//! [`NetworkHandle::connected_peers`](crate::NetworkHandle::connected_peers), and no
//! request can be sent on them. Should such a server send a request, the handler is
//! asked like for anyone else. A connection the application dialed, or one that
//! somebody opened to this node, is reported and listed as before.
//!
//! # What is guaranteed
//!
//! * **Addresses from the network are hints.** `find_peer` returns addresses ending in
//!   `/p2p/<peer id>`, so a dial succeeds only if the other end proves that key. It
//!   never dials them. Only addresses this transport can dial and, unless
//!   [`InternetConfig::allow_private_addresses`](crate::InternetConfig::allow_private_addresses)
//!   is set, only public IP addresses are returned, dialed by the node itself or
//!   announced. Servers that lie can keep a peer from being found or have a lookup
//!   return addresses that lead nowhere; they cannot make a dial reach the wrong peer.
//! * **Everything a remote party can grow is bounded**: the routing table by the
//!   k-buckets of Kademlia (20 peers a bucket), lookups in flight by
//!   [`MAX_CONCURRENT_FINDS`], the addresses of an answer by [`MAX_FOUND_ADDRS`],
//!   reservations by [`MAX_RELAYS`], the own addresses under test by
//!   [`MAX_ADDRESS_CANDIDATES`] for the life of the process, and the connections the
//!   node opens on its own by half of
//!   [`NetworkConfig::max_connections`](crate::NetworkConfig::max_connections). The
//!   limits of [`crate::policy`] and [`crate::limiter`] apply to every connection,
//!   relayed or not.
//! * **Logs carry ids and counts.** The libp2p crates log addresses, so while the mode
//!   is on their log output is discarded; this crate logs peer ids and counts.
//! * **Stopping stops it.** [`NetworkHandle::shutdown`](crate::NetworkHandle::shutdown)
//!   ends lookups, closes every connection (which ends the reservations) and ends the
//!   DNS thread if one is running.
//!
//! # Limits that are not papered over
//!
//! Public relays are *limited* relays: go-libp2p's default, which is what the public
//! network runs, ends a circuit after 2 minutes or 128 KiB in one direction, whichever
//! comes first. A relayed connection is enough to say `hello` and to agree on a hole
//! punch. An exchange larger than the relay's limit fails with
//! [`NetError::ConnectionClosed`] unless the direct
//! upgrade succeeded first. [`PeerInfo::relayed`](crate::PeerInfo::relayed) and
//! [`NetEvent::DirectUpgradeSucceeded`](crate::NetEvent::DirectUpgradeSucceeded) say
//! which kind of connection there is. Hole punching does not get through every NAT: a
//! node whose NAT gives every destination another port has no address to offer, and
//! then nothing is attempted.
//!
//! A node has to listen on all interfaces, or not at all
//! ([`NetworkConfig::internet`](crate::NetworkConfig::internet)). One that does not
//! listen is reached through relays only: there is no socket to punch a hole to.
//!
//! Every node in the mode holds relay reservations while it is not known to be publicly
//! reachable, also one that runs for a moment to fetch something. Such a node should
//! set [`InternetConfig::max_relays`](crate::InternetConfig::max_relays) to 0.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use libp2p::core::transport::{ListenerId, PortUse};
use libp2p::core::{ConnectedPoint, Endpoint};
use libp2p::identity::Keypair;
use libp2p::kad::{self, store::MemoryStore, QueryId};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{
    CloseConnection, ConnectionDenied, ConnectionId, FromSwarm, ListenOpts, NetworkBehaviour,
    THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::{autonat, dcutr, identify, relay, Multiaddr, PeerId, StreamProtocol};
use tokio::sync::{mpsc, oneshot};

use crate::config::InternetConfig;
use crate::error::NetError;

/// The most bootstrap addresses a configuration may list.
pub const MAX_BOOTSTRAP_ADDRS: usize = 16;

/// The most relay reservations a node holds.
pub const MAX_RELAYS: usize = 4;

/// The relay reservations a node holds unless configured otherwise.
pub const DEFAULT_RELAYS: usize = 2;

/// The most addresses one [`NetworkHandle::find_peer`](crate::NetworkHandle::find_peer)
/// returns. When servers name more, the oldest are dropped. One answer of one server
/// counts for at most half of them, so a single server cannot push out what the others
/// said.
pub const MAX_FOUND_ADDRS: usize = 16;

/// The most lookups in flight at once; one more is refused with
/// [`NetError::Busy`].
pub const MAX_CONCURRENT_FINDS: usize = 8;

/// How many of the peers the application named (looked up or dialed) are remembered as
/// peers the node must not dial on its own. Beyond it the oldest is forgotten.
pub const MAX_NAMED_PEERS: usize = 1024;

/// How many different peers have to report the same address of this node before it is
/// tested and, if a server reaches it, announced. One peer could report anything.
pub const OBSERVERS_NEEDED: usize = 3;

/// The most own addresses that are ever handed on for testing while the process runs.
/// libp2p's AutoNAT client keeps every candidate for good, so this is what bounds it.
/// A node that moved through that many networks keeps working through relays and no
/// longer finds out that it has become publicly reachable, until it is restarted.
pub const MAX_ADDRESS_CANDIDATES: usize = 32;

/// How often the node looks itself up, which is what keeps the DHT servers closest to
/// its id holding its current addresses. go-libp2p forgets the addresses of a peer
/// some minutes after it disconnected, so this has to stay well below that.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// How long a lookup keeps collecting after the first server named the peer.
pub const FIND_SETTLE: Duration = Duration::from_millis(1500);

/// The identify agent string: fixed, with no version, host or user name.
pub const AGENT_VERSION: &str = "peerharness";

/// The identify protocol-family string of the public network.
pub const PROTOCOL_VERSION: &str = "ipfs/0.1.0";

/// The DHT protocol of the public libp2p (IPFS) network.
pub const DHT_PROTOCOL: StreamProtocol = StreamProtocol::new("/ipfs/kad/1.0.0");

/// The relay service a peer has to offer to be asked for a reservation.
const HOP_PROTOCOL: StreamProtocol = relay::HOP_PROTOCOL_NAME;

/// See [`InternetConfig::public_bootstrap`].
pub(crate) const PUBLIC_BOOTSTRAP: [&str; 6] = [
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
    "/dnsaddr/va1.bootstrap.libp2p.io/p2p/12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8",
    "/ip4/104.131.131.82/udp/4001/quic-v1/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
];

/// How many DHT servers a lookup asks at the same time. Many servers of the public
/// network do not answer, and each of those costs a timeout.
const LOOKUP_PARALLELISM: usize = 8;
/// A lookup ends when this many of the servers closest to the key have answered and
/// none closer is known. Fewer than Kademlia's 20: the peer that is looked for is with
/// the closest few or with none.
const LOOKUP_CLOSEST: usize = 8;
/// How often timers are looked at.
const TICK: Duration = Duration::from_millis(250);
/// The longest a DHT query of this node runs.
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
/// The pause before a lookup of the own id that reached nobody is tried again: this
/// long after the first failure, doubling up to [`RETRY_INTERVAL`].
const RETRY_FIRST: Duration = Duration::from_secs(3);
const RETRY_INTERVAL: Duration = Duration::from_secs(60);
/// How long lookups wait for DNS to name the bootstrap peers before they start with
/// the addresses that needed no DNS.
const DNS_PATIENCE: Duration = Duration::from_secs(3);
/// The shortest time between two lookups of the own id.
const MIN_REFRESH_GAP: Duration = Duration::from_secs(20);
/// How long after the own addresses changed they are pushed to connected peers and the
/// own id is looked up again.
const ANNOUNCE_DELAY: Duration = Duration::from_millis(500);
/// A connection the node opened on its own is left alone for this long, so that what
/// it was opened for can finish.
const OWN_CONNECTION_MIN_AGE: Duration = Duration::from_secs(10);
/// How long a relay may take to accept a reservation.
const RESERVATION_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a relay that refused, timed out or dropped a reservation is left alone.
const RELAY_BACKOFF: Duration = Duration::from_secs(10 * 60);
/// How long a dial of a relay that an explicit dial or a reservation needs is expected.
const RELAY_DIAL_WINDOW: Duration = Duration::from_secs(60);
/// The most peers remembered as possible relays.
const MAX_RELAY_CANDIDATES: usize = 32;
/// The most relays remembered as recently failed.
const MAX_RELAY_BACKOFFS: usize = 64;
/// The most relays a dial is currently expected for.
const MAX_RELAY_DIALS: usize = 16;
/// The most different observed addresses of this node that are counted at once.
const MAX_OBSERVED_ADDRS: usize = 16;
/// The most peers whose reports are remembered to judge the kind of NAT.
const MAX_OBSERVERS: usize = 64;
/// With reports from this many peers and no address that enough of them agree on, every
/// peer sees the node at another address: it is behind a NAT that cannot be dialed.
const SYMMETRIC_OBSERVERS: usize = 8;
/// A confirmed address is dropped after this many peers in a row saw the node somewhere
/// else: the node has moved.
const STALE_AFTER_MISSES: usize = 12;
/// The most confirmed direct addresses that are kept.
const MAX_DIRECT_ADDRS: usize = 8;
/// The most addresses the node offers for one dial of its own.
const MAX_DIAL_ADDRS: usize = 8;
/// The most addresses taken from DNS for one bootstrap peer, and in total.
const MAX_ADDRS_PER_BOOTSTRAP: usize = 8;
const MAX_RESOLVED_ADDRS: usize = 64;
/// The most DNS lookups for one resolution of the bootstrap list.
const MAX_DNS_LOOKUPS: usize = 48;
/// The deepest chain of `/dnsaddr` records that is followed.
const MAX_DNSADDR_DEPTH: usize = 3;
/// How long one resolution of the bootstrap list may take.
const RESOLVE_DEADLINE: Duration = Duration::from_secs(30);
/// How many things the libp2p behaviours may hand over in one poll before the rest of
/// the swarm gets its turn.
const POLL_BUDGET: usize = 256;
/// The shortest time between two reports of what the libp2p layers complained about.
const PROBLEM_REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// Whether other nodes can dial this node directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reachability {
    /// A server of the public network dialed an address of this node on a fresh
    /// connection: others can, too.
    Public,
    /// Not directly: the address peers see the node at could not be dialed, or every
    /// peer sees it at another one.
    Private,
    /// Not known (yet): too few peers reported an address, or none could test it.
    Unknown,
}

impl Reachability {
    /// `"public"`, `"private"` or `"unknown"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Reachability::Public => "public",
            Reachability::Private => "private",
            Reachability::Unknown => "unknown",
        }
    }
}

/// Where a node stands on the public network
/// ([`NetworkHandle::internet_status`](crate::NetworkHandle::internet_status)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InternetStatus {
    /// Whether the mode is on. If not, everything else is empty.
    pub enabled: bool,
    /// Whether a lookup of the own id reached at least one DHT server: the node is on
    /// the network and the servers closest to it have seen it.
    pub bootstrapped: bool,
    /// The DHT servers in the routing table.
    pub routing_peers: usize,
    /// Whether the node can be dialed directly.
    pub reachability: Reachability,
    /// The confirmed addresses others can dial directly, each ending in
    /// `/p2p/<own peer id>`. Empty unless [`Reachability::Public`].
    pub external_addrs: Vec<Multiaddr>,
    /// The relay addresses the node holds a reservation for, each in the form
    /// `/…/p2p/<relay>/p2p-circuit/p2p/<own peer id>`.
    pub relay_addrs: Vec<Multiaddr>,
}

impl InternetStatus {
    pub(crate) fn off() -> Self {
        Self {
            enabled: false,
            bootstrapped: false,
            routing_peers: 0,
            reachability: Reachability::Unknown,
            external_addrs: Vec::new(),
            relay_addrs: Vec::new(),
        }
    }
}

/// Whether `addr` goes through a relay (it has a `/p2p-circuit` component).
pub fn is_relayed(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| p == Protocol::P2pCircuit)
}

/// Whether `ip` is an address of the public internet: not private, loopback,
/// link-local, shared (CGNAT), documentation, benchmarking, multicast or otherwise
/// reserved. Deliberately strict: a wrong "no" costs a hint, a wrong "yes" a dial into
/// somebody's local network.
pub(crate) fn is_global_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_broadcast()
                || a.is_documentation()
                || a.is_unspecified()
                || a.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 240)
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            // Global unicast is 2000::/3; within it, leave out documentation
            // (2001:db8::/32), 6to4 (2002::/16) and Teredo (2001::/32), which carry
            // an IPv4 address that was not looked at.
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && s[1] == 0x0db8)
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && s[1] == 0)
        }
    }
}

/// Whether the node may use `ip` at all: any address that can name one host when
/// private addresses are allowed, a public one otherwise.
fn usable_ip(ip: &IpAddr, allow_private: bool) -> bool {
    if allow_private {
        match ip {
            IpAddr::V4(a) => !(a.is_unspecified() || a.is_multicast() || a.is_broadcast()),
            IpAddr::V6(a) => !(a.is_unspecified() || a.is_multicast()),
        }
    } else {
        is_global_ip(ip)
    }
}

/// The parts of `/ip4|ip6/<address>/udp/<port>/quic-v1[/p2p/<peer>]`, or `None` if
/// `addr` is anything else.
fn quic_parts(addr: &Multiaddr) -> Option<(IpAddr, u16, Option<PeerId>)> {
    let mut parts = addr.iter();
    let ip = match parts.next()? {
        Protocol::Ip4(a) => IpAddr::V4(a),
        Protocol::Ip6(a) => IpAddr::V6(a),
        _ => return None,
    };
    let port = match parts.next()? {
        Protocol::Udp(port) if port != 0 => port,
        _ => return None,
    };
    if !matches!(parts.next()?, Protocol::QuicV1) {
        return None;
    }
    let peer = match parts.next() {
        None => None,
        Some(Protocol::P2p(peer)) => Some(peer),
        Some(_) => return None,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((ip, port, peer))
}

fn quic_addr(ip: IpAddr, port: u16) -> Multiaddr {
    Multiaddr::empty()
        .with(match ip {
            IpAddr::V4(a) => Protocol::Ip4(a),
            IpAddr::V6(a) => Protocol::Ip6(a),
        })
        .with(Protocol::Udp(port))
        .with(Protocol::QuicV1)
}

/// `addr` as `/ip4|ip6/…/udp/…/quic-v1` if it is such an address of `peer` (it names no
/// other peer) at an IP address the node may use.
fn direct_addr(addr: &Multiaddr, peer: &PeerId, allow_private: bool) -> Option<Multiaddr> {
    let (ip, port, named) = quic_parts(addr)?;
    if named.is_some_and(|p| p != *peer) || !usable_ip(&ip, allow_private) {
        return None;
    }
    Some(quic_addr(ip, port))
}

/// A relayed address taken apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Circuit {
    /// Where the relay is, as `/ip4|ip6/…/udp/…/quic-v1`.
    pub(crate) relay_addr: Multiaddr,
    pub(crate) relay: PeerId,
    /// The peer behind the relay, if the address names it.
    pub(crate) target: Option<PeerId>,
}

/// The parts of `/ip4|ip6/…/udp/…/quic-v1/p2p/<relay>/p2p-circuit[/p2p/<target>]`, or
/// `None` if `addr` is anything else or the relay's IP address is one the node may not
/// use.
pub(crate) fn circuit_parts(addr: &Multiaddr, allow_private: bool) -> Option<Circuit> {
    let mut parts = addr.iter();
    let head: Multiaddr = parts.by_ref().take(4).collect();
    let (ip, port, relay) = quic_parts(&head)?;
    let relay = relay?;
    if !usable_ip(&ip, allow_private) || !matches!(parts.next()?, Protocol::P2pCircuit) {
        return None;
    }
    let target = match parts.next() {
        None => None,
        Some(Protocol::P2p(peer)) => Some(peer),
        Some(_) => return None,
    };
    if parts.next().is_some() || target == Some(relay) {
        return None;
    }
    Some(Circuit {
        relay_addr: quic_addr(ip, port),
        relay,
        target,
    })
}

/// An address a DHT server gave for `target`, in the one of the two forms
/// [`NetworkHandle::dial`](crate::NetworkHandle::dial) takes, ending in
/// `/p2p/<target>`: direct, or through a relay that is reached over QUIC. `None` for
/// everything else.
fn found_addr(target: &PeerId, addr: &Multiaddr, allow_private: bool) -> Option<Multiaddr> {
    if let Some(direct) = direct_addr(addr, target, allow_private) {
        return Some(direct.with(Protocol::P2p(*target)));
    }
    let circuit = circuit_parts(addr, allow_private)?;
    if circuit.target.is_some_and(|t| t != *target) || circuit.relay == *target {
        return None;
    }
    Some(
        circuit
            .relay_addr
            .with(Protocol::P2p(circuit.relay))
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(*target)),
    )
}

/// Whether `addr` can be in [`InternetConfig::bootstrap`]: it ends in `/p2p/<peer>` and
/// is a QUIC address by IP or by name, or a `/dnsaddr` name.
pub(crate) fn is_bootstrap_addr(addr: &Multiaddr) -> bool {
    let parts: Vec<Protocol<'_>> = addr.iter().collect();
    match parts.as_slice() {
        [Protocol::Ip4(_) | Protocol::Ip6(_), ..] => {
            quic_parts(addr).is_some_and(|(ip, _, peer)| peer.is_some() && !ip.is_unspecified())
        }
        [Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_), Protocol::Udp(port), Protocol::QuicV1, Protocol::P2p(_)] => {
            *port != 0
        }
        [Protocol::Dnsaddr(_), Protocol::P2p(_)] => true,
        _ => false,
    }
}

/// Why the node refused to dial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refused {
    /// The peer is one the application named: only the application dials it.
    Named,
    /// An address is not one the node dials on its own.
    Address,
    /// The node holds as many connections as it opens on its own.
    Budget,
    /// The mode is stopping.
    Stopped,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Refused::Named => "not dialed without the application asking",
            Refused::Address => "address not dialed by the node itself",
            Refused::Budget => "connection budget of the internet mode used up",
            Refused::Stopped => "internet mode stopped",
        })
    }
}

impl std::error::Error for Refused {}

/// The libp2p behaviours of the mode.
#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
pub(crate) struct Stack {
    kad: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
    autonat: autonat::v2::client::Behaviour,
    relay: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
}

/// What the mode reports to the event loop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InternetEvent {
    Reachability(Reachability),
    RelayReserved {
        relay: PeerId,
        relays: usize,
    },
    RelayLost {
        relay: PeerId,
        relays: usize,
    },
    /// The hole punch with `peer` failed. The event loop knows whether a direct
    /// connection exists all the same.
    UpgradeFailed {
        peer: PeerId,
    },
}

type FindReply = oneshot::Sender<Result<Vec<Multiaddr>, NetError>>;

/// One lookup of a peer.
struct Find {
    target: PeerId,
    /// What servers named so far, oldest first, at most [`MAX_FOUND_ADDRS`].
    found: Vec<Multiaddr>,
    reply: Option<FindReply>,
    deadline: Instant,
    /// When to stop collecting: set when the first address arrived.
    settle: Option<Instant>,
}

impl Find {
    fn record(&mut self, addr: Multiaddr, now: Instant) {
        if let Some(i) = self.found.iter().position(|a| *a == addr) {
            self.found.remove(i);
        } else if self.found.len() >= MAX_FOUND_ADDRS {
            self.found.remove(0);
        }
        self.found.push(addr);
        self.settle.get_or_insert(now + FIND_SETTLE);
    }

    /// Answers the caller: newest first.
    fn finish(&mut self) {
        if let Some(reply) = self.reply.take() {
            let mut found = std::mem::take(&mut self.found);
            found.reverse();
            let _ = reply.send(Ok(found));
        }
    }
}

/// One relay the node holds, or asks for, a reservation with.
struct RelaySlot {
    listener: ListenerId,
    reserved: bool,
    asked: Instant,
}

/// One connection, as far as the mode cares.
struct Link {
    peer: PeerId,
    /// The address the node dialed, if it is the dialer of a direct connection.
    dialed: Option<Multiaddr>,
    relayed: bool,
    /// Whether the node opened it on its own (to a DHT server or a relay), as opposed
    /// to the application dialing or the other side connecting.
    own: bool,
    /// Whether the node has asked for it to be closed.
    closing: bool,
    since: Instant,
}

/// The addresses peers say they see this node at.
#[derive(Default)]
struct Observed {
    /// Address, who reported it, and whether it was handed on for testing.
    seen: Vec<(Multiaddr, Vec<PeerId>, bool)>,
    /// Who reported anything at all.
    observers: Vec<PeerId>,
    /// How many addresses were ever handed on.
    offered: usize,
}

impl Observed {
    /// Counts a report. Returns the address if it should now be tested.
    fn report(&mut self, peer: PeerId, addr: Multiaddr, needed: usize) -> Option<Multiaddr> {
        if !self.observers.contains(&peer) && self.observers.len() < MAX_OBSERVERS {
            self.observers.push(peer);
        }
        let i = match self.seen.iter().position(|(a, _, _)| *a == addr) {
            Some(i) => i,
            None => {
                if self.seen.len() >= MAX_OBSERVED_ADDRS {
                    // Make room: drop the address that the fewest peers reported and
                    // that was not handed on (a NAT that shows every peer another
                    // address fills the list with such addresses), or else the oldest.
                    let weakest = self
                        .seen
                        .iter()
                        .enumerate()
                        .filter(|(_, (_, _, offered))| !offered)
                        .min_by_key(|(_, (_, who, _))| who.len())
                        .map_or(0, |(i, _)| i);
                    self.seen.remove(weakest);
                }
                self.seen.push((addr, Vec::new(), false));
                self.seen.len() - 1
            }
        };
        let (addr, who, offered) = &mut self.seen[i];
        if !who.contains(&peer) && who.len() < needed.max(1) {
            who.push(peer);
        }
        if *offered || who.len() < needed.max(1) || self.offered >= MAX_ADDRESS_CANDIDATES {
            return None;
        }
        *offered = true;
        self.offered += 1;
        Some(addr.clone())
    }
}

/// The internet mode as one behaviour: libp2p's behaviours behind a gate.
///
/// It is a `NetworkBehaviour` of its own, not the five libp2p behaviours side by side,
/// because of what it keeps between them and the swarm:
///
/// * every dial they ask for passes [`Internet::handle_pending_outbound_connection`],
///   which refuses a peer the application named, an address the node does not dial on
///   its own, and anything over the connection budget;
/// * the addresses they would add to a dial are filtered the same way, and the ones a
///   DHT server gave for the target of a lookup end up in the lookup's answer instead
///   of in a dial;
/// * what peers report as this node's address is counted here, and only an address
///   that enough of them agree on reaches the AutoNAT client and the hole puncher;
/// * what they learn about other peers' addresses is not passed on to the swarm.
pub(crate) struct Internet {
    stack: Toggle<Stack>,
    local_peer_id: PeerId,
    allow_private: bool,
    max_relays: usize,
    /// Connections beyond which the node opens none on its own.
    budget: usize,
    /// Bootstrap addresses that need no DNS, and those DNS gave.
    bootstrap: Vec<(PeerId, Multiaddr)>,
    /// Bootstrap addresses that need DNS.
    names: Vec<Multiaddr>,
    resolving: Option<Resolving>,
    resolving_since: Option<Instant>,
    resolved: usize,

    /// The dial the application is making right now.
    explicit: Option<ConnectionId>,
    /// The application's dials that have not connected or failed yet.
    explicit_pending: HashSet<ConnectionId>,
    /// Relays a dial is expected for, because the application dialed through them or
    /// the node asks them for a reservation: relay, its address, until when.
    relay_dials: VecDeque<(PeerId, Multiaddr, Instant)>,
    /// Peers the application named, oldest first.
    named: VecDeque<PeerId>,
    named_set: HashSet<PeerId>,

    links: HashMap<ConnectionId, Link>,
    connected: HashMap<PeerId, usize>,
    /// Listen addresses that are not relayed.
    listen_addrs: Vec<Multiaddr>,

    finds: HashMap<QueryId, Find>,
    /// Lookups that wait for the first DHT server to be known: peer, deadline, reply.
    waiting: Vec<(PeerId, Instant, FindReply)>,

    observed: Observed,
    /// Confirmed direct addresses and, for each, how many peers in a row saw the node
    /// elsewhere.
    direct: Vec<(Multiaddr, usize)>,
    /// Confirmed relayed addresses.
    circuits: Vec<Multiaddr>,
    probe_failures: usize,
    /// There was a reason to think that the node cannot be dialed.
    seen_private: bool,
    reachability: Reachability,

    relay_candidates: VecDeque<(PeerId, Multiaddr)>,
    relays: HashMap<PeerId, RelaySlot>,
    relay_backoff: VecDeque<(PeerId, Instant)>,

    bootstrapped: bool,
    /// Lookups of the own id in a row that reached nobody.
    lookup_failures: u32,
    self_lookup: Option<QueryId>,
    /// When the own id was last looked up, and when it is due again.
    last_refresh: Option<Instant>,
    next_refresh: Instant,
    /// The addresses changed since the last lookup of the own id.
    refresh_wanted: bool,
    announce_at: Option<Instant>,

    tick: Option<tokio::time::Interval>,
    pending: VecDeque<ToSwarm<InternetEvent, THandlerInEvent<Self>>>,
    problems: Arc<AtomicUsize>,
    problems_reported: Option<Instant>,
    stopped: bool,
}

impl Internet {
    /// The mode off: no behaviour, no protocol, no timer. Never produces an event.
    pub(crate) fn off(local_peer_id: PeerId) -> Self {
        Self {
            stack: Toggle::from(None),
            local_peer_id,
            allow_private: false,
            max_relays: 0,
            budget: 0,
            bootstrap: Vec::new(),
            names: Vec::new(),
            resolving: None,
            resolving_since: None,
            resolved: 0,
            explicit: None,
            explicit_pending: HashSet::new(),
            relay_dials: VecDeque::new(),
            named: VecDeque::new(),
            named_set: HashSet::new(),
            links: HashMap::new(),
            connected: HashMap::new(),
            listen_addrs: Vec::new(),
            finds: HashMap::new(),
            waiting: Vec::new(),
            observed: Observed::default(),
            direct: Vec::new(),
            circuits: Vec::new(),
            probe_failures: 0,
            seen_private: false,
            reachability: Reachability::Unknown,
            relay_candidates: VecDeque::new(),
            relays: HashMap::new(),
            relay_backoff: VecDeque::new(),
            bootstrapped: false,
            lookup_failures: 0,
            self_lookup: None,
            last_refresh: None,
            next_refresh: Instant::now(),
            refresh_wanted: false,
            announce_at: None,
            tick: None,
            pending: VecDeque::new(),
            problems: Arc::new(AtomicUsize::new(0)),
            problems_reported: None,
            stopped: false,
        }
    }

    /// The mode on. `relay` is the behaviour that belongs to the relay transport of the
    /// swarm; `max_connections` is the connection limit of the node, half of which the
    /// mode may use for connections it opens on its own; `problems` counts what the
    /// libp2p layers complain about (see [`quiet`]).
    pub(crate) fn on(
        keypair: &Keypair,
        relay: relay::client::Behaviour,
        config: &InternetConfig,
        max_connections: usize,
        problems: Arc<AtomicUsize>,
    ) -> Self {
        let local_peer_id = keypair.public().to_peer_id();
        let mut me = Self::off(local_peer_id);
        me.allow_private = config.allow_private_addresses;
        me.max_relays = config.max_relays.min(MAX_RELAYS);
        me.budget = (max_connections / 2).max(1);
        me.problems = problems;

        let mut kad_config = kad::Config::new(DHT_PROTOCOL);
        kad_config
            .set_query_timeout(QUERY_TIMEOUT)
            .set_parallelism(NonZeroUsize::new(LOOKUP_PARALLELISM).unwrap_or(NonZeroUsize::MIN))
            // The node looks itself up on its own schedule and stores nothing.
            .set_periodic_bootstrap_interval(None)
            .set_replication_interval(None)
            .set_publication_interval(None)
            .set_provider_publication_interval(None)
            .set_caching(kad::Caching::Disabled);
        let mut kad =
            kad::Behaviour::with_config(local_peer_id, MemoryStore::new(local_peer_id), kad_config);
        // Never a server, whatever addresses get confirmed.
        kad.set_mode(Some(kad::Mode::Client));

        let identify = identify::Behaviour::new(
            identify::Config::new(PROTOCOL_VERSION.to_owned(), keypair.public())
                .with_agent_version(AGENT_VERSION.to_owned())
                // Confirmed addresses only: no LAN or loopback address leaves the node.
                .with_hide_listen_addrs(true)
                // What peers say about their own addresses is not kept for dialing.
                .with_cache_size(0),
        );

        for addr in &config.bootstrap {
            let Some(Protocol::P2p(peer)) = addr.iter().last() else {
                continue;
            };
            if peer == local_peer_id {
                continue;
            }
            match quic_parts(addr) {
                Some((ip, port, _)) => {
                    let addr = quic_addr(ip, port);
                    kad.add_address(&peer, addr.clone());
                    me.bootstrap.push((peer, addr));
                }
                None => me.names.push(addr.clone()),
            }
        }

        me.stack = Toggle::from(Some(Stack {
            kad,
            identify,
            autonat: autonat::v2::client::Behaviour::default(),
            relay,
            dcutr: dcutr::Behaviour::new(local_peer_id),
        }));
        me.resolve_names();
        me
    }

    pub(crate) fn is_on(&self) -> bool {
        self.stack.is_enabled()
    }

    /// Whether `connection` is one the node opened on its own, to a DHT server or a
    /// relay. Such a connection is the mode's business and not the application's.
    pub(crate) fn is_own(&self, connection: ConnectionId) -> bool {
        self.links.get(&connection).is_some_and(|link| link.own)
    }

    /// Marks the dial the application is about to make with `connection`, so that the
    /// gate lets it through, and remembers who it names: the peer as one the node will
    /// not dial on its own, and the relay of a relayed address as one the relay client
    /// may dial for this. Followed by [`Internet::dial_made`].
    pub(crate) fn dial_asked(&mut self, connection: ConnectionId, addr: &Multiaddr) {
        if !self.is_on() {
            return;
        }
        self.explicit = Some(connection);
        self.explicit_pending.insert(connection);
        if let Some(circuit) = circuit_parts(addr, true) {
            self.expect_relay_dial(circuit.relay, circuit.relay_addr);
        }
        if let Some(Protocol::P2p(peer)) = addr.iter().last() {
            self.name(peer);
        }
    }

    /// The application's dial was handed to the swarm, which took it or not.
    pub(crate) fn dial_made(&mut self, connection: ConnectionId, accepted: bool) {
        self.explicit = None;
        if !accepted {
            self.explicit_pending.remove(&connection);
        }
    }

    /// Looks `peer` up. The answer goes to `reply`, at the latest after `timeout`.
    pub(crate) fn find(&mut self, peer: PeerId, timeout: Duration, reply: FindReply) {
        if !self.is_on() {
            let _ = reply.send(Err(NetError::InternetOff));
            return;
        }
        if self.stopped {
            let _ = reply.send(Err(NetError::Shutdown));
            return;
        }
        if peer == self.local_peer_id {
            let _ = reply.send(Ok(Vec::new()));
            return;
        }
        if self.finds.len() + self.waiting.len() >= MAX_CONCURRENT_FINDS {
            let _ = reply.send(Err(NetError::Busy));
            return;
        }
        self.name(peer);
        let deadline = Instant::now() + timeout.min(QUERY_TIMEOUT);
        self.waiting.push((peer, deadline, reply));
        self.start_finds(Instant::now());
    }

    /// Starts the lookups that wait, once a DHT server is known to ask, and answers
    /// those whose time is up.
    fn start_finds(&mut self, now: Instant) {
        if self.waiting.is_empty() {
            return;
        }
        let ready = self.ready(now);
        let Some(stack) = self.stack.as_mut() else {
            return;
        };
        for (peer, deadline, reply) in std::mem::take(&mut self.waiting) {
            if now >= deadline {
                let _ = reply.send(Ok(Vec::new()));
            } else if ready {
                let closest = NonZeroUsize::new(LOOKUP_CLOSEST).unwrap_or(NonZeroUsize::MIN);
                let query = stack.kad.get_n_closest_peers(peer, closest);
                tracing::debug!(peer = %peer, "looking a peer up on the public network");
                self.finds.insert(
                    query,
                    Find {
                        target: peer,
                        found: Vec::new(),
                        reply: Some(reply),
                        deadline,
                        settle: None,
                    },
                );
            } else {
                self.waiting.push((peer, deadline, reply));
            }
        }
    }

    pub(crate) fn status(&mut self) -> InternetStatus {
        let me = self.local_peer_id;
        let Some(stack) = self.stack.as_mut() else {
            return InternetStatus::off();
        };
        InternetStatus {
            enabled: true,
            bootstrapped: self.bootstrapped,
            routing_peers: stack.kad.kbuckets().map(|b| b.num_entries()).sum(),
            reachability: self.reachability,
            external_addrs: self
                .direct
                .iter()
                .map(|(a, _)| a.clone().with(Protocol::P2p(me)))
                .collect(),
            relay_addrs: self.circuits.clone(),
        }
    }

    /// Stops the mode: lookups are answered with [`NetError::Shutdown`], the DNS thread
    /// ends, relay listeners are closed, and the node dials nothing on its own any
    /// more. Connections are closed by the event loop.
    pub(crate) fn stop(&mut self) {
        self.stopped = true;
        self.resolving = None;
        for (_, mut find) in self.finds.drain() {
            if let Some(reply) = find.reply.take() {
                let _ = reply.send(Err(NetError::Shutdown));
            }
        }
        for (_, _, reply) in self.waiting.drain(..) {
            let _ = reply.send(Err(NetError::Shutdown));
        }
        for slot in self.relays.values() {
            self.pending
                .push_back(ToSwarm::RemoveListener { id: slot.listener });
        }
    }

    fn name(&mut self, peer: PeerId) {
        if self.named_set.insert(peer) {
            self.named.push_back(peer);
            if self.named.len() > MAX_NAMED_PEERS {
                if let Some(old) = self.named.pop_front() {
                    self.named_set.remove(&old);
                }
            }
        }
    }

    fn expect_relay_dial(&mut self, relay: PeerId, relay_addr: Multiaddr) {
        let until = Instant::now() + RELAY_DIAL_WINDOW;
        self.relay_dials.retain(|(p, _, _)| *p != relay);
        if self.relay_dials.len() >= MAX_RELAY_DIALS {
            self.relay_dials.pop_front();
        }
        self.relay_dials.push_back((relay, relay_addr, until));
    }

    /// Starts resolving the bootstrap names, unless that is running or there are none.
    fn resolve_names(&mut self) {
        if self.names.is_empty() || self.resolving.is_some() || self.stopped {
            return;
        }
        match Resolving::start(self.names.clone()) {
            Ok(resolving) => {
                self.resolving = Some(resolving);
                self.resolving_since = Some(Instant::now());
            }
            Err(_) => tracing::warn!(
                names = self.names.len(),
                "internet: the bootstrap names could not be resolved (no thread)"
            ),
        }
    }

    /// Whether lookups can start: a DHT server is known, and DNS has had its time to
    /// name the others. A lookup asks the servers that are known when it starts, so one
    /// that starts with a single server stands or falls with that server.
    fn ready(&mut self, now: Instant) -> bool {
        let settled = self.resolving.is_none()
            || self
                .resolving_since
                .is_some_and(|t| now.saturating_duration_since(t) >= DNS_PATIENCE);
        settled
            && self
                .stack
                .as_mut()
                .is_some_and(|s| s.kad.kbuckets().next().is_some())
    }

    /// Whether a non-loopback address of the family of `ip` is listened on (any
    /// address, when private ones are allowed): only then can an observed address be
    /// one that others reach this node at.
    fn listens_on_family_of(&self, ip: &IpAddr) -> bool {
        self.listen_addrs.iter().any(|a| match a.iter().next() {
            Some(Protocol::Ip4(l)) => ip.is_ipv4() && (self.allow_private || !l.is_loopback()),
            Some(Protocol::Ip6(l)) => ip.is_ipv6() && (self.allow_private || !l.is_loopback()),
            _ => false,
        })
    }

    fn update_reachability(&mut self) {
        // Once there was a reason to think the node cannot be dialed, that stands until
        // an address is confirmed: an address that is still under test is no news.
        self.seen_private |= self.probe_failures > 0
            || (self.observed.observers.len() >= SYMMETRIC_OBSERVERS && self.observed.offered == 0);
        let new = if !self.direct.is_empty() {
            Reachability::Public
        } else if self.seen_private {
            Reachability::Private
        } else {
            Reachability::Unknown
        };
        if new != self.reachability {
            self.reachability = new;
            tracing::info!(
                reachability = new.as_str(),
                "internet: reachability changed"
            );
            self.pending
                .push_back(ToSwarm::GenerateEvent(InternetEvent::Reachability(new)));
        }
    }

    /// The addresses changed: tell the connected peers soon, and the DHT servers
    /// closest to the own id, which may not be connected any more.
    fn announce_soon(&mut self, now: Instant) {
        self.announce_at.get_or_insert(now + ANNOUNCE_DELAY);
    }

    fn on_tick(&mut self, now: Instant) {
        self.start_finds(now);
        // Lookups that are due.
        let due: Vec<QueryId> = self
            .finds
            .iter()
            .filter(|(_, f)| now >= f.deadline || f.settle.is_some_and(|t| now >= t))
            .map(|(id, _)| *id)
            .collect();
        for id in due {
            if let Some(mut find) = self.finds.remove(&id) {
                tracing::debug!(peer = %find.target, addresses = find.found.len(), "lookup finished");
                find.finish();
            }
            if let Some(mut query) = self.stack.as_mut().and_then(|s| s.kad.query_mut(&id)) {
                query.finish();
            }
        }

        self.relay_dials.retain(|(_, _, until)| now < *until);
        self.relay_backoff.retain(|(_, until)| now < *until);
        if self.stopped {
            return;
        }

        if self.announce_at.is_some_and(|t| now >= t) {
            self.announce_at = None;
            let peers: Vec<PeerId> = self.connected.keys().copied().collect();
            tracing::debug!(
                peers = peers.len(),
                "internet: pushing the changed addresses to connected peers"
            );
            if let Some(stack) = self.stack.as_mut() {
                stack.identify.push(peers);
            }
            self.refresh_wanted = true;
        }

        // The lookup of the own id.
        let gap_over = self
            .last_refresh
            .is_none_or(|t| now.saturating_duration_since(t) >= MIN_REFRESH_GAP);
        let due = now >= self.next_refresh || self.refresh_wanted;
        let me = self.local_peer_id;
        let ready = self.ready(now);
        if let Some(stack) = self.stack.as_mut() {
            // libp2p starts a "bootstrap" by itself whenever the routing table is
            // small: a lookup of the own id with Kademlia's full width, then one lookup
            // per bucket. That would have the node contact some hundred servers for a
            // routing table it does not need. The node looks its own id up itself,
            // below, so each of those is ended as soon as it shows up.
            for mut query in stack.kad.iter_queries_mut() {
                if matches!(query.info(), kad::QueryInfo::Bootstrap { .. }) {
                    query.finish();
                }
            }
            if due && self.self_lookup.is_none() && gap_over && ready {
                let closest = NonZeroUsize::new(LOOKUP_CLOSEST).unwrap_or(NonZeroUsize::MIN);
                self.self_lookup = Some(stack.kad.get_n_closest_peers(me, closest));
                self.last_refresh = Some(now);
                self.next_refresh = now + REFRESH_INTERVAL;
                self.refresh_wanted = false;
            }
        }

        self.manage_relays(now);
        self.trim(now);
        self.report_problems(now);
    }

    /// Closes the oldest of the connections the node opened on its own once they are
    /// more than half of what it may open. A lookup leaves dozens of connections to
    /// DHT servers behind that nothing uses any more; without this they would sit until
    /// they time out and keep the next lookup from dialing.
    fn trim(&mut self, now: Instant) {
        let keep = self.budget / 2;
        let mut own: Vec<(Instant, ConnectionId, PeerId)> = self
            .links
            .iter()
            .filter(|(_, link)| link.own && !link.closing && !self.relays.contains_key(&link.peer))
            .map(|(id, link)| (link.since, *id, link.peer))
            .collect();
        if own.len() <= keep {
            return;
        }
        own.sort_unstable_by_key(|(since, _, _)| *since);
        let excess = own.len() - keep;
        let mut closed = 0usize;
        for (since, connection, peer_id) in own.into_iter().take(excess) {
            if now.saturating_duration_since(since) < OWN_CONNECTION_MIN_AGE {
                break;
            }
            // Counted as gone at once, so that the next tick does not close more.
            if let Some(link) = self.links.get_mut(&connection) {
                link.closing = true;
            }
            closed += 1;
            self.pending.push_back(ToSwarm::CloseConnection {
                peer_id,
                connection: CloseConnection::One(connection),
            });
        }
        if closed > 0 {
            tracing::debug!(
                closed,
                "internet: closed connections to DHT servers that are no longer needed"
            );
        }
    }

    fn manage_relays(&mut self, now: Instant) {
        let wanted = if self.reachability == Reachability::Public {
            0
        } else {
            self.max_relays
        };
        // Reservations that are not answered, and all of them once they are not needed.
        let drop: Vec<PeerId> = self
            .relays
            .iter()
            .filter(|(_, slot)| {
                wanted == 0
                    || (!slot.reserved
                        && now.saturating_duration_since(slot.asked) >= RESERVATION_TIMEOUT)
            })
            .map(|(relay, _)| *relay)
            .collect();
        for relay in drop {
            if let Some(slot) = self.relays.remove(&relay) {
                self.pending
                    .push_back(ToSwarm::RemoveListener { id: slot.listener });
                self.relay_dropped(relay, slot.reserved, now);
            }
        }
        while self.relays.len() < wanted {
            let usable = |(relay, _): &(PeerId, Multiaddr)| {
                !self.relays.contains_key(relay)
                    && !self.relay_backoff.iter().any(|(p, _)| p == relay)
            };
            // A relay at an IPv4 address first: everybody can reach those.
            let ip4 = |(_, addr): &(PeerId, Multiaddr)| {
                matches!(addr.iter().next(), Some(Protocol::Ip4(_)))
            };
            let Some(i) = self
                .relay_candidates
                .iter()
                .position(|c| usable(c) && ip4(c))
                .or_else(|| self.relay_candidates.iter().position(usable))
            else {
                break;
            };
            let Some((relay, addr)) = self.relay_candidates.remove(i) else {
                break;
            };
            let listen = addr
                .clone()
                .with(Protocol::P2p(relay))
                .with(Protocol::P2pCircuit);
            let opts = ListenOpts::new(listen);
            self.relays.insert(
                relay,
                RelaySlot {
                    listener: opts.listener_id(),
                    reserved: false,
                    asked: now,
                },
            );
            self.expect_relay_dial(relay, addr);
            tracing::debug!(relay = %relay, "internet: asking a relay for a reservation");
            self.pending.push_back(ToSwarm::ListenOn { opts });
        }
    }

    /// A relay left the list: leave it alone for a while and say so if it was held.
    fn relay_dropped(&mut self, relay: PeerId, was_reserved: bool, now: Instant) {
        if self.relay_backoff.len() >= MAX_RELAY_BACKOFFS {
            self.relay_backoff.pop_front();
        }
        self.relay_backoff.push_back((relay, now + RELAY_BACKOFF));
        if was_reserved {
            let relays = self.relays.values().filter(|s| s.reserved).count();
            tracing::info!(relay = %relay, relays, "internet: relay reservation lost");
            self.pending
                .push_back(ToSwarm::GenerateEvent(InternetEvent::RelayLost {
                    relay,
                    relays,
                }));
        }
    }

    fn report_problems(&mut self, now: Instant) {
        if self.problems.load(Ordering::Relaxed) == 0 {
            return;
        }
        let due = self
            .problems_reported
            .is_none_or(|t| now.saturating_duration_since(t) >= PROBLEM_REPORT_INTERVAL);
        if due {
            self.problems_reported = Some(now);
            let count = self.problems.swap(0, Ordering::Relaxed);
            tracing::debug!(
                count,
                "internet: the libp2p layers reported warnings (their messages are not logged)"
            );
        }
    }

    /// Takes what DNS gave for the bootstrap names.
    fn poll_resolving(&mut self, cx: &mut Context<'_>) {
        let Some(resolving) = self.resolving.as_mut() else {
            return;
        };
        loop {
            match resolving.results.poll_recv(cx) {
                Poll::Ready(Some((peer, addr))) => {
                    if self.resolved >= MAX_RESOLVED_ADDRS || peer == self.local_peer_id {
                        continue;
                    }
                    let Some(addr) = direct_addr(&addr, &peer, self.allow_private) else {
                        continue;
                    };
                    if self.bootstrap.contains(&(peer, addr.clone())) {
                        continue;
                    }
                    self.resolved += 1;
                    if let Some(stack) = self.stack.as_mut() {
                        stack.kad.add_address(&peer, addr.clone());
                    }
                    self.bootstrap.push((peer, addr));
                }
                Poll::Ready(None) => {
                    tracing::debug!(
                        addresses = self.resolved,
                        "internet: bootstrap names resolved"
                    );
                    // Joins the thread, which has nothing left to do.
                    self.resolving = None;
                    return;
                }
                Poll::Pending => return,
            }
        }
    }

    /// Records what the DHT says about the targets of the lookups in flight.
    fn harvest(&mut self) {
        if self.finds.is_empty() {
            return;
        }
        let Some(stack) = self.stack.as_mut() else {
            return;
        };
        let now = Instant::now();
        let allow_private = self.allow_private;
        for find in self.finds.values_mut() {
            // Asks the DHT behaviour what it would add to a dial of the target, which
            // is what the servers said so far. The connection id is not used by it.
            let Ok(offered) = stack.kad.handle_pending_outbound_connection(
                ConnectionId::new_unchecked(0),
                Some(find.target),
                &[],
                Endpoint::Dialer,
            ) else {
                continue;
            };
            // What the DHT behaviour holds is the last answer that named the target.
            let target = find.target;
            let named: Vec<Multiaddr> = offered
                .iter()
                .filter_map(|addr| found_addr(&target, addr, allow_private))
                .take(MAX_FOUND_ADDRS / 2)
                .collect();
            for addr in named {
                if find.found.last() != Some(&addr) {
                    find.record(addr, now);
                }
            }
        }
    }

    fn on_stack_event(&mut self, event: StackEvent) {
        match event {
            StackEvent::Kad(kad::Event::OutboundQueryProgressed {
                id, result, stats, ..
            }) => self.on_query(id, result, &stats),
            StackEvent::Kad(_) => {}
            StackEvent::Identify(identify::Event::Received {
                connection_id,
                peer_id,
                info,
            }) => self.on_identified(connection_id, peer_id, info),
            StackEvent::Identify(_) => {}
            StackEvent::Autonat(event) => {
                if event.result.is_err() {
                    self.probe_failures = self.probe_failures.saturating_add(1);
                    tracing::debug!(server = %event.server, "internet: an own address could not be dialed back");
                    self.update_reachability();
                }
            }
            StackEvent::Relay(relay::client::Event::ReservationReqAccepted {
                relay_peer_id,
                renewal,
                limit,
            }) => {
                let Some(slot) = self.relays.get_mut(&relay_peer_id) else {
                    return;
                };
                if !slot.reserved {
                    slot.reserved = true;
                    let relays = self.relays.values().filter(|s| s.reserved).count();
                    tracing::info!(
                        relay = %relay_peer_id,
                        relays,
                        limit_bytes = limit.and_then(|l| l.data_in_bytes()).unwrap_or(0),
                        limit_secs = limit.and_then(|l| l.duration()).map_or(0, |d| d.as_secs()),
                        "internet: relay reservation held (limits are per circuit, 0 is none)"
                    );
                    self.pending
                        .push_back(ToSwarm::GenerateEvent(InternetEvent::RelayReserved {
                            relay: relay_peer_id,
                            relays,
                        }));
                } else if renewal {
                    tracing::debug!(relay = %relay_peer_id, "internet: relay reservation renewed");
                }
            }
            StackEvent::Relay(_) => {}
            StackEvent::Dcutr(dcutr::Event {
                remote_peer_id,
                result,
            }) => {
                if result.is_err() {
                    self.pending
                        .push_back(ToSwarm::GenerateEvent(InternetEvent::UpgradeFailed {
                            peer: remote_peer_id,
                        }));
                }
            }
        }
    }

    fn on_query(&mut self, id: QueryId, result: kad::QueryResult, stats: &kad::QueryStats) {
        let now = Instant::now();
        match result {
            kad::QueryResult::Bootstrap(_) => {
                // See `on_tick`: the next step of it has started; end that, too.
                if let Some(mut query) = self.stack.as_mut().and_then(|s| s.kad.query_mut(&id)) {
                    query.finish();
                }
            }
            kad::QueryResult::GetClosestPeers(_) if self.self_lookup == Some(id) => {
                self.self_lookup = None;
                tracing::debug!(
                    requests = stats.num_requests(),
                    answered = stats.num_successes(),
                    millis = stats.duration().map_or(0, |d| d.as_millis()),
                    "internet: looked the own id up"
                );
                self.on_self_lookup(stats.num_successes(), now);
            }
            kad::QueryResult::GetClosestPeers(_) => {
                self.harvest();
                if let Some(mut find) = self.finds.remove(&id) {
                    tracing::debug!(
                        peer = %find.target,
                        addresses = find.found.len(),
                        requests = stats.num_requests(),
                        millis = stats.duration().map_or(0, |d| d.as_millis()),
                        "lookup finished"
                    );
                    find.finish();
                }
            }
            _ => {}
        }
    }

    fn on_self_lookup(&mut self, successes: u32, now: Instant) {
        let reached = successes > 0;
        if reached != self.bootstrapped {
            self.bootstrapped = reached;
            let routing_peers: usize = self
                .stack
                .as_mut()
                .map_or(0, |s| s.kad.kbuckets().map(|b| b.num_entries()).sum());
            if reached {
                tracing::info!(
                    servers = successes,
                    routing_peers,
                    "internet: joined the public network"
                );
            } else {
                tracing::warn!("internet: no DHT server could be reached");
            }
        }
        if reached {
            self.lookup_failures = 0;
            self.last_refresh = Some(now);
            self.next_refresh = now + REFRESH_INTERVAL;
        } else {
            // Offline, the servers asked first did not answer, or the bootstrap peers
            // moved: retry soon, then less often, and ask DNS again if it gave nothing.
            let pause = RETRY_FIRST
                .saturating_mul(1 << self.lookup_failures.min(8))
                .min(RETRY_INTERVAL);
            self.lookup_failures = self.lookup_failures.saturating_add(1);
            self.last_refresh = None;
            self.next_refresh = now + pause;
            if self.resolved == 0 {
                self.resolve_names();
            }
        }
    }

    fn on_identified(&mut self, connection: ConnectionId, peer: PeerId, info: identify::Info) {
        let Some(link) = self.links.get(&connection) else {
            return;
        };
        if link.relayed || link.peer != peer {
            return;
        }
        // A possible relay: a server the node itself dialed, at the address it reached
        // it at, that offers the relay service.
        if let Some(dialed) = &link.dialed {
            let offers_relay = info.protocols.contains(&HOP_PROTOCOL);
            let known = self.relays.contains_key(&peer)
                || self.relay_candidates.iter().any(|(p, _)| *p == peer);
            if offers_relay && !known && self.max_relays > 0 {
                if self.relay_candidates.len() >= MAX_RELAY_CANDIDATES {
                    self.relay_candidates.pop_front();
                }
                self.relay_candidates.push_back((peer, dialed.clone()));
            }
        }
        // Where that peer sees this node.
        let Some((ip, port, _)) = quic_parts(&info.observed_addr) else {
            return;
        };
        if !usable_ip(&ip, self.allow_private) || !self.listens_on_family_of(&ip) {
            return;
        }
        let observed = quic_addr(ip, port);
        // A confirmed address that peers stop seeing is not this node's any more.
        let mut expired = Vec::new();
        for (addr, misses) in &mut self.direct {
            let same_family = quic_parts(addr).is_some_and(|(a, _, _)| a.is_ipv4() == ip.is_ipv4());
            if *addr == observed {
                *misses = 0;
            } else if same_family {
                *misses += 1;
                if *misses >= STALE_AFTER_MISSES {
                    expired.push(addr.clone());
                }
            }
        }
        for addr in expired {
            tracing::info!("internet: a confirmed address is no longer seen by peers");
            self.pending.push_back(ToSwarm::ExternalAddrExpired(addr));
        }
        let needed = if self.allow_private {
            1
        } else {
            OBSERVERS_NEEDED
        };
        if let Some(candidate) = self.observed.report(peer, observed, needed) {
            tracing::debug!(
                candidates = self.observed.offered,
                "internet: peers agree on an address of this node; testing it"
            );
            self.pending
                .push_back(ToSwarm::NewExternalAddrCandidate(candidate));
        } else if self.observed.offered >= MAX_ADDRESS_CANDIDATES {
            tracing::debug!(
                limit = MAX_ADDRESS_CANDIDATES,
                "internet: no further own address is tested until the node is restarted"
            );
        }
        self.update_reachability();
    }

    fn on_established(
        &mut self,
        connection: ConnectionId,
        peer: PeerId,
        endpoint: &ConnectedPoint,
    ) {
        let relayed = endpoint.is_relayed();
        let dialed = match endpoint {
            ConnectedPoint::Dialer { address, .. } if !relayed => {
                direct_addr(address, &peer, self.allow_private)
            }
            _ => None,
        };
        let explicit = self.explicit_pending.remove(&connection);
        // The node's own: it dialed, the application did not ask for it, and the peer
        // is not one the application has to do with (a hole punch dials such a peer).
        let own = endpoint.is_dialer()
            && !relayed
            && !explicit
            && !self.named_set.contains(&peer)
            && !self.connected.contains_key(&peer);
        self.links.insert(
            connection,
            Link {
                peer,
                dialed,
                relayed,
                own,
                closing: false,
                since: Instant::now(),
            },
        );
        *self.connected.entry(peer).or_insert(0) += 1;
    }

    fn on_closed(&mut self, connection: ConnectionId, peer: PeerId) {
        self.links.remove(&connection);
        if let Some(n) = self.connected.get_mut(&peer) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.connected.remove(&peer);
            }
        }
    }

    fn on_external_addr(&mut self, addr: &Multiaddr, confirmed: bool) {
        let now = Instant::now();
        if is_relayed(addr) {
            self.circuits.retain(|a| a != addr);
            if confirmed && self.circuits.len() < MAX_RELAYS {
                self.circuits.push(addr.clone());
            }
        } else {
            let Some((ip, port, _)) = quic_parts(addr) else {
                return;
            };
            let addr = quic_addr(ip, port);
            self.direct.retain(|(a, _)| *a != addr);
            if confirmed && self.direct.len() < MAX_DIRECT_ADDRS {
                tracing::info!("internet: an address of this node was dialed back by a server");
                self.direct.push((addr, 0));
            }
        }
        self.update_reachability();
        self.announce_soon(now);
    }

    fn on_listener_closed(&mut self, listener: ListenerId) {
        let Some(relay) = self
            .relays
            .iter()
            .find(|(_, slot)| slot.listener == listener)
            .map(|(relay, _)| *relay)
        else {
            return;
        };
        if let Some(slot) = self.relays.remove(&relay) {
            if !slot.reserved {
                tracing::debug!(relay = %relay, "internet: a relay did not give a reservation");
            }
            self.relay_dropped(relay, slot.reserved, Instant::now());
        }
    }

    /// The gate for a dial the application did not ask for. `offered` is what the
    /// behaviours would add to it.
    fn admit(
        &mut self,
        peer: PeerId,
        given: &[Multiaddr],
        offered: Vec<Multiaddr>,
    ) -> Result<Vec<Multiaddr>, Refused> {
        if self.stopped {
            return Err(Refused::Stopped);
        }
        // The relay of a relayed dial of the application, or of a reservation.
        if let [addr] = given {
            if self.relay_dials.iter().any(|(relay, expected, _)| {
                *relay == peer && direct_addr(addr, &peer, true).as_ref() == Some(expected)
            }) {
                return Ok(Vec::new());
            }
        }
        let connected = self.connected.contains_key(&peer);
        // A peer the application named is dialed by the application. The one case in
        // which the node dials it is the hole punch, which needs a connection that
        // already exists.
        if self.named_set.contains(&peer) && !connected {
            return Err(Refused::Named);
        }
        // Addresses that come with the dial are the other side's word (hole punch).
        if !given
            .iter()
            .all(|a| direct_addr(a, &peer, self.allow_private).is_some())
        {
            return Err(Refused::Address);
        }
        if !connected && self.links.len() >= self.budget {
            return Err(Refused::Budget);
        }
        let mut addrs: Vec<Multiaddr> = Vec::new();
        for addr in offered {
            let Some(addr) = direct_addr(&addr, &peer, self.allow_private) else {
                continue;
            };
            if !addrs.contains(&addr) && addrs.len() < MAX_DIAL_ADDRS {
                addrs.push(addr);
            }
        }
        Ok(addrs)
    }
}

impl NetworkBehaviour for Internet {
    type ConnectionHandler = THandler<Toggle<Stack>>;
    type ToSwarm = InternetEvent;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.stack
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.stack.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if !self.is_on() {
            return Ok(Vec::new());
        }
        let offered = self.stack.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )?;
        if self.explicit == Some(connection_id) {
            // The application's dial uses the address it was given and no other.
            return Ok(Vec::new());
        }
        // Nothing here dials without knowing whom.
        let peer = maybe_peer.ok_or_else(|| ConnectionDenied::new(Refused::Named))?;
        if self.finds.values().any(|f| f.target == peer) {
            self.harvest();
        }
        self.admit(peer, addresses, offered).map_err(|refused| {
            tracing::trace!(peer = %peer, reason = %refused, "internet: dial refused");
            ConnectionDenied::new(refused)
        })
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.stack.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        if !self.is_on() {
            return;
        }
        match event {
            FromSwarm::ConnectionEstablished(e) => {
                self.on_established(e.connection_id, e.peer_id, e.endpoint);
            }
            FromSwarm::ConnectionClosed(e) => self.on_closed(e.connection_id, e.peer_id),
            FromSwarm::DialFailure(e) => {
                self.explicit_pending.remove(&e.connection_id);
            }
            FromSwarm::ExternalAddrConfirmed(e) => self.on_external_addr(e.addr, true),
            FromSwarm::ExternalAddrExpired(e) => self.on_external_addr(e.addr, false),
            FromSwarm::NewListenAddr(e) => {
                if !is_relayed(e.addr) && !self.listen_addrs.contains(e.addr) {
                    self.listen_addrs.push(e.addr.clone());
                }
            }
            FromSwarm::ExpiredListenAddr(e) => self.listen_addrs.retain(|a| a != e.addr),
            FromSwarm::ListenerClosed(e) => self.on_listener_closed(e.listener_id),
            // What other behaviours learn about a peer's addresses stays with them.
            FromSwarm::NewExternalAddrOfPeer(_) => return,
            _ => {}
        }
        self.stack.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.stack
            .on_connection_handler_event(peer_id, connection_id, event);
        // An answer of a DHT server may name the target of a lookup.
        self.harvest();
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(event) = self.pending.pop_front() {
            return Poll::Ready(event);
        }
        if !self.is_on() {
            return Poll::Pending;
        }
        self.poll_resolving(cx);
        let tick = self.tick.get_or_insert_with(|| {
            let mut tick = tokio::time::interval(TICK);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            tick
        });
        let mut ticked = false;
        while tick.poll_tick(cx).is_ready() {
            ticked = true;
        }
        if ticked {
            self.on_tick(Instant::now());
        }
        let mut budget = POLL_BUDGET;
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Poll::Ready(event);
            }
            if budget == 0 {
                // Whoever keeps the behaviours busy gets a share of the event loop,
                // not all of it.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            budget -= 1;
            let event = match self.stack.poll(cx) {
                Poll::Ready(event) => event,
                Poll::Pending => return Poll::Pending,
            };
            match event {
                ToSwarm::GenerateEvent(event) => self.on_stack_event(event),
                // Own address candidates come from the count of reports in
                // `on_identified`, not from what a single peer says; addresses of
                // other peers are not handed to the swarm.
                ToSwarm::NewExternalAddrCandidate(_) | ToSwarm::NewExternalAddrOfPeer { .. } => {}
                ToSwarm::Dial { opts } => return Poll::Ready(ToSwarm::Dial { opts }),
                ToSwarm::ListenOn { opts } => return Poll::Ready(ToSwarm::ListenOn { opts }),
                ToSwarm::RemoveListener { id } => {
                    return Poll::Ready(ToSwarm::RemoveListener { id })
                }
                ToSwarm::NotifyHandler {
                    peer_id,
                    handler,
                    event,
                } => {
                    return Poll::Ready(ToSwarm::NotifyHandler {
                        peer_id,
                        handler,
                        event,
                    })
                }
                ToSwarm::ExternalAddrConfirmed(addr) => {
                    return Poll::Ready(ToSwarm::ExternalAddrConfirmed(addr))
                }
                ToSwarm::ExternalAddrExpired(addr) => {
                    return Poll::Ready(ToSwarm::ExternalAddrExpired(addr))
                }
                ToSwarm::CloseConnection {
                    peer_id,
                    connection,
                } => {
                    return Poll::Ready(ToSwarm::CloseConnection {
                        peer_id,
                        connection,
                    })
                }
                _ => {}
            }
        }
    }
}

/// The subscriber that is current while libp2p code of a node in internet mode runs.
///
/// The libp2p crates log addresses: identify logs observed addresses at INFO, the DHT,
/// the hole puncher, the QUIC transport and the swarm log dialed, failed and listen
/// addresses at DEBUG. PeerHarness logs ids and counts only, so while the mode is on
/// nothing a `libp2p_*` crate (or the DNS resolver) logs is written. Their warnings and
/// errors are counted, and the count is reported. Everything else, this crate's own log
/// output first of all, goes to the subscriber that was current when the node started.
struct Quiet {
    outer: tracing::Dispatch,
    problems: Arc<AtomicUsize>,
}

fn muted(metadata: &tracing::Metadata<'_>) -> bool {
    let target = metadata.target();
    target.starts_with("libp2p_") || target.starts_with("hickory")
}

fn counted(metadata: &tracing::Metadata<'_>) -> bool {
    metadata.is_event() && *metadata.level() <= tracing::Level::WARN
}

impl tracing::Subscriber for Quiet {
    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if !muted(metadata) {
            self.outer.register_callsite(metadata)
        } else if counted(metadata) {
            tracing::subscriber::Interest::sometimes()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        if muted(metadata) {
            counted(metadata)
        } else {
            self.outer.enabled(metadata)
        }
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        self.outer.new_span(span)
    }

    fn record(&self, span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        self.outer.record(span, values);
    }

    fn record_follows_from(&self, span: &tracing::span::Id, follows: &tracing::span::Id) {
        self.outer.record_follows_from(span, follows);
    }

    fn event(&self, event: &tracing::Event<'_>) {
        if muted(event.metadata()) {
            self.problems.fetch_add(1, Ordering::Relaxed);
        } else {
            self.outer.event(event);
        }
    }

    fn enter(&self, span: &tracing::span::Id) {
        self.outer.enter(span);
    }

    fn exit(&self, span: &tracing::span::Id) {
        self.outer.exit(span);
    }

    fn clone_span(&self, id: &tracing::span::Id) -> tracing::span::Id {
        self.outer.clone_span(id)
    }

    fn try_close(&self, id: tracing::span::Id) -> bool {
        self.outer.try_close(id)
    }
}

/// The dispatcher for the tasks of a node in internet mode (see [`Quiet`]), built
/// around the subscriber that is current now, and the count of what it kept back.
pub(crate) fn quiet() -> (tracing::Dispatch, Arc<AtomicUsize>) {
    let problems = Arc::new(AtomicUsize::new(0));
    let outer = tracing::dispatcher::get_default(Clone::clone);
    let dispatch = tracing::Dispatch::new(Quiet {
        outer,
        problems: problems.clone(),
    });
    (dispatch, problems)
}

/// The name servers of a `resolv.conf`, without those this resolver cannot use (an
/// address with a zone, as in `fe80::1%en0`).
fn nameservers(resolv_conf: &str) -> Vec<IpAddr> {
    resolv_conf
        .lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver"))
        .filter_map(|rest| rest.split_whitespace().next()?.parse().ok())
        .take(4)
        .collect()
}

/// The DNS resolvers of this system.
///
/// The resolver library reads them from the system. On macOS it gives up when one of
/// them is a link-local IPv6 address with a zone, which is what a phone used as a
/// hotspot hands out; the usable ones are then taken from `/etc/resolv.conf`. No
/// resolver from outside the system's configuration is ever used.
fn resolver_config() -> Option<(ResolverConfig, ResolverOpts)> {
    if let Ok(config) = hickory_resolver::system_conf::read_system_conf() {
        return Some(config);
    }
    let servers = nameservers(&std::fs::read_to_string("/etc/resolv.conf").ok()?);
    if servers.is_empty() {
        return None;
    }
    Some((
        ResolverConfig::from_name_servers(
            servers
                .into_iter()
                .map(NameServerConfig::udp_and_tcp)
                .collect(),
        ),
        ResolverOpts::default(),
    ))
}

/// The multiaddr of a `dnsaddr=<multiaddr>` TXT record, if it is one for `peer`.
fn dnsaddr_record(txt: &[u8], peer: &PeerId) -> Option<Multiaddr> {
    let addr: Multiaddr = std::str::from_utf8(txt)
        .ok()?
        .strip_prefix("dnsaddr=")?
        .parse()
        .ok()?;
    (addr.iter().last() == Some(Protocol::P2p(*peer))).then_some(addr)
}

type Resolved = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Resolves one bootstrap address of `peer` to `/ip4|ip6/…/udp/…/quic-v1` addresses,
/// following `/dnsaddr` records up to [`MAX_DNSADDR_DEPTH`] deep.
fn resolve(
    resolver: Arc<TokioResolver>,
    addr: Multiaddr,
    peer: PeerId,
    depth: usize,
    lookups: Arc<AtomicUsize>,
    out: mpsc::Sender<(PeerId, Multiaddr)>,
) -> Resolved {
    Box::pin(async move {
        if let Some((ip, port, _)) = quic_parts(&addr) {
            let _ = out.send((peer, quic_addr(ip, port))).await;
            return;
        }
        let parts: Vec<Protocol<'_>> = addr.iter().collect();
        let look = || lookups.fetch_add(1, Ordering::Relaxed) < MAX_DNS_LOOKUPS;
        match parts.as_slice() {
            [Protocol::Dnsaddr(name), Protocol::P2p(_)] if depth < MAX_DNSADDR_DEPTH => {
                if !look() {
                    return;
                }
                let Ok(answer) = resolver.txt_lookup(format!("_dnsaddr.{name}")).await else {
                    return;
                };
                let next: Vec<Multiaddr> = answer
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::TXT(txt) => dnsaddr_record(txt.txt_data.first()?, &peer),
                        _ => None,
                    })
                    .take(MAX_ADDRS_PER_BOOTSTRAP * 2)
                    .collect();
                for addr in next {
                    resolve(
                        resolver.clone(),
                        addr,
                        peer,
                        depth + 1,
                        lookups.clone(),
                        out.clone(),
                    )
                    .await;
                }
            }
            [name @ (Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_)), Protocol::Udp(port), Protocol::QuicV1, Protocol::P2p(_)] =>
            {
                let (host, v4, v6) = match name {
                    Protocol::Dns4(n) => (n.to_string(), true, false),
                    Protocol::Dns6(n) => (n.to_string(), false, true),
                    Protocol::Dns(n) => (n.to_string(), true, true),
                    _ => return,
                };
                let mut ips: Vec<IpAddr> = Vec::new();
                if v4 && look() {
                    if let Ok(answer) = resolver.ipv4_lookup(host.clone()).await {
                        ips.extend(answer.answers().iter().filter_map(|r| match &r.data {
                            RData::A(a) => Some(IpAddr::V4(Ipv4Addr::from(*a))),
                            _ => None,
                        }));
                    }
                }
                if v6 && look() {
                    if let Ok(answer) = resolver.ipv6_lookup(host).await {
                        ips.extend(answer.answers().iter().filter_map(|r| match &r.data {
                            RData::AAAA(a) => Some(IpAddr::V6(Ipv6Addr::from(*a))),
                            _ => None,
                        }));
                    }
                }
                for ip in ips.into_iter().take(MAX_ADDRS_PER_BOOTSTRAP) {
                    let _ = out.send((peer, quic_addr(ip, *port))).await;
                }
            }
            // Another transport (TCP, WebSocket, …): not for this node.
            _ => {}
        }
    })
}

async fn resolve_all(names: Vec<Multiaddr>, out: mpsc::Sender<(PeerId, Multiaddr)>) {
    let Some((config, opts)) = resolver_config() else {
        return;
    };
    let Ok(resolver) = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
    else {
        return;
    };
    let resolver = Arc::new(resolver);
    let lookups = Arc::new(AtomicUsize::new(0));
    let all = names.into_iter().filter_map(|addr| {
        let Some(Protocol::P2p(peer)) = addr.iter().last() else {
            return None;
        };
        Some(resolve(
            resolver.clone(),
            addr,
            peer,
            0,
            lookups.clone(),
            out.clone(),
        ))
    });
    futures::future::join_all(all).await;
}

/// One resolution of the bootstrap names, on a thread of its own.
///
/// The resolver library spawns tasks that hold its sockets and log what they do
/// (names, name server addresses). Running the whole resolution on a single-threaded
/// runtime that this thread owns keeps both in one place: what it logs is discarded,
/// and when the resolution is over, or the `Resolving` is dropped, the runtime and with
/// it every task and socket of the resolver is gone. The thread exists only while a
/// resolution runs.
struct Resolving {
    results: mpsc::Receiver<(PeerId, Multiaddr)>,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Resolving {
    fn start(names: Vec<Multiaddr>) -> std::io::Result<Self> {
        Self::run(move |out| Box::pin(resolve_all(names, out)))
    }

    /// Runs `work` on the thread, with a deadline, until it ends or `self` is dropped.
    fn run(
        work: impl FnOnce(mpsc::Sender<(PeerId, Multiaddr)>) -> Resolved + Send + 'static,
    ) -> std::io::Result<Self> {
        let (out, results) = mpsc::channel(MAX_RESOLVED_ADDRS);
        let (stop, stopped) = oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("ph-internet-dns".to_owned())
            .spawn(move || {
                // Built and dropped on this thread: a runtime must not be dropped
                // inside another runtime's task.
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                else {
                    return;
                };
                let _quiet = tracing::dispatcher::set_default(&tracing::Dispatch::none());
                runtime.block_on(async move {
                    tokio::select! {
                        // Resolves when the `Resolving` is dropped.
                        _ = stopped => {}
                        _ = tokio::time::timeout(RESOLVE_DEADLINE, work(out)) => {}
                    }
                });
                // Ends the resolver's tasks and closes its sockets, before this thread
                // ends and while its log output is still discarded.
                drop(runtime);
            })?;
        Ok(Self {
            results,
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for Resolving {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            // The thread stops at the signal above (or has finished), so this returns
            // as soon as it has dropped its runtime.
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(n: u8) -> PeerId {
        let mut seed = [0u8; 32];
        seed[0] = n;
        seed[31] = 0x5a;
        crate::identity::keypair_from_seed(&zeroize::Zeroizing::new(seed))
            .unwrap()
            .public()
            .to_peer_id()
    }

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn bounds_are_the_documented_ones() {
        assert_eq!(DEFAULT_RELAYS, 2);
        assert_eq!(MAX_RELAYS, 4);
        assert_eq!(MAX_FOUND_ADDRS, 16);
        assert_eq!(MAX_CONCURRENT_FINDS, 8);
        assert_eq!(OBSERVERS_NEEDED, 3);
        assert_eq!(MAX_ADDRESS_CANDIDATES, 32);
        assert_eq!(AGENT_VERSION, "peerharness");
        assert_eq!(DHT_PROTOCOL.as_ref(), "/ipfs/kad/1.0.0");
        assert!(PUBLIC_BOOTSTRAP.iter().all(|a| is_bootstrap_addr(&addr(a))));
    }

    #[test]
    fn only_public_ip_addresses_count_as_global() {
        for public in ["8.8.8.8", "104.131.131.82", "2a0d:6fc7::1", "2604:2dc0::1"] {
            assert!(is_global_ip(&public.parse().unwrap()), "{public}");
        }
        for not in [
            "10.1.2.3",
            "172.16.0.1",
            "172.20.10.7",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "0.1.2.3",
            "192.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.7",
            "224.0.0.251",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:8.8.8.8",
            "fe80::1",
            "fd00::7",
            "ff02::fb",
            "2001:db8::1",
            "2002:c000:0204::1",
            "2001:0:1::1",
            "64:ff9b::808:808",
        ] {
            assert!(!is_global_ip(&not.parse().unwrap()), "{not}");
        }
    }

    #[test]
    fn found_addresses_are_normalized_and_everything_else_is_dropped() {
        let (target, relay, other) = (peer(1), peer(2), peer(3));
        let direct = addr("/ip4/8.8.4.4/udp/4001/quic-v1");
        let want_direct = direct.clone().with(Protocol::P2p(target));
        assert_eq!(
            found_addr(&target, &direct, false),
            Some(want_direct.clone())
        );
        assert_eq!(found_addr(&target, &want_direct, false), Some(want_direct));
        let circuit = addr(&format!(
            "/ip4/8.8.4.4/udp/4001/quic-v1/p2p/{relay}/p2p-circuit"
        ));
        let want_circuit = circuit.clone().with(Protocol::P2p(target));
        assert_eq!(
            found_addr(&target, &circuit, false),
            Some(want_circuit.clone())
        );
        assert_eq!(
            found_addr(&target, &want_circuit, false),
            Some(want_circuit)
        );
        for bad in [
            // Not this transport, or a relay that is not reached over it.
            "/ip4/8.8.4.4/tcp/4001".to_owned(),
            "/ip4/8.8.4.4/udp/4001/quic".to_owned(),
            "/ip4/8.8.4.4/udp/4001/quic-v1/webtransport".to_owned(),
            "/dns4/example.org/udp/4001/quic-v1".to_owned(),
            format!("/ip4/8.8.4.4/tcp/4001/p2p/{relay}/p2p-circuit"),
            format!("/dns4/example.org/udp/4001/quic-v1/p2p/{relay}/p2p-circuit"),
            // Not a public address.
            "/ip4/192.168.1.7/udp/4001/quic-v1".to_owned(),
            "/ip4/127.0.0.1/udp/4001/quic-v1".to_owned(),
            "/ip6/fe80::1/udp/4001/quic-v1".to_owned(),
            format!("/ip4/10.0.0.1/udp/4001/quic-v1/p2p/{relay}/p2p-circuit"),
            // Another peer, a relay without a name, two relays, the target as its relay.
            format!("/ip4/8.8.4.4/udp/4001/quic-v1/p2p/{other}"),
            format!("/ip4/8.8.4.4/udp/4001/quic-v1/p2p/{relay}/p2p-circuit/p2p/{other}"),
            "/ip4/8.8.4.4/udp/4001/quic-v1/p2p-circuit".to_owned(),
            format!("/ip4/8.8.4.4/udp/4001/quic-v1/p2p/{relay}/p2p-circuit/p2p/{other}/p2p-circuit/p2p/{target}"),
            format!("/ip4/8.8.4.4/udp/4001/quic-v1/p2p/{target}/p2p-circuit"),
            "/ip4/8.8.4.4/udp/0/quic-v1".to_owned(),
            format!("/p2p/{target}"),
        ] {
            assert_eq!(found_addr(&target, &addr(&bad), false), None, "{bad}");
        }
        // A closed network may use private addresses.
        let local = addr("/ip4/127.0.0.1/udp/4001/quic-v1");
        assert_eq!(
            found_addr(&target, &local, true),
            Some(local.with(Protocol::P2p(target)))
        );
        assert_eq!(
            found_addr(&target, &addr("/ip4/0.0.0.0/udp/4001/quic-v1"), true),
            None
        );
    }

    #[test]
    fn bootstrap_addresses_need_a_peer_id_and_a_form_this_node_can_use() {
        let p = peer(1);
        for good in [
            format!("/ip4/104.131.131.82/udp/4001/quic-v1/p2p/{p}"),
            format!("/ip6/2604:2dc0::1/udp/4001/quic-v1/p2p/{p}"),
            format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{p}"),
            format!("/dns4/example.org/udp/4001/quic-v1/p2p/{p}"),
            format!("/dns6/example.org/udp/4001/quic-v1/p2p/{p}"),
            format!("/dns/example.org/udp/4001/quic-v1/p2p/{p}"),
            format!("/dnsaddr/example.org/p2p/{p}"),
        ] {
            assert!(is_bootstrap_addr(&addr(&good)), "{good}");
        }
        for bad in [
            "/ip4/104.131.131.82/udp/4001/quic-v1".to_owned(),
            "/dnsaddr/example.org".to_owned(),
            format!("/ip4/104.131.131.82/tcp/4001/p2p/{p}"),
            format!("/ip4/0.0.0.0/udp/4001/quic-v1/p2p/{p}"),
            format!("/dns4/example.org/tcp/4001/p2p/{p}"),
            format!("/dns4/example.org/udp/0/quic-v1/p2p/{p}"),
            format!("/dnsaddr/example.org/udp/4001/quic-v1/p2p/{p}"),
            format!("/p2p/{p}"),
        ] {
            assert!(!is_bootstrap_addr(&addr(&bad)), "{bad}");
        }
    }

    #[test]
    fn a_lookup_keeps_the_newest_addresses_and_answers_newest_first() {
        let target = peer(1);
        let (reply, mut answer) = oneshot::channel();
        let now = Instant::now();
        let mut find = Find {
            target,
            found: Vec::new(),
            reply: Some(reply),
            deadline: now + Duration::from_secs(10),
            settle: None,
        };
        let a = |n: u16| addr(&format!("/ip4/8.8.4.4/udp/{n}/quic-v1/p2p/{target}"));
        for n in 1..=MAX_FOUND_ADDRS as u16 + 4 {
            find.record(a(n), now);
        }
        assert_eq!(find.found.len(), MAX_FOUND_ADDRS);
        assert_eq!(find.settle, Some(now + FIND_SETTLE));
        // Named again: it is the newest now, and still listed once.
        find.record(a(7), now);
        assert_eq!(find.found.len(), MAX_FOUND_ADDRS);
        find.finish();
        let got = answer.try_recv().unwrap().unwrap();
        assert_eq!(got.len(), MAX_FOUND_ADDRS);
        assert_eq!(got[0], a(7));
        assert_eq!(got[1], a(MAX_FOUND_ADDRS as u16 + 4));
        // The four oldest were dropped.
        assert!(!got.contains(&a(1)) && !got.contains(&a(4)) && got.contains(&a(5)));
    }

    #[test]
    fn an_observed_address_is_tested_only_when_enough_peers_agree() {
        let mut o = Observed::default();
        let home = addr("/ip4/8.8.4.4/udp/4001/quic-v1");
        assert_eq!(o.report(peer(1), home.clone(), OBSERVERS_NEEDED), None);
        // The same peer again does not count twice.
        assert_eq!(o.report(peer(1), home.clone(), OBSERVERS_NEEDED), None);
        assert_eq!(o.report(peer(2), home.clone(), OBSERVERS_NEEDED), None);
        assert_eq!(
            o.report(peer(3), home.clone(), OBSERVERS_NEEDED),
            Some(home.clone())
        );
        // Handed on once.
        assert_eq!(o.report(peer(4), home.clone(), OBSERVERS_NEEDED), None);
        assert_eq!(o.offered, 1);
        // A closed network takes one peer's word.
        let mut o = Observed::default();
        assert_eq!(o.report(peer(1), home.clone(), 1), Some(home));
    }

    #[test]
    fn observed_addresses_and_candidates_are_bounded() {
        // A NAT that shows every peer another port: nothing is ever tested, and the
        // list does not grow.
        let mut o = Observed::default();
        for n in 0..200u16 {
            let a = addr(&format!("/ip4/8.8.4.4/udp/{}/quic-v1", 10_000 + n));
            assert_eq!(o.report(peer((n % 250) as u8), a, OBSERVERS_NEEDED), None);
        }
        assert_eq!(o.seen.len(), MAX_OBSERVED_ADDRS);
        assert!(o.observers.len() <= MAX_OBSERVERS);
        assert_eq!(o.offered, 0);
        // Peers that agree on ever new addresses: no more than the lifetime bound is
        // handed on, however many they name.
        let mut o = Observed::default();
        let mut handed_on = 0;
        for n in 0..(MAX_ADDRESS_CANDIDATES as u16 + 20) {
            let a = addr(&format!("/ip4/8.8.4.4/udp/{}/quic-v1", 20_000 + n));
            if o.report(peer(1), a, 1).is_some() {
                handed_on += 1;
            }
        }
        assert_eq!(handed_on, MAX_ADDRESS_CANDIDATES);
        assert_eq!(o.seen.len(), MAX_OBSERVED_ADDRS);
    }

    #[test]
    fn name_servers_with_a_zone_are_skipped() {
        let conf = "#\n# macOS Notice\n#\nnameserver fe80::d42f:caff:fe47:2d64%en0\nnameserver 172.20.10.1\n  nameserver   2001:4860:4860::8888  \nsearch lan\noptions edns0\n";
        assert_eq!(
            nameservers(conf),
            vec![
                "172.20.10.1".parse::<IpAddr>().unwrap(),
                "2001:4860:4860::8888".parse().unwrap()
            ]
        );
        assert!(nameservers("search lan\n").is_empty());
    }

    #[test]
    fn dnsaddr_records_must_name_the_peer_they_were_asked_for() {
        let (p, other) = (peer(1), peer(2));
        let record = format!("dnsaddr=/ip4/104.131.131.82/udp/4001/quic-v1/p2p/{p}");
        assert_eq!(
            dnsaddr_record(record.as_bytes(), &p),
            Some(addr(&format!(
                "/ip4/104.131.131.82/udp/4001/quic-v1/p2p/{p}"
            )))
        );
        assert_eq!(dnsaddr_record(record.as_bytes(), &other), None);
        assert_eq!(
            dnsaddr_record(b"dnsaddr=/ip4/104.131.131.82/udp/4001/quic-v1", &p),
            None
        );
        assert_eq!(dnsaddr_record(b"v=spf1 -all", &p), None);
        assert_eq!(dnsaddr_record(&[0xff, 0xfe], &p), None);
    }

    #[test]
    fn off_has_no_behaviour_and_never_produces_an_event() {
        let mut i = Internet::off(peer(1));
        assert!(!i.is_on());
        assert_eq!(i.status(), InternetStatus::off());
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(i.poll(&mut cx).is_pending());
        assert!(i.tick.is_none() && i.resolving.is_none());
        // It adds nothing to a dial and refuses none.
        assert_eq!(
            i.handle_pending_outbound_connection(
                ConnectionId::new_unchecked(1),
                Some(peer(2)),
                &[],
                Endpoint::Dialer,
            )
            .unwrap(),
            Vec::<Multiaddr>::new()
        );
        let (reply, mut answer) = oneshot::channel();
        i.find(peer(2), Duration::from_secs(1), reply);
        assert_eq!(answer.try_recv().unwrap(), Err(NetError::InternetOff));
        assert!(i.finds.is_empty() && i.waiting.is_empty() && i.named.is_empty());
    }

    /// A node in internet mode that is connected to nobody.
    fn on(allow_private: bool) -> Internet {
        let keypair =
            crate::identity::keypair_from_seed(&zeroize::Zeroizing::new([7u8; 32])).unwrap();
        let (_transport, relay) = relay::client::new(keypair.public().to_peer_id());
        let config = InternetConfig {
            bootstrap: vec![addr(&format!(
                "/ip4/104.131.131.82/udp/4001/quic-v1/p2p/{}",
                peer(200)
            ))],
            max_relays: 2,
            allow_private_addresses: allow_private,
        };
        Internet::on(&keypair, relay, &config, 16, Arc::new(AtomicUsize::new(0)))
    }

    #[test]
    fn the_gate_refuses_named_peers_bad_addresses_and_dials_over_budget() {
        let mut i = on(false);
        assert!(i.is_on());
        let (stranger, named) = (peer(1), peer(2));
        let good = addr("/ip4/8.8.4.4/udp/4001/quic-v1");
        let lan = addr("/ip4/192.168.1.7/udp/4001/quic-v1");
        let tcp = addr("/ip4/8.8.4.4/tcp/4001");
        let via = addr(&format!(
            "/ip4/8.8.4.4/udp/4001/quic-v1/p2p/{}/p2p-circuit",
            peer(9)
        ));

        // A DHT server: dialed, at public QUIC addresses only.
        let offered = vec![
            lan.clone(),
            good.clone(),
            tcp.clone(),
            via.clone(),
            good.clone(),
        ];
        assert_eq!(
            i.admit(stranger, &[], offered.clone()),
            Ok(vec![good.clone()])
        );
        // Addresses that come with a dial must all be dialable.
        assert_eq!(
            i.admit(stranger, std::slice::from_ref(&good), vec![]),
            Ok(vec![])
        );
        for bad in [&lan, &tcp, &via] {
            assert_eq!(
                i.admit(stranger, &[good.clone(), bad.clone()], vec![]),
                Err(Refused::Address),
                "{bad}"
            );
        }
        // No more addresses than the bound.
        let many: Vec<Multiaddr> = (1..=40u16)
            .map(|n| addr(&format!("/ip4/8.8.4.4/udp/{n}/quic-v1")))
            .collect();
        assert_eq!(i.admit(stranger, &[], many).unwrap().len(), MAX_DIAL_ADDRS);

        // A peer the application named is not dialed by the node …
        i.name(named);
        assert_eq!(i.admit(named, &[], offered.clone()), Err(Refused::Named));
        assert_eq!(
            i.admit(named, std::slice::from_ref(&good), vec![]),
            Err(Refused::Named)
        );
        // … unless a connection with it exists (the hole punch).
        i.connected.insert(named, 1);
        assert_eq!(
            i.admit(named, std::slice::from_ref(&good), vec![]),
            Ok(vec![])
        );
        assert_eq!(
            i.admit(named, std::slice::from_ref(&lan), vec![]),
            Err(Refused::Address)
        );
        i.connected.clear();

        // The relay of an explicit relayed dial, at exactly the address given.
        let relay = peer(9);
        i.expect_relay_dial(relay, lan.clone());
        assert_eq!(
            i.admit(relay, std::slice::from_ref(&lan), vec![]),
            Ok(vec![])
        );
        assert_eq!(
            i.admit(relay, std::slice::from_ref(&tcp), vec![]),
            Err(Refused::Address)
        );

        // Over the budget (half of 16 connections) the node opens no more.
        for n in 0..8usize {
            i.links.insert(
                ConnectionId::new_unchecked(100 + n),
                Link {
                    peer: peer(50),
                    dialed: None,
                    relayed: false,
                    own: true,
                    closing: false,
                    since: Instant::now(),
                },
            );
        }
        assert_eq!(
            i.admit(stranger, &[], offered.clone()),
            Err(Refused::Budget)
        );
        // After stop it dials nothing.
        i.links.clear();
        i.stop();
        assert_eq!(i.admit(stranger, &[], offered), Err(Refused::Stopped));
    }

    #[test]
    fn connections_the_node_opened_itself_are_trimmed_and_no_others() {
        let mut i = on(false);
        // 16 connections allowed, so the node may open 8 on its own and keeps 4.
        let old = Instant::now() - 2 * OWN_CONNECTION_MIN_AGE;
        let direct = |a: &str, p: PeerId| ConnectedPoint::Dialer {
            address: addr(&format!("{a}/p2p/{p}")),
            role_override: Endpoint::Dialer,
            port_use: PortUse::Reuse,
        };
        let server = "/ip4/8.8.4.4/udp/4001/quic-v1";
        for n in 0..7usize {
            let p = peer(100 + n as u8);
            i.on_established(ConnectionId::new_unchecked(n), p, &direct(server, p));
        }
        assert!(i.links.values().all(|l| l.own));
        // A peer the application dialed, one that connected to this node, and one the
        // node dialed for a hole punch while it was connected through a relay.
        let app = peer(1);
        i.dial_asked(
            ConnectionId::new_unchecked(50),
            &addr(&format!("{server}/p2p/{app}")),
        );
        i.dial_made(ConnectionId::new_unchecked(50), true);
        i.on_established(ConnectionId::new_unchecked(50), app, &direct(server, app));
        let inbound = peer(2);
        i.on_established(
            ConnectionId::new_unchecked(51),
            inbound,
            &ConnectedPoint::Listener {
                local_addr: addr("/ip4/192.168.1.2/udp/4001/quic-v1"),
                send_back_addr: addr(server),
            },
        );
        let punched = peer(3);
        i.on_established(
            ConnectionId::new_unchecked(52),
            punched,
            &ConnectedPoint::Listener {
                local_addr: addr(&format!("{server}/p2p/{}/p2p-circuit", peer(9))),
                send_back_addr: addr(&format!("/p2p/{punched}")),
            },
        );
        i.on_established(
            ConnectionId::new_unchecked(53),
            punched,
            &direct(server, punched),
        );
        for id in [50, 51, 52, 53] {
            assert!(!i.links[&ConnectionId::new_unchecked(id)].own, "{id}");
        }
        // Young connections are left alone.
        i.trim(Instant::now());
        assert!(i.pending.is_empty());
        // Old ones go, down to half of the budget; the others stay whatever their age.
        for link in i.links.values_mut() {
            link.since = old;
        }
        i.trim(Instant::now());
        let closed: Vec<ConnectionId> = i
            .pending
            .drain(..)
            .filter_map(|e| match e {
                ToSwarm::CloseConnection {
                    connection: CloseConnection::One(id),
                    ..
                } => Some(id),
                _ => None,
            })
            .collect();
        assert_eq!(closed.len(), 3);
        assert!(closed
            .iter()
            .all(|id| (0..7).any(|n| *id == ConnectionId::new_unchecked(n))));
        // Nothing more on the next tick.
        i.trim(Instant::now());
        assert!(i.pending.is_empty());
    }

    #[test]
    fn the_set_of_named_peers_and_the_lookups_are_bounded() {
        let mut i = on(false);
        for n in 0..(MAX_NAMED_PEERS + 10) {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(n as u64).to_be_bytes());
            seed[31] = 0x5a;
            let p = crate::identity::keypair_from_seed(&zeroize::Zeroizing::new(seed))
                .unwrap()
                .public()
                .to_peer_id();
            i.name(p);
        }
        assert_eq!(i.named.len(), MAX_NAMED_PEERS);
        assert_eq!(i.named_set.len(), MAX_NAMED_PEERS);

        let mut answers = Vec::new();
        for n in 0..MAX_CONCURRENT_FINDS as u8 {
            let (reply, answer) = oneshot::channel();
            i.find(peer(10 + n), Duration::from_secs(5), reply);
            answers.push(answer);
        }
        assert_eq!(i.finds.len(), MAX_CONCURRENT_FINDS);
        let (reply, mut answer) = oneshot::channel();
        i.find(peer(99), Duration::from_secs(5), reply);
        assert_eq!(answer.try_recv().unwrap(), Err(NetError::Busy));
        // The own id is not looked up.
        let (reply, mut answer) = oneshot::channel();
        let me = i.local_peer_id;
        i.find(me, Duration::from_secs(5), reply);
        assert_eq!(answer.try_recv().unwrap(), Ok(vec![]));
        // Stopping answers every lookup.
        i.stop();
        for mut answer in answers {
            assert_eq!(answer.try_recv().unwrap(), Err(NetError::Shutdown));
        }
        let (reply, mut answer) = oneshot::channel();
        i.find(peer(98), Duration::from_secs(5), reply);
        assert_eq!(answer.try_recv().unwrap(), Err(NetError::Shutdown));
    }

    #[test]
    fn libp2p_log_output_is_counted_not_written_and_the_rest_passes() {
        use std::sync::Mutex;

        /// Keeps the target of every event it is given.
        struct Keep(Arc<Mutex<Vec<String>>>);
        impl tracing::Subscriber for Keep {
            fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                self.0
                    .lock()
                    .unwrap()
                    .push(event.metadata().target().to_owned());
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }

        let kept = Arc::new(Mutex::new(Vec::new()));
        let outer = tracing::Dispatch::new(Keep(kept.clone()));
        let (dispatch, problems) = tracing::dispatcher::with_default(&outer, quiet);
        tracing::dispatcher::with_default(&dispatch, || {
            tracing::info!(target: "libp2p_identify", address = "192.0.2.7", "observed address changed");
            tracing::debug!(target: "libp2p_kad::behaviour", address = "192.0.2.7", "address removed");
            tracing::debug!(target: "libp2p_swarm", address = "192.0.2.7", "new listener address");
            tracing::debug!(target: "hickory_net::udp", "querying 192.0.2.53");
            assert!(tracing::info_span!(target: "libp2p_swarm", "poll").is_disabled());
            assert_eq!(problems.load(Ordering::Relaxed), 0);
            tracing::warn!(target: "libp2p_quic::transport", socket_address = "192.0.2.7", "unexpected peer");
            tracing::error!(target: "libp2p_relay", "failed");
            assert_eq!(problems.load(Ordering::Relaxed), 2);
            tracing::info!(target: "ph_network::internet", relays = 2, "relay reservation held");
            tracing::debug!(target: "quinn_proto", "connection closed");
        });
        assert_eq!(
            *kept.lock().unwrap(),
            vec!["ph_network::internet".to_owned(), "quinn_proto".to_owned()]
        );
    }

    #[test]
    fn the_dns_thread_ends_what_runs_on_it_when_dropped() {
        use std::sync::atomic::AtomicBool;

        /// Stands for the resolver's sockets: says when it was dropped.
        struct Held(Arc<AtomicBool>);
        impl Drop for Held {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let released = Arc::new(AtomicBool::new(false));
        let held = Held(released.clone());
        let (running, is_running) = std::sync::mpsc::channel();
        let p = peer(1);
        let resolving = Resolving::run(move |out| {
            Box::pin(async move {
                // As the resolver does: a task that never ends by itself.
                tokio::spawn(async move {
                    let _held = held;
                    let _ = running.send(std::thread::current().name().map(str::to_owned));
                    std::future::pending::<()>().await;
                });
                let _ = out.send((p, addr("/ip4/8.8.4.4/udp/4001/quic-v1"))).await;
                std::future::pending::<()>().await;
            })
        })
        .unwrap();
        let thread = is_running
            .recv_timeout(Duration::from_secs(20))
            .expect("the task runs");
        assert_eq!(thread.as_deref(), Some("ph-internet-dns"));
        assert!(!released.load(Ordering::SeqCst));
        drop(resolving);
        // Not "soon": the task and what it held are gone when `drop` returns.
        assert!(released.load(Ordering::SeqCst));
    }
}
