//! Opt-in discovery of libp2p nodes on the local network (mDNS).
//!
//! Off unless [`NetworkConfig::lan_discovery`](crate::NetworkConfig::lan_discovery) is
//! set. When off, nothing of this module runs: no mDNS behaviour is built, no interface
//! watcher, no multicast socket and no thread exist, and nothing is announced.
//!
//! When on, the node runs libp2p's mDNS (`libp2p-mdns`, service name `_p2p._udp.local`,
//! IPv4 only) on every non-loopback IPv4 interface. On each of them it
//!
//! * **asks**: it sends a query for `_p2p._udp.local` to `224.0.0.251:5353` when it
//!   starts, again after 1 s, 2 s, 4 s and so on until another node has answered or the
//!   pause has grown to [`QUERY_INTERVAL`], and from then on every [`QUERY_INTERVAL`].
//!   A query names the service and nothing else;
//! * **answers** every such query it hears, from anyone, to the whole multicast group:
//!   one record per listen address *on that interface*, each reading
//!   `dnsaddr=<listen address>/p2p/<peer id>`, valid for [`RECORD_TTL`]. A node with no
//!   listen address on the interface (a node that only dials, or one that listens on
//!   loopback only) answers with an empty record: no peer id and no address. It also
//!   answers the question a service browser asks (`_services._dns-sd._udp.local`) with
//!   the service name, so its host is visibly one that runs a libp2p node.
//!
//! The peer id is the device key, so an answer says "the device with this public key
//! listens at this address and port" to every host on the network segment. It says
//! nothing about circles, and this crate still knows nothing about them. mDNS is not
//! authenticated: any host on the segment can announce any peer id at any address. A
//! discovered address is therefore a hint and nothing more. What this module guarantees:
//!
//! * **Nothing is dialed.** A discovered address never enters the swarm's address book
//!   and no behaviour is told about it. It reaches the application as a
//!   [`NetEvent::PeerDiscovered`](crate::NetEvent::PeerDiscovered) and through
//!   [`NetworkHandle::discovered`](crate::NetworkHandle::discovered), and is used only if
//!   the application passes it to [`NetworkHandle::dial`](crate::NetworkHandle::dial).
//!   Every reported address ends in `/p2p/<peer id>`, so such a dial succeeds only if the
//!   other end proves that key.
//! * **Only what the transport can dial is reported**: `/ip4|ip6/…/udp/…/quic-v1`
//!   addresses of peer ids that are device keys.
//! * **The list is bounded**: [`MAX_DISCOVERED_PEERS`] peers with
//!   [`MAX_ADDRS_PER_PEER`] addresses each. What does not fit is dropped and counted.
//!   libp2p-mdns reports a record once and then only refreshes it, so a dropped record
//!   is not offered again until it has expired there and is announced anew. libp2p-mdns
//!   also keeps its own record table, which has no bound, so discovery turns itself off
//!   (until the network is started again) when that table passes [`MAX_MDNS_RECORDS`].
//! * **Logs carry ids and counts.** libp2p-mdns logs interface and peer addresses; its
//!   log output is discarded and only its errors are counted.
//! * **Stopping stops it.** libp2p-mdns never ends the tasks that hold its sockets, so
//!   they run on a runtime of their own that ends with the network: after
//!   [`NetworkHandle::shutdown`](crate::NetworkHandle::shutdown) the multicast sockets
//!   are closed and nothing answers.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::mdns;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{
    dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use tokio::sync::oneshot;
use tracing::level_filters::LevelFilter;

use crate::identity::device_key_from_peer_id;

/// The most peers kept in the list of discovered peers.
pub const MAX_DISCOVERED_PEERS: usize = 256;

/// The most addresses kept for one discovered peer.
pub const MAX_ADDRS_PER_PEER: usize = 8;

/// Discovery turns itself off, until the network is started again, when libp2p-mdns
/// holds more records than this. Its table has no bound of its own and a record lives
/// for as long as its sender says, so this is what bounds the memory a host on the
/// local network can make this node spend on discovery. An honest network does not come
/// close: this is eight times a full list.
pub const MAX_MDNS_RECORDS: usize = 8 * MAX_DISCOVERED_PEERS * MAX_ADDRS_PER_PEER;

/// How long other nodes keep an announcement of this node without hearing it again
/// (libp2p-mdns's default). mDNS in libp2p has no goodbye message, so this is also how
/// long a node that has left stays in the lists of the others.
pub const RECORD_TTL: Duration = Duration::from_secs(6 * 60);

/// The pause between two queries once a node has heard an answer (libp2p-mdns's
/// default). It has to stay below [`RECORD_TTL`], or records would expire between two
/// rounds. Every node on the network answers every query, so one node asking refreshes
/// everybody's list.
pub const QUERY_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// The shortest time between two warnings about dropped records or mDNS problems.
pub const WARN_INTERVAL: Duration = Duration::from_secs(60);

/// How many things libp2p-mdns may hand over in one poll of the behaviour before the
/// rest of the swarm gets its turn.
const POLL_BUDGET: usize = 256;

/// What the discovery behaviour reports to the event loop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DiscoveryEvent {
    /// Addresses of `peer_id` that were not in the list before.
    Discovered {
        peer_id: PeerId,
        addrs: Vec<Multiaddr>,
    },
    /// Addresses of `peer_id` that left the list because their records expired.
    Expired {
        peer_id: PeerId,
        addrs: Vec<Multiaddr>,
    },
}

/// `addr` in the one form this transport dials,
/// `/ip4|ip6/<address>/udp/<port>/quic-v1/p2p/<peer>`, or `None` if it is anything else:
/// another transport, more components after `quic-v1`, port 0, an unspecified, multicast
/// or broadcast address, or a `/p2p` component naming another peer.
pub(crate) fn dialable(peer: &PeerId, addr: &Multiaddr) -> Option<Multiaddr> {
    let mut parts = addr.iter();
    let ip = match parts.next()? {
        Protocol::Ip4(a) if !(a.is_unspecified() || a.is_multicast() || a.is_broadcast()) => {
            Protocol::Ip4(a)
        }
        Protocol::Ip6(a) if !(a.is_unspecified() || a.is_multicast()) => Protocol::Ip6(a),
        _ => return None,
    };
    let port = match parts.next()? {
        Protocol::Udp(port) if port != 0 => port,
        _ => return None,
    };
    if !matches!(parts.next()?, Protocol::QuicV1) {
        return None;
    }
    match parts.next() {
        None => {}
        Some(Protocol::P2p(named)) if named == *peer && parts.next().is_none() => {}
        Some(_) => return None,
    }
    Some(
        Multiaddr::empty()
            .with(ip)
            .with(Protocol::Udp(port))
            .with(Protocol::QuicV1)
            .with(Protocol::P2p(*peer)),
    )
}

/// The outcome of offering one address to the [`Table`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admit {
    /// Stored: it was not known before.
    Added,
    /// Already stored.
    Known,
    /// Dropped: the list holds [`MAX_DISCOVERED_PEERS`] other peers.
    PeerLimit,
    /// Dropped: the peer already has [`MAX_ADDRS_PER_PEER`] addresses.
    AddrLimit,
}

/// The bounded list of discovered peers. What does not fit is dropped, never swapped
/// for an older entry.
#[derive(Debug, Default)]
struct Table {
    peers: BTreeMap<PeerId, Vec<Multiaddr>>,
}

impl Table {
    fn admit(&mut self, peer: PeerId, addr: Multiaddr) -> Admit {
        if let Some(addrs) = self.peers.get_mut(&peer) {
            if addrs.contains(&addr) {
                return Admit::Known;
            }
            if addrs.len() >= MAX_ADDRS_PER_PEER {
                return Admit::AddrLimit;
            }
            addrs.push(addr);
            return Admit::Added;
        }
        if self.peers.len() >= MAX_DISCOVERED_PEERS {
            return Admit::PeerLimit;
        }
        self.peers.insert(peer, vec![addr]);
        Admit::Added
    }

    /// Removes one address. Returns whether it was stored. A peer left without
    /// addresses leaves the list and frees its place.
    fn remove(&mut self, peer: &PeerId, addr: &Multiaddr) -> bool {
        let Some(addrs) = self.peers.get_mut(peer) else {
            return false;
        };
        let before = addrs.len();
        addrs.retain(|a| a != addr);
        let removed = addrs.len() != before;
        if addrs.is_empty() {
            self.peers.remove(peer);
        }
        removed
    }

    /// Every peer with its addresses, ordered by peer id.
    fn snapshot(&self) -> Vec<(PeerId, Vec<Multiaddr>)> {
        self.peers.iter().map(|(p, a)| (*p, a.clone())).collect()
    }
}

/// The subscriber that is current while libp2p-mdns code runs.
///
/// libp2p-mdns logs the addresses of the local interfaces and of every discovered peer
/// at INFO, and text taken from received packets at DEBUG. PeerHarness logs ids and
/// counts only, so none of it may reach the application's log. This subscriber drops
/// every span and event and counts the errors (a socket that could not be opened, a
/// send or receive that failed), which the behaviour then reports as a number. Warnings
/// are not counted: the DNS parser warns about odd packets of other devices.
struct CountProblems(Arc<AtomicUsize>);

impl tracing::Subscriber for CountProblems {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.is_event() && *metadata.level() == tracing::Level::ERROR
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::ERROR)
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        // Never called: `enabled` refuses every span.
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, _: &tracing::Event<'_>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// A thread with a single-threaded Tokio runtime that owns what libp2p-mdns spawns:
/// one task per interface, with its two UDP sockets and its timers.
///
/// libp2p-mdns 0.49 starts those tasks with `tokio::spawn` and never ends them. Dropping
/// its behaviour leaves them running on whatever runtime they were spawned on, holding
/// the multicast sockets and answering queries with the peer id and the last known
/// listen addresses. Running them on a runtime of their own lets dropping the `Host` end
/// exactly that runtime, and with it the sockets, so that a stopped network is silent.
struct Host {
    runtime: tokio::runtime::Handle,
    quiet: tracing::Dispatch,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Host {
    fn start(problems: Arc<AtomicUsize>) -> io::Result<Self> {
        let quiet = tracing::Dispatch::new(CountProblems(problems));
        let (stop, stopped) = oneshot::channel::<()>();
        let (ready, started) = std::sync::mpsc::channel();
        let thread_quiet = quiet.clone();
        let thread = std::thread::Builder::new()
            .name("ph-lan-discovery".to_owned())
            .spawn(move || {
                // The runtime is built and dropped on this thread: a runtime must not
                // be dropped inside another runtime's task.
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(e) => {
                        let _ = ready.send(Err(e));
                        return;
                    }
                };
                let _ = ready.send(Ok(runtime.handle().clone()));
                let _quiet = tracing::dispatcher::set_default(&thread_quiet);
                runtime.block_on(async {
                    // Resolves when the `Host` is dropped.
                    let _ = stopped.await;
                });
                // Drops the interface tasks and closes their sockets, before this
                // thread ends and while its log output is still discarded.
                drop(runtime);
            })?;
        let runtime = match started.recv() {
            Ok(Ok(runtime)) => runtime,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(io::Error::other("discovery thread ended early")),
        };
        Ok(Self {
            runtime,
            quiet,
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            // The thread only waits for the signal above, so this returns as soon as
            // it has dropped its runtime: the sockets are closed when `drop` returns.
            let _ = thread.join();
        }
    }
}

/// The running mDNS behaviour and the runtime its tasks live on.
struct Lan {
    // Declared first, so it is dropped before the runtime it spawned onto.
    mdns: mdns::tokio::Behaviour,
    host: Host,
}

impl Lan {
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<mdns::Event, THandlerInEvent<mdns::tokio::Behaviour>>> {
        // Whatever libp2p-mdns spawns or registers while it is polled (interface tasks,
        // sockets, timers) lands on the host runtime, and whatever it logs is counted
        // instead of written.
        let _runtime = self.host.runtime.enter();
        let mdns = &mut self.mdns;
        tracing::dispatcher::with_default(&self.host.quiet, || mdns.poll(cx))
    }
}

/// Addresses dropped since the last warning.
#[derive(Debug, Default)]
struct Unreported {
    /// Addresses dropped because the list of peers was full.
    peer_limit: u64,
    /// Addresses dropped because their peer had [`MAX_ADDRS_PER_PEER`] already.
    addr_limit: u64,
}

/// The discovery behaviour: libp2p-mdns behind a filter, when it is on.
///
/// It is a `NetworkBehaviour` of its own instead of a `Toggle` around libp2p-mdns
/// because of what it keeps away from the swarm. libp2p-mdns emits
/// `NewExternalAddrOfPeer` for every address it hears and offers its addresses to every
/// dial of a known peer id; both would put unauthenticated addresses where a later dial
/// by peer id could pick them up. This behaviour emits neither and offers no addresses.
pub(crate) struct Discovery {
    lan: Option<Lan>,
    local_peer_id: PeerId,
    table: Table,
    pending: VecDeque<DiscoveryEvent>,
    problems: Arc<AtomicUsize>,
    unreported: Unreported,
    last_warning: Option<Instant>,
}

impl Discovery {
    /// Discovery off: no mDNS behaviour, no socket, no thread. Never produces an event.
    pub(crate) fn off(local_peer_id: PeerId) -> Self {
        Self {
            lan: None,
            local_peer_id,
            table: Table::default(),
            pending: VecDeque::new(),
            problems: Arc::new(AtomicUsize::new(0)),
            unreported: Unreported::default(),
            last_warning: None,
        }
    }

    /// Discovery on. Must be called inside a Tokio runtime (the interface watcher
    /// registers with it on Linux). The multicast sockets are opened when the swarm is
    /// first polled, one pair per non-loopback IPv4 interface.
    pub(crate) fn lan(local_peer_id: PeerId) -> io::Result<Self> {
        let mut discovery = Self::off(local_peer_id);
        let host = Host::start(discovery.problems.clone())?;
        let config = mdns::Config {
            ttl: RECORD_TTL,
            query_interval: QUERY_INTERVAL,
            // libp2p-mdns does IPv4 or IPv6, not both, and its IPv6 side joins the
            // group on the default interface only.
            enable_ipv6: false,
        };
        let mdns = mdns::tokio::Behaviour::new(config, local_peer_id)?;
        discovery.lan = Some(Lan { mdns, host });
        Ok(discovery)
    }

    /// Whether mDNS is running.
    pub(crate) fn is_on(&self) -> bool {
        self.lan.is_some()
    }

    /// Every discovered peer with its addresses, ordered by peer id.
    pub(crate) fn snapshot(&self) -> Vec<(PeerId, Vec<Multiaddr>)> {
        self.table.snapshot()
    }

    /// Stops mDNS: ends the interface tasks and closes their sockets before returning.
    /// The list is kept; nothing is reported any more.
    pub(crate) fn stop(&mut self) {
        self.lan = None;
    }

    /// Takes one event of libp2p-mdns into the list and queues what changed.
    fn on_mdns_event(&mut self, event: mdns::Event) {
        match event {
            mdns::Event::Discovered(records) => self.on_discovered(records),
            mdns::Event::Expired(records) => self.on_expired(records),
        }
    }

    fn on_discovered(&mut self, records: Vec<(PeerId, Multiaddr)>) {
        let mut ignored = 0u64;
        // In order of first appearance, so that events are deterministic.
        let mut news: Vec<(PeerId, Vec<Multiaddr>)> = Vec::new();
        for (peer, addr) in records {
            if peer == self.local_peer_id || device_key_from_peer_id(&peer).is_none() {
                ignored += 1;
                continue;
            }
            let Some(addr) = dialable(&peer, &addr) else {
                ignored += 1;
                continue;
            };
            match self.table.admit(peer, addr.clone()) {
                Admit::Added => match news.iter_mut().find(|(p, _)| *p == peer) {
                    Some((_, addrs)) => addrs.push(addr),
                    None => news.push((peer, vec![addr])),
                },
                Admit::Known => {}
                Admit::PeerLimit => {
                    self.unreported.peer_limit = self.unreported.peer_limit.saturating_add(1);
                }
                Admit::AddrLimit => {
                    self.unreported.addr_limit = self.unreported.addr_limit.saturating_add(1);
                }
            }
        }
        if ignored > 0 {
            tracing::debug!(
                count = ignored,
                "LAN discovery: announcements this transport cannot dial were ignored"
            );
        }
        for (peer_id, addrs) in news {
            tracing::debug!(peer = %peer_id, addresses = addrs.len(), "peer discovered on the local network");
            self.pending
                .push_back(DiscoveryEvent::Discovered { peer_id, addrs });
        }
    }

    fn on_expired(&mut self, records: Vec<(PeerId, Multiaddr)>) {
        let mut gone: Vec<(PeerId, Vec<Multiaddr>)> = Vec::new();
        for (peer, addr) in records {
            // Records that were never stored (ignored or dropped) expire unnoticed.
            let Some(addr) = dialable(&peer, &addr) else {
                continue;
            };
            if self.table.remove(&peer, &addr) {
                match gone.iter_mut().find(|(p, _)| *p == peer) {
                    Some((_, addrs)) => addrs.push(addr),
                    None => gone.push((peer, vec![addr])),
                }
            }
        }
        for (peer_id, addrs) in gone {
            tracing::debug!(peer = %peer_id, addresses = addrs.len(), "discovered peer's records expired");
            self.pending
                .push_back(DiscoveryEvent::Expired { peer_id, addrs });
        }
    }

    /// Turns discovery off for good and reports every listed peer as expired.
    fn give_up(&mut self, records: usize) {
        self.stop();
        let table = std::mem::take(&mut self.table);
        let peers = table.peers.len();
        for (peer_id, addrs) in table.peers {
            self.pending
                .push_back(DiscoveryEvent::Expired { peer_id, addrs });
        }
        tracing::warn!(
            records,
            limit = MAX_MDNS_RECORDS,
            peers,
            "LAN discovery turned off: too many records are announced on the local network"
        );
    }

    /// Logs what was dropped and what libp2p-mdns complained about, as counts, at most
    /// once per [`WARN_INTERVAL`].
    fn warn_if_due(&mut self, now: Instant) {
        let problems = self.problems.load(Ordering::Relaxed);
        let dropped = self.unreported.peer_limit > 0 || self.unreported.addr_limit > 0;
        if problems == 0 && !dropped {
            return;
        }
        let due = self
            .last_warning
            .is_none_or(|t| now.saturating_duration_since(t) >= WARN_INTERVAL);
        if !due {
            return;
        }
        self.last_warning = Some(now);
        if dropped {
            let unreported = std::mem::take(&mut self.unreported);
            tracing::warn!(
                list_full = unreported.peer_limit,
                peer_full = unreported.addr_limit,
                max_peers = MAX_DISCOVERED_PEERS,
                max_addresses = MAX_ADDRS_PER_PEER,
                "LAN discovery dropped announced addresses: the list is full"
            );
        }
        if problems > 0 {
            let count = self.problems.swap(0, Ordering::Relaxed);
            tracing::warn!(
                count,
                "LAN discovery: the mDNS layer reported errors (its messages are not logged)"
            );
        }
    }
}

impl NetworkBehaviour for Discovery {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = DiscoveryEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    // `handle_pending_outbound_connection` keeps its default and offers no addresses:
    // libp2p-mdns is not asked, so a dial uses the addresses it was given and no others.

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        // libp2p-mdns needs the listen addresses, which are what it announces, and is
        // told nothing else.
        if let Some(lan) = self.lan.as_mut() {
            if matches!(
                event,
                FromSwarm::NewListenAddr(_) | FromSwarm::ExpiredListenAddr(_)
            ) {
                lan.mdns.on_swarm_event(event);
            }
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        let mut budget = POLL_BUDGET;
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Poll::Ready(ToSwarm::GenerateEvent(event));
            }
            let Some(lan) = self.lan.as_mut() else {
                return Poll::Pending;
            };
            if budget == 0 {
                // Whoever floods the network with announcements gets a share of the
                // event loop, not all of it.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            budget -= 1;
            match lan.poll(cx) {
                Poll::Ready(ToSwarm::GenerateEvent(event)) => {
                    let records = lan.mdns.discovered_nodes().len();
                    self.on_mdns_event(event);
                    if records > MAX_MDNS_RECORDS {
                        self.give_up(records);
                    }
                }
                // `NewExternalAddrOfPeer`, which libp2p-mdns emits for every address it
                // hears, ends here: the swarm and the other behaviours never see it.
                Poll::Ready(_) => {}
                Poll::Pending => {
                    self.warn_if_due(Instant::now());
                    return Poll::Pending;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::multihash::Multihash;

    fn peer(n: u16) -> PeerId {
        let mut seed = [0u8; 32];
        seed[..2].copy_from_slice(&n.to_be_bytes());
        seed[31] = 0x5a;
        crate::identity::keypair_from_seed(&zeroize::Zeroizing::new(seed))
            .unwrap()
            .public()
            .to_peer_id()
    }

    fn quic(host: u8, port: u16) -> Multiaddr {
        format!("/ip4/192.168.7.{host}/udp/{port}/quic-v1")
            .parse()
            .unwrap()
    }

    /// The form libp2p-mdns reports: the address with the peer id appended.
    fn announced(peer: PeerId, host: u8, port: u16) -> (PeerId, Multiaddr) {
        (peer, quic(host, port).with(Protocol::P2p(peer)))
    }

    fn drain(d: &mut Discovery) -> Vec<DiscoveryEvent> {
        d.pending.drain(..).collect()
    }

    #[test]
    fn dialable_accepts_quic_v1_and_appends_the_peer_id() {
        let p = peer(1);
        let want: Multiaddr = format!("/ip4/192.168.7.2/udp/4001/quic-v1/p2p/{p}")
            .parse()
            .unwrap();
        assert_eq!(dialable(&p, &quic(2, 4001)), Some(want.clone()));
        assert_eq!(dialable(&p, &want), Some(want));
        let v6: Multiaddr = "/ip6/fd00::7/udp/4001/quic-v1".parse().unwrap();
        assert_eq!(
            dialable(&p, &v6),
            Some(v6.clone().with(Protocol::P2p(p))),
            "{v6}"
        );
    }

    #[test]
    fn dialable_rejects_everything_the_transport_cannot_dial() {
        let p = peer(1);
        let other = peer(2);
        for bad in [
            "/ip4/192.168.7.2/tcp/4001".to_owned(),
            "/ip4/192.168.7.2/udp/4001".to_owned(),
            "/ip4/192.168.7.2/udp/4001/quic".to_owned(),
            "/ip4/192.168.7.2/udp/0/quic-v1".to_owned(),
            "/ip4/0.0.0.0/udp/4001/quic-v1".to_owned(),
            "/ip4/224.0.0.251/udp/4001/quic-v1".to_owned(),
            "/ip4/255.255.255.255/udp/4001/quic-v1".to_owned(),
            "/ip6/::/udp/4001/quic-v1".to_owned(),
            "/ip6/ff02::fb/udp/4001/quic-v1".to_owned(),
            "/dns4/example.org/udp/4001/quic-v1".to_owned(),
            "/ip4/192.168.7.2/udp/4001/quic-v1/webtransport".to_owned(),
            format!("/ip4/192.168.7.2/udp/4001/quic-v1/p2p/{other}"),
            format!("/ip4/192.168.7.2/udp/4001/quic-v1/p2p/{p}/p2p-circuit"),
            format!("/ip4/192.168.7.2/udp/4001/quic-v1/p2p/{other}/p2p-circuit/p2p/{p}"),
            format!("/p2p/{p}"),
        ] {
            let addr: Multiaddr = bad.parse().unwrap();
            assert_eq!(dialable(&p, &addr), None, "{bad}");
        }
        assert_eq!(dialable(&p, &Multiaddr::empty()), None);
    }

    #[test]
    fn table_keeps_at_most_the_documented_number_of_peers_and_addresses() {
        let mut t = Table::default();
        for n in 0..MAX_DISCOVERED_PEERS {
            assert_eq!(t.admit(peer(n as u16), quic(1, 4001)), Admit::Added);
        }
        // The list is full: a new peer is dropped, a listed one still gains addresses.
        let late = peer(MAX_DISCOVERED_PEERS as u16);
        assert_eq!(t.admit(late, quic(1, 4001)), Admit::PeerLimit);
        assert_eq!(t.snapshot().len(), MAX_DISCOVERED_PEERS);
        let p = peer(0);
        assert_eq!(t.admit(p, quic(1, 4001)), Admit::Known);
        for port in 1..MAX_ADDRS_PER_PEER as u16 {
            assert_eq!(t.admit(p, quic(1, 5000 + port)), Admit::Added);
        }
        assert_eq!(t.admit(p, quic(1, 6000)), Admit::AddrLimit);
        assert_eq!(t.peers[&p].len(), MAX_ADDRS_PER_PEER);
        assert_eq!(t.snapshot().len(), MAX_DISCOVERED_PEERS);

        // An expired address frees its slot, an expired peer its place in the list.
        assert!(t.remove(&p, &quic(1, 4001)));
        assert!(!t.remove(&p, &quic(1, 4001)));
        assert_eq!(t.admit(p, quic(1, 6000)), Admit::Added);
        let q = peer(1);
        assert!(t.remove(&q, &quic(1, 4001)));
        assert!(!t.peers.contains_key(&q));
        assert!(!t.remove(&q, &quic(1, 4001)));
        assert_eq!(t.admit(late, quic(1, 4001)), Admit::Added);
        assert_eq!(t.snapshot().len(), MAX_DISCOVERED_PEERS);
    }

    #[test]
    fn snapshot_is_ordered_by_peer_id() {
        let mut t = Table::default();
        for n in [5u16, 1, 9, 3] {
            t.admit(peer(n), quic(1, 4001));
        }
        let ids: Vec<PeerId> = t.snapshot().into_iter().map(|(p, _)| p).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn off_has_no_mdns_and_never_produces_an_event() {
        let mut d = Discovery::off(peer(1));
        assert!(!d.is_on());
        assert!(d.lan.is_none());
        assert!(d.snapshot().is_empty());
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(d.poll(&mut cx).is_pending());
        // Listen addresses are not passed anywhere either.
        let addr = quic(1, 4001);
        d.on_swarm_event(FromSwarm::NewListenAddr(libp2p::swarm::NewListenAddr {
            listener_id: libp2p::core::transport::ListenerId::next(),
            addr: &addr,
        }));
        assert!(d.poll(&mut cx).is_pending());
        assert_eq!(
            d.handle_pending_outbound_connection(
                ConnectionId::new_unchecked(1),
                Some(peer(2)),
                &[],
                Endpoint::Dialer,
            )
            .unwrap(),
            Vec::<Multiaddr>::new()
        );
    }

    #[test]
    fn discovered_records_become_one_event_per_peer_with_only_new_addresses() {
        let me = peer(1);
        let (a, b) = (peer(2), peer(3));
        let mut d = Discovery::off(me);
        d.on_mdns_event(mdns::Event::Discovered(vec![
            announced(a, 2, 4001),
            announced(b, 3, 4001),
            announced(a, 2, 4002),
        ]));
        let with = |p: PeerId, host, port| quic(host, port).with(Protocol::P2p(p));
        assert_eq!(
            drain(&mut d),
            vec![
                DiscoveryEvent::Discovered {
                    peer_id: a,
                    addrs: vec![with(a, 2, 4001), with(a, 2, 4002)],
                },
                DiscoveryEvent::Discovered {
                    peer_id: b,
                    addrs: vec![with(b, 3, 4001)],
                },
            ]
        );
        // Hearing a record again is not news; a further address is.
        d.on_mdns_event(mdns::Event::Discovered(vec![
            announced(a, 2, 4001),
            announced(a, 2, 4003),
        ]));
        assert_eq!(
            drain(&mut d),
            vec![DiscoveryEvent::Discovered {
                peer_id: a,
                addrs: vec![with(a, 2, 4003)],
            }]
        );
        let listed = d.snapshot();
        assert_eq!(listed.len(), 2);
        let of_a = &listed.iter().find(|(p, _)| *p == a).unwrap().1;
        assert_eq!(
            of_a,
            &vec![with(a, 2, 4001), with(a, 2, 4002), with(a, 2, 4003)]
        );
        // The behaviour offers none of it to a dial.
        assert!(d
            .handle_pending_outbound_connection(
                ConnectionId::new_unchecked(1),
                Some(a),
                &[],
                Endpoint::Dialer,
            )
            .unwrap()
            .is_empty());
    }

    #[test]
    fn undialable_records_own_id_and_foreign_identities_are_ignored() {
        let me = peer(1);
        let a = peer(2);
        // A hashed (non-Ed25519) peer id, as RSA-keyed libp2p nodes have.
        let hashed =
            PeerId::from_multihash(Multihash::<64>::wrap(0x12, &[7u8; 32]).unwrap()).unwrap();
        let tcp: Multiaddr = format!("/ip4/192.168.7.2/tcp/4001/p2p/{a}")
            .parse()
            .unwrap();
        let webtransport: Multiaddr =
            format!("/ip4/192.168.7.2/udp/4001/quic-v1/webtransport/p2p/{a}")
                .parse()
                .unwrap();
        let mut d = Discovery::off(me);
        d.on_mdns_event(mdns::Event::Discovered(vec![
            announced(me, 9, 4001),
            (hashed, quic(4, 4001).with(Protocol::P2p(hashed))),
            (a, tcp.clone()),
            (a, webtransport),
        ]));
        assert_eq!(drain(&mut d), vec![]);
        assert!(d.snapshot().is_empty());
        // Their expiry is not reported either.
        d.on_mdns_event(mdns::Event::Expired(vec![
            (a, tcp),
            (hashed, quic(4, 4001).with(Protocol::P2p(hashed))),
        ]));
        assert_eq!(drain(&mut d), vec![]);
    }

    #[test]
    fn expiry_reports_what_left_the_list_and_frees_the_peer() {
        let (a, b) = (peer(2), peer(3));
        let mut d = Discovery::off(peer(1));
        d.on_mdns_event(mdns::Event::Discovered(vec![
            announced(a, 2, 4001),
            announced(a, 2, 4002),
            announced(b, 3, 4001),
        ]));
        drain(&mut d);
        d.on_mdns_event(mdns::Event::Expired(vec![
            announced(a, 2, 4001),
            announced(b, 3, 9999),
        ]));
        let with = |p: PeerId, host, port| quic(host, port).with(Protocol::P2p(p));
        assert_eq!(
            drain(&mut d),
            vec![DiscoveryEvent::Expired {
                peer_id: a,
                addrs: vec![with(a, 2, 4001)],
            }]
        );
        assert_eq!(d.snapshot().len(), 2);
        d.on_mdns_event(mdns::Event::Expired(vec![
            announced(a, 2, 4002),
            announced(b, 3, 4001),
        ]));
        assert_eq!(drain(&mut d).len(), 2);
        assert!(d.snapshot().is_empty());
    }

    #[test]
    fn records_over_the_bounds_are_dropped_and_counted() {
        let mut d = Discovery::off(peer(0));
        let crowd: Vec<(PeerId, Multiaddr)> = (1..=MAX_DISCOVERED_PEERS as u16 + 10)
            .map(|n| announced(peer(n), 1, 4001))
            .collect();
        d.on_mdns_event(mdns::Event::Discovered(crowd));
        assert_eq!(drain(&mut d).len(), MAX_DISCOVERED_PEERS);
        assert_eq!(d.snapshot().len(), MAX_DISCOVERED_PEERS);
        assert_eq!(d.unreported.peer_limit, 10);

        let p = peer(1);
        let many: Vec<(PeerId, Multiaddr)> = (0..MAX_ADDRS_PER_PEER as u16 + 5)
            .map(|i| announced(p, 1, 5000 + i))
            .collect();
        d.on_mdns_event(mdns::Event::Discovered(many));
        let events = drain(&mut d);
        assert_eq!(events.len(), 1);
        match &events[0] {
            DiscoveryEvent::Discovered { peer_id, addrs } => {
                assert_eq!(*peer_id, p);
                // One address was known already.
                assert_eq!(addrs.len(), MAX_ADDRS_PER_PEER - 1);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(d.unreported.addr_limit, 6);
        let listed = d.snapshot();
        assert!(listed.len() <= MAX_DISCOVERED_PEERS);
        assert!(listed.iter().all(|(_, a)| a.len() <= MAX_ADDRS_PER_PEER));

        // The counts are logged at most once per interval and then start again.
        let t0 = Instant::now();
        d.warn_if_due(t0);
        assert_eq!(d.unreported.peer_limit, 0);
        assert_eq!(d.unreported.addr_limit, 0);
        d.on_mdns_event(mdns::Event::Discovered(vec![announced(p, 1, 7000)]));
        d.warn_if_due(t0 + Duration::from_secs(1));
        assert_eq!(d.unreported.addr_limit, 1);
        d.warn_if_due(t0 + WARN_INTERVAL);
        assert_eq!(d.unreported.addr_limit, 0);
    }

    #[test]
    fn giving_up_expires_every_listed_peer() {
        let (a, b) = (peer(2), peer(3));
        let mut d = Discovery::off(peer(1));
        d.on_mdns_event(mdns::Event::Discovered(vec![
            announced(a, 2, 4001),
            announced(b, 3, 4001),
        ]));
        drain(&mut d);
        d.give_up(MAX_MDNS_RECORDS + 1);
        let events = drain(&mut d);
        assert_eq!(events.len(), 2);
        assert!(events
            .iter()
            .all(|e| matches!(e, DiscoveryEvent::Expired { .. })));
        assert!(d.snapshot().is_empty());
        assert!(!d.is_on());
    }

    #[test]
    fn mdns_log_output_is_counted_not_written() {
        let problems = Arc::new(AtomicUsize::new(0));
        let quiet = tracing::Dispatch::new(CountProblems(problems.clone()));
        tracing::dispatcher::with_default(&quiet, || {
            let span = tracing::info_span!("poll", address = "192.168.7.2");
            assert!(span.is_disabled());
            tracing::trace!(address = "192.168.7.2", "sending query on iface");
            tracing::debug!("parsing failed");
            tracing::info!(address = "192.168.7.2", "discovered peer on address");
            tracing::warn!(address = "192.168.7.2", "excluding address");
            assert_eq!(problems.load(Ordering::Relaxed), 0);
            tracing::error!(address = "192.168.7.2", "error sending packet");
            tracing::error!("failed to create instance");
        });
        assert_eq!(problems.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn host_ends_what_was_spawned_on_it_and_counts_what_it_logs() {
        use std::sync::atomic::AtomicBool;

        /// Stands for an interface task's sockets: says when it was dropped.
        struct Held(Arc<AtomicBool>);
        impl Drop for Held {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let problems = Arc::new(AtomicUsize::new(0));
        let host = Host::start(problems.clone()).unwrap();
        let released = Arc::new(AtomicBool::new(false));
        let held = Held(released.clone());
        let (running, is_running) = std::sync::mpsc::channel();
        {
            // As `Lan::poll` does: what is spawned here lands on the host's runtime.
            let _runtime = host.runtime.enter();
            tokio::spawn(async move {
                let _held = held;
                tracing::info!(
                    address = "192.168.7.2",
                    "creating instance on iface address"
                );
                tracing::error!(address = "192.168.7.2", "error sending packet");
                let _ = running.send(std::thread::current().name().map(str::to_owned));
                // Like an interface task, it never ends by itself.
                std::future::pending::<()>().await;
            });
        }
        let thread = is_running
            .recv_timeout(Duration::from_secs(20))
            .expect("the task runs");
        assert_eq!(thread.as_deref(), Some("ph-lan-discovery"));
        assert_eq!(problems.load(Ordering::Relaxed), 1);
        assert!(!released.load(Ordering::SeqCst));

        drop(host);
        // Not "soon": the task and what it held are gone when `drop` returns.
        assert!(released.load(Ordering::SeqCst));
    }

    #[test]
    fn bounds_and_intervals_are_the_documented_ones() {
        assert_eq!(MAX_DISCOVERED_PEERS, 256);
        assert_eq!(MAX_ADDRS_PER_PEER, 8);
        assert_eq!(MAX_MDNS_RECORDS, 16_384);
        assert!(QUERY_INTERVAL < RECORD_TTL);
    }
}
