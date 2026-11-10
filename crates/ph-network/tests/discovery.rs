//! Opt-in discovery on the local network (mDNS).
//!
//! The tests that need real multicast are `#[ignore]`d: with discovery on, a node opens
//! sockets on UDP 5353 and sends to `224.0.0.251` on every non-loopback IPv4 interface
//! of this machine, which a CI container may not have or allow. Run them with
//!
//! ```sh
//! cargo test -p ph-network --locked --test discovery -- --ignored
//! ```
//!
//! While they run, this machine announces throwaway peer ids on its network. The other
//! tests here keep discovery off and run everywhere.

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::*;
use ph_network::{
    device_key_from_peer_id, peer_id_of_addr, start, without_p2p, HelloOnlyHandler, Multiaddr,
    NetError, NetEvent, NetworkConfig, NetworkHandle, PeerId,
};
use ph_protocol::wire::{Request, Response};
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use zeroize::Zeroizing;

/// How long a node may take to hear of another one. A node asks when it starts, and
/// again after 1 s, 2 s, 4 s and so on while nobody has answered.
const DISCOVERY: Duration = Duration::from_secs(60);

/// How long to wait for news before one more node is started to ask the network.
const ASK_AGAIN: Duration = Duration::from_secs(3);

/// How long a node that must stay unseen is watched after everything else was seen.
const WATCH: Duration = Duration::from_secs(3);

/// A seed that no other node of this run has and, in practice, no other run either:
/// these nodes announce themselves on a real network, where a second run of the same
/// tests (or what is left of an earlier one in other nodes' lists) may be around.
fn fresh_seed() -> Zeroizing<[u8; 32]> {
    static RUN: OnceLock<[u8; 20]> = OnceLock::new();
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let run = RUN.get_or_init(|| {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after 1970")
            .as_nanos();
        let mut id = [0u8; 20];
        id[..16].copy_from_slice(&nanos.to_be_bytes());
        id[16..].copy_from_slice(&std::process::id().to_be_bytes());
        id
    });
    let mut seed = [0u8; 32];
    seed[..20].copy_from_slice(run);
    seed[20..24].copy_from_slice(&NEXT.fetch_add(1, Ordering::SeqCst).to_be_bytes());
    seed[31] = 0xa5;
    Zeroizing::new(seed)
}

/// Whether a node has an address others can reach it at.
#[derive(Clone, Copy)]
enum Listen {
    /// On every interface: mDNS never announces a loopback address.
    AllInterfaces,
    /// Not at all: a node that only dials.
    Nowhere,
}

fn lan_config(listen: Listen, lan_discovery: bool) -> NetworkConfig {
    let listen_addrs = match listen {
        Listen::AllInterfaces => vec!["/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap()],
        Listen::Nowhere => Vec::new(),
    };
    NetworkConfig {
        lan_discovery,
        ..NetworkConfig::listening_on(listen_addrs)
    }
}

fn lan_node_with(config: NetworkConfig) -> Node {
    let (net, join) =
        start(fresh_seed(), config, Arc::new(HelloOnlyHandler)).expect("start network");
    Node { net, join }
}

fn lan_node(listen: Listen, lan_discovery: bool) -> Node {
    lan_node_with(lan_config(listen, lan_discovery))
}

/// The addresses `net` currently lists for `peer`.
async fn listed(net: &NetworkHandle, peer: PeerId) -> Vec<Multiaddr> {
    within("discovered()", net.discovered())
        .await
        .expect("network running")
        .into_iter()
        .find(|(p, _)| *p == peer)
        .map(|(_, addrs)| addrs)
        .unwrap_or_default()
}

/// Waits until `events` reports `peer` as discovered.
async fn discovered_event(events: &mut tokio::sync::broadcast::Receiver<NetEvent>, peer: PeerId) {
    loop {
        match events.recv().await {
            Ok(NetEvent::PeerDiscovered { peer_id, .. }) if peer_id == peer => return,
            Ok(_) | Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => panic!("event channel closed"),
        }
    }
}

/// Waits until `net` lists `peer` and returns its addresses.
///
/// A node that is already running hears of a newcomer when the newcomer answers a
/// query. That is usually the newcomer's own first query, but its next chance may be
/// minutes away. So whenever nothing was heard for a while, one more node is started:
/// its first query makes every node on the network answer.
async fn wait_discovered(net: &NetworkHandle, peer: PeerId, what: &str) -> Vec<Multiaddr> {
    let mut events = net.subscribe();
    let deadline = tokio::time::Instant::now() + DISCOVERY;
    let mut askers = Vec::new();
    let found = loop {
        let addrs = listed(net, peer).await;
        if !addrs.is_empty() {
            break addrs;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        let news = tokio::time::timeout(ASK_AGAIN, discovered_event(&mut events, peer)).await;
        if news.is_err() {
            askers.push(lan_node(Listen::Nowhere, true));
        }
    };
    for asker in askers {
        stop(asker).await;
    }
    found
}

/// Fails if `net` reports `peer` as discovered within [`WATCH`] or lists it afterwards.
async fn assert_stays_unseen(net: &NetworkHandle, peer: PeerId, what: &str) {
    let mut events = net.subscribe();
    assert!(listed(net, peer).await.is_empty(), "{what}");
    let seen = tokio::time::timeout(WATCH, discovered_event(&mut events, peer)).await;
    assert!(seen.is_err(), "{what}");
    assert!(listed(net, peer).await.is_empty(), "{what}");
}

/// Every discovery event `events` holds right now.
fn discovery_events(events: &mut tokio::sync::broadcast::Receiver<NetEvent>) -> Vec<NetEvent> {
    let mut found = Vec::new();
    loop {
        match events.try_recv() {
            Ok(e @ (NetEvent::PeerDiscovered { .. } | NetEvent::PeerExpired { .. })) => {
                found.push(e)
            }
            Ok(_) | Err(TryRecvError::Lagged(_)) => {}
            Err(TryRecvError::Empty | TryRecvError::Closed) => return found,
        }
    }
}

/// What was logged, as `(target, fields)`.
type Logged = Arc<std::sync::Mutex<Vec<(String, String)>>>;

/// A subscriber that keeps every event, at every level, of this crate and of the crates
/// that libp2p's mDNS consists of.
struct KeepLogs(Logged);

impl tracing::Subscriber for KeepLogs {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        ["ph_network", "libp2p_mdns", "hickory", "if_watch"]
            .iter()
            .any(|prefix| metadata.target().starts_with(prefix))
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                let _ = write!(self.0, " {}={value:?}", field.name());
            }
        }
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        self.0
            .lock()
            .unwrap()
            .push((event.metadata().target().to_owned(), fields.0));
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs multicast on the local network"]
async fn discovery_logs_peer_ids_and_counts_and_never_an_address() {
    // For the whole process: the nodes of the other tests are held to the same rule.
    let logged = Logged::default();
    tracing::subscriber::set_global_default(KeepLogs(logged.clone()))
        .expect("no other global subscriber in this test binary");

    let a = lan_node(Listen::AllInterfaces, true);
    let b = lan_node(Listen::AllInterfaces, true);
    let (a_id, b_id) = (a.net.local_peer_id(), b.net.local_peer_id());
    let b_addrs = wait_discovered(&a.net, b_id, "A to discover B").await;
    wait_discovered(&b.net, a_id, "B to discover A").await;
    // What must not be logged in any form: the interface addresses of this machine,
    // which are the addresses the two nodes announced and discovered.
    let mut interface_addrs: Vec<String> = Vec::new();
    for addr in a.net.current_listen_addrs() {
        if let Some(ph_network::libp2p::multiaddr::Protocol::Ip4(ip)) = addr.iter().next() {
            interface_addrs.push(ip.to_string());
        }
    }
    assert!(!interface_addrs.is_empty() && !b_addrs.is_empty());
    for n in [a, b] {
        stop(n).await;
    }

    let logged = logged.lock().unwrap().clone();
    // This crate did log the discovery, naming the peer.
    assert!(
        logged.iter().any(|(target, fields)| {
            target.starts_with("ph_network")
                && fields.contains("discovered on the local network")
                && fields.contains(&b_id.to_string())
        }),
        "the discovery of B was not logged"
    );
    for (target, fields) in &logged {
        // libp2p-mdns and its DNS parser log addresses and packet contents: nothing of
        // theirs gets through, at any level.
        assert!(target.starts_with("ph_network"), "{target} logged");
        assert!(!fields.contains("/ip4/"), "{target} logged an address");
        assert!(!fields.contains("/udp/"), "{target} logged an address");
        for ip in &interface_addrs {
            assert!(!fields.contains(ip.as_str()), "{target} logged an address");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_is_off_by_default_and_then_nothing_is_reported() {
    assert!(!NetworkConfig::default().lan_discovery);
    assert!(!loopback_config().lan_discovery);

    let a = node(60, loopback_config(), Arc::new(HelloOnlyHandler));
    let b = node(61, loopback_config(), Arc::new(HelloOnlyHandler));
    let mut a_events = a.net.subscribe();
    assert_eq!(a.net.discovered().await, Ok(Vec::new()));

    // The transport works as before, and a peer one connects to is not "discovered".
    let b_id = connect(&a.net, &b.net).await;
    assert_eq!(
        within("hello", a.net.request(b_id, &Request::hello())).await,
        Ok(Response::hello())
    );
    assert_eq!(a.net.discovered().await, Ok(Vec::new()));
    assert_eq!(b.net.discovered().await, Ok(Vec::new()));

    let a_net = a.net.clone();
    stop(b).await;
    stop(a).await;
    assert_eq!(a_net.discovered().await, Err(NetError::Shutdown));
    assert_eq!(discovery_events(&mut a_events), Vec::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs multicast on the local network"]
async fn nodes_with_discovery_find_each_other_and_a_node_without_it_stays_invisible() {
    // C has discovery off. It is up before the others, so it is there, listening on the
    // same interfaces, for every query they send.
    let c = lan_node(Listen::AllInterfaces, false);
    within("C listens", c.net.listen_addrs()).await.unwrap();
    let mut c_events = c.net.subscribe();
    let a = lan_node(Listen::AllInterfaces, true);
    let b = lan_node(Listen::AllInterfaces, true);
    let (a_id, b_id, c_id) = (
        a.net.local_peer_id(),
        b.net.local_peer_id(),
        c.net.local_peer_id(),
    );

    let b_addrs = wait_discovered(&a.net, b_id, "A to discover B").await;
    let a_addrs = wait_discovered(&b.net, a_id, "B to discover A").await;

    // What is reported: QUIC addresses the peer really listens on, naming the peer.
    for (peer, addrs, node) in [(b_id, &b_addrs, &b), (a_id, &a_addrs, &a)] {
        assert!(device_key_from_peer_id(&peer).is_some());
        assert!(addrs.len() <= ph_network::discovery::MAX_ADDRS_PER_PEER);
        let listens = node.net.current_listen_addrs();
        for addr in addrs {
            assert_eq!(peer_id_of_addr(addr), Some(peer), "{addr}");
            assert!(addr.to_string().contains("/quic-v1/p2p/"), "{addr}");
            assert!(listens.contains(&without_p2p(addr)), "{addr}");
            assert!(!addr.to_string().starts_with("/ip4/127."), "{addr}");
        }
    }

    // Discovery dialed nobody.
    assert_eq!(a.net.is_connected(b_id).await, Ok(false));
    assert_eq!(b.net.is_connected(a_id).await, Ok(false));
    assert_eq!(c.net.connected_peers().await, Ok(Vec::new()));

    // The node with discovery off is not found, and finds nobody.
    assert_stays_unseen(&a.net, c_id, "A found the node that has discovery off").await;
    assert!(listed(&b.net, c_id).await.is_empty());
    assert_eq!(c.net.discovered().await, Ok(Vec::new()));
    assert_eq!(discovery_events(&mut c_events), Vec::new());

    // The application decides: a discovered address works with an explicit dial, which
    // then proves the announced identity.
    let dialed = within("dial a discovered address", a.net.dial(b_addrs[0].clone())).await;
    assert_eq!(dialed, Ok(b_id));
    assert_eq!(
        within("hello", a.net.request(b_id, &Request::hello())).await,
        Ok(Response::hello())
    );

    for n in [a, b, c] {
        stop(n).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs multicast on the local network"]
async fn a_node_that_only_dials_discovers_others_and_is_not_announced() {
    let a = lan_node(Listen::AllInterfaces, true);
    let d = lan_node(Listen::Nowhere, true);
    let (a_id, d_id) = (a.net.local_peer_id(), d.net.local_peer_id());

    let a_addrs = wait_discovered(&d.net, a_id, "the dial-only node to discover A").await;

    // E arrives later. Once A lists E, A has heard the answers to a query that the
    // dial-only node answered too.
    let e = lan_node(Listen::AllInterfaces, true);
    let e_id = e.net.local_peer_id();
    wait_discovered(&a.net, e_id, "A to discover E").await;
    wait_discovered(&e.net, a_id, "E to discover A").await;
    assert_stays_unseen(&a.net, d_id, "A found the node that only dials").await;
    assert!(listed(&e.net, d_id).await.is_empty());

    // The dial-only node can use what it discovered.
    let dialed = within("dial a discovered address", d.net.dial(a_addrs[0].clone())).await;
    assert_eq!(dialed, Ok(a_id));

    for n in [a, d, e] {
        stop(n).await;
    }
}

/// An mDNS answer in the form libp2p nodes send: `peer` at `addrs`, valid for `ttl`
/// seconds. Any host on the network can send one, for any peer id.
fn announcement(peer: PeerId, addrs: &[String], ttl: u32) -> Vec<u8> {
    fn name(out: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }
    let mut host = Vec::new();
    name(&mut host, "phnetworkdiscoverytesthost");
    // Header: an answer with one answer record and one additional record per address.
    let mut packet = vec![0, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0];
    packet.extend_from_slice(&u16::try_from(addrs.len()).unwrap().to_be_bytes());
    // PTR _p2p._udp.local -> host
    name(&mut packet, "_p2p._udp.local");
    packet.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01]);
    packet.extend_from_slice(&ttl.to_be_bytes());
    packet.extend_from_slice(&u16::try_from(host.len()).unwrap().to_be_bytes());
    packet.extend_from_slice(&host);
    // TXT host -> "dnsaddr=<address>/p2p/<peer>"
    for addr in addrs {
        let txt = format!("dnsaddr={addr}/p2p/{peer}");
        packet.extend_from_slice(&host);
        packet.extend_from_slice(&[0x00, 0x10, 0x80, 0x01]);
        packet.extend_from_slice(&ttl.to_be_bytes());
        packet.extend_from_slice(&u16::try_from(txt.len() + 1).unwrap().to_be_bytes());
        packet.push(u8::try_from(txt.len()).unwrap());
        packet.extend_from_slice(txt.as_bytes());
    }
    packet
}

fn fresh_peer_id() -> PeerId {
    ph_network::keypair_from_seed(&fresh_seed())
        .unwrap()
        .public()
        .to_peer_id()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs multicast on the local network"]
async fn an_announcement_from_the_network_is_a_bounded_hint_that_is_not_dialed_and_expires() {
    use ph_network::discovery::MAX_ADDRS_PER_PEER;
    use ph_network::libp2p::multihash::Multihash;

    // A short dial timeout: the one dial below goes to an address where nothing answers.
    let a = lan_node_with(NetworkConfig {
        dial_timeout: Duration::from_secs(2),
        ..lan_config(Listen::AllInterfaces, true)
    });
    let mut events = a.net.subscribe();

    // Three announcements that no libp2p node stands behind. `ghost` is a device key
    // nobody holds, announced at more addresses than a peer may have plus one that is
    // not QUIC. `hashed` is not a device key. `tcp_only` has nothing this transport
    // dials. The addresses are in a documentation range: nothing is there.
    const TTL_SECS: u32 = 3;
    let ghost = fresh_peer_id();
    let hashed =
        PeerId::from_multihash(Multihash::<64>::wrap(0x12, &fresh_seed()[..]).unwrap()).unwrap();
    let tcp_only = fresh_peer_id();
    let mut ghost_addrs: Vec<String> = (0..MAX_ADDRS_PER_PEER + 4)
        .map(|i| format!("/ip4/203.0.113.7/udp/{}/quic-v1", 40_000 + i))
        .collect();
    ghost_addrs.push("/ip4/203.0.113.7/tcp/40000".to_owned());
    let packets = [
        announcement(
            hashed,
            &["/ip4/203.0.113.7/udp/40000/quic-v1".to_owned()],
            TTL_SECS,
        ),
        announcement(
            tcp_only,
            &["/ip4/203.0.113.7/tcp/40000".to_owned()],
            TTL_SECS,
        ),
        announcement(ghost, &ghost_addrs, TTL_SECS),
    ];
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();

    // The node's multicast sockets open a moment after it starts, so the packets are
    // sent again until the last of them was heard.
    let deadline = tokio::time::Instant::now() + DISCOVERY;
    let ghost_listed = loop {
        for packet in &packets {
            socket.send_to(packet, "224.0.0.251:5353").unwrap();
        }
        let heard = tokio::time::timeout(
            Duration::from_millis(500),
            discovered_event(&mut events, ghost),
        )
        .await;
        let addrs = listed(&a.net, ghost).await;
        if heard.is_ok() || !addrs.is_empty() {
            break addrs;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for the announcement to be heard"
        );
    };

    // Reported: QUIC addresses only, no more than the bound, naming the announced
    // peer, and at the address the packet came from, not the one it claimed.
    assert_eq!(ghost_listed.len(), MAX_ADDRS_PER_PEER);
    for addr in &ghost_listed {
        assert_eq!(peer_id_of_addr(addr), Some(ghost), "{addr}");
        assert!(addr.to_string().contains("/quic-v1/p2p/"), "{addr}");
        assert!(!addr.to_string().contains("203.0.113.7"), "{addr}");
    }
    assert!(listed(&a.net, hashed).await.is_empty());
    assert!(listed(&a.net, tcp_only).await.is_empty());

    // Not dialed: nothing connects to an announced peer unless the application dials.
    assert_eq!(a.net.is_connected(ghost).await, Ok(false));

    // An explicit dial of the hint fails: nobody there holds the announced key.
    let dialed = within("dial", a.net.dial(ghost_listed[0].clone())).await;
    assert_eq!(dialed, Err(NetError::Dial));

    // Not announced again, the records expire and the peer leaves the list.
    let mut expired = 0;
    while expired < MAX_ADDRS_PER_PEER {
        match wait_event(
            &mut events,
            "the announcement to expire",
            |e| matches!(e, NetEvent::PeerExpired { peer_id, .. } if *peer_id == ghost),
        )
        .await
        {
            NetEvent::PeerExpired { addrs, .. } => expired += addrs.len(),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(expired, MAX_ADDRS_PER_PEER);
    assert!(listed(&a.net, ghost).await.is_empty());

    stop(a).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs multicast on the local network"]
async fn a_stopped_node_is_no_longer_announced() {
    let a = lan_node(Listen::AllInterfaces, true);
    let b = lan_node(Listen::AllInterfaces, true);
    let (a_id, b_id) = (a.net.local_peer_id(), b.net.local_peer_id());
    // A was announced while it ran.
    wait_discovered(&b.net, a_id, "B to discover A").await;

    stop(a).await;

    // F starts after A has stopped. Anything that still answered for A would answer
    // the same queries as B, to the whole network. So F and a second newcomer hearing
    // B, and neither hearing A, shows that nothing answers for A any more.
    let f = lan_node(Listen::AllInterfaces, true);
    wait_discovered(&f.net, b_id, "F to discover B").await;
    let g = lan_node(Listen::Nowhere, true);
    wait_discovered(&g.net, b_id, "G to discover B").await;
    assert_stays_unseen(&f.net, a_id, "a stopped node was still announced").await;
    assert!(listed(&g.net, a_id).await.is_empty());

    for n in [b, f, g] {
        stop(n).await;
    }
}
