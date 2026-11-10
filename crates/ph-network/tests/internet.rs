//! The opt-in internet mode: finding and reaching a peer by its peer id.
//!
//! Most tests here need no internet. They build a private miniature of the public
//! network on loopback: one **hub** that is bootstrap peer, DHT server, relay and
//! (when asked) AutoNAT server, and PeerHarness nodes that are configured with that
//! hub as their only bootstrap peer and with
//! `InternetConfig::allow_private_addresses`, so that loopback addresses count.
//!
//! The hub is test-only code built from libp2p directly. PeerHarness never ships a DHT
//! server or a relay. It is written to answer like the servers of the public network
//! do (go-libp2p): a `FIND_NODE` for a peer id is answered with the addresses that
//! peer reported over identify while it is connected, and with nothing otherwise.
//! That the public network really behaves this way is what the `#[ignore]`d tests at
//! the end check, against the real thing:
//!
//! ```sh
//! cargo test -p ph-network --locked --test internet -- --ignored --nocapture --test-threads 1
//! ```
//!
//! They join the public libp2p network with throwaway keys and need internet access.

mod common;
#[path = "common/hub.rs"]
mod hub;

use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use common::*;
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use hub::*;
use ph_network::libp2p::multiaddr::Protocol;
use ph_network::libp2p::request_response::{self, ProtocolSupport};
use ph_network::libp2p::swarm::SwarmEvent;
use ph_network::libp2p::{StreamProtocol, SwarmBuilder};
use ph_network::{
    device_key_from_peer_id, internet, is_relayed, keypair_from_seed, peer_id_of_addr, start,
    HelloOnlyHandler, InternetConfig, Multiaddr, NetError, NetEvent, NetworkConfig, PeerId,
    RateLimits, Reachability,
};
use ph_protocol::wire::{ErrorCode, Request, Response};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------------
// What a node speaks: probing it protocol by protocol.
// ---------------------------------------------------------------------------------

/// Opens a stream for one protocol, sends nothing, and reads what comes back.
#[derive(Clone, Default)]
struct ProbeCodec;

impl request_response::Codec for ProbeCodec {
    type Protocol = StreamProtocol;
    type Request = ();
    type Response = usize;

    async fn read_request<T>(&mut self, _: &StreamProtocol, _: &mut T) -> io::Result<()>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        Err(io::Error::other("the probe answers nothing"))
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<usize>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        // A node may reset the stream when it gets no request: that is an answer too.
        let _ = io.take(1024 * 1024).read_to_end(&mut buf).await;
        Ok(buf.len())
    }

    async fn write_request<T>(&mut self, _: &StreamProtocol, io: &mut T, _: ()) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        io.close().await
    }

    async fn write_response<T>(&mut self, _: &StreamProtocol, _: &mut T, _: usize) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        Err(io::Error::other("the probe answers nothing"))
    }
}

/// Whether the node at `addr` agrees to speak `protocol` with a stranger that dials it.
async fn speaks(addr: &Multiaddr, protocol: &'static str, probe_seed: u8) -> bool {
    let mut swarm =
        SwarmBuilder::with_existing_identity(keypair_from_seed(&seed(probe_seed)).unwrap())
            .with_tokio()
            .with_quic()
            .with_behaviour(|_| {
                request_response::Behaviour::with_codec(
                    ProbeCodec,
                    [(StreamProtocol::new(protocol), ProtocolSupport::Outbound)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_secs(10)),
                )
            })
            .unwrap()
            .build();
    swarm.dial(addr.clone()).unwrap();
    within(protocol, async {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    swarm.behaviour_mut().send_request(&peer_id, ());
                }
                SwarmEvent::Behaviour(request_response::Event::Message { .. }) => return true,
                SwarmEvent::Behaviour(request_response::Event::OutboundFailure {
                    error, ..
                }) => {
                    return match error {
                        request_response::OutboundFailure::UnsupportedProtocols => false,
                        other => panic!("{protocol}: {other}"),
                    }
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    panic!("{protocol}: dial failed: {error}")
                }
                _ => {}
            }
        }
    })
    .await
}

/// Every protocol the internet mode could bring, and the one the node always speaks.
const PROTOCOLS: [&str; 11] = [
    "/peerharness/req/0.1.0",
    "/ipfs/id/1.0.0",
    "/ipfs/id/push/1.0.0",
    "/ipfs/kad/1.0.0",
    "/ipfs/lan/kad/1.0.0",
    "/ipfs/ping/1.0.0",
    "/libp2p/circuit/relay/0.2.0/hop",
    "/libp2p/circuit/relay/0.2.0/stop",
    "/libp2p/autonat/1.0.0",
    "/libp2p/autonat/2/dial-request",
    "/libp2p/autonat/2/dial-back",
];

async fn spoken(addr: &Multiaddr) -> Vec<&'static str> {
    let mut spoken = Vec::new();
    for (i, protocol) in PROTOCOLS.into_iter().enumerate() {
        if speaks(addr, protocol, 200 + i as u8).await {
            spoken.push(protocol);
        }
    }
    spoken
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn off_by_default_the_node_speaks_its_one_protocol_and_nothing_else() {
    assert_eq!(NetworkConfig::default().internet, None);
    let a = node(1, loopback_config(), Arc::new(HelloOnlyHandler));
    let addr = within("listen addr", a.net.listen_addrs()).await.unwrap()[0].clone();
    assert_eq!(spoken(&addr).await, vec!["/peerharness/req/0.1.0"]);

    // The calls of the mode say that it is off, and nothing was started for them.
    assert_eq!(
        a.net
            .find_peer(a.net.local_peer_id(), Duration::from_secs(1))
            .await,
        Err(NetError::InternetOff)
    );
    let b = node(2, loopback_config(), Arc::new(HelloOnlyHandler));
    assert_eq!(
        a.net
            .find_peer(b.net.local_peer_id(), Duration::from_secs(1))
            .await,
        Err(NetError::InternetOff)
    );
    let s = status(&a.net).await;
    assert!(!s.enabled && !s.bootstrapped);
    assert_eq!(s.routing_peers, 0);
    assert_eq!(s.reachability, Reachability::Unknown);
    assert!(s.external_addrs.is_empty() && s.relay_addrs.is_empty());

    // A relayed address is not something a node without the mode can dial.
    let relayed: Multiaddr = format!(
        "{addr}/p2p/{}/p2p-circuit/p2p/{}",
        a.net.local_peer_id(),
        b.net.local_peer_id()
    )
    .parse()
    .unwrap();
    assert_eq!(b.net.dial(relayed).await, Err(NetError::Dial));
    // Peers are still not told apart by anything but what they are: not relayed.
    let pid = connect(&b.net, &a.net).await;
    assert!(!b.net.peer_info(pid).await.unwrap().unwrap().relayed);
    stop(a).await;
    stop(b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_the_mode_on_the_node_is_a_client_and_serves_nobody() {
    let hub = Hub::start(100, HubOptions::default()).await;
    let a = node(
        1,
        internet_config(&hub, Listen::Loopback),
        Arc::new(HelloOnlyHandler),
    );
    let addr = within("listen addr", a.net.listen_addrs()).await.unwrap()[0].clone();
    // To a stranger that dials it, the node answers identify, takes an identify push,
    // and would take a circuit from a relay it has a reservation with or the dial-back
    // of an AutoNAT server it asked. It is no DHT server (no `kad`), no relay (no
    // `hop`) and no AutoNAT server (no `dial-request`, no v1).
    assert_eq!(
        spoken(&addr).await,
        vec![
            "/peerharness/req/0.1.0",
            "/ipfs/id/1.0.0",
            "/ipfs/id/push/1.0.0",
            "/libp2p/circuit/relay/0.2.0/stop",
            "/libp2p/autonat/2/dial-back",
        ]
    );

    // What the hub was told about the node over identify: the fixed strings, and no
    // address that is not confirmed. The node listens on loopback and nobody dialed it
    // back, so the only address it gives is the one through the relay.
    let me = a.net.local_peer_id();
    let relayed = relay_addrs(&a.net).await;
    assert_eq!(relayed, vec![hub.circuit(me)]);
    let (agent, family, addrs) = eventually("identify with the relayed address", || async {
        let id = hub.state().identified.get(&me).cloned()?;
        (!id.2.is_empty()).then_some(id)
    })
    .await;
    assert_eq!(agent, internet::AGENT_VERSION);
    assert_eq!(agent, "peerharness");
    assert_eq!(family, "ipfs/0.1.0");
    assert_eq!(addrs, relayed);
    // The listen address of the application is still what it was, and only that.
    assert_eq!(a.net.current_listen_addrs(), vec![addr]);
    let s = status(&a.net).await;
    assert!(s.enabled);
    assert_eq!(s.routing_peers, 1);
    assert!(s.external_addrs.is_empty());
    stop(a).await;
    hub.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_behind_a_relay_is_found_by_its_peer_id_and_greeted() {
    let hub = Hub::start(100, HubOptions::default()).await;
    let seen = Seen::default();
    // A listens nowhere: the relay is the only way to it.
    let a = node(
        1,
        internet_config(&hub, Listen::Nowhere),
        recording_handler(seen.clone()),
    );
    let b = node(
        2,
        internet_config(&hub, Listen::Loopback),
        Arc::new(HelloOnlyHandler),
    );
    let (a_id, b_id) = (a.net.local_peer_id(), b.net.local_peer_id());
    let mut a_events = a.net.subscribe();
    let mut b_events = b.net.subscribe();
    assert_eq!(relay_addrs(&a.net).await, vec![hub.circuit(a_id)]);

    // B knows A's peer id and nothing else.
    let found = find(&b.net, a_id).await;
    assert_eq!(found, vec![hub.circuit(a_id)]);
    assert!(found.iter().all(|addr| peer_id_of_addr(addr) == Some(a_id)));
    assert!(found.iter().all(is_relayed));
    // Looking up dialed nobody but the hub: no connection to A, no circuit asked for.
    assert_eq!(b.net.is_connected(a_id).await, Ok(false));
    let b_peers: Vec<PeerId> = b
        .net
        .connected_peers()
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.peer_id)
        .collect();
    assert_eq!(b_peers, vec![hub.peer_id]);
    assert!(hub.state().circuits.is_empty());
    assert!(seen.lock().unwrap().is_empty());
    // The hub learned whom B is looking for; that is the price of asking.
    assert!(hub.state().asked.contains(&(b_id, a_id.to_bytes())));

    // The explicit dial connects, and the handshake proved A's key through the relay.
    assert_eq!(within("dial", b.net.dial(found[0].clone())).await, Ok(a_id));
    assert_eq!(hub.state().circuits, vec![(b_id, a_id)]);
    let info = b.net.peer_info(a_id).await.unwrap().unwrap();
    assert_eq!(info.device_key, device_key(1));
    assert_eq!(info.remote_addr, Some(found[0].clone()));
    assert!(info.relayed);
    match wait_event(
        &mut a_events,
        "Connected on A",
        |e| matches!(e, NetEvent::Connected { peer_id, .. } if *peer_id == b_id),
    )
    .await
    {
        NetEvent::Connected {
            peer_id,
            device_key: key,
            remote_addr,
        } if peer_id == b_id => {
            assert_eq!(key, device_key(2));
            assert!(is_relayed(&remote_addr));
            assert_eq!(peer_id_of_addr(&remote_addr), Some(b_id));
        }
        other => panic!("unexpected {other:?}"),
    }

    // `hello` works; anything else is still refused: a peer found on the public network
    // is a stranger like any other.
    let resp = within("hello", b.net.request(a_id, &Request::hello()))
        .await
        .unwrap();
    assert_eq!(resp, Response::hello());
    let resp = within("fetch_bundle", b.net.request(a_id, &fetch_bundle()))
        .await
        .unwrap();
    assert_eq!(resp, Response::error(ErrorCode::Unauthorized));
    // A's handler was given B's proven identity, exactly as on a direct connection.
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        for peer in seen.iter() {
            assert_eq!(peer.peer_id, b_id);
            assert_eq!(peer.device_key, device_key(2));
            assert_eq!(
                device_key_from_peer_id(&peer.peer_id),
                Some(peer.device_key)
            );
            assert!(peer.relayed);
        }
    }

    // A has no socket to punch a hole to, so the connection stays relayed, and both
    // sides are told.
    for (events, peer) in [(&mut a_events, b_id), (&mut b_events, a_id)] {
        wait_event(events, "DirectUpgradeFailed", |e| {
            *e == NetEvent::DirectUpgradeFailed { peer_id: peer }
        })
        .await;
    }
    assert!(b.net.peer_info(a_id).await.unwrap().unwrap().relayed);
    let resp = within("hello again", b.net.request(a_id, &Request::hello()))
        .await
        .unwrap();
    assert_eq!(resp, Response::hello());
    stop(a).await;
    stop(b).await;
    hub.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relayed_connection_is_upgraded_to_a_direct_one_when_a_hole_can_be_punched() {
    let hub = Hub::start(100, HubOptions::default()).await;
    let seen = Seen::default();
    // A has a socket, but nobody confirms that it can be dialed (the hub does not dial
    // back), so A announces the relayed address only.
    let a = node(
        1,
        internet_config(&hub, Listen::Loopback),
        recording_handler(seen.clone()),
    );
    let b = node(
        2,
        internet_config(&hub, Listen::Loopback),
        Arc::new(HelloOnlyHandler),
    );
    let (a_id, b_id) = (a.net.local_peer_id(), b.net.local_peer_id());
    let mut a_events = a.net.subscribe();
    let mut b_events = b.net.subscribe();
    relay_addrs(&a.net).await;
    assert_eq!(status(&a.net).await.external_addrs, Vec::<Multiaddr>::new());

    let found = find(&b.net, a_id).await;
    assert_eq!(found, vec![hub.circuit(a_id)]);
    assert_eq!(within("dial", b.net.dial(found[0].clone())).await, Ok(a_id));

    // Both ends tell each other where the hub sees them and dial at the same time.
    for (events, peer) in [(&mut a_events, b_id), (&mut b_events, a_id)] {
        wait_event(events, "DirectUpgradeSucceeded", |e| {
            *e == NetEvent::DirectUpgradeSucceeded { peer_id: peer }
        })
        .await;
    }
    // The relayed connection goes; what is left is direct.
    let info = eventually("only the direct connection to be left", || async {
        let info = b.net.peer_info(a_id).await.unwrap()?;
        (!info.relayed).then_some(info)
    })
    .await;
    let direct = info.remote_addr.unwrap();
    assert!(!is_relayed(&direct));
    eventually("A to drop the relayed connection, too", || async {
        let info = a.net.peer_info(b_id).await.unwrap()?;
        (!info.relayed).then_some(())
    })
    .await;

    // An exchange far larger than a public relay would carry goes through, and A's
    // handler sees the same proven identity on the punched connection.
    seen.lock().unwrap().clear();
    let resp = within(
        "sync-sized request",
        b.net.request(a_id, &sync_sized_request()),
    )
    .await
    .unwrap();
    assert_eq!(resp, Response::error(ErrorCode::Unauthorized));
    let resp = within("hello", b.net.request(a_id, &Request::hello()))
        .await
        .unwrap();
    assert_eq!(resp, Response::hello());
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        for peer in seen.iter() {
            assert_eq!(peer.peer_id, b_id);
            assert_eq!(peer.device_key, device_key(2));
            assert!(!peer.relayed);
        }
    }
    // One circuit was used, to agree on the hole punch.
    assert_eq!(hub.state().circuits, vec![(b_id, a_id)]);
    stop(a).await;
    stop(b).await;
    hub.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_publicly_reachable_node_is_found_at_its_own_address() {
    let hub = Hub::start(
        100,
        HubOptions {
            autonat: true,
            ..HubOptions::default()
        },
    )
    .await;
    let seen = Seen::default();
    let a = node(
        1,
        internet_config(&hub, Listen::Loopback),
        recording_handler(seen.clone()),
    );
    let mut a_events = a.net.subscribe();
    let a_id = a.net.local_peer_id();
    let listen = within("listen addr", a.net.listen_addrs()).await.unwrap()[0].clone();
    // The hub sees A at its listen address and, asked to, dials it back on a new
    // connection: A is reachable, says so, and needs no relay.
    let s = eventually("A to learn that it is reachable", || async {
        let s = status(&a.net).await;
        (s.reachability == Reachability::Public && s.relay_addrs.is_empty()).then_some(s)
    })
    .await;
    let own = listen.clone().with(Protocol::P2p(a_id));
    assert_eq!(s.external_addrs, vec![own.clone()]);
    wait_event(&mut a_events, "ReachabilityChanged", |e| {
        *e == NetEvent::ReachabilityChanged {
            reachability: Reachability::Public,
        }
    })
    .await;

    let b = node(
        2,
        internet_config(&hub, Listen::Nowhere),
        Arc::new(HelloOnlyHandler),
    );
    let b_id = b.net.local_peer_id();
    let found = eventually("A's own address to be found", || async {
        let found = b.net.find_peer(a_id, Duration::from_secs(5)).await.unwrap();
        (found == vec![own.clone()]).then_some(found)
    })
    .await;
    assert_eq!(b.net.is_connected(a_id).await, Ok(false));
    assert_eq!(within("dial", b.net.dial(found[0].clone())).await, Ok(a_id));
    let resp = within("hello", b.net.request(a_id, &Request::hello()))
        .await
        .unwrap();
    assert_eq!(resp, Response::hello());
    let info = b.net.peer_info(a_id).await.unwrap().unwrap();
    assert!(!info.relayed);
    assert_eq!(info.device_key, device_key(1));
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].peer_id, b_id);
        assert_eq!(seen[0].device_key, device_key(2));
        assert!(!seen[0].relayed);
    }
    // No relay was involved at any point, and A takes no call through one any more: it
    // gave its reservation up when it learned that it is reachable.
    assert!(hub.state().circuits.is_empty());
    within("disconnect", b.net.disconnect(a_id)).await.unwrap();
    eventually("B to be disconnected", || async {
        (b.net.is_connected(a_id).await == Ok(false)).then_some(())
    })
    .await;
    assert_eq!(
        within("dial", b.net.dial(hub.circuit(a_id))).await,
        Err(NetError::Dial)
    );
    assert!(hub.state().circuits.is_empty());
    stop(a).await;
    stop(b).await;
    hub.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_peer_is_not_found_and_the_lookup_keeps_to_its_timeout() {
    let hub = Hub::start(100, HubOptions::default()).await;
    let b = node(
        2,
        internet_config(&hub, Listen::Loopback),
        Arc::new(HelloOnlyHandler),
    );
    let nobody = ph_network::peer_id_from_device_key(&device_key(77));
    let started = Instant::now();
    let found = b.net.find_peer(nobody, Duration::from_secs(3)).await;
    assert_eq!(found, Ok(Vec::new()));
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
    // A node that is offline is not found either, and asking for oneself asks nobody.
    let asked_before = hub.state().asked.len();
    assert_eq!(
        b.net
            .find_peer(b.net.local_peer_id(), Duration::from_secs(3))
            .await,
        Ok(Vec::new())
    );
    assert_eq!(hub.state().asked.len(), asked_before);
    stop(b).await;

    // With no DHT server to ask at all, a lookup returns empty when its time is up.
    let dead: Multiaddr = format!("/ip4/127.0.0.1/udp/9/quic-v1/p2p/{}", hub.peer_id)
        .parse()
        .unwrap();
    let alone = node(
        3,
        NetworkConfig {
            internet: Some(InternetConfig {
                bootstrap: vec![dead],
                max_relays: 2,
                allow_private_addresses: true,
            }),
            ..loopback_config()
        },
        Arc::new(HelloOnlyHandler),
    );
    let started = Instant::now();
    let found = alone.net.find_peer(nobody, Duration::from_secs(2)).await;
    assert_eq!(found, Ok(Vec::new()));
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
    let s = status(&alone.net).await;
    assert!(s.enabled && !s.bootstrapped);
    stop(alone).await;
    hub.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn addresses_from_a_lying_server_are_filtered_bounded_and_never_dialed() {
    let hub = Hub::start(100, HubOptions::default()).await;
    let b = node(
        2,
        internet_config(&hub, Listen::Loopback),
        Arc::new(HelloOnlyHandler),
    );
    let victim = ph_network::peer_id_from_device_key(&device_key(50));
    let other = ph_network::peer_id_from_device_key(&device_key(51));
    // Something that listens and is not the victim.
    let decoy = node(3, loopback_config(), Arc::new(HelloOnlyHandler));
    let decoy_addr = within("listen addr", decoy.net.listen_addrs())
        .await
        .unwrap()[0]
        .clone();

    let mut lies: Vec<Multiaddr> = vec![
        // Not this transport.
        "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
        "/dns4/example.org/udp/4001/quic-v1".parse().unwrap(),
        "/ip4/127.0.0.1/udp/4001/quic-v1/webtransport"
            .parse()
            .unwrap(),
        // Another peer's address, and a relay that is not reached over QUIC.
        format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{other}")
            .parse()
            .unwrap(),
        format!("/ip4/127.0.0.1/tcp/4001/p2p/{other}/p2p-circuit")
            .parse()
            .unwrap(),
        "/ip4/0.0.0.0/udp/4001/quic-v1".parse().unwrap(),
        // The decoy's real address, claimed to be the victim's.
        decoy_addr.clone(),
    ];
    // And far more addresses than anyone has.
    lies.extend((1..=100u16).map(|port| {
        format!("/ip4/127.0.0.1/udp/{}/quic-v1", 20_000 + port)
            .parse::<Multiaddr>()
            .unwrap()
    }));
    hub.state().lies.insert(victim, lies);

    let found = find(&b.net, victim).await;
    assert_eq!(found.len(), internet::MAX_FOUND_ADDRS);
    for addr in &found {
        assert_eq!(peer_id_of_addr(addr), Some(victim), "{addr}");
        let text = addr.to_string();
        assert!(
            text.starts_with("/ip4/127.0.0.1/udp/") && text.contains("/quic-v1/p2p/"),
            "{addr}"
        );
    }
    // Newest first: the last addresses the server named.
    assert_eq!(
        found[0],
        format!("/ip4/127.0.0.1/udp/20100/quic-v1/p2p/{victim}")
            .parse::<Multiaddr>()
            .unwrap()
    );
    // Nothing was dialed: B is connected to the hub and to nobody else, and the decoy
    // was not contacted.
    let b_peers: Vec<PeerId> = b
        .net
        .connected_peers()
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.peer_id)
        .collect();
    assert_eq!(b_peers, vec![hub.peer_id]);
    assert_eq!(decoy.net.connected_peers().await.unwrap(), vec![]);

    // Dialing the decoy's address as the victim's fails in the handshake: whoever
    // answers there cannot prove the victim's key.
    let claimed = decoy_addr.with(Protocol::P2p(victim));
    assert_eq!(
        within("dial", b.net.dial(claimed)).await,
        Err(NetError::Dial)
    );
    assert_eq!(b.net.is_connected(victim).await, Ok(false));
    // The same through a relay: a relayed address whose relay is not who it says.
    let wrong_relay: Multiaddr = format!(
        "{}/p2p/{other}/p2p-circuit/p2p/{victim}",
        ph_network::without_p2p(&hub.addr)
    )
    .parse()
    .unwrap();
    assert_eq!(
        within("dial", b.net.dial(wrong_relay)).await,
        Err(NetError::Dial)
    );
    // And a relayed address for a peer that has no reservation at the relay.
    assert_eq!(
        within("dial", b.net.dial(hub.circuit(victim))).await,
        Err(NetError::Dial)
    );
    stop(b).await;
    stop(decoy).await;
    hub.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limits_apply_to_a_relayed_peer_like_to_any_other() {
    let hub = Hub::start(100, HubOptions::default()).await;
    let seen = Seen::default();
    let a_config = NetworkConfig {
        rate_limits: RateLimits {
            requests_per_sec: 1,
            burst: 3,
            ..RateLimits::default()
        },
        ..internet_config(&hub, Listen::Nowhere)
    };
    let a = node(1, a_config, recording_handler(seen.clone()));
    let b = node(
        2,
        internet_config(&hub, Listen::Loopback),
        Arc::new(HelloOnlyHandler),
    );
    let a_id = a.net.local_peer_id();
    relay_addrs(&a.net).await;
    let found = find(&b.net, a_id).await;
    assert_eq!(within("dial", b.net.dial(found[0].clone())).await, Ok(a_id));
    assert!(b.net.peer_info(a_id).await.unwrap().unwrap().relayed);

    let mut answers = Vec::new();
    for _ in 0..8 {
        answers.push(
            within("hello", b.net.request(a_id, &Request::hello()))
                .await
                .unwrap(),
        );
    }
    let limited = answers
        .iter()
        .filter(|r| **r == Response::error(ErrorCode::RateLimited))
        .count();
    let served = answers.iter().filter(|r| **r == Response::hello()).count();
    assert_eq!(limited + served, 8);
    assert!((3..=5).contains(&served), "{served} served");
    // The handler saw the requests that were let through and no others.
    assert_eq!(seen.lock().unwrap().len(), served);
    stop(a).await;
    stop(b).await;
    hub.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_connection_limit_per_peer_holds_across_relayed_and_direct_connections() {
    let hub = Hub::start(100, HubOptions::default()).await;
    // A takes one connection per peer. B reaches it through the relay; the direct
    // connection that the hole punch would add is one too many and is refused.
    let a_config = NetworkConfig {
        max_connections_per_peer: 1,
        ..internet_config(&hub, Listen::Loopback)
    };
    let a = node(1, a_config, Arc::new(HelloOnlyHandler));
    let b = node(
        2,
        internet_config(&hub, Listen::Loopback),
        Arc::new(HelloOnlyHandler),
    );
    let (a_id, b_id) = (a.net.local_peer_id(), b.net.local_peer_id());
    let mut a_events = a.net.subscribe();
    relay_addrs(&a.net).await;
    let found = find(&b.net, a_id).await;
    assert_eq!(within("dial", b.net.dial(found[0].clone())).await, Ok(a_id));
    wait_event(&mut a_events, "DirectUpgradeFailed on A", |e| {
        *e == NetEvent::DirectUpgradeFailed { peer_id: b_id }
    })
    .await;
    let info = a.net.peer_info(b_id).await.unwrap().unwrap();
    assert!(info.relayed);
    // B was never told of an upgrade: a direct connection that the other side closes
    // right after the handshake does not count as one.
    let mut b_events = b.net.subscribe();
    // A request that B sent on a refused connection before it saw it closing is lost;
    // the relayed connection is still there for the next one.
    eventually("hello over the relayed connection", || async {
        (b.net.request(a_id, &Request::hello()).await == Ok(Response::hello())).then_some(())
    })
    .await;
    eventually("B to be left with the relayed connection", || async {
        b.net.peer_info(a_id).await.unwrap()?.relayed.then_some(())
    })
    .await;
    while let Ok(event) = b_events.try_recv() {
        assert!(
            !matches!(event, NetEvent::DirectUpgradeSucceeded { .. }),
            "{event:?}"
        );
    }
    stop(a).await;
    stop(b).await;
    hub.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exchange_larger_than_the_relay_carries_fails_and_says_so() {
    // The limit of the public network's relays: 128 KiB per circuit.
    let hub = Hub::start(
        100,
        HubOptions {
            max_circuit_bytes: 128 * 1024,
            ..HubOptions::default()
        },
    )
    .await;
    let seen = Seen::default();
    // No socket on A: there will be no direct connection to fall back on.
    let a = node(
        1,
        internet_config(&hub, Listen::Nowhere),
        recording_handler(seen.clone()),
    );
    let b = node(
        2,
        internet_config(&hub, Listen::Loopback),
        Arc::new(HelloOnlyHandler),
    );
    let a_id = a.net.local_peer_id();
    let mut b_events = b.net.subscribe();
    relay_addrs(&a.net).await;
    let found = find(&b.net, a_id).await;
    assert_eq!(within("dial", b.net.dial(found[0].clone())).await, Ok(a_id));
    let resp = within("hello", b.net.request(a_id, &Request::hello()))
        .await
        .unwrap();
    assert_eq!(resp, Response::hello());
    wait_event(&mut b_events, "DirectUpgradeFailed", |e| {
        *e == NetEvent::DirectUpgradeFailed { peer_id: a_id }
    })
    .await;

    // A sync-sized request does not fit through the relay. The relay cuts the circuit,
    // and the caller gets an error, not a truncated or a made-up answer.
    let result = within(
        "sync-sized request",
        b.net.request(a_id, &sync_sized_request()),
    )
    .await;
    assert!(
        matches!(
            result,
            Err(NetError::ConnectionClosed | NetError::Codec | NetError::Timeout)
        ),
        "{result:?}"
    );
    wait_event(&mut b_events, "Disconnected", |e| {
        *e == NetEvent::Disconnected { peer_id: a_id }
    })
    .await;
    // A's handler never saw the request: it did not arrive whole.
    assert_eq!(seen.lock().unwrap().len(), 1);
    // The peer can be dialed again; small exchanges still work.
    assert_eq!(within("dial", b.net.dial(found[0].clone())).await, Ok(a_id));
    let resp = within("hello", b.net.request(a_id, &Request::hello()))
        .await
        .unwrap();
    assert_eq!(resp, Response::hello());
    stop(a).await;
    stop(b).await;
    hub.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_ends_the_reservation_the_lookups_and_every_connection() {
    // The hub runs on a runtime of its own: every task here belongs to a node.
    let tasks = || {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    };
    assert_eq!(tasks(), 0);
    let hub = Hub::start(100, HubOptions::default()).await;
    let a = node(
        1,
        internet_config(&hub, Listen::Loopback),
        Arc::new(HelloOnlyHandler),
    );
    let b = node(
        2,
        internet_config(&hub, Listen::Loopback),
        Arc::new(HelloOnlyHandler),
    );
    let a_id = a.net.local_peer_id();
    let listen = within("listen addr", a.net.listen_addrs()).await.unwrap()[0].clone();
    let relayed = relay_addrs(&a.net).await;
    assert!(hub.state().reservations.contains(&a_id));
    assert_eq!(find(&b.net, a_id).await, relayed);

    // A lookup that is in flight when the node stops is answered, not left hanging.
    let nobody = ph_network::peer_id_from_device_key(&device_key(77));
    let handle = a.net.clone();
    let pending =
        tokio::spawn(async move { handle.find_peer(nobody, Duration::from_secs(20)).await });
    let handle = a.net.clone();
    within("shutdown", a.net.shutdown()).await;
    within("join", a.join).await.expect("event loop task");
    let answered = within("the pending lookup", pending).await.unwrap();
    assert!(
        matches!(answered, Ok(ref found) if found.is_empty())
            || answered == Err(NetError::Shutdown),
        "{answered:?}"
    );
    assert_eq!(
        handle.find_peer(nobody, Duration::from_secs(1)).await,
        Err(NetError::Shutdown)
    );
    assert_eq!(handle.internet_status().await, Err(NetError::Shutdown));

    // The hub lost the connection, and with it the reservation.
    eventually("the hub to see A gone", || async {
        let state = hub.state();
        (!state.connected.contains(&a_id) && !state.reservations.contains(&a_id)).then_some(())
    })
    .await;
    // A is no longer named, cannot be reached through the relay, and its socket is
    // free again.
    assert_eq!(
        b.net.find_peer(a_id, Duration::from_secs(2)).await,
        Ok(Vec::new())
    );
    assert_eq!(
        within("dial", b.net.dial(relayed[0].clone())).await,
        Err(NetError::Dial)
    );
    // (The socket is closed by the QUIC endpoint's own task a moment after the event
    // loop has ended, with the mode as without it.)
    let again = eventually("A's socket to be free", || async {
        let config = NetworkConfig::listening_on([listen.clone()]);
        let (net, join) = start(seed(1), config, Arc::new(HelloOnlyHandler)).ok()?;
        Some(Node { net, join })
    })
    .await;
    assert_eq!(
        within("listen addr", again.net.listen_addrs())
            .await
            .unwrap(),
        vec![listen]
    );
    stop(again).await;
    stop(b).await;
    // No task of any of the nodes is left: not the event loops, not a connection, not a
    // timer, not the QUIC endpoints.
    eventually("every task to end", || async {
        (tasks() == 0).then_some(())
    })
    .await;
    hub.stop().await;
}

// ---------------------------------------------------------------------------------
// The public network. These tests use the internet.
// ---------------------------------------------------------------------------------

/// A seed that no other node has, and in practice no other run either: these nodes
/// show up on a real network.
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

/// Prints what `ph_network` logs (peer ids and counts) when `PH_TEST_LOG` is set.
struct PrintLogs(Instant);

impl tracing::Subscriber for PrintLogs {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target().starts_with("ph_network")
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
        eprintln!(
            "[{:8.2}] {:5}{}",
            self.0.elapsed().as_secs_f64(),
            event.metadata().level(),
            fields.0
        );
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

fn print_logs_if_asked() {
    if std::env::var_os("PH_TEST_LOG").is_some() {
        let _ = tracing::dispatcher::set_global_default(tracing::Dispatch::new(PrintLogs(
            Instant::now(),
        )));
    }
}

/// A node on the public network: default bootstrap peers, listening on every interface
/// (IPv4 and, where the machine has it, IPv6).
fn public_node(handler: Arc<dyn ph_network::RequestHandler>) -> Node {
    let config = NetworkConfig {
        internet: Some(InternetConfig::default()),
        ..NetworkConfig::listening_on([
            "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap(),
            "/ip6/::/udp/0/quic-v1".parse().unwrap(),
        ])
    };
    let (net, join) = start(fresh_seed(), config, handler).expect("start network");
    Node { net, join }
}

/// Polls `check` until it returns `Some`, for at most `limit`. Returns the value and
/// how long it took, or `None`.
async fn timed<T, F, Fut>(limit: Duration, mut check: F) -> Option<(T, Duration)>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let started = Instant::now();
    while started.elapsed() < limit {
        if let Some(v) = check().await {
            return Some((v, started.elapsed()));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

/// Two nodes of this machine join the public libp2p network with throwaway keys. One
/// is then found by the other from its peer id alone, dialed at what was found, and
/// greeted. Prints what was measured.
///
/// Both nodes sit behind the same NAT here, so a hole punch that succeeds in this test
/// says little about two different NATs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the public libp2p network"]
async fn public_network_a_node_is_found_by_its_peer_id_and_greeted() {
    print_logs_if_asked();
    let seen = Seen::default();
    let a = public_node(recording_handler(seen.clone()));
    let a_id = a.net.local_peer_id();
    let mut a_events = a.net.subscribe();
    let started = Instant::now();

    let (_, joined) = timed(Duration::from_secs(90), || async {
        status(&a.net).await.bootstrapped.then_some(())
    })
    .await
    .expect("A joins the public network");
    println!("A joined the public network after {joined:.1?}");
    let reachable = timed(Duration::from_secs(60), || async {
        let s = status(&a.net).await;
        (!s.relay_addrs.is_empty() || !s.external_addrs.is_empty()).then_some(s)
    })
    .await;
    let (s, _) = reachable.expect("A gets an address others can use");
    println!(
        "A after {:.1?}: reachability {}, {} direct address(es), {} relay reservation(s), {} DHT servers in the routing table",
        started.elapsed(),
        s.reachability.as_str(),
        s.external_addrs.len(),
        s.relay_addrs.len(),
        s.routing_peers
    );

    let b = public_node(Arc::new(HelloOnlyHandler));
    let mut b_events = b.net.subscribe();
    let b_started = Instant::now();
    let (found, findable) = timed(Duration::from_secs(120), || async {
        let found = b
            .net
            .find_peer(a_id, Duration::from_secs(20))
            .await
            .expect("lookup");
        (!found.is_empty()).then_some(found)
    })
    .await
    .expect("B finds A by its peer id");
    let relayed = found.iter().filter(|a| is_relayed(a)).count();
    println!(
        "B found A {findable:.1?} after B started ({:.1?} after A started): {} address(es), {relayed} relayed",
        started.elapsed(),
        found.len()
    );
    assert!(found.iter().all(|addr| peer_id_of_addr(addr) == Some(a_id)));
    assert_eq!(b.net.is_connected(a_id).await, Ok(false));

    let mut dialed = None;
    for addr in &found {
        let t = Instant::now();
        if b.net.dial(addr.clone()).await == Ok(a_id) {
            dialed = Some((is_relayed(addr), t.elapsed()));
            break;
        }
    }
    let (via_relay, dial_time) = dialed.expect("one of the found addresses connects");
    println!(
        "B connected to A in {dial_time:.1?} ({})",
        if via_relay {
            "through a relay"
        } else {
            "directly"
        }
    );
    let t = Instant::now();
    let resp = b.net.request(a_id, &Request::hello()).await.expect("hello");
    assert_eq!(resp, Response::hello());
    println!(
        "hello answered in {:.1?}, {:.1?} after B started",
        t.elapsed(),
        b_started.elapsed()
    );
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].peer_id, b.net.local_peer_id());
        assert_eq!(
            device_key_from_peer_id(&seen[0].peer_id),
            Some(seen[0].device_key)
        );
        assert_eq!(seen[0].relayed, via_relay);
    }

    if via_relay {
        // Was the connection upgraded?
        let upgrade = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                tokio::select! {
                    e = a_events.recv() => match e {
                        Ok(NetEvent::DirectUpgradeSucceeded { .. }) => return true,
                        Ok(NetEvent::DirectUpgradeFailed { .. }) => return false,
                        _ => {}
                    },
                    e = b_events.recv() => match e {
                        Ok(NetEvent::DirectUpgradeSucceeded { .. }) => return true,
                        Ok(NetEvent::DirectUpgradeFailed { .. }) => return false,
                        _ => {}
                    },
                }
            }
        })
        .await;
        match upgrade {
            Ok(true) => println!("the relayed connection was upgraded to a direct one"),
            Ok(false) => println!("the hole punch failed: the connection stays relayed"),
            Err(_) => println!("no upgrade within 30 s: the connection stays relayed"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        let still_relayed = b
            .net
            .peer_info(a_id)
            .await
            .unwrap()
            .is_none_or(|info| info.relayed);
        // What a sync-sized exchange does on whatever connection there is now.
        let t = Instant::now();
        let result = b.net.request(a_id, &sync_sized_request()).await;
        println!(
            "a sync-sized request (about 300 KiB) over the {} connection: {} after {:.1?}",
            if still_relayed { "relayed" } else { "direct" },
            match &result {
                Ok(_) => "answered".to_owned(),
                Err(e) => format!("failed ({e})"),
            },
            t.elapsed()
        );
        if !still_relayed {
            assert_eq!(result, Ok(Response::error(ErrorCode::Unauthorized)));
        }
    }
    stop(a).await;
    stop(b).await;
}

/// How long a node stays findable after it stopped refreshing, which is what the
/// refresh interval has to stay below. Runs for up to 45 minutes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the public libp2p network and up to 45 minutes"]
async fn public_network_how_long_a_stopped_node_stays_findable() {
    print_logs_if_asked();
    let a = public_node(Arc::new(HelloOnlyHandler));
    let a_id = a.net.local_peer_id();
    timed(Duration::from_secs(120), || async {
        let s = status(&a.net).await;
        (s.bootstrapped && !s.relay_addrs.is_empty()).then_some(())
    })
    .await
    .expect("A joins and gets a relay");
    let b = public_node(Arc::new(HelloOnlyHandler));
    timed(Duration::from_secs(120), || async {
        let found = b.net.find_peer(a_id, Duration::from_secs(20)).await.ok()?;
        (!found.is_empty()).then_some(())
    })
    .await
    .expect("B finds A");
    stop(a).await;
    let stopped = Instant::now();
    println!("A stopped; B keeps looking it up");
    let mut last_found = Duration::ZERO;
    while stopped.elapsed() < Duration::from_secs(45 * 60) {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let found = b
            .net
            .find_peer(a_id, Duration::from_secs(25))
            .await
            .unwrap_or_default();
        println!(
            "{:>5.0?} after A stopped: {} address(es)",
            stopped.elapsed(),
            found.len()
        );
        if found.is_empty() {
            break;
        }
        last_found = stopped.elapsed();
    }
    println!("A was last found {last_found:.0?} after it stopped");
    stop(b).await;
}
