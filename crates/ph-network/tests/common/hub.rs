//! A private miniature of the public libp2p network, for tests of the internet mode.
//!
//! The **hub** is bootstrap peer, DHT server, relay and (when asked) AutoNAT server in
//! one. It is test-only code built from libp2p directly: PeerHarness never ships a DHT
//! server or a relay. It answers like the servers of the public network do
//! (go-libp2p): a `FIND_NODE` for a peer id is answered with the addresses that peer
//! reported over identify while it is connected, and with nothing otherwise.
//!
//! Included by the test files that need it with
//! `#[path = "common/hub.rs"] mod hub;` next to `mod common;`.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use ph_network::libp2p::multiaddr::Protocol;
use ph_network::libp2p::request_response::{self, ProtocolSupport};
use ph_network::libp2p::swarm::behaviour::toggle::Toggle;
use ph_network::libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use ph_network::libp2p::{autonat, identify, relay, StreamProtocol, Swarm, SwarmBuilder};
use ph_network::{
    handler_fn, keypair_from_seed, InternetConfig, InternetStatus, Multiaddr, NetworkConfig,
    NetworkHandle, PeerId, PeerInfo,
};
use ph_protocol::wire::{ErrorCode, Request, Response};
use tokio::sync::oneshot;

use crate::common::*;

pub const KAD: StreamProtocol = StreamProtocol::new("/ipfs/kad/1.0.0");

// ---------------------------------------------------------------------------------
// The hub: a stand-in for the servers of the public network.
// ---------------------------------------------------------------------------------

/// The DHT wire format, as far as the hub needs it: a `FIND_NODE` request is read for
/// its key, and answered with a list of peers and their addresses.
///
/// ```text
/// message Message { MessageType type = 1; bytes key = 2; repeated Peer closerPeers = 8; }
/// message Peer    { bytes id = 1; repeated bytes addrs = 2; ConnectionType connection = 3; }
/// ```
///
/// Each message is prefixed with its length as an unsigned varint.
#[derive(Clone, Default)]
pub struct FindNodeCodec;

pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

pub fn put_bytes(out: &mut Vec<u8>, field: u64, bytes: &[u8]) {
    put_varint(out, (field << 3) | 2);
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

pub fn take_varint(buf: &mut &[u8]) -> io::Result<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = buf
            .split_first()
            .ok_or_else(|| io::Error::other("short varint"))?;
        *buf = rest;
        v |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(io::Error::other("long varint"))
}

/// The `key` of a DHT request message.
pub fn key_of(mut msg: &[u8]) -> io::Result<Vec<u8>> {
    let mut key = Vec::new();
    while !msg.is_empty() {
        let tag = take_varint(&mut msg)?;
        match tag & 7 {
            0 => {
                take_varint(&mut msg)?;
            }
            2 => {
                let len = take_varint(&mut msg)? as usize;
                if len > msg.len() {
                    return Err(io::Error::other("short field"));
                }
                let (bytes, rest) = msg.split_at(len);
                msg = rest;
                if tag >> 3 == 2 {
                    key = bytes.to_vec();
                }
            }
            _ => return Err(io::Error::other("unexpected wire type")),
        }
    }
    Ok(key)
}

pub fn find_node_response(peers: &[(PeerId, Vec<Multiaddr>)]) -> Vec<u8> {
    let mut msg = Vec::new();
    // type = FIND_NODE
    put_varint(&mut msg, 1 << 3);
    put_varint(&mut msg, 4);
    for (peer, addrs) in peers {
        let mut p = Vec::new();
        put_bytes(&mut p, 1, &peer.to_bytes());
        for addr in addrs {
            put_bytes(&mut p, 2, &addr.to_vec());
        }
        // connection = CONNECTED
        put_varint(&mut p, 3 << 3);
        put_varint(&mut p, 1);
        put_bytes(&mut msg, 8, &p);
    }
    let mut framed = Vec::new();
    put_varint(&mut framed, msg.len() as u64);
    framed.extend_from_slice(&msg);
    framed
}

impl request_response::Codec for FindNodeCodec {
    type Protocol = StreamProtocol;
    /// The key that is asked for.
    type Request = Vec<u8>;
    /// The peers to name.
    type Response = Vec<(PeerId, Vec<Multiaddr>)>;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Vec<u8>>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        let mut len = 0u64;
        for shift in (0..35).step_by(7) {
            let mut byte = [0u8; 1];
            io.read_exact(&mut byte).await?;
            len |= u64::from(byte[0] & 0x7f) << shift;
            if byte[0] & 0x80 == 0 {
                break;
            }
        }
        if len > 16 * 1024 {
            return Err(io::Error::other("request too large"));
        }
        let mut msg = vec![0u8; len as usize];
        io.read_exact(&mut msg).await?;
        key_of(&msg)
    }

    async fn read_response<T>(
        &mut self,
        _: &StreamProtocol,
        _: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        Err(io::Error::other("the hub asks nothing"))
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        _: &mut T,
        _: Vec<u8>,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        Err(io::Error::other("the hub asks nothing"))
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        peers: Self::Response,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        io.write_all(&find_node_response(&peers)).await?;
        io.close().await
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(prelude = "ph_network::libp2p::swarm::derive_prelude")]
pub struct HubBehaviour {
    dht: request_response::Behaviour<FindNodeCodec>,
    identify: identify::Behaviour,
    relay: relay::Behaviour,
    autonat: Toggle<autonat::v2::server::Behaviour>,
}

/// What a hub is asked to be.
#[derive(Clone, Copy, Default)]
pub struct HubOptions {
    /// Dial clients back when they ask whether an address of theirs is reachable.
    pub autonat: bool,
    /// The most bytes a relayed connection may carry (0: no limit).
    pub max_circuit_bytes: u64,
}

/// What a hub saw and what it is told to say.
#[derive(Default)]
pub struct HubState {
    /// Connected peers and the addresses they reported over identify.
    pub known: HashMap<PeerId, Vec<Multiaddr>>,
    pub connected: HashSet<PeerId>,
    /// Peers holding a reservation.
    pub reservations: HashSet<PeerId>,
    /// Circuits that were opened: who called whom.
    pub circuits: Vec<(PeerId, PeerId)>,
    /// `FIND_NODE` requests: who asked for which key.
    pub asked: Vec<(PeerId, Vec<u8>)>,
    /// Identify records received: agent string, protocol-family string, addresses.
    pub identified: HashMap<PeerId, (String, String, Vec<Multiaddr>)>,
    /// Addresses the hub gives for a peer instead of what it knows: a lying server.
    pub lies: HashMap<PeerId, Vec<Multiaddr>>,
}

pub struct Hub {
    pub peer_id: PeerId,
    /// The address of the hub, ending in its peer id.
    pub addr: Multiaddr,
    pub state: Arc<Mutex<HubState>>,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Hub {
    /// Starts a hub with the identity of `seed(n)`.
    ///
    /// It runs on a thread and a runtime of its own, with its log output discarded, so
    /// that the tasks and the log output a test sees are those of the nodes it tests.
    pub async fn start(n: u8, options: HubOptions) -> Hub {
        let state = Arc::new(Mutex::new(HubState::default()));
        let shared = state.clone();
        let (ready, started) = oneshot::channel();
        let (stop, stopped) = oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("test-hub".to_owned())
            .spawn(move || {
                let _quiet = tracing::dispatcher::set_default(&tracing::Dispatch::none());
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("hub runtime");
                runtime.block_on(run_hub(n, options, shared, ready, stopped));
            })
            .expect("hub thread");
        let (peer_id, addr) = within("the hub to listen", started)
            .await
            .expect("hub started");
        Hub {
            peer_id,
            addr,
            state,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    pub fn state(&self) -> std::sync::MutexGuard<'_, HubState> {
        self.state.lock().unwrap()
    }

    /// The relayed address of `peer` through this hub.
    pub fn circuit(&self, peer: PeerId) -> Multiaddr {
        self.addr
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(peer))
    }

    /// Stops the hub and waits until its thread, and with it every task and socket of
    /// it, is gone.
    pub async fn stop(mut self) {
        self.end();
    }

    fn end(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        self.end();
    }
}

/// The hub itself: builds the swarm, reports where it listens, and serves until told to
/// stop.
async fn run_hub(
    n: u8,
    options: HubOptions,
    state: Arc<Mutex<HubState>>,
    ready: oneshot::Sender<(PeerId, Multiaddr)>,
    mut stopped: oneshot::Receiver<()>,
) {
    let keypair = keypair_from_seed(&seed(n)).unwrap();
    let peer_id = keypair.public().to_peer_id();
    let mut swarm: Swarm<HubBehaviour> = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic()
        .with_behaviour(|key| {
            let mut relay_config = relay::Config {
                max_circuit_bytes: options.max_circuit_bytes,
                ..relay::Config::default()
            };
            // Every node of a test comes from 127.0.0.1.
            relay_config.reservation_rate_limiters.clear();
            relay_config.circuit_src_rate_limiters.clear();
            HubBehaviour {
                dht: request_response::Behaviour::with_codec(
                    FindNodeCodec,
                    [(KAD, ProtocolSupport::Inbound)],
                    request_response::Config::default(),
                ),
                identify: identify::Behaviour::new(identify::Config::new(
                    "ipfs/0.1.0".to_owned(),
                    key.public(),
                )),
                relay: relay::Behaviour::new(key.public().to_peer_id(), relay_config),
                autonat: Toggle::from(
                    options
                        .autonat
                        .then(autonat::v2::server::Behaviour::default),
                ),
            }
        })
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    swarm
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
        .unwrap();
    let listen = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            break address;
        }
    };
    // The relay offers its service once it has an address others can reach.
    swarm.add_external_address(listen.clone());
    let _ = ready.send((peer_id, listen.with(Protocol::P2p(peer_id))));
    loop {
        tokio::select! {
            _ = &mut stopped => return,
            event = swarm.select_next_some() => hub_event(&mut swarm, &state, event),
        }
    }
}

fn hub_event(
    swarm: &mut Swarm<HubBehaviour>,
    state: &Arc<Mutex<HubState>>,
    event: SwarmEvent<HubBehaviourEvent>,
) {
    let mut state = state.lock().unwrap();
    match event {
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            state.connected.insert(peer_id);
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            num_established: 0,
            ..
        } => {
            // go-libp2p remembers a peer's addresses for some minutes after it left;
            // the hub forgets at once, so that a test can tell.
            state.connected.remove(&peer_id);
            state.known.remove(&peer_id);
            state.reservations.remove(&peer_id);
        }
        SwarmEvent::Behaviour(HubBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            state.known.insert(peer_id, info.listen_addrs.clone());
            state.identified.insert(
                peer_id,
                (info.agent_version, info.protocol_version, info.listen_addrs),
            );
        }
        SwarmEvent::Behaviour(HubBehaviourEvent::Dht(request_response::Event::Message {
            peer,
            message:
                request_response::Message::Request {
                    request, channel, ..
                },
            ..
        })) => {
            // Like go-libp2p: name the peer that is asked for, if it is (here: still)
            // connected and its addresses are known, and never the one who asks. There
            // are no other DHT servers to name.
            let target = PeerId::from_bytes(&request).ok().filter(|t| *t != peer);
            let named = target
                .and_then(|t| {
                    let addrs = state.lies.get(&t).or_else(|| state.known.get(&t))?;
                    (!addrs.is_empty()).then(|| vec![(t, addrs.clone())])
                })
                .unwrap_or_default();
            state.asked.push((peer, request));
            let _ = swarm.behaviour_mut().dht.send_response(channel, named);
        }
        SwarmEvent::Behaviour(HubBehaviourEvent::Relay(event)) => match event {
            relay::Event::ReservationReqAccepted { src_peer_id, .. } => {
                state.reservations.insert(src_peer_id);
            }
            relay::Event::ReservationClosed { src_peer_id }
            | relay::Event::ReservationTimedOut { src_peer_id } => {
                state.reservations.remove(&src_peer_id);
            }
            relay::Event::CircuitReqAccepted {
                src_peer_id,
                dst_peer_id,
            } => state.circuits.push((src_peer_id, dst_peer_id)),
            _ => {}
        },
        _ => {}
    }
}

// ---------------------------------------------------------------------------------
// PeerHarness nodes in internet mode.
// ---------------------------------------------------------------------------------

/// Where a node listens.
#[derive(Clone, Copy, PartialEq)]
pub enum Listen {
    Loopback,
    /// Not at all: it can only be reached through a relay.
    Nowhere,
}

pub fn internet_config(hub: &Hub, listen: Listen) -> NetworkConfig {
    let listen_addrs = match listen {
        Listen::Loopback => vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        Listen::Nowhere => Vec::new(),
    };
    NetworkConfig {
        internet: Some(InternetConfig {
            bootstrap: vec![hub.addr.clone()],
            max_relays: 2,
            allow_private_addresses: true,
        }),
        ..NetworkConfig::listening_on(listen_addrs)
    }
}

pub type Seen = Arc<Mutex<Vec<PeerInfo>>>;

/// Answers like a node without circles (`hello` and nothing else) and keeps who asked.
pub fn recording_handler(seen: Seen) -> Arc<dyn ph_network::RequestHandler> {
    handler_fn(move |peer: PeerInfo, req: Request| {
        let seen = seen.clone();
        async move {
            seen.lock().unwrap().push(peer);
            match req {
                Request::Hello { .. } => Response::hello(),
                _ => Response::error(ErrorCode::Unauthorized),
            }
        }
    })
}

/// Polls `check` until it returns `Some`, for at most [`SOON`].
pub async fn eventually<T, F, Fut>(what: &str, mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    within(what, async {
        loop {
            if let Some(v) = check().await {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
}

pub async fn status(net: &NetworkHandle) -> InternetStatus {
    within("internet_status", net.internet_status())
        .await
        .expect("network running")
}

/// Waits until `net` holds a relay reservation and returns its relayed addresses.
pub async fn relay_addrs(net: &NetworkHandle) -> Vec<Multiaddr> {
    eventually("a relay reservation", || async {
        let s = status(net).await;
        (!s.relay_addrs.is_empty()).then_some(s.relay_addrs)
    })
    .await
}

/// Looks `peer` up until an address is found, for at most [`SOON`].
pub async fn find(net: &NetworkHandle, peer: PeerId) -> Vec<Multiaddr> {
    eventually("the peer to be found", || async {
        let found = net
            .find_peer(peer, Duration::from_secs(5))
            .await
            .expect("lookup");
        (!found.is_empty()).then_some(found)
    })
    .await
}

pub fn fetch_bundle() -> Request {
    Request::FetchBundle {
        circle_id: ph_core::CircleId::derive(&device_key(9)),
        digest: ph_core::Digest::sha256(b"x"),
    }
}

/// A valid request of some hundred KiB: what a sync of a circle with history sends.
pub fn sync_sized_request() -> Request {
    let known: Vec<ph_core::EventId> = (0..4096u32)
        .map(|i| ph_core::EventId::from_digest(ph_core::Digest::sha256(&i.to_be_bytes())))
        .collect();
    let request = Request::FetchEvents {
        circle_id: ph_core::CircleId::derive(&device_key(9)),
        known,
        limit: 1,
        after: None,
    };
    let size = request.to_bytes().expect("encodes").len();
    assert!(size > 256 * 1024, "{size} bytes");
    request
}
