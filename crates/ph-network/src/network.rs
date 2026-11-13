//! The swarm event loop and the async [`NetworkHandle`].

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{FutureExt, StreamExt};
use libp2p::core::transport::ListenerId;
use libp2p::core::ConnectedPoint;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{
    self, InboundRequestId, Message, OutboundFailure, OutboundRequestId, ProtocolSupport,
    ResponseChannel,
};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::{ConnectionId, SwarmEvent};
use libp2p::{Multiaddr, PeerId, Swarm, SwarmBuilder};
use ph_core::DeviceKey;
use ph_protocol::wire::{ErrorCode, Request, Response};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tracing::instrument::WithSubscriber;
use zeroize::Zeroizing;

use crate::codec::{encode_response, PhCodec, RequestFrame, ResponseFrame, PROTOCOL};
use crate::config::NetworkConfig;
use crate::discovery::{Discovery, DiscoveryEvent};
use crate::error::NetError;
use crate::handler::{PeerInfo, RequestHandler};
use crate::identity::{
    device_key_from_peer_id, device_key_of_keypair, keypair_from_seed, peer_id_of_addr,
};
use crate::internet::{self, Internet, InternetEvent, InternetStatus, Reachability};
use crate::limiter::{Limited, PeerLimiter};
use crate::policy::PeerPolicy;

/// Commands queued from handles to the event loop.
const COMMAND_BUFFER: usize = 256;
/// How often idle per-peer limiter state is pruned.
const PRUNE_INTERVAL: Duration = Duration::from_secs(30);
/// Limiter state of a disconnected peer is kept at least this long (so reconnecting
/// does not reset a peer's budget).
const LIMITER_IDLE: Duration = Duration::from_secs(60);
/// Time allowed for connections to close cleanly on shutdown.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
/// Extra slack on handle-side waits beyond the libp2p-enforced timeouts.
const HANDLE_SLACK: Duration = Duration::from_secs(10);
/// Internet mode: how long a direct connection next to a relayed one has to last before
/// it counts as the upgrade. A peer that refuses the second connection (its limit of
/// connections per peer) closes it right after the handshake.
const UPGRADE_SETTLE: Duration = Duration::from_secs(1);
/// Internet mode: how long a relayed connection may stay open for requests in flight
/// once a direct connection to the same peer exists.
const RELAYED_GRACE: Duration = Duration::from_secs(10);
/// Internet mode: how often upgrades are looked at.
const UPGRADE_TICK: Duration = Duration::from_millis(250);

/// Events broadcast to [`NetworkHandle::subscribe`] receivers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetEvent {
    /// The first connection to a peer was established (inbound or outbound). Further
    /// parallel connections to the same peer do not produce another event.
    Connected {
        /// The peer.
        peer_id: PeerId,
        /// Its device key (bound to the peer id).
        device_key: DeviceKey,
        /// The remote address of that connection (for inbound connections the observed
        /// source address, not necessarily a listen address).
        remote_addr: Multiaddr,
    },
    /// The last connection to a peer closed.
    Disconnected {
        /// The peer.
        peer_id: PeerId,
    },
    /// A new local listen address is active.
    ListenAddr(Multiaddr),
    /// A local listen address is no longer active.
    ListenAddrExpired(Multiaddr),
    /// LAN discovery (only with [`NetworkConfig::lan_discovery`]): a libp2p node
    /// announced itself on the local network under this peer id.
    ///
    /// `addrs` are the addresses that were not known before, each in the form
    /// `/ip4|ip6/…/udp/…/quic-v1/p2p/<peer_id>`, ready for [`NetworkHandle::dial`]
    /// (which then requires the other end to prove that peer id). Another event follows
    /// if the peer is later heard at further addresses; [`NetworkHandle::discovered`]
    /// returns everything known.
    ///
    /// This is a hint, not a fact: mDNS is unauthenticated, so any host on the network
    /// can announce any peer id at any address. Nothing was dialed, nothing was
    /// authorized, and the event says nothing about circles. The application decides
    /// whether this device key is one it wants to dial.
    PeerDiscovered {
        /// The announced peer id. It is always one that binds to a device key
        /// ([`crate::device_key_from_peer_id`] returns `Some`).
        peer_id: PeerId,
        /// The newly announced addresses, at least one.
        addrs: Vec<Multiaddr>,
    },
    /// LAN discovery: addresses of a discovered peer were not announced again in time
    /// and left the list. The peer is no longer listed at all once
    /// [`NetworkHandle::discovered`] does not return it. Connections to it are not
    /// affected.
    PeerExpired {
        /// The peer.
        peer_id: PeerId,
        /// The addresses that expired, at least one.
        addrs: Vec<Multiaddr>,
    },
    /// Internet mode (only with [`NetworkConfig::internet`]): what the node knows about
    /// whether others can dial it directly has changed. While it is not
    /// [`Reachability::Public`] the node holds relay reservations.
    ReachabilityChanged {
        /// The new state.
        reachability: Reachability,
    },
    /// Internet mode: a relay accepted a reservation. The node can now be reached at
    /// `/…/p2p/<relay>/p2p-circuit/p2p/<own peer id>`
    /// ([`NetworkHandle::internet_status`] lists the addresses).
    RelayReserved {
        /// The relay.
        relay: PeerId,
        /// How many reservations the node holds now.
        relays: usize,
    },
    /// Internet mode: a reservation ended (the relay closed the connection or dropped
    /// it, or the node became publicly reachable and gave it up).
    RelayLost {
        /// The relay.
        relay: PeerId,
        /// How many reservations the node holds now.
        relays: usize,
    },
    /// Internet mode: a direct connection to a peer was established while the node was
    /// connected to it through a relay (the hole punch worked, or one side could simply
    /// be dialed). Requests go over the direct connection from now on; the relayed one
    /// is closed once nothing is in flight on it.
    DirectUpgradeSucceeded {
        /// The peer.
        peer_id: PeerId,
    },
    /// Internet mode: the attempt to replace a relayed connection to a peer with a
    /// direct one failed. The relayed connection stays, with the limits of its relay
    /// (see [`crate::internet`]).
    DirectUpgradeFailed {
        /// The peer.
        peer_id: PeerId,
    },
}

enum Command {
    Dial {
        addr: Multiaddr,
        reply: oneshot::Sender<Result<PeerId, NetError>>,
    },
    Request {
        peer: PeerId,
        body: Vec<u8>,
        reply: oneshot::Sender<Result<Response, NetError>>,
    },
    ConnectedPeers {
        reply: oneshot::Sender<Vec<PeerInfo>>,
    },
    PeerInfo {
        peer: PeerId,
        reply: oneshot::Sender<Option<PeerInfo>>,
    },
    Disconnect {
        peer: PeerId,
        reply: oneshot::Sender<bool>,
    },
    Discovered {
        reply: oneshot::Sender<Vec<(PeerId, Vec<Multiaddr>)>>,
    },
    FindPeer {
        peer: PeerId,
        timeout: Duration,
        reply: oneshot::Sender<Result<Vec<Multiaddr>, NetError>>,
    },
    InternetStatus {
        reply: oneshot::Sender<InternetStatus>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

/// The behaviour, in a module of its own for one reason: the code that
/// `#[derive(NetworkBehaviour)]` writes for a behaviour whose event cannot occur holds
/// a call that rustc 1.100 reports as unreachable, and the workspace builds with
/// warnings as errors. The lint is switched off for that generated code and for
/// nothing else in this crate.
mod behaviour {
    #![allow(unreachable_code)]

    use libp2p::request_response;
    use libp2p::swarm::NetworkBehaviour;

    use super::{Discovery, Internet, PeerPolicy, PhCodec};

    #[derive(NetworkBehaviour)]
    #[behaviour(prelude = "libp2p::swarm::derive_prelude")]
    pub(super) struct Behaviour {
        pub(super) policy: PeerPolicy,
        pub(super) internet: Internet,
        pub(super) rr: request_response::Behaviour<PhCodec>,
        pub(super) discovery: Discovery,
    }
}
use behaviour::{Behaviour, BehaviourEvent};

/// Listen state shared with handles.
#[derive(Clone, Debug, Default)]
struct ListenState {
    /// Active listen addresses.
    addrs: Vec<Multiaddr>,
    /// Listeners that have not closed yet.
    open_listeners: usize,
    /// The event loop has stopped.
    stopped: bool,
}

struct HandleInner {
    local_peer_id: PeerId,
    local_device_key: DeviceKey,
    commands: mpsc::Sender<Command>,
    events: broadcast::WeakSender<NetEvent>,
    listen: watch::Receiver<ListenState>,
    expects_listen: bool,
    request_timeout: Duration,
    dial_timeout: Duration,
}

/// A cheap, cloneable handle to a running network.
///
/// All methods are safe to call concurrently from any task. Once the event loop has
/// stopped (after [`NetworkHandle::shutdown`], or if it ended), every method that talks
/// to it returns [`NetError::Shutdown`].
///
/// The event loop also stops when every handle has been dropped. Note that an
/// application handler that itself stores a `NetworkHandle` keeps the loop alive; call
/// [`NetworkHandle::shutdown`] explicitly in that case.
#[derive(Clone)]
pub struct NetworkHandle {
    inner: Arc<HandleInner>,
}

impl fmt::Debug for NetworkHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkHandle")
            .field("local_peer_id", &self.inner.local_peer_id)
            .finish_non_exhaustive()
    }
}

/// Starts the network: builds the QUIC swarm with the identity derived from `seed`,
/// binds every configured listen address, and spawns the event loop on the current
/// Tokio runtime.
///
/// `seed` is the 32-byte Ed25519 secret of the device key
/// (`ph_identity::DeviceIdentity::libp2p_seed()`), so the local `PeerId` binds to the
/// device key. `handler` receives every inbound request that decodes and passes the
/// per-peer rate limits.
///
/// Returns the handle and the event loop's `JoinHandle`, which completes after
/// [`NetworkHandle::shutdown`] (or when every handle is dropped).
///
/// # Errors
///
/// [`NetError::NoRuntime`] outside a Tokio runtime, [`NetError::InvalidConfig`],
/// [`NetError::Identity`], [`NetError::Listen`] if any listen address cannot be bound
/// (only `/ip4|ip6/<addr>/udp/<port>/quic-v1` addresses are supported),
/// [`NetError::Discovery`] if [`NetworkConfig::lan_discovery`] is set and LAN discovery
/// cannot be started, or [`NetError::Internet`] if [`NetworkConfig::internet`] is set
/// and the mode cannot be started.
pub fn start(
    seed: Zeroizing<[u8; 32]>,
    config: NetworkConfig,
    handler: Arc<dyn RequestHandler>,
) -> Result<(NetworkHandle, JoinHandle<()>), NetError> {
    let runtime = tokio::runtime::Handle::try_current().map_err(|_| NetError::NoRuntime)?;
    config.validate()?;
    let keypair = keypair_from_seed(&seed)?;
    drop(seed);
    let local_device_key = device_key_of_keypair(&keypair).ok_or(NetError::Identity)?;
    let local_peer_id = keypair.public().to_peer_id();

    let rr_config = request_response::Config::default()
        .with_request_timeout(config.request_timeout)
        .with_max_concurrent_streams(config.max_concurrent_streams);
    let discovery = if config.lan_discovery {
        // The interface watcher registers with the runtime on some platforms.
        let _guard = runtime.enter();
        match Discovery::lan(local_peer_id) {
            Ok(discovery) => discovery,
            Err(_) => {
                tracing::warn!("failed to start LAN discovery");
                return Err(NetError::Discovery);
            }
        }
    } else {
        Discovery::off(local_peer_id)
    };
    let policy = PeerPolicy::new(
        config.max_connections,
        config.max_connections_per_peer,
        config.max_pending_inbound,
    )
    .with_foreign_identities(config.internet.is_some());
    let rr = request_response::Behaviour::with_codec(
        PhCodec::with_inbound_budget(config.max_inbound_buffer_bytes),
        [(PROTOCOL, ProtocolSupport::Full)],
        rr_config,
    );
    let stream_limit = u32::try_from(config.max_concurrent_streams).unwrap_or(u32::MAX);
    let idle_timeout = config.idle_timeout;
    let quic = move |mut c: libp2p::quic::Config| {
        c.max_concurrent_stream_limit = stream_limit;
        // A stream never needs more than one maximal frame in flight.
        c.max_stream_data = 1024 * 1024;
        c.max_connection_data = 8 * 1024 * 1024;
        c
    };
    // Internet mode only: the dispatcher that keeps the libp2p crates' log output back.
    // It is current for the rest of this function (building the swarm logs, too), for
    // the event loop and for the connection tasks.
    let quiet = config.internet.as_ref().map(|_| internet::quiet());
    let _quiet_here = quiet
        .as_ref()
        .map(|(dispatch, _)| tracing::dispatcher::set_default(dispatch));
    let mut swarm = match (&config.internet, &quiet) {
        (None, _) | (_, None) => {
            let behaviour = Behaviour {
                policy,
                internet: Internet::off(local_peer_id),
                rr,
                discovery,
            };
            let builder = {
                // Entering the runtime is required for the QUIC transport's socket setup.
                let _guard = runtime.enter();
                SwarmBuilder::with_existing_identity(keypair)
                    .with_tokio()
                    .with_quic_config(quic)
                    .with_behaviour(|_| behaviour)
            };
            let builder = match builder {
                Ok(b) => b,
                Err(never) => match never {},
            };
            builder
                .with_swarm_config(|c| c.with_idle_connection_timeout(idle_timeout))
                .with_connection_timeout(config.dial_timeout)
                .build()
        }
        (Some(internet_config), Some((dispatch, problems))) => {
            let problems = problems.clone();
            let max_connections = config.max_connections;
            let max_streams = config.max_concurrent_streams;
            let builder = {
                let _guard = runtime.enter();
                SwarmBuilder::with_existing_identity(keypair)
                    .with_tokio()
                    .with_quic_config(quic)
                    // A relayed connection is a stream through the relay. It is secured
                    // between its two ends with TLS 1.3 and the same libp2p certificates
                    // as QUIC, so the handshake proves both peer ids to each other and
                    // the relay sees ciphertext; yamux then carries the streams.
                    .with_relay_client(libp2p::tls::Config::new, move || {
                        let mut yamux = libp2p::yamux::Config::default();
                        yamux.set_max_num_streams(max_streams);
                        yamux
                    })
            };
            let Ok(builder) = builder else {
                tracing::warn!("failed to start the internet mode");
                return Err(NetError::Internet);
            };
            let builder = builder.with_behaviour(|key, relay| Behaviour {
                policy,
                internet: Internet::on(key, relay, internet_config, max_connections, problems),
                rr,
                discovery,
            });
            let builder = match builder {
                Ok(b) => b,
                Err(never) => match never {},
            };
            // Connection tasks run libp2p code too, so they get the same dispatcher.
            let tasks = runtime.clone();
            let task_dispatch = dispatch.clone();
            let executor = move |task: Pin<Box<dyn Future<Output = ()> + Send>>| {
                tasks.spawn(task.with_subscriber(task_dispatch.clone()));
            };
            builder
                .with_swarm_config(|_| {
                    libp2p::swarm::Config::with_executor(executor)
                        .with_idle_connection_timeout(idle_timeout)
                })
                .with_connection_timeout(config.dial_timeout)
                .build()
        }
    };

    let mut listeners = HashSet::new();
    {
        let _guard = runtime.enter();
        for addr in &config.listen_addrs {
            match swarm.listen_on(addr.clone()) {
                Ok(id) => {
                    listeners.insert(id);
                }
                Err(_) => {
                    tracing::warn!("failed to listen on a configured address");
                    return Err(NetError::Listen);
                }
            }
        }
    }

    let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_BUFFER);
    let (events_tx, _) = broadcast::channel(config.event_buffer);
    let (listen_tx, listen_rx) = watch::channel(ListenState {
        open_listeners: config.listen_addrs.len(),
        ..ListenState::default()
    });

    let handle = NetworkHandle {
        inner: Arc::new(HandleInner {
            local_peer_id,
            local_device_key,
            commands: cmd_tx,
            events: events_tx.downgrade(),
            listen: listen_rx,
            expects_listen: !config.listen_addrs.is_empty(),
            request_timeout: config.request_timeout,
            dial_timeout: config.dial_timeout,
        }),
    };

    let event_loop = EventLoop {
        swarm,
        commands: cmd_rx,
        events: events_tx,
        listen: listen_tx,
        handler,
        config,
        peers: HashMap::new(),
        limiters: HashMap::new(),
        pending_dials: HashMap::new(),
        pending_requests: HashMap::new(),
        tasks: JoinSet::new(),
        shutdown_acks: Vec::new(),
        stopping: false,
        internet_on: quiet.is_some(),
        listeners,
        unlisted: HashMap::new(),
        inbound_open: HashMap::new(),
    };
    tracing::info!(peer = %local_peer_id, "network starting");
    if event_loop.swarm.behaviour().discovery.is_on() {
        tracing::info!(peer = %local_peer_id, "LAN discovery on: the peer id and listen addresses are announced over mDNS");
    }
    let join = match quiet {
        Some((dispatch, _)) => {
            tracing::info!(
                peer = %local_peer_id,
                "internet mode on: the node joins the public libp2p network as a client and can be found there by its peer id"
            );
            runtime.spawn(event_loop.run().with_subscriber(dispatch))
        }
        None => runtime.spawn(event_loop.run()),
    };
    Ok((handle, join))
}

impl NetworkHandle {
    /// The local libp2p peer id.
    pub fn local_peer_id(&self) -> PeerId {
        self.inner.local_peer_id
    }

    /// The local device key (equal to the public key of the seed given to [`start`]).
    pub fn local_device_key(&self) -> DeviceKey {
        self.inner.local_device_key
    }

    /// The currently active listen addresses, without waiting. These carry no
    /// `/p2p/<peer_id>` suffix; see [`crate::with_p2p`].
    pub fn current_listen_addrs(&self) -> Vec<Multiaddr> {
        self.inner.listen.borrow().addrs.clone()
    }

    /// Waits until at least one listen address is active and returns all active ones.
    ///
    /// Returns immediately with an empty list when the configuration had no listen
    /// addresses. Ephemeral ports (`udp/0`) are resolved to the bound port.
    ///
    /// # Errors
    ///
    /// [`NetError::Shutdown`] if the network has stopped (or stops while waiting);
    /// [`NetError::Listen`] if every configured listener closed (for example on a
    /// socket error) before an address became active.
    pub async fn listen_addrs(&self) -> Result<Vec<Multiaddr>, NetError> {
        let mut rx = self.inner.listen.clone();
        let state = rx
            .wait_for(|s| s.stopped || !s.addrs.is_empty() || s.open_listeners == 0)
            .await
            .map_err(|_| NetError::Shutdown)?
            .clone();
        if state.stopped {
            Err(NetError::Shutdown)
        } else if state.addrs.is_empty() && self.inner.expects_listen {
            Err(NetError::Listen)
        } else {
            Ok(state.addrs)
        }
    }

    /// Dials `addr` and resolves once the connection is established, returning the
    /// remote's authenticated peer id.
    ///
    /// If `addr` ends in `/p2p/<peer_id>`, the handshake must prove that identity
    /// (otherwise the dial fails), and if that peer is already connected this returns
    /// immediately without a new connection. Without a `/p2p` suffix any Ed25519
    /// identity is accepted; check the returned peer id (or its device key) yourself.
    ///
    /// With [`NetworkConfig::internet`], `addr` may also be a relayed address,
    /// `/ip4|ip6/…/udp/…/quic-v1/p2p/<relay>/p2p-circuit/p2p/<peer_id>`, as
    /// [`NetworkHandle::find_peer`] returns them. The connection then runs through that
    /// relay and is authenticated and encrypted between the two ends exactly like a
    /// direct one; the upgrade to a direct connection is attempted by itself
    /// ([`NetEvent::DirectUpgradeSucceeded`], [`NetEvent::DirectUpgradeFailed`]).
    ///
    /// # Errors
    ///
    /// [`NetError::Dial`] for unreachable/dead addresses, wrong peer id, refused
    /// identities, connection limits or the dial timeout; [`NetError::Shutdown`].
    pub async fn dial(&self, addr: Multiaddr) -> Result<PeerId, NetError> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::Dial { addr, reply }).await?;
        match tokio::time::timeout(self.inner.dial_timeout + HANDLE_SLACK, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(NetError::Shutdown),
            Err(_) => Err(NetError::Dial),
        }
    }

    /// Sends `request` to a connected peer and waits for its response.
    ///
    /// The request is encoded (JCS, strict bounds) on the calling task. The peer must
    /// already be connected (see [`NetworkHandle::dial`]); ph-network never dials
    /// implicitly. A `Response::Error` from the peer (for example `rate_limited` or
    /// `unauthorized`) is returned as `Ok`.
    ///
    /// # Errors
    ///
    /// [`NetError::Encode`] (nothing sent), [`NetError::NotConnected`],
    /// [`NetError::Timeout`], [`NetError::ConnectionClosed`],
    /// [`NetError::UnsupportedProtocol`], [`NetError::Codec`] (malformed or oversized
    /// response, stream failure), [`NetError::Shutdown`].
    pub async fn request(&self, peer: PeerId, request: &Request) -> Result<Response, NetError> {
        let body = request.to_bytes().map_err(|_| NetError::Encode)?;
        let (reply, rx) = oneshot::channel();
        self.send(Command::Request { peer, body, reply }).await?;
        match tokio::time::timeout(self.inner.request_timeout + HANDLE_SLACK, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(NetError::Shutdown),
            Err(_) => Err(NetError::Timeout),
        }
    }

    /// Every currently connected peer, with the remote address of its oldest connection.
    ///
    /// With [`NetworkConfig::internet`] the node also holds connections that it opened on
    /// its own to servers of the public network. Those are not listed here and not
    /// reported as [`NetEvent::Connected`].
    pub async fn connected_peers(&self) -> Result<Vec<PeerInfo>, NetError> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::ConnectedPeers { reply }).await?;
        rx.await.map_err(|_| NetError::Shutdown)
    }

    /// Information about one connected peer, or `None` if it is not connected.
    pub async fn peer_info(&self, peer: PeerId) -> Result<Option<PeerInfo>, NetError> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::PeerInfo { peer, reply }).await?;
        rx.await.map_err(|_| NetError::Shutdown)
    }

    /// Whether `peer` currently has an established connection.
    pub async fn is_connected(&self, peer: PeerId) -> Result<bool, NetError> {
        Ok(self.peer_info(peer).await?.is_some())
    }

    /// Closes every connection to `peer`. Returns whether it was connected. In-flight
    /// requests to it fail with [`NetError::ConnectionClosed`]; a
    /// [`NetEvent::Disconnected`] follows once the connections are closed.
    pub async fn disconnect(&self, peer: PeerId) -> Result<bool, NetError> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::Disconnect { peer, reply }).await?;
        rx.await.map_err(|_| NetError::Shutdown)
    }

    /// The peers currently known from LAN discovery, ordered by peer id, each with its
    /// announced addresses (at most [`crate::discovery::MAX_DISCOVERED_PEERS`] peers and
    /// [`crate::discovery::MAX_ADDRS_PER_PEER`] addresses per peer). Empty unless
    /// [`NetworkConfig::lan_discovery`] is set.
    ///
    /// Everything said about [`NetEvent::PeerDiscovered`] holds here: the addresses end
    /// in `/p2p/<peer_id>`, they are unauthenticated hints, none of these peers was
    /// dialed, and being listed gives a peer no standing. A peer stays listed until its
    /// records expire (minutes after it left) whether or not it is connected.
    ///
    /// # Errors
    ///
    /// [`NetError::Shutdown`].
    pub async fn discovered(&self) -> Result<Vec<(PeerId, Vec<Multiaddr>)>, NetError> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::Discovered { reply }).await?;
        rx.await.map_err(|_| NetError::Shutdown)
    }

    /// Internet mode: looks `peer` up on the public network and returns the addresses
    /// its servers hold for it, newest first, at most
    /// [`crate::internet::MAX_FOUND_ADDRS`]. Empty if nobody named the peer within
    /// `timeout` (at most 30 s are used).
    ///
    /// Every address ends in `/p2p/<peer>` and is either direct
    /// (`/ip4|ip6/…/udp/…/quic-v1/p2p/<peer>`) or relayed
    /// (`/…/quic-v1/p2p/<relay>/p2p-circuit/p2p/<peer>`), ready for
    /// [`NetworkHandle::dial`]. They are unauthenticated hints from strangers: a dial
    /// succeeds only if the other end proves that key. This call dials nothing itself
    /// and connects to nobody but DHT servers, and the node will not dial `peer` on its
    /// own afterwards either. The servers that are asked learn which peer id this node
    /// is looking for.
    ///
    /// A peer can be found while it runs in internet mode and for some minutes after it
    /// stopped. Right after this node started the lookup waits, within `timeout`, until
    /// the node knows a DHT server.
    ///
    /// # Errors
    ///
    /// [`NetError::InternetOff`] without [`NetworkConfig::internet`], [`NetError::Busy`]
    /// with [`crate::internet::MAX_CONCURRENT_FINDS`] lookups in flight,
    /// [`NetError::Shutdown`].
    pub async fn find_peer(
        &self,
        peer: PeerId,
        timeout: Duration,
    ) -> Result<Vec<Multiaddr>, NetError> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::FindPeer {
            peer,
            timeout,
            reply,
        })
        .await?;
        match tokio::time::timeout(timeout.saturating_add(HANDLE_SLACK), rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(NetError::Shutdown),
            Err(_) => Err(NetError::Timeout),
        }
    }

    /// Where this node stands on the public network: whether it has joined, whether it
    /// can be dialed directly, and the addresses others can reach it at. With the
    /// internet mode off, [`InternetStatus::enabled`] is `false` and the rest is empty.
    ///
    /// # Errors
    ///
    /// [`NetError::Shutdown`].
    pub async fn internet_status(&self) -> Result<InternetStatus, NetError> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::InternetStatus { reply }).await?;
        rx.await.map_err(|_| NetError::Shutdown)
    }

    /// Subscribes to [`NetEvent`]s from now on. Events emitted before the call are not
    /// replayed (use [`NetworkHandle::connected_peers`],
    /// [`NetworkHandle::listen_addrs`] and [`NetworkHandle::discovered`] for current
    /// state). After shutdown the receiver yields `RecvError::Closed`.
    pub fn subscribe(&self) -> broadcast::Receiver<NetEvent> {
        match self.inner.events.upgrade() {
            Some(tx) => tx.subscribe(),
            None => broadcast::channel(1).1,
        }
    }

    /// Stops the network: stops LAN discovery (its multicast sockets are closed and
    /// nothing is announced any more) and the internet mode (lookups end, and closing
    /// the connections ends the relay reservations), fails pending requests and dials with
    /// [`NetError::Shutdown`], aborts in-flight handler tasks, closes every connection
    /// (waiting up to 3 s for clean closes), and releases the sockets. Resolves when the
    /// event loop has finished. Idempotent; returns immediately if already stopped.
    pub async fn shutdown(&self) {
        let (reply, rx) = oneshot::channel();
        if self.send(Command::Shutdown { reply }).await.is_ok() {
            let _ = rx.await;
        }
    }

    /// Whether the event loop is still accepting commands.
    pub fn is_running(&self) -> bool {
        !self.inner.commands.is_closed()
    }

    async fn send(&self, cmd: Command) -> Result<(), NetError> {
        self.inner
            .commands
            .send(cmd)
            .await
            .map_err(|_| NetError::Shutdown)
    }
}

struct PeerEntry {
    device_key: DeviceKey,
    /// Established connections, oldest first.
    connections: Vec<Link>,
    /// Internet mode: a direct connection exists next to a relayed one.
    upgraded: Option<Upgrade>,
}

/// A direct connection that appeared while the peer was connected through a relay.
#[derive(Clone, Copy)]
struct Upgrade {
    since: Instant,
    /// Whether it lasted and was reported.
    announced: bool,
}

/// One established connection to a peer.
struct Link {
    id: ConnectionId,
    remote_addr: Multiaddr,
    /// Whether it goes through a relay.
    relayed: bool,
}

impl PeerEntry {
    fn has_direct(&self) -> bool {
        self.connections.iter().any(|c| !c.relayed)
    }

    fn has_relayed(&self) -> bool {
        self.connections.iter().any(|c| c.relayed)
    }
}

type HandlerOutput = (
    ResponseChannel<ResponseFrame>,
    ResponseFrame,
    InboundRequestId,
);

struct EventLoop {
    swarm: Swarm<Behaviour>,
    commands: mpsc::Receiver<Command>,
    events: broadcast::Sender<NetEvent>,
    listen: watch::Sender<ListenState>,
    handler: Arc<dyn RequestHandler>,
    config: NetworkConfig,
    peers: HashMap<PeerId, PeerEntry>,
    limiters: HashMap<PeerId, PeerLimiter>,
    pending_dials: HashMap<ConnectionId, oneshot::Sender<Result<PeerId, NetError>>>,
    pending_requests:
        HashMap<OutboundRequestId, (PeerId, oneshot::Sender<Result<Response, NetError>>)>,
    tasks: JoinSet<HandlerOutput>,
    shutdown_acks: Vec<oneshot::Sender<()>>,
    /// Set once shutdown has begun: new inbound requests are refused.
    stopping: bool,
    /// Whether the internet mode is on.
    internet_on: bool,
    /// The listeners of the configured listen addresses. With the internet mode there
    /// are also listeners on relays, which are not the application's.
    listeners: HashSet<ListenerId>,
    /// Internet mode: connections that are not the application's: those the node
    /// opened on its own to servers of the public network, and those with peers that
    /// have no device key. They are counted so that shutdown closes them.
    unlisted: HashMap<ConnectionId, PeerId>,
    /// Internet mode: inbound requests that have not been answered on the wire yet.
    inbound_open: HashMap<InboundRequestId, PeerId>,
}

fn send_response(
    swarm: &mut Swarm<Behaviour>,
    channel: ResponseChannel<ResponseFrame>,
    frame: ResponseFrame,
) {
    if swarm
        .behaviour_mut()
        .rr
        .send_response(channel, frame)
        .is_err()
    {
        tracing::debug!("response dropped: inbound stream already closed");
    }
}

fn error_frame(code: ErrorCode) -> ResponseFrame {
    ResponseFrame::Encoded(encode_response(&Response::error(code)))
}

fn map_outbound_failure(e: &OutboundFailure) -> NetError {
    match e {
        OutboundFailure::DialFailure => NetError::NotConnected,
        OutboundFailure::Timeout => NetError::Timeout,
        OutboundFailure::ConnectionClosed => NetError::ConnectionClosed,
        OutboundFailure::UnsupportedProtocols => NetError::UnsupportedProtocol,
        OutboundFailure::Io(_) => NetError::Codec,
    }
}

/// Logs a rate-limit refusal: a warning with the peer id and limit name at most once
/// per [`crate::limiter::WARN_INTERVAL`] per peer, debug otherwise.
fn warn_limited(limiter: &mut PeerLimiter, peer: &PeerId, limit: Limited, now: Instant) {
    match limiter.note_limited(now) {
        Some(suppressed) => tracing::warn!(
            peer = %peer,
            limit = limit.as_str(),
            suppressed,
            "inbound request rate limited"
        ),
        None => {
            tracing::debug!(peer = %peer, limit = limit.as_str(), "inbound request rate limited")
        }
    }
}

async fn run_handler(
    handler: Arc<dyn RequestHandler>,
    peer: PeerInfo,
    request: Request,
    timeout: Duration,
) -> Response {
    let peer_id = peer.peer_id;
    let kind = request.kind();
    let fut = match std::panic::catch_unwind(AssertUnwindSafe(|| handler.handle(peer, request))) {
        Ok(f) => f,
        Err(_) => {
            tracing::warn!(peer = %peer_id, kind, "request handler panicked");
            return Response::error(ErrorCode::Unavailable);
        }
    };
    match tokio::time::timeout(timeout, AssertUnwindSafe(fut).catch_unwind()).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(_)) => {
            tracing::warn!(peer = %peer_id, kind, "request handler panicked");
            Response::error(ErrorCode::Unavailable)
        }
        Err(_) => {
            tracing::warn!(peer = %peer_id, kind, "request handler timed out");
            Response::error(ErrorCode::Unavailable)
        }
    }
}

/// The next tick of `interval`; never, if there is none.
async fn tick(interval: &mut Option<tokio::time::Interval>) {
    match interval {
        Some(interval) => {
            interval.tick().await;
        }
        None => std::future::pending().await,
    }
}

impl EventLoop {
    async fn run(mut self) {
        let mut prune = tokio::time::interval(PRUNE_INTERVAL);
        prune.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Internet mode only; without it there is no such timer.
        let mut upgrades = self.internet_on.then(|| {
            let mut upgrades = tokio::time::interval(UPGRADE_TICK);
            upgrades.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            upgrades
        });
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => self.on_swarm_event(event),
                cmd = self.commands.recv() => match cmd {
                    Some(Command::Shutdown { reply }) => {
                        self.shutdown_acks.push(reply);
                        break;
                    }
                    Some(cmd) => self.on_command(cmd),
                    None => break,
                },
                Some(done) = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    match done {
                        Ok((channel, frame, id)) => {
                            tracing::trace!(request = %id, "handler finished");
                            send_response(&mut self.swarm, channel, frame);
                        }
                        Err(_) => tracing::warn!("request handler task failed"),
                    }
                }
                _ = prune.tick() => self.prune_limiters(),
                _ = tick(&mut upgrades) => self.settle_upgrades(),
            }
        }
        self.shutdown().await;
    }

    async fn shutdown(mut self) {
        tracing::info!(peer = %self.swarm.local_peer_id(), "network shutting down");
        self.stopping = true;
        // First, so that the node is no longer announced while connections close.
        self.swarm.behaviour_mut().discovery.stop();
        self.swarm.behaviour_mut().internet.stop();
        self.commands.close();
        while let Ok(cmd) = self.commands.try_recv() {
            self.reject_command(cmd);
        }
        self.tasks.abort_all();
        for (_, (_, tx)) in self.pending_requests.drain() {
            let _ = tx.send(Err(NetError::Shutdown));
        }
        for (_, tx) in self.pending_dials.drain() {
            let _ = tx.send(Err(NetError::Shutdown));
        }
        let peers: HashSet<PeerId> = self
            .peers
            .keys()
            .chain(self.unlisted.values())
            .copied()
            .collect();
        for p in peers {
            let _ = self.swarm.disconnect_peer_id(p);
        }
        let deadline = tokio::time::sleep(SHUTDOWN_GRACE);
        tokio::pin!(deadline);
        while !(self.peers.is_empty() && self.unlisted.is_empty()) {
            tokio::select! {
                event = self.swarm.select_next_some() => self.on_swarm_event(event),
                _ = &mut deadline => break,
            }
        }
        self.listen.send_replace(ListenState {
            addrs: Vec::new(),
            open_listeners: 0,
            stopped: true,
        });
        // Drain aborted tasks (their response channels are dropped).
        while self.tasks.join_next().await.is_some() {}
        let acks = std::mem::take(&mut self.shutdown_acks);
        let local = *self.swarm.local_peer_id();
        drop(self);
        tracing::info!(peer = %local, "network stopped");
        for ack in acks {
            let _ = ack.send(());
        }
    }

    fn reject_command(&mut self, cmd: Command) {
        match cmd {
            Command::Dial { reply, .. } => {
                let _ = reply.send(Err(NetError::Shutdown));
            }
            Command::Request { reply, .. } => {
                let _ = reply.send(Err(NetError::Shutdown));
            }
            Command::FindPeer { reply, .. } => {
                let _ = reply.send(Err(NetError::Shutdown));
            }
            Command::Shutdown { reply } => self.shutdown_acks.push(reply),
            // Dropping the reply sender makes the caller see `Shutdown`.
            Command::ConnectedPeers { .. }
            | Command::PeerInfo { .. }
            | Command::Disconnect { .. }
            | Command::Discovered { .. }
            | Command::InternetStatus { .. } => {}
        }
    }

    fn info_of(&self, peer: &PeerId, connection: Option<ConnectionId>) -> Option<PeerInfo> {
        let entry = self.peers.get(peer)?;
        let link = connection
            .and_then(|c| entry.connections.iter().find(|l| l.id == c))
            .or_else(|| entry.connections.first());
        Some(PeerInfo {
            peer_id: *peer,
            device_key: entry.device_key,
            remote_addr: link.map(|l| l.remote_addr.clone()),
            relayed: link.is_some_and(|l| l.relayed),
        })
    }

    fn emit(&self, event: NetEvent) {
        // No receivers is fine.
        let _ = self.events.send(event);
    }

    fn on_command(&mut self, cmd: Command) {
        match cmd {
            Command::Dial { addr, reply } => self.dial(addr, reply),
            Command::Request { peer, body, reply } => {
                // With the internet mode the node is also connected to servers of the
                // public network that are no peers of the application.
                let connected = if self.internet_on {
                    self.peers.contains_key(&peer)
                } else {
                    self.swarm.is_connected(&peer)
                };
                if !connected {
                    let _ = reply.send(Err(NetError::NotConnected));
                    return;
                }
                let id = self
                    .swarm
                    .behaviour_mut()
                    .rr
                    .send_request(&peer, RequestFrame::Encoded(body));
                tracing::debug!(peer = %peer, request = %id, "outbound request");
                self.pending_requests.insert(id, (peer, reply));
            }
            Command::ConnectedPeers { reply } => {
                let mut v: Vec<PeerInfo> = self
                    .peers
                    .keys()
                    .filter_map(|p| self.info_of(p, None))
                    .collect();
                v.sort_by_key(|i| i.peer_id);
                let _ = reply.send(v);
            }
            Command::PeerInfo { peer, reply } => {
                let _ = reply.send(self.info_of(&peer, None));
            }
            Command::Disconnect { peer, reply } => {
                // A connection the internet mode opened on its own is not the
                // application's to close.
                let listed = !self.internet_on || self.peers.contains_key(&peer);
                let was = listed && self.swarm.disconnect_peer_id(peer).is_ok();
                let _ = reply.send(was);
            }
            Command::Discovered { reply } => {
                let _ = reply.send(self.swarm.behaviour().discovery.snapshot());
            }
            Command::FindPeer {
                peer,
                timeout,
                reply,
            } => self
                .swarm
                .behaviour_mut()
                .internet
                .find(peer, timeout, reply),
            Command::InternetStatus { reply } => {
                let _ = reply.send(self.swarm.behaviour_mut().internet.status());
            }
            Command::Shutdown { reply } => self.shutdown_acks.push(reply),
        }
    }

    fn dial(&mut self, addr: Multiaddr, reply: oneshot::Sender<Result<PeerId, NetError>>) {
        let opts = match peer_id_of_addr(&addr) {
            Some(pid) => {
                if self.peers.contains_key(&pid) {
                    let _ = reply.send(Ok(pid));
                    return;
                }
                if device_key_from_peer_id(&pid).is_none() {
                    let _ = reply.send(Err(NetError::Dial));
                    return;
                }
                DialOpts::peer_id(pid)
                    .addresses(vec![addr.clone()])
                    .condition(PeerCondition::Always)
                    .build()
            }
            None => DialOpts::unknown_peer_id().address(addr.clone()).build(),
        };
        let connection_id = opts.connection_id();
        // Internet mode: this is the one kind of dial that may reach a peer the
        // application named. Nothing happens here when the mode is off.
        self.swarm
            .behaviour_mut()
            .internet
            .dial_asked(connection_id, &addr);
        let dialed = self.swarm.dial(opts);
        self.swarm
            .behaviour_mut()
            .internet
            .dial_made(connection_id, dialed.is_ok());
        match dialed {
            Ok(()) => {
                tracing::debug!(connection = %connection_id, "dialing");
                self.pending_dials.insert(connection_id, reply);
            }
            Err(_) => {
                tracing::debug!(connection = %connection_id, "dial rejected");
                let _ = reply.send(Err(NetError::Dial));
            }
        }
    }

    fn on_swarm_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Rr(e)) => self.on_rr_event(e),
            SwarmEvent::Behaviour(BehaviourEvent::Policy(never)) => match never {},
            SwarmEvent::Behaviour(BehaviourEvent::Internet(e)) => self.on_internet_event(e),
            // Reported and nothing else: ph-network never dials a discovered peer.
            SwarmEvent::Behaviour(BehaviourEvent::Discovery(e)) => self.emit(match e {
                DiscoveryEvent::Discovered { peer_id, addrs } => {
                    NetEvent::PeerDiscovered { peer_id, addrs }
                }
                DiscoveryEvent::Expired { peer_id, addrs } => {
                    NetEvent::PeerExpired { peer_id, addrs }
                }
            }),
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => {
                let relayed = endpoint.is_relayed();
                if self.internet_on && self.swarm.behaviour().internet.is_own(connection_id) {
                    // A connection the node opened on its own, to a DHT server or a
                    // relay: the internet mode's business, not the application's. It is
                    // not reported or listed, and no request is sent on it.
                    tracing::trace!(peer = %peer_id, connection = %connection_id, "connection to a server of the public network");
                    self.unlisted.insert(connection_id, peer_id);
                    if self.stopping {
                        self.swarm.close_connection(connection_id);
                    }
                    return;
                }
                let Some(device_key) = device_key_from_peer_id(&peer_id) else {
                    if self.internet_on
                        && !relayed
                        && !self.pending_dials.contains_key(&connection_id)
                    {
                        // A server of the public network with another kind of key that
                        // connected to this node (the dial-back of an AutoNAT server,
                        // for one). No peer of the application either: it is answered
                        // `unauthorized` whatever it asks.
                        tracing::debug!(peer = %peer_id, connection = %connection_id, "connection from a peer that has no device key");
                        self.unlisted.insert(connection_id, peer_id);
                        if self.stopping {
                            self.swarm.close_connection(connection_id);
                        }
                        return;
                    }
                    // Defence in depth: the policy behaviour already refuses these.
                    tracing::warn!(peer = %peer_id, "closing connection with unsupported identity");
                    self.swarm.close_connection(connection_id);
                    if let Some(tx) = self.pending_dials.remove(&connection_id) {
                        let _ = tx.send(Err(NetError::Dial));
                    }
                    return;
                };
                let remote_addr = match &endpoint {
                    // A relay says who is calling and not from where: report the relay
                    // address the connection came in through.
                    ConnectedPoint::Listener { local_addr, .. } if relayed => {
                        local_addr.clone().with(Protocol::P2p(peer_id))
                    }
                    _ => endpoint.get_remote_address().clone(),
                };
                let entry = self.peers.entry(peer_id).or_insert_with(|| PeerEntry {
                    device_key,
                    connections: Vec::new(),
                    upgraded: None,
                });
                if !relayed && entry.has_relayed() && entry.upgraded.is_none() {
                    // Reported once it has lasted (`settle_upgrades`).
                    entry.upgraded = Some(Upgrade {
                        since: Instant::now(),
                        announced: false,
                    });
                }
                entry.connections.push(Link {
                    id: connection_id,
                    remote_addr: remote_addr.clone(),
                    relayed,
                });
                let first = entry.connections.len() == 1;
                tracing::debug!(peer = %peer_id, connection = %connection_id, relayed, "connection established");
                if first {
                    self.emit(NetEvent::Connected {
                        peer_id,
                        device_key,
                        remote_addr,
                    });
                }
                if let Some(tx) = self.pending_dials.remove(&connection_id) {
                    let _ = tx.send(Ok(peer_id));
                }
                if self.stopping && self.internet_on {
                    self.swarm.close_connection(connection_id);
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                ..
            } => {
                if self.unlisted.remove(&connection_id).is_some() {
                    return;
                }
                tracing::debug!(peer = %peer_id, connection = %connection_id, "connection closed");
                let mut gone = false;
                let mut upgraded = false;
                if let Some(entry) = self.peers.get_mut(&peer_id) {
                    entry.connections.retain(|l| l.id != connection_id);
                    gone = entry.connections.is_empty();
                    if !(entry.has_relayed() && entry.has_direct()) {
                        // The relayed connection went first (the other side settled
                        // sooner) and the direct one is still there: that is the upgrade.
                        upgraded = entry.has_direct()
                            && entry.upgraded.take().is_some_and(|u| !u.announced);
                        entry.upgraded = None;
                    }
                }
                if upgraded {
                    tracing::info!(peer = %peer_id, "relayed connection upgraded to a direct one");
                    self.emit(NetEvent::DirectUpgradeSucceeded { peer_id });
                }
                if gone {
                    self.peers.remove(&peer_id);
                    self.inbound_open.retain(|_, p| *p != peer_id);
                    self.emit(NetEvent::Disconnected { peer_id });
                }
            }
            SwarmEvent::OutgoingConnectionError { connection_id, .. } => {
                tracing::debug!(connection = %connection_id, "outgoing connection failed");
                if let Some(tx) = self.pending_dials.remove(&connection_id) {
                    let _ = tx.send(Err(NetError::Dial));
                }
            }
            SwarmEvent::IncomingConnectionError { connection_id, .. } => {
                tracing::debug!(connection = %connection_id, "incoming connection failed");
            }
            // Only the configured listeners are the application's. With the internet
            // mode the node also listens on relays; those addresses are reported by
            // `internet_status`. With the mode off there are no other listeners.
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } if self.listeners.contains(&listener_id) => {
                tracing::debug!("listen address active");
                let a = address.clone();
                self.listen.send_modify(|s| {
                    if !s.addrs.contains(&a) {
                        s.addrs.push(a);
                    }
                });
                self.emit(NetEvent::ListenAddr(address));
            }
            SwarmEvent::ExpiredListenAddr {
                listener_id,
                address,
            } if self.listeners.contains(&listener_id) => {
                self.listen
                    .send_modify(|s| s.addrs.retain(|x| *x != address));
                self.emit(NetEvent::ListenAddrExpired(address));
            }
            SwarmEvent::ListenerClosed {
                listener_id,
                addresses,
                ..
            } if self.listeners.remove(&listener_id) => {
                tracing::warn!(count = addresses.len(), "listener closed");
                self.listen.send_modify(|s| {
                    s.addrs.retain(|x| !addresses.contains(x));
                    s.open_listeners = s.open_listeners.saturating_sub(1);
                });
                for a in addresses {
                    self.emit(NetEvent::ListenAddrExpired(a));
                }
            }
            SwarmEvent::ListenerError { listener_id, .. }
                if self.listeners.contains(&listener_id) =>
            {
                tracing::warn!("listener error")
            }
            _ => {}
        }
    }

    fn on_internet_event(&mut self, event: InternetEvent) {
        match event {
            InternetEvent::Reachability(reachability) => {
                self.emit(NetEvent::ReachabilityChanged { reachability });
            }
            InternetEvent::RelayReserved { relay, relays } => {
                self.emit(NetEvent::RelayReserved { relay, relays });
            }
            InternetEvent::RelayLost { relay, relays } => {
                self.emit(NetEvent::RelayLost { relay, relays });
            }
            InternetEvent::UpgradeFailed { peer } => {
                // The hole punch has two sides; when the other side's dial got through,
                // a direct connection exists although this side's attempt failed.
                let relayed_only = self
                    .peers
                    .get(&peer)
                    .is_some_and(|e| e.has_relayed() && !e.has_direct());
                if relayed_only {
                    tracing::info!(peer = %peer, "no direct connection could be made; the connection stays relayed");
                    self.emit(NetEvent::DirectUpgradeFailed { peer_id: peer });
                }
            }
        }
    }

    /// Internet mode: closes the relayed connections to `peer` if a direct one exists
    /// that has lasted and, unless `force`, nothing is in flight with that peer. A
    /// relayed connection carries little and not for long, and request/response picks
    /// any connection, so it has to go for requests to use the direct one.
    fn close_relayed(&mut self, peer: PeerId, force: bool) {
        let Some(entry) = self.peers.get(&peer) else {
            return;
        };
        let settled = entry.upgraded.is_some_and(|u| u.announced);
        if !settled || !entry.has_direct() || !entry.has_relayed() {
            return;
        }
        let busy = self.pending_requests.values().any(|(p, _)| *p == peer)
            || self.inbound_open.values().any(|p| *p == peer);
        if busy && !force {
            return;
        }
        let relayed: Vec<ConnectionId> = entry
            .connections
            .iter()
            .filter(|l| l.relayed)
            .map(|l| l.id)
            .collect();
        tracing::debug!(peer = %peer, connections = relayed.len(), "closing relayed connections: a direct one exists");
        for id in relayed {
            self.swarm.close_connection(id);
        }
    }

    /// Internet mode: reports the direct connections that have lasted
    /// [`UPGRADE_SETTLE`] next to a relayed one, and closes the relayed one: when
    /// nothing is in flight, or after [`RELAYED_GRACE`] whatever is.
    fn settle_upgrades(&mut self) {
        let now = Instant::now();
        let due: Vec<(PeerId, bool, bool)> = self
            .peers
            .iter_mut()
            .filter_map(|(peer, entry)| {
                if !entry.has_direct() {
                    return None;
                }
                let upgrade = entry.upgraded.as_mut()?;
                let age = now.saturating_duration_since(upgrade.since);
                if age < UPGRADE_SETTLE {
                    return None;
                }
                let news = !upgrade.announced;
                upgrade.announced = true;
                Some((*peer, news, age >= RELAYED_GRACE))
            })
            .collect();
        for (peer_id, news, force) in due {
            if news {
                tracing::info!(peer = %peer_id, "relayed connection upgraded to a direct one");
                self.emit(NetEvent::DirectUpgradeSucceeded { peer_id });
            }
            self.close_relayed(peer_id, force);
        }
    }

    fn on_rr_event(&mut self, event: request_response::Event<RequestFrame, ResponseFrame>) {
        match event {
            request_response::Event::Message {
                peer,
                connection_id,
                message,
            } => match message {
                Message::Request {
                    request_id,
                    request,
                    channel,
                } => {
                    if self.internet_on {
                        self.inbound_open.insert(request_id, peer);
                    }
                    self.on_inbound(peer, connection_id, request_id, request, channel)
                }
                Message::Response {
                    request_id,
                    response,
                } => {
                    let Some((_, tx)) = self.pending_requests.remove(&request_id) else {
                        return;
                    };
                    let result = match response {
                        ResponseFrame::Decoded(r) => Ok(r),
                        ResponseFrame::Encoded(b) => {
                            Response::from_bytes(&b).map_err(|_| NetError::Codec)
                        }
                    };
                    let _ = tx.send(result);
                    self.close_relayed(peer, false);
                }
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                let e = map_outbound_failure(&error);
                tracing::debug!(peer = %peer, request = %request_id, error = %e, "outbound request failed");
                if let Some((_, tx)) = self.pending_requests.remove(&request_id) {
                    let _ = tx.send(Err(e));
                }
                self.close_relayed(peer, false);
            }
            request_response::Event::InboundFailure {
                peer, request_id, ..
            } => {
                tracing::debug!(peer = %peer, request = %request_id, "inbound request failed");
                if self.inbound_open.remove(&request_id).is_some() {
                    self.close_relayed(peer, false);
                }
            }
            request_response::Event::ResponseSent {
                peer, request_id, ..
            } => {
                if self.inbound_open.remove(&request_id).is_some() {
                    self.close_relayed(peer, false);
                }
            }
        }
    }

    fn on_inbound(
        &mut self,
        peer: PeerId,
        connection_id: ConnectionId,
        request_id: InboundRequestId,
        frame: RequestFrame,
        channel: ResponseChannel<ResponseFrame>,
    ) {
        if self.stopping {
            send_response(
                &mut self.swarm,
                channel,
                error_frame(ErrorCode::Unavailable),
            );
            return;
        }
        let now = Instant::now();
        let limits = &self.config.rate_limits;
        let limiter = self
            .limiters
            .entry(peer)
            .or_insert_with(|| PeerLimiter::new(limits, now));
        if let Err(l) = limiter.admit(frame.wire_bytes(), now) {
            warn_limited(limiter, &peer, l, now);
            send_response(
                &mut self.swarm,
                channel,
                error_frame(ErrorCode::RateLimited),
            );
            return;
        }
        let request = match frame {
            RequestFrame::Decoded { request, .. } => request,
            RequestFrame::Rejected { code, .. } => {
                tracing::debug!(peer = %peer, request = %request_id, code = ?code, "rejected inbound frame");
                send_response(&mut self.swarm, channel, error_frame(code));
                return;
            }
            RequestFrame::Encoded(_) => {
                send_response(&mut self.swarm, channel, error_frame(ErrorCode::BadRequest));
                return;
            }
        };
        let permit = match limiter.try_permit() {
            Ok(p) => p,
            Err(l) => {
                warn_limited(limiter, &peer, l, now);
                send_response(
                    &mut self.swarm,
                    channel,
                    error_frame(ErrorCode::RateLimited),
                );
                return;
            }
        };
        let info = match self.info_of(&peer, Some(connection_id)) {
            Some(i) => i,
            None => match device_key_from_peer_id(&peer) {
                Some(device_key) => PeerInfo {
                    peer_id: peer,
                    device_key,
                    remote_addr: None,
                    relayed: false,
                },
                None => {
                    send_response(
                        &mut self.swarm,
                        channel,
                        error_frame(ErrorCode::Unauthorized),
                    );
                    return;
                }
            },
        };
        tracing::debug!(peer = %peer, request = %request_id, kind = request.kind(), "inbound request");
        let handler = Arc::clone(&self.handler);
        let timeout = self.config.request_timeout;
        self.tasks.spawn(async move {
            let response = run_handler(handler, info, request, timeout).await;
            let frame = ResponseFrame::Encoded(encode_response(&response));
            drop(permit);
            (channel, frame, request_id)
        });
    }

    fn prune_limiters(&mut self) {
        let now = Instant::now();
        let limits = self.config.rate_limits.clone();
        let peers = &self.peers;
        self.limiters
            .retain(|p, l| peers.contains_key(p) || !l.is_stale(&limits, LIMITER_IDLE, now));
    }
}
