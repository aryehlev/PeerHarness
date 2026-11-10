//! The swarm event loop and the async [`NetworkHandle`].

use std::collections::HashMap;
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{FutureExt, StreamExt};
use libp2p::request_response::{
    self, InboundRequestId, Message, OutboundFailure, OutboundRequestId, ProtocolSupport,
    ResponseChannel,
};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::{ConnectionId, NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, Swarm, SwarmBuilder};
use ph_core::DeviceKey;
use ph_protocol::wire::{ErrorCode, Request, Response};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use zeroize::Zeroizing;

use crate::codec::{encode_response, PhCodec, RequestFrame, ResponseFrame, PROTOCOL};
use crate::config::NetworkConfig;
use crate::discovery::{Discovery, DiscoveryEvent};
use crate::error::NetError;
use crate::handler::{PeerInfo, RequestHandler};
use crate::identity::{
    device_key_from_peer_id, device_key_of_keypair, keypair_from_seed, peer_id_of_addr,
};
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
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
struct Behaviour {
    policy: PeerPolicy,
    rr: request_response::Behaviour<PhCodec>,
    discovery: Discovery,
}

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
/// (only `/ip4|ip6/<addr>/udp/<port>/quic-v1` addresses are supported), or
/// [`NetError::Discovery`] if [`NetworkConfig::lan_discovery`] is set and LAN discovery
/// cannot be started.
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
    let behaviour = Behaviour {
        policy: PeerPolicy::new(
            config.max_connections,
            config.max_connections_per_peer,
            config.max_pending_inbound,
        ),
        rr: request_response::Behaviour::with_codec(
            PhCodec::with_inbound_budget(config.max_inbound_buffer_bytes),
            [(PROTOCOL, ProtocolSupport::Full)],
            rr_config,
        ),
        discovery,
    };
    let stream_limit = u32::try_from(config.max_concurrent_streams).unwrap_or(u32::MAX);
    let idle_timeout = config.idle_timeout;
    let builder = {
        // Entering the runtime is required for the QUIC transport's socket setup.
        let _guard = runtime.enter();
        SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_quic_config(|mut c| {
                c.max_concurrent_stream_limit = stream_limit;
                // A stream never needs more than one maximal frame in flight.
                c.max_stream_data = 1024 * 1024;
                c.max_connection_data = 8 * 1024 * 1024;
                c
            })
            .with_behaviour(|_| behaviour)
    };
    let builder = match builder {
        Ok(b) => b,
        Err(never) => match never {},
    };
    let mut swarm = builder
        .with_swarm_config(|c| c.with_idle_connection_timeout(idle_timeout))
        .with_connection_timeout(config.dial_timeout)
        .build();

    {
        let _guard = runtime.enter();
        for addr in &config.listen_addrs {
            if swarm.listen_on(addr.clone()).is_err() {
                tracing::warn!("failed to listen on a configured address");
                return Err(NetError::Listen);
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
    };
    tracing::info!(peer = %local_peer_id, "network starting");
    if event_loop.swarm.behaviour().discovery.is_on() {
        tracing::info!(peer = %local_peer_id, "LAN discovery on: the peer id and listen addresses are announced over mDNS");
    }
    let join = runtime.spawn(event_loop.run());
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
    /// nothing is announced any more), fails pending requests and dials with
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
    connections: Vec<(ConnectionId, Multiaddr)>,
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
    pending_requests: HashMap<OutboundRequestId, oneshot::Sender<Result<Response, NetError>>>,
    tasks: JoinSet<HandlerOutput>,
    shutdown_acks: Vec<oneshot::Sender<()>>,
    /// Set once shutdown has begun: new inbound requests are refused.
    stopping: bool,
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

impl EventLoop {
    async fn run(mut self) {
        let mut prune = tokio::time::interval(PRUNE_INTERVAL);
        prune.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
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
            }
        }
        self.shutdown().await;
    }

    async fn shutdown(mut self) {
        tracing::info!(peer = %self.swarm.local_peer_id(), "network shutting down");
        self.stopping = true;
        // First, so that the node is no longer announced while connections close.
        self.swarm.behaviour_mut().discovery.stop();
        self.commands.close();
        while let Ok(cmd) = self.commands.try_recv() {
            self.reject_command(cmd);
        }
        self.tasks.abort_all();
        for (_, tx) in self.pending_requests.drain() {
            let _ = tx.send(Err(NetError::Shutdown));
        }
        for (_, tx) in self.pending_dials.drain() {
            let _ = tx.send(Err(NetError::Shutdown));
        }
        let peers: Vec<PeerId> = self.peers.keys().copied().collect();
        for p in peers {
            let _ = self.swarm.disconnect_peer_id(p);
        }
        let deadline = tokio::time::sleep(SHUTDOWN_GRACE);
        tokio::pin!(deadline);
        while !self.peers.is_empty() {
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
            Command::Shutdown { reply } => self.shutdown_acks.push(reply),
            // Dropping the reply sender makes the caller see `Shutdown`.
            Command::ConnectedPeers { .. }
            | Command::PeerInfo { .. }
            | Command::Disconnect { .. }
            | Command::Discovered { .. } => {}
        }
    }

    fn info_of(&self, peer: &PeerId, connection: Option<ConnectionId>) -> Option<PeerInfo> {
        let entry = self.peers.get(peer)?;
        let addr = connection
            .and_then(|c| entry.connections.iter().find(|(id, _)| *id == c))
            .or_else(|| entry.connections.first())
            .map(|(_, a)| a.clone());
        Some(PeerInfo {
            peer_id: *peer,
            device_key: entry.device_key,
            remote_addr: addr,
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
                if !self.swarm.is_connected(&peer) {
                    let _ = reply.send(Err(NetError::NotConnected));
                    return;
                }
                let id = self
                    .swarm
                    .behaviour_mut()
                    .rr
                    .send_request(&peer, RequestFrame::Encoded(body));
                tracing::debug!(peer = %peer, request = %id, "outbound request");
                self.pending_requests.insert(id, reply);
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
                let was = self.swarm.disconnect_peer_id(peer).is_ok();
                let _ = reply.send(was);
            }
            Command::Discovered { reply } => {
                let _ = reply.send(self.swarm.behaviour().discovery.snapshot());
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
                    .addresses(vec![addr])
                    .condition(PeerCondition::Always)
                    .build()
            }
            None => DialOpts::unknown_peer_id().address(addr).build(),
        };
        let connection_id = opts.connection_id();
        match self.swarm.dial(opts) {
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
                let Some(device_key) = device_key_from_peer_id(&peer_id) else {
                    // Defence in depth: the policy behaviour already refuses these.
                    tracing::warn!(peer = %peer_id, "closing connection with unsupported identity");
                    self.swarm.close_connection(connection_id);
                    if let Some(tx) = self.pending_dials.remove(&connection_id) {
                        let _ = tx.send(Err(NetError::Dial));
                    }
                    return;
                };
                let remote_addr = endpoint.get_remote_address().clone();
                let entry = self.peers.entry(peer_id).or_insert_with(|| PeerEntry {
                    device_key,
                    connections: Vec::new(),
                });
                entry.connections.push((connection_id, remote_addr.clone()));
                let first = entry.connections.len() == 1;
                tracing::debug!(peer = %peer_id, connection = %connection_id, "connection established");
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
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                ..
            } => {
                tracing::debug!(peer = %peer_id, connection = %connection_id, "connection closed");
                let mut gone = false;
                if let Some(entry) = self.peers.get_mut(&peer_id) {
                    entry.connections.retain(|(id, _)| *id != connection_id);
                    gone = entry.connections.is_empty();
                }
                if gone {
                    self.peers.remove(&peer_id);
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
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::debug!("listen address active");
                let a = address.clone();
                self.listen.send_modify(|s| {
                    if !s.addrs.contains(&a) {
                        s.addrs.push(a);
                    }
                });
                self.emit(NetEvent::ListenAddr(address));
            }
            SwarmEvent::ExpiredListenAddr { address, .. } => {
                self.listen
                    .send_modify(|s| s.addrs.retain(|x| *x != address));
                self.emit(NetEvent::ListenAddrExpired(address));
            }
            SwarmEvent::ListenerClosed { addresses, .. } => {
                tracing::warn!(count = addresses.len(), "listener closed");
                self.listen.send_modify(|s| {
                    s.addrs.retain(|x| !addresses.contains(x));
                    s.open_listeners = s.open_listeners.saturating_sub(1);
                });
                for a in addresses {
                    self.emit(NetEvent::ListenAddrExpired(a));
                }
            }
            SwarmEvent::ListenerError { .. } => tracing::warn!("listener error"),
            _ => {}
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
                } => self.on_inbound(peer, connection_id, request_id, request, channel),
                Message::Response {
                    request_id,
                    response,
                } => {
                    let Some(tx) = self.pending_requests.remove(&request_id) else {
                        return;
                    };
                    let result = match response {
                        ResponseFrame::Decoded(r) => Ok(r),
                        ResponseFrame::Encoded(b) => {
                            Response::from_bytes(&b).map_err(|_| NetError::Codec)
                        }
                    };
                    let _ = tx.send(result);
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
                if let Some(tx) = self.pending_requests.remove(&request_id) {
                    let _ = tx.send(Err(e));
                }
            }
            request_response::Event::InboundFailure {
                peer, request_id, ..
            } => {
                tracing::debug!(peer = %peer, request = %request_id, "inbound request failed");
            }
            request_response::Event::ResponseSent { .. } => {}
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
