//! Running this node on the network: the QUIC transport from `ph-network`, the request
//! handler from `peer`, and a two-way sync with one peer.
//!
//! # Shape
//!
//! * One **node thread** owns the [`Node`] (store, keystore, unlocked keys). Everything
//!   that touches the database or signs runs there, one job at a time, so requests from
//!   several peers never interleave inside a transaction and the keys are unlocked once.
//!   The async side reaches it through [`Worker::call`].
//! * The transport runs on the Tokio runtime. Each inbound request becomes one job on
//!   the node thread ([`peer::answer`]), after which the circles that received new events
//!   are settled: results published, a passed amendment notarized on the founder's node,
//!   the rules in force applied.
//! * There is no gossip. A node sends and receives when its owner runs `sync`, when a
//!   peer syncs with its running `daemon`, or when the owner started the daemon with a
//!   sync interval; then it syncs with the peers it already knows and with nobody else.
//! * Each side remembers how far it got with the other (a cursor per peer and circle),
//!   so a sync transfers what is new and not the whole log.
//!
//! The transport authenticates device keys. What a key may have is decided per request
//! from the roll (see `peer`).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ph_core::{CircleId, DeviceKey, Digest, EventId, MembershipOracle};
use ph_network::{handler_fn, Multiaddr, NetEvent, NetworkConfig, NetworkHandle, PeerId, PeerInfo};
use ph_protocol::limits::MAX_FETCH_LIMIT;
use ph_protocol::wire::{ErrorCode, PushStatus, Request, Response, PROTOCOL_VERSION};
use serde_json::{json, Value};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::error::{refused, usage, CliError};
use crate::governance;
use crate::home::Home;
use crate::node::Node;
use crate::peer;

/// Most `fetch_events` rounds for one circle in one sync.
const MAX_FETCH_ROUNDS: usize = 64;

/// How long an answer waits for this node's own fetch-back from the same peer.
const PULL_WAIT: Duration = Duration::from_secs(15);

/// Most events a sync keeps aside while the records they depend on have not arrived.
const MAX_POOL_EVENTS: usize = 8192;

/// How long a sync waits for a connection through a relay to be replaced by a direct
/// one before it goes on over the relay. Long enough for the first attempt, which is
/// the one that works where the networks allow it at all (measured: about three
/// seconds); the transport keeps trying while the exchange runs.
const UPGRADE_WAIT: Duration = Duration::from_secs(6);

/// How many devices one internet sync looks up at the same time (the transport allows
/// [`ph_network::internet::MAX_CONCURRENT_FINDS`] lookups in flight).
const FINDS_AT_ONCE: usize = 6;

/// The most devices one internet sync looks up. A node whose rolls list more looks the
/// first ones up and says how many it left out.
const MAX_DEVICES_LOOKED_UP: usize = 128;

/// How many of the addresses found for a device are tried.
const MAX_ADDRS_TRIED: usize = 6;

/// What a person is told when an exchange failed on a connection through a relay.
const RELAY_LIMIT: &str = "the connection to that peer goes through a public relay, which      carries about 128 KiB and two minutes per connection, and a direct connection could      not be made (the networks in between do not allow it). What arrived is kept, and the      next sync goes on from there. For a dependable link, one member's node needs an      address the others can reach.";

type Job = Box<dyn FnOnce(&Node) + Send + 'static>;

/// A handle to the node thread.
#[derive(Clone)]
pub struct Worker {
    tx: std::sync::mpsc::Sender<Job>,
}

impl Worker {
    /// Starts the node thread: opens the node and unlocks the device key (which may ask
    /// for the key file's passphrase on the terminal). Returns the worker, the seed for
    /// the transport identity and the device key.
    pub fn spawn(home: Home) -> Result<(Self, Zeroizing<[u8; 32]>, DeviceKey)> {
        let (tx, rx) = std::sync::mpsc::channel::<Job>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("peerharness-node".into())
            .spawn(move || {
                let node = match Node::open(&home) {
                    Ok(n) => n,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let unlocked = node
                    .device()
                    .map(|d| (d.libp2p_seed(), d.public()))
                    .context("cannot unlock the device key");
                let ok = unlocked.is_ok();
                let _ = ready_tx.send(unlocked);
                if !ok {
                    return;
                }
                while let Ok(job) = rx.recv() {
                    job(&node);
                }
            })
            .context("cannot start the node thread")?;
        let (seed, key) = ready_rx
            .recv()
            .map_err(|_| anyhow!("the node thread stopped while starting"))??;
        Ok((Self { tx }, seed, key))
    }

    /// Runs `f` on the node thread and returns its result.
    pub async fn call<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Node) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Box::new(move |node: &Node| {
                let _ = tx.send(f(node));
            }))
            .map_err(|_| anyhow!("the node thread has stopped"))?;
        rx.await
            .map_err(|_| anyhow!("the node thread dropped a job"))?
    }
}

/// State shared between the request handler and a running sync.
#[derive(Default)]
struct Shared {
    /// For each peer, the task that fetches back the rule texts of what that peer just
    /// pushed and then settles. The peer's next request waits for it, so what settling
    /// produced here (a result, a new charter) is there when the peer fetches again.
    pulls: tokio::sync::Mutex<HashMap<PeerId, JoinHandle<()>>>,
    /// The transport, once started (the handler needs it to fetch bundles back).
    net: OnceLock<NetworkHandle>,
}

/// What settling circles on the node thread changed, for the report.
#[derive(Debug, Default, Clone)]
pub struct Changes {
    pub installed: Vec<String>,
    pub removed: Vec<String>,
    pub asking: Vec<String>,
    pub charters_issued: Vec<u64>,
    /// Events this node signed while settling (results and charters).
    pub signed: usize,
}

impl Changes {
    fn absorb(&mut self, other: Changes) {
        self.installed.extend(other.installed);
        self.removed.extend(other.removed);
        self.asking.extend(other.asking);
        self.charters_issued.extend(other.charters_issued);
        self.signed += other.signed;
    }

    /// Whether anything visible to the owner happened.
    pub fn is_empty(&self) -> bool {
        self.installed.is_empty()
            && self.removed.is_empty()
            && self.asking.is_empty()
            && self.charters_issued.is_empty()
    }
}

/// Settles `circles` on the node thread. A circle that cannot be settled is logged and
/// skipped: its events are stored either way and the next command settles it.
fn settle_circles(node: &Node, circles: &BTreeSet<CircleId>) -> Result<Changes> {
    let installer = governance::user_installer()?;
    let mut changes = Changes::default();
    for id in circles {
        let Some(circle) = node.store.circle(id)? else {
            continue;
        };
        match governance::settle(node, &circle, &installer, &[]) {
            Ok(settled) => {
                changes.signed += settled.results_published.len();
                if let Some(seq) = settled.charter_notarized {
                    changes.charters_issued.push(seq);
                    changes.signed += 1;
                }
                changes.installed.extend(settled.applied.installed);
                changes.removed.extend(settled.applied.removed);
                changes
                    .asking
                    .extend(settled.applied.asking.into_iter().map(|(name, _)| name));
            }
            Err(e) => tracing::warn!(error = %e, "could not settle a circle after a sync"),
        }
    }
    Ok(changes)
}

/// The request handler: one job on the node thread per request.
fn handler(worker: Worker, shared: Arc<Shared>) -> Arc<dyn ph_network::RequestHandler> {
    handler_fn(move |info: PeerInfo, request: Request| {
        let worker = worker.clone();
        let shared = shared.clone();
        async move {
            let device = info.device_key;
            let peer_id = info.peer_id;
            // Everything but a greeting and the fetch-back itself waits for this node's
            // fetch-back from the same peer to finish (see `Shared::pulls`).
            if !matches!(request, Request::Hello { .. } | Request::FetchBundle { .. }) {
                let pending = shared.pulls.lock().await.remove(&peer_id);
                if let Some(task) = pending {
                    let _ = tokio::time::timeout(PULL_WAIT, task).await;
                }
            }
            let answered = worker
                .call(move |node| {
                    let bundles = crate::library::bundle_store(&node.home);
                    let answer = peer::answer(
                        &node.store,
                        &bundles,
                        &device,
                        &peer_id.to_string(),
                        request,
                        node.now(),
                    )?;
                    // With bundles still to fetch, settling waits until they are here.
                    if answer.pulls.is_empty() && !answer.touched.is_empty() {
                        settle_circles(node, &answer.touched)?;
                    }
                    Ok(answer)
                })
                .await;
            match answered {
                Ok(answer) => {
                    if !answer.pulls.is_empty() {
                        let task = tokio::spawn(pull_then_settle(
                            worker,
                            shared.clone(),
                            peer_id,
                            answer.pulls,
                            answer.touched,
                        ));
                        shared.pulls.lock().await.insert(peer_id, task);
                    }
                    answer.response
                }
                Err(e) => {
                    tracing::warn!(error = %e, "a peer request could not be answered");
                    Response::error(ErrorCode::Unavailable)
                }
            }
        }
    })
}

/// Fetches from `peer` the bundles this node lacks for proposals it just accepted from
/// that peer, then settles the circles concerned.
async fn pull_then_settle(
    worker: Worker,
    shared: Arc<Shared>,
    peer: PeerId,
    pulls: Vec<(CircleId, Digest)>,
    touched: BTreeSet<CircleId>,
) {
    if let Some(net) = shared.net.get() {
        for (circle, digest) in pulls {
            let _ = fetch_bundle(&worker, net, peer, circle, digest).await;
        }
    }
    let _ = worker
        .call(move |node| settle_circles(node, &touched))
        .await;
}

/// Asks `peer` for one bundle and stores it if it is the one a proposal names.
async fn fetch_bundle(
    worker: &Worker,
    net: &NetworkHandle,
    peer: PeerId,
    circle: CircleId,
    digest: Digest,
) -> Result<bool> {
    let response = net
        .request(
            peer,
            &Request::FetchBundle {
                circle_id: circle,
                digest,
            },
        )
        .await
        .map_err(|e| anyhow!("cannot fetch a bundle: {e}"))?;
    let Response::Bundle {
        digest: got, files, ..
    } = response
    else {
        return Ok(false);
    };
    if got != digest {
        return Ok(false);
    }
    worker
        .call(move |node| {
            let bundles = crate::library::bundle_store(&node.home);
            peer::store_bundle(&node.store, &bundles, &circle, &digest, &files, node.now())
        })
        .await
}

/// This node, running on the network.
pub struct Running {
    pub worker: Worker,
    pub net: NetworkHandle,
    pub device_key: DeviceKey,
    /// Whether this node tells a peer where it listens when it announces itself.
    announce_addrs: bool,
    join: JoinHandle<()>,
}

impl Running {
    /// Starts the node thread and the transport. Must be called inside a Tokio runtime.
    /// With no `listen` addresses the node only dials.
    pub fn start(home: Home, config: NetworkConfig) -> Result<Self> {
        let (worker, seed, device_key) = Worker::spawn(home)?;
        let shared = Arc::new(Shared::default());
        let (net, join) = ph_network::start(seed, config, handler(worker.clone(), shared.clone()))
            .map_err(|e| anyhow!("cannot start the transport: {e}"))?;
        let _ = shared.net.set(net.clone());
        Ok(Self {
            worker,
            net,
            device_key,
            announce_addrs: true,
            join,
        })
    }

    /// For a node that listens only for the length of one command (a hole punch needs
    /// a socket): where it listens is of no use to a peer afterwards, so it does not
    /// say.
    pub fn passing(mut self) -> Self {
        self.announce_addrs = false;
        self
    }

    /// Stops the transport and waits for its event loop.
    pub async fn stop(self) {
        self.net.shutdown().await;
        let _ = self.join.await;
    }

    /// The addresses this node listens on, each ending in `/p2p/<peer id>`.
    pub async fn dialable_addrs(&self) -> Result<Vec<String>> {
        let peer = self.net.local_peer_id();
        Ok(self
            .net
            .listen_addrs()
            .await
            .map_err(|e| anyhow!("cannot read the listen addresses: {e}"))?
            .iter()
            .map(|a| ph_network::with_p2p(a, peer).to_string())
            .collect())
    }
}

/// What one sync did.
#[derive(Debug, Default, Clone)]
pub struct SyncReport {
    pub peer_id: String,
    pub circles: usize,
    /// New events received and stored.
    pub received: usize,
    /// Rule texts received.
    pub bundles: usize,
    /// Events the peer did not have and accepted.
    pub sent: usize,
    /// Events the peer refused.
    pub refused_by_peer: usize,
    /// Circles this node learned it was voted off, by name.
    pub removed_from: Vec<String>,
    /// Circles this node holds with the peer on the roll in which the peer does not
    /// recognize this node, and gave no verifiable reason.
    pub not_recognized: Vec<String>,
    /// Whether the exchange ran through a relay (internet mode, no direct connection).
    pub relayed: bool,
    pub changes: Changes,
}

/// Dials `addr` and exchanges greetings. Nothing else is sent to a peer that does not
/// speak this node's protocol version.
async fn greet(run: &Running, addr: &Multiaddr) -> Result<(PeerId, DeviceKey)> {
    // Subscribed before the dial, so that the outcome of the upgrade is not missed.
    let mut events = ph_network::is_relayed(addr).then(|| run.net.subscribe());
    let peer = run
        .net
        .dial(addr.clone())
        .await
        .map_err(|e| anyhow!("cannot reach that address: {e}"))?;
    let peer_key = ph_network::device_key_from_peer_id(&peer)
        .ok_or_else(|| anyhow!("the peer's identity is not a device key"))?;
    match run.net.request(peer, &Request::hello()).await {
        Ok(Response::Hello { versions, .. }) if versions.iter().any(|v| v == PROTOCOL_VERSION) => {}
        Ok(Response::Hello { .. }) => {
            return Err(anyhow!(
                "the peer speaks a different protocol version (this node speaks {PROTOCOL_VERSION})"
            ))
        }
        Ok(_) => return Err(anyhow!("the peer did not answer hello")),
        Err(e) => return Err(anyhow!("the peer does not speak this protocol: {e}")),
    }
    if let Some(events) = events.as_mut() {
        wait_for_direct(run, peer, events).await;
    }
    Ok((peer, peer_key))
}

/// Whether the connection to `peer` goes through a relay.
async fn via_relay(run: &Running, peer: PeerId) -> bool {
    matches!(run.net.peer_info(peer).await, Ok(Some(info)) if info.relayed)
}

/// After a dial through a relay: waits, for at most [`UPGRADE_WAIT`], until the
/// transport has replaced the relayed connection with a direct one or has given up. A
/// relay of the public network carries little, so the exchange is worth that wait.
async fn wait_for_direct(
    run: &Running,
    peer: PeerId,
    events: &mut tokio::sync::broadcast::Receiver<NetEvent>,
) {
    use tokio::sync::broadcast::error::RecvError;
    let deadline = tokio::time::Instant::now() + UPGRADE_WAIT;
    while via_relay(run, peer).await {
        match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Ok(NetEvent::DirectUpgradeSucceeded { peer_id })) if peer_id == peer => {
                // The relayed connection is closed a moment later; requests already go
                // over the direct one.
                return;
            }
            Ok(Ok(NetEvent::DirectUpgradeFailed { peer_id })) if peer_id == peer => return,
            Ok(Ok(_)) | Ok(Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) | Err(_) => return,
        }
    }
}

/// Announces this node to `peer`. Returns the circles in which the peer has this
/// node's device on the roll, or `None` when it has it on none.
async fn announce(run: &Running, peer: PeerId) -> Result<Option<Vec<CircleId>>> {
    let listen: Vec<String> = if run.announce_addrs {
        run.net
            .current_listen_addrs()
            .iter()
            .map(|a| ph_network::with_p2p(a, run.net.local_peer_id()).to_string())
            .collect()
    } else {
        Vec::new()
    };
    let request = Request::Authenticate {
        memberships: Vec::new(),
        listen_addrs: listen,
    };
    match run.net.request(peer, &request).await {
        Ok(Response::Authenticated { circles, .. }) => Ok(Some(circles)),
        Ok(Response::Error {
            code: ErrorCode::Unauthorized,
        }) => Ok(None),
        Ok(_) | Err(_) => Err(anyhow!("the peer did not complete the handshake")),
    }
}

/// The circles this node holds in which both it and `peer_key` are on the roll.
async fn circles_with(run: &Running, peer_key: DeviceKey) -> Result<Vec<CircleId>> {
    let me = run.device_key;
    run.worker
        .call(move |node| Ok(peer::roll_oracle(&node.store)?.shared_circles(&me, &peer_key)))
        .await
}

async fn remember(
    run: &Running,
    addr: &Multiaddr,
    peer: PeerId,
    peer_key: DeviceKey,
    circles: Vec<CircleId>,
) -> Result<()> {
    // An address through a relay names a reservation that ends with the peer's
    // process: it is found again when needed, not stored.
    let dialed: Vec<String> = if ph_network::is_relayed(addr) {
        Vec::new()
    } else {
        vec![ph_network::with_p2p(addr, peer).to_string()]
    };
    run.worker
        .call(move |node| {
            peer::remember_peer(
                &node.store,
                &peer.to_string(),
                &peer_key,
                &dialed,
                &circles,
                node.now(),
            )
        })
        .await
}

/// Connects to `addr` and checks who answered: returns the peer and the circles in
/// which both it and this node are on the roll, each by its own records. Nothing
/// circle-specific is sent to a peer that shares no circle with this node.
pub async fn connect(
    run: &Running,
    addr: &Multiaddr,
) -> Result<(PeerId, DeviceKey, Vec<CircleId>)> {
    let (peer, peer_key) = greet(run, addr).await?;
    let mine = circles_with(run, peer_key).await?;
    if mine.is_empty() {
        return Err(refused(
            "that peer and this node share no circle (each must be on the roll the other \
             holds). Nothing was exchanged.",
        ));
    }
    let Some(theirs) = announce(run, peer).await? else {
        return Err(refused(
            "the peer does not recognize this node as a member of any circle it holds. \
             Nothing was exchanged.",
        ));
    };
    let shared = both(&mine, &theirs);
    if shared.is_empty() {
        return Err(refused(
            "the peer does not recognize this node in any circle you hold with it. Nothing \
             was exchanged.",
        ));
    }
    remember(run, addr, peer, peer_key, shared.clone()).await?;
    Ok((peer, peer_key, shared))
}

/// The circles of `mine` that the peer also named. A peer that names none (one that
/// predates the list) is taken to mean all of them.
fn both(mine: &[CircleId], theirs: &[CircleId]) -> Vec<CircleId> {
    if theirs.is_empty() {
        return mine.to_vec();
    }
    mine.iter()
        .filter(|c| theirs.contains(c))
        .copied()
        .collect()
}

fn unauthorized(response: &Response) -> bool {
    matches!(
        response,
        Response::Error {
            code: ErrorCode::Unauthorized
        }
    )
}

/// Fetches what the peer stored of `circle` since the last sync with it. Returns the
/// number of events stored here.
///
/// The peer serves its log in the order it stored it, from the cursor this node kept.
/// An event that cannot be placed yet stays in a pool and is offered again with each
/// later batch. The cursor is only moved forward when nothing is left in the pool, so
/// an event is never skipped for good because of the order it arrived in.
async fn fetch_events(run: &Running, peer: PeerId, circle: CircleId) -> Result<usize> {
    let peer_s = peer.to_string();
    let who = peer_s.clone();
    let mut after = run
        .worker
        .call(move |node| {
            Ok(node
                .store
                .sync_cursor(&who, &circle)?
                .and_then(|c| c.after_event_id))
        })
        .await?;
    let mut pool: Vec<Value> = Vec::new();
    let mut stored = 0;
    for _ in 0..MAX_FETCH_ROUNDS {
        let known = run
            .worker
            .call(move |node| peer::known_ids(&node.store, &circle, node.now()))
            .await?;
        let request = Request::FetchEvents {
            circle_id: circle,
            known,
            limit: MAX_FETCH_LIMIT,
            after,
        };
        let response = run
            .net
            .request(peer, &request)
            .await
            .map_err(|e| anyhow!("cannot fetch events: {e}"))?;
        if unauthorized(&response) {
            return Err(refused(
                "the peer no longer recognizes this node as a member of that circle",
            ));
        }
        let Response::Events { events, more } = response else {
            return Err(anyhow!("the peer answered a fetch with something else"));
        };
        let last: Option<EventId> = events.last().and_then(|v| peer::field(v, "event_id"));
        let mut batch = std::mem::take(&mut pool);
        batch.extend(events);
        let origin = peer_s.clone();
        let (ingested, kept) = run
            .worker
            .call(move |node| {
                let only: HashSet<CircleId> = [circle].into();
                let ingested = peer::ingest_values(
                    &node.store,
                    &batch,
                    Some(&only),
                    Some(&origin),
                    node.now(),
                )?;
                let kept: Vec<Value> = ingested
                    .deferred
                    .iter()
                    .filter_map(|i| batch.get(*i).cloned())
                    .collect();
                Ok((ingested.stored, kept))
            })
            .await?;
        stored += ingested;
        pool = kept;
        let Some(last) = last else { break };
        after = Some(last);
        // Kept after every batch that left nothing in the pool, so that a connection
        // that ends early (a relay's limit) does not cost what already arrived.
        if pool.is_empty() {
            let who = peer_s.clone();
            run.worker
                .call(move |node| {
                    Ok(node.store.advance_sync_cursor(
                        &who,
                        &circle,
                        Some(&last),
                        None,
                        node.now(),
                    )?)
                })
                .await?;
        }
        if !more || pool.len() > MAX_POOL_EVENTS {
            break;
        }
    }
    Ok(stored)
}

/// Fetches the rule texts this node lacks for the circle's proposals.
async fn fetch_bundles(run: &Running, peer: PeerId, circle: CircleId) -> Result<usize> {
    let missing = run
        .worker
        .call(move |node| {
            let bundles = crate::library::bundle_store(&node.home);
            peer::missing_bundles(&node.store, &bundles, &circle)
        })
        .await?;
    let mut stored = 0;
    for digest in missing {
        if fetch_bundle(&run.worker, &run.net, peer, circle, digest)
            .await
            .unwrap_or(false)
        {
            stored += 1;
        }
    }
    Ok(stored)
}

/// Pushes what the peer may read of `circle` and has not taken yet. Returns
/// `(accepted, refused)`.
///
/// The push cursor moves past everything up to the first event the peer refused: a
/// refusal may only mean that the peer lacks a record the event depends on, so that
/// event and what follows it are offered again next time.
async fn push_events(
    run: &Running,
    peer: PeerId,
    peer_key: DeviceKey,
    circle: CircleId,
) -> Result<(usize, usize)> {
    let peer_s = peer.to_string();
    let who = peer_s.clone();
    let outgoing = run
        .worker
        .call(move |node| {
            let after = node
                .store
                .sync_cursor(&who, &circle)?
                .and_then(|c| c.pushed_event_id);
            peer::outgoing_batches(&node.store, &circle, &peer_key, after.as_ref(), node.now())
        })
        .await?;
    let (mut accepted, mut rejected) = (0, 0);
    let mut taken: Option<EventId> = None;
    let mut blocked = false;
    for events in outgoing.batches {
        let ids: Vec<Option<EventId>> = events.iter().map(|v| peer::field(v, "event_id")).collect();
        let response = run
            .net
            .request(peer, &Request::PushEvents { events })
            .await
            .map_err(|e| anyhow!("cannot send events: {e}"))?;
        if unauthorized(&response) {
            return Err(refused(
                "the peer no longer recognizes this node as a member of that circle",
            ));
        }
        let Response::PushResult { results } = response else {
            return Err(anyhow!("the peer answered a push with something else"));
        };
        if results.len() != ids.len() {
            return Err(anyhow!(
                "the peer answered a push with the wrong number of results"
            ));
        }
        for (id, r) in ids.into_iter().zip(results) {
            match r.status {
                PushStatus::Accepted => accepted += 1,
                PushStatus::Duplicate => {}
                PushStatus::Rejected => {
                    rejected += 1;
                    blocked = true;
                }
            }
            if !blocked {
                taken = id.or(taken);
            }
        }
    }
    let cursor = if blocked { taken } else { outgoing.last_seen };
    if let Some(cursor) = cursor {
        run.worker
            .call(move |node| {
                Ok(node.store.advance_sync_cursor(
                    &peer_s,
                    &circle,
                    None,
                    Some(&cursor),
                    node.now(),
                )?)
            })
            .await?;
    }
    Ok((accepted, rejected))
}

/// The full exchange for one circle both sides recognize.
async fn exchange(
    run: &Running,
    peer: PeerId,
    peer_key: DeviceKey,
    circle: CircleId,
    report: &mut SyncReport,
) -> Result<()> {
    let only: BTreeSet<CircleId> = [circle].into();
    report.received += fetch_events(run, peer, circle).await?;
    report.bundles += fetch_bundles(run, peer, circle).await?;
    let settle = only.clone();
    let changes = run
        .worker
        .call(move |node| settle_circles(node, &settle))
        .await?;
    report.changes.absorb(changes);

    let (accepted, rejected) = push_events(run, peer, peer_key, circle).await?;
    report.sent += accepted;
    report.refused_by_peer += rejected;

    // What the exchange produced over there. The peer answers this only after it has
    // fetched the rule texts of what was just pushed and settled (`Shared::pulls`).
    report.received += fetch_events(run, peer, circle).await?;
    report.bundles += fetch_bundles(run, peer, circle).await?;
    let changes = run
        .worker
        .call(move |node| settle_circles(node, &only))
        .await?;
    let signed = changes.signed;
    report.changes.absorb(changes);
    if signed > 0 {
        // This node just signed a result or a charter: the peer should have it too.
        let (accepted, rejected) = push_events(run, peer, peer_key, circle).await?;
        report.sent += accepted;
        report.refused_by_peer += rejected;
    }
    Ok(())
}

/// For a circle this node holds with the peer on the roll, in which the peer does not
/// recognize this node: asks why. A peer that saw this node voted off answers with the
/// records of that vote, which this node verifies like any others (`governance::ingest`:
/// the charter must be signed by the root and justified by a passed amendment). Returns
/// whether this node is off the roll afterwards, and what that took off this machine.
async fn learn_of_removal(
    run: &Running,
    peer: PeerId,
    circle: CircleId,
) -> Result<(bool, Changes)> {
    let origin = peer.to_string();
    for _ in 0..MAX_FETCH_ROUNDS {
        let known = run
            .worker
            .call(move |node| peer::known_ids(&node.store, &circle, node.now()))
            .await?;
        let request = Request::FetchEvents {
            circle_id: circle,
            known,
            limit: MAX_FETCH_LIMIT,
            after: None,
        };
        let Ok(Response::Events { events, more }) = run.net.request(peer, &request).await else {
            break;
        };
        if events.is_empty() {
            break;
        }
        let from = origin.clone();
        let stored =
            run.worker
                .call(move |node| {
                    let only: HashSet<CircleId> = [circle].into();
                    Ok(peer::ingest_values(
                        &node.store,
                        &events,
                        Some(&only),
                        Some(&from),
                        node.now(),
                    )?
                    .stored)
                })
                .await?;
        if stored == 0 || !more {
            break;
        }
    }
    let me = run.device_key;
    run.worker
        .call(move |node| {
            let off = !peer::roll_oracle(&node.store)?.is_active_member(&circle, &me, node.now());
            // Nothing of that circle binds this node any more.
            let changes = if off {
                settle_circles(node, &[circle].into())?
            } else {
                Changes::default()
            };
            Ok((off, changes))
        })
        .await
}

/// A two-way sync with the peer at `addr`: fetch what it has, send what it lacks, let it
/// fetch the rule texts, settle, and fetch once more for what the exchange produced on
/// its side (a result, a new charter).
pub async fn sync(run: &Running, addr: &Multiaddr) -> Result<SyncReport> {
    let (peer, peer_key) = greet(run, addr).await?;
    let relayed = via_relay(run, peer).await;
    match sync_greeted(run, addr, peer, peer_key).await {
        Ok(mut report) => {
            report.relayed = relayed;
            Ok(report)
        }
        // A refusal is an answer: the relay had nothing to do with it.
        Err(e) if relayed && e.downcast_ref::<CliError>().is_none() => {
            Err(anyhow!("{e}: {RELAY_LIMIT}"))
        }
        Err(e) => Err(e),
    }
}

async fn sync_greeted(
    run: &Running,
    addr: &Multiaddr,
    peer: PeerId,
    peer_key: DeviceKey,
) -> Result<SyncReport> {
    let mine = circles_with(run, peer_key).await?;
    if mine.is_empty() {
        return Err(refused(
            "that peer and this node share no circle (each must be on the roll the other \
             holds). Nothing was exchanged. If you were just admitted to a circle that node \
             holds: `peerharness circle join <its address> --expect-fingerprint <fingerprint>`.",
        ));
    }
    let theirs = announce(run, peer).await?;
    let shared = theirs
        .as_deref()
        .map(|t| both(&mine, t))
        .unwrap_or_default();
    // A list at its maximum may have been cut short: a circle missing from it then says
    // nothing about this node's membership there.
    let cut_short = theirs
        .as_ref()
        .is_some_and(|t| t.len() >= ph_protocol::limits::MAX_SHARED_CIRCLES);
    let mut report = SyncReport {
        peer_id: peer.to_string(),
        circles: shared.len(),
        ..SyncReport::default()
    };
    if !shared.is_empty() {
        remember(run, addr, peer, peer_key, shared.clone()).await?;
    }
    for circle in &shared {
        exchange(run, peer, peer_key, *circle, &mut report).await?;
    }
    // Circles this node believes it shares with the peer, and the peer does not.
    for circle in mine.iter().filter(|c| !shared.contains(c) && !cut_short) {
        let circle = *circle;
        let (off, changes) = learn_of_removal(run, peer, circle).await?;
        let name = run
            .worker
            .call(move |node| {
                Ok(node
                    .store
                    .circle(&circle)?
                    .map_or_else(|| circle.to_string(), |c| c.name))
            })
            .await?;
        report.changes.absorb(changes);
        if off {
            report.removed_from.push(name);
        } else {
            report.not_recognized.push(name);
        }
    }
    if shared.is_empty() && report.removed_from.is_empty() {
        return Err(refused(
            "the peer does not recognize this node as a member of any circle it holds. \
             Nothing was exchanged.",
        ));
    }
    Ok(report)
}

/// A circle a peer offered to a device it has on that circle's roll, before the device
/// holds the circle itself: everything needed to check the roll and join.
pub struct Offered {
    pub circle: CircleId,
    /// One `{"event": …}` line per event, unverified, as `events export` writes them.
    pub lines: Vec<String>,
    /// The last event the peer served (the cursor for later syncs).
    pub last: Option<EventId>,
}

/// Asks the peer at `addr` which circles it has this node's device on the roll of, and
/// fetches the records of those this node does not hold yet. Nothing is stored: the
/// caller shows the owner the charter and joins only on their confirmation.
///
/// Before that confirmation this node has sent a greeting, an announcement without
/// addresses, and the circle ids the peer itself just named.
pub async fn fetch_for_join(run: &Running, addr: &Multiaddr) -> Result<(PeerId, Vec<Offered>)> {
    let (peer, _) = greet(run, addr).await?;
    let request = Request::Authenticate {
        memberships: Vec::new(),
        listen_addrs: Vec::new(),
    };
    let circles = match run.net.request(peer, &request).await {
        Ok(Response::Authenticated { circles, .. }) => circles,
        Ok(Response::Error {
            code: ErrorCode::Unauthorized,
        }) => {
            return Err(refused(
                "that node does not have this device on the roll of any circle it holds. \
                 Has your admission passed, and has that node received it? (It must hold \
                 the charter that lists your device key.)",
            ))
        }
        Ok(_) | Err(_) => return Err(anyhow!("the peer did not complete the handshake")),
    };
    let held: HashSet<CircleId> = run
        .worker
        .call(|node| {
            Ok(node
                .store
                .circles()?
                .into_iter()
                .map(|c| c.circle_id)
                .collect())
        })
        .await?;
    let mut offered = Vec::new();
    let mut bytes: u64 = 0;
    for circle in circles.into_iter().filter(|c| !held.contains(c)) {
        let mut lines = Vec::new();
        let mut after = None;
        for _ in 0..MAX_FETCH_ROUNDS * 4 {
            let request = Request::FetchEvents {
                circle_id: circle,
                known: Vec::new(),
                limit: MAX_FETCH_LIMIT,
                after,
            };
            let response = run
                .net
                .request(peer, &request)
                .await
                .map_err(|e| anyhow!("cannot fetch the circle's records: {e}"))?;
            let Response::Events { events, more } = response else {
                break;
            };
            let Some(last) = events
                .last()
                .and_then(|v| peer::field::<EventId>(v, "event_id"))
            else {
                break;
            };
            for ev in events {
                let line = json!({ "event": ev }).to_string();
                bytes += line.len() as u64;
                if bytes > crate::carrier::MAX_SOURCE_BYTES {
                    return Err(anyhow!(
                        "that circle's records are too large to join from here"
                    ));
                }
                lines.push(line);
            }
            after = Some(last);
            if !more {
                break;
            }
        }
        offered.push(Offered {
            circle,
            lines,
            last: after,
        });
    }
    Ok((peer, offered))
}

/// After a join from the network: remembers the peer and how far its log was read.
pub async fn remember_join(
    run: &Running,
    addr: &Multiaddr,
    peer: PeerId,
    circle: CircleId,
    last: Option<EventId>,
) -> Result<()> {
    let peer_key = ph_network::device_key_from_peer_id(&peer)
        .ok_or_else(|| anyhow!("the peer's identity is not a device key"))?;
    remember(run, addr, peer, peer_key, vec![circle]).await?;
    if let Some(last) = last {
        run.worker
            .call(move |node| {
                Ok(node.store.advance_sync_cursor(
                    &peer.to_string(),
                    &circle,
                    Some(&last),
                    None,
                    node.now(),
                )?)
            })
            .await?;
    }
    Ok(())
}

/// Syncs with every peer this node has an address for, one after the other. For each
/// peer the stored addresses are tried in order until one answers. Returns one entry
/// per peer: its id and what the sync did, or why it failed.
pub async fn sync_known(run: &Running) -> Result<Vec<(String, Result<SyncReport>)>> {
    let peers: Vec<(String, Vec<String>)> = run
        .worker
        .call(|node| {
            Ok(node
                .store
                .peers()?
                .into_iter()
                .filter(|p| !p.blocked && !p.addrs.is_empty())
                .map(|p| (p.peer_id, p.addrs))
                .collect())
        })
        .await?;
    let mut out = Vec::with_capacity(peers.len());
    for (id, addrs) in peers {
        let mut outcome = Err(anyhow!("no usable address is stored for that peer"));
        for addr in addrs.iter().filter_map(|a| a.parse::<Multiaddr>().ok()) {
            outcome = sync(run, &addr).await;
            if outcome.is_ok() {
                break;
            }
        }
        out.push((id, outcome));
    }
    Ok(out)
}

/// How long after the first member was heard a LAN sync keeps listening for more.
const LAN_SETTLE: Duration = Duration::from_millis(700);

/// Syncs with the members of this node's circles that announced themselves on the local
/// network (the transport must have been started with `lan_discovery`). Listens for at
/// most `wait`, then syncs with each member found, skipping the peer ids in `skip`.
///
/// An announcement is an unauthenticated hint. This node dials only device keys that
/// are on a roll it holds, at the announced address with that key's peer id, so the
/// handshake must prove the key; whoever answers is then judged by the roll like any
/// other peer. Devices on no roll of this node are never dialed, so nothing is sent to
/// them, not even a greeting.
pub async fn sync_lan(
    run: &Running,
    wait: Duration,
    skip: &HashSet<String>,
) -> Result<Vec<(String, Result<SyncReport>)>> {
    let deadline = tokio::time::Instant::now() + wait;
    let mut members: Vec<(String, Vec<Multiaddr>)> = Vec::new();
    let mut first_seen: Option<tokio::time::Instant> = None;
    loop {
        let heard = run
            .net
            .discovered()
            .await
            .map_err(|e| anyhow!("cannot read the discovered peers: {e}"))?;
        for (peer, addrs) in heard {
            let id = peer.to_string();
            if skip.contains(&id) || members.iter().any(|(m, _)| *m == id) {
                continue;
            }
            let Some(key) = ph_network::device_key_from_peer_id(&peer) else {
                continue;
            };
            if key == run.device_key || circles_with(run, key).await?.is_empty() {
                continue;
            }
            members.push((id, addrs));
            first_seen.get_or_insert_with(tokio::time::Instant::now);
        }
        let now = tokio::time::Instant::now();
        if now >= deadline || first_seen.is_some_and(|t| now >= t + LAN_SETTLE) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut out = Vec::with_capacity(members.len());
    for (id, addrs) in members {
        let mut outcome = Err(anyhow!("it announced no usable address"));
        for addr in &addrs {
            outcome = sync(run, addr).await;
            if outcome.is_ok() {
                break;
            }
        }
        out.push((id, outcome));
    }
    Ok(out)
}

/// Looks `peer` up on the public network (internet mode). The addresses are hints from
/// strangers, each ending in the peer's id, so a dial succeeds only if the other end
/// proves that key. Direct addresses come first: a relay of the public network carries
/// little.
async fn find(run: &Running, peer: PeerId, wait: Duration) -> Result<Vec<Multiaddr>> {
    let mut addrs = run
        .net
        .find_peer(peer, wait)
        .await
        .map_err(|e| anyhow!("cannot look that device up: {e}"))?;
    addrs.sort_by_key(ph_network::is_relayed);
    addrs.truncate(MAX_ADDRS_TRIED);
    Ok(addrs)
}

/// Syncs with a device at the first of `addrs` that answers. A refusal ends it: the
/// peer answered, and another address of it would say the same.
async fn sync_at(run: &Running, addrs: &[Multiaddr]) -> Result<SyncReport> {
    let mut outcome = Err(anyhow!("no address was found for that device"));
    for addr in addrs {
        outcome = sync(run, addr).await;
        match &outcome {
            Ok(_) => break,
            Err(e) if e.downcast_ref::<CliError>().is_some() => break,
            Err(_) => {}
        }
    }
    outcome
}

/// Finds one device over the public network and syncs with it. The device must be on
/// the roll of a circle this node holds: nothing else is looked up, so the servers of
/// the public network only ever learn of device keys the owner's circles list.
pub async fn sync_found(run: &Running, peer: PeerId, wait: Duration) -> Result<SyncReport> {
    let key = ph_network::device_key_from_peer_id(&peer)
        .ok_or_else(|| usage("that peer id is not a device key"))?;
    if key == run.device_key {
        return Err(usage("that is this node's own peer id"));
    }
    if circles_with(run, key).await?.is_empty() {
        return Err(refused(
            "that device is on no roll this node holds with you on it, so it is not looked \
             up. If you were just admitted to a circle its node holds: `peerharness circle \
             join <its peer id> --internet --expect-fingerprint <fingerprint>`.",
        ));
    }
    let addrs = find(run, peer, wait).await?;
    if addrs.is_empty() {
        return Err(anyhow!(
            "that device was not found on the public network. Its node must be running \
             `peerharness daemon --internet`, and stays findable for a few minutes after \
             it stops."
        ));
    }
    sync_at(run, &addrs).await
}

/// What an internet sync did.
#[derive(Debug, Default)]
pub struct InternetSync {
    /// One entry per device that was found: its peer id and what the sync did.
    pub results: Vec<(String, Result<SyncReport>)>,
    /// Devices on this node's rolls that were looked up.
    pub looked_up: usize,
    /// Of those, the devices nobody on the public network knew.
    pub not_found: usize,
    /// Devices that were not looked up: more than the limit, or no time left.
    pub left_out: usize,
}

/// Syncs with the members of this node's circles that can be found over the public
/// network (the transport must have been started in internet mode). Looks up, for at
/// most `wait`, every device that shares a roll with this node except those in `skip`,
/// then syncs with each one found.
///
/// Only device keys on a roll this node holds are looked up, and whoever answers at an
/// address that was found must prove that key in the handshake and is then judged by
/// the roll like any other peer.
pub async fn sync_internet(
    run: &Running,
    wait: Duration,
    skip: &HashSet<String>,
) -> Result<InternetSync> {
    let me = run.device_key;
    let devices: Vec<DeviceKey> = run
        .worker
        .call(move |node| {
            let oracle = peer::roll_oracle(&node.store)?;
            let mut devices = BTreeSet::new();
            for circle in node.store.circles()? {
                let Some(charter) = node.store.current_charter(&circle.circle_id)? else {
                    continue;
                };
                for entry in &charter.content.roll {
                    devices.extend(entry.devices.iter().map(DeviceKey::to_string));
                }
            }
            Ok(devices
                .iter()
                .filter_map(|d| d.parse::<DeviceKey>().ok())
                .filter(|d| *d != me && !oracle.shared_circles(&me, d).is_empty())
                .collect())
        })
        .await?;
    let mut peers: Vec<PeerId> = devices
        .iter()
        .map(ph_network::peer_id_from_device_key)
        .filter(|p| !skip.contains(&p.to_string()))
        .collect();
    let mut out = InternetSync::default();
    if peers.len() > MAX_DEVICES_LOOKED_UP {
        out.left_out = peers.len() - MAX_DEVICES_LOOKED_UP;
        peers.truncate(MAX_DEVICES_LOOKED_UP);
    }
    let deadline = tokio::time::Instant::now() + wait;
    let mut found: Vec<(PeerId, Vec<Multiaddr>)> = Vec::new();
    for group in peers.chunks(FINDS_AT_ONCE) {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left < Duration::from_secs(1) {
            out.left_out += group.len();
            continue;
        }
        let lookups = group.iter().map(|peer| find(run, *peer, left));
        for (peer, addrs) in group.iter().zip(futures::future::join_all(lookups).await) {
            out.looked_up += 1;
            match addrs {
                Ok(addrs) if !addrs.is_empty() => found.push((*peer, addrs)),
                _ => out.not_found += 1,
            }
        }
    }
    for (peer, addrs) in found {
        out.results
            .push((peer.to_string(), sync_at(run, &addrs).await));
    }
    Ok(out)
}

/// `circle join <peer id> --internet`: finds the node its owner named over the public
/// network and fetches what it offers this device ([`fetch_for_join`]). Returns the
/// address that answered as well. The peer id is the one thing looked up here that is
/// on no roll of this node: its owner typed it.
pub async fn fetch_for_join_found(
    run: &Running,
    peer: PeerId,
    wait: Duration,
) -> Result<(Multiaddr, PeerId, Vec<Offered>)> {
    let addrs = find(run, peer, wait).await?;
    if addrs.is_empty() {
        return Err(anyhow!(
            "that node was not found on the public network. It must be running \
             `peerharness daemon --internet`; check the peer id (its daemon prints it)."
        ));
    }
    let mut outcome = Err(anyhow!("no address was found for that node"));
    for addr in addrs {
        match fetch_for_join(run, &addr).await {
            Ok((answered, offered)) => return Ok((addr, answered, offered)),
            Err(e) if e.downcast_ref::<CliError>().is_some() => return Err(e),
            Err(e) => outcome = Err(e),
        }
    }
    outcome
}

/// Where this node stands on the public network, for `daemon.json` and the daemon's
/// own notes. `None` when the mode is off.
pub async fn internet_info(run: &Running) -> Option<crate::daemon_info::InternetInfo> {
    let status = run.net.internet_status().await.ok()?;
    status.enabled.then(|| crate::daemon_info::InternetInfo {
        joined: status.bootstrapped,
        reachability: status.reachability.as_str().to_owned(),
        relays: status.relay_addrs.len(),
        direct_addrs: status
            .external_addrs
            .iter()
            .map(Multiaddr::to_string)
            .collect(),
    })
}
