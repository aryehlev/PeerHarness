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
//! * There is no gossip and no background dialing. A node sends and receives when its
//!   owner runs `sync`, or when a peer syncs with its running `daemon`.
//!
//! The transport authenticates device keys. What a key may have is decided per request
//! from the roll (see `peer`).

use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ph_core::{CircleId, DeviceKey, Digest, EventId};
use ph_network::{handler_fn, Multiaddr, NetworkConfig, NetworkHandle, PeerId, PeerInfo};
use ph_protocol::limits::MAX_FETCH_LIMIT;
use ph_protocol::wire::{ErrorCode, PushStatus, Request, Response, PROTOCOL_VERSION};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::error::refused;
use crate::governance;
use crate::home::Home;
use crate::node::Node;
use crate::peer;

/// Most `fetch_events` rounds for one circle in one sync.
const MAX_FETCH_ROUNDS: usize = 64;

/// How long a sync waits for the peer to fetch the bundles of what was just pushed.
const BUNDLE_PULL_WAIT: Duration = Duration::from_secs(10);

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
    /// Digests of bundles this node served during this run.
    served: Mutex<HashSet<Digest>>,
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
            let asked_bundle = match &request {
                Request::FetchBundle { digest, .. } => Some(*digest),
                _ => None,
            };
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
                    if let (Some(digest), Response::Bundle { .. }) =
                        (asked_bundle, &answer.response)
                    {
                        if let Ok(mut served) = shared.served.lock() {
                            served.insert(digest);
                        }
                    }
                    if !answer.pulls.is_empty() {
                        tokio::spawn(pull_then_settle(
                            worker,
                            shared,
                            peer_id,
                            answer.pulls,
                            answer.touched,
                        ));
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
    shared: Arc<Shared>,
    join: JoinHandle<()>,
}

impl Running {
    /// Starts the node thread and the transport. Must be called inside a Tokio runtime.
    /// With no `listen` addresses the node only dials.
    pub fn start(home: Home, listen: Vec<Multiaddr>) -> Result<Self> {
        let (worker, seed, device_key) = Worker::spawn(home)?;
        let shared = Arc::new(Shared::default());
        let config = NetworkConfig::listening_on(listen);
        let (net, join) = ph_network::start(seed, config, handler(worker.clone(), shared.clone()))
            .map_err(|e| anyhow!("cannot start the transport: {e}"))?;
        let _ = shared.net.set(net.clone());
        Ok(Self {
            worker,
            net,
            device_key,
            shared,
            join,
        })
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
    pub changes: Changes,
}

/// Connects to `addr` and checks who answered: returns the peer and the circles in
/// which both it and this node are on the roll. Nothing circle-specific is sent to a
/// peer that shares no circle with this node.
pub async fn connect(
    run: &Running,
    addr: &Multiaddr,
) -> Result<(PeerId, DeviceKey, Vec<CircleId>)> {
    let peer = run
        .net
        .dial(addr.clone())
        .await
        .map_err(|e| anyhow!("cannot reach that address: {e}"))?;
    let peer_key = ph_network::device_key_from_peer_id(&peer)
        .ok_or_else(|| anyhow!("the peer's identity is not a device key"))?;
    match run.net.request(peer, &Request::hello()).await {
        // Stop unless the peer speaks our version: nothing else is sent to one that
        // does not.
        Ok(Response::Hello { versions, .. }) if versions.iter().any(|v| v == PROTOCOL_VERSION) => {}
        Ok(Response::Hello { .. }) => {
            return Err(anyhow!(
                "the peer speaks a different protocol version (this node speaks {PROTOCOL_VERSION})"
            ))
        }
        Ok(_) => return Err(anyhow!("the peer did not answer hello")),
        Err(e) => return Err(anyhow!("the peer does not speak this protocol: {e}")),
    }
    let me = run.device_key;
    let circles = run
        .worker
        .call(move |node| Ok(peer::roll_oracle(&node.store)?.shared_circles(&me, &peer_key)))
        .await?;
    if circles.is_empty() {
        return Err(refused(
            "that peer and this node share no circle (each must be on the roll the other \
             holds). Nothing was exchanged.",
        ));
    }
    // Announce ourselves. A peer that does not see us on its roll says so here.
    let listen: Vec<String> = run
        .net
        .current_listen_addrs()
        .iter()
        .map(|a| ph_network::with_p2p(a, run.net.local_peer_id()).to_string())
        .collect();
    let announce = Request::Authenticate {
        memberships: Vec::new(),
        listen_addrs: listen,
    };
    match run.net.request(peer, &announce).await {
        Ok(Response::Authenticated { .. }) => {}
        Ok(Response::Error {
            code: ErrorCode::Unauthorized,
        }) => {
            return Err(refused(
                "the peer does not recognize this node as a member of any circle it holds. \
                 Nothing was exchanged.",
            ))
        }
        Ok(_) | Err(_) => return Err(anyhow!("the peer did not complete the handshake")),
    }
    let shared = circles.clone();
    let dialed = ph_network::with_p2p(addr, peer).to_string();
    run.worker
        .call(move |node| {
            peer::remember_peer(
                &node.store,
                &peer.to_string(),
                &peer_key,
                &[dialed],
                &shared,
                node.now(),
            )
        })
        .await?;
    Ok((peer, peer_key, circles))
}

fn unauthorized(response: &Response) -> bool {
    matches!(
        response,
        Response::Error {
            code: ErrorCode::Unauthorized
        }
    )
}

/// Fetches what the peer has of `circle` that this node lacks. Returns events stored.
async fn fetch_events(run: &Running, peer: PeerId, circle: CircleId) -> Result<usize> {
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
        let origin = peer.to_string();
        let ingested = run
            .worker
            .call(move |node| {
                let only: HashSet<CircleId> = [circle].into();
                peer::ingest_values(&node.store, &events, Some(&only), Some(&origin), node.now())
            })
            .await?;
        stored += ingested.stored;
        if ingested.stored == 0 || !more {
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

/// Pushes everything of `circle` the peer may read. Returns `(accepted, refused)` and
/// the ids the peer accepted as new.
async fn push_events(
    run: &Running,
    peer: PeerId,
    peer_key: DeviceKey,
    circle: CircleId,
) -> Result<(usize, usize, Vec<EventId>)> {
    let batches = run
        .worker
        .call(move |node| peer::outgoing_batches(&node.store, &circle, &peer_key, node.now()))
        .await?;
    let (mut accepted, mut rejected, mut new_ids) = (0, 0, Vec::new());
    for events in batches {
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
        for r in results {
            match r.status {
                PushStatus::Accepted => {
                    accepted += 1;
                    new_ids.extend(r.event_id);
                }
                PushStatus::Duplicate => {}
                PushStatus::Rejected => rejected += 1,
            }
        }
    }
    Ok((accepted, rejected, new_ids))
}

/// Waits until the peer has fetched the bundles named by the proposals it just accepted
/// from this node, or until [`BUNDLE_PULL_WAIT`] has passed.
async fn wait_for_bundle_pulls(run: &Running, accepted: Vec<EventId>) -> Result<()> {
    let expected: HashSet<Digest> = run
        .worker
        .call(move |node| {
            let mut digests = HashSet::new();
            for id in &accepted {
                if let Some(d) = node.store.event(id)?.and_then(|ev| ev.bundle_digest) {
                    digests.insert(d);
                }
            }
            Ok(digests)
        })
        .await?;
    if expected.is_empty() {
        return Ok(());
    }
    let deadline = tokio::time::Instant::now() + BUNDLE_PULL_WAIT;
    loop {
        let done = run
            .shared
            .served
            .lock()
            .map(|served| expected.is_subset(&served))
            .unwrap_or(true);
        if done || tokio::time::Instant::now() >= deadline {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// A two-way sync with the peer at `addr`: fetch what it has, send what it lacks, let it
/// fetch the rule texts, settle, and fetch once more for what the exchange produced on
/// its side (a result, a new charter).
pub async fn sync(run: &Running, addr: &Multiaddr) -> Result<SyncReport> {
    let (peer, peer_key, circles) = connect(run, addr).await?;
    let mut report = SyncReport {
        peer_id: peer.to_string(),
        circles: circles.len(),
        ..SyncReport::default()
    };
    for circle in circles {
        let only: BTreeSet<CircleId> = [circle].into();
        report.received += fetch_events(run, peer, circle).await?;
        report.bundles += fetch_bundles(run, peer, circle).await?;
        let settle = only.clone();
        let changes = run
            .worker
            .call(move |node| settle_circles(node, &settle))
            .await?;
        report.changes.absorb(changes);

        let (accepted, rejected, new_ids) = push_events(run, peer, peer_key, circle).await?;
        report.sent += accepted;
        report.refused_by_peer += rejected;
        wait_for_bundle_pulls(run, new_ids).await?;

        // What the exchange produced over there.
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
            let (accepted, rejected, _) = push_events(run, peer, peer_key, circle).await?;
            report.sent += accepted;
            report.refused_by_peer += rejected;
        }
    }
    Ok(report)
}
