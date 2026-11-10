//! `peerharness daemon`, `connect` and `sync`: the live transport (architecture
//! section 7).
//!
//! * `daemon` listens and answers peers until it is stopped. It dials nobody, unless
//!   its owner asked for a sync interval: then it syncs with the peers this node
//!   already knows, and with nobody else.
//! * `sync <address or peer id>` connects to one peer, exchanges what each side lacks
//!   and exits. It does not need a daemon of its own. Without an argument it does that
//!   with every peer whose address is stored.
//! * `connect <address>` only checks who answers and remembers the address.
//!
//! A peer is recognized by its device key being on the roll of a circle this node
//! holds. A device that was just admitted holds no roll yet: it gets the circle with
//! `circle join <address>`.

use std::time::Duration;

use anyhow::{anyhow, Result};
use ph_network::{Multiaddr, NetworkConfig};
use serde_json::{json, Value};

use crate::cli::{ConnectArgs, DaemonArgs, SyncArgs};
use crate::commands::Ctx;
use crate::daemon_info::{DaemonInfo, DaemonLock};
use crate::error::usage;
use crate::output::{safe, Report, Text};
use crate::runtime::{self, Running, SyncReport};

pub fn tokio_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("cannot start the async runtime: {e}"))
}

pub fn parse_addr(s: &str) -> Result<Multiaddr> {
    s.trim().parse::<Multiaddr>().map_err(|_| {
        usage(format!(
            "{s:?} is not a multiaddr (for example /ip4/192.0.2.7/udp/4001/quic-v1/p2p/<peer id>)"
        ))
    })
}

/// The transport configuration of a node that only dials.
pub fn dial_only() -> NetworkConfig {
    NetworkConfig::listening_on(Vec::new())
}

/// Resolves `sync`'s argument: a multiaddr, or the id of a peer whose address a
/// previous `connect` or `sync` stored.
fn resolve_target(ctx: &Ctx, target: &str) -> Result<Multiaddr> {
    if target.trim_start().starts_with('/') {
        return parse_addr(target);
    }
    let node = ctx.open_node()?;
    let peer = node
        .store
        .peer(target.trim())
        .map_err(|_| usage("that is neither a multiaddr nor a peer id"))?
        .ok_or_else(|| {
            usage("no peer with that id is known here: give its address once (`peerharness sync <multiaddr>`)")
        })?;
    let addr = peer
        .addrs
        .first()
        .ok_or_else(|| usage("no address is stored for that peer: give its address"))?;
    parse_addr(addr)
}

async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// What one sync did, as lines for a person.
fn sync_lines(t: &mut Text, r: &SyncReport) {
    if r.circles > 0 {
        t.line(format!(
            "Synced {} circle(s) with {}: received {} new event(s) and {} rule text(s), sent {}.",
            r.circles, r.peer_id, r.received, r.bundles, r.sent
        ));
    }
    if r.refused_by_peer > 0 {
        t.line(format!(
            "  The peer did not take {} event(s) (it may lack a record they depend on; they are offered again next time).",
            r.refused_by_peer
        ));
    }
    for name in &r.removed_from {
        t.line(format!(
            "  You are no longer a member of {}: the members voted to take this device's \
             member off the roll. The peer sent the vote and this node verified it.",
            safe(name)
        ));
    }
    for name in &r.not_recognized {
        t.line(format!(
            "  The peer does not have you on the roll of {} and gave no record of a removal. \
             It may be behind: sync with another member.",
            safe(name)
        ));
    }
    for seq in &r.changes.charters_issued {
        t.line(format!("  an amendment passed; issued charter {seq}"));
    }
    for skill in &r.changes.installed {
        t.line(format!("  installed rule {skill} for your agent"));
    }
    for skill in &r.changes.removed {
        t.line(format!("  removed rule {skill}"));
    }
    for skill in &r.changes.asking {
        t.line(format!(
            "  rule {skill} is in force and waits for your confirmation: `peerharness proposal adopt <id>`"
        ));
    }
}

fn sync_json(r: &SyncReport) -> Value {
    json!({
        "peer_id": r.peer_id,
        "circles": r.circles,
        "received": r.received,
        "bundles": r.bundles,
        "sent": r.sent,
        "refused_by_peer": r.refused_by_peer,
        "removed_from": r.removed_from,
        "not_recognized": r.not_recognized,
        "installed": r.changes.installed,
        "removed": r.changes.removed,
        "asking": r.changes.asking,
        "charters_issued": r.changes.charters_issued,
    })
}

pub fn daemon(ctx: &Ctx, args: DaemonArgs) -> Result<Report> {
    let configured = if args.listen.is_empty() {
        ctx.open_node()?.config.node.listen.clone()
    } else {
        args.listen
    };
    let listen = configured
        .iter()
        .map(|s| parse_addr(s))
        .collect::<Result<Vec<_>>>()?;
    if listen.is_empty() {
        return Err(usage("no listen address: pass --listen <multiaddr>"));
    }
    let home = ctx.home.clone();
    let out = ctx.out;
    // Held until this function returns; the operating system releases it if we crash.
    let _lock = DaemonLock::acquire(&home)?
        .ok_or_else(|| usage("a daemon is already running for this home"))?;
    tokio_runtime()?.block_on(async move {
        let run = Running::start(home.clone(), NetworkConfig::listening_on(listen))?;
        let addrs = run.dialable_addrs().await?;
        DaemonInfo {
            pid: std::process::id(),
            peer_id: run.net.local_peer_id().to_string(),
            listen_addrs: addrs.clone(),
        }
        .write(&home)?;
        out.note("Listening. Members of your circles can sync with this node at:");
        for a in &addrs {
            out.note(format!("  {a}"));
        }
        out.note(
            "Only devices on the roll of a circle this node holds are answered. Ctrl-C stops it.",
        );
        if let Some(secs) = args.sync_every {
            out.note(format!(
                "Syncing with the peers this node knows every {secs} seconds."
            ));
        }
        let stop = stop_signal();
        tokio::pin!(stop);
        let mut ticker = args.sync_every.map(|secs| {
            let every = Duration::from_secs(u64::from(secs));
            tokio::time::interval_at(tokio::time::Instant::now() + every, every)
        });
        loop {
            let tick = async {
                match ticker.as_mut() {
                    Some(t) => {
                        t.tick().await;
                    }
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = &mut stop => break,
                _ = tick => {
                    // Failures are expected (a peer that is off) and only counted.
                    if let Ok(results) = runtime::sync_known(&run).await {
                        for (_, r) in results.iter().filter_map(|(id, r)| Some((id, r.as_ref().ok()?))) {
                            if r.received > 0 || r.sent > 0 || !r.changes.is_empty() || !r.removed_from.is_empty() {
                                let mut t = Text::new();
                                sync_lines(&mut t, r);
                                out.note(t.finish().trim_end());
                            }
                        }
                        let failed = results.iter().filter(|(_, r)| r.is_err()).count();
                        tracing::info!(peers = results.len(), failed, "periodic sync");
                    }
                }
            }
        }
        DaemonInfo::remove(&home);
        run.stop().await;
        Ok(Report::new(
            json!({ "stopped": true, "listen_addrs": addrs }),
            "Stopped.",
        ))
    })
}

pub fn connect(ctx: &Ctx, args: ConnectArgs) -> Result<Report> {
    let addr = parse_addr(&args.multiaddr)?;
    let home = ctx.home.clone();
    tokio_runtime()?.block_on(async move {
        let run = Running::start(home, dial_only())?;
        let result = runtime::connect(&run, &addr).await;
        run.stop().await;
        let (peer, key, circles) = result?;
        Ok(Report::new(
            json!({
                "peer_id": peer.to_string(),
                "device_fingerprint": key.fingerprint(),
                "shared_circles": circles.len(),
            }),
            format!(
                "Reached {peer} (device {}). You share {} circle(s). Its address is stored: \
                 `peerharness sync {peer}`.",
                key.fingerprint(),
                circles.len()
            ),
        ))
    })
}

pub fn sync(ctx: &Ctx, args: SyncArgs) -> Result<Report> {
    let Some(target) = args.peer_id else {
        return sync_all(ctx);
    };
    let addr = resolve_target(ctx, &target)?;
    let home = ctx.home.clone();
    tokio_runtime()?.block_on(async move {
        let run = Running::start(home, dial_only())?;
        let result = runtime::sync(&run, &addr).await;
        run.stop().await;
        let r = result?;
        let mut t = Text::new();
        sync_lines(&mut t, &r);
        if r.received > 0 {
            t.line("See what needs your vote: `peerharness proposal list`.");
        }
        Ok(Report::new(sync_json(&r), t.finish()))
    })
}

/// `sync` without an argument: every peer whose address this node has stored.
fn sync_all(ctx: &Ctx) -> Result<Report> {
    let home = ctx.home.clone();
    tokio_runtime()?.block_on(async move {
        let run = Running::start(home, dial_only())?;
        let results = runtime::sync_known(&run).await;
        run.stop().await;
        let results = results?;
        if results.is_empty() {
            return Err(usage(
                "this node knows no peer yet: sync once with an address, `peerharness sync <multiaddr>`",
            ));
        }
        let mut t = Text::new();
        let mut synced = Vec::new();
        let mut failed = Vec::new();
        let mut received = 0;
        for (id, outcome) in &results {
            match outcome {
                Ok(r) => {
                    sync_lines(&mut t, r);
                    received += r.received;
                    synced.push(sync_json(r));
                }
                Err(e) => {
                    t.line(format!("Could not sync with {id}: {e}"));
                    failed.push(json!({ "peer_id": id, "error": e.to_string() }));
                }
            }
        }
        if synced.is_empty() {
            return Err(anyhow!(
                "none of the {} known peer(s) could be synced with:\n{}",
                results.len(),
                t.finish().trim_end()
            ));
        }
        if received > 0 {
            t.line("See what needs your vote: `peerharness proposal list`.");
        }
        Ok(Report::new(
            json!({ "synced": synced, "failed": failed }),
            t.finish(),
        ))
    })
}
