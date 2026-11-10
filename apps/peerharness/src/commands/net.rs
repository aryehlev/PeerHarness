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
//! * With `--internet` (ADR-032) the node joins the public libp2p network: a daemon can
//!   be found there by its peer id, and `sync --internet` looks the devices on this
//!   node's rolls up there. Off unless asked for.
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
use crate::internet;
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

/// How often a daemon in internet mode looks at where it stands on the public network.
const STANDING_INTERVAL: Duration = Duration::from_secs(5);

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
    if r.relayed {
        t.line(
            "  This went through a public relay: a direct connection could not be made. A \
             relay carries about 128 KiB per connection, enough for a small exchange.",
        );
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
    for waiting in &r.changes.asking {
        t.line(format!("  {}", waiting.line()));
    }
    for (rule, circle) in &r.changes.held {
        t.line(format!("  {}", rule.line(circle)));
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
        "relayed": r.relayed,
        "removed_from": r.removed_from,
        "not_recognized": r.not_recognized,
        "installed": r.changes.installed,
        "removed": r.changes.removed,
        "asking": r.changes.asking.iter().map(|w| &w.name).collect::<Vec<_>>(),
        "held": r.changes.held.iter().map(|(rule, _)| rule.json()).collect::<Vec<_>>(),
        "charters_issued": r.changes.charters_issued,
    })
}

pub fn daemon(ctx: &Ctx, args: DaemonArgs) -> Result<Report> {
    let lan = args.lan;
    let on_internet = args.internet;
    let given = args
        .listen
        .iter()
        .map(|s| parse_addr(s))
        .collect::<Result<Vec<_>>>()?;
    let config = if on_internet {
        // The configured default listens on loopback, which is of no use here.
        internet::daemon_config((!given.is_empty()).then_some(given), lan)?
    } else {
        let listen = if given.is_empty() {
            ctx.open_node()?
                .config
                .node
                .listen
                .iter()
                .map(|s| parse_addr(s))
                .collect::<Result<Vec<_>>>()?
        } else {
            given
        };
        if listen.is_empty() {
            return Err(usage("no listen address: pass --listen <multiaddr>"));
        }
        NetworkConfig {
            lan_discovery: lan,
            ..NetworkConfig::listening_on(listen)
        }
    };
    // Asked for and impossible is refused, not dropped: the owner would wait for a
    // notification that never comes. The message says what does run.
    let desktop = match args.notify {
        true => Some(crate::notify::Desktop::find().ok_or_else(|| {
            usage(
                "--notify needs macOS: this build can show a desktop notification only \
                 there. Nothing was started. The daemon runs without it: give the same \
                 command without --notify. `peerharness inbox` shows what waits for your \
                 vote.",
            )
        })?),
        false => None,
    };
    let home = ctx.home.clone();
    let out = ctx.out;
    // Held until this function returns; the operating system releases it if we crash.
    let _lock = DaemonLock::acquire(&home)?
        .ok_or_else(|| usage("a daemon is already running for this home"))?;
    // On loopback only there is nothing to announce, and the line below is not printed.
    let announces = announces_on_lan(lan, &config.listen_addrs);
    if lan && !announces {
        out.warn(
            "--lan: this daemon only listens on loopback, so it has no address to announce. \
             Listen on a network address, for example --listen /ip4/0.0.0.0/udp/4001/quic-v1.",
        );
    }
    tokio_runtime()?.block_on(async move {
        let run = Running::start(home.clone(), config)?;
        let addrs = run.dialable_addrs().await?;
        let peer_id = run.net.local_peer_id().to_string();
        let mut info = DaemonInfo {
            pid: std::process::id(),
            peer_id: peer_id.clone(),
            listen_addrs: addrs.clone(),
            internet: runtime::internet_info(&run).await,
        };
        info.write(&home)?;
        out.note("Listening. Members of your circles can sync with this node at:");
        for a in &addrs {
            out.note(format!("  {a}"));
        }
        out.note(
            "Only devices on the roll of a circle this node holds are answered. Ctrl-C stops it.",
        );
        if on_internet {
            out.note(internet::DISCLOSURE);
            out.note("Internet: joining the public network.");
            out.note(format!(
                "Members anywhere reach this node by its peer id:\n  peerharness sync \
                 --internet\n  peerharness circle join {peer_id} --internet   (a device \
                 that was just admitted)"
            ));
        }
        if announces {
            out.note(
                "Announcing this device's public key and port on the local network (mDNS). \
                 Members find it with `peerharness sync --lan`.",
            );
        }
        if let Some(secs) = args.sync_every {
            out.note(format!(
                "Syncing with the peers this node knows{}{} every {secs} seconds.",
                if lan {
                    ", members heard on the local network"
                } else {
                    ""
                },
                if on_internet {
                    ", members found over the public network"
                } else {
                    ""
                }
            ));
        } else if on_internet {
            out.note(
                "This node answers and dials nobody. To also fetch from members by itself, \
                 add --sync-every <seconds>.",
            );
        }
        if desktop.is_some() {
            out.note(
                "A proposal that needs your vote is announced on this desktop when it arrives.",
            );
        }
        let stop = stop_signal();
        tokio::pin!(stop);
        // With --notify: looks every few seconds at what waits for the owner's vote.
        let mut desktop = desktop;
        let mut watch = desktop
            .is_some()
            .then(|| tokio::time::interval(crate::notify::LOOK_EVERY));
        // In internet mode: looks every few seconds at where the node stands, keeps
        // `daemon.json` current and tells the owner when it changes.
        let mut standing = on_internet.then(|| tokio::time::interval(STANDING_INTERVAL));
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
            let look = async {
                match standing.as_mut() {
                    Some(t) => {
                        t.tick().await;
                    }
                    None => std::future::pending().await,
                }
            };
            let news = async {
                match watch.as_mut() {
                    Some(t) => {
                        t.tick().await;
                    }
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = &mut stop => break,
                _ = news => {
                    let found = run.worker.call(crate::notify::news).await;
                    if let (Ok(Some(news)), Some(shows)) = (found, desktop.clone()) {
                        let text = news.text.clone();
                        let shown = tokio::task::spawn_blocking(move || shows.show(&text))
                            .await
                            .unwrap_or(false);
                        if shown {
                            out.note(&news.text);
                            let _ = run
                                .worker
                                .call(move |node| crate::notify::record(node, &news.proposals))
                                .await;
                        } else {
                            // Not tried again: a machine that cannot show one now will
                            // not be able to in three seconds either.
                            out.warn("a desktop notification could not be shown; --notify is off for this run");
                            desktop = None;
                            watch = None;
                        }
                    }
                }
                _ = look => {
                    let now = runtime::internet_info(&run).await;
                    if now != info.internet {
                        let said = info.internet.as_ref().map(|i| i.summary());
                        if let Some(i) = now.as_ref().filter(|i| Some(i.summary()) != said) {
                            out.note(format!("Internet: {}.", i.summary()));
                        }
                        info.internet = now;
                        // Best effort: the file is for `status`, the daemon does not need it.
                        let _ = info.write(&home);
                    }
                }
                _ = tick => {
                    // Failures are expected (a peer that is off) and only counted.
                    let mut results = runtime::sync_known(&run).await.unwrap_or_default();
                    if on_internet {
                        // Members that were not just synced, found by their device keys.
                        let done = results
                            .iter()
                            .filter(|(_, r)| r.is_ok())
                            .map(|(id, _)| id.clone())
                            .collect();
                        let wait = Duration::from_secs(u64::from(internet::DEFAULT_WAIT_SECS));
                        if let Ok(found) = runtime::sync_internet(&run, wait, &done).await {
                            tracing::info!(
                                looked_up = found.looked_up,
                                not_found = found.not_found,
                                left_out = found.left_out,
                                "internet lookups"
                            );
                            results.extend(found.results);
                        }
                    }
                    if lan {
                        // Members heard on the local network that were not just synced.
                        let done = results
                            .iter()
                            .filter(|(_, r)| r.is_ok())
                            .map(|(id, _)| id.clone())
                            .collect();
                        results.extend(
                            runtime::sync_lan(&run, Duration::ZERO, &done)
                                .await
                                .unwrap_or_default(),
                        );
                    }
                    {
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
    if args.wait.is_some() && !args.lan && !args.internet {
        return Err(usage("--wait goes with --lan or --internet"));
    }
    let wait = |default: u32| Duration::from_secs(u64::from(args.wait.unwrap_or(default)));
    if args.lan {
        return sync_many(ctx, Find::Lan(wait(3)));
    }
    let Some(target) = args.peer_id else {
        return sync_many(
            ctx,
            if args.internet {
                Find::Internet(wait(internet::DEFAULT_WAIT_SECS))
            } else {
                Find::Known
            },
        );
    };
    // With --internet: an address (it may go through a relay), or the peer id of a
    // device on a roll this node holds, which is then looked up.
    let found = if args.internet && !target.trim_start().starts_with('/') {
        Some(internet::peer_id_of(&target).ok_or_else(|| usage("that is not a peer id"))?)
    } else {
        None
    };
    let addr = match found {
        Some(_) => None,
        None => Some(resolve_target(ctx, &target)?),
    };
    let config = if args.internet {
        internet::client_config()?
    } else {
        dial_only()
    };
    if args.internet {
        ctx.out.note(internet::DISCLOSURE);
    }
    let wait = wait(internet::DEFAULT_WAIT_SECS);
    let home = ctx.home.clone();
    let passing = args.internet;
    tokio_runtime()?.block_on(async move {
        let run = Running::start(home, config)?;
        let run = if passing { run.passing() } else { run };
        let result = match (found, addr) {
            (Some(peer), _) => runtime::sync_found(&run, peer, wait).await,
            (None, Some(addr)) => runtime::sync(&run, &addr).await,
            (None, None) => Err(usage("no peer to sync with")),
        };
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

/// How `sync` without an address finds whom to sync with.
enum Find {
    /// Every peer whose address this node has stored.
    Known,
    /// The members that announce themselves on the local network within that time.
    Lan(Duration),
    /// The devices on this node's rolls that the public network knows, looked up for
    /// at most that long.
    Internet(Duration),
}

/// Whether a daemon that listens on `listen` has an address to announce on the local
/// network: with `--lan`, and not on loopback only.
fn announces_on_lan(lan: bool, listen: &[Multiaddr]) -> bool {
    lan && !listen.iter().all(is_loopback)
}

fn is_loopback(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        ph_network::libp2p::multiaddr::Protocol::Ip4(ip) => ip.is_loopback(),
        ph_network::libp2p::multiaddr::Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}

/// `sync` without an address: with whoever `find` turns up.
fn sync_many(ctx: &Ctx, find: Find) -> Result<Report> {
    let home = ctx.home.clone();
    let config = match find {
        Find::Known => dial_only(),
        Find::Lan(_) => NetworkConfig {
            lan_discovery: true,
            ..dial_only()
        },
        Find::Internet(_) => {
            ctx.out.note(internet::DISCLOSURE);
            internet::client_config()?
        }
    };
    tokio_runtime()?.block_on(async move {
        let run = Running::start(home, config)?;
        let run = if matches!(find, Find::Internet(_)) {
            run.passing()
        } else {
            run
        };
        // Devices that were looked up over the public network and not found.
        let mut missing = None;
        let results = match find {
            Find::Lan(wait) => runtime::sync_lan(&run, wait, &Default::default()).await,
            Find::Known => runtime::sync_known(&run).await,
            Find::Internet(wait) => runtime::sync_internet(&run, wait, &Default::default())
                .await
                .map(|found| {
                    missing = Some((found.looked_up, found.not_found, found.left_out));
                    found.results
                }),
        };
        run.stop().await;
        let results = results?;
        if results.is_empty() {
            return Err(usage(match (find, missing) {
                (Find::Lan(_), _) => {
                    "no member of your circles announced itself on this network. A member's \
                     node must run `peerharness daemon --lan` on a network address, and this \
                     node must already hold a circle with it."
                        .to_owned()
                }
                (Find::Internet(_), Some((0, _, 0))) => {
                    "no other device is on the roll of a circle this node holds, so there is \
                     nobody to look for. A device that was just admitted joins first: \
                     `peerharness circle join <peer id> --internet`."
                        .to_owned()
                }
                (Find::Internet(_), Some((looked_up, _, left_out))) => format!(
                    "none of the {looked_up} other device(s) on your rolls was found on the \
                     public network{}. A member's node must be running `peerharness daemon \
                     --internet`.",
                    if left_out > 0 {
                        format!(" ({left_out} more were not looked up in time: raise --wait)")
                    } else {
                        String::new()
                    }
                ),
                _ => "this node knows no peer yet: sync once with an address, `peerharness \
                      sync <multiaddr>`, or find members over the internet with \
                      `peerharness sync --internet`"
                    .to_owned(),
            }));
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
                "none of the {} peer(s) could be synced with:\n{}",
                results.len(),
                t.finish().trim_end()
            ));
        }
        if received > 0 {
            t.line("See what needs your vote: `peerharness proposal list`.");
        }
        let mut json = json!({ "synced": synced, "failed": failed });
        if let Some((looked_up, not_found, left_out)) = missing {
            json["looked_up"] = json!(looked_up);
            json["not_found"] = json!(not_found);
            json["left_out"] = json!(left_out);
            if not_found > 0 {
                t.line(format!(
                    "{not_found} other device(s) on your rolls were not found on the public \
                     network (their nodes are not running `daemon --internet`)."
                ));
            }
            if left_out > 0 {
                t.line(format!(
                    "{left_out} device(s) were not looked up in time: raise --wait."
                ));
            }
        }
        Ok(Report::new(json, t.finish()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A daemon that listens on loopback only has nothing to announce: `--lan` there
    /// gets the warning, and the "Announcing ..." line is not printed after it.
    #[test]
    fn a_daemon_on_loopback_only_announces_nothing_on_the_local_network() {
        let addr = |s: &str| s.parse::<Multiaddr>().unwrap();
        let loopback = [
            addr("/ip4/127.0.0.1/udp/0/quic-v1"),
            addr("/ip6/::1/udp/0/quic-v1"),
        ];
        let any = [addr("/ip4/0.0.0.0/udp/4001/quic-v1")];
        let mixed = [
            addr("/ip4/127.0.0.1/udp/0/quic-v1"),
            addr("/ip4/192.0.2.7/udp/4001/quic-v1"),
        ];
        assert!(!announces_on_lan(true, &loopback));
        assert!(announces_on_lan(true, &any));
        assert!(announces_on_lan(true, &mixed));
        // Without --lan nothing is announced, whatever it listens on.
        assert!(!announces_on_lan(false, &any));
    }
}
