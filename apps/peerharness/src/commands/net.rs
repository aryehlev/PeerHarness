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

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{anyhow, Result};
use ph_core::EventId;
use ph_network::{Multiaddr, NetworkConfig};
use serde_json::{json, Value};

use crate::cli::{ConnectArgs, DaemonArgs, SyncArgs};
use crate::commands::Ctx;
use crate::daemon_info::{DaemonInfo, DaemonLock};
use crate::error::usage;
use crate::governance;
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

/// The holds a running daemon has told its owner about: each rule that is held, by its
/// circle and the proposal that put it in force.
///
/// A hold is a state, so a daemon does not print it tick after tick: every settle of
/// the circle finds it again. It is also something that happens: a rule becomes held
/// when a peer's push brings the ballot that passes it, and that push is settled by the
/// request handler. So a daemon prints each hold once per run, when it first learns of
/// it: from a report of its own exchanges ([`daemon_report`]), or from the request
/// handler ([`runtime::held_queue`]), whichever comes first.
#[derive(Default)]
struct HoldsTold(HashSet<(String, EventId)>);

impl HoldsTold {
    /// The holds in `held` that this daemon has not printed yet. Every hold in it
    /// counts as printed from now on: the caller prints the ones returned.
    fn new_in(&mut self, held: &[(governance::HeldRule, String)]) -> runtime::HeldRules {
        held.iter()
            .filter(|(rule, circle)| self.0.insert((circle.clone(), rule.proposal_id)))
            .cloned()
            .collect()
    }
}

/// What a running daemon prints for one peer's report of a sync it made itself, or
/// `None` when the report has nothing to say that this run has not said.
///
/// A report is printed when the exchange moved an event, changed something on this
/// machine, found a rule that waits for the owner, or found a hold that is new to this
/// run. The hold lines in it are the new ones only: a report that is printed for
/// another reason does not repeat a hold that was printed before.
fn daemon_report(told: &mut HoldsTold, r: &SyncReport) -> Option<String> {
    let new_holds = told.new_in(&r.changes.held);
    let anything = r.received > 0
        || r.sent > 0
        || !r.changes.is_empty()
        || !r.removed_from.is_empty()
        || !new_holds.is_empty();
    anything.then(|| {
        let mut t = Text::new();
        sync_lines(&mut t, r, &new_holds);
        t.finish().trim_end().to_owned()
    })
}

/// What one sync did, as lines for a person. `held` is the held rules to list: all the
/// report has for a one-shot `sync`, and for a daemon the ones it has not printed yet.
fn sync_lines(t: &mut Text, r: &SyncReport, held: &[(governance::HeldRule, String)]) {
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
    for skill in &r.changes.not_removed {
        t.line(format!("  {}", governance::not_removed_line(skill)));
    }
    for kept in &r.changes.kept_edited {
        t.line(format!("  {}", kept.line()));
    }
    for waiting in &r.changes.asking {
        t.line(format!("  {}", waiting.line()));
    }
    for (rule, circle) in held {
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
        "not_removed": r.changes.not_removed,
        "kept_edited": r.changes.kept_edited.iter().map(|k| &k.name).collect::<Vec<_>>(),
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
        // What the request handler finds held when it settles a peer's push comes here.
        let (held_tx, mut held_rx) = runtime::held_queue();
        let run = Running::start_telling(home.clone(), config, held_tx)?;
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
        let mut holds_told = HoldsTold::default();
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
                Some(held) = held_rx.recv() => {
                    // A peer synced to this node and what it brought left a rule held
                    // here. This daemon may never exchange with that peer by itself
                    // (it knows no address, or has no sync interval), so it says so
                    // now: once, like a hold its own exchange finds.
                    for (rule, circle) in holds_told.new_in(&held) {
                        out.note(rule.line(&circle));
                    }
                }
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
                    for r in results.iter().filter_map(|(_, r)| r.as_ref().ok()) {
                        // A hold is printed once, when it is new to this run.
                        if let Some(report) = daemon_report(&mut holds_told, r) {
                            out.note(report);
                        }
                    }
                    let failed = results.iter().filter(|(_, r)| r.is_err()).count();
                    tracing::info!(peers = results.len(), failed, "periodic sync");
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
        sync_lines(&mut t, &r, &r.changes.held);
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
                    sync_lines(&mut t, r, &r.changes.held);
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

    fn held(name: &str, circle: &str) -> (governance::HeldRule, String) {
        (
            governance::HeldRule {
                name: name.to_owned(),
                proposal_id: EventId::from_digest(ph_core::Digest::sha256(name.as_bytes())),
                why: governance::Held::OwnSkill,
                place: None,
            },
            circle.to_owned(),
        )
    }

    /// The line of a report that says the rule `name` is held. (What follows the colon
    /// depends on who reads it, a person or a session, and is not looked at here.)
    fn hold_line(name: &str) -> String {
        format!("  rule {name} is in force and is held on this machine:")
    }

    /// A hold reaches a daemon as a state: every settle of the circle finds it again,
    /// in the daemon's own exchanges and in what the request handler hands over. Each
    /// is new once, and a second rule that becomes held is new in its turn.
    #[test]
    fn a_daemon_tells_a_hold_once_when_it_is_new() {
        let mut told = HoldsTold::default();
        let names = |new: runtime::HeldRules| -> Vec<(String, String)> {
            new.into_iter()
                .map(|(rule, circle)| (rule.name, circle))
                .collect()
        };
        let at = |name: &str, circle: &str| (name.to_owned(), circle.to_owned());
        // Nothing held: nothing new.
        assert!(told.new_in(&[]).is_empty());
        // A peer pushed the ballot that passed the rule: new.
        let style = held("style", "team");
        assert_eq!(
            names(told.new_in(std::slice::from_ref(&style))),
            [at("style", "team")]
        );
        // Every later settle finds the same hold, and it is not new again.
        for _ in 0..3 {
            assert!(told.new_in(std::slice::from_ref(&style)).is_empty());
        }
        // A second rule becomes held: that one is new, and only that one.
        let both = [style.clone(), held("commits", "team")];
        assert_eq!(names(told.new_in(&both)), [at("commits", "team")]);
        assert!(told.new_in(&both).is_empty());
        // Another circle's rule of the same name is another hold.
        let other = [held("style", "other-circle")];
        assert_eq!(names(told.new_in(&other)), [at("style", "other-circle")]);
        assert!(told.new_in(&other).is_empty());
    }

    /// What a daemon prints for the reports of its own exchanges. A hold is printed
    /// with the first report that has it, also when that exchange moved nothing. A
    /// later report that is printed for another reason (events moved, a rule that
    /// waits for the owner) does not print it again, which it used to do: with one
    /// rule waiting, the hold's lines came back on every tick. A one-shot `sync`
    /// lists every hold each time.
    #[test]
    fn a_daemon_prints_a_hold_with_one_report_and_no_later_one() {
        let report = |received: usize, held: &[(governance::HeldRule, String)]| SyncReport {
            peer_id: "a-peer".to_owned(),
            circles: 1,
            received,
            changes: runtime::Changes {
                held: held.to_vec(),
                ..runtime::Changes::default()
            },
            ..SyncReport::default()
        };
        let style = held("style", "team");
        let mut told = HoldsTold::default();

        // An exchange that moved nothing and found nothing held prints nothing.
        assert_eq!(daemon_report(&mut told, &report(0, &[])), None);

        // The first report with the hold: printed, though no event moved.
        let first = daemon_report(&mut told, &report(0, std::slice::from_ref(&style)))
            .expect("a new hold is a reason to print the report");
        assert!(first.contains("received 0 new event(s)"), "{first}");
        assert_eq!(first.matches(&hold_line("style")).count(), 1, "{first}");

        // The next tick finds the same state and moved nothing: not printed.
        assert_eq!(
            daemon_report(&mut told, &report(0, std::slice::from_ref(&style))),
            None
        );

        // A later exchange moved events: the report is printed, without the hold.
        let moved = daemon_report(&mut told, &report(4, std::slice::from_ref(&style)))
            .expect("events moved");
        assert!(moved.contains("received 4 new event(s)"), "{moved}");
        assert!(!moved.contains("is held on this machine"), "{moved}");

        // A rule waits for the owner, which is reported on every tick while it waits.
        // The hold is not reported with it.
        let mut waiting = report(0, std::slice::from_ref(&style));
        waiting.changes.asking = vec![governance::Waiting {
            name: "commits".to_owned(),
            proposal_id: EventId::from_digest(ph_core::Digest::sha256(b"commits")),
            why: "ask_owner",
        }];
        for _ in 0..2 {
            let printed = daemon_report(&mut told, &waiting).expect("a rule waits");
            assert!(
                printed.contains("rule commits is in force and waits for your confirmation"),
                "{printed}"
            );
            assert!(!printed.contains("is held on this machine"), "{printed}");
        }

        // A second rule becomes held: the report has that hold, and not the first.
        let both = [style.clone(), held("tests", "team")];
        let second = daemon_report(&mut told, &report(0, &both)).expect("a new hold");
        assert_eq!(second.matches(&hold_line("tests")).count(), 1, "{second}");
        assert!(!second.contains(&hold_line("style")), "{second}");
        assert_eq!(daemon_report(&mut told, &report(0, &both)), None);

        // What the request handler hands over goes through the same record: a hold it
        // reported is not printed again by the daemon's own next exchange, and the
        // other way round.
        let pushed = [held("layout", "team")];
        assert_eq!(told.new_in(&pushed).len(), 1);
        assert_eq!(daemon_report(&mut told, &report(0, &pushed)), None);
        assert!(told.new_in(&both).is_empty());

        // A one-shot `sync` is one report: it lists every hold it found.
        let once = report(0, &both);
        let mut t = Text::new();
        sync_lines(&mut t, &once, &once.changes.held);
        let printed = t.finish();
        assert!(printed.contains(&hold_line("style")), "{printed}");
        assert!(printed.contains(&hold_line("tests")), "{printed}");
    }

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
