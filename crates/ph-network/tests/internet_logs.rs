//! What a node in internet mode writes to the log: peer ids and counts, no addresses.
//!
//! This test is a file of its own because it installs the process-wide log subscriber,
//! which can be done once. It keeps every log event of every crate at every level while
//! two nodes go through the whole life of the mode on the private network of
//! `common/hub.rs`: join, reserve a relay, be found, connect through the relay, punch a
//! hole, exchange requests, stop.

mod common;
#[path = "common/hub.rs"]
mod hub;

use std::sync::{Arc, Mutex};

use common::*;
use hub::*;
use ph_network::{HelloOnlyHandler, NetEvent};
use ph_protocol::wire::{ErrorCode, Request, Response};

/// What was logged: target, level and the fields as text.
type Logged = Arc<Mutex<Vec<(String, tracing::Level, String)>>>;

/// Keeps everything.
struct KeepLogs(Logged);

impl tracing::Subscriber for KeepLogs {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        // The fields of a span are log output, too.
        let mut fields = Fields(String::new());
        span.record(&mut fields);
        self.0.lock().unwrap().push((
            span.metadata().target().to_owned(),
            *span.metadata().level(),
            fields.0,
        ));
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push((
            event.metadata().target().to_owned(),
            *event.metadata().level(),
            fields.0,
        ));
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

struct Fields(String);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        let _ = write!(self.0, " {}={value:?}", field.name());
    }
}

/// Whether `text` looks like it holds a network address: a multiaddr, or an IPv4
/// address with a port.
fn names_an_address(text: &str) -> bool {
    let multiaddr = ["/ip4/", "/ip6/", "/udp/", "/quic", "/p2p-circuit", "/dns"]
        .iter()
        .any(|part| text.contains(part));
    let socket = text.contains("127.0.0.1") || text.contains("[::1]");
    multiaddr || socket
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_in_internet_mode_logs_peer_ids_and_counts_and_no_addresses() {
    let logged = Logged::default();
    tracing::dispatcher::set_global_default(tracing::Dispatch::new(KeepLogs(logged.clone())))
        .expect("no other subscriber in this process");

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
    let (a_id, b_id) = (a.net.local_peer_id(), b.net.local_peer_id());
    let mut a_events = a.net.subscribe();
    let mut b_events = b.net.subscribe();
    relay_addrs(&a.net).await;
    let found = find(&b.net, a_id).await;
    assert_eq!(within("dial", b.net.dial(found[0].clone())).await, Ok(a_id));
    let resp = within("hello", b.net.request(a_id, &Request::hello()))
        .await
        .unwrap();
    assert_eq!(resp, Response::hello());
    for (events, peer) in [(&mut a_events, b_id), (&mut b_events, a_id)] {
        wait_event(events, "DirectUpgradeSucceeded", |e| {
            *e == NetEvent::DirectUpgradeSucceeded { peer_id: peer }
        })
        .await;
    }
    let resp = within(
        "sync-sized request",
        b.net.request(a_id, &sync_sized_request()),
    )
    .await
    .unwrap();
    assert_eq!(resp, Response::error(ErrorCode::Unauthorized));
    // A dial that fails is logged, too.
    let nobody = ph_network::peer_id_from_device_key(&device_key(77));
    assert!(within("dial", b.net.dial(hub.circuit(nobody)))
        .await
        .is_err());
    stop(a).await;
    stop(b).await;
    hub.stop().await;

    let logged = logged.lock().unwrap();
    // The mode did log what it did, with peer ids and counts.
    let said = |what: &str| {
        logged
            .iter()
            .any(|(target, _, fields)| target.starts_with("ph_network") && fields.contains(what))
    };
    for what in [
        "internet mode on",
        "joined the public network",
        "relay reservation held",
        "looking a peer up",
        "relayed connection upgraded to a direct one",
        "network stopped",
    ] {
        assert!(said(what), "not logged: {what}");
    }
    assert!(logged
        .iter()
        .any(|(_, _, fields)| fields.contains(&a_id.to_string())));

    // Nothing a libp2p crate or the DNS resolver logs was written, at any level.
    let libp2p: Vec<_> = logged
        .iter()
        .filter(|(target, _, _)| target.starts_with("libp2p") || target.starts_with("hickory"))
        .take(5)
        .collect();
    assert!(libp2p.is_empty(), "{libp2p:?}");
    // And nothing that was written at ERROR, WARN, INFO or DEBUG names an address.
    let with_addresses: Vec<_> = logged
        .iter()
        .filter(|(_, level, fields)| *level <= tracing::Level::DEBUG && names_an_address(fields))
        .take(5)
        .collect();
    assert!(with_addresses.is_empty(), "{with_addresses:?}");
    // At TRACE one other crate does: the QUIC implementation (`quinn`) logs the socket
    // address of every packet from tasks of its own, with the mode as without it.
    let others: std::collections::BTreeSet<&str> = logged
        .iter()
        .filter(|(_, _, fields)| names_an_address(fields))
        .map(|(target, _, _)| target.split("::").next().unwrap_or(target))
        .collect();
    assert!(
        others.iter().all(|target| target.starts_with("quinn")),
        "{others:?}"
    );
}
