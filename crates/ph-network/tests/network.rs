//! In-process multi-node tests over real QUIC on 127.0.0.1 ephemeral ports.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use ph_core::DeviceKey;
use ph_network::{
    device_key_from_peer_id, handler_fn, peer_id_from_device_key, start, with_p2p,
    HelloOnlyHandler, NetError, NetEvent, NetworkConfig, PeerInfo, RateLimits,
};
use ph_protocol::wire::{ErrorCode, Request, Response};
use tokio::sync::{mpsc, Notify};

type Seen = Arc<Mutex<Vec<PeerInfo>>>;

fn recording_handler(seen: Seen) -> Arc<dyn ph_network::RequestHandler> {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_nodes_hello_round_trip() {
    let a = node(1, loopback_config(), Arc::new(HelloOnlyHandler));
    let b = node(2, loopback_config(), Arc::new(HelloOnlyHandler));
    assert_eq!(a.net.local_device_key(), device_key(1));
    assert_eq!(
        device_key_from_peer_id(&a.net.local_peer_id()),
        Some(device_key(1))
    );
    assert_eq!(
        peer_id_from_device_key(&device_key(2)),
        b.net.local_peer_id()
    );

    let mut a_events = a.net.subscribe();
    let pid = connect(&b.net, &a.net).await;

    let ev = wait_event(&mut a_events, "Connected on A", |e| {
        matches!(e, NetEvent::Connected { .. })
    })
    .await;
    match ev {
        NetEvent::Connected {
            peer_id,
            device_key,
            ..
        } => {
            assert_eq!(peer_id, b.net.local_peer_id());
            assert_eq!(device_key, device_key_of(2));
        }
        other => panic!("unexpected {other:?}"),
    }

    let resp = within("hello", b.net.request(pid, &Request::hello()))
        .await
        .unwrap();
    assert_eq!(resp, Response::hello());

    // The unauthenticated peer gets `unauthorized` for anything but hello.
    let resp = within(
        "fetch_bundle",
        b.net.request(
            pid,
            &Request::FetchBundle {
                circle_id: ph_core::CircleId::derive(&device_key(9)),
                digest: ph_core::Digest::sha256(b"x"),
            },
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp, Response::error(ErrorCode::Unauthorized));

    stop(a).await;
    stop(b).await;
}

fn device_key_of(n: u8) -> DeviceKey {
    device_key(n)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_sees_seed_derived_device_key() {
    let seen: Seen = Arc::default();
    let a = node(3, loopback_config(), recording_handler(seen.clone()));
    let b = node(4, loopback_config(), Arc::new(HelloOnlyHandler));
    let pid = connect(&b.net, &a.net).await;
    within("hello", b.net.request(pid, &Request::hello()))
        .await
        .unwrap();
    // Requests in the other direction work over the same connection.
    let back = within(
        "reverse hello",
        a.net.request(b.net.local_peer_id(), &Request::hello()),
    )
    .await
    .unwrap();
    assert_eq!(back, Response::hello());

    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].peer_id, b.net.local_peer_id());
    assert_eq!(seen[0].device_key, device_key(4));
    assert!(seen[0].remote_addr.is_some());

    let peers = within("connected_peers", a.net.connected_peers())
        .await
        .unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].device_key, device_key(4));
    stop(a).await;
    stop(b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_nodes_handler_distinguishes_peers() {
    let allowed = device_key(6);
    let seen: Seen = Arc::default();
    let seen2 = seen.clone();
    let handler = handler_fn(move |peer: PeerInfo, _req: Request| {
        let seen = seen2.clone();
        async move {
            seen.lock().unwrap().push(peer.clone());
            if peer.device_key == allowed {
                Response::hello()
            } else {
                Response::error(ErrorCode::Unauthorized)
            }
        }
    });
    let a = node(5, loopback_config(), handler);
    let b = node(6, loopback_config(), Arc::new(HelloOnlyHandler));
    let c = node(7, loopback_config(), Arc::new(HelloOnlyHandler));
    let pa_b = connect(&b.net, &a.net).await;
    let pa_c = connect(&c.net, &a.net).await;
    assert_eq!(pa_b, pa_c);

    let hello = Request::hello();
    let (rb, rc) = tokio::join!(
        within("b", b.net.request(pa_b, &hello)),
        within("c", c.net.request(pa_c, &hello)),
    );
    assert_eq!(rb.unwrap(), Response::hello());
    assert_eq!(rc.unwrap(), Response::error(ErrorCode::Unauthorized));

    let seen = seen.lock().unwrap().clone();
    let mut keys: Vec<DeviceKey> = seen.iter().map(|p| p.device_key).collect();
    keys.sort();
    let mut expected = vec![device_key(6), device_key(7)];
    expected.sort();
    assert_eq!(keys, expected);
    for p in &seen {
        assert_eq!(peer_id_from_device_key(&p.device_key), p.peer_id);
    }

    let mut peers: Vec<_> = within("peers", a.net.connected_peers())
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.peer_id)
        .collect();
    peers.sort();
    let mut want = vec![b.net.local_peer_id(), c.net.local_peer_id()];
    want.sort();
    assert_eq!(peers, want);

    stop(a).await;
    stop(b).await;
    stop(c).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_count_rate_limit_triggers() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls2 = calls.clone();
    let handler = handler_fn(move |_p: PeerInfo, _r: Request| {
        calls2.fetch_add(1, Ordering::SeqCst);
        async { Response::hello() }
    });
    let config = NetworkConfig {
        rate_limits: RateLimits {
            requests_per_sec: 1,
            burst: 2,
            ..RateLimits::default()
        },
        ..loopback_config()
    };
    let a = node(8, config, handler);
    let b = node(9, loopback_config(), Arc::new(HelloOnlyHandler));
    let pid = connect(&b.net, &a.net).await;

    let mut limited = 0;
    let mut ok = 0;
    for _ in 0..6 {
        match within("req", b.net.request(pid, &Request::hello()))
            .await
            .unwrap()
        {
            Response::Error {
                code: ErrorCode::RateLimited,
            } => limited += 1,
            Response::Hello { .. } => ok += 1,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(limited >= 1, "expected at least one rate_limited");
    assert!(ok >= 2, "burst should admit the first two");
    // The handler ran only for admitted requests.
    assert_eq!(calls.load(Ordering::SeqCst), ok);
    stop(a).await;
    stop(b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrency_limit_triggers_rate_limited() {
    let release = Arc::new(Notify::new());
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel::<()>();
    let release2 = release.clone();
    let handler = handler_fn(move |_p: PeerInfo, _r: Request| {
        let release = release2.clone();
        let entered = entered_tx.clone();
        async move {
            let _ = entered.send(());
            release.notified().await;
            Response::hello()
        }
    });
    let config = NetworkConfig {
        rate_limits: RateLimits {
            max_concurrent_inbound: 1,
            ..RateLimits::default()
        },
        ..loopback_config()
    };
    let a = node(10, config, handler);
    let b = node(11, loopback_config(), Arc::new(HelloOnlyHandler));
    let pid = connect(&b.net, &a.net).await;

    let b2 = b.net.clone();
    let first = tokio::spawn(async move { b2.request(pid, &Request::hello()).await });
    within("handler entered", entered_rx.recv()).await.unwrap();

    let second = within("second", b.net.request(pid, &Request::hello()))
        .await
        .unwrap();
    assert_eq!(second, Response::error(ErrorCode::RateLimited));

    release.notify_one();
    let first = within("first", first).await.unwrap().unwrap();
    assert_eq!(first, Response::hello());
    stop(a).await;
    stop(b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_handler_surfaces_timeout() {
    let handler = handler_fn(|_p: PeerInfo, _r: Request| async {
        tokio::time::sleep(Duration::from_secs(60)).await;
        Response::hello()
    });
    let a = node(12, loopback_config(), handler);
    let b_config = NetworkConfig {
        request_timeout: Duration::from_secs(1),
        ..loopback_config()
    };
    let b = node(13, b_config, Arc::new(HelloOnlyHandler));
    let pid = connect(&b.net, &a.net).await;
    let r = within("timeout", b.net.request(pid, &Request::hello())).await;
    assert_eq!(r, Err(NetError::Timeout));
    stop(a).await;
    stop(b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn panicking_handler_yields_unavailable() {
    let handler = handler_fn(|_p: PeerInfo, r: Request| async move {
        if matches!(r, Request::Hello { .. }) {
            panic!("handler bug");
        }
        Response::hello()
    });
    let a = node(14, loopback_config(), handler);
    let b = node(15, loopback_config(), Arc::new(HelloOnlyHandler));
    let pid = connect(&b.net, &a.net).await;
    let r = within("panic", b.net.request(pid, &Request::hello()))
        .await
        .unwrap();
    assert_eq!(r, Response::error(ErrorCode::Unavailable));
    // The node keeps working.
    let r = within(
        "after panic",
        b.net.request(
            pid,
            &Request::FetchBundle {
                circle_id: ph_core::CircleId::derive(&device_key(1)),
                digest: ph_core::Digest::sha256(b""),
            },
        ),
    )
    .await
    .unwrap();
    assert_eq!(r, Response::hello());
    stop(a).await;
    stop(b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dialing_dead_address_errors() {
    let config = NetworkConfig {
        dial_timeout: Duration::from_secs(5),
        ..loopback_config()
    };
    let b = node(16, config, Arc::new(HelloOnlyHandler));
    // A plain UDP socket that never answers: the QUIC handshake times out. The socket
    // stays bound for the whole dial so no concurrently started test node can take the
    // port (releasing it first made this test flaky).
    let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = blackhole.local_addr().unwrap().port();
    let addr = format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
        .parse()
        .unwrap();
    let r = within("dead dial", b.net.dial(addr)).await;
    assert_eq!(r, Err(NetError::Dial));
    drop(blackhole);

    // Non-QUIC address: rejected as a dial failure.
    let tcp = "/ip4/127.0.0.1/tcp/1".parse().unwrap();
    assert_eq!(
        within("tcp dial", b.net.dial(tcp)).await,
        Err(NetError::Dial)
    );
    stop(b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dial_with_wrong_peer_id_fails() {
    let a = node(17, loopback_config(), Arc::new(HelloOnlyHandler));
    let b = node(18, loopback_config(), Arc::new(HelloOnlyHandler));
    let addr = within("addrs", a.net.listen_addrs()).await.unwrap()[0].clone();
    let wrong = peer_id_from_device_key(&device_key(99));
    let r = within("wrong pid", b.net.dial(with_p2p(&addr, wrong))).await;
    assert_eq!(r, Err(NetError::Dial));
    assert!(
        !within("connected?", b.net.is_connected(a.net.local_peer_id()))
            .await
            .unwrap()
    );

    // The right /p2p suffix works, and a second dial is a no-op returning the same id.
    let good = with_p2p(&addr, a.net.local_peer_id());
    let pid = within("good", b.net.dial(good.clone())).await.unwrap();
    assert_eq!(pid, a.net.local_peer_id());
    assert_eq!(within("again", b.net.dial(good)).await.unwrap(), pid);
    stop(a).await;
    stop(b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_errors_without_connection_or_encoding() {
    let b = node(19, loopback_config(), Arc::new(HelloOnlyHandler));
    let stranger = peer_id_from_device_key(&device_key(98));
    assert_eq!(
        within("nc", b.net.request(stranger, &Request::hello())).await,
        Err(NetError::NotConnected)
    );
    let too_many = Request::Hello {
        versions: (0..100).map(|i| format!("v{i}")).collect(),
    };
    assert_eq!(
        within("enc", b.net.request(stranger, &too_many)).await,
        Err(NetError::Encode)
    );
    stop(b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_emits_event_on_both_sides() {
    let a = node(20, loopback_config(), Arc::new(HelloOnlyHandler));
    let b = node(21, loopback_config(), Arc::new(HelloOnlyHandler));
    let mut a_events = a.net.subscribe();
    let mut b_events = b.net.subscribe();
    let pid = connect(&b.net, &a.net).await;
    assert!(within("disc", b.net.disconnect(pid)).await.unwrap());
    let a_id = a.net.local_peer_id();
    let b_id = b.net.local_peer_id();
    wait_event(&mut b_events, "B disconnected", |e| {
        *e == NetEvent::Disconnected { peer_id: a_id }
    })
    .await;
    wait_event(&mut a_events, "A disconnected", |e| {
        *e == NetEvent::Disconnected { peer_id: b_id }
    })
    .await;
    assert!(!within("is_connected", b.net.is_connected(pid))
        .await
        .unwrap());
    assert!(!within("disc again", b.net.disconnect(pid)).await.unwrap());
    stop(a).await;
    stop(b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_is_clean() {
    let a = node(22, loopback_config(), Arc::new(HelloOnlyHandler));
    let b = node(23, loopback_config(), Arc::new(HelloOnlyHandler));
    let mut b_events = b.net.subscribe();
    let mut a_events = a.net.subscribe();
    let pid = connect(&b.net, &a.net).await;
    let a_net = a.net.clone();
    stop(a).await;

    // The remote observes the close promptly (clean QUIC close, not an idle timeout).
    wait_event(&mut b_events, "B sees A gone", |e| {
        *e == NetEvent::Disconnected { peer_id: pid }
    })
    .await;
    assert!(!a_net.is_running());
    assert_eq!(
        a_net
            .request(b.net.local_peer_id(), &Request::hello())
            .await,
        Err(NetError::Shutdown)
    );
    assert_eq!(
        a_net
            .dial("/ip4/127.0.0.1/udp/1/quic-v1".parse().unwrap())
            .await,
        Err(NetError::Shutdown)
    );
    assert_eq!(a_net.connected_peers().await, Err(NetError::Shutdown));
    assert_eq!(a_net.listen_addrs().await, Err(NetError::Shutdown));
    assert!(a_net.current_listen_addrs().is_empty());
    // Idempotent.
    within("second shutdown", a_net.shutdown()).await;
    // Subscribers drain and then see Closed.
    loop {
        match a_events.recv().await {
            Ok(_) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
        }
    }
    assert!(matches!(
        a_net.subscribe().recv().await,
        Err(tokio::sync::broadcast::error::RecvError::Closed)
    ));
    // B is unaffected.
    assert!(b.net.is_running());
    stop(b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_all_handles_stops_loop() {
    let a = node(24, loopback_config(), Arc::new(HelloOnlyHandler));
    let Node { net, join } = a;
    drop(net);
    within("loop end", join).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listen_addrs_resolve_ephemeral_port() {
    let a = node(25, loopback_config(), Arc::new(HelloOnlyHandler));
    let addrs = within("addrs", a.net.listen_addrs()).await.unwrap();
    assert!(!addrs.is_empty());
    for addr in &addrs {
        let s = addr.to_string();
        assert!(s.starts_with("/ip4/127.0.0.1/udp/"), "{s}");
        assert!(s.ends_with("/quic-v1"), "{s}");
        assert!(!s.contains("/udp/0/"), "{s}");
    }
    assert_eq!(a.net.current_listen_addrs(), addrs);

    // A dial-only node returns immediately with no addresses.
    let d = node(26, NetworkConfig::default(), Arc::new(HelloOnlyHandler));
    assert!(within("none", d.net.listen_addrs())
        .await
        .unwrap()
        .is_empty());
    // ... and can still dial and talk.
    let pid = connect(&d.net, &a.net).await;
    assert_eq!(
        within("hello", d.net.request(pid, &Request::hello()))
            .await
            .unwrap(),
        Response::hello()
    );
    stop(a).await;
    stop(d).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_listen_address_and_config_rejected() {
    let tcp = NetworkConfig::listening_on(["/ip4/127.0.0.1/tcp/0".parse().unwrap()]);
    assert_eq!(
        start(seed(27), tcp, Arc::new(HelloOnlyHandler)).err(),
        Some(NetError::Listen)
    );
    let bad = NetworkConfig {
        rate_limits: RateLimits {
            requests_per_sec: 0,
            ..RateLimits::default()
        },
        ..loopback_config()
    };
    assert_eq!(
        start(seed(27), bad, Arc::new(HelloOnlyHandler)).err(),
        Some(NetError::InvalidConfig)
    );
}

#[test]
fn start_outside_runtime_fails() {
    assert_eq!(
        start(seed(28), loopback_config(), Arc::new(HelloOnlyHandler)).err(),
        Some(NetError::NoRuntime)
    );
}

#[test]
fn errors_display_generically() {
    for e in [
        NetError::Dial,
        NetError::Timeout,
        NetError::ConnectionClosed,
        NetError::Codec,
        NetError::Shutdown,
        NetError::NotConnected,
        NetError::Encode,
    ] {
        let s = e.to_string();
        assert!(!s.is_empty());
        assert!(!s.contains('/'), "{s}");
    }
}

/// A handler that panics synchronously, before returning its future.
struct SyncPanic;

impl ph_network::RequestHandler for SyncPanic {
    fn handle(
        &self,
        _peer: PeerInfo,
        request: Request,
    ) -> futures::future::BoxFuture<'static, Response> {
        if matches!(request, Request::Hello { .. }) {
            panic!("synchronous handler bug");
        }
        Box::pin(async { Response::hello() })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn synchronously_panicking_handler_yields_unavailable() {
    let a = node(29, loopback_config(), Arc::new(SyncPanic));
    let b = node(30, loopback_config(), Arc::new(HelloOnlyHandler));
    let pid = connect(&b.net, &a.net).await;
    for _ in 0..2 {
        let r = within("panic", b.net.request(pid, &Request::hello()))
            .await
            .unwrap();
        assert_eq!(r, Response::error(ErrorCode::Unavailable));
    }
    let r = within(
        "after panic",
        b.net.request(
            pid,
            &Request::FetchBundle {
                circle_id: ph_core::CircleId::derive(&device_key(1)),
                digest: ph_core::Digest::sha256(b""),
            },
        ),
    )
    .await
    .unwrap();
    assert_eq!(r, Response::hello());
    stop(a).await;
    stop(b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_peer_connection_limit_refuses_extra_connections() {
    let a = node(31, loopback_config(), Arc::new(HelloOnlyHandler));
    let b_config = NetworkConfig {
        max_connections_per_peer: 1,
        ..loopback_config()
    };
    let b = node(32, b_config, Arc::new(HelloOnlyHandler));
    let addr = within("addrs", a.net.listen_addrs()).await.unwrap()[0].clone();
    // Without a /p2p suffix every dial opens a new connection; the second one to the
    // same peer exceeds the limit and is refused.
    let pid = within("first", b.net.dial(addr.clone())).await.unwrap();
    assert_eq!(pid, a.net.local_peer_id());
    assert_eq!(
        within("second", b.net.dial(addr)).await,
        Err(NetError::Dial)
    );
    // The first connection is unaffected.
    assert!(within("still", b.net.is_connected(pid)).await.unwrap());
    assert_eq!(
        within("hello", b.net.request(pid, &Request::hello()))
            .await
            .unwrap(),
        Response::hello()
    );
    stop(a).await;
    stop(b).await;
}
