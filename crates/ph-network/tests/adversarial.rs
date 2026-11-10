//! A hostile raw client speaking `/peerharness/req/0.1.0` with arbitrary bytes over real
//! QUIC. Malformed frames must be answered with `bad_request` / `too_large` without
//! reaching the application handler, and must not disturb the node.

mod common;

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use ph_network::libp2p::request_response::{self, Codec, Message, ProtocolSupport};
use ph_network::libp2p::swarm::SwarmEvent;
use ph_network::libp2p::{identity::Keypair, StreamProtocol, Swarm, SwarmBuilder};
use ph_network::{handler_fn, PeerId, PeerInfo};
use ph_protocol::wire::{ErrorCode, Request, Response, PROTOCOL_ID};

/// A raw request: bytes written verbatim, optionally followed by stalling forever
/// (keeping the stream open without finishing the frame).
#[derive(Clone, Debug)]
struct RawReq {
    bytes: Vec<u8>,
    stall: bool,
}

/// Writes request bytes verbatim; reads the whole response stream.
#[derive(Clone, Default)]
struct RawCodec;

impl Codec for RawCodec {
    type Protocol = StreamProtocol;
    type Request = RawReq;
    type Response = Vec<u8>;

    async fn read_request<T>(&mut self, _: &StreamProtocol, _io: &mut T) -> io::Result<RawReq>
    where
        T: AsyncRead + Unpin + Send,
    {
        Err(io::Error::other("raw client does not accept requests"))
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut v = Vec::new();
        io.take(2 * 1024 * 1024).read_to_end(&mut v).await?;
        Ok(v)
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        req: RawReq,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&req.bytes).await?;
        io.flush().await?;
        if req.stall {
            futures::future::pending::<()>().await;
        }
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        _io: &mut T,
        _r: Vec<u8>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Err(io::Error::other("unused"))
    }
}

type RawSwarm = Swarm<request_response::Behaviour<RawCodec>>;

fn raw_swarm(seed: [u8; 32]) -> RawSwarm {
    let mut seed = seed;
    let kp = Keypair::ed25519_from_bytes(&mut seed[..]).unwrap();
    let rr = request_response::Behaviour::with_codec(
        RawCodec,
        [(StreamProtocol::new(PROTOCOL_ID), ProtocolSupport::Outbound)],
        request_response::Config::default().with_request_timeout(Duration::from_secs(15)),
    );
    SwarmBuilder::with_existing_identity(kp)
        .with_tokio()
        .with_quic()
        .with_behaviour(|_| rr)
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build()
}

async fn raw_connect(swarm: &mut RawSwarm, addr: ph_network::Multiaddr) -> PeerId {
    swarm.dial(addr).unwrap();
    within("raw connect", async {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => return peer_id,
                SwarmEvent::OutgoingConnectionError { .. } => panic!("raw dial failed"),
                _ => {}
            }
        }
    })
    .await
}

/// Sends raw bytes and returns the decoded response, or `None` if the stream failed.
async fn raw_request(swarm: &mut RawSwarm, peer: PeerId, bytes: Vec<u8>) -> Option<Response> {
    let id = swarm.behaviour_mut().send_request(
        &peer,
        RawReq {
            bytes,
            stall: false,
        },
    );
    let raw = within("raw response", async {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message:
                        Message::Response {
                            request_id,
                            response,
                        },
                    ..
                }) if request_id == id => return Some(response),
                SwarmEvent::Behaviour(request_response::Event::OutboundFailure {
                    request_id,
                    ..
                }) if request_id == id => return None,
                _ => {}
            }
        }
    })
    .await?;
    if raw.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    assert_eq!(
        raw.len(),
        4 + len,
        "response frame length must match prefix"
    );
    Some(Response::from_bytes(&raw[4..]).expect("server responses are valid"))
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut v = (body.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(body);
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_frames_never_reach_the_handler() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls2 = calls.clone();
    let handler = handler_fn(move |_p: PeerInfo, _r: Request| {
        calls2.fetch_add(1, Ordering::SeqCst);
        async { Response::hello() }
    });
    let a = node(40, loopback_config(), handler);
    let addr = within("addrs", a.net.listen_addrs()).await.unwrap()[0].clone();

    let mut raw = raw_swarm([41; 32]);
    let pid = raw_connect(&mut raw, addr).await;
    assert_eq!(pid, a.net.local_peer_id());

    let bad_request = Some(Response::error(ErrorCode::BadRequest));
    for body in [
        &b"garbage"[..],
        b"",
        br#"{"type":"hello","versions":["0.1"],"versions":["0.1"]}"#,
        br#"{"type":"hello","versions":["0.1"],"admin":true}"#,
        br#"{"type":"push_events","events":[1,2,3]}"#,
    ] {
        assert_eq!(raw_request(&mut raw, pid, framed(body)).await, bad_request);
    }

    // Oversized prefix: answered too_large without the body being read.
    let mut big = (8u32 * 1024 * 1024).to_be_bytes().to_vec();
    big.extend_from_slice(&[b'{'; 32]);
    let r = raw_request(&mut raw, pid, big).await;
    assert_eq!(r, Some(Response::error(ErrorCode::TooLarge)));

    // Truncated body: the stream is dropped, no response, node unaffected.
    let mut trunc = 1000u32.to_be_bytes().to_vec();
    trunc.extend_from_slice(b"{\"type\"");
    assert_eq!(raw_request(&mut raw, pid, trunc).await, None);

    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "handler must not see bad frames"
    );

    // A well-formed frame from the same raw client still works.
    let ok = raw_request(&mut raw, pid, framed(&Request::hello().to_bytes().unwrap())).await;
    assert_eq!(ok, Some(Response::hello()));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // And so do normal peers.
    let b = node(
        42,
        loopback_config(),
        Arc::new(ph_network::HelloOnlyHandler),
    );
    let pa = connect(&b.net, &a.net).await;
    assert_eq!(
        within("hello", b.net.request(pa, &Request::hello()))
            .await
            .unwrap(),
        Response::hello()
    );
    stop(a).await;
    stop(b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_frames_count_against_rate_limit() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls2 = calls.clone();
    let handler = handler_fn(move |_p: PeerInfo, _r: Request| {
        calls2.fetch_add(1, Ordering::SeqCst);
        async { Response::hello() }
    });
    let config = ph_network::NetworkConfig {
        rate_limits: ph_network::RateLimits {
            requests_per_sec: 1,
            burst: 3,
            ..ph_network::RateLimits::default()
        },
        ..loopback_config()
    };
    let a = node(43, config, handler);
    let addr = within("addrs", a.net.listen_addrs()).await.unwrap()[0].clone();
    let mut raw = raw_swarm([44; 32]);
    let pid = raw_connect(&mut raw, addr).await;
    let mut limited = 0;
    for _ in 0..6 {
        match raw_request(&mut raw, pid, framed(b"junk")).await {
            Some(Response::Error {
                code: ErrorCode::BadRequest,
            }) => {}
            Some(Response::Error {
                code: ErrorCode::RateLimited,
            }) => limited += 1,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(limited >= 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    stop(a).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_frames_do_not_wedge_the_node() {
    // A node with the smallest inbound buffer budget (one maximal frame) and a short
    // request timeout, so stalled streams are dropped quickly.
    let calls = Arc::new(AtomicUsize::new(0));
    let calls2 = calls.clone();
    let handler = handler_fn(move |_p: PeerInfo, _r: Request| {
        calls2.fetch_add(1, Ordering::SeqCst);
        async { Response::hello() }
    });
    let config = ph_network::NetworkConfig {
        request_timeout: Duration::from_secs(2),
        max_inbound_buffer_bytes: ph_protocol::wire::MAX_FRAME_BYTES,
        ..loopback_config()
    };
    let a = node(45, config, handler);
    let addr = within("addrs", a.net.listen_addrs()).await.unwrap()[0].clone();

    // The attacker opens several streams, each declaring a maximal frame and then
    // stalling after a few bytes, so the whole budget is held.
    let mut raw = raw_swarm([46; 32]);
    let pid = raw_connect(&mut raw, addr).await;
    for _ in 0..6 {
        let mut bytes = (ph_protocol::wire::MAX_FRAME_BYTES as u32)
            .to_be_bytes()
            .to_vec();
        bytes.extend_from_slice(b"{\"type\":");
        raw.behaviour_mut()
            .send_request(&pid, RawReq { bytes, stall: true });
    }
    // Keep the raw swarm polled in the background so its streams stay alive.
    let raw_task = tokio::spawn(async move {
        loop {
            let _ = raw.select_next_some().await;
        }
    });

    // While the budget is held a well-behaved peer gets a prompt, retryable
    // `unavailable` (never a hang); once the stalled streams time out it is served
    // again. The node never wedges and the handler never sees the stalled frames.
    let b = node(
        47,
        loopback_config(),
        Arc::new(ph_network::HelloOnlyHandler),
    );
    let pa = connect(&b.net, &a.net).await;
    let mut served = 0;
    within("served after stall", async {
        while served < 3 {
            match b.net.request(pa, &Request::hello()).await {
                Ok(Response::Hello { .. }) => served += 1,
                Ok(Response::Error {
                    code: ErrorCode::Unavailable,
                }) => tokio::time::sleep(Duration::from_millis(100)).await,
                other => panic!("unexpected {other:?}"),
            }
        }
    })
    .await;
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    raw_task.abort();
    stop(a).await;
    stop(b).await;
}
