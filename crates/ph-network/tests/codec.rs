//! Direct codec tests against in-memory `futures::io::Cursor` streams.

use std::io;

use futures::executor::block_on;
use futures::io::Cursor;
use ph_network::codec::{
    read_frame, FrameReadError, PhCodec, RequestFrame, ResponseFrame, PROTOCOL,
};
use ph_network::libp2p::request_response::Codec;
use ph_protocol::wire::{ErrorCode, Request, Response, MAX_FRAME_BYTES};

fn framed(body: &[u8]) -> Vec<u8> {
    let mut v = (body.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(body);
    v
}

fn read_req(bytes: Vec<u8>) -> (io::Result<RequestFrame>, u64) {
    let mut cur = Cursor::new(bytes);
    let r = block_on(PhCodec::default().read_request(&PROTOCOL, &mut cur));
    (r, cur.position())
}

fn read_resp(bytes: Vec<u8>) -> (io::Result<ResponseFrame>, u64) {
    let mut cur = Cursor::new(bytes);
    let r = block_on(PhCodec::default().read_response(&PROTOCOL, &mut cur));
    (r, cur.position())
}

fn rejected(r: io::Result<RequestFrame>) -> ErrorCode {
    match r {
        Ok(RequestFrame::Rejected { code, .. }) => code,
        other => panic!("expected rejection, got {other:?}"),
    }
}

#[test]
fn request_round_trip() {
    let mut out = Cursor::new(Vec::new());
    let body = Request::hello().to_bytes().unwrap();
    block_on(PhCodec::default().write_request(
        &PROTOCOL,
        &mut out,
        RequestFrame::Encoded(body.clone()),
    ))
    .unwrap();
    let wire = out.into_inner();
    assert_eq!(&wire[..4], &(body.len() as u32).to_be_bytes());
    let (r, _) = read_req(wire);
    assert_eq!(
        r.unwrap(),
        RequestFrame::Decoded {
            request: Request::hello(),
            wire_len: body.len()
        }
    );

    // The Decoded variant re-encodes to the same canonical bytes.
    let mut out = Cursor::new(Vec::new());
    block_on(PhCodec::default().write_request(
        &PROTOCOL,
        &mut out,
        RequestFrame::Decoded {
            request: Request::hello(),
            wire_len: 0,
        },
    ))
    .unwrap();
    assert_eq!(out.into_inner(), framed(&body));
}

#[test]
fn response_round_trip() {
    let mut out = Cursor::new(Vec::new());
    block_on(PhCodec::default().write_response(
        &PROTOCOL,
        &mut out,
        ResponseFrame::Decoded(Response::hello()),
    ))
    .unwrap();
    let (r, _) = read_resp(out.into_inner());
    assert_eq!(r.unwrap(), ResponseFrame::Decoded(Response::hello()));
}

#[test]
fn oversized_request_prefix_rejected_before_body() {
    for declared in [MAX_FRAME_BYTES as u32 + 1, u32::MAX, 0x7fff_ffff] {
        let mut bytes = declared.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[b'{'; 64]);
        let (r, pos) = read_req(bytes);
        assert_eq!(rejected(r), ErrorCode::TooLarge);
        assert_eq!(pos, 4, "no body byte may be consumed");
    }
    assert!(matches!(
        block_on(read_frame(
            &mut Cursor::new(u32::MAX.to_be_bytes().to_vec()),
            MAX_FRAME_BYTES
        )),
        Err(FrameReadError::TooLarge { declared }) if declared == u64::from(u32::MAX)
    ));
}

#[test]
fn max_size_request_is_read_but_rejected_as_malformed() {
    let body = vec![b' '; MAX_FRAME_BYTES];
    let (r, pos) = read_req(framed(&body));
    assert_eq!(rejected(r), ErrorCode::BadRequest);
    assert_eq!(pos as usize, MAX_FRAME_BYTES + 4);
}

#[test]
fn malformed_requests_become_bad_request() {
    let cases: &[&[u8]] = &[
        b"",
        b"not json",
        b"{",
        b"[]",
        b"null",
        br#"{"type":"hello"}"#,
        br#"{"type":"nope","versions":["0.1"]}"#,
        br#"{"type":"hello","versions":["0.1"],"extra":1}"#,
        br#"{"type":"hello","versions":["0.1"],"versions":["0.1"]}"#,
        br#"{"type":"hello","versions":[1.5]}"#,
        br#"{"type":"hello","versions":[""]}"#,
        br#"{"type":"fetch_events","circle_id":"sha256:00","known":[],"limit":1}"#,
        b"\xff\xfe\x00",
        br#"{"type":"hello","versions":[[[[[[[[[[[["x"]]]]]]]]]]]]}"#,
    ];
    for c in cases {
        let (r, _) = read_req(framed(c));
        assert_eq!(
            rejected(r),
            ErrorCode::BadRequest,
            "case {:?}",
            String::from_utf8_lossy(c)
        );
    }
    // Collection bounds: limit out of range.
    let circle = ph_core::CircleId::derive(&ph_core::DeviceKey::from_signing_key(
        &ed25519_dalek::SigningKey::from_bytes(&[1; 32]),
    ));
    let body =
        format!(r#"{{"circle_id":"{circle}","known":[],"limit":100000,"type":"fetch_events"}}"#);
    let (r, _) = read_req(framed(body.as_bytes()));
    assert_eq!(rejected(r), ErrorCode::BadRequest);
}

#[test]
fn truncated_or_empty_streams_fail_the_read() {
    let (r, _) = read_req(Vec::new());
    assert_eq!(r.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    let (r, _) = read_req(vec![0, 0]);
    assert_eq!(r.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    let mut bytes = 100u32.to_be_bytes().to_vec();
    bytes.extend_from_slice(b"{\"type\":");
    let (r, _) = read_req(bytes);
    assert_eq!(r.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn malformed_or_oversized_responses_fail_the_read() {
    let (r, pos) = read_resp(u32::MAX.to_be_bytes().to_vec());
    assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(pos, 4);
    for c in [
        &b"garbage"[..],
        br#"{"type":"hello"}"#,
        br#"{"type":"error","code":"nope"}"#,
        br#"{"type":"error","code":"unauthorized","x":1}"#,
    ] {
        let (r, _) = read_resp(framed(c));
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
    let (r, _) = read_resp(framed(br#"{"code":"rate_limited","type":"error"}"#));
    assert_eq!(
        r.unwrap(),
        ResponseFrame::Decoded(Response::error(ErrorCode::RateLimited))
    );
}

#[test]
fn writer_refuses_invalid_frames() {
    let mut out = Cursor::new(Vec::new());
    let r = block_on(PhCodec::default().write_request(
        &PROTOCOL,
        &mut out,
        RequestFrame::Encoded(vec![b' '; MAX_FRAME_BYTES + 1]),
    ));
    assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    assert!(
        out.get_ref().is_empty(),
        "nothing written for oversized frames"
    );

    let r = block_on(PhCodec::default().write_request(
        &PROTOCOL,
        &mut out,
        RequestFrame::Rejected {
            code: ErrorCode::BadRequest,
            wire_len: 0,
        },
    ));
    assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidInput);

    let r = block_on(PhCodec::default().write_request(
        &PROTOCOL,
        &mut out,
        RequestFrame::Decoded {
            request: Request::Hello {
                versions: (0..50).map(|i| i.to_string()).collect(),
            },
            wire_len: 0,
        },
    ));
    assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    assert!(out.get_ref().is_empty());
}

#[test]
fn unencodable_response_is_replaced_by_error() {
    let mut out = Cursor::new(Vec::new());
    let bad = Response::Hello {
        versions: vec![String::new()],
        capabilities: vec![],
    };
    block_on(PhCodec::default().write_response(&PROTOCOL, &mut out, ResponseFrame::Decoded(bad)))
        .unwrap();
    let (r, _) = read_resp(out.into_inner());
    assert_eq!(
        r.unwrap(),
        ResponseFrame::Decoded(Response::error(ErrorCode::Unavailable))
    );
}

/// Yields `data`, then (optionally) never completes, like a peer that stalls mid-frame.
struct Stalling {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
    stall: bool,
}

impl futures::AsyncRead for Stalling {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.pos >= this.data.len() {
            return if this.stall {
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(Ok(0))
            };
        }
        let n = buf.len().min(this.chunk).min(this.data.len() - this.pos);
        buf[..n].copy_from_slice(&this.data[this.pos..this.pos + n]);
        this.pos += n;
        std::task::Poll::Ready(Ok(n))
    }
}

#[test]
fn body_delivered_in_small_pieces_is_reassembled() {
    // A valid request padded with JSON whitespace to ~300 KiB, delivered 1000 bytes at a
    // time, crosses many buffer growth steps.
    let mut body = Request::hello().to_bytes().unwrap();
    body.extend(std::iter::repeat_n(b' ', 300 * 1024));
    let mut r = Stalling {
        data: framed(&body),
        pos: 0,
        chunk: 1000,
        stall: false,
    };
    let frame = block_on(PhCodec::default().read_request(&PROTOCOL, &mut r)).unwrap();
    assert_eq!(
        frame,
        RequestFrame::Decoded {
            request: Request::hello(),
            wire_len: body.len()
        }
    );
}

#[test]
fn stalled_body_fails_or_waits_without_reading_past_frame() {
    // Declared 1000 bytes, only 10 arrive, then EOF: truncated, stream dropped.
    let mut data = 1000u32.to_be_bytes().to_vec();
    data.extend_from_slice(&[b' '; 10]);
    let mut r = Stalling {
        data,
        pos: 0,
        chunk: 4096,
        stall: false,
    };
    let err = block_on(PhCodec::default().read_request(&PROTOCOL, &mut r)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test(flavor = "current_thread")]
async fn inbound_budget_is_shared_and_released() {
    use futures::FutureExt;

    let codec = PhCodec::with_inbound_budget(MAX_FRAME_BYTES);
    assert_eq!(codec.inbound_budget_available(), Some(MAX_FRAME_BYTES));
    assert_eq!(PhCodec::default().inbound_budget_available(), None);

    // A stalled peer declares a maximal frame and sends only part of it.
    let mut stalled_data = (MAX_FRAME_BYTES as u32).to_be_bytes().to_vec();
    stalled_data.extend_from_slice(&[b' '; 100]);
    let mut stalled_io = Stalling {
        data: stalled_data,
        pos: 0,
        chunk: 4096,
        stall: true,
    };
    let mut c1 = codec.clone();
    let mut stalled = Box::pin(async move { c1.read_request(&PROTOCOL, &mut stalled_io).await });
    assert!((&mut stalled).now_or_never().is_none());
    // The whole budget is reserved by the stalled stream (clones share it).
    assert_eq!(codec.inbound_budget_available(), Some(0));

    // Another request is refused at once with `unavailable`; its body is not read.
    let hello = framed(&Request::hello().to_bytes().unwrap());
    let mut cur = Cursor::new(hello.clone());
    let r = codec.clone().read_request(&PROTOCOL, &mut cur).await;
    assert_eq!(rejected(r), ErrorCode::Unavailable);
    assert_eq!(cur.position(), 4);

    // Dropping the stalled stream (as libp2p's stream timeout does) frees the budget.
    drop(stalled);
    assert_eq!(codec.inbound_budget_available(), Some(MAX_FRAME_BYTES));
    let mut cur = Cursor::new(hello);
    let r = codec.clone().read_request(&PROTOCOL, &mut cur).await;
    assert!(matches!(r, Ok(RequestFrame::Decoded { .. })));
    // Completed reads release their reservation.
    assert_eq!(codec.inbound_budget_available(), Some(MAX_FRAME_BYTES));

    // Oversized prefixes never touch the budget.
    let mut c3 = codec.clone();
    let mut cur = Cursor::new(u32::MAX.to_be_bytes().to_vec());
    let r = c3.read_request(&PROTOCOL, &mut cur).await;
    assert_eq!(rejected(r), ErrorCode::TooLarge);
    assert_eq!(codec.inbound_budget_available(), Some(MAX_FRAME_BYTES));

    // A budget below one frame is clamped up so a maximal frame always fits.
    assert_eq!(
        PhCodec::with_inbound_budget(1).inbound_budget_available(),
        Some(MAX_FRAME_BYTES)
    );
}
