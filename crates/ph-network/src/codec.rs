//! The bounded, length-prefixed JSON codec for `/peerharness/req/0.1.0`.
//!
//! A frame is a 4-byte big-endian body length followed by the JSON body. Request and
//! response bodies are capped at [`MAX_FRAME_BYTES`] (512 KiB); an oversized length
//! prefix is rejected **before** any body byte is read or any buffer is allocated, and
//! the body buffer grows only as bytes arrive. An optional shared inbound budget
//! ([`PhCodec::with_inbound_budget`]) bounds the total request bytes buffered at once.
//!
//! Inbound requests never make the codec fail on content: a body that is not a valid
//! [`Request`] (bad JSON, duplicate keys, unknown fields, nesting too deep, collection
//! bounds exceeded) or an oversized prefix becomes [`RequestFrame::Rejected`] with the
//! error code to answer, so the swarm replies `error{bad_request|too_large}` without
//! invoking the application. Only transport-level problems (I/O errors, a body shorter
//! than its prefix) fail the read, which drops the stream.
//!
//! Inbound responses are strict: anything other than a valid [`Response`] fails the
//! read with an `InvalidData` I/O error, surfacing as [`crate::NetError::Codec`].

use std::io;
use std::sync::Arc;

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use libp2p::StreamProtocol;
use ph_protocol::wire::{ErrorCode, Request, Response, MAX_FRAME_BYTES, PROTOCOL_ID};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Size of the length prefix.
pub const LENGTH_PREFIX_BYTES: usize = 4;

/// The libp2p stream protocol (`/peerharness/req/0.1.0`).
pub const PROTOCOL: StreamProtocol = StreamProtocol::new(PROTOCOL_ID);

/// A request as carried by the codec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestFrame {
    /// An already-encoded request body (JCS bytes from [`Request::to_bytes`]); this is
    /// what [`crate::NetworkHandle::request`] sends. Writing fails if it is larger than
    /// [`MAX_FRAME_BYTES`].
    Encoded(Vec<u8>),
    /// A strictly decoded and validated inbound request. Writing re-encodes it.
    Decoded {
        /// The request.
        request: Request,
        /// Body bytes read from the wire (without the 4-byte prefix).
        wire_len: usize,
    },
    /// An inbound frame that must be answered with `error{code}` without reaching the
    /// application. Writing this variant fails with `InvalidInput`.
    Rejected {
        /// `bad_request` (malformed body), `too_large` (oversized prefix; body not read)
        /// or `unavailable` (inbound buffer budget exhausted; body not read).
        code: ErrorCode,
        /// Body bytes read from the wire (0 when the prefix itself was rejected).
        wire_len: usize,
    },
}

impl RequestFrame {
    /// Bytes this frame occupied on the wire including the length prefix (for the
    /// inbound byte budget). Encoded frames report their body length plus the prefix.
    pub fn wire_bytes(&self) -> usize {
        let body = match self {
            RequestFrame::Encoded(b) => b.len(),
            RequestFrame::Decoded { wire_len, .. } | RequestFrame::Rejected { wire_len, .. } => {
                *wire_len
            }
        };
        body.saturating_add(LENGTH_PREFIX_BYTES)
    }
}

/// A response as carried by the codec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseFrame {
    /// An already-encoded response body (JCS bytes).
    Encoded(Vec<u8>),
    /// A strictly decoded and validated response. Writing re-encodes it.
    Decoded(Response),
}

/// Why reading a length-prefixed frame failed.
#[derive(Debug)]
pub enum FrameReadError {
    /// The declared body length exceeds the maximum. No body byte was read.
    TooLarge {
        /// The declared length.
        declared: u64,
    },
    /// I/O error or truncated body.
    Io(io::Error),
}

impl From<io::Error> for FrameReadError {
    fn from(e: io::Error) -> Self {
        FrameReadError::Io(e)
    }
}

/// Reads a 4-byte big-endian length prefix and checks it against `max`.
///
/// Returns the declared body length. No body byte is read.
pub async fn read_prefix<T>(io: &mut T, max: usize) -> Result<usize, FrameReadError>
where
    T: AsyncRead + Unpin + Send,
{
    let mut prefix = [0u8; LENGTH_PREFIX_BYTES];
    io.read_exact(&mut prefix).await?;
    let declared = u32::from_be_bytes(prefix);
    match usize::try_from(declared) {
        Ok(len) if len <= max => Ok(len),
        _ => Err(FrameReadError::TooLarge {
            declared: u64::from(declared),
        }),
    }
}

/// Initial (and minimum) growth step of the body buffer.
const BODY_CHUNK: usize = 16 * 1024;

/// Reads exactly `len` body bytes.
///
/// The buffer grows only as bytes actually arrive: its capacity never exceeds `len`, nor
/// `max(16 KiB, 2 x bytes received so far)`, so a peer that declares a large frame and
/// then stalls does not make us allocate the declared size. A body shorter than `len`
/// is an `UnexpectedEof` I/O error.
pub async fn read_body<T>(io: &mut T, len: usize) -> Result<Vec<u8>, FrameReadError>
where
    T: AsyncRead + Unpin + Send,
{
    let mut body: Vec<u8> = Vec::new();
    let mut filled = 0usize;
    while filled < len {
        if filled == body.len() {
            let step = body.len().max(BODY_CHUNK).min(len - body.len());
            body.reserve_exact(step);
            body.resize(body.len() + step, 0);
        }
        match io.read(&mut body[filled..]).await {
            Ok(0) => {
                return Err(FrameReadError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated frame",
                )))
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(FrameReadError::Io(e)),
        }
    }
    Ok(body)
}

/// Reads one length-prefixed frame body of at most `max` bytes
/// ([`read_prefix`] followed by [`read_body`]).
///
/// An oversized prefix fails with [`FrameReadError::TooLarge`] before any body byte is
/// read or any body buffer is allocated.
pub async fn read_frame<T>(io: &mut T, max: usize) -> Result<Vec<u8>, FrameReadError>
where
    T: AsyncRead + Unpin + Send,
{
    let len = read_prefix(io, max).await?;
    read_body(io, len).await
}

/// Writes one length-prefixed frame (prefix and body), refusing bodies over `max`.
pub async fn write_frame<T>(io: &mut T, body: &[u8], max: usize) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    if body.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame exceeds maximum size",
        ));
    }
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    io.write_all(&len.to_be_bytes()).await?;
    io.write_all(body).await?;
    io.flush().await
}

/// Decodes an inbound request body into a frame; never fails.
pub fn decode_request(body: &[u8]) -> RequestFrame {
    match Request::from_bytes(body) {
        Ok(request) => RequestFrame::Decoded {
            request,
            wire_len: body.len(),
        },
        Err(e) => RequestFrame::Rejected {
            code: ErrorCode::for_decode_error(&e),
            wire_len: body.len(),
        },
    }
}

fn invalid_data(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// The `request_response::Codec` implementation used by the swarm.
///
/// libp2p clones the codec for every connection and stream, so an inbound budget set
/// with [`PhCodec::with_inbound_budget`] is shared by all of them: it bounds the total
/// number of inbound request body bytes buffered (and being decoded) at any moment,
/// across all peers and connections. A request whose declared body does not fit into
/// the remaining budget is not read; it becomes [`RequestFrame::Rejected`] with
/// `unavailable`, so the sender gets an immediate, retryable answer instead of a stream
/// that hangs until it times out. [`PhCodec::default`] has no budget.
#[derive(Clone, Debug, Default)]
pub struct PhCodec {
    inbound_budget: Option<Arc<Semaphore>>,
}

impl PhCodec {
    /// A codec whose inbound request buffering is capped at `bytes` in total (clamped
    /// to at least [`MAX_FRAME_BYTES`], so one maximal frame always fits, and at most
    /// [`Semaphore::MAX_PERMITS`]).
    pub fn with_inbound_budget(bytes: usize) -> Self {
        let bytes = bytes.clamp(MAX_FRAME_BYTES, Semaphore::MAX_PERMITS);
        Self {
            inbound_budget: Some(Arc::new(Semaphore::new(bytes))),
        }
    }

    /// Inbound budget bytes currently available, or `None` if the codec has no budget.
    pub fn inbound_budget_available(&self) -> Option<usize> {
        self.inbound_budget.as_ref().map(|s| s.available_permits())
    }

    /// Reserves `len` bytes of inbound budget. `Ok(None)` when there is no budget,
    /// `Err(())` when the budget is exhausted.
    fn reserve(&self, len: usize) -> Result<Option<OwnedSemaphorePermit>, ()> {
        let Some(budget) = &self.inbound_budget else {
            return Ok(None);
        };
        // len <= MAX_FRAME_BYTES (512 KiB) always fits in u32.
        let permits = u32::try_from(len).map_err(|_| ())?;
        Arc::clone(budget)
            .try_acquire_many_owned(permits)
            .map(Some)
            .map_err(|_| ())
    }
}

impl request_response::Codec for PhCodec {
    type Protocol = StreamProtocol;
    type Request = RequestFrame;
    type Response = ResponseFrame;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<RequestFrame>
    where
        T: AsyncRead + Unpin + Send,
    {
        let len = match read_prefix(io, MAX_FRAME_BYTES).await {
            Ok(len) => len,
            Err(FrameReadError::TooLarge { .. }) => {
                return Ok(RequestFrame::Rejected {
                    code: ErrorCode::TooLarge,
                    wire_len: 0,
                })
            }
            Err(FrameReadError::Io(e)) => return Err(e),
        };
        // Held while the body is buffered and decoded.
        let Ok(_permit) = self.reserve(len) else {
            return Ok(RequestFrame::Rejected {
                code: ErrorCode::Unavailable,
                wire_len: 0,
            });
        };
        match read_body(io, len).await {
            Ok(body) => Ok(decode_request(&body)),
            Err(FrameReadError::TooLarge { .. }) => Ok(RequestFrame::Rejected {
                code: ErrorCode::TooLarge,
                wire_len: 0,
            }),
            Err(FrameReadError::Io(e)) => Err(e),
        }
    }

    async fn read_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<ResponseFrame>
    where
        T: AsyncRead + Unpin + Send,
    {
        let body = match read_frame(io, MAX_FRAME_BYTES).await {
            Ok(b) => b,
            Err(FrameReadError::TooLarge { .. }) => return Err(invalid_data("oversized frame")),
            Err(FrameReadError::Io(e)) => return Err(e),
        };
        Response::from_bytes(&body)
            .map(ResponseFrame::Decoded)
            .map_err(|_| invalid_data("malformed response"))
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        req: RequestFrame,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let body = match req {
            RequestFrame::Encoded(b) => b,
            RequestFrame::Decoded { request, .. } => request
                .to_bytes()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "unencodable request"))?,
            RequestFrame::Rejected { .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "rejected frames cannot be sent",
                ))
            }
        };
        write_frame(io, &body, MAX_FRAME_BYTES).await
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        res: ResponseFrame,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let body = match res {
            ResponseFrame::Encoded(b) => b,
            ResponseFrame::Decoded(r) => encode_response(&r),
        };
        write_frame(io, &body, MAX_FRAME_BYTES).await
    }
}

/// Canonical bytes of `error{unavailable}`, used when a response cannot be encoded.
const UNAVAILABLE_BYTES: &[u8] = br#"{"code":"unavailable","type":"error"}"#;

/// Encodes a response, substituting `error{too_large}` (frame over 512 KiB) or
/// `error{unavailable}` (any other bound violated) when it cannot be encoded, so that a
/// buggy handler never produces an invalid frame.
pub fn encode_response(response: &Response) -> Vec<u8> {
    match response.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            let code = match ErrorCode::for_decode_error(&e) {
                ErrorCode::TooLarge => ErrorCode::TooLarge,
                _ => ErrorCode::Unavailable,
            };
            tracing::warn!(
                kind = response.kind(),
                "local response could not be encoded"
            );
            Response::error(code)
                .to_bytes()
                .unwrap_or_else(|_| UNAVAILABLE_BYTES.to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_constant_is_canonical() {
        assert_eq!(
            Response::error(ErrorCode::Unavailable).to_bytes().unwrap(),
            UNAVAILABLE_BYTES
        );
    }

    #[test]
    fn wire_bytes_includes_prefix() {
        assert_eq!(RequestFrame::Encoded(vec![0; 10]).wire_bytes(), 14);
        assert_eq!(
            RequestFrame::Rejected {
                code: ErrorCode::TooLarge,
                wire_len: 0
            }
            .wire_bytes(),
            4
        );
    }

    #[test]
    fn oversized_response_is_replaced() {
        let big = "a".repeat(32);
        let files: Vec<_> = (0..16)
            .map(|i| ph_protocol::wire::WireFile {
                path: format!("{big}{i}"),
                content_b64: "A".repeat(40_000),
            })
            .collect();
        let r = Response::Bundle {
            digest: ph_core::Digest::sha256(b"x"),
            files,
        };
        let bytes = encode_response(&r);
        let back = Response::from_bytes(&bytes).unwrap();
        assert!(matches!(back, Response::Error { .. }));
    }
}
