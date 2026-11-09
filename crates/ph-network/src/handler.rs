//! The inbound request handler interface implemented by the application.

use std::future::Future;
use std::sync::Arc;

use futures::future::BoxFuture;
use futures::FutureExt;
use libp2p::{Multiaddr, PeerId};
use ph_core::DeviceKey;
use ph_protocol::wire::{ErrorCode, Request, Response};

/// The authenticated identity of a remote peer.
///
/// `peer_id` is the transport identity proven by the QUIC/TLS handshake, and
/// `device_key` is the PeerHarness device key it binds to (they are two encodings of the
/// same Ed25519 public key). Possessing a `PeerInfo` proves nothing about circle
/// membership; the application authorizes with its own state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PeerInfo {
    /// The libp2p peer id.
    pub peer_id: PeerId,
    /// The PeerHarness device key of the peer.
    pub device_key: DeviceKey,
    /// The remote address of the connection the request (or connection) arrived on,
    /// when known. For inbound connections this is the observed source address, not a
    /// dialable listen address.
    pub remote_addr: Option<Multiaddr>,
}

/// Handles inbound requests that passed decoding and rate limiting.
///
/// Each call runs on its own Tokio task, so a slow handler never blocks the swarm or
/// other peers. The returned future is abandoned after the configured request timeout
/// (the peer then sees a timeout). If the handler panics, the peer receives
/// `error{unavailable}`.
///
/// ph-network performs **no** authorization: it only guarantees that `peer` is the
/// authenticated sender. The handler must answer `Hello` to anyone, and must answer any
/// other request from a peer that has not proven membership with `error{unauthorized}`
/// (architecture section 7).
pub trait RequestHandler: Send + Sync + 'static {
    /// Produces the response for one request.
    fn handle(&self, peer: PeerInfo, request: Request) -> BoxFuture<'static, Response>;
}

/// Adapts an async closure into a [`RequestHandler`].
///
/// ```
/// # use ph_network::{handler_fn, PeerInfo};
/// # use ph_protocol::wire::{Request, Response};
/// let h = handler_fn(|_peer: PeerInfo, req: Request| async move {
///     match req {
///         Request::Hello { .. } => Response::hello(),
///         _ => Response::error(ph_protocol::wire::ErrorCode::Unauthorized),
///     }
/// });
/// # let _ = h;
/// ```
pub fn handler_fn<F, Fut>(f: F) -> Arc<dyn RequestHandler>
where
    F: Fn(PeerInfo, Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    Arc::new(FnHandler(f))
}

struct FnHandler<F>(F);

impl<F, Fut> RequestHandler for FnHandler<F>
where
    F: Fn(PeerInfo, Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    fn handle(&self, peer: PeerInfo, request: Request) -> BoxFuture<'static, Response> {
        (self.0)(peer, request).boxed()
    }
}

/// A minimal handler for nodes with no circle state: answers `Hello` with
/// [`Response::hello`] and every other request with `error{unauthorized}`.
#[derive(Clone, Copy, Debug, Default)]
pub struct HelloOnlyHandler;

impl RequestHandler for HelloOnlyHandler {
    fn handle(&self, _peer: PeerInfo, request: Request) -> BoxFuture<'static, Response> {
        let resp = match request {
            Request::Hello { .. } => Response::hello(),
            _ => Response::error(ErrorCode::Unauthorized),
        };
        futures::future::ready(resp).boxed()
    }
}
