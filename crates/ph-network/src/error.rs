//! Network errors.

/// Errors returned by the network API.
///
/// Every variant carries no payload and its `Display` text is generic: it never includes
/// addresses, peer-supplied bytes, request contents or key material, so it is safe to
/// show to a user or write to a log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum NetError {
    /// [`crate::start`] was called outside a Tokio runtime.
    #[error("no tokio runtime is running")]
    NoRuntime,
    /// The [`crate::NetworkConfig`] is invalid (for example a zero rate limit).
    #[error("invalid network configuration")]
    InvalidConfig,
    /// The 32-byte identity seed could not be turned into a libp2p identity.
    #[error("invalid identity seed")]
    Identity,
    /// Listening on a configured address failed (bind error or an address that is not
    /// `/ip4|ip6/…/udp/…/quic-v1`).
    #[error("failed to listen on a configured address")]
    Listen,
    /// [`crate::NetworkConfig::lan_discovery`] is set and LAN discovery could not be
    /// started (no interface watcher, or no thread for it). Nothing was announced.
    #[error("failed to start LAN discovery")]
    Discovery,
    /// Dialing failed: unreachable or dead address, handshake failure, wrong peer id,
    /// a peer identity that is not Ed25519, a connection limit, or the dial timeout.
    #[error("dial failed")]
    Dial,
    /// The target peer has no established connection. ph-network never dials
    /// implicitly; call [`crate::NetworkHandle::dial`] first.
    #[error("peer is not connected")]
    NotConnected,
    /// No response arrived within the request timeout.
    #[error("request timed out")]
    Timeout,
    /// The connection closed before a response was received.
    #[error("connection closed before a response was received")]
    ConnectionClosed,
    /// The remote does not speak `/peerharness/req/0.1.0`.
    #[error("peer does not support the protocol")]
    UnsupportedProtocol,
    /// The remote sent a malformed, oversized or truncated response frame, or the
    /// stream failed mid-exchange.
    #[error("malformed or oversized frame")]
    Codec,
    /// The local request could not be encoded (it violates a wire bound or exceeds
    /// 512 KiB). Nothing was sent.
    #[error("request could not be encoded")]
    Encode,
    /// [`crate::NetworkConfig::internet`] is set and the internet mode could not be
    /// started (the relay transport could not be set up). Nothing was sent.
    #[error("failed to start the internet mode")]
    Internet,
    /// The call needs the internet mode ([`crate::NetworkConfig::internet`]), which is
    /// off.
    #[error("the internet mode is off")]
    InternetOff,
    /// Too many lookups are in flight ([`crate::internet::MAX_CONCURRENT_FINDS`]). Try
    /// again when one has finished.
    #[error("too many lookups in flight")]
    Busy,
    /// The network event loop has stopped (after [`crate::NetworkHandle::shutdown`]
    /// or because it ended).
    #[error("network is shut down")]
    Shutdown,
}
