//! PeerHarness peer transport (architecture section 7, spec 6.1, 6.4, 6.5).
//!
//! * **Transport**: libp2p over QUIC only (`/ip4/…/udp/…/quic-v1`), with the libp2p
//!   identity derived from the device key's Ed25519 seed, so the authenticated
//!   `PeerId` binds to the PeerHarness [`DeviceKey`](ph_core::DeviceKey). Connections
//!   from peer ids that are not Ed25519 identity multihashes are refused.
//! * **Protocol**: libp2p request/response on [`ph_protocol::wire::PROTOCOL_ID`] with
//!   a custom [`codec::PhCodec`]: 4-byte big-endian length prefix plus a JSON body of at
//!   most 512 KiB, strictly decoded with [`ph_protocol::wire::Request::from_bytes`] /
//!   [`ph_protocol::wire::Response::from_bytes`]. Malformed inbound requests are answered
//!   `error{bad_request}` / `error{too_large}` without reaching the application.
//! * **Limits**: per-peer token buckets (request count, inbound bytes) and a concurrency
//!   cap, checked before the [`RequestHandler`] runs; over the limit the peer gets
//!   `error{rate_limited}`. Connection counts (total, per peer, still handshaking) are
//!   bounded, and a shared inbound buffer budget caps the memory that request bodies
//!   in flight can occupy across all peers (over it: `error{unavailable}`).
//! * **No dialing by itself**: no DHT or gossip unless the internet mode is on. Peers
//!   are reached only by explicit [`NetworkHandle::dial`]. This crate knows wire types
//!   but nothing about circles; the application's handler performs all authorization.
//! * **Discovery is opt-in and only reports**: with [`NetworkConfig::lan_discovery`]
//!   (default off) the node announces its peer id and listen addresses over mDNS on the
//!   local network and reports the libp2p nodes it hears ([`NetEvent::PeerDiscovered`],
//!   [`NetworkHandle::discovered`]). It never dials them. See [`discovery`] for what
//!   goes on the wire and what is guaranteed.
//! * **The internet mode is opt-in, finds and never connects**: with
//!   [`NetworkConfig::internet`] (default off) the node joins the public libp2p network
//!   as a client. [`NetworkHandle::find_peer`] then turns a peer id into addresses,
//!   the node learns whether it can be dialed ([`NetworkHandle::internet_status`]) and
//!   keeps itself reachable through relays while it cannot, and a relayed connection is
//!   upgraded to a direct one when the networks allow it. The node contacts servers of
//!   that network on its own; a peer of the application is still dialed only by
//!   [`NetworkHandle::dial`], and whoever answers is still a stranger to the handler.
//!   See [`internet`] for who learns what, the bounds, and the limits of public relays.
//!
//! # Usage
//!
//! ```no_run
//! # async fn demo(seed: zeroize::Zeroizing<[u8; 32]>) -> Result<(), ph_network::NetError> {
//! use std::sync::Arc;
//! use ph_network::{start, NetworkConfig, HelloOnlyHandler};
//! use ph_protocol::wire::Request;
//!
//! let config = NetworkConfig::listening_on(["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()]);
//! let (net, join) = start(seed, config, Arc::new(HelloOnlyHandler))?;
//! let addrs = net.listen_addrs().await?;
//! let peer = net.dial("/ip4/127.0.0.1/udp/4001/quic-v1".parse().unwrap()).await?;
//! let resp = net.request(peer, &Request::hello()).await?;
//! net.shutdown().await;
//! let _ = join.await;
//! # let _ = (addrs, resp); Ok(()) }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod codec;
mod config;
pub mod discovery;
mod error;
mod handler;
mod identity;
pub mod internet;
pub mod limiter;
mod network;
pub mod policy;

pub use config::{InternetConfig, NetworkConfig, RateLimits};
pub use error::NetError;
pub use handler::{handler_fn, HelloOnlyHandler, PeerInfo, RequestHandler};
pub use identity::{
    device_key_from_peer_id, device_key_of_keypair, keypair_from_seed, peer_id_from_device_key,
    peer_id_of_addr, with_p2p, without_p2p,
};
pub use internet::{is_relayed, InternetStatus, Reachability};
pub use network::{start, NetEvent, NetworkHandle};

/// The libp2p crate this network is built on (for `Multiaddr`, `PeerId`, `multiaddr`).
pub use libp2p;
pub use libp2p::{Multiaddr, PeerId};
