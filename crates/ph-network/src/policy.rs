//! Connection gating: only Ed25519 peer identities, bounded connection counts.

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::fmt;
use std::task::{Context, Poll};

use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::swarm::{
    dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};

use crate::identity::device_key_from_peer_id;

/// Why a connection was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denied {
    /// The peer id is not an identity-multihash Ed25519 key valid as a device key.
    NotEd25519,
    /// Too many established connections in total.
    TotalLimit,
    /// Too many established connections to this peer.
    PeerLimit,
    /// Too many inbound connections still handshaking.
    PendingLimit,
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Denied::NotEd25519 => "unsupported peer identity",
            Denied::TotalLimit => "connection limit reached",
            Denied::PeerLimit => "per-peer connection limit reached",
            Denied::PendingLimit => "pending inbound connection limit reached",
        })
    }
}

impl std::error::Error for Denied {}

/// A `NetworkBehaviour` that only gates connections; it has no protocol of its own.
///
/// It refuses established connections whose peer id is not a valid Ed25519 device key
/// or that exceed the total / per-peer limits, and refuses new incoming connections
/// while too many are still in the handshake.
#[derive(Debug)]
pub struct PeerPolicy {
    max_total: usize,
    max_per_peer: usize,
    max_pending_inbound: usize,
    total: usize,
    per_peer: HashMap<PeerId, usize>,
    pending_inbound: HashSet<ConnectionId>,
}

impl PeerPolicy {
    /// A policy with the given limits (all must be > 0).
    pub fn new(max_total: usize, max_per_peer: usize, max_pending_inbound: usize) -> Self {
        Self {
            max_total,
            max_per_peer,
            max_pending_inbound,
            total: 0,
            per_peer: HashMap::new(),
            pending_inbound: HashSet::new(),
        }
    }

    /// Number of inbound connections currently in the handshake.
    pub fn pending_inbound(&self) -> usize {
        self.pending_inbound.len()
    }

    /// Decides whether a newly established connection from `peer` may proceed.
    pub fn check(&self, peer: &PeerId) -> Result<(), Denied> {
        if device_key_from_peer_id(peer).is_none() {
            return Err(Denied::NotEd25519);
        }
        if self.total >= self.max_total {
            return Err(Denied::TotalLimit);
        }
        if self.per_peer.get(peer).copied().unwrap_or(0) >= self.max_per_peer {
            return Err(Denied::PeerLimit);
        }
        Ok(())
    }

    fn deny(&self, peer: &PeerId) -> Result<THandler<Self>, ConnectionDenied> {
        match self.check(peer) {
            Ok(()) => Ok(dummy::ConnectionHandler),
            Err(d) => {
                // Limit refusals can be triggered at will by remote peers, so they are
                // logged at debug level to keep a flood from flooding the log.
                if d == Denied::NotEd25519 {
                    tracing::warn!(peer = %peer, reason = %d, "connection refused");
                } else {
                    tracing::debug!(peer = %peer, reason = %d, "connection refused");
                }
                Err(ConnectionDenied::new(d))
            }
        }
    }
}

impl NetworkBehaviour for PeerPolicy {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        if self.pending_inbound.len() >= self.max_pending_inbound {
            tracing::debug!(reason = %Denied::PendingLimit, "incoming connection refused");
            return Err(ConnectionDenied::new(Denied::PendingLimit));
        }
        self.pending_inbound.insert(connection_id);
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.pending_inbound.remove(&connection_id);
        self.deny(&peer)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.deny(&peer)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(e) => {
                self.total = self.total.saturating_add(1);
                *self.per_peer.entry(e.peer_id).or_insert(0) += 1;
            }
            FromSwarm::ListenFailure(e) => {
                self.pending_inbound.remove(&e.connection_id);
            }
            FromSwarm::ConnectionClosed(e) => {
                self.total = self.total.saturating_sub(1);
                if let Some(n) = self.per_peer.get_mut(&e.peer_id) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        self.per_peer.remove(&e.peer_id);
                    }
                }
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::multihash::Multihash;

    fn ed_peer(b: u8) -> PeerId {
        let kp = crate::identity::keypair_from_seed(&zeroize::Zeroizing::new([b; 32])).unwrap();
        kp.public().to_peer_id()
    }

    #[test]
    fn denies_non_ed25519_peer() {
        let mh = Multihash::<64>::wrap(0x12, &[1u8; 32]).unwrap();
        let pid = PeerId::from_multihash(mh).unwrap();
        let mut p = PeerPolicy::new(10, 2, 4);
        assert_eq!(p.check(&pid), Err(Denied::NotEd25519));
        let addr: Multiaddr = "/ip4/127.0.0.1/udp/1/quic-v1".parse().unwrap();
        assert!(p
            .handle_established_inbound_connection(
                ConnectionId::new_unchecked(1),
                pid,
                &addr,
                &addr
            )
            .is_err());
        assert!(p
            .handle_established_inbound_connection(
                ConnectionId::new_unchecked(2),
                ed_peer(1),
                &addr,
                &addr
            )
            .is_ok());
    }

    #[test]
    fn counts_limits() {
        let mut p = PeerPolicy::new(3, 2, 4);
        let a = ed_peer(1);
        let b = ed_peer(2);
        p.total = 2;
        p.per_peer.insert(a, 2);
        assert_eq!(p.check(&a), Err(Denied::PeerLimit));
        assert_eq!(p.check(&b), Ok(()));
        p.total = 3;
        assert_eq!(p.check(&b), Err(Denied::TotalLimit));
    }

    #[test]
    fn bounds_pending_inbound_handshakes() {
        let mut p = PeerPolicy::new(10, 2, 2);
        let addr: Multiaddr = "/ip4/127.0.0.1/udp/1/quic-v1".parse().unwrap();
        let c1 = ConnectionId::new_unchecked(1);
        let c2 = ConnectionId::new_unchecked(2);
        let c3 = ConnectionId::new_unchecked(3);
        assert!(p
            .handle_pending_inbound_connection(c1, &addr, &addr)
            .is_ok());
        assert!(p
            .handle_pending_inbound_connection(c2, &addr, &addr)
            .is_ok());
        assert!(p
            .handle_pending_inbound_connection(c3, &addr, &addr)
            .is_err());
        assert_eq!(p.pending_inbound(), 2);
        // Completing a handshake (accepted or not) frees a slot.
        assert!(p
            .handle_established_inbound_connection(c1, ed_peer(1), &addr, &addr)
            .is_ok());
        assert_eq!(p.pending_inbound(), 1);
        assert!(p
            .handle_pending_inbound_connection(c3, &addr, &addr)
            .is_ok());
        let bad = PeerId::from_multihash(Multihash::<64>::wrap(0x12, &[1u8; 32]).unwrap()).unwrap();
        assert!(p
            .handle_established_inbound_connection(c3, bad, &addr, &addr)
            .is_err());
        assert_eq!(p.pending_inbound(), 1);
    }
}
