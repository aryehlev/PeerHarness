//! Binding between libp2p `PeerId`s and PeerHarness [`DeviceKey`]s.
//!
//! A PeerHarness node uses its Ed25519 device key as its libp2p identity (ADR-001), so
//! the `PeerId` authenticated by the QUIC/TLS handshake is the *identity multihash* of
//! the protobuf-encoded Ed25519 public key. That makes the mapping between the two
//! lossless and lets the application authorize by device key.

use libp2p::identity::{self, Keypair};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use ph_core::DeviceKey;
use zeroize::Zeroizing;

use crate::error::NetError;

/// Multihash code of the identity "hash" (the digest *is* the input).
const MULTIHASH_IDENTITY_CODE: u64 = 0x00;

/// Builds the libp2p keypair from a 32-byte Ed25519 secret seed.
///
/// The seed is the same secret that `ph-identity` uses for the device signing key, so
/// the returned keypair's public key equals the device key. The temporary copy handed to
/// libp2p is zeroized; the caller's `Zeroizing` buffer is wiped when dropped.
pub fn keypair_from_seed(seed: &Zeroizing<[u8; 32]>) -> Result<Keypair, NetError> {
    let mut copy = Zeroizing::new(**seed);
    Keypair::ed25519_from_bytes(&mut copy[..]).map_err(|_| NetError::Identity)
}

/// The device key of a keypair, if it is an Ed25519 keypair whose public key is a valid
/// PeerHarness device key.
pub fn device_key_of_keypair(keypair: &Keypair) -> Option<DeviceKey> {
    let ed = keypair.public().try_into_ed25519().ok()?;
    DeviceKey::from_bytes(ed.to_bytes()).ok()
}

/// Extracts the PeerHarness device key bound to a `PeerId`.
///
/// Returns `Some` only for an **identity-multihash** `PeerId` whose digest is the
/// canonical protobuf encoding of an **Ed25519** public key that is also a valid
/// [`DeviceKey`] (canonical point encoding, not small-order). Hashed (SHA-256) peer ids,
/// RSA/secp256k1/ECDSA keys, non-canonical protobuf encodings and weak keys all return
/// `None`. Connections from such peers are refused by the swarm.
pub fn device_key_from_peer_id(peer_id: &PeerId) -> Option<DeviceKey> {
    let mh = peer_id.as_ref();
    if mh.code() != MULTIHASH_IDENTITY_CODE {
        return None;
    }
    let public = identity::PublicKey::try_decode_protobuf(mh.digest()).ok()?;
    // Reject alternative encodings of the same key: the peer id must be exactly the one
    // libp2p derives from this key.
    if public.to_peer_id() != *peer_id {
        return None;
    }
    let ed = public.try_into_ed25519().ok()?;
    DeviceKey::from_bytes(ed.to_bytes()).ok()
}

/// The libp2p `PeerId` of a device key (the inverse of [`device_key_from_peer_id`]).
pub fn peer_id_from_device_key(key: &DeviceKey) -> PeerId {
    // A `DeviceKey` is always a valid, canonical Ed25519 point (checked at construction),
    // which is all `try_from_bytes` requires, so the error branch cannot be taken.
    let ed = identity::ed25519::PublicKey::try_from_bytes(key.as_bytes())
        .expect("a DeviceKey is a valid ed25519 point");
    identity::PublicKey::from(ed).to_peer_id()
}

/// Returns `addr` with a trailing `/p2p/<peer_id>` component.
///
/// Any existing trailing `/p2p/…` component is replaced. Use this to build dialable
/// addresses for invites (`issuer_addrs`), so that [`crate::NetworkHandle::dial`]
/// verifies the remote's identity during the handshake.
pub fn with_p2p(addr: &Multiaddr, peer_id: PeerId) -> Multiaddr {
    let mut out = without_p2p(addr);
    out.push(Protocol::P2p(peer_id));
    out
}

/// Returns `addr` without a trailing `/p2p/<peer_id>` component.
pub fn without_p2p(addr: &Multiaddr) -> Multiaddr {
    let mut out = addr.clone();
    if matches!(out.iter().last(), Some(Protocol::P2p(_))) {
        out.pop();
    }
    out
}

/// The peer id in a trailing `/p2p/<peer_id>` component of `addr`, if any.
pub fn peer_id_of_addr(addr: &Multiaddr) -> Option<PeerId> {
    match addr.iter().last() {
        Some(Protocol::P2p(p)) => Some(p),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::multihash::Multihash;

    fn seed(b: u8) -> Zeroizing<[u8; 32]> {
        Zeroizing::new([b; 32])
    }

    #[test]
    fn seed_keypair_matches_dalek_device_key() {
        let s = seed(7);
        let kp = keypair_from_seed(&s).unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&s);
        let expected = DeviceKey::from_signing_key(&sk);
        assert_eq!(device_key_of_keypair(&kp), Some(expected));
        // The caller's seed is left intact (only the internal copy is consumed).
        assert_eq!(*s, [7u8; 32]);
    }

    #[test]
    fn peer_id_round_trip() {
        for b in 1..20u8 {
            let kp = keypair_from_seed(&seed(b)).unwrap();
            let pid = kp.public().to_peer_id();
            let dk = device_key_from_peer_id(&pid).unwrap();
            assert_eq!(peer_id_from_device_key(&dk), pid);
            assert_eq!(device_key_of_keypair(&kp), Some(dk));
        }
    }

    #[test]
    fn rejects_hashed_peer_id() {
        let mh = Multihash::<64>::wrap(0x12, &[0u8; 32]).unwrap();
        let pid = PeerId::from_multihash(mh).unwrap();
        assert_eq!(device_key_from_peer_id(&pid), None);
    }

    #[test]
    fn rejects_garbage_identity_digest() {
        let mh = Multihash::<64>::wrap(0x00, &[0xffu8; 36]).unwrap();
        let pid = PeerId::from_multihash(mh).unwrap();
        assert_eq!(device_key_from_peer_id(&pid), None);
        let mh = Multihash::<64>::wrap(0x00, &[]).unwrap();
        let pid = PeerId::from_multihash(mh).unwrap();
        assert_eq!(device_key_from_peer_id(&pid), None);
    }

    #[test]
    fn rejects_non_ed25519_key_type() {
        // protobuf PublicKey { Type = Secp256k1 (2), Data = 33 bytes }
        let mut enc = vec![0x08, 0x02, 0x12, 33];
        enc.push(0x02);
        enc.extend_from_slice(&[0x11; 32]);
        let mh = Multihash::<64>::wrap(0x00, &enc).unwrap();
        let pid = PeerId::from_multihash(mh).unwrap();
        assert_eq!(device_key_from_peer_id(&pid), None);
    }

    #[test]
    fn rejects_small_order_ed25519_key() {
        // The identity point (small order) is a valid ed25519 encoding for libp2p but
        // not a valid DeviceKey.
        let mut point = [0u8; 32];
        point[0] = 1;
        let mut enc = vec![0x08, 0x01, 0x12, 0x20];
        enc.extend_from_slice(&point);
        let mh = Multihash::<64>::wrap(0x00, &enc).unwrap();
        let pid = PeerId::from_multihash(mh).unwrap();
        assert_eq!(device_key_from_peer_id(&pid), None);
    }

    #[test]
    fn rejects_non_canonical_protobuf() {
        let kp = keypair_from_seed(&seed(3)).unwrap();
        let mut enc = kp.public().encode_protobuf();
        // Append an unknown trailing field; decoders may accept it but the peer id differs.
        enc.extend_from_slice(&[0x18, 0x01]);
        if let Ok(mh) = Multihash::<64>::wrap(0x00, &enc) {
            if let Ok(pid) = PeerId::from_multihash(mh) {
                assert_eq!(device_key_from_peer_id(&pid), None);
            }
        }
    }

    #[test]
    fn p2p_helpers() {
        let kp = keypair_from_seed(&seed(9)).unwrap();
        let pid = kp.public().to_peer_id();
        let a: Multiaddr = "/ip4/127.0.0.1/udp/4001/quic-v1".parse().unwrap();
        let b = with_p2p(&a, pid);
        assert_eq!(peer_id_of_addr(&b), Some(pid));
        assert_eq!(without_p2p(&b), a);
        assert_eq!(with_p2p(&b, pid), b);
        assert_eq!(peer_id_of_addr(&a), None);
    }
}
