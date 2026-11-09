//! The device identity: one Ed25519 key per node home (spec 5.1, ADR-001).

use std::fmt;

use ed25519_dalek::SigningKey;
use ph_core::DeviceKey;
use rand::TryRng as _;
use zeroize::Zeroizing;

use crate::error::{IdentityError, Result};
use crate::keystore::KeyStore;

/// Draws 32 bytes from the operating system RNG.
pub(crate) fn random_seed() -> Result<Zeroizing<[u8; 32]>> {
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rngs::SysRng
        .try_fill_bytes(&mut seed[..])
        .map_err(|_| IdentityError::Randomness)?;
    Ok(seed)
}

/// This node's device key. It identifies the node in circles and is also its libp2p
/// identity (so the transport-authenticated `PeerId` binds to the [`DeviceKey`]).
///
/// The device key is distinct from any circle root key ([`crate::CircleAuthority`]).
/// Possessing it proves possession of a device, not the identity of a human.
///
/// `Debug` shows only the public key. The signing key is zeroized on drop.
pub struct DeviceIdentity {
    signing_key: SigningKey,
    public: DeviceKey,
}

impl DeviceIdentity {
    /// Keystore label under which the device seed is stored.
    pub const LABEL: &'static str = "device";

    /// Generates a fresh key from 32 bytes of the OS RNG. Does not store it.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_seed(&random_seed()?))
    }

    /// Rebuilds an identity from its 32-byte Ed25519 seed.
    pub fn from_seed(seed: &Zeroizing<[u8; 32]>) -> Self {
        Self::from_signing_key(SigningKey::from_bytes(seed))
    }

    /// Wraps an existing signing key (tests, fixtures).
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let public = DeviceKey::from_signing_key(&signing_key);
        Self {
            signing_key,
            public,
        }
    }

    /// Stores the seed under [`Self::LABEL`]. Fails with
    /// [`IdentityError::AlreadyExists`] if this keystore already holds a device key.
    pub fn save(&self, keystore: &dyn KeyStore) -> Result<()> {
        keystore.store_secret(Self::LABEL, &self.seed())?;
        tracing::info!(device = %self.public, backend = %keystore.backend(), "device key stored");
        Ok(())
    }

    /// Loads the device key from `keystore` ([`IdentityError::NotFound`] if absent).
    pub fn load(keystore: &dyn KeyStore) -> Result<Self> {
        let seed = keystore.load_secret(Self::LABEL)?;
        Ok(Self::from_seed(&seed))
    }

    /// Whether `keystore` holds a device key (no passphrase needed).
    pub fn exists(keystore: &dyn KeyStore) -> Result<bool> {
        keystore.exists(Self::LABEL)
    }

    /// Generates a new key and stores it (what `peerharness init` does).
    pub fn create(keystore: &dyn KeyStore) -> Result<Self> {
        let id = Self::generate()?;
        id.save(keystore)?;
        Ok(id)
    }

    /// The public device key.
    pub fn public(&self) -> DeviceKey {
        self.public
    }

    /// The Ed25519 signing key, for signing envelopes and acceptances.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// The 32-byte Ed25519 seed for building the libp2p identity
    /// (`libp2p::identity::Keypair::ed25519_from_bytes`), so the node's `PeerId`
    /// corresponds to [`Self::public`]. Handle with care; it is the private key.
    pub fn libp2p_seed(&self) -> Zeroizing<[u8; 32]> {
        self.seed()
    }

    /// The human fingerprint `xxxx-xxxx-xxxx-xxxx-xxxx` of the public key.
    pub fn fingerprint(&self) -> String {
        self.public.fingerprint()
    }

    fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing_key.to_bytes())
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_random_and_consistent() {
        let a = DeviceIdentity::generate().unwrap();
        let b = DeviceIdentity::generate().unwrap();
        assert_ne!(a.public(), b.public());
        assert_eq!(DeviceKey::from_signing_key(a.signing_key()), a.public());
        let again = DeviceIdentity::from_seed(&a.libp2p_seed());
        assert_eq!(again.public(), a.public());
        assert_eq!(a.fingerprint(), a.public().fingerprint());
        // The public key is a valid, canonical, non-small-order point.
        assert!(DeviceKey::from_bytes(*a.public().as_bytes()).is_ok());
    }

    #[test]
    fn debug_hides_secret() {
        let a = DeviceIdentity::from_signing_key(SigningKey::from_bytes(&[9; 32]));
        let d = format!("{a:?}");
        assert!(d.contains("public"));
        assert!(!d.contains("signing_key"));
    }
}
