//! Keystores for 32-byte Ed25519 seeds (ADR-004).
//!
//! Three backends implement the [`KeyStore`] trait:
//!
//! * [`OsKeyStore`] (`os`): the OS credential store through the `keyring` crate
//!   (Keychain Services on macOS, Credential Manager on Windows, Secret Service on other
//!   unix systems). Service `"peerharness"`, account
//!   `"<16 hex of a domain hash of the canonical home path>/<label>"`, so separate
//!   `PEERHARNESS_HOME` directories never collide.
//! * [`FileKeyStore`] (`file`): Argon2id + XChaCha20-Poly1305 encrypted JSON files at
//!   `<home>/keys/<label>.key` (dir 0700, file 0600).
//! * [`InsecureDevKeyStore`] (`insecure-dev`): plaintext 0600 files at
//!   `<home>/keys/<label>.insecure-key`, constructible only with an explicit
//!   [`InsecureAcknowledged`] marker; it warns on every load.
//!
//! Every stored secret is a 32-byte Ed25519 seed (`SigningKey::from_bytes` input). The
//! file backends also record the matching public key so it can be shown without
//! unlocking. Secrets are never overwritten silently: [`KeyStore::store_secret`] fails
//! with [`IdentityError::AlreadyExists`] when the label is taken.

mod file;
pub(crate) mod fsutil;
mod insecure;
mod os;
mod passphrase;

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{IdentityError, Result};

pub use file::{FileKeyStore, KdfParams, KEYFILE_SCHEMA};
pub use insecure::{InsecureAcknowledged, InsecureDevKeyStore, INSECURE_KEYFILE_SCHEMA};
pub use os::{OsKeyStore, OS_SERVICE};
pub use passphrase::{PassphraseSource, PASSPHRASE_ENV};

/// Maximum keystore label length in bytes.
pub const MAX_LABEL_LEN: usize = 128;

/// Name of the directory under the home that holds key files.
pub const KEYS_DIR: &str = "keys";

/// Which keystore backend to use. Serde/`FromStr`/`Display` use `"os"`, `"file"` and
/// `"insecure-dev"` (the `--keystore` flag values and the `identity_metadata` column).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeystoreBackend {
    /// The OS credential store.
    #[serde(rename = "os")]
    Os,
    /// Passphrase-encrypted key files.
    #[serde(rename = "file")]
    File,
    /// Plaintext key files (development only).
    #[serde(rename = "insecure-dev")]
    InsecureDev,
}

impl KeystoreBackend {
    /// All backends.
    pub const ALL: [KeystoreBackend; 3] = [
        KeystoreBackend::Os,
        KeystoreBackend::File,
        KeystoreBackend::InsecureDev,
    ];

    /// The stable string form.
    pub const fn as_str(self) -> &'static str {
        match self {
            KeystoreBackend::Os => "os",
            KeystoreBackend::File => "file",
            KeystoreBackend::InsecureDev => "insecure-dev",
        }
    }

    /// The platform default (ADR-004): `os` on macOS and Windows, `file` elsewhere
    /// (Linux machines often lack a Secret Service, especially headless and CI).
    pub const fn platform_default() -> Self {
        if cfg!(any(target_os = "macos", target_os = "windows")) {
            KeystoreBackend::Os
        } else {
            KeystoreBackend::File
        }
    }
}

impl fmt::Display for KeystoreBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for KeystoreBackend {
    type Err = ph_core::ParseError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "os" => Ok(KeystoreBackend::Os),
            "file" => Ok(KeystoreBackend::File),
            "insecure-dev" => Ok(KeystoreBackend::InsecureDev),
            _ => Err(ph_core::ParseError::new(
                "keystore backend",
                "expected os, file or insecure-dev",
            )),
        }
    }
}

/// Storage for 32-byte Ed25519 seeds under short labels.
///
/// Labels must match `[a-z0-9][a-z0-9-]{0,127}` (see [`validate_label`]); this crate
/// uses `"device"` ([`crate::DeviceIdentity::LABEL`]) and `"circle-root-<64 hex>"`
/// ([`crate::CircleAuthority::keystore_label`]).
///
/// Implementations are `Send + Sync`; methods take `&self` (a file keystore caches the
/// passphrase internally after the first successful use).
pub trait KeyStore: Send + Sync {
    /// Stores `secret` under `label`. Fails with [`IdentityError::AlreadyExists`] when
    /// the label is already in use (never overwrites). The file backends enforce this
    /// atomically (a concurrent creator loses with `AlreadyExists`); the OS backend
    /// checks first and then writes, because the keychain API has no create-only call.
    fn store_secret(&self, label: &str, secret: &Zeroizing<[u8; 32]>) -> Result<()>;

    /// Loads the secret stored under `label`, or [`IdentityError::NotFound`].
    fn load_secret(&self, label: &str) -> Result<Zeroizing<[u8; 32]>>;

    /// Deletes the secret under `label`. Returns `Ok(false)` if nothing was stored.
    fn delete(&self, label: &str) -> Result<bool>;

    /// Whether a secret is stored under `label`. Never needs the passphrase.
    fn exists(&self, label: &str) -> Result<bool>;

    /// Which backend this is.
    fn backend(&self) -> KeystoreBackend;

    /// A human-readable, non-secret locator for `label` (a file path, or
    /// `service/account` for the OS store), suitable for the `keystore_ref` column and
    /// for diagnostics.
    fn locator(&self, label: &str) -> Result<String>;
}

impl<K: KeyStore + ?Sized> KeyStore for Box<K> {
    fn store_secret(&self, label: &str, secret: &Zeroizing<[u8; 32]>) -> Result<()> {
        (**self).store_secret(label, secret)
    }
    fn load_secret(&self, label: &str) -> Result<Zeroizing<[u8; 32]>> {
        (**self).load_secret(label)
    }
    fn delete(&self, label: &str) -> Result<bool> {
        (**self).delete(label)
    }
    fn exists(&self, label: &str) -> Result<bool> {
        (**self).exists(label)
    }
    fn backend(&self) -> KeystoreBackend {
        (**self).backend()
    }
    fn locator(&self, label: &str) -> Result<String> {
        (**self).locator(label)
    }
}

impl<K: KeyStore + ?Sized> KeyStore for std::sync::Arc<K> {
    fn store_secret(&self, label: &str, secret: &Zeroizing<[u8; 32]>) -> Result<()> {
        (**self).store_secret(label, secret)
    }
    fn load_secret(&self, label: &str) -> Result<Zeroizing<[u8; 32]>> {
        (**self).load_secret(label)
    }
    fn delete(&self, label: &str) -> Result<bool> {
        (**self).delete(label)
    }
    fn exists(&self, label: &str) -> Result<bool> {
        (**self).exists(label)
    }
    fn backend(&self) -> KeystoreBackend {
        (**self).backend()
    }
    fn locator(&self, label: &str) -> Result<String> {
        (**self).locator(label)
    }
}

/// Checks that `label` matches `[a-z0-9][a-z0-9-]{0,127}`. Labels become file names and
/// keychain account suffixes, so this rules out traversal and separators.
pub fn validate_label(label: &str) -> Result<()> {
    let b = label.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= MAX_LABEL_LEN
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
    if ok {
        Ok(())
    } else {
        Err(IdentityError::InvalidLabel)
    }
}

/// How to open a keystore with [`open_keystore`].
#[derive(Debug)]
pub enum KeystoreConfig {
    /// The OS credential store.
    Os,
    /// Encrypted key files.
    File {
        /// Where the passphrase comes from.
        passphrase: PassphraseSource,
        /// Argon2id parameters for newly written files (loads use the file's own).
        kdf: KdfParams,
    },
    /// Plaintext key files; requires the explicit acknowledgement marker.
    InsecureDev(InsecureAcknowledged),
}

impl KeystoreConfig {
    /// The backend this config selects.
    pub const fn backend(&self) -> KeystoreBackend {
        match self {
            KeystoreConfig::Os => KeystoreBackend::Os,
            KeystoreConfig::File { .. } => KeystoreBackend::File,
            KeystoreConfig::InsecureDev(_) => KeystoreBackend::InsecureDev,
        }
    }

    /// A file config with the default (production) Argon2id parameters.
    pub fn file(passphrase: PassphraseSource) -> Self {
        KeystoreConfig::File {
            passphrase,
            kdf: KdfParams::default(),
        }
    }
}

/// Opens the keystore selected by `config` for the node home directory `home`.
///
/// The OS backend canonicalizes `home` (creating it with mode 0700 if missing) to derive
/// its account namespace. The file backends only touch `<home>/keys/` when a key is
/// written or read.
pub fn open_keystore(home: &Path, config: KeystoreConfig) -> Result<Box<dyn KeyStore>> {
    Ok(match config {
        KeystoreConfig::Os => Box::new(OsKeyStore::new(home)?),
        KeystoreConfig::File { passphrase, kdf } => {
            Box::new(FileKeyStore::new(home, passphrase).with_kdf_params(kdf))
        }
        KeystoreConfig::InsecureDev(ack) => Box::new(InsecureDevKeyStore::new(home, ack)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels() {
        for ok in ["device", "circle-root-00ff", "a", "0", &"a".repeat(128)] {
            assert!(validate_label(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "-x",
            "Device",
            "a/b",
            "..",
            "a.b",
            "a_b",
            "a b",
            &"a".repeat(129),
            "é",
        ] {
            assert!(validate_label(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn backend_strings() {
        for b in KeystoreBackend::ALL {
            assert_eq!(b.as_str().parse::<KeystoreBackend>().unwrap(), b);
            assert_eq!(
                serde_json::to_string(&b).unwrap(),
                format!("\"{}\"", b.as_str())
            );
            assert_eq!(
                serde_json::from_str::<KeystoreBackend>(&format!("\"{b}\"")).unwrap(),
                b
            );
        }
        assert!("OS".parse::<KeystoreBackend>().is_err());
        assert!(serde_json::from_str::<KeystoreBackend>("\"insecure_dev\"").is_err());
    }
}
