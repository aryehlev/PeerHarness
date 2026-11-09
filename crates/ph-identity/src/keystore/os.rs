//! OS credential store backend (`os`), via the `keyring` crate.

use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use keyring::{Entry, Error as KeyringError};
use zeroize::Zeroizing;

use super::fsutil;
use super::{validate_label, KeyStore, KeystoreBackend};
use crate::error::{IdentityError, Result};

/// Keychain service name used for every entry.
pub const OS_SERVICE: &str = "peerharness";
const ACCOUNT_CONTEXT: &str = "peerharness-keyring-account-v0";
const BACKEND: &str = "os";

/// The OS credential store: Keychain Services (macOS), Credential Manager (Windows), or
/// the Secret Service (other unix).
///
/// Entries use service [`OS_SERVICE`] and account `"<ns>/<label>"`, where `<ns>` is the
/// first 16 hex characters of `SHA-256("peerharness-keyring-account-v0\0" ||
/// canonical_home_path)`. Two different `PEERHARNESS_HOME` directories therefore never
/// share keys. The secret is stored as base64url (no padding) of the 32-byte seed.
///
/// Errors from the platform store are mapped to static messages; keychain error payloads
/// are never shown, because some of them echo stored bytes. If no OS store is available
/// you get [`IdentityError::KeystoreUnavailable`], which suggests `--keystore file`.
#[derive(Debug, Clone)]
pub struct OsKeyStore {
    namespace: String,
    home: PathBuf,
}

impl OsKeyStore {
    /// Creates the store for node home `home`. The home directory is created (mode 0700)
    /// if missing and then canonicalized; the canonical path determines the namespace.
    pub fn new(home: &Path) -> Result<Self> {
        if !fsutil::path_exists(home)? {
            fsutil::ensure_private_dir(home)?;
        }
        let canonical =
            fs::canonicalize(home).map_err(|e| IdentityError::io("canonicalize", home, &e))?;
        let ns = ph_core::encoding::domain_hash(
            ACCOUNT_CONTEXT,
            canonical.as_os_str().as_encoded_bytes(),
        );
        Ok(Self {
            namespace: hex::encode(&ns[..8]),
            home: canonical,
        })
    }

    /// The 16-hex-character namespace derived from the canonical home path.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Checks that the platform credential store could be initialized, without reading
    /// or writing any entry. Returns [`IdentityError::KeystoreUnavailable`] (whose
    /// message suggests `--keystore file`) otherwise. Call it in `init` before
    /// generating keys, and in `doctor`. It does not prove that access will be granted
    /// (a locked keychain or a denied prompt still fails later with the same error).
    pub fn check_available() -> Result<()> {
        match Entry::store_status() {
            Ok(()) => Ok(()),
            Err(e) => Err(map_err("", e)),
        }
    }

    /// The canonical home path the namespace was derived from.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The keychain account for `label`: `"<namespace>/<label>"`.
    pub fn account(&self, label: &str) -> Result<String> {
        validate_label(label)?;
        Ok(format!("{}/{label}", self.namespace))
    }

    fn entry(&self, label: &str) -> Result<Entry> {
        let account = self.account(label)?;
        Entry::new(OS_SERVICE, &account).map_err(|e| map_err(label, &e))
    }
}

fn map_err(label: &str, e: &KeyringError) -> IdentityError {
    match e {
        KeyringError::NoEntry => IdentityError::NotFound {
            label: label.to_owned(),
            backend: BACKEND,
        },
        KeyringError::NoDefaultStore => IdentityError::KeystoreUnavailable {
            reason: "no OS credential store could be initialized",
        },
        KeyringError::NoStorageAccess(_) => IdentityError::KeystoreUnavailable {
            reason: "access to the OS credential store was denied or it is locked",
        },
        KeyringError::PlatformFailure(_) => IdentityError::KeystoreUnavailable {
            reason: "the OS credential store reported a failure",
        },
        KeyringError::NotSupportedByStore(_) => IdentityError::KeystoreUnavailable {
            reason: "operation not supported by the OS credential store",
        },
        KeyringError::Invalid(_, _) | KeyringError::TooLong(_, _) => {
            IdentityError::KeystoreUnavailable {
                reason: "the OS credential store rejected the entry",
            }
        }
        KeyringError::BadEncoding(_) | KeyringError::BadDataFormat(_, _) => {
            IdentityError::CorruptSecret {
                label: label.to_owned(),
                reason: "keychain entry is not valid text",
            }
        }
        KeyringError::Ambiguous(_) => IdentityError::CorruptSecret {
            label: label.to_owned(),
            reason: "several keychain entries match",
        },
        _ => IdentityError::KeystoreUnavailable {
            reason: "unexpected OS credential store error",
        },
    }
}

impl KeyStore for OsKeyStore {
    fn store_secret(&self, label: &str, secret: &Zeroizing<[u8; 32]>) -> Result<()> {
        if self.exists(label)? {
            return Err(IdentityError::AlreadyExists {
                label: label.to_owned(),
                backend: BACKEND,
            });
        }
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(&secret[..]));
        self.entry(label)?
            .set_password(&encoded)
            .map_err(|e| map_err(label, &e))?;
        tracing::debug!(backend = BACKEND, label, "stored key");
        Ok(())
    }

    fn load_secret(&self, label: &str) -> Result<Zeroizing<[u8; 32]>> {
        let encoded = Zeroizing::new(
            self.entry(label)?
                .get_password()
                .map_err(|e| map_err(label, &e))?,
        );
        let corrupt = |reason| IdentityError::CorruptSecret {
            label: label.to_owned(),
            reason,
        };
        let raw = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded.as_bytes())
                .map_err(|_| corrupt("keychain entry is not base64url"))?,
        );
        if raw.len() != 32 {
            return Err(corrupt("keychain entry has the wrong length"));
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&raw);
        tracing::debug!(backend = BACKEND, label, "loaded key");
        Ok(seed)
    }

    fn delete(&self, label: &str) -> Result<bool> {
        match self.entry(label)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(KeyringError::NoEntry) => Ok(false),
            Err(e) => Err(map_err(label, &e)),
        }
    }

    fn exists(&self, label: &str) -> Result<bool> {
        match self.entry(label)?.get_password() {
            Ok(p) => {
                drop(Zeroizing::new(p));
                Ok(true)
            }
            Err(KeyringError::NoEntry) => Ok(false),
            Err(KeyringError::BadEncoding(mut b)) => {
                zeroize::Zeroize::zeroize(&mut b);
                Ok(true)
            }
            Err(e) => Err(map_err(label, &e)),
        }
    }

    fn backend(&self) -> KeystoreBackend {
        KeystoreBackend::Os
    }

    fn locator(&self, label: &str) -> Result<String> {
        Ok(format!("{OS_SERVICE}/{}", self.account(label)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_differ_per_home() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let sa = OsKeyStore::new(a.path()).unwrap();
        let sb = OsKeyStore::new(b.path()).unwrap();
        assert_eq!(sa.namespace().len(), 16);
        assert_ne!(sa.namespace(), sb.namespace());
        assert_ne!(sa.account("device").unwrap(), sb.account("device").unwrap());
        // Same home through a different spelling gives the same namespace.
        let again = OsKeyStore::new(&a.path().join(".")).unwrap();
        assert_eq!(again.namespace(), sa.namespace());
        assert!(sa.account("../x").is_err());
        assert_eq!(
            sa.locator("device").unwrap(),
            format!("peerharness/{}/device", sa.namespace())
        );
    }

    #[test]
    fn missing_home_is_created() {
        let a = tempfile::tempdir().unwrap();
        let home = a.path().join("nested").join("home");
        let s = OsKeyStore::new(&home).unwrap();
        assert!(home.is_dir());
        assert_eq!(s.namespace().len(), 16);
    }

    #[test]
    fn unavailable_error_is_actionable_and_static() {
        let e = map_err(
            "device",
            &KeyringError::PlatformFailure("secret payload 0123".into()),
        );
        let msg = e.to_string();
        assert!(matches!(e, IdentityError::KeystoreUnavailable { .. }));
        assert!(msg.contains("--keystore file"), "{msg}");
        assert!(!msg.contains("secret payload"), "{msg}");
        let e = map_err("device", &KeyringError::NoDefaultStore);
        assert!(e.to_string().contains("--keystore file"));
        let e = map_err("device", &KeyringError::BadEncoding(vec![1, 2, 3]));
        assert!(matches!(e, IdentityError::CorruptSecret { .. }));
        assert!(matches!(
            map_err("device", &KeyringError::NoEntry),
            IdentityError::NotFound { .. }
        ));
    }

    /// Touches the real OS keychain (may prompt, and writes a temporary entry).
    #[test]
    #[ignore = "uses the real OS keychain"]
    fn real_keychain_round_trip() {
        let a = tempfile::tempdir().unwrap();
        let s = OsKeyStore::new(a.path()).unwrap();
        let label = "test-roundtrip";
        let _ = s.delete(label);
        assert!(!s.exists(label).unwrap());
        let secret = Zeroizing::new([7u8; 32]);
        s.store_secret(label, &secret).unwrap();
        assert!(s.exists(label).unwrap());
        assert!(matches!(
            s.store_secret(label, &secret),
            Err(IdentityError::AlreadyExists { .. })
        ));
        assert_eq!(*s.load_secret(label).unwrap(), *secret);
        assert!(s.delete(label).unwrap());
        assert!(!s.delete(label).unwrap());
        assert!(matches!(
            s.load_secret(label),
            Err(IdentityError::NotFound { .. })
        ));
    }
}
