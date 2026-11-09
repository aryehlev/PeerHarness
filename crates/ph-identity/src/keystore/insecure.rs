//! Plaintext development keystore (`insecure-dev` backend).

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use ph_core::DeviceKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::fsutil;
use super::{validate_label, KeyStore, KeystoreBackend, KEYS_DIR};
use crate::error::{IdentityError, Result};

/// The `schema` member of a plaintext development key file.
pub const INSECURE_KEYFILE_SCHEMA: &str = "peerharness.insecure-keyfile/0.1";
const MAX_FILE_BYTES: usize = 4096;
const BACKEND: &str = "insecure-dev";

/// Proof that the caller explicitly opted into plaintext key storage (the CLI's
/// `--insecure-dev-keystore` flag). It has no public fields, so it can only be made with
/// [`InsecureAcknowledged::i_understand_keys_are_stored_in_plaintext`].
#[derive(Debug)]
pub struct InsecureAcknowledged(());

impl InsecureAcknowledged {
    /// Acknowledges that private keys will be written to disk unencrypted.
    pub fn i_understand_keys_are_stored_in_plaintext() -> Self {
        InsecureAcknowledged(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InsecureKeyFile {
    schema: String,
    label: String,
    public_key: DeviceKey,
    seed: String,
}

/// Plaintext key files at `<home>/keys/<label>.insecure-key` (JSON, mode 0600). For
/// development and demos only: anyone who can read the file has the key. Every load
/// emits a `tracing::warn!`.
#[derive(Debug)]
pub struct InsecureDevKeyStore {
    dir: PathBuf,
}

impl InsecureDevKeyStore {
    /// Creates the store; requires the explicit acknowledgement marker.
    pub fn new(home: &Path, _ack: InsecureAcknowledged) -> Self {
        Self {
            dir: home.join(KEYS_DIR),
        }
    }

    /// Path of the key file for `label`.
    pub fn key_path(&self, label: &str) -> Result<PathBuf> {
        validate_label(label)?;
        Ok(self.dir.join(format!("{label}.insecure-key")))
    }
}

impl KeyStore for InsecureDevKeyStore {
    fn store_secret(&self, label: &str, secret: &Zeroizing<[u8; 32]>) -> Result<()> {
        let path = self.key_path(label)?;
        if fsutil::path_exists(&path)? {
            return Err(IdentityError::AlreadyExists {
                label: label.to_owned(),
                backend: BACKEND,
            });
        }
        let kf = InsecureKeyFile {
            schema: INSECURE_KEYFILE_SCHEMA.to_owned(),
            label: label.to_owned(),
            public_key: DeviceKey::from_signing_key(&SigningKey::from_bytes(secret)),
            seed: URL_SAFE_NO_PAD.encode(&secret[..]),
        };
        let json =
            Zeroizing::new(
                serde_json::to_vec(&kf).map_err(|_| IdentityError::CorruptKeyFile {
                    path: path.clone(),
                    reason: "cannot serialize key file",
                })?,
            );
        drop(Zeroizing::new(kf.seed));
        fsutil::ensure_private_dir(&self.dir)?;
        if !fsutil::write_new_private(&path, &json)? {
            return Err(IdentityError::AlreadyExists {
                label: label.to_owned(),
                backend: BACKEND,
            });
        }
        tracing::warn!(
            backend = BACKEND,
            label,
            "stored a private key in PLAINTEXT (insecure development keystore)"
        );
        Ok(())
    }

    fn load_secret(&self, label: &str) -> Result<Zeroizing<[u8; 32]>> {
        let path = self.key_path(label)?;
        if !fsutil::check_private_file(&path)? {
            return Err(IdentityError::NotFound {
                label: label.to_owned(),
                backend: BACKEND,
            });
        }
        tracing::warn!(
            backend = BACKEND,
            label,
            "loading a PLAINTEXT private key (insecure development keystore); do not use this for real circles"
        );
        let bytes = fsutil::read_private_bounded(&path, MAX_FILE_BYTES)?;
        let corrupt = |reason| IdentityError::CorruptKeyFile {
            path: path.clone(),
            reason,
        };
        let kf: InsecureKeyFile =
            serde_json::from_slice(&bytes).map_err(|_| corrupt("not a valid key file"))?;
        let seed_b64 = Zeroizing::new(kf.seed);
        if kf.schema != INSECURE_KEYFILE_SCHEMA {
            return Err(corrupt("unsupported schema"));
        }
        if kf.label != label {
            return Err(corrupt("label does not match the file name"));
        }
        let raw = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(seed_b64.as_bytes())
                .map_err(|_| corrupt("bad seed encoding"))?,
        );
        if raw.len() != 32 {
            return Err(corrupt("bad seed length"));
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&raw);
        if DeviceKey::from_signing_key(&SigningKey::from_bytes(&seed)) != kf.public_key {
            return Err(corrupt("seed does not match the recorded public key"));
        }
        Ok(seed)
    }

    fn delete(&self, label: &str) -> Result<bool> {
        fsutil::remove_file(&self.key_path(label)?)
    }

    fn exists(&self, label: &str) -> Result<bool> {
        fsutil::path_exists(&self.key_path(label)?)
    }

    fn backend(&self) -> KeystoreBackend {
        KeystoreBackend::InsecureDev
    }

    fn locator(&self, label: &str) -> Result<String> {
        Ok(self.key_path(label)?.display().to_string())
    }
}
