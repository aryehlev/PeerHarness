//! Passphrase-encrypted key files (`file` backend).
//!
//! `<home>/keys/<label>.key` holds one JSON object:
//!
//! ```json
//! {"schema":"peerharness.keyfile/0.1","kdf":"argon2id","m_kib":65536,"t":3,"p":1,
//!  "salt":"<b64url 16 bytes>","nonce":"<b64url 24 bytes>",
//!  "ciphertext":"<b64url 48 bytes>","public_key":"ed25519:..."}
//! ```
//!
//! * key = Argon2id(passphrase, salt, m_kib, t, p) -> 32 bytes (Argon2 version 0x13)
//! * ciphertext = XChaCha20-Poly1305(key, nonce, seed, aad)
//! * aad = `"peerharness-keyfile-v0" 0x00 label 0x00 public_key 0x00 "argon2id:m:t:p"`
//!
//! The AAD binds the label, the public key and the KDF parameters, so renaming a file,
//! swapping its public key or editing the header makes decryption fail. Base64 is
//! URL-safe without padding.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, AeadInOut, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use ph_core::DeviceKey;
use rand::TryRng as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::fsutil;
use super::passphrase::PassphraseSource;
use super::{validate_label, KeyStore, KeystoreBackend, KEYS_DIR};
use crate::error::{IdentityError, Result};

/// The `schema` member of an encrypted key file.
pub const KEYFILE_SCHEMA: &str = "peerharness.keyfile/0.1";
const KDF_NAME: &str = "argon2id";
const AAD_CONTEXT: &[u8] = b"peerharness-keyfile-v0";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const CIPHERTEXT_LEN: usize = 32 + 16;
const MAX_KEYFILE_BYTES: usize = 4096;
const BACKEND: &str = "file";

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    m_kib: u32,
    t: u32,
    p: u32,
}

impl KdfParams {
    /// Largest accepted memory cost (1 GiB), also when reading a key file.
    pub const MAX_M_KIB: u32 = 1024 * 1024;
    /// Largest accepted time cost.
    pub const MAX_T: u32 = 16;
    /// Largest accepted parallelism.
    pub const MAX_P: u32 = 16;
    /// Production default: m = 65536 KiB (64 MiB), t = 3, p = 1.
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: 65536,
        t: 3,
        p: 1,
    };

    /// Validated constructor: `1 <= p <= 16`, `8*p <= m_kib <= 1 GiB`, `1 <= t <= 16`.
    pub fn new(m_kib: u32, t: u32, p: u32) -> Result<Self> {
        let bad = |reason| Err(IdentityError::KdfParams { reason });
        if p == 0 || p > Self::MAX_P {
            return bad("parallelism out of range");
        }
        if m_kib < 8 * p || m_kib > Self::MAX_M_KIB {
            return bad("memory cost out of range");
        }
        if t == 0 || t > Self::MAX_T {
            return bad("time cost out of range");
        }
        Ok(Self { m_kib, t, p })
    }

    /// Very cheap parameters (m = 64 KiB, t = 1, p = 1) for tests and demos only. They
    /// give almost no protection against passphrase guessing.
    pub const fn insecure_fast_for_tests() -> Self {
        KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
        }
    }

    /// Memory cost in KiB.
    pub const fn m_kib(&self) -> u32 {
        self.m_kib
    }
    /// Time cost (passes).
    pub const fn t(&self) -> u32 {
        self.t
    }
    /// Parallelism (lanes).
    pub const fn p(&self) -> u32 {
        self.p
    }

    fn derive(&self, passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let params = Params::new(self.m_kib, self.t, self.p, Some(32)).map_err(|_| {
            IdentityError::KdfParams {
                reason: "rejected by argon2",
            }
        })?;
        let mut out = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase, salt, &mut out[..])
            .map_err(|_| IdentityError::KdfParams {
                reason: "argon2 key derivation failed",
            })?;
        Ok(out)
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    schema: String,
    kdf: String,
    m_kib: u32,
    t: u32,
    p: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
    public_key: DeviceKey,
}

/// Encrypted key files under `<home>/keys/`. See the module docs for the format.
///
/// The passphrase is obtained from the [`PassphraseSource`] the first time it is needed
/// and then cached in memory (zeroized on drop) for the lifetime of this value, so a
/// process that unlocks several keys prompts once. A failed decryption clears the cache.
///
/// All key files in one home share one passphrase: when a new key file is created and
/// no passphrase is cached yet, an existing key file (preferably `device.key`) is
/// unlocked first to verify it, so a wrong passphrase fails with
/// [`IdentityError::DecryptionFailed`] and nothing is written. Creation never replaces
/// an existing file, even under a concurrent creator (temp file + hard link).
pub struct FileKeyStore {
    dir: PathBuf,
    passphrase: PassphraseSource,
    kdf: KdfParams,
    cached: Mutex<Option<Zeroizing<String>>>,
}

impl std::fmt::Debug for FileKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKeyStore")
            .field("dir", &self.dir)
            .field("passphrase", &self.passphrase)
            .field("kdf", &self.kdf)
            .finish_non_exhaustive()
    }
}

impl FileKeyStore {
    /// A file keystore for node home `home` with default Argon2id parameters.
    pub fn new(home: &Path, passphrase: PassphraseSource) -> Self {
        Self {
            dir: home.join(KEYS_DIR),
            passphrase,
            kdf: KdfParams::DEFAULT,
            cached: Mutex::new(None),
        }
    }

    /// Uses `kdf` for newly written key files (existing files keep their own).
    pub fn with_kdf_params(mut self, kdf: KdfParams) -> Self {
        self.kdf = kdf;
        self
    }

    /// The key directory (`<home>/keys`).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Path of the key file for `label`.
    pub fn key_path(&self, label: &str) -> Result<PathBuf> {
        validate_label(label)?;
        Ok(self.dir.join(format!("{label}.key")))
    }

    /// The public key recorded in the key file, without decrypting (no passphrase).
    pub fn public_key(&self, label: &str) -> Result<DeviceKey> {
        let path = self.key_path(label)?;
        Ok(self.read_keyfile(label, &path)?.public_key)
    }

    fn passphrase(&self, creating: bool) -> Result<Zeroizing<String>> {
        let mut guard = self.cached.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = guard.as_ref() {
            return Ok(p.clone());
        }
        let p = self.passphrase.obtain(creating)?;
        *guard = Some(p.clone());
        Ok(p)
    }

    /// The passphrase to encrypt a new key file with.
    ///
    /// All key files in one home share one passphrase (the passphrase is cached per
    /// keystore, and a later process unlocks every key with whatever it was given
    /// first). So if no passphrase is cached yet and another key file already exists
    /// (normally `device.key`), the passphrase is obtained as for an unlock and verified
    /// by decrypting that file; a wrong one fails with
    /// [`IdentityError::DecryptionFailed`] instead of silently creating a key that the
    /// next run cannot open together with the others. Only when no key file exists is
    /// the passphrase asked as a new one (twice when prompting).
    fn passphrase_for_new_key(&self, label: &str) -> Result<Zeroizing<String>> {
        let cached = self
            .cached
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some();
        if !cached {
            if let Some(existing) = self.reference_label(label) {
                // Unlocks (and caches) the passphrase, or fails without caching it.
                drop(self.load_secret(&existing)?);
            }
        }
        self.passphrase(true)
    }

    /// An existing key file other than `label` to verify the passphrase against:
    /// `device` if present, otherwise the first valid label in sorted order.
    fn reference_label(&self, label: &str) -> Option<String> {
        let device = crate::DeviceIdentity::LABEL;
        if label != device && fsutil::path_exists(&self.dir.join(format!("{device}.key"))).ok()? {
            return Some(device.to_owned());
        }
        let mut labels: Vec<String> = std::fs::read_dir(&self.dir)
            .ok()?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let l = name.strip_suffix(".key")?.to_owned();
                (l != label && validate_label(&l).is_ok() && e.file_type().ok()?.is_file())
                    .then_some(l)
            })
            .collect();
        labels.sort();
        labels.into_iter().next()
    }

    fn forget_passphrase(&self) {
        let mut guard = self.cached.lock().unwrap_or_else(|e| e.into_inner());
        *guard = None;
    }

    fn read_keyfile(&self, label: &str, path: &Path) -> Result<KeyFile> {
        if !fsutil::check_private_file(path)? {
            return Err(IdentityError::NotFound {
                label: label.to_owned(),
                backend: BACKEND,
            });
        }
        let bytes = fsutil::read_private_bounded(path, MAX_KEYFILE_BYTES)?;
        let corrupt = |reason| IdentityError::CorruptKeyFile {
            path: path.to_path_buf(),
            reason,
        };
        let kf: KeyFile =
            serde_json::from_slice(&bytes).map_err(|_| corrupt("not a valid key file"))?;
        if kf.schema != KEYFILE_SCHEMA {
            return Err(corrupt("unsupported schema"));
        }
        if kf.kdf != KDF_NAME {
            return Err(corrupt("unsupported kdf"));
        }
        Ok(kf)
    }
}

fn aad(label: &str, public_key: &DeviceKey, kdf: &KdfParams) -> Vec<u8> {
    let mut v = Vec::with_capacity(160);
    v.extend_from_slice(AAD_CONTEXT);
    v.push(0);
    v.extend_from_slice(label.as_bytes());
    v.push(0);
    v.extend_from_slice(public_key.to_string().as_bytes());
    v.push(0);
    v.extend_from_slice(format!("{KDF_NAME}:{}:{}:{}", kdf.m_kib, kdf.t, kdf.p).as_bytes());
    v
}

fn b64_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    let v = URL_SAFE_NO_PAD.decode(s).ok()?;
    <[u8; N]>::try_from(v.as_slice()).ok()
}

fn cipher(key: &Zeroizing<[u8; 32]>) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| IdentityError::KdfParams {
        reason: "derived key has the wrong length",
    })
}

impl KeyStore for FileKeyStore {
    fn store_secret(&self, label: &str, secret: &Zeroizing<[u8; 32]>) -> Result<()> {
        let path = self.key_path(label)?;
        if fsutil::path_exists(&path)? {
            return Err(IdentityError::AlreadyExists {
                label: label.to_owned(),
                backend: BACKEND,
            });
        }
        let public_key = DeviceKey::from_signing_key(&SigningKey::from_bytes(secret));
        let passphrase = self.passphrase_for_new_key(label)?;

        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::SysRng
            .try_fill_bytes(&mut salt)
            .and_then(|()| rand::rngs::SysRng.try_fill_bytes(&mut nonce))
            .map_err(|_| IdentityError::Randomness)?;

        let key = self.kdf.derive(passphrase.as_bytes(), &salt)?;
        let aad = aad(label, &public_key, &self.kdf);
        let ciphertext = cipher(&key)?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &secret[..],
                    aad: &aad,
                },
            )
            .map_err(|_| IdentityError::KdfParams {
                reason: "encryption failed",
            })?;

        let kf = KeyFile {
            schema: KEYFILE_SCHEMA.to_owned(),
            kdf: KDF_NAME.to_owned(),
            m_kib: self.kdf.m_kib,
            t: self.kdf.t,
            p: self.kdf.p,
            salt: URL_SAFE_NO_PAD.encode(salt),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(&ciphertext),
            public_key,
        };
        let json = serde_json::to_vec(&kf).map_err(|_| IdentityError::CorruptKeyFile {
            path: path.clone(),
            reason: "cannot serialize key file",
        })?;
        fsutil::ensure_private_dir(&self.dir)?;
        if !fsutil::write_new_private(&path, &json)? {
            return Err(IdentityError::AlreadyExists {
                label: label.to_owned(),
                backend: BACKEND,
            });
        }
        tracing::debug!(backend = BACKEND, label, "stored key");
        Ok(())
    }

    fn load_secret(&self, label: &str) -> Result<Zeroizing<[u8; 32]>> {
        let path = self.key_path(label)?;
        let kf = self.read_keyfile(label, &path)?;
        let corrupt = |reason| IdentityError::CorruptKeyFile {
            path: path.clone(),
            reason,
        };
        let kdf = KdfParams::new(kf.m_kib, kf.t, kf.p)
            .map_err(|_| corrupt("key-derivation parameters out of range"))?;
        let salt: [u8; SALT_LEN] = b64_fixed(&kf.salt).ok_or_else(|| corrupt("bad salt"))?;
        let nonce: [u8; NONCE_LEN] = b64_fixed(&kf.nonce).ok_or_else(|| corrupt("bad nonce"))?;
        let ct: [u8; CIPHERTEXT_LEN] =
            b64_fixed(&kf.ciphertext).ok_or_else(|| corrupt("bad ciphertext"))?;

        let passphrase = self.passphrase(false)?;
        // Until decryption succeeds the cached passphrase is unverified; drop it on any
        // failure so a later `store_secret` never encrypts with an unverified one.
        let key = match kdf.derive(passphrase.as_bytes(), &salt) {
            Ok(k) => k,
            Err(e) => {
                self.forget_passphrase();
                return Err(e);
            }
        };
        let aad = aad(label, &kf.public_key, &kdf);
        let mut buf = Zeroizing::new(ct.to_vec());
        if cipher(&key)?
            .decrypt_in_place(&XNonce::from(nonce), &aad, &mut *buf)
            .is_err()
        {
            self.forget_passphrase();
            tracing::warn!(backend = BACKEND, label, "key decryption failed");
            return Err(IdentityError::DecryptionFailed {
                label: label.to_owned(),
            });
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        if buf.len() != seed.len() {
            return Err(corrupt("decrypted key has the wrong length"));
        }
        seed.copy_from_slice(&buf);
        if DeviceKey::from_signing_key(&SigningKey::from_bytes(&seed)) != kf.public_key {
            return Err(corrupt(
                "decrypted key does not match the recorded public key",
            ));
        }
        tracing::debug!(backend = BACKEND, label, "loaded key");
        Ok(seed)
    }

    fn delete(&self, label: &str) -> Result<bool> {
        let path = self.key_path(label)?;
        fsutil::remove_file(&path)
    }

    fn exists(&self, label: &str) -> Result<bool> {
        let path = self.key_path(label)?;
        fsutil::path_exists(&path)
    }

    fn backend(&self) -> KeystoreBackend {
        KeystoreBackend::File
    }

    fn locator(&self, label: &str) -> Result<String> {
        Ok(self.key_path(label)?.display().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_bounds() {
        assert!(KdfParams::new(65536, 3, 1).is_ok());
        assert!(KdfParams::new(7, 1, 1).is_err());
        assert!(KdfParams::new(15, 1, 2).is_err());
        assert!(KdfParams::new(KdfParams::MAX_M_KIB + 1, 1, 1).is_err());
        assert!(KdfParams::new(64, 0, 1).is_err());
        assert!(KdfParams::new(64, 17, 1).is_err());
        assert!(KdfParams::new(64, 1, 0).is_err());
        assert_eq!(KdfParams::default(), KdfParams::DEFAULT);
        let f = KdfParams::insecure_fast_for_tests();
        assert_eq!(KdfParams::new(f.m_kib(), f.t(), f.p()).unwrap(), f);
    }

    #[test]
    fn aad_binds_everything() {
        let pk = DeviceKey::from_signing_key(&SigningKey::from_bytes(&[3; 32]));
        let pk2 = DeviceKey::from_signing_key(&SigningKey::from_bytes(&[4; 32]));
        let k = KdfParams::insecure_fast_for_tests();
        let base = aad("device", &pk, &k);
        assert_ne!(base, aad("devicf", &pk, &k));
        assert_ne!(base, aad("device", &pk2, &k));
        assert_ne!(base, aad("device", &pk, &KdfParams::new(64, 2, 1).unwrap()));
    }
}
