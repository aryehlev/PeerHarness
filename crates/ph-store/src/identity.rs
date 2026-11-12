//! `identity_metadata`: the single row describing this node's public identity.

use ph_core::{DeviceKey, Timestamp};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

use crate::error::Result;
use crate::sql;
use crate::Store;

/// Maximum length of [`IdentityMetadata::keystore_backend`] and `keystore_ref`.
pub const MAX_KEYSTORE_REF_BYTES: usize = 1024;

/// Public identity of this node and where its private key lives.
///
/// `keystore_ref` is a *reference* (a keychain service/account name or a key file
/// path), never key material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IdentityMetadata {
    /// The device public key.
    pub device_key: DeviceKey,
    /// Keystore backend name (`"os"`, `"file"`, `"insecure-dev"`).
    pub keystore_backend: String,
    /// Backend-specific reference to the stored private key.
    pub keystore_ref: String,
    /// When the identity was created.
    pub created_at: Timestamp,
}

/// Whether `keystore_ref` can be recorded: not empty, at most
/// [`MAX_KEYSTORE_REF_BYTES`] and with no control character. [`Store::set_identity`]
/// checks it. It is public so that a caller can check the reference of a key before
/// the key is written: a key file's reference is its path.
///
/// # Errors
///
/// [`crate::StoreError::Invalid`] otherwise.
pub fn check_keystore_ref(keystore_ref: &str) -> Result<()> {
    sql::check_short("keystore reference", keystore_ref, MAX_KEYSTORE_REF_BYTES)
}

impl Store {
    /// The identity row, if `peerharness init` has run.
    pub fn identity(&self) -> Result<Option<IdentityMetadata>> {
        Ok(self
            .conn
            .query_row(
                "SELECT device_key, keystore_backend, keystore_ref, created_at
                 FROM identity_metadata WHERE id = 1",
                [],
                |r| {
                    Ok(IdentityMetadata {
                        device_key: sql::parse(r, 0, "device key")?,
                        keystore_backend: r.get(1)?,
                        keystore_ref: r.get(2)?,
                        created_at: sql::ts(r, 3)?,
                    })
                },
            )
            .optional()?)
    }

    /// Creates or replaces the identity row (device re-enrollment replaces it).
    pub fn set_identity(&self, id: &IdentityMetadata) -> Result<()> {
        sql::check_short("keystore backend", &id.keystore_backend, 64)?;
        check_keystore_ref(&id.keystore_ref)?;
        self.conn.execute(
            "INSERT INTO identity_metadata (id, device_key, keystore_backend, keystore_ref, created_at)
             VALUES (1, ?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET device_key = excluded.device_key,
                 keystore_backend = excluded.keystore_backend,
                 keystore_ref = excluded.keystore_ref,
                 created_at = excluded.created_at",
            params![
                id.device_key.to_string(),
                id.keystore_backend,
                id.keystore_ref,
                id.created_at.unix_seconds()
            ],
        )?;
        Ok(())
    }
}
