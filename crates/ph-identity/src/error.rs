//! Error types for `ph-identity`.
//!
//! No `Display` output in this module ever contains secret material (seeds, passphrases,
//! decrypted plaintext), untrusted payload contents (circle names, revocation reasons,
//! addresses from invites) or keychain error payloads. Errors name the operation, a
//! static reason and, for local filesystem problems, the local path involved.

use std::io;
use std::path::PathBuf;

use ph_protocol::ProtocolError;
use thiserror::Error;

/// Convenience alias.
pub type Result<T, E = IdentityError> = std::result::Result<T, E>;

/// Why an invitation was rejected by [`crate::validate_invite`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InviteRejection {
    /// The bytes are not a well-formed invite document (strict schema, size and nesting
    /// limits, field bounds).
    #[error("the invite file is malformed: {0}")]
    Malformed(ProtocolError),
    /// The invite signature does not verify under its `circle_root_key`, so the invite
    /// (or its claimed root) is forged or was modified.
    #[error("the invite signature is invalid (forged or modified invite)")]
    BadSignature,
    /// The embedded credential was not issued (or not validly signed) by the circle root
    /// key named in the invite.
    #[error("the credential in the invite was not issued by the circle root key")]
    CredentialNotFromRoot,
    /// The embedded credential is for a different device key than ours.
    #[error("the invite is bound to a different device key; ask the inviter to re-issue it for this device")]
    NotForThisDevice,
    /// `invite_expires_at` is not in the future.
    #[error("the invite has expired; ask the inviter for a new one")]
    Expired,
    /// The embedded credential fails its time rules (expired, not yet valid, lifetime).
    #[error("the credential in the invite is not currently valid: {0}")]
    CredentialInvalid(ProtocolError),
}

/// Why a membership object was refused by the [`crate::MembershipRegistry`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MembershipRejection {
    /// The circle is not known to the registry (call `add_circle` first).
    #[error("unknown circle")]
    UnknownCircle,
    /// The circle id is not derived from the root key supplied for it.
    #[error("circle id is not derived from the given root key")]
    CircleRootMismatch,
    /// The circle is already known with a different root key.
    #[error("circle is already registered with a different root key")]
    ConflictingRoot,
    /// The object was issued by a key other than the circle root.
    #[error("issuer is not the circle root key")]
    IssuerNotRoot,
    /// Credential/acceptance verification failed.
    #[error("invalid membership proof: {0}")]
    InvalidProof(ProtocolError),
    /// Revocation verification failed.
    #[error("invalid revocation: {0}")]
    InvalidRevocation(ProtocolError),
}

/// Every error returned by this crate.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// A keystore label is not `[a-z0-9][a-z0-9-]{0,127}`.
    #[error("invalid keystore label")]
    InvalidLabel,
    /// No secret is stored under this label.
    #[error("no key named {label:?} in the {backend} keystore")]
    NotFound {
        /// The label.
        label: String,
        /// Backend name.
        backend: &'static str,
    },
    /// A secret already exists under this label; it is never silently overwritten.
    #[error("a key named {label:?} already exists in the {backend} keystore; delete it first if you really want to replace it")]
    AlreadyExists {
        /// The label.
        label: String,
        /// Backend name.
        backend: &'static str,
    },
    /// The OS credential store could not be used.
    #[error("the OS keychain is unavailable ({reason}); re-run with `--keystore file` to use an encrypted key file instead")]
    KeystoreUnavailable {
        /// Static reason.
        reason: &'static str,
    },
    /// No passphrase could be obtained (environment variable unset and no terminal).
    #[error("no passphrase available: set PEERHARNESS_PASSPHRASE or run interactively ({reason})")]
    PassphraseUnavailable {
        /// Static reason.
        reason: &'static str,
    },
    /// The passphrase is empty.
    #[error("the passphrase must not be empty")]
    EmptyPassphrase,
    /// The confirmation passphrase did not match.
    #[error("the passphrases did not match")]
    PassphraseMismatch,
    /// Authenticated decryption failed: wrong passphrase, or the file was modified.
    #[error("cannot decrypt key {label:?}: wrong passphrase, or the key file was modified")]
    DecryptionFailed {
        /// The label.
        label: String,
    },
    /// A key file is structurally invalid.
    #[error("key file {path} is corrupt: {reason}")]
    CorruptKeyFile {
        /// Local path of the file.
        path: PathBuf,
        /// Static reason.
        reason: &'static str,
    },
    /// A stored secret could not be decoded (OS keychain entry).
    #[error("stored key {label:?} is corrupt: {reason}")]
    CorruptSecret {
        /// The label.
        label: String,
        /// Static reason.
        reason: &'static str,
    },
    /// A key file is readable or writable by group/others (unix).
    #[error("refusing to use {path}: permissions {mode:o} allow group/other access; run `chmod 600` on it")]
    InsecurePermissions {
        /// Local path.
        path: PathBuf,
        /// The offending permission bits.
        mode: u32,
    },
    /// A key path is not a regular file (for example a symlink).
    #[error("refusing to use {path}: not a regular file")]
    NotRegularFile {
        /// Local path.
        path: PathBuf,
    },
    /// Invalid Argon2 parameters (from a constructor or a key file).
    #[error("invalid key-derivation parameters: {reason}")]
    KdfParams {
        /// Static reason.
        reason: &'static str,
    },
    /// A local filesystem operation failed.
    #[error("{op} {path}: {kind}")]
    Io {
        /// Operation, e.g. "write".
        op: &'static str,
        /// Local path.
        path: PathBuf,
        /// I/O error kind (the OS message is omitted on purpose).
        kind: io::ErrorKind,
    },
    /// The operating system random number generator failed.
    #[error("operating system random number generator failed")]
    Randomness,
    /// Two keys that must match do not (for example a stored circle root key that does
    /// not derive the requested circle id).
    #[error("key mismatch: {what}")]
    KeyMismatch {
        /// Static description.
        what: &'static str,
    },
    /// A time-to-live argument is out of range.
    #[error("invalid lifetime: {reason}")]
    InvalidTtl {
        /// Static reason.
        reason: &'static str,
    },
    /// A file is larger than allowed.
    #[error("{path} is larger than {max} bytes")]
    FileTooLarge {
        /// Local path.
        path: PathBuf,
        /// Limit.
        max: usize,
    },
    /// A protocol object could not be built, signed, parsed or verified.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// An invitation was rejected.
    #[error(transparent)]
    Invite(#[from] InviteRejection),
    /// A membership object was rejected by the registry.
    #[error(transparent)]
    Membership(#[from] MembershipRejection),
}

impl From<ph_core::RandomnessError> for IdentityError {
    fn from(_: ph_core::RandomnessError) -> Self {
        IdentityError::Randomness
    }
}

impl IdentityError {
    pub(crate) fn io(op: &'static str, path: impl Into<PathBuf>, e: &io::Error) -> Self {
        IdentityError::Io {
            op,
            path: path.into(),
            kind: e.kind(),
        }
    }
}
