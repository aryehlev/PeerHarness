//! # ph-identity
//!
//! Identity and membership for PeerHarness (architecture sections 1 and 6, spec
//! 5.1-5.3, ADR-001, ADR-004, ADR-010):
//!
//! * [`keystore`]: where private keys live. [`KeyStore`] trait with three backends:
//!   [`OsKeyStore`] (OS keychain), [`FileKeyStore`] (Argon2id + XChaCha20-Poly1305
//!   encrypted files) and [`InsecureDevKeyStore`] (plaintext, explicit opt-in only).
//! * [`DeviceIdentity`]: this node's Ed25519 device key, which is also its libp2p
//!   identity.
//! * [`CircleAuthority`]: a circle's root key (separate from any device key) that signs
//!   credentials, invites and revocations.
//! * [`validate_invite`] / [`accept_invite`]: joining a circle.
//! * [`MembershipRegistry`]: the verified membership view implementing
//!   [`ph_core::MembershipOracle`].
//!
//! ## Typical flows
//!
//! ```text
//! init:    ks = open_keystore(home, cfg)?; id = DeviceIdentity::create(&*ks)?
//! create:  (auth, circle) = CircleAuthority::create(&*ks)?
//!          cred  = auth.issue_founder_credential(id.public(), now)?
//!          proof = accept_credential(&cred, &id, now)?
//!          reg.add_circle(circle, auth.root_key())?; reg.add_proof(proof, now)?
//! invite:  auth = CircleAuthority::load(&*ks, &circle)?
//!          inv  = auth.invite_member(name, invitee, roles, scopes, id.public(), addrs, now)?
//!          write_invite_file(path, &inv)?
//! join:    v = validate_invite(&read_invite_file(path)?, &id.public(), now)?
//!          (show v.circle_name and v.root_fingerprint; confirm)
//!          proof = accept_invite(&v, &id, now)?
//!          reg.add_circle(v.circle_id, v.root_key)?; reg.add_proof(proof, now)?
//!          reg.note_invite_issuer(&v.circle_id, v.issuer_device_key)?
//! revoke:  rev = auth.issue_revocation(subject, reason, now)?; reg.add_revocation(rev, now)?
//! startup: for each stored circle:      reg.add_circle(id, root)?
//!          for each stored membership:  reg.add_stored_proof(proof, now)  (skip errors)
//!          for each stored revocation:  reg.add_revocation(rev, now)      (skip errors)
//!          for each joined circle:      reg.note_invite_issuer(&id, issuer)?
//! network: proofs from MEMBERSHIP events / Authenticate go through reg.add_proof or
//!          reg.accept_presented_proofs (expired proofs are refused there)
//! ```
//!
//! ## Keystore passphrases
//!
//! All encrypted key files in one home share one passphrase: creating a new key file
//! while another exists first verifies the passphrase by unlocking the existing one.
//!
//! ## Privacy
//!
//! Errors and logs never contain seeds, passphrases, decrypted data, circle names,
//! revocation reasons or keychain error payloads. Logs carry keys, ids and counts only.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod authority;
pub mod device;
pub mod error;
pub mod invite;
pub mod keystore;
pub mod registry;

pub use authority::{
    root_key_label, CircleAuthority, DEFAULT_CREDENTIAL_TTL_SECS, DEFAULT_INVITE_TTL_SECS,
    FOUNDER_CREDENTIAL_TTL_SECS, MAX_INVITE_TTL_SECS,
};
pub use device::DeviceIdentity;
pub use error::{IdentityError, InviteRejection, MembershipRejection, Result};
pub use invite::{
    accept_credential, accept_invite, invite_from_bytes, invite_to_bytes, read_invite_file,
    validate_invite, validate_parsed_invite, write_invite_file, ValidatedInvite,
    MAX_INVITE_FILE_BYTES,
};
pub use keystore::{
    open_keystore, validate_label, FileKeyStore, InsecureAcknowledged, InsecureDevKeyStore,
    KdfParams, KeyStore, KeystoreBackend, KeystoreConfig, OsKeyStore, PassphraseSource,
    PASSPHRASE_ENV,
};
pub use registry::{
    AddOutcome, MemberView, MembershipRegistry, PresentedOutcome, SharedMembershipRegistry,
};

/// Re-exported so callers zeroize secrets with the same crate version.
pub use zeroize::Zeroizing;
