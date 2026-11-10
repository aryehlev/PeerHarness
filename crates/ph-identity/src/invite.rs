//! Joining a circle: validating an invite and signing the acceptance (spec 5.2).

use std::fmt;
use std::path::Path;

use ph_core::{CircleId, DeviceKey, Timestamp};
use ph_protocol::limits::MAX_CREDENTIAL_BYTES;
use ph_protocol::signing::{self, Context};
use ph_protocol::{
    verify_credential_signature, verify_invite_for_subject, verify_membership_proof, Invite,
    MembershipCredential, MembershipProof, UnsignedAcceptance,
};

use crate::device::DeviceIdentity;
use crate::error::{IdentityError, InviteRejection, Result};
use crate::keystore::fsutil;

/// Largest invite file accepted, in bytes (the protocol's credential document limit).
pub const MAX_INVITE_FILE_BYTES: usize = MAX_CREDENTIAL_BYTES;

/// An invite that passed every check in [`validate_invite`] for our device key.
///
/// Show `circle_name` and `root_fingerprint` to the human and require confirmation
/// (or `--yes --expect-fingerprint <fp>` matching `root_fingerprint`) before calling
/// [`accept_invite`]. `circle_name` is peer-supplied text: display it, never log it.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedInvite {
    /// The circle, `derive(root_key)`.
    pub circle_id: CircleId,
    /// Local label chosen by the inviter (1-64 chars, single line, bidi-free).
    pub circle_name: String,
    /// The circle root key.
    pub root_key: DeviceKey,
    /// Fingerprint of `root_key` to compare out of band.
    pub root_fingerprint: String,
    /// Our credential, issued by `root_key` for our device key.
    pub credential: MembershipCredential,
    /// Device key of the inviting node (dial and authenticate it; present credentials
    /// to it, see [`crate::MembershipRegistry::note_invite_issuer`]).
    pub issuer_device_key: DeviceKey,
    /// Multiaddr strings of the inviting node (at most 8; not yet parsed).
    pub issuer_addrs: Vec<String>,
    /// When the invite expires.
    pub invite_expires_at: Timestamp,
    /// The full signed invite (for storage or re-validation).
    pub invite: Invite,
}

impl ValidatedInvite {
    /// Whether `expected` (for example from `--expect-fingerprint`) equals
    /// [`Self::root_fingerprint`], ignoring ASCII case and surrounding whitespace.
    pub fn fingerprint_matches(&self, expected: &str) -> bool {
        expected.trim().eq_ignore_ascii_case(&self.root_fingerprint)
    }
}

impl fmt::Debug for ValidatedInvite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedInvite")
            .field("circle_id", &self.circle_id)
            .field("circle_name_len", &self.circle_name.len())
            .field("root_key", &self.root_key)
            .field("credential", &self.credential)
            .field("issuer_device_key", &self.issuer_device_key)
            .field("issuer_addrs_count", &self.issuer_addrs.len())
            .field("invite_expires_at", &self.invite_expires_at)
            .finish_non_exhaustive()
    }
}

/// Strictly parses and fully verifies an invite file for `my_device_key` at `now`.
///
/// Checks, in order (each failure is a distinct [`InviteRejection`]):
/// 1. strict JSON parse, schema, size/nesting limits and field bounds (`Malformed`);
/// 2. the credential's `issuer_key` is the invite's `circle_root_key`, and the
///    credential signature verifies under it (`CredentialNotFromRoot`);
/// 3. the invite signature verifies under `circle_root_key` (`BadSignature`, which is
///    what a forged or swapped root produces);
/// 4. the credential subject is `my_device_key` (`NotForThisDevice`);
/// 5. `invite_expires_at > now` (`Expired`);
/// 6. the credential's time rules at `now` (`CredentialInvalid`).
pub fn validate_invite(
    bytes: &[u8],
    my_device_key: &DeviceKey,
    now: Timestamp,
) -> Result<ValidatedInvite> {
    let inv = Invite::from_json_bytes(bytes).map_err(InviteRejection::Malformed)?;
    validate_parsed_invite(inv, my_device_key, now)
}

/// [`validate_invite`] for an already parsed [`Invite`].
pub fn validate_parsed_invite(
    inv: Invite,
    my_device_key: &DeviceKey,
    now: Timestamp,
) -> Result<ValidatedInvite> {
    if inv.credential.issuer_key != inv.circle_root_key {
        return Err(InviteRejection::CredentialNotFromRoot.into());
    }
    inv.check_structure().map_err(InviteRejection::Malformed)?;
    if verify_credential_signature(&inv.credential).is_err() {
        return Err(InviteRejection::CredentialNotFromRoot.into());
    }
    let input = inv.signing_input().map_err(InviteRejection::Malformed)?;
    if signing::verify_input(
        Context::Invite,
        &inv.circle_root_key,
        &input,
        &inv.signature,
    )
    .is_err()
    {
        return Err(InviteRejection::BadSignature.into());
    }
    if inv.credential.subject_device_key != *my_device_key {
        return Err(InviteRejection::NotForThisDevice.into());
    }
    if inv.invite_expires_at <= now {
        return Err(InviteRejection::Expired.into());
    }
    inv.credential
        .check_time(now)
        .map_err(InviteRejection::CredentialInvalid)?;
    // Belt and braces: the protocol crate's combined check must agree.
    verify_invite_for_subject(&inv, my_device_key, now).map_err(InviteRejection::Malformed)?;

    Ok(ValidatedInvite {
        circle_id: inv.circle_id(),
        circle_name: inv.circle_name.clone(),
        root_key: inv.circle_root_key,
        root_fingerprint: inv.root_fingerprint(),
        credential: inv.credential.clone(),
        issuer_device_key: inv.issuer_device_key,
        issuer_addrs: inv.issuer_addrs.clone(),
        invite_expires_at: inv.invite_expires_at,
        invite: inv,
    })
}

/// Signs the acceptance for a validated invite with our device key, producing the
/// [`MembershipProof`] we present to peers (and publish as a MEMBERSHIP event).
///
/// Fails with [`IdentityError::KeyMismatch`] if `identity` is not the credential
/// subject. The invite is re-checked for expiry at `now` (time may have passed while the
/// human confirmed).
pub fn accept_invite(
    invite: &ValidatedInvite,
    identity: &DeviceIdentity,
    now: Timestamp,
) -> Result<MembershipProof> {
    if invite.invite_expires_at <= now {
        return Err(InviteRejection::Expired.into());
    }
    accept_credential(&invite.credential, identity, now)
}

/// Signs an acceptance of `credential` (for example the founder accepting their own
/// founder credential) and returns the verified proof.
pub fn accept_credential(
    credential: &MembershipCredential,
    identity: &DeviceIdentity,
    now: Timestamp,
) -> Result<MembershipProof> {
    if credential.subject_device_key != identity.public() {
        return Err(IdentityError::KeyMismatch {
            what: "credential subject is not this device",
        });
    }
    let acceptance =
        UnsignedAcceptance::for_credential(credential, now)?.sign(identity.signing_key())?;
    let proof = MembershipProof {
        credential: credential.clone(),
        acceptance,
    };
    verify_membership_proof(&proof, now)?;
    tracing::info!(circle = %credential.circle_id, "credential accepted");
    Ok(proof)
}

/// The canonical (JCS) bytes of an invite, as written to an invite file.
pub fn invite_to_bytes(invite: &Invite) -> Result<Vec<u8>> {
    Ok(invite.to_canonical_json()?.into_bytes())
}

/// Strictly parses invite bytes without verifying signatures (use
/// [`validate_invite`] to join).
pub fn invite_from_bytes(bytes: &[u8]) -> Result<Invite> {
    Ok(Invite::from_json_bytes(bytes).map_err(InviteRejection::Malformed)?)
}

/// Reads an invite file, refusing files larger than [`MAX_INVITE_FILE_BYTES`]. Pass the
/// result to [`validate_invite`].
pub fn read_invite_file(path: &Path) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path).map_err(|e| IdentityError::io("inspect", path, &e))?;
    if !meta.is_file() {
        return Err(IdentityError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    Ok(fsutil::read_bounded(path, MAX_INVITE_FILE_BYTES)?.to_vec())
}

/// Writes an invite file atomically with mode 0600 (replacing an existing file).
pub fn write_invite_file(path: &Path, invite: &Invite) -> Result<()> {
    fsutil::write_atomic_private(path, &invite_to_bytes(invite)?)
}
