//! The circle authority (root) key and everything it signs (spec 5.2, architecture 6).

use std::fmt;

use ed25519_dalek::SigningKey;
use ph_core::{CircleId, DeviceKey, EventId, Nonce, Role, Scope, Timestamp};
use ph_protocol::limits::{lifetimes, MAX_CREDENTIAL_LIFETIME_SECS};
use ph_protocol::{
    verify_credential, verify_invite, Charter, CharterContent, Invite, MembershipCredential,
    Revocation, UnsignedCharter, UnsignedInvite, UnsignedMembershipCredential, UnsignedRevocation,
};

use crate::device::random_seed;
use crate::error::{IdentityError, Result};
use crate::keystore::KeyStore;

/// Default lifetime of a member credential: 30 days.
pub const DEFAULT_CREDENTIAL_TTL_SECS: i64 = lifetimes::CREDENTIAL_SECS;
/// Default lifetime of an invite: 24 hours.
pub const DEFAULT_INVITE_TTL_SECS: i64 = lifetimes::INVITE_SECS;
/// Longest invite lifetime this crate will sign: 7 days (invites are meant to be short).
pub const MAX_INVITE_TTL_SECS: i64 = 7 * 86_400;
/// Lifetime of the founder's own credential: 365 days. The founder holds the root key
/// and can re-issue it at any time with [`CircleAuthority::issue_founder_credential`].
pub const FOUNDER_CREDENTIAL_TTL_SECS: i64 = 365 * 86_400;

/// The keystore label for a circle's root key: `"circle-root-<64 hex of circle id>"`.
pub fn root_key_label(circle_id: &CircleId) -> String {
    format!("circle-root-{}", circle_id.to_hex())
}

/// A circle's root (authority) key, held only by the founder.
///
/// It is a separate Ed25519 key from the founder's device key, it is never sent
/// anywhere, and in v0 it is the only issuer for the circle: `circle_id ==
/// CircleId::derive(root_key)`. It signs credentials, invites and revocations.
///
/// `Debug` shows only the circle id and root public key.
pub struct CircleAuthority {
    signing_key: SigningKey,
    root_key: DeviceKey,
    circle_id: CircleId,
}

impl CircleAuthority {
    /// Generates a new root key, stores it under [`root_key_label`], and returns the
    /// authority with its derived circle id.
    pub fn create(keystore: &dyn KeyStore) -> Result<(Self, CircleId)> {
        let seed = random_seed()?;
        let authority = Self::from_signing_key(SigningKey::from_bytes(&seed));
        let circle_id = authority.circle_id;
        keystore.store_secret(&authority.keystore_label(), &seed)?;
        tracing::info!(circle = %circle_id, backend = %keystore.backend(), "circle root key created");
        Ok((authority, circle_id))
    }

    /// Loads the root key for `circle_id` and checks that it derives that circle id.
    pub fn load(keystore: &dyn KeyStore, circle_id: &CircleId) -> Result<Self> {
        let seed = keystore.load_secret(&root_key_label(circle_id))?;
        let authority = Self::from_signing_key(SigningKey::from_bytes(&seed));
        if authority.circle_id != *circle_id {
            return Err(IdentityError::KeyMismatch {
                what: "stored root key does not derive the requested circle id",
            });
        }
        Ok(authority)
    }

    /// Whether `keystore` holds the root key for `circle_id` (i.e. we founded it).
    pub fn exists(keystore: &dyn KeyStore, circle_id: &CircleId) -> Result<bool> {
        keystore.exists(&root_key_label(circle_id))
    }

    /// Wraps an existing root signing key (tests, fixtures). Not stored anywhere.
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let root_key = DeviceKey::from_signing_key(&signing_key);
        Self {
            circle_id: CircleId::derive(&root_key),
            root_key,
            signing_key,
        }
    }

    /// The circle id, `derive(root_key)`.
    pub fn circle_id(&self) -> CircleId {
        self.circle_id
    }

    /// The root public key (the `issuer_key` of everything this authority signs).
    pub fn root_key(&self) -> DeviceKey {
        self.root_key
    }

    /// Fingerprint of the root key, which invitees compare out of band.
    pub fn root_fingerprint(&self) -> String {
        self.root_key.fingerprint()
    }

    /// The keystore label of this root key.
    pub fn keystore_label(&self) -> String {
        root_key_label(&self.circle_id)
    }

    /// The root signing key. Use only for signing circle-root objects (for example
    /// wrapping a [`Revocation`] in a REVOCATION envelope authored by the root key).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Issues a credential for `subject` valid from `now` for `ttl_secs` seconds
    /// (`1..=400 days`). Roles must be 1-2 distinct values and scopes 1-16 distinct
    /// values. `subject` must not be the root key itself ([`IdentityError::KeyMismatch`]).
    pub fn issue_credential(
        &self,
        subject: DeviceKey,
        roles: Vec<Role>,
        scopes: Vec<Scope>,
        ttl_secs: i64,
        now: Timestamp,
    ) -> Result<MembershipCredential> {
        if subject == self.root_key {
            // The root key is never a device/member key (spec 5.1); a credential for it
            // would let the never-distributed authority key act as an ordinary member.
            return Err(IdentityError::KeyMismatch {
                what: "the circle root key cannot be issued a membership credential",
            });
        }
        if ttl_secs <= 0 || ttl_secs > MAX_CREDENTIAL_LIFETIME_SECS {
            return Err(IdentityError::InvalidTtl {
                reason: "credential lifetime must be between 1 second and 400 days",
            });
        }
        let expires_at = now
            .checked_add_secs(ttl_secs)
            .ok_or(IdentityError::InvalidTtl {
                reason: "credential expiry is out of range",
            })?;
        let cred = UnsignedMembershipCredential::new(
            self.root_key,
            subject,
            roles,
            scopes,
            now,
            expires_at,
        )
        .sign(&self.signing_key)?;
        tracing::debug!(circle = %self.circle_id, subject = %subject, "credential issued");
        Ok(cred)
    }

    /// The founder's own credential: roles `[owner, member]`, scopes `["*"]`, valid for
    /// [`FOUNDER_CREDENTIAL_TTL_SECS`]. The founder must still accept it with
    /// [`crate::accept_credential`] to get an active [`ph_protocol::MembershipProof`].
    pub fn issue_founder_credential(
        &self,
        founder_device_key: DeviceKey,
        now: Timestamp,
    ) -> Result<MembershipCredential> {
        self.issue_credential(
            founder_device_key,
            vec![Role::Owner, Role::Member],
            vec![Scope::all()],
            FOUNDER_CREDENTIAL_TTL_SECS,
            now,
        )
    }

    /// Re-issues `old` (same subject, roles and scopes) valid from `now` for `ttl_secs`.
    /// `old` must have been issued by this authority (it may be expired). The subject
    /// must accept the new credential again.
    pub fn renew_credential(
        &self,
        old: &MembershipCredential,
        ttl_secs: i64,
        now: Timestamp,
    ) -> Result<MembershipCredential> {
        if old.issuer_key != self.root_key {
            return Err(IdentityError::KeyMismatch {
                what: "credential was not issued by this circle root",
            });
        }
        ph_protocol::verify_credential_signature(old)?;
        self.issue_credential(
            old.subject_device_key,
            old.roles.clone(),
            old.scopes.clone(),
            ttl_secs,
            now,
        )
    }

    /// Builds and signs an invite carrying `credential` (which this authority must have
    /// issued and which must be valid at `now`), the inviting node's device key and
    /// listen addresses (at most 8 multiaddr strings).
    ///
    /// `circle_name` is a 1-64 character single-line label shown to the invitee.
    /// `ttl_secs` must be `1..=MAX_INVITE_TTL_SECS` and the invite may not outlive the
    /// credential. Use [`DEFAULT_INVITE_TTL_SECS`] (24 h) normally.
    #[allow(clippy::too_many_arguments)]
    pub fn create_invite(
        &self,
        circle_name: &str,
        credential: MembershipCredential,
        issuer_device_key: DeviceKey,
        issuer_addrs: Vec<String>,
        ttl_secs: i64,
        now: Timestamp,
    ) -> Result<Invite> {
        if credential.issuer_key != self.root_key {
            return Err(IdentityError::KeyMismatch {
                what: "credential was not issued by this circle root",
            });
        }
        verify_credential(&credential, now)?;
        if ttl_secs <= 0 || ttl_secs > MAX_INVITE_TTL_SECS {
            return Err(IdentityError::InvalidTtl {
                reason: "invite lifetime must be between 1 second and 7 days",
            });
        }
        let invite_expires_at = now.plus_secs(ttl_secs);
        if invite_expires_at > credential.expires_at {
            return Err(IdentityError::InvalidTtl {
                reason: "the invite would outlive its credential",
            });
        }
        let invite = UnsignedInvite {
            circle_name: circle_name.to_owned(),
            circle_root_key: self.root_key,
            credential,
            issuer_device_key,
            issuer_addrs,
            invite_expires_at,
            nonce: Nonce::random()?,
        }
        .sign(&self.signing_key)?;
        verify_invite(&invite, now)?;
        tracing::debug!(circle = %self.circle_id, subject = %invite.credential.subject_device_key, "invite created");
        Ok(invite)
    }

    /// Convenience: issues a credential for `subject` with
    /// [`DEFAULT_CREDENTIAL_TTL_SECS`] and wraps it in an invite with
    /// [`DEFAULT_INVITE_TTL_SECS`]. Returns the invite (whose `credential` field the
    /// caller records in `issued_invites`).
    #[allow(clippy::too_many_arguments)]
    pub fn invite_member(
        &self,
        circle_name: &str,
        subject: DeviceKey,
        roles: Vec<Role>,
        scopes: Vec<Scope>,
        issuer_device_key: DeviceKey,
        issuer_addrs: Vec<String>,
        now: Timestamp,
    ) -> Result<Invite> {
        let credential =
            self.issue_credential(subject, roles, scopes, DEFAULT_CREDENTIAL_TTL_SECS, now)?;
        self.create_invite(
            circle_name,
            credential,
            issuer_device_key,
            issuer_addrs,
            DEFAULT_INVITE_TTL_SECS,
            now,
        )
    }

    /// Signs a revocation of `subject` in this circle. `reason` is 0-200 characters,
    /// single line (it travels to every member; keep it free of personal data).
    ///
    /// Revocation in v0 is permanent for that device key in this circle: every node
    /// denies the key regardless of when its credentials were issued, so re-enrolling
    /// the same person requires a new device key.
    pub fn issue_revocation(
        &self,
        subject: DeviceKey,
        reason: &str,
        now: Timestamp,
    ) -> Result<Revocation> {
        let rev = UnsignedRevocation::new(
            self.root_key,
            subject,
            now,
            reason.to_owned(),
            Nonce::random()?,
        )
        .sign(&self.signing_key)?;
        tracing::info!(circle = %self.circle_id, subject = %subject, "revocation issued");
        Ok(rev)
    }

    /// Signs the founding charter of this circle (`seq` 1): `content` is normally
    /// `CharterContent::founding(founder_entry)`, the founder as the only member with
    /// the default rules (architecture section 10.2).
    pub fn issue_founding_charter(
        &self,
        content: CharterContent,
        now: Timestamp,
    ) -> Result<Charter> {
        let charter =
            UnsignedCharter::founding(self.root_key, content, now).sign(&self.signing_key)?;
        tracing::info!(circle = %self.circle_id, members = charter.content.roll.len(), "founding charter issued");
        Ok(charter)
    }

    /// Notarizes the next charter: the successor of `current` with content `next`,
    /// justified by the RESULT event `justification`.
    ///
    /// The root key is a notary, not a ruler (architecture section 10.8). This method
    /// only signs; it cannot know whether a vote passed. **The caller must verify the
    /// returned charter with `ph_governance::check_successor` before storing or
    /// publishing it**, exactly as every other node will: a charter whose content
    /// differs from the passed amendment, or whose amendment did not pass, is rejected
    /// by all of them however validly it is signed.
    pub fn issue_next_charter(
        &self,
        current: &Charter,
        next: CharterContent,
        justification: EventId,
        now: Timestamp,
    ) -> Result<Charter> {
        if current.circle_id != self.circle_id || current.issuer_key != self.root_key {
            return Err(IdentityError::KeyMismatch {
                what: "the current charter belongs to another circle",
            });
        }
        let charter = UnsignedCharter::successor(current, next, justification, now)?
            .sign(&self.signing_key)?;
        tracing::info!(circle = %self.circle_id, seq = charter.seq, members = charter.content.roll.len(), "charter notarized");
        Ok(charter)
    }
}

impl fmt::Debug for CircleAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CircleAuthority")
            .field("circle_id", &self.circle_id)
            .field("root_key", &self.root_key)
            .finish_non_exhaustive()
    }
}
