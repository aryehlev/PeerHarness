//! Membership objects (architecture section 6): [`MembershipCredential`],
//! [`Acceptance`], [`Revocation`] and [`Invite`].
//!
//! Each kind has an `Unsigned*` form (all members except `signature`) with a `sign`
//! method, and a signed form that wraps the unsigned form plus the signature and
//! dereferences to it. Both forms (de)serialize with serde to exactly the documented
//! JSON, including the constant `schema` member, and reject unknown members.
//!
//! Deserializing checks only the schema. Use the `verify_*` functions to check
//! signatures, bindings and time rules. v0 has exactly one issuer per circle, the root
//! key: `circle_id == CircleId::derive(issuer_key)`.

use std::collections::HashSet;
use std::ops::Deref;

use ed25519_dalek::SigningKey;
use ph_core::{CircleId, DeviceKey, Digest, Nonce, Role, Scope, Signature, Timestamp};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{ProtocolError, TimeRule};
use crate::jcs::{self, ParseLimits};
use crate::limits::{
    self, CLOCK_SKEW_SECS, MAX_ADDRS, MAX_ADDR_BYTES, MAX_CREDENTIAL_BYTES,
    MAX_CREDENTIAL_LIFETIME_SECS, MAX_CREDENTIAL_ROLES, MAX_CREDENTIAL_SCOPES, MAX_DEPTH,
};
use crate::signing::{self, Context};
use crate::text::{check_text, Lines};

const CREDENTIAL_LIMITS: ParseLimits = ParseLimits {
    max_bytes: MAX_CREDENTIAL_BYTES,
    max_depth: MAX_DEPTH,
};

/// Strictly parses a standalone signed or unsigned object of kind `context`.
pub(crate) fn parse_document<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    limits: ParseLimits,
    context: Context,
) -> Result<T, ProtocolError> {
    let v = jcs::parse_strict(bytes, limits)?;
    from_value_checked(&v, context)
}

/// Typed conversion of an already strictly parsed value: checks the `schema` member,
/// deserializes, and requires that re-serializing yields the same value (so the typed
/// form and the signed bytes can never disagree).
pub(crate) fn from_value_checked<T: DeserializeOwned + Serialize>(
    v: &Value,
    context: Context,
) -> Result<T, ProtocolError> {
    check_schema_member(v, context)?;
    let schema_err = ProtocolError::Schema {
        object: context.object_name(),
    };
    let t: T = serde_json::from_value(v.clone()).map_err(|_| schema_err.clone())?;
    if jcs::to_value(&t)? != *v {
        return Err(schema_err);
    }
    Ok(t)
}

pub(crate) fn check_schema_member(v: &Value, context: Context) -> Result<(), ProtocolError> {
    match v.get("schema").and_then(Value::as_str) {
        Some(s) if s == context.schema() => Ok(()),
        _ => Err(ProtocolError::UnsupportedSchema {
            object: context.object_name(),
        }),
    }
}

fn check_schema_str(s: &str, context: Context) -> Result<(), ProtocolError> {
    if s == context.schema() {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedSchema {
            object: context.object_name(),
        })
    }
}

fn not_future(object: &'static str, t: Timestamp, now: Timestamp) -> Result<(), ProtocolError> {
    if t > now.plus_secs(CLOCK_SKEW_SECS) {
        return Err(ProtocolError::Time {
            object,
            rule: TimeRule::FutureDated,
        });
    }
    Ok(())
}

fn require_key(
    what: &'static str,
    key: &SigningKey,
    expected: &DeviceKey,
) -> Result<(), ProtocolError> {
    if DeviceKey::from_signing_key(key) == *expected {
        Ok(())
    } else {
        Err(ProtocolError::Mismatch { what })
    }
}

/// Deserializes a field that must be present and non-null when the containing struct
/// uses `#[serde(default)]` for it.
pub(crate) fn some<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

macro_rules! signed_wrapper {
    ($signed:ident, $unsigned:ident) => {
        impl Deref for $signed {
            type Target = $unsigned;
            fn deref(&self) -> &$unsigned {
                &self.unsigned
            }
        }
    };
}

// =======================================================================================
// MembershipCredential
// =======================================================================================

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRepr {
    schema: String,
    circle_id: CircleId,
    subject_device_key: DeviceKey,
    roles: Vec<Role>,
    scopes: Vec<Scope>,
    issued_at: Timestamp,
    expires_at: Timestamp,
    issuer_key: DeviceKey,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    signature: Option<Signature>,
}

/// The unsigned members of a [`MembershipCredential`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CredentialRepr", into = "CredentialRepr")]
pub struct UnsignedMembershipCredential {
    /// Circle the credential is for; must equal `CircleId::derive(issuer_key)`.
    pub circle_id: CircleId,
    /// Device key of the member.
    pub subject_device_key: DeviceKey,
    /// Granted roles (1-2, unique).
    pub roles: Vec<Role>,
    /// Granted scopes (1-16, unique).
    pub scopes: Vec<Scope>,
    /// Issue time.
    pub issued_at: Timestamp,
    /// Expiry time.
    pub expires_at: Timestamp,
    /// The circle root key that signs it.
    pub issuer_key: DeviceKey,
}

/// A signed statement by a circle root that `subject_device_key` holds `roles` within
/// `scopes` until `expires_at`.
///
/// ```json
/// {"schema":"peerharness.membership/0.1","circle_id":"sha256:…","subject_device_key":"ed25519:…",
///  "roles":["member"],"scopes":["team/backend"],"issued_at":"…","expires_at":"…",
///  "issuer_key":"ed25519:…","signature":"base64url:…"}
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CredentialRepr", into = "CredentialRepr")]
pub struct MembershipCredential {
    /// The signed members.
    pub unsigned: UnsignedMembershipCredential,
    /// Signature by `issuer_key`.
    pub signature: Signature,
}

signed_wrapper!(MembershipCredential, UnsignedMembershipCredential);

impl From<UnsignedMembershipCredential> for CredentialRepr {
    fn from(u: UnsignedMembershipCredential) -> Self {
        CredentialRepr {
            schema: Context::Membership.schema().to_owned(),
            circle_id: u.circle_id,
            subject_device_key: u.subject_device_key,
            roles: u.roles,
            scopes: u.scopes,
            issued_at: u.issued_at,
            expires_at: u.expires_at,
            issuer_key: u.issuer_key,
            signature: None,
        }
    }
}

impl From<MembershipCredential> for CredentialRepr {
    fn from(c: MembershipCredential) -> Self {
        let mut r = CredentialRepr::from(c.unsigned);
        r.signature = Some(c.signature);
        r
    }
}

impl CredentialRepr {
    fn split(self) -> Result<(UnsignedMembershipCredential, Option<Signature>), ProtocolError> {
        check_schema_str(&self.schema, Context::Membership)?;
        Ok((
            UnsignedMembershipCredential {
                circle_id: self.circle_id,
                subject_device_key: self.subject_device_key,
                roles: self.roles,
                scopes: self.scopes,
                issued_at: self.issued_at,
                expires_at: self.expires_at,
                issuer_key: self.issuer_key,
            },
            self.signature,
        ))
    }
}

impl TryFrom<CredentialRepr> for UnsignedMembershipCredential {
    type Error = ProtocolError;
    fn try_from(r: CredentialRepr) -> Result<Self, ProtocolError> {
        match r.split()? {
            (u, None) => Ok(u),
            (_, Some(_)) => Err(ProtocolError::Schema {
                object: "membership credential",
            }),
        }
    }
}

impl TryFrom<CredentialRepr> for MembershipCredential {
    type Error = ProtocolError;
    fn try_from(r: CredentialRepr) -> Result<Self, ProtocolError> {
        match r.split()? {
            (unsigned, Some(signature)) => Ok(Self {
                unsigned,
                signature,
            }),
            (_, None) => Err(ProtocolError::Schema {
                object: "membership credential",
            }),
        }
    }
}

impl UnsignedMembershipCredential {
    /// Builds a credential issued by `issuer_key`, deriving `circle_id` from it.
    pub fn new(
        issuer_key: DeviceKey,
        subject_device_key: DeviceKey,
        roles: Vec<Role>,
        scopes: Vec<Scope>,
        issued_at: Timestamp,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            circle_id: CircleId::derive(&issuer_key),
            subject_device_key,
            roles,
            scopes,
            issued_at,
            expires_at,
            issuer_key,
        }
    }

    /// The unsigned JSON object.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        jcs::to_value(self)
    }

    /// `"peerharness-membership-v0\0" || JCS(unsigned)`.
    pub fn signing_input(&self) -> Result<Vec<u8>, ProtocolError> {
        signing::signing_input(Context::Membership, &self.to_value()?)
    }

    /// The credential digest (object digest of the signing input), referenced by
    /// acceptances.
    pub fn digest(&self) -> Result<Digest, ProtocolError> {
        Ok(signing::digest_of_input(&self.signing_input()?))
    }

    /// Checks the time-independent rules: roles, scopes and the circle/issuer binding.
    pub fn check_structure(&self) -> Result<(), ProtocolError> {
        if self.roles.is_empty() || self.roles.len() > MAX_CREDENTIAL_ROLES {
            return Err(ProtocolError::field("roles", "expected 1-2 roles"));
        }
        if self.roles.iter().collect::<HashSet<_>>().len() != self.roles.len() {
            return Err(ProtocolError::field("roles", "duplicate role"));
        }
        if self.scopes.is_empty() || self.scopes.len() > MAX_CREDENTIAL_SCOPES {
            return Err(ProtocolError::field("scopes", "expected 1-16 scopes"));
        }
        if self.scopes.iter().collect::<HashSet<_>>().len() != self.scopes.len() {
            return Err(ProtocolError::field("scopes", "duplicate scope"));
        }
        if !self.circle_id.is_derived_from(&self.issuer_key) {
            return Err(ProtocolError::Mismatch {
                what: "credential circle_id and issuer_key",
            });
        }
        Ok(())
    }

    /// Checks the time rules at `now`: `issued_at <= now + skew`, `expires_at > now`,
    /// `expires_at > issued_at` and a lifetime of at most 400 days.
    pub fn check_time(&self, now: Timestamp) -> Result<(), ProtocolError> {
        let object = "membership credential";
        not_future(object, self.issued_at, now)?;
        if self.expires_at <= self.issued_at {
            return Err(ProtocolError::Time {
                object,
                rule: TimeRule::ExpiresBeforeCreated,
            });
        }
        if self.expires_at.secs_since(self.issued_at) > MAX_CREDENTIAL_LIFETIME_SECS {
            return Err(ProtocolError::Time {
                object,
                rule: TimeRule::LifetimeTooLong,
            });
        }
        if self.expires_at <= now {
            return Err(ProtocolError::Time {
                object,
                rule: TimeRule::Expired,
            });
        }
        Ok(())
    }

    /// Signs with the circle root key, which must match `issuer_key`.
    pub fn sign(self, root_key: &SigningKey) -> Result<MembershipCredential, ProtocolError> {
        require_key("signing key and issuer_key", root_key, &self.issuer_key)?;
        self.check_structure()?;
        let signature = signing::sign_input(root_key, &self.signing_input()?);
        Ok(MembershipCredential {
            unsigned: self,
            signature,
        })
    }
}

impl MembershipCredential {
    /// Strictly parses a standalone credential JSON document (schema only, no
    /// signature check).
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        parse_document(bytes, CREDENTIAL_LIMITS, Context::Membership)
    }

    /// The signed JSON object.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        jcs::to_value(self)
    }

    /// The canonical (JCS) JSON text of the signed object, for storage.
    pub fn to_canonical_json(&self) -> Result<String, ProtocolError> {
        jcs::to_canonical_string(self)
    }

    /// Whether this credential's roles grant `cap` and one of its scopes covers `scope`.
    /// Checks neither the signature, the time rules, the acceptance nor revocation.
    pub fn grants(&self, scope: &Scope, cap: ph_core::Capability) -> bool {
        ph_core::roles_grant(&self.roles, cap) && Scope::any_covers(&self.scopes, scope)
    }
}

/// Checks a credential's structure and signature, without time rules (for credentials
/// loaded from local storage).
pub fn verify_credential_signature(cred: &MembershipCredential) -> Result<(), ProtocolError> {
    cred.check_structure()?;
    signing::verify_input(
        Context::Membership,
        &cred.issuer_key,
        &cred.signing_input()?,
        &cred.signature,
    )
}

/// Fully verifies a credential at `now`: roles and scopes valid and bounded,
/// `circle_id == derive(issuer_key)`, a valid signature by `issuer_key`, and the time
/// rules of [`UnsignedMembershipCredential::check_time`].
pub fn verify_credential(cred: &MembershipCredential, now: Timestamp) -> Result<(), ProtocolError> {
    verify_credential_signature(cred)?;
    cred.check_time(now)
}

// =======================================================================================
// Acceptance
// =======================================================================================

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceRepr {
    schema: String,
    circle_id: CircleId,
    credential_digest: Digest,
    subject_device_key: DeviceKey,
    accepted_at: Timestamp,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    signature: Option<Signature>,
}

/// The unsigned members of an [`Acceptance`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AcceptanceRepr", into = "AcceptanceRepr")]
pub struct UnsignedAcceptance {
    /// Circle of the accepted credential.
    pub circle_id: CircleId,
    /// Digest of the accepted credential.
    pub credential_digest: Digest,
    /// The subject, who signs the acceptance.
    pub subject_device_key: DeviceKey,
    /// When it was accepted.
    pub accepted_at: Timestamp,
}

/// The subject's signed acceptance of a credential. A credential is active only with a
/// matching acceptance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AcceptanceRepr", into = "AcceptanceRepr")]
pub struct Acceptance {
    /// The signed members.
    pub unsigned: UnsignedAcceptance,
    /// Signature by `subject_device_key`.
    pub signature: Signature,
}

signed_wrapper!(Acceptance, UnsignedAcceptance);

impl From<UnsignedAcceptance> for AcceptanceRepr {
    fn from(u: UnsignedAcceptance) -> Self {
        AcceptanceRepr {
            schema: Context::Acceptance.schema().to_owned(),
            circle_id: u.circle_id,
            credential_digest: u.credential_digest,
            subject_device_key: u.subject_device_key,
            accepted_at: u.accepted_at,
            signature: None,
        }
    }
}

impl From<Acceptance> for AcceptanceRepr {
    fn from(a: Acceptance) -> Self {
        let mut r = AcceptanceRepr::from(a.unsigned);
        r.signature = Some(a.signature);
        r
    }
}

impl AcceptanceRepr {
    fn split(self) -> Result<(UnsignedAcceptance, Option<Signature>), ProtocolError> {
        check_schema_str(&self.schema, Context::Acceptance)?;
        Ok((
            UnsignedAcceptance {
                circle_id: self.circle_id,
                credential_digest: self.credential_digest,
                subject_device_key: self.subject_device_key,
                accepted_at: self.accepted_at,
            },
            self.signature,
        ))
    }
}

impl TryFrom<AcceptanceRepr> for UnsignedAcceptance {
    type Error = ProtocolError;
    fn try_from(r: AcceptanceRepr) -> Result<Self, ProtocolError> {
        match r.split()? {
            (u, None) => Ok(u),
            _ => Err(ProtocolError::Schema {
                object: "acceptance",
            }),
        }
    }
}

impl TryFrom<AcceptanceRepr> for Acceptance {
    type Error = ProtocolError;
    fn try_from(r: AcceptanceRepr) -> Result<Self, ProtocolError> {
        match r.split()? {
            (unsigned, Some(signature)) => Ok(Self {
                unsigned,
                signature,
            }),
            _ => Err(ProtocolError::Schema {
                object: "acceptance",
            }),
        }
    }
}

impl UnsignedAcceptance {
    /// An acceptance of `credential` by its subject at `accepted_at`.
    pub fn for_credential(
        credential: &MembershipCredential,
        accepted_at: Timestamp,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            circle_id: credential.circle_id,
            credential_digest: credential.digest()?,
            subject_device_key: credential.subject_device_key,
            accepted_at,
        })
    }

    /// The unsigned JSON object.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        jcs::to_value(self)
    }

    /// `"peerharness-acceptance-v0\0" || JCS(unsigned)`.
    pub fn signing_input(&self) -> Result<Vec<u8>, ProtocolError> {
        signing::signing_input(Context::Acceptance, &self.to_value()?)
    }

    /// Object digest of the signing input.
    pub fn digest(&self) -> Result<Digest, ProtocolError> {
        Ok(signing::digest_of_input(&self.signing_input()?))
    }

    /// Signs with the subject's device key, which must match `subject_device_key`.
    pub fn sign(self, subject_key: &SigningKey) -> Result<Acceptance, ProtocolError> {
        require_key(
            "signing key and subject_device_key",
            subject_key,
            &self.subject_device_key,
        )?;
        let signature = signing::sign_input(subject_key, &self.signing_input()?);
        Ok(Acceptance {
            unsigned: self,
            signature,
        })
    }
}

impl Acceptance {
    /// Strictly parses a standalone acceptance JSON document (schema only).
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        parse_document(bytes, CREDENTIAL_LIMITS, Context::Acceptance)
    }

    /// The signed JSON object.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        jcs::to_value(self)
    }

    /// The canonical (JCS) JSON text of the signed object.
    pub fn to_canonical_json(&self) -> Result<String, ProtocolError> {
        jcs::to_canonical_string(self)
    }
}

/// Verifies that `acc` accepts `cred` at `now`: [`verify_acceptance_signature`] plus
/// `accepted_at <= now + skew`. Does not verify `cred` itself.
pub fn verify_acceptance(
    acc: &Acceptance,
    cred: &MembershipCredential,
    now: Timestamp,
) -> Result<(), ProtocolError> {
    verify_acceptance_signature(acc, cred)?;
    not_future("acceptance", acc.accepted_at, now)
}

/// Verifies that `acc` accepts `cred`, without time rules (for acceptances loaded from
/// local storage): same subject and circle, `credential_digest == cred.digest()`, and a
/// valid signature by `cred.subject_device_key`. Does not verify `cred` itself.
pub fn verify_acceptance_signature(
    acc: &Acceptance,
    cred: &MembershipCredential,
) -> Result<(), ProtocolError> {
    if acc.subject_device_key != cred.subject_device_key {
        return Err(ProtocolError::Mismatch {
            what: "acceptance subject",
        });
    }
    if acc.circle_id != cred.circle_id {
        return Err(ProtocolError::Mismatch {
            what: "acceptance circle_id",
        });
    }
    if acc.credential_digest != cred.digest()? {
        return Err(ProtocolError::Mismatch {
            what: "acceptance credential_digest",
        });
    }
    signing::verify_input(
        Context::Acceptance,
        &acc.subject_device_key,
        &acc.signing_input()?,
        &acc.signature,
    )
}

/// A credential together with its acceptance, as carried in MEMBERSHIP events and in
/// `Authenticate` / `Authenticated` wire messages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipProof {
    /// The credential.
    pub credential: MembershipCredential,
    /// The subject's acceptance of it.
    pub acceptance: Acceptance,
}

/// [`verify_credential`] followed by [`verify_acceptance`].
pub fn verify_membership_proof(
    proof: &MembershipProof,
    now: Timestamp,
) -> Result<(), ProtocolError> {
    verify_credential(&proof.credential, now)?;
    verify_acceptance(&proof.acceptance, &proof.credential, now)
}

// =======================================================================================
// Revocation
// =======================================================================================

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationRepr {
    schema: String,
    circle_id: CircleId,
    subject_device_key: DeviceKey,
    revoked_at: Timestamp,
    reason: String,
    issuer_key: DeviceKey,
    nonce: Nonce,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    signature: Option<Signature>,
}

/// The unsigned members of a [`Revocation`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RevocationRepr", into = "RevocationRepr")]
pub struct UnsignedRevocation {
    /// Circle; must equal `CircleId::derive(issuer_key)`.
    pub circle_id: CircleId,
    /// The revoked device key.
    pub subject_device_key: DeviceKey,
    /// When it was revoked.
    pub revoked_at: Timestamp,
    /// Human-readable reason (0-200 characters, single line).
    pub reason: String,
    /// The circle root key.
    pub issuer_key: DeviceKey,
    /// Random nonce.
    pub nonce: Nonce,
}

/// A signed revocation of a device key from a circle. Revocations do not expire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RevocationRepr", into = "RevocationRepr")]
pub struct Revocation {
    /// The signed members.
    pub unsigned: UnsignedRevocation,
    /// Signature by `issuer_key`.
    pub signature: Signature,
}

signed_wrapper!(Revocation, UnsignedRevocation);

impl From<UnsignedRevocation> for RevocationRepr {
    fn from(u: UnsignedRevocation) -> Self {
        RevocationRepr {
            schema: Context::Revocation.schema().to_owned(),
            circle_id: u.circle_id,
            subject_device_key: u.subject_device_key,
            revoked_at: u.revoked_at,
            reason: u.reason,
            issuer_key: u.issuer_key,
            nonce: u.nonce,
            signature: None,
        }
    }
}

impl From<Revocation> for RevocationRepr {
    fn from(r: Revocation) -> Self {
        let mut repr = RevocationRepr::from(r.unsigned);
        repr.signature = Some(r.signature);
        repr
    }
}

impl RevocationRepr {
    fn split(self) -> Result<(UnsignedRevocation, Option<Signature>), ProtocolError> {
        check_schema_str(&self.schema, Context::Revocation)?;
        Ok((
            UnsignedRevocation {
                circle_id: self.circle_id,
                subject_device_key: self.subject_device_key,
                revoked_at: self.revoked_at,
                reason: self.reason,
                issuer_key: self.issuer_key,
                nonce: self.nonce,
            },
            self.signature,
        ))
    }
}

impl TryFrom<RevocationRepr> for UnsignedRevocation {
    type Error = ProtocolError;
    fn try_from(r: RevocationRepr) -> Result<Self, ProtocolError> {
        match r.split()? {
            (u, None) => Ok(u),
            _ => Err(ProtocolError::Schema {
                object: "revocation",
            }),
        }
    }
}

impl TryFrom<RevocationRepr> for Revocation {
    type Error = ProtocolError;
    fn try_from(r: RevocationRepr) -> Result<Self, ProtocolError> {
        match r.split()? {
            (unsigned, Some(signature)) => Ok(Self {
                unsigned,
                signature,
            }),
            _ => Err(ProtocolError::Schema {
                object: "revocation",
            }),
        }
    }
}

impl std::fmt::Debug for UnsignedRevocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnsignedRevocation")
            .field("circle_id", &self.circle_id)
            .field("subject_device_key", &self.subject_device_key)
            .field("revoked_at", &self.revoked_at)
            .field("reason_len", &self.reason.len())
            .field("issuer_key", &self.issuer_key)
            .field("nonce", &self.nonce)
            .finish()
    }
}

impl UnsignedRevocation {
    /// Builds a revocation issued by `issuer_key`, deriving `circle_id` from it.
    pub fn new(
        issuer_key: DeviceKey,
        subject_device_key: DeviceKey,
        revoked_at: Timestamp,
        reason: String,
        nonce: Nonce,
    ) -> Self {
        Self {
            circle_id: CircleId::derive(&issuer_key),
            subject_device_key,
            revoked_at,
            reason,
            issuer_key,
            nonce,
        }
    }

    /// The unsigned JSON object.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        jcs::to_value(self)
    }

    /// `"peerharness-revocation-v0\0" || JCS(unsigned)`.
    pub fn signing_input(&self) -> Result<Vec<u8>, ProtocolError> {
        signing::signing_input(Context::Revocation, &self.to_value()?)
    }

    /// Object digest of the signing input.
    pub fn digest(&self) -> Result<Digest, ProtocolError> {
        Ok(signing::digest_of_input(&self.signing_input()?))
    }

    /// Checks `reason` bounds, the circle/issuer binding, and that the subject is not
    /// the issuer: the circle root holds no credential and cannot be revoked in v0 (a
    /// compromised root means a new circle), so a root self-revocation is malformed.
    /// Revoking the founder's **device** key (a different key) is allowed.
    pub fn check_structure(&self) -> Result<(), ProtocolError> {
        check_text(
            "reason",
            &self.reason,
            0,
            limits::text::REVOCATION_REASON,
            Lines::Single,
        )?;
        if !self.circle_id.is_derived_from(&self.issuer_key) {
            return Err(ProtocolError::Mismatch {
                what: "revocation circle_id and issuer_key",
            });
        }
        if self.subject_device_key == self.issuer_key {
            return Err(ProtocolError::field(
                "subject_device_key",
                "the circle root cannot revoke itself",
            ));
        }
        Ok(())
    }

    /// Signs with the circle root key, which must match `issuer_key`.
    pub fn sign(self, root_key: &SigningKey) -> Result<Revocation, ProtocolError> {
        require_key("signing key and issuer_key", root_key, &self.issuer_key)?;
        self.check_structure()?;
        let signature = signing::sign_input(root_key, &self.signing_input()?);
        Ok(Revocation {
            unsigned: self,
            signature,
        })
    }
}

impl Revocation {
    /// Strictly parses a standalone revocation JSON document (schema only).
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        parse_document(bytes, CREDENTIAL_LIMITS, Context::Revocation)
    }

    /// The signed JSON object.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        jcs::to_value(self)
    }

    /// The canonical (JCS) JSON text of the signed object.
    pub fn to_canonical_json(&self) -> Result<String, ProtocolError> {
        jcs::to_canonical_string(self)
    }
}

/// Checks a revocation's structure and signature, without time rules (for revocations
/// loaded from local storage): `reason` bounded, `circle_id == derive(issuer_key)`,
/// `subject_device_key != issuer_key` (the root cannot revoke itself), and a valid
/// signature by `issuer_key`.
pub fn verify_revocation_signature(rev: &Revocation) -> Result<(), ProtocolError> {
    rev.check_structure()?;
    signing::verify_input(
        Context::Revocation,
        &rev.issuer_key,
        &rev.signing_input()?,
        &rev.signature,
    )
}

/// Verifies a revocation at `now`: [`verify_revocation_signature`] plus
/// `revoked_at <= now + skew`.
pub fn verify_revocation(rev: &Revocation, now: Timestamp) -> Result<(), ProtocolError> {
    verify_revocation_signature(rev)?;
    not_future("revocation", rev.revoked_at, now)
}

// =======================================================================================
// Invite
// =======================================================================================

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteRepr {
    schema: String,
    circle_name: String,
    circle_root_key: DeviceKey,
    credential: MembershipCredential,
    issuer_device_key: DeviceKey,
    issuer_addrs: Vec<String>,
    invite_expires_at: Timestamp,
    nonce: Nonce,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    signature: Option<Signature>,
}

/// The unsigned members of an [`Invite`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "InviteRepr", into = "InviteRepr")]
pub struct UnsignedInvite {
    /// Local label shown to the invitee (1-64 characters, single line).
    pub circle_name: String,
    /// The circle root key, which signs the invite.
    pub circle_root_key: DeviceKey,
    /// The credential for the invitee, issued by `circle_root_key`.
    pub credential: MembershipCredential,
    /// Device key of the inviting node (to dial and authenticate).
    pub issuer_device_key: DeviceKey,
    /// Multiaddrs of the inviting node (at most 8, each at most 256 bytes). Kept as
    /// strings here; `ph-network` parses them.
    pub issuer_addrs: Vec<String>,
    /// Invite expiry (default 24 h after creation).
    pub invite_expires_at: Timestamp,
    /// Random nonce.
    pub nonce: Nonce,
}

/// An invitation file: a credential for the invitee plus how to reach the issuer,
/// signed by the circle root key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "InviteRepr", into = "InviteRepr")]
pub struct Invite {
    /// The signed members.
    pub unsigned: UnsignedInvite,
    /// Signature by `circle_root_key`.
    pub signature: Signature,
}

signed_wrapper!(Invite, UnsignedInvite);

impl From<UnsignedInvite> for InviteRepr {
    fn from(u: UnsignedInvite) -> Self {
        InviteRepr {
            schema: Context::Invite.schema().to_owned(),
            circle_name: u.circle_name,
            circle_root_key: u.circle_root_key,
            credential: u.credential,
            issuer_device_key: u.issuer_device_key,
            issuer_addrs: u.issuer_addrs,
            invite_expires_at: u.invite_expires_at,
            nonce: u.nonce,
            signature: None,
        }
    }
}

impl From<Invite> for InviteRepr {
    fn from(i: Invite) -> Self {
        let mut r = InviteRepr::from(i.unsigned);
        r.signature = Some(i.signature);
        r
    }
}

impl InviteRepr {
    fn split(self) -> Result<(UnsignedInvite, Option<Signature>), ProtocolError> {
        check_schema_str(&self.schema, Context::Invite)?;
        Ok((
            UnsignedInvite {
                circle_name: self.circle_name,
                circle_root_key: self.circle_root_key,
                credential: self.credential,
                issuer_device_key: self.issuer_device_key,
                issuer_addrs: self.issuer_addrs,
                invite_expires_at: self.invite_expires_at,
                nonce: self.nonce,
            },
            self.signature,
        ))
    }
}

impl TryFrom<InviteRepr> for UnsignedInvite {
    type Error = ProtocolError;
    fn try_from(r: InviteRepr) -> Result<Self, ProtocolError> {
        match r.split()? {
            (u, None) => Ok(u),
            _ => Err(ProtocolError::Schema { object: "invite" }),
        }
    }
}

impl TryFrom<InviteRepr> for Invite {
    type Error = ProtocolError;
    fn try_from(r: InviteRepr) -> Result<Self, ProtocolError> {
        match r.split()? {
            (unsigned, Some(signature)) => Ok(Self {
                unsigned,
                signature,
            }),
            _ => Err(ProtocolError::Schema { object: "invite" }),
        }
    }
}

/// Checks a list of multiaddr strings: at most 8, each 1-256 bytes of printable,
/// non-whitespace ASCII.
pub fn check_addrs(field: &'static str, addrs: &[String]) -> Result<(), ProtocolError> {
    if addrs.len() > MAX_ADDRS {
        return Err(ProtocolError::field(field, "too many addresses"));
    }
    for a in addrs {
        if a.is_empty() || a.len() > MAX_ADDR_BYTES {
            return Err(ProtocolError::field(field, "address length out of bounds"));
        }
        if !a.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ProtocolError::field(
                field,
                "address must be printable ASCII",
            ));
        }
    }
    Ok(())
}

impl std::fmt::Debug for UnsignedInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnsignedInvite")
            .field("circle_name_len", &self.circle_name.len())
            .field("circle_root_key", &self.circle_root_key)
            .field("credential", &self.credential)
            .field("issuer_device_key", &self.issuer_device_key)
            .field("issuer_addrs_count", &self.issuer_addrs.len())
            .field("invite_expires_at", &self.invite_expires_at)
            .field("nonce", &self.nonce)
            .finish()
    }
}

impl UnsignedInvite {
    /// The unsigned JSON object.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        jcs::to_value(self)
    }

    /// `"peerharness-invite-v0\0" || JCS(unsigned)`.
    pub fn signing_input(&self) -> Result<Vec<u8>, ProtocolError> {
        signing::signing_input(Context::Invite, &self.to_value()?)
    }

    /// Object digest of the signing input.
    pub fn digest(&self) -> Result<Digest, ProtocolError> {
        Ok(signing::digest_of_input(&self.signing_input()?))
    }

    /// Checks name and address bounds and that the credential was issued by
    /// `circle_root_key`.
    pub fn check_structure(&self) -> Result<(), ProtocolError> {
        check_text(
            "circle_name",
            &self.circle_name,
            1,
            limits::text::CIRCLE_NAME,
            Lines::Single,
        )?;
        check_addrs("issuer_addrs", &self.issuer_addrs)?;
        if self.credential.issuer_key != self.circle_root_key {
            return Err(ProtocolError::Mismatch {
                what: "invite credential issuer_key and circle_root_key",
            });
        }
        Ok(())
    }

    /// Signs with the circle root key, which must match `circle_root_key`.
    pub fn sign(self, root_key: &SigningKey) -> Result<Invite, ProtocolError> {
        require_key(
            "signing key and circle_root_key",
            root_key,
            &self.circle_root_key,
        )?;
        self.check_structure()?;
        let signature = signing::sign_input(root_key, &self.signing_input()?);
        Ok(Invite {
            unsigned: self,
            signature,
        })
    }
}

impl Invite {
    /// Strictly parses an invite file (schema only).
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        parse_document(bytes, CREDENTIAL_LIMITS, Context::Invite)
    }

    /// The signed JSON object.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        jcs::to_value(self)
    }

    /// The canonical (JCS) JSON text of the signed object.
    pub fn to_canonical_json(&self) -> Result<String, ProtocolError> {
        jcs::to_canonical_string(self)
    }

    /// The circle this invite is for.
    pub fn circle_id(&self) -> CircleId {
        CircleId::derive(&self.circle_root_key)
    }

    /// Fingerprint of the root key, to compare out of band before joining.
    pub fn root_fingerprint(&self) -> String {
        self.circle_root_key.fingerprint()
    }
}

/// Verifies an invite at `now`: bounds, a valid signature by `circle_root_key`,
/// `credential.issuer_key == circle_root_key`, the credential verifies
/// ([`verify_credential`]), and `invite_expires_at > now`.
///
/// This does **not** check that the credential is for you; use
/// [`verify_invite_for_subject`] when joining.
pub fn verify_invite(inv: &Invite, now: Timestamp) -> Result<(), ProtocolError> {
    inv.check_structure()?;
    signing::verify_input(
        Context::Invite,
        &inv.circle_root_key,
        &inv.signing_input()?,
        &inv.signature,
    )?;
    verify_credential(&inv.credential, now)?;
    if inv.invite_expires_at <= now {
        return Err(ProtocolError::Time {
            object: "invite",
            rule: TimeRule::Expired,
        });
    }
    Ok(())
}

/// [`verify_invite`] plus `credential.subject_device_key == subject`.
pub fn verify_invite_for_subject(
    inv: &Invite,
    subject: &DeviceKey,
    now: Timestamp,
) -> Result<(), ProtocolError> {
    verify_invite(inv, now)?;
    if inv.credential.subject_device_key != *subject {
        return Err(ProtocolError::Mismatch {
            what: "invite credential subject",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::lifetimes;

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn pk(seed: u8) -> DeviceKey {
        DeviceKey::from_signing_key(&sk(seed))
    }
    fn t0() -> Timestamp {
        "2026-11-09T18:00:00Z".parse().unwrap()
    }

    fn cred(subject: u8) -> MembershipCredential {
        UnsignedMembershipCredential::new(
            pk(2),
            pk(subject),
            vec![Role::Member],
            vec![Scope::new("team/backend").unwrap()],
            t0(),
            t0().plus_secs(lifetimes::CREDENTIAL_SECS),
        )
        .sign(&sk(2))
        .unwrap()
    }

    #[test]
    fn credential_roundtrip_and_verify() {
        let c = cred(1);
        verify_credential(&c, t0()).unwrap();
        let json = c.to_canonical_json().unwrap();
        assert!(json.starts_with("{\"circle_id\":"));
        assert!(json.contains("\"schema\":\"peerharness.membership/0.1\""));
        let back = MembershipCredential::from_json_bytes(json.as_bytes()).unwrap();
        assert_eq!(back, c);
        // unsigned form refuses a signature member and vice versa
        assert!(serde_json::from_str::<UnsignedMembershipCredential>(&json).is_err());
        let unsigned_json = jcs::to_canonical_string(&c.unsigned).unwrap();
        assert!(MembershipCredential::from_json_bytes(unsigned_json.as_bytes()).is_err());
        assert!(c.grants(
            &Scope::new("team/backend/api").unwrap(),
            ph_core::Capability::Vote
        ));
        assert!(!c.grants(
            &Scope::new("team/finance").unwrap(),
            ph_core::Capability::Vote
        ));
        assert!(!c.grants(
            &Scope::new("team/backend").unwrap(),
            ph_core::Capability::Revoke
        ));
    }

    #[test]
    fn credential_negative() {
        let c = cred(1);
        // expired / future
        assert!(matches!(
            verify_credential(&c, c.expires_at),
            Err(ProtocolError::Time {
                rule: TimeRule::Expired,
                ..
            })
        ));
        assert!(matches!(
            verify_credential(&c, t0().minus_secs(CLOCK_SKEW_SECS + 1)),
            Err(ProtocolError::Time {
                rule: TimeRule::FutureDated,
                ..
            })
        ));
        assert!(verify_credential(&c, t0().minus_secs(CLOCK_SKEW_SECS)).is_ok());
        // tampered scope
        let mut m = c.clone();
        m.unsigned.scopes = vec![Scope::all()];
        assert!(matches!(
            verify_credential(&m, t0()),
            Err(ProtocolError::BadSignature { .. })
        ));
        // forged signature
        let mut m = c.clone();
        m.signature = Signature::from_bytes([0u8; 64]);
        assert!(verify_credential(&m, t0()).is_err());
        // signed by a non-root key claiming to be root of the root's circle
        let forged = UnsignedMembershipCredential {
            issuer_key: pk(3),
            ..c.unsigned.clone()
        };
        assert!(forged.clone().sign(&sk(3)).is_err()); // circle mismatch caught at sign
                                                       // wrong signing key
        assert!(c.unsigned.clone().sign(&sk(3)).is_err());
        // bounds
        let mut u = c.unsigned.clone();
        u.roles = vec![];
        assert!(u.sign(&sk(2)).is_err());
        let mut u = c.unsigned.clone();
        u.roles = vec![Role::Member, Role::Member];
        assert!(u.sign(&sk(2)).is_err());
        let mut u = c.unsigned.clone();
        u.scopes = (0..17)
            .map(|i| Scope::new(&format!("s{i}")).unwrap())
            .collect();
        assert!(u.sign(&sk(2)).is_err());
        let mut u = c.unsigned.clone();
        u.expires_at = u.issued_at.plus_days(401);
        let long = u.sign(&sk(2)).unwrap();
        assert!(matches!(
            verify_credential(&long, t0()),
            Err(ProtocolError::Time {
                rule: TimeRule::LifetimeTooLong,
                ..
            })
        ));
        // unknown role / unknown field
        let mut v = c.to_value().unwrap();
        v["roles"] = serde_json::json!(["admin"]);
        assert!(MembershipCredential::from_json_bytes(v.to_string().as_bytes()).is_err());
        let mut v = c.to_value().unwrap();
        v["extra"] = serde_json::json!(1);
        assert!(matches!(
            MembershipCredential::from_json_bytes(v.to_string().as_bytes()),
            Err(ProtocolError::Schema { .. })
        ));
        let mut v = c.to_value().unwrap();
        v["schema"] = serde_json::json!("peerharness.membership/0.2");
        assert!(matches!(
            MembershipCredential::from_json_bytes(v.to_string().as_bytes()),
            Err(ProtocolError::UnsupportedSchema { .. })
        ));
    }

    #[test]
    fn acceptance() {
        let c = cred(1);
        let a = UnsignedAcceptance::for_credential(&c, t0().plus_secs(60))
            .unwrap()
            .sign(&sk(1))
            .unwrap();
        verify_acceptance(&a, &c, t0().plus_secs(60)).unwrap();
        let proof = MembershipProof {
            credential: c.clone(),
            acceptance: a.clone(),
        };
        verify_membership_proof(&proof, t0().plus_secs(60)).unwrap();
        // only the subject can sign
        assert!(UnsignedAcceptance::for_credential(&c, t0())
            .unwrap()
            .sign(&sk(3))
            .is_err());
        // acceptance for another credential
        let other = cred(3);
        assert!(verify_acceptance(&a, &other, t0()).is_err());
        let mut different_scopes = c.unsigned.clone();
        different_scopes.scopes = vec![Scope::all()];
        let c2 = different_scopes.sign(&sk(2)).unwrap();
        assert!(matches!(
            verify_acceptance(&a, &c2, t0().plus_secs(60)),
            Err(ProtocolError::Mismatch { .. })
        ));
        // tampered
        let mut m = a.clone();
        m.unsigned.accepted_at = t0();
        assert!(verify_acceptance(&m, &c, t0()).is_err());
        assert!(verify_acceptance_signature(&m, &c).is_err());
        assert!(verify_acceptance_signature(&a, &other).is_err());
        // the signature-only check ignores time; the full check does not
        verify_acceptance_signature(&a, &c).unwrap();
        assert!(verify_acceptance(&a, &c, t0().minus_secs(3600)).is_err());
        assert_eq!(
            Acceptance::from_json_bytes(a.to_canonical_json().unwrap().as_bytes()).unwrap(),
            a
        );
    }

    #[test]
    fn revocation() {
        let r = UnsignedRevocation::new(
            pk(2),
            pk(1),
            t0(),
            "left the team".into(),
            Nonce::from_bytes([5; 16]),
        )
        .sign(&sk(2))
        .unwrap();
        verify_revocation(&r, t0()).unwrap();
        assert!(verify_revocation(&r, t0().minus_secs(301)).is_err());
        // a member cannot revoke
        let fake = UnsignedRevocation::new(
            pk(1),
            pk(3),
            t0(),
            String::new(),
            Nonce::from_bytes([5; 16]),
        );
        let fake = UnsignedRevocation {
            circle_id: r.circle_id,
            ..fake
        };
        assert!(fake.clone().sign(&sk(1)).is_err());
        let mut m = r.clone();
        m.unsigned.reason = "x".repeat(201);
        assert!(verify_revocation(&m, t0()).is_err());
        let mut m = r.clone();
        m.unsigned.subject_device_key = pk(3);
        assert!(verify_revocation(&m, t0()).is_err());
        assert!(verify_revocation_signature(&m).is_err());
        assert_eq!(
            Revocation::from_json_bytes(r.to_canonical_json().unwrap().as_bytes()).unwrap(),
            r
        );
        // The signature-only check ignores time; the full check does not.
        verify_revocation_signature(&r).unwrap();
        let future = UnsignedRevocation::new(
            pk(2),
            pk(1),
            t0().plus_days(30),
            String::new(),
            Nonce::from_bytes([7; 16]),
        )
        .sign(&sk(2))
        .unwrap();
        verify_revocation_signature(&future).unwrap();
        assert!(verify_revocation(&future, t0()).is_err());
    }

    #[test]
    fn root_cannot_revoke_itself() {
        let u = UnsignedRevocation::new(
            pk(2),
            pk(2),
            t0(),
            String::new(),
            Nonce::from_bytes([8; 16]),
        );
        // Signing refuses it ...
        assert!(matches!(
            u.clone().sign(&sk(2)),
            Err(ProtocolError::Field {
                field: "subject_device_key",
                ..
            })
        ));
        // ... and a hand-signed one never verifies, with or without time rules.
        let signature = signing::sign_input(&sk(2), &u.signing_input().unwrap());
        let r = Revocation {
            unsigned: u,
            signature,
        };
        assert!(verify_revocation_signature(&r).is_err());
        assert!(verify_revocation(&r, t0()).is_err());
        // It still parses (schema only), so the stateless event validation must catch it.
        assert_eq!(
            Revocation::from_json_bytes(r.to_canonical_json().unwrap().as_bytes()).unwrap(),
            r
        );
    }

    fn invite() -> Invite {
        UnsignedInvite {
            circle_name: "acme".into(),
            circle_root_key: pk(2),
            credential: cred(1),
            issuer_device_key: pk(4),
            issuer_addrs: vec!["/ip4/127.0.0.1/udp/4001/quic-v1".into()],
            invite_expires_at: t0().plus_secs(lifetimes::INVITE_SECS),
            nonce: Nonce::from_bytes([6; 16]),
        }
        .sign(&sk(2))
        .unwrap()
    }

    #[test]
    fn invites() {
        let i = invite();
        verify_invite(&i, t0()).unwrap();
        verify_invite_for_subject(&i, &pk(1), t0()).unwrap();
        assert!(verify_invite_for_subject(&i, &pk(3), t0()).is_err());
        assert!(matches!(
            verify_invite(&i, i.invite_expires_at),
            Err(ProtocolError::Time {
                rule: TimeRule::Expired,
                ..
            })
        ));
        assert_eq!(i.circle_id(), CircleId::derive(&pk(2)));
        assert_eq!(i.root_fingerprint().len(), 24);
        // not signed by root
        let mut m = i.clone();
        m.unsigned
            .issuer_addrs
            .push("/ip4/10.0.0.1/udp/1/quic-v1".into());
        assert!(matches!(
            verify_invite(&m, t0()),
            Err(ProtocolError::BadSignature { .. })
        ));
        // bounds
        let mut u = i.unsigned.clone();
        u.issuer_addrs = vec!["/a".into(); 9];
        assert!(u.sign(&sk(2)).is_err());
        let mut u = i.unsigned.clone();
        u.issuer_addrs = vec!["x".repeat(257)];
        assert!(u.sign(&sk(2)).is_err());
        let mut u = i.unsigned.clone();
        u.issuer_addrs = vec!["/ip4/1.2.3.4 /udp".into()];
        assert!(u.sign(&sk(2)).is_err());
        let mut u = i.unsigned.clone();
        u.circle_name = String::new();
        assert!(u.sign(&sk(2)).is_err());
        let mut u = i.unsigned.clone();
        u.circle_name = "a\u{1b}[2J".into();
        assert!(u.sign(&sk(2)).is_err());
        // credential from a different root
        let other_root = UnsignedMembershipCredential::new(
            pk(5),
            pk(1),
            vec![Role::Member],
            vec![Scope::all()],
            t0(),
            t0().plus_days(30),
        )
        .sign(&sk(5))
        .unwrap();
        let mut u = i.unsigned.clone();
        u.credential = other_root;
        assert!(u.sign(&sk(2)).is_err());
        let bytes = i.to_canonical_json().unwrap();
        assert_eq!(Invite::from_json_bytes(bytes.as_bytes()).unwrap(), i);
    }
}
