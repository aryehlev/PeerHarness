//! The [`MembershipOracle`] trait: the authorization question every crate asks.
//!
//! `ph-identity` provides the real implementation (`MembershipRegistry`), backed by
//! verified credentials, acceptances and revocations. Other crates (governance,
//! the network request handler) depend only on this trait.

use std::fmt;

use crate::encoding::{CircleId, DeviceKey};
use crate::role::Capability;
use crate::scope::Scope;
use crate::timestamp::Timestamp;

/// Why an authorization request was denied.
///
/// The variant is for local diagnostics and tests. **`Display` is deliberately the same
/// generic text for every variant**, so a denial reported to a peer never reveals whether
/// a circle exists, whether a key was ever a member, or which check failed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DenyReason {
    /// No credential for this key in this circle.
    NotMember,
    /// The credential has expired (or is not yet valid).
    Expired,
    /// The key has been revoked.
    Revoked,
    /// None of the credential's scopes covers the requested scope.
    ScopeDenied,
    /// None of the credential's roles grants the requested capability.
    CapabilityDenied,
    /// A credential exists but no matching acceptance signed by the subject.
    NotAccepted,
}

impl DenyReason {
    /// A stable machine-readable code for local logs (never sent to peers).
    pub const fn code(self) -> &'static str {
        match self {
            DenyReason::NotMember => "not_member",
            DenyReason::Expired => "expired",
            DenyReason::Revoked => "revoked",
            DenyReason::ScopeDenied => "scope_denied",
            DenyReason::CapabilityDenied => "capability_denied",
            DenyReason::NotAccepted => "not_accepted",
        }
    }
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not authorized")
    }
}

impl std::error::Error for DenyReason {}

/// Answers "may `key` do `cap` on `scope` in `circle` at time `now`?".
///
/// Implementations must evaluate the latest local state on **every** call (expiry and
/// revocations), never a cached decision, and must treat a credential as active only
/// when a matching acceptance signed by the subject exists (architecture section 6).
/// `now` is the local clock, never a remote timestamp.
pub trait MembershipOracle: Send + Sync {
    /// `Ok(())` iff `key` holds an active, unexpired, unrevoked, accepted credential for
    /// `circle` whose scopes cover `scope` and whose roles grant `cap`.
    fn authorize(
        &self,
        circle: &CircleId,
        key: &DeviceKey,
        scope: &Scope,
        cap: Capability,
        now: Timestamp,
    ) -> Result<(), DenyReason>;

    /// Whether `key` holds any active (accepted, unexpired, unrevoked) credential for
    /// `circle`, regardless of scope and capability.
    fn is_active_member(&self, circle: &CircleId, key: &DeviceKey, now: Timestamp) -> bool;

    /// Shorthand for `authorize(.., Capability::Read, ..)`.
    fn authorize_read(
        &self,
        circle: &CircleId,
        key: &DeviceKey,
        scope: &Scope,
        now: Timestamp,
    ) -> Result<(), DenyReason> {
        self.authorize(circle, key, scope, Capability::Read, now)
    }
}

/// An oracle that denies everything with [`DenyReason::NotMember`]. Useful as a safe
/// default and in tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAllOracle;

impl MembershipOracle for DenyAllOracle {
    fn authorize(
        &self,
        _circle: &CircleId,
        _key: &DeviceKey,
        _scope: &Scope,
        _cap: Capability,
        _now: Timestamp,
    ) -> Result<(), DenyReason> {
        Err(DenyReason::NotMember)
    }

    fn is_active_member(&self, _circle: &CircleId, _key: &DeviceKey, _now: Timestamp) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_generic() {
        let all = [
            DenyReason::NotMember,
            DenyReason::Expired,
            DenyReason::Revoked,
            DenyReason::ScopeDenied,
            DenyReason::CapabilityDenied,
            DenyReason::NotAccepted,
        ];
        for r in all {
            assert_eq!(r.to_string(), "not authorized");
        }
        let codes: std::collections::HashSet<_> = all.iter().map(|r| r.code()).collect();
        assert_eq!(codes.len(), all.len());
    }

    #[test]
    fn deny_all() {
        let key = DeviceKey::from_signing_key(&ed25519_dalek::SigningKey::from_bytes(&[1; 32]));
        let circle = CircleId::derive(&key);
        let now = Timestamp::now();
        let o: &dyn MembershipOracle = &DenyAllOracle;
        assert_eq!(
            o.authorize_read(&circle, &key, &Scope::all(), now),
            Err(DenyReason::NotMember)
        );
        assert!(!o.is_active_member(&circle, &key, now));
    }
}
