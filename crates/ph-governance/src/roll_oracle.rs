//! Membership as the charter states it: a device on the current roll of a circle.
//!
//! [`RollOracle`] answers the questions the transport asks about a peer (may it connect,
//! read, fetch) from the one membership statement every member has verified and voted
//! on. The roll changes only by an amendment that passed, so:
//!
//! * nobody gets read access to a circle without a vote, not even from the founder
//!   (whose root key can sign a credential but cannot put anyone on the roll);
//! * membership has no expiry to renew, so a circle whose founder is gone keeps
//!   exchanging its records;
//! * a member removed by vote loses access on every node as soon as that node has
//!   accepted the new charter.
//!
//! A locally known revocation of a device still denies it, so a stolen device can be cut
//! off before the roll is amended.
//!
//! The oracle is a snapshot. Build it from the store for each request and never keep it
//! across requests: authorization is evaluated at the time of use.

use std::collections::{HashMap, HashSet};

use ph_core::{
    roles_grant, Capability, CircleId, DenyReason, DeviceKey, MembershipOracle, Role, Scope,
    Timestamp,
};
use ph_protocol::Charter;

/// What every member on a roll may do. The roll has no roles: one member, one vote.
const MEMBER: &[Role] = &[Role::Member];

/// A [`MembershipOracle`] backed by the current charter of each circle.
#[derive(Clone, Debug, Default)]
pub struct RollOracle {
    charters: HashMap<CircleId, Charter>,
    revoked: HashSet<(CircleId, DeviceKey)>,
}

impl RollOracle {
    /// An oracle that knows no circle and denies everything.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the current charter of its circle. The caller passes a charter it has
    /// accepted (the store's current charter); nothing is verified here.
    pub fn set_charter(&mut self, charter: Charter) {
        self.charters.insert(charter.circle_id, charter);
    }

    /// Records a locally known revocation of `device` in `circle`.
    pub fn revoke(&mut self, circle: CircleId, device: DeviceKey) {
        self.revoked.insert((circle, device));
    }

    /// The circles in which both `a` and `b` are active members.
    pub fn shared_circles(&self, a: &DeviceKey, b: &DeviceKey) -> Vec<CircleId> {
        let mut out: Vec<CircleId> = self
            .charters
            .keys()
            .filter(|c| self.active(c, a) && self.active(c, b))
            .copied()
            .collect();
        out.sort_by_key(CircleId::to_string);
        out
    }

    fn active(&self, circle: &CircleId, key: &DeviceKey) -> bool {
        !self.revoked.contains(&(*circle, *key))
            && self
                .charters
                .get(circle)
                .is_some_and(|c| c.content.member_of(key).is_some())
    }
}

impl MembershipOracle for RollOracle {
    fn authorize(
        &self,
        circle: &CircleId,
        key: &DeviceKey,
        scope: &Scope,
        cap: Capability,
        _now: Timestamp,
    ) -> Result<(), DenyReason> {
        // An unknown circle and a device that is not on the roll look the same.
        let charter = self.charters.get(circle).ok_or(DenyReason::NotMember)?;
        if self.revoked.contains(&(*circle, *key)) {
            return Err(DenyReason::Revoked);
        }
        let entry = charter
            .content
            .member_of(key)
            .ok_or(DenyReason::NotMember)?;
        if !roles_grant(MEMBER, cap) {
            return Err(DenyReason::CapabilityDenied);
        }
        if !entry.covers(scope) {
            return Err(DenyReason::ScopeDenied);
        }
        Ok(())
    }

    fn is_active_member(&self, circle: &CircleId, key: &DeviceKey, _now: Timestamp) -> bool {
        self.active(circle, key)
    }

    fn is_revoked(&self, circle: &CircleId, key: &DeviceKey) -> bool {
        self.revoked.contains(&(*circle, *key))
    }
}
