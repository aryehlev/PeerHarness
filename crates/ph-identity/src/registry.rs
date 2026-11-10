//! [`MembershipRegistry`]: the in-memory membership view that implements
//! [`ph_core::MembershipOracle`].
//!
//! The registry is built from known circle roots, verified [`MembershipProof`]s
//! (credential plus the subject's acceptance) and verified [`Revocation`]s. The daemon
//! loads it from the store at startup (`circles` via `add_circle`, `memberships` rows
//! with an acceptance via `add_stored_proof`, `revocations` via `add_revocation`) and
//! feeds it every newly received MEMBERSHIP/REVOCATION and every proof presented in
//! `Authenticate` (via `add_proof` / `accept_presented_proofs`). It never caches decisions: each `authorize` call
//! evaluates expiry against the `now` it is given and the current revocation state.
//!
//! ## Revocation semantics (v0)
//!
//! A revocation denies its subject key in that circle **permanently**, regardless of
//! when the subject's credentials were issued (including credentials issued after the
//! revocation). Re-enrolling a revoked person therefore requires a new device key. This
//! keeps revocation monotonic and order-independent across nodes that learn objects in
//! different orders.
//!
//! ## Multiple credentials
//!
//! A key may hold several credentials in one circle (renewals, extra scopes). A request
//! is authorized if **any** active credential grants it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use ph_core::{
    fingerprint, Capability, CircleId, DenyReason, DeviceKey, Digest, MembershipOracle, Role,
    Scope, Timestamp,
};
use ph_protocol::limits::MAX_AUTH_MEMBERSHIPS;
use ph_protocol::{
    verify_acceptance, verify_credential_signature, verify_membership_proof,
    verify_revocation_signature, MembershipProof, Revocation,
};

use crate::error::{MembershipRejection, Result};

/// Whether an add call changed the registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddOutcome {
    /// The object was new and has been recorded.
    Added,
    /// An identical object (same credential digest / same revoked subject / same circle
    /// root) was already present; nothing changed.
    Duplicate,
}

/// One member of a circle as shown by `circle members`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberView {
    /// The member's device key.
    pub key: DeviceKey,
    /// Its human fingerprint.
    pub fingerprint: String,
    /// Union of roles over the member's active credentials (or over all known
    /// credentials if none is active), in `Role::ALL` order.
    pub roles: Vec<Role>,
    /// Union of scopes over the same credentials, sorted.
    pub scopes: Vec<Scope>,
    /// The latest `expires_at` among the member's credentials.
    pub expires_at: Timestamp,
    /// Whether the key is revoked in this circle.
    pub revoked: bool,
    /// Whether the member currently holds an active credential (unexpired, unrevoked).
    pub active: bool,
    /// Number of known credentials for this key in this circle.
    pub credential_count: usize,
}

/// Result of [`MembershipRegistry::accept_presented_proofs`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PresentedOutcome {
    /// Circles in which the presenting peer is now an active member (deduplicated,
    /// sorted). Answer `Authenticated` with our proofs for exactly these circles.
    pub active_circles: Vec<CircleId>,
    /// Number of proofs refused (wrong subject, unknown circle, bad signature, expired).
    pub rejected: usize,
}

#[derive(Debug, Clone)]
struct CircleState {
    root_key: DeviceKey,
    /// Keyed by credential digest.
    proofs: BTreeMap<Digest, MembershipProof>,
    by_subject: BTreeMap<DeviceKey, BTreeSet<Digest>>,
    revocations: BTreeMap<DeviceKey, Revocation>,
    invite_issuers: BTreeSet<DeviceKey>,
}

impl CircleState {
    fn new(root_key: DeviceKey) -> Self {
        Self {
            root_key,
            proofs: BTreeMap::new(),
            by_subject: BTreeMap::new(),
            revocations: BTreeMap::new(),
            invite_issuers: BTreeSet::new(),
        }
    }

    fn subject_proofs<'a>(&'a self, key: &DeviceKey) -> impl Iterator<Item = &'a MembershipProof> {
        self.by_subject
            .get(key)
            .into_iter()
            .flatten()
            .filter_map(|d| self.proofs.get(d))
    }
}

fn is_active(proof: &MembershipProof, now: Timestamp) -> bool {
    proof.credential.check_time(now).is_ok()
}

/// The membership view. See the module docs.
///
/// This type is not internally synchronized; wrap it in [`SharedMembershipRegistry`]
/// (an `Arc<RwLock<_>>` that also implements [`MembershipOracle`]) to share it between
/// the daemon's tasks.
#[derive(Debug, Clone, Default)]
pub struct MembershipRegistry {
    circles: BTreeMap<CircleId, CircleState>,
}

impl MembershipRegistry {
    /// An empty registry (denies everything).
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a circle and its root key. `circle_id` must equal
    /// `CircleId::derive(root_key)`. Re-adding the same pair is a no-op (`Duplicate`).
    pub fn add_circle(&mut self, circle_id: CircleId, root_key: DeviceKey) -> Result<AddOutcome> {
        if !circle_id.is_derived_from(&root_key) {
            return Err(MembershipRejection::CircleRootMismatch.into());
        }
        if let Some(existing) = self.circles.get(&circle_id) {
            // Unreachable for honest input (the id is derived from the key) but cheap.
            if existing.root_key != root_key {
                return Err(MembershipRejection::ConflictingRoot.into());
            }
            return Ok(AddOutcome::Duplicate);
        }
        self.circles.insert(circle_id, CircleState::new(root_key));
        tracing::debug!(circle = %circle_id, "circle registered");
        Ok(AddOutcome::Added)
    }

    /// Forgets a circle and everything recorded for it (leaving a circle). Returns
    /// whether it was known.
    pub fn remove_circle(&mut self, circle_id: &CircleId) -> bool {
        self.circles.remove(circle_id).is_some()
    }

    /// Whether the circle is registered.
    pub fn knows_circle(&self, circle_id: &CircleId) -> bool {
        self.circles.contains_key(circle_id)
    }

    /// All registered circles, sorted.
    pub fn known_circles(&self) -> Vec<CircleId> {
        self.circles.keys().copied().collect()
    }

    /// The root key of a registered circle.
    pub fn root_key(&self, circle_id: &CircleId) -> Option<DeviceKey> {
        self.circles.get(circle_id).map(|c| c.root_key)
    }

    /// Records a membership proof after verifying it at `now`: the credential signature,
    /// structure and time rules, the acceptance (subject signature, digest and circle
    /// binding), that the circle is registered, and that the credential's issuer is the
    /// circle root key.
    ///
    /// Use this for proofs received from the network (MEMBERSHIP events, `Authenticate`).
    /// Proofs that are already expired at `now` are rejected
    /// (`MembershipRejection::InvalidProof`). A proof for a revoked subject is recorded
    /// but never authorizes anything.
    pub fn add_proof(&mut self, proof: MembershipProof, now: Timestamp) -> Result<AddOutcome> {
        let state = self.state_for_issuer(&proof)?;
        verify_membership_proof(&proof, now).map_err(MembershipRejection::InvalidProof)?;
        Self::insert_proof(state, proof)
    }

    /// Records a proof loaded from local storage (daemon startup). It is verified like
    /// [`Self::add_proof`] (signatures, structure, acceptance binding, root issuer,
    /// `expires_at > issued_at`, lifetime at most 400 days, acceptance not future-dated)
    /// **except** that an expired credential is accepted.
    ///
    /// Expired proofs never authorize anything (every [`MembershipOracle`] call checks
    /// expiry at its own `now`), but keeping them lets [`Self::members`] show expired
    /// members and lets [`Self::is_plausible_member`] recognize a peer that may since
    /// have renewed, exactly as before a restart.
    pub fn add_stored_proof(
        &mut self,
        proof: MembershipProof,
        now: Timestamp,
    ) -> Result<AddOutcome> {
        let state = self.state_for_issuer(&proof)?;
        let cred = &proof.credential;
        verify_credential_signature(cred).map_err(MembershipRejection::InvalidProof)?;
        // The time-independent rules (ordering and maximum lifetime), evaluated at the
        // issue time so that expiry itself is not an error.
        cred.check_time(cred.issued_at)
            .map_err(MembershipRejection::InvalidProof)?;
        verify_acceptance(&proof.acceptance, cred, now)
            .map_err(MembershipRejection::InvalidProof)?;
        Self::insert_proof(state, proof)
    }

    fn state_for_issuer(&mut self, proof: &MembershipProof) -> Result<&mut CircleState> {
        let state = self
            .circles
            .get_mut(&proof.credential.circle_id)
            .ok_or(MembershipRejection::UnknownCircle)?;
        if proof.credential.issuer_key != state.root_key {
            return Err(MembershipRejection::IssuerNotRoot.into());
        }
        Ok(state)
    }

    fn insert_proof(state: &mut CircleState, proof: MembershipProof) -> Result<AddOutcome> {
        let digest = proof
            .credential
            .digest()
            .map_err(MembershipRejection::InvalidProof)?;
        if state.proofs.contains_key(&digest) {
            return Ok(AddOutcome::Duplicate);
        }
        let circle_id = proof.credential.circle_id;
        let subject = proof.credential.subject_device_key;
        state.by_subject.entry(subject).or_default().insert(digest);
        state.proofs.insert(digest, proof);
        tracing::debug!(circle = %circle_id, subject = %subject, "membership proof recorded");
        Ok(AddOutcome::Added)
    }

    /// Records a revocation after verifying its structure and root signature and
    /// checking that its circle is registered and its issuer is the circle root. Only
    /// the first revocation per subject is kept (`Duplicate` after).
    ///
    /// No time rule applies, and `_now` is unused: a revocation only ever denies, so it
    /// must never be refused because the issuer's clock runs ahead of this node's, nor
    /// dropped when stored revocations are reloaded after the local clock stepped back.
    /// Refusing it would leave the revoked device trusted.
    pub fn add_revocation(&mut self, rev: Revocation, _now: Timestamp) -> Result<AddOutcome> {
        let circle_id = rev.circle_id;
        let state = self
            .circles
            .get_mut(&circle_id)
            .ok_or(MembershipRejection::UnknownCircle)?;
        if rev.issuer_key != state.root_key {
            return Err(MembershipRejection::IssuerNotRoot.into());
        }
        verify_revocation_signature(&rev).map_err(MembershipRejection::InvalidRevocation)?;
        let subject = rev.subject_device_key;
        if state.revocations.contains_key(&subject) {
            return Ok(AddOutcome::Duplicate);
        }
        state.revocations.insert(subject, rev);
        tracing::info!(circle = %circle_id, subject = %subject, "revocation recorded");
        Ok(AddOutcome::Added)
    }

    /// Records that `issuer` is the device that invited us into `circle_id`, so
    /// [`Self::is_plausible_member`] treats it as a member before we have seen its
    /// credential. The circle must be registered.
    pub fn note_invite_issuer(&mut self, circle_id: &CircleId, issuer: DeviceKey) -> Result<()> {
        let state = self
            .circles
            .get_mut(circle_id)
            .ok_or(MembershipRejection::UnknownCircle)?;
        state.invite_issuers.insert(issuer);
        Ok(())
    }

    /// Whether `key` is revoked in `circle_id`.
    pub fn is_revoked(&self, circle_id: &CircleId, key: &DeviceKey) -> bool {
        self.circles
            .get(circle_id)
            .is_some_and(|c| c.revocations.contains_key(key))
    }

    /// The recorded revocation of `key` in `circle_id`, if any.
    pub fn revocation(&self, circle_id: &CircleId, key: &DeviceKey) -> Option<&Revocation> {
        self.circles.get(circle_id)?.revocations.get(key)
    }

    /// Every recorded revocation in `circle_id`, sorted by subject key.
    pub fn revocations(&self, circle_id: &CircleId) -> Vec<Revocation> {
        self.circles
            .get(circle_id)
            .map(|c| c.revocations.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Every recorded proof for `key` in `circle_id` (active or not).
    pub fn proofs_for(&self, circle_id: &CircleId, key: &DeviceKey) -> Vec<MembershipProof> {
        self.circles
            .get(circle_id)
            .map(|c| c.subject_proofs(key).cloned().collect())
            .unwrap_or_default()
    }

    /// The proofs for `key` in `circle_id` that are active at `now` (empty if revoked).
    pub fn active_proofs_for(
        &self,
        circle_id: &CircleId,
        key: &DeviceKey,
        now: Timestamp,
    ) -> Vec<MembershipProof> {
        let Some(c) = self.circles.get(circle_id) else {
            return Vec::new();
        };
        if c.revocations.contains_key(key) {
            return Vec::new();
        }
        c.subject_proofs(key)
            .filter(|p| is_active(p, now))
            .cloned()
            .collect()
    }

    /// Every recorded proof whose subject is `key`, across all circles (for example our
    /// own credentials).
    pub fn credentials_for_subject(&self, key: &DeviceKey) -> Vec<MembershipProof> {
        self.circles
            .values()
            .flat_map(|c| c.subject_proofs(key).cloned())
            .collect()
    }

    /// The members of `circle_id` (every key with at least one recorded proof), sorted by
    /// key. Revoked keys are included with `revoked: true`.
    pub fn members(&self, circle_id: &CircleId, now: Timestamp) -> Vec<MemberView> {
        let Some(c) = self.circles.get(circle_id) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for key in c.by_subject.keys() {
            let all: Vec<&MembershipProof> = c.subject_proofs(key).collect();
            let Some(expires_at) = all.iter().map(|p| p.credential.expires_at).max() else {
                continue;
            };
            let revoked = c.revocations.contains_key(key);
            let active_set: Vec<&MembershipProof> =
                all.iter().copied().filter(|p| is_active(p, now)).collect();
            let active = !revoked && !active_set.is_empty();
            let basis = if active_set.is_empty() {
                &all
            } else {
                &active_set
            };
            let roles: Vec<Role> = Role::ALL
                .iter()
                .copied()
                .filter(|r| basis.iter().any(|p| p.credential.roles.contains(r)))
                .collect();
            let scopes: BTreeSet<Scope> = basis
                .iter()
                .flat_map(|p| p.credential.scopes.iter().cloned())
                .collect();
            out.push(MemberView {
                key: *key,
                fingerprint: fingerprint(key),
                roles,
                scopes: scopes.into_iter().collect(),
                expires_at,
                revoked,
                active,
                credential_count: all.len(),
            });
        }
        out
    }

    /// Whether `peer` is plausibly a member of `circle_id`, i.e. whether we may present
    /// our credentials for that circle to it (architecture section 7): the peer is not
    /// revoked there, and it is either the subject of a credential we know for that
    /// circle (even an expired one, since it may hold a renewal we have not seen) or the
    /// device that invited us ([`Self::note_invite_issuer`]). Unknown peers get `false`.
    pub fn is_plausible_member(&self, circle_id: &CircleId, peer: &DeviceKey) -> bool {
        let Some(c) = self.circles.get(circle_id) else {
            return false;
        };
        if c.revocations.contains_key(peer) {
            return false;
        }
        c.by_subject.contains_key(peer) || c.invite_issuers.contains(peer)
    }

    /// The circles in which `peer` is plausibly a member, sorted.
    pub fn plausible_circles_for(&self, peer: &DeviceKey) -> Vec<CircleId> {
        self.circles
            .keys()
            .filter(|c| self.is_plausible_member(c, peer))
            .copied()
            .collect()
    }

    /// The proofs to put in an `Authenticate` request to `peer`: for every circle where
    /// `peer` is plausibly a member and `me` holds an active proof, the active proof of
    /// `me` with the latest expiry. At most [`MAX_AUTH_MEMBERSHIPS`] entries.
    pub fn proofs_to_present(
        &self,
        peer: &DeviceKey,
        me: &DeviceKey,
        now: Timestamp,
    ) -> Vec<MembershipProof> {
        let circles = self.plausible_circles_for(peer);
        self.best_proofs(me, &circles, now)
    }

    /// For each circle in `circles`, the active proof of `me` with the latest expiry
    /// (circles where `me` has none are skipped). At most [`MAX_AUTH_MEMBERSHIPS`]
    /// entries. Use it to build the `Authenticated` response from
    /// [`PresentedOutcome::active_circles`].
    pub fn best_proofs(
        &self,
        me: &DeviceKey,
        circles: &[CircleId],
        now: Timestamp,
    ) -> Vec<MembershipProof> {
        let mut out = Vec::new();
        for circle in circles {
            if out.len() >= MAX_AUTH_MEMBERSHIPS {
                break;
            }
            if let Some(best) = self
                .active_proofs_for(circle, me, now)
                .into_iter()
                .max_by_key(|p| p.credential.expires_at)
            {
                out.push(best);
            }
        }
        out
    }

    /// Processes the proofs a peer presented in `Authenticate` (or `Authenticated`).
    ///
    /// `peer` must be the device key bound to the transport `PeerId`. Proofs whose
    /// subject is not `peer`, for unknown circles, or that fail verification are counted
    /// in `rejected`. Valid ones are recorded. Returns the circles where `peer` is an
    /// active member afterwards (considering only circles it presented a proof for).
    pub fn accept_presented_proofs(
        &mut self,
        peer: &DeviceKey,
        proofs: &[MembershipProof],
        now: Timestamp,
    ) -> PresentedOutcome {
        let mut rejected = 0usize;
        let mut circles = BTreeSet::new();
        for p in proofs {
            if p.credential.subject_device_key != *peer {
                rejected += 1;
                continue;
            }
            match self.add_proof(p.clone(), now) {
                Ok(_) => {
                    circles.insert(p.credential.circle_id);
                }
                Err(_) => rejected += 1,
            }
        }
        let active_circles = circles
            .into_iter()
            .filter(|c| self.is_active_member(c, peer, now))
            .collect();
        if rejected > 0 {
            tracing::debug!(peer = %peer, rejected, "rejected presented membership proofs");
        }
        PresentedOutcome {
            active_circles,
            rejected,
        }
    }

    fn decide(
        &self,
        circle: &CircleId,
        key: &DeviceKey,
        scope: &Scope,
        cap: Capability,
        now: Timestamp,
    ) -> std::result::Result<(), DenyReason> {
        let c = self.circles.get(circle).ok_or(DenyReason::NotMember)?;
        if c.revocations.contains_key(key) {
            return Err(DenyReason::Revoked);
        }
        let mut any = false;
        let mut any_active = false;
        let mut scope_ok = false;
        for p in c.subject_proofs(key) {
            any = true;
            if !is_active(p, now) {
                continue;
            }
            any_active = true;
            if p.credential.grants(scope, cap) {
                return Ok(());
            }
            if Scope::any_covers(&p.credential.scopes, scope) {
                scope_ok = true;
            }
        }
        Err(if !any {
            DenyReason::NotMember
        } else if !any_active {
            DenyReason::Expired
        } else if !scope_ok {
            DenyReason::ScopeDenied
        } else {
            DenyReason::CapabilityDenied
        })
    }
}

impl MembershipOracle for MembershipRegistry {
    /// Order of checks: unknown circle (`NotMember`), revoked (`Revoked`), no proof
    /// (`NotMember`), no active proof (`Expired`), then if no active credential grants:
    /// `ScopeDenied` when no active credential's scopes cover `scope`, otherwise
    /// `CapabilityDenied`.
    fn authorize(
        &self,
        circle: &CircleId,
        key: &DeviceKey,
        scope: &Scope,
        cap: Capability,
        now: Timestamp,
    ) -> std::result::Result<(), DenyReason> {
        self.decide(circle, key, scope, cap, now)
    }

    fn is_active_member(&self, circle: &CircleId, key: &DeviceKey, now: Timestamp) -> bool {
        let Some(c) = self.circles.get(circle) else {
            return false;
        };
        !c.revocations.contains_key(key) && c.subject_proofs(key).any(|p| is_active(p, now))
    }

    /// Same as the inherent [`MembershipRegistry::is_revoked`].
    fn is_revoked(&self, circle: &CircleId, key: &DeviceKey) -> bool {
        MembershipRegistry::is_revoked(self, circle, key)
    }
}

/// A cloneable, thread-safe handle to a [`MembershipRegistry`] (`Arc<RwLock<_>>`) that
/// implements [`MembershipOracle`] by taking a read lock per call.
///
/// A poisoned lock is recovered (the registry has no invariants a panicking writer could
/// break halfway that would grant access: every mutation is a single map insert).
#[derive(Debug, Clone, Default)]
pub struct SharedMembershipRegistry {
    inner: Arc<RwLock<MembershipRegistry>>,
}

impl SharedMembershipRegistry {
    /// Wraps a registry.
    pub fn new(registry: MembershipRegistry) -> Self {
        Self {
            inner: Arc::new(RwLock::new(registry)),
        }
    }

    /// A read guard.
    pub fn read(&self) -> RwLockReadGuard<'_, MembershipRegistry> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    /// A write guard.
    pub fn write(&self) -> RwLockWriteGuard<'_, MembershipRegistry> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }
}

impl From<MembershipRegistry> for SharedMembershipRegistry {
    fn from(r: MembershipRegistry) -> Self {
        Self::new(r)
    }
}

impl MembershipOracle for SharedMembershipRegistry {
    fn authorize(
        &self,
        circle: &CircleId,
        key: &DeviceKey,
        scope: &Scope,
        cap: Capability,
        now: Timestamp,
    ) -> std::result::Result<(), DenyReason> {
        self.read().authorize(circle, key, scope, cap, now)
    }

    fn is_active_member(&self, circle: &CircleId, key: &DeviceKey, now: Timestamp) -> bool {
        self.read().is_active_member(circle, key, now)
    }

    fn is_revoked(&self, circle: &CircleId, key: &DeviceKey) -> bool {
        self.read().is_revoked(circle, key)
    }
}
