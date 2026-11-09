//! Incoming-event authorization: the **stateful** half of event validation
//! (architecture section 5, steps 3-4; ADR-010).
//!
//! The pipeline for every received event is:
//!
//! 1. `ph_protocol::validate_stateless(raw, now)` (size, schema, signature, event id,
//!    time rules, body/binding checks, embedded proof signatures). Forged signatures and
//!    modified bodies stop here and never reach this module.
//! 2. [`authorize_incoming`] (this module): circle known, author authorized for the
//!    event type in the event scope at `now`, control-plane rules for MEMBERSHIP and
//!    REVOCATION, and body-level sanity checks ([`check_body`]).
//! 3. Referential checks that need stored events, done by the caller with the helpers
//!    [`check_answer_reference`], [`check_vote_reference`], [`check_release_reference`]
//!    and [`check_supersedes_reference`].
//! 4. Store insert (`Inserted` / `Duplicate`): event-id uniqueness gives idempotency and
//!    replay rejection.
//!
//! ## Authorization by event type
//!
//! | type | rule |
//! |---|---|
//! | QUESTION, ANSWER, PROPOSAL, VOTE, RELEASE | `oracle.authorize(circle, author, scope, cap, now)` with the type's capability |
//! | MEMBERSHIP | embedded proof re-verified at `now`; `author == credential.subject_device_key`; `credential.circle_id == circle_id`; `circle_id == derive(credential.issuer_key)` (issuer is the circle root); scope rule below; subject not revoked locally |
//! | REVOCATION | `circle_id == derive(author)` (author is the circle root); revocation re-verified; issuer and circle bound to the envelope; the subject is not the root key itself. The oracle is **not** consulted (the root holds no credential). |
//!
//! **MEMBERSHIP scope rule.** A MEMBERSHIP event's envelope scope must be
//! [`MEMBERSHIP_CONTROL_SCOPE`] (`"*"`, the recommended value) or be covered by at least
//! one of the embedded credential's scopes. The envelope scope of control-plane events is
//! otherwise informational: MEMBERSHIP and REVOCATION events are readable by every
//! active member of the circle (see [`crate::read`]). REVOCATION events may carry any
//! scope; `"*"` is recommended.
//!
//! In every case the circle must be known locally (`known_circle`), and the event's time
//! rules are re-checked at `now`, so an envelope that was verified earlier but has since
//! expired is rejected.

use std::fmt;

use ph_core::{CircleId, DenyReason, DeviceKey, EventId, MembershipOracle, Scope, Timestamp};
use ph_protocol::{
    check_time_rules, verify_membership_proof, verify_revocation, Authorization, EventBody,
    EventType, SignedEnvelope, VerifiedEnvelope,
};

/// The envelope scope recommended for MEMBERSHIP and REVOCATION events.
pub const MEMBERSHIP_CONTROL_SCOPE: &str = "*";

/// Why an incoming event was rejected by governance.
///
/// The variant (and [`Rejection::code`]) are for local logs and tests. **`Display` is
/// the same generic text for every variant**, so a rejection reported to a peer (as
/// `PushStatus::Rejected`) never reveals which check failed or whether a circle exists.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Rejection {
    /// The event's circle is not known to this node.
    UnknownCircle,
    /// The membership oracle denied the author (not a member, expired, revoked, scope or
    /// capability denied, not accepted). Also used when a MEMBERSHIP subject is revoked.
    Denied(DenyReason),
    /// The event's time rules fail at `now` (expired, future-dated, bad lifetime).
    Expired,
    /// The embedded credential/acceptance (MEMBERSHIP) or revocation (REVOCATION) does
    /// not verify at `now`.
    InvalidProof,
    /// MEMBERSHIP: the author is not the credential subject.
    AuthorNotSubject,
    /// MEMBERSHIP: the credential issuer is not the circle root.
    IssuerNotRoot,
    /// The embedded object is for a different circle than the envelope.
    CircleMismatch,
    /// MEMBERSHIP: the envelope scope is neither `*` nor covered by the credential.
    ScopeNotCovered,
    /// REVOCATION: the author is not the circle root key.
    NotCircleRoot,
    /// REVOCATION: the root key revokes itself. The root holds no credential and cannot
    /// be revoked in v0 (a compromised root means a new circle), so such an entry is
    /// meaningless and is refused rather than stored. Revoking the founder's **device**
    /// key (a different key) is allowed.
    RootSelfRevocation,
    /// A body-level reference is malformed or inconsistent with the referenced event.
    BadReference,
}

impl Rejection {
    /// A stable machine-readable code for local logs and tests (never sent to peers).
    /// For [`Rejection::Denied`] this is the [`DenyReason::code`].
    pub const fn code(self) -> &'static str {
        match self {
            Rejection::UnknownCircle => "unknown_circle",
            Rejection::Denied(r) => r.code(),
            Rejection::Expired => "expired_event",
            Rejection::InvalidProof => "invalid_proof",
            Rejection::AuthorNotSubject => "author_not_subject",
            Rejection::IssuerNotRoot => "issuer_not_root",
            Rejection::CircleMismatch => "circle_mismatch",
            Rejection::ScopeNotCovered => "scope_not_covered",
            Rejection::NotCircleRoot => "not_circle_root",
            Rejection::RootSelfRevocation => "root_self_revocation",
            Rejection::BadReference => "bad_reference",
        }
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("event rejected")
    }
}

impl std::error::Error for Rejection {}

/// An event that passed [`authorize_incoming`]. Dereferences to the
/// [`VerifiedEnvelope`].
///
/// Holding one means: the signature verified, the time rules held at the evaluation
/// time, the circle is known, and the author was authorized for the event at that time.
/// Referential checks against stored events are still the caller's job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedEvent {
    env: VerifiedEnvelope,
    basis: Authorization,
}

impl AuthorizedEvent {
    /// The verified envelope.
    pub fn verified(&self) -> &VerifiedEnvelope {
        &self.env
    }

    /// Consumes the wrapper, returning the verified envelope (for storage).
    pub fn into_verified(self) -> VerifiedEnvelope {
        self.env
    }

    /// Which rule authorized the event.
    pub fn basis(&self) -> Authorization {
        self.basis
    }

    /// The event id.
    pub fn event_id(&self) -> EventId {
        self.env.event_id()
    }

    /// The event type.
    pub fn event_type(&self) -> EventType {
        self.env.event_type()
    }

    /// The circle id.
    pub fn circle_id(&self) -> CircleId {
        self.env.circle_id
    }
}

impl std::ops::Deref for AuthorizedEvent {
    type Target = VerifiedEnvelope;
    fn deref(&self) -> &VerifiedEnvelope {
        &self.env
    }
}

/// Authorizes a statelessly verified incoming event at local time `now`.
///
/// * `oracle`: the local membership state (credentials, acceptances, revocations).
/// * `known_circle`: whether this node knows (has joined or founded) the circle.
/// * `now`: the **local** clock, never a remote timestamp.
///
/// For MEMBERSHIP events the subject's local revocation state is probed through the
/// oracle: the subject counts as revoked when `oracle.authorize(circle, subject, "*",
/// Read, now)` returns [`DenyReason::Revoked`]. That is reliable only for oracles that
/// report revocation before scope/capability denials (the documented `ph-identity`
/// registry behaviour). Use [`authorize_incoming_with_revocations`] to pass an explicit
/// revocation predicate instead.
///
/// See the [module docs](self) for the rule per event type.
pub fn authorize_incoming(
    env: &VerifiedEnvelope,
    oracle: &dyn MembershipOracle,
    known_circle: &dyn Fn(&CircleId) -> bool,
    now: Timestamp,
) -> Result<AuthorizedEvent, Rejection> {
    let probe = |circle: &CircleId, key: &DeviceKey| {
        matches!(
            oracle.authorize(circle, key, &Scope::all(), ph_core::Capability::Read, now),
            Err(DenyReason::Revoked)
        )
    };
    authorize_incoming_with_revocations(env, oracle, known_circle, &probe, now)
}

/// [`authorize_incoming`] with an explicit revocation predicate:
/// `is_revoked(circle, key)` must return `true` iff the local store holds a verified
/// revocation of `key` in `circle`. It is consulted for MEMBERSHIP subjects (whose
/// credentials the oracle may not know yet); all other event types rely on the oracle,
/// which applies revocations itself.
pub fn authorize_incoming_with_revocations(
    env: &VerifiedEnvelope,
    oracle: &dyn MembershipOracle,
    known_circle: &dyn Fn(&CircleId) -> bool,
    is_revoked: &dyn Fn(&CircleId, &DeviceKey) -> bool,
    now: Timestamp,
) -> Result<AuthorizedEvent, Rejection> {
    let result = authorize_inner(env, oracle, known_circle, is_revoked, now);
    match &result {
        Ok(_) => tracing::debug!(
            event_id = %env.event_id(),
            event_type = env.event_type().as_str(),
            "incoming event authorized"
        ),
        Err(r) => tracing::debug!(
            event_id = %env.event_id(),
            event_type = env.event_type().as_str(),
            code = r.code(),
            "incoming event rejected"
        ),
    }
    result
}

fn authorize_inner(
    env: &VerifiedEnvelope,
    oracle: &dyn MembershipOracle,
    known_circle: &dyn Fn(&CircleId) -> bool,
    is_revoked: &dyn Fn(&CircleId, &DeviceKey) -> bool,
    now: Timestamp,
) -> Result<AuthorizedEvent, Rejection> {
    check_time_rules(env.created_at, env.expires_at, now).map_err(|_| Rejection::Expired)?;
    let circle = env.circle_id;
    if !known_circle(&circle) {
        return Err(Rejection::UnknownCircle);
    }
    check_body(env)?;
    let basis = env.authorization();
    match basis {
        Authorization::Capability(cap) => {
            oracle
                .authorize(&circle, &env.author, &env.scope, cap, now)
                .map_err(Rejection::Denied)?;
        }
        Authorization::EmbeddedCredential => {
            let EventBody::Membership(b) = &env.body else {
                return Err(Rejection::BadReference);
            };
            let cred = &b.credential;
            if env.author != cred.subject_device_key {
                return Err(Rejection::AuthorNotSubject);
            }
            if cred.circle_id != circle {
                return Err(Rejection::CircleMismatch);
            }
            if !circle.is_derived_from(&cred.issuer_key) {
                return Err(Rejection::IssuerNotRoot);
            }
            verify_membership_proof(&b.to_proof(), now).map_err(|_| Rejection::InvalidProof)?;
            if !(env.scope.is_wildcard() || Scope::any_covers(&cred.scopes, &env.scope)) {
                return Err(Rejection::ScopeNotCovered);
            }
            if is_revoked(&circle, &env.author) {
                return Err(Rejection::Denied(DenyReason::Revoked));
            }
        }
        Authorization::CircleRoot => {
            let EventBody::Revocation(b) = &env.body else {
                return Err(Rejection::BadReference);
            };
            if !circle.is_derived_from(&env.author) {
                return Err(Rejection::NotCircleRoot);
            }
            let rev = &b.revocation;
            if rev.issuer_key != env.author {
                return Err(Rejection::NotCircleRoot);
            }
            if rev.circle_id != circle {
                return Err(Rejection::CircleMismatch);
            }
            verify_revocation(rev, now).map_err(|_| Rejection::InvalidProof)?;
            if rev.subject_device_key == env.author {
                return Err(Rejection::RootSelfRevocation);
            }
        }
    }
    Ok(AuthorizedEvent {
        env: env.clone(),
        basis,
    })
}

/// Body-level checks that need no stored state.
///
/// * Re-runs the protocol body validation (bounded text, skill names, bundle size,
///   unique RELEASE approvals). Typed bodies already guarantee that every digest and
///   event-id reference (`VOTE.proposal_id`, `VOTE.bundle_digest`,
///   `ANSWER.question_id`, `PROPOSAL.supersedes`, ...) is a well-formed `sha256:` value.
/// * An event may not reference its own id (`VOTE.proposal_id`, `ANSWER.question_id`,
///   `RELEASE.proposal_id`, `PROPOSAL.supersedes`, `PROPOSAL.related_question`).
/// * A RELEASE must list at least one approval (an empty claim can never verify, since
///   every circle policy requires at least one approval).
pub fn check_body(env: &SignedEnvelope) -> Result<(), Rejection> {
    env.body.validate().map_err(|_| Rejection::BadReference)?;
    let own = env.event_id;
    let self_ref = match &env.body {
        EventBody::Vote(b) => b.proposal_id == own,
        EventBody::Answer(b) => b.question_id == own,
        EventBody::Release(b) => b.proposal_id == own || b.approvals.contains(&own),
        EventBody::Proposal(b) => b.supersedes == Some(own) || b.related_question == Some(own),
        _ => false,
    };
    if self_ref {
        return Err(Rejection::BadReference);
    }
    if let EventBody::Release(b) = &env.body {
        if b.approvals.is_empty() {
            return Err(Rejection::BadReference);
        }
    }
    Ok(())
}

/// The outcome of a referential check against a stored event.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Reference {
    /// The reference resolves to a consistent stored event (or there is none to check).
    Resolved,
    /// The referenced event is not stored (yet). The caller may keep the event and
    /// re-check after the next sync; it simply has no effect until then (votes for an
    /// unknown proposal count for nothing).
    Missing,
    /// The reference can never be satisfied (wrong type, circle, scope, digest or skill
    /// name). The caller should reject the event.
    Invalid(Rejection),
}

impl Reference {
    /// `true` for [`Reference::Resolved`].
    pub fn is_resolved(self) -> bool {
        self == Reference::Resolved
    }
}

const INVALID: Reference = Reference::Invalid(Rejection::BadReference);

/// Checks an ANSWER against the referenced QUESTION, looked up by the caller by
/// `answer.body.question_id` (`None` if not stored).
///
/// Rules: the question is a QUESTION with exactly that event id, in the same circle and
/// the **same scope** as the answer.
pub fn check_answer_reference(
    answer: &SignedEnvelope,
    question: Option<&SignedEnvelope>,
) -> Reference {
    let EventBody::Answer(a) = &answer.body else {
        return INVALID;
    };
    let Some(q) = question else {
        return Reference::Missing;
    };
    let ok = q.event_type() == EventType::Question
        && q.event_id == a.question_id
        && q.circle_id == answer.circle_id
        && q.scope == answer.scope;
    if ok {
        Reference::Resolved
    } else {
        INVALID
    }
}

/// Checks a VOTE against the referenced PROPOSAL, looked up by the caller by
/// `vote.body.proposal_id` (`None` if not stored).
///
/// Rules: the proposal is a PROPOSAL with exactly that event id, in the same circle and
/// the **same scope**, and `vote.bundle_digest == proposal.bundle_digest`. (The tally
/// applies the same rules again; this helper lets the caller reject hopeless votes at
/// intake.)
pub fn check_vote_reference(vote: &SignedEnvelope, proposal: Option<&SignedEnvelope>) -> Reference {
    let EventBody::Vote(v) = &vote.body else {
        return INVALID;
    };
    let Some(p) = proposal else {
        return Reference::Missing;
    };
    let EventBody::Proposal(pb) = &p.body else {
        return INVALID;
    };
    let ok = p.event_id == v.proposal_id
        && p.circle_id == vote.circle_id
        && p.scope == vote.scope
        && pb.bundle_digest == v.bundle_digest;
    if ok {
        Reference::Resolved
    } else {
        INVALID
    }
}

/// Checks a RELEASE against the referenced PROPOSAL, looked up by the caller by
/// `release.body.proposal_id` (`None` if not stored).
///
/// Rules: the proposal is a PROPOSAL with exactly that id, in the same circle and scope,
/// with the same `bundle_digest` and `skill_name`. This does **not** verify the claimed
/// approvals; use [`crate::verify_release`] for that.
pub fn check_release_reference(
    release: &SignedEnvelope,
    proposal: Option<&SignedEnvelope>,
) -> Reference {
    let EventBody::Release(r) = &release.body else {
        return INVALID;
    };
    let Some(p) = proposal else {
        return Reference::Missing;
    };
    let EventBody::Proposal(pb) = &p.body else {
        return INVALID;
    };
    let ok = p.event_id == r.proposal_id
        && p.circle_id == release.circle_id
        && p.scope == release.scope
        && pb.bundle_digest == r.bundle_digest
        && pb.skill_name == r.skill_name;
    if ok {
        Reference::Resolved
    } else {
        INVALID
    }
}

/// Checks a PROPOSAL's optional `supersedes` reference against the superseded
/// PROPOSAL, looked up by the caller (`None` if not stored).
///
/// Returns [`Reference::Resolved`] when the proposal supersedes nothing. Otherwise the
/// superseded event must be a PROPOSAL with that id in the same circle and with the same
/// `skill_name`. Lineage never moves votes (see [`crate::conflicts`]).
pub fn check_supersedes_reference(
    proposal: &SignedEnvelope,
    superseded: Option<&SignedEnvelope>,
) -> Reference {
    let EventBody::Proposal(p) = &proposal.body else {
        return INVALID;
    };
    let Some(target) = p.supersedes else {
        return Reference::Resolved;
    };
    let Some(old) = superseded else {
        return Reference::Missing;
    };
    let EventBody::Proposal(ob) = &old.body else {
        return INVALID;
    };
    let ok = old.event_id == target
        && old.circle_id == proposal.circle_id
        && ob.skill_name == p.skill_name;
    if ok {
        Reference::Resolved
    } else {
        INVALID
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_generic_and_codes_unique() {
        let all = [
            Rejection::UnknownCircle,
            Rejection::Denied(DenyReason::NotMember),
            Rejection::Denied(DenyReason::Revoked),
            Rejection::Expired,
            Rejection::InvalidProof,
            Rejection::AuthorNotSubject,
            Rejection::IssuerNotRoot,
            Rejection::CircleMismatch,
            Rejection::ScopeNotCovered,
            Rejection::NotCircleRoot,
            Rejection::RootSelfRevocation,
            Rejection::BadReference,
        ];
        for r in all {
            assert_eq!(r.to_string(), "event rejected");
        }
        let codes: std::collections::HashSet<_> = all.iter().map(|r| r.code()).collect();
        assert_eq!(codes.len(), all.len());
    }
}
