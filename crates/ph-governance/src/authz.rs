//! Incoming-event authorization: the **stateful** half of event validation
//! (architecture section 5, steps 3-4; section 10; ADR-010).
//!
//! The pipeline for every received event is:
//!
//! 1. `ph_protocol::validate_stateless(raw, now)` (size, schema, signature, event id,
//!    time rules, body/binding checks, embedded proof signatures). Forged signatures and
//!    modified bodies stop here and never reach this module.
//! 2. [`authorize_incoming`] (this module): circle known, author authorized for the
//!    event type, control-plane rules for MEMBERSHIP, REVOCATION and CHARTER, and
//!    body-level sanity checks ([`check_body`]).
//! 3. Referential checks that need further stored events, done by the caller with the
//!    helpers [`check_answer_reference`], [`check_supersedes_reference`] and
//!    [`check_repeal_reference`]. A RESULT is verified with [`crate::verify_result`] and
//!    a CHARTER with [`crate::check_successor`] before either has any effect.
//! 4. Store insert (`Inserted` / `Duplicate`): event-id uniqueness gives idempotency and
//!    replay rejection.
//!
//! ## Authorization by event type
//!
//! | type | rule |
//! |---|---|
//! | QUESTION, ANSWER | `oracle.authorize(circle, author, scope, cap, now)` with the type's capability |
//! | PROPOSAL | the charter it names is in this circle's accepted chain; `author` is a device of a member in the proposal's electorate under that charter; the device is not revoked locally |
//! | VOTE, RESULT | the proposal it names is stored, in the same circle and scope; `author` is a device of a member in **that proposal's** electorate, under the charter the proposal names; the device is not revoked locally |
//! | STANCE | the `adopt` proposal it names is stored, in the same circle and scope; the charter **the stance names** is in this circle's accepted chain; `author` is a device of a member whose roll entry in that charter covers the scope; the device is not revoked locally. A stance is a record: nothing is counted from it |
//! | MEMBERSHIP | embedded proof re-verified at `now`; `author == credential.subject_device_key`; `credential.circle_id == circle_id`; `circle_id == derive(credential.issuer_key)` (issuer is the circle root); scope rule below; subject not revoked locally (`oracle.is_revoked`) |
//! | REVOCATION | `circle_id == derive(author)` (author is the circle root); revocation signature re-verified; issuer and circle bound to the envelope; the subject is not the root key itself. The oracle is **not** consulted (the root holds no credential). No time rule applies: a revocation only ever denies. |
//! | CHARTER | `circle_id == derive(author)` (author is the circle root); charter structure and signature re-verified; same circle. This only establishes that the charter is authentic. Whether it becomes the current charter is decided by [`crate::check_successor`]. |
//!
//! Decision events (PROPOSAL, VOTE, RESULT) are authorized by the **roll**, not by a
//! credential: the answer depends only on signed, permanent records, so it is the same
//! on every node and at every time. They never expire.
//!
//! **MEMBERSHIP scope rule.** A MEMBERSHIP event's envelope scope must be
//! [`MEMBERSHIP_CONTROL_SCOPE`] (`"*"`, the recommended value) or be covered by at least
//! one of the embedded credential's scopes. The envelope scope of control-plane events is
//! otherwise informational: MEMBERSHIP, REVOCATION and CHARTER events are readable by
//! every active member of the circle (see [`crate::read`]). REVOCATION events may carry
//! any scope; `"*"` is recommended.
//!
//! In every case the circle must be known locally (`known_circle`), and the event's time
//! rules are re-checked at `now`, so a QUESTION or ANSWER that was verified earlier but
//! has since expired is rejected.

use std::fmt;

use ph_core::{CircleId, DenyReason, Digest, EventId, MembershipOracle, Scope, Timestamp};
use ph_protocol::{
    check_time_rules_for, verify_charter_signature, verify_membership_proof,
    verify_revocation_signature, Authorization, Charter, EventBody, EventType, ProposalAction,
    ProposalKind, SignedEnvelope, VerifiedEnvelope,
};

use crate::views::ProposalView;

/// What decision-event authorization needs from local storage. The daemon and CLI
/// implement it over the store; tests use an in-memory map.
///
/// Implementations must return only records this node has itself verified: a charter
/// that is part of the circle's accepted chain (the founding charter received at join
/// time, and successors accepted through [`crate::check_successor`]), and proposals that
/// already passed [`authorize_incoming`].
pub trait DecisionRecords {
    /// The charter with this digest, if it is part of `circle`'s accepted chain.
    fn charter(&self, circle: &CircleId, digest: &Digest) -> Option<Charter>;
    /// The stored PROPOSAL with this event id in `circle`, if any.
    fn proposal(&self, circle: &CircleId, id: &EventId) -> Option<SignedEnvelope>;
}

/// A [`DecisionRecords`] that knows nothing: every decision event is refused as
/// retryable. Useful for nodes that are not in any circle.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoRecords;

impl DecisionRecords for NoRecords {
    fn charter(&self, _circle: &CircleId, _digest: &Digest) -> Option<Charter> {
        None
    }
    fn proposal(&self, _circle: &CircleId, _id: &EventId) -> Option<SignedEnvelope> {
        None
    }
}

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
    /// key (a different key) is allowed. Since ph-protocol rejects such revocations
    /// during stateless validation, this is a defense-in-depth check that a
    /// [`VerifiedEnvelope`] normally cannot reach.
    RootSelfRevocation,
    /// A body-level reference is malformed or inconsistent with the referenced event.
    BadReference,
    /// CHARTER: the author is not the circle root key.
    CharterNotFromRoot,
    /// PROPOSAL (or the proposal a VOTE or RESULT names): it names a charter that is not
    /// in this node's accepted chain. Retryable: the charter may simply not have arrived
    /// yet.
    UnknownCharter,
    /// VOTE or RESULT: the proposal it names is not stored. Retryable.
    MissingProposal,
    /// Decision event: the signing device is not on the roll of the charter the
    /// proposal names.
    NotOnRoll,
    /// Decision event: the signing device belongs to a member outside the proposal's
    /// electorate.
    NotInElectorate,
}

impl Rejection {
    /// Whether the same event may be accepted later without anything being wrong with
    /// it now: this node just lacks a record it depends on (a charter or a proposal).
    /// The caller may keep such an event aside and try again after the next sync.
    pub const fn is_retryable(self) -> bool {
        matches!(self, Rejection::UnknownCharter | Rejection::MissingProposal)
    }

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
            Rejection::CharterNotFromRoot => "charter_not_from_root",
            Rejection::UnknownCharter => "unknown_charter",
            Rejection::MissingProposal => "missing_proposal",
            Rejection::NotOnRoll => "not_on_roll",
            Rejection::NotInElectorate => "not_in_electorate",
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
/// time, the circle is known, and the author was authorized for the event (by
/// credential, by the roll, or as the circle root; see the module docs).
///
/// It does **not** mean the event has taken effect. A RESULT still has to pass
/// [`crate::verify_result`], a CHARTER still has to pass [`crate::check_successor`], and
/// the remaining referential checks are the caller's job.
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
/// * `records`: the accepted charters and stored proposals, for decision events.
/// * `known_circle`: whether this node knows (has joined or founded) the circle.
/// * `now`: the **local** clock, never a remote timestamp. It is used only for the
///   time rules of expiring events and for credential checks; decision events are
///   authorized by the roll and the outcome does not depend on it.
///
/// For MEMBERSHIP and decision events the author's local revocation state is read with
/// [`MembershipOracle::is_revoked`], which reports a revocation even when the oracle
/// does not know the device's credential. QUESTION and ANSWER rely on
/// [`MembershipOracle::authorize`], which applies revocations itself.
///
/// See the [module docs](self) for the rule per event type.
pub fn authorize_incoming(
    env: &VerifiedEnvelope,
    oracle: &dyn MembershipOracle,
    records: &dyn DecisionRecords,
    known_circle: &dyn Fn(&CircleId) -> bool,
    now: Timestamp,
) -> Result<AuthorizedEvent, Rejection> {
    let result = authorize_inner(env, oracle, records, known_circle, now);
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
    records: &dyn DecisionRecords,
    known_circle: &dyn Fn(&CircleId) -> bool,
    now: Timestamp,
) -> Result<AuthorizedEvent, Rejection> {
    check_time_rules_for(env.event_type(), env.created_at, env.expires_at, now)
        .map_err(|_| Rejection::Expired)?;
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
        Authorization::Roll => authorize_by_roll(env, oracle, records)?,
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
            if oracle.is_revoked(&circle, &env.author) {
                return Err(Rejection::Denied(DenyReason::Revoked));
            }
        }
        Authorization::CircleRoot => match &env.body {
            EventBody::Revocation(b) => {
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
                // Defense in depth: ph-protocol already refuses root self-revocations
                // (`UnsignedRevocation::check_structure`, so `validate_stateless`,
                // `verify_revocation_signature` and `check_body` all reject them first).
                if rev.subject_device_key == env.author {
                    return Err(Rejection::RootSelfRevocation);
                }
                // No time rule: a revocation only ever denies, so it is never refused
                // because the issuer's clock runs ahead of ours.
                verify_revocation_signature(rev).map_err(|_| Rejection::InvalidProof)?;
            }
            EventBody::Charter(b) => {
                let charter = &b.charter;
                if !circle.is_derived_from(&env.author) || charter.issuer_key != env.author {
                    return Err(Rejection::CharterNotFromRoot);
                }
                if charter.circle_id != circle {
                    return Err(Rejection::CircleMismatch);
                }
                verify_charter_signature(charter).map_err(|_| Rejection::InvalidProof)?;
            }
            _ => return Err(Rejection::BadReference),
        },
    }
    Ok(AuthorizedEvent {
        env: env.clone(),
        basis,
    })
}

/// Authorizes a PROPOSAL, VOTE or RESULT by the roll of the charter the proposal names,
/// and a STANCE by the roll of the charter the stance names.
fn authorize_by_roll(
    env: &VerifiedEnvelope,
    oracle: &dyn MembershipOracle,
    records: &dyn DecisionRecords,
) -> Result<(), Rejection> {
    let circle = env.circle_id;
    // The proposal that fixes the charter and the electorate: the event itself, or the
    // stored proposal a ballot or result names.
    let proposal = match &env.body {
        EventBody::Proposal(_) => ProposalView::from_verified(env),
        EventBody::Vote(b) => referenced_proposal(env, records, &b.proposal_id)?,
        EventBody::Result(b) => referenced_proposal(env, records, &b.proposal_id)?,
        EventBody::Stance(b) => referenced_proposal(env, records, &b.proposal_id)?,
        _ => return Err(Rejection::BadReference),
    }
    .map_err(|_| Rejection::BadReference)?;
    // The charter whose roll decides: the one the proposal names, except for a STANCE,
    // which is about a rule that may have been adopted before its author joined and so
    // names the charter under which its author is a member.
    let named = match &env.body {
        EventBody::Stance(b) => {
            // A stance is about a rule, and only an `adopt` proposal makes one.
            if proposal.kind() != ProposalKind::Adopt {
                return Err(Rejection::BadReference);
            }
            b.charter
        }
        _ => proposal.charter(),
    };
    let charter = records
        .charter(&circle, &named)
        .ok_or(Rejection::UnknownCharter)?;
    // Never trust the lookup: the record must be this circle's charter with exactly the
    // digest that was named.
    if charter.circle_id != circle || charter.digest().ok() != Some(named) {
        return Err(Rejection::UnknownCharter);
    }
    let entry = charter
        .content
        .member_of(&env.author)
        .ok_or(Rejection::NotOnRoll)?;
    if !ph_protocol::CharterContent::in_electorate(entry, &proposal.electorate()) {
        return Err(Rejection::NotInElectorate);
    }
    if oracle.is_revoked(&circle, &env.author) {
        return Err(Rejection::Denied(DenyReason::Revoked));
    }
    Ok(())
}

/// Looks up and checks the proposal a VOTE, RESULT or STANCE names: it must be a stored
/// PROPOSAL with exactly that id, in the same circle and the same scope.
fn referenced_proposal(
    env: &VerifiedEnvelope,
    records: &dyn DecisionRecords,
    proposal_id: &EventId,
) -> Result<Result<ProposalView, crate::views::ViewError>, Rejection> {
    let stored = records
        .proposal(&env.circle_id, proposal_id)
        .ok_or(Rejection::MissingProposal)?;
    if stored.event_id != *proposal_id
        || stored.circle_id != env.circle_id
        || stored.scope != env.scope
    {
        return Err(Rejection::BadReference);
    }
    // Re-verifies the signature and event id of the stored envelope.
    Ok(ProposalView::from_envelope(&stored))
}

/// Body-level checks that need no stored state.
///
/// * Re-runs the protocol body validation (bounded text, skill names, bundle size,
///   sorted unique RESULT approvals, charter structure). Typed bodies already guarantee
///   that every digest and event-id reference (`VOTE.proposal_id`, `ANSWER.question_id`,
///   `PROPOSAL.supersedes`, ...) is a well-formed `sha256:` value.
/// * An event may not reference its own id (`VOTE.proposal_id`, `ANSWER.question_id`,
///   `RESULT.proposal_id` or an approval, `PROPOSAL.supersedes`,
///   `PROPOSAL.related_question`, a repeal `target`, an amendment's `carried`).
/// * An `amend` proposal and a CHARTER event have scope `*`.
pub fn check_body(env: &SignedEnvelope) -> Result<(), Rejection> {
    env.check_bindings().map_err(|_| Rejection::BadReference)?;
    let own = env.event_id;
    let self_ref = match &env.body {
        EventBody::Vote(b) => b.proposal_id == own,
        EventBody::Stance(b) => b.proposal_id == own,
        EventBody::Answer(b) => b.question_id == own,
        EventBody::Result(b) => b.proposal_id == own || b.approvals.contains(&own),
        EventBody::Proposal(b) => match &b.action {
            ProposalAction::Adopt(a) => {
                a.supersedes == Some(own) || a.related_question == Some(own)
            }
            ProposalAction::Repeal { target } => *target == own,
            ProposalAction::Amend { next } => next.carried.contains(&own),
        },
        _ => false,
    };
    if self_ref {
        return Err(Rejection::BadReference);
    }
    Ok(())
}

/// The outcome of a referential check against a stored event.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Reference {
    /// The reference resolves to a consistent stored event (or there is none to check).
    Resolved,
    /// The referenced event is not stored (yet). The caller may keep the event and
    /// re-check after the next sync; it simply has no effect until then.
    Missing,
    /// The reference can never be satisfied (wrong type, kind, circle, scope or skill
    /// name). The caller rejects an ANSWER for it. A PROPOSAL is kept all the same and
    /// its reference has no effect (ADR-051).
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

/// Describes an `adopt` PROPOSAL's optional `supersedes` reference against the
/// referenced PROPOSAL, looked up by the caller (`None` if not stored).
///
/// This is a description, not a gate: a node must keep a proposal whatever its
/// `supersedes` names, or what it keeps would depend on which of the two arrived first
/// (ADR-051). An invalid reference records no lineage ([`crate::supersede_links`]).
///
/// Returns [`Reference::Resolved`] when the proposal supersedes nothing (always the case
/// for `repeal` and `amend` proposals). Otherwise the referenced event must be an
/// `adopt` PROPOSAL with that id in the same circle and with the same `skill_name`.
/// Lineage never moves approvals (see [`crate::conflicts`]).
pub fn check_supersedes_reference(
    proposal: &SignedEnvelope,
    superseded: Option<&SignedEnvelope>,
) -> Reference {
    let EventBody::Proposal(p) = &proposal.body else {
        return INVALID;
    };
    let Some(adopt) = p.as_adopt() else {
        return Reference::Resolved;
    };
    let Some(target) = adopt.supersedes else {
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
        && ob
            .as_adopt()
            .is_some_and(|o| o.skill_name == adopt.skill_name);
    if ok {
        Reference::Resolved
    } else {
        INVALID
    }
}

/// Describes a `repeal` PROPOSAL against its target, looked up by the caller by the
/// proposal's `target` (`None` if not stored).
///
/// This is a description, not a gate: a node must keep a repeal whatever it names, or
/// what it keeps would depend on which of the two arrived first (ADR-051). The scope
/// rule below is enforced where a repeal takes effect, in [`crate::rules_in_force`].
///
/// Returns [`Reference::Resolved`] for proposals of another kind. Otherwise the target
/// must be an `adopt` PROPOSAL with that id, in the same circle and the **same scope**,
/// so that the electorate that adopted a rule is the one that repeals it. Whether the
/// target is currently in force is not checked here: repealing a rule that is not in
/// force has no effect (see [`crate::rules_in_force`]).
pub fn check_repeal_reference(
    proposal: &SignedEnvelope,
    target_proposal: Option<&SignedEnvelope>,
) -> Reference {
    let EventBody::Proposal(p) = &proposal.body else {
        return INVALID;
    };
    let ProposalAction::Repeal { target } = &p.action else {
        return Reference::Resolved;
    };
    let Some(old) = target_proposal else {
        return Reference::Missing;
    };
    let EventBody::Proposal(ob) = &old.body else {
        return INVALID;
    };
    let ok = old.event_id == *target
        && old.circle_id == proposal.circle_id
        && old.scope == proposal.scope
        && ob.kind() == ProposalKind::Adopt;
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
            Rejection::CharterNotFromRoot,
            Rejection::UnknownCharter,
            Rejection::MissingProposal,
            Rejection::NotOnRoll,
            Rejection::NotInElectorate,
        ];
        for r in all {
            assert_eq!(r.to_string(), "event rejected");
        }
        let codes: std::collections::HashSet<_> = all.iter().map(|r| r.code()).collect();
        assert_eq!(codes.len(), all.len());
        let retryable: Vec<_> = all.iter().filter(|r| r.is_retryable()).collect();
        assert_eq!(
            retryable,
            [&Rejection::UnknownCharter, &Rejection::MissingProposal]
        );
    }
}
