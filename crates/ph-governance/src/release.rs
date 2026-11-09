//! RELEASE verification (architecture section 10: "a RELEASE event is a claim").
//!
//! [`verify_release`] never trusts the RELEASE: it recomputes the proposal's status from
//! locally stored votes with [`evaluate_proposal`] and accepts
//! the claim only if the local computation independently agrees. A RELEASE therefore
//! never makes a proposal eligible on its own; at most it tells the node which vote ids
//! to fetch.

use ph_core::{Capability, DenyReason, EventId, MembershipOracle, Timestamp};
use ph_protocol::VoteDecision;

use crate::policy::{CirclePolicy, LocalPolicy};
use crate::tally::{evaluate_proposal, time_check, IgnoreReason, ProposalStatus, TimeCheck};
use crate::views::{ProposalView, ReleaseView, VoteView};

/// Why a RELEASE claim was not accepted. `Display` is generic; use
/// [`ReleaseError::code`] and [`ReleaseError::describe`] locally.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ReleaseError {
    /// The release is for a different circle than the proposal.
    #[error("release claim not verified")]
    WrongCircle,
    /// The release references a different proposal id.
    #[error("release claim not verified")]
    WrongProposal,
    /// The release scope differs from the proposal scope.
    #[error("release claim not verified")]
    ScopeMismatch,
    /// The release digest differs from the proposal digest.
    #[error("release claim not verified")]
    DigestMismatch,
    /// The release skill name differs from the proposal skill name.
    #[error("release claim not verified")]
    SkillNameMismatch,
    /// The release envelope has expired.
    #[error("release claim not verified")]
    Expired,
    /// The release envelope fails the other event time rules now (future-dated beyond
    /// the clock skew, or an impossible lifetime).
    #[error("release claim not verified")]
    InvalidTime,
    /// The publisher lacks the `publish` capability on the proposal scope now.
    #[error("release claim not verified")]
    PublisherNotAuthorized(DenyReason),
    /// A listed approval is not among the locally stored votes (fetch it and retry).
    #[error("release claim not verified")]
    UnknownApproval(EventId),
    /// A listed approval is stored but was not counted.
    #[error("release claim not verified")]
    ApprovalIgnored {
        /// The listed vote.
        vote_id: EventId,
        /// Why the tally ignored it.
        reason: IgnoreReason,
    },
    /// A listed approval is counted but its decision is not `approve`.
    #[error("release claim not verified")]
    ApprovalNotApprove {
        /// The listed vote.
        vote_id: EventId,
        /// Its decision.
        decision: VoteDecision,
    },
    /// The listed approvals alone do not satisfy the circle policy (too few distinct
    /// approvers, or none besides the proposer when that is required).
    #[error("release claim not verified")]
    InsufficientEvidence {
        /// Distinct approvers among the listed approvals.
        listed: u32,
        /// Approvals the circle policy requires.
        need: u32,
    },
    /// The locally computed status is not eligible (includes the local policy).
    #[error("release claim not verified")]
    NotEligible(Box<ProposalStatus>),
}

impl ReleaseError {
    /// A stable machine-readable code.
    pub const fn code(&self) -> &'static str {
        match self {
            ReleaseError::WrongCircle => "wrong_circle",
            ReleaseError::WrongProposal => "wrong_proposal",
            ReleaseError::ScopeMismatch => "scope_mismatch",
            ReleaseError::DigestMismatch => "digest_mismatch",
            ReleaseError::SkillNameMismatch => "skill_name_mismatch",
            ReleaseError::Expired => "expired",
            ReleaseError::InvalidTime => "invalid_time",
            ReleaseError::PublisherNotAuthorized(_) => "publisher_not_authorized",
            ReleaseError::UnknownApproval(_) => "unknown_approval",
            ReleaseError::ApprovalIgnored { .. } => "approval_ignored",
            ReleaseError::ApprovalNotApprove { .. } => "approval_not_approve",
            ReleaseError::InsufficientEvidence { .. } => "insufficient_evidence",
            ReleaseError::NotEligible(_) => "not_eligible",
        }
    }

    /// A short human-readable description for the CLI (ids and codes, no peer text).
    pub fn describe(&self) -> String {
        match self {
            ReleaseError::WrongCircle => "release is for another circle".into(),
            ReleaseError::WrongProposal => "release references another proposal".into(),
            ReleaseError::ScopeMismatch => "release scope differs from the proposal".into(),
            ReleaseError::DigestMismatch => "release digest differs from the proposal".into(),
            ReleaseError::SkillNameMismatch => {
                "release skill name differs from the proposal".into()
            }
            ReleaseError::Expired => "release has expired".into(),
            ReleaseError::InvalidTime => {
                "release is future-dated or has an invalid lifetime".into()
            }
            ReleaseError::PublisherNotAuthorized(r) => {
                format!("publisher is not authorized to publish ({})", r.code())
            }
            ReleaseError::UnknownApproval(id) => format!("approval {id} is not stored locally"),
            ReleaseError::ApprovalIgnored { vote_id, reason } => {
                format!("approval {vote_id} does not count: {}", reason.describe())
            }
            ReleaseError::ApprovalNotApprove { vote_id, .. } => {
                format!("approval {vote_id} is not an approve decision")
            }
            ReleaseError::InsufficientEvidence { listed, need } => {
                format!("release lists {listed} valid approvers, circle policy needs {need}")
            }
            ReleaseError::NotEligible(status) => {
                let reasons: Vec<String> = status.blockers.iter().map(|b| b.describe()).collect();
                format!("proposal is not eligible locally: {}", reasons.join("; "))
            }
        }
    }
}

/// Verifies a RELEASE claim against the proposal and the locally stored votes at `now`.
///
/// Checks, in order:
/// 1. the release matches the proposal: circle, proposal id, scope, bundle digest and
///    skill name;
/// 2. the release envelope satisfies the event time rules at `now` (not expired, not
///    future-dated beyond the clock skew);
/// 3. the release author (publisher) holds `publish` on the proposal scope now;
/// 4. the local tally ([`evaluate_proposal`]) is computed from `votes`;
/// 5. every listed approval is a **counted** `approve` vote in that tally;
/// 6. the listed approvals by themselves satisfy the circle policy's approval count and
///    non-proposer rule;
/// 7. the local status is eligible (circle policy plus `local`).
///
/// On success returns the locally computed [`ProposalStatus`]. The release's own list is
/// never used to make anything count.
pub fn verify_release(
    release: &ReleaseView,
    proposal: &ProposalView,
    votes: &[VoteView],
    oracle: &dyn MembershipOracle,
    policy: &CirclePolicy,
    local: &LocalPolicy,
    now: Timestamp,
) -> Result<ProposalStatus, ReleaseError> {
    let result = verify_inner(release, proposal, votes, oracle, policy, local, now);
    match &result {
        Ok(_) => tracing::debug!(
            release_id = %release.event_id(),
            proposal_id = %proposal.event_id(),
            "release verified"
        ),
        Err(e) => tracing::debug!(
            release_id = %release.event_id(),
            proposal_id = %proposal.event_id(),
            code = e.code(),
            "release not verified"
        ),
    }
    result
}

fn verify_inner(
    release: &ReleaseView,
    proposal: &ProposalView,
    votes: &[VoteView],
    oracle: &dyn MembershipOracle,
    policy: &CirclePolicy,
    local: &LocalPolicy,
    now: Timestamp,
) -> Result<ProposalStatus, ReleaseError> {
    if release.circle_id() != proposal.circle_id() {
        return Err(ReleaseError::WrongCircle);
    }
    if release.proposal_id() != proposal.event_id() {
        return Err(ReleaseError::WrongProposal);
    }
    if release.scope() != proposal.scope() {
        return Err(ReleaseError::ScopeMismatch);
    }
    if release.bundle_digest() != proposal.bundle_digest() {
        return Err(ReleaseError::DigestMismatch);
    }
    if release.skill_name() != proposal.skill_name() {
        return Err(ReleaseError::SkillNameMismatch);
    }
    match time_check(release.created_at(), release.expires_at(), now) {
        TimeCheck::Valid => {}
        TimeCheck::Expired => return Err(ReleaseError::Expired),
        TimeCheck::Invalid => return Err(ReleaseError::InvalidTime),
    }
    oracle
        .authorize(
            &proposal.circle_id(),
            &release.publisher(),
            proposal.scope(),
            Capability::Publish,
            now,
        )
        .map_err(ReleaseError::PublisherNotAuthorized)?;

    let status = evaluate_proposal(proposal, votes, oracle, policy, local, now);

    let mut listed_voters = Vec::new();
    for id in release.approvals() {
        match status.counted_decision(id) {
            Some(d) if d.decision == VoteDecision::Approve => listed_voters.push(d.voter),
            Some(d) => {
                return Err(ReleaseError::ApprovalNotApprove {
                    vote_id: *id,
                    decision: d.decision,
                })
            }
            None => {
                return Err(match status.ignore_reason(id) {
                    Some(reason) => ReleaseError::ApprovalIgnored {
                        vote_id: *id,
                        reason,
                    },
                    None => ReleaseError::UnknownApproval(*id),
                })
            }
        }
    }
    listed_voters.sort();
    listed_voters.dedup();
    let listed = u32::try_from(listed_voters.len()).unwrap_or(u32::MAX);
    let need = policy.min_approvals.max(1);
    let non_proposer_ok =
        !policy.require_non_proposer || listed_voters.iter().any(|v| *v != proposal.author());
    if listed < need || !non_proposer_ok {
        return Err(ReleaseError::InsufficientEvidence { listed, need });
    }
    if !status.eligible {
        return Err(ReleaseError::NotEligible(Box::new(status)));
    }
    Ok(status)
}
