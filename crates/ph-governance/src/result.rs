//! Result certificates (architecture section 10.6).
//!
//! A RESULT event lists the `approve` ballots that carry a proposal over its threshold.
//! It has no authority of its own: [`verify_result`] counts exactly the listed ballots
//! under the charter the proposal names and accepts the certificate only if they are
//! enough. A node that already holds those ballots reaches the same conclusion without
//! the certificate; the certificate just lets it get there without waiting for every
//! ballot to arrive on its own.
//!
//! Verification uses signatures and the roll only. It does not look at a clock, so a
//! certificate that verifies today verifies forever.

use std::collections::HashMap;

use ph_core::{DeviceKey, EventId};
use ph_protocol::{Charter, CharterContent};

use crate::tally::{tally, IgnoreReason, Tally, TallyError};
use crate::views::{ProposalView, ResultView, VoteView};

/// Why a RESULT was not accepted. `Display` never includes peer-supplied text.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, thiserror::Error)]
pub enum ResultError {
    /// The result is for another proposal, circle or scope than the proposal passed in.
    #[error("the result does not match the proposal")]
    WrongProposal,
    /// The device that assembled the result is not a member of the proposal's
    /// electorate under the charter the proposal names.
    #[error("the result was not assembled by a member of the electorate")]
    AssemblerNotInElectorate,
    /// A listed ballot is not among the ballots supplied. The caller should fetch it
    /// and verify again; this is not evidence of a bad certificate.
    #[error("a listed ballot is not available locally")]
    MissingBallot(EventId),
    /// A listed ballot does not count as an approval of this proposal (wrong proposal,
    /// not on the roll, revoked, a second ballot from the same member, ...).
    #[error("a listed ballot does not count")]
    BallotNotCounted {
        /// The ballot.
        vote_id: EventId,
        /// Why the tally ignored it.
        reason: IgnoreReason,
    },
    /// A listed ballot is a `reject` or `revise`, not an approval.
    #[error("a listed ballot is not an approval")]
    NotAnApproval(EventId),
    /// The listed ballots are valid approvals but there are not enough of them.
    #[error("the listed approvals do not reach the threshold")]
    BelowThreshold {
        /// Approving members among the listed ballots.
        have: usize,
        /// Approvals needed.
        need: usize,
    },
    /// The charter passed in is not the one the proposal names.
    #[error("the charter is not the one this proposal names")]
    WrongCharter,
}

impl ResultError {
    /// Whether verifying again later can succeed without anything being wrong now: the
    /// node simply lacks a ballot.
    pub const fn is_retryable(&self) -> bool {
        matches!(self, ResultError::MissingBallot(_))
    }

    /// A stable machine-readable code.
    pub const fn code(&self) -> &'static str {
        match self {
            ResultError::WrongProposal => "wrong_proposal",
            ResultError::AssemblerNotInElectorate => "assembler_not_in_electorate",
            ResultError::MissingBallot(_) => "missing_ballot",
            ResultError::BallotNotCounted { .. } => "ballot_not_counted",
            ResultError::NotAnApproval(_) => "not_an_approval",
            ResultError::BelowThreshold { .. } => "below_threshold",
            ResultError::WrongCharter => "wrong_charter",
        }
    }
}

impl From<TallyError> for ResultError {
    fn from(_: TallyError) -> Self {
        ResultError::WrongCharter
    }
}

/// Verifies a RESULT against the ballots it lists.
///
/// * `proposal` is the proposal the result names and `charter` the charter that
///   proposal names.
/// * `votes` are ballots this node holds (already signature-verified views). Only the
///   ones the result lists are counted; extra ones are ignored.
/// * `is_revoked` reports devices with a locally known revocation.
///
/// On success the returned [`Tally`] is the count of exactly the listed ballots, and
/// [`Tally::passed`] is true.
pub fn verify_result(
    result: &ResultView,
    proposal: &ProposalView,
    charter: &Charter,
    votes: &[VoteView],
    is_revoked: &dyn Fn(&DeviceKey) -> bool,
) -> Result<Tally, ResultError> {
    if result.proposal_id() != proposal.event_id()
        || result.circle_id() != proposal.circle_id()
        || result.scope() != proposal.scope()
    {
        return Err(ResultError::WrongProposal);
    }
    let by_id: HashMap<EventId, &VoteView> = votes.iter().map(|v| (v.event_id(), v)).collect();
    let mut listed = Vec::with_capacity(result.approvals().len());
    for id in result.approvals() {
        match by_id.get(id) {
            Some(v) => listed.push((*v).clone()),
            None => return Err(ResultError::MissingBallot(*id)),
        }
    }
    let counted = tally(proposal, charter, &listed, is_revoked)?;
    if charter
        .content
        .voter(&result.assembler(), &proposal.electorate())
        .is_none()
    {
        return Err(ResultError::AssemblerNotInElectorate);
    }
    // Every listed ballot must be the counted approval of a distinct member.
    for id in result.approvals() {
        if let Some(reason) = counted.ignore_reason(id) {
            return Err(ResultError::BallotNotCounted {
                vote_id: *id,
                reason,
            });
        }
        if !counted.approvals().iter().any(|a| a.vote_id == *id) {
            return Err(ResultError::NotAnApproval(*id));
        }
    }
    if !counted.passed() {
        return Err(ResultError::BelowThreshold {
            have: counted.approvals().len(),
            need: counted.need(),
        });
    }
    tracing::debug!(
        result_id = %result.event_id(),
        proposal_id = %proposal.event_id(),
        approvals = counted.approvals().len(),
        need = counted.need(),
        "result verified"
    );
    Ok(counted)
}

/// Whether `device` may author decision events about `proposal` under `content`: it
/// signs for a member of the proposal's electorate.
pub fn in_electorate(
    content: &CharterContent,
    proposal: &ProposalView,
    device: &DeviceKey,
) -> bool {
    content.voter(device, &proposal.electorate()).is_some()
}
