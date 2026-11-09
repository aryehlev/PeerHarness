//! The final gate before a received skill is installed (spec sections 7.3, 9 and 11).
//!
//! No accepted action depends on trusting LLM-generated authorization decisions.
//!
//! [`adoption_readiness`] takes only verification results computed by deterministic code
//! (the local tally, the bundle digest check in `ph-skills`, the skill validator) and the
//! human's explicit confirmation. Advisory agent output must never be passed for any of
//! these inputs.

use crate::tally::ProposalStatus;

/// Why a skill is not ready to adopt.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum NotReadyReason {
    /// The locally computed proposal status is not eligible.
    ProposalNotEligible,
    /// The bundle bytes were not verified against the proposal's `bundle_digest`.
    BundleDigestUnverified,
    /// The bundle failed strict skill validation (frontmatter, name, paths, size).
    SkillInvalid,
    /// The human has not confirmed the install (after seeing the diff and warnings).
    AwaitingHumanConfirmation,
}

impl NotReadyReason {
    /// A stable machine-readable code.
    pub const fn code(self) -> &'static str {
        match self {
            NotReadyReason::ProposalNotEligible => "proposal_not_eligible",
            NotReadyReason::BundleDigestUnverified => "bundle_digest_unverified",
            NotReadyReason::SkillInvalid => "skill_invalid",
            NotReadyReason::AwaitingHumanConfirmation => "awaiting_human_confirmation",
        }
    }
}

/// Whether adoption may proceed.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Readiness {
    /// Every check passed and the human confirmed.
    Ready,
    /// The unmet conditions, in a fixed order (eligibility, digest, validity, human).
    NotReady(Vec<NotReadyReason>),
}

impl Readiness {
    /// `true` for [`Readiness::Ready`].
    pub fn is_ready(&self) -> bool {
        matches!(self, Readiness::Ready)
    }

    /// The unmet conditions (empty when ready).
    pub fn reasons(&self) -> &[NotReadyReason] {
        match self {
            Readiness::Ready => &[],
            Readiness::NotReady(r) => r,
        }
    }
}

/// Combines the deterministic verification results with the human's confirmation.
///
/// No accepted action depends on trusting LLM-generated authorization decisions.
///
/// * `status`: from [`evaluate_proposal`](crate::evaluate_proposal) or
///   [`verify_release`](crate::verify_release), computed locally just now. It counts as
///   eligible only if `eligible` is set, `blockers` is empty **and** it is internally
///   consistent (`required_approvals >= 1` and at least that many `approvers`), so a
///   status edited after the fact to claim eligibility is still refused. Never build a
///   `ProposalStatus` by hand or from deserialized/peer/LLM data.
/// * `bundle_digest_verified`: the fetched bundle's recomputed digest equals the
///   proposal's `bundle_digest`.
/// * `skill_valid`: strict `ph-skills` validation of the bundle succeeded.
/// * `human_confirmed`: the human explicitly confirmed this install in the CLI. Never
///   derived from an agent's or peer's output.
pub fn adoption_readiness(
    status: &ProposalStatus,
    bundle_digest_verified: bool,
    skill_valid: bool,
    human_confirmed: bool,
) -> Readiness {
    let mut missing = Vec::new();
    let quorum_consistent = status.required_approvals >= 1
        && u32::try_from(status.approvers.len()).unwrap_or(u32::MAX) >= status.required_approvals;
    if !status.eligible || !status.blockers.is_empty() || !quorum_consistent {
        missing.push(NotReadyReason::ProposalNotEligible);
    }
    if !bundle_digest_verified {
        missing.push(NotReadyReason::BundleDigestUnverified);
    }
    if !skill_valid {
        missing.push(NotReadyReason::SkillInvalid);
    }
    if !human_confirmed {
        missing.push(NotReadyReason::AwaitingHumanConfirmation);
    }
    if missing.is_empty() {
        Readiness::Ready
    } else {
        Readiness::NotReady(missing)
    }
}
