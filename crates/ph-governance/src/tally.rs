//! Vote tally and eligibility (architecture section 10, spec section 8).
//!
//! [`evaluate_proposal`] is a pure function of the proposal, the locally stored votes,
//! the membership oracle at `now`, and the circle and local policies. Every node runs it
//! itself; nothing here trusts a peer's conclusion.
//!
//! ## Which votes count
//!
//! Each vote passes these checks in order; the first failure is recorded in
//! [`ProposalStatus::ignored`] with an [`IgnoreReason`]:
//!
//! 1. its event id was not already seen in this evaluation ([`IgnoreReason::Duplicate`];
//!    a replayed vote therefore counts once);
//! 2. `vote.circle_id == proposal.circle_id`;
//! 3. `vote.proposal_id == proposal.event_id`;
//! 4. `vote.bundle_digest == proposal.bundle_digest` (a vote for digest A never counts
//!    for a modified proposal with digest B);
//! 5. `vote.scope == proposal.scope` (a vote cast in a wider or narrower scope than the
//!    proposal is ignored; whether the voter may vote is decided on the proposal scope in
//!    step 7, never on the vote's own scope);
//! 6. the vote envelope satisfies the event time rules at `now`
//!    (`ph_protocol::check_time_rules`): not expired ([`IgnoreReason::Expired`]), and not
//!    future-dated beyond the clock skew nor with an impossible lifetime
//!    ([`IgnoreReason::InvalidTime`]);
//! 7. the voter is authorized for `vote` on the proposal scope at `now`
//!    (`oracle.authorize`), which applies acceptance, expiry and revocation, so a revoked
//!    voter's earlier approval stops counting and self-made keys without root-issued
//!    credentials never count;
//! 8. one decision per voter: only the voter's latest vote by `(created_at, event_id)`
//!    counts; earlier ones get [`IgnoreReason::Replaced`].
//!
//! ### Ordering by the claimed `created_at`
//!
//! `created_at` is chosen by the voter, so it is only trusted to order **that voter's
//! own** votes: no timestamp can add, remove or change anyone else's decision. Step 6
//! bounds it: a vote whose `created_at` is later than `now + CLOCK_SKEW_SECS` (5 min) is
//! not counted at all (rather than capped), so a vote pinned far in the future (for
//! example signed with a briefly stolen key, or accepted by a node with a wrong clock)
//! can never permanently override the voter's later votes. Within the skew window a
//! voter's own clock error can still make an older vote win for a few minutes. The
//! latest vote is picked among the votes that pass steps 1-6, so when a voter's newest
//! vote expires, their newest still-valid vote counts again (default vote lifetimes are
//! equal, so this only happens with a deliberately shortened lifetime).
//!
//! ## Eligibility
//!
//! The proposal is eligible iff [`ProposalStatus::blockers`] is empty, where blockers are:
//!
//! * fewer distinct approvers than `max(circle.min_approvals, local.extra_min_approvals, 1)`;
//! * `require_non_proposer` and no approver other than the proposal author;
//! * `block_on_reject` and any counted latest decision of `reject` or `revise`;
//! * a `LocalPolicy::required_approvers` key that is not among the approvers;
//! * the proposal envelope has expired at `now`, or fails the other event time rules
//!   (future-dated beyond the clock skew, impossible lifetime);
//! * the proposal author is no longer authorized to `propose` in the proposal scope at
//!   `now` (for example revoked after proposing).

use std::collections::{BTreeMap, HashSet};
use std::fmt::{self, Write as _};

use ph_core::{Capability, DenyReason, DeviceKey, EventId, MembershipOracle, Timestamp};
use ph_protocol::{check_time_rules, ProtocolError, TimeRule, VoteDecision};

use crate::policy::{CirclePolicy, LocalPolicy};
use crate::views::{ProposalView, VoteView};

/// Why a vote was not counted.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum IgnoreReason {
    /// The same event id was already processed in this evaluation.
    Duplicate,
    /// The vote is for a different circle.
    WrongCircle,
    /// The vote signs a different proposal id.
    WrongProposal,
    /// The vote signs a different bundle digest.
    DigestMismatch,
    /// The vote envelope scope differs from the proposal scope.
    ScopeMismatch,
    /// The vote envelope has expired.
    Expired,
    /// The vote envelope fails the other event time rules at evaluation time: its
    /// `created_at` is more than the clock skew in the future, or its lifetime is
    /// impossible (`expires_at <= created_at` or over 400 days). Such a vote could not
    /// pass intake now.
    InvalidTime,
    /// The voter is not authorized to vote on the proposal scope now.
    VoterNotAuthorized(DenyReason),
    /// A later vote by the same voter replaced this one.
    Replaced,
}

impl IgnoreReason {
    /// A stable machine-readable code.
    pub const fn code(self) -> &'static str {
        match self {
            IgnoreReason::Duplicate => "duplicate",
            IgnoreReason::WrongCircle => "wrong_circle",
            IgnoreReason::WrongProposal => "wrong_proposal",
            IgnoreReason::DigestMismatch => "digest_mismatch",
            IgnoreReason::ScopeMismatch => "scope_mismatch",
            IgnoreReason::Expired => "expired",
            IgnoreReason::InvalidTime => "invalid_time",
            IgnoreReason::VoterNotAuthorized(_) => "voter_not_authorized",
            IgnoreReason::Replaced => "replaced",
        }
    }

    /// A short human-readable description for the CLI.
    pub fn describe(self) -> String {
        match self {
            IgnoreReason::Duplicate => "duplicate of an event already processed".into(),
            IgnoreReason::WrongCircle => "vote is for another circle".into(),
            IgnoreReason::WrongProposal => "vote is for another proposal".into(),
            IgnoreReason::DigestMismatch => "vote signs a different bundle digest".into(),
            IgnoreReason::ScopeMismatch => "vote scope differs from the proposal scope".into(),
            IgnoreReason::Expired => "vote has expired".into(),
            IgnoreReason::InvalidTime => "vote is future-dated or has an invalid lifetime".into(),
            IgnoreReason::VoterNotAuthorized(r) => {
                format!("voter is not an eligible voter ({})", r.code())
            }
            IgnoreReason::Replaced => "replaced by a later vote from the same voter".into(),
        }
    }
}

/// Something that keeps a proposal from being eligible.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Blocker {
    /// Fewer distinct eligible approvers than required.
    NotEnoughApprovals {
        /// Distinct eligible approvers.
        have: u32,
        /// Required approvers.
        need: u32,
    },
    /// `require_non_proposer`: every approver is the proposal author.
    NoNonProposerApproval,
    /// `block_on_reject`: this eligible voter's latest decision is `reject`.
    Rejected(DeviceKey),
    /// `block_on_reject`: this eligible voter's latest decision is `revise`.
    RevisionRequested(DeviceKey),
    /// Local policy: this key must approve but has not.
    MissingRequiredApprover(DeviceKey),
    /// The proposal envelope has expired.
    ProposalExpired,
    /// The proposal envelope fails the other event time rules at evaluation time
    /// (future-dated beyond the clock skew, or an impossible lifetime).
    ProposalInvalidTime,
    /// The proposal author is no longer authorized to propose in the proposal scope.
    ProposerNotAuthorized(DenyReason),
}

impl Blocker {
    /// A stable machine-readable code.
    pub const fn code(&self) -> &'static str {
        match self {
            Blocker::NotEnoughApprovals { .. } => "not_enough_approvals",
            Blocker::NoNonProposerApproval => "no_non_proposer_approval",
            Blocker::Rejected(_) => "rejected",
            Blocker::RevisionRequested(_) => "revision_requested",
            Blocker::MissingRequiredApprover(_) => "missing_required_approver",
            Blocker::ProposalExpired => "proposal_expired",
            Blocker::ProposalInvalidTime => "proposal_invalid_time",
            Blocker::ProposerNotAuthorized(_) => "proposer_not_authorized",
        }
    }

    /// A short human-readable description for the CLI (fingerprints, no peer text).
    pub fn describe(&self) -> String {
        match self {
            Blocker::NotEnoughApprovals { have, need } => {
                format!("{have} of {need} required approvals")
            }
            Blocker::NoNonProposerApproval => {
                "needs an approval from someone other than the proposer".into()
            }
            Blocker::Rejected(k) => format!("rejected by {}", k.fingerprint()),
            Blocker::RevisionRequested(k) => format!("revision requested by {}", k.fingerprint()),
            Blocker::MissingRequiredApprover(k) => {
                format!("local policy requires approval by {}", k.fingerprint())
            }
            Blocker::ProposalExpired => "proposal has expired".into(),
            Blocker::ProposalInvalidTime => {
                "proposal is future-dated or has an invalid lifetime".into()
            }
            Blocker::ProposerNotAuthorized(r) => {
                format!("proposer is no longer authorized ({})", r.code())
            }
        }
    }
}

/// One eligible voter's counted (latest) decision.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct VoterDecision {
    /// The voter.
    pub voter: DeviceKey,
    /// Their latest decision.
    pub decision: VoteDecision,
    /// The counted vote's event id.
    pub vote_id: EventId,
    /// The counted vote's claimed creation time.
    pub created_at: Timestamp,
    /// Rationale length in characters (0 when absent). The text itself is available from
    /// the [`VoteView`].
    pub rationale_chars: usize,
}

/// The locally computed state of a proposal. See the [module docs](self).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProposalStatus {
    /// The evaluated proposal.
    pub proposal_id: EventId,
    /// Its author.
    pub proposer: DeviceKey,
    /// Distinct eligible voters whose latest decision is `approve`, sorted.
    pub approvers: Vec<DeviceKey>,
    /// Distinct eligible voters whose latest decision is `reject`, sorted.
    pub rejecters: Vec<DeviceKey>,
    /// Distinct eligible voters whose latest decision is `revise`, sorted.
    pub revisers: Vec<DeviceKey>,
    /// Event ids of the counted votes (one per eligible voter), sorted by voter.
    pub counted_votes: Vec<EventId>,
    /// Every vote occurrence that was not counted, in input order, with the reason. A
    /// duplicate of a counted vote appears here once as [`IgnoreReason::Duplicate`].
    pub ignored: Vec<(EventId, IgnoreReason)>,
    /// The counted decisions, sorted by voter.
    pub decisions: Vec<VoterDecision>,
    /// The approval count required after applying the local policy.
    pub required_approvals: u32,
    /// `true` iff `blockers` is empty.
    pub eligible: bool,
    /// Everything that prevents eligibility (empty when eligible).
    pub blockers: Vec<Blocker>,
}

impl ProposalStatus {
    /// The counted decision for `vote_id`, if that vote was counted.
    pub fn counted_decision(&self, vote_id: &EventId) -> Option<&VoterDecision> {
        self.decisions.iter().find(|d| &d.vote_id == vote_id)
    }

    /// Why `vote_id` was ignored, if it was. When the vote occurred several times, the
    /// substantive reason recorded for its first occurrence (for example
    /// [`IgnoreReason::VoterNotAuthorized`]) is returned in preference to
    /// [`IgnoreReason::Duplicate`]; `Duplicate` alone means the first occurrence was
    /// counted (see [`ProposalStatus::counted_decision`]).
    pub fn ignore_reason(&self, vote_id: &EventId) -> Option<IgnoreReason> {
        let mut reasons = self
            .ignored
            .iter()
            .filter(|(id, _)| id == vote_id)
            .map(|(_, r)| *r);
        let first = reasons.next()?;
        if first != IgnoreReason::Duplicate {
            return Some(first);
        }
        Some(
            reasons
                .find(|r| *r != IgnoreReason::Duplicate)
                .unwrap_or(IgnoreReason::Duplicate),
        )
    }

    /// A multi-line, human-readable explanation for `proposal status`: eligibility,
    /// required approvals, each counted decision with the signer fingerprint and
    /// rationale length, blockers, and ignored votes with reasons. It contains no
    /// peer-supplied text.
    pub fn explain(&self) -> String {
        let mut s = String::new();
        let verdict = if self.eligible {
            "ELIGIBLE"
        } else {
            "NOT ELIGIBLE"
        };
        let _ = writeln!(s, "proposal {}", self.proposal_id);
        let _ = writeln!(s, "  proposer: {}", self.proposer.fingerprint());
        let _ = writeln!(s, "  status:   {verdict} (computed locally)");
        let _ = writeln!(
            s,
            "  approvals: {} of {} required",
            self.approvers.len(),
            self.required_approvals
        );
        if self.decisions.is_empty() {
            let _ = writeln!(s, "  decisions: none counted");
        } else {
            let _ = writeln!(s, "  decisions:");
            for d in &self.decisions {
                let who = if d.voter == self.proposer {
                    " (proposer)"
                } else {
                    ""
                };
                let decision = match d.decision {
                    VoteDecision::Approve => "approve",
                    VoteDecision::Reject => "reject",
                    VoteDecision::Revise => "revise",
                };
                let _ = writeln!(
                    s,
                    "    {decision:<7} {}{who}  at {}  rationale: {} chars  vote {}",
                    d.voter.fingerprint(),
                    d.created_at,
                    d.rationale_chars,
                    d.vote_id
                );
            }
        }
        if !self.blockers.is_empty() {
            let _ = writeln!(s, "  blockers:");
            for b in &self.blockers {
                let _ = writeln!(s, "    - {}", b.describe());
            }
        }
        if !self.ignored.is_empty() {
            let _ = writeln!(s, "  ignored votes: {}", self.ignored.len());
            for (id, r) in &self.ignored {
                let _ = writeln!(s, "    {id}: {}", r.describe());
            }
        }
        s
    }
}

impl fmt::Display for ProposalStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.explain())
    }
}

/// The outcome of the event time rules at evaluation time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TimeCheck {
    /// All time rules hold.
    Valid,
    /// Well-formed but `expires_at <= now`.
    Expired,
    /// Future-dated beyond the clock skew, or an impossible lifetime.
    Invalid,
}

/// Applies `ph_protocol::check_time_rules` at `now` and classifies the result.
pub(crate) fn time_check(
    created_at: Timestamp,
    expires_at: Timestamp,
    now: Timestamp,
) -> TimeCheck {
    match check_time_rules(created_at, expires_at, now) {
        Ok(()) => TimeCheck::Valid,
        Err(ProtocolError::Time {
            rule: TimeRule::Expired,
            ..
        }) => TimeCheck::Expired,
        Err(_) => TimeCheck::Invalid,
    }
}

/// Evaluates `proposal` against the locally stored `votes` at local time `now`.
///
/// `votes` may contain anything (votes for other proposals, duplicates, unauthorized
/// voters); see the [module docs](self) for the exact counting and eligibility rules.
/// The result is deterministic for a given input set, regardless of vote order (except
/// the order of [`ProposalStatus::ignored`], which follows the input).
pub fn evaluate_proposal(
    proposal: &ProposalView,
    votes: &[VoteView],
    oracle: &dyn MembershipOracle,
    policy: &CirclePolicy,
    local: &LocalPolicy,
    now: Timestamp,
) -> ProposalStatus {
    let circle = proposal.circle_id();
    let scope = proposal.scope();
    let mut ignored = Vec::new();
    let mut seen = HashSet::new();
    let mut by_voter: BTreeMap<DeviceKey, Vec<&VoteView>> = BTreeMap::new();

    for v in votes {
        let id = v.event_id();
        let reason = if !seen.insert(id) {
            Some(IgnoreReason::Duplicate)
        } else if v.circle_id() != circle {
            Some(IgnoreReason::WrongCircle)
        } else if v.proposal_id() != proposal.event_id() {
            Some(IgnoreReason::WrongProposal)
        } else if v.bundle_digest() != proposal.bundle_digest() {
            Some(IgnoreReason::DigestMismatch)
        } else if v.scope() != scope {
            Some(IgnoreReason::ScopeMismatch)
        } else {
            match time_check(v.created_at(), v.expires_at(), now) {
                TimeCheck::Valid => None,
                TimeCheck::Expired => Some(IgnoreReason::Expired),
                TimeCheck::Invalid => Some(IgnoreReason::InvalidTime),
            }
        };
        match reason {
            Some(r) => ignored.push((id, r)),
            None => by_voter.entry(v.voter()).or_default().push(v),
        }
    }

    let mut decisions = Vec::new();
    for (voter, vs) in &by_voter {
        if let Err(r) = oracle.authorize(&circle, voter, scope, Capability::Vote, now) {
            ignored.extend(
                vs.iter()
                    .map(|v| (v.event_id(), IgnoreReason::VoterNotAuthorized(r))),
            );
            continue;
        }
        let Some(latest) = vs.iter().max_by_key(|v| (v.created_at(), v.event_id())) else {
            continue;
        };
        ignored.extend(
            vs.iter()
                .filter(|v| v.event_id() != latest.event_id())
                .map(|v| (v.event_id(), IgnoreReason::Replaced)),
        );
        decisions.push(VoterDecision {
            voter: *voter,
            decision: latest.decision(),
            vote_id: latest.event_id(),
            created_at: latest.created_at(),
            rationale_chars: latest.rationale_chars(),
        });
    }

    let pick = |want: VoteDecision| -> Vec<DeviceKey> {
        decisions
            .iter()
            .filter(|d| d.decision == want)
            .map(|d| d.voter)
            .collect()
    };
    let approvers = pick(VoteDecision::Approve);
    let rejecters = pick(VoteDecision::Reject);
    let revisers = pick(VoteDecision::Revise);
    let required = policy.required_approvals(local);
    let proposer = proposal.author();

    let mut blockers = Vec::new();
    let have = u32::try_from(approvers.len()).unwrap_or(u32::MAX);
    if have < required {
        blockers.push(Blocker::NotEnoughApprovals {
            have,
            need: required,
        });
    }
    if policy.require_non_proposer && !approvers.iter().any(|a| *a != proposer) {
        blockers.push(Blocker::NoNonProposerApproval);
    }
    if policy.block_on_reject {
        blockers.extend(rejecters.iter().copied().map(Blocker::Rejected));
        blockers.extend(revisers.iter().copied().map(Blocker::RevisionRequested));
    }
    let mut required_keys: Vec<DeviceKey> = local.required_approvers.clone();
    required_keys.sort();
    required_keys.dedup();
    blockers.extend(
        required_keys
            .into_iter()
            .filter(|k| !approvers.contains(k))
            .map(Blocker::MissingRequiredApprover),
    );
    match time_check(proposal.created_at(), proposal.expires_at(), now) {
        TimeCheck::Valid => {}
        TimeCheck::Expired => blockers.push(Blocker::ProposalExpired),
        TimeCheck::Invalid => blockers.push(Blocker::ProposalInvalidTime),
    }
    if let Err(r) = oracle.authorize(&circle, &proposer, scope, Capability::Propose, now) {
        blockers.push(Blocker::ProposerNotAuthorized(r));
    }

    let eligible = blockers.is_empty();
    tracing::debug!(
        proposal_id = %proposal.event_id(),
        approvals = approvers.len(),
        required,
        counted = decisions.len(),
        ignored = ignored.len(),
        eligible,
        "proposal evaluated"
    );
    ProposalStatus {
        proposal_id: proposal.event_id(),
        proposer,
        counted_votes: decisions.iter().map(|d| d.vote_id).collect(),
        approvers,
        rejecters,
        revisers,
        ignored,
        decisions,
        required_approvals: required,
        eligible,
        blockers,
    }
}
