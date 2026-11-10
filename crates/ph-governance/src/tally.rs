//! Counting a vote (architecture sections 10.3, 10.5 and 10.6).
//!
//! [`tally`] takes one proposal, the charter it names, and the ballots this node holds
//! for it, and returns a [`Tally`]: who is in the electorate, how many approvals are
//! needed, which members have approved, which have dissented, which are silent, and
//! whether the proposal has passed.
//!
//! The rules:
//!
//! * **Per member, not per device.** A ballot counts for the member whose roll entry
//!   lists the signing device. Two devices of one member are one voter.
//! * **Majority of the whole electorate.** The proposal passes once approvals from
//!   `need(n, threshold)` distinct members exist, where `n` is the size of the
//!   electorate. Not voting counts the same as not approving.
//! * **No veto.** `reject` and `revise` ballots are recorded as dissent and shown with
//!   their rationale. They do not affect the count.
//! * **Approvals only accumulate.** A member has approved as soon as any valid `approve`
//!   ballot of theirs exists; a later `reject` does not undo it. "Passed" therefore
//!   never turns back into "not passed", and the result does not depend on the order in
//!   which ballots arrive.
//! * **No clock.** Nothing here looks at the time. Ballots do not expire.
//!
//! The result is a pure function of `(proposal, charter, ballots, revoked devices)`.
//! Two nodes holding the same inputs compute the same [`Tally`].

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use ph_core::{DeviceKey, Digest, EventId};
use ph_protocol::{Charter, CharterContent, ProposalKind, Threshold, VoteDecision};

use crate::views::{ProposalView, VoteView};

/// Why a ballot was not counted. Ordered roughly from structural to circumstantial.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum IgnoreReason {
    /// The same event id appeared more than once in the input.
    Duplicate,
    /// The ballot is for another circle.
    WrongCircle,
    /// The ballot is for another proposal.
    WrongProposal,
    /// The ballot's envelope scope differs from the proposal's.
    ScopeMismatch,
    /// The signing device is not on the roll of the charter the proposal names.
    NotOnRoll,
    /// The signing device belongs to a member outside this proposal's electorate.
    NotInElectorate,
    /// The signing device has a locally known revocation.
    Revoked,
    /// The member's standing is already decided by another of their ballots (a second
    /// approval, an older dissent, or a dissent from a member who has also approved).
    Redundant,
}

impl IgnoreReason {
    /// A stable machine-readable code.
    pub const fn code(self) -> &'static str {
        match self {
            IgnoreReason::Duplicate => "duplicate",
            IgnoreReason::WrongCircle => "wrong_circle",
            IgnoreReason::WrongProposal => "wrong_proposal",
            IgnoreReason::ScopeMismatch => "scope_mismatch",
            IgnoreReason::NotOnRoll => "not_on_roll",
            IgnoreReason::NotInElectorate => "not_in_electorate",
            IgnoreReason::Revoked => "revoked",
            IgnoreReason::Redundant => "redundant",
        }
    }
}

/// One member's approval and the ballot that evidences it.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Approval {
    /// The approving member.
    pub member: String,
    /// The device that signed the ballot.
    pub device: DeviceKey,
    /// The `approve` ballot. When a member has several, the one with the smallest event
    /// id is chosen so that every node lists the same one.
    pub vote_id: EventId,
}

/// One member's recorded dissent: their latest `reject` or `revise` ballot, for a member
/// who has not approved.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Dissent {
    /// The dissenting member.
    pub member: String,
    /// The device that signed the ballot.
    pub device: DeviceKey,
    /// The ballot.
    pub vote_id: EventId,
    /// `Reject` or `Revise`.
    pub decision: VoteDecision,
    /// Length of the rationale in characters (0 when absent). The text itself is
    /// peer-supplied: fetch it from the ballot for display, never log it.
    pub rationale_chars: usize,
}

/// Why a tally could not be computed at all.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, thiserror::Error)]
pub enum TallyError {
    /// The charter passed in is not the one the proposal names, or is for another circle.
    #[error("the charter is not the one this proposal names")]
    WrongCharter,
    /// The charter's digest could not be computed (it is outside the protocol's limits).
    #[error("the charter cannot be encoded")]
    InvalidCharter,
}

/// The outcome of counting the ballots held for one proposal.
///
/// Only [`tally`] and [`crate::verify_result`] produce one. Do not build or edit one by
/// hand, and never from peer or model output.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Tally {
    proposal_id: EventId,
    kind: ProposalKind,
    charter: Digest,
    threshold: Threshold,
    electorate: Vec<String>,
    need: usize,
    approvals: Vec<Approval>,
    dissent: Vec<Dissent>,
    silent: Vec<String>,
    ignored: Vec<(EventId, IgnoreReason)>,
}

impl Tally {
    /// The proposal that was counted.
    pub fn proposal_id(&self) -> EventId {
        self.proposal_id
    }
    /// Its kind.
    pub fn kind(&self) -> ProposalKind {
        self.kind
    }
    /// Digest of the charter it was counted under.
    pub fn charter(&self) -> Digest {
        self.charter
    }
    /// The threshold that applies (`rules.amend` for an amendment that changes the
    /// rules, `rules.pass` otherwise).
    pub fn threshold(&self) -> Threshold {
        self.threshold
    }
    /// The members entitled to vote, in roll order.
    pub fn electorate(&self) -> &[String] {
        &self.electorate
    }
    /// How many members must approve.
    pub fn need(&self) -> usize {
        self.need
    }
    /// The members who have approved, sorted by member, one entry each.
    pub fn approvals(&self) -> &[Approval] {
        &self.approvals
    }
    /// The members who have dissented and not approved, sorted by member.
    pub fn dissent(&self) -> &[Dissent] {
        &self.dissent
    }
    /// The members of the electorate with no counted ballot.
    pub fn silent(&self) -> &[String] {
        &self.silent
    }
    /// The ballots that were not counted, with the reason.
    pub fn ignored(&self) -> &[(EventId, IgnoreReason)] {
        &self.ignored
    }
    /// Why `vote_id` was not counted, if it was ignored.
    pub fn ignore_reason(&self, vote_id: &EventId) -> Option<IgnoreReason> {
        self.ignored
            .iter()
            .find(|(id, _)| id == vote_id)
            .map(|(_, r)| *r)
    }
    /// Whether enough members have approved. This says nothing about whether the
    /// charter is still the current one; see [`crate::ruleset`] and
    /// [`crate::succession`] for that.
    pub fn passed(&self) -> bool {
        self.approvals.len() >= self.need
    }
    /// How many more approvals are needed (0 once passed).
    pub fn missing(&self) -> usize {
        self.need.saturating_sub(self.approvals.len())
    }
    /// The ballots that evidence the approvals, sorted: the `approvals` member of a
    /// RESULT event. `None` until the proposal has passed.
    pub fn certificate(&self) -> Option<Vec<EventId>> {
        if !self.passed() {
            return None;
        }
        let mut ids: Vec<EventId> = self.approvals.iter().map(|a| a.vote_id).collect();
        ids.sort_by_key(EventId::to_string);
        Some(ids)
    }
    /// A one-line summary for the CLI, for example
    /// `"passed: 2 of 3 approved (2 needed), 1 dissenting"`.
    pub fn summary(&self) -> String {
        let state = if self.passed() { "passed" } else { "open" };
        let mut s = format!(
            "{state}: {} of {} approved ({} needed)",
            self.approvals.len(),
            self.electorate.len(),
            self.need
        );
        if !self.dissent.is_empty() {
            s.push_str(&format!(", {} dissenting", self.dissent.len()));
        }
        s
    }
}

impl fmt::Display for Tally {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.summary())
    }
}

/// The threshold that applies to `proposal` under `charter`: `rules.amend` for an
/// `amend` proposal whose proposed rules differ from the charter's, `rules.pass` for
/// everything else, including an amendment that only changes the roll.
pub fn threshold_for(proposal: &ProposalView, charter: &CharterContent) -> Threshold {
    match proposal.amend_next() {
        Some(next) if next.rules != charter.rules => charter.rules.amend,
        _ => charter.rules.pass,
    }
}

/// Counts the ballots held for `proposal`.
///
/// * `charter` must be the charter the proposal names (`proposal.charter()`), which
///   fixes the electorate and the threshold.
/// * `votes` may contain anything; ballots for other proposals, other circles, from
///   devices that are not on the roll or not in the electorate are ignored with a
///   reason.
/// * `is_revoked` reports devices with a locally known revocation. Their ballots are
///   not counted.
///
/// The result does not depend on the order of `votes`.
pub fn tally(
    proposal: &ProposalView,
    charter: &Charter,
    votes: &[VoteView],
    is_revoked: &dyn Fn(&DeviceKey) -> bool,
) -> Result<Tally, TallyError> {
    let digest = charter.digest().map_err(|_| TallyError::InvalidCharter)?;
    if digest != proposal.charter() || charter.circle_id != proposal.circle_id() {
        return Err(TallyError::WrongCharter);
    }
    let content = &charter.content;
    let electorate = proposal.electorate();
    let threshold = threshold_for(proposal, content);
    let members: Vec<String> = content
        .electorate(&electorate)
        .map(|e| e.member.clone())
        .collect();
    let need = threshold.need(members.len());

    let mut ignored: Vec<(EventId, IgnoreReason)> = Vec::new();
    let mut seen = HashSet::new();
    // member -> their valid ballots
    let mut by_member: BTreeMap<&str, Vec<&VoteView>> = BTreeMap::new();
    for v in votes {
        let id = v.event_id();
        let reason = if !seen.insert(id) {
            Some(IgnoreReason::Duplicate)
        } else if v.circle_id() != proposal.circle_id() {
            Some(IgnoreReason::WrongCircle)
        } else if v.proposal_id() != proposal.event_id() {
            Some(IgnoreReason::WrongProposal)
        } else if v.scope() != proposal.scope() {
            Some(IgnoreReason::ScopeMismatch)
        } else {
            match content.member_of(&v.voter()) {
                None => Some(IgnoreReason::NotOnRoll),
                Some(entry) if !CharterContent::in_electorate(entry, &electorate) => {
                    Some(IgnoreReason::NotInElectorate)
                }
                Some(_) if is_revoked(&v.voter()) => Some(IgnoreReason::Revoked),
                Some(entry) => {
                    by_member.entry(entry.member.as_str()).or_default().push(v);
                    None
                }
            }
        };
        if let Some(r) = reason {
            ignored.push((id, r));
        }
    }

    let mut approvals = Vec::new();
    let mut dissent = Vec::new();
    let mut redundant: HashSet<EventId> = HashSet::new();
    for (member, ballots) in &by_member {
        // Every node must pick the same ballot, whatever order they arrived in.
        let approval = ballots
            .iter()
            .filter(|v| v.decision() == VoteDecision::Approve)
            .min_by_key(|v| v.event_id().to_string());
        let counted = match approval {
            Some(v) => {
                approvals.push(Approval {
                    member: (*member).to_owned(),
                    device: v.voter(),
                    vote_id: v.event_id(),
                });
                Some(v.event_id())
            }
            None => {
                // No approval: the member's latest ballot is their recorded dissent.
                let latest = ballots
                    .iter()
                    .max_by_key(|v| (v.created_at(), v.event_id().to_string()));
                latest.map(|v| {
                    dissent.push(Dissent {
                        member: (*member).to_owned(),
                        device: v.voter(),
                        vote_id: v.event_id(),
                        decision: v.decision(),
                        rationale_chars: v.rationale_chars(),
                    });
                    v.event_id()
                })
            }
        };
        redundant.extend(
            ballots
                .iter()
                .map(|v| v.event_id())
                .filter(|id| Some(*id) != counted),
        );
    }
    // Report redundant ballots in input order, so the output is deterministic.
    for v in votes {
        let id = v.event_id();
        if redundant.remove(&id) {
            ignored.push((id, IgnoreReason::Redundant));
        }
    }

    let silent = members
        .iter()
        .filter(|m| !by_member.contains_key(m.as_str()))
        .cloned()
        .collect();

    let out = Tally {
        proposal_id: proposal.event_id(),
        kind: proposal.kind(),
        charter: digest,
        threshold,
        electorate: members,
        need,
        approvals,
        dissent,
        silent,
        ignored,
    };
    tracing::debug!(
        proposal_id = %out.proposal_id,
        kind = out.kind.as_str(),
        electorate = out.electorate.len(),
        need = out.need,
        approvals = out.approvals.len(),
        dissent = out.dissent.len(),
        ignored = out.ignored.len(),
        passed = out.passed(),
        "proposal tallied"
    );
    Ok(out)
}
