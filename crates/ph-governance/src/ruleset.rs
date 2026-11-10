//! The rules in force (architecture section 10.7).
//!
//! The rule set is a pure function of the current charter and the proposals that have
//! passed under it. It does not depend on the order in which anything arrived:
//!
//! ```text
//! A = charter.carried  ∪  { adopt proposals passed under the current charter }
//! R = { target of every repeal proposal passed under the current charter }
//! for each skill name s:
//!     winner(s) = the proposal in A named s with the greatest (created_at, event_id)
//!     s is in force, with winner(s)'s bundle, iff winner(s) ∉ R
//! ```
//!
//! A newer passed rule of the same name replaces the older one. Repealing the winner
//! leaves that name with no rule; an older one does not come back.
//!
//! A proposal enters this computation only through a [`Passed`] value, which can be
//! obtained in exactly two ways: from a [`Tally`] that has passed under the current
//! charter ([`Passed::by_vote`]), or because the current charter lists it in `carried`
//! ([`Passed::carried`]).

use std::collections::{BTreeMap, HashSet};

use ph_core::{Digest, EventId, Scope, Timestamp};
use ph_protocol::{Charter, ProposalKind};

use crate::tally::Tally;
use crate::views::ProposalView;

/// Why a proposal cannot be treated as passed under a charter.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, thiserror::Error)]
pub enum NotPassed {
    /// The tally is for another proposal.
    #[error("the tally is for another proposal")]
    WrongTally,
    /// The tally has not reached its threshold.
    #[error("the proposal has not reached its threshold")]
    BelowThreshold,
    /// The proposal names a charter other than the current one. It can no longer pass
    /// and must be proposed again.
    #[error("the proposal names a charter that is not the current one")]
    StaleCharter,
    /// The current charter does not list this proposal in `carried`.
    #[error("the current charter does not carry this proposal")]
    NotCarried,
    /// Only `adopt` proposals can be carried.
    #[error("only adopt proposals can be carried")]
    NotAnAdoption,
    /// The charter's digest could not be computed.
    #[error("the charter cannot be encoded")]
    InvalidCharter,
}

/// How a proposal came to count.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Basis {
    /// Enough members approved it under the current charter.
    Vote,
    /// The current charter carried it over from its predecessor.
    Carried,
}

/// A proposal that counts as passed under a specific charter. Fields are private: the
/// only constructors are [`Passed::by_vote`] and [`Passed::carried`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Passed {
    proposal: ProposalView,
    charter: Digest,
    basis: Basis,
}

impl Passed {
    /// A proposal that has passed by vote under `current`: `tally` is the tally of
    /// this proposal, it has reached its threshold, and the proposal names `current`.
    pub fn by_vote(
        proposal: &ProposalView,
        tally: &Tally,
        current: &Charter,
    ) -> Result<Self, NotPassed> {
        let digest = current.digest().map_err(|_| NotPassed::InvalidCharter)?;
        if tally.proposal_id() != proposal.event_id() {
            return Err(NotPassed::WrongTally);
        }
        if proposal.charter() != digest
            || tally.charter() != digest
            || proposal.circle_id() != current.circle_id
        {
            return Err(NotPassed::StaleCharter);
        }
        if !tally.passed() {
            return Err(NotPassed::BelowThreshold);
        }
        Ok(Self {
            proposal: proposal.clone(),
            charter: digest,
            basis: Basis::Vote,
        })
    }

    /// An `adopt` proposal that `current` lists in `carried`. The majority that
    /// approved `current` attested that it was in force, so its ballots are not
    /// re-counted.
    pub fn carried(proposal: &ProposalView, current: &Charter) -> Result<Self, NotPassed> {
        let digest = current.digest().map_err(|_| NotPassed::InvalidCharter)?;
        if proposal.kind() != ProposalKind::Adopt {
            return Err(NotPassed::NotAnAdoption);
        }
        if proposal.circle_id() != current.circle_id
            || !current.content.carried.contains(&proposal.event_id())
        {
            return Err(NotPassed::NotCarried);
        }
        Ok(Self {
            proposal: proposal.clone(),
            charter: digest,
            basis: Basis::Carried,
        })
    }

    /// The proposal.
    pub fn proposal(&self) -> &ProposalView {
        &self.proposal
    }
    /// How it came to count.
    pub fn basis(&self) -> Basis {
        self.basis
    }
    /// Digest of the charter it counts under.
    pub fn charter(&self) -> Digest {
        self.charter
    }
}

/// One rule in force.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Rule {
    skill_name: String,
    proposal_id: EventId,
    bundle_digest: Digest,
    bundle_size: u64,
    scope: Scope,
    proposed_at: Timestamp,
    basis: Basis,
}

impl Rule {
    /// The Agent Skills name. At most one rule per name is in force.
    pub fn skill_name(&self) -> &str {
        &self.skill_name
    }
    /// The `adopt` proposal that put it in force. This id identifies the rule: it is
    /// what `carried` lists and what a `repeal` proposal targets.
    pub fn proposal_id(&self) -> EventId {
        self.proposal_id
    }
    /// The bundle to install.
    pub fn bundle_digest(&self) -> Digest {
        self.bundle_digest
    }
    /// The bundle size in bytes, as stated by the proposal.
    pub fn bundle_size(&self) -> u64 {
        self.bundle_size
    }
    /// The scope it was adopted for.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    /// The proposal's `created_at` (used only to order rules of the same name).
    pub fn proposed_at(&self) -> Timestamp {
        self.proposed_at
    }
    /// Whether it passed under the current charter or was carried into it.
    pub fn basis(&self) -> Basis {
        self.basis
    }
}

/// The rules in force under one charter.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RuleSet {
    rules: BTreeMap<String, Rule>,
    missing_carried: Vec<EventId>,
}

impl RuleSet {
    /// The rules, sorted by skill name.
    pub fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules.values()
    }
    /// The rule named `skill_name`, if one is in force.
    pub fn get(&self, skill_name: &str) -> Option<&Rule> {
        self.rules.get(skill_name)
    }
    /// The rule adopted by `proposal_id`, if it is in force.
    pub fn by_proposal(&self, proposal_id: &EventId) -> Option<&Rule> {
        self.rules.values().find(|r| r.proposal_id == *proposal_id)
    }
    /// Number of rules in force.
    pub fn len(&self) -> usize {
        self.rules.len()
    }
    /// Whether no rule is in force.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
    /// Proposals the charter carries that were not supplied. The rule set is incomplete
    /// until the node has fetched them.
    pub fn missing_carried(&self) -> &[EventId] {
        &self.missing_carried
    }
    /// The ids of the rules in force, sorted: exactly what the `carried` member of the
    /// next charter must list to carry all of them forward.
    pub fn carried_ids(&self) -> Vec<EventId> {
        let mut ids: Vec<EventId> = self.rules.values().map(|r| r.proposal_id).collect();
        ids.sort_by_key(EventId::to_string);
        ids
    }
}

/// How a proposed `carried` list differs from the rules actually in force.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct CarriedDiff {
    /// Rules in force that the list drops. Approving the amendment repeals them.
    pub dropped: Vec<EventId>,
    /// Listed proposals that are not in force here. Approving the amendment puts them
    /// in force without their own vote.
    pub added: Vec<EventId>,
}

impl CarriedDiff {
    /// Whether the list carries exactly the rules in force.
    pub fn is_exact(&self) -> bool {
        self.dropped.is_empty() && self.added.is_empty()
    }
}

/// Compares the `carried` list of a proposed amendment with the rules in force. A
/// voter's node shows any difference before the human votes, because approving an
/// amendment also approves the rule set it carries forward.
pub fn carried_diff(proposed: &[EventId], in_force: &RuleSet) -> CarriedDiff {
    let current: HashSet<EventId> = in_force.rules.values().map(|r| r.proposal_id).collect();
    let listed: HashSet<EventId> = proposed.iter().copied().collect();
    let mut dropped: Vec<EventId> = current.difference(&listed).copied().collect();
    let mut added: Vec<EventId> = listed.difference(&current).copied().collect();
    dropped.sort_by_key(EventId::to_string);
    added.sort_by_key(EventId::to_string);
    CarriedDiff { dropped, added }
}

/// Computes the rules in force under `current` from the proposals that count under it.
///
/// `passed` may be in any order and may contain entries for other charters (ignored).
/// Carried proposals the caller did not supply are reported in
/// [`RuleSet::missing_carried`].
pub fn rules_in_force(current: &Charter, passed: &[Passed]) -> RuleSet {
    let Ok(digest) = current.digest() else {
        return RuleSet::default();
    };
    let mut repealed: HashSet<EventId> = HashSet::new();
    let mut winners: BTreeMap<String, Rule> = BTreeMap::new();
    let mut supplied: HashSet<EventId> = HashSet::new();
    for p in passed.iter().filter(|p| p.charter == digest) {
        let proposal = &p.proposal;
        if let Some(target) = proposal.repeal_target() {
            repealed.insert(target);
            continue;
        }
        let Some(adopt) = proposal.adopt() else {
            continue; // an amendment changes the charter, not the rule set
        };
        if p.basis == Basis::Carried {
            supplied.insert(proposal.event_id());
        }
        let rule = Rule {
            skill_name: adopt.skill_name.clone(),
            proposal_id: proposal.event_id(),
            bundle_digest: adopt.bundle_digest,
            bundle_size: adopt.bundle_size,
            scope: proposal.scope().clone(),
            proposed_at: proposal.created_at(),
            basis: p.basis,
        };
        let key = |r: &Rule| (r.proposed_at, r.proposal_id.to_string());
        match winners.get(&rule.skill_name) {
            Some(existing) if key(existing) >= key(&rule) => {}
            _ => {
                winners.insert(rule.skill_name.clone(), rule);
            }
        }
    }
    winners.retain(|_, r| !repealed.contains(&r.proposal_id));
    let missing_carried = current
        .content
        .carried
        .iter()
        .filter(|id| !supplied.contains(id))
        .copied()
        .collect();
    RuleSet {
        rules: winners,
        missing_carried,
    }
}
