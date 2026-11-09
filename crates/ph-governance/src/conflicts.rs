//! Conflicting proposals and supersede lineage (architecture section 10, spec 6.4/8).
//!
//! There is no canonical answer and no global ordering. Proposals for the same skill in
//! the same circle and scope with different bundle digests are **alternatives** that
//! coexist; each is evaluated on its own votes until the responsible people resolve the
//! conflict (for example by rejecting one).
//!
//! `PROPOSAL.supersedes` marks lineage only. **Votes never transfer**: a vote signs one
//! proposal id and digest, so a superseding proposal starts with zero votes, and the
//! superseded proposal keeps its own votes and stays evaluable. Superseding is not a
//! veto: a member cannot block someone else's proposal by "superseding" it. The CLI may
//! show lineage and, on a human action, mark a local candidate `Superseded`.

use std::collections::{BTreeMap, HashMap};

use ph_core::{CircleId, Digest, EventId, Scope, Timestamp};

use crate::views::ProposalView;

/// What makes proposals compete: the same circle, scope and skill name.
#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct ConflictKey {
    /// Circle.
    pub circle_id: CircleId,
    /// Proposal scope.
    pub scope: Scope,
    /// Skill name.
    pub skill_name: String,
}

/// One alternative: the proposals (possibly several, e.g. re-proposals) that share a
/// bundle digest.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Alternative {
    /// The bundle digest.
    pub bundle_digest: Digest,
    /// Proposals with this digest, sorted by `(created_at, event_id)`.
    pub proposals: Vec<EventId>,
}

/// A set of competing alternatives (at least two distinct digests).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConflictGroup {
    /// The shared key.
    pub key: ConflictKey,
    /// Alternatives sorted by digest; always at least two.
    pub alternatives: Vec<Alternative>,
}

/// Groups `proposals` by `(circle, scope, skill_name)` and returns the groups that have
/// at least two distinct bundle digests. Duplicate event ids are counted once. Output
/// order is deterministic (sorted by key, then digest, then `(created_at, event_id)`).
pub fn find_conflicts(proposals: &[ProposalView]) -> Vec<ConflictGroup> {
    type Members = BTreeMap<Digest, Vec<(Timestamp, EventId)>>;
    let mut groups: BTreeMap<ConflictKey, Members> = BTreeMap::new();
    for p in proposals {
        let key = ConflictKey {
            circle_id: p.circle_id(),
            scope: p.scope().clone(),
            skill_name: p.skill_name().to_owned(),
        };
        let members = groups
            .entry(key)
            .or_default()
            .entry(p.bundle_digest())
            .or_default();
        let entry = (p.created_at(), p.event_id());
        if !members.contains(&entry) {
            members.push(entry);
        }
    }
    groups
        .into_iter()
        .filter(|(_, by_digest)| by_digest.len() >= 2)
        .map(|(key, by_digest)| ConflictGroup {
            key,
            alternatives: by_digest
                .into_iter()
                .map(|(bundle_digest, mut ps)| {
                    ps.sort();
                    Alternative {
                        bundle_digest,
                        proposals: ps.into_iter().map(|(_, id)| id).collect(),
                    }
                })
                .collect(),
        })
        .collect()
}

/// How a `supersedes` link relates the two proposals.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SupersedeKind {
    /// Same circle and skill name, same author: the author revising their own proposal.
    SameAuthor,
    /// Same circle and skill name, different author: an alternative claiming lineage.
    DifferentAuthor,
    /// The superseded proposal is not in the given set (not stored yet).
    Unresolved,
    /// The superseded proposal is in another circle or for another skill name; the link
    /// is meaningless and should be ignored.
    Invalid,
}

/// One `supersedes` reference.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SupersedeLink {
    /// The newer proposal that declares `supersedes`.
    pub superseding: EventId,
    /// The referenced older proposal.
    pub superseded: EventId,
    /// How the two relate.
    pub kind: SupersedeKind,
}

/// Every `supersedes` reference among `proposals`, sorted by `(superseded,
/// superseding)`. Duplicate event ids are counted once.
pub fn supersede_links(proposals: &[ProposalView]) -> Vec<SupersedeLink> {
    let by_id: HashMap<EventId, &ProposalView> =
        proposals.iter().map(|p| (p.event_id(), p)).collect();
    let mut links: Vec<SupersedeLink> = by_id
        .values()
        .filter_map(|p| {
            let target = p.supersedes()?;
            let kind = match by_id.get(&target) {
                None => SupersedeKind::Unresolved,
                Some(old)
                    if old.circle_id() != p.circle_id() || old.skill_name() != p.skill_name() =>
                {
                    SupersedeKind::Invalid
                }
                Some(old) if old.author() == p.author() => SupersedeKind::SameAuthor,
                Some(_) => SupersedeKind::DifferentAuthor,
            };
            Some(SupersedeLink {
                superseding: p.event_id(),
                superseded: target,
                kind,
            })
        })
        .collect();
    links.sort_by_key(|l| (l.superseded, l.superseding));
    links
}

/// The proposals that validly (same circle and skill name, any author) declare that they
/// supersede `proposal_id`, sorted. Informational only; it changes no vote and no
/// eligibility.
pub fn superseded_by(proposal_id: &EventId, proposals: &[ProposalView]) -> Vec<EventId> {
    supersede_links(proposals)
        .into_iter()
        .filter(|l| {
            &l.superseded == proposal_id
                && matches!(
                    l.kind,
                    SupersedeKind::SameAuthor | SupersedeKind::DifferentAuthor
                )
        })
        .map(|l| l.superseding)
        .collect()
}
