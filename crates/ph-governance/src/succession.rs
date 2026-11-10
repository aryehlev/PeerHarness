//! Charter succession (architecture section 10.8).
//!
//! The charter changes only by vote. An `amend` proposal carries the complete proposed
//! content `{rules, roll, carried}`; once it has passed, the holder of the circle root
//! key issues the next charter with exactly that content, naming a RESULT for the
//! proposal as its justification.
//!
//! [`check_successor`] is what every node runs before it accepts a charter as the new
//! current one. It makes the root key a **notary, not a ruler**: a charter that adds a
//! member, removes one or changes a threshold without a passed vote is rejected, however
//! validly it is signed. The root can refuse to sign, which stalls changes to the
//! charter, but it cannot decide anything on its own.
//!
//! [`propose_content`] and its helpers build the `next` content for the common
//! amendments so that `carried` is filled in correctly.

use ph_core::DeviceKey;
use ph_protocol::{
    verify_charter_signature, Charter, CharterContent, CharterRules, ProposalKind, RollEntry,
};

use crate::result::{verify_result, ResultError};
use crate::ruleset::RuleSet;
use crate::views::{ProposalView, ResultView, VoteView};

/// Why a charter was not accepted as the successor of the current one.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, thiserror::Error)]
pub enum SuccessionError {
    /// The charter's structure or root signature does not verify.
    #[error("the charter does not verify")]
    InvalidCharter,
    /// The charter is for another circle or signed by another root key.
    #[error("the charter belongs to another circle")]
    WrongCircle,
    /// `seq` is not the current `seq + 1`, or `previous` is not the current digest.
    #[error("the charter does not follow the current one")]
    NotNext,
    /// The charter names a justification other than the RESULT supplied.
    #[error("the charter is justified by another result")]
    WrongJustification,
    /// The justifying proposal is not an `amend` proposal under the current charter.
    #[error("the justification is not an amendment of the current charter")]
    NotAnAmendment,
    /// The charter's content differs from what the amendment proposed.
    #[error("the charter differs from what was voted on")]
    ContentMismatch,
    /// The justifying RESULT does not verify under the current charter.
    #[error("the amendment did not pass")]
    NotPassed(ResultError),
}

impl SuccessionError {
    /// Whether verifying again later can succeed without anything being wrong now (the
    /// node lacks a ballot the justification lists).
    pub const fn is_retryable(&self) -> bool {
        matches!(self, SuccessionError::NotPassed(e) if e.is_retryable())
    }

    /// A stable machine-readable code.
    pub const fn code(&self) -> &'static str {
        match self {
            SuccessionError::InvalidCharter => "invalid_charter",
            SuccessionError::WrongCircle => "wrong_circle",
            SuccessionError::NotNext => "not_next",
            SuccessionError::WrongJustification => "wrong_justification",
            SuccessionError::NotAnAmendment => "not_an_amendment",
            SuccessionError::ContentMismatch => "content_mismatch",
            SuccessionError::NotPassed(_) => "amendment_not_passed",
        }
    }
}

/// Checks that `next` is the legitimate successor of `current`.
///
/// * `proposal` is the `amend` proposal that `result` is for, and `result` is the RESULT
///   that `next.justification` names.
/// * `votes` are ballots this node holds; the ones `result` lists must be among them.
/// * `is_revoked` reports devices with a locally known revocation.
///
/// Everything is verified against `current`: its roll decides who could vote and its
/// rules decide how many approvals were needed.
pub fn check_successor(
    current: &Charter,
    next: &Charter,
    proposal: &ProposalView,
    result: &ResultView,
    votes: &[VoteView],
    is_revoked: &dyn Fn(&DeviceKey) -> bool,
) -> Result<(), SuccessionError> {
    verify_charter_signature(next).map_err(|_| SuccessionError::InvalidCharter)?;
    if next.circle_id != current.circle_id || next.issuer_key != current.issuer_key {
        return Err(SuccessionError::WrongCircle);
    }
    let current_digest = current
        .digest()
        .map_err(|_| SuccessionError::InvalidCharter)?;
    if next.seq != current.seq + 1 || next.previous != Some(current_digest) {
        return Err(SuccessionError::NotNext);
    }
    if next.justification != Some(result.event_id()) {
        return Err(SuccessionError::WrongJustification);
    }
    if proposal.kind() != ProposalKind::Amend
        || proposal.charter() != current_digest
        || proposal.circle_id() != current.circle_id
    {
        return Err(SuccessionError::NotAnAmendment);
    }
    if proposal.amend_next() != Some(&next.content) {
        return Err(SuccessionError::ContentMismatch);
    }
    verify_result(result, proposal, current, votes, is_revoked)
        .map_err(SuccessionError::NotPassed)?;
    tracing::debug!(
        circle_id = %next.circle_id,
        seq = next.seq,
        members = next.content.roll.len(),
        carried = next.content.carried.len(),
        "charter successor verified"
    );
    Ok(())
}

/// Why an amendment could not be drafted.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, thiserror::Error)]
pub enum DraftError {
    /// A member with that handle is already on the roll.
    #[error("that member is already on the roll")]
    MemberExists,
    /// No member with that handle is on the roll.
    #[error("no such member on the roll")]
    NoSuchMember,
    /// The device already belongs to a member.
    #[error("that device is already on the roll")]
    DeviceExists,
    /// The member does not have that device.
    #[error("the member does not have that device")]
    NoSuchDevice,
    /// The change would leave the roll, a member or the rules invalid (for example an
    /// empty roll, a member with no device, or a threshold below one half).
    #[error("the resulting charter would be invalid")]
    Invalid,
}

fn finish(mut next: CharterContent) -> Result<CharterContent, DraftError> {
    next.normalize();
    for entry in &mut next.roll {
        entry.devices.sort_by_key(DeviceKey::to_string);
        entry.scopes.sort();
    }
    next.check_structure().map_err(|_| DraftError::Invalid)?;
    Ok(next)
}

/// The starting point for any amendment: the current rules and roll, with `carried`
/// set to the rules in force right now. Approving an amendment built from this carries
/// every current rule forward unchanged.
pub fn propose_content(current: &CharterContent, in_force: &RuleSet) -> CharterContent {
    CharterContent {
        rules: current.rules,
        roll: current.roll.clone(),
        carried: in_force.carried_ids(),
    }
}

/// An amendment that admits `entry` as a new member.
pub fn admit_member(
    current: &CharterContent,
    in_force: &RuleSet,
    entry: RollEntry,
) -> Result<CharterContent, DraftError> {
    if current.member(&entry.member).is_some() {
        return Err(DraftError::MemberExists);
    }
    if entry.devices.iter().any(|d| current.member_of(d).is_some()) {
        return Err(DraftError::DeviceExists);
    }
    let mut next = propose_content(current, in_force);
    next.roll.push(entry);
    finish(next)
}

/// An amendment that removes the member named `member`.
pub fn remove_member(
    current: &CharterContent,
    in_force: &RuleSet,
    member: &str,
) -> Result<CharterContent, DraftError> {
    if current.member(member).is_none() {
        return Err(DraftError::NoSuchMember);
    }
    let mut next = propose_content(current, in_force);
    next.roll.retain(|e| e.member != member);
    finish(next)
}

/// An amendment that adds `device` to the member named `member`.
pub fn add_device(
    current: &CharterContent,
    in_force: &RuleSet,
    member: &str,
    device: DeviceKey,
) -> Result<CharterContent, DraftError> {
    if current.member_of(&device).is_some() {
        return Err(DraftError::DeviceExists);
    }
    let mut next = propose_content(current, in_force);
    let entry = next
        .roll
        .iter_mut()
        .find(|e| e.member == member)
        .ok_or(DraftError::NoSuchMember)?;
    entry.devices.push(device);
    finish(next)
}

/// An amendment that removes `device` from the member named `member`.
pub fn remove_device(
    current: &CharterContent,
    in_force: &RuleSet,
    member: &str,
    device: &DeviceKey,
) -> Result<CharterContent, DraftError> {
    let mut next = propose_content(current, in_force);
    let entry = next
        .roll
        .iter_mut()
        .find(|e| e.member == member)
        .ok_or(DraftError::NoSuchMember)?;
    if !entry.has_device(device) {
        return Err(DraftError::NoSuchDevice);
    }
    entry.devices.retain(|d| d != device);
    finish(next)
}

/// An amendment that replaces the rules of the vote. Needs the `amend` threshold.
pub fn change_rules(
    current: &CharterContent,
    in_force: &RuleSet,
    rules: CharterRules,
) -> Result<CharterContent, DraftError> {
    let mut next = propose_content(current, in_force);
    next.rules = rules;
    finish(next)
}
