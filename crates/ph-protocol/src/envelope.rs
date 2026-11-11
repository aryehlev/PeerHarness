//! Event envelopes (architecture section 5).
//!
//! ```json
//! {"schema":"peerharness.event/0.1","type":"QUESTION","circle_id":"sha256:…",
//!  "scope":"team/backend","author":"ed25519:…","nonce":"base64url:…",
//!  "created_at":"2026-11-09T18:10:00Z","expires_at":"2026-12-09T18:10:00Z",
//!  "body":{…},"signature":"base64url:…","event_id":"sha256:…"}
//! ```
//!
//! * [`UnsignedEnvelope`] / [`EnvelopeBuilder`] build an envelope; `sign` produces a
//!   [`SignedEnvelope`].
//! * [`SignedEnvelope::from_json_bytes`] / [`SignedEnvelope::from_value`] parse with the
//!   strict schema only (useful for re-loading stored events).
//! * [`validate_stateless`] performs every check that needs no local state and returns
//!   a [`VerifiedEnvelope`], which can only be obtained this way.
//!   [`VerifiedEnvelope::authorization`] says which stateful [`Authorization`] check
//!   remains.
//! * `Debug` output of bodies prints text lengths, never peer-supplied text.
//!
//! Optional body members are omitted when absent; an explicit `null` is rejected so the
//! typed form and the signed bytes always agree.
//!
//! Text limits count Unicode scalar values and also reject terminal control and bidi
//! override characters (see [`crate::text`]).

use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use ed25519_dalek::SigningKey;
use ph_core::{
    is_valid_skill_name, Capability, CircleId, DeviceKey, Digest, EventId, Nonce, Scope, Signature,
    Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::charter::{verify_charter_signature, Charter, CharterContent};
use crate::credentials::{
    check_schema_member, some, verify_membership_proof, verify_revocation_signature, Acceptance,
    MembershipCredential, MembershipProof, Revocation,
};
use crate::error::{JcsError, ProtocolError, TimeRule};
use crate::jcs::{self, ParseLimits};
use crate::limits::{
    self, lifetimes, CLOCK_SKEW_SECS, MAX_BUNDLE_BYTES, MAX_DEPTH, MAX_EVENT_BYTES,
    MAX_EVENT_LIFETIME_SECS, MAX_RESULT_APPROVALS,
};
use crate::signing::{self, Context};
use crate::text::{check_text, Lines};

const OBJECT: &str = "event";
const BODY: &str = "event body";

// =======================================================================================
// EventType
// =======================================================================================

/// The event type allowlist.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    /// `QUESTION`: ask peers to validate a sanitized claim. Capability `ask`, 30 d.
    Question,
    /// `ANSWER`: respond to a question. Capability `answer`, 30 d.
    Answer,
    /// `PROPOSAL`: put an `adopt`, `repeal` or `amend` proposal to the vote. Authorized
    /// by the roll of the charter it names. Permanent.
    Proposal,
    /// `VOTE`: a ballot on one proposal. Authorized by the roll. Permanent.
    Vote,
    /// `RESULT`: a certificate that a proposal passed (the approving ballots).
    /// Authorized by the roll. Permanent.
    Result,
    /// `CHARTER`: the next charter of the circle, authored by the root key. Control
    /// plane. Permanent.
    Charter,
    /// `MEMBERSHIP`: convey a credential and acceptance. Control plane, no capability;
    /// lifetime = credential expiry.
    Membership,
    /// `REVOCATION`: convey a revocation, authored by the root key. Control plane.
    /// Permanent.
    Revocation,
    /// `STANCE`: a member's public statement that they do not follow a rule in force on
    /// their own machine, or follow it again. Authorized by the roll of the charter it
    /// names. Permanent. It is a record and nothing else: it never changes whether a
    /// rule passed, is in force, or is installed anywhere.
    Stance,
}

impl EventType {
    /// All event types.
    pub const ALL: [EventType; 9] = [
        EventType::Question,
        EventType::Answer,
        EventType::Proposal,
        EventType::Vote,
        EventType::Result,
        EventType::Charter,
        EventType::Membership,
        EventType::Revocation,
        EventType::Stance,
    ];

    /// The wire string, e.g. `"QUESTION"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            EventType::Question => "QUESTION",
            EventType::Answer => "ANSWER",
            EventType::Proposal => "PROPOSAL",
            EventType::Vote => "VOTE",
            EventType::Result => "RESULT",
            EventType::Charter => "CHARTER",
            EventType::Membership => "MEMBERSHIP",
            EventType::Revocation => "REVOCATION",
            EventType::Stance => "STANCE",
        }
    }

    /// The credential capability the author needs, for the two types that are
    /// authorized by credential (`QUESTION`, `ANSWER`). `None` for every other type:
    /// use [`EventType::authorization`] to decide which stateful check to run.
    pub const fn required_capability(self) -> Option<Capability> {
        match self {
            EventType::Question => Some(Capability::Ask),
            EventType::Answer => Some(Capability::Answer),
            EventType::Proposal
            | EventType::Vote
            | EventType::Result
            | EventType::Charter
            | EventType::Membership
            | EventType::Revocation
            | EventType::Stance => None,
        }
    }

    /// How an envelope of this type is authorized after [`validate_stateless`].
    pub const fn authorization(self) -> Authorization {
        match self {
            EventType::Question => Authorization::Capability(Capability::Ask),
            EventType::Answer => Authorization::Capability(Capability::Answer),
            EventType::Proposal | EventType::Vote | EventType::Result | EventType::Stance => {
                Authorization::Roll
            }
            EventType::Membership => Authorization::EmbeddedCredential,
            EventType::Charter | EventType::Revocation => Authorization::CircleRoot,
        }
    }

    /// Default lifetime in seconds, or `None` for MEMBERSHIP (the credential's expiry).
    /// Permanent types get the longest lifetime the envelope schema allows; receivers
    /// do not enforce it (see [`EventType::is_permanent`]).
    pub const fn default_lifetime_secs(self) -> Option<i64> {
        match self {
            EventType::Question => Some(lifetimes::QUESTION_SECS),
            EventType::Answer => Some(lifetimes::ANSWER_SECS),
            EventType::Proposal
            | EventType::Vote
            | EventType::Result
            | EventType::Charter
            | EventType::Revocation
            | EventType::Stance => Some(lifetimes::PERMANENT_SECS),
            EventType::Membership => None,
        }
    }

    /// Whether this is a control-plane event (MEMBERSHIP, REVOCATION or CHARTER), which
    /// `FetchEvents` returns to every active member regardless of scope.
    pub const fn is_control_plane(self) -> bool {
        matches!(
            self,
            EventType::Membership | EventType::Revocation | EventType::Charter
        )
    }

    /// Whether this is a decision event (PROPOSAL, VOTE or RESULT): authorized by the
    /// roll of the charter the proposal names, never by a credential.
    pub const fn is_decision(self) -> bool {
        matches!(
            self,
            EventType::Proposal | EventType::Vote | EventType::Result
        )
    }

    /// Whether events of this type are authorized by a roll and read by the members
    /// that roll entitles: the decision events and STANCE. With scope `*` they concern,
    /// and reach, every member; with another scope, the members whose roll entry covers
    /// it.
    pub const fn is_roll_record(self) -> bool {
        matches!(
            self,
            EventType::Proposal | EventType::Vote | EventType::Result | EventType::Stance
        )
    }

    /// Whether events of this type are permanent records whose `expires_at` is never
    /// enforced (architecture section 10.11): the decision events, CHARTER, REVOCATION
    /// and STANCE. Outcomes of a vote must not depend on a clock, a revocation must
    /// never lapse, and what a member put on the record stays there.
    pub const fn is_permanent(self) -> bool {
        matches!(
            self,
            EventType::Proposal
                | EventType::Vote
                | EventType::Result
                | EventType::Charter
                | EventType::Revocation
                | EventType::Stance
        )
    }
}

/// The authorization step (architecture section 5, step 4) that remains for an envelope
/// after [`validate_stateless`] succeeded.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Authorization {
    /// QUESTION and ANSWER: ask the [`ph_core::MembershipOracle`] whether `author`
    /// holds this capability on the envelope `scope` in `circle_id` at local `now`.
    Capability(Capability),
    /// MEMBERSHIP: the embedded credential and acceptance were verified statelessly and
    /// the author is the credential subject. No oracle call; the caller still applies
    /// local revocation state for the subject before storing it as active.
    EmbeddedCredential,
    /// REVOCATION and CHARTER: stateless validation proved the author is the circle
    /// root key (`circle_id == CircleId::derive(author)`). The root key has no
    /// credential, so do **not** ask the oracle. A CHARTER must additionally be a valid
    /// successor of the current charter (`ph-governance`).
    CircleRoot,
    /// PROPOSAL, VOTE, RESULT and STANCE: the author must be a device of a member in the
    /// proposal's electorate, per the roll of the charter the proposal names (for a
    /// STANCE, the charter the stance itself names; architecture section 10). The
    /// credential oracle is **not** consulted, so the answer does not change with time.
    Roll,
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EventType {
    type Err = ProtocolError;
    fn from_str(s: &str) -> Result<Self, ProtocolError> {
        EventType::ALL
            .into_iter()
            .find(|t| t.as_str() == s)
            .ok_or(ProtocolError::UnknownEventType)
    }
}

// =======================================================================================
// Bodies
// =======================================================================================

/// ANSWER `answer` values.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnswerChoice {
    /// `"agree"`.
    Agree,
    /// `"disagree"`.
    Disagree,
    /// `"unsure"`.
    Unsure,
}

/// VOTE `decision` values.
///
/// Only `approve` affects the count. `reject` and `revise` are the signed record of
/// dissent and of requested changes; nobody holds a veto (architecture section 10.5).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VoteDecision {
    /// `"approve"`. Cannot be withdrawn once published.
    Approve,
    /// `"reject"`.
    Reject,
    /// `"revise"` (request revision).
    Revise,
}

/// PROPOSAL `kind` values.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProposalKind {
    /// `"adopt"`: put a rule (an instruction-only skill bundle) in force.
    Adopt,
    /// `"repeal"`: take a rule out of force.
    Repeal,
    /// `"amend"`: replace the charter (its rules, its roll, or both).
    Amend,
}

impl ProposalKind {
    /// The wire string.
    pub const fn as_str(self) -> &'static str {
        match self {
            ProposalKind::Adopt => "adopt",
            ProposalKind::Repeal => "repeal",
            ProposalKind::Amend => "amend",
        }
    }
}

impl fmt::Display for ProposalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// QUESTION body.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionBody {
    /// The human-confirmed question text (1-2000 chars, multi-line).
    pub question: String,
    /// Topic label (1-128 chars, single line).
    pub topic: String,
    /// Optional opaque reference to the asker's local candidate.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    pub related_candidate: Option<Digest>,
}

/// ANSWER body.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerBody {
    /// The QUESTION being answered.
    pub question_id: EventId,
    /// The answer.
    pub answer: AnswerChoice,
    /// Optional rationale (0-2000 chars, multi-line).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    pub rationale: Option<String>,
}

/// The rule an `adopt` proposal puts to the vote.
#[derive(Clone, PartialEq, Eq)]
pub struct AdoptAction {
    /// Agent Skills name ([`ph_core::is_valid_skill_name`]).
    pub skill_name: String,
    /// Skill description (1-1024 chars, multi-line).
    pub description: String,
    /// Digest of the bundle ([`crate::bundle::bundle_digest`]).
    pub bundle_digest: Digest,
    /// Total bundle size in bytes (1..=256 KiB).
    pub bundle_size: u64,
    /// Optional QUESTION this proposal follows from.
    pub related_question: Option<EventId>,
    /// Optional earlier `adopt` PROPOSAL this one revises (lineage only; approvals never
    /// move between proposals).
    pub supersedes: Option<EventId>,
}

/// What a proposal asks the electorate to decide. The variant is the `kind` member.
#[derive(Clone, PartialEq, Eq)]
pub enum ProposalAction {
    /// `"adopt"`: put this rule in force.
    Adopt(AdoptAction),
    /// `"repeal"`: take the rule adopted by the `adopt` PROPOSAL `target` out of force.
    Repeal {
        /// Event id of the `adopt` PROPOSAL to repeal.
        target: EventId,
    },
    /// `"amend"`: make `next` the content of the next charter.
    Amend {
        /// The complete proposed rules, roll and carried rules.
        next: CharterContent,
    },
}

impl ProposalAction {
    /// The proposal kind.
    pub const fn kind(&self) -> ProposalKind {
        match self {
            ProposalAction::Adopt(_) => ProposalKind::Adopt,
            ProposalAction::Repeal { .. } => ProposalKind::Repeal,
            ProposalAction::Amend { .. } => ProposalKind::Amend,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposalRepr {
    kind: ProposalKind,
    charter: Digest,
    title: String,
    summary: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    skill_name: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    description: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    bundle_digest: Option<Digest>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    bundle_size: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    related_question: Option<EventId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    supersedes: Option<EventId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    target: Option<EventId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    next: Option<CharterContent>,
}

/// PROPOSAL body.
///
/// On the wire this is one flat object: `kind`, `charter`, `title`, `summary`, plus the
/// members of that kind only (`skill_name`, `description`, `bundle_digest`,
/// `bundle_size`, `related_question?`, `supersedes?` for `adopt`; `target` for `repeal`;
/// `next` for `amend`). A member that belongs to another kind is rejected.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ProposalRepr", into = "ProposalRepr")]
pub struct ProposalBody {
    /// Digest of the charter this proposal is voted under. It can pass only while that
    /// charter is the current one.
    pub charter: Digest,
    /// Proposal title (1-200 chars, single line).
    pub title: String,
    /// Human-confirmed summary of what is proposed and why (0-1000 chars, multi-line).
    pub summary: String,
    /// What is being decided.
    pub action: ProposalAction,
}

impl ProposalBody {
    /// The proposal kind.
    pub const fn kind(&self) -> ProposalKind {
        self.action.kind()
    }

    /// The rule, if this is an `adopt` proposal.
    pub const fn as_adopt(&self) -> Option<&AdoptAction> {
        match &self.action {
            ProposalAction::Adopt(a) => Some(a),
            _ => None,
        }
    }
}

impl From<ProposalBody> for ProposalRepr {
    fn from(b: ProposalBody) -> Self {
        let mut r = ProposalRepr {
            kind: b.action.kind(),
            charter: b.charter,
            title: b.title,
            summary: b.summary,
            skill_name: None,
            description: None,
            bundle_digest: None,
            bundle_size: None,
            related_question: None,
            supersedes: None,
            target: None,
            next: None,
        };
        match b.action {
            ProposalAction::Adopt(a) => {
                r.skill_name = Some(a.skill_name);
                r.description = Some(a.description);
                r.bundle_digest = Some(a.bundle_digest);
                r.bundle_size = Some(a.bundle_size);
                r.related_question = a.related_question;
                r.supersedes = a.supersedes;
            }
            ProposalAction::Repeal { target } => r.target = Some(target),
            ProposalAction::Amend { next } => r.next = Some(next),
        }
        r
    }
}

impl TryFrom<ProposalRepr> for ProposalBody {
    type Error = ProtocolError;
    fn try_from(r: ProposalRepr) -> Result<Self, ProtocolError> {
        let schema = ProtocolError::Schema { object: BODY };
        let adopt_members = r.skill_name.is_some()
            || r.description.is_some()
            || r.bundle_digest.is_some()
            || r.bundle_size.is_some()
            || r.related_question.is_some()
            || r.supersedes.is_some();
        let action = match r.kind {
            ProposalKind::Adopt => {
                if r.target.is_some() || r.next.is_some() {
                    return Err(schema);
                }
                match (r.skill_name, r.description, r.bundle_digest, r.bundle_size) {
                    (Some(skill_name), Some(description), Some(bundle_digest), Some(size)) => {
                        ProposalAction::Adopt(AdoptAction {
                            skill_name,
                            description,
                            bundle_digest,
                            bundle_size: size,
                            related_question: r.related_question,
                            supersedes: r.supersedes,
                        })
                    }
                    _ => return Err(schema),
                }
            }
            ProposalKind::Repeal => match (r.target, r.next) {
                (Some(target), None) if !adopt_members => ProposalAction::Repeal { target },
                _ => return Err(schema),
            },
            ProposalKind::Amend => match (r.next, r.target) {
                (Some(next), None) if !adopt_members => ProposalAction::Amend { next },
                _ => return Err(schema),
            },
        };
        Ok(ProposalBody {
            charter: r.charter,
            title: r.title,
            summary: r.summary,
            action,
        })
    }
}

/// VOTE body: one ballot on one proposal.
///
/// `proposal_id` is the hash of everything the proposer signed (the signature itself is
/// not hashed), so the ballot is bound to every signed byte of what was proposed,
/// including the bundle digest of an `adopt` proposal.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoteBody {
    /// The PROPOSAL voted on.
    pub proposal_id: EventId,
    /// The decision.
    pub decision: VoteDecision,
    /// Optional rationale (0-2000 chars, multi-line).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    pub rationale: Option<String>,
}

/// What a member says about a rule in force (STANCE `stance`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stance {
    /// `"opted_out"`: the member keeps the rule off their own machine.
    OptedOut,
    /// `"following"`: the member follows the rule (again).
    Following,
}

impl Stance {
    /// The wire string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Stance::OptedOut => "opted_out",
            Stance::Following => "following",
        }
    }
}

/// STANCE body: a member's statement about one rule in force.
///
/// An opt-out is the owner's right and works without telling anyone. A STANCE is the
/// choice to put it on the circle's record, so that "binding" keeps an honest meaning:
/// the members can see who follows what they voted. It names the `adopt` proposal of the
/// rule, and, like a proposal, the charter under which its author is a member, so every
/// node judges it against the same roll at any time. A member's latest stance on a
/// proposal (by `created_at`, then event id) is their current one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StanceBody {
    /// The `adopt` PROPOSAL whose rule the stance is about.
    pub proposal_id: EventId,
    /// Digest of the charter whose roll lists the author.
    pub charter: Digest,
    /// The stance.
    pub stance: Stance,
    /// Optional reason (0-2000 chars, multi-line).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    pub reason: Option<String>,
}

impl fmt::Debug for StanceBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StanceBody")
            .field("proposal_id", &self.proposal_id)
            .field("charter", &self.charter)
            .field("stance", &self.stance)
            .field("reason_len", &self.reason.as_ref().map(String::len))
            .finish()
    }
}

// Free text received from peers never appears in `Debug` output (architecture section
// 13: logs carry ids and counts only). The impls below print lengths instead.

impl fmt::Debug for QuestionBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuestionBody")
            .field("question_len", &self.question.len())
            .field("topic_len", &self.topic.len())
            .field("related_candidate", &self.related_candidate)
            .finish()
    }
}

impl fmt::Debug for AnswerBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnswerBody")
            .field("question_id", &self.question_id)
            .field("answer", &self.answer)
            .field("rationale_len", &self.rationale.as_ref().map(String::len))
            .finish()
    }
}

impl fmt::Debug for AdoptAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdoptAction")
            .field("skill_name_len", &self.skill_name.len())
            .field("description_len", &self.description.len())
            .field("bundle_digest", &self.bundle_digest)
            .field("bundle_size", &self.bundle_size)
            .field("related_question", &self.related_question)
            .field("supersedes", &self.supersedes)
            .finish()
    }
}

impl fmt::Debug for ProposalAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProposalAction::Adopt(a) => f.debug_tuple("Adopt").field(a).finish(),
            ProposalAction::Repeal { target } => {
                f.debug_struct("Repeal").field("target", target).finish()
            }
            // Member handles are chosen by peers; print counts only.
            ProposalAction::Amend { next } => f
                .debug_struct("Amend")
                .field("rules", &next.rules)
                .field("roll_len", &next.roll.len())
                .field("carried_len", &next.carried.len())
                .finish(),
        }
    }
}

impl fmt::Debug for ProposalBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProposalBody")
            .field("charter", &self.charter)
            .field("title_len", &self.title.len())
            .field("summary_len", &self.summary.len())
            .field("action", &self.action)
            .finish()
    }
}

impl fmt::Debug for VoteBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VoteBody")
            .field("proposal_id", &self.proposal_id)
            .field("decision", &self.decision)
            .field("rationale_len", &self.rationale.as_ref().map(String::len))
            .finish()
    }
}

/// RESULT body: a certificate that a proposal passed.
///
/// It carries no authority. A node that receives it verifies the listed ballots itself
/// and reaches the conclusion it would have reached from those ballots alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultBody {
    /// The PROPOSAL that passed.
    pub proposal_id: EventId,
    /// The approving VOTE event ids (1-64, unique, sorted).
    pub approvals: Vec<EventId>,
}

impl ResultBody {
    /// Builds a result, sorting `approvals` into canonical order.
    pub fn new(proposal_id: EventId, mut approvals: Vec<EventId>) -> Self {
        approvals.sort_by_key(EventId::to_string);
        Self {
            proposal_id,
            approvals,
        }
    }
}

/// CHARTER body. The envelope author must be the circle root key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CharterBody {
    /// The charter.
    pub charter: Charter,
}

/// MEMBERSHIP body. The envelope author must be the credential subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipBody {
    /// The credential.
    pub credential: MembershipCredential,
    /// The subject's acceptance of it.
    pub acceptance: Acceptance,
}

impl MembershipBody {
    /// As a [`MembershipProof`].
    pub fn to_proof(&self) -> MembershipProof {
        MembershipProof {
            credential: self.credential.clone(),
            acceptance: self.acceptance.clone(),
        }
    }
}

/// REVOCATION body. In v0 the envelope author must be the circle root key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationBody {
    /// The revocation.
    pub revocation: Revocation,
}

/// A typed event body; the variant determines the envelope `type`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventBody {
    /// QUESTION.
    Question(QuestionBody),
    /// ANSWER.
    Answer(AnswerBody),
    /// PROPOSAL.
    Proposal(ProposalBody),
    /// VOTE.
    Vote(VoteBody),
    /// RESULT.
    Result(ResultBody),
    /// CHARTER.
    Charter(CharterBody),
    /// MEMBERSHIP.
    Membership(MembershipBody),
    /// REVOCATION.
    Revocation(RevocationBody),
    /// STANCE.
    Stance(StanceBody),
}

fn opt_text(
    field: &'static str,
    s: &Option<String>,
    max: usize,
    lines: Lines,
) -> Result<(), ProtocolError> {
    match s {
        Some(s) => check_text(field, s, 0, max, lines),
        None => Ok(()),
    }
}

fn skill_name(s: &str) -> Result<(), ProtocolError> {
    if is_valid_skill_name(s) {
        Ok(())
    } else {
        Err(ProtocolError::field("skill_name", "invalid skill name"))
    }
}

impl EventBody {
    /// The event type of this body.
    pub const fn event_type(&self) -> EventType {
        match self {
            EventBody::Question(_) => EventType::Question,
            EventBody::Answer(_) => EventType::Answer,
            EventBody::Proposal(_) => EventType::Proposal,
            EventBody::Vote(_) => EventType::Vote,
            EventBody::Result(_) => EventType::Result,
            EventBody::Charter(_) => EventType::Charter,
            EventBody::Membership(_) => EventType::Membership,
            EventBody::Revocation(_) => EventType::Revocation,
            EventBody::Stance(_) => EventType::Stance,
        }
    }

    /// Parses the `body` member for an event of type `t` (strict schema, then bounds).
    pub fn from_parts(t: EventType, body: Value) -> Result<Self, ProtocolError> {
        fn de<T: serde::de::DeserializeOwned>(v: Value) -> Result<T, ProtocolError> {
            serde_json::from_value(v).map_err(|_| ProtocolError::Schema { object: BODY })
        }
        let b = match t {
            EventType::Question => EventBody::Question(de(body)?),
            EventType::Answer => EventBody::Answer(de(body)?),
            EventType::Proposal => EventBody::Proposal(de(body)?),
            EventType::Vote => EventBody::Vote(de(body)?),
            EventType::Result => EventBody::Result(de(body)?),
            EventType::Charter => EventBody::Charter(de(body)?),
            EventType::Membership => EventBody::Membership(de(body)?),
            EventType::Revocation => EventBody::Revocation(de(body)?),
            EventType::Stance => EventBody::Stance(de(body)?),
        };
        b.validate()?;
        Ok(b)
    }

    /// The `body` JSON value.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        match self {
            EventBody::Question(b) => jcs::to_value(b),
            EventBody::Answer(b) => jcs::to_value(b),
            EventBody::Proposal(b) => jcs::to_value(b),
            EventBody::Vote(b) => jcs::to_value(b),
            EventBody::Result(b) => jcs::to_value(b),
            EventBody::Charter(b) => jcs::to_value(b),
            EventBody::Membership(b) => jcs::to_value(b),
            EventBody::Revocation(b) => jcs::to_value(b),
            EventBody::Stance(b) => jcs::to_value(b),
        }
    }

    /// Checks the per-type bounds of section 5 (no signatures, no time rules).
    pub fn validate(&self) -> Result<(), ProtocolError> {
        use limits::text as t;
        match self {
            EventBody::Question(b) => {
                check_text("question", &b.question, 1, t::QUESTION, Lines::Multi)?;
                check_text("topic", &b.topic, 1, t::TOPIC, Lines::Single)?;
            }
            EventBody::Answer(b) => {
                opt_text("rationale", &b.rationale, t::RATIONALE, Lines::Multi)?;
            }
            EventBody::Proposal(b) => {
                check_text("title", &b.title, 1, t::TITLE, Lines::Single)?;
                check_text("summary", &b.summary, 0, t::SUMMARY, Lines::Multi)?;
                match &b.action {
                    ProposalAction::Adopt(a) => {
                        skill_name(&a.skill_name)?;
                        check_text(
                            "description",
                            &a.description,
                            1,
                            t::DESCRIPTION,
                            Lines::Multi,
                        )?;
                        if a.bundle_size == 0 || a.bundle_size > MAX_BUNDLE_BYTES as u64 {
                            return Err(ProtocolError::field("bundle_size", "out of bounds"));
                        }
                    }
                    ProposalAction::Repeal { .. } => {}
                    ProposalAction::Amend { next } => next.check_structure()?,
                }
            }
            EventBody::Vote(b) => {
                opt_text("rationale", &b.rationale, t::RATIONALE, Lines::Multi)?;
            }
            EventBody::Result(b) => {
                if b.approvals.is_empty() {
                    return Err(ProtocolError::field("approvals", "no approvals"));
                }
                if b.approvals.len() > MAX_RESULT_APPROVALS {
                    return Err(ProtocolError::field("approvals", "too many approvals"));
                }
                let sorted = b
                    .approvals
                    .windows(2)
                    .all(|w| matches!(w, [x, y] if x.to_string() < y.to_string()));
                if !sorted {
                    return Err(ProtocolError::field(
                        "approvals",
                        "approvals must be unique and sorted",
                    ));
                }
            }
            EventBody::Charter(b) => {
                b.charter.check_structure()?;
            }
            EventBody::Membership(b) => {
                b.credential.check_structure()?;
            }
            EventBody::Revocation(b) => {
                b.revocation.check_structure()?;
            }
            EventBody::Stance(b) => {
                opt_text("reason", &b.reason, t::RATIONALE, Lines::Multi)?;
            }
        }
        Ok(())
    }
}

// =======================================================================================
// Envelope representation
// =======================================================================================

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeRepr {
    schema: String,
    #[serde(rename = "type")]
    event_type: EventType,
    circle_id: CircleId,
    scope: Scope,
    author: DeviceKey,
    nonce: Nonce,
    created_at: Timestamp,
    expires_at: Timestamp,
    body: Value,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    signature: Option<Signature>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    event_id: Option<EventId>,
}

/// An envelope before signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedEnvelope {
    /// Target circle.
    pub circle_id: CircleId,
    /// Object scope; the author's credential must cover it.
    pub scope: Scope,
    /// Author device key; signs the envelope.
    pub author: DeviceKey,
    /// Random nonce.
    pub nonce: Nonce,
    /// Creation time (author's clock; informational).
    pub created_at: Timestamp,
    /// Expiry time.
    pub expires_at: Timestamp,
    /// Typed body; determines `type`.
    pub body: EventBody,
}

impl UnsignedEnvelope {
    /// The envelope `type`.
    pub const fn event_type(&self) -> EventType {
        self.body.event_type()
    }

    fn repr(&self) -> Result<EnvelopeRepr, ProtocolError> {
        Ok(EnvelopeRepr {
            schema: Context::Event.schema().to_owned(),
            event_type: self.event_type(),
            circle_id: self.circle_id,
            scope: self.scope.clone(),
            author: self.author,
            nonce: self.nonce,
            created_at: self.created_at,
            expires_at: self.expires_at,
            body: self.body.to_value()?,
            signature: None,
            event_id: None,
        })
    }

    /// The unsigned JSON object.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        jcs::to_value(&self.repr()?)
    }

    /// The exact canonical text that is signed (after the context prefix).
    pub fn to_canonical_json(&self) -> Result<String, ProtocolError> {
        Ok(jcs::canonicalize(&self.to_value()?)?)
    }

    /// `"peerharness-event-v0\0" || JCS(unsigned)`.
    pub fn signing_input(&self) -> Result<Vec<u8>, ProtocolError> {
        signing::signing_input(Context::Event, &self.to_value()?)
    }

    /// The event id this envelope will have.
    pub fn event_id(&self) -> Result<EventId, ProtocolError> {
        Ok(EventId::from_digest(signing::digest_of_input(
            &self.signing_input()?,
        )))
    }

    /// Time-independent consistency rules between envelope and body: body bounds;
    /// MEMBERSHIP author == credential subject, same circle, envelope does not outlive
    /// the credential; REVOCATION author == issuer (root) key, same circle; CHARTER
    /// author == issuer (root) key, same circle, scope `*`; an `amend` PROPOSAL has
    /// scope `*` (it concerns every member).
    pub fn check_bindings(&self) -> Result<(), ProtocolError> {
        self.body.validate()?;
        match &self.body {
            EventBody::Proposal(b) => {
                if b.kind() == ProposalKind::Amend && !self.scope.is_wildcard() {
                    return Err(ProtocolError::field(
                        "scope",
                        "an amend proposal must have scope *",
                    ));
                }
            }
            EventBody::Charter(b) => {
                if self.author != b.charter.issuer_key {
                    return Err(ProtocolError::Mismatch {
                        what: "CHARTER author and issuer_key",
                    });
                }
                if self.circle_id != b.charter.circle_id {
                    return Err(ProtocolError::Mismatch {
                        what: "CHARTER circle_id",
                    });
                }
                if !self.scope.is_wildcard() {
                    return Err(ProtocolError::field(
                        "scope",
                        "a CHARTER event must have scope *",
                    ));
                }
            }
            EventBody::Membership(b) => {
                if self.author != b.credential.subject_device_key {
                    return Err(ProtocolError::Mismatch {
                        what: "MEMBERSHIP author and credential subject",
                    });
                }
                if self.circle_id != b.credential.circle_id {
                    return Err(ProtocolError::Mismatch {
                        what: "MEMBERSHIP circle_id",
                    });
                }
                if self.expires_at > b.credential.expires_at {
                    return Err(ProtocolError::Time {
                        object: OBJECT,
                        rule: TimeRule::OutlivesCredential,
                    });
                }
            }
            EventBody::Revocation(b) => {
                if self.author != b.revocation.issuer_key {
                    return Err(ProtocolError::Mismatch {
                        what: "REVOCATION author and issuer_key",
                    });
                }
                if self.circle_id != b.revocation.circle_id {
                    return Err(ProtocolError::Mismatch {
                        what: "REVOCATION circle_id",
                    });
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Signs with the author's device key (which must match `author`).
    ///
    /// Refuses to sign anything a peer would reject for structural reasons: invalid
    /// body bounds or bindings, `expires_at <= created_at`, a lifetime over 400 days,
    /// or a canonical size over 64 KiB / depth over 8.
    pub fn sign(self, key: &SigningKey) -> Result<SignedEnvelope, ProtocolError> {
        if DeviceKey::from_signing_key(key) != self.author {
            return Err(ProtocolError::Mismatch {
                what: "signing key and author",
            });
        }
        self.check_bindings()?;
        check_lifetime(self.created_at, self.expires_at)?;
        let value = self.to_value()?;
        check_shape(&value)?;
        let input = signing::signing_input(Context::Event, &value)?;
        let signature = signing::sign_input(key, &input);
        let event_id = EventId::from_digest(signing::digest_of_input(&input));
        let signed = SignedEnvelope {
            envelope: self,
            signature,
            event_id,
        };
        // The transmitted form adds ~200 bytes; make sure it still fits.
        check_shape(&signed.to_value()?)?;
        Ok(signed)
    }
}

/// Depth (<= 8) and canonical-size (<= 64 KiB) check.
fn check_shape(v: &Value) -> Result<(), ProtocolError> {
    if jcs::depth(v) > MAX_DEPTH {
        return Err(JcsError::TooDeep { max: MAX_DEPTH }.into());
    }
    let size = jcs::canonicalize(v)?.len();
    if size > MAX_EVENT_BYTES {
        return Err(ProtocolError::TooLarge {
            what: OBJECT,
            size,
            max: MAX_EVENT_BYTES,
        });
    }
    Ok(())
}

fn check_lifetime(created_at: Timestamp, expires_at: Timestamp) -> Result<(), ProtocolError> {
    if expires_at <= created_at {
        return Err(ProtocolError::Time {
            object: OBJECT,
            rule: TimeRule::ExpiresBeforeCreated,
        });
    }
    if expires_at.secs_since(created_at) > MAX_EVENT_LIFETIME_SECS {
        return Err(ProtocolError::Time {
            object: OBJECT,
            rule: TimeRule::LifetimeTooLong,
        });
    }
    Ok(())
}

/// The time rules of section 5 step 3 for an event of type `t`:
///
/// * `expires_at > created_at` and a lifetime of at most 400 days, for every type;
/// * `created_at <= now + 5 min`, except for REVOCATION: a revocation only ever denies,
///   so it is never refused because the issuer's clock runs ahead;
/// * `expires_at > now`, except for the permanent types ([`EventType::is_permanent`]),
///   whose outcome must not depend on a clock.
pub fn check_time_rules_for(
    t: EventType,
    created_at: Timestamp,
    expires_at: Timestamp,
    now: Timestamp,
) -> Result<(), ProtocolError> {
    if !matches!(t, EventType::Revocation) && created_at > now.plus_secs(CLOCK_SKEW_SECS) {
        return Err(ProtocolError::Time {
            object: OBJECT,
            rule: TimeRule::FutureDated,
        });
    }
    check_lifetime(created_at, expires_at)?;
    if !t.is_permanent() && expires_at <= now {
        return Err(ProtocolError::Time {
            object: OBJECT,
            rule: TimeRule::Expired,
        });
    }
    Ok(())
}

/// The time rules for an expiring event (QUESTION, ANSWER, MEMBERSHIP):
/// `created_at <= now + 5 min`, `expires_at > now`, `expires_at > created_at`, lifetime
/// at most 400 days. Use [`check_time_rules_for`] when the type is known.
pub fn check_time_rules(
    created_at: Timestamp,
    expires_at: Timestamp,
    now: Timestamp,
) -> Result<(), ProtocolError> {
    if created_at > now.plus_secs(CLOCK_SKEW_SECS) {
        return Err(ProtocolError::Time {
            object: OBJECT,
            rule: TimeRule::FutureDated,
        });
    }
    check_lifetime(created_at, expires_at)?;
    if expires_at <= now {
        return Err(ProtocolError::Time {
            object: OBJECT,
            rule: TimeRule::Expired,
        });
    }
    Ok(())
}

// =======================================================================================
// SignedEnvelope
// =======================================================================================

/// A signed envelope as transmitted: the unsigned members plus `signature` and
/// `event_id`. Holding one does **not** imply it was verified; see
/// [`VerifiedEnvelope`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedEnvelope {
    /// The signed members.
    pub envelope: UnsignedEnvelope,
    /// Signature by `author`.
    pub signature: Signature,
    /// Transmitted event id.
    pub event_id: EventId,
}

impl Deref for SignedEnvelope {
    type Target = UnsignedEnvelope;
    fn deref(&self) -> &UnsignedEnvelope {
        &self.envelope
    }
}

impl SignedEnvelope {
    /// Strictly parses envelope bytes (64 KiB, depth 8, duplicate keys, integer-only)
    /// and applies the strict schema. Does **not** verify the signature or time.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_EVENT_BYTES {
            return Err(ProtocolError::TooLarge {
                what: OBJECT,
                size: bytes.len(),
                max: MAX_EVENT_BYTES,
            });
        }
        let v = jcs::parse_strict(bytes, ParseLimits::EVENT)?;
        Self::from_value(&v)
    }

    /// Applies the strict schema to an already parsed value: depth and canonical size,
    /// `schema`, the type allowlist, no unknown members, typed body with bounds, and an
    /// exact re-serialization round trip. Does **not** verify the signature or time.
    pub fn from_value(v: &Value) -> Result<Self, ProtocolError> {
        check_shape(v)?;
        if !v.is_object() {
            return Err(ProtocolError::Schema { object: OBJECT });
        }
        check_schema_member(v, Context::Event)?;
        match v.get("type") {
            Some(Value::String(s)) => {
                s.parse::<EventType>()?;
            }
            _ => return Err(ProtocolError::Schema { object: OBJECT }),
        }
        let repr: EnvelopeRepr = serde_json::from_value(v.clone())
            .map_err(|_| ProtocolError::Schema { object: OBJECT })?;
        let (Some(signature), Some(event_id)) = (repr.signature, repr.event_id) else {
            return Err(ProtocolError::Schema { object: OBJECT });
        };
        let body = EventBody::from_parts(repr.event_type, repr.body)?;
        let signed = SignedEnvelope {
            envelope: UnsignedEnvelope {
                circle_id: repr.circle_id,
                scope: repr.scope,
                author: repr.author,
                nonce: repr.nonce,
                created_at: repr.created_at,
                expires_at: repr.expires_at,
                body,
            },
            signature,
            event_id,
        };
        if signed.to_value()? != *v {
            return Err(ProtocolError::Schema { object: OBJECT });
        }
        Ok(signed)
    }

    /// The transmitted JSON object.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        let mut repr = self.envelope.repr()?;
        repr.signature = Some(self.signature);
        repr.event_id = Some(self.event_id);
        jcs::to_value(&repr)
    }

    /// The canonical (JCS) text of the transmitted object, for storage and transport.
    pub fn to_canonical_json(&self) -> Result<String, ProtocolError> {
        Ok(jcs::canonicalize(&self.to_value()?)?)
    }

    /// Verifies the signature by `author` (`verify_strict`) and that `event_id` matches
    /// the recomputed digest.
    pub fn verify_signature(&self) -> Result<(), ProtocolError> {
        let input = self.envelope.signing_input()?;
        signing::verify_input(
            Context::Event,
            &self.envelope.author,
            &input,
            &self.signature,
        )?;
        if signing::digest_of_input(&input) != self.event_id.digest() {
            return Err(ProtocolError::EventIdMismatch);
        }
        Ok(())
    }
}

impl Serialize for SignedEnvelope {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_value()
            .map_err(serde::ser::Error::custom)?
            .serialize(s)
    }
}

/// Deserialization applies [`SignedEnvelope::from_value`] (strict schema, no
/// signature check). Prefer [`SignedEnvelope::from_json_bytes`] on raw bytes, which
/// also detects duplicate keys.
impl<'de> Deserialize<'de> for SignedEnvelope {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        SignedEnvelope::from_value(&v).map_err(serde::de::Error::custom)
    }
}

// =======================================================================================
// VerifiedEnvelope and stateless validation
// =======================================================================================

/// An envelope that passed [`validate_stateless`] at some `now`. Only obtainable from
/// that function.
///
/// The remaining (stateful) checks are the author's authorization, as given by
/// [`VerifiedEnvelope::authorization`] (a [`ph_core::MembershipOracle`] call for
/// QUESTION and ANSWER, the roll of the named charter for PROPOSAL, VOTE and RESULT,
/// charter succession for CHARTER, nothing more for root-authored REVOCATIONs, local
/// revocation state for MEMBERSHIP), and `event_id` uniqueness in the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEnvelope {
    envelope: SignedEnvelope,
    canonical_json: String,
}

impl VerifiedEnvelope {
    /// The verified envelope.
    pub fn envelope(&self) -> &SignedEnvelope {
        &self.envelope
    }

    /// Unwraps the verified envelope.
    pub fn into_envelope(self) -> SignedEnvelope {
        self.envelope
    }

    /// The canonical JCS text of the transmitted object (store this).
    pub fn canonical_json(&self) -> &str {
        &self.canonical_json
    }

    /// The verified event id.
    pub fn event_id(&self) -> EventId {
        self.envelope.event_id
    }

    /// The credential capability the author needs, for QUESTION and ANSWER only (see
    /// [`EventType::required_capability`]). Prefer [`Self::authorization`], which
    /// covers every type.
    pub fn required_capability(&self) -> Option<Capability> {
        self.envelope.event_type().required_capability()
    }

    /// The stateful authorization check that remains (see [`Authorization`]).
    pub fn authorization(&self) -> Authorization {
        self.envelope.event_type().authorization()
    }
}

impl Deref for VerifiedEnvelope {
    type Target = SignedEnvelope;
    fn deref(&self) -> &SignedEnvelope {
        &self.envelope
    }
}

/// Stateless validation of raw envelope bytes at local time `now`:
///
/// 1. size <= 64 KiB (raw and canonical), depth <= 8, no duplicate keys, integers only,
///    schema exactly `peerharness.event/0.1`, type in the allowlist, no unknown members,
///    typed body with its bounds;
/// 2. valid signature by `author` and matching `event_id`;
/// 3. the time rules of [`check_time_rules_for`]: `expires_at > created_at`, lifetime
///    <= 400 days, `created_at <= now + 5 min` (not for REVOCATION), `expires_at > now`
///    (not for the permanent types);
/// 4. MEMBERSHIP: the embedded credential and acceptance verify at `now`, the author is
///    the subject, same circle, the envelope does not outlive the credential.
///    REVOCATION: the embedded revocation's structure and signature verify (no time
///    rule), the author is its issuer (the root key, `circle_id == derive(author)`),
///    same circle. CHARTER: the embedded charter's structure and signature verify, the
///    author is its issuer (the root key), same circle, scope `*`.
pub fn validate_stateless(raw: &[u8], now: Timestamp) -> Result<VerifiedEnvelope, ProtocolError> {
    if raw.len() > MAX_EVENT_BYTES {
        return Err(ProtocolError::TooLarge {
            what: OBJECT,
            size: raw.len(),
            max: MAX_EVENT_BYTES,
        });
    }
    let v = jcs::parse_strict(raw, ParseLimits::EVENT)?;
    validate_stateless_value(&v, now)
}

/// [`validate_stateless`] for an already strictly parsed value (for example an element
/// of `PushEvents.events`).
pub fn validate_stateless_value(
    v: &Value,
    now: Timestamp,
) -> Result<VerifiedEnvelope, ProtocolError> {
    let env = SignedEnvelope::from_value(v)?;
    env.verify_signature()?;
    check_time_rules_for(env.event_type(), env.created_at, env.expires_at, now)?;
    env.check_bindings()?;
    match &env.body {
        EventBody::Membership(b) => verify_membership_proof(&b.to_proof(), now)?,
        EventBody::Revocation(b) => verify_revocation_signature(&b.revocation)?,
        EventBody::Charter(b) => verify_charter_signature(&b.charter)?,
        _ => {}
    }
    let canonical_json = env.to_canonical_json()?;
    Ok(VerifiedEnvelope {
        envelope: env,
        canonical_json,
    })
}

// =======================================================================================
// Builder
// =======================================================================================

/// Convenience builder for [`UnsignedEnvelope`] with per-type default lifetimes.
#[derive(Clone, Debug)]
pub struct EnvelopeBuilder {
    circle_id: CircleId,
    scope: Scope,
    body: EventBody,
    created_at: Option<Timestamp>,
    expires_at: Option<Timestamp>,
    nonce: Option<Nonce>,
}

impl EnvelopeBuilder {
    /// Starts an envelope for `body` in `circle_id` / `scope`.
    pub fn new(circle_id: CircleId, scope: Scope, body: EventBody) -> Self {
        Self {
            circle_id,
            scope,
            body,
            created_at: None,
            expires_at: None,
            nonce: None,
        }
    }

    /// Sets `created_at` (default: `now` passed to [`Self::build`]).
    pub fn created_at(mut self, t: Timestamp) -> Self {
        self.created_at = Some(t);
        self
    }

    /// Sets `expires_at` (default: `created_at` + the type's default lifetime, or the
    /// credential expiry for MEMBERSHIP).
    pub fn expires_at(mut self, t: Timestamp) -> Self {
        self.expires_at = Some(t);
        self
    }

    /// Sets the nonce (default: fresh from the OS RNG). Use fixed nonces only in tests.
    pub fn nonce(mut self, n: Nonce) -> Self {
        self.nonce = Some(n);
        self
    }

    /// Builds the unsigned envelope.
    pub fn build(
        self,
        author: DeviceKey,
        now: Timestamp,
    ) -> Result<UnsignedEnvelope, ProtocolError> {
        let created_at = self.created_at.unwrap_or(now);
        let expires_at = match (self.expires_at, &self.body) {
            (Some(t), _) => t,
            (None, EventBody::Membership(b)) => b.credential.expires_at,
            (None, b) => created_at.plus_secs(
                b.event_type()
                    .default_lifetime_secs()
                    .unwrap_or(lifetimes::QUESTION_SECS),
            ),
        };
        let nonce = match self.nonce {
            Some(n) => n,
            None => Nonce::random()?,
        };
        Ok(UnsignedEnvelope {
            circle_id: self.circle_id,
            scope: self.scope,
            author,
            nonce,
            created_at,
            expires_at,
            body: self.body,
        })
    }

    /// Builds and signs with `key` as the author.
    pub fn sign(self, key: &SigningKey, now: Timestamp) -> Result<SignedEnvelope, ProtocolError> {
        self.build(DeviceKey::from_signing_key(key), now)?.sign(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{
        UnsignedAcceptance, UnsignedMembershipCredential, UnsignedRevocation,
    };
    use ph_core::Role;
    use serde_json::json;

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn pk(seed: u8) -> DeviceKey {
        DeviceKey::from_signing_key(&sk(seed))
    }
    fn now() -> Timestamp {
        "2026-11-09T18:10:00Z".parse().unwrap()
    }
    fn circle() -> CircleId {
        CircleId::derive(&pk(2))
    }
    fn scope() -> Scope {
        Scope::new("team/backend").unwrap()
    }

    fn question() -> SignedEnvelope {
        EnvelopeBuilder::new(
            circle(),
            scope(),
            EventBody::Question(QuestionBody {
                question: "Should this repository use pnpm rather than npm?".into(),
                topic: "package-manager".into(),
                related_candidate: None,
            }),
        )
        .nonce(Nonce::from_bytes([1; 16]))
        .sign(&sk(1), now())
        .unwrap()
    }

    fn raw(e: &SignedEnvelope) -> Vec<u8> {
        e.to_canonical_json().unwrap().into_bytes()
    }

    #[test]
    fn roundtrip_and_validate() {
        let e = question();
        assert_eq!(e.expires_at, now().plus_days(30));
        let v = validate_stateless(&raw(&e), now()).unwrap();
        assert_eq!(v.event_id(), e.event_id);
        assert_eq!(v.envelope(), &e);
        assert_eq!(v.required_capability(), Some(Capability::Ask));
        assert_eq!(SignedEnvelope::from_json_bytes(&raw(&e)).unwrap(), e);
        let via_serde: SignedEnvelope = serde_json::from_slice(&raw(&e)).unwrap();
        assert_eq!(via_serde, e);
        // non-canonical whitespace in input is fine
        let pretty = serde_json::to_vec_pretty(&e.to_value().unwrap()).unwrap();
        assert!(validate_stateless(&pretty, now()).is_ok());
    }

    fn mutate(e: &SignedEnvelope, f: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut v = e.to_value().unwrap();
        f(&mut v);
        v.to_string().into_bytes()
    }

    #[test]
    fn negative_cases() {
        let e = question();
        let n = now();
        let check = |bytes: Vec<u8>| validate_stateless(&bytes, n);

        // modified body after signing
        assert!(matches!(
            check(mutate(&e, |v| v["body"]["question"] = json!("Use npm?"))),
            Err(ProtocolError::BadSignature { .. })
        ));
        // forged signature
        assert!(matches!(
            check(mutate(&e, |v| v["signature"] =
                json!(Signature::from_bytes([3; 64]).to_string()))),
            Err(ProtocolError::BadSignature { .. })
        ));
        // signature by a different key
        let other = UnsignedEnvelope {
            author: pk(3),
            ..e.envelope.clone()
        }
        .sign(&sk(3))
        .unwrap();
        assert!(matches!(
            check(mutate(&e, |v| v["signature"] = json!(other.signature.to_string()))),
            Err(ProtocolError::BadSignature { .. })
        ));
        // wrong event id
        assert!(matches!(
            check(mutate(&e, |v| v["event_id"] =
                json!(Digest::sha256(b"x").to_string()))),
            Err(ProtocolError::EventIdMismatch)
        ));
        // unknown top-level field
        assert!(matches!(
            check(mutate(&e, |v| v["extra"] = json!(1))),
            Err(ProtocolError::Schema { .. })
        ));
        // unknown body field
        assert!(matches!(
            check(mutate(&e, |v| v["body"]["extra"] = json!("x"))),
            Err(ProtocolError::Schema { .. })
        ));
        // explicit null optional
        assert!(matches!(
            check(mutate(&e, |v| v["body"]["related_candidate"] = Value::Null)),
            Err(ProtocolError::Schema { .. })
        ));
        // unknown type
        assert_eq!(
            check(mutate(&e, |v| v["type"] = json!("GOSSIP"))),
            Err(ProtocolError::UnknownEventType)
        );
        assert_eq!(
            check(mutate(&e, |v| v["type"] = json!("question"))),
            Err(ProtocolError::UnknownEventType)
        );
        // wrong schema
        assert!(matches!(
            check(mutate(&e, |v| v["schema"] = json!("peerharness.event/0.2"))),
            Err(ProtocolError::UnsupportedSchema { .. })
        ));
        // missing signature / event_id
        assert!(matches!(
            check(mutate(&e, |v| {
                v.as_object_mut().unwrap().remove("signature");
            })),
            Err(ProtocolError::Schema { .. })
        ));
        assert!(matches!(
            check(mutate(&e, |v| {
                v.as_object_mut().unwrap().remove("event_id");
            })),
            Err(ProtocolError::Schema { .. })
        ));
        // float number anywhere
        assert_eq!(
            check(mutate(&e, |v| v["body"]["topic"] = json!(1.5))),
            Err(ProtocolError::Jcs(JcsError::NonInteger))
        );
        // duplicate keys
        let s = String::from_utf8(raw(&e)).unwrap();
        let dup = s.replacen("{", "{\"scope\":\"team\",", 1);
        assert_eq!(
            check(dup.into_bytes()),
            Err(ProtocolError::Jcs(JcsError::DuplicateKey))
        );
        // oversize
        let mut big = raw(&e);
        big.extend(std::iter::repeat_n(b' ', MAX_EVENT_BYTES));
        assert!(matches!(check(big), Err(ProtocolError::TooLarge { .. })));
        // too deep
        let deep = mutate(&e, |v| {
            v["body"]["topic"] = json!([[[[[[[["x"]]]]]]]]);
        });
        assert!(matches!(
            check(deep),
            Err(ProtocolError::Jcs(JcsError::TooDeep { .. }))
        ));
        // expired / future-dated
        assert!(matches!(
            validate_stateless(&raw(&e), e.expires_at),
            Err(ProtocolError::Time {
                rule: TimeRule::Expired,
                ..
            })
        ));
        assert!(matches!(
            validate_stateless(&raw(&e), n.minus_secs(CLOCK_SKEW_SECS + 1)),
            Err(ProtocolError::Time {
                rule: TimeRule::FutureDated,
                ..
            })
        ));
        assert!(validate_stateless(&raw(&e), n.minus_secs(CLOCK_SKEW_SECS)).is_ok());
        // garbage
        assert!(check(b"not json".to_vec()).is_err());
        assert!(check(b"[]".to_vec()).is_err());
    }

    #[test]
    fn lifetime_rules_on_sign() {
        let base = question().envelope;
        let long = UnsignedEnvelope {
            expires_at: base.created_at.plus_days(401),
            ..base.clone()
        };
        assert!(matches!(
            long.sign(&sk(1)),
            Err(ProtocolError::Time {
                rule: TimeRule::LifetimeTooLong,
                ..
            })
        ));
        let inverted = UnsignedEnvelope {
            expires_at: base.created_at,
            ..base.clone()
        };
        assert!(inverted.sign(&sk(1)).is_err());
        assert!(base.clone().sign(&sk(3)).is_err());
        assert!(check_time_rules(now(), now().plus_days(400), now()).is_ok());
        assert!(check_time_rules(now(), now().plus_days(400).plus_secs(1), now()).is_err());
    }

    #[test]
    fn body_bounds() {
        let q = |question: String, topic: &str| {
            EnvelopeBuilder::new(
                circle(),
                scope(),
                EventBody::Question(QuestionBody {
                    question,
                    topic: topic.into(),
                    related_candidate: None,
                }),
            )
            .sign(&sk(1), now())
        };
        assert!(q("x".repeat(2000), "t").is_ok());
        assert!(q("x".repeat(2001), "t").is_err());
        assert!(q(String::new(), "t").is_err());
        assert!(q("ok".into(), "").is_err());
        assert!(q("ok".into(), "a\nb").is_err());
        assert!(q("\u{1b}[2Jclear".into(), "t").is_err());

        let p = |name: &str, size: u64| {
            EnvelopeBuilder::new(
                circle(),
                scope(),
                EventBody::Proposal(adopt_body(name, size)),
            )
            .sign(&sk(1), now())
        };
        assert!(p("pnpm-repo", 10).is_ok());
        assert!(p("Pnpm", 10).is_err());
        assert!(p("../x", 10).is_err());
        assert!(p("pnpm", 0).is_err());
        assert!(p("pnpm", MAX_BUNDLE_BYTES as u64 + 1).is_err());

        let r = |approvals: Vec<EventId>| {
            EnvelopeBuilder::new(
                circle(),
                scope(),
                EventBody::Result(ResultBody {
                    proposal_id: EventId::from_digest(Digest::sha256(b"p")),
                    approvals,
                }),
            )
            .sign(&sk(1), now())
        };
        let mut ids: Vec<EventId> = (0..65u32)
            .map(|i| EventId::from_digest(Digest::sha256(&i.to_be_bytes())))
            .collect();
        ids.sort_by_key(EventId::to_string);
        assert!(r(ids[..64].to_vec()).is_ok());
        assert!(r(ids.clone()).is_err(), "more than 64 approvals");
        assert!(r(vec![ids[0], ids[0]]).is_err(), "duplicate approval");
        assert!(r(vec![ids[1], ids[0]]).is_err(), "unsorted approvals");
        assert!(r(Vec::new()).is_err(), "no approvals");
        // ResultBody::new puts them in canonical order
        let b = ResultBody::new(ids[0], vec![ids[2], ids[1]]);
        assert_eq!(b.approvals, vec![ids[1], ids[2]]);
    }

    fn adopt_body(name: &str, size: u64) -> ProposalBody {
        ProposalBody {
            charter: Digest::sha256(b"charter"),
            title: "t".into(),
            summary: String::new(),
            action: ProposalAction::Adopt(AdoptAction {
                skill_name: name.into(),
                description: "d".into(),
                bundle_digest: Digest::sha256(b"b"),
                bundle_size: size,
                related_question: None,
                supersedes: None,
            }),
        }
    }

    fn roll_entry(member: &str, seed: u8) -> crate::charter::RollEntry {
        crate::charter::RollEntry::new(member, vec![pk(seed)], vec![Scope::all()])
    }

    fn founding_charter() -> Charter {
        crate::charter::UnsignedCharter::founding(
            pk(2),
            CharterContent::founding(roll_entry("alice", 1)),
            now(),
        )
        .sign(&sk(2))
        .unwrap()
    }

    fn sign_proposal(scope: Scope, body: ProposalBody) -> Result<SignedEnvelope, ProtocolError> {
        EnvelopeBuilder::new(circle(), scope, EventBody::Proposal(body))
            .nonce(Nonce::from_bytes([5; 16]))
            .sign(&sk(1), now())
    }

    #[test]
    fn proposal_kinds_on_the_wire() {
        let target = EventId::from_digest(Digest::sha256(b"old"));
        let mut next = CharterContent::founding(roll_entry("alice", 1));
        next.roll.push(roll_entry("bob", 3));
        next.normalize();

        let adopt = sign_proposal(scope(), adopt_body("pnpm-repo", 10)).unwrap();
        let repeal = sign_proposal(
            scope(),
            ProposalBody {
                charter: Digest::sha256(b"charter"),
                title: "Drop the pnpm rule".into(),
                summary: "We moved to bun.".into(),
                action: ProposalAction::Repeal { target },
            },
        )
        .unwrap();
        let amend_body = ProposalBody {
            charter: Digest::sha256(b"charter"),
            title: "Admit bob".into(),
            summary: String::new(),
            action: ProposalAction::Amend { next: next.clone() },
        };
        let amend = sign_proposal(Scope::all(), amend_body.clone()).unwrap();

        // Each kind carries exactly its own members.
        let members = |e: &SignedEnvelope| -> Vec<String> {
            let v = e.to_value().unwrap();
            v["body"].as_object().unwrap().keys().cloned().collect()
        };
        assert_eq!(
            members(&adopt),
            [
                "bundle_digest",
                "bundle_size",
                "charter",
                "description",
                "kind",
                "skill_name",
                "summary",
                "title"
            ]
        );
        assert_eq!(
            members(&repeal),
            ["charter", "kind", "summary", "target", "title"]
        );
        assert_eq!(
            members(&amend),
            ["charter", "kind", "next", "summary", "title"]
        );
        for (e, kind) in [(&adopt, "adopt"), (&repeal, "repeal"), (&amend, "amend")] {
            assert_eq!(e.to_value().unwrap()["body"]["kind"], json!(kind));
            let v = validate_stateless(&raw(e), now()).unwrap();
            assert_eq!(v.envelope(), e);
            assert_eq!(v.authorization(), Authorization::Roll);
            assert_eq!(v.required_capability(), None);
        }

        // An amend proposal concerns everyone: it must have scope `*`.
        assert!(sign_proposal(scope(), amend_body).is_err());
        // The proposed content is checked like a charter's.
        let mut bad = next;
        bad.roll.swap(0, 1);
        assert!(sign_proposal(
            Scope::all(),
            ProposalBody {
                charter: Digest::sha256(b"charter"),
                title: "x".into(),
                summary: String::new(),
                action: ProposalAction::Amend { next: bad },
            }
        )
        .is_err());

        // A member of another kind is refused, as is a missing required one.
        let n = now();
        let check = |bytes: Vec<u8>| validate_stateless(&bytes, n);
        for bytes in [
            mutate(&adopt, |v| v["body"]["target"] = json!(target.to_string())),
            mutate(&repeal, |v| v["body"]["skill_name"] = json!("pnpm-repo")),
            mutate(&repeal, |v| {
                v["body"]["supersedes"] = json!(target.to_string())
            }),
            mutate(&amend, |v| v["body"]["target"] = json!(target.to_string())),
            mutate(&adopt, |v| {
                v["body"].as_object_mut().unwrap().remove("bundle_digest");
            }),
            mutate(&repeal, |v| {
                v["body"].as_object_mut().unwrap().remove("target");
            }),
            mutate(&adopt, |v| {
                v["body"].as_object_mut().unwrap().remove("charter");
            }),
            mutate(&adopt, |v| v["body"]["kind"] = json!("veto")),
            mutate(&adopt, |v| v["body"]["kind"] = json!("repeal")),
        ] {
            assert!(
                matches!(check(bytes), Err(ProtocolError::Schema { .. })),
                "a body that mixes kinds must be a schema error"
            );
        }
    }

    #[test]
    fn decision_events_never_expire() {
        let proposal = sign_proposal(scope(), adopt_body("pnpm-repo", 10)).unwrap();
        let vote = EnvelopeBuilder::new(
            circle(),
            scope(),
            EventBody::Vote(VoteBody {
                proposal_id: proposal.event_id,
                decision: VoteDecision::Approve,
                rationale: None,
            }),
        )
        .sign(&sk(1), now())
        .unwrap();
        let result = EnvelopeBuilder::new(
            circle(),
            scope(),
            EventBody::Result(ResultBody::new(proposal.event_id, vec![vote.event_id])),
        )
        .sign(&sk(1), now())
        .unwrap();
        // A ballot is bound to the proposal by its id alone.
        assert_eq!(
            vote.to_value().unwrap()["body"],
            json!({"proposal_id": proposal.event_id.to_string(), "decision": "approve"})
        );
        for e in [&proposal, &vote, &result] {
            assert!(e.event_type().is_permanent() && e.event_type().is_decision());
            assert_eq!(e.expires_at, now().plus_days(400));
            // Ten years on, the record still verifies: the outcome of a vote must not
            // depend on a clock.
            validate_stateless(&raw(e), now().plus_days(3650)).unwrap();
            // A date from the future is still refused.
            assert!(matches!(
                validate_stateless(&raw(e), now().minus_secs(CLOCK_SKEW_SECS + 1)),
                Err(ProtocolError::Time {
                    rule: TimeRule::FutureDated,
                    ..
                })
            ));
        }
        // QUESTION and ANSWER still expire.
        assert!(!EventType::Question.is_permanent() && !EventType::Answer.is_permanent());
        assert!(!EventType::Membership.is_permanent());
    }

    #[test]
    fn charter_events() {
        let charter = founding_charter();
        let event = |author: u8, scope: Scope, charter: Charter| {
            EnvelopeBuilder::new(circle(), scope, EventBody::Charter(CharterBody { charter }))
                .nonce(Nonce::from_bytes([6; 16]))
                .sign(&sk(author), now())
        };
        let e = event(2, Scope::all(), charter.clone()).unwrap();
        let v = validate_stateless(&raw(&e), now().plus_days(3650)).unwrap();
        assert_eq!(v.authorization(), Authorization::CircleRoot);
        assert!(e.event_type().is_control_plane() && e.event_type().is_permanent());
        // only the root key may author it, and only with scope `*`
        assert!(event(1, Scope::all(), charter.clone()).is_err());
        assert!(event(2, scope(), charter.clone()).is_err());
        // a charter of another circle cannot ride in this circle's envelope
        let other = crate::charter::UnsignedCharter::founding(
            pk(7),
            CharterContent::founding(roll_entry("mallory", 7)),
            now(),
        )
        .sign(&sk(7))
        .unwrap();
        assert!(event(2, Scope::all(), other).is_err());
        // tampering with the embedded charter breaks its signature
        let bad = mutate(&e, |v| {
            v["body"]["charter"]["rules"]["binding"] = json!(false)
        });
        assert!(validate_stateless(&bad, now()).is_err());
        let bad = mutate(&e, |v| v["body"]["charter"]["seq"] = json!(2));
        assert!(validate_stateless(&bad, now()).is_err());
    }

    fn membership_event(author: u8) -> Result<SignedEnvelope, ProtocolError> {
        let cred = UnsignedMembershipCredential::new(
            pk(2),
            pk(1),
            vec![Role::Member],
            vec![scope()],
            now(),
            now().plus_days(30),
        )
        .sign(&sk(2))?;
        let acc = UnsignedAcceptance::for_credential(&cred, now())?.sign(&sk(1))?;
        EnvelopeBuilder::new(
            circle(),
            Scope::all(),
            EventBody::Membership(MembershipBody {
                credential: cred,
                acceptance: acc,
            }),
        )
        .nonce(Nonce::from_bytes([2; 16]))
        .sign(&sk(author), now())
    }

    #[test]
    fn membership_events() {
        let e = membership_event(1).unwrap();
        assert_eq!(e.expires_at, now().plus_days(30));
        let v = validate_stateless(&raw(&e), now()).unwrap();
        assert_eq!(v.required_capability(), None);
        // only the subject may author it
        assert!(membership_event(3).is_err());
        // expired credential inside
        assert!(validate_stateless(&raw(&e), now().plus_days(30)).is_err());
        // tampered embedded credential
        let bad = mutate(&e, |v| v["body"]["credential"]["scopes"] = json!(["*"]));
        assert!(validate_stateless(&bad, now()).is_err());
    }

    #[test]
    fn revocation_events() {
        let rev = UnsignedRevocation::new(
            pk(2),
            pk(1),
            now(),
            "bye".into(),
            Nonce::from_bytes([4; 16]),
        )
        .sign(&sk(2))
        .unwrap();
        let e = EnvelopeBuilder::new(
            circle(),
            Scope::all(),
            EventBody::Revocation(RevocationBody {
                revocation: rev.clone(),
            }),
        )
        .sign(&sk(2), now())
        .unwrap();
        assert!(validate_stateless(&raw(&e), now()).is_ok());
        // A revocation only ever denies, so it is accepted whatever the clocks say:
        // from an issuer whose clock runs a day ahead, and ten years later.
        assert!(validate_stateless(&raw(&e), now().minus_secs(86_400)).is_ok());
        assert!(validate_stateless(&raw(&e), now().plus_days(3650)).is_ok());
        assert_eq!(e.expires_at, now().plus_days(400));
        // a member cannot forward-author a revocation
        assert!(EnvelopeBuilder::new(
            circle(),
            Scope::all(),
            EventBody::Revocation(RevocationBody { revocation: rev })
        )
        .sign(&sk(1), now())
        .is_err());
    }

    #[test]
    fn event_type_strings() {
        for t in EventType::ALL {
            assert_eq!(t.as_str().parse::<EventType>().unwrap(), t);
            assert_eq!(serde_json::to_value(t).unwrap(), json!(t.as_str()));
        }
    }
}
