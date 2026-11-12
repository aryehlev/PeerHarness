//! Typed, read-only views of PROPOSAL, VOTE and RESULT events for the tally.
//!
//! A view can only be built from a correctly signed envelope:
//! [`from_envelope`](ProposalView::from_envelope) re-verifies the signature and event id
//! (and the stateless body checks) of a [`SignedEnvelope`] (for example one loaded from
//! the store), and
//! [`from_verified`](ProposalView::from_verified) accepts a [`VerifiedEnvelope`] whose
//! signature was already checked by `ph_protocol::validate_stateless`. Fields are
//! private, so a view cannot be fabricated or edited after construction: a vote cannot
//! be retargeted to another proposal without breaking its signature.
//!
//! Views do **not** check authorization; the tally does that against the roll of the
//! charter the proposal names. Decision events never expire (architecture 10.11).

use std::fmt;

use ph_core::{CircleId, DeviceKey, Digest, EventId, Scope, Timestamp};
use ph_protocol::{
    AdoptAction, CharterContent, Electorate, EventBody, EventType, ProposalAction, ProposalBody,
    ProposalKind, ResultBody, SignedEnvelope, VerifiedEnvelope, VoteBody, VoteDecision,
};

/// Why a view could not be built.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, thiserror::Error)]
pub enum ViewError {
    /// The envelope is not of the expected type.
    #[error("unexpected event type")]
    WrongType {
        /// The type the view requires.
        expected: EventType,
    },
    /// The signature or event id does not verify.
    #[error("event signature does not verify")]
    BadSignature,
    /// The body fails the protocol's stateless body checks (bounds, skill name, unique
    /// approvals, ...). Only possible for an envelope built in memory, since parsing
    /// already applies these checks.
    #[error("event body is invalid")]
    InvalidBody,
}

fn checked(env: &SignedEnvelope, expected: EventType) -> Result<(), ViewError> {
    if env.event_type() != expected {
        return Err(ViewError::WrongType { expected });
    }
    env.verify_signature()
        .map_err(|_| ViewError::BadSignature)?;
    env.check_bindings().map_err(|_| ViewError::InvalidBody)
}

macro_rules! common_accessors {
    () => {
        /// The event id.
        pub fn event_id(&self) -> EventId {
            self.env.event_id
        }
        /// The circle id.
        pub fn circle_id(&self) -> CircleId {
            self.env.circle_id
        }
        /// The envelope scope.
        pub fn scope(&self) -> &Scope {
            &self.env.scope
        }
        /// The signing author.
        pub fn author(&self) -> DeviceKey {
            self.env.author
        }
        /// The author-claimed creation time (informational only).
        pub fn created_at(&self) -> Timestamp {
            self.env.created_at
        }
        /// The envelope expiry.
        pub fn expires_at(&self) -> Timestamp {
            self.env.expires_at
        }
        /// The underlying signed envelope.
        pub fn envelope(&self) -> &SignedEnvelope {
            &self.env
        }
    };
}

/// A signature-verified PROPOSAL.
#[derive(Clone, PartialEq, Eq)]
pub struct ProposalView {
    env: SignedEnvelope,
    body: ProposalBody,
}

impl ProposalView {
    /// Builds a view from a signed envelope, re-verifying its signature, event id and
    /// stateless body checks.
    pub fn from_envelope(env: &SignedEnvelope) -> Result<Self, ViewError> {
        checked(env, EventType::Proposal)?;
        Self::unchecked(env)
    }

    /// Builds a view from an envelope already verified by `validate_stateless`.
    pub fn from_verified(env: &VerifiedEnvelope) -> Result<Self, ViewError> {
        Self::unchecked(env)
    }

    fn unchecked(env: &SignedEnvelope) -> Result<Self, ViewError> {
        match &env.body {
            EventBody::Proposal(b) => Ok(Self {
                env: env.clone(),
                body: b.clone(),
            }),
            _ => Err(ViewError::WrongType {
                expected: EventType::Proposal,
            }),
        }
    }

    common_accessors!();

    /// The proposal body (title, summary and description are peer-supplied text:
    /// display only, never log).
    pub fn body(&self) -> &ProposalBody {
        &self.body
    }
    /// The proposal kind.
    pub fn kind(&self) -> ProposalKind {
        self.body.kind()
    }
    /// Digest of the charter this proposal is voted under.
    pub fn charter(&self) -> Digest {
        self.body.charter
    }
    /// The rule, for an `adopt` proposal.
    pub fn adopt(&self) -> Option<&AdoptAction> {
        self.body.as_adopt()
    }
    /// The skill name, for an `adopt` proposal.
    pub fn skill_name(&self) -> Option<&str> {
        self.adopt().map(|a| a.skill_name.as_str())
    }
    /// The proposed bundle digest, for an `adopt` proposal.
    pub fn bundle_digest(&self) -> Option<Digest> {
        self.adopt().map(|a| a.bundle_digest)
    }
    /// The earlier proposal an `adopt` proposal claims to revise, if any.
    pub fn supersedes(&self) -> Option<EventId> {
        self.adopt().and_then(|a| a.supersedes)
    }
    /// The `adopt` proposal a `repeal` proposal targets.
    pub fn repeal_target(&self) -> Option<EventId> {
        match &self.body.action {
            ProposalAction::Repeal { target } => Some(*target),
            _ => None,
        }
    }
    /// The proposed next charter content, for an `amend` proposal.
    pub fn amend_next(&self) -> Option<&CharterContent> {
        match &self.body.action {
            ProposalAction::Amend { next } => Some(next),
            _ => None,
        }
    }
    /// Who votes on this proposal (architecture section 10.3): the whole roll for an
    /// `amend` proposal, otherwise the members concerned by the envelope scope.
    pub fn electorate(&self) -> Electorate<'_> {
        match self.kind() {
            ProposalKind::Amend => Electorate::WholeRoll,
            ProposalKind::Adopt | ProposalKind::Repeal => Electorate::Scope(&self.env.scope),
        }
    }
}

impl fmt::Debug for ProposalView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProposalView")
            .field("event_id", &self.env.event_id)
            .field("circle_id", &self.env.circle_id)
            .field("author", &self.env.author)
            .field("body", &self.body)
            .finish()
    }
}

/// A signature-verified VOTE.
#[derive(Clone, PartialEq, Eq)]
pub struct VoteView {
    env: SignedEnvelope,
    body: VoteBody,
}

impl VoteView {
    /// Builds a view from a signed envelope, re-verifying its signature, event id and
    /// stateless body checks.
    pub fn from_envelope(env: &SignedEnvelope) -> Result<Self, ViewError> {
        checked(env, EventType::Vote)?;
        Self::unchecked(env)
    }

    /// Builds a view from an envelope already verified by `validate_stateless`.
    pub fn from_verified(env: &VerifiedEnvelope) -> Result<Self, ViewError> {
        Self::unchecked(env)
    }

    fn unchecked(env: &SignedEnvelope) -> Result<Self, ViewError> {
        match &env.body {
            EventBody::Vote(b) => Ok(Self {
                env: env.clone(),
                body: b.clone(),
            }),
            _ => Err(ViewError::WrongType {
                expected: EventType::Vote,
            }),
        }
    }

    common_accessors!();

    /// The device that signed the ballot (same as [`author`](Self::author)). Which
    /// member it signs for is decided by the roll.
    pub fn voter(&self) -> DeviceKey {
        self.env.author
    }
    /// The proposal id the ballot signs. It is the hash of everything the proposer
    /// signed (the signature itself is not hashed).
    pub fn proposal_id(&self) -> EventId {
        self.body.proposal_id
    }
    /// The decision.
    pub fn decision(&self) -> VoteDecision {
        self.body.decision
    }
    /// The optional rationale (peer-supplied text: display only, never log).
    pub fn rationale(&self) -> Option<&str> {
        self.body.rationale.as_deref()
    }
    /// Rationale length in characters (0 when absent).
    pub fn rationale_chars(&self) -> usize {
        self.body
            .rationale
            .as_deref()
            .map_or(0, |r| r.chars().count())
    }
}

impl fmt::Debug for VoteView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VoteView")
            .field("event_id", &self.env.event_id)
            .field("circle_id", &self.env.circle_id)
            .field("voter", &self.env.author)
            .field("created_at", &self.env.created_at)
            .field("body", &self.body)
            .finish()
    }
}

/// A signature-verified RESULT: a certificate that a proposal passed. It carries no
/// authority; [`crate::verify_result`] checks the ballots it lists.
#[derive(Clone, PartialEq, Eq)]
pub struct ResultView {
    env: SignedEnvelope,
    body: ResultBody,
}

impl ResultView {
    /// Builds a view from a signed envelope, re-verifying its signature, event id and
    /// stateless body checks.
    pub fn from_envelope(env: &SignedEnvelope) -> Result<Self, ViewError> {
        checked(env, EventType::Result)?;
        Self::unchecked(env)
    }

    /// Builds a view from an envelope already verified by `validate_stateless`.
    pub fn from_verified(env: &VerifiedEnvelope) -> Result<Self, ViewError> {
        Self::unchecked(env)
    }

    fn unchecked(env: &SignedEnvelope) -> Result<Self, ViewError> {
        match &env.body {
            EventBody::Result(b) => Ok(Self {
                env: env.clone(),
                body: b.clone(),
            }),
            _ => Err(ViewError::WrongType {
                expected: EventType::Result,
            }),
        }
    }

    common_accessors!();

    /// The device that assembled the certificate (same as [`author`](Self::author)).
    pub fn assembler(&self) -> DeviceKey {
        self.env.author
    }
    /// The proposal the certificate is for.
    pub fn proposal_id(&self) -> EventId {
        self.body.proposal_id
    }
    /// The ballots listed as approvals.
    pub fn approvals(&self) -> &[EventId] {
        &self.body.approvals
    }
}

impl fmt::Debug for ResultView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResultView")
            .field("event_id", &self.env.event_id)
            .field("circle_id", &self.env.circle_id)
            .field("assembler", &self.env.author)
            .field("proposal_id", &self.body.proposal_id)
            .field("approvals", &self.body.approvals.len())
            .finish()
    }
}
