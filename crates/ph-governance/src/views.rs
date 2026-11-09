//! Typed, read-only views of PROPOSAL, VOTE and RELEASE events for the tally.
//!
//! A view can only be built from a correctly signed envelope:
//! [`from_envelope`](ProposalView::from_envelope) re-verifies the signature and event id
//! (and the stateless body checks) of a [`SignedEnvelope`] (for example one loaded from
//! the store), and
//! [`from_verified`](ProposalView::from_verified) accepts a [`VerifiedEnvelope`] whose
//! signature was already checked by `ph_protocol::validate_stateless`. Fields are
//! private, so a view cannot be fabricated or edited after construction: a vote cannot
//! be retargeted to another proposal or digest without breaking its signature.
//!
//! Views do **not** check authorization or expiry; the tally does that at evaluation
//! time.

use std::fmt;

use ph_core::{CircleId, DeviceKey, Digest, EventId, Scope, Timestamp};
use ph_protocol::{
    EventBody, EventType, ProposalBody, ReleaseBody, SignedEnvelope, VerifiedEnvelope, VoteBody,
    VoteDecision,
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
    /// stateless body checks. Time rules are not checked here (the tally and release
    /// verification apply them at evaluation time).
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

    /// The proposal body (title, description, provenance summary are peer-supplied
    /// text: display only, never log).
    pub fn body(&self) -> &ProposalBody {
        &self.body
    }
    /// The skill name.
    pub fn skill_name(&self) -> &str {
        &self.body.skill_name
    }
    /// The proposed bundle digest.
    pub fn bundle_digest(&self) -> Digest {
        self.body.bundle_digest
    }
    /// The proposal this one claims to supersede, if any.
    pub fn supersedes(&self) -> Option<EventId> {
        self.body.supersedes
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
    /// stateless body checks. Time rules are not checked here (the tally and release
    /// verification apply them at evaluation time).
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

    /// The voter (same as [`author`](Self::author)).
    pub fn voter(&self) -> DeviceKey {
        self.env.author
    }
    /// The proposal id the vote signs.
    pub fn proposal_id(&self) -> EventId {
        self.body.proposal_id
    }
    /// The bundle digest the vote signs.
    pub fn bundle_digest(&self) -> Digest {
        self.body.bundle_digest
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

/// A signature-verified RELEASE (a claim, never evidence on its own).
#[derive(Clone, PartialEq, Eq)]
pub struct ReleaseView {
    env: SignedEnvelope,
    body: ReleaseBody,
}

impl ReleaseView {
    /// Builds a view from a signed envelope, re-verifying its signature, event id and
    /// stateless body checks. Time rules are not checked here (the tally and release
    /// verification apply them at evaluation time).
    pub fn from_envelope(env: &SignedEnvelope) -> Result<Self, ViewError> {
        checked(env, EventType::Release)?;
        Self::unchecked(env)
    }

    /// Builds a view from an envelope already verified by `validate_stateless`.
    pub fn from_verified(env: &VerifiedEnvelope) -> Result<Self, ViewError> {
        Self::unchecked(env)
    }

    fn unchecked(env: &SignedEnvelope) -> Result<Self, ViewError> {
        match &env.body {
            EventBody::Release(b) => Ok(Self {
                env: env.clone(),
                body: b.clone(),
            }),
            _ => Err(ViewError::WrongType {
                expected: EventType::Release,
            }),
        }
    }

    common_accessors!();

    /// The publisher (same as [`author`](Self::author)).
    pub fn publisher(&self) -> DeviceKey {
        self.env.author
    }
    /// The released proposal id.
    pub fn proposal_id(&self) -> EventId {
        self.body.proposal_id
    }
    /// The released bundle digest.
    pub fn bundle_digest(&self) -> Digest {
        self.body.bundle_digest
    }
    /// The released skill name.
    pub fn skill_name(&self) -> &str {
        &self.body.skill_name
    }
    /// The vote event ids claimed as approval evidence.
    pub fn approvals(&self) -> &[EventId] {
        &self.body.approvals
    }
}

impl fmt::Debug for ReleaseView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReleaseView")
            .field("event_id", &self.env.event_id)
            .field("circle_id", &self.env.circle_id)
            .field("publisher", &self.env.author)
            .field("proposal_id", &self.body.proposal_id)
            .field("bundle_digest", &self.body.bundle_digest)
            .field("approvals", &self.body.approvals.len())
            .finish()
    }
}
