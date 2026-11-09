//! # ph-governance
//!
//! Pure governance logic for PeerHarness (spec sections 5.3, 6.2, 6.4, 8 and 11;
//! architecture sections 5, 7 and 10; ADR-010). This crate has **no storage and no
//! network**: callers (the daemon and CLI in `apps/peerharness`) load events from the
//! store, pass them in, and act on the results.
//!
//! * [`authz`] module: the stateful half of incoming-event validation.
//!   [`authorize_incoming`] takes a [`VerifiedEnvelope`](ph_protocol::VerifiedEnvelope)
//!   (already through `ph_protocol::validate_stateless`) and applies the circle,
//!   membership, scope, capability and revocation rules. Helpers check body references
//!   that need stored events ([`check_answer_reference`], [`check_vote_reference`], ...).
//! * [`read`] module: who may read what. [`may_read`], [`may_read_event`], [`recipients`] and
//!   [`filter_readable`] filter outgoing pushes and `FetchEvents` responses;
//!   [`may_fetch_bundle`] gates `FetchBundle`.
//! * [`policy`] module: [`CirclePolicy`] (circle-wide quorum rules, hashed into the circle row)
//!   and [`LocalPolicy`] (a node's own stricter requirements).
//! * [`views`] module: [`ProposalView`], [`VoteView`] and [`ReleaseView`], typed read-only views
//!   built only from correctly signed envelopes.
//! * [`tally`] module: [`evaluate_proposal`] computes a [`ProposalStatus`] (approvers, blockers,
//!   counted and ignored votes, eligibility) and a human-readable explanation.
//! * [`release`] module: [`verify_release`] re-verifies a RELEASE claim against local votes.
//! * [`conflicts`] module: [`find_conflicts`] groups competing proposals; [`supersede_links`]
//!   reports lineage (votes never transfer).
//! * [`questions`] module: [`QuestionGuard`] quotas, dedup, mute and block for received
//!   questions, and [`normalize_question_text`].
//! * [`adoption`] module: [`adoption_readiness`], the final gate before a human installs a skill.
//!
//! ## Trust model in one paragraph
//!
//! Every node computes everything itself. A RELEASE is a claim, never evidence; votes
//! count only for the exact proposal id and bundle digest they sign; voter eligibility is
//! re-evaluated through the [`MembershipOracle`](ph_core::MembershipOracle) at evaluation
//! time (so later revocations and expiries take effect); and a node's [`LocalPolicy`] can
//! only add requirements. No accepted action depends on trusting LLM-generated
//! authorization decisions: every input here is a signature-verified event, an oracle
//! answer derived from root-signed credentials, or an explicit human confirmation.
//!
//! ## Privacy
//!
//! Error `Display` texts are generic and never include peer-supplied text (questions,
//! rationales, titles), key material or payload contents. `Debug` of the views prints
//! lengths instead of text. `tracing` events carry ids and counts only.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod adoption;
pub mod authz;
pub mod conflicts;
pub mod policy;
pub mod questions;
pub mod read;
pub mod release;
pub mod tally;
pub mod views;

pub use adoption::{adoption_readiness, NotReadyReason, Readiness};
pub use authz::{
    authorize_incoming, authorize_incoming_with_revocations, check_answer_reference, check_body,
    check_release_reference, check_supersedes_reference, check_vote_reference, AuthorizedEvent,
    Reference, Rejection, MEMBERSHIP_CONTROL_SCOPE,
};
pub use conflicts::{
    find_conflicts, supersede_links, superseded_by, Alternative, ConflictGroup, ConflictKey,
    SupersedeKind, SupersedeLink,
};
pub use policy::{CirclePolicy, LocalPolicy, PolicyError, MAX_MIN_APPROVALS, POLICY_HASH_CONTEXT};
pub use questions::{
    normalize_question_text, question_dedup_key, DropReason, GuardDecision, QuestionContext,
    QuestionGuard, QUESTION_DEDUP_CONTEXT,
};
pub use read::{
    filter_readable, may_fetch_bundle, may_read, may_read_event, recipients, recipients_for_event,
};
pub use release::{verify_release, ReleaseError};
pub use tally::{evaluate_proposal, Blocker, IgnoreReason, ProposalStatus, VoterDecision};
pub use views::{ProposalView, ReleaseView, ViewError, VoteView};
