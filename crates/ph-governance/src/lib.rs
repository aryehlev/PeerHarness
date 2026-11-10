//! # ph-governance
//!
//! Pure governance logic for PeerHarness (architecture sections 5, 7 and 10; ADR-010 and
//! ADR-012 to ADR-016). This crate has **no storage and no network**: callers (the
//! daemon and CLI in `apps/peerharness`) load events from the store, pass them in, and
//! act on the results.
//!
//! A circle governs itself by majority vote under a charter. In order of use:
//!
//! * [`authz`] module: the stateful half of incoming-event validation.
//!   [`authorize_incoming`] takes a [`VerifiedEnvelope`](ph_protocol::VerifiedEnvelope)
//!   (already through `ph_protocol::validate_stateless`) and authorizes it: QUESTION and
//!   ANSWER by credential, PROPOSAL, VOTE and RESULT by the **roll** of the charter the
//!   proposal names, CHARTER and REVOCATION by the circle root key.
//! * [`views`] module: [`ProposalView`], [`VoteView`] and [`ResultView`], typed read-only
//!   views built only from correctly signed envelopes.
//! * [`tally`] module: [`tally()`](tally::tally) counts the ballots for one proposal:
//!   one vote per member, a majority of the whole electorate, no veto, approvals that
//!   only accumulate, and no clock.
//! * [`result`] module: [`verify_result`] checks a RESULT certificate against the
//!   ballots it lists.
//! * [`ruleset`] module: [`rules_in_force`] computes the rules in force from the current
//!   charter and the proposals that passed under it, independent of arrival order.
//! * [`succession`] module: [`check_successor`] accepts a new charter only if a passed
//!   amendment justifies it, which makes the root key a notary rather than a ruler.
//!   Helpers draft the common amendments (admit or remove a member, change devices or
//!   rules).
//! * [`adoption`] module: [`adoption_step`] decides what a passed rule means on this
//!   machine: install, ask the owner, leave out, or refuse.
//! * [`policy`] module: [`LocalPolicy`], a node's own conditions for following a rule
//!   without asking.
//! * [`read`] module: who may read what. [`may_read`], [`may_read_event`], [`recipients`] and
//!   [`filter_readable`] filter outgoing pushes and `FetchEvents` responses;
//!   [`may_fetch_bundle`] gates `FetchBundle`.
//! * [`conflicts`] module: [`find_conflicts`] groups competing proposals; [`supersede_links`]
//!   reports lineage (approvals never transfer).
//! * [`questions`] module: [`QuestionGuard`] quotas, dedup, mute and block for received
//!   questions, and [`normalize_question_text`].
//!
//! ## Trust model in one paragraph
//!
//! Every node computes everything itself, from signed records. A proposal passes when
//! more than the charter's threshold of the members entitled to vote on it have
//! approved; a RESULT is only a list of ballots to check; a charter is accepted only
//! when a passed amendment justifies it. None of this consults a clock, so two nodes
//! holding the same records reach the same outcome and an outcome never changes later.
//! What a vote cannot do is fixed in code rather than in the charter: it cannot widen
//! read access ([`read`] never looks at ballots), it cannot make a node install a bundle
//! that fails its digest or validity checks, and it cannot bypass the owner's opt-out
//! ([`adoption`]). No accepted action depends on trusting model-generated decisions.
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
pub mod result;
pub mod ruleset;
pub mod succession;
pub mod tally;
pub mod views;

pub use adoption::{
    adoption_step, local_policy_met, AdoptionMode, AdoptionStep, AskReason, BundleChecks,
    OwnerChoice, RefuseReason,
};
pub use authz::{
    authorize_incoming, check_answer_reference, check_body, check_repeal_reference,
    check_supersedes_reference, AuthorizedEvent, DecisionRecords, NoRecords, Reference, Rejection,
    MEMBERSHIP_CONTROL_SCOPE,
};
pub use conflicts::{
    find_conflicts, supersede_links, superseded_by, Alternative, ConflictGroup, ConflictKey,
    SupersedeKind, SupersedeLink,
};
pub use policy::{LocalPolicy, PolicyError};
pub use questions::{
    normalize_question_text, question_dedup_key, DropReason, GuardDecision, QuestionContext,
    QuestionGuard, QUESTION_DEDUP_CONTEXT,
};
pub use read::{
    filter_readable, may_fetch_bundle, may_read, may_read_event, recipients, recipients_for_event,
};
pub use result::{verify_result, ResultError};
pub use ruleset::{
    carried_diff, rules_in_force, Basis, CarriedDiff, NotPassed, Passed, Rule, RuleSet,
};
pub use succession::{
    add_device, admit_member, change_rules, check_successor, propose_content, remove_device,
    remove_member, DraftError, SuccessionError,
};
pub use tally::{tally, threshold_for, Approval, Dissent, IgnoreReason, Tally, TallyError};
pub use views::{ProposalView, ResultView, ViewError, VoteView};
