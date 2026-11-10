//! Candidate lifecycle state machine (architecture section 9, spec 7.3).
//!
//! ```text
//! Detected -> LocalReview -> LocalApproved -> ShareAuthorized -> Questioned -> Proposed -> Voting -> Eligible -> Adopted
//! LocalApproved -> Adopted            (personal mode)
//! ShareAuthorized -> Proposed         (proposal without a prior question)
//! Eligible -> Voting                  (eligibility lost when a later reject/revise vote arrives)
//! Voting | Eligible -> Proposed       (a revised proposal replaces the current one)
//! any non-terminal -> Rejected | Superseded
//! ```
//!
//! Terminal states are [`Adopted`](CandidateStatus::Adopted),
//! [`Rejected`](CandidateStatus::Rejected) and [`Superseded`](CandidateStatus::Superseded).
//!
//! Transitions that require [`Actor::Human`]:
//!
//! * any transition **into** `LocalApproved`, `ShareAuthorized`, `Adopted` or `Proposed`.
//!
//! (`-> Proposed` is human-only because a proposal places human-confirmed text on the
//! network.) Everything coming from an LLM, a heuristic or a peer is [`Actor::System`].
//! A same-state "transition" is an error ([`TransitionError::Unchanged`]).

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::encoding::string_serde;
use crate::error::ParseError;

/// Lifecycle state of a local skill candidate.
///
/// The string form (used in storage and JSON) is `snake_case`, e.g. `"local_review"`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum CandidateStatus {
    /// Found by a detector, not yet shown to the human.
    Detected,
    /// Shown to the human for review.
    LocalReview,
    /// The human approved it as a personal rule.
    LocalApproved,
    /// The human authorized sharing it with a circle.
    ShareAuthorized,
    /// A QUESTION about it was sent.
    Questioned,
    /// A PROPOSAL for it was created.
    Proposed,
    /// Votes are being collected.
    Voting,
    /// The circle policy is satisfied.
    Eligible,
    /// Installed / adopted by the human (terminal).
    Adopted,
    /// Rejected (terminal).
    Rejected,
    /// Superseded by another candidate or proposal (terminal).
    Superseded,
}

/// Who is causing a transition.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Actor {
    /// A direct, explicit action by the local human user (a CLI confirmation).
    Human,
    /// Anything else: detectors, LLM providers, peers, background jobs.
    System,
}

/// Why a transition was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum TransitionError {
    /// `from == to`.
    #[error("candidate is already in state {0}")]
    Unchanged(CandidateStatus),
    /// `from` is terminal.
    #[error("candidate state {0} is terminal")]
    Terminal(CandidateStatus),
    /// The edge does not exist in the lifecycle.
    #[error("transition {from} -> {to} is not allowed")]
    NotAllowed {
        /// Current state.
        from: CandidateStatus,
        /// Requested state.
        to: CandidateStatus,
    },
    /// The edge exists but needs [`Actor::Human`].
    #[error("transition {from} -> {to} requires a human action")]
    RequiresHuman {
        /// Current state.
        from: CandidateStatus,
        /// Requested state.
        to: CandidateStatus,
    },
}

impl CandidateStatus {
    /// Every state, in lifecycle order.
    pub const ALL: [CandidateStatus; 11] = [
        CandidateStatus::Detected,
        CandidateStatus::LocalReview,
        CandidateStatus::LocalApproved,
        CandidateStatus::ShareAuthorized,
        CandidateStatus::Questioned,
        CandidateStatus::Proposed,
        CandidateStatus::Voting,
        CandidateStatus::Eligible,
        CandidateStatus::Adopted,
        CandidateStatus::Rejected,
        CandidateStatus::Superseded,
    ];

    /// The `snake_case` string form.
    pub const fn as_str(self) -> &'static str {
        match self {
            CandidateStatus::Detected => "detected",
            CandidateStatus::LocalReview => "local_review",
            CandidateStatus::LocalApproved => "local_approved",
            CandidateStatus::ShareAuthorized => "share_authorized",
            CandidateStatus::Questioned => "questioned",
            CandidateStatus::Proposed => "proposed",
            CandidateStatus::Voting => "voting",
            CandidateStatus::Eligible => "eligible",
            CandidateStatus::Adopted => "adopted",
            CandidateStatus::Rejected => "rejected",
            CandidateStatus::Superseded => "superseded",
        }
    }

    /// Whether no further transitions are possible.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            CandidateStatus::Adopted | CandidateStatus::Rejected | CandidateStatus::Superseded
        )
    }

    /// Whether entering this state always requires [`Actor::Human`].
    pub const fn requires_human_to_enter(self) -> bool {
        matches!(
            self,
            CandidateStatus::LocalApproved
                | CandidateStatus::ShareAuthorized
                | CandidateStatus::Adopted
                | CandidateStatus::Proposed
        )
    }

    /// Whether the lifecycle has an edge `self -> to` (ignoring the actor).
    pub fn can_transition_to(self, to: CandidateStatus) -> bool {
        use CandidateStatus::*;
        if self.is_terminal() || self == to {
            return false;
        }
        if matches!(to, Rejected | Superseded) {
            return true;
        }
        matches!(
            (self, to),
            (Detected, LocalReview)
                | (LocalReview, LocalApproved)
                | (LocalApproved, ShareAuthorized)
                | (LocalApproved, Adopted)
                | (ShareAuthorized, Questioned)
                | (ShareAuthorized, Proposed)
                | (Questioned, Proposed)
                | (Proposed, Voting)
                | (Voting, Eligible)
                | (Voting, Proposed)
                | (Eligible, Voting)
                | (Eligible, Proposed)
                | (Eligible, Adopted)
        )
    }
}

/// Checks and performs a lifecycle transition, returning the new state.
///
/// See the [module docs](self) for the full table.
pub fn transition(
    from: CandidateStatus,
    to: CandidateStatus,
    actor: Actor,
) -> Result<CandidateStatus, TransitionError> {
    if from == to {
        return Err(TransitionError::Unchanged(from));
    }
    if from.is_terminal() {
        return Err(TransitionError::Terminal(from));
    }
    if !from.can_transition_to(to) {
        return Err(TransitionError::NotAllowed { from, to });
    }
    if to.requires_human_to_enter() && actor != Actor::Human {
        return Err(TransitionError::RequiresHuman { from, to });
    }
    Ok(to)
}

impl fmt::Display for CandidateStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CandidateStatus {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        CandidateStatus::ALL
            .into_iter()
            .find(|c| c.as_str() == s)
            .ok_or(ParseError::new("candidate status", "unknown status"))
    }
}

string_serde!(CandidateStatus, "a candidate status string");

#[cfg(test)]
mod tests {
    use super::Actor::{Human, System};
    use super::CandidateStatus::*;
    use super::*;

    /// (from, to, allowed for System, allowed for Human)
    const TABLE: &[(CandidateStatus, CandidateStatus, bool, bool)] = &[
        (Detected, LocalReview, true, true),
        (LocalReview, LocalApproved, false, true),
        (LocalApproved, ShareAuthorized, false, true),
        (LocalApproved, Adopted, false, true),
        (ShareAuthorized, Questioned, true, true),
        (ShareAuthorized, Proposed, false, true),
        (Questioned, Proposed, false, true),
        (Proposed, Voting, true, true),
        (Voting, Eligible, true, true),
        (Voting, Proposed, false, true),
        (Eligible, Voting, true, true),
        (Eligible, Proposed, false, true),
        (Eligible, Adopted, false, true),
        // skipping steps is never allowed
        (Detected, LocalApproved, false, false),
        (Detected, ShareAuthorized, false, false),
        (Detected, Adopted, false, false),
        (LocalReview, ShareAuthorized, false, false),
        (LocalReview, Adopted, false, false),
        (ShareAuthorized, Adopted, false, false),
        (Questioned, Adopted, false, false),
        (Proposed, Adopted, false, false),
        (Voting, Adopted, false, false),
        (Proposed, Eligible, false, false),
        (Questioned, Voting, false, false),
        // backwards
        (LocalReview, Detected, false, false),
        (LocalApproved, LocalReview, false, false),
        (Proposed, Questioned, false, false),
        (Questioned, ShareAuthorized, false, false),
    ];

    #[test]
    fn table() {
        for &(from, to, sys, human) in TABLE {
            assert_eq!(
                transition(from, to, System).is_ok(),
                sys,
                "{from} -> {to} as System"
            );
            assert_eq!(
                transition(from, to, Human).is_ok(),
                human,
                "{from} -> {to} as Human"
            );
        }
    }

    #[test]
    fn any_non_terminal_can_be_rejected_or_superseded() {
        for from in CandidateStatus::ALL {
            for to in [Rejected, Superseded] {
                let r = transition(from, to, System);
                if from == to {
                    assert!(matches!(r, Err(TransitionError::Unchanged(_))));
                } else if from.is_terminal() {
                    assert!(matches!(r, Err(TransitionError::Terminal(_))));
                } else {
                    assert_eq!(r, Ok(to), "{from} -> {to}");
                }
            }
        }
    }

    #[test]
    fn terminal_states_are_final() {
        for from in [Adopted, Rejected, Superseded] {
            for to in CandidateStatus::ALL {
                assert!(transition(from, to, Human).is_err());
            }
        }
    }

    #[test]
    fn system_can_never_enter_human_states() {
        for from in CandidateStatus::ALL {
            for to in [LocalApproved, ShareAuthorized, Adopted, Proposed] {
                assert!(transition(from, to, System).is_err(), "{from} -> {to}");
            }
        }
    }

    #[test]
    fn error_kinds() {
        assert_eq!(
            transition(Detected, Detected, Human),
            Err(TransitionError::Unchanged(Detected))
        );
        assert_eq!(
            transition(LocalReview, LocalApproved, System),
            Err(TransitionError::RequiresHuman {
                from: LocalReview,
                to: LocalApproved
            })
        );
        assert_eq!(
            transition(Detected, Adopted, Human),
            Err(TransitionError::NotAllowed {
                from: Detected,
                to: Adopted
            })
        );
    }

    #[test]
    fn exhaustive_matches_edge_function() {
        for from in CandidateStatus::ALL {
            for to in CandidateStatus::ALL {
                let edge = from.can_transition_to(to);
                assert_eq!(transition(from, to, Human).is_ok(), edge);
                assert_eq!(
                    transition(from, to, System).is_ok(),
                    edge && !to.requires_human_to_enter()
                );
            }
        }
    }

    #[test]
    fn strings() {
        for s in CandidateStatus::ALL {
            assert_eq!(s.as_str().parse::<CandidateStatus>().unwrap(), s);
        }
        assert!("DETECTED".parse::<CandidateStatus>().is_err());
        assert_eq!(
            serde_json::to_string(&ShareAuthorized).unwrap(),
            "\"share_authorized\""
        );
    }
}
