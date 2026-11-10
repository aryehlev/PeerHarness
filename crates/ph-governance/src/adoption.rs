//! From "passed" to "installed on this machine" (architecture sections 10.9 and 10.10).
//!
//! Whether a rule has passed is a fact about the circle. Whether it is installed on a
//! machine is a decision of that machine's owner, given in advance: on joining, the
//! human is shown the charter and accepts it, and the node records an
//! [`AdoptionMode`].
//!
//! [`adoption_step`] combines that standing decision with the checks that no vote can
//! override:
//!
//! * a bundle that does not match its digest, or is not a valid instruction-only skill,
//!   is **refused**, whatever the tally and whatever the human says;
//! * a rule with a high-risk scanner finding is **never installed automatically**;
//! * a rule the owner opted out of stays out;
//! * in `ask` mode, or when the node's own [`LocalPolicy`] is not met, the owner is
//!   asked first.
//!
//! No accepted action depends on trusting model-generated decisions: every input here
//! is a [`Rule`] (obtainable only from a counted vote or a carried charter entry), a
//! verification result computed by deterministic code, or an explicit human choice.

use serde::{Deserialize, Serialize};

use crate::policy::LocalPolicy;
use crate::ruleset::Rule;
use crate::tally::Tally;

/// The owner's standing decision about rules that pass in a circle.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdoptionMode {
    /// Install passed rules without asking (and remove repealed ones), then tell the
    /// owner. The default in a circle whose charter is binding.
    Follow,
    /// Put every change in the inbox and act only on confirmation. The default in a
    /// circle whose charter is advisory, and always available as the owner's choice.
    #[default]
    Ask,
}

impl AdoptionMode {
    /// The mode a node starts in after the human accepts a charter with this
    /// `binding` value.
    pub const fn default_for(binding: bool) -> Self {
        if binding {
            AdoptionMode::Follow
        } else {
            AdoptionMode::Ask
        }
    }

    /// The config and storage string: `"follow"` or `"ask"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            AdoptionMode::Follow => "follow",
            AdoptionMode::Ask => "ask",
        }
    }
}

/// Results of the deterministic checks on a rule's bundle, computed locally just now.
/// Never fill these in from peer or model output.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BundleChecks {
    /// The fetched bundle's recomputed digest equals the rule's `bundle_digest`.
    pub digest_verified: bool,
    /// Strict `ph-skills` validation succeeded: one instruction-only `SKILL.md`, no
    /// tool pre-approval, no shell-injection syntax.
    pub skill_valid: bool,
    /// The risk scanner reported at least one high-risk finding.
    pub high_risk: bool,
}

/// Why a rule cannot be installed at all.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RefuseReason {
    /// The bundle bytes do not match the digest that was voted on.
    BundleDigestUnverified,
    /// The bundle is not a valid instruction-only skill.
    SkillInvalid,
}

/// Why the owner is asked before a rule is installed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AskReason {
    /// The scanner found high-risk content. Asked in every mode.
    HighRisk,
    /// The node's own [`LocalPolicy`] is not met by the approvals.
    LocalPolicy,
    /// The node is in [`AdoptionMode::Ask`].
    AskMode,
}

/// What to do about one rule in force on this machine.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AdoptionStep {
    /// Install it now.
    Install,
    /// Put it in the inbox and install only if the owner confirms.
    AskOwner(AskReason),
    /// Leave it out: the owner opted out of this rule.
    OptedOut,
    /// It cannot be installed. No confirmation changes this.
    Refuse(RefuseReason),
}

impl AdoptionStep {
    /// A stable machine-readable code.
    pub const fn code(self) -> &'static str {
        match self {
            AdoptionStep::Install => "install",
            AdoptionStep::AskOwner(AskReason::HighRisk) => "ask_high_risk",
            AdoptionStep::AskOwner(AskReason::LocalPolicy) => "ask_local_policy",
            AdoptionStep::AskOwner(AskReason::AskMode) => "ask_mode",
            AdoptionStep::OptedOut => "opted_out",
            AdoptionStep::Refuse(RefuseReason::BundleDigestUnverified) => {
                "refuse_bundle_digest_unverified"
            }
            AdoptionStep::Refuse(RefuseReason::SkillInvalid) => "refuse_skill_invalid",
        }
    }
}

/// The owner's choices about one rule.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct OwnerChoice {
    /// The owner opted out of this rule (`rule opt-out`).
    pub opted_out: bool,
    /// The owner explicitly confirmed installing this exact rule, after seeing the diff
    /// and any warnings. Never derived from an agent's or a peer's output.
    pub confirmed: bool,
}

/// Decides what to do about `rule` on this machine.
///
/// `_rule` is required as evidence that the rule is in force: a [`Rule`] can only come
/// out of [`crate::rules_in_force`]. `local_policy_met` is the result of
/// [`local_policy_met`] for this rule.
///
/// The order of the checks is the order of the rights in architecture section 10.10:
/// integrity first, then the owner's refusal, then the owner's explicit consent, then
/// the conditions under which consent must be asked for.
pub fn adoption_step(
    _rule: &Rule,
    mode: AdoptionMode,
    checks: BundleChecks,
    choice: OwnerChoice,
    local_policy_met: bool,
) -> AdoptionStep {
    if !checks.digest_verified {
        return AdoptionStep::Refuse(RefuseReason::BundleDigestUnverified);
    }
    if !checks.skill_valid {
        return AdoptionStep::Refuse(RefuseReason::SkillInvalid);
    }
    if choice.opted_out {
        return AdoptionStep::OptedOut;
    }
    if choice.confirmed {
        return AdoptionStep::Install;
    }
    if checks.high_risk {
        return AdoptionStep::AskOwner(AskReason::HighRisk);
    }
    if !local_policy_met {
        return AdoptionStep::AskOwner(AskReason::LocalPolicy);
    }
    match mode {
        AdoptionMode::Follow => AdoptionStep::Install,
        AdoptionMode::Ask => AdoptionStep::AskOwner(AskReason::AskMode),
    }
}

/// Whether the node's own policy is satisfied for a rule.
///
/// `tally` is the count that passed the rule under the current charter, or `None` for a
/// rule that was carried into the current charter (its ballots are not re-counted). An
/// empty policy is always met. A non-empty policy is not met by a carried rule, so the
/// owner is asked.
pub fn local_policy_met(policy: &LocalPolicy, tally: Option<&Tally>) -> bool {
    if policy.is_empty() {
        return true;
    }
    let Some(tally) = tally else {
        return false;
    };
    let approved = |member: &String| tally.approvals().iter().any(|a| &a.member == member);
    let enough = policy
        .min_approvals
        .is_none_or(|n| tally.approvals().len() >= n as usize);
    enough && policy.required_members.iter().all(approved)
}
