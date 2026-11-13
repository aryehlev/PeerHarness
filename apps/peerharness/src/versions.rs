//! The versions of a rule (ADR-053).
//!
//! A rule is identified by the `adopt` proposal that put it in force, and that proposal
//! signs the digest of the rule's text. So a rule in force never changes in place: a
//! changed text is another proposal with another digest, and it needs its own vote.
//! This module says, for one such proposal, which earlier version it stands against
//! and how the two texts differ, so that whoever proposes, votes or installs reads the
//! change and not only the result.
//!
//! The earlier version is found on the records this node holds, never taken on the
//! proposer's word. While a rule of the proposal's name is in force, that rule is the
//! version a vote would replace, whatever the proposal's `supersedes` says: a proposer
//! who named another, closer text there would otherwise choose how small the change
//! looks. Only where no other rule of the name is in force (the proposal is itself the
//! rule in force, or the name has none) is `supersedes` read, as the lineage it is.
//!
//! Everything here is shown, and nothing is decided: a ballot signs the proposal's id,
//! and with it the whole text, which every preview shows in full beside the changes.

use anyhow::Result;
use ph_core::{CircleId, Digest, EventId, Scope, Timestamp};
use ph_governance::ProposalView;
use ph_skills::{Bundle, BundleStore};
use ph_store::Store;
use serde_json::{json, Value};

use crate::governance;
use crate::output::{quoted, short_id};

/// The mark in front of every line of a comparison in a preview. The lines between the
/// marks are text members wrote (an earlier rule's and the proposed one's).
pub const CHANGE_MARK: &str = "  | ";

/// How an earlier version relates to the proposal it is compared with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Basis {
    /// It is the rule of that name in force on this node now.
    InForce,
    /// The proposal names it in `supersedes`, and no other rule of the name is in force.
    Named,
}

impl Basis {
    const fn code(self) -> &'static str {
        match self {
            Basis::InForce => "in_force",
            Basis::Named => "named",
        }
    }
}

/// The version of a rule that a proposal is compared with.
pub struct Earlier {
    /// The `adopt` proposal of the earlier version.
    pub proposal_id: EventId,
    /// The digest of its text: what that proposal's voters approved.
    pub bundle_digest: Digest,
    /// The scope it was proposed for.
    pub scope: Scope,
    /// When it was proposed, by its proposer's clock. Rules of one name are ordered by
    /// this.
    pub proposed_at: Timestamp,
    /// Why it is the one compared with.
    pub basis: Basis,
    /// Its text, when this node has it.
    pub bundle: Option<Bundle>,
}

/// The rule named `name` in force in `circle` now, as the version a new proposal of
/// that name would replace.
pub fn in_force(
    store: &Store,
    bundles: &BundleStore,
    circle: &CircleId,
    name: &str,
) -> Result<Option<Earlier>> {
    let (_, rules, _) = governance::rule_set(store, circle)?;
    Ok(rules.get(name).map(|rule| Earlier {
        proposal_id: rule.proposal_id(),
        bundle_digest: rule.bundle_digest(),
        scope: rule.scope().clone(),
        proposed_at: rule.proposed_at(),
        basis: Basis::InForce,
        bundle: bundles.get(&rule.bundle_digest()).ok(),
    }))
}

/// The version the rule proposal `p` is compared with, if there is one: the rule of
/// its name in force now when that is another proposal, and otherwise the proposal it
/// names in `supersedes`, when that is an `adopt` proposal of the same circle and name
/// on this node. `None` for a proposal that is not about a rule's text.
pub fn earlier(store: &Store, bundles: &BundleStore, p: &ProposalView) -> Result<Option<Earlier>> {
    let Some(name) = p.skill_name() else {
        return Ok(None);
    };
    if let Some(found) = in_force(store, bundles, &p.circle_id(), name)? {
        if found.proposal_id != p.event_id() {
            return Ok(Some(found));
        }
    }
    let Some(named) = p.supersedes() else {
        return Ok(None);
    };
    let Ok(old) = governance::proposal_view(store, &named) else {
        return Ok(None);
    };
    if old.circle_id() != p.circle_id() || old.skill_name() != Some(name) {
        return Ok(None); // not lineage (`ph_governance::supersede_links`)
    }
    let Some(digest) = old.bundle_digest() else {
        return Ok(None);
    };
    Ok(Some(Earlier {
        proposal_id: old.event_id(),
        bundle_digest: digest,
        scope: old.scope().clone(),
        proposed_at: old.created_at(),
        basis: Basis::Named,
        bundle: bundles.get(&digest).ok(),
    }))
}

/// How far ahead of this machine's clock the rule in force may be dated for a proposal
/// to be signed that replaces it, in seconds. Well inside the skew every node allows.
const MAX_AHEAD_SECS: i64 = 60;

/// The refusal of a proposal that could not take the place of the rule it is shown
/// against. Names nothing a member wrote.
const DATED_AHEAD: &str =
    "the rule of that name in force is dated later than this machine's clock says it is      now. Of two rules of one name the later-dated one is in force, so a proposal signed      now would not take its place if it passed. Check this machine's clock, or try again      later. Nothing was proposed and nothing was signed.";

/// The time to sign a proposal with that replaces `replaces` (the rule of its name in
/// force, if there is one), given this machine's clock `now`.
///
/// Of two passed rules of one name, the one with the later `created_at` is in force
/// (`ph_governance::rules_in_force`), and a timestamp counts seconds. A proposal signed
/// in the second the rule in force was signed in, or on a clock a little behind its
/// proposer's, would pass and change nothing, after a preview that said it takes that
/// rule's place. So it is dated one second after that rule where the clock is not
/// already past it, and refused where that would be more than a minute ahead.
pub fn signing_time(now: Timestamp, replaces: Option<&Earlier>) -> Result<Timestamp> {
    let Some(old) = replaces else {
        return Ok(now);
    };
    let ahead = old.proposed_at.secs_since(now);
    if ahead < 0 {
        Ok(now)
    } else if ahead <= MAX_AHEAD_SECS {
        Ok(old.proposed_at.plus_secs(1))
    } else {
        Err(crate::error::refused(DATED_AHEAD))
    }
}

impl Earlier {
    /// What a reader is told about this version and the text `new`: which version it
    /// is, in PeerHarness's own words, and then the differences, every line of them
    /// behind `mark`. `name` is the rule's name.
    ///
    /// The comparison holds lines of two texts that members wrote. It goes where the
    /// rule's text goes and nowhere else: never into a coding agent's session
    /// ([`Earlier::describe_without_texts`]).
    pub fn describe(&self, name: &str, new: &Bundle, mark: &str) -> String {
        let head = self.head(name);
        if self.bundle_digest == new.digest() {
            return format!("{head} This text is the same, word for word.");
        }
        let Some(old) = &self.bundle else {
            return format!("{head} Its text is not on this node, so the changes cannot be shown.");
        };
        let diff = ph_skills::unified_diff(
            old.skill_md(),
            new.skill_md(),
            &format!(
                "{} (proposal {})",
                self.label(),
                short_id(&self.proposal_id)
            ),
            "this proposal",
        );
        format!(
            "{head} What this text changes from it (- taken out, + added):\n{}",
            quoted(&diff, mark)
        )
    }

    /// [`Earlier::describe`] without a line of either text: which version it is, and
    /// that the changes are for the person to read.
    pub fn describe_without_texts(&self, name: &str) -> String {
        format!(
            "{} The changes are not shown inside a coding agent's session.",
            self.head(name)
        )
    }

    fn label(&self) -> &'static str {
        match self.basis {
            Basis::InForce => "in force",
            Basis::Named => "replaced",
        }
    }

    fn head(&self, name: &str) -> String {
        let version = format!(
            "proposal {}, scope {}, text {}",
            short_id(&self.proposal_id),
            self.scope,
            short_id(&self.bundle_digest)
        );
        match self.basis {
            Basis::InForce => format!("A rule named {name} is in force here ({version})."),
            Basis::Named => {
                format!("It names an earlier version of {name} as the one it replaces ({version}).")
            }
        }
    }

    /// For a JSON report. No text of a rule.
    pub fn json(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "bundle_digest": self.bundle_digest,
            "scope": self.scope,
            "basis": self.basis.code(),
            "text_on_this_node": self.bundle.is_some(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(statement: &str) -> Bundle {
        let md = ph_skills::render_skill_md("build-rule", statement, statement, None).unwrap();
        ph_skills::build_bundle(&md, Some("build-rule")).unwrap()
    }

    fn version(basis: Basis, bundle: Option<Bundle>, digest: Digest) -> Earlier {
        Earlier {
            proposal_id: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                .parse()
                .unwrap(),
            bundle_digest: digest,
            scope: Scope::all(),
            proposed_at: Timestamp::from_unix_seconds(1_800_000_000).unwrap(),
            basis,
            bundle,
        }
    }

    #[test]
    fn the_changes_are_marked_line_by_line() {
        let old = bundle("Run the tests.");
        let new = bundle("Run the tests.\nAn approval cannot be withdrawn.");
        let said = version(Basis::InForce, Some(old.clone()), old.digest()).describe(
            "build-rule",
            &new,
            CHANGE_MARK,
        );
        let mut lines = said.lines();
        let head = lines.next().unwrap();
        assert!(head.starts_with("A rule named build-rule is in force here (proposal sha256:"));
        assert!(head.ends_with("(- taken out, + added):"));
        // Every further line is behind the mark: a line of a rule's text cannot pass
        // for one of PeerHarness's own.
        let rest: Vec<&str> = lines.collect();
        assert!(rest.iter().all(|l| l.starts_with(CHANGE_MARK)), "{said}");
        assert!(rest.contains(&"  | +An approval cannot be withdrawn."));
        assert!(rest
            .iter()
            .any(|l| l.starts_with("  | --- in force (proposal ")));
    }

    #[test]
    fn a_replacement_is_dated_after_the_rule_it_replaces() {
        let old = bundle("Run the tests.");
        let v = version(Basis::InForce, Some(old.clone()), old.digest());
        let at = v.proposed_at;
        // No rule to replace, or a clock that is past it: the clock.
        assert_eq!(signing_time(at, None).unwrap(), at);
        assert_eq!(
            signing_time(at.plus_secs(5), Some(&v)).unwrap(),
            at.plus_secs(5)
        );
        // The same second, or a clock a little behind: one second after the rule.
        assert_eq!(signing_time(at, Some(&v)).unwrap(), at.plus_secs(1));
        assert_eq!(
            signing_time(at.minus_secs(60), Some(&v)).unwrap(),
            at.plus_secs(1)
        );
        // Further behind than that: refused, and nothing is signed.
        let e = signing_time(at.minus_secs(61), Some(&v)).unwrap_err();
        assert!(e.to_string().contains("Nothing was proposed"));
    }

    #[test]
    fn the_same_text_and_a_missing_text_are_said() {
        let old = bundle("Run the tests.");
        let same = version(Basis::InForce, Some(old.clone()), old.digest());
        assert!(same
            .describe("build-rule", &old, CHANGE_MARK)
            .ends_with("This text is the same, word for word."));
        let new = bundle("Run the linter.");
        let missing = version(Basis::Named, None, old.digest());
        let said = missing.describe("build-rule", &new, CHANGE_MARK);
        assert!(said.starts_with("It names an earlier version of build-rule"));
        assert!(said.ends_with("so the changes cannot be shown."));
        // Inside a session: which version, and no line of either text.
        let quiet = version(Basis::InForce, Some(old), new.digest()).describe_without_texts("x");
        assert!(!quiet.contains("Run the"));
        assert_eq!(quiet.lines().count(), 1);
    }
}
