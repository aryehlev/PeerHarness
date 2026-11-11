//! The rules in force: a pure function of the current charter and what passed under it
//! (architecture section 10.7).

mod common;

use common::*;
use ph_governance::{
    carried_diff, rules_in_force, tally, Basis, NotPassed, Passed, ProposalView, RuleSet,
};
use ph_protocol::{Charter, ProposalAction, ProposalBody};

/// Passes `p` under `c` with approvals from the given device seeds.
fn pass(p: &ProposalView, c: &Charter, seeds: &[u8]) -> Passed {
    let votes: Vec<_> = seeds.iter().map(|s| approve(*s, p)).collect();
    let t = tally(p, c, &votes, &nobody_revoked).unwrap();
    Passed::by_vote(p, &t, c).unwrap()
}

fn names(rs: &RuleSet) -> Vec<&str> {
    rs.rules().map(|r| r.skill_name()).collect()
}

#[test]
fn a_passed_rule_is_in_force_and_an_open_one_is_not() {
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    assert!(rules_in_force(&c, &[]).is_empty());

    // One approval of three: not passed, so there is nothing to hand to the rule set.
    let t = tally(&p, &c, &[approve(1, &p)], &nobody_revoked).unwrap();
    assert_eq!(Passed::by_vote(&p, &t, &c), Err(NotPassed::BelowThreshold));

    let rs = rules_in_force(&c, &[pass(&p, &c, &[1, 2])]);
    assert_eq!(names(&rs), [SKILL]);
    let rule = rs.get(SKILL).unwrap();
    assert_eq!(rule.proposal_id(), p.event_id());
    assert_eq!(rule.bundle_digest(), digest(b"b"));
    assert_eq!(rule.basis(), Basis::Vote);
    assert_eq!(rs.by_proposal(&p.event_id()).unwrap().skill_name(), SKILL);
    assert_eq!(rs.carried_ids(), [p.event_id()]);
}

#[test]
fn a_newer_rule_of_the_same_name_replaces_the_older_one() {
    let c = abc();
    let old = adopt_named(1, &c, "*", SKILL, digest(b"v1"), now().minus_secs(7000));
    let new = adopt_named(2, &c, "*", SKILL, digest(b"v2"), now().minus_secs(100));
    let other = adopt_named(
        3,
        &c,
        "*",
        "vitest-convention",
        digest(b"x"),
        now().minus_secs(50),
    );
    let passed = [
        pass(&old, &c, &[1, 2]),
        pass(&new, &c, &[2, 3]),
        pass(&other, &c, &[1, 3]),
    ];
    let rs = rules_in_force(&c, &passed);
    assert_eq!(names(&rs), [SKILL, "vitest-convention"]);
    assert_eq!(rs.get(SKILL).unwrap().bundle_digest(), digest(b"v2"));
    assert_eq!(rs.len(), 2);

    // The same answer in every order of arrival.
    let reference = rs;
    let mut order = passed.to_vec();
    for _ in 0..order.len() {
        order.rotate_left(1);
        assert_eq!(rules_in_force(&c, &order), reference);
        let reversed: Vec<Passed> = order.iter().rev().cloned().collect();
        assert_eq!(rules_in_force(&c, &reversed), reference);
    }
}

/// A repeal counts only against a rule of its own scope, so that the electorate that
/// adopted a rule is the one that repeals it. The check is part of the rule set and
/// not of what a node stores (ADR-051): a repeal from another scope is a record like
/// any other, in whatever order it arrived, and it takes nothing out of force.
#[test]
fn a_repeal_from_another_scope_takes_nothing_out_of_force() {
    let c = founding(vec![
        entry("alice", &[1], &["*"]),
        entry("bob", &[2], &["team/backend"]),
        entry("carol", &[3], &["team/backend"]),
        entry("dave", &[4], &["team/backend"]),
        entry("erin", &[5], &["team/frontend"]),
    ]);
    let rule = adopt(2, &c, "team/backend", digest(b"b"));
    // Another scope has another electorate: here alice and erin, and none of the three
    // who adopted the rule with alice.
    let from_elsewhere = proposal_from(
        1,
        "team/frontend",
        ProposalBody {
            charter: c.digest().unwrap(),
            title: "Drop the rule".into(),
            summary: String::new(),
            action: ProposalAction::Repeal {
                target: rule.event_id(),
            },
        },
        now().minus_secs(1800),
    );
    let adopted = || pass(&rule, &c, &[2, 3, 4]);
    let elsewhere = || pass(&from_elsewhere, &c, &[1, 5]);
    for passed in [[adopted(), elsewhere()], [elsewhere(), adopted()]] {
        let rs = rules_in_force(&c, &passed);
        assert_eq!(names(&rs), [SKILL], "another scope repealed the rule");
    }

    // The repeal in the rule's own scope, passed by that scope's electorate, does.
    let own = repeal(2, &c, &rule);
    let rs = rules_in_force(&c, &[adopted(), pass(&own, &c, &[2, 3, 4])]);
    assert!(rs.is_empty());
}

#[test]
fn repeal_removes_the_rule_and_an_older_one_does_not_return() {
    let c = abc();
    let old = adopt_named(1, &c, "*", SKILL, digest(b"v1"), now().minus_secs(7000));
    let new = adopt_named(2, &c, "*", SKILL, digest(b"v2"), now().minus_secs(100));
    let drop_new = repeal(3, &c, &new);
    let passed = [
        pass(&old, &c, &[1, 2]),
        pass(&new, &c, &[1, 2]),
        pass(&drop_new, &c, &[2, 3]),
    ];
    let rs = rules_in_force(&c, &passed);
    assert!(
        rs.is_empty(),
        "repealing the winner leaves the name with no rule"
    );

    // Repealing a rule that already lost to a newer one changes nothing.
    let drop_old = repeal(3, &c, &old);
    let passed = [
        pass(&old, &c, &[1, 2]),
        pass(&new, &c, &[1, 2]),
        pass(&drop_old, &c, &[2, 3]),
    ];
    let rs = rules_in_force(&c, &passed);
    assert_eq!(rs.get(SKILL).unwrap().bundle_digest(), digest(b"v2"));

    // A repeal that has not passed has no effect either.
    let t = tally(&drop_new, &c, &[approve(3, &drop_new)], &nobody_revoked).unwrap();
    assert_eq!(
        Passed::by_vote(&drop_new, &t, &c),
        Err(NotPassed::BelowThreshold)
    );
}

#[test]
fn a_proposal_can_pass_only_under_the_current_charter() {
    let c1 = abc();
    let p = adopt(1, &c1, "*", digest(b"b"));
    let votes = [approve(1, &p), approve(2, &p)];
    let t = tally(&p, &c1, &votes, &nobody_revoked).unwrap();
    assert!(t.passed());

    // The charter changes (dave is admitted). The old proposal is dead: it names
    // charter 1, and must be proposed again under charter 2.
    let mut next = c1.content.clone();
    next.roll.push(entry("dave", &[4], &["*"]));
    next.normalize();
    let c2 = successor(&c1, next, p.event_id());
    assert_eq!(Passed::by_vote(&p, &t, &c2), Err(NotPassed::StaleCharter));
    assert!(rules_in_force(&c2, &[]).is_empty());

    // A `Passed` made under charter 1 is ignored when computing charter 2's rules.
    let under_c1 = Passed::by_vote(&p, &t, &c1).unwrap();
    assert!(rules_in_force(&c2, &[under_c1]).is_empty());

    // A tally of another proposal cannot vouch for this one.
    let q = adopt(1, &c1, "*", digest(b"q"));
    assert_eq!(Passed::by_vote(&q, &t, &c1), Err(NotPassed::WrongTally));
}

#[test]
fn carried_rules_stay_in_force_without_recounting() {
    let c1 = abc();
    let p = adopt(1, &c1, "*", digest(b"b"));
    let q = adopt_named(
        2,
        &c1,
        "*",
        "vitest-convention",
        digest(b"q"),
        now().minus_secs(900),
    );
    let in_force = rules_in_force(&c1, &[pass(&p, &c1, &[1, 2]), pass(&q, &c1, &[2, 3])]);

    // Charter 2 admits dave and carries both rules.
    let mut next = c1.content.clone();
    next.roll.push(entry("dave", &[4], &["*"]));
    next.carried = in_force.carried_ids();
    next.normalize();
    let c2 = successor(&c1, next, p.event_id());

    // A node that joins at charter 2 holds no ballots from charter 1. It needs only the
    // carried proposals themselves.
    let carried = [
        Passed::carried(&p, &c2).unwrap(),
        Passed::carried(&q, &c2).unwrap(),
    ];
    let rs = rules_in_force(&c2, &carried);
    assert_eq!(names(&rs), [SKILL, "vitest-convention"]);
    assert_eq!(rs.get(SKILL).unwrap().basis(), Basis::Carried);
    assert!(rs.missing_carried().is_empty());

    // Until it has fetched one of them, the set is reported as incomplete.
    let rs = rules_in_force(&c2, &carried[..1]);
    assert_eq!(names(&rs), [SKILL]);
    assert_eq!(rs.missing_carried(), [q.event_id()]);

    // A proposal the charter does not list cannot be smuggled in as carried.
    let stranger = adopt(3, &c1, "*", digest(b"stranger"));
    assert_eq!(Passed::carried(&stranger, &c2), Err(NotPassed::NotCarried));
    // Nor can a repeal or an amendment be carried.
    let r = repeal(1, &c1, &p);
    assert_eq!(Passed::carried(&r, &c2), Err(NotPassed::NotAnAdoption));

    // A carried rule can be replaced and repealed under the new charter like any other.
    let newer = adopt_named(4, &c2, "*", SKILL, digest(b"v2"), now());
    let votes = [approve(1, &newer), approve(2, &newer), approve(4, &newer)];
    let t = tally(&newer, &c2, &votes, &nobody_revoked).unwrap();
    assert_eq!(t.need(), 3, "four members now");
    let mut all = carried.to_vec();
    all.push(Passed::by_vote(&newer, &t, &c2).unwrap());
    let rs = rules_in_force(&c2, &all);
    assert_eq!(rs.get(SKILL).unwrap().bundle_digest(), digest(b"v2"));
    assert_eq!(rs.get(SKILL).unwrap().basis(), Basis::Vote);
}

#[test]
fn an_amendment_that_changes_the_carried_rules_is_visible_to_voters() {
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    let q = adopt_named(
        2,
        &c,
        "*",
        "vitest-convention",
        digest(b"q"),
        now().minus_secs(900),
    );
    let in_force = rules_in_force(&c, &[pass(&p, &c, &[1, 2]), pass(&q, &c, &[2, 3])]);

    // An honest amendment carries exactly what is in force.
    assert!(carried_diff(&in_force.carried_ids(), &in_force).is_exact());

    // One that silently drops a rule and slips in an unvoted one is shown as such.
    let unvoted = adopt(3, &c, "*", digest(b"never-passed"));
    let d = carried_diff(&[p.event_id(), unvoted.event_id()], &in_force);
    assert!(!d.is_exact());
    assert_eq!(d.dropped, [q.event_id()]);
    assert_eq!(d.added, [unvoted.event_id()]);
}

#[test]
fn amendments_do_not_enter_the_rule_set() {
    let c = founding(vec![entry("alice", &[1], &["*"])]);
    let mut next = c.content.clone();
    next.roll.push(entry("bob", &[2], &["*"]));
    next.normalize();
    let a = amend(1, &c, next);
    let rs = rules_in_force(&c, &[pass(&a, &c, &[1])]);
    assert!(rs.is_empty());
}
