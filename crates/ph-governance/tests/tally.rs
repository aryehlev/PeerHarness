//! Counting a vote: one member one vote, a majority of the whole electorate, no veto,
//! approvals that only accumulate, and no clock (architecture section 10).

mod common;

use common::*;
use ph_core::DeviceKey;
use ph_governance::{tally, threshold_for, IgnoreReason, Tally, TallyError, VoteView};
use ph_protocol::{Charter, CharterRules, Threshold, VoteDecision::*};

fn count(p: &ph_governance::ProposalView, c: &Charter, votes: &[VoteView]) -> Tally {
    tally(p, c, votes, &nobody_revoked).unwrap()
}

fn approvers(t: &Tally) -> Vec<&str> {
    t.approvals().iter().map(|a| a.member.as_str()).collect()
}

#[test]
fn two_of_three_pass_and_one_is_not_enough() {
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));

    let t = count(&p, &c, &[]);
    assert_eq!(t.electorate(), ["alice", "bob", "carol"]);
    assert_eq!((t.need(), t.missing()), (2, 2));
    assert!(!t.passed());
    assert_eq!(t.silent(), ["alice", "bob", "carol"]);
    assert_eq!(t.certificate(), None);

    let a = approve(1, &p);
    let t = count(&p, &c, std::slice::from_ref(&a));
    assert!(!t.passed(), "the proposer alone is not a majority of three");
    assert_eq!(t.missing(), 1);

    let b = approve(2, &p);
    let t = count(&p, &c, &[a.clone(), b.clone()]);
    assert!(t.passed());
    assert_eq!(approvers(&t), ["alice", "bob"]);
    assert_eq!(t.silent(), ["carol"]);
    assert_eq!(t.summary(), "passed: 2 of 3 approved (2 needed)");
    let mut expected = vec![a.event_id(), b.event_id()];
    expected.sort_by_key(|id| id.to_string());
    assert_eq!(t.certificate(), Some(expected));
}

#[test]
fn nobody_holds_a_veto() {
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    // Carol rejects and Bob asks for a revision before anyone approves.
    let votes = [
        vote(3, &p, Reject),
        vote(2, &p, Revise),
        approve(1, &p),
        // Bob is persuaded and approves with a later ballot.
        vote_at(2, &p, Approve, now()),
    ];
    let t = count(&p, &c, &votes);
    assert!(t.passed(), "one dissent cannot block a majority");
    assert_eq!(approvers(&t), ["alice", "bob"]);
    // Carol's dissent is on the record, with her rationale length but not its text.
    assert_eq!(t.dissent().len(), 1);
    let d = &t.dissent()[0];
    assert_eq!((d.member.as_str(), d.decision), ("carol", Reject));
    assert_eq!(d.rationale_chars, "looks right".len());
    assert_eq!(
        t.summary(),
        "passed: 2 of 3 approved (2 needed), 1 dissenting"
    );
    // Bob's earlier `revise` is superseded by his approval.
    assert_eq!(
        t.ignore_reason(&votes[1].event_id()),
        Some(IgnoreReason::Redundant)
    );

    // Even two members dissenting only matters because they did not approve.
    let t = count(
        &p,
        &c,
        &[approve(1, &p), vote(2, &p, Reject), vote(3, &p, Revise)],
    );
    assert!(!t.passed());
    assert_eq!(t.dissent().len(), 2);
    assert_eq!(t.missing(), 1);
}

#[test]
fn one_person_one_vote_however_many_devices() {
    // Alice has three devices; bob and carol one each.
    let c = founding(vec![
        entry("alice", &[1, 11, 21], &["*"]),
        entry("bob", &[2], &["*"]),
        entry("carol", &[3], &["*"]),
    ]);
    let p = adopt(1, &c, "*", digest(b"b"));
    let votes = [approve(1, &p), approve(11, &p), approve(21, &p)];
    let t = count(&p, &c, &votes);
    assert_eq!(
        approvers(&t),
        ["alice"],
        "three devices are still one member"
    );
    assert!(!t.passed());
    assert_eq!(
        t.electorate().len(),
        3,
        "devices do not enlarge the electorate"
    );
    // Exactly one of her ballots evidences the approval; the others are redundant.
    let redundant = t
        .ignored()
        .iter()
        .filter(|(_, r)| *r == IgnoreReason::Redundant)
        .count();
    assert_eq!(redundant, 2);
    // Which one is chosen does not depend on the order they are supplied in.
    let chosen = t.approvals()[0].vote_id;
    let reversed: Vec<VoteView> = votes.iter().rev().cloned().collect();
    assert_eq!(count(&p, &c, &reversed).approvals()[0].vote_id, chosen);
}

#[test]
fn approvals_only_accumulate() {
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    let a = approve(1, &p);
    let b = approve(2, &p);
    // Bob later signs a reject. It does not undo his approval.
    let b_regret = vote_at(2, &p, Reject, now());
    let t = count(&p, &c, &[a.clone(), b.clone(), b_regret.clone()]);
    assert!(t.passed(), "passed never turns back into not passed");
    assert_eq!(approvers(&t), ["alice", "bob"]);
    assert!(t.dissent().is_empty());
    assert_eq!(
        t.ignore_reason(&b_regret.event_id()),
        Some(IgnoreReason::Redundant)
    );
    // Adding ballots never removes an approval: every superset of a passing set passes.
    let extra = [vote(3, &p, Reject), vote_at(1, &p, Revise, now())];
    let mut all = vec![a, b, b_regret];
    for e in extra {
        all.push(e);
        assert!(count(&p, &c, &all).passed());
    }
}

#[test]
fn the_outcome_does_not_depend_on_arrival_order() {
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    let votes = vec![
        vote(3, &p, Reject),
        approve(1, &p),
        vote(2, &p, Revise),
        vote_at(2, &p, Approve, now()),
        vote_at(3, &p, Revise, now()),
        vote(42, &p, Approve), // not on the roll
    ];
    let reference = count(&p, &c, &votes);
    // Every rotation and the reverse of the input give the same approvals and dissent.
    let mut order = votes.clone();
    for _ in 0..votes.len() {
        order.rotate_left(1);
        for candidate in [order.clone(), order.iter().rev().cloned().collect()] {
            let t = count(&p, &c, &candidate);
            assert_eq!(t.approvals(), reference.approvals());
            assert_eq!(t.dissent(), reference.dissent());
            assert_eq!(t.passed(), reference.passed());
            assert_eq!(t.certificate(), reference.certificate());
        }
    }
    assert!(reference.passed());
    // Carol's recorded dissent is her latest ballot.
    assert_eq!(reference.dissent()[0].decision, Revise);
}

#[test]
fn the_outcome_does_not_depend_on_a_clock() {
    let c = abc();
    // A proposal and ballots stamped ten years apart count exactly the same: nothing in
    // the tally reads the time, and decision events never expire.
    let old = now().minus_secs(10 * 365 * 86_400);
    let p = adopt_named(1, &c, "*", SKILL, digest(b"b"), old);
    let votes = [vote_at(1, &p, Approve, old), vote_at(2, &p, Approve, now())];
    let t = count(&p, &c, &votes);
    assert!(t.passed());
    assert_eq!(approvers(&t), ["alice", "bob"]);
}

#[test]
fn silence_counts_as_not_approving() {
    // Five members: three approvals are needed whether or not the others ever vote.
    let c = founding(
        (1..=5u8)
            .map(|i| entry(&format!("m{i}"), &[i], &["*"]))
            .collect(),
    );
    let p = adopt(1, &c, "*", digest(b"b"));
    let t = count(&p, &c, &[approve(1, &p), approve(2, &p)]);
    assert_eq!((t.need(), t.passed()), (3, false));
    assert_eq!(t.silent(), ["m3", "m4", "m5"]);
    let t = count(&p, &c, &[approve(1, &p), approve(2, &p), approve(3, &p)]);
    assert!(t.passed());
}

#[test]
fn founder_alone_and_a_circle_of_two() {
    let solo = founding(vec![entry("alice", &[1], &["*"])]);
    let p = adopt(1, &solo, "*", digest(b"b"));
    assert!(!count(&p, &solo, &[]).passed());
    assert!(count(&p, &solo, &[approve(1, &p)]).passed());

    // With two members a majority means both.
    let two = founding(vec![
        entry("alice", &[1], &["*"]),
        entry("bob", &[2], &["*"]),
    ]);
    let p = adopt(1, &two, "*", digest(b"b"));
    let t = count(&p, &two, &[approve(1, &p)]);
    assert_eq!((t.need(), t.passed()), (2, false));
    assert!(count(&p, &two, &[approve(1, &p), approve(2, &p)]).passed());
}

#[test]
fn the_electorate_follows_the_scope() {
    let c = founding(vec![
        entry("alice", &[1], &["*"]),
        entry("bob", &[2], &["team/backend"]),
        entry("carol", &[3], &["team/frontend"]),
        entry("dave", &[4], &["team/backend", "docs"]),
    ]);
    // A backend rule: alice (wildcard), bob and dave vote. Carol does not.
    let p = adopt(2, &c, "team/backend", digest(b"b"));
    let carol_ballot = approve(3, &p);
    let t = count(
        &p,
        &c,
        &[approve(2, &p), approve(4, &p), carol_ballot.clone()],
    );
    assert_eq!(t.electorate(), ["alice", "bob", "dave"]);
    assert_eq!(t.need(), 2);
    assert!(t.passed());
    assert_eq!(approvers(&t), ["bob", "dave"]);
    assert_eq!(
        t.ignored(),
        [(carol_ballot.event_id(), IgnoreReason::NotInElectorate)],
        "a frontend member cannot vote on a backend rule"
    );

    // A narrower scope is covered by the broader grant.
    let p = adopt(2, &c, "team/backend/db", digest(b"b"));
    assert_eq!(count(&p, &c, &[]).electorate(), ["alice", "bob", "dave"]);

    // A circle-wide (`*`) rule concerns everyone, whatever their own scopes.
    let p = adopt(2, &c, "*", digest(b"b"));
    let t = count(&p, &c, &[approve(2, &p), approve(3, &p), approve(4, &p)]);
    assert_eq!(t.electorate().len(), 4);
    assert_eq!(t.need(), 3);
    assert!(t.passed());

    // A scope nobody but the wildcard member covers: she decides alone.
    let p = adopt(1, &c, "finance", digest(b"b"));
    let t = count(&p, &c, &[approve(1, &p)]);
    assert_eq!(t.electorate(), ["alice"]);
    assert!(t.passed());
}

#[test]
fn an_empty_electorate_passes_nothing() {
    let c = founding(vec![entry("bob", &[2], &["team/backend"])]);
    let p = adopt(2, &c, "team/frontend", digest(b"b"));
    let t = count(&p, &c, &[approve(2, &p)]);
    assert!(t.electorate().is_empty());
    assert_eq!(t.need(), 1);
    assert!(!t.passed());
}

#[test]
fn amendments_are_decided_by_the_whole_roll() {
    let c = founding(vec![
        entry("alice", &[1], &["*"]),
        entry("bob", &[2], &["team/backend"]),
        entry("carol", &[3], &["team/frontend"]),
    ]);
    // Admitting dave changes only the roll: simple majority of all three members.
    let mut next = c.content.clone();
    next.roll.push(entry("dave", &[4], &["*"]));
    next.normalize();
    let p = amend(2, &c, next);
    assert_eq!(threshold_for(&p, &c.content), Threshold::MAJORITY);
    let t = count(&p, &c, &[approve(2, &p), approve(3, &p)]);
    assert_eq!(t.electorate(), ["alice", "bob", "carol"]);
    assert!(t.passed(), "narrow-scope members vote on the charter too");

    // Changing the rules needs the amend threshold: more than two thirds of three is
    // all three.
    let mut next = c.content.clone();
    next.rules = CharterRules {
        binding: false,
        ..next.rules
    };
    let p = amend(1, &c, next);
    assert_eq!(threshold_for(&p, &c.content), Threshold::TWO_THIRDS);
    let two = [approve(1, &p), approve(2, &p)];
    let t = count(&p, &c, &two);
    assert_eq!((t.need(), t.passed()), (3, false));
    let t = count(&p, &c, &[two[0].clone(), two[1].clone(), approve(3, &p)]);
    assert!(t.passed());
}

#[test]
fn keys_cannot_be_invented_to_reach_a_majority() {
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    // Fifty fresh keys approve. None is on the roll.
    let mut votes: Vec<VoteView> = (100..150u8).map(|s| approve(s, &p)).collect();
    votes.push(approve(1, &p));
    let t = count(&p, &c, &votes);
    assert_eq!(approvers(&t), ["alice"]);
    assert!(!t.passed());
    assert_eq!(
        t.ignored()
            .iter()
            .filter(|(_, r)| *r == IgnoreReason::NotOnRoll)
            .count(),
        50
    );
    // The circle root key is not a member either.
    let t = count(&p, &c, &[approve(ROOT, &p)]);
    assert_eq!(t.ignored()[0].1, IgnoreReason::NotOnRoll);
}

#[test]
fn a_ballot_counts_only_for_the_proposal_it_signs() {
    let c = abc();
    let a = adopt(1, &c, "*", digest(b"bundle-a"));
    // The same rule with one byte of the bundle changed is a different proposal.
    let b = adopt(1, &c, "*", digest(b"bundle-b"));
    assert_ne!(a.event_id(), b.event_id());
    let votes_for_a = [approve(1, &a), approve(2, &a)];
    assert!(count(&a, &c, &votes_for_a).passed());
    let t = count(&b, &c, &votes_for_a);
    assert!(!t.passed(), "approvals of A are not approvals of B");
    assert!(t.approvals().is_empty());
    assert!(t
        .ignored()
        .iter()
        .all(|(_, r)| *r == IgnoreReason::WrongProposal));
}

#[test]
fn a_replayed_ballot_counts_once() {
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    let a = approve(1, &p);
    let t = count(&p, &c, &[a.clone(), a.clone(), a.clone()]);
    assert_eq!(approvers(&t), ["alice"]);
    assert_eq!(
        t.ignored(),
        [
            (a.event_id(), IgnoreReason::Duplicate),
            (a.event_id(), IgnoreReason::Duplicate)
        ]
    );
    assert!(!t.passed());
}

#[test]
fn ballots_with_the_wrong_scope_or_circle_are_ignored() {
    let c = founding(vec![
        entry("alice", &[1], &["*"]),
        entry("bob", &[2], &["*"]),
    ]);
    let p = adopt(1, &c, "team/backend", digest(b"b"));
    // Bob signs a ballot for the right proposal id but under another envelope scope.
    let wrong_scope = VoteView::from_envelope(&sign_at(
        &sk(2),
        circle(),
        "team/frontend",
        ph_protocol::EventBody::Vote(ph_protocol::VoteBody {
            proposal_id: p.event_id(),
            decision: Approve,
            rationale: None,
        }),
        now(),
    ))
    .unwrap();
    // And one in another circle entirely.
    let other_circle = VoteView::from_envelope(&sign_at(
        &sk(2),
        ph_core::CircleId::derive(&pk(77)),
        "team/backend",
        ph_protocol::EventBody::Vote(ph_protocol::VoteBody {
            proposal_id: p.event_id(),
            decision: Approve,
            rationale: None,
        }),
        now(),
    ))
    .unwrap();
    let t = count(
        &p,
        &c,
        &[approve(1, &p), wrong_scope.clone(), other_circle.clone()],
    );
    assert!(!t.passed());
    assert_eq!(
        t.ignore_reason(&wrong_scope.event_id()),
        Some(IgnoreReason::ScopeMismatch)
    );
    assert_eq!(
        t.ignore_reason(&other_circle.event_id()),
        Some(IgnoreReason::WrongCircle)
    );
}

#[test]
fn a_revoked_device_cannot_approve() {
    let c = founding(vec![
        entry("alice", &[1, 11], &["*"]),
        entry("bob", &[2], &["*"]),
        entry("carol", &[3], &["*"]),
    ]);
    let p = adopt(1, &c, "*", digest(b"b"));
    let votes = [approve(2, &p), approve(11, &p)];
    assert!(count(&p, &c, &votes).passed());

    // Alice's second device is lost and revoked before the proposal passed here.
    let lost = pk(11);
    let revoked = move |d: &DeviceKey| *d == lost;
    let t = tally(&p, &c, &votes, &revoked).unwrap();
    assert!(!t.passed());
    assert_eq!(approvers(&t), ["bob"]);
    assert_eq!(
        t.ignore_reason(&votes[1].event_id()),
        Some(IgnoreReason::Revoked)
    );
    // Revoking a device does not shrink the electorate: it can block, never pass.
    assert_eq!(t.electorate().len(), 3);
    assert_eq!(t.need(), 2);
    // Alice is still a member and can vote from her other device.
    let t = tally(
        &p,
        &c,
        &[votes[0].clone(), votes[1].clone(), approve(1, &p)],
        &revoked,
    )
    .unwrap();
    assert!(t.passed());
}

#[test]
fn the_charter_must_be_the_one_the_proposal_names() {
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    // The same people under different rules is a different charter.
    let mut other = c.content.clone();
    other.rules.binding = false;
    let other = founding_with(other);
    assert_eq!(
        tally(&p, &other, &[approve(1, &p)], &nobody_revoked),
        Err(TallyError::WrongCharter)
    );
    // So is a charter that only differs in who is on the roll.
    let bigger = founding(vec![
        entry("alice", &[1], &["*"]),
        entry("bob", &[2], &["*"]),
        entry("carol", &[3], &["*"]),
        entry("mallory", &[66], &["*"]),
    ]);
    assert_eq!(
        tally(&p, &bigger, &[], &nobody_revoked),
        Err(TallyError::WrongCharter)
    );
}

#[test]
fn stricter_charters_need_more_approvals() {
    let mut content = abc().content.clone();
    content.rules = CharterRules {
        pass: Threshold { num: 3, den: 4 },
        amend: Threshold { num: 3, den: 4 },
        binding: true,
    };
    let c = founding_with(content);
    let p = adopt(1, &c, "*", digest(b"b"));
    let t = count(&p, &c, &[approve(1, &p), approve(2, &p)]);
    assert_eq!((t.need(), t.passed()), (3, false));
    assert_eq!(t.threshold(), Threshold { num: 3, den: 4 });
}
