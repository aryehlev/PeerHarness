//! Charter succession: the roll and the rules change only by vote, and the root key can
//! notarize but not decide (architecture section 10.8).

mod common;

use common::*;
use ph_governance::{
    add_device, admit_member, change_rules, check_successor, propose_content, remove_device,
    remove_member, rules_in_force, tally, DraftError, Passed, ProposalView, ResultError,
    ResultView, RuleSet, SuccessionError, VoteView,
};
use ph_protocol::{Charter, CharterContent, CharterRules, Threshold, UnsignedCharter};

fn no_rules() -> RuleSet {
    RuleSet::default()
}

/// Proposes `next` under `current` from device `proposer`, collects approvals from
/// `approvers`, and returns what a node needs to check the successor.
fn vote_through(
    current: &Charter,
    next: &CharterContent,
    proposer: u8,
    approvers: &[u8],
) -> (ProposalView, Vec<VoteView>, ResultView) {
    let p = amend(proposer, current, next.clone());
    let votes: Vec<VoteView> = approvers.iter().map(|s| approve(*s, &p)).collect();
    let r = result_of(proposer, &p, &votes);
    (p, votes, r)
}

#[test]
fn the_founder_admits_the_second_member_and_two_admit_the_third() {
    // Charter 1: alice alone. Her own approval is the majority.
    let c1 = founding(vec![entry("alice", &[1], &["*"])]);
    let next = admit_member(&c1.content, &no_rules(), entry("bob", &[2], &["*"])).unwrap();
    let (p, votes, r) = vote_through(&c1, &next, 1, &[1]);
    let c2 = successor(&c1, next, r.event_id());
    check_successor(&c1, &c2, &p, &r, &votes, &nobody_revoked).unwrap();
    assert_eq!(c2.seq, 2);
    assert_eq!(c2.content.roll.len(), 2);

    // Charter 2: alice and bob. Admitting carol now needs both of them.
    let next = admit_member(&c2.content, &no_rules(), entry("carol", &[3], &["*"])).unwrap();
    let (p, votes, r) = vote_through(&c2, &next, 1, &[1]);
    let c3 = successor(&c2, next.clone(), r.event_id());
    assert_eq!(
        check_successor(&c2, &c3, &p, &r, &votes, &nobody_revoked),
        Err(SuccessionError::NotPassed(ResultError::BelowThreshold {
            have: 1,
            need: 2
        })),
        "the founder can no longer admit members alone"
    );
    let (p, votes, r) = vote_through(&c2, &next, 1, &[1, 2]);
    let c3 = successor(&c2, next, r.event_id());
    check_successor(&c2, &c3, &p, &r, &votes, &nobody_revoked).unwrap();
    assert_eq!(c3.content.roll.len(), 3);
}

#[test]
fn the_root_key_cannot_change_the_roll_without_a_vote() {
    let c1 = abc();
    // A real, passed amendment admitting dave.
    let voted = admit_member(&c1.content, &no_rules(), entry("dave", &[4], &["*"])).unwrap();
    let (p, votes, r) = vote_through(&c1, &voted, 1, &[1, 2]);

    // The root signs a charter that also adds mallory. Its signature is valid, and the
    // charter is still refused: its content is not what was voted on.
    let mut stuffed = voted.clone();
    stuffed.roll.push(entry("mallory", &[66], &["*"]));
    stuffed.normalize();
    let bad = successor(&c1, stuffed, r.event_id());
    ph_protocol::verify_charter_signature(&bad).unwrap();
    assert_eq!(
        check_successor(&c1, &bad, &p, &r, &votes, &nobody_revoked),
        Err(SuccessionError::ContentMismatch)
    );

    // The root drops carol instead of adding dave.
    let purged = remove_member(&c1.content, &no_rules(), "carol").unwrap();
    let bad = successor(&c1, purged, r.event_id());
    assert_eq!(
        check_successor(&c1, &bad, &p, &r, &votes, &nobody_revoked),
        Err(SuccessionError::ContentMismatch)
    );

    // The root loosens the rules.
    let mut loose = voted.clone();
    loose.rules.binding = false;
    let bad = successor(&c1, loose, r.event_id());
    assert_eq!(
        check_successor(&c1, &bad, &p, &r, &votes, &nobody_revoked),
        Err(SuccessionError::ContentMismatch)
    );

    // The honest charter is accepted.
    let good = successor(&c1, voted, r.event_id());
    check_successor(&c1, &good, &p, &r, &votes, &nobody_revoked).unwrap();
}

#[test]
fn an_amendment_that_did_not_pass_justifies_nothing() {
    let c1 = abc();
    let next = admit_member(&c1.content, &no_rules(), entry("dave", &[4], &["*"])).unwrap();

    // Only the proposer approved: one of three.
    let (p, votes, r) = vote_through(&c1, &next, 1, &[1]);
    let c2 = successor(&c1, next.clone(), r.event_id());
    assert_eq!(
        check_successor(&c1, &c2, &p, &r, &votes, &nobody_revoked),
        Err(SuccessionError::NotPassed(ResultError::BelowThreshold {
            have: 1,
            need: 2
        }))
    );

    // Approvals from keys that are not members do not help.
    let (p, votes, r) = vote_through(&c1, &next, 1, &[1, 77, 78, 79]);
    let c2 = successor(&c1, next.clone(), r.event_id());
    assert!(matches!(
        check_successor(&c1, &c2, &p, &r, &votes, &nobody_revoked),
        Err(SuccessionError::NotPassed(
            ResultError::BallotNotCounted { .. }
        ))
    ));

    // Dave cannot vote on his own admission: he is not on the roll yet.
    let (p, votes, r) = vote_through(&c1, &next, 1, &[1, 4]);
    let c2 = successor(&c1, next.clone(), r.event_id());
    assert!(check_successor(&c1, &c2, &p, &r, &votes, &nobody_revoked).is_err());

    // A node that has not received a listed ballot yet may try again later.
    let (p, votes, r) = vote_through(&c1, &next, 1, &[1, 2]);
    let c2 = successor(&c1, next, r.event_id());
    let err = check_successor(&c1, &c2, &p, &r, &votes[..1], &nobody_revoked).unwrap_err();
    assert!(err.is_retryable());
    check_successor(&c1, &c2, &p, &r, &votes, &nobody_revoked).unwrap();
}

#[test]
fn changing_the_rules_needs_the_amend_threshold() {
    let c1 = abc();
    let advisory = CharterRules {
        binding: false,
        ..c1.content.rules
    };
    let next = change_rules(&c1.content, &no_rules(), advisory).unwrap();

    // Two of three would pass an ordinary proposal, but not a change of the rules.
    let (p, votes, r) = vote_through(&c1, &next, 1, &[1, 2]);
    let c2 = successor(&c1, next.clone(), r.event_id());
    assert_eq!(
        check_successor(&c1, &c2, &p, &r, &votes, &nobody_revoked),
        Err(SuccessionError::NotPassed(ResultError::BelowThreshold {
            have: 2,
            need: 3
        }))
    );
    let (p, votes, r) = vote_through(&c1, &next, 1, &[1, 2, 3]);
    let c2 = successor(&c1, next, r.event_id());
    check_successor(&c1, &c2, &p, &r, &votes, &nobody_revoked).unwrap();
    assert!(!c2.content.rules.binding);

    // Rules that would let a minority decide cannot even be drafted.
    let minority = CharterRules {
        pass: Threshold { num: 1, den: 3 },
        ..c1.content.rules
    };
    assert_eq!(
        change_rules(&c1.content, &no_rules(), minority),
        Err(DraftError::Invalid)
    );
}

#[test]
fn removing_a_member_is_decided_by_everyone_including_them() {
    let c1 = abc();
    let next = remove_member(&c1.content, &no_rules(), "carol").unwrap();
    // Carol votes no. Alice and bob are still two of three.
    let p = amend(1, &c1, next.clone());
    let votes = vec![
        approve(1, &p),
        approve(2, &p),
        vote(3, &p, ph_protocol::VoteDecision::Reject),
    ];
    let t = tally(&p, &c1, &votes, &nobody_revoked).unwrap();
    assert_eq!(
        t.electorate().len(),
        3,
        "carol is in the electorate of her own removal"
    );
    assert!(t.passed());
    assert_eq!(t.dissent()[0].member, "carol");
    let r = result_of(1, &p, &votes[..2]);
    let c2 = successor(&c1, next, r.event_id());
    check_successor(&c1, &c2, &p, &r, &votes, &nobody_revoked).unwrap();
    assert!(c2.content.member("carol").is_none());

    // One member alone cannot remove another.
    let next = remove_member(&c1.content, &no_rules(), "bob").unwrap();
    let (p, votes, r) = vote_through(&c1, &next, 1, &[1]);
    let c2 = successor(&c1, next, r.event_id());
    assert!(check_successor(&c1, &c2, &p, &r, &votes, &nobody_revoked).is_err());
}

#[test]
fn a_successor_must_follow_the_current_charter_exactly() {
    let c1 = abc();
    let next = admit_member(&c1.content, &no_rules(), entry("dave", &[4], &["*"])).unwrap();
    let (p, votes, r) = vote_through(&c1, &next, 1, &[1, 2]);
    let good = successor(&c1, next.clone(), r.event_id());
    check_successor(&c1, &good, &p, &r, &votes, &nobody_revoked).unwrap();

    let sign = |u: UnsignedCharter| u.sign(&root()).unwrap();
    // A skipped sequence number.
    let mut u = good.unsigned.clone();
    u.seq = 3;
    assert_eq!(
        check_successor(&c1, &sign(u), &p, &r, &votes, &nobody_revoked),
        Err(SuccessionError::NotNext)
    );
    // A different predecessor.
    let mut u = good.unsigned.clone();
    u.previous = Some(digest(b"another history"));
    assert_eq!(
        check_successor(&c1, &sign(u), &p, &r, &votes, &nobody_revoked),
        Err(SuccessionError::NotNext)
    );
    // A justification other than the result supplied.
    let mut u = good.unsigned.clone();
    u.justification = Some(p.event_id());
    assert_eq!(
        check_successor(&c1, &sign(u), &p, &r, &votes, &nobody_revoked),
        Err(SuccessionError::WrongJustification)
    );
    // A charter that was edited after the root signed it.
    let mut tampered = good.clone();
    tampered.unsigned.content.roll.pop();
    assert_eq!(
        check_successor(&c1, &tampered, &p, &r, &votes, &nobody_revoked),
        Err(SuccessionError::InvalidCharter)
    );
    // A charter signed by somebody else's root, for another circle.
    let other_root = sk(201);
    let foreign = UnsignedCharter {
        circle_id: ph_core::CircleId::derive(&pk(201)),
        issuer_key: pk(201),
        ..good.unsigned.clone()
    }
    .sign(&other_root)
    .unwrap();
    assert_eq!(
        check_successor(&c1, &foreign, &p, &r, &votes, &nobody_revoked),
        Err(SuccessionError::WrongCircle)
    );
    // An ordinary rule that passed is not a mandate to change the charter.
    let rule = adopt(1, &c1, "*", digest(b"b"));
    let rule_votes = vec![approve(1, &rule), approve(2, &rule)];
    let rule_result = result_of(1, &rule, &rule_votes);
    let hijack = successor(&c1, next.clone(), rule_result.event_id());
    assert_eq!(
        check_successor(
            &c1,
            &hijack,
            &rule,
            &rule_result,
            &rule_votes,
            &nobody_revoked
        ),
        Err(SuccessionError::NotAnAmendment)
    );
    // An amendment that passed under an older charter cannot be replayed onto a newer one.
    let c2 = good;
    let replay = UnsignedCharter::successor(&c2, next, r.event_id(), now())
        .unwrap()
        .sign(&root())
        .unwrap();
    assert_eq!(
        check_successor(&c2, &replay, &p, &r, &votes, &nobody_revoked),
        Err(SuccessionError::NotAnAmendment)
    );
}

#[test]
fn a_new_charter_carries_the_rules_in_force_and_drops_open_proposals() {
    let c1 = abc();
    let rule = adopt(1, &c1, "*", digest(b"b"));
    let rule_votes = [approve(1, &rule), approve(2, &rule)];
    let t = tally(&rule, &c1, &rule_votes, &nobody_revoked).unwrap();
    let in_force = rules_in_force(&c1, &[Passed::by_vote(&rule, &t, &c1).unwrap()]);
    let open = adopt_named(3, &c1, "*", "vitest-convention", digest(b"open"), now());

    // The amendment built by the helper carries the rule in force.
    let next = admit_member(&c1.content, &in_force, entry("dave", &[4], &["*"])).unwrap();
    assert_eq!(next.carried, [rule.event_id()]);
    assert_eq!(
        propose_content(&c1.content, &in_force).carried,
        [rule.event_id()]
    );
    let (p, votes, r) = vote_through(&c1, &next, 1, &[1, 2]);
    let c2 = successor(&c1, next, r.event_id());
    check_successor(&c1, &c2, &p, &r, &votes, &nobody_revoked).unwrap();

    // Under charter 2 the rule is in force as carried, for old and new members alike.
    let rs = rules_in_force(&c2, &[Passed::carried(&rule, &c2).unwrap()]);
    assert_eq!(rs.get(SKILL).unwrap().proposal_id(), rule.event_id());
    // The proposal that was still open names charter 1 and can no longer pass.
    let late = [approve(1, &open), approve(2, &open), approve(3, &open)];
    let t = tally(&open, &c1, &late, &nobody_revoked).unwrap();
    assert!(
        t.passed(),
        "it reaches its threshold under the charter it names"
    );
    assert!(
        Passed::by_vote(&open, &t, &c2).is_err(),
        "but that charter is over"
    );
}

#[test]
fn drafting_helpers_refuse_nonsense() {
    let c = abc().content.clone();
    let none = no_rules();
    assert_eq!(
        admit_member(&c, &none, entry("alice", &[9], &["*"])),
        Err(DraftError::MemberExists)
    );
    assert_eq!(
        admit_member(&c, &none, entry("dave", &[2], &["*"])),
        Err(DraftError::DeviceExists),
        "bob's device cannot be enrolled under another name"
    );
    assert_eq!(
        remove_member(&c, &none, "zed"),
        Err(DraftError::NoSuchMember)
    );
    assert_eq!(
        add_device(&c, &none, "alice", pk(3)),
        Err(DraftError::DeviceExists)
    );
    assert_eq!(
        add_device(&c, &none, "zed", pk(9)),
        Err(DraftError::NoSuchMember)
    );
    assert_eq!(
        remove_device(&c, &none, "alice", &pk(9)),
        Err(DraftError::NoSuchDevice)
    );
    // A member's last device cannot be removed; remove the member instead.
    assert_eq!(
        remove_device(&c, &none, "alice", &pk(1)),
        Err(DraftError::Invalid)
    );
    // The last member cannot be removed.
    let solo = founding(vec![entry("alice", &[1], &["*"])]).content.clone();
    assert_eq!(
        remove_member(&solo, &none, "alice"),
        Err(DraftError::Invalid)
    );

    // Adding a second device keeps one member, one vote.
    let next = add_device(&c, &none, "alice", pk(11)).unwrap();
    assert_eq!(next.roll.len(), 3);
    assert_eq!(next.member("alice").unwrap().devices.len(), 2);
    next.check_structure().unwrap();
    let back = remove_device(&next, &none, "alice", &pk(11)).unwrap();
    assert_eq!(back, c);
}
