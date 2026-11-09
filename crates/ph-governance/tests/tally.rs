//! Vote tally and eligibility (architecture section 10; spec section 11 vote cases).

mod common;

use common::*;
use ph_core::{DenyReason, EventId, Role};
use ph_governance::{
    evaluate_proposal, Blocker, CirclePolicy, IgnoreReason, LocalPolicy, ProposalStatus,
    ProposalView, ViewError, VoteView,
};
use ph_protocol::{validate_stateless, EventBody, ProtocolError, VoteDecision};
use serde_json::json;

const S: &str = "team/frontend";

/// Alice (1) proposes; Bob (2), Carol (3) and Dave (4) are members of team/frontend.
fn setup() -> (TestOracle, ProposalView) {
    let o = TestOracle::new();
    for seed in 1..=4 {
        enroll(&o, seed, &[S]);
    }
    (o, proposal(1, S, digest(b"A")))
}

fn eval(o: &TestOracle, p: &ProposalView, votes: &[VoteView]) -> ProposalStatus {
    evaluate_proposal(
        p,
        votes,
        o,
        &CirclePolicy::default(),
        &LocalPolicy::default(),
        now(),
    )
}

#[test]
fn two_distinct_approvers_make_eligible() {
    let (o, p) = setup();
    let votes = [
        vote(1, &p, VoteDecision::Approve),
        vote(2, &p, VoteDecision::Approve),
    ];
    let st = eval(&o, &p, &votes);
    assert!(st.eligible, "{}", st.explain());
    assert!(st.blockers.is_empty());
    let mut want = vec![pk(1), pk(2)];
    want.sort();
    assert_eq!(st.approvers, want);
    assert_eq!(st.counted_votes.len(), 2);
    assert!(st.ignored.is_empty());
    assert_eq!(st.required_approvals, 2);
}

#[test]
fn proposer_alone_cannot_reach_eligibility() {
    let (o, p) = setup();
    let votes = [vote(1, &p, VoteDecision::Approve)];
    let st = eval(&o, &p, &votes);
    assert!(!st.eligible);
    assert!(st
        .blockers
        .contains(&Blocker::NotEnoughApprovals { have: 1, need: 2 }));
    assert!(st.blockers.contains(&Blocker::NoNonProposerApproval));
    // Even with a 1-approval policy, require_non_proposer still blocks.
    let lax = CirclePolicy {
        min_approvals: 1,
        ..CirclePolicy::default()
    };
    let st = evaluate_proposal(&p, &votes, &o, &lax, &LocalPolicy::default(), now());
    assert_eq!(st.blockers, vec![Blocker::NoNonProposerApproval]);
    // The proposer voting many times is still one approver.
    let many: Vec<_> = (0..5)
        .map(|i| vote_at(1, &p, VoteDecision::Approve, now().minus_secs(100 + i)))
        .collect();
    let st = eval(&o, &p, &many);
    assert_eq!(st.approvers, vec![pk(1)]);
    assert!(!st.eligible);
    assert_eq!(
        st.ignored
            .iter()
            .filter(|(_, r)| *r == IgnoreReason::Replaced)
            .count(),
        4
    );
}

#[test]
fn replayed_vote_counts_once() {
    let (o, p) = setup();
    let v = vote(2, &p, VoteDecision::Approve);
    let st = eval(&o, &p, &[v.clone(), v.clone(), v.clone()]);
    assert_eq!(st.approvers, vec![pk(2)]);
    assert_eq!(st.counted_votes, vec![v.event_id()]);
    assert_eq!(
        st.ignored,
        vec![
            (v.event_id(), IgnoreReason::Duplicate),
            (v.event_id(), IgnoreReason::Duplicate)
        ]
    );
    assert!(!st.eligible);
}

#[test]
fn vote_cannot_be_retargeted() {
    let (_o, p) = setup();
    let other = proposal(1, S, digest(b"B"));
    let env = vote_env_for(2, &p, VoteDecision::Approve, now());

    // Over the wire: changing proposal_id or bundle_digest breaks the signature.
    for (field, value) in [
        ("proposal_id", json!(other.event_id().to_string())),
        ("bundle_digest", json!(digest(b"B").to_string())),
        ("decision", json!("reject")),
    ] {
        let mut v = env.to_value().unwrap();
        v["body"][field] = value;
        assert!(
            matches!(
                validate_stateless(v.to_string().as_bytes(), now()),
                Err(ProtocolError::BadSignature { .. })
            ),
            "{field}"
        );
    }
    // In memory: a view cannot be built from a re-pointed envelope.
    let mut forged = env.clone();
    if let EventBody::Vote(b) = &mut forged.envelope.body {
        b.proposal_id = other.event_id();
    }
    assert_eq!(
        VoteView::from_envelope(&forged),
        Err(ViewError::BadSignature)
    );
    let mut forged = env.clone();
    if let EventBody::Vote(b) = &mut forged.envelope.body {
        b.bundle_digest = digest(b"B");
    }
    assert_eq!(
        VoteView::from_envelope(&forged),
        Err(ViewError::BadSignature)
    );
    // Wrong type.
    let q = question_env(2, S, "q?");
    assert!(matches!(
        VoteView::from_envelope(&q),
        Err(ViewError::WrongType { .. })
    ));
}

#[test]
fn sybil_keys_without_root_credentials_cannot_satisfy_quorum() {
    let (o, p) = setup();
    let mut votes = vec![vote(2, &p, VoteDecision::Approve)];
    // Ten self-made keys, each with a self-issued "credential" the oracle happily stores
    // (it is valid for the attacker's own circle) and a valid-looking signed vote.
    for seed in 100..110u8 {
        let fake = proof_by(
            &sk(seed),
            &sk(seed),
            vec![Role::Owner],
            &["*"],
            now().minus_secs(60),
            now().plus_days(10),
        );
        assert!(o.add_proof(&fake, now()));
        votes.push(vote(seed, &p, VoteDecision::Approve));
    }
    // Ten keys issued by a fake root claiming to be ours are equally useless.
    let fake_root = sk(150);
    for seed in 110..120u8 {
        let fake = proof_by(
            &fake_root,
            &sk(seed),
            vec![Role::Member],
            &[S],
            now().minus_secs(60),
            now().plus_days(10),
        );
        assert!(o.add_proof(&fake, now()));
        votes.push(vote(seed, &p, VoteDecision::Approve));
    }
    let st = eval(&o, &p, &votes);
    assert_eq!(st.approvers, vec![pk(2)]);
    assert!(!st.eligible);
    assert_eq!(st.ignored.len(), 20);
    assert!(st
        .ignored
        .iter()
        .all(|(_, r)| *r == IgnoreReason::VoterNotAuthorized(DenyReason::NotMember)));
}

#[test]
fn vote_for_hash_a_does_not_count_for_modified_hash_b() {
    let (o, p_a) = setup();
    // Alice modifies the bundle: a new proposal with digest B.
    let p_b = proposal(1, S, digest(b"B"));
    let votes_a = [
        vote(2, &p_a, VoteDecision::Approve),
        vote(3, &p_a, VoteDecision::Approve),
    ];
    assert!(eval(&o, &p_a, &votes_a).eligible);
    let st_b = eval(&o, &p_b, &votes_a);
    assert!(!st_b.eligible);
    assert!(st_b.approvers.is_empty());
    assert!(st_b
        .ignored
        .iter()
        .all(|(_, r)| *r == IgnoreReason::WrongProposal));

    // A vote naming B's id but A's digest (signed so by a confused/malicious member).
    let mixed = sign_at(
        &sk(3),
        circle(),
        S,
        EventBody::Vote(ph_protocol::VoteBody {
            proposal_id: p_b.event_id(),
            bundle_digest: digest(b"A"),
            decision: VoteDecision::Approve,
            rationale: None,
        }),
        now(),
    );
    let mixed = VoteView::from_envelope(&mixed).unwrap();
    let st = eval(&o, &p_b, std::slice::from_ref(&mixed));
    assert_eq!(
        st.ignored,
        vec![(mixed.event_id(), IgnoreReason::DigestMismatch)]
    );
}

#[test]
fn later_reject_blocks_and_latest_decision_wins() {
    let (o, p) = setup();
    let t1 = now().minus_secs(600);
    let t2 = now().minus_secs(300);
    let approve_then_reject = [
        vote_at(1, &p, VoteDecision::Approve, t1),
        vote_at(3, &p, VoteDecision::Approve, t1),
        vote_at(2, &p, VoteDecision::Approve, t1),
        vote_at(2, &p, VoteDecision::Reject, t2),
    ];
    let st = eval(&o, &p, &approve_then_reject);
    assert!(!st.eligible);
    assert_eq!(st.rejecters, vec![pk(2)]);
    assert!(st.blockers.contains(&Blocker::Rejected(pk(2))));
    assert!(!st.approvers.contains(&pk(2)));

    // Order of input does not matter.
    let mut rev = approve_then_reject.to_vec();
    rev.reverse();
    let st2 = eval(&o, &p, &rev);
    assert_eq!(st2.approvers, st.approvers);
    assert_eq!(st2.blockers, st.blockers);
    assert_eq!(st2.counted_votes, st.counted_votes);

    // Changing one's mind back to approve unblocks.
    let mut votes = approve_then_reject.to_vec();
    votes.push(vote_at(2, &p, VoteDecision::Approve, now().minus_secs(10)));
    assert!(eval(&o, &p, &votes).eligible);

    // Revise blocks too.
    let st = eval(
        &o,
        &p,
        &[
            vote(1, &p, VoteDecision::Approve),
            vote(2, &p, VoteDecision::Approve),
            vote(3, &p, VoteDecision::Revise),
        ],
    );
    assert_eq!(st.blockers, vec![Blocker::RevisionRequested(pk(3))]);

    // block_on_reject = false: a reject no longer blocks.
    let lenient = CirclePolicy {
        block_on_reject: false,
        ..CirclePolicy::default()
    };
    let st = evaluate_proposal(
        &p,
        &approve_then_reject,
        &o,
        &lenient,
        &LocalPolicy::default(),
        now(),
    );
    assert!(st.eligible);
    assert_eq!(st.rejecters, vec![pk(2)]);
}

#[test]
fn same_timestamp_tie_breaks_by_event_id() {
    let (o, p) = setup();
    let t = now().minus_secs(5);
    let a = vote_at(2, &p, VoteDecision::Approve, t);
    let r = vote_at(2, &p, VoteDecision::Reject, t);
    let winner = if a.event_id() > r.event_id() { &a } else { &r };
    for order in [[a.clone(), r.clone()], [r.clone(), a.clone()]] {
        let st = eval(&o, &p, &order);
        assert_eq!(st.counted_votes, vec![winner.event_id()]);
    }
}

#[test]
fn revoked_voters_earlier_approve_no_longer_counts() {
    let (o, p) = setup();
    let votes = [
        vote(1, &p, VoteDecision::Approve),
        vote(2, &p, VoteDecision::Approve),
    ];
    assert!(eval(&o, &p, &votes).eligible);
    assert!(o.revoke(&revocation_of(2, now()), now()));
    let st = eval(&o, &p, &votes);
    assert!(!st.eligible);
    assert_eq!(st.approvers, vec![pk(1)]);
    assert_eq!(
        st.ignored,
        vec![(
            votes[1].event_id(),
            IgnoreReason::VoterNotAuthorized(DenyReason::Revoked)
        )]
    );
}

#[test]
fn expired_voter_credential_and_out_of_scope_voter_do_not_count() {
    let (o, p) = setup();
    // Eve (5) only has team/finance.
    enroll(&o, 5, &["team/finance"]);
    // Bob's credential is evaluated after it expires.
    let votes = [
        vote(1, &p, VoteDecision::Approve),
        vote(2, &p, VoteDecision::Approve),
        vote(5, &p, VoteDecision::Approve),
    ];
    let st = eval(&o, &p, &votes);
    assert!(st.eligible);
    assert!(st.ignored.contains(&(
        votes[2].event_id(),
        IgnoreReason::VoterNotAuthorized(DenyReason::ScopeDenied)
    )));
    let later = now().plus_days(30);
    let st = evaluate_proposal(
        &p,
        &votes,
        &o,
        &CirclePolicy::default(),
        &LocalPolicy::default(),
        later,
    );
    assert!(!st.eligible);
    assert!(st.approvers.is_empty());
}

#[test]
fn vote_scope_and_circle_must_match() {
    let (o, p) = setup();
    let wrong_scope = sign_at(
        &sk(2),
        circle(),
        "team/frontend/web",
        EventBody::Vote(ph_protocol::VoteBody {
            proposal_id: p.event_id(),
            bundle_digest: p.bundle_digest(),
            decision: VoteDecision::Approve,
            rationale: None,
        }),
        now(),
    );
    let other_circle = sign_at(
        &sk(2),
        ph_core::CircleId::derive(&pk(9)),
        S,
        EventBody::Vote(ph_protocol::VoteBody {
            proposal_id: p.event_id(),
            bundle_digest: p.bundle_digest(),
            decision: VoteDecision::Approve,
            rationale: None,
        }),
        now(),
    );
    let ws = VoteView::from_envelope(&wrong_scope).unwrap();
    let oc = VoteView::from_envelope(&other_circle).unwrap();
    let st = eval(&o, &p, &[ws.clone(), oc.clone()]);
    assert_eq!(
        st.ignored,
        vec![
            (ws.event_id(), IgnoreReason::ScopeMismatch),
            (oc.event_id(), IgnoreReason::WrongCircle)
        ]
    );
}

#[test]
fn expired_vote_and_expired_proposal() {
    let (o, p) = setup();
    let old = vote_at(2, &p, VoteDecision::Approve, now().minus_secs(3000));
    // Evaluate at the vote's expiry, which is after the proposal's expiry.
    let at = old.expires_at();
    let st = evaluate_proposal(
        &p,
        std::slice::from_ref(&old),
        &o,
        &CirclePolicy::default(),
        &LocalPolicy::default(),
        at,
    );
    assert_eq!(st.ignored, vec![(old.event_id(), IgnoreReason::Expired)]);
    assert!(st.blockers.contains(&Blocker::ProposalExpired));
}

#[test]
fn local_required_approvers_give_distinct_local_views() {
    let (o, p) = setup();
    let votes = [
        vote(1, &p, VoteDecision::Approve),
        vote(2, &p, VoteDecision::Approve),
    ];
    let node_b = LocalPolicy::default();
    let node_c = LocalPolicy {
        required_approvers: vec![pk(3), pk(3)],
        extra_min_approvals: None,
    };
    let policy = CirclePolicy::default();
    let b = evaluate_proposal(&p, &votes, &o, &policy, &node_b, now());
    let c = evaluate_proposal(&p, &votes, &o, &policy, &node_c, now());
    assert!(b.eligible);
    assert!(!c.eligible);
    assert_eq!(c.blockers, vec![Blocker::MissingRequiredApprover(pk(3))]);
    // Once Carol approves, node C agrees.
    let mut more = votes.to_vec();
    more.push(vote(3, &p, VoteDecision::Approve));
    assert!(evaluate_proposal(&p, &more, &o, &policy, &node_c, now()).eligible);

    // extra_min_approvals raises the bar, never lowers it.
    let strict = LocalPolicy {
        required_approvers: vec![],
        extra_min_approvals: Some(3),
    };
    let st = evaluate_proposal(&p, &votes, &o, &policy, &strict, now());
    assert_eq!(
        st.blockers,
        vec![Blocker::NotEnoughApprovals { have: 2, need: 3 }]
    );
    let lower = LocalPolicy {
        required_approvers: vec![],
        extra_min_approvals: Some(1),
    };
    let st = evaluate_proposal(&p, &[votes[1].clone()], &o, &policy, &lower, now());
    assert!(!st.eligible);
    assert_eq!(st.required_approvals, 2);
}

#[test]
fn revoked_proposer_blocks() {
    let (o, p) = setup();
    let votes = [
        vote(2, &p, VoteDecision::Approve),
        vote(3, &p, VoteDecision::Approve),
    ];
    assert!(eval(&o, &p, &votes).eligible);
    o.revoke(&revocation_of(1, now()), now());
    let st = eval(&o, &p, &votes);
    assert_eq!(
        st.blockers,
        vec![Blocker::ProposerNotAuthorized(DenyReason::Revoked)]
    );
}

#[test]
fn explanation_has_fingerprints_and_no_peer_text() {
    let (o, p) = setup();
    let votes = [
        vote(1, &p, VoteDecision::Approve),
        vote(2, &p, VoteDecision::Reject),
        vote(60, &p, VoteDecision::Approve),
    ];
    let st = eval(&o, &p, &votes);
    let text = st.explain();
    assert!(text.contains("NOT ELIGIBLE"));
    assert!(text.contains(&pk(1).fingerprint()));
    assert!(text.contains("(proposer)"));
    assert!(text.contains(&format!("rejected by {}", pk(2).fingerprint())));
    assert!(text.contains("rationale: 11 chars"));
    assert!(text.contains("not an eligible voter (not_member)"));
    assert!(!text.contains("looks right"));
    assert_eq!(st.to_string(), text);
    // Debug of views prints lengths only.
    let dbg = format!("{:?} {:?}", votes[0], p);
    assert!(!dbg.contains("looks right"));
    assert!(!dbg.contains("pnpm repository convention"));
    // Accessors.
    assert_eq!(votes[0].rationale(), Some("looks right"));
    assert_eq!(votes[1].decision(), VoteDecision::Reject);
    assert_eq!(
        st.counted_decision(&votes[0].event_id()).unwrap().voter,
        pk(1)
    );
    assert!(st
        .counted_decision(&EventId::from_digest(digest(b"z")))
        .is_none());
}

#[test]
fn proposal_view_requires_valid_signature() {
    let env = proposal_env(1, S, "pnpm-repository-convention", digest(b"A"));
    let mut forged = env.clone();
    if let EventBody::Proposal(b) = &mut forged.envelope.body {
        b.bundle_digest = digest(b"evil");
    }
    assert_eq!(
        ProposalView::from_envelope(&forged),
        Err(ViewError::BadSignature)
    );
    let v = ProposalView::from_verified(&verified(&env)).unwrap();
    assert_eq!(v, ProposalView::from_envelope(&env).unwrap());
    assert_eq!(v.skill_name(), "pnpm-repository-convention");
    assert_eq!(v.envelope(), &env);
}
