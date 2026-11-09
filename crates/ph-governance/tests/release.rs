//! RELEASE verification: a RELEASE is a claim, re-verified locally.

mod common;

use common::*;
use ph_core::{DenyReason, EventId};
use ph_governance::{
    verify_release, Blocker, CirclePolicy, IgnoreReason, LocalPolicy, ProposalView, ReleaseError,
    ReleaseView, ViewError, VoteView,
};
use ph_protocol::{EventBody, ReleaseBody, VoteDecision};

const S: &str = "team/frontend";

fn setup() -> (TestOracle, ProposalView, Vec<VoteView>) {
    let o = TestOracle::new();
    for seed in 1..=4 {
        enroll(&o, seed, &[S]);
    }
    let p = proposal(1, S, digest(b"A"));
    let votes = vec![
        vote(1, &p, VoteDecision::Approve),
        vote(2, &p, VoteDecision::Approve),
    ];
    (o, p, votes)
}

fn check(
    o: &TestOracle,
    r: &ReleaseView,
    p: &ProposalView,
    votes: &[VoteView],
) -> Result<ph_governance::ProposalStatus, ReleaseError> {
    verify_release(
        r,
        p,
        votes,
        o,
        &CirclePolicy::default(),
        &LocalPolicy::default(),
        now(),
    )
}

fn ids(votes: &[VoteView]) -> Vec<EventId> {
    votes.iter().map(|v| v.event_id()).collect()
}

#[test]
fn valid_release_verifies() {
    let (o, p, votes) = setup();
    let r = release(1, &p, ids(&votes));
    let st = check(&o, &r, &p, &votes).unwrap();
    assert!(st.eligible);
    assert_eq!(r.approvals().len(), 2);
    assert_eq!(r.publisher(), pk(1));
    // Any member with publish may announce it, not only the proposer.
    let r2 = release(3, &p, ids(&votes));
    assert!(check(&o, &r2, &p, &votes).is_ok());
}

#[test]
fn release_never_makes_eligible_on_its_own() {
    let (o, p, votes) = setup();
    let r = release(1, &p, ids(&votes));
    // Without locally stored votes, the claim cannot be verified.
    assert_eq!(
        check(&o, &r, &p, &[]),
        Err(ReleaseError::UnknownApproval(votes[0].event_id()))
    );
    // With only part of the evidence.
    assert_eq!(
        check(&o, &r, &p, &votes[..1]),
        Err(ReleaseError::UnknownApproval(votes[1].event_id()))
    );
}

#[test]
fn release_with_unverifiable_approvals_is_rejected() {
    let (o, p, mut votes) = setup();
    // A Sybil vote listed as approval.
    let sybil = vote(100, &p, VoteDecision::Approve);
    votes.push(sybil.clone());
    let r = release(1, &p, vec![votes[0].event_id(), sybil.event_id()]);
    assert_eq!(
        check(&o, &r, &p, &votes),
        Err(ReleaseError::ApprovalIgnored {
            vote_id: sybil.event_id(),
            reason: IgnoreReason::VoterNotAuthorized(DenyReason::NotMember)
        })
    );
    // A vote for another digest listed as approval.
    let other = proposal(1, S, digest(b"B"));
    let foreign = vote(3, &other, VoteDecision::Approve);
    votes.push(foreign.clone());
    let r = release(1, &p, vec![votes[0].event_id(), foreign.event_id()]);
    assert_eq!(
        check(&o, &r, &p, &votes),
        Err(ReleaseError::ApprovalIgnored {
            vote_id: foreign.event_id(),
            reason: IgnoreReason::WrongProposal
        })
    );
    // A reject listed as approval.
    let (o2, p2, mut v2) = setup();
    let rej = vote(3, &p2, VoteDecision::Reject);
    v2.push(rej.clone());
    let r = release(1, &p2, vec![v2[0].event_id(), rej.event_id()]);
    let err = check(&o2, &r, &p2, &v2).unwrap_err();
    assert_eq!(
        err,
        ReleaseError::ApprovalNotApprove {
            vote_id: rej.event_id(),
            decision: VoteDecision::Reject
        }
    );
    assert_eq!(err.to_string(), "release claim not verified");
    let _ = o;
}

#[test]
fn replaced_vote_cannot_be_listed() {
    let (o, p, mut votes) = setup();
    let early = vote_at(2, &p, VoteDecision::Approve, now().minus_secs(500));
    votes.push(early.clone());
    let r = release(1, &p, vec![votes[0].event_id(), early.event_id()]);
    assert_eq!(
        check(&o, &r, &p, &votes),
        Err(ReleaseError::ApprovalIgnored {
            vote_id: early.event_id(),
            reason: IgnoreReason::Replaced
        })
    );
}

#[test]
fn release_must_match_proposal() {
    let (o, p, votes) = setup();
    let other = proposal(1, S, digest(b"B"));
    let r = release(1, &other, ids(&votes));
    assert_eq!(check(&o, &r, &p, &votes), Err(ReleaseError::WrongProposal));

    let make = |body: ReleaseBody, scope_s: &str| {
        ReleaseView::from_envelope(&sign_at(
            &sk(1),
            circle(),
            scope_s,
            EventBody::Release(body),
            now(),
        ))
        .unwrap()
    };
    let base = ReleaseBody {
        proposal_id: p.event_id(),
        bundle_digest: p.bundle_digest(),
        skill_name: p.skill_name().into(),
        approvals: ids(&votes),
    };
    let r = make(
        ReleaseBody {
            bundle_digest: digest(b"B"),
            ..base.clone()
        },
        S,
    );
    assert_eq!(check(&o, &r, &p, &votes), Err(ReleaseError::DigestMismatch));
    let r = make(
        ReleaseBody {
            skill_name: "another-skill".into(),
            ..base.clone()
        },
        S,
    );
    assert_eq!(
        check(&o, &r, &p, &votes),
        Err(ReleaseError::SkillNameMismatch)
    );
    let r = make(base.clone(), "team/frontend/web");
    assert_eq!(check(&o, &r, &p, &votes), Err(ReleaseError::ScopeMismatch));
    let r = make(base, S);
    assert!(check(&o, &r, &p, &votes).is_ok());
}

#[test]
fn publisher_must_have_publish() {
    let (o, p, votes) = setup();
    let r = release(60, &p, ids(&votes));
    assert_eq!(
        check(&o, &r, &p, &votes),
        Err(ReleaseError::PublisherNotAuthorized(DenyReason::NotMember))
    );
    enroll(&o, 61, &["team/finance"]);
    let r = release(61, &p, ids(&votes));
    assert_eq!(
        check(&o, &r, &p, &votes),
        Err(ReleaseError::PublisherNotAuthorized(
            DenyReason::ScopeDenied
        ))
    );
}

#[test]
fn insufficient_listed_evidence_and_local_policy() {
    let (o, p, votes) = setup();
    // Locally eligible, but the release lists a single approval.
    let r = release(1, &p, vec![votes[0].event_id()]);
    assert_eq!(
        check(&o, &r, &p, &votes),
        Err(ReleaseError::InsufficientEvidence { listed: 1, need: 2 })
    );
    // Listing the proposer's approval twice-by-id is impossible (protocol rejects
    // duplicate approvals), and a release listing only proposer approvals fails the
    // non-proposer rule.
    let lax = CirclePolicy {
        min_approvals: 1,
        ..CirclePolicy::default()
    };
    let r = release(1, &p, vec![votes[0].event_id()]);
    assert!(matches!(
        verify_release(&r, &p, &votes, &o, &lax, &LocalPolicy::default(), now()),
        Err(ReleaseError::InsufficientEvidence { .. })
    ));
    // A node with a stricter local policy refuses a release another node accepts.
    let r = release(1, &p, ids(&votes));
    let strict = LocalPolicy {
        required_approvers: vec![pk(4)],
        extra_min_approvals: None,
    };
    let policy = CirclePolicy::default();
    assert!(verify_release(&r, &p, &votes, &o, &policy, &LocalPolicy::default(), now()).is_ok());
    match verify_release(&r, &p, &votes, &o, &policy, &strict, now()) {
        Err(e @ ReleaseError::NotEligible(_)) => {
            let ReleaseError::NotEligible(st) = &e else {
                unreachable!()
            };
            assert_eq!(st.blockers, vec![Blocker::MissingRequiredApprover(pk(4))]);
            assert!(e.describe().contains(&pk(4).fingerprint()));
            assert_eq!(e.code(), "not_eligible");
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn release_blocked_by_reject_or_revocation() {
    let (o, p, mut votes) = setup();
    let r = release(1, &p, ids(&votes));
    votes.push(vote(3, &p, VoteDecision::Reject));
    assert!(matches!(
        check(&o, &r, &p, &votes),
        Err(ReleaseError::NotEligible(_))
    ));
    let (o, p, votes) = setup();
    let r = release(1, &p, ids(&votes));
    o.revoke(&revocation_of(2, now()), now());
    assert_eq!(
        check(&o, &r, &p, &votes),
        Err(ReleaseError::ApprovalIgnored {
            vote_id: votes[1].event_id(),
            reason: IgnoreReason::VoterNotAuthorized(DenyReason::Revoked)
        })
    );
}

#[test]
fn tampered_release_approvals_break_signature() {
    let (_o, p, votes) = setup();
    let env = release_env(1, &p, ids(&votes));
    let mut forged = env.clone();
    if let EventBody::Release(b) = &mut forged.envelope.body {
        b.approvals.push(EventId::from_digest(digest(b"x")));
    }
    assert_eq!(
        ReleaseView::from_envelope(&forged),
        Err(ViewError::BadSignature)
    );
}

#[test]
fn expired_release() {
    let (o, p, votes) = setup();
    let r = release(1, &p, ids(&votes));
    let at = r.expires_at();
    assert_eq!(
        verify_release(
            &r,
            &p,
            &votes,
            &o,
            &CirclePolicy::default(),
            &LocalPolicy::default(),
            at
        ),
        Err(ReleaseError::Expired)
    );
}
