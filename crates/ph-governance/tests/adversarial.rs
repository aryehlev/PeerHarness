//! Adversarial cases added in review: timestamp gaming of the latest-vote rule, scope
//! mismatches between voters, votes and proposals, RELEASE evidence taken from other
//! proposals, ADR-010 control-plane edge cases (cross-circle MEMBERSHIP, non-root and
//! self REVOCATION, founder-device revocation), forged statuses at the adoption gate and
//! in-memory envelopes that bypass parsing.

mod common;

use common::*;
use ph_core::{CircleId, DenyReason, EventId, MembershipOracle, Nonce, Role, Scope, Timestamp};
use ph_governance::{
    adoption_readiness, authorize_incoming, authorize_incoming_with_revocations, evaluate_proposal,
    verify_release, Blocker, CirclePolicy, IgnoreReason, LocalPolicy, NotReadyReason,
    ProposalStatus, ProposalView, Rejection, ReleaseError, ReleaseView, ViewError, VoteView,
};
use ph_protocol::limits::CLOCK_SKEW_SECS;
use ph_protocol::{
    signing, validate_stateless, EnvelopeBuilder, EventBody, MembershipBody, ReleaseBody,
    Revocation, RevocationBody, SignedEnvelope, SigningKey, UnsignedEnvelope, UnsignedRevocation,
    VoteBody, VoteDecision,
};

const S: &str = "team/frontend";

/// Alice (1) proposes in team/frontend; Bob (2), Carol (3), Dave (4) are members there.
fn setup() -> (TestOracle, ProposalView) {
    let o = TestOracle::new();
    for seed in 1..=4 {
        enroll(&o, seed, &[S]);
    }
    (o, proposal(1, S, digest(b"A")))
}

fn eval_at(o: &TestOracle, p: &ProposalView, votes: &[VoteView], at: Timestamp) -> ProposalStatus {
    evaluate_proposal(
        p,
        votes,
        o,
        &CirclePolicy::default(),
        &LocalPolicy::default(),
        at,
    )
}

fn eval(o: &TestOracle, p: &ProposalView, votes: &[VoteView]) -> ProposalStatus {
    eval_at(o, p, votes, now())
}

/// Signs `u` directly, bypassing every check `UnsignedEnvelope::sign` would apply (what
/// a malicious peer can always do).
fn hand_sign(author: &SigningKey, u: &UnsignedEnvelope) -> SignedEnvelope {
    let input = u.signing_input().unwrap();
    SignedEnvelope {
        envelope: u.clone(),
        signature: signing::sign_input(author, &input),
        event_id: EventId::from_digest(signing::digest_of_input(&input)),
    }
}

fn unsigned(
    author: &SigningKey,
    circle: CircleId,
    scope_s: &str,
    body: EventBody,
    created_at: Timestamp,
    expires_at: Timestamp,
) -> UnsignedEnvelope {
    UnsignedEnvelope {
        circle_id: circle,
        scope: scope(scope_s),
        author: ph_core::DeviceKey::from_signing_key(author),
        nonce: Nonce::from_bytes([7; 16]),
        created_at,
        expires_at,
        body,
    }
}

fn vote_body(p: &ProposalView, decision: VoteDecision) -> EventBody {
    EventBody::Vote(VoteBody {
        proposal_id: p.event_id(),
        bundle_digest: p.bundle_digest(),
        decision,
        rationale: None,
    })
}

// ---------------------------------------------------------------------------------------
// Latest-vote ordering cannot be gamed with future-dated created_at
// ---------------------------------------------------------------------------------------

#[test]
fn far_future_vote_cannot_pin_a_decision() {
    let (o, p) = setup();
    // Bob's key signs an approve dated a year ahead (e.g. briefly stolen key, or a node
    // whose clock was wrong at intake). Bob later rejects with an honest timestamp.
    let future = now().plus_days(365);
    let pinned = VoteView::from_envelope(&hand_sign(
        &sk(2),
        &unsigned(
            &sk(2),
            circle(),
            S,
            vote_body(&p, VoteDecision::Approve),
            future,
            future.plus_days(30),
        ),
    ))
    .unwrap();
    let honest_reject = vote_at(2, &p, VoteDecision::Reject, now().minus_secs(30));
    let votes = [
        vote(1, &p, VoteDecision::Approve),
        vote(3, &p, VoteDecision::Approve),
        pinned.clone(),
        honest_reject.clone(),
    ];
    let st = eval(&o, &p, &votes);
    assert_eq!(
        st.ignore_reason(&pinned.event_id()),
        Some(IgnoreReason::InvalidTime)
    );
    assert_eq!(st.rejecters, vec![pk(2)]);
    assert!(st.blockers.contains(&Blocker::Rejected(pk(2))));
    assert!(!st.eligible);
    assert!(st.explain().contains("future-dated"));
}

#[test]
fn vote_within_clock_skew_counts_and_beyond_does_not() {
    let (o, p) = setup();
    let within = now().plus_secs(CLOCK_SKEW_SECS - 1);
    let beyond = now().plus_secs(CLOCK_SKEW_SECS + 1);
    let mk = |seed: u8, at: Timestamp| {
        VoteView::from_envelope(
            &EnvelopeBuilder::new(circle(), scope(S), vote_body(&p, VoteDecision::Approve))
                .created_at(at)
                .sign(&sk(seed), at)
                .unwrap(),
        )
        .unwrap()
    };
    let ok = mk(2, within);
    let late = mk(3, beyond);
    let st = eval(&o, &p, &[ok.clone(), late.clone()]);
    assert!(st.counted_decision(&ok.event_id()).is_some());
    assert_eq!(
        st.ignore_reason(&late.event_id()),
        Some(IgnoreReason::InvalidTime)
    );
    // Once local time catches up, the same vote counts.
    let st = eval_at(&o, &p, &[ok, late.clone()], beyond);
    assert!(st.counted_decision(&late.event_id()).is_some());
}

#[test]
fn impossible_vote_lifetime_is_ignored() {
    let (o, p) = setup();
    // Signed by hand with a 2-year lifetime (over the 400-day maximum).
    let v = VoteView::from_envelope(&hand_sign(
        &sk(2),
        &unsigned(
            &sk(2),
            circle(),
            S,
            vote_body(&p, VoteDecision::Approve),
            now().minus_secs(60),
            now().plus_days(730),
        ),
    ))
    .unwrap();
    let st = eval(&o, &p, std::slice::from_ref(&v));
    assert_eq!(st.ignored, vec![(v.event_id(), IgnoreReason::InvalidTime)]);
}

#[test]
fn future_dated_proposal_is_blocked() {
    let (o, _) = setup();
    let at = now().plus_days(10);
    let env = EnvelopeBuilder::new(
        circle(),
        scope(S),
        EventBody::Proposal(proposal_body("pnpm-repository-convention", digest(b"A"))),
    )
    .created_at(at)
    .sign(&sk(1), at)
    .unwrap();
    let p = ProposalView::from_envelope(&env).unwrap();
    let votes = [
        vote_at(2, &p, VoteDecision::Approve, now().minus_secs(5)),
        vote_at(3, &p, VoteDecision::Approve, now().minus_secs(5)),
    ];
    let st = eval(&o, &p, &votes);
    assert_eq!(st.blockers, vec![Blocker::ProposalInvalidTime]);
    assert_eq!(Blocker::ProposalInvalidTime.code(), "proposal_invalid_time");
}

#[test]
fn future_dated_release_is_refused() {
    let (o, p) = setup();
    let votes = [
        vote(1, &p, VoteDecision::Approve),
        vote(2, &p, VoteDecision::Approve),
    ];
    let at = now().plus_days(2);
    let r = ReleaseView::from_envelope(
        &EnvelopeBuilder::new(
            circle(),
            scope(S),
            EventBody::Release(ReleaseBody {
                proposal_id: p.event_id(),
                bundle_digest: p.bundle_digest(),
                skill_name: p.skill_name().into(),
                approvals: votes.iter().map(|v| v.event_id()).collect(),
            }),
        )
        .created_at(at)
        .sign(&sk(1), at)
        .unwrap(),
    )
    .unwrap();
    let res = verify_release(
        &r,
        &p,
        &votes,
        &o,
        &CirclePolicy::default(),
        &LocalPolicy::default(),
        now(),
    );
    assert_eq!(res, Err(ReleaseError::InvalidTime));
    assert_eq!(ReleaseError::InvalidTime.code(), "invalid_time");
}

// ---------------------------------------------------------------------------------------
// Scope: voter credential vs. proposal scope vs. vote envelope scope
// ---------------------------------------------------------------------------------------

#[test]
fn voter_scope_must_cover_the_proposal_scope() {
    let (o, p) = setup();
    enroll(&o, 10, &["team"]); // wider grant: covers team/frontend
    enroll(&o, 11, &["team/frontend/web"]); // narrower grant: does not cover team/frontend
    enroll(&o, 12, &["team/frontend-legacy"]); // sibling prefix: does not cover
    let votes = [
        vote(10, &p, VoteDecision::Approve),
        vote(11, &p, VoteDecision::Approve),
        vote(12, &p, VoteDecision::Approve),
    ];
    let st = eval(&o, &p, &votes);
    assert_eq!(st.approvers, vec![pk(10)]);
    for v in &votes[1..] {
        assert_eq!(
            st.ignore_reason(&v.event_id()),
            Some(IgnoreReason::VoterNotAuthorized(DenyReason::ScopeDenied))
        );
    }
}

#[test]
fn vote_envelope_scope_must_equal_proposal_scope() {
    let (o, p) = setup();
    enroll(&o, 10, &["*"]);
    // A voter authorized everywhere still cannot cast the vote in a wider ("team", "*")
    // or narrower scope than the proposal: it would be delivered to a different audience.
    let mut votes = Vec::new();
    for s in ["team", "*", "team/frontend/web"] {
        votes.push(
            VoteView::from_envelope(&sign_at(
                &sk(10),
                circle(),
                s,
                vote_body(&p, VoteDecision::Approve),
                now(),
            ))
            .unwrap(),
        );
    }
    let st = eval(&o, &p, &votes);
    assert!(st.approvers.is_empty());
    assert!(st
        .ignored
        .iter()
        .all(|(_, r)| *r == IgnoreReason::ScopeMismatch));
}

#[test]
fn wildcard_proposal_needs_wildcard_voters() {
    let o = TestOracle::new();
    enroll(&o, 1, &["*"]);
    enroll(&o, 2, &["team"]);
    enroll(&o, 3, &["*"]);
    let p = proposal(1, "*", digest(b"A"));
    let votes = [
        vote(1, &p, VoteDecision::Approve),
        vote(2, &p, VoteDecision::Approve),
    ];
    let st = eval(&o, &p, &votes);
    assert_eq!(st.approvers, vec![pk(1)]);
    assert!(!st.eligible);
    let mut more = votes.to_vec();
    more.push(vote(3, &p, VoteDecision::Approve));
    assert!(eval(&o, &p, &more).eligible);
}

#[test]
fn root_key_is_not_a_voter() {
    let (o, p) = setup();
    let v = vote(ROOT, &p, VoteDecision::Approve);
    let st = eval(&o, &p, &[vote(2, &p, VoteDecision::Approve), v.clone()]);
    assert_eq!(
        st.ignore_reason(&v.event_id()),
        Some(IgnoreReason::VoterNotAuthorized(DenyReason::NotMember))
    );
    assert!(!st.eligible);
}

// ---------------------------------------------------------------------------------------
// RELEASE evidence must come from the released proposal itself
// ---------------------------------------------------------------------------------------

#[test]
fn release_cannot_borrow_votes_from_a_same_digest_proposal() {
    let (o, p) = setup();
    // Carol re-proposes the identical bundle (same digest, different proposal id).
    let twin = proposal(3, S, digest(b"A"));
    assert_ne!(twin.event_id(), p.event_id());
    assert_eq!(twin.bundle_digest(), p.bundle_digest());
    let twin_votes = [
        vote(2, &twin, VoteDecision::Approve),
        vote(4, &twin, VoteDecision::Approve),
    ];
    assert!(eval(&o, &twin, &twin_votes).eligible);
    // The votes do not count for p...
    let st = eval(&o, &p, &twin_votes);
    assert!(st.approvers.is_empty());
    assert!(st
        .ignored
        .iter()
        .all(|(_, r)| *r == IgnoreReason::WrongProposal));
    // ...and a RELEASE of p listing them is refused, even with p's own proposer approval.
    let mut all = twin_votes.to_vec();
    let own = vote(1, &p, VoteDecision::Approve);
    all.push(own.clone());
    let r = release(
        1,
        &p,
        vec![
            own.event_id(),
            twin_votes[0].event_id(),
            twin_votes[1].event_id(),
        ],
    );
    assert_eq!(
        verify_release(
            &r,
            &p,
            &all,
            &o,
            &CirclePolicy::default(),
            &LocalPolicy::default(),
            now()
        ),
        Err(ReleaseError::ApprovalIgnored {
            vote_id: twin_votes[0].event_id(),
            reason: IgnoreReason::WrongProposal
        })
    );
}

#[test]
fn release_cannot_list_an_approve_its_voter_later_withdrew() {
    let (o, p) = setup();
    let approve = vote_at(2, &p, VoteDecision::Approve, now().minus_secs(600));
    let reject = vote_at(2, &p, VoteDecision::Reject, now().minus_secs(60));
    let a1 = vote(1, &p, VoteDecision::Approve);
    let a3 = vote(3, &p, VoteDecision::Approve);
    let votes = [a1.clone(), a3.clone(), approve.clone(), reject];
    let r = release(1, &p, vec![a1.event_id(), approve.event_id()]);
    assert_eq!(
        verify_release(
            &r,
            &p,
            &votes,
            &o,
            &CirclePolicy::default(),
            &LocalPolicy::default(),
            now()
        ),
        Err(ReleaseError::ApprovalIgnored {
            vote_id: approve.event_id(),
            reason: IgnoreReason::Replaced
        })
    );
}

#[test]
fn release_with_in_memory_duplicate_approvals_is_refused_as_a_view() {
    let (_o, p) = setup();
    let a = vote(2, &p, VoteDecision::Approve);
    let env = hand_sign(
        &sk(1),
        &unsigned(
            &sk(1),
            circle(),
            S,
            EventBody::Release(ReleaseBody {
                proposal_id: p.event_id(),
                bundle_digest: p.bundle_digest(),
                skill_name: p.skill_name().into(),
                approvals: vec![a.event_id(), a.event_id()],
            }),
            now().minus_secs(10),
            now().plus_days(30),
        ),
    );
    assert_eq!(env.verify_signature(), Ok(()));
    assert_eq!(
        ReleaseView::from_envelope(&env),
        Err(ViewError::InvalidBody)
    );
    // The same bytes never parse.
    assert!(validate_stateless(&raw(&env), now()).is_err());
}

// ---------------------------------------------------------------------------------------
// ADR-010: MEMBERSHIP and REVOCATION authorization
// ---------------------------------------------------------------------------------------

#[test]
fn membership_for_circle_x_carrying_credential_for_circle_y_is_rejected() {
    let other_root = sk(201);
    let y = CircleId::derive(&pk(201));
    let proof_y = proof_by(
        &other_root,
        &sk(1),
        vec![Role::Member],
        &["*"],
        now().minus_secs(60),
        now().plus_days(10),
    );
    let body = EventBody::Membership(MembershipBody {
        credential: proof_y.credential.clone(),
        acceptance: proof_y.acceptance.clone(),
    });
    // The honest signer refuses.
    assert!(EnvelopeBuilder::new(circle(), Scope::all(), body.clone())
        .sign(&sk(1), now())
        .is_err());
    // A hand-signed envelope claiming our circle is rejected statelessly.
    let forged = hand_sign(
        &sk(1),
        &unsigned(
            &sk(1),
            circle(),
            "*",
            body,
            now().minus_secs(5),
            now().plus_days(5),
        ),
    );
    assert!(validate_stateless(&raw(&forged), now()).is_err());
    // The genuine circle-Y event is "unknown circle" here.
    let genuine = membership_env(1, &proof_y, "*");
    assert_eq!(genuine.circle_id, y);
    let o = TestOracle::new();
    assert_eq!(
        authorize_incoming(&verified(&genuine), &o, &known, now()).unwrap_err(),
        Rejection::UnknownCircle
    );
}

#[test]
fn revocation_for_our_circle_by_a_non_root_key_never_verifies() {
    let o = TestOracle::new();
    enroll(&o, 1, &["*"]);
    enroll(&o, 2, &["*"]);
    // An owner-role member is still not the root.
    enroll(&o, 3, &["*"]);
    // A member forges a revocation of Bob "issued" by itself but claiming our circle.
    let mut u = UnsignedRevocation::new(
        pk(1),
        pk(2),
        now(),
        String::new(),
        Nonce::from_bytes([9; 16]),
    );
    u.circle_id = circle();
    let sig = signing::sign_input(&sk(1), &u.signing_input().unwrap());
    let rev = Revocation {
        unsigned: u,
        signature: sig,
    };
    let env = hand_sign(
        &sk(1),
        &unsigned(
            &sk(1),
            circle(),
            "*",
            EventBody::Revocation(RevocationBody { revocation: rev }),
            now().minus_secs(5),
            now().plus_days(5),
        ),
    );
    assert!(validate_stateless(&raw(&env), now()).is_err());

    // A revocation claiming the root as issuer but signed by the member.
    let u = UnsignedRevocation::new(
        pk(ROOT),
        pk(2),
        now(),
        String::new(),
        Nonce::from_bytes([9; 16]),
    );
    let sig = signing::sign_input(&sk(1), &u.signing_input().unwrap());
    let rev = Revocation {
        unsigned: u,
        signature: sig,
    };
    let env = hand_sign(
        &sk(1),
        &unsigned(
            &sk(1),
            circle(),
            "*",
            EventBody::Revocation(RevocationBody { revocation: rev }),
            now().minus_secs(5),
            now().plus_days(5),
        ),
    );
    assert!(validate_stateless(&raw(&env), now()).is_err());
    // Bob is unaffected.
    assert!(o.is_active_member(&circle(), &pk(2), now()));
}

#[test]
fn root_cannot_revoke_itself() {
    let o = TestOracle::new();
    let rev = revocation_of(ROOT, now());
    let env = revocation_env(&root(), &rev);
    // It is a valid signed object, so stateless validation passes...
    let v = verified(&env);
    // ...but governance refuses to treat it as a revocation.
    assert_eq!(
        authorize_incoming(&v, &o, &known, now()).unwrap_err(),
        Rejection::RootSelfRevocation
    );
    assert_eq!(Rejection::RootSelfRevocation.code(), "root_self_revocation");
}

#[test]
fn founder_device_can_be_revoked_and_loses_its_votes() {
    // The founder's device key (seed 1) is distinct from the root key.
    let (o, p) = setup();
    let votes = [
        vote(1, &p, VoteDecision::Approve),
        vote(2, &p, VoteDecision::Approve),
    ];
    assert!(eval(&o, &p, &votes).eligible);
    let rev = revocation_of(1, now());
    let env = revocation_env(&root(), &rev);
    let a = authorize_incoming(&verified(&env), &o, &known, now()).unwrap();
    assert_eq!(a.basis(), ph_protocol::Authorization::CircleRoot);
    assert!(o.revoke(&rev, now()));
    let st = eval(&o, &p, &votes);
    assert!(!st.eligible);
    assert!(st
        .blockers
        .contains(&Blocker::ProposerNotAuthorized(DenyReason::Revoked)));
    assert_eq!(
        st.ignore_reason(&votes[0].event_id()),
        Some(IgnoreReason::VoterNotAuthorized(DenyReason::Revoked))
    );
    // Its MEMBERSHIP republish is refused under both revocation checks.
    let m = verified(&membership_env(1, &member_proof(1, &[S]), "*"));
    assert_eq!(
        authorize_incoming(&m, &o, &known, now()).unwrap_err(),
        Rejection::Denied(DenyReason::Revoked)
    );
    let is_revoked = |c: &CircleId, k: &ph_core::DeviceKey| o.is_revoked(c, k);
    assert_eq!(
        authorize_incoming_with_revocations(&m, &o, &known, &is_revoked, now()).unwrap_err(),
        Rejection::Denied(DenyReason::Revoked)
    );
}

// ---------------------------------------------------------------------------------------
// Nothing outside deterministic verification can flip eligibility
// ---------------------------------------------------------------------------------------

#[test]
fn adoption_refuses_an_inconsistent_status() {
    let (o, p) = setup();
    let one = eval(&o, &p, &[vote(2, &p, VoteDecision::Approve)]);
    assert!(!one.eligible);
    // Edited to claim eligibility with the blockers wiped: still not enough approvers.
    let mut forged = one.clone();
    forged.eligible = true;
    forged.blockers.clear();
    assert_eq!(
        adoption_readiness(&forged, true, true, true).reasons(),
        &[NotReadyReason::ProposalNotEligible]
    );
    // Edited to require zero approvals.
    let mut forged = eval(&o, &p, &[]);
    forged.eligible = true;
    forged.blockers.clear();
    forged.required_approvals = 0;
    assert!(!adoption_readiness(&forged, true, true, true).is_ready());
    // The genuine eligible status passes.
    let ok = eval(
        &o,
        &p,
        &[
            vote(1, &p, VoteDecision::Approve),
            vote(2, &p, VoteDecision::Approve),
        ],
    );
    assert!(adoption_readiness(&ok, true, true, true).is_ready());
}

#[test]
fn votes_from_another_circle_with_the_same_proposal_id_do_not_count() {
    // A voter who is a member of circle Y signs a vote naming our proposal id in Y.
    let (o, p) = setup();
    let y_root = sk(202);
    let y = CircleId::derive(&pk(202));
    let py = proof_by(
        &y_root,
        &sk(30),
        vec![Role::Member],
        &[S],
        now().minus_secs(60),
        now().plus_days(10),
    );
    assert!(o.add_proof(&py, now()));
    let v = VoteView::from_envelope(&sign_at(
        &sk(30),
        y,
        S,
        vote_body(&p, VoteDecision::Approve),
        now(),
    ))
    .unwrap();
    // Even in our circle's envelope it has no credential from our root.
    let v_ours = VoteView::from_envelope(&sign_at(
        &sk(30),
        circle(),
        S,
        vote_body(&p, VoteDecision::Approve),
        now(),
    ))
    .unwrap();
    let st = eval(&o, &p, &[v.clone(), v_ours.clone()]);
    assert_eq!(
        st.ignore_reason(&v.event_id()),
        Some(IgnoreReason::WrongCircle)
    );
    assert_eq!(
        st.ignore_reason(&v_ours.event_id()),
        Some(IgnoreReason::VoterNotAuthorized(DenyReason::NotMember))
    );
    assert!(st.approvers.is_empty());
}

#[test]
fn ignore_reason_prefers_the_substantive_reason_over_duplicate() {
    let (o, p) = setup();
    let sybil = vote(100, &p, VoteDecision::Approve);
    let st = eval(&o, &p, &[sybil.clone(), sybil.clone()]);
    assert_eq!(
        st.ignored,
        vec![
            (sybil.event_id(), IgnoreReason::Duplicate),
            (
                sybil.event_id(),
                IgnoreReason::VoterNotAuthorized(DenyReason::NotMember)
            ),
        ]
    );
    assert_eq!(
        st.ignore_reason(&sybil.event_id()),
        Some(IgnoreReason::VoterNotAuthorized(DenyReason::NotMember))
    );
    // A RELEASE listing it reports the real reason.
    let a = vote(2, &p, VoteDecision::Approve);
    let r = release(1, &p, vec![a.event_id(), sybil.event_id()]);
    assert_eq!(
        verify_release(
            &r,
            &p,
            &[a, sybil.clone(), sybil.clone()],
            &o,
            &CirclePolicy::default(),
            &LocalPolicy::default(),
            now()
        ),
        Err(ReleaseError::ApprovalIgnored {
            vote_id: sybil.event_id(),
            reason: IgnoreReason::VoterNotAuthorized(DenyReason::NotMember)
        })
    );
    // A counted vote replayed: only Duplicate is recorded.
    let b = vote(3, &p, VoteDecision::Approve);
    let st = eval(&o, &p, &[b.clone(), b.clone()]);
    assert_eq!(
        st.ignore_reason(&b.event_id()),
        Some(IgnoreReason::Duplicate)
    );
    assert!(st.counted_decision(&b.event_id()).is_some());
}
