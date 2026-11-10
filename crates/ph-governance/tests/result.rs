//! RESULT certificates: a list of ballots to check, never an authority (architecture
//! section 10.6).

mod common;

use common::*;
use ph_core::DeviceKey;
use ph_governance::{verify_result, IgnoreReason, ResultError, VoteView};
use ph_protocol::VoteDecision::*;

#[test]
fn a_certificate_with_enough_approvals_verifies() {
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    let votes = [approve(1, &p), approve(2, &p)];
    // Any member of the electorate may assemble it, including one who dissented.
    for assembler in [1u8, 2, 3] {
        let r = result_of(assembler, &p, &votes);
        let t = verify_result(&r, &p, &c, &votes, &nobody_revoked).unwrap();
        assert!(t.passed());
        assert_eq!(t.approvals().len(), 2);
    }
}

#[test]
fn it_verifies_at_any_later_time_and_with_any_other_ballots_around() {
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    let a = approve(1, &p);
    let b = approve(2, &p);
    let r = result_of(2, &p, &[a.clone(), b.clone()]);
    // Later ballots, including the approvers changing their minds or approving again,
    // do not affect a certificate: only the ballots it lists are counted.
    let later: Vec<VoteView> = vec![
        a.clone(),
        b.clone(),
        vote_at(2, &p, Reject, now().plus_days(400)),
        vote_at(1, &p, Approve, now().plus_days(800)),
        vote(3, &p, Reject),
    ];
    assert!(verify_result(&r, &p, &c, &later, &nobody_revoked).is_ok());
    // verify_result takes no clock at all, so there is nothing that could expire.
}

#[test]
fn approving_twice_does_not_break_an_existing_result() {
    // Regression for the old RELEASE design, where a second approval from the same
    // member replaced the first and invalidated every release that listed it.
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    let a = approve(1, &p);
    let b1 = approve(2, &p);
    let r = result_of(1, &p, &[a.clone(), b1.clone()]);
    let b2 = vote_at(2, &p, Approve, now());
    let all = [a, b1, b2];
    assert!(verify_result(&r, &p, &c, &all, &nobody_revoked).is_ok());
}

#[test]
fn a_missing_ballot_is_retryable_not_a_verdict() {
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    let a = approve(1, &p);
    let b = approve(2, &p);
    let r = result_of(1, &p, &[a.clone(), b.clone()]);
    let err = verify_result(&r, &p, &c, &[a], &nobody_revoked).unwrap_err();
    assert_eq!(err, ResultError::MissingBallot(b.event_id()));
    assert!(err.is_retryable());
}

#[test]
fn too_few_approvals_is_refused() {
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    let a = approve(1, &p);
    let r = result_of(1, &p, std::slice::from_ref(&a));
    let err = verify_result(&r, &p, &c, &[a], &nobody_revoked).unwrap_err();
    assert_eq!(err, ResultError::BelowThreshold { have: 1, need: 2 });
    assert!(!err.is_retryable());
}

#[test]
fn a_certificate_cannot_be_padded() {
    let c = founding(vec![
        entry("alice", &[1, 11], &["*"]),
        entry("bob", &[2], &["*"]),
        entry("carol", &[3], &["*"]),
    ]);
    let p = adopt(1, &c, "*", digest(b"b"));

    // Two ballots from two devices of the same member are one approval.
    let votes = [approve(1, &p), approve(11, &p)];
    let err =
        verify_result(&result_of(1, &p, &votes), &p, &c, &votes, &nobody_revoked).unwrap_err();
    assert!(matches!(
        err,
        ResultError::BallotNotCounted {
            reason: IgnoreReason::Redundant,
            ..
        }
    ));

    // A dissenting ballot is not an approval.
    let votes = [approve(1, &p), vote(2, &p, Reject)];
    let err =
        verify_result(&result_of(1, &p, &votes), &p, &c, &votes, &nobody_revoked).unwrap_err();
    assert_eq!(err, ResultError::NotAnApproval(votes[1].event_id()));

    // A ballot from a key that is not on the roll is not counted.
    let votes = [approve(1, &p), approve(99, &p)];
    let err =
        verify_result(&result_of(1, &p, &votes), &p, &c, &votes, &nobody_revoked).unwrap_err();
    assert_eq!(
        err,
        ResultError::BallotNotCounted {
            vote_id: votes[1].event_id(),
            reason: IgnoreReason::NotOnRoll
        }
    );

    // Approvals of another proposal cannot be borrowed, even one with the same bundle.
    let twin = adopt(2, &c, "*", digest(b"b"));
    let borrowed = [approve(1, &p), approve(2, &twin)];
    let err = verify_result(
        &result_of(1, &p, &borrowed),
        &p,
        &c,
        &borrowed,
        &nobody_revoked,
    )
    .unwrap_err();
    assert_eq!(
        err,
        ResultError::BallotNotCounted {
            vote_id: borrowed[1].event_id(),
            reason: IgnoreReason::WrongProposal
        }
    );
}

#[test]
fn a_result_for_another_proposal_or_from_an_outsider_is_refused() {
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    let other = adopt(1, &c, "*", digest(b"other"));
    let votes = [approve(1, &p), approve(2, &p)];
    // The result names `other`.
    let r = result_of(1, &other, &votes);
    assert_eq!(
        verify_result(&r, &p, &c, &votes, &nobody_revoked),
        Err(ResultError::WrongProposal)
    );
    // Assembled by a key that is not a member.
    let r = result_of(99, &p, &votes);
    assert_eq!(
        verify_result(&r, &p, &c, &votes, &nobody_revoked),
        Err(ResultError::AssemblerNotInElectorate)
    );
    // The wrong charter.
    let other_charter = founding(vec![entry("alice", &[1], &["*"])]);
    assert_eq!(
        verify_result(
            &result_of(1, &p, &votes),
            &p,
            &other_charter,
            &votes,
            &nobody_revoked
        ),
        Err(ResultError::WrongCharter)
    );
}

#[test]
fn a_revoked_device_does_not_count_toward_a_new_certificate() {
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    let votes = [approve(1, &p), approve(2, &p)];
    let r = result_of(1, &p, &votes);
    let bob = pk(2);
    let revoked = move |d: &DeviceKey| *d == bob;
    assert_eq!(
        verify_result(&r, &p, &c, &votes, &revoked),
        Err(ResultError::BallotNotCounted {
            vote_id: votes[1].event_id(),
            reason: IgnoreReason::Revoked
        })
    );
    // With carol's approval instead, the proposal still passes.
    let votes = [votes[0].clone(), approve(3, &p)];
    assert!(verify_result(&result_of(1, &p, &votes), &p, &c, &votes, &revoked).is_ok());
}

#[test]
fn error_text_is_generic_and_codes_are_distinct() {
    let id = adopt(1, &abc(), "*", digest(b"b")).event_id();
    let all = [
        ResultError::WrongProposal,
        ResultError::AssemblerNotInElectorate,
        ResultError::MissingBallot(id),
        ResultError::BallotNotCounted {
            vote_id: id,
            reason: IgnoreReason::NotOnRoll,
        },
        ResultError::NotAnApproval(id),
        ResultError::BelowThreshold { have: 1, need: 2 },
        ResultError::WrongCharter,
    ];
    let codes: std::collections::HashSet<_> = all.iter().map(|e| e.code()).collect();
    assert_eq!(codes.len(), all.len());
    for e in all {
        assert!(!e.to_string().contains("sha256:"), "{e}");
    }
}
