//! Incoming-event authorization and read authorization (spec section 11 cases at the
//! governance layer).

mod common;

use common::*;
use ph_core::{CircleId, DenyReason, Digest, MembershipOracle, Role, Scope};
use ph_governance::{
    authorize_incoming, authorize_incoming_with_revocations, check_answer_reference,
    check_release_reference, check_supersedes_reference, check_vote_reference, filter_readable,
    may_fetch_bundle, may_read, may_read_event, recipients, recipients_for_event, ProposalView,
    Reference, Rejection,
};
use ph_protocol::{
    validate_stateless, Authorization, EventBody, MembershipBody, ProtocolError, SignedEnvelope,
    UnsignedEnvelope, UnsignedMembershipCredential, UnsignedRevocation, VoteDecision,
};
use serde_json::json;

fn authorize(
    env: &SignedEnvelope,
    oracle: &TestOracle,
) -> Result<ph_governance::AuthorizedEvent, Rejection> {
    authorize_incoming(&verified(env), oracle, &known, now())
}

fn tamper(env: &SignedEnvelope, f: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut v = env.to_value().unwrap();
    f(&mut v);
    v.to_string().into_bytes()
}

#[test]
fn genuine_question_is_authorized() {
    let o = TestOracle::new();
    enroll(&o, 1, &["team/frontend"]);
    let q = question_env(1, "team/frontend", "Should this repository use pnpm?");
    let a = authorize(&q, &o).unwrap();
    assert_eq!(a.event_id(), q.event_id);
    assert_eq!(
        a.basis(),
        Authorization::Capability(ph_core::Capability::Ask)
    );
    assert_eq!(a.circle_id(), circle());
    assert_eq!(a.into_verified().envelope(), &q);
}

#[test]
fn forged_signature_and_modified_body_never_reach_authorization() {
    let o = TestOracle::new();
    enroll(&o, 1, &["team/frontend"]);
    let q = question_env(1, "team/frontend", "Should this repository use pnpm?");

    // Modified signed body.
    let modified = tamper(&q, |v| {
        v["body"]["question"] = json!("Should this repository use npm?")
    });
    assert!(matches!(
        validate_stateless(&modified, now()),
        Err(ProtocolError::BadSignature { .. })
    ));
    // Modified scope (escalation attempt).
    let rescoped = tamper(&q, |v| v["scope"] = json!("team/finance"));
    assert!(matches!(
        validate_stateless(&rescoped, now()),
        Err(ProtocolError::BadSignature { .. })
    ));
    // Forged signature: signed by a different key but claiming the member as author.
    let forged = UnsignedEnvelope {
        author: pk(99),
        ..q.envelope.clone()
    }
    .sign(&sk(99))
    .unwrap();
    let forged_raw = tamper(&q, |v| v["signature"] = json!(forged.signature.to_string()));
    assert!(matches!(
        validate_stateless(&forged_raw, now()),
        Err(ProtocolError::BadSignature { .. })
    ));
    // The genuine event still passes both stages.
    let v = validate_stateless(&raw(&q), now()).unwrap();
    assert!(authorize_incoming(&v, &o, &known, now()).is_ok());
}

#[test]
fn expired_credential_is_rejected() {
    let o = TestOracle::new();
    let p = proof_by(
        &root(),
        &sk(1),
        vec![Role::Member],
        &["team/frontend"],
        now().minus_secs(40 * 86_400),
        now().minus_secs(86_400),
    );
    assert!(o.add_proof(&p, now().minus_secs(2 * 86_400)));
    let q = question_env(1, "team/frontend", "Use pnpm?");
    assert_eq!(
        authorize(&q, &o).unwrap_err(),
        Rejection::Denied(DenyReason::Expired)
    );
    // A MEMBERSHIP event carrying the credential, signed while it was still valid,
    // fails stateless validation now, and authorization when re-checked now.
    let then = now().minus_secs(2 * 86_400);
    let m = ph_protocol::EnvelopeBuilder::new(
        circle(),
        Scope::all(),
        EventBody::Membership(MembershipBody {
            credential: p.credential.clone(),
            acceptance: p.acceptance.clone(),
        }),
    )
    .created_at(then)
    .sign(&sk(1), then)
    .unwrap();
    assert!(validate_stateless(&raw(&m), now()).is_err());
    let v = validate_stateless(&raw(&m), then).unwrap();
    assert!(authorize_incoming(&v, &o, &known, then).is_ok());
    assert!(authorize_incoming(&v, &o, &known, now()).is_err());
}

#[test]
fn revoked_credential_is_rejected() {
    let o = TestOracle::new();
    let p = enroll(&o, 1, &["team/frontend"]);
    let q = question_env(1, "team/frontend", "Use pnpm?");
    assert!(authorize(&q, &o).is_ok());
    assert!(o.revoke(&revocation_of(1, now()), now()));
    assert_eq!(
        authorize(&q, &o).unwrap_err(),
        Rejection::Denied(DenyReason::Revoked)
    );
    // A revoked subject re-publishing its MEMBERSHIP is rejected too, both with the
    // oracle probe and with an explicit revocation predicate.
    let m = membership_env(1, &p, "*");
    assert_eq!(
        authorize(&m, &o).unwrap_err(),
        Rejection::Denied(DenyReason::Revoked)
    );
    let revoked = |c: &CircleId, k: &ph_core::DeviceKey| o.is_revoked(c, k);
    assert_eq!(
        authorize_incoming_with_revocations(&verified(&m), &o, &known, &revoked, now())
            .unwrap_err(),
        Rejection::Denied(DenyReason::Revoked)
    );
    // Revoked members also lose read access.
    assert!(!may_read(
        &o,
        &circle(),
        &pk(1),
        &scope("team/frontend"),
        now()
    ));
    assert!(!o.is_active_member(&circle(), &pk(1), now()));
}

#[test]
fn unaccepted_credential_is_rejected() {
    let o = TestOracle::new();
    let p = member_proof(1, &["team/frontend"]);
    assert!(o.add_unaccepted(&p.credential));
    let q = question_env(1, "team/frontend", "Use pnpm?");
    assert_eq!(
        authorize(&q, &o).unwrap_err(),
        Rejection::Denied(DenyReason::NotAccepted)
    );
}

#[test]
fn frontend_member_cannot_post_or_read_finance() {
    let o = TestOracle::new();
    enroll(&o, 1, &["team/frontend"]);
    enroll(&o, 2, &["team/finance"]);
    let fin = question_env(1, "team/finance", "What is the budget?");
    assert_eq!(
        authorize(&fin, &o).unwrap_err(),
        Rejection::Denied(DenyReason::ScopeDenied)
    );
    // A sub-scope of the grant is fine; a sibling prefix is not.
    assert!(authorize(&question_env(1, "team/frontend/web", "q?"), &o).is_ok());
    assert!(authorize(&question_env(1, "team/frontend-legacy", "q?"), &o).is_err());
    assert!(authorize(&question_env(1, "team", "q?"), &o).is_err());

    // Read side.
    assert!(!may_read(
        &o,
        &circle(),
        &pk(1),
        &scope("team/finance"),
        now()
    ));
    assert!(may_read(
        &o,
        &circle(),
        &pk(1),
        &scope("team/frontend"),
        now()
    ));
    let fin_by_2 = question_env(2, "team/finance", "What is the budget?");
    assert!(authorize(&fin_by_2, &o).is_ok());
    assert!(!may_read_event(&o, &fin_by_2, &pk(1), now()));
    assert_eq!(
        recipients_for_event(&fin_by_2, &[pk(1), pk(2), pk(3)], &o, now()),
        vec![pk(2)]
    );
    let front = question_env(1, "team/frontend", "Use pnpm?");
    let events = [fin_by_2.clone(), front.clone()];
    let visible = filter_readable(&events, &circle(), &pk(1), &o, now());
    assert_eq!(visible, vec![&front]);
    let visible2 = filter_readable(&events, &circle(), &pk(2), &o, now());
    assert_eq!(visible2, vec![&fin_by_2]);
    // An outsider sees nothing.
    assert!(filter_readable(&events, &circle(), &pk(50), &o, now()).is_empty());
}

#[test]
fn recipients_dedup_and_control_plane_reach_all_members() {
    let o = TestOracle::new();
    let p1 = enroll(&o, 1, &["team/frontend"]);
    enroll(&o, 2, &["team/finance"]);
    enroll(&o, 3, &["*"]);
    enroll(&o, 4, &["team/frontend"]);
    o.revoke(&revocation_of(4, now()), now());
    let cands = [pk(3), pk(1), pk(2), pk(1), pk(4), pk(50)];
    assert_eq!(
        recipients(&scope("team/frontend"), &circle(), &cands, &o, now()),
        vec![pk(3), pk(1)]
    );
    // MEMBERSHIP / REVOCATION are readable by every active member regardless of scope.
    let m = membership_env(1, &p1, "*");
    assert_eq!(
        recipients_for_event(&m, &cands, &o, now()),
        vec![pk(3), pk(1), pk(2)]
    );
    let r = revocation_env(&root(), &revocation_of(4, now()));
    assert_eq!(
        recipients_for_event(&r, &cands, &o, now()),
        vec![pk(3), pk(1), pk(2)]
    );
    // Control-plane events of the circle are returned to any active member on fetch.
    let events = [m.clone(), r.clone()];
    assert_eq!(
        filter_readable(&events, &circle(), &pk(2), &o, now()).len(),
        2
    );
    assert!(filter_readable(&events, &circle(), &pk(4), &o, now()).is_empty());
    assert!(filter_readable(&events, &CircleId::derive(&pk(9)), &pk(2), &o, now()).is_empty());
}

#[test]
fn bundle_fetch_requires_readable_proposal() {
    let o = TestOracle::new();
    enroll(&o, 1, &["team/frontend"]);
    enroll(&o, 2, &["team/finance"]);
    let d = digest(b"A");
    let p = proposal(1, "team/frontend", d);
    let ps = [p];
    assert!(may_fetch_bundle(&circle(), &d, &ps, &pk(1), &o, now()));
    assert!(!may_fetch_bundle(&circle(), &d, &ps, &pk(2), &o, now()));
    assert!(!may_fetch_bundle(
        &circle(),
        &digest(b"B"),
        &ps,
        &pk(1),
        &o,
        now()
    ));
    assert!(!may_fetch_bundle(
        &CircleId::derive(&pk(9)),
        &d,
        &ps,
        &pk(1),
        &o,
        now()
    ));
    assert!(!may_fetch_bundle(&circle(), &d, &ps, &pk(50), &o, now()));
}

#[test]
fn unknown_circle_is_rejected() {
    let o = TestOracle::new();
    enroll(&o, 1, &["*"]);
    let q = question_env(1, "team", "q?");
    let none = |_: &CircleId| false;
    assert_eq!(
        authorize_incoming(&verified(&q), &o, &none, now()).unwrap_err(),
        Rejection::UnknownCircle
    );
}

#[test]
fn outsider_and_capability_checks() {
    let o = TestOracle::new();
    // Outsider with no credential at all.
    let q = question_env(50, "team", "q?");
    assert_eq!(
        authorize(&q, &o).unwrap_err(),
        Rejection::Denied(DenyReason::NotMember)
    );
    // A member cannot author a REVOCATION (needs the root key), see below; and cannot
    // pretend to be the root by authoring with its own key.
    enroll(&o, 1, &["*"]);
    let own_rev = UnsignedRevocation::new(
        pk(1),
        pk(2),
        now(),
        "".into(),
        ph_core::Nonce::from_bytes([3; 16]),
    )
    .sign(&sk(1))
    .unwrap();
    let env = revocation_env(&sk(1), &own_rev);
    // Its circle is derive(member key): unknown here, and not the root of our circle.
    assert_eq!(authorize(&env, &o).unwrap_err(), Rejection::UnknownCircle);
    let any = |_: &CircleId| true;
    // Even when every circle is "known", the author is the root of *its own* circle only,
    // so it cannot touch ours; and a revocation in our circle needs the root's signature.
    assert!(authorize_incoming(&verified(&env), &o, &any, now()).is_ok());
    assert_ne!(env.circle_id, circle());
}

#[test]
fn revocation_by_root_is_authorized_without_oracle() {
    let o = TestOracle::new(); // the root holds no credential
    let rev = revocation_of(1, now());
    let env = revocation_env(&root(), &rev);
    let a = authorize(&env, &o).unwrap();
    assert_eq!(a.basis(), Authorization::CircleRoot);
    // A member relaying the root's revocation as author fails stateless binding checks.
    let relayed = ph_protocol::EnvelopeBuilder::new(
        circle(),
        Scope::all(),
        EventBody::Revocation(ph_protocol::RevocationBody { revocation: rev }),
    )
    .sign(&sk(1), now());
    assert!(relayed.is_err());
}

#[test]
fn membership_event_rules() {
    let o = TestOracle::new();
    let p = member_proof(1, &["team/frontend"]);
    // The subject publishing its own MEMBERSHIP with "*" or a covered scope is fine,
    // even before the oracle knows it.
    for s in ["*", "team/frontend", "team/frontend/web"] {
        let a = authorize(&membership_env(1, &p, s), &o).unwrap();
        assert_eq!(a.basis(), Authorization::EmbeddedCredential);
    }
    // A scope outside the credential is refused.
    assert_eq!(
        authorize(&membership_env(1, &p, "team/finance"), &o).unwrap_err(),
        Rejection::ScopeNotCovered
    );
    // Another device cannot publish someone else's MEMBERSHIP (binding check).
    let stolen = ph_protocol::EnvelopeBuilder::new(
        circle(),
        Scope::all(),
        EventBody::Membership(MembershipBody {
            credential: p.credential.clone(),
            acceptance: p.acceptance.clone(),
        }),
    )
    .sign(&sk(7), now());
    assert!(stolen.is_err());
    // Re-checked at a later time when the credential has expired.
    let m = verified(&membership_env(1, &p, "*"));
    let later = now().plus_days(40);
    assert!(authorize_incoming(&m, &o, &known, later).is_err());
}

#[test]
fn self_issued_membership_cannot_join_a_circle() {
    // A Sybil key issues itself a credential. Its circle is derive(sybil key), so it can
    // never be bound to our circle.
    let o = TestOracle::new();
    let fake = proof_by(
        &sk(100),
        &sk(100),
        vec![Role::Owner],
        &["*"],
        now().minus_secs(60),
        now().plus_days(10),
    );
    assert_ne!(fake.credential.circle_id, circle());
    let env = membership_env(100, &fake, "*");
    assert_eq!(authorize(&env, &o).unwrap_err(), Rejection::UnknownCircle);
    // Forcing our circle id into the credential makes it unsignable / unverifiable.
    let mut u = UnsignedMembershipCredential::new(
        pk(100),
        pk(100),
        vec![Role::Owner],
        vec![Scope::all()],
        now(),
        now().plus_days(10),
    );
    u.circle_id = circle();
    assert!(u.sign(&sk(100)).is_err());
}

#[test]
fn expired_event_is_rejected_on_late_authorization() {
    let o = TestOracle::new();
    enroll(&o, 1, &["*"]);
    let q = verified(&question_env(1, "team", "q?"));
    assert_eq!(
        authorize_incoming(&q, &o, &known, now().plus_days(31)).unwrap_err(),
        Rejection::Expired
    );
}

#[test]
fn release_without_approvals_is_rejected() {
    let o = TestOracle::new();
    enroll(&o, 1, &["*"]);
    let p = proposal(1, "team", digest(b"A"));
    let r = release_env(1, &p, vec![]);
    assert_eq!(authorize(&r, &o).unwrap_err(), Rejection::BadReference);
}

#[test]
fn reference_helpers() {
    let o = TestOracle::new();
    enroll(&o, 1, &["*"]);
    enroll(&o, 2, &["*"]);
    let q = question_env(1, "team/frontend", "Use pnpm?");
    let ans = answer_env(2, "team/frontend", q.event_id);
    assert!(authorize(&ans, &o).is_ok());
    assert_eq!(check_answer_reference(&ans, Some(&q)), Reference::Resolved);
    assert!(check_answer_reference(&ans, Some(&q)).is_resolved());
    assert_eq!(check_answer_reference(&ans, None), Reference::Missing);
    let other_scope = answer_env(2, "team/backend", q.event_id);
    assert_eq!(
        check_answer_reference(&other_scope, Some(&q)),
        Reference::Invalid(Rejection::BadReference)
    );
    let wrong_target = answer_env(
        2,
        "team/frontend",
        ph_core::EventId::from_digest(digest(b"x")),
    );
    assert!(matches!(
        check_answer_reference(&wrong_target, Some(&q)),
        Reference::Invalid(_)
    ));
    // An answer whose "question" is a proposal.
    let p_env = proposal_env(
        1,
        "team/frontend",
        "pnpm-repository-convention",
        digest(b"A"),
    );
    let ans_p = answer_env(2, "team/frontend", p_env.event_id);
    assert!(matches!(
        check_answer_reference(&ans_p, Some(&p_env)),
        Reference::Invalid(_)
    ));

    let p = ProposalView::from_envelope(&p_env).unwrap();
    let v = vote_env_for(2, &p, VoteDecision::Approve, now());
    assert_eq!(check_vote_reference(&v, Some(&p_env)), Reference::Resolved);
    assert_eq!(check_vote_reference(&v, None), Reference::Missing);
    let p2_env = proposal_env(
        1,
        "team/frontend",
        "pnpm-repository-convention",
        digest(b"B"),
    );
    assert!(matches!(
        check_vote_reference(&v, Some(&p2_env)),
        Reference::Invalid(_)
    ));
    assert!(matches!(
        check_vote_reference(&q, Some(&p_env)),
        Reference::Invalid(_)
    ));

    let r = release_env(1, &p, vec![v.event_id]);
    assert_eq!(
        check_release_reference(&r, Some(&p_env)),
        Reference::Resolved
    );
    assert!(matches!(
        check_release_reference(&r, Some(&p2_env)),
        Reference::Invalid(_)
    ));
    assert_eq!(check_release_reference(&r, None), Reference::Missing);

    // supersedes
    assert_eq!(
        check_supersedes_reference(&p_env, None),
        Reference::Resolved
    );
    let mut body = proposal_body("pnpm-repository-convention", digest(b"B"));
    body.supersedes = Some(p_env.event_id);
    let newer = sign_at(
        &sk(1),
        circle(),
        "team/frontend",
        EventBody::Proposal(body.clone()),
        now(),
    );
    assert_eq!(
        check_supersedes_reference(&newer, Some(&p_env)),
        Reference::Resolved
    );
    assert_eq!(check_supersedes_reference(&newer, None), Reference::Missing);
    body.skill_name = "other-skill".into();
    let renamed = sign_at(
        &sk(1),
        circle(),
        "team/frontend",
        EventBody::Proposal(body),
        now(),
    );
    assert!(matches!(
        check_supersedes_reference(&renamed, Some(&p_env)),
        Reference::Invalid(_)
    ));
}

#[test]
fn rejection_display_is_generic() {
    let o = TestOracle::new();
    let q = question_env(50, "team", "SECRET question text");
    let e = authorize(&q, &o).unwrap_err();
    assert_eq!(e.to_string(), "event rejected");
    assert_eq!(e.code(), "not_member");
    assert!(!format!("{e:?}").contains("SECRET"));
    let _ = Digest::sha256(b"");
}
