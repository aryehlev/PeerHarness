//! Incoming-event authorization and read authorization (spec section 11 cases at the
//! governance layer).

mod common;

use common::*;
use ph_core::{CircleId, DenyReason, Digest, MembershipOracle, Role, Scope};
use ph_governance::{
    authorize_incoming, check_answer_reference, check_repeal_reference, check_supersedes_reference,
    filter_readable, may_fetch_bundle, may_read, may_read_event, recipients, recipients_for_event,
    DecisionRecords, NoRecords, Reference, Rejection,
};
use ph_protocol::{
    validate_stateless, Authorization, EventBody, MembershipBody, ProposalAction, ProtocolError,
    SignedEnvelope, UnsignedEnvelope, UnsignedMembershipCredential, UnsignedRevocation,
    VoteDecision,
};
use serde_json::json;

fn authorize(
    env: &SignedEnvelope,
    oracle: &TestOracle,
) -> Result<ph_governance::AuthorizedEvent, Rejection> {
    authorize_incoming(&verified(env), oracle, &NoRecords, &known, now())
}

/// Authorizes a decision event against `records`.
fn decide(
    env: &SignedEnvelope,
    oracle: &TestOracle,
    records: &dyn DecisionRecords,
) -> Result<ph_governance::AuthorizedEvent, Rejection> {
    authorize_incoming(&verified(env), oracle, records, &known, now())
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
    assert!(authorize_incoming(&v, &o, &NoRecords, &known, now()).is_ok());
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
    assert!(authorize_incoming(&v, &o, &NoRecords, &known, then).is_ok());
    assert!(authorize_incoming(&v, &o, &NoRecords, &known, now()).is_err());
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
    // A revoked subject re-publishing its MEMBERSHIP is rejected too.
    let m = membership_env(1, &p, "*");
    assert_eq!(
        authorize(&m, &o).unwrap_err(),
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

/// An oracle that knows revocations but no credentials, and whose `authorize` reports
/// `NotMember` before checking revocations: governance must still refuse a revoked
/// subject's MEMBERSHIP via `is_revoked`, not via the order of `authorize` checks.
struct RevocationsOnly(std::collections::HashSet<(CircleId, ph_core::DeviceKey)>);

impl MembershipOracle for RevocationsOnly {
    fn authorize(
        &self,
        _: &CircleId,
        _: &ph_core::DeviceKey,
        _: &Scope,
        _: ph_core::Capability,
        _: ph_core::Timestamp,
    ) -> Result<(), DenyReason> {
        Err(DenyReason::NotMember)
    }
    fn is_active_member(
        &self,
        _: &CircleId,
        _: &ph_core::DeviceKey,
        _: ph_core::Timestamp,
    ) -> bool {
        false
    }
    fn is_revoked(&self, circle: &CircleId, key: &ph_core::DeviceKey) -> bool {
        self.0.contains(&(*circle, *key))
    }
}

#[test]
fn membership_of_subject_revoked_before_its_credential_was_seen_is_rejected() {
    let p = member_proof(1, &["team/frontend"]);
    let m = verified(&membership_env(1, &p, "*"));
    let clean = RevocationsOnly(Default::default());
    assert!(authorize_incoming(&m, &clean, &NoRecords, &known, now()).is_ok());
    let revoked = RevocationsOnly([(circle(), pk(1))].into_iter().collect());
    assert_eq!(
        authorize_incoming(&m, &revoked, &NoRecords, &known, now()).unwrap_err(),
        Rejection::Denied(DenyReason::Revoked)
    );
    // Another subject is unaffected.
    let p2 = member_proof(2, &["team/frontend"]);
    assert!(authorize_incoming(
        &verified(&membership_env(2, &p2, "*")),
        &revoked,
        &NoRecords,
        &known,
        now()
    )
    .is_ok());
    // The same holds with the TestOracle that has never seen the credential.
    let o = TestOracle::new();
    assert!(o.revoke(&revocation_of(1, now()), now()));
    assert_eq!(
        authorize_incoming(&m, &o, &NoRecords, &known, now()).unwrap_err(),
        Rejection::Denied(DenyReason::Revoked)
    );
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
    let charter = founding(vec![entry("alice", &[1], &["team/frontend"])]);
    let p = adopt(1, &charter, "team/frontend", d);
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
        authorize_incoming(&verified(&q), &o, &NoRecords, &none, now()).unwrap_err(),
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
    assert!(authorize_incoming(&verified(&env), &o, &NoRecords, &any, now()).is_ok());
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
    assert!(authorize_incoming(&m, &o, &NoRecords, &known, later).is_err());
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
        authorize_incoming(&q, &o, &NoRecords, &known, now().plus_days(31)).unwrap_err(),
        Rejection::Expired
    );
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
    let c = abc();
    let p = adopt(1, &c, "team/frontend", digest(b"A"));
    let p_env = p.envelope().clone();
    let ans_p = answer_env(2, "team/frontend", p_env.event_id);
    assert!(matches!(
        check_answer_reference(&ans_p, Some(&p_env)),
        Reference::Invalid(_)
    ));

    // supersedes: lineage between adopt proposals of the same skill
    assert_eq!(
        check_supersedes_reference(&p_env, None),
        Reference::Resolved
    );
    let revised = |skill: &str| {
        let mut body = adopt_body(&c, skill, digest(b"B"));
        if let ProposalAction::Adopt(a) = &mut body.action {
            a.supersedes = Some(p_env.event_id);
        }
        sign_at(
            &sk(1),
            circle(),
            "team/frontend",
            EventBody::Proposal(body),
            now(),
        )
    };
    let newer = revised(SKILL);
    assert_eq!(
        check_supersedes_reference(&newer, Some(&p_env)),
        Reference::Resolved
    );
    assert_eq!(check_supersedes_reference(&newer, None), Reference::Missing);
    assert!(matches!(
        check_supersedes_reference(&revised("other-skill"), Some(&p_env)),
        Reference::Invalid(_)
    ));
    assert!(matches!(
        check_supersedes_reference(&newer, Some(&q)),
        Reference::Invalid(_)
    ));

    // repeal: the target is an adopt proposal in the same circle and scope
    let r = repeal(2, &c, &p);
    assert_eq!(
        check_repeal_reference(r.envelope(), Some(&p_env)),
        Reference::Resolved
    );
    assert_eq!(
        check_repeal_reference(r.envelope(), None),
        Reference::Missing
    );
    // a repeal cannot target another repeal, a question, or a rule in another scope
    assert!(matches!(
        check_repeal_reference(r.envelope(), Some(r.envelope())),
        Reference::Invalid(_)
    ));
    assert!(matches!(
        check_repeal_reference(r.envelope(), Some(&q)),
        Reference::Invalid(_)
    ));
    let elsewhere = adopt(1, &c, "team/backend", digest(b"A"));
    let cross_scope = sign_at(
        &sk(2),
        circle(),
        "team/frontend",
        EventBody::Proposal(ph_protocol::ProposalBody {
            charter: c.digest().unwrap(),
            title: "t".into(),
            summary: String::new(),
            action: ProposalAction::Repeal {
                target: elsewhere.event_id(),
            },
        }),
        now(),
    );
    assert!(matches!(
        check_repeal_reference(&cross_scope, Some(elsewhere.envelope())),
        Reference::Invalid(_)
    ));
    // proposals of another kind have no repeal target to check
    assert_eq!(check_repeal_reference(&p_env, None), Reference::Resolved);
}

// ---------------------------------------------------------------------------------------
// Decision events are authorized by the roll, not by credentials
// ---------------------------------------------------------------------------------------

#[test]
fn a_member_on_the_roll_may_propose_vote_and_publish_a_result() {
    // Nobody holds a credential here at all: the roll alone decides.
    let o = TestOracle::new();
    let c = abc();
    let mut records = TestRecords::new().with_charter(&c);
    let p = adopt(1, &c, "*", digest(b"b"));
    let a = decide(p.envelope(), &o, &records).unwrap();
    assert_eq!(a.basis(), Authorization::Roll);
    records.add_proposal(&p);
    let v1 = vote_env_for(1, &p, VoteDecision::Approve, now());
    let v2 = vote_env_for(2, &p, VoteDecision::Reject, now());
    assert!(decide(&v1, &o, &records).is_ok());
    assert!(
        decide(&v2, &o, &records).is_ok(),
        "dissent is a valid ballot"
    );
    let r = result_env(3, &p, vec![v1.event_id]);
    assert!(decide(&r, &o, &records).is_ok());
}

#[test]
fn a_valid_credential_does_not_make_a_voter() {
    // Mallory holds a genuine, root-issued, wildcard credential, but is not on the roll.
    let o = TestOracle::new();
    enroll(&o, 66, &["*"]);
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    let records = TestRecords::new().with_charter(&c).with_proposal(&p);
    let q = question_env(66, "team", "may I ask?");
    assert!(
        authorize(&q, &o).is_ok(),
        "the credential is good for questions"
    );

    let forged_proposal = adopt(66, &c, "*", digest(b"evil"));
    assert_eq!(
        decide(forged_proposal.envelope(), &o, &records).unwrap_err(),
        Rejection::NotOnRoll
    );
    let ballot = vote_env_for(66, &p, VoteDecision::Approve, now());
    assert_eq!(
        decide(&ballot, &o, &records).unwrap_err(),
        Rejection::NotOnRoll
    );
    let res = result_env(66, &p, vec![ballot.event_id]);
    assert_eq!(
        decide(&res, &o, &records).unwrap_err(),
        Rejection::NotOnRoll
    );
    // The circle root key is a notary, not a member.
    let root_ballot = vote_env_for(ROOT, &p, VoteDecision::Approve, now());
    assert_eq!(
        decide(&root_ballot, &o, &records).unwrap_err(),
        Rejection::NotOnRoll
    );
}

#[test]
fn members_outside_the_electorate_cannot_propose_or_vote_there() {
    let o = TestOracle::new();
    let c = founding(vec![
        entry("alice", &[1], &["*"]),
        entry("bob", &[2], &["team/backend"]),
        entry("carol", &[3], &["team/frontend"]),
    ]);
    let p = adopt(2, &c, "team/backend", digest(b"b"));
    let records = TestRecords::new().with_charter(&c).with_proposal(&p);
    assert!(decide(p.envelope(), &o, &records).is_ok());
    assert!(decide(
        &vote_env_for(1, &p, VoteDecision::Approve, now()),
        &o,
        &records
    )
    .is_ok());
    assert_eq!(
        decide(
            &vote_env_for(3, &p, VoteDecision::Approve, now()),
            &o,
            &records
        )
        .unwrap_err(),
        Rejection::NotInElectorate
    );
    // Carol cannot propose a backend rule either.
    let hers = adopt(3, &c, "team/backend", digest(b"c"));
    assert_eq!(
        decide(hers.envelope(), &o, &records).unwrap_err(),
        Rejection::NotInElectorate
    );
    // But every member may propose and vote on the charter and on circle-wide rules.
    let mut next = c.content.clone();
    next.roll.push(entry("dave", &[4], &["*"]));
    next.normalize();
    let am = amend(3, &c, next);
    let records = records.with_proposal(&am);
    assert!(decide(am.envelope(), &o, &records).is_ok());
    assert!(decide(
        &vote_env_for(2, &am, VoteDecision::Approve, now()),
        &o,
        &records
    )
    .is_ok());
    let wide = adopt(3, &c, "*", digest(b"w"));
    assert!(decide(wide.envelope(), &o, &records).is_ok());
}

#[test]
fn missing_records_are_retryable_not_fatal() {
    let o = TestOracle::new();
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    // The charter has not arrived yet.
    let e = decide(p.envelope(), &o, &NoRecords).unwrap_err();
    assert_eq!(e, Rejection::UnknownCharter);
    assert!(e.is_retryable());
    // The proposal a ballot names has not arrived yet.
    let records = TestRecords::new().with_charter(&c);
    let v = vote_env_for(2, &p, VoteDecision::Approve, now());
    let e = decide(&v, &o, &records).unwrap_err();
    assert_eq!(e, Rejection::MissingProposal);
    assert!(e.is_retryable());
    // Once both are known the same events are accepted.
    let records = records.with_proposal(&p);
    assert!(decide(p.envelope(), &o, &records).is_ok());
    assert!(decide(&v, &o, &records).is_ok());
    // Being a non-member is not retryable.
    assert!(!Rejection::NotOnRoll.is_retryable());
}

#[test]
fn a_ballot_must_match_its_proposals_circle_and_scope() {
    let o = TestOracle::new();
    let c = abc();
    let p = adopt(1, &c, "team/backend", digest(b"b"));
    let records = TestRecords::new().with_charter(&c).with_proposal(&p);
    let wrong_scope = sign_at(
        &sk(2),
        circle(),
        "team/frontend",
        EventBody::Vote(ph_protocol::VoteBody {
            proposal_id: p.event_id(),
            decision: VoteDecision::Approve,
            rationale: None,
        }),
        now(),
    );
    assert_eq!(
        decide(&wrong_scope, &o, &records).unwrap_err(),
        Rejection::BadReference
    );
}

#[test]
fn a_revoked_device_cannot_add_ballots() {
    let o = TestOracle::new();
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    let records = TestRecords::new().with_charter(&c).with_proposal(&p);
    let v = vote_env_for(2, &p, VoteDecision::Approve, now());
    assert!(decide(&v, &o, &records).is_ok());
    assert!(o.revoke(&revocation_of(2, now()), now()));
    assert_eq!(
        decide(&v, &o, &records).unwrap_err(),
        Rejection::Denied(DenyReason::Revoked)
    );
    let again = adopt(2, &c, "*", digest(b"c"));
    assert_eq!(
        decide(again.envelope(), &o, &records).unwrap_err(),
        Rejection::Denied(DenyReason::Revoked)
    );
}

#[test]
fn decision_events_are_accepted_long_after_they_were_signed() {
    // A node that joins in ten years can still replay the circle's history: decision
    // events are authorized by the roll and never expire.
    let o = TestOracle::new();
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    let records = TestRecords::new().with_charter(&c).with_proposal(&p);
    let later = now().plus_days(3650);
    for env in [
        p.envelope().clone(),
        vote_env_for(2, &p, VoteDecision::Approve, now()),
    ] {
        let v = validate_stateless(&raw(&env), later).unwrap();
        assert!(authorize_incoming(&v, &o, &records, &known, later).is_ok());
    }
    // A question, by contrast, has expired by then.
    enroll(&o, 1, &["*"]);
    let q = question_env(1, "team", "q?");
    assert!(validate_stateless(&raw(&q), later).is_err());
}

#[test]
fn a_charter_event_is_authentic_only_from_the_circle_root() {
    let o = TestOracle::new();
    let c1 = abc();
    let c2 = successor(
        &c1,
        c1.content.clone(),
        adopt(1, &c1, "*", digest(b"x")).event_id(),
    );
    let env = charter_env(&root(), &c2);
    let a = authorize(&env, &o).unwrap();
    assert_eq!(a.basis(), Authorization::CircleRoot);
    // A member cannot author one for our circle: signing refuses, since the envelope
    // author must be the charter's issuer.
    assert!(ph_protocol::EnvelopeBuilder::new(
        circle(),
        Scope::all(),
        EventBody::Charter(ph_protocol::CharterBody {
            charter: c2.clone()
        })
    )
    .sign(&sk(1), now())
    .is_err());
    // A charter from somebody else's root is for somebody else's circle.
    let foreign = ph_protocol::UnsignedCharter::founding(
        pk(201),
        content(vec![entry("mallory", &[66], &["*"])]),
        now(),
    )
    .sign(&sk(201))
    .unwrap();
    let env = charter_env(&sk(201), &foreign);
    assert_eq!(authorize(&env, &o).unwrap_err(), Rejection::UnknownCircle);
}

#[test]
fn a_revocation_is_accepted_whatever_the_clocks_say() {
    // The founder's clock runs a day ahead. A revocation only ever denies, so it must
    // not be refused for being "from the future": that would leave the device trusted.
    let o = TestOracle::new();
    let rev = revocation_of(4, now().plus_days(1));
    let env = ph_protocol::EnvelopeBuilder::new(
        circle(),
        Scope::all(),
        EventBody::Revocation(ph_protocol::RevocationBody {
            revocation: rev.clone(),
        }),
    )
    .created_at(now().plus_days(1))
    .sign(&root(), now().plus_days(1))
    .unwrap();
    let v = validate_stateless(&raw(&env), now()).unwrap();
    assert!(authorize_incoming(&v, &o, &NoRecords, &known, now()).is_ok());
    assert!(o.revoke(&rev, now()));
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
