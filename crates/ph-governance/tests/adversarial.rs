//! Adversarial cases against the voting model (architecture section 10) and the
//! control plane (ADR-010): a founder stuffing the roll, a departed majority voting
//! under an old charter, a member approving two conflicting amendments, certificates and
//! charters built in memory to bypass parsing, cross-circle MEMBERSHIP, non-root and
//! self REVOCATION, and revoking the founder's own device.

mod common;

use common::*;
use ph_core::{
    CircleId, DenyReason, DeviceKey, EventId, MembershipOracle, Nonce, Role, Scope, Timestamp,
};
use ph_governance::{
    admit_member, authorize_incoming, check_successor, remove_member, rules_in_force, tally,
    IgnoreReason, NoRecords, NotPassed, Passed, Rejection, ResultView, RuleSet, SuccessionError,
    ViewError, VoteView,
};
use ph_protocol::{
    signing, validate_stateless, EnvelopeBuilder, EventBody, MembershipBody, ResultBody,
    Revocation, RevocationBody, SignedEnvelope, SigningKey, UnsignedEnvelope, UnsignedRevocation,
    VoteDecision,
};

const S: &str = "team/frontend";

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

// ---------------------------------------------------------------------------------------
// The electorate cannot be gamed
// ---------------------------------------------------------------------------------------

#[test]
fn a_founder_cannot_out_vote_the_circle_with_extra_devices_or_sock_puppets() {
    // The founder has the maximum four devices. They are still one member of three.
    let c = founding(vec![
        entry("alice", &[1, 11, 21, 31], &["*"]),
        entry("bob", &[2], &["*"]),
        entry("carol", &[3], &["*"]),
    ]);
    let p = adopt(1, &c, "*", digest(b"b"));
    let votes: Vec<VoteView> = [1u8, 11, 21, 31].iter().map(|s| approve(*s, &p)).collect();
    let t = tally(&p, &c, &votes, &nobody_revoked).unwrap();
    assert_eq!(t.approvals().len(), 1);
    assert!(!t.passed());

    // She cannot add sock-puppet members on her own either: admission is a vote of the
    // current roll, and one of three is not a majority.
    let none = RuleSet::default();
    let mut next = c.content.clone();
    for (name, seed) in [("sock1", 41u8), ("sock2", 42), ("sock3", 43)] {
        next = admit_member(&next, &none, entry(name, &[seed], &["*"])).unwrap();
    }
    let am = amend(1, &c, next.clone());
    let votes = vec![
        approve(1, &am),
        approve(41, &am),
        approve(42, &am),
        approve(43, &am),
    ];
    let t = tally(&am, &c, &votes, &nobody_revoked).unwrap();
    assert_eq!(
        t.approvals().len(),
        1,
        "the puppets are not on the roll yet"
    );
    assert!(!t.passed());
    // Even with the root key's signature on the stuffed charter, nodes refuse it.
    let r = result_of(1, &am, &votes);
    let stuffed = successor(&c, next, r.event_id());
    assert!(matches!(
        check_successor(&c, &stuffed, &am, &r, &votes, &nobody_revoked),
        Err(SuccessionError::NotPassed(_))
    ));
}

#[test]
fn a_departed_majority_cannot_pass_rules_under_the_old_charter() {
    // Five members. Three leave by a proper vote, leaving alice and bob.
    let c1 = founding(
        [
            ("alice", 1u8),
            ("bob", 2),
            ("carol", 3),
            ("dave", 4),
            ("erin", 5),
        ]
        .iter()
        .map(|(n, s)| entry(n, &[*s], &["*"]))
        .collect(),
    );
    let none = RuleSet::default();
    let mut next = c1.content.clone();
    for gone in ["carol", "dave", "erin"] {
        next = remove_member(&next, &none, gone).unwrap();
    }
    let am = amend(1, &c1, next.clone());
    let votes: Vec<VoteView> = [1u8, 3, 4, 5].iter().map(|s| approve(*s, &am)).collect();
    let r = result_of(1, &am, &votes);
    let c2 = successor(&c1, next, r.event_id());
    check_successor(&c1, &c2, &am, &r, &votes, &nobody_revoked).unwrap();

    // Later the three departed keys (lost laptops, say) sign a rule under charter 1,
    // where they were a majority of five.
    let evil = adopt_named(3, &c1, "*", "exfiltrate-convention", digest(b"evil"), now());
    let evil_votes: Vec<VoteView> = [3u8, 4, 5].iter().map(|s| approve(*s, &evil)).collect();
    let t = tally(&evil, &c1, &evil_votes, &nobody_revoked).unwrap();
    assert!(
        t.passed(),
        "under the charter it names, the count is what it is"
    );
    // But that charter is over. Nothing they sign there takes effect.
    assert_eq!(
        Passed::by_vote(&evil, &t, &c2),
        Err(NotPassed::StaleCharter)
    );
    assert!(rules_in_force(&c2, &[]).is_empty());
    // And under the current charter they are not on the roll at all.
    let evil2 = adopt_named(3, &c2, "*", "exfiltrate-convention", digest(b"evil"), now());
    let votes2: Vec<VoteView> = [3u8, 4, 5].iter().map(|s| approve(*s, &evil2)).collect();
    let t = tally(&evil2, &c2, &votes2, &nobody_revoked).unwrap();
    assert!(t.approvals().is_empty());
    assert!(t
        .ignored()
        .iter()
        .all(|(_, r)| *r == IgnoreReason::NotOnRoll));
}

#[test]
fn two_conflicting_amendments_cannot_both_take_effect() {
    // Bob approves two different amendments under the same charter, so both reach two
    // of three. The root notarizes one; the other is then an amendment of a charter
    // that is no longer current.
    let c1 = abc();
    let none = RuleSet::default();
    let with_dave = admit_member(&c1.content, &none, entry("dave", &[4], &["*"])).unwrap();
    let with_erin = admit_member(&c1.content, &none, entry("erin", &[5], &["*"])).unwrap();
    let pa = amend(1, &c1, with_dave.clone());
    let pb = amend(3, &c1, with_erin.clone());
    let va = vec![approve(1, &pa), approve(2, &pa)];
    let vb = vec![approve(3, &pb), approve(2, &pb)];
    let ra = result_of(1, &pa, &va);
    let rb = result_of(3, &pb, &vb);
    let c2a = successor(&c1, with_dave, ra.event_id());
    let c2b = successor(&c1, with_erin.clone(), rb.event_id());
    // Seen from charter 1, either would be a valid successor ...
    check_successor(&c1, &c2a, &pa, &ra, &va, &nobody_revoked).unwrap();
    check_successor(&c1, &c2b, &pb, &rb, &vb, &nobody_revoked).unwrap();
    // ... but once a node has accepted one, the other does not follow it.
    assert_eq!(
        check_successor(&c2a, &c2b, &pb, &rb, &vb, &nobody_revoked),
        Err(SuccessionError::NotNext)
    );
    // Re-issuing the losing amendment on top of the winner does not work either: its
    // proposal and ballots name charter 1.
    let replay = successor(&c2a, with_erin, rb.event_id());
    assert_eq!(
        check_successor(&c2a, &replay, &pb, &rb, &vb, &nobody_revoked),
        Err(SuccessionError::NotAnAmendment)
    );
}

// ---------------------------------------------------------------------------------------
// Objects built in memory cannot bypass the parser's checks
// ---------------------------------------------------------------------------------------

#[test]
fn a_hand_built_result_with_duplicate_approvals_is_refused_as_a_view() {
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    let v = approve(1, &p);
    // `ResultBody` built directly, listing the same ballot twice, then signed by hand.
    let body = EventBody::Result(ResultBody {
        proposal_id: p.event_id(),
        approvals: vec![v.event_id(), v.event_id()],
    });
    let env = hand_sign(
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
    assert!(
        env.verify_signature().is_ok(),
        "the signature itself is fine"
    );
    assert_eq!(ResultView::from_envelope(&env), Err(ViewError::InvalidBody));
    assert!(validate_stateless(&raw(&env), now()).is_err());
}

#[test]
fn a_ballot_signed_by_one_key_cannot_be_relabelled_as_another_members() {
    let c = abc();
    let p = adopt(1, &c, "*", digest(b"b"));
    // Mallory (not on the roll) signs a ballot, then rewrites `author` to bob's key.
    let mut env = vote_env_for(66, &p, VoteDecision::Approve, now());
    env.envelope.author = pk(2);
    assert_eq!(VoteView::from_envelope(&env), Err(ViewError::BadSignature));
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
        authorize_incoming(&verified(&genuine), &o, &NoRecords, &known, now()).unwrap_err(),
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
    // ph-protocol refuses to sign a root self-revocation ...
    let u = UnsignedRevocation::new(
        pk(ROOT),
        pk(ROOT),
        now(),
        String::new(),
        Nonce::from_bytes([3; 16]),
    );
    assert!(u.clone().sign(&root()).is_err());
    // ... and a hand-signed one, wrapped in a correctly signed envelope by the root,
    // never becomes a VerifiedEnvelope, so it cannot reach governance at all.
    let sig = signing::sign_input(&root(), &u.signing_input().unwrap());
    let rev = Revocation {
        unsigned: u,
        signature: sig,
    };
    assert!(ph_protocol::verify_revocation_signature(&rev).is_err());
    let env = hand_sign(
        &root(),
        &unsigned(
            &root(),
            circle(),
            "*",
            EventBody::Revocation(RevocationBody { revocation: rev }),
            now().minus_secs(5),
            now().plus_days(5),
        ),
    );
    assert!(env.verify_signature().is_ok());
    assert!(validate_stateless(&raw(&env), now()).is_err());
    // Governance keeps its own check (Rejection::RootSelfRevocation) as defense in
    // depth; body validation would reject it there too.
    assert_eq!(
        ph_governance::check_body(&env).unwrap_err(),
        Rejection::BadReference
    );
    assert_eq!(Rejection::RootSelfRevocation.code(), "root_self_revocation");
}

#[test]
fn founder_device_can_be_revoked_and_its_ballots_stop_counting() {
    // The founder's device key (seed 1) is distinct from the root key, and can be
    // revoked like any other device.
    let o = TestOracle::new();
    for seed in 1..=3 {
        enroll(&o, seed, &[S]);
    }
    let c = founding(vec![
        entry("alice", &[1], &[S]),
        entry("bob", &[2], &[S]),
        entry("carol", &[3], &[S]),
    ]);
    let p = adopt(1, &c, S, digest(b"A"));
    let votes = [approve(1, &p), approve(2, &p)];
    assert!(tally(&p, &c, &votes, &nobody_revoked).unwrap().passed());

    let rev = revocation_of(1, now());
    let env = revocation_env(&root(), &rev);
    let a = authorize_incoming(&verified(&env), &o, &NoRecords, &known, now()).unwrap();
    assert_eq!(a.basis(), ph_protocol::Authorization::CircleRoot);
    assert!(o.revoke(&rev, now()));

    // On a node where the proposal had not passed yet, the device's ballot is void.
    let revoked = |d: &DeviceKey| o.is_revoked(&circle(), d);
    let t = tally(&p, &c, &votes, &revoked).unwrap();
    assert!(!t.passed());
    assert_eq!(
        t.ignore_reason(&votes[0].event_id()),
        Some(IgnoreReason::Revoked)
    );
    // A revocation can block but never pass: the electorate is still three.
    assert_eq!((t.electorate().len(), t.need()), (3, 2));
    // Its MEMBERSHIP republish is refused (oracle.is_revoked).
    let m = verified(&membership_env(1, &member_proof(1, &[S]), "*"));
    assert_eq!(
        authorize_incoming(&m, &o, &NoRecords, &known, now()).unwrap_err(),
        Rejection::Denied(DenyReason::Revoked)
    );
}
