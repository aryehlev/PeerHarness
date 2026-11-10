//! Shared test fixtures.
#![allow(dead_code)]

use ph_core::{CircleId, DeviceKey, Digest, EventId, Nonce, Role, Scope, Timestamp};
use ph_protocol::{
    validate_stateless, Acceptance, AdoptAction, AnswerBody, AnswerChoice, Charter, CharterContent,
    EnvelopeBuilder, EventBody, MembershipBody, MembershipCredential, MembershipProof,
    ProposalAction, ProposalBody, QuestionBody, Revocation, RevocationBody, RollEntry,
    SignedEnvelope, SigningKey, UnsignedAcceptance, UnsignedCharter, UnsignedMembershipCredential,
    UnsignedRevocation, VerifiedEnvelope, VoteBody, VoteDecision,
};
use ph_store::{CircleRow, Store};

pub const ROOT: u8 = 2;
pub const ALICE: u8 = 1;
pub const BOB: u8 = 3;
pub const CAROL: u8 = 4;

pub fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn pk(seed: u8) -> DeviceKey {
    DeviceKey::from_signing_key(&sk(seed))
}

pub fn now() -> Timestamp {
    "2026-11-09T18:10:00Z".parse().unwrap()
}

pub fn circle() -> CircleId {
    CircleId::derive(&pk(ROOT))
}

pub fn scope(s: &str) -> Scope {
    Scope::new(s).unwrap()
}

pub fn circle_row() -> CircleRow {
    CircleRow {
        circle_id: circle(),
        name: "acme".into(),
        root_key: pk(ROOT),
        is_founder: true,
        root_keystore_ref: Some("file:keys/root-acme.key".into()),
        adoption_mode: "ask".into(),
        accepted_charter: None,
        created_at: now(),
    }
}

/// An in-memory store with the test circle inserted.
pub fn store_with_circle() -> Store {
    let s = Store::open_in_memory().unwrap();
    s.insert_circle(&circle_row()).unwrap();
    s
}

pub fn credential(subject: u8, scopes: &[&str]) -> MembershipCredential {
    UnsignedMembershipCredential::new(
        pk(ROOT),
        pk(subject),
        vec![Role::Member],
        scopes.iter().map(|s| scope(s)).collect(),
        now(),
        now().plus_days(30),
    )
    .sign(&sk(ROOT))
    .unwrap()
}

pub fn acceptance(subject: u8, cred: &MembershipCredential) -> Acceptance {
    UnsignedAcceptance::for_credential(cred, now())
        .unwrap()
        .sign(&sk(subject))
        .unwrap()
}

pub fn proof(subject: u8, scopes: &[&str]) -> MembershipProof {
    let credential = credential(subject, scopes);
    let acceptance = acceptance(subject, &credential);
    MembershipProof {
        credential,
        acceptance,
    }
}

pub fn revocation(subject: u8, nonce: u8) -> Revocation {
    UnsignedRevocation::new(
        pk(ROOT),
        pk(subject),
        now(),
        "left the team".into(),
        Nonce::from_bytes([nonce; 16]),
    )
    .sign(&sk(ROOT))
    .unwrap()
}

fn sign(author: u8, sc: &str, body: EventBody, nonce: u8, created: Timestamp) -> SignedEnvelope {
    EnvelopeBuilder::new(circle(), scope(sc), body)
        .nonce(Nonce::from_bytes([nonce; 16]))
        .created_at(created)
        .sign(&sk(author), created)
        .unwrap()
}

pub fn question_at(
    author: u8,
    sc: &str,
    text: &str,
    nonce: u8,
    created: Timestamp,
) -> SignedEnvelope {
    sign(
        author,
        sc,
        EventBody::Question(QuestionBody {
            question: text.into(),
            topic: "package-manager".into(),
            related_candidate: None,
        }),
        nonce,
        created,
    )
}

pub fn question(author: u8, sc: &str, text: &str, nonce: u8) -> SignedEnvelope {
    question_at(author, sc, text, nonce, now())
}

pub fn answer(author: u8, sc: &str, q: EventId, nonce: u8) -> SignedEnvelope {
    sign(
        author,
        sc,
        EventBody::Answer(AnswerBody {
            question_id: q,
            answer: AnswerChoice::Agree,
            rationale: None,
        }),
        nonce,
        now(),
    )
}

pub fn proposal(author: u8, sc: &str, digest: Digest, nonce: u8) -> SignedEnvelope {
    sign(
        author,
        sc,
        EventBody::Proposal(ProposalBody {
            charter: charter_digest(),
            title: "pnpm".into(),
            summary: "corrected twice".into(),
            action: ProposalAction::Adopt(AdoptAction {
                skill_name: "pnpm-repository-convention".into(),
                description: "Use pnpm.".into(),
                bundle_digest: digest,
                bundle_size: 10,
                related_question: None,
                supersedes: None,
            }),
        }),
        nonce,
        now(),
    )
}

/// The founding charter of the test circle: alice, bob and carol, all with scope `*`.
pub fn charter() -> Charter {
    let mut content =
        CharterContent::founding(RollEntry::new("alice", vec![pk(ALICE)], vec![Scope::all()]));
    for (name, seed) in [("bob", BOB), ("carol", CAROL)] {
        content
            .roll
            .push(RollEntry::new(name, vec![pk(seed)], vec![Scope::all()]));
    }
    content.normalize();
    UnsignedCharter::founding(pk(ROOT), content, now())
        .sign(&sk(ROOT))
        .unwrap()
}

pub fn charter_digest() -> Digest {
    charter().digest().unwrap()
}

/// A ballot. `_digest` is accepted and ignored: a ballot is bound to the proposal by
/// its id alone.
pub fn vote(author: u8, sc: &str, p: EventId, _digest: Digest, nonce: u8) -> SignedEnvelope {
    sign(
        author,
        sc,
        EventBody::Vote(VoteBody {
            proposal_id: p,
            decision: VoteDecision::Approve,
            rationale: None,
        }),
        nonce,
        now(),
    )
}

pub fn membership_event(subject: u8, sc: &str, nonce: u8) -> SignedEnvelope {
    let p = proof(subject, &[sc]);
    sign(
        subject,
        sc,
        EventBody::Membership(MembershipBody {
            credential: p.credential,
            acceptance: p.acceptance,
        }),
        nonce,
        now(),
    )
}

pub fn revocation_event(subject: u8, nonce: u8) -> SignedEnvelope {
    sign(
        ROOT,
        "*",
        EventBody::Revocation(RevocationBody {
            revocation: revocation(subject, nonce),
        }),
        nonce,
        now(),
    )
}

pub fn verified(e: &SignedEnvelope) -> VerifiedEnvelope {
    validate_stateless(e.to_canonical_json().unwrap().as_bytes(), now()).unwrap()
}

pub fn peer_id(n: u8) -> String {
    format!("12D3KooWPeer{n}")
}
