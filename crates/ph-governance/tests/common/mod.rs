//! Shared fixtures: a small in-memory `MembershipOracle` built only from real, verified
//! ph-protocol credentials, acceptances and revocations, plus event builders.
#![allow(dead_code)]

use std::collections::HashSet;
use std::sync::Mutex;

use ph_core::{
    roles_grant, Capability, CircleId, DenyReason, DeviceKey, Digest, EventId, MembershipOracle,
    Nonce, Role, Scope, Timestamp,
};
use ph_governance::{ProposalView, ReleaseView, VoteView};
use ph_protocol::{
    validate_stateless, verify_credential_signature, verify_membership_proof, verify_revocation,
    AnswerBody, AnswerChoice, EnvelopeBuilder, EventBody, MembershipBody, MembershipCredential,
    MembershipProof, ProposalBody, QuestionBody, ReleaseBody, Revocation, RevocationBody,
    SignedEnvelope, SigningKey, UnsignedAcceptance, UnsignedMembershipCredential,
    UnsignedRevocation, VerifiedEnvelope, VoteBody, VoteDecision,
};

pub fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
pub fn pk(seed: u8) -> DeviceKey {
    DeviceKey::from_signing_key(&sk(seed))
}
pub fn now() -> Timestamp {
    "2026-11-09T18:10:00Z".parse().unwrap()
}
pub fn scope(s: &str) -> Scope {
    Scope::new(s).unwrap()
}
pub fn digest(tag: &[u8]) -> Digest {
    Digest::sha256(tag)
}

/// Seed of the default circle root key.
pub const ROOT: u8 = 200;

pub fn root() -> SigningKey {
    sk(ROOT)
}
pub fn circle() -> CircleId {
    CircleId::derive(&pk(ROOT))
}

/// In-memory oracle. Credentials are only stored after full verification; a credential
/// counts only if its issuer derives the circle id (root-issued). Revocations are only
/// stored after verification against the circle root.
#[derive(Default)]
pub struct TestOracle {
    proofs: Mutex<Vec<MembershipProof>>,
    unaccepted: Mutex<Vec<MembershipCredential>>,
    revoked: Mutex<HashSet<(CircleId, DeviceKey)>>,
}

impl TestOracle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a proof only if it verifies at `at`. Returns whether it was added.
    pub fn add_proof(&self, proof: &MembershipProof, at: Timestamp) -> bool {
        if verify_membership_proof(proof, at).is_err() {
            return false;
        }
        self.proofs.lock().unwrap().push(proof.clone());
        true
    }

    /// Adds a credential without acceptance (verified signature only).
    pub fn add_unaccepted(&self, cred: &MembershipCredential) -> bool {
        if verify_credential_signature(cred).is_err() {
            return false;
        }
        self.unaccepted.lock().unwrap().push(cred.clone());
        true
    }

    /// Applies a revocation only if it verifies and was issued by the circle root.
    pub fn revoke(&self, rev: &Revocation, at: Timestamp) -> bool {
        if verify_revocation(rev, at).is_err() || !rev.circle_id.is_derived_from(&rev.issuer_key) {
            return false;
        }
        self.revoked
            .lock()
            .unwrap()
            .insert((rev.circle_id, rev.subject_device_key));
        true
    }

    pub fn is_revoked(&self, circle: &CircleId, key: &DeviceKey) -> bool {
        self.revoked.lock().unwrap().contains(&(*circle, *key))
    }

    fn creds(&self, circle: &CircleId, key: &DeviceKey) -> Vec<MembershipCredential> {
        self.proofs
            .lock()
            .unwrap()
            .iter()
            .map(|p| &p.credential)
            .filter(|c| {
                &c.circle_id == circle
                    && &c.subject_device_key == key
                    && circle.is_derived_from(&c.issuer_key)
            })
            .cloned()
            .collect()
    }
}

impl MembershipOracle for TestOracle {
    fn authorize(
        &self,
        circle: &CircleId,
        key: &DeviceKey,
        scope: &Scope,
        cap: Capability,
        now: Timestamp,
    ) -> Result<(), DenyReason> {
        if self.is_revoked(circle, key) {
            return Err(DenyReason::Revoked);
        }
        let creds = self.creds(circle, key);
        if creds.is_empty() {
            let pending = self
                .unaccepted
                .lock()
                .unwrap()
                .iter()
                .any(|c| &c.circle_id == circle && &c.subject_device_key == key);
            return Err(if pending {
                DenyReason::NotAccepted
            } else {
                DenyReason::NotMember
            });
        }
        let live: Vec<_> = creds
            .into_iter()
            .filter(|c| c.check_time(now).is_ok())
            .collect();
        if live.is_empty() {
            return Err(DenyReason::Expired);
        }
        let in_scope: Vec<_> = live
            .iter()
            .filter(|c| Scope::any_covers(&c.scopes, scope))
            .collect();
        if in_scope.is_empty() {
            return Err(DenyReason::ScopeDenied);
        }
        if in_scope.iter().any(|c| roles_grant(&c.roles, cap)) {
            Ok(())
        } else {
            Err(DenyReason::CapabilityDenied)
        }
    }

    fn is_active_member(&self, circle: &CircleId, key: &DeviceKey, now: Timestamp) -> bool {
        !self.is_revoked(circle, key)
            && self
                .creds(circle, key)
                .iter()
                .any(|c| c.check_time(now).is_ok())
    }
}

/// Issues (by `issuer`) and accepts (by the subject) a credential.
pub fn proof_by(
    issuer: &SigningKey,
    subject: &SigningKey,
    roles: Vec<Role>,
    scopes: &[&str],
    issued_at: Timestamp,
    expires_at: Timestamp,
) -> MembershipProof {
    let credential = UnsignedMembershipCredential::new(
        DeviceKey::from_signing_key(issuer),
        DeviceKey::from_signing_key(subject),
        roles,
        scopes.iter().map(|s| scope(s)).collect(),
        issued_at,
        expires_at,
    )
    .sign(issuer)
    .unwrap();
    let acceptance = UnsignedAcceptance::for_credential(&credential, issued_at)
        .unwrap()
        .sign(subject)
        .unwrap();
    MembershipProof {
        credential,
        acceptance,
    }
}

/// A root-issued member proof valid from a day ago for 30 days.
pub fn member_proof(seed: u8, scopes: &[&str]) -> MembershipProof {
    proof_by(
        &root(),
        &sk(seed),
        vec![Role::Member],
        scopes,
        now().minus_secs(86_400),
        now().plus_days(29),
    )
}

/// Adds a root-issued member to the oracle.
pub fn enroll(oracle: &TestOracle, seed: u8, scopes: &[&str]) -> MembershipProof {
    let p = member_proof(seed, scopes);
    assert!(oracle.add_proof(&p, now()));
    p
}

pub fn revocation_of(subject: u8, at: Timestamp) -> Revocation {
    UnsignedRevocation::new(
        pk(ROOT),
        pk(subject),
        at,
        "device lost".into(),
        Nonce::from_bytes([subject; 16]),
    )
    .sign(&root())
    .unwrap()
}

pub fn sign_at(
    author: &SigningKey,
    circle: CircleId,
    scope_s: &str,
    body: EventBody,
    created_at: Timestamp,
) -> SignedEnvelope {
    EnvelopeBuilder::new(circle, scope(scope_s), body)
        .created_at(created_at)
        .sign(author, created_at)
        .unwrap()
}

pub fn raw(env: &SignedEnvelope) -> Vec<u8> {
    env.to_canonical_json().unwrap().into_bytes()
}

pub fn verified(env: &SignedEnvelope) -> VerifiedEnvelope {
    validate_stateless(&raw(env), now()).unwrap()
}

pub fn question_env(seed: u8, scope_s: &str, text: &str) -> SignedEnvelope {
    sign_at(
        &sk(seed),
        circle(),
        scope_s,
        EventBody::Question(QuestionBody {
            question: text.into(),
            topic: "package-manager".into(),
            related_candidate: None,
        }),
        now(),
    )
}

pub fn answer_env(seed: u8, scope_s: &str, question_id: EventId) -> SignedEnvelope {
    sign_at(
        &sk(seed),
        circle(),
        scope_s,
        EventBody::Answer(AnswerBody {
            question_id,
            answer: AnswerChoice::Agree,
            rationale: Some("we already have pnpm-lock.yaml".into()),
        }),
        now(),
    )
}

pub fn proposal_body(skill: &str, d: Digest) -> ProposalBody {
    ProposalBody {
        skill_name: skill.into(),
        description: "Use pnpm when installing packages in this repository.".into(),
        title: "pnpm repository convention".into(),
        bundle_digest: d,
        bundle_size: 321,
        related_question: None,
        supersedes: None,
        provenance_summary: "Corrected twice in local sessions".into(),
    }
}

pub fn proposal_env(seed: u8, scope_s: &str, skill: &str, d: Digest) -> SignedEnvelope {
    sign_at(
        &sk(seed),
        circle(),
        scope_s,
        EventBody::Proposal(proposal_body(skill, d)),
        now().minus_secs(3600),
    )
}

pub fn proposal(seed: u8, scope_s: &str, d: Digest) -> ProposalView {
    ProposalView::from_envelope(&proposal_env(
        seed,
        scope_s,
        "pnpm-repository-convention",
        d,
    ))
    .unwrap()
}

pub fn vote_env_for(
    seed: u8,
    p: &ProposalView,
    decision: VoteDecision,
    created_at: Timestamp,
) -> SignedEnvelope {
    sign_at(
        &sk(seed),
        p.circle_id(),
        p.scope().as_str(),
        EventBody::Vote(VoteBody {
            proposal_id: p.event_id(),
            bundle_digest: p.bundle_digest(),
            decision,
            rationale: Some("looks right".into()),
        }),
        created_at,
    )
}

pub fn vote(seed: u8, p: &ProposalView, decision: VoteDecision) -> VoteView {
    VoteView::from_envelope(&vote_env_for(seed, p, decision, now().minus_secs(60))).unwrap()
}

pub fn vote_at(seed: u8, p: &ProposalView, decision: VoteDecision, at: Timestamp) -> VoteView {
    VoteView::from_envelope(&vote_env_for(seed, p, decision, at)).unwrap()
}

pub fn release_env(seed: u8, p: &ProposalView, approvals: Vec<EventId>) -> SignedEnvelope {
    sign_at(
        &sk(seed),
        p.circle_id(),
        p.scope().as_str(),
        EventBody::Release(ReleaseBody {
            proposal_id: p.event_id(),
            bundle_digest: p.bundle_digest(),
            skill_name: p.skill_name().into(),
            approvals,
        }),
        now(),
    )
}

pub fn release(seed: u8, p: &ProposalView, approvals: Vec<EventId>) -> ReleaseView {
    ReleaseView::from_envelope(&release_env(seed, p, approvals)).unwrap()
}

pub fn membership_env(seed: u8, proof: &MembershipProof, scope_s: &str) -> SignedEnvelope {
    EnvelopeBuilder::new(
        proof.credential.circle_id,
        scope(scope_s),
        EventBody::Membership(MembershipBody {
            credential: proof.credential.clone(),
            acceptance: proof.acceptance.clone(),
        }),
    )
    .sign(&sk(seed), now())
    .unwrap()
}

pub fn revocation_env(author: &SigningKey, rev: &Revocation) -> SignedEnvelope {
    EnvelopeBuilder::new(
        rev.circle_id,
        Scope::all(),
        EventBody::Revocation(RevocationBody {
            revocation: rev.clone(),
        }),
    )
    .sign(author, now())
    .unwrap()
}

pub fn known(c: &CircleId) -> bool {
    *c == circle()
}
