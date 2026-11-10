//! Shared fixtures: a small in-memory `MembershipOracle` built only from real, verified
//! ph-protocol credentials, acceptances and revocations; an in-memory
//! `DecisionRecords`; charters signed by the test root key; and event builders.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use ph_core::{
    roles_grant, Capability, CircleId, DenyReason, DeviceKey, Digest, EventId, MembershipOracle,
    Nonce, Role, Scope, Timestamp,
};
use ph_governance::{DecisionRecords, ProposalView, ResultView, VoteView};
use ph_protocol::{
    validate_stateless, verify_credential_signature, verify_membership_proof,
    verify_revocation_signature, AdoptAction, AnswerBody, AnswerChoice, Charter, CharterBody,
    CharterContent, CharterRules, EnvelopeBuilder, EventBody, MembershipBody, MembershipCredential,
    MembershipProof, ProposalAction, ProposalBody, QuestionBody, ResultBody, Revocation,
    RevocationBody, RollEntry, SignedEnvelope, SigningKey, UnsignedAcceptance, UnsignedCharter,
    UnsignedMembershipCredential, UnsignedRevocation, VerifiedEnvelope, VoteBody, VoteDecision,
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

    /// Applies a revocation only if it verifies and was issued by the circle root. A
    /// revocation only ever denies, so no time rule applies (`_at` is unused).
    pub fn revoke(&self, rev: &Revocation, _at: Timestamp) -> bool {
        if verify_revocation_signature(rev).is_err()
            || !rev.circle_id.is_derived_from(&rev.issuer_key)
        {
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

    fn is_revoked(&self, circle: &CircleId, key: &DeviceKey) -> bool {
        TestOracle::is_revoked(self, circle, key)
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

// ---------------------------------------------------------------------------------------
// Charters
// ---------------------------------------------------------------------------------------

/// A roll entry: member `name`, devices from `seeds`, scopes from `scopes`.
pub fn entry(name: &str, seeds: &[u8], scopes: &[&str]) -> RollEntry {
    RollEntry::new(
        name,
        seeds.iter().map(|s| pk(*s)).collect(),
        scopes.iter().map(|s| scope(s)).collect(),
    )
}

/// Charter content with default rules (majority to pass, two thirds to change the
/// rules, binding), the given roll and nothing carried.
pub fn content(roll: Vec<RollEntry>) -> CharterContent {
    let mut c = CharterContent {
        rules: CharterRules::default(),
        roll,
        carried: Vec::new(),
    };
    c.normalize();
    c
}

/// A founding charter (seq 1) of the default circle, signed by the test root key.
pub fn founding(roll: Vec<RollEntry>) -> Charter {
    founding_with(content(roll))
}

pub fn founding_with(content: CharterContent) -> Charter {
    UnsignedCharter::founding(pk(ROOT), content, now().minus_secs(7200))
        .sign(&root())
        .unwrap()
}

/// The usual three-member circle: alice (device 1), bob (device 2), carol (device 3),
/// all with scope `*`.
pub fn abc() -> Charter {
    founding(vec![
        entry("alice", &[1], &["*"]),
        entry("bob", &[2], &["*"]),
        entry("carol", &[3], &["*"]),
    ])
}

/// The successor of `current` with `next` as content, justified by `result`, signed by
/// the test root key.
pub fn successor(current: &Charter, next: CharterContent, result: EventId) -> Charter {
    UnsignedCharter::successor(current, next, result, now())
        .unwrap()
        .sign(&root())
        .unwrap()
}

pub fn charter_env(author: &SigningKey, charter: &Charter) -> SignedEnvelope {
    EnvelopeBuilder::new(
        charter.circle_id,
        Scope::all(),
        EventBody::Charter(CharterBody {
            charter: charter.clone(),
        }),
    )
    .sign(author, now())
    .unwrap()
}

/// In-memory `DecisionRecords`.
#[derive(Default)]
pub struct TestRecords {
    charters: HashMap<Digest, Charter>,
    proposals: HashMap<EventId, SignedEnvelope>,
}

impl TestRecords {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_charter(mut self, c: &Charter) -> Self {
        self.add_charter(c);
        self
    }
    pub fn add_charter(&mut self, c: &Charter) {
        self.charters.insert(c.digest().unwrap(), c.clone());
    }
    pub fn add_proposal(&mut self, p: &ProposalView) {
        self.proposals.insert(p.event_id(), p.envelope().clone());
    }
    pub fn with_proposal(mut self, p: &ProposalView) -> Self {
        self.add_proposal(p);
        self
    }
}

impl DecisionRecords for TestRecords {
    fn charter(&self, circle: &CircleId, digest: &Digest) -> Option<Charter> {
        self.charters
            .get(digest)
            .filter(|c| &c.circle_id == circle)
            .cloned()
    }
    fn proposal(&self, circle: &CircleId, id: &EventId) -> Option<SignedEnvelope> {
        self.proposals
            .get(id)
            .filter(|p| &p.circle_id == circle)
            .cloned()
    }
}

pub fn nobody_revoked(_: &DeviceKey) -> bool {
    false
}

// ---------------------------------------------------------------------------------------
// Decision events
// ---------------------------------------------------------------------------------------

pub const SKILL: &str = "pnpm-repository-convention";

pub fn adopt_body(charter: &Charter, skill: &str, d: Digest) -> ProposalBody {
    ProposalBody {
        charter: charter.digest().unwrap(),
        title: "pnpm repository convention".into(),
        summary: "Corrected twice in local sessions".into(),
        action: ProposalAction::Adopt(AdoptAction {
            skill_name: skill.into(),
            description: "Use pnpm when installing packages in this repository.".into(),
            bundle_digest: d,
            bundle_size: 321,
            related_question: None,
            supersedes: None,
        }),
    }
}

pub fn proposal_from(seed: u8, scope_s: &str, body: ProposalBody, at: Timestamp) -> ProposalView {
    ProposalView::from_envelope(&sign_at(
        &sk(seed),
        circle(),
        scope_s,
        EventBody::Proposal(body),
        at,
    ))
    .unwrap()
}

/// An `adopt` proposal for [`SKILL`] under `charter`, by device `seed`.
pub fn adopt(seed: u8, charter: &Charter, scope_s: &str, d: Digest) -> ProposalView {
    adopt_named(seed, charter, scope_s, SKILL, d, now().minus_secs(3600))
}

pub fn adopt_named(
    seed: u8,
    charter: &Charter,
    scope_s: &str,
    skill: &str,
    d: Digest,
    at: Timestamp,
) -> ProposalView {
    proposal_from(seed, scope_s, adopt_body(charter, skill, d), at)
}

/// A `repeal` proposal targeting `target`, in the target's scope.
pub fn repeal(seed: u8, charter: &Charter, target: &ProposalView) -> ProposalView {
    proposal_from(
        seed,
        target.scope().as_str(),
        ProposalBody {
            charter: charter.digest().unwrap(),
            title: "Drop the rule".into(),
            summary: String::new(),
            action: ProposalAction::Repeal {
                target: target.event_id(),
            },
        },
        now().minus_secs(1800),
    )
}

/// An `amend` proposal under `charter` proposing `next`.
pub fn amend(seed: u8, charter: &Charter, next: CharterContent) -> ProposalView {
    proposal_from(
        seed,
        "*",
        ProposalBody {
            charter: charter.digest().unwrap(),
            title: "Amend the charter".into(),
            summary: String::new(),
            action: ProposalAction::Amend { next },
        },
        now().minus_secs(1800),
    )
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

pub fn approve(seed: u8, p: &ProposalView) -> VoteView {
    vote(seed, p, VoteDecision::Approve)
}

pub fn result_env(seed: u8, p: &ProposalView, approvals: Vec<EventId>) -> SignedEnvelope {
    sign_at(
        &sk(seed),
        p.circle_id(),
        p.scope().as_str(),
        EventBody::Result(ResultBody::new(p.event_id(), approvals)),
        now(),
    )
}

pub fn result(seed: u8, p: &ProposalView, approvals: Vec<EventId>) -> ResultView {
    ResultView::from_envelope(&result_env(seed, p, approvals)).unwrap()
}

/// The RESULT a member publishes once `votes` carry `p` over its threshold.
pub fn result_of(seed: u8, p: &ProposalView, votes: &[VoteView]) -> ResultView {
    result(seed, p, votes.iter().map(|v| v.event_id()).collect())
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
