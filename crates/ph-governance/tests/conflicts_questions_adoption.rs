//! Conflicts and supersede lineage, the question guard, and adoption readiness.

mod common;

use common::*;
use ph_governance::{
    adoption_readiness, evaluate_proposal, find_conflicts, normalize_question_text,
    question_dedup_key, supersede_links, superseded_by, CirclePolicy, DropReason, GuardDecision,
    LocalPolicy, NotReadyReason, ProposalView, QuestionContext, QuestionGuard, Readiness,
    SupersedeKind,
};
use ph_protocol::{EventBody, VoteDecision};

const S: &str = "team/frontend";
const SKILL: &str = "pnpm-repository-convention";

fn superseding(seed: u8, old: &ProposalView, d: ph_core::Digest, skill: &str) -> ProposalView {
    let mut body = proposal_body(skill, d);
    body.supersedes = Some(old.event_id());
    ProposalView::from_envelope(&sign_at(
        &sk(seed),
        circle(),
        old.scope().as_str(),
        EventBody::Proposal(body),
        now(),
    ))
    .unwrap()
}

#[test]
fn conflicting_proposals_coexist_as_alternatives() {
    let a = proposal(1, S, digest(b"A"));
    let b = proposal(2, S, digest(b"B"));
    let a_again = proposal(3, S, digest(b"A"));
    let elsewhere = proposal(2, "team/backend", digest(b"C"));
    let groups = find_conflicts(&[a.clone(), b.clone(), a_again.clone(), a.clone(), elsewhere]);
    assert_eq!(groups.len(), 1);
    let g = &groups[0];
    assert_eq!(g.key.skill_name, SKILL);
    assert_eq!(g.key.scope.as_str(), S);
    assert_eq!(g.alternatives.len(), 2);
    let alt_a = g
        .alternatives
        .iter()
        .find(|x| x.bundle_digest == digest(b"A"))
        .unwrap();
    assert_eq!(alt_a.proposals.len(), 2);
    assert!(alt_a.proposals.contains(&a.event_id()));
    assert!(alt_a.proposals.contains(&a_again.event_id()));
    // Same digest only: no conflict.
    assert!(find_conflicts(&[a.clone(), a_again]).is_empty());
    assert!(find_conflicts(&[]).is_empty());
}

#[test]
fn votes_never_transfer_to_a_superseding_proposal() {
    let o = TestOracle::new();
    for seed in 1..=3 {
        enroll(&o, seed, &[S]);
    }
    let old = proposal(1, S, digest(b"A"));
    let new = superseding(1, &old, digest(b"B"), SKILL);
    let votes = [
        vote(1, &old, VoteDecision::Approve),
        vote(2, &old, VoteDecision::Approve),
    ];
    let policy = CirclePolicy::default();
    let local = LocalPolicy::default();
    let st_new = evaluate_proposal(&new, &votes, &o, &policy, &local, now());
    assert!(!st_new.eligible);
    assert!(st_new.approvers.is_empty());
    // The superseded proposal keeps its own votes (superseding is not a veto).
    assert!(evaluate_proposal(&old, &votes, &o, &policy, &local, now()).eligible);

    let other_author = superseding(2, &old, digest(b"C"), SKILL);
    let renamed = superseding(1, &old, digest(b"D"), "other-skill");
    let all = [
        old.clone(),
        new.clone(),
        other_author.clone(),
        renamed.clone(),
    ];
    let links = supersede_links(&all);
    assert_eq!(links.len(), 3);
    let kind = |id| links.iter().find(|l| l.superseding == id).unwrap().kind;
    assert_eq!(kind(new.event_id()), SupersedeKind::SameAuthor);
    assert_eq!(
        kind(other_author.event_id()),
        SupersedeKind::DifferentAuthor
    );
    assert_eq!(kind(renamed.event_id()), SupersedeKind::Invalid);
    let mut by = superseded_by(&old.event_id(), &all);
    by.sort();
    let mut want = vec![new.event_id(), other_author.event_id()];
    want.sort();
    assert_eq!(by, want);
    // The superseded proposal not stored yet.
    let links = supersede_links(std::slice::from_ref(&new));
    assert_eq!(links[0].kind, SupersedeKind::Unresolved);
    assert!(superseded_by(&old.event_id(), &[new]).is_empty());
}

#[test]
fn question_guard_quotas() {
    let g = QuestionGuard::default();
    assert_eq!(g.per_author_per_day, 20);
    assert_eq!(g.per_circle_per_day, 100);
    let ctx = |a, c| QuestionContext {
        author_count_24h: a,
        circle_count_24h: c,
        ..QuestionContext::default()
    };
    assert_eq!(g.check(&ctx(0, 0)), GuardDecision::Accept);
    assert!(g.check(&ctx(19, 99)).is_accept());
    assert_eq!(
        g.check(&ctx(20, 0)),
        GuardDecision::Drop(DropReason::AuthorQuota)
    );
    assert_eq!(
        g.check(&ctx(5, 100)),
        GuardDecision::Drop(DropReason::CircleQuota)
    );
    // Simulate a burst from one author: exactly 20 are accepted.
    let mut accepted = 0u32;
    for _ in 0..50 {
        if g.check(&ctx(accepted, accepted)).is_accept() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 20);
    // Many authors: the circle cap holds at 100.
    let mut circle_count = 0u32;
    for _author in 0..30 {
        let mut mine = 0u32;
        for _ in 0..10 {
            if g.check(&ctx(mine, circle_count)).is_accept() {
                mine += 1;
                circle_count += 1;
            }
        }
    }
    assert_eq!(circle_count, 100);
    let tight = QuestionGuard {
        per_author_per_day: 0,
        per_circle_per_day: 100,
    };
    assert!(!tight.check(&ctx(0, 0)).is_accept());
}

#[test]
fn question_guard_dedup_mute_block() {
    let g = QuestionGuard::default();
    let base = QuestionContext::default();
    let dup = QuestionContext {
        duplicate: true,
        ..base
    };
    assert_eq!(g.check(&dup), GuardDecision::Drop(DropReason::Duplicate));
    let muted = QuestionContext {
        author_muted: true,
        duplicate: true,
        ..base
    };
    assert_eq!(g.check(&muted), GuardDecision::Drop(DropReason::Muted));
    let blocked = QuestionContext {
        author_blocked: true,
        author_muted: true,
        author_count_24h: 1000,
        ..base
    };
    assert_eq!(g.check(&blocked), GuardDecision::Drop(DropReason::Blocked));
    assert_eq!(DropReason::Blocked.code(), "blocked");

    // Dedup keys: rephrasings that differ only in case/punctuation/spacing collide.
    let c = circle();
    let k1 = question_dedup_key(&c, "Should this repository use pnpm rather than npm?");
    let k2 = question_dedup_key(&c, "should   this repository use PNPM, rather than npm");
    let k3 = question_dedup_key(&c, "Should this repository use yarn rather than npm?");
    assert_eq!(k1, k2);
    assert_ne!(k1, k3);
    assert_eq!(
        normalize_question_text("Use\tPNPM —\u{202F}not npm!"),
        "use pnpm not npm"
    );
}

#[test]
fn adoption_requires_every_check_and_the_human() {
    let o = TestOracle::new();
    for seed in 1..=2 {
        enroll(&o, seed, &[S]);
    }
    let p = proposal(1, S, digest(b"A"));
    let votes = [
        vote(1, &p, VoteDecision::Approve),
        vote(2, &p, VoteDecision::Approve),
    ];
    let policy = CirclePolicy::default();
    let local = LocalPolicy::default();
    let ok = evaluate_proposal(&p, &votes, &o, &policy, &local, now());
    let not_ok = evaluate_proposal(&p, &votes[..1], &o, &policy, &local, now());
    assert_eq!(adoption_readiness(&ok, true, true, true), Readiness::Ready);
    assert!(adoption_readiness(&ok, true, true, true).is_ready());
    assert_eq!(
        adoption_readiness(&ok, true, true, false).reasons(),
        &[NotReadyReason::AwaitingHumanConfirmation]
    );
    assert_eq!(
        adoption_readiness(&not_ok, false, false, false),
        Readiness::NotReady(vec![
            NotReadyReason::ProposalNotEligible,
            NotReadyReason::BundleDigestUnverified,
            NotReadyReason::SkillInvalid,
            NotReadyReason::AwaitingHumanConfirmation,
        ])
    );
    // A status forged to claim eligibility while carrying blockers is still refused.
    let mut forged = not_ok.clone();
    forged.eligible = true;
    assert_eq!(
        adoption_readiness(&forged, true, true, true).reasons(),
        &[NotReadyReason::ProposalNotEligible]
    );
}
