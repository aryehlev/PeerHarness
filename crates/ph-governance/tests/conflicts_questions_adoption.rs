//! Conflicts and supersede lineage, the question guard, and the adoption gate.

mod common;

use common::*;
use ph_governance::{
    adoption_step, find_conflicts, local_policy_met, normalize_question_text, question_dedup_key,
    rules_in_force, supersede_links, superseded_by, tally, AdoptionMode, AdoptionStep, AskReason,
    BundleChecks, DropReason, GuardDecision, LocalPolicy, OwnerChoice, Passed, ProposalView,
    QuestionContext, QuestionGuard, RefuseReason, Rule, SupersedeKind,
};
use ph_protocol::{Charter, EventBody, ProposalAction};

const S: &str = "team/frontend";

fn team() -> Charter {
    founding(vec![
        entry("alice", &[1], &[S]),
        entry("bob", &[2], &[S, "team/backend"]),
        entry("carol", &[3], &[S]),
    ])
}

fn proposal(seed: u8, scope_s: &str, d: ph_core::Digest) -> ProposalView {
    adopt(seed, &team(), scope_s, d)
}

fn superseding(seed: u8, old: &ProposalView, d: ph_core::Digest, skill: &str) -> ProposalView {
    let mut body = adopt_body(&team(), skill, d);
    if let ProposalAction::Adopt(a) = &mut body.action {
        a.supersedes = Some(old.event_id());
    }
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
    // Repeals and amendments are not alternatives of anything.
    let c = team();
    let r = repeal(2, &c, &a);
    let am = amend(1, &c, c.content.clone());
    assert!(find_conflicts(&[a, r, am]).is_empty());
}

#[test]
fn approvals_never_transfer_to_a_superseding_proposal() {
    let c = team();
    let old = proposal(1, S, digest(b"A"));
    let new = superseding(1, &old, digest(b"B"), SKILL);
    let votes = [approve(1, &old), approve(2, &old)];
    let t_new = tally(&new, &c, &votes, &nobody_revoked).unwrap();
    assert!(!t_new.passed());
    assert!(t_new.approvals().is_empty());
    // The superseded proposal keeps its own approvals (superseding is not a veto).
    assert!(tally(&old, &c, &votes, &nobody_revoked).unwrap().passed());

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

/// A rule in force, with the tally that passed it.
fn passed_rule() -> (Rule, ph_governance::Tally) {
    let c = team();
    let p = proposal(1, S, digest(b"A"));
    let votes = [approve(1, &p), approve(2, &p)];
    let t = tally(&p, &c, &votes, &nobody_revoked).unwrap();
    let rs = rules_in_force(&c, &[Passed::by_vote(&p, &t, &c).unwrap()]);
    (rs.get(SKILL).unwrap().clone(), t)
}

const CLEAN: BundleChecks = BundleChecks {
    digest_verified: true,
    skill_valid: true,
    high_risk: false,
};

#[test]
fn a_binding_circle_installs_a_passed_rule_and_an_advisory_one_asks() {
    let (rule, _) = passed_rule();
    let none = OwnerChoice::default();
    assert_eq!(AdoptionMode::default_for(true), AdoptionMode::Follow);
    assert_eq!(AdoptionMode::default_for(false), AdoptionMode::Ask);
    assert_eq!(
        adoption_step(&rule, AdoptionMode::Follow, CLEAN, none, true),
        AdoptionStep::Install
    );
    assert_eq!(
        adoption_step(&rule, AdoptionMode::Ask, CLEAN, none, true),
        AdoptionStep::AskOwner(AskReason::AskMode)
    );
    // In ask mode the owner's confirmation installs it.
    let confirmed = OwnerChoice {
        confirmed: true,
        ..none
    };
    assert_eq!(
        adoption_step(&rule, AdoptionMode::Ask, CLEAN, confirmed, true),
        AdoptionStep::Install
    );
}

#[test]
fn no_vote_and_no_confirmation_installs_a_bundle_that_fails_its_checks() {
    let (rule, _) = passed_rule();
    let eager = OwnerChoice {
        opted_out: false,
        confirmed: true,
    };
    for mode in [AdoptionMode::Follow, AdoptionMode::Ask] {
        let bad_digest = BundleChecks {
            digest_verified: false,
            ..CLEAN
        };
        assert_eq!(
            adoption_step(&rule, mode, bad_digest, eager, true),
            AdoptionStep::Refuse(RefuseReason::BundleDigestUnverified)
        );
        let invalid = BundleChecks {
            skill_valid: false,
            ..CLEAN
        };
        assert_eq!(
            adoption_step(&rule, mode, invalid, eager, true),
            AdoptionStep::Refuse(RefuseReason::SkillInvalid)
        );
    }
}

#[test]
fn high_risk_content_always_asks_even_in_a_binding_circle() {
    let (rule, _) = passed_rule();
    let risky = BundleChecks {
        high_risk: true,
        ..CLEAN
    };
    assert_eq!(
        adoption_step(
            &rule,
            AdoptionMode::Follow,
            risky,
            OwnerChoice::default(),
            true
        ),
        AdoptionStep::AskOwner(AskReason::HighRisk)
    );
    // Only the owner's explicit confirmation installs it.
    let confirmed = OwnerChoice {
        opted_out: false,
        confirmed: true,
    };
    assert_eq!(
        adoption_step(&rule, AdoptionMode::Follow, risky, confirmed, true),
        AdoptionStep::Install
    );
}

#[test]
fn an_opt_out_keeps_a_passed_rule_off_this_machine() {
    let (rule, _) = passed_rule();
    let out = OwnerChoice {
        opted_out: true,
        confirmed: false,
    };
    assert_eq!(
        adoption_step(&rule, AdoptionMode::Follow, CLEAN, out, true),
        AdoptionStep::OptedOut
    );
    // Opting out wins over a stale confirmation.
    let both = OwnerChoice {
        opted_out: true,
        confirmed: true,
    };
    assert_eq!(
        adoption_step(&rule, AdoptionMode::Follow, CLEAN, both, true),
        AdoptionStep::OptedOut
    );
}

#[test]
fn a_local_policy_can_hold_a_rule_back_but_not_change_whether_it_passed() {
    let (rule, t) = passed_rule();
    assert!(t.passed());
    let empty = LocalPolicy::default();
    assert!(local_policy_met(&empty, Some(&t)));
    assert!(local_policy_met(&empty, None));

    // "Only follow what bob approved": met, since alice and bob approved.
    let needs_bob = LocalPolicy {
        required_members: vec!["bob".into()],
        min_approvals: None,
    };
    assert!(local_policy_met(&needs_bob, Some(&t)));
    // "Only follow what carol approved": not met, so the owner is asked.
    let needs_carol = LocalPolicy {
        required_members: vec!["carol".into()],
        min_approvals: None,
    };
    assert!(!local_policy_met(&needs_carol, Some(&t)));
    let met = local_policy_met(&needs_carol, Some(&t));
    assert_eq!(
        adoption_step(
            &rule,
            AdoptionMode::Follow,
            CLEAN,
            OwnerChoice::default(),
            met
        ),
        AdoptionStep::AskOwner(AskReason::LocalPolicy)
    );
    // "At least three approvals": two is not enough for this node.
    let three = LocalPolicy {
        required_members: Vec::new(),
        min_approvals: Some(3),
    };
    assert!(!local_policy_met(&three, Some(&t)));
    assert!(local_policy_met(
        &LocalPolicy {
            required_members: Vec::new(),
            min_approvals: Some(2)
        },
        Some(&t)
    ));
    // A carried rule has no tally to check a non-empty policy against: ask.
    assert!(!local_policy_met(&needs_bob, None));
    // None of this changed the outcome of the vote.
    assert!(t.passed());
}

#[test]
fn adoption_step_codes_are_distinct() {
    let all = [
        AdoptionStep::Install,
        AdoptionStep::AskOwner(AskReason::HighRisk),
        AdoptionStep::AskOwner(AskReason::LocalPolicy),
        AdoptionStep::AskOwner(AskReason::AskMode),
        AdoptionStep::OptedOut,
        AdoptionStep::Refuse(RefuseReason::BundleDigestUnverified),
        AdoptionStep::Refuse(RefuseReason::SkillInvalid),
    ];
    let codes: std::collections::HashSet<_> = all.iter().map(|s| s.code()).collect();
    assert_eq!(codes.len(), all.len());
    assert_eq!(AdoptionMode::Follow.as_str(), "follow");
    assert_eq!(AdoptionMode::Ask.as_str(), "ask");
}
