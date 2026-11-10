//! Candidate merge/dedup and transactional status transitions.

mod common;

use std::sync::{Arc, Barrier};

use common::*;
use ph_core::{
    Actor, CandidateStatus, Confidence, EventId, ObservationId, SkillCandidate, TransitionError,
};
use ph_store::{CandidateId, Store, StoreError};

fn oid(s: &str) -> ObservationId {
    ObservationId::new(s).unwrap()
}

fn cand(evidence: &[&str], confidence: Confidence) -> SkillCandidate {
    SkillCandidate {
        concept_key: "package-manager:pnpm".into(),
        repo_key: "repo1".into(),
        statement: "This repository uses pnpm, not npm.".into(),
        preferred: Some("pnpm".into()),
        avoided: Some("npm".into()),
        confidence,
        evidence: evidence.iter().map(|e| oid(e)).collect(),
        suggested_skill_name: "pnpm-repository-convention".into(),
        topic: "package-manager".into(),
    }
}

#[test]
fn insert_then_merge_dedups_evidence_and_raises_confidence() {
    let s = Store::open_in_memory().unwrap();
    let (id, created) = s
        .insert_or_merge_candidate(&cand(&["o1"], Confidence::Low), now())
        .unwrap();
    assert!(created);
    let row = s.candidate(&id).unwrap().unwrap();
    assert_eq!(row.status, CandidateStatus::Detected);
    assert_eq!(row.confidence, Confidence::Low);
    assert_eq!(row.evidence, vec![oid("o1")]);

    // Same concept + repo: merged, not duplicated.
    let (id2, created2) = s
        .insert_or_merge_candidate(
            &cand(&["o1", "o2", "o2"], Confidence::Low),
            now().plus_secs(5),
        )
        .unwrap();
    assert_eq!(id2, id);
    assert!(!created2);
    let row = s.candidate(&id).unwrap().unwrap();
    assert_eq!(row.evidence, vec![oid("o1"), oid("o2")]);
    assert_eq!(row.confidence, Confidence::Medium);
    assert_eq!(row.updated_at, now().plus_secs(5));
    assert_eq!(row.created_at, now());
    assert_eq!(s.candidates(&[]).unwrap().len(), 1);

    // A different repo is a different candidate.
    let mut other = cand(&["o3"], Confidence::Low);
    other.repo_key = "repo2".into();
    let (id3, created3) = s.insert_or_merge_candidate(&other, now()).unwrap();
    assert!(created3);
    assert_ne!(id3, id);
    assert_eq!(s.candidates(&[]).unwrap().len(), 2);
    assert_eq!(
        s.candidate_by_concept("package-manager:pnpm", "repo2")
            .unwrap()
            .unwrap()
            .id,
        id3
    );
}

#[test]
fn new_candidate_with_two_evidence_items_is_medium() {
    let s = Store::open_in_memory().unwrap();
    let (id, _) = s
        .insert_or_merge_candidate(&cand(&["o1", "o2"], Confidence::Low), now())
        .unwrap();
    assert_eq!(
        s.candidate(&id).unwrap().unwrap().confidence,
        Confidence::Medium
    );
    let (id2, _) = s
        .insert_or_merge_candidate(
            &SkillCandidate {
                concept_key: "k2".into(),
                ..cand(&["o1", "o1"], Confidence::Low)
            },
            now(),
        )
        .unwrap();
    assert_eq!(
        s.candidate(&id2).unwrap().unwrap().confidence,
        Confidence::Low
    );
}

#[test]
fn merge_keeps_human_edits_and_status() {
    let s = Store::open_in_memory().unwrap();
    let (id, _) = s
        .insert_or_merge_candidate(&cand(&["o1"], Confidence::Low), now())
        .unwrap();
    s.update_candidate_status(
        &id,
        CandidateStatus::Detected,
        CandidateStatus::LocalReview,
        Actor::System,
        now(),
    )
    .unwrap();
    s.set_candidate_statement(&id, "Edited by human.", now())
        .unwrap();
    s.insert_or_merge_candidate(&cand(&["o2"], Confidence::Low), now())
        .unwrap();
    let row = s.candidate(&id).unwrap().unwrap();
    assert_eq!(row.statement, "Edited by human.");
    assert_eq!(row.status, CandidateStatus::LocalReview);
    assert_eq!(row.evidence.len(), 2);
}

#[test]
fn rejected_and_terminal_candidates_are_never_resurrected() {
    let s = Store::open_in_memory().unwrap();
    let (id, _) = s
        .insert_or_merge_candidate(&cand(&["o1"], Confidence::Low), now())
        .unwrap();
    s.update_candidate_status(
        &id,
        CandidateStatus::Detected,
        CandidateStatus::Rejected,
        Actor::System,
        now(),
    )
    .unwrap();
    let before = s.candidate(&id).unwrap().unwrap();
    let (id2, created) = s
        .insert_or_merge_candidate(
            &cand(&["o2", "o3"], Confidence::Medium),
            now().plus_secs(60),
        )
        .unwrap();
    assert_eq!(id2, id);
    assert!(!created);
    let after = s.candidate(&id).unwrap().unwrap();
    assert_eq!(after, before, "terminal candidate left untouched");
    assert_eq!(after.status, CandidateStatus::Rejected);
    assert_eq!(s.candidates(&[]).unwrap().len(), 1);

    // Adopted is terminal too.
    let mut c = cand(&["x"], Confidence::Low);
    c.concept_key = "k-adopted".into();
    let (aid, _) = s.insert_or_merge_candidate(&c, now()).unwrap();
    for (from, to, actor) in [
        (
            CandidateStatus::Detected,
            CandidateStatus::LocalReview,
            Actor::System,
        ),
        (
            CandidateStatus::LocalReview,
            CandidateStatus::LocalApproved,
            Actor::Human,
        ),
        (
            CandidateStatus::LocalApproved,
            CandidateStatus::Adopted,
            Actor::Human,
        ),
    ] {
        s.update_candidate_status(&aid, from, to, actor, now())
            .unwrap();
    }
    c.evidence.push(oid("y"));
    s.insert_or_merge_candidate(&c, now()).unwrap();
    let row = s.candidate(&aid).unwrap().unwrap();
    assert_eq!(row.status, CandidateStatus::Adopted);
    assert_eq!(row.evidence, vec![oid("x")]);
}

#[test]
fn invalid_candidate_inputs_are_rejected() {
    let s = Store::open_in_memory().unwrap();
    let mut c = cand(&["o1"], Confidence::Low);
    c.suggested_skill_name = "Not Valid".into();
    assert!(matches!(
        s.insert_or_merge_candidate(&c, now()),
        Err(StoreError::Invalid { .. })
    ));
    let mut c = cand(&["o1"], Confidence::Low);
    c.statement = "x".repeat(5000);
    assert!(matches!(
        s.insert_or_merge_candidate(&c, now()),
        Err(StoreError::Invalid { .. })
    ));
    let mut c = cand(&["o1"], Confidence::Low);
    c.concept_key.clear();
    assert!(matches!(
        s.insert_or_merge_candidate(&c, now()),
        Err(StoreError::Invalid { .. })
    ));
    assert!(s.candidates(&[]).unwrap().is_empty());
}

#[test]
fn status_transitions_are_checked_and_compare_and_set() {
    let s = Store::open_in_memory().unwrap();
    let (id, _) = s
        .insert_or_merge_candidate(&cand(&["o1"], Confidence::Low), now())
        .unwrap();

    // expected_from mismatch.
    let err = s
        .update_candidate_status(
            &id,
            CandidateStatus::LocalReview,
            CandidateStatus::LocalApproved,
            Actor::Human,
            now(),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            StoreError::StatusMismatch {
                expected: CandidateStatus::LocalReview,
                actual: CandidateStatus::Detected
            }
        ),
        "{err:?}"
    );

    s.update_candidate_status(
        &id,
        CandidateStatus::Detected,
        CandidateStatus::LocalReview,
        Actor::System,
        now(),
    )
    .unwrap();

    // Human-only edge refused for System, nothing written.
    let err = s
        .update_candidate_status(
            &id,
            CandidateStatus::LocalReview,
            CandidateStatus::LocalApproved,
            Actor::System,
            now(),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        StoreError::Transition(TransitionError::RequiresHuman { .. })
    ));
    assert_eq!(
        s.candidate(&id).unwrap().unwrap().status,
        CandidateStatus::LocalReview
    );

    // Edge not in the lifecycle.
    let err = s
        .update_candidate_status(
            &id,
            CandidateStatus::LocalReview,
            CandidateStatus::Voting,
            Actor::Human,
            now(),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        StoreError::Transition(TransitionError::NotAllowed { .. })
    ));

    let new = s
        .update_candidate_status(
            &id,
            CandidateStatus::LocalReview,
            CandidateStatus::LocalApproved,
            Actor::Human,
            now().plus_secs(1),
        )
        .unwrap();
    assert_eq!(new, CandidateStatus::LocalApproved);
    let row = s.candidate(&id).unwrap().unwrap();
    assert_eq!(row.status, CandidateStatus::LocalApproved);
    assert_eq!(row.updated_at, now().plus_secs(1));

    // Unknown id.
    let unknown: CandidateId = "cand_0000000000000000".parse().unwrap();
    assert!(matches!(
        s.update_candidate_status(
            &unknown,
            CandidateStatus::Detected,
            CandidateStatus::LocalReview,
            Actor::System,
            now()
        ),
        Err(StoreError::NotFound { .. })
    ));

    // Status filter.
    assert_eq!(
        s.candidates(&[CandidateStatus::LocalApproved])
            .unwrap()
            .len(),
        1
    );
    assert!(s
        .candidates(&[CandidateStatus::Detected, CandidateStatus::Rejected])
        .unwrap()
        .is_empty());
}

#[test]
fn setters() {
    let s = store_with_circle();
    let (id, _) = s
        .insert_or_merge_candidate(&cand(&["o1"], Confidence::Low), now())
        .unwrap();
    s.set_candidate_skill_name(&id, "use-pnpm", now()).unwrap();
    assert!(matches!(
        s.set_candidate_skill_name(&id, "-bad", now()),
        Err(StoreError::Invalid { .. })
    ));
    s.set_candidate_skill_draft(&id, Some("---\nname: use-pnpm\n---\n"), now())
        .unwrap();
    s.set_candidate_share_target(&id, &circle(), &scope("team/backend"), now())
        .unwrap();
    let q = EventId::from_digest(ph_core::Digest::sha256(b"q"));
    let p = EventId::from_digest(ph_core::Digest::sha256(b"p"));
    s.set_candidate_question_event(&id, &q, now()).unwrap();
    s.set_candidate_proposal_event(&id, &p, now()).unwrap();
    let row = s.candidate(&id).unwrap().unwrap();
    assert_eq!(row.skill_name, "use-pnpm");
    assert!(row.skill_draft.as_deref().unwrap().contains("use-pnpm"));
    assert_eq!(row.circle_id, Some(circle()));
    assert_eq!(row.scope, Some(scope("team/backend")));
    assert_eq!(row.question_event_id, Some(q));
    assert_eq!(row.proposal_event_id, Some(p));
    assert_eq!(s.candidate_by_question_event(&q).unwrap().unwrap().id, id);
    assert_eq!(s.candidate_by_proposal_event(&p).unwrap().unwrap().id, id);
    s.set_candidate_skill_draft(&id, None, now()).unwrap();
    assert!(s.candidate(&id).unwrap().unwrap().skill_draft.is_none());

    // Unknown circle violates the foreign key.
    let other = ph_core::CircleId::derive(&pk(9));
    assert!(matches!(
        s.set_candidate_share_target(&id, &other, &scope("x"), now()),
        Err(StoreError::MissingReference)
    ));
    let unknown: CandidateId = "cand_0000000000000000".parse().unwrap();
    assert!(matches!(
        s.set_candidate_statement(&unknown, "x", now()),
        Err(StoreError::NotFound { .. })
    ));
    // Debug does not leak statement text.
    assert!(!format!("{row:?}").contains("pnpm"));
}

/// Two connections on one file: the second one's compare-and-set must fail, not
/// silently overwrite (no lost update).
#[test]
fn lost_update_is_prevented_across_connections() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.db");
    let a = Store::open(&path).unwrap();
    let b = Store::open(&path).unwrap();
    let (id, _) = a
        .insert_or_merge_candidate(&cand(&["o1"], Confidence::Low), now())
        .unwrap();
    a.update_candidate_status(
        &id,
        CandidateStatus::Detected,
        CandidateStatus::LocalReview,
        Actor::System,
        now(),
    )
    .unwrap();

    // Both read LocalReview.
    assert_eq!(
        a.candidate(&id).unwrap().unwrap().status,
        CandidateStatus::LocalReview
    );
    assert_eq!(
        b.candidate(&id).unwrap().unwrap().status,
        CandidateStatus::LocalReview
    );

    // A approves; B, still believing LocalReview, tries to reject.
    a.update_candidate_status(
        &id,
        CandidateStatus::LocalReview,
        CandidateStatus::LocalApproved,
        Actor::Human,
        now(),
    )
    .unwrap();
    let err = b
        .update_candidate_status(
            &id,
            CandidateStatus::LocalReview,
            CandidateStatus::Rejected,
            Actor::Human,
            now(),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        StoreError::StatusMismatch {
            actual: CandidateStatus::LocalApproved,
            ..
        }
    ));
    assert_eq!(
        b.candidate(&id).unwrap().unwrap().status,
        CandidateStatus::LocalApproved
    );
}

/// Many threads race the same transition from separate connections: exactly one wins.
#[test]
fn concurrent_transitions_exactly_one_wins() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.db");
    let id = {
        let s = Store::open(&path).unwrap();
        let (id, _) = s
            .insert_or_merge_candidate(&cand(&["o1"], Confidence::Low), now())
            .unwrap();
        s.update_candidate_status(
            &id,
            CandidateStatus::Detected,
            CandidateStatus::LocalReview,
            Actor::System,
            now(),
        )
        .unwrap();
        id
    };
    let n = 8;
    let barrier = Arc::new(Barrier::new(n));
    let handles: Vec<_> = (0..n)
        .map(|i| {
            let path = path.clone();
            let id = id.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let s = Store::open(&path).unwrap();
                let to = if i % 2 == 0 {
                    CandidateStatus::LocalApproved
                } else {
                    CandidateStatus::Rejected
                };
                barrier.wait();
                s.update_candidate_status(
                    &id,
                    CandidateStatus::LocalReview,
                    to,
                    Actor::Human,
                    now(),
                )
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let wins: Vec<_> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
    assert_eq!(
        wins.len(),
        1,
        "exactly one transition must win: {results:?}"
    );
    for r in &results {
        if let Err(e) = r {
            assert!(
                matches!(e, StoreError::StatusMismatch { .. }),
                "unexpected error {e:?}"
            );
        }
    }
    let s = Store::open(&path).unwrap();
    assert_eq!(s.candidate(&id).unwrap().unwrap().status, *wins[0]);
}
