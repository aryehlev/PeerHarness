//! `peerharness inbox`: a bounded summary of candidates to review, received questions
//! and proposals waiting for the owner's vote (`governance::awaiting_vote`). Showing a Detected candidate moves it to
//! LocalReview (System).

use anyhow::Result;
use ph_core::{Actor, CandidateStatus};
use ph_store::{CandidateRow, QuestionStatus};
use serde_json::{json, Value};

use super::Ctx;
use crate::cli::InboxArgs;
use crate::detect;
use crate::output::{continued, safe, short_id, Report, Text, MEMBERS_WORDS};

pub fn run(ctx: &Ctx, a: InboxArgs) -> Result<Report> {
    let node = ctx.open_node()?;
    let now = node.now();
    let limit = a.limit as usize;
    let retention = node.config.retention.observation_secs();
    detect::drain_spool(&node.home.spool_path(), &node.store, retention);
    let purged = node.store.purge_expired_observations(now)?;
    if purged > 0 {
        tracing::info!(purged, "expired observations purged");
    }
    detect::run_detection(&node.store, None, retention, now)?;

    // Candidates.
    let all = node
        .store
        .candidates(&[CandidateStatus::Detected, CandidateStatus::LocalReview])?;
    let total_candidates = all.len();
    let mut shown: Vec<CandidateRow> = Vec::new();
    for mut c in all.into_iter().take(limit) {
        if c.status == CandidateStatus::Detected {
            match node.store.update_candidate_status(
                &c.id,
                CandidateStatus::Detected,
                CandidateStatus::LocalReview,
                Actor::System,
                now,
            ) {
                Ok(s) => c.status = s,
                Err(ph_store::StoreError::StatusMismatch { actual, .. }) => c.status = actual,
                Err(e) => return Err(e.into()),
            }
        }
        shown.push(c);
    }

    // Received questions.
    let questions = node.store.inbox(&[QuestionStatus::New])?;
    let total_questions = questions.len();

    // Proposals that wait for the owner's ballot (the same count the Stop notice uses).
    let mut awaiting: Vec<Value> = Vec::new();
    let mut awaiting_text: Vec<String> = Vec::new();
    for (circle, p) in crate::governance::awaiting_vote(&node.store, &node.device_key())? {
        awaiting.push(json!({
            "proposal_id": p.event_id(),
            "circle": circle.name,
            "scope": p.scope(),
            "kind": p.kind().as_str(),
            "skill_name": p.skill_name(),
            "title": p.body().title,
            "author_fingerprint": p.author().fingerprint(),
        }));
        awaiting_text.push(format!(
            "  {}  {} [{} / {}] by {}",
            short_id(&p.event_id()),
            safe(&p.body().title),
            safe(&circle.name),
            p.scope(),
            p.author().fingerprint()
        ));
    }
    let total_awaiting = awaiting.len();
    awaiting.truncate(limit);
    awaiting_text.truncate(limit);

    let json = json!({
        "candidates": shown.iter().map(candidate_json).collect::<Vec<_>>(),
        "candidates_total": total_candidates,
        "questions": questions.iter().take(limit).map(|q| json!({
            "question_id": q.event_id,
            "circle_id": q.circle_id,
            "scope": q.scope,
            "author_fingerprint": q.author.fingerprint(),
            "topic": q.topic,
            "question": q.question,
            "received_at": q.received_at,
        })).collect::<Vec<_>>(),
        "questions_total": total_questions,
        "proposals_awaiting_vote": awaiting,
        "proposals_awaiting_vote_total": total_awaiting,
    });

    let mut t = Text::new();
    if shown.is_empty() {
        t.line("No candidate conventions to review.");
    } else {
        t.line(format!(
            "Candidate conventions to review ({total_candidates}):"
        ));
        for c in &shown {
            let how = if crate::library::is_note(c) {
                crate::library::origin_label(c).to_owned()
            } else {
                format!(
                    "{} confidence, {} observation(s)",
                    c.confidence.as_str(),
                    c.evidence.len()
                )
            };
            // What PeerHarness says about a row stands before the text of the row
            // (ADR-050): a statement cannot end with a label of its own.
            t.line(format!(
                "  {}  ({how}, repo {})  \"{}\"",
                c.id,
                safe(&c.repo_key),
                continued(&c.statement, MEMBERS_WORDS),
            ));
        }
        more(&mut t, total_candidates, shown.len());
        t.line("  Review one with `peerharness review <candidate-id>`.");
    }
    if total_questions > 0 {
        t.line(format!("Questions from your circles ({total_questions}):"));
        for q in questions.iter().take(limit) {
            t.line(format!(
                "  {}  from {}, scope {}: {}",
                short_id(&q.event_id),
                q.author.fingerprint(),
                q.scope,
                continued(&q.question, MEMBERS_WORDS),
            ));
        }
        more(&mut t, total_questions, limit.min(total_questions));
    }
    if total_awaiting > 0 {
        t.line(format!(
            "Proposals waiting for your vote ({total_awaiting}):"
        ));
        for l in &awaiting_text {
            t.line(l);
        }
        more(&mut t, total_awaiting, awaiting_text.len());
    }
    Ok(Report::new(json, t.finish()))
}

fn more(t: &mut Text, total: usize, shown: usize) {
    if total > shown {
        t.line(format!("  ... and {} more (use --limit)", total - shown));
    }
}

pub fn candidate_json(c: &CandidateRow) -> Value {
    json!({
        "id": c.id.to_string(),
        "status": c.status.as_str(),
        "statement": c.statement,
        "preferred": c.preferred,
        "avoided": c.avoided,
        "origin": crate::library::origin_label(c),
        "confidence": c.confidence.as_str(),
        "evidence_count": c.evidence.len(),
        "repo": c.repo_key,
        "skill_name": c.skill_name,
        "topic": c.topic,
        "created_at": c.created_at,
        "updated_at": c.updated_at,
    })
}
