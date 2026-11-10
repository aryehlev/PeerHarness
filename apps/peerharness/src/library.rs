//! The local skill library: drafting skills from candidates and storing immutable,
//! content-addressed bundles (`$PEERHARNESS_HOME/bundles/<hex>/SKILL.md` plus the
//! `bundles` and `skills` tables).
use anyhow::{Context, Result};
use ph_core::{SkillCandidate, Timestamp};
use ph_skills::{Bundle, BundleStore};
use ph_store::{BundleRow, CandidateRow, NewSkill, SkillOrigin, SkillStatus, Store};

use crate::error::usage;
use crate::home::Home;

/// Longest human-edited statement.
pub const MAX_STATEMENT_CHARS: usize = 500;

pub fn bundle_store(home: &Home) -> BundleStore {
    BundleStore::new(home.bundles_dir())
}

/// The candidate as a detector-style `SkillCandidate` (for ph-learning drafts).
pub fn as_skill_candidate(c: &CandidateRow) -> SkillCandidate {
    SkillCandidate {
        concept_key: c.concept_key.clone(),
        repo_key: c.repo_key.clone(),
        statement: c.statement.clone(),
        preferred: c.preferred.clone(),
        avoided: c.avoided.clone(),
        confidence: c.confidence,
        evidence: c.evidence.clone(),
        suggested_skill_name: c.skill_name.clone(),
        topic: c.topic.clone(),
    }
}

/// Whether the statement differs from the one the detector derives (so a human edited
/// it).
pub fn statement_was_edited(c: &CandidateRow) -> bool {
    let auto = ph_learning::detector::statement_for(c.preferred.as_deref(), c.avoided.as_deref());
    c.statement.trim() != auto.trim()
}

/// Validates and redacts a human-edited statement.
pub fn clean_statement(s: &str) -> Result<String> {
    let s = s.trim();
    ph_protocol::text::check_text(
        "statement",
        s,
        1,
        MAX_STATEMENT_CHARS,
        ph_protocol::text::Lines::Single,
    )
    .map_err(|_| {
        usage(format!(
            "the statement must be a single line of 1-{MAX_STATEMENT_CHARS} characters without control characters"
        ))
    })?;
    Ok(ph_core::redact(s).text)
}

/// Whether the candidate is a note: a rule written down as free text by the person or
/// reported by their agent, rather than found by the pattern detector.
pub fn is_note(c: &CandidateRow) -> bool {
    ph_learning::is_note_key(&c.concept_key)
}

/// The display label of a note origin.
pub fn origin_label_of(origin: ph_learning::NoteOrigin) -> &'static str {
    match origin {
        ph_learning::NoteOrigin::Written => "written down",
        ph_learning::NoteOrigin::AgentReported => "reported by your agent",
    }
}

/// How a candidate came to be, for display.
pub fn origin_label(c: &CandidateRow) -> &'static str {
    ph_learning::note_origin(&c.concept_key, &c.topic).map_or("detected", origin_label_of)
}

/// Renders the SKILL.md for a candidate.
///
/// * A note: the statement itself, redacted, under a title (`ph_learning::draft_note_skill`).
/// * A detected candidate: the ph-learning template built only from the validated
///   preferred/avoided tokens, plus the statement when a human edited it.
pub fn render_candidate_skill(c: &CandidateRow) -> Result<(String, String)> {
    if is_note(c) {
        let mut cand = as_skill_candidate(c);
        cand.statement = clean_statement(&c.statement)?;
        let draft = ph_learning::draft_note_skill(&cand);
        let md = ph_skills::render_skill_md(&draft.name, &draft.description, &draft.body, None)
            .map_err(|e| anyhow::anyhow!("cannot render the skill: {e}"))?;
        return Ok((draft.name, md));
    }
    let draft = ph_learning::draft_skill(&as_skill_candidate(c));
    let mut body = draft.body.clone();
    if statement_was_edited(c) {
        let st = clean_statement(&c.statement)?;
        body.push_str("\n\nConvention as reviewed locally: ");
        body.push_str(&st);
        body.push('\n');
    }
    let md = ph_skills::render_skill_md(&draft.name, &draft.description, &body, None)
        .map_err(|e| anyhow::anyhow!("cannot render the skill: {e}"))?;
    Ok((draft.name, md))
}

/// Builds, validates and stores a bundle; records it in the `bundles` table.
pub fn store_bundle(
    home: &Home,
    store: &Store,
    md: &str,
    name: &str,
    now: Timestamp,
) -> Result<Bundle> {
    let bundle = ph_skills::build_bundle(md, Some(name))
        .map_err(|e| anyhow::anyhow!("the skill draft is invalid: {e}"))?;
    bundle_store(home)
        .put(&bundle)
        .map_err(|e| anyhow::anyhow!("cannot store the bundle: {e}"))?;
    store
        .insert_bundle(&BundleRow {
            digest: bundle.digest(),
            skill_name: bundle.name().to_owned(),
            manifest: bundle.manifest().clone(),
            rel_path: format!(
                "{}/{}",
                crate::home::BUNDLES_DIR,
                BundleStore::relative_path(&bundle.digest())
            ),
            size: bundle.size(),
            created_at: now,
        })
        .context("cannot record the bundle")?;
    Ok(bundle)
}

/// Drafts the candidate's skill, stores the bundle and adds a `skills` row (origin
/// local). Idempotent per (name, digest). Returns (skill id, bundle, created).
pub fn create_local_skill(
    home: &Home,
    store: &Store,
    c: &CandidateRow,
    now: Timestamp,
) -> Result<(i64, Bundle, bool)> {
    let (name, md) = render_candidate_skill(c)?;
    let bundle = store_bundle(home, store, &md, &name, now)?;
    store.transaction(|s| {
        if name != c.skill_name {
            s.set_candidate_skill_name(&c.id, &name, now)?;
        }
        s.set_candidate_skill_draft(&c.id, Some(&md), now)?;
        Ok(())
    })?;
    let (id, created) = store.insert_skill(&NewSkill {
        name,
        bundle_digest: bundle.digest(),
        origin_kind: SkillOrigin::Local,
        origin_ref: c.id.to_string(),
        status: SkillStatus::Available,
        created_at: now,
    })?;
    Ok((id, bundle, created))
}
