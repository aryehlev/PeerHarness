//! `peerharness note "<rule>"`: write a rule down as one sentence.
//!
//! The pattern detector only recognizes "use X, not Y". This is the direct way in: the
//! person types the rule, or their coding agent reports a correction it was just given
//! (`--from-agent`). Either way the result is a **candidate** in the inbox and nothing
//! more: nothing is installed, shared or approved here, and no step that needs consent is
//! reachable from this command. `--from-agent` is a label for the inbox, not a privilege.

use anyhow::Result;
use ph_core::CandidateStatus;
use ph_learning::{draft_note_skill, note_candidate, NoteOrigin};
use serde_json::json;

use super::Ctx;
use crate::cli::NoteArgs;
use crate::error::{refused, usage};
use crate::library::{self, clean_statement};
use crate::output::{safe, Report, Text};

/// Unreviewed agent-reported notes kept at once. More are refused until the person
/// reviews some, so a looping agent cannot bury the inbox.
pub const MAX_PENDING_AGENT_NOTES: usize = 20;

/// The repository key for the current directory, as the hooks derive it.
fn current_repo_key() -> String {
    std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(ph_observer::repo_key))
        .unwrap_or_else(|| ph_observer::hook::UNKNOWN_REPO_KEY.to_owned())
}

pub fn run(ctx: &Ctx, a: NoteArgs) -> Result<Report> {
    let node = ctx.open_node()?;
    let now = node.now();
    let origin = if a.from_agent {
        NoteOrigin::AgentReported
    } else {
        NoteOrigin::Written
    };
    let statement = clean_statement(&a.text)?;
    let redacted = statement != a.text.trim();
    if let Some(n) = a.name.as_deref() {
        if !ph_core::is_valid_skill_name(n) {
            return Err(usage(
                "--name must be 1-64 characters of a-z, 0-9 and single hyphens",
            ));
        }
    }
    let cand = note_candidate(&statement, &current_repo_key(), origin, a.name.as_deref())
        .ok_or_else(|| usage("the rule must be one line of 1-500 characters"))?;

    // Refuse now what could never become a skill, instead of at review time.
    let draft = draft_note_skill(&cand);
    ph_skills::render_skill_md(&draft.name, &draft.description, &draft.body, None)
        .map_err(|e| e.to_string())
        .and_then(|md| ph_skills::build_bundle(&md, Some(&draft.name)).map_err(|e| e.to_string()))
        .map_err(|e| usage(format!("that text cannot become a rule: {e}")))?;

    if let Some(existing) = node
        .store
        .candidate_by_concept(&cand.concept_key, &cand.repo_key)?
    {
        let mut t = Text::new();
        if a.from_agent {
            t.line("Already noted. Nothing else to do.");
        } else {
            t.line(format!(
                "Already noted as {} ({}).",
                existing.id, existing.status
            ));
            if !existing.status.is_terminal() {
                t.line(format!("Next: `peerharness review {}`.", existing.id));
            }
        }
        return Ok(Report::new(
            json!({
                "candidate_id": existing.id.to_string(),
                "created": false,
                "status": existing.status.as_str(),
                "skill_name": existing.skill_name,
            }),
            t.finish(),
        ));
    }

    if a.from_agent {
        let pending = node
            .store
            .candidates(&[CandidateStatus::Detected, CandidateStatus::LocalReview])?
            .iter()
            .filter(|c| {
                ph_learning::note_origin(&c.concept_key, &c.topic)
                    == Some(NoteOrigin::AgentReported)
            })
            .count();
        if pending >= MAX_PENDING_AGENT_NOTES {
            return Err(refused(format!(
                "{pending} agent-reported notes already wait for review. Nothing was added: \
                 the user reviews them with `peerharness inbox`."
            )));
        }
    }

    let (id, created) = node.store.insert_or_merge_candidate(&cand, now)?;
    let mut t = Text::new();
    if a.from_agent {
        // Read by the agent: say what happened and that its part is over.
        t.line(
            if node.config.agent.asked() != crate::config::Asked::Nothing {
                "Noted for the user's review. Start nothing else unless the user asks you to."
            } else {
                "Noted for the user's review. Do not run any other peerharness command."
            },
        );
    } else {
        t.line(format!("Noted: \"{}\"", safe(&statement)));
        if redacted {
            t.line("  (something that looked like a secret or a personal path was redacted)");
        }
        t.line(format!(
            "  candidate {id}, would become the skill {}",
            draft.name
        ));
        t.line(format!(
            "Next: `peerharness review {id} --approve` saves it to your library."
        ));
    }
    Ok(Report::new(
        json!({
            "candidate_id": id.to_string(),
            "created": created,
            "status": CandidateStatus::Detected.as_str(),
            "statement": statement,
            "skill_name": draft.name,
            "origin": library::origin_label_of(origin),
            "redacted": redacted,
        }),
        t.finish(),
    ))
}
