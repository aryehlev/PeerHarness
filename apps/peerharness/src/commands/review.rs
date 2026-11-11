//! `peerharness review <candidate>`: the owner's decision about a candidate rule.
//!
//! A candidate comes from the pattern detector, from `peerharness note`, or from the
//! owner's agent reporting a correction. None of those decide anything. Here the owner
//! reads the exact text and saves it to their library (`--approve`), changes it
//! (`--edit`) or ignores it (`--reject`). Saving is local: it installs nothing and shares
//! nothing. Every decision here is human-only and refuses inside an agent session.

use anyhow::Result;
use ph_core::{Actor, CandidateStatus};
use ph_store::CandidateRow;
use serde_json::{json, Value};

use super::inbox::candidate_json;
use super::Ctx;
use crate::cli::ReviewArgs;
use crate::consent::{human_only, in_agent_session, interactive, prompt_line};
use crate::error::usage;
use crate::library::{self, clean_statement};
use crate::node::Node;
use crate::output::{safe, Report, Text};

pub fn run(ctx: &Ctx, a: ReviewArgs) -> Result<Report> {
    let node = ctx.open_node()?;
    let mut cand = crate::ids::resolve_candidate(&node.store, &a.candidate)?;
    let deciding = a.approve || a.reject || a.edit.is_some();
    if deciding {
        human_only("reviewing a candidate rule")?;
    }
    cand = shown(&node, cand)?;

    if let Some(text) = a.edit.as_deref() {
        cand = edit(&node, &cand, text)?;
    }
    if a.approve {
        return approve(&node, &cand);
    }
    if a.reject {
        return reject(&node, &cand);
    }
    if a.edit.is_some() {
        return show(&node, &cand, "edited");
    }

    // No decision on the command line: show it, and ask when a person is at a terminal.
    let report = show(&node, &cand, "shown")?;
    let can_ask = cand.status == CandidateStatus::LocalReview
        && !ctx.out.json
        && interactive()
        && !in_agent_session();
    if !can_ask {
        return Ok(report);
    }
    ctx.out.note(report.text.trim_end());
    loop {
        let answer =
            prompt_line("[a] save to your library  [e] edit  [n] ignore  [enter] later: ")?;
        match answer.trim().to_ascii_lowercase().as_str() {
            "a" => return approve(&node, &cand),
            "n" => return reject(&node, &cand),
            "e" => {
                let text = prompt_line("The rule, as one sentence: ")?;
                match edit(&node, &cand, &text) {
                    Ok(c) => {
                        cand = c;
                        ctx.out.note(show(&node, &cand, "edited")?.text.trim_end());
                    }
                    Err(e) => ctx.out.warn(e.to_string()),
                }
            }
            "" => return Ok(Report::new(report.json, "Left for later.")),
            _ => ctx.out.note("Please answer a, e, n or press enter."),
        }
    }
}

/// A candidate the owner looks at has been shown: `Detected` becomes `LocalReview`.
/// Inside a coding agent's session it is the agent that looks, and nothing changes
/// (ADR-051): the Stop notice still tells the owner that the note waits.
fn shown(node: &Node, mut cand: CandidateRow) -> Result<CandidateRow> {
    if cand.status == CandidateStatus::Detected && !in_agent_session() {
        match node.store.update_candidate_status(
            &cand.id,
            CandidateStatus::Detected,
            CandidateStatus::LocalReview,
            Actor::System,
            node.now(),
        ) {
            Ok(s) => cand.status = s,
            Err(ph_store::StoreError::StatusMismatch { actual, .. }) => cand.status = actual,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(cand)
}

fn reload(node: &Node, cand: &CandidateRow) -> Result<CandidateRow> {
    node.store
        .candidate(&cand.id)?
        .ok_or_else(|| anyhow::anyhow!("the candidate disappeared"))
}

/// The draft SKILL.md, or why there is none.
fn draft(cand: &CandidateRow) -> Result<(String, String)> {
    let (name, md) = library::render_candidate_skill(cand)?;
    crate::agent_notes::refuse_reserved_name(&name)?;
    ph_skills::build_bundle(&md, Some(&name))
        .map_err(|e| usage(format!("this text cannot become a rule: {e}")))?;
    Ok((name, md))
}

fn show(node: &Node, cand: &CandidateRow, action: &str) -> Result<Report> {
    let mut t = Text::new();
    t.line(format!("\"{}\"", safe(&cand.statement)));
    t.kv("candidate", &cand.id);
    t.kv("status", cand.status);
    t.kv("origin", library::origin_label(cand));
    if !library::is_note(cand) {
        t.kv(
            "seen",
            format!(
                "{} time(s), {} confidence",
                cand.evidence.len(),
                cand.confidence.as_str()
            ),
        );
    }
    let mut json = json!({ "action": action, "candidate": candidate_json(cand) });
    match draft(cand) {
        Ok((name, md)) => {
            let findings = ph_skills::scan(&md);
            t.line(format!(
                "As a skill for your agent ({name}, {} bytes, {} scanner finding(s)):",
                md.len(),
                findings.len()
            ));
            t.line("");
            t.line(safe(&md).trim_end());
            t.line("");
            for f in &findings {
                t.line(format!("  scanner, line {}: {}", f.line, f.explanation()));
            }
            json["skill_name"] = Value::String(name);
            json["skill_md"] = Value::String(md);
        }
        Err(e) => {
            t.line(format!("It cannot become a skill as written: {e}"));
        }
    }
    if cand.status == CandidateStatus::LocalReview {
        t.line(format!(
            "Save it: `peerharness review {id} --approve`. Change it: `--edit \"...\"`. \
             Ignore it: `--reject`.",
            id = cand.id
        ));
    } else if !cand.status.is_terminal() {
        next_steps(node, cand, &mut t)?;
    }
    Ok(Report::new(json, t.finish()))
}

fn next_steps(node: &Node, cand: &CandidateRow, t: &mut Text) -> Result<()> {
    t.line(format!(
        "Use it yourself: `peerharness skills install {}` (add `--scope project` to keep \
         it to the repository you are in).",
        cand.skill_name
    ));
    match node.store.circles()?.first() {
        Some(c) => t.line(format!(
            "Ask the circle first: `peerharness question send {} --circle {}`. Or put it \
             to the vote: `peerharness proposal create {} --circle {}`.",
            cand.id, c.name, cand.id, c.name
        )),
        None => t.line(
            "Put it to a vote: found a circle with `peerharness circle create <name>` first.",
        ),
    };
    Ok(())
}

fn edit(node: &Node, cand: &CandidateRow, text: &str) -> Result<CandidateRow> {
    if !matches!(
        cand.status,
        CandidateStatus::LocalReview | CandidateStatus::LocalApproved
    ) {
        return Err(usage(format!(
            "this candidate is {} and can no longer be edited: write the new rule down with \
             `peerharness note`",
            cand.status
        )));
    }
    let statement = clean_statement(text)?;
    let mut edited = cand.clone();
    edited.statement = statement.clone();
    // Refuse an edit that could not become a skill, before storing it.
    draft(&edited)?;
    node.store
        .set_candidate_statement(&cand.id, &statement, node.now())?;
    reload(node, cand)
}

fn approve(node: &Node, cand: &CandidateRow) -> Result<Report> {
    if cand.status.is_terminal() {
        return Err(usage(format!("this candidate is {}", cand.status)));
    }
    // Before anything moves: a rule that could not be saved is not approved either.
    draft(cand)?;
    let now = node.now();
    if cand.status == CandidateStatus::LocalReview {
        node.store.update_candidate_status(
            &cand.id,
            CandidateStatus::LocalReview,
            CandidateStatus::LocalApproved,
            Actor::Human,
            now,
        )?;
    }
    let cand = reload(node, cand)?;
    let (skill_id, bundle, created) =
        library::create_local_skill(&node.home, &node.store, &cand, now)?;
    let cand = reload(node, &cand)?;
    let mut t = Text::new();
    t.line(format!(
        "{} rule {} in your library (skill {skill_id}). Nothing was installed or shared.",
        if created { "Saved" } else { "Kept" },
        bundle.name()
    ));
    next_steps(node, &cand, &mut t)?;
    Ok(Report::new(
        json!({
            "action": "approved",
            "candidate": candidate_json(&cand),
            "skill_id": skill_id,
            "skill_name": bundle.name(),
            "bundle_digest": bundle.digest(),
            "created": created,
        }),
        t.finish(),
    ))
}

fn reject(node: &Node, cand: &CandidateRow) -> Result<Report> {
    if cand.status.is_terminal() {
        return Err(usage(format!("this candidate is already {}", cand.status)));
    }
    node.store.update_candidate_status(
        &cand.id,
        cand.status,
        CandidateStatus::Rejected,
        Actor::Human,
        node.now(),
    )?;
    let cand = reload(node, cand)?;
    Ok(Report::new(
        json!({ "action": "rejected", "candidate": candidate_json(&cand) }),
        "Ignored. It will not be suggested again.",
    ))
}
