//! `peerharness keep <candidate>`: the owner keeps a noted rule for their own agent, in
//! one step (ADR-040).
//!
//! It is `review --approve` followed by `skills install`: the rule is saved to the
//! owner's library and installed for their agent, for them alone. Nothing is shared.
//! The owner sees the exact text that would be installed and where, and confirms once.
//!
//! Like every consent step it is refused inside a coding agent's session, unless the
//! owner allowed it to be asked in a window (`consent::confirm_own_or_window`). Then
//! the window shows that exact text, and only a click on "Proceed" installs it. An
//! agent can note a rule and can open this window. It cannot give itself an
//! instruction.
//!
//! What it leaves to the two commands it stands for, in the owner's terminal: a rule
//! with a high-risk scanner finding, a skill of that name the owner wrote or edited,
//! and installing for one project only.

use anyhow::{anyhow, Result};
use ph_core::{Actor, CandidateStatus};
use ph_skills::{InstallOptions, InstallState, SkillScope};
use serde_json::json;

use super::Ctx;
use crate::cli::KeepArgs;
use crate::consent::confirm_own_or_window;
use crate::error::{refused, usage};
use crate::library;
use crate::output::{safe, Report, Text};

pub fn run(ctx: &Ctx, a: &KeepArgs) -> Result<Report> {
    let node = ctx.open_node()?;
    let cand = crate::ids::resolve_candidate(&node.store, &a.candidate)?;
    if cand.status.is_terminal() {
        return Err(usage(format!("this candidate is {}", cand.status)));
    }
    // Draft the skill for the preview. Nothing is saved until the owner has confirmed.
    let (name, md) = library::render_candidate_skill(&cand)?;
    crate::agent_notes::refuse_reserved_name(&name)?;
    let draft = ph_skills::build_bundle(&md, Some(&name))
        .map_err(|e| usage(format!("this text cannot become a rule: {e}")))?;
    let terminal = format!(
        "Decide it in your own terminal: `peerharness review {id}`, then `peerharness \
         review {id} --approve` and `peerharness skills install {name}`.",
        id = cand.id
    );
    if ph_skills::has_high_risk(&draft.scan()) {
        return Err(refused(format!(
            "this rule has high-risk scanner findings, so it is not kept in one step. \
             {terminal}"
        )));
    }
    let installer = crate::governance::user_installer()?;
    let dir = installer
        .skill_dir(&name)
        .map_err(|e| anyhow!("cannot locate the skill directory: {e}"))?;
    let state = installer
        .status(&name)
        .map_err(|e| anyhow!("cannot inspect the skill directory: {e}"))?;
    let already = match state {
        InstallState::NotInstalled => false,
        InstallState::Managed {
            digest,
            modified: false,
        } if digest == draft.digest() => true,
        // Replacing something is shown as a difference, which is the terminal's job.
        _ => {
            return Err(refused(format!(
                "a skill named {name} is already installed for your agent, with another \
                 text. {terminal}"
            )))
        }
    };

    if already {
        // Exactly this text is installed already: there is nothing to ask about.
        return Ok(Report::new(
            json!({
                "skill_name": name,
                "bundle_digest": draft.digest(),
                "path": dir,
                "installed": false,
            }),
            format!(
                "Rule {name} is already kept: it is installed at {}.",
                dir.display()
            ),
        ));
    }

    let mut preview = format!(
        "This keeps the following rule for your own agent. It is installed at {dir} and \
         your agent reads it from its next session. Nothing is shared with anyone.\n\n\
         {md}\n",
        dir = dir.display(),
        md = safe(draft.skill_md()).trim_end(),
    );
    // What the scanner finds in the text, as on a ballot and before an install. (A
    // high-risk finding was refused above.) Without a finding this adds nothing, and
    // the preview reads as it always did.
    crate::commands::proposal::findings_preview(&mut preview, &draft);
    if !preview.ends_with('\n') {
        preview.push('\n');
    }
    preview.push_str(&format!(
        "\nTake it out again with `peerharness skills uninstall {name}`."
    ));
    confirm_own_or_window(&ctx.out, &preview, a.yes, "keeping the rule", &node.config)?;

    // Confirmed: the owner has read it and said yes. Save exactly that text, then
    // install it.
    let now = node.now();
    let mut status = cand.status;
    for (next, by) in [
        (CandidateStatus::LocalReview, Actor::System),
        (CandidateStatus::LocalApproved, Actor::Human),
    ] {
        if status.can_transition_to(next) {
            status = node
                .store
                .update_candidate_status(&cand.id, status, next, by, now)?;
        }
    }
    let cand = node
        .store
        .candidate(&cand.id)?
        .ok_or_else(|| anyhow!("the candidate disappeared"))?;
    let (skill_id, bundle, _) = library::create_local_skill(&node.home, &node.store, &cand, now)?;
    if bundle.digest() != draft.digest() {
        return Err(anyhow!(
            "the rule's text changed while it was being confirmed: nothing was installed"
        ));
    }
    let outcome = installer
        .install(&bundle, InstallOptions::default())
        .map_err(|e| anyhow!("cannot install the skill: {e}"))?;
    crate::installs::record_install(&node.store, SkillScope::User, &bundle, &outcome, now)?;

    let mut t = Text::new();
    t.line(format!(
        "Kept rule {name}: installed at {}.",
        outcome.path.display()
    ));
    t.line("Your agent reads it from its next session. Nothing was shared.");
    Ok(Report::new(
        json!({
            "skill_name": name,
            "skill_id": skill_id,
            "bundle_digest": bundle.digest(),
            "path": outcome.path,
            "installed": true,
        }),
        t.finish(),
    ))
}
