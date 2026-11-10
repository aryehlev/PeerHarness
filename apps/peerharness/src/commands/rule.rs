//! `peerharness rule`: the rules in force, the owner's choices about them, and
//! proposing a repeal (architecture sections 10.4, 10.7 and 10.9).

use anyhow::Result;
use ph_skills::InstallState;
use ph_store::CircleRow;
use serde_json::json;

use crate::cli::RuleCommand;
use crate::commands::circle::find_circle;
use crate::commands::Ctx;
use crate::error::usage;
use crate::governance;
use crate::node::Node;
use crate::output::{safe, short_id, Report, Text};

pub fn run(ctx: &Ctx, command: RuleCommand) -> Result<Report> {
    let node = ctx.open_node()?;
    match command {
        RuleCommand::Repeal {
            name,
            circle,
            reason,
            yes,
        } => {
            let circle = find_circle(&node, Some(&circle))?;
            repeal(ctx, &node, &circle, &name, reason.as_deref(), yes)
        }
        RuleCommand::List { circle } => list(&node, circle.as_deref()),
        RuleCommand::OptOut { name, circle } => {
            let circle = find_circle(&node, Some(&circle))?;
            opt(&node, &circle, &name, true)
        }
        RuleCommand::OptIn { name, circle } => {
            let circle = find_circle(&node, Some(&circle))?;
            opt(&node, &circle, &name, false)
        }
    }
}

fn list(node: &Node, circle: Option<&str>) -> Result<Report> {
    let circles = match circle {
        Some(_) => vec![find_circle(node, circle)?],
        None => node.store.circles()?,
    };
    let installer = governance::user_installer()?;
    let mut rows = Vec::new();
    let mut t = Text::new();
    for c in &circles {
        let (charter, rules, _) = governance::rule_set(&node.store, &c.circle_id)?;
        t.line(format!(
            "{} (charter {}, your mode: {}): {} rule(s) in force",
            safe(&c.name),
            charter.seq,
            c.adoption_mode,
            rules.len()
        ));
        for rule in rules.rules() {
            let opted_out = node
                .store
                .is_rule_opted_out(&c.circle_id, rule.skill_name())?;
            let binds_me = charter
                .content
                .voter(
                    &node.device_key(),
                    &ph_protocol::Electorate::Scope(rule.scope()),
                )
                .is_some();
            let here = match installer.status(rule.skill_name()) {
                _ if !binds_me => "does not bind you: you are not in its electorate",
                Ok(InstallState::Managed { digest, modified })
                    if digest == rule.bundle_digest() =>
                {
                    if modified {
                        "installed, edited by hand"
                    } else {
                        "installed"
                    }
                }
                Ok(InstallState::Managed { .. }) => "another version installed",
                Ok(InstallState::Unmanaged) => {
                    "a skill of that name you manage yourself is in the way"
                }
                _ if opted_out => "opted out",
                _ => "not installed",
            };
            t.line(format!(
                "  {}  scope {}  proposal {}  [{here}]",
                rule.skill_name(),
                rule.scope(),
                short_id(&rule.proposal_id())
            ));
            rows.push(json!({
                "circle": c.name,
                "skill_name": rule.skill_name(),
                "scope": rule.scope(),
                "proposal_id": rule.proposal_id(),
                "bundle_digest": rule.bundle_digest(),
                "opted_out": opted_out,
                "binds_you": binds_me,
                "state": here,
            }));
        }
        for id in rules.missing_carried() {
            t.line(format!(
                "  (a carried rule, proposal {}, has not arrived on this node yet)",
                short_id(id)
            ));
        }
    }
    if circles.is_empty() {
        t.line("This node is in no circle.");
    }
    Ok(Report::new(json!({ "rules": rows }), t.finish()))
}

/// Opts out of (`out == true`) or back into the rule named `name`, then brings the
/// agent's skills directory in line. Only this machine changes.
pub fn opt(node: &Node, circle: &CircleRow, name: &str, out: bool) -> Result<Report> {
    if !ph_core::is_valid_skill_name(name) {
        return Err(usage("that is not a rule (skill) name"));
    }
    let id = &circle.circle_id;
    if out {
        node.store.set_rule_opt_out(id, name, node.now())?;
    } else {
        node.store.clear_rule_opt_out(id, name)?;
    }
    let settled = governance::settle(node, circle, &governance::user_installer()?, &[])?;
    let mut t = Text::new();
    if out {
        t.line(format!(
            "Opted out of {name} in {}. Only this machine changes; the rule stays in force for the circle.",
            safe(&circle.name)
        ));
        if settled.applied.removed.iter().any(|s| s == name) {
            t.line("  removed it from your agent's skills");
        }
        t.line("  Your recorded dissent is your ballot: `peerharness proposal vote <id> reject`.");
    } else {
        t.line(format!("Following {name} again."));
        if settled.applied.installed.iter().any(|s| s == name) {
            t.line("  installed it for your agent");
        }
        for (skill, why) in &settled.applied.asking {
            if skill == name {
                t.line(format!("  it waits for your confirmation ({why})"));
            }
        }
    }
    Ok(Report::new(
        json!({
            "circle": circle.name,
            "skill_name": name,
            "opted_out": out,
            "installed": settled.applied.installed,
            "removed": settled.applied.removed,
        }),
        t.finish(),
    ))
}

/// Puts the repeal of the rule named `name` to the vote of the electorate that adopted
/// it. Creating the proposal is not a vote.
fn repeal(
    ctx: &Ctx,
    node: &Node,
    circle: &CircleRow,
    name: &str,
    reason: Option<&str>,
    yes: bool,
) -> Result<Report> {
    use ph_protocol::{Electorate, ProposalAction};

    let id = &circle.circle_id;
    let (charter, rules, _) = governance::rule_set(&node.store, id)?;
    let rule = rules.get(name).ok_or_else(|| {
        usage(format!(
            "no rule named {name:?} is in force in {}: see `peerharness rule list`",
            circle.name
        ))
    })?;
    // A repeal has the scope of its target, so the same electorate decides.
    let scope = rule.scope().clone();
    let target = rule.proposal_id();
    let summary = match reason {
        Some(r) => {
            let r = ph_core::redact(r.trim()).text;
            ph_protocol::text::check_text(
                "reason",
                &r,
                1,
                ph_protocol::limits::text::SUMMARY,
                ph_protocol::text::Lines::Single,
            )
            .map_err(|_| usage("the reason must be one line of at most 1000 characters"))?;
            r
        }
        None => String::new(),
    };
    let title = format!("Repeal {name}");
    let electorate = charter
        .content
        .electorate(&Electorate::Scope(&scope))
        .count();
    let mut preview = format!(
        "This asks the members of {circle} (scope {scope}) to vote on repealing the rule \
         {name}.\nExactly this text leaves your machine, and nothing else:\n\n  title: {title}",
        circle = safe(&circle.name),
    );
    if !summary.is_empty() {
        preview.push_str(&format!("\n  why: {}", safe(&summary)));
    }
    preview.push_str(&format!(
        "\n\nIt passes with {need} of {electorate} member approval(s). Creating it is not a \
         vote: cast yours with `peerharness proposal vote`.",
        need = charter.content.rules.pass.need(electorate),
    ));
    crate::consent::confirm(&ctx.out, &preview, yes, "sharing the repeal proposal")?;

    let key = node.device()?.signing_key();
    let proposal = governance::propose(
        &node.store,
        key,
        id,
        governance::NewProposal {
            scope: &scope,
            title: &title,
            summary: &summary,
            action: ProposalAction::Repeal { target },
        },
        node.now(),
    )?;
    let mut t = Text::new();
    t.line(format!(
        "Proposed repealing {name} in {} (proposal {}).",
        safe(&circle.name),
        short_id(&proposal.event_id())
    ));
    t.line(format!(
        "Vote: `peerharness proposal vote {} approve`.",
        short_id(&proposal.event_id())
    ));
    t.line(format!(
        "Send it to the others: `peerharness events export --circle {} --out <file>`.",
        circle.name
    ));
    Ok(Report::new(
        json!({
            "proposal_id": proposal.event_id(),
            "kind": "repeal",
            "skill_name": name,
            "target": target,
            "circle": circle.name,
            "scope": scope,
        }),
        t.finish(),
    ))
}
