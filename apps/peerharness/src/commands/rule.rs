//! `peerharness rule`: the rules in force, the owner's choices about them, and
//! proposing a repeal (architecture sections 10.4, 10.7 and 10.9).

use anyhow::Result;
use ph_protocol::Stance;
use ph_skills::InstallState;
use ph_store::CircleRow;
use serde_json::json;

use crate::cli::RuleCommand;
use crate::commands::circle::find_circle;
use crate::commands::Ctx;
use crate::error::{refused, usage};
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
        RuleCommand::OptOut {
            name,
            circle,
            announce,
            reason,
            yes,
        } => {
            let circle = find_circle(&node, Some(&circle))?;
            if announce {
                // Checked before anything changes, so a typo announces nothing.
                rule_in_force(&node, &circle, &name)?;
            }
            let report = opt(&node, &circle, &name, true)?;
            if announce {
                let said = Stance::OptedOut;
                return put_on_record(
                    ctx,
                    &node,
                    &circle,
                    &name,
                    said,
                    reason.as_deref(),
                    yes,
                    report,
                );
            }
            Ok(report)
        }
        RuleCommand::OptIn {
            name,
            circle,
            announce,
            yes,
        } => {
            let circle = find_circle(&node, Some(&circle))?;
            if announce {
                rule_in_force(&node, &circle, &name)?;
            }
            let report = opt(&node, &circle, &name, false)?;
            if announce {
                return put_on_record(
                    ctx,
                    &node,
                    &circle,
                    &name,
                    Stance::Following,
                    None,
                    yes,
                    report,
                );
            }
            Ok(report)
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
            let recorded = governance::stances(
                &node.store,
                &c.circle_id,
                &rule.proposal_id(),
                &node.device_key(),
            )?;
            let out_of_it: Vec<String> = recorded
                .iter()
                .filter(|s| s.stance == Stance::OptedOut)
                .map(|s| match s.reason.as_deref().filter(|r| !r.is_empty()) {
                    Some(r) => format!("{} ({})", s.member, safe(r)),
                    None => s.member.clone(),
                })
                .collect();
            if !out_of_it.is_empty() {
                t.line(format!(
                    "      on record as opted out: {}",
                    out_of_it.join(", ")
                ));
            }
            rows.push(json!({
                "circle": c.name,
                "skill_name": rule.skill_name(),
                "scope": rule.scope(),
                "proposal_id": rule.proposal_id(),
                "bundle_digest": rule.bundle_digest(),
                "opted_out": opted_out,
                "binds_you": binds_me,
                "state": here,
                "on_record": recorded.iter().map(|s| json!({
                    "member": s.member,
                    "stance": s.stance.as_str(),
                    "reason": s.reason,
                })).collect::<Vec<_>>(),
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
        t.line(format!(
            "  Nobody else is told. To put it on the circle's record: \
             `peerharness rule opt-out {name} --circle {} --announce`.",
            circle.name
        ));
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

/// The rule named `name` in force in `circle`, which must bind this node's owner.
fn rule_in_force(node: &Node, circle: &CircleRow, name: &str) -> Result<ph_governance::Rule> {
    let (charter, rules, _) = governance::rule_set(&node.store, &circle.circle_id)?;
    let rule = rules.get(name).ok_or_else(|| {
        usage(format!(
            "no rule named {name:?} is in force in {}, so there is nothing to put on record \
             (without --announce, an opt-out also keeps a future rule of that name off this \
             machine)",
            circle.name
        ))
    })?;
    let bound = charter
        .content
        .voter(
            &node.device_key(),
            &ph_protocol::Electorate::Scope(rule.scope()),
        )
        .is_some();
    if !bound {
        return Err(usage(format!(
            "{name} does not bind you (you are not in its electorate), so there is no stance \
             of yours to record"
        )));
    }
    Ok(rule.clone())
}

/// After the change on this machine (`done`): asks the owner whether to tell the circle,
/// and signs the STANCE if they confirm. The local change stands either way: an opt-out
/// never depends on anyone's permission, including this prompt's.
#[allow(clippy::too_many_arguments)]
fn put_on_record(
    ctx: &Ctx,
    node: &Node,
    circle: &CircleRow,
    name: &str,
    stance: Stance,
    reason: Option<&str>,
    yes: bool,
    mut done: Report,
) -> Result<Report> {
    let rule = rule_in_force(node, circle, name)?;
    let reason = reason
        .map(|r| ph_core::redact(r.trim()).text)
        .filter(|r| !r.is_empty());
    if reason.as_ref().is_some_and(|r| r.chars().count() > 2000) {
        return Err(usage("a reason is at most 2000 characters"));
    }
    let what = match stance {
        Stance::OptedOut => "do not follow",
        Stance::Following => "follow",
    };
    let mut preview = format!(
        "This tells the members of {circle} (scope {scope}) that you {what} the rule {name}.\n\
         Exactly this leaves your machine, signed with your device key:\n  \
         rule: {name} (proposal {id})\n  stance: {stance}",
        circle = safe(&circle.name),
        scope = rule.scope(),
        id = short_id(&rule.proposal_id()),
        stance = stance.as_str(),
    );
    if let Some(r) = &reason {
        preview.push_str(&format!("\n  reason: {}", safe(r)));
    }
    preview.push_str(
        "\nIt is a permanent record with your name. It changes nothing about the rule: it \
         stays in force for the circle, and what is on your machine is already your choice.",
    );
    if let Err(e) = crate::consent::confirm(&ctx.out, &preview, yes, "putting it on the record") {
        return Err(refused(format!(
            "{} Nothing was announced: {e}",
            done.text.trim_end()
        )));
    }
    let key = node.device()?.signing_key();
    let env = governance::announce_stance(
        &node.store,
        key,
        &circle.circle_id,
        &rule,
        stance,
        reason,
        node.now(),
    )?;
    done.json["announced"] = json!(true);
    done.json["stance_id"] = json!(env.event_id);
    done.text.push_str(&format!(
        "On the circle's record: you {what} {name}. It reaches the others with your next \
         `peerharness sync` or `events sync`.\n"
    ));
    Ok(done)
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
