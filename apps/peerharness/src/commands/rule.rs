//! `peerharness rule`: the rules in force, the owner's choices about them, and
//! proposing a repeal (architecture sections 10.4, 10.7 and 10.9).
//!
//! The two choices are not alike. Opting out is immediate and asks nobody: an opt-out
//! never waits for anyone, in a coding agent's session either. Opting back in puts a
//! rule's text back into the owner's agent, so it is a consent step in the owner's own
//! terminal: they are shown that text and where it goes, and a session is refused.

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
            let report = opt_out(&node, &circle, &name)?;
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
            // Following a rule again puts its text back into the owner's agent. That is
            // a consent step like installing it, and it has no window: a session is
            // refused before anything is read.
            crate::consent::human_only("following a rule again")?;
            let circle = find_circle(&node, Some(&circle))?;
            if announce {
                rule_in_force(&node, &circle, &name)?;
            }
            let report = opt_in(ctx, &node, &circle, &name, yes)?;
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
        let places = node.store.rule_places(&c.circle_id)?;
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
            // Where this machine puts rules of that scope (`circle place`).
            let target =
                governance::Target::of(&installer, governance::place_for(&places, rule.scope()));
            // A rule this node holds back, whatever its owner's mode (a skill of their
            // own has the name, or PeerHarness's own skill does).
            let held = if binds_me && !opted_out {
                governance::held(&node.store, &c.circle_id, &target, rule)?
            } else {
                None
            };
            let here = match (held, target.installer.status(rule.skill_name())) {
                _ if !binds_me => "does not bind you: you are not in its electorate",
                (Some(why), _) => why.state(),
                (None, Ok(InstallState::Managed { digest, modified }))
                    if digest == rule.bundle_digest() =>
                {
                    if modified {
                        "installed, edited by hand"
                    } else {
                        "installed"
                    }
                }
                (None, Ok(InstallState::Managed { .. })) => "another version installed",
                (None, Ok(InstallState::Unmanaged)) => {
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
            if let Some(dir) = &target.dir {
                t.line(format!("      in the project {dir}"));
            }
            if let Some(why) = held {
                let held = governance::HeldRule {
                    name: rule.skill_name().to_owned(),
                    proposal_id: rule.proposal_id(),
                    why,
                    place: target.dir.clone(),
                };
                t.line(format!("      {}", held.explain(&c.name)));
            }
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
                "held": held.map(governance::Held::code),
                "project": target.dir,
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

/// Opts out of the rule named `name`, then brings the agent's skills directory in line.
/// Only this machine changes, and nobody is asked: an opt-out never waits for anyone.
///
/// Nor for a key. The machine is changed first, with no key
/// ([`governance::settle_machine_first`]). Where settling the circle would also sign
/// something (the RESULT of a vote that passed here) the device key is asked for after
/// that, and a key that does not unlock is a line in the report, not a failure: the
/// rule is off this machine either way.
pub fn opt_out(node: &Node, circle: &CircleRow, name: &str) -> Result<Report> {
    if !ph_core::is_valid_skill_name(name) {
        return Err(usage("that is not a rule (skill) name"));
    }
    let id = &circle.circle_id;
    node.store.set_rule_opt_out(id, name, node.now())?;
    let done = governance::settle_machine_first(node, circle, &governance::user_installer()?, &[])?;
    let applied = &done.applied;
    let mut t = Text::new();
    t.line(format!(
        "Opted out of {name} in {}. Only this machine changes; the rule stays in force for the circle.",
        safe(&circle.name)
    ));
    if applied.removed.iter().any(|s| s == name) {
        t.line("  removed it from your agent's skills");
    }
    // Bringing the skills directory in line can change more than this one rule: a
    // rule that passed since the circle was last settled is installed by it (mode
    // `follow`), and one that was repealed goes. The owner is told of each here, as
    // by a sync: this may be the first command to settle since.
    for skill in applied.removed.iter().filter(|s| *s != name) {
        t.line(format!("  removed rule {skill}"));
    }
    for skill in &applied.installed {
        t.line(format!("  installed rule {skill} for your agent"));
    }
    for line in applied.left_in_place_lines() {
        t.line(format!("  {line}"));
    }
    if done.key_locked {
        t.line(format!("  {}", governance::NOT_SIGNED_KEY_LOCKED));
    }
    t.line(format!(
        "  Nobody else is told. To put it on the circle's record: \
         `peerharness rule opt-out {name} --circle {} --announce`.",
        circle.name
    ));
    Ok(Report::new(
        json!({
            "circle": circle.name,
            "skill_name": name,
            "opted_out": true,
            "installed": applied.installed,
            "removed": applied.removed,
            "not_removed": applied.not_removed,
            "kept_edited": applied.kept_edited_names(),
            "device_key_locked": done.key_locked,
        }),
        t.finish(),
    ))
}

/// Follows the rule named `name` again after an opt-out: the owner is shown the rule's
/// exact text and where it goes, and it is installed only if they confirm. The step is
/// the owner's and is taken in their terminal (`run` refuses it inside an agent's
/// session before this is reached, and `confirm` would again).
///
/// The confirmation is the one installing the rule needs (`proposal adopt` asks the
/// same), so the rule is installed in either mode. When no rule of that name binds the
/// owner now there is no text to show: the preview says that only the opt-out goes, and
/// nothing is installed.
///
/// The confirmation counts for the proposal that was shown and for no other. If the
/// rule of that name is another one by the time the owner answers (a sync or an import
/// stored a newer proposal while the prompt waited), nothing changes: the opt-out
/// stands, and the owner runs the command again to read the rule as it is now.
fn opt_in(ctx: &Ctx, node: &Node, circle: &CircleRow, name: &str, yes: bool) -> Result<Report> {
    if !ph_core::is_valid_skill_name(name) {
        return Err(usage("that is not a rule (skill) name"));
    }
    let id = &circle.circle_id;
    let rule = binding_rule(node, circle, name)?;
    let rule = rule.as_ref();
    let installer = governance::user_installer()?;
    let again = format!(
        "You can opt out again at any time: `peerharness rule opt-out {name} --circle {}`.",
        circle.name
    );
    let preview = match rule {
        Some(rule) => {
            // Told before anything is asked: a held rule is not installed by a yes.
            // Once the hold is gone, this command is the one to run again: an
            // opted-out rule is not installed by `proposal adopt`.
            governance::refuse_held(node, circle, rule, governance::Then::OptIn)?;
            let bundle = crate::library::bundle_store(&node.home)
                .get(&rule.bundle_digest())
                .map_err(|_| {
                    refused(
                        "this node does not have the rule's text yet, so you cannot have read \
                         what you would follow. Import the circle's events or sync first.",
                    )
                })?;
            let target = governance::rule_target(&node.store, id, &installer, rule.scope())?;
            let dir = target
                .installer
                .skill_dir(name)
                .map_err(|e| anyhow::anyhow!("cannot locate the skill directory: {e}"))?;
            let mut preview = format!(
                "This follows the rule {name} of {circle} again. Your opt-out is removed and \
                 the rule is installed for your agent at {dir}; your agent reads it from its \
                 next session. The rule, exactly as the circle passed it:\n\n{md}\n",
                circle = safe(&circle.name),
                dir = dir.display(),
                md = safe(bundle.skill_md()).trim_end(),
            );
            crate::commands::proposal::findings_preview(&mut preview, &bundle);
            if !preview.ends_with('\n') {
                preview.push('\n');
            }
            preview.push_str(&again);
            preview
        }
        None => format!(
            "No rule named {name} binds you in {circle} now, so nothing is installed. This \
             removes your opt-out: a rule of that name that the circle passes later is \
             treated like its other rules (your mode there is {mode}).\n{again}",
            circle = safe(&circle.name),
            mode = circle.adoption_mode,
        ),
    };
    crate::consent::confirm(&ctx.out, &preview, yes, "following the rule again")?;

    // What was shown, by the id of its proposal, which signs the rule's name, the
    // digest of its text and its scope. The store can have changed while the owner
    // read: looked at again before anything is changed.
    let shown = rule.map(ph_governance::Rule::proposal_id);
    if binding_rule(node, circle, name)?.map(|r| r.proposal_id()) != shown {
        return Err(refused(
            "the rule changed while it was being confirmed: nothing was changed, and your \
             opt-out stands. Run the command again to read the rule as it is now.",
        ));
    }
    node.store.clear_rule_opt_out(id, name)?;
    // The owner has read the text and said yes: that is the confirmation an install
    // needs, for the proposal they were shown and no other (`apply_rules` reads the
    // rules once more, and counts the confirmation only for that proposal).
    //
    // The install needs no key and comes first. What settling the circle would sign
    // besides comes after it, and a key that does not unlock leaves that unsigned
    // without undoing what the owner just confirmed.
    let done = governance::settle_machine_first(node, circle, &installer, shown.as_slice())?;
    let applied = &done.applied;
    let mut t = Text::new();
    t.line(format!("Following {name} again."));
    if applied.installed.iter().any(|s| s == name) {
        t.line("  installed it for your agent");
    }
    for waiting in &applied.asking {
        if waiting.name == name {
            t.line(format!(
                "  it waits for your confirmation, because {}: `peerharness proposal adopt {}`",
                waiting.because(),
                short_id(&waiting.proposal_id)
            ));
        }
    }
    for (skill, why) in &applied.refused {
        if skill == name {
            t.line(format!("  it cannot be installed ({why})"));
        }
    }
    if applied.conflicts.iter().any(|s| s == name) {
        t.line(
            "  it was not installed: a skill of that name that PeerHarness does not manage \
             is in the way",
        );
    }
    for held in applied.held.iter().filter(|h| h.name == name) {
        t.line(format!("  {}", held.line(&circle.name)));
    }
    // What the same run changed for other rules of the circle, as `rule opt-out`
    // says it. An edited copy that was left is named by this run or by none.
    for skill in applied.installed.iter().filter(|s| *s != name) {
        t.line(format!("  installed rule {skill} for your agent"));
    }
    for skill in &applied.removed {
        t.line(format!("  removed rule {skill}"));
    }
    for line in applied.left_in_place_lines() {
        t.line(format!("  {line}"));
    }
    if done.key_locked {
        t.line(format!("  {}", governance::NOT_SIGNED_KEY_LOCKED));
    }
    Ok(Report::new(
        json!({
            "circle": circle.name,
            "skill_name": name,
            "opted_out": false,
            "installed": applied.installed,
            "removed": applied.removed,
            "not_removed": applied.not_removed,
            "kept_edited": applied.kept_edited_names(),
            "device_key_locked": done.key_locked,
        }),
        t.finish(),
    ))
}

/// The rule named `name` that binds this node's owner in `circle` now, if there is
/// one: it is in force, the owner has not left the circle on this machine, and they are
/// in its electorate.
fn binding_rule(
    node: &Node,
    circle: &CircleRow,
    name: &str,
) -> Result<Option<ph_governance::Rule>> {
    let id = &circle.circle_id;
    let (charter, rules, _) = governance::rule_set(&node.store, id)?;
    let left = node.store.circle_left_at(id)?.is_some();
    Ok(rules
        .get(name)
        .filter(|r| {
            !left
                && charter
                    .content
                    .voter(
                        &node.device_key(),
                        &ph_protocol::Electorate::Scope(r.scope()),
                    )
                    .is_some()
        })
        .cloned())
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
    // The stance names the proposal the preview named. The key first, then a look at
    // whether that is still the rule: a newer rule can take the name while the owner
    // reads or types a passphrase, and a stance about the old one would not say what
    // they were shown.
    let Ok(device) = node.device() else {
        // What was done on this machine stands, and is said first, as below.
        ctx.out.note(done.text.trim_end());
        return Err(refused(
            "nothing was announced: the device key could not be unlocked, and a stance is \
             signed with it. What was changed on this machine stands. Run the command \
             again to put it on the record.",
        ));
    };
    let key = device.signing_key();
    // The look and the stance are one transaction: no other process stores a rule of
    // this name between them. `None` is a rule that changed: nothing was signed.
    let announced = governance::atomically(&node.store, key, |store| {
        if !governance::rule_as_shown(store, key, &circle.circle_id, name, &rule.proposal_id())? {
            return Ok(None);
        }
        governance::announce_stance(
            store,
            key,
            &circle.circle_id,
            &rule,
            stance,
            reason,
            node.now(),
        )
        .map(Some)
    })?;
    let Some(env) = announced else {
        // What was done on this machine stands, and is said first. The error after it
        // names nothing.
        ctx.out.note(done.text.trim_end());
        return Err(refused(
            "nothing was announced: the rule changed while this was being confirmed, and \
             what you were shown is no longer the rule in force. Run the command again to \
             see the rule as it is now.",
        ));
    };
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
    // The charter the preview is built from: it fixes who votes on the repeal and how
    // many approvals it takes, which the preview states. The proposal is signed under
    // this charter or not at all.
    let (charter, rules, _) = governance::rule_set(&node.store, id)?;
    let shown = charter.digest()?;
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

    // A repeal names the proposal it repeals, which was read before the preview. The
    // key first, then a look at whether that proposal is still the rule of this name:
    // one that took the name while the owner read or typed a passphrase is another
    // text, which this repeal would leave in force. Then the charter: the preview
    // stated its electorate and count, and under a newer one nothing is signed
    // (`propose_under`). Both looks and the signature are one transaction, so no
    // other process stores a rule or a charter between them.
    let key = node.device()?.signing_key();
    let proposal = governance::atomically(&node.store, key, |store| {
        if !governance::rule_as_shown(store, key, id, name, &target)? {
            return Err(refused(
                "the rule changed while this was being confirmed: what you were shown is \
                 no longer the rule in force. Nothing was proposed and nothing was signed. \
                 Run the command again to see the rule as it is now.",
            ));
        }
        governance::propose_under(
            store,
            key,
            id,
            &shown,
            governance::NewProposal {
                scope: &scope,
                title: &title,
                summary: &summary,
                action: ProposalAction::Repeal { target },
            },
            node.now(),
        )
    })?;
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
