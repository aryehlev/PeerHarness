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
use crate::output::{continued, safe, short_id, Report, Text, MEMBERS_WORDS};

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
        RuleCommand::History { name, circle } => {
            let circle = find_circle(&node, Some(&circle))?;
            history(&node, &circle, &name)
        }
        RuleCommand::Restore {
            name,
            circle,
            to,
            yes,
        } => {
            let circle = find_circle(&node, Some(&circle))?;
            restore(ctx, &node, &circle, &name, &to, yes)
        }
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
        // An owner who left the circle on this machine is bound by none of its rules,
        // whatever the roll still says: `apply_rules` installs nothing for them, and
        // this listing says the same (ADR-051).
        let left = node.store.circle_left_at(&c.circle_id)?.is_some();
        if left {
            t.line(format!(
                "{} (charter {}, you left this circle on this machine): {} rule(s) in force \
                 for its members, none of them for you",
                safe(&c.name),
                charter.seq,
                rules.len()
            ));
        } else {
            t.line(format!(
                "{} (charter {}, your mode: {}): {} rule(s) in force",
                safe(&c.name),
                charter.seq,
                c.adoption_mode,
                rules.len()
            ));
        }
        for rule in rules.rules() {
            let opted_out = node
                .store
                .is_rule_opted_out(&c.circle_id, rule.skill_name())?;
            let binds_me = !left
                && charter
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
                _ if left => "does not bind you: you left this circle",
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
                "  {}  scope {}  proposal {}  text {}  [{here}]",
                rule.skill_name(),
                rule.scope(),
                short_id(&rule.proposal_id()),
                short_id(&rule.bundle_digest())
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
            // One line a member, the name first and the member's own words last, and
            // every further line of those behind a mark: a reason cannot add a name
            // to the list or a line to the listing (ADR-051).
            let out_of_it: Vec<String> = recorded
                .iter()
                .filter(|s| s.stance == Stance::OptedOut)
                .map(|s| match s.reason.as_deref().filter(|r| !r.is_empty()) {
                    Some(r) => format!("{}: {}", s.member, continued(r, MEMBERS_WORDS)),
                    None => s.member.clone(),
                })
                .collect();
            if !out_of_it.is_empty() {
                t.line("      on record as opted out:");
                for member in &out_of_it {
                    t.line(format!("        - {member}"));
                }
            }
            rows.push(json!({
                "circle": c.name,
                "skill_name": rule.skill_name(),
                "scope": rule.scope(),
                "proposal_id": rule.proposal_id(),
                "bundle_digest": rule.bundle_digest(),
                "opted_out": opted_out,
                "binds_you": binds_me,
                "left_circle": left,
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

/// Where one version of a rule stands, in PeerHarness's own words.
fn version_standing(
    node: &Node,
    p: &ph_governance::ProposalView,
    tally: &ph_governance::Tally,
    rules: &ph_governance::RuleSet,
) -> Result<String> {
    if rules.by_proposal(&p.event_id()).is_some() {
        return Ok("in force".to_owned());
    }
    let standing = crate::commands::proposal::standing(node, p, tally)?;
    Ok(match standing {
        // It passed under the charter in force and is not the rule of its name: a
        // newer version has the name, or a repeal took it out.
        "passed" | "carried" => match p.skill_name().and_then(|n| rules.get(n)) {
            Some(newer) => format!(
                "passed, replaced by proposal {}",
                short_id(&newer.proposal_id())
            ),
            None => "passed, repealed since".to_owned(),
        },
        "passed under an earlier charter" => {
            "passed under an earlier charter, not in force now".to_owned()
        }
        other => other.to_owned(),
    })
}

/// Every `adopt` proposal for the rule named `name` that this node holds for `circle`,
/// oldest first: the digest of the text each one signs, who proposed it, who approved
/// it and where it stands. Then the repeal proposals that name one of them.
///
/// It prints no text of a rule and nothing a member wrote: ids, digests, the handles of
/// the signed charters and the counts. So it reads the same inside a session.
fn history(node: &Node, circle: &CircleRow, name: &str) -> Result<Report> {
    if !ph_core::is_valid_skill_name(name) {
        return Err(usage("that is not a rule (skill) name"));
    }
    let id = &circle.circle_id;
    let (_, rules, _) = governance::rule_set(&node.store, id)?;
    let mut all = Vec::new();
    for ev in node.store.proposals(id)? {
        if let Ok(p) = governance::proposal_view(&node.store, &ev.event_id) {
            all.push(p);
        }
    }
    all.sort_by_key(|p| (p.created_at(), p.event_id().to_string()));
    let versions: Vec<&ph_governance::ProposalView> = all
        .iter()
        .filter(|p| p.skill_name() == Some(name))
        .collect();
    if versions.is_empty() {
        return Err(usage(format!(
            "no rule named {name:?} was ever proposed in {} on this node",
            circle.name
        )));
    }
    let bundles = crate::library::bundle_store(&node.home);
    let mut rows = Vec::new();
    let mut t = Text::new();
    t.line(format!(
        "{}: {} version(s) of the rule {name} were put to the vote, oldest first",
        safe(&circle.name),
        versions.len()
    ));
    for (n, p) in versions.iter().enumerate() {
        let (charter, tally) = governance::count(&node.store, p)?;
        let standing = version_standing(node, p, &tally, &rules)?;
        let digest = p.bundle_digest();
        let approved: Vec<&str> = tally
            .approvals()
            .iter()
            .map(|a| a.member.as_str())
            .collect();
        t.line(format!(
            "  {}. proposal {}  text {}  scope {}  [{standing}]",
            n + 1,
            short_id(&p.event_id()),
            digest.map_or_else(|| "?".to_owned(), |d| short_id(&d)),
            p.scope(),
        ));
        t.line(format!(
            "       proposed by {} at {}, under charter {}",
            crate::commands::proposal::proposer(node, p)?,
            p.created_at(),
            charter.seq
        ));
        t.line(format!(
            "       approved by {} of {} ({} needed){}{}",
            approved.len(),
            tally.electorate().len(),
            tally.need(),
            if approved.is_empty() { "" } else { ": " },
            approved.join(", ")
        ));
        if let Some(older) = p.supersedes() {
            t.line(format!(
                "       names proposal {} as the version it replaces",
                short_id(&older)
            ));
        }
        let text_here = digest.is_some_and(|d| bundles.contains(&d));
        if !text_here {
            t.line("       its text is not on this node");
        }
        rows.push(json!({
            "proposal_id": p.event_id(),
            "bundle_digest": digest,
            "scope": p.scope(),
            "standing": standing,
            "in_force": rules.by_proposal(&p.event_id()).is_some(),
            "proposed_by": p.author().fingerprint(),
            "created_at": p.created_at().to_string(),
            "charter": charter.seq,
            "approvals": tally.approvals().iter().map(|a| json!({
                "member": a.member,
                "device": a.device.fingerprint(),
                "vote_id": a.vote_id,
            })).collect::<Vec<_>>(),
            "need": tally.need(),
            "electorate": tally.electorate(),
            "supersedes": p.supersedes(),
            "text_on_this_node": text_here,
        }));
    }
    let mut repeals = Vec::new();
    for p in &all {
        let Some(target) = p.repeal_target() else {
            continue;
        };
        if !versions.iter().any(|v| v.event_id() == target) {
            continue;
        }
        let (_, tally) = governance::count(&node.store, p)?;
        let standing = crate::commands::proposal::standing(node, p, &tally)?;
        t.line(format!(
            "  repeal proposal {} names proposal {}  [{standing}]",
            short_id(&p.event_id()),
            short_id(&target)
        ));
        repeals.push(json!({
            "proposal_id": p.event_id(),
            "target": target,
            "standing": standing,
        }));
    }
    t.line(format!(
        "Read a version and its changes: `peerharness proposal show <proposal>`. Put an \
         earlier one back to the vote: `peerharness rule restore {name} --circle {} --to \
         <proposal>`.",
        circle.name
    ));
    Ok(Report::new(
        json!({
            "circle": circle.name,
            "skill_name": name,
            "versions": rows,
            "repeals": repeals,
        }),
        t.finish(),
    ))
}

/// Puts an earlier version of the rule named `name` back to the vote: a new `adopt`
/// proposal for exactly the text the proposal `to` signed. Creating it is not a vote,
/// and nothing changes for anyone until it passes.
///
/// It is the team's way back from a version it regrets. Nothing is taken on trust for
/// it: the members are shown the text in full and the changes from the rule in force,
/// like for any other proposal, and the approvals of the earlier proposal do not count
/// for this one. Asked in the terminal only.
fn restore(
    ctx: &Ctx,
    node: &Node,
    circle: &CircleRow,
    name: &str,
    to: &str,
    yes: bool,
) -> Result<Report> {
    use ph_protocol::{AdoptAction, Electorate, ProposalAction};

    if !ph_core::is_valid_skill_name(name) {
        return Err(usage("that is not a rule (skill) name"));
    }
    crate::agent_notes::refuse_reserved_name(name)?;
    let id = &circle.circle_id;
    let not_a_version = || {
        usage(format!(
            "that is not a version of the rule {name} in {}: `peerharness rule history {name} \
             --circle {}` lists them",
            circle.name, circle.name
        ))
    };
    let old_id = crate::ids::resolve_event(&node.store, to)?;
    let old = governance::proposal_view(&node.store, &old_id).map_err(|_| not_a_version())?;
    let old_digest = old
        .bundle_digest()
        .filter(|_| old.circle_id() == *id && old.skill_name() == Some(name))
        .ok_or_else(not_a_version)?;
    // "Restore" is for a text the circle had approved. One that never passed is
    // proposed like any new rule, from a note.
    let (_, old_tally) = governance::count(&node.store, &old)?;
    if !old_tally.passed() {
        return Err(refused(
            "that version never passed, so there is nothing to restore. A text the circle \
             has not approved is proposed with `peerharness proposal create`.",
        ));
    }
    let bundles = crate::library::bundle_store(&node.home);
    let bundle = bundles.get(&old_digest).map_err(|_| {
        refused(
            "this node does not have that version's text, so it cannot show what it would \
             propose. Import the circle's events or sync first.",
        )
    })?;
    // The charter the preview is built from, and the rule of this name in force now:
    // the version the restored text would replace.
    let charter = governance::current_charter(&node.store, id)?;
    let shown = charter.digest()?;
    let replaces = crate::versions::in_force(&node.store, &bundles, id, name)?;
    if replaces
        .as_ref()
        .is_some_and(|r| r.bundle_digest == old_digest)
    {
        return Err(usage(format!(
            "that version's text is, word for word, the rule {name} in force in {}",
            circle.name
        )));
    }
    // Dated so that it takes that rule's place if it passes, or refused before anything
    // is asked.
    let signed_at = crate::versions::signing_time(node.now(), replaces.as_ref())?;
    let scope = old.scope().clone();
    let title = format!(
        "Restore {name} to the version of proposal {}",
        short_id(&old_id)
    );
    let electorate = charter
        .content
        .electorate(&Electorate::Scope(&scope))
        .count();
    let mut preview = format!(
        "This asks the members of {circle} (scope {scope}) to vote on putting an earlier \
         version of the rule {name} back in force: the text of proposal {old}.\n\
         Exactly this text leaves your machine, and nothing else:\n\n\
         title: {title}\n\n{skill}\n",
        circle = safe(&circle.name),
        old = short_id(&old_id),
        skill = safe(bundle.skill_md()),
    );
    crate::commands::proposal::findings_preview(&mut preview, &bundle);
    if !preview.ends_with('\n') {
        preview.push('\n');
    }
    match &replaces {
        Some(earlier) => preview.push_str(&format!(
            "{}\nIf this passes, it takes that rule's place, and the proposal names it as \
             the version it replaces.\n",
            earlier.describe(name, &bundle, crate::versions::CHANGE_MARK)
        )),
        None => preview.push_str(&format!(
            "No rule named {name} is in force here now: if this passes, the rule is in \
             force again with this text.\n"
        )),
    }
    preview.push_str(&format!(
        "It passes with {need} of {electorate} member approval(s). The approvals of the \
         earlier proposal do not count for this one. Creating it is not a vote: cast yours \
         with `peerharness proposal vote`.",
        need = charter.content.rules.pass.need(electorate),
    ));
    crate::consent::confirm(&ctx.out, &preview, yes, "sharing the proposal")?;

    // The key first, then the looks and the signature in one transaction: the rule of
    // this name is still the one the changes were shown against (or there is still
    // none), and the charter is still the one the count was read from.
    let key = node.device()?.signing_key();
    let superseded = replaces.as_ref().map(|r| r.proposal_id);
    let proposal = governance::atomically(&node.store, key, |store| {
        if !governance::name_as_shown(store, key, id, name, superseded.as_ref())? {
            return Err(refused(governance::VERSION_CHANGED));
        }
        // The text is on this node already. Its row is what `events export` and a sync
        // hand on with the proposal.
        governance::record_bundle(store, &bundles, &bundle, node.now())?;
        governance::propose_under(
            store,
            key,
            id,
            &shown,
            governance::NewProposal {
                scope: &scope,
                title: &title,
                summary: "",
                action: ProposalAction::Adopt(AdoptAction {
                    skill_name: bundle.name().to_owned(),
                    description: bundle.description().to_owned(),
                    bundle_digest: bundle.digest(),
                    bundle_size: bundle.size(),
                    related_question: None,
                    supersedes: superseded,
                }),
            },
            signed_at,
        )
    })?;
    let mut t = Text::new();
    t.line(format!(
        "Proposed restoring {name} in {} to the version of proposal {} (proposal {}).",
        safe(&circle.name),
        short_id(&old_id),
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
            "kind": "adopt",
            "skill_name": name,
            "bundle_digest": bundle.digest(),
            "restores": old_id,
            "supersedes": superseded,
            "circle": circle.name,
            "scope": scope,
        }),
        t.finish(),
    ))
}
