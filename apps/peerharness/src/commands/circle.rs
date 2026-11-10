//! `peerharness circle`: founding a circle, showing its charter, joining, and every
//! change to the charter.
//!
//! Membership and the rules of the vote are decided by vote (architecture section
//! 10.8). `invite`, `remove`, `leave`, `amend` and `device` therefore change nothing by
//! themselves: each puts an amendment to the vote and casts the proposer's own approval.
//! With one member that approval is the majority, so the change passes at once; with
//! more, the other members have to approve too.
//!
//! Two commands act on this machine alone. `mode` is the owner's standing choice about
//! rules that pass. `revoke` is the founder's emergency brake for a lost device: it cuts
//! one device key off and leaves the roll as the members voted it.

use anyhow::{anyhow, Context, Result};
use ph_core::{DeviceKey, Scope};
use ph_governance::{
    add_device, admit_member, change_rules, remove_device, remove_member, threshold_for,
    ProposalView, Tally,
};
use ph_identity::{accept_credential, CircleAuthority};
use ph_protocol::{
    is_valid_member_name, validate_stateless, Charter, CharterContent, EventBody, ProposalAction,
    RevocationBody, RollEntry, Threshold, VoteDecision,
};
use ph_store::CircleRow;
use serde_json::{json, Value};

use crate::cli::{
    CircleAmendArgs, CircleCommand, CircleDeviceArgs, CircleInviteArgs, CircleJoinArgs,
    CircleLeaveArgs, CircleModeArgs, CircleRemoveArgs, CircleRevokeArgs, DeviceCommand, ModeArg,
};
use crate::commands::Ctx;
use crate::consent::confirm;
use crate::error::{refused, usage};
use crate::governance::{self, NewProposal, Settled};
use crate::node::Node;
use crate::output::{safe, short_id, Report, Text};

pub fn run(ctx: &Ctx, command: CircleCommand) -> Result<Report> {
    match command {
        CircleCommand::Create { name, member } => create(ctx, &name, member.as_deref()),
        CircleCommand::Members { circle } => members(ctx, circle.as_deref()),
        CircleCommand::Invite(args) => invite(ctx, args),
        CircleCommand::Join(args) => join(ctx, args),
        CircleCommand::Remove(args) => remove(ctx, args),
        CircleCommand::Leave(args) => leave(ctx, args),
        CircleCommand::Amend(args) => amend(ctx, args),
        CircleCommand::Device { command } => match command {
            DeviceCommand::Add(args) => device(ctx, args, true),
            DeviceCommand::Remove(args) => device(ctx, args, false),
        },
        CircleCommand::Mode(args) => mode(ctx, args),
        CircleCommand::Revoke(args) => revoke(ctx, args),
    }
}

/// The circle named `name`, or the only circle when `name` is `None`.
pub fn find_circle(node: &Node, name: Option<&str>) -> Result<CircleRow> {
    match name {
        Some(n) => node
            .store
            .circle_by_name(n)?
            .ok_or_else(|| usage(format!("no circle named {n:?} on this node"))),
        None => {
            let mut all = node.store.circles()?;
            match all.len() {
                0 => Err(usage(
                    "this node is in no circle: `peerharness circle create <name>`",
                )),
                1 => Ok(all.remove(0)),
                _ => Err(usage(
                    "this node is in several circles: pass --circle <name>",
                )),
            }
        }
    }
}

fn default_member_name() -> String {
    let raw = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
        .take(32)
        .collect();
    if is_valid_member_name(&cleaned) {
        cleaned
    } else {
        "founder".to_owned()
    }
}

fn check_member_name(name: &str) -> Result<()> {
    if is_valid_member_name(name) {
        Ok(())
    } else {
        Err(usage(
            "a member handle is 1-32 characters of a-z, 0-9, '.', '_' and '-', starting with a letter or digit",
        ))
    }
}

/// The charter as human text: rules, then the roll.
pub fn describe_charter(charter: &Charter, me: Option<&DeviceKey>) -> String {
    let rules = charter.content.rules;
    let mut t = Text::new();
    t.line(format!(
        "charter {} ({} member{})",
        charter.seq,
        charter.content.roll.len(),
        if charter.content.roll.len() == 1 {
            ""
        } else {
            "s"
        }
    ));
    t.line(format!(
        "  a proposal passes with more than {}/{} of the members entitled to vote on it",
        rules.pass.num, rules.pass.den
    ));
    t.line(format!(
        "  changing these rules needs more than {}/{}",
        rules.amend.num, rules.amend.den
    ));
    t.line(if rules.binding {
        "  passed rules are binding: they are installed for every member (you can opt out of any rule)"
    } else {
        "  passed rules are advisory: each member is asked before anything is installed"
    });
    t.line("  roll:");
    for entry in &charter.content.roll {
        let scopes: Vec<&str> = entry.scopes.iter().map(Scope::as_str).collect();
        let you = me.is_some_and(|d| entry.has_device(d));
        t.line(format!(
            "    {}{}  scopes {}  devices {}",
            entry.member,
            if you { " (you)" } else { "" },
            scopes.join(", "),
            entry
                .devices
                .iter()
                .map(DeviceKey::fingerprint)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !charter.content.carried.is_empty() {
        t.line(format!(
            "  carries {} rule(s) from the previous charter",
            charter.content.carried.len()
        ));
    }
    t.finish()
}

fn charter_json(charter: &Charter) -> Result<Value> {
    Ok(json!({
        "seq": charter.seq,
        "digest": charter.digest()?,
        "rules": charter.content.rules,
        "roll": charter.content.roll,
        "carried": charter.content.carried,
    }))
}

fn create(ctx: &Ctx, name: &str, member: Option<&str>) -> Result<Report> {
    let node = ctx.open_node()?;
    let handle = member.map_or_else(default_member_name, str::to_owned);
    check_member_name(&handle)?;
    if node.store.circle_by_name(name)?.is_some() {
        return Err(usage(format!(
            "a circle named {name:?} already exists here"
        )));
    }
    let now = node.now();
    let device = node.device()?;
    let (authority, circle_id) =
        CircleAuthority::create(node.keystore()?).context("cannot create the circle root key")?;
    let founder = RollEntry::new(&handle, vec![device.public()], vec![Scope::all()]);
    let charter = governance::found_circle(
        &node.store,
        &authority,
        name,
        founder,
        Some(authority.keystore_label()),
        now,
    )?;
    // The founder's own credential, for the network transport later on.
    let credential = authority.issue_founder_credential(device.public(), now)?;
    let proof = accept_credential(&credential, device, now)?;
    node.store.upsert_membership_proof(&proof, true, now)?;

    let mut t = Text::new();
    t.line(format!("Founded the circle {}.", safe(name)));
    t.kv("circle id", short_id(&circle_id));
    t.kv("root fingerprint", authority.root_fingerprint());
    t.line("");
    t.line(describe_charter(&charter, Some(&device.public())).trim_end());
    t.line("");
    t.line("Tell new members the root fingerprint out of band (in person, by phone).");
    t.line(format!(
        "Next: `peerharness circle invite <their ed25519: device key> --circle {name} --member <handle>`."
    ));
    Ok(Report::new(
        json!({
            "circle": name,
            "circle_id": circle_id,
            "root_fingerprint": authority.root_fingerprint(),
            "member": handle,
            "charter": charter_json(&charter)?,
        }),
        t.finish(),
    ))
}

fn members(ctx: &Ctx, name: Option<&str>) -> Result<Report> {
    let node = ctx.open_node()?;
    let circle = find_circle(&node, name)?;
    let charter = governance::current_charter(&node.store, &circle.circle_id)?;
    let mut t = Text::new();
    t.line(format!(
        "{} ({}, root fingerprint {})",
        safe(&circle.name),
        if circle.is_founder {
            "founded here"
        } else {
            "joined"
        },
        circle.root_key.fingerprint()
    ));
    t.line(describe_charter(&charter, Some(&node.device_key())).trim_end());
    t.kv("your mode", &circle.adoption_mode);
    Ok(Report::new(
        json!({
            "circle": circle.name,
            "circle_id": circle.circle_id,
            "root_fingerprint": circle.root_key.fingerprint(),
            "adoption_mode": circle.adoption_mode,
            "charter": charter_json(&charter)?,
        }),
        t.finish(),
    ))
}

fn invite(ctx: &Ctx, args: CircleInviteArgs) -> Result<Report> {
    let node = ctx.open_node()?;
    let circle = find_circle(&node, Some(&args.circle))?;
    check_member_name(&args.member)?;
    let device: DeviceKey = args.invitee.trim().parse().map_err(|_| {
        usage(
            "the invitee must be an `ed25519:` device key (they see it with `peerharness status`)",
        )
    })?;
    let scopes = if args.scopes.is_empty() {
        vec![Scope::all()]
    } else {
        args.scopes
            .iter()
            .map(|s| Scope::new(s).map_err(|_| usage(format!("invalid scope {s:?}"))))
            .collect::<Result<Vec<_>>>()?
    };
    let id = circle.circle_id;
    let now = node.now();
    let (current, rules, _) = governance::rule_set(&node.store, &id)?;
    let entry = RollEntry::new(&args.member, vec![device], scopes);
    let next = admit_member(&current.content, &rules, entry)
        .map_err(|e| usage(format!("cannot propose that admission: {e}")))?;
    let need = current.content.rules.pass.need(current.content.roll.len());

    let preview = format!(
        "This puts an amendment of {circle} to the vote and casts your approval:\n  \
         admit {member} (device {fp}) to the roll of charter {seq}\n  \
         it passes with {need} of {n} member approval(s); yours is one\n\
         An approval cannot be withdrawn.",
        circle = safe(&circle.name),
        member = args.member,
        fp = device.fingerprint(),
        seq = current.seq,
        n = current.content.roll.len(),
    );
    confirm(&ctx.out, &preview, args.yes, "the admission proposal")?;

    let key = node.device()?.signing_key();
    let title = format!("Admit {}", args.member);
    let proposal = governance::propose(
        &node.store,
        key,
        &id,
        NewProposal {
            scope: &Scope::all(),
            title: &title,
            summary: "",
            action: ProposalAction::Amend { next },
        },
        now,
    )?;
    governance::cast_vote(
        &node.store,
        key,
        &proposal,
        VoteDecision::Approve,
        None,
        now,
    )?;
    let settled = governance::settle(&node, &circle, &governance::user_installer()?, &[])?;
    let (_, tally) = governance::count(&node.store, &proposal)?;

    let mut t = Text::new();
    t.line(format!(
        "Proposed admitting {} (proposal {}).",
        args.member,
        short_id(&proposal.event_id())
    ));
    t.line(format!("  {tally}"));
    let mut written = None;
    match settled.charter_notarized {
        Some(seq) => {
            t.line(format!(
                "  The admission passed. Charter {seq} is now in force."
            ));
            let path = match args.out {
                Some(p) => crate::home::absolute(&p)?,
                None => std::env::current_dir()?.join(format!(
                    "peerharness-{}-events.jsonl",
                    circle.name.replace(' ', "-")
                )),
            };
            let lines = governance::export_circle(
                &node.store,
                &crate::library::bundle_store(&node.home),
                &id,
            )?;
            crate::home::write_private_file(&path, (lines.join("\n") + "\n").as_bytes())?;
            t.line(format!("  Wrote {}", path.display()));
            t.line(format!(
                "Give that file to {} together with the root fingerprint {} (out of band).",
                args.member,
                circle.root_key.fingerprint()
            ));
            t.line(
                "They run: `peerharness circle join <file> --expect-fingerprint <fingerprint>`.",
            );
            written = Some(path.display().to_string());
        }
        None if tally.passed() => {
            t.line("  It passed. The node that founded the circle will issue the next charter");
            t.line("  once it has these events: `peerharness events export` and send it the file.");
        }
        None => {
            t.line(format!(
                "  {} more approval(s) needed. Send the other members your events",
                tally.missing()
            ));
            t.line(format!(
                "  (`peerharness events export --circle {}`); they vote with",
                circle.name
            ));
            t.line(format!(
                "  `peerharness proposal vote {} approve`.",
                short_id(&proposal.event_id())
            ));
        }
    }
    Ok(Report::new(
        json!({
            "proposal_id": proposal.event_id(),
            "passed": tally.passed(),
            "approvals": tally.approvals().len(),
            "need": tally.need(),
            "charter_seq": settled.charter_notarized,
            "events_file": written,
        }),
        t.finish(),
    ))
}

/// An amendment put to the vote by [`put_amendment`], and where it stands.
struct Put {
    proposal: ProposalView,
    settled: Settled,
    tally: Tally,
}

/// The line a preview ends with: how many approvals the amendment needs.
fn need_line(current: &Charter, next: &CharterContent) -> String {
    let n = current.content.roll.len();
    let threshold = if next.rules == current.content.rules {
        current.content.rules.pass
    } else {
        current.content.rules.amend
    };
    format!(
        "It passes with {} of {n} member approval(s); yours is one.\n\
         An approval cannot be withdrawn.",
        threshold.need(n)
    )
}

/// Puts `next` to the vote as an amendment of `circle`'s current charter, casts the
/// proposer's approval and settles. The caller has shown the preview and has the
/// owner's confirmation.
fn put_amendment(
    node: &Node,
    circle: &CircleRow,
    title: &str,
    next: CharterContent,
) -> Result<Put> {
    let now = node.now();
    let key = node.device()?.signing_key();
    let proposal = governance::propose(
        &node.store,
        key,
        &circle.circle_id,
        NewProposal {
            scope: &Scope::all(),
            title,
            summary: "",
            action: ProposalAction::Amend { next },
        },
        now,
    )?;
    governance::cast_vote(
        &node.store,
        key,
        &proposal,
        VoteDecision::Approve,
        None,
        now,
    )?;
    let settled = governance::settle(node, circle, &governance::user_installer()?, &[])?;
    let (_, tally) = governance::count(&node.store, &proposal)?;
    Ok(Put {
        proposal,
        settled,
        tally,
    })
}

/// What to tell the proposer after [`put_amendment`], and the JSON of the report.
fn amendment_report(circle: &CircleRow, put: &Put, done: &str, mut t: Text) -> Report {
    t.line(format!("  {}", put.tally));
    match put.settled.charter_notarized {
        Some(seq) => {
            t.line(format!("  {done} Charter {seq} is now in force."));
            t.line(format!(
                "  Send the others your events: `peerharness sync <peer>` or \
                 `peerharness events export --circle {}`.",
                circle.name
            ));
        }
        None if put.tally.passed() => {
            t.line("  It passed. The node that founded the circle issues the next charter");
            t.line("  once it has these events: sync with it, or send it an events file.");
        }
        None => {
            t.line(format!(
                "  {} more approval(s) needed. Send the other members your events",
                put.tally.missing()
            ));
            t.line(format!(
                "  (`peerharness sync <peer>` or `peerharness events export --circle {}`);",
                circle.name
            ));
            t.line(format!(
                "  they vote with `peerharness proposal vote {} approve`.",
                short_id(&put.proposal.event_id())
            ));
        }
    }
    Report::new(
        json!({
            "proposal_id": put.proposal.event_id(),
            "passed": put.tally.passed(),
            "approvals": put.tally.approvals().len(),
            "need": put.tally.need(),
            "charter_seq": put.settled.charter_notarized,
            "removed_rules": put.settled.applied.removed,
        }),
        t.finish(),
    )
}

/// Puts the removal of a member to the vote and casts the proposer's approval. Like an
/// admission it is an amendment: nobody is removed until a majority of the roll approves
/// and the founder's node has notarized the charter that was voted on.
fn remove(ctx: &Ctx, args: CircleRemoveArgs) -> Result<Report> {
    let node = ctx.open_node()?;
    let circle = find_circle(&node, Some(&args.circle))?;
    let (current, rules, _) = governance::rule_set(&node.store, &circle.circle_id)?;
    let next = remove_member(&current.content, &rules, &args.member)
        .map_err(|e| usage(format!("cannot propose that removal: {e}")))?;
    let preview = format!(
        "This puts an amendment of {circle} to the vote and casts your approval:\n  \
         remove {member} from the roll of charter {seq}\n{need}",
        circle = safe(&circle.name),
        member = args.member,
        seq = current.seq,
        need = need_line(&current, &next),
    );
    confirm(&ctx.out, &preview, args.yes, "the removal proposal")?;
    let put = put_amendment(&node, &circle, &format!("Remove {}", args.member), next)?;
    let mut t = Text::new();
    t.line(format!(
        "Proposed removing {} (proposal {}).",
        args.member,
        short_id(&put.proposal.event_id())
    ));
    Ok(amendment_report(&circle, &put, "The removal passed.", t))
}

/// `circle leave`: the owner stops following the circle on this machine at once, and
/// asks the members to take them off the roll. Nobody can be made to follow a circle;
/// the roll itself changes only by vote, like every change to it.
fn leave(ctx: &Ctx, args: CircleLeaveArgs) -> Result<Report> {
    let node = ctx.open_node()?;
    let circle = find_circle(&node, Some(&args.circle))?;
    let id = circle.circle_id;
    let me = node.device_key();
    let left = node.store.circle_left_at(&id)?;
    if args.undo {
        if left.is_none() {
            return Err(usage("you have not left that circle"));
        }
        confirm(
            &ctx.out,
            &format!(
                "This follows {} again on this machine: rules in force are installed for \
                 your agent according to your mode ({}).\nYour request to be taken off the \
                 roll stays on record; the members may still approve it.",
                safe(&circle.name),
                circle.adoption_mode
            ),
            args.yes,
            "following the circle again",
        )?;
        node.store.set_circle_left(&id, None)?;
        let settled = governance::settle(&node, &circle, &governance::user_installer()?, &[])?;
        let mut t = Text::new();
        t.line(format!("Following {} again.", safe(&circle.name)));
        for skill in &settled.applied.installed {
            t.line(format!("  installed rule {skill} for your agent"));
        }
        return Ok(Report::new(
            json!({ "circle": circle.name, "left": false, "installed": settled.applied.installed }),
            t.finish(),
        ));
    }
    if left.is_some() {
        return Err(usage(
            "you already left that circle on this machine (`circle leave --undo` follows it again)",
        ));
    }
    let (current, rules, _) = governance::rule_set(&node.store, &id)?;
    let Some(entry) = current.content.member_of(&me) else {
        // Already off the roll: only this machine is left to change.
        confirm(
            &ctx.out,
            &format!(
                "You are not on the roll of {}. This removes the rules it installed for \
                 your agent.",
                safe(&circle.name)
            ),
            args.yes,
            "leaving the circle",
        )?;
        node.store.set_circle_left(&id, Some(node.now()))?;
        let settled = governance::settle(&node, &circle, &governance::user_installer()?, &[])?;
        return Ok(Report::new(
            json!({ "circle": circle.name, "left": true, "removed_rules": settled.applied.removed }),
            format!("Left {} on this machine.", safe(&circle.name)),
        ));
    };
    let member = entry.member.clone();
    let next = remove_member(&current.content, &rules, &member).map_err(|_| {
        usage(
            "you are the only member, so there is nobody to leave. To delete this node and \
             the circle with it: `peerharness reset`.",
        )
    })?;
    let installed = node.store.rule_installs(&id)?.len();
    let mut preview = format!(
        "Leaving {circle}:\n  \
         now, on this machine: the {installed} rule(s) the circle installed for your agent \
         are removed, and no rule of this circle is installed here again;\n  \
         for the circle: an amendment that removes {member} from the roll of charter {seq} \
         is put to the vote, with your approval.\n\
         You stay on the roll until the members have approved it. {need}",
        circle = safe(&circle.name),
        seq = current.seq,
        need = need_line(&current, &next),
    );
    if circle.is_founder {
        preview.push_str(
            "\nThis node holds the circle's root key, which signs every change to the roll. \
             Once you are off the roll the members' nodes no longer sync with this one \
             directly, so later changes to the roll will need an events file carried to \
             and from this node. Consider staying a member.",
        );
    }
    confirm(&ctx.out, &preview, args.yes, "leaving the circle")?;

    node.store.set_circle_left(&id, Some(node.now()))?;
    let put = put_amendment(&node, &circle, &format!("Remove {member}"), next)?;
    let mut t = Text::new();
    t.line(format!(
        "Left {} on this machine and asked to be taken off the roll (proposal {}).",
        safe(&circle.name),
        short_id(&put.proposal.event_id())
    ));
    for skill in &put.settled.applied.removed {
        t.line(format!("  removed rule {skill}"));
    }
    let mut report = amendment_report(&circle, &put, "You are off the roll.", t);
    report.json["left"] = json!(true);
    Ok(report)
}

fn parse_threshold(arg: &str, flag: &str) -> Result<Threshold> {
    let bad = || usage(format!("{flag} takes a fraction such as 1/2 or 2/3"));
    let (num, den) = arg.trim().split_once('/').ok_or_else(bad)?;
    let t = Threshold {
        num: num.trim().parse().map_err(|_| bad())?,
        den: den.trim().parse().map_err(|_| bad())?,
    };
    t.check("threshold").map_err(|_| {
        usage(format!(
            "{flag}: a threshold is at least 1/2 and less than 1 (nothing passes without a \
             majority), with a denominator of at most 100"
        ))
    })?;
    Ok(t)
}

/// `circle amend`: puts new rules of the vote to the vote. It needs the charter's own
/// `amend` threshold, which is at least the threshold for an ordinary rule.
fn amend(ctx: &Ctx, args: CircleAmendArgs) -> Result<Report> {
    let node = ctx.open_node()?;
    let circle = find_circle(&node, Some(&args.circle))?;
    let (current, in_force, _) = governance::rule_set(&node.store, &circle.circle_id)?;
    let old = current.content.rules;
    let mut new = old;
    if let Some(p) = &args.pass {
        new.pass = parse_threshold(p, "--pass")?;
    }
    if let Some(a) = &args.amend {
        new.amend = parse_threshold(a, "--amend")?;
    }
    if args.binding {
        new.binding = true;
    }
    if args.advisory {
        new.binding = false;
    }
    if new == old {
        return Err(usage(
            "nothing to change: pass --pass, --amend, --binding or --advisory",
        ));
    }
    new.check().map_err(|_| {
        usage("changing the rules must take at least as many approvals as passing a rule: --amend must be at least --pass")
    })?;
    let next = change_rules(&current.content, &in_force, new)
        .map_err(|e| usage(format!("cannot propose that amendment: {e}")))?;
    let force = |binding: bool| if binding { "binding" } else { "advisory" };
    let mut changes = Vec::new();
    if new.pass != old.pass {
        changes.push(format!(
            "a rule passes with more than {}/{} of its electorate (now {}/{})",
            new.pass.num, new.pass.den, old.pass.num, old.pass.den
        ));
    }
    if new.amend != old.amend {
        changes.push(format!(
            "changing these rules needs more than {}/{} of the roll (now {}/{})",
            new.amend.num, new.amend.den, old.amend.num, old.amend.den
        ));
    }
    if new.binding != old.binding {
        changes.push(format!(
            "passed rules become {} (now {})",
            force(new.binding),
            force(old.binding)
        ));
    }
    let preview = format!(
        "This puts an amendment of {circle} to the vote and casts your approval:\n  {changes}\n\
         The roll and the rules in force stay as they are.\n{need}",
        circle = safe(&circle.name),
        changes = changes.join("\n  "),
        need = need_line(&current, &next),
    );
    confirm(&ctx.out, &preview, args.yes, "the amendment proposal")?;
    let put = put_amendment(&node, &circle, "Change the rules of the vote", next)?;
    // What the proposal needs is decided by the charter, not by this command.
    debug_assert_eq!(threshold_for(&put.proposal, &current.content), old.amend);
    let mut t = Text::new();
    t.line(format!(
        "Proposed changing the rules of the vote (proposal {}).",
        short_id(&put.proposal.event_id())
    ));
    Ok(amendment_report(&circle, &put, "The amendment passed.", t))
}

/// `circle device add|remove`: a member's devices are part of the roll, so changing them
/// is an amendment. One member has one vote however many devices they list.
fn device(ctx: &Ctx, args: CircleDeviceArgs, add: bool) -> Result<Report> {
    let node = ctx.open_node()?;
    let circle = find_circle(&node, Some(&args.circle))?;
    let key: DeviceKey = args.device.trim().parse().map_err(|_| {
        usage("the device must be an `ed25519:` key (its owner sees it with `peerharness status`)")
    })?;
    let (current, rules, _) = governance::rule_set(&node.store, &circle.circle_id)?;
    let member = match &args.member {
        Some(m) => m.clone(),
        None => current
            .content
            .member_of(&node.device_key())
            .map(|e| e.member.clone())
            .ok_or_else(|| usage("you are not on the roll of that circle: pass --member"))?,
    };
    let next = if add {
        add_device(&current.content, &rules, &member, key)
    } else {
        remove_device(&current.content, &rules, &member, &key)
    }
    .map_err(|e| usage(format!("cannot propose that change: {e}")))?;
    let verb = if add { "add" } else { "remove" };
    let preview = format!(
        "This puts an amendment of {circle} to the vote and casts your approval:\n  \
         {verb} device {fp} {prep} {member} on the roll of charter {seq}\n\
         {member} keeps one vote, whichever of their devices signs it.\n{need}",
        circle = safe(&circle.name),
        fp = key.fingerprint(),
        prep = if add { "to" } else { "from" },
        seq = current.seq,
        need = need_line(&current, &next),
    );
    confirm(&ctx.out, &preview, args.yes, "the device proposal")?;
    let title = format!(
        "{} a device {} {member}",
        if add { "Add" } else { "Remove" },
        if add { "to" } else { "from" }
    );
    let put = put_amendment(&node, &circle, &title, next)?;
    let mut t = Text::new();
    t.line(format!(
        "Proposed to {verb} device {} for {member} (proposal {}).",
        key.fingerprint(),
        short_id(&put.proposal.event_id())
    ));
    let mut report = amendment_report(&circle, &put, "The change passed.", t);
    if add && put.settled.charter_notarized.is_some() {
        report.text.push_str(&format!(
            "The new device joins like a new member: `peerharness circle join <address or \
             file> --expect-fingerprint {}`.\n",
            circle.root_key.fingerprint()
        ));
    }
    Ok(report)
}

/// `circle mode`: the owner's standing choice about rules that pass in this circle.
fn mode(ctx: &Ctx, args: CircleModeArgs) -> Result<Report> {
    let node = ctx.open_node()?;
    let circle = find_circle(&node, Some(&args.circle))?;
    let charter = governance::current_charter(&node.store, &circle.circle_id)?;
    let wanted = match args.mode {
        ModeArg::Follow => "follow",
        ModeArg::Ask => "ask",
    };
    if args.mode == ModeArg::Follow {
        // Standing consent to future installs: it takes the owner's confirmation.
        let preview = format!(
            "From now on, rules that pass in {circle} are installed for your agent without \
             asking you each time.\n\
             Still never without asking: a rule with a high-risk finding. You can opt out \
             of any rule (`peerharness rule opt-out`) and switch back to asking at any \
             time.\n\n{charter}",
            circle = safe(&circle.name),
            charter = describe_charter(&charter, Some(&node.device_key())).trim_end(),
        );
        confirm(&ctx.out, &preview, args.yes, "following the circle's rules")?;
    }
    node.store
        .set_circle_adoption(&circle.circle_id, wanted, &charter.digest()?)?;
    let settled = governance::settle(&node, &circle, &governance::user_installer()?, &[])?;
    let mut t = Text::new();
    t.line(format!(
        "Your mode in {} is now {wanted}.",
        safe(&circle.name)
    ));
    for skill in &settled.applied.installed {
        t.line(format!("  installed rule {skill} for your agent"));
    }
    for (skill, why) in &settled.applied.asking {
        t.line(format!(
            "  rule {skill} waits for your confirmation ({why}): `peerharness proposal adopt <id>`"
        ));
    }
    Ok(Report::new(
        json!({
            "circle": circle.name,
            "adoption_mode": wanted,
            "installed": settled.applied.installed,
        }),
        t.finish(),
    ))
}

/// The device `arg` names: an `ed25519:` key, a peer id, or the handle of a member with
/// exactly one device on the roll.
fn resolve_device(charter: &Charter, arg: &str) -> Result<DeviceKey> {
    let arg = arg.trim();
    if let Ok(key) = arg.parse::<DeviceKey>() {
        return Ok(key);
    }
    if let Some(key) = arg
        .parse::<ph_network::PeerId>()
        .ok()
        .and_then(|p| ph_network::device_key_from_peer_id(&p))
    {
        return Ok(key);
    }
    match charter.content.member(arg) {
        Some(entry) if entry.devices.len() == 1 => Ok(entry.devices[0]),
        Some(entry) => Err(usage(format!(
            "{arg} has {} devices; name the one to revoke by its key: {}",
            entry.devices.len(),
            entry
                .devices
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ))),
        None => Err(usage(
            "that is not an `ed25519:` device key, a peer id, or a member on the roll",
        )),
    }
}

/// `circle revoke`: the emergency brake (architecture section 10.8). The root key signs
/// a revocation of one device key. Every node that learns of it stops answering that
/// device and stops counting its ballots. The roll is not changed.
fn revoke(ctx: &Ctx, args: CircleRevokeArgs) -> Result<Report> {
    let node = ctx.open_node()?;
    let circle = find_circle(&node, Some(&args.circle))?;
    let id = circle.circle_id;
    if !circle.is_founder {
        return Err(refused(format!(
            "only the node that founded {} holds its root key and can revoke a device. Ask \
             the founder, or put a removal to the vote: `peerharness circle remove`.",
            circle.name
        )));
    }
    let charter = governance::current_charter(&node.store, &id)?;
    let device = resolve_device(&charter, &args.device)?;
    if device == node.device_key() {
        return Err(refused(
            "that is the device you are using. Revoking it would cut this node, which holds \
             the circle's root key, off from the members.",
        ));
    }
    if node.store.is_revoked(&id, &device)? {
        return Err(usage("that device is already revoked in this circle"));
    }
    let reason = ph_core::redact(args.reason.trim()).text;
    ph_protocol::text::check_text("reason", &reason, 0, 200, ph_protocol::text::Lines::Single)
        .map_err(|_| usage("the reason must be one line of at most 200 characters"))?;
    let owner = charter.content.member_of(&device).map(|e| e.member.clone());
    let mut preview = format!(
        "This revokes device {fp}{owner} in {circle}, signed with the circle's root key.\n  \
         Every node that learns of it stops syncing with that device and stops counting \
         its ballots, including ballots it already cast.\n  \
         It cannot be undone: that device key can never be used in this circle again.\n  \
         It does not change the roll.",
        fp = device.fingerprint(),
        owner = owner
            .as_ref()
            .map(|m| format!(" ({m})"))
            .unwrap_or_default(),
        circle = safe(&circle.name),
    );
    if let Some(m) = &owner {
        preview.push_str(&format!(
            " {m} stays a member: to replace the device, `peerharness circle device add`; \
             to remove the member, `peerharness circle remove {m}`."
        ));
    }
    if !reason.is_empty() {
        preview.push_str(&format!(
            "\nEvery member can read this reason, exactly as sent: {}",
            safe(&reason)
        ));
    }
    confirm(&ctx.out, &preview, args.yes, "the revocation")?;

    let now = node.now();
    let authority = CircleAuthority::load(node.keystore()?, &id)
        .context("cannot unlock the circle root key")?;
    let revocation = authority
        .issue_revocation(device, &reason, now)
        .map_err(|e| anyhow!("cannot sign the revocation: {e}"))?;
    let env = governance::submit(
        &node.store,
        authority.signing_key(),
        &id,
        &Scope::all(),
        EventBody::Revocation(RevocationBody { revocation }),
        now,
    )?;
    let settled = governance::settle(&node, &circle, &governance::user_installer()?, &[])?;
    let mut t = Text::new();
    t.line(format!(
        "Revoked device {} in {}.",
        device.fingerprint(),
        safe(&circle.name)
    ));
    t.line(format!(
        "Send it to the members now: `peerharness sync <peer>` or `peerharness events \
         export --circle {}`. A node counts that device until the revocation reaches it.",
        circle.name
    ));
    for skill in &settled.applied.removed {
        t.line(format!(
            "  rule {skill} is no longer in force here without that device's approval"
        ));
    }
    Ok(Report::new(
        json!({
            "circle": circle.name,
            "revoked_device": device,
            "member": owner,
            "event_id": env.event_id,
        }),
        t.finish(),
    ))
}

/// The newest charter in `lines` whose roll lists `device`, verified statelessly.
fn charter_for(lines: &[&str], device: &DeviceKey, now: ph_core::Timestamp) -> Option<Charter> {
    let mut best: Option<Charter> = None;
    for line in lines {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(ev) = v.get("event") else { continue };
        let Ok(verified) = validate_stateless(ev.to_string().as_bytes(), now) else {
            continue;
        };
        let EventBody::Charter(body) = &verified.body else {
            continue;
        };
        let charter = &body.charter;
        if charter.content.member_of(device).is_some()
            && best.as_ref().is_none_or(|b| charter.seq > b.seq)
        {
            best = Some(charter.clone());
        }
    }
    best
}

fn join(ctx: &Ctx, args: CircleJoinArgs) -> Result<Report> {
    let node = ctx.open_node()?;
    let now = node.now();
    let me = node.device_key();
    let source = crate::carrier::read_source(&args.invite_file)?;
    let lines: Vec<&str> = source.lines.iter().map(String::as_str).collect();
    let charter = charter_for(&lines, &me, now).ok_or_else(|| {
        refused(
            "that file holds no charter with this device on its roll. Ask a member to run \
             `peerharness circle invite` with your device key (see `peerharness status`) \
             and to export again once the admission has passed.",
        )
    })?;
    let fingerprint = charter.issuer_key.fingerprint();
    if let Some(expected) = &args.expect_fingerprint {
        if expected.trim() != fingerprint {
            return Err(refused(format!(
                "the circle root fingerprint is {fingerprint}, not the one you expected. Do not join."
            )));
        }
    } else if args.yes {
        return Err(usage("--yes requires --expect-fingerprint"));
    }
    let name = args
        .name
        .unwrap_or_else(|| format!("circle-{}", &fingerprint[..fingerprint.len().min(9)]));
    if node.store.circle(&charter.circle_id)?.is_some() {
        return Err(usage(
            "this node is already in that circle: use `peerharness events import`",
        ));
    }
    let my_entry = charter
        .content
        .member_of(&me)
        .ok_or_else(|| anyhow!("this device is not on the roll"))?;
    let preview = format!(
        "You are about to join a circle as {member}.\n  root fingerprint {fingerprint}\n\
         Check that fingerprint with the founder through another channel before you continue.\n\n{charter}\n\
         Joining means accepting this charter and the way it is amended.{binding}",
        member = my_entry.member,
        charter = describe_charter(&charter, Some(&me)).trim_end(),
        binding = if charter.content.rules.binding {
            "\nRules that pass will be installed for your agent without asking each time; \
             you can opt out of any rule, or switch to asking, at any time."
        } else {
            ""
        },
    );
    confirm(&ctx.out, &preview, args.yes, "joining the circle")?;

    governance::join_circle(&node.store, &name, &charter, &me, now)?;
    let bundles = crate::library::bundle_store(&node.home);
    let summary = governance::import_lines(&node.store, &bundles, lines.iter().copied(), now)?;
    let circle = node
        .store
        .circle(&charter.circle_id)?
        .ok_or_else(|| anyhow!("the circle was not stored"))?;
    let settled = governance::settle(&node, &circle, &governance::user_installer()?, &[])?;

    let mut t = Text::new();
    t.line(format!("Joined {} as {}.", safe(&name), my_entry.member));
    t.kv("charter", charter.seq);
    t.kv("events imported", summary.stored);
    t.kv("your mode", &circle.adoption_mode);
    for skill in &settled.applied.installed {
        t.line(format!("  installed rule {skill}"));
    }
    for (skill, why) in &settled.applied.asking {
        t.line(format!(
            "  rule {skill} waits for your confirmation ({why})"
        ));
    }
    Ok(Report::new(
        json!({
            "circle": name,
            "circle_id": charter.circle_id,
            "member": my_entry.member,
            "charter_seq": charter.seq,
            "events_imported": summary.stored,
            "installed": settled.applied.installed,
        }),
        t.finish(),
    ))
}
