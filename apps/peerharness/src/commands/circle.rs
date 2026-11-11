//! `peerharness circle`: founding a circle, showing its charter, joining, and every
//! change to the charter.
//!
//! Membership and the rules of the vote are decided by vote (architecture section
//! 10.8). `invite`, `remove`, `leave`, `amend` and `device` therefore change nothing by
//! themselves: each puts an amendment to the vote and casts the proposer's own approval.
//! With one member that approval is the majority, so the change passes at once; with
//! more, the other members have to approve too.
//!
//! An amendment carries the rules in force forward by listing them. A node that lacks a
//! rule the charter in force carries cannot list it, so `invite`, `remove`, `amend` and
//! `device` draft nothing there ([`holds_every_carried_rule`]). `leave` never waits: it
//! changes its owner's machine there as everywhere, and makes no request to change the
//! roll from that node.
//!
//! What is put to the vote is what was shown. Each of these commands drafts from the
//! charter and the rules in force it read before its preview. After the owner answered
//! it unlocks the key, checks that the node still holds exactly that, and signs, in
//! that order, with the check and the signatures in one transaction of the store
//! ([`put_amendment`]). `leave` is no exception: its first run changes the machine and
//! then signs the request it previewed, or none.
//!
//! Two commands act on this machine alone. `mode` is the owner's standing choice about
//! rules that pass. `revoke` is the founder's emergency brake for a lost device: it cuts
//! one device key off and leaves the roll as the members voted it.
//!
//! Inside a coding agent's session every step here is refused, except two that the
//! owner may be asked about in a window when they allowed it (ADR-037): `invite` and
//! `join`. `create` shares nothing and asks nothing, in a session as in a terminal.

use std::collections::BTreeSet;

use anyhow::{anyhow, Context, Result};
use ph_core::{CircleId, DeviceKey, Scope, Timestamp};
use ph_governance::{
    add_device, admit_member, change_rules, remove_device, remove_member, threshold_for,
    ProposalView, RuleSet, Tally,
};
use ph_identity::{accept_credential, CircleAuthority};
use ph_protocol::{
    is_valid_member_name, validate_stateless, Charter, CharterContent, EventBody, ProposalAction,
    RevocationBody, RollEntry, SigningKey, Threshold, VoteDecision,
};
use ph_store::{CircleRow, Store};
use serde_json::{json, Value};

use crate::carrier::Record;
use crate::cli::{
    CircleAmendArgs, CircleCommand, CircleDeviceArgs, CircleInviteArgs, CircleJoinArgs,
    CircleLeaveArgs, CircleModeArgs, CirclePlaceArgs, CircleRemoveArgs, CircleRevokeArgs,
    DeviceCommand, ModeArg,
};
use crate::commands::proposal::key_before_window;
use crate::commands::Ctx;
use crate::config::Config;
use crate::consent::{
    asks_circle_in_window, circle_step_can_be_asked, confirm, confirm_circle_or_window, human_only,
    in_agent_session,
};
use crate::error::{exit_kind, refused, usage, ExitKind};
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
        CircleCommand::Place(args) => place(ctx, args),
        CircleCommand::Revoke(args) => revoke(ctx, args),
    }
}

/// The circle named `name`, or the only circle when `name` is `None`.
pub fn find_circle(node: &Node, name: Option<&str>) -> Result<CircleRow> {
    match name {
        // The error names no circle, neither the one asked for nor the ones there are:
        // it says where the names can be read.
        Some(n) => node.store.circle_by_name(n)?.ok_or_else(|| {
            usage(
                "no circle on this node has that name. `peerharness status` lists the \
                 circles of this node by name. A circle you joined is called \
                 circle-<start of its root fingerprint> here, unless you passed --name \
                 to `circle join`.",
            )
        }),
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
    let (current, rules, _) = governance::rule_set(&node.store, &id)?;
    holds_every_carried_rule(&rules)?;
    let entry = RollEntry::new(&args.member, vec![device], scopes);
    let next = admit_member(&current.content, &rules, entry)
        .map_err(|e| usage(format!("cannot propose that admission: {e}")))?;
    let need = current.content.rules.pass.need(current.content.roll.len());

    // A file with the circle's records is the person's own step (`events export`): inside
    // an agent's session none is written, and asking for one there is refused.
    let in_session = in_agent_session();
    if args.out.is_some() {
        human_only("writing a circle's records out")?;
    }
    let mut preview = format!(
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
    let in_window = asks_circle_in_window(&node.config);
    if in_window {
        // In a terminal the person typed the key. Here their agent passed it on.
        preview.push_str(&admission_check(&args.member, &circle.name));
    }
    key_before_window(&node, "the admission proposal", in_window)?;
    confirm_circle_or_window(
        &ctx.out,
        &preview,
        args.yes,
        "the admission proposal",
        &node.config,
    )?;

    // The yes was for an admission to the charter the preview named. What this node
    // holds can have changed while the owner read (a sync, an import), and unlocking
    // the key can ask for a passphrase, which is one more wait. So the key is unlocked
    // first and the node is checked after, in the transaction that signs: when the
    // node changed, nothing is signed (`put_amendment`).
    let from = Drafted {
        current: &current,
        rules: &rules,
    };
    let title = format!("Admit {}", args.member);
    let Put {
        proposal,
        settled,
        tally,
    } = put_amendment(&node, &circle, &title, next, &from)?;

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
            let fingerprint = circle.root_key.fingerprint();
            let peer = node.peer_id();
            let daemon = crate::daemon_info::DaemonInfo::running(&node.home);
            if in_session {
                // The fingerprint is what tells the invitee that the circle is the
                // inviter's. It is named apart from everything that travels by chat, and
                // the line to join with leaves it out.
                let reachable = daemon.as_ref().filter(|d| d.internet.is_some());
                let address = daemon
                    .as_ref()
                    .filter(|d| d.internet.is_none())
                    .and_then(|d| d.listen_addrs.first().cloned());
                let (what, how) = match (reachable, &address) {
                    (Some(d), _) => (
                        format!("this node's peer id, {}", d.peer_id),
                        format!("{} --internet", d.peer_id),
                    ),
                    (None, Some(addr)) => (format!("this node's address, {addr}"), addr.clone()),
                    (None, None) => (
                        format!("this node's peer id, {peer}"),
                        format!("{peer} --internet"),
                    ),
                };
                t.line(format!(
                    "{} needs two things from you: {what}, by any channel, and the root \
                     fingerprint {fingerprint}, by phone or in person.",
                    args.member
                ));
                t.line(format!(
                    "With both they join: by asking their agent to, or in a terminal with \
                     `peerharness circle join {how} --expect-fingerprint <the fingerprint \
                     you told them>`."
                ));
                if reachable.is_none() && address.is_none() {
                    t.line(
                        "This node is not reachable yet, and has to be for them to join: \
                         `peerharness daemon --internet` has to run here.",
                    );
                }
                t.line(
                    "No file with the circle's records was written: inside a coding agent's \
                     session that stays your own step (`peerharness events export`).",
                );
            } else {
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
                    "Give that file to {} together with the root fingerprint {fingerprint} (out of band).",
                    args.member,
                ));
                t.line(
                    "They run: `peerharness circle join <file> --expect-fingerprint <fingerprint>`.",
                );
                // A running daemon here already has them on its roll: no file is needed.
                if let Some(d) = daemon.as_ref().filter(|d| d.internet.is_some()) {
                    t.line(format!(
                        "Or, from anywhere, since your daemon is on the public network: \
                         `peerharness circle join {} --internet --expect-fingerprint {fingerprint}`.",
                        d.peer_id,
                    ));
                } else if let Some(addr) = daemon.and_then(|d| d.listen_addrs.into_iter().next()) {
                    t.line(format!(
                        "Or, if they can reach your daemon: `peerharness circle join {addr} \
                         --expect-fingerprint {fingerprint}`."
                    ));
                } else {
                    t.line(format!(
                        "Or run `peerharness daemon --internet` and give them this node's peer \
                         id instead of the file: `peerharness circle join {peer} --internet \
                         --expect-fingerprint {fingerprint}`."
                    ));
                }
                written = Some(path.display().to_string());
            }
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
    for line in settled_rule_lines(&settled) {
        t.line(format!("  {line}"));
    }
    Ok(Report::new(
        json!({
            "proposal_id": proposal.event_id(),
            "passed": tally.passed(),
            "approvals": tally.approvals().len(),
            "need": tally.need(),
            "charter_seq": settled.charter_notarized,
            "removed_rules": settled.applied.removed,
            "not_removed_rules": settled.applied.not_removed,
            "kept_edited_rules": settled.applied.kept_edited_names(),
            "events_file": written,
            "peer_id": node.peer_id().to_string(),
            "root_fingerprint": circle.root_key.fingerprint(),
        }),
        t.finish(),
    ))
}

/// Refuses to draft an amendment on a node that does not hold every rule the charter in
/// force carries.
///
/// An amendment's `carried` list is filled from the rules in force on the node that
/// drafts it. A carried proposal that never reached this node (a join that did not
/// finish, a rule in a scope this node is not sent) is not among them, so the draft
/// would leave it out, and approving it would take that rule out of force for everyone
/// under a preview that says nothing about rules.
fn holds_every_carried_rule(rules: &RuleSet) -> Result<()> {
    let missing = rules.missing_carried().len();
    if missing == 0 {
        return Ok(());
    }
    Err(refused(format!(
        "the charter in force carries {missing} rule(s) that this node does not hold, so a \
         change to the charter drafted here would leave them out and take them out of force \
         for everyone. Nothing was proposed. Import the events file of a member who holds \
         them first (`peerharness events import`); `peerharness rule list` shows what is \
         missing."
    )))
}

/// What a window adds to the preview of an admission, whether the owner proposes it or
/// votes on it. In a terminal the person typed or read the device key themselves; in a
/// window all they have is what the window says.
pub(crate) fn admission_check(member: &str, circle: &str) -> String {
    format!(
        "\n\nCheck the device with {member} first: `peerharness status` on their machine shows \
         the same fingerprint. Whoever holds that device gets a vote in {circle} and can read \
         its proposals and ballots.\n\
         If you did not just ask your agent for this, choose Cancel.",
        circle = safe(circle),
    )
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

/// What an amendment was drafted from and its preview was made of: the charter that
/// was current then, and the rules in force then, which the draft carries.
struct Drafted<'a> {
    current: &'a Charter,
    rules: &'a RuleSet,
}

/// Puts `next` to the vote as an amendment of the charter it was drafted from, casts
/// the proposer's approval and settles. The caller has shown the preview and has the
/// owner's confirmation.
///
/// The confirmation is for what the preview said. When this node no longer holds what
/// the draft was made from (`from`), because a sync or an import stored a newer charter
/// or changed the rules in force while the owner read or typed a passphrase, this
/// refuses after the key is unlocked and before it signs, and nothing is stored
/// ([`governance::as_drafted`]).
///
/// The order is: the key, then one transaction that holds the check, the proposal and
/// the proposer's approval, then settling. Unlocking can ask for a passphrase, so it
/// comes before the transaction, in which nothing waits for anyone. Nobody else writes
/// to the store inside it ([`governance::atomically`]), so no ballot and no charter
/// arrives between the check and the two signatures, and an approval that cannot be
/// stored leaves no proposal either. Settling changes the owner's skills and comes
/// after the commit.
fn put_amendment(
    node: &Node,
    circle: &CircleRow,
    title: &str,
    next: CharterContent,
    from: &Drafted<'_>,
) -> Result<Put> {
    let key = node.device()?.signing_key();
    let now = node.now();
    let proposal = governance::atomically(&node.store, key, |store| {
        let proposal = propose_amendment(store, key, &circle.circle_id, title, next, from, now)?;
        approve(store, key, &proposal, now)?;
        Ok(proposal)
    })?;
    settled(node, circle, proposal)
}

/// The check and the first signature of [`put_amendment`], for the inside of its
/// transaction: that the draft is still what this node would draft, then the proposal
/// under the charter it was drafted from. `key` is the unlocked device key. An error
/// here means that nothing was stored.
fn propose_amendment(
    store: &Store,
    key: &SigningKey,
    circle: &CircleId,
    title: &str,
    next: CharterContent,
    from: &Drafted<'_>,
    now: Timestamp,
) -> Result<ProposalView> {
    let drafted = governance::as_drafted(store, key, circle, from.current, from.rules)?;
    governance::propose_under(
        store,
        key,
        circle,
        &drafted,
        NewProposal {
            scope: &Scope::all(),
            title,
            summary: "",
            action: ProposalAction::Amend { next },
        },
        now,
    )
}

/// The proposer's approval of the amendment they just proposed: signed in the same
/// transaction as the proposal.
fn approve(store: &Store, key: &SigningKey, proposal: &ProposalView, now: Timestamp) -> Result<()> {
    governance::cast_vote(store, key, proposal, VoteDecision::Approve, None, now)?;
    Ok(())
}

/// What follows from an amendment that was proposed and approved, after the
/// transaction that stored both: settling the circle, and the count.
fn settled(node: &Node, circle: &CircleRow, proposal: ProposalView) -> Result<Put> {
    let settled = governance::settle(node, circle, &governance::user_installer()?, &[])?;
    let (_, tally) = governance::count(&node.store, &proposal)?;
    Ok(Put {
        proposal,
        settled,
        tally,
    })
}

/// What settling the circle did to the owner's skills besides the amendment a command
/// was run for: a rule that went, a skill that could not be removed and a voted copy
/// that was left because it was edited. The command may be the first to settle since
/// a vote passed on this node, and an edited copy is named by that run or by none
/// ([`governance::Applied::left_in_place_lines`]).
fn settled_rule_lines(settled: &governance::Settled) -> Vec<String> {
    let mut lines: Vec<String> = settled
        .applied
        .removed
        .iter()
        .map(|skill| format!("removed rule {skill}"))
        .collect();
    lines.extend(settled.applied.left_in_place_lines());
    lines
}

/// [`settled_rule_lines`] under the report of an amendment a command proposed.
/// `circle leave` prints its own and does not use this.
fn with_rule_lines(mut report: Report, settled: &governance::Settled) -> Report {
    for line in settled_rule_lines(settled) {
        report.text.push_str(&format!("  {line}\n"));
    }
    report
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
            "not_removed_rules": put.settled.applied.not_removed,
            "kept_edited_rules": put.settled.applied.kept_edited_names(),
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
    holds_every_carried_rule(&rules)?;
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
    let from = Drafted {
        current: &current,
        rules: &rules,
    };
    let put = put_amendment(
        &node,
        &circle,
        &format!("Remove {}", args.member),
        next,
        &from,
    )?;
    let mut t = Text::new();
    t.line(format!(
        "Proposed removing {} (proposal {}).",
        args.member,
        short_id(&put.proposal.event_id())
    ));
    let report = amendment_report(&circle, &put, "The removal passed.", t);
    Ok(with_rule_lines(report, &put.settled))
}

/// Why `circle leave` made no request to take its owner off the roll.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NoRequest {
    /// This node does not hold every rule the charter in force carries: how many it
    /// lacks. A removal drafted here would leave them out, or list them by id and bring
    /// back one that was repealed since. This node cannot tell which, so it could not
    /// show its owner what they would approve.
    MissingCarried(usize),
    /// The device key could not be unlocked.
    KeyLocked,
    /// What this node holds of the circle is no longer what the preview was built
    /// from: the charter in force or the rules in force changed while the owner read
    /// or while the key was being unlocked. What the preview said about the request is
    /// not carried out on another state.
    Changed,
    /// The proposal was refused when it was to be stored: this node would not accept
    /// the event. (The sentence for it also names a charter that changed in the instant
    /// after the check. Since the check and the signature are one transaction, that no
    /// longer happens.)
    Refused,
    /// The member is no longer on the roll of the charter in force.
    OffTheRoll,
    /// The request is on record already: a proposal under the charter in force that is
    /// exactly this removal ([`removals_on_record`]).
    OnRecord,
}

impl NoRequest {
    /// A stable machine-readable code, the `reason` of the JSON report.
    const fn code(self) -> &'static str {
        match self {
            NoRequest::MissingCarried(_) => "missing_carried_rules",
            NoRequest::KeyLocked => "device_key_locked",
            NoRequest::Changed => "changed_while_confirming",
            NoRequest::Refused => "proposal_refused",
            NoRequest::OffTheRoll => "off_the_roll",
            NoRequest::OnRecord => "request_on_record",
        }
    }

    /// Why no request to take `member` off the roll of `circle` was made on this node,
    /// and how it can be made: for a preview or a report. `circle` is the circle's name
    /// as its owner types it after `--circle`.
    fn explain(self, circle: &str, member: &str) -> String {
        let again = format!("`peerharness circle leave --circle {circle}`");
        match self {
            NoRequest::MissingCarried(n) => format!(
                "this node does not hold {n} rule(s) that the charter in force carries, and \
                 a request drafted here would either drop them or bring back one that was \
                 repealed since. You stay on the roll. To make the request, import the \
                 events file of a member who holds those rules (`peerharness events \
                 import`) and run {again} again, or ask a member to run `peerharness \
                 circle remove {member} --circle {circle}`."
            ),
            NoRequest::KeyLocked => format!(
                "the device key could not be unlocked, and the request is signed with it. \
                 You stay on the roll. Run {again} again to make the request."
            ),
            NoRequest::Changed => format!(
                "what this node holds of the circle changed while this was being confirmed \
                 (its charter, or the rules in force). This machine was changed as shown. \
                 No request was made and nothing was signed: what you were shown about the \
                 request no longer holds. Run {again} again: it shows the request as it \
                 would be now and, once you confirm, makes it."
            ),
            NoRequest::Refused => format!(
                "the circle's charter changed on this node at that moment, or this node \
                 would not accept the request. You stay on the roll. Run {again} again to \
                 make the request."
            ),
            NoRequest::OffTheRoll => {
                "you are not on the roll of the charter in force, so there is nothing to \
                 ask for."
                    .to_owned()
            }
            NoRequest::OnRecord => "one is on record already.".to_owned(),
        }
    }
}

/// The error when something failed after `circle leave` changed the machine and before
/// a request existed. It names no circle: the owner knows which one they left.
const LEFT_WITHOUT_REQUEST: &str =
    "this machine left <circle> and the rules that circle installed were removed, but no \
     request to take you off the roll was made. Run `peerharness circle leave --circle \
     <circle>` again to make it";

/// The same once the request is stored: what failed is what follows from it.
const LEFT_AND_REQUESTED: &str =
    "this machine left <circle>, the rules that circle installed were removed, and the \
     request to take you off the roll is stored. What follows from it failed";

/// A charter's content in the order `remove_member` and the other drafting functions
/// give it: the roll by member, each entry's devices and scopes sorted, the carried
/// rules by id. Two contents that say the same compare equal afterwards.
fn canonical(mut content: CharterContent) -> CharterContent {
    content.normalize();
    for entry in &mut content.roll {
        entry.devices.sort_by_key(DeviceKey::to_string);
        entry.scopes.sort();
    }
    content
}

/// The proposals on this node that would take one member off the roll of the charter
/// in force.
struct OnRecord {
    /// The request: a proposal whose next charter is exactly what this node would draft
    /// for the removal now, with its count. The member's own comes first, then another
    /// member's `circle remove`.
    request: Option<(ProposalView, Tally)>,
    /// A proposal that takes the member off the roll and is not the request: it changes
    /// something else as well (a removal drafted before a rule passed drops that rule),
    /// or this node cannot draft the removal to compare it with. The member's own
    /// comes first.
    other: Option<ProposalView>,
}

/// What is on record about taking `member` off the roll of `current`, the charter in
/// force. `draft` is the removal this node would draft now (`remove_member` from the
/// charter and the rules in force), or `None` where it drafts none.
///
/// Only a proposal whose next charter equals `draft` counts as "the request". An
/// amendment that takes the member off the roll and changes anything else is another
/// proposal: `circle leave` does not call it the request to leave, does not point its
/// owner at approving it, and goes on to make a request of its own.
fn removals_on_record(
    store: &Store,
    me: &DeviceKey,
    current: &Charter,
    draft: Option<&CharterContent>,
    member: &str,
) -> Result<OnRecord> {
    let digest = current.digest()?;
    let mut request: Option<ProposalView> = None;
    let mut other: Option<ProposalView> = None;
    for ev in store.proposals(&current.circle_id)? {
        let Ok(p) = governance::proposal_view(store, &ev.event_id) else {
            continue;
        };
        let Some(next) = p
            .amend_next()
            .filter(|next| p.charter() == digest && next.member(member).is_none())
        else {
            continue;
        };
        let exact = draft.is_some_and(|draft| canonical(next.clone()) == *draft);
        let slot = if exact { &mut request } else { &mut other };
        // The first one found, unless a later one is the member's own.
        let own = p.author() == *me;
        let have_own = slot.as_ref().is_some_and(|held| held.author() == *me);
        if slot.is_none() || (own && !have_own) {
            *slot = Some(p);
        }
    }
    let request = match request {
        Some(p) => {
            let (_, tally) = governance::count(store, &p)?;
            Some((p, tally))
        }
        None => None,
    };
    Ok(OnRecord { request, other })
}

/// The line that names a proposal which takes the member off the roll and is not the
/// request `circle leave` makes (see [`OnRecord::other`]). `comparable` says whether
/// this node could draft the removal to compare it with.
fn other_removal_line(other: &ProposalView, comparable: bool) -> String {
    let id = short_id(&other.event_id());
    if comparable {
        format!(
            "Proposal {id} on record also takes you off the roll, and changes more than \
             that: `peerharness proposal show {id}`."
        )
    } else {
        format!(
            "Proposal {id} on record takes you off the roll. This node cannot show whether \
             it changes anything else: `peerharness proposal show {id}`."
        )
    }
}

/// The lines of a report about a request that is on record, and whether the member's
/// own approval is on it.
fn on_record_lines(t: &mut Text, proposal: &ProposalView, tally: &Tally, member: &str) {
    t.line(format!("  {tally}"));
    if !tally.approvals().iter().any(|a| a.member == member) {
        t.line(format!(
            "  Your approval is not on it: `peerharness proposal vote {} approve`.",
            short_id(&proposal.event_id())
        ));
    }
}

fn on_record_json(proposal: &ProposalView, tally: &Tally) -> Value {
    json!({
        "proposal_id": proposal.event_id(),
        "passed": tally.passed(),
        "approvals": tally.approvals().len(),
        "need": tally.need(),
    })
}

/// What the first run of `circle leave` does about the request to be taken off the
/// roll. It is decided from what the node holds before its owner is asked, and the
/// preview says exactly this. After the answer the run does this or nothing: it never
/// makes a request that its preview did not announce.
enum RequestPlan {
    /// No request from this node, and why ([`NoRequest::MissingCarried`]).
    None(NoRequest),
    /// No request by this run: this one is on record under the charter in force.
    OnRecord(Box<ProposalView>),
    /// The request: the removal that was drafted for the preview.
    Make,
}

/// Decides [`RequestPlan`] for the member `member` of `current`, from the rules in
/// force that were read with it and the removal drafted from both (`draft`).
fn plan_request(
    store: &Store,
    me: &DeviceKey,
    current: &Charter,
    rules: &RuleSet,
    draft: &CharterContent,
    member: &str,
) -> Result<(RequestPlan, Option<ProposalView>)> {
    let missing = rules.missing_carried().len();
    if missing > 0 {
        // Nothing can be compared with a draft this node could not make.
        let on_record = removals_on_record(store, me, current, None, member)?;
        return Ok((
            RequestPlan::None(NoRequest::MissingCarried(missing)),
            on_record.other,
        ));
    }
    let on_record = removals_on_record(store, me, current, Some(draft), member)?;
    Ok(match on_record.request {
        Some((proposal, _)) => (RequestPlan::OnRecord(Box::new(proposal)), on_record.other),
        None => (RequestPlan::Make, on_record.other),
    })
}

/// Why a first `circle leave` signed no request, with the request and its count when
/// the reason is that one is on record ([`NoRequest::OnRecord`]).
type NotRequested = (NoRequest, Option<Box<(ProposalView, Tally)>>);

/// Signs the request a first `circle leave` previewed, and its owner's approval of it:
/// the removal `next`, drafted from `from` before the owner was asked, under the charter
/// it was drafted from. `key` is the unlocked device key, so no prompt lies between the
/// checks here and the signatures. The checks, the proposal and the approval are one
/// transaction ([`governance::atomically`]): no other process writes to the store
/// between a check and a signature, and an approval that cannot be stored leaves no
/// proposal.
///
/// The first check is the one every change to a charter gets
/// ([`governance::as_drafted`]). When this node no longer holds what the preview was
/// built from, nothing is signed and the reason is [`NoRequest::Changed`]: the draft is
/// not made anew from what the node holds now, because nobody was shown that.
///
/// The second is about what is on record. `as_drafted` compares the charter and the
/// rules in force, not the proposals, and a member's `circle remove` of this very
/// member can arrive while the owner reads or types a passphrase. A second, identical
/// removal would split the members' approvals between two proposals, so when exactly
/// this removal is on record now nothing is signed, and the reason is
/// [`NoRequest::OnRecord`] with that proposal.
fn sign_removal(
    store: &Store,
    key: &SigningKey,
    circle: &CircleId,
    member: &str,
    next: CharterContent,
    from: &Drafted<'_>,
    now: Timestamp,
) -> Result<std::result::Result<ProposalView, NotRequested>> {
    governance::atomically(store, key, |store| {
        let drafted = match governance::as_drafted(store, key, circle, from.current, from.rules) {
            Ok(drafted) => drafted,
            Err(e) if exit_kind(&e) == ExitKind::Refused => {
                return Ok(Err((NoRequest::Changed, None)))
            }
            Err(e) => return Err(e),
        };
        let me = DeviceKey::from_signing_key(key);
        let on_record = removals_on_record(store, &me, from.current, Some(&next), member)?;
        if let Some(found) = on_record.request {
            return Ok(Err((NoRequest::OnRecord, Some(Box::new(found)))));
        }
        let title = format!("Remove {member}");
        let signed = governance::propose_under(
            store,
            key,
            circle,
            &drafted,
            NewProposal {
                scope: &Scope::all(),
                title: &title,
                summary: "",
                action: ProposalAction::Amend { next },
            },
            now,
        );
        let proposal = match signed {
            Ok(proposal) => proposal,
            Err(e) if exit_kind(&e) == ExitKind::Refused => {
                return Ok(Err((NoRequest::Refused, None)))
            }
            Err(e) => return Err(e),
        };
        approve(store, key, &proposal, now)?;
        Ok(Ok(proposal))
    })
}

/// The request half of a first `circle leave`, after the machine was changed: unlocks
/// the device key, then signs the removal the preview described and the owner's
/// approval of it ([`sign_removal`]), and settles.
///
/// Nothing in here undoes the leave. A request that cannot be made is a reason in the
/// report (`Err` of the inner result), and a later `circle leave` shows and makes it.
fn request_removal(
    node: &Node,
    circle: &CircleRow,
    member: &str,
    next: CharterContent,
    from: &Drafted<'_>,
) -> Result<std::result::Result<Put, NotRequested>> {
    // A passphrase prompt, where the keystore has one, is here: before the checks.
    let Ok(device) = node.device() else {
        return Ok(Err((NoRequest::KeyLocked, None)));
    };
    // An error here took back whatever the transaction had stored: no request exists.
    let signed = sign_removal(
        &node.store,
        device.signing_key(),
        &circle.circle_id,
        member,
        next,
        from,
        node.now(),
    )
    .map_err(|e| e.context(LEFT_WITHOUT_REQUEST))?;
    let proposal = match signed {
        Ok(proposal) => proposal,
        Err(why) => return Ok(Err(why)),
    };
    let put = settled(node, circle, proposal).context(LEFT_AND_REQUESTED)?;
    Ok(Ok(put))
}

/// `circle leave --undo`: the owner follows the circle again on this machine. Nothing
/// is signed and nothing on record changes; the preview says what is on record.
fn follow_again(ctx: &Ctx, node: &Node, circle: &CircleRow, yes: bool) -> Result<Report> {
    let id = circle.circle_id;
    let me = node.device_key();
    let name = safe(&circle.name);
    let (current, rules, _) = governance::rule_set(&node.store, &id)?;
    let preview = match current.content.member_of(&me) {
        Some(entry) => {
            let member = entry.member.clone();
            // A request that is on record stays there: this run withdraws nothing, and
            // nothing that was signed can be withdrawn. Whether one is on record is
            // read here, not assumed: a machine can have left without making one.
            let draft = if rules.missing_carried().is_empty() {
                remove_member(&current.content, &rules, &member).ok()
            } else {
                None
            };
            let on_record =
                removals_on_record(&node.store, &me, &current, draft.as_ref(), &member)?;
            let request = on_record
                .request
                .map(|(proposal, _)| proposal)
                .or(on_record.other.filter(|p| p.author() == me));
            let about_the_request = match request {
                Some(proposal) => format!(
                    "A request to take you off the roll is on record (proposal {}) and \
                     stays there; the members may still approve it.",
                    short_id(&proposal.event_id())
                ),
                None => "No request to take you off the roll is on record.".to_owned(),
            };
            format!(
                "This follows {name} again on this machine: rules in force are installed \
                 for your agent according to your mode ({}).\n{about_the_request}",
                circle.adoption_mode
            )
        }
        None => format!(
            "This follows {name} again on this machine. You are not on the roll of its \
             charter in force, so none of its rules binds you and none is installed."
        ),
    };
    confirm(&ctx.out, &preview, yes, "following the circle again")?;
    node.store.set_circle_left(&id, None)?;
    let settled = governance::settle(node, circle, &governance::user_installer()?, &[])?;
    let mut t = Text::new();
    t.line(format!("Following {name} again."));
    for skill in &settled.applied.installed {
        t.line(format!("  installed rule {skill} for your agent"));
    }
    for skill in &settled.applied.removed {
        t.line(format!("  removed rule {skill}"));
    }
    for line in settled.applied.left_in_place_lines() {
        t.line(format!("  {line}"));
    }
    for held in &settled.applied.held {
        t.line(format!("  {}", held.line(&circle.name)));
    }
    Ok(Report::new(
        json!({
            "circle": circle.name,
            "left": false,
            "installed": settled.applied.installed,
            "removed_rules": settled.applied.removed,
            "not_removed_rules": settled.applied.not_removed,
            "kept_edited_rules": settled.applied.kept_edited_names(),
        }),
        t.finish(),
    ))
}

/// `circle leave`: the owner stops following the circle on this machine at once, and
/// asks the members to take them off the roll. Nobody can be made to follow a circle;
/// the roll itself changes only by vote, like every change to it.
///
/// What the run does about the request is decided before the owner is asked
/// ([`RequestPlan`]), and the preview says it. The machine then comes first and needs
/// no key: the circle is marked as left and the rules it installed are removed before
/// anything is signed. The request comes after, and is signed only if it is still what
/// the preview said: the key is unlocked, the node is checked against what the preview
/// was built from, and the removal that was drafted for the preview is signed, unless
/// exactly that removal has arrived on record meanwhile ([`sign_removal`]). A
/// request that was not made (a node that lacks a carried rule, a key that does not
/// unlock, a node that changed meanwhile) leaves the owner off this machine and on the
/// roll, and running the command again shows and makes it ([`leave_again`]).
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
        return follow_again(ctx, &node, &circle, args.yes);
    }
    if left.is_some() {
        return leave_again(ctx, &node, &circle, args.yes);
    }
    let (current, rules, _) = governance::rule_set(&node.store, &id)?;
    let Some(entry) = current.content.member_of(&me) else {
        // Already off the roll: only this machine is left to change. No key is used.
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
        let installer = governance::user_installer()?;
        node.store.set_circle_left(&id, Some(node.now()))?;
        let applied = governance::apply_on(&node, &circle, &installer, &[])?;
        let why = NoRequest::OffTheRoll;
        let mut t = Text::new();
        t.line(format!("Left {} on this machine.", safe(&circle.name)));
        for skill in &applied.removed {
            t.line(format!("  removed rule {skill}"));
        }
        for skill in &applied.not_removed {
            t.line(format!("  {}", governance::not_removed_line(skill)));
        }
        for kept in &applied.kept_edited {
            t.line(format!("  {}", kept.line()));
        }
        t.line(format!(
            "No request to take you off the roll was made: {}",
            why.explain(&circle.name, "")
        ));
        return Ok(Report::new(
            json!({
                "circle": circle.name,
                "left": true,
                "requested": false,
                "reason": why.code(),
                "removed_rules": applied.removed,
                "not_removed_rules": applied.not_removed,
                "kept_edited_rules": applied.kept_edited_names(),
            }),
            t.finish(),
        ));
    };
    let member = entry.member.clone();
    // The removal that is signed, if one is: drafted here, shown in the preview, and
    // signed after the owner's answer only if the node still holds what it was drafted
    // from.
    let draft = remove_member(&current.content, &rules, &member).map_err(|_| only_member())?;
    let installed = node.store.rule_installs(&id)?.len();
    let (plan, other) = plan_request(&node.store, &me, &current, &rules, &draft, &member)?;
    let mut preview = format!(
        "Leaving {circle}:\n  \
         now, on this machine: the {installed} rule(s) the circle installed for your agent \
         are removed, and no rule of this circle is installed here again;\n  ",
        circle = safe(&circle.name),
    );
    // A proposal on record that takes the member off the roll and is not this request.
    let also = other
        .as_ref()
        .map(|p| {
            let comparable = !matches!(plan, RequestPlan::None(_));
            format!("\n{}", other_removal_line(p, comparable))
        })
        .unwrap_or_default();
    match &plan {
        RequestPlan::Make => preview.push_str(&format!(
            "for the circle: an amendment that removes {member} from the roll of charter \
             {seq} is put to the vote, with your approval.{also}\n\
             You stay on the roll until the members have approved it. {need}",
            seq = current.seq,
            need = need_line(&current, &draft),
        )),
        // The node cannot show what such a request would do to the rules, so it does
        // not promise one: its owner would be approving what they cannot read.
        RequestPlan::None(why) => preview.push_str(&format!(
            "for the circle: no request to take you off the roll is made from this node, \
             because {}{also}",
            why.explain(&circle.name, &member),
        )),
        RequestPlan::OnRecord(proposal) => preview.push_str(&format!(
            "for the circle: no request is made by this run and nothing is signed, because \
             a request to take {member} off the roll of charter {seq} is on record already \
             (proposal {id}).{also}\n\
             You stay on the roll until the members have approved it.",
            seq = current.seq,
            id = short_id(&proposal.event_id()),
        )),
    }
    if circle.is_founder {
        preview.push_str(FOUNDER_LEAVES);
    }
    confirm(&ctx.out, &preview, args.yes, "leaving the circle")?;

    // The machine first. Neither step uses a key, so a key that does not unlock and a
    // request that cannot be made leave nothing of the circle installed here. (Where
    // the skills directory cannot be located nothing is marked either.) Neither step
    // touches what the request is checked against: the charter and the rules in force
    // are read from the circle's records, which these two do not write.
    let installer = governance::user_installer()?;
    node.store.set_circle_left(&id, Some(node.now()))?;
    let applied = governance::apply_on(&node, &circle, &installer, &[])?;

    // Then the request, as the preview said and only that. Where the preview announced
    // none, no key is asked for. The report says when the node changed while its owner
    // read: what the preview said about the request would no longer be true of it.
    let from = Drafted {
        current: &current,
        rules: &rules,
    };
    let outcome = match plan {
        RequestPlan::Make => request_removal(&node, &circle, &member, draft, &from)?,
        RequestPlan::None(why) => Err((unless_changed(&node, &from, why)?, None)),
        RequestPlan::OnRecord(proposal) => {
            let why = unless_changed(&node, &from, NoRequest::OnRecord)?;
            let (_, tally) =
                governance::count(&node.store, &proposal).context(LEFT_WITHOUT_REQUEST)?;
            Err((why, Some(Box::new((*proposal, tally)))))
        }
    };
    let mut t = Text::new();
    let mut removed = applied.removed;
    let mut not_removed = applied.not_removed;
    let mut kept_edited = applied.kept_edited;
    let mut report = match outcome {
        Ok(put) => {
            t.line(format!(
                "Left {} on this machine and asked to be taken off the roll of charter {} \
                 (proposal {}).",
                safe(&circle.name),
                current.seq,
                short_id(&put.proposal.event_id())
            ));
            for skill in &put.settled.applied.removed {
                if !removed.contains(skill) {
                    removed.push(skill.clone());
                }
            }
            not_removed.retain(|skill| !removed.contains(skill));
            for skill in &put.settled.applied.not_removed {
                if !not_removed.contains(skill) {
                    not_removed.push(skill.clone());
                }
            }
            for kept in &put.settled.applied.kept_edited {
                if !kept_edited.contains(kept) {
                    kept_edited.push(kept.clone());
                }
            }
            for skill in &removed {
                t.line(format!("  removed rule {skill}"));
            }
            for skill in &not_removed {
                t.line(format!("  {}", governance::not_removed_line(skill)));
            }
            for kept in &kept_edited {
                t.line(format!("  {}", kept.line()));
            }
            let mut report = amendment_report(&circle, &put, "You are off the roll.", t);
            report.json["requested"] = json!(true);
            report.json["reason"] = Value::Null;
            report
        }
        Err((why, on_record)) => {
            t.line(format!("Left {} on this machine.", safe(&circle.name)));
            for skill in &removed {
                t.line(format!("  removed rule {skill}"));
            }
            for skill in &not_removed {
                t.line(format!("  {}", governance::not_removed_line(skill)));
            }
            for kept in &kept_edited {
                t.line(format!("  {}", kept.line()));
            }
            let mut json = json!({ "requested": false, "reason": why.code() });
            match on_record.filter(|_| why == NoRequest::OnRecord) {
                Some(found) => {
                    let (proposal, tally) = *found;
                    t.line(format!(
                        "No request to take you off the roll was made by this run: one is \
                         on record already, under charter {} (proposal {}):",
                        current.seq,
                        short_id(&proposal.event_id())
                    ));
                    on_record_lines(&mut t, &proposal, &tally, &member);
                    if let (Some(json), Some(extra)) = (
                        json.as_object_mut(),
                        on_record_json(&proposal, &tally).as_object(),
                    ) {
                        json.extend(extra.clone());
                    }
                }
                None => {
                    t.line(format!(
                        "No request to take you off the roll was made: {}",
                        why.explain(&circle.name, &member)
                    ));
                }
            }
            Report::new(json, t.finish())
        }
    };
    report.json["circle"] = json!(circle.name);
    report.json["left"] = json!(true);
    report.json["removed_rules"] = json!(removed);
    report.json["not_removed_rules"] = json!(not_removed);
    report.json["kept_edited_rules"] = json!(kept_edited
        .iter()
        .map(|kept| kept.name.as_str())
        .collect::<Vec<_>>());
    Ok(report)
}

/// For the report of a first `circle leave` that makes no request: `why`, unless this
/// node no longer holds what the preview was built from (`from`), in which case what
/// the preview said about the request no longer holds either ([`NoRequest::Changed`]).
///
/// This decides what a report says and nothing else. Nothing is signed on its answer:
/// what is signed is checked by [`governance::as_drafted`], which takes the key.
fn unless_changed(node: &Node, from: &Drafted<'_>, why: NoRequest) -> Result<NoRequest> {
    let same = governance::still_as_read(
        &node.store,
        &from.current.circle_id,
        from.current,
        from.rules,
    )
    .context(LEFT_WITHOUT_REQUEST)?;
    Ok(if same { why } else { NoRequest::Changed })
}

/// What the founder is told before they ask to be taken off the roll.
const FOUNDER_LEAVES: &str =
    "\nThis node holds the circle's root key, which signs every change to the roll. Once \
     you are off the roll the members' nodes no longer sync with this one directly, so \
     later changes to the roll will need an events file carried to and from this node. \
     Consider staying a member.";

fn only_member() -> anyhow::Error {
    usage(
        "you are the only member, so there is nobody to leave. To delete this node and \
         the circle with it: `peerharness reset`.",
    )
}

/// `circle leave` on a machine that left already. Two things can be left to do.
///
/// One is on this machine: a rule the circle installed that the first run could not
/// remove (its files could not be changed). It is tried again here, first and with no
/// key, as the first run changes the machine ([`governance::apply_on`]), and what it
/// did is printed before anything else. Nothing of a circle that was left is installed
/// by it. Like the first run, none of this happens inside a coding agent's session: the
/// first run is refused there before it changes anything, and so is this one.
///
/// The other is the request to be taken off the roll, when the first run could not
/// make it. That is a request to change the charter like any other: previewed,
/// confirmed, and bound to the charter the preview named.
fn leave_again(ctx: &Ctx, node: &Node, circle: &CircleRow, yes: bool) -> Result<Report> {
    human_only("leaving the circle")?;
    let name = safe(&circle.name);
    let undo = format!(
        "(`peerharness circle leave --circle {} --undo` follows the circle again on this \
         machine.)",
        circle.name
    );
    // The machine first. This writes none of what the request is checked against: the
    // charter and the rules in force are read from the circle's records.
    let applied = governance::apply_on(node, circle, &governance::user_installer()?, &[])?;
    let mut machine = Text::new();
    for skill in &applied.removed {
        machine.line(format!("removed rule {skill}"));
    }
    for skill in &applied.not_removed {
        machine.line(governance::not_removed_line(skill));
    }
    for kept in &applied.kept_edited {
        machine.line(kept.line());
    }
    let machine = machine.finish();
    if !machine.is_empty() {
        // Said now: the request below can still be declined or refused.
        ctx.out.note(machine.trim_end());
    }
    let nothing_changed = if applied.removed.is_empty() {
        "Nothing was changed and nothing was signed."
    } else {
        "Nothing else was changed, and nothing was signed."
    };
    let me = node.device_key();
    let (current, rules, _) = governance::rule_set(&node.store, &circle.circle_id)?;
    let mut t = Text::new();
    let nothing = |why: NoRequest, t: Text, extra: Value| -> Report {
        let mut json = json!({
            "circle": circle.name,
            "left": true,
            "requested": false,
            "reason": why.code(),
            "removed_rules": applied.removed,
            "not_removed_rules": applied.not_removed,
            "kept_edited_rules": applied.kept_edited_names(),
        });
        if let (Some(json), Some(extra)) = (json.as_object_mut(), extra.as_object()) {
            json.extend(extra.clone());
        }
        Report::new(json, t.finish())
    };
    let Some(entry) = current.content.member_of(&me) else {
        t.line(format!(
            "You left {name} on this machine already, and you are not on its roll: there \
             is nothing left to ask for."
        ));
        t.line(undo);
        return Ok(nothing(NoRequest::OffTheRoll, t, Value::Null));
    };
    let member = entry.member.clone();
    // The removal this node would ask for now. Where it lacks a carried rule it drafts
    // none, and then nothing on record can be called this request either.
    let missing = rules.missing_carried().len();
    let draft = if missing == 0 {
        Some(remove_member(&current.content, &rules, &member).map_err(|_| only_member())?)
    } else {
        None
    };
    let on_record = removals_on_record(&node.store, &me, &current, draft.as_ref(), &member)?;
    if let Some((proposal, tally)) = &on_record.request {
        t.line(format!(
            "You left {name} on this machine already, and a request to take {member} off \
             the roll of charter {} is on record (proposal {}):",
            current.seq,
            short_id(&proposal.event_id())
        ));
        on_record_lines(&mut t, proposal, tally, &member);
        t.line(nothing_changed);
        t.line(undo);
        return Ok(nothing(
            NoRequest::OnRecord,
            t,
            on_record_json(proposal, tally),
        ));
    }
    // A proposal that takes the member off the roll and does something else is not
    // their request to leave. It is named, and the request is still theirs to make.
    let other = on_record
        .other
        .as_ref()
        .map(|p| other_removal_line(p, draft.is_some()));
    let Some(next) = draft else {
        let why = NoRequest::MissingCarried(missing);
        t.line(format!("You left {name} on this machine already."));
        t.line(format!(
            "No request to take you off the roll was made: {}",
            why.explain(&circle.name, &member)
        ));
        if let Some(other) = other {
            t.line(other);
        }
        return Ok(nothing(why, t, Value::Null));
    };
    let also = other.map(|line| format!("\n{line}")).unwrap_or_default();
    let mut preview = format!(
        "You left {name} on this machine already. This asks the members to take you off \
         its roll:\n  \
         an amendment that removes {member} from the roll of charter {seq} is put to the \
         vote, with your approval.{also}\n\
         You stay on the roll until the members have approved it. {need}",
        seq = current.seq,
        need = need_line(&current, &next),
    );
    if circle.is_founder {
        preview.push_str(FOUNDER_LEAVES);
    }
    confirm(&ctx.out, &preview, yes, "the request to leave the roll")?;
    let from = Drafted {
        current: &current,
        rules: &rules,
    };
    let put = put_amendment(node, circle, &format!("Remove {member}"), next, &from)?;
    t.line(format!(
        "Asked to be taken off the roll of charter {} (proposal {}).",
        current.seq,
        short_id(&put.proposal.event_id())
    ));
    // What the machine part did above and what settling after the ballot did, together.
    // The lines of the first were printed; these are the ones that are new.
    let all = applied.clone().followed_by(put.settled.applied.clone());
    for skill in all.removed.iter().filter(|s| !applied.removed.contains(s)) {
        t.line(format!("  removed rule {skill}"));
    }
    let mut report = amendment_report(circle, &put, "You are off the roll.", t);
    report.json["circle"] = json!(circle.name);
    report.json["left"] = json!(true);
    report.json["requested"] = json!(true);
    report.json["reason"] = Value::Null;
    report.json["removed_rules"] = json!(all.removed);
    report.json["not_removed_rules"] = json!(all.not_removed);
    report.json["kept_edited_rules"] = json!(all.kept_edited_names());
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
    holds_every_carried_rule(&in_force)?;
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
    let from = Drafted {
        current: &current,
        rules: &in_force,
    };
    let put = put_amendment(&node, &circle, "Change the rules of the vote", next, &from)?;
    // What the proposal needs is decided by the charter, not by this command.
    debug_assert_eq!(threshold_for(&put.proposal, &current.content), old.amend);
    let mut t = Text::new();
    t.line(format!(
        "Proposed changing the rules of the vote (proposal {}).",
        short_id(&put.proposal.event_id())
    ));
    let report = amendment_report(&circle, &put, "The amendment passed.", t);
    Ok(with_rule_lines(report, &put.settled))
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
    holds_every_carried_rule(&rules)?;
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
    let from = Drafted {
        current: &current,
        rules: &rules,
    };
    let put = put_amendment(&node, &circle, &title, next, &from)?;
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
    Ok(with_rule_lines(report, &put.settled))
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
    for skill in &settled.applied.removed {
        t.line(format!("  removed rule {skill}"));
    }
    for line in settled.applied.left_in_place_lines() {
        t.line(format!("  {line}"));
    }
    // Rules in force that are not installed and wait for the owner: each with the
    // proposal to confirm. What is installed already stays and is not listed.
    for waiting in &settled.applied.asking {
        t.line(format!("  {}", waiting.line()));
    }
    for held in &settled.applied.held {
        t.line(format!("  {}", held.line(&circle.name)));
    }
    if args.mode == ModeArg::Ask {
        t.line(
            "  From now on a rule that passes is installed only after you confirm it. \
             Rules that are installed stay (`peerharness rule list`).",
        );
    }
    Ok(Report::new(
        json!({
            "circle": circle.name,
            "adoption_mode": wanted,
            "installed": settled.applied.installed,
            "removed_rules": settled.applied.removed,
            "not_removed_rules": settled.applied.not_removed,
            "kept_edited_rules": settled.applied.kept_edited_names(),
            "waiting": settled.applied.asking.iter().map(governance::Waiting::json).collect::<Vec<_>>(),
        }),
        t.finish(),
    ))
}

/// `circle place`: where the rules of one scope go on this machine. Nothing is sent and
/// nothing about the circle changes: every member chooses this for their own machine.
fn place(ctx: &Ctx, args: CirclePlaceArgs) -> Result<Report> {
    let node = ctx.open_node()?;
    let circle = find_circle(&node, Some(&args.circle))?;
    let scope =
        Scope::new(&args.scope).map_err(|_| usage(format!("invalid scope {:?}", args.scope)))?;
    let id = circle.circle_id;
    let dir = match &args.project {
        Some(p) => {
            let dir = std::fs::canonicalize(p)
                .map_err(|_| usage(format!("{} is not an existing directory", p.display())))?;
            if !dir.is_dir() {
                return Err(usage(format!("{} is not a directory", dir.display())));
            }
            Some(
                dir.to_str()
                    .ok_or_else(|| usage("that path is not valid UTF-8"))?
                    .to_owned(),
            )
        }
        None => None,
    };
    let preview = match &dir {
        Some(d) => format!(
            "From now on, rules of {circle} with scope {scope} (and the scopes below it) are \
             installed for your agent in this project only:\n  {d}/.claude/skills\n\
             Rules of that scope already installed for every project are moved there. Only \
             this machine changes.",
            circle = safe(&circle.name),
        ),
        None => format!(
            "From now on, rules of {circle} with scope {scope} are installed for your agent \
             in every project again (unless a wider scope is placed in a project). Only this \
             machine changes.",
            circle = safe(&circle.name),
        ),
    };
    confirm(&ctx.out, &preview, args.yes, "placing the scope")?;
    match &dir {
        Some(d) => node.store.set_rule_place(&id, &scope, d)?,
        None => {
            node.store.clear_rule_place(&id, &scope)?;
        }
    }
    let settled = governance::settle(&node, &circle, &governance::user_installer()?, &[])?;
    let mut t = Text::new();
    t.line(match &dir {
        Some(d) => format!(
            "Rules of scope {scope} in {} now go to {d}.",
            safe(&circle.name)
        ),
        None => format!(
            "Rules of scope {scope} in {} now go to every project.",
            safe(&circle.name)
        ),
    });
    for skill in &settled.applied.installed {
        t.line(format!("  moved rule {skill}"));
    }
    // A rule whose copy in the old place could not be removed is not moved yet.
    for skill in &settled.applied.not_removed {
        t.line(format!("  {}", governance::not_removed_line(skill)));
    }
    // A copy in the old place that was edited there stays, beside the one that moved.
    for kept in &settled.applied.kept_edited {
        t.line(format!("  {}", kept.line()));
    }
    for held in &settled.applied.held {
        t.line(format!("  {}", held.line(&circle.name)));
    }
    let places: Vec<Value> = node
        .store
        .rule_places(&id)?
        .into_iter()
        .map(|(s, d)| json!({ "scope": s, "project": d }))
        .collect();
    Ok(Report::new(
        json!({
            "circle": circle.name,
            "scope": scope,
            "project": dir,
            "moved": settled.applied.installed,
            "places": places,
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
    for skill in &settled.applied.not_removed {
        t.line(format!("  {}", governance::not_removed_line(skill)));
    }
    for kept in &settled.applied.kept_edited {
        t.line(format!("  {}", kept.line()));
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

/// The charters in `lines` whose roll lists `device`, verified statelessly, in the order
/// of the lines. A line is parsed strictly, like every imported record
/// (`carrier::parse_record`): what is shown to the owner before a join is what the
/// import after it will accept.
fn charters_for(lines: &[&str], device: &DeviceKey, now: Timestamp) -> Vec<Charter> {
    let mut found = Vec::new();
    for line in lines {
        let Some(Record::Event(event)) = crate::carrier::parse_record(line) else {
            continue;
        };
        let Ok(verified) = validate_stateless(event.to_string().as_bytes(), now) else {
            continue;
        };
        let EventBody::Charter(body) = &verified.body else {
            continue;
        };
        if body.charter.content.member_of(device).is_some() {
            found.push(body.charter.clone());
        }
    }
    found
}

/// The newest of `charters`: the first one with the highest number.
fn newest(charters: impl IntoIterator<Item = Charter>) -> Option<Charter> {
    let mut best: Option<Charter> = None;
    for charter in charters {
        if best.as_ref().is_none_or(|b| charter.seq > b.seq) {
            best = Some(charter);
        }
    }
    best
}

/// The newest charter in `lines` whose roll lists `device`, verified statelessly.
fn charter_for(lines: &[&str], device: &DeviceKey, now: Timestamp) -> Option<Charter> {
    newest(charters_for(lines, device, now))
}

/// The charter a file or a directory is joined by, out of the charters in it that list
/// this device (`found`): the newest one of a single circle, or `None` when there is
/// none.
///
/// Which circle is for the owner to say, not for the file. A file is whatever someone
/// put together, and a shared directory takes records from everyone who can write to
/// it: anyone can sign a charter of a circle of their own that lists this device's key,
/// with any number. So when the owner gave a root fingerprint, only charters under the
/// root key with that fingerprint are looked at, and the newest is chosen among those.
/// Without one, charters of several circles are not chosen between: the highest number
/// says nothing about which circle the owner was admitted to.
///
/// With one circle in the file nothing changes: its newest charter is returned, and
/// `plan_join` refuses a fingerprint that is not its own.
fn charter_from_source(found: Vec<Charter>, expected: Option<&str>) -> Result<Option<Charter>> {
    let circles: BTreeSet<CircleId> = found.iter().map(|c| c.circle_id).collect();
    if circles.len() <= 1 {
        return Ok(newest(found));
    }
    let Some(expected) = expected else {
        return Err(usage(
            "that file holds charters of several circles with this device on the roll: \
             pass --expect-fingerprint with the root fingerprint the founder gave you, to \
             say which circle you mean",
        ));
    };
    let expected = expected.trim();
    let of_that_root = found
        .into_iter()
        .filter(|c| c.issuer_key.fingerprint() == expected);
    match newest(of_that_root) {
        Some(charter) => Ok(Some(charter)),
        None => Err(refused(
            "none of the circles in that file has the root fingerprint you expected. \
             Do not join.",
        )),
    }
}

/// A join the owner has confirmed: the charter that becomes this node's trust anchor.
struct JoinPlan {
    charter: Charter,
    name: String,
    member: String,
}

/// Shows the owner the circle `charter` belongs to and asks for the join: in their
/// terminal, or in a window when their agent's session started the step and they
/// allowed that (`config`, ADR-037). Refuses when the root fingerprint is not the one
/// the owner expected.
fn plan_join(
    ctx: &Ctx,
    charter: Charter,
    me: &DeviceKey,
    args: &CircleJoinArgs,
    config: &Config,
) -> Result<JoinPlan> {
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
        .clone()
        .unwrap_or_else(|| format!("circle-{}", &fingerprint[..fingerprint.len().min(9)]));
    let member = charter
        .content
        .member_of(me)
        .ok_or_else(|| anyhow!("this device is not on the roll"))?
        .member
        .clone();
    let mut preview = format!(
        "You are about to join a circle as {member}.\n  root fingerprint {fingerprint}\n\
         Check that fingerprint with the founder through another channel before you continue.\n\n{charter}\n\
         Joining means accepting this charter and the way it is amended.{binding}",
        charter = describe_charter(&charter, Some(me)).trim_end(),
        binding = if charter.content.rules.binding {
            "\nThe rules this circle has passed are installed for your agent when you join, \
             and the ones it passes later without asking each time; you can opt out of any \
             rule, or switch to asking, at any time (`peerharness circle mode ask`)."
        } else {
            ""
        },
    );
    if asks_circle_in_window(config) {
        preview.push_str("\n\nIf you did not just ask your agent to join a circle, choose Cancel.");
    }
    confirm_circle_or_window(&ctx.out, &preview, args.yes, "joining the circle", config)?;
    Ok(JoinPlan {
        charter,
        name,
        member,
    })
}

/// Joins on the owner's confirmation: stores the circle with the charter as its anchor,
/// takes in the records that came with it, and settles.
fn finish_join(node: &Node, plan: &JoinPlan, lines: &[&str]) -> Result<(Value, Text)> {
    let now = node.now();
    let charter = &plan.charter;
    if node.store.circle(&charter.circle_id)?.is_some() {
        return Err(usage(
            "this node is already in that circle: use `peerharness sync` or `peerharness events import`",
        ));
    }
    governance::join_circle(&node.store, &plan.name, charter, &node.device_key(), now)?;
    let bundles = crate::library::bundle_store(&node.home);
    let summary = governance::import_lines(&node.store, &bundles, lines.iter().copied(), now)?;
    let circle = node
        .store
        .circle(&charter.circle_id)?
        .ok_or_else(|| anyhow!("the circle was not stored"))?;
    let settled = governance::settle(node, &circle, &governance::user_installer()?, &[])?;

    let mut t = Text::new();
    t.line(format!("Joined {} as {}.", safe(&plan.name), plan.member));
    t.kv("charter", charter.seq);
    t.kv("events imported", summary.stored);
    t.kv("your mode", &circle.adoption_mode);
    for skill in &settled.applied.installed {
        t.line(format!("  installed rule {skill}"));
    }
    for waiting in &settled.applied.asking {
        t.line(format!("  {}", waiting.line()));
    }
    for held in &settled.applied.held {
        t.line(format!("  {}", held.line(&circle.name)));
    }
    Ok((
        json!({
            "circle": plan.name,
            "circle_id": charter.circle_id,
            "member": plan.member,
            "charter_seq": charter.seq,
            "events_imported": summary.stored,
            "installed": settled.applied.installed,
        }),
        t,
    ))
}

fn join(ctx: &Ctx, args: CircleJoinArgs) -> Result<Report> {
    // A path that exists is a file or a directory. Anything else that reads as a
    // multiaddr is a member's node; with --internet, so is a peer id.
    if !args.invite_file.exists() {
        let text = args.invite_file.to_string_lossy().trim().to_owned();
        let peer = crate::internet::peer_id_of(&text);
        if let (true, Some(peer)) = (args.internet, peer) {
            return join_from_peer(ctx, args, JoinFrom::Found(peer));
        }
        if peer.is_some() {
            return Err(usage(
                "that is a peer id: pass --internet to find its node over the public \
                 network, or give the node's address",
            ));
        }
        if let Ok(addr) = text.parse::<ph_network::Multiaddr>() {
            return join_from_peer(ctx, args, JoinFrom::Addr(addr));
        }
    }
    if args.internet {
        return Err(usage(
            "--internet goes with the peer id of a member's node (its `daemon --internet` \
             prints it), not with a file",
        ));
    }
    let node = ctx.open_node()?;
    let now = node.now();
    let me = node.device_key();
    let source = crate::carrier::read_source(&args.invite_file)?;
    let lines: Vec<&str> = source.lines.iter().map(String::as_str).collect();
    let found = charters_for(&lines, &me, now);
    let Some(charter) = charter_from_source(found, args.expect_fingerprint.as_deref())? else {
        return Err(refused(
            "that file holds no charter with this device on its roll. Ask a member to run \
             `peerharness circle invite` with your device key (see `peerharness status`) \
             and to export again once the admission has passed.",
        ));
    };
    if node.store.circle(&charter.circle_id)?.is_some() {
        return Err(usage(
            "this node is already in that circle: use `peerharness events import`",
        ));
    }
    // Settling after the join may sign with the device key.
    key_before_window(
        &node,
        "joining the circle",
        asks_circle_in_window(&node.config),
    )?;
    let plan = plan_join(ctx, charter, &me, &args, &node.config)?;
    let (json, t) = finish_join(&node, &plan, &lines)?;
    Ok(Report::new(json, t.finish()))
}

/// Where `circle join` gets a circle from when it is not a file.
enum JoinFrom {
    /// A member's node at an address the owner gave.
    Addr(ph_network::Multiaddr),
    /// A member's node the owner named by its peer id, to be found over the public
    /// network (`--internet`).
    Found(ph_network::PeerId),
}

/// `circle join <address>`: gets the circle from a member's running daemon. That node
/// answers because the admission that passed put this device on its roll; what it sends
/// is verified here exactly like a file (the charter must carry the root signature and
/// the fingerprint the owner expects, and every record is checked on import).
fn join_from_peer(ctx: &Ctx, args: CircleJoinArgs, from: JoinFrom) -> Result<Report> {
    use crate::commands::net::{dial_only, tokio_runtime};
    use crate::runtime::{self, Running};

    // Getting the charter means starting the transport, and looking the peer up or
    // dialling it. Inside a session that is done only for a join the owner can be asked
    // about: where the window is not allowed or cannot be shown, the refusal the
    // confirmation would end in comes now, before anything leaves this machine. (A
    // home without a readable configuration has no node: the start below says so.)
    if in_agent_session() {
        if let Ok(config) = Config::load(&ctx.home) {
            circle_step_can_be_asked("joining the circle", &config)?;
        }
    }
    let home = ctx.home.clone();
    let config = if args.internet {
        ctx.out.note(crate::internet::DISCLOSURE);
        crate::internet::client_config()?
    } else {
        dial_only()
    };
    tokio_runtime()?.block_on(async {
        let run = Running::start(home, config)?;
        let run = if args.internet { run.passing() } else { run };
        let joined = async {
            let me = run.device_key;
            let now = ph_core::Timestamp::now();
            let (addr, peer, offered) = match from {
                JoinFrom::Addr(addr) => {
                    let (peer, offered) = runtime::fetch_for_join(&run, &addr).await?;
                    (addr, peer, offered)
                }
                JoinFrom::Found(peer) => {
                    let wait = std::time::Duration::from_secs(u64::from(
                        crate::internet::DEFAULT_WAIT_SECS,
                    ));
                    runtime::fetch_for_join_found(&run, peer, wait).await?
                }
            };
            // The circles on offer whose records hold a charter that lists this device
            // and is signed by the key the circle id is derived from.
            let mut choices = Vec::new();
            for o in offered {
                let lines: Vec<&str> = o.lines.iter().map(String::as_str).collect();
                let Some(charter) = charter_for(&lines, &me, now) else {
                    continue;
                };
                if charter.circle_id == o.circle && o.circle.is_derived_from(&charter.issuer_key) {
                    choices.push((o, charter));
                }
            }
            if choices.is_empty() {
                return Err(refused(
                    "that node offered no circle that this node does not hold already and \
                     whose charter lists this device. If you are a member already, use \
                     `peerharness sync`.",
                ));
            }
            if let Some(expected) = &args.expect_fingerprint {
                choices.retain(|(_, c)| c.issuer_key.fingerprint() == expected.trim());
                if choices.is_empty() {
                    return Err(refused(
                        "no circle that node offered has the root fingerprint you expected. \
                         Do not join.",
                    ));
                }
            }
            if choices.len() > 1 {
                return Err(usage(
                    "that node has this device on the roll of several circles: pass \
                     --expect-fingerprint to say which one you mean",
                ));
            }
            let (offer, charter) = choices.remove(0);
            // The node is running by now, so its home holds a configuration.
            let config = Config::load(&ctx.home)?;
            let plan = plan_join(ctx, charter, &me, &args, &config)?;
            let circle = offer.circle;
            let last = offer.last;
            let lines = offer.lines;
            let (mut json, mut t) = run
                .worker
                .call(move |node| {
                    let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
                    finish_join(node, &plan, &lines)
                })
                .await?;
            runtime::remember_join(&run, &addr, peer, circle, last).await?;
            // The rule texts, and whatever is newer than what was just read.
            match runtime::sync(&run, &addr).await {
                Ok(r) => {
                    for skill in &r.changes.installed {
                        t.line(format!("  installed rule {skill}"));
                    }
                    for waiting in &r.changes.asking {
                        t.line(format!("  {}", waiting.line()));
                    }
                    for (rule, circle) in &r.changes.held {
                        t.line(format!("  {}", rule.line(circle)));
                    }
                    let mut installed: Vec<Value> =
                        json["installed"].as_array().cloned().unwrap_or_default();
                    installed.extend(r.changes.installed.iter().map(|s| json!(s)));
                    json["installed"] = json!(installed);
                    json["peer_id"] = json!(r.peer_id);
                    t.line(if args.internet {
                        "From now on: `peerharness sync --internet` finds the members of \
                         this circle by their device keys."
                    } else {
                        "That node's address is stored: `peerharness sync` syncs with it."
                    });
                }
                Err(e) => {
                    t.line(format!(
                        "Joined, but the first sync did not finish ({e}). Run `peerharness \
                         sync{}`.",
                        if args.internet { " --internet" } else { "" }
                    ));
                }
            }
            Ok(Report::new(json, t.finish()))
        }
        .await;
        run.stop().await;
        joined
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::tests::{adopt, device, key, next_charter, node, pass};
    use ph_core::{Digest, EventId};

    /// The charter in force and the rules in force, as a command reads them before
    /// its preview.
    fn read(store: &Store, circle: &CircleId) -> (Charter, RuleSet) {
        let (current, rules, _) = governance::rule_set(store, circle).unwrap();
        (current, rules)
    }

    fn id(proposal: &Option<ProposalView>) -> Option<EventId> {
        proposal.as_ref().map(ProposalView::event_id)
    }

    /// An amendment of `current` with the next content `next`, signed by `seed`.
    fn amendment(
        store: &Store,
        seed: u8,
        current: &Charter,
        title: &str,
        next: CharterContent,
        now: Timestamp,
    ) -> ProposalView {
        governance::propose_under(
            store,
            &key(seed),
            &current.circle_id,
            &current.digest().unwrap(),
            NewProposal {
                scope: &Scope::all(),
                title,
                summary: "",
                action: ProposalAction::Amend { next },
            },
            now,
        )
        .unwrap()
    }

    /// What a first `circle leave` does about the request is decided from what the
    /// node holds before its owner is asked, and it is one of three things: the
    /// request, no request because one is on record, or no request from this node
    /// because it lacks a rule the charter carries. Bob (device 2) leaves; the store
    /// is what his node holds.
    #[test]
    fn a_first_leave_decides_about_its_request_before_it_asks() {
        let (store, circle, now) = node();
        let bob = device(2);
        let (current, rules) = read(&store, &circle);
        let draft = remove_member(&current.content, &rules, "bob").unwrap();

        // Nothing is on record and the node is complete: the request.
        let (plan, other) = plan_request(&store, &bob, &current, &rules, &draft, "bob").unwrap();
        assert!(matches!(plan, RequestPlan::Make));
        assert_eq!(id(&other), None);

        // The request is made. A first run after `--undo` finds it on record, and
        // plans no second one.
        let from = Drafted {
            current: &current,
            rules: &rules,
        };
        let request = sign_removal(&store, &key(2), &circle, "bob", draft.clone(), &from, now)
            .unwrap()
            .unwrap();
        let (plan, other) = plan_request(&store, &bob, &current, &rules, &draft, "bob").unwrap();
        assert!(
            matches!(&plan, RequestPlan::OnRecord(p) if p.event_id() == request.event_id()),
            "the request on record is the plan"
        );
        assert_eq!(id(&other), None);

        // A newer charter carries a rule that never reached this node. No request is
        // made from here, and the old request, which names the earlier charter, is
        // nothing on record under this one.
        let mut content = current.content.clone();
        content.carried = vec![EventId::from_digest(Digest::sha256(
            b"a rule not held here",
        ))];
        next_charter(&store, &current, content, now);
        let (current, rules) = read(&store, &circle);
        assert_eq!(current.seq, 2);
        assert_eq!(rules.missing_carried().len(), 1);
        let draft = remove_member(&current.content, &rules, "bob").unwrap();
        let (plan, other) = plan_request(&store, &bob, &current, &rules, &draft, "bob").unwrap();
        assert!(matches!(
            plan,
            RequestPlan::None(NoRequest::MissingCarried(1))
        ));
        assert_eq!(id(&other), None);
        // A removal a complete node drafted under this charter is on record. This node
        // cannot compare it with a draft of its own, so it is not called the request.
        let mut honest = current.content.clone();
        honest.roll.retain(|e| e.member != "bob");
        let by_alice = amendment(&store, 1, &current, "Remove bob", honest, now);
        let (plan, other) = plan_request(&store, &bob, &current, &rules, &draft, "bob").unwrap();
        assert!(matches!(
            plan,
            RequestPlan::None(NoRequest::MissingCarried(1))
        ));
        assert_eq!(id(&other), Some(by_alice.event_id()));
    }

    /// The request a first `circle leave` signs is the removal its preview described,
    /// and it is signed only while the node still holds what that preview was built
    /// from. The check runs with the unlocked key, after every prompt. A rule that
    /// passed or a charter that arrived meanwhile leaves no request, with the reason
    /// `changed_while_confirming`: the removal is not drafted anew from a state nobody
    /// was shown.
    #[test]
    fn a_leave_request_is_signed_only_as_it_was_previewed() {
        let (store, circle, now) = node();
        let proposals = |store: &Store| store.proposals(&circle).unwrap().len();
        let (current, rules) = read(&store, &circle);
        let draft = remove_member(&current.content, &rules, "bob").unwrap();
        let from = Drafted {
            current: &current,
            rules: &rules,
        };
        let sign = |next: &CharterContent, from: &Drafted<'_>| {
            sign_removal(&store, &key(2), &circle, "bob", next.clone(), from, now).unwrap()
        };

        // A rule passes while the owner reads the preview or types a passphrase. The
        // removal that was shown carries no rule and would now take that one out of
        // force: nothing is signed.
        let rule = adopt(&store, &circle, "*", now);
        pass(&store, &rule, now);
        let before = proposals(&store);
        assert_eq!(sign(&draft, &from).unwrap_err().0, NoRequest::Changed);
        assert_eq!(NoRequest::Changed.code(), "changed_while_confirming");
        assert_eq!(proposals(&store), before, "nothing was signed or stored");
        // The sentence says what happened and what to run, and names the circle only
        // inside that command.
        let said = NoRequest::Changed.explain("team", "bob");
        assert!(said.contains("changed while this was being confirmed"));
        assert!(said.contains("This machine was changed as shown."));
        assert!(said.contains("No request was made and nothing was signed"));
        assert!(said.contains("`peerharness circle leave --circle team` again"));
        assert_eq!(said.matches("team").count(), 1, "{said}");

        // Read again, as a second run does: the removal carries the rule, and is
        // signed exactly as drafted, under the charter it was drafted from.
        let (current, rules) = read(&store, &circle);
        let draft = remove_member(&current.content, &rules, "bob").unwrap();
        assert_eq!(draft.carried, [rule.event_id()]);
        let from = Drafted {
            current: &current,
            rules: &rules,
        };
        let request = sign(&draft, &from).unwrap();
        assert_eq!(request.charter(), current.digest().unwrap());
        assert_eq!(request.amend_next(), Some(&draft));
        assert_eq!(proposals(&store), before + 1);

        // A newer charter arrives while another member reads the same kind of preview.
        let carol_goes = remove_member(&current.content, &rules, "carol").unwrap();
        let mut content = current.content.clone();
        content
            .roll
            .push(RollEntry::new("dave", vec![device(4)], vec![Scope::all()]));
        content.normalize();
        next_charter(&store, &current, content, now);
        let stored = proposals(&store);
        let outcome =
            sign_removal(&store, &key(3), &circle, "carol", carol_goes, &from, now).unwrap();
        assert_eq!(outcome.unwrap_err().0, NoRequest::Changed);
        assert_eq!(proposals(&store), stored);
    }

    /// A member's exact removal of the one who leaves can arrive while that one reads
    /// the preview or types a passphrase: the plan was to make the request, and by the
    /// time the key is unlocked the request is on record. The charter and the rules in
    /// force are what they were, so the check every draft gets passes. A first run
    /// used to sign a second, identical removal there, and the members had two to
    /// split their approvals between. Now nothing is signed, and the reason comes with
    /// the proposal that is on record, as when the plan had found it.
    #[test]
    fn a_request_that_arrived_while_the_owner_was_asked_is_not_made_a_second_time() {
        let (store, circle, now) = node();
        let bob = device(2);
        let proposals = |store: &Store| store.proposals(&circle).unwrap().len();
        let (current, rules) = read(&store, &circle);
        let draft = remove_member(&current.content, &rules, "bob").unwrap();
        let from = Drafted {
            current: &current,
            rules: &rules,
        };
        // Before the owner is asked nothing is on record: the plan is the request.
        let (plan, _) = plan_request(&store, &bob, &current, &rules, &draft, "bob").unwrap();
        assert!(matches!(plan, RequestPlan::Make));

        // A removal that also takes carol off arrives. It is not this request, and
        // would not stop it (see the next test); the exact one that follows does.
        let mut more = draft.clone();
        more.roll.retain(|e| e.member != "carol");
        amendment(&store, 1, &current, "Remove bob", more, now);
        let by_alice = amendment(&store, 1, &current, "Remove bob", draft.clone(), now);
        let before = proposals(&store);

        let (why, on_record) =
            sign_removal(&store, &key(2), &circle, "bob", draft.clone(), &from, now)
                .unwrap()
                .unwrap_err();
        assert_eq!(why, NoRequest::OnRecord);
        assert_eq!(why.code(), "request_on_record");
        let (found, tally) = *on_record.expect("the request that is on record");
        assert_eq!(found.event_id(), by_alice.event_id());
        assert!(tally.approvals().is_empty(), "bob's approval is not on it");
        assert_eq!(proposals(&store), before, "nothing was signed or stored");
        // The node itself did not change: the other check still passes.
        assert!(governance::as_drafted(&store, &key(2), &circle, &current, &rules).is_ok());
    }

    /// Only a proposal that is exactly the removal this node would draft now counts as
    /// "the request to take you off the roll". A removal that was drafted before a rule
    /// passed drops that rule when it is approved: `circle leave` used to call it the
    /// request, point its owner at approving it, and make none of its own.
    #[test]
    fn a_removal_that_changes_anything_else_is_not_the_request_to_leave() {
        let (store, circle, now) = node();
        let bob = device(2);
        let (current, rules) = read(&store, &circle);
        let stale = remove_member(&current.content, &rules, "bob").unwrap();
        let by_alice = amendment(&store, 1, &current, "Remove bob", stale.clone(), now);
        // While no rule is in force it is exactly the removal: the request.
        let on = removals_on_record(&store, &bob, &current, Some(&stale), "bob").unwrap();
        assert_eq!(
            on.request.as_ref().map(|(p, _)| p.event_id()),
            Some(by_alice.event_id())
        );
        assert_eq!(id(&on.other), None);

        // A rule passes under the same charter. Alice's removal would now drop it.
        let rule = adopt(&store, &circle, "*", now);
        pass(&store, &rule, now);
        let (current, rules) = read(&store, &circle);
        let draft = remove_member(&current.content, &rules, "bob").unwrap();
        assert_ne!(draft, stale);
        let on = removals_on_record(&store, &bob, &current, Some(&draft), "bob").unwrap();
        assert!(on.request.is_none(), "a stale removal is not the request");
        assert_eq!(id(&on.other), Some(by_alice.event_id()));
        // So a first run plans a request of its own, and a second run previews one.
        let (plan, other) = plan_request(&store, &bob, &current, &rules, &draft, "bob").unwrap();
        assert!(matches!(plan, RequestPlan::Make));
        assert_eq!(id(&other), Some(by_alice.event_id()));
        let said = other_removal_line(other.as_ref().unwrap(), true);
        assert!(said.contains("also takes you off the roll, and changes more than that"));
        assert!(said.contains(&format!(
            "`peerharness proposal show {}`",
            short_id(&by_alice.event_id())
        )));

        // An amendment that takes bob off the roll and changes the rules of the vote,
        // or takes someone else off as well, is not the request either.
        let mut more = draft.clone();
        more.roll.retain(|e| e.member != "carol");
        let both = amendment(&store, 1, &current, "Remove bob", more, now);
        let others = [by_alice.event_id(), both.event_id()];
        let on = removals_on_record(&store, &bob, &current, Some(&draft), "bob").unwrap();
        assert!(on.request.is_none());
        assert!(id(&on.other).is_some_and(|other| others.contains(&other)));

        // Bob's own clean request is the request, whatever else is on record.
        let from = Drafted {
            current: &current,
            rules: &rules,
        };
        let own = sign_removal(&store, &key(2), &circle, "bob", draft.clone(), &from, now)
            .unwrap()
            .unwrap();
        let on = removals_on_record(&store, &bob, &current, Some(&draft), "bob").unwrap();
        assert_eq!(
            on.request.as_ref().map(|(p, _)| p.event_id()),
            Some(own.event_id())
        );
        assert!(id(&on.other).is_some_and(|other| others.contains(&other)));
        // Nothing under this charter takes carol off the roll and nothing else.
        let carol_goes = remove_member(&current.content, &rules, "carol").unwrap();
        let on =
            removals_on_record(&store, &device(3), &current, Some(&carol_goes), "carol").unwrap();
        assert!(on.request.is_none());
        assert_eq!(id(&on.other), Some(both.event_id()));
    }
}
