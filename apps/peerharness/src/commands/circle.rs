//! `peerharness circle`: founding a circle, showing its charter, proposing an admission
//! and joining from an events file.
//!
//! Membership is decided by vote (architecture section 10.8). `circle invite` therefore
//! does not admit anyone by itself: it puts an amendment to the vote and casts the
//! inviter's own approval. With one member that approval is the majority, so the
//! admission passes at once; with more, the other members have to approve too.

use anyhow::{anyhow, Context, Result};
use ph_core::{DeviceKey, Scope};
use ph_governance::{admit_member, remove_member};
use ph_identity::{accept_credential, CircleAuthority};
use ph_protocol::{
    is_valid_member_name, validate_stateless, Charter, EventBody, ProposalAction, RollEntry,
    VoteDecision,
};
use ph_store::CircleRow;
use serde_json::{json, Value};

use crate::cli::{CircleCommand, CircleInviteArgs, CircleJoinArgs, CircleRemoveArgs};
use crate::commands::Ctx;
use crate::consent::confirm;
use crate::error::{not_implemented, refused, usage};
use crate::governance::{self, NewProposal};
use crate::node::Node;
use crate::output::{safe, short_id, Report, Text};

pub fn run(ctx: &Ctx, command: CircleCommand) -> Result<Report> {
    match command {
        CircleCommand::Create { name, member } => create(ctx, &name, member.as_deref()),
        CircleCommand::Members { circle } => members(ctx, circle.as_deref()),
        CircleCommand::Invite(args) => invite(ctx, args),
        CircleCommand::Join(args) => join(ctx, args),
        CircleCommand::Remove(args) => remove(ctx, args),
        CircleCommand::Revoke(_) => Err(not_implemented("circle revoke")),
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

/// Puts the removal of a member to the vote and casts the proposer's approval. Like an
/// admission it is an amendment: nobody is removed until a majority of the roll approves
/// and the founder's node has notarized the charter that was voted on.
fn remove(ctx: &Ctx, args: CircleRemoveArgs) -> Result<Report> {
    let node = ctx.open_node()?;
    let circle = find_circle(&node, Some(&args.circle))?;
    let id = circle.circle_id;
    let now = node.now();
    let (current, rules, _) = governance::rule_set(&node.store, &id)?;
    let next = remove_member(&current.content, &rules, &args.member)
        .map_err(|e| usage(format!("cannot propose that removal: {e}")))?;
    let n = current.content.roll.len();
    let need = current.content.rules.pass.need(n);
    let preview = format!(
        "This puts an amendment of {circle} to the vote and casts your approval:\n  \
         remove {member} from the roll of charter {seq}\n  \
         it passes with {need} of {n} member approval(s); yours is one\n\
         An approval cannot be withdrawn.",
        circle = safe(&circle.name),
        member = args.member,
        seq = current.seq,
    );
    confirm(&ctx.out, &preview, args.yes, "the removal proposal")?;

    let key = node.device()?.signing_key();
    let title = format!("Remove {}", args.member);
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
        "Proposed removing {} (proposal {}).",
        args.member,
        short_id(&proposal.event_id())
    ));
    t.line(format!("  {tally}"));
    match settled.charter_notarized {
        Some(seq) => {
            t.line(format!(
                "  The removal passed. Charter {seq} is now in force."
            ));
            t.line(format!(
                "  Send the others your events: `peerharness events export --circle {}`.",
                circle.name
            ));
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
    let bytes = crate::home::read_bounded_file(&args.invite_file, 64 * 1024 * 1024)?;
    let text = String::from_utf8(bytes).map_err(|_| usage("that file is not UTF-8 text"))?;
    let lines: Vec<&str> = text.lines().collect();
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
