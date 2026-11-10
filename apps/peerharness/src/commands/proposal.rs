//! `peerharness proposal`: putting a rule to the vote, casting ballots and reading the
//! count (architecture section 10).

use anyhow::{anyhow, Result};
use ph_core::{Actor, CandidateStatus, EventId, Scope};
use ph_governance::{carried_diff, ProposalView, Tally};
use ph_protocol::{AdoptAction, ProposalAction, ProposalKind, VoteDecision};
use ph_store::CircleRow;
use serde_json::{json, Value};

use crate::cli::{DecisionArg, ProposalCommand};
use crate::commands::circle::find_circle;
use crate::commands::Ctx;
use crate::consent::confirm;
use crate::error::{refused, usage};
use crate::governance::{self, NewProposal, Settled};
use crate::node::Node;
use crate::output::{safe, short_id, Report, Text};

pub fn run(ctx: &Ctx, command: ProposalCommand) -> Result<Report> {
    match command {
        ProposalCommand::Create {
            candidate,
            circle,
            scope,
            yes,
        } => create(ctx, &candidate, &circle, scope.as_deref(), yes),
        ProposalCommand::List => list(ctx),
        ProposalCommand::Show { id } | ProposalCommand::Status { id } => show(ctx, &id),
        ProposalCommand::Vote {
            id,
            decision,
            rationale,
            yes,
        } => vote(ctx, &id, decision, rationale.as_deref(), yes),
        ProposalCommand::Release { id, .. } => release(ctx, &id),
        ProposalCommand::Adopt { id, yes, .. } => adopt(ctx, &id, yes),
        ProposalCommand::Refuse { id } => refuse(ctx, &id),
    }
}

/// Where a proposal stands on this node.
fn standing(node: &Node, p: &ProposalView, tally: &Tally) -> Result<&'static str> {
    let current = governance::current_charter(&node.store, &p.circle_id())?;
    Ok(if current.content.carried.contains(&p.event_id()) {
        "carried"
    } else if p.charter() != current.digest()? {
        if tally.passed() {
            "passed under an earlier charter"
        } else {
            "lapsed (the charter changed before it passed)"
        }
    } else if tally.passed() {
        "passed"
    } else {
        "open"
    })
}

fn load(node: &Node, arg: &str) -> Result<(ProposalView, CircleRow)> {
    let id: EventId = crate::ids::resolve_event(&node.store, arg)?;
    let p = governance::proposal_view(&node.store, &id)
        .map_err(|_| usage("that id is not a proposal on this node"))?;
    let circle = node
        .store
        .circle(&p.circle_id())?
        .ok_or_else(|| anyhow!("the proposal's circle is not on this node"))?;
    Ok((p, circle))
}

fn what(p: &ProposalView) -> String {
    match &p.body().action {
        ProposalAction::Adopt(a) => format!("adopt rule {}", a.skill_name),
        ProposalAction::Repeal { target } => format!("repeal rule {}", short_id(target)),
        ProposalAction::Amend { next } => {
            format!("amend the charter ({} members)", next.roll.len())
        }
    }
}

fn proposal_json(p: &ProposalView, tally: &Tally, standing: &str) -> Value {
    json!({
        "proposal_id": p.event_id(),
        "kind": p.kind().as_str(),
        "scope": p.scope(),
        "title": p.body().title,
        "skill_name": p.skill_name(),
        "author_fingerprint": p.author().fingerprint(),
        "standing": standing,
        "passed": tally.passed(),
        "approvals": tally.approvals().iter().map(|a| a.member.clone()).collect::<Vec<_>>(),
        "dissent": tally.dissent().iter().map(|d| json!({"member": d.member, "decision": format!("{:?}", d.decision).to_lowercase()})).collect::<Vec<_>>(),
        "silent": tally.silent(),
        "need": tally.need(),
        "electorate": tally.electorate(),
    })
}

fn settled_lines(t: &mut Text, s: &Settled) {
    if let Some(seq) = s.charter_notarized {
        t.line(format!(
            "  The amendment passed. Charter {seq} is now in force."
        ));
    }
    for skill in &s.applied.installed {
        t.line(format!("  installed rule {skill} for your agent"));
    }
    for skill in &s.applied.removed {
        t.line(format!("  removed rule {skill}"));
    }
    for (skill, why) in &s.applied.asking {
        t.line(format!(
            "  rule {skill} is in force and waits for your confirmation ({why}): `peerharness proposal adopt <id>`"
        ));
    }
    for (skill, why) in &s.applied.refused {
        t.line(format!("  rule {skill} cannot be installed ({why})"));
    }
    for skill in &s.applied.conflicts {
        t.line(format!(
            "  rule {skill} was not installed: a skill of that name that PeerHarness does not manage is in the way"
        ));
    }
    for skill in &s.applied.not_bound {
        t.line(format!(
            "  rule {skill} is in force and does not bind you (you are not in its electorate)"
        ));
    }
    for skill in &s.applied.waiting_for_bundle {
        t.line(format!(
            "  rule {skill} is in force; its content has not arrived yet"
        ));
    }
}

fn create(
    ctx: &Ctx,
    candidate: &str,
    circle: &str,
    scope: Option<&str>,
    yes: bool,
) -> Result<Report> {
    let node = ctx.open_node()?;
    let circle = find_circle(&node, Some(circle))?;
    let cand = crate::ids::resolve_candidate(&node.store, candidate)?;
    if cand.status.is_terminal() {
        return Err(usage(format!("that candidate is {}", cand.status)));
    }
    let scope = match scope {
        Some(s) => Scope::new(s).map_err(|_| usage(format!("invalid scope {s:?}")))?,
        None => Scope::all(),
    };
    let now = node.now();
    // Draft the skill for the preview. Nothing is saved until the owner has confirmed.
    let (name, md) = crate::library::render_candidate_skill(&cand)?;
    let draft = ph_skills::build_bundle(&md, Some(&name))
        .map_err(|e| usage(format!("this candidate cannot become a rule: {e}")))?;
    let title = crate::library::clean_statement(&cand.statement)?;
    let charter = governance::current_charter(&node.store, &circle.circle_id)?;
    let electorate = charter
        .content
        .electorate(&ph_protocol::Electorate::Scope(&scope))
        .count();
    let preview = format!(
        "This shares the following with the members of {circle} (scope {scope}) and puts it to the vote.\n\
         Exactly this text leaves your machine, and nothing else:\n\n\
         title: {title}\n\n{skill}\n\
         It passes with {need} of {electorate} member approval(s). Creating it is not a vote:\n\
         cast yours with `peerharness proposal vote`.",
        circle = safe(&circle.name),
        skill = safe(draft.skill_md()),
        need = charter.content.rules.pass.need(electorate),
    );
    confirm(&ctx.out, &preview, yes, "sharing the proposal")?;

    // Confirmed: save exactly the previewed text to the library.
    let (_, bundle, _) = crate::library::create_local_skill(&node.home, &node.store, &cand, now)?;
    if bundle.digest() != draft.digest() {
        return Err(anyhow!(
            "the rule's text changed while it was being confirmed: nothing was shared"
        ));
    }

    // The human confirmed the exact text: walk the candidate to `Proposed`.
    let mut status = cand.status;
    for next in [
        CandidateStatus::LocalReview,
        CandidateStatus::LocalApproved,
        CandidateStatus::ShareAuthorized,
        CandidateStatus::Proposed,
    ] {
        if status.can_transition_to(next) {
            status =
                node.store
                    .update_candidate_status(&cand.id, status, next, Actor::Human, now)?;
        }
    }
    // A question the owner asked this circle about the same candidate, in the same
    // scope, is named by the proposal so that voters can find the answers.
    let related_question = match cand.question_event_id {
        Some(q) => node
            .store
            .question(&q)?
            .filter(|row| row.circle_id == circle.circle_id && row.scope == scope)
            .map(|row| row.event_id),
        None => None,
    };
    let key = node.device()?.signing_key();
    let proposal = governance::propose(
        &node.store,
        key,
        &circle.circle_id,
        NewProposal {
            scope: &scope,
            title: &title,
            summary: "",
            action: ProposalAction::Adopt(AdoptAction {
                skill_name: bundle.name().to_owned(),
                description: bundle.description().to_owned(),
                bundle_digest: bundle.digest(),
                bundle_size: bundle.size(),
                related_question,
                supersedes: None,
            }),
        },
        now,
    )?;
    node.store
        .set_candidate_share_target(&cand.id, &circle.circle_id, &scope, now)?;
    node.store
        .set_candidate_proposal_event(&cand.id, &proposal.event_id(), now)?;

    let mut t = Text::new();
    t.line(format!(
        "Proposed rule {} to {} (proposal {}).",
        bundle.name(),
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
            "skill_name": bundle.name(),
            "bundle_digest": bundle.digest(),
            "circle": circle.name,
            "scope": scope,
            "related_question": related_question,
        }),
        t.finish(),
    ))
}

fn list(ctx: &Ctx) -> Result<Report> {
    let node = ctx.open_node()?;
    let mut rows = Vec::new();
    let mut t = Text::new();
    for circle in node.store.circles()? {
        let mut any = false;
        for ev in node.store.proposals(&circle.circle_id)?.into_iter().rev() {
            let Ok(p) = governance::proposal_view(&node.store, &ev.event_id) else {
                continue;
            };
            let Ok((_, tally)) = governance::count(&node.store, &p) else {
                continue;
            };
            let st = standing(&node, &p, &tally)?;
            if !any {
                t.line(format!("{}:", safe(&circle.name)));
                any = true;
            }
            t.line(format!(
                "  {}  {:<8} {}  [{}; {} of {} approved, {} needed]",
                short_id(&p.event_id()),
                p.kind().as_str(),
                safe(&p.body().title),
                st,
                tally.approvals().len(),
                tally.electorate().len(),
                tally.need()
            ));
            rows.push(proposal_json(&p, &tally, st));
        }
    }
    if rows.is_empty() {
        t.line("No proposals.");
    }
    Ok(Report::new(json!({ "proposals": rows }), t.finish()))
}

fn show(ctx: &Ctx, arg: &str) -> Result<Report> {
    let node = ctx.open_node()?;
    let (p, circle) = load(&node, arg)?;
    let (charter, tally) = governance::count(&node.store, &p)?;
    let st = standing(&node, &p, &tally)?;
    let mut t = Text::new();
    t.line(format!("{} ({})", safe(&p.body().title), what(&p)));
    t.kv("proposal", p.event_id());
    t.kv("circle", safe(&circle.name));
    t.kv("scope", p.scope());
    t.kv("proposed by", p.author().fingerprint());
    t.kv("under charter", charter.seq);
    t.kv("standing", st);
    t.kv("count", &tally);
    if !p.body().summary.is_empty() {
        t.line(format!("  why: {}", safe(&p.body().summary)));
    }
    if let Some(q) = p.adopt().and_then(|a| a.related_question) {
        t.line(format!(
            "  follows question {} (`peerharness question list` shows the answers)",
            short_id(&q)
        ));
    }
    for a in tally.approvals() {
        t.line(format!("  approve  {}", a.member));
    }
    for d in tally.dissent() {
        let text = governance::votes_for(&node.store, &p.event_id())?
            .into_iter()
            .find(|v| v.event_id() == d.vote_id)
            .and_then(|v| v.rationale().map(safe))
            .unwrap_or_default();
        t.line(format!(
            "  {:<8} {}{}",
            format!("{:?}", d.decision).to_lowercase(),
            d.member,
            if text.is_empty() {
                String::new()
            } else {
                format!(": {text}")
            }
        ));
    }
    for m in tally.silent() {
        t.line(format!("  (no ballot) {m}"));
    }
    if p.kind() == ProposalKind::Adopt {
        let recorded = governance::stances(
            &node.store,
            &circle.circle_id,
            &p.event_id(),
            &node.device_key(),
        )?;
        for s in recorded
            .iter()
            .filter(|s| s.stance == ph_protocol::Stance::OptedOut)
        {
            t.line(format!(
                "  on record as opted out: {}{}",
                s.member,
                s.reason
                    .as_deref()
                    .filter(|r| !r.is_empty())
                    .map(|r| format!(": {}", safe(r)))
                    .unwrap_or_default()
            ));
        }
    }
    if let Some(next) = p.amend_next() {
        let (_, rules, _) = governance::rule_set(&node.store, &circle.circle_id)?;
        let diff = carried_diff(&next.carried, &rules);
        let names = |c: &ph_protocol::CharterContent| -> Vec<String> {
            c.roll.iter().map(|e| e.member.clone()).collect()
        };
        t.line(format!("  proposed roll: {}", names(next).join(", ")));
        if next.rules != charter.content.rules {
            t.line("  it also changes the rules of the vote");
        }
        if p.charter() == governance::current_charter(&node.store, &circle.circle_id)?.digest()?
            && !diff.is_exact()
        {
            t.line(format!(
                "  WARNING: it drops {} rule(s) in force and carries {} this node does not have in force",
                diff.dropped.len(),
                diff.added.len()
            ));
        }
    }
    if let Some(adopt) = p.adopt() {
        let bundles = crate::library::bundle_store(&node.home);
        match bundles.get(&adopt.bundle_digest) {
            Ok(b) => {
                let findings = b.scan();
                t.line(format!(
                    "  rule text ({} bytes, {} scanner finding(s){}):",
                    b.size(),
                    findings.len(),
                    if ph_skills::has_high_risk(&findings) {
                        ", HIGH RISK"
                    } else {
                        ""
                    }
                ));
                t.line(safe(b.skill_md()).trim_end());
            }
            Err(_) => {
                t.line("  rule text: not on this node yet (import the proposer's events file)");
            }
        }
    }
    Ok(Report::new(proposal_json(&p, &tally, st), t.finish()))
}

fn vote(
    ctx: &Ctx,
    arg: &str,
    decision: DecisionArg,
    rationale: Option<&str>,
    yes: bool,
) -> Result<Report> {
    let node = ctx.open_node()?;
    let (p, circle) = load(&node, arg)?;
    let decision = match decision {
        DecisionArg::Approve => VoteDecision::Approve,
        DecisionArg::Reject => VoteDecision::Reject,
        DecisionArg::Revise => VoteDecision::Revise,
    };
    // What the human typed is what is sent, after redaction, and it is shown first.
    let rationale = rationale.map(|r| ph_core::redact(r).text);
    if decision == VoteDecision::Approve && p.kind() == ProposalKind::Adopt {
        let bundles = crate::library::bundle_store(&node.home);
        let adopt = p.adopt().ok_or_else(|| anyhow!("not an adopt proposal"))?;
        if bundles.get(&adopt.bundle_digest).is_err() {
            return Err(refused(
                "this node does not have the rule's text yet, so you cannot have read what you \
                 would approve. Import the proposer's events file first.",
            ));
        }
    }
    let mut preview = format!(
        "You are about to sign a ballot in {}:\n  {} on \"{}\" ({})",
        safe(&circle.name),
        format!("{decision:?}").to_lowercase(),
        safe(&p.body().title),
        what(&p)
    );
    if let Some(r) = &rationale {
        preview.push_str(&format!(
            "\n  with this rationale, exactly as sent: {}",
            safe(r)
        ));
    }
    preview.push_str(match decision {
        VoteDecision::Approve => {
            "\nAn approval cannot be withdrawn. See the text with `peerharness proposal show`."
        }
        _ => "\nA reject or revise is recorded with your name. It does not block the proposal.",
    });
    confirm(&ctx.out, &preview, yes, "the ballot")?;

    let key = node.device()?.signing_key();
    governance::cast_vote(
        &node.store,
        key,
        &p,
        decision,
        rationale.as_deref(),
        node.now(),
    )?;
    let settled = governance::settle(&node, &circle, &governance::user_installer()?, &[])?;
    let (_, tally) = governance::count(&node.store, &p)?;
    let mut t = Text::new();
    t.line(format!("Ballot recorded. {tally}"));
    settled_lines(&mut t, &settled);
    if !tally.passed() {
        t.line(format!(
            "Share it: `peerharness events export --circle {} --out <file>`.",
            circle.name
        ));
    }
    let st = standing(&node, &p, &tally)?;
    Ok(Report::new(proposal_json(&p, &tally, st), t.finish()))
}

fn release(ctx: &Ctx, arg: &str) -> Result<Report> {
    let node = ctx.open_node()?;
    let (p, _) = load(&node, arg)?;
    let key = node.device()?.signing_key();
    match governance::publish_result(&node.store, key, &p, node.now())? {
        Some(env) => Ok(Report::new(
            json!({ "result_id": env.event_id, "proposal_id": p.event_id() }),
            format!("Published the result {}.", short_id(&env.event_id)),
        )),
        None => {
            let (_, tally) = governance::count(&node.store, &p)?;
            Err(refused(format!(
                "that proposal has not passed here: {tally}"
            )))
        }
    }
}

fn adopt(ctx: &Ctx, arg: &str, yes: bool) -> Result<Report> {
    let node = ctx.open_node()?;
    let (p, circle) = load(&node, arg)?;
    let name = p
        .skill_name()
        .ok_or_else(|| usage("only an adopt proposal installs a rule"))?
        .to_owned();
    let (_, rules, _) = governance::rule_set(&node.store, &circle.circle_id)?;
    let rule = rules
        .get(&name)
        .filter(|r| r.proposal_id() == p.event_id())
        .ok_or_else(|| refused("that rule is not in force here, so there is nothing to install"))?;
    let bundles = crate::library::bundle_store(&node.home);
    let bundle = bundles
        .get(&rule.bundle_digest())
        .map_err(|_| refused("this node does not have the rule's text yet"))?;
    let findings = bundle.scan();
    let mut preview = format!(
        "Install rule {name} for your agent? It passed in {}.\n\n{}\n",
        safe(&circle.name),
        safe(bundle.skill_md()).trim_end()
    );
    for f in &findings {
        preview.push_str(&format!(
            "\n  scanner, line {}: {}",
            f.line,
            f.explanation()
        ));
    }
    if ph_skills::has_high_risk(&findings) {
        preview.push_str("\n  HIGH RISK findings above. Scanning never proves a text is safe.");
    }
    confirm(&ctx.out, &preview, yes, "installing the rule")?;
    let settled = governance::settle(
        &node,
        &circle,
        &governance::user_installer()?,
        std::slice::from_ref(&name),
    )?;
    let mut t = Text::new();
    if settled.applied.installed.contains(&name) {
        t.line(format!("Installed rule {name}."));
    } else {
        t.line(format!(
            "Rule {name} was already in place or could not be installed."
        ));
    }
    settled_lines(&mut t, &settled);
    Ok(Report::new(
        json!({ "skill_name": name, "installed": settled.applied.installed.contains(&name) }),
        t.finish(),
    ))
}

fn refuse(ctx: &Ctx, arg: &str) -> Result<Report> {
    let node = ctx.open_node()?;
    let (p, circle) = load(&node, arg)?;
    let name = p
        .skill_name()
        .ok_or_else(|| usage("only an adopt proposal has a rule to opt out of"))?;
    crate::commands::rule::opt(&node, &circle, name, true)
}
