//! `peerharness proposal`: putting a rule to the vote, casting ballots and reading the
//! count (architecture section 10).

use anyhow::{anyhow, Result};
use ph_core::{Actor, CandidateStatus, DeviceKey, EventId, Scope};
use ph_governance::{carried_diff, ProposalView, RuleSet, Tally};
use ph_protocol::text::{is_forbidden_char, Lines};
use ph_protocol::{
    AdoptAction, Charter, ProposalAction, ProposalKind, RollEntry, SigningKey, VoteDecision,
};
use ph_store::{CircleRow, Store};
use serde_json::{json, Value};

use crate::cli::{DecisionArg, ProposalCommand};
use crate::commands::circle::{admission_check, find_circle};
use crate::commands::Ctx;
use crate::consent::{
    asks_circle_in_window, asks_in_window, confirm, confirm_circle_or_window, confirm_or_window,
};
use crate::error::{refused, usage};
use crate::governance::{self, NewProposal, Settled};
use crate::node::Node;
use crate::output::{quoted, safe, short_id, Report, Text};

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

fn settled_lines(t: &mut Text, s: &Settled, circle: &CircleRow) {
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
    for skill in &s.applied.not_removed {
        t.line(format!("  {}", governance::not_removed_line(skill)));
    }
    for kept in &s.applied.kept_edited {
        t.line(format!("  {}", kept.line()));
    }
    for waiting in &s.applied.asking {
        t.line(format!("  {}", waiting.line()));
    }
    for (skill, why) in &s.applied.refused {
        t.line(format!("  rule {skill} cannot be installed ({why})"));
    }
    for skill in &s.applied.conflicts {
        t.line(format!(
            "  rule {skill} was not installed: a skill of that name that PeerHarness does not manage is in the way"
        ));
    }
    for held in &s.applied.held {
        t.line(format!("  {}", held.line(&circle.name)));
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

/// Inside a coding agent's session nobody can type a passphrase. Before the owner is
/// asked anything in a window (`in_window`), make sure the step could be carried out
/// afterwards.
pub(crate) fn key_before_window(node: &Node, what: &str, in_window: bool) -> Result<()> {
    if !in_window {
        return Ok(());
    }
    if node.unlocks_without_terminal()? && node.device().is_ok() {
        return Ok(());
    }
    Err(refused(format!(
        "{what} needs your device key, which cannot be unlocked from inside a coding \
         agent's session. Run it yourself in your own terminal."
    )))
}

/// The scanner's findings as preview lines, and whether one of them is high-risk.
pub(crate) fn findings_preview(preview: &mut String, bundle: &ph_skills::Bundle) -> bool {
    let findings = bundle.scan();
    for f in &findings {
        preview.push_str(&format!(
            "\n  scanner, line {}: {}",
            f.line,
            f.explanation()
        ));
    }
    let high = ph_skills::has_high_risk(&findings);
    if high {
        preview.push_str("\n  HIGH RISK findings above. Scanning never proves a text is safe.");
    }
    high
}

/// The member an amendment admits, when admitting them is all it does: it is voted
/// under the charter in force, keeps the rules of the vote and every entry of the roll
/// as they are, carries exactly the rules in force on this node, and adds one member.
/// Any other amendment is `None`: a window could not say in a few lines what it changes.
///
/// Nor is it one while this node lacks a rule the charter in force carries
/// ([`RuleSet::missing_carried`]): then "exactly the rules in force on this node" is not
/// "exactly the rules in force", and a window that says "and nothing else" could be
/// saying it about an amendment that drops that rule.
fn sole_admission<'a>(
    p: &'a ProposalView,
    current: &Charter,
    in_force: &RuleSet,
) -> Result<Option<&'a RollEntry>> {
    let Some(next) = p.amend_next() else {
        return Ok(None);
    };
    let roll = &current.content.roll;
    if p.charter() != current.digest()?
        || next.rules != current.content.rules
        || !carried_diff(&next.carried, in_force).is_exact()
        || !in_force.missing_carried().is_empty()
        || next.roll.len() != roll.len() + 1
        || !roll.iter().all(|e| next.roll.contains(e))
    {
        return Ok(None);
    }
    Ok(next.roll.iter().find(|e| !roll.contains(e)))
}

/// The lines of a ballot's preview that say who an admission admits.
fn admission_lines(entry: &RollEntry, seq: u64) -> String {
    let devices: Vec<String> = entry.devices.iter().map(|d| d.fingerprint()).collect();
    let scopes: Vec<String> = entry.scopes.iter().map(ToString::to_string).collect();
    format!(
        "\nWhat this amendment changes, and nothing else:\n  \
         admit {} (device {}, scopes {}) to the roll of charter {seq}",
        entry.member,
        devices.join(", "),
        scopes.join(", "),
    )
}

/// The mark in front of every line of text a member wrote, where `proposal show` prints
/// it among its own lines.
const MEMBER_TEXT: &str = "      | ";

/// The longest rationale `proposal vote` signs, in characters. The protocol allows ten
/// times as much, over several lines; a ballot's preview shows the rationale as one
/// line among PeerHarness's own, in a window too.
pub(crate) const MAX_RATIONALE_CHARS: usize = 200;

/// Whether `c` has no place in a rationale although it is neither a control character
/// nor forbidden by the protocol: a character the preview would not show as it is
/// signed ([`safe`] rewrites it; emoji variation selectors are let through, as in a
/// rule's text), or one that shows as nothing without being a space. A run of those
/// pads a line as spaces would, and `split_whitespace` does not collapse it.
fn blank_or_rewritten(c: char) -> bool {
    let blank = matches!(
        c,
        // Braille blank, the interlinear annotation marks, and the musical null
        // notehead and format marks.
        '\u{2800}' | '\u{fff9}'..='\u{fffb}' | '\u{1d159}' | '\u{1d173}'..='\u{1d17a}'
    );
    let mut buf = [0u8; 4];
    let as_signed: &str = c.encode_utf8(&mut buf);
    blank || (!matches!(c, '\u{fe00}'..='\u{fe0f}') && safe(as_signed) != as_signed)
}

/// The rationale of a ballot as it will be shown and sent: redacted, one line without
/// control, invisible or blank characters, runs of spaces made one space, at most
/// [`MAX_RATIONALE_CHARS`] characters. `None` when there is none.
///
/// Whoever starts the step chooses the rationale, a coding agent's session included,
/// and it is shown in the preview the person decides on. A rationale that could break
/// a line could lay that preview out: put a second "rule, exactly as proposed" above
/// the real one, or an "An approval cannot be withdrawn." of its own. One padded with
/// characters that show as nothing could do the same in a window that wraps.
fn one_line_rationale(given: Option<&str>) -> Result<Option<String>> {
    let Some(given) = given else {
        return Ok(None);
    };
    // The message says everything that is checked. The character that gets a line
    // refused is often one its writer cannot see: the joiner inside an emoji, or
    // between letters of Persian or Hindi.
    let refuse = || {
        usage(format!(
            "the rationale must be one line of at most {MAX_RATIONALE_CHARS} characters \
             after redaction, without control or invisible characters (the zero-width \
             joiner of some emoji and scripts is one) or blanks that are not spaces"
        ))
    };
    let text = ph_core::redact(given.trim()).text;
    if text
        .chars()
        .any(|c| c.is_control() || is_forbidden_char(c, Lines::Single) || blank_or_rewritten(c))
    {
        return Err(refuse());
    }
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() > MAX_RATIONALE_CHARS {
        return Err(refuse());
    }
    Ok((!text.is_empty()).then_some(text))
}

/// Who signed a proposal: the member the roll of the charter it names lists the signing
/// device under, and the device. The handle comes from the signed charter.
fn proposer(node: &Node, p: &ProposalView) -> Result<String> {
    let fingerprint = p.author().fingerprint();
    let member = node
        .store
        .charter_by_digest(&p.circle_id(), &p.charter())?
        .and_then(|c| c.content.member_of(&p.author()).map(|e| e.member.clone()));
    Ok(match member {
        Some(m) => format!("{m} (device {fingerprint})"),
        None => format!("device {fingerprint}"),
    })
}

/// The title of an amendment, shown for what it is: a line its proposer wrote. It comes
/// after the description read from the signed content and is never that description.
fn proposers_words(title: &str) -> String {
    format!(
        "The proposer's own words for it (its title, which decides nothing): \"{}\"",
        safe(title).replace('\n', " ")
    )
}

/// The refusal of an approval of an amendment whose effects on this node are no longer
/// the ones its voter was shown. Names nothing a member wrote.
const AMENDMENT_CHANGED: &str =
    "what this amendment would change is no longer what you were shown: the charter or the \
     rules in force changed on this node while you read. Nothing was signed. Run the command \
     again.";

/// The refusal of `proposal adopt` when the rule it showed is no longer the rule of
/// that name. Names nothing a member wrote.
const RULE_CHANGED: &str =
    "the rule changed while it was being confirmed: what you were shown is no longer the \
     rule in force, and nothing was installed on your confirmation. `peerharness rule list` \
     shows the rule as it is now.";

/// The refusal of `proposal adopt` when the rule it showed was installed on the
/// owner's confirmation and another rule took the name before the command was done.
/// Names nothing a member wrote.
const RULE_CHANGED_SINCE: &str =
    "the rule was installed as you were shown it, and another rule of that name is in force \
     since: it took the name while this command ran. What is installed now is the text you \
     confirmed, not the rule in force. `peerharness rule list` shows the rule as it is now.";

/// What `proposal adopt` says when its look after settling finds that the rule of the
/// name is no longer the one it showed. `installed_as_shown`: the settle installed the
/// text the owner confirmed. Then that is said, and not that nothing was installed.
const fn changed_after_settling(installed_as_shown: bool) -> &'static str {
    if installed_as_shown {
        RULE_CHANGED_SINCE
    } else {
        RULE_CHANGED
    }
}

/// Why this node cannot say what an amendment changes. (A proposal is stored only once
/// the charter it names is here, so this is a damaged store, not an everyday case.)
const NO_NAMED_CHARTER: &str = "this node does not hold the charter that amendment names";

/// Checks, after the owner confirmed an approval of the amendment `p`, that it still
/// changes what they were shown. `shown` is what the preview described (`None`: this
/// node could not describe it). `in_window` is the member and the charter number a
/// window named, when the ballot was asked there as "admit this member, and nothing
/// else".
///
/// What an amendment changes is read against the charter and the rules in force on
/// this node, and both can have changed while the owner read (a sync, an import): a
/// rule that passed meanwhile is one the amendment now drops, and a window that said
/// "and nothing else" said it about another state. So it is read again here, and the
/// approval is refused when it is no longer what they were shown.
///
/// `unlocked` is the key the ballot will be signed with. Nothing is done with it here.
/// It is a parameter so that this cannot be called before the key is unlocked: a
/// passphrase prompt is one more place where the node changes, and this check comes
/// after it and immediately before the signature ([`governance::as_drafted`] takes the
/// key for the same reason). `vote` calls it in the transaction that stores the ballot
/// ([`governance::atomically`]), with that transaction's `store`. `me` is this node's
/// device key.
fn approval_as_shown(
    store: &Store,
    me: &DeviceKey,
    unlocked: &SigningKey,
    bundles: &ph_skills::BundleStore,
    p: &ProposalView,
    shown: Option<&crate::amendment::Changes>,
    in_window: Option<(&RollEntry, u64)>,
) -> Result<()> {
    let _ = unlocked;
    let now = governance::amendment_changes(store, bundles, p, me)?;
    let same = match (shown, &now) {
        (Some(shown), Some(now)) => shown.same_as(now),
        _ => false,
    };
    let window_still_fits = match in_window {
        Some((entry, seq)) => {
            let (current, in_force, _) = governance::rule_set(store, &p.circle_id())?;
            current.seq == seq
                && matches!(
                    sole_admission(p, &current, &in_force),
                    Ok(Some(still)) if still == entry
                )
        }
        None => true,
    };
    if !same || !window_still_fits {
        return Err(refused(AMENDMENT_CHANGED));
    }
    Ok(())
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
    // A rule named like PeerHarness's own skill is never put to a vote from here.
    crate::agent_notes::refuse_reserved_name(&name)?;
    let draft = ph_skills::build_bundle(&md, Some(&name))
        .map_err(|e| usage(format!("this candidate cannot become a rule: {e}")))?;
    let title = crate::library::clean_statement(&cand.statement)?;
    // The statement is the proposal's title, which is shorter than a note may be. Say so
    // before anything is confirmed or saved, not when the event is signed.
    let length = title.chars().count();
    if length > ph_protocol::limits::text::TITLE {
        return Err(usage(format!(
            "a rule put to the vote is at most {} characters and this one has {length}. \
             Shorten it first: `peerharness review {} --edit \"<the rule>\"`",
            ph_protocol::limits::text::TITLE,
            cand.id
        )));
    }
    // The charter the preview is built from: it fixes who votes on the rule and how
    // many approvals it takes, which the preview states. The proposal is signed under
    // this charter or not at all.
    let charter = governance::current_charter(&node.store, &circle.circle_id)?;
    let shown = charter.digest()?;
    let electorate = charter
        .content
        .electorate(&ph_protocol::Electorate::Scope(&scope))
        .count();
    let mut preview = format!(
        "This shares the following with the members of {circle} (scope {scope}) and puts it to the vote.\n\
         Exactly this text leaves your machine, and nothing else:\n\n\
         title: {title}\n\n{skill}\n",
        circle = safe(&circle.name),
        skill = safe(draft.skill_md()),
    );
    // What the scanner finds in the text, as on a ballot and before an install.
    let high_risk = findings_preview(&mut preview, &draft);
    if !preview.ends_with('\n') {
        preview.push('\n');
    }
    preview.push_str(&format!(
        "It passes with {need} of {electorate} member approval(s). Creating it is not a vote:\n\
         cast yours with `peerharness proposal vote`.",
        need = charter.content.rules.pass.need(electorate),
    ));
    if high_risk {
        // A rule with a high-risk finding is never decided in a window: its proposer is
        // asked in their terminal, like its voters and whoever installs it.
        confirm(&ctx.out, &preview, yes, "sharing the proposal")?;
    } else {
        key_before_window(&node, "sharing the proposal", asks_in_window(&node.config))?;
        confirm_or_window(
            &ctx.out,
            &preview,
            yes,
            "sharing the proposal",
            &node.config,
        )?;
    }

    // The key first: a key that does not unlock leaves the candidate and the library
    // as they were, and nothing says "proposed" about a rule that was never signed.
    // Unlocking can ask for a passphrase, and nothing in the transaction below waits
    // for anyone.
    let key = node.device()?.signing_key();

    // Everything the owner's yes allows is one transaction: the library entry, the
    // candidate's walk to `Proposed`, the proposal, and the candidate's link to it. An
    // error in any of them takes back all of them, so no state says "proposed" unless
    // a proposal was signed.
    let (bundle, proposal, related_question) = governance::atomically(&node.store, key, |store| {
        // The yes was for the electorate and the count the preview stated. A sync or
        // an import can have stored a newer charter while the owner read or typed a
        // passphrase: then nothing is saved, the candidate stays as it was and
        // nothing is signed. Inside the transaction no charter arrives after this
        // look, so `propose_under` below finds the same one.
        if !governance::charter_as_shown(store, key, &circle.circle_id, &shown)? {
            return Err(refused(governance::CHARTER_CHANGED));
        }

        // Confirmed: save exactly the previewed text to the library. This is inside
        // the transaction, after the check, so that a refusal saves nothing and the
        // rows of the library stand or fall with the proposal. It also writes the
        // bundle's file, which no rollback takes back: a later error here leaves a
        // content-addressed file with the text the owner confirmed and no row that
        // names it, and the next run stores the same file again without effect.
        let (_, bundle, _) = crate::library::create_local_skill(&node.home, store, &cand, now)?;
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
                    store.update_candidate_status(&cand.id, status, next, Actor::Human, now)?;
            }
        }
        // A question the owner asked this circle about the same candidate, in the
        // same scope, is named by the proposal so that voters can find the answers.
        let related_question = match cand.question_event_id {
            Some(q) => store
                .question(&q)?
                .filter(|row| row.circle_id == circle.circle_id && row.scope == scope)
                .map(|row| row.event_id),
            None => None,
        };
        let proposal = governance::propose_under(
            store,
            key,
            &circle.circle_id,
            &shown,
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
        store.set_candidate_share_target(&cand.id, &circle.circle_id, &scope, now)?;
        store.set_candidate_proposal_event(&cand.id, &proposal.event_id(), now)?;
        Ok((bundle, proposal, related_question))
    })?;

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
    // What an amendment changes is read from its signed content. Its title is what the
    // proposer called it, and comes after.
    let amendment = match p.amend_next() {
        Some(_) => Some(governance::amendment_changes(
            &node.store,
            &crate::library::bundle_store(&node.home),
            &p,
            &node.device_key(),
        )?),
        None => None,
    };
    let mut t = Text::new();
    if amendment.is_some() {
        t.line("An amendment to the charter");
    } else {
        t.line(format!("{} ({})", safe(&p.body().title), what(&p)));
    }
    t.kv("proposal", p.event_id());
    t.kv("circle", safe(&circle.name));
    t.kv("scope", p.scope());
    t.kv("proposed by", proposer(&node, &p)?);
    t.kv("under charter", charter.seq);
    t.kv("standing", st);
    t.kv("count", &tally);
    if !p.body().summary.trim().is_empty() {
        t.line("  why, in the proposer's words:");
        t.line(quoted(&p.body().summary, MEMBER_TEXT));
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
        // A rationale from another node can have several lines (the protocol allows
        // them): each is printed behind a mark, so none can pass for a line of ours.
        let text = governance::votes_for(&node.store, &p.event_id())?
            .into_iter()
            .find(|v| v.event_id() == d.vote_id)
            .and_then(|v| v.rationale().map(str::to_owned))
            .filter(|r| !r.trim().is_empty());
        t.line(format!(
            "  {:<8} {}{}",
            format!("{:?}", d.decision).to_lowercase(),
            d.member,
            if text.is_some() { ", who wrote:" } else { "" }
        ));
        if let Some(text) = text {
            t.line(quoted(&text, MEMBER_TEXT));
        }
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
            let reason = s.reason.as_deref().filter(|r| !r.trim().is_empty());
            t.line(format!(
                "  on record as opted out: {}{}",
                s.member,
                if reason.is_some() { ", who wrote:" } else { "" }
            ));
            if let Some(reason) = reason {
                t.line(quoted(reason, MEMBER_TEXT));
            }
        }
    }
    match &amendment {
        Some(Some(changes)) => {
            t.line("  what it changes, read from its signed content:");
            t.line(changes.describe("    ").trim_end());
            if let Some(unread) = changes.unread() {
                t.line(format!(
                    "  it cannot be approved on this node: {}",
                    unread.missing()
                ));
            }
        }
        Some(None) => {
            t.line(format!(
                "  what it changes cannot be shown: {NO_NAMED_CHARTER}"
            ));
        }
        None => {}
    }
    if amendment.is_some() {
        t.line(format!("  {}", proposers_words(&p.body().title)));
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
                // The rule's text is a member's: every line of it behind the mark, like
                // a reason or a summary above, so none can pass for a line of ours.
                t.line(quoted(b.skill_md(), MEMBER_TEXT));
            }
            Err(_) => {
                t.line("  rule text: not on this node yet (import the proposer's events file)");
            }
        }
    }
    let mut json = proposal_json(&p, &tally, st);
    if let Some(changes) = &amendment {
        json["amendment"] = changes.as_ref().map_or(Value::Null, |c| c.json());
    }
    Ok(Report::new(json, t.finish()))
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
    // What the human typed is what is sent, after redaction, as one line.
    let rationale = one_line_rationale(rationale)?;
    let bundles = crate::library::bundle_store(&node.home);
    // The text of the rule, when this is a ballot on one and this node has it.
    let rule_text = p
        .adopt()
        .and_then(|adopt| bundles.get(&adopt.bundle_digest).ok());
    if decision == VoteDecision::Approve && p.kind() == ProposalKind::Adopt && rule_text.is_none() {
        return Err(refused(
            "this node does not have the rule's text yet, so you cannot have read what you \
             would approve. Import the proposer's events file first.",
        ));
    }
    // What an amendment changes, read from its signed content: the outer `None` is a
    // proposal that is not an amendment, the inner one an amendment this node cannot
    // describe. An amendment can put a rule in force as an adopt proposal can, so the
    // same holds for it: no approval of what this node cannot show. A reject or a
    // revise approves nothing and stays possible.
    let amendment = match p.amend_next() {
        Some(_) => Some(governance::amendment_changes(
            &node.store,
            &bundles,
            &p,
            &node.device_key(),
        )?),
        None => None,
    };
    if decision == VoteDecision::Approve {
        match &amendment {
            Some(None) => {
                return Err(refused(format!(
                    "{NO_NAMED_CHARTER}, so it cannot show what the amendment changes and \
                     you cannot have read what you would approve. Import the proposer's \
                     events file first."
                )))
            }
            Some(Some(changes)) => {
                if let Some(unread) = changes.unread() {
                    return Err(refused(unread.refusal()));
                }
            }
            None => {}
        }
    }
    let ballot = format!(
        "You are about to sign a ballot in {}:\n  {} on",
        safe(&circle.name),
        format!("{decision:?}").to_lowercase(),
    );
    // In a window the title stands where it always stood; see below for what the
    // window adds from the signed content.
    let titled = format!("{ballot} \"{}\" ({})", safe(&p.body().title), what(&p));
    let said = rationale
        .as_ref()
        .map(|r| format!("\n  with this rationale, exactly as sent: {}", safe(r)))
        .unwrap_or_default();
    // In a window the owner cannot run `proposal show` first, and what their agent
    // tells them about a proposal is not the proposal: the window carries what is being
    // decided itself. Two kinds of ballot are asked there. One is on a rule whose text
    // is here, with no high-risk finding (ADR-033). The other is on an amendment that
    // admits one member and changes nothing else (ADR-037): the window names the member
    // and the device from the amendment, whatever its title says. Every other ballot (a
    // repeal, any other change to the charter) stays in the terminal.
    let approval = match decision {
        VoteDecision::Approve => "\nAn approval cannot be withdrawn.",
        _ => "\nA reject or revise is recorded with your name. It does not block the proposal.",
    };
    // The member a window would be asked about, when this is a ballot for a window.
    let admission = if asks_circle_in_window(&node.config) && p.amend_next().is_some() {
        let current = governance::current_charter(&node.store, &circle.circle_id)?;
        let (_, in_force, _) = governance::rule_set(&node.store, &circle.circle_id)?;
        sole_admission(&p, &current, &in_force)?.map(|entry| (entry, current.seq))
    } else {
        None
    };
    let mut rule_window = false;
    let mut circle_window = false;
    let preview = if let (true, Some(bundle)) = (asks_in_window(&node.config), &rule_text) {
        let mut preview = format!(
            "{titled}{said}{approval} The rule, exactly as proposed:\n\n{}\n",
            safe(bundle.skill_md()).trim_end()
        );
        rule_window = !findings_preview(&mut preview, bundle);
        preview
    } else if let Some((entry, seq)) = admission {
        circle_window = true;
        format!(
            "{titled}{said}{}{approval}{}",
            admission_lines(entry, seq),
            admission_check(&entry.member, &circle.name)
        )
    } else if let Some(changes) = &amendment {
        // In the terminal: every amendment, an admission included, is described from
        // what was signed. The title comes after, as the proposer's words.
        let what_it_changes = match changes {
            Some(changes) => format!(
                "What this amendment changes, read from its signed content:\n{}",
                changes.describe("  ").trim_end()
            ),
            None => format!("What it changes cannot be shown: {NO_NAMED_CHARTER}."),
        };
        format!(
            "{ballot} an amendment to the charter (proposal {})\n  proposed by {}{said}\n\
             {what_it_changes}\n{}{approval}",
            short_id(&p.event_id()),
            proposer(&node, &p)?,
            proposers_words(&p.body().title),
        )
    } else {
        let see = match decision {
            VoteDecision::Approve => " See the text with `peerharness proposal show`.",
            _ => "",
        };
        format!("{titled}{said}{approval}{see}")
    };
    if rule_window {
        key_before_window(&node, "the ballot", true)?;
        confirm_or_window(&ctx.out, &preview, yes, "the ballot", &node.config)?;
    } else if circle_window {
        key_before_window(&node, "the ballot", true)?;
        confirm_circle_or_window(&ctx.out, &preview, yes, "the ballot", &node.config)?;
    } else {
        confirm(&ctx.out, &preview, yes, "the ballot")?;
    }

    // The key first: unlocking it can ask for a passphrase, and a prompt is a place
    // where the node changes. What follows is checked with the key in hand, and no
    // prompt lies between that check and the signature.
    let key = node.device()?.signing_key();
    let cast = |store: &Store| {
        governance::cast_vote(store, key, &p, decision, rationale.as_deref(), node.now())
    };
    // An approval is for what was shown. A reject or a revise approves nothing and is
    // never refused here.
    match &amendment {
        Some(shown) if decision == VoteDecision::Approve => {
            // The look and the ballot are one transaction: a ballot or a charter that
            // another process stores cannot come between them.
            let in_window = admission.filter(|_| circle_window);
            let me = node.device_key();
            governance::atomically(&node.store, key, |store| {
                approval_as_shown(store, &me, key, &bundles, &p, shown.as_ref(), in_window)?;
                cast(store)
            })?;
        }
        _ => {
            cast(&node.store)?;
        }
    }
    let settled = governance::settle(&node, &circle, &governance::user_installer()?, &[])?;
    let (_, tally) = governance::count(&node.store, &p)?;
    let mut t = Text::new();
    t.line(format!("Ballot recorded. {tally}"));
    settled_lines(&mut t, &settled, &circle);
    if !tally.passed() {
        if crate::consent::in_agent_session() {
            t.line("The other members get it with the next sync: `peerharness sync --internet`.");
        } else {
            t.line(format!(
                "Share it: `peerharness events export --circle {} --out <file>`.",
                circle.name
            ));
        }
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
    // A rule that is held is not installed whatever is confirmed: say so before asking.
    governance::refuse_held(&node, &circle, rule, governance::Then::Adopt)?;
    let bundles = crate::library::bundle_store(&node.home);
    let bundle = bundles
        .get(&rule.bundle_digest())
        .map_err(|_| refused("this node does not have the rule's text yet"))?;
    let mut preview = format!(
        "Install rule {name} for your agent? It passed in {}.\n\n{}\n",
        safe(&circle.name),
        safe(bundle.skill_md()).trim_end()
    );
    // A high-risk finding always asks the owner, and asks them in their terminal.
    if findings_preview(&mut preview, &bundle) {
        confirm(&ctx.out, &preview, yes, "installing the rule")?;
    } else {
        key_before_window(&node, "installing the rule", asks_in_window(&node.config))?;
        confirm_or_window(&ctx.out, &preview, yes, "installing the rule", &node.config)?;
    }
    // The confirmation is for this proposal: for the text that was shown. The store can
    // have changed while the owner read (a sync, an import): when the rule of that
    // name is another one now, or none, nothing is installed on that yes, and the
    // command says so with a refusal, as `rule opt-in` does.
    let still_the_rule = |node: &Node| -> Result<bool> {
        let (_, rules, _) = governance::rule_set(&node.store, &circle.circle_id)?;
        Ok(rules
            .get(&name)
            .is_some_and(|r| r.proposal_id() == p.event_id()))
    };
    if !still_the_rule(&node)? {
        return Err(refused(RULE_CHANGED));
    }
    // `apply_rules` reads the rules once more and counts the confirmation for this
    // proposal only, so a rule that takes the name in the instant between is not
    // installed on it either. That is looked at afterwards.
    let installer = governance::user_installer()?;
    let settled = governance::settle(&node, &circle, &installer, &[p.event_id()])?;
    let installed = settled.applied.installed.contains(&name);
    if !still_the_rule(&node)? {
        // Another rule has the name now. What the settle did is said as it is: when it
        // installed something under the name and the text that is there is the one
        // that was shown, the owner's confirmation was used, and for that text.
        let target =
            governance::rule_target(&node.store, &circle.circle_id, &installer, rule.scope())?;
        let installed_as_shown = installed
            && matches!(
                target.installer.status(&name),
                Ok(ph_skills::InstallState::Managed { digest, modified: false })
                    if digest == rule.bundle_digest()
            );
        if installed_as_shown {
            // Everything else the settle did, as after any other adopt. These lines
            // can name the circle, so they are no part of the error that follows.
            let mut t = Text::new();
            t.line(format!("Installed rule {name}, as you were shown it."));
            settled_lines(&mut t, &settled, &circle);
            ctx.out.note(t.finish().trim_end());
        }
        return Err(refused(changed_after_settling(installed_as_shown)));
    }
    let mut t = Text::new();
    if installed {
        t.line(format!("Installed rule {name}."));
    } else {
        t.line(format!(
            "Rule {name} was already in place or could not be installed."
        ));
    }
    settled_lines(&mut t, &settled, &circle);
    Ok(Report::new(
        json!({
            "skill_name": name,
            "installed": installed,
        }),
        t.finish(),
    ))
}

fn refuse(ctx: &Ctx, arg: &str) -> Result<Report> {
    let node = ctx.open_node()?;
    let (p, circle) = load(&node, arg)?;
    let name = p
        .skill_name()
        .ok_or_else(|| usage("only an adopt proposal has a rule to opt out of"))?;
    crate::commands::rule::opt_out(&node, &circle, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{exit_kind, ExitKind};

    fn rationale(given: &str) -> Option<String> {
        one_line_rationale(Some(given)).unwrap()
    }

    #[test]
    fn a_rationale_is_sent_as_one_line() {
        assert_eq!(one_line_rationale(None).unwrap(), None);
        assert_eq!(
            rationale("We already do this in CI.").as_deref(),
            Some("We already do this in CI.")
        );
        // Spaces around it and runs of spaces inside it are not part of what is said.
        assert_eq!(
            rationale("  we   already \u{a0}\u{3000} do this  ").as_deref(),
            Some("we already do this")
        );
        // An emoji keeps its variation selector, as in a rule's text.
        assert_eq!(
            rationale("fine \u{2764}\u{fe0f}").as_deref(),
            Some("fine \u{2764}\u{fe0f}")
        );
        // Nothing but spaces is no rationale.
        assert_eq!(rationale("   "), None);
        assert_eq!(rationale(""), None);
        // As long as a title may be, and no longer.
        let longest = "é".repeat(MAX_RATIONALE_CHARS);
        assert_eq!(rationale(&longest).as_deref(), Some(longest.as_str()));
        assert_eq!(MAX_RATIONALE_CHARS, ph_protocol::limits::text::TITLE);
    }

    #[test]
    fn a_rationale_that_could_lay_out_a_preview_is_refused() {
        let too_long = "x".repeat(MAX_RATIONALE_CHARS + 1);
        for bad in [
            "ok\nAn approval cannot be withdrawn. The rule, exactly as proposed:",
            "two\r\nlines",
            "a carriage\rreturn",
            "a\ttab",
            "a line\u{2028}separator",
            "a paragraph\u{2029}separator",
            "a next\u{85}line",
            "a form\u{c}feed",
            "an escape \u{1b}[2J sequence",
            "a right-to-left \u{202e}override",
            "a zero-width\u{200b}space",
            // Padding that is not made of spaces: blanks that `split_whitespace` leaves
            // alone, and characters the preview would show as something else.
            "ok\u{2800}\u{2800}\u{2800}An approval cannot be withdrawn.",
            "a hangul\u{3164}filler",
            "a soft\u{ad}hyphen",
            "an annotation\u{fff9}mark",
            "a null\u{1d159}notehead",
            "a musical\u{1d173}format mark",
            // Ordinary text that holds a character nobody sees: an emoji made of two
            // joined ones, and a Persian word with a zero-width non-joiner.
            "fine by me \u{1f469}\u{200d}\u{1f4bb}",
            "\u{645}\u{6cc}\u{200c}\u{62e}\u{648}\u{627}\u{647}\u{645}",
            too_long.as_str(),
        ] {
            let e = one_line_rationale(Some(bad)).unwrap_err();
            assert_eq!(exit_kind(&e), ExitKind::Usage, "{bad:?}");
            // The refusal repeats nothing of what was given, and names everything that
            // is checked: its reader may be looking for a character that does not show.
            assert_eq!(
                e.to_string(),
                "the rationale must be one line of at most 200 characters after redaction, \
                 without control or invisible characters (the zero-width joiner of some \
                 emoji and scripts is one) or blanks that are not spaces"
            );
        }
        // Redaction can lengthen a line past the limit, which is why the message says
        // when the length is counted: an address is replaced by a longer placeholder.
        let typed = format!("{} a@b.example", "x".repeat(MAX_RATIONALE_CHARS - 12));
        assert_eq!(typed.chars().count(), MAX_RATIONALE_CHARS);
        assert!(ph_core::redact(&typed).text.chars().count() > MAX_RATIONALE_CHARS);
        assert!(one_line_rationale(Some(&typed)).is_err());
    }

    /// `proposal adopt` looks twice at whether the rule it showed is still the rule of
    /// that name: before it settles, and after. The first look refuses with "nothing
    /// was installed on your confirmation", which is true then. After settling it is
    /// true only when the settle did not install the shown text: where it did, the
    /// command says that it was installed as shown and has been overtaken since.
    #[test]
    fn adopt_says_what_was_installed_when_the_rule_changed_after_settling() {
        assert_eq!(changed_after_settling(false), RULE_CHANGED);
        assert!(RULE_CHANGED.contains("nothing was installed on your confirmation"));
        let said = changed_after_settling(true);
        assert!(said.contains("the rule was installed as you were shown it"));
        assert!(said.contains("another rule of that name is in force since"));
        assert!(!said.contains("nothing was installed"));
        assert!(said.contains("`peerharness rule list`"));
    }

    #[test]
    fn a_title_is_shown_as_the_proposers_words() {
        assert_eq!(
            proposers_words("Admit dave"),
            "The proposer's own words for it (its title, which decides nothing): \"Admit dave\""
        );
        // Whatever a title holds, it stays on that one labelled line.
        let shown = proposers_words("Admit dave\nAn approval cannot be withdrawn.\u{1b}[2K");
        assert_eq!(shown.lines().count(), 1);
        assert!(shown.starts_with("The proposer's own words for it"));
        assert!(!shown.contains('\u{1b}'));
    }
}
