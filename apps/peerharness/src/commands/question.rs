//! `peerharness question`: asking the circle before proposing, and answering.
//!
//! A question is the light step before a vote: "should our agents do this?". Members
//! answer agree, disagree or unsure, with an optional reason. An answer is an opinion on
//! the record. It is not a ballot, it decides nothing, and a rule still needs a proposal
//! and a majority.
//!
//! Who may ask and answer is the roll of the current charter (ADR-027): a member whose
//! roll entry covers the question's scope. The text that leaves the machine is exactly
//! what the preview shows, after redaction.

use anyhow::{anyhow, Result};
use ph_core::{Actor, CandidateStatus, DeviceKey, EventId, Scope};
use ph_governance::normalize_question_text;
use ph_protocol::{AnswerBody, AnswerChoice, Charter, EventBody, QuestionBody};
use ph_store::{QuestionRow, QuestionStatus};
use serde_json::{json, Value};

use crate::cli::{AnswerArg, QuestionCommand};
use crate::commands::circle::find_circle;
use crate::commands::Ctx;
use crate::consent::{confirm, human_only};
use crate::error::{refused, usage};
use crate::governance;
use crate::node::Node;
use crate::output::{continued, quoted, safe, short_id, Report, Text, MEMBERS_WORDS};

pub fn run(ctx: &Ctx, command: QuestionCommand) -> Result<Report> {
    match command {
        QuestionCommand::Send {
            candidate,
            circle,
            scope,
            text,
            yes,
        } => send(
            ctx,
            &candidate,
            &circle,
            scope.as_deref(),
            text.as_deref(),
            yes,
        ),
        QuestionCommand::List => list(ctx),
        QuestionCommand::Answer {
            question,
            answer,
            rationale,
            yes,
        } => answer_question(ctx, &question, answer, rationale.as_deref(), yes),
        QuestionCommand::Dismiss {
            question,
            mute_author,
        } => dismiss(ctx, &question, mute_author),
    }
}

/// The handle of the member `device` belongs to under `charter`, or its fingerprint when
/// it is not on that roll (a member who has since been removed).
fn member_name(charter: Option<&Charter>, device: &DeviceKey) -> String {
    charter
        .and_then(|c| c.content.member_of(device))
        .map_or_else(|| device.fingerprint(), |e| e.member.clone())
}

fn choice_str(c: AnswerChoice) -> &'static str {
    match c {
        AnswerChoice::Agree => "agree",
        AnswerChoice::Disagree => "disagree",
        AnswerChoice::Unsure => "unsure",
    }
}

/// One member's current answer to a question.
struct Answer {
    member: String,
    choice: AnswerChoice,
    rationale: Option<String>,
    mine: bool,
}

/// The answers to `question`, one per member: a member who answers again replaces their
/// earlier answer (the later `created_at`, then the greater event id, wins).
fn answers(node: &Node, question: &QuestionRow) -> Result<Vec<Answer>> {
    let charter = node.store.current_charter(&question.circle_id)?;
    let me = node.device_key();
    let mut latest: Vec<(String, (i64, EventId), Answer)> = Vec::new();
    for ev in node.store.answers_for_question(&question.event_id)? {
        let Ok(env) = ev.envelope() else { continue };
        let EventBody::Answer(body) = &env.body else {
            continue;
        };
        if env.circle_id != question.circle_id {
            continue;
        }
        let member = member_name(charter.as_ref(), &env.author);
        let order = (env.created_at.unix_seconds(), env.event_id);
        let answer = Answer {
            member: member.clone(),
            choice: body.answer,
            rationale: body.rationale.clone(),
            mine: env.author == me,
        };
        match latest.iter_mut().find(|(m, _, _)| *m == member) {
            Some(slot) if slot.1 < order => *slot = (member, order, answer),
            Some(_) => {}
            None => latest.push((member, order, answer)),
        }
    }
    latest.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(latest.into_iter().map(|(_, _, a)| a).collect())
}

fn answers_json(list: &[Answer]) -> Value {
    json!(list
        .iter()
        .map(|a| json!({
            "member": a.member,
            "answer": choice_str(a.choice),
            "rationale": a.rationale,
        }))
        .collect::<Vec<_>>())
}

fn count(list: &[Answer], c: AnswerChoice) -> usize {
    list.iter().filter(|a| a.choice == c).count()
}

/// The refusal of `question send` when the charter its preview counted the readers on
/// is no longer the one in force. Names nothing a member wrote.
const READERS_CHANGED: &str =
    "the circle's charter changed on this node while this was being confirmed, so the \
     members who can read the question may no longer be the ones you were shown. Nothing \
     was shared and nothing was signed. Run the command again to see who would read it now.";

fn send(
    ctx: &Ctx,
    candidate: &str,
    circle: &str,
    scope: Option<&str>,
    text: Option<&str>,
    yes: bool,
) -> Result<Report> {
    let node = ctx.open_node()?;
    let circle = find_circle(&node, Some(circle))?;
    let cand = crate::ids::resolve_candidate(&node.store, candidate)?;
    if cand.status.is_terminal() {
        return Err(usage(format!("that candidate is {}", cand.status)));
    }
    if let Some(asked) = cand.question_event_id {
        return Err(usage(format!(
            "you already asked about this candidate (question {}): `peerharness question list`",
            short_id(&asked)
        )));
    }
    if cand.proposal_event_id.is_some() {
        return Err(usage(
            "this candidate is already proposed: the members answer it with their ballots",
        ));
    }
    let scope = match scope {
        Some(s) => Scope::new(s).map_err(|_| usage(format!("invalid scope {s:?}")))?,
        None => Scope::all(),
    };
    let statement = crate::library::clean_statement(&cand.statement)?;
    // What the human typed, or the default wording, is what is sent, after redaction.
    let question = match text {
        Some(t) => ph_core::redact(t.trim()).text,
        None => format!("Should our agents follow this rule? {statement}"),
    };
    if question.is_empty() || question.chars().count() > 2000 {
        return Err(usage("a question is 1 to 2000 characters"));
    }
    let topic = ph_core::redact(cand.topic.trim()).text;
    let normalized = normalize_question_text(&question);
    if normalized.is_empty() {
        return Err(usage("a question needs some words"));
    }
    if node
        .store
        .question_text_exists(&circle.circle_id, &normalized)?
    {
        return Err(usage(
            "that question was already asked in this circle: `peerharness question list`",
        ));
    }
    // The charter the preview is built from: the members who can read the question
    // are counted on its roll, and the preview states that number.
    let charter = governance::current_charter(&node.store, &circle.circle_id)?;
    let shown = charter.digest()?;
    let readers = charter
        .content
        .roll
        .iter()
        .filter(|e| e.covers(&scope))
        .count();
    let preview = format!(
        "This shares the following question with the members of {circle} (scope {scope}, \
         {readers} member(s) can read it).\n\
         Exactly this text leaves your machine, and nothing else:\n\n\
         topic: {topic}\n\
         question: {question}\n\n\
         Members answer agree, disagree or unsure. An answer is an opinion, not a vote.",
        circle = safe(&circle.name),
        topic = safe(&topic),
        question = safe(&question),
    );
    confirm(&ctx.out, &preview, yes, "sharing the question")?;

    let now = node.now();
    let key = node.device()?.signing_key();
    // The owner confirmed sending their text to the members they were shown. A sync or
    // an import can have stored a newer charter while they read or typed a passphrase,
    // with another roll: then nothing is sent on that yes. The look and the signature
    // are one transaction, like every check after a yes (`governance::atomically`).
    let env = governance::atomically(&node.store, key, |store| {
        if !governance::charter_as_shown(store, key, &circle.circle_id, &shown)? {
            return Err(refused(READERS_CHANGED));
        }
        governance::submit(
            store,
            key,
            &circle.circle_id,
            &scope,
            EventBody::Question(QuestionBody {
                question,
                topic,
                related_candidate: None,
            }),
            now,
        )
    })?;
    // The human confirmed the exact text: walk the candidate to `Questioned`.
    let mut status = cand.status;
    for next in [
        CandidateStatus::LocalReview,
        CandidateStatus::LocalApproved,
        CandidateStatus::ShareAuthorized,
        CandidateStatus::Questioned,
    ] {
        if status.can_transition_to(next) {
            status =
                node.store
                    .update_candidate_status(&cand.id, status, next, Actor::Human, now)?;
        }
    }
    node.store
        .set_candidate_share_target(&cand.id, &circle.circle_id, &scope, now)?;
    node.store
        .set_candidate_question_event(&cand.id, &env.event_id, now)?;

    let mut t = Text::new();
    t.line(format!(
        "Asked {} (question {}).",
        safe(&circle.name),
        short_id(&env.event_id)
    ));
    t.line("It reaches the others with your next `peerharness sync` or `events sync`.");
    t.line("See the answers: `peerharness question list`.");
    Ok(Report::new(
        json!({
            "question_id": env.event_id,
            "circle": circle.name,
            "scope": scope,
            "candidate_id": cand.id,
        }),
        t.finish(),
    ))
}

fn question_json(node: &Node, q: &QuestionRow, list: &[Answer]) -> Result<Value> {
    let circle = node.store.circle(&q.circle_id)?;
    Ok(json!({
        "question_id": q.event_id,
        "circle": circle.map(|c| c.name),
        "scope": q.scope,
        "topic": q.topic,
        "question": q.question,
        "status": q.status.as_str(),
        "asked_by": member_name(node.store.current_charter(&q.circle_id)?.as_ref(), &q.author),
        "agree": count(list, AnswerChoice::Agree),
        "disagree": count(list, AnswerChoice::Disagree),
        "unsure": count(list, AnswerChoice::Unsure),
        "answers": answers_json(list),
    }))
}

fn answer_lines(t: &mut Text, list: &[Answer]) {
    for a in list {
        let why = a
            .rationale
            .as_deref()
            .filter(|r| !r.is_empty())
            .map(|r| format!(": {}", continued(r, MEMBERS_WORDS)))
            .unwrap_or_default();
        t.line(format!(
            "      {:<8} {}{}{why}",
            choice_str(a.choice),
            a.member,
            if a.mine { " (you)" } else { "" },
        ));
    }
}

fn list(ctx: &Ctx) -> Result<Report> {
    let node = ctx.open_node()?;
    let mut t = Text::new();
    let mut asked_json = Vec::new();
    let mut received_json = Vec::new();

    let asked = node.store.local_questions()?;
    if !asked.is_empty() {
        t.line("Questions you asked:");
    }
    for q in &asked {
        let list = answers(&node, q)?;
        // What PeerHarness says about a row stands before the member's words, here
        // and below (ADR-050): a text cannot end with counts or a sender of its own.
        t.line(format!(
            "  {}  [{} agree, {} disagree, {} unsure]  {}",
            short_id(&q.event_id),
            count(&list, AnswerChoice::Agree),
            count(&list, AnswerChoice::Disagree),
            count(&list, AnswerChoice::Unsure),
            continued(&q.question, MEMBERS_WORDS),
        ));
        answer_lines(&mut t, &list);
        asked_json.push(question_json(&node, q, &list)?);
    }

    let received = node.store.inbox(&[
        QuestionStatus::New,
        QuestionStatus::Answered,
        QuestionStatus::Dismissed,
    ])?;
    if !received.is_empty() {
        t.line("Questions from your circles:");
    }
    for q in &received {
        let list = answers(&node, q)?;
        let charter = node.store.current_charter(&q.circle_id)?;
        t.line(format!(
            "  {}  from {}, scope {}, {}: {}",
            short_id(&q.event_id),
            member_name(charter.as_ref(), &q.author),
            q.scope,
            q.status,
            continued(&q.question, MEMBERS_WORDS),
        ));
        answer_lines(&mut t, &list);
        received_json.push(question_json(&node, q, &list)?);
    }
    if asked.is_empty() && received.is_empty() {
        t.line("No questions.");
    } else if received.iter().any(|q| q.status == QuestionStatus::New) {
        t.line("Answer one: `peerharness question answer <id> --answer agree|disagree|unsure`.");
    }
    Ok(Report::new(
        json!({ "asked": asked_json, "received": received_json }),
        t.finish(),
    ))
}

/// The stored question `arg` names.
fn load(node: &Node, arg: &str) -> Result<QuestionRow> {
    let id = crate::ids::resolve_event(&node.store, arg)?;
    node.store
        .question(&id)?
        .ok_or_else(|| usage("that id is not a question on this node"))
}

fn answer_question(
    ctx: &Ctx,
    arg: &str,
    choice: AnswerArg,
    rationale: Option<&str>,
    yes: bool,
) -> Result<Report> {
    let node = ctx.open_node()?;
    let q = load(&node, arg)?;
    if q.is_local {
        return Err(usage(
            "you asked this question: the others answer it (`peerharness question list`)",
        ));
    }
    let circle = node
        .store
        .circle(&q.circle_id)?
        .ok_or_else(|| anyhow!("the question's circle is not on this node"))?;
    let choice = match choice {
        AnswerArg::Agree => AnswerChoice::Agree,
        AnswerArg::Disagree => AnswerChoice::Disagree,
        AnswerArg::Unsure => AnswerChoice::Unsure,
    };
    let rationale = rationale
        .map(|r| ph_core::redact(r.trim()).text)
        .filter(|r| !r.is_empty());
    if rationale.as_ref().is_some_and(|r| r.chars().count() > 2000) {
        return Err(usage("a rationale is at most 2000 characters"));
    }
    // The question is another member's text, and it can hold several lines: every
    // one of them stands behind a mark, so that none can pass for a line of this
    // preview (ADR-050).
    let mut preview = format!(
        "You are about to share this answer with the members of {} (scope {}):\n  \
         {} to this question:\n{}",
        safe(&circle.name),
        q.scope,
        choice_str(choice),
        quoted(&q.question, MEMBERS_WORDS),
    );
    if let Some(r) = &rationale {
        preview.push_str(&format!(
            "\n  with this rationale, exactly as sent:\n{}",
            quoted(r, MEMBERS_WORDS)
        ));
    }
    preview.push_str(
        "\nAn answer is recorded with your name. It is an opinion, not a ballot, and you can \
         answer again to change it.",
    );
    confirm(&ctx.out, &preview, yes, "sharing the answer")?;

    let key = node.device()?.signing_key();
    let env = governance::submit(
        &node.store,
        key,
        &q.circle_id,
        &q.scope,
        EventBody::Answer(AnswerBody {
            question_id: q.event_id,
            answer: choice,
            rationale,
        }),
        node.now(),
    )
    .map_err(|e| {
        // The usual reason: this member's roll entry does not cover the question's scope.
        refused(format!("the answer was not recorded: {e}"))
    })?;
    node.store
        .set_question_status(&q.event_id, QuestionStatus::Answered)?;
    let list = answers(&node, &q)?;
    let mut t = Text::new();
    t.line(format!(
        "Answered {} ({}).",
        choice_str(choice),
        short_id(&env.event_id)
    ));
    t.line("It reaches the others with your next `peerharness sync` or `events sync`.");
    let mut json = question_json(&node, &q, &list)?;
    json["answer_id"] = json!(env.event_id);
    json["status"] = json!(QuestionStatus::Answered.as_str());
    Ok(Report::new(json, t.finish()))
}

/// Takes a question out of the inbox on this machine. Nothing is sent. With
/// `mute_author`, later questions from that device are kept out of the inbox too.
fn dismiss(ctx: &Ctx, arg: &str, mute_author: bool) -> Result<Report> {
    human_only("dismissing a question")?;
    let node = ctx.open_node()?;
    let q = load(&node, arg)?;
    if q.is_local {
        return Err(usage(
            "you asked this question; there is nothing to dismiss",
        ));
    }
    node.store
        .set_question_status(&q.event_id, QuestionStatus::Dismissed)?;
    let mut text = format!("Dismissed question {}.", short_id(&q.event_id));
    if mute_author {
        let peer_id = ph_network::peer_id_from_device_key(&q.author).to_string();
        if node.store.peer(&peer_id)?.is_none() {
            node.store
                .upsert_peer(&peer_id, &q.author, &[], node.now())?;
        }
        node.store.set_peer_muted(&peer_id, true)?;
        text.push_str(" Later questions from that device stay out of your inbox.");
    }
    Ok(Report::new(
        json!({
            "question_id": q.event_id,
            "status": QuestionStatus::Dismissed.as_str(),
            "author_muted": mute_author,
        }),
        text,
    ))
}
