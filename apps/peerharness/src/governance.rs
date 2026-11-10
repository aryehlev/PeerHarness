//! Governance glue: the one path every decision event takes into the local store, the
//! queries commands need, and file-based exchange of signed events between nodes.
//!
//! `ph-governance` holds the rules and has no storage. This module connects it to
//! `ph-store`:
//!
//! * [`ingest`] is the **only** way an event enters the event log here, whether it was
//!   received from a peer or just signed locally ([`submit`]). It runs stateless
//!   validation, roll-based authorization, the reference checks, RESULT verification
//!   and charter succession, in that order, before anything is written. A node therefore
//!   never stores a local event that its peers would refuse.
//! * [`count`] and [`rule_set`] answer "has this passed?" and "what is in force?" from
//!   the stored records alone.
//! * [`export_circle`] / [`import_lines`] move signed events (and the bundles `adopt`
//!   proposals name) between nodes as JSON lines. Events are self-certifying, so the
//!   carrier does not need to be trusted: a file, a shared folder or a git repository
//!   all work. The QUIC daemon will reuse the same [`ingest`].

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, bail, Context, Result};
use ph_core::{CircleId, DeviceKey, Digest, EventId, Scope, Timestamp};
use ph_governance::{
    authorize_incoming, check_answer_reference, check_repeal_reference, check_successor,
    check_supersedes_reference, normalize_question_text, rules_in_force, tally, verify_result,
    DecisionRecords, GuardDecision, Passed, ProposalView, QuestionContext, QuestionGuard,
    Reference, ResultView, RuleSet, Tally, VoteView,
};
use ph_identity::CircleAuthority;
use ph_protocol::{
    validate_stateless, Charter, CharterBody, CharterContent, EnvelopeBuilder, EventBody,
    EventType, ProposalBody, ProposalKind, ResultBody, RollEntry, SignedEnvelope, SigningKey,
    VerifiedEnvelope, VoteBody, VoteDecision,
};
use ph_skills::{Bundle, BundleStore};
use ph_store::{BundleRow, CircleRow, InsertOutcome, NewQuestion, QuestionStatus, Store};
use serde_json::{json, Value};

/// [`DecisionRecords`] over the local store: accepted charters and stored proposals.
pub struct StoreRecords<'a>(pub &'a Store);

impl DecisionRecords for StoreRecords<'_> {
    fn charter(&self, circle: &CircleId, digest: &Digest) -> Option<Charter> {
        self.0.charter_by_digest(circle, digest).ok().flatten()
    }

    fn proposal(&self, circle: &CircleId, id: &EventId) -> Option<SignedEnvelope> {
        let ev = self.0.event(id).ok().flatten()?;
        (ev.event_type == EventType::Proposal && ev.circle_id == *circle)
            .then(|| ev.envelope().ok())
            .flatten()
    }
}

/// What happened to an event offered to [`ingest`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ingest {
    /// Verified, authorized and stored. Its effects (a new current charter, a recorded
    /// revocation) have been applied.
    Stored,
    /// Already stored; nothing changed.
    Duplicate,
    /// Nothing is wrong with it, but this node lacks a record it depends on (a charter,
    /// a proposal, a ballot a result lists). Offer it again after more events arrived.
    Deferred(&'static str),
    /// Refused. The code is for local logs; it is never sent to a peer.
    Rejected(&'static str),
}

fn revoked_in<'a>(store: &'a Store, circle: &'a CircleId) -> impl Fn(&DeviceKey) -> bool + 'a {
    // A store error is treated as "revoked": failing closed can block an approval but
    // never count one that should not count.
    move |device| store.is_revoked(circle, device).unwrap_or(true)
}

/// The stored, signature-verified proposal with this id.
pub fn proposal_view(store: &Store, id: &EventId) -> Result<ProposalView> {
    let ev = store
        .event(id)?
        .ok_or_else(|| anyhow!("no such proposal in the local store"))?;
    let env = ev.envelope().context("stored proposal is unreadable")?;
    ProposalView::from_envelope(&env).map_err(|_| anyhow!("that event is not a valid proposal"))
}

/// The stored ballots for `proposal_id` (signature-verified; not yet counted).
pub fn votes_for(store: &Store, proposal_id: &EventId) -> Result<Vec<VoteView>> {
    let mut out = Vec::new();
    for ev in store.votes_for_proposal(proposal_id)? {
        if let Ok(env) = ev.envelope() {
            if let Ok(v) = VoteView::from_envelope(&env) {
                out.push(v);
            }
        }
    }
    Ok(out)
}

/// Counts the stored ballots for `proposal` under the charter it names.
pub fn count(store: &Store, proposal: &ProposalView) -> Result<(Charter, Tally)> {
    let circle = proposal.circle_id();
    let charter = store
        .charter_by_digest(&circle, &proposal.charter())?
        .ok_or_else(|| anyhow!("this node does not hold the charter the proposal names"))?;
    let votes = votes_for(store, &proposal.event_id())?;
    let t = tally(proposal, &charter, &votes, &revoked_in(store, &circle))
        .map_err(|e| anyhow!("cannot count the proposal: {e}"))?;
    Ok((charter, t))
}

/// The circle's current charter.
pub fn current_charter(store: &Store, circle: &CircleId) -> Result<Charter> {
    store
        .current_charter(circle)?
        .ok_or_else(|| anyhow!("this node holds no charter for that circle"))
}

/// The rules in force in `circle`, with the tally of each proposal that passed under
/// the current charter (carried rules have none).
pub fn rule_set(
    store: &Store,
    circle: &CircleId,
) -> Result<(Charter, RuleSet, HashMap<EventId, Tally>)> {
    let charter = current_charter(store, circle)?;
    let digest = charter.digest()?;
    let mut passed = Vec::new();
    let mut tallies = HashMap::new();
    for ev in store.proposals(circle)? {
        let Ok(env) = ev.envelope() else { continue };
        let Ok(p) = ProposalView::from_envelope(&env) else {
            continue;
        };
        if charter.content.carried.contains(&p.event_id()) {
            if let Ok(c) = Passed::carried(&p, &charter) {
                passed.push(c);
            }
            continue;
        }
        if p.charter() != digest {
            continue; // names an earlier charter: it can no longer pass
        }
        let votes = votes_for(store, &p.event_id())?;
        let Ok(t) = tally(&p, &charter, &votes, &revoked_in(store, circle)) else {
            continue;
        };
        if let Ok(ok) = Passed::by_vote(&p, &t, &charter) {
            passed.push(ok);
            tallies.insert(p.event_id(), t);
        }
    }
    let rules = rules_in_force(&charter, &passed);
    Ok((charter, rules, tallies))
}

/// Offers one event to this node: validates, authorizes and verifies it, then stores it
/// and applies its effects. See the module docs.
///
/// `origin_peer` is the peer it came from (`None` for a local event or a file import).
pub fn ingest(
    store: &Store,
    raw: &[u8],
    origin_peer: Option<&str>,
    now: Timestamp,
) -> Result<Ingest> {
    let Ok(verified) = validate_stateless(raw, now) else {
        return Ok(Ingest::Rejected("invalid"));
    };
    if store.has_event(&verified.event_id())? {
        return Ok(Ingest::Duplicate);
    }
    // Membership is the roll of the current charter (ADR-026, ADR-027): it authorizes
    // QUESTION and ANSWER, and it carries the revocations every other type checks.
    let oracle = crate::peer::roll_oracle(store)?;
    let known = |c: &CircleId| store.circle(c).ok().flatten().is_some();
    if let Err(r) = authorize_incoming(&verified, &oracle, &StoreRecords(store), &known, now) {
        return Ok(if r.is_retryable() {
            Ingest::Deferred(r.code())
        } else {
            Ingest::Rejected(r.code())
        });
    }
    let circle = verified.circle_id;
    let env: &SignedEnvelope = &verified;
    match &verified.body {
        EventBody::Proposal(b) => {
            let lookup = |id: &EventId| -> Option<SignedEnvelope> {
                store
                    .event(id)
                    .ok()
                    .flatten()
                    .and_then(|e| e.envelope().ok())
            };
            let superseded = b
                .as_adopt()
                .and_then(|a| a.supersedes)
                .and_then(|id| lookup(&id));
            if let Reference::Invalid(_) = check_supersedes_reference(env, superseded.as_ref()) {
                return Ok(Ingest::Rejected("bad_supersedes"));
            }
            let target = ProposalView::from_verified(&verified)
                .ok()
                .and_then(|p| p.repeal_target())
                .and_then(|id| lookup(&id));
            if let Reference::Invalid(_) = check_repeal_reference(env, target.as_ref()) {
                return Ok(Ingest::Rejected("bad_repeal_target"));
            }
        }
        EventBody::Result(b) => {
            let result =
                ResultView::from_verified(&verified).map_err(|_| anyhow!("not a result"))?;
            let Ok(proposal) = proposal_view(store, &b.proposal_id) else {
                return Ok(Ingest::Deferred("missing_proposal"));
            };
            let Some(charter) = store.charter_by_digest(&circle, &proposal.charter())? else {
                return Ok(Ingest::Deferred("unknown_charter"));
            };
            let votes = votes_for(store, &b.proposal_id)?;
            if let Err(e) = verify_result(
                &result,
                &proposal,
                &charter,
                &votes,
                &revoked_in(store, &circle),
            ) {
                return Ok(if e.is_retryable() {
                    Ingest::Deferred(e.code())
                } else {
                    Ingest::Rejected(e.code())
                });
            }
        }
        EventBody::Charter(b) => {
            return ingest_charter(store, &verified, &b.charter, origin_peer, now)
        }
        EventBody::Membership(b) => {
            store.upsert_membership_proof(&b.to_proof(), false, now)?;
        }
        EventBody::Revocation(b) => {
            store.insert_revocation(&b.revocation, now)?;
        }
        EventBody::Question(_) => return ingest_question(store, &verified, origin_peer, now),
        EventBody::Answer(b) => {
            let question = store.event(&b.question_id)?.and_then(|e| e.envelope().ok());
            match check_answer_reference(env, question.as_ref()) {
                Reference::Resolved => {}
                Reference::Missing => return Ok(Ingest::Deferred("missing_question")),
                Reference::Invalid(_) => return Ok(Ingest::Rejected("bad_answer_reference")),
            }
        }
        // A ballot and a stance need nothing beyond the authorization above.
        EventBody::Vote(_) | EventBody::Stance(_) => {}
    }
    Ok(stored(store.insert_event(&verified, origin_peer, now)?))
}

/// Seconds the question quotas look back.
const QUESTION_WINDOW_SECS: i64 = 86_400;

/// A QUESTION: stored in the event log like any other event, and listed for the owner
/// unless the local guard holds it back (`ph_governance::QuestionGuard`): a blocked
/// author's question is not stored at all; a muted author's, and one over the daily
/// quota, is kept but not shown; one whose text was already asked in the circle gets no
/// second entry. None of this is told to the peer that carried it.
fn ingest_question(
    store: &Store,
    verified: &VerifiedEnvelope,
    origin_peer: Option<&str>,
    now: Timestamp,
) -> Result<Ingest> {
    let EventBody::Question(body) = &verified.body else {
        return Ok(Ingest::Rejected("invalid"));
    };
    let mine = store
        .identity()?
        .is_some_and(|me| me.device_key == verified.author);
    let normalized = normalize_question_text(&body.question);
    let mut decision = GuardDecision::Accept;
    if !mine {
        let author = store.peer_by_device_key(&verified.author)?;
        let since = now.minus_secs(QUESTION_WINDOW_SECS);
        let count = |n: u64| u32::try_from(n).unwrap_or(u32::MAX);
        let ctx = QuestionContext {
            author_count_24h: count(
                store.count_questions_by_author_since(&verified.author, since)?,
            ),
            circle_count_24h: count(
                store.count_questions_by_circle_since(&verified.circle_id, since)?,
            ),
            duplicate: !normalized.is_empty()
                && store.question_text_exists(&verified.circle_id, &normalized)?,
            author_muted: author.as_ref().is_some_and(|p| p.muted),
            author_blocked: author.as_ref().is_some_and(|p| p.blocked),
        };
        decision = QuestionGuard::default().check(&ctx);
        if decision == GuardDecision::Drop(ph_governance::DropReason::Blocked) {
            return Ok(Ingest::Rejected("blocked"));
        }
    }
    let outcome = store.transaction(|s| {
        let outcome = s.insert_event(verified, origin_peer, now)?;
        if outcome == InsertOutcome::Inserted && !normalized.is_empty() {
            if let Some(q) = NewQuestion::from_envelope(verified, normalized.clone(), mine, now) {
                let listed = s.insert_question(&q)? == ph_store::QuestionInsert::Inserted;
                if listed && !decision.is_accept() {
                    s.set_question_status(&q.event_id, QuestionStatus::Muted)?;
                }
            }
        }
        Ok(outcome)
    })?;
    Ok(stored(outcome))
}

fn stored(outcome: InsertOutcome) -> Ingest {
    match outcome {
        InsertOutcome::Inserted => Ingest::Stored,
        InsertOutcome::Duplicate => Ingest::Duplicate,
    }
}

/// A CHARTER event: accepted as the new current charter only if a passed amendment of
/// the current charter justifies it (`check_successor`). The root key is a notary.
fn ingest_charter(
    store: &Store,
    verified: &VerifiedEnvelope,
    next: &Charter,
    origin_peer: Option<&str>,
    now: Timestamp,
) -> Result<Ingest> {
    let circle = next.circle_id;
    let Some(current) = store.current_charter(&circle)? else {
        // Without a trust anchor (the founding charter, or the one in the invitation)
        // this node cannot judge any successor.
        return Ok(Ingest::Rejected("no_charter_anchor"));
    };
    if store.charter_by_digest(&circle, &next.digest()?)?.is_some() {
        // A charter this node already accepted: keep the event for peers that sync.
        return Ok(stored(store.insert_event(verified, origin_peer, now)?));
    }
    if next.seq < current.seq {
        // An older charter can only be history. It is accepted when the chain this node
        // already holds names it by hash (`Store::insert_charter_history`); until the
        // charters in between have arrived it waits.
        let linked = store.oldest_charter(&circle)?.is_some_and(|oldest| {
            next.digest().ok() == oldest.previous && next.seq.checked_add(1) == Some(oldest.seq)
        });
        if !linked {
            return Ok(Ingest::Deferred("charter_history_not_linked"));
        }
        let outcome = store.transaction(|s| {
            s.insert_charter_history(next, now)?;
            s.insert_event(verified, origin_peer, now)
        })?;
        tracing::info!(circle = %circle, seq = next.seq, "charter stored as history");
        return Ok(stored(outcome));
    }
    if next.seq == current.seq {
        // A different charter with the current number: not a successor of anything.
        return Ok(Ingest::Rejected("charter_not_newer"));
    }
    let Some(justification) = next.justification else {
        return Ok(Ingest::Rejected("charter_without_justification"));
    };
    let Some(result_ev) = store.event(&justification)? else {
        return Ok(Ingest::Deferred("missing_result"));
    };
    let Ok(result) = result_ev
        .envelope()
        .map_err(|_| ())
        .and_then(|e| ResultView::from_envelope(&e).map_err(|_| ()))
    else {
        return Ok(Ingest::Rejected("justification_not_a_result"));
    };
    let Ok(proposal) = proposal_view(store, &result.proposal_id()) else {
        return Ok(Ingest::Deferred("missing_proposal"));
    };
    let votes = votes_for(store, &proposal.event_id())?;
    if let Err(e) = check_successor(
        &current,
        next,
        &proposal,
        &result,
        &votes,
        &revoked_in(store, &circle),
    ) {
        return Ok(if e.is_retryable() {
            Ingest::Deferred(e.code())
        } else {
            Ingest::Rejected(e.code())
        });
    }
    let outcome = store.transaction(|s| {
        s.insert_charter(next, now)?;
        s.insert_event(verified, origin_peer, now)
    })?;
    tracing::info!(circle = %circle, seq = next.seq, "charter accepted as current");
    Ok(stored(outcome))
}

/// Signs `body` with `key` and submits it through [`ingest`], exactly as a peer would
/// receive it. Fails if this node itself would not accept the event.
pub fn submit(
    store: &Store,
    key: &SigningKey,
    circle: &CircleId,
    scope: &Scope,
    body: EventBody,
    now: Timestamp,
) -> Result<SignedEnvelope> {
    let env = EnvelopeBuilder::new(*circle, scope.clone(), body)
        .sign(key, now)
        .context("cannot sign the event")?;
    let raw = env.to_canonical_json()?;
    match ingest(store, raw.as_bytes(), None, now)? {
        Ingest::Stored | Ingest::Duplicate => Ok(env),
        Ingest::Deferred(code) => bail!("this node cannot accept that event yet ({code})"),
        Ingest::Rejected(code) => Err(crate::error::refused(format!(
            "this node would not accept that event ({code})"
        ))),
    }
}

/// Founds a circle on this node: stores the circle row and the founding charter, with
/// `founder` as the only member. The caller has shown the charter to the human; the
/// node starts in the adoption mode a binding or advisory charter implies.
pub fn found_circle(
    store: &Store,
    authority: &CircleAuthority,
    name: &str,
    founder: RollEntry,
    root_keystore_ref: Option<String>,
    now: Timestamp,
) -> Result<Charter> {
    let charter = authority.issue_founding_charter(CharterContent::founding(founder), now)?;
    let mode = ph_governance::AdoptionMode::default_for(charter.content.rules.binding);
    store.transaction(|s| {
        s.insert_circle(&CircleRow {
            circle_id: authority.circle_id(),
            name: name.to_owned(),
            root_key: authority.root_key(),
            is_founder: true,
            root_keystore_ref: root_keystore_ref.clone(),
            adoption_mode: mode.as_str().to_owned(),
            accepted_charter: Some(charter.digest()?),
            created_at: now,
        })?;
        s.insert_charter(&charter, now)?;
        Ok(())
    })?;
    // Publish it as an event too. Members who join later start from a later charter;
    // this lets them hold the founding one as history and with it the votes cast under
    // it (`Store::insert_charter_history`).
    submit(
        store,
        authority.signing_key(),
        &authority.circle_id(),
        &Scope::all(),
        EventBody::Charter(CharterBody {
            charter: charter.clone(),
        }),
        now,
    )?;
    Ok(charter)
}

/// Joins a circle on this node with `anchor` as the trust anchor: the charter the
/// invitation carried, which the human was shown and accepted. `my_device` must be on
/// its roll.
pub fn join_circle(
    store: &Store,
    name: &str,
    anchor: &Charter,
    my_device: &DeviceKey,
    now: Timestamp,
) -> Result<()> {
    ph_protocol::verify_charter_signature(anchor).context("the charter does not verify")?;
    if anchor.content.member_of(my_device).is_none() {
        return Err(crate::error::refused(
            "this device is not on the roll of that charter",
        ));
    }
    let mode = ph_governance::AdoptionMode::default_for(anchor.content.rules.binding);
    store.transaction(|s| {
        s.insert_circle(&CircleRow {
            circle_id: anchor.circle_id,
            name: name.to_owned(),
            root_key: anchor.issuer_key,
            is_founder: false,
            root_keystore_ref: None,
            adoption_mode: mode.as_str().to_owned(),
            accepted_charter: Some(anchor.digest()?),
            created_at: now,
        })?;
        s.insert_charter(anchor, now)?;
        Ok(())
    })?;
    Ok(())
}

/// What a member proposes: where it applies, how it is described, and the action.
pub struct NewProposal<'a> {
    /// The scope of an `adopt` or `repeal` proposal. Ignored for `amend`, which always
    /// concerns the whole circle.
    pub scope: &'a Scope,
    /// Title shown to voters (1-200 characters, single line).
    pub title: &'a str,
    /// Why (0-1000 characters). Human-confirmed text only.
    pub summary: &'a str,
    /// What is being decided.
    pub action: ph_protocol::ProposalAction,
}

/// Puts a proposal to the vote under the circle's current charter.
pub fn propose(
    store: &Store,
    key: &SigningKey,
    circle: &CircleId,
    new: NewProposal<'_>,
    now: Timestamp,
) -> Result<ProposalView> {
    let charter = current_charter(store, circle)?;
    let scope = if new.action.kind() == ProposalKind::Amend {
        Scope::all()
    } else {
        new.scope.clone()
    };
    let body = EventBody::Proposal(ProposalBody {
        charter: charter.digest()?,
        title: new.title.to_owned(),
        summary: new.summary.to_owned(),
        action: new.action,
    });
    let env = submit(store, key, circle, &scope, body, now)?;
    ProposalView::from_envelope(&env).map_err(|_| anyhow!("the signed proposal is invalid"))
}

/// Casts a ballot on a stored proposal.
pub fn cast_vote(
    store: &Store,
    key: &SigningKey,
    proposal: &ProposalView,
    decision: VoteDecision,
    rationale: Option<&str>,
    now: Timestamp,
) -> Result<SignedEnvelope> {
    let body = EventBody::Vote(VoteBody {
        proposal_id: proposal.event_id(),
        decision,
        rationale: rationale.map(str::to_owned),
    });
    submit(
        store,
        key,
        &proposal.circle_id(),
        proposal.scope(),
        body,
        now,
    )
}

/// What a member put on the circle's record about a rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedStance {
    /// The member's handle.
    pub member: String,
    /// Their current stance.
    pub stance: ph_protocol::Stance,
    /// The reason they gave, if any.
    pub reason: Option<String>,
    /// Whether this node's own device belongs to that member.
    pub mine: bool,
}

/// The current recorded stance of every member of the current roll who made one about
/// the rule `proposal_id` adopts, by member handle. A member's latest stance (by
/// `created_at`, then event id) is the current one; stances of members who have left
/// the roll, and of revoked devices, are not shown.
///
/// This is a record. Nothing is counted from it.
pub fn stances(
    store: &Store,
    circle: &CircleId,
    proposal_id: &EventId,
    me: &DeviceKey,
) -> Result<Vec<RecordedStance>> {
    let current = current_charter(store, circle)?;
    let mut latest: HashMap<String, ((i64, EventId), RecordedStance)> = HashMap::new();
    for ev in store.stances_for_proposal(proposal_id)? {
        let Ok(env) = ev.envelope() else { continue };
        let EventBody::Stance(body) = &env.body else {
            continue;
        };
        if store.is_revoked(circle, &env.author)? {
            continue;
        }
        // The handle is the one on the roll the stance names; it must still be on the
        // current roll.
        let Some(member) = store
            .charter_by_digest(circle, &body.charter)?
            .and_then(|c| c.content.member_of(&env.author).map(|e| e.member.clone()))
            .filter(|m| current.content.member(m).is_some())
        else {
            continue;
        };
        let order = (env.created_at.unix_seconds(), env.event_id);
        if latest.get(&member).is_some_and(|(o, _)| *o >= order) {
            continue;
        }
        let mine = current
            .content
            .member_of(me)
            .is_some_and(|e| e.member == member);
        latest.insert(
            member.clone(),
            (
                order,
                RecordedStance {
                    member,
                    stance: body.stance,
                    reason: body.reason.clone(),
                    mine,
                },
            ),
        );
    }
    let mut out: Vec<RecordedStance> = latest.into_values().map(|(_, s)| s).collect();
    out.sort_by(|a, b| a.member.cmp(&b.member));
    Ok(out)
}

/// Puts this member's stance on the rule `rule` on the circle's record, under the
/// current charter. The caller has shown the exact text and has the owner's
/// confirmation.
pub fn announce_stance(
    store: &Store,
    key: &SigningKey,
    circle: &CircleId,
    rule: &ph_governance::Rule,
    stance: ph_protocol::Stance,
    reason: Option<String>,
    now: Timestamp,
) -> Result<SignedEnvelope> {
    let charter = current_charter(store, circle)?;
    submit(
        store,
        key,
        circle,
        rule.scope(),
        EventBody::Stance(ph_protocol::StanceBody {
            proposal_id: rule.proposal_id(),
            charter: charter.digest()?,
            stance,
            reason,
        }),
        now,
    )
}

/// Publishes a RESULT for `proposal` if the ballots this node holds carry it over its
/// threshold. Returns `None` while it has not passed.
pub fn publish_result(
    store: &Store,
    key: &SigningKey,
    proposal: &ProposalView,
    now: Timestamp,
) -> Result<Option<SignedEnvelope>> {
    let (_, t) = count(store, proposal)?;
    let Some(approvals) = t.certificate() else {
        return Ok(None);
    };
    let body = EventBody::Result(ResultBody::new(proposal.event_id(), approvals));
    submit(
        store,
        key,
        &proposal.circle_id(),
        proposal.scope(),
        body,
        now,
    )
    .map(Some)
}

/// Notarizes the amendment that `result_id` certifies: issues the next charter with the
/// root key, checks it exactly as every other node will, and publishes it. Only the
/// node that holds the circle root key can do this, and it can only sign what passed.
pub fn notarize(
    store: &Store,
    authority: &CircleAuthority,
    result_id: &EventId,
    now: Timestamp,
) -> Result<Charter> {
    let circle = authority.circle_id();
    let current = current_charter(store, &circle)?;
    let result_ev = store
        .event(result_id)?
        .ok_or_else(|| anyhow!("no such result in the local store"))?;
    let result = ResultView::from_envelope(&result_ev.envelope()?)
        .map_err(|_| anyhow!("that event is not a result"))?;
    let proposal = proposal_view(store, &result.proposal_id())?;
    let next_content = proposal
        .amend_next()
        .ok_or_else(|| crate::error::refused("only a passed amendment changes the charter"))?
        .clone();
    let next = authority.issue_next_charter(&current, next_content, *result_id, now)?;
    let votes = votes_for(store, &proposal.event_id())?;
    check_successor(
        &current,
        &next,
        &proposal,
        &result,
        &votes,
        &revoked_in(store, &circle),
    )
    .map_err(|e| {
        crate::error::refused(format!(
            "the amendment does not justify a new charter ({})",
            e.code()
        ))
    })?;
    submit(
        store,
        authority.signing_key(),
        &circle,
        &Scope::all(),
        EventBody::Charter(CharterBody {
            charter: next.clone(),
        }),
        now,
    )?;
    Ok(next)
}

// ---------------------------------------------------------------------------------------
// File exchange
// ---------------------------------------------------------------------------------------

/// Everything this node holds for `circle`, as JSON lines: one `{"event": <envelope>}`
/// per stored event (oldest first) and one `{"bundle": {"digest", "skill_md"}}` per
/// bundle an `adopt` proposal names and this node has. The recipient verifies every
/// line; the carrier is not trusted.
///
/// This hands over all of the circle's events, including the roll. Give the output only
/// to members of the circle.
pub fn export_circle(
    store: &Store,
    bundles: &BundleStore,
    circle: &CircleId,
) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    let mut digests = HashSet::new();
    for ev in store
        .list_events(circle, &ph_store::EventFilter::default())?
        .into_iter()
        .rev()
    {
        if let Some(d) = ev.bundle_digest {
            digests.insert(d);
        }
        lines.push(json!({ "event": ev.to_value()? }).to_string());
    }
    let mut digests: Vec<Digest> = digests.into_iter().collect();
    digests.sort();
    for d in digests {
        if let Ok(bundle) = bundles.get(&d) {
            lines.push(json!({"bundle": {"digest": d, "skill_md": bundle.skill_md()}}).to_string());
        }
    }
    Ok(lines)
}

/// What [`import_lines`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportSummary {
    pub stored: usize,
    pub duplicate: usize,
    pub deferred: usize,
    pub rejected: usize,
    pub bundles: usize,
    /// Rejection codes with counts, for the local report.
    pub rejection_codes: Vec<(String, usize)>,
}

/// Imports lines produced by [`export_circle`]. Every event goes through [`ingest`];
/// events are retried in passes until a pass stores nothing new, so the order of the
/// lines does not matter. A bundle is stored only if an `adopt` proposal this node
/// holds names its digest and it validates as an instruction-only skill.
pub fn import_lines<'a>(
    store: &Store,
    bundles: &BundleStore,
    lines: impl IntoIterator<Item = &'a str>,
    now: Timestamp,
) -> Result<ImportSummary> {
    let mut events: Vec<String> = Vec::new();
    let mut offered_bundles: Vec<(Digest, String)> = Vec::new();
    let mut summary = ImportSummary::default();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            summary.rejected += 1;
            continue;
        };
        if let Some(ev) = v.get("event") {
            events.push(ev.to_string());
        } else if let Some(b) = v.get("bundle") {
            let digest = b
                .get("digest")
                .and_then(Value::as_str)
                .and_then(|s| s.parse().ok());
            let md = b.get("skill_md").and_then(Value::as_str);
            match (digest, md) {
                (Some(d), Some(md)) => offered_bundles.push((d, md.to_owned())),
                _ => summary.rejected += 1,
            }
        } else {
            summary.rejected += 1;
        }
    }
    let mut pending = events;
    let mut codes: HashMap<&'static str, usize> = HashMap::new();
    loop {
        let mut progress = false;
        let mut next = Vec::new();
        for raw in pending {
            match ingest(store, raw.as_bytes(), None, now)? {
                Ingest::Stored => {
                    summary.stored += 1;
                    progress = true;
                }
                Ingest::Duplicate => summary.duplicate += 1,
                Ingest::Deferred(_) => next.push(raw),
                Ingest::Rejected(code) => {
                    summary.rejected += 1;
                    *codes.entry(code).or_default() += 1;
                }
            }
        }
        pending = next;
        if !progress || pending.is_empty() {
            break;
        }
    }
    summary.deferred = pending.len();
    for (digest, md) in offered_bundles {
        if bundles.contains(&digest) {
            continue;
        }
        // Only bundles that a stored adopt proposal names are of any interest.
        let mut named = false;
        for c in store.circles()? {
            if !store
                .proposals_with_bundle(&c.circle_id, &digest)?
                .is_empty()
            {
                named = true;
                break;
            }
        }
        if !named {
            summary.rejected += 1;
            continue;
        }
        match ph_skills::validate_received(
            vec![("SKILL.md".to_owned(), md.into_bytes())],
            &digest,
            None,
        ) {
            Ok(bundle) => {
                record_bundle(store, bundles, &bundle, now)?;
                summary.bundles += 1;
            }
            Err(_) => summary.rejected += 1,
        }
    }
    let mut codes: Vec<(String, usize)> =
        codes.into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
    codes.sort();
    summary.rejection_codes = codes;
    Ok(summary)
}

/// Stores a validated bundle on disk and in the `bundles` table.
pub fn record_bundle(
    store: &Store,
    bundles: &BundleStore,
    bundle: &Bundle,
    now: Timestamp,
) -> Result<()> {
    bundles
        .put(bundle)
        .map_err(|e| anyhow!("cannot store the bundle: {e}"))?;
    store.insert_bundle(&BundleRow {
        digest: bundle.digest(),
        skill_name: bundle.name().to_owned(),
        manifest: bundle.manifest().clone(),
        rel_path: format!(
            "{}/{}",
            crate::home::BUNDLES_DIR,
            BundleStore::relative_path(&bundle.digest())
        ),
        size: bundle.size(),
        created_at: now,
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Settling: results, notarization and the agent's skills directory
// ---------------------------------------------------------------------------------------

/// What [`apply_rules`] did to the agent's skills directory, and what it is waiting for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// Rules installed or updated now.
    pub installed: Vec<String>,
    /// Managed skills removed now (repealed, replaced or opted out).
    pub removed: Vec<String>,
    /// Rules in force that wait for the owner's confirmation, with the reason code.
    pub asking: Vec<(String, &'static str)>,
    /// Rules in force that cannot be installed, with the reason code.
    pub refused: Vec<(String, &'static str)>,
    /// Rules in force that the owner opted out of.
    pub opted_out: Vec<String>,
    /// Rules in force whose bundle this node does not hold yet.
    pub waiting_for_bundle: Vec<String>,
    /// Rules that could not be installed because something PeerHarness does not manage
    /// is in the way (it is never overwritten).
    pub conflicts: Vec<String>,
    /// Rules in force that do not bind this node: it is not in their electorate.
    pub not_bound: Vec<String>,
}

/// The owner of this node, as far as applying rules is concerned.
#[derive(Clone, Copy)]
pub struct Owner<'a> {
    /// The node's device key, which places the owner on the roll (or not).
    pub me: &'a DeviceKey,
    /// The owner's stricter local policy.
    pub policy: &'a ph_governance::LocalPolicy,
    /// Rules the owner explicitly confirmed in this command.
    pub confirmed: &'a [String],
}

/// Brings the agent's skills directory in line with the rules in force in `circle`,
/// according to the owner's adoption mode, opt-outs and local policy (architecture
/// section 10.9). `confirmed` names rules the owner explicitly confirmed just now.
///
/// Only skills PeerHarness installed for this circle are ever removed: a managed
/// installation whose recorded digest is the bundle of one of this circle's `adopt`
/// proposals and whose file the user has not edited.
pub fn apply_rules(
    store: &Store,
    bundles: &BundleStore,
    installer: &ph_skills::Installer,
    circle: &CircleRow,
    owner: &Owner<'_>,
    now: Timestamp,
) -> Result<Applied> {
    let Owner {
        me,
        policy,
        confirmed,
    } = *owner;
    use ph_governance::{
        adoption_step, local_policy_met, AdoptionMode, AdoptionStep, BundleChecks, OwnerChoice,
    };
    use ph_skills::{InstallOptions, InstallState, UninstallOptions};

    use crate::installs;

    let id = &circle.circle_id;
    let (charter, rules, tallies) = rule_set(store, id)?;
    // A rule binds the members who were entitled to vote on it: those on the roll whose
    // scopes cover the rule's scope. A node outside that electorate (a member of another
    // team, or someone who was removed) installs nothing and keeps nothing the circle
    // had installed.
    // An owner who left the circle on this machine (`circle leave`) is bound by nothing
    // here, whatever the roll still says.
    let left = store.circle_left_at(id)?.is_some();
    let binds_me = |rule: &ph_governance::Rule| -> bool {
        !left
            && charter
                .content
                .voter(me, &ph_protocol::Electorate::Scope(rule.scope()))
                .is_some()
    };
    let mode = match circle.adoption_mode.as_str() {
        "follow" => AdoptionMode::Follow,
        _ => AdoptionMode::Ask,
    };
    let mut applied = Applied::default();
    let places = store.rule_places(id)?;
    // Where a rule of this scope goes on this machine: the project directory the owner
    // chose for the most specific scope that covers it, or the user's skills directory.
    let target_for = |scope: &Scope| -> Target { Target::of(installer, place_for(&places, scope)) };
    let managed_with = |target: &Target, name: &str, digest: &Digest| -> bool {
        matches!(
            target.installer.status(name),
            Ok(InstallState::Managed { digest: d, modified: false }) if d == *digest
        )
    };
    // Removes what a vote installed for `name`, from wherever it was put.
    let remove = |name: &str, digest: &Digest, applied: &mut Applied| -> Result<()> {
        let Some(place) = store.rule_install_place(id, name)? else {
            return Ok(());
        };
        let target = Target::of(installer, place);
        if managed_with(&target, name, digest) {
            if let Ok(gone) = target
                .installer
                .uninstall(name, UninstallOptions::default())
            {
                installs::record_uninstall(
                    store,
                    target.scope,
                    name,
                    &gone.removed_digest,
                    &gone.path,
                    now,
                )?;
                if !applied.removed.iter().any(|n| n == name) {
                    applied.removed.push(name.to_owned());
                }
            }
        }
        store.clear_rule_install(id, name)?;
        Ok(())
    };

    for rule in rules.rules() {
        let name = rule.skill_name().to_owned();
        if !binds_me(rule) {
            applied.not_bound.push(name);
            continue;
        }
        let Ok(bundle) = bundles.get(&rule.bundle_digest()) else {
            applied.waiting_for_bundle.push(name);
            continue;
        };
        let checks = BundleChecks {
            digest_verified: bundle.digest() == rule.bundle_digest(),
            // The proposal names the skill; the bundle must be that skill and nothing else.
            skill_valid: bundle.name() == rule.skill_name(),
            high_risk: ph_skills::has_high_risk(&bundle.scan()),
        };
        let choice = OwnerChoice {
            opted_out: store.is_rule_opted_out(id, &name)?,
            confirmed: confirmed.contains(&name),
        };
        let policy_ok = local_policy_met(policy, tallies.get(&rule.proposal_id()));
        let target = target_for(rule.scope());
        match adoption_step(rule, mode, checks, choice, policy_ok) {
            AdoptionStep::Install => {
                // A copy this circle put somewhere else (the owner moved the scope) or
                // of another version goes first.
                let recorded = store.rule_install_place(id, &name)?;
                let moved = recorded.as_ref().is_some_and(|p| *p != target.dir);
                if moved {
                    let old = store
                        .rule_installs(id)?
                        .into_iter()
                        .find(|(n, _, _)| *n == name)
                        .map(|(_, d, _)| d);
                    if let Some(old) = old {
                        remove(&name, &old, &mut applied)?;
                    }
                } else if managed_with(&target, &name, &rule.bundle_digest()) {
                    continue; // already in place
                }
                match target.installer.install(&bundle, InstallOptions::default()) {
                    Ok(outcome) => {
                        // Remember that the vote put it here, so a repeal removes it.
                        store.record_rule_install(id, &name, &rule.bundle_digest(), now)?;
                        store.set_rule_install_place(id, &name, target.dir.as_deref())?;
                        installs::ensure_circle_skill(store, &bundle, &rule.proposal_id(), now)?;
                        installs::record_install(store, target.scope, &bundle, &outcome, now)?;
                        applied.installed.push(name);
                    }
                    Err(_) => applied.conflicts.push(name),
                }
            }
            step @ AdoptionStep::AskOwner(_) => applied.asking.push((name, step.code())),
            step @ AdoptionStep::Refuse(_) => applied.refused.push((name, step.code())),
            AdoptionStep::OptedOut => {
                remove(&name, &rule.bundle_digest(), &mut applied)?;
                store.clear_rule_install(id, &name)?;
                applied.opted_out.push(name);
            }
        }
    }

    // Rules that are no longer in force, or no longer bind this node: remove what this
    // circle's votes installed, and only that. A skill the owner installed personally has
    // no record here and stays.
    for (name, digest, _) in store.rule_installs(id)? {
        let still_applies = rules
            .get(&name)
            .is_some_and(|r| r.bundle_digest() == digest && binds_me(r));
        if !still_applies {
            remove(&name, &digest, &mut applied)?;
        }
    }
    Ok(applied)
}

/// Where one rule is installed on this machine.
pub struct Target {
    /// The installer for that place.
    pub installer: ph_skills::Installer,
    /// The agent's notion of the place.
    pub scope: ph_skills::SkillScope,
    /// The project directory, or `None` for the user's skills directory.
    pub dir: Option<String>,
}

impl Target {
    /// The target for `dir` (a project directory the owner chose), or the user's skills
    /// directory behind `user` when there is none. A project installer never follows a
    /// link out of the project (`Installer::confine_to`).
    pub fn of(user: &ph_skills::Installer, dir: Option<String>) -> Self {
        match dir {
            Some(d) => {
                let root = std::path::Path::new(&d);
                Self {
                    installer: ph_skills::Installer::new(root.join(".claude").join("skills"))
                        .confine_to(root),
                    scope: ph_skills::SkillScope::Project,
                    dir: Some(d),
                }
            }
            None => Self {
                installer: user.clone(),
                scope: ph_skills::SkillScope::User,
                dir: None,
            },
        }
    }
}

/// The project directory for rules of `scope`: the place of the most specific scope
/// that covers it.
pub fn place_for(places: &[(Scope, String)], scope: &Scope) -> Option<String> {
    places
        .iter()
        .filter(|(s, _)| s.covers(scope))
        .max_by_key(|(s, _)| (!s.is_wildcard(), s.as_str().len()))
        .map(|(_, dir)| dir.clone())
}

/// What [`settle`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settled {
    /// RESULT events this node published.
    pub results_published: Vec<EventId>,
    /// The `seq` of a charter this node notarized (founder only).
    pub charter_notarized: Option<u64>,
    /// Changes to the agent's skills directory.
    pub applied: Applied,
}

/// Brings one circle up to date after anything changed (a ballot was cast, events were
/// imported):
///
/// 1. publishes a RESULT for every proposal that the ballots held here carry over its
///    threshold and that has none yet (needs the device key);
/// 2. on the node that holds the circle root key, notarizes a passed amendment into the
///    next charter (needs the root key; the notary has no discretion, so this is
///    automatic);
/// 3. applies the rules in force to the agent's skills directory ([`apply_rules`]).
pub fn settle(
    node: &crate::node::Node,
    circle: &CircleRow,
    installer: &ph_skills::Installer,
    confirmed: &[String],
) -> Result<Settled> {
    let store = &node.store;
    let id = circle.circle_id;
    let now = node.now();
    let mut settled = Settled::default();
    let me = node.device_key();

    let open_and_passed = |store: &Store| -> Result<Vec<(ProposalView, bool)>> {
        let current = current_charter(store, &id)?.digest()?;
        let mut out = Vec::new();
        for ev in store.proposals(&id)? {
            let Ok(p) = ev
                .envelope()
                .map_err(|_| ())
                .and_then(|e| ProposalView::from_envelope(&e).map_err(|_| ()))
            else {
                continue;
            };
            if p.charter() != current {
                continue;
            }
            let Ok((_, t)) = count(store, &p) else {
                continue;
            };
            if t.passed() {
                let has_result = !store.results_for_proposal(&p.event_id())?.is_empty();
                out.push((p, has_result));
            }
        }
        Ok(out)
    };

    // 1. Results.
    for (p, has_result) in open_and_passed(store)? {
        let charter = current_charter(store, &id)?;
        if has_result || charter.content.voter(&me, &p.electorate()).is_none() {
            continue;
        }
        let key = node.device()?.signing_key();
        if let Some(env) = publish_result(store, key, &p, now)? {
            settled.results_published.push(env.event_id);
        }
    }

    // 2. Notarization (founder only).
    if circle.is_founder {
        for (p, _) in open_and_passed(store)? {
            if p.kind() != ProposalKind::Amend {
                continue;
            }
            let Some(result) = store
                .results_for_proposal(&p.event_id())?
                .into_iter()
                .next()
            else {
                continue;
            };
            let authority = CircleAuthority::load(node.keystore()?, &id)
                .context("cannot unlock the circle root key")?;
            let next = notarize(store, &authority, &result.event_id, now)?;
            settled.charter_notarized = Some(next.seq);
            break; // the charter changed: every other open proposal is now stale
        }
    }

    // 3. Rules.
    let bundles = crate::library::bundle_store(&node.home);
    // Re-read the circle row: adoption settings may have changed during this command.
    let circle = store.circle(&id)?.unwrap_or_else(|| circle.clone());
    settled.applied = apply_rules(
        store,
        &bundles,
        installer,
        &circle,
        &Owner {
            me: &me,
            policy: &node.config.policy,
            confirmed,
        },
        now,
    )?;
    Ok(settled)
}

/// The installer for the user's Claude Code skills directory (honours
/// `PEERHARNESS_CLAUDE_SKILLS_DIR`).
pub fn user_installer() -> Result<ph_skills::Installer> {
    let cwd = std::env::current_dir().context("cannot read the current directory")?;
    ph_skills::claude_installer(ph_skills::SkillScope::User, &cwd)
        .map_err(|e| anyhow!("cannot locate the agent's skills directory: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ph_protocol::{AnswerBody, AnswerChoice, QuestionBody};
    use ph_store::QuestionStatus;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn device(seed: u8) -> DeviceKey {
        DeviceKey::from_signing_key(&key(seed))
    }

    /// A node (device 1, alice) holding a circle whose roll is alice (every scope), bob
    /// (device 2, every scope) and carol (device 3, only `team/backend`).
    fn node() -> (Store, CircleId, Timestamp) {
        let store = Store::open_in_memory().unwrap();
        let now = Timestamp::now();
        store
            .set_identity(&ph_store::IdentityMetadata {
                device_key: device(1),
                keystore_backend: "insecure-dev".into(),
                keystore_ref: "test".into(),
                created_at: now,
            })
            .unwrap();
        let authority = CircleAuthority::from_signing_key(key(100));
        let circle = authority.circle_id();
        let mut content =
            CharterContent::founding(RollEntry::new("alice", vec![device(1)], vec![Scope::all()]));
        content
            .roll
            .push(RollEntry::new("bob", vec![device(2)], vec![Scope::all()]));
        content.roll.push(RollEntry::new(
            "carol",
            vec![device(3)],
            vec![Scope::new("team/backend").unwrap()],
        ));
        content.normalize();
        let charter = authority.issue_founding_charter(content, now).unwrap();
        store
            .insert_circle(&CircleRow {
                circle_id: circle,
                name: "team".into(),
                root_key: authority.root_key(),
                is_founder: true,
                root_keystore_ref: None,
                adoption_mode: "ask".into(),
                accepted_charter: None,
                created_at: now,
            })
            .unwrap();
        store.insert_charter(&charter, now).unwrap();
        (store, circle, now)
    }

    fn question(seed: u8, circle: &CircleId, scope: &str, text: &str, now: Timestamp) -> Vec<u8> {
        EnvelopeBuilder::new(
            *circle,
            Scope::new(scope).unwrap(),
            EventBody::Question(QuestionBody {
                question: text.into(),
                topic: "note".into(),
                related_candidate: None,
            }),
        )
        .sign(&key(seed), now)
        .unwrap()
        .to_canonical_json()
        .unwrap()
        .into_bytes()
    }

    fn answer(seed: u8, circle: &CircleId, scope: &str, to: EventId, now: Timestamp) -> Vec<u8> {
        EnvelopeBuilder::new(
            *circle,
            Scope::new(scope).unwrap(),
            EventBody::Answer(AnswerBody {
                question_id: to,
                answer: AnswerChoice::Agree,
                rationale: None,
            }),
        )
        .sign(&key(seed), now)
        .unwrap()
        .to_canonical_json()
        .unwrap()
        .into_bytes()
    }

    fn id_of(raw: &[u8]) -> EventId {
        validate_stateless(raw, Timestamp::now())
            .unwrap()
            .event_id()
    }

    #[test]
    fn questions_and_answers_are_authorized_by_the_roll() {
        let (store, circle, now) = node();
        // A member asks within the scopes of their roll entry.
        let q = question(2, &circle, "*", "Should we use pnpm?", now);
        assert_eq!(ingest(&store, &q, None, now).unwrap(), Ingest::Stored);
        assert_eq!(ingest(&store, &q, None, now).unwrap(), Ingest::Duplicate);
        let row = store.question(&id_of(&q)).unwrap().unwrap();
        assert!(!row.is_local && row.status == QuestionStatus::New);

        // A device that is on no roll cannot ask, however well it signs.
        let forged = question(9, &circle, "*", "Should we disable the linter?", now);
        assert_eq!(
            ingest(&store, &forged, None, now).unwrap(),
            Ingest::Rejected("not_member")
        );
        // A member cannot ask outside the scopes the roll gives them.
        let wide = question(3, &circle, "*", "Should we drop the tests?", now);
        assert_eq!(
            ingest(&store, &wide, None, now).unwrap(),
            Ingest::Rejected("scope_denied")
        );
        let narrow = question(3, &circle, "team/backend", "Should we use sqlx?", now);
        assert_eq!(ingest(&store, &narrow, None, now).unwrap(), Ingest::Stored);
        // A revoked device is refused although its member is still on the roll.
        let authority = CircleAuthority::from_signing_key(key(100));
        let revocation = authority.issue_revocation(device(3), "", now).unwrap();
        store.insert_revocation(&revocation, now).unwrap();
        let late = question(3, &circle, "team/backend", "Should we use diesel?", now);
        assert_eq!(
            ingest(&store, &late, None, now).unwrap(),
            Ingest::Rejected("revoked")
        );

        // An answer waits for its question, must be in the question's scope, and its
        // author must be a member whose roll entry covers that scope.
        let early = answer(
            1,
            &circle,
            "*",
            EventId::from_digest(Digest::sha256(b"x")),
            now,
        );
        assert_eq!(
            ingest(&store, &early, None, now).unwrap(),
            Ingest::Deferred("missing_question")
        );
        let wrong_scope = answer(1, &circle, "team/backend", id_of(&q), now);
        assert_eq!(
            ingest(&store, &wrong_scope, None, now).unwrap(),
            Ingest::Rejected("bad_answer_reference")
        );
        let stranger = answer(9, &circle, "*", id_of(&q), now);
        assert_eq!(
            ingest(&store, &stranger, None, now).unwrap(),
            Ingest::Rejected("not_member")
        );
        let good = answer(1, &circle, "*", id_of(&q), now);
        assert_eq!(ingest(&store, &good, None, now).unwrap(), Ingest::Stored);
        assert_eq!(store.answers_for_question(&id_of(&q)).unwrap().len(), 1);
    }

    #[test]
    fn the_local_guard_keeps_noise_out_of_the_inbox() {
        let (store, circle, now) = node();
        let pid = ph_network::peer_id_from_device_key(&device(2)).to_string();
        store.upsert_peer(&pid, &device(2), &[], now).unwrap();

        // The same text asked again gets no second entry, whatever its punctuation.
        let first = question(2, &circle, "*", "Should we use pnpm?", now);
        let again = question(1, &circle, "*", "should we use PNPM", now);
        assert_eq!(ingest(&store, &first, None, now).unwrap(), Ingest::Stored);
        assert_eq!(ingest(&store, &again, None, now).unwrap(), Ingest::Stored);
        assert_eq!(store.all_questions().unwrap().len(), 1);

        // A muted author's question is kept, so syncing stays idempotent, and is not
        // shown.
        store.set_peer_muted(&pid, true).unwrap();
        let muted = question(2, &circle, "*", "Should we use yarn?", now);
        assert_eq!(ingest(&store, &muted, None, now).unwrap(), Ingest::Stored);
        assert_eq!(
            store.question(&id_of(&muted)).unwrap().unwrap().status,
            QuestionStatus::Muted
        );
        assert_eq!(store.inbox(&[QuestionStatus::New]).unwrap().len(), 1);

        // A blocked author's question is not stored at all.
        store.set_peer_blocked(&pid, true).unwrap();
        let blocked = question(2, &circle, "*", "Should we use bun?", now);
        assert_eq!(
            ingest(&store, &blocked, None, now).unwrap(),
            Ingest::Rejected("blocked")
        );
        assert!(!store.has_event(&id_of(&blocked)).unwrap());
        store.set_peer_blocked(&pid, false).unwrap();
        store.set_peer_muted(&pid, false).unwrap();

        // Over the daily quota per author, questions are kept and not shown.
        for i in 0..25 {
            let raw = question(2, &circle, "*", &format!("Is option number {i} fine?"), now);
            assert_eq!(ingest(&store, &raw, None, now).unwrap(), Ingest::Stored);
        }
        let shown = store.inbox(&[QuestionStatus::New]).unwrap().len();
        assert!(
            shown <= 20,
            "{shown} questions shown from one author in a day"
        );
        // What this node's own owner asks is never held back.
        let mine = question(1, &circle, "*", "Should we pin the toolchain?", now);
        assert_eq!(ingest(&store, &mine, None, now).unwrap(), Ingest::Stored);
        let row = store.question(&id_of(&mine)).unwrap().unwrap();
        assert!(row.is_local && row.status == QuestionStatus::New);
    }

    fn adopt(store: &Store, circle: &CircleId, scope: &str, now: Timestamp) -> ProposalView {
        propose(
            store,
            &key(1),
            circle,
            NewProposal {
                scope: &Scope::new(scope).unwrap(),
                title: "Use pnpm",
                summary: "",
                action: ph_protocol::ProposalAction::Adopt(ph_protocol::AdoptAction {
                    skill_name: "pnpm".into(),
                    description: "Use pnpm, not npm.".into(),
                    bundle_digest: Digest::sha256(b"bundle"),
                    bundle_size: 10,
                    related_question: None,
                    supersedes: None,
                }),
            },
            now,
        )
        .unwrap()
    }

    fn stance(
        seed: u8,
        circle: &CircleId,
        scope: &str,
        proposal: EventId,
        charter: Digest,
        stance: ph_protocol::Stance,
        at: Timestamp,
    ) -> Vec<u8> {
        EnvelopeBuilder::new(
            *circle,
            Scope::new(scope).unwrap(),
            EventBody::Stance(ph_protocol::StanceBody {
                proposal_id: proposal,
                charter,
                stance,
                reason: Some("Our CI images only ship npm.".into()),
            }),
        )
        .created_at(at)
        .sign(&key(seed), at)
        .unwrap()
        .to_canonical_json()
        .unwrap()
        .into_bytes()
    }

    #[test]
    fn a_stance_is_a_record_by_a_member_of_the_roll_and_counts_for_nothing() {
        use ph_protocol::Stance::{Following, OptedOut};
        let (store, circle, now) = node();
        let charter = current_charter(&store, &circle).unwrap().digest().unwrap();
        let wide = adopt(&store, &circle, "*", now);
        let backend = adopt(&store, &circle, "team/backend", now);
        cast_vote(&store, &key(1), &wide, VoteDecision::Approve, None, now).unwrap();
        cast_vote(&store, &key(2), &wide, VoteDecision::Approve, None, now).unwrap();
        let (_, before) = count(&store, &wide).unwrap();
        assert!(before.passed());

        // Bob, who approved, records that he does not follow the rule on his machine.
        let out = stance(2, &circle, "*", wide.event_id(), charter, OptedOut, now);
        assert_eq!(ingest(&store, &out, None, now).unwrap(), Ingest::Stored);
        let recorded = stances(&store, &circle, &wide.event_id(), &device(1)).unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            (recorded[0].member.as_str(), recorded[0].stance),
            ("bob", OptedOut)
        );
        assert!(!recorded[0].mine);
        // Nothing is counted from it: his approval stands and the rule is in force.
        let (_, after) = count(&store, &wide).unwrap();
        assert_eq!(after.approvals().len(), before.approvals().len());
        assert!(after.passed());
        assert!(rule_set(&store, &circle).unwrap().1.get("pnpm").is_some());
        // His later stance replaces the earlier one.
        let back = stance(
            2,
            &circle,
            "*",
            wide.event_id(),
            charter,
            Following,
            now.plus_secs(60),
        );
        assert_eq!(
            ingest(&store, &back, None, now.plus_secs(60)).unwrap(),
            Ingest::Stored
        );
        let recorded = stances(&store, &circle, &wide.event_id(), &device(2)).unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].stance, Following);
        assert!(recorded[0].mine);

        // Not from a device that is on no roll, and not about a rule outside the scopes
        // the roll gives the member. (A rule with scope `*` concerns every member.)
        let forged = stance(9, &circle, "*", wide.event_id(), charter, OptedOut, now);
        assert_eq!(
            ingest(&store, &forged, None, now).unwrap(),
            Ingest::Rejected("not_on_roll")
        );
        let finance = adopt(&store, &circle, "team/finance", now);
        let outside = stance(
            3,
            &circle,
            "team/finance",
            finance.event_id(),
            charter,
            OptedOut,
            now,
        );
        assert_eq!(
            ingest(&store, &outside, None, now).unwrap(),
            Ingest::Rejected("not_in_electorate")
        );
        let inside = stance(
            3,
            &circle,
            "team/backend",
            backend.event_id(),
            charter,
            OptedOut,
            now,
        );
        assert_eq!(ingest(&store, &inside, None, now).unwrap(), Ingest::Stored);
        let everyone = stance(3, &circle, "*", wide.event_id(), charter, OptedOut, now);
        assert_eq!(
            ingest(&store, &everyone, None, now).unwrap(),
            Ingest::Stored
        );
        // Its scope is the rule's scope, it is about a rule, and it waits for the
        // records it names.
        let wrong_scope = stance(
            2,
            &circle,
            "team/backend",
            wide.event_id(),
            charter,
            OptedOut,
            now,
        );
        assert_eq!(
            ingest(&store, &wrong_scope, None, now).unwrap(),
            Ingest::Rejected("bad_reference")
        );
        let (current, rules, _) = rule_set(&store, &circle).unwrap();
        let next = ph_governance::remove_member(&current.content, &rules, "carol").unwrap();
        let amendment = propose(
            &store,
            &key(1),
            &circle,
            NewProposal {
                scope: &Scope::all(),
                title: "Remove carol",
                summary: "",
                action: ph_protocol::ProposalAction::Amend { next },
            },
            now,
        )
        .unwrap();
        let not_a_rule = stance(
            2,
            &circle,
            "*",
            amendment.event_id(),
            charter,
            OptedOut,
            now,
        );
        assert_eq!(
            ingest(&store, &not_a_rule, None, now).unwrap(),
            Ingest::Rejected("bad_reference")
        );
        let unknown = EventId::from_digest(Digest::sha256(b"no such proposal"));
        let early = stance(2, &circle, "*", unknown, charter, OptedOut, now);
        assert_eq!(
            ingest(&store, &early, None, now).unwrap(),
            Ingest::Deferred("missing_proposal")
        );
        let other_charter = stance(
            2,
            &circle,
            "*",
            wide.event_id(),
            Digest::sha256(b"c"),
            OptedOut,
            now,
        );
        assert_eq!(
            ingest(&store, &other_charter, None, now).unwrap(),
            Ingest::Deferred("unknown_charter")
        );
        // A revoked device's stance is refused, and what it recorded is no longer shown.
        let authority = CircleAuthority::from_signing_key(key(100));
        let revocation = authority.issue_revocation(device(2), "", now).unwrap();
        store.insert_revocation(&revocation, now).unwrap();
        let late = stance(
            2,
            &circle,
            "*",
            wide.event_id(),
            charter,
            OptedOut,
            now.plus_secs(120),
        );
        assert_eq!(
            ingest(&store, &late, None, now.plus_secs(120)).unwrap(),
            Ingest::Rejected("revoked")
        );
        let left: Vec<String> = stances(&store, &circle, &wide.event_id(), &device(1))
            .unwrap()
            .into_iter()
            .map(|s| s.member)
            .collect();
        assert_eq!(left, ["carol"]);
    }
}
