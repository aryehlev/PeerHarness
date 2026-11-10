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
    authorize_incoming, check_repeal_reference, check_successor, check_supersedes_reference,
    rules_in_force, tally, verify_result, DecisionRecords, Passed, ProposalView, Reference,
    ResultView, RuleSet, Tally, VoteView,
};
use ph_identity::CircleAuthority;
use ph_protocol::{
    validate_stateless, Charter, CharterBody, CharterContent, EnvelopeBuilder, EventBody,
    EventType, ProposalBody, ProposalKind, ResultBody, RollEntry, SignedEnvelope, SigningKey,
    VerifiedEnvelope, VoteBody, VoteDecision,
};
use ph_skills::{Bundle, BundleStore};
use ph_store::{BundleRow, CircleRow, InsertOutcome, Store};
use serde_json::{json, Value};

use crate::events::build_registry;

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
    let registry = build_registry(store, now)?;
    let known = |c: &CircleId| store.circle(c).ok().flatten().is_some();
    if let Err(r) = authorize_incoming(&verified, &registry, &StoreRecords(store), &known, now) {
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
        EventBody::Question(_) | EventBody::Answer(_) | EventBody::Vote(_) => {}
    }
    Ok(stored(store.insert_event(&verified, origin_peer, now)?))
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
    if next.seq <= current.seq {
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
    use ph_skills::{InstallOptions, InstallState, SkillScope, UninstallOptions};

    use crate::installs;

    let id = &circle.circle_id;
    let (charter, rules, tallies) = rule_set(store, id)?;
    // A rule binds the members who were entitled to vote on it: those on the roll whose
    // scopes cover the rule's scope. A node outside that electorate (a member of another
    // team, or someone who was removed) installs nothing and keeps nothing the circle
    // had installed.
    let binds_me = |rule: &ph_governance::Rule| -> bool {
        charter
            .content
            .voter(me, &ph_protocol::Electorate::Scope(rule.scope()))
            .is_some()
    };
    let mode = match circle.adoption_mode.as_str() {
        "follow" => AdoptionMode::Follow,
        _ => AdoptionMode::Ask,
    };
    let mut applied = Applied::default();
    let managed_with = |name: &str, digest: &Digest| -> bool {
        matches!(
            installer.status(name),
            Ok(InstallState::Managed { digest: d, modified: false }) if d == *digest
        )
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
        match adoption_step(rule, mode, checks, choice, policy_ok) {
            AdoptionStep::Install => {
                if managed_with(&name, &rule.bundle_digest()) {
                    continue; // already in place
                }
                match installer.install(&bundle, InstallOptions::default()) {
                    Ok(outcome) => {
                        // Remember that the vote put it here, so a repeal removes it.
                        store.record_rule_install(id, &name, &rule.bundle_digest(), now)?;
                        installs::ensure_circle_skill(store, &bundle, &rule.proposal_id(), now)?;
                        installs::record_install(store, SkillScope::User, &bundle, &outcome, now)?;
                        applied.installed.push(name);
                    }
                    Err(_) => applied.conflicts.push(name),
                }
            }
            step @ AdoptionStep::AskOwner(_) => applied.asking.push((name, step.code())),
            step @ AdoptionStep::Refuse(_) => applied.refused.push((name, step.code())),
            AdoptionStep::OptedOut => {
                if managed_with(&name, &rule.bundle_digest()) {
                    if let Ok(gone) = installer.uninstall(&name, UninstallOptions::default()) {
                        installs::record_uninstall(
                            store,
                            SkillScope::User,
                            &name,
                            &gone.removed_digest,
                            &gone.path,
                            now,
                        )?;
                        applied.removed.push(name.clone());
                    }
                }
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
        if still_applies {
            continue;
        }
        if managed_with(&name, &digest) {
            if let Ok(gone) = installer.uninstall(&name, UninstallOptions::default()) {
                installs::record_uninstall(
                    store,
                    SkillScope::User,
                    &name,
                    &gone.removed_digest,
                    &gone.path,
                    now,
                )?;
                if !applied.removed.contains(&name) {
                    applied.removed.push(name.clone());
                }
            }
        }
        store.clear_rule_install(id, &name)?;
    }
    Ok(applied)
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
