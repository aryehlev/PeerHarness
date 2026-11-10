//! This node's side of the peer protocol (architecture section 7): answering a peer's
//! requests, and the pieces a sync with a peer is made of.
//!
//! Everything here is synchronous and works on the store, so it can be tested without a
//! network. `runtime` connects it to `ph-network`.
//!
//! # Who is answered
//!
//! The transport proves which device key is on the other end and nothing else. This
//! module decides what that key may have, from the **roll** of the current charter
//! (`ph_governance::RollOracle`, ADR-026), on every request:
//!
//! * `hello` is answered to anyone and says nothing about this node's circles;
//! * every other request from a device that is not an active member of the circle it
//!   concerns gets `error{unauthorized}`, the same answer whether the circle exists
//!   here or not;
//! * a member receives the events the read rules give it
//!   (`Store::missing_for_peer`, `ph_governance::may_fetch_bundle`): circle-wide
//!   decisions and control events, and scoped events only within its own scopes;
//! * events a peer pushes are accepted only for circles the pusher is a member of, and
//!   then each one goes through `governance::ingest` like any other event. Who pushed
//!   an event gives it no standing: it counts by its author and signature alone;
//! * a device that this node's own records show was on the roll, and was then taken off
//!   it by a vote, is told exactly that and nothing else (`farewell`, ADR-028): the
//!   charters up to the one that removed it, with the amendment, ballots and result
//!   behind each. It was entitled to every one of those records as a member, and the
//!   removing charter is word for word the amendment it could vote on. A revoked device
//!   is told nothing.

use std::collections::{BTreeSet, HashSet};

use anyhow::Result;
use ph_core::{CircleId, DeviceKey, Digest, EventId, MembershipOracle, Timestamp};
use ph_governance::{may_fetch_bundle, ProposalView, ResultView, RollOracle};
use ph_protocol::limits::{MAX_FETCH_LIMIT, MAX_KNOWN_IDS, MAX_PUSH_EVENTS, MAX_SHARED_CIRCLES};
use ph_protocol::wire::{ErrorCode, PushOutcome, PushStatus, Request, Response, WireFile};
use ph_protocol::{EventBody, EventType};
use ph_skills::BundleStore;
use ph_store::{EventFilter, MissingQuery, Store, StoredEvent, DEFAULT_SYNC_MAX_BYTES};
use serde_json::Value;

use crate::governance::{self, Ingest};

/// Most addresses remembered for a peer.
const MAX_PEER_ADDRS: usize = 8;

/// The roll-backed membership oracle for everything this node holds: the current
/// charter of each circle and every revocation it knows. Built per request.
pub fn roll_oracle(store: &Store) -> Result<RollOracle> {
    let mut oracle = RollOracle::new();
    for circle in store.circles()? {
        if let Some(charter) = store.current_charter(&circle.circle_id)? {
            oracle.set_charter(charter);
        }
        for r in store.revocations_for_circle(&circle.circle_id)? {
            oracle.revoke(circle.circle_id, r.subject_key);
        }
    }
    Ok(oracle)
}

/// The circles on this node in which `peer` is an active member.
fn circles_of(
    store: &Store,
    oracle: &RollOracle,
    peer: &DeviceKey,
    now: Timestamp,
) -> Result<Vec<CircleId>> {
    Ok(store
        .circles()?
        .into_iter()
        .map(|c| c.circle_id)
        .filter(|c| oracle.is_active_member(c, peer, now))
        .collect())
}

fn unauthorized() -> Response {
    Response::error(ErrorCode::Unauthorized)
}

/// What answering one request produced.
#[derive(Debug)]
pub struct Answer {
    /// The response to send.
    pub response: Response,
    /// Circles that received new events: they need `governance::settle`.
    pub touched: BTreeSet<CircleId>,
    /// Bundles this node now lacks for stored `adopt` proposals and should fetch from
    /// the peer that pushed them.
    pub pulls: Vec<(CircleId, Digest)>,
}

impl Answer {
    fn only(response: Response) -> Self {
        Self {
            response,
            touched: BTreeSet::new(),
            pulls: Vec::new(),
        }
    }
}

/// Answers `request` from the transport-authenticated device `peer`.
pub fn answer(
    store: &Store,
    bundles: &BundleStore,
    peer: &DeviceKey,
    peer_id: &str,
    request: Request,
    now: Timestamp,
) -> Result<Answer> {
    if matches!(request, Request::Hello { .. }) {
        return Ok(Answer::only(Response::hello()));
    }
    let oracle = roll_oracle(store)?;
    match request {
        Request::Hello { .. } => Ok(Answer::only(Response::hello())),
        Request::Authenticate { listen_addrs, .. } => {
            // Membership is the roll, so there is nothing to prove with a credential.
            // The request still serves to announce where the peer can be reached.
            let mut circles = circles_of(store, &oracle, peer, now)?;
            if circles.is_empty() {
                return Ok(Answer::only(unauthorized()));
            }
            // The peer is remembered as a member seen here. Where it says it listens is
            // not stored: a node dials only addresses its own owner gave it, so a member
            // cannot point another member's node at an address of its choosing.
            let _ = listen_addrs;
            remember_peer(store, peer_id, peer, &[], &circles, now)?;
            // The peer is on these rolls, so it may know that this node holds them. A
            // device that was just admitted learns here which circle to fetch.
            circles.truncate(MAX_SHARED_CIRCLES);
            Ok(Answer::only(Response::Authenticated {
                memberships: Vec::new(),
                circles,
            }))
        }
        Request::PushEvents { events } => {
            let circles: HashSet<CircleId> =
                circles_of(store, &oracle, peer, now)?.into_iter().collect();
            if circles.is_empty() {
                return Ok(Answer::only(unauthorized()));
            }
            let ingested = ingest_values(store, &events, Some(&circles), Some(peer_id), now)?;
            let mut pulls = Vec::new();
            for circle in &ingested.touched {
                for digest in missing_bundles(store, bundles, circle)? {
                    pulls.push((*circle, digest));
                }
            }
            Ok(Answer {
                response: Response::PushResult {
                    results: ingested.outcomes,
                },
                touched: ingested.touched,
                pulls,
            })
        }
        Request::FetchEvents {
            circle_id,
            known,
            limit,
            after,
        } => {
            let known: HashSet<EventId> = known.into_iter().collect();
            if !oracle.is_active_member(&circle_id, peer, now) {
                // Not a member. A device that used to be one and was voted off is told
                // of that; everyone else gets the answer a stranger gets.
                return Ok(Answer::only(
                    match farewell(store, &oracle, &circle_id, peer, &known, limit as usize)? {
                        Some((events, more)) => Response::Events { events, more },
                        None => unauthorized(),
                    },
                ));
            }
            let query = MissingQuery::new(&circle_id, &known, now)
                .with_limit(limit as usize)
                .after(after.as_ref());
            let missing = store.missing_for_peer(&query, |scope| {
                oracle.authorize_read(&circle_id, peer, scope, now).is_ok()
            })?;
            let mut events = Vec::with_capacity(missing.events.len());
            for ev in &missing.events {
                events.push(ev.to_value()?);
            }
            Ok(Answer::only(Response::Events {
                events,
                more: missing.more,
            }))
        }
        Request::FetchBundle { circle_id, digest } => {
            if !oracle.is_active_member(&circle_id, peer, now) {
                return Ok(Answer::only(unauthorized()));
            }
            let proposals: Vec<ProposalView> = store
                .proposals_with_bundle(&circle_id, &digest)?
                .iter()
                .filter_map(|ev| ev.envelope().ok())
                .filter_map(|env| ProposalView::from_envelope(&env).ok())
                .collect();
            // No readable proposal names it: the same answer as for a stranger.
            if !may_fetch_bundle(&circle_id, &digest, &proposals, peer, &oracle, now) {
                return Ok(Answer::only(unauthorized()));
            }
            Ok(Answer::only(match bundles.get(&digest) {
                Ok(bundle) => Response::Bundle {
                    digest,
                    files: bundle.to_wire_files(),
                },
                Err(_) => Response::error(ErrorCode::Unavailable),
            }))
        }
    }
}

/// What a device that is no longer a member of `circle` may still be told: how it came
/// off the roll. `None` for a device this node never knew as a member, and for a
/// revoked one.
///
/// The answer holds the CHARTER events up to the first charter without the device,
/// each preceded by the amendment that justifies it, that amendment's ballots and its
/// result, without what the device says it already has. Nothing of what the circle did
/// afterwards is in it: no later charter, so no later roll, and no rule proposal.
fn farewell(
    store: &Store,
    oracle: &RollOracle,
    circle: &CircleId,
    device: &DeviceKey,
    known: &HashSet<EventId>,
    limit: usize,
) -> Result<Option<(Vec<Value>, bool)>> {
    if oracle.is_revoked(circle, device) {
        return Ok(None);
    }
    let charters = store.charters(circle)?;
    let Some(last_listed) = charters
        .iter()
        .filter(|c| c.content.member_of(device).is_some())
        .map(|c| c.seq)
        .max()
    else {
        return Ok(None);
    };
    let Some(removed_at) = last_listed.checked_add(1) else {
        return Ok(None);
    };
    // CHARTER events by the digest of the charter they carry.
    let charter_events = store.list_events(
        circle,
        &EventFilter {
            types: &[EventType::Charter],
            ..EventFilter::default()
        },
    )?;
    let event_of = |digest: &Digest| -> Option<&StoredEvent> {
        charter_events.iter().find(|ev| {
            ev.envelope().ok().is_some_and(|env| {
                matches!(&env.body, EventBody::Charter(b) if b.charter.digest().ok().as_ref() == Some(digest))
            })
        })
    };
    let mut chain: Vec<StoredEvent> = Vec::new();
    for charter in charters.iter().filter(|c| c.seq <= removed_at) {
        if let Some(result_id) = &charter.justification {
            if let Some(result) = store.event(result_id)? {
                let view = result
                    .envelope()
                    .ok()
                    .and_then(|env| ResultView::from_envelope(&env).ok());
                if let Some(view) = view {
                    chain.extend(store.event(&view.proposal_id())?);
                    chain.extend(store.votes_for_proposal(&view.proposal_id())?);
                }
                chain.push(result);
            }
        }
        if let Some(ev) = event_of(&charter.digest()?) {
            chain.push(ev.clone());
        }
    }
    // Bounded like any other answer: by the requester's limit and by what fits a frame.
    // What does not fit is asked for again, with what was received listed as known.
    let limit = limit.clamp(1, MAX_FETCH_LIMIT as usize);
    let mut events = Vec::new();
    let mut more = false;
    let mut bytes = 0usize;
    let mut seen = HashSet::new();
    for ev in chain {
        if known.contains(&ev.event_id) || !seen.insert(ev.event_id) {
            continue;
        }
        let size = ev.envelope_json.len() + 1;
        if events.len() >= limit
            || (!events.is_empty() && bytes.saturating_add(size) > DEFAULT_SYNC_MAX_BYTES)
        {
            more = true;
            break;
        }
        bytes = bytes.saturating_add(size);
        events.push(ev.to_value()?);
    }
    Ok(Some((events, more)))
}

/// Stores where `peer` can be reached and which circles it shares with this node.
pub fn remember_peer(
    store: &Store,
    peer_id: &str,
    peer: &DeviceKey,
    addrs: &[String],
    circles: &[CircleId],
    now: Timestamp,
) -> Result<()> {
    let addrs: Vec<String> = addrs
        .iter()
        .filter(|a| a.parse::<ph_network::Multiaddr>().is_ok())
        .take(MAX_PEER_ADDRS)
        .cloned()
        .collect();
    store.upsert_peer(peer_id, peer, &addrs, now)?;
    for circle in circles {
        store.add_peer_circle(peer_id, circle)?;
    }
    store.touch_peer_last_seen(peer_id, now)?;
    Ok(())
}

/// The result of taking in a batch of events.
#[derive(Debug, Default)]
pub struct Ingested {
    /// One outcome per offered event, in order.
    pub outcomes: Vec<PushOutcome>,
    /// How many were new and stored.
    pub stored: usize,
    /// Circles that received new events.
    pub touched: BTreeSet<CircleId>,
    /// Indexes of the offered events that could not be placed yet: nothing is wrong
    /// with them, this node lacks a record they depend on. They are reported to a peer
    /// as rejected; a sync keeps them and offers them again with the next batch.
    pub deferred: Vec<usize>,
}

/// A string member of an unverified event, parsed.
pub fn field<T: std::str::FromStr>(value: &Value, name: &str) -> Option<T> {
    value.get(name)?.as_str()?.parse().ok()
}

/// Verifies and stores a batch of events through `governance::ingest`.
///
/// With `allowed`, an event of any other circle is refused before it is looked at
/// further. Events that depend on one another may come in any order: those that cannot
/// be placed yet are tried again while the batch still makes progress, and what is left
/// is reported as rejected (no reason is ever given to the peer).
pub fn ingest_values(
    store: &Store,
    events: &[Value],
    allowed: Option<&HashSet<CircleId>>,
    origin_peer: Option<&str>,
    now: Timestamp,
) -> Result<Ingested> {
    let mut status: Vec<Option<PushStatus>> = vec![None; events.len()];
    let mut out = Ingested::default();
    loop {
        let mut progress = false;
        for (i, value) in events.iter().enumerate() {
            if status[i].is_some() {
                continue;
            }
            let circle: Option<CircleId> = field(value, "circle_id");
            let permitted = match (allowed, &circle) {
                (Some(set), Some(c)) => set.contains(c),
                (Some(_), None) => false,
                (None, _) => true,
            };
            if !permitted {
                status[i] = Some(PushStatus::Rejected);
                continue;
            }
            match governance::ingest(store, value.to_string().as_bytes(), origin_peer, now)? {
                Ingest::Stored => {
                    status[i] = Some(PushStatus::Accepted);
                    out.stored += 1;
                    if let Some(c) = circle {
                        out.touched.insert(c);
                    }
                    progress = true;
                }
                Ingest::Duplicate => status[i] = Some(PushStatus::Duplicate),
                Ingest::Rejected(_) => status[i] = Some(PushStatus::Rejected),
                Ingest::Deferred(_) => {}
            }
        }
        if !progress {
            break;
        }
    }
    out.deferred = status
        .iter()
        .enumerate()
        .filter_map(|(i, s)| s.is_none().then_some(i))
        .collect();
    out.outcomes = events
        .iter()
        .zip(status)
        .map(|(value, s)| PushOutcome {
            event_id: field(value, "event_id"),
            status: s.unwrap_or(PushStatus::Rejected),
        })
        .collect();
    Ok(out)
}

/// Digests of the bundles that stored `adopt` proposals of `circle` name and this node
/// does not hold, without duplicates.
pub fn missing_bundles(
    store: &Store,
    bundles: &BundleStore,
    circle: &CircleId,
) -> Result<Vec<Digest>> {
    let mut seen = BTreeSet::new();
    for ev in store.proposals(circle)? {
        if let Some(d) = ev.bundle_digest {
            if !bundles.contains(&d) {
                seen.insert(d);
            }
        }
    }
    Ok(seen.into_iter().collect())
}

/// Validates a bundle a peer sent for `digest` and stores it. Only a bundle that a
/// stored `adopt` proposal of `circle` names is of any interest; anything else, and
/// anything that does not match the digest or is not an instruction-only skill, is
/// dropped. Returns whether it was stored.
pub fn store_bundle(
    store: &Store,
    bundles: &BundleStore,
    circle: &CircleId,
    digest: &Digest,
    files: &[WireFile],
    now: Timestamp,
) -> Result<bool> {
    if bundles.contains(digest) {
        return Ok(false);
    }
    let name = store
        .proposals_with_bundle(circle, digest)?
        .iter()
        .filter_map(|ev| ev.envelope().ok())
        .filter_map(|env| ProposalView::from_envelope(&env).ok())
        .find_map(|p| p.skill_name().map(str::to_owned));
    let Some(name) = name else {
        return Ok(false);
    };
    match ph_skills::from_wire_files(files, digest, Some(&name)) {
        Ok(bundle) => {
            governance::record_bundle(store, bundles, &bundle, now)?;
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

/// The ids this node sends as `known` in `fetch_events`: its newest events of the
/// circle, at most the protocol's limit.
pub fn known_ids(store: &Store, circle: &CircleId, now: Timestamp) -> Result<Vec<EventId>> {
    let mut ids = store.event_ids_for_circle(circle, now)?;
    if ids.len() > MAX_KNOWN_IDS {
        ids.drain(..ids.len() - MAX_KNOWN_IDS);
    }
    Ok(ids)
}

/// What a push to one peer consists of.
#[derive(Debug, Default)]
pub struct Outgoing {
    /// Batches that each fit one `push_events` request, in the order this node stored
    /// the events.
    pub batches: Vec<Vec<Value>>,
    /// The last event of this node's log that was considered, sent or not. When the
    /// peer has taken every batch, the next push starts after it.
    pub last_seen: Option<EventId>,
}

/// What `peer` may read of `circle` on this node and has not been pushed yet: the
/// events stored after `after` (the push cursor for that peer, `None` for everything).
/// Empty when `peer` is not an active member.
pub fn outgoing_batches(
    store: &Store,
    circle: &CircleId,
    peer: &DeviceKey,
    after: Option<&EventId>,
    now: Timestamp,
) -> Result<Outgoing> {
    let oracle = roll_oracle(store)?;
    let mut out = Outgoing::default();
    if !oracle.is_active_member(circle, peer, now) {
        return Ok(out);
    }
    let none = HashSet::new();
    let mut cursor = after.copied();
    loop {
        let query = MissingQuery::new(circle, &none, now)
            .with_limit(MAX_PUSH_EVENTS)
            .after(cursor.as_ref());
        let missing = store.missing_for_peer(&query, |scope| {
            oracle.authorize_read(circle, peer, scope, now).is_ok()
        })?;
        if missing.last_seen.is_some() {
            out.last_seen = missing.last_seen;
        }
        let Some(last) = missing.events.last().map(|ev| ev.event_id) else {
            break;
        };
        let mut batch = Vec::with_capacity(missing.events.len());
        for ev in &missing.events {
            batch.push(ev.to_value()?);
        }
        out.batches.push(batch);
        if !missing.more {
            break;
        }
        cursor = Some(last);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ph_core::Scope;
    use ph_identity::CircleAuthority;
    use ph_protocol::{
        AdoptAction, CharterContent, ProposalAction, RollEntry, SigningKey, VoteDecision,
    };
    use ph_store::CircleRow;
    use serde_json::Value;

    use crate::governance::NewProposal;

    const SKILL_MD: &str = "---\nname: pnpm\ndescription: Use pnpm, not npm.\n---\n\nUse pnpm.\n";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn device(seed: u8) -> DeviceKey {
        DeviceKey::from_signing_key(&key(seed))
    }
    fn pid(seed: u8) -> String {
        ph_network::peer_id_from_device_key(&device(seed)).to_string()
    }

    /// A node holding a circle whose roll is alice (1, every scope), bob (2, every
    /// scope) and carol (3, only `team/backend`), with one circle-wide rule proposal,
    /// one proposal scoped to `team/finance`, and their bundles.
    struct Fixture {
        _tmp: tempfile::TempDir,
        store: Store,
        bundles: BundleStore,
        circle: CircleId,
        wide: ProposalView,
        finance: ProposalView,
        digest: Digest,
        now: Timestamp,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Store::open_in_memory().unwrap();
        let bundles = BundleStore::new(tmp.path().join("bundles"));
        let now = Timestamp::now();
        let authority = CircleAuthority::from_signing_key(key(100));
        let circle = authority.circle_id();
        // The founding charter already lists all three, as a founder could write it.
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

        let bundle = ph_skills::build_bundle(SKILL_MD, Some("pnpm")).unwrap();
        governance::record_bundle(&store, &bundles, &bundle, now).unwrap();
        let adopt = |scope: &str| {
            governance::propose(
                &store,
                &key(1),
                &circle,
                NewProposal {
                    scope: &Scope::new(scope).unwrap(),
                    title: "Use pnpm",
                    summary: "",
                    action: ProposalAction::Adopt(AdoptAction {
                        skill_name: "pnpm".into(),
                        description: bundle.description().to_owned(),
                        bundle_digest: bundle.digest(),
                        bundle_size: bundle.size(),
                        related_question: None,
                        supersedes: None,
                    }),
                },
                now,
            )
            .unwrap()
        };
        let wide = adopt("*");
        let finance = adopt("team/finance");
        governance::cast_vote(&store, &key(1), &wide, VoteDecision::Approve, None, now).unwrap();
        Fixture {
            _tmp: tmp,
            store,
            bundles,
            circle,
            wide,
            finance,
            digest: bundle.digest(),
            now,
        }
    }

    fn ask(f: &Fixture, seed: u8, request: Request) -> Answer {
        answer(
            &f.store,
            &f.bundles,
            &device(seed),
            &pid(seed),
            request,
            f.now,
        )
        .unwrap()
    }

    fn fetch(f: &Fixture, seed: u8, circle: CircleId) -> Response {
        ask(
            f,
            seed,
            Request::FetchEvents {
                circle_id: circle,
                known: Vec::new(),
                limit: 256,
                after: None,
            },
        )
        .response
    }

    fn ids(response: &Response) -> Vec<String> {
        let Response::Events { events, .. } = response else {
            panic!("expected events, got {response:?}");
        };
        events
            .iter()
            .map(|e| e["event_id"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn a_stranger_gets_hello_and_nothing_else() {
        let f = fixture();
        let stranger = 9;
        assert_eq!(
            ask(&f, stranger, Request::hello()).response,
            Response::hello()
        );
        let other_circle = CircleId::derive(&device(55));
        let denied = Response::error(ErrorCode::Unauthorized);
        // The answer is the same for a circle that exists here and one that does not,
        // for a bundle that exists and one that does not.
        for request in [
            Request::FetchEvents {
                circle_id: f.circle,
                known: Vec::new(),
                limit: 10,
                after: None,
            },
            Request::FetchEvents {
                circle_id: other_circle,
                known: Vec::new(),
                limit: 10,
                after: None,
            },
            Request::FetchBundle {
                circle_id: f.circle,
                digest: f.digest,
            },
            Request::FetchBundle {
                circle_id: f.circle,
                digest: Digest::sha256(b"no such bundle"),
            },
            Request::Authenticate {
                memberships: Vec::new(),
                listen_addrs: vec!["/ip4/127.0.0.1/udp/4001/quic-v1".into()],
            },
            Request::PushEvents {
                events: vec![f.wide.envelope().to_value().unwrap()],
            },
        ] {
            let a = ask(&f, stranger, request);
            assert_eq!(a.response, denied);
            assert!(a.touched.is_empty() && a.pulls.is_empty());
        }
        // Nothing about the stranger was stored.
        assert!(f.store.peers().unwrap().is_empty());
        // A member asking about a circle this node does not hold gets the same answer.
        assert_eq!(fetch(&f, 1, other_circle), denied);
    }

    #[test]
    fn a_member_reads_within_its_scopes() {
        let f = fixture();
        let wide = f.wide.event_id().to_string();
        let finance = f.finance.event_id().to_string();
        // bob has every scope: both proposals, the ballot and the charter.
        let bob = ids(&fetch(&f, 2, f.circle));
        assert!(bob.contains(&wide) && bob.contains(&finance));
        assert_eq!(bob.len(), 3, "two proposals and one ballot");
        // carol has only team/backend: the circle-wide proposal and its ballot reach
        // her, the finance proposal does not.
        let carol = ids(&fetch(&f, 3, f.circle));
        assert!(carol.contains(&wide));
        assert!(!carol.contains(&finance));
        assert_eq!(carol.len(), 2);
        // What the peer says it has is not sent again.
        let again = ask(
            &f,
            2,
            Request::FetchEvents {
                circle_id: f.circle,
                known: vec![f.wide.event_id()],
                limit: 256,
                after: None,
            },
        );
        assert!(!ids(&again.response).contains(&wide));
        // The bundle is named by a proposal carol may read, so she may fetch it.
        let got = ask(
            &f,
            3,
            Request::FetchBundle {
                circle_id: f.circle,
                digest: f.digest,
            },
        );
        assert!(matches!(got.response, Response::Bundle { digest, .. } if digest == f.digest));
        // Announcing makes the member known here. The addresses it claims are not kept:
        // this node dials only addresses its own owner gave it.
        let a = ask(
            &f,
            2,
            Request::Authenticate {
                memberships: Vec::new(),
                listen_addrs: vec![
                    "/ip4/127.0.0.1/udp/4001/quic-v1".into(),
                    "not an address".into(),
                ],
            },
        );
        assert_eq!(
            a.response,
            Response::Authenticated {
                memberships: Vec::new(),
                circles: vec![f.circle],
            }
        );
        let peer = f.store.peer(&pid(2)).unwrap().unwrap();
        assert!(peer.addrs.is_empty());
        assert_eq!(peer.circles, [f.circle]);
        // An address the owner dialed earlier is not replaced by an announcement.
        remember_peer(
            &f.store,
            &pid(2),
            &device(2),
            &["/ip4/192.0.2.7/udp/4001/quic-v1".to_owned()],
            &[f.circle],
            f.now,
        )
        .unwrap();
        ask(
            &f,
            2,
            Request::Authenticate {
                memberships: Vec::new(),
                listen_addrs: vec!["/ip4/203.0.113.9/udp/1/quic-v1".into()],
            },
        );
        assert_eq!(
            f.store.peer(&pid(2)).unwrap().unwrap().addrs,
            ["/ip4/192.0.2.7/udp/4001/quic-v1"]
        );
    }

    #[test]
    fn a_revoked_device_is_a_stranger_at_once() {
        let f = fixture();
        assert!(matches!(fetch(&f, 2, f.circle), Response::Events { .. }));
        let authority = CircleAuthority::from_signing_key(key(100));
        let revocation = authority.issue_revocation(device(2), "", f.now).unwrap();
        f.store.insert_revocation(&revocation, f.now).unwrap();
        assert_eq!(
            fetch(&f, 2, f.circle),
            Response::error(ErrorCode::Unauthorized)
        );
        assert!(
            outgoing_batches(&f.store, &f.circle, &device(2), None, f.now)
                .unwrap()
                .batches
                .is_empty()
        );
    }

    #[test]
    fn pushed_events_count_by_their_author_not_by_who_pushed_them() {
        let f = fixture();
        // A second node that has only the charter: bob's.
        let tmp = tempfile::TempDir::new().unwrap();
        let theirs = Store::open_in_memory().unwrap();
        let their_bundles = BundleStore::new(tmp.path().join("bundles"));
        let circle_row = f.store.circle(&f.circle).unwrap().unwrap();
        theirs
            .insert_circle(&CircleRow {
                is_founder: false,
                ..circle_row
            })
            .unwrap();
        theirs
            .insert_charter(&f.store.current_charter(&f.circle).unwrap().unwrap(), f.now)
            .unwrap();

        // Alice's node sends bob's node everything bob may read, ballot before proposal.
        let mut batch: Vec<Value> = outgoing_batches(&f.store, &f.circle, &device(2), None, f.now)
            .unwrap()
            .batches
            .concat();
        batch.reverse();
        let pushed = answer(
            &theirs,
            &their_bundles,
            &device(1),
            &pid(1),
            Request::PushEvents {
                events: batch.clone(),
            },
            f.now,
        )
        .unwrap();
        let Response::PushResult { results } = &pushed.response else {
            panic!("expected a push result");
        };
        assert_eq!(results.len(), batch.len());
        assert!(results.iter().all(|r| r.status == PushStatus::Accepted));
        assert_eq!(pushed.touched.into_iter().collect::<Vec<_>>(), [f.circle]);
        // The receiving node now lacks the bundle the proposals name and will pull it.
        assert_eq!(pushed.pulls, [(f.circle, f.digest)]);

        // The same push again: all known.
        let again = answer(
            &theirs,
            &their_bundles,
            &device(1),
            &pid(1),
            Request::PushEvents { events: batch },
            f.now,
        )
        .unwrap();
        let Response::PushResult { results } = &again.response else {
            panic!("expected a push result");
        };
        assert!(results.iter().all(|r| r.status == PushStatus::Duplicate));
        assert!(again.touched.is_empty());

        // A ballot signed by a device that is not on the roll is refused, whoever
        // carries it: a member pushing it gives it no standing.
        let stranger_ballot = ph_protocol::EnvelopeBuilder::new(
            f.circle,
            Scope::all(),
            ph_protocol::EventBody::Vote(ph_protocol::VoteBody {
                proposal_id: f.wide.event_id(),
                decision: VoteDecision::Approve,
                rationale: None,
            }),
        )
        .sign(&key(9), f.now)
        .unwrap();
        let refused = answer(
            &theirs,
            &their_bundles,
            &device(1),
            &pid(1),
            Request::PushEvents {
                events: vec![stranger_ballot.to_value().unwrap()],
            },
            f.now,
        )
        .unwrap();
        let Response::PushResult { results } = &refused.response else {
            panic!("expected a push result");
        };
        assert_eq!(results[0].status, PushStatus::Rejected);
        assert_eq!(results[0].event_id, Some(stranger_ballot.event_id));
        let (_, tally) = governance::count(&theirs, &f.wide).unwrap();
        assert_eq!(tally.approvals().len(), 1, "only alice's ballot counts");

        // An altered event and an event of a circle the pusher is not in are refused.
        let mut altered = f.wide.envelope().to_value().unwrap();
        altered["body"]["title"] = Value::String("Use yarn".into());
        let mut foreign = f.finance.envelope().to_value().unwrap();
        foreign["circle_id"] = Value::String(CircleId::derive(&device(55)).to_string());
        let refused = answer(
            &Store::open_in_memory().unwrap(),
            &their_bundles,
            &device(1),
            &pid(1),
            Request::PushEvents {
                events: vec![altered.clone()],
            },
            f.now,
        )
        .unwrap();
        assert_eq!(refused.response, Response::error(ErrorCode::Unauthorized));
        let refused = answer(
            &theirs,
            &their_bundles,
            &device(1),
            &pid(1),
            Request::PushEvents {
                events: vec![altered, foreign],
            },
            f.now,
        )
        .unwrap();
        let Response::PushResult { results } = &refused.response else {
            panic!("expected a push result");
        };
        assert!(results.iter().all(|r| r.status == PushStatus::Rejected));

        // The bundle arrives over the wire and is checked against the voted digest.
        let Response::Bundle { files, .. } = ask(
            &f,
            2,
            Request::FetchBundle {
                circle_id: f.circle,
                digest: f.digest,
            },
        )
        .response
        else {
            panic!("expected the bundle");
        };
        let tampered = vec![WireFile::new(
            "SKILL.md",
            SKILL_MD.replace("pnpm", "yarn").as_bytes(),
        )];
        assert!(!store_bundle(
            &theirs,
            &their_bundles,
            &f.circle,
            &f.digest,
            &tampered,
            f.now
        )
        .unwrap());
        assert!(
            store_bundle(&theirs, &their_bundles, &f.circle, &f.digest, &files, f.now).unwrap()
        );
        assert!(their_bundles.contains(&f.digest));
        assert!(missing_bundles(&theirs, &their_bundles, &f.circle)
            .unwrap()
            .is_empty());
        // A bundle no stored proposal names is not kept.
        let stray = ph_skills::build_bundle(
            "---\nname: stray\ndescription: Stray.\n---\n\nStray.\n",
            Some("stray"),
        )
        .unwrap();
        assert!(!store_bundle(
            &theirs,
            &their_bundles,
            &f.circle,
            &stray.digest(),
            &stray.to_wire_files(),
            f.now
        )
        .unwrap());
    }

    /// The syncing side of `fetch_events` without a network: pages through `theirs` as
    /// device `seed` from `after`, storing into `mine`. Returns the rounds it took, the
    /// events stored and the cursor reached.
    fn fetch_all(
        theirs: &Fixture,
        mine: &Store,
        seed: u8,
        mut after: Option<EventId>,
    ) -> (usize, usize, Option<EventId>) {
        let only: HashSet<CircleId> = [theirs.circle].into();
        let (mut rounds, mut stored) = (0, 0);
        loop {
            rounds += 1;
            assert!(rounds < 100, "the fetch does not terminate");
            let response = ask(
                theirs,
                seed,
                Request::FetchEvents {
                    circle_id: theirs.circle,
                    known: known_ids(mine, &theirs.circle, theirs.now).unwrap(),
                    limit: 256,
                    after,
                },
            )
            .response;
            let Response::Events { events, more } = response else {
                panic!("expected events, got {response:?}");
            };
            let Some(last) = events.last().and_then(|v| field::<EventId>(v, "event_id")) else {
                break;
            };
            let got = ingest_values(mine, &events, Some(&only), None, theirs.now).unwrap();
            assert!(got.deferred.is_empty());
            stored += got.stored;
            after = Some(last);
            if !more {
                break;
            }
        }
        (rounds, stored, after)
    }

    /// A second node of the same circle that so far holds only the charter.
    fn second_node(f: &Fixture) -> Store {
        let store = Store::open_in_memory().unwrap();
        let row = f.store.circle(&f.circle).unwrap().unwrap();
        store
            .insert_circle(&CircleRow {
                is_founder: false,
                ..row
            })
            .unwrap();
        store
            .insert_charter(&f.store.current_charter(&f.circle).unwrap().unwrap(), f.now)
            .unwrap();
        store
    }

    #[test]
    fn a_cursor_pages_through_a_log_larger_than_the_known_list() {
        let f = fixture();
        let ballot = |n: usize| {
            governance::cast_vote(
                &f.store,
                &key(2),
                &f.wide,
                VoteDecision::Revise,
                Some(&format!("round {n}")),
                f.now,
            )
            .unwrap()
        };
        // Bob's node has everything so far: more events than fit in one `known` list.
        for n in 0..MAX_KNOWN_IDS + 300 {
            ballot(n);
        }
        let bobs = second_node(&f);
        let (_, stored, cursor) = fetch_all(&f, &bobs, 2, None);
        assert_eq!(stored, MAX_KNOWN_IDS + 300 + 3);
        assert_eq!(
            bobs.event_count(&f.circle).unwrap(),
            f.store.event_count(&f.circle).unwrap()
        );
        // Nothing new: one round, nothing sent, from the cursor.
        assert_eq!(fetch_all(&f, &bobs, 2, cursor), (1, 0, cursor));

        // Alice's node gets fifty more. Without a cursor the first pages are events Bob
        // has and could not list as known (the list holds 4096); the fetch still gets to
        // the new ones instead of stopping at the first page of duplicates.
        let new: Vec<EventId> = (0..50).map(|n| ballot(100_000 + n).event_id).collect();
        let fresh = second_node(&f);
        let all: Vec<Value> = bobs
            .all_events()
            .unwrap()
            .iter()
            .map(|ev| ev.to_value().unwrap())
            .collect();
        ingest_values(&fresh, &all, None, None, f.now).unwrap();
        let (rounds, stored, _) = fetch_all(&f, &fresh, 2, None);
        assert_eq!(stored, 50);
        assert!(rounds > 1, "it had to page past what it already held");
        // With the cursor it is one round and exactly the new events.
        let (rounds, stored, reached) = fetch_all(&f, &bobs, 2, cursor);
        assert_eq!((rounds, stored), (1, 50));
        assert_eq!(reached, new.last().copied());
        assert!(new.iter().all(|id| bobs.has_event(id).unwrap()));

        // The push side: after the cursor there is nothing left to offer, and a cursor
        // this node does not know means everything.
        let out =
            outgoing_batches(&f.store, &f.circle, &device(2), reached.as_ref(), f.now).unwrap();
        assert!(out.batches.is_empty());
        let unknown = EventId::from_digest(Digest::sha256(b"not an event here"));
        let out = outgoing_batches(&f.store, &f.circle, &device(2), Some(&unknown), f.now).unwrap();
        assert_eq!(
            out.batches.iter().map(Vec::len).sum::<usize>() as u64,
            f.store.event_count(&f.circle).unwrap()
        );
        assert_eq!(out.last_seen, reached);
        // A cursor never widens what is read: carol still gets nothing of finance.
        let carol = ids(&ask(
            &f,
            3,
            Request::FetchEvents {
                circle_id: f.circle,
                known: Vec::new(),
                limit: 256,
                after: Some(f.wide.event_id()),
            },
        )
        .response);
        assert!(!carol.contains(&f.finance.event_id().to_string()));
    }

    #[test]
    fn a_member_voted_off_is_told_of_the_vote_and_nothing_else() {
        let f = fixture();
        let authority = CircleAuthority::from_signing_key(key(100));
        // Bob's node, as it was while he was a member.
        let bobs = second_node(&f);
        fetch_all(&f, &bobs, 2, None);

        // Alice and Carol vote Bob off; the founder's node notarizes charter 2.
        let (current, rules, _) = governance::rule_set(&f.store, &f.circle).unwrap();
        let next = ph_governance::remove_member(&current.content, &rules, "bob").unwrap();
        let removal = governance::propose(
            &f.store,
            &key(1),
            &f.circle,
            NewProposal {
                scope: &Scope::all(),
                title: "Remove bob",
                summary: "",
                action: ProposalAction::Amend { next },
            },
            f.now,
        )
        .unwrap();
        let mut expected = vec![removal.event_id()];
        for seed in [1, 3] {
            let ballot = governance::cast_vote(
                &f.store,
                &key(seed),
                &removal,
                VoteDecision::Approve,
                None,
                f.now,
            )
            .unwrap();
            expected.push(ballot.event_id);
        }
        let result = governance::publish_result(&f.store, &key(1), &removal, f.now)
            .unwrap()
            .unwrap();
        expected.push(result.event_id);
        let second = governance::notarize(&f.store, &authority, &result.event_id, f.now).unwrap();
        assert_eq!(second.seq, 2);

        // The circle goes on without him: a new member and charter 3.
        let (current, rules, _) = governance::rule_set(&f.store, &f.circle).unwrap();
        let next = ph_governance::admit_member(
            &current.content,
            &rules,
            RollEntry::new("dave", vec![device(4)], vec![Scope::all()]),
        )
        .unwrap();
        let admission = governance::propose(
            &f.store,
            &key(1),
            &f.circle,
            NewProposal {
                scope: &Scope::all(),
                title: "Admit dave",
                summary: "",
                action: ProposalAction::Amend { next },
            },
            f.now,
        )
        .unwrap();
        for seed in [1, 3] {
            governance::cast_vote(
                &f.store,
                &key(seed),
                &admission,
                VoteDecision::Approve,
                None,
                f.now,
            )
            .unwrap();
        }
        let result = governance::publish_result(&f.store, &key(1), &admission, f.now)
            .unwrap()
            .unwrap();
        assert_eq!(
            governance::notarize(&f.store, &authority, &result.event_id, f.now)
                .unwrap()
                .seq,
            3
        );

        // Bob asks. He is told how he came off the roll: the amendment, its ballots, its
        // result and the charter it justifies. Not the admission, not charter 3.
        let request = |known: Vec<EventId>| Request::FetchEvents {
            circle_id: f.circle,
            known,
            limit: 256,
            after: None,
        };
        let answer = ask(&f, 2, request(known_ids(&bobs, &f.circle, f.now).unwrap()));
        assert!(answer.touched.is_empty() && answer.pulls.is_empty());
        let Response::Events { events, more } = &answer.response else {
            panic!("expected the removal, got {:?}", answer.response);
        };
        assert!(!more);
        let told: Vec<EventId> = events
            .iter()
            .map(|v| field(v, "event_id").unwrap())
            .collect();
        assert_eq!(told.len(), expected.len() + 1, "and the CHARTER event");
        assert!(expected.iter().all(|id| told.contains(id)));
        assert!(!told.contains(&admission.event_id()));
        let charters: Vec<u64> = events
            .iter()
            .filter(|v| v["type"] == "CHARTER")
            .map(|v| v["body"]["charter"]["seq"].as_u64().unwrap())
            .collect();
        assert_eq!(charters, [2]);
        // Everything else is still refused: he is not a member.
        let denied = Response::error(ErrorCode::Unauthorized);
        for request in [
            Request::FetchBundle {
                circle_id: f.circle,
                digest: f.digest,
            },
            Request::Authenticate {
                memberships: Vec::new(),
                listen_addrs: Vec::new(),
            },
            Request::PushEvents {
                events: vec![f.wide.envelope().to_value().unwrap()],
            },
        ] {
            assert_eq!(ask(&f, 2, request).response, denied);
        }

        // His own node verifies the vote like any other record and takes the charter.
        let only: HashSet<CircleId> = [f.circle].into();
        let got = ingest_values(&bobs, events, Some(&only), None, f.now).unwrap();
        assert_eq!(got.stored, events.len());
        let current = bobs.current_charter(&f.circle).unwrap().unwrap();
        assert_eq!(current.seq, 2);
        assert!(current.content.member_of(&device(2)).is_none());
        // A small limit pages through the same notice, with what was received listed
        // as known.
        let mut got: Vec<EventId> = Vec::new();
        let mut rounds = 0;
        loop {
            rounds += 1;
            let mut known = known_ids(&second_node(&f), &f.circle, f.now).unwrap();
            known.extend(got.iter().copied());
            let answer = ask(
                &f,
                2,
                Request::FetchEvents {
                    circle_id: f.circle,
                    known,
                    limit: 2,
                    after: None,
                },
            );
            let Response::Events { events, more } = answer.response else {
                panic!("expected events");
            };
            assert!(events.len() <= 2);
            got.extend(
                events
                    .iter()
                    .map(|v| field::<EventId>(v, "event_id").unwrap()),
            );
            if !more {
                break;
            }
            assert!(rounds < 10);
        }
        assert!(rounds > 1);
        assert!(expected.iter().all(|id| got.contains(id)));
        // Asked again, there is nothing more to tell.
        let again = ask(&f, 2, request(known_ids(&bobs, &f.circle, f.now).unwrap()));
        assert_eq!(
            again.response,
            Response::Events {
                events: Vec::new(),
                more: false
            }
        );

        // A device that was never on a roll here learns nothing, and neither does a
        // former member whose device was revoked.
        assert_eq!(ask(&f, 9, request(Vec::new())).response, denied);
        let revocation = authority.issue_revocation(device(2), "", f.now).unwrap();
        f.store.insert_revocation(&revocation, f.now).unwrap();
        assert_eq!(ask(&f, 2, request(Vec::new())).response, denied);
    }
}
