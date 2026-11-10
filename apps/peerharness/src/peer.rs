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
//!   an event gives it no standing: it counts by its author and signature alone.

use std::collections::{BTreeSet, HashSet};

use anyhow::Result;
use ph_core::{CircleId, DeviceKey, Digest, EventId, MembershipOracle, Timestamp};
use ph_governance::{may_fetch_bundle, ProposalView, RollOracle};
use ph_protocol::limits::{MAX_KNOWN_IDS, MAX_PUSH_EVENTS};
use ph_protocol::wire::{ErrorCode, PushOutcome, PushStatus, Request, Response, WireFile};
use ph_skills::BundleStore;
use ph_store::{MissingQuery, Store};
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
            let circles = circles_of(store, &oracle, peer, now)?;
            if circles.is_empty() {
                return Ok(Answer::only(unauthorized()));
            }
            remember_peer(store, peer_id, peer, &listen_addrs, &circles, now)?;
            Ok(Answer::only(Response::Authenticated {
                memberships: Vec::new(),
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
        } => {
            if !oracle.is_active_member(&circle_id, peer, now) {
                return Ok(Answer::only(unauthorized()));
            }
            let known: HashSet<EventId> = known.into_iter().collect();
            let query = MissingQuery::new(&circle_id, &known, now).with_limit(limit as usize);
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
}

fn field<T: std::str::FromStr>(value: &Value, name: &str) -> Option<T> {
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

/// Everything of `circle` on this node that `peer` may read, as batches that each fit
/// one `push_events` request. Empty when `peer` is not an active member.
pub fn outgoing_batches(
    store: &Store,
    circle: &CircleId,
    peer: &DeviceKey,
    now: Timestamp,
) -> Result<Vec<Vec<Value>>> {
    let oracle = roll_oracle(store)?;
    if !oracle.is_active_member(circle, peer, now) {
        return Ok(Vec::new());
    }
    let mut sent: HashSet<EventId> = HashSet::new();
    let mut batches = Vec::new();
    loop {
        let query = MissingQuery::new(circle, &sent, now).with_limit(MAX_PUSH_EVENTS);
        let missing = store.missing_for_peer(&query, |scope| {
            oracle.authorize_read(circle, peer, scope, now).is_ok()
        })?;
        if missing.events.is_empty() {
            break;
        }
        let mut batch = Vec::with_capacity(missing.events.len());
        for ev in &missing.events {
            batch.push(ev.to_value()?);
            sent.insert(ev.event_id);
        }
        batches.push(batch);
        if !missing.more {
            break;
        }
    }
    Ok(batches)
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
            },
            Request::FetchEvents {
                circle_id: other_circle,
                known: Vec::new(),
                limit: 10,
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
        // Announcing addresses stores them, bounded and validated.
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
                memberships: Vec::new()
            }
        );
        let peer = f.store.peer(&pid(2)).unwrap().unwrap();
        assert_eq!(peer.addrs, ["/ip4/127.0.0.1/udp/4001/quic-v1"]);
        assert_eq!(peer.circles, [f.circle]);
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
        assert!(outgoing_batches(&f.store, &f.circle, &device(2), f.now)
            .unwrap()
            .is_empty());
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
        let mut batch: Vec<Value> = outgoing_batches(&f.store, &f.circle, &device(2), f.now)
            .unwrap()
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
}
