//! Event log, sync queries and outbox.

mod common;

use std::collections::HashSet;

use common::*;
use ph_core::{Digest, EventId, Nonce, Scope};
use ph_protocol::{EventType, SignedEnvelope};
use ph_store::{EventFilter, InsertOutcome, MissingQuery, StoreError};

#[test]
fn duplicate_insert_is_reported_not_an_error() {
    let s = store_with_circle();
    let q = verified(&question(ALICE, "team/backend", "Use pnpm?", 1));
    assert_eq!(
        s.insert_event(&q, Some(&peer_id(1)), now()).unwrap(),
        InsertOutcome::Inserted
    );
    for _ in 0..3 {
        assert_eq!(
            s.insert_event(&q, Some(&peer_id(2)), now().plus_secs(5))
                .unwrap(),
            InsertOutcome::Duplicate
        );
    }
    // Via the SignedEnvelope path too.
    assert_eq!(
        s.insert_signed_event(q.envelope(), None, now()).unwrap(),
        InsertOutcome::Duplicate
    );
    let stored = s.event(&q.event_id()).unwrap().unwrap();
    // The first insert wins (origin and received_at unchanged).
    assert_eq!(stored.origin_peer.as_deref(), Some(peer_id(1).as_str()));
    assert_eq!(stored.received_at, now());
    assert_eq!(stored.envelope_json, q.canonical_json());
    assert_eq!(&stored.envelope().unwrap(), q.envelope());
    assert_eq!(s.event_count(&circle()).unwrap(), 1);
}

#[test]
fn signed_insert_verifies_signature() {
    let s = store_with_circle();
    let q = question(ALICE, "team/backend", "Use pnpm?", 1);
    let mut forged = q.clone();
    forged.envelope.author = pk(BOB);
    let err = s.insert_signed_event(&forged, None, now()).unwrap_err();
    assert!(matches!(err, StoreError::Protocol(_)), "{err:?}");
    assert!(!s.has_event(&q.event_id).unwrap());
    assert_eq!(
        s.insert_signed_event(&q, None, now()).unwrap(),
        InsertOutcome::Inserted
    );
}

#[test]
fn bad_origin_peer_is_rejected() {
    let s = store_with_circle();
    let q = verified(&question(ALICE, "team/backend", "Use pnpm?", 1));
    for bad in ["", "has space", "x/y", &"a".repeat(129)] {
        assert!(matches!(
            s.insert_event(&q, Some(bad), now()),
            Err(StoreError::Invalid { .. })
        ));
    }
}

#[test]
fn reference_queries() {
    let s = store_with_circle();
    let q = question(ALICE, "team/backend", "Use pnpm?", 1);
    let a1 = answer(BOB, "team/backend", q.event_id, 2);
    let a2 = answer(CAROL, "team/backend", q.event_id, 3);
    let digest = Digest::sha256(b"bundle");
    let p = proposal(ALICE, "team/backend", digest, 4);
    let v1 = vote(BOB, "team/backend", p.event_id, digest, 5);
    let v2 = vote(
        ALICE,
        "team/backend",
        p.event_id,
        Digest::sha256(b"other"),
        6,
    );
    let other_p = proposal(BOB, "team/frontend", Digest::sha256(b"b2"), 7);
    for e in [&q, &a1, &a2, &p, &v1, &v2, &other_p] {
        assert_eq!(
            s.insert_signed_event(e, None, now()).unwrap(),
            InsertOutcome::Inserted
        );
    }
    let ids = |v: Vec<ph_store::StoredEvent>| -> HashSet<EventId> {
        v.into_iter().map(|e| e.event_id).collect()
    };
    assert_eq!(
        ids(s.answers_for_question(&q.event_id).unwrap()),
        HashSet::from([a1.event_id, a2.event_id])
    );
    let votes = s.votes_for_proposal(&p.event_id).unwrap();
    assert_eq!(
        ids(votes.clone()),
        HashSet::from([v1.event_id, v2.event_id])
    );
    assert!(votes.iter().all(|v| v.event_type == EventType::Vote));
    // A ballot is bound to its proposal by id; only the adopt proposal indexes a bundle.
    assert!(votes.iter().all(|v| v.bundle_digest.is_none()));
    assert!(votes.iter().all(|v| v.ref_event_id == Some(p.event_id)));
    assert_eq!(
        ids(s.proposals(&circle()).unwrap()),
        HashSet::from([p.event_id, other_p.event_id])
    );
    assert_eq!(
        ids(s.proposals_with_bundle(&circle(), &digest).unwrap()),
        HashSet::from([p.event_id])
    );
    assert!(s.results_for_proposal(&p.event_id).unwrap().is_empty());
    assert!(s.repeals_of(&p.event_id).unwrap().is_empty());
    assert!(s.votes_for_proposal(&q.event_id).unwrap().is_empty());
}

#[test]
fn list_events_filters() {
    let s = store_with_circle();
    let digest = Digest::sha256(b"bundle");
    let q1 = question_at(ALICE, "team/backend", "q1", 1, now());
    let q2 = question_at(ALICE, "team/frontend", "q2", 2, now().plus_secs(1));
    let q3 = question_at(ALICE, "team/backend/api", "q3", 3, now().plus_secs(2));
    let p = proposal(ALICE, "team/backend", digest, 4);
    for e in [&q1, &q2, &q3, &p] {
        s.insert_signed_event(e, None, now()).unwrap();
    }
    let all = s.list_events(&circle(), &EventFilter::default()).unwrap();
    assert_eq!(all.len(), 4);
    let qs = s
        .list_events(
            &circle(),
            &EventFilter {
                types: &[EventType::Question],
                ..Default::default()
            },
        )
        .unwrap();
    // Newest first.
    assert_eq!(
        qs.iter().map(|e| e.event_id).collect::<Vec<_>>(),
        vec![q3.event_id, q2.event_id, q1.event_id]
    );
    let backend = [scope("team/backend")];
    let readable = s
        .list_events(
            &circle(),
            &EventFilter {
                types: &[EventType::Question],
                readable_scopes: Some(&backend),
                limit: 10,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        readable.iter().map(|e| e.event_id).collect::<Vec<_>>(),
        vec![q3.event_id, q1.event_id]
    );
    let limited = s
        .list_events(
            &circle(),
            &EventFilter {
                readable_scopes: Some(&backend),
                limit: 1,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(limited.len(), 1);
    // Far in the future the questions have expired. The proposal has not: decision
    // events are permanent records.
    let still_live = s
        .list_events(
            &circle(),
            &EventFilter {
                not_expired_at: Some(now().plus_days(4000)),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        still_live.iter().map(|e| e.event_id).collect::<Vec<_>>(),
        vec![p.event_id]
    );
}

/// A node that joins years later can still fetch the circle's decisions: PROPOSAL, VOTE
/// and RESULT never expire, while a QUESTION does.
#[test]
fn decisions_are_served_long_after_questions_expired() {
    let s = store_with_circle();
    let digest = Digest::sha256(b"bundle");
    let q = question(ALICE, "team/backend", "q", 1);
    let p = proposal(ALICE, "team/backend", digest, 2);
    let v = vote(BOB, "team/backend", p.event_id, digest, 3);
    let r = in_circle(
        circle(),
        BOB,
        "team/backend",
        ph_protocol::EventBody::Result(ph_protocol::ResultBody::new(p.event_id, vec![v.event_id])),
        4,
    );
    for e in [&q, &p, &v, &r] {
        s.insert_signed_event(e, None, now()).unwrap();
    }
    let much_later = now().plus_days(3650);
    let got = s
        .missing_for_peer(
            &MissingQuery::new(&circle(), &HashSet::new(), much_later),
            readable,
        )
        .unwrap();
    assert_eq!(
        ids(got.events),
        HashSet::from([p.event_id, v.event_id, r.event_id])
    );
    assert_eq!(
        s.event_ids_for_circle(&circle(), much_later)
            .unwrap()
            .into_iter()
            .collect::<HashSet<_>>(),
        HashSet::from([p.event_id, v.event_id, r.event_id])
    );
}

/// A circle-wide (`*`) decision concerns every member, so it is served whatever the
/// requester's scopes are; a decision in a scope the requester cannot read is not.
#[test]
fn circle_wide_decisions_reach_every_member() {
    let s = store_with_circle();
    let digest = Digest::sha256(b"bundle");
    let wide = proposal(ALICE, "*", digest, 1);
    let wide_vote = vote(BOB, "*", wide.event_id, digest, 2);
    let finance = proposal(ALICE, "team/finance", digest, 3);
    let wide_question = question(ALICE, "*", "everyone?", 4);
    for e in [&wide, &wide_vote, &finance, &wide_question] {
        s.insert_signed_event(e, None, now()).unwrap();
    }
    // `readable` grants team/backend only.
    let got = s
        .missing_for_peer(
            &MissingQuery::new(&circle(), &HashSet::new(), now()),
            readable,
        )
        .unwrap();
    assert_eq!(
        ids(got.events),
        HashSet::from([wide.event_id, wide_vote.event_id]),
        "the `*` decisions, but neither the finance proposal nor the `*` question"
    );
}

/// Scope `team/backend` is readable; `team/finance` is not.
/// The event ids of `events`, as a set.
fn ids(events: Vec<ph_store::StoredEvent>) -> HashSet<EventId> {
    events.into_iter().map(|e| e.event_id).collect()
}

fn readable(sc: &Scope) -> bool {
    Scope::any_covers(&[scope("team/backend")], sc)
}

#[test]
fn missing_for_peer_respects_scope_known_and_control_plane() {
    let s = store_with_circle();
    let ok1 = question_at(ALICE, "team/backend", "a", 1, now());
    let ok2 = question_at(ALICE, "team/backend/api", "b", 2, now().plus_secs(1));
    let secret = question_at(ALICE, "team/finance", "c", 3, now().plus_secs(2));
    let tricky = question_at(ALICE, "team/backendx", "d", 4, now().plus_secs(3));
    let member = membership_event(BOB, "team/finance", 5);
    let revoked = revocation_event(CAROL, 6);
    for e in [&ok1, &ok2, &secret, &tricky, &member, &revoked] {
        s.insert_event(&verified(e), None, now()).unwrap();
    }
    let known = HashSet::new();
    let got = s
        .missing_for_peer(&MissingQuery::new(&circle(), &known, now()), readable)
        .unwrap();
    let ids: HashSet<EventId> = got.events.iter().map(|e| e.event_id).collect();
    assert_eq!(
        ids,
        HashSet::from([
            ok1.event_id,
            ok2.event_id,
            member.event_id,
            revoked.event_id
        ])
    );
    assert!(!got.more);
    assert!(!ids.contains(&secret.event_id));
    assert!(
        !ids.contains(&tricky.event_id),
        "prefix without '/' is not covered"
    );

    // Known ids are skipped.
    let known = HashSet::from([ok1.event_id, member.event_id]);
    let got = s
        .missing_for_peer(&MissingQuery::new(&circle(), &known, now()), readable)
        .unwrap();
    let ids: HashSet<EventId> = got.events.iter().map(|e| e.event_id).collect();
    assert_eq!(ids, HashSet::from([ok2.event_id, revoked.event_id]));

    // A deny-all predicate still returns control-plane events only.
    let got = s
        .missing_for_peer(
            &MissingQuery::new(&circle(), &HashSet::new(), now()),
            |_| false,
        )
        .unwrap();
    assert!(got.events.iter().all(|e| e.event_type.is_control_plane()));
    assert_eq!(got.events.len(), 2);

    // Another circle has nothing.
    let other = ph_core::CircleId::derive(&pk(9));
    let got = s
        .missing_for_peer(&MissingQuery::new(&other, &HashSet::new(), now()), |_| true)
        .unwrap();
    assert!(got.events.is_empty() && !got.more);
}

#[test]
fn missing_for_peer_limits_and_paging() {
    let s = store_with_circle();
    let mut all = Vec::new();
    for i in 0..10u8 {
        let e = question_at(
            ALICE,
            "team/backend",
            &format!("q{i}"),
            i + 1,
            now().plus_secs(i64::from(i)),
        );
        s.insert_signed_event(&e, None, now()).unwrap();
        all.push(e.event_id);
    }
    // Unreadable events interleaved must not count against the limit.
    for i in 0..5u8 {
        let e = question_at(ALICE, "team/finance", &format!("f{i}"), 100 + i, now());
        s.insert_signed_event(&e, None, now()).unwrap();
    }
    let mut known = HashSet::new();
    let mut pages = 0;
    loop {
        let c = circle();
        let q = MissingQuery::new(&c, &known, now()).with_limit(3);
        let got = s.missing_for_peer(&q, readable).unwrap();
        assert!(got.events.len() <= 3);
        pages += 1;
        for e in &got.events {
            assert!(known.insert(e.event_id), "no event returned twice");
        }
        if !got.more {
            break;
        }
        assert_eq!(got.events.len(), 3);
    }
    assert_eq!(pages, 4);
    assert_eq!(known, all.iter().copied().collect::<HashSet<_>>());

    // Ordering is (created_at, event_id).
    let got = s
        .missing_for_peer(
            &MissingQuery::new(&circle(), &HashSet::new(), now()),
            readable,
        )
        .unwrap();
    assert_eq!(
        got.events.iter().map(|e| e.event_id).collect::<Vec<_>>(),
        all
    );

    // Limit is clamped to MAX_FETCH_LIMIT and byte budget is honoured.
    let one = s
        .missing_for_peer(
            &MissingQuery::new(&circle(), &HashSet::new(), now()),
            readable,
        )
        .unwrap()
        .events[0]
        .envelope_json
        .len();
    let c = circle();
    let empty = HashSet::new();
    let mut q = MissingQuery::new(&c, &empty, now()).with_limit(usize::MAX);
    q.max_bytes = 2 * (one + 1) + 1;
    let got = s.missing_for_peer(&q, readable).unwrap();
    assert_eq!(got.events.len(), 2);
    assert!(got.more);
    // A budget smaller than one event still returns one, so sync always progresses.
    q.max_bytes = 1;
    let got = s.missing_for_peer(&q, readable).unwrap();
    assert_eq!(got.events.len(), 1);
    assert!(got.more);
    q.limit = 0;
    let got = s.missing_for_peer(&q, readable).unwrap();
    assert!(got.events.is_empty() && got.more);
}

#[test]
fn missing_for_peer_skips_expired() {
    let s = store_with_circle();
    let e = question(ALICE, "team/backend", "q", 1);
    s.insert_signed_event(&e, None, now()).unwrap();
    let later = e.expires_at;
    let got = s
        .missing_for_peer(
            &MissingQuery::new(&circle(), &HashSet::new(), later),
            readable,
        )
        .unwrap();
    assert!(got.events.is_empty());
    assert!(s.event_ids_for_circle(&circle(), later).unwrap().is_empty());
    assert_eq!(
        s.event_ids_for_circle(&circle(), now()).unwrap(),
        vec![e.event_id]
    );
}

#[test]
fn stored_event_value_round_trips() {
    let s = store_with_circle();
    let e = question(ALICE, "team/backend", "q", 1);
    s.insert_signed_event(&e, None, now()).unwrap();
    let stored = s.event(&e.event_id).unwrap().unwrap();
    let v = stored.to_value().unwrap();
    assert_eq!(SignedEnvelope::from_value(&v).unwrap(), e);
    assert!(s
        .event(&EventId::from_digest(Digest::sha256(b"none")))
        .unwrap()
        .is_none());
    // Debug never shows the question text.
    assert!(!format!("{stored:?}").contains("\"q\""));
}

#[test]
fn outbox_flow() {
    let s = store_with_circle();
    let e = question(ALICE, "team/backend", "q", 1);
    // Unknown peer: foreign key.
    s.insert_signed_event(&e, None, now()).unwrap();
    assert!(matches!(
        s.enqueue_outbox(&e.event_id, &peer_id(1), now()),
        Err(StoreError::MissingReference)
    ));
    s.upsert_peer(&peer_id(1), &pk(BOB), &[], now()).unwrap();
    s.upsert_peer(&peer_id(2), &pk(CAROL), &[], now()).unwrap();

    let e2 = question(ALICE, "team/backend", "q2", 2);
    assert_eq!(
        s.insert_local_event_with_outbox(&e2, [peer_id(1), peer_id(2)], now())
            .unwrap(),
        InsertOutcome::Inserted
    );
    assert!(s
        .enqueue_outbox(&e.event_id, &peer_id(1), now().plus_secs(1))
        .unwrap());
    assert!(
        !s.enqueue_outbox(&e.event_id, &peer_id(1), now()).unwrap(),
        "idempotent"
    );
    assert_eq!(s.pending_outbox_count().unwrap(), 3);
    assert_eq!(
        s.peers_with_pending(now()).unwrap(),
        vec![peer_id(1), peer_id(2)]
    );

    let pending = s.pending_for_peer(&peer_id(1), now(), 10).unwrap();
    assert_eq!(
        pending.iter().map(|p| p.event.event_id).collect::<Vec<_>>(),
        vec![e2.event_id, e.event_id]
    );
    assert_eq!(pending[0].event.envelope().unwrap(), e2);
    assert_eq!(s.pending_for_peer(&peer_id(1), now(), 1).unwrap().len(), 1);

    assert_eq!(
        s.bump_outbox_attempts(&e2.event_id, &peer_id(1), now())
            .unwrap(),
        1
    );
    assert_eq!(
        s.bump_outbox_attempts(&e2.event_id, &peer_id(1), now())
            .unwrap(),
        2
    );
    assert!(matches!(
        s.bump_outbox_attempts(&e2.event_id, &peer_id(9), now()),
        Err(StoreError::NotFound { .. })
    ));
    assert!(s.mark_delivered(&e2.event_id, &peer_id(1), now()).unwrap());
    assert!(!s.mark_delivered(&e2.event_id, &peer_id(1), now()).unwrap());
    assert!(matches!(
        s.mark_delivered(&e2.event_id, &peer_id(9), now()),
        Err(StoreError::NotFound { .. })
    ));
    assert_eq!(s.pending_outbox_count().unwrap(), 2);
    let pending = s.pending_for_peer(&peer_id(1), now(), 10).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].entry.attempts, 0);

    // Expired events are not offered and can be dropped.
    let after = e.expires_at;
    assert!(s
        .pending_for_peer(&peer_id(1), after, 10)
        .unwrap()
        .is_empty());
    assert!(s.peers_with_pending(after).unwrap().is_empty());
    assert_eq!(s.drop_expired_outbox(after).unwrap(), 2);
    assert_eq!(s.pending_outbox_count().unwrap(), 0);
}

#[test]
fn local_event_with_outbox_is_atomic() {
    let s = store_with_circle();
    s.upsert_peer(&peer_id(1), &pk(BOB), &[], now()).unwrap();
    let e = question(ALICE, "team/backend", "q", 1);
    // Second peer unknown: the whole operation rolls back, including the event.
    let err = s
        .insert_local_event_with_outbox(&e, [peer_id(1), peer_id(7)], now())
        .unwrap_err();
    assert!(matches!(err, StoreError::MissingReference));
    assert!(!s.has_event(&e.event_id).unwrap());
    assert_eq!(s.pending_outbox_count().unwrap(), 0);
}

#[test]
fn many_distinct_nonces_are_distinct_events() {
    let s = store_with_circle();
    let mut ids = HashSet::new();
    for n in 0..20u8 {
        let e = ph_protocol::EnvelopeBuilder::new(
            circle(),
            scope("team/backend"),
            ph_protocol::EventBody::Question(ph_protocol::QuestionBody {
                question: "same text".into(),
                topic: "t".into(),
                related_candidate: None,
            }),
        )
        .nonce(Nonce::from_bytes([n; 16]))
        .sign(&sk(ALICE), now())
        .unwrap();
        assert_eq!(
            s.insert_signed_event(&e, None, now()).unwrap(),
            InsertOutcome::Inserted
        );
        ids.insert(e.event_id);
    }
    assert_eq!(ids.len(), 20);
    assert_eq!(s.event_count(&circle()).unwrap(), 20);
}

// ------------------------------------------------------------------ review additions

fn other_circle_row() -> ph_store::CircleRow {
    let mut c = circle_row();
    c.root_key = pk(9);
    c.circle_id = ph_core::CircleId::derive(&pk(9));
    c.name = "other".into();
    c
}

fn in_circle(
    circle_id: ph_core::CircleId,
    author: u8,
    sc: &str,
    body: ph_protocol::EventBody,
    nonce: u8,
) -> SignedEnvelope {
    ph_protocol::EnvelopeBuilder::new(circle_id, scope(sc), body)
        .nonce(Nonce::from_bytes([nonce; 16]))
        .sign(&sk(author), now())
        .unwrap()
}

fn qbody(text: &str) -> ph_protocol::EventBody {
    ph_protocol::EventBody::Question(ph_protocol::QuestionBody {
        question: text.into(),
        topic: "t".into(),
        related_candidate: None,
    })
}

/// Two circles with events at the same scopes: syncing one circle never returns the
/// other's events, not even control-plane ones and not with an allow-all predicate.
#[test]
fn missing_for_peer_never_crosses_circles() {
    let s = store_with_circle();
    let other = other_circle_row();
    s.insert_circle(&other).unwrap();
    let mine = question(ALICE, "team/backend", "mine", 1);
    s.insert_signed_event(&mine, None, now()).unwrap();
    let theirs = in_circle(other.circle_id, ALICE, "team/backend", qbody("theirs"), 2);
    s.insert_signed_event(&theirs, None, now()).unwrap();
    // A REVOCATION in the other circle (control plane, always included for *its* circle).
    let rev = ph_protocol::UnsignedRevocation::new(
        pk(9),
        pk(BOB),
        now(),
        String::new(),
        Nonce::from_bytes([3; 16]),
    )
    .sign(&sk(9))
    .unwrap();
    let rev_event = in_circle(
        other.circle_id,
        9,
        "*",
        ph_protocol::EventBody::Revocation(ph_protocol::RevocationBody { revocation: rev }),
        4,
    );
    s.insert_signed_event(&rev_event, None, now()).unwrap();

    let empty = HashSet::new();
    let got = s
        .missing_for_peer(&MissingQuery::new(&circle(), &empty, now()), |_| true)
        .unwrap();
    assert_eq!(
        got.events.iter().map(|e| e.event_id).collect::<Vec<_>>(),
        vec![mine.event_id]
    );
    assert!(got.events.iter().all(|e| e.circle_id == circle()));
    // Ids for the other circle in `known` change nothing.
    let known = HashSet::from([theirs.event_id, rev_event.event_id]);
    let got = s
        .missing_for_peer(&MissingQuery::new(&circle(), &known, now()), |_| true)
        .unwrap();
    assert_eq!(got.events.len(), 1);
    assert_eq!(
        s.event_ids_for_circle(&circle(), now()).unwrap(),
        vec![mine.event_id]
    );
    let listed = s.list_events(&circle(), &EventFilter::default()).unwrap();
    assert_eq!(listed.len(), 1);
}

/// The readable predicate is consulted with each event's own scope, and nothing it
/// refuses is returned, at any paging position.
#[test]
fn missing_for_peer_passes_each_scope_to_the_predicate() {
    let s = store_with_circle();
    let scopes = [
        "team",
        "team/backend",
        "team/finance",
        "other",
        "team/backend/api",
    ];
    for (i, sc) in scopes.iter().enumerate() {
        let n = u8::try_from(i).unwrap();
        s.insert_signed_event(
            &question_at(
                ALICE,
                sc,
                &format!("q{i}"),
                n + 1,
                now().plus_secs(i64::from(n)),
            ),
            None,
            now(),
        )
        .unwrap();
    }
    let seen = std::cell::RefCell::new(Vec::new());
    let empty = HashSet::new();
    let got = s
        .missing_for_peer(&MissingQuery::new(&circle(), &empty, now()), |sc| {
            seen.borrow_mut().push(sc.as_str().to_owned());
            sc.as_str().starts_with("team/backend")
        })
        .unwrap();
    assert_eq!(seen.into_inner(), scopes.to_vec());
    let got_scopes: Vec<_> = got.events.iter().map(|e| e.scope.as_str()).collect();
    assert_eq!(got_scopes, vec!["team/backend", "team/backend/api"]);
}

/// Two independent stores: B pulls from A until `more` is false, then a second sync
/// returns nothing and replaying the same events is reported as duplicates.
#[test]
fn resync_between_two_stores_is_idempotent() {
    let a = store_with_circle();
    let b = store_with_circle();
    let mut ids = Vec::new();
    for i in 0..7u8 {
        let e = question_at(
            ALICE,
            "team/backend",
            &format!("q{i}"),
            i + 1,
            now().plus_secs(i64::from(i)),
        );
        a.insert_signed_event(&e, None, now()).unwrap();
        ids.push(e.event_id);
    }
    let pull = |limit: usize| -> (usize, usize) {
        let mut inserted = 0;
        let mut duplicate = 0;
        loop {
            let known: HashSet<EventId> = b
                .event_ids_for_circle(&circle(), now())
                .unwrap()
                .into_iter()
                .collect();
            let c = circle();
            let batch = a
                .missing_for_peer(
                    &MissingQuery::new(&c, &known, now()).with_limit(limit),
                    readable,
                )
                .unwrap();
            for ev in &batch.events {
                // Re-validate like a real receiver would.
                let v =
                    ph_protocol::validate_stateless(ev.envelope_json.as_bytes(), now()).unwrap();
                match b.insert_event(&v, Some(&peer_id(1)), now()).unwrap() {
                    InsertOutcome::Inserted => inserted += 1,
                    InsertOutcome::Duplicate => duplicate += 1,
                }
            }
            if !batch.more {
                return (inserted, duplicate);
            }
        }
    };
    assert_eq!(pull(3), (7, 0));
    assert_eq!(pull(3), (0, 0), "second sync transfers nothing");
    // A replay of everything (e.g. a peer that lost its cursor) is all duplicates.
    for id in &ids {
        let ev = a.event(id).unwrap().unwrap();
        let v = ph_protocol::validate_stateless(ev.envelope_json.as_bytes(), now()).unwrap();
        assert_eq!(
            b.insert_event(&v, None, now()).unwrap(),
            InsertOutcome::Duplicate
        );
    }
    assert_eq!(b.event_count(&circle()).unwrap(), 7);
}

/// A VOTE/ANSWER/RESULT published in another circle that names this circle's
/// proposal or question is not returned by the reference queries.
#[test]
fn reference_queries_stay_in_the_target_circle() {
    let s = store_with_circle();
    let other = other_circle_row();
    s.insert_circle(&other).unwrap();
    let digest = Digest::sha256(b"bundle");
    let p = proposal(ALICE, "team/backend", digest, 1);
    let q = question(ALICE, "team/backend", "q", 2);
    let good_vote = vote(BOB, "team/backend", p.event_id, digest, 3);
    let foreign_vote = in_circle(
        other.circle_id,
        BOB,
        "team/backend",
        ph_protocol::EventBody::Vote(ph_protocol::VoteBody {
            proposal_id: p.event_id,
            decision: ph_protocol::VoteDecision::Approve,
            rationale: None,
        }),
        4,
    );
    let foreign_answer = in_circle(
        other.circle_id,
        BOB,
        "team/backend",
        ph_protocol::EventBody::Answer(ph_protocol::AnswerBody {
            question_id: q.event_id,
            answer: ph_protocol::AnswerChoice::Agree,
            rationale: None,
        }),
        5,
    );
    let foreign_result = in_circle(
        other.circle_id,
        BOB,
        "team/backend",
        ph_protocol::EventBody::Result(ph_protocol::ResultBody::new(
            p.event_id,
            vec![good_vote.event_id],
        )),
        6,
    );
    // Votes arriving before their proposal are stored but not yet listed.
    s.insert_signed_event(&good_vote, None, now()).unwrap();
    assert!(s.votes_for_proposal(&p.event_id).unwrap().is_empty());
    for e in [&p, &q, &foreign_vote, &foreign_answer, &foreign_result] {
        s.insert_signed_event(e, None, now()).unwrap();
    }
    let votes = s.votes_for_proposal(&p.event_id).unwrap();
    assert_eq!(
        votes.iter().map(|e| e.event_id).collect::<Vec<_>>(),
        vec![good_vote.event_id]
    );
    assert!(s.answers_for_question(&q.event_id).unwrap().is_empty());
    assert!(s.results_for_proposal(&p.event_id).unwrap().is_empty());
    // A result published in the proposal's own circle is listed.
    let own_result = in_circle(
        circle(),
        BOB,
        "team/backend",
        ph_protocol::EventBody::Result(ph_protocol::ResultBody::new(
            p.event_id,
            vec![good_vote.event_id],
        )),
        8,
    );
    s.insert_signed_event(&own_result, None, now()).unwrap();
    assert_eq!(
        s.results_for_proposal(&p.event_id)
            .unwrap()
            .iter()
            .map(|e| e.event_id)
            .collect::<Vec<_>>(),
        vec![own_result.event_id]
    );
    // An id that is a QUESTION, not a PROPOSAL, has no votes even if one names it.
    let odd_vote = vote(CAROL, "team/backend", q.event_id, digest, 7);
    s.insert_signed_event(&odd_vote, None, now()).unwrap();
    assert!(s.votes_for_proposal(&q.event_id).unwrap().is_empty());
}

/// `insert_signed_event` applies the wire parser's schema and size rules, so an
/// envelope a peer would reject (here: an over-long question, correctly re-signed) is
/// never stored or queued.
#[test]
fn signed_insert_rejects_schema_violations_even_with_valid_signature() {
    use ph_protocol::signing::{digest_of_input, sign_input};
    let s = store_with_circle();
    s.upsert_peer(&peer_id(1), &pk(BOB), &[], now()).unwrap();
    let mut e = question(ALICE, "team/backend", "q", 1);
    e.envelope.body = qbody(&"x".repeat(3000));
    let input = e.envelope.signing_input().unwrap();
    e.signature = sign_input(&sk(ALICE), &input);
    e.event_id = EventId::from_digest(digest_of_input(&input));
    assert!(e.verify_signature().is_ok(), "signature itself is fine");
    let err = s.insert_signed_event(&e, None, now()).unwrap_err();
    assert!(matches!(err, StoreError::Protocol(_)), "{err:?}");
    let err = s
        .insert_local_event_with_outbox(&e, [peer_id(1)], now())
        .unwrap_err();
    assert!(matches!(err, StoreError::Protocol(_)), "{err:?}");
    assert!(!s.has_event(&e.event_id).unwrap());
    assert_eq!(s.pending_outbox_count().unwrap(), 0);
}

/// A tampered body with the original signature is refused.
#[test]
fn signed_insert_rejects_modified_body() {
    let s = store_with_circle();
    let mut e = question(ALICE, "team/backend", "Use pnpm?", 1);
    e.envelope.body = qbody("Use npm?");
    let err = s.insert_signed_event(&e, None, now()).unwrap_err();
    assert!(matches!(err, StoreError::Protocol(_)), "{err:?}");
    assert_eq!(s.event_count(&circle()).unwrap(), 0);
}
