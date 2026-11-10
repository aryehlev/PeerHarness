//! Per-table repository behaviour.

mod common;

use common::*;
use ph_core::{
    Digest, EventId, NormalizedObservation, ObservationId, ObservationKind, ObservationSource,
};
use ph_protocol::{bundle_digest, manifest_for_files};
use ph_store::*;

// ------------------------------------------------------------------- identity, circles

#[test]
fn identity_roundtrip_and_replace() {
    let s = Store::open_in_memory().unwrap();
    assert!(s.identity().unwrap().is_none());
    let id = IdentityMetadata {
        device_key: pk(ALICE),
        keystore_backend: "os".into(),
        keystore_ref: "peerharness/device".into(),
        created_at: now(),
    };
    s.set_identity(&id).unwrap();
    assert_eq!(s.identity().unwrap().unwrap(), id);
    let id2 = IdentityMetadata {
        device_key: pk(BOB),
        ..id.clone()
    };
    s.set_identity(&id2).unwrap();
    assert_eq!(s.identity().unwrap().unwrap(), id2);
    assert!(matches!(
        s.set_identity(&IdentityMetadata {
            keystore_backend: String::new(),
            ..id
        }),
        Err(StoreError::Invalid { .. })
    ));
}

#[test]
fn circles() {
    let s = Store::open_in_memory().unwrap();
    let c = circle_row();
    s.insert_circle(&c).unwrap();
    assert_eq!(s.circle(&circle()).unwrap().unwrap(), c);
    assert_eq!(s.circle_by_name("acme").unwrap().unwrap(), c);
    assert!(s.circle_by_name("other").unwrap().is_none());
    // Duplicate id, duplicate name.
    assert!(matches!(
        s.insert_circle(&c),
        Err(StoreError::AlreadyExists { .. })
    ));
    let mut c2 = c.clone();
    c2.root_key = pk(8);
    c2.circle_id = ph_core::CircleId::derive(&pk(8));
    assert!(matches!(
        s.insert_circle(&c2),
        Err(StoreError::AlreadyExists { .. })
    ));
    // Id not derived from root key.
    let mut c3 = c2.clone();
    c3.name = "b".into();
    c3.root_key = pk(7);
    assert!(matches!(
        s.insert_circle(&c3),
        Err(StoreError::Mismatch { .. })
    ));
    c2.name = "beta".into();
    s.insert_circle(&c2).unwrap();
    assert_eq!(s.circles().unwrap().len(), 2);
    // Bad names.
    for bad in ["", "a\u{202e}b", &"x".repeat(65)] {
        let mut c4 = c2.clone();
        c4.root_key = pk(6);
        c4.circle_id = ph_core::CircleId::derive(&pk(6));
        c4.name = bad.to_string();
        assert!(matches!(
            s.insert_circle(&c4),
            Err(StoreError::Invalid { .. })
        ));
    }
    // The owner's adoption mode and the charter they accepted.
    let row = s.circle(&circle()).unwrap().unwrap();
    assert_eq!(
        (row.adoption_mode.as_str(), row.accepted_charter),
        ("ask", None)
    );
    let h = charter_digest();
    s.set_circle_adoption(&circle(), "follow", &h).unwrap();
    let row = s.circle(&circle()).unwrap().unwrap();
    assert_eq!(row.adoption_mode, "follow");
    assert_eq!(row.accepted_charter, Some(h));
    assert!(matches!(
        s.set_circle_adoption(&circle(), "always", &h),
        Err(StoreError::Invalid { .. })
    ));
    assert!(matches!(
        s.set_circle_adoption(&ph_core::CircleId::derive(&pk(5)), "ask", &h),
        Err(StoreError::NotFound { .. })
    ));
    let mut bad = circle_row();
    bad.adoption_mode = "yolo".into();
    bad.name = "gamma".into();
    assert!(matches!(
        s.insert_circle(&bad),
        Err(StoreError::Invalid { .. })
    ));
}

// ------------------------------------------------------------------- memberships

#[test]
fn membership_upsert_and_queries() {
    let s = store_with_circle();
    let p = proof(ALICE, &["team/backend"]);
    // Bare credential first, then the acceptance.
    assert_eq!(
        s.upsert_membership(&p.credential, None, false, now())
            .unwrap(),
        UpsertOutcome::Inserted
    );
    assert!(s.all_membership_proofs().unwrap().is_empty());
    assert_eq!(
        s.upsert_membership_proof(&p, true, now().plus_secs(9))
            .unwrap(),
        UpsertOutcome::Updated
    );
    assert_eq!(
        s.upsert_membership_proof(&p, true, now()).unwrap(),
        UpsertOutcome::Unchanged
    );
    let digest = p.credential.digest().unwrap();
    let row = s.membership(&digest).unwrap().unwrap();
    assert_eq!(row.credential, p.credential);
    assert_eq!(row.acceptance.as_ref(), Some(&p.acceptance));
    assert!(row.is_self);
    assert_eq!(row.received_at, now(), "first received_at kept");
    assert_eq!(row.scopes, vec![scope("team/backend")]);
    assert_eq!(row.proof().unwrap(), p);

    let bob = proof(BOB, &["team/frontend"]);
    s.upsert_membership_proof(&bob, false, now()).unwrap();
    assert_eq!(s.memberships_for_circle(&circle()).unwrap().len(), 2);
    assert_eq!(s.memberships_for_subject(&pk(BOB)).unwrap().len(), 1);
    assert_eq!(s.all_membership_proofs().unwrap().len(), 2);
    assert_eq!(
        s.self_membership(&circle()).unwrap().unwrap().subject_key,
        pk(ALICE)
    );
    assert_eq!(s.self_membership_proofs(now()).unwrap(), vec![p.clone()]);
    assert!(s
        .self_membership_proofs(now().plus_days(31))
        .unwrap()
        .is_empty());
    // is_self never goes back down.
    s.upsert_membership_proof(&p, false, now()).unwrap();
    assert!(s.membership(&digest).unwrap().unwrap().is_self);
}

#[test]
fn membership_integrity_checks() {
    let s = store_with_circle();
    let p = proof(ALICE, &["team"]);
    // Acceptance of another credential.
    let other = proof(BOB, &["team"]);
    let err = s
        .upsert_membership(&p.credential, Some(&other.acceptance), false, now())
        .unwrap_err();
    assert!(matches!(err, StoreError::Mismatch { .. }), "{err:?}");
    // Acceptance signed by the wrong key.
    let forged = ph_protocol::UnsignedAcceptance::for_credential(&p.credential, now())
        .unwrap()
        .sign(&sk(ALICE))
        .unwrap();
    let mut bad = forged.clone();
    bad.signature = other.acceptance.signature;
    assert!(matches!(
        s.upsert_membership(&p.credential, Some(&bad), false, now()),
        Err(StoreError::Protocol(_))
    ));
    // Tampered credential.
    let mut cred = p.credential.clone();
    cred.unsigned.scopes = vec![scope("*")];
    assert!(matches!(
        s.upsert_membership(&cred, None, false, now()),
        Err(StoreError::Protocol(_))
    ));
    // Unknown circle.
    let foreign = ph_protocol::UnsignedMembershipCredential::new(
        pk(9),
        pk(ALICE),
        vec![ph_core::Role::Member],
        vec![scope("team")],
        now(),
        now().plus_days(1),
    )
    .sign(&sk(9))
    .unwrap();
    assert!(matches!(
        s.upsert_membership(&foreign, None, false, now()),
        Err(StoreError::MissingReference)
    ));
    assert!(s.all_memberships().unwrap().is_empty());
}

#[test]
fn issued_invites() {
    let s = store_with_circle();
    let inv = IssuedInviteRow {
        credential_digest: Digest::sha256(b"c"),
        circle_id: circle(),
        invitee_key: pk(BOB),
        created_at: now(),
        invite_expires_at: now().plus_days(1),
    };
    assert!(s.insert_issued_invite(&inv).unwrap());
    assert!(!s.insert_issued_invite(&inv).unwrap());
    assert_eq!(
        s.issued_invites(Some(&circle())).unwrap(),
        vec![inv.clone()]
    );
    assert_eq!(s.issued_invites(None).unwrap(), vec![inv]);
    assert!(s
        .issued_invites(Some(&ph_core::CircleId::derive(&pk(9))))
        .unwrap()
        .is_empty());
}

// ------------------------------------------------------------------- revocations

#[test]
fn revocations_are_idempotent_and_epoch_grows() {
    let s = store_with_circle();
    assert_eq!(s.revocation_epoch(&circle()).unwrap(), 0);
    assert!(!s.is_revoked(&circle(), &pk(BOB)).unwrap());
    assert_eq!(
        s.insert_revocation(&revocation(BOB, 1), now()).unwrap(),
        RevocationInsert::Inserted { epoch: 1 }
    );
    // Same subject with a different nonce: still one revocation.
    assert_eq!(
        s.insert_revocation(&revocation(BOB, 2), now()).unwrap(),
        RevocationInsert::AlreadyRevoked
    );
    assert_eq!(
        s.insert_revocation(&revocation(CAROL, 3), now()).unwrap(),
        RevocationInsert::Inserted { epoch: 2 }
    );
    assert!(s.is_revoked(&circle(), &pk(BOB)).unwrap());
    assert!(!s.is_revoked(&circle(), &pk(ALICE)).unwrap());
    assert_eq!(s.revocation_epoch(&circle()).unwrap(), 2);
    let list = s.revocations_for_circle(&circle()).unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].revocation, revocation(BOB, 1));
    assert_eq!(
        s.revocation(&circle(), &pk(CAROL)).unwrap().unwrap().epoch,
        2
    );
    assert_eq!(s.all_revocations().unwrap().len(), 2);

    // Forged signature.
    let mut forged = revocation(ALICE, 4);
    forged.signature = revocation(BOB, 1).signature;
    assert!(matches!(
        s.insert_revocation(&forged, now()),
        Err(StoreError::Protocol(_))
    ));
    assert!(!s.is_revoked(&circle(), &pk(ALICE)).unwrap());
}

// ------------------------------------------------------------------- peers

#[test]
fn peers() {
    let s = store_with_circle();
    let addrs = vec!["/ip4/127.0.0.1/udp/4001/quic-v1".to_string()];
    assert_eq!(
        s.upsert_peer(&peer_id(1), &pk(BOB), &addrs, now()).unwrap(),
        UpsertPeer::Inserted
    );
    // Empty addrs keep the old ones.
    assert_eq!(
        s.upsert_peer(&peer_id(1), &pk(BOB), &[], now()).unwrap(),
        UpsertPeer::Updated
    );
    assert_eq!(s.peer(&peer_id(1)).unwrap().unwrap().addrs, addrs);
    let addrs2 = vec!["/ip4/10.0.0.1/udp/9/quic-v1".to_string()];
    s.upsert_peer(&peer_id(1), &pk(BOB), &addrs2, now())
        .unwrap();
    assert_eq!(s.peer(&peer_id(1)).unwrap().unwrap().addrs, addrs2);
    // Rebinding id or key fails.
    assert!(matches!(
        s.upsert_peer(&peer_id(1), &pk(CAROL), &[], now()),
        Err(StoreError::Mismatch { .. })
    ));
    assert!(matches!(
        s.upsert_peer(&peer_id(2), &pk(BOB), &[], now()),
        Err(StoreError::Mismatch { .. })
    ));
    // Bad input.
    assert!(matches!(
        s.upsert_peer("bad id", &pk(CAROL), &[], now()),
        Err(StoreError::Invalid { .. })
    ));
    let many: Vec<String> = (0..9)
        .map(|i| format!("/ip4/1.1.1.{i}/udp/1/quic-v1"))
        .collect();
    assert!(matches!(
        s.upsert_peer(&peer_id(3), &pk(CAROL), &many, now()),
        Err(StoreError::Invalid { .. })
    ));
    assert!(matches!(
        s.upsert_peer(&peer_id(3), &pk(CAROL), &["not a multiaddr".into()], now()),
        Err(StoreError::Invalid { .. })
    ));

    s.upsert_peer(&peer_id(2), &pk(CAROL), &[], now()).unwrap();
    assert!(s.add_peer_circle(&peer_id(1), &circle()).unwrap());
    assert!(!s.add_peer_circle(&peer_id(1), &circle()).unwrap());
    assert_eq!(s.peers().unwrap().len(), 2);
    let in_circle = s.peers_for_circle(&circle()).unwrap();
    assert_eq!(in_circle.len(), 1);
    assert_eq!(in_circle[0].circles, vec![circle()]);
    assert_eq!(
        s.peer_by_device_key(&pk(CAROL)).unwrap().unwrap().peer_id,
        peer_id(2)
    );

    s.set_peer_blocked(&peer_id(1), true).unwrap();
    s.set_peer_muted(&peer_id(1), true).unwrap();
    s.touch_peer_last_seen(&peer_id(1), now().plus_secs(10))
        .unwrap();
    s.touch_peer_last_seen(&peer_id(1), now()).unwrap(); // never backwards
    let p = s.peer(&peer_id(1)).unwrap().unwrap();
    assert!(p.blocked && p.muted);
    assert_eq!(p.last_seen, Some(now().plus_secs(10)));
    s.set_peer_blocked(&peer_id(1), false).unwrap();
    assert!(!s.peer(&peer_id(1)).unwrap().unwrap().blocked);
    assert!(matches!(
        s.set_peer_muted("nobody", true),
        Err(StoreError::NotFound { .. })
    ));
    assert!(matches!(
        s.touch_peer_last_seen("nobody", now()),
        Err(StoreError::NotFound { .. })
    ));
    assert!(s.remove_peer_circle(&peer_id(1), &circle()).unwrap());
    assert!(s.peers_for_circle(&circle()).unwrap().is_empty());
}

// ------------------------------------------------------------------- observations

fn obs(id: &str, repo: &str, offset: i64) -> NormalizedObservation {
    NormalizedObservation::from_raw(
        ObservationId::new(id).unwrap(),
        now().plus_secs(offset),
        ObservationSource::Demo,
        Some(Digest::sha256(b"session")),
        repo.into(),
        ObservationKind::UserPrompt,
        "No, use pnpm, not npm.",
    )
}

#[test]
fn observations_recent_and_purge() {
    let s = Store::open_in_memory().unwrap();
    for (i, repo) in ["a", "b", "a", "a", "b"].iter().enumerate() {
        let o = obs(&format!("o{i}"), repo, i as i64 * 60);
        assert!(s
            .insert_observation(&o, o.created_at.plus_days(14))
            .unwrap());
    }
    // Duplicate id is ignored.
    assert!(!s.insert_observation(&obs("o0", "zzz", 0), now()).unwrap());
    assert_eq!(
        s.observation(&ObservationId::new("o0").unwrap())
            .unwrap()
            .unwrap()
            .observation
            .repo_key,
        "a"
    );

    let all = s.recent_observations(None, now(), 100).unwrap();
    assert_eq!(all.len(), 5);
    assert!(all
        .windows(2)
        .all(|w| w[0].observation.created_at <= w[1].observation.created_at));
    let a = s.recent_observations(Some("a"), now(), 2).unwrap();
    // The two most recent of repo a, in chronological order.
    assert_eq!(
        a.iter()
            .map(|o| o.observation.id.as_str())
            .collect::<Vec<_>>(),
        vec!["o2", "o3"]
    );
    let since = s
        .recent_observations(None, now().plus_secs(120), 100)
        .unwrap();
    assert_eq!(since.len(), 3);
    assert_eq!(
        all[0].observation.session_hash,
        Some(Digest::sha256(b"session"))
    );

    // Purge: expiry is created_at + 14 d, so purge at +14 d + 120 s removes o0..o2.
    assert_eq!(
        s.purge_expired_observations(now().plus_days(14).plus_secs(120))
            .unwrap(),
        3
    );
    assert_eq!(s.observation_count().unwrap(), 2);
    assert_eq!(s.purge_expired_observations(now()).unwrap(), 0);
    assert_eq!(
        s.purge_expired_observations(now().plus_days(100)).unwrap(),
        2
    );
    assert_eq!(s.observation_count().unwrap(), 0);
    assert_eq!(default_observation_expiry(now()), now().plus_days(14));
}

#[test]
fn observation_text_is_bounded_backstop() {
    let s = Store::open_in_memory().unwrap();
    let mut o = obs("big", "r", 0);
    o.text = "é".repeat(10_000); // bypasses from_raw
    s.insert_observation(&o, now().plus_days(1)).unwrap();
    let got = s.observation(&o.id).unwrap().unwrap();
    assert!(got.observation.text.len() <= ph_core::MAX_OBSERVATION_TEXT_BYTES);
    let mut o2 = obs("big2", "r", 0);
    o2.repo_key = "r".repeat(300);
    assert!(matches!(
        s.insert_observation(&o2, now()),
        Err(StoreError::Invalid { .. })
    ));
}

// ------------------------------------------------------------------- questions

#[test]
fn questions_dedup_inbox_and_quotas() {
    let s = store_with_circle();
    let q1 = question(BOB, "team/backend", "Should this repo use pnpm?", 1);
    let nq = |e: &ph_protocol::SignedEnvelope, norm: &str, local: bool| {
        NewQuestion::from_envelope(e, norm.into(), local, now()).unwrap()
    };
    assert_eq!(
        s.insert_question(&nq(&q1, "should this repo use pnpm", false))
            .unwrap(),
        QuestionInsert::Inserted
    );
    assert_eq!(
        s.insert_question(&nq(&q1, "should this repo use pnpm", false))
            .unwrap(),
        QuestionInsert::DuplicateEvent
    );
    let q2 = question(CAROL, "team/backend", "should this repo use PNPM", 2);
    assert_eq!(
        s.insert_question(&nq(&q2, "should this repo use pnpm", false))
            .unwrap(),
        QuestionInsert::DuplicateText
    );
    assert!(s
        .question_text_exists(&circle(), "should this repo use pnpm")
        .unwrap());
    assert!(!s.question_text_exists(&circle(), "other").unwrap());
    let q3 = question(BOB, "team/backend", "Tabs or spaces?", 3);
    s.insert_question(&nq(&q3, "tabs or spaces", false))
        .unwrap();
    let mine = question(ALICE, "team/backend", "Use yarn?", 4);
    s.insert_question(&nq(&mine, "use yarn", true)).unwrap();
    // Not a QUESTION.
    let a = answer(BOB, "team/backend", q1.event_id, 5);
    assert!(NewQuestion::from_envelope(&a, "x".into(), false, now()).is_none());

    assert_eq!(s.inbox(&[]).unwrap().len(), 2);
    assert_eq!(s.local_questions().unwrap().len(), 1);
    s.set_question_status(&q1.event_id, QuestionStatus::Answered)
        .unwrap();
    assert_eq!(s.inbox(&[QuestionStatus::New]).unwrap().len(), 1);
    assert_eq!(
        s.inbox(&[QuestionStatus::Answered, QuestionStatus::Muted])
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        s.question(&q1.event_id).unwrap().unwrap().status,
        QuestionStatus::Answered
    );
    assert!(matches!(
        s.set_question_status(
            &EventId::from_digest(Digest::sha256(b"x")),
            QuestionStatus::Muted
        ),
        Err(StoreError::NotFound { .. })
    ));

    assert_eq!(
        s.count_questions_by_author_since(&pk(BOB), now()).unwrap(),
        2
    );
    assert_eq!(
        s.count_questions_by_author_since(&pk(BOB), now().plus_secs(1))
            .unwrap(),
        0
    );
    assert_eq!(
        s.count_questions_by_circle_since(&circle(), now()).unwrap(),
        3
    );
    assert!(matches!(
        s.insert_question(&nq(&q3, "", false)),
        Err(StoreError::Invalid { .. })
    ));
    let row = s.question(&q3.event_id).unwrap().unwrap();
    assert!(!format!("{row:?}").contains("Tabs"));
}

// ------------------------------------------------------------------- bundles, skills, installations

fn bundle_row(content: &[u8]) -> BundleRow {
    let manifest = manifest_for_files(&[("SKILL.md", content)]);
    let digest = bundle_digest(&manifest).unwrap();
    BundleRow {
        digest,
        skill_name: "use-pnpm".into(),
        size: manifest.total_size(),
        manifest,
        rel_path: format!("bundles/{}", digest.to_hex()),
        created_at: now(),
    }
}

#[test]
fn bundles_skills_installations() {
    let s = Store::open_in_memory().unwrap();
    let b1 = bundle_row(b"v1");
    let b2 = bundle_row(b"v2");
    assert!(s.insert_bundle(&b1).unwrap());
    assert!(!s.insert_bundle(&b1).unwrap());
    s.insert_bundle(&b2).unwrap();
    assert_eq!(s.bundle(&b1.digest).unwrap().unwrap(), b1);
    assert_eq!(s.bundles().unwrap().len(), 2);
    // Integrity checks.
    let mut bad = bundle_row(b"v3");
    bad.digest = b1.digest;
    assert!(matches!(
        s.insert_bundle(&bad),
        Err(StoreError::Mismatch { .. })
    ));
    let mut bad = bundle_row(b"v3");
    bad.size += 1;
    assert!(matches!(
        s.insert_bundle(&bad),
        Err(StoreError::Mismatch { .. })
    ));
    let mut bad = bundle_row(b"v3");
    bad.rel_path = "../../etc".into();
    assert!(matches!(
        s.insert_bundle(&bad),
        Err(StoreError::Invalid { .. })
    ));

    // Skills.
    let new = |d: Digest, kind| NewSkill {
        name: "use-pnpm".into(),
        bundle_digest: d,
        origin_kind: kind,
        origin_ref: "cand_0123456789abcdef".into(),
        status: SkillStatus::Available,
        created_at: now(),
    };
    let (id1, c1) = s.insert_skill(&new(b1.digest, SkillOrigin::Local)).unwrap();
    assert!(c1);
    assert_eq!(
        s.insert_skill(&new(b1.digest, SkillOrigin::Local)).unwrap(),
        (id1, false)
    );
    let (id2, _) = s
        .insert_skill(&new(b2.digest, SkillOrigin::Proposal))
        .unwrap();
    assert_eq!(s.skill_by_name("use-pnpm").unwrap().unwrap().id, id2);
    assert_eq!(s.skills_by_name("use-pnpm").unwrap().len(), 2);
    assert_eq!(s.skills().unwrap().len(), 2);
    s.set_skill_status(id1, SkillStatus::Refused, now())
        .unwrap();
    assert_eq!(s.skill(id1).unwrap().unwrap().status, SkillStatus::Refused);
    assert_eq!(
        s.skill(id2).unwrap().unwrap().origin_kind,
        SkillOrigin::Proposal
    );
    assert!(matches!(
        s.set_skill_status(999, SkillStatus::Installed, now()),
        Err(StoreError::NotFound { .. })
    ));
    assert!(matches!(
        s.insert_skill(&new(Digest::sha256(b"missing"), SkillOrigin::Local)),
        Err(StoreError::MissingReference)
    ));

    // Installations with rollback history.
    let inst = |d: Digest, prev: Option<Digest>, t: i64| NewInstallation {
        skill_name: "use-pnpm".into(),
        agent: "claude".into(),
        install_scope: "user".into(),
        path: "/home/u/.claude/skills/use-pnpm".into(),
        bundle_digest: d,
        previous_digest: prev,
        installed_at: now().plus_secs(t),
    };
    let i1 = s.record_install(&inst(b1.digest, None, 0)).unwrap();
    let i2 = s
        .record_install(&inst(b2.digest, Some(b1.digest), 10))
        .unwrap();
    let active = s
        .active_installation("use-pnpm", "claude", "user")
        .unwrap()
        .unwrap();
    assert_eq!(active.id, i2);
    assert_eq!(active.previous_digest, Some(b1.digest));
    let hist = s.installation_history("use-pnpm").unwrap();
    assert_eq!(hist.len(), 2);
    assert_eq!(hist[0].id, i1);
    assert_eq!(
        hist[0].removed_at,
        Some(now().plus_secs(10)),
        "replaced install closed"
    );
    assert_eq!(s.active_installations().unwrap().len(), 1);
    assert!(s
        .active_installation_at(
            "use-pnpm",
            "claude",
            "user",
            "/home/u/.claude/skills/use-pnpm"
        )
        .unwrap()
        .is_some());
    assert!(s
        .active_installation("use-pnpm", "claude", "project")
        .unwrap()
        .is_none());
    assert!(s
        .mark_installation_removed(i2, now().plus_secs(20))
        .unwrap());
    assert!(!s
        .mark_installation_removed(i2, now().plus_secs(30))
        .unwrap());
    assert!(matches!(
        s.mark_installation_removed(999, now()),
        Err(StoreError::NotFound { .. })
    ));
    assert!(s
        .active_installation("use-pnpm", "claude", "user")
        .unwrap()
        .is_none());
    assert!(matches!(
        s.record_install(&inst(Digest::sha256(b"missing"), None, 40)),
        Err(StoreError::MissingReference)
    ));
    // The failed install did not close anything or leave rows behind.
    assert_eq!(s.installation_history("use-pnpm").unwrap().len(), 2);
}

// ------------------------------------------------------------------- sync cursors, notifications

#[test]
fn sync_cursors_and_notifications() {
    let s = store_with_circle();
    s.upsert_peer(&peer_id(1), &pk(BOB), &[], now()).unwrap();
    assert!(s.sync_cursor(&peer_id(1), &circle()).unwrap().is_none());
    s.set_sync_cursor(&peer_id(1), &circle(), now()).unwrap();
    s.set_sync_cursor(&peer_id(1), &circle(), now().plus_secs(5))
        .unwrap();
    assert_eq!(
        s.sync_cursor(&peer_id(1), &circle())
            .unwrap()
            .unwrap()
            .last_sync_at,
        now().plus_secs(5)
    );
    assert_eq!(s.sync_cursors().unwrap().len(), 1);
    assert!(matches!(
        s.set_sync_cursor("unknownpeer", &circle(), now()),
        Err(StoreError::MissingReference)
    ));

    assert_eq!(s.count_notifications_since(now()).unwrap(), 0);
    assert!(s.last_notification_for_topic("pm").unwrap().is_none());
    s.record_notification("pm", now()).unwrap();
    s.record_notification("pm", now().plus_secs(100)).unwrap();
    s.record_notification("style", now().plus_secs(50)).unwrap();
    assert_eq!(s.count_notifications_since(now()).unwrap(), 3);
    assert_eq!(s.count_notifications_since(now().plus_secs(60)).unwrap(), 1);
    assert_eq!(
        s.last_notification_for_topic("pm").unwrap(),
        Some(now().plus_secs(100))
    );
    assert_eq!(
        s.purge_notifications_before(now().plus_secs(60)).unwrap(),
        2
    );
    assert_eq!(s.notifications().unwrap().len(), 1);
    assert!(matches!(
        s.record_notification("", now()),
        Err(StoreError::Invalid { .. })
    ));
}

// ------------------------------------------------------------------ review additions

/// Values that look like SQL are stored and returned verbatim (every query is
/// parameterized) and the schema is untouched.
#[test]
fn sql_metacharacters_are_plain_data() {
    use ph_core::{Confidence, SkillCandidate};
    let s = Store::open_in_memory().unwrap();
    let evil = "x'); DROP TABLE events; --";
    let mut c = circle_row();
    c.name = evil.into();
    s.insert_circle(&c).unwrap();
    assert_eq!(s.circle_by_name(evil).unwrap().unwrap().circle_id, circle());
    assert!(s.circle_by_name("x").unwrap().is_none());

    let cand = SkillCandidate {
        concept_key: format!("{evil} OR 1=1"),
        repo_key: "' OR ''='".into(),
        statement: evil.into(),
        preferred: Some("\"; DELETE FROM candidates; --".into()),
        avoided: None,
        confidence: Confidence::Low,
        evidence: vec![ph_core::ObservationId::new("o1").unwrap()],
        suggested_skill_name: "use-pnpm".into(),
        topic: evil.into(),
    };
    let (id, _) = s.insert_or_merge_candidate(&cand, now()).unwrap();
    let row = s
        .candidate_by_concept(&cand.concept_key, &cand.repo_key)
        .unwrap()
        .unwrap();
    assert_eq!(row.id, id);
    assert_eq!(row.statement, evil);
    assert!(s.candidate_by_concept("x", "").unwrap().is_none());

    s.record_notification(evil, now()).unwrap();
    assert_eq!(s.last_notification_for_topic(evil).unwrap(), Some(now()));
    assert_eq!(s.last_notification_for_topic("x").unwrap(), None);
    assert!(s
        .question_text_exists(&circle(), "' OR 1=1 --")
        .map(|b| !b)
        .unwrap());

    // Everything is still there.
    s.insert_signed_event(&question(ALICE, "team", "q", 1), None, now())
        .unwrap();
    assert_eq!(s.event_count(&circle()).unwrap(), 1);
    assert_eq!(s.candidates(&[]).unwrap().len(), 1);
}
