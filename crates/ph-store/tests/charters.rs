//! The accepted charter chain and rule opt-outs (architecture section 10).

mod common;

use common::*;
use ph_core::{Digest, EventId, Scope};
use ph_protocol::{Charter, RollEntry, UnsignedCharter};
use ph_store::{InsertOutcome, Store, StoreError};

/// The successor of `current` that admits `name` (device `seed`).
fn admit(current: &Charter, name: &str, seed: u8) -> Charter {
    let mut next = current.content.clone();
    next.roll
        .push(RollEntry::new(name, vec![pk(seed)], vec![Scope::all()]));
    next.normalize();
    UnsignedCharter::successor(
        current,
        next,
        EventId::from_digest(Digest::sha256(name.as_bytes())),
        now(),
    )
    .unwrap()
    .sign(&sk(ROOT))
    .unwrap()
}

#[test]
fn the_chain_is_stored_in_order_and_the_latest_is_current() {
    let s = store_with_circle();
    assert!(s.current_charter(&circle()).unwrap().is_none());
    assert!(s.charters(&circle()).unwrap().is_empty());

    let c1 = charter();
    assert_eq!(
        s.insert_charter(&c1, now()).unwrap(),
        InsertOutcome::Inserted
    );
    assert_eq!(
        s.insert_charter(&c1, now()).unwrap(),
        InsertOutcome::Duplicate
    );
    assert_eq!(s.current_charter(&circle()).unwrap().unwrap(), c1);

    let c2 = admit(&c1, "dave", 21);
    let c3 = admit(&c2, "erin", 22);
    // A charter that skips its predecessor is refused.
    assert!(matches!(
        s.insert_charter(&c3, now()),
        Err(StoreError::Mismatch { .. })
    ));
    assert_eq!(
        s.insert_charter(&c2, now()).unwrap(),
        InsertOutcome::Inserted
    );
    assert_eq!(
        s.insert_charter(&c3, now()).unwrap(),
        InsertOutcome::Inserted
    );
    assert_eq!(s.current_charter(&circle()).unwrap().unwrap(), c3);
    assert_eq!(
        s.charters(&circle()).unwrap(),
        vec![c1.clone(), c2.clone(), c3.clone()]
    );

    // Every accepted charter can be looked up by the digest a proposal names.
    for c in [&c1, &c2, &c3] {
        let found = s
            .charter_by_digest(&circle(), &c.digest().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(&found, c);
    }
    assert!(s
        .charter_by_digest(&circle(), &Digest::sha256(b"nope"))
        .unwrap()
        .is_none());
    // An earlier charter cannot be re-inserted as if it were new, and a rival
    // successor of charter 1 is refused once charter 2 is current.
    assert_eq!(
        s.insert_charter(&c2, now()).unwrap(),
        InsertOutcome::Duplicate
    );
    let rival = admit(&c1, "mallory", 66);
    assert!(matches!(
        s.insert_charter(&rival, now()),
        Err(StoreError::Mismatch { .. })
    ));
    assert_eq!(s.charters(&circle()).unwrap().len(), 3);
}

#[test]
fn a_late_joiner_starts_from_the_charter_in_its_invitation() {
    let c1 = charter();
    let c2 = admit(&c1, "dave", 21);
    let c3 = admit(&c2, "erin", 22);
    // This node never saw charters 1 and 2. Charter 3 is its trust anchor.
    let s = store_with_circle();
    assert_eq!(
        s.insert_charter(&c3, now()).unwrap(),
        InsertOutcome::Inserted
    );
    assert_eq!(s.current_charter(&circle()).unwrap().unwrap().seq, 3);
    // From there on the chain rule applies.
    let c4 = admit(&c3, "frank", 23);
    assert!(matches!(
        s.insert_charter(&admit(&c4, "gina", 24), now()),
        Err(StoreError::Mismatch { .. })
    ));
    assert_eq!(
        s.insert_charter(&c4, now()).unwrap(),
        InsertOutcome::Inserted
    );
    // It cannot be walked backwards either.
    assert!(matches!(
        s.insert_charter(&c2, now()),
        Err(StoreError::Mismatch { .. })
    ));
}

#[test]
fn only_authentic_charters_of_a_known_circle_are_stored() {
    let s = store_with_circle();
    let c1 = charter();

    // Edited after signing.
    let mut tampered = c1.clone();
    tampered.unsigned.content.rules.binding = false;
    assert!(matches!(
        s.insert_charter(&tampered, now()),
        Err(StoreError::Protocol(_))
    ));

    // A valid charter of a circle this node does not know.
    let foreign = UnsignedCharter::founding(pk(9), c1.content.clone(), now())
        .sign(&sk(9))
        .unwrap();
    assert!(matches!(
        s.insert_charter(&foreign, now()),
        Err(StoreError::MissingReference)
    ));
    assert!(s.current_charter(&circle()).unwrap().is_none());
}

#[test]
fn a_tampered_database_cannot_change_the_roll() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peerharness.db");
    let c1 = charter();
    {
        let s = Store::open(&path).unwrap();
        s.insert_circle(&circle_row()).unwrap();
        s.insert_charter(&c1, now()).unwrap();
    }
    // Someone with file access rewrites the stored roll to add a member.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let json: String = conn
            .query_row("SELECT charter_json FROM charters", [], |r| r.get(0))
            .unwrap();
        let forged = json.replace("\"member\":\"alice\"", "\"member\":\"aaron\"");
        assert_ne!(forged, json);
        conn.execute("UPDATE charters SET charter_json = ?1", [forged])
            .unwrap();
    }
    let s = Store::open(&path).unwrap();
    assert!(matches!(
        s.current_charter(&circle()),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn rule_opt_outs() {
    let s = store_with_circle();
    assert!(!s
        .is_rule_opted_out(&circle(), "pnpm-repository-convention")
        .unwrap());
    assert!(s.rule_opt_outs(&circle()).unwrap().is_empty());

    s.set_rule_opt_out(&circle(), "pnpm-repository-convention", now())
        .unwrap();
    // Idempotent: the first opt-out time is kept.
    s.set_rule_opt_out(&circle(), "pnpm-repository-convention", now().plus_secs(60))
        .unwrap();
    s.set_rule_opt_out(&circle(), "avoid-pip-convention", now())
        .unwrap();
    assert!(s
        .is_rule_opted_out(&circle(), "pnpm-repository-convention")
        .unwrap());
    assert_eq!(
        s.rule_opt_outs(&circle()).unwrap(),
        vec![
            ("avoid-pip-convention".to_owned(), now()),
            ("pnpm-repository-convention".to_owned(), now()),
        ]
    );

    assert!(s
        .clear_rule_opt_out(&circle(), "pnpm-repository-convention")
        .unwrap());
    assert!(!s
        .clear_rule_opt_out(&circle(), "pnpm-repository-convention")
        .unwrap());
    assert!(!s
        .is_rule_opted_out(&circle(), "pnpm-repository-convention")
        .unwrap());

    // Not a skill name, and not a known circle.
    assert!(matches!(
        s.set_rule_opt_out(&circle(), "../etc/passwd", now()),
        Err(StoreError::Invalid { .. })
    ));
    assert!(matches!(
        s.set_rule_opt_out(&ph_core::CircleId::derive(&pk(9)), "pnpm", now()),
        Err(StoreError::MissingReference)
    ));
}

#[test]
fn rule_installs_remember_what_a_vote_put_on_this_machine() {
    let s = store_with_circle();
    let d1 = ph_core::Digest::domain("test", b"one");
    let d2 = ph_core::Digest::domain("test", b"two");
    assert!(s.rule_installs(&circle()).unwrap().is_empty());

    s.record_rule_install(&circle(), "pnpm", &d1, now())
        .unwrap();
    s.record_rule_install(&circle(), "avoid-pip", &d1, now())
        .unwrap();
    // A later version of the same rule replaces the record.
    s.record_rule_install(&circle(), "pnpm", &d2, now().plus_secs(5))
        .unwrap();
    assert_eq!(
        s.rule_installs(&circle()).unwrap(),
        vec![
            ("avoid-pip".to_owned(), d1, now()),
            ("pnpm".to_owned(), d2, now().plus_secs(5)),
        ]
    );

    assert!(s.clear_rule_install(&circle(), "pnpm").unwrap());
    assert!(!s.clear_rule_install(&circle(), "pnpm").unwrap());
    assert_eq!(s.rule_installs(&circle()).unwrap().len(), 1);

    assert!(matches!(
        s.record_rule_install(&circle(), "../x", &d1, now()),
        Err(StoreError::Invalid { .. })
    ));
    assert!(matches!(
        s.record_rule_install(&ph_core::CircleId::derive(&pk(9)), "pnpm", &d1, now()),
        Err(StoreError::MissingReference)
    ));
    // It is part of the owner's export.
    let export = s.export_owned_json().unwrap();
    assert_eq!(export["rule_installs"][0]["skill_name"], "avoid-pip");
}

#[test]
fn earlier_charters_are_stored_as_history_only_through_the_hash_link() {
    let c1 = charter();
    let c2 = admit(&c1, "dave", 21);
    let c3 = admit(&c2, "erin", 22);
    let s = store_with_circle();
    // Nothing to link to yet.
    assert!(matches!(
        s.insert_charter_history(&c1, now()),
        Err(StoreError::MissingReference)
    ));
    s.insert_charter(&c3, now()).unwrap();
    assert_eq!(s.oldest_charter(&circle()).unwrap().unwrap().seq, 3);

    // Charter 1 is not the predecessor charter 3 names: it has to wait for charter 2.
    assert!(matches!(
        s.insert_charter_history(&c1, now()),
        Err(StoreError::Mismatch { .. })
    ));
    // A different charter with the right number is not the one charter 3 names either.
    let other2 = admit(&c1, "mallory", 66);
    assert_eq!(other2.seq, 2);
    assert!(matches!(
        s.insert_charter_history(&other2, now()),
        Err(StoreError::Mismatch { .. })
    ));
    // Nor is a later charter history.
    assert!(matches!(
        s.insert_charter_history(&admit(&c3, "frank", 23), now()),
        Err(StoreError::Mismatch { .. })
    ));

    assert_eq!(
        s.insert_charter_history(&c2, now()).unwrap(),
        InsertOutcome::Inserted
    );
    assert_eq!(
        s.insert_charter_history(&c2, now()).unwrap(),
        InsertOutcome::Duplicate
    );
    assert_eq!(
        s.insert_charter_history(&c1, now()).unwrap(),
        InsertOutcome::Inserted
    );
    // History never becomes the current charter, and the chain still grows forward.
    assert_eq!(s.current_charter(&circle()).unwrap().unwrap().seq, 3);
    assert_eq!(s.oldest_charter(&circle()).unwrap().unwrap().seq, 1);
    let seqs: Vec<u64> = s
        .charters(&circle())
        .unwrap()
        .iter()
        .map(|c| c.seq)
        .collect();
    assert_eq!(seqs, [1, 2, 3]);
    for c in [&c1, &c2] {
        assert_eq!(
            s.charter_by_digest(&circle(), &c.digest().unwrap())
                .unwrap()
                .unwrap()
                .seq,
            c.seq
        );
    }
    s.insert_charter(&admit(&c3, "frank", 23), now()).unwrap();
    assert_eq!(s.current_charter(&circle()).unwrap().unwrap().seq, 4);
}
