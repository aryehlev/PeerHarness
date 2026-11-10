//! The database and its export never contain private key material, and errors never
//! contain stored content.

mod common;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use common::*;
use ph_core::{
    Confidence, DeviceKey, NormalizedObservation, ObservationId, ObservationKind,
    ObservationSource, SkillCandidate,
};
use ph_protocol::SigningKey;
use ph_store::{default_observation_expiry, IdentityMetadata, Store, StoreError};

const SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Fills a file-backed store with every kind of row, all derived from a device whose
/// private seed is `SEED`.
fn populated(path: &std::path::Path) -> Store {
    let device = SigningKey::from_bytes(&SEED);
    let device_pk = DeviceKey::from_signing_key(&device);
    let s = Store::open(path).unwrap();
    s.set_identity(&IdentityMetadata {
        device_key: device_pk,
        keystore_backend: "file".into(),
        keystore_ref: "keys/device.key".into(),
        created_at: now(),
    })
    .unwrap();
    s.insert_circle(&circle_row()).unwrap();
    // A credential for the seed device.
    let cred = ph_protocol::UnsignedMembershipCredential::new(
        pk(ROOT),
        device_pk,
        vec![ph_core::Role::Member],
        vec![scope("team")],
        now(),
        now().plus_days(30),
    )
    .sign(&sk(ROOT))
    .unwrap();
    let acc = ph_protocol::UnsignedAcceptance::for_credential(&cred, now())
        .unwrap()
        .sign(&device)
        .unwrap();
    s.upsert_membership(&cred, Some(&acc), true, now()).unwrap();
    // An event signed by the seed device.
    let e = ph_protocol::EnvelopeBuilder::new(
        circle(),
        scope("team"),
        ph_protocol::EventBody::Question(ph_protocol::QuestionBody {
            question: "Use pnpm?".into(),
            topic: "pm".into(),
            related_candidate: None,
        }),
    )
    .sign(&device, now())
    .unwrap();
    s.insert_signed_event(&e, None, now()).unwrap();
    let o = NormalizedObservation::from_raw(
        ObservationId::new("o1").unwrap(),
        now(),
        ObservationSource::Demo,
        None,
        "r".into(),
        ObservationKind::UserPrompt,
        "No, use pnpm, not npm. token=sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
    s.insert_observation(&o, default_observation_expiry(now()))
        .unwrap();
    s.insert_or_merge_candidate(
        &SkillCandidate {
            concept_key: "pm:pnpm".into(),
            repo_key: "r".into(),
            statement: "Use pnpm.".into(),
            preferred: None,
            avoided: None,
            confidence: Confidence::Low,
            evidence: vec![ObservationId::new("o1").unwrap()],
            suggested_skill_name: "use-pnpm".into(),
            topic: "pm".into(),
        },
        now(),
    )
    .unwrap();
    s.upsert_peer(
        &peer_id(1),
        &pk(BOB),
        &["/ip4/127.0.0.1/udp/4001/quic-v1".into()],
        now(),
    )
    .unwrap();
    s.record_notification("pm", now()).unwrap();
    s
}

#[test]
fn database_file_contains_no_private_seed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.db");
    let s = populated(&path);
    // Scan both before and after checkpointing (WAL contents, then the main file).
    let encodings: Vec<Vec<u8>> = vec![
        SEED.to_vec(),
        hex::encode(SEED).into_bytes(),
        URL_SAFE_NO_PAD.encode(SEED).into_bytes(),
        STANDARD.encode(SEED).into_bytes(),
    ];
    let scan = |label: &str| {
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let p = entry.unwrap().path();
            let bytes = std::fs::read(&p).unwrap();
            for enc in &encodings {
                assert!(
                    !contains(&bytes, enc),
                    "{label}: seed found in {}",
                    p.display()
                );
            }
        }
    };
    scan("before checkpoint");
    s.checkpoint().unwrap();
    scan("after checkpoint");
    // Sanity: the public key *is* in there, so the scan does look at real content.
    let pubkey = DeviceKey::from_signing_key(&SigningKey::from_bytes(&SEED)).to_string();
    let main = std::fs::read(&path).unwrap();
    assert!(contains(&main, pubkey.as_bytes()));
}

#[test]
fn export_covers_tables_and_has_no_private_material() {
    let dir = tempfile::tempdir().unwrap();
    let s = populated(&dir.path().join("p.db"));
    let v = s.export_owned_json().unwrap();
    assert_eq!(v["schema"], ph_store::EXPORT_SCHEMA);
    for table in [
        "circles",
        "memberships",
        "issued_invites",
        "revocations",
        "peers",
        "observations",
        "candidates",
        "questions",
        "events",
        "outbox",
        "bundles",
        "skills",
        "installations",
        "sync_cursors",
        "notifications",
    ] {
        assert!(v[table].is_array(), "missing {table}");
    }
    assert!(v["identity"].is_object());
    assert_eq!(v["observations"].as_array().unwrap().len(), 1);
    assert_eq!(v["events"].as_array().unwrap().len(), 1);
    assert_eq!(v["events"][0]["envelope"]["type"], "QUESTION");
    assert_eq!(
        v["memberships"][0]["credential"]["schema"],
        "peerharness.membership/0.1"
    );
    assert_eq!(v["identity"]["created_at"], "2026-11-09T18:10:00Z");

    let text = serde_json::to_string(&v).unwrap();
    let lower = text.to_lowercase();
    for forbidden in ["seed", "private", "secret_key", "signing_key"] {
        assert!(!lower.contains(forbidden), "export contains {forbidden:?}");
    }
    assert!(!text.contains(&hex::encode(SEED)));
    assert!(!text.contains(&URL_SAFE_NO_PAD.encode(SEED)));
    // Observations were redacted on the way in.
    assert!(!text.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
}

#[test]
fn errors_and_debug_do_not_leak_content() {
    let s = store_with_circle();
    let secret = "SECRET-CIRCLE-NAME";
    let mut c = circle_row();
    c.name = secret.into();
    let err = s.insert_circle(&c).unwrap_err(); // same id
    assert!(matches!(err, StoreError::AlreadyExists { .. }));
    assert!(!err.to_string().contains(secret));
    assert!(!format!("{err:?}").contains(secret));
    assert!(!format!("{c:?}").contains(secret));

    // Bad multiline name.
    let mut c2 = circle_row();
    c2.circle_id = ph_core::CircleId::derive(&pk(8));
    c2.root_key = pk(8);
    c2.name = format!("{secret}\nx");
    let err = s.insert_circle(&c2).unwrap_err();
    assert!(!err.to_string().contains(secret));

    // Corrupt stored data surfaces as Corrupt without echoing it.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.db");
    let st = Store::open(&path).unwrap();
    st.insert_circle(&circle_row()).unwrap();
    {
        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute("UPDATE circles SET root_key = 'SECRET-garbage'", [])
            .unwrap();
    }
    let err = st.circles().unwrap_err();
    assert!(matches!(err, StoreError::Corrupt { .. }), "{err:?}");
    assert!(!err.to_string().contains("SECRET"));
}
