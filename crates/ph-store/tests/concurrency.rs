//! Concurrent writers on one database file (hooks, CLI and daemon share it).

mod common;

use std::collections::HashSet;
use std::sync::{Arc, Barrier};

use common::*;
use ph_core::{
    NormalizedObservation, ObservationId, ObservationKind, ObservationSource, Timestamp,
};
use ph_store::{default_observation_expiry, Store, DEFAULT_BUSY_TIMEOUT_MS};

const THREADS: usize = 8;
const PER_THREAD: usize = 150;

fn obs(thread: usize, i: usize) -> NormalizedObservation {
    NormalizedObservation::from_raw(
        ObservationId::new(&format!("obs_t{thread}_{i}")).unwrap(),
        now().plus_secs(i64::try_from(i).unwrap()),
        ObservationSource::Hook,
        None,
        format!("repo{}", thread % 3),
        ObservationKind::UserPrompt,
        "No, use pnpm, not npm.",
    )
}

/// Each thread is one "hook process": its own connection, opened concurrently, inserting
/// as fast as it can. No row may be lost and nobody may see SQLITE_BUSY at a 5 s timeout.
fn hammer(path: &std::path::Path) {
    let barrier = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let path = path.to_owned();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || -> Result<(), String> {
                barrier.wait();
                let s = Store::open_with_busy_timeout(&path, DEFAULT_BUSY_TIMEOUT_MS)
                    .map_err(|e| format!("open: {e}"))?;
                for i in 0..PER_THREAD {
                    let o = obs(t, i);
                    let inserted = s
                        .insert_observation(&o, default_observation_expiry(o.created_at))
                        .map_err(|e| format!("insert: {e}"))?;
                    if !inserted {
                        return Err("unexpected duplicate".into());
                    }
                }
                Ok(())
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn concurrent_hook_writes_on_existing_db_lose_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peerharness.db");
    drop(Store::open(&path).unwrap());
    hammer(&path);
    let s = Store::open(&path).unwrap();
    assert_eq!(
        s.observation_count().unwrap(),
        (THREADS * PER_THREAD) as u64
    );
    let all = s.all_observations().unwrap();
    let ids: HashSet<String> = all.iter().map(|o| o.observation.id.to_string()).collect();
    assert_eq!(ids.len(), THREADS * PER_THREAD);
    assert!(s.quick_check().unwrap());
}

#[test]
fn concurrent_first_open_migrates_once_and_loses_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fresh.db");
    hammer(&path);
    let s = Store::open(&path).unwrap();
    assert_eq!(s.schema_version().unwrap(), ph_store::SCHEMA_VERSION);
    assert_eq!(
        s.observation_count().unwrap(),
        (THREADS * PER_THREAD) as u64
    );
}

#[test]
fn concurrent_candidate_merges_produce_one_candidate() {
    use ph_core::{Confidence, SkillCandidate};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.db");
    drop(Store::open(&path).unwrap());
    let barrier = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let s = Store::open(&path).unwrap();
                barrier.wait();
                let c = SkillCandidate {
                    concept_key: "package-manager:pnpm".into(),
                    repo_key: "r".into(),
                    statement: "Use pnpm.".into(),
                    preferred: None,
                    avoided: None,
                    confidence: Confidence::Low,
                    evidence: vec![ObservationId::new(&format!("o{t}")).unwrap()],
                    suggested_skill_name: "use-pnpm".into(),
                    topic: "pm".into(),
                };
                s.insert_or_merge_candidate(&c, Timestamp::now()).unwrap()
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|(_, created)| *created).count(), 1);
    let ids: HashSet<_> = results.iter().map(|(id, _)| id.clone()).collect();
    assert_eq!(ids.len(), 1);
    let s = Store::open(&path).unwrap();
    let rows = s.candidates(&[]).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].evidence.len(),
        THREADS,
        "every merge kept its evidence"
    );
    assert_eq!(rows[0].confidence, Confidence::Medium);
}

#[test]
fn short_busy_timeout_reports_busy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.db");
    let holder = Store::open(&path).unwrap();
    let hook = Store::open_with_busy_timeout(&path, 50).unwrap();
    // Hold the write lock in another connection.
    holder
        .transaction(|h| {
            h.record_notification("lock", now())?;
            let o = obs(0, 0);
            let err = hook
                .insert_observation(&o, default_observation_expiry(o.created_at))
                .unwrap_err();
            assert!(err.is_busy(), "{err:?}");
            Ok(())
        })
        .unwrap();
    // Once released, the hook connection writes fine.
    let o = obs(0, 0);
    assert!(hook
        .insert_observation(&o, default_observation_expiry(o.created_at))
        .unwrap());
}
