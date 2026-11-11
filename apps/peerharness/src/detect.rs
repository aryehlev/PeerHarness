//! Local learning: spool drain, observation storage and deterministic candidate
//! detection. Everything here is local only; nothing is shared.

use std::collections::HashSet;
use std::path::Path;

use ph_core::{NormalizedObservation, Timestamp};
use ph_learning::{CandidateDetector, DeterministicDetector};
use ph_store::{CandidateId, Store};

/// Observations considered per detection run.
pub const DETECTION_WINDOW: usize = 500;

/// Result of a detection run.
#[derive(Debug, Default)]
pub struct DetectSummary {
    pub created: Vec<CandidateId>,
    pub merged: Vec<CandidateId>,
}

/// Stores an observation with the configured retention.
pub fn store_observation(
    store: &Store,
    obs: &NormalizedObservation,
    retention_secs: i64,
) -> ph_store::Result<bool> {
    store.insert_observation(obs, obs.created_at.plus_secs(retention_secs))
}

/// Why a drain stored nothing.
#[derive(Debug)]
enum DrainError {
    Store(ph_store::StoreError),
    Spool(ph_observer::SpoolError),
}

impl From<ph_store::StoreError> for DrainError {
    fn from(e: ph_store::StoreError) -> Self {
        DrainError::Store(e)
    }
}

/// Moves spooled hook observations into the database. Returns the number inserted.
///
/// The order is what keeps a line from being lost (ADR-050). The write lock of the
/// database is taken first. While another process holds it, this waits once for the
/// connection's busy timeout and leaves the spool as it is: nothing was claimed. With
/// the lock in hand the spool is claimed and its lines are inserted in the one
/// transaction, and the claim files are deleted only after it is committed. If
/// anything fails in between, the transaction stores nothing and the claim files
/// stay, to be read again by a later drain. Inserting is idempotent by observation id.
///
/// It used to delete the spool once it was read, insert line by line, each insert
/// waiting for the lock on its own, and append what failed to the spool again, where
/// a full spool dropped it.
pub fn drain_spool(spool: &Path, store: &Store, retention_secs: i64) -> usize {
    let taken = store.transaction_with(|store| -> Result<_, DrainError> {
        let claimed = ph_observer::claim_spool(spool).map_err(DrainError::Spool)?;
        let mut inserted = 0;
        for obs in &claimed.observations {
            if store_observation(store, obs, retention_secs)? {
                inserted += 1;
            }
        }
        Ok((claimed, inserted))
    });
    match taken {
        Ok((claimed, inserted)) => {
            let skipped = claimed.skipped_lines;
            if let Err(e) = claimed.release() {
                // The rows are stored. A claim file that stays is read again later,
                // and inserts nothing twice.
                tracing::warn!(error = %e, "cannot delete a drained spool file");
            }
            if inserted + skipped > 0 {
                tracing::info!(inserted, skipped, "drained observation spool");
            }
            inserted
        }
        Err(DrainError::Store(e)) if e.is_busy() => {
            tracing::debug!("the database is busy: the observation spool stays as it is");
            0
        }
        Err(DrainError::Store(e)) => {
            tracing::warn!(error = %e, "cannot store the observation spool; it is kept");
            0
        }
        Err(DrainError::Spool(e)) => {
            tracing::warn!(error = %e, "cannot drain the observation spool");
            0
        }
    }
}

/// Runs the deterministic detector over recent observations (optionally one repo) and
/// records candidates (new ones as Detected). Known concepts get new evidence merged;
/// terminal (adopted/rejected/superseded) candidates are left unchanged by the store; a
/// new concept whose suggested skill name already exists in the library is skipped.
pub fn run_detection(
    store: &Store,
    repo_key: Option<&str>,
    retention_secs: i64,
    now: Timestamp,
) -> ph_store::Result<DetectSummary> {
    let since = now.minus_secs(retention_secs);
    let obs: Vec<NormalizedObservation> = store
        .recent_observations(repo_key, since, DETECTION_WINDOW)?
        .into_iter()
        .map(|s| s.observation)
        .collect();
    let detected = DeterministicDetector::new().detect(&obs);
    let skill_names: HashSet<String> = store.skills()?.into_iter().map(|s| s.name).collect();
    let mut summary = DetectSummary::default();
    for c in detected {
        match store.candidate_by_concept(&c.concept_key, &c.repo_key)? {
            Some(existing) => {
                let known: HashSet<_> = existing.evidence.iter().collect();
                if c.evidence.iter().all(|e| known.contains(e)) || existing.status.is_terminal() {
                    continue;
                }
                let (id, _) = store.insert_or_merge_candidate(&c, now)?;
                summary.merged.push(id);
            }
            None => {
                if skill_names.contains(&c.suggested_skill_name) {
                    continue;
                }
                // A correction that names only one side ("no, use pnpm", "stop using
                // npm") is easy to mistake for an ordinary request, so it becomes a
                // candidate only when it was said twice. One that names both what to
                // use and what to avoid stands on one sentence, as before.
                let one_sided = c.preferred.is_none() || c.avoided.is_none();
                if one_sided && c.evidence.len() < 2 {
                    continue;
                }
                let (id, created) = store.insert_or_merge_candidate(&c, now)?;
                if created {
                    summary.created.push(id);
                } else {
                    summary.merged.push(id);
                }
            }
        }
    }
    if !summary.created.is_empty() || !summary.merged.is_empty() {
        tracing::info!(
            observations = obs.len(),
            created = summary.created.len(),
            merged = summary.merged.len(),
            "candidate detection"
        );
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ph_core::{ObservationId, ObservationKind, ObservationSource};

    fn prompt(text: &str, repo: &str, now: Timestamp) -> NormalizedObservation {
        NormalizedObservation::from_raw(
            ObservationId::random().unwrap(),
            now,
            ObservationSource::Demo,
            None,
            repo.into(),
            ObservationKind::UserPrompt,
            text,
        )
    }

    /// The spool loses no line while the database is busy (ADR-050). The drain used
    /// to delete the spool once it had read it, wait for the lock once for every
    /// line, and append each line that failed to the spool again.
    ///
    /// No sleeps and no threads: neither connection waits (busy timeout 0), and the
    /// other one holds the write lock while this one drains.
    #[test]
    fn a_drain_while_the_database_is_busy_leaves_the_spool_as_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peerharness.db");
        let store = Store::open_with_busy_timeout(&path, 0).unwrap();
        let spool = ph_observer::spool::spool_path(dir.path());
        let now = Timestamp::now();
        let ret = 14 * 86_400;
        let lines: Vec<_> = (0..40)
            .map(|i| prompt(&format!("Use tabs in module {i}."), "r", now))
            .collect();
        for obs in &lines {
            ph_observer::append_observation(&spool, obs).unwrap();
        }
        let before = std::fs::read(&spool).unwrap();
        let in_spool_dir = || std::fs::read_dir(spool.parent().unwrap()).unwrap().count();

        // Another process writes. Nothing is claimed, nothing is stored, and the
        // spool is byte for byte what it was.
        let other = Store::open_with_busy_timeout(&path, 0).unwrap();
        other
            .transaction(|_| {
                assert_eq!(drain_spool(&spool, &store, ret), 0);
                Ok(())
            })
            .unwrap();
        assert_eq!(std::fs::read(&spool).unwrap(), before);
        assert_eq!(in_spool_dir(), 1, "no claim file was made");
        assert!(store
            .recent_observations(None, now.minus_secs(60), 500)
            .unwrap()
            .is_empty());

        // The lock is free: every line is stored, and the spool is gone.
        assert_eq!(drain_spool(&spool, &store, ret), lines.len());
        assert_eq!(in_spool_dir(), 0);
        assert_eq!(
            store
                .recent_observations(None, now.minus_secs(60), 500)
                .unwrap()
                .len(),
            lines.len()
        );
        // Again: nothing to do, and nothing stored twice.
        assert_eq!(drain_spool(&spool, &store, ret), 0);

        // Lines that a drain claimed and could not store are in a claim file. A later
        // drain stores them, with what the spool got meanwhile, each once.
        for obs in &lines[..3] {
            ph_observer::append_observation(&spool, obs).unwrap();
        }
        let fresh = prompt("Use spaces in module 99.", "r", now);
        ph_observer::append_observation(&spool, &fresh).unwrap();
        drop(ph_observer::claim_spool(&spool).unwrap());
        assert_eq!(in_spool_dir(), 1);
        let claim = std::fs::read_dir(spool.parent().unwrap())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let stale = format!(
            "{}-{}-1-0",
            ph_observer::spool::processing_path(&spool).display(),
            now.unix_seconds() - 3600
        );
        std::fs::rename(claim, stale).unwrap();
        assert_eq!(
            drain_spool(&spool, &store, ret),
            1,
            "only the new line is new"
        );
        assert_eq!(in_spool_dir(), 0);
    }

    #[test]
    fn detects_and_merges() {
        let s = Store::open_in_memory().unwrap();
        let now = Timestamp::now();
        let ret = 14 * 86_400;
        store_observation(&s, &prompt("No, use pnpm, not npm.", "r", now), ret).unwrap();
        let a = run_detection(&s, Some("r"), ret, now).unwrap();
        assert_eq!(a.created.len(), 1);
        // Re-running with no new evidence changes nothing.
        let b = run_detection(&s, Some("r"), ret, now).unwrap();
        assert!(b.created.is_empty() && b.merged.is_empty());
        store_observation(&s, &prompt("No, use pnpm, not npm!", "r", now), ret).unwrap();
        let c = run_detection(&s, None, ret, now).unwrap();
        assert_eq!(c.merged, a.created);
        let row = s.candidate(&a.created[0]).unwrap().unwrap();
        assert_eq!(row.evidence.len(), 2);
        assert_eq!(row.confidence, ph_core::Confidence::Medium);
        // A one-sided correction needs to be said twice before it is worth a review.
        store_observation(&s, &prompt("no, use ripgrep", "r3", now), ret).unwrap();
        assert!(run_detection(&s, Some("r3"), ret, now)
            .unwrap()
            .created
            .is_empty());
        store_observation(&s, &prompt("No, use ripgrep.", "r3", now), ret).unwrap();
        let again = run_detection(&s, Some("r3"), ret, now).unwrap();
        assert_eq!(again.created.len(), 1);
        let row = s.candidate(&again.created[0]).unwrap().unwrap();
        assert_eq!(row.preferred.as_deref(), Some("ripgrep"));
        assert!(row.avoided.is_none());
        // Benign prompts give nothing.
        store_observation(&s, &prompt("Please add a README section.", "r2", now), ret).unwrap();
        assert!(run_detection(&s, Some("r2"), ret, now)
            .unwrap()
            .created
            .is_empty());
    }
}
