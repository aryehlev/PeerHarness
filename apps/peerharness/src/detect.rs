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

/// Moves spooled hook observations into the database. Observations that cannot be
/// inserted are appended to the spool again. Returns the number inserted.
pub fn drain_spool(spool: &Path, store: &Store, retention_secs: i64) -> usize {
    let drained = match ph_observer::drain(spool) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "cannot drain the observation spool");
            return 0;
        }
    };
    let mut inserted = 0;
    let mut requeued = 0;
    for obs in &drained.observations {
        match store_observation(store, obs, retention_secs) {
            Ok(true) => inserted += 1,
            Ok(false) => {}
            Err(_) => {
                requeued += 1;
                let _ = ph_observer::append_observation(spool, obs);
            }
        }
    }
    if inserted + requeued + drained.skipped_lines > 0 {
        tracing::info!(
            inserted,
            requeued,
            skipped = drained.skipped_lines,
            "drained observation spool"
        );
    }
    inserted
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
