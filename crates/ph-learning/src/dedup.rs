//! Candidate deduplication (spec 7.2: "deduplicate candidate concepts per
//! repository/scope; avoid proposing an existing skill repeatedly").
//!
//! The store keeps `UNIQUE(concept_key, repo_key)` on the `candidates` table
//! (architecture section 8). Before inserting freshly detected candidates, the caller
//! loads the keys it already has (in any status, including `rejected`, so a dismissed
//! concept is not raised again) and filters with [`filter_known`].

use std::collections::HashSet;

use ph_core::SkillCandidate;

/// The dedup key of a candidate: `(concept_key, repo_key)`.
pub fn dedup_key(candidate: &SkillCandidate) -> (String, String) {
    (candidate.concept_key.clone(), candidate.repo_key.clone())
}

/// Removes candidates whose `(concept_key, repo_key)` is in `known`, and collapses
/// duplicates within `candidates` itself (the first occurrence wins). Order is kept.
pub fn filter_known(
    candidates: Vec<SkillCandidate>,
    known: &HashSet<(String, String)>,
) -> Vec<SkillCandidate> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    candidates
        .into_iter()
        .filter(|c| {
            let key = dedup_key(c);
            !known.contains(&key) && seen.insert(key)
        })
        .collect()
}

/// Removes candidates whose `suggested_skill_name` is already in `skill_names` (for
/// example skills installed or adopted locally), so an existing skill is not proposed
/// again under a different concept key. Order is kept.
pub fn filter_existing_skills(
    candidates: Vec<SkillCandidate>,
    skill_names: &HashSet<String>,
) -> Vec<SkillCandidate> {
    candidates
        .into_iter()
        .filter(|c| !skill_names.contains(&c.suggested_skill_name))
        .collect()
}
