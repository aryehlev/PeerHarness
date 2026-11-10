//! Id arguments: full ids or unique prefixes of at least 8 hex characters, as git does.
use anyhow::Result;
use ph_core::{Digest, EventId};
use ph_store::{CandidateId, CandidateRow, SkillRow, Store};

use crate::error::usage;

/// Minimum hex characters of a prefix.
pub const MIN_PREFIX_HEX: usize = 8;

/// Normalizes an id argument to lowercase hex (prefix) after an optional `sha256:`.
fn hex_part<'a>(arg: &'a str, prefix: &str) -> Option<&'a str> {
    let h = arg.strip_prefix(prefix).unwrap_or(arg);
    (!h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit())).then_some(h)
}

/// Picks the unique element whose hex id starts with `hex` (case-insensitive).
fn unique<T>(items: Vec<(String, T)>, hex: &str, what: &str) -> Result<T> {
    let hex = hex.to_ascii_lowercase();
    if hex.len() < MIN_PREFIX_HEX {
        return Err(usage(format!(
            "{what} prefix is too short: give at least {MIN_PREFIX_HEX} hex characters"
        )));
    }
    let mut found: Vec<T> = items
        .into_iter()
        .filter(|(h, _)| h.starts_with(&hex))
        .map(|(_, t)| t)
        .collect();
    match found.len() {
        0 => Err(usage(format!("no {what} matches that id"))),
        1 => Ok(found.remove(0)),
        n => Err(usage(format!(
            "that prefix matches {n} {what}s: give more characters"
        ))),
    }
}

/// Resolves an event id or prefix among stored events.
pub fn resolve_event(store: &Store, arg: &str) -> Result<EventId> {
    let arg = arg.trim();
    if let Ok(id) = arg.parse::<EventId>() {
        return Ok(id);
    }
    let hex = hex_part(arg, "sha256:")
        .ok_or_else(|| usage("not an event id: expected sha256:<hex> or a hex prefix"))?;
    let events = store.all_events()?;
    unique(
        events
            .into_iter()
            .map(|e| (e.event_id.to_hex(), e.event_id))
            .collect(),
        hex,
        "event",
    )
}

/// Resolves a candidate id or `cand_` prefix.
pub fn resolve_candidate(store: &Store, arg: &str) -> Result<CandidateRow> {
    let arg = arg.trim();
    if let Ok(id) = arg.parse::<CandidateId>() {
        return store
            .candidate(&id)?
            .ok_or_else(|| usage("no candidate with that id"));
    }
    let hex = hex_part(arg, "cand_")
        .ok_or_else(|| usage("not a candidate id: expected cand_<hex> or a unique prefix"))?;
    let rows = store.candidates(&[])?;
    unique(
        rows.into_iter()
            .map(|c| {
                let h = c.id.as_str().trim_start_matches("cand_").to_owned();
                (h, c)
            })
            .collect(),
        hex,
        "candidate",
    )
}

// Used by the `skills` commands, which are not implemented in this build yet.
#[allow(dead_code)]
/// Resolves a skill by row id (number), candidate id (`cand_…`), bundle digest (prefix)
/// or name (the latest row with that name).
pub fn resolve_skill(store: &Store, arg: &str) -> Result<SkillRow> {
    let arg = arg.trim();
    if !arg.is_empty() && arg.bytes().all(|b| b.is_ascii_digit()) {
        let id: i64 = arg.parse().map_err(|_| usage("skill id is out of range"))?;
        return store
            .skill(id)?
            .ok_or_else(|| usage("no skill with that id"));
    }
    if arg.starts_with("cand_") {
        let cand = resolve_candidate(store, arg)?;
        return store
            .skills()?
            .into_iter()
            .filter(|s| s.origin_ref == cand.id.as_str())
            .max_by_key(|s| (s.updated_at, s.id))
            .ok_or_else(|| {
                usage("that candidate has no skill yet: approve it with `peerharness review <id> --approve`")
            });
    }
    if let Ok(d) = arg.parse::<Digest>() {
        return latest_with_digest(store, &d);
    }
    if arg.starts_with("sha256:") {
        let hex = hex_part(arg, "sha256:").ok_or_else(|| usage("not a bundle digest"))?;
        let skills = store.skills()?;
        let d = unique(dedup_digests(&skills), hex, "skill bundle")?;
        return latest_with_digest(store, &d);
    }
    if let Some(s) = store.skill_by_name(arg)? {
        return Ok(s);
    }
    if let Some(hex) = hex_part(arg, "") {
        if hex.len() >= MIN_PREFIX_HEX {
            let skills = store.skills()?;
            if let Ok(d) = unique(dedup_digests(&skills), hex, "skill bundle") {
                return latest_with_digest(store, &d);
            }
        }
    }
    Err(usage(
        "no skill matches: use the number from `peerharness skills list`, a skill name, a candidate id or a digest prefix",
    ))
}

// Used by `resolve_skill`.
#[allow(dead_code)]
fn dedup_digests(skills: &[SkillRow]) -> Vec<(String, Digest)> {
    let mut v: Vec<(String, Digest)> = skills
        .iter()
        .map(|s| (s.bundle_digest.to_hex(), s.bundle_digest))
        .collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v.dedup_by(|a, b| a.0 == b.0);
    v
}

// Used by `resolve_skill`.
#[allow(dead_code)]
fn latest_with_digest(store: &Store, d: &Digest) -> Result<SkillRow> {
    store
        .skills()?
        .into_iter()
        .filter(|s| s.bundle_digest == *d)
        .max_by_key(|s| (s.updated_at, s.id))
        .ok_or_else(|| usage("no skill with that bundle digest"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_rules() {
        let items = vec![
            ("abcdef0011".to_owned(), 1),
            ("abcdef0022".to_owned(), 2),
            ("12345678ff".to_owned(), 3),
        ];
        assert_eq!(unique(items.clone(), "12345678", "x").unwrap(), 3);
        assert_eq!(unique(items.clone(), "ABCDEF0011", "x").unwrap(), 1);
        assert!(unique(items.clone(), "abcdef00", "x").is_err()); // ambiguous
        assert!(unique(items.clone(), "abc", "x").is_err()); // too short
        assert!(unique(items, "99999999", "x").is_err()); // none
        assert_eq!(hex_part("sha256:abcd", "sha256:"), Some("abcd"));
        assert_eq!(hex_part("cand_zz", "cand_"), None);
    }

    #[test]
    fn resolves_events_by_prefix() {
        let s = Store::open_in_memory().unwrap();
        assert!(resolve_event(&s, "deadbeef").is_err());
        assert!(resolve_event(&s, "not-hex").is_err());
        let full = format!("sha256:{}", "ab".repeat(32));
        assert_eq!(resolve_event(&s, &full).unwrap().to_string(), full);
    }
}
