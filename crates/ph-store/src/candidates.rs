//! `candidates`: local skill candidates and their lifecycle.

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use ph_core::{
    is_valid_skill_name, transition, Actor, CandidateStatus, CircleId, Confidence, EventId,
    ObservationId, ParseError, RandomnessError, Scope, SkillCandidate, Timestamp,
};
use rand::TryRng as _;
use rusqlite::{params, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

use crate::error::{Result, StoreError};
use crate::sql;
use crate::Store;

/// At most this many evidence ids are kept per candidate (the oldest are dropped).
pub const MAX_CANDIDATE_EVIDENCE: usize = 64;
/// Maximum size of a candidate statement, preferred/avoided option, topic or concept
/// key, in bytes.
pub const MAX_CANDIDATE_TEXT_BYTES: usize = 4096;
/// Maximum size of a stored skill draft (the bundle limit).
pub const MAX_SKILL_DRAFT_BYTES: usize = ph_protocol::limits::MAX_BUNDLE_BYTES;

/// Identifier of a local candidate: `cand_` followed by 16 lowercase hex characters.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CandidateId(String);

impl CandidateId {
    /// A fresh random id from the OS RNG.
    pub fn random() -> Result<Self, RandomnessError> {
        let mut b = [0u8; 8];
        rand::rngs::SysRng
            .try_fill_bytes(&mut b)
            .map_err(|_| RandomnessError)?;
        Ok(Self(format!("cand_{}", hex::encode(b))))
    }

    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for CandidateId {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        let ok = s.len() == 21
            && s.starts_with("cand_")
            && s.bytes()
                .skip(5)
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(ParseError::new(
                "candidate id",
                "expected cand_ and 16 lowercase hex characters",
            ))
        }
    }
}

impl fmt::Display for CandidateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for CandidateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CandidateId({})", self.0)
    }
}

impl Serialize for CandidateId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CandidateId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A stored candidate.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct CandidateRow {
    /// Local id.
    pub id: CandidateId,
    /// Dedup key of the concept.
    pub concept_key: String,
    /// Repository the concept applies to.
    pub repo_key: String,
    /// Lifecycle state.
    pub status: CandidateStatus,
    /// Human-readable statement (editable by the human).
    pub statement: String,
    /// Preferred option, if identified.
    pub preferred: Option<String>,
    /// Avoided option, if identified.
    pub avoided: Option<String>,
    /// Detector confidence (merged: `Medium` once there are 2+ evidence items).
    pub confidence: Confidence,
    /// Supporting local observation ids (deduplicated, oldest first).
    pub evidence: Vec<ObservationId>,
    /// Agent Skills name for the generated skill.
    pub skill_name: String,
    /// Topic label for notification cooldowns.
    pub topic: String,
    /// Draft SKILL.md text, once generated.
    pub skill_draft: Option<String>,
    /// Circle chosen for sharing, once share-authorized.
    pub circle_id: Option<CircleId>,
    /// Scope chosen for sharing.
    pub scope: Option<Scope>,
    /// QUESTION event sent about it.
    pub question_event_id: Option<EventId>,
    /// Current PROPOSAL event for it.
    pub proposal_event_id: Option<EventId>,
    /// Creation time.
    pub created_at: Timestamp,
    /// Last modification time.
    pub updated_at: Timestamp,
}

impl fmt::Debug for CandidateRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CandidateRow")
            .field("id", &self.id)
            .field("status", &self.status)
            .field("statement_len", &self.statement.len())
            .field("confidence", &self.confidence)
            .field("evidence_count", &self.evidence.len())
            .field("has_skill_draft", &self.skill_draft.is_some())
            .field("circle_id", &self.circle_id)
            .field("question_event_id", &self.question_event_id)
            .field("proposal_event_id", &self.proposal_event_id)
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}

const COLS: &str = "id, concept_key, repo_key, status, statement, preferred, avoided, confidence, \
                    evidence_json, skill_name, topic, skill_draft, circle_id, scope, \
                    question_event_id, proposal_event_id, created_at, updated_at";

fn row(r: &Row<'_>) -> rusqlite::Result<CandidateRow> {
    Ok(CandidateRow {
        id: sql::parse(r, 0, "candidate id")?,
        concept_key: r.get(1)?,
        repo_key: r.get(2)?,
        status: sql::parse(r, 3, "candidate status")?,
        statement: r.get(4)?,
        preferred: r.get(5)?,
        avoided: r.get(6)?,
        confidence: sql::parse(r, 7, "confidence")?,
        evidence: sql::json(r, 8, "candidate evidence")?,
        skill_name: r.get(9)?,
        topic: r.get(10)?,
        skill_draft: r.get(11)?,
        circle_id: sql::parse_opt(r, 12, "circle id")?,
        scope: sql::parse_opt(r, 13, "scope")?,
        question_event_id: sql::parse_opt(r, 14, "event id")?,
        proposal_event_id: sql::parse_opt(r, 15, "event id")?,
        created_at: sql::ts(r, 16)?,
        updated_at: sql::ts(r, 17)?,
    })
}

fn check_text(what: &'static str, s: &str, allow_empty: bool) -> Result<()> {
    if !allow_empty && s.is_empty() {
        return Err(StoreError::invalid(what, "empty"));
    }
    if s.len() > MAX_CANDIDATE_TEXT_BYTES {
        return Err(StoreError::invalid(what, "too long"));
    }
    Ok(())
}

fn check_skill_name(s: &str) -> Result<()> {
    if is_valid_skill_name(s) {
        Ok(())
    } else {
        Err(StoreError::invalid(
            "skill name",
            "not a valid Agent Skills name",
        ))
    }
}

/// Appends `new` to `old`, dropping duplicates and keeping the newest
/// [`MAX_CANDIDATE_EVIDENCE`] entries.
fn merge_evidence(old: &[ObservationId], new: &[ObservationId]) -> Vec<ObservationId> {
    let mut seen = HashSet::new();
    let mut out: Vec<ObservationId> = old
        .iter()
        .chain(new)
        .filter(|id| seen.insert((*id).clone()))
        .cloned()
        .collect();
    if out.len() > MAX_CANDIDATE_EVIDENCE {
        out.drain(..out.len() - MAX_CANDIDATE_EVIDENCE);
    }
    out
}

fn merged_confidence(a: Confidence, b: Confidence, evidence: usize) -> Confidence {
    let floor = if evidence >= 2 {
        Confidence::Medium
    } else {
        Confidence::Low
    };
    a.max(b).max(floor)
}

impl Store {
    /// Inserts a detected candidate, or merges it into the existing candidate with the
    /// same `(concept_key, repo_key)`. Returns the id and whether a row was created.
    ///
    /// * New: stored with status `Detected`; evidence deduplicated; confidence raised
    ///   to `Medium` when there are 2+ evidence items.
    /// * Existing, non-terminal: evidence ids appended (deduplicated, newest
    ///   [`MAX_CANDIDATE_EVIDENCE`] kept), confidence raised the same way, `updated_at`
    ///   bumped. The status, statement and other human-editable fields are untouched.
    /// * Existing, terminal (`Adopted`, `Rejected`, `Superseded`): left completely
    ///   unchanged. A rejected candidate is never resurrected.
    ///
    /// Runs in one `BEGIN IMMEDIATE` transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::Invalid`] for an invalid skill name or oversized/empty text.
    pub fn insert_or_merge_candidate(
        &self,
        c: &SkillCandidate,
        now: Timestamp,
    ) -> Result<(CandidateId, bool)> {
        check_text("concept key", &c.concept_key, false)?;
        check_text("repository key", &c.repo_key, true)?;
        check_text("candidate statement", &c.statement, false)?;
        check_text("candidate topic", &c.topic, true)?;
        for o in [&c.preferred, &c.avoided].into_iter().flatten() {
            check_text("candidate option", o, true)?;
        }
        check_skill_name(&c.suggested_skill_name)?;

        let tx = self.tx()?;
        let existing = self
            .conn
            .query_row(
                "SELECT id, status, evidence_json, confidence FROM candidates
                 WHERE concept_key = ?1 AND repo_key = ?2",
                params![c.concept_key, c.repo_key],
                |r| {
                    Ok((
                        sql::parse::<CandidateId>(r, 0, "candidate id")?,
                        sql::parse::<CandidateStatus>(r, 1, "candidate status")?,
                        sql::json::<Vec<ObservationId>>(r, 2, "candidate evidence")?,
                        sql::parse::<Confidence>(r, 3, "confidence")?,
                    ))
                },
            )
            .optional()?;
        let out = match existing {
            Some((id, status, _, _)) if status.is_terminal() => (id, false),
            Some((id, _, old_ev, old_conf)) => {
                let evidence = merge_evidence(&old_ev, &c.evidence);
                let confidence = merged_confidence(old_conf, c.confidence, evidence.len());
                self.conn.execute(
                    "UPDATE candidates SET evidence_json = ?2, confidence = ?3, updated_at = ?4
                     WHERE id = ?1",
                    params![
                        id.as_str(),
                        sql::to_json(&evidence, "candidate evidence")?,
                        confidence.as_str(),
                        now.unix_seconds()
                    ],
                )?;
                (id, false)
            }
            None => {
                let evidence = merge_evidence(&[], &c.evidence);
                let confidence = merged_confidence(c.confidence, c.confidence, evidence.len());
                let id = self.fresh_candidate_id()?;
                self.conn.execute(
                    &format!(
                        "INSERT INTO candidates ({COLS}) VALUES
                         (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, NULL, NULL,
                          NULL, NULL, ?12, ?12)"
                    ),
                    params![
                        id.as_str(),
                        c.concept_key,
                        c.repo_key,
                        CandidateStatus::Detected.as_str(),
                        c.statement,
                        c.preferred,
                        c.avoided,
                        confidence.as_str(),
                        sql::to_json(&evidence, "candidate evidence")?,
                        c.suggested_skill_name,
                        c.topic,
                        now.unix_seconds()
                    ],
                )?;
                (id, true)
            }
        };
        tx.commit()?;
        tracing::debug!(candidate = %out.0, created = out.1, "candidate insert_or_merge");
        Ok(out)
    }

    fn fresh_candidate_id(&self) -> Result<CandidateId> {
        for _ in 0..8 {
            let id = CandidateId::random()?;
            let taken: bool = self.conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM candidates WHERE id = ?1)",
                [id.as_str()],
                |r| r.get(0),
            )?;
            if !taken {
                return Ok(id);
            }
        }
        Err(StoreError::Randomness)
    }

    /// The candidate with this id.
    pub fn candidate(&self, id: &CandidateId) -> Result<Option<CandidateRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM candidates WHERE id = ?1"),
                [id.as_str()],
                row,
            )
            .optional()?)
    }

    /// The candidate for a `(concept_key, repo_key)` pair.
    pub fn candidate_by_concept(
        &self,
        concept_key: &str,
        repo_key: &str,
    ) -> Result<Option<CandidateRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM candidates WHERE concept_key = ?1 AND repo_key = ?2"),
                params![concept_key, repo_key],
                row,
            )
            .optional()?)
    }

    /// The candidate whose QUESTION event is `event_id`.
    pub fn candidate_by_question_event(&self, event_id: &EventId) -> Result<Option<CandidateRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM candidates WHERE question_event_id = ?1 LIMIT 1"),
                [event_id.to_string()],
                row,
            )
            .optional()?)
    }

    /// The candidate whose current PROPOSAL event is `event_id`.
    pub fn candidate_by_proposal_event(&self, event_id: &EventId) -> Result<Option<CandidateRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM candidates WHERE proposal_event_id = ?1 LIMIT 1"),
                [event_id.to_string()],
                row,
            )
            .optional()?)
    }

    /// Candidates whose status is in `statuses` (all candidates when empty), most
    /// recently updated first.
    pub fn candidates(&self, statuses: &[CandidateStatus]) -> Result<Vec<CandidateRow>> {
        let filter = if statuses.is_empty() {
            String::new()
        } else {
            format!("WHERE status IN ({})", sql::placeholders(statuses.len()))
        };
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS} FROM candidates {filter} ORDER BY updated_at DESC, id"
        ))?;
        let args: Vec<&str> = statuses.iter().map(|s| s.as_str()).collect();
        let rows = st
            .query_map(rusqlite::params_from_iter(args), row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Compare-and-set status transition.
    ///
    /// In one `BEGIN IMMEDIATE` transaction: reads the current status, fails with
    /// [`StoreError::StatusMismatch`] unless it equals `expected_from`, checks the edge
    /// with [`ph_core::transition`] (which enforces the human-only edges), and writes
    /// `to`. Because the write lock is held from the read to the write, two processes
    /// racing on the same candidate cannot both succeed (no lost update).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`], [`StoreError::StatusMismatch`],
    /// [`StoreError::Transition`]. On any error nothing is written.
    pub fn update_candidate_status(
        &self,
        id: &CandidateId,
        expected_from: CandidateStatus,
        to: CandidateStatus,
        actor: Actor,
        now: Timestamp,
    ) -> Result<CandidateStatus> {
        let tx = self.tx()?;
        let actual: CandidateStatus = self
            .conn
            .query_row(
                "SELECT status FROM candidates WHERE id = ?1",
                [id.as_str()],
                |r| sql::parse(r, 0, "candidate status"),
            )
            .optional()?
            .ok_or(StoreError::NotFound { what: "candidate" })?;
        if actual != expected_from {
            return Err(StoreError::StatusMismatch {
                expected: expected_from,
                actual,
            });
        }
        let new = transition(actual, to, actor)?;
        self.conn.execute(
            "UPDATE candidates SET status = ?2, updated_at = ?3 WHERE id = ?1",
            params![id.as_str(), new.as_str(), now.unix_seconds()],
        )?;
        tx.commit()?;
        tracing::debug!(candidate = %id, from = %actual, to = %new, "candidate status changed");
        Ok(new)
    }

    fn set_candidate_columns(
        &self,
        id: &CandidateId,
        assignments: &str,
        values: &[&dyn rusqlite::ToSql],
        now: Timestamp,
    ) -> Result<()> {
        let mut args: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(values.len() + 2);
        let id_s = id.as_str();
        let now_s = now.unix_seconds();
        args.push(&id_s);
        args.push(&now_s);
        args.extend_from_slice(values);
        let n = self.conn.execute(
            &format!("UPDATE candidates SET {assignments}, updated_at = ?2 WHERE id = ?1"),
            args.as_slice(),
        )?;
        if n == 0 {
            return Err(StoreError::NotFound { what: "candidate" });
        }
        Ok(())
    }

    /// Replaces the statement (after a human edit).
    pub fn set_candidate_statement(
        &self,
        id: &CandidateId,
        statement: &str,
        now: Timestamp,
    ) -> Result<()> {
        check_text("candidate statement", statement, false)?;
        self.set_candidate_columns(id, "statement = ?3", &[&statement], now)
    }

    /// Replaces the skill name (must be a valid Agent Skills name).
    pub fn set_candidate_skill_name(
        &self,
        id: &CandidateId,
        name: &str,
        now: Timestamp,
    ) -> Result<()> {
        check_skill_name(name)?;
        self.set_candidate_columns(id, "skill_name = ?3", &[&name], now)
    }

    /// Sets or clears the SKILL.md draft (at most 256 KiB).
    pub fn set_candidate_skill_draft(
        &self,
        id: &CandidateId,
        draft: Option<&str>,
        now: Timestamp,
    ) -> Result<()> {
        if draft.is_some_and(|d| d.len() > MAX_SKILL_DRAFT_BYTES) {
            return Err(StoreError::invalid("skill draft", "too large"));
        }
        self.set_candidate_columns(id, "skill_draft = ?3", &[&draft], now)
    }

    /// Sets the circle and scope chosen for sharing. The circle must be stored.
    pub fn set_candidate_share_target(
        &self,
        id: &CandidateId,
        circle: &CircleId,
        scope: &Scope,
        now: Timestamp,
    ) -> Result<()> {
        let c = circle.to_string();
        let s = scope.as_str();
        self.set_candidate_columns(id, "circle_id = ?3, scope = ?4", &[&c, &s], now)
    }

    /// Records the QUESTION event sent about the candidate.
    pub fn set_candidate_question_event(
        &self,
        id: &CandidateId,
        event_id: &EventId,
        now: Timestamp,
    ) -> Result<()> {
        let e = event_id.to_string();
        self.set_candidate_columns(id, "question_event_id = ?3", &[&e], now)
    }

    /// Records the current PROPOSAL event for the candidate (replacing a previous one
    /// after a revision).
    pub fn set_candidate_proposal_event(
        &self,
        id: &CandidateId,
        event_id: &EventId,
        now: Timestamp,
    ) -> Result<()> {
        let e = event_id.to_string();
        self.set_candidate_columns(id, "proposal_event_id = ?3", &[&e], now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_id_format() {
        let id = CandidateId::random().unwrap();
        assert!(id.as_str().starts_with("cand_"));
        assert_eq!(id.as_str().len(), 21);
        assert_eq!(id.as_str().parse::<CandidateId>().unwrap(), id);
        for bad in [
            "",
            "cand_",
            "cand_0123456789abcdeF",
            "cand_0123456789abcde",
            "x_0123456789abcdef0",
            "cand_0123456789abcdef0",
        ] {
            assert!(bad.parse::<CandidateId>().is_err(), "{bad}");
        }
    }

    #[test]
    fn evidence_merge_dedups_and_caps() {
        let ids: Vec<ObservationId> = (0..100)
            .map(|i| ObservationId::new(&format!("o{i}")).unwrap())
            .collect();
        let merged = merge_evidence(&ids[..10], &ids[5..15]);
        assert_eq!(merged, ids[..15].to_vec());
        let capped = merge_evidence(&ids[..50], &ids[50..]);
        assert_eq!(capped.len(), MAX_CANDIDATE_EVIDENCE);
        assert_eq!(capped.last(), ids.last());
        assert_eq!(
            merged_confidence(Confidence::Low, Confidence::Low, 1),
            Confidence::Low
        );
        assert_eq!(
            merged_confidence(Confidence::Low, Confidence::Low, 2),
            Confidence::Medium
        );
        assert_eq!(
            merged_confidence(Confidence::Medium, Confidence::Low, 0),
            Confidence::Medium
        );
    }
}
