//! `observations`: local-only, bounded, redacted agent observations.
//!
//! Nothing in this table is ever sent anywhere. Callers must construct observations
//! through `NormalizedObservation::from_raw` (which redacts and bounds the text); the
//! store additionally truncates text to `MAX_OBSERVATION_TEXT_BYTES` as a backstop.

use std::fmt;

use ph_core::{
    bound_text, NormalizedObservation, ObservationId, Timestamp, MAX_OBSERVATION_TEXT_BYTES,
};
use rusqlite::{params, OptionalExtension, Row};
use serde::Serialize;

use crate::error::{Result, StoreError};
use crate::sql;
use crate::Store;

/// Default observation retention (architecture section 8).
pub const DEFAULT_OBSERVATION_RETENTION_DAYS: i64 = 14;

/// Maximum length of a repository key.
pub const MAX_REPO_KEY_BYTES: usize = 256;

/// The default expiry for an observation created at `created_at`.
pub fn default_observation_expiry(created_at: Timestamp) -> Timestamp {
    created_at.plus_days(DEFAULT_OBSERVATION_RETENTION_DAYS)
}

/// A stored observation with its expiry.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct StoredObservation {
    /// The observation.
    #[serde(flatten)]
    pub observation: NormalizedObservation,
    /// When it is purged.
    pub expires_at: Timestamp,
}

impl fmt::Debug for StoredObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredObservation")
            .field("observation", &self.observation)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

const COLS: &str = "id, created_at, source, session_hash, repo_key, kind, text, expires_at";

fn row(r: &Row<'_>) -> rusqlite::Result<StoredObservation> {
    Ok(StoredObservation {
        observation: NormalizedObservation {
            id: sql::parse(r, 0, "observation id")?,
            created_at: sql::ts(r, 1)?,
            source: sql::parse(r, 2, "observation source")?,
            session_hash: sql::parse_opt(r, 3, "session hash")?,
            repo_key: r.get(4)?,
            kind: sql::parse(r, 5, "observation kind")?,
            text: r.get(6)?,
        },
        expires_at: sql::ts(r, 7)?,
    })
}

impl Store {
    /// Inserts an observation. Idempotent on the observation id: returns `false` if an
    /// observation with the same id already exists (the stored one is kept).
    ///
    /// This is a single autocommit statement, safe to run from many hook processes at
    /// once; it waits up to the busy timeout and then fails with [`StoreError::Busy`].
    pub fn insert_observation(
        &self,
        obs: &NormalizedObservation,
        expires_at: Timestamp,
    ) -> Result<bool> {
        if obs.repo_key.len() > MAX_REPO_KEY_BYTES {
            return Err(StoreError::invalid("repository key", "too long"));
        }
        let text = bound_text(&obs.text, MAX_OBSERVATION_TEXT_BYTES);
        let n = self.conn.execute(
            &format!(
                "INSERT INTO observations ({COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(id) DO NOTHING"
            ),
            params![
                obs.id.as_str(),
                obs.created_at.unix_seconds(),
                obs.source.as_str(),
                obs.session_hash.as_ref().map(ToString::to_string),
                obs.repo_key,
                obs.kind.as_str(),
                text,
                expires_at.unix_seconds()
            ],
        )?;
        Ok(n == 1)
    }

    /// The observation with this id.
    pub fn observation(&self, id: &ObservationId) -> Result<Option<StoredObservation>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM observations WHERE id = ?1"),
                [id.as_str()],
                row,
            )
            .optional()?)
    }

    /// The most recent observations with `created_at >= since` (optionally only for one
    /// repository), at most `limit` of them, returned in **chronological** order
    /// (oldest first) as detectors expect.
    pub fn recent_observations(
        &self,
        repo_key: Option<&str>,
        since: Timestamp,
        limit: usize,
    ) -> Result<Vec<StoredObservation>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS} FROM observations
             WHERE created_at >= ?1 AND (?2 IS NULL OR repo_key = ?2)
             ORDER BY created_at DESC, rowid DESC LIMIT ?3"
        ))?;
        let mut rows = st
            .query_map(
                params![since.unix_seconds(), repo_key, sql::limit(limit)],
                row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.reverse();
        Ok(rows)
    }

    /// Deletes observations with `expires_at <= now`; returns how many were deleted.
    pub fn purge_expired_observations(&self, now: Timestamp) -> Result<usize> {
        let n = self.conn.execute(
            "DELETE FROM observations WHERE expires_at <= ?1",
            [now.unix_seconds()],
        )?;
        if n > 0 {
            tracing::debug!(count = n, "purged expired observations");
        }
        Ok(n)
    }

    /// Number of stored observations.
    pub fn observation_count(&self) -> Result<u64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM observations", [], |r| r.get(0))?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Every stored observation, oldest first (for export).
    pub fn all_observations(&self) -> Result<Vec<StoredObservation>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS} FROM observations ORDER BY created_at, rowid"
        ))?;
        let rows = st
            .query_map([], row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}
