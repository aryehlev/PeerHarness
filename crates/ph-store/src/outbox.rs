//! `outbox`: per-peer delivery queue of stored events.

use ph_core::{EventId, Timestamp};
use rusqlite::{params, Row};
use serde::Serialize;

use crate::error::{Result, StoreError};
use crate::events::StoredEvent;
use crate::sql;
use crate::Store;

/// One outbox row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OutboxEntry {
    /// Queued event.
    pub event_id: EventId,
    /// Destination peer.
    pub peer_id: String,
    /// When it was queued.
    pub enqueued_at: Timestamp,
    /// When delivery was confirmed (`accepted` or `duplicate`).
    pub delivered_at: Option<Timestamp>,
    /// Number of failed delivery attempts so far.
    pub attempts: u32,
    /// Time of the last failed attempt.
    pub last_attempt_at: Option<Timestamp>,
}

/// A pending outbox entry together with the event to send.
#[derive(Clone, Debug)]
pub struct PendingDelivery {
    /// The outbox row.
    pub entry: OutboxEntry,
    /// The stored event.
    pub event: StoredEvent,
}

fn entry(r: &Row<'_>, base: usize) -> rusqlite::Result<OutboxEntry> {
    let attempts: i64 = r.get(base + 4)?;
    Ok(OutboxEntry {
        event_id: sql::parse(r, base, "event id")?,
        peer_id: r.get(base + 1)?,
        enqueued_at: sql::ts(r, base + 2)?,
        delivered_at: sql::ts_opt(r, base + 3)?,
        attempts: u32::try_from(attempts).map_err(|_| sql::corrupt(base + 4, "attempts"))?,
        last_attempt_at: sql::ts_opt(r, base + 5)?,
    })
}

const COLS: &str =
    "o.event_id, o.peer_id, o.enqueued_at, o.delivered_at, o.attempts, o.last_attempt_at";

impl Store {
    /// Queues a stored event for a peer. Idempotent: returns `false` if it is already
    /// queued (delivered or not).
    ///
    /// # Errors
    ///
    /// [`StoreError::MissingReference`] if the event or the peer is not stored.
    pub fn enqueue_outbox(
        &self,
        event_id: &EventId,
        peer_id: &str,
        now: Timestamp,
    ) -> Result<bool> {
        let n = self.conn.execute(
            "INSERT INTO outbox (event_id, peer_id, enqueued_at, attempts) VALUES (?1, ?2, ?3, 0)
             ON CONFLICT(event_id, peer_id) DO NOTHING",
            params![event_id.to_string(), peer_id, now.unix_seconds()],
        )?;
        Ok(n == 1)
    }

    /// Undelivered entries for a peer whose events have not expired at `now`, oldest
    /// first, at most `limit`, joined with their events.
    ///
    /// The outbox records intent at enqueue time only. Before sending, re-check that the
    /// peer is not blocked and may still read each event's scope (credentials expire and
    /// get revoked after enqueueing); drop or skip entries that fail.
    pub fn pending_for_peer(
        &self,
        peer_id: &str,
        now: Timestamp,
        limit: usize,
    ) -> Result<Vec<PendingDelivery>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS}, e.event_id, e.type, e.circle_id, e.scope, e.author, e.created_at,
                    e.expires_at, e.received_at, e.origin_peer, e.ref_event_id, e.bundle_digest,
                    e.envelope_json
             FROM outbox o JOIN events e ON e.event_id = o.event_id
             WHERE o.peer_id = ?1 AND o.delivered_at IS NULL AND e.expires_at > ?2
             ORDER BY o.enqueued_at, o.event_id LIMIT ?3"
        ))?;
        let rows = st
            .query_map(
                params![peer_id, now.unix_seconds(), sql::limit(limit)],
                |r| {
                    Ok(PendingDelivery {
                        entry: entry(r, 0)?,
                        event: StoredEvent {
                            event_id: sql::parse(r, 6, "event id")?,
                            event_type: sql::parse(r, 7, "event type")?,
                            circle_id: sql::parse(r, 8, "circle id")?,
                            scope: sql::parse(r, 9, "scope")?,
                            author: sql::parse(r, 10, "author key")?,
                            created_at: sql::ts(r, 11)?,
                            expires_at: sql::ts(r, 12)?,
                            received_at: sql::ts(r, 13)?,
                            origin_peer: r.get(14)?,
                            ref_event_id: sql::parse_opt(r, 15, "event id")?,
                            bundle_digest: sql::parse_opt(r, 16, "digest")?,
                            envelope_json: r.get(17)?,
                        },
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Marks an entry delivered. Returns `false` if it was already delivered.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such entry exists.
    pub fn mark_delivered(&self, event_id: &EventId, peer_id: &str, at: Timestamp) -> Result<bool> {
        let tx = self.tx()?;
        let n = self.conn.execute(
            "UPDATE outbox SET delivered_at = ?3
             WHERE event_id = ?1 AND peer_id = ?2 AND delivered_at IS NULL",
            params![event_id.to_string(), peer_id, at.unix_seconds()],
        )?;
        if n == 0 && !self.outbox_exists(event_id, peer_id)? {
            return Err(StoreError::NotFound {
                what: "outbox entry",
            });
        }
        tx.commit()?;
        Ok(n == 1)
    }

    /// Records a failed delivery attempt; returns the new attempt count.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such entry exists.
    pub fn bump_outbox_attempts(
        &self,
        event_id: &EventId,
        peer_id: &str,
        at: Timestamp,
    ) -> Result<u32> {
        let attempts: Option<i64> = self
            .conn
            .query_row(
                "UPDATE outbox SET attempts = attempts + 1, last_attempt_at = ?3
                 WHERE event_id = ?1 AND peer_id = ?2 RETURNING attempts",
                params![event_id.to_string(), peer_id, at.unix_seconds()],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(e),
            })?;
        let a = attempts.ok_or(StoreError::NotFound {
            what: "outbox entry",
        })?;
        u32::try_from(a).map_err(|_| StoreError::Corrupt { what: "attempts" })
    }

    fn outbox_exists(&self, event_id: &EventId, peer_id: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM outbox WHERE event_id = ?1 AND peer_id = ?2)",
            params![event_id.to_string(), peer_id],
            |r| r.get(0),
        )?)
    }

    /// Total number of undelivered outbox entries (all peers, expired events included).
    pub fn pending_outbox_count(&self) -> Result<u64> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM outbox WHERE delivered_at IS NULL",
            [],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Peers that have undelivered, unexpired entries at `now`, ordered by `peer_id`.
    pub fn peers_with_pending(&self, now: Timestamp) -> Result<Vec<String>> {
        let mut st = self.conn.prepare(
            "SELECT DISTINCT o.peer_id FROM outbox o JOIN events e ON e.event_id = o.event_id
             WHERE o.delivered_at IS NULL AND e.expires_at > ?1 ORDER BY o.peer_id",
        )?;
        let rows = st
            .query_map([now.unix_seconds()], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(rows)
    }

    /// Deletes undelivered entries whose events expired at `now` (they would be
    /// rejected by every peer); returns how many were deleted.
    pub fn drop_expired_outbox(&self, now: Timestamp) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM outbox WHERE delivered_at IS NULL AND event_id IN
                 (SELECT event_id FROM events WHERE expires_at <= ?1)",
            [now.unix_seconds()],
        )?)
    }

    /// Every outbox row (for export).
    pub fn all_outbox(&self) -> Result<Vec<OutboxEntry>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS} FROM outbox o ORDER BY o.enqueued_at, o.event_id, o.peer_id"
        ))?;
        let rows = st
            .query_map([], |r| entry(r, 0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}
