//! `sync_cursors`, `notifications` and the owned-data export.

use ph_core::{CircleId, EventId, Timestamp};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Value};

use crate::error::{Result, StoreError};
use crate::schema::SCHEMA_VERSION;
use crate::sql;
use crate::Store;

/// `schema` member of [`Store::export_owned_json`] output.
pub const EXPORT_SCHEMA: &str = "peerharness.export/0.1";

/// Last successful sync with a peer for one circle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SyncCursor {
    /// Peer.
    pub peer_id: String,
    /// Circle.
    pub circle_id: CircleId,
    /// When the last sync completed.
    pub last_sync_at: Timestamp,
    /// The last event the peer served from its log (the `after` of the next fetch).
    pub after_event_id: Option<EventId>,
    /// The last event of this node's own log the peer has taken (where the next push
    /// starts).
    pub pushed_event_id: Option<EventId>,
}

const CURSOR_COLS: &str = "peer_id, circle_id, last_sync_at, after_event_id, pushed_event_id";

fn cursor_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SyncCursor> {
    Ok(SyncCursor {
        peer_id: r.get(0)?,
        circle_id: sql::parse(r, 1, "circle id")?,
        last_sync_at: sql::ts(r, 2)?,
        after_event_id: sql::parse_opt(r, 3, "event id")?,
        pushed_event_id: sql::parse_opt(r, 4, "event id")?,
    })
}

/// One shown notification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotificationRow {
    /// Local id.
    pub id: i64,
    /// Topic label.
    pub topic: String,
    /// When it was shown.
    pub shown_at: Timestamp,
}

fn rows_json<T: Serialize>(rows: &[T]) -> Result<Value> {
    serde_json::to_value(rows).map_err(|_| StoreError::Corrupt {
        what: "row during export",
    })
}

impl Store {
    // ------------------------------------------------------------------ sync cursors

    /// The sync cursor for `(peer_id, circle)`.
    pub fn sync_cursor(&self, peer_id: &str, circle: &CircleId) -> Result<Option<SyncCursor>> {
        Ok(self
            .conn
            .query_row(
                &format!(
                    "SELECT {CURSOR_COLS} FROM sync_cursors
                     WHERE peer_id = ?1 AND circle_id = ?2"
                ),
                params![peer_id, circle.to_string()],
                cursor_row,
            )
            .optional()?)
    }

    /// Records how far a sync with `peer_id` got in `circle` (upsert): `fetched` is the
    /// last event the peer served, `pushed` the last of this node's events the peer
    /// took. `None` leaves that cursor where it was.
    ///
    /// # Errors
    ///
    /// [`StoreError::MissingReference`] if the peer or circle is not stored.
    pub fn advance_sync_cursor(
        &self,
        peer_id: &str,
        circle: &CircleId,
        fetched: Option<&EventId>,
        pushed: Option<&EventId>,
        at: Timestamp,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sync_cursors (peer_id, circle_id, last_sync_at, after_event_id, pushed_event_id)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(peer_id, circle_id) DO UPDATE SET
                 last_sync_at = excluded.last_sync_at,
                 after_event_id = COALESCE(excluded.after_event_id, after_event_id),
                 pushed_event_id = COALESCE(excluded.pushed_event_id, pushed_event_id)",
            params![
                peer_id,
                circle.to_string(),
                at.unix_seconds(),
                fetched.map(ToString::to_string),
                pushed.map(ToString::to_string)
            ],
        )?;
        Ok(())
    }

    /// Records a completed sync (upsert).
    ///
    /// # Errors
    ///
    /// [`StoreError::MissingReference`] if the peer or circle is not stored.
    pub fn set_sync_cursor(&self, peer_id: &str, circle: &CircleId, at: Timestamp) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sync_cursors (peer_id, circle_id, last_sync_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(peer_id, circle_id) DO UPDATE SET last_sync_at = excluded.last_sync_at",
            params![peer_id, circle.to_string(), at.unix_seconds()],
        )?;
        Ok(())
    }

    /// Every sync cursor (for export and `status`).
    pub fn sync_cursors(&self) -> Result<Vec<SyncCursor>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {CURSOR_COLS} FROM sync_cursors ORDER BY peer_id, circle_id"
        ))?;
        let rows = st
            .query_map([], cursor_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ------------------------------------------------------------------ notifications

    /// Records that a notification about `topic` was shown at `now`.
    pub fn record_notification(&self, topic: &str, now: Timestamp) -> Result<()> {
        sql::check_short("notification topic", topic, 256)?;
        self.conn.execute(
            "INSERT INTO notifications (topic, shown_at) VALUES (?1, ?2)",
            params![topic, now.unix_seconds()],
        )?;
        Ok(())
    }

    /// Number of notifications shown at or after `since` (for the 2-per-day cap).
    pub fn count_notifications_since(&self, since: Timestamp) -> Result<u64> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM notifications WHERE shown_at >= ?1",
            [since.unix_seconds()],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// When a notification about `topic` was last shown (for the per-topic cooldown).
    pub fn last_notification_for_topic(&self, topic: &str) -> Result<Option<Timestamp>> {
        let t: Option<i64> = self.conn.query_row(
            "SELECT MAX(shown_at) FROM notifications WHERE topic = ?1",
            [topic],
            |r| r.get(0),
        )?;
        t.map(|s| {
            Timestamp::from_unix_seconds(s).map_err(|_| StoreError::Corrupt { what: "timestamp" })
        })
        .transpose()
    }

    /// Deletes notification records shown before `before`; returns how many.
    pub fn purge_notifications_before(&self, before: Timestamp) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM notifications WHERE shown_at < ?1",
            [before.unix_seconds()],
        )?)
    }

    /// Every notification record, oldest first.
    pub fn notifications(&self) -> Result<Vec<NotificationRow>> {
        let mut st = self
            .conn
            .prepare("SELECT id, topic, shown_at FROM notifications ORDER BY shown_at, id")?;
        let rows = st
            .query_map([], |r| {
                Ok(NotificationRow {
                    id: r.get(0)?,
                    topic: r.get(1)?,
                    shown_at: sql::ts(r, 2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ------------------------------------------------------------------ export

    /// Exports every table as one JSON document for `peerharness export --local`.
    ///
    /// # Privacy: local use only
    ///
    /// The result contains **local-only** data: observation text, candidate
    /// statements and skill drafts, local questions, peer addresses and keystore
    /// references. Write it only to a file (0600) or stdout the local human asked for.
    /// Never put it, or any part of it, into a network payload, a signed event, the
    /// daemon control endpoint's responses to anything but the local CLI, tracing logs,
    /// or an advisory-provider prompt. Data meant for peers comes only from
    /// [`Store::missing_for_peer`] / [`Store::pending_for_peer`], which read nothing
    /// but the signed event log.
    ///
    /// The database holds no private key material, so none can be exported; the
    /// identity section contains the public device key and the keystore *reference*.
    /// The export is read inside one transaction, so it is a consistent snapshot.
    ///
    /// Shape: `{"schema": "peerharness.export/0.1", "schema_version": N,
    /// "identity": {...}|null, "circles": [...], "memberships": [...],
    /// "issued_invites": [...], "revocations": [...], "peers": [...],
    /// "observations": [...], "candidates": [...], "questions": [...], "events": [...],
    /// "outbox": [...], "bundles": [...], "skills": [...], "installations": [...],
    /// "sync_cursors": [...], "notifications": [...]}`.
    /// Timestamps are RFC 3339 strings; events carry their parsed `envelope`.
    pub fn export_owned_json(&self) -> Result<Value> {
        // A read transaction gives a consistent snapshot across tables.
        let own = self.conn.is_autocommit();
        if own {
            self.conn.execute_batch("BEGIN DEFERRED")?;
        }
        let res = self.export_inner();
        if own {
            let end = if res.is_ok() { "COMMIT" } else { "ROLLBACK" };
            self.conn.execute_batch(end)?;
        }
        res
    }

    fn export_inner(&self) -> Result<Value> {
        let identity = match self.identity()? {
            Some(i) => serde_json::to_value(i).map_err(|_| StoreError::Corrupt {
                what: "identity during export",
            })?,
            None => Value::Null,
        };
        let circles = self.circles()?;
        let mut charters = Vec::new();
        let mut optouts = Vec::new();
        let mut rule_installs = Vec::new();
        for c in &circles {
            for (skill_name, digest, at) in self.rule_installs(&c.circle_id)? {
                rule_installs.push(json!({
                    "circle_id": c.circle_id,
                    "skill_name": skill_name,
                    "bundle_digest": digest,
                    "installed_at": at,
                }));
            }
            for charter in self.charters(&c.circle_id)? {
                charters.push(charter.to_value()?);
            }
            for (skill_name, at) in self.rule_opt_outs(&c.circle_id)? {
                optouts.push(json!({
                    "circle_id": c.circle_id,
                    "skill_name": skill_name,
                    "opted_out_at": at,
                }));
            }
        }
        Ok(json!({
            "schema": EXPORT_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "identity": identity,
            "circles": rows_json(&circles)?,
            "charters": Value::Array(charters),
            "rule_optouts": Value::Array(optouts),
            "rule_installs": Value::Array(rule_installs),
            "memberships": rows_json(&self.all_memberships()?)?,
            "issued_invites": rows_json(&self.issued_invites(None)?)?,
            "revocations": rows_json(&self.all_revocations()?)?,
            "peers": rows_json(&self.peers()?)?,
            "observations": rows_json(&self.all_observations()?)?,
            "candidates": rows_json(&self.candidates(&[])?)?,
            "questions": rows_json(&self.all_questions()?)?,
            "events": rows_json(&self.all_events()?)?,
            "outbox": rows_json(&self.all_outbox()?)?,
            "bundles": rows_json(&self.bundles()?)?,
            "skills": rows_json(&self.skills()?)?,
            "installations": rows_json(&self.all_installations()?)?,
            "sync_cursors": rows_json(&self.sync_cursors()?)?,
            "notifications": rows_json(&self.notifications()?)?,
        }))
    }
}
