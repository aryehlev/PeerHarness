//! `peers` and `peer_circles`.

use ph_core::{CircleId, DeviceKey, Timestamp};
use ph_protocol::limits::{MAX_ADDRS, MAX_ADDR_BYTES};
use rusqlite::{params, OptionalExtension, Row};
use serde::Serialize;

use crate::error::{Result, StoreError};
use crate::sql;
use crate::Store;

/// Maximum length of a stored libp2p `PeerId` string.
pub const MAX_PEER_ID_LEN: usize = 128;

/// A known peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PeerRow {
    /// libp2p `PeerId` in its string form.
    pub peer_id: String,
    /// The peer's device key (bound to `peer_id` by the transport handshake).
    pub device_key: DeviceKey,
    /// Last known listen multiaddrs (at most 8).
    pub addrs: Vec<String>,
    /// When the peer was first stored.
    pub created_at: Timestamp,
    /// Last successful contact.
    pub last_seen: Option<Timestamp>,
    /// Locally blocked: nothing from this peer is accepted.
    pub blocked: bool,
    /// Locally muted: its questions are not shown.
    pub muted: bool,
    /// Circles this node believes the peer belongs to.
    pub circles: Vec<CircleId>,
}

/// Validates a libp2p `PeerId` string: 1-128 ASCII alphanumerics (base58btc or
/// base32 multibase forms).
pub fn check_peer_id(peer_id: &str) -> Result<()> {
    if peer_id.is_empty()
        || peer_id.len() > MAX_PEER_ID_LEN
        || !peer_id.bytes().all(|c| c.is_ascii_alphanumeric())
    {
        return Err(StoreError::invalid(
            "peer id",
            "expected 1-128 ASCII alphanumerics",
        ));
    }
    Ok(())
}

fn check_addrs(addrs: &[String]) -> Result<()> {
    if addrs.len() > MAX_ADDRS {
        return Err(StoreError::invalid("peer addresses", "more than 8"));
    }
    for a in addrs {
        if a.is_empty() || a.len() > MAX_ADDR_BYTES || !a.starts_with('/') {
            return Err(StoreError::invalid("peer address", "expected a multiaddr"));
        }
        if a.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(StoreError::invalid("peer address", "forbidden character"));
        }
    }
    Ok(())
}

const COLS: &str = "peer_id, device_key, addrs_json, created_at, last_seen, blocked, muted";

fn base_row(r: &Row<'_>) -> rusqlite::Result<PeerRow> {
    Ok(PeerRow {
        peer_id: r.get(0)?,
        device_key: sql::parse(r, 1, "device key")?,
        addrs: sql::json(r, 2, "peer addresses")?,
        created_at: sql::ts(r, 3)?,
        last_seen: sql::ts_opt(r, 4)?,
        blocked: sql::flag(r, 5)?,
        muted: sql::flag(r, 6)?,
        circles: Vec::new(),
    })
}

impl Store {
    /// Inserts or updates a peer.
    ///
    /// A non-empty `addrs` replaces the stored addresses; an empty one keeps them (so an
    /// `Authenticate` without listen addresses does not erase addresses from an
    /// invite). `blocked`, `muted`, `last_seen` and circles are untouched on update.
    ///
    /// # Errors
    ///
    /// [`StoreError::Invalid`] for a malformed peer id or addresses (at most 8, each a
    /// multiaddr of at most 256 bytes), and [`StoreError::Mismatch`] if `peer_id` or
    /// `device_key` is already stored paired with a different key or id.
    pub fn upsert_peer(
        &self,
        peer_id: &str,
        device_key: &DeviceKey,
        addrs: &[String],
        now: Timestamp,
    ) -> Result<UpsertPeer> {
        check_peer_id(peer_id)?;
        check_addrs(addrs)?;
        let addrs_json = sql::to_json(addrs, "peer addresses")?;
        let tx = self.tx()?;
        let by_id: Option<String> = self
            .conn
            .query_row(
                "SELECT device_key FROM peers WHERE peer_id = ?1",
                [peer_id],
                |r| r.get(0),
            )
            .optional()?;
        let by_key: Option<String> = self
            .conn
            .query_row(
                "SELECT peer_id FROM peers WHERE device_key = ?1",
                [device_key.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        let outcome = match (by_id, by_key) {
            (None, None) => {
                self.conn.execute(
                    &format!("INSERT INTO peers ({COLS}) VALUES (?1, ?2, ?3, ?4, NULL, 0, 0)"),
                    params![
                        peer_id,
                        device_key.to_string(),
                        addrs_json,
                        now.unix_seconds()
                    ],
                )?;
                UpsertPeer::Inserted
            }
            (Some(k), Some(p)) if k == device_key.to_string() && p == peer_id => {
                if !addrs.is_empty() {
                    self.conn.execute(
                        "UPDATE peers SET addrs_json = ?2 WHERE peer_id = ?1",
                        params![peer_id, addrs_json],
                    )?;
                }
                UpsertPeer::Updated
            }
            _ => {
                return Err(StoreError::Mismatch {
                    what: "peer id and device key",
                })
            }
        };
        tx.commit()?;
        Ok(outcome)
    }

    /// Records that a peer belongs to a circle. Idempotent; returns whether it was new.
    pub fn add_peer_circle(&self, peer_id: &str, circle: &CircleId) -> Result<bool> {
        let n = self.conn.execute(
            "INSERT INTO peer_circles (peer_id, circle_id) VALUES (?1, ?2)
             ON CONFLICT DO NOTHING",
            params![peer_id, circle.to_string()],
        )?;
        Ok(n == 1)
    }

    /// Removes a peer's circle association (for example after its revocation).
    pub fn remove_peer_circle(&self, peer_id: &str, circle: &CircleId) -> Result<bool> {
        let n = self.conn.execute(
            "DELETE FROM peer_circles WHERE peer_id = ?1 AND circle_id = ?2",
            params![peer_id, circle.to_string()],
        )?;
        Ok(n == 1)
    }

    fn with_circles(&self, mut p: PeerRow) -> Result<PeerRow> {
        let mut st = self.conn.prepare_cached(
            "SELECT circle_id FROM peer_circles WHERE peer_id = ?1 ORDER BY circle_id",
        )?;
        p.circles = st
            .query_map([&p.peer_id], |r| sql::parse(r, 0, "circle id"))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(p)
    }

    fn peers_query(&self, sql_text: &str, args: impl rusqlite::Params) -> Result<Vec<PeerRow>> {
        let mut st = self.conn.prepare(sql_text)?;
        let rows = st
            .query_map(args, base_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(|p| self.with_circles(p)).collect()
    }

    /// The peer with this `PeerId`.
    pub fn peer(&self, peer_id: &str) -> Result<Option<PeerRow>> {
        let p = self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM peers WHERE peer_id = ?1"),
                [peer_id],
                base_row,
            )
            .optional()?;
        p.map(|p| self.with_circles(p)).transpose()
    }

    /// The peer with this device key.
    pub fn peer_by_device_key(&self, key: &DeviceKey) -> Result<Option<PeerRow>> {
        let p = self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM peers WHERE device_key = ?1"),
                [key.to_string()],
                base_row,
            )
            .optional()?;
        p.map(|p| self.with_circles(p)).transpose()
    }

    /// All peers, ordered by `peer_id`.
    pub fn peers(&self) -> Result<Vec<PeerRow>> {
        self.peers_query(&format!("SELECT {COLS} FROM peers ORDER BY peer_id"), [])
    }

    /// Peers associated with a circle, ordered by `peer_id` (blocked ones included;
    /// check [`PeerRow::blocked`]).
    pub fn peers_for_circle(&self, circle: &CircleId) -> Result<Vec<PeerRow>> {
        self.peers_query(
            "SELECT p.peer_id, p.device_key, p.addrs_json, p.created_at, p.last_seen,
                    p.blocked, p.muted
             FROM peers p JOIN peer_circles pc ON pc.peer_id = p.peer_id
             WHERE pc.circle_id = ?1 ORDER BY p.peer_id",
            [circle.to_string()],
        )
    }

    fn set_peer_flag(&self, column: &str, peer_id: &str, v: bool) -> Result<()> {
        let n = self.conn.execute(
            &format!("UPDATE peers SET {column} = ?2 WHERE peer_id = ?1"),
            params![peer_id, sql::b(v)],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound { what: "peer" });
        }
        Ok(())
    }

    /// Sets or clears the local block flag.
    pub fn set_peer_blocked(&self, peer_id: &str, blocked: bool) -> Result<()> {
        self.set_peer_flag("blocked", peer_id, blocked)
    }

    /// Sets or clears the local mute flag.
    pub fn set_peer_muted(&self, peer_id: &str, muted: bool) -> Result<()> {
        self.set_peer_flag("muted", peer_id, muted)
    }

    /// Updates `last_seen` (never moves it backwards).
    pub fn touch_peer_last_seen(&self, peer_id: &str, now: Timestamp) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE peers SET last_seen = MAX(COALESCE(last_seen, ?2), ?2) WHERE peer_id = ?1",
            params![peer_id, now.unix_seconds()],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound { what: "peer" });
        }
        Ok(())
    }
}

/// Outcome of [`Store::upsert_peer`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UpsertPeer {
    /// A new peer row was created.
    Inserted,
    /// The existing row was found (and its addresses replaced if any were given).
    Updated,
}
