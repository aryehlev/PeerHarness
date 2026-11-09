//! `circles`: circles this node founded or joined.

use std::fmt;

use ph_core::{CircleId, DeviceKey, Digest, Timestamp};
use ph_protocol::limits::text::CIRCLE_NAME;
use ph_protocol::text::{check_text, Lines};
use rusqlite::{params, OptionalExtension, Row};
use serde::Serialize;

use crate::error::{Result, StoreError};
use crate::sql;
use crate::Store;

/// Maximum size of a stored circle policy document.
pub const MAX_POLICY_JSON_BYTES: usize = 16 * 1024;

/// A circle row.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct CircleRow {
    /// `CircleId::derive(root_key)`.
    pub circle_id: CircleId,
    /// Local label (unique on this node; for joined circles it comes from the invite).
    pub name: String,
    /// The circle root (authority) public key.
    pub root_key: DeviceKey,
    /// Whether this node created the circle and holds its root key.
    pub is_founder: bool,
    /// Keystore reference of the root private key (founder only; never key bytes).
    pub root_keystore_ref: Option<String>,
    /// Circle policy document (JSON text owned by ph-governance).
    pub policy_json: String,
    /// Hash of the policy, as computed by ph-governance.
    pub policy_hash: Digest,
    /// When the row was created locally.
    pub created_at: Timestamp,
}

impl fmt::Debug for CircleRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CircleRow")
            .field("circle_id", &self.circle_id)
            .field("name_len", &self.name.len())
            .field("root_key", &self.root_key)
            .field("is_founder", &self.is_founder)
            .field("policy_hash", &self.policy_hash)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

const COLS: &str = "circle_id, name, root_key, is_founder, root_keystore_ref, policy_json, \
                    policy_hash, created_at";

fn row(r: &Row<'_>) -> rusqlite::Result<CircleRow> {
    Ok(CircleRow {
        circle_id: sql::parse(r, 0, "circle id")?,
        name: r.get(1)?,
        root_key: sql::parse(r, 2, "root key")?,
        is_founder: sql::flag(r, 3)?,
        root_keystore_ref: r.get(4)?,
        policy_json: r.get(5)?,
        policy_hash: sql::parse(r, 6, "policy hash")?,
        created_at: sql::ts(r, 7)?,
    })
}

impl Store {
    /// Inserts a circle.
    ///
    /// # Errors
    ///
    /// [`StoreError::Mismatch`] if `circle_id != CircleId::derive(root_key)`,
    /// [`StoreError::Invalid`] for a bad name (1-64 chars, single line) or oversized
    /// policy, [`StoreError::AlreadyExists`] if the id or the name is taken.
    pub fn insert_circle(&self, c: &CircleRow) -> Result<()> {
        if !c.circle_id.is_derived_from(&c.root_key) {
            return Err(StoreError::Mismatch {
                what: "circle id and root key",
            });
        }
        check_text("circle name", &c.name, 1, CIRCLE_NAME, Lines::Single)
            .map_err(|_| StoreError::invalid("circle name", "expected 1-64 characters"))?;
        if c.policy_json.len() > MAX_POLICY_JSON_BYTES {
            return Err(StoreError::invalid("circle policy", "too large"));
        }
        if let Some(r) = &c.root_keystore_ref {
            sql::check_short("root keystore reference", r, 1024)?;
        }
        let res = self.conn.execute(
            &format!("INSERT INTO circles ({COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"),
            params![
                c.circle_id.to_string(),
                c.name,
                c.root_key.to_string(),
                sql::b(c.is_founder),
                c.root_keystore_ref,
                c.policy_json,
                c.policy_hash.to_string(),
                c.created_at.unix_seconds()
            ],
        );
        match res.map_err(StoreError::from) {
            Ok(_) => Ok(()),
            Err(StoreError::Constraint) => Err(StoreError::AlreadyExists { what: "circle" }),
            Err(e) => Err(e),
        }
    }

    /// The circle with this id.
    pub fn circle(&self, id: &CircleId) -> Result<Option<CircleRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM circles WHERE circle_id = ?1"),
                [id.to_string()],
                row,
            )
            .optional()?)
    }

    /// The circle with this local name (names are unique per node).
    pub fn circle_by_name(&self, name: &str) -> Result<Option<CircleRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM circles WHERE name = ?1"),
                [name],
                row,
            )
            .optional()?)
    }

    /// All circles, ordered by creation time.
    pub fn circles(&self) -> Result<Vec<CircleRow>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS} FROM circles ORDER BY created_at, circle_id"
        ))?;
        let rows = st
            .query_map([], row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Replaces a circle's policy document and hash.
    pub fn set_circle_policy(
        &self,
        id: &CircleId,
        policy_json: &str,
        policy_hash: &Digest,
    ) -> Result<()> {
        if policy_json.len() > MAX_POLICY_JSON_BYTES {
            return Err(StoreError::invalid("circle policy", "too large"));
        }
        let n = self.conn.execute(
            "UPDATE circles SET policy_json = ?2, policy_hash = ?3 WHERE circle_id = ?1",
            params![id.to_string(), policy_json, policy_hash.to_string()],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound { what: "circle" });
        }
        Ok(())
    }
}
