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

/// The values of `circles.adoption_mode`: install passed rules without asking
/// (`"follow"`) or ask the owner first (`"ask"`). See architecture section 10.9.
pub const ADOPTION_MODES: [&str; 2] = ["follow", "ask"];

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
    /// The owner's standing decision about rules that pass in this circle, one of
    /// [`ADOPTION_MODES`].
    pub adoption_mode: String,
    /// Digest of the charter the owner was last shown and accepted (`None` until then).
    pub accepted_charter: Option<Digest>,
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
            .field("adoption_mode", &self.adoption_mode)
            .field("accepted_charter", &self.accepted_charter)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

const COLS: &str = "circle_id, name, root_key, is_founder, root_keystore_ref, adoption_mode, \
                    accepted_charter, created_at";

fn row(r: &Row<'_>) -> rusqlite::Result<CircleRow> {
    Ok(CircleRow {
        circle_id: sql::parse(r, 0, "circle id")?,
        name: r.get(1)?,
        root_key: sql::parse(r, 2, "root key")?,
        is_founder: sql::flag(r, 3)?,
        root_keystore_ref: r.get(4)?,
        adoption_mode: r.get(5)?,
        accepted_charter: sql::parse_opt(r, 6, "charter digest")?,
        created_at: sql::ts(r, 7)?,
    })
}

impl Store {
    /// Inserts a circle.
    ///
    /// # Errors
    ///
    /// [`StoreError::Mismatch`] if `circle_id != CircleId::derive(root_key)`,
    /// [`StoreError::Invalid`] for a bad name (1-64 chars, single line) or an unknown
    /// adoption mode, [`StoreError::AlreadyExists`] if the id or the name is taken.
    pub fn insert_circle(&self, c: &CircleRow) -> Result<()> {
        if !c.circle_id.is_derived_from(&c.root_key) {
            return Err(StoreError::Mismatch {
                what: "circle id and root key",
            });
        }
        check_text("circle name", &c.name, 1, CIRCLE_NAME, Lines::Single)
            .map_err(|_| StoreError::invalid("circle name", "expected 1-64 characters"))?;
        check_adoption_mode(&c.adoption_mode)?;
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
                c.adoption_mode,
                c.accepted_charter.as_ref().map(ToString::to_string),
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

    /// Records the owner's adoption mode for a circle and the digest of the charter the
    /// owner was shown and accepted when choosing it.
    ///
    /// Only call this after an explicit human confirmation: `"follow"` lets rules that
    /// pass in the circle be installed without asking (architecture section 10.9).
    pub fn set_circle_adoption(
        &self,
        id: &CircleId,
        adoption_mode: &str,
        accepted_charter: &Digest,
    ) -> Result<()> {
        check_adoption_mode(adoption_mode)?;
        let n = self.conn.execute(
            "UPDATE circles SET adoption_mode = ?2, accepted_charter = ?3 WHERE circle_id = ?1",
            params![id.to_string(), adoption_mode, accepted_charter.to_string()],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound { what: "circle" });
        }
        Ok(())
    }

    /// When the owner stopped following `id` on this machine (`circle leave`), if they
    /// did. A circle that was left installs nothing here; the node stays on the roll
    /// until the members amend it.
    pub fn circle_left_at(&self, id: &CircleId) -> Result<Option<Timestamp>> {
        let left: Option<Option<i64>> = self
            .conn
            .query_row(
                "SELECT left_at FROM circles WHERE circle_id = ?1",
                [id.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        match left.flatten() {
            Some(secs) => Timestamp::from_unix_seconds(secs)
                .map(Some)
                .map_err(|_| StoreError::Corrupt { what: "left_at" }),
            None => Ok(None),
        }
    }

    /// Records that the owner left `id` at `at`, or (`None`) follows it again.
    pub fn set_circle_left(&self, id: &CircleId, at: Option<Timestamp>) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE circles SET left_at = ?2 WHERE circle_id = ?1",
            params![id.to_string(), at.map(|t| t.unix_seconds())],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound { what: "circle" });
        }
        Ok(())
    }
}

fn check_adoption_mode(mode: &str) -> Result<()> {
    if ADOPTION_MODES.contains(&mode) {
        Ok(())
    } else {
        Err(StoreError::invalid(
            "adoption mode",
            "expected follow or ask",
        ))
    }
}
