//! `charters`, `rule_optouts` and `rule_installs`: the chain of charters this node has
//! accepted for each circle, the rules its owner opted out of, and the skills a circle's
//! vote installed on this machine (architecture section 10).
//!
//! The charter with the greatest `seq` is the circle's current charter. A node that
//! founded the circle holds the chain from `seq` 1; a node that joined later starts at
//! whatever charter its invitation carried, which is its trust anchor.
//!
//! The store checks what it can check cheaply and without a clock: the charter's
//! structure and root signature, that it belongs to the stored circle, and that it
//! links to the charter before it. It does **not** decide whether a successor is
//! legitimate: the caller must first run `ph_governance::check_successor`, which
//! verifies that a passed amendment justifies it.

use ph_core::{CircleId, Digest, Timestamp};
use ph_protocol::{verify_charter_signature, Charter};
use rusqlite::{params, OptionalExtension};

use crate::error::{Result, StoreError};
use crate::events::InsertOutcome;
use crate::sql;
use crate::Store;

fn parse_charter(json: String) -> Result<Charter> {
    let charter = Charter::from_json_bytes(json.as_bytes()).map_err(|_| StoreError::Corrupt {
        what: "stored charter",
    })?;
    // A stored charter was verified on insert; verifying again on load costs one
    // signature check and means a tampered database cannot change who may vote.
    verify_charter_signature(&charter).map_err(|_| StoreError::Corrupt {
        what: "stored charter",
    })?;
    Ok(charter)
}

impl Store {
    /// Records `charter` as accepted for its circle.
    ///
    /// The first charter stored for a circle may have any `seq` (it is the trust
    /// anchor: the founding charter, or the one a joining node received in its
    /// invitation). Every later one must be the next in the chain: `seq` one greater
    /// than the current charter's and `previous` equal to its digest.
    ///
    /// **Precondition for a successor:** the caller has verified it with
    /// `ph_governance::check_successor`. This method cannot check that a vote
    /// justifies it.
    ///
    /// Returns [`InsertOutcome::Duplicate`] if exactly this charter is already stored.
    ///
    /// # Errors
    ///
    /// [`StoreError::Protocol`] if the structure or root signature does not verify,
    /// [`StoreError::MissingReference`] if the circle is not stored,
    /// [`StoreError::Mismatch`] if it is for another root key or does not follow the
    /// current charter.
    pub fn insert_charter(
        &self,
        charter: &Charter,
        accepted_at: Timestamp,
    ) -> Result<InsertOutcome> {
        verify_charter_signature(charter)?;
        let digest = charter.digest()?;
        let json = charter.to_canonical_json()?;
        let tx = self.tx()?;
        let circle = self
            .circle(&charter.circle_id)?
            .ok_or(StoreError::MissingReference)?;
        if circle.root_key != charter.issuer_key {
            return Err(StoreError::Mismatch {
                what: "charter issuer and circle root key",
            });
        }
        if self
            .charter_by_digest(&charter.circle_id, &digest)?
            .is_some()
        {
            return Ok(InsertOutcome::Duplicate);
        }
        if let Some(current) = self.current_charter(&charter.circle_id)? {
            let follows =
                charter.seq == current.seq + 1 && charter.previous == Some(current.digest()?);
            if !follows {
                return Err(StoreError::Mismatch {
                    what: "charter and the current charter",
                });
            }
        }
        self.conn.execute(
            "INSERT INTO charters (circle_id, seq, digest, charter_json, accepted_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                charter.circle_id.to_string(),
                i64::try_from(charter.seq)
                    .map_err(|_| StoreError::invalid("charter seq", "out of range"))?,
                digest.to_string(),
                json,
                accepted_at.unix_seconds()
            ],
        )?;
        tx.commit()?;
        tracing::debug!(circle = %charter.circle_id, seq = charter.seq, "charter accepted");
        Ok(InsertOutcome::Inserted)
    }

    /// Stores a charter that is **older** than every charter this node holds for the
    /// circle, as history.
    ///
    /// A node that joined late starts at the charter in its invitation and cannot check
    /// the votes that came before it. It can still hold the earlier charters, because
    /// every charter names its predecessor by hash: `charter` is accepted here only if
    /// the oldest charter already stored has `previous` equal to its digest and a `seq`
    /// one greater. The hash link authenticates it, and the root signature and issuer are
    /// checked as for any charter. History never becomes the current charter and gives
    /// nobody a vote; it lets the node verify and keep the proposals, ballots and results
    /// that name it, which is how a rule carried from before the node joined arrives.
    pub fn insert_charter_history(
        &self,
        charter: &Charter,
        accepted_at: Timestamp,
    ) -> Result<InsertOutcome> {
        verify_charter_signature(charter)?;
        let digest = charter.digest()?;
        let json = charter.to_canonical_json()?;
        let tx = self.tx()?;
        let circle = self
            .circle(&charter.circle_id)?
            .ok_or(StoreError::MissingReference)?;
        if circle.root_key != charter.issuer_key {
            return Err(StoreError::Mismatch {
                what: "charter issuer and circle root key",
            });
        }
        if self
            .charter_by_digest(&charter.circle_id, &digest)?
            .is_some()
        {
            return Ok(InsertOutcome::Duplicate);
        }
        let oldest = self
            .oldest_charter(&charter.circle_id)?
            .ok_or(StoreError::MissingReference)?;
        let precedes =
            oldest.previous == Some(digest) && charter.seq.checked_add(1) == Some(oldest.seq);
        if !precedes {
            return Err(StoreError::Mismatch {
                what: "charter and the oldest accepted charter",
            });
        }
        self.conn.execute(
            "INSERT INTO charters (circle_id, seq, digest, charter_json, accepted_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                charter.circle_id.to_string(),
                i64::try_from(charter.seq)
                    .map_err(|_| StoreError::invalid("charter seq", "out of range"))?,
                digest.to_string(),
                json,
                accepted_at.unix_seconds()
            ],
        )?;
        tx.commit()?;
        tracing::debug!(circle = %charter.circle_id, seq = charter.seq, "charter history stored");
        Ok(InsertOutcome::Inserted)
    }

    /// The oldest charter this node holds for `circle` (its trust anchor, or history
    /// stored behind it).
    pub fn oldest_charter(&self, circle: &CircleId) -> Result<Option<Charter>> {
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT charter_json FROM charters WHERE circle_id = ?1
                 ORDER BY seq ASC LIMIT 1",
                [circle.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        json.map(parse_charter).transpose()
    }

    /// The circle's current charter: the accepted one with the greatest `seq`.
    pub fn current_charter(&self, circle: &CircleId) -> Result<Option<Charter>> {
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT charter_json FROM charters WHERE circle_id = ?1
                 ORDER BY seq DESC LIMIT 1",
                [circle.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        json.map(parse_charter).transpose()
    }

    /// The accepted charter of `circle` with this digest, if any. This is what
    /// decision-event authorization looks up for the charter a proposal names.
    pub fn charter_by_digest(&self, circle: &CircleId, digest: &Digest) -> Result<Option<Charter>> {
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT charter_json FROM charters WHERE circle_id = ?1 AND digest = ?2",
                params![circle.to_string(), digest.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        json.map(parse_charter).transpose()
    }

    /// Every accepted charter of `circle`, oldest first.
    pub fn charters(&self, circle: &CircleId) -> Result<Vec<Charter>> {
        let mut st = self
            .conn
            .prepare("SELECT charter_json FROM charters WHERE circle_id = ?1 ORDER BY seq")?;
        let jsons = st
            .query_map([circle.to_string()], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        jsons.into_iter().map(parse_charter).collect()
    }

    /// Records that the owner opted out of the rule named `skill_name` in `circle`.
    /// Idempotent; the first opt-out time is kept.
    ///
    /// Only call this on an explicit human action.
    pub fn set_rule_opt_out(
        &self,
        circle: &CircleId,
        skill_name: &str,
        at: Timestamp,
    ) -> Result<()> {
        if !ph_core::is_valid_skill_name(skill_name) {
            return Err(StoreError::invalid("skill name", "not a valid skill name"));
        }
        // A foreign-key failure (unknown circle) maps to `StoreError::MissingReference`.
        self.conn.execute(
            "INSERT INTO rule_optouts (circle_id, skill_name, opted_out_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(circle_id, skill_name) DO NOTHING",
            params![circle.to_string(), skill_name, at.unix_seconds()],
        )?;
        Ok(())
    }

    /// Removes an opt-out. Returns whether one existed.
    pub fn clear_rule_opt_out(&self, circle: &CircleId, skill_name: &str) -> Result<bool> {
        let n = self.conn.execute(
            "DELETE FROM rule_optouts WHERE circle_id = ?1 AND skill_name = ?2",
            params![circle.to_string(), skill_name],
        )?;
        Ok(n > 0)
    }

    /// Whether the owner opted out of the rule named `skill_name` in `circle`.
    pub fn is_rule_opted_out(&self, circle: &CircleId, skill_name: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM rule_optouts WHERE circle_id = ?1 AND skill_name = ?2)",
            params![circle.to_string(), skill_name],
            |r| r.get(0),
        )?)
    }

    /// The rules the owner opted out of in `circle`, with the time of each opt-out,
    /// sorted by skill name.
    pub fn rule_opt_outs(&self, circle: &CircleId) -> Result<Vec<(String, Timestamp)>> {
        let mut st = self.conn.prepare(
            "SELECT skill_name, opted_out_at FROM rule_optouts WHERE circle_id = ?1
             ORDER BY skill_name",
        )?;
        let rows = st
            .query_map([circle.to_string()], |r| Ok((r.get(0)?, sql::ts(r, 1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Records that the rule `skill_name` of `circle` was installed on this machine with
    /// `digest` because it passed a vote. Replaces an earlier record for the same rule.
    pub fn record_rule_install(
        &self,
        circle: &CircleId,
        skill_name: &str,
        digest: &Digest,
        at: Timestamp,
    ) -> Result<()> {
        if !ph_core::is_valid_skill_name(skill_name) {
            return Err(StoreError::invalid("skill name", "not a valid skill name"));
        }
        self.conn.execute(
            "INSERT INTO rule_installs (circle_id, skill_name, bundle_digest, installed_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(circle_id, skill_name)
             DO UPDATE SET bundle_digest = excluded.bundle_digest,
                           installed_at = excluded.installed_at",
            params![
                circle.to_string(),
                skill_name,
                digest.to_string(),
                at.unix_seconds()
            ],
        )?;
        Ok(())
    }

    /// Forgets that `circle` installed `skill_name`. Returns whether a record existed.
    pub fn clear_rule_install(&self, circle: &CircleId, skill_name: &str) -> Result<bool> {
        let n = self.conn.execute(
            "DELETE FROM rule_installs WHERE circle_id = ?1 AND skill_name = ?2",
            params![circle.to_string(), skill_name],
        )?;
        Ok(n > 0)
    }

    /// The skills `circle`'s votes installed on this machine: name, bundle digest and
    /// time, sorted by name.
    pub fn rule_installs(&self, circle: &CircleId) -> Result<Vec<(String, Digest, Timestamp)>> {
        let mut st = self.conn.prepare(
            "SELECT skill_name, bundle_digest, installed_at FROM rule_installs
             WHERE circle_id = ?1 ORDER BY skill_name",
        )?;
        let rows = st
            .query_map([circle.to_string()], |r| {
                Ok((
                    r.get(0)?,
                    sql::parse::<Digest>(r, 1, "rule install digest")?,
                    sql::ts(r, 2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}
