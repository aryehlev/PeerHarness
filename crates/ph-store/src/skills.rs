//! `bundles` (metadata only; files live in ph-skills' bundle store), `skills` and
//! `installations`.

use std::fmt;
use std::str::FromStr;

use ph_core::{is_valid_skill_name, Digest, ParseError, Timestamp};
use ph_protocol::{bundle_digest, BundleManifest};
use rusqlite::{params, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

use crate::error::{Result, StoreError};
use crate::sql;
use crate::Store;

/// Maximum length of a stored path (bundle `rel_path`, installation `path`).
pub const MAX_PATH_BYTES: usize = 4096;

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

// =======================================================================================
// bundles
// =======================================================================================

/// Metadata of an immutable content-addressed bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BundleRow {
    /// `bundle_digest(manifest)`.
    pub digest: Digest,
    /// Skill name from the bundle's frontmatter.
    pub skill_name: String,
    /// The manifest.
    pub manifest: BundleManifest,
    /// Path of the bundle directory relative to `$PEERHARNESS_HOME`
    /// (for example `bundles/<hex>`).
    pub rel_path: String,
    /// Total content size in bytes (`manifest.total_size()`).
    pub size: u64,
    /// When it was stored.
    pub created_at: Timestamp,
}

fn check_rel_path(p: &str) -> Result<()> {
    let bad = p.is_empty()
        || p.len() > MAX_PATH_BYTES
        || p.starts_with('/')
        || p.contains('\\')
        || p.contains('\0')
        || p.split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..");
    if bad {
        return Err(StoreError::invalid(
            "bundle path",
            "expected a relative path without '.', '..' or empty segments",
        ));
    }
    Ok(())
}

fn bundle_row(r: &Row<'_>) -> rusqlite::Result<BundleRow> {
    Ok(BundleRow {
        digest: sql::parse(r, 0, "bundle digest")?,
        skill_name: r.get(1)?,
        manifest: sql::json(r, 2, "bundle manifest")?,
        rel_path: r.get(3)?,
        size: sql::uint(r, 4, "bundle size")?,
        created_at: sql::ts(r, 5)?,
    })
}

const B_COLS: &str = "digest, skill_name, manifest_json, rel_path, size, created_at";

// =======================================================================================
// skills
// =======================================================================================

/// Where a skill came from.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillOrigin {
    /// Generated from a local candidate (`origin_ref` = candidate id).
    Local,
    /// Adopted from a circle proposal (`origin_ref` = PROPOSAL event id).
    Proposal,
}

impl SkillOrigin {
    /// Stored string form.
    pub const fn as_str(self) -> &'static str {
        match self {
            SkillOrigin::Local => "local",
            SkillOrigin::Proposal => "proposal",
        }
    }
}

impl FromStr for SkillOrigin {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        match s {
            "local" => Ok(Self::Local),
            "proposal" => Ok(Self::Proposal),
            _ => Err(ParseError::new("skill origin", "unknown origin")),
        }
    }
}

/// Local state of a skill.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillStatus {
    /// Known and available to install.
    Available,
    /// Currently installed for at least one agent/scope.
    Installed,
    /// Was installed and has been removed.
    Uninstalled,
    /// The local human refused it (a distinct local view; spec section 11).
    Refused,
}

impl SkillStatus {
    /// Stored string form.
    pub const fn as_str(self) -> &'static str {
        match self {
            SkillStatus::Available => "available",
            SkillStatus::Installed => "installed",
            SkillStatus::Uninstalled => "uninstalled",
            SkillStatus::Refused => "refused",
        }
    }
}

impl fmt::Display for SkillStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SkillStatus {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        match s {
            "available" => Ok(Self::Available),
            "installed" => Ok(Self::Installed),
            "uninstalled" => Ok(Self::Uninstalled),
            "refused" => Ok(Self::Refused),
            _ => Err(ParseError::new("skill status", "unknown status")),
        }
    }
}

/// A skill to store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewSkill {
    /// Skill name.
    pub name: String,
    /// Bundle digest (the bundle must be stored first).
    pub bundle_digest: Digest,
    /// Origin kind.
    pub origin_kind: SkillOrigin,
    /// Candidate id (local) or PROPOSAL event id (proposal).
    pub origin_ref: String,
    /// Initial status.
    pub status: SkillStatus,
    /// Creation time.
    pub created_at: Timestamp,
}

/// A stored skill.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SkillRow {
    /// Local numeric id (`peerharness skills show <id>`).
    pub id: i64,
    /// Skill name.
    pub name: String,
    /// Bundle digest.
    pub bundle_digest: Digest,
    /// Origin kind.
    pub origin_kind: SkillOrigin,
    /// Candidate id or PROPOSAL event id.
    pub origin_ref: String,
    /// Local status.
    pub status: SkillStatus,
    /// Creation time.
    pub created_at: Timestamp,
    /// Last status change.
    pub updated_at: Timestamp,
}

const S_COLS: &str =
    "id, name, bundle_digest, origin_kind, origin_ref, status, created_at, updated_at";

fn skill_row(r: &Row<'_>) -> rusqlite::Result<SkillRow> {
    Ok(SkillRow {
        id: r.get(0)?,
        name: r.get(1)?,
        bundle_digest: sql::parse(r, 2, "bundle digest")?,
        origin_kind: sql::parse(r, 3, "skill origin")?,
        origin_ref: r.get(4)?,
        status: sql::parse(r, 5, "skill status")?,
        created_at: sql::ts(r, 6)?,
        updated_at: sql::ts(r, 7)?,
    })
}

// =======================================================================================
// installations
// =======================================================================================

/// An installation to record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewInstallation {
    /// Skill name.
    pub skill_name: String,
    /// Agent (`"claude"`).
    pub agent: String,
    /// Install scope (`"user"` or `"project"`).
    pub install_scope: String,
    /// Absolute path of the installed skill directory.
    pub path: String,
    /// Installed bundle (must be stored).
    pub bundle_digest: Digest,
    /// Bundle that was installed at the same location before, for rollback.
    pub previous_digest: Option<Digest>,
    /// Install time.
    pub installed_at: Timestamp,
}

/// A stored installation record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InstallationRow {
    /// Local id.
    pub id: i64,
    /// Skill name.
    pub skill_name: String,
    /// Agent.
    pub agent: String,
    /// Install scope.
    pub install_scope: String,
    /// Installed directory.
    pub path: String,
    /// Installed bundle.
    pub bundle_digest: Digest,
    /// Previously installed bundle at this location.
    pub previous_digest: Option<Digest>,
    /// Install time.
    pub installed_at: Timestamp,
    /// When it was removed or replaced (`None` while active).
    pub removed_at: Option<Timestamp>,
}

const I_COLS: &str = "id, skill_name, agent, install_scope, path, bundle_digest, previous_digest, \
                      installed_at, removed_at";

fn inst_row(r: &Row<'_>) -> rusqlite::Result<InstallationRow> {
    Ok(InstallationRow {
        id: r.get(0)?,
        skill_name: r.get(1)?,
        agent: r.get(2)?,
        install_scope: r.get(3)?,
        path: r.get(4)?,
        bundle_digest: sql::parse(r, 5, "bundle digest")?,
        previous_digest: sql::parse_opt(r, 6, "bundle digest")?,
        installed_at: sql::ts(r, 7)?,
        removed_at: sql::ts_opt(r, 8)?,
    })
}

impl Store {
    // ------------------------------------------------------------------ bundles

    /// Records bundle metadata. Idempotent on the digest: returns `false` if it is
    /// already stored (bundles are immutable, so the stored row is kept).
    ///
    /// Checks that `digest == bundle_digest(manifest)`, that `size` equals the
    /// manifest's total size, the skill name, and that `rel_path` is a clean relative
    /// path.
    pub fn insert_bundle(&self, b: &BundleRow) -> Result<bool> {
        if bundle_digest(&b.manifest)? != b.digest {
            return Err(StoreError::Mismatch {
                what: "bundle digest and manifest",
            });
        }
        if b.manifest.total_size() != b.size {
            return Err(StoreError::Mismatch {
                what: "bundle size and manifest",
            });
        }
        check_skill_name(&b.skill_name)?;
        check_rel_path(&b.rel_path)?;
        let manifest_json = b.manifest.to_canonical_json()?;
        let n = self.conn.execute(
            &format!(
                "INSERT INTO bundles ({B_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(digest) DO NOTHING"
            ),
            params![
                b.digest.to_string(),
                b.skill_name,
                manifest_json,
                b.rel_path,
                sql::int(b.size, "bundle size")?,
                b.created_at.unix_seconds()
            ],
        )?;
        Ok(n == 1)
    }

    /// Bundle metadata by digest.
    pub fn bundle(&self, digest: &Digest) -> Result<Option<BundleRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {B_COLS} FROM bundles WHERE digest = ?1"),
                [digest.to_string()],
                bundle_row,
            )
            .optional()?)
    }

    /// All bundles, oldest first.
    pub fn bundles(&self) -> Result<Vec<BundleRow>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {B_COLS} FROM bundles ORDER BY created_at, digest"
        ))?;
        let rows = st
            .query_map([], bundle_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ------------------------------------------------------------------ skills

    /// Stores a skill. Idempotent on `(name, bundle_digest)`: returns the existing id
    /// and `false` if that pair is already stored.
    ///
    /// # Errors
    ///
    /// [`StoreError::MissingReference`] if the bundle is not stored.
    pub fn insert_skill(&self, s: &NewSkill) -> Result<(i64, bool)> {
        check_skill_name(&s.name)?;
        sql::check_short("skill origin reference", &s.origin_ref, 256)?;
        let tx = self.tx()?;
        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM skills WHERE name = ?1 AND bundle_digest = ?2",
                params![s.name, s.bundle_digest.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            return Ok((id, false));
        }
        self.conn.execute(
            "INSERT INTO skills (name, bundle_digest, origin_kind, origin_ref, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            params![
                s.name,
                s.bundle_digest.to_string(),
                s.origin_kind.as_str(),
                s.origin_ref,
                s.status.as_str(),
                s.created_at.unix_seconds()
            ],
        )?;
        let id = self.conn.last_insert_rowid();
        tx.commit()?;
        Ok((id, true))
    }

    /// The skill with this id.
    pub fn skill(&self, id: i64) -> Result<Option<SkillRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {S_COLS} FROM skills WHERE id = ?1"),
                [id],
                skill_row,
            )
            .optional()?)
    }

    /// The most recently stored skill with this name.
    pub fn skill_by_name(&self, name: &str) -> Result<Option<SkillRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {S_COLS} FROM skills WHERE name = ?1 ORDER BY id DESC LIMIT 1"),
                [name],
                skill_row,
            )
            .optional()?)
    }

    /// All versions of a skill name, oldest first.
    pub fn skills_by_name(&self, name: &str) -> Result<Vec<SkillRow>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {S_COLS} FROM skills WHERE name = ?1 ORDER BY id"
        ))?;
        let rows = st
            .query_map([name], skill_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// All skills, ordered by id.
    pub fn skills(&self) -> Result<Vec<SkillRow>> {
        let mut st = self
            .conn
            .prepare(&format!("SELECT {S_COLS} FROM skills ORDER BY id"))?;
        let rows = st
            .query_map([], skill_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Sets a skill's status.
    pub fn set_skill_status(&self, id: i64, status: SkillStatus, now: Timestamp) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE skills SET status = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, status.as_str(), now.unix_seconds()],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound { what: "skill" });
        }
        Ok(())
    }

    // ------------------------------------------------------------------ installations

    /// Records an installation. Any active installation of the same skill at the same
    /// `(agent, install_scope, path)` is closed (`removed_at = installed_at`) in the
    /// same transaction, so at most one installation per location is active.
    ///
    /// # Errors
    ///
    /// [`StoreError::MissingReference`] if `bundle_digest` is not a stored bundle.
    pub fn record_install(&self, i: &NewInstallation) -> Result<i64> {
        check_skill_name(&i.skill_name)?;
        sql::check_short("agent", &i.agent, 64)?;
        sql::check_short("install scope", &i.install_scope, 64)?;
        sql::check_short("install path", &i.path, MAX_PATH_BYTES)?;
        let tx = self.tx()?;
        self.conn.execute(
            "UPDATE installations SET removed_at = ?5
             WHERE skill_name = ?1 AND agent = ?2 AND install_scope = ?3 AND path = ?4
               AND removed_at IS NULL",
            params![
                i.skill_name,
                i.agent,
                i.install_scope,
                i.path,
                i.installed_at.unix_seconds()
            ],
        )?;
        let bundle_known: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM bundles WHERE digest = ?1)",
            [i.bundle_digest.to_string()],
            |r| r.get(0),
        )?;
        if !bundle_known {
            return Err(StoreError::MissingReference);
        }
        self.conn.execute(
            "INSERT INTO installations
                 (skill_name, agent, install_scope, path, bundle_digest, previous_digest, installed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                i.skill_name,
                i.agent,
                i.install_scope,
                i.path,
                i.bundle_digest.to_string(),
                i.previous_digest.as_ref().map(ToString::to_string),
                i.installed_at.unix_seconds()
            ],
        )?;
        let id = self.conn.last_insert_rowid();
        tx.commit()?;
        tracing::debug!(installation = id, "recorded installation");
        Ok(id)
    }

    /// The most recent active installation of `skill_name` for `(agent, install_scope)`
    /// (any path).
    pub fn active_installation(
        &self,
        skill_name: &str,
        agent: &str,
        install_scope: &str,
    ) -> Result<Option<InstallationRow>> {
        Ok(self
            .conn
            .query_row(
                &format!(
                    "SELECT {I_COLS} FROM installations
                     WHERE skill_name = ?1 AND agent = ?2 AND install_scope = ?3
                       AND removed_at IS NULL
                     ORDER BY installed_at DESC, id DESC LIMIT 1"
                ),
                params![skill_name, agent, install_scope],
                inst_row,
            )
            .optional()?)
    }

    /// The active installation of `skill_name` at exactly this location.
    pub fn active_installation_at(
        &self,
        skill_name: &str,
        agent: &str,
        install_scope: &str,
        path: &str,
    ) -> Result<Option<InstallationRow>> {
        Ok(self
            .conn
            .query_row(
                &format!(
                    "SELECT {I_COLS} FROM installations
                     WHERE skill_name = ?1 AND agent = ?2 AND install_scope = ?3 AND path = ?4
                       AND removed_at IS NULL"
                ),
                params![skill_name, agent, install_scope, path],
                inst_row,
            )
            .optional()?)
    }

    /// All active installations, ordered by skill name then id.
    pub fn active_installations(&self) -> Result<Vec<InstallationRow>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {I_COLS} FROM installations WHERE removed_at IS NULL ORDER BY skill_name, id"
        ))?;
        let rows = st
            .query_map([], inst_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Marks an installation removed. Returns `false` if it was already removed.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the id does not exist.
    pub fn mark_installation_removed(&self, id: i64, at: Timestamp) -> Result<bool> {
        let tx = self.tx()?;
        let n = self.conn.execute(
            "UPDATE installations SET removed_at = ?2 WHERE id = ?1 AND removed_at IS NULL",
            params![id, at.unix_seconds()],
        )?;
        if n == 0 {
            let exists: bool = self.conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM installations WHERE id = ?1)",
                [id],
                |r| r.get(0),
            )?;
            if !exists {
                return Err(StoreError::NotFound {
                    what: "installation",
                });
            }
        }
        tx.commit()?;
        Ok(n == 1)
    }

    /// Every installation record of a skill, oldest first.
    pub fn installation_history(&self, skill_name: &str) -> Result<Vec<InstallationRow>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {I_COLS} FROM installations WHERE skill_name = ?1 ORDER BY installed_at, id"
        ))?;
        let rows = st
            .query_map([skill_name], inst_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Every installation record (for export).
    pub fn all_installations(&self) -> Result<Vec<InstallationRow>> {
        let mut st = self
            .conn
            .prepare(&format!("SELECT {I_COLS} FROM installations ORDER BY id"))?;
        let rows = st
            .query_map([], inst_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rel_paths() {
        assert!(check_rel_path("bundles/abc").is_ok());
        assert!(check_rel_path("bundles/abc/SKILL.md").is_ok());
        for bad in [
            "", "/abs", "a/../b", "a//b", "./a", "a\\b", "a/", "..", "a/\0",
        ] {
            assert!(check_rel_path(bad).is_err(), "{bad:?}");
        }
    }
}
