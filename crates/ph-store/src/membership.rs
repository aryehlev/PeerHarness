//! `memberships`, `issued_invites` and `revocations`.
//!
//! The store performs **time-independent** integrity checks only (signatures, bindings
//! between credential, acceptance and circle). Callers must still run the full
//! `ph_protocol::verify_membership_proof` / `verify_revocation` at the current time
//! before trusting an object, and must evaluate expiry and revocation at use time.

use ph_core::{CircleId, DeviceKey, Digest, Role, Scope, Timestamp};
use ph_protocol::signing::verify_input;
use ph_protocol::{
    verify_credential_signature, Acceptance, Context, MembershipCredential, MembershipProof,
    Revocation,
};
use rusqlite::{params, OptionalExtension, Row};
use serde::Serialize;

use crate::error::{Result, StoreError};
use crate::sql;
use crate::Store;

/// Outcome of an idempotent upsert.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpsertOutcome {
    /// A new row was created.
    Inserted,
    /// An existing row gained information (an acceptance, or the self flag).
    Updated,
    /// The row already held everything supplied.
    Unchanged,
}

/// A stored membership credential (and its acceptance, once known).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MembershipRow {
    /// `credential.digest()`, the primary key.
    pub credential_digest: Digest,
    /// Circle of the credential.
    pub circle_id: CircleId,
    /// Subject device key.
    pub subject_key: DeviceKey,
    /// Granted roles.
    pub roles: Vec<Role>,
    /// Granted scopes.
    pub scopes: Vec<Scope>,
    /// Credential issue time.
    pub issued_at: Timestamp,
    /// Credential expiry.
    pub expires_at: Timestamp,
    /// The signed credential.
    pub credential: MembershipCredential,
    /// The subject's signed acceptance, if known. A credential is only *active* with one.
    pub acceptance: Option<Acceptance>,
    /// Whether the subject is this node's own device key.
    pub is_self: bool,
    /// When this node first stored it.
    pub received_at: Timestamp,
}

impl MembershipRow {
    /// The credential and acceptance as a proof, if the acceptance is known.
    pub fn proof(&self) -> Option<MembershipProof> {
        self.acceptance.as_ref().map(|a| MembershipProof {
            credential: self.credential.clone(),
            acceptance: a.clone(),
        })
    }
}

const M_COLS: &str = "credential_digest, circle_id, subject_key, roles_json, scopes_json, \
                      issued_at, expires_at, credential_json, acceptance_json, is_self, received_at";

fn m_row(r: &Row<'_>) -> rusqlite::Result<MembershipRow> {
    let cred_json: String = r.get(7)?;
    let credential = MembershipCredential::from_json_bytes(cred_json.as_bytes())
        .map_err(|_| sql::corrupt(7, "membership credential"))?;
    let acc_json: Option<String> = r.get(8)?;
    let acceptance = acc_json
        .map(|s| {
            Acceptance::from_json_bytes(s.as_bytes()).map_err(|_| sql::corrupt(8, "acceptance"))
        })
        .transpose()?;
    Ok(MembershipRow {
        credential_digest: sql::parse(r, 0, "credential digest")?,
        circle_id: sql::parse(r, 1, "circle id")?,
        subject_key: sql::parse(r, 2, "subject key")?,
        roles: sql::json(r, 3, "roles")?,
        scopes: sql::json(r, 4, "scopes")?,
        issued_at: sql::ts(r, 5)?,
        expires_at: sql::ts(r, 6)?,
        credential,
        acceptance,
        is_self: sql::flag(r, 9)?,
        received_at: sql::ts(r, 10)?,
    })
}

/// A record of an invite this node issued.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IssuedInviteRow {
    /// Digest of the credential inside the invite.
    pub credential_digest: Digest,
    /// Circle.
    pub circle_id: CircleId,
    /// The invitee's device key.
    pub invitee_key: DeviceKey,
    /// When the invite was created.
    pub created_at: Timestamp,
    /// When the invite stops being valid.
    pub invite_expires_at: Timestamp,
}

/// A stored revocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RevocationRow {
    /// Local row id.
    pub id: i64,
    /// Circle.
    pub circle_id: CircleId,
    /// Revoked device key.
    pub subject_key: DeviceKey,
    /// `revoked_at` of the signed revocation.
    pub revoked_at: Timestamp,
    /// The signed revocation.
    pub revocation: Revocation,
    /// When this node stored it.
    pub received_at: Timestamp,
    /// Per-circle revocation epoch: 1 for the first revocation stored for the circle,
    /// incremented by one for each further one.
    pub epoch: u64,
}

/// Outcome of [`Store::insert_revocation`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationInsert {
    /// Stored; the circle's revocation epoch is now `epoch`.
    Inserted {
        /// The new epoch.
        epoch: u64,
    },
    /// The subject was already revoked in this circle; nothing changed.
    AlreadyRevoked,
}

const R_COLS: &str = "id, circle_id, subject_key, revoked_at, revocation_json, received_at, epoch";

fn r_row(r: &Row<'_>) -> rusqlite::Result<RevocationRow> {
    let j: String = r.get(4)?;
    let revocation =
        Revocation::from_json_bytes(j.as_bytes()).map_err(|_| sql::corrupt(4, "revocation"))?;
    Ok(RevocationRow {
        id: r.get(0)?,
        circle_id: sql::parse(r, 1, "circle id")?,
        subject_key: sql::parse(r, 2, "subject key")?,
        revoked_at: sql::ts(r, 3)?,
        revocation,
        received_at: sql::ts(r, 5)?,
        epoch: sql::uint(r, 6, "epoch")?,
    })
}

fn check_acceptance(cred: &MembershipCredential, digest: &Digest, acc: &Acceptance) -> Result<()> {
    if acc.credential_digest != *digest
        || acc.subject_device_key != cred.subject_device_key
        || acc.circle_id != cred.circle_id
    {
        return Err(StoreError::Mismatch {
            what: "acceptance does not match credential",
        });
    }
    verify_input(
        Context::Acceptance,
        &acc.subject_device_key,
        &acc.signing_input()?,
        &acc.signature,
    )?;
    Ok(())
}

impl Store {
    /// Stores a credential with its acceptance. See [`Store::upsert_membership`].
    pub fn upsert_membership_proof(
        &self,
        proof: &MembershipProof,
        is_self: bool,
        received_at: Timestamp,
    ) -> Result<UpsertOutcome> {
        self.upsert_membership(
            &proof.credential,
            Some(&proof.acceptance),
            is_self,
            received_at,
        )
    }

    /// Stores a credential, optionally with its acceptance, keyed by credential digest.
    ///
    /// Idempotent: storing the same credential again never removes information. An
    /// existing acceptance is kept (a different later one is ignored), a missing one is
    /// filled in, and `is_self` is only ever raised. `received_at` keeps the first value.
    ///
    /// Checks (time-independent): the credential's structure and root signature, and,
    /// if given, that the acceptance references this credential digest, subject and
    /// circle and carries a valid subject signature. Expiry is **not** checked here.
    ///
    /// # Errors
    ///
    /// [`StoreError::Protocol`] for a bad signature or structure,
    /// [`StoreError::Mismatch`] for an acceptance of another credential, and
    /// [`StoreError::MissingReference`] if the circle is not stored.
    pub fn upsert_membership(
        &self,
        cred: &MembershipCredential,
        acceptance: Option<&Acceptance>,
        is_self: bool,
        received_at: Timestamp,
    ) -> Result<UpsertOutcome> {
        verify_credential_signature(cred)?;
        let digest = cred.digest()?;
        if let Some(acc) = acceptance {
            check_acceptance(cred, &digest, acc)?;
        }
        let cred_json = cred.to_canonical_json()?;
        let acc_json = acceptance.map(Acceptance::to_canonical_json).transpose()?;
        let tx = self.tx()?;
        let existing: Option<(Option<String>, bool)> = self
            .conn
            .query_row(
                "SELECT acceptance_json, is_self FROM memberships WHERE credential_digest = ?1",
                [digest.to_string()],
                |r| Ok((r.get(0)?, sql::flag(r, 1)?)),
            )
            .optional()?;
        let outcome = match existing {
            None => {
                self.conn.execute(
                    &format!(
                        "INSERT INTO memberships ({M_COLS})
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
                    ),
                    params![
                        digest.to_string(),
                        cred.circle_id.to_string(),
                        cred.subject_device_key.to_string(),
                        sql::to_json(&cred.roles, "roles")?,
                        sql::to_json(&cred.scopes, "scopes")?,
                        cred.issued_at.unix_seconds(),
                        cred.expires_at.unix_seconds(),
                        cred_json,
                        acc_json,
                        sql::b(is_self),
                        received_at.unix_seconds()
                    ],
                )?;
                UpsertOutcome::Inserted
            }
            Some((old_acc, old_self)) => {
                let add_acc = old_acc.is_none() && acc_json.is_some();
                let add_self = is_self && !old_self;
                if add_acc || add_self {
                    self.conn.execute(
                        "UPDATE memberships
                         SET acceptance_json = COALESCE(acceptance_json, ?2),
                             is_self = MAX(is_self, ?3)
                         WHERE credential_digest = ?1",
                        params![digest.to_string(), acc_json, sql::b(is_self)],
                    )?;
                    UpsertOutcome::Updated
                } else {
                    UpsertOutcome::Unchanged
                }
            }
        };
        tx.commit()?;
        Ok(outcome)
    }

    /// The membership with this credential digest.
    pub fn membership(&self, credential_digest: &Digest) -> Result<Option<MembershipRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {M_COLS} FROM memberships WHERE credential_digest = ?1"),
                [credential_digest.to_string()],
                m_row,
            )
            .optional()?)
    }

    fn memberships_where(&self, cond: &str, arg: String) -> Result<Vec<MembershipRow>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {M_COLS} FROM memberships WHERE {cond}
             ORDER BY issued_at, credential_digest"
        ))?;
        let rows = st
            .query_map([arg], m_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// All memberships (any subject, expired or not) stored for a circle, oldest first.
    pub fn memberships_for_circle(&self, circle: &CircleId) -> Result<Vec<MembershipRow>> {
        self.memberships_where("circle_id = ?1", circle.to_string())
    }

    /// All memberships of a subject key across circles, oldest first.
    pub fn memberships_for_subject(&self, subject: &DeviceKey) -> Result<Vec<MembershipRow>> {
        self.memberships_where("subject_key = ?1", subject.to_string())
    }

    /// This node's own membership in a circle: the `is_self` row with an acceptance and
    /// the latest expiry, falling back to an unaccepted one. Expiry is not checked.
    pub fn self_membership(&self, circle: &CircleId) -> Result<Option<MembershipRow>> {
        Ok(self
            .conn
            .query_row(
                &format!(
                    "SELECT {M_COLS} FROM memberships WHERE circle_id = ?1 AND is_self = 1
                     ORDER BY (acceptance_json IS NOT NULL) DESC, expires_at DESC, issued_at DESC
                     LIMIT 1"
                ),
                [circle.to_string()],
                m_row,
            )
            .optional()?)
    }

    /// Every `is_self` membership with an acceptance whose credential has not expired
    /// at `now`, newest expiry first (what this node presents in `Authenticate`).
    pub fn self_membership_proofs(&self, now: Timestamp) -> Result<Vec<MembershipProof>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {M_COLS} FROM memberships
             WHERE is_self = 1 AND acceptance_json IS NOT NULL AND expires_at > ?1
             ORDER BY expires_at DESC, credential_digest"
        ))?;
        let rows = st
            .query_map([now.unix_seconds()], m_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows.iter().filter_map(MembershipRow::proof).collect())
    }

    /// Every stored credential that has an acceptance (all circles, all subjects,
    /// including expired ones), for loading the membership registry.
    pub fn all_membership_proofs(&self) -> Result<Vec<MembershipProof>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {M_COLS} FROM memberships WHERE acceptance_json IS NOT NULL
             ORDER BY issued_at, credential_digest"
        ))?;
        let rows = st
            .query_map([], m_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows.iter().filter_map(MembershipRow::proof).collect())
    }

    /// Every stored membership row (for export and diagnostics).
    pub fn all_memberships(&self) -> Result<Vec<MembershipRow>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {M_COLS} FROM memberships ORDER BY issued_at, credential_digest"
        ))?;
        let rows = st
            .query_map([], m_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ---------------------------------------------------------------- issued invites

    /// Records an invite this node issued. Returns `false` (and changes nothing) if an
    /// invite for the same credential digest is already recorded.
    pub fn insert_issued_invite(&self, inv: &IssuedInviteRow) -> Result<bool> {
        let n = self.conn.execute(
            "INSERT INTO issued_invites
                 (credential_digest, circle_id, invitee_key, created_at, invite_expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(credential_digest) DO NOTHING",
            params![
                inv.credential_digest.to_string(),
                inv.circle_id.to_string(),
                inv.invitee_key.to_string(),
                inv.created_at.unix_seconds(),
                inv.invite_expires_at.unix_seconds()
            ],
        )?;
        Ok(n == 1)
    }

    /// Invites issued for a circle (or for all circles with `None`), oldest first.
    pub fn issued_invites(&self, circle: Option<&CircleId>) -> Result<Vec<IssuedInviteRow>> {
        let mut st = self.conn.prepare(
            "SELECT credential_digest, circle_id, invitee_key, created_at, invite_expires_at
             FROM issued_invites WHERE (?1 IS NULL OR circle_id = ?1)
             ORDER BY created_at, credential_digest",
        )?;
        let rows = st
            .query_map([circle.map(ToString::to_string)], |r| {
                Ok(IssuedInviteRow {
                    credential_digest: sql::parse(r, 0, "credential digest")?,
                    circle_id: sql::parse(r, 1, "circle id")?,
                    invitee_key: sql::parse(r, 2, "invitee key")?,
                    created_at: sql::ts(r, 3)?,
                    invite_expires_at: sql::ts(r, 4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ---------------------------------------------------------------- revocations

    /// Stores a revocation, idempotent on `(circle_id, subject_device_key)`: the first
    /// stored revocation for a subject is kept and later ones return
    /// [`RevocationInsert::AlreadyRevoked`].
    ///
    /// Checks (time-independent): structure, `circle_id == derive(issuer_key)` and the
    /// root signature. A new revocation raises the circle's epoch by one.
    ///
    /// # Errors
    ///
    /// [`StoreError::Protocol`] for a bad signature or structure and
    /// [`StoreError::MissingReference`] if the circle is not stored.
    pub fn insert_revocation(
        &self,
        rev: &Revocation,
        received_at: Timestamp,
    ) -> Result<RevocationInsert> {
        rev.check_structure()?;
        verify_input(
            Context::Revocation,
            &rev.issuer_key,
            &rev.signing_input()?,
            &rev.signature,
        )?;
        let json = rev.to_canonical_json()?;
        let circle = rev.circle_id.to_string();
        let tx = self.tx()?;
        let exists: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM revocations WHERE circle_id = ?1 AND subject_key = ?2)",
            params![circle, rev.subject_device_key.to_string()],
            |r| r.get(0),
        )?;
        if exists {
            return Ok(RevocationInsert::AlreadyRevoked);
        }
        let epoch: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(epoch), 0) + 1 FROM revocations WHERE circle_id = ?1",
            [&circle],
            |r| r.get(0),
        )?;
        self.conn.execute(
            "INSERT INTO revocations
                 (circle_id, subject_key, revoked_at, revocation_json, received_at, epoch)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                circle,
                rev.subject_device_key.to_string(),
                rev.revoked_at.unix_seconds(),
                json,
                received_at.unix_seconds(),
                epoch
            ],
        )?;
        tx.commit()?;
        tracing::debug!(epoch, "stored revocation");
        Ok(RevocationInsert::Inserted {
            epoch: u64::try_from(epoch).unwrap_or(0),
        })
    }

    /// Revocations stored for a circle, in epoch order.
    pub fn revocations_for_circle(&self, circle: &CircleId) -> Result<Vec<RevocationRow>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {R_COLS} FROM revocations WHERE circle_id = ?1 ORDER BY epoch"
        ))?;
        let rows = st
            .query_map([circle.to_string()], r_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Every stored revocation (all circles), for loading the membership registry.
    pub fn all_revocations(&self) -> Result<Vec<RevocationRow>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {R_COLS} FROM revocations ORDER BY circle_id, epoch"
        ))?;
        let rows = st
            .query_map([], r_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// The revocation of `subject` in `circle`, if any.
    pub fn revocation(
        &self,
        circle: &CircleId,
        subject: &DeviceKey,
    ) -> Result<Option<RevocationRow>> {
        Ok(self
            .conn
            .query_row(
                &format!(
                    "SELECT {R_COLS} FROM revocations WHERE circle_id = ?1 AND subject_key = ?2"
                ),
                params![circle.to_string(), subject.to_string()],
                r_row,
            )
            .optional()?)
    }

    /// Whether `subject` is revoked in `circle` (regardless of `revoked_at`: a stored
    /// revocation applies from the moment this node learned of it).
    pub fn is_revoked(&self, circle: &CircleId, subject: &DeviceKey) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM revocations WHERE circle_id = ?1 AND subject_key = ?2)",
            params![circle.to_string(), subject.to_string()],
            |r| r.get(0),
        )?)
    }

    /// The circle's revocation epoch: the number of revocations stored for it (0 when
    /// none). It only ever grows, so callers can cache authorization by epoch.
    pub fn revocation_epoch(&self, circle: &CircleId) -> Result<u64> {
        let e: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(epoch), 0) FROM revocations WHERE circle_id = ?1",
            [circle.to_string()],
            |r| r.get(0),
        )?;
        u64::try_from(e).map_err(|_| StoreError::Corrupt { what: "epoch" })
    }
}
