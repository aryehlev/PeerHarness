//! [`StoreError`]: the single error type of this crate.
//!
//! `Display` never includes stored or supplied payload contents (observation text,
//! questions, envelopes, names), key material or SQL parameter values. It names the kind
//! of object and a static reason, a SQLite result code, or a candidate status.

use ph_core::{CandidateStatus, TransitionError};
use ph_protocol::ProtocolError;
use rusqlite::ffi;
use thiserror::Error;

/// Convenience alias.
pub type Result<T, E = StoreError> = std::result::Result<T, E>;

/// Errors returned by [`crate::Store`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The database stayed locked by another connection for longer than the busy
    /// timeout. Hook writers should fall back to the spool file.
    #[error("database is busy (locked by another connection)")]
    Busy,
    /// Any other SQLite failure. The code is a static SQLite result-code name.
    #[error("database error: {code:?}")]
    Sqlite {
        /// The primary SQLite result code, if the failure came from SQLite.
        code: Option<rusqlite::ErrorCode>,
        /// The underlying error.
        #[source]
        source: rusqlite::Error,
    },
    /// Creating or securing the database file failed.
    #[error("i/o error while {op}: {kind}")]
    Io {
        /// What was being done (static).
        op: &'static str,
        /// The I/O error kind.
        kind: std::io::ErrorKind,
    },
    /// The database was written by a newer PeerHarness (forward-only migrations).
    #[error("database schema version {found} is newer than the supported version {supported}")]
    SchemaTooNew {
        /// `PRAGMA user_version` found in the file.
        found: u32,
        /// Highest version this build knows.
        supported: u32,
    },
    /// The row to read or update does not exist.
    #[error("{what} not found")]
    NotFound {
        /// The kind of row.
        what: &'static str,
    },
    /// A row with the same unique key exists and the operation is not idempotent.
    #[error("{what} already exists")]
    AlreadyExists {
        /// The kind of row or key.
        what: &'static str,
    },
    /// A foreign key points at a missing row (for example an event for an unknown
    /// circle, or an outbox entry for an unknown peer).
    #[error("referenced row does not exist (foreign key)")]
    MissingReference,
    /// Some other database constraint was violated.
    #[error("database constraint violated")]
    Constraint,
    /// Compare-and-set on a candidate status failed: somebody else changed it first.
    #[error("candidate status is {actual}, expected {expected}")]
    StatusMismatch {
        /// The status the caller expected.
        expected: CandidateStatus,
        /// The status actually stored.
        actual: CandidateStatus,
    },
    /// The lifecycle refused the transition.
    #[error(transparent)]
    Transition(#[from] TransitionError),
    /// An argument failed validation before anything was written.
    #[error("invalid {what}: {reason}")]
    Invalid {
        /// The argument kind.
        what: &'static str,
        /// Static reason.
        reason: &'static str,
    },
    /// Two values that must agree do not (for example a credential and its acceptance).
    #[error("mismatch: {what}")]
    Mismatch {
        /// Static description.
        what: &'static str,
    },
    /// A stored value could not be decoded. The database was modified outside
    /// PeerHarness or is damaged.
    #[error("stored {what} is corrupt")]
    Corrupt {
        /// The kind of value.
        what: &'static str,
    },
    /// Encoding, parsing or signature checks of a protocol object failed.
    #[error("protocol object rejected: {0}")]
    Protocol(#[from] ProtocolError),
    /// The operating system random number generator failed.
    #[error("operating system random number generator failed")]
    Randomness,
}

impl StoreError {
    /// Whether the failure is a lock timeout (`SQLITE_BUSY` / `SQLITE_LOCKED`).
    pub fn is_busy(&self) -> bool {
        matches!(self, StoreError::Busy)
    }

    pub(crate) const fn invalid(what: &'static str, reason: &'static str) -> Self {
        StoreError::Invalid { what, reason }
    }
}

/// Marker error used inside row mappers so a decoding failure surfaces as
/// [`StoreError::Corrupt`] with a static name.
#[derive(Debug, Error)]
#[error("stored {0} is corrupt")]
pub(crate) struct CorruptColumn(pub(crate) &'static str);

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        if let rusqlite::Error::FromSqlConversionFailure(_, _, inner) = &e {
            if let Some(c) = inner.downcast_ref::<CorruptColumn>() {
                return StoreError::Corrupt { what: c.0 };
            }
            return StoreError::Corrupt { what: "column" };
        }
        if matches!(
            e,
            rusqlite::Error::InvalidColumnType(..) | rusqlite::Error::IntegralValueOutOfRange(..)
        ) {
            return StoreError::Corrupt { what: "column" };
        }
        if let Some(fe) = e.sqlite_error() {
            match fe.code {
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked => {
                    return StoreError::Busy
                }
                rusqlite::ErrorCode::ConstraintViolation => {
                    return if fe.extended_code == ffi::SQLITE_CONSTRAINT_FOREIGNKEY {
                        StoreError::MissingReference
                    } else {
                        StoreError::Constraint
                    };
                }
                _ => {}
            }
        }
        StoreError::Sqlite {
            code: e.sqlite_error_code(),
            source: e,
        }
    }
}

impl From<ph_core::RandomnessError> for StoreError {
    fn from(_: ph_core::RandomnessError) -> Self {
        StoreError::Randomness
    }
}
