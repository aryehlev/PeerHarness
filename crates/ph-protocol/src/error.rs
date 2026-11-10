//! Error types. No variant ever carries payload contents.

use thiserror::Error;

/// Errors from the strict JSON parser and the canonicalizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum JcsError {
    /// Input larger than the configured limit.
    #[error("JSON input is {size} bytes, limit is {max}")]
    TooLarge {
        /// Actual size in bytes.
        size: usize,
        /// Limit in bytes.
        max: usize,
    },
    /// Nesting deeper than the configured limit.
    #[error("JSON nesting exceeds depth {max}")]
    TooDeep {
        /// The depth limit.
        max: usize,
    },
    /// An object contains the same key twice.
    #[error("duplicate object key")]
    DuplicateKey,
    /// A number with a fraction or exponent, or an integer too large to be exact.
    #[error("non-integer number")]
    NonInteger,
    /// An integer outside `[-(2^53-1), 2^53-1]`.
    #[error("integer outside the range +-(2^53-1)")]
    IntegerOutOfRange,
    /// Syntactically invalid JSON (including invalid UTF-8, lone surrogates and
    /// trailing data). Position only, never content.
    #[error("malformed JSON at line {line} column {column}")]
    Malformed {
        /// 1-based line (0 if unknown).
        line: usize,
        /// 1-based column (0 if unknown).
        column: usize,
    },
}

/// Which time rule an object violated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeRule {
    /// `created_at` / `issued_at` / `accepted_at` / `revoked_at` is later than
    /// `now + CLOCK_SKEW_SECS`.
    FutureDated,
    /// `expires_at <= now`.
    Expired,
    /// `expires_at <= created_at`.
    ExpiresBeforeCreated,
    /// Lifetime longer than the maximum.
    LifetimeTooLong,
    /// An event outlives the credential embedded in it.
    OutlivesCredential,
}

impl TimeRule {
    /// Static description.
    pub const fn as_str(self) -> &'static str {
        match self {
            TimeRule::FutureDated => "timestamp is too far in the future",
            TimeRule::Expired => "expired",
            TimeRule::ExpiresBeforeCreated => "expires before it was created",
            TimeRule::LifetimeTooLong => "lifetime exceeds the maximum",
            TimeRule::OutlivesCredential => "outlives its credential",
        }
    }
}

impl std::fmt::Display for TimeRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors from protocol parsing, signing and verification.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    /// Strict JSON parsing or canonicalization failed.
    #[error(transparent)]
    Jcs(#[from] JcsError),
    /// An object or collection exceeds a size limit.
    #[error("{what} is {size} bytes, limit is {max}")]
    TooLarge {
        /// What was too large.
        what: &'static str,
        /// Actual size.
        size: usize,
        /// Limit.
        max: usize,
    },
    /// The `schema` member is missing or not the expected version.
    #[error("unsupported or missing schema for {object}")]
    UnsupportedSchema {
        /// Object kind.
        object: &'static str,
    },
    /// The event `type` is not in the allowlist.
    #[error("unknown event type")]
    UnknownEventType,
    /// The object does not match its strict schema (unknown or missing fields, wrong
    /// types, invalid encodings, explicit nulls).
    #[error("{object} does not match its schema")]
    Schema {
        /// Object kind.
        object: &'static str,
    },
    /// A field violates a bound or format rule.
    #[error("field {field}: {reason}")]
    Field {
        /// Static field name.
        field: &'static str,
        /// Static reason.
        reason: &'static str,
    },
    /// Signature verification failed.
    #[error("invalid signature on {object}")]
    BadSignature {
        /// Object kind.
        object: &'static str,
    },
    /// The transmitted `event_id` does not match the recomputed one.
    #[error("event_id does not match the envelope contents")]
    EventIdMismatch,
    /// Two values that must be equal differ (keys, circle ids, digests).
    #[error("{what} mismatch")]
    Mismatch {
        /// What differs, for example `"credential circle_id"`.
        what: &'static str,
    },
    /// A time rule was violated.
    #[error("{object}: {rule}")]
    Time {
        /// Object kind.
        object: &'static str,
        /// The rule.
        rule: TimeRule,
    },
    /// The OS random number generator failed.
    #[error("operating system random number generator failed")]
    Randomness,
}

impl From<ph_core::RandomnessError> for ProtocolError {
    fn from(_: ph_core::RandomnessError) -> Self {
        ProtocolError::Randomness
    }
}

impl ProtocolError {
    pub(crate) const fn field(field: &'static str, reason: &'static str) -> Self {
        ProtocolError::Field { field, reason }
    }
}
