//! Common error types.
//!
//! Every error here is payload-free: it names the kind of value and a static reason,
//! never the offending input, so errors can be logged without leaking content.

use thiserror::Error;

/// A value failed to parse from its string encoding.
///
/// `what` names the value kind (for example `"device key"`) and `reason` is a static
/// description. Neither ever contains the rejected input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid {what}: {reason}")]
pub struct ParseError {
    /// The kind of value that failed to parse.
    pub what: &'static str,
    /// A static description of why it was rejected.
    pub reason: &'static str,
}

impl ParseError {
    /// Creates a new parse error.
    pub const fn new(what: &'static str, reason: &'static str) -> Self {
        Self { what, reason }
    }
}

/// The operating system random number generator failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("operating system random number generator failed")]
pub struct RandomnessError;
