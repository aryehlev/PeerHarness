//! Exit codes and typed CLI errors.
//!
//! Commands return `anyhow::Result`. A [`CliError`] anywhere in the chain selects the exit
//! code; every other error is a runtime error (exit 1). Library error `Display`s are
//! privacy-safe by design (no observation text, prompts, passphrases or key material),
//! and the messages built here follow the same rule.

use std::fmt;

/// Process exit codes (the CLI contract).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitKind {
    /// 1: runtime error.
    Runtime,
    /// 2: usage error (bad arguments or input the user supplied).
    Usage,
    /// 3: refused or denied (authorization or consent).
    Refused,
}

impl ExitKind {
    pub const fn code(self) -> i32 {
        match self {
            ExitKind::Runtime => 1,
            ExitKind::Usage => 2,
            ExitKind::Refused => 3,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            ExitKind::Runtime => "runtime",
            ExitKind::Usage => "usage",
            ExitKind::Refused => "refused",
        }
    }
}

/// An error with an explicit exit kind.
#[derive(Debug)]
pub struct CliError {
    pub kind: ExitKind,
    pub message: String,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

/// A usage error (exit 2).
pub fn usage(message: impl Into<String>) -> anyhow::Error {
    CliError {
        kind: ExitKind::Usage,
        message: message.into(),
    }
    .into()
}

/// A refusal: missing consent or a denied authorization (exit 3).
pub fn refused(message: impl Into<String>) -> anyhow::Error {
    CliError {
        kind: ExitKind::Refused,
        message: message.into(),
    }
    .into()
}

/// A command of a later build stage (exit 1).
pub fn not_implemented(what: &str) -> anyhow::Error {
    CliError {
        kind: ExitKind::Runtime,
        message: format!("`peerharness {what}` is not yet implemented in this build"),
    }
    .into()
}

/// The exit kind selected by `err` (the first [`CliError`] in its chain).
pub fn exit_kind(err: &anyhow::Error) -> ExitKind {
    err.chain()
        .find_map(|e| e.downcast_ref::<CliError>())
        .map_or(ExitKind::Runtime, |e| e.kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn kinds_survive_context() {
        let e: anyhow::Result<()> = Err(refused("no"));
        let e = e.context("while doing x").unwrap_err();
        assert_eq!(exit_kind(&e), ExitKind::Refused);
        assert_eq!(exit_kind(&usage("bad")), ExitKind::Usage);
        assert_eq!(exit_kind(&anyhow::anyhow!("other")), ExitKind::Runtime);
        assert_eq!(ExitKind::Refused.code(), 3);
        assert!(not_implemented("daemon")
            .to_string()
            .contains("not yet implemented"));
    }
}
