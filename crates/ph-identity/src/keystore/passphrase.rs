//! Where the file keystore gets its passphrase.

use std::fmt;

use zeroize::Zeroizing;

use crate::error::{IdentityError, Result};

/// Environment variable read by [`PassphraseSource::Env`].
pub const PASSPHRASE_ENV: &str = "PEERHARNESS_PASSPHRASE";

/// Source of the file-keystore passphrase. The passphrase is used as its UTF-8 bytes,
/// without normalization or trimming, and is never logged or included in errors.
pub enum PassphraseSource {
    /// Read [`PASSPHRASE_ENV`] (`PEERHARNESS_PASSPHRASE`) each time it is needed (until
    /// cached by the keystore).
    Env,
    /// A fixed passphrase (tests, or a passphrase the caller obtained some other way).
    Fixed(Zeroizing<String>),
    /// Ask on the controlling terminal with `rpassword`; when a new key file is created
    /// the passphrase is asked twice and must match.
    Prompt,
}

impl PassphraseSource {
    /// Convenience constructor for [`PassphraseSource::Fixed`].
    pub fn fixed(passphrase: impl Into<String>) -> Self {
        PassphraseSource::Fixed(Zeroizing::new(passphrase.into()))
    }

    /// `Env` if `PEERHARNESS_PASSPHRASE` is set, otherwise `Prompt`. This is the usual
    /// choice for the CLI.
    pub fn env_or_prompt() -> Self {
        if std::env::var_os(PASSPHRASE_ENV).is_some() {
            PassphraseSource::Env
        } else {
            PassphraseSource::Prompt
        }
    }

    /// Obtains the passphrase. `creating` asks for confirmation when prompting.
    pub(crate) fn obtain(&self, creating: bool) -> Result<Zeroizing<String>> {
        let p = match self {
            PassphraseSource::Env => match std::env::var(PASSPHRASE_ENV) {
                Ok(v) => Zeroizing::new(v),
                Err(std::env::VarError::NotPresent) => {
                    return Err(IdentityError::PassphraseUnavailable {
                        reason: "PEERHARNESS_PASSPHRASE is not set",
                    })
                }
                Err(std::env::VarError::NotUnicode(_)) => {
                    return Err(IdentityError::PassphraseUnavailable {
                        reason: "PEERHARNESS_PASSPHRASE is not valid UTF-8",
                    })
                }
            },
            PassphraseSource::Fixed(p) => p.clone(),
            PassphraseSource::Prompt => {
                let first = prompt(if creating {
                    "New PeerHarness key passphrase: "
                } else {
                    "PeerHarness key passphrase: "
                })?;
                if creating {
                    if first.is_empty() {
                        return Err(IdentityError::EmptyPassphrase);
                    }
                    let second = prompt("Repeat passphrase: ")?;
                    if *first != *second {
                        return Err(IdentityError::PassphraseMismatch);
                    }
                }
                first
            }
        };
        if p.is_empty() {
            return Err(IdentityError::EmptyPassphrase);
        }
        Ok(p)
    }
}

fn prompt(text: &str) -> Result<Zeroizing<String>> {
    rpassword::prompt_password(text)
        .map(Zeroizing::new)
        .map_err(|_| IdentityError::PassphraseUnavailable {
            reason: "cannot read a passphrase from the terminal",
        })
}

impl fmt::Debug for PassphraseSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PassphraseSource::Env => f.write_str("PassphraseSource::Env"),
            PassphraseSource::Fixed(_) => f.write_str("PassphraseSource::Fixed(<redacted>)"),
            PassphraseSource::Prompt => f.write_str("PassphraseSource::Prompt"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_hides_fixed() {
        let s = format!("{:?}", PassphraseSource::fixed("hunter2-secret"));
        assert!(!s.contains("hunter2"));
    }

    #[test]
    fn fixed_empty_rejected() {
        assert!(matches!(
            PassphraseSource::fixed("").obtain(true),
            Err(IdentityError::EmptyPassphrase)
        ));
        assert_eq!(&*PassphraseSource::fixed("x").obtain(false).unwrap(), "x");
    }
}
