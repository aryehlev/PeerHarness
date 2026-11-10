//! Consent: exact previews followed by an explicit human confirmation.
//!
//! `--yes` is the human's explicit scripting flag. Without a terminal and without
//! `--yes` a command refuses (exit 3). Consent is never inferred from anything else.
use std::io::{BufRead, IsTerminal, Read as _, Write};

use anyhow::Result;

use crate::error::refused;
use crate::output::Output;

/// Longest accepted answer line.
const MAX_ANSWER_BYTES: u64 = 4096;

/// Whether an interactive human can answer on this terminal.
pub fn interactive() -> bool {
    std::io::stdin().is_terminal()
}

/// Shows `preview` and asks `Proceed? [y/N]`. `what` names the action for the
/// refusal message.
pub fn confirm(out: &Output, preview: &str, yes: bool, what: &str) -> Result<()> {
    if !preview.is_empty() {
        out.note(preview);
    }
    if yes {
        return Ok(());
    }
    if !interactive() {
        return Err(refused(format!(
            "{what} needs your confirmation, but no terminal is attached: review the preview \
             above and re-run with --yes"
        )));
    }
    let answer = prompt_line("Proceed? [y/N] ")?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(refused(format!("{what} cancelled")))
    }
}

// Used by `skills install`, which is not implemented in this build yet.
#[allow(dead_code)]
/// Requires `--accept-risk` when the scanner reported high-risk findings.
pub fn require_accept_risk(high_risk: bool, accept_risk: bool) -> Result<()> {
    if high_risk && !accept_risk {
        return Err(refused(
            "the skill has HIGH-risk scanner findings: review them above and re-run with \
             --accept-risk if you still want it (scanning never proves safety)",
        ));
    }
    Ok(())
}

/// Prints `prompt` on stderr and reads one line from the terminal.
pub fn prompt_line(prompt: &str) -> Result<String> {
    if !interactive() {
        return Err(refused("this step needs an interactive terminal"));
    }
    {
        let mut e = std::io::stderr().lock();
        let _ = write!(e, "{prompt}");
        let _ = e.flush();
    }
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .take(MAX_ANSWER_BYTES)
        .read_line(&mut line)
        .map_err(|_| refused("could not read your answer"))?;
    Ok(line.trim_end_matches(['\n', '\r']).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_risk_rule() {
        assert!(require_accept_risk(false, false).is_ok());
        assert!(require_accept_risk(true, true).is_ok());
        let e = require_accept_risk(true, false).unwrap_err();
        assert_eq!(crate::error::exit_kind(&e), crate::error::ExitKind::Refused);
    }

    #[test]
    fn yes_skips_prompt() {
        let out = Output { json: true };
        assert!(confirm(&out, "", true, "x").is_ok());
    }
}
