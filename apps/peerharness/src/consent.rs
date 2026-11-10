//! Consent: exact previews followed by an explicit human confirmation.
//!
//! `--yes` is the human's explicit scripting flag. Without a terminal and without
//! `--yes` a command refuses (exit 3). Consent is never inferred from anything else.
//!
//! Consent steps also refuse to run inside a coding agent's session
//! ([`in_agent_session`]). An agent may write a rule down for its user to review
//! (`peerharness note`); approving, sharing, voting and installing are the person's, in
//! their own terminal. The check reads environment variables the agent's shell sets, so
//! it stops an agent that is being helpful, not one that is trying to get around it:
//! it is a guard against accidents, not a security boundary.
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

/// Environment variables that mark a shell started by a coding agent. `CLAUDECODE` is set
/// by Claude Code in every command it runs; `PEERHARNESS_AGENT_SESSION` lets any other
/// agent wrapper (and the tests) say the same thing.
pub const AGENT_SESSION_ENV: [&str; 2] = ["CLAUDECODE", "PEERHARNESS_AGENT_SESSION"];

/// Whether this process appears to run inside a coding agent's session.
pub fn in_agent_session() -> bool {
    AGENT_SESSION_ENV
        .iter()
        .any(|k| std::env::var_os(k).is_some_and(|v| !v.is_empty() && v != "0"))
}

fn agent_refusal(what: &str) -> anyhow::Error {
    refused(format!(
        "{what} is your decision, and this command is running inside a coding agent's \
         session. Run it yourself in your own terminal."
    ))
}

/// Refuses a step that only the person may take when running inside an agent session.
pub fn human_only(what: &str) -> Result<()> {
    if in_agent_session() {
        return Err(agent_refusal(what));
    }
    Ok(())
}

/// Shows `preview` and asks `Proceed? [y/N]`. `what` names the action for the
/// refusal message. Refuses inside an agent session, with or without `--yes`.
pub fn confirm(out: &Output, preview: &str, yes: bool, what: &str) -> Result<()> {
    confirm_in(out, preview, yes, what, in_agent_session())
}

fn confirm_in(out: &Output, preview: &str, yes: bool, what: &str, agent: bool) -> Result<()> {
    if agent {
        return Err(agent_refusal(what));
    }
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
        assert!(confirm_in(&out, "", true, "x", false).is_ok());
    }

    #[test]
    fn an_agent_session_cannot_consent_even_with_yes() {
        let out = Output { json: true };
        let e = confirm_in(&out, "", true, "the ballot", true).unwrap_err();
        assert_eq!(crate::error::exit_kind(&e), crate::error::ExitKind::Refused);
        assert!(e.to_string().contains("your own terminal"));
    }
}
