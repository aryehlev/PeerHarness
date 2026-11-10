//! Consent: exact previews followed by an explicit human confirmation.
//!
//! `--yes` is the human's explicit scripting flag. Without a terminal and without
//! `--yes` a command refuses (exit 3). Consent is never inferred from anything else.
//!
//! Consent steps are never answered from inside a coding agent's session
//! ([`in_agent_session`]). An agent may write a rule down for its user to review
//! (`peerharness note`); approving, sharing, voting and installing are the person's.
//! Inside a session every step refuses, with one exception the owner has to turn on:
//! a few steps may be put to the person in a window of the operating system. They are
//! proposing a rule, a ballot on a proposed rule and installing a rule that passed
//! (ADR-033, [`confirm_or_window`]), admitting a member, a ballot on an admission and
//! joining a circle (ADR-037, [`confirm_circle_or_window`]), and keeping a noted rule
//! for oneself (ADR-040, [`confirm_own_or_window`]). The session can make
//! that window appear and cannot answer it: nothing it writes, passes or sets counts,
//! `--yes` included.
//!
//! The check reads environment variables the agent's shell sets, so it stops an agent
//! that is being helpful, not one that is trying to get around it: it is a guard
//! against accidents, not a security boundary.
use std::io::{BufRead, IsTerminal, Read as _, Write};

use anyhow::Result;

use crate::config::{Asked, Config};
use crate::error::refused;
use crate::output::Output;
use crate::window::{self, Answer, Ask, Window};

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

/// The first line of every confirmation window, above the preview.
const WINDOW_HEADER: &str =
    "Your coding agent started this step. Nothing happens unless you choose Proceed.";

/// Whether a step that goes through [`confirm_or_window`] would be put to the owner in
/// a window if it ran now: this is an agent session and the owner allowed windows.
pub fn asks_in_window(config: &Config) -> bool {
    in_agent_session() && config.agent.asked() >= Asked::Rules
}

/// The same for a step that goes through [`confirm_circle_or_window`].
pub fn asks_circle_in_window(config: &Config) -> bool {
    in_agent_session() && config.agent.asked() >= Asked::RulesAndCircle
}

/// [`confirm`] for the steps about rules that the owner may be asked about in a window
/// (ADR-033).
///
/// In the person's own terminal this is exactly [`confirm`]. Inside an agent session
/// it refuses unless the owner turned windows on; then the exact `preview` is shown in
/// a window of the operating system, and only a click on "Proceed" there returns `Ok`.
/// `yes` is ignored inside a session, and the preview is not printed there: it is the
/// person who has to read it, and they read it in the window.
pub fn confirm_or_window(
    out: &Output,
    preview: &str,
    yes: bool,
    what: &str,
    config: &Config,
) -> Result<()> {
    confirm_or_window_for(out, preview, yes, what, config, Asked::Rules)
}

/// [`confirm_or_window`] for the steps about who is in a circle (ADR-037). The owner
/// allowed these apart from the steps about rules, so windows that were turned on
/// before they existed do not cover them.
pub fn confirm_circle_or_window(
    out: &Output,
    preview: &str,
    yes: bool,
    what: &str,
    config: &Config,
) -> Result<()> {
    confirm_or_window_for(out, preview, yes, what, config, Asked::RulesAndCircle)
}

/// [`confirm_or_window`] for keeping a noted rule for oneself (ADR-040), which the
/// owner allowed apart from the steps before it.
pub fn confirm_own_or_window(
    out: &Output,
    preview: &str,
    yes: bool,
    what: &str,
    config: &Config,
) -> Result<()> {
    confirm_or_window_for(out, preview, yes, what, config, Asked::All)
}

fn confirm_or_window_for(
    out: &Output,
    preview: &str,
    yes: bool,
    what: &str,
    config: &Config,
    needs: Asked,
) -> Result<()> {
    if !in_agent_session() {
        return confirm_in(out, preview, yes, what, false);
    }
    let window = Window::find();
    if config.agent.asked() < needs {
        return Err(windows_off(what, window.is_some()));
    }
    ask_in_window(preview, what, window.as_ref().map(|w| w as &dyn Ask))
}

fn windows_off(what: &str, has_window: bool) -> anyhow::Error {
    if !has_window {
        return agent_refusal(what);
    }
    refused(format!(
        "{what} is your decision, and this command is running inside a coding agent's \
         session. Run it yourself in your own terminal. (To be asked in a window instead, \
         run `peerharness setup` there once.)"
    ))
}

/// Puts `preview` to the person in `window`. Everything but a click on "Proceed" is a
/// refusal, and a preview that cannot be shown in full is not shown at all.
fn ask_in_window(preview: &str, what: &str, window: Option<&dyn Ask>) -> Result<()> {
    let terminal = "Run it yourself in your own terminal.";
    let Some(window) = window else {
        return Err(refused(format!(
            "{what} is your decision, and this machine has no confirmation window that \
             PeerHarness can show. {terminal}"
        )));
    };
    let preview = preview.trim_end();
    if preview.trim().is_empty() {
        // Nothing to read is nothing to consent to.
        return Err(agent_refusal(what));
    }
    let text = format!("{WINDOW_HEADER}\n\n{preview}");
    if !window::fits(&text) {
        return Err(refused(format!(
            "{what} is your decision, and what it would do is too long to show in full in \
             a window. {terminal}"
        )));
    }
    match window.ask(&text) {
        Answer::Proceed => Ok(()),
        Answer::Declined => Err(refused(format!(
            "{what} cancelled: it was declined in the window"
        ))),
        Answer::TimedOut => Err(refused(format!(
            "{what} was not confirmed: the window closed without an answer"
        ))),
        Answer::TooTall => Err(refused(format!(
            "{what} is your decision, and what it would do is too long to show in full in \
             a window on this screen. {terminal}"
        ))),
        Answer::Failed => Err(refused(format!(
            "{what} is your decision, and the window for it could not be shown. {terminal}"
        ))),
    }
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

    /// A window that gives a fixed answer and remembers what it was asked to show.
    struct Fixed(Answer, std::cell::RefCell<Vec<String>>);

    impl Fixed {
        fn new(answer: Answer) -> Self {
            Self(answer, std::cell::RefCell::new(Vec::new()))
        }
    }

    impl Ask for Fixed {
        fn ask(&self, text: &str) -> Answer {
            self.1.borrow_mut().push(text.to_owned());
            self.0
        }
    }

    fn refusal(r: Result<()>) -> String {
        let e = r.unwrap_err();
        assert_eq!(crate::error::exit_kind(&e), crate::error::ExitKind::Refused);
        e.to_string()
    }

    #[test]
    fn only_proceed_in_the_window_confirms() {
        let w = Fixed::new(Answer::Proceed);
        assert!(ask_in_window("the exact preview\n", "the ballot", Some(&w)).is_ok());
        // The person saw the header and exactly the preview.
        assert_eq!(
            *w.1.borrow(),
            [format!("{WINDOW_HEADER}\n\nthe exact preview")]
        );

        let declined = Fixed::new(Answer::Declined);
        assert!(refusal(ask_in_window("p", "the ballot", Some(&declined))).contains("declined"));
        let silent = Fixed::new(Answer::TimedOut);
        assert!(
            refusal(ask_in_window("p", "the ballot", Some(&silent))).contains("without an answer")
        );
        let tall = Fixed::new(Answer::TooTall);
        assert!(refusal(ask_in_window("p", "the ballot", Some(&tall))).contains("too long"));
        let broken = Fixed::new(Answer::Failed);
        assert!(
            refusal(ask_in_window("p", "the ballot", Some(&broken))).contains("your own terminal")
        );
        assert!(refusal(ask_in_window("p", "the ballot", None)).contains("your own terminal"));
    }

    #[test]
    fn a_window_shows_all_of_a_preview_or_is_not_used() {
        let w = Fixed::new(Answer::Proceed);
        let long = "a line of the rule\n".repeat(window::MAX_ROWS);
        let msg = refusal(ask_in_window(&long, "installing the rule", Some(&w)));
        assert!(msg.contains("too long") && msg.contains("your own terminal"));
        // Nor is the person asked to confirm nothing.
        assert!(
            refusal(ask_in_window("  \n", "installing the rule", Some(&w)))
                .contains("your own terminal")
        );
        assert!(w.1.borrow().is_empty(), "the window was never opened");
    }

    #[test]
    fn windows_that_are_off_refuse_as_before() {
        assert!(windows_off("the ballot", false)
            .to_string()
            .ends_with("Run it yourself in your own terminal."));
        let hint = windows_off("the ballot", true).to_string();
        assert!(hint.contains("your own terminal") && hint.contains("peerharness setup"));
    }
}
