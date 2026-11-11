//! Consent: exact previews followed by an explicit human confirmation.
//!
//! `--yes` is the human's explicit scripting flag. Without a terminal and without
//! `--yes` a command refuses (exit 3). Consent is never inferred from anything else.
//! That refusal names the flag as the person's own, for a script they wrote: an agent
//! that no variable marks reads the message too, and is told to stop and ask.
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

/// Refuses a step that goes through [`confirm_circle_or_window`] before it does
/// anything else, when the refusal is certain: this is an agent's session and the step
/// cannot be put in a window, because the owner did not allow that or because this
/// machine can show none. The refusal is the one the consent step itself would give.
///
/// For a step with work before its preview that reaches outside the machine: `circle
/// join <peer id>` looks a peer up and dials it to get the charter it then shows. A
/// session must not make a node do that for a join nobody can be asked about.
/// In the person's own terminal, and in a session that can show the window, this is
/// `Ok` and the step goes on to its preview as before.
pub fn circle_step_can_be_asked(what: &str, config: &Config) -> Result<()> {
    if !in_agent_session() {
        return Ok(());
    }
    cannot_be_asked(
        what,
        config.agent.asked() >= Asked::RulesAndCircle,
        Window::find().is_some(),
    )
    .map_or(Ok(()), Err)
}

/// The refusal of a step inside a session that cannot be put in a window, if it cannot:
/// `allowed` is whether the owner allowed windows for it, `has_window` whether this
/// machine can show one.
fn cannot_be_asked(what: &str, allowed: bool, has_window: bool) -> Option<anyhow::Error> {
    if !allowed {
        return Some(windows_off(what, has_window));
    }
    (!has_window).then(|| no_window(what))
}

/// The refusal where the owner allowed the window and this machine can show none.
fn no_window(what: &str) -> anyhow::Error {
    refused(format!(
        "{what} is your decision, and this machine has no confirmation window that \
         PeerHarness can show. Run it yourself in your own terminal."
    ))
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
        return Err(no_window(what));
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

/// The refusal when a consent step has no terminal to ask on and no `--yes`.
///
/// Whoever reads it may be a coding agent whose shell sets neither variable of
/// [`AGENT_SESSION_ENV`], so it is not worded as an instruction to pass the flag: it
/// says whose decision this is, and tells an agent to stop.
fn no_terminal(what: &str) -> anyhow::Error {
    refused(format!(
        "{what} needs your confirmation, and no terminal is attached. It is the owner's \
         decision: a person runs this command in their own terminal, or passes --yes in a \
         script they wrote themselves. A coding agent stops here and asks the person."
    ))
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
        return Err(no_terminal(what));
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
    fn without_a_terminal_the_refusal_tells_nobody_to_pass_yes() {
        let e = no_terminal("the ballot");
        assert_eq!(crate::error::exit_kind(&e), crate::error::ExitKind::Refused);
        let said = e.to_string();
        assert!(
            said.starts_with("the ballot needs your confirmation, and no terminal is attached.")
        );
        // Whose decision it is, and what an agent that reads this does.
        assert!(said.contains("the owner's decision"));
        assert!(said.contains("a person runs this command in their own terminal"));
        assert!(said.ends_with("A coding agent stops here and asks the person."));
        // The flag is named as the person's, in a script of theirs: never as the next
        // thing to try.
        assert!(said.contains("passes --yes in a script they wrote themselves"));
        assert!(!said.contains("re-run") && !said.contains("review the preview"));
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

    /// What `circle join <peer id>` asks before it goes to the network: inside a
    /// session, a step that cannot be put in a window is refused with the words the
    /// consent step itself has for that case.
    #[test]
    fn a_step_that_cannot_be_asked_is_refused_with_the_consent_steps_own_words() {
        let said = |allowed, has_window| {
            cannot_be_asked("joining the circle", allowed, has_window).map(|e| {
                assert_eq!(crate::error::exit_kind(&e), crate::error::ExitKind::Refused);
                e.to_string()
            })
        };
        // Allowed, and a window to show it in: nothing is refused here.
        assert_eq!(said(true, true), None);
        // Not allowed: what `confirm_circle_or_window` says with windows off.
        assert_eq!(
            said(false, true),
            Some(windows_off("joining the circle", true).to_string())
        );
        assert_eq!(
            said(false, false),
            Some(windows_off("joining the circle", false).to_string())
        );
        // Allowed, and no window on this machine: what `ask_in_window` says then.
        assert_eq!(
            said(true, false),
            Some(refusal(ask_in_window("p", "joining the circle", None)))
        );
        assert!(said(true, false)
            .unwrap()
            .contains("this machine has no confirmation window"));
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
