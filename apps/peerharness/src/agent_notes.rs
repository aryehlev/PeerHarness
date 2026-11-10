//! The skill that asks a coding agent to report corrections.
//!
//! The pattern detector sees only prompts, and only recognizes a few shapes. The agent
//! is the one party that reliably knows it was just corrected, so `watch claude
//! --install` also installs this small skill, which asks the agent to write the rule
//! down with `peerharness note --from-agent`.
//!
//! What that can and cannot do:
//!
//! * `note` only adds a candidate to the local inbox. It installs nothing, shares nothing
//!   and approves nothing.
//! * Every step that needs consent refuses to run inside an agent session
//!   (`consent::human_only`), and the skill tells the agent not to try.
//! * The skill is this product's own fixed text, installed with the same installer as any
//!   other skill, so it is marked as managed and `watch claude --remove` removes it. It
//!   is not a shared bundle and never leaves the machine.

use anyhow::{anyhow, Result};
use ph_skills::Bundle;

/// The directory name of the skill under the agent's skills directory.
pub const SKILL_NAME: &str = "peerharness-notes";

const DESCRIPTION: &str = "Use when the user corrects how you work or states a standing rule \
    for this project (a tool to use or avoid, a convention, a step to always or never do). \
    Records the rule on the user's machine for them to review later.";

/// The SKILL.md body. `program` is the shell-quoted way to run this binary for this home.
fn body(program: &str) -> String {
    format!(
        "# Report corrections\n\
         \n\
         When the user corrects you in a way that should apply again later, write the rule \
         down so that they can review it and, if they choose, put it to their team's vote. \
         Examples: \"no, use pnpm here, not npm\", \"always run the tests before you say you \
         are done\", \"never edit generated files by hand\".\n\
         \n\
         Do this once per rule, after you have dealt with the correction itself:\n\
         \n\
         \x20   {program} note --from-agent '<the rule as one sentence>'\n\
         \n\
         How to write the sentence:\n\
         \n\
         - State the rule, not the incident: \"Use pnpm, not npm, in this repository.\"\n\
         - One imperative sentence, under 500 characters, without quotes or backticks.\n\
         - No secrets, tokens, personal names or absolute paths.\n\
         - Skip instructions that apply only to the task at hand.\n\
         \n\
         Limits:\n\
         \n\
         - The command records a note on the user's machine and sends nothing anywhere.\n\
         - Do not run any other peerharness command and never pass a flag that skips a \
         confirmation. Reviewing, approving, sharing and voting are the user's decisions.\n\
         - If the command fails, carry on with the task and do not retry.\n"
    )
}

/// Builds the skill for the given program words (`HookCommand::render_program`).
pub fn bundle(program: &str) -> Result<Bundle> {
    let md = ph_skills::render_skill_md(SKILL_NAME, DESCRIPTION, &body(program), None)
        .map_err(|e| anyhow!("cannot render the reporting skill: {e}"))?;
    ph_skills::build_bundle(&md, Some(SKILL_NAME))
        .map_err(|e| anyhow!("the reporting skill is not valid: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_skill_is_valid_instruction_only_and_names_the_command() {
        let b = bundle("PEERHARNESS_HOME='/x y' '/opt/ph/peerharness'").unwrap();
        assert_eq!(b.name(), SKILL_NAME);
        assert!(b
            .skill_md()
            .contains("    PEERHARNESS_HOME='/x y' '/opt/ph/peerharness' note --from-agent '"));
        // It tells the agent where its part ends.
        assert!(b
            .skill_md()
            .contains("Do not run any other peerharness command"));
        // Nothing in it trips the scanner as high risk.
        assert!(!ph_skills::has_high_risk(&b.scan()));
        // The same input always gives the same bundle (so "already installed" is exact).
        assert_eq!(
            b.digest(),
            bundle("PEERHARNESS_HOME='/x y' '/opt/ph/peerharness'")
                .unwrap()
                .digest()
        );
    }
}
