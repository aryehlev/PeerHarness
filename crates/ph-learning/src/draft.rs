//! Skill and question drafts built from a candidate's extracted tokens only.
//!
//! The text produced here never contains observation text, repository keys or paths:
//! it is assembled from fixed templates plus the candidate's `preferred` and `avoided`
//! tokens, which are re-validated with [`normalize_token`] first (a candidate edited by
//! a human, or built elsewhere, may carry arbitrary strings; an invalid token is
//! treated as absent). The result is still a **draft**: the CLI shows it, lets the human
//! edit it, and runs `ph_core::redact` before any preview of outgoing text.

use std::fmt;

use ph_core::{is_valid_skill_name, SkillCandidate};

use crate::detector::{
    normalize_token, suggested_skill_name, topic_for, TOPICS, TOPIC_CONVENTION, TOPIC_INDENTATION,
    TOPIC_LINT_FORMAT, TOPIC_PACKAGE_MANAGER, TOPIC_PYTHON_PACKAGING, TOPIC_TEST_RUNNER,
};

/// Maximum Agent Skills `description` length (architecture section 11).
pub const MAX_DESCRIPTION_CHARS: usize = 1024;

/// A drafted instruction-only skill.
#[derive(Clone, PartialEq, Eq)]
pub struct SkillDraft {
    /// Agent Skills `name`; always satisfies [`ph_core::is_valid_skill_name`].
    pub name: String,
    /// Agent Skills `description` (1-1024 chars, single line, no `: ` sequence and no
    /// leading YAML indicator, so it is a safe plain scalar).
    pub description: String,
    /// Markdown body (instructions only; no scripts, links or commands to run).
    pub body: String,
}

impl SkillDraft {
    /// The complete `SKILL.md` text: YAML frontmatter with `name` and `description`,
    /// a blank line, then the body. The CLI should still validate it with `ph-skills`
    /// before building a bundle.
    pub fn to_skill_md(&self) -> String {
        format!(
            "---\nname: {}\ndescription: {}\n---\n\n{}",
            self.name, self.description, self.body
        )
    }
}

impl fmt::Debug for SkillDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SkillDraft")
            .field("name", &self.name)
            .field("description_len", &self.description.len())
            .field("body_len", &self.body.len())
            .finish()
    }
}

struct Parts {
    x: Option<String>,
    y: Option<String>,
    topic: &'static str,
}

fn parts(c: &SkillCandidate) -> Parts {
    let x = c.preferred.as_deref().and_then(normalize_token);
    let y = c.avoided.as_deref().and_then(normalize_token);
    let y = if x.is_some() && x == y { None } else { y };
    // Use the candidate's topic when it is one we know, otherwise recompute.
    let topic = TOPICS
        .iter()
        .copied()
        .find(|t| *t == c.topic)
        .filter(|t| *t != TOPIC_CONVENTION)
        .unwrap_or_else(|| topic_for(x.as_deref(), y.as_deref()));
    Parts { x, y, topic }
}

/// Phrase that completes "Use X instead of Y ... in this repository".
fn activity(topic: &str) -> &'static str {
    match topic {
        TOPIC_PACKAGE_MANAGER => "when installing packages or running package scripts",
        TOPIC_PYTHON_PACKAGING => "when installing Python dependencies or managing environments",
        TOPIC_TEST_RUNNER => "when writing or running tests",
        TOPIC_LINT_FORMAT => "when linting or formatting code",
        TOPIC_INDENTATION => "for indentation when editing files",
        _ => "when working",
    }
}

fn config_hint(topic: &str) -> &'static str {
    match topic {
        TOPIC_PACKAGE_MANAGER => " (for example `package.json` and the lockfile in use)",
        TOPIC_PYTHON_PACKAGING => {
            " (for example `pyproject.toml` and any lock or requirements files)"
        }
        TOPIC_TEST_RUNNER => " (for example the test scripts and test configuration files)",
        TOPIC_LINT_FORMAT => " (for example the linter and formatter configuration files)",
        TOPIC_INDENTATION => " (for example `.editorconfig` and the style of existing files)",
        _ => "",
    }
}

fn no_auto_convert(topic: &str) -> &'static str {
    match topic {
        TOPIC_PACKAGE_MANAGER => {
            "Do not convert the project between package managers automatically, and do not \
             change lockfiles unless the user asks."
        }
        TOPIC_PYTHON_PACKAGING => {
            "Do not migrate the project between Python packaging tools automatically, and do \
             not rewrite lock or requirements files unless the user asks."
        }
        TOPIC_TEST_RUNNER => {
            "Do not migrate existing tests to a different test runner automatically."
        }
        TOPIC_LINT_FORMAT => {
            "Do not reformat unrelated files or replace the configured tooling automatically."
        }
        TOPIC_INDENTATION => "Do not reformat unrelated lines or whole files automatically.",
        _ => {
            "Do not rewrite existing code or configuration to follow this convention automatically."
        }
    }
}

fn title_from_name(name: &str) -> String {
    let spaced = name.replace('-', " ");
    let mut chars = spaced.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => "Repository convention".to_owned(),
    }
}

/// Drafts an instruction-only skill for `candidate`.
///
/// Example for `pnpm`/`npm`:
///
/// ```text
/// name: pnpm-repository-convention
/// description: Use pnpm instead of npm when installing packages or running package
///              scripts in this repository.
/// body: "# Pnpm repository convention\n\nWhen working in this repository, use `pnpm`
///        instead of `npm` when installing packages ... Verify the repository
///        configuration ... Do not convert the project between package managers
///        automatically ..."
/// ```
pub fn draft_skill(candidate: &SkillCandidate) -> SkillDraft {
    let Parts { x, y, topic } = parts(candidate);
    let name = if is_valid_skill_name(&candidate.suggested_skill_name) {
        candidate.suggested_skill_name.clone()
    } else {
        suggested_skill_name(x.as_deref(), y.as_deref(), topic)
    };
    let act = activity(topic);
    let (description, rule) = match (&x, &y) {
        (Some(x), Some(y)) => (
            format!("Use {x} instead of {y} {act} in this repository."),
            format!("When working in this repository, use `{x}` instead of `{y}` {act}."),
        ),
        (Some(x), None) => (
            format!("Use {x} {act} in this repository."),
            format!("When working in this repository, use `{x}` {act}."),
        ),
        (None, Some(y)) => (
            format!("Avoid {y} {act} in this repository."),
            format!("When working in this repository, avoid `{y}` {act}."),
        ),
        (None, None) => (
            "Use when working in this repository to follow its reviewed convention.".to_owned(),
            "When working in this repository, follow the convention the user reviewed.".to_owned(),
        ),
    };
    let description: String = description.chars().take(MAX_DESCRIPTION_CHARS).collect();
    let body = format!(
        "# {title}\n\n{rule}\n\n## Guidelines\n\n\
         - Verify the repository configuration{hint} before acting on this convention.\n\
         - {convert}\n\
         - If the configuration contradicts this convention, ask the user before \
         proceeding instead of changing it.\n",
        title = title_from_name(&name),
        hint = config_hint(topic),
        convert = no_auto_convert(topic),
    );
    SkillDraft {
        name,
        description,
        body,
    }
}

/// The exact sanitized question text proposed for sharing, e.g.
/// `"Should this repository use pnpm instead of npm?"`. Single line, at most a few
/// hundred characters (well within the 2000-char QUESTION limit).
pub fn draft_question(candidate: &SkillCandidate) -> String {
    let Parts { x, y, .. } = parts(candidate);
    match (x, y) {
        (Some(x), Some(y)) => format!("Should this repository use {x} instead of {y}?"),
        (Some(x), None) => format!("Should this repository always use {x}?"),
        (None, Some(y)) => format!("Should this repository avoid {y}?"),
        (None, None) => "Should this repository adopt this convention?".to_owned(),
    }
}

/// The QUESTION `topic` for a candidate: its topic label if known, else recomputed from
/// the tokens (always one of [`TOPICS`]).
pub fn question_topic(candidate: &SkillCandidate) -> &'static str {
    parts(candidate).topic
}
