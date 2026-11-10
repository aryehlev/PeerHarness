//! Rules written down as free text: by the person (`peerharness note "..."`) or reported
//! by their coding agent when it notices that it was corrected.
//!
//! The pattern detector in [`crate::detector`] only understands "use X, not Y". Most
//! real corrections are sentences ("run the tests before you say a task is done"), so a
//! note carries the sentence itself.
//!
//! A note is still only a **candidate**. Whoever wrote it, it enters the same review as a
//! detected candidate, and nothing here decides anything: an agent's report is advisory
//! text that a human may approve, edit or ignore. The origin recorded in the topic
//! ([`TOPIC_NOTE`] or [`TOPIC_AGENT_NOTE`]) is a display label, not an authorization: a
//! caller can claim either.
//!
//! Unlike detector drafts, a note draft contains the statement. The caller redacts it
//! (`ph_core::redact`) before building the candidate, and the human sees the exact text
//! before it is saved, installed or shared.

use ph_core::{is_valid_skill_name, Confidence, Digest, SkillCandidate};

use crate::draft::{SkillDraft, MAX_DESCRIPTION_CHARS};

/// Prefix of the `concept_key` of every note candidate.
pub const NOTE_CONCEPT_PREFIX: &str = "note:";

/// Topic of a note written with `peerharness note`.
pub const TOPIC_NOTE: &str = "note";

/// Topic of a note reported by a coding agent.
pub const TOPIC_AGENT_NOTE: &str = "agent-note";

/// Longest note statement, in characters.
pub const MAX_NOTE_CHARS: usize = 500;

/// Domain-separation context of the note concept hash.
pub const NOTE_KEY_CONTEXT: &str = "peerharness-note-v0";

const MAX_NAME_WORDS: usize = 6;
const MAX_NAME_CHARS: usize = 48;

/// Words left out of a derived skill name: they carry no meaning in a short label.
const NAME_STOP_WORDS: &[&str] = &[
    "a", "an", "the", "this", "that", "these", "those", "i", "you", "your", "we", "our", "it",
    "its", "is", "are", "be", "to", "of", "in", "on", "for", "and", "or", "as", "at", "by", "with",
];

/// Who a note says it comes from. A label for display only.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum NoteOrigin {
    /// Typed by the person.
    Written,
    /// Reported by a coding agent.
    AgentReported,
}

impl NoteOrigin {
    /// The candidate topic for this origin.
    pub const fn topic(self) -> &'static str {
        match self {
            NoteOrigin::Written => TOPIC_NOTE,
            NoteOrigin::AgentReported => TOPIC_AGENT_NOTE,
        }
    }
}

/// Whether `statement` can be a note: one line of 1 to [`MAX_NOTE_CHARS`] characters
/// with no control characters, and not only whitespace.
pub fn is_valid_note(statement: &str) -> bool {
    let n = statement.chars().count();
    (1..=MAX_NOTE_CHARS).contains(&n)
        && !statement.trim().is_empty()
        && !statement.chars().any(char::is_control)
}

/// Lowercased, with runs of whitespace collapsed and surrounding whitespace and trailing
/// sentence punctuation removed, so "Use pnpm." and "use  pnpm" are the same concept.
fn normalized(statement: &str) -> String {
    let lower = statement.to_lowercase();
    let joined = lower.split_whitespace().collect::<Vec<_>>().join(" ");
    joined.trim_end_matches(['.', '!', ' ']).to_owned()
}

fn key_hex(statement: &str) -> String {
    Digest::domain(NOTE_KEY_CONTEXT, normalized(statement).as_bytes()).to_hex()
}

/// The dedup key of a note: [`NOTE_CONCEPT_PREFIX`] followed by 16 hex characters of a
/// domain-separated hash of the normalized statement. It reveals nothing readable about
/// the statement.
pub fn note_concept_key(statement: &str) -> String {
    let hex = key_hex(statement);
    format!("{NOTE_CONCEPT_PREFIX}{}", hex.get(..16).unwrap_or(&hex))
}

/// A skill name for a note: its first few meaningful ASCII words joined by hyphens, at
/// most [`MAX_NAME_CHARS`] characters (articles, pronouns and similar filler are left
/// out). A statement with no usable ASCII words (for example one written in another
/// script) gets `rule-` followed by 8 hex characters of its hash. The result always
/// satisfies [`ph_core::is_valid_skill_name`].
pub fn note_skill_name(statement: &str) -> String {
    let lower = statement.to_ascii_lowercase();
    let mut name = String::new();
    let words = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty() && !NAME_STOP_WORDS.contains(w))
        .take(MAX_NAME_WORDS);
    for w in words {
        let extra = usize::from(!name.is_empty());
        if name.len() + extra + w.len() > MAX_NAME_CHARS {
            break;
        }
        if extra == 1 {
            name.push('-');
        }
        name.push_str(w);
    }
    if is_valid_skill_name(&name) {
        return name;
    }
    let hex = key_hex(statement);
    format!("rule-{}", hex.get(..8).unwrap_or("00000000"))
}

/// Builds the candidate for a note, or `None` when the statement or the given name is
/// not valid.
///
/// `statement` must already be redacted. `name` overrides the derived skill name.
/// The candidate has no evidence observations and [`Confidence::Low`]: nothing was
/// detected, something was said.
pub fn note_candidate(
    statement: &str,
    repo_key: &str,
    origin: NoteOrigin,
    name: Option<&str>,
) -> Option<SkillCandidate> {
    let statement = statement.trim();
    if !is_valid_note(statement) {
        return None;
    }
    let suggested_skill_name = match name {
        Some(n) if is_valid_skill_name(n) => n.to_owned(),
        Some(_) => return None,
        None => note_skill_name(statement),
    };
    Some(SkillCandidate {
        concept_key: note_concept_key(statement),
        repo_key: repo_key.to_owned(),
        statement: statement.to_owned(),
        preferred: None,
        avoided: None,
        confidence: Confidence::Low,
        evidence: Vec::new(),
        suggested_skill_name,
        topic: origin.topic().to_owned(),
    })
}

/// Whether a concept key belongs to a note.
pub fn is_note_key(concept_key: &str) -> bool {
    concept_key.starts_with(NOTE_CONCEPT_PREFIX)
}

/// The origin a note candidate claims, or `None` for a detected candidate.
pub fn note_origin(concept_key: &str, topic: &str) -> Option<NoteOrigin> {
    if !is_note_key(concept_key) {
        return None;
    }
    Some(if topic == TOPIC_AGENT_NOTE {
        NoteOrigin::AgentReported
    } else {
        NoteOrigin::Written
    })
}

/// The sentence added to every note skill so that a rule never outranks the person the
/// agent is working for.
pub const USER_WINS: &str = "If this conflicts with what the user asks for in the current \
                             session, follow the user and say that it conflicts with this rule.";

/// The heading of every note skill.
pub const NOTE_TITLE: &str = "Rule";

/// Drafts the instruction-only skill for a note candidate.
///
/// The description is the statement itself (an agent reads descriptions before it loads a
/// skill, so a short rule is in view from the start). The body repeats it under the
/// fixed heading [`NOTE_TITLE`] and adds [`USER_WINS`]. Nothing else is added and nothing
/// is taken from observations.
///
/// ```
/// use ph_learning::{draft_note_skill, note_candidate, NoteOrigin};
///
/// let c = note_candidate(
///     "Run the tests before you say a task is done.",
///     "repo-key",
///     NoteOrigin::Written,
///     None,
/// )
/// .unwrap();
/// let d = draft_note_skill(&c);
/// assert_eq!(d.name, "run-tests-before-say-task-done");
/// assert_eq!(d.description, "Run the tests before you say a task is done.");
/// assert!(d.body.starts_with("# Rule\n\nRun the tests before you say a task is done.\n"));
/// ```
pub fn draft_note_skill(candidate: &SkillCandidate) -> SkillDraft {
    let statement = candidate.statement.trim();
    let name = if is_valid_skill_name(&candidate.suggested_skill_name) {
        candidate.suggested_skill_name.clone()
    } else {
        note_skill_name(statement)
    };
    let description: String = statement.chars().take(MAX_DESCRIPTION_CHARS).collect();
    let body = format!("# {NOTE_TITLE}\n\n{statement}\n\n{USER_WINS}\n");
    SkillDraft {
        name,
        description,
        body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validity() {
        assert!(is_valid_note("Use pnpm."));
        assert!(!is_valid_note(""));
        assert!(!is_valid_note("   "));
        assert!(!is_valid_note("two\nlines"));
        assert!(!is_valid_note("tab\there"));
        assert!(is_valid_note(&"x".repeat(MAX_NOTE_CHARS)));
        assert!(!is_valid_note(&"x".repeat(MAX_NOTE_CHARS + 1)));
    }

    #[test]
    fn concept_key_ignores_case_spacing_and_final_punctuation() {
        let a = note_concept_key("Use pnpm, not npm.");
        assert_eq!(a, note_concept_key("use  pnpm, not npm"));
        assert_eq!(a, note_concept_key("  USE pnpm, not npm!  "));
        assert_ne!(a, note_concept_key("Use npm, not pnpm."));
        assert!(a.starts_with(NOTE_CONCEPT_PREFIX));
        assert_eq!(a.len(), NOTE_CONCEPT_PREFIX.len() + 16);
        // Nothing readable from the statement is in the key.
        assert!(!a.contains("pnpm"));
    }

    #[test]
    fn names() {
        assert_eq!(
            note_skill_name("Run the tests before you say a task is done."),
            "run-tests-before-say-task-done"
        );
        assert_eq!(note_skill_name("Use pnpm, not npm!"), "use-pnpm-not-npm");
        assert_eq!(
            note_skill_name("Use pnpm, not npm, in this repository."),
            "use-pnpm-not-npm-repository"
        );
        // Only filler: nothing usable is left, so the name comes from the hash.
        assert!(note_skill_name("It is to be.").starts_with("rule-"));
        assert_eq!(note_skill_name("  --Tabs--  "), "tabs");
        // Long words stop the name before it grows past the limit.
        let long = note_skill_name(&format!("{} {} tail", "a".repeat(30), "b".repeat(30)));
        assert_eq!(long, "a".repeat(30));
        // A single word longer than the limit, and non-ASCII text, fall back to a hash.
        for s in [
            "x".repeat(80),
            "תמיד להריץ בדיקות".to_owned(),
            "!!!".to_owned(),
        ] {
            let n = note_skill_name(&s);
            assert!(n.starts_with("rule-") && n.len() == 13, "{n}");
            assert!(is_valid_skill_name(&n));
        }
        // Different statements with no usable words get different names.
        assert_ne!(note_skill_name("תמיד"), note_skill_name("לעולם"));
    }

    #[test]
    fn candidates() {
        let c = note_candidate("  Use pnpm.  ", "r", NoteOrigin::AgentReported, None).unwrap();
        assert_eq!(c.statement, "Use pnpm.");
        assert_eq!(c.topic, TOPIC_AGENT_NOTE);
        assert_eq!(c.suggested_skill_name, "use-pnpm");
        assert!(c.evidence.is_empty() && c.preferred.is_none() && c.avoided.is_none());
        assert_eq!(c.confidence, Confidence::Low);
        assert_eq!(
            note_origin(&c.concept_key, &c.topic),
            Some(NoteOrigin::AgentReported)
        );
        let named = note_candidate("Use pnpm.", "r", NoteOrigin::Written, Some("pnpm")).unwrap();
        assert_eq!(named.suggested_skill_name, "pnpm");
        assert_eq!(named.concept_key, c.concept_key);
        assert_eq!(
            note_origin(&named.concept_key, &named.topic),
            Some(NoteOrigin::Written)
        );
        assert!(note_candidate("Use pnpm.", "r", NoteOrigin::Written, Some("Bad Name")).is_none());
        assert!(note_candidate("", "r", NoteOrigin::Written, None).is_none());
        assert!(note_candidate("a\nb", "r", NoteOrigin::Written, None).is_none());
        assert_eq!(note_origin("prefer:pnpm|avoid:npm", TOPIC_NOTE), None);
    }

    #[test]
    fn drafts_carry_the_statement_and_nothing_else() {
        let c = note_candidate(
            "Use pnpm, not npm.",
            "secret-repo",
            NoteOrigin::Written,
            None,
        )
        .unwrap();
        let d = draft_note_skill(&c);
        assert_eq!(d.name, "use-pnpm-not-npm");
        assert_eq!(d.description, "Use pnpm, not npm.");
        assert_eq!(
            d.body,
            format!("# Rule\n\nUse pnpm, not npm.\n\n{USER_WINS}\n")
        );
        assert!(!d.to_skill_md().contains("secret-repo"));
        // An invalid stored name is replaced rather than emitted.
        let mut bad = c.clone();
        bad.suggested_skill_name = "Not Valid".into();
        assert_eq!(draft_note_skill(&bad).name, "use-pnpm-not-npm");
    }
}
