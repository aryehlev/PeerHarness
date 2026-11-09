//! Local learning data: [`NormalizedObservation`] and [`SkillCandidate`].
//!
//! These types are **local only**. They never go on the wire. Their `Debug` impls print
//! text lengths instead of text so an accidental `{:?}` in a log cannot leak content
//! (architecture section 13).

use std::fmt;
use std::str::FromStr;

use rand::TryRng as _;
use serde::{Deserialize, Serialize};

use crate::encoding::{string_serde, Digest};
use crate::error::{ParseError, RandomnessError};
use crate::redact::redact;
use crate::timestamp::Timestamp;

/// Default upper bound for stored observation text, in bytes.
pub const MAX_OBSERVATION_TEXT_BYTES: usize = 4096;

/// Maximum length of an [`ObservationId`].
pub const MAX_OBSERVATION_ID_LEN: usize = 128;

/// Truncates `text` to at most `max_bytes` bytes on a UTF-8 character boundary.
pub fn bound_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default().to_owned()
}

/// Opaque identifier of a local observation: 1-128 characters of `[A-Za-z0-9._:-]`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObservationId(String);

impl ObservationId {
    /// Validates and wraps an id.
    pub fn new(s: &str) -> Result<Self, ParseError> {
        let ok = !s.is_empty()
            && s.len() <= MAX_OBSERVATION_ID_LEN
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-'));
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(ParseError::new(
                "observation id",
                "expected 1-128 of [A-Za-z0-9._:-]",
            ))
        }
    }

    /// A fresh random id of the form `obs_` + 32 lowercase hex chars.
    pub fn random() -> Result<Self, RandomnessError> {
        let mut b = [0u8; 16];
        rand::rngs::SysRng
            .try_fill_bytes(&mut b)
            .map_err(|_| RandomnessError)?;
        Ok(Self(format!("obs_{}", hex::encode(b))))
    }

    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ObservationId {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        Self::new(s)
    }
}

impl fmt::Display for ObservationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ObservationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObservationId({})", self.0)
    }
}

string_serde!(ObservationId, "an observation id");

/// Where an observation came from.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSource {
    /// A Claude Code hook.
    Hook,
    /// `peerharness observe demo` synthetic input.
    Demo,
    /// An explicit local import.
    Import,
}

impl ObservationSource {
    /// The `snake_case` string form.
    pub const fn as_str(self) -> &'static str {
        match self {
            ObservationSource::Hook => "hook",
            ObservationSource::Demo => "demo",
            ObservationSource::Import => "import",
        }
    }
}

impl FromStr for ObservationSource {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        match s {
            "hook" => Ok(Self::Hook),
            "demo" => Ok(Self::Demo),
            "import" => Ok(Self::Import),
            _ => Err(ParseError::new("observation source", "unknown source")),
        }
    }
}

/// The kind of agent event an observation was derived from.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    /// The user submitted a prompt (`UserPromptSubmit`).
    UserPrompt,
    /// The agent finished a turn (`Stop`).
    AgentStop,
    /// A tool call failed (`PostToolUseFailure`).
    ToolFailure,
}

impl ObservationKind {
    /// The `snake_case` string form.
    pub const fn as_str(self) -> &'static str {
        match self {
            ObservationKind::UserPrompt => "user_prompt",
            ObservationKind::AgentStop => "agent_stop",
            ObservationKind::ToolFailure => "tool_failure",
        }
    }
}

impl FromStr for ObservationKind {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        match s {
            "user_prompt" => Ok(Self::UserPrompt),
            "agent_stop" => Ok(Self::AgentStop),
            "tool_failure" => Ok(Self::ToolFailure),
            _ => Err(ParseError::new("observation kind", "unknown kind")),
        }
    }
}

/// A bounded, redacted, local-only observation of agent activity.
///
/// Invariant (maintained by [`NormalizedObservation::from_raw`], expected of any other
/// constructor): `text` has already passed through [`redact`] and is at most
/// [`MAX_OBSERVATION_TEXT_BYTES`] bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedObservation {
    /// Local identifier.
    pub id: ObservationId,
    /// When it was observed (local clock).
    pub created_at: Timestamp,
    /// Origin.
    pub source: ObservationSource,
    /// Salted hash of the agent session id, used only to associate adjacent events.
    pub session_hash: Option<Digest>,
    /// Local repository identifier (for example a hash of the repository root).
    pub repo_key: String,
    /// Event kind.
    pub kind: ObservationKind,
    /// Redacted and bounded text.
    pub text: String,
}

impl NormalizedObservation {
    /// Builds an observation from raw text, applying [`redact`] and then bounding to
    /// [`MAX_OBSERVATION_TEXT_BYTES`].
    ///
    /// The raw text is first cut to 4x the limit (to bound redaction cost), then redacted,
    /// then cut to the limit. Redacting before the final cut means a secret straddling
    /// the final boundary is still removed rather than half-kept.
    pub fn from_raw(
        id: ObservationId,
        created_at: Timestamp,
        source: ObservationSource,
        session_hash: Option<Digest>,
        repo_key: String,
        kind: ObservationKind,
        raw_text: &str,
    ) -> Self {
        let pre = bound_text(raw_text, MAX_OBSERVATION_TEXT_BYTES * 4);
        let text = bound_text(&redact(&pre).text, MAX_OBSERVATION_TEXT_BYTES);
        Self {
            id,
            created_at,
            source,
            session_hash,
            repo_key,
            kind,
            text,
        }
    }
}

impl fmt::Debug for NormalizedObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NormalizedObservation")
            .field("id", &self.id)
            .field("created_at", &self.created_at)
            .field("source", &self.source)
            .field("session_hash", &self.session_hash)
            .field("repo_key_len", &self.repo_key.len())
            .field("kind", &self.kind)
            .field("text_len", &self.text.len())
            .finish()
    }
}

/// Detector confidence. Deliberately capped at `Medium`: a human always decides.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Weak signal (single occurrence, ambiguous phrasing).
    Low,
    /// Stronger signal (explicit correction or repetition).
    Medium,
}

impl Confidence {
    /// The `snake_case` string form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
        }
    }
}

impl FromStr for Confidence {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        match s {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            _ => Err(ParseError::new("confidence", "unknown confidence")),
        }
    }
}

/// A possible convention detected from local observations, awaiting human review.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillCandidate {
    /// Normalized dedup key for the concept (for example `"package-manager:pnpm"`).
    pub concept_key: String,
    /// Repository the concept applies to.
    pub repo_key: String,
    /// Human-readable statement of the convention.
    pub statement: String,
    /// The preferred option, if the detector identified one (`"pnpm"`).
    pub preferred: Option<String>,
    /// The avoided option, if identified (`"npm"`).
    pub avoided: Option<String>,
    /// Detector confidence.
    pub confidence: Confidence,
    /// Local observations that support it.
    pub evidence: Vec<ObservationId>,
    /// Proposed Agent Skills name (see [`crate::is_valid_skill_name`]).
    pub suggested_skill_name: String,
    /// Short topic label used for notification cooldowns.
    pub topic: String,
}

impl fmt::Debug for SkillCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SkillCandidate")
            .field("concept_key_len", &self.concept_key.len())
            .field("repo_key_len", &self.repo_key.len())
            .field("statement_len", &self.statement.len())
            .field("has_preferred", &self.preferred.is_some())
            .field("has_avoided", &self.avoided.is_some())
            .field("confidence", &self.confidence)
            .field("evidence_count", &self.evidence.len())
            .field("suggested_skill_name_len", &self.suggested_skill_name.len())
            .field("topic_len", &self.topic.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_text_respects_char_boundaries() {
        assert_eq!(bound_text("hello", 10), "hello");
        assert_eq!(bound_text("hello", 3), "hel");
        assert_eq!(bound_text("héllo", 2), "h");
        assert_eq!(bound_text("€€", 4), "€");
        assert_eq!(bound_text("abc", 0), "");
    }

    #[test]
    fn observation_ids() {
        assert!(ObservationId::new("obs_123:abc-1.2").is_ok());
        assert!(ObservationId::new("").is_err());
        assert!(ObservationId::new("a b").is_err());
        assert!(ObservationId::new(&"a".repeat(129)).is_err());
        let r = ObservationId::random().unwrap();
        assert!(r.as_str().starts_with("obs_"));
        assert_eq!(r.as_str().len(), 36);
    }

    #[test]
    fn from_raw_redacts_bounds_and_debug_hides_text() {
        let raw = format!(
            "use pnpm, my key is sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKE {}",
            "x".repeat(10_000)
        );
        let o = NormalizedObservation::from_raw(
            ObservationId::new("o1").unwrap(),
            Timestamp::now(),
            ObservationSource::Demo,
            None,
            "repo".into(),
            ObservationKind::UserPrompt,
            &raw,
        );
        assert!(o.text.len() <= MAX_OBSERVATION_TEXT_BYTES);
        assert!(!o.text.contains("FAKEFAKE"));
        assert!(o.text.contains("[REDACTED]"));
        let dbg = format!("{o:?}");
        assert!(!dbg.contains("pnpm"));
        assert!(dbg.contains("text_len"));
        let j = serde_json::to_value(&o).unwrap();
        assert_eq!(j["kind"], "user_prompt");
        assert_eq!(j["source"], "demo");
    }

    #[test]
    fn candidate_debug_hides_text() {
        let c = SkillCandidate {
            concept_key: "package-manager:pnpm".into(),
            repo_key: "r".into(),
            statement: "This repository uses pnpm, not npm.".into(),
            preferred: Some("pnpm".into()),
            avoided: Some("npm".into()),
            confidence: Confidence::Medium,
            evidence: vec![ObservationId::new("o1").unwrap()],
            suggested_skill_name: "pnpm-repository-convention".into(),
            topic: "package-manager".into(),
        };
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("pnpm"));
        assert!(serde_json::to_string(&c).unwrap().contains("\"medium\""));
    }
}
