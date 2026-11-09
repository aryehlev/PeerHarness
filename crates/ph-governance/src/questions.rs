//! Anti-spam for received questions (architecture section 10, spec sections 6.4 and 8).
//!
//! The caller (which owns the store) gathers the facts into a [`QuestionContext`] and
//! asks [`QuestionGuard::check`]. Defaults: at most 20 questions per author per day and
//! 100 per circle per day, dedup by `(circle, normalized question text)`
//! ([`question_dedup_key`]), plus the local mute and block lists.
//!
//! [`GuardDecision::Drop`] means "do not surface in the inbox and do not notify". What
//! happens to the event itself is the caller's choice: a blocked author's event should
//! not be stored at all; muted, duplicate and over-quota questions may still be kept in
//! the event log (so sync stays idempotent) with question status `muted`.

use ph_core::{CircleId, Digest};
use serde::{Deserialize, Serialize};

/// Domain-separation context for [`question_dedup_key`].
pub const QUESTION_DEDUP_CONTEXT: &str = "peerharness-question-dedup-v0";

/// Question quotas. Serde-friendly for `config.toml` (missing fields take defaults).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QuestionGuard {
    /// Maximum accepted questions per author per rolling 24 h (default 20).
    pub per_author_per_day: u32,
    /// Maximum accepted questions per circle per rolling 24 h (default 100).
    pub per_circle_per_day: u32,
}

impl Default for QuestionGuard {
    fn default() -> Self {
        Self {
            per_author_per_day: 20,
            per_circle_per_day: 100,
        }
    }
}

/// Facts about one received question, gathered by the caller from its store.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct QuestionContext {
    /// Questions from this author key already **accepted** in the last 24 h (local
    /// receive time), not counting this one. Count across **all** circles this node
    /// shares with the author (the architecture's limit is per author per day; counting
    /// per circle would multiply it by the number of shared circles).
    pub author_count_24h: u32,
    /// Questions already **accepted** in this circle in the last 24 h, not counting this
    /// one.
    pub circle_count_24h: u32,
    /// An accepted question with the same [`question_dedup_key`] already exists.
    pub duplicate: bool,
    /// The author (peer) is locally muted.
    pub author_muted: bool,
    /// The author (peer) is locally blocked.
    pub author_blocked: bool,
}

/// Why a question was dropped.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DropReason {
    /// The author is blocked.
    Blocked,
    /// The author is muted.
    Muted,
    /// Same normalized text already asked in this circle.
    Duplicate,
    /// The author's daily quota is used up.
    AuthorQuota,
    /// The circle's daily quota is used up.
    CircleQuota,
}

impl DropReason {
    /// A stable machine-readable code.
    pub const fn code(self) -> &'static str {
        match self {
            DropReason::Blocked => "blocked",
            DropReason::Muted => "muted",
            DropReason::Duplicate => "duplicate",
            DropReason::AuthorQuota => "author_quota",
            DropReason::CircleQuota => "circle_quota",
        }
    }
}

/// The guard's verdict.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum GuardDecision {
    /// Show the question in the inbox.
    Accept,
    /// Do not surface it; see the [module docs](self).
    Drop(DropReason),
}

impl GuardDecision {
    /// `true` for [`GuardDecision::Accept`].
    pub fn is_accept(self) -> bool {
        self == GuardDecision::Accept
    }
}

impl QuestionGuard {
    /// Decides on one question. Precedence: blocked, muted, duplicate, author quota,
    /// circle quota. A quota is exhausted when the count of already accepted questions
    /// is `>=` the limit.
    pub fn check(&self, ctx: &QuestionContext) -> GuardDecision {
        let reason = if ctx.author_blocked {
            DropReason::Blocked
        } else if ctx.author_muted {
            DropReason::Muted
        } else if ctx.duplicate {
            DropReason::Duplicate
        } else if ctx.author_count_24h >= self.per_author_per_day {
            DropReason::AuthorQuota
        } else if ctx.circle_count_24h >= self.per_circle_per_day {
            DropReason::CircleQuota
        } else {
            return GuardDecision::Accept;
        };
        tracing::debug!(code = reason.code(), "question dropped by guard");
        GuardDecision::Drop(reason)
    }
}

/// Normalizes question text for deduplication: full-width ASCII forms (U+FF01-U+FF5E)
/// folded to ASCII, lowercase, every character that is not alphanumeric or whitespace
/// removed (punctuation, symbols, control and format characters such as zero-width
/// spaces), whitespace runs collapsed to one ASCII space, and the ends trimmed.
///
/// `"Should we use PNPM,   not npm?"` and `"should we use pnpm not npm"` normalize to the
/// same string. Full Unicode compatibility normalization (NFKC) and homoglyph folding
/// (for example Cyrillic `а` for Latin `a`) are **not** applied, so such variants are not
/// deduplicated; the per-author and per-circle quotas still bound them.
pub fn normalize_question_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending_space = false;
    for c in text.chars().map(fold_fullwidth) {
        if c.is_whitespace() {
            pending_space = !out.is_empty();
        } else if c.is_alphanumeric() {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.extend(c.to_lowercase());
        }
    }
    out
}

/// Maps a full-width ASCII variant (U+FF01-U+FF5E) to its ASCII character.
fn fold_fullwidth(c: char) -> char {
    match c {
        '\u{FF01}'..='\u{FF5E}' => char::from_u32(u32::from(c) - 0xFEE0).unwrap_or(c),
        _ => c,
    }
}

/// The dedup key for a question in a circle:
/// `Digest::domain("peerharness-question-dedup-v0", circle_id_bytes || normalized_utf8)`.
/// Store it with the question to find duplicates without keeping extra text.
pub fn question_dedup_key(circle: &CircleId, text: &str) -> Digest {
    let normalized = normalize_question_text(text);
    let mut data = Vec::with_capacity(32 + normalized.len());
    data.extend_from_slice(circle.as_bytes());
    data.extend_from_slice(normalized.as_bytes());
    Digest::domain(QUESTION_DEDUP_CONTEXT, &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization() {
        assert_eq!(
            normalize_question_text("  Should we use PNPM,   not npm?\n"),
            "should we use pnpm not npm"
        );
        assert_eq!(
            normalize_question_text("should we use pnpm not npm"),
            normalize_question_text("Should   we use pnpm... not NPM!!")
        );
        assert_eq!(normalize_question_text("?!...  "), "");
        assert_eq!(normalize_question_text("Ünïcode\u{200B}ok"), "ünïcodeok");
        assert_eq!(normalize_question_text("a\t\tb"), "a b");
        // Full-width forms fold to ASCII.
        assert_eq!(
            normalize_question_text("\u{FF35}\u{FF53}\u{FF45}\u{3000}ｐｎｐｍ\u{FF1F}"),
            "use pnpm"
        );
    }

    #[test]
    fn dedup_key_is_circle_bound() {
        let a = CircleId::from_digest(Digest::sha256(b"a"));
        let b = CircleId::from_digest(Digest::sha256(b"b"));
        assert_eq!(
            question_dedup_key(&a, "Use pnpm?"),
            question_dedup_key(&a, "use PNPM")
        );
        assert_ne!(
            question_dedup_key(&a, "Use pnpm?"),
            question_dedup_key(&b, "Use pnpm?")
        );
    }

    #[test]
    fn serde_defaults() {
        let g: QuestionGuard = serde_json::from_str("{}").unwrap();
        assert_eq!(g, QuestionGuard::default());
        let g: QuestionGuard = serde_json::from_str(r#"{"per_author_per_day":5}"#).unwrap();
        assert_eq!(g.per_author_per_day, 5);
        assert_eq!(g.per_circle_per_day, 100);
        assert!(serde_json::from_str::<QuestionGuard>(r#"{"x":1}"#).is_err());
    }
}
