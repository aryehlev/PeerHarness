//! Candidate detection: the [`CandidateDetector`] trait and the offline
//! [`DeterministicDetector`] (spec 7.2).
//!
//! # Heuristics of the deterministic detector
//!
//! The detector looks only at [`ObservationKind::UserPrompt`] observations. Their text is
//! ASCII-lowercased (which keeps byte offsets stable) and matched against a small set of
//! correction patterns. `X` is the preferred option, `Y` the avoided one:
//!
//! | pattern | result |
//! |---|---|
//! | `don't use Y, use X` / `do not use Y; use X` / `never use Y. Use X` (an optional `in this repo` after `Y`, optional `but`/`instead` before the second `use`) | prefer X, avoid Y |
//! | `use X instead of Y` / `using X instead of Y` | prefer X, avoid Y |
//! | `use X, not Y` / `using X, not Y` (a comma or dash is required), which also covers `no, use X, not Y` and `we use X, not Y` | prefer X, avoid Y |
//! | `we use X not Y` / `we're using X not Y` (no comma needed after `we`) | prefer X, avoid Y |
//! | `prefer X over Y` | prefer X, avoid Y |
//! | `this repo uses X, not Y` (`repo`, `repository`, `project`, `codebase`, `monorepo`, `workspace`) | prefer X, avoid Y |
//! | `always use X (for\|in) (this\|the\|our) repo` | prefer X |
//! | `never use Y (for\|in) this repo` / `don't use Y in this repo` | avoid Y |
//!
//! Precision matters more than recall, so a match is **discarded** when any of these hold:
//!
//! * the sentence containing it ends with `?` (a question, not a correction);
//! * the clause before the match (back to the previous sentence end, comma, semicolon,
//!   colon, parenthesis or dash) has more than six words, starts with a question or
//!   auxiliary word (`should`, `can`, `do`, `is`, ...), or contains a first or third
//!   person subject (`I`, `my`, `they`, `people`, ...), a hedge (`maybe`, `can`,
//!   `usually`, ...), a negation (`don't`, `not`, `never`, ...), a conditional or
//!   interrogative (`if`, `when`, `why`, `whether`, ...), reported speech (`said`,
//!   `told`, `say`, ...) or permission (`fine`, `free`, `allowed`, `ok`, ...), as in
//!   `feel free to use npm`. `you` is accepted only when followed by `should`, `must`, `need`,
//!   `have`, `gotta` or `ought` (`you should use X, not Y`);
//! * the sentence contains a word typical of pasted tool output (`deprecated`, `warn`,
//!   `warning`, `error`, `err`, `fatal`, `hint`, `traceback`, `exception`);
//! * a hedge or condition follows the match in the same sentence (`if`, `unless`,
//!   `whether`, `maybe`, `perhaps`, `probably`, `guess`, `lol`, `jk`, ...);
//! * the match is inside a fenced code block (```` ``` ```` or `~~~`) or a Markdown
//!   blockquote line (`>`), i.e. quoted text rather than the user's own words;
//! * a token is not a short tool or identifier (see below), or `X == Y`.
//!
//! So `No, use pnpm, not npm.` and `We use pnpm, not npm, for this repo.` trigger, while
//! `Should we use pnpm instead of npm?`, `use npm install to add deps` and
//! `I use vim, not emacs` do not.
//!
//! # Tokens
//!
//! A token is 1-3 words of `[a-z0-9@._/+-]` (after ASCII lowercasing), at most 40 bytes.
//! Surrounding quotes and backticks are allowed and stripped, as are trailing `.`, `-`
//! and `/`. A leading article (`the`, `a`, `an`) is dropped, and the token is cut at the
//! first stop word (`for`, `in`, `to`, `instead`, `here`, filler such as `going`,
//! `thanks`, `lol`, and generic adjectives such as `new`, `old`, `right`, `other`), so
//! `use pnpm, not npm for installs` yields `npm` and `use the new api, not the old one`
//! yields nothing. A token is rejected if it becomes empty, has no ASCII letter, starts
//! with something other than a letter, digit or `@`, contains `..` or `//`, contains
//! more than one `/` (which keeps paths out), or contains an email address.
//!
//! # Grouping and confidence
//!
//! Matches are grouped by `(concept_key, repo_key)`, where
//! `concept_key = "prefer:<x>|avoid:<y>"` (either side may be absent, see
//! [`Correction::concept_key`]). Confidence is [`Confidence::Low`] for one supporting
//! observation and [`Confidence::Medium`] for two or more distinct observations in the
//! same repository. It is never higher: a human always decides.

use std::collections::HashMap;
use std::fmt;
use std::sync::LazyLock;

use ph_core::{
    is_valid_skill_name, Confidence, NormalizedObservation, ObservationId, ObservationKind,
    SkillCandidate,
};
use regex::Regex;

/// Maximum number of words in an extracted token.
pub const MAX_TOKEN_WORDS: usize = 3;
/// Maximum length of an extracted token in bytes.
pub const MAX_TOKEN_BYTES: usize = 40;
/// Maximum number of evidence ids stored on one candidate (the earliest are kept).
/// Confidence still counts every supporting observation.
pub const MAX_EVIDENCE: usize = 64;

/// Topic label for package managers (`npm`, `pnpm`, `yarn`, `bun`).
pub const TOPIC_PACKAGE_MANAGER: &str = "package-manager";
/// Topic label for Python packaging tools (`pip`, `poetry`, `uv`, `pipenv`).
pub const TOPIC_PYTHON_PACKAGING: &str = "python-packaging";
/// Topic label for test runners (`jest`, `vitest`, `mocha`, `pytest`, `unittest`).
pub const TOPIC_TEST_RUNNER: &str = "test-runner";
/// Topic label for linters and formatters (`eslint`, `biome`, `prettier`).
pub const TOPIC_LINT_FORMAT: &str = "lint-format";
/// Topic label for indentation (`tabs`, `spaces`).
pub const TOPIC_INDENTATION: &str = "indentation";
/// Fallback topic label.
pub const TOPIC_CONVENTION: &str = "convention";

/// Every topic label the detector can emit.
pub const TOPICS: &[&str] = &[
    TOPIC_PACKAGE_MANAGER,
    TOPIC_PYTHON_PACKAGING,
    TOPIC_TEST_RUNNER,
    TOPIC_LINT_FORMAT,
    TOPIC_INDENTATION,
    TOPIC_CONVENTION,
];

const TOPIC_TABLE: &[(&str, &str)] = &[
    ("npm", TOPIC_PACKAGE_MANAGER),
    ("pnpm", TOPIC_PACKAGE_MANAGER),
    ("yarn", TOPIC_PACKAGE_MANAGER),
    ("bun", TOPIC_PACKAGE_MANAGER),
    ("pip", TOPIC_PYTHON_PACKAGING),
    ("pip3", TOPIC_PYTHON_PACKAGING),
    ("poetry", TOPIC_PYTHON_PACKAGING),
    ("uv", TOPIC_PYTHON_PACKAGING),
    ("pipenv", TOPIC_PYTHON_PACKAGING),
    ("jest", TOPIC_TEST_RUNNER),
    ("vitest", TOPIC_TEST_RUNNER),
    ("mocha", TOPIC_TEST_RUNNER),
    ("pytest", TOPIC_TEST_RUNNER),
    ("unittest", TOPIC_TEST_RUNNER),
    ("eslint", TOPIC_LINT_FORMAT),
    ("biome", TOPIC_LINT_FORMAT),
    ("prettier", TOPIC_LINT_FORMAT),
    ("tabs", TOPIC_INDENTATION),
    ("spaces", TOPIC_INDENTATION),
];

/// Detects possible conventions from local observations (spec 7.2).
///
/// Detectors are advisory: every candidate they return starts in
/// [`ph_core::CandidateStatus::Detected`] and needs a human decision before it is saved,
/// shared or installed. Implementations must not log observation text.
pub trait CandidateDetector {
    /// Stable short name of the detector (for logs and provenance), e.g. `"deterministic"`.
    fn name(&self) -> &str;

    /// Returns the candidates supported by `observations`, grouped by
    /// `(concept_key, repo_key)`. The order is deterministic for a given input.
    fn detect(&self, observations: &[NormalizedObservation]) -> Vec<SkillCandidate>;
}

/// One extracted correction: a preferred and/or an avoided token.
///
/// Tokens are lowercase, 1-3 words of `[a-z0-9@._/+-]`, at most [`MAX_TOKEN_BYTES`].
/// At least one side is always present. `Debug` prints lengths only.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Correction {
    /// The option to use (`"pnpm"`).
    pub preferred: Option<String>,
    /// The option to avoid (`"npm"`).
    pub avoided: Option<String>,
}

impl Correction {
    /// The dedup key: `"prefer:<x>|avoid:<y>"`, `"prefer:<x>"` or `"avoid:<y>"`.
    pub fn concept_key(&self) -> String {
        concept_key(self.preferred.as_deref(), self.avoided.as_deref())
    }

    /// The topic label from the built-in table (see [`topic_for`]).
    pub fn topic(&self) -> &'static str {
        topic_for(self.preferred.as_deref(), self.avoided.as_deref())
    }
}

impl fmt::Debug for Correction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Correction")
            .field("preferred_len", &self.preferred.as_ref().map(String::len))
            .field("avoided_len", &self.avoided.as_ref().map(String::len))
            .finish()
    }
}

/// Builds a concept key from (already normalized, lowercase) tokens.
///
/// `concept_key(Some("pnpm"), Some("npm")) == "prefer:pnpm|avoid:npm"`. Inputs are
/// lowercased defensively. With both sides absent the key is `""`.
pub fn concept_key(preferred: Option<&str>, avoided: Option<&str>) -> String {
    match (preferred, avoided) {
        (Some(x), Some(y)) => format!(
            "prefer:{}|avoid:{}",
            x.to_ascii_lowercase(),
            y.to_ascii_lowercase()
        ),
        (Some(x), None) => format!("prefer:{}", x.to_ascii_lowercase()),
        (None, Some(y)) => format!("avoid:{}", y.to_ascii_lowercase()),
        (None, None) => String::new(),
    }
}

/// Topic label for a token pair: the table entry of `preferred`, else that of `avoided`,
/// else [`TOPIC_CONVENTION`]. Lookup is by the whole (lowercased) token.
pub fn topic_for(preferred: Option<&str>, avoided: Option<&str>) -> &'static str {
    let lookup = |t: &str| {
        let t = t.to_ascii_lowercase();
        TOPIC_TABLE
            .iter()
            .find(|(k, _)| *k == t)
            .map(|(_, topic)| *topic)
    };
    preferred
        .and_then(lookup)
        .or_else(|| avoided.and_then(lookup))
        .unwrap_or(TOPIC_CONVENTION)
}

/// The candidate statement shown for review, e.g. `"This repository uses pnpm, not npm."`.
pub fn statement_for(preferred: Option<&str>, avoided: Option<&str>) -> String {
    match (preferred, avoided) {
        (Some(x), Some(y)) => format!("This repository uses {x}, not {y}."),
        (Some(x), None) => format!("This repository uses {x}."),
        (None, Some(y)) => format!("This repository does not use {y}."),
        (None, None) => "This repository follows a convention.".to_owned(),
    }
}

/// Fallback skill name used when nothing better can be derived.
pub const FALLBACK_SKILL_NAME: &str = "repository-convention";

const NAME_SUFFIX: &str = "-convention";

/// Proposed Agent Skills name for a token pair. The result always satisfies
/// [`ph_core::is_valid_skill_name`].
///
/// * package manager topic with a preferred token: `"<x>-repository-convention"`
///   (`"pnpm-repository-convention"`, as in the spec example);
/// * both tokens: `"<x>-over-<y>-convention"`;
/// * preferred only: `"<x>-convention"`; avoided only: `"avoid-<y>-convention"`.
///
/// Tokens are slugged (lowercase, every run of other characters becomes one `-`) and the
/// part before `-convention` is cut to fit 64 characters without a trailing hyphen.
pub fn suggested_skill_name(preferred: Option<&str>, avoided: Option<&str>, topic: &str) -> String {
    let px = preferred.map(slug).filter(|s| !s.is_empty());
    let py = avoided.map(slug).filter(|s| !s.is_empty());
    let core = match (px, py) {
        (Some(x), _) if topic == TOPIC_PACKAGE_MANAGER => format!("{x}-repository"),
        (Some(x), Some(y)) => format!("{x}-over-{y}"),
        (Some(x), None) => x,
        (None, Some(y)) => format!("avoid-{y}"),
        (None, None) => return FALLBACK_SKILL_NAME.to_owned(),
    };
    let max_core = ph_core::names::MAX_SKILL_NAME_LEN - NAME_SUFFIX.len();
    let core = truncate_slug(&core, max_core);
    let name = format!("{core}{NAME_SUFFIX}");
    if is_valid_skill_name(&name) {
        name
    } else {
        FALLBACK_SKILL_NAME.to_owned()
    }
}

/// Lowercase ASCII slug: alphanumerics are kept, every other run becomes one `-`, and
/// leading/trailing hyphens are removed.
fn slug(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            pending_dash = false;
            out.push(c.to_ascii_lowercase());
        } else {
            pending_dash = true;
        }
    }
    out
}

/// Cuts an ASCII slug to at most `max` bytes and removes trailing hyphens.
fn truncate_slug(s: &str, max: usize) -> String {
    let cut = if s.len() > max {
        s.get(..max).unwrap_or(s)
    } else {
        s
    };
    cut.trim_end_matches('-').to_owned()
}

/// Builds the full candidate for one correction (used by the detector and by callers
/// that construct candidates from edited tokens).
pub fn candidate_for(
    correction: &Correction,
    repo_key: &str,
    evidence: Vec<ObservationId>,
    confidence: Confidence,
) -> SkillCandidate {
    let x = correction.preferred.as_deref();
    let y = correction.avoided.as_deref();
    let topic = topic_for(x, y);
    SkillCandidate {
        concept_key: correction.concept_key(),
        repo_key: repo_key.to_owned(),
        statement: statement_for(x, y),
        preferred: correction.preferred.clone(),
        avoided: correction.avoided.clone(),
        confidence,
        evidence,
        suggested_skill_name: suggested_skill_name(x, y, topic),
        topic: topic.to_owned(),
    }
}

// ---------------------------------------------------------------------------------------
// Pattern matching
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Shape {
    /// Captures `x` and `y`.
    Both,
    /// Captures `x` only.
    PreferOnly,
    /// Captures `y` only.
    AvoidOnly,
}

struct Pattern {
    re: Regex,
    shape: Shape,
}

const QUOTE: &str = r#"[`'"\x{201C}\x{201D}\x{2018}\x{2019}]?"#;
// A word never ends with '.', so a token cannot run across a sentence end ("jest. and").
const WORD: &str = r"[a-z0-9@](?:[a-z0-9@._/+\-]*[a-z0-9@_/+\-])?";
const REPO: &str = r"(?:this|the|our)\s+(?:repo|repository|project|codebase|monorepo|workspace)\b";
const APOS: &str = r"['\x{2019}]";
const DASH: &str = r"(?:--?|\x{2014}|\x{2013})";

fn tok(name: &str) -> String {
    format!("{QUOTE}(?P<{name}>{WORD}(?:[ \t]+{WORD}){{0,2}}){QUOTE}")
}

static PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    let x = tok("x");
    let y = tok("y");
    let neg = format!(r"(?:do\s+not|don{APOS}?t|never)");
    let specs: Vec<(String, Shape)> = vec![
        // don't use Y, use X / do not use Y; use X / never use Y in this repo, use X
        (
            format!(
                r"\b{neg}\s+use\s+{y}(?:\s+(?:for|in)\s+{REPO})?\s*(?:[,;:.!]|{DASH})?\s*(?:(?:but|and|instead)\s*,?\s+)?(?:(?:just|please|always)\s+)?use\s+{x}"
            ),
            Shape::Both,
        ),
        // use X instead of Y
        (
            format!(r"\b(?:use|using)\s+{x}\s+instead\s+of\s+{y}"),
            Shape::Both,
        ),
        // use X, not Y (also "no, use X, not Y" and "we use X, not Y")
        (
            format!(r"\b(?:use|using)\s+{x}\s*(?:,|{DASH})\s*(?:(?:and|but)\s+)?not\s+{y}"),
            Shape::Both,
        ),
        // we use X not Y
        (
            format!(r"\bwe(?:\s+use|\s+are\s+using|{APOS}re\s+using)\s+{x}\s+not\s+{y}"),
            Shape::Both,
        ),
        // prefer X over Y
        (format!(r"\bprefer\s+{x}\s+over\s+{y}"), Shape::Both),
        // this repo uses X, not Y
        (
            format!(r"\b{REPO}\s+uses\s+{x}\s*(?:,|{DASH})?\s*(?:(?:and|but)\s+)?not\s+{y}"),
            Shape::Both,
        ),
        // always use X for this repo
        (
            format!(r"\balways\s+use\s+{x}\s+(?:for|in)\s+{REPO}"),
            Shape::PreferOnly,
        ),
        // never use Y in this repo
        (
            format!(
                r"\b(?:never|do\s+not|don{APOS}?t)\s+(?:ever\s+)?use\s+{y}\s+(?:for|in)\s+{REPO}"
            ),
            Shape::AvoidOnly,
        ),
    ];
    specs
        .into_iter()
        .filter_map(|(src, shape)| match Regex::new(&src) {
            Ok(re) => Some(Pattern { re, shape }),
            Err(_) => {
                // The patterns are static and covered by tests; never panic at runtime.
                tracing::error!("ph-learning: a built-in correction pattern failed to compile");
                None
            }
        })
        .collect()
});

/// Words that end a token: the token is cut before the first of them.
const STOP_WORDS: &[&str] = &[
    "for",
    "in",
    "on",
    "at",
    "to",
    "of",
    "with",
    "and",
    "or",
    "but",
    "when",
    "if",
    "because",
    "since",
    "so",
    "as",
    "this",
    "that",
    "these",
    "those",
    "it",
    "its",
    "them",
    "they",
    "here",
    "there",
    "now",
    "then",
    "instead",
    "please",
    "again",
    "too",
    "also",
    "only",
    "always",
    "anymore",
    "ever",
    "everywhere",
    "any",
    "all",
    "our",
    "my",
    "your",
    "their",
    "is",
    "are",
    "be",
    "was",
    "were",
    "which",
    "while",
    "from",
    "by",
    "via",
    "like",
    "not",
    "use",
    "using",
    "unless",
    "than",
    "rather",
    "either",
    "both",
    "everything",
    "something",
    "anything",
    "nothing",
    "one",
    "ones",
    "whatever",
    "stuff",
    "thing",
    "things",
    "way",
    "etc",
    "e.g.",
    "i.e.",
    "we",
    "you",
    "i",
    "me",
    "us",
    "no",
    "yes",
    // filler that often trails a correction ("npm going forward", "npm lol")
    "going",
    "next",
    "time",
    "today",
    "yet",
    "thanks",
    "thank",
    "thx",
    "pls",
    "plz",
    "lol",
    "jk",
    "ok",
    "okay",
    // generic adjectives: "use the new api, not the old one" names no tool
    "new",
    "old",
    "other",
    "same",
    "different",
    "right",
    "wrong",
    "correct",
    "better",
    "best",
    "proper",
    "good",
    "bad",
    "else",
    "existing",
    "current",
];

const ARTICLES: &[&str] = &["the", "a", "an"];

/// A clause starting with one of these is a question or a statement about ability.
const LEAD_DENY: &[&str] = &[
    "should", "shall", "could", "can", "would", "will", "do", "does", "did", "is", "are", "was",
    "were", "may", "might", "have", "has", "had",
];

/// A clause prefix containing one of these is not an imperative correction.
const ANY_DENY: &[&str] = &[
    // interrogative / conditional
    "why",
    "how",
    "what",
    "which",
    "who",
    "whom",
    "whether",
    "if",
    "when",
    "whenever",
    "unless",
    "though",
    "although",
    "wonder",
    "wondering",
    // first / third person subjects
    "i",
    "i'm",
    "im",
    "i've",
    "ive",
    "i'd",
    "i'll",
    "me",
    "my",
    "they",
    "they're",
    "theyre",
    "he",
    "she",
    "he's",
    "she's",
    "people",
    "someone",
    "somebody",
    "everyone",
    "everybody",
    "folks",
    "some",
    "many",
    "most",
    "others",
    "you're",
    "youre",
    "you've",
    "you'd",
    "you'll",
    // hedges / permissive
    "can",
    "could",
    "might",
    "may",
    "maybe",
    "perhaps",
    "possibly",
    "probably",
    "sometimes",
    "usually",
    "often",
    // negation
    "not",
    "never",
    "don't",
    "dont",
    "didn't",
    "didnt",
    "doesn't",
    "doesnt",
    "won't",
    "wont",
    "wouldn't",
    "shouldn't",
    "can't",
    "cant",
    "cannot",
    "couldn't",
    "isn't",
    "aren't",
    "wasn't",
    "weren't",
    // reported speech / past tense
    "said",
    "says",
    "told",
    "asked",
    "used",
    "tried",
    "say",
    "saying",
    "suggests",
    "suggested",
    "claims",
    "claimed",
    "mentioned",
    "wrote",
    // permissive ("it's fine to use npm", "feel free to use npm")
    "fine",
    "free",
    "allowed",
    "okay",
    "ok",
    "acceptable",
    "optional",
    "optionally",
    "alright",
    "guess",
    "think",
];

/// A sentence containing one of these anywhere is treated as pasted tool output (for
/// example `npm WARN deprecated foo: use bar instead of foo`), not as a correction.
const SENTENCE_DENY: &[&str] = &[
    "deprecated",
    "deprecation",
    "warn",
    "warning",
    "error",
    "err",
    "fatal",
    "hint",
    "traceback",
    "exception",
];

/// A word after the match in the same sentence that turns it into a hedge or a
/// condition (`use pnpm instead of npm if you can`, `... i guess`, `... lol`).
const SUFFIX_DENY: &[&str] = &[
    "if", "unless", "whether", "maybe", "perhaps", "possibly", "probably", "guess", "jk", "lol",
    "idk", "dunno",
];

const YOU_MODALS: &[&str] = &["should", "must", "need", "needs", "have", "gotta", "ought"];

const MAX_PREFIX_WORDS: usize = 6;

/// Extracts every correction in `text` (any case), applying all the precision filters
/// described in the [module documentation](self). The result is deduplicated and in
/// order of appearance.
pub fn extract_corrections(text: &str) -> Vec<Correction> {
    let lower = mask_quoted(&text.to_ascii_lowercase());
    // (start, end, correction)
    let mut found: Vec<(usize, usize, Correction)> = Vec::new();
    for pattern in PATTERNS.iter() {
        for caps in pattern.re.captures_iter(&lower) {
            let Some(m) = caps.get(0) else { continue };
            let gx = caps.name("x");
            let gy = caps.name("y");
            let nx =
                gx.and_then(|g| normalize_token_span(g.as_str()).map(|(t, u)| (t, g.start() + u)));
            let ny =
                gy.and_then(|g| normalize_token_span(g.as_str()).map(|(t, u)| (t, g.start() + u)));
            // The effective end: when a token closes the match, only the words actually
            // kept count, so trailing stop words ("jest and ...") cannot shadow a
            // following match.
            let last_group_end = gx.map_or(0, |g| g.end()).max(gy.map_or(0, |g| g.end()));
            let eff_end = if last_group_end + 3 >= m.end() {
                nx.as_ref()
                    .map_or(m.start(), |(_, e)| *e)
                    .max(ny.as_ref().map_or(m.start(), |(_, e)| *e))
            } else {
                m.end()
            };
            if !context_ok(&lower, m.start(), eff_end.max(m.start())) {
                continue;
            }
            let x = nx.map(|(t, _)| t);
            let y = ny.map(|(t, _)| t);
            let correction = match pattern.shape {
                Shape::Both => match (x, y) {
                    (Some(x), Some(y)) if x != y => Correction {
                        preferred: Some(x),
                        avoided: Some(y),
                    },
                    _ => continue,
                },
                Shape::PreferOnly => match x {
                    Some(x) => Correction {
                        preferred: Some(x),
                        avoided: None,
                    },
                    None => continue,
                },
                Shape::AvoidOnly => match y {
                    Some(y) => Correction {
                        preferred: None,
                        avoided: Some(y),
                    },
                    None => continue,
                },
            };
            found.push((m.start(), eff_end.max(m.start() + 1), correction));
        }
    }
    // Earliest first, longest first; then drop matches overlapping an already kept one.
    found.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let mut kept: Vec<(usize, usize, Correction)> = Vec::new();
    for (s, e, c) in found {
        if kept.iter().any(|(ks, ke, _)| s < *ke && *ks < e) {
            continue;
        }
        kept.push((s, e, c));
    }
    let mut out: Vec<Correction> = Vec::new();
    for (_, _, c) in kept {
        if !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

/// Whether byte `i` of `s` ends a sentence.
fn is_sentence_end(s: &[u8], i: usize) -> bool {
    match s.get(i) {
        Some(b'\n' | b'?' | b'!') => true,
        Some(b'.') => s.get(i + 1).is_none_or(|c| c.is_ascii_whitespace()),
        _ => false,
    }
}

/// Blanks out lines that quote someone else's text: fenced code blocks (```` ``` ```` or
/// `~~~`, including an unclosed fence up to the end) and Markdown blockquotes (`>`).
/// Each masked line becomes empty, so it also ends the previous sentence.
fn mask_quoted(lower: &str) -> String {
    let mut out = String::with_capacity(lower.len());
    let mut in_fence = false;
    for (i, line) in lower.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let t = line.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence || t.starts_with('>') {
            continue;
        }
        out.push_str(line);
    }
    out
}

/// Splits `s` into lowercase words with surrounding punctuation removed (apostrophes
/// inside words are kept and normalized to `'`).
fn clause_words(s: &str) -> Vec<String> {
    s.split_whitespace()
        .map(|w| {
            w.replace('\u{2019}', "'")
                .trim_matches(|c: char| !(c.is_alphanumeric() || c == '\''))
                .trim_matches('\'')
                .to_owned()
        })
        .filter(|w| !w.is_empty())
        .collect()
}

/// Checks the sentence and clause around a match (see the module docs). `end` is the
/// effective end of the match (after the last kept token word).
fn context_ok(lower: &str, start: usize, end: usize) -> bool {
    let bytes = lower.as_bytes();
    // Sentence end; a question is not a correction.
    let mut se = end;
    while se < bytes.len() {
        if is_sentence_end(bytes, se) {
            if bytes.get(se) == Some(&b'?') {
                return false;
            }
            break;
        }
        se += 1;
    }
    // Sentence start.
    let mut ss = start;
    while ss > 0 && !is_sentence_end(bytes, ss - 1) {
        ss -= 1;
    }
    let (Some(sentence_prefix), Some(suffix), Some(sentence)) =
        (lower.get(ss..start), lower.get(end..se), lower.get(ss..se))
    else {
        return false;
    };
    // Pasted tool output ("npm WARN deprecated ...: use X instead of Y").
    if clause_words(sentence)
        .iter()
        .any(|w| SENTENCE_DENY.contains(&w.as_str()))
    {
        return false;
    }
    // Hedges and conditions after the match.
    if clause_words(suffix)
        .iter()
        .any(|w| SUFFIX_DENY.contains(&w.as_str()))
    {
        return false;
    }
    // Clause prefix: after the last clause separator.
    let clause = sentence_prefix
        .rfind([',', ';', ':', '(', '\u{2014}', '\u{2013}'])
        .and_then(|p| {
            let sep_len = sentence_prefix
                .get(p..)
                .and_then(|r| r.chars().next())
                .map_or(1, char::len_utf8);
            sentence_prefix.get(p + sep_len..)
        })
        .unwrap_or(sentence_prefix);
    let clause = clause.rsplit(" - ").next().unwrap_or(clause);
    prefix_words_ok(&clause_words(clause))
}

fn prefix_words_ok(words: &[String]) -> bool {
    if words.len() > MAX_PREFIX_WORDS {
        return false;
    }
    if let Some(first) = words.first() {
        if LEAD_DENY.contains(&first.as_str()) {
            return false;
        }
    }
    for (i, w) in words.iter().enumerate() {
        if ANY_DENY.contains(&w.as_str()) {
            return false;
        }
        if w == "you" {
            let next_ok = words
                .get(i + 1)
                .is_some_and(|n| YOU_MODALS.contains(&n.as_str()));
            if !next_ok {
                return false;
            }
        }
    }
    true
}

fn is_quote(c: char) -> bool {
    matches!(
        c,
        '`' | '\'' | '"' | '\u{201C}' | '\u{201D}' | '\u{2018}' | '\u{2019}'
    )
}

/// Normalizes and validates a candidate token (see the module docs). Returns the
/// lowercase token or `None` when it is not a short tool or identifier.
///
/// Public so that callers (for example a review flow where the human edits the
/// preferred or avoided option) can apply exactly the same rules.
pub fn normalize_token(raw: &str) -> Option<String> {
    normalize_token_span(raw).map(|(t, _)| t)
}

/// Byte spans of the whitespace-separated words of `s`.
fn word_spans(s: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in s.char_indices() {
        if c.is_whitespace() {
            if let Some(st) = start.take() {
                spans.push((st, i));
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(st) = start {
        spans.push((st, s.len()));
    }
    spans
}

/// [`normalize_token`] plus the byte offset in `raw` where the last kept word ends.
fn normalize_token_span(raw: &str) -> Option<(String, usize)> {
    // (normalized word, raw end offset)
    let mut words: Vec<(String, usize)> = Vec::new();
    for (s, e) in word_spans(raw) {
        let w = raw.get(s..e).unwrap_or_default();
        let w = w.trim_matches(is_quote);
        let w = w.trim_end_matches(['.', '-', '/', ',', ';', ':', '!', '?']);
        let w = w.trim_end_matches(is_quote);
        if w.is_empty() {
            continue;
        }
        words.push((w.to_ascii_lowercase(), e));
    }
    while words
        .first()
        .is_some_and(|(w, _)| ARTICLES.contains(&w.as_str()))
    {
        words.remove(0);
    }
    if let Some(pos) = words
        .iter()
        .position(|(w, _)| STOP_WORDS.contains(&w.as_str()))
    {
        words.truncate(pos);
    }
    if words.is_empty() || words.len() > MAX_TOKEN_WORDS {
        return None;
    }
    let used = words.last().map_or(0, |(_, e)| *e);
    let words: Vec<String> = words.into_iter().map(|(w, _)| w).collect();
    let token = words.join(" ");
    let valid_chars = token.bytes().all(|b| {
        b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || matches!(b, b'@' | b'.' | b'_' | b'/' | b'+' | b'-' | b' ')
    });
    let ok = valid_chars
        && token.len() <= MAX_TOKEN_BYTES
        && token.bytes().any(|b| b.is_ascii_lowercase())
        && words.iter().all(|w| {
            w.bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'@')
        })
        && !token.contains("..")
        && !token.contains("//")
        && token.bytes().filter(|&b| b == b'/').count() <= 1
        && !words.iter().any(|w| looks_like_email(w));
    ok.then_some((token, used))
}

/// `local@domain.tld` (a personal identifier, never a tool name). Package specs such as
/// `@scope/pkg`, `pkg@5` or `pkg@5.1.0` are not emails.
fn looks_like_email(word: &str) -> bool {
    let Some((local, domain)) = word.split_once('@') else {
        return false;
    };
    let Some((_, tld)) = domain.rsplit_once('.') else {
        return false;
    };
    !local.is_empty()
        && domain
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase())
        && tld.len() >= 2
        && tld.bytes().all(|b| b.is_ascii_lowercase())
}

// ---------------------------------------------------------------------------------------
// The detector
// ---------------------------------------------------------------------------------------

/// The offline correction detector (see the [module documentation](self) for the exact
/// heuristics). Stateless and cheap to construct.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeterministicDetector;

impl DeterministicDetector {
    /// Creates the detector.
    pub const fn new() -> Self {
        Self
    }
}

struct Group {
    correction: Correction,
    repo_key: String,
    evidence: Vec<ObservationId>,
    count: usize,
}

impl CandidateDetector for DeterministicDetector {
    fn name(&self) -> &str {
        "deterministic"
    }

    fn detect(&self, observations: &[NormalizedObservation]) -> Vec<SkillCandidate> {
        let mut groups: Vec<Group> = Vec::new();
        let mut index: HashMap<(String, String), usize> = HashMap::new();
        let mut scanned = 0usize;
        for obs in observations {
            if obs.kind != ObservationKind::UserPrompt {
                continue;
            }
            scanned += 1;
            for correction in extract_corrections(&obs.text) {
                let key = (correction.concept_key(), obs.repo_key.clone());
                let gi = *index.entry(key).or_insert_with(|| {
                    groups.push(Group {
                        correction,
                        repo_key: obs.repo_key.clone(),
                        evidence: Vec::new(),
                        count: 0,
                    });
                    groups.len() - 1
                });
                let Some(group) = groups.get_mut(gi) else {
                    continue;
                };
                if group.evidence.contains(&obs.id) {
                    continue;
                }
                group.count += 1;
                if group.evidence.len() < MAX_EVIDENCE {
                    group.evidence.push(obs.id.clone());
                }
            }
        }
        tracing::debug!(
            observations = observations.len(),
            scanned,
            candidates = groups.len(),
            "deterministic detector ran"
        );
        groups
            .into_iter()
            .map(|g| {
                let confidence = if g.count >= 2 {
                    Confidence::Medium
                } else {
                    Confidence::Low
                };
                candidate_for(&g.correction, &g.repo_key, g.evidence, confidence)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(text: &str) -> Option<(Option<String>, Option<String>)> {
        let v = extract_corrections(text);
        assert!(v.len() <= 1, "more than one correction in {text:?}");
        v.into_iter().next().map(|c| (c.preferred, c.avoided))
    }

    fn both(x: &str, y: &str) -> Option<(Option<String>, Option<String>)> {
        Some((Some(x.into()), Some(y.into())))
    }

    #[test]
    fn all_patterns_compile() {
        assert_eq!(PATTERNS.len(), 8);
    }

    #[test]
    fn basic_shapes() {
        assert_eq!(one("No, use pnpm, not npm."), both("pnpm", "npm"));
        assert_eq!(one("use pnpm instead of npm"), both("pnpm", "npm"));
        assert_eq!(one("don't use npm, use pnpm"), both("pnpm", "npm"));
        assert_eq!(one("Do not use npm; use pnpm."), both("pnpm", "npm"));
        assert_eq!(one("we use pnpm not npm"), both("pnpm", "npm"));
        assert_eq!(one("Prefer ruff over flake8."), both("ruff", "flake8"));
        assert_eq!(
            one("Always use uv for this repo."),
            Some((Some("uv".into()), None))
        );
        assert_eq!(
            one("Never use pip in this project!"),
            Some((None, Some("pip".into())))
        );
    }

    #[test]
    fn slug_and_truncate() {
        assert_eq!(slug("@types/node"), "types-node");
        assert_eq!(slug("--a__b--"), "a-b");
        assert_eq!(truncate_slug("abc-def", 4), "abc");
        assert_eq!(truncate_slug("abc", 10), "abc");
    }

    #[test]
    fn prefix_rules() {
        let w = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        assert!(prefix_words_ok(&w("")));
        assert!(prefix_words_ok(&w("please")));
        assert!(prefix_words_ok(&w("you should")));
        assert!(!prefix_words_ok(&w("you")));
        assert!(!prefix_words_ok(&w("you can")));
        assert!(!prefix_words_ok(&w("i")));
        assert!(!prefix_words_ok(&w("should we")));
        assert!(!prefix_words_ok(&w("a b c d e f g")));
    }
}
