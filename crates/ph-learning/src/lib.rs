//! # ph-learning
//!
//! Local learning for PeerHarness (spec 7.2 and 7.3, architecture section 12, ADR-006):
//!
//! * [`detector`]: the [`CandidateDetector`] trait and the offline
//!   [`DeterministicDetector`], which finds correction patterns such as
//!   "No, use pnpm, not npm" in user prompts and groups them into
//!   [`ph_core::SkillCandidate`]s by `(concept_key, repo_key)`.
//! * [`dedup`]: [`filter_known`] to avoid raising a known concept again.
//! * [`draft`]: [`draft_skill`] (an instruction-only `SKILL.md` draft) and
//!   [`draft_question`] (the sanitized question text), built only from extracted tokens.
//! * [`providers`]: optional, **advisory-only** agent providers (Claude Code CLI, Codex
//!   CLI, Ollama-compatible local endpoint). Disabled by default.
//! * [`assisted`]: [`AgentAssistedDetector`], which asks a provider to rephrase
//!   deterministic candidates.
//!
//! ## Typical flow (CLI / daemon)
//!
//! ```
//! use std::collections::HashSet;
//! use ph_core::{NormalizedObservation, ObservationId, ObservationKind, ObservationSource, Timestamp};
//! use ph_learning::{draft_question, draft_skill, filter_known, CandidateDetector, DeterministicDetector};
//!
//! let obs = NormalizedObservation::from_raw(
//!     ObservationId::new("obs_1").unwrap(),
//!     Timestamp::now(),
//!     ObservationSource::Demo,
//!     None,
//!     "repo-key".into(),
//!     ObservationKind::UserPrompt,
//!     "We use pnpm, not npm, for this repo.",
//! );
//! let candidates = DeterministicDetector::new().detect(&[obs]);
//! let known: HashSet<(String, String)> = HashSet::new(); // from the store
//! let fresh = filter_known(candidates, &known);
//! let c = &fresh[0];
//! assert_eq!(c.concept_key, "prefer:pnpm|avoid:npm");
//! assert_eq!(c.statement, "This repository uses pnpm, not npm.");
//! assert_eq!(c.suggested_skill_name, "pnpm-repository-convention");
//! assert_eq!(draft_question(c), "Should this repository use pnpm instead of npm?");
//! assert_eq!(draft_skill(c).name, "pnpm-repository-convention");
//! ```
//!
//! ## Privacy
//!
//! Nothing in this crate logs observation text, prompts or provider output; tracing
//! events carry counts and provider names only. Error `Display` strings are static.
//! Detector output and drafts contain only fixed template text plus extracted tokens.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod assisted;
pub mod dedup;
pub mod detector;
pub mod draft;
pub mod providers;

pub use assisted::{AgentAssistedDetector, AssistedCandidate, SkipReason};
pub use dedup::{dedup_key, filter_existing_skills, filter_known};
pub use detector::{
    concept_key, extract_corrections, normalize_token, CandidateDetector, Correction,
    DeterministicDetector,
};
pub use draft::{draft_question, draft_skill, question_topic, SkillDraft};
pub use providers::{
    build_provider, AdvisoryPurpose, AdvisoryRequest, AdvisoryResponse, AgentProvider,
    ClaudeCodeCli, CodexCli, OllamaLocal, ProviderConfig, ProviderError, ProviderKind,
};
