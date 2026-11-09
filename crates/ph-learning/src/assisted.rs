//! [`AgentAssistedDetector`]: an optional wrapper that asks an [`AgentProvider`] to
//! rephrase the statements of a base detector's candidates.
//!
//! The provider only ever sees [`AdvisoryRequest::refine_candidate`] payloads (the
//! deterministic statement, tokens and topic; no observation text, repository key or
//! evidence). Its reply can only replace the human-readable `statement`, and only after
//! sanitizing. Concept keys, tokens, topic, skill name, evidence and confidence stay
//! exactly as the deterministic detector produced them, so dedup and every later
//! decision are unaffected, and every candidate still needs human review.

use std::fmt;

use ph_core::{bound_text, redact, NormalizedObservation, SkillCandidate};

use crate::detector::CandidateDetector;
use crate::providers::{single_line, AdvisoryRequest, AgentProvider, ProviderError};

/// Longest accepted advisory statement, in characters.
pub const MAX_ADVISORY_STATEMENT_CHARS: usize = 200;

/// Confirmation callback: receives the request and the provider (call
/// [`AdvisoryRequest::preview`] to render the exact preview) and returns `true` to send.
pub type ConfirmFn = dyn Fn(&AdvisoryRequest, &dyn AgentProvider) -> bool + Send + Sync;

/// A deterministic candidate plus the provider's advisory rephrasing, if any.
pub struct AssistedCandidate {
    /// The candidate exactly as the base detector produced it.
    pub candidate: SkillCandidate,
    /// The sanitized advisory statement, when the provider was asked, answered and the
    /// answer passed [`sanitize_statement`].
    pub advisory_statement: Option<String>,
    /// Why there is no advisory statement (declined, provider error, or rejected
    /// output). `None` when `advisory_statement` is set.
    pub skipped: Option<SkipReason>,
}

impl fmt::Debug for AssistedCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssistedCandidate")
            .field("candidate", &self.candidate)
            .field(
                "advisory_statement_len",
                &self.advisory_statement.as_ref().map(String::len),
            )
            .field("skipped", &self.skipped)
            .finish()
    }
}

/// Why a candidate has no advisory statement.
#[derive(Debug)]
pub enum SkipReason {
    /// The confirmation callback returned `false`.
    Declined,
    /// The provider failed.
    Provider(ProviderError),
    /// The reply was empty, too long after cleanup, or did not mention the tokens.
    Unusable,
}

/// Wraps a base detector and an advisory provider.
///
/// The [`CandidateDetector`] impl returns the base candidates with `statement`
/// replaced by the advisory text where one was obtained. Use
/// [`detect_assisted`](Self::detect_assisted) to keep both versions for display.
///
/// The confirmation callback runs before **every** provider call when the provider
/// is remote, and also for local providers when
/// [`confirm_local`](Self::confirm_local) is set. Provider calls are sequential and
/// each one blocks for at most the provider's timeout.
pub struct AgentAssistedDetector<D> {
    base: D,
    provider: Box<dyn AgentProvider>,
    confirm: Box<ConfirmFn>,
    confirm_local: bool,
}

impl<D: CandidateDetector> AgentAssistedDetector<D> {
    /// Creates the wrapper. `confirm` must show the preview to the human and return their
    /// decision; it must not auto-approve remote providers.
    pub fn new(
        base: D,
        provider: Box<dyn AgentProvider>,
        confirm: impl Fn(&AdvisoryRequest, &dyn AgentProvider) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            base,
            provider,
            confirm: Box::new(confirm),
            confirm_local: false,
        }
    }

    /// Also ask for confirmation before calls to a local provider.
    pub fn confirm_local(mut self, yes: bool) -> Self {
        self.confirm_local = yes;
        self
    }

    /// The wrapped provider.
    pub fn provider(&self) -> &dyn AgentProvider {
        self.provider.as_ref()
    }

    /// Asks the provider to rephrase one candidate's statement (after confirmation).
    pub fn refine(&self, candidate: &SkillCandidate) -> AssistedCandidate {
        let req = AdvisoryRequest::refine_candidate(candidate);
        let needs_confirm = self.provider.is_remote() || self.confirm_local;
        let mut out = AssistedCandidate {
            candidate: candidate.clone(),
            advisory_statement: None,
            skipped: None,
        };
        if needs_confirm && !(self.confirm)(&req, self.provider.as_ref()) {
            out.skipped = Some(SkipReason::Declined);
            return out;
        }
        match self.provider.complete(&req) {
            Ok(resp) => match sanitize_statement(&resp.text, candidate) {
                Some(s) => out.advisory_statement = Some(s),
                None => out.skipped = Some(SkipReason::Unusable),
            },
            Err(e) => {
                tracing::warn!(provider = self.provider.name(), error = %e, "advisory refinement failed");
                out.skipped = Some(SkipReason::Provider(e));
            }
        }
        out
    }

    /// Runs the base detector, then [`refine`](Self::refine) on each candidate.
    pub fn detect_assisted(
        &self,
        observations: &[NormalizedObservation],
    ) -> Vec<AssistedCandidate> {
        self.base
            .detect(observations)
            .iter()
            .map(|c| self.refine(c))
            .collect()
    }
}

impl<D: CandidateDetector> CandidateDetector for AgentAssistedDetector<D> {
    fn name(&self) -> &str {
        "agent-assisted"
    }

    fn detect(&self, observations: &[NormalizedObservation]) -> Vec<SkillCandidate> {
        self.detect_assisted(observations)
            .into_iter()
            .map(|a| {
                let mut c = a.candidate;
                if let Some(s) = a.advisory_statement {
                    c.statement = s;
                }
                c
            })
            .collect()
    }
}

/// Cleans an advisory statement: redacts, strips controls, joins lines, trims quotes and
/// backticks, and requires 1-[`MAX_ADVISORY_STATEMENT_CHARS`] characters that mention
/// the candidate's preferred token (or, if none, its avoided token) case-insensitively.
/// Returns `None` if the text is unusable.
pub fn sanitize_statement(text: &str, candidate: &SkillCandidate) -> Option<String> {
    let cleaned = single_line(&redact(&bound_text(text, 4096)).text);
    let cleaned = cleaned
        .trim_matches(|c: char| {
            c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '\u{201C}' | '\u{201D}')
        })
        .to_owned();
    if cleaned.is_empty() || cleaned.chars().count() > MAX_ADVISORY_STATEMENT_CHARS {
        return None;
    }
    let anchor = candidate
        .preferred
        .as_deref()
        .or(candidate.avoided.as_deref())?;
    if !cleaned
        .to_ascii_lowercase()
        .contains(&anchor.to_ascii_lowercase())
    {
        return None;
    }
    Some(cleaned)
}
