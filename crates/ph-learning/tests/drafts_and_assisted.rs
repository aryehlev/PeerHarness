//! Skill/question drafts and the agent-assisted detector (with in-process fake
//! providers).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ph_core::{
    is_valid_skill_name, Confidence, NormalizedObservation, ObservationId, ObservationKind,
    ObservationSource, SkillCandidate, Timestamp,
};
use ph_learning::assisted::sanitize_statement;
use ph_learning::{
    draft_question, draft_skill, question_topic, AdvisoryPurpose, AdvisoryRequest,
    AdvisoryResponse, AgentAssistedDetector, AgentProvider, CandidateDetector,
    DeterministicDetector, ProviderError, SkipReason,
};
use ph_protocol::text::{check_text, Lines};

fn cand(x: Option<&str>, y: Option<&str>, topic: &str, name: &str) -> SkillCandidate {
    SkillCandidate {
        concept_key: ph_learning::concept_key(x, y),
        repo_key: "sha256:REPOKEY0000".into(),
        statement: "This repository uses something.".into(),
        preferred: x.map(str::to_owned),
        avoided: y.map(str::to_owned),
        confidence: Confidence::Low,
        evidence: vec![ObservationId::new("obs_EVID").unwrap()],
        suggested_skill_name: name.into(),
        topic: topic.into(),
    }
}

fn prompt(id: &str, text: &str) -> NormalizedObservation {
    NormalizedObservation::from_raw(
        ObservationId::new(id).unwrap(),
        Timestamp::from_unix_seconds(1_800_000_000).unwrap(),
        ObservationSource::Demo,
        None,
        "sha256:REPOKEY0000".into(),
        ObservationKind::UserPrompt,
        text,
    )
}

#[test]
fn pnpm_skill_draft_matches_spec_shape() {
    let c = cand(
        Some("pnpm"),
        Some("npm"),
        "package-manager",
        "pnpm-repository-convention",
    );
    let d = draft_skill(&c);
    assert_eq!(d.name, "pnpm-repository-convention");
    assert_eq!(
        d.description,
        "Use pnpm instead of npm when installing packages or running package scripts in this repository."
    );
    assert!(d.body.starts_with("# Pnpm repository convention\n"));
    assert!(d
        .body
        .contains("use `pnpm` instead of `npm` when installing packages"));
    assert!(d.body.contains("Verify the repository configuration"));
    assert!(d
        .body
        .contains("Do not convert the project between package managers automatically"));
    let md = d.to_skill_md();
    assert!(md.starts_with(
        "---\nname: pnpm-repository-convention\ndescription: Use pnpm instead of npm"
    ));
    assert!(md.contains("\n---\n\n# Pnpm"));
    assert_eq!(
        draft_question(&c),
        "Should this repository use pnpm instead of npm?"
    );
    assert_eq!(question_topic(&c), "package-manager");
    let dbg = format!("{d:?}");
    assert!(!dbg.contains("Verify"));
}

#[test]
fn drafts_for_every_topic_are_valid() {
    let cases = [
        (Some("pnpm"), Some("npm"), "package-manager"),
        (Some("uv"), Some("pip"), "python-packaging"),
        (Some("vitest"), Some("jest"), "test-runner"),
        (Some("biome"), Some("eslint"), "lint-format"),
        (Some("tabs"), Some("spaces"), "indentation"),
        (Some("ruff"), Some("flake8"), "convention"),
        (Some("uv"), None, "python-packaging"),
        (None, Some("yarn"), "package-manager"),
        (None, Some("lodash"), "convention"),
    ];
    for (x, y, topic) in cases {
        let name = ph_learning::detector::suggested_skill_name(x, y, topic);
        let c = cand(x, y, topic, &name);
        let d = draft_skill(&c);
        assert!(is_valid_skill_name(&d.name), "{}", d.name);
        check_text("description", &d.description, 1, 1024, Lines::Single).unwrap();
        assert!(
            d.description.starts_with("Use ") || d.description.starts_with("Avoid "),
            "{}",
            d.description
        );
        assert!(
            !d.description.contains(": "),
            "plain YAML scalar: {}",
            d.description
        );
        check_text("body", &d.body, 1, 256 * 1024, Lines::Multi).unwrap();
        let q = draft_question(&c);
        check_text("question", &q, 1, 2000, Lines::Single).unwrap();
        assert!(
            q.starts_with("Should this repository ") && q.ends_with('?'),
            "{q}"
        );
        for t in [x, y].into_iter().flatten() {
            assert!(q.contains(t));
            assert!(d.body.contains(&format!("`{t}`")));
        }
        for text in [&d.description, &d.body, &q] {
            assert!(!text.contains("REPOKEY"));
            assert!(!text.contains("EVID"));
            assert!(!text.contains("something"), "statement text must not leak");
        }
    }
    let c = cand(Some("uv"), None, "python-packaging", "uv-convention");
    assert_eq!(draft_question(&c), "Should this repository always use uv?");
    let c = cand(
        None,
        Some("yarn"),
        "package-manager",
        "avoid-yarn-convention",
    );
    assert_eq!(draft_question(&c), "Should this repository avoid yarn?");
    assert_eq!(
        draft_skill(&c).description,
        "Avoid yarn when installing packages or running package scripts in this repository."
    );
}

#[test]
fn hostile_edited_candidate_does_not_leak_into_drafts() {
    let c = SkillCandidate {
        concept_key: "x".into(),
        repo_key: "/Users/alice/secret-project".into(),
        statement: "my password is hunter2".into(),
        preferred: Some("/Users/alice/secret-project/bin/tool; rm -rf /".into()),
        avoided: Some("npm".into()),
        confidence: Confidence::Medium,
        evidence: vec![],
        suggested_skill_name: "../../etc/passwd".into(),
        topic: "<script>".into(),
    };
    let d = draft_skill(&c);
    assert!(is_valid_skill_name(&d.name), "{}", d.name);
    assert_eq!(d.name, "avoid-npm-convention");
    let q = draft_question(&c);
    assert_eq!(q, "Should this repository avoid npm?");
    for text in [&d.description, &d.body, &q, &d.name] {
        assert!(!text.contains("alice"));
        assert!(!text.contains("hunter2"));
        assert!(!text.contains("rm -rf"));
        assert!(!text.contains("<script>"));
    }
    // Nothing usable at all.
    let empty = SkillCandidate {
        preferred: None,
        avoided: Some("..".into()),
        ..c
    };
    let d = draft_skill(&empty);
    assert_eq!(d.name, "repository-convention");
    assert_eq!(
        draft_question(&empty),
        "Should this repository adopt this convention?"
    );
}

#[test]
fn detector_output_round_trips_through_drafts() {
    let out = DeterministicDetector::new().detect(&[
        prompt("o1", "Honestly, use vitest instead of jest."),
        prompt("o2", "Always use uv for this repo."),
    ]);
    assert_eq!(out.len(), 2);
    for c in &out {
        let d = draft_skill(c);
        assert_eq!(d.name, c.suggested_skill_name);
        assert!(!d.body.contains("Honestly"));
    }
}

// ---------------------------------------------------------------------------------------
// Agent-assisted detector
// ---------------------------------------------------------------------------------------

struct FakeProvider {
    remote: bool,
    reply: Result<String, ()>,
    payloads: Arc<Mutex<Vec<String>>>,
}

impl AgentProvider for FakeProvider {
    fn name(&self) -> &str {
        "fake"
    }
    fn is_remote(&self) -> bool {
        self.remote
    }
    fn complete(&self, req: &AdvisoryRequest) -> Result<AdvisoryResponse, ProviderError> {
        self.payloads.lock().unwrap().push(req.exact_payload());
        match &self.reply {
            Ok(t) => Ok(AdvisoryResponse {
                text: t.clone(),
                provider: "fake".into(),
            }),
            Err(()) => Err(ProviderError::Timeout { secs: 1 }),
        }
    }
}

fn fake(remote: bool, reply: Result<&str, ()>) -> (Box<FakeProvider>, Arc<Mutex<Vec<String>>>) {
    let payloads = Arc::new(Mutex::new(Vec::new()));
    (
        Box::new(FakeProvider {
            remote,
            reply: reply.map(str::to_owned),
            payloads: Arc::clone(&payloads),
        }),
        payloads,
    )
}

const PROMPTS: &[&str] = &[
    "Ugh, my private plan is secret. No, use pnpm, not npm.",
    "Please! Don't use npm, use pnpm.",
];

fn observations() -> Vec<NormalizedObservation> {
    PROMPTS
        .iter()
        .enumerate()
        .map(|(i, t)| prompt(&format!("o{i}"), t))
        .collect()
}

#[test]
fn assisted_remote_requires_confirmation_and_only_rephrases() {
    let (p, payloads) = fake(
        true,
        Ok("\"This repository standardizes on pnpm rather than npm.\""),
    );
    let confirms = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&confirms);
    let det = AgentAssistedDetector::new(DeterministicDetector::new(), p, move |req, prov| {
        seen.fetch_add(1, Ordering::SeqCst);
        let preview = req.preview(prov);
        assert!(preview.contains("REMOTE"));
        assert!(preview.contains("fake"));
        true
    });
    assert_eq!(det.name(), "agent-assisted");
    let base = DeterministicDetector::new().detect(&observations());
    let out = det.detect(&observations());
    assert_eq!(confirms.load(Ordering::SeqCst), 1);
    assert_eq!(out.len(), 1);
    let c = &out[0];
    assert_eq!(
        c.statement,
        "This repository standardizes on pnpm rather than npm."
    );
    // Everything except the statement is untouched.
    assert_eq!(c.concept_key, base[0].concept_key);
    assert_eq!(c.confidence, Confidence::Medium);
    assert_eq!(c.evidence, base[0].evidence);
    assert_eq!(c.suggested_skill_name, base[0].suggested_skill_name);
    assert_eq!(c.preferred, base[0].preferred);
    // The provider never saw observation text or the repo key.
    let sent = payloads.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert!(!sent[0].contains("secret"));
    assert!(!sent[0].contains("Ugh"));
    assert!(!sent[0].contains("REPOKEY"));
    assert!(sent[0].contains("This repository uses pnpm, not npm."));
}

#[test]
fn assisted_declined_or_failing_keeps_deterministic_statement() {
    let (p, payloads) = fake(true, Ok("This repository uses pnpm."));
    let det = AgentAssistedDetector::new(DeterministicDetector::new(), p, |_, _| false);
    let a = det.detect_assisted(&observations());
    assert!(matches!(a[0].skipped, Some(SkipReason::Declined)));
    assert!(a[0].advisory_statement.is_none());
    assert_eq!(
        det.detect(&observations())[0].statement,
        "This repository uses pnpm, not npm."
    );
    assert!(
        payloads.lock().unwrap().is_empty(),
        "nothing sent when declined"
    );

    let (p, _) = fake(true, Err(()));
    let det = AgentAssistedDetector::new(DeterministicDetector::new(), p, |_, _| true);
    let a = det.detect_assisted(&observations());
    assert!(matches!(
        a[0].skipped,
        Some(SkipReason::Provider(ProviderError::Timeout { .. }))
    ));
    assert_eq!(
        a[0].candidate.statement,
        "This repository uses pnpm, not npm."
    );

    // Output that ignores the tokens, or is too long, is unusable.
    for bad in ["Sure! Here you go.", "", &"pnpm ".repeat(100)] {
        let (p, _) = fake(true, Ok(bad));
        let det = AgentAssistedDetector::new(DeterministicDetector::new(), p, |_, _| true);
        let a = det.detect_assisted(&observations());
        assert!(
            matches!(a[0].skipped, Some(SkipReason::Unusable)),
            "{bad:?}"
        );
        assert_eq!(
            det.detect(&observations())[0].statement,
            "This repository uses pnpm, not npm."
        );
    }
}

#[test]
fn assisted_local_skips_confirmation_unless_requested() {
    let (p, payloads) = fake(false, Ok("This repository uses pnpm."));
    let calls = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::clone(&calls);
    let det = AgentAssistedDetector::new(DeterministicDetector::new(), p, move |_, _| {
        c2.fetch_add(1, Ordering::SeqCst);
        false
    });
    let out = det.detect(&observations());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(out[0].statement, "This repository uses pnpm.");
    assert_eq!(payloads.lock().unwrap().len(), 1);

    let (p, payloads) = fake(false, Ok("This repository uses pnpm."));
    let det = AgentAssistedDetector::new(DeterministicDetector::new(), p, |_, _| false)
        .confirm_local(true);
    let out = det.detect(&observations());
    assert_eq!(out[0].statement, "This repository uses pnpm, not npm.");
    assert!(payloads.lock().unwrap().is_empty());
}

#[test]
fn sanitize_statement_rules() {
    let c = cand(
        Some("pnpm"),
        Some("npm"),
        "package-manager",
        "pnpm-repository-convention",
    );
    assert_eq!(
        sanitize_statement("  `This repo uses PNPM.`\n", &c).as_deref(),
        Some("This repo uses PNPM.")
    );
    assert_eq!(
        sanitize_statement("line one pnpm\nline\u{1b}[31m two", &c).as_deref(),
        Some("line one pnpm line[31m two")
    );
    let red = sanitize_statement("pnpm sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKE", &c).unwrap();
    assert!(!red.contains("FAKEFAKE"));
    assert!(sanitize_statement("use npm", &c).is_none());
    let avoid_only = cand(None, Some("npm"), "package-manager", "avoid-npm-convention");
    assert!(sanitize_statement("This repository avoids npm.", &avoid_only).is_some());
    let none = cand(None, None, "convention", "repository-convention");
    assert!(sanitize_statement("anything", &none).is_none());
    let _ = AdvisoryPurpose::ReviewSkill;
}
