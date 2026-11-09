//! Detector corpus: positives, negatives, grouping, confidence, dedup and naming.

use std::collections::HashSet;

use ph_core::{
    is_valid_skill_name, Confidence, NormalizedObservation, ObservationId, ObservationKind,
    ObservationSource, Timestamp,
};
use ph_learning::detector::{suggested_skill_name, MAX_TOKEN_BYTES};
use ph_learning::{
    concept_key, extract_corrections, filter_existing_skills, filter_known, normalize_token,
    CandidateDetector, DeterministicDetector,
};

fn obs(id: &str, repo: &str, kind: ObservationKind, text: &str) -> NormalizedObservation {
    NormalizedObservation::from_raw(
        ObservationId::new(id).unwrap(),
        Timestamp::from_unix_seconds(1_800_000_000).unwrap(),
        ObservationSource::Demo,
        None,
        repo.into(),
        kind,
        text,
    )
}

fn prompt(id: &str, repo: &str, text: &str) -> NormalizedObservation {
    obs(id, repo, ObservationKind::UserPrompt, text)
}

type Pair = (Option<&'static str>, Option<&'static str>);

/// (text, preferred, avoided)
const POSITIVES: &[(&str, Pair)] = &[
    ("No, use pnpm, not npm.", (Some("pnpm"), Some("npm"))),
    ("no use pnpm, not npm", (Some("pnpm"), Some("npm"))),
    (
        "We use pnpm, not npm, for this repo.",
        (Some("pnpm"), Some("npm")),
    ),
    ("we use pnpm not npm", (Some("pnpm"), Some("npm"))),
    ("We're using pnpm not npm", (Some("pnpm"), Some("npm"))),
    ("Use pnpm instead of npm", (Some("pnpm"), Some("npm"))),
    (
        "please use vitest instead of jest here",
        (Some("vitest"), Some("jest")),
    ),
    ("Use `pnpm`, not `npm`.", (Some("pnpm"), Some("npm"))),
    ("use \"yarn\", not 'npm'", (Some("yarn"), Some("npm"))),
    ("Don't use npm, use pnpm.", (Some("pnpm"), Some("npm"))),
    (
        "don\u{2019}t use npm, use pnpm",
        (Some("pnpm"), Some("npm")),
    ),
    ("Do not use npm; use pnpm.", (Some("pnpm"), Some("npm"))),
    ("do not use pip. use uv", (Some("uv"), Some("pip"))),
    (
        "Never use npm in this repo, use pnpm instead.",
        (Some("pnpm"), Some("npm")),
    ),
    (
        "don't use jest, just use vitest",
        (Some("vitest"), Some("jest")),
    ),
    ("Prefer ruff over flake8.", (Some("ruff"), Some("flake8"))),
    (
        "We prefer biome over eslint",
        (Some("biome"), Some("eslint")),
    ),
    ("Always use uv for this repo.", (Some("uv"), None)),
    ("always use poetry in this project", (Some("poetry"), None)),
    ("Never use pip in this repository!", (None, Some("pip"))),
    ("don't use yarn in our codebase", (None, Some("yarn"))),
    (
        "Actually, we use yarn, not npm here.",
        (Some("yarn"), Some("npm")),
    ),
    (
        "You should use bun instead of npm.",
        (Some("bun"), Some("npm")),
    ),
    (
        "you need to use pytest instead of unittest",
        (Some("pytest"), Some("unittest")),
    ),
    ("This repo uses pnpm, not npm.", (Some("pnpm"), Some("npm"))),
    (
        "the project uses tabs, not spaces",
        (Some("tabs"), Some("spaces")),
    ),
    ("Use tabs, not spaces.", (Some("tabs"), Some("spaces"))),
    ("using pnpm, not npm, please", (Some("pnpm"), Some("npm"))),
    (
        "Stop. Use pnpm instead of npm!",
        (Some("pnpm"), Some("npm")),
    ),
    (
        "Wrong tool. Use the pnpm cli, not npm.",
        (Some("pnpm cli"), Some("npm")),
    ),
    ("Use pnpm to install, not npm", (Some("pnpm"), Some("npm"))),
    ("USE PNPM, NOT NPM", (Some("pnpm"), Some("npm"))),
    (
        "use @biomejs/biome instead of prettier",
        (Some("@biomejs/biome"), Some("prettier")),
    ),
    (
        "use node.js 20, not node 18",
        (Some("node.js 20"), Some("node 18")),
    ),
    ("Use pnpm \u{2014} not npm", (Some("pnpm"), Some("npm"))),
    ("use pnpm - not npm", (Some("pnpm"), Some("npm"))),
    ("Use pnpm, but not npm", (Some("pnpm"), Some("npm"))),
    ("Let's use pnpm, not npm", (Some("pnpm"), Some("npm"))),
    (
        "use pnpm instead of npm going forward",
        (Some("pnpm"), Some("npm")),
    ),
    ("No, use pnpm, not npm, thanks", (Some("pnpm"), Some("npm"))),
    (
        "use pnpm instead of npm next time",
        (Some("pnpm"), Some("npm")),
    ),
    (
        "use typescript@5, not typescript@4",
        (Some("typescript@5"), Some("typescript@4")),
    ),
    (
        "Here is the log:\n```\nnpm ERR! use yarn instead of npm\n```\nNo, use pnpm, not npm.",
        (Some("pnpm"), Some("npm")),
    ),
];

const NEGATIVES: &[&str] = &[
    "Should we use npm?",
    "use npm install to add deps",
    "I use vim, not emacs",
    "I use vim, not emacs, but whatever you like",
    "Should we use pnpm instead of npm?",
    "should we use pnpm instead of npm",
    "Can you use pnpm instead of npm?",
    "can we use pnpm, not npm",
    "Why did you use npm instead of pnpm",
    "Why do you use npm instead of pnpm",
    "Do you use npm instead of yarn?",
    "Don't use npm instead of pnpm",
    "If you use yarn instead of npm, the lockfile changes",
    "When people use yarn instead of npm the lockfile changes.",
    "They use jest, not vitest",
    "My team uses jest, not vitest.",
    "I prefer tabs over spaces",
    "I always use vim for this project",
    "you can use npm instead of pnpm if you want",
    "You use npm instead of pnpm",
    "You're using npm, not pnpm!",
    "Maybe use pnpm instead of npm",
    "we could use pnpm instead of npm",
    "he said use pnpm, not npm",
    "use it, not that",
    "use this instead of that",
    "use the one instead of the other",
    "use pnpm, not pnpm",
    "Please run the tests and use npm to install.",
    "use 2, not 4",
    "use /usr/local/bin/npm, not npm",
    "use ../scripts/build.sh instead of make",
    "use src/a/b instead of src/c",
    "a misuse of npm instead of pnpm",
    "we reuse pnpm, not npm",
    "We used npm, not pnpm.",
    "Is it better to use pnpm instead of npm?",
    "what if we use pnpm instead of npm",
    "use pnpm, not npm?",
    "do people prefer ruff over flake8",
    "Never use pip.",
    "always use uv",
    "use pnpm",
    "pnpm, not npm",
    "We tried using pnpm, not npm, and it broke",
    "Usually use pnpm instead of npm",
    "",
    "[REDACTED], not npm",
    // pasted tool output, quoted text and code
    "npm WARN deprecated request@2.88.2: request has been deprecated, use got instead of request",
    "warning: `foo` is deprecated: use bar instead of foo",
    "error: use --force instead of --legacy-peer-deps",
    "hint: use rebase instead of merge",
    "```\nuse npm, not pnpm\n```\nwhat does this do",
    "~~~\nuse npm, not pnpm\n~~~",
    "```\nunclosed fence\nuse npm, not pnpm",
    "> use npm, not pnpm",
    "  > We use npm, not pnpm.",
    "You said 'use npm, not pnpm' but that's wrong",
    "the docs say to use pnpm instead of npm",
    // permissive, hedged or conditional
    "it's fine to use npm instead of pnpm",
    "Feel free to use npm instead of pnpm",
    "Ok so use pnpm instead of npm I guess",
    "use pnpm instead of npm lol jk",
    "use pnpm instead of npm if you can",
    "Use spaces, not tabs, unless the file already uses tabs",
    "use pnpm, not npm, maybe",
    // generic words and personal identifiers are not tools
    "Use the new API, not the old one",
    "Use the right one, not the wrong one",
    "use something else instead of npm",
    "use alice@corp.com, not bob@corp.com",
    "use pnpm instead of carol@example.org",
];

#[test]
fn positives_are_detected() {
    for (text, (x, y)) in POSITIVES {
        let found = extract_corrections(text);
        assert_eq!(
            found.len(),
            1,
            "expected one correction in {text:?}, got {found:?}"
        );
        let c = &found[0];
        assert_eq!(c.preferred.as_deref(), *x, "preferred in {text:?}");
        assert_eq!(c.avoided.as_deref(), *y, "avoided in {text:?}");
    }
}

#[test]
fn negatives_are_not_detected() {
    for text in NEGATIVES {
        let found = extract_corrections(text);
        assert!(
            found.is_empty(),
            "unexpected correction in {text:?}: {:?}",
            found
                .iter()
                .map(|c| (c.preferred.clone(), c.avoided.clone()))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn several_corrections_in_one_prompt() {
    let found = extract_corrections(
        "Use pnpm, not npm. Also, use vitest instead of jest. And prefer biome over eslint.",
    );
    let keys: Vec<String> = found.iter().map(|c| c.concept_key()).collect();
    assert_eq!(
        keys,
        vec![
            "prefer:pnpm|avoid:npm",
            "prefer:vitest|avoid:jest",
            "prefer:biome|avoid:eslint"
        ]
    );
    // Trailing stop words of a token do not shadow a following match.
    let keys: Vec<String> =
        extract_corrections("use vitest instead of jest and prefer biome over eslint")
            .iter()
            .map(|c| c.concept_key())
            .collect();
    assert_eq!(
        keys,
        vec!["prefer:vitest|avoid:jest", "prefer:biome|avoid:eslint"]
    );
    // The same correction twice in one prompt counts once.
    assert_eq!(
        extract_corrections("use pnpm, not npm. use pnpm, not npm!").len(),
        1
    );
}

#[test]
fn only_user_prompts_are_scanned() {
    let d = DeterministicDetector::new();
    let input = vec![
        obs(
            "o1",
            "r",
            ObservationKind::AgentStop,
            "No, use pnpm, not npm.",
        ),
        obs(
            "o2",
            "r",
            ObservationKind::ToolFailure,
            "No, use pnpm, not npm.",
        ),
    ];
    assert!(d.detect(&input).is_empty());
    assert_eq!(d.name(), "deterministic");
}

#[test]
fn candidate_fields_for_spec_example() {
    let d = DeterministicDetector::new();
    let out = d.detect(&[prompt(
        "o1",
        "repo-a",
        "We use pnpm, not npm, for this repo.",
    )]);
    assert_eq!(out.len(), 1);
    let c = &out[0];
    assert_eq!(c.concept_key, "prefer:pnpm|avoid:npm");
    assert_eq!(c.repo_key, "repo-a");
    assert_eq!(c.statement, "This repository uses pnpm, not npm.");
    assert_eq!(c.preferred.as_deref(), Some("pnpm"));
    assert_eq!(c.avoided.as_deref(), Some("npm"));
    assert_eq!(c.confidence, Confidence::Low);
    assert_eq!(c.evidence, vec![ObservationId::new("o1").unwrap()]);
    assert_eq!(c.suggested_skill_name, "pnpm-repository-convention");
    assert_eq!(c.topic, "package-manager");
}

#[test]
fn repeats_in_same_repo_raise_confidence_to_medium() {
    let d = DeterministicDetector::new();
    let out = d.detect(&[
        prompt("o1", "repo-a", "No, use pnpm, not npm."),
        prompt("o2", "repo-a", "noise without corrections"),
        prompt("o3", "repo-a", "Don't use npm, use pnpm!"),
        prompt("o4", "repo-a", "use pnpm instead of npm"),
    ]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].confidence, Confidence::Medium);
    let ids: Vec<&str> = out[0].evidence.iter().map(ObservationId::as_str).collect();
    assert_eq!(ids, vec!["o1", "o3", "o4"]);
}

#[test]
fn different_repos_are_separate_and_low() {
    let d = DeterministicDetector::new();
    let out = d.detect(&[
        prompt("o1", "repo-a", "No, use pnpm, not npm."),
        prompt("o2", "repo-b", "No, use pnpm, not npm."),
    ]);
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|c| c.confidence == Confidence::Low));
    assert_eq!(out[0].repo_key, "repo-a");
    assert_eq!(out[1].repo_key, "repo-b");
}

#[test]
fn duplicate_observation_ids_count_once() {
    let d = DeterministicDetector::new();
    let o = prompt("o1", "r", "No, use pnpm, not npm.");
    let out = d.detect(&[o.clone(), o]);
    assert_eq!(out[0].confidence, Confidence::Low);
    assert_eq!(out[0].evidence.len(), 1);
}

#[test]
fn case_insensitive_grouping() {
    let d = DeterministicDetector::new();
    let out = d.detect(&[
        prompt("o1", "r", "Use PNPM, not NPM."),
        prompt("o2", "r", "use pnpm, not npm"),
    ]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].concept_key, "prefer:pnpm|avoid:npm");
    assert_eq!(out[0].confidence, Confidence::Medium);
}

#[test]
fn prefer_only_and_avoid_only_keys_and_names() {
    let d = DeterministicDetector::new();
    let out = d.detect(&[
        prompt("o1", "r", "Always use uv for this repo."),
        prompt("o2", "r", "Never use yarn in this repo."),
        prompt("o3", "r", "always use pnpm in this project"),
    ]);
    assert_eq!(out.len(), 3);
    assert_eq!(out[0].concept_key, "prefer:uv");
    assert_eq!(out[0].statement, "This repository uses uv.");
    assert_eq!(out[0].topic, "python-packaging");
    assert_eq!(out[0].suggested_skill_name, "uv-convention");
    assert_eq!(out[1].concept_key, "avoid:yarn");
    assert_eq!(out[1].statement, "This repository does not use yarn.");
    assert_eq!(out[1].topic, "package-manager");
    assert_eq!(out[1].suggested_skill_name, "avoid-yarn-convention");
    assert_eq!(out[2].suggested_skill_name, "pnpm-repository-convention");
}

#[test]
fn topics_and_names_from_table() {
    let cases = [
        (
            "use vitest instead of jest",
            "test-runner",
            "vitest-over-jest-convention",
        ),
        (
            "prefer biome over prettier",
            "lint-format",
            "biome-over-prettier-convention",
        ),
        (
            "use tabs, not spaces",
            "indentation",
            "tabs-over-spaces-convention",
        ),
        (
            "use poetry instead of pipenv",
            "python-packaging",
            "poetry-over-pipenv-convention",
        ),
        (
            "use ruff, not flake8",
            "convention",
            "ruff-over-flake8-convention",
        ),
        (
            "use bun instead of npm",
            "package-manager",
            "bun-repository-convention",
        ),
        (
            "use @types/node, not typings",
            "convention",
            "types-node-over-typings-convention",
        ),
        ("use c++ instead of c", "convention", "c-over-c-convention"),
    ];
    let d = DeterministicDetector::new();
    for (text, topic, name) in cases {
        let out = d.detect(&[prompt("o1", "r", text)]);
        assert_eq!(out.len(), 1, "{text}");
        assert_eq!(out[0].topic, topic, "{text}");
        assert_eq!(out[0].suggested_skill_name, name, "{text}");
        assert!(is_valid_skill_name(&out[0].suggested_skill_name));
    }
}

#[test]
fn skill_names_are_always_valid_and_bounded() {
    let long_x = "a".repeat(40);
    let long_y = "b-".repeat(20);
    let names = [
        suggested_skill_name(Some(&long_x), Some(&long_y), "convention"),
        suggested_skill_name(Some(&long_x), None, "package-manager"),
        suggested_skill_name(None, Some(&long_y), "convention"),
        suggested_skill_name(Some("@"), Some("@@"), "convention"),
        suggested_skill_name(None, None, "convention"),
        suggested_skill_name(Some("x--y__z"), Some("..q"), "convention"),
        suggested_skill_name(Some("a b c"), Some("d.e/f"), "convention"),
    ];
    for n in &names {
        assert!(is_valid_skill_name(n), "{n}");
        assert!(n.len() <= 64, "{n}");
        assert!(n.ends_with("-convention"), "{n}");
    }
    assert_eq!(names[4], "repository-convention");
    assert_eq!(names[6], "a-b-c-over-d-e-f-convention");
    // A truncated core never ends with a hyphen.
    let n = suggested_skill_name(Some(&"ab-".repeat(13)), Some("zz"), "convention");
    assert!(is_valid_skill_name(&n), "{n}");
}

#[test]
fn token_sanitization() {
    assert_eq!(normalize_token("`pnpm`").as_deref(), Some("pnpm"));
    assert_eq!(normalize_token("\"npm\".").as_deref(), Some("npm"));
    assert_eq!(normalize_token("the pnpm CLI").as_deref(), Some("pnpm cli"));
    assert_eq!(normalize_token("npm for installs").as_deref(), Some("npm"));
    assert_eq!(normalize_token("pnpm instead").as_deref(), Some("pnpm"));
    assert_eq!(normalize_token("@scope/pkg").as_deref(), Some("@scope/pkg"));
    assert_eq!(normalize_token("node.js").as_deref(), Some("node.js"));
    assert_eq!(normalize_token("src/").as_deref(), Some("src"));
    assert_eq!(normalize_token("pkg@5.1.0").as_deref(), Some("pkg@5.1.0"));
    assert_eq!(
        normalize_token("@scope/pkg@next").as_deref(),
        Some("@scope/pkg@next")
    );
    assert_eq!(normalize_token("npm going forward").as_deref(), Some("npm"));
    for bad in [
        "",
        "it",
        "this",
        "alice@example.com",
        "bob@corp.io",
        "x.y@mail.example.net",
        "new",
        "the",
        "123",
        "a/b/c",
        "../x",
        "/usr/bin/npm",
        "a//b",
        "-flag",
        ".hidden",
        "one two three four",
        "pnpm\u{0}",
        "p\u{e9}npm",
        "[REDACTED]",
        "x y z w",
    ] {
        assert_eq!(normalize_token(bad), None, "{bad:?}");
    }
    let long = "a".repeat(MAX_TOKEN_BYTES + 1);
    assert_eq!(normalize_token(&long), None);
    assert_eq!(
        normalize_token(&"a".repeat(MAX_TOKEN_BYTES)).map(|s| s.len()),
        Some(MAX_TOKEN_BYTES)
    );
}

#[test]
fn tokens_in_output_are_lowercase_ascii_and_short() {
    let d = DeterministicDetector::new();
    let texts: Vec<&str> = POSITIVES.iter().map(|(t, _)| *t).collect();
    let input: Vec<NormalizedObservation> = texts
        .iter()
        .enumerate()
        .map(|(i, t)| prompt(&format!("o{i}"), "r", t))
        .collect();
    for c in d.detect(&input) {
        for t in [c.preferred.as_deref(), c.avoided.as_deref()]
            .into_iter()
            .flatten()
        {
            assert!(t.len() <= MAX_TOKEN_BYTES);
            assert!(t.is_ascii());
            assert_eq!(t, t.to_ascii_lowercase());
            assert!(t.split(' ').count() <= 3);
        }
        assert!(is_valid_skill_name(&c.suggested_skill_name));
    }
}

#[test]
fn adversarial_inputs_do_not_panic() {
    let d = DeterministicDetector::new();
    let mut inputs: Vec<String> = vec![
        "use ".repeat(2000),
        "use x, not ".repeat(400),
        "\u{2019}".repeat(1000),
        "don't use a, use b; ".repeat(300),
        "use \u{1F600}, not \u{1F601}".into(),
        "use\u{202E}pnpm, not npm".into(),
        "use pnpm,\nnot npm".into(),
        "use İstanbul, not npm".into(),
        "use \u{212A}nife, not npm".into(),
    ];
    inputs.push("x".repeat(5000));
    for (i, t) in inputs.iter().enumerate() {
        let out = d.detect(&[prompt(&format!("o{i}"), "r", t)]);
        for c in out {
            assert!(is_valid_skill_name(&c.suggested_skill_name));
            assert!(c
                .preferred
                .iter()
                .chain(c.avoided.iter())
                .all(|t| t.is_ascii()));
        }
    }
}

#[test]
fn many_observations_cap_evidence() {
    let d = DeterministicDetector::new();
    let input: Vec<NormalizedObservation> = (0..200)
        .map(|i| prompt(&format!("o{i}"), "r", "No, use pnpm, not npm."))
        .collect();
    let out = d.detect(&input);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].evidence.len(), ph_learning::detector::MAX_EVIDENCE);
    assert_eq!(out[0].evidence[0].as_str(), "o0");
    assert_eq!(out[0].confidence, Confidence::Medium);
}

#[test]
fn dedup_filter_known() {
    let d = DeterministicDetector::new();
    let out = d.detect(&[
        prompt("o1", "repo-a", "No, use pnpm, not npm."),
        prompt("o2", "repo-b", "No, use pnpm, not npm."),
        prompt("o3", "repo-a", "use vitest instead of jest"),
    ]);
    let mut known = HashSet::new();
    known.insert((concept_key(Some("pnpm"), Some("npm")), "repo-a".to_owned()));
    let fresh = filter_known(out.clone(), &known);
    let keys: Vec<(String, String)> = fresh
        .iter()
        .map(|c| (c.concept_key.clone(), c.repo_key.clone()))
        .collect();
    assert_eq!(
        keys,
        vec![
            ("prefer:pnpm|avoid:npm".to_owned(), "repo-b".to_owned()),
            ("prefer:vitest|avoid:jest".to_owned(), "repo-a".to_owned()),
        ]
    );
    // Duplicates within the input collapse too.
    let mut doubled = out.clone();
    doubled.extend(out.clone());
    assert_eq!(filter_known(doubled, &HashSet::new()).len(), 3);
    // Existing skills.
    let names: HashSet<String> = ["pnpm-repository-convention".to_owned()].into();
    assert_eq!(filter_existing_skills(out, &names).len(), 1);
}

#[test]
fn concept_key_shapes() {
    assert_eq!(
        concept_key(Some("PNPM"), Some("npm")),
        "prefer:pnpm|avoid:npm"
    );
    assert_eq!(concept_key(Some("uv"), None), "prefer:uv");
    assert_eq!(concept_key(None, Some("pip")), "avoid:pip");
    assert_eq!(concept_key(None, None), "");
}

#[test]
fn debug_does_not_leak_tokens() {
    let c = &extract_corrections("use supersecretthing, not npm")[0];
    let dbg = format!("{c:?}");
    assert!(!dbg.contains("supersecretthing"));
}
