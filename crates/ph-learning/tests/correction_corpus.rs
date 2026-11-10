//! How many realistic corrections the deterministic detector recognizes, and that it
//! stays silent on ordinary prompts.
//!
//! The corpus is hand-written, the way people type to a coding agent: lowercase, casual,
//! sometimes with code spans. It is not a field sample. It leans toward corrections that
//! name a tool or convention to use or to avoid, because that is what a candidate can
//! express (`preferred` / `avoided`); [`FREE_TEXT_RULES`] holds corrections that are
//! whole sentences with no such pair, which the detector cannot express and which count
//! as misses. In real sessions the share of those is likely higher than here, so the hit
//! rate below describes this corpus and nothing more.
//!
//! On this corpus: 46 of 70 corrections recognized (46 of the 56 that name something
//! to use or avoid, 0 of the 14 whole-sentence rules), and nothing on the 52 ordinary
//! prompts. The corpus was written first and the detector changed afterwards; the
//! detector before the change recognized 13 of the 70 and fired on one of the ordinary
//! prompts (a pasted compiler `help:` line).

use ph_core::{
    is_valid_skill_name, Confidence, NormalizedObservation, ObservationId, ObservationKind,
    ObservationSource, Timestamp,
};
use ph_learning::{concept_key, extract_corrections, CandidateDetector, DeterministicDetector};

type Pair = (Option<&'static str>, Option<&'static str>);

const fn both(x: &'static str, y: &'static str) -> Pair {
    (Some(x), Some(y))
}

const fn prefer(x: &'static str) -> Pair {
    (Some(x), None)
}

const fn avoid(y: &'static str) -> Pair {
    (None, Some(y))
}

/// Corrections that name what to use and/or what to avoid: (prompt, expected).
const CORRECTIONS: &[(&str, Pair)] = &[
    ("no, use pnpm", prefer("pnpm")),
    ("don't use npm here, we use pnpm", both("pnpm", "npm")),
    ("use pnpm instead of npm", both("pnpm", "npm")),
    ("prefer vitest over jest", both("vitest", "jest")),
    ("we use pnpm, not npm", both("pnpm", "npm")),
    ("switch to pnpm", prefer("pnpm")),
    ("stop using npm", avoid("npm")),
    ("nope, use yarn", prefer("yarn")),
    ("no we use uv here", prefer("uv")),
    ("dont use pip, use uv", both("uv", "pip")),
    ("use pnpm not npm", both("pnpm", "npm")),
    ("pls use bun instead of npm", both("bun", "npm")),
    ("use `ruff` instead of `flake8`", both("ruff", "flake8")),
    ("we don't use jest, we use vitest", both("vitest", "jest")),
    ("stop using npm, use pnpm", both("pnpm", "npm")),
    ("use pnpm instead", prefer("pnpm")),
    ("never use pip", avoid("pip")),
    ("always use uv", prefer("uv")),
    ("don't use yarn", avoid("yarn")),
    ("switch from jest to vitest", both("vitest", "jest")),
    ("we prefer biome to eslint", both("biome", "eslint")),
    ("use tabs, never spaces", both("tabs", "spaces")),
    (
        "please stop using `unittest`, we use pytest",
        both("pytest", "unittest"),
    ),
    ("no, use poetry here", prefer("poetry")),
    ("wrong, we use pnpm in this repo", prefer("pnpm")),
    ("i told you, don't use npm", avoid("npm")),
    (
        "use pytest rather than unittest",
        both("pytest", "unittest"),
    ),
    ("use pnpm, don't use npm", both("pnpm", "npm")),
    (
        "no. use `cargo nextest` instead of `cargo test`",
        both("cargo nextest", "cargo test"),
    ),
    ("we always use pnpm", prefer("pnpm")),
    ("we never use yarn here", avoid("yarn")),
    ("stick with vitest", prefer("vitest")),
    ("again: use pnpm, not npm", both("pnpm", "npm")),
    ("hey, we use pnpm not npm", both("pnpm", "npm")),
    ("you should use bun, not node", both("bun", "node")),
    ("why are you using npm? we use pnpm", both("pnpm", "npm")),
    ("that's npm again. this repo uses pnpm", prefer("pnpm")),
    (
        "use spaces for indentation, not tabs",
        both("spaces", "tabs"),
    ),
    ("stop using any, use unknown", both("unknown", "any")),
    ("we're on pnpm, not npm", both("pnpm", "npm")),
    ("from now on use pnpm instead of npm", both("pnpm", "npm")),
    ("no \u{2014} use bun", prefer("bun")),
    ("use yarn here, not npm", both("yarn", "npm")),
    ("ugh, stop using sudo", avoid("sudo")),
    ("it's pnpm in this repo, not npm", both("pnpm", "npm")),
    (
        "Don't use `print` for logging, use the `logging` module.",
        both("logging", "print"),
    ),
    ("no, tabs", prefer("tabs")),
    ("not npm, pnpm", both("pnpm", "npm")),
    ("we use yarn in this project", prefer("yarn")),
    ("quit using npx, use pnpm dlx", both("pnpm dlx", "npx")),
    ("avoid moment, use date-fns", both("date-fns", "moment")),
    ("go with vitest instead of jest", both("vitest", "jest")),
    (
        "keep using jest, don't switch to vitest",
        both("jest", "vitest"),
    ),
    (
        "run pnpm install, not npm install",
        both("pnpm install", "npm install"),
    ),
    ("Actually we use `uv` here, not pip.", both("uv", "pip")),
    ("NO. use pnpm", prefer("pnpm")),
];

/// Corrections that are a whole sentence with nothing to put in `preferred` or
/// `avoided`. The detector must leave them alone (a person can write them down with
/// `peerharness note`); they count as misses.
const FREE_TEXT_RULES: &[&str] = &[
    "always run the tests before you say you're done",
    "never commit directly to main",
    "stop adding comments everywhere",
    "run the linter before committing, always",
    "don't touch the generated files",
    "use the makefile targets, don't call cargo directly",
    "never push without asking me first",
    "always ask before deleting files",
    "don't add new dependencies without asking",
    "keep commits small, one change per commit",
    "no emojis in commit messages",
    "stop apologizing, just fix it",
    "write the tests first next time",
    "don't mock the database in these tests",
];

/// Ordinary prompts: requests, questions, remarks, pasted output and code. None of them
/// is a correction, and many use the same words as one.
const NOT_CORRECTIONS: &[&str] = &[
    "use the function above to compute the total",
    "can you use a loop here?",
    "don't worry about it",
    "what does this function do?",
    "add a test for the login handler",
    "why is the build failing?",
    "use the existing helper in utils.rs for this",
    "can we switch to a different approach?",
    "should we use pnpm or npm for this?",
    "stop the dev server and run the tests again",
    "never mind, I figured it out",
    "always wondered how this works, can you explain the cache layer?",
    "I don't use windows so I can't test that",
    "please rename the variable to user_count",
    "switch to the staging branch and pull",
    "switch to main and rebase",
    "I prefer the second option",
    "we use redis for caching, can you add a ttl to the session keys?",
    "is it better to use tabs or spaces here?",
    "you can use either yarn or npm, whatever works",
    "let's use the same pattern as in the user service",
    "make sure to use the latest version of the sdk",
    "use npm run build to check that it compiles",
    "instead of a class, can you make this a plain function?",
    "the docs say to never use eval, is that still true?",
    "remove the unused imports and stop there",
    "no worries, use whatever you think is best",
    "what's the difference between pnpm and npm?",
    "explain why we use pnpm instead of npm",
    "I always use vim for editing, sorry about the swap files",
    "stop",
    "thanks, now switch to the next task",
    "never seen this error before: TypeError: cannot read properties of undefined",
    "always happens on the second run, any idea why?",
    "do not use this in production yet",
    "use sudo if you need to",
    "don't use more than 2 workers for the test run",
    "no, I meant the other file",
    "yes, use it",
    "does this repo use pnpm or yarn?",
    "we don't use this module anymore, can you delete it?",
    "how do I switch to pnpm?",
    "can you switch to pnpm",
    "please use a hashmap for the lookup",
    "never used pnpm before, how does the workspace protocol work?",
    "always use the same seed so the test is reproducible",
    // pasted tool output
    "warning: used `unwrap()` on a `Result` value\n  --> src/main.rs:10:5\n   = help: use `expect` instead of `unwrap`",
    "npm WARN deprecated har-validator@5.1.5: this library is no longer supported\nnpm WARN deprecated request@2.88.2: use got instead of request",
    "git says:\nhint: use --force-with-lease instead of --force",
    // pasted code and quoted text
    "```python\n# use requests, not urllib\nimport requests\n```\nwhy does this import fail?",
    "> never use npm\nwhy does the readme say this?",
    "```sh\n# stop using npm\npnpm install\n```\ndoes this look right",
];

/// The corrections in [`CORRECTIONS`] that the detector does not recognize, each with
/// the reason. Listed so that the hit rate is a fact of this file: the test fails when
/// this list and the detector disagree.
const MISSED: &[&str] = &[
    // "stick with X" reads the same as "stick to the plan".
    "stick with vitest",
    // Spread over two sentences, and "we use X" alone is also how context is given.
    "why are you using npm? we use pnpm",
    // `any` is a stop word, so no token.
    "stop using any, use unknown",
    // No verb to anchor on.
    "we're on pnpm, not npm",
    "it's pnpm in this repo, not npm",
    "no, tabs",
    "not npm, pnpm",
    // "avoid X, use Y" is ordinary English ("avoid the rate limit, use a backoff").
    "avoid moment, use date-fns",
    // Must not come out reversed, and does not come out at all.
    "keep using jest, don't switch to vitest",
    // "run X, not Y" is as often about one command as about a convention.
    "run pnpm install, not npm install",
];

/// Hits on this corpus before the one-sided and casual shapes were added, when the
/// detector knew "use X, not Y", "use X instead of Y", "don't use Y, use X",
/// "prefer X over Y" and the "... in this repo" forms: 13 of 70. Measured by running
/// this corpus against that detector; kept here as the baseline.
const HITS_BEFORE: usize = 13;

/// The least the detector must reach on this corpus: 46 of 70.
const MIN_HITS: usize = 46;

fn found(text: &str) -> Vec<(Option<String>, Option<String>)> {
    extract_corrections(text)
        .into_iter()
        .map(|c| (c.preferred, c.avoided))
        .collect()
}

fn is_hit(text: &str, want: Pair) -> bool {
    let got = found(text);
    got.len() == 1 && got[0].0.as_deref() == want.0 && got[0].1.as_deref() == want.1
}

fn prompt(id: usize, text: &str) -> NormalizedObservation {
    NormalizedObservation::from_raw(
        ObservationId::new(&format!("o{id}")).unwrap(),
        Timestamp::from_unix_seconds(1_800_000_000).unwrap(),
        ObservationSource::Demo,
        None,
        "repo".into(),
        ObservationKind::UserPrompt,
        text,
    )
}

#[test]
fn corpus_is_large_enough() {
    assert!(CORRECTIONS.len() + FREE_TEXT_RULES.len() >= 40);
    assert!(NOT_CORRECTIONS.len() >= 30);
    let mut all: Vec<&str> = CORRECTIONS.iter().map(|(t, _)| *t).collect();
    all.extend(FREE_TEXT_RULES);
    all.extend(NOT_CORRECTIONS);
    let unique: std::collections::HashSet<&str> = all.iter().copied().collect();
    assert_eq!(unique.len(), all.len(), "a prompt is listed twice");
}

#[test]
fn hit_rate_on_corrections() {
    let total = CORRECTIONS.len() + FREE_TEXT_RULES.len();
    let mut missed = Vec::new();
    for (text, want) in CORRECTIONS {
        if is_hit(text, *want) {
            continue;
        }
        // A miss must be silence. A different correction (the sides swapped, another
        // token) would be a wrong candidate, which is worse than none.
        assert!(
            found(text).is_empty(),
            "wrong correction for {text:?}: {:?}, expected {want:?}",
            found(text)
        );
        missed.push(*text);
    }
    assert_eq!(missed, MISSED, "the list of known misses is out of date");
    let hits = CORRECTIONS.len() - missed.len();
    assert!(
        hits >= MIN_HITS,
        "{hits} of {total} corrections recognized, expected at least {MIN_HITS}"
    );
    assert!(hits > HITS_BEFORE);
    // 46 of 70 in all, 46 of the 56 that name something to use or to avoid.
    assert_eq!((hits, total, CORRECTIONS.len()), (46, 70, 56));
}

#[test]
fn free_text_rules_are_left_alone() {
    for text in FREE_TEXT_RULES {
        assert!(
            found(text).is_empty(),
            "unexpected correction in {text:?}: {:?}",
            found(text)
        );
    }
}

#[test]
fn ordinary_prompts_are_not_corrections() {
    for text in NOT_CORRECTIONS {
        assert!(
            found(text).is_empty(),
            "unexpected correction in {text:?}: {:?}",
            found(text)
        );
    }
    // The same through the detector, as the app calls it: no candidate at all.
    let observations: Vec<NormalizedObservation> = NOT_CORRECTIONS
        .iter()
        .chain(FREE_TEXT_RULES)
        .enumerate()
        .map(|(i, t)| prompt(i, t))
        .collect();
    assert!(DeterministicDetector::new()
        .detect(&observations)
        .is_empty());
}

#[test]
fn every_hit_becomes_a_reviewable_candidate() {
    let detector = DeterministicDetector::new();
    for (i, (text, want)) in CORRECTIONS.iter().enumerate() {
        if MISSED.contains(text) {
            continue;
        }
        let out = detector.detect(&[prompt(i, text)]);
        assert_eq!(out.len(), 1, "{text:?}");
        let c = &out[0];
        assert_eq!(c.preferred.as_deref(), want.0, "{text:?}");
        assert_eq!(c.avoided.as_deref(), want.1, "{text:?}");
        // One sighting is never more than low confidence, and a name is always valid.
        assert_eq!(c.confidence, Confidence::Low, "{text:?}");
        assert_eq!(c.evidence.len(), 1);
        assert!(is_valid_skill_name(&c.suggested_skill_name), "{text:?}");
        assert_eq!(c.concept_key, concept_key(want.0, want.1));
    }
}

#[test]
fn a_one_sided_correction_must_open_the_prompt() {
    // At the start of a prompt, possibly after a lead-in.
    for (text, want) in [
        ("don't use recursion", avoid("recursion")),
        ("ok. from now on always use uv", prefer("uv")),
        ("no. no. stop using npm", avoid("npm")),
        ("Like I said, never use pip!", avoid("pip")),
        ("rule: never use pip", avoid("pip")),
        (
            "```\nnpm ERR! missing script\n```\nstop using npm",
            avoid("npm"),
        ),
    ] {
        assert!(is_hit(text, want), "{text:?}: {:?}", found(text));
    }
    // In the middle of a request the same words are a constraint on that task.
    for text in [
        "write a function that flattens a list, don't use recursion",
        "implement the parser. never use regex",
        "the build is slow. always use release mode",
        "can you fix the test and stop using sleep",
        "I always use vim",
        "you never use pnpm",
        "they said never use pip",
        "maybe always use uv",
    ] {
        assert!(found(text).is_empty(), "{text:?}: {:?}", found(text));
    }
}

#[test]
fn a_one_sided_correction_names_the_option_bare() {
    for text in [
        // An article points at something in the conversation.
        "no, use the helper",
        "no, use a loop",
        "use a loop instead",
        "use the function above instead",
        "always use the same seed",
        "don't use the cache",
        "stop using an array",
        // Stop words and pointing words leave no token.
        "no, use that",
        "don't use it",
        "never use this again",
        "don't use more than 2 workers",
        "stop using so much memory",
        // "it's no use ..." is not "no, use ...".
        "no use trying that",
        // A token must still be a short identifier.
        "no, use ../scripts/build.sh",
        "stop using alice@example.com",
    ] {
        assert!(found(text).is_empty(), "{text:?}: {:?}", found(text));
    }
    // Both sides may carry an article: the contrast is the signal there.
    assert!(is_hit(
        "use the pnpm cli, not the npm cli",
        both("pnpm cli", "npm cli")
    ));
}

#[test]
fn switching_branches_and_modes_is_not_a_correction() {
    for text in [
        "switch to main",
        "switch to the staging branch and pull",
        "switch to dark mode",
        "switch back to master",
        "switch to plan mode",
        "switch from main to develop",
        "switch to the next task",
    ] {
        assert!(found(text).is_empty(), "{text:?}: {:?}", found(text));
    }
    assert!(is_hit("switch back to yarn", prefer("yarn")));
    assert!(is_hit("switch to pnpm from npm", both("pnpm", "npm")));
    assert!(is_hit(
        "switch to vitest instead of jest",
        both("vitest", "jest")
    ));
}

#[test]
fn statements_count_only_when_the_clause_ends_there() {
    for (text, want) in [
        ("this repo uses pnpm", prefer("pnpm")),
        ("We use pnpm here.", prefer("pnpm")),
        ("we use pnpm in this repo, thanks", prefer("pnpm")),
        ("We don't use yarn in this project.", avoid("yarn")),
        ("you ran npm again. we use pnpm here", prefer("pnpm")),
        (
            "we use zod here, add a schema for the new endpoint",
            prefer("zod"),
        ),
    ] {
        assert!(is_hit(text, want), "{text:?}: {:?}", found(text));
    }
    for text in [
        // Context for a request, not a correction.
        "this repo uses typescript and react, add a settings page",
        "this project uses a custom build script, can you document it?",
        "we use zod here for validation, add a schema for the new endpoint",
        "we use redis for caching",
        "we use pnpm",
        // Questions, hedges and other people.
        "do we use pnpm here?",
        "i think we use pnpm here",
        "if we use pnpm here the lockfile changes",
        "they use pnpm here",
    ] {
        assert!(found(text).is_empty(), "{text:?}: {:?}", found(text));
    }
}

#[test]
fn conditions_and_one_offs_are_not_rules() {
    for text in [
        "don't use caching when running the integration tests",
        "stop using npm until the registry is back",
        "never use sudo unless I say so",
        "never use force push on this branch without telling me",
        "use pnpm instead for now",
        "use pnpm instead of npm for now",
        "use tabs, not spaces, in this file",
        "no, use yarn this time",
        "don't use npm instead of pnpm",
        "always use uv, maybe",
    ] {
        assert!(found(text).is_empty(), "{text:?}: {:?}", found(text));
    }
    // A reason is not a condition.
    assert!(is_hit(
        "never use pip because it ignores the lockfile",
        avoid("pip")
    ));
    assert!(is_hit(
        "use pnpm instead of npm next time",
        both("pnpm", "npm")
    ));
}

#[test]
fn both_sides_win_over_one_side() {
    // Overlapping matches: the pair, not the shorter "no, use pnpm".
    assert_eq!(
        found("No, use pnpm, not npm."),
        vec![(Some("pnpm".to_owned()), Some("npm".to_owned()))]
    );
    // Said twice in one prompt, once with one side and once with both: one correction.
    for text in [
        "no, use pnpm. we use pnpm, not npm",
        "stop using npm. use pnpm instead of npm",
        "never use pip. always use uv",
        "always use uv. never use pip",
    ] {
        let got = found(text);
        assert_eq!(got.len(), 1, "{text:?}: {got:?}");
        assert!(got[0].0.is_some() && got[0].1.is_some(), "{text:?}");
    }
    // Unrelated corrections in one prompt are all kept, in order.
    assert_eq!(
        found("stop using npm. also use vitest instead of jest"),
        vec![
            (None, Some("npm".to_owned())),
            (Some("vitest".to_owned()), Some("jest".to_owned()))
        ]
    );
}

#[test]
fn repeats_of_different_shapes_support_one_candidate() {
    let detector = DeterministicDetector::new();
    let out = detector.detect(&[
        prompt(1, "stop using npm"),
        prompt(2, "ugh, don't use npm"),
        prompt(3, "we never use npm here"),
    ]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].concept_key, "avoid:npm");
    assert_eq!(out[0].confidence, Confidence::Medium);
    assert_eq!(out[0].evidence.len(), 3);
    assert_eq!(out[0].statement, "This repository does not use npm.");
}

/// Long inputs with many matches and no sentence end must not panic, and every token
/// that comes out is still a short ASCII identifier.
#[test]
fn long_repetitive_inputs_are_handled() {
    let detector = DeterministicDetector::new();
    for (i, text) in [
        "no, use ".repeat(600),
        "switch to the ".repeat(500),
        "we use a here ".repeat(300),
        "stop using x and ".repeat(300),
        "always use \u{1F600} ".repeat(200),
        "no, use pnpm ".repeat(300),
    ]
    .iter()
    .enumerate()
    {
        for c in detector.detect(&[prompt(i, text)]) {
            assert!(is_valid_skill_name(&c.suggested_skill_name));
            for t in c.preferred.iter().chain(c.avoided.iter()) {
                assert!(t.is_ascii() && t.split(' ').count() <= 3);
            }
        }
    }
}
