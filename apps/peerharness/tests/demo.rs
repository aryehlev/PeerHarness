//! End-to-end check of `peerharness demo`: the real binary runs the whole voting flow
//! across three independent nodes and fails if any step misbehaves.

use assert_cmd::Command;
use predicates::prelude::*;

fn peerharness() -> Command {
    let mut cmd = Command::cargo_bin("peerharness").unwrap();
    // The demo must not depend on, read or change the developer's own home.
    cmd.env_remove("PEERHARNESS_HOME");
    cmd.env_remove("PEERHARNESS_CLAUDE_SKILLS_DIR");
    cmd
}

#[test]
fn demo_runs_the_whole_vote_and_explains_it() {
    peerharness()
        .arg("demo")
        .assert()
        .success()
        .stdout(predicate::str::contains("charter 3: alice, bob, carol."))
        // The founder alone can admit the second member, but not the third.
        .stdout(predicate::str::contains(
            "alice approves: 1 of 2 (2 needed)",
        ))
        // One approval of three is not a majority, and a rejection is not a veto.
        .stdout(predicate::str::contains(
            "open: 1 of 3 approved (2 needed), 1 dissenting",
        ))
        .stdout(predicate::str::contains(
            "passed: 2 of 3 approved (2 needed), 1 dissenting",
        ))
        .stdout(predicate::str::contains(
            "carol: removed pnpm-repository-convention; alice and bob: unchanged.",
        ))
        .stdout(predicate::str::contains("She is not on the roll: refused."))
        .stdout(predicate::str::contains("a notary, not a ruler"))
        // Honest about what the demo does not show.
        .stdout(predicate::str::contains(
            "The QUIC transport is not wired into the CLI yet.",
        ));
}

#[test]
fn demo_json_report_is_a_single_document_on_stdout() {
    let out = peerharness().args(["--json", "demo"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is one JSON document");
    assert_eq!(v["charter_seq"], 3);
    assert_eq!(v["skill_name"], "pnpm-repository-convention");
    assert_eq!(
        v["tally"],
        "passed: 2 of 3 approved (2 needed), 1 dissenting"
    );
    // Binding rule: installed for the members who did not opt out.
    assert_eq!(v["installed"]["alice"], true);
    assert_eq!(v["installed"]["bob"], true);
    assert_eq!(v["installed"]["carol"], false);
    // The narrative went to stderr, so stdout stayed machine-readable.
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("Three independent nodes decided one shared rule"));
}

#[test]
fn demo_leaves_the_developers_home_alone() {
    let home = tempfile::tempdir().unwrap();
    let skills = tempfile::tempdir().unwrap();
    peerharness()
        .arg("demo")
        .env("PEERHARNESS_HOME", home.path())
        .env("PEERHARNESS_CLAUDE_SKILLS_DIR", skills.path())
        .assert()
        .success();
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(skills.path()).unwrap().count(), 0);
}
