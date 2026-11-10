//! Confirmation windows (ADR-033), through the real binary.
//!
//! Inside a coding agent's session a consent step is refused. When the owner has turned
//! windows on, three steps are instead put to the person in a window of the operating
//! system: proposing a rule, a ballot on a proposed rule, and installing a rule that
//! passed. These tests show both sides: what the click in the window does, and
//! everything that is not that click doing nothing.
//!
//! No test here opens a real window. Every command gets `PEERHARNESS_TEST_WINDOW_BIN`,
//! a script that stands in for the window: it records the exact text it was asked to
//! show and gives the answer the test wrote down for it. Only debug builds read that
//! variable, so the file is compiled for debug builds only.
#![cfg(all(unix, debug_assertions))]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

const RULE: &str = "Run the tests before you say a task is done.";
const SKILL: &str = "run-tests-before-say-task-done";

/// Who is at the keyboard.
#[derive(Clone, Copy)]
enum By {
    /// The person, in their own terminal.
    Person,
    /// A coding agent's shell (`CLAUDECODE` is set, as Claude Code does).
    Agent,
}

struct Node {
    home: PathBuf,
    skills: PathBuf,
    settings: PathBuf,
    cwd: PathBuf,
    /// The stand-in window: the script, the answer it gives, its exit code and what it
    /// was asked to show.
    window: PathBuf,
    answer: PathBuf,
    exit: PathBuf,
    saw: PathBuf,
}

impl Node {
    fn new(root: &Path) -> Self {
        let node = Self {
            home: root.join("home"),
            skills: root.join("skills"),
            settings: root.join("claude-settings.json"),
            cwd: root.join("project"),
            window: root.join("window.sh"),
            answer: root.join("answer"),
            exit: root.join("exit"),
            saw: root.join("saw"),
        };
        std::fs::create_dir_all(&node.cwd).unwrap();
        // Whatever arrives on standard input is what a person would have read.
        let script = format!(
            "#!/bin/sh\ncat >> '{saw}'\nprintf '\\n--shown--\\n' >> '{saw}'\n\
             cat '{answer}'\nexit \"$(cat '{exit}')\"\n",
            saw = node.saw.display(),
            answer = node.answer.display(),
            exit = node.exit.display(),
        );
        std::fs::write(&node.window, script).unwrap();
        std::fs::set_permissions(&node.window, std::fs::Permissions::from_mode(0o755)).unwrap();
        node.answers("declined", 0);
        node.run(&[
            "init",
            "--keystore",
            "insecure-dev",
            "--insecure-dev-keystore",
        ]);
        node
    }

    /// What the next window will say, and how its program will exit.
    fn answers(&self, word: &str, exit: i32) {
        std::fs::write(&self.answer, format!("{word}\n")).unwrap();
        std::fs::write(&self.exit, exit.to_string()).unwrap();
    }

    /// Everything the windows were asked to show so far, one entry per window.
    fn shown(&self) -> Vec<String> {
        let all = std::fs::read_to_string(&self.saw).unwrap_or_default();
        all.split("\n--shown--\n")
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    }

    fn cmd(&self, by: By, args: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("peerharness").unwrap();
        cmd.current_dir(&self.cwd)
            .env("PEERHARNESS_HOME", &self.home)
            .env("PEERHARNESS_CLAUDE_SKILLS_DIR", &self.skills)
            .env("PEERHARNESS_CLAUDE_SETTINGS", &self.settings)
            // Never a real window, on any machine these tests run on.
            .env("PEERHARNESS_TEST_WINDOW_BIN", &self.window)
            .env("USER", "alice")
            .env_remove("CLAUDECODE")
            .env_remove("PEERHARNESS_AGENT_SESSION")
            .arg("--json")
            .args(args);
        if let By::Agent = by {
            cmd.env("CLAUDECODE", "1");
        }
        cmd
    }

    /// The person runs a command that must succeed.
    fn run(&self, args: &[&str]) -> Value {
        let out = self.cmd(By::Person, args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?} failed: {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap_or(Value::Null)
    }

    /// The agent's session runs a command: exit code, JSON and everything it printed.
    fn agent(&self, args: &[&str]) -> (i32, Value, String) {
        let out = self.cmd(By::Agent, args).output().unwrap();
        let printed = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (
            out.status.code().unwrap(),
            serde_json::from_slice(&out.stdout).unwrap_or(Value::Null),
            printed,
        )
    }

    /// A command the agent's session is refused: the message.
    fn refused(&self, args: &[&str]) -> String {
        let (code, json, printed) = self.agent(args);
        assert_eq!(code, 3, "{args:?} should be refused: {printed}");
        json["error"]["message"].as_str().unwrap_or("").to_owned()
    }

    fn note(&self, text: &str) -> String {
        self.run(&["note", text])["candidate_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn windows_on(&self) {
        let on = self.run(&["watch", "claude", "--install", "--windows", "--yes"]);
        assert_eq!(on["windows"], true);
    }

    fn proposals(&self) -> Vec<Value> {
        self.run(&["proposal", "list"])["proposals"]
            .as_array()
            .unwrap()
            .clone()
    }

    fn skill_file(&self, name: &str) -> PathBuf {
        self.skills.join(name).join("SKILL.md")
    }
}

#[test]
fn windows_are_off_until_the_owner_turns_them_on_in_their_own_terminal() {
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path());
    node.run(&["circle", "create", "team"]);
    let cand = node.note(RULE);
    node.answers("proceed", 0);

    // Off by default: the step is refused as it always was, and no window opens.
    assert_eq!(node.run(&["watch", "claude", "--status"])["windows"], false);
    let msg = node.refused(&["proposal", "create", &cand, "--circle", "team", "--yes"]);
    assert!(msg.contains("your own terminal"), "{msg}");
    assert!(msg.contains("--windows"), "it says how to be asked: {msg}");
    assert!(node.shown().is_empty());
    assert!(node.proposals().is_empty());

    // The agent's session cannot turn windows on. Not with --yes, and not through a
    // window either: that step is never asked in one.
    let msg = node.refused(&["watch", "claude", "--install", "--windows", "--yes"]);
    assert!(msg.contains("your own terminal"), "{msg}");
    assert!(node.shown().is_empty());
    assert_eq!(node.run(&["watch", "claude", "--status"])["windows"], false);
    assert!(!node.settings.exists());
    node.refused(&["proposal", "create", &cand, "--circle", "team", "--yes"]);

    // The owner turns them on. The reporting skill now names the three steps.
    let on = node.run(&["watch", "claude", "--install", "--windows", "--yes"]);
    assert_eq!(on["windows"], true);
    assert_eq!(on["changed"], true);
    let skill = std::fs::read_to_string(node.skill_file("peerharness-notes")).unwrap();
    assert!(skill.contains("proposal vote <proposal id>"));
    assert!(skill.contains("only the user's click in that window decides"));
    let status = node.run(&["watch", "claude", "--status"]);
    assert_eq!(status["windows"], true);
    assert_eq!(status["agent_notes"], "installed");
    // Again: nothing to change.
    let again = node.run(&["watch", "claude", "--install", "--windows", "--yes"]);
    assert_eq!(again["changed"], false);
    // A plain --install keeps the owner's choice.
    let plain = node.run(&["watch", "claude", "--install", "--yes"]);
    assert_eq!(plain["windows"], true);
    assert_eq!(plain["changed"], false);

    // The agent's session cannot change the setting in either direction.
    node.refused(&["watch", "claude", "--install", "--no-windows", "--yes"]);
    node.refused(&["watch", "claude", "--remove", "--yes"]);
    assert_eq!(node.run(&["watch", "claude", "--status"])["windows"], true);

    // The owner turns them off again: the skill goes back to notes only, and the step
    // is refused again without a window.
    let off = node.run(&["watch", "claude", "--install", "--no-windows", "--yes"]);
    assert_eq!(off["windows"], false);
    let skill = std::fs::read_to_string(node.skill_file("peerharness-notes")).unwrap();
    assert!(!skill.contains("proposal"));
    assert!(skill.contains("Do not run any other peerharness command and never"));
    node.refused(&["proposal", "create", &cand, "--circle", "team", "--yes"]);
    assert!(node.shown().is_empty());

    // Removing the integration turns them off as well.
    node.windows_on();
    let removed = node.run(&["watch", "claude", "--remove", "--yes"]);
    assert_eq!(removed["windows"], false);
    assert_eq!(node.run(&["watch", "claude", "--status"])["windows"], false);
    assert!(!node.skill_file("peerharness-notes").exists());
    node.refused(&["proposal", "create", &cand, "--circle", "team", "--yes"]);
    assert!(node.shown().is_empty());
    assert!(node.proposals().is_empty());
}

#[test]
fn only_the_click_in_the_window_decides() {
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path());
    node.run(&["circle", "create", "team"]);
    // Rules that pass wait for the owner, so that installing one is a step of its own.
    node.run(&["circle", "mode", "ask", "--circle", "team"]);
    node.windows_on();
    let cand = node.note(RULE);
    let propose = [
        "proposal",
        "create",
        cand.as_str(),
        "--circle",
        "team",
        "--yes",
    ];

    // --- Proposing. Everything that is not a click on Proceed leaves nothing behind,
    // and --yes on the agent's command line changes none of it.
    node.answers("declined", 0);
    assert!(node.refused(&propose).contains("declined in the window"));
    node.answers("gave-up", 0);
    assert!(node.refused(&propose).contains("without an answer"));
    // A window program that says anything but the one word, or that fails while
    // saying it, has not confirmed.
    for (word, exit) in [("yes", 0), ("Proceed", 0), ("", 0), ("proceed", 1)] {
        node.answers(word, exit);
        let msg = node.refused(&propose);
        assert!(msg.contains("could not be shown"), "{word:?}/{exit}: {msg}");
    }
    assert!(node.proposals().is_empty());
    assert_eq!(
        node.run(&["skills", "list"])["skills"],
        serde_json::json!([])
    );
    let shown = node.shown();
    assert_eq!(shown.len(), 6, "each attempt asked the person");

    // What the person read is the exact preview: the text that would leave the machine.
    let window = &shown[0];
    assert!(window.starts_with("Your coding agent started this step."));
    assert!(window.contains("Exactly this text leaves your machine, and nothing else:"));
    assert!(window.contains(&format!("title: {RULE}")));
    assert!(window.contains(&format!("description: {RULE}")));
    assert!(window.contains(&format!("name: {SKILL}")));
    assert!(shown.iter().all(|w| w == window));

    // The person clicks Proceed.
    node.answers("proceed", 0);
    let (code, proposed, printed) = node.agent(&propose);
    assert_eq!(code, 0, "{printed}");
    assert_eq!(proposed["skill_name"], SKILL);
    let adopt = proposed["proposal_id"].as_str().unwrap().to_owned();
    // The preview went to the window, not into the agent's session.
    assert!(!printed.contains("Exactly this text leaves"), "{printed}");
    assert!(!printed.contains(RULE), "{printed}");
    assert_eq!(node.proposals().len(), 1);
    // What was shared is what was shown.
    let text = node.run(&["skills", "show", SKILL])["skill_md"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(node.shown()[6].contains(text.trim_end()));

    // --- The ballot. The window carries the rule's text itself.
    let vote = ["proposal", "vote", adopt.as_str(), "approve", "--yes"];
    node.answers("declined", 0);
    assert!(node.refused(&vote).contains("declined in the window"));
    assert_eq!(
        node.run(&["proposal", "show", &adopt])["approvals"],
        serde_json::json!([])
    );
    let window = node.shown().pop().unwrap();
    assert!(window.contains("You are about to sign a ballot in team:"));
    assert!(window.contains(&format!("approve on \"{RULE}\"")));
    assert!(window.contains("An approval cannot be withdrawn. The rule, exactly as proposed:"));
    assert!(window.contains(text.trim_end()));

    node.answers("proceed", 0);
    let (code, voted, printed) = node.agent(&vote);
    assert_eq!(code, 0, "{printed}");
    assert_eq!(voted["passed"], true);
    assert!(!printed.contains("# Rule"), "{printed}");
    assert!(
        !node.skill_file(SKILL).exists(),
        "in ask mode a rule that passed waits for the owner"
    );

    // --- Installing the rule that passed.
    let install = ["proposal", "adopt", adopt.as_str(), "--yes"];
    node.answers("declined", 0);
    assert!(node.refused(&install).contains("declined in the window"));
    assert!(!node.skill_file(SKILL).exists());
    let window = node.shown().pop().unwrap();
    assert!(window.contains(&format!("Install rule {SKILL} for your agent?")));
    assert!(window.contains(text.trim_end()));

    node.answers("proceed", 0);
    let (code, installed, printed) = node.agent(&install);
    assert_eq!(code, 0, "{printed}");
    assert_eq!(installed["installed"], true);
    assert_eq!(
        std::fs::read_to_string(node.skill_file(SKILL)).unwrap(),
        text,
        "what was shown is what was installed"
    );

    // In their own terminal the person is asked as before, and no window opens.
    let before = node.shown().len();
    let other = node.note("Never edit generated files by hand.");
    node.run(&["proposal", "create", &other, "--circle", "team", "--yes"]);
    assert_eq!(node.shown().len(), before);
}

#[test]
fn every_other_decision_still_needs_the_terminal() {
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path());
    node.run(&["circle", "create", "team"]);
    node.windows_on();
    // A window that would say yes to anything it was asked.
    node.answers("proceed", 0);

    let cand = node.note(RULE);
    let adopt = node.run(&["proposal", "create", &cand, "--circle", "team", "--yes"])
        ["proposal_id"]
        .as_str()
        .unwrap()
        .to_owned();
    node.run(&["proposal", "vote", &adopt, "approve", "--yes"]);
    assert!(node.skill_file(SKILL).exists());
    let repeal = node.run(&["rule", "repeal", SKILL, "--circle", "team", "--yes"])["proposal_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let other = node.note("Never edit generated files by hand.");
    node.run(&["review", &other, "--approve"]);

    let refused: &[&[&str]] = &[
        // Reviewing and installing for oneself.
        &["review", &cand, "--approve"],
        &["review", &cand, "--reject"],
        &[
            "skills",
            "install",
            "never-edit-generated-files-hand",
            "--yes",
        ],
        // A ballot on anything but a rule's text: here, taking a rule out of force.
        &["proposal", "vote", &repeal, "approve", "--yes"],
        &["proposal", "vote", &repeal, "reject", "--yes"],
        // Proposing a repeal, and everything about the circle itself.
        &["rule", "repeal", SKILL, "--circle", "team", "--yes"],
        &["circle", "mode", "follow", "--circle", "team", "--yes"],
        // The integration and the node.
        &["watch", "claude", "--remove", "--yes"],
        &["events", "export", "--circle", "team"],
        &["reset", "--confirm"],
    ];
    for args in refused {
        let msg = node.refused(args);
        assert!(msg.contains("your own terminal"), "{args:?}: {msg}");
    }
    assert!(node.shown().is_empty(), "none of them opened a window");
    assert_eq!(
        node.run(&["proposal", "show", &repeal])["approvals"],
        serde_json::json!([])
    );
    assert!(node.skill_file(SKILL).exists());
    assert!(node.home.join("peerharness.db").is_file());

    // A text too long to be shown in full is not shown in part: the step is refused and
    // no window opens, although this one would have said Proceed.
    let long = format!(
        "Run every one of the checks of this project before you say a task is done{}.",
        ", and then run them once more to be sure".repeat(9)
    );
    assert!(long.len() < 500);
    let long = node.note(&long);
    let msg = node.refused(&["proposal", "create", &long, "--circle", "team", "--yes"]);
    assert!(msg.contains("too long to show in full"), "{msg}");
    assert!(msg.contains("your own terminal"), "{msg}");
    assert!(node.shown().is_empty());
    assert_eq!(node.proposals().len(), 2);

    // A window program that is not there has not confirmed anything.
    let short = node.note("Use pnpm, not npm, in this repository.");
    let out = node
        .cmd(
            By::Agent,
            &["proposal", "create", &short, "--circle", "team", "--yes"],
        )
        .env(
            "PEERHARNESS_TEST_WINDOW_BIN",
            tmp.path().join("no-such-program"),
        )
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(node.proposals().len(), 2);
}
