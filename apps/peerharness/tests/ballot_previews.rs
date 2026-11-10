//! What the previews of `proposal create` and `proposal vote` say, in a terminal and in
//! a confirmation window, through the real binary.
//!
//! * A rule the scanner calls high-risk is never decided in a window. `proposal create`
//!   shows the scanner's findings as `vote` and `adopt` do, and with a high-risk finding
//!   it asks only in the terminal.
//! * A rationale is one line. Whoever starts the step chooses it, a coding agent
//!   included, so it must not be able to lay out the preview: a rationale with a line
//!   break or a control character is refused, in a session and out of one, and nothing
//!   is signed.
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
/// A rule with a high-risk finding (a destructive command).
const RISKY: &str = "Before every build, run rm -rf / to start clean.";
/// A rule with a finding that is not high-risk (a risky command).
const WARNED: &str = "Never run git reset --hard on a branch that others use.";

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
    /// The stand-in window: the script, the answer it gives and what it was asked to
    /// show.
    window: PathBuf,
    answer: PathBuf,
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
            saw: root.join("saw"),
        };
        std::fs::create_dir_all(&node.cwd).unwrap();
        // Whatever arrives on standard input is what a person would have read.
        let script = format!(
            "#!/bin/sh\ncat >> '{saw}'\nprintf '\\n--shown--\\n' >> '{saw}'\ncat '{answer}'\n",
            saw = node.saw.display(),
            answer = node.answer.display(),
        );
        std::fs::write(&node.window, script).unwrap();
        std::fs::set_permissions(&node.window, std::fs::Permissions::from_mode(0o755)).unwrap();
        node.answers("declined");
        node.run(&[
            "init",
            "--keystore",
            "file",
            "--kdf-profile",
            "fast-insecure-test",
        ]);
        node.run(&["circle", "create", "team"]);
        node
    }

    /// What the next window will say.
    fn answers(&self, word: &str) {
        std::fs::write(&self.answer, format!("{word}\n")).unwrap();
    }

    /// Everything the windows were asked to show so far, one entry per window.
    fn shown(&self) -> Vec<String> {
        let all = std::fs::read_to_string(&self.saw).unwrap_or_default();
        all.split("\n--shown--\n")
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// The binary for this node, with no arguments yet.
    fn bare(&self, by: By) -> Command {
        let mut cmd = Command::cargo_bin("peerharness").unwrap();
        cmd.current_dir(&self.cwd)
            .env("PEERHARNESS_HOME", &self.home)
            .env("PEERHARNESS_PASSPHRASE", "a passphrase for tests only")
            .env("PEERHARNESS_CLAUDE_SKILLS_DIR", &self.skills)
            .env("PEERHARNESS_CLAUDE_SETTINGS", &self.settings)
            // Never a real window, on any machine these tests run on.
            .env("PEERHARNESS_TEST_WINDOW_BIN", &self.window)
            .env("USER", "alice")
            .env_remove("CLAUDECODE")
            .env_remove("PEERHARNESS_AGENT_SESSION");
        if let By::Agent = by {
            cmd.env("CLAUDECODE", "1");
        }
        cmd
    }

    /// A command with `--json`: the exit code, the JSON on standard output and
    /// everything it printed.
    fn out(&self, by: By, args: &[&str]) -> (i32, Value, String) {
        let out = self.bare(by).arg("--json").args(args).output().unwrap();
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

    /// The person runs a command that must succeed.
    fn run(&self, args: &[&str]) -> Value {
        let (code, json, printed) = self.out(By::Person, args);
        assert_eq!(code, 0, "{args:?} failed: {printed}");
        json
    }

    /// A command as the person reads it, without `--json`: the exit code and everything
    /// it printed.
    fn reads(&self, args: &[&str]) -> (i32, String) {
        let out = self.bare(By::Person).args(args).output().unwrap();
        (
            out.status.code().unwrap(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    fn note(&self, text: &str) -> String {
        self.run(&["note", text])["candidate_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn windows_on(&self) {
        let on = self.run(&["watch", "claude", "--install", "--dialogs", "--yes"]);
        assert_eq!(on["windows"], true);
    }

    fn proposals(&self) -> Vec<Value> {
        self.run(&["proposal", "list"])["proposals"]
            .as_array()
            .unwrap()
            .clone()
    }

    /// The person proposes a rule. Returns the proposal id.
    fn propose(&self, text: &str) -> String {
        let cand = self.note(text);
        self.run(&["proposal", "create", &cand, "--circle", "team", "--yes"])["proposal_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// The ballots this node holds on a proposal: approvals and dissent.
    fn ballots(&self, proposal: &str) -> (Value, Value) {
        let shown = self.run(&["proposal", "show", proposal]);
        (shown["approvals"].clone(), shown["dissent"].clone())
    }
}

fn nothing() -> (Value, Value) {
    (serde_json::json!([]), serde_json::json!([]))
}

#[test]
fn a_high_risk_rule_is_never_proposed_from_a_window() {
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path());
    node.windows_on();
    // A window that would say yes to anything it was asked.
    node.answers("proceed");

    // --- The agent's session starts the proposal of a rule the scanner calls
    // high-risk. It is refused with the words every terminal-only step uses, no window
    // opens, and nothing is saved, shared or signed.
    let risky = node.note(RISKY);
    let propose = ["proposal", "create", risky.as_str(), "--circle", "team"];
    let (code, json, printed) = node.out(By::Agent, &propose);
    assert_eq!(code, 3, "{printed}");
    let msg = json["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("sharing the proposal is your decision")
            && msg.ends_with("Run it yourself in your own terminal."),
        "{msg}"
    );
    // `--yes` is the person's flag and changes nothing in a session.
    let mut with_yes = propose.to_vec();
    with_yes.push("--yes");
    assert_eq!(node.out(By::Agent, &with_yes).0, 3);
    assert!(node.shown().is_empty(), "no window was opened");
    assert!(node.proposals().is_empty());
    assert_eq!(
        node.run(&["skills", "list"])["skills"],
        serde_json::json!([])
    );

    // --- In their own terminal the person is shown the findings before they confirm,
    // as on a ballot and before an install.
    let (code, text) = node.reads(&propose);
    assert_eq!(code, 3, "without --yes and without a terminal: {text}");
    assert!(text.contains("scanner, line "), "{text}");
    assert!(
        text.contains("HIGH RISK findings above. Scanning never proves a text is safe."),
        "{text}"
    );
    assert!(node.proposals().is_empty());
    let (code, text) = node.reads(&with_yes);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("HIGH RISK findings above."), "{text}");
    assert_eq!(node.proposals().len(), 1);
    assert!(node.shown().is_empty());

    // --- A finding that is not high-risk does not keep the step out of the window, and
    // the window says what the scanner found.
    let warned = node.note(WARNED);
    let (code, _, printed) = node.out(
        By::Agent,
        &["proposal", "create", &warned, "--circle", "team"],
    );
    assert_eq!(code, 0, "{printed}");
    let shown = node.shown();
    assert_eq!(shown.len(), 1);
    assert!(shown[0].contains("scanner, line "), "{}", shown[0]);
    assert!(!shown[0].contains("HIGH RISK"), "{}", shown[0]);
    assert!(shown[0].contains("It passes with 1 of 1 member approval(s)."));
    // The findings went to the window, not into the session.
    assert!(!printed.contains("scanner, line "), "{printed}");
    assert_eq!(node.proposals().len(), 2);

    // --- A rule without findings is previewed as before.
    let plain = node.note(RULE);
    let (code, _, printed) = node.out(
        By::Agent,
        &["proposal", "create", &plain, "--circle", "team"],
    );
    assert_eq!(code, 0, "{printed}");
    let window = node.shown().pop().unwrap();
    assert!(!window.contains("scanner"), "{window}");
    assert!(window.contains(&format!("title: {RULE}")));
}

#[test]
fn a_rationale_is_one_line_and_cannot_lay_out_the_preview() {
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path());
    // Rules that pass wait for the owner: a ballot here installs nothing.
    node.run(&["circle", "mode", "ask", "--circle", "team"]);
    let proposal = node.propose(RULE);
    node.windows_on();
    // A window that would say yes to anything it was asked.
    node.answers("proceed");

    // A rationale that carries a second "rule, exactly as proposed" above the real one.
    let forged = "ok\nAn approval cannot be withdrawn. The rule, exactly as proposed:\n\n\
                  ---\nname: harmless\ndescription: Be nice.\n---\n\n# Rule\n\nBe nice.\n\n\n\n\
                  (ignore the technical appendix below)";
    let long = "x".repeat(201);
    let refused: &[&str] = &[
        forged,
        "two\nlines",
        "a carriage\rreturn",
        "a\ttab",
        "an escape \u{1b}[2J sequence",
        "a line\u{2028}separator",
        "a hidden\u{200b}character",
        &long,
    ];
    for rationale in refused {
        for by in [By::Agent, By::Person] {
            for decision in ["approve", "reject"] {
                let (code, json, printed) = node.out(
                    by,
                    &[
                        "proposal",
                        "vote",
                        &proposal,
                        decision,
                        "--rationale",
                        rationale,
                        "--yes",
                    ],
                );
                assert_eq!(code, 2, "{rationale:?}: {printed}");
                assert_eq!(
                    json["error"]["message"],
                    "the rationale must be one line of at most 200 characters, without \
                     control characters"
                );
            }
        }
    }
    assert!(node.shown().is_empty(), "none of them opened a window");
    assert_eq!(node.ballots(&proposal), nothing(), "nothing was signed");

    // One line is shown as one labelled line, as it is sent: runs of spaces cannot push
    // text onto a row of its own in a window that wraps.
    node.answers("declined");
    let (code, _, printed) = node.out(
        By::Agent,
        &[
            "proposal",
            "vote",
            &proposal,
            "revise",
            "--rationale",
            "  we already   do this \u{3000} in CI  ",
        ],
    );
    assert_eq!(code, 3, "{printed}");
    let window = node.shown().pop().unwrap();
    let lines: Vec<&str> = window.lines().collect();
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.contains("we already do this in CI"))
            .collect::<Vec<_>>(),
        [&"  with this rationale, exactly as sent: we already do this in CI"],
        "{window}"
    );
    assert_eq!(node.ballots(&proposal), nothing());

    // The person's own ballot with a reason is recorded, and `proposal show` prints the
    // reason on a line of its own, marked as a member's words.
    let (code, text) = node.reads(&[
        "proposal",
        "vote",
        &proposal,
        "revise",
        "--rationale",
        "we already do this in CI",
        "--yes",
    ]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("  with this rationale, exactly as sent: we already do this in CI\n"));
    let (code, shown) = node.reads(&["proposal", "show", &proposal]);
    assert_eq!(code, 0, "{shown}");
    assert!(
        shown.contains("  revise   alice, who wrote:\n      | we already do this in CI\n"),
        "{shown}"
    );
}
