//! `peerharness setup` (ADR-039), through the real binary: the one command a person
//! runs before they use PeerHarness from their coding agent.
//!
//! What these tests show: it creates the node, connects the agent and registers the
//! tools, each after a preview; running it again changes nothing; an agent's session
//! cannot run it; and where Claude Code is missing or refuses, it says what to run.
//!
//! Nothing here touches the developer's own Claude Code or keychain. Claude Code's
//! `claude` command is a stand-in script named by `PEERHARNESS_TEST_CLAUDE_BIN`, which
//! debug builds require and release builds do not read; the settings and skills go to
//! temporary paths; the key is the plaintext test keystore; the window is the stand-in
//! of `agent_windows.rs`.
#![cfg(all(unix, debug_assertions))]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

struct Machine {
    home: PathBuf,
    skills: PathBuf,
    settings: PathBuf,
    window: PathBuf,
    /// The stand-in for `claude`: what it was called with, whether it has the server,
    /// and whether `mcp add` is to fail.
    claude: PathBuf,
    calls: PathBuf,
    registered: PathBuf,
    refuse: PathBuf,
}

impl Machine {
    fn new(root: &Path) -> Self {
        let m = Self {
            home: root.join("home"),
            skills: root.join("skills"),
            settings: root.join("claude-settings.json"),
            window: root.join("window.sh"),
            claude: root.join("claude"),
            calls: root.join("claude-calls"),
            registered: root.join("claude-has-it"),
            refuse: root.join("claude-refuses"),
        };
        let script = |path: &Path, text: String| {
            std::fs::write(path, text).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        script(
            &m.window,
            "#!/bin/sh\ncat > /dev/null\necho declined\n".to_owned(),
        );
        script(
            &m.claude,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{calls}'\n\
                 case \"$1 $2\" in\n\
                 'mcp get') [ -f '{has}' ]; exit $? ;;\n\
                 'mcp add')\n\
                 if [ -f '{refuse}' ]; then echo 'the config file is locked' >&2; exit 1; fi\n\
                 : > '{has}'; exit 0 ;;\n\
                 esac\nexit 2\n",
                calls = m.calls.display(),
                has = m.registered.display(),
                refuse = m.refuse.display(),
            ),
        );
        m
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin("peerharness"));
        cmd.env("PEERHARNESS_HOME", &self.home)
            .env("PEERHARNESS_CLAUDE_SKILLS_DIR", &self.skills)
            .env("PEERHARNESS_CLAUDE_SETTINGS", &self.settings)
            .env("PEERHARNESS_TEST_WINDOW_BIN", &self.window)
            .env("PEERHARNESS_TEST_CLAUDE_BIN", &self.claude)
            .env("USER", "alice")
            .env_remove("CLAUDECODE")
            .env_remove("PEERHARNESS_AGENT_SESSION")
            .args(args);
        cmd
    }

    /// `setup` with the test keystore, as the person. `more` are further arguments.
    fn setup(&self, more: &[&str]) -> Command {
        let mut args = vec![
            "setup",
            "--keystore",
            "insecure-dev",
            "--insecure-dev-keystore",
        ];
        args.extend(more);
        self.cmd(&args)
    }

    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(&self.calls)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

fn json(out: &Output) -> Value {
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn one_command_sets_everything_up_and_a_second_run_changes_nothing() {
    let tmp = TempDir::new().unwrap();
    let m = Machine::new(tmp.path());

    let out = m.setup(&["--yes"]).output().unwrap();
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    // Each change was shown before it was made.
    assert!(said.contains("This lets your agent put seven decisions in front of you"));
    assert!(said.contains("This will install the skill peerharness-notes"));
    assert!(said.contains("This gives Claude Code the PeerHarness steps as tools"));
    // What it reports.
    assert!(said.contains("1. Your node: created."), "{said}");
    assert!(said.contains("2. Claude Code: connected."), "{said}");
    assert!(
        said.contains("3. The tools: registered with Claude Code."),
        "{said}"
    );
    assert!(said.contains("Start a new Claude Code session"), "{said}");

    // The node, the hooks, the skill with every step, and the windows.
    assert!(m.home.join("peerharness.db").is_file());
    let status = json(
        &m.cmd(&["--json", "watch", "claude", "--status"])
            .output()
            .unwrap(),
    );
    assert_eq!(status["installed"], true);
    assert_eq!(status["agent_notes"], "installed");
    assert_eq!(status["windows"], true);
    assert_eq!(status["circle_windows"], true);
    assert_eq!(status["own_windows"], true);

    // Claude Code was asked whether it has the server, then told to add this binary
    // for this home, and nothing else.
    let exe = assert_cmd::cargo::cargo_bin("peerharness")
        .canonicalize()
        .unwrap();
    assert_eq!(
        m.calls(),
        [
            "mcp get peerharness".to_owned(),
            format!(
                "mcp add --scope user peerharness -- {} --home {} mcp",
                exe.display(),
                m.home.display()
            ),
        ]
    );
    // The line it showed is that command.
    assert!(said.contains(&format!(
        "claude mcp add --scope user peerharness -- {} --home {} mcp",
        exe.display(),
        m.home.display()
    )));

    // Again: nothing to create, connect or register.
    let again = json(&m.setup(&["--yes", "--json"]).output().unwrap());
    assert_eq!(again["node_created"], false);
    assert_eq!(again["agent"]["changed"], false);
    assert_eq!(again["tools"], "already_registered");
    assert_eq!(m.calls().len(), 3, "it asked, and did not add again");

    // Without the windows: every decision goes back to the terminal.
    let plain = json(
        &m.setup(&["--no-dialogs", "--yes", "--json"])
            .output()
            .unwrap(),
    );
    assert_eq!(plain["agent"]["windows"], false);
    assert_eq!(plain["agent"]["circle_windows"], false);
}

#[test]
fn an_agents_session_cannot_set_peerharness_up() {
    let tmp = TempDir::new().unwrap();
    let m = Machine::new(tmp.path());
    let out = m
        .setup(&["--yes", "--json"])
        .env("CLAUDECODE", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", text(&out));
    assert!(text(&out).contains("your own terminal"));
    // Nothing was created, connected or registered.
    assert!(!m.home.join("peerharness.db").exists());
    assert!(!m.settings.exists());
    assert!(!m.skills.exists());
    assert!(m.calls().is_empty());
}

#[test]
fn nothing_is_connected_or_registered_without_the_persons_yes() {
    let tmp = TempDir::new().unwrap();
    let m = Machine::new(tmp.path());
    // No terminal is attached and there is no --yes: the first step that asks stops.
    let out = m.setup(&[]).output().unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", text(&out));
    assert!(text(&out).contains("needs your confirmation"));
    assert!(!m.settings.exists());
    assert!(!m.skills.exists());
    assert!(m.calls().is_empty());
    // A node is no decision about the agent: the one that was created stays.
    assert!(m.home.join("peerharness.db").is_file());
}

#[test]
fn where_claude_code_is_missing_or_refuses_setup_says_what_to_run() {
    let tmp = TempDir::new().unwrap();
    let m = Machine::new(tmp.path());

    // No `claude` command at all.
    let out = m
        .setup(&["--yes"])
        .env_remove("PEERHARNESS_TEST_CLAUDE_BIN")
        .output()
        .unwrap();
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(said.contains("`claude` command was not found"), "{said}");
    assert!(
        said.contains("claude mcp add --scope user peerharness -- "),
        "{said}"
    );
    assert!(m.calls().is_empty());

    // Claude Code refuses to add it: the reason it gave is passed on.
    std::fs::write(&m.refuse, "").unwrap();
    let out = m.setup(&["--yes"]).output().unwrap();
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(
        said.contains("`claude mcp add` failed (the config file is locked)"),
        "{said}"
    );
    let refused = json(&m.setup(&["--yes", "--json"]).output().unwrap());
    assert_eq!(refused["tools"], "failed");

    // Once it works, it is registered.
    std::fs::remove_file(&m.refuse).unwrap();
    let done = json(&m.setup(&["--yes", "--json"]).output().unwrap());
    assert_eq!(done["tools"], "registered");
}
