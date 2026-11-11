//! `peerharness setup` (ADR-039), through the real binary: the one command a person
//! runs before they use PeerHarness from their coding agent.
//!
//! What these tests show: it creates the node, connects the agent and registers the
//! tools, each after a preview; running it again changes nothing; an agent's session
//! cannot run it; and where Claude Code is missing or refuses, it says what to run.
//! Without confirmation windows it ends by saying what works there, not by suggesting
//! prompts the agent can only refuse; for a node that is already there it names the
//! keystore, and warns about a plaintext one; and `reset` names the command that takes
//! the tools out of Claude Code again.
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
    // What the owner reads about the windows claims no more than the guard does: it
    // holds inside a session PeerHarness recognizes, and says what it is not.
    let said_flat = said.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        said_flat.contains(
            "Inside its session your agent cannot answer the window, and --yes does not skip \
             it there. That guards against an agent that is trying to help, not against a \
             process that hides that it is one."
        ),
        "{said}"
    );
    assert!(
        !said_flat.contains("Your agent cannot answer it and --yes does not skip it."),
        "{said}"
    );
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

/// Without confirmation windows every tool but `note` answers that the step is the
/// owner's (ADR-038). `setup` used to end by suggesting two prompts for the agent all
/// the same, and the agent answered them with "run `peerharness setup`".
#[test]
fn without_windows_setup_says_what_works_and_suggests_nothing_that_cannot() {
    let tmp = TempDir::new().unwrap();
    let m = Machine::new(tmp.path());
    let prompts = [
        "Start a new Claude Code session and ask it",
        "What is my PeerHarness device key?",
        "Create a PeerHarness team called acme.",
    ];

    // The owner keeps every decision in the terminal.
    let out = m.setup(&["--no-dialogs", "--yes"]).output().unwrap();
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(said.contains("off (every decision needs your own terminal)"));
    // What works there: the note, the count at the end of a turn, and the terminal.
    assert!(
        said.contains("Without confirmation windows, this is what works from here:"),
        "{said}"
    );
    assert!(said.contains("Your agent notes a rule"), "{said}");
    assert!(said.contains("At the end of a turn"), "{said}");
    assert!(
        said.contains("Every decision is typed in your own terminal"),
        "{said}"
    );
    assert!(said.contains("`peerharness keep <id>`"), "{said}");
    assert!(
        said.contains(concat!(
            env!("CARGO_PKG_REPOSITORY"),
            "/blob/main/docs/terminal.md"
        )),
        "{said}"
    );
    // Neither prompt would be answered with anything but a refusal.
    for prompt in prompts {
        assert!(!said.contains(prompt), "{prompt}: {said}");
    }
    // Running it again says the same, and says so to a program too.
    let again = m.setup(&["--no-dialogs", "--yes"]).output().unwrap();
    assert!(text(&again).contains("this is what works from here"));
    assert!(!text(&again).contains(prompts[0]));
    let report = json(
        &m.setup(&["--no-dialogs", "--yes", "--json"])
            .output()
            .unwrap(),
    );
    assert_eq!(report["agent_can_ask"], false);
    assert_eq!(report["agent"]["windows"], false);

    // With the windows on, the prompts are what to try, and the other text is not there.
    let out = m.setup(&["--yes"]).output().unwrap();
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    for prompt in prompts {
        assert!(said.contains(prompt), "{prompt}: {said}");
    }
    assert!(!said.contains("Without confirmation windows"), "{said}");
    let report = json(&m.setup(&["--yes", "--json"]).output().unwrap());
    assert_eq!(report["agent_can_ask"], true);
}

/// The same on a machine that can show no window at all: `setup` cannot turn anything
/// on there, and does not pretend to.
#[cfg(not(target_os = "macos"))]
#[test]
fn on_a_machine_without_a_window_setup_says_what_works_there() {
    let tmp = TempDir::new().unwrap();
    let m = Machine::new(tmp.path());
    for _ in 0..2 {
        let out = m
            .setup(&["--yes"])
            .env_remove("PEERHARNESS_TEST_WINDOW_BIN")
            .output()
            .unwrap();
        let said = text(&out);
        assert!(out.status.success(), "{said}");
        assert!(
            said.contains("This machine has no window PeerHarness can show"),
            "{said}"
        );
        assert!(said.contains("this is what works from here"), "{said}");
        assert!(said.contains("docs/terminal.md"), "{said}");
        assert!(!said.contains("Start a new Claude Code session"), "{said}");
        assert!(!said.contains("Create a PeerHarness team"), "{said}");
    }
    let status = json(
        &m.cmd(&["--json", "watch", "claude", "--status"])
            .env_remove("PEERHARNESS_TEST_WINDOW_BIN")
            .output()
            .unwrap(),
    );
    assert_eq!(status["windows"], false);
    assert_eq!(status["windows_available"], false);
}

/// Windows that were turned on where one could be shown, and a machine that can show
/// none (a home that came along from a Mac). `setup` turns nothing off by itself, and
/// what a tool may run is read from the settings: the tools that need no window still
/// run. The closing lines must not say that the agent only notes rules. They say what
/// still runs, and the command that turns it off does.
#[cfg(not(target_os = "macos"))]
#[test]
fn settings_that_allow_more_than_this_machine_can_ask_are_said_and_can_be_turned_off() {
    let tmp = TempDir::new().unwrap();
    let m = Machine::new(tmp.path());
    // Where a window can be shown (the stand-in), the owner allows every step.
    let out = m.setup(&["--yes"]).output().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let windowless = |args: &[&str]| -> Output {
        m.setup(args)
            .env_remove("PEERHARNESS_TEST_WINDOW_BIN")
            .output()
            .unwrap()
    };

    // The same home on a machine without one.
    let out = windowless(&["--yes"]);
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(
        said.contains("This machine has no window PeerHarness can show")
            || said.contains("this machine has no window PeerHarness can show"),
        "{said}"
    );
    assert!(!said.contains("That is all it does"), "{said}");
    assert!(!said.contains("Start a new Claude Code session"), "{said}");
    assert!(
        said.contains("A step that would ask you in a window is refused on this machine."),
        "{said}"
    );
    assert!(
        said.contains("still allow your agent the steps that need no window"),
        "{said}"
    );
    assert!(said.contains("founding a circle"), "{said}");
    assert!(said.contains("over the public network"), "{said}");
    assert!(said.contains("`peerharness setup --no-dialogs`"), "{said}");
    let report = json(&windowless(&["--yes", "--json"]));
    assert_eq!(report["agent_can_ask"], false);
    assert_eq!(report["agent"]["windows"], true, "nothing was turned off");

    // The command it names turns them off, and then the agent does only note.
    let out = windowless(&["--no-dialogs", "--yes"]);
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(said.contains("That is all it does"), "{said}");
    assert!(!said.contains("still allow your agent"), "{said}");
    let report = json(&windowless(&["--no-dialogs", "--yes", "--json"]));
    assert_eq!(report["agent"]["windows"], false);
}

/// For a node that is already there, step 1 says which keystore holds its key. A
/// plaintext keystore is said loudly: whoever ran `init` saw its warning, and that may
/// not have been the owner.
#[test]
fn setup_says_which_keystore_an_existing_node_uses_and_warns_about_plaintext() {
    let tmp = TempDir::new().unwrap();

    // --- A node with plaintext keys, made before the owner ran `setup`.
    let root = |name: &str| {
        let root = tmp.path().join(name);
        std::fs::create_dir_all(&root).unwrap();
        root
    };
    let m = Machine::new(&root("plain"));
    let made = m
        .cmd(&[
            "--json",
            "init",
            "--keystore",
            "insecure-dev",
            "--insecure-dev-keystore",
        ])
        .output()
        .unwrap();
    assert_eq!(json(&made)["keystore"], "insecure-dev");
    let out = m.cmd(&["setup", "--yes"]).output().unwrap();
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(said.contains("1. Your node: already there."), "{said}");
    assert!(
        said.contains("Its private key is in a plaintext file (the insecure-dev keystore)."),
        "{said}"
    );
    assert!(
        said.contains("WARNING: this node's private keys are stored in PLAINTEXT"),
        "{said}"
    );
    assert!(said.contains("`peerharness reset`"), "{said}");
    // With --json the warning is on standard error, and the keystore is in the report.
    let out = m.cmd(&["setup", "--yes", "--json"]).output().unwrap();
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("warning: this node's private keys are stored in PLAINTEXT"),
        "{}",
        text(&out)
    );
    let report = json(&out);
    assert_eq!(report["node_created"], false);
    assert_eq!(report["keystore"], "insecure-dev");

    // --- A node with its key in an encrypted file: named, and no warning.
    let m = Machine::new(&root("file"));
    let init = m
        .cmd(&[
            "init",
            "--keystore",
            "file",
            "--kdf-profile",
            "fast-insecure-test",
        ])
        .env("PEERHARNESS_PASSPHRASE", "a passphrase for tests only")
        .output()
        .unwrap();
    assert!(init.status.success(), "{}", text(&init));
    // The passphrase is given to every command on this node: `setup` does not unlock
    // the key today, and if it ever did, the prompt would read the terminal the tests
    // were started from.
    let passphrase = "a passphrase for tests only";
    let out = m
        .cmd(&["setup", "--yes"])
        .env("PEERHARNESS_PASSPHRASE", passphrase)
        .output()
        .unwrap();
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(said.contains("1. Your node: already there."), "{said}");
    assert!(
        said.contains("Its private key is in an encrypted file, protected by your passphrase."),
        "{said}"
    );
    assert!(!said.contains("PLAINTEXT"), "{said}");
    let report = json(
        &m.cmd(&["setup", "--yes", "--json"])
            .env("PEERHARNESS_PASSPHRASE", passphrase)
            .output()
            .unwrap(),
    );
    assert_eq!(report["keystore"], "file");
}

/// An `init` that is interrupted (Ctrl-C at the passphrase prompt) leaves a config file
/// and a database that holds no identity. `setup` used to take the two files for a
/// node, skip its first step and fail with "this home has no device identity yet: run
/// `peerharness init`", every time. It asks the database now, and completes the home.
#[test]
fn setup_completes_a_home_that_an_interrupted_init_left() {
    let tmp = TempDir::new().unwrap();
    let m = Machine::new(tmp.path());

    // The half-made home: a config file as `init` writes it, and a database with its
    // tables and nothing in them. No key was made.
    let elsewhere = tmp.path().join("another-home");
    let made = m
        .cmd(&[
            "init",
            "--keystore",
            "insecure-dev",
            "--insecure-dev-keystore",
        ])
        .env("PEERHARNESS_HOME", &elsewhere)
        .output()
        .unwrap();
    assert!(made.status.success(), "{}", text(&made));
    std::fs::create_dir_all(&m.home).unwrap();
    std::fs::set_permissions(&m.home, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::copy(elsewhere.join("config.toml"), m.home.join("config.toml")).unwrap();
    drop(ph_store::Store::open(m.home.join("peerharness.db")).unwrap());
    let status = m.cmd(&["status"]).output().unwrap();
    assert_eq!(status.status.code(), Some(2), "{}", text(&status));
    assert!(
        text(&status).contains("this home has no device identity yet"),
        "{}",
        text(&status)
    );

    // `setup` makes the node and goes on to its other steps.
    let out = m.setup(&["--yes"]).output().unwrap();
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(said.contains("1. Your node: created."), "{said}");
    assert!(said.contains("2. Claude Code: connected."), "{said}");
    assert!(!said.contains("no device identity yet"), "{said}");
    let status = json(&m.cmd(&["--json", "status"]).output().unwrap());
    let key = status["device_key"].as_str().unwrap().to_owned();
    assert!(key.starts_with("ed25519:"), "{status}");
    assert_ne!(
        json(
            &m.cmd(&["--json", "status"])
                .env("PEERHARNESS_HOME", &elsewhere)
                .output()
                .unwrap()
        )["device_key"],
        key.as_str(),
        "a key of its own, not the other home's"
    );

    // A second run finds the node, as on any home.
    let again = m.setup(&["--yes"]).output().unwrap();
    let said = text(&again);
    assert!(again.status.success(), "{said}");
    assert!(said.contains("1. Your node: already there."), "{said}");
    assert_eq!(
        json(&m.cmd(&["--json", "status"]).output().unwrap())["device_key"],
        key.as_str()
    );
}

/// `reset` leaves the registration with Claude Code in place, and names the command
/// that takes it out: the one `setup` showed when it made the registration.
#[test]
fn reset_names_the_command_that_takes_the_tools_out_of_claude_code() {
    const UNREGISTER: &str = "`claude mcp remove peerharness --scope user`";
    let tmp = TempDir::new().unwrap();
    let m = Machine::new(tmp.path());
    let out = m.setup(&["--yes"]).output().unwrap();
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(
        said.contains(&format!("Take it out again with {UNREGISTER}.")),
        "{said}"
    );

    // Before anything is deleted: what stays, each with the way to remove it.
    let out = m.cmd(&["reset"]).output().unwrap();
    let dry = text(&out);
    assert!(out.status.success(), "{dry}");
    let left = dry
        .split("Left in place:")
        .nth(1)
        .unwrap_or_else(|| panic!("{dry}"));
    assert!(left.contains("registration of the PeerHarness tools with Claude Code"));
    assert!(left.contains(UNREGISTER), "{dry}");
    assert!(
        left.contains("`peerharness watch claude --remove`"),
        "{dry}"
    );
    assert!(left.contains("Nothing was deleted."), "{dry}");
    assert!(m.home.join("peerharness.db").is_file());

    // After the node is gone the same lines say what is still there. PeerHarness did
    // not run Claude Code's command itself.
    let out = m.cmd(&["reset", "--confirm"]).output().unwrap();
    let done = text(&out);
    assert!(out.status.success(), "{done}");
    assert!(done.contains("This node no longer exists."), "{done}");
    let still = done
        .split("Still in place:")
        .nth(1)
        .unwrap_or_else(|| panic!("{done}"));
    assert!(still.contains(UNREGISTER), "{done}");
    assert!(!m.home.exists());
    assert!(
        m.calls().iter().all(|c| !c.contains("remove")),
        "{:?}",
        m.calls()
    );
    assert!(m.registered.is_file(), "the registration is still there");
}
