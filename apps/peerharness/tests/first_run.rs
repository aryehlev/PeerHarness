//! The first ten minutes, through the real binary: what `--help` says the tool is, the
//! next step each command points at, and the messages a newcomer meets when something
//! is not there.
//!
//! What these tests show:
//!
//! * the first line of `--help`, the package description and the README say the same
//!   sentence, and `observe` and `hook` are out of the list of commands but still run;
//! * `init` and `note` point at `demo`, `note` and `keep`, and following them works;
//! * an `init` that fails before it has a key leaves the home as it found it;
//! * `circle invite` has no option that does nothing, and its help names the file it
//!   writes;
//! * a circle name that is not on this node is answered with where the names are, and
//!   with no circle's name;
//! * `circle mode ask` does not list an installed rule as waiting, and a rule that does
//!   wait is named with its proposal id, in words;
//! * `daemon --notify` where no notification can be shown says that the daemon runs
//!   without it, and a key that cannot be unlocked is said once;
//! * `doctor` and `status` say that a debug build is one, and refuse nothing;
//! * `demo/two-peers.sh` runs with an installed binary and builds nothing then.
//!
//! Every node lives in a temporary folder with its own skills directory and settings
//! file, and no command here turns confirmation windows on.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use tempfile::TempDir;

const PASSPHRASE: &str = "a passphrase for tests only";
const RULE: &str = "Use pnpm, not npm, in this repository.";
const SKILL: &str = "use-pnpm-not-npm-repository";

struct Node {
    home: PathBuf,
    skills: PathBuf,
    settings: PathBuf,
    cwd: PathBuf,
    name: String,
}

impl Node {
    /// The folders of a node. Nothing is created in the home.
    fn bare(root: &Path, name: &str) -> Self {
        let node = Self {
            home: root.join(name).join("home"),
            skills: root.join(name).join("skills"),
            settings: root.join(name).join("claude-settings.json"),
            cwd: root.join(name).join("project"),
            name: name.to_owned(),
        };
        std::fs::create_dir_all(&node.cwd).unwrap();
        node
    }

    /// A node with a key in an encrypted file.
    fn new(root: &Path, name: &str) -> Self {
        let node = Self::bare(root, name);
        node.ok(&["init", "--keystore", "file"]);
        node
    }

    /// A command as the person runs it in their own terminal: no mark of an agent's
    /// session, no stand-in for a window, a notification or Claude Code.
    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin("peerharness"));
        cmd.current_dir(&self.cwd)
            .env("PEERHARNESS_HOME", &self.home)
            .env("PEERHARNESS_CLAUDE_SKILLS_DIR", &self.skills)
            .env("PEERHARNESS_CLAUDE_SETTINGS", &self.settings)
            .env("PEERHARNESS_PASSPHRASE", PASSPHRASE)
            .env("USER", &self.name)
            .env_remove("CLAUDECODE")
            .env_remove("PEERHARNESS_AGENT_SESSION")
            .env_remove("PEERHARNESS_TEST_WINDOW_BIN")
            .env_remove("PEERHARNESS_TEST_NOTIFY_BIN")
            .env_remove("PEERHARNESS_TEST_CLAUDE_BIN")
            .stdin(Stdio::null());
        cmd.args(args);
        // The weak key-file parameters, where the command takes them.
        if args.contains(&"init") {
            cmd.args(["--kdf-profile", "fast-insecure-test"]);
        }
        cmd
    }

    fn out(&self, args: &[&str]) -> Output {
        self.cmd(args).output().unwrap()
    }

    /// Runs a command that must succeed and returns what it printed.
    fn ok(&self, args: &[&str]) -> String {
        let out = self.out(args);
        assert!(out.status.success(), "{args:?} failed:\n{}", said(&out));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Runs a command with `--json` that must succeed.
    fn json(&self, args: &[&str]) -> Value {
        let mut all = vec!["--json"];
        all.extend(args);
        let out = self.out(&all);
        assert!(out.status.success(), "{args:?} failed:\n{}", said(&out));
        serde_json::from_slice(&out.stdout).unwrap_or(Value::Null)
    }

    /// Runs a command that must fail: its exit code and everything it printed.
    fn fails(&self, args: &[&str]) -> (i32, String) {
        let out = self.out(args);
        assert!(!out.status.success(), "{args:?} should have failed");
        (out.status.code().unwrap(), said(&out))
    }

    /// Notes `rule`, puts it to the vote of `team` and approves it: in a circle of one
    /// that passes it. Returns the proposal's id.
    fn pass_rule(&self, rule: &str) -> String {
        let candidate = self.json(&["note", rule])["candidate_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let proposal = self.json(&[
            "proposal", "create", &candidate, "--circle", "team", "--yes",
        ])["proposal_id"]
            .as_str()
            .unwrap()
            .to_owned();
        self.ok(&["proposal", "vote", &proposal, "approve", "--yes"]);
        proposal
    }
}

/// Standard output and standard error together.
fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The start of an id, as the commands print it (`sha256:` and twelve characters).
fn short(id: &str) -> &str {
    &id[.."sha256:".len() + 12]
}

const PITCH: &str = "Your team votes on how its AI coding agents behave.";

#[test]
fn help_opens_with_the_sentence_the_readme_opens_with() {
    let tmp = TempDir::new().unwrap();
    let node = Node::bare(tmp.path(), "alice");

    let help = node.ok(&["--help"]);
    assert_eq!(help.lines().next(), Some(PITCH), "{help}");
    // One plain line after it, and no trace of the earlier pitch.
    assert!(help.contains("your team votes on it"), "{help}");
    assert!(!help.contains("learning harness"), "{help}");
    assert!(!help.contains("Your AI learns from you"), "{help}");
    let brief = node.ok(&["-h"]);
    assert_eq!(
        brief.lines().next(),
        Some(PITCH.trim_end_matches('.')),
        "{brief}"
    );

    // The same sentence in the package description and in the README.
    assert_eq!(env!("CARGO_PKG_DESCRIPTION"), PITCH.trim_end_matches('.'));
    let readme =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md"))
            .unwrap();
    assert!(
        readme.contains(PITCH),
        "the README no longer has the sentence"
    );

    // `observe` and `hook` are not in the list, and `demo`, `note` and `keep` are.
    let listed: Vec<&str> = help
        .lines()
        .skip_while(|l| l.trim() != "Commands:")
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    assert!(!listed.contains(&"observe"), "{listed:?}");
    assert!(!listed.contains(&"hook"), "{listed:?}");
    for command in ["setup", "demo", "note", "keep", "circle", "proposal"] {
        assert!(listed.contains(&command), "{command}: {listed:?}");
    }
    // Hidden is not removed: both still run. A hook exits 0 whatever happens.
    node.ok(&["init", "--keystore", "file"]);
    let injected = node.ok(&["observe", "demo"]);
    assert!(injected.contains("Injected"), "{injected}");
    assert!(node.out(&["hook", "stop"]).status.success());
    assert!(node.ok(&["observe", "--help"]).contains("demo"));
}

#[test]
fn init_and_note_point_at_the_steps_the_guide_teaches_and_they_work() {
    let tmp = TempDir::new().unwrap();
    let node = Node::bare(tmp.path(), "alice");

    let init = node.ok(&["init", "--keystore", "file"]);
    assert!(
        init.contains("Initialized a new PeerHarness node."),
        "{init}"
    );
    for step in ["peerharness demo", "peerharness note", "peerharness keep"] {
        assert!(init.contains(step), "{step}: {init}");
    }
    // Not the command that injects synthetic observations for tests.
    assert!(!init.contains("observe"), "{init}");
    // A second init has nothing to point at.
    let again = node.ok(&["init", "--keystore", "file"]);
    assert!(again.contains("Already initialized"), "{again}");
    assert!(!again.contains("Next:"), "{again}");

    let noted = node.ok(&["note", RULE]);
    let id = noted
        .split_whitespace()
        .find(|w| w.starts_with("cand_"))
        .unwrap()
        .trim_end_matches(',')
        .to_owned();
    // `keep` first; `review` for changing or dropping it; no `review --approve`.
    assert!(
        noted.contains(&format!("Next: `peerharness keep {id}`")),
        "{noted}"
    );
    assert!(
        noted.contains(&format!("`peerharness review {id} --edit")),
        "{noted}"
    );
    assert!(noted.contains("--reject"), "{noted}");
    assert!(!noted.contains("--approve"), "{noted}");
    // Noting it again points at the same step.
    let twice = node.ok(&["note", RULE]);
    assert!(twice.contains("Already noted"), "{twice}");
    assert!(
        twice.contains(&format!("`peerharness keep {id}`")),
        "{twice}"
    );

    // The step it names is a command that does what the line says.
    let kept = node.ok(&["keep", &id, "--yes"]);
    assert!(kept.contains(&format!("Kept rule {SKILL}")), "{kept}");
    assert!(node.skills.join(SKILL).join("SKILL.md").is_file());
}

#[test]
fn an_init_that_fails_leaves_the_home_as_it_found_it() {
    let tmp = TempDir::new().unwrap();
    // The key file cannot be written: its passphrase is empty. (No terminal is
    // involved, so nothing is asked on the terminal the tests were started from.)
    let failing = |node: &Node| -> String {
        let out = node
            .cmd(&["init", "--keystore", "file"])
            .env("PEERHARNESS_PASSPHRASE", "")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{}", said(&out));
        let msg = said(&out);
        assert!(msg.contains("cannot create the device key"), "{msg}");
        msg
    };

    // --- A home that did not exist: nothing of it is left, and the node is not
    // "initialized without an identity".
    let fresh = Node::bare(tmp.path(), "alice");
    failing(&fresh);
    assert!(
        !fresh.home.exists(),
        "left behind: {:?}",
        std::fs::read_dir(&fresh.home)
            .map(|d| d.map(|e| e.unwrap().file_name()).collect::<Vec<_>>())
            .unwrap_or_default()
    );
    let (code, msg) = fresh.fails(&["status"]);
    assert_eq!(code, 2, "{msg}");
    assert!(msg.contains("is not initialized"), "{msg}");
    assert!(!msg.contains("no device identity"), "{msg}");

    // --- A directory that was there, with a file of the owner's in it: both stay, and
    // only what the failed run made is gone.
    let used = Node::bare(tmp.path(), "bob");
    std::fs::create_dir_all(&used.home).unwrap();
    std::fs::write(used.home.join("notes.txt"), "mine").unwrap();
    failing(&used);
    let left: Vec<String> = std::fs::read_dir(&used.home)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, ["notes.txt"]);
    assert_eq!(
        std::fs::read_to_string(used.home.join("notes.txt")).unwrap(),
        "mine"
    );

    // --- A config file that was there is not this run's to remove.
    let preset = Node::bare(tmp.path(), "carol");
    std::fs::create_dir_all(&preset.home).unwrap();
    let config = "[node]\nkeystore = \"file\"\nkdf_profile = \"fast-insecure-test\"\n";
    std::fs::write(preset.home.join("config.toml"), config).unwrap();
    failing(&preset);
    assert!(preset.home.join("config.toml").is_file());
    assert!(!preset.home.join("peerharness.db").exists());

    // --- Running it again with a passphrase makes the node, in each of the three.
    for node in [&fresh, &used, &preset] {
        let made = node.json(&["init", "--keystore", "file"]);
        assert_eq!(made["created"], true, "{}", node.name);
        assert_eq!(made["keystore"], "file");
        node.ok(&["status"]);
    }
    assert!(used.home.join("notes.txt").is_file());

    // --- A node that exists is never taken apart by a later init that fails to read
    // its options: the identity is kept.
    let out = fresh
        .cmd(&["init", "--keystore", "file"])
        .env("PEERHARNESS_PASSPHRASE", "")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", said(&out));
    assert!(fresh.home.join("peerharness.db").is_file());
    assert!(fresh.home.join("keys").is_dir());
}

#[test]
fn circle_invite_has_no_option_that_does_nothing() {
    let tmp = TempDir::new().unwrap();
    let alice = Node::new(tmp.path(), "alice");
    let bob = Node::new(tmp.path(), "bob");
    alice.ok(&["circle", "create", "team"]);
    let key = bob.json(&["status"])["device_key"]
        .as_str()
        .unwrap()
        .to_owned();

    let help = alice.ok(&["circle", "invite", "--help"]);
    for gone in ["--role", "--addr", "--ttl-hours", "peerharness-invite-"] {
        assert!(!help.contains(gone), "{gone}: {help}");
    }
    // An option that promised an expiry or a role is refused, not swallowed: nothing
    // is proposed.
    for dead in [
        vec!["--ttl-hours", "1"],
        vec!["--role", "owner"],
        vec!["--addr", "/ip4/203.0.113.9/udp/1/quic-v1"],
    ] {
        let mut args = vec![
            "circle", "invite", &key, "--circle", "team", "--member", "bob", "--yes",
        ];
        args.extend(&dead);
        let (code, msg) = alice.fails(&args);
        assert_eq!(code, 2, "{dead:?}: {msg}");
        assert!(msg.contains("unexpected argument"), "{dead:?}: {msg}");
    }
    assert_eq!(
        alice.json(&["proposal", "list"])["proposals"],
        serde_json::json!([])
    );

    // The file `--out` describes is the file the command writes.
    assert!(help.contains("peerharness-<circle>-events.jsonl"), "{help}");
    let invited = alice.ok(&[
        "circle", "invite", &key, "--circle", "team", "--member", "bob", "--yes",
    ]);
    assert!(invited.contains("The admission passed."), "{invited}");
    let written: Vec<String> = std::fs::read_dir(&alice.cwd)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(written, ["peerharness-team-events.jsonl"]);

    // `circle join --name`: the default is not "the name in the invite".
    let join = bob.ok(&["circle", "join", "--help"]);
    assert!(!join.contains("the name in the invite"), "{join}");
    assert!(join.contains("circle-"), "{join}");
    let file = alice.cwd.join("peerharness-team-events.jsonl");
    let fingerprint = alice.json(&["circle", "members", "--circle", "team"])["root_fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    let joined = bob.json(&[
        "circle",
        "join",
        file.to_str().unwrap(),
        "--expect-fingerprint",
        &fingerprint,
        "--yes",
    ]);
    let local = joined["circle"].as_str().unwrap();
    assert_eq!(local, format!("circle-{}", &fingerprint[..9]));
}

#[test]
fn a_circle_name_that_is_not_on_this_node_is_answered_with_where_the_names_are() {
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path(), "alice");
    node.ok(&["circle", "create", "skunkworks-7"]);

    for args in [
        vec!["circle", "members", "--circle", "team"],
        vec!["rule", "list", "--circle", "team"],
        vec!["rule", "opt-out", "pnpm", "--circle", "team"],
        vec!["circle", "mode", "ask", "--circle", "team"],
    ] {
        let (code, msg) = node.fails(&args);
        assert_eq!(code, 2, "{args:?}: {msg}");
        assert!(
            msg.contains("no circle on this node has that name"),
            "{msg}"
        );
        // Where the names are, and why a joiner's name is not the founder's.
        assert!(msg.contains("`peerharness status`"), "{msg}");
        assert!(msg.contains("--name"), "{msg}");
        // No circle's name is in an error: not the one this node has, and not the one
        // that was asked for.
        assert!(!msg.contains("skunkworks-7"), "{msg}");
        assert!(!msg.contains("\"team\""), "{msg}");
    }
    // The command it names does list them.
    assert!(node.ok(&["status"]).contains("skunkworks-7"));
}

#[test]
fn circle_mode_ask_lists_only_what_waits_and_names_its_proposal() {
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path(), "alice");
    node.ok(&["circle", "create", "team"]);
    // A circle of one: her approval passes the rule, and following installs it.
    node.pass_rule(RULE);
    assert!(node.skills.join(SKILL).join("SKILL.md").is_file());

    // Switching to `ask`: the rule is installed and stays. It waits for nothing.
    let asked = node.ok(&["circle", "mode", "ask", "--circle", "team"]);
    assert!(asked.contains("Your mode in team is now ask."), "{asked}");
    assert!(!asked.contains("waits for your confirmation"), "{asked}");
    assert!(!asked.contains(SKILL), "{asked}");
    assert!(asked.contains("Rules that are installed stay"), "{asked}");
    assert_eq!(
        node.json(&["circle", "mode", "ask", "--circle", "team"])["waiting"],
        serde_json::json!([])
    );
    assert!(node.skills.join(SKILL).join("SKILL.md").is_file());
    let rules = node.ok(&["rule", "list"]);
    assert!(rules.contains("[installed]"), "{rules}");

    // A rule that passes now is not installed: it does wait, and every command that
    // says so names the proposal to confirm, in words.
    let candidate = node.json(&["note", "Keep commits small."])["candidate_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let proposal = node.json(&[
        "proposal", "create", &candidate, "--circle", "team", "--yes",
    ])["proposal_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let voted = node.ok(&["proposal", "vote", &proposal, "approve", "--yes"]);
    let again = node.ok(&["circle", "mode", "ask", "--circle", "team"]);
    let adopt = format!("`peerharness proposal adopt {}`", short(&proposal));
    for text in [&voted, &again] {
        assert!(
            text.contains("rule keep-commits-small is in force and waits for your confirmation"),
            "{text}"
        );
        assert!(text.contains("you chose to be asked"), "{text}");
        assert!(text.contains(&adopt), "{text}");
        // Neither a placeholder nor an internal code.
        assert!(!text.contains("<id>"), "{text}");
        assert!(!text.contains("ask_mode"), "{text}");
        // The installed rule is still not among them.
        assert!(!text.contains(SKILL), "{text}");
    }
    let waiting = node.json(&["circle", "mode", "ask", "--circle", "team"])["waiting"].clone();
    assert_eq!(waiting.as_array().unwrap().len(), 1, "{waiting}");
    assert_eq!(waiting[0]["skill_name"], "keep-commits-small");
    assert_eq!(waiting[0]["proposal_id"], proposal.as_str());
    assert!(!node.skills.join("keep-commits-small").exists());

    // The command the line names installs it, and then nothing waits.
    let adopted = node.ok(&["proposal", "adopt", short(&proposal), "--yes"]);
    assert!(
        adopted.contains("Installed rule keep-commits-small."),
        "{adopted}"
    );
    assert!(
        !adopted.contains("waits for your confirmation"),
        "{adopted}"
    );
    assert!(node
        .skills
        .join("keep-commits-small")
        .join("SKILL.md")
        .is_file());
}

/// An error says what failed once. `daemon` and `sync` used to say "cannot unlock the
/// device key: cannot unlock the device key: ...".
#[test]
fn a_key_that_cannot_be_unlocked_is_said_once() {
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path(), "alice");
    for args in [
        vec!["daemon", "--listen", "/ip4/127.0.0.1/udp/0/quic-v1"],
        vec!["sync", "/ip4/127.0.0.1/udp/9/quic-v1"],
    ] {
        // An empty passphrase: refused without a prompt on any terminal.
        let out = node
            .cmd(&args)
            .env("PEERHARNESS_PASSPHRASE", "")
            .output()
            .unwrap();
        let msg = said(&out);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {msg}");
        assert_eq!(
            msg.matches("cannot unlock the device key").count(),
            1,
            "{args:?}: {msg}"
        );
        assert!(msg.contains("the passphrase must not be empty"), "{msg}");
    }
    assert!(!node.home.join("daemon.json").exists());
}

/// Kills the daemon when the test ends, however it ends.
struct Daemon(std::process::Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Where no notification can be shown, `--notify` is refused with what to do instead,
/// and the same command without it starts the daemon.
#[cfg(not(target_os = "macos"))]
#[test]
fn daemon_notify_says_that_the_daemon_runs_without_it() {
    use std::time::{Duration, Instant};

    const LISTEN: &str = "/ip4/127.0.0.1/udp/0/quic-v1";
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path(), "alice");

    let (code, msg) = node.fails(&["daemon", "--listen", LISTEN, "--notify"]);
    assert_eq!(code, 2, "{msg}");
    assert!(msg.contains("--notify needs macOS"), "{msg}");
    assert!(msg.contains("The daemon runs without it"), "{msg}");
    assert!(msg.contains("Nothing was started"), "{msg}");
    assert!(!node.home.join("daemon.json").exists());

    // As the message says: the same command without --notify.
    let child = node
        .cmd(&["daemon", "--listen", LISTEN])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = u64::from(child.id());
    let mut daemon = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let info: Option<Value> = std::fs::read(node.home.join("daemon.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        if info.is_some_and(|i| i["pid"].as_u64() == Some(pid)) {
            break;
        }
        assert!(Instant::now() < deadline, "the daemon did not start");
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "the daemon exited early"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(node.json(&["status"])["daemon"]["pid"].as_u64(), Some(pid));
}

/// The tests run a debug build, which obeys the stand-ins for the window, the
/// notification and Claude Code. `doctor` and `status` say so, and nothing is refused.
#[cfg(debug_assertions)]
#[test]
fn a_debug_build_says_that_it_is_one_and_refuses_nothing() {
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path(), "alice");

    let out = node.out(&["doctor"]);
    let doctor = said(&out);
    assert!(out.status.success(), "a line, never a refusal: {doctor}");
    let line = doctor
        .lines()
        .find(|l| l.contains(" build "))
        .unwrap_or_else(|| panic!("no line about the build: {doctor}"));
    assert!(line.starts_with("[warn]"), "{line}");
    assert!(line.contains("debug build"), "{line}");
    assert!(line.contains("PEERHARNESS_TEST_"), "{line}");
    assert!(line.contains("not for daily use"), "{line}");
    assert_eq!(doctor.lines().filter(|l| l.contains(" build ")).count(), 1);
    let checks = node.json(&["doctor"]);
    assert_eq!(checks["ok"], true, "{checks}");
    let build = checks["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["check"] == "build")
        .unwrap();
    assert_eq!(build["level"], "warn");

    let status = node.ok(&["status"]);
    assert!(
        status.contains("debug: for development and tests, not for daily use"),
        "{status}"
    );
    assert_eq!(node.json(&["status"])["debug_build"], true);

    // It holds without a node as well: `doctor` says it before it looks for one.
    let nowhere = Node::bare(tmp.path(), "nobody");
    let out = nowhere.out(&["doctor"]);
    assert!(said(&out).contains("debug build"), "{}", said(&out));

    // And every command still runs: the build is named, not refused.
    node.ok(&["note", RULE]);
    node.ok(&["circle", "create", "team"]);
}

/// `demo/two-peers.sh` with `PEERHARNESS_BIN`: two nodes, two processes, QUIC on
/// loopback, with the binary it was given and without building one.
#[cfg(unix)]
#[test]
fn the_two_peer_demo_runs_with_an_installed_binary_and_builds_nothing() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo/two-peers.sh");
    // A `cargo` that records that it was called, first on PATH.
    let bin = tmp.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let called = tmp.path().join("cargo-was-called");
    std::fs::write(
        bin.join("cargo"),
        format!("#!/bin/sh\n: > '{}'\nexit 1\n", called.display()),
    )
    .unwrap();
    std::fs::set_permissions(bin.join("cargo"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = std::env::join_paths(
        std::iter::once(bin.clone())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let work = tmp.path().join("work");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&home).unwrap();

    let run = |binary: &std::ffi::OsStr| -> Output {
        Command::new("bash")
            .arg(&script)
            // From somewhere that is not the repository.
            .current_dir(&work)
            .env("PEERHARNESS_BIN", binary)
            .env("PATH", &path)
            .env("TMPDIR", &work)
            .env("HOME", &home)
            .env(
                "PEERHARNESS_CLAUDE_SETTINGS",
                tmp.path().join("settings.json"),
            )
            .env_remove("PEERHARNESS_HOME")
            .env_remove("CLAUDECODE")
            .env_remove("PEERHARNESS_AGENT_SESSION")
            .env_remove("PEERHARNESS_TEST_WINDOW_BIN")
            .env_remove("PEERHARNESS_TEST_NOTIFY_BIN")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };

    let binary = assert_cmd::cargo::cargo_bin("peerharness");
    let out = run(binary.as_os_str());
    let text = said(&out);
    assert!(out.status.success(), "{text}");
    assert!(!called.exists(), "cargo was run:\n{text}");
    assert!(text.contains(&format!("at {}", binary.display())), "{text}");
    // The whole story: joined over QUIC, voted, installed on both, outsider refused.
    assert!(text.contains("Joined team as bob."), "{text}");
    assert!(text.contains("passed: 2 of 2 approved"), "{text}");
    assert!(
        text.contains(&format!("alice's agent: {SKILL}    bob's agent: {SKILL}")),
        "{text}"
    );
    assert!(text.contains("mallory: error:"), "{text}");
    assert!(text.contains("No server was involved."), "{text}");
    // Alice corrects her agent, not the other way round.
    assert!(text.contains("Alice corrected her agent"), "{text}");
    // Nothing is left behind, in the temporary folder or in the home it was given.
    assert_eq!(std::fs::read_dir(&work).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(&home).unwrap().count(), 0);

    // A binary that is not there is said so, and still nothing is built.
    let out = run(std::ffi::OsStr::new("/nonexistent/peerharness"));
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(
        said(&out).contains("PEERHARNESS_BIN names no program"),
        "{}",
        said(&out)
    );
    assert!(!called.exists());
}
