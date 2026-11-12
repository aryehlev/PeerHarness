//! Steps that ran inside a coding agent's session without the owner, and no longer do,
//! through the real binary.
//!
//! * `rule opt-in` undoes the owner's refusal of a rule and puts its text back into
//!   their agent. It is a consent step in the owner's terminal, with a preview of the
//!   rule's exact text and of where it goes. It has no window. `rule opt-out` stays
//!   immediate and unasked, in a session too.
//! * `export --local` writes circle records and the owner's notes out: refused.
//! * `init` with the plaintext keystore: refused, because its warning has to reach a
//!   person. A plain `init` is still allowed.
//! * A note written inside a session is an agent's note whatever flags it was given:
//!   labelled so, and counted against the cap on waiting agent notes.
//! * `inbox` and `review` inside a session do not mark a note as shown to its owner,
//!   so the notice at the end of a turn still tells the owner that it waits.
//! * `proposal show` inside a session does not print the text of a rule that is not
//!   installed on the machine.
//! * The cap on an agent's waiting notes holds for notes written at the same moment,
//!   and `observe import` and `observe demo`, which store text as the owner's own
//!   prompts, are refused.
//! * The `join_circle` tool of `peerharness mcp` takes a peer id or an address, never a
//!   path, so an agent cannot make a join read a file it wrote. `circle join` itself
//!   holds to that inside a session: what reads as a peer id or as an address is never
//!   read as a file there, whatever is on disk under that name.
//! * Without a terminal a consent step does not tell whoever reads the refusal to pass
//!   `--yes`.
//!
//! No test opens a real window: every command gets `PEERHARNESS_TEST_WINDOW_BIN`, a
//! script that records the exact text it was asked to show and gives the answer the
//! test wrote down for it. Only debug builds read that variable, so the file is
//! compiled for debug builds only.
#![cfg(all(unix, debug_assertions))]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};

use serde_json::{json, Value};
use tempfile::TempDir;

const RULE: &str = "Run the tests before you say a task is done.";
const SKILL: &str = "run-tests-before-say-task-done";
const PASSPHRASE: &str = "test-passphrase-not-real";

/// Who is at the keyboard.
#[derive(Clone, Copy, PartialEq)]
enum By {
    /// The person, in their own terminal. (No terminal is attached in a test: a step
    /// that asks is answered with `--yes`, as in a script the person wrote.)
    Person,
    /// A coding agent's shell: `CLAUDECODE` is set, as Claude Code does.
    Agent,
    /// A session that another wrapper marked, with `PEERHARNESS_AGENT_SESSION`.
    Marked,
}

struct Node {
    name: &'static str,
    home: PathBuf,
    skills: PathBuf,
    settings: PathBuf,
    cwd: PathBuf,
    fake_home: PathBuf,
    /// The stand-in window: the script, the answer it gives and what it was shown.
    window: PathBuf,
    answer: PathBuf,
    saw: PathBuf,
    /// Stands in for a desktop notification. Nothing here starts a daemon that would
    /// show one; the variable is set all the same, as for every MCP server in a test.
    notifier: PathBuf,
}

impl Node {
    /// A node's directories and its stand-in window. Nothing is initialized yet.
    fn bare_dirs(root: &Path, name: &'static str) -> Self {
        let dir = root.join(name);
        let node = Self {
            name,
            home: dir.join("home"),
            skills: dir.join("skills"),
            settings: dir.join("claude-settings.json"),
            cwd: dir.join("project"),
            fake_home: dir.join("fakehome"),
            window: dir.join("window.sh"),
            answer: dir.join("answer"),
            saw: dir.join("saw"),
            notifier: dir.join("notifier.sh"),
        };
        std::fs::create_dir_all(&node.cwd).unwrap();
        std::fs::create_dir_all(&node.fake_home).unwrap();
        let script = format!(
            "#!/bin/sh\ncat >> '{saw}'\nprintf '\\n--shown--\\n' >> '{saw}'\ncat '{answer}'\n",
            saw = node.saw.display(),
            answer = node.answer.display(),
        );
        std::fs::write(&node.window, script).unwrap();
        std::fs::set_permissions(&node.window, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&node.notifier, "#!/bin/sh\ncat > /dev/null\n").unwrap();
        std::fs::set_permissions(&node.notifier, std::fs::Permissions::from_mode(0o755)).unwrap();
        node.answers("declined");
        node
    }

    fn new(root: &Path, name: &'static str) -> Self {
        let node = Self::bare_dirs(root, name);
        node.run(&[
            "init",
            "--keystore",
            "file",
            "--kdf-profile",
            "fast-insecure-test",
        ]);
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

    /// The environment of every process of this node. The suite itself may be run by a
    /// coding agent, so the marks of a session are taken out and put back only for
    /// `By::Agent` and `By::Marked`.
    fn env(&self, cmd: &mut std::process::Command, by: By) {
        cmd.current_dir(&self.cwd)
            .env("PEERHARNESS_HOME", &self.home)
            .env("PEERHARNESS_PASSPHRASE", PASSPHRASE)
            .env("PEERHARNESS_CLAUDE_SKILLS_DIR", &self.skills)
            .env("PEERHARNESS_CLAUDE_SETTINGS", &self.settings)
            // Never a real window, on any machine these tests run on.
            .env("PEERHARNESS_TEST_WINDOW_BIN", &self.window)
            .env("PEERHARNESS_TEST_NOTIFY_BIN", &self.notifier)
            .env("HOME", &self.fake_home)
            .env("USER", self.name)
            .env_remove("CLAUDECODE")
            .env_remove("PEERHARNESS_AGENT_SESSION")
            .env_remove("CODEX_CI")
            .env_remove("CODEX_TOOL_CALL_ID")
            .env_remove("CODEX_THREAD_ID")
            .env_remove("OPENCODE")
            .env_remove("PI_CODING_AGENT")
            .env_remove("AI_AGENT")
            .env_remove("ANTIGRAVITY_AGENT")
            .env_remove("DSH_SHELL")
            .stdin(Stdio::null());
        match by {
            By::Person => {}
            By::Agent => {
                cmd.env("CLAUDECODE", "1");
            }
            By::Marked => {
                cmd.env("PEERHARNESS_AGENT_SESSION", "1");
            }
        }
    }

    /// Runs a command with `--json`: exit code, the JSON on standard output and
    /// everything it printed.
    fn out(&self, by: By, args: &[&str]) -> (i32, Value, String) {
        let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("peerharness"));
        self.env(&mut cmd, by);
        let out = cmd.arg("--json").args(args).output().unwrap();
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
        assert_eq!(code, 0, "{} {args:?} failed: {printed}", self.name);
        json
    }

    /// A command that is refused (exit 3): its message.
    fn refused(&self, by: By, args: &[&str]) -> String {
        let (code, json, printed) = self.out(by, args);
        assert_eq!(code, 3, "{args:?} should be refused: {printed}");
        json["error"]["message"].as_str().unwrap_or("").to_owned()
    }

    fn skill_file(&self, name: &str) -> PathBuf {
        self.skills.join(name).join("SKILL.md")
    }

    fn status(&self, key: &str) -> String {
        self.run(&["status"])[key].as_str().unwrap().to_owned()
    }

    /// The owner allows every step that can be asked in a window.
    fn windows_on(&self) {
        let on = self.run(&["watch", "claude", "--install", "--dialogs", "--yes"]);
        assert_eq!(on["windows"], true);
        assert_eq!(on["circle_windows"], true);
        assert_eq!(on["own_windows"], true);
    }

    fn candidates(&self) -> Vec<Value> {
        self.run(&["inbox", "--limit", "200"])["candidates"]
            .as_array()
            .unwrap()
            .clone()
    }

    fn serve(&self) -> Client {
        let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("peerharness"));
        // The server runs without the mark of a session. It sets the mark itself.
        self.env(&mut cmd, By::Person);
        let mut child = cmd
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Client {
            child,
            input: Some(input),
            output,
            next: 0,
        }
    }
}

/// A client of `peerharness mcp`, as in `mcp_server.rs`.
struct Client {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    next: u64,
}

impl Client {
    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let id = self.next;
        let message = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let input = self.input.as_mut().unwrap();
        writeln!(input, "{message}").unwrap();
        input.flush().unwrap();
        let mut line = String::new();
        assert!(
            self.output.read_line(&mut line).unwrap() > 0,
            "the server closed its output"
        );
        let reply: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(reply["id"], id, "{reply}");
        reply
    }

    fn handshake(&mut self) {
        let hello = self.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "0" },
            }),
        );
        assert_eq!(hello["result"]["serverInfo"]["name"], "peerharness");
    }

    /// Calls a tool that must fail, and returns what it said.
    fn fails(&mut self, tool: &str, arguments: Value) -> String {
        let reply = self.request(
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        );
        let result = &reply["result"];
        assert!(result.is_object(), "{tool}: {reply}");
        let text = result["content"][0]["text"].as_str().unwrap().to_owned();
        assert_eq!(result["isError"], true, "{tool} should have failed: {text}");
        text
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        drop(self.input.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A node that founded `team` alone and has one rule in force and installed.
fn node_with_a_rule(root: &Path) -> Node {
    let node = Node::new(root, "alice");
    node.run(&["circle", "create", "team"]);
    let cand = node.run(&["note", RULE])["candidate_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let adopt = node.run(&["proposal", "create", &cand, "--circle", "team", "--yes"])
        ["proposal_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let voted = node.run(&["proposal", "vote", &adopt, "approve", "--yes"]);
    assert_eq!(voted["passed"], true);
    assert!(node.skill_file(SKILL).is_file());
    node
}

fn opted_out(node: &Node) -> bool {
    node.run(&["rule", "list"])["rules"][0]["opted_out"] == true
}

/// consent-4. The owner refused a rule. Their agent cannot take the refusal back: with
/// or without `--yes`, under either mark of a session, and with windows on (there is no
/// window for this step).
#[test]
fn opting_back_into_a_rule_is_the_owners_step_and_shows_the_rule() {
    let tmp = TempDir::new().unwrap();
    let node = node_with_a_rule(tmp.path());
    let opt_in = ["rule", "opt-in", SKILL, "--circle", "team"];
    let opt_in_yes = ["rule", "opt-in", SKILL, "--circle", "team", "--yes"];

    // The owner opts out, in their terminal. Nothing is asked.
    let out = node.run(&["rule", "opt-out", SKILL, "--circle", "team"]);
    assert_eq!(out["removed"], json!([SKILL]));
    assert!(!node.skill_file(SKILL).exists());

    // --- Inside a session: refused, and nothing comes back.
    for (by, args) in [
        (By::Agent, &opt_in[..]),
        (By::Agent, &opt_in_yes[..]),
        (By::Marked, &opt_in[..]),
        (By::Marked, &opt_in_yes[..]),
    ] {
        let msg = node.refused(by, args);
        assert!(msg.contains("your own terminal"), "{args:?}: {msg}");
        assert!(!node.skill_file(SKILL).exists(), "{args:?}");
        assert!(opted_out(&node), "{args:?}");
    }
    // A name no rule has is refused the same way: the step is the owner's, whatever it
    // would come to.
    node.refused(
        By::Agent,
        &["rule", "opt-in", "no-such-rule", "--circle", "team"],
    );

    // --- With windows on, and a window that would say yes to anything: still refused,
    // and no window was opened. This step is not one of the seven.
    node.windows_on();
    node.answers("proceed");
    for args in [&opt_in[..], &opt_in_yes[..]] {
        let msg = node.refused(By::Agent, args);
        assert!(msg.contains("your own terminal"), "{args:?}: {msg}");
    }
    assert!(node.shown().is_empty(), "no window: {:?}", node.shown());
    assert!(!node.skill_file(SKILL).exists());
    assert!(opted_out(&node));

    // --- The opt-out itself never waits for anyone, in a session either.
    let (code, json, printed) =
        node.out(By::Agent, &["rule", "opt-out", SKILL, "--circle", "team"]);
    assert_eq!(code, 0, "{printed}");
    assert_eq!(json["opted_out"], true);

    // --- The owner, without a terminal and without --yes: shown what would happen,
    // and nothing happens.
    let (code, _, printed) = node.out(By::Person, &opt_in);
    assert_eq!(code, 3, "{printed}");
    // The rule's exact text, and where it would be installed.
    assert!(printed.contains(RULE), "{printed}");
    assert!(
        printed.contains("name: run-tests-before-say-task-done"),
        "{printed}"
    );
    let dir = node.skills.join(SKILL);
    assert!(printed.contains(dir.to_str().unwrap()), "{printed}");
    assert!(printed.contains("no terminal is attached"), "{printed}");
    assert!(!node.skill_file(SKILL).exists());
    assert!(opted_out(&node));

    // --- The owner confirms: the rule is back.
    let back = node.run(&opt_in_yes);
    assert_eq!(back["installed"], json!([SKILL]));
    assert!(node.skill_file(SKILL).is_file());
    assert!(!opted_out(&node));

    // --- In mode `ask` the same confirmation is the one an install needs: the owner
    // read the text and said yes once.
    node.run(&["circle", "mode", "ask", "--circle", "team"]);
    node.run(&["rule", "opt-out", SKILL, "--circle", "team"]);
    assert!(!node.skill_file(SKILL).exists());
    let back = node.run(&opt_in_yes);
    assert_eq!(back["installed"], json!([SKILL]));
    assert!(node.skill_file(SKILL).is_file());

    // --- An opt-out of a name no rule has can be taken back too. Nothing is installed,
    // and the preview says so.
    node.run(&["rule", "opt-out", "no-such-rule", "--circle", "team"]);
    let (code, _, printed) = node.out(
        By::Person,
        &[
            "rule",
            "opt-in",
            "no-such-rule",
            "--circle",
            "team",
            "--yes",
        ],
    );
    assert_eq!(code, 0, "{printed}");
    assert!(printed.contains("nothing is installed"), "{printed}");
    assert!(node.shown().is_empty());
}

/// consent-11, first half. "Inside a session no command writes a circle's records to a
/// file": `export --local` holds them, and the owner's notes.
#[test]
fn the_local_export_is_refused_inside_a_session() {
    let tmp = TempDir::new().unwrap();
    let node = node_with_a_rule(tmp.path());
    let file = tmp.path().join("export.json");
    let to_file = ["export", "--local", "--out", file.to_str().unwrap()];

    for by in [By::Agent, By::Marked] {
        // To a file, and to standard output, which inside a session is the session's.
        let msg = node.refused(by, &to_file);
        assert!(msg.contains("your own terminal"), "{msg}");
        let (code, json, printed) = node.out(by, &["export", "--local"]);
        assert_eq!(code, 3, "{printed}");
        assert!(json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("your own terminal"));
        // Nothing of the node's data was printed with the refusal.
        assert!(!printed.contains(RULE), "{printed}");
        assert!(!printed.contains("\"events\""), "{printed}");
    }
    assert!(!file.exists(), "no file was written");

    // The person's export is what it was.
    let written = node.run(&to_file);
    assert_eq!(written["written"], file.to_str().unwrap());
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains(RULE));
    assert!(node.run(&["export", "--local"]).to_string().contains(RULE));
}

/// consent-11, second half. "No silent plaintext keys": the warning of the plaintext
/// keystore has to reach a person, and inside a session it would reach the agent.
#[test]
fn the_plaintext_keystore_is_refused_inside_a_session_and_a_plain_init_is_not() {
    let tmp = TempDir::new().unwrap();
    let plaintext = [
        "init",
        "--keystore",
        "insecure-dev",
        "--insecure-dev-keystore",
    ];

    // --- A fresh home: refused before anything is created.
    let node = Node::bare_dirs(tmp.path(), "alice");
    for by in [By::Agent, By::Marked] {
        let msg = node.refused(by, &plaintext);
        assert!(msg.contains("plaintext"), "{msg}");
        assert!(msg.contains("your own terminal"), "{msg}");
        assert!(!node.home.exists(), "nothing was created");
    }
    // The short form of the same request.
    node.refused(By::Agent, &["init", "--insecure-dev-keystore"]);
    assert!(!node.home.exists());

    // --- A config file that names the plaintext keystore asks for the same thing.
    let preset = Node::bare_dirs(tmp.path(), "bob");
    std::fs::create_dir_all(&preset.home).unwrap();
    std::fs::write(
        preset.home.join("config.toml"),
        "[node]\nkeystore = \"insecure-dev\"\n",
    )
    .unwrap();
    let msg = preset.refused(By::Agent, &["init"]);
    assert!(msg.contains("plaintext"), "{msg}");
    assert!(!preset.home.join("keys").exists(), "no key was written");
    assert!(!preset.home.join("peerharness.db").exists());
    // For the person the file does not stand in for the flag (ADR-051): it used to,
    // and a file put into a home made a plain `init` write a plaintext key.
    let (code, json, printed) = preset.out(By::Person, &["init"]);
    assert_eq!(code, 2, "{printed}");
    let msg = json["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("--insecure-dev-keystore"), "{printed}");
    assert!(!preset.home.join("keys").exists(), "no key was written");
    assert!(!preset.home.join("peerharness.db").exists());
    let (code, json, printed) = preset.out(By::Person, &["init", "--insecure-dev-keystore"]);
    assert_eq!(code, 0, "{printed}");
    assert_eq!(json["keystore"], "insecure-dev");
    assert!(printed.contains("PLAINTEXT"), "{printed}");

    // --- A plain init is allowed inside a session: the README's setup prompt has the
    // agent run it. The keys go to an encrypted file here, with the parameters a key
    // file has by default.
    let (code, json, printed) = node.out(By::Agent, &["init", "--keystore", "file"]);
    assert_eq!(code, 0, "{printed}");
    assert_eq!(json["created"], true);
    assert_eq!(json["keystore"], "file");
    assert!(!node.home.join("keys").join("device.insecure-key").exists());
    assert_eq!(
        kdf_of(&node.home.join("keys").join("device.key")),
        (65536, 3)
    );
    assert!(!printed.contains("warning"), "{printed}");

    // --- And the person may still choose the plaintext keystore, with its warning.
    let dev = Node::bare_dirs(tmp.path(), "carol");
    let (code, json, printed) = dev.out(By::Person, &plaintext);
    assert_eq!(code, 0, "{printed}");
    assert_eq!(json["keystore"], "insecure-dev");
    assert!(printed.contains("PLAINTEXT"), "{printed}");

    // --- The warning is not only `init`'s (ADR-051). It used to be a line in the log
    // from then on, which nobody sees: a command that uses the key says it where a
    // person reads, and `status`, which uses none, says it too.
    let (code, _, printed) = dev.out(
        By::Person,
        &["circle", "create", "team", "--member", "carol"],
    );
    assert_eq!(code, 0, "{printed}");
    assert!(
        printed.contains("warning: this node's private keys are stored in PLAINTEXT"),
        "{printed}"
    );
    let (_, status, printed) = dev.out(By::Person, &["status"]);
    assert!(
        status["keystore_warning"]
            .as_str()
            .unwrap()
            .contains("PLAINTEXT"),
        "{printed}"
    );
    // A command that uses no key says nothing.
    let (code, _, printed) = dev.out(By::Person, &["inbox"]);
    assert_eq!(code, 0, "{printed}");
    assert!(!printed.contains("PLAINTEXT"), "{printed}");
}

/// The memory and time parameters a key file was encrypted with.
fn kdf_of(key_file: &Path) -> (u64, u64) {
    let file: Value = serde_json::from_slice(&std::fs::read(key_file).unwrap()).unwrap();
    (file["m_kib"].as_u64().unwrap(), file["t"].as_u64().unwrap())
}

/// The weak parameters for key files are the tests' (ADR-051). Choosing them is the
/// owner's decision like the plaintext keystore: a session is refused, whether a flag
/// asks or a config file that was already there, and a person is warned in both cases
/// and by every later command that writes or opens a key file under that profile. A
/// config file used to turn the profile on with no word from `init`, and a session
/// could pass the flag.
#[test]
fn the_weak_key_file_profile_is_refused_inside_a_session_and_never_silent() {
    let tmp = TempDir::new().unwrap();
    let weak = [
        "init",
        "--keystore",
        "file",
        "--kdf-profile",
        "fast-insecure-test",
    ];
    let preset_config = "[node]\nkeystore = \"file\"\nkdf_profile = \"fast-insecure-test\"\n";

    // --- The flag, inside a session: refused before anything is created.
    let node = Node::bare_dirs(tmp.path(), "alice");
    for by in [By::Agent, By::Marked] {
        let msg = node.refused(by, &weak);
        assert!(msg.contains("fast-insecure-test"), "{msg}");
        assert!(msg.contains("your own terminal"), "{msg}");
        assert!(!node.home.exists(), "nothing was created");
    }

    // --- A config file that names the profile, inside a session: the same.
    let preset = Node::bare_dirs(tmp.path(), "bob");
    std::fs::create_dir_all(&preset.home).unwrap();
    std::fs::write(preset.home.join("config.toml"), preset_config).unwrap();
    let msg = preset.refused(By::Agent, &["init"]);
    assert!(msg.contains("fast-insecure-test"), "{msg}");
    assert!(!preset.home.join("keys").exists(), "no key was written");
    assert!(!preset.home.join("peerharness.db").exists());

    // --- The person, with that config file and no flag: the node is made, and the
    // warning that the flag always had is printed. It was not.
    let (code, json, printed) = preset.out(By::Person, &["init"]);
    assert_eq!(code, 0, "{printed}");
    assert_eq!(json["created"], true);
    assert_eq!(
        kdf_of(&preset.home.join("keys").join("device.key")),
        (64, 1)
    );
    assert!(
        printed.contains("warning: kdf profile fast-insecure-test"),
        "{printed}"
    );

    // --- A node made with the default profile, whose config file is changed
    // afterwards. The circle's root key is then written with the weak parameters: the
    // command that writes it says so, and so does `status`.
    let late = Node::bare_dirs(tmp.path(), "carol");
    let (code, _, printed) = late.out(By::Person, &["init", "--keystore", "file"]);
    assert_eq!(code, 0, "{printed}");
    assert!(!printed.contains("warning"), "{printed}");
    let (_, status, _) = late.out(By::Person, &["status"]);
    assert_eq!(status["keystore_warning"], Value::Null);
    let config = late.home.join("config.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(text.contains("[node]\n"), "{text}");
    std::fs::write(
        &config,
        text.replace("[node]\n", "[node]\nkdf_profile = \"fast-insecure-test\"\n"),
    )
    .unwrap();
    let (code, _, printed) = late.out(
        By::Person,
        &["circle", "create", "team", "--member", "carol"],
    );
    assert_eq!(code, 0, "{printed}");
    assert!(
        printed.contains("warning: this node writes its key files with the test profile"),
        "{printed}"
    );
    let (_, status, printed) = late.out(By::Person, &["status"]);
    assert!(
        status["keystore_warning"]
            .as_str()
            .unwrap()
            .contains("fast-insecure-test"),
        "{printed}"
    );
}

/// consent-12. The inbox label tells the owner which rules their agent wrote. Inside a
/// session it does not depend on the agent passing `--from-agent`, and neither does the
/// cap on waiting agent notes.
#[test]
fn a_note_written_inside_a_session_is_an_agents_note() {
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path(), "alice");

    // Without the flag, under either mark of a session.
    let (code, noted, printed) = node.out(
        By::Agent,
        &["note", "Prefer early returns over nested conditionals."],
    );
    assert_eq!(code, 0, "{printed}");
    assert_eq!(noted["origin"], "reported by your agent");
    let (code, noted, _) = node.out(By::Marked, &["note", "Never edit generated files by hand."]);
    assert_eq!(code, 0);
    assert_eq!(noted["origin"], "reported by your agent");
    let inbox = node.candidates();
    assert_eq!(inbox.len(), 2);
    assert!(
        inbox
            .iter()
            .all(|c| c["origin"] == "reported by your agent"),
        "{inbox:?}"
    );

    // The cap: 20 waiting agent notes, with or without the flag, and then no more.
    for i in 2..20 {
        let text = format!("Rule number {i} for this project.");
        let (code, _, printed) = node.out(By::Agent, &["note", &text]);
        assert_eq!(code, 0, "note {i}: {printed}");
    }
    for args in [
        &["note", "One more rule."][..],
        &["note", "--from-agent", "One more rule."][..],
    ] {
        let msg = node.refused(By::Agent, args);
        assert!(msg.contains("already wait for review"), "{msg}");
    }
    assert_eq!(node.candidates().len(), 20);

    // The person's own note is theirs: labelled so, and not capped by the agent's.
    let own = node.run(&["note", "One more rule."]);
    assert_eq!(own["origin"], "written down");
    assert_eq!(node.candidates().len(), 21);
}

/// The cap counted the waiting notes and then inserted, as two steps: notes written at
/// the same moment each counted fewer than twenty, and up to 26 of 60 were kept in the
/// audit's runs (ADR-051). The count and the insert are one write transaction now.
#[test]
fn the_cap_holds_for_notes_written_at_the_same_moment() {
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path(), "alice");
    let codes: Vec<i32> = std::thread::scope(|s| {
        let writers: Vec<_> = (0..40)
            .map(|i| {
                let node = &node;
                s.spawn(move || {
                    let text = format!("Parallel rule {i}: always pass flag{i} to the build.");
                    node.out(By::Agent, &["note", &text]).0
                })
            })
            .collect();
        writers.into_iter().map(|w| w.join().unwrap()).collect()
    });
    let kept = codes.iter().filter(|c| **c == 0).count();
    let refused = codes.iter().filter(|c| **c == 3).count();
    assert_eq!((kept, refused), (20, 20), "{codes:?}");
    assert_eq!(node.candidates().len(), 20);
}

/// `observe import` stores lines as if the owner had typed them to their agent, and the
/// detector makes candidates from them that carry the label of the owner's own prompts
/// and are not counted by the cap. Inside a session an agent wrote 30 such candidates
/// past a full cap (ADR-051). Both `observe` commands are the person's now.
#[test]
fn observations_are_not_added_by_hand_inside_a_session() {
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path(), "alice");
    let file = tmp.path().join("made-up.jsonl");
    let mut lines = String::new();
    for i in 0..3 {
        for session in ["s1", "s2"] {
            lines.push_str(&format!(
                r#"{{"kind":"user_prompt","repo":"myrepo","session":"{session}","text":"No, use tool{i}x, not tool{i}y, for this repo."}}"#
            ));
            lines.push('\n');
        }
    }
    std::fs::write(&file, lines).unwrap();
    let file = file.to_str().unwrap();

    for by in [By::Agent, By::Marked] {
        for args in [&["observe", "import", file][..], &["observe", "demo"][..]] {
            let msg = node.refused(by, args);
            assert!(msg.contains("inside a coding agent's session"), "{msg}");
        }
    }
    assert_eq!(node.run(&["status"])["candidates"], json!({}));
    assert!(node.candidates().is_empty());

    // In the person's own terminal both still work.
    let imported = node.run(&["observe", "import", file]);
    assert_eq!(imported["observations_stored"], 6, "{imported}");
    assert_eq!(node.candidates().len(), 3);
    node.run(&["observe", "demo"]);
    assert_eq!(node.candidates().len(), 4);
}

/// `proposal show` printed the text of a rule that had not passed into the session
/// that ran it, while the security model says a rule's text reaches an agent only
/// after the rule passed (ADR-051). Inside a session the text is printed only where
/// exactly that text is installed on the machine already.
#[test]
fn a_rule_that_is_not_installed_is_not_printed_into_a_session() {
    let tmp = TempDir::new().unwrap();
    // One rule in force and installed, in a circle of one.
    let alice = node_with_a_rule(tmp.path());
    let installed = alice.run(&["proposal", "list"])["proposals"][0]["proposal_id"]
        .as_str()
        .unwrap()
        .to_owned();
    // A second member is admitted, so the next rule needs two approvals and stays open.
    let bob = Node::new(tmp.path(), "bob");
    let bob_key = bob.run(&["status"])["device_key"]
        .as_str()
        .unwrap()
        .to_owned();
    alice.run(&[
        "circle", "invite", &bob_key, "--circle", "team", "--member", "bob", "--yes",
    ]);
    const OPEN_RULE: &str = "When a file named NOTES exists, read it before anything else.";
    let cand = alice.run(&["note", OPEN_RULE])["candidate_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let open = alice.run(&["proposal", "create", &cand, "--circle", "team", "--yes"])
        ["proposal_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let show = |by: By, id: &str| -> String {
        let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("peerharness"));
        alice.env(&mut cmd, by);
        let out = cmd.args(["proposal", "show", id]).output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    // The body of the skill that a rule becomes: its heading, then the sentence.
    let body = format!("| # Rule\n      | \n      | {OPEN_RULE}");

    // The open rule: its owner reads the text in their terminal, a session does not.
    let read = show(By::Person, &open);
    assert!(read.contains("standing           open"), "{read}");
    assert!(read.contains(&body), "{read}");
    for by in [By::Agent, By::Marked] {
        let read = show(by, &open);
        assert!(read.contains("standing           open"), "{read}");
        assert!(read.contains("  rule text ("), "{read}");
        assert!(
            read.contains("not printed inside a coding agent's session"),
            "{read}"
        );
        assert!(!read.contains("| # Rule"), "{read}");
        assert!(!read.contains("| name:"), "{read}");
        // The title is the rule's sentence and is listed in the inbox as well: it is
        // the text of the skill that is held back.
        assert_eq!(read.matches(OPEN_RULE).count(), 1, "{read}");
    }

    // The rule that is installed for the agent is in its context anyway.
    let read = show(By::Agent, &installed);
    assert!(
        read.contains(&format!("| # Rule\n      | \n      | {RULE}")),
        "{read}"
    );
    assert!(!read.contains("not printed inside"), "{read}");
}

/// What Claude Code shows its user at the end of a turn: the output of the Stop hook,
/// run inside the session as Claude Code runs it.
fn stop_notice(node: &Node) -> String {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("peerharness"));
    node.env(&mut cmd, By::Agent);
    let mut child = cmd
        .args(["hook", "stop"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            br#"{"hook_event_name":"Stop","session_id":"s1","cwd":"/nowhere","transcript_path":"/nowhere/t"}"#,
        )
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap()
}

/// A note that was shown to its owner stops being announced at the end of a turn.
/// `inbox` and `review` marked it as shown for whoever ran them, so an agent that
/// wrote a note and then read the inbox kept its owner from ever being told
/// (ADR-051). Inside a session nothing is marked: the reader is the agent.
#[test]
fn a_session_that_reads_the_inbox_has_shown_the_owner_nothing() {
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path(), "alice");
    let (code, noted, printed) = node.out(
        By::Agent,
        &["note", "Never force-push to main without asking first."],
    );
    assert_eq!(code, 0, "{printed}");
    let id = noted["candidate_id"].as_str().unwrap().to_owned();

    // The agent reads the inbox and the note, under either mark of a session. (The
    // `inbox` tool of `peerharness mcp` runs under the second.)
    for by in [By::Agent, By::Marked] {
        let (code, inbox, printed) = node.out(by, &["inbox"]);
        assert_eq!(code, 0, "{printed}");
        assert_eq!(inbox["candidates"][0]["status"], "detected", "{inbox}");
        let (code, shown, printed) = node.out(by, &["review", &id]);
        assert_eq!(code, 0, "{printed}");
        assert_eq!(shown["candidate"]["status"], "detected", "{shown}");
    }
    assert_eq!(node.run(&["status"])["candidates"]["detected"], 1);

    // So the owner is told at the end of the turn.
    let notice = stop_notice(&node);
    assert!(
        notice.contains("1 possible convention to review"),
        "{notice:?}"
    );

    // The owner reads the inbox in their terminal: now it has been shown.
    assert_eq!(node.candidates()[0]["status"], "local_review");
    let status = node.run(&["status"]);
    assert_eq!(status["candidates"]["local_review"], 1, "{status}");
    assert!(status["candidates"]["detected"].is_null(), "{status}");
}

/// consent-16. The tool's own comment says a word that names a file is never taken for
/// an address. An absolute path was: the join then read the file. Here that file is a
/// real invitation and the window would say yes, so before the fix this node joined a
/// circle from a file its agent chose.
#[test]
fn the_join_tool_takes_a_peer_id_or_an_address_and_never_a_path() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let alice = Node::new(root, "alice");
    let bob = Node::new(root, "bob");
    let created = alice.run(&["circle", "create", "team"]);
    let fingerprint = created["root_fingerprint"].as_str().unwrap().to_owned();
    let invite = root.join("invite.jsonl");
    let invite = invite.to_str().unwrap().to_owned();
    let invited = alice.run(&[
        "circle",
        "invite",
        &bob.status("device_key"),
        "--circle",
        "team",
        "--member",
        "bob",
        "--yes",
        "--out",
        &invite,
    ]);
    assert_eq!(invited["passed"], true);

    // Bob allowed the circle steps, and his window would say yes.
    bob.windows_on();
    bob.answers("proceed");
    let mut client = bob.serve();
    client.handshake();

    let said = client.fails(
        "join_circle",
        json!({ "member": invite, "fingerprint": fingerprint }),
    );
    assert!(said.contains("neither a peer id nor an address"), "{said}");
    // A relative path, and a file whose name reads as a peer id: the same.
    std::fs::copy(&invite, bob.cwd.join("invite.jsonl")).unwrap();
    let peer_id = alice.status("peer_id");
    std::fs::copy(&invite, bob.cwd.join(&peer_id)).unwrap();
    for member in ["invite.jsonl", "./invite.jsonl", peer_id.as_str()] {
        let said = client.fails(
            "join_circle",
            json!({ "member": member, "fingerprint": fingerprint }),
        );
        assert!(
            said.contains("neither a peer id nor an address"),
            "{member}: {said}"
        );
    }
    assert!(bob.shown().is_empty(), "no window: {:?}", bob.shown());
    assert_eq!(bob.run(&["status"])["circles"], json!([]));

    // The file is a real invitation: in his own terminal Bob joins with it.
    let joined = bob.run(&[
        "circle",
        "join",
        &invite,
        "--expect-fingerprint",
        &fingerprint,
        "--yes",
        "--name",
        "team",
    ]);
    assert_eq!(joined["member"], "bob");
}

/// Inside a session `circle join` does not read an argument that reads as a peer id
/// or as an address as a file, whatever is on disk: such an argument names a node. The
/// `join_circle` tool
/// has its own look at the disk before it starts the command, and the command used to
/// look again by itself; the tool's rule that it never makes `circle join` read a file
/// no longer rests on those two looks agreeing. (Through the tool a peer id came with
/// `--internet`, which `circle join` already refused together with a file. The case
/// below is the command as a session can type it, without `--internet`.) The file is
/// there all along, it is a real invitation, and the window would say yes: before the
/// change this node joined from it.
#[test]
fn inside_a_session_a_peer_id_is_never_read_as_a_file() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let alice = Node::new(root, "alice");
    let bob = Node::new(root, "bob");
    let created = alice.run(&["circle", "create", "team"]);
    let fingerprint = created["root_fingerprint"].as_str().unwrap().to_owned();
    let invite = root.join("invite.jsonl");
    let invite = invite.to_str().unwrap().to_owned();
    let invited = alice.run(&[
        "circle",
        "invite",
        &bob.status("device_key"),
        "--circle",
        "team",
        "--member",
        "bob",
        "--yes",
        "--out",
        &invite,
    ]);
    assert_eq!(invited["passed"], true);

    // Bob allowed the circle steps, and his window would say yes.
    bob.windows_on();
    bob.answers("proceed");
    // The invitation, under a name that reads as a peer id, in the directory the
    // command runs in.
    let peer_id = alice.status("peer_id");
    std::fs::copy(&invite, bob.cwd.join(&peer_id)).unwrap();
    let join = [
        "circle",
        "join",
        peer_id.as_str(),
        "--expect-fingerprint",
        fingerprint.as_str(),
        "--name",
        "team",
    ];
    let join_yes = [&join[..], &["--yes"]].concat();

    // --- Inside a session: the argument is a peer id, and without --internet that is
    // a usage error. The file is not read, no window opens and nothing is joined.
    for (by, args) in [
        (By::Agent, &join[..]),
        (By::Agent, &join_yes[..]),
        (By::Marked, &join[..]),
    ] {
        let (code, json, printed) = bob.out(by, args);
        assert_eq!(code, 2, "{args:?}: {printed}");
        assert_eq!(json["error"]["kind"], "usage", "{printed}");
        assert_eq!(
            json["error"]["message"],
            "that is a peer id: pass --internet to find its node over the public network, \
             or give the node's address",
            "{printed}"
        );
        assert!(bob.shown().is_empty(), "no window: {:?}", bob.shown());
        assert_eq!(bob.run(&["status"])["circles"], json!([]));
    }

    // --- In his own terminal nothing changed: a path that exists is the file it
    // names, whatever else its name reads as, and Bob joins with it.
    let joined = bob.run(&join_yes);
    assert_eq!(joined["member"], "bob");
    assert!(bob.shown().is_empty());
}

/// consent-9. An agent whose shell sets neither variable is not marked as a session.
/// What it reads when a consent step finds no terminal must not be an instruction to
/// pass `--yes`.
#[test]
fn without_a_terminal_nobody_is_told_to_pass_yes() {
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path(), "alice");
    let cand = node.run(&["note", RULE])["candidate_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Neither variable is set and no terminal is attached.
    let msg = node.refused(By::Person, &["keep", &cand]);
    assert!(msg.contains("no terminal is attached"), "{msg}");
    assert!(msg.contains("the owner's decision"), "{msg}");
    assert!(
        msg.contains("A coding agent stops here and asks the person."),
        "{msg}"
    );
    assert!(!msg.contains("re-run"), "{msg}");
    assert!(!node.skill_file(SKILL).exists());
    // The flag is still the person's, for a script they wrote.
    let kept = node.run(&["keep", &cand, "--yes"]);
    assert_eq!(kept["installed"], true);
}
