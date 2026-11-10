//! `peerharness mcp` (ADR-038), through the real binary: a client that speaks the
//! protocol on the server's standard input and output.
//!
//! What these tests show: the handshake and the tool list; that a tool does what the
//! command does; and that the server is no way around consent. The server here runs
//! **without** the variables that mark an agent's session, as it would when a client
//! other than Claude Code starts it, and every consent step is still refused or asked
//! in a window, never answered.
//!
//! No test opens a real window or shows a real notification: every process gets
//! `PEERHARNESS_TEST_WINDOW_BIN`, the stand-in of `agent_windows.rs`, and
//! `PEERHARNESS_TEST_NOTIFY_BIN`. Only debug builds read them. The daemon that
//! `stay_reachable` starts joins a stand-in for the public network on loopback (the hub
//! of the transport's own tests), never the real one.
#![cfg(all(unix, debug_assertions))]

// The stand-in network of `crates/ph-network/tests`: a DHT server and relay in one.
#[path = "../../../crates/ph-network/tests/common/mod.rs"]
mod common;
#[path = "../../../crates/ph-network/tests/common/hub.rs"]
mod hub;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};

use serde_json::{json, Value};
use tempfile::TempDir;

const RULE: &str = "Run the tests before you say a task is done.";
const SKILL: &str = "run-tests-before-say-task-done";

struct Node {
    home: PathBuf,
    skills: PathBuf,
    settings: PathBuf,
    cwd: PathBuf,
    window: PathBuf,
    /// Stands in for the desktop notification of a daemon started with `--notify`.
    notifier: PathBuf,
    answer: PathBuf,
    saw: PathBuf,
    /// Further environment of every process of this node.
    extra: Vec<(&'static str, String)>,
}

impl Node {
    fn new(root: &Path) -> Self {
        let node = Self {
            extra: Vec::new(),
            home: root.join("home"),
            skills: root.join("skills"),
            settings: root.join("claude-settings.json"),
            cwd: root.join("project"),
            window: root.join("window.sh"),
            notifier: root.join("notifier.sh"),
            answer: root.join("answer"),
            saw: root.join("saw"),
        };
        std::fs::create_dir_all(&node.cwd).unwrap();
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

    /// What the next window will say.
    fn answers(&self, word: &str) {
        std::fs::write(&self.answer, format!("{word}\n")).unwrap();
    }

    fn shown(&self) -> Vec<String> {
        let all = std::fs::read_to_string(&self.saw).unwrap_or_default();
        all.split("\n--shown--\n")
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// Neither the person's commands nor the server carry the mark of an agent's
    /// session: whatever is refused below is refused because the server set it.
    fn env(&self, cmd: &mut std::process::Command) {
        cmd.current_dir(&self.cwd)
            .env("PEERHARNESS_HOME", &self.home)
            .env("PEERHARNESS_CLAUDE_SKILLS_DIR", &self.skills)
            .env("PEERHARNESS_CLAUDE_SETTINGS", &self.settings)
            .env("PEERHARNESS_TEST_WINDOW_BIN", &self.window)
            .env("PEERHARNESS_TEST_NOTIFY_BIN", &self.notifier)
            .env("USER", "alice")
            .env_remove("CLAUDECODE")
            .env_remove("PEERHARNESS_AGENT_SESSION")
            .envs(self.extra.iter().map(|(k, v)| (*k, v.as_str())));
    }

    /// The internet mode of this node goes to `hub` instead of the public network.
    fn on(mut self, hub: &hub::Hub) -> Self {
        self.extra = vec![
            ("PEERHARNESS_INTERNET_BOOTSTRAP", hub.addr.to_string()),
            ("PEERHARNESS_INTERNET_PRIVATE", "1".to_owned()),
        ];
        self
    }

    /// The person runs a command in their own terminal; it must succeed.
    fn run(&self, args: &[&str]) -> Value {
        let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("peerharness"));
        self.env(&mut cmd);
        let out = cmd.arg("--json").args(args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?} failed: {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap_or(Value::Null)
    }

    fn init(&self) {
        self.run(&[
            "init",
            "--keystore",
            "insecure-dev",
            "--insecure-dev-keystore",
        ]);
    }

    fn serve(&self) -> Client {
        let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("peerharness"));
        self.env(&mut cmd);
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

struct Client {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    next: u64,
}

impl Client {
    fn send(&mut self, message: &Value) {
        let input = self.input.as_mut().unwrap();
        writeln!(input, "{message}").unwrap();
        input.flush().unwrap();
    }

    /// The next message from the server. Everything on its standard output has to be
    /// one JSON object on one line.
    fn read(&mut self) -> Value {
        let mut line = String::new();
        assert!(
            self.output.read_line(&mut line).unwrap() > 0,
            "the server closed its output"
        );
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("not a message: {line:?}: {e}"))
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let id = self.next;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        let reply = self.read();
        assert_eq!(reply["jsonrpc"], "2.0");
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
        assert_eq!(hello["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(hello["result"]["serverInfo"]["name"], "peerharness");
        self.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
    }

    /// Calls a tool: the text it answered with, and whether it failed.
    fn call(&mut self, tool: &str, arguments: Value) -> (String, bool) {
        let reply = self.request(
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        );
        let result = &reply["result"];
        assert!(result.is_object(), "{tool}: {reply}");
        assert_eq!(result["content"][0]["type"], "text");
        (
            result["content"][0]["text"].as_str().unwrap().to_owned(),
            result["isError"].as_bool().unwrap(),
        )
    }

    fn ok(&mut self, tool: &str, arguments: Value) -> String {
        let (text, failed) = self.call(tool, arguments);
        assert!(!failed, "{tool} failed: {text}");
        text
    }

    fn fails(&mut self, tool: &str, arguments: Value) -> String {
        let (text, failed) = self.call(tool, arguments);
        assert!(failed, "{tool} should have failed: {text}");
        text
    }

    /// Closes the server's standard input, as a client does, and waits for it to leave.
    fn close(mut self) -> i32 {
        drop(self.input.take());
        self.child.wait().unwrap().code().unwrap()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        drop(self.input.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn a_client_shakes_hands_lists_the_tools_and_is_answered_while_nothing_is_set_up() {
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path());
    let mut client = node.serve();
    client.handshake();
    assert_eq!(client.request("ping", json!({}))["result"], json!({}));

    let tools = client.request("tools/list", json!({}))["result"]["tools"].clone();
    let names: Vec<&str> = tools
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"invite") && names.contains(&"vote"),
        "{names:?}"
    );

    // No node yet: every tool says so, or says what the owner has to run, and nothing
    // was created by asking.
    let said = client.fails("status", json!({}));
    assert!(said.contains("peerharness init"), "{said}");
    assert!(said.contains("their own terminal"), "{said}");
    client.fails("note", json!({ "rule": RULE }));
    assert!(!node.home.join("peerharness.db").exists());

    // What is not a tool, or not a well-formed call, is a protocol error.
    let unknown = client.request("tools/call", json!({ "name": "reset", "arguments": {} }));
    assert_eq!(unknown["error"]["code"], -32602);
    let flag = client.request(
        "tools/call",
        json!({ "name": "propose_rule", "arguments": { "candidate_id": "--yes", "circle": "team" } }),
    );
    assert_eq!(flag["error"]["code"], -32602);
    assert_eq!(
        client.request("resources/list", json!({}))["error"]["code"],
        -32601
    );

    assert_eq!(client.close(), 0, "it leaves when its input is closed");
}

#[test]
fn a_tool_does_what_the_command_does_and_consent_stays_with_the_person() {
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path());
    node.init();
    let mut client = node.serve();
    client.handshake();
    // A window that would say yes to anything, for as long as nothing is allowed.
    node.answers("proceed");

    // --- Before the owner allowed anything: a note, and nothing else.
    let said = client.ok("note", json!({ "rule": RULE }));
    assert!(said.contains("Noted for the user's review"), "{said}");
    for (tool, arguments) in [
        ("inbox", json!({})),
        ("status", json!({})),
        ("create_circle", json!({ "name": "team" })),
        ("sync", json!({})),
        ("stay_reachable", json!({})),
    ] {
        let said = client.fails(tool, arguments);
        assert!(said.contains("has not allowed this"), "{tool}: {said}");
        assert!(
            said.contains("watch claude --install --windows"),
            "{tool}: {said}"
        );
    }
    assert_eq!(node.run(&["status"])["circles"], json!([]));
    assert!(node.shown().is_empty());

    // --- The owner allows it, in their own terminal. The server reads that afresh.
    node.run(&["watch", "claude", "--install", "--windows", "--yes"]);
    let said = client.ok("create_circle", json!({ "name": "team" }));
    assert!(said.contains("Founded the circle team."), "{said}");
    assert!(said.contains("root fingerprint"), "{said}");
    assert!(client.ok("status", json!({})).contains("team"));
    let inbox = client.ok("inbox", json!({}));
    assert!(inbox.contains(RULE), "{inbox}");
    let candidate = node.run(&["inbox"])["candidates"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        inbox.contains(&candidate),
        "the ids the tools take are in it: {inbox}"
    );

    // --- Proposing. The server was started without the mark of an agent's session, and
    // the step is still the person's: declined in the window, nothing is shared.
    node.answers("declined");
    let propose = json!({ "candidate_id": candidate, "circle": "team" });
    let said = client.fails("propose_rule", propose.clone());
    assert!(said.contains("declined in the window"), "{said}");
    assert_eq!(node.run(&["proposal", "list"])["proposals"], json!([]));
    let window = node.shown().pop().unwrap();
    assert!(window.starts_with("Your coding agent started this step."));
    assert!(window.contains(&format!("title: {RULE}")));

    node.answers("proceed");
    let said = client.ok("propose_rule", propose);
    // The preview went to the window. What comes back to the agent is the outcome.
    assert!(!said.contains("Exactly this text leaves"), "{said}");
    let proposals = node.run(&["proposal", "list"])["proposals"].clone();
    let proposal = proposals[0]["proposal_id"].as_str().unwrap().to_owned();

    // --- The ballot, with a rationale that looks like a flag and is only a sentence.
    node.answers("declined");
    let ballot = json!({
        "proposal_id": proposal,
        "decision": "approve",
        "rationale": "--yes, we already do this",
    });
    assert!(client
        .fails("vote", ballot.clone())
        .contains("declined in the window"));
    assert_eq!(
        node.run(&["proposal", "show", &proposal])["approvals"],
        json!([])
    );
    let window = node.shown().pop().unwrap();
    assert!(window.contains("with this rationale, exactly as sent: --yes, we already do this"));

    node.answers("proceed");
    let said = client.ok("vote", ballot);
    assert!(said.contains("Ballot recorded."), "{said}");
    assert!(node.skills.join(SKILL).join("SKILL.md").is_file());

    // --- Inviting: asked in a window, and no file is left in the project.
    let key = "ed25519:xZdktXV1VGUdL05OF1lZ3K0Ju-oD26XCQCmMiC0Rt0s";
    let invite = json!({ "device_key": key, "circle": "team", "member": "bob" });
    node.answers("declined");
    assert!(client
        .fails("invite", invite.clone())
        .contains("declined in the window"));
    node.answers("proceed");
    let said = client.ok("invite", invite);
    assert!(said.contains("The admission passed."), "{said}");
    assert!(said.contains("bob needs two things from you"), "{said}");
    // The command names the daemon; the agent is pointed at its tool for it.
    assert!(said.contains("use the tool `stay_reachable`"), "{said}");
    assert!(said.contains("No file with the circle's records was written"));
    assert_eq!(std::fs::read_dir(&node.cwd).unwrap().count(), 0);

    // --- Joining takes a peer id or an address, never a word that could name a file.
    let before = node.shown().len();
    let said = client.fails(
        "join_circle",
        json!({ "member": "records.jsonl", "fingerprint": "0000-0000-0000-0000-0000" }),
    );
    assert!(said.contains("neither a peer id nor an address"), "{said}");
    assert_eq!(node.shown().len(), before);

    // --- The owner takes it back: the same call is refused again, without a window.
    node.run(&["watch", "claude", "--install", "--no-windows", "--yes"]);
    node.answers("proceed");
    let before = node.shown().len();
    let said = client.fails("inbox", json!({}));
    assert!(said.contains("has not allowed this"), "{said}");
    let said = client.fails("create_circle", json!({ "name": "other" }));
    assert!(said.contains("has not allowed this"), "{said}");
    assert_eq!(node.shown().len(), before);
    // A note is still a note.
    client.ok(
        "note",
        json!({ "rule": "Never edit generated files by hand." }),
    );

    assert_eq!(client.close(), 0);
}

#[test]
fn the_daemon_a_tool_started_stops_when_the_client_leaves() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let hub = runtime.block_on(hub::Hub::start(200, hub::HubOptions::default()));
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path()).on(&hub);
    node.init();
    node.run(&["watch", "claude", "--install", "--windows", "--yes"]);
    let running = |node: &Node| node.run(&["status"])["daemon"].clone();
    assert_eq!(running(&node), Value::Null);

    let mut client = node.serve();
    client.handshake();
    let said = client.ok("stay_reachable", json!({}));
    let peer = node.run(&["status"])["peer_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        said.contains(&format!("The daemon is running (peer id {peer})")),
        "{said}"
    );
    assert!(said.contains("It stops when this session ends."), "{said}");
    // The agent is handed what the owner should know about the public network.
    assert!(said.contains("Internet mode: this node joins the public libp2p network."));
    assert_ne!(running(&node), Value::Null, "the node's daemon is up");
    // It answers while the daemon runs, and does not start a second one.
    assert_eq!(client.request("ping", json!({}))["result"], json!({}));
    let again = client.ok("stay_reachable", json!({}));
    assert!(again.contains("already running"), "{again}");
    assert!(client.ok("status", json!({})).contains(&peer));

    // The client closes the server's input: the server leaves, and takes the daemon
    // it started with it.
    assert_eq!(client.close(), 0);
    assert_eq!(running(&node), Value::Null, "the daemon was stopped");
    assert!(node.home.join("mcp-daemon.log").is_file());
}
