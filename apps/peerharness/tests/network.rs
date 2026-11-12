//! Separate OS processes talking over real QUIC on loopback: one node runs `daemon`, the
//! others `sync` with it. No shared database, no mock transport.
//!
//! Covered here: a rule proposed on one node, voted on another and installed on both;
//! an admission and a removal decided by ballots that arrive over the network, with the
//! founder's daemon issuing the charters; a new member who gets the circle from a
//! member's node; a removed member whose node is shown the vote that removed it; a
//! daemon that tells its owner of a rule that a peer's push left held on its node, and
//! of one that a push installed, removed or left waiting for them; and
//! the ways a node that is not on the roll is turned away; and the internet mode, in
//! which members find each other by device key, against a private stand-in for the
//! public network (the hub that the transport's own tests use).

// The stand-in network of `crates/ph-network/tests`: a DHT server and relay in one.
#[path = "../../../crates/ph-network/tests/common/mod.rs"]
mod common;
#[path = "../../../crates/ph-network/tests/common/hub.rs"]
mod hub;

use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

const RULE: &str = "Use pnpm, not npm, in this repository.";
const SKILL: &str = "use-pnpm-not-npm-repository";
const LISTEN: &str = "/ip4/127.0.0.1/udp/0/quic-v1";

struct Node {
    name: &'static str,
    home: PathBuf,
    skills: PathBuf,
    /// Where this node looks for Claude Code's settings: never the developer's own.
    settings: PathBuf,
    /// Further environment of every command of this node.
    env: Vec<(&'static str, String)>,
}

/// A running `peerharness daemon`, killed when dropped.
struct Daemon {
    child: Child,
    addr: String,
    peer_id: String,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Node {
    fn new(root: &Path, name: &'static str) -> Self {
        let node = Self {
            name,
            home: root.join(name),
            skills: root.join(format!("{name}-skills")),
            settings: root.join(format!("{name}-claude-settings.json")),
            env: Vec::new(),
        };
        node.run(&[
            "init",
            "--keystore",
            "insecure-dev",
            "--insecure-dev-keystore",
        ]);
        node
    }

    fn envs(&self) -> Vec<(&'static str, std::ffi::OsString)> {
        let mut envs: Vec<(&'static str, std::ffi::OsString)> = vec![
            ("PEERHARNESS_HOME", self.home.clone().into()),
            ("PEERHARNESS_CLAUDE_SKILLS_DIR", self.skills.clone().into()),
            ("PEERHARNESS_CLAUDE_SETTINGS", self.settings.clone().into()),
            ("USER", self.name.into()),
        ];
        envs.extend(self.env.iter().map(|(k, v)| (*k, v.into())));
        envs
    }

    /// The internet mode of this node goes to `hub` instead of the public network.
    fn on(mut self, hub: &hub::Hub) -> Self {
        self.env = vec![
            ("PEERHARNESS_INTERNET_BOOTSTRAP", hub.addr.to_string()),
            ("PEERHARNESS_INTERNET_PRIVATE", "1".to_owned()),
        ];
        self
    }

    /// Runs a command that depends on what another process has done by now, again
    /// until it succeeds. Only a runtime failure (exit 1) is tried again.
    fn eventually(&self, args: &[&str]) -> Value {
        let deadline = Instant::now() + Duration::from_secs(40);
        loop {
            let out = self.cmd(args).output().unwrap();
            if out.status.success() {
                return serde_json::from_slice(&out.stdout).unwrap();
            }
            assert!(
                out.status.code() == Some(1) && Instant::now() < deadline,
                "{} {:?} failed:\n{}\n{}",
                self.name,
                args,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Waits until this node's daemon says it has reached the network.
    fn wait_joined(&self) -> Value {
        let deadline = Instant::now() + Duration::from_secs(40);
        loop {
            let internet = self.run(&["status"])["daemon"]["internet"].clone();
            if internet["joined"] == true {
                return internet;
            }
            assert!(
                Instant::now() < deadline,
                "{}'s daemon did not reach the network: {internet}",
                self.name
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("peerharness").unwrap();
        cmd.envs(self.envs())
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
            .env_remove("GEMINI_CLI")
            .env_remove("QWEN_CODE")
            .env_remove("COPILOT_CLI")
            .env_remove("CURSOR_AGENT")
            .env_remove("AMP_CURRENT_THREAD_ID")
            .env_remove("FACTORY_SESSION_ID")
            .env_remove("CRUSH")
            .env_remove("KILO")
            .env_remove("GOOSE_TERMINAL")
            .env_remove("AGENT_SESSION_ID")
            .arg("--json")
            .args(args);
        cmd
    }

    fn run(&self, args: &[&str]) -> Value {
        let out = self.cmd(args).output().unwrap();
        assert!(
            out.status.success(),
            "{} {:?} failed:\n{}\n{}",
            self.name,
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("{} {:?}: stdout is not JSON: {e}", self.name, args))
    }

    /// The exit code and error message of a command that must fail.
    fn fail(&self, args: &[&str]) -> (i32, String) {
        let out = self.cmd(args).output().unwrap();
        assert!(
            !out.status.success(),
            "{} {:?} should fail",
            self.name,
            args
        );
        let json: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        (
            out.status.code().unwrap(),
            json["error"]["message"].as_str().unwrap_or("").to_owned(),
        )
    }

    fn device_key(&self) -> String {
        self.run(&["status"])["device_key"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn has_skill(&self) -> bool {
        self.skills.join(SKILL).join("SKILL.md").is_file()
    }

    fn charter_seq(&self) -> u64 {
        self.run(&["circle", "members", "--circle", "team"])["charter"]["seq"]
            .as_u64()
            .unwrap()
    }

    fn roll(&self) -> Vec<String> {
        self.run(&["circle", "members", "--circle", "team"])["charter"]["roll"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["member"].as_str().unwrap().to_owned())
            .collect()
    }

    /// Starts `daemon` on an ephemeral loopback port and waits until it has written
    /// where it listens.
    fn daemon(&self) -> Daemon {
        self.daemon_with(&["--listen", LISTEN])
    }

    fn daemon_with(&self, args: &[&str]) -> Daemon {
        self.daemon_printing(args, Stdio::null())
    }

    /// Starts `daemon` with what it prints for its owner going to `said`.
    fn daemon_printing(&self, args: &[&str], said: Stdio) -> Daemon {
        let bin = assert_cmd::cargo::cargo_bin("peerharness");
        let child = std::process::Command::new(bin)
            .envs(self.envs())
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
            .env_remove("GEMINI_CLI")
            .env_remove("QWEN_CODE")
            .env_remove("COPILOT_CLI")
            .env_remove("CURSOR_AGENT")
            .env_remove("AMP_CURRENT_THREAD_ID")
            .env_remove("FACTORY_SESSION_ID")
            .env_remove("CRUSH")
            .env_remove("KILO")
            .env_remove("GOOSE_TERMINAL")
            .env_remove("AGENT_SESSION_ID")
            .arg("daemon")
            .args(args)
            .stdin(Stdio::null())
            .stdout(said)
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let mut daemon = Daemon {
            child,
            addr: String::new(),
            peer_id: String::new(),
        };
        let file = self.home.join("daemon.json");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let info: Option<Value> = std::fs::read(&file)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok());
            if let Some(info) = info.filter(|i| i["pid"].as_u64() == Some(u64::from(pid))) {
                daemon.addr = info["listen_addrs"][0].as_str().unwrap().to_owned();
                daemon.peer_id = info["peer_id"].as_str().unwrap().to_owned();
                return daemon;
            }
            assert!(
                Instant::now() < deadline,
                "{}'s daemon did not start",
                self.name
            );
            assert!(
                daemon.child.try_wait().unwrap().is_none(),
                "{}'s daemon exited early",
                self.name
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Joins the circle from a file a member exported.
    fn join(&self, from: &Node, root: &Path, fingerprint: &str) {
        let file = root.join(format!("for-{}.jsonl", self.name));
        let path = file.to_str().unwrap();
        from.run(&["events", "export", "--circle", "team", "--out", path]);
        self.run(&[
            "circle",
            "join",
            path,
            "--expect-fingerprint",
            fingerprint,
            "--yes",
            "--name",
            "team",
        ]);
    }
}

/// The notifications a daemon showed, as its stand-in notification program recorded
/// them (`PEERHARNESS_TEST_NOTIFY_BIN`, read by debug builds only).
#[cfg(debug_assertions)]
fn notifications(file: &Path) -> Vec<String> {
    std::fs::read_to_string(file)
        .unwrap_or_default()
        .split("\n--shown--\n")
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(debug_assertions)]
#[test]
fn a_daemon_announces_a_proposal_that_needs_its_owners_vote_once() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let alice = Node::new(root, "alice");
    let mut bob = Node::new(root, "bob");

    // Bob's notifications go to a file instead of his screen.
    let shown = root.join("bob-notifications");
    let program = root.join("notify.sh");
    std::fs::write(
        &program,
        format!(
            "#!/bin/sh\ncat >> '{0}'\nprintf '\\n--shown--\\n' >> '{0}'\n",
            shown.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    bob.env
        .push(("PEERHARNESS_TEST_NOTIFY_BIN", program.display().to_string()));

    let created = alice.run(&["circle", "create", "team"]);
    let fingerprint = created["root_fingerprint"].as_str().unwrap().to_owned();
    alice.run(&[
        "circle",
        "invite",
        &bob.device_key(),
        "--circle",
        "team",
        "--member",
        "bob",
        "--yes",
        "--out",
        root.join("unused.jsonl").to_str().unwrap(),
    ]);
    bob.join(&alice, root, &fingerprint);

    // Bob's node runs and tells him when something needs his vote. Nothing does yet.
    let daemon = bob.daemon_with(&["--listen", LISTEN, "--notify"]);

    // Alice proposes a rule, approves it and sends it to Bob's node.
    let cand = alice.run(&["note", RULE])["candidate_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let rule = alice.run(&["proposal", "create", &cand, "--circle", "team", "--yes"])
        ["proposal_id"]
        .as_str()
        .unwrap()
        .to_owned();
    alice.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    assert!(
        notifications(&shown).is_empty(),
        "nothing has reached Bob's node yet"
    );
    let synced = alice.run(&["sync", &daemon.addr]);
    assert_eq!(synced["sent"], 2, "the proposal and her ballot");

    // Within a few seconds Bob is told: a count and where to look, and none of the
    // proposal's text.
    let deadline = Instant::now() + Duration::from_secs(30);
    while notifications(&shown).is_empty() {
        assert!(Instant::now() < deadline, "Bob's daemon announced nothing");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        notifications(&shown),
        ["1 proposal waits for your vote. Run: peerharness inbox"]
    );
    let inbox = bob.run(&["inbox"]);
    assert_eq!(
        inbox["proposals_awaiting_vote"][0]["proposal_id"],
        rule.as_str()
    );

    // The daemon keeps looking every three seconds while the proposal still waits. It
    // has said it once and does not say it again.
    std::thread::sleep(Duration::from_secs(7));
    assert_eq!(notifications(&shown).len(), 1);

    // Nor after a restart: what was announced is in the store.
    drop(daemon);
    let _daemon = bob.daemon_with(&["--listen", LISTEN, "--notify"]);
    std::thread::sleep(Duration::from_secs(7));
    assert_eq!(notifications(&shown).len(), 1);
    assert_eq!(
        bob.run(&["inbox"])["proposals_awaiting_vote_total"],
        1,
        "it still waits for him"
    );
}

/// Without a notification program, `--notify` is refused when the daemon starts.
#[cfg(not(target_os = "macos"))]
#[test]
fn notify_is_refused_where_no_notification_can_be_shown() {
    let tmp = TempDir::new().unwrap();
    let alice = Node::new(tmp.path(), "alice");
    let (code, msg) = alice.fail(&["daemon", "--listen", LISTEN, "--notify"]);
    assert_eq!(code, 2, "{msg}");
    assert!(msg.contains("--notify"), "{msg}");
}

#[test]
fn members_vote_over_quic_and_strangers_are_turned_away() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let alice = Node::new(root, "alice");
    let bob = Node::new(root, "bob");
    let carol = Node::new(root, "carol");
    let mallory = Node::new(root, "mallory");
    let nobody = Node::new(root, "nobody");

    // --- Alice founds the circle and admits Bob (her approval is the majority of one).
    let created = alice.run(&["circle", "create", "team"]);
    let fingerprint = created["root_fingerprint"].as_str().unwrap().to_owned();
    alice.run(&[
        "circle",
        "invite",
        &bob.device_key(),
        "--circle",
        "team",
        "--member",
        "bob",
        "--yes",
        "--out",
        root.join("unused.jsonl").to_str().unwrap(),
    ]);
    bob.join(&alice, root, &fingerprint);

    // --- Alice's node goes on the network. Only one daemon per home.
    let daemon = alice.daemon();
    assert!(daemon.addr.ends_with(&format!("/p2p/{}", daemon.peer_id)));
    assert_eq!(
        alice.run(&["status"])["daemon"]["listen_addrs"][0],
        daemon.addr.as_str()
    );
    assert_eq!(alice.fail(&["daemon", "--listen", LISTEN]).0, 2);

    // --- A rule: proposed and approved on Alice's node while her daemon runs.
    let cand = alice.run(&["note", RULE])["candidate_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let rule = alice.run(&["proposal", "create", &cand, "--circle", "team", "--yes"])
        ["proposal_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        alice.run(&["proposal", "vote", &rule, "approve", "--yes"])["passed"],
        false
    );

    // Bob fetches it, with the rule's text, over QUIC.
    let synced = bob.run(&["sync", &daemon.addr]);
    assert_eq!(synced["peer_id"], daemon.peer_id.as_str());
    assert_eq!(synced["received"], 2, "the proposal and Alice's ballot");
    assert_eq!(synced["bundles"], 1);
    assert_eq!(synced["sent"], 0);
    let shown = bob.run(&["proposal", "show", &rule]);
    assert_eq!(shown["title"], RULE);
    assert_eq!(shown["standing"], "open");
    assert!(!bob.has_skill());

    // He approves: two of two. It is installed on his machine, and after his next sync
    // (now by peer id: the address was remembered) on Alice's, by her daemon.
    assert_eq!(
        bob.run(&["proposal", "vote", &rule, "approve", "--yes"])["passed"],
        true
    );
    assert!(bob.has_skill());
    assert!(!alice.has_skill());
    let synced = bob.run(&["sync", &daemon.peer_id]);
    assert_eq!(synced["sent"], 2, "his ballot and the result he published");
    assert_eq!(synced["refused_by_peer"], 0);
    assert!(alice.has_skill(), "the daemon applied the passed rule");
    assert_eq!(
        alice.run(&["proposal", "show", &rule])["standing"],
        "passed"
    );

    // Syncing again changes nothing on either side.
    let again = bob.run(&["sync", &daemon.peer_id]);
    assert_eq!(
        (again["received"].as_u64(), again["sent"].as_u64()),
        (Some(0), Some(0))
    );

    // --- Admitting Carol takes both members. Bob's ballot arrives over the network and
    // the founder's daemon issues the charter that was voted on.
    let invited = alice.run(&[
        "circle",
        "invite",
        &carol.device_key(),
        "--circle",
        "team",
        "--member",
        "carol",
        "--yes",
    ]);
    assert_eq!(invited["passed"], false);
    let admission = invited["proposal_id"].as_str().unwrap().to_owned();
    bob.run(&["sync", &daemon.peer_id]);
    assert_eq!(
        bob.run(&["proposal", "vote", &admission, "approve", "--yes"])["passed"],
        true
    );
    assert_eq!(bob.charter_seq(), 2, "Bob holds no root key");
    let synced = bob.run(&["sync", &daemon.peer_id]);
    assert_eq!(alice.charter_seq(), 3, "the daemon notarized the admission");
    assert_eq!(
        synced["received"], 1,
        "and Bob received charter 3 in the same sync"
    );
    assert_eq!(bob.charter_seq(), 3);
    assert_eq!(bob.roll(), ["alice", "bob", "carol"]);

    // Carol joins from Alice's node. It answers her because the admission that passed
    // put her device on its roll; before that it told her nothing.
    let join = |fingerprint: &str| {
        vec![
            "circle".to_owned(),
            "join".to_owned(),
            daemon.addr.clone(),
            "--expect-fingerprint".to_owned(),
            fingerprint.to_owned(),
            "--yes".to_owned(),
            "--name".to_owned(),
            "team".to_owned(),
        ]
    };
    let args = join("0000-0000-0000-0000-0000");
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, msg) = carol.fail(&args);
    assert_eq!(code, 3, "the wrong root fingerprint: {msg}");
    assert_eq!(
        carol.run(&["status"])["circles"],
        serde_json::json!([]),
        "nothing was stored by the refused join"
    );
    let args = join(&fingerprint);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let joined = carol.run(&args);
    assert_eq!(joined["member"], "carol");
    assert_eq!(joined["charter_seq"], 3);
    assert_eq!(carol.roll(), ["alice", "bob", "carol"]);
    // The rule from before her time is installed for her, with its text.
    assert!(carol.has_skill());
    // A device that is on no roll is offered nothing to join.
    let (code, msg) = nobody.fail(&args);
    assert_eq!(code, 3, "{msg}");
    assert!(
        msg.contains("does not have this device on the roll"),
        "{msg}"
    );
    assert_eq!(nobody.run(&["status"])["circles"], serde_json::json!([]));
    // There is nothing left for her to join there, and a plain sync has nothing to move.
    assert_eq!(carol.fail(&args).0, 3);
    let synced = carol.run(&["sync"]);
    assert_eq!(synced["failed"], serde_json::json!([]));
    assert_eq!(synced["synced"][0]["peer_id"], daemon.peer_id.as_str());
    assert_eq!(
        (
            synced["synced"][0]["received"].as_u64(),
            synced["synced"][0]["sent"].as_u64(),
            synced["synced"][0]["refused_by_peer"].as_u64()
        ),
        (Some(0), Some(0), Some(0))
    );

    // --- The daemon is restarted on another port. Nothing is lost or repeated.
    drop(daemon);
    assert_eq!(alice.run(&["status"])["daemon"], Value::Null);
    let daemon = alice.daemon();
    let again = carol.run(&["sync", &daemon.addr]);
    assert_eq!(
        (again["received"].as_u64(), again["sent"].as_u64()),
        (Some(0), Some(0))
    );

    // --- Strangers.
    // A node in no circle sends nothing at all: it has nothing in common with the peer.
    let (code, msg) = nobody.fail(&["sync", &daemon.addr]);
    assert_eq!(code, 3, "{msg}");
    assert!(msg.contains("share no circle"), "{msg}");
    // Mallory puts Alice's device on the roll of a circle of her own, so that her node
    // believes they share one. Alice's daemon does not know that circle, and Mallory is
    // on no roll Alice holds: it answers nothing but the refusal.
    mallory.run(&["circle", "create", "team"]);
    mallory.run(&[
        "circle",
        "invite",
        &alice.device_key(),
        "--circle",
        "team",
        "--member",
        "alice",
        "--yes",
        "--out",
        root.join("mallory.jsonl").to_str().unwrap(),
    ]);
    let (code, msg) = mallory.fail(&["sync", &daemon.addr]);
    assert_eq!(code, 3, "{msg}");
    assert!(msg.contains("does not recognize this node"), "{msg}");
    let titles: Vec<String> = mallory.run(&["proposal", "list"])["proposals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["title"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        titles,
        ["Admit alice"],
        "she learned nothing of Alice's circle"
    );
    assert!(!mallory.has_skill());
    // And Alice's node took nothing from her.
    assert_eq!(alice.roll(), ["alice", "bob", "carol"]);

    // --- Bob is removed by vote: Alice proposes, Carol's ballot arrives over the
    // network, the daemon issues charter 4. From then on Bob is a stranger to it.
    let removal = alice.run(&["circle", "remove", "bob", "--circle", "team", "--yes"]);
    assert_eq!(removal["passed"], false);
    let removal = removal["proposal_id"].as_str().unwrap().to_owned();
    carol.run(&["sync", &daemon.addr]);
    assert_eq!(
        carol.run(&["proposal", "vote", &removal, "approve", "--yes"])["passed"],
        true
    );
    carol.run(&["sync", &daemon.addr]);
    assert_eq!(alice.charter_seq(), 4);
    assert_eq!(alice.roll(), ["alice", "carol"]);
    assert_eq!(carol.roll(), ["alice", "carol"]);

    // (The address Bob remembered is the one from before the restart: a dead port is a
    // plain failure, not a refusal.)
    assert_eq!(bob.fail(&["sync", &daemon.peer_id]).0, 1);
    // Bob's node still believes he is a member. Alice's daemon no longer answers him as
    // one, but it shows him the vote that removed him, and his node checks it itself.
    assert!(bob.has_skill());
    let told = bob.run(&["sync", &daemon.addr]);
    assert_eq!(told["removed_from"], serde_json::json!(["team"]));
    assert_eq!(told["circles"], 0, "nothing else was exchanged");
    assert_eq!(told["sent"], 0);
    assert_eq!(bob.charter_seq(), 4);
    assert_eq!(bob.roll(), ["alice", "carol"]);
    assert!(!bob.has_skill(), "the circle's rule no longer binds him");
    assert_eq!(told["removed"], serde_json::json!([SKILL]));
    assert_eq!(
        bob.run(&["status"])["circles"][0]["standing"],
        "you are not on the roll"
    );
    // From then on his node has nothing in common with hers and sends nothing.
    let (code, msg) = bob.fail(&["sync", &daemon.addr]);
    assert_eq!(code, 3, "{msg}");
    assert!(msg.contains("share no circle"), "{msg}");
    // He cannot get back in by asking to join, either.
    let (code, msg) = bob.fail(&[
        "circle",
        "join",
        &daemon.addr,
        "--expect-fingerprint",
        &fingerprint,
        "--yes",
    ]);
    assert_eq!(code, 3, "{msg}");
}

/// A file of the circle's records, from one node to another.
fn hand_over(root: &Path, from: &Node, to: &Node, tag: &str) {
    let file = root.join(format!("{}-{tag}.jsonl", from.name));
    let path = file.to_str().unwrap();
    from.run(&["events", "export", "--circle", "team", "--out", path]);
    to.run(&["events", "import", path]);
}

/// Alice founds the circle `team`; Bob and Carol are admitted by vote and join by file.
/// All three hold charter 3, and no node knows another's address.
fn three_members(root: &Path) -> (Node, Node, Node) {
    let alice = Node::new(root, "alice");
    let bob = Node::new(root, "bob");
    let carol = Node::new(root, "carol");
    let id = |report: &Value, key: &str| report[key].as_str().unwrap().to_owned();
    let created = alice.run(&["circle", "create", "team"]);
    let fingerprint = id(&created, "root_fingerprint");
    alice.run(&[
        "circle",
        "invite",
        &bob.device_key(),
        "--circle",
        "team",
        "--member",
        "bob",
        "--yes",
        "--out",
        root.join("unused.jsonl").to_str().unwrap(),
    ]);
    bob.join(&alice, root, &fingerprint);
    let admission = id(
        &alice.run(&[
            "circle",
            "invite",
            &carol.device_key(),
            "--circle",
            "team",
            "--member",
            "carol",
            "--yes",
        ]),
        "proposal_id",
    );
    hand_over(root, &alice, &bob, "admission");
    bob.run(&["proposal", "vote", &admission, "approve", "--yes"]);
    hand_over(root, &bob, &alice, "admitted");
    carol.join(&alice, root, &fingerprint);
    hand_over(root, &alice, &bob, "charter");
    for node in [&alice, &bob, &carol] {
        assert_eq!(node.charter_seq(), 3, "{}", node.name);
    }
    (alice, bob, carol)
}

/// A daemon that only answers. Bob's node runs `daemon` without a sync interval and
/// knows no peer: the members sync to it, and it dials nobody. Alice and Carol pass a
/// rule that has the name of a skill Bob keeps for himself, and Alice's sync pushes
/// the ballots to Bob's daemon. On his node the rule is held, and his daemon says so:
/// once, when the push that made it arrives. It used to say nothing at all, because
/// the request handler settles a push and nobody was told what the settle found.
///
/// A later push settles the circle again and finds the same hold: it is not printed
/// again. A second rule that becomes held is printed in its turn.
#[test]
fn a_daemon_that_only_answers_tells_a_hold_that_a_push_created_once() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let (alice, bob, carol) = three_members(root);
    let id = |report: &Value, key: &str| report[key].as_str().unwrap().to_owned();
    let hand_over = |from: &Node, to: &Node, tag: &str| hand_over(root, from, to, tag);

    // --- Bob keeps two rules for himself.
    for (name, text) in [
        ("style", "Indent with tabs."),
        ("commits", "Write commit subjects in the imperative mood."),
    ] {
        let noted = id(&bob.run(&["note", text, "--name", name]), "candidate_id");
        assert_eq!(bob.run(&["keep", &noted, "--yes"])["installed"], true);
    }

    // --- His daemon: it listens, has no sync interval and knows no peer.
    let said = root.join("bob-daemon.out");
    let daemon = bob.daemon_printing(
        &["--listen", LISTEN],
        Stdio::from(std::fs::File::create(&said).unwrap()),
    );
    let printed = || std::fs::read_to_string(&said).unwrap_or_default();
    let held = |name: &str| format!("rule {name} is in force and is held on this machine:");
    let wait_for = |line: &str| {
        let deadline = Instant::now() + Duration::from_secs(40);
        while !printed().contains(line) {
            assert!(
                Instant::now() < deadline,
                "bob's daemon never printed {line:?}:\n{}",
                printed()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    // Alice and Carol pass a rule under `name`, on their own nodes.
    let pass = |name: &str, text: &str| {
        let noted = id(&alice.run(&["note", text, "--name", name]), "candidate_id");
        let rule = id(
            &alice.run(&["proposal", "create", &noted, "--circle", "team", "--yes"]),
            "proposal_id",
        );
        alice.run(&["proposal", "vote", &rule, "approve", "--yes"]);
        hand_over(&alice, &carol, name);
        let voted = carol.run(&["proposal", "vote", &rule, "approve", "--yes"]);
        assert_eq!(voted["passed"], true, "{voted}");
        hand_over(&carol, &alice, name);
    };

    // --- The first rule passes, and Alice's sync pushes it to Bob's daemon.
    pass("style", "Indent with two spaces.");
    assert!(!printed().contains("is held on this machine"));
    let pushed = alice.run(&["sync", &daemon.addr]);
    assert!(pushed["sent"].as_u64().unwrap() >= 3, "{pushed}");
    wait_for(&held("style"));

    // --- Another push, of something that changes no rule: Bob's node settles the
    // circle again and finds the same hold.
    let noted = id(
        &alice.run(&["note", "Prefer small pull requests."]),
        "candidate_id",
    );
    alice.run(&["question", "send", &noted, "--circle", "team", "--yes"]);
    let pushed = alice.run(&["sync", &daemon.addr]);
    assert_eq!(pushed["sent"], 1, "{pushed}");

    // --- A second rule becomes held by a third push. Its line comes after anything
    // the second push could have printed, so the count below is of everything.
    pass("commits", "Commit subjects are a single word.");
    alice.run(&["sync", &daemon.addr]);
    wait_for(&held("commits"));
    let all = printed();
    assert_eq!(all.matches(&held("style")).count(), 1, "{all}");
    assert_eq!(all.matches(&held("commits")).count(), 1, "{all}");
    // It made no exchange of its own, so it has no report of one.
    assert!(!all.contains("Synced "), "{all}");

    // The rules passed all the same, and `rule list` shows both as held.
    let rules = bob.run(&["rule", "list"])["rules"].clone();
    let rules = rules.as_array().unwrap();
    assert_eq!(rules.len(), 2, "{rules:?}");
    assert!(
        rules.iter().all(|r| r["held"] == "held_own_skill"),
        "{rules:?}"
    );
    drop(daemon);
}

/// The same daemon, and what a push changes besides holds. Bob follows the circle: a
/// rule that Alice and Carol pass is installed on his node by the push that brings its
/// ballots, and his daemon says so when it happens. Then he chooses to be asked first:
/// the next rule waits for his confirmation, and the daemon says that once, with the
/// command that confirms it, although every later push settles the circle again and
/// finds the rule waiting. A repeal that a push brings is said as well.
///
/// The daemon used to be told holds and nothing else. One that makes no exchange of
/// its own has no report in which these lines appear, so its owner learned of a rule
/// in their agent, or of one waiting for them, from `rule list` only.
#[test]
fn a_daemon_that_only_answers_tells_what_a_push_installed_and_what_waits() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let (alice, bob, carol) = three_members(root);
    let id = |report: &Value, key: &str| report[key].as_str().unwrap().to_owned();
    let hand_over = |from: &Node, to: &Node, tag: &str| hand_over(root, from, to, tag);
    let said = root.join("bob-daemon.out");
    let daemon = bob.daemon_printing(
        &["--listen", LISTEN],
        Stdio::from(std::fs::File::create(&said).unwrap()),
    );
    let printed = || std::fs::read_to_string(&said).unwrap_or_default();
    let wait_for = |line: &str| {
        let deadline = Instant::now() + Duration::from_secs(40);
        while !printed().contains(line) {
            assert!(
                Instant::now() < deadline,
                "bob's daemon never printed {line:?}:\n{}",
                printed()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    // Alice and Carol decide `proposal` between them, on their own nodes.
    let decide = |proposal: &str, tag: &str| {
        alice.run(&["proposal", "vote", proposal, "approve", "--yes"]);
        hand_over(&alice, &carol, tag);
        let voted = carol.run(&["proposal", "vote", proposal, "approve", "--yes"]);
        assert_eq!(voted["passed"], true, "{voted}");
        hand_over(&carol, &alice, tag);
    };
    let pass = |name: &str, text: &str| -> String {
        let noted = id(&alice.run(&["note", text, "--name", name]), "candidate_id");
        let rule = id(
            &alice.run(&["proposal", "create", &noted, "--circle", "team", "--yes"]),
            "proposal_id",
        );
        decide(&rule, name);
        rule
    };
    let installed = |name: &str| format!("installed rule {name} for your agent");
    let waits = |name: &str| format!("rule {name} is in force and waits for your confirmation");
    let on_bob = |name: &str| bob.skills.join(name).join("SKILL.md").is_file();

    // --- A rule passes and Alice's sync pushes it. Bob follows: it is installed, and
    // the daemon says so.
    pass("tests", "Run the tests before you say a change is done.");
    alice.run(&["sync", &daemon.addr]);
    wait_for(&installed("tests"));
    assert!(on_bob("tests"));

    // --- Bob chooses to be asked first. The next rule a push brings waits for him.
    bob.run(&["circle", "mode", "ask", "--circle", "team"]);
    let commits = pass("commits", "Write commit subjects in the imperative mood.");
    alice.run(&["sync", &daemon.addr]);
    wait_for(&waits("commits"));
    assert!(!on_bob("commits"));
    let all = printed();
    let short: String = commits.chars().take(19).collect();
    assert!(
        all.contains(&format!("`peerharness proposal adopt {short}`")),
        "the line names the command with the proposal: {all}"
    );

    // --- The first rule is repealed, and a push brings the repeal: said when it
    // happens. That push settles the circle again and finds `commits` still waiting.
    let repeal = id(
        &alice.run(&["rule", "repeal", "tests", "--circle", "team", "--yes"]),
        "proposal_id",
    );
    decide(&repeal, "repeal");
    alice.run(&["sync", &daemon.addr]);
    wait_for("removed rule tests");
    assert!(!on_bob("tests"));

    // --- A second rule waits after a fourth push. Its line comes after anything the
    // earlier pushes could have printed, so the counts below are of everything.
    pass("naming", "Names are lower case.");
    alice.run(&["sync", &daemon.addr]);
    wait_for(&waits("naming"));
    let all = printed();
    assert_eq!(all.matches(&installed("tests")).count(), 1, "{all}");
    assert_eq!(all.matches("removed rule tests").count(), 1, "{all}");
    assert_eq!(all.matches(&waits("commits")).count(), 1, "{all}");
    assert_eq!(all.matches(&waits("naming")).count(), 1, "{all}");
    // It made no exchange of its own, so it has no report of one, and nothing is held.
    assert!(!all.contains("Synced "), "{all}");
    assert!(!all.contains("is held on this machine"), "{all}");
    drop(daemon);
}

/// Needs working multicast between processes on this machine and a non-loopback IPv4
/// interface, which CI containers often lack. Run it with `-- --ignored`.
#[test]
#[ignore = "needs multicast on the local network"]
fn members_find_each_other_on_the_local_network() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let alice = Node::new(root, "alice");
    let bob = Node::new(root, "bob");
    let nobody = Node::new(root, "nobody");
    let created = alice.run(&["circle", "create", "team"]);
    let fingerprint = created["root_fingerprint"].as_str().unwrap().to_owned();
    alice.run(&[
        "circle",
        "invite",
        &bob.device_key(),
        "--circle",
        "team",
        "--member",
        "bob",
        "--yes",
        "--out",
        root.join("unused.jsonl").to_str().unwrap(),
    ]);
    bob.join(&alice, root, &fingerprint);
    let cand = alice.run(&["note", RULE])["candidate_id"]
        .as_str()
        .unwrap()
        .to_owned();
    alice.run(&["proposal", "create", &cand, "--circle", "team", "--yes"]);

    // Without --lan nothing is announced, so nobody is found.
    let quiet = alice.daemon_with(&["--listen", "/ip4/0.0.0.0/udp/0/quic-v1"]);
    assert_eq!(bob.fail(&["sync", "--lan", "--wait", "2"]).0, 2);
    drop(quiet);

    let daemon = alice.daemon_with(&["--listen", "/ip4/0.0.0.0/udp/0/quic-v1", "--lan"]);
    // Bob was given no address. He finds Alice's node because her device is on a roll
    // he holds, and gets the proposal.
    let synced = bob.run(&["sync", "--lan", "--wait", "10"]);
    assert_eq!(synced["failed"], serde_json::json!([]));
    assert_eq!(synced["synced"][0]["peer_id"], daemon.peer_id.as_str());
    assert_eq!(synced["synced"][0]["received"], 1);
    // The address he found her at is stored like any other.
    let again = bob.run(&["sync"]);
    assert_eq!(again["synced"][0]["peer_id"], daemon.peer_id.as_str());
    // A node in no circle hears the announcement too and contacts nobody.
    let (code, msg) = nobody.fail(&["sync", "--lan", "--wait", "2"]);
    assert_eq!(code, 2, "{msg}");
    assert!(msg.contains("no member of your circles"), "{msg}");
}

/// The internet mode, end to end, with real processes. The public network is replaced
/// by a hub on loopback that answers like its servers do; the lookups, the handshakes
/// and the sync are the real ones.
#[test]
fn members_find_each_other_by_device_key_over_a_dht() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let hub = runtime.block_on(hub::Hub::start(200, hub::HubOptions::default()));
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let alice = Node::new(root, "alice").on(&hub);
    let bob = Node::new(root, "bob").on(&hub);
    let mallory = Node::new(root, "mallory").on(&hub);
    let peer_id = |node: &Node| {
        node.run(&["status"])["peer_id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    // Who asked the hub for whose key.
    let asked = |who: &str, whom: &str| {
        let who: ph_network::PeerId = who.parse().unwrap();
        let whom: ph_network::PeerId = whom.parse().unwrap();
        hub.state()
            .asked
            .iter()
            .any(|(peer, key)| *peer == who && *key == whom.to_bytes())
    };

    let created = alice.run(&["circle", "create", "team"]);
    let fingerprint = created["root_fingerprint"].as_str().unwrap().to_owned();
    alice.run(&[
        "circle",
        "invite",
        &bob.device_key(),
        "--circle",
        "team",
        "--member",
        "bob",
        "--yes",
        "--out",
        root.join("unused.jsonl").to_str().unwrap(),
    ]);
    let alice_id = peer_id(&alice);

    // What is refused before anything goes on a network.
    let (code, msg) = bob.fail(&["circle", "join", &alice_id]);
    assert_eq!(code, 2, "{msg}");
    assert!(msg.contains("--internet"), "{msg}");
    assert_eq!(bob.fail(&["sync", "--wait", "5"]).0, 2);
    assert_eq!(bob.fail(&["sync", "--internet", "--lan"]).0, 2);
    // Nobody is on the network yet, and Bob holds no circle: there is nobody to look for.
    let (code, msg) = bob.fail(&["sync", "--internet", "--wait", "3"]);
    assert_eq!(code, 2, "{msg}");
    assert!(msg.contains("nobody to look for"), "{msg}");
    assert!(!asked(&peer_id(&bob), &alice_id));

    // Alice's node goes on the network. She gave it no address to listen on.
    let daemon = alice.daemon_with(&["--internet"]);
    assert_eq!(daemon.peer_id, alice_id);
    let standing = alice.wait_joined();
    assert!(standing["reachability"].is_string(), "{standing}");

    // Bob was given a peer id and a fingerprint, no address. His node finds hers,
    // which answers because the admission that passed put his device on its roll.
    let wrong = [
        "circle",
        "join",
        &alice_id,
        "--internet",
        "--expect-fingerprint",
        "0000-0000-0000-0000-0000",
        "--yes",
    ];
    let join = [
        "circle",
        "join",
        &alice_id,
        "--internet",
        "--expect-fingerprint",
        &fingerprint,
        "--yes",
        "--name",
        "team",
    ];
    let joined = bob.eventually(&join);
    assert_eq!(joined["peer_id"], alice_id.as_str(), "{joined}");
    assert_eq!(bob.roll(), ["alice", "bob"]);
    assert!(
        asked(&peer_id(&bob), &alice_id),
        "the hub was asked for her key"
    );
    // He is in it now, so there is nothing left to join there.
    let (code, msg) = bob.fail(&wrong);
    assert_eq!(code, 3, "{msg}");

    // A rule, proposed and approved on Alice's node. Bob's node looks up the devices
    // on his roll, finds hers and fetches it.
    let cand = alice.run(&["note", RULE])["candidate_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let rule = alice.run(&["proposal", "create", &cand, "--circle", "team", "--yes"])
        ["proposal_id"]
        .as_str()
        .unwrap()
        .to_owned();
    alice.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    let synced = bob.run(&["sync", "--internet", "--wait", "20"]);
    assert_eq!(synced["failed"], serde_json::json!([]), "{synced}");
    assert_eq!(synced["synced"][0]["peer_id"], alice_id.as_str());
    assert_eq!(synced["synced"][0]["received"], 2, "{synced}");
    assert_eq!(synced["synced"][0]["bundles"], 1);
    assert_eq!(
        (synced["looked_up"].as_u64(), synced["not_found"].as_u64()),
        (Some(1), Some(0)),
        "{synced}"
    );

    // He approves: two of two. One member, named by peer id, is looked up and takes
    // his ballot; her daemon installs the rule.
    assert_eq!(
        bob.run(&["proposal", "vote", &rule, "approve", "--yes"])["passed"],
        true
    );
    let synced = bob.run(&["sync", &alice_id, "--internet"]);
    assert_eq!(synced["sent"], 2, "{synced}");
    assert!(alice.has_skill(), "the daemon applied the passed rule");

    // Mallory is on no roll. Her node does not look anybody up for a sync: the device
    // she names is on no roll she holds.
    let mallory_id = peer_id(&mallory);
    let (code, msg) = mallory.fail(&["sync", &alice_id, "--internet"]);
    assert_eq!(code, 3, "{msg}");
    assert!(msg.contains("on no roll"), "{msg}");
    assert!(!asked(&mallory_id, &alice_id));
    // She can find Alice's node by its peer id, like anybody can, and is told nothing.
    let attempt = [
        "circle",
        "join",
        &alice_id,
        "--internet",
        "--expect-fingerprint",
        &fingerprint,
        "--yes",
    ];
    let (code, msg) = mallory.fail(&attempt);
    assert_eq!(code, 3, "{msg}");
    assert!(
        msg.contains("does not have this device on the roll"),
        "{msg}"
    );
    assert!(asked(&mallory_id, &alice_id));
    assert_eq!(mallory.run(&["status"])["circles"], serde_json::json!([]));

    // When Alice's node is gone, nobody is found, and Bob is told why.
    drop(daemon);
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        let out = bob
            .cmd(&["sync", "--internet", "--wait", "3"])
            .output()
            .unwrap();
        if out.status.code() == Some(2) {
            let json: Value = serde_json::from_slice(&out.stdout).unwrap();
            let msg = json["error"]["message"].as_str().unwrap();
            assert!(msg.contains("daemon --internet"), "{msg}");
            break;
        }
        assert!(Instant::now() < deadline, "her node is still found");
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// `--internet` and a loopback address do not go together, and the node says so before
/// it starts anything.
#[test]
fn internet_mode_refuses_a_loopback_listener() {
    let tmp = TempDir::new().unwrap();
    let node = Node::new(tmp.path(), "alice");
    let (code, msg) = node.fail(&["daemon", "--internet", "--listen", LISTEN]);
    assert_eq!(code, 2, "{msg}");
    assert!(msg.contains("loopback"), "{msg}");
    assert!(!node.home.join("daemon.json").exists());
}
