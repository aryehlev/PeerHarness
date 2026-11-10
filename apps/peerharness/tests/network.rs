//! Separate OS processes talking over real QUIC on loopback: one node runs `daemon`, the
//! others `sync` with it. No shared database, no mock transport.
//!
//! Covered here: a rule proposed on one node, voted on another and installed on both;
//! an admission and a removal decided by ballots that arrive over the network, with the
//! founder's daemon issuing the charters; and the three ways a node that is not on the
//! roll is turned away.

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
        vec![
            ("PEERHARNESS_HOME", self.home.clone().into()),
            ("PEERHARNESS_CLAUDE_SKILLS_DIR", self.skills.clone().into()),
            ("USER", self.name.into()),
        ]
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("peerharness").unwrap();
        cmd.envs(self.envs())
            .env_remove("CLAUDECODE")
            .env_remove("PEERHARNESS_AGENT_SESSION")
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
        let bin = assert_cmd::cargo::cargo_bin("peerharness");
        let child = std::process::Command::new(bin)
            .envs(self.envs())
            .env_remove("CLAUDECODE")
            .args(["daemon", "--listen", LISTEN])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
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

    // Carol joins from a file (a new member is not on any roll she holds yet), then
    // syncs like everyone else. The rule from before her time is installed for her.
    carol.join(&alice, root, &fingerprint);
    assert!(carol.has_skill());
    let synced = carol.run(&["sync", &daemon.addr]);
    assert_eq!(synced["refused_by_peer"], 0);

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
    let (code, msg) = bob.fail(&["sync", &daemon.addr]);
    assert_eq!(code, 3, "{msg}");
    assert!(msg.contains("does not recognize this node"), "{msg}");
    assert_eq!(bob.charter_seq(), 3, "he was told nothing more");
}
