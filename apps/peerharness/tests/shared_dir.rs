//! Two nodes exchange their circle through a directory each of them holds a copy of, the
//! way a team would through a git repository: sync, "push" (here: copy the files the
//! other side lacks), sync. Every record is its own file, so the two copies merge by
//! union with nothing to resolve.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

const RULE: &str = "Use pnpm, not npm, in this repository.";
const SKILL: &str = "use-pnpm-not-npm-repository";

struct Node {
    name: &'static str,
    home: PathBuf,
    skills: PathBuf,
    /// This member's checkout of the shared directory.
    shared: PathBuf,
}

impl Node {
    fn new(root: &Path, name: &'static str) -> Self {
        let node = Self {
            name,
            home: root.join(name),
            skills: root.join(format!("{name}-skills")),
            shared: root
                .join(format!("{name}-checkout"))
                .join(".peerharness/team"),
        };
        node.run(&[
            "init",
            "--keystore",
            "insecure-dev",
            "--insecure-dev-keystore",
        ]);
        node
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("peerharness").unwrap();
        cmd.env("PEERHARNESS_HOME", &self.home)
            .env("PEERHARNESS_CLAUDE_SKILLS_DIR", &self.skills)
            .env_remove("CLAUDECODE")
            .env_remove("PEERHARNESS_AGENT_SESSION")
            .env("USER", self.name)
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
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn sync(&self) -> Value {
        self.run(&["events", "sync", self.shared.to_str().unwrap()])
    }

    fn has_skill(&self) -> bool {
        self.skills.join(SKILL).join("SKILL.md").is_file()
    }

    fn record_files(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.shared)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("event-") || n.starts_with("bundle-"))
            .collect();
        names.sort();
        names
    }
}

/// What `git pull` and `git push` amount to for a directory of content-named files:
/// each side gets the files it lacks. Returns how many files moved.
fn merge(a: &Node, b: &Node) -> usize {
    let mut moved = 0;
    for (from, to) in [(a, b), (b, a)] {
        std::fs::create_dir_all(&to.shared).unwrap();
        for entry in std::fs::read_dir(&from.shared).unwrap() {
            let entry = entry.unwrap();
            let target = to.shared.join(entry.file_name());
            if !target.exists() {
                std::fs::copy(entry.path(), &target).unwrap();
                moved += 1;
            }
        }
    }
    moved
}

#[test]
fn two_members_vote_through_a_shared_directory() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let alice = Node::new(root, "alice");
    let bob = Node::new(root, "bob");

    // --- Alice founds the circle and admits Bob. The records go into her checkout.
    let created = alice.run(&["circle", "create", "team"]);
    let fingerprint = created["root_fingerprint"].as_str().unwrap().to_owned();
    let bob_key = bob.run(&["status"])["device_key"]
        .as_str()
        .unwrap()
        .to_owned();
    let invite = root.join("unused-invite.jsonl");
    alice.run(&[
        "circle",
        "invite",
        &bob_key,
        "--circle",
        "team",
        "--member",
        "bob",
        "--yes",
        "--out",
        invite.to_str().unwrap(),
    ]);
    let synced = alice.sync();
    assert!(synced["written"].as_u64().unwrap() >= 4, "{synced}");
    assert!(alice.shared.join("README.md").is_file());
    // Nothing new: a second sync writes nothing.
    assert_eq!(alice.sync()["written"], 0);

    // --- Bob pulls and joins straight from the directory.
    merge(&alice, &bob);
    let joined = bob.run(&[
        "circle",
        "join",
        bob.shared.to_str().unwrap(),
        "--expect-fingerprint",
        &fingerprint,
        "--yes",
        "--name",
        "team",
    ]);
    assert_eq!(joined["member"], "bob");
    assert_eq!(joined["charter_seq"], 2);

    // --- Alice proposes a rule and votes; Bob adds his ballot at the same time as
    // Alice adds an unrelated note of her own. Both push.
    let cand = alice.run(&["note", RULE])["candidate_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let rule = alice.run(&["proposal", "create", &cand, "--circle", "team", "--yes"])
        ["proposal_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let voted = alice.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    assert_eq!(voted["passed"], false, "one of two is not a majority");
    alice.sync();
    merge(&alice, &bob);

    let pulled = bob.sync();
    assert!(pulled["stored"].as_u64().unwrap() >= 2, "{pulled}");
    assert_eq!(pulled["bundles"], 1);
    let shown = bob.run(&["proposal", "show", &rule]);
    assert_eq!(shown["standing"], "open");
    let voted = bob.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    assert_eq!(voted["passed"], true);
    assert!(bob.has_skill());
    let pushed = bob.sync();
    assert!(pushed["written"].as_u64().unwrap() >= 1);

    // Meanwhile Alice wrote more records of her own: a second proposal. The two
    // checkouts now differ in both directions.
    let other = alice.run(&["note", "Never edit generated files by hand."])["candidate_id"]
        .as_str()
        .unwrap()
        .to_owned();
    alice.run(&["proposal", "create", &other, "--circle", "team", "--yes"]);
    alice.sync();
    assert_ne!(alice.record_files(), bob.record_files());

    // --- Union merge: no file exists on both sides with different content.
    assert!(merge(&alice, &bob) >= 2);
    assert_eq!(alice.record_files(), bob.record_files());

    let pulled = alice.sync();
    assert_eq!(pulled["installed"], serde_json::json!([SKILL]));
    assert!(alice.has_skill());
    assert_eq!(
        alice.run(&["proposal", "show", &rule])["standing"],
        "passed"
    );
    let pulled = bob.sync();
    assert!(
        pulled["stored"].as_u64().unwrap() >= 1,
        "Alice's second proposal"
    );
    // (Bob joined at charter 2, so the vote that admitted him is not among his
    // proposals; everything since then is.)
    let titles: Vec<String> = bob.run(&["proposal", "list"])["proposals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["title"].as_str().unwrap().to_owned())
        .collect();
    assert!(titles.contains(&RULE.to_owned()), "{titles:?}");
    assert!(
        titles.contains(&"Never edit generated files by hand.".to_owned()),
        "{titles:?}"
    );

    // --- Settled: once both have everything, syncing changes nothing on either side.
    merge(&alice, &bob);
    alice.sync();
    merge(&alice, &bob);
    for node in [&alice, &bob] {
        let again = node.sync();
        assert_eq!(again["stored"], 0, "{}", node.name);
        assert_eq!(again["written"], 0, "{}", node.name);
        assert_eq!(again["rejected"], 0, "{}", node.name);
    }
}

#[test]
fn a_shared_directory_is_not_trusted() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let alice = Node::new(root, "alice");
    let mallory = Node::new(root, "mallory");
    alice.run(&["circle", "create", "team"]);
    let cand = alice.run(&["note", RULE])["candidate_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let rule = alice.run(&["proposal", "create", &cand, "--circle", "team", "--yes"])
        ["proposal_id"]
        .as_str()
        .unwrap()
        .to_owned();
    alice.sync();
    let files = alice.record_files();
    let proposal_file = alice.shared.join(format!(
        "event-{}.json",
        rule.strip_prefix("sha256:").unwrap()
    ));
    assert!(files.iter().any(|f| proposal_file.ends_with(f)));
    let original = std::fs::read_to_string(&proposal_file).unwrap();

    // Someone with write access to the repository edits the proposal's text, drops in a
    // file that is no record, and plants a link named like a record.
    let tampered = original.replace("pnpm", "yarn");
    assert_ne!(tampered, original);
    std::fs::write(&proposal_file, &tampered).unwrap();
    std::fs::write(alice.shared.join("notes.txt"), "not a record").unwrap();
    let secret = root.join("secret.txt");
    std::fs::write(&secret, "outside the directory").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        &secret,
        alice.shared.join(format!("event-{}.json", "77".repeat(32))),
    )
    .unwrap();

    // Alice's node refuses the edited record, leaves the strangers alone, and puts the
    // record it had verified back.
    let synced = alice.sync();
    assert_eq!(synced["stored"], 0);
    assert_eq!(synced["rejected"], 1, "{synced}");
    assert_eq!(synced["ignored"], if cfg!(unix) { 2 } else { 1 });
    assert_eq!(synced["written"], 1);
    assert_eq!(std::fs::read_to_string(&proposal_file).unwrap(), original);
    assert_eq!(
        std::fs::read_to_string(&secret).unwrap(),
        "outside the directory"
    );
    let shown = alice.run(&["proposal", "show", &rule]);
    assert_eq!(shown["title"], RULE);

    // A node that is in no circle takes nothing from the directory and cannot join by it.
    let imported = mallory.run(&["events", "import", alice.shared.to_str().unwrap()]);
    assert_eq!(imported["stored"], 0);
    assert_eq!(imported["bundles"], 0);
    let out = mallory
        .cmd(&["circle", "join", alice.shared.to_str().unwrap(), "--yes"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));

    // Writing records out is the person's step: refused inside an agent's session.
    for args in [
        vec!["events", "sync", alice.shared.to_str().unwrap()],
        vec!["events", "export", "--circle", "team"],
    ] {
        let out = alice.cmd(&args).env("CLAUDECODE", "1").output().unwrap();
        assert_eq!(out.status.code(), Some(3), "{args:?}");
    }
    // Reading them in is not.
    let out = alice
        .cmd(&["events", "import", alice.shared.to_str().unwrap()])
        .env("CLAUDECODE", "1")
        .output()
        .unwrap();
    assert!(out.status.success());
}
