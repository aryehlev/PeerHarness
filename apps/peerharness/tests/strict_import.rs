//! Records that arrive as a file or as a directory, driven through the real binary on
//! separate nodes: separate homes, keys, databases and skills directories.
//!
//! A line of a file and a record file of a directory are held to what a frame from the
//! wire is held to before anything in them is looked at: a size limit, no member twice,
//! no member that is not known, no explicit `null`. What does not pass is refused and
//! counted, and the other records of the same file are still imported.
//!
//! `circle join <file|directory>` looks only at the charters of the circle whose root
//! fingerprint its owner gave. A charter of another circle in the same file, however
//! high its number, changes neither what is joined nor what is refused.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

const PASSPHRASE: &str = "test-passphrase-not-real";

/// Most bytes of one record, as a line of a file or as a record file
/// (`carrier::MAX_ENTRY_BYTES`).
const RECORD_LIMIT: usize = 1024 * 1024;

/// What a line of an export starts with when it carries an event.
const EVENT_PREFIX: &str = r#"{"event":"#;

struct Node {
    name: &'static str,
    home: PathBuf,
    skills: PathBuf,
    settings: PathBuf,
    cwd: PathBuf,
    fake_home: PathBuf,
    /// Stands in for a confirmation window. Windows are off in every test here: the
    /// stand-in only declines, so that nothing could open a real one.
    window: PathBuf,
}

impl Node {
    fn new(root: &Path, name: &'static str) -> Self {
        let dir = root.join(name);
        let node = Self {
            name,
            home: dir.join("home"),
            skills: dir.join("skills"),
            settings: dir.join("claude-settings.json"),
            cwd: dir.join("project"),
            fake_home: dir.join("fakehome"),
            window: dir.join("window.sh"),
        };
        std::fs::create_dir_all(&node.cwd).unwrap();
        std::fs::create_dir_all(&node.fake_home).unwrap();
        std::fs::write(&node.window, "#!/bin/sh\ncat > /dev/null\necho declined\n").unwrap();
        std::fs::set_permissions(&node.window, std::fs::Permissions::from_mode(0o755)).unwrap();
        node.run(&[
            "init",
            "--keystore",
            "file",
            "--kdf-profile",
            "fast-insecure-test",
        ]);
        node
    }

    /// The person of this node, in their own terminal: the suite itself may be run by
    /// a coding agent, so the marks of a session are taken out.
    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("peerharness").unwrap();
        cmd.current_dir(&self.cwd)
            .env("PEERHARNESS_HOME", &self.home)
            .env("PEERHARNESS_PASSPHRASE", PASSPHRASE)
            .env("PEERHARNESS_CLAUDE_SKILLS_DIR", &self.skills)
            .env("PEERHARNESS_CLAUDE_SETTINGS", &self.settings)
            .env("PEERHARNESS_TEST_WINDOW_BIN", &self.window)
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
            .arg("--json")
            .args(args);
        cmd
    }

    /// Runs a command that must succeed and returns its JSON report.
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
        serde_json::from_slice(&out.stdout).unwrap_or(Value::Null)
    }

    /// Runs a command that must fail: its exit code and error message.
    fn fail(&self, args: &[&str]) -> (i32, String) {
        let out = self.cmd(args).output().unwrap();
        assert!(
            !out.status.success(),
            "{} {:?} should fail:\n{}",
            self.name,
            args,
            String::from_utf8_lossy(&out.stdout)
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

    /// The ids of the circles this node is in.
    fn circles(&self) -> Vec<String> {
        self.run(&["status"])["circles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["circle_id"].as_str().unwrap().to_owned())
            .collect()
    }

    /// Founds a circle named `circle` and returns its id and its root fingerprint.
    fn found(&self, circle: &str) -> (String, String) {
        let created = self.run(&["circle", "create", circle]);
        (
            created["circle_id"].as_str().unwrap().to_owned(),
            created["root_fingerprint"].as_str().unwrap().to_owned(),
        )
    }

    /// Proposes admitting `key` as `member` and returns the report. Alone on the roll,
    /// the proposer's approval passes it.
    fn admit(&self, circle: &str, key: &str, member: &str, out: Option<&str>) -> Value {
        let mut args = vec![
            "circle", "invite", key, "--circle", circle, "--member", member, "--yes",
        ];
        if let Some(out) = out {
            args.extend(["--out", out]);
        }
        self.run(&args)
    }

    fn export(&self, root: &Path, circle: &str, tag: &str) -> String {
        let path = path_str(&root.join(format!("{}-{tag}.jsonl", self.name)));
        self.run(&["events", "export", "--circle", circle, "--out", &path]);
        path
    }

    fn export_dir(&self, circle: &str, dir: &Path) {
        self.run(&[
            "events",
            "export",
            "--circle",
            circle,
            "--dir",
            &path_str(dir),
        ]);
    }

    fn import(&self, from: &str) -> Value {
        self.run(&["events", "import", from])
    }

    /// Notes `rule` and puts it to the vote of `team`, without a ballot.
    fn propose(&self, rule: &str) -> Offer {
        let candidate = self.run(&["note", rule])["candidate_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let made = self.run(&[
            "proposal", "create", &candidate, "--circle", "team", "--yes",
        ]);
        Offer {
            id: made["proposal_id"].as_str().unwrap().to_owned(),
            bundle: made["bundle_digest"].as_str().unwrap().to_owned(),
            title: rule.to_owned(),
        }
    }

    /// The titles of the proposals this node holds.
    fn titles(&self) -> Vec<String> {
        self.run(&["proposal", "list"])["proposals"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["title"].as_str().unwrap().to_owned())
            .collect()
    }
}

/// A proposed rule: the id of its PROPOSAL, the digest of its text, and its title.
struct Offer {
    id: String,
    bundle: String,
    title: String,
}

fn path_str(path: &Path) -> String {
    path.to_str().unwrap().to_owned()
}

fn lines_of(file: &str) -> Vec<String> {
    std::fs::read_to_string(file)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn write_lines(path: &Path, lines: &[String]) -> String {
    std::fs::write(path, lines.join("\n") + "\n").unwrap();
    path_str(path)
}

/// The line of `lines` that carries the event `id`.
fn event_line(lines: &[String], id: &str) -> String {
    lines
        .iter()
        .find(|l| serde_json::from_str::<Value>(l).is_ok_and(|v| v["event"]["event_id"] == id))
        .unwrap_or_else(|| panic!("no line carries {id}"))
        .clone()
}

/// The line of `lines` that carries the rule text with `digest`.
fn bundle_line(lines: &[String], digest: &str) -> String {
    lines
        .iter()
        .find(|l| serde_json::from_str::<Value>(l).is_ok_and(|v| v["bundle"]["digest"] == digest))
        .unwrap_or_else(|| panic!("no line carries {digest}"))
        .clone()
}

/// The JSON text of the event object a line carries: `{"event":<this>}`.
fn event_text(line: &str) -> &str {
    line.strip_prefix(EVENT_PREFIX)
        .and_then(|rest| rest.strip_suffix('}'))
        .filter(|event| event.starts_with('{') && event.ends_with('}'))
        .expect("an export line that carries an event")
}

/// The same line with a member of the event stated twice. A parser that keeps the last
/// of two members reads the signed PROPOSAL or CHARTER; one that keeps the first reads
/// a VOTE. The strict parser refuses the line.
fn with_a_member_twice(line: &str) -> String {
    format!(
        r#"{EVENT_PREFIX}{{"type":"VOTE",{}}}"#,
        &event_text(line)[1..]
    )
}

/// The same line, padded with spaces (which no JSON parser minds) to `len` bytes.
fn padded_to(line: &str, len: usize) -> String {
    let event = event_text(line);
    let padding = len - EVENT_PREFIX.len() - event.len() - 1;
    format!("{EVENT_PREFIX}{}{event}}}", " ".repeat(padding))
}

fn record_file(dir: &Path, kind: &str, id: &str) -> PathBuf {
    dir.join(format!(
        "{kind}-{}.json",
        id.strip_prefix("sha256:").unwrap()
    ))
}

/// `circle join <from>` as `name`, by the root fingerprint the founder gave.
fn join<'a>(from: &'a str, fingerprint: &'a str, name: &'a str) -> [&'a str; 8] {
    [
        "circle",
        "join",
        from,
        "--expect-fingerprint",
        fingerprint,
        "--yes",
        "--name",
        name,
    ]
}

/// Alice founds `team` and admits Bob, who joins. Returns the two nodes.
fn alice_and_bob(root: &Path) -> (Node, Node) {
    let alice = Node::new(root, "alice");
    let bob = Node::new(root, "bob");
    let (_, fingerprint) = alice.found("team");
    let for_bob = path_str(&root.join("for-bob.jsonl"));
    let invited = alice.admit("team", &bob.device_key(), "bob", Some(&for_bob));
    assert_eq!(invited["passed"], true);
    bob.run(&join(&for_bob, &fingerprint, "team"));
    (alice, bob)
}

const RULES: [&str; 8] = [
    "Use pnpm, not npm, in this repository.",
    "Never edit generated files by hand.",
    "Run the formatter before every commit.",
    "Write commit messages in the imperative mood.",
    "Keep every public function documented.",
    "Prefer small pull requests over large ones.",
    "Name test files after the module they cover.",
    "Update the changelog with every user-visible change.",
];

/// Seven sound, signed proposals, each in a line that is not a record in strict JSON,
/// and an eighth in a line that is exactly as long as a record may be. The five lines
/// marked "new" are what the strict parser is for: plain serde_json read them, and
/// their proposals were stored. The other two were refused before as well, by the
/// checks on the event itself.
#[test]
fn a_line_of_a_file_is_parsed_as_strictly_as_a_frame_from_the_wire() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let (alice, bob) = alice_and_bob(root);
    let offers: Vec<Offer> = RULES.iter().map(|rule| alice.propose(rule)).collect();
    let export = alice.export(root, "team", "eight");
    let all = lines_of(&export);
    let line = |i: usize| event_line(&all, &offers[i].id);
    let event = |i: usize| event_text(&line(i)).to_owned();
    let good = &offers[7];

    let crafted = vec![
        // A member twice, inside the event (new).
        with_a_member_twice(&line(0)),
        // A member twice, in the line itself: an empty event and then the signed one (new).
        format!(r#"{{"event":{{}},"event":{}}}"#, event(1)),
        // A member the event does not have.
        format!(r#"{EVENT_PREFIX}{{"extra":1,{}}}"#, &event(2)[1..]),
        // A member a line does not have (new).
        format!(r#"{EVENT_PREFIX}{},"note":"x"}}"#, event(3)),
        // An explicit null for an optional member of the event.
        line(4).replacen(r#""body":{"#, r#""body":{"supersedes":null,"#, 1),
        // An explicit null in the line itself (new).
        format!(r#"{{"bundle":null,"event":{}}}"#, event(5)),
        // One byte over the size limit: the padding is only spaces (new).
        padded_to(&line(6), RECORD_LIMIT + 1),
        // Exactly at the limit, and otherwise as exported: this one is a record.
        padded_to(&line(7), RECORD_LIMIT),
        bundle_line(&all, &good.bundle),
    ];
    assert_ne!(crafted[4], line(4));
    assert_eq!(crafted[6].len(), RECORD_LIMIT + 1);
    assert_eq!(crafted[7].len(), RECORD_LIMIT);
    let file = write_lines(&root.join("crafted.jsonl"), &crafted);

    let imported = bob.import(&file);
    assert_eq!(imported["rejected"], 7, "{imported}");
    assert_eq!(imported["stored"], 1, "{imported}");
    assert_eq!(imported["bundles"], 1, "{imported}");
    assert_eq!(imported["duplicate"], 0, "{imported}");
    assert_eq!(imported["deferred"], 0, "{imported}");
    let titles = bob.titles();
    assert!(titles.contains(&good.title), "{titles:?}");
    for refused in &offers[..7] {
        assert!(!titles.contains(&refused.title), "{}", refused.title);
    }

    // Nothing was wrong with the seven proposals themselves: the same events in the
    // lines Alice's node wrote are all stored, with their rule texts.
    let imported = bob.import(&export);
    assert_eq!(imported["stored"], 7, "{imported}");
    assert_eq!(imported["bundles"], 7, "{imported}");
    assert_eq!(imported["rejected"], 0, "{imported}");
    let titles = bob.titles();
    for offer in &offers {
        assert!(titles.contains(&offer.title), "{}", offer.title);
    }
}

/// The same for a directory, where every record is a file of its own.
#[test]
fn a_record_file_of_a_directory_is_parsed_as_strictly() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let (alice, bob) = alice_and_bob(root);
    let offers: Vec<Offer> = RULES[..5].iter().map(|rule| alice.propose(rule)).collect();
    let dir = root.join("shared");
    alice.export_dir("team", &dir);
    let read = |i: usize| {
        std::fs::read_to_string(record_file(&dir, "event", &offers[i].id))
            .unwrap()
            .trim()
            .to_owned()
    };
    let rewrite = |i: usize, line: String| {
        std::fs::write(record_file(&dir, "event", &offers[i].id), line + "\n").unwrap();
    };
    // Three record files a lenient parser would read, and one that is too large to be
    // read at all. The rule texts of those four proposals are taken out, so that what
    // is counted below is the record files alone.
    rewrite(0, with_a_member_twice(&read(0)));
    rewrite(
        1,
        format!(r#"{EVENT_PREFIX}{},"note":"x"}}"#, event_text(&read(1))),
    );
    rewrite(
        2,
        format!(r#"{{"bundle":null,"event":{}}}"#, event_text(&read(2))),
    );
    rewrite(3, padded_to(&read(3), RECORD_LIMIT + 1));
    for offer in &offers[..4] {
        std::fs::remove_file(record_file(&dir, "bundle", &offer.bundle)).unwrap();
    }

    let imported = bob.import(&path_str(&dir));
    assert_eq!(imported["rejected"], 3, "{imported}");
    assert_eq!(
        imported["ignored"], 1,
        "the oversized file is not read: {imported}"
    );
    assert_eq!(imported["stored"], 1, "{imported}");
    assert_eq!(imported["bundles"], 1, "{imported}");
    let titles = bob.titles();
    assert!(titles.contains(&offers[4].title), "{titles:?}");
    for refused in &offers[..4] {
        assert!(!titles.contains(&refused.title), "{}", refused.title);
    }
}

/// `circle join` reads the charter it shows its owner from the same lines, with the same
/// parser: a CHARTER in a line that states a member twice is not a charter to join by.
#[test]
fn a_charter_in_a_line_that_is_not_strict_json_is_not_joined_from() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let alice = Node::new(root, "alice");
    let bob = Node::new(root, "bob");
    let (circle, fingerprint) = alice.found("team");
    let for_bob = path_str(&root.join("for-bob.jsonl"));
    alice.admit("team", &bob.device_key(), "bob", Some(&for_bob));

    let mut charters = 0;
    let tampered: Vec<String> = lines_of(&for_bob)
        .iter()
        .map(|line| {
            let is_charter =
                serde_json::from_str::<Value>(line).is_ok_and(|v| v["event"]["type"] == "CHARTER");
            if is_charter {
                charters += 1;
                with_a_member_twice(line)
            } else {
                line.clone()
            }
        })
        .collect();
    assert_eq!(
        charters, 2,
        "the founding charter and the one that admits Bob"
    );
    let tampered = write_lines(&root.join("tampered.jsonl"), &tampered);

    let (code, message) = bob.fail(&join(&tampered, &fingerprint, "team"));
    assert_eq!(code, 3, "{message}");
    assert!(
        message.contains("no charter with this device on its roll"),
        "{message}"
    );
    assert!(bob.circles().is_empty());

    // The file as Alice's node wrote it is joined from.
    let joined = bob.run(&join(&for_bob, &fingerprint, "team"));
    assert_eq!(joined["circle_id"], circle.as_str());
    assert_eq!(bob.circles(), vec![circle]);
}

/// Bob was admitted to Alice's circle `team`, at charter 2. The file and the directory
/// he is to join from also hold the records of another circle, `other`, whose founder
/// put Bob's device key on its roll at charter 4.
struct TwoCircles {
    bob: Node,
    team: String,
    team_fingerprint: String,
    other: String,
    other_fingerprint: String,
    /// A file with the records of both circles, the other circle's first.
    file: String,
    /// A directory with the records of both circles.
    dir: String,
}

fn two_circles_that_list_bob(root: &Path) -> TwoCircles {
    let alice = Node::new(root, "alice");
    let mallory = Node::new(root, "mallory");
    let bob = Node::new(root, "bob");
    let bob_key = bob.device_key();

    let (team, team_fingerprint) = alice.found("team");
    let for_bob = path_str(&root.join("for-bob.jsonl"));
    let invited = alice.admit("team", &bob_key, "bob", Some(&for_bob));
    assert_eq!(invited["charter_seq"], 2);

    // The other circle: two changes of its rules first, so that the charter that lists
    // Bob has a higher number than the one of Alice's circle.
    let (other, other_fingerprint) = mallory.found("other");
    assert_ne!(other_fingerprint, team_fingerprint);
    for (flag, seq) in [("--advisory", 2), ("--binding", 3)] {
        let amended = mallory.run(&["circle", "amend", "--circle", "other", flag, "--yes"]);
        assert_eq!(amended["charter_seq"], seq, "{amended}");
    }
    let admitted = mallory.admit("other", &bob_key, "bob", None);
    assert_eq!(admitted["charter_seq"], 4);
    let others = mallory.export(root, "other", "all");

    let mut both = lines_of(&others);
    both.extend(lines_of(&for_bob));
    let file = write_lines(&root.join("both.jsonl"), &both);
    let dir = root.join("shared");
    alice.export_dir("team", &dir);
    mallory.export_dir("other", &dir);
    TwoCircles {
        bob,
        team,
        team_fingerprint,
        other,
        other_fingerprint,
        file,
        dir: path_str(&dir),
    }
}

/// Before this was fixed, `circle join` took the highest-numbered charter that lists the
/// device, whatever its root key, and only then compared the fingerprint: with the
/// fingerprint of Alice's circle the join was refused, because charter 4 of the other
/// circle had been picked.
#[test]
fn the_expected_fingerprint_says_which_circle_is_joined_not_the_highest_charter() {
    let tmp = TempDir::new().unwrap();
    let two = two_circles_that_list_bob(tmp.path());
    let bob = &two.bob;

    // A fingerprint that is neither circle's still refuses, and nothing is joined.
    for from in [&two.file, &two.dir] {
        let (code, message) = bob.fail(&join(from, "0000-0000-0000-0000-0000", "team"));
        assert_eq!(code, 3, "{message}");
        assert!(message.contains("Do not join"), "{message}");
        assert!(bob.circles().is_empty());
    }

    // The fingerprint Alice gave Bob: her circle is joined, at the charter that admits
    // him, although the file holds a higher-numbered charter that lists his key.
    let joined = bob.run(&join(&two.file, &two.team_fingerprint, "team"));
    assert_eq!(joined["circle_id"], two.team.as_str());
    assert_eq!(joined["charter_seq"], 2);
    assert_eq!(joined["member"], "bob");
    // Nothing of the other circle came in with it.
    assert_eq!(bob.circles(), vec![two.team.clone()]);
    let members = bob.run(&["circle", "members", "--circle", "team"]);
    assert_eq!(members["charter"]["seq"], 2);

    // The choice follows the fingerprint in the other direction as well: asked for the
    // other circle by its fingerprint, the directory gives that one, at its newest
    // charter that lists this device.
    let joined = bob.run(&join(&two.dir, &two.other_fingerprint, "other"));
    assert_eq!(joined["circle_id"], two.other.as_str());
    assert_eq!(joined["charter_seq"], 4);
    let mut circles = bob.circles();
    circles.sort();
    let mut expected = vec![two.team.clone(), two.other.clone()];
    expected.sort();
    assert_eq!(circles, expected);
}

/// Without a fingerprint nothing says which of the two circles is meant, so none is
/// shown and none is joined: the highest charter number does not decide. Before this
/// was fixed the other circle's charter 4 was the one put before the owner.
#[test]
fn without_a_fingerprint_a_file_with_several_circles_is_not_joined_from() {
    let tmp = TempDir::new().unwrap();
    let two = two_circles_that_list_bob(tmp.path());
    let bob = &two.bob;
    for from in [&two.file, &two.dir] {
        let (code, message) = bob.fail(&["circle", "join", from]);
        assert_eq!(code, 2, "{message}");
        assert!(message.contains("several circles"), "{message}");
        assert!(message.contains("--expect-fingerprint"), "{message}");
        assert!(bob.circles().is_empty());
    }
}
