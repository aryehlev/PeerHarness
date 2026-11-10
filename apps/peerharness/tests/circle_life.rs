//! The life of a circle beyond admitting members and passing a rule, with separate
//! nodes driven only through the real binary: asking before proposing, a second device
//! for one member, changing the rules of the vote, leaving, the owner's mode, and the
//! founder's emergency revocation of a lost device.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

struct Node {
    name: &'static str,
    home: PathBuf,
    skills: PathBuf,
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

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("peerharness").unwrap();
        cmd.env("PEERHARNESS_HOME", &self.home)
            .env("PEERHARNESS_CLAUDE_SKILLS_DIR", &self.skills)
            // These tests play the people. Consent steps refuse inside an agent session,
            // and the test suite itself may be run by a coding agent.
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
        serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("{} {:?}: stdout is not JSON: {e}", self.name, args))
    }

    /// Runs a command that must fail and returns its exit code.
    fn fail(&self, args: &[&str]) -> i32 {
        let out = self.cmd(args).output().unwrap();
        assert!(
            !out.status.success(),
            "{} {:?} should fail",
            self.name,
            args
        );
        out.status.code().unwrap()
    }

    /// The same command as a coding agent's session would run it.
    fn fail_as_agent(&self, args: &[&str]) -> i32 {
        let out = self.cmd(args).env("CLAUDECODE", "1").output().unwrap();
        assert!(
            !out.status.success(),
            "{} {:?} should fail",
            self.name,
            args
        );
        out.status.code().unwrap()
    }

    fn device_key(&self) -> String {
        self.run(&["status"])["device_key"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn has_skill(&self, name: &str) -> bool {
        self.skills.join(name).join("SKILL.md").is_file()
    }

    fn charter(&self) -> Value {
        self.run(&["circle", "members", "--circle", "team"])["charter"].clone()
    }

    fn roll(&self) -> Vec<String> {
        self.charter()["roll"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["member"].as_str().unwrap().to_owned())
            .collect()
    }
}

fn names(v: &Value) -> Vec<&str> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect()
}

/// Carries every node's events to every other node, twice, so that what one node signs
/// on receiving something (a result, a charter) reaches the rest as well.
fn carry(root: &Path, nodes: &[&Node]) {
    for round in 0..2 {
        for from in nodes {
            let path = root.join(format!("{}-{round}.jsonl", from.name));
            let p = path.to_str().unwrap();
            from.run(&["events", "export", "--circle", "team", "--out", p]);
            for to in nodes {
                if to.name != from.name {
                    to.run(&["events", "import", p]);
                }
            }
        }
    }
}

/// Alice founds `team`, then Bob and Carol are admitted by vote and join. `carol_scope`
/// is the scope Carol's roll entry gets.
fn trio(root: &Path, carol_scope: &str) -> (Node, Node, Node, String) {
    let alice = Node::new(root, "alice");
    let bob = Node::new(root, "bob");
    let carol = Node::new(root, "carol");
    let created = alice.run(&["circle", "create", "team"]);
    let fingerprint = created["root_fingerprint"].as_str().unwrap().to_owned();

    let file = root.join("for-bob.jsonl");
    let file = file.to_str().unwrap().to_owned();
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
        &file,
    ]);
    join(&bob, &file, &fingerprint);

    let admission = alice.run(&[
        "circle",
        "invite",
        &carol.device_key(),
        "--circle",
        "team",
        "--member",
        "carol",
        "--scope",
        carol_scope,
        "--yes",
    ]);
    let id = admission["proposal_id"].as_str().unwrap().to_owned();
    carry(root, &[&alice, &bob]);
    bob.run(&["proposal", "vote", &id, "approve", "--yes"]);
    carry(root, &[&alice, &bob]);
    assert_eq!(alice.roll(), ["alice", "bob", "carol"]);

    let file = root.join("for-carol.jsonl");
    let file = file.to_str().unwrap().to_owned();
    alice.run(&["events", "export", "--circle", "team", "--out", &file]);
    join(&carol, &file, &fingerprint);
    (alice, bob, carol, fingerprint)
}

fn join(node: &Node, file: &str, fingerprint: &str) {
    node.run(&[
        "circle",
        "join",
        file,
        "--expect-fingerprint",
        fingerprint,
        "--yes",
        "--name",
        "team",
    ]);
}

/// Alice writes a rule down and proposes it. Returns `(proposal id, skill name)`.
fn propose(alice: &Node, text: &str) -> (String, String) {
    let noted = alice.run(&["note", text]);
    let candidate = noted["candidate_id"].as_str().unwrap().to_owned();
    let proposed = alice.run(&[
        "proposal", "create", &candidate, "--circle", "team", "--yes",
    ]);
    (
        proposed["proposal_id"].as_str().unwrap().to_owned(),
        proposed["skill_name"].as_str().unwrap().to_owned(),
    )
}

#[test]
fn a_question_is_asked_and_answered_by_members_of_the_roll() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let (alice, bob, carol, _) = trio(root, "team/backend");

    // --- Alice asks before proposing. Exactly the previewed text is shared.
    let noted = alice.run(&["note", "Use pnpm, not npm, in this repository."]);
    let candidate = noted["candidate_id"].as_str().unwrap().to_owned();
    // A coding agent cannot ask the circle on its user's behalf.
    assert_eq!(
        alice.fail_as_agent(&["question", "send", &candidate, "--circle", "team", "--yes"]),
        3
    );
    assert_eq!(
        alice.run(&["question", "list"])["asked"],
        serde_json::json!([])
    );
    let asked = alice.run(&["question", "send", &candidate, "--circle", "team", "--yes"]);
    let question = asked["question_id"].as_str().unwrap().to_owned();
    // The same candidate is not asked about twice.
    assert_eq!(
        alice.fail(&["question", "send", &candidate, "--circle", "team", "--yes"]),
        2
    );
    let listed = alice.run(&["question", "list"]);
    assert_eq!(listed["asked"][0]["question_id"], question.as_str());
    assert!(listed["asked"][0]["question"]
        .as_str()
        .unwrap()
        .contains("Use pnpm, not npm"));
    // Nobody answers their own question.
    assert_eq!(
        alice.fail(&["question", "answer", &question, "--answer", "agree", "--yes"]),
        2
    );

    // --- It reaches Bob's inbox. He answers, with a reason.
    carry(root, &[&alice, &bob, &carol]);
    let inbox = bob.run(&["inbox"]);
    assert_eq!(inbox["questions_total"], 1);
    assert_eq!(inbox["questions"][0]["question_id"], question.as_str());
    assert_eq!(
        bob.fail_as_agent(&["question", "answer", &question, "--answer", "agree", "--yes"]),
        3,
        "an agent cannot answer for its user"
    );
    let answered = bob.run(&[
        "question",
        "answer",
        &question,
        "--answer",
        "agree",
        "--rationale",
        "We already do this in CI.",
        "--yes",
    ]);
    assert_eq!(answered["status"], "answered");
    assert_eq!(bob.run(&["inbox"])["questions_total"], 0);

    // --- Carol's roll entry covers only team/backend. This question was asked of the
    // whole circle, so her answer is not hers to give: her own node refuses to sign it,
    // and no other node would accept it.
    assert_eq!(
        carol.fail(&["question", "answer", &question, "--answer", "disagree", "--yes"]),
        3
    );

    // --- Alice sees the answer, attributed to the member.
    carry(root, &[&alice, &bob, &carol]);
    let listed = alice.run(&["question", "list"]);
    let q = &listed["asked"][0];
    assert_eq!(
        (q["agree"].as_u64(), q["disagree"].as_u64()),
        (Some(1), Some(0))
    );
    assert_eq!(q["answers"][0]["member"], "bob");
    assert_eq!(q["answers"][0]["rationale"], "We already do this in CI.");

    // --- Bob changes his mind. A member has one current answer.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    bob.run(&[
        "question", "answer", &question, "--answer", "disagree", "--yes",
    ]);
    carry(root, &[&alice, &bob, &carol]);
    let q = alice.run(&["question", "list"])["asked"][0].clone();
    assert_eq!(
        (q["agree"].as_u64(), q["disagree"].as_u64()),
        (Some(0), Some(1))
    );
    assert_eq!(q["answers"].as_array().unwrap().len(), 1);

    // --- An answer decides nothing: no proposal exists and nothing was installed.
    assert_eq!(
        alice.run(&["proposal", "list"])["proposals"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // (the two admissions)

    // --- The question leads to a proposal that names it.
    let proposed = alice.run(&[
        "proposal", "create", &candidate, "--circle", "team", "--yes",
    ]);
    assert_eq!(proposed["related_question"], question.as_str());

    // --- Dismissing is local, and a person's decision.
    let (other, _) = (
        alice.run(&["note", "Run the tests before you say you are done."]),
        (),
    );
    let asked = alice.run(&[
        "question",
        "send",
        other["candidate_id"].as_str().unwrap(),
        "--circle",
        "team",
        "--text",
        "Should agents always run the tests first?",
        "--yes",
    ]);
    let second = asked["question_id"].as_str().unwrap().to_owned();
    carry(root, &[&alice, &bob, &carol]);
    assert_eq!(bob.fail_as_agent(&["question", "dismiss", &second]), 3);
    let dismissed = bob.run(&["question", "dismiss", &second, "--mute-author"]);
    assert_eq!(dismissed["status"], "dismissed");
    assert_eq!(bob.run(&["inbox"])["questions_total"], 0);
    // A muted author's later questions are kept but stay out of the inbox.
    let third = alice.run(&["note", "Never commit directly to main."]);
    alice.run(&[
        "question",
        "send",
        third["candidate_id"].as_str().unwrap(),
        "--circle",
        "team",
        "--yes",
    ]);
    let third = alice.run(&["question", "list"])["asked"]
        .as_array()
        .unwrap()
        .iter()
        .find(|q| q["question"].as_str().unwrap().contains("commit directly"))
        .unwrap()["question_id"]
        .as_str()
        .unwrap()
        .to_owned();
    carry(root, &[&alice, &bob, &carol]);
    assert_eq!(bob.run(&["inbox"])["questions_total"], 0);
    // It did arrive: Bob can still answer it if he looks it up.
    bob.run(&["question", "answer", &third, "--answer", "unsure", "--yes"]);
}

#[test]
fn a_second_device_new_rules_of_the_vote_the_owners_mode_and_leaving() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let (alice, bob, carol, fingerprint) = trio(root, "*");
    let all = [&alice, &bob, &carol];

    // --- Bob adds a laptop. It is an amendment: the members decide.
    let laptop = Node::new(root, "bob-laptop");
    let added = bob.run(&[
        "circle",
        "device",
        "add",
        &laptop.device_key(),
        "--circle",
        "team",
        "--yes",
    ]);
    assert_eq!(
        (added["passed"].as_bool(), added["need"].as_u64()),
        (Some(false), Some(2))
    );
    let id = added["proposal_id"].as_str().unwrap().to_owned();
    carry(root, &all);
    alice.run(&["proposal", "vote", &id, "approve", "--yes"]);
    carry(root, &all);
    let charter = alice.charter();
    assert_eq!(charter["seq"], 4);
    let bob_entry = charter["roll"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["member"] == "bob")
        .unwrap();
    assert_eq!(bob_entry["devices"].as_array().unwrap().len(), 2);
    let file = root.join("for-laptop.jsonl");
    let file = file.to_str().unwrap().to_owned();
    alice.run(&["events", "export", "--circle", "team", "--out", &file]);
    join(&laptop, &file, &fingerprint);

    // One member, one vote: both of Bob's devices approve, and it is one approval.
    let (rule, skill) = propose(&alice, "Use pnpm, not npm, in this repository.");
    carry(root, &[&alice, &bob, &carol, &laptop]);
    bob.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    let voted = laptop.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    carry(root, &[&alice, &bob, &carol, &laptop]);
    let shown = alice.run(&["proposal", "show", &rule]);
    assert_eq!(names(&shown["approvals"]), ["bob"]);
    assert_eq!(shown["passed"], false);
    assert_eq!(voted["passed"], false);
    // Alice's approval makes two members of three.
    alice.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    carry(root, &[&alice, &bob, &carol, &laptop]);
    for node in [&alice, &bob, &carol, &laptop] {
        assert!(node.has_skill(&skill), "{}", node.name);
    }

    // --- The owner's mode. Asking is always allowed; following is standing consent,
    // which only a person can give.
    assert_eq!(
        carol.run(&["circle", "mode", "ask", "--circle", "team"])["adoption_mode"],
        "ask"
    );
    assert_eq!(
        carol.fail_as_agent(&["circle", "mode", "follow", "--circle", "team", "--yes"]),
        3
    );
    let (second, second_skill) = propose(&alice, "Run the tests before you say you are done.");
    alice.run(&["proposal", "vote", &second, "approve", "--yes"]);
    carry(root, &all);
    bob.run(&["proposal", "vote", &second, "approve", "--yes"]);
    carry(root, &all);
    assert!(alice.has_skill(&second_skill) && bob.has_skill(&second_skill));
    assert!(
        !carol.has_skill(&second_skill),
        "in ask mode a passed rule waits for its owner"
    );
    let followed = carol.run(&["circle", "mode", "follow", "--circle", "team", "--yes"]);
    assert_eq!(names(&followed["installed"]), [second_skill.as_str()]);
    assert!(carol.has_skill(&second_skill));

    // --- Changing the rules of the vote needs the charter's own amend threshold: more
    // than two thirds of three members is all three.
    assert_eq!(
        alice.fail(&["circle", "amend", "--circle", "team", "--pass", "1/3", "--yes"]),
        2,
        "nothing may pass without a majority"
    );
    assert_eq!(
        alice.fail(&["circle", "amend", "--circle", "team", "--pass", "3/4", "--yes"]),
        2,
        "changing the rules must not be easier than passing one"
    );
    assert_eq!(
        alice.fail(&["circle", "amend", "--circle", "team", "--yes"]),
        2
    );
    let amended = alice.run(&[
        "circle",
        "amend",
        "--circle",
        "team",
        "--pass",
        "2/3",
        "--advisory",
        "--yes",
    ]);
    assert_eq!(
        (amended["passed"].as_bool(), amended["need"].as_u64()),
        (Some(false), Some(3))
    );
    let id = amended["proposal_id"].as_str().unwrap().to_owned();
    carry(root, &all);
    bob.run(&["proposal", "vote", &id, "approve", "--yes"]);
    carry(root, &all);
    assert_eq!(
        alice.charter()["seq"],
        4,
        "two of three is not enough to change the rules"
    );
    carol.run(&["proposal", "vote", &id, "approve", "--yes"]);
    carry(root, &all);
    for node in all {
        let charter = node.charter();
        assert_eq!(charter["seq"], 5, "{}", node.name);
        assert_eq!(
            charter["rules"]["pass"],
            serde_json::json!({"num": 2, "den": 3})
        );
        assert_eq!(charter["rules"]["binding"], false);
        // The rules in force were carried over the charter change.
        assert!(
            node.has_skill(&skill) && node.has_skill(&second_skill),
            "{}",
            node.name
        );
    }

    // --- Carol leaves. Her machine changes at once; the roll changes by vote.
    assert_eq!(
        carol.fail_as_agent(&["circle", "leave", "--circle", "team", "--yes"]),
        3
    );
    let left = carol.run(&["circle", "leave", "--circle", "team", "--yes"]);
    assert_eq!(left["left"], true);
    assert_eq!(left["passed"], false);
    assert!(!carol.has_skill(&skill) && !carol.has_skill(&second_skill));
    assert_eq!(carol.roll(), ["alice", "bob", "carol"], "still on the roll");
    assert_eq!(
        carol.fail(&["circle", "leave", "--circle", "team", "--yes"]),
        2
    );
    // She can change her mind about this machine.
    let back = carol.run(&["circle", "leave", "--circle", "team", "--undo", "--yes"]);
    assert_eq!(back["left"], false);
    assert!(carol.has_skill(&skill));
    // And leave again. The members approve (pass is now 2/3 of three: all three, and
    // her own approval is one of them).
    let left = carol.run(&["circle", "leave", "--circle", "team", "--yes"]);
    let id = left["proposal_id"].as_str().unwrap().to_owned();
    carry(root, &all);
    alice.run(&["proposal", "vote", &id, "approve", "--yes"]);
    bob.run(&["proposal", "vote", &id, "approve", "--yes"]);
    carry(root, &all);
    for node in all {
        assert_eq!(node.roll(), ["alice", "bob"], "{}", node.name);
    }
    assert!(!carol.has_skill(&skill));
    assert!(alice.has_skill(&skill) && bob.has_skill(&skill));
}

#[test]
fn the_founder_cuts_off_a_lost_device_and_the_roll_stays_as_voted() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let (alice, bob, carol, _) = trio(root, "*");
    let all = [&alice, &bob, &carol];

    // Carol's approval is on record for an open proposal.
    let (rule, skill) = propose(&alice, "Use pnpm, not npm, in this repository.");
    carry(root, &all);
    carol.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    carry(root, &all);
    assert_eq!(
        names(&alice.run(&["proposal", "show", &rule])["approvals"]),
        ["carol"]
    );

    // Only the node that holds the root key can revoke, and only a person.
    assert_eq!(
        bob.fail(&["circle", "revoke", "carol", "--circle", "team", "--yes"]),
        3
    );
    assert_eq!(
        alice.fail_as_agent(&["circle", "revoke", "carol", "--circle", "team", "--yes"]),
        3
    );
    // Not the device the founder is using, and not a name that is on no roll.
    assert_eq!(
        alice.fail(&["circle", "revoke", "alice", "--circle", "team", "--yes"]),
        3
    );
    assert_eq!(
        alice.fail(&["circle", "revoke", "dave", "--circle", "team", "--yes"]),
        2
    );

    let revoked = alice.run(&[
        "circle",
        "revoke",
        "carol",
        "--circle",
        "team",
        "--reason",
        "laptop lost",
        "--yes",
    ]);
    assert_eq!(revoked["member"], "carol");
    assert_eq!(revoked["revoked_device"], carol.device_key().as_str());
    assert_eq!(
        alice.fail(&["circle", "revoke", "carol", "--circle", "team", "--yes"]),
        2
    );

    // The roll is what the members voted. The device no longer counts.
    assert_eq!(alice.roll(), ["alice", "bob", "carol"]);
    let shown = alice.run(&["proposal", "show", &rule]);
    assert_eq!(shown["approvals"], serde_json::json!([]));
    assert_eq!(shown["need"], 2, "the electorate is still three members");

    // Bob learns of the revocation and stops counting the device too. One approval
    // from him is then one of two needed, not two.
    carry(root, &[&alice, &bob]);
    let voted = bob.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    assert_eq!(names(&voted["approvals"]), ["bob"]);
    assert_eq!(voted["passed"], false);
    assert!(!bob.has_skill(&skill));

    // Carol's own node has not heard of the revocation and signs another ballot. Every
    // node that knows of the revocation refuses it, whoever carries it.
    carol.run(&["proposal", "vote", &rule, "revise", "--yes"]);
    let file = root.join("from-carol.jsonl");
    let file = file.to_str().unwrap().to_owned();
    carol.run(&["events", "export", "--circle", "team", "--out", &file]);
    for node in [&alice, &bob] {
        let imported = node.run(&["events", "import", &file]);
        assert_eq!(imported["rejected"], 1, "{}", node.name);
        assert_eq!(imported["stored"], 0, "{}", node.name);
    }

    // Once her node has the revocation it no longer signs for that device.
    let (second, _) = propose(&alice, "Run the tests before you say you are done.");
    let file = root.join("from-alice.jsonl");
    let file = file.to_str().unwrap().to_owned();
    alice.run(&["events", "export", "--circle", "team", "--out", &file]);
    carol.run(&["events", "import", &file]);
    assert_eq!(
        carol.fail(&["proposal", "vote", &second, "reject", "--yes"]),
        3,
        "a node that knows its device is revoked does not sign ballots with it"
    );
}

#[test]
fn an_opt_out_can_be_put_on_the_circles_record() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let (alice, bob, carol, fingerprint) = trio(root, "*");
    let all = [&alice, &bob, &carol];
    let (rule, skill) = propose(&alice, "Use pnpm, not npm, in this repository.");
    alice.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    carry(root, &all);
    bob.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    carry(root, &all);
    assert!(carol.has_skill(&skill), "binding: installed for carol too");

    // Nothing is on record for a rule that is not in force, and nothing changes.
    assert_eq!(
        carol.fail(&[
            "rule",
            "opt-out",
            "no-such-rule",
            "--circle",
            "team",
            "--announce",
            "--yes"
        ]),
        2
    );
    // A plain opt-out tells nobody.
    carol.run(&["rule", "opt-out", &skill, "--circle", "team"]);
    assert!(!carol.has_skill(&skill));
    carry(root, &all);
    assert_eq!(
        alice.run(&["rule", "list"])["rules"][0]["on_record"],
        serde_json::json!([])
    );
    carol.run(&["rule", "opt-in", &skill, "--circle", "team", "--yes"]);
    assert!(carol.has_skill(&skill));

    // An agent can never speak for its user. The opt-out itself still happens: no
    // prompt stands between an owner and their own machine.
    assert_eq!(
        carol.fail_as_agent(&[
            "rule",
            "opt-out",
            &skill,
            "--circle",
            "team",
            "--announce",
            "--yes"
        ]),
        3
    );
    assert!(!carol.has_skill(&skill));
    carry(root, &all);
    assert_eq!(
        alice.run(&["rule", "list"])["rules"][0]["on_record"],
        serde_json::json!([])
    );

    // Carol puts it on the record, with her reason.
    let announced = carol.run(&[
        "rule",
        "opt-out",
        &skill,
        "--circle",
        "team",
        "--announce",
        "--reason",
        "Our CI images only ship npm.",
        "--yes",
    ]);
    assert_eq!(announced["announced"], true);
    carry(root, &all);
    for node in [&alice, &bob] {
        let rules = node.run(&["rule", "list"]);
        let record = &rules["rules"][0]["on_record"];
        assert_eq!(record[0]["member"], "carol", "{}", node.name);
        assert_eq!(record[0]["stance"], "opted_out");
        assert_eq!(record[0]["reason"], "Our CI images only ship npm.");
        // The rule is as much in force as before, and installed where it was.
        assert_eq!(rules["rules"].as_array().unwrap().len(), 1);
        assert!(node.has_skill(&skill), "{}", node.name);
        let shown = node.run(&["proposal", "show", &rule]);
        assert_eq!(shown["passed"], true);
        assert_eq!(names(&shown["approvals"]), ["alice", "bob"]);
    }

    // A member admitted after the rule passed is bound by it and can record a stance
    // too, although they were on no roll when it was voted.
    let dave = Node::new(root, "dave");
    let invited = alice.run(&[
        "circle",
        "invite",
        &dave.device_key(),
        "--circle",
        "team",
        "--member",
        "dave",
        "--yes",
    ]);
    let id = invited["proposal_id"].as_str().unwrap().to_owned();
    carry(root, &all);
    bob.run(&["proposal", "vote", &id, "approve", "--yes"]);
    carry(root, &all);
    let file = root.join("for-dave.jsonl");
    let file = file.to_str().unwrap().to_owned();
    alice.run(&["events", "export", "--circle", "team", "--out", &file]);
    join(&dave, &file, &fingerprint);
    assert!(dave.has_skill(&skill));
    dave.run(&[
        "rule",
        "opt-out",
        &skill,
        "--circle",
        "team",
        "--announce",
        "--yes",
    ]);
    let everyone = [&alice, &bob, &carol, &dave];
    carry(root, &everyone);
    let record = alice.run(&["rule", "list"])["rules"][0]["on_record"].clone();
    let who: Vec<&str> = record
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["member"].as_str().unwrap())
        .collect();
    assert_eq!(who, ["carol", "dave"]);

    // Carol follows the rule again and says so. Her latest stance is her current one.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    carol.run(&[
        "rule",
        "opt-in",
        &skill,
        "--circle",
        "team",
        "--announce",
        "--yes",
    ]);
    assert!(carol.has_skill(&skill));
    carry(root, &everyone);
    let record = bob.run(&["rule", "list"])["rules"][0]["on_record"].clone();
    let carols = record
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["member"] == "carol")
        .unwrap();
    assert_eq!(carols["stance"], "following");
}

#[test]
fn the_rules_of_a_scope_can_live_in_one_project() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let (alice, bob, carol, _) = trio(root, "*");
    let all = [&alice, &bob, &carol];

    // A rule about one repository is proposed in a scope the members use for it.
    let noted = alice.run(&["note", "Use pnpm, not npm, in this repository."]);
    let proposed = alice.run(&[
        "proposal",
        "create",
        noted["candidate_id"].as_str().unwrap(),
        "--circle",
        "team",
        "--scope",
        "repo/web",
        "--yes",
    ]);
    let web_rule = proposed["proposal_id"].as_str().unwrap().to_owned();
    let web = proposed["skill_name"].as_str().unwrap().to_owned();
    // And one for the whole circle.
    let (wide_rule, wide) = propose(&alice, "Run the tests before you say you are done.");
    for rule in [&web_rule, &wide_rule] {
        alice.run(&["proposal", "vote", rule, "approve", "--yes"]);
    }
    carry(root, &all);
    for rule in [&web_rule, &wide_rule] {
        bob.run(&["proposal", "vote", rule, "approve", "--yes"]);
    }
    carry(root, &all);
    assert!(bob.has_skill(&web) && bob.has_skill(&wide));

    // Bob says where his checkout of that repository is. Only a person can.
    let checkout = root.join("bob-web");
    std::fs::create_dir(&checkout).unwrap();
    let dir = checkout.to_str().unwrap();
    let in_project = |name: &str| checkout.join(".claude/skills").join(name).join("SKILL.md");
    assert_eq!(
        bob.fail_as_agent(&[
            "circle",
            "place",
            "repo/web",
            "--circle",
            "team",
            "--project",
            dir,
            "--yes"
        ]),
        3
    );
    assert_eq!(
        bob.fail(&[
            "circle",
            "place",
            "repo/web",
            "--circle",
            "team",
            "--project",
            root.join("missing").to_str().unwrap(),
            "--yes"
        ]),
        2
    );
    let placed = bob.run(&[
        "circle",
        "place",
        "repo/web",
        "--circle",
        "team",
        "--project",
        dir,
        "--yes",
    ]);
    assert_eq!(names(&placed["moved"]), [web.as_str()]);
    // The repository's rule is in the repository and nowhere else; the circle-wide rule
    // is where it was.
    assert!(in_project(&web).is_file());
    assert!(!bob.has_skill(&web));
    assert!(bob.has_skill(&wide) && !in_project(&wide).exists());
    let rules = bob.run(&["rule", "list"]);
    let listed = rules["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["skill_name"] == web.as_str())
        .unwrap();
    assert_eq!(listed["state"], "installed");
    assert!(listed["project"].as_str().unwrap().ends_with("bob-web"));
    // Nobody else's machine changed.
    assert!(alice.has_skill(&web) && carol.has_skill(&web));

    // An opt-out, and opting back in, act on the copy in the project.
    bob.run(&["rule", "opt-out", &web, "--circle", "team"]);
    assert!(!in_project(&web).exists() && !bob.has_skill(&web));
    bob.run(&["rule", "opt-in", &web, "--circle", "team", "--yes"]);
    assert!(in_project(&web).is_file() && !bob.has_skill(&web));

    // A repeal by vote removes it from the project too.
    let repeal = alice.run(&["rule", "repeal", &web, "--circle", "team", "--yes"]);
    let repeal = repeal["proposal_id"].as_str().unwrap().to_owned();
    alice.run(&["proposal", "vote", &repeal, "approve", "--yes"]);
    carry(root, &all);
    carol.run(&["proposal", "vote", &repeal, "approve", "--yes"]);
    carry(root, &all);
    assert!(!in_project(&web).exists());
    assert!(!bob.has_skill(&web) && !alice.has_skill(&web));
    assert!(bob.has_skill(&wide), "the other rule is untouched");

    // Placing the whole circle in a project and taking it back moves the rule there
    // and back.
    bob.run(&[
        "circle",
        "place",
        "*",
        "--circle",
        "team",
        "--project",
        dir,
        "--yes",
    ]);
    assert!(in_project(&wide).is_file() && !bob.has_skill(&wide));
    let back = bob.run(&[
        "circle", "place", "*", "--circle", "team", "--user", "--yes",
    ]);
    assert_eq!(names(&back["moved"]), [wide.as_str()]);
    assert!(!in_project(&wide).exists() && bob.has_skill(&wide));
}
