//! Three separate nodes, driven only through the real binary: separate homes, separate
//! keys, separate databases and separate skills directories. They found a circle, admit
//! members by vote, pass a rule 2 to 1 and see it installed. The only thing that moves
//! between them is a file of signed events, which every node verifies for itself.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

const SKILL: &str = "pnpm-repository-convention";

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

    fn device_key(&self) -> String {
        self.run(&["status"])["device_key"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn has_skill(&self) -> bool {
        self.skills.join(SKILL).join("SKILL.md").is_file()
    }

    /// The proposals that wait for this member's vote, as their inbox lists them.
    fn awaiting(&self) -> Vec<String> {
        let inbox = self.run(&["inbox"]);
        let listed = inbox["proposals_awaiting_vote"].as_array().unwrap();
        assert_eq!(inbox["proposals_awaiting_vote_total"], listed.len());
        listed
            .iter()
            .map(|p| p["proposal_id"].as_str().unwrap().to_owned())
            .collect()
    }

    /// What Claude Code would show this member at the end of a turn: the output of the
    /// Stop hook. It always exits 0.
    fn stop_notice(&self) -> String {
        let out = self.cmd(&["hook", "stop"]).output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    }

    fn export(&self, root: &Path, tag: &str) -> String {
        let path = root.join(format!("{}-{tag}.jsonl", self.name));
        let p = path.to_str().unwrap().to_owned();
        self.run(&["events", "export", "--circle", "team", "--out", &p]);
        p
    }
}

fn names(v: &Value) -> Vec<&str> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect()
}

#[test]
fn three_nodes_admit_by_vote_and_pass_a_rule_two_to_one() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let alice = Node::new(root, "alice");
    let bob = Node::new(root, "bob");
    let carol = Node::new(root, "carol");

    // --- Alice founds the circle. She is the whole roll.
    let created = alice.run(&["circle", "create", "team"]);
    assert_eq!(created["member"], "alice");
    assert_eq!(created["charter"]["seq"], 1);
    let fingerprint = created["root_fingerprint"].as_str().unwrap().to_owned();

    // --- Admitting Bob: one member, so her approval is the majority.
    let invite = root.join("bob-invite.jsonl");
    let invite_path = invite.to_str().unwrap();
    let invited = alice.run(&[
        "circle",
        "invite",
        &bob.device_key(),
        "--circle",
        "team",
        "--member",
        "bob",
        "--yes",
        "--out",
        invite_path,
    ]);
    assert_eq!(invited["passed"], true);
    assert_eq!(invited["charter_seq"], 2);

    // Bob refuses to join when the fingerprint is not the one he was told.
    assert_eq!(
        bob.fail(&[
            "circle",
            "join",
            invite_path,
            "--expect-fingerprint",
            "0000-0000-0000-0000-0000",
            "--yes",
            "--name",
            "team",
        ]),
        3
    );
    let joined = bob.run(&[
        "circle",
        "join",
        invite_path,
        "--expect-fingerprint",
        &fingerprint,
        "--yes",
        "--name",
        "team",
    ]);
    assert_eq!(joined["member"], "bob");
    assert_eq!(joined["charter_seq"], 2);

    // Carol is not on the roll of anything in that file: she cannot join with it.
    assert_eq!(
        carol.fail(&[
            "circle",
            "join",
            invite_path,
            "--expect-fingerprint",
            &fingerprint,
            "--yes",
            "--name",
            "team",
        ]),
        3
    );

    // --- Admitting Carol now takes both members. The founder cannot do it alone.
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
    assert_eq!(invited["passed"], false, "one of two is not a majority");
    assert_eq!(invited["charter_seq"], Value::Null);
    let admission = invited["proposal_id"].as_str().unwrap().to_owned();

    bob.run(&["events", "import", &alice.export(root, "1")]);
    let voted = bob.run(&["proposal", "vote", &admission, "approve", "--yes"]);
    assert_eq!(voted["passed"], true);
    assert_eq!(names(&voted["approvals"]), ["alice", "bob"]);
    // Bob does not hold the root key, so the charter has not changed on his node.
    assert_eq!(bob.run(&["circle", "members"])["charter"]["seq"], 2);

    // Alice's node receives Bob's ballot and notarizes exactly what was voted.
    let imported = alice.run(&["events", "import", &bob.export(root, "1")]);
    assert_eq!(imported["charters_issued"], serde_json::json!([3]));
    let roll = alice.run(&["circle", "members"]);
    let members: Vec<&str> = roll["charter"]["roll"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["member"].as_str().unwrap())
        .collect();
    assert_eq!(members, ["alice", "bob", "carol"]);

    let for_carol = alice.export(root, "2");
    let joined = carol.run(&[
        "circle",
        "join",
        &for_carol,
        "--expect-fingerprint",
        &fingerprint,
        "--yes",
        "--name",
        "team",
    ]);
    assert_eq!(joined["member"], "carol");
    assert_eq!(joined["charter_seq"], 3);
    bob.run(&["events", "import", &for_carol]);
    assert_eq!(bob.run(&["circle", "members"])["charter"]["seq"], 3);

    // --- A correction becomes a rule proposal.
    alice.run(&["observe", "demo"]);
    let candidate = alice.run(&["inbox"])["candidates"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let proposed = alice.run(&[
        "proposal", "create", &candidate, "--circle", "team", "--yes",
    ]);
    assert_eq!(proposed["skill_name"], SKILL);
    let rule = proposed["proposal_id"].as_str().unwrap().to_owned();
    // Nothing has reached Bob yet, so nothing waits for him and he is told nothing.
    assert!(bob.awaiting().is_empty());
    assert_eq!(bob.stop_notice(), "");

    // Creating a proposal is not a vote, and one approval of three is not enough.
    assert_eq!(
        alice.awaiting(),
        [rule.as_str()],
        "her own ballot is missing too"
    );
    let voted = alice.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    assert_eq!(voted["passed"], false);
    assert!(alice.awaiting().is_empty());
    assert_eq!(
        (
            voted["need"].as_u64(),
            voted["electorate"].as_array().map(Vec::len)
        ),
        (Some(2), Some(3))
    );
    assert!(
        !alice.has_skill(),
        "nothing is installed before the vote passes"
    );

    let from_alice = alice.export(root, "3");
    bob.run(&["events", "import", &from_alice]);
    carol.run(&["events", "import", &from_alice]);

    // The proposal now waits for Bob and Carol. At the end of Bob's next turn with his
    // agent he is told so, once: a count, and where to look.
    assert_eq!(bob.awaiting(), [rule.as_str()]);
    assert_eq!(carol.awaiting(), [rule.as_str()]);
    assert_eq!(
        bob.stop_notice().trim_end(),
        r#"{"systemMessage":"PeerHarness: 1 proposal waits for your vote — run `peerharness inbox`"}"#
    );
    assert_eq!(bob.stop_notice(), "", "not again the same day");

    // Carol rejects, with a reason. It is recorded and it blocks nothing.
    let voted = carol.run(&[
        "proposal",
        "vote",
        &rule,
        "reject",
        "--rationale",
        "Our CI images only ship npm.",
        "--yes",
    ]);
    assert_eq!(voted["passed"], false);
    assert_eq!(voted["dissent"][0]["member"], "carol");
    assert!(carol.awaiting().is_empty(), "a reject is a ballot");
    bob.run(&["events", "import", &carol.export(root, "1")]);

    // Bob approves: two of three. It passes on his node and is installed there.
    let voted = bob.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    assert_eq!(voted["passed"], true);
    assert_eq!(names(&voted["approvals"]), ["alice", "bob"]);
    assert_eq!(voted["dissent"][0]["member"], "carol");
    assert!(bob.has_skill());
    assert!(bob.awaiting().is_empty());

    // The others learn of it from Bob's file and reach the same count themselves.
    let from_bob = bob.export(root, "2");
    for node in [&alice, &carol] {
        let imported = node.run(&["events", "import", &from_bob]);
        assert_eq!(names(&imported["installed"]), [SKILL], "{}", node.name);
        assert!(node.has_skill(), "{}", node.name);
        let shown = node.run(&["proposal", "show", &rule]);
        assert_eq!(shown["standing"], "passed", "{}", node.name);
        assert_eq!(
            names(&shown["approvals"]),
            ["alice", "bob"],
            "{}",
            node.name
        );
        assert_eq!(shown["dissent"][0]["member"], "carol", "{}", node.name);
    }
    // The charter is binding, so it is on Carol's machine too, although she voted no.
    assert!(carol.has_skill());

    // --- Carol opts out of this one rule. Only her machine changes.
    let out = carol.run(&["rule", "opt-out", SKILL, "--circle", "team"]);
    assert_eq!(names(&out["removed"]), [SKILL]);
    assert!(!carol.has_skill());
    assert!(alice.has_skill() && bob.has_skill());
    let rules = carol.run(&["rule", "list"]);
    assert_eq!(rules["rules"][0]["skill_name"], SKILL);
    assert_eq!(rules["rules"][0]["opted_out"], true);
    // Importing the same events again changes nothing, on any node.
    for node in [&alice, &bob, &carol] {
        let again = node.run(&["events", "import", &from_bob]);
        assert_eq!(again["stored"], 0, "{}", node.name);
        assert_eq!(again["installed"], serde_json::json!([]), "{}", node.name);
    }
    assert!(!carol.has_skill(), "an opt-out survives later imports");
    // And she can change her mind.
    carol.run(&["rule", "opt-in", SKILL, "--circle", "team", "--yes"]);
    assert!(carol.has_skill());

    // --- Removing a member takes a vote too. The founder cannot do it alone.
    let removal = alice.run(&["circle", "remove", "carol", "--circle", "team", "--yes"]);
    assert_eq!(removal["passed"], false);
    assert_eq!(removal["need"], 2);
    assert_eq!(removal["charter_seq"], Value::Null);
    let removal_id = removal["proposal_id"].as_str().unwrap().to_owned();
    assert_eq!(alice.run(&["circle", "members"])["charter"]["seq"], 3);
    // Nobody is removed without a member of that name, either.
    assert_eq!(
        alice.fail(&["circle", "remove", "dave", "--circle", "team", "--yes"]),
        2
    );

    bob.run(&["events", "import", &alice.export(root, "4")]);
    assert_eq!(bob.awaiting(), [removal_id.as_str()]);
    let voted = bob.run(&["proposal", "vote", &removal_id, "approve", "--yes"]);
    assert_eq!(voted["passed"], true);
    let imported = alice.run(&["events", "import", &bob.export(root, "3")]);
    assert_eq!(imported["charters_issued"], serde_json::json!([4]));
    let after = alice.export(root, "5");
    bob.run(&["events", "import", &after]);
    for node in [&alice, &bob] {
        let roll = node.run(&["circle", "members"]);
        assert_eq!(roll["charter"]["seq"], 4, "{}", node.name);
        let members: Vec<&str> = roll["charter"]["roll"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["member"].as_str().unwrap())
            .collect();
        assert_eq!(members, ["alice", "bob"], "{}", node.name);
        // The amendment carried the rule: it stays in force for those who remain.
        assert!(node.has_skill(), "{}", node.name);
        assert_eq!(
            node.run(&["rule", "list"])["rules"][0]["skill_name"],
            SKILL,
            "{}",
            node.name
        );
    }

    // Carol's node learns of it. The circle's rule no longer binds her, so what the
    // vote had installed on her machine is removed, and her ballots count for nothing.
    let imported = carol.run(&["events", "import", &after]);
    assert_eq!(names(&imported["removed"]), [SKILL]);
    assert!(!carol.has_skill());
    assert_eq!(carol.run(&["circle", "members"])["charter"]["seq"], 4);
    assert_eq!(carol.run(&["rule", "list"])["rules"][0]["binds_you"], false);
    // The vote that removed her passed without her and asks nothing of her now.
    assert!(carol.awaiting().is_empty());
    assert_eq!(carol.stop_notice(), "");
    assert_eq!(
        carol.fail(&["rule", "repeal", SKILL, "--circle", "team", "--yes"]),
        3,
        "she is not on the roll any more"
    );
}

#[test]
fn an_outsider_gets_nothing_from_a_circles_events() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let alice = Node::new(root, "alice");
    let mallory = Node::new(root, "mallory");
    alice.run(&["circle", "create", "team"]);
    alice.run(&["observe", "demo"]);
    let candidate = alice.run(&["inbox"])["candidates"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let proposed = alice.run(&[
        "proposal", "create", &candidate, "--circle", "team", "--yes",
    ]);
    let rule = proposed["proposal_id"].as_str().unwrap().to_owned();
    // A circle of one: her own approval passes it and installs it for her.
    let voted = alice.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    assert_eq!(voted["passed"], true);
    assert!(alice.has_skill());

    // Mallory obtains the file. Her node is in no circle, so it stores none of it and
    // installs nothing.
    let file = alice.export(root, "1");
    let imported = mallory.run(&["events", "import", &file]);
    assert_eq!(imported["stored"], 0);
    assert_eq!(imported["bundles"], 0);
    assert!(!mallory.has_skill());
    // She cannot join either: she is not on any roll.
    // (Exit code 3: refused.)
    assert_eq!(mallory.fail(&["circle", "join", &file, "--yes"]), 3);
    assert_eq!(
        mallory.run(&["rule", "list"])["rules"],
        serde_json::json!([])
    );
}

#[test]
fn a_member_who_joins_later_gets_the_rules_passed_before_they_joined() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let alice = Node::new(root, "alice");
    let bob = Node::new(root, "bob");

    // Alice founds the circle and passes a rule on her own, under charter 1.
    let created = alice.run(&["circle", "create", "team"]);
    let fingerprint = created["root_fingerprint"].as_str().unwrap().to_owned();
    alice.run(&["observe", "demo"]);
    let candidate = alice.run(&["inbox"])["candidates"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let rule = alice.run(&[
        "proposal", "create", &candidate, "--circle", "team", "--yes",
    ])["proposal_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        alice.run(&["proposal", "vote", &rule, "approve", "--yes"])["passed"],
        true
    );

    // Bob is admitted afterwards. Charter 2 carries the rule; it is his trust anchor.
    let invite = root.join("bob-invite.jsonl");
    let invite_path = invite.to_str().unwrap();
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
        invite_path,
    ]);
    let joined = bob.run(&[
        "circle",
        "join",
        invite_path,
        "--expect-fingerprint",
        &fingerprint,
        "--yes",
        "--name",
        "team",
    ]);
    assert_eq!(joined["charter_seq"], 2);

    // He holds charter 1 as history (it is the one his anchor names by hash), so the
    // proposal and the ballot from before his time verify, and the carried rule is in
    // force and installed on his machine too.
    let again = bob.run(&["events", "import", invite_path]);
    assert_eq!(again["deferred"], 0, "nothing is left unplaced: {again}");
    assert_eq!(again["rejected"], 0);
    let rules = bob.run(&["rule", "list"]);
    assert_eq!(rules["rules"][0]["skill_name"], SKILL);
    assert_eq!(rules["rules"][0]["binds_you"], true);
    // What was decided before his time does not wait for his vote.
    assert!(bob.awaiting().is_empty());
    assert_eq!(bob.stop_notice(), "");
    assert!(bob.has_skill());
    let shown = bob.run(&["proposal", "show", &rule]);
    assert_eq!(shown["standing"], "carried");
    assert_eq!(names(&shown["approvals"]), ["alice"]);
    // History gives nobody a vote: the current charter is still the one he joined at.
    assert_eq!(bob.run(&["circle", "members"])["charter"]["seq"], 2);
}
