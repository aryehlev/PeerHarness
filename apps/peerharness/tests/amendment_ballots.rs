//! What a member is shown before they sign a ballot on a change to the charter, in
//! their own terminal, with separate nodes driven only through the real binary.
//!
//! The title of an amendment is text its proposer wrote. `proposal vote` and `proposal
//! show` therefore say what the signed `next` charter changes against the charter the
//! proposal names: who is admitted and removed, which device keys are added to and
//! taken from a member, the rules of the vote before and after, and which rules in
//! force the amendment would drop or bring into force. A rule it would bring into force
//! is shown with its text, and an approval is refused while this node cannot show it.
//!
//! Every amendment here is made with the stock commands. What a modified client can
//! sign under a harmless title is covered by the unit tests of `amendment.rs` and
//! `governance.rs`.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

const RULE: &str = "Use pnpm, not npm, in this repository.";

struct Node {
    name: &'static str,
    home: PathBuf,
    skills: PathBuf,
    settings: PathBuf,
    cwd: PathBuf,
}

impl Node {
    fn new(root: &Path, name: &'static str) -> Self {
        let node = Self {
            name,
            home: root.join(name),
            skills: root.join(format!("{name}-skills")),
            settings: root.join(format!("{name}-settings.json")),
            cwd: root.join(format!("{name}-project")),
        };
        std::fs::create_dir_all(&node.cwd).unwrap();
        node.run(&[
            "init",
            "--keystore",
            "file",
            "--kdf-profile",
            "fast-insecure-test",
        ]);
        node
    }

    /// The binary for this node, run by the person in their own terminal: these tests
    /// play the people, and the suite itself may be run by a coding agent.
    fn bare(&self) -> Command {
        let mut cmd = Command::cargo_bin("peerharness").unwrap();
        cmd.current_dir(&self.cwd)
            .env("PEERHARNESS_HOME", &self.home)
            .env("PEERHARNESS_PASSPHRASE", "a passphrase for tests only")
            .env("PEERHARNESS_CLAUDE_SKILLS_DIR", &self.skills)
            .env("PEERHARNESS_CLAUDE_SETTINGS", &self.settings)
            .env_remove("CLAUDECODE")
            .env_remove("PEERHARNESS_AGENT_SESSION")
            .env("USER", self.name);
        cmd
    }

    /// A command that must succeed: its JSON.
    fn run(&self, args: &[&str]) -> Value {
        let out = self.bare().arg("--json").args(args).output().unwrap();
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

    /// A command as the person reads it, without `--json`: the exit code and everything
    /// it printed.
    fn reads(&self, args: &[&str]) -> (i32, String) {
        let out = self.bare().args(args).output().unwrap();
        (
            out.status.code().unwrap(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    /// The preview of a ballot, and nothing signed: without `--yes` and without a
    /// terminal the command shows what it would do and stops.
    fn ballot_preview(&self, proposal: &str, decision: &str) -> String {
        let (code, text) = self.reads(&["proposal", "vote", proposal, decision]);
        assert_eq!(code, 3, "{text}");
        assert!(text.contains("no terminal is attached"), "{text}");
        text
    }

    fn status(&self, key: &str) -> String {
        self.run(&["status"])[key].as_str().unwrap().to_owned()
    }

    fn device_key(&self) -> String {
        self.status("device_key")
    }

    fn fingerprint(&self) -> String {
        self.status("fingerprint")
    }

    fn approvals(&self, proposal: &str) -> Value {
        self.run(&["proposal", "show", proposal])["approvals"].clone()
    }

    /// The names of the rules in force on this node.
    fn rules(&self) -> Vec<String> {
        self.run(&["rule", "list"])["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["skill_name"].as_str().unwrap().to_owned())
            .collect()
    }

    fn export(&self, to: &Path) -> String {
        let path = to.to_str().unwrap().to_owned();
        self.run(&["events", "export", "--circle", "team", "--out", &path]);
        path
    }
}

/// Carries every node's events to every other node, twice, so that what one node signs
/// on receiving something (a result, a charter) reaches the rest as well.
fn carry(root: &Path, nodes: &[&Node]) {
    for round in 0..2 {
        for from in nodes {
            let path = from.export(&root.join(format!("{}-{round}.jsonl", from.name)));
            for to in nodes {
                if to.name != from.name {
                    to.run(&["events", "import", &path]);
                }
            }
        }
    }
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

/// Alice founds `team`; Bob and Carol are admitted by vote and join.
fn trio(root: &Path) -> (Node, Node, Node) {
    let alice = Node::new(root, "alice");
    let bob = Node::new(root, "bob");
    let carol = Node::new(root, "carol");
    let fingerprint = alice.run(&["circle", "create", "team"])["root_fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
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
    let admission = invite(&alice, &carol, "carol");
    carry(root, &[&alice, &bob]);
    bob.run(&["proposal", "vote", &admission, "approve", "--yes"]);
    carry(root, &[&alice, &bob]);
    let file = alice.export(&root.join("for-carol.jsonl"));
    join(&carol, &file, &fingerprint);
    assert_eq!(
        alice.run(&["circle", "members", "--circle", "team"])["charter"]["seq"],
        3
    );
    (alice, bob, carol)
}

/// `by` proposes to admit `whom` under the handle `member`. Returns the proposal id.
fn invite(by: &Node, whom: &Node, member: &str) -> String {
    by.run(&[
        "circle",
        "invite",
        &whom.device_key(),
        "--circle",
        "team",
        "--member",
        member,
        "--yes",
    ])["proposal_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// `by` writes a rule down and proposes it. Returns `(proposal id, skill name)`.
fn propose(by: &Node, text: &str) -> (String, String) {
    let noted = by.run(&["note", text]);
    let candidate = noted["candidate_id"].as_str().unwrap().to_owned();
    let proposed = by.run(&[
        "proposal", "create", &candidate, "--circle", "team", "--yes",
    ]);
    (
        proposed["proposal_id"].as_str().unwrap().to_owned(),
        proposed["skill_name"].as_str().unwrap().to_owned(),
    )
}

/// Where the first of `needles` that is in `text` begins. Panics when none is.
fn position(text: &str, needle: &str) -> usize {
    text.find(needle)
        .unwrap_or_else(|| panic!("{needle:?} is not in:\n{text}"))
}

/// The description read from the signed content comes first, and the proposer's title
/// after it, quoted and labelled as their words.
fn title_is_only_the_proposers_words(text: &str, title: &str) {
    let described = position(text, "read from its signed content");
    let labelled = position(text, "The proposer's own words for it");
    let quoted = position(text, &format!("\"{title}\""));
    assert!(described < labelled && labelled < quoted, "{text}");
    assert_eq!(
        text.matches(title).count(),
        1,
        "the title is nowhere else:\n{text}"
    );
}

#[test]
fn a_ballot_on_a_device_names_the_device_and_whose_it_becomes() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let (alice, bob, _carol) = trio(root);

    // Alice proposes a device key she holds herself as a second device of Carol. The
    // title the stock command writes says only whose device it is said to be.
    let spare = Node::new(root, "spare");
    let fingerprint = spare.fingerprint();
    let proposed = alice.run(&[
        "circle",
        "device",
        "add",
        &spare.device_key(),
        "--circle",
        "team",
        "--member",
        "carol",
        "--yes",
    ]);
    let id = proposed["proposal_id"].as_str().unwrap().to_owned();
    carry(root, &[&alice, &bob]);
    let change = format!(
        "carol gets device {fingerprint} as well: whoever holds it can sign and vote as carol"
    );

    // Bob's approval would pass it. Before he signs anything he is shown the device and
    // whose it becomes, read from the amendment, and who proposed it.
    let preview = bob.ballot_preview(&id, "approve");
    assert!(preview.contains("approve on an amendment to the charter"));
    assert!(preview.contains("proposed by alice"), "{preview}");
    assert!(preview.contains(&change), "{preview}");
    assert!(preview.contains("the rules of the vote stay as they are"));
    assert!(preview.contains("the rules in force stay as they are"));
    assert!(preview.contains("An approval cannot be withdrawn."));
    title_is_only_the_proposers_words(&preview, "Add a device to carol");
    assert_eq!(bob.approvals(&id), serde_json::json!(["alice"]));

    // `proposal show` says the same, and so does its JSON.
    let (code, shown) = bob.reads(&["proposal", "show", &id]);
    assert_eq!(code, 0, "{shown}");
    assert!(shown.contains(&change), "{shown}");
    title_is_only_the_proposers_words(&shown, "Add a device to carol");
    let json = bob.run(&["proposal", "show", &id]);
    let changed = &json["amendment"]["roll"]["changed"];
    assert_eq!(changed.as_array().unwrap().len(), 1);
    assert_eq!(changed[0]["member"], "carol");
    assert_eq!(
        changed[0]["devices_added"][0]["fingerprint"],
        fingerprint.as_str()
    );
    assert_eq!(
        changed[0]["devices_added"][0]["device_key"],
        spare.device_key().as_str()
    );
    assert_eq!(changed[0]["devices_removed"], serde_json::json!([]));
    assert_eq!(json["amendment"]["roll"]["admitted"], serde_json::json!([]));
    assert_eq!(json["amendment"]["roll"]["removed"], serde_json::json!([]));
    assert_eq!(json["amendment"]["rules_of_the_vote"], Value::Null);
    assert_eq!(json["amendment"]["can_be_approved_here"], true);

    // A reject is shown the same description, and is his to give.
    let (code, text) = bob.reads(&["proposal", "vote", &id, "reject", "--yes"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains(&change), "{text}");
    assert!(text.contains("It does not block the proposal."));
    assert_eq!(bob.approvals(&id), serde_json::json!(["alice"]));
}

#[test]
fn a_ballot_on_the_rules_of_the_vote_names_the_old_and_the_new() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let (alice, bob, _carol) = trio(root);

    let proposed = alice.run(&[
        "circle",
        "amend",
        "--circle",
        "team",
        "--pass",
        "2/3",
        "--advisory",
        "--yes",
    ]);
    let id = proposed["proposal_id"].as_str().unwrap().to_owned();
    carry(root, &[&alice, &bob]);

    let pass = "a rule passes with more than 2/3 of its electorate (now 1/2)";
    let force = "passed rules become advisory (now binding)";
    let preview = bob.ballot_preview(&id, "approve");
    assert!(preview.contains(pass), "{preview}");
    assert!(preview.contains(force), "{preview}");
    // The threshold for changing the rules is not touched, and is not listed as changed.
    assert!(!preview.contains("changing these rules needs"), "{preview}");
    assert!(preview.contains("the roll of charter 3 stays as it is (3 members)"));
    title_is_only_the_proposers_words(&preview, "Change the rules of the vote");

    let (_, shown) = bob.reads(&["proposal", "show", &id]);
    assert!(shown.contains(pass) && shown.contains(force), "{shown}");
    let json = bob.run(&["proposal", "show", &id]);
    let rules = &json["amendment"]["rules_of_the_vote"];
    assert_eq!(
        rules["before"]["pass"],
        serde_json::json!({ "num": 1, "den": 2 })
    );
    assert_eq!(
        rules["after"]["pass"],
        serde_json::json!({ "num": 2, "den": 3 })
    );
    assert_eq!(rules["before"]["amend"], rules["after"]["amend"]);
    assert_eq!(rules["before"]["binding"], true);
    assert_eq!(rules["after"]["binding"], false);
    assert_eq!(json["amendment"]["roll"]["changed"], serde_json::json!([]));
}

#[test]
fn the_last_voter_is_told_which_rule_a_pending_admission_would_drop() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let (alice, bob, carol) = trio(root);
    let dave = Node::new(root, "dave");

    // Alice proposes to admit Dave. Her approval is one of the two it needs, so it
    // stays open, and it carries the rules in force at that moment: none.
    let admission = invite(&alice, &dave, "dave");
    // Meanwhile a rule passes, with Alice's and Carol's approvals.
    let (rule, skill) = propose(&alice, RULE);
    alice.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    carry(root, &[&alice, &carol]);
    carol.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    carry(root, &[&alice, &bob, &carol]);
    assert_eq!(bob.rules(), [skill.as_str()]);

    // Bob gets round to the admission. Approving it would also approve the rule set it
    // carries, which lacks the rule that passed since: he is told which rule that is.
    let dropped = format!("rule {skill} goes out of force: the amendment does not carry it");
    let admits = format!("admits dave (device {}, scopes *)", dave.fingerprint());
    let preview = bob.ballot_preview(&admission, "approve");
    assert!(preview.contains(&admits), "{preview}");
    assert!(preview.contains(&dropped), "{preview}");
    title_is_only_the_proposers_words(&preview, "Admit dave");
    let (_, shown) = bob.reads(&["proposal", "show", &admission]);
    assert!(
        shown.contains(&dropped) && shown.contains(&admits),
        "{shown}"
    );
    let json = bob.run(&["proposal", "show", &admission]);
    let rules = &json["amendment"]["rules_in_force"];
    assert_eq!(rules["dropped"][0]["skill_name"], skill.as_str());
    assert_eq!(rules["dropped"][0]["proposal_id"], rule.as_str());
    assert_eq!(rules["added"], serde_json::json!([]));
    assert_eq!(
        json["amendment"]["roll"]["admitted"][0]["devices"][0]["fingerprint"],
        dave.fingerprint().as_str()
    );

    // Nothing about what passes is different: having read it, Bob may approve, and the
    // charter that follows has exactly the rules the amendment carried.
    assert_eq!(bob.approvals(&admission), serde_json::json!(["alice"]));
    bob.run(&["proposal", "vote", &admission, "approve", "--yes"]);
    carry(root, &[&alice, &bob, &carol]);
    assert_eq!(
        bob.run(&["circle", "members", "--circle", "team"])["charter"]["seq"],
        4
    );
    assert!(
        bob.rules().is_empty(),
        "what the preview said is what happened"
    );
}

#[test]
fn the_last_voter_is_told_which_rule_a_pending_admission_would_bring_back() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let (alice, bob, carol) = trio(root);
    let dave = Node::new(root, "dave");

    // A rule is in force when Alice proposes to admit Dave, so the admission carries it.
    let (rule, skill) = propose(&alice, RULE);
    alice.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    carry(root, &[&alice, &carol]);
    carol.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    carry(root, &[&alice, &bob, &carol]);
    let admission = invite(&alice, &dave, "dave");
    carry(root, &[&alice, &bob, &carol]);

    // Meanwhile Bob and Carol repeal the rule.
    let repeal = bob.run(&["rule", "repeal", &skill, "--circle", "team", "--yes"])["proposal_id"]
        .as_str()
        .unwrap()
        .to_owned();
    bob.run(&["proposal", "vote", &repeal, "approve", "--yes"]);
    carry(root, &[&bob, &carol]);
    carol.run(&["proposal", "vote", &repeal, "approve", "--yes"]);
    carry(root, &[&alice, &bob, &carol]);
    assert!(carol.rules().is_empty());

    // Carol gets round to the admission, which would put the repealed rule back in
    // force. She is told which rule, and shown its text, marked as text a member wrote.
    let back = format!("rule {skill} comes into force without a vote of its own");
    let preview = carol.ballot_preview(&admission, "approve");
    assert!(preview.contains(&back), "{preview}");
    assert!(preview.contains("its text ("), "{preview}");
    assert!(preview.contains(&format!("| name: {skill}")), "{preview}");
    assert!(preview.contains(&format!("| description: {RULE}")));
    let (_, shown) = carol.reads(&["proposal", "show", &admission]);
    assert!(shown.contains(&back), "{shown}");
    assert!(shown.contains(&format!("| name: {skill}")), "{shown}");
    let json = carol.run(&["proposal", "show", &admission]);
    let rules = &json["amendment"]["rules_in_force"];
    assert_eq!(rules["dropped"], serde_json::json!([]));
    assert_eq!(rules["added"][0]["skill_name"], skill.as_str());
    assert_eq!(rules["added"][0]["proposal_id"], rule.as_str());
    assert_eq!(rules["added"][0]["text_on_this_node"], true);
    assert_eq!(json["amendment"]["can_be_approved_here"], true);
    assert_eq!(carol.approvals(&admission), serde_json::json!(["alice"]));
}

/// One line of an events file.
fn line(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap()
}

#[test]
fn an_amendment_is_not_a_way_to_approve_a_rule_nobody_here_could_read() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let (alice, bob, carol) = trio(root);
    let dave = Node::new(root, "dave");

    // A rule passes on Alice's node with Carol's approval, and Alice then proposes to
    // admit Dave: the admission carries the rule.
    let (rule, skill) = propose(&alice, RULE);
    alice.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    carry(root, &[&alice, &carol]);
    carol.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    carry(root, &[&alice, &carol]);
    assert_eq!(alice.rules(), [skill.as_str()]);
    let admission = invite(&alice, &dave, "dave");

    // What reaches Bob is incomplete, as a carrier may be: the proposals and Alice's
    // ballots, without Carol's ballot on the rule and without the rule's text. On his
    // node the rule is therefore not in force, and its text is not there.
    let all = std::fs::read_to_string(alice.export(&root.join("all.jsonl"))).unwrap();
    let carol_key = carol.device_key();
    let (texts, events): (Vec<&str>, Vec<&str>) = all
        .lines()
        .partition(|raw| line(raw).get("bundle").is_some());
    assert_eq!(texts.len(), 1);
    let partial: Vec<&str> = events
        .into_iter()
        .filter(|raw| {
            let event = &line(raw)["event"];
            !(event["type"] == "VOTE"
                && event["author"] == carol_key.as_str()
                && event["body"]["proposal_id"] == rule.as_str())
        })
        .collect();
    let file = root.join("partial.jsonl");
    std::fs::write(&file, partial.join("\n") + "\n").unwrap();
    bob.run(&["events", "import", file.to_str().unwrap()]);
    assert!(bob.rules().is_empty());
    assert_eq!(bob.approvals(&rule), serde_json::json!(["alice"]));

    // Bob cannot approve the rule itself without its text. Nor can he approve the
    // amendment that would put it in force: `--yes` signs nothing.
    let (code, text) = bob.reads(&["proposal", "vote", &rule, "approve", "--yes"]);
    assert_eq!(code, 3, "{text}");
    let (code, text) = bob.reads(&["proposal", "vote", &admission, "approve", "--yes"]);
    assert_eq!(code, 3, "{text}");
    assert!(
        text.contains("would put a rule in force whose text this node does not have"),
        "{text}"
    );
    assert!(text.contains("you cannot have read what you would approve"));
    assert_eq!(bob.approvals(&admission), serde_json::json!(["alice"]));

    // `proposal show` says what is missing, by the rule's name.
    let (_, shown) = bob.reads(&["proposal", "show", &admission]);
    assert!(
        shown.contains(&format!(
            "rule {skill} comes into force without a vote of its own"
        )),
        "{shown}"
    );
    assert!(
        shown.contains("its text is not on this node yet"),
        "{shown}"
    );
    let json = bob.run(&["proposal", "show", &admission]);
    let added = &json["amendment"]["rules_in_force"]["added"][0];
    assert_eq!(added["skill_name"], skill.as_str());
    assert_eq!(added["text_on_this_node"], false);
    assert_eq!(json["amendment"]["can_be_approved_here"], false);

    // A reject stays possible: it is recorded dissent and approves nothing.
    let (code, text) = bob.reads(&["proposal", "vote", &admission, "reject", "--yes"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("its text is not on this node yet"), "{text}");
    assert_eq!(bob.approvals(&admission), serde_json::json!(["alice"]));

    // The text arrives. Now the preview shows it, and the approval is Bob's to give.
    let file = root.join("text.jsonl");
    std::fs::write(&file, format!("{}\n", texts[0])).unwrap();
    assert_eq!(
        bob.run(&["events", "import", file.to_str().unwrap()])["bundles"],
        1
    );
    let preview = bob.ballot_preview(&admission, "approve");
    assert!(
        preview.contains(&format!("| description: {RULE}")),
        "{preview}"
    );
    assert!(bob.rules().is_empty());
    let (code, text) = bob.reads(&["proposal", "vote", &admission, "approve", "--yes"]);
    assert_eq!(code, 0, "{text}");
    assert_eq!(
        bob.approvals(&admission),
        serde_json::json!(["alice", "bob"])
    );
}
