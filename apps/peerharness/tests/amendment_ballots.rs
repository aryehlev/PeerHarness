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
//! Every amendment here is made with the stock commands, with one exception. What a
//! modified client can sign under a harmless title is covered by the unit tests of
//! `amendment.rs` and `governance.rs`. The exception is the last part: a node that lacks
//! a rule the charter in force carries no longer drafts an amendment at all, so the
//! amendment that drops that rule is signed here with a member's own device key, the
//! way a modified client, or a version before this one, signs it.
//!
//! Some tests turn confirmation windows on. Every command of every node therefore gets
//! `PEERHARNESS_TEST_WINDOW_BIN`, a script that records that it was started and
//! declines; only debug builds read that variable, and those tests are compiled for
//! debug builds only.
//!
//! Two of them are about what a node receives while its owner reads a preview: a newer
//! charter, or a rule that passed. Their stand-in window imports a file before it
//! answers Proceed, which is what a sync by a running daemon does while a real window
//! is open. The terminal's prompt cannot be held open that way without a terminal, so
//! the check that `circle remove`, `amend` and `device` share with `circle invite` is
//! covered there by the window test of `invite` and by the unit tests of
//! `governance::as_drafted` and `governance::propose_under`.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use ph_core::{Scope, Timestamp};
use ph_identity::{open_keystore, DeviceIdentity, KeystoreConfig, PassphraseSource};
use ph_protocol::{
    validate_stateless, Charter, EnvelopeBuilder, EventBody, ProposalAction, ProposalBody,
    RollEntry,
};
use serde_json::Value;
use tempfile::TempDir;

const RULE: &str = "Use pnpm, not npm, in this repository.";
const PASSPHRASE: &str = "a passphrase for tests only";

struct Node {
    name: &'static str,
    home: PathBuf,
    skills: PathBuf,
    settings: PathBuf,
    cwd: PathBuf,
    /// Stands in for a confirmation window: it records that it was started, and
    /// declines.
    window: PathBuf,
    opened: PathBuf,
}

impl Node {
    fn new(root: &Path, name: &'static str) -> Self {
        let node = Self {
            name,
            home: root.join(name),
            skills: root.join(format!("{name}-skills")),
            settings: root.join(format!("{name}-settings.json")),
            cwd: root.join(format!("{name}-project")),
            window: root.join(format!("{name}-window.sh")),
            opened: root.join(format!("{name}-window-opened")),
        };
        std::fs::create_dir_all(&node.cwd).unwrap();
        std::fs::write(
            &node.window,
            format!(
                "#!/bin/sh\ncat > /dev/null\necho opened >> '{}'\necho declined\n",
                node.opened.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&node.window, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
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
            .env("PEERHARNESS_PASSPHRASE", PASSPHRASE)
            .env("PEERHARNESS_CLAUDE_SKILLS_DIR", &self.skills)
            .env("PEERHARNESS_CLAUDE_SETTINGS", &self.settings)
            // Never a real window, on any machine these tests run on.
            .env("PEERHARNESS_TEST_WINDOW_BIN", &self.window)
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

/// The circle's current charter, read from a member's export.
fn current_charter(export: &str) -> Charter {
    let mut charters: Vec<Charter> = std::fs::read_to_string(export)
        .unwrap()
        .lines()
        .filter_map(|raw| line(raw).get("event").map(Value::to_string))
        .filter_map(|raw| validate_stateless(raw.as_bytes(), Timestamp::now()).ok())
        .filter_map(|event| match &event.body {
            EventBody::Charter(body) => Some(body.charter.clone()),
            _ => None,
        })
        .collect();
    charters.sort_by_key(|c| c.seq);
    charters.pop().expect("the export holds a charter")
}

/// A circle of four whose charter carries a rule, and one member whose node does not
/// hold that rule.
struct Incomplete {
    alice: Node,
    dave: Node,
    erin: Node,
    /// The rule the charter carries: its proposal id and its skill name.
    rule: String,
    skill: String,
    /// An amendment that admits Erin and carries no rule, signed with Carol's device
    /// key: its proposal id, and a file with it that `events import` reads.
    drops_the_rule: String,
    file: String,
}

/// Alice, Bob and Carol pass a rule. Dave is admitted by a charter that carries it, and
/// joins from a file that lacks the rule's proposal, its ballots, its result and its
/// text: a join whose carrier was incomplete. (A member whose scopes do not cover the
/// rule is in the same state after every sync.) On his node no rule is in force, and
/// `rule list` says that a carried rule has not arrived.
///
/// Then an amendment arrives that admits Erin and whose `carried` list is empty: what
/// a node in Dave's state drafted before it refused to, and what a modified client can
/// sign at any time. Approved, it takes the rule out of force for everyone.
fn a_node_that_lacks_a_carried_rule(root: &Path) -> Incomplete {
    let (alice, bob, carol) = trio(root);
    let dave = Node::new(root, "dave");
    let erin = Node::new(root, "erin");
    let fingerprint = alice.run(&["circle", "members", "--circle", "team"])["root_fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();

    let (rule, skill) = propose(&alice, RULE);
    alice.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    carry(root, &[&alice, &carol]);
    carol.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    carry(root, &[&alice, &bob, &carol]);
    let admission = invite(&alice, &dave, "dave");
    carry(root, &[&alice, &bob]);
    bob.run(&["proposal", "vote", &admission, "approve", "--yes"]);
    carry(root, &[&alice, &bob, &carol]);
    let members = alice.run(&["circle", "members", "--circle", "team"]);
    assert_eq!(members["charter"]["seq"], 4);
    assert_eq!(members["charter"]["carried"], serde_json::json!([rule]));

    // What reaches Dave: everything but the rule.
    let all = std::fs::read_to_string(alice.export(&root.join("all.jsonl"))).unwrap();
    let without: Vec<&str> = all
        .lines()
        .filter(|raw| {
            let record = line(raw);
            let event = &record["event"];
            record.get("bundle").is_none()
                && event["event_id"] != rule.as_str()
                && event["body"]["proposal_id"] != rule.as_str()
        })
        .collect();
    assert_eq!(all.lines().count() - without.len(), 5, "the rule's records");
    let partial = root.join("without-the-rule.jsonl");
    std::fs::write(&partial, without.join("\n") + "\n").unwrap();
    join(&dave, partial.to_str().unwrap(), &fingerprint);
    assert!(dave.rules().is_empty());
    let (_, listed) = dave.reads(&["rule", "list"]);
    assert!(listed.contains("0 rule(s) in force"), "{listed}");
    assert!(
        listed.contains("has not arrived on this node yet"),
        "{listed}"
    );

    // The amendment, signed with Carol's own key under charter 4.
    let charter = current_charter(&alice.export(&root.join("charter-4.jsonl")));
    assert_eq!(charter.seq, 4);
    let keystore = open_keystore(
        &carol.home,
        KeystoreConfig::file(PassphraseSource::fixed(PASSPHRASE)),
    )
    .unwrap();
    let device = DeviceIdentity::load(&*keystore).unwrap();
    let mut next = charter.content.clone();
    next.roll.push(RollEntry::new(
        "erin",
        vec![erin.device_key().parse().unwrap()],
        vec![Scope::all()],
    ));
    next.carried.clear();
    next.normalize();
    let proposal = EnvelopeBuilder::new(
        charter.circle_id,
        Scope::all(),
        EventBody::Proposal(ProposalBody {
            charter: charter.digest().unwrap(),
            title: "Admit erin".to_owned(),
            summary: String::new(),
            action: ProposalAction::Amend { next },
        }),
    )
    .sign(device.signing_key(), Timestamp::now())
    .unwrap();
    let event: Value = serde_json::from_str(&proposal.to_canonical_json().unwrap()).unwrap();
    let file = root.join("admit-erin-and-carry-nothing.jsonl");
    std::fs::write(
        &file,
        serde_json::json!({ "event": event }).to_string() + "\n",
    )
    .unwrap();
    let file = file.to_str().unwrap().to_owned();
    for node in [&alice, &dave] {
        assert_eq!(node.run(&["events", "import", &file])["stored"], 1);
    }
    Incomplete {
        alice,
        dave,
        erin,
        rule,
        skill,
        drops_the_rule: proposal.event_id.to_string(),
        file,
    }
}

/// The start of an id, as the commands print it (`sha256:` and twelve characters).
fn short(id: &str) -> &str {
    &id[.."sha256:".len() + 12]
}

/// A node that lacks a rule the charter in force carries does not hold "the rules in
/// force". An amendment that leaves that rule out drops it for the circle. Such a node
/// used to describe it as "the rules in force stay as they are" and sign the approval.
#[test]
fn a_node_that_lacks_a_carried_rule_says_so_and_approves_no_amendment_that_drops_it() {
    let tmp = TempDir::new().unwrap();
    let c = a_node_that_lacks_a_carried_rule(tmp.path());
    let (alice, dave, id) = (&c.alice, &c.dave, c.drops_the_rule.as_str());

    // --- On a node that holds the rule the amendment is described as what it is.
    let named = format!(
        "rule {} goes out of force: the amendment does not carry it",
        c.skill
    );
    let preview = alice.ballot_preview(id, "approve");
    assert!(preview.contains(&named), "{preview}");

    // --- Dave's node cannot name the rule. It says that one goes out of force, with
    // the proposal's id, and never that the rules stay as they are.
    let unnamed = format!(
        "a rule the charter in force carries, which this node does not hold, goes out of \
         force: the amendment does not carry it (proposal {})",
        short(&c.rule)
    );
    let (code, shown) = dave.reads(&["proposal", "show", id]);
    assert_eq!(code, 0, "{shown}");
    assert!(shown.contains(&unnamed), "{shown}");
    assert!(
        !shown.contains("the rules in force stay as they are"),
        "{shown}"
    );
    assert!(
        shown.contains(
            "it cannot be approved on this node: it leaves out a rule the charter in force \
             carries, which this node does not hold"
        ),
        "{shown}"
    );
    let json = dave.run(&["proposal", "show", id]);
    let rules = &json["amendment"]["rules_in_force"];
    assert_eq!(
        rules["dropped"],
        serde_json::json!([{ "skill_name": null, "proposal_id": c.rule }])
    );
    assert_eq!(rules["added"], serde_json::json!([]));
    assert_eq!(json["amendment"]["can_be_approved_here"], false);

    // --- An approval is refused, with `--yes` too, and nothing is signed.
    for args in [
        vec!["proposal", "vote", id, "approve"],
        vec!["proposal", "vote", id, "approve", "--yes"],
    ] {
        let (code, text) = dave.reads(&args);
        assert_eq!(code, 3, "{args:?}: {text}");
        assert!(
            text.contains(
                "leaves out a rule that the charter in force carries and this node does not hold"
            ),
            "{text}"
        );
        assert!(text.contains("you cannot have read what you would approve"));
        assert!(text.contains("`peerharness events import`"), "{text}");
    }
    assert_eq!(dave.approvals(id), serde_json::json!([]));

    // --- A reject stays possible: it approves nothing. Its preview says the same.
    let (code, text) = dave.reads(&["proposal", "vote", id, "reject", "--yes"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains(&unnamed), "{text}");
    assert!(
        !text.contains("the rules in force stay as they are"),
        "{text}"
    );
    assert_eq!(dave.approvals(id), serde_json::json!([]));

    // --- With the rule's records on his node, Dave reads which rule it is, and the
    // decision is his again.
    let full = alice.export(&tmp.path().join("everything.jsonl"));
    dave.run(&["events", "import", &full]);
    assert_eq!(dave.rules(), [c.skill.as_str()]);
    let (_, shown) = dave.reads(&["proposal", "show", id]);
    assert!(shown.contains(&named), "{shown}");
    assert!(
        !shown.contains("cannot be approved on this node"),
        "{shown}"
    );
    assert_eq!(
        dave.run(&["proposal", "show", id])["amendment"]["can_be_approved_here"],
        true
    );
}

/// The same amendment, with windows on. It admits one member and its `carried` list
/// equals the rules in force on Dave's node (none), so it used to be put to him in a
/// window as "What this amendment changes, and nothing else: admit erin". It is not a
/// ballot for a window while his node lacks a rule the charter carries.
#[cfg(all(unix, debug_assertions))]
#[test]
fn an_amendment_that_drops_an_unheld_rule_is_never_a_ballot_for_a_window() {
    let tmp = TempDir::new().unwrap();
    let c = a_node_that_lacks_a_carried_rule(tmp.path());
    let (dave, id) = (&c.dave, c.drops_the_rule.as_str());
    let on = dave.run(&["watch", "claude", "--install", "--dialogs", "--yes"]);
    assert_eq!(on["circle_windows"], true);

    // His agent's session starts each kind of ballot. None opens a window, and nothing
    // is signed: the approval is refused for what the node cannot show, and a reject is
    // a step for his own terminal.
    for decision in ["approve", "reject", "revise"] {
        let out = dave
            .bare()
            .args(["--json", "proposal", "vote", id, decision])
            .env("CLAUDECODE", "1")
            .output()
            .unwrap();
        let printed = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.status.code(), Some(3), "{decision}: {printed}");
        assert!(
            !dave.opened.exists(),
            "{decision}: a window was opened\n{printed}"
        );
        if decision != "approve" {
            assert!(printed.contains("your own terminal"), "{printed}");
        }
    }
    let shown = dave.run(&["proposal", "show", id]);
    assert_eq!(shown["approvals"], serde_json::json!([]));
    assert_eq!(shown["dissent"], serde_json::json!([]));
}

/// Where such amendments came from with nobody attacking: the node that lacks the rule
/// drafted one, because an amendment carries "the rules in force" of the node that
/// drafts it. It no longer drafts any. Leaving is the exception, because leaving never
/// waits: the request lists the rule by the id the charter lists, and drops nothing.
#[test]
fn a_node_that_lacks_a_carried_rule_drafts_no_amendment_and_can_still_leave() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let c = a_node_that_lacks_a_carried_rule(root);
    let (alice, dave, erin) = (&c.alice, &c.dave, &c.erin);
    let proposals = |node: &Node| {
        node.run(&["proposal", "list"])["proposals"]
            .as_array()
            .unwrap()
            .len()
    };
    let before = proposals(dave);

    // --- Every command that would draft a change to the charter is refused, with
    // `--yes` too, and stores nothing.
    let erin_key = erin.device_key();
    let dave_key = dave.device_key();
    for args in [
        vec![
            "circle", "invite", &erin_key, "--circle", "team", "--member", "erin", "--yes",
        ],
        vec!["circle", "remove", "bob", "--circle", "team", "--yes"],
        vec!["circle", "amend", "--circle", "team", "--advisory", "--yes"],
        vec![
            "circle", "device", "add", &erin_key, "--circle", "team", "--yes",
        ],
        vec![
            "circle", "device", "remove", &dave_key, "--circle", "team", "--yes",
        ],
    ] {
        let (code, text) = dave.reads(&args);
        assert_eq!(code, 3, "{args:?}: {text}");
        assert!(
            text.contains("the charter in force carries 1 rule(s) that this node does not hold"),
            "{args:?}: {text}"
        );
        assert!(text.contains("Nothing was proposed."), "{args:?}: {text}");
        assert!(text.contains("`peerharness events import`"), "{text}");
        // Refused before anything is previewed: no preview claims what would change.
        assert!(!text.contains("This puts an amendment"), "{args:?}: {text}");
    }
    assert_eq!(proposals(dave), before, "nothing was stored");

    // --- Leaving is not refused, and changes his machine first. What it asks the
    // circle for changes the roll and nothing else: on Alice's complete node the
    // amendment carries exactly the rules in force.
    let left = dave.run(&["circle", "leave", "--circle", "team", "--yes"]);
    assert_eq!(left["left"], true, "{left}");
    let removal = left["proposal_id"].as_str().unwrap().to_owned();
    alice.run(&[
        "events",
        "import",
        &dave.export(&root.join("dave-left.jsonl")),
    ]);
    let json = alice.run(&["proposal", "show", &removal]);
    let amendment = &json["amendment"];
    assert_eq!(amendment["roll"]["removed"][0]["member"], "dave");
    assert_eq!(
        amendment["rules_in_force"],
        serde_json::json!({ "dropped": [], "added": [] }),
        "{amendment}"
    );
    let preview = alice.ballot_preview(&removal, "approve");
    assert!(
        preview.contains("the rules in force stay as they are (1 in force)"),
        "{preview}"
    );
    assert_eq!(alice.rules(), [c.skill.as_str()]);

    // --- A node that holds the rule drafts as before, and carries it.
    let admission = invite(alice, erin, "erin");
    let json = alice.run(&["proposal", "show", &admission]);
    assert_eq!(
        json["amendment"]["rules_in_force"],
        serde_json::json!({ "dropped": [], "added": [] })
    );
    // The amendment a modified client signed is on Alice's node too, and unchanged by
    // any of this: a file anyone may carry.
    assert_eq!(alice.run(&["events", "import", &c.file])["stored"], 0);
    assert_eq!(alice.approvals(&c.drops_the_rule), serde_json::json!([]));
}

/// Replaces `node`'s stand-in window with one that saves what it was asked to show,
/// then imports `file` into the node as its owner's own terminal would, and only then
/// answers Proceed. Returns where the window's text and the import's output are saved.
#[cfg(all(unix, debug_assertions))]
fn window_that_imports_before_it_proceeds(
    node: &Node,
    root: &Path,
    file: &str,
) -> (PathBuf, PathBuf) {
    let saw = root.join(format!("{}-window-saw", node.name));
    let log = root.join(format!("{}-import-during-the-window", node.name));
    let script = format!(
        "#!/bin/sh\ncat > '{saw}'\n\
         env -u CLAUDECODE -u PEERHARNESS_AGENT_SESSION '{bin}' events import '{file}' \
         > '{log}' 2>&1 || {{ echo declined; exit 0; }}\necho proceed\n",
        saw = saw.display(),
        bin = assert_cmd::cargo::cargo_bin("peerharness").display(),
        log = log.display(),
    );
    std::fs::write(&node.window, script).unwrap();
    (saw, log)
}

/// A command started by the coding agent's session of `node`: its exit code and
/// everything it printed.
#[cfg(all(unix, debug_assertions))]
fn in_session(node: &Node, args: &[&str]) -> (i32, String) {
    let out = node
        .bare()
        .arg("--json")
        .args(args)
        .env("CLAUDECODE", "1")
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// The proposals on a node: id, title and who approved, sorted by id.
#[cfg(all(unix, debug_assertions))]
fn proposals_and_approvals(node: &Node) -> Vec<(String, String, Value)> {
    let mut all: Vec<(String, String, Value)> = node.run(&["proposal", "list"])["proposals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["proposal_id"].as_str().unwrap().to_owned(),
                p["title"].as_str().unwrap().to_owned(),
                p["approvals"].clone(),
            )
        })
        .collect();
    all.sort_by(|a, b| a.0.cmp(&b.0));
    all
}

/// A request to change the charter is for the charter that was shown. Bob's agent
/// starts an invitation, and the window says "admit dave to the roll of charter 3".
/// While Bob reads, his node receives charter 4, which admitted Erin (here an import; a
/// daemon's sync does the same). Then he clicks Proceed. His draft was made from
/// charter 3: signed under charter 4, as it used to be, it is an amendment that admits
/// Dave and takes Erin off the roll again, with Bob's approval on it.
#[cfg(all(unix, debug_assertions))]
#[test]
fn a_yes_to_a_change_of_one_charter_is_not_signed_as_a_change_of_the_next() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let (alice, bob, carol) = trio(root);
    let dave = Node::new(root, "dave");
    let erin = Node::new(root, "erin");
    let on = bob.run(&["watch", "claude", "--install", "--dialogs", "--yes"]);
    assert_eq!(on["circle_windows"], true);

    // Alice and Carol admit Erin: charter 4. Nothing of it has reached Bob.
    let admission = invite(&alice, &erin, "erin");
    carry(root, &[&alice, &carol]);
    carol.run(&["proposal", "vote", &admission, "approve", "--yes"]);
    carry(root, &[&alice, &carol]);
    assert_eq!(
        alice.run(&["circle", "members", "--circle", "team"])["charter"]["seq"],
        4
    );
    assert_eq!(
        bob.run(&["circle", "members", "--circle", "team"])["charter"]["seq"],
        3
    );
    let newer = alice.export(&root.join("charter-4-for-bob.jsonl"));

    // --- His agent starts the invitation. The window gets the preview, and before it
    // answers Proceed the newer charter arrives.
    let dave_key = dave.device_key();
    let invitation = [
        "circle", "invite", &dave_key, "--circle", "team", "--member", "dave",
    ];
    let (saw, log) = window_that_imports_before_it_proceeds(&bob, root, &newer);
    let (code, printed) = in_session(&bob, &invitation);
    let shown = std::fs::read_to_string(&saw).unwrap_or_default();
    assert!(
        shown.contains(&format!(
            "admit dave (device {}) to the roll of charter 3",
            dave.fingerprint()
        )),
        "{shown}\n{printed}"
    );
    assert!(shown.contains("it passes with 2 of 3"), "{shown}");
    let during = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(during.contains("Imported"), "{during}\n{printed}");
    assert_eq!(
        bob.run(&["circle", "members", "--circle", "team"])["charter"]["seq"],
        4
    );

    // His click was for a change to charter 3. Nothing is proposed and nothing signed.
    assert_eq!(code, 3, "{printed}");
    assert!(
        printed.contains(
            "the circle's charter changed on this node while this was being confirmed. \
             Nothing was proposed and nothing was signed. Run the command again to see what \
             it would do now."
        ),
        "{printed}"
    );
    // His node holds what the file held and nothing more: no amendment that admits
    // Dave, and no ballot of Bob's that Alice's node does not have.
    let on_bob = proposals_and_approvals(&bob);
    assert_eq!(on_bob, proposals_and_approvals(&alice));
    assert!(on_bob.iter().all(|(_, title, _)| title != "Admit dave"));

    // --- Run again, the same command previews the charter that is in force now, with
    // Erin on its roll: four members, three approvals.
    std::fs::write(
        &bob.window,
        format!("#!/bin/sh\ncat > '{}'\necho declined\n", saw.display()),
    )
    .unwrap();
    let (code, printed) = in_session(&bob, &invitation);
    assert_eq!(code, 3, "{printed}");
    let shown = std::fs::read_to_string(&saw).unwrap();
    assert!(shown.contains("to the roll of charter 4"), "{shown}");
    assert!(shown.contains("it passes with 3 of 4"), "{shown}");
    assert_eq!(proposals_and_approvals(&bob), on_bob);

    // In his own terminal the invitation is made under charter 4 and keeps Erin.
    let made = invite(&bob, &dave, "dave");
    let json = bob.run(&["proposal", "show", &made]);
    assert_eq!(json["amendment"]["names_charter_seq"], 4);
    assert_eq!(json["amendment"]["roll"]["removed"], serde_json::json!([]));
    assert_eq!(json["amendment"]["roll"]["admitted"][0]["member"], "dave");
}

/// An approval is for what was shown, too. Bob's agent starts his ballot on the
/// admission of Dave, and the window says "What this amendment changes, and nothing
/// else: admit dave". While he reads, a rule that the others passed arrives on his
/// node. The admission was drafted before that rule, so approving it now also takes the
/// rule out of force: no longer "nothing else". His click signs nothing.
#[cfg(all(unix, debug_assertions))]
#[test]
fn an_approval_is_not_signed_for_what_an_amendment_changes_since_it_was_shown() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let (alice, bob, carol) = trio(root);
    let dave = Node::new(root, "dave");
    let on = bob.run(&["watch", "claude", "--install", "--dialogs", "--yes"]);
    assert_eq!(on["circle_windows"], true);

    // Alice proposes to admit Dave, and Bob's node gets the proposal.
    let admission = invite(&alice, &dave, "dave");
    bob.run(&[
        "events",
        "import",
        &alice.export(&root.join("admission.jsonl")),
    ]);
    // Then Alice and Carol pass a rule. Nothing of it has reached Bob.
    let (rule, skill) = propose(&alice, RULE);
    alice.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    carry(root, &[&alice, &carol]);
    carol.run(&["proposal", "vote", &rule, "approve", "--yes"]);
    carry(root, &[&alice, &carol]);
    assert_eq!(alice.rules(), [skill.as_str()]);
    assert!(bob.rules().is_empty());
    let newer = alice.export(&root.join("a-rule-passed.jsonl"));

    // --- His agent starts the ballot; the rule arrives while the window is open.
    let (saw, log) = window_that_imports_before_it_proceeds(&bob, root, &newer);
    let ballot = ["proposal", "vote", admission.as_str(), "approve"];
    let (code, printed) = in_session(&bob, &ballot);
    let shown = std::fs::read_to_string(&saw).unwrap_or_default();
    assert!(
        shown.contains("What this amendment changes, and nothing else:"),
        "{shown}\n{printed}"
    );
    assert!(shown.contains("admit dave (device "), "{shown}");
    let during = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(during.contains("Imported"), "{during}\n{printed}");
    assert_eq!(bob.rules(), [skill.as_str()]);

    // Nothing is signed: the amendment no longer changes what the window said.
    assert_eq!(code, 3, "{printed}");
    assert!(
        printed.contains(
            "what this amendment would change is no longer what you were shown: the charter \
             or the rules in force changed on this node while you read. Nothing was signed. \
             Run the command again."
        ),
        "{printed}"
    );
    assert_eq!(bob.approvals(&admission), serde_json::json!(["alice"]));

    // --- Run again, it is no ballot for a window any more, and his terminal says which
    // rule the admission would now drop. Having read that, the approval is his to give.
    std::fs::write(
        &bob.window,
        format!(
            "#!/bin/sh\ncat > /dev/null\necho opened >> '{}'\necho proceed\n",
            bob.opened.display()
        ),
    )
    .unwrap();
    let (code, printed) = in_session(&bob, &ballot);
    assert_eq!(code, 3, "{printed}");
    assert!(printed.contains("your own terminal"), "{printed}");
    assert!(!bob.opened.exists(), "a window was opened\n{printed}");
    let preview = bob.ballot_preview(&admission, "approve");
    assert!(
        preview.contains(&format!(
            "rule {skill} goes out of force: the amendment does not carry it"
        )),
        "{preview}"
    );
    assert_eq!(bob.approvals(&admission), serde_json::json!(["alice"]));
    bob.run(&["proposal", "vote", &admission, "approve", "--yes"]);
    assert_eq!(
        bob.approvals(&admission),
        serde_json::json!(["alice", "bob"])
    );
}
