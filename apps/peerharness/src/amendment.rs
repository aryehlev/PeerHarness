//! What an amendment changes, read from its signed content.
//!
//! An `amend` proposal carries the complete proposed charter content `next`. Its title
//! is text the proposer wrote and proves nothing: "Admit dave" can be the title of an
//! amendment that also replaces another member's device key, lowers a threshold or
//! lists a rule nobody voted on. Before a member signs a ballot on an amendment, and
//! in `proposal show`, PeerHarness therefore says what `next` changes against the
//! charter the proposal names:
//!
//! * members admitted and removed, with their device fingerprints and scopes;
//! * for members who stay, the devices added and removed and any change of scopes;
//! * the rules of the vote, old and new, when they change;
//! * the rules in force on this node that `next.carried` leaves out, and the proposals
//!   it lists that are not in force here, with the text of each such rule;
//! * the rules the charter in force carries that this node does not hold and that
//!   `next.carried` leaves out. Such a rule goes out of force as well, and this node
//!   cannot name it: it says so, and no approval is signed here.
//!
//! [`changes`] is a pure function of the two contents and of what this node knows about
//! the rules ([`Rules`], which `governance::amendment_changes` reads from the store).
//! Nothing here counts a ballot or changes what passes. It is what a person is shown,
//! and [`Changes::unread`] is why `proposal vote` declines to sign an approval of
//! something this node could not show.
//!
//! Member handles, scopes and skill names are validated identifiers. A rule's text is
//! written by a member: it is shown line by line behind a prefix ([`quoted`]), so that
//! no line of it can pass for one of the lines written here.

use ph_core::{DeviceKey, EventId, Scope};
use ph_protocol::{CharterContent, CharterRules, RollEntry};
use ph_skills::Bundle;
use serde_json::{json, Value};

use crate::output::{quoted, short_id};

/// What changes for a member who stays on the roll.
struct MemberChange {
    /// The member's handle.
    member: String,
    /// Device keys the amendment adds to the member.
    devices_added: Vec<DeviceKey>,
    /// Device keys the amendment takes from the member.
    devices_removed: Vec<DeviceKey>,
    /// How many of the devices the member has now stay.
    devices_kept: usize,
    /// The member's scopes before and after, when they change.
    scopes: Option<(Vec<Scope>, Vec<Scope>)>,
}

/// A rule the amendment does not carry: one in force on this node, or one the charter
/// in force carries that this node does not hold.
pub struct Dropped {
    /// The rule's skill name. `None` when the charter in force carries the proposal and
    /// this node does not hold it: the rule exists for the circle, and this node can
    /// say neither its name nor its text.
    pub skill_name: Option<String>,
    /// The `adopt` proposal that put it in force.
    pub proposal_id: EventId,
}

/// A proposal the amendment carries that is not a rule in force on this node.
pub struct Added {
    /// The id the amendment lists.
    pub proposal_id: EventId,
    /// The rule, when this node holds that id as an `adopt` proposal of the circle.
    pub rule: Option<AddedRule>,
}

/// A rule the amendment would put in force without a vote of its own.
pub struct AddedRule {
    /// The rule's skill name, from the signed `adopt` proposal.
    pub skill_name: String,
    /// The rule's text, when this node has it.
    pub text: Option<Bundle>,
    /// A rule in force with the same name that the amendment carries as well. One rule
    /// per name is in force, the later proposal of the two, so listing both does not
    /// add a rule: it replaces the text of one, or changes nothing.
    pub same_name: Option<SameName>,
}

/// How a listed proposal stands to a rule in force of the same name that the amendment
/// also carries. Which of the two is the later one is read from what each signed (its
/// time, then its id), as the rule set reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SameName {
    /// The listed proposal is the later one. Under the next charter it is the rule of
    /// that name, and the rule in force (this proposal) goes out of force.
    Replaces(EventId),
    /// The rule in force (this proposal) is the later one and stays. The listed
    /// proposal does not come into force.
    Behind(EventId),
}

/// How the amendment's `carried` list compares with the rules in force on this node.
pub enum Rules {
    /// The proposal names a charter that is not the current one. It counts only under
    /// the charter it names (it passed then, or can no longer pass), so its list is not
    /// compared with the rules in force now.
    Lapsed {
        /// The `seq` of the charter in force on this node.
        current_seq: u64,
    },
    /// The proposal names the current charter.
    Compared {
        /// How many rules are in force on this node.
        in_force: usize,
        /// Rules in force that the amendment leaves out, and rules the charter in force
        /// carries, which this node does not hold, that it leaves out.
        dropped: Vec<Dropped>,
        /// Listed proposals that are not in force here.
        added: Vec<Added>,
    },
}

/// Why an approval cannot be given on this node: something the amendment would put in
/// force, or take out of force, cannot be shown here, so its voter cannot have read it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Unread {
    /// The amendment carries an id this node does not hold as a rule proposal.
    Proposal,
    /// The amendment carries a rule whose text this node does not have.
    Text,
    /// The amendment leaves out a rule that the charter in force carries and this node
    /// does not hold: it would take a rule out of force that this node cannot name.
    Dropped,
}

impl Unread {
    /// The refusal of an approval. Names nothing a member wrote.
    pub const fn refusal(self) -> &'static str {
        match self {
            Unread::Proposal => {
                "that amendment carries a rule proposal this node does not hold, so this node \
                 cannot show what it would put in force and you cannot have read what you \
                 would approve. Import the proposer's events file first."
            }
            Unread::Text => {
                "that amendment would put a rule in force whose text this node does not have, \
                 so you cannot have read what you would approve. Import the proposer's events \
                 file first."
            }
            Unread::Dropped => {
                "that amendment leaves out a rule that the charter in force carries and this \
                 node does not hold, so this node cannot show which rule it would take out of \
                 force and you cannot have read what you would approve. Import the events \
                 file of a member who holds that rule first (`peerharness events import`)."
            }
        }
    }

    /// The same, as a line of `proposal show`.
    pub const fn missing(self) -> &'static str {
        match self {
            Unread::Proposal => "it carries a rule proposal this node does not hold",
            Unread::Text => "it would put a rule in force whose text is not on this node",
            Unread::Dropped => {
                "it leaves out a rule the charter in force carries, which this node does not \
                 hold"
            }
        }
    }
}

/// What an amendment changes. Built by [`changes`].
pub struct Changes {
    seq: u64,
    members_before: usize,
    members_after: usize,
    /// The handle of the member this node's device signs for, on the named roll.
    you: Option<String>,
    admitted: Vec<RollEntry>,
    removed: Vec<RollEntry>,
    changed: Vec<MemberChange>,
    /// The rules of the vote before and after, when they change.
    vote_rules: Option<(CharterRules, CharterRules)>,
    rules: Rules,
}

/// What the signed `next` changes against `named`, the content of the charter with
/// sequence number `seq` that the proposal names. `rules` is how `next.carried`
/// compares with the rules in force; `me` is this node's device, to mark its member.
pub fn changes(
    seq: u64,
    named: &CharterContent,
    next: &CharterContent,
    rules: Rules,
    me: Option<&DeviceKey>,
) -> Changes {
    let admitted = next
        .roll
        .iter()
        .filter(|e| named.member(&e.member).is_none())
        .cloned()
        .collect();
    let removed = named
        .roll
        .iter()
        .filter(|e| next.member(&e.member).is_none())
        .cloned()
        .collect();
    let mut changed = Vec::new();
    for before in &named.roll {
        let Some(after) = next.member(&before.member) else {
            continue;
        };
        let devices_added: Vec<DeviceKey> = after
            .devices
            .iter()
            .filter(|d| !before.has_device(d))
            .copied()
            .collect();
        let devices_removed: Vec<DeviceKey> = before
            .devices
            .iter()
            .filter(|d| !after.has_device(d))
            .copied()
            .collect();
        let sorted = |scopes: &[Scope]| {
            let mut s = scopes.to_vec();
            s.sort();
            s.dedup();
            s
        };
        let scopes = (sorted(&before.scopes) != sorted(&after.scopes))
            .then(|| (before.scopes.clone(), after.scopes.clone()));
        if devices_added.is_empty() && devices_removed.is_empty() && scopes.is_none() {
            continue;
        }
        changed.push(MemberChange {
            member: before.member.clone(),
            devices_kept: before.devices.len() - devices_removed.len(),
            devices_added,
            devices_removed,
            scopes,
        });
    }
    Changes {
        seq,
        members_before: named.roll.len(),
        members_after: next.roll.len(),
        you: me
            .and_then(|d| named.member_of(d))
            .map(|e| e.member.clone()),
        admitted,
        removed,
        changed,
        vote_rules: (named.rules != next.rules).then_some((named.rules, next.rules)),
        rules,
    }
}

/// The lines of a description under construction.
struct Lines<'a> {
    indent: &'a str,
    lines: Vec<String>,
}

impl Lines<'_> {
    /// One line of ours, `depth` levels in.
    fn line(&mut self, depth: usize, text: impl AsRef<str>) {
        self.lines.push(format!(
            "{}{}{}",
            self.indent,
            "  ".repeat(depth),
            text.as_ref()
        ));
    }

    /// Text a member wrote, `depth` levels in: every line of it behind a mark.
    fn member_text(&mut self, depth: usize, text: &str) {
        let prefix = format!("{}{}| ", self.indent, "  ".repeat(depth));
        self.lines.push(quoted(text, &prefix));
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn fingerprints(devices: &[DeviceKey]) -> String {
    devices
        .iter()
        .map(DeviceKey::fingerprint)
        .collect::<Vec<_>>()
        .join(", ")
}

fn scope_list(scopes: &[Scope]) -> String {
    scopes
        .iter()
        .map(Scope::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

/// A roll entry in one line: `(device 1234-..., scopes *)`.
fn entry_line(entry: &RollEntry) -> String {
    format!(
        "(device{} {}, scopes {})",
        plural(entry.devices.len()),
        fingerprints(&entry.devices),
        scope_list(&entry.scopes)
    )
}

fn devices_json(devices: &[DeviceKey]) -> Value {
    devices
        .iter()
        .map(|d| json!({ "device_key": d, "fingerprint": d.fingerprint() }))
        .collect()
}

fn entry_json(entry: &RollEntry) -> Value {
    json!({
        "member": entry.member,
        "devices": devices_json(&entry.devices),
        "scopes": entry.scopes,
    })
}

impl Changes {
    /// Why an approval cannot be given on this node, if anything the amendment would
    /// put in force cannot be shown here.
    pub fn unread(&self) -> Option<Unread> {
        let Rules::Compared { added, dropped, .. } = &self.rules else {
            return None;
        };
        if added.iter().any(|a| a.rule.is_none()) {
            return Some(Unread::Proposal);
        }
        // A listed proposal that stays behind a later rule of its name puts nothing in
        // force: there is no text of it to have read.
        if added.iter().any(|a| {
            a.rule.as_ref().is_some_and(|r| {
                r.text.is_none() && !matches!(r.same_name, Some(SameName::Behind(_)))
            })
        }) {
            return Some(Unread::Text);
        }
        // Losing a rule this node can name is something its owner may approve. Losing
        // one it cannot name is not something they can have read.
        dropped
            .iter()
            .any(|d| d.skill_name.is_none())
            .then_some(Unread::Dropped)
    }

    fn who(&self, member: &str) -> String {
        if self.you.as_deref() == Some(member) {
            format!("{member} (you)")
        } else {
            member.to_owned()
        }
    }

    /// The changes as lines for a person, each beginning with `indent`. Three parts,
    /// always in this order and always present: the roll, the rules of the vote, the
    /// rules in force.
    pub fn describe(&self, indent: &str) -> String {
        let mut out = Lines {
            indent,
            lines: Vec::new(),
        };

        // --- The roll.
        let seq = self.seq;
        let before = self.members_before;
        if self.admitted.is_empty() && self.removed.is_empty() && self.changed.is_empty() {
            out.line(
                0,
                format!(
                    "the roll of charter {seq} stays as it is ({before} member{})",
                    plural(before)
                ),
            );
        } else {
            out.line(
                0,
                format!(
                    "the roll of charter {seq} ({before} member{}; {} after):",
                    plural(before),
                    self.members_after
                ),
            );
        }
        for entry in &self.admitted {
            out.line(1, format!("admits {} {}", entry.member, entry_line(entry)));
        }
        for entry in &self.removed {
            out.line(
                1,
                format!("removes {} {}", self.who(&entry.member), entry_line(entry)),
            );
        }
        for change in &self.changed {
            let member = &change.member;
            let who = self.who(member);
            for device in &change.devices_added {
                out.line(
                    1,
                    format!(
                        "{who} gets device {} as well: whoever holds it can sign and vote as \
                         {member}",
                        device.fingerprint()
                    ),
                );
            }
            for device in &change.devices_removed {
                out.line(1, format!("{who} loses device {}", device.fingerprint()));
            }
            if change.devices_kept == 0 {
                out.line(
                    2,
                    format!(
                        "none of the devices {member} has now stays: only whoever holds a new \
                         one can sign and vote as {member}"
                    ),
                );
            }
            if let Some((old, new)) = &change.scopes {
                out.line(
                    1,
                    format!(
                        "{who}'s scopes become {} (now {})",
                        scope_list(new),
                        scope_list(old)
                    ),
                );
            }
        }

        // --- The rules of the vote.
        match &self.vote_rules {
            None => out.line(0, "the rules of the vote stay as they are"),
            Some((old, new)) => {
                out.line(0, "the rules of the vote:");
                if new.pass != old.pass {
                    out.line(
                        1,
                        format!(
                            "a rule passes with more than {}/{} of its electorate (now {}/{})",
                            new.pass.num, new.pass.den, old.pass.num, old.pass.den
                        ),
                    );
                }
                if new.amend != old.amend {
                    out.line(
                        1,
                        format!(
                            "changing these rules needs more than {}/{} of the roll (now {}/{})",
                            new.amend.num, new.amend.den, old.amend.num, old.amend.den
                        ),
                    );
                }
                if new.binding != old.binding {
                    let force = |binding: bool| if binding { "binding" } else { "advisory" };
                    out.line(
                        1,
                        format!(
                            "passed rules become {} (now {})",
                            force(new.binding),
                            force(old.binding)
                        ),
                    );
                }
            }
        }

        // --- The rules in force.
        match &self.rules {
            Rules::Lapsed { current_seq } => out.line(
                0,
                format!(
                    "the rules in force: not compared. This proposal names charter {seq} and \
                     charter {current_seq} is in force here; a proposal counts only under the \
                     charter it names."
                ),
            ),
            Rules::Compared {
                in_force,
                dropped,
                added,
            } if dropped.is_empty() && added.is_empty() => out.line(
                0,
                format!("the rules in force stay as they are ({in_force} in force)"),
            ),
            Rules::Compared {
                in_force,
                dropped,
                added,
            } => {
                out.line(0, format!("the rules in force ({in_force} now):"));
                for rule in dropped {
                    let id = short_id(&rule.proposal_id);
                    out.line(
                        1,
                        match &rule.skill_name {
                            Some(name) => format!(
                                "rule {name} goes out of force: the amendment does not carry \
                                 it (proposal {id})"
                            ),
                            None => format!(
                                "a rule the charter in force carries, which this node does \
                                 not hold, goes out of force: the amendment does not carry it \
                                 (proposal {id}). This node cannot say which rule that is"
                            ),
                        },
                    );
                }
                for listed in added {
                    let id = short_id(&listed.proposal_id);
                    let Some(rule) = &listed.rule else {
                        out.line(
                            1,
                            format!(
                                "it carries {id}, which is not a rule proposal this node \
                                 holds: this node cannot say what that would put in force"
                            ),
                        );
                        continue;
                    };
                    let name = &rule.skill_name;
                    match rule.same_name {
                        Some(SameName::Behind(in_force)) => {
                            out.line(
                                1,
                                format!(
                                    "it carries {id}, an earlier proposal for rule {name}: \
                                     the rule of that name in force (proposal {}) is the \
                                     later one and stays as it is",
                                    short_id(&in_force)
                                ),
                            );
                            continue;
                        }
                        Some(SameName::Replaces(in_force)) => out.line(
                            1,
                            format!(
                                "rule {name} gets another text without a vote of its own: \
                                 the amendment carries proposal {id}, which is not in force \
                                 here and is later than the rule in force (proposal {}). \
                                 That one goes out of force",
                                short_id(&in_force)
                            ),
                        ),
                        None => out.line(
                            1,
                            format!(
                                "rule {name} comes into force without a vote of its own: the \
                                 amendment carries it and it is not in force here (proposal \
                                 {id})"
                            ),
                        ),
                    }
                    let Some(bundle) = &rule.text else {
                        out.line(
                            2,
                            "its text is not on this node yet (import the proposer's events file)",
                        );
                        continue;
                    };
                    out.line(
                        2,
                        format!("its text ({} bytes), exactly as proposed:", bundle.size()),
                    );
                    out.member_text(3, bundle.skill_md());
                    let findings = bundle.scan();
                    for f in &findings {
                        out.line(2, format!("scanner, line {}: {}", f.line, f.explanation()));
                    }
                    if ph_skills::has_high_risk(&findings) {
                        out.line(
                            2,
                            "HIGH RISK findings above. Scanning never proves a text is safe.",
                        );
                    }
                }
            }
        }
        out.lines.join("\n") + "\n"
    }

    /// The changes for `proposal show --json`. A rule's text is not part of it.
    pub fn json(&self) -> Value {
        let changed: Vec<Value> = self
            .changed
            .iter()
            .map(|c| {
                json!({
                    "member": c.member,
                    "devices_added": devices_json(&c.devices_added),
                    "devices_removed": devices_json(&c.devices_removed),
                    "devices_kept": c.devices_kept,
                    "scopes_before": c.scopes.as_ref().map(|(old, _)| old),
                    "scopes_after": c.scopes.as_ref().map(|(_, new)| new),
                })
            })
            .collect();
        let rules_in_force = match &self.rules {
            Rules::Lapsed { .. } => Value::Null,
            Rules::Compared { dropped, added, .. } => json!({
                "dropped": dropped.iter().map(|d| json!({
                    "skill_name": d.skill_name,
                    "proposal_id": d.proposal_id,
                })).collect::<Vec<_>>(),
                "added": added.iter().map(|a| {
                    let text = a.rule.as_ref().and_then(|r| r.text.as_ref());
                    let same_name = a.rule.as_ref().and_then(|r| r.same_name);
                    json!({
                        "proposal_id": a.proposal_id,
                        "skill_name": a.rule.as_ref().map(|r| r.skill_name.as_str()),
                        "text_on_this_node": text.is_some(),
                        "high_risk": text.map(|b| ph_skills::has_high_risk(&b.scan())),
                        // A rule in force of the same name that the amendment carries
                        // too: replaced by this proposal, or staying in front of it.
                        "replaces": match same_name {
                            Some(SameName::Replaces(id)) => json!(id),
                            _ => Value::Null,
                        },
                        "stays_behind": match same_name {
                            Some(SameName::Behind(id)) => json!(id),
                            _ => Value::Null,
                        },
                    })
                }).collect::<Vec<_>>(),
            }),
        };
        json!({
            "names_charter_seq": self.seq,
            "roll": {
                "members_before": self.members_before,
                "members_after": self.members_after,
                "admitted": self.admitted.iter().map(entry_json).collect::<Vec<_>>(),
                "removed": self.removed.iter().map(entry_json).collect::<Vec<_>>(),
                "changed": changed,
            },
            "rules_of_the_vote": self.vote_rules.map(|(before, after)| json!({
                "before": before,
                "after": after,
            })),
            "rules_in_force": rules_in_force,
            "can_be_approved_here": self.unread().is_none(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ph_core::Digest;
    use ph_protocol::Threshold;

    fn device(seed: u8) -> DeviceKey {
        DeviceKey::from_signing_key(&SigningKey::from_bytes(&[seed; 32]))
    }

    fn fp(seed: u8) -> String {
        device(seed).fingerprint()
    }

    fn entry(member: &str, seeds: &[u8], scopes: &[&str]) -> RollEntry {
        RollEntry::new(
            member,
            seeds.iter().map(|s| device(*s)).collect(),
            scopes.iter().map(|s| Scope::new(s).unwrap()).collect(),
        )
    }

    /// alice (device 1), bob (device 2) and mallory (device 3), default rules.
    fn trio() -> CharterContent {
        let mut c = CharterContent::founding(entry("alice", &[1], &["*"]));
        c.roll.push(entry("bob", &[2], &["*"]));
        c.roll.push(entry("mallory", &[3], &["*"]));
        c.normalize();
        c
    }

    fn id(n: u8) -> EventId {
        EventId::from_digest(Digest::sha256(&[n]))
    }

    fn exact(in_force: usize) -> Rules {
        Rules::Compared {
            in_force,
            dropped: Vec::new(),
            added: Vec::new(),
        }
    }

    fn rule_text(name: &str, body: &str) -> Bundle {
        let md = format!("---\nname: {name}\ndescription: A rule.\n---\n\n# Rule\n\n{body}\n");
        ph_skills::build_bundle(&md, Some(name)).unwrap()
    }

    fn lines(text: &str) -> Vec<&str> {
        text.lines().collect()
    }

    #[test]
    fn an_amendment_that_changes_nothing_says_so_in_three_lines() {
        let named = trio();
        let c = changes(3, &named, &named.clone(), exact(2), Some(&device(1)));
        assert_eq!(
            lines(&c.describe("  ")),
            [
                "  the roll of charter 3 stays as it is (3 members)",
                "  the rules of the vote stay as they are",
                "  the rules in force stay as they are (2 in force)",
            ]
        );
        assert_eq!(c.unread(), None);
        let json = c.json();
        assert_eq!(json["roll"]["changed"], json!([]));
        assert_eq!(json["rules_of_the_vote"], Value::Null);
        assert_eq!(json["can_be_approved_here"], true);
    }

    /// The audit's first case: the title says "Admit dave", and the amendment does admit
    /// dave. It also replaces bob's device key with one the proposer made. The names on
    /// the roll are the same either way, so only the description of the signed content
    /// can tell a voter.
    #[test]
    fn an_admission_that_also_replaces_another_members_device_says_so() {
        let named = trio();
        let mut next = named.clone();
        next.roll.retain(|e| e.member != "bob");
        next.roll.push(entry("bob", &[9], &["*"]));
        next.roll.push(entry("dave", &[4], &["*"]));
        next.normalize();

        // Alice is asked to approve it; bob is the member whose key it replaces.
        let said = changes(3, &named, &next, exact(0), Some(&device(1))).describe("  ");
        let expected = [
            "  the roll of charter 3 (3 members; 4 after):".to_owned(),
            format!("    admits dave (device {}, scopes *)", fp(4)),
            format!(
                "    bob gets device {} as well: whoever holds it can sign and vote as bob",
                fp(9)
            ),
            format!("    bob loses device {}", fp(2)),
            "      none of the devices bob has now stays: only whoever holds a new one can \
             sign and vote as bob"
                .to_owned(),
            "  the rules of the vote stay as they are".to_owned(),
            "  the rules in force stay as they are (0 in force)".to_owned(),
        ];
        assert_eq!(lines(&said), expected);
        // Nothing in it comes from a title: the function is never given one.
        assert!(!said.contains("Admit"));

        // On bob's own node the lines about his key are marked as being about him.
        let bobs = changes(3, &named, &next, exact(0), Some(&device(2))).describe("");
        assert!(
            bobs.contains(&format!("bob (you) loses device {}", fp(2))),
            "{bobs}"
        );

        let json = changes(3, &named, &next, exact(0), None).json();
        assert_eq!(json["names_charter_seq"], 3);
        assert_eq!(json["roll"]["members_before"], 3);
        assert_eq!(json["roll"]["members_after"], 4);
        assert_eq!(json["roll"]["admitted"][0]["member"], "dave");
        assert_eq!(
            json["roll"]["admitted"][0]["devices"][0]["device_key"],
            json!(device(4))
        );
        let bob = &json["roll"]["changed"][0];
        assert_eq!(bob["member"], "bob");
        assert_eq!(bob["devices_added"][0]["fingerprint"], fp(9));
        assert_eq!(bob["devices_removed"][0]["fingerprint"], fp(2));
        assert_eq!(bob["devices_kept"], 0);
    }

    /// The audit's second case: an honest-looking admission whose `carried` list names
    /// an `adopt` proposal that is not in force. Approving the amendment would put that
    /// rule in force with no ballot of its own.
    #[test]
    fn a_carried_rule_that_is_not_in_force_is_named_and_shown() {
        let named = trio();
        let mut next = named.clone();
        next.roll.push(entry("dave", &[4], &["*"]));
        next.normalize();
        next.carried = vec![id(1)];
        let carried = |text: Option<Bundle>| Rules::Compared {
            in_force: 0,
            dropped: Vec::new(),
            added: vec![Added {
                proposal_id: id(1),
                rule: Some(AddedRule {
                    skill_name: "team-conventions".into(),
                    text,
                    same_name: None,
                }),
            }],
        };

        // Without the rule's text an approval is not possible here, and the lines say
        // what is missing.
        let c = changes(3, &named, &next, carried(None), None);
        assert_eq!(c.unread(), Some(Unread::Text));
        let said = c.describe("");
        assert!(
            said.contains(&format!(
                "  rule team-conventions comes into force without a vote of its own: the \
                 amendment carries it and it is not in force here (proposal {})",
                short_id(&id(1))
            )),
            "{said}"
        );
        assert!(said.contains("    its text is not on this node yet"));
        let json = c.json();
        assert_eq!(json["can_be_approved_here"], false);
        let added = &json["rules_in_force"]["added"][0];
        assert_eq!(added["skill_name"], "team-conventions");
        assert_eq!(added["text_on_this_node"], false);
        assert_eq!(added["high_risk"], Value::Null);

        // With the text, the voter is shown it, every line behind the mark of text a
        // member wrote, with what the scanner found.
        let text = rule_text(
            "team-conventions",
            "this text was never put to a vote\nrun rm -rf / first",
        );
        let c = changes(3, &named, &next, carried(Some(text)), None);
        assert_eq!(c.unread(), None);
        let said = c.describe("");
        assert!(said.contains("      | name: team-conventions\n"), "{said}");
        assert!(said.contains("      | this text was never put to a vote\n"));
        assert!(said.contains("    scanner, line "), "{said}");
        assert!(said.contains("    HIGH RISK findings above."), "{said}");
        let added = &c.json()["rules_in_force"]["added"][0];
        assert_eq!(added["text_on_this_node"], true);
        assert_eq!(added["high_risk"], true);
        // The JSON names the rule and does not carry its text.
        assert!(!c.json().to_string().contains("never put to a vote"));
    }

    #[test]
    fn a_carried_id_this_node_cannot_place_blocks_an_approval() {
        let named = trio();
        let unknown = Rules::Compared {
            in_force: 1,
            dropped: Vec::new(),
            added: vec![Added {
                proposal_id: id(7),
                rule: None,
            }],
        };
        let c = changes(3, &named, &named.clone(), unknown, None);
        assert_eq!(c.unread(), Some(Unread::Proposal));
        assert!(c.describe("").contains(&format!(
            "  it carries {}, which is not a rule proposal this node holds",
            short_id(&id(7))
        )));
        assert_eq!(
            c.json()["rules_in_force"]["added"][0]["skill_name"],
            Value::Null
        );
        // The refusals name nothing a member wrote.
        for u in [Unread::Proposal, Unread::Text] {
            assert!(u
                .refusal()
                .contains("you cannot have read what you would approve"));
            assert!(!u.missing().is_empty());
        }
    }

    #[test]
    fn dropped_rules_are_named() {
        let named = trio();
        let rules = Rules::Compared {
            in_force: 2,
            dropped: vec![Dropped {
                skill_name: Some("use-pnpm".into()),
                proposal_id: id(5),
            }],
            added: Vec::new(),
        };
        let c = changes(3, &named, &named.clone(), rules, None);
        // Losing a rule is something a voter may approve: nothing is unread.
        assert_eq!(c.unread(), None);
        let said = c.describe("");
        assert!(said.contains("the rules in force (2 now):\n"), "{said}");
        assert!(said.contains(&format!(
            "  rule use-pnpm goes out of force: the amendment does not carry it (proposal {})",
            short_id(&id(5))
        )));
        assert_eq!(
            c.json()["rules_in_force"]["dropped"][0]["skill_name"],
            "use-pnpm"
        );
    }

    /// A rule the charter in force carries and this node does not hold: an amendment
    /// that leaves it out takes it out of force for the circle. This node cannot name
    /// it, so it does not say that the rules stay as they are, and it signs no approval.
    #[test]
    fn a_dropped_rule_this_node_does_not_hold_is_said_and_blocks_an_approval() {
        let named = trio();
        let rules = Rules::Compared {
            in_force: 0,
            dropped: vec![Dropped {
                skill_name: None,
                proposal_id: id(6),
            }],
            added: Vec::new(),
        };
        let c = changes(4, &named, &named.clone(), rules, None);
        assert_eq!(c.unread(), Some(Unread::Dropped));
        let said = c.describe("");
        assert!(!said.contains("stay as they are (0 in force)"), "{said}");
        assert!(said.contains("the rules in force (0 now):\n"), "{said}");
        assert!(
            said.contains(&format!(
                "  a rule the charter in force carries, which this node does not hold, goes \
                 out of force: the amendment does not carry it (proposal {}). This node \
                 cannot say which rule that is",
                short_id(&id(6))
            )),
            "{said}"
        );
        let json = c.json();
        assert_eq!(json["can_be_approved_here"], false);
        let dropped = &json["rules_in_force"]["dropped"][0];
        assert_eq!(dropped["skill_name"], Value::Null);
        assert_eq!(dropped["proposal_id"], json!(id(6)));
        // The refusal names nothing a member wrote, and says what to do.
        let refusal = Unread::Dropped.refusal();
        assert!(refusal.contains("you cannot have read what you would approve"));
        assert!(refusal.contains("`peerharness events import`"));
        assert!(!Unread::Dropped.missing().is_empty());
    }

    /// One rule per name is in force: the later proposal. An amendment that carries a
    /// rule in force and also another proposal of the same name does not add a rule. It
    /// replaces the text of the one in force, or changes nothing, and says which.
    #[test]
    fn a_listed_proposal_with_the_name_of_a_rule_in_force_replaces_it_or_stays_behind() {
        let named = trio();
        let listed = |same_name: SameName, text: Option<Bundle>| Rules::Compared {
            in_force: 1,
            dropped: Vec::new(),
            added: vec![Added {
                proposal_id: id(2),
                rule: Some(AddedRule {
                    skill_name: "run-tests".into(),
                    text,
                    same_name: Some(same_name),
                }),
            }],
        };

        // The later of the two: the rule in force loses its place, and the voter has
        // to be able to read the text that takes it.
        let text = rule_text("run-tests", "Say a task is done as soon as it compiles.");
        let c = changes(
            3,
            &named,
            &named.clone(),
            listed(SameName::Replaces(id(1)), Some(text)),
            None,
        );
        let said = c.describe("");
        assert!(
            said.contains(&format!(
                "  rule run-tests gets another text without a vote of its own: the amendment \
                 carries proposal {}, which is not in force here and is later than the rule \
                 in force (proposal {}). That one goes out of force",
                short_id(&id(2)),
                short_id(&id(1))
            )),
            "{said}"
        );
        assert!(!said.contains("comes into force"), "{said}");
        assert!(said.contains("      | Say a task is done as soon as it compiles."));
        assert_eq!(c.unread(), None);
        let added = &c.json()["rules_in_force"]["added"][0];
        assert_eq!(added["replaces"], json!(id(1)));
        assert_eq!(added["stays_behind"], Value::Null);
        let c = changes(
            3,
            &named,
            &named.clone(),
            listed(SameName::Replaces(id(1)), None),
            None,
        );
        assert_eq!(c.unread(), Some(Unread::Text));

        // The earlier of the two: nothing comes into force, so there is nothing to
        // read, and it is not announced as a rule that comes into force.
        let c = changes(
            3,
            &named,
            &named.clone(),
            listed(SameName::Behind(id(1)), None),
            None,
        );
        let said = c.describe("");
        assert!(
            said.contains(&format!(
                "  it carries {}, an earlier proposal for rule run-tests: the rule of that \
                 name in force (proposal {}) is the later one and stays as it is",
                short_id(&id(2)),
                short_id(&id(1))
            )),
            "{said}"
        );
        assert!(!said.contains("comes into force") && !said.contains("its text"));
        assert_eq!(c.unread(), None);
        let added = &c.json()["rules_in_force"]["added"][0];
        assert_eq!(added["stays_behind"], json!(id(1)));
        assert_eq!(added["replaces"], Value::Null);
    }

    #[test]
    fn the_rules_of_the_vote_are_shown_old_and_new() {
        let named = trio();
        let mut next = named.clone();
        next.rules = CharterRules {
            pass: Threshold::TWO_THIRDS,
            amend: Threshold { num: 3, den: 4 },
            binding: false,
        };
        let c = changes(3, &named, &next, exact(0), None);
        assert_eq!(
            lines(&c.describe("")),
            [
                "the roll of charter 3 stays as it is (3 members)",
                "the rules of the vote:",
                "  a rule passes with more than 2/3 of its electorate (now 1/2)",
                "  changing these rules needs more than 3/4 of the roll (now 2/3)",
                "  passed rules become advisory (now binding)",
                "the rules in force stay as they are (0 in force)",
            ]
        );
        let rules = &c.json()["rules_of_the_vote"];
        assert_eq!(rules["before"]["pass"], json!({ "num": 1, "den": 2 }));
        assert_eq!(rules["after"]["amend"], json!({ "num": 3, "den": 4 }));
        assert_eq!(rules["after"]["binding"], false);

        // Only what changes is listed.
        let mut next = named.clone();
        next.rules.binding = false;
        let said = changes(3, &named, &next, exact(0), None).describe("");
        assert!(said.contains("passed rules become advisory (now binding)"));
        assert!(!said.contains("a rule passes with") && !said.contains("changing these"));
    }

    #[test]
    fn removals_devices_and_scopes_are_shown_per_member() {
        let mut named = trio();
        named.roll.push(entry("carol", &[5, 6], &["team/backend"]));
        named.normalize();
        let mut next = named.clone();
        // mallory is removed; carol loses one of two devices and gets every scope; a
        // device moves from bob to alice.
        next.roll.retain(|e| e.member != "mallory");
        for e in &mut next.roll {
            match e.member.as_str() {
                "carol" => *e = entry("carol", &[5], &["*"]),
                "alice" => *e = entry("alice", &[1, 2], &["*"]),
                "bob" => *e = entry("bob", &[8], &["*"]),
                _ => {}
            }
        }
        let c = changes(4, &named, &next, exact(0), Some(&device(3)));
        let said = c.describe("");
        let expected = [
            "the roll of charter 4 (4 members; 3 after):".to_owned(),
            format!("  removes mallory (you) (device {}, scopes *)", fp(3)),
            format!(
                "  alice gets device {} as well: whoever holds it can sign and vote as alice",
                fp(2)
            ),
            format!(
                "  bob gets device {} as well: whoever holds it can sign and vote as bob",
                fp(8)
            ),
            format!("  bob loses device {}", fp(2)),
            "    none of the devices bob has now stays: only whoever holds a new one can sign \
             and vote as bob"
                .to_owned(),
            format!("  carol loses device {}", fp(6)),
            "  carol's scopes become * (now team/backend)".to_owned(),
            "the rules of the vote stay as they are".to_owned(),
            "the rules in force stay as they are (0 in force)".to_owned(),
        ];
        assert_eq!(lines(&said), expected);
        let json = c.json();
        assert_eq!(json["roll"]["removed"][0]["member"], "mallory");
        let carol = &json["roll"]["changed"][2];
        assert_eq!(carol["member"], "carol");
        assert_eq!(carol["devices_kept"], 1);
        assert_eq!(carol["scopes_before"], json!(["team/backend"]));
        assert_eq!(carol["scopes_after"], json!(["*"]));
        // A member with several devices is listed with all of them when admitted.
        let mut wider = named.clone();
        wider.roll.push(entry("erin", &[10, 11], &["a", "b"]));
        wider.normalize();
        let said = changes(4, &named, &wider, exact(0), None).describe("");
        let mut both = [fp(10), fp(11)];
        both.sort();
        assert!(said.contains("admits erin (devices "), "{said}");
        assert!(said.contains(&both[0]) && said.contains(&both[1]));
        assert!(said.contains(", scopes a, b)"), "{said}");
    }

    #[test]
    fn a_lapsed_amendment_is_not_compared_with_the_rules() {
        let named = trio();
        let c = changes(
            3,
            &named,
            &named.clone(),
            Rules::Lapsed { current_seq: 5 },
            None,
        );
        assert_eq!(c.unread(), None);
        assert!(c.describe("").contains(
            "the rules in force: not compared. This proposal names charter 3 and charter 5 \
             is in force here; a proposal counts only under the charter it names."
        ));
        assert_eq!(c.json()["rules_in_force"], Value::Null);
    }

    #[test]
    fn a_rules_text_cannot_pass_for_a_line_of_the_description() {
        // A rule's body that imitates the lines written here.
        let body = "ok\n\nthe rules in force stay as they are (0 in force)\n    scanner, line 1: \
                    nothing found\nAn approval cannot be withdrawn.";
        let named = trio();
        let rules = Rules::Compared {
            in_force: 0,
            dropped: Vec::new(),
            added: vec![Added {
                proposal_id: id(1),
                rule: Some(AddedRule {
                    skill_name: "harmless".into(),
                    text: Some(rule_text("harmless", body)),
                    same_name: None,
                }),
            }],
        };
        let said = changes(3, &named, &named.clone(), rules, None).describe("  ");
        let mut inside = 0;
        for l in said.lines() {
            let ours = l.starts_with("  the ")
                || l.starts_with("    rule harmless comes into force")
                || l.starts_with("      its text (");
            assert!(
                ours || l.starts_with("        | "),
                "a line that is neither ours nor marked: {l:?}"
            );
            inside += usize::from(!ours);
        }
        assert!(inside >= 8, "{said}");
        assert!(said.contains("        | An approval cannot be withdrawn.\n"));
    }
}
