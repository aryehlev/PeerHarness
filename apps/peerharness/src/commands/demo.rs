//! `peerharness demo`: a self-contained run of the whole voting flow.
//!
//! Three members (alice, bob, carol) and one outsider (mallory) each get their own
//! temporary home: a separate device key, a separate SQLite database and a separate
//! skills directory. Nothing is shared between them. Every event is signed, exported
//! as JSON lines and imported by the other nodes through exactly the code path that
//! `ingest` gives a real peer, so each node verifies everything itself.
//!
//! Honest limits, printed at the end: the nodes run in one process, and the events
//! travel as files, not over the QUIC transport (which is not wired into the CLI yet).
//! Skills are installed into temporary directories, never into `~/.claude`.
//!
//! The demo doubles as an end-to-end check: any step that does not behave as the
//! architecture says fails the command with a non-zero exit.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use ph_core::{
    CircleId, DeviceKey, NormalizedObservation, ObservationId, ObservationKind, ObservationSource,
    Scope, Timestamp,
};
use ph_governance::{
    admit_member, adoption_step, local_policy_met, AdoptionMode, AdoptionStep, BundleChecks,
    LocalPolicy, OwnerChoice,
};
use ph_identity::CircleAuthority;
use ph_learning::{draft_skill, CandidateDetector, DeterministicDetector};
use ph_protocol::{
    AdoptAction, Charter, CharterBody, EnvelopeBuilder, EventBody, ProposalAction, RollEntry,
    SigningKey, UnsignedCharter, VoteBody, VoteDecision,
};
use ph_skills::{BundleStore, InstallOptions, Installer, UninstallOptions};
use ph_store::Store;
use serde_json::json;

use crate::commands::Ctx;
use crate::governance::{self, Ingest, NewProposal};
use crate::output::{short_id, Output, Report};

/// One independent node of the demo.
struct DemoNode {
    name: &'static str,
    store: Store,
    key: SigningKey,
    bundles: BundleStore,
    skills_dir: PathBuf,
}

impl DemoNode {
    fn create(root: &Path, name: &'static str) -> Result<Self> {
        let home = root.join(name);
        crate::home::ensure_private_dir(&home)?;
        let mut seed = [0u8; 32];
        crate::home::getrandom_fill(&mut seed)?;
        Ok(Self {
            name,
            store: Store::open(home.join(crate::home::DB_FILE))
                .with_context(|| format!("cannot create {name}'s database"))?,
            key: SigningKey::from_bytes(&seed),
            bundles: BundleStore::new(home.join(crate::home::BUNDLES_DIR)),
            skills_dir: home.join("agent-skills"),
        })
    }

    fn device(&self) -> DeviceKey {
        DeviceKey::from_signing_key(&self.key)
    }

    fn entry(&self) -> RollEntry {
        RollEntry::new(self.name, vec![self.device()], vec![Scope::all()])
    }

    fn installed(&self, skill: &str) -> bool {
        self.skills_dir.join(skill).join("SKILL.md").is_file()
    }
}

/// Hands everything `from` holds for the circle to `to`, as exported lines.
fn hand_over(from: &DemoNode, to: &DemoNode, circle: &CircleId, now: Timestamp) -> Result<()> {
    let lines = governance::export_circle(&from.store, &from.bundles, circle)?;
    governance::import_lines(
        &to.store,
        &to.bundles,
        lines.iter().map(String::as_str),
        now,
    )?;
    Ok(())
}

/// Exchanges events between every pair until nothing new moves.
fn sync(nodes: &[&DemoNode], circle: &CircleId, now: Timestamp) -> Result<()> {
    for _ in 0..2 {
        for a in nodes {
            for b in nodes {
                if a.name != b.name {
                    hand_over(a, b, circle, now)?;
                }
            }
        }
    }
    Ok(())
}

fn ensure(condition: bool, what: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        bail!("demo check failed: {what}")
    }
}

/// Runs an amendment that admits `newcomer`: `proposer` proposes, `voters` approve on
/// their own nodes, the founder's node publishes the result and notarizes the charter.
fn admit(
    out: &Output,
    members: &[&DemoNode],
    founder: &DemoNode,
    authority: &CircleAuthority,
    newcomer: &DemoNode,
    circle: &CircleId,
    now: Timestamp,
) -> Result<Charter> {
    let (current, rules, _) = governance::rule_set(&founder.store, circle)?;
    let next = admit_member(&current.content, &rules, newcomer.entry())
        .map_err(|e| anyhow!("cannot draft the amendment: {e}"))?;
    let proposal = governance::propose(
        &founder.store,
        &founder.key,
        circle,
        NewProposal {
            scope: &Scope::all(),
            title: &format!("Admit {}", newcomer.name),
            summary: "",
            action: ProposalAction::Amend { next },
        },
        now,
    )?;
    sync(members, circle, now)?;
    for (i, voter) in members.iter().enumerate() {
        let p = governance::proposal_view(&voter.store, &proposal.event_id())?;
        governance::cast_vote(
            &voter.store,
            &voter.key,
            &p,
            VoteDecision::Approve,
            None,
            now,
        )?;
        sync(members, circle, now)?;
        let (_, t) = governance::count(&founder.store, &proposal)?;
        out.note(format!(
            "    {} approves: {} of {} ({} needed)",
            voter.name,
            i + 1,
            t.electorate().len(),
            t.need()
        ));
    }
    let result = governance::publish_result(&founder.store, &founder.key, &proposal, now)?
        .ok_or_else(|| anyhow!("demo check failed: the admission did not pass"))?;
    let charter = governance::notarize(&founder.store, authority, &result.event_id, now)?;
    governance::join_circle(&newcomer.store, "acme", &charter, &newcomer.device(), now)?;
    Ok(charter)
}

/// Applies the rule set to one node's skills directory, as a node in `follow` mode does.
fn follow_rules(node: &DemoNode, circle: &CircleId) -> Result<Vec<(String, AdoptionStep)>> {
    let (charter, rules, tallies) = governance::rule_set(&node.store, circle)?;
    let mode = AdoptionMode::default_for(charter.content.rules.binding);
    let installer = Installer::new(&node.skills_dir);
    let mut steps = Vec::new();
    for rule in rules.rules() {
        let bundle = node.bundles.get(&rule.bundle_digest());
        let checks = BundleChecks {
            digest_verified: bundle
                .as_ref()
                .is_ok_and(|b| b.digest() == rule.bundle_digest()),
            skill_valid: bundle.is_ok(),
            high_risk: bundle
                .as_ref()
                .is_ok_and(|b| ph_skills::has_high_risk(&b.scan())),
        };
        let choice = OwnerChoice {
            opted_out: node.store.is_rule_opted_out(circle, rule.skill_name())?,
            confirmed: false,
        };
        let policy_ok = local_policy_met(&LocalPolicy::default(), tallies.get(&rule.proposal_id()));
        let step = adoption_step(rule, mode, checks, choice, policy_ok);
        match (step, bundle) {
            (AdoptionStep::Install, Ok(b)) => {
                installer
                    .install(&b, InstallOptions::default())
                    .map_err(|e| anyhow!("cannot install the skill: {e}"))?;
            }
            (AdoptionStep::OptedOut, _) if node.installed(rule.skill_name()) => {
                installer
                    .uninstall(rule.skill_name(), UninstallOptions::default())
                    .map_err(|e| anyhow!("cannot remove the skill: {e}"))?;
            }
            _ => {}
        }
        steps.push((rule.skill_name().to_owned(), step));
    }
    Ok(steps)
}

pub fn run(ctx: &Ctx) -> Result<Report> {
    let out = &ctx.out;
    let now = Timestamp::now();
    let tmp = tempfile::Builder::new()
        .prefix("peerharness-demo-")
        .tempdir()
        .context("cannot create a temporary directory")?;
    let alice = DemoNode::create(tmp.path(), "alice")?;
    let bob = DemoNode::create(tmp.path(), "bob")?;
    let carol = DemoNode::create(tmp.path(), "carol")?;
    let mallory = DemoNode::create(tmp.path(), "mallory")?;

    out.note("PeerHarness demo: three members vote on how their AI coding agents behave.");
    out.note("Each has their own key, their own database and their own skills directory.\n");

    // 1. Founding.
    let mut root_seed = [0u8; 32];
    crate::home::getrandom_fill(&mut root_seed)?;
    let authority = CircleAuthority::from_signing_key(SigningKey::from_bytes(&root_seed));
    let circle = authority.circle_id();
    let c1 = governance::found_circle(&alice.store, &authority, "acme", alice.entry(), None, now)?;
    let rules = c1.content.rules;
    out.note("1. Alice founds the circle \"acme\".");
    out.note(format!(
        "    charter 1: 1 member; a proposal passes with more than {}/{} of those entitled to vote;",
        rules.pass.num, rules.pass.den
    ));
    out.note(format!(
        "    changing these rules needs more than {}/{}; passed rules are {}.",
        rules.amend.num,
        rules.amend.den,
        if rules.binding { "binding" } else { "advisory" }
    ));

    // 2. Admission by vote.
    out.note("\n2. Bob is admitted. Alice is the only member, so her approval is the majority.");
    let c2 = admit(out, &[&alice], &alice, &authority, &bob, &circle, now)?;
    sync(&[&alice, &bob], &circle, now)?;
    out.note(format!("    charter {}: alice, bob.", c2.seq));

    out.note("\n3. Carol is admitted. Now it takes both members: the founder cannot do it alone.");
    let c3 = admit(
        out,
        &[&alice, &bob],
        &alice,
        &authority,
        &carol,
        &circle,
        now,
    )?;
    let members = [&alice, &bob, &carol];
    sync(&members, &circle, now)?;
    out.note(format!("    charter {}: alice, bob, carol.", c3.seq));
    for node in members {
        let current = governance::current_charter(&node.store, &circle)?;
        ensure(
            current.digest()? == c3.digest()?,
            "every member holds the same current charter",
        )?;
    }

    // 3. A rule learned from a correction.
    out.note("\n4. Alice corrected her agent twice: \"No, use pnpm, not npm.\"");
    let observations: Vec<NormalizedObservation> = (1..=2)
        .map(|i| {
            NormalizedObservation::from_raw(
                ObservationId::new(&format!("obs_demo_{i}")).expect("valid observation id"),
                now,
                ObservationSource::Demo,
                None,
                "repo:demo".to_owned(),
                ObservationKind::UserPrompt,
                "No, use pnpm, not npm.",
            )
        })
        .collect();
    let candidate = DeterministicDetector::new()
        .detect(&observations)
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("demo check failed: the detector found no correction"))?;
    let draft = draft_skill(&candidate);
    let bundle = ph_skills::build_bundle(&draft.to_skill_md(), Some(&draft.name))
        .map_err(|e| anyhow!("the drafted skill is invalid: {e}"))?;
    governance::record_bundle(&alice.store, &alice.bundles, &bundle, now)?;
    out.note(format!(
        "    Her node drafts the rule \"{}\":",
        candidate.statement
    ));
    out.note(format!(
        "    skill {} ({} bytes, instructions only).",
        draft.name,
        bundle.size()
    ));

    let proposal = governance::propose(
        &alice.store,
        &alice.key,
        &circle,
        NewProposal {
            scope: &Scope::all(),
            title: &candidate.statement,
            summary: "Corrected twice in my own sessions.",
            action: ProposalAction::Adopt(AdoptAction {
                skill_name: draft.name.clone(),
                description: draft.description.clone(),
                bundle_digest: bundle.digest(),
                bundle_size: bundle.size(),
                related_question: None,
                supersedes: None,
            }),
        },
        now,
    )?;
    out.note(format!(
        "\n5. Alice puts it to the vote (proposal {}).",
        short_id(&proposal.event_id())
    ));
    governance::cast_vote(
        &alice.store,
        &alice.key,
        &proposal,
        VoteDecision::Approve,
        None,
        now,
    )?;
    sync(&members, &circle, now)?;
    out.note("    alice approves.");

    let on_carol = governance::proposal_view(&carol.store, &proposal.event_id())?;
    governance::cast_vote(
        &carol.store,
        &carol.key,
        &on_carol,
        VoteDecision::Reject,
        Some("Our CI images only ship npm."),
        now,
    )?;
    sync(&members, &circle, now)?;
    let (_, t) = governance::count(&bob.store, &proposal)?;
    out.note("    carol rejects: \"Our CI images only ship npm.\"");
    out.note(format!("    {t}"));
    ensure(!t.passed(), "one approval of three is not a majority")?;
    ensure(
        follow_rules(&bob, &circle)?.is_empty() && !bob.installed(&draft.name),
        "nothing is installed before the vote passes",
    )?;

    let on_bob = governance::proposal_view(&bob.store, &proposal.event_id())?;
    governance::cast_vote(
        &bob.store,
        &bob.key,
        &on_bob,
        VoteDecision::Approve,
        None,
        now,
    )?;
    governance::publish_result(&bob.store, &bob.key, &on_bob, now)?
        .ok_or_else(|| anyhow!("demo check failed: two of three did not pass"))?;
    sync(&members, &circle, now)?;
    out.note("    bob approves.");

    let mut tallies = Vec::new();
    for node in members {
        let (_, t) = governance::count(&node.store, &proposal)?;
        ensure(t.passed(), "every node computes that the proposal passed")?;
        ensure(
            t.dissent().len() == 1 && t.dissent()[0].member == "carol",
            "carol's dissent is on every node's record",
        )?;
        tallies.push(t.summary());
    }
    ensure(
        tallies.windows(2).all(|w| w[0] == w[1]),
        "every node computes the same tally",
    )?;
    out.note(format!(
        "    Every node counts for itself and agrees: {}",
        tallies[0]
    ));
    out.note("    No one held a veto, and carol's dissent stays on the record.");

    // 4. A passed rule takes effect.
    out.note("\n6. The charter is binding, so the rule is installed for every member's agent.");
    for node in members {
        let steps = follow_rules(node, &circle)?;
        ensure(
            steps == [(draft.name.clone(), AdoptionStep::Install)] && node.installed(&draft.name),
            "the rule is installed on every member's node",
        )?;
        out.note(format!("    {}: installed {}", node.name, draft.name));
    }

    out.note(
        "\n7. Carol opts out of this one rule. That is her right, and only her machine changes.",
    );
    carol.store.set_rule_opt_out(&circle, &draft.name, now)?;
    follow_rules(&carol, &circle)?;
    ensure(!carol.installed(&draft.name), "carol's copy is removed")?;
    ensure(
        alice.installed(&draft.name) && bob.installed(&draft.name),
        "the others keep the rule",
    )?;
    out.note(format!(
        "    carol: removed {}; alice and bob: unchanged.",
        draft.name
    ));

    // 5. What cannot happen.
    out.note("\n8. What cannot happen:");
    // An outsider's ballot.
    let forged_ballot = EnvelopeBuilder::new(
        circle,
        Scope::all(),
        EventBody::Vote(VoteBody {
            proposal_id: proposal.event_id(),
            decision: VoteDecision::Approve,
            rationale: None,
        }),
    )
    .sign(&mallory.key, now)?
    .to_canonical_json()?;
    let outcome = governance::ingest(&alice.store, forged_ballot.as_bytes(), None, now)?;
    ensure(
        outcome == Ingest::Rejected("not_on_roll"),
        "an outsider's ballot is refused",
    )?;
    out.note("    Mallory signs a ballot. She is not on the roll: refused.");

    // The root key trying to add a member without a vote.
    let mut stuffed = c3.content.clone();
    stuffed.roll.push(mallory.entry());
    stuffed.normalize();
    let some_result = alice
        .store
        .results_for_proposal(&proposal.event_id())?
        .first()
        .map(|e| e.event_id)
        .ok_or_else(|| anyhow!("demo check failed: no result stored"))?;
    let rogue = UnsignedCharter::successor(&c3, stuffed, some_result, now)?
        .sign(authority.signing_key())?;
    let rogue_event = EnvelopeBuilder::new(
        circle,
        Scope::all(),
        EventBody::Charter(CharterBody { charter: rogue }),
    )
    .sign(authority.signing_key(), now)?
    .to_canonical_json()?;
    let outcome = governance::ingest(&bob.store, rogue_event.as_bytes(), None, now)?;
    ensure(
        matches!(outcome, Ingest::Rejected(_)),
        "a charter without a passed amendment is refused",
    )?;
    ensure(
        governance::current_charter(&bob.store, &circle)?.seq == c3.seq,
        "the roll did not change",
    )?;
    out.note("    The founder's root key signs a charter that adds Mallory without a vote.");
    out.note("    The signature is valid and every node still refuses it: the key is a notary, not a ruler.");

    out.note("\nThree independent nodes decided one shared rule by majority vote. No server was involved.");
    out.note("In this demo the signed events travelled between the nodes as files, and the skills");
    out.note("went into temporary directories. The QUIC transport is not wired into the CLI yet.");

    Ok(Report::new(
        json!({
            "circle_id": circle,
            "charter_seq": c3.seq,
            "members": ["alice", "bob", "carol"],
            "proposal_id": proposal.event_id(),
            "skill_name": draft.name,
            "tally": tallies[0],
            "installed": {"alice": alice.installed(&draft.name), "bob": bob.installed(&draft.name), "carol": carol.installed(&draft.name)},
            "transport": "files (in-process); QUIC not wired yet",
        }),
        "",
    ))
}
