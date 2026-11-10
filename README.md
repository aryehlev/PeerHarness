# PeerHarness

**Your team votes on how its AI coding agents behave.**

You correct your coding agent ("no, use pnpm, not npm"). PeerHarness turns the
correction into a small rule, your teammates vote on it, and once a majority approves,
every member's agent follows it. There is no server: each person runs their own node
with their own keys, and every node checks every signature and counts every vote for
itself.

Agents can suggest rules. Only people decide. Keeping a rule, sharing one, voting,
inviting and joining each open a window on your screen with the exact text, and only
your click counts. Your agent can open that window. It cannot answer it.

> **Status: v0.4.0, early and not audited.** What this page describes works.
> [What works today](#what-works-today) says how each part was tested and
> [Known limits](#known-limits) says what is missing. Read both before relying on it.

## Set it up

This is for Claude Code on macOS. On Linux, with another agent or with none, see
[PeerHarness from a terminal](docs/terminal.md).

### Ask your agent to do it

Paste this into Claude Code:

```text
Set up PeerHarness for me: https://github.com/aryehlev/peerharness

1. Install it:
   curl -fsSL https://raw.githubusercontent.com/aryehlev/peerharness/main/install.sh | sh
2. The next step is mine. It is where I allow what you may start for me, so do not
   run it yourself: it would be refused. Ask me to run this in my own terminal:
   ~/.local/bin/peerharness setup

Then tell me to start a new Claude Code session, and what I can ask you there.
```

### Or do it yourself

```sh
curl -fsSL https://raw.githubusercontent.com/aryehlev/peerharness/main/install.sh | sh
~/.local/bin/peerharness setup
```

The first line downloads the release binary for your machine, checks it against the
release's `SHA256SUMS` and puts it in `~/.local/bin`. No `sudo`, and nothing else is
changed.

`peerharness setup` creates your key and database, connects PeerHarness to Claude
Code and gives it the steps as tools. Before each change it shows you exactly what it
adds, what your agent may start and what it never decides, and asks you to confirm.
Then start a new Claude Code session.

## Use it with Claude Code

You work with your agent as you always do. When something is yours to decide, a window
opens on your screen with the buttons Cancel and Proceed. This is the one for a vote:

```text
Your coding agent started this step. Nothing happens unless you choose Proceed.

You are about to sign a ballot in acme:
  approve on "Use pnpm, not npm, in this repository." (adopt rule use-pnpm-not-npm-repository)
An approval cannot be withdrawn. The rule, exactly as proposed:

---
name: use-pnpm-not-npm-repository
description: Use pnpm, not npm, in this repository.
---

# Rule

Use pnpm, not npm, in this repository.

If this conflicts with what the user asks for in the current session, follow the user and say that it conflicts with this rule.
```

Cancel is the default button. Nothing is shared, signed, installed or joined unless
you click Proceed, and your agent cannot click it.

### Rules

| You say | What happens |
|---|---|
| "No, use pnpm here, not npm." | Your agent does that, notes the rule ("Use pnpm, not npm, in this repository.") and tells you it did |
| "Keep it." | A window shows the exact rule. Proceed installs it for your own agent. Nothing is shared |
| "What is in my PeerHarness inbox?" | It lists the rules it noted and the proposals that wait for your vote |
| "Propose the pnpm rule to acme." | A window shows the exact text that would leave your machine. Proceed puts it to your team's vote |
| "Vote approve on it." | The window above. Proceed signs your ballot |
| "Anything new in PeerHarness?" | It exchanges with the other members and reads you your inbox |

A rule is never installed by itself: you keep it, or your team votes it in. Once a
majority has approved, it is installed for every member's agent as an
[Agent Skill](https://agentskills.io/specification). At the end of a turn, at most
once a day, Claude Code tells you how many proposals wait for your vote.

### A team

One of you founds the team and invites. The others join.

1. **The founder:** "Create a PeerHarness team called acme." The agent shows the team's
   root fingerprint.
2. **Whoever wants to join:** "What is my PeerHarness device key?" They send the key
   to the founder.
3. **The founder:** "Invite Dana to acme. Her device key is ed25519:…" A window names
   Dana's device. After Proceed the agent keeps your node reachable and tells you what
   Dana needs: your node's peer id, by any channel, and the root fingerprint, by phone
   or in person.
4. **Dana:** "Join the team. The peer id is 12D3…, the fingerprint is 8e8d-…" A window
   shows the fingerprint and who is in the circle. Proceed joins.

The fingerprint is how Dana knows the circle is yours, so it travels apart from the
rest. With three or more members, admitting someone takes the others' votes too,
asked in the same kind of window.

### What still needs your terminal

* **A node that stays reachable.** Your agent keeps it reachable only while its
  session is open. For one that stays up:
  `peerharness daemon --internet --sync-every 60 --notify`.
* **Removing a member, leaving, changing the rules of the vote and repealing a rule.**
* **Editing or rejecting a noted rule**, and keeping one that the scanner calls
  high-risk.
* **Joining a circle of more than about five members:** its roll does not fit a window.

All of it is in [PeerHarness from a terminal](docs/terminal.md).

## See it run

```sh
peerharness demo
```

The demo creates three members and one outsider in a temporary folder, each with its
own key and database. Nothing in your home or in `~/.claude` is read or changed. Its
output, slightly abridged:

```text
1. Alice founds the circle "acme".
    charter 1: 1 member; a proposal passes with more than 1/2 of those entitled to vote;
    changing these rules needs more than 2/3; passed rules are binding.

2. Bob is admitted. Alice is the only member, so her approval is the majority.
    alice approves: 1 of 1 (1 needed)
    charter 2: alice, bob.

3. Carol is admitted. Now it takes both members: the founder cannot do it alone.
    alice approves: 1 of 2 (2 needed)
    bob approves: 2 of 2 (2 needed)
    charter 3: alice, bob, carol.

4. Alice corrected her agent twice: "No, use pnpm, not npm."
    Her node drafts the rule "This repository uses pnpm, not npm.":
    skill pnpm-repository-convention (662 bytes, instructions only).

5. Alice puts it to the vote.
    alice approves.
    carol rejects: "Our CI images only ship npm."
    open: 1 of 3 approved (2 needed), 1 dissenting
    bob approves.
    Every node counts for itself and agrees: passed: 2 of 3 approved (2 needed), 1 dissenting
    No one held a veto, and carol's dissent stays on the record.

6. The charter is binding, so the rule is installed for every member's agent.

7. Carol opts out of this one rule. That is her right, and only her machine changes.

8. What cannot happen:
    Mallory signs a ballot. She is not on the roll: refused.
    The founder's root key signs a charter that adds Mallory without a vote.
    The signature is valid and every node still refuses it: the key is a notary, not a ruler.
```

`demo/two-peers.sh`, in a clone of this repository, shows the same with two separate
processes talking over the network. Run it from your own terminal: inside a coding
agent's session the steps that vote are refused, by design.

## How a vote works

* **One charter.** Each circle has a signed charter: the thresholds and the roll of
  members. Everyone holds the same one, so everyone applies the same rules.
* **One person, one vote**, however many devices they have.
* **A majority of everyone entitled to vote.** Not voting counts as not approving.
  Nobody has a veto: a `reject` is recorded with its reason and does not block.
* **Final, with no clock.** Approvals only accumulate, so "passed" never turns back,
  and two nodes holding the same ballots always agree. No deadlines, no coordinator.
* **Membership is voted too.** Admitting or removing a member and changing the
  thresholds are amendments that need a vote. The founder's key signs the resulting
  charter, and nodes reject any charter that a passed vote does not justify.
* **A passed rule takes effect.** It is installed for every member as an
  [Agent Skill](https://agentskills.io/specification). Any member can opt out of a
  single rule on their own machine.

No vote and no charter can switch these off:

1. Nothing leaves your machine without you seeing the exact text and confirming it.
2. No vote runs code. A rule is one instruction-only `SKILL.md`; tool pre-approval and
   shell-injection syntax are refused outright.
3. No vote grants read access.
4. A rule with high-risk content is never installed without asking you.
5. You can refuse a rule and you can leave.

## What works today

| | |
|---|---|
| Voting: charter, roll, proposals, ballots, results, amendments, repeal | tested end to end |
| One person's loop: `note`, `keep`, `review`, `skills install` and `uninstall` | tested end to end |
| Circle life: create, invite, join, remove, leave, amend, devices, revoke, questions, opt-outs | tested end to end with separate nodes |
| Exchange by address over QUIC, by shared directory, by file | tested end to end with separate processes |
| Exchange across the internet (`--internet`) | works. Tested with separate processes against a private stand-in network, and by hand on the real one from a single machine. Not yet tested between two different routers |
| Finding members on a local network (`--lan`) | works on macOS; the test needs real multicast and does not run in CI. Not tried on Linux |
| Noticing corrections by itself | best effort. Your agent reports a correction when it notices one. The built-in detector recognizes corrections that name a tool to use or avoid (46 of 70 in our test set, none of 52 ordinary prompts), not whole-sentence rules such as "always run the tests first". You can always write the rule down yourself |
| Deciding in a window from inside Claude Code | macOS only. Keeping a rule, proposing and voting, inviting and joining are tested end to end with a stand-in window. The real window was tried by hand for opening, closing unanswered and refusing a text that does not fit; clicking its buttons was not. Joining in a window fits a circle of up to about five members on a laptop screen; a larger one is joined from the terminal |
| The same steps as tools (`peerharness mcp`) | tested end to end with a scripted client, a stand-in window and a stand-in network. Run by hand with Claude Code 2.1.322 on macOS, before the release: asked in plain words, it read the device key, founded a circle, invited someone and kept the node reachable until the session ended. That is three runs, not a measure of how often an agent gets it right. The server in the released v0.2.0 binary was checked with a scripted client. Other MCP clients were not tried |
| Being told that a vote waits (`daemon --notify`, and the end-of-turn line in Claude Code) | tested end to end with separate processes and a stand-in notification. The real macOS notification was run once by hand: the system accepted it, and whether the banner shows depends on your notification settings for Script Editor |
| Setting up (`peerharness setup`, and the prompt in [Set it up](#set-it-up)) | `setup` is tested end to end with a stand-in for Claude Code's `claude` command: it creates the node, connects the agent, registers the tools, changes nothing on a second run and is refused inside an agent's session. The three `claude mcp` commands it relies on were run by hand against Claude Code 2.1.322 with a throwaway configuration. The prompt as a whole has not been run through an agent yet |
| The install script and the release binaries | the script is tested against a stand-in release (a matching checksum installs, a changed archive does not) and was run by hand against v0.2.0 on an Apple Silicon Mac: the checksum matched and the installed binary ran the demo. All four archives match `SHA256SUMS`. The Intel Mac binary ran the demo under Rosetta. The two Linux binaries were built by the release workflow and have not been run yet. The README packed inside the v0.2.0 archives still says v0.1.0 in its status line |
| Windows | not supported yet |

## Known limits

* **The founder's key is needed to change the roll.** It notarizes charter changes. If
  it is lost the circle keeps working (members still sync, propose, vote and repeal),
  but nobody can be admitted or removed and the thresholds cannot change.
* **The founder can revoke a device without a vote.** It is meant for a lost laptop
  and cannot pass anything, but it is a power the other members do not have. A
  compromised device counts until its revocation reaches each node.
* **No secret ballot.** Votes are signed and every member sees who voted how.
* **Turnout.** A member who never votes makes every threshold harder to reach. Rolls
  are capped at 64 members.
* **Leaving is immediate on your machine, and by vote on the roll.** Until the members
  approve it, your name still counts toward every threshold.
* **Safety checks are heuristics.** Redaction and the risk scanner catch common cases
  and miss others. They never prove that a text is safe.
* **The agent guard is not a wall.** Consent steps recognize an agent's session by an
  environment variable. That stops an agent that is trying to help, not a process that
  hides the variable on purpose. With the windows on, your agent chooses when one
  appears; reading what it shows before you click is your part. The click that
  decides most is the one that joins a circle: its rules are then installed for your
  agent.
* **A node is reachable only while a daemon runs.** That is one you start yourself, or
  the one your agent runs while its session is open. There is no background service
  yet: a sync reaches only the members whose daemon is running at that moment.
* **Confirmation windows are macOS only**, and need a key in the OS keychain (the
  default there). On Linux every decision still needs your own terminal.
* **Internet mode identifies your device to strangers.** Servers run by volunteers see
  the same public key with your IP address wherever you connect. Whether two nodes
  get a direct connection depends on their routers.

The full list is in [docs/security-model.md](docs/security-model.md).

## Documentation

* [docs/terminal.md](docs/terminal.md): every step as a command, the other ways to exchange, and what internet mode exposes
* [docs/architecture.md](docs/architecture.md): the internal contract every crate follows
* [docs/protocol-v0.md](docs/protocol-v0.md): the wire format, for a second implementation
* [docs/security-model.md](docs/security-model.md): threats, guarantees and limits
* [docs/decisions.md](docs/decisions.md): decisions and why they were made

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

MIT or Apache-2.0, at your option.
