# PeerHarness

**Your team votes on how its AI coding agents behave.**

You correct your coding agent ("no, use pnpm, not npm"). PeerHarness turns the
correction into a small rule, your teammates vote on it, and once a majority approves,
every member's agent follows it. There is no server: each person runs their own node
with their own keys and their own database, and every node checks every signature and
counts every vote for itself.

Agents can suggest rules. Only people decide: your agent may write a rule down for you
to review, and every step that approves, shares, votes or installs refuses to run
inside an agent's session.

> **Status: pre-release, not audited.** Writing rules down, reviewing and installing
> them, founding a circle, admitting and removing members by vote, proposing, voting,
> repealing and installing passed rules all work today from the command line.
> Nodes exchange their signed events as a file you send however you like. The live
> peer-to-peer transport exists as a library but is not wired into the CLI yet. See
> [What works today](#what-works-today) before relying on anything.

## See it run

```sh
git clone https://github.com/aryehlev/peerharness
cd peerharness
cargo run -p peerharness -- demo
```

The demo creates three members and one outsider, each with a separate key, database
and skills directory in a temporary folder. Nothing in your home or in `~/.claude` is
read or changed. Its output, slightly abridged:

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

In the demo the signed events travel between the nodes as files, in one process. That
is stated in its output too.

## How a vote works

* **A charter.** Each circle has one signed charter: the thresholds, and the roll of
  members. Everyone holds the same one, so everyone applies the same rules.
* **One person, one vote.** A member may have several devices. They are still one vote.
* **Majority of everyone entitled to vote.** A proposal passes when more than the
  charter's threshold (one half by default) of its electorate has approved. Not voting
  counts as not approving. Nobody has a veto: a `reject` is recorded with its reason and
  does not block.
* **Final, with no clock.** Approvals only accumulate, so "passed" never turns back
  into "not passed", and two nodes holding the same ballots always agree. There are no
  deadlines and no coordinator.
* **Membership is voted too.** Admitting or removing a member, and changing the rules,
  are amendments that need a vote. The founder's key signs the resulting charter, but
  nodes reject any charter that a passed vote does not justify.
* **A passed rule takes effect.** In a binding circle it is installed for every member
  as an [Agent Skill](https://agentskills.io/specification). Any member can opt out of a
  single rule on their own machine.

### What no vote can do

These are enforced in code and no charter can switch them off:

1. Nothing leaves your machine without you seeing the exact text and confirming it.
2. No vote runs code. A rule is one instruction-only `SKILL.md`. Tool pre-approval and
   shell-injection syntax are refused outright.
3. No vote grants read access.
4. A rule with high-risk content is never installed without asking you.
5. You can refuse a rule and you can leave.

The precise rules are in [docs/architecture.md](docs/architecture.md), section 10.

## What works today

| | |
|---|---|
| Voting core: charter, roll, proposals, ballots, result certificates, rule set, charter succession | works, tested |
| `peerharness demo` | works, tested end to end |
| `note`, `review`, `skills list/show/install/uninstall/rollback` (the loop for one person) | work, tested end to end |
| `circle create`, `circle invite`, `circle join`, `circle members`, `circle remove` | work, tested end to end with three separate nodes |
| `proposal create`, `list`, `show`, `vote`, `adopt`, `refuse` | work, tested end to end |
| `rule list`, `rule opt-out`, `rule opt-in`, `rule repeal` | work, tested end to end |
| `events export`, `events import` (signed events as a file) | work, tested end to end |
| `init`, `status`, `doctor`, `observe demo`, `inbox`, `export --local` | work |
| `watch claude --install` / `--remove`: the hooks, and the skill that asks your agent to report corrections | work, tested; other hooks and settings in the file are kept, with a backup |
| `question`, `circle revoke`, `reset` | not implemented yet (they say so) |
| Live peer-to-peer transport over QUIC (`daemon`, `connect`, `sync`) | library exists and is tested, not wired into the CLI |
| Finding corrections | you write the rule down, or your agent reports it when you correct it (best effort: it depends on the agent noticing). The built-in pattern detector only knows "use X, not Y" |
| Windows | not supported yet |

## Start alone

No circle and no network are needed for a rule of your own. Install the binary from
your clone first:

```sh
cargo install --path apps/peerharness --locked
```

```sh
peerharness init

# Write a rule down in one sentence. It becomes a candidate in your inbox.
peerharness note "Run the tests before you say a task is done."

# Read the exact skill text it would become, then save it to your library.
peerharness review <candidate-id>
peerharness review <candidate-id> --approve

# Install it for Claude Code (~/.claude/skills/<name>/SKILL.md). Reversible.
peerharness skills install <name>
peerharness skills uninstall <name>
```

To have your agent report corrections by itself, run `peerharness watch claude
--install`. It shows exactly what it adds before it adds anything: two hooks that store
redacted observations locally, and a small skill that asks the agent to run
`peerharness note --from-agent "..."` when you correct it. Claude Code asks you before
it runs that command, as it does for any shell command you have not allowed. The
agent's note lands in `peerharness inbox` and waits there. Approving it is yours:
`review --approve`, `skills install`, `proposal create` and `proposal vote` all refuse
inside an agent's session ([how far that check goes](#known-limits)).
`peerharness watch claude --remove` takes both out again.

To experiment without touching your real setup, point it at throwaway directories:

```sh
export PEERHARNESS_HOME=$(mktemp -d) PEERHARNESS_CLAUDE_SKILLS_DIR=$(mktemp -d)
export PEERHARNESS_CLAUDE_SETTINGS=$(mktemp -d)/settings.json
peerharness init --keystore insecure-dev --insecure-dev-keystore
```

`insecure-dev` stores the key in plaintext and is for experiments only. Without those
flags, `init` uses the OS keychain on macOS and an encrypted key file elsewhere.

## Use it with a teammate

Each of you runs your own node. Nothing is shared except the files you choose to send.

```sh
# Both: create a node. Each prints its device key with `peerharness status`.
peerharness init

# Alice founds the circle. She tells Bob the root fingerprint in person or by phone.
peerharness circle create team

# Alice proposes admitting Bob. She is the only member, so her approval passes it.
peerharness circle invite <bob's ed25519: device key> --circle team --member bob
#   -> writes peerharness-team-events.jsonl; she sends Bob that file

# Bob checks the fingerprint, reads the charter and joins.
peerharness circle join peerharness-team-events.jsonl --expect-fingerprint <fingerprint>

# Alice puts a rule to the vote, and votes. Creating a proposal is not a vote.
peerharness note "Use pnpm, not npm, in this repository."
peerharness proposal create <candidate-id> --circle team
peerharness proposal vote <proposal-id> approve
peerharness events export --circle team --out for-bob.jsonl

# Bob imports, reads the exact text, and votes. Two of two: it passes and is installed.
peerharness events import for-bob.jsonl
peerharness proposal show <proposal-id>
peerharness proposal vote <proposal-id> approve
peerharness events export --circle team --out for-alice.jsonl   # so Alice learns of it
```

With three or more members a rule passes on a majority, and admitting or removing
someone takes a vote of the current members. What else there is:

```sh
peerharness rule list                              # what is in force, and where it stands on this machine
peerharness rule opt-out <name> --circle team      # keep one rule off your own machine
peerharness rule repeal <name> --circle team       # ask the members to vote it out
peerharness circle remove <member> --circle team   # ask the members to vote someone off the roll
```

A rule binds the members who were entitled to vote on it. A repeal removes the rule
from every member's machine, and never a skill someone installed for themselves.

An exported file contains the circle's roll and proposals in clear text. Send it only
to members. Every node verifies each line itself, so the channel you send it over does
not need to be trusted for integrity.

## Known limits

* **The founder's key must stay available.** It notarizes charter changes and renews
  member credentials. If it is lost the circle keeps its rules but cannot change its
  roll.
* **Turnout.** A member who never votes makes every threshold harder to reach. Rolls
  are capped at 64 members.
* **Votes are signed and attributable.** There is no secret ballot.
* **Heuristic safety checks.** Redaction and the risk scanner catch common cases and
  miss others. They never prove that a text is safe.
* **The agent guard is not a wall.** Consent steps recognize an agent's session by an
  environment variable. That stops an agent that is trying to help; it does not stop a
  process that deliberately hides the variable.
* **No way to leave on your own yet.** You can opt out of any rule, but coming off the
  roll takes a vote, like any change to it.
* **A compromised device** counts until its revocation reaches each node.

The full list is in [docs/security-model.md](docs/security-model.md).

## Documentation

* [docs/architecture.md](docs/architecture.md): the internal contract every crate follows
* [docs/protocol-v0.md](docs/protocol-v0.md): the wire format, for a second implementation
* [docs/security-model.md](docs/security-model.md): threats, guarantees and limits
* [docs/decisions.md](docs/decisions.md): decisions and deviations from the original brief
* [crates/ph-protocol/tests/vectors](crates/ph-protocol/tests/vectors): golden test vectors

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Requires Rust 1.89 or newer. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md).

## License

MIT or Apache-2.0, at your option.
