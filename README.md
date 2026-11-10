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

> **Status: pre-release, not audited.** Everything in the command reference works today
> and is tested end to end: writing rules down, reviewing and installing them, asking
> the circle a question, founding a circle, admitting and removing members by vote,
> proposing, voting, repealing, changing the rules of the vote, and leaving.
> Nodes exchange their signed events directly over QUIC (finding each other on a local
> network if you ask them to), through a directory in a git repository you already
> share, or as a file you send however you like. There are no relays: for a direct
> sync one node must be reachable by the other. See
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

In that demo the signed events travel between the nodes as files, in one process (its
output says so). To see two separate processes do it over the network, each with its
own key and database, talking QUIC on loopback:

```sh
demo/two-peers.sh
```

It ends with the rule installed for both agents and a third node, which is not on the
roll, being told nothing. Run it from your own terminal: inside a coding agent's
session the steps that vote are refused, by design.

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
| `circle create`, `invite`, `join`, `members`, `remove` | work, tested end to end with three separate nodes |
| `circle leave`, `amend` (thresholds, binding or advisory), `device add/remove`, `mode`, `place`, `revoke` | work, tested end to end |
| `question send`, `list`, `answer`, `dismiss` (ask the circle before proposing) | work, tested end to end |
| `proposal create`, `list`, `show`, `vote`, `adopt`, `refuse` | work, tested end to end |
| `rule list`, `rule opt-out`, `rule opt-in`, `rule repeal`; `--announce` puts an opt-out on the circle's record | work, tested end to end |
| `events export`, `events import` (signed events as a file) | work, tested end to end |
| `events sync <dir>` (the circle as a directory in a repository you already share) | works, tested end to end |
| `init`, `status`, `doctor`, `observe demo`, `inbox`, `export --local` | work |
| `watch claude --install` / `--remove`: the hooks, and the skill that asks your agent to report corrections | work, tested; other hooks and settings in the file are kept, with a backup |
| `reset` (delete this node and its keys; explains first, deletes only with `--confirm`) | works, tested |
| `daemon`, `sync`, `connect` (direct peer-to-peer over QUIC), joining a circle from a member's node | work, tested with separate processes on loopback. No relays or hole punching: one side must be reachable |
| `daemon --lan`, `sync --lan` (members find each other on a local network) | work on macOS, tested there with separate processes; the test needs real multicast and does not run in CI. Not tried on Linux |
| Finding corrections | you write the rule down, or your agent reports it when you correct it (best effort: it depends on the agent noticing). The built-in detector recognizes corrections that name a tool to use or avoid (46 of 70 in our own test set, none of 52 ordinary prompts); it does not recognize whole-sentence rules such as "always run the tests first" |
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
# Before you propose: ask. Answers are opinions on the record, not ballots.
peerharness question send <candidate-id> --circle team
peerharness question list
peerharness question answer <question-id> --answer agree --rationale "we already do"

# The rules in force, and your own machine.
peerharness rule list                              # what is in force, and where it stands on this machine
peerharness rule opt-out <name> --circle team      # keep one rule off your own machine; nobody is told
peerharness rule opt-out <name> --circle team --announce --reason "..."   # ...and put that on the circle's record
peerharness rule repeal <name> --circle team       # ask the members to vote it out
peerharness circle mode ask --circle team          # be asked before any rule is installed (or: follow)
peerharness circle place repo/web --circle team --project ~/code/web   # rules of that scope go in that repository only

# The circle itself. Each of these is put to the vote.
peerharness circle remove <member> --circle team   # vote someone off the roll
peerharness circle device add <ed25519: key> --circle team   # a second device for you; still one vote
peerharness circle amend --circle team --pass 2/3  # change the rules of the vote (needs the amend threshold)
peerharness circle leave --circle team             # stop following now, and ask to be taken off the roll
```

A rule binds the members who were entitled to vote on it. A repeal removes the rule
from every member's machine, and never a skill someone installed for themselves.

A rule about one repository should not follow you into every other one. Propose it in
a scope your team uses for that repository (`proposal create ... --scope repo/web`),
and let each member say once where their checkout is with `circle place`. Rules with
other scopes still apply everywhere.

One thing is not voted on. If a device is lost or stolen, the founder's node can cut
that device key off at once with `peerharness circle revoke <member or key> --circle
team`. That stops the device from syncing and from being counted. It cannot add a vote,
and it does not take the member off the roll: that is still `circle remove`.

An exported file contains the circle's roll and proposals in clear text. Send it only
to members. Every node verifies each line itself, so the channel you send it over does
not need to be trusted for integrity.

### Directly, peer to peer

One of you leaves a node listening; the others sync with it. No server is involved:
the two nodes talk over QUIC, each proves its device key in the handshake, and each
answers the other only because that key is on the roll you all voted on.

```sh
peerharness daemon --listen /ip4/0.0.0.0/udp/4001/quic-v1    # prints the address to give the others
peerharness sync /ip4/192.0.2.7/udp/4001/quic-v1/p2p/<peer id>   # the others; after that just: peerharness sync
```

A sync fetches what the peer has, sends what it lacks, and applies what has passed:
when your ballot completes a majority, the rule is installed on both sides. After the
first sync a node remembers the peer and how far it got, so `peerharness sync` with no
argument syncs with everyone it knows and moves only what is new. A daemon started with
`--sync-every 300` does that by itself every five minutes.

A device that is not on the roll gets no answer beyond a version greeting, and learns
nothing about the circle, not even whether it exists there. Once your admission has
passed you are on the roll, so you can get the circle straight from a member's node,
without a file:

```sh
peerharness circle join /ip4/192.0.2.7/udp/4001/quic-v1/p2p/<peer id> --expect-fingerprint <fingerprint>
```

If the members vote you off, the next node you sync with shows your node the vote, and
your node checks it before it believes it and removes that circle's rules.

On a network you share (an office, a home), nodes can find each other instead of being
given addresses:

```sh
peerharness daemon --listen /ip4/0.0.0.0/udp/4001/quic-v1 --lan   # announces itself
peerharness sync --lan                                            # finds members and syncs
```

Announcing is off unless you ask for it. It tells everyone on that network this
device's public key and port, and nothing about any circle. A node only contacts
announced devices that are on a roll it holds.

There is no relay: for a direct sync one of the two machines has to be reachable by the
other (same network, VPN, or a forwarded UDP port). You do not need every pair to
connect, though. One member's node that the others can reach carries everyone's records
to everyone else, and it hands each member only what the roll lets them read.

### Through a repository you already share

Instead of sending files around, keep the circle in a directory of your team's
repository. Every signed record is its own small file named by its hash, so two people
adding records at the same time never conflict.

```sh
peerharness events sync .peerharness/team --circle team   # import what is there, write what is missing
git add .peerharness && git commit -m "votes" && git push
# the others: git pull, then the same sync command
```

A new member joins from the same directory: `peerharness circle join .peerharness/team
--expect-fingerprint <fingerprint>`. The directory is not trusted: a record that was
edited is refused and put back, and files that are not records are never read. Two
things to know before you use it. Everyone who can read the repository can read the
roll, the proposals and the ballots. And someone who can write to it can delete
records, which delays them for whoever has not synced yet, but cannot forge or change a
vote.

## Known limits

* **The founder's key must stay available to change the roll.** It notarizes charter
  changes. If it is lost the circle keeps working: members still sync, propose, vote
  and repeal. What stops is admitting and removing members and changing the thresholds.
* **Turnout.** A member who never votes makes every threshold harder to reach. Rolls
  are capped at 64 members.
* **Votes are signed and attributable.** There is no secret ballot.
* **Heuristic safety checks.** Redaction and the risk scanner catch common cases and
  miss others. They never prove that a text is safe.
* **The agent guard is not a wall.** Consent steps recognize an agent's session by an
  environment variable. That stops an agent that is trying to help; it does not stop a
  process that deliberately hides the variable.
* **Leaving takes effect on your machine at once, and on the roll by vote.** `circle
  leave` removes the circle's rules from your agent immediately. Your name stays on the
  roll, and counts toward every threshold, until the members approve the removal.
* **The founder can revoke any device without a vote.** It is meant for a lost laptop.
  It cannot pass anything, and everyone sees it, but it is a power the other members
  do not have.
* **A compromised device** counts until its revocation reaches each node.
* **Announcing on a local network identifies your device.** With `--lan`, anyone on that
  network sees the same public key wherever you connect.

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
