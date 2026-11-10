# PeerHarness

**Your team votes on how its AI coding agents behave.**

You correct your coding agent ("no, use pnpm, not npm"). PeerHarness turns the
correction into a small rule, your teammates vote on it, and once a majority approves,
every member's agent follows it. There is no server: each person runs their own node
with their own keys, and every node checks every signature and counts every vote for
itself.

Agents can suggest rules. Only people decide: no step that approves, shares, votes or
installs can be answered from inside an agent's session. If you allow it, your agent
can put a proposal or a ballot in front of you in a window, and your click decides.

> **Status: pre-release, not audited.** The commands on this page work and are tested
> end to end. Read [What works today](#what-works-today) and
> [Known limits](#known-limits) before relying on it.

## See it run

```sh
git clone https://github.com/aryehlev/peerharness
cd peerharness
cargo run -p peerharness -- demo
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

`demo/two-peers.sh` shows the same with two separate processes talking over the
network. Run it from your own terminal: inside a coding agent's session the steps that
vote are refused, by design.

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

## Start alone

A rule of your own needs no circle and no network. Install the binary from your clone
(Rust 1.89 or newer; macOS and Linux):

```sh
cargo install --path apps/peerharness --locked
peerharness init

# Write a rule down in one sentence. It becomes a candidate in your inbox.
peerharness note "Run the tests before you say a task is done."

# Read the exact skill text it would become, then save it to your library.
peerharness review <candidate-id>
peerharness review <candidate-id> --approve

# Install it for Claude Code (~/.claude/skills/<name>/SKILL.md). Reversible.
peerharness skills install <name>
```

To have your agent report corrections by itself, run `peerharness watch claude
--install`. It shows what it adds before it adds anything: two hooks that store
redacted observations locally, and a small skill that asks the agent to note a rule
when you correct it. The note waits in `peerharness inbox`; approving it stays yours.
`peerharness watch claude --remove` takes it out again.

On macOS you can also decide without leaving the agent. Add `--windows`:

```sh
peerharness watch claude --install --windows
```

When you then tell your agent "propose that to the team" or "vote approve on it", a
window opens on your screen with the exact text that would be shared, signed or
installed, and buttons Cancel and Proceed. Only your click on Proceed does anything;
your agent cannot answer the window and `--yes` does not skip it. It covers three
steps: proposing a rule, your ballot on a proposed rule, and installing a rule that
passed. Everything else, and any text too long to show in full, still needs your own
terminal. `--install --no-windows` turns it off.

To experiment without touching your real setup:

```sh
export PEERHARNESS_HOME=$(mktemp -d) PEERHARNESS_CLAUDE_SKILLS_DIR=$(mktemp -d)
export PEERHARNESS_CLAUDE_SETTINGS=$(mktemp -d)/settings.json
peerharness init --keystore insecure-dev --insecure-dev-keystore   # plaintext key: experiments only
```

## Use it with your team

Each member runs their own node. With `--internet`, nodes find each other from
anywhere by peer id: no address, no port forwarding, no server of ours.

```sh
# Both: create a node. `peerharness status` prints its device key and peer id.
peerharness init

# Alice founds the circle and tells Bob the root fingerprint, in person or by phone.
peerharness circle create team

# Alice proposes admitting Bob's device. She is the only member, so her approval passes it.
# (It also writes an events file, for joining without a network. Not needed here.)
peerharness circle invite <bob's device key> --circle team --member bob

# Alice leaves her node running.
peerharness daemon --internet

# Bob finds her node by its peer id, checks the fingerprint, reads the charter and joins.
peerharness circle join <alice's peer id> --internet --expect-fingerprint <fingerprint>

# Alice puts a rule to the vote, and votes. Creating a proposal is not a vote.
peerharness note "Use pnpm, not npm, in this repository."
peerharness proposal create <candidate-id> --circle team
peerharness proposal vote <proposal-id> approve

# Bob fetches it, reads the exact text, and votes. Two of two: it passes.
peerharness sync --internet
peerharness proposal show <proposal-id>
peerharness proposal vote <proposal-id> approve
peerharness sync --internet     # Alice's node learns of it and installs the rule too
```

With three or more members a rule passes on a majority, and admitting or removing
someone takes a vote of the current members. A daemon started with `--sync-every 300`
also fetches from the other members by itself every five minutes.

### What `--internet` exposes

It uses the public libp2p network (the one IPFS uses) to look a node up by its key,
reach it through a relay, and connect directly where both routers allow it. It is off
unless you pass the flag.

* **A peer id is an address, not a key.** Whoever has it can find your node, and gets a
  version greeting and nothing else: not even whether a circle exists there. Joining
  takes the members' vote on that device's key, and the device must then prove it
  holds that key.
* **Strangers' servers see** your device's public key, your IP address, and which
  device keys your node looks up. They are never told a circle, a roll or a vote.
* **A relay sees** which two devices talk, when and how much. It cannot read or change
  what they say: the connection is encrypted between the two devices.
* **Your node looks up only** devices on a roll it holds, and the peer id you type for
  `circle join`.

What to expect: about ten seconds to join the network and a few more to find a member.
Two nodes behind routers connect directly where both routers allow it. Where they do
not, the public relays carry about 128 KiB per connection: enough for votes and short
rules, and a larger sync continues where it stopped the next time. For a link that
always works, give one member's node an address the others can reach (a small server
as that member's second device will do). Every node carries the whole circle, so the
others sync through it.

### Other ways to exchange

Every node verifies each record itself, so none of these channels has to be trusted to
keep a vote intact.

| | Commands | Good to know |
|---|---|---|
| A repository you already share | `peerharness events sync .peerharness/team --circle team`, then commit and push | Each record is its own file, so there are no merge conflicts. Everyone who can read the repository can read the roll and the ballots |
| A member's address | `peerharness daemon --listen /ip4/0.0.0.0/udp/4001/quic-v1`, then `peerharness sync <the address it prints>` | Needs the same network, a VPN or a forwarded UDP port |
| The local network | `peerharness daemon --listen … --lan`, then `peerharness sync --lan` | Announces the device's public key and port on that network |
| A file | `peerharness events export --circle team --out f.jsonl`, then `peerharness events import f.jsonl` | Holds the roll and proposals in clear text: send it only to members |

A new member can join from any of them: `peerharness circle join <address, directory or
file> --expect-fingerprint <fingerprint>`.

### More commands

```sh
# Ask before you propose. Answers are opinions on the record, not ballots.
peerharness question send <candidate-id> --circle team
peerharness question answer <question-id> --answer agree --rationale "we already do"

# Rules, on your own machine.
peerharness rule list                               # what is in force, and where it stands here
peerharness rule opt-out <name> --circle team       # keep one rule off your machine; add --announce to put it on record
peerharness circle mode ask --circle team           # be asked before any rule is installed
peerharness circle place repo/web --circle team --project ~/code/web   # rules of that scope go in that repository only

# The circle. Each of these is put to the vote.
peerharness rule repeal <name> --circle team        # vote a rule out
peerharness circle remove <member> --circle team    # vote someone off the roll
peerharness circle device add <device key> --circle team   # a second device; still one vote
peerharness circle amend --circle team --pass 2/3   # change the rules of the vote
peerharness circle leave --circle team              # stop following now, and ask to be taken off the roll

# Not voted on: the founder cuts off a lost or stolen device. It cannot pass anything.
peerharness circle revoke <member or device key> --circle team
```

`peerharness status` and `peerharness doctor` show where your node stands. Every
command has `--help`.

## What works today

| | |
|---|---|
| Voting: charter, roll, proposals, ballots, results, amendments, repeal | tested end to end |
| One person's loop: `note`, `review`, `skills install` and `uninstall` | tested end to end |
| Circle life: create, invite, join, remove, leave, amend, devices, revoke, questions, opt-outs | tested end to end with separate nodes |
| Exchange by address over QUIC, by shared directory, by file | tested end to end with separate processes |
| Exchange across the internet (`--internet`) | works. Tested with separate processes against a private stand-in network, and by hand on the real one from a single machine. Not yet tested between two different routers |
| Finding members on a local network (`--lan`) | works on macOS; the test needs real multicast and does not run in CI. Not tried on Linux |
| Noticing corrections by itself | best effort. Your agent reports a correction when it notices one. The built-in detector recognizes corrections that name a tool to use or avoid (46 of 70 in our test set, none of 52 ordinary prompts), not whole-sentence rules such as "always run the tests first". You can always write the rule down yourself |
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
  hides the variable on purpose. With `--windows` your agent chooses when a window
  appears; reading what it shows before you click is your part.
* **Confirmation windows are macOS only**, and need a key in the OS keychain (the
  default there). On Linux every decision still needs your own terminal.
* **Internet mode identifies your device to strangers.** Servers run by volunteers see
  the same public key with your IP address wherever you connect. Whether two nodes
  get a direct connection depends on their routers.

The full list is in [docs/security-model.md](docs/security-model.md).

## Documentation

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
