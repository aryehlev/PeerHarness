# PeerHarness

**Your team votes on how its AI coding agents behave.**

You correct your coding agent ("no, use pnpm, not npm"). PeerHarness turns the
correction into a one-sentence rule. Keep it for your own agent, or propose it to your
team: once a majority approves, every member's agent follows it. There is no server.
Each person runs their own node with their own keys, and every node checks every
signature and counts every vote for itself.

Agents suggest, people decide. Your agent can note a rule and open a window on your
screen that shows the exact text. It cannot answer the window: inside its session,
keeping a rule, sharing one, voting, inviting and joining take your click. That stops
an agent that is trying to help. It is not a sandbox ([Limits](#limits)).

> **Status: v0.4.0, early and not audited.** For Claude Code on macOS. On Linux it
> works from a terminal, without the windows. Windows is not supported. Read
> [Limits](#limits) before you rely on it.

## Set it up

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

Or run the two lines yourself, then start a new Claude Code session:

```sh
curl -fsSL https://raw.githubusercontent.com/aryehlev/peerharness/main/install.sh | sh
~/.local/bin/peerharness setup
```

* **The first line** downloads the release binary for your machine, checks it against
  the release's `SHA256SUMS` and puts it in `~/.local/bin`. No `sudo`, and nothing
  else is changed.
* **`setup`** creates your key and database and connects PeerHarness to Claude Code:
  two hooks, one skill and its tools. It shows each change before it makes it and asks
  you to confirm.
* **What it stores.** One hook keeps a redacted copy of each prompt you type, so that
  corrections can be noticed. The copies stay on your machine, for 14 days by default,
  in a database that is not encrypted.

More: [what setup adds and stores](docs/terminal.md#what-setup-adds-and-what-is-stored),
[how to take it out again](docs/terminal.md#take-it-out-again), and
[Linux, another agent or none](docs/terminal.md).

## Use it

Work with your agent as you always do.

| You say | What happens |
|---|---|
| "No, use pnpm here, not npm." | Your agent does that, notes the rule ("Use pnpm, not npm, in this repository.") and tells you it did |
| "Keep it." | A window shows the exact rule. Proceed installs it for your own agent. Nothing is shared |
| "What is in my PeerHarness inbox?" | It lists the rules it noted and the proposals that wait for your vote |
| "Propose the pnpm rule to acme." | A window shows the exact text that would leave your machine, and what the scanner found in it. Proceed puts it to your team's vote |
| "Vote approve on it." | A window shows the ballot and the rule. Proceed signs your ballot |
| "Anything new in PeerHarness?" | It exchanges with the other members and reads you your inbox |

When something is yours to decide, the window has the exact text and two buttons,
Cancel and Proceed. Cancel is the default. This is the one for a vote:

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

A rule is never installed by itself: you keep it, or your team votes it in. A rule
your team passed is installed for every member's agent as an
[Agent Skill](https://agentskills.io/specification) when their node learns of it,
without a window. `peerharness circle mode ask --circle <team>` makes your node ask
you first, and you can opt out of any single rule on your own machine.

### A team

One of you founds the team and invites. The others join. The commands call a team a
*circle*.

1. **The founder:** "Create a PeerHarness team called acme." The agent shows the team's
   root fingerprint.
2. **Whoever wants to join:** "What is my PeerHarness device key?" They send the key
   to the founder.
3. **The founder:** "Invite Dana to acme. Her device key is ed25519:…" A window names
   Dana's device. After Proceed the agent keeps the founder's node reachable and says
   what Dana needs: the node's peer id, by any channel, and the root fingerprint, by
   phone or in person.
4. **Dana:** "Join the team. The peer id is 12D3…, the fingerprint is 8e8d-…" A window
   shows the fingerprint and who is in the team. Proceed joins.

The fingerprint is how Dana knows the team is yours, so it travels apart from the
rest. Once a team has two or more members, admitting someone takes the others' votes
too, asked in the same kind of window.

### What needs your terminal

* **A node that stays reachable.** Your agent keeps it reachable only while its
  session is open. For one that stays up:
  `peerharness daemon --internet --sync-every 60`, and on macOS add `--notify`.
* **Removing a member, leaving, changing the rules of the vote and repealing a rule.**
* **Editing or rejecting a noted rule**, and anything about a rule that the scanner
  calls high-risk.
* **Every decision on Linux**, where no window can be shown.

Each step as a command is in [PeerHarness from a terminal](docs/terminal.md).

## See it run

```sh
peerharness demo
```

The demo needs only the binary. It creates three members and one outsider in a
temporary folder, each with its own key and database, and nothing in your home or in
`~/.claude` is read or changed. The second half of its output, abridged:

```text
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

## How a vote works

* **One person, one vote**, however many devices they have.
* **A majority of everyone entitled to vote.** Not voting counts as not approving.
  Nobody has a veto: a `reject` is recorded with its reason and does not block.
* **No deadlines and no coordinator.** A member cannot withdraw an approval, and
  counting reads no clock, so two nodes that hold the same records always agree.
* **Membership is voted too.** Admitting or removing a member and changing the
  thresholds need a vote. The founder's key signs the resulting charter, and nodes
  refuse any charter that a passed vote does not justify.
* **A passed rule takes effect.** It is installed for every member's agent, and any
  member can opt out of a single rule on their own machine.

No vote and no charter can switch these off:

1. Nothing leaves your machine without you seeing the exact text and confirming it.
2. PeerHarness never executes a rule. A rule is one instruction-only `SKILL.md`; tool
   pre-approval and shell-injection syntax are refused outright.
3. No vote grants read access.
4. A rule with high-risk content is never installed without asking you.
5. You can refuse a rule and you can leave.

## Why not a CLAUDE.md in git?

If the rule is about one repository and your team already reviews pull requests,
commit the file. You need nothing else. PeerHarness is for rules that follow people
across repositories, for groups with no shared repository or nobody who administers
one, and for members who want to see the exact text they vote on and to opt out of a
rule alone.

## Limits

* **The agent guard is not a sandbox.** A session is recognized by an environment
  variable, and only Claude Code's by default. A process running as you that hides it
  can run the same commands with `--yes`. Your agent chooses when a window appears:
  reading it before you click is your part.
* **A rule is text that your agent acts on**, and your agent can run commands. The
  risk scanner and the redaction are heuristics. Read a rule as you would a script.
* **Joining installs rules you have not read.** The join window shows the charter and
  how many rules it carries, not their text. You can opt out of any afterwards.
* **The founder can revoke a device without a vote**, for a lost laptop. Its ballots
  stop counting, so a result that needed one is undone. The founder's key also signs
  every change of the roll: if it is lost, nobody can be admitted or removed.
* **No secret ballot**, and at most 64 members. A member who never votes makes every
  threshold harder to reach.
* **A node is reachable only while a daemon runs**: yours, or the one your agent runs
  while its session is open. There is no background service yet.
* **Internet mode** shows your node's public key and IP address to servers run by
  volunteers.
* **Not tried yet:** clicking the buttons of the real window, a real agent noting,
  keeping, proposing, voting or joining, and internet mode between two different
  routers. The tests run these against stand-ins.

The full list is in [docs/limits.md](docs/limits.md), and how each part was checked
is in [docs/checked.md](docs/checked.md).

## Documentation

* [docs/terminal.md](docs/terminal.md): every step as a command, the other ways to exchange, and how to take it out again
* [docs/limits.md](docs/limits.md): what it does not do, or not yet
* [docs/checked.md](docs/checked.md): how each part was checked, and what was never tried
* [docs/security-model.md](docs/security-model.md): threats, guarantees and limits
* [docs/architecture.md](docs/architecture.md): the internal contract every crate follows
* [docs/protocol-v0.md](docs/protocol-v0.md): the wire format, for a second implementation
* [docs/decisions.md](docs/decisions.md): decisions and why they were made
* [CHANGELOG.md](CHANGELOG.md): what each version added

## Development

Written from 9 to 11 November 2026 with an AI coding agent, as the commit trailers
say, from the brief in [docs/spec.md](docs/spec.md). To build and test, see
[CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, see
[SECURITY.md](SECURITY.md).

## License

MIT or Apache-2.0, at your option.
