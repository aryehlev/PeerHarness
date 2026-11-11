# PeerHarness

**Your team votes on how its AI coding agents behave.**

You correct your coding agent ("no, use pnpm, not npm"). PeerHarness turns the
correction into a small rule, your teammates vote on it, and once a majority approves,
every member's agent follows it. There is no server: each person runs their own node
with their own keys, and every node checks every signature and counts every vote for
itself.

Agents can suggest rules. People decide. Keeping a rule, sharing one, voting, inviting
and joining are yours. Inside a session that PeerHarness recognizes as a coding
agent's, each of these steps is refused or put in a window on your screen that only
your click answers. No flag, argument or input of the session answers for you. The
window shows what you decide: the exact rule, the device you admit, or the charter
you join.

That stops an agent that is trying to help. It is not a sandbox. A session is
recognized by an environment variable, and only Claude Code's sessions are recognized
by default. [Known limits](#known-limits) begins with what this stops and what it does
not.

> **Status: v0.4.0, early and not audited.** It has had no
> independent review. [What works today](#what-works-today) says how each part was
> checked and what was never tried, and [Known limits](#known-limits) says what is
> missing. Read both before relying on it. What changed since v0.3.0 is in
> [CHANGELOG.md](CHANGELOG.md).

**Where it runs.** Claude Code on macOS, with the windows. Linux from your own
terminal, without windows. Windows is not supported.

## Why not a CLAUDE.md in git?

If the rule is about one repository and your team already reviews pull requests,
commit the file and review it in a pull request. You need nothing else.

PeerHarness is for what a file in one repository does not cover:

* rules that follow people across repositories;
* groups with no shared repository, or with nobody who administers one;
* members who want to see the exact text they vote on, and to be able to opt out of a
  rule alone.

The two combine: a team's signed records can live in a directory of a repository you
already share ([Other ways to exchange](docs/terminal.md#other-ways-to-exchange)).

## See it run

The demo needs the binary and changes nothing else on your machine.

```sh
curl -fsSL https://raw.githubusercontent.com/aryehlev/peerharness/main/install.sh | sh
~/.local/bin/peerharness demo
```

The first line downloads the release binary for your machine, checks it against the
release's `SHA256SUMS` and puts it in `~/.local/bin`. No `sudo`, and nothing else is
changed. To read the script before you run it:

```sh
curl -fsSL https://raw.githubusercontent.com/aryehlev/peerharness/main/install.sh -o install.sh
less install.sh
sh install.sh
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

Three independent nodes decided one shared rule by majority vote. No server was involved.
In this demo the signed events travelled between the nodes as files, and the skills
went into temporary directories. Between real machines the same events travel over
QUIC: see `peerharness sync --help`.
```

In the demo the rule is drafted by the built-in detector, from the two corrections.
That is why its wording and its name differ from the rule in the rest of this page,
which a person or their agent wrote down as one sentence.

`demo/two-peers.sh`, in a clone of this repository, shows the same with two separate
processes talking over the network. By default it builds the checkout first, which
needs a Rust toolchain and takes a few minutes. To run it with a binary you already
have: `PEERHARNESS_BIN="$(command -v peerharness)" demo/two-peers.sh`. Run it from
your own terminal: inside a coding agent's session the steps that vote are refused,
by design.

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

Install it as in [See it run](#see-it-run), then:

```sh
~/.local/bin/peerharness setup
```

`peerharness setup` creates your key and database, connects PeerHarness to Claude
Code and gives it the steps as tools. Before each change it shows you exactly what it
adds, what your agent may start and what it never decides, and asks you to confirm.
Then start a new Claude Code session.

### What setup adds, and what is stored

* **Your node**: a key in your keystore (the OS keychain on macOS, an encrypted file
  on Linux), and a database and a configuration file in `~/.peerharness`.
* **Two hooks** in Claude Code's settings, after a backup of the file.
  `UserPromptSubmit` keeps a redacted copy of each prompt you type, at most 4 KiB of
  it, in `~/.peerharness`. The built-in detector reads the copies to notice
  corrections. `Stop` stores no text; it prints the line that says how many proposals
  or notes wait for you.
* **One skill**, `peerharness-notes`, which asks your agent to note a rule when you
  correct it.
* **The tools**: the line `claude mcp add --scope user peerharness -- … mcp`, which
  setup shows you before it runs it.

The copies of your prompts stay on your machine and are never sent anywhere. Each
expires after 14 days by default (`[retention] observation_days` in
`~/.peerharness/config.toml`) and is deleted the next time the inbox is read. The
database is not encrypted: it relies on file permissions and on your disk's
encryption. To stop the recording, take the hooks out with `peerharness watch claude
--remove`. There is no switch for the hooks alone: that command also removes the skill
and turns the windows off.

## Take it out again

Every step, in this order. The first two need the node, so `reset` comes after them.

```sh
# 1. The rules installed for your agent.
peerharness skills list                               # the ones you kept for yourself
peerharness skills uninstall <name>
peerharness rule list                                 # the ones a team's vote installed
peerharness rule opt-out <name> --circle <team>       # one rule
peerharness circle leave --circle <team>              # or all of that team's rules

# 2. The two hooks and the skill. This also turns the windows off.
peerharness watch claude --remove

# 3. The tools.
claude mcp remove peerharness --scope user

# 4. The node: your key and your database. Without --confirm it only says what would go.
peerharness reset
peerharness reset --confirm

# 5. The binary.
rm ~/.local/bin/peerharness
```

`circle leave` also asks the members to take you off the roll, and signs that request
only as its preview showed it. Where it makes no request, it says so and why, and
running it again once the cause is gone shows the request and makes it. A team's
only member cannot leave it: opt out of its rules one by one. `reset --confirm` cannot
be undone, and ballots you already cast stay on the other members' nodes. A skill
that is still installed when you reset stays where it is, and the report lists its
folder for you to delete by hand. If you founded a team, its root key is deleted with
your node, and nobody can be admitted to that team or removed from it afterwards.

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

Cancel is the default button. In a session that PeerHarness recognizes, nothing is
kept, proposed, voted on, admitted or joined unless you click Proceed, and no flag,
argument or input of the agent is taken for that click. A rule your team passed is
installed when your node learns of it, without a window. That is shown where you
join, in the join window or the terminal's preview, and `peerharness circle create`
prints it to whoever runs it when a team is founded. `peerharness circle mode ask`
changes it.

### Rules

| You say | What happens |
|---|---|
| "No, use pnpm here, not npm." | Your agent does that, notes the rule ("Use pnpm, not npm, in this repository.") and tells you it did |
| "Keep it." | A window shows the exact rule. Proceed installs it for your own agent. Nothing is shared |
| "What is in my PeerHarness inbox?" | It lists the rules it noted and the proposals that wait for your vote |
| "Propose the pnpm rule to acme." | A window shows the exact text that would leave your machine, and what the scanner found in it. Proceed puts it to your team's vote |
| "Vote approve on it." | The window above. Proceed signs your ballot |
| "Anything new in PeerHarness?" | It exchanges with the other members and reads you your inbox |

A rule is never installed by itself: you keep it, or your team votes it in. Once a
majority has approved, it is installed for every member's agent as an
[Agent Skill](https://agentskills.io/specification). At the end of a turn, at most
once a day, Claude Code tells you how many proposals wait for your vote.

A vote never replaces a skill it did not install. If a skill that PeerHarness
installed is already there under the rule's name with another text (one you kept, or
another team's rule), the team's rule is held on your machine and nothing is written:
`peerharness rule list` says so and names the two ways out. A skill folder you made
by hand is not replaced either, and is not shown as held: `rule list` says that a
skill you manage yourself is in the way, and the rule is installed once you move the
folder away and run `peerharness proposal adopt <proposal-id>`. A repeal removes only
what a vote installed. `peerharness-notes` is the name of PeerHarness's own skill: no
rule can be noted, kept or proposed under it, and a rule of that name is never
installed.

### Words

| Word | What it is | Who gives it to whom |
|---|---|---|
| team, circle | The same thing. This page says team, the commands say circle | |
| charter, roll | The charter is the signed document every member holds: the thresholds of the vote and the roll, the list of members with their device keys | Every node holds a copy and checks it for itself |
| device key | Your node's public key (`ed25519:…`). It is not a secret | Whoever wants to join sends theirs to the member who invites them, by any channel |
| peer id | Your node's name on the network (`12D3…`), made from the same key | The member who invited sends theirs to the person joining, by any channel |
| root fingerprint | A short form of the team's root key (`8e8d-…`). It is how you know a team is the one you mean | The founder tells it to the person joining, by phone or in person, apart from the rest |

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
rest. The join window shows the charter, not the rules the team has already passed:
joining installs those for Dana's agent ([Known limits](#known-limits)). Once a team
has two or more members, admitting someone takes the others' votes too, asked in the
same kind of window.

### What still needs your terminal

* **A node that stays reachable.** Your agent keeps it reachable only while its
  session is open. For one that stays up:
  `peerharness daemon --internet --sync-every 60`, and on macOS add `--notify`.
* **Removing a member, leaving, changing the rules of the vote and repealing a rule**,
  and your ballot on any of them. For a change to the charter the terminal says what
  it does before you sign, read from the signed proposal and not from its title.
* **Editing or rejecting a noted rule**, and keeping, proposing, voting on or
  installing one that the scanner calls high-risk.
* **Following a rule again after you opted out** (`peerharness rule opt-in`). It shows
  the rule's exact text and where it goes, and asks. Your yes counts for that text
  only. It has no window and no tool. Opting out needs nobody and works anywhere.
* **Writing your data or a team's records to a file** (`peerharness export --local`,
  `peerharness events export`), and creating a node with a plaintext key.
* **Joining a circle of more than about five members:** its roll does not fit a window.
* **Everything but noting a rule, without windows:** on Linux, where none can be
  shown, or after `peerharness setup --no-dialogs`. Setup says so when it ends. One
  exception: a node whose settings allow windows on a machine that can show none, a
  home copied from a Mac for example, still runs the tools that need no window
  ([Without windows](docs/terminal.md#without-windows)).

All of it is in [PeerHarness from a terminal](docs/terminal.md).

## How a vote works

* **One charter.** Each circle has a signed charter: the thresholds and the roll of
  members. Everyone holds the same one, so everyone applies the same rules.
* **One person, one vote**, however many devices they have.
* **A majority of everyone entitled to vote.** Not voting counts as not approving.
  Nobody has a veto: a `reject` is recorded with its reason and does not block.
* **No clock, and no taking back.** A member cannot withdraw an approval, and counting
  reads no clock, so two nodes holding the same records always agree. No deadlines, no
  coordinator. One exception: when the founder revokes a device, its ballots stop
  counting, including ballots on proposals that had passed
  ([Known limits](#known-limits)).
* **Membership is voted too.** Admitting or removing a member and changing the
  thresholds are amendments that need a vote. The founder's key signs the resulting
  charter, and nodes reject any charter that a passed vote does not justify.
* **You are shown what you sign.** An approval of a rule is refused until the rule's
  exact text is on your node. The window shows that text. In a terminal the ballot
  shows the proposal's title, and `peerharness proposal show` prints the text. A
  ballot on an amendment in a terminal says what the amendment changes, read from its
  signed content and not from its title. A request to change the charter, and an
  approval of one, are signed only if the charter and the rules on your node are still
  what you were shown
  ([What a ballot shows](docs/terminal.md#what-a-ballot-shows)).
* **A passed rule takes effect.** It is installed for every member as an Agent Skill,
  unless a skill that no vote of the team installed has its name. Any member can opt
  out of a single rule on their own machine.

No vote and no charter can switch these off:

1. Nothing leaves your machine without you seeing the exact text and confirming it.
2. PeerHarness never executes a rule. A rule is one instruction-only `SKILL.md`; tool
   pre-approval and shell-injection syntax are refused outright. Your agent still
   acts on it ([Known limits](#known-limits)).
3. No vote grants read access.
4. A rule with high-risk content is never installed without asking you.
5. You can refuse a rule and you can leave.

## What works today

*Tested* means an automated test covers it. *By hand* means a run during development
that [docs/decisions.md](docs/decisions.md), this file's history or the pre-launch
check records, on the version named. *Not tried* means no run is recorded.
[docs/checked.md](docs/checked.md) has the table, part by part.

* **Tested.** Voting, one person's loop, a circle's life and the exchange over QUIC,
  by shared directory and by file: the tests with several nodes run them as separate
  processes. What a ballot shows, that a change to the charter is signed only as it
  was shown, what a vote may do to your own skills and what a session is refused.
  Setup, the tools, the windows, the notification, internet mode and the install
  script, each against a stand-in: for Claude Code's `claude` command, for an MCP
  client, for the window, for the notification, for the public network and for a
  release.
* **By hand.** The real window on macOS 14.2, before v0.1.0: it opened, closed
  unanswered and refused a text that does not fit. Internet mode on the real network,
  before v0.1.0, from one machine with both ends behind the same router. The tools
  with Claude Code 2.1.322 on macOS, before v0.2.0, in three runs. The real
  notification on macOS, once. `--lan` worked on macOS when it was built, before
  v0.1.0; no run of its tests is recorded. The install script with the v0.3.0 x86_64
  Linux binary, in a container. On Linux, with a debug build of this tree, on a
  pseudo-terminal: when the records of a rule that passed arrive on a node while its
  owner answers a prompt or types a passphrase, nothing is signed for a change to the
  charter, an approval of one, a repeal or an announced opt-out.
* **Not tried.** Clicking the buttons of the real window. The setup prompt above
  through an agent. A real agent noting, keeping, proposing, voting or joining.
  Internet mode between two different routers, over IPv6 or on Linux. `--lan` on
  Linux. The aarch64 Linux binary, and the macOS binaries since v0.2.0. The release
  binaries of 0.4.0, which the release workflow builds from the tag: none had been
  run when this page was tagged. MCP clients other than Claude Code. Windows is not
  supported.

The whole suite was run on 2026-11-10, on Linux, at commit `e6fae27` (0.4.0), in a
pre-launch check made with AI coding agents: 843 tests passed, none failed, and 10
were skipped because they need multicast, the public network or the real OS keychain.
After the fixes the suite was run again on Linux on 2026-11-11: 983 tests passed, none failed and 10 were skipped. CI ran it for pull request #7 at commit `400fd20` on Linux and macOS: 983 tests passed on Linux and 978 on macOS, none failed and 10 were skipped on each.
What that check was, what was fixed after it and what CI runs is in
[docs/checked.md](docs/checked.md#the-pre-launch-check-and-the-runs-of-the-suite).

## Known limits

**The agent guard is not a wall.** Consent steps recognize an agent's session by an
environment variable: the one Claude Code sets, or `PEERHARNESS_AGENT_SESSION` for
another agent's wrapper. An agent whose shell sets neither is refused only where a
step finds no terminal, with a message that tells it to stop and ask you, and nothing
keeps it from passing `--yes`.

| Who starts the step | What happens |
|---|---|
| An agent that behaves | It can note a rule and, where you allowed it, open a window. It cannot answer the window, and `--yes` is ignored in its session |
| An agent that was misled, by a page it read for example, and stays within its tools | The same. It chooses when a window appears and what it asks, so reading the window before you click is your part |
| A process that sets out to get around it | Not stopped. Anything running as you that hides the variable can run the same commands with `--yes`, edit the installed rules and the database, or use a key that unlocks without you |

Founding a team, exchanging with its members and keeping your node reachable are not
decisions in this sense. Once you allowed the steps about a team, your agent does them
when you ask, without a window. The longer account is section 4.17 of
[docs/security-model.md](docs/security-model.md#417-llm-generated-decisions-and-the-agent-acting-for-its-user).

The other limits:

* **The founder's key is needed to change the roll.** It notarizes charter changes. If
  it is lost the circle keeps working (members still sync, propose, vote and repeal),
  but nobody can be admitted or removed and the thresholds cannot change.
* **The founder can revoke a device without a vote, and that can undo a result.** It
  is meant for a lost laptop. A revocation adds no approval and does not change the
  roll. But every node that learns of it stops counting all ballots of that device,
  on proposals that had passed too. A rule that needed that ballot is open again and
  is removed from the members' agents. A repeal that needed it lapses, and the
  repealed rule is installed again. A compromised device counts until its revocation
  reaches each node. Whether a revocation should reach back like this is an open
  decision ([ADR-044](docs/decisions.md)).
* **After a revocation, an import can leave a member on the old charter**, and
  importing again does not help. It was seen with a file and with a shared directory.
  No way out has been tested. `peerharness reset` is not one: it deletes the node's
  device key, and a new key has to be voted onto the roll (`peerharness circle device
  add`), which may not reach its threshold once a device is revoked. What was tried
  by hand is in [ADR-044](docs/decisions.md), and the mechanism in section 4.16 of
  the [security model](docs/security-model.md#416-root-key-holder-and-circle-administrator).
* **The roll changes by simple majority**, so a majority can shrink the roll and then
  change the rules of the vote alone
  ([security model, 4.20](docs/security-model.md#420-governance-by-vote)).
* **An amendment carries the rule set of the moment it was proposed.** If a rule
  passes or is repealed while the amendment is open, approving it undoes that. The
  ballot names each such rule, and nothing stops the vote
  ([security model, 4.29](docs/security-model.md#429-what-a-voter-is-shown-before-a-ballot)).
* **A node that lacks a rule the charter carries can neither approve nor draft a
  change to the charter.** A join from an incomplete file leaves a node so, and so
  does every sync for a member whose scopes do not cover the rule. Its owner can
  still leave on their own machine, and the request to be taken off the roll is not
  made from that node. The way out is to import the events file of a member who holds
  the rule ([What a ballot shows](docs/terminal.md#what-a-ballot-shows)). That file
  holds every scope's records, the rule's text included. For a member whose scopes do
  not cover the rule this gives them what the scope withholds, and it is needed again
  after each change to the charter that carries a new such rule.
* **A rule can be in force and not on your machine.** A team rule whose name a skill
  that PeerHarness installed on your machine already has, with another text, is held
  there. It stays in force for the team, and nobody else is told. `peerharness rule
  list` shows it
  ([A rule that is held](docs/terminal.md#more-commands),
  [security model, 4.30](docs/security-model.md#430-a-passed-rule-and-the-skills-already-on-a-machine)).
  One case is not covered: a rule you keep after a vote already installed the
  identical text still counts as the vote's, so a repeal removes it.
* **One rule per name, across scopes.** A rule adopted in a narrower scope replaces a
  team-wide rule of the same name for everyone, although only that scope's members
  voted. A team in which every member has the default scope is not affected
  ([security model, 4.20](docs/security-model.md#420-governance-by-vote)).
* **No secret ballot.** Votes are signed and every member sees who voted how.
* **Turnout.** A member who never votes makes every threshold harder to reach. Rolls
  are capped at 64 members.
* **Leaving is immediate on your machine, and by vote on the roll.** Until the members
  approve it, your name still counts toward every threshold. If your node made no
  request (a key that did not unlock, a rule of the charter that the node does not
  hold, or records of the team that arrived while you confirmed), you are off the
  team on your machine and still on its roll. The request is then made when you run
  `peerharness circle leave` again once the cause is gone, or when a member proposes
  your removal.
* **A team rule is one sentence of at most 200 characters.** A note may be up to 500.
  A longer one has to be shortened before it can be proposed (`peerharness review
  <candidate-id> --edit "…"`).
* **Safety checks are heuristics.** Redaction and the risk scanner catch common cases
  and miss others. They never prove that a text is safe. The scanner rates as
  high-risk a text that tells the agent to fetch a URL and follow what it finds, and
  one that gives instructions about PeerHarness's own guard. Both go by wording: the
  same thing in other words is not found, and a harmless rule can be.
* **A rule is text that your agent acts on.** "PeerHarness never executes a rule"
  means exactly that: PeerHarness runs nothing from it, and a rule cannot pre-approve
  a tool. Your agent follows the rule, and your agent can run commands. Read a rule as
  you would read a script.
* **Joining installs rules you have not read.** The join window, like the terminal's
  preview, shows the root fingerprint, the charter and how many rules the charter
  carries. It does not show their names or their text. In a team whose charter makes
  rules binding, which is the default, they are installed for your agent when you
  join. A rule with a high-risk finding still asks first. `peerharness rule list`
  shows them afterwards, and you can opt out of any.
* **Your prompts are kept on your machine, in a database that is not encrypted.** See
  [What setup adds, and what is stored](#what-setup-adds-and-what-is-stored).
* **A node is reachable only while a daemon runs.** That is one you start yourself, or
  the one your agent runs while its session is open. There is no background service
  yet: a sync reaches only the members whose daemon is running at that moment.
* **Confirmation windows are macOS only**, and need a key in the OS keychain (the
  default there). On Linux every decision needs your own terminal: of the tools your
  agent is given, only the one that notes a rule runs there, and every other one
  answers that the step is yours. The exception is a node whose settings allow
  windows, a home copied from a Mac for example: there the tools that need no window
  still run ([Without windows](docs/terminal.md#without-windows)).
* **Internet mode identifies your device to strangers.** Servers run by volunteers see
  the same public key with your IP address wherever you connect. Whether two nodes
  get a direct connection depends on their routers.

The full list is in [docs/security-model.md](docs/security-model.md).

## Documentation

* [docs/terminal.md](docs/terminal.md): every step as a command, the other ways to exchange, and what internet mode exposes
* [docs/architecture.md](docs/architecture.md): the internal contract every crate follows
* [docs/protocol-v0.md](docs/protocol-v0.md): the wire format, for a second implementation
* [docs/security-model.md](docs/security-model.md): threats, guarantees and limits
* [docs/checked.md](docs/checked.md): how each part was checked, and what was never tried
* [docs/decisions.md](docs/decisions.md): decisions and why they were made
* [CHANGELOG.md](CHANGELOG.md): what each version added

## Development

The code and its tests were written from 9 to 11 November 2026 with an AI coding
agent, as the commit trailers say, from the brief in [docs/spec.md](docs/spec.md). The
decisions made on the way, and where the product departs from the brief, are in
[docs/decisions.md](docs/decisions.md).

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

MIT or Apache-2.0, at your option.
