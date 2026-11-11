# PeerHarness from a terminal

Everything PeerHarness does can be done from a terminal, on macOS and Linux, with any
agent or with none. The [README](../README.md) shows the way through Claude Code. This
page has the same steps as commands, and the ones that have no window.

```sh
curl -fsSL https://raw.githubusercontent.com/aryehlev/peerharness/main/install.sh | sh
```

To read the script before you run it, download it first: the three lines are in the
README under [See it run](../README.md#see-it-run). Or build from source, with Rust
1.89 or newer:
`cargo install --locked --git https://github.com/aryehlev/peerharness peerharness`.
`peerharness status` and `peerharness doctor` show where your node stands, and every
command has `--help`. A binary made with a plain `cargo build` is a debug build, for
development and tests: it obeys the stand-in programs the tests use in place of a
confirmation window, and `doctor` and `status` say that it is one.

This page says "circle" where the README says "team": it is the word the commands
use. The README has the other words under [Words](../README.md#words).

> **This page describes 0.4.0, which is on `main` and not released.** The install
> script above installs v0.3.0, which has no `peerharness keep`: there, use
> `peerharness review <candidate-id> --approve` and then `peerharness skills install
> <name>`. The `cargo install` line above builds 0.4.0. What else v0.3.0 does
> differently is in the [README's status note](../README.md#peerharness).

## A rule of your own

A rule of your own needs no circle and no network.

```sh
peerharness init

# Write a rule down in one sentence. It becomes a candidate in your inbox.
peerharness note "Use pnpm, not npm, in this repository."

# Keep it: it shows the exact skill text and anything the scanner found in it, asks
# once, and installs it for Claude Code (~/.claude/skills/<name>/SKILL.md).
# Reversible with `skills uninstall`.
peerharness keep <candidate-id>
```

On Linux the key is kept in an encrypted file, and `init` asks for its passphrase
twice. There is no way to recover it. Every command that needs the key asks for it
again, the daemon when it starts included, unless `PEERHARNESS_PASSPHRASE` is set in
its environment. An `init` that fails before the key exists, for want of a passphrase
for example, takes away what it created, and a configuration file that was already
there gets its content back: the next `init` starts clean. An `init` that is
interrupted, with Ctrl-C at the passphrase prompt for example, takes nothing away: it
leaves a configuration file and a database without a key, and other commands then say
"this home has no device identity yet". The next `init` or `setup` completes that
home. One `init` runs for a home at a time. A second one is refused while the first
is running ("another `peerharness init` is running for this home") and changes
nothing.

`note` makes the skill's name from the rule's words, or takes one with `--name`. One
name is taken: `peerharness-notes` is PeerHarness's own skill, and no rule can be
noted, kept or proposed under it.

`keep` is two steps in one. Taken apart, they let you edit the rule, ignore it, accept
a high-risk finding or install it for one project only:

```sh
peerharness review <candidate-id>                       # read it; --edit "..." changes it, --reject ignores it
peerharness review <candidate-id> --approve             # save it to your library
peerharness skills install <name>                       # install it; --scope project keeps it to one repository
```

## Connect your agent

```sh
peerharness setup                # everything below, each step shown first and confirmed
peerharness setup --no-dialogs   # the same, with every decision in your terminal
```

`setup` runs three steps, which you can also run one at a time:

```sh
peerharness init                               # your key and your database
peerharness watch claude --install --dialogs   # hooks, the skill, and deciding in a window (macOS)
claude mcp add --scope user peerharness -- ~/.local/bin/peerharness mcp   # the steps as tools
peerharness watch claude --remove              # take the hooks and the skill out again
```

`watch claude --install` shows what it adds before it adds anything: two hooks and a
small skill that asks the agent to note a rule when you correct it. One of the hooks
keeps a redacted copy of each prompt you type, on your machine only; the README says
[what is stored and for how long](../README.md#what-setup-adds-and-what-is-stored).
The note waits in `peerharness inbox`; approving it stays yours.

With `--dialogs` your agent may ask you in a window on your screen. (The flag used to
be `--windows`, which still works; it never meant the operating system.) A window
shows the exact text and the buttons Cancel and Proceed. Only your click on Proceed
counts there: inside its session your agent cannot answer the window, and `--yes` does
not skip it there. It covers keeping a rule for yourself, proposing a rule,
your ballot on one, installing one that passed, inviting someone, your ballot on
admitting someone and joining a circle. Everything else, and any text too long to show
in full, needs your own terminal. Inside an agent's session those steps are refused,
and so is `setup` itself. A rule with a high-risk scanner finding is never decided in
a window: not when it is proposed, voted on, installed or kept.

Among the steps without a window, and so refused inside a session whatever you
allowed:

* `peerharness rule opt-in`, which follows a rule again after an opt-out. Opting out
  is never refused.
* `peerharness export --local` and `peerharness events export`, which write your notes
  and a circle's records out.
* `peerharness init` with the plaintext keystore (`insecure-dev`). A plain `init`
  works there.

A note written inside a session is labelled "reported by your agent" in your inbox,
whether or not the agent passed `--from-agent`, and at most 20 such notes wait at a
time. When a step needs your confirmation and no terminal is attached, PeerHarness
stops and says so. `--yes` is for a script you wrote yourself. A coding agent that
reads that message is told to stop and ask you.

This guards against an agent that is trying to help. It is not a sandbox: a session
is recognized by an environment variable (`CLAUDECODE`, which Claude Code sets, or
`PEERHARNESS_AGENT_SESSION`), so a process running as you that hides it can run the
same commands with `--yes`. The table under
[Known limits](../README.md#known-limits) in the README says what is stopped and what
is not.

`peerharness mcp` gives an agent the same steps as tools. Without it the agent runs
the commands it read in the skill. Other agents that speak MCP can use it too; only
Claude Code was tried. The tool that joins a circle takes a member's peer id or
address and never a file: joining from a file is `peerharness circle join <file>` in
your own terminal. The tool that votes takes a reason of one line of at most 200
characters, the limit of `proposal vote`.

### Without windows

Without confirmation windows your agent can do one thing with these tools: note a
rule. That is the case on Linux, where no window can be shown, and after `peerharness
setup --no-dialogs`. Every other tool answers that the step is yours. On a machine
that cannot show a window the answer names this page and not `setup`, since no setting
changes it. `setup` says the same when it ends, and suggests nothing to ask the agent.

One case differs: a node whose settings allow windows, on a machine that can show
none. A home copied from a Mac is one. A tool runs at the level the settings allow, so
the steps that would ask in a window are refused there and the tools that need none
still run: the status and the inbox, and with the steps about a circle allowed also
founding a circle, the exchange over the public network and the daemon. `setup` says
so when it ends, and `peerharness setup --no-dialogs` turns them off. Joining is one
of the steps that are refused there, and it is refused before the node looks anyone
up: inside a session, `circle join <peer id or address>` goes to the network only for
a join that can be put in a window.

On Linux `peerharness setup` still creates your node, installs the hooks and the
notes skill and registers the tools. What you get from it there: Claude Code notes the
rules you give it and tells you, at the end of a turn and at most once a day, how many
noted rules and proposals wait for you. You decide in the terminal:

```sh
peerharness inbox                                   # what waits for you
peerharness keep <candidate-id>                     # keep a noted rule for your own agent
peerharness proposal create <candidate-id> --circle team
peerharness proposal vote <proposal-id> approve
```

For a node that is already there, `setup` says which keystore holds its key, and
warns when it is the plaintext one.

## A team

Each member runs their own node. With `--internet`, nodes find each other from
anywhere by peer id: no address, no port forwarding, no server of ours.

```sh
# Both: create a node. `peerharness status` prints its device key and peer id.
peerharness init

# Alice founds the circle and tells Bob the root fingerprint, in person or by phone.
peerharness circle create team

# Alice proposes admitting Bob's device. She is the only member, so her approval passes it.
# (It also writes peerharness-team-events.jsonl into the current directory, for joining
# without a network. Not needed here.)
peerharness circle invite <bob's device key> --circle team --member bob

# Alice leaves her node running.
peerharness daemon --internet

# Bob finds her node by its peer id, checks the fingerprint, reads the charter and joins.
# --name is what Bob's node calls the circle. Without it: circle-<fingerprint>.
peerharness circle join <alice's peer id> --internet --expect-fingerprint <fingerprint> --name team

# Alice puts a rule to the vote, and votes. Creating a proposal is not a vote.
# (If she noted this rule before, `note` prints the id it already has.)
peerharness note "Use pnpm, not npm, in this repository."
peerharness proposal create <candidate-id> --circle team
peerharness proposal vote <proposal-id> approve

# Bob fetches it, reads the exact text, and votes. Two of two: it passes.
peerharness sync --internet
peerharness proposal show <proposal-id>
peerharness proposal vote <proposal-id> approve
peerharness sync --internet     # Alice's node learns of it and installs the rule too
```

A circle's name is local: each member's node has its own name for it, and `--circle`
takes that one. `peerharness status` lists the names, and a command given a name that
is not on your node says so. A rule needs the approval of more than half of the
members: of two, both; of three, two. Admitting or removing someone is a vote of the
current members with the same threshold, from the second member on.

### What a ballot shows

`proposal create` shows the exact text that leaves your machine and what the scanner
found in it. A rule with a high-risk finding is asked in your terminal only.

`proposal vote` on a rule refuses an approval until the rule's text is on your node:
read it with `proposal show`. In a terminal the ballot itself shows the proposal's
title and not the text. `proposal show` prints the text, every line behind `| `, with
the number of scanner findings and whether one is high-risk. It does not print the
findings: those are shown when a rule is proposed, on a ballot asked in a window, and
before an install that asks.

On an amendment (an admission, a removal, a device, new rules of the vote) `proposal
vote` says what the amendment changes, read from its signed content and not from its
title. For an admission it reads like this:

```text
You are about to sign a ballot in team:
  approve on an amendment to the charter (proposal sha256:b7cb86239a67)
  proposed by alice (device 8ceb-2ba9-db82-00ad-5ab2)
What this amendment changes, read from its signed content:
  the roll of charter 3 (3 members; 4 after):
    admits dave (device 1807-d84b-a2f5-0d07-3869, scopes *)
  the rules of the vote stay as they are
  the rules in force stay as they are (1 in force)
The proposer's own words for it (its title, which decides nothing): "Admit dave"
An approval cannot be withdrawn.
```

The three parts are always there: the roll, the rules of the vote, the rules in force.
For a member who stays, each device added or taken is a line of its own ("bob gets
device … as well: whoever holds it can sign and vote as bob"). New thresholds are
shown with the old ones. `proposal show` prints the same description.

An amendment carries the rule set of the moment it was proposed. If a rule passed or
was repealed since, the amendment would undo that, and the third part names each such
rule: "goes out of force", or "comes into force without a vote of its own", followed
by that rule's exact text with every line behind `| `. An approval is refused until
that text is on your node; `reject` and `revise` are always possible. Approving still
makes the rule set exactly what the amendment carries. If that is not what you want,
do not approve it, and propose the amendment again.

An amendment can also list a second proposal under the name of a rule that is in
force. If the listed one is the later of the two, it would take the rule's place, and
the line reads "rule <name> gets another text without a vote of its own", with that
text. If it is the earlier one, nothing changes, and the line says that the rule in
force "is the later one and stays as it is".

A node can lack a rule that the charter in force carries. A join from a file that did
not hold the rule leaves it so, and so does every sync for a member whose scopes do
not cover the rule, because a sync does not send it. `peerharness rule list` then has
the line "(a carried rule, proposal <id>, has not arrived on this node yet)". On such
a node:

* An approval of an amendment is refused, with `--yes` too. One that leaves the rule
  out is described with "a rule the charter in force carries, which this node does not
  hold, goes out of force … This node cannot say which rule that is". One that keeps
  it, as an honest amendment drafted on a complete node does, is described with "a
  rule the charter in force carries, which this node does not hold, is kept … This
  node cannot say whether that changes anything: a rule repealed since would come back
  into force". Neither is put in a window.
* `circle invite`, `circle remove`, `circle amend` and `circle device` are refused
  before anything is shown: an amendment drafted there would leave the rule out and
  take it out of force for everyone.
* `circle leave` is not refused, and it makes no request to the circle from that
  node. It removes the circle's rules from your machine, says that no request to take
  you off the roll was made, and says why
  ([Leaving a circle](#leaving-a-circle)).

The way out is to import the events file of a member who holds the rule
(`peerharness events import`). That file holds the records of every scope, the rule's
text included. For a member whose scopes do not cover the rule, it gives them what
the scope withholds, and it is needed again after each change to the charter that
carries a new such rule. One case stays open: a rule that passed under the
current charter in a scope your node cannot read is neither among the rules in force
on your node nor among the carried rules it lacks. An amendment that leaves it out is
not caught there.

A yes counts for what you were shown. If a sync or an import changes the charter or
the rules in force on your node while you read, or while you type your passphrase,
nothing is signed. Your node looks again after the key is unlocked, and nothing asks
you anything between that look and the signature:

* `circle invite`, `remove`, `amend` and `device` stop with "the circle's charter or
  the rules in force changed on this node while this was being confirmed. Nothing
  was proposed and nothing was signed. Run the command again to see what it would do
  now."
* `proposal vote <id> approve` on an amendment stops with "what this amendment would
  change is no longer what you were shown: the charter or the rules in force changed
  on this node while you read. Nothing was signed. Run the command again." A `reject`
  or a `revise` is not refused.
* `rule repeal` stops when the rule it showed is no longer the rule of that name,
  with "the rule changed while this was being confirmed: what you were shown is no
  longer the rule in force. Nothing was proposed and nothing was signed. Run the
  command again to see the rule as it is now." `rule opt-out --announce` and `rule
  opt-in --announce` look in the same way before they sign the record for the
  circle: what they did on your machine stands and is reported, and the command then
  ends with "nothing was announced: the rule changed while this was being confirmed,
  and what you were shown is no longer the rule in force. Run the command again to
  see the rule as it is now."

Each of these exits 3. `circle leave` signs its request under the same check
([Leaving a circle](#leaving-a-circle)).

A reason given with `--rationale` is published with the ballot. It is one line of at
most 200 characters, counted after redaction, without control characters, invisible
characters or blanks that are not spaces. Zero-width characters are invisible ones:
the joiner inside some emoji and in Hindi, the non-joiner in Persian. A line that has
one is refused, and the error says what is checked. `proposal show` prints what other
members wrote (a reason, a summary, a rule's text) on lines of their own, each
beginning with `| `.

To hear about a vote when it happens, leave your node running like this:

```sh
peerharness daemon --internet --sync-every 60            # Linux
peerharness daemon --internet --sync-every 60 --notify   # macOS
```

It fetches from the other members every minute. `--notify` is macOS only: on Linux
the daemon refuses to start with it. With it, a desktop notification appears within
seconds of a proposal that needs your vote arriving. The notification says how many
wait, never what they say. Without it, the end of your next turn in Claude Code tells
you instead (with `watch claude --install`), once a day at most.

## What `--internet` exposes

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

## Other ways to exchange

Every node verifies each record itself, so none of these channels has to be trusted to
keep a vote intact.

| | Commands | Good to know |
|---|---|---|
| A repository you already share | `peerharness events sync .peerharness/team --circle team`, then commit and push | Each record is its own file, so there are no merge conflicts. Everyone who can read the repository can read the roll and the ballots |
| A member's address | `peerharness daemon --listen /ip4/0.0.0.0/udp/4001/quic-v1`, then `peerharness sync <the address it prints>` | Needs the same network, a VPN or a forwarded UDP port |
| The local network | `peerharness daemon --listen … --lan`, then `peerharness sync --lan` | Announces the device's public key and port on that network |
| A file | `peerharness events export --circle team --out f.jsonl`, then `peerharness events import f.jsonl` | Holds the roll and proposals in clear text: send it only to members |

A new member can join from any of them: `peerharness circle join <address, directory or
file> --expect-fingerprint <fingerprint> --name team`. The name is local: it is what
that member's node calls the circle.

A line of an events file and a record file in a shared directory are parsed like a
frame from the network before anything in them is looked at: at most 1 MiB, integers
only, no member twice, and nothing but the one member a record has (`event` or
`bundle`). A line that is not such a record is refused and counted, and the other
records are still imported. The event inside is then verified as one from a peer is,
which refuses an unknown member or an explicit `null` anywhere in it.

Joining from a file or a directory joins the circle whose root fingerprint you pass.
Anyone who can write to a shared directory can add records of a circle of their own
that list your device key. They cannot make you join it: with the fingerprint the
founder gave you, only that circle's charters are looked at. If the file or directory
holds charters of more than one circle that list your device and you pass no
fingerprint, the command stops and asks for it. It does not choose for you.

## More commands

```sh
# Ask before you propose. Answers are opinions on the record, not ballots.
peerharness question send <candidate-id> --circle team
peerharness question answer <question-id> --answer agree --rationale "we already do"

# Rules, on your own machine.
peerharness rule list                               # what is in force, and where it stands here
peerharness rule opt-out <name> --circle team       # keep one rule off your machine; add --announce to put it on record
peerharness rule opt-in <name> --circle team        # follow it again: shows the rule's text and where it goes, and asks
peerharness circle mode ask --circle team           # be asked before any rule is installed; what is installed stays
peerharness proposal adopt <proposal-id>            # install a rule that waits for your confirmation
peerharness circle place repo/web --circle team --project ~/code/web   # rules of that scope go in that repository only

# The circle. Each of these is put to the vote.
peerharness rule repeal <name> --circle team        # vote a rule out
peerharness circle remove <member> --circle team    # vote someone off the roll
peerharness circle device add <device key> --circle team   # a second device; still one vote
peerharness circle amend --circle team --pass 2/3   # change the rules of the vote
peerharness circle leave --circle team              # stop following now, and ask to be taken off the roll
# (invite, remove, device and amend draft nothing on a node that lacks a rule the charter
# carries: see "What a ballot shows" above.)

# Not voted on: the founder cuts off a lost or stolen device. Its ballots stop counting,
# the ones it already cast included, so a result that needed one of them is open again.
peerharness circle revoke <member or device key> --circle team
```

What a revocation does to results that had passed, and what can go wrong with an
import afterwards, is under [Known limits](../README.md#known-limits) in the README.
Whether it should stay that way is an open decision (ADR-044 in
[decisions.md](decisions.md)).

`rule opt-out` is immediate and asks nobody. `rule opt-in` is the reverse step and is
yours: it shows the rule's exact text, the scanner's findings and the directory it is
installed in, and installs the rule when you confirm, also when your mode is `ask`. In
a script of your own, `--yes` skips the prompt.

Your yes counts for the rule you were shown and for no other rule of that name. If a
sync or an import stored a newer proposal of the same name while you read, `rule
opt-in` changes nothing, leaves your opt-out in place and says to run it again.
`proposal adopt` installs nothing on that yes and says that `peerharness rule list`
shows the rule as it is now. Both are refusals: the command exits 3, so a script of
yours does not go on as if the rule it confirmed were installed. One case differs: if
the newer proposal takes the name only after `proposal adopt` installed the rule you
confirmed, it prints "Installed rule <name>, as you were shown it.", and then ends
with exit 3 and "the rule was installed as you were shown it, and another rule of
that name is in force since".

A rule that waits for you is printed with the command that confirms it, by every
command that brings the rules on your machine up to date: "rule <name> is in force and
waits for your confirmation, because …", followed by `peerharness proposal adopt` and
the proposal's id. It waits because you chose `ask`, because the scanner found
high-risk content, or because a policy you set for your node is not met. A rule that
is installed is never listed as waiting. A sync reports a rule that waits or is held
once per exchange, and a one-shot `sync` lists every hold it finds.

A running daemon prints each hold once for as long as it runs:

* A hold that one of its own exchanges finds is printed with the first report that
  has it, also when that exchange moved no event. A later report, printed because
  events moved or because a rule waits, does not repeat it.
* A hold that a member's sync to your node created is printed when that push is
  settled, as a line of its own without a "Synced …" line above it: "rule <name> is
  in force and is held on this machine: …". This needs no `--sync-every`, and your
  daemon does not have to know that member's address.

A rule that waits for your confirmation is printed on every tick while it waits. A
hold that goes away and comes back while the daemon runs is not printed a second
time. `peerharness rule list` shows a hold at any time.

**A rule that is held.** A vote never replaces a skill it did not install. If a skill
that PeerHarness installed and that no vote of that circle installed (one you kept,
or another circle's rule) has the name of a rule your circle passes, with another
text, the rule is held on your machine and nothing is written. `peerharness rule
list` shows it as `held`, with the two ways out:

```sh
peerharness skills uninstall <name>                 # take the one that is there out ...
peerharness proposal adopt <proposal-id>            # ... and follow the circle's rule
peerharness rule opt-out <name> --circle team       # or keep the one that is there
```

If the skill in the way is a copy of the rule's text that you edited, `skills
uninstall` needs `--allow-modified`. If the rule is held when you opt back in, the
second step is `rule opt-in` again, not `proposal adopt`. If the skill in the way is
another circle's rule, `skills uninstall` names that circle and its opt-out. If you
placed the rule's scope in a project (`circle place`), the skill in the way is in
that project, and the hint names the first step as `peerharness skills uninstall
<name> --scope project`, run in that directory. `skills uninstall <name> --scope user`
is refused there while a copy that a vote installed for every project is still
followed. Inside a coding agent's session the hold is reported without these
commands: the agent is told that the choice is yours and to take nothing out. `skills
uninstall` itself is not refused there.

`skills uninstall` does not take out a rule in force that you follow: it is refused
(exit 2) with "<name> is a rule in force in <circle>. To keep it off this machine, opt
out", followed by the opt-out command. That holds in your user directory and in a
project. In a project it is refused for a rule that lives in the project you run it
in, and for a copy that a circle's vote installed there. Your own skill that holds a
rule there, and a copy you installed yourself of a rule that lives elsewhere, are
yours to take out. The project is the directory the command runs in.

A skill folder that you made by hand, and that PeerHarness therefore does not manage,
is not a hold: `rule list` shows "a skill of that name you manage yourself is in the
way" and names no way out, `skills uninstall` leaves the folder untouched, and the
rule is installed once you move the folder away yourself and run `peerharness proposal
adopt <proposal-id>`.

Holding a rule on one machine never changes whether it passed: it stays in force for
the circle, and nobody else is told. If the same text is already installed, a passing
rule changes nothing and the copy stays yours. A repeal removes only what a vote
installed, from where it was put. A rule named `peerharness-notes` is never installed,
whoever passed it.

If a skill that a vote installed cannot be removed when it should go (after a repeal,
an opt-out, `circle leave` or a move of its scope), because its files cannot be
changed, the command says so: "rule <name> could not be removed: its files could not
be changed. It is still installed. It is tried again each time this circle is settled
on this machine (an `events import`, or a sync with one of its members)." While the
old copy of a rule whose scope you moved cannot be removed, the rule is not installed
in the new place.

After an upgrade from 0.3.0 or earlier, on a node where a vote had put a rule's text
under `peerharness-notes`: that text is removed the next time the rules are brought up
to date, and PeerHarness's own skill is not put back by itself. If `peerharness watch
claude --status` shows the reporting skill as not installed, run `peerharness setup`
once more.

### Leaving a circle

`peerharness circle leave --circle team` shows what it will do and asks. After your
yes it does two things, in this order:

1. On your machine, at once: the circle is marked as left, and the rules it installed
   for your agent are removed. This needs no key and nobody's agreement.
2. For the circle: an amendment that takes you off the roll is put to the vote, with
   your approval. You stay on the roll until the members have approved it.

What the second step will be is decided before you are asked, and the preview says
it. It is one of three:

* The request: "an amendment that removes <you> from the roll of charter <n> is put
  to the vote, with your approval."
* No request from this node, while it lacks a rule that the charter in force carries:
  a request drafted there would either drop those rules or bring back one that was
  repealed since.
* No request by this run, because one is on record already. A request is on record
  when a proposal under the charter in force is exactly the removal your node would
  ask for now: your own, or a member's `circle remove`.

The request is signed only as the preview showed it. After your yes, once your
machine has left and the key is unlocked, your node checks that the charter and the
rules in force are still what the preview was built from. If a sync or an import
changed them while you read or typed your passphrase, no request is made and nothing
is signed. The same when the device key does not unlock. The command then ends with
"Left team on this machine." and "No request to take you off the roll was made:"
followed by the reason, and exits 0. Your machine is free of the circle, and you are
still on its roll. In `--json`, `requested` is false and `reason` is one of
`missing_carried_rules`, `request_on_record`, `device_key_locked`,
`changed_while_confirming`, `proposal_refused` or `off_the_roll`. The last is for a
member the others already voted off the roll: their first run removes the circle's
rules from the machine and uses no key.

To make the request afterwards, run the same command again: with the right passphrase,
or after you imported the events file of a member who holds the rules your node lacked.
On a machine that already left, it changes nothing there: it shows the request as it
would be now and asks, and it is refused (exit 3) if your node changes again while you
answer. While your node still lacks a rule, it says again that no request was made.
If you are off the roll by then, or your request is on record, it says so and signs
nothing, and where your approval is not on that proposal it names the command that
gives it. A member whose node holds the circle's rules can also propose it for you:
`peerharness circle remove <you> --circle team`.

A proposal on record that takes you off the roll and changes anything else is not
your request: a removal that was drafted before a rule passed, for example, would
also take that rule out of force. `circle leave` names it ("Proposal <id> on record
also takes you off the roll, and changes more than that: `peerharness proposal show
<id>`."), and shows and makes a request of your own.

`peerharness circle leave --circle team --undo` follows the circle again on your
machine. Its preview says whether a request to take you off the roll is on record. A
request that was made stays on record, and leaving again makes no second one while
that request is still the one your node would make. Inside a coding agent's session
leaving is refused, the second run too.

## Take it out again

The README lists every step in order, from the installed rules to the binary:
[Take it out again](../README.md#take-it-out-again).

## Try it without touching your setup

```sh
export PEERHARNESS_HOME=$(mktemp -d) PEERHARNESS_CLAUDE_SKILLS_DIR=$(mktemp -d)
export PEERHARNESS_CLAUDE_SETTINGS=$(mktemp -d)/settings.json
peerharness init --keystore insecure-dev --insecure-dev-keystore   # plaintext key: experiments only
```

Type the last line in your own terminal: inside a coding agent's session the plaintext
keystore is refused.

`demo/two-peers.sh`, in a clone of the repository, runs two nodes as two processes
over QUIC on loopback, in a temporary folder. It refuses inside a coding agent's
session. By default it builds the checkout first, or runs the `peerharness` on your
`PATH` where there is no `cargo`. To run a binary you name, and build nothing:

```sh
PEERHARNESS_BIN="$(command -v peerharness)" demo/two-peers.sh
```
