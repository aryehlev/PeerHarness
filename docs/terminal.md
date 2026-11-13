# PeerHarness from a terminal

Everything PeerHarness does can be done from a terminal, on macOS and Linux, with any
agent or with none. The [README](../README.md) shows the way through Claude Code. This
page has the same steps as commands, and the ones that have no window.

```sh
curl -fsSL https://raw.githubusercontent.com/aryehlev/peerharness/main/install.sh | sh
```

It downloads the release binary for your machine, checks it against the release's
`SHA256SUMS` and puts it in `~/.local/bin`. No `sudo`, and nothing else is changed. To
read the script before you run it:

```sh
curl -fsSL https://raw.githubusercontent.com/aryehlev/peerharness/main/install.sh -o install.sh
less install.sh
sh install.sh
```

Or build from source, with Rust 1.89 or newer:
`cargo install --locked --git https://github.com/aryehlev/peerharness peerharness`.
That builds whatever is on `main`; add `--tag v0.4.0` to build this release.
`peerharness status` and `peerharness doctor` show where your node stands, and every
command has `--help`. A binary made with a plain `cargo build` is a debug build, for
development and tests: it obeys the stand-in programs the tests use in place of a
confirmation window, and `doctor` and `status` say that it is one.

This page says "circle" where the README says "team": it is the word the commands
use. The other words:

| Word | What it is | Who gives it to whom |
|---|---|---|
| charter, roll | The charter is the signed document every member holds: the thresholds of the vote and the roll, the list of members with their device keys | Every node holds a copy and checks it for itself |
| device key | Your node's public key (`ed25519:…`). It is not a secret | Whoever wants to join sends theirs to the member who invites them, by any channel, and reads them its fingerprint by phone or in person: `status` shows both |
| peer id | Your node's name on the network (`12D3…`), made from the same key | The member who invited sends theirs to the person joining, by any channel |
| root fingerprint | A short form of the team's root key (`8e8d-…`). It is how you know a team is the one you mean | The founder tells it to the person joining, by phone or in person, apart from the rest |

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
keeps a redacted copy of each prompt you type, on your machine only:
[what is stored and for how long](#what-setup-adds-and-what-is-stored).
The note waits in `peerharness inbox`; approving it stays yours.

With `--dialogs` your agent may ask you in a window on your screen. (The flag used to
be `--windows`, which still works; it never meant the operating system.) A window
shows the exact text and the buttons Cancel and Proceed. Only your click on Proceed
counts there: inside its session your agent cannot answer the window, and `--yes` does
not skip it there. It covers keeping a rule for yourself, proposing a rule,
your ballot on one, installing one that passed, inviting someone, your ballot on
admitting someone and joining a circle. Everything else, and any text too long to show
in full, needs your own terminal: the roll of a circle of more than about five members
does not fit a window on a laptop screen, so such a circle is joined from the terminal.
Inside an agent's session those steps are refused,
and so is `setup` itself. A rule with a high-risk scanner finding is never decided in
a window: not when it is proposed, voted on, installed or kept.

Among the steps without a window, and so refused inside a session whatever you
allowed:

* `peerharness rule opt-in`, which follows a rule again after an opt-out. Opting out
  is never refused.
* `peerharness export --local` and `peerharness events export`, which write your notes
  and a circle's records out.
* `peerharness init` with the plaintext keystore (`insecure-dev`), or with the weak
  key-file parameters of the tests (`--kdf-profile fast-insecure-test`), whether a
  flag asks for it or a `config.toml` that is already in the home. A plain `init`
  works there.
* `peerharness observe import` and `peerharness observe demo`, which store text as
  prompts you typed. Inside a session `note` is the one way to write something down.

Two things are narrower inside a session and are not refused. A circle's name, given
to `circle create` or to `circle join --name`, is one word there: letters and digits,
with `.`, `_` and `-` after the first. The name is local to your machine and later
windows show it among PeerHarness's own words; in your terminal you name a circle as
you like, and
the preview of a join shows the name before you answer. And `inbox` or `review` run
by your agent do not count as you having seen a note: the line at the end of a turn
still tells you that it waits.

A note written inside a session is labelled "reported by your agent" in your inbox,
whether or not the agent passed `--from-agent`, and at most 20 such notes wait at a
time. When a step needs your confirmation and no terminal is attached, PeerHarness
stops and says so. `--yes` is for a script you wrote yourself. A coding agent that
reads that message is told to stop and ask you.

This guards against an agent that is trying to help. It is not a sandbox: a session
is recognized by an environment variable (`CLAUDECODE`, which Claude Code sets, the
ones the [other agents](#other-coding-agents) set, or `PEERHARNESS_AGENT_SESSION`), so a process running as you that hides it can run the
same commands with `--yes`. The table under
[Known limits](limits.md) says what is stopped and what is not.

`peerharness mcp` gives an agent the same steps as tools. Without it the agent runs
the commands it read in the skill. `setup` registers it with the other agents it
connects too ([Other coding agents](#other-coding-agents)); only Claude Code was tried
with a real session. The tool that joins a circle takes a member's peer id or
address and never a file: joining from a file is `peerharness circle join <file>` in
your own terminal. Inside a session `circle join` itself reads no argument as a file
when it is a peer id or an address, also when a file of that name exists. The tool
that votes takes a reason of one line of at most 200 characters, the limit of
`proposal vote`.

### Other coding agents

After its three steps, `setup` connects every other coding agent it finds on your
machine (a directory of its own exists), each with a preview of its own. Name the ones
you want instead with `--agent`, which you can repeat:

```sh
peerharness setup --agent codex --agent pi
peerharness watch codex --install      # one agent: any id in the first column below
peerharness watch codex --status
peerharness watch codex --remove       # what PeerHarness put there goes, nothing else
```

| agent (id) | your rules | the tools | its commands are recognized by |
|---|---|---|---|
| Codex (`codex`) | copied to `~/.agents/skills` | appended to `~/.codex/config.toml` | `CODEX_CI`, `CODEX_TOOL_CALL_ID`, `CODEX_THREAD_ID` |
| opencode (`opencode`) | read from Claude Code's `~/.claude/skills` | added to `~/.config/opencode/opencode.json` | `OPENCODE`, `AI_AGENT` |
| Pi (`pi`) | copied to `~/.agents/skills` | added to `~/.pi/agent/mcp.json` | `PI_CODING_AGENT`, `AI_AGENT` |
| Antigravity (`antigravity`) | copied to `~/.gemini/config/skills` | added to `~/.gemini/config/mcp_config.json` | `ANTIGRAVITY_AGENT`, which Google does not document |
| DeepSeek Harness (`deepseek`) | copied to `~/.agents/skills` | shown for you to add to `~/.dsh/cordis.patch.yml` | `DSH_SHELL` |
| Gemini CLI (`gemini`) | copied to `~/.agents/skills` | added to `~/.gemini/settings.json`; it starts them only in a folder you trusted | `GEMINI_CLI` |
| Qwen Code (`qwen`) | copied to `~/.agents/skills` | added to `~/.qwen/settings.json` | `QWEN_CODE` |
| Copilot CLI (`copilot`) | copied to `~/.agents/skills` | added to `~/.copilot/mcp-config.json` | `COPILOT_CLI` |
| Cursor (`cursor`) | read from Claude Code's `~/.claude/skills` | added to `~/.cursor/mcp.json`; its CLI asks you to approve them once per project | `CURSOR_AGENT` |
| Amp (`amp`) | read from Claude Code's `~/.claude/skills` | added to `~/.config/amp/settings.json` | `AMP_CURRENT_THREAD_ID` |
| Droid (`droid`) | copied to `~/.agents/skills` | added to `~/.factory/mcp.json` | `FACTORY_SESSION_ID` |
| Crush (`crush`) | read from Claude Code's `~/.claude/skills` | added to `~/.config/crush/crush.json` | `CRUSH`, `AI_AGENT` |
| Kilo (`kilo`) | copied to `~/.agents/skills` | added to `~/.config/kilo/kilo.jsonc` | `KILO`, `OPENCODE` |
| goose (`goose`) | read from Claude Code's `~/.claude/skills` | shown for you to add to `~/.config/goose/config.yaml` | `AGENT_SESSION_ID`, `GOOSE_TERMINAL` |

Rules are still installed in Claude Code's skills directory, and decided there. A
connected agent that reads another directory gets copies of what PeerHarness manages
in it, PeerHarness's own skill included, brought up to date after every command. A
rule in a project goes to that project's `.agents/skills` too. A skill in those
directories that PeerHarness did not put there is never touched, and a copy you edit
is left as it is: a command that changes a rule says so. Each change to an agent's
configuration file is backed up first, and an entry named `peerharness` that you wrote
yourself is left alone. A file PeerHarness cannot read safely (one with comments or a
trailing comma, as `opencode.jsonc`, Kilo's `kilo.jsonc` or Gemini CLI's
`settings.json` may have) is not changed: `setup` shows the entry for you to add, and
`watch <agent> --status` says `file_not_editable` until you did.

When a command is refused because it runs inside an agent, the message names the
variable that said so. goose's terminal integration (`goose term init`) sets
`AGENT_SESSION_ID` in your own shell too: run PeerHarness's consent steps from a shell
without it.

What your agent may start through the tools is what you allowed with `setup`, for every
agent alike. The limits of each are in [Known limits](limits.md).

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
* **For each other agent it connects**: copies of your rules where it reads skills,
  and one entry in its configuration file, after a backup of the file
  ([Other coding agents](#other-coding-agents)).

The copies of your prompts stay on your machine and are never sent anywhere. Each
expires after 14 days by default (`[retention] observation_days` in
`~/.peerharness/config.toml`) and is deleted the next time the inbox is read. The
database is not encrypted: it relies on file permissions and on your disk's
encryption. To stop the recording, take the hooks out with `peerharness watch claude
--remove`. There is no switch for the hooks alone: that command also removes the skill
and turns the windows off.

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
# The preview names the device by its fingerprint. Bob reads her the one that
# `peerharness status` shows him, and she goes on only if they are the same: a key that
# was exchanged on its way to her would admit someone else under his name.
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
found in it. A rule with a high-risk finding is asked in your terminal only. After
your yes it unlocks your key before it saves anything: if the key does not unlock,
the command fails (exit 1), your note is not marked as proposed and nothing is saved
to your library. The preview ends with how many approvals the rule needs ("It passes
with <need> of <n> member approval(s)"), counted on the charter in force when it is
shown. The rule is proposed under that charter or not at all (below, under "A yes
counts for what you were shown").

`proposal vote` on a rule refuses an approval until the rule's text is on your node:
read it with `proposal show`. In a terminal the ballot itself shows the proposal's
title and not the text. `proposal show` prints the text, every line behind `| `, with
the number of scanner findings and whether one is high-risk. (When a coding agent
runs it in its session, the text is left out unless that rule is installed on your
machine already: a rule's text is for you to read first.) It does not print the
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
* `proposal create` and `rule repeal` stop with the first of these messages when a
  newer charter arrived. Their preview counted the voters on the charter it read,
  and a newer one can have another electorate and need another number of approvals.
  Run the command again to see the count as it is now. After a refused `proposal
  create` your note is not marked as proposed and nothing was saved to your library.
* `question send` stops with "the circle's charter changed on this node while this
  was being confirmed, so the members who can read the question may no longer be the
  ones you were shown. Nothing was shared and nothing was signed. Run the command
  again to see who would read it now." Its preview says how many members can read
  the question, counted on the charter it read.

Each of these exits 3. `circle leave` signs its request under the same check
([Leaving a circle](#leaving-a-circle)).

The look and what it lets the command sign are also one transaction of your node's
database, so a sync by a daemon you left running, or an import in another terminal,
cannot store anything between the two. Your answer and your passphrase are asked for
before that transaction and never inside it. What follows from a vote (a result, a
new charter, your skills brought in line) is done after it. This holds for every
command above, `question send` included.

`--announce` ends in the same way when your key does not unlock. What was done on
your machine is reported, and the command exits 3 with "nothing was announced: the
device key could not be unlocked, and a stance is signed with it. What was changed
on this machine stands. Run the command again to put it on the record."

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
| A repository you already share | `peerharness events sync .peerharness/team --circle team`, then commit and push | Each record is its own file, so members who add different records never touch the same file. Everyone who can read the repository can read the roll and the ballots |
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

The report gives a reason for what was refused, one line for each (`refused
(not_a_record): 3`). At most 64 MiB of records are read from one directory, and as
much again of files that have a record's name and hold none. Beyond that the command
goes on with what it read and says how many files it did NOT read: take out the files
that are no records and run it again. In a shared directory, a file that already
holds a record is left as it is, and a file with a record's name and anything else in
it is replaced by the record.

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
peerharness rule history <name> --circle team       # every version that was voted on: its text's digest, who approved it
peerharness rule opt-out <name> --circle team       # keep one rule off your machine; add --announce to put it on record
peerharness rule opt-in <name> --circle team        # follow it again: shows the rule's text and where it goes, and asks
peerharness circle mode ask --circle team           # be asked before any rule is installed; what is installed stays
peerharness proposal adopt <proposal-id>            # install a rule that waits for your confirmation
peerharness circle place repo/web --circle team --project ~/code/web   # rules of that scope go in that repository only

# The circle. Each of these is put to the vote.
peerharness rule repeal <name> --circle team        # vote a rule out
peerharness rule restore <name> --circle team --to <proposal-id>   # vote an earlier version back in
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

A revocation cannot be taken back, and a device key that no member has can be revoked
like any other. The preview says so when no member on the roll has the device, so that
a mistyped key is noticed before the yes. `circle invite` shows the scopes of the new
member beside the device (`--scope`, or `*` for all).

What a revocation does to results that had passed, and what can go wrong with an
import afterwards, is under [Known limits](limits.md).
Whether it should stay that way is an open decision (ADR-044 in
[decisions.md](decisions.md)).

`rule opt-out` is immediate and asks nobody. `rule opt-in` is the reverse step and is
yours: it shows the rule's exact text, the scanner's findings and the directory it is
installed in, and installs the rule when you confirm, also when your mode is `ask`. In
a script of your own, `--yes` skips the prompt.

An opt-out does not wait for your key either. Your machine is changed first, with no
key. Your node may then have something to sign for the circle, for example the
result of a vote that passed on it while your key was locked. Only in that case are
you asked for the key, and only after your machine has changed. If it does not
unlock, the opt-out stands, the command exits 0, and it says so: "What this node
could sign for the circle now (the result of a vote that passed, or on the founder's
node the charter that follows from one) was not signed: the device key could not be
unlocked. It is signed the next time this circle is settled with the key unlocked
(an `events import`, a sync or a ballot)." `proposal refuse` is the same step and
behaves the same. `rule opt-in` installs what you confirmed in the same order. In
`--json` the three have `device_key_locked`. Bringing your skills in line this way
can also install another rule that passed on your node, in mode `follow`, before its
result is signed. The command says so ("installed rule <name> for your agent"), as it
says "removed rule <name>" for another rule that went in the same run; `--json` lists
them under `installed` and `removed`.

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

A daemon also tells you what else a member's sync to your node changed for you,
again as lines of their own with no "Synced …" line above them:

* "installed rule <name> for your agent" and "removed rule <name>", when it happens.
  On the founder's node also "an amendment passed; issued charter <n>".
* A rule that the push left waiting for your confirmation, with the command that
  confirms it: once per proposal for as long as the daemon runs.
* A skill that could not be removed, once per name, and a copy you edited that was
  left in place (both below).

For its own exchanges nothing is different: a rule that waits is listed with every
report the daemon prints, which is every tick only when it exchanges with a member
on each tick. A daemon that both exchanges on a timer and is synced to can therefore
print a waiting rule from both. A hold that goes away and comes back while the
daemon runs is not printed a second time. At most 64 reports of pushes wait to be
printed, and one that finds no room is dropped: its "installed" or "removed" line is
not printed, while a hold or a waiting rule in it is found again at the next push.
`peerharness rule list` shows at any time what is installed, what is not and what is
held. None of this reaches `--notify`.

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
out", followed by the opt-out command. You follow a rule while it binds you (you are
on the circle's roll and your scopes cover the rule), you have not opted out of it,
and you have not left its circle on this machine. Nothing is refused for a rule of a
circle you left with `circle leave`, or for a rule that does not bind you: a copy of
its text is yours to take out. For a rule you follow, what is refused depends on the
directory:

* **In your user directory:** every copy with the text of a rule you follow. That
  includes a copy you installed yourself while the rule lives in a project (`circle
  place`). The opt-out that the refusal names takes the circle's copy out of that
  project. To take out your own copy alone, opt out, uninstall it, and opt in again.
* **In a project**, which is the directory the command runs in: a rule that lives in
  that project, and a copy that a circle's vote installed there. A copy you installed
  yourself of a rule that lives elsewhere is yours to take out.

In both, your own skill that holds a rule in that directory is yours to take out:
that is the way out of the hold.

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
in the new place. Two circles can each have installed a rule of one name, in two
places. When a sync removes one circle's copy and cannot remove the other's, it
prints the line for the one that stayed, in whichever order it came to the two. For
a circle you left, running
`circle leave` again tries too, which the line does not say. Once the files can be
changed you can also take the leftover out yourself with `skills uninstall`, unless
you still follow the rule. The record that a vote installed that copy goes with it,
so the same text installed by you afterwards is yours, and no later vote removes it.

A copy that a vote installed and that you then edited is never deleted. When it
should go it is left in place, and the command says so once: "rule <name>: the copy
a vote installed was edited on this machine and was left in place. `peerharness
skills uninstall <name> --allow-modified` takes it out." For a copy in a project the
command it names is `peerharness skills uninstall <name> --scope project
--allow-modified`, run in that directory. From then on the copy is yours: it is not
named again, and no vote removes it. Two cases name no command that takes it out:

* You moved the rule's scope from your user directory to a project and still follow
  the rule. `skills uninstall` refuses the edited copy in your user directory like
  every other copy of that text there, and the line says so: "You still follow a
  rule with this text, and while you do `peerharness skills uninstall <name> --scope
  user` refuses this copy as well and names the opt-out."
* Inside a coding agent's session the line says that the choice is yours, made in
  your own terminal, and tells the agent to take nothing out.

In `--json` the names are in `kept_edited_rules` beside `not_removed_rules` (`circle
leave`, `remove`, `amend`, `device`) and in `kept_edited` beside `not_removed`
(`events import`, `sync`, `rule opt-out`, `rule opt-in`), and `circle mode`, `circle
leave --undo` and `circle invite` have `kept_edited_rules` and `not_removed_rules`
too. Every command that brings your skills in line prints both lines, these among
them: the one run that finds an edited copy is the one that names it. The preview of
`circle leave` still says that the rules the circle installed are removed. An edited copy is
the exception, and the report names it. After `circle leave`, `rule list` shows that
rule as `held` by your edited copy and names `proposal adopt`, which is not for a
circle you left.

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

One more thing is looked at once the key is unlocked: whether exactly this removal
has arrived on record meanwhile, for example a member's `circle remove` of you that
a sync brought while you read. Your node then signs no second one. The command ends
with "Left team on this machine." and "No request to take you off the roll was made
by this run: one is on record already, under charter <n> (proposal <id>):", followed
by its count and, where your approval is not on it, "Your approval is not on it:
`peerharness proposal vote <id> approve`." It exits 0, and the reason is
`request_on_record`, with `proposal_id`, `approvals`, `need` and `passed`.

To make the request afterwards, run the same command again: with the right passphrase,
or after you imported the events file of a member who holds the rules your node lacked.
On a machine that already left, the second run begins with your machine. With no key,
it tries again to remove a rule the circle installed that the first run could not
remove, and prints what it did before anything else: "removed rule <name>", or the
line for a rule that still cannot be removed or for a copy you edited. Then it shows
the request as it would be now and asks, and it is refused (exit 3) if your node
changes again while you answer. It also looks once more at what is on record, as the
first run does: if exactly your removal arrived while you answered, it signs no
second one, exits 0 and prints the report for a request on record. While your node
still lacks a rule, it says again that no request was made. If you are off the roll
by then, or your request is on record, it says so and signs nothing, and where your
approval is not on that proposal it names the command that gives it. With a request
on record it says
"Nothing was changed and nothing was signed.", or "Nothing else was changed, and
nothing was signed." when a rule was removed. In `--json` every second run that ends
with a report has `removed_rules`, `not_removed_rules` and `kept_edited_rules`; one
that ends in an error printed its lines on standard error before that. A member whose node
holds the circle's rules can also propose your removal for you: `peerharness circle
remove <you> --circle team`.

A proposal on record that takes you off the roll and changes anything else is not
your request: a removal that was drafted before a rule passed, for example, would
also take that rule out of force. `circle leave` names it ("Proposal <id> on record
also takes you off the roll, and changes more than that: `peerharness proposal show
<id>`."), and shows and makes a request of your own.

`peerharness circle leave --circle team --undo` follows the circle again on your
machine. Its preview says whether a request to take you off the roll is on record. A
proposal of another member that takes you off the roll and is not your request is
named there too, with the line above ("Proposal <id> on record also takes you off
the roll, and changes more than that"). A request that was made stays on record, and
leaving again makes no second one while that request is still the one your node
would make. Inside a coding agent's session
leaving is refused, the second run too, before anything on the machine is changed.

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

# 3. The tools, and the other agents: their copies of your rules and their entry.
claude mcp remove peerharness --scope user
peerharness watch codex --remove                      # and so on, for each one connected

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
be undone, and ballots you already cast stay on the other members' nodes. It deletes
what PeerHarness put into its folder and nothing else: a file of yours that lies there
stays, the folder stays with it, and the report says so. It also works when the
database can no longer be read. A skill
that is still installed when you reset stays where it is, and the report lists its
folder for you to delete by hand. If you founded a team, its root key is deleted with
your node, and nobody can be admitted to that team or removed from it afterwards.

## Try it without touching your setup

```sh
export PEERHARNESS_HOME=$(mktemp -d) PEERHARNESS_CLAUDE_SKILLS_DIR=$(mktemp -d)
export PEERHARNESS_CLAUDE_SETTINGS=$(mktemp -d)/settings.json
peerharness init --keystore insecure-dev --insecure-dev-keystore   # plaintext key: experiments only
```

Type the last line in your own terminal: inside a coding agent's session the plaintext
keystore is refused. From then on every command that uses the key prints a warning
that it is stored in plaintext, and `peerharness status` says it too.

`demo/two-peers.sh`, in a clone of the repository, runs two nodes as two processes
over QUIC on loopback, in a temporary folder. It refuses inside a coding agent's
session. By default it builds the checkout first, or runs the `peerharness` on your
`PATH` where there is no `cargo`. To run a binary you name, and build nothing:

```sh
PEERHARNESS_BIN="$(command -v peerharness)" demo/two-peers.sh
```
