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
command has `--help`.

This page says "circle" where the README says "team": it is the word the commands
use. The README has the other words under [Words](../README.md#words).

## A rule of your own

A rule of your own needs no circle and no network.

```sh
peerharness init

# Write a rule down in one sentence. It becomes a candidate in your inbox.
peerharness note "Use pnpm, not npm, in this repository."

# Keep it: it shows the exact skill text, asks once, and installs it for Claude Code
# (~/.claude/skills/<name>/SKILL.md). Reversible with `skills uninstall`.
peerharness keep <candidate-id>
```

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
counts there: nothing the session writes, passes or sets answers the window, and
`--yes` does not skip it. It covers keeping a rule for yourself, proposing a rule,
your ballot on one, installing one that passed, inviting someone, your ballot on
admitting someone and joining a circle. Everything else, and any text too long to show
in full, needs your own terminal. Inside an agent's session those steps are refused,
and so is `setup` itself.

This guards against an agent that is trying to help. It is not a sandbox: a session
is recognized by an environment variable (`CLAUDECODE`, which Claude Code sets, or
`PEERHARNESS_AGENT_SESSION`), so a process running as you that hides it can run the
same commands with `--yes`. The table at the top of the [README](../README.md) says
what is stopped and what is not.

`peerharness mcp` gives an agent the same steps as tools. Without it the agent runs
the commands it read in the skill. Other agents that speak MCP can use it too; only
Claude Code was tried.

## A team

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
takes that one. A rule needs the approval of more than half of the members: of two,
both; of three, two. Admitting or removing someone is a vote of the current members
with the same threshold, from the second member on.

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

## More commands

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

# Not voted on: the founder cuts off a lost or stolen device. Its ballots stop counting,
# the ones it already cast included, so a result that needed one of them is open again.
peerharness circle revoke <member or device key> --circle team
```

What a revocation does to results that had passed, and what can go wrong with an
import afterwards, is under [Known limits](../README.md#known-limits) in the README.

## Take it out again

The README lists every step in order, from the installed rules to the binary:
[Take it out again](../README.md#take-it-out-again).

## Try it without touching your setup

```sh
export PEERHARNESS_HOME=$(mktemp -d) PEERHARNESS_CLAUDE_SKILLS_DIR=$(mktemp -d)
export PEERHARNESS_CLAUDE_SETTINGS=$(mktemp -d)/settings.json
peerharness init --keystore insecure-dev --insecure-dev-keystore   # plaintext key: experiments only
```
