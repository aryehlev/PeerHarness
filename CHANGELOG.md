# Changelog

What each version added, newest first. Versions follow
[Semantic Versioning](https://semver.org/). While the major version is 0, a minor
version may break the command line, the configuration file, the database schema or the
protocol ([docs/release.md](docs/release.md)). Each entry names the protocol version
the binary speaks ([docs/protocol-v0.md](docs/protocol-v0.md), section 15) and the
database schema it writes.

## Unreleased (0.4.0)

`main` carries version 0.4.0. It is not tagged.

* `peerharness keep <candidate>` saves a noted rule to your library and installs it for
  your own agent in one step, after showing the exact text and where it goes. It
  shares nothing. Inside an agent's session it can be asked in a window, under a
  setting of its own (`[agent] own_windows`): run `peerharness setup` again to allow
  it. The MCP server has a tool for it, `keep_rule`. A rule with a high-risk finding
  is refused by `keep` and stays with `review` and `skills install` (ADR-040).

A check of 0.4.0 before any tag found defects, and the changes below fix some of them
(ADR-041 to ADR-045 in [docs/decisions.md](docs/decisions.md)). Several change what a
command prints, asks or accepts.

**What a voter is shown**

* A ballot on an amendment in a terminal, and `proposal show`, say what the amendment
  changes, read from its signed content and not from its title: the members admitted
  and removed with device fingerprints and scopes, each device added to or taken from
  a member who stays, the thresholds old and new, and by name the rules it would drop
  or bring back. The title follows, marked as the proposer's own words. `proposal show
  --json` has an `amendment` object. The lines `proposed roll: …` and `it also changes
  the rules of the vote`, and the warning that only counted rules, are gone (ADR-041).
* `proposal vote <id> approve` on an amendment is refused, with `--yes` too, while the
  node cannot show what the amendment would put in force: the text of a rule it
  carries is not there, or it lists a proposal the node does not hold. `reject` and
  `revise` are not refused.
* `proposal create` shows what the scanner found. A rule with a high-risk finding is
  proposed from a terminal only: inside a session it is refused, windows or not.
* `proposal vote --rationale` takes one line of at most 200 characters without control
  characters; anything else is a usage error. `proposal show` prints what other
  members wrote (a rationale, a summary, the reason of an opt-out) on lines of their
  own behind `| `, and names the proposer by member and device.

**What a vote may do to your own skills**

* A rule that passed is no longer installed over a skill of the same name that no
  vote of that circle installed. The rule is held on that machine and nothing is
  written. `rule list` shows it as `held` with the two ways out, and the commands that
  bring rules up to date print the same. A repeal no longer deletes such a skill
  (ADR-042).
* The name `peerharness-notes` is reserved for PeerHarness's own skill. `note`,
  `review`, `keep` and `proposal create` refuse it, and a rule of that name that a
  circle passes is never installed. On a node where an earlier version let a vote put
  a rule under that name, the rule's text is removed; run `peerharness setup` once
  more to put PeerHarness's own skill back.
* `rule list --json` has `held` for each rule, and `events import --json` and `sync
  --json` have a `held` list.

**What runs inside a session**

* `rule opt-in` asks before it acts. It shows the rule's exact text, the scanner's
  findings and where the rule is installed, and installs it when you confirm, in mode
  `ask` too. Inside a coding agent's session it is refused, and it has no window and
  no tool. `--yes` skips the prompt and no longer needs `--announce`. `rule opt-out` is
  unchanged: immediate, and never refused.
* `export --local` is refused inside a session, to a file and on standard output.
* `init` with the plaintext keystore (`insecure-dev`) is refused inside a session. A
  plain `init` still works there.
* A note written inside a session is recorded as reported by the agent, with or
  without `--from-agent`, and counts against the 20 notes that may wait.
* The `join_circle` tool of `peerharness mcp` takes a peer id or an address, never a
  path to a file.
* A step that needs a confirmation and finds no terminal no longer says "re-run with
  --yes". It says that the decision is the owner's and that a coding agent stops and
  asks.

**First-run messages**

* Removed: `circle invite --role`, `--addr` and `--ttl-hours`. They were accepted and
  did nothing. Passing one is now an error (ADR-045). The help of `circle invite
  --out` and of `circle join --name` states the real defaults.
* `--help` opens with the sentence the README opens with. `observe` and `hook` are no
  longer in its list of commands; both still run.
* `init` and `note` name the next steps the guide teaches: `demo`, `note`, `keep`. An
  `init` that fails before the node has a key takes away what it created.
* `setup` without confirmation windows (on Linux, or with `--no-dialogs`) ends with
  what works from the terminal, and no longer suggests prompts for the agent. For a
  node that is already there it names the keystore and warns about a plaintext one.
  `setup --json` has `agent_can_ask` and `keystore`. On a machine that cannot show a
  window, a refused tool no longer points to `peerharness setup`: it names
  [docs/terminal.md](docs/terminal.md). The install script says the same on Linux.
* A rule that waits for your confirmation is printed the same way by every command,
  with the reason in words and the command that confirms it. `circle mode ask` no
  longer lists rules that are installed. `circle mode --json` has `waiting`.
* A circle name that is not on the node is answered with where the names are listed,
  and the error repeats no name.
* `daemon --notify` off macOS says that the daemon runs without it. `daemon --lan` on
  loopback only no longer says that it announces. A key that cannot be unlocked is
  reported once.
* `reset` also lists the registration of the tools with Claude Code, with the command
  that removes it, and the binary.
* `doctor` and `status` say when the binary is a debug build, which obeys the
  stand-ins the tests use. `status --json` has `debug_build`.
* `demo/two-peers.sh` runs the binary named by `PEERHARNESS_BIN` and builds nothing
  then.

**Parsing**

* A line of an imported file and a record file of a directory are parsed as strictly
  as a frame from the network: at most 1 MiB, no member twice, nothing but the one
  member a record has. A line that breaks one of these used to be imported when the
  event in it verified. Now it is counted as refused, and the other lines are still
  imported (ADR-043).
* `circle join <file or directory>` looks only at the circle whose root fingerprint
  you pass with `--expect-fingerprint`. When the source holds charters of several
  circles that list your device and you pass none, it stops and asks for it.
* The scanner has two more high-risk rules: a text that tells the agent to fetch a URL
  and follow what it finds there, and a text that gives an instruction about
  PeerHarness's own guard. A rule with such a finding is decided in a terminal.

Not decided: what a revocation does to ballots that were already counted (ADR-044).
The behaviour is unchanged and is under Known limits in the README.

Protocol `0.1` and database schema 4, as in 0.3.0.

## 0.3.0 (2026-11-10)

* `peerharness setup` does the owner's part in one command: it creates the node,
  connects Claude Code and registers the tools, each step shown first and confirmed.
  It is refused inside an agent's session (ADR-039).
* The flag of `watch claude --install` that allows confirmation windows is `--dialogs`.
  `--windows` still works.
* The install script names `peerharness setup` as the next step.

Protocol `0.1` and database schema 4, as in 0.2.0.

## 0.2.0 (2026-11-10)

* Inviting someone, a ballot on an admission and joining a circle can be asked in a
  window on macOS, under a setting of their own (`[agent] circle_windows`) (ADR-037).
* `peerharness mcp` gives an agent the steps it may start as tools of an MCP server.
  Every tool runs the command as a child process marked as an agent's session, so it
  adds no way to consent (ADR-038).
* `demo` no longer says that the QUIC transport is not wired into the command line.

Protocol `0.1` and database schema 4, as in 0.1.0.

## 0.1.0 (2026-11-10)

The first release.

* Voting under a signed charter: thresholds, a roll of members, proposals, ballots
  counted per member, results, amendments and repeal (ADR-012 to ADR-016).
* One person's loop: `note`, `review`, `skills install`, `uninstall` and `rollback`,
  and the Claude Code hooks and reporting skill (`watch claude`).
* A circle's life: `circle create`, `invite`, `join`, `remove`, `leave`, `amend`,
  `device`, `mode`, `place` and `revoke`, questions and answers, and opt-outs that can
  be put on record.
* Exchange of signed records by file, by shared directory (`events`), and directly
  over QUIC (`daemon`, `sync`, `connect`), with discovery on the local network
  (`--lan`) and by device key across the internet (`--internet`), both off unless
  asked for (ADR-031, ADR-032).
* Confirmation windows on macOS for three decisions about rules, started from inside
  an agent's session and answered only by a click (ADR-033).
* Being told that a vote waits: a line at the end of a turn in Claude Code, and
  `daemon --notify` on macOS (ADR-035, ADR-036).
* `install.sh`, which installs a release after checking it against `SHA256SUMS`
  (ADR-034), and `peerharness demo`.

Protocol `0.1` (wire protocol `/peerharness/req/0.1.0`, schemas `*/0.1`). Database
schema 4. The schema's migrations only go forward.
