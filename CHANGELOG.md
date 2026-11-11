# Changelog

What each version added, newest first. Versions follow
[Semantic Versioning](https://semver.org/). While the major version is 0, a minor
version may break the command line, the configuration file, the database schema or the
protocol ([docs/release.md](docs/release.md)). Each entry names the protocol version
the binary speaks ([docs/protocol-v0.md](docs/protocol-v0.md), section 15) and the
database schema it writes.

## Unreleased

* Documents only. The README is shorter: what PeerHarness does, how to set it up and
  how to use it, with a short list of limits. What it held beyond that moved without a
  change of content: the known limits to [docs/limits.md](docs/limits.md), the summary
  of what was tested, run by hand and never tried to
  [docs/checked.md](docs/checked.md), and what setup adds and stores, the words and
  the steps that take PeerHarness out again to [docs/terminal.md](docs/terminal.md).
  Release archives pack `limits.md` as well (ADR-046).
* `docs/checked.md` records the first run of a 0.4.0 release binary: the install
  script with the aarch64 macOS one.
* Documents only. The README is about what is said in Claude Code, and opens with a
  screenshot of a session in which the agent notes a rule. The commands it still
  shows stand in one section at its end, "From a terminal", with the steps that are
  done only there. One sentence under its status says that PeerHarness is also a
  command-line tool (ADR-047).
* A project page, published from `site/` to GitHub Pages: what the README says, as
  one static page that loads nothing from another origin (ADR-048).
* The project page says what it is to search engines and language models: a section
  of questions with the same answers as structured data, `llms.txt`, a sitemap, and a
  notice to IndexNow each time it is published. The repository has a description and
  topics on GitHub (ADR-049).

* Fixes after a second audit of 0.4.0, made with AI coding agents (ADR-050):
  * **A member could keep a passed rule from one node.** Whether a node kept a
    proposal depended on whether the proposal its `supersedes` named had arrived
    first, so a member who chose the order could leave one node without a rule that
    passed for everyone else. A proposal is now kept whatever it names, and a repeal
    takes a rule out of force only if it has that rule's scope, which is checked in
    the rule set and no longer on arrival. A node that had refused such a proposal
    keeps it at its next exchange. Protocol sections 8.4, 12.5 and 14.4 say so.
  * **A rule could carry a command that Claude Code runs when the skill loads.** The
    check that refuses that syntax looked at the start of a line and within one line.
    A fence in the middle of a sentence, or a command closed on the next line, passed,
    and such a rule could be kept or proposed. The syntax is now refused anywhere in
    the file, the frontmatter included. A rule that only mentions `!` in a code span
    and has another code span further down is refused too.
  * **`reset --confirm` could delete files that were not PeerHarness's.** It removed
    the whole home folder, so with `PEERHARNESS_HOME` pointed at a folder with other
    work in it, that work went too, and the check that refuses your home directory
    could be passed with another spelling of the same path. `reset` now deletes only
    what PeerHarness put there and says what stays, refuses your home directory under
    every spelling, and works when the database cannot be read.
  * **One failed request could stop a daemon without stopping its process.** A panic
    in one request ended the thread that serves the node, and the daemon went on
    listening while every later request failed. A request that panics now fails
    alone.
  * **A confirmation window could be taller than the screen.** Whether a preview
    fits was estimated from character widths, and text in a script with wide and
    high glyphs was estimated far too low, so its end could lie below the screen. The
    window now measures the text on the machine before it shows anything, and the
    step is refused when it does not fit.
  * **A member's text could add lines to another member's inbox.** A question, an
    answer's rationale and the reason of an opt-out can hold several lines, and
    `inbox`, `question list` and `rule list` printed them as they came: a question
    could end with a proposal that waits and the command that approves it. Every
    further line of such text now stands behind a mark, and who a question is from
    stands before its text.
  * **A rule could stay installed after an opt-out or a repeal.** When the database
    was busy at the wrong moment, a rule was installed without the record that a
    vote installed it, and nothing removed it afterwards. The copy and the record
    are now written together.
  * **Opting out in one team could remove a rule another team still had in force.**
    With the same rule in two teams, the copy now stays while you follow the other
    team, and the command says how to take it out there too.

## 0.4.0 (2026-11-11)

* `peerharness keep <candidate>` saves a noted rule to your library and installs it for
  your own agent in one step, after showing the exact text and where it goes. It
  shares nothing. Inside an agent's session it can be asked in a window, under a
  setting of its own (`[agent] own_windows`): run `peerharness setup` again to allow
  it. The MCP server has a tool for it, `keep_rule`. A rule with a high-risk finding
  is refused by `keep` and stays with `review` and `skills install` (ADR-040).

A check of 0.4.0 before any tag found defects, and the changes below fix some of them
(ADR-041 to ADR-045 in [docs/decisions.md](docs/decisions.md)). A review of those fixes
found more, and so did a second, a third and a fourth review. A fifth found three
things that a command did not say. After the branch was opened as a pull request, an
automated review of the pull request named more. What was changed for them is in the
same lists. Several change what a command prints, asks or accepts.

**What a voter is shown**

* A ballot on an amendment in a terminal, and `proposal show`, say what the amendment
  changes, read from its signed content and not from its title: the members admitted
  and removed with device fingerprints and scopes, each device added to or taken from
  a member who stays, the thresholds old and new, and by name the rules it would drop
  or bring back. The title follows, marked as the proposer's own words. `proposal show
  --json` has an `amendment` object. The lines `proposed roll: …` and `it also changes
  the rules of the vote`, and the warning that only counted rules, are gone (ADR-041).
* `proposal vote <id> approve` on an amendment is refused, with `--yes` too, while the
  node cannot show what the amendment would put in force or take out of force: the
  text of a rule it carries is not there, it lists a proposal the node does not hold,
  or it leaves out or keeps a rule that the charter in force carries and the node
  does not hold. Such a rule is listed in the ballot by its proposal id. Left out, it
  "goes out of force", with the words that this node cannot say which rule that is,
  and in `proposal show --json` its `skill_name` is null. Kept, it "is kept", with the
  words that this node cannot say whether that changes anything, since a rule
  repealed since would come back into force; in the JSON each entry of
  `rules_in_force.added` has `carried_by_charter_in_force`. The refusal names the
  events file of a member who holds the rule. No such ballot is put in a window.
  `reject` and `revise` are not refused.
* `circle invite`, `circle remove`, `circle amend` and `circle device add` and `remove`
  are refused on a node that lacks a rule the charter in force carries, before any
  preview: an amendment drafted there would leave the rule out. The message says to
  import the events file of a member who holds it. `circle leave` is not refused
  there: it changes your machine and makes no request to change the roll from that
  node (below).
* When an amendment lists a second proposal under the name of a rule in force, the
  ballot says which of the two would be in force afterwards: the rule "gets another
  text without a vote of its own", or the rule in force "is the later one and stays as
  it is". `proposal show --json` has `replaces` and `stays_behind` on each entry of
  `rules_in_force.added`.
* `proposal create` shows what the scanner found. A rule with a high-risk finding is
  proposed from a terminal only: inside a session it is refused, windows or not.
* `proposal vote --rationale` takes one line of at most 200 characters without control
  characters, invisible characters, blanks that are not spaces or characters the
  preview would rewrite; anything else is a usage error, which says what is checked:
  after redaction, and that the zero-width joiner of some emoji and scripts is such a
  character. `proposal show` prints what
  other members wrote (a rationale, a summary, the reason of an opt-out, the text of a
  rule) on lines of their own behind `| `, and names the proposer by member and
  device.
* `keep` shows what the scanner found in a rule, in the terminal and in its window.
  Without a finding its preview is unchanged.

**What a change to the charter signs**

* A request to change the charter is signed under the charter you were shown, or not
  at all. `circle invite`, `circle remove`, `circle amend` and `circle device add` and
  `remove` check after your answer, in a terminal or in a window, that the charter and
  the rules in force on your node are still what the preview was built from. The
  check comes after the key is unlocked, so it also covers the time you take to type
  a passphrase, and nothing asks you anything between it and the signature. If a
  sync or an import changed them meanwhile, the command is refused (exit 3): "the
  circle's charter or the rules in force changed on this node while this was being
  confirmed. Nothing was proposed and nothing was signed. Run the command again to
  see what it would do now." Before, the draft of one charter was signed as an
  amendment of the next, and undid what that one had changed.
* `proposal vote <id> approve` on an amendment reads what the amendment changes again
  after your answer, once the key is unlocked. If that is no longer what you were
  shown, nothing is signed (exit 3): "what this amendment would change is no longer
  what you were shown: the charter or the rules in force changed on this node while
  you read. Nothing was signed. Run the command again." `reject` and `revise` are not
  refused.
* `rule repeal` checks in the same place that the rule it showed is still the rule of
  that name. If a newer rule took the name meanwhile, nothing is proposed (exit 3):
  "the rule changed while this was being confirmed: what you were shown is no longer
  the rule in force. Nothing was proposed and nothing was signed. Run the command
  again to see the rule as it is now." `rule opt-out --announce` and `rule opt-in
  --announce` check it before they sign the record for the circle. What they did on
  your machine stands and is reported, and the command then ends with exit 3 and
  "nothing was announced: the rule changed while this was being confirmed, and what
  you were shown is no longer the rule in force. Run the command again to see the
  rule as it is now."
* `proposal create` and `rule repeal` are signed under the charter their preview
  counted the voters on, or not at all. The preview says "It passes with <need> of
  <n> member approval(s)". If a sync or an import stored a newer charter while you
  read or typed your passphrase, the command is refused (exit 3) with the same "the
  circle's charter or the rules in force changed on this node while this was being
  confirmed" as above, and running it again shows the count as it is now. After a
  refused `proposal create` your note and your library are as they were. Before,
  the proposal was signed under the newer charter, with an electorate and a count
  you had not been shown.
* `question send` is refused in the same case (exit 3): "the circle's charter changed
  on this node while this was being confirmed, so the members who can read the
  question may no longer be the ones you were shown. Nothing was shared and nothing
  was signed. Run the command again to see who would read it now." Its preview says
  how many members can read the question, counted on the charter it read. Before,
  the question was shared under the newer roll.
* The check after your answer and what it lets a command sign are one transaction of
  your node's database. A running daemon's sync and an import in another terminal
  cannot store anything between the two. This holds for `circle invite`, `remove`,
  `amend`, `device` and `leave`, for an approval of an amendment, for `rule repeal`,
  for `--announce`, for `proposal create` and for `question send`. Your answer and
  your passphrase are asked for before the transaction, never inside it, and what
  follows from a vote (a result, a new charter, your skills) is done after it. In
  the ordinary case nothing looks different. When a
  later step fails, less is left behind: a proposal is not stored without its
  proposer's approval, and `proposal create` leaves no library entry and no note
  marked as proposed for a proposal that was refused.
* `circle leave` changes your machine before it uses a key: the circle is marked as
  left and the rules it installed are removed, also when the device key does not
  unlock. What it does about the request to take you off the roll is decided before
  it asks, and the preview says it: the request, under the charter the preview
  names; no request from a node that lacks a rule the charter in force carries; or
  no request by this run, because one is on record already. After your yes it signs
  the request only as the preview showed it. It makes none when the key does not
  unlock, when the charter or the rules in force on your node changed while you
  confirmed, or when the proposal is refused: the command says so, with the reason,
  and exits 0, and running it again shows the request and makes it. Before, a
  request from a node that lacked a rule listed that rule by id, which brought a rule
  back into force that had been repealed since.
* A second `circle leave` on a machine that already left is no longer a usage error.
  It first tries again, with no key, to remove a rule the circle installed that the
  first run could not remove, and prints what it did ("removed rule <name>", or the
  line for a rule that still cannot be removed or for a copy you edited). Then it
  makes the request when the first run did not, after its own preview and
  confirmation. Inside a session it is refused before anything is removed. If you
  are off the roll, or your request is on record, it says so and signs nothing. It
  looks at what is on record once more after your answer and after the key is
  unlocked, as the first run does: if exactly your removal arrived meanwhile, it
  signs no second one, exits 0 and prints the report for a request on record
  (reason `request_on_record`). Before, it signed a second, identical request.
* A request is on record when a proposal under the charter in force is exactly the
  removal your node would ask for now: your own, or a member's `circle remove`. A
  first `circle leave` looks for one as well, so leaving again after `--undo` makes
  no second request. It looks once more after the key is unlocked: if exactly that
  removal arrived while you read or typed your passphrase, it signs no second one
  and ends with "No request to take you off the roll was made by this run: one is
  on record already". A proposal that takes you off the roll and changes anything
  else is not your request: `circle leave` names it ("Proposal <id> on record also
  takes you off the roll, and changes more than that"), and shows and makes your
  own.
* `circle leave --json` has `circle`, `requested` and `reason` (`null`,
  `missing_carried_rules`, `device_key_locked`, `changed_while_confirming`,
  `proposal_refused`, `off_the_roll` or `request_on_record`), also on the first run
  of a member who is already off the roll, which uses no key. With
  `request_on_record` it has the `proposal_id` and the count of the request on
  record. A second run that ends with a report has `removed_rules`,
  `not_removed_rules` and `kept_edited_rules` like the first.
* `circle leave --undo` says in its preview whether a request to take you off the
  roll is on record, and names it. It no longer says that one stays on record when
  none was made. A proposal of another member that takes you off the roll and is
  not your request is named as well ("Proposal <id> on record also takes you off
  the roll, and changes more than that"), beside your request or where the preview
  said that no request is on record.

**When your key does not unlock**

* `rule opt-out` and `proposal refuse` change your machine before any key is asked
  for. Where a vote had passed on your node without its result being signed (an
  import while the key was locked leaves that), they asked for the key first, and
  with a key that did not unlock they failed with the rule still installed. Now the
  rule is removed first. The key is asked for afterwards, and only when there is
  something to sign. If it does not unlock, the command still exits 0 and says that
  what the node could sign for the circle was not signed and is signed the next time
  the circle is settled with the key unlocked. `rule opt-in` installs what you
  confirmed in the same order. `--json` of the three has `device_key_locked`.
* `rule opt-out --announce` and `rule opt-in --announce` with a key that does not
  unlock report what they did on your machine and then end with exit 3 and "nothing
  was announced: the device key could not be unlocked, and a stance is signed with
  it. What was changed on this machine stands. Run the command again to put it on
  the record." Before, they ended with the key error and exit 1, and did not say
  what had been done.
* `proposal create` unlocks the key directly after your confirmation, before it
  saves the rule to your library and marks your note as proposed. With a key that
  does not unlock it fails as before (exit 1), and the note and the library are as
  they were. Before, `status` counted the note as proposed although nothing had been
  signed.

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
* The way out of a hold: `skills uninstall` takes out the skill that holds a rule, an
  edited copy with `--allow-modified`. It still refuses a rule that a vote installed
  and that you follow, also when that rule is held in a project by another skill.
  Where the rule's scope is placed in a project (`circle place`), the hint names
  `skills uninstall <name> --scope project` and the directory to run it in. For a
  rule that is held when you opt back in, the second step is `rule opt-in` again.
  Inside a coding agent's session the hint does not name these commands: it says
  that the choice is the owner's and to take nothing out.
* `skills uninstall` refuses a voted copy in a project as it does in your user
  directory: with `--scope project`, or without `--scope` where the project's copy is
  the only one, it is refused (exit 2) for a rule that lives in the project you run
  it in, and for a copy that a circle's vote installed there. The message names the
  circle and its opt-out. Your own skill that holds a rule in that project, and a
  copy you installed yourself of a rule that lives elsewhere, are still yours to
  take out. Before, nothing was refused in a project, and a repeal could later
  remove a skill you had installed yourself. In your user directory every copy with
  the text of a rule you follow is refused, also one you installed yourself while
  the rule lives in a project.
* `skills uninstall` refuses nothing for a circle you left on this machine (`circle
  leave`), or for a rule that does not bind you because you are not in its
  electorate. A copy of such a rule's text is yours to take out, in a project and in
  your user directory. Before, it answered with the opt-out of a circle you had
  left.
* A skill that a vote installed and that cannot be removed when it should go (its
  files cannot be changed) is no longer forgotten. The commands that print removed
  rules print "rule <name> could not be removed: its files could not be changed. It
  is still installed. It is tried again each time this circle is settled on this
  machine (an `events import`, or a sync with one of its members)." The JSON has
  `not_removed_rules` beside `removed_rules` (`circle leave`, `remove`, `amend`,
  `device`) and `not_removed` beside `removed` (`events import`, `sync`, `rule
  opt-out`, `rule opt-in`). While the old copy of a rule whose scope you moved cannot
  be removed, the rule is not installed in the new place. A second `circle leave`
  tries the removal again too. When you take such a leftover out yourself with
  `skills uninstall`, the record that a vote installed it goes with it: the same
  text installed by you afterwards is yours, and no later vote removes it. Two
  circles can each have installed a rule of one name, in two places. The report of
  a sync that removed one circle's copy and could not remove the other's now has the
  line for the one that stayed, in whichever order it came to the two. Before, the
  removal of the one took that line out of the report.
* A copy that a vote installed and that you edited is still never deleted, and is no
  longer left without a word. The commands that print removed rules say once: "rule
  <name>: the copy a vote installed was edited on this machine and was left in
  place. `peerharness skills uninstall <name> --allow-modified` takes it out." For a
  copy in a project the command it names has `--scope project` and the directory to
  run it in. Where you still follow a rule with that text and the copy is in your
  user directory, the line says that `skills uninstall` refuses it, and inside a
  coding agent's session it names no command. The JSON has `kept_edited_rules`
  beside `not_removed_rules` and `kept_edited` beside `not_removed`. The copy is
  yours from then on. `circle mode`, `circle leave --undo`, `rule opt-in` and the
  commands that propose a change to the charter print these lines too: each can be
  the first command to bring your skills in line after a vote, and an edited copy is
  named by that run or by none.
* `rule opt-out`, `proposal refuse` and `rule opt-in` say what else the same run did
  to your skills: "installed rule <name> for your agent" for a rule that passed since
  your node last settled the circle (in mode `follow`), and "removed rule <name>" for
  one that went.
* Your yes to `rule opt-in` and to `proposal adopt` counts for the rule you were shown
  and for no other rule of that name. If a newer proposal took the name while you
  read, `rule opt-in` changes nothing and leaves your opt-out in place, and `proposal
  adopt` installs nothing on that yes. Both are refused then (exit 3) and say that
  the rule changed while it was being confirmed. If the newer proposal takes the
  name only after `proposal adopt` installed the rule you confirmed, the command
  prints "Installed rule <name>, as you were shown it." and then refuses (exit 3)
  with "the rule was installed as you were shown it, and another rule of that name
  is in force since".
* A rule that is held or waits is reported once per exchange. A running daemon
  prints each hold once per run. A hold that its own exchange finds comes with the
  first report that has it, also when that exchange moved no event, and a later
  report that is printed for another reason does not repeat it. A hold that a
  peer's push created is printed when the push is settled, as a line of its own
  ("rule <name> is in force and is held on this machine: …"), with or without
  `--sync-every` and also by a daemon that never dials that peer. A one-shot `sync`
  lists every hold. `sync --json` lists a held rule once.
* A running daemon also says what else a peer's push changed for you, each as a
  line of its own: "installed rule <name> for your agent" and "removed rule <name>"
  when it happens, a copy you edited that was left in place, and on the founder's
  node "an amendment passed; issued charter <n>". A rule that the push left waiting
  for your confirmation is printed once per proposal per run, with the command that
  confirms it, and a skill that could not be removed once per name. Before, a
  daemon that only answers printed none of these. With a report of its own exchange
  a daemon lists a waiting rule every time, as before. If more than 64 such reports
  wait to be printed, further ones are dropped, and an "installed" or "removed"
  line in them is not printed: `peerharness rule list` shows what is installed.

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
  path to a file. Inside a session `circle join` itself reads no argument as a file
  when it is a peer id or an address, also when a file of that name exists. A peer
  id without `--internet` is the usage error it was (exit 2). In your own terminal
  a path that exists is still the file it names.
* `circle join <peer id or address>` inside a session is refused before it goes to
  the network when the join could not be put in a window: where the windows for the
  steps about a circle are not allowed, or the machine can show none. Before, the
  node looked the peer up and dialed it first.
* A step that needs a confirmation and finds no terminal no longer says "re-run with
  --yes". It says that the decision is the owner's and that a coding agent stops and
  asks.
* The preview that turns confirmation windows on no longer says without condition that
  your agent cannot answer a window. It says that this holds inside the agent's
  session, and that it guards against an agent that is trying to help, not against a
  process that hides that it is one. What it says the agent cannot do with the
  reporting skill is said for inside its session as well: with windows, "Inside its
  session the agent cannot approve, share, install or join anything"; without, "It
  asks your agent to write down a rule when you correct it, and to run nothing else.
  Inside its session the agent cannot approve, share or install anything." It no
  longer says that the agent can only add a note to your inbox, which no check
  enforces.
* The `vote` tool of `peerharness mcp` takes a reason of one line of at most 200
  characters, the limit of `proposal vote`.

**First-run messages**

* Removed: `circle invite --role`, `--addr` and `--ttl-hours`. They were accepted and
  did nothing. Passing one is now an error (ADR-045). The help of `circle invite
  --out` and of `circle join --name` states the real defaults.
* `--help` opens with the sentence the README opens with. `observe` and `hook` are no
  longer in its list of commands; both still run.
* `init` and `note` name the next steps the guide teaches: `demo`, `note`, `keep`. An
  `init` that fails before the node has a key takes away what it created, and puts
  back a configuration file that was there. One `init` runs for a home at a time: a
  second one is refused while the first is running. `init --help` gives the keystore
  default for macOS and Linux.
* `setup` completes a home that an interrupted `init` left (Ctrl-C at the passphrase
  prompt: a configuration file and a database without an identity). Before, it took
  the two files for a node and failed with "this home has no device identity yet".
* `setup` without confirmation windows (on Linux, or with `--no-dialogs`) ends with
  what works from the terminal, and no longer suggests prompts for the agent. For a
  node that is already there it names the keystore and warns about a plaintext one.
  `setup --json` has `agent_can_ask` and `keystore`. On a machine that cannot show a
  window, a refused tool no longer points to `peerharness setup`: it names
  [docs/terminal.md](docs/terminal.md). The install script says the same on Linux. On
  such a machine, a node whose settings allow windows is told which tools still run
  and that `peerharness setup --no-dialogs` turns them off.
* A rule that waits for your confirmation is printed the same way by every command,
  with the reason in words and the command that confirms it. `circle mode ask` no
  longer lists rules that are installed. `circle mode --json` has `waiting`.
* A circle name that is not on the node is answered with where the names are listed,
  and the error repeats no name.
* `daemon --notify` off macOS says that the daemon runs without it. `daemon --lan` on
  loopback only no longer says that it announces. A key that cannot be unlocked is
  reported once.
* `reset` also lists the registration of the tools with Claude Code, with the command
  that removes it, and the binary. Before it deletes the node it says that `skills
  uninstall` and `rule opt-out` need the node. Afterwards it lists the folders of the
  skills that are still installed, to delete by hand (`installed_skill_folders_left`
  in `reset --json`).
* The help of `proposal adopt --accept-risk` and of `proposal release --yes` says that
  each is accepted and has no effect.
* `doctor` and `status` say when the binary is a debug build, which obeys the
  stand-ins the tests use. `status --json` has `debug_build`.
* `demo/two-peers.sh` runs the binary named by `PEERHARNESS_BIN` and builds nothing
  then. Its step that reads the rule prints the text with a binary of 0.4.0, where
  `proposal show` marks each line of it, as with v0.3.0.

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
The behaviour is unchanged and is under Known limits in the README. No way back is
tested for a node that an import left on an old charter after a revocation.
`peerharness reset` is not one: it deletes the device key that is on the roll.

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
