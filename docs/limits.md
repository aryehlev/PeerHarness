# Known limits

What PeerHarness does not do, or does not do yet. The [README](../README.md#limits)
has the short list. This is the whole of it, and the threats and what answers each
of them are in [security-model.md](security-model.md). How each part was checked,
and what was never tried, is in [checked.md](checked.md).

**The agent guard is not a wall.** Consent steps recognize an agent's session by an
environment variable: the one Claude Code sets, the ones Codex, opencode, Pi and
DeepSeek Harness set ([terminal.md](terminal.md#other-coding-agents)), or
`PEERHARNESS_AGENT_SESSION` for another agent's wrapper. An agent whose shell sets neither is refused only where a
step finds no terminal, with a message that tells it to stop and ask you, and nothing
keeps it from passing `--yes`.

| Who starts the step | What happens |
|---|---|
| An agent that behaves | It can note a rule and, where you allowed it, open a window. It cannot answer the window, and `--yes` is ignored in its session |
| An agent that was misled, by a page it read for example, and stays within its tools | The same. It chooses when a window appears and what it asks, so reading the window before you click is your part |
| A process that sets out to get around it | Not stopped. Anything running as you that hides the variable can run the same commands with `--yes`, edit the installed rules and the database, or use a key that unlocks without you |

The same holds for what looks like your own prompt. Claude Code hands each prompt to
PeerHarness through a hook that runs inside the session, and a process there that
calls the hook with a text it made up is taken for it: a note that is made from such
prompts carries the label of your own, not "reported by your agent". It is still only
a line in your inbox, and nothing is kept, installed or shared without your yes.

Founding a team, exchanging with its members and keeping your node reachable are not
decisions in this sense. Once you allowed the steps about a team, your agent does them
when you ask, without a window. The longer account is section 4.17 of
[docs/security-model.md](security-model.md#417-llm-generated-decisions-and-the-agent-acting-for-its-user).

The other limits:

* **The agents besides Claude Code were connected from their documentation and
  source, not tried in a real session** (ADR-050). In particular:
  * Google Antigravity documents no variable that marks the commands its agent runs.
    PeerHarness checks `ANTIGRAVITY_AGENT`, which its program (1.5.6) contains as
    `ANTIGRAVITY_AGENT=1` and other tools check, but this was not seen in a session: a
    command Antigravity runs may carry no mark and look like one you typed. Its tools
    are marked in every case.
  * Codex and Antigravity run their agent's shell in a sandbox by default, which may
    keep `peerharness note` from writing to `~/.peerharness`. Their MCP servers run
    outside it, so the `note` tool works.
  * opencode reads both `~/.claude/skills` and `~/.agents/skills`. With Codex, Pi or
    DeepSeek Harness connected too, it finds two identical copies of each rule; its
    second major version keeps one, its first keeps the later and warns.
  * Pi reads a project's skills only after its user trusted the project.
  * DeepSeek Harness's tools entry is shown for you to add: PeerHarness does not edit
    its YAML patches.
  * The hooks, and the notice at the end of a turn, are Claude Code's alone.

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
  decision ([ADR-044](decisions.md)).
* **After a revocation, an import can leave a member on the old charter**, and
  importing again does not help. It was seen with a file and with a shared directory.
  No way out has been tested. `peerharness reset` is not one: it deletes the node's
  device key, and a new key has to be voted onto the roll (`peerharness circle device
  add`), which may not reach its threshold once a device is revoked. What was tried
  by hand is in [ADR-044](decisions.md), and the mechanism in section 4.16 of
  the [security model](security-model.md#416-root-key-holder-and-circle-administrator).
* **An event its author signed twice can conflict once in a shared git directory.**
  An event's id does not cover its signature. If two members each add the same
  event, signed a second time by its author, before either pulled, git reports one
  conflict on that file. Either copy settles it, and no sync rewrites it afterwards
  ([ADR-051](decisions.md)).
* **The roll changes by simple majority**, so a majority can shrink the roll and then
  change the rules of the vote alone
  ([security model, 4.20](security-model.md#420-governance-by-vote)).
* **An amendment carries the rule set of the moment it was proposed.** If a rule
  passes or is repealed while the amendment is open, approving it undoes that. The
  ballot names each such rule, and nothing stops the vote
  ([security model, 4.29](security-model.md#429-what-a-voter-is-shown-before-a-ballot)).
* **A node that lacks a rule the charter carries can neither approve nor draft a
  change to the charter.** A join from an incomplete file leaves a node so, and so
  does every sync for a member whose scopes do not cover the rule. Its owner can
  still leave on their own machine, and the request to be taken off the roll is not
  made from that node. The way out is to import the events file of a member who holds
  the rule ([What a ballot shows](terminal.md#what-a-ballot-shows)). That file
  holds every scope's records, the rule's text included. For a member whose scopes do
  not cover the rule this gives them what the scope withholds, and it is needed again
  after each change to the charter that carries a new such rule.
* **A rule can be in force and not on your machine.** A team rule whose name a skill
  that PeerHarness installed on your machine already has, with another text, is held
  there. It stays in force for the team, and nobody else is told. `peerharness rule
  list` shows it
  ([A rule that is held](terminal.md#more-commands),
  [security model, 4.30](security-model.md#430-a-passed-rule-and-the-skills-already-on-a-machine)).
  One case is not covered: a rule you keep after a vote already installed the
  identical text still counts as the vote's, so a repeal removes it.
* **One rule per name, across scopes.** A rule adopted in a narrower scope replaces a
  team-wide rule of the same name for everyone, although only that scope's members
  voted. A team in which every member has the default scope is not affected
  ([security model, 4.20](security-model.md#420-governance-by-vote)).
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
* **A rule that an earlier version installed is not checked again.** Since ADR-051
  the syntax that makes Claude Code run a command when a skill loads is refused
  anywhere in a rule. Nothing reads the skills that are already installed, so a rule
  that 0.4.0 or an earlier version let through stays where it is until you take it
  out (`peerharness skills uninstall <name>`, or `peerharness rule opt-out` for a
  team's rule).
* **What other members wrote reaches your agent when it reads the inbox or a
  proposal.** A title, a proposer's summary, a question and the reason a member gave
  for a ballot or an opt-out are their words. A session that runs `inbox` or `proposal
  show` reads them, each behind a mark, and for a rule that came from a note the
  title is the rule's sentence. Only the text of a rule that is not installed on your
  machine is left out there ([security model, 4.17](security-model.md#417-llm-generated-decisions-and-the-agent-acting-for-its-user)).
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
  [What setup adds, and what is stored](terminal.md#what-setup-adds-and-what-is-stored).
* **A key file keeps the parameters it was written with.** A key written with the
  weak profile of the tests (`--kdf-profile fast-insecure-test`) stays weak when the
  profile is taken out of `config.toml`, and the warning, which reads that file, stops.
  Nothing encrypts a key file again.
* **A question that was held back is not shown later.** At most 20 questions of one
  member and 100 of a team are shown within 24 hours. One that arrived beyond that,
  or from a member you muted, stays out of the inbox when there is room again.
* **A node is reachable only while a daemon runs.** That is one you start yourself, or
  the one your agent runs while its session is open. There is no background service
  yet: a sync reaches only the members whose daemon is running at that moment.
* **Confirmation windows are macOS only**, and need a key in the OS keychain (the
  default there). On Linux every decision needs your own terminal: of the tools your
  agent is given, only the one that notes a rule runs there, and every other one
  answers that the step is yours. The exception is a node whose settings allow
  windows, a home copied from a Mac for example: there the tools that need no window
  still run ([Without windows](terminal.md#without-windows)).
* **Internet mode identifies your device to strangers.** Servers run by volunteers see
  the same public key with your IP address wherever you connect. Whether two nodes
  get a direct connection depends on their routers.
