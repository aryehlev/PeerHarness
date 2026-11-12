# What was checked, and how

This page says how each part of PeerHarness was checked. It has the summary, then
the table that says, part by part, what a test covers, what was run by
hand and what was never tried, then what followed the pre-launch check and the runs
of the whole suite, and at its end the second audit.

*Tested* means an automated test covers it. *By hand* means a run during development
that [decisions.md](decisions.md), the README's history, the pre-launch check or
the second audit records, on the version named. *Not tried* means no run is recorded.

The pre-launch check is a check of the 0.4.0 tree as it was before the fixes, made
with AI coding agents on 2026-11-10, which [decisions.md](decisions.md) calls the
launch audit. Its report is not in the repository. What this page and the ADRs say it ran is
all that is published of it.

The second audit is a later check, of 0.4.0 as it was released, made with AI coding
agents on 2026-11-11 ([ADR-051](decisions.md)). What it ran, and what was run again
after its fixes, is in [the last section](#the-second-audit).

## In short

* **Tested.** Voting, one person's loop, a circle's life and the exchange over QUIC,
  by shared directory and by file: the tests with several nodes run them as separate
  processes. What a ballot shows, that a change to the charter is signed only as it
  was shown, what a vote may do to your own skills and what a session is refused.
  Setup, the tools, the windows, the notification, internet mode and the install
  script, each against a stand-in: for Claude Code's `claude` command, for an MCP
  client, for the window, for the notification, for the public network and for a
  release. Connecting each of the fourteen other coding agents, against throwaway
  homes.
* **By hand.** The real window on macOS 14.2, before v0.1.0: it opened, closed
  unanswered and refused a text that does not fit. Internet mode on the real network,
  before v0.1.0, from one machine with both ends behind the same router. The tools
  with Claude Code 2.1.322 on macOS, before v0.2.0, in three runs. The real
  notification on macOS, once. `--lan` worked on macOS when it was built, before
  v0.1.0; no run of its tests is recorded. The real Codex 0.167.1, opencode 1.1.50, Pi 1.5.2,
  Antigravity 1.5.6 and DeepSeek Harness 0.2.2-rc.1 reading what PeerHarness wrote
  for them, on 2026-11-12, without a model. The install script with the v0.3.0 x86_64
  Linux binary, in a container. The install script with the v0.4.0 aarch64 macOS
  binary, on macOS 14.2 on 2026-11-11, after the release was published. On Linux,
  with a debug build of this tree, on a pseudo-terminal: when the records of a rule
  that passed arrive on a node while its owner answers a prompt or types a
  passphrase, nothing is signed for a change to the charter, an approval of one, a
  repeal or an announced opt-out. On macOS 14.2 (arm64), with debug builds of 0.4.0
  and of this tree and a stand-in window: the scripts with which the second audit
  showed each fault, run again after the fix
  ([the last section](#the-second-audit)).
* **Not tried.** Clicking the buttons of the real window. The setup prompt of the
  README through an agent. A real agent noting, keeping, proposing, voting or joining.
  Internet mode between two different routers, over IPv6 or on Linux. `--lan` on
  Linux. The aarch64 Linux binary. The x86_64 macOS binary since v0.2.0. Of the
  release binaries of 0.4.0, the three that are not the aarch64 macOS one. A session
  of any other coding agent with a real model. Amp at all. A real window
  for a text that the measure of ADR-051 lets through or refuses. `reset` on a node
  whose keys are in the OS keychain. Windows is not supported.

## Part by part

Where each threat of the security model is tested, test by test, is in the last
section of [security-model.md](security-model.md#test-coverage).

| Part | How it was checked |
|---|---|
| Voting: charter, roll, proposals, ballots, results, amendments, repeal | tested. A `proposal create` whose key does not unlock leaves the note and the library as they were, and nothing is proposed (`a_proposal_that_could_not_be_signed_leaves_its_candidate_as_it_was`). A rule is proposed under the charter its preview counted the voters on, or not at all: a stand-in window imports a newer charter before it answers Proceed, and nothing is proposed or saved (`a_rule_is_not_proposed_under_a_charter_that_arrived_while_its_proposer_read`, debug builds on unix). The same for a repeal has a unit test only (`a_rule_and_a_repeal_are_signed_only_under_the_charter_that_was_shown`). By hand for `proposal create`, `rule repeal` and `question send` at a terminal prompt: see the row about a ballot on an amendment |
| One person's loop: `note`, `keep`, `review`, `skills install` and `uninstall` | tested |
| Creating a node (`init`) | tested: a second `init` for the same home is refused while one runs, and one that fails leaves the home as it found it, a configuration file that was there included. Until CI ran the suite for pull request #7 on Linux and macOS (below), these tests had been run on Linux only. By hand on Linux, on a pseudo-terminal: the first `init` waiting at its passphrase prompt, the second refused, the first then failing and leaving nothing. Not tried: macOS, where the keychain asks in place of the prompt, and a file system without locks. Two limits are known, and the code was not changed for them ([ADR-045](decisions.md)): a configuration file that is a link is replaced by a regular file, and two inits that race and both fail can leave an empty home directory |
| Circle life: create, invite, join, remove, leave, amend, devices, revoke, questions, opt-outs | tested, with separate nodes. Leaving: with a passphrase that does not unlock the key, the circle's rule is removed from the machine and nothing is signed; a second run makes the request; a request that is on record, the member's own or another member's removal of them, is not made a second time, by a first run after `--undo` either (`leaving_again_after_an_undo_makes_no_second_request`, `a_first_leave_names_a_members_removal_that_is_on_record_and_signs_nothing`); a removal on record that would also drop a rule is named as another proposal, and the member's own request is made (`a_removal_that_would_also_drop_a_rule_is_not_reported_as_the_request_to_leave`); a member who was voted off the roll leaves with no key used and gets the same report (`leaving_when_already_off_the_roll_reports_like_every_other_leave`). That a first run signs the request it previewed or none has unit tests only (`a_first_leave_decides_about_its_request_before_it_asks`, `a_leave_request_is_signed_only_as_it_was_previewed`), and so has that it makes no second request when a member's removal of the leaver arrives while they are asked (`a_request_that_arrived_while_the_owner_was_asked_is_not_made_a_second_time`), and that a second run makes none either (`a_second_leave_makes_no_second_request_when_the_same_one_arrived_meanwhile`); by hand, see the next row. The preview of `circle leave --undo` names another member's proposal that takes the owner off the roll and is not their request: a unit test of the whole preview (`undoing_a_leave_names_another_members_proposal_that_takes_the_owner_off_the_roll`), and by hand through the binary on Linux, where the command printed the preview and, with no terminal, was refused. A second run of `circle leave` first removes a rule the first run could not remove, also with a passphrase that unlocks nothing, and inside a session it is refused with the rule still there (`leaving_names_what_it_left_in_place_and_a_second_run_tries_again`). Opt-outs: with a passphrase that unlocks nothing, on a node where a vote passed without its result, `rule opt-out` and `proposal refuse` remove the rule, `rule opt-in` installs what was confirmed, and nothing is signed (`an_opt_out_changes_the_machine_before_any_key_is_asked_for`); `--announce` with such a key reports what was done on the machine and is refused (`an_announcement_that_cannot_be_signed_says_what_was_done_on_the_machine`). No test for: `circle leave` from a revoked device, which previews a request it cannot make (by hand in the fourth review; not changed), and a founder's root key that fails after the device key unlocked (not tried) |
| What you are shown before a ballot on an amendment, in a terminal | tested, with separate nodes and stock commands: a device proposed for another member, new thresholds, an admission that would drop or bring back a rule, and an approval refused until the text of a carried rule is on the node. A node that joined without a rule the charter carries: the approval of an amendment that leaves the rule out is refused, and so is the approval of an honest one that keeps it; no window opens for either (`an_amendment_that_drops_an_unheld_rule_is_never_a_ballot_for_a_window`, which runs both, debug builds on unix); the node drafts no amendment of its own, and its `circle leave` changes the machine and makes no request, so that a rule repealed since is not brought back. The amendment that leaves the rule out is signed with a member's key, as a modified client signs it. A yes signs what was shown: a stand-in window imports a newer charter, or a rule that passed, before it answers Proceed, and neither the request to admit nor the approval is signed (debug builds on unix). No test for: the same at a prompt in a terminal or at a passphrase prompt while a second process changes the node. The suite has no pseudo-terminal; that the check comes after the key is unlocked has unit tests only (`a_draft_is_put_to_the_vote_only_while_the_node_would_still_draft_it`, `a_repeal_and_a_stance_are_signed_only_for_the_rule_that_was_shown`). By hand on 2026-11-11, on Linux, with a debug build, on a pseudo-terminal, with the key in an encrypted file and an `events import` from a second process while the prompt waited: a rule arriving at the y/N prompt and at the passphrase prompt of `circle remove`, `amend`, `device add`, `invite` and `proposal vote <admission> approve`, a newer charter at the passphrase prompt of `circle remove`, a second `circle leave`, `rule repeal`, and `rule opt-out --announce` each ended with exit 3 and nothing signed; a first `circle leave` left the machine, made no request and signed nothing, also on a node that lacked a carried rule whose records arrived at the prompt. The third review had run the same at the passphrase prompt before that fix, where an amendment and a deciding approval were signed ([ADR-041](decisions.md), "After a third review"). The fourth review ran these cases again and nothing was signed. After its fixes, again by hand on a pseudo-terminal on Linux: `rule opt-out` with no passphrase in the environment had removed the rule while the passphrase prompt still waited, and it stayed removed after Ctrl-C; a first `circle leave` with a member's exact removal of the leaver imported at the y/N prompt, and at the passphrase prompt, made no second request. By hand in the fourth review: a charter that admits a member, imported at the prompt of `proposal create`, `rule repeal` and `question send`, left the count in the preview (approvals needed, members who can read) one charter behind what was then signed, with the text as shown ([ADR-041](decisions.md), "After a fourth review"). That was changed after an automated review of the pull request named it too ([ADR-041](decisions.md), "After a review of the pull request"). After the change, by hand on a pseudo-terminal on Linux, with the newer charter imported at the y/N prompt: each of the three was refused with exit 3 and nothing was signed; after `proposal create` the note, the library and the bundle files were as before, and after `question send` the note was as before; run again, each showed the count of the newer charter and went through. The agents that reviewed the change ran the same at the passphrase prompt, with the same result, and `question send` once more after it was moved into the transaction. A second `circle leave` with a member's exact removal of the leaver imported at its y/N prompt signed nothing and printed the report for a request on record. A check after the yes and the signatures it allows are one transaction of the store since that review: a unit test with a second connection to the same file, which cannot store a ballot between the check and the signatures and can after the commit (`nobody_else_writes_between_a_check_and_the_signatures_it_allows`), and one for what an error leaves (`an_error_after_a_proposal_was_stored_leaves_no_proposal`). By hand on Linux, with a daemon running on each of three homes over QUIC on loopback: `circle invite`, `proposal vote` and both runs of `circle leave`, and ten more invitations and ballots while a third node pushed new proposals to the two daemons in a loop; fourteen commands, none failed and none reported a busy database. By hand in the review of that change: 220 commands with daemons on every home, a peer that pushed in a loop and three terminals on one home, none failed and none met a locked database (one `proposal create` failed in a run before those, with its output discarded and the cause not recorded); and an `events import` of a successor charter raced against commands run with `--yes`, 200 times, where every proposal that was signed names the charter whose count its preview printed. Not tried: macOS, where the keychain may ask in place of the passphrase prompt. The two amendments the pre-launch check crafted by hand, and an amendment that lists a second proposal under the name of a rule in force, are unit tests with hand-signed events |
| A vote and the skills you already have | tested, with three separate nodes: a rule named like PeerHarness's own skill, signed the way a modified client can, is never installed, and a rule kept with `keep` is neither replaced nor removed by a vote on its name. A yes counts for the rule that was shown: a stand-in window imports a newer rule of the same name before it answers Proceed, and nothing is installed. `proposal adopt` is refused then. The way out of a hold is followed step by step in two states. With a rule held in a project, the copy a vote installed for every project cannot be taken out with `skills uninstall`, as the person or in a session. In a project, a copy a vote installed there is refused in the same way, with and without `--scope`, while a copy the owner installed in another project is theirs to remove (`a_voted_copy_in_a_project_is_not_taken_out_by_skills_uninstall`); and where the skill that holds a rule in a project is another circle's voted rule, the command the hold names is refused and names that circle, whose opt-out then lets the held rule be adopted (`the_way_out_of_a_hold_does_not_take_out_another_circles_rule_unasked`). A skill that cannot be removed keeps its record, is reported and is tried again: a unit test (`a_skill_that_cannot_be_removed_stays_on_record_and_is_tried_again`, unix), and through the binary for a copy in a project, whose skills directory the test turns into a link that leads out of the project (`leaving_names_what_it_left_in_place_and_a_second_run_tries_again`); by hand on Linux with a file made unchangeable (`chattr +i`) while its owner left the circle. When the owner takes such a leftover out with `skills uninstall`, the vote's record goes with it, and the same text installed by the owner afterwards survives the next import, after a repeal and after an opt-out (`a_record_of_a_vote_goes_with_the_copy_its_owner_takes_out`). `skills uninstall` refuses a copy of a rule its owner follows, and not one of a rule that no longer binds them: a member voted off the roll, and a member who left, in a project and in the user's directory (`a_copy_of_a_rule_that_no_longer_binds_its_owner_is_theirs_to_take_out`). A voted copy that its owner edited is left in place and named, in the user's directory and in a project, and the command the line names takes it out (`leaving_names_what_it_left_in_place_and_a_second_run_tries_again`), also where `circle mode` or `rule opt-in` is the first command to settle after the repeal, and a `rule opt-out` names another rule it installs (`a_command_that_settles_says_what_it_did_to_other_rules`); an opt-out, a repeal, a moved scope and the wording inside a session are a unit test (`a_voted_copy_that_was_edited_is_left_in_place_and_named_once`), and were run by hand through the binary. No test for: the same race at the prompt of `rule opt-in`, which needs a terminal and a second process (a unit test covers where the confirmation is counted), a hold caused by another circle's rule in the user's skills directory, and the refusal in the user's directory of a copy the owner installed themselves while the rule lives in a project (by hand in the fourth review; not changed). The first two were run by hand in the second review, on Linux with a debug build: at a real prompt on a pseudo-terminal, a newer rule of the same name and a repeal each gave the refusal and left the opt-out in place; and the way out of a hold caused by another circle's rule was followed through the binary. Not reproduced: a rule that takes the name while `proposal adopt` applies the rules; a unit test covers which sentence it then says |
| What a session is refused beyond the windows: `rule opt-in`, `export --local`, a plaintext `init`, a file path given to the join tool, a join that cannot be put in a window | tested, the first three with each of the two session variables. Inside a session `circle join` reads no argument as a file when it reads as a peer id, also when a file of that name exists and holds a real invitation: tested with each of the two session variables, and in the person's terminal the same argument joins from the file (`inside_a_session_a_peer_id_is_never_read_as_a_file`). An argument that reads as an address goes the same way in the code and has no test of its own. The join by peer id is tested against a private stand-in network, which sees no connection and no lookup from the session's command and does see the same command run by the person; with windows allowed and no window on the machine, the join tool is refused the same way (not on macOS). No test for: the prompt of `rule opt-in` on a real terminal, which the tests answer with `--yes` |
| Exchange by address over QUIC, by shared directory, by file | tested, with separate processes. A line or record file that is not strict JSON is refused, and a join from a file that holds several circles takes the one whose fingerprint you gave: both tested. That a held or waiting rule is reported once per exchange has unit tests only, and so has what a sync report keeps of a skill that could not be removed: only a later settle of the same circle that removed the skill takes the line back, and another circle's removal of a copy of that name does not, in either order (`a_failed_removal_is_taken_back_only_by_the_same_circle`). Two circles with a rule of one name in two places were run through the binary by hand, in both orders, with a one-shot `sync`, a daemon that syncs on a timer and one that only answers: both lines each time. A daemon prints each hold once per run: tested for a hold that a peer's push created, with three separate processes and a daemon that has no sync interval and knows no peer (`a_daemon_that_only_answers_tells_a_hold_that_a_push_created_once`); for a hold that the daemon's own exchange finds, unit tests only (`a_daemon_prints_a_hold_with_one_report_and_no_later_one`, `a_daemon_tells_a_hold_once_when_it_is_new`). What such a daemon prints for a rule that a push installed, removed or left waiting for its owner: tested with three separate processes, each line once over four pushes (`a_daemon_that_only_answers_tells_what_a_push_installed_and_what_waits`), and a unit test (`a_daemon_tells_what_a_push_changed_and_each_state_once`). By hand on 2026-11-11, on Linux, with debug builds: two daemons over QUIC on loopback, for four ticks of 30 seconds after a peer's push made a rule held on one of them. The binary before the second review's change printed nothing about the hold; the one after it printed the report with the hold once. After the third review's change, again by hand: two daemons where a later report was printed for new events, with one hold line where the third review had counted two, and a daemon that dials nobody, with and without `--sync-every 30`, with one hold line after a push. After the fourth review's change, again by hand: a daemon with `--sync-every 30` that knows no peer, its owner in mode `ask`, printed one line for the rule a push left waiting, where the fourth review had seen none through two ticks; and a daemon without a sync interval printed one line for each of two rules a push installed. Not tried: a report dropped from a full queue (64), and daemons started with `--lan`, with `--internet` or by the MCP tool. After a revocation an import can go wrong: see the next row |
| A node left on an old charter after a revocation ([Known limits](limits.md)) | no test. By hand on 2026-11-11, on Linux, with a debug build of this tree, encrypted-file keystores and a shared directory, in a circle of four with one device revoked: the node stayed on charter 3, and a second import changed nothing. After `reset` and `init` its join was refused. The amendment that would add its new key needs 3 of 4, and only two members had a device that still counted. On a copy of the home, deleting only the database, then `init` and `circle join`, joined at charter 4 with the same key ([ADR-044](decisions.md)). Not tried: the OS keychain, a node in several circles, the same over QUIC |
| Exchange across the internet (`--internet`) | tested against a private stand-in network. By hand on the real network on 2026-11-10, before v0.1.0, from one machine with both ends behind the same router. Not tried: two different routers, IPv6, Linux |
| Finding members on a local network (`--lan`) | worked on macOS when it was built, before v0.1.0. Its tests need real multicast and do not run in CI, and no run of them is recorded. Not tried on Linux |
| Noticing corrections by itself | best effort. Your agent reports a correction when it notices one. The built-in detector recognizes corrections that name a tool to use or avoid (46 of 70 in our test set, none of 52 ordinary prompts), not whole-sentence rules such as "always run the tests first". You can always write the rule down yourself |
| Deciding in a window from inside Claude Code | macOS only. Tested with a stand-in window: keeping a rule, proposing, voting, inviting and joining. By hand on macOS 14.2, before v0.1.0: the real window opened, closed unanswered and refused a text that does not fit. Whether a text fits is measured by the window's own script before anything is shown ([ADR-051](decisions.md)): tested on macOS with the real `osascript`, the height of a screen given and the script ended where the dialog would begin. Not tried: clicking its buttons, and a real window for a text the measure lets through or refuses. Joining in a window fits a circle of up to about five members on a laptop screen |
| The same steps as tools (`peerharness mcp`) | tested with a scripted client, a stand-in window and a stand-in network. By hand before v0.2.0, with Claude Code 2.1.322 on macOS, a stand-in window and a private network in place of the public one ([ADR-038](decisions.md)): asked in plain words, it read the device key, founded a circle, invited someone and kept the node reachable. Three runs, not a measure of how often an agent gets it right. No run with a real agent of noting, keeping, proposing, voting or joining is recorded. Other MCP clients: not tried |
| Being told that a vote waits (`daemon --notify`, and the end-of-turn line in Claude Code) | `--notify` is macOS only. Tested with separate processes and a stand-in notification. By hand, once: macOS accepted the real notification, and whether the banner shows depends on your notification settings for Script Editor. The timer of `--sync-every` has no test beyond its argument |
| Setting up (`peerharness setup`, and the prompt in [Set it up](../README.md#set-it-up)) | tested with a stand-in for Claude Code's `claude` command: it creates the node, connects the agent, registers the tools, changes nothing on a second run and is refused inside an agent's session. Without windows it ends with what works from the terminal, tested on Linux. A home whose settings allow windows, run where none can be shown: it says what still runs and how to turn that off, tested on Linux. A home that an interrupted `init` left, with a configuration file and a database without an identity: `setup` completes it, tested with a home made that way. The interruption itself, Ctrl-C at the passphrase prompt, was run by hand on a pseudo-terminal on Linux, before that fix. By hand: the three `claude mcp` commands it relies on, against Claude Code 2.1.322 with a throwaway configuration. Not tried: the prompt through an agent |
| The other coding agents: Codex, opencode, Pi, Antigravity, DeepSeek Harness ([ADR-050](decisions.md)) | tested, for each of the five through the binary (`apps/peerharness/tests/other_agents.rs`): `setup` connects the agent it finds and no other, the tools entry is written where the agent reads it (DeepSeek Harness's is shown), a kept rule and PeerHarness's own skill are copied byte for byte where it reads skills (none for opencode), `skills uninstall` takes the copy out, a skill of the owner's own there and an entry of their own are left, a file with comments is not rewritten, and `--remove` takes out what was put in. Connecting, `keep` and `setup` are refused under each agent's variable. A debug build finds no agent outside `PEERHARNESS_AGENTS_HOME`. Unit tests for the copies (`ph_skills::mirror`) and for the edits of TOML and JSON (`ph_observer::agent_config`). By hand on 2026-11-12, on macOS 14.2, with a debug build and every agent in a throwaway home: **Codex 0.167.1** lists the server from the appended block, and its model's prompt input (`codex debug prompt-input`) lists both copied skills; the server answered `initialize` and `tools/list` with the twelve tools in the environment Codex gives an MCP server. **opencode 1.1.50** connected to the server (`opencode mcp list`) and lists both skills from Claude Code's directory (`opencode debug skill`). **Pi 1.5.2** connected to it with twelve tools exposed directly (`pi mcp list`) and lists both skills (RPC `get_commands`). **Antigravity 1.5.6** (`agy`, installed into the throwaway home) lists the server from its configuration (`agy mcp list`), and starts the servers configured there; both skills were copied to `~/.gemini/config/skills`, the directory its program names, but with no session (`agy acp` needs a Google login) it was not seen listing them. The environment it gives an MCP server carries no mark of Antigravity, which does not matter for the tools (the server marks its own commands); its program contains the literal `ANTIGRAVITY_AGENT=1` beside `TERM=dumb` and `PAGER=cat`, which is what its shell tool would set, but that was not seen. **DeepSeek Harness 0.2.2-rc.1** composed the entry PeerHarness shows (`dsh --dump-config`) and started a server given in that shape. The environment opencode and Pi give the programs they start carries `OPENCODE=1`, and `PI_CODING_AGENT=true` with `AI_AGENT=pi`; with exactly those marks, `keep`, `setup`, `watch codex --remove` and `rule opt-in` were refused with exit 3 and nothing changed. Not tried: any agent's session with a model, so the marks in its agent's own shell (Codex's `CODEX_CI`, DeepSeek Harness's `DSH_SHELL`) are read from their source, and Antigravity's `ANTIGRAVITY_AGENT` from its program, not seen; opencode 2.x |
| Nine more agents: Gemini CLI, Qwen Code, Copilot CLI, Cursor, Amp, Droid, Crush, Kilo, goose ([ADR-052](decisions.md)) | tested through the binary like the first five (`apps/peerharness/tests/other_agents.rs`), with Kilo's entry going into the file it already has, and a consent step refused under each new variable with that variable named and its value not repeated. By hand on 2026-11-12, on macOS 14.2, with a debug build and every agent in a throwaway home, without a model unless said: **Gemini CLI 0.68.0** connected to the server (`gemini mcp list`, in a trusted folder) and lists both copied skills (`gemini skills list`). **Qwen Code 0.27.2** connected to it (`qwen mcp list`). **Copilot CLI 1.0.109** lists the server (`copilot mcp list`, which does not start it) and both skills (`copilot skill list`). **Cursor's agent CLI 2026.11.11** loaded it once it was approved (`agent mcp enable`) and lists its twelve tools. **Droid 1.8.0** connected to it with twelve tools (`droid mcp list`). **Kilo 7.8.27** connected to it (`kilo mcp list`) and lists both skills (`kilo debug skill`); it rewrote its own file on its first run, and PeerHarness still found its entry. **Crush 0.100.0**, run against a fake model, offered its model the twelve tools and both skills from Claude Code's directory, and the shell command it ran carried `CRUSH=1`, `AGENT=crush` and `AI_AGENT=crush`. **goose 1.59.0** lists both skills from Claude Code's directory alone (`goose skills list`) and, against a fake model with the entry PeerHarness shows added to `config.yaml`, offered the twelve tools; the shell command it ran carried `AGENT_SESSION_ID` and no `GOOSE_TERMINAL`. With exactly the environments Crush's and goose's shells gave, `keep` was put in a window and nothing was kept. During the research, against a fake model, the marks of Qwen Code and Copilot CLI were seen in their agent's shell and in `!` commands, and Gemini CLI's in `!` commands (its agent's shell runs through the same code); Cursor's and Droid's were read in their programs, and Amp's in its last readable build. Not tried: Amp, which needs an account for every command but `--version`; any of the nine with a real model |
| Taking it out (`reset`) | tested: it explains first, deletes only when a person confirms, refuses a home that is a link, and afterwards lists the folder of each skill that is still installed. It deletes what PeerHarness put into its home and nothing else, refuses the user's home directory under every spelling, and deletes a node whose database cannot be read ([ADR-051](decisions.md)). By hand on macOS: a home in a folder that also held `src`, `.git` and a note, which stayed. Not tried: a node whose keys are in the OS keychain |
| The install script and the release binaries | the script is tested against a stand-in release: a matching checksum installs, a changed archive does not. In the pre-launch check, on 2026-11-10, the script installed the v0.3.0 x86_64 Linux binary in a container: the checksum matched, and the binary ran `demo` and two processes voting over QUIC on loopback. The aarch64 Linux binary has not been run. On 2026-11-11, after v0.4.0 was published, the script installed the v0.4.0 aarch64 macOS binary into a temporary folder on macOS 14.2 (Apple Silicon): the checksum matched, and the binary ran `demo` to its end. For the x86_64 macOS binary the last run on record is of v0.2.0. The three other binaries of 0.4.0 have not been run |
| The two-process demo script (`demo/two-peers.sh`) | tested on Linux with the binary of this tree named by `PEERHARNESS_BIN` and a `cargo` that fails if it is called; the test asserts that the step that reads the rule prints its name and description. By hand in the second review: the script with the v0.3.0 x86_64 Linux release binary, and the filter of that step against that binary and a build of this tree, with the same nine lines from both. The release binaries of 0.4.0 had not been run with this script when this page was tagged |
| Windows | not supported |

## The pre-launch check and the runs of the suite

The pre-launch check ran the whole suite on 2026-11-10, on Linux, at commit `e6fae27`
(the 0.4.0 tree before the fixes): 843 tests passed, none failed, and 10 were skipped because they need
multicast, the public network or the real OS keychain. The finding ids that
[decisions.md](decisions.md) cites are the report's own.

Findings of that check were then fixed. A review of the fixes found more, and those
were fixed. A second review found more again, and so did a third and a fourth. What
the fourth found was fixed in part: what was left is listed as not done under "After
a fourth review" in ADR-041, ADR-042 and ADR-045. A fifth review, of the code and of
the documents, found no case in which something was signed, installed or removed
that its owner had not been shown, and three things that a command did not say;
those were changed (ADR-042, "After a fifth review"). Then the branch was opened as
pull request #7, and an automated review of the pull request commented on it. Each
comment was checked against the code before anything was changed. Six named
something in the code, and those were changed; for one of them, the join tool, what
could go wrong was narrower than the comment said. Two named a sentence in a
document, and those were corrected. One named a point that is already listed as open,
and nothing was changed for it (ADR-041, "After a review of the pull request"). Tests
were added each time, and the changes are recorded in ADR-041 to ADR-045 of
[decisions.md](decisions.md). All five reviews were made with AI coding agents, like
the check and like the fixes, and so were the check of the automated review's
comments and the changes for them. Each of the five reviews ran what it reports with
a debug build on Linux, in temporary homes. Where a row above says "by hand in the
second review", that is the run it means. The third and the fourth review, and the
fixes that followed each, also ran commands at real prompts on a pseudo-terminal,
and so did the changes after the review of the pull request. Those changes were
reviewed in their turn by two agents, and the small changes that followed by two
more (ADR-041, "After a review of the pull request"). Those runs are by hand:
the suite has no pseudo-terminal, and their outputs are not in the repository.

After the fixes for the first review the suite was run on Linux on 2026-11-11, on the
tree of commit `f1c7997`: 932 tests passed, none failed and the same 10 were skipped.
After the fixes for the second review it was run at commit `95830ff`: 947 passed,
none failed and the same 10 were skipped. After the fixes for the third review it
was run at commit `daab3d7`: 961 passed, none failed and the same 10 were skipped.
After the fixes for the fourth review it was run at commit `6431fa6`: 972 passed,
none failed and the same 10 were skipped. That is a run of the whole suite at the
last of those commits; each commit before it was checked with `cargo fmt`, `cargo
clippy` and the tests of the files it touches. After the changes for the fifth
review 973 passed, none failed and the same 10 were skipped. After the
changes for the review of the pull request it was run again on Linux on 2026-11-11:
983 passed, none failed and the same 10 were skipped.

CI runs the same suite on Linux and macOS. It ran for pull request #7 at commit
`0ffc90e`, on the merge of that commit with `main` (`e6fae27`), on 2026-11-11. On
Linux (Ubuntu 26.04, x86_64) 973 tests passed, none failed and 10 were skipped. On
macOS (macOS 26.7, arm64, runner image `macos-26-arm64`) 968 passed, none failed and
10 were skipped. The difference of 5 is tests that are compiled for one of the two
only: 6 run only on Linux and 1 only on macOS. `cargo deny`, `cargo audit` and the
check with Rust 1.89 passed in the same run. That was the first run on macOS on record
for the fixes, of the tree before the changes for the review of the pull request. CI
ran again with those changes, at commit `400fd20` on the merge of that commit with
`main`, on the same day and the same runner images: 983 tests passed on Linux and
978 on macOS, none failed and 10 were skipped on each, and `cargo deny`, `cargo
audit` and the check with Rust 1.89 passed. No run by hand was made on macOS for any
of the fixes. Outside CI the suite was run once on a Mac, on 2026-11-11 at the commit
that is tagged v0.4.0 (macOS 14.2, arm64, the stable toolchain): 978 passed, none
failed and 10 were skipped.

One test was found to fail now and then, and was changed: the control of
`a_join_nobody_can_be_asked_about_goes_nowhere_near_the_network` waited for a
connection that the stand-in network forgets when it closes, and the third review
saw its file fail 2 times in 18 runs. The control now waits for a question the
stand-in network keeps. After that change the file was run 25 times in a row on
Linux, 10 of them under load, and passed each time.

## The second audit

On 2026-11-11, after 0.4.0 was released, eight AI coding agents each attacked one
area of the tree as it was at commit `d71d62c`: the protocol parser, the counting of
votes, the life of a circle, the network, skills, consent and windows, keys and the
store, hooks and learning. They ran on macOS 14.2 (arm64) with debug builds, in
temporary homes, with a stand-in window and on loopback only. A claim counted only
after the agent that led the audit had read the code for it and run its reproduction
again. What was confirmed, what was changed and what was left is
[ADR-051](decisions.md). Like the pre-launch check and the five reviews, the audit
and the fixes were made with AI coding agents, and no one who is not one has reviewed
them. It is not a security audit by a third party.

Each fix has a test, which ADR-051 names. Where the audit had shown a fault with a
script, the script was run again with a build of the fixed tree, on the same machine.
Those runs are by hand: their outputs are not in the repository.

| What was found in 0.4.0 | Tested | By hand, after the fix |
|---|---|---|
| A member could send two proposals in two orders and leave one node without a rule that passed; a repeal from another scope could count | unit tests of both orders, and of the rule set | the node that had refused the proposal imported the same file again, kept it and installed the rule |
| A rule could carry syntax that Claude Code runs as a command when the skill loads | tests, and a property that holds the detector against a model of Claude Code's two patterns | the sentence of the audit, given to `note`: 0.4.0 stored it and `keep` installed it; this tree refuses it at `note`, and at `keep` for the note 0.4.0 had stored |
| `reset --confirm` deleted everything in a home, also files that were not PeerHarness's | tested | a home in a folder with `src`, `.git` and a note. Not tried: the OS keychain |
| A request that panicked stopped a daemon's node and left its process running | a unit test | none |
| A window could be taller than the screen | on macOS, with the real `osascript` and no dialog shown | none: no window was opened |
| A member's text could add lines to the inbox, the list of questions and the list of rules | tested | the three scripts of the audit |
| A rule could stay installed with no record that a vote installed it | a unit test | an adoption while another connection held the database for nine seconds |
| An opt-out in one team removed a copy that another team's rule still needed | unit tests | the script of the audit |
| The same event, signed twice by its author, was rewritten in a shared directory at every sync | a unit test | two nodes and a git repository: after one conflict, three rounds of sync by each wrote nothing |
| A large file in a shared directory was read into memory | a test with a sparse file of 1 GiB | a file of 2 GiB: 15.5 MiB at the peak for `events sync` |
| Files that are no records stopped `events sync` for a team | tested | 65 such files: the sync and the import end with exit code 0 and report them |
| A frame was read in forms the protocol does not have | tested; the golden vectors did not change | none |
| A plaintext keystore and the weak key-file profile were warned about only at `init`, or not at all | tested | the two scripts of the audit |
| A `circle create` that failed left a root key behind | tested, with six runs at once | one root key where the script had left nine |
| `init` in a folder whose path holds a tab or a line break left a home that could not be used | tested | the script of the audit. Not tried: a path longer than 1024 bytes |
| One member's hundred questions hid everyone else's | tested | three nodes: the next member's question is shown |
| A `Stop` hook that met a busy database lost lines of the spool | tested | 200 lines with the database held by `sqlite3` and the hook killed after three seconds: all 200 were stored afterwards, where 0.4.0 kept 8 |
| Connecting Claude Code rewrote numbers elsewhere in its settings file | tested | a line of ten such numbers came back character for character |
| An agent that read the inbox kept its owner from being told about a note | tested, under two marks of a session | the hook prints its line after the agent's `inbox` |
| More than 20 notes of an agent could wait, and a session could add observations as the owner's | tested | 60 notes at the same moment left exactly 20, four runs out of four; the import is refused |
| An invitation did not show the scopes it gave | tested, in the terminal and with a stand-in window | the window says the scopes that the roll then holds |
| A circle's name could put a sentence into later windows | tested, with six names that are refused | the join under such a name is refused and no window is asked |
| `proposal show` printed a rule nobody had voted on into an agent's session | tested | the session gets one line in place of the text |
| `setup` handed the passphrase of the key file to the `claude` command | tested with a stand-in `claude` | none. Not tested: the same for `osascript` and `kill` |
| `circle revoke` took a key that no member has without a word | tested | none |

Three more changes were to what a command or a document says, and have a test where a
command says it: what `circle members` and a ballot say about an advisory team, what
`rule list` says about a team its owner left, and the list of programs PeerHarness
starts in the security model.

Not changed, and listed in ADR-051 under "Seen in passing and not changed" or in
[limits.md](limits.md): votes cast at the same moment can leave several RESULT
records for one proposal, which count as one; an import retries the lines it could
not place yet in whole passes; a process inside a session can hand the hook a prompt
it made up.

The whole suite was run on 2026-11-12 on a Mac (macOS 14.2, arm64, Rust
1.93.0-nightly), on the tree of commit `59ba4c7`, which holds every fix and `main` as
it was at `774d855`: 1033 tests passed, none failed, and the same 10 were skipped.
`cargo fmt --all --check` passed on that tree, and so did `cargo clippy` with `-D
warnings` under that toolchain and under stable (1.91.0), and `cargo +1.89 check`.
Each commit before it was checked with `cargo fmt`, `cargo clippy` and the tests of
the files it touches, and the suite was run once in between, before the last five
commits of fixes: 1025 passed and none failed. No run of the suite was made on Linux outside CI.
`cargo deny` and `cargo audit` are not installed on that Mac and were not run there:
the fixes add no crate and `Cargo.lock` did not change, and CI runs both.

CI ran for pull request #10 at commit `5b332c4`, which has the same code as `59ba4c7`
and the documents after it. On Linux (Ubuntu 26.04, x86_64) 1036 tests passed, none
failed and 10 were skipped. On macOS (macOS 26.7, arm64) 1033 passed, none failed and
10 were skipped. `cargo deny`, `cargo audit` and the check with Rust 1.89 passed in
the same run. That is the only run on Linux for these fixes: no reproduction of the
audit was run there by hand.
