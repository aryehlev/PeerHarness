# Guidance for AI coding agents

This file is for AI coding agents (Claude Code, Codex and similar) working on this
repository. Humans should follow it too. It is short on purpose: read the documents it
points to before changing anything non-trivial.

## Read before you change code

1. `docs/spec.md`: what we are building and the hard requirements.
2. `docs/architecture.md`: the contract between crates (encodings, signing, events,
   wire, schema, governance by vote under a charter in section 10, privacy rules).
3. `docs/decisions.md`: ADRs. Record every new decision or deviation there.
4. `docs/protocol-v0.md` and `docs/security-model.md` before touching protocol,
   authorization, networking, keys, skills or anything that sends data off the device.
5. The crate-level docs (`//!` in each `src/lib.rs`) of the crates you touch.

If a library's API differs from what the docs assume, check the library's current
official documentation, adapt, and record the deviation in `docs/decisions.md`.

## Crate boundaries

```text
ph-core  <-  ph-protocol  <-  ph-identity, ph-governance, ph-skills, ph-network, ph-store
ph-core  <-  ph-observer, ph-learning
apps/peerharness depends on everything and is the only place crates are wired together.
```

| crate | owns | must not |
|---|---|---|
| `ph-core` | encodings and ids, `Scope`, `Role`/`Capability`, candidate state machine, observations, redaction, `Clock`, `MembershipOracle` | depend on any other workspace crate |
| `ph-protocol` | JCS, signing, envelopes and bodies, credentials, the charter, bundles, wire types, limits, golden vectors | do I/O or networking |
| `ph-identity` | keystores, device identity, circle authority (credentials, revocations, charter issuance), invites, `MembershipRegistry` | store private keys anywhere but the keystore; decide whether a charter change was voted |
| `ph-store` | SQLite schema, migrations, typed repositories | make authorization decisions |
| `ph-network` | libp2p QUIC transport, framing, rate limits; opt-in LAN discovery; opt-in internet mode (lookup by peer id, relay reservations, hole punching) | know about circles or authorize anything; dial a peer the application named unless told to |
| `ph-observer` | hook parsing, settings install/remove, spool, notification throttle | open paths from hook payloads |
| `ph-learning` | detectors, free-text notes, drafts, advisory providers | let provider or agent output drive any decision |
| `ph-governance` | incoming-event authorization, the roll as membership (`RollOracle`), read rules, tally, result verification, rules in force, charter succession, conflicts, anti-spam, adoption gate | do storage or networking; read a clock when counting |
| `ph-skills` | `SKILL.md` parsing and validation, the instruction-only rule, scanner, bundles, bundle store, installer | execute skill content |

Only `apps/peerharness` may depend on `ph-store` or `ph-network`. Library crates talk
through types and traits from `ph-core` and `ph-protocol`. Integration tests that run
the binary live in `apps/peerharness/tests/` (ADR-007); shared fixtures in
`tests/fixtures/`.

## Invariants that must never be loosened

Do not weaken any of these to make a test pass or a feature work. If one blocks you,
stop, leave the feature disabled, and document the blocker.

**Consent and privacy**

* Nothing leaves the device automatically. Only text the human saw in an exact preview
  and confirmed goes into QUESTION, ANSWER or PROPOSAL bodies or bundles, and
  `ph_core::redact` runs before the preview.
* Never infer consent from agent or model output. Model output is advisory only and is
  never `Actor::Human`. Human-only lifecycle transitions stay human-only.
* A coding agent may write a note (`peerharness note --from-agent`), which creates a
  `Detected` candidate and nothing else, and it never answers a consent step. Every
  consent step goes through `consent::confirm`, `consent::human_only`,
  `consent::confirm_or_window` or `consent::confirm_circle_or_window` and refuses
  inside an agent session (architecture 12.1, ADR-022). Do not add a flag, a variable
  or a path that lets a session answer one, and do not let `note` approve, install or
  share anything.
* One exception, and do not widen it: confirmation windows (ADR-033, ADR-037,
  ADR-040). Only when the owner turned them on in their own terminal (`peerharness
  setup`, or `watch claude --install --dialogs`), a session may make a window of the
  operating system appear for seven steps: proposing a rule, a ballot on a proposed
  rule, installing a rule that passed, proposing to admit a member (`circle invite`), a
  ballot on an amendment that admits one member and changes nothing else, joining a
  circle, and keeping a noted rule for oneself (`keep`). Only a click on "Proceed" in
  it counts; `--yes`, arguments, standard input and the environment never do. The
  window shows the exact preview in full or the step is refused, the preview is not
  printed into the session, and a rule with a high-risk finding is never decided
  there. Turning windows on is never asked in a window. The stand-in window program
  (`PEERHARNESS_TEST_WINDOW_BIN`) exists in debug builds only: do not make a release
  build read it.
* A noted rule is never installed without its owner's yes. A note comes from an agent,
  and an agent repeats what it read. Do not add a setting, a mode or a default that
  keeps a rule by itself, and do not let `note` or a hook install anything.
* Inside a session a note is always an agent's note, whatever flags were passed
  (ADR-042): its label and the cap on waiting notes follow
  `consent::in_agent_session()`, never `--from-agent` alone.
* `rule opt-in` is a consent step in the terminal (ADR-042). It puts a rule's text
  back into the owner's agent, so it goes through `consent::human_only` and
  `consent::confirm` with the rule's exact text and the install directory in the
  preview. It has no window and no MCP tool: do not add either without a setting of
  its own that the owner allowed. `rule opt-out` stays immediate and unasked.
* A ballot on an amendment is shown from the signed content in the terminal as in a
  window (ADR-041). `proposal vote` and `proposal show` describe the proposal's `next`
  against the charter it names (`amendment::changes`), with the rules it would drop or
  bring back by name, and show the title afterwards as the proposer's words. Never
  build that description from a title, and never sign an approval of an amendment
  whose effects this node cannot show (`amendment::Changes::unread`): `--yes` does not
  override it, and `reject` and `revise` are not refused. A rule with a high-risk
  finding is asked in the terminal when it is proposed too (`proposal create`). A
  rationale typed for `proposal vote` is one line, checked before any preview or
  window. Where `proposal show` or an amendment's description prints several lines
  that a member wrote, every line goes behind a mark (`output::quoted`).
* An amendment is drafted only on a node that holds every rule the charter in force
  carries (ADR-041). `circle invite`, `remove`, `amend` and `device` fill `carried`
  from the rules in force on the node, so they refuse while
  `RuleSet::missing_carried` is not empty (`circle::holds_every_carried_rule`), and
  no ballot on an amendment is put in a window on such a node
  (`proposal::sole_admission`). `circle leave` is never refused for it, because
  leaving never waits: it changes the owner's machine at once, before any key is used
  (`governance::apply_on`), and on a node that lacks a carried rule it puts no request
  to the circle (`circle::plan_request`). Never copy an id the node does not hold
  into `carried`: a rule that was repealed since would come back into force. And never
  let a draft leave a carried rule out because the node cannot name it.
* A request to change the charter and an approval of an amendment are signed only if
  the charter and the rules in force are still what the preview was built from
  (ADR-041). A sync or an import can change the node while its owner reads, and while
  they type a passphrase. A command that drafts an amendment calls
  `governance::as_drafted` after the owner's answer, after the key is unlocked and
  before it signs, with no prompt in between: `as_drafted` takes the unlocked key as
  a parameter for that reason. It signs through `governance::propose_under`, which
  names the charter that was shown. So do `proposal create` and `rule repeal`, with
  the charter their preview counted the voters on (`governance::charter_as_shown`),
  and `question send` refuses when the charter it counted its readers on changed.
  `governance::propose_without_preview` signs under whatever charter is current: it
  is for the demo and for tests, returns an error for an amendment, and no command
  that asked its owner calls it. `proposal vote` unlocks the
  key, then reads `governance::amendment_changes` again
  (`proposal::approval_as_shown`, which takes the key in the same way) and signs an
  approval only when it says what was shown (`amendment::Changes::same_as`), and for
  a ballot asked in a window only while `proposal::sole_admission` still gives the
  same entry under the same charter. `rule repeal` and `--announce` look again in
  the same place at the proposal they name (`governance::rule_as_shown`). Do not move
  any of these checks before the prompt, the window or the unlocking of the key, and
  do not sign a draft under a charter other than the one it was built from. Each
  check and the signatures it allows are one write transaction of the store
  (`governance::atomically`): another process cannot store a ballot or a charter
  between them. The key is unlocked before the transaction begins, and nothing inside
  it prompts, opens a window, reads standard input, touches the network or settles.
  Do not take a check or a signature out of it, and do not put a prompt into it. The
  first run of `circle leave` decides before it asks what it does about the request
  (`circle::plan_request`) and says so in its preview. It signs the request only
  where the preview announced one and the node is still what the preview was built
  from, after the machine changed and after the key is unlocked: the removal that
  was drafted for the preview, never a new draft. It signs none either when exactly
  that removal is on record by then (`circle::request_as_previewed` reads
  `circle::removals_on_record` again with the key in hand, inside the transaction).
  Otherwise it makes none.
  A second run first removes, with no key and never inside a session, what the
  circle installed and the first run could not remove (`governance::apply_on`). Then
  it asks about the request alone and signs through the same function as the first
  run: it is checked like every other draft, and it makes no second request when
  exactly that removal arrived meanwhile.
* What the owner allowed is what they read when they allowed it. The steps about a
  circle have their own setting (`[agent] circle_windows`, `config::Asked`), because
  windows turned on before ADR-037 were allowed for three steps, and keeping a rule has
  `own_windows` for the same reason. A step added to the
  list later needs a setting of its own in the same way, and a new preview in `watch
  claude --install --dialogs`: never let an older "yes" cover it.
* `peerharness mcp` (ADR-038) is not a way to consent and must not become one. Every
  tool runs this binary as a child process with `PEERHARNESS_AGENT_SESSION` set: never
  run a command in-process from a tool, never pass `--yes` or any flag taken from an
  argument, and never add a tool for a step that has no window (reviewing, installing
  for oneself, export, reset, hooks, any change to a charter but an admission). A tool
  runs only at the level the owner allowed (`config::Asked`), consent step or not.
* `peerharness setup` (ADR-039) is where the owner allows what their agent may start.
  It is refused inside a session as a whole, before it creates anything. Do not let a
  session run part of it.
* Inside a session no command writes a circle's records to a file: that is `events
  export`, in the person's terminal. A window that asks about a device or a circle
  takes what it shows from the signed content (the amendment, the charter), never from
  a title or any other text a member wrote.
* Inside a session `export --local` is refused as well, on standard output as to a
  file, and `init` refuses the plaintext keystore, whether a flag or an existing
  config file asks for it; a plain `init` stays allowed there (ADR-042). The
  `join_circle` tool takes a peer id or a multiaddr that names nothing on disk: a tool
  never makes `circle join` read a file. Inside a session `circle join` itself reads
  no argument that parses as a peer id or as a multiaddr as a file, whatever is on
  disk, so that rule does not rest on the tool's own look. No refusal of a consent step
  tells its reader
  to pass `--yes` (`consent::no_terminal`).
* Nothing is saved to the library, installed or signed before the confirmation it
  belongs to: build previews from drafts, and persist only after `confirm` returns.
* A confirmation counts for what was shown (ADR-042). The owner's yes to an install
  (`rule opt-in`, `proposal adopt`) is passed on as the id of the proposal that was
  shown (`governance::Owner::confirmed`), and `apply_rules` counts it for that
  proposal only. Never confirm an install by a rule's name: another proposal can take
  the name while the owner reads. Inside a session, what is said about a held rule
  does not name the commands that take a skill out or install the rule
  (`HeldRule::explain_to`), and neither does the line for a voted copy that was left
  in place because its owner edited it (`KeptEdited::line_for`).
* The reverse holds for an opt-out: it never waits for anyone. `rule opt-out --announce`
  and `circle leave` change the owner's machine first and ask about what is published
  after.
* An opt-out waits for no key either (ADR-041). `rule opt-out`, `proposal refuse` and
  the install that `rule opt-in` confirmed change the machine first and unlock the
  device key only afterwards, and only where something is to be signed
  (`governance::settle_machine_first`). A key that does not unlock is a line in the
  report there, not a failure. Do not put `governance::settle` or any other use of a
  key in front of the machine change in these three.
* Observation text, prompts, transcripts, tool output, skill text, circle names,
  revocation reasons and passphrases never appear in logs, error `Display` strings,
  panic messages or network payloads. Log ids and counts only. The same holds for
  what PeerHarness shows unasked (the Stop notice, `daemon --notify`): a count, never
  text another member wrote. `Debug` of types holding
  such text prints lengths.
* `transcript_path` and any other path from a hook payload is never opened. Hooks always
  exit 0, never block, and print nothing for `UserPromptSubmit`.
* Joining a circle never uploads existing local data.
* Remote advisory providers stay off by default and need both config opt-in and a
  per-invocation exact preview.

**Keys and identity**

* No private key bytes in SQLite, logs or files other than the keystore. No silent
  plaintext keys: `insecure-dev` requires an explicit flag and warns.
* The circle root key is separate from every device key and never leaves its keystore.
* The libp2p identity is the device key; authorization uses the transport-authenticated
  device key, never a claimed id.

**Protocol and authorization**

* Deny by default. Before membership is proven, only `hello` gets a real answer; every
  other request gets `error{unauthorized}`, identical whether a circle exists or not.
* Request authorization (who may connect, read, ask, answer) is re-evaluated on every
  request and every use, at the local clock. Never cache an authorization decision.
* On the transport, a peer is answered because its transport-authenticated device key is
  on the roll of the current charter of the circle the request concerns, within the
  scopes of its roll entry and unless the device is revoked (`RollOracle`, ADR-026).
  Never answer a request on the strength of a credential, a claimed id or an earlier
  `authenticate`. A pushed event gets no standing from who pushed it.
* One exception, and do not widen it: the removal notice (`peer::farewell`, ADR-028). A
  device that is not revoked and is on the roll of an **earlier** charter this node
  holds gets, for `fetch_events` only, the charters up to the first one without it and
  the amendment, ballots and result behind each. Nothing later, nothing else.
* A syncing node sends nothing circle-specific, not even a circle id, to a peer it does
  not share that circle's roll with. A node that is joining (`circle join <address>`)
  sends back only circle ids the peer itself just named, and stores nothing before its
  owner has confirmed the charter.
* A node dials only an address its owner gave, a peer an earlier sync stored, with
  `--lan` an announced device key that is on a roll it holds, or with `--internet` an
  address the public network gave for a device key on a roll it holds or for the one
  peer id its owner typed for `circle join`. An mDNS announcement and a lookup answer
  are unauthenticated hints: never treat one as membership, never dial without the
  `/p2p/<peer id>` that makes the handshake prove the key, and never look up or dial a
  key that is on no roll (ADR-031, ADR-032). Discovery and the internet mode stay off
  unless asked for.
* In internet mode the public network learns a device key, an IP address and which
  device keys a node looks up. Never send it anything else: no circle id, name, roll or
  event, and store nothing in the DHT. A node is a client there, never a DHT server, a
  relay or a dial-back server. A relay gives no standing: authorize by the device key
  at the far end of a relayed connection exactly as on a direct one. Do not store an
  address that goes through a relay.
* Never move a fetch cursor past an event that could not be placed yet, and never move
  a push cursor past an event the peer refused (ADR-028).
* A credential counts only with a matching subject-signed acceptance, only from the
  circle root, only within its scopes and roles, and never after revocation or expiry.
* How each event type is authorized, never interchangeable (ADR-010, ADR-012, ADR-027,
  ADR-029): QUESTION and ANSWER by the roll of the circle's **current** charter, judged
  when they arrive; PROPOSAL, VOTE and RESULT by the roll of the charter the proposal
  names; STANCE by the roll of the charter the stance names; MEMBERSHIP by its embedded
  proof; REVOCATION and CHARTER by the root-key binding. A valid credential makes
  neither a voter nor a member, and the root key has no vote.
* Strict parsing: integer-only JCS, duplicate keys rejected, unknown members rejected at
  every level, explicit `null` rejected, size and depth limits enforced before parsing
  further.
* Imports go through the strict parser too (ADR-043). A line of an imported file and a
  record file of a directory are parsed by `carrier::parse_record` and by nothing
  else: never read one with plain `serde_json`. A join from a file or a directory
  looks only at charters of one circle, the one with the fingerprint its owner gave
  when the source holds several: never pick a charter across root keys by its number.
* Signing input is exactly `context || 0x00 || JCS(unsigned)`; verification uses
  `verify_strict` and recomputes the canonical form. Do not change the bytes that are
  signed without a new schema version, regenerated vectors and a protocol doc update.

**Voting (architecture section 10)**

* A proposal passes only with approvals from `need(n, t) = floor(n*num/den) + 1` members
  of its whole electorate, never fewer than a strict majority. Count members, not
  devices. Nobody has a veto: `reject` and `revise` are recorded dissent.
* An approval is never withdrawn and "passed" never reverts. A ballot counts only for
  the exact proposal id it signs.
  The code diverges from this in one known case that is not decided: a REVOCATION
  stops counting every ballot of the revoked device, on proposals that had passed
  too, and ADR-044 holds the facts and the options.
* Counting, result verification, the rule set and charter succession never read a clock
  and never depend on arrival order. Do not add `now`, expiry or "latest wins" to them.
  PROPOSAL, VOTE, RESULT, CHARTER, REVOCATION and STANCE never expire, and a revocation
  is never refused for its date (ADR-015, ADR-017).
* What a node keeps never depends on the order its records came in (ADR-050). `ingest`
  checks nothing about a PROPOSAL against other stored events: not its `supersedes`,
  not a repeal's `target`. A reference rule is applied where the reference is used, on
  the records the node holds (`supersede_links`, and `rules_in_force`, where a repeal
  counts only against a rule of its own scope). Do not add a check on arrival whose
  answer changes with what is already stored, other than "a record it depends on is
  missing", which waits and is tried again.
* A STANCE is a record of what a member says about a rule. Never read one in a tally, a
  result, the rule set or an installation decision (ADR-029).
* A RESULT and a root-signed CHARTER carry no authority. Nothing takes effect before
  `verify_result` or `check_successor` passes locally. The root key notarizes: never
  accept a charter (other than a node's first) that a passed amendment does not justify
  with exactly the content that was voted on.
* The founder's node does exactly one thing alone: `circle revoke`, a REVOCATION of one
  device key. It can block and never pass, and it never changes the roll. Do not give
  the root key any other power. Every other change to a charter (`invite`, `remove`,
  `leave`, `amend`, `device`) is an amendment that needs its threshold.
* A proposal counts only under the current charter. Only `Passed::by_vote` and
  `Passed::carried` feed `rules_in_force`; do not add another way in.
* A rule binds only the members of its electorate. A vote removes only what a vote
  installed (`rule_installs`), from where it was put: never uninstall a skill the owner
  installed personally because of a vote (ADR-023). Where a rule is installed
  (`circle place`) comes from the owner's command line only, never from a hook payload
  or a peer (ADR-030).
* A vote never replaces or removes a skill it did not install (ADR-042). `apply_rules`
  installs over a managed skill only when `rule_installs` records that a vote of the
  same circle put exactly that text at that place. Otherwise the rule is held
  (`governance::held`) and nothing is written: do not add a mode, a flag or a
  confirmation that installs a held rule. The name of PeerHarness's own skill
  (`agent_notes::SKILL_NAME`) is reserved: `note`, `review`, `keep` and `proposal
  create` refuse it, and no vote installs a rule under it. Do not refuse such a
  proposal at `ingest`: what is stored and counted must not differ between nodes. A
  hold is local and never changes whether a rule passed. A record in `rule_installs`
  never outlives the copy it stands for: `skills uninstall` clears the row of a copy
  it removes, or the next settle would remove a copy its owner installed since. A
  voted copy that its owner edited is never deleted. It is left, its row is cleared,
  and the run that finds it names it (`Applied::left_in_place_lines`): every command
  that settles a circle prints those lines.
* Rights no vote overrides (10.10): no vote widens read access; a bundle that fails its
  digest or validity check is never installed; a high-risk finding always asks the
  owner; an opt-out always wins. `LocalPolicy` can hold a rule back on one node and can
  never change whether it passed.

**Skills and the file system**

* Received bundles are exactly one `SKILL.md`. Reject traversal, absolute paths,
  backslashes, hidden files, symlinks, duplicates and extra files. Never execute skill
  content. Scanning never proves safety; do not claim it does.
* Every bundle, local or received, is instructions only: no `allowed-tools`, no
  shell-injection syntax (`ph_skills::check_instruction_only`, ADR-018). These are hard
  refusals. Do not downgrade them to scanner warnings or add a flag that overrides them.
* Installation requires the owner's consent: an explicit confirmation, or the owner's
  standing `follow` choice for a rule that passed a vote, verified its digest and has no
  high-risk finding (architecture 10.9). It is atomic, never overwrites an unmanaged
  directory without `--force-overwrite-unmanaged`, and uninstall/rollback touch only
  managed files.
* Changes to Claude settings are idempotent, backed up and atomic.

**Honesty**

* Do not claim a security audit, production readiness, or that a test passed when you
  did not run it.

## Commands

Run these before you say a change is done, and report the actual results:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

When dependencies change, also run `cargo deny check` and `cargo audit` if installed
(CI runs both), and keep `cargo +1.89 check --workspace --locked` working (MSRV).

Protocol vectors: `cargo test -p ph-protocol --test vectors`. Never edit files in
`crates/ph-protocol/tests/vectors/` by hand; after an intentional protocol change run
`PH_UPDATE_VECTORS=1 cargo test -p ph-protocol --test vectors` and review the diff.

## Testing rules

* Every test uses fresh temporary homes (`PEERHARNESS_HOME`), `PEERHARNESS_PASSPHRASE`,
  `init --kdf-profile fast-insecure-test`, a temporary `PEERHARNESS_CLAUDE_SKILLS_DIR`
  and a temporary `PEERHARNESS_CLAUDE_SETTINGS`. Never touch the developer's real
  `~/.claude`, real settings or the OS keychain; tests that must are `#[ignore]`d.
* Multi-node tests use real separate OS processes on ephemeral loopback QUIC ports, with
  no shared database and no network mocks. Poll with deadlines instead of fixed sleeps,
  and kill daemons in `Drop` guards.
* Tests of the internet mode run against the private hub in
  `crates/ph-network/tests/common/hub.rs` (the app reaches it through
  `PEERHARNESS_INTERNET_BOOTSTRAP` and `PEERHARNESS_INTERNET_PRIVATE`). A test that
  needs the public network is `#[ignore]`d and uses throwaway keys.
* Tests that play the person remove `CLAUDECODE` and `PEERHARNESS_AGENT_SESSION` from
  the child process (the suite itself may be run by a coding agent). Tests of the
  agent-session guard set one of them.
* No test opens a real window or shows a real notification. A test that turns
  confirmation windows on sets `PEERHARNESS_TEST_WINDOW_BIN` on every command it runs
  (see `apps/peerharness/tests/agent_windows.rs`), and a test that starts `daemon
  --notify` sets `PEERHARNESS_TEST_NOTIFY_BIN`; otherwise a developer's Mac would show
  dialogs and banners during `cargo test`. Both variables are read by debug builds
  only. Tests of the MCP server (`apps/peerharness/tests/mcp_server.rs`) set both, run
  the server without `CLAUDECODE` and `PEERHARNESS_AGENT_SESSION` (it has to set the
  mark itself), and point its daemon at the hub, never at the public network.
  The tests of what a session is refused and of what a ballot shows there
  (`apps/peerharness/tests/session_gates.rs`, `ballot_previews.rs`) set the stand-in
  window on every command too, and are compiled for debug builds only.
* No test waits for a person at a prompt. A step that asks is answered with `--yes`,
  as in a script the person wrote. A test that needs `init` to fail must not count on
  a missing passphrase: the prompt reads the controlling terminal, so a developer who
  runs `cargo test` from one would be asked. Give it an empty `PEERHARNESS_PASSPHRASE`
  (see `apps/peerharness/tests/first_run.rs`). No command may refuse because the build
  is a debug build: the suite and the demo script run debug builds.
* No test runs the developer's own `claude` command. `setup` registers an MCP server by
  running it, so debug builds never look for it on `PATH`: they run only the stand-in
  named by `PEERHARNESS_TEST_CLAUDE_BIN` (see `apps/peerharness/tests/setup.rs`). Do
  not make a debug build search `PATH`, and do not make a release build read the
  variable.
* Security behaviour needs negative tests: show the forged, expired, revoked,
  out-of-scope, replayed or oversized input being rejected.
* Use fake provider binaries via `PEERHARNESS_CLAUDE_BIN` / `PEERHARNESS_CODEX_BIN`; never
  call a real model in tests.

## Code conventions

* `#![forbid(unsafe_code)]` everywhere. Edition 2021, MSRV 1.89.
* Clippy clean with `-D warnings`. Errors via `thiserror` in libraries, with static,
  content-free messages.
* Prefer crates already in the workspace; new dependencies must be permissively licensed,
  from crates.io, and pass `cargo deny check`. Avoid OpenSSL.
* Keep `apps/peerharness/src/main.rs` thin; one module per command group.
* Commit logically separate increments. Update docs and ADRs in the same change.
