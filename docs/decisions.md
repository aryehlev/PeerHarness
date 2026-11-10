# Architecture decisions and deviations

These are short ADR-style entries. Newest entries go last.

## ADR-001: Crypto stack follows libp2p 0.57
`libp2p 0.57.1` pulls in `ed25519-dalek 3`, `sha2 0.11` and `rand 0.10`. We pin the same
majors workspace-wide so only one copy of each primitive is compiled in. The device key is
a single Ed25519 key that serves as both the PeerHarness identity and the libp2p identity,
so the QUIC/TLS-authenticated `PeerId` binds directly to the device key.

## ADR-002: Our own restricted JCS
We implement RFC 8785 ourselves over a JSON subset that forbids non-integer numbers and
integers above 2^53-1. That keeps the canonical form trivially reproducible in other
languages and avoids float serialization edge cases. Golden vectors live in
`crates/ph-protocol/tests/vectors/`.

## ADR-003: Loopback TCP control endpoint instead of a Unix socket
The CLI talks to its own daemon over `127.0.0.1:<ephemeral>` and authenticates with a
256-bit token stored in `daemon.json` (0600). Unix socket paths are limited to about 104
bytes on macOS, which breaks deeply nested temp homes used in tests. The loopback design
also carries over to Windows later.

## ADR-004: Keystore backends
* `os` (macOS default): the OS keychain through the `keyring` crate.
* `file` (Linux default, and used by tests/demo): Argon2id key derivation plus
  XChaCha20-Poly1305 encrypted files, 0600, passphrase taken from
  `PEERHARNESS_PASSPHRASE` or an interactive prompt.
* `insecure-dev`: plaintext 0600 file, only with the explicit `--insecure-dev-keystore`
  flag, and it prints a warning on every unlock.

On Linux we do not depend on the D-Bus Secret Service by default, because it is often
missing on headless and CI machines.

## ADR-005: Strict YAML-subset frontmatter parser
Instead of a general YAML library (`serde_yaml` is deprecated, and general YAML allows
anchors, aliases and tags), `ph-skills` parses only the flat key/value plus one-level
`metadata` map subset that the Agent Skills spec needs. Anything else is rejected.

## ADR-006: Optional advisory agent providers
Following user direction, PeerHarness can use a developer's existing coding-agent CLI
(`claude -p`, `codex exec`) as an advisory provider. It spawns the user's unmodified
binary, which handles its own authentication, and never collects or proxies credentials.
Because this sends content to a remote service, it is off by default and requires config
opt-in plus a per-invocation exact preview. Its output is never an authorization input.
The deterministic detector remains the default, so the demo needs no subscription.

## ADR-007: Integration tests live in `apps/peerharness/tests`
Cargo only exposes `CARGO_BIN_EXE_peerharness` to tests in the binary's own package, so
the multi-process network tests live in `apps/peerharness/tests/`. Shared fixtures are in
`tests/fixtures/`.

## ADR-008: Explicit `proposal create`, `proposal release` and `proposal adopt` commands
The specification's CLI list has no command that creates a PROPOSAL or RELEASE, or that
imports a peer's released skill, so we add these three. The proposer must vote
explicitly; creating a proposal is not an implicit vote.

## ADR-009: rusqlite (bundled SQLite) rather than Turso/Limbo
We considered the Rust SQLite rewrite (`turso 0.9.0-pre.2`). We stay on `rusqlite` with
bundled SQLite for three reasons:
1. Turso is still pre-release, and our database holds security-relevant state (signed
   events, memberships, revocations).
2. Several processes (Claude Code hooks, CLI, daemon) write to one database file, and
   SQLite's WAL plus file locking is proven for that pattern.
3. Our write rate is tiny, so raw engine speed is not a bottleneck.
All access goes through `ph-store`, so switching engines later stays a contained change.

## ADR-010: REVOCATION and CHARTER authorization is by root-key binding
A REVOCATION is authored by the circle root key, which holds no membership credential.
It is therefore authorized by checking `derive(author) == circle_id` (see
`ph_protocol::Authorization::CircleRoot`), not through the `MembershipOracle`.
MEMBERSHIP events are authorized by their embedded credential and acceptance
(`Authorization::EmbeddedCredential`).

Since ADR-012 the same root-key binding authorizes CHARTER events. For a charter the
binding only proves authenticity: the charter takes effect only if a passed amendment
justifies it (ADR-014). PROPOSAL, VOTE and RESULT are authorized by the roll of the
charter the proposal names (`Authorization::Roll`), so only QUESTION and ANSWER still go
through the `MembershipOracle`.

## ADR-011: Stricter-than-spec input rules
* A `DeviceKey` must be a canonical point encoding and must not be small-order, so each
  key has exactly one string, circle id and fingerprint.
* Free-text fields reject bidi controls (Trojan-source) and, for single-line fields, the
  U+2028/U+2029 line separators.
* `Debug` output of peer-supplied text prints lengths only.

## ADR-012: Majority of the roll replaces the approval-count policy
The first implementation followed the specification's small-circle policy: two
approvals, one of them not the proposer, and any `reject` or `revise` blocks. That is
review with a veto, not a vote. It ignores the size of the circle, lets one member block
everything for good, counts devices instead of people, and each node held its own copy
of the policy, so two nodes could disagree about the same ballots.

A circle now has a **charter** (`ph_protocol::Charter`): one root-signed object holding
the thresholds, the roll of members (people, each with their devices and scopes) and
the rules carried forward. A proposal passes when more than `num/den` of the members
entitled to vote on it have approved, counted per member. `reject` and `revise` are
recorded dissent and do not block. `CirclePolicy` is gone; `LocalPolicy` remains as a
node's private condition for installing a passed rule without asking and can no longer
affect whether a rule passed. This departs from specification section 8 ("at least two
distinct eligible device identities", "no unresolved rejection") on purpose.

## ADR-013: Approvals are grow-only
An approval cannot be withdrawn: a member has approved once any valid `approve` ballot
of theirs exists, and a later `reject` does not undo it. The set of approvals therefore
only grows, "passed" is monotonic, and the outcome does not depend on the order in which
ballots arrive or on any clock. This removes deadlines, latest-vote ordering by
author-controlled timestamps, and the earlier defect where approving twice invalidated
a release. A member who changes their mind proposes a repeal. The cost is that
thresholds are fractions of the whole electorate, so not voting counts as not
approving; v0 caps a roll at 64 members for that reason.

## ADR-014: The root key notarizes charter changes
Every change to the roll or the rules is an `amend` proposal carrying the complete next
content. After it passes, the root key signs the next charter, and every node accepts it
only if `ph_governance::check_successor` holds: it follows the current charter, its
content equals what was voted on, and the cited RESULT verifies under the current
charter. The root can therefore not add or remove a member or change a threshold on its
own. One signer keeps the chain fork-free in v0 without a consensus protocol: if two
conflicting amendments both pass, the root picks one. The costs are that changes stall
if the root holder is unavailable, and that a root signing two successors can split a
circle. Leaderless ratification (the certificate alone makes the next charter) is left
for later.

## ADR-015: Decision events do not expire
PROPOSAL, VOTE, RESULT and CHARTER (and REVOCATION, ADR-017) are permanent records.
The envelope keeps `expires_at` for uniformity and builders set the longest allowed
lifetime, but receivers never enforce it for these types
(`EventType::is_permanent`, `check_time_rules_for`), and the store's sync queries treat
them as never expired. Decision events are also authorized by the roll of the charter
they name instead of by the author's credential at the time of receipt. Before this,
votes and proposals expired after 90 days and were authorized at `now`, so a passed
rule became unverifiable after 90 days (or 30, when an approver's credential lapsed)
and a node that joined later could not ingest the circle's history.

## ADR-016: `carried` checkpoints the rule set at every charter change
A proposal can pass only under the charter it names, and each charter lists in
`carried` the `adopt` proposals in force when it begins. On a charter change every
node's rule set becomes exactly `carried`. This gives three things: every node
converges on the same rules after a change, whatever it had or had not received before;
a node that joins later needs only its first charter and the carried proposals, not the
old ballots; and a majority of a *past* roll (members who have since left, whose keys
may be less well kept) cannot pass anything, because results count only under the
current charter. The amendment's voters approve the carried list together with the roll
change, and `carried_diff` shows them what it drops or adds. The cost is a size limit:
at most 256 carried rules, bounded in practice by the 64 KiB event limit.

## ADR-017: Revocations are never refused for their date
A revocation only ever denies. Refusing one because its `revoked_at` (or its envelope's
`created_at`) is ahead of the local clock leaves the revoked device trusted on that
node, and dropping stored revocations on reload after the local clock stepped back does
the same. Stateless validation, `ph_governance::authorize_incoming` and
`MembershipRegistry::add_revocation` therefore verify a revocation's structure and
signature only (`verify_revocation_signature`); the store already did. REVOCATION
events are also exempt from the "not from the future" rule and never expire, where
before they lapsed after 365 days while a credential could live 400.

## ADR-018: Bundles are instructions only, enforced syntactically
"Instruction-only" used to mean "one `SKILL.md`, no scripts". That is not enough for
Claude Code: an `allowed-tools` frontmatter key pre-approves tools for the agent, and
dynamic-context syntax in the body runs a shell command when the skill loads, before
the model sees anything. Both were left to the advisory risk scanner, which flagged the
first as a warning and did not see the second. `ph_skills::check_instruction_only` now
refuses, in every bundle whether built locally or received, a declared `allowed-tools`
and any body line matching `has_shell_injection` (an exclamation mark directly followed
by a backtick with another backtick later on the line, or a fence opened with three
backticks or tildes directly followed by an exclamation mark). The check is exact and
deliberately errs towards refusing; no flag overrides it. This is what lets a binding
circle install a passed rule without asking (architecture section 10.9 and 10.10).

## ADR-019: Events travel as files first
Every event is signed and names the charter it belongs to, so the carrier does not have
to be trusted. The CLI therefore exchanges a circle's events as a file of JSON lines
(`events export` / `events import`) before the QUIC daemon is wired. It works across
NATs, needs nobody to be online at the same time, and uses the same `ingest` path the
daemon will use. Two costs: a file is readable by whoever holds it, so read access is
"whoever a member gave the file to" rather than a credential check; and nothing is
delivered until someone moves a file. The library-level QUIC transport (ph-network) is
unchanged and remains the plan for live sync.

## ADR-020: Joining takes a charter as the trust anchor
A new member cannot verify a charter chain they were not part of. `circle join` takes
the newest CHARTER event in the given file whose roll lists the joining device, shows it
with the circle root fingerprint, and requires the human to confirm (or to pass
`--expect-fingerprint`). That charter becomes the node's anchor; every later charter
must pass succession. Earlier decision events, which name charters the node does not
hold, are not stored. The credential-based `Invite` object stays in the protocol for
the network transport.

## ADR-021: Rules can be written down, and the agent may report a correction
The deterministic detector only recognizes a few "use X, not Y" shapes and found about
one in five corrections in a hand-made sample. Rather than grow the patterns, a rule can
be stated directly: `peerharness note "<one sentence>"` creates a candidate whose skill
draft is that sentence. The coding agent, which is the one party that reliably knows it
was just corrected, may run the same command with `--from-agent`; `watch claude
--install` installs a small fixed skill that asks it to. This deviates from the
crate's earlier rule that drafts contain only fixed text plus extracted tokens: a note
draft contains the statement. It is redacted on the way in and shown in full before it
is saved, installed or shared. An agent's report is advisory and creates a `Detected`
candidate, nothing more, so the spec's "never infer consent from an agent's output"
holds. The detector stays as a third source.

## ADR-022: Consent steps refuse inside a coding agent's session
Giving the agent a command to run made it likely that a helpful agent would also run the
next one (`review --approve`, `proposal vote --yes`). Every consent step therefore
refuses when `CLAUDECODE` or `PEERHARNESS_AGENT_SESSION` is set, with or without
`--yes`, and the installed skill tells the agent that its part ends with the note. This
is deliberately described as a guard against accidents: it reads environment variables,
so an agent that clears them is not stopped, and an agent with shell access to the
owner's account has other ways to change local files. Cost: a person who types a
PeerHarness command through the agent's own shell escape is refused as well and must
use their own terminal. No override is offered, because an override an agent can set
would make the guard meaningless.

## ADR-023: A rule binds its electorate, and a vote removes only what a vote installed
Two questions the first version of section 10.9 left open. (1) Who gets a passed rule
installed: the members of its electorate (on the roll, with a scope covering the
rule's), not every node holding the circle's events. A member of another team is not
bound by a vote they could not take part in, and a removed member's node removes what
the circle had installed. (2) What a repeal removes: installs made because a rule
passed are recorded in the new table `rule_installs` (schema version 3), and only those
are removed when the rule leaves force. Without the record a repeal would have deleted
a skill the owner had installed for themselves under the same name and digest.
Consequence: on the machine of a proposer who installed their own rule personally
before proposing it, a later repeal leaves that personal copy in place.

## ADR-024: Earlier charters are held as history through the hash link
ADR-020 left a node that joined late unable to store any decision event from before its
anchor, because those events name charters it did not hold. The consequence was worse
than a gap in the audit trail: the adopt proposals listed in the anchor's `carried` are
such events, so rules passed before a member joined never reached that member's
machine. Every charter names its predecessor by hash, so the fix needs no new trust: a
charter older than every stored one is accepted as history exactly when the oldest
stored charter names it in `previous` (`Store::insert_charter_history`). The founding
charter, which was only stored locally, is now also published as a CHARTER event so it
can travel. History never becomes current and gives nobody a vote. The late joiner
still takes its anchor on the root's signature and does not re-count the votes behind
earlier steps; that limit is unchanged. This replaces the last sentence but one of
ADR-020.

## ADR-025: A circle's records can live in a shared directory
Sending a JSON lines file back and forth works and is tedious. Teams already share a
git repository, so `events sync <dir>` imports what a directory holds and writes what it
lacks, one file per record named by the record's own hash (`event-<hex>.json`,
`bundle-<hex>.json`). Two members adding records at the same time add different files,
so the directory merges by union and never conflicts. The directory is not trusted:
names are a convenience, every line is verified by `ingest`, links and other files are
never read, and a record file whose content was changed is refused and rewritten from
the verified copy. Costs, stated in the README and in the command's output: everyone
who can read the directory can read the roll, the proposals and the ballots, and
someone with write access can delete record files (which withholds them from whoever
has not synced yet, but cannot forge or alter a vote). Writing records out is a human
step and refuses inside an agent session; importing is open. The spec's request for a
libp2p transport stands; this does not replace it.

## ADR-026: The transport answers the roll, not credentials
The spec authorizes peers by membership credential, and the library implements that.
Wiring the transport showed two consequences of using it for access once membership is
decided by vote. First, a credential is issued by the root key alone, so the founder
could give any device read access to the circle's proposals and ballots without a
vote, which contradicts "the root key is a notary, not a ruler". Second, credentials
expire and only the root key renews them, so a circle whose founder left would stop
syncing after thirty days although its roll and rules are intact. The daemon therefore
decides access from the roll of the current charter, per request
(`ph_governance::RollOracle`, `apps/peerharness/src/peer.rs`): a device on the roll, in
the scopes of its roll entry, not locally known as revoked. The roll is itself a
locally verifiable, root-signed membership statement, which is what hard requirement 4
asks for, and it changes only by a passed amendment. `Authenticate` keeps its wire
shape and only announces addresses. Credentials, acceptances, invites and MEMBERSHIP
events stay in the protocol and the library; they still authorize QUESTION and ANSWER
events, which no CLI command produces yet, and that should move to the roll when
`question` is wired. Also decided here: no control endpoint, delivery loop or gossip in
v0. `daemon` only answers, `sync` is one exchange with one peer, and a held file lock
(not a pid or a port) says whether a daemon runs. Costs: a new member cannot join over
the network (it holds no roll yet) and joins from a file or directory; a removed
member's node is not told of its removal by peers.

## ADR-027: Questions and answers are authorized by the roll; the founder keeps one emergency power
ADR-026 left QUESTION and ANSWER on membership credentials because no command produced
them. With `question` wired, that would have meant that only devices holding a
root-issued credential could ask or answer, and since admission is by vote and issues no
credential, in practice only the founder. `governance::ingest` therefore passes
`ph_governance::RollOracle` to `authorize_incoming` for every event: a QUESTION or
ANSWER is accepted when its author's device is on the roll of the circle's **current**
charter, the roll entry covers the event's scope, and the device is not revoked. The
library's rule ("ask the membership oracle for the capability") is unchanged; what
changed is which membership statement the application gives it. Unlike decision events,
questions and answers are judged against the current roll at the time they arrive, so a
node that has since accepted a charter without the author refuses them. That is
acceptable because they decide nothing: they expire, they are advisory, and a rule still
needs a proposal and a majority. The local guard (`QuestionGuard`: quotas, duplicates,
mute and block) and `check_answer_reference` now run in `ingest`.

Also decided here, with the commands that complete the circle's life cycle:

* `circle revoke` is the one thing the founder's node does alone. It signs a REVOCATION
  of one device key with the root key (architecture 10.8, "Emergency"). It can stop a
  device from syncing and from being counted; it cannot add an approval, and it does not
  change the roll or the size of any electorate, so it can block and never pass. It
  refuses to revoke the device it runs on.
* `circle leave` acts on the owner's machine at once (nothing of that circle stays
  installed, `circles.left_at`) and puts the owner's removal to the vote. A unilateral
  exit from the roll was rejected: it would be a second way for the roll to change, and
  a threshold other than a majority of the electorate.
* `circle amend`, `circle device add|remove` and `circle remove` are amendments like an
  admission. `circle mode` is the owner's standing choice (10.9); switching to `follow`
  is consent and needs the owner, switching to `ask` does not.
