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
