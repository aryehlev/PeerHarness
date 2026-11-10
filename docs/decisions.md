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

## ADR-028: Joining and learning of a removal over the network; a cursor for sync
ADR-026 listed two costs of authorizing the transport by the roll: a new member could
not join over the network, and a removed member's node was not told. Both are closed
here without answering anyone who is not, or was not, on a roll this node itself holds.

* **Joining.** `authenticated` now names the circles in which the requester's device is
  an active member (`circles`, at most 64). A device that was admitted by vote is on the
  responder's roll, so it was already entitled to that circle's records; what it lacked
  was the circle id. `circle join <address>` greets, announces without addresses, fetches
  the records of the circles named, and then does exactly what a join from a file does:
  it finds the newest charter that lists the device, shows it with the root fingerprint,
  and stores nothing before the owner confirms. A device on no roll still gets
  `unauthorized` and learns nothing.
* **Removal.** A `fetch_events` from a device that is not an active member, is not
  revoked, and is on the roll of an **earlier** charter this node holds, is answered with
  the CHARTER events up to the first charter without it, each with the amendment, the
  ballots and the result that justify it, and nothing else (`peer::farewell`). The device
  was entitled to every one of those records as a member, and the removing charter is
  word for word the amendment it could vote on, so nothing it could not already have
  read is disclosed: no later charter, no later roll, no rule. Its node verifies the
  records like any others and only then considers itself removed. Every other request
  from it is refused as before. This is a deliberate, narrow exception to "a peer is
  answered because it is on the current roll", made because the alternative is a node
  that keeps following a circle that voted it out and cannot find out why it is refused.
* **Cursor.** `fetch_events` served a circle's events by `created_at` and could only
  exclude what the requester listed in `known` (at most 4096 ids), so a node holding more
  than that was sent events it already had until a page held nothing new, and stopped.
  Events are now served in the order the responder stored them, and the request carries
  `after`, the last event of an earlier answer from that responder. Stored order rather
  than `created_at`, because an event may arrive long after it was created and would
  fall behind a time-based cursor. The syncing node keeps one cursor per peer and circle
  for what it fetched and one for what the peer has taken (`sync_cursors`), keeps events
  it cannot place yet in a pool that is offered again with every later batch, and moves
  the fetch cursor only when that pool is empty. `known` stays as a cheap way to skip
  recent events both sides have.
* **No timer.** A sync used to wait up to ten seconds for the peer to fetch the rule
  texts of what it had pushed. The responder now makes the requester's next request wait
  for its own fetch-back and settling, so the result or charter that settling produces
  is there to be fetched, and the wait is exactly as long as the work.
* `sync` without an argument syncs with every peer whose address is stored, and
  `daemon --sync-every <seconds>` does the same on a timer. Neither dials anyone the
  owner has not synced with before.

## ADR-029: An opt-out can be put on the record (STANCE)
An opt-out was local only: the circle could not tell a binding rule that everyone
follows from one that half the members had quietly switched off. Recording dissent as a
`reject` ballot does not cover it: a ballot counts only for the roll the proposal names,
so a member admitted after a rule passed has no ballot to cast, and a member who
approved and later opts out would be on record with both an approval and a rejection.
A new event type, `STANCE`, carries the statement: the `adopt` proposal of the rule, the
digest of the charter under which the author is a member, `opted_out` or `following`,
and an optional reason. It is authorized like a ballot, by the roll, but by the roll of
the charter **it names** rather than the proposal's, so members who joined later can
make one, and the answer is the same on every node at any time. It is read like the
decision events of its rule and never expires.

It is a record and nothing else. No tally, certificate, rule set or installation reads
it; "passed never reverts" and "an opt-out always wins" are untouched. Publishing one is
the owner's choice (`rule opt-out --announce`, `rule opt-in --announce`), previewed and
confirmed like everything that leaves the machine. The opt-out on the machine never
waits for that confirmation: it has already happened when the prompt appears, and stays
if the announcement is refused. A member's latest stance on a rule is the current one;
stances of members no longer on the roll, and of revoked devices, are not shown. This is
display state ordered by `created_at`, which is acceptable only because nothing is
decided from it.

Adding an event type is a protocol change: the envelope schema version is unchanged
(existing events are byte-for-byte what they were, and the golden vectors only gained
one entry), and a node that predates the type rejects a STANCE as an unknown event type
without affecting anything else it holds.

## ADR-030: A scope's rules can be placed in one project directory
A rule about one repository ("use pnpm here") was installed in the user's skills
directory and so applied in every repository. The protocol already has the right handle:
a rule has a scope, and a team can agree that `repo/web` means one repository. What was
missing is the last step on each machine. `circle place <scope> --project <dir>` records,
on that machine only, that rules of that scope (and the scopes below it) are installed in
`<dir>/.claude/skills` instead; `--user` undoes it. The most specific placed scope that
covers a rule wins. `rule_installs.project_dir` remembers where a vote put each rule, so
a repeal, an opt-out, a removal from the roll or a changed placement removes exactly
that copy. The project installer is confined to the directory (`Installer::confine_to`),
so a linked `.claude` in an untrusted checkout is refused.

Nothing about this is shared or voted: where a member keeps a checkout is their own
business, and the directory comes from the owner's command line, never from a hook
payload or a peer. Choosing a place is a confirmation step like `circle mode follow`,
because it decides where files are written. Rejected: binding a rule to a repository
identity inside the proposal (a remote URL or a hash of one). It would put repository
names or their hashes on the wire and in the vote, and it would still need each member
to say where their checkout is.

## ADR-031: Opt-in LAN discovery announces a device key and nothing about circles
A node could only dial addresses a person gave it. `ph-network` can now find nodes on
the local network with libp2p's mDNS, off unless `NetworkConfig::lan_discovery` is set
(`daemon --lan`, `sync --lan`); with it off no multicast socket exists and nothing is
sent. With it on, a node asks for the generic libp2p service `_p2p._udp.local` on each
non-loopback IPv4 interface and answers every such query with
`dnsaddr=<listen address>/p2p/<peer id>` for its listen addresses on that interface.
That is all it says: the device public key and where it listens. A node with no listen
address there (a `sync` client, or a daemon on the default loopback address) answers
with an empty record, so it finds others without being found.

Accepted costs. The device key is stable, so an announcing device can be recognized on
every network it joins and matched to a roll by whoever holds that roll. Other libp2p
software sees the node and may connect; it gets `hello` and nothing else. mDNS is
unauthenticated, so an announcement is a hint: `ph-network` only reports
(`PeerDiscovered`, `PeerExpired`, `discovered()`), never dials, and keeps discovered
addresses out of the swarm's address book. The application dials only device keys that
are on a roll it holds, at an address ending in `/p2p/<peer id>`, so the handshake must
prove the key, and the peer is then answered by the roll like any other (ADR-026). A
device on no roll of this node is never dialed and is sent nothing. Any host on the
segment can fill the list or keep a member out of it, which costs discovery and nothing
else. Bounds: 256 peers with 8 addresses each; discovery turns itself off when
libp2p-mdns's own unbounded table passes 16,384 records. IPv4 only, with libp2p's
defaults of a six minute record lifetime and a query every five minutes.

Three deviations from plain use of libp2p-mdns 0.49, each found by experiment: its
tasks run on a runtime of their own because it never stops them (a stopped node would go
on answering); its log output is discarded because it logs addresses; its address
reports to the swarm are not passed on.

Not done, deliberately. Relays and hole punching (spec section 15) are not needed for a
circle to converge across networks: every member's node holds what the roll lets it
read, so one reachable member, or the shared directory of ADR-025, already carries
everyone's records to everyone else, with the roll deciding who gets what. A libp2p
circuit relay would add a party that the roll says nothing about. Hole punching and
router port mapping were left out because they cannot be tested from one machine.
(ADR-032 revises this paragraph: finding and reaching members across networks is now
built, opt-in.)

## ADR-032: Opt-in internet mode: members find each other by device key on the public libp2p network
ADR-031 left a circle to converge through one reachable member or a shared directory.
That asks every team to have a member who can open a port, and discovery on a local
network does not help a team that is not on one. So a node can now find and reach
another by its device key from anywhere, off unless its owner asks for it:
`daemon --internet`, `sync --internet`, `circle join <peer id> --internet`
(`NetworkConfig::internet`, default `None`; with it off the transport is built exactly
as before and speaks its one protocol).

What it uses, all from libp2p 0.57 and all as a client: the Kademlia DHT of the public
libp2p (IPFS) network (`/ipfs/kad/1.0.0`, client mode, bootstrap peers as that network's
own software ships them) to turn a peer id into addresses; identify and AutoNAT v2 to
learn whether the node can be dialed; circuit relay v2 reservations while it cannot;
DCUtR hole punching to replace a relayed connection with a direct one. A node never
serves the DHT, never relays and never dials back for others, and it stores nothing in
the DHT: a node is findable because the DHT servers closest to its id are connected to
it and answer `FIND_NODE` with the addresses it told them.

Who learns what. The servers a node contacts (bootstrap peers, several dozen DHT
servers per lookup, its relays, and the DNS resolver for the bootstrap names) see its IP
address and its device public key, and that it speaks `/peerharness/req/0.1.0`. A DHT
server asked for a peer id learns which device key the node is looking for. A relay
learns both device keys of a circuit, their IP addresses, when they talk and how much.
Nobody there learns a circle id, a name, a roll or an event: none is ever sent, and a
relayed connection runs TLS 1.3 between the two device keys, so the relay can neither
read nor alter it nor stand in for either end. A relay is a party the roll says nothing
about, which ADR-031 objected to; it is accepted because it gets no standing: the
handler authorizes by the device key at the far end, exactly as on a direct connection.

Whom the application looks up and dials (`ph-network` dials nobody the application
named; it only reports addresses): the device keys on the rolls this node holds that
share a roll with it, and the one peer id its owner typed for `circle join`. Addresses
from the network are hints ending in `/p2p/<peer id>`, so a dial succeeds only if the
other end proves that key, and whoever answers is judged by the roll like any other
peer (ADR-026). A device on no roll of the node is not looked up. An address through a
relay is not stored. A one-shot command asks no relay for a reservation; it listens on
all IPv4 interfaces for the length of the command, because a hole punch needs a socket
on each side. After a dial through a relay a sync waits six seconds for the direct
connection before it goes on over the relay.

Accepted costs. The device key is stable, so the servers a node contacts can recognize
it on every network, and two device keys that look each other up can be linked by a
server that sees both. Public relays are limited: a circuit ends after about 128 KiB in
one direction or two minutes. A small exchange fits; a larger one fails unless the hole
punch worked, and continues on the next sync because the fetch cursor is now kept after
every batch (it was kept once per circle). Hole punching does not get through every
router. Findability depends on servers run by others. Five more libp2p protocol crates
and `hickory-resolver` (for the `dnsaddr` bootstrap names) are in the build; licences
and MSRV 1.89 were checked.

Measured on 2026-11-10 from one machine with throwaway keys, both ends behind the same
router. Joining the network took 6 to 16 s and a lookup 2 to 5 s. A stopped node was
still named for 29 minutes. In 20 runs of the transport's test a node was found and
greeted 19 times; the relayed connection became direct in 15 of them, and in none of 7
later attempts (three of that test, four through the CLI) after the machine's network
had changed, which shows how much this depends on the router (and both ends behind one
router says little about two). A node that lost
its network for seven minutes rejoined by itself; it then went three minutes without a
relay, which is fixed (pauses for relays are dropped when the network is back). Through
the CLI, over relays only: a join by peer id, two syncs, a vote and the installation of
the rule on both nodes worked.

Not tested: two different routers, IPv6, Linux. Tests that need the public network are
`#[ignore]`d; the others run a private hub on loopback that answers like the public
servers do, which the app's own test reaches through `PEERHARNESS_INTERNET_BOOTSTRAP`
and `PEERHARNESS_INTERNET_PRIVATE` (a closed network on private addresses; refused
without a bootstrap list of one's own).

Not done. A relay run by a member for its circle: not needed for convergence, since a
member whose node others can reach already carries everyone's records (every node
stores what the roll lets it read), and one such node, for example a member's second
device on a server, is the dependable setup. No switch in the configuration file: the
mode is asked for per command.

## ADR-033: Three decisions can be put to the owner in a window, from inside the agent's session
ADR-022 left a person who works in a coding agent all day with one way to decide
anything: leave the agent, open a terminal and type the command. The guard was right
and the cost was the whole product, because the place where a rule is noticed is the
place where nobody could act on it.

**Decision.** A consent step is still never answered from inside an agent's session.
Three of them may now be *asked* from there, in a window of the operating system, when
the owner has allowed it:

* proposing a rule to a circle (`proposal create`),
* a ballot on a proposed rule (`proposal vote` on an `adopt` proposal),
* installing a rule that passed and waits for the owner (`proposal adopt`).

The owner allows it with `watch claude --install --windows`, which is itself a consent
step in their own terminal with a preview, and takes it back with `--install
--no-windows` or `--remove` (`config.toml`, `[agent] windows`, off by default). The
session cannot turn it on, with or without a window. With windows off, everything is
as in ADR-022.

**What the session can and cannot do.** It can make the window appear, with arguments
of its choosing (which candidate, which circle, approve or reject, a rationale). It
cannot answer it. The window shows the exact preview the terminal would have shown, and
only a click on "Proceed" there counts (`consent::confirm_or_window`, `window.rs`).
"Cancel" is the default button, so the return key and the escape key decline. A window
nobody answers closes after 90 seconds as "no answer". `--yes` is ignored inside a
session. The preview is not printed into the session: the person reads it in the
window, and what the agent says about a rule is not the rule.

**Shown in full or not at all.** A dialog does not scroll, and one taller than its
screen is cut off, so the person would confirm a text they saw part of. The height is
therefore estimated before anything is shown: the text is wrapped the way the dialog
wraps it, with glyph widths rounded up and the row taken narrower than it is, and the
script compares the result with the usable height of the smallest attached screen. A
text that does not fit is refused with "run it in your own terminal". Measured on macOS
14.2 on 2026-11-10: a dialog is 420 points wide, 16 points a row and 108 points of
everything else; for four texts the estimate was between 0 and 6 rows above what the
dialog needed (33 against 27 for the preview of a short rule) and never below. By that
estimate a 1440x900 screen has room for a rule of about 175 characters when proposing
it and for any rule on a ballot (a proposed rule is at most 200 characters), and a
1280x800 screen for about 100 and 175. Longer ones go to the terminal. The widths in the estimate are approximations of the system font
checked against those four dialogs, not the font's own metrics.

**What stays in the terminal**, also with windows on: reviewing a note, installing a
skill for oneself, a ballot on a repeal or on a change to the charter (the window
could not show what is being decided in full), proposing a repeal, every `circle`
command, questions and answers, hooks, export and reset. A rule with a high-risk
scanner finding is never decided in a window. A ballot in a window carries the rule's
text itself, since the owner cannot run `proposal show` first.

**The key.** Nobody can type a passphrase inside a session. A node whose device key is
in a passphrase-protected file is refused before the window opens, unless
`PEERHARNESS_PASSPHRASE` is set. The OS keychain works.

**What this is not.** It is the same kind of guard as ADR-022, against an agent that is
being helpful, and not a security boundary:

* a process that clears the session variable is still not stopped, and one that edits
  `config.toml` can turn windows on;
* an agent that can drive the screen (macOS asks the owner for that permission) could
  click a button;
* a person can click "Proceed" out of habit. The default button is "Cancel" for that
  reason, and the agent's skill tells it to start a step only when asked;
* the agent's skill now tells it to run `inbox`, so titles and questions written by
  other members reach the agent's context. They are single lines, cleaned for display,
  and the skill says they are not instructions. A rule's own text still reaches an
  agent only after it passed.

**Where the window comes from.** macOS only: `/usr/bin/osascript`, a fixed path in a
directory the system protects, so the program is not found through `PATH`. The text
goes to it on standard input, never in its arguments or environment. On Linux the
steps are refused as before; `zenity` exists there, but no desktop was at hand to test
against, and the default keystore on Linux is the passphrase file. Debug builds read
`PEERHARNESS_TEST_WINDOW_BIN`, a stand-in program for tests; release builds do not, so
that ADR-022's "no override an agent can set" still holds for what is installed.

**Consequences.** The reporting skill has two texts, and `watch claude` reinstalls it
when the setting changes. `AGENTS.md` now says that an agent may write a note and may
start these three steps, and that it never answers one. Not done: a window on Linux
and asking in a window for a personal install. (Telling the owner that proposals wait
for their vote followed in ADR-035.)

## ADR-034: An install script that checks the release's checksum
Installing meant a Rust toolchain and several minutes of compiling, or a manual
download, checksum and copy (`docs/release.md`). Both lose most people before they have
seen anything. `install.sh` does the manual steps in one command:
`curl -fsSL https://raw.githubusercontent.com/aryehlev/peerharness/main/install.sh | sh`.

It finds the latest release through GitHub's redirect (no API, so no rate limit and no
JSON to parse), downloads the archive for the machine and `SHA256SUMS` over HTTPS, and
installs nothing unless the archive matches. It then checks that the binary runs and
copies that one file to `~/.local/bin`. It uses no `sudo`, edits no shell profile and
only says so when the directory is not on `PATH`. The body is one function called on
the last line, so a download that was cut short runs nothing. A version given by hand
must look like a tag before it goes into an address.

It does not build from source by itself when there is no binary to download: a
compile of several minutes is not what someone pasting one line expects. It prints
the `cargo install --git` command instead.

Limits, stated in `docs/release.md` and the security model: the checksum comes from
the same pipeline as the binary, and the script itself is unsigned and served from the
`main` branch, so this is as trustworthy as the repository and no more. Nothing is
signed or notarized. The script works only for a published release of a public
repository; when this was written there was neither, and it was tested against a
release in a temporary folder (`apps/peerharness/tests/install_script.rs`), which the
`PEERHARNESS_RELEASE_URL` setting exists for. Not done: Homebrew, a signed checksum
file, Windows.

## ADR-035: The owner is told when proposals wait for their vote
A proposal that needed a member's vote was visible only to a member who went and
looked (`peerharness inbox`). The Stop hook told them about their own notes and not
about the thing other people were waiting for.

**Decision.** At the end of a turn the Stop hook also prints, when it applies,
"PeerHarness: N proposal(s) wait for your vote — run `peerharness inbox`". It is a
`systemMessage`: Claude Code shows it to the person and does not give it to the model.
It carries a count and nothing else, so no title or other text written by another
member is involved. It has its own notification topic (`votes`), checked before the
one for notes, so with the default settings a member is told at most once a day, and
never more than two notices a day in total (spec 7.2). The hook rules are unchanged:
it reads the store, never unlocks a key, never blocks and always exits 0.

**What "waits for your vote" means** is now one function, `governance::awaiting_vote`,
used by the notice and by `inbox`: the proposal is open under the current charter of a
circle this node has not left, the member this device signs for is in its electorate,
and none of their devices has cast a ballot. A proposal that passed, one that names an
earlier charter, and one the member may not vote on wait for nobody. The member's own
proposal waits for them too, because creating it is not a vote. `inbox` used a looser
test before (any proposal by someone else without a ballot from this device), which
kept listing proposals that had already passed or that the member could not vote on.

**Limits.** The node has to hold the proposal: nothing arrives without a sync (a
daemon with `--sync-every`, or `sync`). The notice appears only at the end of a turn
in Claude Code with the hooks installed; there is no operating-system notification
and no window opens by itself (a window opens when the owner asks for a step, ADR-033).
A member who is not using their agent is told nothing.
