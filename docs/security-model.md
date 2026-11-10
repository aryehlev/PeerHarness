# PeerHarness security model (v0.1)

This document describes what PeerHarness protects, against whom, how, and what it does
not protect. It is meant to be read before trusting PeerHarness with anything.

**No security audit has been done.** PeerHarness v0.1 is a demo-grade release written to
a specification, with automated tests but no independent review. It is not ready for
production or enterprise use. Arrange a separate security review before deploying it in
an organization.

Scope: the `peerharness` binary and its crates, protocol v0 (`docs/protocol-v0.md`), on
macOS and Linux. Windows is not supported. Mitigations at the library level are
implemented in the crates named in each entry. Statements about CLI and daemon behaviour
describe the v0.1 command and daemon contract for `apps/peerharness`. At this revision
the local commands, the governance commands and the transport (`daemon`, `connect`,
`sync`) are wired and exercised end to end: signed events travel as a file, as a
directory of record files, or between separate processes over QUIC. A file or directory
of exported events contains the circle's roll and proposals in clear; whoever can read
it can read them, so it must be given only to members.

## 1. Assets

| asset | where it lives | why it matters |
|---|---|---|
| device private key | keystore: OS keychain (`os`), Argon2id + XChaCha20-Poly1305 encrypted file (`file`), or plaintext file (`insecure-dev`, explicit opt-in only) | whoever holds it *is* that member of every circle the device joined |
| circle root private key | the founder's keystore only; never transmitted | whoever holds it issues access credentials and revocations and notarizes charter changes. It cannot change the roll or the voting rules without a passed vote (4.16) |
| charter (voting rules and roll) | every member's `peerharness.db`, CHARTER events | decides who may vote and how many approvals pass a rule |
| keystore passphrase | the user's head, a prompt, or `PEERHARNESS_PASSPHRASE` | unlocks the `file` keystore |
| local observations | `peerharness.db` (SQLite, 0600) and the hook spool, local only, 14-day retention by default | redacted copies of the user's prompts to their coding agent |
| candidates and skill drafts | `peerharness.db` | derived from observations; may reveal working habits |
| circle metadata | `peerharness.db`, invite files | circle names, member handles and device keys, scopes, question text, skill titles, who voted how |
| received and shared content | event log, bundle store | questions, answers, proposals, votes, skills |
| installed skills and agent settings | `~/.claude/skills/`, `./.claude/skills/`, `~/.claude/settings.json` | they change what the coding agent does |
| daemon control token | `daemon.json` (0600) while the daemon runs | lets a local process drive the daemon |
| export file | wherever `peerharness export --local --out` writes it | contains observation text and drafts |

PeerHarness never stores private key bytes in SQLite. The SQLite database itself is
**not encrypted**: it relies on file permissions (home 0700, files 0600) and on the
operating system's disk encryption.

## 2. Trust boundaries

1. **Coding agent hook to PeerHarness.** Claude Code runs `peerharness hook <event>` and
   passes a JSON payload on stdin. The payload is untrusted input.
2. **Local CLI to the local daemon.** The CLI talks to its own daemon over loopback TCP
   (`127.0.0.1`), authenticated by a 256-bit token stored in `daemon.json` (0600).
3. **Network to node.** Anyone who can reach the QUIC port can connect. Before proving
   membership they are untrusted.
4. **Circle member to node.** An authenticated member is trusted only within the roles
   and scopes of its root-signed credential, re-checked on every request. For voting, a
   device is trusted only as the member the charter's roll says it signs for, and only
   in the electorates that member belongs to.
5. **Received content to human and agent.** Received questions, rationales and skills are
   untrusted text shown to a human and, once installed, read by an AI agent.
6. **PeerHarness to an advisory provider.** Optional `claude -p`, `codex exec` or an
   Ollama-compatible endpoint receive text PeerHarness sends them.
7. **PeerHarness to the file system.** Skill installation and hook installation write
   into agent directories and settings files.
8. **PeerHarness to the keystore.** The OS keychain or the encrypted key files.

## 3. Adversaries

From specification section 11, plus a few that follow from the design:

* a **malicious P2P client** that connects without membership;
* a **malicious or curious circle member** (including one trying forged membership,
  stolen or duplicated votes, or access outside their scope), and a **group of members**
  below or above the voting threshold;
* **former members** whose keys were on an earlier roll;
* a **network attacker** who can observe, replay, delay or inject traffic;
* a **spammer or DoS attacker**;
* an attacker with a **stolen or compromised device**;
* an attacker who supplies **malicious content**: a skill with prompt injection, a
  bundle with traversal paths or scripts, a malicious hook payload, untrusted repository
  content;
* the **circle founder / root-key holder** acting against members' interests;
* an **LLM** (local or remote) whose output is wrong or adversarial;
* a **remote inference vendor** that receives advisory requests.

## 4. Threats, mitigations and residual risk

Each entry gives the threat, the mitigation, and the risk that remains.

### 4.1 Malicious P2P client without membership

* **Threat.** A peer connects to a node and tries to read circle data or metadata, or to
  inject events.
* **Mitigation.** Only `hello` gets a real answer, and it is the same generic answer for
  everyone. A peer is answered further only if its transport-authenticated device key is
  on the roll of the current charter of the circle its request concerns, checked again
  on every request (`apps/peerharness/src/peer.rs`, `ph_governance::RollOracle`). Every
  other request gets `error{unauthorized}`, identical whether the circle exists or not.
  A syncing node sends nothing that names a circle to a peer it does not share that
  circle with. Pushed events are taken only for circles the pusher is a member of and
  must then pass signature, schema, time and authorship checks (`ph-protocol`,
  `ph-governance::authorize_incoming`); who pushed an event gives it no standing.
  Requests are strictly parsed with size and depth limits before any handler runs
  (`ph-network`). There is no discovery: no mDNS, DHT or gossip, so a node is not
  advertised.
* **Residual risk.** An attacker who can reach the port learns that a PeerHarness node
  listens there, its `PeerId` (device public key) and the protocol version. Parser or
  libp2p/QUIC bugs are possible; the wire parser has property and adversarial tests, but
  no fuzzing campaign or audit has been done.

### 4.2 Forged membership

* **Threat.** An attacker fabricates a credential, alters one, or uses someone else's to
  join a circle or impersonate a member.
* **Mitigation.** The circle id is a hash of the root public key, and every credential
  must be signed by exactly that root key (`circle_id == derive(issuer_key)`). A
  credential is active only with an acceptance signed by the subject device key. Proofs
  presented on the wire are accepted only when the subject equals the device key bound to
  the TLS-authenticated libp2p connection. Possessing an invite file or a credential is
  useless without the subject's private device key. Joining shows the root fingerprint
  and requires confirmation; scripted joins need `--expect-fingerprint`.
  For access over the transport and for voting, the membership statement is the roll of
  the charter, which changes only by a passed amendment. A credential, even a genuine
  one signed by the root key, gives no transport access by itself (ADR-026).
* **Residual risk.** The human fingerprint check is the only link between a root key and
  the real organization. A user who joins a circle from a forged invite without checking
  the fingerprint out of band joins the attacker's circle (this does not compromise the
  real circle, but the user may then share content with the attacker). Fingerprints are
  80 bits, enough for human comparison but not a cryptographic commitment.

### 4.3 Stolen or duplicated votes, invented voters

* **Threat.** Replaying a ballot to count it twice, moving a ballot to a different
  proposal, voting from several devices, or inventing device keys to reach a threshold.
* **Mitigation.** Every ballot is signed and names one `proposal_id`, which is the hash
  of the whole signed proposal, so it counts only for exactly what was proposed
  (including the bundle digest) and only if its envelope scope equals the proposal's. A
  ballot counts only from a device on the **roll** of the charter the proposal names,
  for a member in the proposal's electorate. Ballots are counted **per member**: any
  number of devices and any number of ballots of one member are one approval. A repeated
  event id is counted once. A proposal passes only with approvals from more than the
  charter's threshold of the whole electorate, never fewer than a strict majority
  (`ph_protocol::Threshold`, `ph-governance::tally`). A RESULT is only a list of ballots:
  a node counts exactly the listed ballots itself, and a certificate padded with a
  second ballot of the same member, a dissent, a non-member's ballot or a ballot for
  another proposal is rejected (`verify_result`). The roll changes only through a passed
  amendment (4.20), so keys cannot be added to it unilaterally, not even by the root.
* **Residual risk.** A ballot signed with a stolen device key is indistinguishable from
  a real one until the key is revoked, and it counts on nodes that have not yet learned
  of the revocation (4.9). A majority of the electorate can pass any rule; a passed rule
  is not a safe rule (4.10). The roll lists member handles, and nothing in the protocol
  proves that two handles are two people: the members who vote to admit someone are the
  check (section 5). Thresholds are fractions of the whole electorate, so members who
  never vote make everything harder to pass.

### 4.4 Unauthorized scope access

* **Threat.** A member authorized for `team/frontend` requests `team/finance` objects.
* **Mitigation.** Scope coverage is exact (`*`, equality, or a `/`-separated prefix; no
  other wildcard). `fetch_events` returns a QUESTION, ANSWER or scoped decision event
  only when the requester has `read` on its scope; `fetch_bundle` serves a bundle only if
  a stored `adopt` PROPOSAL with that digest is readable by the requester; outgoing
  pushes and the outbox are filtered the same way at send time. A member whose roll
  entry does not cover a scope is not in that scope's electorate and cannot propose or
  vote there. No vote, result or charter widens read access: the read rules never look
  at a ballot (`ph-governance::read`).
* **Residual risk.** Control-plane events (MEMBERSHIP, REVOCATION, CHARTER) are readable
  by every active member regardless of scope, so every member learns every other
  member's handle, device keys, roles, scopes and credential expiry, and who was revoked
  and why (the revocation `reason`). Decision events with scope `*` (every amendment to
  the charter, and every circle-wide rule) and their ballots are readable by every
  active member too, since everyone votes on them. Scopes partition content, not the
  member list, and not circle-wide decisions. Read access itself is granted by
  root-issued credentials, not by vote (4.16).

### 4.5 Peer impersonation

* **Threat.** An attacker claims to be another member's node.
* **Mitigation.** The libp2p identity is the device key itself; QUIC with the libp2p TLS
  handshake proves possession of it, and the `PeerId` maps to exactly one device key
  (non-canonical and small-order keys are rejected). Dialing an address with
  `/p2p/<PeerId>` requires the handshake to prove that identity. Authorization looks at
  the authenticated device key, never at claimed identifiers.
* **Residual risk.** None at the protocol level beyond key theft (4.6). The mapping from a
  device key to a person rests on the invitation process (section 5).

### 4.6 Compromised or stolen device

* **Threat.** Malware on a member's machine, or a stolen laptop.
* **Mitigation.** Private keys are stored in the OS keychain or in an Argon2id
  (64 MiB, 3 passes) plus XChaCha20-Poly1305 encrypted file with 0600 permissions; the
  plaintext keystore requires an explicit flag and warns on every unlock. Short member
  credentials (30 days by default) and revocation by the root limit how long a stolen key
  stays useful.
* **Residual risk.** **A compromised endpoint cannot be defended against.** Malware
  running as the user can read the database, the spool, the daemon token, an unlocked
  key in memory, `PEERHARNESS_PASSPHRASE` from the environment, and anything the agent
  sees. A stolen device with an unlocked session, a keychain that opens without a prompt,
  or a weak passphrase gives the thief that member's identity, **including their vote**,
  until revocation reaches every peer: approvals signed with the stolen key count on
  each node until that node learns of the revocation. If the **founder's** device is
  compromised, the attacker holds the root key. They cannot change the roll or pass
  rules with it (4.16), but they can issue access credentials, revoke devices and stall
  charter changes, and there is no root key rotation or recovery in v0, so the circle
  must be abandoned and recreated. The SQLite database is not encrypted at rest.

### 4.7 Spam and denial of service

* **Threat.** Floods of connections, requests, oversized frames, or questions.
* **Mitigation.** Frames are capped at 512 KiB, rejected from the length prefix before
  reading the body, with body buffers that grow only as bytes arrive. Per-peer token
  buckets (20 requests/s, burst 40, 512 KiB/s) and at most 8 concurrent inbound requests;
  connection caps (4 per peer, 256 total, 64 handshaking); a shared 32 MiB budget for
  inbound request bodies. Questions from members are limited to 20 per author and 100 per
  circle per day by default, deduplicated, with local mute and block. Unsolicited
  notifications are limited to 2 per day with a per-topic cooldown.
* **Residual risk.** Device keys cost nothing to create, so per-peer limits do not stop an
  attacker who uses many keys; the global caps then protect the node's memory but can
  starve legitimate peers of connection slots. There is no IP-level limiting. A member
  can still annoy others within the quotas. Nothing protects against volumetric attacks
  on the network itself.

### 4.8 Replay of old messages

* **Threat.** Re-sending an old event, an expired credential, or an old revocation state.
* **Mitigation.** Every event has a unique id (the hash of its signed content) and the
  local store enforces uniqueness, so a replay is a no-op `duplicate`. Events carry a
  creation time (at most 5 minutes in the future, except for revocations), an expiry
  and a random nonce. Expired QUESTION, ANSWER and MEMBERSHIP events and expired
  credentials are rejected at the receiver's local time, and request authorization is
  evaluated on every request, never cached. Decision events (PROPOSAL, VOTE, RESULT),
  CHARTER and REVOCATION are permanent on purpose: replaying one changes nothing,
  because an approval cannot be counted twice or withdrawn, a proposal counts only under
  the charter it names, and an old charter can never follow the current one.
* **Residual risk.** Time checks use the local clock. A node with a badly wrong clock may
  accept expired credentials, questions and answers or reject valid ones; the outcome of
  a vote does not depend on any clock. A valid event relayed by another member is
  accepted by design (relaying is how sync works).

### 4.9 Stale revocation while offline

* **Threat.** A revoked member keeps access, or keeps voting, because some nodes have
  not heard of the revocation.
* **Mitigation.** Revocations are signed by the root, sent as REVOCATION events to all
  active members, returned by `fetch_events` to every active member regardless of scope,
  and take effect immediately on each node that learns of them (the revoked peer is
  disconnected, nothing more is pushed to it, new decision events from it are refused
  and its ballots stop being counted). A revocation is a permanent record: it never
  expires and is served by sync indefinitely. It is also never refused for its date: a
  revocation only ever denies, so one from an issuer whose clock runs ahead is accepted
  at once, and stored revocations are not dropped when the local clock steps back
  (ADR-017). Member credentials are short-lived (30 days by default), which bounds the
  access a revocation that never arrives leaves open.
* **Residual risk.** **Offline partitions limit revocation freshness.** A node that has
  not synced with a node that knows the revocation keeps serving the revoked key until it
  does, or until the credential expires, and keeps counting that device's ballots. Nodes
  that learn of a revocation at different times can therefore disagree about whether an
  open proposal has passed; they converge at the next charter change, when the carried
  rule list becomes the rule set everywhere. Revoking a device does not remove its
  member from the roll: that takes a vote. Revocation does not claw back anything already
  delivered (section 5).

### 4.10 Prompt injection via received skills

* **Threat.** A received `SKILL.md` instructs the coding agent to exfiltrate secrets, run
  remote shells, or ignore previous instructions.
* **Mitigation.** v0 skills are one instruction-only Markdown file, never executed by
  PeerHarness. Two ways a single `SKILL.md` can still make Claude Code act without the
  model deciding to are refused outright in every bundle, local or received, by exact
  syntactic rules that no flag or vote overrides (`ph_skills::check_instruction_only`,
  ADR-018): an `allowed-tools` frontmatter key, which pre-approves tools, and
  shell-injection syntax in the body, which runs a command when the skill loads. The
  frontmatter parser rejects every key outside a short allowlist. Beyond that, skills
  are strictly validated and scanned by an advisory risk scanner (credential requests,
  `curl | sh`, reverse shells, exfiltration endpoints, "ignore previous instructions",
  hidden Unicode, long encoded blobs, destructive commands and more). What then happens
  to a rule that passed a vote is the owner's standing choice
  (`ph-governance::adoption_step`): in `ask` mode nothing is installed without an
  explicit confirmation; in `follow` mode a passed rule is installed without asking,
  **except** that a high-risk scanner finding always requires the owner's confirmation,
  an opt-out always wins, and a bundle that fails its digest or validity check is never
  installed. Installation is reversible (uninstall and rollback touch only managed
  files).
* **Residual risk.** **High.** Once installed, a skill is instructions the agent follows.
  The scanner is heuristic and easy to evade with paraphrase; scanning never proves
  safety. In a circle whose charter is binding, a node that follows it installs whatever
  a majority of the electorate approves, without its owner reading it first: **a
  majority of the members can put instructions into every following member's agent.** A
  majority approving a rule says nothing about whether it is safe. The owner's controls
  are choosing `ask` mode, opting out of a rule, a local policy, and leaving the circle.
  The instruction-only rule covers the two Claude Code mechanisms we know of; other
  agents, or future versions, may treat other syntax as executable.

### 4.11 Archive and path traversal

* **Threat.** A bundle with `../`, absolute paths, backslashes, hidden files, symlinks,
  duplicate or extra files, or an install target that is a symlink.
* **Mitigation.** A received bundle must be exactly one file named exactly `SKILL.md`
  (at most 256 KiB, UTF-8, no NUL) whose digest matches the PROPOSAL; everything else is
  rejected before anything touches the disk. The bundle store and installer refuse
  symlinks, FIFOs and non-regular files, open files with `O_NOFOLLOW`, stage installs in
  a temporary directory and rename atomically, never overwrite an unmanaged directory
  without `--force-overwrite-unmanaged`, and confine project-scope installs to the
  project root.
* **Residual risk.** Low for the v0 single-file format. Races with another local process
  that is actively manipulating the same directories are not fully excluded.

### 4.12 Unexpected script execution

* **Threat.** Received content causes code to run.
* **Mitigation.** v0 distributes only `SKILL.md`; no scripts, assets or executables are
  accepted from peers, and nothing in PeerHarness executes skill content. A bundle that
  pre-approves tools (`allowed-tools`) or carries shell-injection syntax is refused
  (4.10). The only
  programs PeerHarness spawns are the optional advisory providers (`claude`, `codex`),
  chosen by the local user, run with tools disabled, in an empty temporary directory,
  with the keystore passphrase removed from their environment.
* **Residual risk.** The coding agent may run commands that an installed skill tells it
  to (4.10). The provider binary is whatever `PEERHARNESS_CLAUDE_BIN`,
  `PEERHARNESS_CODEX_BIN`, the config or `PATH` points to; an attacker who controls those
  already controls the user's environment.

### 4.13 Transcript and secret exfiltration

* **Threat.** Prompts, transcripts, source code, secrets or tool output leave the device.
* **Mitigation.** The hook never opens `transcript_path`, keeps only bounded, redacted
  prompt text locally, and stores nothing for tool failures but the tool name. Nothing
  leaves the device automatically: only text the human saw in an exact preview and
  confirmed is placed in QUESTION, ANSWER or PROPOSAL bodies or bundles, and redaction
  runs before the preview. Question and skill drafts are built from extracted tokens and
  fixed templates, not from raw prompt text. Logs, error messages and `Debug` output
  carry ids and counts only. Joining a circle never uploads existing local data, and no
  protocol request fetches observations.
* **Residual risk.** Redaction is heuristic (section 5). A human can approve text that
  contains sensitive information. The local database and the export file contain
  observation text. Advisory providers are a deliberate, opt-in egress path (section 5).

### 4.14 Malicious local hook payload

* **Threat.** A crafted hook payload on stdin tries to crash PeerHarness, make it read
  files, inject into the agent's context, or block the agent.
* **Mitigation.** Input is capped at 1 MiB and parsed leniently; no path from the payload
  is ever opened; the hook always exits 0, never blocks, and prints nothing for
  `UserPromptSubmit` (whose stdout would become model context). The installed hook
  command quotes its paths for `sh`. Settings changes are idempotent, backed up and
  written atomically.
* **Residual risk.** Anyone who can write the user's Claude settings or invoke the hook
  as the user already controls the agent. The hook stores (redacted) prompt text that
  the agent was given, including text pasted from untrusted sources.

### 4.15 Untrusted repository content

* **Threat.** A repository contains text designed to trigger false "conventions", or
  directories designed to subvert installation.
* **Mitigation.** The detector reads only the user's own prompts, never repository files,
  and every candidate needs human review before it becomes a local skill or is shared.
  The repository path is reduced to a hashed `repo_key`. Project-scope installs are
  confined to the project root and refuse symlinked components.
* **Residual risk.** A user who pastes repository content into a prompt can produce a
  candidate from it; review is the control. PeerHarness does not defend against the
  agent itself being manipulated by repository content.

### 4.16 Root-key holder and circle administrator

* **Threat.** The founder (root-key holder) abuses their position.
* **Mitigation.** Administering a circle gives no access to members' local data: there
  is no request type for observations, candidates or local skills, and joining never
  uploads them. The root key has **no vote** (it is not on the roll) and **cannot change
  who votes or the voting rules**: every charter after a node's first is accepted only
  if a passed amendment justifies it, with content equal to what was voted on
  (`ph-governance::check_successor`). A root-signed charter that adds a key, drops a
  member or changes a threshold on its own is rejected by every node. The founder is one
  member with one vote, whatever the number of their devices. Every node computes every
  outcome itself, and an owner can always opt out of a rule or choose to be asked.
* **Residual risk.** The root-key holder still has real power in v0:
  * **It cannot grant access, but it can take it away.** Who a node answers on the
    transport is the roll, so the root cannot let anyone read the circle by signing a
    credential (ADR-026). It can still revoke any device: peers that hold the revocation
    stop answering that device, and its ballots stop counting (the member stays in the
    electorate, so this makes proposals harder to pass, never easier).
  * **It can block.** It can refuse to notarize a passed amendment, which freezes the
    roll and the voting rules. Rules can still be proposed, passed and repealed.
  * **It can split.** If two conflicting amendments both pass, it chooses one; if it
    signs two successors of one charter, nodes that saw different ones first diverge.
  * **Founding bias.** The founder alone admits the second member, and those two admit
    the third. The early roll is whatever the founder made it.
  * **Trust anchor.** A node that joins later takes its first charter, and the list of
    rules that charter carries, on the root's signature.

  There is no root key rotation, recovery or leaderless ratification yet.

### 4.17 LLM-generated decisions, and the agent acting for its user

* **Threat.** A model's output is treated as consent or authorization, or a coding
  agent that has a shell runs the commands that approve, share, vote or install.
* **Mitigation.** Detectors and advisory providers only suggest text. Their output never
  drives authorization, state transitions, votes, sharing or installation, and never
  counts as a human action; human-only lifecycle transitions are enforced in
  `ph-core::transition`. An agent may write a note (`peerharness note --from-agent`),
  which is a candidate in the inbox and nothing more, and at most 20 unreviewed agent
  notes are kept. Every consent step refuses inside an agent session, with or without
  `--yes` (architecture 12.1). A cancelled or refused command saves nothing.
* **Residual risk.** A human can be persuaded by a model's wording. The deterministic
  detector can be wrong; it never claims more than medium confidence. The agent-session
  check reads environment variables: an agent that clears them, or one that sets none,
  is not stopped by it, and what remains is that consent needs a terminal or an explicit
  `--yes`. An agent running as the owner can also edit the skills directory and the
  database directly, and can use a device key whose keystore unlocks without the owner
  (section 4.6). These rules protect against accidents and against other people. They
  do not protect an owner from their own compromised session.

### 4.18 Other local users and processes

* **Threat.** Another process or user on the same machine reads PeerHarness files or
  interferes with a running daemon.
* **Mitigation.** The home directory is 0700 and its files 0600. The daemon has no
  control endpoint: it takes no commands from anything, local or remote, and only answers
  the peer protocol on its QUIC listener. `daemon.json` holds the listen addresses and
  no secret. One daemon per home is enforced by a file lock.
* **Residual risk.** Any process running as the same user can read the files, the
  database and, depending on the keystore, the keys (section 4.6). Root or an
  administrator on the machine can read everything.

### 4.19 Supply chain and releases

* **Threat.** A malicious or vulnerable dependency, or a tampered download.
* **Mitigation.** `Cargo.lock` is committed and every build uses `--locked`; CI runs
  `cargo deny` (licenses, sources, advisories) and `cargo audit`. Releases publish
  `SHA256SUMS` (`docs/release.md`).
* **Residual risk.** Checksums detect corruption and mirror tampering, not a compromised
  repository, CI pipeline or GitHub account: they are published by the same pipeline.
  Binaries are not code-signed and macOS binaries are not notarized.

### 4.20 Governance by vote

* **Threat.** A minority, a single member, former members or the founder impose or block
  rules; nodes reach different outcomes from the same votes; an outcome changes after
  the fact.
* **Mitigation.** A circle's rules of the vote and its roll of members are one signed
  charter that every node holds (`ph_protocol::Charter`). A proposal names the charter
  it is voted under and passes only with approvals from more than that charter's
  threshold of the members entitled to vote on it, counted per person. No member has a
  veto: `reject` and `revise` are recorded dissent. Approvals cannot be withdrawn, so
  "passed" never reverts, and counting reads no clock and does not depend on arrival
  order: two nodes holding the same ballots compute the same result
  (`ph-governance::tally`). The charter changes only through a passed amendment that
  carries the complete next roll, rules and list of carried rules, and a node's rule set
  after a change is exactly that list, so nodes converge. A proposal counts only under
  the **current** charter: members who have left cannot pass anything by signing under
  an old one, even if together they were a majority of it (the "long-range" case), and
  an amendment cannot be replayed onto a later charter.
* **Residual risk.**
  * **Founder liveness and equivocation** (4.16): no charter change without the root
    holder; a root that signs two successors can split a circle.
  * **Turnout.** Not voting counts as not approving. An absent member makes every
    threshold harder to reach, and removing them is itself a vote. In a circle of two,
    both must approve everything.
  * **Compromised device window** (4.6, 4.9): its approvals count until each node
    learns of the revocation.
  * **A majority decides.** Members outvoted on a rule still get it in a binding circle
    unless they opt out (4.10). A majority can also remove a member.
  * **Votes are public to the circle.** Ballots are signed and attributable, like a
    roll call. There is no secret ballot.
  * **Identity.** The roll counts handles. Whether two handles are two people is judged
    by the members who vote to admit them.
  * **Growth.** Decision events are permanent and v0 never prunes them; sync describes
    at most 4096 known events per request.

## 5. Privacy limitations

These are limits of the design, not bugs, and they apply even when everything works as
intended.

* **Sanitization is heuristic.** `ph_core::redact` replaces common secret shapes (API
  keys, tokens, private key blocks, JWTs, passwords in URLs, `key=value` secrets,
  high-entropy strings) and home-directory paths. It misses secrets it does not
  recognize, and it cannot recognize sensitive information that is not secret-shaped
  (customer names, internal hostnames, plans). The exact preview and the human's
  judgement are the real control.
* **Authorized recipients can copy content.** Encrypted transport protects content in
  transit only. Any member who may read a question, proposal or skill can copy it,
  screenshot it, or forward it outside PeerHarness.
* **Revocation does not claw back data.** Revoking a member stops future delivery from
  nodes that know of the revocation. Everything the member already received stays with
  them. Nothing can be remotely erased.
* **Offline partitions limit revocation freshness.** Revocation spreads only through
  sync. Until a node hears of it, that node keeps serving the revoked key (4.9).
* **A compromised endpoint or stolen device cannot be defended against.** PeerHarness
  runs with the user's privileges on the user's machine. Malware or a thief with access
  to an unlocked session sees what the user sees (4.6).
* **A device key does not prove human identity.** A credential binds roles to a device
  key, and the roll binds device keys to a member handle. Whether a key belongs to the
  person you think rests on the invitation process, an out-of-band fingerprint check and
  the members who voted to admit that handle. One person's several devices are one vote,
  but nothing in the protocol stops a circle from admitting the same person under two
  handles. A key can be shared, and a device can be re-enrolled with a new key.
* **The root-key holder is still a single point of authority for access in v0.** It
  alone issues and revokes the credentials that let a device read, and it can stall
  charter changes. It cannot change the roll or the voting rules, or pass a rule, alone
  (4.16).
* **Votes are visible to the circle.** Every member who may read a proposal sees who
  approved it and who dissented, with their rationale. Circle-wide (`*`) decisions and
  all charter amendments are visible to every member.
* **The advisory providers are remote inference.** `claude -p` (Claude Code) and
  `codex exec` (Codex CLI) send the previewed text to their vendor's service under the
  user's own account; that vendor's data handling then applies. They are off by default
  and require both a config opt-in and a per-invocation exact preview with confirmation.
  An Ollama-compatible endpoint is local only when it is on loopback; non-loopback
  endpoints are refused unless explicitly allowed, and are then remote too.
* **Metadata is visible to members and partly to the network.** Members see the member
  list, including each member's handle, device keys and scopes on the roll (4.4). Network observers see IP addresses, ports, timing and traffic volume of
  QUIC connections, even though content is encrypted. Invite files contain the circle
  name, root key, addresses and the invitee's credential; treat them as sensitive.
* **Local data is stored in plaintext SQLite.** Observations (redacted prompt text) are
  kept for 14 days by default in a database protected only by file permissions and disk
  encryption.

## 6. Out of scope for v0

* Protection against a compromised operating system, user account or coding agent.
* Anonymity or unlinkability of members.
* Censorship resistance, cross-NAT connectivity, relays.
* End-to-end encrypted offline group storage, group rekeying (future, for example MLS).
* Charter changes without the root key as notary, root key rotation and recovery,
  voting on who gets read access, secret ballots.
* Windows.

## 7. Reporting vulnerabilities

See [`SECURITY.md`](../SECURITY.md). Please report privately; do not open public issues
for vulnerabilities.

## Test coverage

Where each group of threats is exercised. Paths are relative to the repository root.
Multi-node tests run separate processes of the real binary, over files, a shared
directory and QUIC on loopback.

| threats | tests |
|---|---|
| 4.1, 4.5, 4.7 (peers without membership, impersonation, limits) | `crates/ph-network/tests/network.rs`, `adversarial.rs`, `codec.rs`; `crates/ph-governance/tests/authz.rs`, `roll_oracle.rs`; `apps/peerharness/src/peer.rs` (unit tests of the request handler); `apps/peerharness/tests/network.rs` (separate processes over QUIC: a stranger, a node that claims a shared circle, a removed member); `apps/peerharness/tests/circle_vote.rs` (an outsider's node stores nothing) |
| 4.2, 4.9 (forged, expired or revoked membership) | `crates/ph-identity/tests/attacks.rs`, `membership.rs` |
| 4.3, 4.20 (stolen, duplicated or invented votes; counting; results; succession) | `crates/ph-governance/tests/tally.rs`, `result.rs`, `ruleset.rs`, `succession.rs`, `adversarial.rs`; `apps/peerharness/tests/circle_vote.rs`, `demo.rs` |
| 4.4, 4.16 (scope access, the root-key holder) | `crates/ph-governance/tests/authz.rs`, `succession.rs` |
| 4.6 (keys at rest) | `crates/ph-identity/tests/keystore.rs` |
| 4.8 (replay, malformed and oversized input) | `crates/ph-protocol/tests/adversarial.rs`, `proptests.rs`, `vectors.rs`; `crates/ph-store/tests/events.rs` |
| 4.10 to 4.12 (hostile skills, paths, script execution) | `crates/ph-skills/tests/malicious.rs`, `bundles.rs`, `install.rs`, `frontmatter_props.rs` |
| 4.13 (secrets and transcripts) | `crates/ph-core/src/redact.rs` (unit tests), `crates/ph-store/tests/privacy.rs`, `apps/peerharness/tests/local_loop.rs` |
| 4.14 (hook payloads, settings) | `crates/ph-observer/tests/hooks.rs`, `settings.rs`, `spool.rs` |
| 4.17 (model output, the agent acting for its user) | `crates/ph-learning/tests/providers.rs`, `drafts_and_assisted.rs`; `apps/peerharness/tests/local_loop.rs` |

Not covered by an automated test: 4.15 (untrusted repository content) beyond the
project-scope symlink checks in `crates/ph-skills/tests/install.rs`, 4.18 (other local
users: file modes are set, not tested against a second account) and 4.19 (supply
chain), which CI checks with `cargo deny` and `cargo audit`.
