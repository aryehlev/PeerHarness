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
of exported events contains the circle's roll, its proposals and ballots, and its
questions, answers and recorded stances in clear; whoever can read it can read them, so
it must be given only to members.

## 1. Assets

| asset | where it lives | why it matters |
|---|---|---|
| device private key | keystore: OS keychain (`os`), Argon2id + XChaCha20-Poly1305 encrypted file (`file`), or plaintext file (`insecure-dev`, explicit opt-in only) | whoever holds it *is* that member of every circle the device joined |
| circle root private key | the founder's keystore only; never transmitted | whoever holds it can revoke any device and notarizes charter changes. It cannot change the roll or the voting rules without a passed vote, and a credential it signs gives nobody access or a voice (4.16) |
| charter (voting rules and roll) | every member's `peerharness.db`, CHARTER events | decides who may vote and how many approvals pass a rule |
| keystore passphrase | the user's head, a prompt, or `PEERHARNESS_PASSPHRASE` | unlocks the `file` keystore |
| local observations | `peerharness.db` (SQLite, 0600) and the hook spool, local only, 14-day retention by default | redacted copies of the user's prompts to their coding agent |
| candidates and skill drafts | `peerharness.db` | derived from observations; may reveal working habits |
| circle metadata | `peerharness.db`, exported event files and directories | circle names, member handles and device keys, scopes, question and answer text, skill titles, who voted how, who put an opt-out on record |
| received and shared content | event log, bundle store | questions, answers, proposals, votes, skills |
| installed skills and agent settings | `~/.claude/skills/`, `./.claude/skills/`, `~/.claude/settings.json` | they change what the coding agent does |
| known peers and sync cursors | `peerharness.db` | which devices this node exchanges with, at which addresses, and how far each exchange got. A daemon with a sync interval dials these addresses unattended (4.26) |
| export file | wherever `peerharness export --local --out` writes it | contains observation text and drafts |

PeerHarness never stores private key bytes in SQLite. The SQLite database itself is
**not encrypted**: it relies on file permissions (home 0700, files 0600) and on the
operating system's disk encryption.

## 2. Trust boundaries

1. **Coding agent hook to PeerHarness.** Claude Code runs `peerharness hook <event>` and
   passes a JSON payload on stdin. The payload is untrusted input.
2. **Local CLI and the local daemon.** They do not talk to each other: the daemon has
   no control endpoint (4.18). Both open the same home directory, and a file lock allows
   one daemon per home.
3. **Network to node.** Anyone who can reach the QUIC port can connect. A peer whose
   transport-authenticated device key is on no roll the node holds is untrusted and is
   told nothing.
4. **Circle member to node.** A peer whose device key is on the roll of the current
   charter is trusted only within the scopes of its roll entry, re-checked on every
   request. For voting, a device is trusted only as the member the charter's roll says
   it signs for, and only in the electorates that member belongs to. A device that was
   on an earlier roll is trusted with one thing: the record of its own removal (4.22).
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
  circle with. The answer to `authenticate` names circles only to a device that is on
  their roll, so a device on no roll that asks to join (4.21) gets the same
  `unauthorized` and learns no circle id. Pushed events are taken only for circles the
  pusher is a member of and must then pass signature, schema, time and authorship checks
  (`ph-protocol`, `ph-governance::authorize_incoming`); who pushed an event gives it no
  standing.
  Requests are strictly parsed with size and depth limits before any handler runs
  (`ph-network`). By default a node is not advertised: there is no DHT and no gossip,
  and discovery on the local network is off unless the owner turns it on (4.27), as is
  the internet mode (4.28).
* **Residual risk.** An attacker who can reach the port learns that a PeerHarness node
  listens there, its `PeerId` (device public key) and the protocol version. Parser or
  libp2p/QUIC bugs are possible; the wire parser has property and adversarial tests, but
  no fuzzing campaign or audit has been done.

### 4.2 Forged membership

* **Threat.** An attacker fabricates a credential, alters one, or uses someone else's to
  join a circle or impersonate a member.
* **Mitigation.** The circle id is a hash of the root public key, and every credential
  must be signed by exactly that root key (`circle_id == derive(issuer_key)`). A
  credential is active only with an acceptance signed by the subject device key.
  Possessing an invite file or a credential is useless without the subject's private
  device key. The reference node goes further and decides nothing by credential: it
  neither sends nor accepts proofs on the wire. For access over the transport, for
  asking and answering questions, and for voting, the membership statement is the roll
  of the charter, which changes only by a passed amendment. A credential, even a genuine
  one signed by the root key, gives none of these (ADR-026, ADR-027). Joining, from a
  file or from a member's node, shows the root fingerprint and requires confirmation;
  scripted joins need `--expect-fingerprint`.
* **Residual risk.** The human fingerprint check is the only link between a root key and
  the real organization. A user who joins a circle from a forged file, or from a hostile
  node (4.21), without checking the fingerprint out of band joins the attacker's circle
  (this does not compromise the real circle, but the user may then share content with
  the attacker). Fingerprints are 80 bits, enough for human comparison but not a
  cryptographic commitment.

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
  only when the requester has `read` on its scope; `fetch_bundle` serves a bundle only
  if a stored `adopt` PROPOSAL with that digest is readable by the requester; outgoing
  pushes are filtered the same way at send time. A sync cursor only selects where a
  responder starts; it is not an authorization. A member whose roll entry does not cover
  a scope is not in that scope's electorate and cannot propose, vote, ask, answer or
  record a stance there. No vote, result or charter widens read access: the read rules
  never look at a ballot (`ph-governance::read`).
* **Residual risk.** Control-plane events (MEMBERSHIP, REVOCATION, CHARTER) are readable
  by every active member regardless of scope, so every member learns every other
  member's handle, device keys and scopes, and who was revoked and why (the revocation
  `reason`). Decision events with scope `*` (every amendment to
  the charter, and every circle-wide rule) and their ballots are readable by every
  active member too, since everyone votes on them. Scopes partition content, not the
  member list, and not circle-wide decisions. Read access follows the roll, which
  changes only by vote; the root key cannot grant it (4.16). A file or directory of
  exported events is not filtered by scope: it holds everything the exporting node has
  for the circle.

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
  plaintext keystore requires an explicit flag and warns on every unlock. The founder
  can revoke a lost or stolen device at once (`circle revoke`, 4.16), which stops it
  from syncing and from being counted on every node that learns of it, and the members
  can vote to replace the device or remove the member.
* **Residual risk.** **A compromised endpoint cannot be defended against.** Malware
  running as the user can read the database, the spool, the daemon token, an unlocked
  key in memory, `PEERHARNESS_PASSPHRASE` from the environment, and anything the agent
  sees. A stolen device with an unlocked session, a keychain that opens without a prompt,
  or a weak passphrase gives the thief that member's identity, **including their vote**,
  until revocation reaches every peer: approvals signed with the stolen key count on
  each node until that node learns of the revocation. If the **founder's** device is
  compromised, the attacker holds the root key. They cannot change the roll, pass rules
  or give anyone access with it (4.16), but they can revoke any device and stall charter
  changes, and there is no root key rotation or recovery in v0, so the circle must be
  abandoned and recreated. The SQLite database is not encrypted at rest.

### 4.7 Spam and denial of service

* **Threat.** Floods of connections, requests, oversized frames, or questions.
* **Mitigation.** Frames are capped at 512 KiB, rejected from the length prefix before
  reading the body, with body buffers that grow only as bytes arrive. Per-peer token
  buckets (20 requests/s, burst 40, 512 KiB/s) and at most 8 concurrent inbound requests;
  connection caps (4 per peer, 256 total, 64 handshaking); a shared 32 MiB budget for
  inbound request bodies. Only a device on the roll, within its scopes, can author a
  question at all (4.23). Questions are then limited to 20 per author and 100 per circle
  per day by default: one over a quota, or from an author the owner muted, is kept and
  not shown; the same text asked again gets no second entry; a blocked author's question
  is not stored. A sync is paged by a cursor and keeps at most 8192 events aside in
  memory while it waits for records they depend on. Unsolicited notifications are
  limited to 2 per day with a per-topic cooldown, and hold a count only: a member who
  floods the circle with proposals changes a number in one daily notice (ADR-035).
  The desktop notifications of `daemon --notify` are off unless asked for, also hold
  a count only, are shown once per proposal, at least 60 seconds apart and for at
  most 10 proposals a day (ADR-036).
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
  and take effect immediately on each node that learns of them (the revoked device is
  refused from its next request on, nothing more is pushed to it, new decision events,
  questions, answers and stances from it are refused, its ballots stop being counted and
  it gets no removal notice, 4.22). A revocation is a permanent record: it never
  expires and is served by sync indefinitely. It is also never refused for its date: a
  revocation only ever denies, so one from an issuer whose clock runs ahead is accepted
  at once, and stored revocations are not dropped when the local clock steps back
  (ADR-017).
* **Residual risk.** **Offline partitions limit revocation freshness.** A node that has
  not synced with a node that knows the revocation keeps serving the revoked key until it
  does, and keeps counting that device's ballots. Nothing else bounds that window: an
  entry on the roll does not expire. Nodes
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
  confined to the project root and refuse symlinked components. A member can have the
  rules of one scope installed in a single project directory instead of for every
  project (`circle place`, ADR-030): the directory comes from the owner's command line,
  never from a hook payload or a peer, choosing it is a confirmation step, and the
  installer is confined to that directory, so a linked `.claude` in an untrusted
  checkout is refused. Nothing about the placement is shared or voted.
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
  outcome itself, and an owner can always opt out of a rule or choose to be asked. A
  credential signed by the root key lets nobody read, ask, answer or vote (ADR-026,
  ADR-027).
* **Residual risk.** The root-key holder still has real power in v0:
  * **It can cut off any device, alone.** This is the one thing the founder decides
    without a vote. `circle revoke` signs a revocation of a device key with the root
    key. There is no vote, no appeal and no undo: that key can never be used in the
    circle again. Peers that hold the revocation stop answering the device, refuse what
    it signs from then on, and stop counting its ballots, including ones it cast before.
    The limits are these. A revocation can block and never pass: the member stays on
    the roll and in every electorate, so removing an approval makes a proposal harder
    to pass, never easier, and a rule that was in force only with that approval may stop
    being in force on nodes that learn of it. It does not change the roll: removing the
    member, or giving them a new device, takes a vote. It cannot grant anything. The
    command refuses to revoke the device it runs on, which guards against an accident,
    not against the holder. A founder can use it against any member's device at any
    time, and the members' only answers are to vote (the founder has one vote) or to
    found another circle.
  * **It can block.** It can refuse to notarize a passed amendment, which freezes the
    roll and the voting rules. Rules can still be proposed, passed and repealed.
  * **It can split.** If two conflicting amendments both pass, it chooses one; if it
    signs two successors of one charter, nodes that saw different ones first diverge.
  * **Founding bias.** The founder alone admits the second member, and those two admit
    the third. The early roll is whatever the founder made it.
  * **Trust anchor.** A node that joins later takes its first charter, and the list of
    rules that charter carries, on the root's signature.
  * **It stays indispensable after leaving.** A founder who leaves the roll (4.24)
    still holds the root key. Members' nodes no longer sync with the founder's node, so
    every later charter change needs the passed amendment carried to that node as a
    file and the new charter carried back.

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
  `--yes` (architecture 12.1): among them asking and answering a question, announcing a
  stance, leaving a circle, proposing an amendment, revoking a device, placing a scope's
  rules in a project and switching to `follow`. A cancelled or refused command saves
  nothing. Two things are deliberately not consent steps: switching to `ask`, and opting
  out of a rule on one's own machine, which is never refused.
* **Confirmation windows (ADR-033).** If the owner turned them on in their own terminal,
  three steps started inside a session are put to the person in a window of the
  operating system instead of being refused: proposing a rule, a ballot on a proposed
  rule, and installing a rule that passed. The session chooses the arguments and can
  make the window appear. It cannot answer it: only a click on "Proceed" counts,
  "Cancel" is the default, `--yes` is ignored, and the exact preview is shown in full
  or the step is refused. A rule with a high-risk finding is never decided in a window.
  Every other consent step refuses inside a session as before, including the one that
  turns windows on.
* **Windows for inviting and joining (ADR-037).** Three steps about who is in a circle
  can be asked the same way, under a setting of their own that the same command turns
  on after previewing all six steps: proposing to admit a member, a ballot on an
  amendment that admits one member and changes nothing else, and joining a circle.
  Windows that were turned on before these steps existed do not cover them. The window
  shows the device fingerprint or the root fingerprint and the whole charter, taken
  from the signed content and not from a title, and says to check it with the other
  person. Inside a session `circle invite` writes no file with the circle's records.
  Removing a member, leaving, changing the rules of the vote, devices, revoking and
  every other ballot on the charter still refuse inside a session.
* **The MCP server (ADR-038).** `peerharness mcp` offers an agent eleven fixed tools.
  It adds no way to consent: each tool runs the command as a child process marked as
  an agent's session, whatever environment the server was started in, so every
  consent step is asked in a window or refused as above. Arguments are checked values
  and are never passed on as flags. A tool runs only if the owner allowed that level
  in their own terminal, which also holds for the tools that are not consent steps
  (`status`, `inbox`, founding a circle, the exchange, the daemon). What it does add:
  an agent that was given the tools can start the exchange and the daemon on the
  public network without a window, once the owner allowed the circle steps and read,
  in that preview, what the network's servers see.
* **Residual risk.** A human can be persuaded by a model's wording. The deterministic
  detector can be wrong; it never claims more than medium confidence. The agent-session
  check reads environment variables: an agent that clears them, or one that sets none,
  is not stopped by it, and what remains is that consent needs a terminal or an explicit
  `--yes`. An agent running as the owner can also edit the skills directory and the
  database directly, and can use a device key whose keystore unlocks without the owner
  (section 4.6). These rules protect against accidents and against other people. They
  do not protect an owner from their own compromised session. With confirmation windows
  on, three more things hold. The agent decides when a window appears and what it asks,
  so a person can be worn down into clicking "Proceed"; the text in the window is
  exact, and reading it is the person's part. An agent that can drive the screen could
  click the button; macOS asks the owner before it lets a program do that. And the
  agent's skill then tells it to read the inbox, so single-line titles and questions
  written by other members reach its context before any vote; the text of a rule still
  reaches an agent only after the rule passed. With the windows for inviting and
  joining, a click decides more than a rule: whoever is admitted gets a vote and reads
  the circle's records, and joining a circle with binding rules installs its rules for
  the person's agent, the ones in force at once. An agent that was talked into
  starting a join cannot finish it, since the other circle must already have admitted
  this device and the person must click "Proceed" in a window that names the circle's
  fingerprint and roll. A person who clicks out of habit is not protected by that.
  Device keys, peer ids and fingerprints reach the command through the agent, so the
  window's fingerprint is the thing to compare with what the other person said.

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
  `SHA256SUMS` (`docs/release.md`). The install script (`install.sh`, ADR-034)
  downloads over HTTPS only, installs nothing unless the archive matches the release's
  checksum, never runs as root and writes one file.
* **Residual risk.** Checksums detect corruption and mirror tampering, not a compromised
  repository, CI pipeline or GitHub account: they are published by the same pipeline.
  Binaries are not code-signed and macOS binaries are not notarized. Piping the install
  script into a shell runs whatever the `main` branch holds at that moment: it is as
  trustworthy as the repository and no more, and it can be downloaded and read first.

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
  * **Growth.** Decision events and recorded stances are permanent and v0 never prunes
    them. Sync is paged by a cursor and no longer stalls on a large log, but every node
    keeps all of it.

### 4.21 Joining from a member's node

* **Threat.** A device that is not a member uses the join exchange to learn which
  circles a node holds, or a node gets a joining device to accept a circle its owner
  did not mean.
* **Mitigation.** A node names its circles only in the answer to `authenticate`, and
  only to a device whose key is on their roll. A device on no roll that asks to join
  gets `unauthorized` and learns nothing: not a circle id, not whether any circle
  exists there. An admitted device is on the roll, so it was already entitled to the
  circle's records; the answer adds the circle id it lacked. Before its owner has
  confirmed anything, the joining node sends a greeting, an announcement that carries no
  address, and fetches that name only circle ids the peer itself just named. It stores
  nothing until the owner has seen the charter, its roll and the root fingerprint and
  confirmed. A scripted join needs `--expect-fingerprint`, and a fingerprint that
  differs is a refusal. After that every fetched record passes the same checks as a
  record from a file (signature, roll, charter succession).
* **Residual risk.** The fingerprint is the only link to the circle the owner means
  (4.2). Device keys are not secret, so a hostile node at the address can offer a circle
  of its own whose charter lists the joiner's key. An owner who confirms without
  comparing the fingerprint out of band joins that circle. The node at the address
  learns the joiner's device key and IP address from the connection, as any dialed node
  does. Joining needs a node that has already accepted the charter listing the device;
  one that has not answers `unauthorized`, which looks the same as not being admitted.

### 4.22 The removal notice

* **Threat.** The one case in which a node answers a device that is not a member is
  used to read what the circle did after a removal, by a device that was never a
  member, or by a device that was cut off because it was compromised.
* **Mitigation.** This is a deliberate and narrow exception to "a peer is answered
  because it is on the current roll" (ADR-028). It applies to one request type,
  `fetch_events`, from a device that the node's own records show on the roll of an
  earlier charter, that is not on the current roll and is not revoked. The answer is a
  fixed set: the CHARTER events up to the first charter that no longer lists the device,
  and for each of them the amendment, the ballots on that amendment and the result that
  justify it (`peer::farewell`). The device could read every one of those records as a
  member, and the removing charter is word for word the amendment it could vote on, so
  nothing it could not already have read is disclosed. No later charter is in it, so no
  later roll; no rule proposal, question, answer or stance; and no rule text, because
  every other request from the device is still `unauthorized`. A device that was never
  on a roll the node holds, and a revoked device, get `unauthorized` as before. The
  asking node does not take the peer's word: it verifies the charter as a successor of
  the one it holds, justified by a result it counts itself, and only then treats itself
  as removed and takes out the rules that circle had installed.
* **Residual risk.** A removed member learns that the amendment passed, who approved it
  and who dissented (the ballots were attributable to it already), and that the
  responder still holds the circle. A member who was removed for cause is answered this
  way too unless the device is also revoked: to cut a device off completely, revoke it.
  A node that never held a charter listing the device cannot give the notice, so a
  removed member may be refused by some peers without explanation. The notice is not
  pushed: a removed node learns of its removal only when it next asks, and follows the
  circle's rules on its own machine until then.

### 4.23 Questions and answers

* **Threat.** A device that is not a member, or a member outside a scope, puts questions
  or answers into a circle; someone takes part on the strength of a credential the
  founder signed without a vote; a member floods the others with questions.
* **Mitigation.** The author of a QUESTION or ANSWER must be a device on the roll of the
  circle's current charter whose roll entry covers the event's scope, and not revoked
  (`ph_governance::RollOracle`, ADR-027). A founder-issued credential no longer lets
  anyone ask or answer, just as it gives no access on the transport. An answer must
  name a stored question in the same circle and scope. The text that leaves the machine
  is exactly what the preview showed, after redaction, and asking or answering is a
  consent step that refuses inside an agent's session (4.17). Received questions pass a
  local guard (4.7). An answer is an opinion on the record and is never counted: a rule
  still needs a proposal and a majority.
* **Residual risk.** These events are judged against the charter each node holds when
  they arrive, so nodes that hold different charters at that moment can differ on
  whether they keep one. Questions and answers are signed and attributable, readable by
  every member whose roll entry covers the scope, and by anyone who can read an exported
  file or shared directory. They expire after 30 days and are not served afterwards, but
  copies stay in the logs that received them. Quotas, mute and block are local: a
  member can still send each other member 20 questions a day.

### 4.24 Leaving a circle

* **Threat.** A member is kept following a circle's rules against their will, or
  leaving is used to change the roll without a vote.
* **Mitigation.** `circle leave` acts on the owner's machine at once: the rules that
  circle installed are removed and none of its rules is installed there again, whatever
  the roll says. Nobody's agreement is needed for that. Separately it puts the owner's
  removal to the vote, with their approval. The roll changes only if that amendment
  passes, like any other: a unilateral exit would be a second way to change the roll,
  with a threshold other than a majority (ADR-027).
* **Residual risk.** Until the members approve, the leaver is still on the roll. They
  count in every electorate, which makes thresholds harder to reach; their device key
  can still read, sync and vote; and their approval of their own removal cannot be
  withdrawn, although they can follow the circle again on their machine. A sole member
  cannot leave. A founder who leaves the roll still holds the root key, and later
  charter changes then depend on files carried to and from that node (4.16).

### 4.25 Recorded opt-outs (STANCE)

* **Threat.** A stance is forged in another member's name, is used to change the
  outcome of a vote, is forced out of a member who wanted to opt out quietly, or stands
  between an owner and their own machine.
* **Mitigation.** A STANCE is signed by its author's device and accepted only from a
  device on the roll of the charter it names, for a member the rule's scope concerns,
  about a stored `adopt` proposal in the same circle and scope; a revoked device's
  stance is refused and its earlier ones are no longer shown. Nothing reads a stance:
  no count, result, rule set or installation changes because of one (ADR-029).
  Publishing one is voluntary. It happens only with `--announce`, after a preview of the
  exact record and a confirmation, and it refuses inside an agent's session. The opt-out
  on the machine does not wait for any of that: it has already happened when the prompt
  appears and stays if the announcement is refused.
* **Residual risk.** A published stance is permanent and attributable. Every member who
  may read the rule sees it, with the reason given, and so does anyone who can read an
  exported file. Publishing an opt-out is a disclosure the member chooses, and it cannot
  be taken back, only followed by a later stance. The record is incomplete by design: a
  member who opted out without announcing is not on it, and a stance says nothing
  verifiable about what is installed on anyone's machine. The current stance is chosen
  by the author's own `created_at`, which the author controls within the usual bounds;
  that affects only how their own stance is displayed.

### 4.26 Syncing with known peers, and on a timer

* **Threat.** A node that syncs unattended is made to contact addresses of an
  attacker's choosing, or sends circle data to a peer its owner never approved.
* **Mitigation.** `sync` without an argument and `daemon --sync-every` dial only
  addresses the node has stored, and it stores only addresses its owner dialed. The
  addresses a peer announces in `authenticate` are not kept, so a member cannot point
  another member's node at an address of its choosing. No address comes from an event,
  and none from discovery unless the owner turned that on (4.27). Each of those syncs is the ordinary session: the node
  sends a greeting, and nothing that names a circle unless the answering device key is
  on a roll the node holds. Only signed events travel, each previewed and confirmed by
  its author when it was created. The timer is off unless the owner starts the daemon
  with it, and its interval is at least 30 seconds.
* **Residual risk.** A daemon that syncs on a timer signs results, and on the founder's
  node new charters, without its owner present, as it already does when it answers.
  Regular dialing is visible to network observers. A stored address that has since
  passed to another party receives a QUIC handshake and, if it answers, a greeting,
  which shows it the node's IP address and device key; nothing more is sent unless the
  answering key is on a shared roll.

### 4.27 Discovery on the local network

* **Threat.** An observer on the local network identifies or tracks PeerHarness nodes; a
  host on the segment feeds a node false announcements, to be dialed or to hide a
  member; a node contacts strangers it heard.
* **Mitigation.** Discovery is off unless the owner asks for it with `--lan`; without it
  no multicast socket exists and nothing is sent (ADR-031). With it, a node announces
  its device public key and its listen addresses under the generic libp2p service name,
  and nothing about circles, members or rules. A node without a listen address on the
  network (a `sync` client, a daemon on loopback) announces an empty record: it finds
  others without being found. What is heard is a hint and nothing more: `ph-network`
  only reports it, never dials it and keeps it out of its address book, and holds at
  most 256 peers with 8 addresses each. The application dials only a device key that is
  on a roll it holds, at an announced address that names that key, so the handshake
  must prove the key; whoever answers is then judged by the roll like any other peer
  (4.1). A device on no roll of the node is never dialed and is sent nothing.
* **Residual risk.** The device key is stable, so an announcing device can be
  recognized on every network it joins, and matched to a member by anyone who holds a
  roll that lists it, a former member included. Other libp2p software on the network
  sees the node and may connect; it gets `hello` and nothing else. mDNS is
  unauthenticated: any host on the segment can fill the list or keep a member out of
  it, which costs discovery and nothing else, and can announce a member's key at an
  address of its choosing, to which the node then sends a handshake that fails unless
  the answerer holds that key. IPv4 only.

### 4.28 Internet mode: the public libp2p network

* **Threat.** Servers run by strangers identify, track or profile PeerHarness nodes; a
  DHT server lies about where a device is, to be dialed in its place, to hide a member
  or to send the node somewhere; a relay reads, alters or injects traffic, or stands in
  for a member; strangers reach a node that was only reachable by address before; a
  remote party makes a node use memory, connections or log space without bound.
* **Mitigation.** The mode is off unless the owner asks for it with `--internet`;
  without it none of its protocols is spoken or answered and no DNS lookup is made
  (ADR-032). With it, the node is a client: it never serves the DHT, never relays and
  never dials back for others, and it stores nothing in the DHT. It sends that network
  its device public key, a fixed agent string, the protocols it speaks and its
  confirmed public or relay addresses, never a listen address on a private network and
  nothing about circles, members or rules. An answer to a lookup is a hint: only
  addresses with a public IP are kept, at most 16 with one server's share capped at
  half, and every one ends in the peer id that was asked for, so a dial succeeds only
  if the other end proves that device key in the TLS handshake. The same handshake runs
  through a relay, between the two ends: a relay cannot read or change the stream or
  answer for a member, and gives a peer no standing. `ph-network` dials no peer the
  application named; the application looks up and dials only device keys that share a
  roll with it (and the peer id its owner typed for `circle join`), and whoever answers
  is judged by the roll like any other peer (4.1). A stranger who finds a node gets
  `hello` and nothing else, as before. An own address is tested only when three peers
  agree on it. Routing table, lookups in flight, reservations, address candidates and
  the connections the node opens on its own are bounded, and the limits of 4.7 apply
  to relayed connections too. The libp2p crates log addresses, so their log output is
  discarded while the mode is on; the node logs ids and counts.
* **Residual risk.** The device key is stable: every server a node contacts can
  recognize the device on any network and tie it to an IP address, and anyone who holds
  a roll that lists the key, a former member included, can look it up and learn the IP
  address or relays of a member whose daemon is in the mode. A server that sees lookups
  can link device keys that look each other up, which reveals that they belong
  together, though not to what. The identify record says the node is a PeerHarness
  node. Servers that lie or go away can keep a member from being found, which costs
  reachability and nothing else. A relay sees who talks to whom, when and how much.
  While a daemon is in the mode, strangers anywhere can connect to it (and get `hello`
  only), so the rate limits of 4.7 are what stands between it and a flood; a one-shot
  command is exposed the same way for as long as it runs. Public relays end a circuit
  after about 128 KiB or two minutes, so where the hole punch fails only small
  exchanges get through. Hole punching between two different routers, IPv6 and Linux
  are untested; the dependency surface grew by the DHT, identify, AutoNAT, relay and
  DCUtR implementations of libp2p and a DNS resolver (4.19).

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
* **The root-key holder is still a single point of authority in v0.** It alone can cut
  a device off, without a vote, and it can stall charter changes. It cannot give anyone
  access, change the roll or the voting rules, or pass a rule, alone (4.16).
* **Votes are visible to the circle.** Every member who may read a proposal sees who
  approved it and who dissented, with their rationale. Circle-wide (`*`) decisions and
  all charter amendments are visible to every member. A member who was voted off is
  shown the ballots of that vote once more (4.22).
* **Questions, answers and recorded opt-outs carry your name.** They are signed, and
  every member who may read their scope sees who asked, who answered what, and who put
  an opt-out on record and why. A recorded opt-out never expires (4.25). An opt-out
  that is not announced stays on your machine.
* **The advisory providers are remote inference.** `claude -p` (Claude Code) and
  `codex exec` (Codex CLI) send the previewed text to their vendor's service under the
  user's own account; that vendor's data handling then applies. They are off by default
  and require both a config opt-in and a per-invocation exact preview with confirmation.
  An Ollama-compatible endpoint is local only when it is on loopback; non-loopback
  endpoints are refused unless explicitly allowed, and are then remote too.
* **Metadata is visible to members and partly to the network.** Members see the member
  list, including each member's handle, device keys and scopes on the roll (4.4), and
  the addresses a member's node announces when it syncs. Network observers see IP
  addresses, ports, timing and traffic volume of QUIC connections, even though content
  is encrypted; a daemon that syncs on a timer shows a regular pattern (4.26), one
  started with `--lan` announces its device key and port to the local network (4.27),
  and one started with `--internet` shows its device key and IP address to servers of
  the public libp2p network, along with the device keys it looks up (4.28).
  Invite
  files contain the circle name, root key, addresses and the invitee's credential; treat
  them as sensitive.
* **Local data is stored in plaintext SQLite.** Observations (redacted prompt text) are
  kept for 14 days by default in a database protected only by file permissions and disk
  encryption.

## 6. Out of scope for v0

* Protection against a compromised operating system, user account or coding agent.
* Anonymity or unlinkability of members.
* Censorship resistance, cross-NAT connectivity, relays.
* End-to-end encrypted offline group storage, group rekeying (future, for example MLS).
* Charter changes without the root key as notary, root key rotation and recovery,
  revocation by vote, leaving a roll without a vote, secret ballots.
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
| 4.1, 4.5, 4.7 (peers without membership, impersonation, limits) | `crates/ph-network/tests/network.rs`, `adversarial.rs`, `codec.rs`; `crates/ph-governance/tests/authz.rs`, `roll_oracle.rs`; `apps/peerharness/src/peer.rs` (unit tests of the request handler; `a_cursor_pages_through_a_log_larger_than_the_known_list`: a log larger than the `known` list, and a cursor that does not widen what is read); `apps/peerharness/tests/network.rs` (separate processes over QUIC: a stranger, a node that claims a shared circle, a device on no roll that asks to join); `apps/peerharness/tests/circle_vote.rs` (an outsider's node stores nothing) |
| 4.2, 4.9 (forged, expired or revoked membership) | `crates/ph-identity/tests/attacks.rs`, `membership.rs`; `apps/peerharness/tests/circle_life.rs` (`the_founder_cuts_off_a_lost_device_and_the_roll_stays_as_voted`: only the founder's node and only a person can revoke, not its own device; the roll and the electorate are unchanged; the device's ballots stop counting, new ones are refused by every node that knows, and its own node stops signing once it knows) |
| 4.3, 4.20 (stolen, duplicated or invented votes; counting; results; succession) | `crates/ph-governance/tests/tally.rs`, `result.rs`, `ruleset.rs`, `succession.rs`, `adversarial.rs`; `apps/peerharness/tests/circle_vote.rs`, `demo.rs` |
| 4.4, 4.16 (scope access, the root-key holder) | `crates/ph-governance/tests/authz.rs`, `succession.rs`; `apps/peerharness/tests/circle_life.rs` (the revocation test above) |
| 4.6 (keys at rest) | `crates/ph-identity/tests/keystore.rs` |
| 4.8 (replay, malformed and oversized input) | `crates/ph-protocol/tests/adversarial.rs`, `proptests.rs`, `vectors.rs`; `crates/ph-store/tests/events.rs` |
| 4.10 to 4.12 (hostile skills, paths, script execution) | `crates/ph-skills/tests/malicious.rs`, `bundles.rs`, `install.rs`, `frontmatter_props.rs` |
| 4.13 (secrets and transcripts) | `crates/ph-core/src/redact.rs` (unit tests), `crates/ph-store/tests/privacy.rs`, `apps/peerharness/tests/local_loop.rs` |
| 4.14 (hook payloads, settings) | `crates/ph-observer/tests/hooks.rs`, `settings.rs`, `spool.rs` |
| 4.17 (model output, the agent acting for its user) | `crates/ph-learning/tests/providers.rs`, `drafts_and_assisted.rs`; `apps/peerharness/tests/local_loop.rs`; `apps/peerharness/tests/circle_life.rs` (refused inside an agent session: asking, answering and dismissing a question, switching to `follow`, leaving, revoking a device, announcing a stance, placing a scope); `apps/peerharness/tests/agent_windows.rs` (confirmation windows, with a stand-in window program: off until the owner turns them on, which a session cannot do; only "Proceed" decides, and a decline, no answer, an unknown answer, a failing or missing window program and a text too long to show all leave nothing behind; every other consent step is still refused with windows on; inviting, a ballot on a plain admission and joining are asked in a window only under their own setting, show the fingerprints from the signed content, leave nothing behind when declined, and write no events file from a session; removing, leaving, changing the rules of the vote and a ballot on any other amendment are still refused); `apps/peerharness/tests/mcp_server.rs` and the unit tests of `apps/peerharness/src/mcp.rs` (the MCP server, started without the session variables: a tool above what the owner allowed runs nothing, a consent step is declined or confirmed only by the stand-in window, an argument that begins with `-` and an unknown tool are errors, and the daemon a tool started stops when the client leaves); `apps/peerharness/src/window.rs` (unit tests: the height estimate against measured dialogs, the text read back exactly by the real `osascript` on macOS) |
| 4.19 (the install script) | `apps/peerharness/tests/install_script.rs` (against a release in a temporary folder: a matching checksum installs one file that runs; a changed archive, a missing checksum and a version that is not a tag install nothing) |
| 4.21, 4.22 (joining from a node, the removal notice) | `apps/peerharness/tests/network.rs` (separate processes over QUIC: a new member joins from a member's node, the wrong root fingerprint is refused and stores nothing, a device on no roll is offered nothing; a removed member's node is shown the vote, verifies it, drops the circle's rule, and can neither sync nor rejoin afterwards); `apps/peerharness/src/peer.rs` (`a_member_voted_off_is_told_of_the_vote_and_nothing_else`: the exact set of records, no later charter, every other request refused, a never-member and a revoked device refused) |
| 4.23 (questions and answers) | `apps/peerharness/src/governance.rs` (`questions_and_answers_are_authorized_by_the_roll`: a device on no roll, a member outside its scopes, a revoked device, an answer without its question or in another scope; `the_local_guard_keeps_noise_out_of_the_inbox`: duplicate, muted, blocked, over quota); `apps/peerharness/tests/circle_life.rs` (`a_question_is_asked_and_answered_by_members_of_the_roll`) |
| 4.24 (leaving, amendments, devices, the owner's mode) | `apps/peerharness/tests/circle_life.rs` (`a_second_device_new_rules_of_the_vote_the_owners_mode_and_leaving`: two devices of one member are one approval, the amend threshold, leaving acts locally at once and changes the roll only by vote) |
| 4.15 (placing a scope's rules in one project) | `apps/peerharness/tests/circle_life.rs` (`the_rules_of_a_scope_can_live_in_one_project`: only a person can place a scope; repeals and opt-outs act on the copy in the project; nobody else's machine changes) |
| 4.27 (discovery on the local network) | `crates/ph-network/tests/discovery.rs` (`discovery_is_off_by_default_and_then_nothing_is_reported` always runs; five tests that need multicast are `#[ignore]`d); `apps/peerharness/tests/network.rs` (`members_find_each_other_on_the_local_network`, `#[ignore]`d for the same reason) |
| 4.28 (internet mode) | `crates/ph-network/tests/internet.rs` (a private hub on loopback that answers like the public servers: off by default and then no further protocol is spoken; with the mode on the node serves nobody; a peer is found by its id, through a relay and at its own address; addresses from a lying server are filtered, bounded and never dialed; rate and connection limits hold for relayed peers; an exchange larger than a relay carries fails and says so; shutdown ends reservations and lookups; three tests against the public network are `#[ignore]`d), `internet_logs.rs` (no address in the log); `crates/ph-network/src/internet.rs` and `config.rs` (unit tests: which addresses count as public, the gate that keeps the node from dialing a peer the application named, the bounds, a loopback listener refused); `apps/peerharness/tests/network.rs` (`members_find_each_other_by_device_key_over_a_dht`, separate processes against that hub: a join by peer id, a sync that looks up the roll, a device on no roll is not looked up for a sync and is told nothing when it finds the node itself; `internet_mode_refuses_a_loopback_listener`) |
| 4.25 (recorded opt-outs) | `apps/peerharness/src/governance.rs` (`a_stance_is_a_record_by_a_member_of_the_roll_and_counts_for_nothing`); `apps/peerharness/tests/circle_life.rs` (`an_opt_out_can_be_put_on_the_circles_record`: voluntary, refused for an agent while the opt-out itself stands, open to a member admitted after the rule passed); `crates/ph-protocol/tests/vectors.rs` (the STANCE vector) |

Not covered by an automated test: 4.15 (untrusted repository content) beyond the
project-scope symlink checks in `crates/ph-skills/tests/install.rs`, 4.18 (other local
users: file modes are set, not tested against a second account), 4.19 (supply
chain), which CI checks with `cargo deny` and `cargo audit`, and of 4.26 the timer
itself: `sync` without an argument runs in `apps/peerharness/tests/network.rs`, while
`daemon --sync-every` has no test beyond argument parsing. The tests of 4.27 that
exercise real announcements need multicast on the local network and do not run in CI;
they are run by hand with `-- --ignored`. Of 4.28, nothing automated runs against the
public network in CI, and a hole punch between two different routers has not been
tried at all: the runs against the public network (ADR-032) were made from one machine.
