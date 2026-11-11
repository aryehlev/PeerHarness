# PeerHarness security model

This document describes what PeerHarness protects, against whom, how, and what it does
not protect. It is meant to be read before trusting PeerHarness with anything.

**No security audit has been done.** PeerHarness is a demo-grade, pre-1.0 project
written to a specification, with automated tests but no independent review. It is not
ready for production or enterprise use. Arrange a separate security review before
deploying it in an organization.

Scope: the `peerharness` binary and its crates, protocol v0 (`docs/protocol-v0.md`), on
macOS and Linux. Windows is not supported. Mitigations at the library level are
implemented in the crates named in each entry. Statements about CLI and daemon behaviour
describe the command and daemon contract of `apps/peerharness`. At this revision
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
| circle root private key | the founder's keystore only; never transmitted | whoever holds it can revoke any device, which also stops that device's earlier ballots from counting (4.16), and notarizes charter changes. It cannot change the roll or the voting rules without a passed vote, and a credential it signs gives nobody access or a voice (4.16) |
| charter (voting rules and roll) | every member's `peerharness.db`, CHARTER events | decides who may vote and how many approvals pass a rule |
| keystore passphrase | the user's head, a prompt, or `PEERHARNESS_PASSPHRASE` | unlocks the `file` keystore |
| local observations | `peerharness.db` (SQLite, 0600) and the hook spool, local only, 14-day retention by default | redacted copies of the user's prompts to their coding agent |
| candidates and skill drafts | `peerharness.db` | derived from observations; may reveal working habits |
| circle metadata | `peerharness.db`, exported event files and directories | circle names, member handles and device keys, scopes, question and answer text, skill titles, who voted how, who put an opt-out on record |
| received and shared content | event log, bundle store | questions, answers, proposals, votes, skills |
| installed skills and agent settings | `~/.claude/skills/`, `./.claude/skills/`, `~/.claude/settings.json` | they change what the coding agent does |
| known peers and sync cursors | `peerharness.db` | which devices this node exchanges with, at which addresses, and how far each exchange got. A daemon with a sync interval dials these addresses unattended (4.26) |
| export file | wherever `peerharness export --local --out` writes it | contains observation text and drafts, and the circles' signed records. The command is refused inside an agent's session (4.17) |

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
  scripted joins need `--expect-fingerprint`. A file or a shared directory can hold
  charters of more than one circle that list the joining device, because anyone who
  can write there can sign a charter of a circle of their own, with any number. The
  join then looks only at the circle with the expected root fingerprint, refuses when
  none has it, and without a fingerprint stops and asks for one: a charter's number
  never chooses between circles (ADR-043).
* **Residual risk.** The human fingerprint check is the only link between a root key and
  the real organization. A user who joins a circle from a forged file, or from a hostile
  node (4.21), without checking the fingerprint out of band joins the attacker's circle
  (this does not compromise the real circle, but the user may then share content with
  the attacker). A planted circle that is the only one in a file is shown like any
  other, with its fingerprint to check. Someone who can write to a shared directory
  can make a join without a fingerprint stop, by adding a second circle. Fingerprints
  are 80 bits, enough for human comparison but not a cryptographic commitment, and two
  root keys with the same fingerprint in one source are not told apart.

### 4.3 Stolen or duplicated votes, invented voters

* **Threat.** Replaying a ballot to count it twice, moving a ballot to a different
  proposal, voting from several devices, or inventing device keys to reach a threshold.
* **Mitigation.** Every ballot is signed and names one `proposal_id`, which is the hash
  of everything the proposer signed, so it counts only for exactly what was proposed
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
  for the circle. The way out for a node that lacks a rule its charter carries (4.29)
  is such a file, so it hands a member with limited scopes the records of the scope
  they are not sent.

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
  plaintext keystore requires an explicit flag, which a config file does not stand in
  for, and every command that uses a key from it says so on standard error, as
  `status` does. The weak parameters that the tests encrypt key files with
  (`fast-insecure-test`) are warned about in the same places, and `init` refuses both
  inside an agent's session. The founder
  can revoke a lost or stolen device at once (`circle revoke`, 4.16), which stops it
  from syncing and from being counted on every node that learns of it, and the members
  can vote to replace the device or remove the member.
* **Residual risk.** **A compromised endpoint cannot be defended against.** Malware
  running as the user can read the database, the spool, an unlocked key in memory,
  `PEERHARNESS_PASSPHRASE` from the environment, and anything the agent sees. A stolen
  device with an unlocked session, a keychain that opens without a prompt, or a weak
  passphrase gives the thief that member's identity, **including their vote**,
  until revocation reaches every peer: approvals signed with the stolen key count on
  each node until that node learns of the revocation. If the **founder's** device is
  compromised, the attacker holds the root key. They cannot change the roll, add an
  approval to anything or give anyone access with it (4.16), but they can revoke any
  device, which also reopens results that needed that device's ballot, and stall
  charter changes, and there is no root key rotation or recovery in v0, so the circle
  must be abandoned and recreated. The SQLite database is not encrypted at rest.

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
  is not stored. Both quotas count the questions that were shown, so a member who
  floods uses up their own day and a fifth of the circle's, and a question that was
  held back does not keep the same question from someone else out of the inbox
  (ADR-051). A sync is paged by a cursor and keeps at most 8192 events aside in
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
  the charter it names, and an old charter can never follow the current one. Records
  that arrive as a file or as a directory are parsed like a frame from the wire
  (`carrier::parse_record`, ADR-043): each line or record file goes through the strict
  parser under a limit of 1 MiB that is applied first, and must be an object with the
  one member a record has. A member stated twice at any level, a second member beside
  `event` or `bundle`, or a number that is not an integer makes it no record; it is
  counted as refused and the rest of the file is imported. The event inside is then
  held to the limits and checks of an event from a peer, which refuse an unknown
  member and an explicit `null` at every level.
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
  open proposal has passed, or whether one that had passed with that device's ballot
  still stands (4.16); they converge at the next charter change, when the carried
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
  shell-injection syntax anywhere in the file, which runs a command when the skill
  loads. Up to 0.4.0 that syntax was looked for at the start of a line and within one
  line only, and a fence in the middle of a sentence passed (ADR-051). The
  frontmatter parser rejects every key outside a short allowlist. Beyond that, skills
  are strictly validated and scanned by an advisory risk scanner (credential requests,
  `curl | sh`, reverse shells, exfiltration endpoints, "ignore previous instructions",
  hidden Unicode, long encoded blobs, destructive commands and more). Two of its
  high-risk rules are about what a rule can do to the vote itself (ADR-043): a text that
  tells the agent to fetch a URL and follow what it finds there, which could change
  after the text was voted on, and a text that gives an instruction about PeerHarness's
  own guard (the variables that mark an agent's session, `--yes`, its configuration).
  The findings are shown when a rule is kept or proposed, on a ballot asked in a window
  (which never carries a rule with a high-risk finding) and before an install that asks.
  A ballot in a terminal shows the proposal's title only: `peerharness proposal show`
  prints the rule's text, the number of findings and whether one is high-risk, not the
  findings themselves. (Inside a session it prints the text only of a rule that is
  installed on the machine, ADR-051.) What then happens to a rule that passed a vote is the owner's
  standing choice (`ph-governance::adoption_step`): in `ask` mode nothing is installed
  without an explicit confirmation; in `follow` mode a passed rule is installed without
  asking, **except** that a high-risk scanner finding always requires the owner's
  confirmation, an opt-out always wins, and a bundle that fails its digest or validity
  check is never installed. Installation is reversible (uninstall and rollback touch
  only managed files).
* **Residual risk.** **High.** Once installed, a skill is instructions the agent follows.
  The scanner is heuristic and easy to evade with paraphrase; scanning never proves
  safety. In a circle whose charter is binding, a node that follows it installs whatever
  a majority of the electorate approves, without its owner reading it first: **a
  majority of the members can put instructions into every following member's agent.** A
  majority approving a rule says nothing about whether it is safe. The owner's controls
  are choosing `ask` mode, opting out of a rule, a local policy, and leaving the circle.
  The instruction-only rule covers the two Claude Code mechanisms we know of, as one
  installed version of it looks for them; other agents, or future versions, may treat
  other syntax as executable. The two scanner
  rules above go by wording: the same instruction in other words, or with a URL that
  has no scheme, has no finding, and a harmless rule can have one (the scanner does
  not read negation, so "never pass --yes to peerharness" is found too). A rule that
  is already installed stays installed when a newer scanner finds something in it.

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
    The limits are these. A revocation adds no approval to anything: the member stays
    on the roll and in every electorate, so removing an approval makes a proposal
    harder to pass, never easier. It does not change the roll: removing the member, or
    giving them a new device, takes a vote. It cannot grant anything. The command
    refuses to revoke the device it runs on, which guards against an accident, not
    against the holder. A founder can use it against any member's device at any time,
    and the members' only answers are to vote (the founder has one vote) or to found
    another circle.
  * **A revocation reaches back to results that had passed.** Nothing latches a
    result: every count is made again from the ballots that still count. On each node
    that learns of the revocation, a proposal that had passed only with the revoked
    device's approval is open again. If it adopted a rule, the rule is no longer in
    force and is removed from the members' agents. If it was a repeal, the repeal
    lapses and the repealed rule is in force and installed again, also for members
    who voted to repeal it. So the founder, alone, can undo any result that passed by
    a margin of one, and this happens in the honest case of a lost laptop as well.
    Only proposals that passed under the current charter are counted again: a rule
    the current charter carries over stays (architecture 10.7).
    `crates/ph-governance/tests/adversarial.rs`
    (`founder_device_can_be_revoked_and_its_ballots_stop_counting`) shows the count
    changing, and the preview of `circle revoke` says "including ballots it already
    cast". Whether a revocation should reach back like this is an open decision,
    with its options in ADR-044.
  * **After a revocation, an import can leave a member on the old charter.** A
    decision event signed by a revoked device is refused for good by a node that
    already knows the revocation, old ballots and results included. If such a result
    is what justifies a later charter, a node that learns of the revocation before it
    has accepted that charter cannot accept it. This was reproduced with an exported
    file and with a shared directory, where the order of the records is not the order
    in which they were made; importing again does not help, and no way out has been
    tested. `peerharness reset` is not one, because it deletes the device key that is
    on the roll: the new key has to be voted onto the roll, and that amendment may not
    reach its threshold once a device is revoked. ADR-044 records what was tried by
    hand. This contradicts "does not depend on arrival order" below. It is a defect.
    No fix exists; what it should be depends on the decision in ADR-044.
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
  notes are kept. A note written inside a session is an agent's note whatever flags
  were passed, so an agent cannot label its text as the owner's or go round that cap
  (ADR-042). Every consent step refuses inside an agent session, with or without
  `--yes` (architecture 12.1): among them asking and answering a question, announcing a
  stance, leaving a circle, proposing an amendment, revoking a device, placing a scope's
  rules in a project and switching to `follow`. A cancelled or refused command saves
  nothing. Two things are deliberately not consent steps: switching to `ask`, and opting
  out of a rule on one's own machine, which is never refused. Opting back in is one
  (ADR-042): `rule opt-in` puts a rule's text back into the owner's agent, so it shows
  that text and the directory it goes to and asks in the terminal, with no window and
  no tool. Two more commands refuse inside a session: `export --local`, on standard
  output as well as to a file, like `events export`; and `init` with the plaintext
  keystore, whose warning has to reach a person.
* **Confirmation windows (ADR-033).** If the owner turned them on in their own terminal,
  three steps started inside a session are put to the person in a window of the
  operating system instead of being refused: proposing a rule, a ballot on a proposed
  rule, and installing a rule that passed. The session chooses the arguments and can
  make the window appear. Inside its session it cannot answer it: only a click on
  "Proceed" counts, "Cancel" is the default, `--yes` is ignored there, and the exact
  preview is shown in full or the step is refused. Whether it fits is measured on the
  machine, by laying the text out before the window is shown (ADR-051); up to 0.4.0
  it was estimated from character widths, and a text in a script with wide and high
  glyphs could be shown cut off. This holds for a session that
  PeerHarness recognizes. The preview that turns windows on says so to the owner: it
  guards against an agent that is trying to help, not against a process that hides that
  it is one (Residual risk, below). A rule with a high-risk finding is never decided in
  a window. That holds for proposing one as well: `proposal create` shows the scanner's
  findings and asks about a high-risk rule in the terminal only (ADR-041). The session
  also chooses a ballot's rationale, which is shown in the window. It is held to one
  line of at most 200 characters without control characters, invisible characters,
  blanks that are not spaces (U+2800 and a few like it) or any character the preview
  would rewrite, so it cannot lay out a second "rule, exactly as proposed" above the
  real one, by line breaks or by padding. Every other consent step refuses inside a
  session as before, including the one that turns windows on.
* **Windows for inviting and joining (ADR-037).** Three steps about who is in a circle
  can be asked the same way, under a setting of their own that the same command turns
  on after previewing every step it allows: proposing to admit a member, a ballot on an
  amendment that admits one member and changes nothing else, and joining a circle.
  Windows that were turned on before these steps existed do not cover them. The window
  shows the device fingerprint and the scopes the new member would get, or the root
  fingerprint and the whole charter, taken from the signed content and not from a
  title, and says to check it with the other person. (Until ADR-051 the preview of
  `circle invite` did not name the scopes, in a window or in the terminal.) The join window
  also shows what the circle will be called on this machine. Inside a session that
  name, like the one given to `circle create`, is one word: every later window puts
  it inside one of PeerHarness's own sentences, where a name of several words could
  read as part of the sentence (ADR-051). Inside a session `circle invite` writes no file with the circle's records.
  Removing a member, leaving, changing the rules of the vote, devices, revoking and
  every other ballot on the charter still refuse inside a session.
* **The MCP server (ADR-038).** `peerharness mcp` offers an agent a fixed list of tools.
  It adds no way to consent: each tool runs the command as a child process marked as an
  agent's session, whatever environment the server was started in, so every consent step
  is asked in a window or refused as above. Arguments are checked values and are never
  passed on as flags, and the reason given to the `vote` tool is held to the 200
  characters that `proposal vote` signs. A tool runs only if the owner allowed that
  level in their own terminal, which also holds for the tools that are not consent steps
  (`status`, `inbox`, founding a circle, the exchange, the daemon). What it does add: an
  agent that was given the tools can start the exchange and the daemon on the public
  network without a window, once the owner allowed the circle steps and read, in that
  preview, what the network's servers see. The tool that joins a circle takes what
  parses as a peer id or an address and names nothing on disk, so it cannot make `circle
  join` read a file the agent wrote (ADR-042). `circle join` holds to that by itself:
  inside a session an argument that parses as a peer id or as an address is never
  read as a file, so a file that appears under such a name after the tool looked is
  not read either (ADR-041, "After a review of the pull request"). On a machine that
  cannot show a window,
  setup leaves the windows off, so every tool but `note` is refused; the refusal there
  names the terminal guide and no setting (ADR-045). A node whose settings allow windows
  on such a machine, a home copied from another one for example, still runs the tools
  that need no window, at the level the settings allow. `setup` says so when it ends and
  names `peerharness setup --no-dialogs`, which turns them off. Joining is not among
  them. `circle join <peer id or address>` gets the charter it then shows from the
  network, so inside a session it asks first whether the join can be put in a window
  (`consent::circle_step_can_be_asked`). Where the windows for the steps about a
  circle are not allowed, or the machine can show none, it is refused before the
  transport starts and before any lookup or dial (ADR-045).
* **Keeping a rule for oneself (ADR-040).** A noted rule is installed only on its
  owner's yes, which can now be one click in a window that shows the exact text and what
  the scanner found in it. An agent can note a rule and open that window, and cannot
  install anything. A rule with a high-risk finding is refused there and decided in the
  terminal. This is the step an agent that was talked into noting a harmful rule would
  need its user to click through: the text in the window is what gets installed, and
  reading it is the person's part.
* **Setup (ADR-039).** `peerharness setup` is the owner's step: it shows what the agent
  may start and registers the tools with Claude Code by running `claude mcp add` after
  showing that line. An agent's session is refused the whole command, so an agent that
  was asked to "set PeerHarness up" can install the binary and must then ask its user
  to run setup themselves. For a node that is already there, setup names the keystore
  that holds its key and warns about a plaintext one (ADR-045).
* **Other agents (ADR-050).** Connecting Codex, opencode, Pi, Antigravity or DeepSeek
  Harness is the owner's step in their own terminal, refused inside a session. It
  writes into two places that belong to that agent: copies of the skills PeerHarness
  manages in Claude Code's directory, in the directory the agent reads skills from,
  and one entry in its configuration that starts `peerharness mcp`. Nothing is decided
  from a copy: it follows a directory where every rule of installation already held,
  never replaces or removes a skill PeerHarness did not put there or one that was
  edited, and is kept only for an agent the owner connected. A copy is text the agent
  acts on, as the rule it copies is. The configuration entry is written only where it
  is absent, changed or removed only when it is exactly what PeerHarness writes, with
  a backup, and a file that does not parse is left alone.
* **Residual risk.** A human can be persuaded by a model's wording. The deterministic
  detector can be wrong; it never claims more than medium confidence. The agent-session
  check reads environment variables: an agent that clears them, or one that sets none,
  is not stopped by it, and what remains is that consent needs a terminal or an explicit
  `--yes`. The refusal for a missing terminal names `--yes` as something a person
  passes in a script they wrote, and tells a coding agent to stop and ask; that is
  wording, and nothing keeps such an agent from passing the flag. Only the variables of
  `consent::AGENT_SESSION_ENV` are read: `CLAUDECODE`, `PEERHARNESS_AGENT_SESSION`, and
  those of the other agents PeerHarness connects (ADR-050). Google Antigravity
  documents none, so its agent's commands may carry no mark at all. A debug build also obeys the stand-ins the
  tests use in place of the window, the notification and the `claude` command, so
  whoever sets its environment can name the program that answers a window; `doctor`
  and `status` say when a binary is one, and release builds do not read them. An agent
  running as the owner can also edit the skills directory and the database directly,
  and can use a device key whose keystore unlocks without the owner
  (section 4.6). These rules protect against accidents and against other people. They
  do not protect an owner from their own compromised session. With confirmation windows
  on, three more things hold. The agent decides when a window appears and what it asks,
  so a person can be worn down into clicking "Proceed"; the text in the window is
  exact, and reading it is the person's part. An agent that can drive the screen could
  click the button; macOS asks the owner before it lets a program do that. And the
  agent's skill then tells it to read the inbox, so titles and questions written by
  other members reach its context before any vote, and so do a proposer's summary and
  the reasons members gave if the session runs `proposal show` (each line behind a
  mark). The text of a rule reaches an agent only once it is installed for it: inside a
  session `proposal show` prints a rule's text only where exactly that text is
  installed on the machine, and never the text of a rule an amendment would carry in
  (ADR-051; until then it printed the text of any proposal the node held). A title is
  one line, and for a rule that came from a note it is the rule's sentence. With the windows for inviting and
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
  veto: `reject` and `revise` are recorded dissent. A member cannot withdraw an
  approval, and counting reads no clock and does not depend on arrival order: two nodes
  holding the same ballots and the same revocations compute the same result
  (`ph-governance::tally`). One thing takes a counted approval away, which is the
  founder's revocation of the device that cast it (4.16). The charter changes only
  through a passed amendment that
  carries the complete next roll, rules and list of carried rules, and a node's rule set
  after a change is exactly that list, so nodes converge. A proposal counts only under
  the **current** charter: members who have left cannot pass anything by signing under
  an old one, even if together they were a majority of it (the "long-range" case), and
  an amendment cannot be replayed onto a later charter. What a member is shown before
  they sign a ballot on an amendment is in 4.29.
* **Residual risk.**
  * **Founder liveness and equivocation** (4.16): no charter change without the root
    holder; a root that signs two successors can split a circle.
  * **An amendment carries a rule set** (4.29). When it passes, the rules in force are
    exactly its `carried` list. One that was proposed before a rule passed, or before
    a repeal passed, undoes that vote. The voter is told and nothing stops it.
  * **Turnout.** Not voting counts as not approving. An absent member makes every
    threshold harder to reach, and removing them is itself a vote. In a circle of two,
    both must approve everything.
  * **Compromised device window** (4.6, 4.9): its approvals count until each node
    learns of the revocation.
  * **"Passed" can turn back after a revocation** (4.16): a result that needed the
    revoked device's ballot is open again, and a repeal that needed it lapses. After
    a revocation an import can also leave a node on the old charter (4.16). What a
    revocation should do to ballots already counted is an open decision (ADR-044).
  * **A majority decides.** Members outvoted on a rule still get it in a binding circle
    unless they opt out (4.10). A majority can also remove a member.
  * **The roll changes by simple majority.** By default, changing the rules of the
    vote needs more than two thirds, but admitting or removing a member needs only
    more than half. A majority can therefore shrink the roll and then reach two thirds
    alone: of five members, three can remove the other two and then change the rules
    by themselves.
  * **One rule per name, across scopes.** Members can be given scopes (`circle invite
    --scope`), and a rule can be voted on by the members of one scope. A rule adopted
    in a narrower scope under the same name replaces a circle-wide rule of that name,
    for everyone, although only that scope's members voted (architecture 10.7). A
    circle in which every member has the default scope is not affected.
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
  the roll says. Nobody's agreement is needed for that, and no key: it is done before
  anything is signed, so it also happens when the device key does not unlock (ADR-041,
  "After a second review"). Separately, and afterwards, it puts the owner's removal to
  the vote, with their approval. The roll changes only if that amendment passes, like
  any other: a unilateral exit would be a second way to change the roll, with a
  threshold other than a majority (ADR-027). What the run does about the request is
  decided before the owner is asked, and the preview says it. The request is signed
  only as it was shown (ADR-041, "After a third review"): once the machine has
  changed and the key is unlocked, the node is checked against the charter and the
  rules in force that the preview was built from (4.29), and the removal that was
  drafted for the preview is signed, or none. A request is made only where the node
  can show what it asks for: not while the node lacks a rule the charter in force
  carries, because a removal drafted there would either drop that rule or bring back
  one that was repealed since. And none is made a second time while a proposal that
  is exactly this removal is on record under the charter in force. The preview says
  both beforehand, and the report says that no request was made and why. The record
  is looked at once more after the key is unlocked, so a member's removal of the
  leaver that arrives while they are asked is not doubled either (ADR-041, "After a
  fourth review"). Running the command again first tries again, with no key, to
  remove what the circle installed and the first run could not. It then makes the
  request when the first run did not: it shows the request alone, asks, and is bound
  to the charter that was shown (4.29). Both runs sign in one place
  (`circle::request_as_previewed`): the check of the node, the look at the record,
  the request and the owner's approval of it are one transaction of the store
  (4.29), so a second run does not double a removal that arrived while its owner was
  asked either (ADR-041, "After a review of the pull request"). `circle leave
  --undo` makes no request and withdraws none. Its preview says what is on record:
  a request, or another member's proposal that takes the owner off the roll and is
  not the request, or nothing.
* **Residual risk.** Until the members approve, the leaver is still on the roll. They
  count in every electorate, which makes thresholds harder to reach; their device key
  can still read, sync and vote; and their approval of their own removal cannot be
  withdrawn, although they can follow the circle again on their machine. A member whose
  node lacks a carried rule, which a member with limited scopes does after every sync,
  has left on their machine and has asked for nothing: they stay on the roll until they
  import the events file of a member who holds the rule and run the command again, or a
  member proposes their removal. A request that was not made for a locked key, or
  because the node changed while its owner confirmed, is likewise made only when the
  owner runs the command again. A rule the circle installed whose files cannot be
  changed stays in the agent after the owner left: the command says so, and each later
  settle of that circle tries again, as does a second run of `circle leave` (4.30). A
  copy of a rule that the owner edited stays as well, and is named in the report with
  the command that takes it out, although the preview says that the circle's rules are
  removed (4.30). A device that the founder revoked cannot make the request at all:
  `circle leave` previews one all the same, reports that it was refused and says to
  run the command again, where what works is a member's `circle remove` (ADR-041,
  "After a fourth review", Not done). A sole member cannot leave. A founder who
  leaves the roll still holds the root key, and later charter changes then depend on
  files carried to and from that node (4.16).

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
  appears and stays if the announcement is refused. It does not wait for a key either.
  `rule opt-out` and `proposal refuse` change the machine before any key is asked for
  (`governance::settle_machine_first`), and succeed when the key does not unlock:
  what the node could have signed for the circle then stays unsigned until the next
  settle with the key, and the command says so. With `--announce` and a key that does
  not unlock, what was done on the machine is reported and the announcement is
  refused (ADR-041, "After a fourth review"). The stance is signed only for the
  proposal the preview named: once the key is unlocked the node looks again
  (`governance::rule_as_shown`), and when a newer rule took the name meanwhile nothing
  is announced. `rule repeal` is held to the same for the proposal it repeals
  (ADR-041, "After a third review"). For both, the look and the signature are one
  transaction of the store (4.29), so no other process stores a rule of that name
  between them. `rule repeal` is also signed under the charter its preview counted
  the voters on, or not at all (ADR-041, "After a review of the pull request").
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
  is judged by the roll like any other peer (4.1). Inside a session that peer id
  reaches the command through the agent: it is looked up only for a join that can
  then be put to the owner in a window, and not at all where the window is not allowed
  or cannot be shown (4.17). A stranger who finds a node gets
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

### 4.29 What a voter is shown before a ballot

* **Threat.** A member approves something other than what they think. An amendment's
  title says one thing and its content does another: "Admit dave" over a roll that also
  replaces another member's device key, a changed threshold, or a `carried` list that
  names a rule nobody voted on. An amendment that was honest when it was proposed would
  now drop a rule passed since, or bring back one repealed since. The charter or the
  rules in force change on the node while its owner reads a preview or types a
  passphrase, so that the yes signs something other than what was shown. Text another
  member wrote, or a rationale the agent chose, imitates PeerHarness's own lines in a
  preview.
* **Mitigation.** In the terminal, `proposal vote` and `proposal show` describe an
  amendment from signed content only (ADR-041, `apps/peerharness/src/amendment.rs`):
  the proposal's `next` against the charter the proposal names. Members admitted and
  removed are shown with device fingerprints and scopes; for a member who stays, every
  device added and taken; the thresholds and binding or advisory, old and new; and by
  name each rule in force the amendment would drop and each it would bring into force,
  the latter with its exact text. A rule that the charter in force carries and this
  node does not hold is listed as dropped as well when the amendment leaves it out:
  by its proposal id, with the words that this node cannot say which rule that is.
  When the amendment keeps such a rule it is listed as kept, by its proposal id, with
  the words that this node cannot say whether that changes anything: a rule repealed
  since would come back into force.
  When the amendment lists a second proposal under the name of a rule in force, the
  description says which of the two would be in force afterwards: the listed one
  takes the rule's place and its text is shown, or the rule in force is the later one
  and stays. The description always has the same three parts, each saying what
  changes or that nothing does. The title comes after it, quoted and labelled as the
  proposer's words. An approval is refused, with `--yes` too, while the node cannot
  show what the amendment would put in force or take out of force: a carried rule's
  text is missing, a carried id is not a rule proposal the node holds, the amendment
  leaves out or keeps a carried rule the node does not hold, or the charter the
  proposal names is not held. A window decides only a ballot on a rule without a
  high-risk finding or on a sole admission, takes the member and the device from the
  amendment (4.17), and is not opened for any amendment while the node lacks a carried
  rule. The node that drafts is held to the same: `circle invite`, `remove`, `amend`
  and `device` are refused while it lacks a rule the charter in force carries, because
  the draft would leave that rule out. `circle leave` is not refused, since leaving
  never waits: it changes the owner's machine and makes no request to change the roll
  from such a node (4.24). A yes counts for what was shown (ADR-041, "After a second
  review" and "After a third review"). After the owner's answer and after the key is
  unlocked, with no prompt between the check and the signature, a command that drafts
  an amendment checks that the charter and the rules in force on the node are still
  what its preview was built from (`governance::as_drafted`, which takes the unlocked
  key so that it cannot be called earlier), and the proposal is signed under the
  digest of the charter that was shown (`governance::propose_under`); otherwise
  nothing is proposed. The check, the proposal and the proposer's approval are one
  write transaction of the store (`governance::atomically`): between the check and
  the signatures no other process, a running daemon or an import in another
  terminal, stores a ballot or a charter (ADR-041, "After a review of the pull
  request"). The key is unlocked before the transaction begins, no prompt and no
  window is inside it, and settling comes after it.
  `governance::propose_without_preview`, which signs under whatever charter is
  current, returns an error for an amendment, and no command that showed its owner a
  preview calls it. `proposal create` and `rule
  repeal` state who votes and how many approvals it takes, read from one charter,
  and are signed through `propose_under` under that charter: when the charter in
  force is another one by then, nothing is proposed, and `proposal create` saves
  nothing. `question send` states how many members can read the question, and
  refuses to send when the charter in force is another one by then. Both runs of
  `circle leave` are held to the same as every draft (4.24). `proposal vote` reads
  what an amendment changes again in the same place (`proposal::approval_as_shown`),
  in one transaction with the ballot, and signs an approval only when it still
  says what was shown (`amendment::Changes::same_as`), and for a ballot asked in a
  window only when the amendment is still a sole admission of the same member under
  the same charter. A rationale typed for `proposal vote` is one line of at most 200
  characters without control characters, invisible characters, blanks that are not
  spaces or characters the preview would rewrite. Text other members wrote (a
  rationale, a summary, an opt-out's reason, the text of a rule in `proposal show` and
  of a carried rule) is printed line by line behind a mark, so no line of it passes
  for one of PeerHarness's own.
* **Residual risk.** This protects a voter who uses this client and reads what it shows.
  The outcome is unchanged: an amendment that reaches its threshold still replaces the
  rule set with its `carried` list on every node, and the founder's node notarizes it
  with nobody present (4.26). A member with a modified client can still sign such an
  amendment, and `check_successor` and `Passed::carried` accept what they accepted
  before. A member who approved before the rule set changed is told nothing. The rules
  are compared with this node's own view of what is in force, and are not compared for a
  proposal that names an earlier charter. One gap stays in that view: a rule that passed
  under the current charter in a scope this node cannot read is neither in force here
  nor among what the charter carries, so an amendment that leaves it out is described as
  dropping nothing, and neither its approval nor its draft is refused on this node.
  Closing it needs a decision about what a member with limited scopes is sent (4.4). A
  node that lacks a carried rule can approve no amendment and draft none until its owner
  imports the events file of a member who holds the rule, and a member whose scopes do
  not cover the rule is in that state after every sync. That file is not filtered by
  scope (4.4): the way out gives such a member the rule's records and text, which is
  what the scope withholds, and it is needed again after each change to the charter
  that carries a new such rule. The check after the yes comes after the key is
  unlocked. Until a third review the passphrase prompt of a key kept in an encrypted
  file lay between the check and the signature, and an amendment and a deciding
  approval were signed through it. After that, what was left was the time between
  two calls in one process, in which another process could still commit: a rule
  that passed in it was not caught by the check. Since a review of the pull request
  the check and the signatures are one transaction of the store, and nothing is
  left between them (ADR-041). The transaction lasts from the check to the last
  signature and no longer. What arrives after the commit is not in a draft: a rule that
  passes then is named on the other voters' ballots, as for any amendment that was
  drafted earlier, and a member who approved before it is told nothing. `question
  send` looks at the charter and signs in a transaction as well, so nothing is left
  between the two there either. A `proposal create` that fails after it
  saved the rule's text can leave that one file in the bundle store, with no row
  that names it. That no other process writes between a check and the signatures
  is shown by a unit test with a second connection to the same file, not by two
  processes that race. No automated test holds a prompt open: the tests use a
  stand-in window that imports a file before it answers. The order at a prompt in a
  terminal and at a passphrase prompt was run by hand on a pseudo-terminal, on
  Linux, with a second process importing a file (ADR-041, "After a third review").
  For `proposal create`, `rule repeal` and `question send` with a newer charter
  arriving, that was done at the y/N prompt and at the passphrase prompt, by the
  agents that reviewed the change ("After a review of the pull request"). Whether
  the macOS keychain asks when the key is
  unlocked was not looked at. A ballot on a rule in a terminal shows
  the proposal's title and neither the text nor a finding (4.10). In the window for a
  sole admission the proposer's title still stands in the second line, above the
  lines read from the amendment. Rule text is printed without a mark in the previews of
  `proposal create`, a ballot on a rule, `proposal adopt` and `keep`, and whether a
  rule's body can imitate the scanner's lines there is not addressed. `proposal list`
  and `inbox` list an amendment by its title, and a repeal ballot names its target by
  the proposer's title and a short id. The mark is per line of text, not per row of a
  terminal: a very long line wraps without it.

### 4.30 A passed rule and the skills already on a machine

* **Threat.** A rule passes under the name of a skill the owner already has, with
  another text: PeerHarness's own skill (`peerharness-notes`), which tells the agent
  where its part ends, or a rule the owner kept for themselves. The vote's text
  replaces it on the machine of every member who follows the circle, including one who
  never voted and saw no window, and a repeal later deletes it. Or an agent gives its
  own note the name of PeerHarness's skill. Or a newer rule takes the name of the one
  its owner is being shown, between the preview and the yes.
* **Mitigation.** A vote installs over a managed skill only when `rule_installs` records
  that a vote of the same circle put exactly that text at that place (ADR-042).
  Otherwise the rule is held: nothing is written, in any mode and whatever the owner
  confirms, and `rule list` and every command that settles say so, with the two ways out
  (take the skill that is there out and adopt the rule, or opt out). Inside a coding
  agent's session the same lines do not name those commands: they say that the choice is
  the owner's and that the agent takes nothing out. The owner's yes to an install
  (`proposal adopt`, `rule opt-in`) counts for the proposal that was shown, by its id,
  which signs the rule's name, the digest of its text and its scope. A rule that took
  the name while the prompt or the window waited is not installed on that yes: both
  commands then refuse, and `rule opt-in` leaves the opt-out in place. `skills
  uninstall` refuses a copy that a vote installed and its owner follows, and names the
  opt-out, in the user's skills directory and in a project. An owner follows a rule
  while it binds them, they have not opted out of it and they have not left its circle
  on this machine: nothing is refused for a circle that was left, or for a rule whose
  electorate does not include this node (ADR-042, "After a fourth review"). The one
  exception is the owner's own skill that holds the rule in the directory the command
  acts on, which is the way out of the hold. The two directories differ in what else
  is refused. In a project it is a rule that lives in that project and a copy that a
  vote installed there, and a copy the owner installed themselves, of a rule that
  lives elsewhere, is theirs to remove. In the user's directory it is every copy with
  the text of a rule the owner follows, also one they installed themselves while the
  rule lives in a project. A rule named `peerharness-notes` is never installed, and
  `note`, `review`, `keep` and `proposal create` refuse the name. A repeal, a lapsed
  rule and an opt-out remove only a file that a vote of that circle installed and that
  still has exactly the recorded text. A copy that its owner edited is left in place
  and named once, with the command that takes it out, or with the fact that `skills
  uninstall` would refuse it; inside a session the line names no command. When
  a file with the recorded text cannot be removed, the record that a vote installed it
  is kept, the command says that the rule could not be removed and is still installed,
  and each later settle tries again; while the old copy of a rule whose scope was
  moved cannot be removed, the rule is not installed in the new place (ADR-042, "After
  a third review"). When the owner takes such a leftover out with `skills uninstall`,
  the record goes with it, so that it cannot later remove a copy they install
  themselves (ADR-042, "After a fourth review"). A hold is local, like an opt-out: it
  never changes the tally or the rule set, and nothing is sent because of it.
* **Residual risk.** A held rule is in force for the circle and not on that member's
  machine, and the others cannot see that. Its owner is told by the command that
  settled, by `rule list`, and once per run by a running daemon, whether one of its own
  exchanges found the hold or a peer's push created it; `status`, the inbox and the
  end-of-turn line do not mention it. A hold that goes away and comes back while a
  daemon runs is not printed a second time, and nothing of a hold reaches `--notify`.
  A rule that a peer's push installed, removed or left waiting on a node whose daemon
  only answers is printed by that daemon, a waiting rule once per run; `status`, the
  inbox and `--notify` say nothing of it, and a report that finds the daemon's queue
  of 64 full is dropped. A skill that cannot be removed stays in the agent until its
  files can be changed and the circle is settled again, its owner runs `circle leave`
  again for a circle they left, or they take it out with `skills uninstall`, which
  refuses it only while they still follow the rule. The report of a sync names
  skills and not places. It keeps the line for a copy that could not be removed when
  another copy of that name, another circle's in another place, was removed earlier
  in the same exchange, or later in it: the report tells the copies apart by their
  circle, and only a later settle of the same circle that removed the skill takes
  the line back (ADR-041, "After a review of the pull request"). An edited copy that
  was left in
  place stays until its owner takes it out; the record that a vote installed it is
  gone, so after `circle leave` `rule list` shows that rule as held by it and names
  `proposal adopt` for a circle its owner left. In the user's directory `skills
  uninstall` refuses a copy the owner installed themselves when the rule they follow
  lives in a project, and the opt-out it names takes the circle's copy out of that
  project; whether the user's directory should get the narrower test of a project is
  open (ADR-042, "After a fourth review", Not done). The first installer of a name on
  a machine keeps it: of two
  circles' rules with one name and different texts, the second is held. A copy the owner
  keeps after a vote installed the identical text still counts as the vote's, so a
  repeal or an opt-out removes it. A library skill named `peerharness-notes` that an
  earlier version saved can still be installed by its owner with `skills install`, which
  asks them. On a node where an earlier version let a vote overwrite PeerHarness's own
  skill, the vote's text is removed and the skill comes back only when the owner runs
  `peerharness setup` or `watch claude --install` again. `skills uninstall` asks nobody
  and is not refused inside a session (ADR-042, Not done): an agent that runs it on the
  skill that holds a rule takes the owner's skill out, and the next settle installs the
  circle's text. A fourth review ran exactly that inside a session, and the preview of
  the reporting skill still says that the agent "cannot approve, share or install
  anything" there (ADR-045, "After a fourth review"). What changed is that a session
  is no longer handed that command. An automated review of the pull request named
  the same sentence, and nothing was changed for it: whether a session may run
  `skills uninstall` is open (ADR-041, "After a review of the pull request", Not
  done). None
  of this stops a process running as the owner from writing to the skills directory
  itself (4.17).

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
  access, change the roll or the voting rules, or add an approval to anything, alone.
  Cutting a device off does undo results that needed that device's ballot (4.16).
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
  the public libp2p network, along with the device keys it looks up (4.28). The
  events file that `circle invite` writes for the invitee, outside a session, holds
  the roll and the proposals in clear: give it only to the invitee.
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

See [`SECURITY.md`](../SECURITY.md). Please report privately; do not put the details of
a vulnerability in a public issue.

## Test coverage

Where each group of threats is exercised. Paths are relative to the repository root.
Multi-node tests run separate processes of the real binary, over files, a shared
directory and QUIC on loopback.

| threats | tests |
|---|---|
| 4.1, 4.5, 4.7 (peers without membership, impersonation, limits) | `crates/ph-network/tests/network.rs`, `adversarial.rs`, `codec.rs`; `crates/ph-governance/tests/authz.rs`, `roll_oracle.rs`; `apps/peerharness/src/peer.rs` (unit tests of the request handler; `a_cursor_pages_through_a_log_larger_than_the_known_list`: a log larger than the `known` list, and a cursor that does not widen what is read); `apps/peerharness/tests/network.rs` (separate processes over QUIC: a stranger, a node that claims a shared circle, a device on no roll that asks to join); `apps/peerharness/tests/circle_vote.rs` (an outsider's node stores nothing) |
| 4.2, 4.9 (forged, expired or revoked membership) | `crates/ph-identity/tests/attacks.rs`, `membership.rs`; `apps/peerharness/tests/circle_life.rs` (`the_founder_cuts_off_a_lost_device_and_the_roll_stays_as_voted`: only the founder's node and only a person can revoke, not its own device; the roll and the electorate are unchanged; the device's ballots stop counting, new ones are refused by every node that knows, and its own node stops signing once it knows); `apps/peerharness/tests/strict_import.rs` (`the_expected_fingerprint_says_which_circle_is_joined_not_the_highest_charter`: a file and a directory that hold a second circle with a higher charter number, a wrong fingerprint refused and the right one joined; `without_a_fingerprint_a_file_with_several_circles_is_not_joined_from`) |
| 4.3, 4.20 (stolen, duplicated or invented votes; counting; results; succession) | `crates/ph-governance/tests/tally.rs`, `result.rs`, `ruleset.rs`, `succession.rs`, `adversarial.rs`; `apps/peerharness/tests/circle_vote.rs`, `demo.rs` |
| 4.4, 4.16 (scope access, the root-key holder) | `crates/ph-governance/tests/authz.rs`, `succession.rs`; `apps/peerharness/tests/circle_life.rs` (the revocation test above) |
| 4.6 (keys at rest) | `crates/ph-identity/tests/keystore.rs` |
| 4.8 (replay, malformed and oversized input) | `crates/ph-protocol/tests/adversarial.rs` (among them `a_frame_in_any_form_but_the_encoders_is_refused`: a frame as an array of its members, a variant as an object with a `null`, an empty list where the member is omitted), `proptests.rs`, `vectors.rs`; `crates/ph-store/tests/events.rs`; `apps/peerharness/tests/strict_import.rs` (`a_line_of_a_file_is_parsed_as_strictly_as_a_frame_from_the_wire`: a member twice in the event and in the line, an unknown member, an explicit null, a line of 1 MiB and one byte refused, a line of exactly 1 MiB imported; `a_record_file_of_a_directory_is_parsed_as_strictly`; `a_charter_in_a_line_that_is_not_strict_json_is_not_joined_from`); `apps/peerharness/src/carrier.rs` (`a_record_is_one_member_in_strict_json`, `a_record_is_held_to_a_size_and_a_depth_before_it_is_read`) |
| 4.10 to 4.12 (hostile skills, paths, script execution) | `crates/ph-skills/tests/malicious.rs`, `bundles.rs`, `install.rs`, `frontmatter_props.rs`; `crates/ph-skills/src/scanner.rs` (the two rules of ADR-043, each in both directions: `fetching_a_url_and_following_it_is_high`, `a_reference_to_read_is_not_an_instruction_to_obey`, `an_instruction_about_peerharness_own_guard_is_high`, `mentioning_a_session_or_a_flag_is_not_tampering`) |
| 4.13 (secrets and transcripts) | `crates/ph-core/src/redact.rs` (unit tests), `crates/ph-store/tests/privacy.rs`, `apps/peerharness/tests/local_loop.rs` |
| 4.14 (hook payloads, settings) | `crates/ph-observer/tests/hooks.rs`, `settings.rs`, `spool.rs` |
| 4.17 (model output, the agent acting for its user) | `crates/ph-learning/tests/providers.rs`, `drafts_and_assisted.rs`; `apps/peerharness/tests/local_loop.rs`; `apps/peerharness/tests/circle_life.rs` (refused inside an agent session: asking, answering and dismissing a question, switching to `follow`, leaving, revoking a device, announcing a stance, placing a scope); `apps/peerharness/tests/agent_windows.rs` (confirmation windows, with a stand-in window program: off until the owner turns them on, which a session cannot do; only "Proceed" decides, and a decline, no answer, an unknown answer, a failing or missing window program and a text too long to show all leave nothing behind; every other consent step is still refused with windows on; inviting, a ballot on a plain admission and joining are asked in a window only under their own setting, show the fingerprints from the signed content, leave nothing behind when declined, and write no events file from a session; removing, leaving, changing the rules of the vote and a ballot on any other amendment are still refused); `apps/peerharness/tests/mcp_server.rs` and the unit tests of `apps/peerharness/src/mcp.rs` (the MCP server, started without the session variables: a tool above what the owner allowed runs nothing, a consent step is declined or confirmed only by the stand-in window, an argument that begins with `-` and an unknown tool are errors, and the daemon a tool started stops when the client leaves); `apps/peerharness/tests/agent_windows.rs` also covers keeping a rule for oneself (refused without windows and with windows allowed before that step existed, installed only by the click, what was shown is what is installed, a high-risk rule refused in a session and in a terminal); `apps/peerharness/tests/setup.rs` (setup, with a stand-in for Claude Code's `claude` command: refused inside a session with nothing created, nothing connected or registered without the person's yes, and no second registration; without windows it suggests nothing to ask the agent; it names the keystore of a node that is already there and warns about a plaintext one); `apps/peerharness/tests/session_gates.rs` (`opting_back_into_a_rule_is_the_owners_step_and_shows_the_rule`: refused with either session variable, with `--yes` and with windows on, while opting out stays immediate; `the_local_export_is_refused_inside_a_session`, to a file and to standard output; `the_plaintext_keystore_is_refused_inside_a_session_and_a_plain_init_is_not`; `a_note_written_inside_a_session_is_an_agents_note`, with the cap of 20; `the_join_tool_takes_a_peer_id_or_an_address_and_never_a_path`; `inside_a_session_a_peer_id_is_never_read_as_a_file`: a real invitation under the name of a peer id in the working directory and a stand-in window that would say Proceed, refused as a usage error with either session variable and with `--yes`, no window and no circle, while the person's own command joins from the file; `without_a_terminal_nobody_is_told_to_pass_yes`); `apps/peerharness/tests/ballot_previews.rs` (`a_high_risk_rule_is_never_proposed_from_a_window`: refused with a stand-in window that would say proceed, nothing saved or signed; `a_rationale_is_one_line_and_cannot_lay_out_the_preview`: a line break, a control or hidden character, padding that is not made of spaces and 201 characters are refused in a session and out of one, and no ballot exists afterwards; `keeping_a_rule_shows_what_the_scanner_found_and_nothing_new_without_a_finding`: the findings are in the window and in the terminal and not in the session's output, and without a finding the window reads as before); `apps/peerharness/src/mcp.rs` (`an_argument_is_a_value_and_never_a_flag`: a reason of 201 characters is refused by the `vote` tool); `apps/peerharness/tests/setup.rs` (`settings_that_allow_more_than_this_machine_can_ask_are_said_and_can_be_turned_off`, not on macOS); `apps/peerharness/tests/mcp_server.rs` (`where_no_window_can_be_shown_a_refused_tool_does_not_point_back_to_setup`, not on macOS; `a_join_nobody_can_be_asked_about_goes_nowhere_near_the_network` and, not on macOS, `the_join_tool_goes_nowhere_where_no_window_can_be_shown`: inside a session a join that cannot be put in a window is refused, and the private hub sees no connection, no identification and no lookup, while the same command run by the person reaches it); `apps/peerharness/tests/first_run.rs` (`a_debug_build_says_that_it_is_one_and_refuses_nothing`); `apps/peerharness/src/window.rs` (unit tests: the height estimate against measured dialogs, the text read back exactly by the real `osascript` on macOS) |
| 4.19 (the install script) | `apps/peerharness/tests/install_script.rs` (against a release in a temporary folder: a matching checksum installs one file that runs; a changed archive, a missing checksum and a version that is not a tag install nothing) |
| 4.21, 4.22 (joining from a node, the removal notice) | `apps/peerharness/tests/network.rs` (separate processes over QUIC: a new member joins from a member's node, the wrong root fingerprint is refused and stores nothing, a device on no roll is offered nothing; a removed member's node is shown the vote, verifies it, drops the circle's rule, and can neither sync nor rejoin afterwards); `apps/peerharness/src/peer.rs` (`a_member_voted_off_is_told_of_the_vote_and_nothing_else`: the exact set of records, no later charter, every other request refused, a never-member and a revoked device refused) |
| 4.23 (questions and answers) | `apps/peerharness/src/governance.rs` (`questions_and_answers_are_authorized_by_the_roll`: a device on no roll, a member outside its scopes, a revoked device, an answer without its question or in another scope; `the_local_guard_keeps_noise_out_of_the_inbox`: duplicate, muted, blocked, over quota; `a_flood_from_one_member_does_not_hide_the_questions_of_another`); `apps/peerharness/tests/circle_life.rs` (`a_question_is_asked_and_answered_by_members_of_the_roll`) |
| 4.24 (leaving, amendments, devices, the owner's mode) | `apps/peerharness/tests/circle_life.rs` (`a_second_device_new_rules_of_the_vote_the_owners_mode_and_leaving`: two devices of one member are one approval, the amend threshold, leaving acts locally at once and changes the roll only by vote; a second `leave` names the request on record, and is refused inside a session); `apps/peerharness/tests/amendment_ballots.rs` (`leaving_changes_the_machine_first_and_a_second_run_makes_the_request`: with a passphrase that does not unlock the key the circle's rule is removed and nothing is signed, the second run makes the request, a third signs nothing; `leaving_from_a_node_that_lacks_a_carried_rule_brings_no_repealed_rule_back`: no request from such a node, and after a full import a request that changes the roll and nothing else; `a_removal_a_member_proposed_is_not_asked_for_a_second_time`; `leaving_again_after_an_undo_makes_no_second_request`: after `--undo` a first run finds the request on record, says so in its preview and succeeds with a passphrase that unlocks nothing; `a_first_leave_names_a_members_removal_that_is_on_record_and_signs_nothing`; `a_removal_that_would_also_drop_a_rule_is_not_reported_as_the_request_to_leave`; `leaving_when_already_off_the_roll_reports_like_every_other_leave`); `apps/peerharness/tests/vote_and_own_skills.rs` (`leaving_names_what_it_left_in_place_and_a_second_run_tries_again`: a copy the owner edited is left and named, a rule that cannot be removed is reported, and a second run is refused inside a session and, for the person with a passphrase that unlocks nothing, removes the rule once it can); `apps/peerharness/src/commands/circle.rs` (unit tests: `a_first_leave_decides_about_its_request_before_it_asks`, `a_leave_request_is_signed_only_as_it_was_previewed`, `a_removal_that_changes_anything_else_is_not_the_request_to_leave`, `a_request_that_arrived_while_the_owner_was_asked_is_not_made_a_second_time`, `a_second_leave_makes_no_second_request_when_the_same_one_arrived_meanwhile`: the function both runs sign through finds the exact removal on record and signs nothing, refuses a node that changed, and otherwise signs the request with the owner's approval; `undoing_a_leave_names_another_members_proposal_that_takes_the_owner_off_the_roll`: the whole preview of `--undo`, with nothing, a request, the owner's own proposal and another member's on record) |
| 4.15 (placing a scope's rules in one project) | `apps/peerharness/tests/circle_life.rs` (`the_rules_of_a_scope_can_live_in_one_project`: only a person can place a scope; repeals and opt-outs act on the copy in the project; nobody else's machine changes) |
| 4.27 (discovery on the local network) | `crates/ph-network/tests/discovery.rs` (`discovery_is_off_by_default_and_then_nothing_is_reported` always runs; five tests that need multicast are `#[ignore]`d); `apps/peerharness/tests/network.rs` (`members_find_each_other_on_the_local_network`, `#[ignore]`d for the same reason) |
| 4.28 (internet mode) | `crates/ph-network/tests/internet.rs` (a private hub on loopback that answers like the public servers: off by default and then no further protocol is spoken; with the mode on the node serves nobody; a peer is found by its id, through a relay and at its own address; addresses from a lying server are filtered, bounded and never dialed; rate and connection limits hold for relayed peers; an exchange larger than a relay carries fails and says so; shutdown ends reservations and lookups; three tests against the public network are `#[ignore]`d), `internet_logs.rs` (no address in the log); `crates/ph-network/src/internet.rs` and `config.rs` (unit tests: which addresses count as public, the gate that keeps the node from dialing a peer the application named, the bounds, a loopback listener refused); `apps/peerharness/tests/network.rs` (`members_find_each_other_by_device_key_over_a_dht`, separate processes against that hub: a join by peer id, a sync that looks up the roll, a device on no roll is not looked up for a sync and is told nothing when it finds the node itself; `internet_mode_refuses_a_loopback_listener`) |
| 4.25 (recorded opt-outs) | `apps/peerharness/src/governance.rs` (`a_stance_is_a_record_by_a_member_of_the_roll_and_counts_for_nothing`, `a_repeal_and_a_stance_are_signed_only_for_the_rule_that_was_shown`, `a_rule_and_a_repeal_are_signed_only_under_the_charter_that_was_shown`); `apps/peerharness/tests/circle_life.rs` (`an_opt_out_can_be_put_on_the_circles_record`: voluntary, refused for an agent while the opt-out itself stands, open to a member admitted after the rule passed); `apps/peerharness/tests/vote_and_own_skills.rs` (`an_opt_out_changes_the_machine_before_any_key_is_asked_for`: with a passphrase that unlocks nothing, on a node where a vote passed without its result, `rule opt-out` and `proposal refuse` remove the rule and `rule opt-in` installs what was confirmed, each with exit 0 and nothing signed; `an_announcement_that_cannot_be_signed_says_what_was_done_on_the_machine`: exit 3, the report of the machine first, no stance); `crates/ph-protocol/tests/vectors.rs` (the STANCE vector) |
| 4.29 (what a voter is shown) | `apps/peerharness/tests/amendment_ballots.rs` (separate nodes, stock commands, in a terminal: `a_ballot_on_a_device_names_the_device_and_whose_it_becomes`, `a_ballot_on_the_rules_of_the_vote_names_the_old_and_the_new`, `the_last_voter_is_told_which_rule_a_pending_admission_would_drop`, `the_last_voter_is_told_which_rule_a_pending_admission_would_bring_back`, `an_amendment_is_not_a_way_to_approve_a_rule_nobody_here_could_read`: the approval refused and nothing signed; `a_node_that_lacks_a_carried_rule_says_so_and_approves_no_amendment_that_drops_it`: a node that joined without a carried rule, the amendment signed with a member's key as a modified client signs it, the approval refused with and without `--yes`, a reject accepted; `an_amendment_that_drops_an_unheld_rule_is_never_a_ballot_for_a_window`, debug builds: no window for the amendment that leaves the rule out nor for an honest admission that keeps it; `a_node_that_lacks_a_carried_rule_drafts_no_amendment_and_can_still_leave`: `invite`, `remove`, `amend` and `device` refused with nothing stored, `leave` accepted with no request made; `a_yes_to_a_change_of_one_charter_is_not_signed_as_a_change_of_the_next` and `an_approval_is_not_signed_for_what_an_amendment_changes_since_it_was_shown`, debug builds: a stand-in window imports a newer charter, or a rule that passed, before it answers Proceed, and nothing is signed); `apps/peerharness/src/amendment.rs` (unit tests of the description, among them `an_admission_that_also_replaces_another_members_device_says_so`, `a_rules_text_cannot_pass_for_a_line_of_the_description`, `a_dropped_rule_this_node_does_not_hold_is_said_and_blocks_an_approval`, `a_kept_rule_this_node_does_not_hold_is_said_and_blocks_an_approval`, `two_readings_are_the_same_only_when_they_say_the_same` and `a_listed_proposal_with_the_name_of_a_rule_in_force_replaces_it_or_stays_behind`); `apps/peerharness/src/governance.rs` (`a_mislabelled_amendment_is_described_by_what_it_signs`, `a_carried_rule_nobody_voted_on_is_named_and_must_be_readable`, `an_amendment_that_drops_a_carried_rule_this_node_lacks_is_not_shown_as_changing_nothing`, `a_carried_proposal_with_the_name_of_a_rule_in_force_is_described_by_its_outcome`: hand-signed events through `ingest`; `a_change_to_the_charter_is_signed_only_under_the_charter_it_was_drafted_from`, which also shows that `propose_without_preview` signs no amendment, `a_draft_is_put_to_the_vote_only_while_the_node_would_still_draft_it`, `a_repeal_and_a_stance_are_signed_only_for_the_rule_that_was_shown`; `a_rule_and_a_repeal_are_signed_only_under_the_charter_that_was_shown`: under a successor charter neither is signed or stored; `nobody_else_writes_between_a_check_and_the_signatures_it_allows`: a second connection to the same file cannot store a ballot between the check and the proposal or between the proposal and the approval, and can after the commit; `an_error_after_a_proposal_was_stored_leaves_no_proposal`); `apps/peerharness/tests/vote_and_own_skills.rs` (`a_rule_is_not_proposed_under_a_charter_that_arrived_while_its_proposer_read`, debug builds: a stand-in window imports a newer charter before it answers Proceed, and nothing is proposed or saved); `crates/ph-store/tests/open_and_migrate.rs` (`transaction_with_rolls_back_on_the_callers_own_error`); `apps/peerharness/tests/ballot_previews.rs` (the rationale test above); `apps/peerharness/src/output.rs` (`every_line_of_a_members_text_carries_the_mark`) |
| 4.30 (a passed rule and the owner's own skills) | `apps/peerharness/tests/vote_and_own_skills.rs` (three separate nodes: `a_voted_rule_named_like_peerharness_own_skill_is_never_installed`, with a proposal signed the way a modified client can; `a_vote_neither_replaces_nor_removes_a_rule_the_owner_kept_for_themselves`; `no_rule_can_take_the_name_of_peerharness_own_skill`; `a_yes_to_one_text_does_not_install_another_that_took_its_name_meanwhile`, debug builds: a stand-in window imports a newer rule of the same name before it answers, the command is refused and nothing is installed; `the_way_out_of_a_hold_is_one_that_works`: an edited copy and a rule opted back into, step by step; `a_hold_in_a_project_does_not_let_the_voted_copy_elsewhere_be_taken_out`: with the rule held in a project, `skills uninstall --scope user` of the copy a vote installed is refused, as the person and in a session; `a_voted_copy_in_a_project_is_not_taken_out_by_skills_uninstall`: refused with and without `--scope`, in a session too, while a copy the owner installed in another project is theirs to remove; `the_way_out_of_a_hold_does_not_take_out_another_circles_rule_unasked`; `a_record_of_a_vote_goes_with_the_copy_its_owner_takes_out`: after a removal that failed, `skills uninstall` of the leftover clears the vote's record, and the owner's own install of the same text survives the next settle; `a_copy_of_a_rule_that_no_longer_binds_its_owner_is_theirs_to_take_out`: refused while the rule is followed, not refused for a member voted off the roll or after `circle leave`; `leaving_names_what_it_left_in_place_and_a_second_run_tries_again`: an edited copy in the user's directory and in a project is left, named and taken out by the command the line names; `a_command_that_settles_says_what_it_did_to_other_rules`: `circle mode` and `rule opt-in` name an edited copy they leave, and `rule opt-out` names another rule it installs); `apps/peerharness/src/governance.rs` (`a_voted_copy_that_was_edited_is_left_in_place_and_named_once`, `a_skill_that_cannot_be_removed_stays_on_record_and_is_tried_again`, `a_vote_never_replaces_or_removes_a_skill_it_did_not_install`, `a_record_of_an_install_covers_only_the_text_it_names`, `a_copy_the_owner_installed_stays_hers_when_the_scope_moves_to_it`, `nothing_a_vote_passed_is_installed_under_the_name_of_peerharness_own_skill`, `a_confirmation_counts_only_for_the_proposal_that_was_shown`, `the_way_out_of_a_hold_is_told_to_the_person_and_not_to_a_session`); `apps/peerharness/src/commands/net.rs` (`a_daemon_tells_a_hold_once_when_it_is_new`, `a_daemon_prints_a_hold_with_one_report_and_no_later_one`, `a_daemon_tells_what_a_push_changed_and_each_state_once`); `apps/peerharness/src/runtime.rs` (`a_failed_removal_is_taken_back_only_by_the_same_circle`: a sync report keeps a skill that could not be removed unless a later settle of the same circle removed it); `apps/peerharness/tests/network.rs` (`a_daemon_that_only_answers_tells_a_hold_that_a_push_created_once` and `a_daemon_that_only_answers_tells_what_a_push_installed_and_what_waits`, three processes over QUIC on loopback); `apps/peerharness/src/commands/proposal.rs` (`adopt_says_what_was_installed_when_the_rule_changed_after_settling`); `apps/peerharness/src/agent_notes.rs` (`the_name_of_the_skill_is_reserved`) |

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
Of 4.17 and 4.29, no test types at a real terminal prompt or clicks a real window: the
tests answer with `--yes` or with the stand-in window, and `session_gates.rs`,
`ballot_previews.rs`, `setup.rs` and `mcp_server.rs` are compiled for debug builds on
unix only, because the stand-ins exist only there. Of 4.16, a node left on an old
charter after a revocation has no test, and neither has any way back from it: the
runs by hand are in ADR-044. Of 4.29, the two outcomes of a second proposal under the
name of a rule in force are unit tests only, because such an amendment needs a
hand-signed `carried` list. Of 4.30, the way back for a node that an earlier version
let a vote overwrite (running `setup` again) has no test of its own; a newer rule
that takes a name while `rule opt-in` waits at its prompt is tested where the
confirmation is counted (a unit test), and at a real prompt it was run by hand only;
and a hold caused by another circle's rule is tested for a rule placed in a project,
and in the user's skills directory it was followed through the binary by hand only
(ADR-042, "After a second review"). That a held rule is reported once per exchange
has unit tests only (`apps/peerharness/src/runtime.rs`). What a daemon prints for a
hold has unit tests (`apps/peerharness/src/commands/net.rs`), and for a hold that a
peer's push created a test with separate processes
(`apps/peerharness/tests/network.rs`); for a hold that the daemon's own timed
exchange finds, two daemons over QUIC were run by hand. What a daemon prints for a
rule that a push installed, removed or left waiting has a unit test and a test with
separate processes in the same two files; a report dropped from a full queue was not
produced by a run. Of 4.30, the second look of `proposal adopt` after a rule took the
name while the rules were being applied was not reproduced. A skill that cannot be
removed is tested through the binary for a copy in a project, whose skills directory
the tests turn into a link that leads out of the project; with a file made
unchangeable (`chattr +i`) it was run by hand only. Of 4.25, the tests show that
an opt-out succeeds and removes the rule with a passphrase that unlocks nothing;
that the machine is changed before the passphrase prompt appears was run by hand on
a pseudo-terminal. Of 4.24, a member's removal of the leaver that arrives while they
are asked has unit tests, one for each run of `circle leave`, and at a real prompt
it was run by hand for each; the preview of `circle leave --undo` has a unit test,
and through the binary it was run by hand; `circle leave` from a revoked device has
no test. Of 4.24 and 4.29, the check that a request to
change the charter and an approval of an amendment still match what was shown is
tested with a stand-in window that imports a file before it answers, and by unit
tests. The same check for a repeal and for an announced stance (4.25) has a unit
test only. Of 4.29, that a rule is proposed under the charter its preview read is
tested with such a window for `proposal create`; for `rule repeal` it has a unit
test; and the refusal of `question send` has no test of its own beyond the unit
test of `governance::charter_as_shown`. That nobody else writes between a check
and the signatures is a unit test with two connections to one file. No test tries
to write between them through the binary, command by command: that each of the
commands runs its check and its signatures in that transaction is read in the
code. No test holds a prompt in a terminal or a passphrase prompt open while a
second process changes the node: that was run by hand on a pseudo-terminal, on Linux
(ADR-041, "After a third review", "After a fourth review" and "After a review of the
pull request"). Of 4.30, what a sync report keeps of a failed removal has a unit
test only.
