# Original implementation specification (v2)

Verbatim copy of the brief this repository implements. `docs/architecture.md` resolves its open choices.

```text
PeerHarness — Coding-Agent Implementation Specification (v2)
Status: Proposed design, not existing software.
Purpose: This document is the implementation brief for an autonomous coding agent building a public Rust GitHub repository.
Primary goal: A useful, trustworthy, genuinely decentralized demo that developers can install and share.
Scope: v0.1–v0.2, with a complete local learning loop and 2–3 independent nodes exchanging signed, authorized questions, votes, and instruction-only skills.
0. Instructions to the implementing coding agent
You are implementing PeerHarness, an open-source, local-first, peer-to-peer learning harness for AI coding agents. Write running code, not just architecture documents. Deliver in small, tested milestones. Do not ask for product decisions that are resolved in this specification. If a library API differs from the description, consult the current official library documentation, adapt the code, and record the deviation in docs/decisions.md.

Hard requirements
1. One installable Rust binary named peerharness, usable with zero peers, plus a daemon mode when networking is enabled.
2. No PeerHarness-owned central server, database, account, hosted registry, blockchain, global ledger, or central approval service. Explicit peer addresses and invitation-based trust are sufficient to start.
3. Every node has independently held Ed25519 identity keys and its own SQLite database. No shared persistence between nodes.
4. Organization mode is private and deny-by-default. Peers can exchange org-scoped data only if authorized by a locally verifiable membership credential.
5. No raw transcripts, source code, secrets, prompts, or tool outputs leave a device automatically. Sharing requires a scoped, visible human authorization action; never infer consent from an agent's output.
6. Automatic candidate detection runs locally. The user is asked to confirm a candidate before local skill creation or network sharing.
7. Use the existing Agent Skills SKILL.md format. Initially distribute instruction-only skills; reject scripts, symlinks, traversal, executable payloads, and unsupported files from peers.
8. Voting is signed and independently verified, not a popularity-based security bypass. Every node evaluates its own local adoption policy.
9. No telemetry by default, no forced cloud LLM, no remote inference without opt-in. Local heuristics must support an offline demo; a local LLM provider is optional.
10. Ship an honest README, threat model, install/uninstall, demo recording script, automated tests, and reproducible release process. Do not claim security audits or production enterprise readiness.
Non-goals for this release: general-purpose agent orchestration, knowledge graph, distributed database, public DHT, token/coin, cryptocurrency, mining, smart contracts, anonymous global voting, Slack, web dashboards, Google SSO, multi-organization federation, enterprise compliance certifications, and automated execution of received scripts.
1. One-sentence product and demo
Pitch: Your AI learns from you. Your peers' AI learns from what you approve.

Target demo: Two terminals, two independent identities, two independent SQLite databases, no server. Alice corrects Claude Code: “We use pnpm, not npm, for this repo.” Her local node identifies a possible convention, asks her to confirm, and drafts an instruction-only skill. Alice explicitly allows sending a sanitized question to Bob's node. Bob's node displays the question, Bob answers, and the nodes exchange signed votes. After local acceptance checks, both users can install the skill into their agent's native skills directory. Neither user sees or downloads the other's session transcript.

For reproducibility, demo tests should be able to inject synthetic observation events instead of requiring a paid LLM or an installed coding-agent subscription.
Definition of success
- Fresh user can run peerharness init, start peerharness daemon, and create a local skill without a server.
- Two independently started instances communicate securely across local loopback or LAN using libp2p.
- A third instance without org membership cannot read org questions, votes, or skill bundles.
- A verified invitation allows a new node to join a private trust circle; authorization is checked by both nodes.
- One person can propose a skill, another can answer/vote, and both can evaluate a proposed release locally.
- Installation remains explicitly approved, reversible, and restricted to instruction-only skills.
- Local files are not transmitted as an accidental side effect of discovery.
2. Architecture: one process per node
                  Developer machine A                      Developer machine B
          +--------------------------------+      +--------------------------------+
          | Claude Code                    |      | Claude Code / other agent      |
          |    | hooks (local only)        |      |    | optional adapter          |
          |    v                           |      |    v                           |
          | peerharness binary             |      | peerharness binary             |
          |   observation -> learning      |      |   questions -> human review    |
          |   local questions / inbox      |      |   candidate / vote evaluation  |
          |   signatures / org policy      |<---->|   signatures / org policy      |
          |   skills installer             | QUIC |   skills installer             |
          |   SQLite + private keys        |      |   SQLite + private keys        |
          +--------------------------------+      +--------------------------------+

                 No shared DB. No global authority. No required coordination server.
The protocol operates in two related modes:
- Personal: local observations, local questions, and local skills; no networking required.
- Private circle: an organization/team represented by a self-sovereign trust root (a public key), with member credentials and scoped policies. Independent nodes exchange authorized data directly.
An organization can manage its own trust root without any PeerHarness vendor account. Governance may be delegated to elected/member-selected signers in future versions, but v0.1 can bootstrap with one organization owner to avoid premature consensus complexity.

Important: No universal company-wide consensus is required. A quorum makes a proposal eligible for release in a circle; each node still performs its own authorization and adoption checks.
3. Rust workspace and dependencies
peerharness/
  Cargo.toml
  README.md
  LICENSE-MIT
  LICENSE-APACHE
  AGENTS.md
  crates/
    ph-core/              # domain types, state transitions, errors
    ph-protocol/          # wire schemas, canonical encoding, signatures, vectors
    ph-identity/          # key management, invitations, membership credentials
    ph-store/             # SQLite migrations and event storage
    ph-network/           # libp2p peer transport and request/response
    ph-observer/          # Claude Code hooks and normalized local observations
    ph-learning/          # correction heuristics, optional provider abstraction
    ph-governance/        # questions, votes, policy, quorum, conflict handling
    ph-skills/            # Agent Skills formatting, validation, safe installation
  apps/
    peerharness/          # clap-based CLI and daemon entrypoint
  tests/
    fixtures/             # synthetic hook/event/protocol inputs
    network/              # 2- and 3-node integration tests
  docs/
    protocol-v0.md
    security-model.md
    decisions.md
    release.md
  demo/
    two-peers.sh
    sample-events.jsonl
Dependencies to evaluate and pin, using current released compatible versions: tokio, libp2p, clap, serde, serde_json, an RFC 8785 JSON canonicalization implementation, sha2, ed25519-dalek or libp2p identity primitives, rusqlite (bundled SQLite where appropriate), tracing, thiserror, time, rand, and a secret-handling/key-store library. Avoid OpenSSL runtime dependencies where practical.

Keep runtime services as modules/crates linked into one executable; no microservices. Test with strict clippy, formatting, and multi-node process isolation (PEERHARNESS_HOME override).
4. Command-line contract
The following commands are desired new CLI commands; they do not exist yet.
peerharness init                         # generate local device key, SQLite, config
peerharness status                       # mode, peer ID, circles, hook status
peerharness daemon --listen /ip4/127.0.0.1/udp/0/quic-v1
peerharness connect <multiaddr>          # direct authenticated P2P dial

peerharness observe demo                 # inject a safe, synthetic correction
peerharness watch claude --install       # opt-in Claude Code hook installation
peerharness watch claude --remove        # clean uninstall
peerharness inbox                        # bounded questions, no pop-up spam
peerharness review <candidate-id>        # approve/edit/reject personal rule
peerharness skills list
peerharness skills show <id>
peerharness skills install <id> --agent claude --scope user
peerharness skills uninstall <id>

peerharness circle create <name>         # local trust root
peerharness circle invite <peer-id>      # invitation bound to recipient key
peerharness circle join <invite-file>    # validate before joining
peerharness circle members
peerharness circle revoke <peer-id>

peerharness question send <candidate-id> --circle <circle>
peerharness question answer <question-id>
peerharness proposal list
peerharness proposal show <id>
peerharness proposal vote <id> approve|reject|revise
peerharness proposal status <id>
peerharness sync <peer-id>                # reconcile missing authorized events

peerharness doctor                       # local diagnostics, no cloud call
peerharness export --local               # export owned data
peerharness reset --confirm              # destructive and clearly explained
Optimize first-run flow for under five minutes to the first local result. Commands should produce concise, human-readable output and optionally --json for scripting. Protect any commands that change hook config with backups and idempotence.
5. Identity, private circles, and organizational policy
5.1 Device identity
- Generate a unique Ed25519 keypair with a cryptographically secure RNG on init.
- Store the private key using an OS secret store where supported; use a documented encrypted-at-rest fallback with strict permissions rather than silently writing plaintext private keys. If secure storage is unavailable, fail with an actionable error or require explicit insecure development mode.
- Device public key identifies the node; libp2p peer ID binds transport connections to it.
- Separate the device key from the circle authority key. Never distribute circle private keys to ordinary members.
- Permit device re-enrollment; do not pretend possession of a device key establishes the real-world identity of a human.
5.2 Circle membership
The circle ID is derived from a domain-separated hash of its founder/trust-root public key. A membership credential is a signed statement:
{
  "schema": "peerharness.membership/0.1",
  "circle_id": "sha256:...",
  "subject_device_key": "ed25519:...",
  "roles": ["member"],
  "scopes": ["team/backend"],
  "issued_at": "2026-11-09T18:00:00Z",
  "expires_at": "2026-12-09T18:00:00Z",
  "issuer_key": "ed25519:...",
  "signature": "base64url:..."
}
- Use signatures over a canonical encoded payload, not arbitrary JSON textual representation.
- Invitations are bound to a recipient device key where possible, are short-lived, and require the human recipient to verify a fingerprint out of band.
- A bearer invite alone must not silently grant organization membership. A signed issuance/acceptance handshake must bind the authorized recipient key.
- A member may propose and vote only within scopes granted by the credential.
- The founder may sign revocations in v0; nodes synchronize revocation entries and reject them appropriately. A revoked peer must not receive new data after the receiving node has learned of revocation.
- Use short-lived credentials and refresh/check membership when receiving sensitive payloads. Offline partitions limit revocation freshness; document this honestly. Previously copied data cannot be remotely erased.
5.3 Permissions
All operations enforce:
1. Authenticated device identity.
2. Valid, current circle membership and local revocation state.
3. Scope authorization (e.g., backend, repo identifier).
4. Event-specific capabilities (ask, answer, propose, vote, publish).
5. User consent for content egress or skill installation.
A majority vote cannot override denied read access, allow secret exfiltration, or install executable code.
6. Protocol v0.1 — direct request/response, not blockchain
6.1 Transport
Use rust-libp2p QUIC with authenticated peer identities and its request/response behavior. Start with explicit peer multiaddresses from invitation or local LAN discovery, not a public discovery network. No relay required for the first demo. Keep the interface able to add TCP/Noise fallback and opt-in relays when cross-network connectivity becomes necessary.

QUIC/libp2p provides authenticated encrypted transport; it does not provide circle membership and content-level authorization. Implement those in ph-identity and ph-governance.
6.2 Wire encoding and signatures
- Use RFC 8785 (JCS) canonical JSON for v0 protocol objects and sign the canonical bytes of an envelope excluding the signature field, with an explicit context prefix such as peerharness-event-v0\0.
- Derive immutable event_id as SHA-256 of that domain-separated canonical signed content.
- Enforce strict supported schema versions, event type allowlist, explicit timestamps, nonce, expiry, bounded lengths, bounded nesting, and maximum sizes.
- Track processed event IDs in SQLite to enforce idempotency. Reject expired, malformed, duplicate, unauthorized, and invalidly signed events.
- Treat remote timestamps as informational with bounded clock skew, never as the source of authorization truth.
Proposed envelope (example before signing; not an existing industry wire protocol):
{
  "schema": "peerharness.event/0.1",
  "type": "QUESTION",
  "circle_id": "sha256:circle-root-fingerprint",
  "scope": "team/backend",
  "author": "ed25519:node-public-key",
  "nonce": "base64url:random-128-bit-value",
  "created_at": "2026-11-09T18:10:00Z",
  "expires_at": "2026-11-10T18:10:00Z",
  "body": {
    "question": "Should this repository use pnpm rather than npm?",
    "related_candidate": "sha256:..."
  }
}
Add signature and event_id to the transmitted envelope. Explicitly specify the exact byte sequence signed and test it with cross-language vectors. Never include raw private observations in the event body.
6.3 Events
Event    Function    Default sharing
QUESTION    Ask peers to validate a sanitized knowledge claim    User-authorized, scoped
ANSWER    Respond with an assertion and optional rationale    User-authorized, scoped
PROPOSAL    Offer an instruction-only skill bundle hash, metadata, provenance summary    User-authorized, scoped
VOTE    Approve/reject/request-revision for a specific proposal digest    Explicit human action
RELEASE    Announce a finalized skill version/hash and approval evidence    Authorized circle only
MEMBERSHIP    Convey signed member credential    Restricted control channel
REVOCATION    Convey signed revocation entry    Restricted control channel


Protocol handlers may perform HELLO, FETCH_EVENTS, and FETCH_BUNDLE operations but they aren't themselves governance votes. Keep control-plane messages separate from knowledge-plane events.
6.4 Anti-abuse and sync
- Enforce per-peer message count, byte rate, question rate, and max concurrent requests. Sample initial caps: <=64 KiB per question/proposal message and <=256 KiB per skill bundle; document and tune.
- Only propagate events to authorized peers who have matching scope. No global gossip of private names or metadata.
- For offline sync, exchange a bounded summary of authorized event IDs/heads and request missing immutable events. Use an append-only local event log and deterministic deduplication.
- There is no global chronological ordering, proof-of-work, token, mining, or requirement to elect a unique canonical answer. Conflicting views can coexist as proposals.
- Start with direct request/response and explicit peer addresses; add gossip, rendezvous, relays, and group end-to-end encryption for offline storage later only when tested needs justify complexity.
6.5 Network boundaries
An untrusted peer may be able to connect to a libp2p listener, but it must not obtain organization-specific data, user names, skill titles, group lists, or member lists. Only advertise generic protocol capabilities prior to circle authorization. Avoid identifying the organization on public multicast discovery by default.
7. Local observation and learning
7.1 Claude Code hooks
Implement opt-in hooks, initially using the documented UserPromptSubmit and Stop events; use PostToolUseFailure only if needed and after checking its actual schema. Claude Code hook handlers receive JSON on stdin. Never assume the hook payload contains complete transcript or sufficient evidence to detect a correction. Build a normalization layer that can associate adjacent, authorized events without transmitting session content.

The installed hook should invoke a short-lived peerharness hook ... command that forwards a bounded local observation to a running daemon or a secure local spool if the daemon is absent. Hooks must not block Claude Code when PeerHarness is unavailable. Never auto-read unrelated directories or exfiltrate transcript files.
7.2 Learning abstraction
// Conceptual interface; adapt implementation details to current APIs.
trait CandidateDetector {
    fn detect(&self, observations: &[NormalizedObservation])
        -> Vec<SkillCandidate>;
}
- Implement a deterministic detector for demos: common correction patterns such as “No, use X, not Y”, “always use X for this repo”, and repeat corrections. Keep its confidence limited; always ask a human.
- Optional LocalModelDetector using a user-configured local inference provider (e.g., an Ollama-compatible endpoint). Never silently use hosted AI APIs.
- Optional remote model support in a later milestone, requiring affirmative opt-in, data preview, scope controls, and visible provider disclosure.
- Store only normalized local observations and minimal provenance references by default; expire or delete unnecessary sensitive data.
- Deduplicate candidate concepts per repository/scope; avoid proposing an existing skill repeatedly.
- Ensure low prompt noise: default <=2 unsolicited question notifications/day, inbox for the rest, per-topic cooldown and quiet-hours settings.
7.3 Candidate lifecycle
DETECTED -> LOCAL_REVIEW -> LOCAL_APPROVED -> SHARE_AUTHORIZED -> QUESTIONED -> PROPOSED -> VOTING -> ELIGIBLE -> ADOPTED / REJECTED / SUPERSEDED

No transition to SHARE_AUTHORIZED without a human action; no transition to ADOPTED based solely on agent-generated content or votes.

A person's local memory/skill can be approved even with zero peers. Joining a circle must never cause old personal memories to be uploaded automatically.
8. Human questions, democratic voting, and conflict handling
Build simple terminal interactions before any GUI.

Example:
PeerHarness: I noticed you corrected this twice:
  "This repository uses pnpm, not npm."

[A] Save locally   [E] Edit   [S] Share as a question   [N] Ignore

If S:
  Proposed sharing scope: circle:acme/team:frontend
  Exact text to transmit: "Should this repository use pnpm instead of npm?"
  [Confirm] [Cancel]
A receiving node should show only the authorized question and enough attribution to understand why it was asked, not the sender's full prompt history.

Small-circle voting policy for v0: require at least two distinct eligible device identities to approve a release (including a reviewer other than the proposer); require no unresolved rejection/request-for-revision under the configured simple policy. Distinct keys count only if issued membership credentials by the circle's trust root; keys cannot vote in unauthorized scopes. A node may impose a stricter local policy (e.g., require a known repository owner) and may choose not to adopt even after the circle's threshold is met.

Do not describe this as “truth by majority.” For factual conflicts, ask follow-up questions and keep alternative proposals until the responsible people resolve them. Every vote references a specific proposal digest; modifying the proposal invalidates earlier votes for that digest. Show provenance, signer fingerprints, and rationale in the CLI.

Prevent question spam with per-circle and per-author quotas, deduplication, local mute controls, and blocklists.
9. Skill packaging, verification, and installation
Use the existing https://agentskills.io/specification structure:
pnpm-repository-convention/
  SKILL.md
Example SKILL.md:
---
name: pnpm-repository-convention
description: Use pnpm when installing packages or running package scripts in the specified repository.
---

When working in this repository, use pnpm instead of npm for dependency
installation and package scripts. Verify repository configuration before
changing lockfiles; do not convert package managers automatically.
Keep PeerHarness approval metadata outside the SKILL.md package in the event/proposal registry. Store an immutable content-addressed archive/bundle only after strict validation. The trusted hash covers all included files and paths, not just the Markdown body.

For v0, accept and distribute only the single SKILL.md file. No scripts, assets, executable files, symlinks, archives containing extra paths, absolute paths, path traversal, or unapproved file modifications.

Before installation:
1. Validate event signature, circle membership, scope, proposal hash, vote eligibility, required approvals, and bundle digest.
2. Parse strict YAML frontmatter, enforce Agent Skills naming and description constraints, size limits, and content policies.
3. Treat all received Markdown as untrusted agent instructions; scan obvious exfiltration, secrets, and dangerous commands, but never claim scanning proves safety.
4. Display a diff and require user approval. Record installed bundle version and provenance.
5. Install atomically into a native skill directory (initially ~/.claude/skills/<name>/), with appropriate platform path handling. Never overwrite an existing manually managed skill without confirmation.
6. Support safe rollback/uninstall of files actually managed by PeerHarness.
Add a second native installer (~/.agents/skills/ for Codex) only after the Claude Code path is validated. Check current vendor docs before implementation and don't assume all agents consume skills identically.
10. SQLite model
Suggested tables (migrations required):
- identity_metadata — public identity, keystore reference, created timestamp.
- circles — circle ID, trust root public key, policy document hash.
- memberships — signed membership credentials, scopes, expiries.
- revocations — signed revocations and last-known change epoch.
- peers — peer ID, authorized addresses, connection metadata.
- observations — normalized local-only observations and retention metadata.
- candidates — local draft skill concepts, status, evidence references.
- questions — local and authorized remote question state.
- events — immutable validated signed P2P events, circle and scope.
- bundles — canonical content hash, local path, immutable version metadata.
- installations — agent, path, bundle hash, previous installed hash for rollback.
- sync_cursors — last successful sync and bounded reconciliation state.
Use migrations, transactions for state transitions, uniqueness constraints on event_id, and tests for concurrent hook writes. Store no private key bytes in the ordinary SQLite file. Locally held observation content should never appear in a P2P query unless explicitly converted to approved, redacted sharing content.
11. Security requirements and adversarial tests
Threats to explicitly test: malicious P2P clients, forged membership, stolen or duplicated votes, unauthorized scope access, compromised device, spam/DoS, replay of old messages, peer impersonation, stale revocation while offline, transcript exfiltration, prompt injection via received skills, archive/path traversal, unexpected script execution, malicious local hook payload, and untrusted repository content.

Mandatory test cases
- Connecting without a membership proves no access to any private circle data or metadata.
- A member authorized for team/frontend cannot request team/finance objects.
- An expired credential and known-revoked credential are rejected.
- A forged signature and modified signed body are rejected.
- A valid vote cannot be replayed as a new or different vote; separate devices/users cannot be invented to satisfy quorum without credentials.
- A vote for proposal hash A does not count for modified proposal hash B.
- An event containing a synthetic API token never leaves the device by default, including through logs, model calls, panic messages, or P2P events.
- A malicious SKILL.md requesting credentials or remote shell execution is not automatically installed or executed.
- A bundle with ../, absolute paths, symlinks, hidden file payloads, or unexpected files is rejected.
- Node reconnect and offline sync are idempotent; no duplicate skills, questions, or counted votes.
- A peer can refuse a previously approved skill and keep a distinct local view.
- A circle administrator cannot read personal local memories merely because they administer the circle.
- No accepted action depends on trusting LLM-generated authorization decisions.
Privacy limitation: local observations and member questions can still reveal sensitive information if the owner approves them; sanitization is heuristic. Show an exact preview and let the owner edit. End-to-end encrypted transport does not prevent an authorized recipient from copying information. Revocation does not claw back already delivered content. Device theft and compromised endpoints remain in the threat model.

Use cargo audit/dependency review, cargo deny where practical, fuzz/property testing for the wire parser and hostile bundles, and CI security checks. Arrange a separate security review before any enterprise deployment.
12. Implementation phases, deliverables, and acceptance gates
Phase A — Project skeleton and strict local identity
Implement the Cargo workspace, one binary, init, status, local config, key creation/storage, SQLite migrations, tracing with privacy-safe defaults, a runnable doctor, and packaging. Test two independent PEERHARNESS_HOME directories do not share identity or storage.

Gate: cargo test --workspace passes; the CLI is functional with network completely disabled.
Phase B — Direct secure P2P and invitation-only circles
Implement direct libp2p QUIC request/response, identity verification, circle create, invitations bound to peer keys, membership verification, restricted handler authorization, connect, circle members, and signed control events. Start two independent nodes on localhost and prove that a third unauthenticated node is rejected. Add negative tests before proceeding.

Gate: a two-process secure encrypted conversation works with no shared database and no hosted server; unauthorized peers receive no circle content.
Phase C — Local agent learning and bounded human questions
Implement Claude Code hook installer/uninstaller, normalizer, safe local observation storage, deterministic correction detector, review workflow, candidate deduplication, personal skill generation, and local skill installer. Add demo event injection and optional local model adapter.

Gate: one user can simulate or perform a correction, review a candidate, and install a valid skill while offline. No network traffic needed.
Phase D — Peer questions, signed votes, decentralized decisions
Implement QUESTION, ANSWER, PROPOSAL, VOTE, RELEASE and deterministic event hashing/signatures; approval policy; question inbox; edit-and-revise flows; provenance display; invalidation of votes when a proposal changes.

Gate: Alice asks Bob, Bob responds and approves a specific digest, Alice and Bob evaluate eligibility independently, and a malicious third node cannot vote.
Phase E — Immutable skill sharing, sync, and rollback
Implement FETCH_BUNDLE, immutable instruction-only bundles, signature/hash checks, local adoption, atomic native skill installation, safe uninstall/rollback, bounded offline event reconciliation, revocations, and replay protection.

Gate: three instances, multiple restarts, a reconnection, a conflicting proposal, and a revoked peer all behave according to the documented trust policy. No automatic script execution.
Phase F — GitHub-ready launch
Publish README with 30-second demo, exact threat model, supported platforms, install and uninstallation steps, examples with no paid API, Architecture Decision Records, protocol specification and test vectors, CONTRIBUTING, code of conduct, CI, release binaries and checksums, semantic versioning. Test install from a clean macOS and Linux environment. Windows support may be later but must be explicitly documented.

Gate: an unrelated developer can install and run the demo without help. A contributor can add a language-independent protocol client using docs/protocol-v0.md and golden test vectors.
13. End-to-end demonstration and CI tests
Implement demo/two-peers.sh or an equivalent integration runner that:
1. Creates isolated homes A, B, and unauthorized C with separate identity keys and SQLite files.
2. Starts A and B as separate OS processes bound to ephemeral loopback QUIC addresses.
3. Creates a private circle in A; B joins using a recipient-key-bound signed invitation.
4. Injects a deterministic synthetic correction into A (pnpm not npm).
5. Shows A's local candidate approval and an exact preview of the sanitized question.
6. Sends the question A -> B over authenticated P2P.
7. Has B answer and sign a vote; A receives and validates it.
8. Publishes a content-addressed instruction-only skill candidate and verifies independent local adoption.
9. Installs the skill into temporary mock agent directories rather than changing the developer's real configuration during CI.
10. Verifies C cannot see the circle's proposals or skill metadata; malicious altered signatures fail.
11. Restarts B, resynchronizes, and proves deduplication.
12. Revokes B, connects again, and verifies access denial after the remaining node has the revocation.
13. Ends with visible output: “Two independent AI harness nodes learned one shared rule. No server was involved.”
Avoid faking network communication with shared files or a mock in the actual demo; mocks are acceptable in unit tests. The demonstration must be honest about a user approval step.
14. Agent execution discipline
For each phase:
1. Read the existing code and current official library APIs before changing core interfaces.
2. Create a short phase plan and implement it, not documentation-only scaffolding.
3. Add unit tests, integration tests, negative authorization tests, and failure handling.
4. Run cargo fmt --all --check, cargo clippy --workspace --all-targets -- -D warnings, and cargo test --workspace.
5. Update the README/docs, provide exact CLI examples, and record deviations/decisions.
6. Keep features behind stable CLI boundaries and commit logically separated increments.
7. Never claim a test passed without running it; show actual results and known limitations.
Prioritize a working, safe two-node network plus the learning loop over feature breadth. Do not silently loosen security requirements to finish a demo. If a requirement cannot safely be met, leave it disabled, document the blocker, and continue with the remaining safe scope.
15. Future milestones, explicitly not part of v0.1
- Cross-NAT discovery, circuit relays and TCP fallback for restrictive corporate networks.
- True offline group delivery with application-layer E2EE and group ratcheting (evaluate MLS/OpenMLS), including safe group rekeying.
- Multi-approver issuance, delegated organizational governance, SSO-backed membership and stronger identity assurance.
- Public federation with carefully constrained publishing, scoped reputation, independent protocol implementations, and spam defenses.
- Additional adapters: Codex, Cursor, and MCP-compatible agents.
- Rich evaluation of actual agent performance, skill regression testing, and automatic suggested skill revision.
- Privacy-preserving distributed discovery beyond explicitly reviewed questions.
Design now for these possibilities; do not implement them until the small network works securely.
16. Documentation to verify against before implementation
- Claude Code hooks: https://code.claude.com/docs/en/hooks
- Agent Skills specification: https://agentskills.io/specification
- rust-libp2p: https://github.com/libp2p/rust-libp2p
- libp2p QUIC and direct connectivity: https://libp2p.io/docs/quic/ and https://libp2p.io/docs/standalone-connectivity/
- RFC 8785 JSON Canonicalization Scheme: https://www.rfc-editor.org/rfc/rfc8785
- OWASP AI Agent Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
- Optional future MLS implementation: https://github.com/openmls/openmls
Final instruction to coding agent: Begin with Phase A and Phase B. Do not jump to a dashboard, external integrations, or a central service. The definition of “PeerHarness” is independent peers that securely exchange collectively validated knowledge.
```
