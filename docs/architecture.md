# PeerHarness architecture and implementation contract (v0.1)

This file is the internal contract shared by every crate. It fixes the decisions the
specification leaves open so that crates written in parallel fit together. If you change
something here, update the code that depends on it and record the change in
`docs/decisions.md`.

## 1. Process model

* One binary, `peerharness`. Each node has its own **home directory**:
  `$PEERHARNESS_HOME`, defaulting to `~/.peerharness`. Nothing is shared between homes.
* Home layout:

  ```text
  $PEERHARNESS_HOME/
    config.toml            # local configuration (0600)
    peerharness.db         # SQLite, WAL mode (0600)
    keys/                  # encrypted key files when the file keystore is used (0700 dir, 0600 files)
    spool/observations.jsonl  # hook fallback spool (0600), drained on the next CLI/daemon run
    bundles/<hex-digest>/SKILL.md  # immutable content-addressed skill bundles
    daemon.json            # {"pid", "control_port", "token"} (0600) only while the daemon runs
    backups/               # backups of files PeerHarness changed (Claude settings)
  ```

* `peerharness daemon` runs the libp2p swarm, a delivery loop and a **local control
  endpoint**. The control endpoint is a loopback TCP listener (`127.0.0.1:0`) speaking
  newline-delimited JSON. Every request must carry a random 256-bit token, which is stored
  in `daemon.json` (0600). We use loopback TCP rather than a Unix socket because of macOS
  path-length limits on temporary homes and for future Windows support (see
  decisions.md).
* Local-only CLI commands open the store, and the keystore when they need it, directly.
  Commands that need the network (`connect`, `sync`, and immediate delivery after
  `question send`, `proposal vote` and similar) ask the daemon over the control endpoint.
  Signed events are always written to the local event log and the **outbox** first, so
  they still reach peers later if the daemon is not running.
* Hooks (`peerharness hook <event>`) never need the private key. They write a bounded,
  redacted observation straight into SQLite with a short busy timeout, fall back to the
  spool file, always exit 0, and print nothing to stdout for `UserPromptSubmit` (stdout
  there becomes model context).

## 2. Crates and dependency direction

```text
ph-core  <-  ph-protocol  <-  ph-identity
                         <-  ph-governance
                         <-  ph-skills
                         <-  ph-network
ph-core  <-  ph-store (also depends on ph-protocol for stored envelope types)
ph-core  <-  ph-observer, ph-learning
apps/peerharness depends on everything and is the only place they are wired together.
```

No crate except `apps/peerharness` may depend on `ph-store` or `ph-network`. Crates talk
through types and traits defined in `ph-core` and `ph-protocol`.

| crate | responsibility |
|---|---|
| ph-core | encodings and ID newtypes, `Scope`, `Role`, `Capability`, `CandidateStatus` state machine, `NormalizedObservation`, `SkillCandidate`, redaction (`redact` module), `Clock` trait, `MembershipOracle` trait, common errors |
| ph-protocol | RFC 8785 JCS, domain-separated signing, `Envelope` and event bodies, membership credential / acceptance / revocation / invite objects and their verification, bundle manifest and digest, wire request/response types, size/nesting limits, golden test vectors |
| ph-identity | keystore backends (OS keychain, encrypted file, explicit insecure dev), device identity, circle authority keys, credential issuance, invite creation/validation, acceptance, revocation issuance, `MembershipRegistry` implementing `MembershipOracle` |
| ph-store | SQLite migrations and typed repositories for every table in section 8 |
| ph-network | libp2p QUIC swarm with request/response, length-prefixed bounded codec, per-peer rate limits, async `NetworkHandle` API plus an inbound `RequestHandler` trait; it knows wire types but nothing about circles |
| ph-observer | Claude Code hook payload parsing and normalization, idempotent settings.json install/remove with backups, spool, notification throttle |
| ph-learning | `CandidateDetector` trait, deterministic correction detector, candidate dedup keys, skill-draft text, optional advisory agent providers (Claude Code CLI, Codex CLI, Ollama-compatible local endpoint) |
| ph-governance | incoming-event authorization pipeline, vote tallying and quorum policy, eligibility, conflict and supersede handling, question anti-spam (quotas, dedup, mute, block) |
| ph-skills | strict SKILL.md frontmatter parser and validator (Agent Skills spec), content risk scanner, bundle build and hostile-bundle validation, diff, atomic install, uninstall and rollback |

## 3. Encodings (ph-core)

All string encodings carry a self-describing prefix:

| kind | format | example |
|---|---|---|
| device / root public key | `ed25519:` + base64url (no padding) of 32 bytes | `ed25519:11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo` |
| signature | `base64url:` + base64url (no padding) of 64 bytes | |
| nonce | `base64url:` + base64url (no padding) of 16 random bytes | |
| digest / IDs | `sha256:` + 64 lowercase hex chars | `sha256:9f86d0…` |
| timestamps | RFC 3339 UTC, whole seconds, `Z` suffix | `2026-11-09T18:10:00Z` |

* `CircleId = "sha256:" + hex(SHA-256("peerharness-circle-v0\0" || root_pubkey_32_bytes))`
* Human fingerprint of a key: the first 20 hex chars of
  `SHA-256("peerharness-fingerprint-v0\0" || pubkey)`, grouped as `xxxx-xxxx-xxxx-xxxx-xxxx`.
* Scopes match `^[a-z0-9][a-z0-9._-]{0,63}(/[a-z0-9][a-z0-9._-]{0,63}){0,7}$`, are at most
  128 bytes, or are exactly `*`. A granted scope `g` **covers** an object scope `o` iff
  `g == "*"`, or `g == o`, or `o` starts with `g + "/"`. There is no other wildcard syntax.
* Roles: `owner`, `member`. Capabilities: `ask`, `answer`, `propose`, `vote`, `publish`,
  `invite`, `revoke`, `read`. `member` gets `read, ask, answer, propose, vote, publish`.
  `owner` gets all of them. Unknown roles grant nothing (reject at parse time).

## 4. Signing (ph-protocol)

Every signed object type has a context string:

| object | schema | context |
|---|---|---|
| event envelope | `peerharness.event/0.1` | `peerharness-event-v0` |
| membership credential | `peerharness.membership/0.1` | `peerharness-membership-v0` |
| acceptance | `peerharness.acceptance/0.1` | `peerharness-acceptance-v0` |
| revocation | `peerharness.revocation/0.1` | `peerharness-revocation-v0` |
| invitation | `peerharness.invite/0.1` | `peerharness-invite-v0` |

```text
unsigned   = the JSON object with the "signature" and "event_id" members removed
signing_input = UTF8(context) || 0x00 || JCS(unsigned)
signature  = Ed25519-Sign(key, signing_input)        (RFC 8032, pure Ed25519)
object_digest = "sha256:" + hex(SHA-256(signing_input))
event_id   = object_digest of an envelope
```

* JCS is our own implementation, restricted to a JSON subset: **numbers must be integers
  with |n| <= 2^53-1**. Floats are rejected, which makes cross-language implementation
  trivial. Keys are sorted by UTF-16 code units and strings use the RFC 8785 / ECMAScript
  escaping rules. Duplicate keys are rejected on parse.
* Verification recomputes `signing_input` from the received object (signature and
  event_id removed) and checks the signature with `verify_strict`. It also checks that the
  transmitted `event_id` equals the recomputed one.
* Parsers reject unknown top-level fields in envelopes and credentials (strict schema),
  JSON nesting deeper than 8, and objects over the size limits.

## 5. Events (ph-protocol)

Envelope fields: `schema`, `type`, `circle_id`, `scope`, `author`, `nonce`, `created_at`,
`expires_at`, `body`, plus the transmitted `signature` and `event_id`.

| type | body | capability | default lifetime |
|---|---|---|---|
| `QUESTION` | `{question: str<=2000, topic: str<=128, related_candidate?: digest}` | ask | 30 d |
| `ANSWER` | `{question_id: event_id, answer: "agree"\|"disagree"\|"unsure", rationale?: str<=2000}` | answer | 30 d |
| `PROPOSAL` | `{skill_name, description<=1024, title<=200, bundle_digest, bundle_size: int, related_question?: event_id, supersedes?: event_id, provenance_summary<=1000}` | propose | 90 d |
| `VOTE` | `{proposal_id: event_id, bundle_digest, decision: "approve"\|"reject"\|"revise", rationale?: str<=2000}` | vote | 90 d |
| `RELEASE` | `{proposal_id, bundle_digest, skill_name, approvals: [event_id] (<=64)}` | publish | 365 d |
| `MEMBERSHIP` | `{credential: MembershipCredential, acceptance: Acceptance}` (author must equal credential subject) | none (control plane) | credential expiry |
| `REVOCATION` | `{revocation: Revocation}` (author must be the circle root key in v0) | revoke | 365 d |

Validation (stateless part in ph-protocol, stateful part in ph-governance):

1. The canonical size is at most 64 KiB, nesting is at most 8 deep, the schema is exactly
   `peerharness.event/0.1`, and the type is in the allowlist.
2. The signature is valid and `event_id` matches.
3. `created_at <= now + 5 min` (clock skew), `expires_at > now`, `expires_at > created_at`,
   and the lifetime is at most 400 days.
4. The author holds a valid, unexpired, unrevoked credential for `circle_id` whose scopes
   cover `scope` and whose roles grant the type's capability (the `MembershipOracle`).
   MEMBERSHIP events are checked by verifying the embedded credential and acceptance
   instead.
5. `event_id` has not been processed before (store uniqueness), which gives idempotency
   and replay rejection.

Remote timestamps are informational and are never the source of authorization truth.

## 6. Membership objects (ph-protocol types; issuance in ph-identity)

```json
MembershipCredential {
  "schema": "peerharness.membership/0.1", "circle_id", "subject_device_key",
  "roles": ["member"], "scopes": ["team/backend"], "issued_at", "expires_at",
  "issuer_key", "signature"
}
Acceptance {
  "schema": "peerharness.acceptance/0.1", "circle_id", "credential_digest",
  "subject_device_key", "accepted_at", "signature"   // signed by the subject device key
}
Revocation {
  "schema": "peerharness.revocation/0.1", "circle_id", "subject_device_key",
  "revoked_at", "reason" (<=200), "issuer_key", "nonce", "signature"
}
Invite {
  "schema": "peerharness.invite/0.1", "circle_name" (<=64, local label shown to invitee),
  "circle_root_key", "credential", "issuer_device_key", "issuer_addrs": [multiaddr] (<=8),
  "invite_expires_at", "nonce", "signature"           // signed by the root key
}
```

* v0 has exactly one issuer per circle, the root key: `circle_id == derive(issuer_key)`.
* The root (authority) key is a separate Ed25519 key, distinct from the founder's device
  key, kept in the founder's keystore and never sent anywhere.
* A credential is **active** only when a matching acceptance signed by the subject exists.
  Each side verifies this when the peer authenticates: transport PeerId, then device key,
  then `subject_device_key`.
* An invite is valid for 24 h by default; the credential inside it is valid for 30 d.
  `circle join` shows the root-key fingerprint and requires confirmation (`--yes` plus
  `--expect-fingerprint` for scripts). Possession of the invite file alone is useless,
  because only the holder of the subject device key can authenticate as the subject.

## 7. Wire protocol (ph-protocol `wire`, transported by ph-network)

libp2p protocol id `/peerharness/req/0.1.0` over QUIC (`/ip4/…/udp/…/quic-v1`). Each
frame is a 4-byte big-endian length followed by a JSON body. Requests are at most
512 KiB, responses at most 512 KiB, and a larger frame closes the stream.

```text
Request                                   Response
Hello { versions: ["0.1"] }           ->  Hello { versions, capabilities: ["events","bundles"] }
Authenticate { memberships: [ {credential, acceptance} ] (<=16),
               listen_addrs: [multiaddr] (<=8) }
                                      ->  Authenticated { memberships: [ {credential, acceptance} ] }
                                          // only for circles where the REQUESTER proved membership
PushEvents { events: [Envelope] (<=64) }  ->  PushResult { results: [{event_id, status: "accepted"|"duplicate"|"rejected"}] }
FetchEvents { circle_id, known: [event_id] (<=4096), limit (<=256) }
                                      ->  Events { events: [Envelope], more: bool }
FetchBundle { circle_id, digest }     ->  Bundle { digest, files: [{path, content_b64}] }
any                                   ->  Error { code: "unauthorized"|"rate_limited"|"bad_request"|"too_large"|"unavailable" }
```

* Before authorization only `Hello` is answered. Every other request from an
  unauthenticated peer gets `Error{unauthorized}`, identical whether the circle exists or
  not. No circle names, member lists, skill titles or counts leak.
* Authorization is re-evaluated on **every** request (expiry and the latest revocation
  state), not cached from `Authenticate`.
* A node presents a credential only to a peer it believes is in that circle: the peer's
  device key is the subject of a credential it knows, or the peer is the invite issuer.
  It never presents credentials to unknown peers.
* `FetchEvents` returns only events whose scope the requester's credential covers, plus
  MEMBERSHIP and REVOCATION events for that circle. `FetchBundle` succeeds only when a
  stored PROPOSAL with that digest has a scope the requester may read.
* Rate limits, enforced in ph-network before the handler runs: per-peer token bucket
  (default 20 requests/s, burst 40), at most 512 KiB/s inbound bytes, at most 8
  concurrent inbound streams per peer. Over the limit gets `rate_limited` and a tracing
  warning with no content.

## 8. SQLite schema (ph-store)

Migrations use `PRAGMA user_version`. The database runs with WAL, `foreign_keys=ON` and
`busy_timeout`. It never stores private key bytes. Tables (the columns listed are the
minimum):

* `identity_metadata(device_key, keystore_backend, keystore_ref, created_at)`, a single row.
* `circles(circle_id PK, name, root_key, is_founder, root_keystore_ref NULL, policy_json, policy_hash, created_at)`.
* `memberships(credential_digest PK, circle_id, subject_key, roles_json, scopes_json, issued_at, expires_at, credential_json, acceptance_json NULL, is_self, received_at)`.
* `issued_invites(credential_digest PK, circle_id, invitee_key, created_at, invite_expires_at)`.
* `revocations(id PK, circle_id, subject_key, revoked_at, revocation_json, received_at)` with `UNIQUE(circle_id, subject_key)` and a per-circle epoch.
* `peers(peer_id PK, device_key, addrs_json, last_seen, blocked, muted)` and `peer_circles(peer_id, circle_id)`.
* `observations(id PK, created_at, source, session_hash, repo_key, kind, text, expires_at)`, local only and default retention 14 days.
* `candidates(id PK, concept_key, repo_key, status, statement, preferred, avoided, confidence, evidence_json, skill_name, skill_draft, circle_id NULL, scope NULL, question_event_id NULL, proposal_event_id NULL, created_at, updated_at)` with `UNIQUE(concept_key, repo_key)`.
* `questions(event_id PK, circle_id, scope, author, question, topic, is_local, status, received_at)`, where status is `new|answered|muted|dismissed`.
* `events(event_id PK, type, circle_id, scope, author, created_at, expires_at, received_at, origin_peer NULL, envelope_json)`.
* `outbox(event_id, peer_id, delivered_at NULL, attempts, PRIMARY KEY(event_id, peer_id))`.
* `bundles(digest PK, skill_name, manifest_json, rel_path, size, created_at)`.
* `skills(id PK, name, bundle_digest, origin_kind ("local"|"proposal"), origin_ref, status, created_at)`.
* `installations(id PK, skill_name, agent, install_scope, path, bundle_digest, previous_digest NULL, installed_at, removed_at NULL)`.
* `sync_cursors(peer_id, circle_id, last_sync_at, PRIMARY KEY(peer_id, circle_id))`.
* `notifications(id PK, topic, shown_at)`, used to enforce at most 2 unsolicited notifications per day and the per-topic cooldown.

State transitions run inside transactions. Inserting an event returns `Inserted` or
`Duplicate` and never errors on a duplicate.

## 9. Candidate lifecycle (ph-core)

```text
Detected -> LocalReview -> LocalApproved -> ShareAuthorized -> Questioned -> Proposed -> Voting -> Eligible -> Adopted
                        \-> Rejected                                           any non-terminal -> Superseded | Rejected
LocalApproved -> Adopted          (personal mode, human install)
LocalApproved -> ShareAuthorized  (HUMAN only)
ShareAuthorized -> Proposed       (proposal without a prior question; still human-authorized)
```

`transition(from, to, actor)` takes `Actor::Human` or `Actor::System`.
`LocalReview -> LocalApproved`, `-> ShareAuthorized` and `-> Adopted` require
`Actor::Human`. Nothing that comes from an LLM or a peer counts as human.

## 10. Governance policy (ph-governance)

The default circle policy, `{min_approvals: 2, require_non_proposer: true, block_on_reject: true}`:

* Votes count only when `vote.proposal_id == proposal.event_id` **and**
  `vote.bundle_digest == proposal.bundle_digest`. Each voter contributes one decision per
  proposal: their latest vote by `(created_at, event_id)`.
* An eligible voter holds an active credential (see section 6) from the circle root, is not
  revoked at evaluation time, has scopes covering the proposal scope, and has the `vote`
  capability.
* The proposal is **eligible** when at least `min_approvals` distinct eligible keys
  approve, at least one approver is not the proposer, and (if `block_on_reject`) no
  eligible voter's latest decision is `reject` or `revise`.
* Every node computes eligibility itself. A RELEASE event is a claim: it is re-verified
  against locally stored votes and never trusted on its own. Local stricter policy (for
  example `required_approvers = [key]`) may only add requirements.
* Conflicting proposals with the same skill name coexist. `supersedes` marks lineage but
  never moves votes over.
* Anti-spam for received questions: at most 20 per author per day and 100 per circle per
  day by default, dedup by `(circle, normalized question text)`, plus local mute and block.

## 11. Skills (ph-skills)

* A bundle is exactly one file, `SKILL.md`, of at most 256 KiB, UTF-8, with no NUL.
* Manifest: `{"schema":"peerharness.bundle/0.1","files":[{"path":"SKILL.md","sha256":"sha256:…","size":N}]}`.
  `bundle_digest = "sha256:" + hex(SHA-256("peerharness-bundle-v0\0" || JCS(manifest)))`.
  The digest therefore covers paths, sizes and content hashes.
* Frontmatter is parsed by a strict YAML-subset parser (no anchors, aliases, tags or
  multi-docs). Allowed keys are `name`, `description`, `license`, `compatibility` and
  `metadata` (string-to-string map), plus `allowed-tools`, which is parsed but flagged as
  a warning. `name` is 1-64 chars of `[a-z0-9-]`, with no leading, trailing or
  consecutive hyphens, and must equal the directory name. `description` is 1-1024 chars.
* Received bundles reject any path other than exactly `SKILL.md`, as well as `..`,
  absolute paths, backslashes, hidden files, duplicates, symlinks and extra files.
* The risk scanner gives advisory warnings (credential requests, `curl | sh`, remote
  shells, exfiltration URLs, "ignore previous instructions", long base64 blobs,
  destructive commands). High-risk findings require an extra explicit confirmation flag.
  Scanning never proves safety.
* Install target: `--agent claude --scope user` installs to `~/.claude/skills/<name>/SKILL.md`
  and `--scope project` installs to `./.claude/skills/<name>/`. The target can be overridden
  by `PEERHARNESS_CLAUDE_SKILLS_DIR` (used by tests and CI). The install is atomic: write to a
  temp dir in the same parent, fsync, then rename. A `.peerharness-managed.json` file is
  written next to `SKILL.md`. An existing directory without that marker is never
  overwritten without `--force-overwrite-unmanaged`. Uninstall removes only managed files.
  Rollback reinstalls `previous_digest` from the bundle store.

## 12. Agent providers (ph-learning, advisory only)

* `trait AgentProvider { fn name(); fn is_remote(); fn complete(&self, req: &AdvisoryRequest) -> Result<AdvisoryResponse> }`.
* `ClaudeCodeCli`: spawns the user's own unmodified `claude` binary (path from
  `PEERHARNESS_CLAUDE_BIN` or `claude` on PATH) as
  `claude -p --output-format json --max-turns 1 --no-session-persistence --tools "" <prompt>`
  in a fresh empty temp directory, with a timeout, and parses the JSON `result`.
  PeerHarness never reads, stores or forwards credentials. Claude Code authenticates
  itself. This is **remote inference**.
* `CodexCli`: `codex exec` with an equivalent read-only, no-tools setup. Also remote.
* `OllamaLocal`: HTTP to a loopback-only endpoint (non-loopback is refused unless explicitly
  configured).
* All providers are disabled by default. Remote providers need `learning.provider` set in
  config **and** a per-invocation exact preview with confirmation. Output is advisory text
  shown to the human. It never drives an authorization, state transition or install.
  Tests use a fake binary via `PEERHARNESS_CLAUDE_BIN`.

## 13. Privacy invariants (all crates)

* Observation text, prompts, transcripts and tool output never appear in tracing logs,
  error messages, panic messages, or network payloads. Log only IDs and counts.
* `transcript_path` from hook payloads is never opened.
* Only text the human has seen in an exact preview and confirmed (optionally edited) is
  placed in QUESTION, ANSWER or PROPOSAL bodies or bundles. `ph_core::redact` runs on
  every outgoing human-approved text before the preview, so the preview shows the
  redacted text.
* Joining a circle never uploads existing local candidates, observations or skills.
