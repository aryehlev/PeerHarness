# PeerHarness architecture and implementation contract (v0.1)

This file is the internal contract shared by every crate. It fixes the decisions the
specification leaves open so that crates written in parallel fit together. If you change
something here, update the code that depends on it and record the change in
`docs/decisions.md`.

Implementation status at this revision: the nine library crates implement and test this
contract. `apps/peerharness` wires the local commands (`init`, `status`, `doctor`,
`observe`, `inbox`, `watch`, `hook`, `export`) and governance (`circle create`,
`circle invite`, `circle join`, `circle members`, `proposal`, `rule`, `events`, `demo`).
Nodes exchange signed events as files (`events export` / `events import`, ADR-019).
The network daemon, including the request handler that applies the authorization rules
of section 7, is **not** wired yet, and neither are `review`, `skills`, `question`,
`circle revoke` and `reset`; statements about the daemon describe what it must
implement. Where this
file departs from `docs/spec.md`, the ADRs in `docs/decisions.md` say why; the largest
departure is governance (section 10, ADR-012 onwards).

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
| ph-protocol | RFC 8785 JCS, domain-separated signing, `Envelope` and event bodies, membership credential / acceptance / revocation / invite objects and their verification, the circle charter (rules, roll, thresholds, electorates), bundle manifest and digest, wire request/response types, size/nesting limits, golden test vectors |
| ph-identity | keystore backends (OS keychain, encrypted file, explicit insecure dev), device identity, circle authority keys, credential issuance, charter issuance (founding charter, and notarizing successors), invite creation/validation, acceptance, revocation issuance, `MembershipRegistry` implementing `MembershipOracle` |
| ph-store | SQLite migrations and typed repositories for every table in section 8 |
| ph-network | libp2p QUIC swarm with request/response, length-prefixed bounded codec, per-peer rate limits, async `NetworkHandle` API plus an inbound `RequestHandler` trait; it knows wire types but nothing about circles |
| ph-observer | Claude Code hook payload parsing and normalization, idempotent settings.json install/remove with backups, spool, notification throttle |
| ph-learning | `CandidateDetector` trait, deterministic correction detector, free-text notes (section 12.1), candidate dedup keys, skill-draft text, optional advisory agent providers (Claude Code CLI, Codex CLI, Ollama-compatible local endpoint) |
| ph-governance | incoming-event authorization (by credential, by roll, by root key), read rules, counting a vote (`tally`), result certificates, the rules in force, charter succession and amendment drafting, the local adoption gate and `LocalPolicy`, conflict and supersede handling, question anti-spam (quotas, dedup, mute, block) |
| ph-skills | strict SKILL.md frontmatter parser and validator (Agent Skills spec), the instruction-only rule for bundles, content risk scanner, bundle build and hostile-bundle validation, diff, atomic install, uninstall and rollback |

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
* Member handles (the people on a charter's roll, section 10.2) match
  `^[a-z0-9][a-z0-9._-]{0,31}$`.
* Roles: `owner`, `member`. Capabilities: `ask`, `answer`, `propose`, `vote`, `publish`,
  `invite`, `revoke`, `read`. `member` gets `read, ask, answer, propose, vote, publish`.
  `owner` gets all of them. Unknown roles grant nothing (reject at parse time).
* Only `read`, `ask` and `answer` are consulted in v0. Who may propose, vote and publish
  a result is decided by the roll of the charter (section 10), never by a credential
  capability, so `propose`, `vote` and `publish` have no effect. `owner`, `invite` and
  `revoke` confer nothing either: the root key signs credentials and revocations, and the
  roll changes only by vote.

## 4. Signing (ph-protocol)

Every signed object type has a context string:

| object | schema | context |
|---|---|---|
| event envelope | `peerharness.event/0.1` | `peerharness-event-v0` |
| membership credential | `peerharness.membership/0.1` | `peerharness-membership-v0` |
| acceptance | `peerharness.acceptance/0.1` | `peerharness-acceptance-v0` |
| revocation | `peerharness.revocation/0.1` | `peerharness-revocation-v0` |
| invitation | `peerharness.invite/0.1` | `peerharness-invite-v0` |
| charter | `peerharness.charter/0.1` | `peerharness-charter-v0` |

```text
unsigned   = the JSON object with the "signature" and "event_id" members removed
signing_input = UTF8(context) || 0x00 || JCS(unsigned)
signature  = Ed25519-Sign(key, signing_input)        (RFC 8032, pure Ed25519)
object_digest = "sha256:" + hex(SHA-256(signing_input))
event_id   = object_digest of an envelope
charter_digest = object_digest of a charter
```

* JCS is our own implementation, restricted to a JSON subset: **numbers must be integers
  with |n| <= 2^53-1**. Floats are rejected, which makes cross-language implementation
  trivial. Keys are sorted by UTF-16 code units and strings use the RFC 8785 / ECMAScript
  escaping rules. Duplicate keys are rejected on parse.
* Verification recomputes `signing_input` from the received object (signature and
  event_id removed) and checks the signature with `verify_strict`. It also checks that the
  transmitted `event_id` equals the recomputed one.
* Parsers reject unknown fields at every level of envelopes, bodies, credentials and
  charters (strict schema), JSON nesting deeper than 8, and objects over the size limits.

## 5. Events (ph-protocol)

Envelope fields: `schema`, `type`, `circle_id`, `scope`, `author`, `nonce`, `created_at`,
`expires_at`, `body`, plus the transmitted `signature` and `event_id`.

| type | body | authorized by | lifetime |
|---|---|---|---|
| `QUESTION` | `{question: str<=2000, topic: str<=128, related_candidate?: digest}` | credential capability `ask` | 30 d |
| `ANSWER` | `{question_id: event_id, answer: "agree"\|"disagree"\|"unsure", rationale?: str<=2000}` | credential capability `answer` | 30 d |
| `PROPOSAL` | `{kind: "adopt"\|"repeal"\|"amend", charter: digest, title<=200, summary<=1000, …}` plus the members of its kind (section 10.4) | the roll of the charter it names | permanent |
| `VOTE` | `{proposal_id: event_id, decision: "approve"\|"reject"\|"revise", rationale?: str<=2000}` | the roll | permanent |
| `RESULT` | `{proposal_id: event_id, approvals: [vote event_id]}` (1-64, sorted, unique) | the roll | permanent |
| `CHARTER` | `{charter: Charter}` (author must be the circle root key, scope `*`) | root-key binding | permanent |
| `MEMBERSHIP` | `{credential: MembershipCredential, acceptance: Acceptance}` (author must equal credential subject) | the embedded credential (control plane) | credential expiry |
| `REVOCATION` | `{revocation: Revocation}` (author must be the circle root key) | root-key binding | permanent |

Three planes:

* **Deliberation** (`QUESTION`, `ANSWER`): authorized by credential, expiring.
* **Decision** (`PROPOSAL`, `VOTE`, `RESULT`): authorized by the roll of the charter the
  proposal names, never by a credential, and permanent. The answer depends only on
  signed records, so it is the same on every node and at every time.
* **Control** (`MEMBERSHIP`, `REVOCATION`, `CHARTER`): readable by every active member of
  the circle regardless of scope.

Validation (stateless part in ph-protocol, stateful part in ph-governance):

1. The canonical size is at most 64 KiB, nesting is at most 8 deep, the schema is exactly
   `peerharness.event/0.1`, and the type is in the allowlist.
2. The signature is valid and `event_id` matches.
3. Time rules, by type (`check_time_rules_for`):
   * every type: `expires_at > created_at`, and the lifetime is at most 400 days;
   * every type except `REVOCATION`: `created_at <= now + 5 min` (clock skew). A
     revocation only ever denies, so it is never refused for its date (ADR-017);
   * only the expiring types (`QUESTION`, `ANSWER`, `MEMBERSHIP`): `expires_at > now`.
     The permanent types (`PROPOSAL`, `VOTE`, `RESULT`, `CHARTER`, `REVOCATION`) still
     carry `expires_at`, set by builders to `created_at + 400 d`, and receivers never
     enforce it (ADR-015).
4. Bindings between envelope and body: MEMBERSHIP author is the credential subject, same
   circle, and the envelope does not outlive the credential; REVOCATION and CHARTER
   author is the embedded object's `issuer_key` (the root), same circle; a CHARTER event
   and an `amend` PROPOSAL have scope `*`. The embedded credential and acceptance,
   revocation or charter is verified.
5. Authorization (`ph_governance::authorize_incoming`):
   * `QUESTION`, `ANSWER`: the author holds a valid, unexpired, unrevoked credential for
     `circle_id` whose scopes cover `scope` and whose roles grant the capability (the
     `MembershipOracle`), at local `now`.
   * `PROPOSAL`: the charter it names is in this node's accepted chain for the circle
     (section 8, `charters`); the author is a device of a member in the proposal's
     electorate (section 10.3); the device has no locally known revocation.
   * `VOTE`, `RESULT`: the proposal it names is stored, in the same circle and with the
     same scope; the author is a device of a member in **that proposal's** electorate,
     under the charter the proposal names; the device is not revoked locally.
   * `MEMBERSHIP`: the embedded credential and acceptance, issued by the circle root; the
     subject is not revoked locally.
   * `REVOCATION`, `CHARTER`: `circle_id == derive(author)`. For a CHARTER this only
     establishes that it is authentic; it becomes the current charter only through
     `check_successor` (section 10.8).

   A decision event whose charter or proposal has not arrived yet is refused as
   *retryable* (`unknown_charter`, `missing_proposal`): nothing is wrong with it, the
   caller may try again after the next sync.
6. `event_id` has not been processed before (store uniqueness), which gives idempotency
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
* A revocation is verified by structure and signature only
  (`verify_revocation_signature`). `revoked_at` is informational and no time rule applies
  to it, in stateless validation, in ph-governance and in the membership registry
  (ADR-017). Revocations are permanent for that device key in that circle.
* Credentials and the charter answer different questions. A **credential** (per device,
  root-issued, expiring, scoped) gives a device access: it may connect, read within its
  scopes, ask and answer. The **charter's roll** (per person, changed only by vote,
  section 10) decides who may propose, vote and publish a result.
* The root key also signs charters (`CircleAuthority::issue_founding_charter` and
  `issue_next_charter`). For every charter after the first it is a notary: nodes accept
  the charter only if a passed amendment justifies it (section 10.8).
* **Joining today (ADR-020).** `circle invite` puts the admission to the vote. Once it
  has passed and the next charter is issued, the inviter exports the circle's events to
  a file. `circle join <file>` picks the newest CHARTER event in it whose roll lists
  this device, shows that charter and the root fingerprint, and on confirmation (or
  `--yes` with `--expect-fingerprint`) takes it as the node's trust anchor. The
  credential-based `Invite` object above is for the network transport and is not used
  by the CLI yet.

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
* Read rule (`ph_governance::may_read_event`): a QUESTION or ANSWER, and a decision event
  with a scope other than `*`, is readable when the requester's credential grants `read`
  on its scope. Control-plane events (MEMBERSHIP, REVOCATION, CHARTER) and decision
  events with scope `*` are readable by every active member: a `*` proposal concerns the
  whole circle and its electorate is the whole roll, and members cannot vote on what they
  cannot read. A vote never widens read access.
* `FetchEvents` returns the events of that circle the requester may read under that
  rule. Permanent events are served however old they are; expired QUESTION, ANSWER and
  MEMBERSHIP events are not. `FetchBundle` succeeds only when a stored `adopt` PROPOSAL
  with that digest is readable by the requester.
* Rate limits, enforced in ph-network before the handler runs: per-peer token bucket
  (default 20 requests/s, burst 40), at most 512 KiB/s inbound bytes, at most 8
  concurrent inbound streams per peer. Over the limit gets `rate_limited` and a tracing
  warning with no content.
* The request handler that applies these authorization rules belongs to the daemon in
  `apps/peerharness` (ph-network knows nothing about circles). It is not written yet;
  ph-governance and ph-store provide the predicates it must compose.

## 8. SQLite schema (ph-store)

Migrations use `PRAGMA user_version` (currently version 2). The database runs with WAL,
`foreign_keys=ON` and `busy_timeout`. It never stores private key bytes. Tables (the
columns listed are the minimum):

* `identity_metadata(device_key, keystore_backend, keystore_ref, created_at)`, a single row.
* `circles(circle_id PK, name, root_key, is_founder, root_keystore_ref NULL, adoption_mode, accepted_charter NULL, created_at)`.
  `adoption_mode` is `"follow"` or `"ask"` (default `"ask"`): the owner's standing
  decision about rules that pass (section 10.9). `accepted_charter` is the digest of the
  charter the owner was last shown and accepted. There is no per-node quorum policy any
  more: the rules of the vote live in the charter.
* `charters(circle_id, seq, digest UNIQUE, charter_json, accepted_at, PRIMARY KEY(circle_id, seq))`:
  the chain of charters this node has accepted. The row with the greatest `seq` is the
  current charter. The first charter stored for a circle may have any `seq` (it is the
  node's trust anchor); every later one must have `seq` one greater than the current
  charter's and `previous` equal to its digest. The store verifies structure, root
  signature and the chain link on insert and the signature again on load. It does not
  check that a vote justifies a successor: the caller runs `check_successor` first.
* `rule_optouts(circle_id, skill_name, opted_out_at, PRIMARY KEY(circle_id, skill_name))`:
  rules the owner opted out of on this machine.
* `rule_installs(circle_id, skill_name, bundle_digest, installed_at, PRIMARY KEY(circle_id, skill_name))`:
  skills that were installed on this machine because a rule passed in that circle. A
  repeal, a superseding rule or an opt-out removes only what is recorded here with the
  digest still in place, so a skill the owner installed personally is never removed by
  a vote.
* `memberships(credential_digest PK, circle_id, subject_key, roles_json, scopes_json, issued_at, expires_at, credential_json, acceptance_json NULL, is_self, received_at)`.
* `issued_invites(credential_digest PK, circle_id, invitee_key, created_at, invite_expires_at)`.
* `revocations(id PK, circle_id, subject_key, revoked_at, revocation_json, received_at)` with `UNIQUE(circle_id, subject_key)` and a per-circle epoch.
* `peers(peer_id PK, device_key, addrs_json, last_seen, blocked, muted)` and `peer_circles(peer_id, circle_id)`.
* `observations(id PK, created_at, source, session_hash, repo_key, kind, text, expires_at)`, local only and default retention 14 days.
* `candidates(id PK, concept_key, repo_key, status, statement, preferred, avoided, confidence, evidence_json, skill_name, skill_draft, circle_id NULL, scope NULL, question_event_id NULL, proposal_event_id NULL, created_at, updated_at)` with `UNIQUE(concept_key, repo_key)`.
* `questions(event_id PK, circle_id, scope, author, question, topic, is_local, status, received_at)`, where status is `new|answered|muted|dismissed`.
* `events(event_id PK, type, circle_id, scope, author, created_at, expires_at, received_at, origin_peer NULL, ref_event_id NULL, bundle_digest NULL, envelope_json)`.
  `ref_event_id` is the `question_id` of an ANSWER, the `proposal_id` of a VOTE or
  RESULT, or the `target` of a `repeal` PROPOSAL; `bundle_digest` is set for an `adopt`
  PROPOSAL. Queries that filter on expiry (`event_ids_for_circle`, `missing_for_peer`,
  `list_events`) treat the permanent types as never expired.
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
Voting -> Proposed, Eligible -> Voting, Eligible -> Proposed   (a revised proposal starts again)
```

`transition(from, to, actor)` takes `Actor::Human` or `Actor::System`. Entering
`LocalApproved`, `ShareAuthorized`, `Proposed` or `Adopted` requires `Actor::Human`.
Nothing that comes from an LLM or a peer counts as human.

`Eligible` means the candidate's proposal **has passed** as defined in section 10.6.
`Adopted`, `Rejected` and `Superseded` are terminal.

Three things create a candidate, all as `Detected` and all as `Actor::System`: the
pattern detector, `peerharness note` (a rule written down as one sentence) and the
owner's coding agent reporting a correction (`note --from-agent`, section 12.1). Which
of them it was is a display label, never an authorization. `review --approve` is the
human step into `LocalApproved` and saves the drafted skill to the local library;
nothing is installed or shared by it. Installing that skill personally (`skills
install`) does not move the candidate to `Adopted`: the CLI leaves it at
`LocalApproved`, so the same rule can still be proposed to a circle.

## 10. Governance: majority rule under a charter (ph-protocol, ph-governance)

Status: the objects, counting, result verification, rule set, charter succession,
adoption gate and storage described here are implemented and tested in ph-protocol,
ph-governance, ph-store, ph-identity and ph-skills, and the CLI drives all of it
(`apps/peerharness/src/governance.rs`: every event, local or received, enters the store
through one `ingest` path; `settle` publishes results, notarizes passed amendments on
the founder's node and applies the rule set to the agent's skills directory). It is
exercised end to end by `peerharness demo` and by `apps/peerharness/tests`. Events
travel as files; the network daemon is not wired yet. Decisions behind this
section: ADR-012 to ADR-018 and ADR-023.

### 10.1 What "democratic" means here

1. **The members decide.** A proposal passes when more than a set fraction of the
   people entitled to vote on it have approved it. No single member can block it and no
   single member, the founder included, can pass it (in a circle of two or more).
2. **One person, one vote.** Votes are counted per member, however many devices the
   member has.
3. **Everyone runs the same rules.** The thresholds and the list of members are one
   signed object, the charter, that every node holds. Two nodes holding the same
   ballots reach the same outcome.
4. **Outcomes are final and need no clock.** Approvals only accumulate. Once enough
   exist the proposal has passed, on every node, for good. No deadline, no coordinator
   and no agreed ordering of events is involved.
5. **A passed rule takes effect.** In a binding circle a passed rule is installed for
   every member's agent. A member may opt out of a single rule.
6. **Some things are not up for a vote.** Section 10.10 lists rights that no majority
   and no charter can override.

Votes are signed and attributable, like a roll-call vote. There is no secret ballot.

### 10.2 The charter

A circle has exactly one charter in force at a time. It holds the rules of the vote, the
roll of members, and the rules carried over from the previous charter.

```json
Charter {
  "schema": "peerharness.charter/0.1",
  "circle_id": "sha256:…",
  "seq": 1,
  "previous": "sha256:…",          // digest of charter seq-1; absent iff seq == 1
  "rules": {
    "pass":  {"num": 1, "den": 2}, // ordinary proposals
    "amend": {"num": 2, "den": 3}, // proposals that change "rules"
    "binding": true                // passed rules install for every member (10.9)
  },
  "roll": [
    {"member": "alice", "devices": ["ed25519:…"], "scopes": ["*"]},
    {"member": "bob",   "devices": ["ed25519:…", "ed25519:…"], "scopes": ["team/backend"]}
  ],
  "carried": ["sha256:…"],         // adopt proposals in force when this charter began
  "justification": "sha256:…",     // RESULT event that passed it; absent iff seq == 1
  "issued_at": "2026-11-09T18:00:00Z",
  "issuer_key": "ed25519:…",       // the circle root key
  "signature": "base64url:…"
}
charter_digest = object_digest(charter)   // context "peerharness-charter-v0", section 4
```

`{rules, roll, carried}` is the charter's **content** (`CharterContent`): the part that
is voted on.

Structure rules, checked wherever a charter or a proposed content is parsed or signed:

* `member` matches `^[a-z0-9][a-z0-9._-]{0,31}$`. The roll has 1-64 entries, sorted by
  `member` and unique. Each member has 1-4 devices, sorted by their string encoding and
  unique, and 1-16 scopes (section 3 syntax), sorted and unique. A device key appears at
  most once in the whole roll.
* `carried` has at most 256 entries, sorted by their string and unique.
* `1 <= num < den <= 100` for both thresholds, `2*num >= den` (nothing passes without a
  strict majority), and `amend >= pass`.
* `circle_id == derive(issuer_key)`. `seq >= 1`, and `previous` and `justification` are
  absent exactly when `seq == 1`.
* A standalone charter document is parsed with a 64 KiB and depth 8 limit. Inside a
  `CHARTER` event or an `amend` PROPOSAL the 64 KiB envelope limit applies to the whole
  event, which is what bounds the roll and `carried` in practice.

`verify_charter_signature` checks these rules and the root signature. There are no time
rules: `issued_at` is informational.

The founding charter (`seq` 1) is `CharterContent::founding(entry)`: the default rules
shown above, the founder as the only member, nothing carried. After that the charter
changes only by vote (10.8).

### 10.3 Electorate and thresholds

The **electorate** of a proposal is fixed by the charter it names and by its envelope
scope:

* `amend` proposals: every member on the roll.
* `adopt` and `repeal` proposals with scope `*`: every member on the roll.
* `adopt` and `repeal` proposals with any other scope `s`: the members with a scope that
  covers `s` (section 3 covering rule).

The number of approvals needed from an electorate of `n` members under threshold `t` is

```text
need(n, t) = floor(n * t.num / t.den) + 1        // "more than num/den of the electorate"
```

| n | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 10 |
|---|---|---|---|---|---|---|---|---|
| need with 1/2 | 1 | 2 | 2 | 3 | 3 | 4 | 4 | 6 |
| need with 2/3 | 1 | 2 | 3 | 3 | 4 | 5 | 5 | 7 |

The threshold (`threshold_for`) is `rules.amend` for an `amend` proposal whose
`next.rules` differ from the charter's rules, and `rules.pass` for everything else,
including an `amend` that only changes the roll. An empty electorate needs one approval
and can never produce it, so it passes nothing.

Not voting counts the same as not approving. That is the price of needing no deadline,
and it is why v0 caps a roll at 64 members.

### 10.4 Proposals

A `PROPOSAL` has a kind and names the charter it is voted under. On the wire the body is
one flat object:

| member | kinds | meaning |
|---|---|---|
| `kind` | all | `"adopt"`, `"repeal"` or `"amend"` |
| `charter` | all | digest of the charter in force when proposed |
| `title` (1-200, single line), `summary` (0-1000, multi-line) | all | human-confirmed text |
| `skill_name`, `description` (1-1024), `bundle_digest`, `bundle_size` (1 to 256 KiB) | adopt | the rule |
| `related_question?`, `supersedes?` | adopt | lineage only; approvals never move between proposals |
| `target` | repeal | event id of the `adopt` proposal to take out of force |
| `next` | amend | the complete proposed content `{rules, roll, carried}` |

A member that belongs to another kind is a schema error, as is a missing member of the
proposal's own kind. An `amend` proposal has envelope scope `*` and its `next` passes
the structure rules of 10.2. A `repeal` must have the scope of its target, so that the
electorate that adopted a rule is the one that repeals it (`check_repeal_reference`).
The author must be a device of a member in the proposal's electorate.

A proposal can pass only while the charter it names is the current one. When the charter
changes, open proposals are dead and must be proposed again.

### 10.5 Ballots

`VOTE` is `{proposal_id, decision: "approve"|"reject"|"revise", rationale?}`. There is
no `bundle_digest` member: `proposal_id` is the hash of the entire signed proposal and
already binds every byte of it.

* A ballot is counted (`tally`) if it is in the proposal's circle, names the proposal,
  has the proposal's envelope scope, is signed by a device of a member in the proposal's
  electorate (per the roll of the charter the proposal names), and that device has no
  locally known revocation. Anything else is ignored with a reason.
* A ballot counts for the **member** whose roll entry lists the signing device. Two
  devices of one member are one voter.
* **A member approves a proposal once any counted `approve` ballot of theirs exists.**
  An approval cannot be withdrawn; a later `reject` from the same member does not undo
  it. A member who changes their mind after the fact proposes a repeal. When a member
  has several `approve` ballots, the one with the smallest event id is the one listed,
  so every node lists the same one.
* `reject` and `revise` ballots are the signed record of dissent and of requested
  changes. For a member who has not approved, the latest one by `(created_at, event_id)`
  is shown with its rationale. They do not affect the count. Nobody holds a veto.
* A member may go from `reject` or `revise` to `approve` by casting another ballot.

Because the set of approvals only grows, "passed" never turns back into "not passed",
and the result does not depend on the order in which ballots arrive.

### 10.6 Passing, and the result certificate

A proposal **has passed** on a node when the node holds counted approvals from at least
`need(n, t)` distinct members of its electorate, and the proposal names the node's
current charter. Each node works this out for itself from ballots it has verified.

`RESULT` replaces the earlier `RELEASE`. Its body is `{proposal_id, approvals}`, where
`approvals` lists 1 to 64 vote event ids, sorted and unique. It carries no authority. It
is a compact proof that any member of the electorate may assemble. `verify_result`
accepts it only if:

* it names the proposal, in the same circle and with the same scope;
* every listed ballot is held locally (a missing one is *retryable*: fetch it and verify
  again, it is not evidence of a bad certificate);
* its author is a device of a member in the proposal's electorate;
* counting **exactly the listed ballots** under the charter the proposal names, every
  one of them is the counted approval of a distinct member. A second ballot from the
  same member, a `reject` or `revise`, a ballot for another proposal, from a device that
  is not on the roll, or from a revoked device makes the certificate invalid;
* those approvals reach `need(n, t)`.

A node that already holds those ballots reaches the same conclusion without the
certificate. Verification uses no clock, so a certificate that verifies today verifies
forever. Several `RESULT`s for one proposal may exist and all are equivalent.

### 10.7 Rules in force

The rules in force (`rules_in_force`) are a pure function of the current charter and the
proposals that count under it, with no dependence on arrival order:

```text
A = charter.carried  ∪  { adopt proposals passed under the current charter }
R = { target of every repeal proposal passed under the current charter }
for each skill name s:
    winner(s) = the proposal in A named s with the greatest (created_at, event_id)
    s is in force, with winner(s)'s bundle, iff winner(s) ∉ R
```

So a newer passed rule of the same name replaces the older one, and repealing the
winner leaves that name with no rule (an older one does not come back). At most one rule
per skill name is in force.

A proposal enters this computation only as a `Passed` value, which has exactly two
constructors: `Passed::by_vote` (a tally of this proposal that has reached its
threshold, where the proposal names the current charter) and `Passed::carried` (an
`adopt` proposal that the current charter lists in `carried`; its ballots are not
re-counted). A proposal that names any other charter is refused as stale. Carried
proposals the node has not fetched yet are reported as missing.

### 10.8 Changing the charter: admission, removal, amendment

Every change to the roll or the rules is an `amend` proposal carrying the complete
proposed `next = {rules, roll, carried}`. `carried` should list what is in force at that
moment; `carried_diff` reports which rules a proposed list drops and which it adds, so
that a voter's node can show any difference before the human votes. Approving an
amendment also approves the rule set it carries forward. Helpers build the common
amendments with `carried` filled in: `admit_member`, `remove_member`, `add_device`,
`remove_device`, `change_rules`.

When the amendment has passed, the holder of the circle root key issues the next
charter (`CircleAuthority::issue_next_charter`) and publishes it in a `CHARTER` event.

A node accepts a charter as the successor of its current one only if `check_successor`
holds:

* its structure and root signature verify, and it has the current charter's `circle_id`
  and `issuer_key`;
* `seq` is the current `seq + 1` and `previous` is the digest of the current charter;
* `justification` is the event id of the `RESULT` supplied;
* that result's proposal is an `amend` proposal that names the current charter;
* the charter's content equals the proposal's `next` exactly;
* the result verifies under the **current** charter (10.6): its roll decides who could
  vote and its rules decide how many approvals were needed.

On acceptance the node's rule set becomes exactly `carried`: anything that passed under
the old charter but is not carried is no longer in force anywhere, which is what makes
every node converge.

The root key is therefore a **notary, not a ruler**. It cannot add a member, remove
one, or change a threshold without a passed vote, because nodes reject a charter that
no passed amendment justifies, however validly it is signed. It can refuse to sign,
which stalls changes to the charter and is visible to every member; adopt and repeal
votes keep working meanwhile.

* **Founding.** The founder issues charter 1 with themselves as the only member
  (`issue_founding_charter`).
* **Admission.** With one member, the founder's own approval is the majority. With two
  or more members an admission needs a passed vote first. (The CLI is to perform
  propose, approve, result and charter in one step when a sole founder invites.)
* **Removal** needs the same majority; the member being removed is in the electorate.
* **Devices.** Adding or replacing a member's device is an amendment to the roll.
* **Emergency.** A `REVOCATION` from the root still cuts a device off at once
  (section 6). New ballots from it are refused and its ballots are not counted in
  tallies and certificates verified after the revocation is known. It can therefore
  block but never pass anything, and it does not change the size of the electorate.

### 10.9 Binding rules, consent and opting out

Whether a rule has passed is a fact about the circle. Whether it is installed on a
machine is a decision of that machine's owner, given in advance. `adoption_step` decides
what one rule in force means on this machine, in this order:

1. the fetched bundle does not match the digest that was voted on, or is not a valid
   instruction-only skill: **refuse**. No vote and no confirmation changes this;
2. the owner opted out of this rule: leave it out;
3. the owner explicitly confirmed this rule: install;
4. the scanner reported a high-risk finding: ask the owner, in every mode;
5. the node's `LocalPolicy` is not met: ask the owner;
6. otherwise install in `follow` mode and ask in `ask` mode.

* The **adoption mode** is stored per circle (`circles.adoption_mode`) together with the
  digest of the charter the owner accepted. A node starts in `follow` after accepting a
  binding charter and in `ask` otherwise (`AdoptionMode::default_for`); the database
  default is `ask`. A member may choose `ask` in a binding circle at any time.
* **Opt-out** is a local, reversible choice recorded in `rule_optouts`. A member's
  public record of disagreement is their `reject` ballot. v0 does not broadcast
  opt-outs.
* A node's `LocalPolicy` (`required_members`, `min_approvals`; for example "only follow
  rules that member X approved") can hold a rule back for local confirmation. It never
  changes whether the rule passed. It is not met by a carried rule, whose ballots are
  not re-counted, so the owner is asked.
* **Who a rule binds.** A rule in force binds the members of its electorate: those on
  the current roll whose scopes cover the rule's scope. A node outside it (a member of
  another team, or a member who was removed) installs nothing for that rule
  (`Applied::not_bound`). Nobody is bound by a vote they were not entitled to take
  part in.
* **What a vote installed, a vote removes.** Every install made because a rule passed
  is recorded in `rule_installs`. When the rule leaves force (repealed, superseded, or
  not carried by an amendment), stops binding the node, or the owner opts out, exactly
  the recorded skill is removed, and only while the installed text still has the digest
  that was voted on. A skill the owner installed personally with `skills install` has
  no such record and is never removed by a vote (ADR-023).
* **CLI.** `circle create` and `circle join` show the charter and record the adoption
  mode. `rule list`, `rule opt-out`, `rule opt-in` and `rule repeal` cover the rules in
  force; `proposal adopt` confirms a rule that is waiting for the owner; `circle invite`
  and `circle remove` propose amendments to the roll. Not written yet: changing the
  thresholds or `binding` from the CLI, asking once before switching to `follow` when
  an amendment turns `binding` from false to true, and a `circle leave` command.

### 10.10 Rights no vote can override

These are enforced by code paths that never consult a ballot, and no charter field can
switch them off.

1. **Nothing leaves your machine without you.** Only text the owner has seen in an
   exact preview and confirmed is ever sent (section 13). No vote can make a node send
   observations, candidates or files.
2. **No vote runs code.** A rule is one instruction-only `SKILL.md`. Every bundle, built
   locally or received, is refused (`ph_skills::check_instruction_only`) if it declares
   `allowed-tools`, which would pre-approve tools for the agent, or if a line of its
   body contains the syntax Claude Code executes when a skill loads
   (`has_shell_injection`): an exclamation mark directly followed by a backtick with
   another backtick later on the same line, or a fence opened with three backticks or
   three tildes directly followed by an exclamation mark. Any file other than `SKILL.md`
   and any frontmatter key outside the allowlist of section 11 is refused as before.
3. **No vote grants access.** Read access comes only from credentials and scopes
   (section 7). Nothing in `ph_governance::read` looks at a ballot.
4. **High-risk content always asks.** A rule with a high-risk scanner finding is never
   installed without the owner's explicit confirmation, in any mode.
5. **You can refuse.** Opt-out always works and only changes your machine. A node that
   is no longer on the roll removes what the circle's votes installed (section 10.9).
   Leaving on your own is not written yet: today a member leaves the roll by a vote
   (`circle remove`), like any other change to it.
6. **Verify before acting.** A node acts on a result or a charter only after verifying
   it itself. A `RESULT` and a root-signed `CHARTER` have no authority of their own.

### 10.11 Time, expiry and replay

Outcomes depend on signatures and on the charter, never on a clock.

* `PROPOSAL`, `VOTE`, `RESULT`, `CHARTER` and `REVOCATION` are permanent records
  (section 5, step 3): `expires_at` is not enforced for them at intake, in tallies or in
  `FetchEvents`. A `created_at` more than five minutes in the future is still refused,
  except for a `REVOCATION`.
* Authorization of decision events is by the roll of the charter they name, not by the
  author's credential at the time of receipt, so history can be replayed by a node that
  joins later.
* A node's first stored charter is its trust anchor and may have any `seq`; it needs no
  earlier history. That charter plus the `PROPOSAL` events named in `carried` and their
  bundles give it every rule in force. Ballots from before the current charter are for
  audit only. (Nothing prunes them in v0.)
* `created_at` is used for exactly one thing, the tie-break in 10.7, where it is part
  of the signed proposal and so identical on every node.
* Replay is harmless: events are idempotent by `event_id`, and a replayed approval is
  the same approval.

### 10.12 Known limits of v0

* **Founder liveness.** Without the root key holder no charter change (and no
  credential renewal, section 6) can happen.
* **Founder equivocation.** If two different amendments both pass under one charter,
  which needs some member to approve both, the root chooses which to notarize. A root
  that signs two successors can split the circle: a node keeps the first valid one it
  accepts and refuses the other as not following its current charter.
* **Turnout.** A member who never votes makes every threshold harder to reach.
  Removing them is itself a vote.
* **Compromised device.** Its approvals count until a revocation is known locally;
  nodes that learn of the revocation at different times can disagree on an open
  proposal until the next charter change makes `carried` the rule set everywhere.
* **Founding bias.** The founder alone admits the second member, and the first two
  together admit the third.
* **Trust anchor on joining.** A node that joins late takes its first charter, and the
  `carried` list in it, on the root's signature. It does not re-count the ballots behind
  carried rules.
* **Growth.** Decision events are permanent and nothing prunes them, while
  `FetchEvents.known` is capped at 4096 ids and has no cursor (section 7).

### 10.13 Worked example

Roll: alice, bob, carol, all with scope `*`. Rules: pass 1/2, binding. `need(3, 1/2) = 2`.

1. Alice proposes `adopt pnpm-repository-convention` under charter 3.
2. Alice approves. One of two needed.
3. Carol casts `reject` with the rationale "our CI images only ship npm". Recorded, no
   effect on the count.
4. Bob approves. Two of two: the proposal has passed on every node that holds both
   ballots. Bob's node publishes a `RESULT` listing the two approvals.
5. All three nodes are in `follow` mode, the bundle verifies and has no high-risk
   finding, so `adoption_step` returns install on all three. Carol's tally shows it
   passed 2 to 1 with her own dissent on record; she may opt out of the rule.

The golden vectors tell a similar story end to end, including a charter change:
`crates/ph-protocol/tests/vectors/events.json` and `charters.json`.

## 11. Skills (ph-skills)

* A bundle is exactly one file, `SKILL.md`, of at most 256 KiB, UTF-8, with no NUL.
* Manifest: `{"schema":"peerharness.bundle/0.1","files":[{"path":"SKILL.md","sha256":"sha256:…","size":N}]}`.
  `bundle_digest = "sha256:" + hex(SHA-256("peerharness-bundle-v0\0" || JCS(manifest)))`.
  The digest therefore covers paths, sizes and content hashes.
* Frontmatter is parsed by a strict YAML-subset parser (no anchors, aliases, tags or
  multi-docs). Allowed keys are `name`, `description`, `license`, `compatibility` and
  `metadata` (string-to-string map), plus `allowed-tools`, which the parser accepts and
  the scanner flags, but which no bundle may contain (next bullet). `name` is 1-64 chars of `[a-z0-9-]`, with no leading, trailing or
  consecutive hyphens, and must equal the directory name. `description` is 1-1024 chars.
* Every bundle, built locally (`build_bundle`) or received (`validate_received`), must be
  instructions only (`check_instruction_only`, section 10.10): no `allowed-tools`, and no
  body line with Claude Code's shell-injection syntax (`has_shell_injection`). These are
  exact syntactic rules, not scanner heuristics, and no flag overrides them (ADR-018).
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

### 12.1 Notes, and corrections reported by the agent

The pattern detector recognizes a few shapes of "use X, not Y" in prompts. Most real
corrections are sentences, so a rule can also be written down directly.

* `peerharness note "<one sentence>"` creates a candidate from free text
  (`ph_learning::note`): `concept_key = "note:" + ` the first 16 hex characters of
  `SHA-256("peerharness-note-v0" || 0x00 || normalized statement)`, no evidence
  observations, `Confidence::Low`, and topic `note` or `agent-note`. The statement is
  redacted (`ph_core::redact`) and must be one line of 1-500 characters. Text that
  could not become an instruction-only skill is refused at once.
* Its skill draft is the statement: the description is the statement, and the body is
  the fixed heading `# Rule`, the statement, and one fixed sentence saying that what the
  user asks for in the current session wins over the rule. The skill name comes from the
  first meaningful ASCII words of the statement (or is `rule-<8 hex>` when there are
  none), or is given with `--name`.
* `watch claude --install` also installs `peerharness-notes`, a fixed skill that asks
  the agent to run `note --from-agent` when the user corrects it
  (`apps/peerharness/src/agent_notes.rs`). `--no-agent-notes` skips it and `--remove`
  removes it. It is installed and marked like any managed skill, never replaces a skill
  the owner wrote or edited, and never leaves the machine.
* An agent's note is advisory text from `Actor::System`. At most 20 unreviewed
  agent-reported notes are kept; further ones are refused until the owner reviews some.
* **Consent is human-only.** Every step that goes through `consent::confirm` or
  `consent::human_only` (reviewing, sharing, proposing, voting, installing, changing
  hooks) refuses with exit code 3 when the process runs inside a coding agent's session,
  with or without `--yes`. A session is recognized by `CLAUDECODE` (which Claude Code
  sets in every command it runs) or `PEERHARNESS_AGENT_SESSION` being set to anything
  but empty or `0`. This stops an agent that is trying to help. It is not a security
  boundary: a process that clears the variable is not stopped by it (ADR-022).

## 13. Privacy invariants (all crates)

* Observation text, prompts, transcripts and tool output never appear in tracing logs,
  error messages, panic messages, or network payloads. Log only IDs and counts.
* `transcript_path` from hook payloads is never opened.
* Only text the human has seen in an exact preview and confirmed (optionally edited) is
  placed in QUESTION, ANSWER or PROPOSAL bodies or bundles. `ph_core::redact` runs on
  every outgoing human-approved text before the preview, so the preview shows the
  redacted text.
* A note is stored locally after redaction. It reaches a bundle or a PROPOSAL only
  through the same exact preview and confirmation as any other text.
* Joining a circle never uploads existing local candidates, observations or skills.
