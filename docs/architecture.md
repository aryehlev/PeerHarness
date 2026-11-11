# PeerHarness architecture and implementation contract

This file is the internal contract shared by every crate. It fixes the decisions the
specification leaves open so that crates written in parallel fit together. If you change
something here, update the code that depends on it and record the change in
`docs/decisions.md`.

Implementation status at this revision: the nine library crates implement and test this
contract. `apps/peerharness` wires every command of the CLI contract: the local ones
(`init`, `status`, `doctor`, `observe`, `note`, `inbox`, `review`, `skills`, `watch`,
`hook`, `export`, `reset`) and governance (`circle create`, `invite`, `join`, `members`,
`remove`, `leave`, `amend`, `device`, `mode`, `place`, `revoke`; `question`; `proposal`;
`rule`; `events`; `demo`). Nodes exchange signed events as a file or as a directory of
small files (`events export`, `events import`, `events sync`; ADR-019, ADR-025), or
directly over QUIC (`daemon`, `connect`, `sync`; section 7, ADR-026, ADR-028), with
optional discovery on the local network (ADR-031) and, also opt-in, across the internet
by device key over the public libp2p network (ADR-032). Not built: gossip, a relay run
by members, and Windows support. Where this file departs from
`docs/spec.md`, the ADRs in `docs/decisions.md` say why; the largest departure is
governance (section 10, ADR-012 onwards).

## 1. Process model

* One binary, `peerharness`. Each node has its own **home directory**:
  `$PEERHARNESS_HOME`, defaulting to `~/.peerharness`. Nothing is shared between homes.
* Home layout:

  ```text
  $PEERHARNESS_HOME/
    config.toml            # local configuration (0600)
    peerharness.db         # SQLite, WAL mode (0600)
    keys/                  # encrypted key files when the file keystore is used (0700 dir, 0600 files)
    spool/observations.jsonl  # hook fallback spool (0600), drained by the next Stop hook, `status` or `inbox`
    bundles/<hex-digest>/SKILL.md  # immutable content-addressed skill bundles
    daemon.json            # {"pid", "peer_id", "listen_addrs"} (0600) while the daemon runs; no secret
    daemon.lock            # locked exclusively by the running daemon
    backups/               # backups of files PeerHarness changed (Claude settings)
  ```

* `peerharness daemon` runs the libp2p transport in the foreground and answers peers.
  It dials on its own only when its owner started it with `--sync-every`, `--lan` or
  `--internet` (section 7), and it has no control endpoint. `daemon.json` records
  where it listens, and it holds an exclusive lock on `daemon.lock` for as long as it
  runs: that lock, which the operating system drops with the process, is how `status`
  knows a daemon is running and why a home has at most one.
* `peerharness sync <address or peer id>` starts the transport for one exchange, without
  listening: it fetches what the peer has, sends what the peer lacks, and exits. It
  needs no daemon of its own and may run while this home's daemon is serving (SQLite
  arbitrates). `connect` only checks who answers and stores the address.
* In both, one **node thread** owns the store and the unlocked keys, and every request
  is one job on it (`apps/peerharness/src/runtime.rs`). After events arrive, the circles
  concerned are settled: results published, a passed amendment notarized on the
  founder's node, the rules in force applied. A daemon tells its owner of a rule that
  a settle found held (10.9), each hold once for as long as it runs: with the report
  of its own exchange that first has it, or, for a settle that the request handler
  ran after a peer's push, as soon as the handler hands it over on a bounded queue
  (`runtime::changes_queue`, ADR-042). That queue carries what each such settle
  changed for the owner (`runtime::Changes`), and the daemon prints it as lines of
  their own (`net::pushed_report`): a rule installed or removed and a charter issued
  when it happens, a rule that waits for the owner once per proposal, a skill that
  could not be removed once per name. A batch that finds the queue full is dropped.
  Every other command that starts the transport prints nothing for a push. One
  exchange settles its circles more than once, and its report adds those settles up
  (`runtime::Changes::absorb`): a rule that waits, is held or could not be removed
  is listed once, and a skill that could not be removed leaves the list only when a
  later settle of the same circle removed it (`Changes::not_removed_in`: two circles
  can each have a rule of one name, in two places).
* Not built: a delivery loop, an outbox drain, gossip. Events reach a peer when someone
  syncs. Nothing in the CLI writes the `outbox` table yet.
* Local-only CLI commands open the store, and the keystore when they need it, directly.
  A command and this home's daemon are two processes, each with its own connection
  to the one database file. A command that signs on the strength of a check it made
  after its owner's answer runs that check and the signatures in one write
  transaction (`governance::atomically`, 10.8), so the daemon cannot store a pushed
  event between them. While the transaction is open the daemon's writes wait, up to
  the busy timeout, and its reads are answered.
* Hooks (`peerharness hook <event>`) never need the private key. They write a bounded,
  redacted observation straight into SQLite with a short busy timeout, fall back to the
  spool file, always exit 0, and print nothing to stdout for `UserPromptSubmit` (stdout
  there becomes model context). For `Stop` they may print one throttled
  `systemMessage`, which Claude Code shows to the person and not to the model: a count
  of the proposals that wait for the owner's vote (`governance::awaiting_vote`,
  ADR-035), or else of the new candidates to review. Each has its own notification
  topic, and the message holds no text written by anyone else.
* `daemon --notify` (ADR-036) looks every three seconds at the same
  `governance::awaiting_vote` and shows one notification of the operating system
  (`apps/peerharness/src/notify.rs`; macOS) for proposals it has not announced before.
  It holds a count only. Announced proposals are rows in `notifications` under the
  topic prefix `desktop:`, with limits of their own (60 seconds apart, 10 proposals a
  day, the owner's quiet hours) that the hook's throttle does not count.

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
| ph-governance | incoming-event authorization (by the membership oracle, by roll, by embedded proof, by root key), read rules, counting a vote (`tally`), result certificates, the rules in force, charter succession and amendment drafting, the local adoption gate and `LocalPolicy`, conflict and supersede handling, question anti-spam (quotas, dedup, mute, block) |
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
* Capabilities matter in one place in v0: `ask` and `answer` are what
  `authorize_incoming` asks the membership oracle for when a QUESTION or ANSWER
  arrives. The application backs that oracle with the roll of the circle's current
  charter (`ph_governance::RollOracle`, ADR-027), in which every member has the
  capabilities of the role `member`; no credential is consulted. Who may propose, vote
  and publish a result is decided by the roll of the charter (section 10), and so is
  who the transport answers and what they may read (section 7, ADR-026), never by a
  credential capability. `owner`, `invite` and `revoke` confer nothing either: the
  root key signs credentials and revocations, and the roll changes only by vote.

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
| `QUESTION` | `{question: str<=2000, topic: str<=128, related_candidate?: digest}` | the membership oracle, capability `ask`: in the application, the roll of the current charter (ADR-027) | 30 d |
| `ANSWER` | `{question_id: event_id, answer: "agree"\|"disagree"\|"unsure", rationale?: str<=2000}` | the membership oracle, capability `answer`: the roll of the current charter | 30 d |
| `PROPOSAL` | `{kind: "adopt"\|"repeal"\|"amend", charter: digest, title<=200, summary<=1000, …}` plus the members of its kind (section 10.4) | the roll of the charter it names | permanent |
| `VOTE` | `{proposal_id: event_id, decision: "approve"\|"reject"\|"revise", rationale?: str<=2000}` | the roll | permanent |
| `RESULT` | `{proposal_id: event_id, approvals: [vote event_id]}` (1-64, sorted, unique) | the roll | permanent |
| `CHARTER` | `{charter: Charter}` (author must be the circle root key, scope `*`) | root-key binding | permanent |
| `MEMBERSHIP` | `{credential: MembershipCredential, acceptance: Acceptance}` (author must equal credential subject) | the embedded credential (control plane) | credential expiry |
| `REVOCATION` | `{revocation: Revocation}` (author must be the circle root key) | root-key binding | permanent |
| `STANCE` | `{proposal_id: event_id, charter: digest, stance: "opted_out"\|"following", reason?: str<=2000}` | the roll of the charter **it** names (ADR-029) | permanent |

Three planes:

* **Deliberation** (`QUESTION`, `ANSWER`): authorized by the membership oracle, which the
  application backs with the roll of the circle's current charter (ADR-027), judged
  when the event arrives; expiring. They decide nothing.
* **Decision** (`PROPOSAL`, `VOTE`, `RESULT`): authorized by the roll of the charter the
  proposal names, never by a credential, and permanent. The answer depends only on
  signed records, so it is the same on every node and at every time.
* **Control** (`MEMBERSHIP`, `REVOCATION`, `CHARTER`): readable by every active member of
  the circle regardless of scope.

`STANCE` belongs to none of them. It is a member's public statement about a rule in
force, authorized like a ballot and read like the decision events of its rule, and it
is a record only: no tally, result, rule set or installation reads it (section 10.9).

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
   * `QUESTION`, `ANSWER`: the membership oracle grants the author the capability
     (`ask` or `answer`) for `circle_id` and `scope`, at local `now`
     (`MembershipOracle::authorize`). The application passes `RollOracle`: the
     author's device is on the roll of the circle's **current** charter, its roll
     entry covers `scope`, and the device has no locally known revocation (ADR-027).
     The oracle backed by credentials (`MembershipRegistry` in ph-identity) is
     implemented and tested in the library and is not used by the application.
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

**Records as files.** A file of JSON lines and a directory of record files (ADR-019,
ADR-025) carry one record per line or file: `{"event": <envelope>}` or `{"bundle":
{"digest": "sha256:…", "skill_md": "…"}}`. `carrier::parse_record` is the one place
where the application parses a record, and it parses it like a frame from the wire
(ADR-043): `ph_protocol::jcs::parse_strict` under `carrier::RECORD_LIMITS`, which is
1 MiB, checked before anything is parsed, and depth 9, one level more than a signed
object may have. A record has exactly one member, and a `bundle` exactly `digest` and
`skill_md`. A line that is not a record is counted as refused, and the rest of the
file is imported. The event inside then goes through the six steps above in `ingest`.
No record is read with plain `serde_json`, which keeps the last of two members with
the same name.

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
* The **charter's roll** (per person, changed only by vote, section 10) is the
  membership statement in use. It decides who may propose, vote and publish a result,
  and it decides who the transport answers and what they may read (section 7, ADR-026).
  **Credentials** (per device, root-issued, expiring) stay in the protocol and the
  library, and the application decides nothing by them. QUESTION and ANSWER events,
  which `question send` and `question answer` produce, are authorized by the roll of
  the current charter (ADR-027), and so is transport access (ADR-026), because the
  root key issues credentials without a vote. The founder's own credential is the only
  one the CLI issues. A MEMBERSHIP event is still verified by the proof it embeds, and
  stored.
* The root key also signs charters (`CircleAuthority::issue_founding_charter` and
  `issue_next_charter`). For every charter after the first it is a notary: nodes accept
  the charter only if a passed amendment justifies it (section 10.8).
* **Joining today (ADR-020).** `circle invite` puts the admission to the vote. Once it
  has passed and the next charter is issued, the inviter exports the circle's events to
  a file. `circle join <file>` picks the newest CHARTER event in it whose roll lists
  this device, among the charters of one circle: when the file or directory holds
  charters of several circles that list the device, only the circle with the expected
  root fingerprint is looked at, a fingerprint that matches none refuses, and without
  one the command stops and asks for it (`circle::charter_from_source`, ADR-043). It
  shows that charter and the root fingerprint, and on confirmation (or
  `--yes` with `--expect-fingerprint`) takes it as the node's trust anchor. The
  earlier charters in the file are then stored as history when the anchor's chain names
  them by hash (section 8, ADR-024), so the proposals and ballots from before the node
  joined verify and the rules the anchor carries arrive. The file may also be a
  directory of record files (ADR-025). The credential-based `Invite` object above is
  implemented and tested in the library and is not used by the application: joining
  from a member's node (ADR-028) does not use it either.

## 7. Wire protocol (ph-protocol `wire`, transported by ph-network)

libp2p protocol id `/peerharness/req/0.1.0` over QUIC (`/ip4/…/udp/…/quic-v1`). Each
frame is a 4-byte big-endian length followed by a JSON body. Requests are at most
512 KiB, responses at most 512 KiB, and a larger frame closes the stream.

```text
Request                                   Response
Hello { versions: ["0.1"] }           ->  Hello { versions, capabilities: ["events","bundles"] }
Authenticate { memberships: [ {credential, acceptance} ] (<=16),
               listen_addrs: [multiaddr] (<=8) }
                                      ->  Authenticated { memberships: [], circles?: [circle_id] (<=64) }
                                          // only to a requester on a roll here; `circles` are
                                          // the circles whose roll lists the requester
PushEvents { events: [Envelope] (<=64) }  ->  PushResult { results: [{event_id, status: "accepted"|"duplicate"|"rejected"}] }
FetchEvents { circle_id, known: [event_id] (<=4096), limit (<=256), after?: event_id }
                                      ->  Events { events: [Envelope], more: bool }
FetchBundle { circle_id, digest }     ->  Bundle { digest, files: [{path, content_b64}] }
any                                   ->  Error { code: "unauthorized"|"rate_limited"|"bad_request"|"too_large"|"unavailable" }
```

* **Who is answered** (`apps/peerharness/src/peer.rs`). The transport proves which
  device key is on the other end. What that key may have is decided from the **roll** of
  the current charter of the circle a request concerns (`ph_governance::RollOracle`),
  with the scopes of the member's roll entry, minus any device this node knows to be
  revoked. Credentials are not consulted (ADR-026).
* Only `Hello` is answered to anyone. Every other request from a device that is not an
  active member of the circle it concerns gets `Error{unauthorized}`, identical whether
  the circle exists here or not. No circle names, member lists, skill titles or counts
  leak.
* The decision is made again on **every** request from the store as it then is, never
  cached. A member removed by a charter this node has accepted, or revoked, is a
  stranger from the next request on.
* `Authenticate` proves nothing any more and its `memberships` may be empty. A peer on
  the roll of a circle this node holds gets `Authenticated` with the ids of the circles
  whose roll lists it; anyone else gets `unauthorized`. The `listen_addrs` it announces
  are not stored: a node dials only addresses its own owner gave it, so a member cannot
  point another member's node at an address of its choosing. A device that was just admitted holds no circle yet; this answer is
  how it learns which circle to fetch (`circle join <address>`, ADR-028). It then
  stores nothing until its owner has seen the charter and the root fingerprint and
  confirmed.
* **One exception: the removal notice** (`peer::farewell`, ADR-028). A `FetchEvents`
  from a device that is not an active member, is not revoked, and is on the roll of an
  earlier charter this node holds, is answered with the CHARTER events up to the first
  charter without it, each with the amendment, the ballots and the result that justify
  it, and nothing else. Every one of those records was readable by it as a member, and
  the removing charter is word for word the amendment it could vote on. Its node
  verifies them like any records and only then treats itself as removed. Every other
  request from it is refused.
* A syncing node sends a circle id only to a peer whose device is on that circle's roll
  as this node holds it. To a peer it shares no circle with it sends `Hello` and nothing
  more.
* `PushEvents` is accepted only for circles the pusher is a member of. Each event then
  goes through `governance::ingest` like any other: it counts by its author and
  signature, and who carried it gives it no standing. Events of one batch may depend on
  one another in any order.
* Read rule (`ph_governance::may_read_event`): a QUESTION or ANSWER, and a decision event
  with a scope other than `*`, is readable when the requester's roll entry covers its
  scope. Control-plane events (MEMBERSHIP, REVOCATION, CHARTER) and decision events with
  scope `*` are readable by every active member: a `*` proposal concerns the whole
  circle and its electorate is the whole roll, and members cannot vote on what they
  cannot read. A vote on a rule never widens read access.
* `FetchEvents` returns the events of that circle the requester may read under that
  rule, in the order this node stored them, starting after the event `after` names
  (absent or unknown: from the beginning). Stored order, not `created_at`, because an
  event can arrive long after it was created and would fall behind a time-based
  cursor. Permanent events are served however old they are; expired QUESTION, ANSWER
  and MEMBERSHIP events are not. `FetchBundle` succeeds only when a stored `adopt`
  PROPOSAL with that digest is readable by the requester.
* **Cursors.** A syncing node keeps, per peer and circle, the last event the peer served
  (the next `after`) and the last event of its own log the peer took
  (`sync_cursors`). Events it cannot place yet stay in a pool that is offered again
  with every later batch, and the fetch cursor moves only when that pool is empty; the
  push cursor moves up to the first event the peer refused. So a sync transfers what
  is new, and no event is skipped for good because of the order it arrived in. (One
  known exception, after a revocation, is in 10.12.)
* A node that accepts pushed `adopt` proposals whose bundle it lacks fetches those
  bundles back from the pusher over the same connection, then settles. The pusher's
  next request (other than `Hello` and `FetchBundle`) waits for that to finish, at most
  15 seconds, so what settling produced is there to be fetched.
* **Who is dialed.** `sync <address>` dials the address its owner gave. `sync` without
  one, and `daemon --sync-every`, dial the peers whose addresses earlier syncs stored.
  With `--lan`, members announce themselves over mDNS (`ph-network`'s `lan_discovery`,
  off by default) and a node dials only announced device keys that are on a roll it
  holds, at an address ending in that key's peer id (ADR-031). With `--internet`
  (below) a node looks up the device keys that share a roll with it, and for
  `circle join <peer id>` the one peer id its owner typed, and dials what the lookup
  returned, again only at addresses ending in that key's peer id. Nobody else is
  looked up or dialed.
* **Internet mode** (`ph-network`'s `NetworkConfig::internet`, off by default; ADR-032).
  The node joins the public libp2p network as a client: it asks that network's DHT for
  the addresses of a peer id (`find_peer`), learns from the servers whether it can be
  dialed itself (`internet_status`), holds up to two relay reservations while it
  cannot, and lets the transport replace a connection through a relay with a direct
  one (hole punching). It never serves the DHT, never relays, and stores nothing in
  the DHT. Those servers see the node's device key and IP address and the device keys
  it looks up; they are sent nothing about circles, and a relay carries TLS between the
  two device keys, which it cannot read. `ph-network` dials no peer the application
  named: the app decides from its rolls. A relayed connection gives no standing: the
  handler sees the device key at the far end and `PeerInfo::relayed`. An address
  through a relay is not stored (`peers.addrs_json`). A relay of the public network
  ends a circuit after about 128 KiB or two minutes, so a sync waits six seconds for
  the direct connection first, and the fetch cursor is kept after every batch that
  left nothing in the pool, so an exchange that a relay cuts off continues next time.
  `daemon --internet` listens on all IPv4 interfaces unless told where (a loopback
  address is refused), writes where it stands to `daemon.json` (`internet`: `joined`,
  `reachability`, `relays`, `direct_addrs`) for `status` and `doctor`, and with
  `--sync-every` also looks its circles' members up on the timer.
* Rate limits, enforced in ph-network before the handler runs: per-peer token bucket
  (default 20 requests/s, burst 40), at most 512 KiB/s inbound bytes, at most 8
  concurrent inbound streams per peer. Over the limit gets `rate_limited` and a tracing
  warning with no content.
* Limits of this transport in v0: without `--internet`, one of two syncing nodes must
  be reachable by the other. With it, two nodes behind routers get a direct connection
  only where both routers allow the hole punch; otherwise they have a public relay's
  128 KiB per connection. No port mapping, and no relay run by members. A circle still
  converges through any one member whose node the others can reach, or through the
  shared directory of ADR-025, because every member's node carries what the roll lets
  it read (ADR-031).

## 8. SQLite schema (ph-store)

Migrations use `PRAGMA user_version` (currently version 4). The database runs with WAL,
`foreign_keys=ON` and `busy_timeout`. It never stores private key bytes. Tables (the
columns listed are the minimum):

* `identity_metadata(device_key, keystore_backend, keystore_ref, created_at)`, a single row.
* `circles(circle_id PK, name, root_key, is_founder, root_keystore_ref NULL, adoption_mode, accepted_charter NULL, left_at NULL, created_at)`.
  `left_at` is set when the owner left the circle on this machine (`circle leave`):
  nothing of that circle is installed here while it is set.
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
  A charter **older** than every stored one is accepted only as history
  (`insert_charter_history`): the oldest stored charter must name it in `previous` and
  have the next `seq`. History is authenticated by that hash link alone, never becomes
  the current charter and gives nobody a vote; it exists so that the decision events
  naming it can be verified and kept.
* `rule_optouts(circle_id, skill_name, opted_out_at, PRIMARY KEY(circle_id, skill_name))`:
  rules the owner opted out of on this machine.
* `rule_installs(circle_id, skill_name, bundle_digest, installed_at, project_dir NULL, PRIMARY KEY(circle_id, skill_name))`:
  skills that were installed on this machine because a rule passed in that circle, and
  where (`project_dir` is NULL for the user's skills directory). A repeal, a
  superseding rule or an opt-out removes only what is recorded here with the digest
  still in place, so a skill the owner installed personally is never removed by a vote.
* `rule_places(circle_id, scope, project_dir, PRIMARY KEY(circle_id, scope))`: the
  project directory the owner chose for rules of a scope (`circle place`, ADR-030).
* `memberships(credential_digest PK, circle_id, subject_key, roles_json, scopes_json, issued_at, expires_at, credential_json, acceptance_json NULL, is_self, received_at)`.
* `issued_invites(credential_digest PK, circle_id, invitee_key, created_at, invite_expires_at)`.
* `revocations(id PK, circle_id, subject_key, revoked_at, revocation_json, received_at)` with `UNIQUE(circle_id, subject_key)` and a per-circle epoch.
* `peers(peer_id PK, device_key, addrs_json, last_seen, blocked, muted)` and `peer_circles(peer_id, circle_id)`.
* `observations(id PK, created_at, source, session_hash, repo_key, kind, text, expires_at)`, local only and default retention 14 days.
* `candidates(id PK, concept_key, repo_key, status, statement, preferred, avoided, confidence, evidence_json, skill_name, skill_draft, circle_id NULL, scope NULL, question_event_id NULL, proposal_event_id NULL, created_at, updated_at)` with `UNIQUE(concept_key, repo_key)`.
* `questions(event_id PK, circle_id, scope, author, question, topic, is_local, status, received_at)`, where status is `new|answered|muted|dismissed`.
* `events(event_id PK, type, circle_id, scope, author, created_at, expires_at, received_at, origin_peer NULL, ref_event_id NULL, bundle_digest NULL, envelope_json)`.
  `ref_event_id` is the `question_id` of an ANSWER, the `proposal_id` of a VOTE,
  RESULT or STANCE, or the `target` of a `repeal` PROPOSAL; `bundle_digest` is set for an `adopt`
  PROPOSAL. Queries that filter on expiry (`event_ids_for_circle`, `missing_for_peer`,
  `list_events`) treat the permanent types as never expired.
* `outbox(event_id, peer_id, delivered_at NULL, attempts, PRIMARY KEY(event_id, peer_id))`.
* `bundles(digest PK, skill_name, manifest_json, rel_path, size, created_at)`.
* `skills(id PK, name, bundle_digest, origin_kind ("local"|"proposal"), origin_ref, status, created_at)`.
* `installations(id PK, skill_name, agent, install_scope, path, bundle_digest, previous_digest NULL, installed_at, removed_at NULL)`.
* `sync_cursors(peer_id, circle_id, last_sync_at, after_event_id NULL, pushed_event_id NULL, PRIMARY KEY(peer_id, circle_id))`:
  how far a sync with that peer got (section 7, "Cursors"). `after_event_id` names an
  event in the peer's log and means something only to that peer.
* `notifications(id PK, topic, shown_at)`, used to enforce at most 2 unsolicited notifications per day and the per-topic cooldown.

State transitions run inside transactions. Inserting an event returns `Inserted` or
`Duplicate` and never errors on a duplicate. `Store::transaction` begins with `BEGIN
IMMEDIATE` at the outermost level, which takes the write lock, and is a savepoint
when it is nested. `Store::transaction_with` is the same transaction for a closure
with an error type of its caller's, so that steps of the application between the
repository calls can fail and roll everything back. Which steps go into one is the
caller's decision: the store makes no authorization decision here either.

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
exercised end to end by `peerharness demo` and by `apps/peerharness/tests`, over files,
a shared directory and QUIC. Decisions behind this section: ADR-012 to ADR-018,
ADR-023, ADR-024 and ADR-026.

### 10.1 What "democratic" means here

1. **The members decide.** A proposal passes when more than a set fraction of the
   people entitled to vote on it have approved it. No single member can block it and no
   single member, the founder included, can pass it (in a circle of two or more).
2. **One person, one vote.** Votes are counted per member, however many devices the
   member has.
3. **Everyone runs the same rules.** The thresholds and the list of members are one
   signed object, the charter, that every node holds. Two nodes holding the same
   ballots reach the same outcome.
4. **Outcomes need no clock, and no member can take one back.** An approval is never
   withdrawn by the member who gave it. Once enough exist the proposal has passed on
   every node that holds them. No deadline, no coordinator and no agreed ordering of
   events is involved. One thing takes counted approvals away: the root's revocation
   of the device that cast them (10.8, "Emergency"). A result that needed one of them
   is then open again (10.12).
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
the structure rules of 10.2. A `repeal` takes a rule out of force only if it has the
scope of its target, so that the electorate that adopted a rule is the one that repeals
it. That is part of the rule set (`rules_in_force`, 10.7) and not of what a node
stores: a proposal is kept whatever its `supersedes` or its `target` names, because
what a node keeps must not depend on the order its records came in (ADR-051).
The author must be a device of a member in the proposal's electorate.

A proposal can pass only while the charter it names is the current one. When the charter
changes, open proposals are dead and must be proposed again.

### 10.5 Ballots

`VOTE` is `{proposal_id, decision: "approve"|"reject"|"revise", rationale?}`. There is
no `bundle_digest` member: `proposal_id` is the hash of everything the proposer signed
(the signature itself is not hashed) and already binds every signed byte of it.

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

No member can shrink the set of approvals, and the result does not depend on the order
in which ballots arrive. Only a revocation takes approvals out of the count, all of the
revoked device's at once (10.8). In that one case "passed" can turn back into "not
passed" (10.12).

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
at any later time, unless a device whose ballot it lists has been revoked since.
Several `RESULT`s for one proposal may exist and all are equivalent.

### 10.7 Rules in force

The rules in force (`rules_in_force`) are a pure function of the current charter and the
proposals that count under it, with no dependence on arrival order:

```text
A = charter.carried  ∪  { adopt proposals passed under the current charter }
R = { (target, scope) of every repeal proposal passed under the current charter }
for each skill name s:
    winner(s) = the proposal in A named s with the greatest (created_at, event_id)
    s is in force, with winner(s)'s bundle, iff (winner(s), its scope) ∉ R
```

So a newer passed rule of the same name replaces the older one, and repealing the
winner leaves that name with no rule (an older one does not come back). At most one rule
per skill name is in force. A repeal counts only against a rule of its own scope: one
that names a proposal of another scope, or anything that is not an `adopt` proposal,
takes nothing out of force.

The function can only be independent of arrival order if the records it reads are.
So a node keeps a proposal whatever it names (`supersedes`, a repeal's `target`) and
whether or not it holds the event named: nothing about a PROPOSAL is checked against
other stored events when it arrives (ADR-051).

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

**What the voter is shown** (ADR-041). `proposal vote` in a terminal and `proposal
show` describe an amendment from signed content, never from its title
(`apps/peerharness/src/amendment.rs`, fed by `governance::amendment_changes`): `next`
against the charter the proposal names. The description has three parts, always in
this order and always present. The roll: members admitted and removed with device
fingerprints and scopes, and for a member who stays every device added and taken and
any change of scopes. The rules of the vote, old and new. The rules in force: by skill
name and proposal id, each rule that `next.carried` leaves out and each proposal it
lists that is not in force on this node, the latter with the rule's exact text, every
line behind a mark. A proposal that the charter in force carries and this node does
not hold (`RuleSet::missing_carried`) is listed as dropped too when `next.carried`
leaves it out, by its id and without a name. When `next.carried` lists it, it is
described as kept (`Added::kept_unheld`), with the words that this node cannot say
whether that changes anything. A listed proposal that has the name of a
rule in force is described by its outcome under 10.7 (`amendment::SameName`): it
takes that rule's place, or it is the earlier of the two and nothing changes. The
title follows, quoted, as the proposer's own words. `approve` is refused while the
node cannot show what the amendment would put in force or take out of force
(`amendment::Changes::unread`): a carried rule's text is not in the bundle store, a
carried id is not an `adopt` proposal of this circle on this node, the amendment
leaves out or keeps a carried proposal this node does not hold, or the named charter
is not held. `reject` and `revise` are not refused. For a proposal that names a charter
other than the current one the rules are not compared. The node that drafts is held
to the same: `circle invite`, `remove`, `amend` and `device` are refused while
`missing_carried` is not empty, because `carried` is filled from the rules in force
on that node and would leave the missing ones out. `circle leave` is not refused. On
such a node it changes the owner's machine and puts no request to the circle: a list
with the missing ids would bring back a rule that was repealed since, and a list
without them would drop one that is in force (10.9, "Leaving").

**What is signed is what was shown.** A sync or an import can change a node while its
owner reads a preview, and while they type a passphrase. A command that drafts an
amendment therefore calls `governance::as_drafted` after the owner's answer, after
the key is unlocked and before it signs, with no prompt between the check and the
signature. `as_drafted` takes the unlocked signing key as a parameter and does
nothing with it: the parameter keeps a caller from running the check before the
key is unlocked, which is where a passphrase is asked for. It reads the rule set
again and refuses when the digest of the current charter, `RuleSet::carried_ids` or
`RuleSet::missing_carried` differ from what the draft was built from.
`governance::propose_under` then signs the proposal under the digest of the charter
that was shown and refuses when the current charter is another one. It signs every
proposal that a command previewed: an amendment, and also a rule (`proposal create`)
and a repeal (`rule repeal`), whose previews state who votes and how many approvals
it takes, both read from that charter. `governance::propose_without_preview` signs
under whatever charter is current, returns an error for an amendment, and is called
only by `peerharness demo` and by tests. `proposal create` asks
`governance::charter_as_shown` before it saves anything. So does `question send`
before it signs: its preview states how many members can read the question, counted
on that charter's roll. `proposal vote` on an amendment checks an approval in the
same way: with the key unlocked it reads `amendment_changes` again
(`proposal::approval_as_shown`, which takes the key in the same way) and signs only
when the two readings say the same (`amendment::Changes::same_as`), and for a ballot
asked in a window only when `proposal::sole_admission` still gives the same entry
under the same charter. A repeal and an announced stance name a proposal that was
read before the preview. `rule repeal` and `--announce` look again in the same place
(`governance::rule_as_shown`) and sign nothing when that proposal is no longer the
rule of its name.

**One transaction.** Each of these checks, the one of `question send` included, runs
in one write transaction of the store with the signatures it allows
(`governance::atomically`, over `Store::transaction_with`, section 8). A process with
a connection of its own, a running daemon or an import in another terminal, cannot
commit between the check and a signature, and an error in a later step takes back
what an earlier one stored: no proposal stays without its proposer's approval.
`atomically` takes the unlocked key as a parameter, as `as_drafted` does, so that the
key is unlocked before the transaction begins. What is inside:

* for an amendment (`circle::put_amendment`, which `circle invite`, `remove`, `amend`
  and `device` share): `as_drafted`, `propose_under` and the proposer's approval;
* for `circle leave` (`circle::request_as_previewed`): the same, with the look at
  what is on record between the check and the proposal (10.9, "Leaving");
* for an approval of an amendment: `approval_as_shown` and the ballot;
* for `rule repeal`: `rule_as_shown` and `propose_under`;
* for `--announce`: `rule_as_shown` and the stance;
* for `proposal create`: `charter_as_shown`, the library entry, the candidate's walk
  to `Proposed`, `propose_under` and the candidate's link to the proposal;
* for `question send`: `charter_as_shown` and the question.

What is never inside: a prompt, a window, standard input, the network, and settling,
which follows the commit. Every other ballot is cast outside a transaction. The
bundle file that `proposal
create` writes is not taken back by a rollback: it can stay, named by no row. While a
transaction is open other writers wait, up to their busy timeout, and readers do not.

All of this is display and refusals in the application. `check_successor` and
`Passed::carried` are unchanged: an amendment that passes still makes the rule set
exactly its `carried` list.

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
  tallies and certificates verified after the revocation is known. That includes
  ballots on proposals that had already passed under the current charter: nothing
  latches a result, so such a proposal is open again (10.12). A revocation adds no
  approval to anything, and it does not change the size of the electorate.
  This is the one thing the founder's node does alone (`circle revoke`, ADR-027): it
  refuses to revoke the device it runs on, and removing the member from the roll is
  still a vote.

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
  public record of disagreement is their `reject` ballot, or, if they choose, a
  `STANCE` (`rule opt-out --announce`, ADR-029): a signed statement that they do not
  follow the rule, under the charter that lists them, so a member admitted after the
  vote can make one too. A member's latest stance on a rule is their current one. It
  is a record and nothing else: `tally`, `verify_result`, `rules_in_force` and
  `adoption_step` never read it. The opt-out on the machine does not wait for the
  announcement to be confirmed.
* **Where a rule is installed.** By default in the user's skills directory, so it
  applies in every project. The owner can place the rules of a scope in one project
  directory instead (`circle place <scope> --project <dir>`, stored in `rule_places`,
  ADR-030); the most specific placed scope that covers a rule wins. The directory comes
  from the owner's command line only, and where a member keeps a checkout is never
  shared.
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
  no such record and is never removed by a vote (ADR-023). A removal that fails keeps
  the record: the skill is reported (`Applied::not_removed`) and the next settle tries
  again, and while the old copy of a rule whose scope was moved cannot be removed, the
  rule is not installed in the new place (ADR-042). A recorded copy that was edited
  since is left in place and reported once (`Applied::kept_edited`); its record is
  cleared, so it is the owner's from then on. `skills uninstall` clears the record of
  a copy it removes (`governance::voted_install`), so that a record never outlives
  the copy it stands for.
* **A vote installs over nothing it did not install** (ADR-042). Before `adoption_step`
  is asked, and before the bundle is fetched, `apply_rules` checks each rule that binds
  the node and is not opted out with `governance::held`. A rule is held when a skill
  PeerHarness manages is at its place under its name with another text, or the same
  text edited by hand, and `rule_installs` has no row of this circle with exactly that
  digest at that place (`Held::OwnSkill`), or when its name is that of PeerHarness's
  own skill, `peerharness-notes` (`Held::ReservedName`). A held rule is reported in
  `Applied.held` and nothing is written, in either mode and when the owner confirmed.
  The same unmodified text is no conflict: the rule counts as in place, and the copy
  stays the owner's. A hold is local, like `LocalPolicy` and an opt-out. It never
  changes whether the rule passed, and a proposal is never refused at `ingest` for its
  name, so every node stores and counts the same.
* **What waits.** `Applied.asking` lists a rule in force only when it is not installed
  with the voted text and `adoption_step` says to ask. Each entry has the proposal id
  and the reason, so every command prints the line that confirms it (`Waiting::line`).
* **Leaving.** `circle leave` takes effect on the owner's machine at once
  (`circles.left_at`: nothing of that circle stays installed or is installed again) and
  then puts the owner's removal from the roll to the vote. The roll changes only by
  that vote. What the run does about the request is decided before the owner is asked
  (`circle::plan_request`), and the preview says it: the removal that was drafted for
  the preview; no request while `missing_carried` is not empty; or none by this run,
  because a proposal that is exactly that removal is on record under the charter in
  force (`circle::removals_on_record`). The order after the confirmation is fixed.
  The circle is marked as left and `governance::apply_on` removes its rules, which is
  step 3 of `settle` alone and uses no key. Only where the preview announced a
  request is the key then unlocked, the node checked with `as_drafted` against what
  the preview was built from, and that very draft signed through `propose_under` and
  approved (`circle::request_removal`). The check, the signatures and one look
  between them are a single transaction (`circle::request_as_previewed`, 10.8), and
  `circle::sign_removal` turns its outcome into the report. Nothing is drafted
  anew after the answer. No request is made when the device key does not unlock,
  when the node changed meanwhile, when exactly this removal arrived on record
  meanwhile (`request_as_previewed` reads `removals_on_record` again after
  `as_drafted`), when the proposal is refused or when the member is off the roll: the
  report says so (`requested`, `reason`). A second `circle leave` on a machine that
  left (`circle::leave_again`) first runs `governance::apply_on` again, which
  removes what the first run could not and uses no key. It then makes the request
  when none is on record, after a preview and a confirmation of its own, and signs
  it through `request_as_previewed` as the first run does: a node that changed
  meanwhile is refused, and when exactly this removal arrived on record meanwhile
  nothing is signed and the report is the one for a request on record. `circle
  leave --undo` makes no request and withdraws none. Its preview
  (`circle::follow_again_preview`) says what is on record: the request, another
  member's proposal that takes the owner off the roll and is not the request, both,
  or nothing. A node that is voted off learns of it from a peer (section 7, the removal
  notice) or from a file.
* **CLI.** `circle create` and `circle join` show the charter and record the adoption
  mode; `circle mode` changes it (switching to `follow` is a confirmation step). `rule
  list`, `rule opt-out`, `rule opt-in` and `rule repeal` cover the rules in force. `rule
  opt-out` is immediate and unasked, and waits for no key: it and `proposal refuse`
  change the machine with `apply_on` first, and unlock the device key only afterwards
  and only when `settle` has something to sign (`governance::settle_machine_first`). A
  key that does not unlock leaves that unsigned and is no error. `rule opt-in` is a
  confirmation step in the terminal (ADR-042): its preview has the rule's exact text,
  the scanner's findings and the install directory, and its confirmation counts as
  the one an install needs, so the rule is installed in mode `ask` too, in the same
  order: the machine first, a key only afterwards. `proposal adopt` confirms a rule
  that is waiting
  for the owner. Both refuse a held rule before they ask. Both pass their confirmation
  on as the id of the proposal that was shown (`Owner::confirmed`), and `apply_rules`
  counts it for that proposal only: a rule that took the name while the owner read does
  not count as confirmed in step 3 of `adoption_step`. `rule opt-in` also looks again
  before it clears the opt-out, and refuses when the rule changed. `proposal adopt`
  looks again after the confirmation and once more after the rules were applied, and
  refuses when the rule of that name is no longer the proposal it showed; where the
  shown text was installed before the name was taken, the refusal says so. `skills
  uninstall` refuses a skill installed with the text of a rule in force that its owner
  follows, in the user's skills directory and in a project, except where that skill is
  itself what holds the rule in that directory (`Held::OwnSkill`). The owner follows a
  rule that binds this node, that they have not opted out of, in a circle they have
  not left on this machine (`circles.left_at`). In a project the refusal is for a rule
  that lives in the project the command runs in, and for a copy that `rule_installs`
  records there. In the user's directory it is for every copy with that text, also one
  the owner installed while the rule is placed in a project. `proposal create` unlocks
  the device key directly after the confirmation, before it saves the rule to the
  library and marks the candidate as proposed. It saves, marks and signs in one
  transaction, after a look at whether the charter in force is still the one its
  preview counted the voters on (10.8).
  `circle invite`, `remove`, `leave`, `amend` (the thresholds, binding or advisory)
  and `device add` / `remove` propose amendments. `circle revoke` is the emergency of
  10.8. Not written yet: asking once before switching to `follow` when an amendment
  turns `binding` from false to true.

### 10.10 Rights no vote can override

These are enforced by code paths that never consult a ballot, and no charter field can
switch them off.

1. **Nothing leaves your machine without you.** Only text the owner has seen in an
   exact preview and confirmed is ever sent (section 13). No vote can make a node send
   observations, candidates or files.
2. **No vote runs code.** A rule is one instruction-only `SKILL.md`. Every bundle, built
   locally or received, is refused (`ph_skills::check_instruction_only`) if it declares
   `allowed-tools`, which would pre-approve tools for the agent, or if its file
   contains, anywhere, the syntax Claude Code executes when a skill loads
   (`has_shell_injection`): an exclamation mark directly followed by a backtick with
   another backtick anywhere after it, on that line or a later one, or three backticks
   or three tildes directly followed by an exclamation mark, wherever on a line they
   stand (ADR-051). Any file other than `SKILL.md`
   and any frontmatter key outside the allowlist of section 11 is refused as before.
3. **No vote on a rule grants access.** Who may read a circle's records is the roll,
   with the scopes in each member's entry (section 7). It changes only by an amendment
   to the roll, which every member sees and votes on, and the root key cannot widen it
   by issuing a credential (ADR-026). Nothing in `ph_governance::read` looks at a
   ballot, and passing a rule gives nobody access to anything.
4. **High-risk content always asks.** A rule with a high-risk scanner finding is never
   installed without the owner's explicit confirmation, in any mode.
5. **You can refuse.** Opt-out always works and only changes your machine. A node that
   is no longer on the roll removes what the circle's votes installed (section 10.9).
   Leaving acts on your own machine at once (`circle leave`). The roll changes only
   by the vote it starts, like any other change to it (ADR-027).
6. **Verify before acting.** A node acts on a result or a charter only after verifying
   it itself. A `RESULT` and a root-signed `CHARTER` have no authority of their own.

### 10.11 Time, expiry and replay

Outcomes depend on signatures and on the charter, never on a clock.

* `PROPOSAL`, `VOTE`, `RESULT`, `CHARTER`, `REVOCATION` and `STANCE` are permanent records
  (section 5, step 3): `expires_at` is not enforced for them at intake, in tallies or in
  `FetchEvents`. A `created_at` more than five minutes in the future is still refused,
  except for a `REVOCATION`.
* Authorization of decision events is by the roll of the charter they name, not by the
  author's credential at the time of receipt, so history can be replayed by a node that
  joins later.
* A node's first stored charter is its trust anchor and may have any `seq`. The rules
  in force are that charter's `carried` list plus what passed since. To hold the
  `PROPOSAL` events `carried` names (they name earlier charters), the node stores those
  earlier charters as history through the hash link (section 8). The founding charter
  is published as a `CHARTER` event for that purpose. Ballots from before the current
  charter are for audit only. (Nothing prunes them in v0.)
* `created_at` is used for exactly one thing, the tie-break in 10.7, where it is part
  of the signed proposal and so identical on every node.
* Replay is harmless: events are idempotent by `event_id`, and a replayed approval is
  the same approval.

### 10.12 Known limits of v0

* **Founder liveness.** Without the root key holder no charter change can happen. The
  members keep exchanging records and voting on rules: access is the roll, which does
  not expire (ADR-026). A founder who leaves the roll keeps the root key, and their node
  is then no member's peer: it can notarize later amendments only from records carried
  to it as a file or directory.
* **The founder's revocation is unilateral.** The root key can cut off any device key
  without a vote. It adds no approval to anything with that power, and every member
  sees the revocation and its reason, but nothing stops a founder from using it against
  a member they disagree with. The remedy is a new circle.
* **A revocation reaches back to results that had passed.** `rule_set` counts every
  proposal of the current charter again on each call, and `tally` ignores every ballot
  of a device with a locally known revocation, whenever it was cast. A proposal that
  had passed only with such a ballot is therefore open again on each node that learns
  of the revocation. If it adopted a rule, the rule leaves the rule set and is
  uninstalled. If it was a repeal, the repeal lapses and its target is in force and
  installed again. Rules listed in `carried` are not counted again (10.7), so they
  stay. The holder of the root key can in this way undo any result of the current
  charter that passed by a margin of one, alone, and the honest revocation of a lost
  device does the same. `crates/ph-governance/tests/adversarial.rs`
  (`founder_device_can_be_revoked_and_its_ballots_stop_counting`) shows the count
  changing. Whether a revocation should reach back is an open decision: ADR-044 has
  the facts and the options.
* **A revocation can strand a node on an old charter.** `authorize_by_roll` refuses a
  decision event from a locally revoked author, and that refusal is not retryable.
  `verify_result` and `check_successor` are given the same revocations. A node that
  stores a revocation before it has accepted a charter whose justifying result the
  revoked device signed, or whose listed ballots it cast, can then not accept that
  charter, and refuses every later one as not following its own. This was reproduced
  with `events import` and with a shared directory, where records are not read in the
  order they were made. No recovery has been tested. `reset` is not one: it deletes
  the device key, and a new key needs an amendment that may not pass once a device is
  revoked (ADR-044 has what was tried by hand). It is a defect: the outcome depends on
  the order of arrival, against 10.7 and 10.11. No fix exists; what it should be
  depends on the decision in ADR-044.
* **An amendment replaces the rule set with what it carries.** An amendment proposed
  before a rule passed, or before a repeal passed, undoes that vote when it passes
  (10.8). The reference client names each such rule to the voter and stops nothing:
  no node refuses an amendment whose `carried` list is not exact, and the founder's
  node notarizes it like any other (ADR-041). A rule that passed under the current
  charter in a scope a node cannot read is not in that node's view at all, so there
  the client names nothing.
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
* **Growth.** Decision events are permanent and nothing prunes them. Syncing no longer
  degrades with the size of the log (section 7, "Cursors"), but a first sync and a join
  transfer all of it.

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
  instructions only (`check_instruction_only`, section 10.10): no `allowed-tools`, and
  Claude Code's shell-injection syntax nowhere in the file, body or frontmatter
  (`has_shell_injection`). These are syntactic rules, not scanner heuristics, they
  refuse more than Claude Code would run, and no flag overrides them (ADR-018,
  ADR-051).
* Received bundles reject any path other than exactly `SKILL.md`, as well as `..`,
  absolute paths, backslashes, hidden files, duplicates, symlinks and extra files.
* The risk scanner gives advisory warnings (credential requests, `curl | sh`, remote
  shells, exfiltration URLs, "ignore previous instructions", long base64 blobs,
  destructive commands). High-risk findings require an extra explicit confirmation flag.
  Scanning never proves safety. Two high-risk rules are about the vote itself
  (ADR-043): `remote-instructions`, a text that tells the agent to fetch a URL and
  follow, apply or execute what it finds there, and `peerharness-guard`, a text that
  gives an instruction about PeerHarness's own guard (setting or clearing `CLAUDECODE`
  or `PEERHARNESS_AGENT_SESSION`, `--yes` in a line that names peerharness, its
  configuration). Both match wording, miss a rephrasing and can find a harmless rule.
* The skill name `peerharness-notes` is reserved for PeerHarness's own skill (section
  12.1): the application refuses it for a note, a kept rule and a proposal, and never
  installs a voted rule under it (section 10.9).
* Install target: `--agent claude --scope user` installs to `~/.claude/skills/<name>/SKILL.md`
  and `--scope project` installs to `./.claude/skills/<name>/`. The target can be overridden
  by `PEERHARNESS_CLAUDE_SKILLS_DIR` (used by tests and CI). The install is atomic: write to a
  temp dir in the same parent, fsync, then rename. A `.peerharness-managed.json` file is
  written next to `SKILL.md`. An existing directory without that marker is never
  overwritten without `--force-overwrite-unmanaged`. Uninstall removes only managed files.
  Rollback reinstalls `previous_digest` from the bundle store.

## 12. Agent providers (ph-learning, advisory only)

No command of the binary calls a provider in this version (ADR-051 corrected the
documents that read as if one did). The code and its tests are in `ph-learning`, the
config key `learning.provider` is checked when the config is read, and `doctor`
reports it. This section is the contract for a command that uses one.

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

The pattern detector recognizes corrections that name what to use, what to avoid, or
both ("use X, not Y", "no, use X", "stop using Y", "this repo uses X"). A correction
that names only one side becomes a candidate only when it was said twice. It does not
recognize whole-sentence rules ("always run the tests first"), so a rule can also be
written down directly.

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
  the owner wrote or edited, and never leaves the machine. Its name is reserved
  (`agent_notes::refuse_reserved_name`, ADR-042): `note`, `review`, `keep` and
  `proposal create` refuse a rule of that name, and no vote installs one (10.9).
* An agent's note is advisory text from `Actor::System`. At most 20 unreviewed
  agent-reported notes are kept; further ones are refused until the owner reviews some.
  Whether a note is an agent's is decided by where the command runs: inside a session
  (`consent::in_agent_session`) it is one with or without `--from-agent`. The count
  and the insert are one write transaction, so the cap holds for notes written at the
  same moment. `observe import` and `observe demo`, which store text as prompts the
  owner typed, are refused inside a session (ADR-051).
* A candidate is `Detected` until its owner was shown it: `inbox` and `review` move
  it to `LocalReview` when they list it, and the notice at the end of a turn counts
  the `Detected` ones. Inside a session the reader is the agent, so neither command
  moves anything there (ADR-051), and the owner is still told that the note waits.
* **Consent is human-only.** Every step that goes through `consent::confirm` or
  `consent::human_only` (reviewing, sharing, proposing, voting, installing, changing
  hooks) refuses with exit code 3 when the process runs inside a coding agent's session,
  with or without `--yes`. A session is recognized by a variable of
  `consent::AGENT_SESSION_ENV` being set to anything but empty or `0`: `CLAUDECODE`
  (which Claude Code sets in every command it runs), `PEERHARNESS_AGENT_SESSION`, or
  one that another agent PeerHarness connects sets (section 12.2, ADR-050). This stops an agent that is trying to help. It is not a security
  boundary: a process that clears the variable is not stopped by it (ADR-022). Since
  ADR-042 the same refusal covers `rule opt-in`, `export --local` (on standard output
  too) and `init` with the plaintext keystore; a plain `init` and `rule opt-out` are
  not consent steps. Without a terminal and without `--yes` a step refuses with a
  message that names `--yes` as the person's own, for a script they wrote, and tells a
  coding agent to stop and ask (`consent::no_terminal`).
* **Three steps can be asked in a window** (ADR-033). When the owner has turned it on
  (`peerharness setup`, or `watch claude --install --dialogs`; stored as `[agent] windows` in `config.toml`,
  off by default, never settable from a session), `proposal create`, `proposal vote` on
  an `adopt` proposal and `proposal adopt` go through `consent::confirm_or_window`.
  Inside a session that shows the exact preview in a window of the operating system
  (`apps/peerharness/src/window.rs`; macOS, `/usr/bin/osascript`) and returns `Ok` only
  for a click on "Proceed". Cancel, the return and escape keys, no answer within 90
  seconds, a window that cannot be shown and `--yes` all refuse with exit code 3. The
  preview is not printed into the session. A text that would not fit on the screen is
  not shown in part: the step is refused. The script that shows the window lays the
  text out with AppKit first and compares its height with the smallest screen
  attached, and shows nothing when that fails (ADR-051). A rule with a high-risk scanner finding, a
  ballot on anything but a rule, and every other consent step refuse inside a session
  as before. That includes `proposal create`: it shows the scanner's findings and goes
  through `consent::confirm` alone when one is high-risk (ADR-041). A rationale given
  to `proposal vote` is one line of at most 200 characters without control
  characters, invisible characters, blanks that are not spaces or characters the
  preview would rewrite (`proposal::one_line_rationale`), checked before any preview
  or window. The reporting skill then also names these three commands and `inbox`, and
  says that only the user's click decides.
* **So can three steps about who is in a circle** (ADR-037), under a setting of their
  own (`[agent] circle_windows`, turned on by the same command, which then previews
  every step it allows): `circle invite`, `proposal vote` on an amendment that admits
  one member and changes nothing else, and `circle join`. They go through
  `consent::confirm_circle_or_window`. The admission windows name the device
  fingerprint and the scopes of the new member's roll entry, both from the amendment
  (for `circle invite`, from the charter it drafted, ADR-051), and tell the owner to
  check the device with the invitee, and so do the terminal's previews of `circle
  invite` and `circle device add`; the
  join window is the terminal's preview, with the root fingerprint, the name the
  circle gets on this machine and the whole charter. That name, and the name a session
  gives to `circle create`, is one word there (letters, digits, `.`, `_`, `-`):
  later previews put it among PeerHarness's own words (ADR-051). Inside a session `circle invite` writes no events file and refuses `--out`.
  `circle join <peer id or address>` fetches the charter before it can show it, so
  inside a session it first asks `consent::circle_step_can_be_asked`: where the step
  is not allowed, or the machine can show no window, the consent step's refusal is
  given before the transport starts and before any lookup or dial (ADR-045).
  Every other `circle` step, and a ballot on any other amendment, refuse as before.
  The reporting skill then has a third part: `status`, `circle create`, `circle
  invite`, `circle join`, `sync --internet` and the daemon, with keys, peer ids and
  fingerprints taken only from what the user said in the conversation.
* **The same steps as MCP tools** (ADR-038). `peerharness mcp`
  (`apps/peerharness/src/mcp.rs`) is a Model Context Protocol server on standard input
  and output with a fixed list of tools. Each tool is a fixed command line run as a
  child process of this binary with `PEERHARNESS_AGENT_SESSION` set, so consent is asked
  or refused by the code above and by nothing in the server. Arguments are checked
  values, never flags, and the `rationale` of the `vote` tool is held to the limit
  `proposal vote` signs (`proposal::MAX_RATIONALE_CHARS`). A tool runs only at the level
  the owner allowed (`config::Asked`, read at every call). `stay_reachable` runs the
  daemon as a child for as long as the client keeps the server's input open.
  `join_circle` takes a value that parses as a peer id or a multiaddr and names nothing
  on disk (`mcp::member_of`, ADR-042). A refused tool says what the owner can do: set
  PeerHarness up when there is no node, run `peerharness setup` when a window can be
  shown and was not allowed, and, on a machine that cannot show a window, type the step
  in a terminal, with the address of the terminal guide and no mention of `setup`
  (ADR-045).
* **Keeping a rule for oneself** (ADR-040). `keep <candidate>` is `review --approve`
  and `skills install` in one consent step, through `consent::confirm_own_or_window`
  and its own setting (`[agent] own_windows`). It refuses a rule with a high-risk
  finding and a name that is taken by another text. Its preview shows the scanner's
  other findings, in the terminal and in the window. With it allowed, `note
  --from-agent` answers with the candidate's id and asks the agent to tell its user
  that there is a rule to keep or to propose.
* **One command for the owner's part** (ADR-039). `peerharness setup`
  (`apps/peerharness/src/commands/setup.rs`) runs `init` when there is no node (no
  device identity in the database, which includes a home that an interrupted `init`
  left), `watch
  claude --install` with the windows where one can be shown, and Claude Code's `claude
  mcp add` for this binary, each with its preview and confirmation. It is refused
  inside a session before it does anything. The flag of `watch claude` is `--dialogs`
  (`--windows` still works). It ends with two prompts to try only when the agent can
  open a window; otherwise with what works from the terminal. Those closing lines
  follow the level the settings allow (`config::Asked`) as well: where windows are on
  in the settings and the machine can show none, they name the tools that still run
  and `setup --no-dialogs`. For a node that is already there it names the keystore,
  and warns about a plaintext one (ADR-045).

### 12.2 Other coding agents (ADR-050)

Codex, opencode, Pi, Google Antigravity and DeepSeek Harness are connected beside
Claude Code (`apps/peerharness/src/agents.rs`), each by `watch <agent> --install` or by
`setup`, in the owner's terminal, and recorded under `[agents] connected`.

* **Rules.** Claude Code's skills directory (and a project's `.claude/skills`) stays
  the one place where rules are installed, held and removed (section 10.9). After each
  command, and after each settle in the daemon, `crate::copies` makes the directory a
  connected agent reads (`~/.agents/skills`, `~/.gemini/config/skills`, a project's
  `.agents/skills`) hold the same managed skills (`ph_skills::mirror`). A copy is
  written where nothing is under that name or over an unedited copy, and removed when
  its source is gone; an unmanaged skill and an edited copy are left and named.
  opencode reads Claude Code's directory and gets no copy.
* **Tools.** `peerharness mcp` is registered in the agent's configuration file
  (`ph_observer::agent_config`): appended to Codex's `config.toml` as one marked TOML
  block, added to the JSON of Pi (`exposure: direct`), Antigravity and opencode, and
  shown for DeepSeek Harness, whose YAML patches are not edited.
* **Sessions.** Each agent's marks are in `consent::AGENT_SESSION_ENV`
  (`Agent::session_env`). Antigravity documents none.
* **Paths.** Under the home directory, honouring the agents' own variables;
  `PEERHARNESS_AGENTS_HOME` replaces the home directory, and a debug build reads
  nothing else.

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
