# PeerHarness protocol v0

Status: v0 (schema versions `*/0.1`, wire protocol `/peerharness/req/0.1.0`). This is a
draft protocol for a demo-grade release. It has not been reviewed by a third party and
no security audit has been done.

This document specifies everything a third party needs to write a client that
interoperates with the reference implementation: encodings, canonical JSON, signatures,
derived identifiers, every signed object, the wire protocol, authorization, sync and
voting. It is language independent. Where it says "the reference implementation",
it names the Rust module that implements the rule so you can check the source.

The source code is normative. Every rule here was taken from the source
(`crates/ph-core`, `crates/ph-protocol`, `crates/ph-network`, `crates/ph-governance`,
`crates/ph-identity`, `crates/ph-skills`). `docs/architecture.md` is the internal design
contract; where the two differ, the source wins and Appendix B lists the differences.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## Contents

1. [Overview](#1-overview)
2. [Primitive encodings](#2-primitive-encodings)
3. [JSON subset and canonical form (JCS)](#3-json-subset-and-canonical-form-jcs)
4. [Signing](#4-signing)
5. [Derived identifiers](#5-derived-identifiers)
6. [Free-text fields](#6-free-text-fields)
7. [Event envelope](#7-event-envelope)
8. [Event types and bodies](#8-event-types-and-bodies)
9. [Membership objects](#9-membership-objects)
10. [Skill bundles](#10-skill-bundles)
11. [Wire protocol](#11-wire-protocol)
12. [Authorization](#12-authorization)
13. [Sync](#13-sync)
14. [Governance: voting under a charter](#14-governance-voting-under-a-charter)
15. [Versioning](#15-versioning)
16. [Golden vectors and a worked example](#16-golden-vectors-and-a-worked-example)
- [Appendix A: limits](#appendix-a-limits)
- [Appendix B: differences from architecture.md](#appendix-b-differences-from-architecturemd)

## 1. Overview

A PeerHarness **node** has one Ed25519 **device key**. The device key is also the node's
libp2p identity, so the QUIC/TLS-authenticated libp2p `PeerId` proves the device key.

A **circle** is a private group defined by an Ed25519 **root key** (the trust root). The
circle id is a hash of the root public key. In v0 the root key is the only issuer: it
signs membership credentials, invites, revocations and charters. The root key is
distinct from every device key and never leaves the founder's keystore.

A **membership credential** (signed by the root) grants a device key roles and scopes in
the circle until an expiry. It only becomes **active** once the subject signs an
**acceptance** of it. A credential plus its acceptance is a **membership proof**.

A circle governs itself by majority vote under a **charter**: one object, signed by the
root, that holds the rules of the vote and the **roll** of members (people, each with
their devices and scopes). The charter changes only by vote; the root key notarizes the
result and cannot change the roll or the rules on its own (section 14).

Nodes exchange signed **events** (QUESTION, ANSWER, PROPOSAL, VOTE, RESULT, CHARTER,
MEMBERSHIP, REVOCATION) over a request/response protocol. Every node validates every
event itself, stores it in its own append-only log, and computes every outcome (which
proposals passed, which rules are in force, which charter is current) itself. Nothing is
trusted because a peer says so.

There is no server, no global ordering and no gossip in v0. Nodes connect to explicit
addresses (taken from invites or configured by the user).

## 2. Primitive encodings

All values that appear in protocol JSON are strings with a self-describing prefix,
except integers (`bundle_size`, `limit`, a charter's `seq` and the `num` and `den` of
its thresholds, plus `size` in a bundle manifest), booleans (`more`, a charter's
`binding`) and arrays/objects. Parsing is strict: the prefix is case-sensitive,
there is no surrounding whitespace, and each value has exactly one valid encoding.
Reference: `crates/ph-core/src/encoding.rs`, `timestamp.rs`, `scope.rs`, `role.rs`.

| kind | encoding | length |
|---|---|---|
| public key (device or root) | `ed25519:` + base64url without padding of the 32-byte compressed point | 8 + 43 chars |
| signature | `base64url:` + base64url without padding of the 64-byte Ed25519 signature | 10 + 86 chars |
| nonce | `base64url:` + base64url without padding of 16 random bytes | 10 + 22 chars |
| digest, event id, circle id | `sha256:` + 64 **lowercase** hex chars | 71 chars |
| timestamp | `YYYY-MM-DDTHH:MM:SSZ`, UTC | exactly 20 chars |

### 2.1 base64url

The base64url alphabet is RFC 4648 section 5 (`A-Z a-z 0-9 - _`), with no `=` padding.
The encoded length MUST be exactly `ceil(4n/3)` for `n` bytes, and the unused trailing
bits of the last character MUST be zero (re-encoding the decoded bytes must reproduce the
input). Anything else is rejected.

### 2.2 Public keys

A key string MUST decode to 32 bytes that are:

* a valid Ed25519 point encoding,
* the **canonical** encoding of that point (the `y` coordinate is reduced, `y < p`), so
  a point has exactly one key string, and
* not a small-order ("weak") point. The 8 small-order points are rejected.

Ed25519 private keys are 32-byte RFC 8032 seeds. The protocol never transmits them.

### 2.3 Digests

`sha256:` followed by exactly 64 characters from `0-9a-f`. Uppercase hex is rejected.
Event ids, circle ids, credential digests and bundle digests all use this format; they
are distinct types in the reference implementation, but the encoding is the same.

### 2.4 Timestamps

Exactly `YYYY-MM-DDTHH:MM:SSZ` (20 ASCII bytes): uppercase `T` and `Z`, whole seconds,
no fractional part, no numeric offset, no leap second (`:60`), a valid calendar date.
The representable range is `0000-01-01T00:00:00Z` to `9999-12-31T23:59:59Z`.
Comparisons are chronological. Timestamps from peers are informational only: they are
checked against bounds (section 7.3) but never used as the basis for authorization;
authorization uses the local clock.

### 2.5 Scopes

A scope is either exactly `*` or matches

```text
^[a-z0-9][a-z0-9._-]{0,63}(/[a-z0-9][a-z0-9._-]{0,63}){0,7}$
```

and is at most 128 bytes: 1 to 8 `/`-separated segments, each 1 to 64 characters.

A **granted** scope `g` **covers** an **object** scope `o` iff

* `g == "*"`, or
* `g == o`, or
* `o` starts with `g + "/"`.

There is no other wildcard. `team/back` does not cover `team/backend`. The object scope
`*` is covered only by the granted scope `*`.

### 2.6 Roles and capabilities

| role | capabilities |
|---|---|
| `member` | `read`, `ask`, `answer`, `propose`, `vote`, `publish` |
| `owner` | `read`, `ask`, `answer`, `propose`, `vote`, `publish`, `invite`, `revoke` |

Role and capability strings are lowercase. An unknown role string makes the containing
object invalid (it is rejected at parse time; it does not silently grant nothing). A set
of roles grants a capability if any role in it does; an empty set grants nothing.

In v0 only `read`, `ask` and `answer` have a protocol effect. `invite` and `revoke`
have none: only the circle root key issues credentials, invites and revocations
(section 12.6). `propose`, `vote` and `publish` have none either: who may author
PROPOSAL, VOTE and RESULT events is decided by the roll of the charter, not by a
credential (sections 9.6 and 12.4).

### 2.7 Skill names

A skill name is 1 to 64 characters of `[a-z0-9-]`, with no leading, trailing or
consecutive hyphens (Agent Skills naming).

### 2.8 Member handles

A member handle names a person on a charter's roll (section 9.6). It matches

```text
^[a-z0-9][a-z0-9._-]{0,31}$
```

so it is 1 to 32 ASCII characters. Handles are unique within one roll and have no
meaning outside it.

## 3. JSON subset and canonical form (JCS)

Reference: `crates/ph-protocol/src/jcs.rs`, ADR-002.

### 3.1 Accepted JSON

Every protocol message is UTF-8 JSON (RFC 8259) restricted as follows. A strict parser
MUST reject:

* invalid UTF-8, unescaped control characters in strings, lone surrogate escapes
  (`"\ud800"`), and any trailing data after the value (including a second value);
* trailing commas and every other syntax error;
* duplicate object member names, compared after unescaping (`{"a":1,"a":2}` is a
  duplicate), at any depth;
* any number with a fraction or an exponent, including `1.0`, `1e2` and `-0`;
* integers outside `[-(2^53-1), 2^53-1]`, that is beyond `±9007199254740991`;
* input larger than the applicable byte limit (Appendix A);
* nesting deeper than the applicable depth limit.

**Depth** counts containers only: a top-level object or array has depth 1, a container
inside it depth 2, and so on. Scalars add no depth. Signed objects (envelopes,
credentials, acceptances, revocations, invites, charters) have a maximum depth of 8; wire
frames
have a maximum depth of 10, because envelopes are nested two levels inside
`push_events` and `events`.

Insignificant whitespace and member order in received JSON are accepted; the canonical
form below is what is signed and hashed.

### 3.2 Canonical form

The canonical form is RFC 8785 (JCS) restricted to the subset above. Within this subset
the output is identical to RFC 8785:

* no insignificant whitespace;
* object members sorted by name, comparing names as sequences of **UTF-16 code units**
  (not UTF-8 bytes, not code points); a name that is a prefix of another sorts first;
* strings escaped exactly like ECMAScript `JSON.stringify`: `\"`, `\\`, `\b`, `\f`, `\n`,
  `\r`, `\t`; every other code point below U+0020 as `\u00xx` with **lowercase** hex;
  everything else literally as UTF-8, including `/`, DEL (U+007F), U+2028, U+2029 and all
  non-ASCII;
* `null`, `true`, `false` as literals;
* integers in plain decimal with no leading zeros and no `+` (and no `-0`).

Because floats cannot occur, there is no number formatting to get wrong. See
`crates/ph-protocol/tests/vectors/jcs.json` for 13 valid and 13 invalid cases.

### 3.3 Strict schemas

Every object in the protocol (envelopes, bodies, credentials, acceptances, revocations,
invites, membership proofs, charters and their rules, thresholds and roll entries,
bundle manifests and file entries, wire messages, push outcomes, wire files) has a fixed
member set:

* unknown members are rejected at **every** level, not only the top level;
* required members MUST be present;
* optional members MUST be omitted when absent; an explicit `null` is rejected;
* the reference implementation also requires that re-serializing the typed object
  yields exactly the received JSON value, so the typed view and the signed bytes can
  never disagree.

## 4. Signing

Reference: `crates/ph-protocol/src/signing.rs`.

### 4.1 Contexts

Every signed object kind has a `schema` value and a domain-separation context string.

| object | `schema` | context | signer | transmits `event_id` |
|---|---|---|---|---|
| event envelope | `peerharness.event/0.1` | `peerharness-event-v0` | `author` | yes |
| membership credential | `peerharness.membership/0.1` | `peerharness-membership-v0` | `issuer_key` (circle root) | no |
| acceptance | `peerharness.acceptance/0.1` | `peerharness-acceptance-v0` | `subject_device_key` | no |
| revocation | `peerharness.revocation/0.1` | `peerharness-revocation-v0` | `issuer_key` (circle root) | no |
| invite | `peerharness.invite/0.1` | `peerharness-invite-v0` | `circle_root_key` | no |
| charter | `peerharness.charter/0.1` | `peerharness-charter-v0` | `issuer_key` (circle root) | no |

### 4.2 Exact signing input

```text
unsigned      = the signed JSON object with its top-level "signature" member removed
                (and, for an envelope, its top-level "event_id" member removed)
signing_input = UTF8(context) || 0x00 || UTF8(JCS(unsigned))
signature     = Ed25519-Sign(private_key, signing_input)       RFC 8032, pure Ed25519
object_digest = "sha256:" + lowercase_hex(SHA-256(signing_input))
```

The context is ASCII with no terminator of its own; exactly one `0x00` byte separates it
from the canonical JSON. Nothing else is prepended or appended. Note that the
`signing_input` is hashed directly: the digest is `SHA-256(context || 0x00 || JCS)`,
not a hash of a hash.

Only the top-level `signature` and `event_id` members are removed. Signatures of nested
objects (for example the credential inside a MEMBERSHIP body, or the charter inside a
CHARTER body) stay in the unsigned form of the outer object and are covered by the outer
signature.

An unsigned object MUST NOT contain a top-level `signature` or `event_id` member.

### 4.3 Verification

To verify a received signed object:

1. Parse it strictly (section 3) and apply its strict schema.
2. Remove the top-level `signature` (and for envelopes `event_id`) member. For an
   envelope both MUST be present; for other objects `event_id` MUST NOT be present.
3. Recompute `signing_input` from the remaining members.
4. Verify the signature with the signer key named in the object using **strict** Ed25519
   verification (as `ed25519_dalek::VerifyingKey::verify_strict`): reject non-canonical
   `S` values, small-order public keys and small-order `R` components.
5. For envelopes, check that the transmitted `event_id` equals
   `"sha256:" + hex(SHA-256(signing_input))`.

The signature is never computed over the received bytes as such: the receiver always
recomputes the canonical form, so whitespace or member order differences in transit do
not matter.

## 5. Derived identifiers

| identifier | definition |
|---|---|
| `event_id` | `"sha256:" + hex(SHA-256("peerharness-event-v0" \|\| 0x00 \|\| JCS(unsigned envelope)))` |
| `circle_id` | `"sha256:" + hex(SHA-256("peerharness-circle-v0" \|\| 0x00 \|\| root_pubkey_32_bytes))` |
| credential digest | object digest of the credential: `"sha256:" + hex(SHA-256("peerharness-membership-v0" \|\| 0x00 \|\| JCS(unsigned credential)))` |
| charter digest | object digest of the charter: `"sha256:" + hex(SHA-256("peerharness-charter-v0" \|\| 0x00 \|\| JCS(unsigned charter)))` (section 9.6) |
| fingerprint of a key | first 20 hex chars of `SHA-256("peerharness-fingerprint-v0" \|\| 0x00 \|\| pubkey_32_bytes)`, grouped as `xxxx-xxxx-xxxx-xxxx-xxxx` |
| bundle digest | `"sha256:" + hex(SHA-256("peerharness-bundle-v0" \|\| 0x00 \|\| JCS(manifest)))` (section 10) |

The circle id and the fingerprint hash the **raw 32 key bytes**, not the `ed25519:`
string. Fingerprints are for humans to compare out of band (for example the root
fingerprint shown when joining). They are 80 bits and are not used for authorization.

Local-only derivation (never sent on the wire, documented so implementations can
interoperate on stored data if they want to): the question dedup key
`Digest.domain("peerharness-question-dedup-v0", ...)`, where
`Digest.domain(ctx, data) = SHA-256(ctx || 0x00 || data)`.

## 6. Free-text fields

Reference: `crates/ph-protocol/src/text.rs`.

Lengths of text fields are counted in Unicode scalar values (code points), not bytes.
Every text field rejects characters that can manipulate a terminal or hide text:

* C0 controls U+0000 to U+001F, except that **multi-line** fields allow `\t`, `\n`, `\r`;
* DEL U+007F and C1 controls U+0080 to U+009F;
* bidirectional formatting characters: U+202A to U+202E, U+2066 to U+2069, U+061C,
  U+200E, U+200F;
* invisible format characters that can hide or split text: U+200B to U+200D (zero-width
  space, non-joiner, joiner), U+2060 (word joiner), U+FEFF (zero-width no-break space /
  BOM), U+180E (Mongolian vowel separator) and the tag characters U+E0000 to U+E007F;
* in **single-line** fields also U+2028 and U+2029.

Because U+200D is forbidden, emoji ZWJ sequences (for example 👩 U+200D 💻) are
rejected; individual emoji, emoji variation selectors (U+FE0F) and right-to-left letters
are allowed. Each field below is marked single-line or multi-line.

## 7. Event envelope

Reference: `crates/ph-protocol/src/envelope.rs`.

### 7.1 Members

| member | type | rule |
|---|---|---|
| `schema` | string | exactly `peerharness.event/0.1` |
| `type` | string | one of `QUESTION`, `ANSWER`, `PROPOSAL`, `VOTE`, `RESULT`, `CHARTER`, `MEMBERSHIP`, `REVOCATION` |
| `circle_id` | circle id | the target circle |
| `scope` | scope | the object scope; see section 12 |
| `author` | public key | signs the envelope |
| `nonce` | nonce | 16 random bytes from a CSPRNG |
| `created_at` | timestamp | author's clock; informational |
| `expires_at` | timestamp | expiry; enforced only for expiring types (section 7.3) |
| `body` | object | depends on `type` (section 8) |
| `signature` | signature | transmitted only; by `author` |
| `event_id` | digest | transmitted only; section 5 |

All eleven members are required in a transmitted envelope; no other member is allowed.
The nonce makes two otherwise identical events distinct; it is not a replay counter.
Replay protection comes from `event_id` uniqueness (section 13.4).

Example (the QUESTION golden vector, `signed` form, members in canonical order):

```json
{
  "author": "ed25519:iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
  "body": {
    "question": "Should this repository use pnpm rather than npm?",
    "related_candidate": "sha256:7b09e531cf94528df2a42bdc19370f2186859afd6bc767dfcfbf076a7e1b487c",
    "topic": "package-manager"
  },
  "circle_id": "sha256:de392f334c6c4a6af8609650d76f7e635a1a507d734033e6dd9fcab222730ae9",
  "created_at": "2026-11-09T18:10:00Z",
  "event_id": "sha256:be79915498eebfc15547bfeedd7b3406478931c71173c0403d1a276b5c28ca17",
  "expires_at": "2026-12-09T18:10:00Z",
  "nonce": "base64url:EBAQEBAQEBAQEBAQEBAQEA",
  "schema": "peerharness.event/0.1",
  "scope": "team/backend",
  "signature": "base64url:jwP0YHfO_2fpVi21SRcqaNVg7QmXhclok9seA0TjTlmyUeX5QQKZ58ViY4d2ow1rtbj1_bpAUv1Y4zYb2QOgCg",
  "type": "QUESTION"
}
```

### 7.2 Size and shape

* The received bytes of one envelope MUST be at most 65,536 bytes (64 KiB).
* The canonical form of the **transmitted** envelope (including `signature` and
  `event_id`) MUST be at most 64 KiB, and its depth at most 8.
* A sender MUST NOT sign an envelope that would violate these limits or any rule of
  sections 7.3 and 8; the reference implementation refuses to.

### 7.3 Time rules

Events fall into two groups:

* **expiring**: `QUESTION`, `ANSWER`, `MEMBERSHIP`;
* **permanent**: `PROPOSAL`, `VOTE`, `RESULT`, `CHARTER`, `REVOCATION`. The outcome of a
  vote must not depend on a clock, and a revocation must never lapse.

At the receiver's local time `now` (`check_time_rules_for`):

1. `created_at <= now + 300 s` (clock skew allowance), else *future-dated*. This rule
   applies to every type **except `REVOCATION`**: a revocation only ever denies, so a
   receiver MUST NOT refuse one because the issuer's clock runs ahead;
2. `expires_at > created_at`, for every type;
3. `expires_at - created_at <= 400 days` (34,560,000 s), for every type;
4. `expires_at > now`, else *expired*, for the **expiring** types only. A receiver MUST
   NOT reject, stop counting or stop serving a permanent event because its `expires_at`
   has passed.

Every envelope carries `expires_at`, permanent or not; rules 2 and 3 are about the shape
of the envelope and always apply. The reference implementation sets `expires_at` of a
permanent event to `created_at + 400 days`.

For expiring events the rules are checked when the event is received and again whenever
it is used later. Nothing in the counting of votes (section 14) reads a clock.

### 7.4 Stateless validation, in order

A receiver MUST perform these checks, which need no local state, before anything else
(`validate_stateless` / `validate_stateless_value`):

1. Size: received bytes at most 64 KiB; strict parse with depth 8 (section 3.1).
2. Shape: canonical size of the value at most 64 KiB, depth at most 8, it is an object.
3. `schema` is exactly `peerharness.event/0.1` (else "unsupported schema").
4. `type` is a string in the allowlist (else "unknown event type").
5. Strict schema of the envelope members; `signature` and `event_id` present; strict
   schema and bounds of the typed body (section 8); exact re-serialization round trip.
6. Signature by `author` (strict verification) and `event_id` match (section 4.3).
7. Time rules for the event's type (section 7.3).
8. Bindings between envelope and body (MEMBERSHIP, REVOCATION, CHARTER and `amend`
   PROPOSAL, section 8).
9. MEMBERSHIP: the embedded proof verifies at `now` (section 9.3). REVOCATION: the
   embedded revocation's structure and signature verify, with no time rule (section
   9.5). CHARTER: the embedded charter's structure and signature verify (section 9.6).

Stateful checks follow in section 12.4.

## 8. Event types and bodies

Optional members are written `name?`. All body objects reject unknown members and
explicit `null`. Lengths are code points (section 6).

| type | plane | authorization (section 12) | lifetime |
|---|---|---|---|
| `QUESTION` | deliberation | credential capability `ask` on the envelope scope | expiring; default 30 days |
| `ANSWER` | deliberation | credential capability `answer` | expiring; default 30 days |
| `PROPOSAL` | decision | the author is on the roll of the charter the proposal names | permanent |
| `VOTE` | decision | the author is on that roll | permanent |
| `RESULT` | decision | the author is on that roll | permanent |
| `CHARTER` | control | author is the circle root key | permanent |
| `MEMBERSHIP` | control | embedded credential and acceptance | expiring; `expires_at` = credential `expires_at` |
| `REVOCATION` | control | author is the circle root key (ADR-010) | permanent |

The default lifetime is what the reference implementation uses when creating events;
permanent events get `created_at + 400 days`. Receivers enforce only the time rules of
section 7.3 plus the MEMBERSHIP binding below.

### 8.1 QUESTION

```json
{"question": "<text>", "topic": "<text>", "related_candidate?": "sha256:..."}
```

* `question`: 1 to 2000 code points, multi-line. The human-confirmed, redacted text.
* `topic`: 1 to 128 code points, single-line. The reference implementation uses a fixed
  topic vocabulary, but the protocol accepts any text within bounds.
* `related_candidate`: an opaque digest that lets the asker link the question to a local
  candidate. It reveals nothing to the receiver.

### 8.2 ANSWER

```json
{"question_id": "sha256:<event id>", "answer": "agree" | "disagree" | "unsure", "rationale?": "<text>"}
```

* `rationale`: 0 to 2000 code points, multi-line.
* Reference rule (checked once the QUESTION is stored, section 12.5): `question_id`
  names a QUESTION in the same circle with the **same scope**.

### 8.3 PROPOSAL

A proposal puts one of three things to the vote, selected by `kind`. The body is one
flat object: four members every kind has, plus the members of that kind only.

```json
{"kind": "adopt", "charter": "sha256:<charter digest>", "title": "<text>", "summary": "<text>",
 "skill_name": "<skill name>", "description": "<text>", "bundle_digest": "sha256:...", "bundle_size": 357,
 "related_question?": "sha256:<event id>", "supersedes?": "sha256:<event id>"}

{"kind": "repeal", "charter": "sha256:<charter digest>", "title": "<text>", "summary": "<text>",
 "target": "sha256:<event id>"}

{"kind": "amend", "charter": "sha256:<charter digest>", "title": "<text>", "summary": "<text>",
 "next": {"rules": {...}, "roll": [...], "carried": [...]}}
```

Members of every kind:

* `kind`: lowercase, one of the three values.
* `charter`: the digest (section 5) of the charter the proposal is voted under. It
  fixes who may vote and how many approvals are needed (section 14). A proposal can pass
  only while that charter is the circle's current one.
* `title`: 1 to 200 code points, single-line.
* `summary`: 0 to 1000 code points, multi-line. Human-confirmed.

`adopt` (put a rule in force). Required: `skill_name`, `description`, `bundle_digest`,
`bundle_size`. Optional: `related_question`, `supersedes`.

* `skill_name`: a valid skill name (section 2.7).
* `description`: 1 to 1024 code points, multi-line.
* `bundle_digest`: the bundle digest (section 10).
* `bundle_size`: integer, 1 to 262,144 (256 KiB), the total bundle size in bytes.
* `related_question`: optional QUESTION event id.
* `supersedes`: optional earlier `adopt` PROPOSAL event id. Lineage only: approvals never
  move to the superseding proposal. Reference rule: it names an `adopt` PROPOSAL in the
  same circle with the same `skill_name`.

`repeal` (take a rule out of force). Required: `target`, the event id of the `adopt`
PROPOSAL whose rule is to be repealed. Reference rule (checked once the target is
stored): the target is an `adopt` PROPOSAL in the same circle with the **same scope**.

`amend` (replace the charter). Required: `next`, the complete proposed charter content
(section 9.6): `rules`, `roll` and `carried`. It MUST satisfy the content structure
rules of section 9.6, and the envelope scope MUST be `*`.

A body that carries a member of another kind (for example a `repeal` with `skill_name`,
or an `adopt` with `target`), or lacks a required member of its own kind, is a schema
error.

### 8.4 VOTE

```json
{"proposal_id": "sha256:<event id>", "decision": "approve" | "reject" | "revise", "rationale?": "<text>"}
```

* `proposal_id` is the event id of the PROPOSAL, which is the hash of the entire signed
  proposal. A ballot is therefore bound to every byte of what was proposed, including
  the bundle digest of an `adopt` proposal; a ballot for proposal A never counts for a
  proposal B that differs in anything. There is no separate `bundle_digest` member.
* `rationale`: 0 to 2000 code points, multi-line.
* Only `approve` affects the count. `reject` and `revise` are the signed record of
  dissent and of requested changes (section 14.2).
* Reference rule: `proposal_id` names a stored PROPOSAL in the same circle with the same
  envelope scope.

### 8.5 RESULT

```json
{"proposal_id": "sha256:<event id>", "approvals": ["sha256:<vote event id>", ...]}
```

* `approvals`: 1 to 64 VOTE event ids, **sorted ascending by their string and unique**.
  An empty, unsorted or repeating list is rejected by stateless validation.
* A RESULT is a certificate that a proposal passed: the `approve` ballots that carry it
  over its threshold. It has **no authority**. A receiver verifies the listed ballots
  itself (section 14.3) and reaches the conclusion it would have reached from those
  ballots alone.
* The envelope scope MUST equal the proposal's.
* Reference rule: `proposal_id` names a stored PROPOSAL in the same circle with the same
  scope.

### 8.6 CHARTER

```json
{"charter": <Charter>}
```

Carries the circle's next charter (section 9.6). Bindings (all checked statelessly):

* `author` MUST equal `charter.issuer_key`, which is the circle root key;
* envelope `circle_id` MUST equal `charter.circle_id`;
* the envelope scope MUST be `*`;
* the charter's structure and signature MUST verify (section 9.6).

A valid CHARTER event proves only that the charter is authentic. It becomes a node's
current charter only if it is a legitimate successor of the one the node holds (section
14.5).

### 8.7 MEMBERSHIP

```json
{"credential": <MembershipCredential>, "acceptance": <Acceptance>}
```

Bindings (all checked statelessly):

* `author` MUST equal `credential.subject_device_key`;
* envelope `circle_id` MUST equal `credential.circle_id`;
* envelope `expires_at` MUST NOT be later than `credential.expires_at`;
* the credential and acceptance MUST verify at `now` (section 9.3).

The recommended envelope scope is `*`. The stateful rule (section 12.4) accepts `*` or a
scope covered by one of the credential's scopes.

### 8.8 REVOCATION

```json
{"revocation": <Revocation>}
```

Bindings:

* `author` MUST equal `revocation.issuer_key`, which is the circle root key;
* envelope `circle_id` MUST equal `revocation.circle_id`;
* the revocation's structure and signature MUST verify (section 9.5). No time rule
  applies to the revocation or to its envelope's `created_at` (section 7.3).

The envelope scope may be any valid scope; `*` is recommended. Because the author is the
root key, the root key signs this envelope, and the root key holds no credential.

## 9. Membership objects

Reference: `crates/ph-protocol/src/credentials.rs`, `crates/ph-protocol/src/charter.rs`,
`crates/ph-identity/src/`.

Credentials and the charter answer different questions. A **credential** is per device,
expires, and gives that device access: it may connect, read within its scopes, ask and
answer. The **charter** is per circle; its roll lists people with their devices and
decides who may propose, vote and publish a result (section 14).

The first four objects (credential, acceptance, invite, revocation) are standalone
signed documents. As standalone documents (for example an invite file) they are limited
to 16,384 bytes and depth 8. The fifth, the charter (section 9.6), is limited to 65,536
bytes.

### 9.1 Membership credential

```json
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
```

Structure rules:

* `roles`: 1 or 2 entries, no duplicates, each `owner` or `member`.
* `scopes`: 1 to 16 entries, no duplicates, each a valid scope.
* `circle_id` MUST equal `circle_id(issuer_key)` (section 5). In v0 the issuer is always
  the circle root.

Verification at `now` (`verify_credential`), in order:

1. structure rules above;
2. signature by `issuer_key` over the membership signing input;
3. `issued_at <= now + 300 s`;
4. `expires_at > issued_at`;
5. `expires_at - issued_at <= 400 days`;
6. `expires_at > now`.

Reference issuance: ordinary members get 30-day credentials with role `member`; the
founder's own credential has roles `["owner","member"]`, scopes `["*"]` and 365 days. The
root key never issues a credential to itself.

### 9.2 Acceptance

```json
{
  "schema": "peerharness.acceptance/0.1",
  "circle_id": "sha256:...",
  "credential_digest": "sha256:...",
  "subject_device_key": "ed25519:...",
  "accepted_at": "2026-11-09T18:05:00Z",
  "signature": "base64url:..."
}
```

Verification of an acceptance `a` for a credential `c` at `now` (`verify_acceptance`):

1. `a.subject_device_key == c.subject_device_key`;
2. `a.circle_id == c.circle_id`;
3. `a.credential_digest == credential digest of c` (section 5);
4. signature by `a.subject_device_key` over the acceptance signing input;
5. `a.accepted_at <= now + 300 s`.

The acceptance proves that the holder of the subject device key took the credential.
Possessing someone else's credential or invite is useless without their device key.

### 9.3 Membership proof

```json
{"credential": <MembershipCredential>, "acceptance": <Acceptance>}
```

Carried in MEMBERSHIP bodies and in `authenticate` / `authenticated` messages.
Verification: credential verification (9.1) at `now`, then acceptance verification
(9.2) at `now`.

A credential is **active** for a device key at `now` when a proof for it verifies at
`now`, the circle is known locally with that root, and the key is not revoked in that
circle (section 9.5).

### 9.4 Invite

```json
{
  "schema": "peerharness.invite/0.1",
  "circle_name": "acme backend",
  "circle_root_key": "ed25519:...",
  "credential": <MembershipCredential>,
  "issuer_device_key": "ed25519:...",
  "issuer_addrs": ["/ip4/127.0.0.1/udp/4001/quic-v1"],
  "invite_expires_at": "2026-11-10T18:00:00Z",
  "nonce": "base64url:...",
  "signature": "base64url:..."
}
```

* `circle_name`: 1 to 64 code points, single-line. A local label shown to the invitee;
  it is not authenticated beyond the root signature and is never sent on the wire later.
* `credential`: the invitee's credential, issued by `circle_root_key`.
* `issuer_device_key`: the inviting node, which the invitee dials.
* `issuer_addrs`: 0 to 8 multiaddr strings, each 1 to 256 bytes of printable,
  non-space ASCII. The reference implementation writes `/ip4/.../udp/.../quic-v1/p2p/<PeerId>`.
* Signed by `circle_root_key`.

Generic verification (`verify_invite`): structure (name, addresses,
`credential.issuer_key == circle_root_key`); invite signature by `circle_root_key`;
credential verification (9.1) at `now`; `invite_expires_at > now`.

Joining (`ph_identity::validate_invite`) checks, in order, and reports the first
failure: credential issuer is the root and the credential signature verifies
("credential not from root"); structure ("malformed"); invite signature ("bad
signature"); `credential.subject_device_key` equals the joining device key ("not for
this device"); `invite_expires_at > now` ("expired"); credential time rules
("credential invalid"). The joiner then shows the root fingerprint, gets human
confirmation, signs an acceptance, and publishes a MEMBERSHIP event to the issuer.

Reference issuance: invites last 24 hours by default (at most 7 days), and an invite
never outlives its credential.

### 9.5 Revocation

```json
{
  "schema": "peerharness.revocation/0.1",
  "circle_id": "sha256:...",
  "subject_device_key": "ed25519:...",
  "revoked_at": "2026-11-10T09:00:00Z",
  "reason": "device lost",
  "issuer_key": "ed25519:...",
  "nonce": "base64url:...",
  "signature": "base64url:..."
}
```

* `reason`: 0 to 200 code points, single-line.
* `circle_id` MUST equal `circle_id(issuer_key)`.
* `subject_device_key` MUST NOT equal `issuer_key`: the root cannot revoke itself. Such
  an object is structurally malformed and is rejected by stateless validation.

Verification (`verify_revocation_signature`): structure (`reason` bounds, the
circle/issuer binding, subject is not the issuer); signature by `issuer_key`. **No time
rule applies.** `revoked_at` is informational, and a receiver MUST NOT refuse a
revocation because `revoked_at` is ahead of its clock: a revocation only ever denies,
and refusing it would leave the revoked device trusted (ADR-017).

Semantics:

* A revocation object does not expire.
* It revokes the subject device key in that circle **permanently**, for every
  credential that key holds or will hold there, from the moment a node learns of it.
  `revoked_at` is informational; it does not limit the effect to later credentials.
* A node keeps the first valid revocation it receives per (circle, subject).
* The root key cannot revoke itself (see above). Revoking the founder's device key, a
  different key, is allowed. A compromised root key means creating a new circle.
* A revoked device must re-enroll with a new device key to rejoin.
* For voting (section 14), a revoked device's ballots are not counted in any count made
  after the node learns of the revocation, and new decision events from it are
  rejected. The member it voted for stays on the roll, and the electorate keeps its
  size, until an amendment changes the roll: a revocation can block but never pass
  anything.

### 9.6 Charter

Reference: `crates/ph-protocol/src/charter.rs`.

A circle has one charter in force at a time. It is the rules of the vote, the roll of
members, and the rules carried over from the previous charter, in one object signed by
the circle root key. Section 14 specifies how it is used.

```json
{
  "schema": "peerharness.charter/0.1",
  "circle_id": "sha256:...",
  "seq": 2,
  "previous": "sha256:<digest of charter seq-1>",
  "rules": {
    "pass":  {"num": 1, "den": 2},
    "amend": {"num": 2, "den": 3},
    "binding": true
  },
  "roll": [
    {"member": "alice", "devices": ["ed25519:..."], "scopes": ["*"]},
    {"member": "bob",   "devices": ["ed25519:..."], "scopes": ["team/backend"]}
  ],
  "carried": ["sha256:<adopt proposal event id>"],
  "justification": "sha256:<RESULT event id>",
  "issued_at": "2026-11-09T18:04:00Z",
  "issuer_key": "ed25519:...",
  "signature": "base64url:..."
}
```

`rules`, `roll` and `carried` together are the charter's **content**. An `amend`
PROPOSAL carries exactly such a content object as its `next` (section 8.3).

Members:

* `seq`: integer, 1 or greater. The founding charter has `seq` 1.
* `previous`: the charter digest of the charter with `seq - 1`. Present iff `seq > 1`.
* `justification`: the event id of a RESULT that passed the `amend` proposal this
  charter enacts. Present iff `seq > 1`.
* `rules.pass`: the threshold for `adopt` and `repeal` proposals, and for `amend`
  proposals that leave `rules` unchanged.
* `rules.amend`: the threshold for `amend` proposals that change `rules`.
* `rules.binding`: whether a passed rule is installed for every member by default. It
  does not affect counting (section 14.6).
* `roll`: the members. `member` is the person's handle; `devices` are the keys that may
  sign for that person; `scopes` are the scopes the person votes in.
* `carried`: the event ids of the `adopt` proposals in force when this charter begins.
* `issued_at`: informational. No time rule applies to a charter.
* `issuer_key`: the circle root key.

Structure rules (a charter, or a proposed content, that breaks one is malformed):

* `circle_id` MUST equal `circle_id(issuer_key)` (section 5).
* `seq` is in `1 ..= 2^53 - 1`; `previous` and `justification` are both absent when
  `seq == 1` and both present otherwise.
* Each threshold satisfies `1 <= num < den <= 100` and `2 * num >= den`, so nothing can
  pass without a strict majority. `amend` is at least `pass`:
  `amend.num * pass.den >= pass.num * amend.den`.
* `roll` has 1 to 64 entries, sorted ascending by `member` (byte order) with no
  duplicates.
* `member` matches `^[a-z0-9][a-z0-9._-]{0,31}$`.
* `devices` has 1 to 4 keys, sorted ascending by their `ed25519:` string, no duplicates.
  A device key MUST NOT appear under two members.
* `scopes` has 1 to 16 scopes (section 2.5), sorted ascending by their string, no
  duplicates.
* `carried` has at most 256 event ids, sorted ascending by their string, no duplicates.

The sort orders are part of the format: there is exactly one valid encoding of a given
roll, so a charter has exactly one digest.

A standalone charter document is limited to 65,536 bytes and depth 8. Inside a CHARTER
event or an `amend` PROPOSAL the 64 KiB envelope limit applies to the whole event.

The **charter digest** is the object digest of the unsigned charter (sections 4.2 and
5). It is what a PROPOSAL carries in `charter` and what the next charter carries in
`previous`.

Verification (`verify_charter_signature`): the structure rules, then the signature by
`issuer_key` over the charter signing input. Whether a charter is a legitimate successor
of another is a stateful question (section 14.5).

**Thresholds.** A threshold `t` requires approvals from more than `t.num / t.den` of an
electorate. For an electorate of `n` members:

```text
need(n, t) = floor(n * t.num / t.den) + 1
```

| n | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 10 |
|---|---|---|---|---|---|---|---|---|
| need with 1/2 | 1 | 2 | 2 | 3 | 3 | 4 | 4 | 6 |
| need with 2/3 | 1 | 2 | 3 | 3 | 4 | 5 | 5 | 7 |

For every valid threshold and `n >= 1`, `n / 2 < need(n, t) <= n`. For `n = 0`,
`need` is 1, which an empty electorate can never reach.

**Electorate.** The electorate of a proposal is a subset of the roll of the charter the
proposal names:

* an `amend` proposal: every member on the roll;
* an `adopt` or `repeal` proposal whose envelope scope is `*`: every member on the roll;
* an `adopt` or `repeal` proposal with any other scope `s`: the members with at least
  one scope that covers `s` (section 2.5).

A device **votes for** the member whose roll entry lists it. `charters.json` in the
golden vectors lists the electorates and approval counts each vector charter implies.

Reference issuance: the founding charter has the default rules shown above (pass 1/2,
amend 2/3, binding), the founder as the only member, and nothing carried.

## 10. Skill bundles

Reference: `crates/ph-protocol/src/bundle.rs`, `crates/ph-skills/src/bundle.rs`.

### 10.1 Manifest and digest

```json
{"schema": "peerharness.bundle/0.1", "files": [{"path": "SKILL.md", "sha256": "sha256:<hex>", "size": 357}]}
```

* `files[].sha256` is the **plain** SHA-256 of the file bytes (no domain separation).
* `files[].size` is the byte length.
* Files are sorted by path, byte order.
* `bundle_digest = "sha256:" + hex(SHA-256("peerharness-bundle-v0" || 0x00 || JCS(manifest)))`.

The manifest is never transmitted: both sides rebuild it from the files, so the digest
covers paths, sizes and contents.

### 10.2 v0 bundle content policy

A v0 bundle is **exactly one file**, `SKILL.md`. A receiver MUST reject a received bundle
that has no files, more than one file, any path other than exactly `SKILL.md` (case
sensitive, so `skill.md` is rejected), duplicate paths, a total size over 262,144 bytes,
a digest mismatch, a NUL byte or invalid UTF-8. The reference receiver then parses the
YAML frontmatter with a strict subset parser (only `name`, `description`, `license`,
`compatibility`, `metadata` and `allowed-tools`; any other key is an error; no anchors,
aliases, tags or flow collections), requires `name` to equal the PROPOSAL `skill_name`,
and requires `description` to be 1 to 1024 characters.

A bundle is **instructions only**. A single `SKILL.md` can still make a coding agent
run things, so every bundle, whether built locally or received, is also refused if
(`check_instruction_only`):

* its frontmatter declares `allowed-tools`, which pre-approves tools for the agent; or
* a line of its body contains syntax that Claude Code executes as a shell command when
  the skill loads, before the model sees anything (`has_shell_injection`):
  * an exclamation mark directly followed by a backtick, with another backtick later on
    the same line; or
  * a line that, after leading whitespace, starts with three backticks or three tildes
    directly followed by an exclamation mark.

These are exact syntactic rules, applied to every line of the body, and they err towards
refusing (a line containing two separate code spans, the first of which ends in an
exclamation mark, is refused). No vote, flag or confirmation overrides them (section
14.6). Received skill text is otherwise untrusted prose: a risk scanner gives advisory
findings, and what happens to a rule that passed is a local decision (section 14.6).

## 11. Wire protocol

Reference: `crates/ph-protocol/src/wire.rs`, `crates/ph-network/src/`.

### 11.1 Transport and identity

* libp2p over **QUIC v1** only (`/ip4/<addr>/udp/<port>/quic-v1`, or `/ip6/...`), with
  the libp2p TLS 1.3 handshake. No TCP, no relays, no mDNS, DHT or gossip in v0.
* The libp2p identity key is the node's Ed25519 device key (the same 32-byte seed). The
  `PeerId` is the identity-multihash of the Ed25519 public key, so the authenticated
  `PeerId` yields the device key directly. Nodes refuse connections whose `PeerId` is not
  an Ed25519 identity multihash of a valid (canonical, not small-order) key.
* Peers are dialed explicitly. Dialing a multiaddr with a trailing `/p2p/<PeerId>` makes
  the handshake prove that identity.

### 11.2 Streams and framing

* Protocol id: `/peerharness/req/0.1.0` (negotiated per stream with multistream-select,
  as libp2p request-response does).
* One request and one response per stream: the requester opens a stream, writes one
  request frame, and reads one response frame.
* **Frame** = 4-byte unsigned big-endian body length, followed by that many bytes of
  UTF-8 JSON. The body is at most 524,288 bytes (512 KiB) in both directions.
* Senders SHOULD encode bodies in canonical form (JCS); the reference implementation
  always does. Receivers accept any JSON that passes the strict parse with the frame
  limits (512 KiB, depth 10).
* An inbound request whose length prefix exceeds 512 KiB is answered with
  `{"type":"error","code":"too_large"}` without reading the body. A request body that is
  not a valid request (bad JSON, duplicate keys, unknown members, bounds exceeded) is
  answered `bad_request` (or `too_large` for a size violation) without reaching the
  application. A response that is oversized or invalid fails the requester's read
  (the stream is dropped).
* Default timeouts in the reference implementation: 20 s per request (including the
  responder's handler), 20 s to dial (the QUIC handshake itself times out after 5 s),
  and an idle connection with no request in flight is closed after 120 s.

### 11.3 Message encoding

Every frame body is one JSON object tagged by a `"type"` member whose value is the
snake_case message name. The message fields are siblings of `"type"`. Unknown members
are rejected.

| request `type` | response `type` on success |
|---|---|
| `hello` | `hello` |
| `authenticate` | `authenticated` |
| `push_events` | `push_result` |
| `fetch_events` | `events` |
| `fetch_bundle` | `bundle` |
| any | `error` |

### 11.4 `hello`

Request:

```json
{"type": "hello", "versions": ["0.1"]}
```

Response:

```json
{"type": "hello", "versions": ["0.1"], "capabilities": ["events", "bundles"]}
```

* `versions` and `capabilities`: at most 8 entries, each 1 to 32 bytes of printable,
  non-space ASCII.
* `hello` is the only request answered for every peer, and its answer is the same for
  every peer: it reveals no circle, member, skill or count.
* v0 nodes send `["0.1"]`. A client MUST NOT send further requests unless the response
  lists `"0.1"`.

### 11.5 `authenticate`

Request:

```json
{
  "type": "authenticate",
  "memberships": [ {"credential": <MembershipCredential>, "acceptance": <Acceptance>} ],
  "listen_addrs": ["/ip4/192.0.2.10/udp/4001/quic-v1"]
}
```

Response:

```json
{"type": "authenticated", "memberships": [ {"credential": ..., "acceptance": ...} ]}
```

* `memberships`: at most 16 membership proofs in each direction.
* `listen_addrs`: at most 8 multiaddr strings, each 1 to 256 bytes of printable,
  non-space ASCII.
* The responder records a presented proof only if the proof's `subject_device_key`
  equals the device key bound to the requesting connection's `PeerId` (proofs for other
  keys are ignored), the circle is known locally and the credential was issued by that
  circle's root, and the proof verifies at the responder's `now` (expired proofs are
  refused). A recorded proof of a revoked key never makes it an active member.
* The response contains the responder's own proofs only for circles in which the
  requester is now an active member (it may be an empty list). The requester verifies
  them the same way, against the responder's transport device key.
* Credential presentation rule: a node presents a proof for a circle only to a peer it
  believes is in that circle (the peer's key is the subject of a credential it knows in
  that circle, or the peer is the invite issuer), at most one proof (the latest-expiring
  active one) per circle. It never presents credentials to unknown peers.

`authenticate` establishes nothing that later requests rely on: authorization is
re-evaluated on every request (section 12.2). It is the way two nodes learn each other's
memberships.

### 11.6 `push_events`

Request:

```json
{"type": "push_events", "events": [ <signed envelope>, ... ]}
```

Response:

```json
{"type": "push_result", "results": [ {"event_id": "sha256:...", "status": "accepted"}, ... ]}
```

* `events`: at most 64 entries; each MUST be a JSON object. Each is validated on its own
  (section 7.4 and 12.4), so one bad event does not invalidate the frame.
* `results`: one entry per pushed event, in request order (at most 64). `status` is
  `accepted` (validated and stored), `duplicate` (already stored) or `rejected` (failed
  validation or authorization; no reason is given). `event_id` is omitted when the
  pushed value had no parseable `event_id`.
* The pusher must be an active member of the event's circle. Relaying a valid event
  authored by another member is allowed; the author's authorization is checked, not the
  pusher's capabilities.
* `rejected` does not say whether the rejection is permanent or retryable (section
  12.4). A ballot or result pushed before its proposal, or a proposal pushed before the
  charter it names, is `rejected` and would be accepted later. A sender SHOULD push an
  event's dependencies first (charter, then proposal, then ballots, then result) and MAY
  offer a rejected decision event again after the next sync.

### 11.7 `fetch_events`

Request:

```json
{"type": "fetch_events", "circle_id": "sha256:...", "known": ["sha256:<event id>", ...], "limit": 256}
```

Response:

```json
{"type": "events", "events": [ <signed envelope>, ... ], "more": false}
```

* `known`: at most 4096 event ids the requester already holds for that circle.
* `limit`: integer 1 to 256.
* `events`: at most 256 envelopes and the frame stays under 512 KiB; `more` is `true`
  when further eligible events remain. Section 13 describes the selection.

### 11.8 `fetch_bundle`

Request:

```json
{"type": "fetch_bundle", "circle_id": "sha256:...", "digest": "sha256:<bundle digest>"}
```

Response:

```json
{"type": "bundle", "digest": "sha256:...", "files": [ {"path": "SKILL.md", "content_b64": "<base64>"} ]}
```

* `files`: at most 16 entries on the wire (v0 bundles have exactly one, section 10.2);
  `path` is 1 to 256 bytes; the total decoded size is at most 262,144 bytes.
* `content_b64` is **standard** base64 (RFC 4648 section 4, alphabet `+` and `/`)
  **with** `=` padding, canonical. This differs from the unpadded base64url used for
  keys, signatures and nonces.
* The receiver recomputes the digest from the files (section 10.1) and rejects the
  bundle unless it equals the digest of the PROPOSAL it fetched for.

### 11.9 `error`

```json
{"type": "error", "code": "unauthorized"}
```

| code | meaning |
|---|---|
| `unauthorized` | not authenticated or not authorized. Identical for an unknown circle, a non-member, a revoked or expired member and an out-of-scope request |
| `rate_limited` | over a per-peer limit; retry later |
| `bad_request` | malformed request or a bound exceeded |
| `too_large` | frame or object too large |
| `unavailable` | temporarily unavailable (for example the responder's inbound buffer budget is exhausted, the handler failed, or a bundle is not stored); retry later |

### 11.10 Rate and resource limits (reference defaults)

Enforced before the request reaches the application handler:

* per peer: a token bucket of 20 requests/s with a burst of 40, an inbound byte budget of
  512 KiB/s (bucket capacity `max(bytes_per_sec, 512 KiB + 4)`), and at most 8 concurrent
  inbound requests. Over any limit: `rate_limited`.
* per connection: at most 32 concurrent streams (inbound plus outbound).
* at most 4 connections per peer, 256 established connections in total, and 64 inbound
  connections still handshaking.
* a shared 32 MiB budget for inbound request bodies being buffered across all peers;
  a request that does not fit is not read and gets `unavailable`.

These are local defaults, not protocol constants. A client SHOULD stay well below them
and back off on `rate_limited` and `unavailable`.

## 12. Authorization

Reference: `crates/ph-governance/src/authz.rs`, `read.rs`, `crates/ph-identity/src/registry.rs`.

### 12.1 What an unauthenticated peer can learn

Anyone who can reach a node's QUIC port can complete the libp2p handshake and send
`hello`. Before a peer has proven membership of a circle, the node:

* answers `hello` with the same generic response it gives everyone;
* answers `authenticate` with an empty `memberships` list (it presents nothing to a
  peer that has not proven membership, and never presents credentials to unknown peers);
* answers every other request with `{"type":"error","code":"unauthorized"}`, byte for
  byte identical whether the circle exists or not.

No circle names, member lists, skill titles, event counts or circle existence leak.
What does leak is that a PeerHarness node listens at that address, its `PeerId` (device
key), and the generic protocol version and capabilities.

### 12.2 Per-request re-check

Authorization is evaluated on **every** request against the latest local state (the
local clock, credential expiry, the latest known revocations). Nothing is cached from
`authenticate`. A peer whose credential expired or was revoked since its last request
gets `unauthorized` on its next one, and nodes stop pushing to it as soon as they learn
of the revocation.

### 12.3 The membership oracle

`authorize(circle, key, scope, capability, now)` succeeds iff, at local `now`:

1. the circle is known locally (else *not member*);
2. `key` is not revoked in the circle (else *revoked*);
3. `key` has at least one credential in the circle (else *not member*);
4. at least one of them is active (section 9.3; else *expired*);
5. a **single** active credential both has a scope covering `scope` (section 2.5) and
   has a role granting `capability` (section 2.6). Otherwise the denial is *scope denied*
   if no active credential covers the scope, else *capability denied*.

`is_active_member(circle, key, now)` is steps 1 to 4. The denial reason is for local logs
only; peers only ever see `unauthorized` or `rejected`.

### 12.4 Incoming events (stateful part)

After stateless validation (section 7.4), a receiver checks, in order
(`ph_governance::authorize_incoming`):

1. the time rules for the event's type at `now` again (section 7.3);
2. the circle is known locally (else `unknown_circle`);
3. body sanity: bounds and bindings again, and no self-references: an event MUST NOT
   name its own id as `question_id`, `proposal_id`, an entry of `approvals`,
   `supersedes`, `related_question`, a repeal `target`, or an entry of an amendment's
   `carried` (else `bad_reference`);
4. by event type:
   * **QUESTION, ANSWER** (credential): `authorize(circle_id, author, scope,
     capability, now)` with the type's capability (section 12.3);
   * **PROPOSAL, VOTE, RESULT** (roll): let `P` be the proposal that fixes the charter
     and the electorate: the event itself for a PROPOSAL, otherwise the **stored**
     PROPOSAL named by `proposal_id`.
     1. For a VOTE or RESULT: if no PROPOSAL with that id is stored, reject as
        `missing_proposal` (retryable). If it is stored, it MUST be in the same circle
        and have the same envelope scope as the event (else `bad_reference`).
     2. The charter with digest `P.charter` MUST be one this node has accepted for the
        circle (section 14.5). If it is not, reject as `unknown_charter` (retryable).
     3. `author` MUST be a device on that charter's roll (else `not_on_roll`), and the
        member it votes for MUST be in `P`'s electorate (section 9.6; else
        `not_in_electorate`).
     4. `author` MUST NOT have a locally known revocation in the circle (else
        `revoked`).

     The membership oracle is **not** consulted and no credential is required: the
     answer depends only on signed, permanent records, so it does not change with time
     and a node that joins later can replay the circle's decisions. A *retryable*
     rejection means nothing is wrong with the event; the receiver lacks a record it
     depends on and MAY accept the same event after its next sync;
   * **MEMBERSHIP** (embedded credential): `author == credential.subject_device_key`;
     `credential.circle_id == circle_id`; `circle_id == circle_id(credential.issuer_key)`
     (the issuer is the root); the proof verifies at `now`; the envelope scope is `*` or
     covered by one of the credential's scopes; the subject is not revoked locally (a
     revocation counts even if this node never saw the subject's credential, so a
     revoked key cannot re-publish its MEMBERSHIP). The oracle need not know the subject
     yet; this is how a new member's proof spreads;
   * **REVOCATION** (circle root, ADR-010): `circle_id == circle_id(author)` (the author
     is the circle root); `revocation.issuer_key == author`; `revocation.circle_id ==
     circle_id`; the subject is not the root key; the revocation's structure and
     signature verify. No time rule applies. The membership oracle is **not** consulted,
     because the root key holds no credential, and the envelope scope is not checked;
   * **CHARTER** (circle root): `circle_id == circle_id(author)`; `charter.issuer_key ==
     author`; `charter.circle_id == circle_id`; the charter's structure and signature
     verify. This establishes authenticity only.
5. referential checks against stored events (section 12.5);
6. insert into the local event log; an `event_id` that is already stored is a
   `duplicate` and has no further effect (idempotency and replay rejection).

Then side effects: a MEMBERSHIP adds the proof to the local membership view; a REVOCATION
is recorded, the revoked peer is disconnected and its pending outbound deliveries are
dropped; a QUESTION goes through the local anti-spam guard (section 14.8); a VOTE or
RESULT may make its proposal pass (sections 14.2 and 14.3); a CHARTER becomes the
current charter if it is a legitimate successor (section 14.5).

Pushing a stored event again is harmless: it is a `duplicate`.

### 12.5 References between events

An ANSWER, a VOTE, a RESULT, an `adopt` PROPOSAL with `supersedes` and a `repeal`
PROPOSAL reference another event. If the referenced event is not stored yet, the
reference is *missing*: a VOTE or RESULT is rejected as retryable (section 12.4), other
events may be kept and re-checked after the next sync, and none has any effect until
then. If the referenced event is stored but inconsistent (wrong type, kind, circle,
scope or skill name, as listed in section 8), the event is rejected.

A RESULT also references the ballots it lists and a CHARTER references the RESULT that
justifies it. Those are resolved when the result or charter is verified (sections 14.3
and 14.5), where a ballot that is not held yet is again a retryable condition.

### 12.6 Who may issue what (v0)

* Credentials, invites and revocations: only the circle root key (`circle_id ==
  circle_id(issuer)`). The `invite` and `revoke` capabilities of `owner` are not used
  for this in v0; there is no delegated issuance.
* Charters: signed only by the circle root key, and accepted by other nodes only when a
  passed amendment justifies them (section 14.5). The root key notarizes; it does not
  decide.
* REVOCATION and CHARTER events: authored by the root key (ADR-010).
* MEMBERSHIP events: authored by the credential subject.
* QUESTION and ANSWER events: authored by an active member holding the type's capability
  on the event scope.
* PROPOSAL, VOTE and RESULT events: authored by a device on the roll of the charter the
  proposal names, for a member in the proposal's electorate. The `propose`, `vote` and
  `publish` capabilities are not used. The circle root key is not on the roll and cannot
  vote.

### 12.7 Read rules

* A QUESTION or ANSWER, and a decision event (PROPOSAL, VOTE, RESULT) whose envelope
  scope is not `*`, is readable by a peer iff `authorize(circle, peer, event.scope,
  read, now)` succeeds.
* A control-plane event (MEMBERSHIP, REVOCATION, CHARTER) is readable by every active
  member of its circle regardless of scope, so revocations and the charter reach
  everyone who must enforce them.
* A decision event whose envelope scope is `*` is readable by every active member of its
  circle. A `*` proposal concerns the whole circle and its electorate is the whole roll
  (every `amend` proposal is one), and members cannot vote on what they cannot read.
  This exception does not apply to QUESTION and ANSWER.
* A bundle is served for `fetch_bundle {circle_id, digest}` only if a stored `adopt`
  PROPOSAL in that circle has that `bundle_digest` and is readable by the requester now
  under the rules above.
* Pushes and the outbox use the same rules, re-checked at send time.
* No vote, result or charter can widen read access: nothing in the read rules looks at
  a ballot.

## 13. Sync

Reference: `crates/ph-store/src/events.rs`, app contract.

### 13.1 Model

Each node keeps an append-only log of validated events per circle. There is no global
order and no canonical head: sync is set reconciliation by event id. Events are
immutable and content-addressed, so the same event received from several peers is
stored once.

### 13.2 Session

When two nodes connect, in either direction, each side runs: `hello`; `authenticate`
(presenting proofs per section 11.5) and verifying the returned proofs; then pushes its
pending outbound events that the peer may read; then, for each circle both share,
`fetch_events` with `known` set to its own event ids for that circle that have not
expired (permanent events never do), repeated while `more` is `true`; then
`fetch_bundle` for the bundle digests of `adopt` PROPOSALs it lacks. Nodes resync
connected peers periodically (about every 30 s in the reference implementation) and
redial known peers.

### 13.3 `fetch_events` selection

The responder MUST first check that the requester is an active member of the circle
(else `unauthorized`). It then returns events of that circle that:

* have not expired at the responder's `now`. Permanent events (section 7.3) never
  expire and are always eligible, however old they are;
* are not in `known`;
* the requester may read (section 12.7): control-plane events and decision events with
  scope `*` always, everything else only when the requester may read its scope,

ordered by `(created_at, event_id)` ascending, at most `limit` (and 256), within a byte
budget that keeps the frame under 512 KiB (at least one event is returned if any is
eligible). `more` is `true` iff further eligible events remain.

Notes for implementers:

* An expired QUESTION, ANSWER or MEMBERSHIP event is never served, so it cannot be
  obtained by sync. PROPOSAL, VOTE, RESULT, CHARTER and REVOCATION events always can, so
  a node that joins later can fetch the circle's decisions and every revocation.
* Events arrive in `(created_at, event_id)` order, which normally delivers a proposal
  before its ballots and a charter after the result that justifies it. A receiver MUST
  NOT rely on that: a decision event whose proposal or charter is missing is rejected as
  retryable (section 12.4) and should be offered again after the next round.
* `known` is capped at 4096 ids and there is no cursor. A circle with more than 4096
  unexpired events cannot be fully described in one `known` list; the responder may
  then keep returning events the requester already holds with `more = true`. Bound the
  number of rounds per sync. Because decision events are permanent and v0 does not prune
  them, a long-lived circle reaches this limit eventually.
* Every received event goes through the full validation of sections 7.4 and 12.4.

### 13.4 Idempotency and replay

`event_id` uniqueness in the local store makes reconnects and repeated syncs idempotent:
no duplicate questions or proposals, and a ballot received twice is one ballot (the
count in section 14.2 also ignores a repeated event id). A replayed event is a duplicate; a
modified one has a different `event_id` and a broken signature or a new author's
signature (and is then judged on its own).

### 13.5 Offline behaviour

Events created while a peer is unreachable are written to the local log and an outbox
first and delivered on the next connection. Revocation reaches a node only when it syncs
with a node that has it; until then that node may keep serving the revoked key (see
`docs/security-model.md`).

## 14. Governance: voting under a charter

Reference: `crates/ph-governance/src/tally.rs`, `result.rs`, `ruleset.rs`,
`succession.rs`, `adoption.rs`; `crates/ph-protocol/src/charter.rs`.

A circle governs itself by majority vote. Every node computes every outcome **locally**,
from signed records it has verified. No peer's conclusion is trusted, and no step below
reads a clock: two nodes holding the same records reach the same outcome, and an outcome
never changes later.

### 14.1 The inputs

* The **charter** a proposal names (section 9.6) fixes the electorate and the threshold.
* The **ballots** a node holds for the proposal (VOTE events, section 8.4).
* The node's local **revocation** state: the device keys it knows to be revoked.

The threshold for a proposal is `rules.amend` if it is an `amend` proposal whose
`next.rules` differ from the charter's `rules`, and `rules.pass` otherwise (including an
`amend` that only changes the roll).

### 14.2 Counting

To count the ballots for a PROPOSAL `p` under charter `c` (`tally`), first require that
`c` is the charter `p` names: `charter_digest(c) == p.charter` and same circle. Let `E`
be `p`'s electorate under `c` (section 9.6), `n = |E|`, and `need = need(n, threshold)`.

A ballot is **counted** iff all of these hold (otherwise it is ignored):

1. it is not a repeat of an event id already seen in this count;
2. `vote.circle_id == p.circle_id`;
3. `vote.proposal_id == p.event_id`;
4. the ballot's envelope scope equals `p`'s (equal, not merely covered);
5. `vote.author` is a device on `c`'s roll;
6. the member that device votes for is in `E`;
7. `vote.author` has no locally known revocation.

Counted ballots are grouped **by member**, not by device: two devices of one member are
one voter.

* A member **has approved** iff at least one of their counted ballots is `approve`. An
  approval cannot be withdrawn: a `reject` or `revise` cast later by the same member
  does not undo it. When a member has several `approve` ballots, the one with the
  smallest event id (as a string) is the one that evidences the approval, so every node
  names the same one.
* A member who has not approved but has cast `reject` or `revise` ballots is a
  **dissenter**; their recorded position is their latest such ballot by
  `(created_at, event_id)`. Dissent is displayed with its rationale. It does not affect
  the count. Nobody holds a veto.
* Members of `E` with no counted ballot are **silent**. Silence counts the same as not
  approving.

The proposal **reaches its threshold** iff the number of members who have approved is at
least `need`. Because approvals only accumulate, this never reverts, and it does not
depend on the order in which ballots arrive. Envelope `created_at` and `expires_at` of
ballots and proposals play no part.

### 14.3 Verifying a RESULT

A RESULT (section 8.5) lists ballots. To verify one for proposal `p` under the charter
`c` that `p` names (`verify_result`):

1. `result.proposal_id == p.event_id`, same circle, same envelope scope.
2. Every listed ballot is held locally. If one is not, stop: this is **retryable**
   (fetch the ballot and verify again), not a verdict on the certificate.
3. Count **exactly the listed ballots** as in 14.2.
4. `result.author` is a device on `c`'s roll whose member is in `p`'s electorate.
5. Every listed ballot is the ballot that evidences a distinct member's approval. The
   certificate is invalid if any listed ballot was ignored (wrong proposal, circle or
   scope, a device not on the roll or outside the electorate, a revoked device, a second
   ballot of a member already represented) or is a `reject` or `revise`.
6. The members so represented number at least `need`.

A RESULT that verifies establishes that `p` reached its threshold under `c`. A node that
already held those ballots knew this without it. Any member of the electorate may
publish one; several for the same proposal are equivalent.

### 14.4 Rules in force

A proposal **counts** under a node's current charter `c` in exactly two ways:

* **by vote**: it names `c` (`p.charter == charter_digest(c)`) and has reached its
  threshold (14.2);
* **carried**: it is an `adopt` proposal whose event id `c` lists in `carried`. Its
  ballots are not re-counted.

A proposal that names any other charter does not count, however many approvals it has:
it is *stale* and must be proposed again under the current charter.

The rules in force are then a pure function of `c` and the proposals that count under it
(`rules_in_force`), independent of the order anything arrived in:

```text
A = { adopt proposals that count under c }          (carried, or passed by vote)
R = { target of every repeal proposal that counts under c }
for each skill name s:
    winner(s) = the proposal in A with skill_name s and the greatest (created_at, event_id)
    s is in force, with winner(s)'s bundle, iff winner(s) is not in R
```

`created_at` here is the proposal's own signed `created_at` and `event_id` is compared
as a string. A newer rule of the same name replaces the older one. Repealing the winner
leaves that name with no rule: an older one does not come back. At most one rule per
skill name is in force.

A node that lacks a carried proposal (it has the id from the charter but not the event)
has an incomplete rule set until it fetches it.

### 14.5 Charter succession

The charter changes only by vote. An `amend` proposal carries the complete proposed
content `next = {rules, roll, carried}`. Its `carried` SHOULD list exactly the rules in
force when it is proposed; a voter's client SHOULD show which rules a proposed list
drops and which it adds before the human votes (`carried_diff`), because approving an
amendment also approves the rule set it carries forward.

Once the amendment has reached its threshold, the holder of the circle root key signs
the next charter and publishes it in a CHARTER event (section 8.6).

A node holding current charter `c` accepts a charter `c'` as its successor iff all of
these hold (`check_successor`):

1. `c'` passes verification (section 9.6);
2. `c'.circle_id == c.circle_id` and `c'.issuer_key == c.issuer_key`;
3. `c'.seq == c.seq + 1` and `c'.previous == charter_digest(c)`;
4. `c'.justification` is the event id of a RESULT `r` the node holds;
5. the proposal `r` names is an `amend` proposal in this circle with
   `charter == charter_digest(c)`;
6. `c'`'s content equals that proposal's `next` exactly (same rules, same roll, same
   `carried`);
7. `r` verifies under `c` (14.3). The threshold is therefore decided by `c`'s rules and
   the electorate is `c`'s whole roll.

On acceptance `c'` is the node's current charter, and its rule set is recomputed under
`c'`: it is exactly `c'.carried` until something passes under `c'`. Proposals that named
`c` and had not been carried no longer count anywhere, which makes every node converge.

Consequences an implementer can rely on:

* The root key **notarizes**; it does not decide. A root-signed charter that adds or
  removes a member, changes a device or a threshold, or alters `carried` beyond what a
  passed amendment proposed fails step 6 or 7 and is rejected.
* A member who is being removed is still in the electorate of that amendment. A member
  who is being admitted is not: they are not on `c`'s roll yet.
* A majority of an **earlier** roll cannot pass anything after the charter has changed:
  what they sign names an old charter and is stale (14.4), and under the current charter
  their devices are not on the roll.
* If two different amendments both reach their threshold under `c` (which requires some
  member to approve both), the root chooses which to notarize. A node accepts the first
  valid successor it sees; the other then fails step 3.

A node's **first** charter for a circle is its trust anchor and is not subject to these
steps: the founder creates charter 1, and a node that joins later starts from whatever
charter it is given (in the reference implementation: the newest CHARTER event, in a
file of exported events, whose roll lists the joining device) and takes that charter's
`carried` list on the root's signature. From then on every charter it accepts must pass
steps 1 to 7. The founding charter of a circle has `seq` 1 and the founder as its only
member, so the founder's single approval admits the second member, and the first two
members together admit the third.

### 14.6 Adoption is local

Sections 14.2 to 14.5 establish facts about the circle. What a node does with a rule in
force is a local decision of its owner and is not part of the wire protocol. The
reference implementation (`adoption_step`) decides, for each rule in force, in this
order:

1. the fetched bundle's digest differs from the proposal's `bundle_digest`, or the
   bundle is not a valid instruction-only skill (section 10.2): refuse. No vote and no
   confirmation overrides this;
2. the owner opted out of this rule: leave it out;
3. the owner explicitly confirmed this rule: install;
4. the risk scanner reported a high-risk finding: ask the owner;
5. the node's own local policy (required approving members, a minimum number of
   approvals) is not met: ask the owner;
6. otherwise install without asking if the owner chose to *follow* the circle, and ask
   if the owner chose to be *asked*.

A node starts in *follow* after its owner accepts a charter with `rules.binding = true`
and in *ask* otherwise; the owner may choose *ask* at any time. `rules.binding` has no
other effect, and none on counting. Opting out is local and is not broadcast; a member's
public record of disagreement is their `reject` ballot.

### 14.7 Conflicts and supersede

`adopt` proposals in the same circle and scope with the same `skill_name` and different
bundle digests are alternatives that coexist. Each is counted on its own ballots; if
more than one reaches its threshold, 14.4 decides which is in force. `supersedes`
records lineage only; it moves no approvals and is not a veto.

### 14.8 Received questions

Local anti-spam, not a protocol rule (defaults): at most 20 accepted questions per author
per 24 h (all circles) and 100 per circle per 24 h; dedup by circle and normalized
question text; local mute and block lists. Dropped questions may still be stored as
events so sync stays idempotent.

### 14.9 Known limits

* **Founder liveness.** Without the root key holder no charter can be issued, so the
  roll and the rules cannot change (adopt and repeal votes keep working).
* **Founder equivocation.** A root that signs two different successors of one charter
  can split a circle between nodes that saw one first and nodes that saw the other.
* **Turnout.** Thresholds are fractions of the whole electorate, so a member who never
  votes makes every threshold harder to reach.
* **Compromised device.** Its approvals count until a node learns of its revocation, and
  nodes that learn at different times can briefly disagree about an open proposal. They
  converge at the next charter change.
* **Trust anchor.** A node's first charter, including its `carried` list, is taken on
  the root's signature.
* **Growth.** Decision events are permanent and v0 has no pruning, while `fetch_events`
  can describe at most 4096 known events (section 13.3).

## 15. Versioning

* **Schemas** carry a version: `peerharness.event/0.1`, `peerharness.membership/0.1`,
  `peerharness.acceptance/0.1`, `peerharness.revocation/0.1`, `peerharness.invite/0.1`,
  `peerharness.charter/0.1`, `peerharness.bundle/0.1`. A receiver MUST reject any other
  `schema` value.
* **Signing contexts** carry a major version (`-v0`). A change to how an object kind is
  signed or hashed MUST use a new context, so a signature can never verify under two
  meanings.
* **Wire**: protocol id `/peerharness/req/0.1.0` and `hello` versions `["0.1"]`.
* v0 has **no extension points**. Unknown members, unknown event types, unknown roles,
  unknown proposal kinds, unknown error codes and unknown message types are rejected.
  Adding a member to any object, a new event type, a new proposal kind or a new message
  is therefore a breaking change: it needs a
  new schema version (and, for the wire, a new protocol id and `hello` version), and the
  golden vectors are regenerated.
* A node that supports several versions lists them in `hello`; the requester picks one
  both list. v0 nodes support only `0.1`.
* Protocol versions are independent of the `peerharness` binary's semantic version.
  Release notes state which protocol versions a binary speaks.

## 16. Golden vectors and a worked example

The vectors live in `crates/ph-protocol/tests/vectors/` and are generated from fixed
seeds by `crates/ph-protocol/tests/vectors.rs`. CI regenerates them and compares the
files byte for byte, so they always match the reference implementation.

| file | contents |
|---|---|
| `keys.json` | seeds `01`x32 (device), `02`x32 (root), `03`x32 (peer); public keys, fingerprints, the circle id and its exact hashed input |
| `jcs.json` | `valid` cases (`input` and expected `canonical`) and `invalid` cases a strict parser must reject (`max_depth` 8) |
| `events.json` | thirteen envelopes covering all eight types and all three proposal kinds, telling one story (below). Each `name` is the type, optionally followed by `/` and a label, for example `PROPOSAL/amend` |
| `charters.json` | `charter_1` (the founding charter) and `charter_2` (its successor), each with the electorates and approval counts it implies |
| `credentials.json` | `membership_credential`, `acceptance`, `revocation`, `invite` |
| `bundle.json` | one `SKILL.md`, its manifest, canonical manifest, digest input and digest |
| `README.md` | the member layout of each vector and a checklist |

Each signed-object vector has: `context`, `schema`, `signer_public_key`, `unsigned`,
`canonical` (= `JCS(unsigned)`), `signing_input_hex`, `signature`, `event_id` (events) or
`digest` (other objects), `signed`, `signed_canonical` (= `JCS(signed)`, what the
reference implementation stores and sends) and `verify_at` (a time at which every time
rule passes).

The story in `events.json`, in which the device key is member `alice`, the peer key
becomes member `bob`, and the root key notarizes:

1. `QUESTION`, `ANSWER`: a question from alice and bob's answer.
2. `PROPOSAL/amend`, `VOTE/amend`, `RESULT/amend`: under `charter_1` (alice alone) alice
   proposes the roll `alice, bob`, approves it and publishes the result. One member, so
   `need` is 1.
3. `CHARTER`: the root key issues `charter_2`. Its `previous` is the digest of
   `charter_1`, its content equals the amendment's `next`, and its `justification` is
   the event id of `RESULT/amend`.
4. `PROPOSAL/adopt`, `VOTE/adopt-alice`, `VOTE/adopt-bob`, `RESULT/adopt`: a rule is
   proposed under `charter_2` for scope `team/backend`. Both members are in that
   electorate and `need` is 2.
5. `PROPOSAL/repeal`: bob proposes to take that rule out of force.
6. `MEMBERSHIP`, `REVOCATION`: one control-plane event of each kind.

The five permanent types must still verify ten years after `verify_at`; QUESTION, ANSWER
and MEMBERSHIP must not.

### 16.1 Worked example: the QUESTION vector

From `events.json`, entry `"name": "QUESTION"`. Author: the device key from `keys.json`
(seed `01`x32, `ed25519:iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w`). Circle: the root
key's circle (`sha256:de392f33...0ae9`).

**Step 1. Canonicalize the unsigned envelope.** Remove `signature` and `event_id`, sort
members by UTF-16 code units, no whitespace. The `canonical` string is exactly:

```text
{"author":"ed25519:iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w","body":{"question":"Should this repository use pnpm rather than npm?","related_candidate":"sha256:7b09e531cf94528df2a42bdc19370f2186859afd6bc767dfcfbf076a7e1b487c","topic":"package-manager"},"circle_id":"sha256:de392f334c6c4a6af8609650d76f7e635a1a507d734033e6dd9fcab222730ae9","created_at":"2026-11-09T18:10:00Z","expires_at":"2026-12-09T18:10:00Z","nonce":"base64url:EBAQEBAQEBAQEBAQEBAQEA","schema":"peerharness.event/0.1","scope":"team/backend","type":"QUESTION"}
```

**Step 2. Build the signing input.** `UTF8("peerharness-event-v0")` is
`706565726861726e6573732d6576656e742d7630`, then one `00` byte, then the canonical
string's UTF-8 bytes (`7b22617574686f72...`). The full `signing_input_hex` (551 bytes)
is:

```text
706565726861726e6573732d6576656e742d7630007b22617574686f72223a22656432353531393a696f6a6a3358514a385a583955747374504c70646373706e436238646c4249623833534941625150623177222c22626f6479223a7b227175657374696f6e223a2253686f756c642074686973207265706f7369746f72792075736520706e706d20726174686572207468616e206e706d3f222c2272656c617465645f63616e646964617465223a227368613235363a37623039653533316366393435323864663261343262646331393337306632313836383539616664366263373637646663666266303736613765316234383763222c22746f706963223a227061636b6167652d6d616e61676572227d2c22636972636c655f6964223a227368613235363a64653339326633333463366334613661663836303936353064373666376536333561316135303764373334303333653664643966636162323232373330616539222c22637265617465645f6174223a22323032362d31312d30395431383a31303a30305a222c22657870697265735f6174223a22323032362d31322d30395431383a31303a30305a222c226e6f6e6365223a2262617365363475726c3a45424151454241514542415145424151454241514541222c22736368656d61223a22706565726861726e6573732e6576656e742f302e31222c2273636f7065223a227465616d2f6261636b656e64222c2274797065223a225155455354494f4e227d
```

**Step 3. Hash it.** `SHA-256(signing_input)` gives the event id:

```text
sha256:be79915498eebfc15547bfeedd7b3406478931c71173c0403d1a276b5c28ca17
```

**Step 4. Sign it.** Ed25519 with seed `01`x32 over the same bytes. Ed25519 is
deterministic, so you must get exactly:

```text
base64url:jwP0YHfO_2fpVi21SRcqaNVg7QmXhclok9seA0TjTlmyUeX5QQKZ58ViY4d2ow1rtbj1_bpAUv1Y4zYb2QOgCg
```

**Step 5. Transmit.** Add `signature` and `event_id` to the unsigned object; its
canonical form is the vector's `signed_canonical`. A receiver at `verify_at`
(`2026-11-10T18:10:00Z`) must accept it statelessly; changing any member must make it
fail.

The vectors were checked with an independent Python implementation (a short JCS
function, `hashlib` and the `cryptography` package), which reproduced the canonical
form, signing input, digest and signature of all thirteen events, the four membership
objects and both charters, and confirmed the links between them (`charter_2.previous`,
`charter_2.justification`, the `charter` member of each proposal, and the amendment's
`next`).

### 16.2 Writing a new client

1. Implement the encodings (section 2) and test them against `keys.json`.
2. Implement the strict parser and canonicalizer (section 3) and pass every case in
   `jcs.json`, valid and invalid.
3. For every vector in `events.json`, `credentials.json` and `charters.json`:
   canonicalize `unsigned` and compare with `canonical`; build the signing input and compare with
   `signing_input_hex`; hash and compare with `event_id` / `digest`; sign with the seed
   from `keys.json` and compare with `signature`; verify `signed_canonical` at
   `verify_at`. An acceptance's `credential_digest` equals the credential vector's
   `digest`.
4. Reproduce `bundle.json`: hash the file, build the manifest, canonicalize it, compare
   `digest_input_hex` and `digest`.
5. Implement the charter (section 9.6) and the voting rules (section 14) and replay the
   story in `events.json`: compute each proposal's electorate and `need` and compare
   with `charters.json`; count the ballots and check that `RESULT/amend` and
   `RESULT/adopt` verify; check that `charter_2` is accepted as the successor of
   `charter_1`; check that the rule adopted by `PROPOSAL/adopt` is in force under
   `charter_2`.
6. Implement the wire messages (section 11) and the validation order (sections 7.4 and
   12.4). Testing against a reference node on loopback will be possible once the
   reference daemon is finished (Appendix B).

## Appendix A: limits

| limit | value |
|---|---|
| envelope, raw and canonical | 65,536 bytes (64 KiB) |
| standalone credential, acceptance, revocation or invite | 16,384 bytes |
| standalone charter | 65,536 bytes |
| wire frame body (request or response) | 524,288 bytes (512 KiB) |
| bundle total size, `bundle_size` | 1 to 262,144 bytes (256 KiB) |
| JSON depth: signed objects / wire frames | 8 / 10 |
| integers | `±(2^53 - 1)` |
| clock skew allowance | 300 s (not applied to REVOCATION) |
| event lifetime / credential lifetime | at most 400 days each |
| expiring / permanent event types | QUESTION, ANSWER, MEMBERSHIP / PROPOSAL, VOTE, RESULT, CHARTER, REVOCATION |
| QUESTION `question` / `topic` | 1-2000 (multi-line) / 1-128 (single-line) code points |
| ANSWER / VOTE `rationale` | 0-2000 code points, multi-line |
| PROPOSAL `title` / `summary` | 1-200 single-line / 0-1000 multi-line |
| `adopt` PROPOSAL `description` | 1-1024 code points, multi-line |
| RESULT `approvals` | 1-64, sorted, unique |
| charter roll | 1-64 members, sorted, unique |
| member handle | 1-32 bytes, `^[a-z0-9][a-z0-9._-]{0,31}$` |
| devices per member / scopes per member | 1-4 / 1-16, sorted, unique |
| charter `carried` | 0-256, sorted, unique |
| threshold | `1 <= num < den <= 100`, `2*num >= den`, `amend >= pass` |
| revocation `reason` | 0-200 code points, single-line |
| invite `circle_name` | 1-64 code points, single-line |
| credential roles / scopes | 1-2 / 1-16, unique |
| scope | `*`, or at most 128 bytes, 1-8 segments of 1-64 chars |
| skill name | 1-64 chars |
| multiaddr strings (`issuer_addrs`, `listen_addrs`) | at most 8, each 1-256 bytes |
| `hello` versions / capabilities | at most 8, each 1-32 bytes |
| `authenticate` / `authenticated` memberships | at most 16 |
| `push_events` events / `push_result` results | at most 64 |
| `fetch_events` known / limit | at most 4096 / 1-256 |
| `events` response | at most 256 events |
| `bundle` response files / path | at most 16 / 1-256 bytes |
| default lifetimes | QUESTION, ANSWER 30 d; permanent types 400 d (not enforced); invite 24 h (max 7 d); member credential 30 d; founder credential 365 d |

## Appendix B: differences from architecture.md

`docs/architecture.md` describes the same design more briefly. The source is
authoritative; these points in this document come from the source and are more precise
or different:

* **Wire message shape.** Architecture writes messages as `Hello { versions }` etc. On
  the wire they are JSON objects tagged with a snake_case `"type"` member (for example
  `{"type":"push_events","events":[...]}`), with fields as siblings.
* **`push_result` entries.** `event_id` is optional (omitted when the pushed value had no
  parseable id); architecture shows it as always present.
* **Oversized frames.** Architecture says a larger frame closes the stream. In the source
  an oversized *request* prefix is answered with `error{too_large}` without reading the
  body, and a malformed request with `error{bad_request}`; only an oversized or invalid
  *response* fails the read and drops the stream. The source also answers
  `error{unavailable}` when the shared inbound buffer budget is exhausted.
* **Frame depth.** Architecture gives depth 8; wire frames allow depth 10 because
  envelopes nest two levels inside them. Each embedded envelope is still limited to 8.
* **Strictness.** Besides rejecting unknown members at every level, the source rejects
  explicit `null` for optional members and requires an exact re-serialization round
  trip.
* **Size checks.** The 64 KiB envelope limit applies to the received bytes and to the
  canonical transmitted form (with `signature` and `event_id`).
* **MEMBERSHIP events.** The envelope scope must be `*` or covered by a credential
  scope; architecture does not state this.
* **Ballot scope.** A ballot's and a result's envelope scope must *equal* the
  proposal's, and a `repeal` must have the scope of its target. Architecture states the
  second and implies the first.
* **Revocations.** The source treats a revocation as permanent for that device key in
  that circle, regardless of `revoked_at`, keeps the first one per subject, and treats a
  revocation of the root key itself as structurally malformed.
* **Text fields.** Besides controls and bidi characters, the source rejects zero-width
  and other invisible format characters (U+200B-U+200D, U+2060, U+FEFF, U+180E, tag
  characters), which also rejects emoji ZWJ sequences.
* **Credential and invite bounds.** Roles 1-2 and scopes 1-16 (unique), standalone
  documents at most 16 KiB, invite address strings printable ASCII; these limits are not
  in architecture.md.
* **Pre-auth exposure.** Architecture says only `hello` is answered before
  authorization. `authenticate` is also answered (that is how authorization happens),
  with an empty `memberships` list unless the requester proved membership.
* **Network not wired yet.** Sections 11 to 13 describe what a node does on the wire.
  The transport, framing, limits and every validation and authorization predicate are
  implemented in the library crates; the daemon that composes them into a request
  handler and a sync loop is not finished, so two reference nodes cannot yet be run
  against each other over QUIC. They can be run against each other today by exchanging
  events as files: one JSON object per line, `{"event": <envelope>}` or
  `{"bundle": {"digest": "sha256:…", "skill_md": "…"}}`. The receiver applies sections
  7, 12 and 14 to every line exactly as it would to a pushed event, and accepts a bundle
  only if a stored `adopt` proposal names its digest.
