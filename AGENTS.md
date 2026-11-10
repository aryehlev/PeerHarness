# Guidance for AI coding agents

This file is for AI coding agents (Claude Code, Codex and similar) working on this
repository. Humans should follow it too. It is short on purpose: read the documents it
points to before changing anything non-trivial.

## Read before you change code

1. `docs/spec.md`: what we are building and the hard requirements.
2. `docs/architecture.md`: the contract between crates (encodings, signing, events,
   wire, schema, governance by vote under a charter in section 10, privacy rules).
3. `docs/decisions.md`: ADRs. Record every new decision or deviation there.
4. `docs/protocol-v0.md` and `docs/security-model.md` before touching protocol,
   authorization, networking, keys, skills or anything that sends data off the device.
5. The crate-level docs (`//!` in each `src/lib.rs`) of the crates you touch.

If a library's API differs from what the docs assume, check the library's current
official documentation, adapt, and record the deviation in `docs/decisions.md`.

## Crate boundaries

```text
ph-core  <-  ph-protocol  <-  ph-identity, ph-governance, ph-skills, ph-network, ph-store
ph-core  <-  ph-observer, ph-learning
apps/peerharness depends on everything and is the only place crates are wired together.
```

| crate | owns | must not |
|---|---|---|
| `ph-core` | encodings and ids, `Scope`, `Role`/`Capability`, candidate state machine, observations, redaction, `Clock`, `MembershipOracle` | depend on any other workspace crate |
| `ph-protocol` | JCS, signing, envelopes and bodies, credentials, the charter, bundles, wire types, limits, golden vectors | do I/O or networking |
| `ph-identity` | keystores, device identity, circle authority (credentials, revocations, charter issuance), invites, `MembershipRegistry` | store private keys anywhere but the keystore; decide whether a charter change was voted |
| `ph-store` | SQLite schema, migrations, typed repositories | make authorization decisions |
| `ph-network` | libp2p QUIC transport, framing, rate limits | know about circles or authorize anything |
| `ph-observer` | hook parsing, settings install/remove, spool, notification throttle | open paths from hook payloads |
| `ph-learning` | detectors, drafts, advisory providers | let provider output drive any decision |
| `ph-governance` | incoming-event authorization, read rules, tally, result verification, rules in force, charter succession, conflicts, anti-spam, adoption gate | do storage or networking; read a clock when counting |
| `ph-skills` | `SKILL.md` parsing and validation, the instruction-only rule, scanner, bundles, bundle store, installer | execute skill content |

Only `apps/peerharness` may depend on `ph-store` or `ph-network`. Library crates talk
through types and traits from `ph-core` and `ph-protocol`. Integration tests that run
the binary live in `apps/peerharness/tests/` (ADR-007); shared fixtures in
`tests/fixtures/`.

## Invariants that must never be loosened

Do not weaken any of these to make a test pass or a feature work. If one blocks you,
stop, leave the feature disabled, and document the blocker.

**Consent and privacy**

* Nothing leaves the device automatically. Only text the human saw in an exact preview
  and confirmed goes into QUESTION, ANSWER or PROPOSAL bodies or bundles, and
  `ph_core::redact` runs before the preview.
* Never infer consent from agent or model output. Model output is advisory only and is
  never `Actor::Human`. Human-only lifecycle transitions stay human-only.
* Observation text, prompts, transcripts, tool output, skill text, circle names,
  revocation reasons and passphrases never appear in logs, error `Display` strings,
  panic messages or network payloads. Log ids and counts only. `Debug` of types holding
  such text prints lengths.
* `transcript_path` and any other path from a hook payload is never opened. Hooks always
  exit 0, never block, and print nothing for `UserPromptSubmit`.
* Joining a circle never uploads existing local data.
* Remote advisory providers stay off by default and need both config opt-in and a
  per-invocation exact preview.

**Keys and identity**

* No private key bytes in SQLite, logs or files other than the keystore. No silent
  plaintext keys: `insecure-dev` requires an explicit flag and warns.
* The circle root key is separate from every device key and never leaves its keystore.
* The libp2p identity is the device key; authorization uses the transport-authenticated
  device key, never a claimed id.

**Protocol and authorization**

* Deny by default. Before membership is proven, only `hello` gets a real answer; every
  other request gets `error{unauthorized}`, identical whether a circle exists or not.
* Request authorization (who may connect, read, ask, answer) is re-evaluated on every
  request and every use, at the local clock. Never cache an authorization decision.
* A credential counts only with a matching subject-signed acceptance, only from the
  circle root, only within its scopes and roles, and never after revocation or expiry.
* Four ways to authorize an event, never interchangeable (ADR-010, ADR-012): QUESTION and
  ANSWER by credential capability; PROPOSAL, VOTE and RESULT by the roll of the charter
  the proposal names; MEMBERSHIP by its embedded proof; REVOCATION and CHARTER by the
  root-key binding. A valid credential does not make a voter, and the root key has no
  vote.
* Strict parsing: integer-only JCS, duplicate keys rejected, unknown members rejected at
  every level, explicit `null` rejected, size and depth limits enforced before parsing
  further.
* Signing input is exactly `context || 0x00 || JCS(unsigned)`; verification uses
  `verify_strict` and recomputes the canonical form. Do not change the bytes that are
  signed without a new schema version, regenerated vectors and a protocol doc update.

**Voting (architecture section 10)**

* A proposal passes only with approvals from `need(n, t) = floor(n*num/den) + 1` members
  of its whole electorate, never fewer than a strict majority. Count members, not
  devices. Nobody has a veto: `reject` and `revise` are recorded dissent.
* An approval is never withdrawn and "passed" never reverts. A ballot counts only for
  the exact proposal id it signs.
* Counting, result verification, the rule set and charter succession never read a clock
  and never depend on arrival order. Do not add `now`, expiry or "latest wins" to them.
  PROPOSAL, VOTE, RESULT, CHARTER and REVOCATION never expire, and a revocation is never
  refused for its date (ADR-015, ADR-017).
* A RESULT and a root-signed CHARTER carry no authority. Nothing takes effect before
  `verify_result` or `check_successor` passes locally. The root key notarizes: never
  accept a charter (other than a node's first) that a passed amendment does not justify
  with exactly the content that was voted on.
* A proposal counts only under the current charter. Only `Passed::by_vote` and
  `Passed::carried` feed `rules_in_force`; do not add another way in.
* Rights no vote overrides (10.10): no vote widens read access; a bundle that fails its
  digest or validity check is never installed; a high-risk finding always asks the
  owner; an opt-out always wins. `LocalPolicy` can hold a rule back on one node and can
  never change whether it passed.

**Skills and the file system**

* Received bundles are exactly one `SKILL.md`. Reject traversal, absolute paths,
  backslashes, hidden files, symlinks, duplicates and extra files. Never execute skill
  content. Scanning never proves safety; do not claim it does.
* Every bundle, local or received, is instructions only: no `allowed-tools`, no
  shell-injection syntax (`ph_skills::check_instruction_only`, ADR-018). These are hard
  refusals. Do not downgrade them to scanner warnings or add a flag that overrides them.
* Installation requires the owner's consent: an explicit confirmation, or the owner's
  standing `follow` choice for a rule that passed a vote, verified its digest and has no
  high-risk finding (architecture 10.9). It is atomic, never overwrites an unmanaged
  directory without `--force-overwrite-unmanaged`, and uninstall/rollback touch only
  managed files.
* Changes to Claude settings are idempotent, backed up and atomic.

**Honesty**

* Do not claim a security audit, production readiness, or that a test passed when you
  did not run it.

## Commands

Run these before you say a change is done, and report the actual results:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

When dependencies change, also run `cargo deny check` and `cargo audit` if installed
(CI runs both), and keep `cargo +1.89 check --workspace --locked` working (MSRV).

Protocol vectors: `cargo test -p ph-protocol --test vectors`. Never edit files in
`crates/ph-protocol/tests/vectors/` by hand; after an intentional protocol change run
`PH_UPDATE_VECTORS=1 cargo test -p ph-protocol --test vectors` and review the diff.

## Testing rules

* Every test uses fresh temporary homes (`PEERHARNESS_HOME`), `PEERHARNESS_PASSPHRASE`,
  `init --kdf-profile fast-insecure-test`, a temporary `PEERHARNESS_CLAUDE_SKILLS_DIR`
  and a temporary `PEERHARNESS_CLAUDE_SETTINGS`. Never touch the developer's real
  `~/.claude`, real settings or the OS keychain; tests that must are `#[ignore]`d.
* Multi-node tests use real separate OS processes on ephemeral loopback QUIC ports, with
  no shared database and no network mocks. Poll with deadlines instead of fixed sleeps,
  and kill daemons in `Drop` guards.
* Security behaviour needs negative tests: show the forged, expired, revoked,
  out-of-scope, replayed or oversized input being rejected.
* Use fake provider binaries via `PEERHARNESS_CLAUDE_BIN` / `PEERHARNESS_CODEX_BIN`; never
  call a real model in tests.

## Code conventions

* `#![forbid(unsafe_code)]` everywhere. Edition 2021, MSRV 1.89.
* Clippy clean with `-D warnings`. Errors via `thiserror` in libraries, with static,
  content-free messages.
* Prefer crates already in the workspace; new dependencies must be permissively licensed,
  from crates.io, and pass `cargo deny check`. Avoid OpenSSL.
* Keep `apps/peerharness/src/main.rs` thin; one module per command group.
* Commit logically separate increments. Update docs and ADRs in the same change.
