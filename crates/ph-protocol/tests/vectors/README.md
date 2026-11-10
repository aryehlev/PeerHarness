# PeerHarness protocol v0 golden test vectors

These files are generated from fixed inputs by `crates/ph-protocol/tests/vectors.rs`.
CI regenerates them and compares the output byte for byte, so they always match the
reference implementation. Do not edit them by hand. After an intentional protocol
change, regenerate them and review the diff:

```sh
PH_UPDATE_VECTORS=1 cargo test -p ph-protocol --test vectors
```

## Files

| file | contents |
|---|---|
| `keys.json` | Ed25519 seeds (32-byte RFC 8032 secret keys) and the derived public keys, fingerprints and circle id. Device seed `01`x32, root seed `02`x32, peer seed `03`x32. |
| `jcs.json` | `valid`: `input` JSON text and the expected `canonical` output. `invalid`: inputs a strict parser must reject (`max_depth` 8). |
| `events.json` | Thirteen envelopes covering every type and every proposal kind, telling one story (see below). Each `name` is the type, optionally followed by `/` and a label, for example `PROPOSAL/amend`. |
| `charters.json` | `charter_1` (the founding charter) and `charter_2` (its successor), each with the electorates and approval counts it implies. |
| `credentials.json` | `membership_credential`, `acceptance`, `revocation`, `invite`. |
| `bundle.json` | One `SKILL.md`, its manifest, canonical manifest, digest input and bundle digest. |

Each signed-object vector has these members:

* `context`: the domain-separation string, for example `peerharness-event-v0`
* `schema`: the object's `schema` value
* `signer_public_key`: the key that must verify the signature
* `unsigned`: the object without `signature` and `event_id`
* `canonical`: `JCS(unsigned)`, exactly
* `signing_input_hex`: hex of `UTF8(context) || 0x00 || canonical`
* `signature`: `base64url:` + base64url-nopad of the Ed25519 signature over the signing input
* `event_id` (events) or `digest` (other objects): `sha256:` + hex(SHA-256(signing input))
* `signed`: the transmitted object (`unsigned` + `signature`, + `event_id` for events)
* `signed_canonical`: `JCS(signed)`, which is what the reference implementation stores and sends
* `verify_at`: a time at which every time rule passes

## The story in `events.json`

The device is member `alice`, the peer becomes member `bob`, and the root key notarizes.

1. `QUESTION`, `ANSWER`: a question from alice and bob's answer. These two types expire.
2. `PROPOSAL/amend`, `VOTE/amend`, `RESULT/amend`: under `charter_1` (alice alone) alice
   proposes the roll `alice, bob`, approves it, and publishes the result. One member, so
   one approval is the majority.
3. `CHARTER`: the root key issues `charter_2`, whose `previous` is the digest of
   `charter_1` and whose `justification` is the event id of `RESULT/amend`.
4. `PROPOSAL/adopt`, `VOTE/adopt-alice`, `VOTE/adopt-bob`, `RESULT/adopt`: a rule is
   proposed under `charter_2` for scope `team/backend`. Both members are in that
   electorate and two approvals are needed.
5. `PROPOSAL/repeal`: bob proposes to take that rule out of force.
6. `MEMBERSHIP`, `REVOCATION`: one control-plane event of each kind.

PROPOSAL, VOTE, RESULT, CHARTER and REVOCATION are permanent records: they must still
verify ten years after `verify_at`. QUESTION, ANSWER and MEMBERSHIP must not.

## How to use them in another implementation

1. **Canonicalization.** For every `jcs.json` `valid` case, parse `input`, canonicalize
   it, and compare the result to `canonical` byte for byte. Keys are sorted by UTF-16
   code units. Strings use ECMAScript `JSON.stringify` escaping (`\b \f \n \r \t \" \\`,
   other characters below U+0020 as lowercase `\u00xx`, everything else literal UTF-8,
   `/` not escaped). Numbers are integers with |n| <= 2^53-1. Your parser must reject
   every `invalid` case: duplicate keys, any fraction or exponent including `1.0` and
   `-0`, out-of-range integers, nesting deeper than 8, lone surrogates and trailing data.
2. **Signing input.** For each signed vector, canonicalize `unsigned` and check it equals
   `canonical`. Then build `context || 0x00 || canonical` and check its hex equals
   `signing_input_hex`.
3. **Digest.** SHA-256 of the signing input must equal `event_id` / `digest`. An
   acceptance's `credential_digest` equals the credential vector's `digest`.
4. **Signature.** Ed25519-verify (RFC 8032, pure, with strict verification) `signature`
   over the signing input using `signer_public_key`. Since Ed25519 is deterministic,
   signing the signing input with the seed from `keys.json` must reproduce `signature`
   exactly.
5. **Reverse direction.** Remove `signature` and `event_id` from `signed` and check you
   get `unsigned` back. Verifying `signed_canonical` as received bytes at `verify_at`
   must succeed, and changing any member must make it fail.
6. **Circle id.** `circle_id = "sha256:" + hex(SHA-256("peerharness-circle-v0" || 0x00 || root_pubkey))`.
   `keys.json` includes the exact hashed input.
7. **Bundle digest.** `sha256` of each file is the plain SHA-256 of its bytes.
   `digest = "sha256:" + hex(SHA-256("peerharness-bundle-v0" || 0x00 || JCS(manifest)))`.
8. **Charters and counting.** A charter's `digest` is what a PROPOSAL carries in its
   `charter` member. The electorate of an `amend` proposal is the whole roll; of an
   `adopt` or `repeal` proposal it is the whole roll when the envelope scope is `*`, and
   otherwise the members with a scope that covers it. A proposal passes with approvals
   from `floor(n * num / den) + 1` distinct members of an electorate of `n`, one per
   member however many devices signed. `charters.json` lists the expected electorates
   and counts. A ballot's author must be a device on the roll of the charter that the
   proposal names.

Encodings: public keys are `ed25519:` + base64url-nopad (32 bytes). Signatures and nonces
are `base64url:` + base64url-nopad (64 and 16 bytes). Digests are `sha256:` + 64
lowercase hex characters. Timestamps are `YYYY-MM-DDTHH:MM:SSZ` (UTC, whole seconds).
