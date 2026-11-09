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
| `events.json` | One envelope of each type: QUESTION, ANSWER, PROPOSAL, VOTE, RELEASE, MEMBERSHIP, REVOCATION. |
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

Encodings: public keys are `ed25519:` + base64url-nopad (32 bytes). Signatures and nonces
are `base64url:` + base64url-nopad (64 and 16 bytes). Digests are `sha256:` + 64
lowercase hex characters. Timestamps are `YYYY-MM-DDTHH:MM:SSZ` (UTC, whole seconds).
