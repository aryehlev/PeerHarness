# Contributing to PeerHarness

Thanks for your interest. PeerHarness is a local-first, peer-to-peer learning harness for
AI coding agents, written in Rust. This file covers the development setup, the checks
every change must pass, how we work in phases, how to write a protocol client in another
language, and how to report security problems.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Read first

* [`docs/spec.md`](docs/spec.md): the original specification this repository implements.
* [`docs/architecture.md`](docs/architecture.md): the internal contract between crates.
* [`docs/decisions.md`](docs/decisions.md): ADRs and deviations from the specification.
* [`docs/protocol-v0.md`](docs/protocol-v0.md): the wire and signing protocol.
* [`docs/security-model.md`](docs/security-model.md): the threat model.
* [`AGENTS.md`](AGENTS.md): crate boundaries and invariants (written for AI coding agents,
  and just as binding for humans).

## Development setup

Supported development platforms are macOS and Linux (x86_64 or aarch64). Windows is not
supported yet.

1. Install Rust with [rustup](https://rustup.rs/). The minimum supported Rust version is
   **1.89** (`rust-version` in `Cargo.toml`); use current stable for development:

   ```sh
   rustup toolchain install stable --component rustfmt --component clippy
   ```

2. Clone and build:

   ```sh
   git clone https://github.com/aryehlev/peerharness
   cd peerharness
   cargo build --workspace --locked
   ```

No system packages are needed. SQLite is bundled, the crypto libraries build with the
platform C compiler (Xcode command line tools on macOS, `gcc` or `clang` on Linux), and
the Linux keyring backend is pure Rust.

Optional tools used in CI:

```sh
cargo install cargo-deny --locked
cargo install cargo-audit --locked
```

### Trying the binary without touching your real setup

Every node lives in its own home directory. Use throwaway homes and override every path
that could touch your real Claude Code configuration or keychain:

```sh
export PEERHARNESS_HOME="$(mktemp -d)"
export PEERHARNESS_PASSPHRASE="dev-only-passphrase"
export PEERHARNESS_CLAUDE_SKILLS_DIR="$(mktemp -d)"
export PEERHARNESS_CLAUDE_SETTINGS="$(mktemp -d)/settings.json"
cargo run -p peerharness -- init --keystore file
```

`init --kdf-profile fast-insecure-test` makes key derivation fast for tests and demos. It
is test-only, prints a warning, and must never be used for real keys.

## Checks every change must pass

These are exactly what CI runs (`.github/workflows/ci.yml`):

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

plus, on the MSRV toolchain and for dependency changes:

```sh
cargo +1.89 check --workspace --locked
cargo deny check
cargo audit
```

Useful narrower commands:

```sh
cargo test -p ph-protocol                       # one crate
cargo test -p ph-protocol --test vectors        # golden vectors only
cargo test -p peerharness --test <name>         # one multi-process integration test
```

Integration tests in `apps/peerharness/tests/` start real `peerharness` processes with
temporary homes and ephemeral loopback QUIC ports. They set all the environment
variables above themselves; you do not need to export anything to run them. Tests that
would use the real OS keychain are `#[ignore]`d.

**Never claim a test passed without running it.** In pull requests, paste the actual
command output or say plainly what you did not run.

## How we work: phases and discipline

The project is built in phases (specification section 12): A (skeleton and local
identity), B (direct P2P and invitation-only circles), C (local learning and human
questions), D (signed questions, votes and decisions), E (immutable skill sharing, sync
and rollback), F (launch). Each phase has an acceptance gate described in the
specification.

For every phase and every non-trivial change, follow the discipline of specification
section 14:

1. **Read the existing code and the current official library documentation** before
   changing a core interface.
2. **Write a short plan, then implement it.** Ship running code, not documentation-only
   scaffolding.
3. **Add tests**: unit tests, integration tests, negative authorization tests and
   failure handling. Security-relevant behaviour needs a test that shows the attack
   failing.
4. **Run** `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D
   warnings` and `cargo test --workspace` (CI adds `--locked`).
5. **Update the docs**: README, `docs/`, exact CLI examples, and an ADR in
   `docs/decisions.md` for every decision or deviation from the specification.
6. **Keep features behind stable CLI boundaries** and commit logically separate
   increments.
7. **Show actual results and known limitations.** Never report a test as passing
   without running it.

Prioritize a working, safe two-node network and the local learning loop over feature
breadth. **Do not loosen a security requirement to finish a feature.** If a requirement
cannot be met safely, leave the feature disabled, document the blocker, and continue with
the safe scope.

### Pull requests

* Keep pull requests focused. Explain what changed and why, how you tested it, and any
  limitation.
* Changes to the protocol (anything in `crates/ph-protocol` that changes bytes on the
  wire or what is signed) need an update to `docs/protocol-v0.md`, regenerated vectors
  (below) and, if incompatible, a new schema version (protocol section 15).
* New dependencies must pass `cargo deny check` (permissive licenses only, crates.io
  only). Prefer crates already in the tree. Avoid OpenSSL.
* Architectural decisions go into `docs/decisions.md` as a short ADR.

## Writing a protocol client in another language

You can write an interoperable client from [`docs/protocol-v0.md`](docs/protocol-v0.md)
and the golden vectors in
[`crates/ph-protocol/tests/vectors/`](crates/ph-protocol/tests/vectors/) alone.

1. **Keys and encodings.** Load `keys.json`. Derive each public key from its seed
   (RFC 8032), encode it as `ed25519:` + base64url without padding, and check the
   fingerprints and the circle id (`circle_id_input_hex` shows the exact hashed bytes).
2. **Canonical JSON.** Implement the strict parser and the integer-only JCS
   canonicalizer (protocol section 3). Every `jcs.json` `valid` case must canonicalize
   byte for byte to `canonical`; every `invalid` case must be rejected.
3. **Signed objects.** For each vector in `events.json` and `credentials.json`:
   canonicalize `unsigned` and compare with `canonical`; build
   `context || 0x00 || canonical` and compare its hex with `signing_input_hex`; SHA-256
   it and compare with `event_id` or `digest`; sign it with the seed from `keys.json` and
   compare with `signature` (Ed25519 is deterministic); strictly verify
   `signed_canonical` at `verify_at`, and check that changing any member makes
   verification fail.
4. **Bundles.** Reproduce `bundle.json`: the file hash, the canonical manifest,
   `digest_input_hex` and `digest`.
5. **Wire.** Implement libp2p QUIC with an Ed25519 identity, the
   `/peerharness/req/0.1.0` request-response protocol with 4-byte big-endian
   length-prefixed JSON frames, and the messages and validation order of protocol
   sections 11 and 12. Test against two reference nodes on loopback.

The worked example in protocol section 16.1 walks through one vector by hand. The
vectors are generated by `crates/ph-protocol/tests/vectors.rs`; CI regenerates them and
fails if the committed files differ. Never edit them by hand. After an intentional
protocol change:

```sh
PH_UPDATE_VECTORS=1 cargo test -p ph-protocol --test vectors
git diff crates/ph-protocol/tests/vectors/
```

If you write a client, we would like to hear about it, and about any place where the
specification was ambiguous.

## Reporting security issues

**Do not open public issues for vulnerabilities.** Follow [`SECURITY.md`](SECURITY.md)
to report privately. PeerHarness has not had a security audit.

## License

PeerHarness is dual-licensed under the MIT license and the Apache License 2.0, at your
option. Unless you explicitly state otherwise, any contribution you intentionally submit
for inclusion in the work, as defined in the Apache-2.0 license, shall be dual licensed
as above, without any additional terms or conditions.
