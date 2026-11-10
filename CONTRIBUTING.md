# Contributing to PeerHarness

Thanks for your interest. PeerHarness lets a team vote on how its AI coding agents
behave: a correction becomes a small rule, the members vote on it, and every node
counts the votes for itself. It is written in Rust. This file covers the development
setup, the checks every change must pass, how a change is made, how to write a protocol
client in another language, and how to report security problems.

The first versions were written with an AI coding agent from the brief in
[`docs/spec.md`](docs/spec.md), and [`AGENTS.md`](AGENTS.md) is addressed to such
agents. The same rules apply to a person and to an agent.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Read first

* [`README.md`](README.md): what the product does today, how each part was checked,
  and its known limits.
* [`docs/architecture.md`](docs/architecture.md): the internal contract between crates.
* [`docs/decisions.md`](docs/decisions.md): ADRs and deviations from the specification.
* [`docs/spec.md`](docs/spec.md): the original brief, kept for history. Its first
  lines list where the product departs from it. Where the two differ, the architecture
  and the ADRs are what holds.
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

`cargo run` and `cargo build` make a debug build. A debug build obeys the
`PEERHARNESS_TEST_*` stand-ins that the tests use in place of a confirmation window, a
notification and Claude Code's `claude` command, so it is for development and tests and
not for daily use. `peerharness doctor` says so in a `build` line and `peerharness
status` in a shorter one. A release build does not read those variables. No command
may refuse because the build is a debug build: the test suite and `demo/two-peers.sh`
run debug builds.

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

## How a change is made

1. **Read first.** The documents above, and the crate-level docs (`//!` in each
   `src/lib.rs`) of the crates you touch. `AGENTS.md` has the crate boundaries and the
   invariants that must never be loosened. Check the current official documentation of
   a library before you change how it is used.
2. **Add tests where they belong.** Unit tests sit next to the code. Tests of one crate
   are in `crates/<crate>/tests/`. Tests that run the binary, the multi-node ones
   included, are in `apps/peerharness/tests/` (ADR-007), with shared fixtures in
   `tests/fixtures/`. Security behaviour needs a negative test: show the forged,
   expired, revoked, out-of-scope, replayed or oversized input being rejected. The
   testing rules in `AGENTS.md` say what every test has to set so that it never touches
   your real `~/.claude`, your keychain or the public network.
3. **Run the checks** above and report what they printed.
4. **Update the docs in the same change**: the README, `docs/`, the exact CLI examples,
   `CHANGELOG.md`, and an ADR in `docs/decisions.md` for every decision or deviation.
5. **Keep commits to one logical increment each.**
6. **Say what you did not do.** Known limitations go in the pull request and, if they
   concern users, in the README's "Known limits".

**Do not loosen a security requirement to finish a feature.** If a requirement cannot
be met safely, leave the feature disabled, document the blocker, and continue with the
safe scope.

### Pull requests

* Keep pull requests focused. Explain what changed and why, how you tested it, and any
  limitation. The pull-request template asks for the same.
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
