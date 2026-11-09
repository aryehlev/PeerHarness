# Architecture decisions and deviations

These are short ADR-style entries. Newest entries go last.

## ADR-001: Crypto stack follows libp2p 0.57
`libp2p 0.57.1` pulls in `ed25519-dalek 3`, `sha2 0.11` and `rand 0.10`. We pin the same
majors workspace-wide so only one copy of each primitive is compiled in. The device key is
a single Ed25519 key that serves as both the PeerHarness identity and the libp2p identity,
so the QUIC/TLS-authenticated `PeerId` binds directly to the device key.

## ADR-002: Our own restricted JCS
We implement RFC 8785 ourselves over a JSON subset that forbids non-integer numbers and
integers above 2^53-1. That keeps the canonical form trivially reproducible in other
languages and avoids float serialization edge cases. Golden vectors live in
`crates/ph-protocol/tests/vectors/`.

## ADR-003: Loopback TCP control endpoint instead of a Unix socket
The CLI talks to its own daemon over `127.0.0.1:<ephemeral>` and authenticates with a
256-bit token stored in `daemon.json` (0600). Unix socket paths are limited to about 104
bytes on macOS, which breaks deeply nested temp homes used in tests. The loopback design
also carries over to Windows later.

## ADR-004: Keystore backends
* `os` (macOS default): the OS keychain through the `keyring` crate.
* `file` (Linux default, and used by tests/demo): Argon2id key derivation plus
  XChaCha20-Poly1305 encrypted files, 0600, passphrase taken from
  `PEERHARNESS_PASSPHRASE` or an interactive prompt.
* `insecure-dev`: plaintext 0600 file, only with the explicit `--insecure-dev-keystore`
  flag, and it prints a warning on every unlock.

On Linux we do not depend on the D-Bus Secret Service by default, because it is often
missing on headless and CI machines.

## ADR-005: Strict YAML-subset frontmatter parser
Instead of a general YAML library (`serde_yaml` is deprecated, and general YAML allows
anchors, aliases and tags), `ph-skills` parses only the flat key/value plus one-level
`metadata` map subset that the Agent Skills spec needs. Anything else is rejected.

## ADR-006: Optional advisory agent providers
Following user direction, PeerHarness can use a developer's existing coding-agent CLI
(`claude -p`, `codex exec`) as an advisory provider. It spawns the user's unmodified
binary, which handles its own authentication, and never collects or proxies credentials.
Because this sends content to a remote service, it is off by default and requires config
opt-in plus a per-invocation exact preview. Its output is never an authorization input.
The deterministic detector remains the default, so the demo needs no subscription.

## ADR-007: Integration tests live in `apps/peerharness/tests`
Cargo only exposes `CARGO_BIN_EXE_peerharness` to tests in the binary's own package, so
the multi-process network tests live in `apps/peerharness/tests/`. Shared fixtures are in
`tests/fixtures/`.

## ADR-008: Explicit `proposal create`, `proposal release` and `proposal adopt` commands
The specification's CLI list has no command that creates a PROPOSAL or RELEASE, or that
imports a peer's released skill, so we add these three. The proposer must vote
explicitly; creating a proposal is not an implicit vote.

## ADR-009: rusqlite (bundled SQLite) rather than Turso/Limbo
We considered the Rust SQLite rewrite (`turso 0.9.0-pre.2`). We stay on `rusqlite` with
bundled SQLite for three reasons:
1. Turso is still pre-release, and our database holds security-relevant state (signed
   events, memberships, revocations).
2. Several processes (Claude Code hooks, CLI, daemon) write to one database file, and
   SQLite's WAL plus file locking is proven for that pattern.
3. Our write rate is tiny, so raw engine speed is not a bottleneck.
All access goes through `ph-store`, so switching engines later stays a contained change.
