# Release process

This is how PeerHarness releases are versioned, built, published and verified. The
automation is `.github/workflows/release.yml`; CI for every push and pull request is
`.github/workflows/ci.yml`.

## Versioning

PeerHarness follows [Semantic Versioning 2.0.0](https://semver.org/).

* The version lives in one place: `[workspace.package] version` in the root
  `Cargo.toml`. Every crate and the `peerharness` binary share it.
* Tags are `v<version>`, for example `v0.1.0` or `v0.2.0-rc.1`. The release workflow
  refuses a tag that does not match the `peerharness` package version.
* A tag with a pre-release suffix (anything containing `-`) is published as a GitHub
  pre-release.
* While the major version is 0, a minor bump (0.1 to 0.2) may contain breaking changes to
  the CLI, the config file, the database schema or the protocol. Patch releases (0.1.0 to
  0.1.1) contain only fixes and never change the protocol or migrate the database in an
  incompatible way.
* The protocol has its own version, independent of the binary's
  (`docs/protocol-v0.md`, section 15). Release notes say which protocol versions a
  release speaks and whether its database migration is one-way.

## Supported platforms

| target | runner | notes |
|---|---|---|
| `x86_64-unknown-linux-musl` | `ubuntu-24.04` via [cross](https://github.com/cross-rs/cross) | static binary |
| `aarch64-unknown-linux-musl` | `ubuntu-24.04` via cross | static binary |
| `x86_64-apple-darwin` | `macos-15` (Apple Silicon), cross-compiled with Apple clang | |
| `aarch64-apple-darwin` | `macos-15` | |

**Linux binaries are static musl builds.** They have no glibc version requirement and
run on any reasonably recent x86_64 or aarch64 Linux kernel. They are built with `cross`
because the dependency tree compiles C code (the `aws-lc-sys` and `ring` crypto
libraries used by libp2p's QUIC/TLS stack, and the bundled SQLite) and needs a musl C
toolchain that also has Linux kernel headers. Ubuntu's `musl-gcc` wrapper does not
expose kernel headers (`aws-lc` includes `<linux/random.h>`), which is why the workflow
does not use it. If a future dependency makes the musl build infeasible, the fallback is
`*-unknown-linux-gnu` built on the oldest supported Ubuntu runner, documented here with
the minimum glibc version.

**Windows is not supported yet**, and no Windows binaries are published. The code has
not been built or tested on Windows.

## What a release contains

For each target, `peerharness-<tag>-<target>.tar.gz` containing:

* `peerharness-<tag>-<target>/peerharness` (the binary),
* `LICENSE-MIT`, `LICENSE-APACHE`,
* `README.md`, `security-model.md` and `release.md` when present.

Plus one `SHA256SUMS` file covering every archive, and auto-generated release notes.

## What is not provided

* **No code signing.** Binaries are not signed with any key or certificate.
* **No macOS notarization.** Gatekeeper will treat the downloaded binary as coming from
  an unidentified developer (see "macOS quarantine" below).
* **No Windows binaries.** Windows is not supported.
* **No signed checksums or provenance attestations.** `SHA256SUMS` is produced by the
  same workflow that builds the binaries. It detects corrupted or swapped downloads, but
  not a compromise of the repository, the CI pipeline or the GitHub account.
* **No package-manager packages** (Homebrew, apt, crates.io) yet.
* **No security audit.** See `docs/security-model.md`.

## How a release is built

The workflow runs on a pushed `v*` tag (a manual run skips the version check and does only step 2):

1. **check-version**: compares the tag with the `peerharness` version from
   `cargo metadata --locked --no-deps`; a mismatch stops the release.
2. **build** (matrix, one job per target):
   * installs the pinned release toolchain (`RELEASE_TOOLCHAIN`, currently `1.89.0`,
     the workspace MSRV) with the target;
   * sets `SOURCE_DATE_EPOCH` to the tagged commit's timestamp and, for native macOS
     builds, `--remap-path-prefix` flags that strip the build machine's paths;
   * builds exactly
     `cargo build --locked --release --target <target> -p peerharness`
     (`cross build` with the same arguments on Linux). `--locked` makes the build fail
     if `Cargo.lock` is out of date, so the published binary uses exactly the committed
     dependency versions. The release profile uses thin LTO, one codegen unit and strips
     symbols;
   * packages the archive deterministically: GNU tar with sorted names, mtime
     `SOURCE_DATE_EPOCH`, owner and group 0, then `gzip -n` (no name or timestamp);
   * uploads the archive as a workflow artifact.
3. **release**: downloads all archives, writes
   `SHA256SUMS` with `sha256sum peerharness-*.tar.gz`, checks it, and creates the GitHub
   release with `softprops/action-gh-release`, attaching the archives and `SHA256SUMS`.

All third-party actions are pinned to a major version (`@v1`, `@v2`, `@v4`).

### Reproducibility

The inputs of a release are fixed: the tagged commit, `Cargo.lock`, the pinned Rust
toolchain, the pinned `cross` version (and its container images), and the runner images.
Archive packaging is deterministic. Bit-for-bit identical binaries across machines are
**not** guaranteed yet: runner images, the C toolchains used by `aws-lc-sys`, `ring` and
SQLite, and paths inside the cross containers can differ between rebuilds. To rebuild a
release yourself:

```sh
git clone https://github.com/aryehlev/peerharness
cd peerharness
git checkout v0.1.0
rustup toolchain install 1.89.0 --target aarch64-apple-darwin   # your target
cargo +1.89.0 build --locked --release --target aarch64-apple-darwin -p peerharness
./target/aarch64-apple-darwin/release/peerharness --help
```

For Linux musl targets, install `cross` 0.2.5 (`cargo install cross --version 0.2.5
--locked`) and run `cross build` with the same arguments; it needs Docker or Podman.

## Cutting a release (maintainers)

1. Make sure `main` is green in CI (fmt, clippy, tests on Linux and macOS, MSRV,
   cargo-deny, cargo-audit). Before the first release, and after any change to the
   release workflow or to native dependencies, run the Release workflow manually
   (**Actions > Release > Run workflow**). A manual run builds every target and uploads
   the archives as workflow artifacts named `peerharness-dev-<commit>-<target>`, but
   publishes nothing. Before a release is announced, check that private vulnerability
   reporting is switched on for the repository (**Settings > Code security**):
   `gh api repos/aryehlev/peerharness/private-vulnerability-reporting` prints
   `{"enabled":true}` when it is. `SECURITY.md` and `CODE_OF_CONDUCT.md` name that
   form, and `SECURITY.md` says that it was off when it was written: correct that
   sentence once it is on.
2. Update the version in the root `Cargo.toml` (`[workspace.package] version` and the
   `version` of the internal path dependencies under `[workspace.dependencies]`), run
   `cargo build` so `Cargo.lock` is updated, and commit both.
3. Update `README.md` in the same pull request, every time. Its status line names the
   version being released. While that version is not released, the status block also
   says which version the install line installs and what is missing from it: take
   that note out in this pull request. Read "What works today", `docs/checked.md` and
   "Known limits" again against what this release contains, and check each command
   the README shows against the binary. The README is packed into every archive, so
   what is tagged is what people read. `docs/checked.md` is not packed: the archive's
   README links to it.
4. Note in the release notes draft: user-visible changes, protocol version, database
   migrations, and any change to `RELEASE_TOOLCHAIN`. Move the "Unreleased" entries of
   `CHANGELOG.md` under the new version in the same pull request.
5. Tag and push:

   ```sh
   git tag -a v0.1.0 -m "PeerHarness v0.1.0"
   git push origin v0.1.0
   ```

6. Watch the Release workflow. When it finishes, download one archive and verify it as
   below before announcing the release. Then run the install script once on a clean
   machine or with `PEERHARNESS_INSTALL_DIR=$(mktemp -d)`: it only works for a
   published release of a public repository.
7. Say what was checked on the published release, and what was not: in the README
   ("What works today") and in `docs/checked.md` (the row about the install script
   and the release binaries). Open that pull request right away: it is part of the
   release, not a follow-up.
8. If a build job fails, fix the problem on `main`, delete the tag locally and on GitHub,
   and tag again. Never replace the assets of a published release; publish a new patch
   version instead.

## The install script

`install.sh` in the repository root does the download, the check and the copy below in
one step:

```sh
curl -fsSL https://raw.githubusercontent.com/aryehlev/peerharness/main/install.sh | sh
```

It finds the latest release (or takes `PEERHARNESS_VERSION=v0.1.0`), downloads the
archive for the machine and `SHA256SUMS` over HTTPS, stops unless the archive matches
its checksum, checks that the binary runs, and copies that one file to `~/.local/bin`
(or `PEERHARNESS_INSTALL_DIR`). It uses no `sudo`, edits no shell profile and tells you
if the directory is not on your `PATH`. Pre-releases are not "latest": name them with
`PEERHARNESS_VERSION`.

What it proves is what the manual check below proves, and no more: the file is the one
the release workflow published. The script itself comes from the `main` branch over
HTTPS and is not signed either, so running it trusts this repository the same way
downloading its binary does. To read it first:

```sh
curl -fsSL https://raw.githubusercontent.com/aryehlev/peerharness/main/install.sh -o install.sh
less install.sh
sh install.sh
```

`apps/peerharness/tests/install_script.rs` runs the script against a release in a
temporary folder. Finding the latest release relies on GitHub's redirect and is not
covered by that test.

## Verifying a download

Download the archive for your platform and `SHA256SUMS` from the same release page.

Linux:

```sh
sha256sum --ignore-missing -c SHA256SUMS
# peerharness-v0.1.0-x86_64-unknown-linux-musl.tar.gz: OK
```

macOS:

```sh
grep ' peerharness-v0.1.0-aarch64-apple-darwin.tar.gz$' SHA256SUMS | shasum -a 256 -c -
# peerharness-v0.1.0-aarch64-apple-darwin.tar.gz: OK
```

Only continue when the check prints `OK`. Then unpack and install:

```sh
tar -xzf peerharness-v0.1.0-aarch64-apple-darwin.tar.gz
install -m 0755 peerharness-v0.1.0-aarch64-apple-darwin/peerharness ~/.local/bin/peerharness
```

A matching checksum shows that you have the file the release workflow published. It does
not show that the workflow, the repository or the dependencies were trustworthy (see
"What is not provided").

### macOS quarantine

Because the binary is not notarized, macOS may refuse to run a file downloaded with a
browser ("cannot be opened because the developer cannot be verified"). After verifying
the checksum, you can remove the quarantine attribute from that one file:

```sh
xattr -d com.apple.quarantine ~/.local/bin/peerharness
```

Files downloaded with `curl` are usually not quarantined. Building from source avoids the
issue entirely.
