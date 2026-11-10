#!/bin/sh
# Installs the PeerHarness binary.
#
#   curl -fsSL https://raw.githubusercontent.com/aryehlev/peerharness/main/install.sh | sh
#
# What it does: finds the latest release, downloads the archive for this machine and the
# release's SHA256SUMS, stops unless the archive matches its checksum, checks that the
# binary runs, and copies that one file to ~/.local/bin. It does not use sudo, edits no
# shell profile and changes nothing else.
#
# A matching checksum shows that the file is the one the release workflow published. It
# is not a signature: see docs/release.md for what a release does and does not prove.
#
# Settings, as environment variables:
#   PEERHARNESS_VERSION      the release to install, for example v0.1.0 (default: latest)
#   PEERHARNESS_INSTALL_DIR  where the binary goes (default: ~/.local/bin)
#   PEERHARNESS_RELEASE_URL  where the releases are (default: this repository's GitHub
#                            releases). For a mirror, and for this script's own test.

set -eu

REPO="aryehlev/peerharness"
SOURCE="cargo install --locked --git https://github.com/${REPO} peerharness"

say() {
    printf '%s\n' "$*"
}

fail() {
    printf 'install.sh: %s\n' "$*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || fail "this script needs \`$1\`, which was not found"
}

# download <address> <curl options>: curl, held to HTTPS for every address that is one.
download() {
    case "$1" in
        https://*) curl --proto '=https' --tlsv1.2 -fsSL "$@" ;;
        *) curl -fsSL "$@" ;;
    esac
}

# The release target for this machine, as the release workflow names it.
target() {
    os=$(uname -s)
    arch=$(uname -m)
    case "$arch" in
        x86_64 | amd64) arch=x86_64 ;;
        arm64 | aarch64) arch=aarch64 ;;
        *) fail "there is no release binary for the processor \"$arch\". Build from source: $SOURCE" ;;
    esac
    case "$os" in
        Darwin)
            # A shell running under Rosetta reports x86_64 on an Apple Silicon Mac.
            if [ "$arch" = x86_64 ] &&
                [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
                arch=aarch64
            fi
            say "${arch}-apple-darwin"
            ;;
        Linux) say "${arch}-unknown-linux-musl" ;;
        *) fail "there is no release binary for \"$os\". Build from source: $SOURCE" ;;
    esac
}

# The tag of the latest release. GitHub answers /releases/latest with a redirect to
# /releases/tag/<tag>, or to the list of releases when there is none.
latest() {
    url=$(download "$1/latest" -o /dev/null -w '%{url_effective}' 2>/dev/null) || return 1
    case "$url" in
        */releases/tag/?*) say "${url##*/}" ;;
        *) return 1 ;;
    esac
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d ' ' -f 1
    else
        fail "this script needs \`sha256sum\` or \`shasum\` to check the download"
    fi
}

main() {
    need curl
    need tar
    need uname
    need mktemp

    releases=${PEERHARNESS_RELEASE_URL:-"https://github.com/${REPO}/releases"}
    dir=${PEERHARNESS_INSTALL_DIR:-"${HOME:?HOME is not set: set PEERHARNESS_INSTALL_DIR}/.local/bin"}
    target=$(target)

    version=${PEERHARNESS_VERSION:-}
    if [ -z "$version" ]; then
        version=$(latest "$releases") || fail "no release has been published yet. Build from source: $SOURCE"
    fi
    # A tag of this project: v, a digit, then only letters, digits, dots, plus and minus.
    case "$version" in
        v[0-9]*) ;;
        *) fail "\"$version\" is not a release tag such as v0.1.0" ;;
    esac
    case "$version" in
        *[!0-9A-Za-z.+-]*) fail "\"$version\" is not a release tag such as v0.1.0" ;;
    esac

    name="peerharness-${version}-${target}"
    archive="${name}.tar.gz"
    tmp=$(mktemp -d 2>/dev/null || mktemp -d -t peerharness)
    trap 'rm -rf "$tmp"' EXIT
    trap 'exit 1' INT TERM

    say "Downloading PeerHarness ${version} for ${target}"
    download "$releases/download/$version/$archive" -o "$tmp/$archive" ||
        fail "could not download $archive from the release $version"
    download "$releases/download/$version/SHA256SUMS" -o "$tmp/SHA256SUMS" ||
        fail "could not download SHA256SUMS of the release $version"

    # Nothing is unpacked or installed before the archive matches the published checksum.
    expected=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/SHA256SUMS")
    [ "${#expected}" -eq 64 ] || fail "SHA256SUMS of $version has no checksum for $archive"
    actual=$(sha256 "$tmp/$archive")
    [ "$actual" = "$expected" ] ||
        fail "the checksum of $archive does not match SHA256SUMS. Nothing was installed."
    say "Checksum matches SHA256SUMS"

    tar -xzf "$tmp/$archive" -C "$tmp"
    binary="$tmp/$name/peerharness"
    if [ ! -f "$binary" ] || [ -L "$binary" ]; then
        fail "$archive does not hold the peerharness binary"
    fi
    chmod 755 "$binary"
    # It has to run here before it replaces anything.
    installed=$("$binary" --version) || fail "the downloaded binary does not run on this machine"

    mkdir -p "$dir"
    cp "$binary" "$dir/.peerharness.new.$$"
    chmod 755 "$dir/.peerharness.new.$$"
    mv -f "$dir/.peerharness.new.$$" "$dir/peerharness"

    say "Installed $installed at $dir/peerharness"
    case ":${PATH:-}:" in
        *":$dir:"*) ;;
        *)
            say ""
            say "$dir is not on your PATH. Add it, for example in ~/.zshrc or ~/.bashrc:"
            say "  export PATH=\"$dir:\$PATH\""
            ;;
    esac
    say ""
    say "Next:"
    say "  peerharness demo    three members vote on a rule, in temporary folders"
    say "  peerharness init    create your own node"
}

# The whole script is read before anything runs, so a download that was cut short
# does nothing.
main "$@"
