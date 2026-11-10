#!/usr/bin/env bash
# Two independent PeerHarness nodes, two operating-system processes, talking over QUIC
# on loopback. Each node has its own key, its own database and its own skills
# directory, all inside a temporary directory that is removed at the end. Nothing in
# your home or in ~/.claude is read or changed, and nothing leaves this machine.
#
# Usage:  demo/two-peers.sh          (run it from your own terminal, not from inside a
#                                     coding agent: the steps that vote are refused there)
set -euo pipefail

if [ -n "${CLAUDECODE:-}${PEERHARNESS_AGENT_SESSION:-}" ]; then
  echo "This demo casts votes, and PeerHarness refuses to vote from inside a coding agent's" >&2
  echo "session. Run it from your own terminal." >&2
  exit 1
fi

cd "$(dirname "$0")/.."
cargo build --quiet -p peerharness
BIN="$PWD/target/debug/peerharness"

WORK="$(mktemp -d)"
DAEMON_PID=""
cleanup() {
  if [ -n "$DAEMON_PID" ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# Run a command as one of the two people.
alice() { USER=alice PEERHARNESS_HOME="$WORK/alice" PEERHARNESS_CLAUDE_SKILLS_DIR="$WORK/alice-skills" "$BIN" "$@"; }
bob()   { USER=bob   PEERHARNESS_HOME="$WORK/bob"   PEERHARNESS_CLAUDE_SKILLS_DIR="$WORK/bob-skills"   "$BIN" "$@"; }
# One string field of a command's --json output.
field() { sed -n "s/.*\"$1\": \"\\([^\"]*\\)\".*/\\1/p" | head -n 1; }
say() { printf '\n== %s\n' "$*"; }

say "Two nodes, each with its own key and database"
alice init --keystore insecure-dev --insecure-dev-keystore >/dev/null 2>&1
bob   init --keystore insecure-dev --insecure-dev-keystore >/dev/null 2>&1
echo "alice: $(alice --json status | field fingerprint)    bob: $(bob --json status | field fingerprint)"

say "Alice founds a circle and proposes admitting Bob (one member: her approval is the majority)"
FINGERPRINT="$(alice --json circle create team 2>/dev/null | field root_fingerprint)"
BOB_KEY="$(bob --json status | field device_key)"
alice circle invite "$BOB_KEY" --circle team --member bob --yes --out "$WORK/unused.jsonl" 2>/dev/null | sed -n '1,3p'

say "Alice's node starts listening (QUIC, loopback, a port the system picks)"
# The binary is started directly, not through the function above, so that the process id
# kept here is the daemon's own and stopping it leaves nothing behind.
USER=alice PEERHARNESS_HOME="$WORK/alice" PEERHARNESS_CLAUDE_SKILLS_DIR="$WORK/alice-skills" \
  "$BIN" daemon --listen /ip4/127.0.0.1/udp/0/quic-v1 >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 200); do [ -f "$WORK/alice/daemon.json" ] && break; sleep 0.05; done
ADDR="$(grep -o '/ip4[^"]*' "$WORK/alice/daemon.json" | head -n 1)"
echo "$ADDR"

say "Bob checks the root fingerprint and joins straight from Alice's node: he is on its roll now"
bob circle join "$ADDR" --expect-fingerprint "$FINGERPRINT" --yes --name team 2>/dev/null | grep -E '^Joined|^  charter'

say "Alice was corrected by her agent, writes the rule down and puts it to the vote"
CANDIDATE="$(alice --json note 'Use pnpm, not npm, in this repository.' | field candidate_id)"
PROPOSAL="$(alice --json proposal create "$CANDIDATE" --circle team --yes 2>/dev/null | field proposal_id)"
alice proposal vote "$PROPOSAL" approve --yes 2>/dev/null | sed -n 's/^Ballot recorded. //p'

say "Bob syncs with Alice's node, reads the exact text, and votes"
bob sync "$ADDR" | head -n 1
bob proposal show "$PROPOSAL" | sed -n '/^---$/,$p' | sed -n '1,9p'
bob proposal vote "$PROPOSAL" approve --yes 2>/dev/null | sed -n 's/^Ballot recorded. //p; /installed rule/p'

say "Bob syncs again: his ballot reaches Alice's node, which counts for itself and installs the rule"
bob sync "$ADDR" | head -n 1
alice rule list
echo "alice's agent: $(ls "$WORK/alice-skills")    bob's agent: $(ls "$WORK/bob-skills")"

say "A node that is not on the roll gets nothing"
mallory() { USER=mallory PEERHARNESS_HOME="$WORK/mallory" PEERHARNESS_CLAUDE_SKILLS_DIR="$WORK/mallory-skills" "$BIN" "$@"; }
mallory init --keystore insecure-dev --insecure-dev-keystore >/dev/null 2>&1
mallory sync "$ADDR" 2>&1 | sed 's/^/mallory: /' || true

printf '\nTwo independent AI harness nodes learned one shared rule. No server was involved.\n'
