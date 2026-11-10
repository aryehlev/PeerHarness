# Changelog

What each version added, newest first. Versions follow
[Semantic Versioning](https://semver.org/). While the major version is 0, a minor
version may break the command line, the configuration file, the database schema or the
protocol ([docs/release.md](docs/release.md)). Each entry names the protocol version
the binary speaks ([docs/protocol-v0.md](docs/protocol-v0.md), section 15) and the
database schema it writes.

## Unreleased (0.4.0)

`main` carries version 0.4.0. It is not tagged.

* `peerharness keep <candidate>` saves a noted rule to your library and installs it for
  your own agent in one step, after showing the exact text and where it goes. It
  shares nothing. Inside an agent's session it can be asked in a window, under a
  setting of its own (`[agent] own_windows`): run `peerharness setup` again to allow
  it. The MCP server has a tool for it, `keep_rule`. A rule with a high-risk finding
  is refused by `keep` and stays with `review` and `skills install` (ADR-040).

Protocol `0.1` and database schema 4, as in 0.3.0.

## 0.3.0 (2026-11-10)

* `peerharness setup` does the owner's part in one command: it creates the node,
  connects Claude Code and registers the tools, each step shown first and confirmed.
  It is refused inside an agent's session (ADR-039).
* The flag of `watch claude --install` that allows confirmation windows is `--dialogs`.
  `--windows` still works.
* The install script names `peerharness setup` as the next step.

Protocol `0.1` and database schema 4, as in 0.2.0.

## 0.2.0 (2026-11-10)

* Inviting someone, a ballot on an admission and joining a circle can be asked in a
  window on macOS, under a setting of their own (`[agent] circle_windows`) (ADR-037).
* `peerharness mcp` gives an agent the steps it may start as tools of an MCP server.
  Every tool runs the command as a child process marked as an agent's session, so it
  adds no way to consent (ADR-038).
* `demo` no longer says that the QUIC transport is not wired into the command line.

Protocol `0.1` and database schema 4, as in 0.1.0.

## 0.1.0 (2026-11-10)

The first release.

* Voting under a signed charter: thresholds, a roll of members, proposals, ballots
  counted per member, results, amendments and repeal (ADR-012 to ADR-016).
* One person's loop: `note`, `review`, `skills install`, `uninstall` and `rollback`,
  and the Claude Code hooks and reporting skill (`watch claude`).
* A circle's life: `circle create`, `invite`, `join`, `remove`, `leave`, `amend`,
  `device`, `mode`, `place` and `revoke`, questions and answers, and opt-outs that can
  be put on record.
* Exchange of signed records by file, by shared directory (`events`), and directly
  over QUIC (`daemon`, `sync`, `connect`), with discovery on the local network
  (`--lan`) and by device key across the internet (`--internet`), both off unless
  asked for (ADR-031, ADR-032).
* Confirmation windows on macOS for three decisions about rules, started from inside
  an agent's session and answered only by a click (ADR-033).
* Being told that a vote waits: a line at the end of a turn in Claude Code, and
  `daemon --notify` on macOS (ADR-035, ADR-036).
* `install.sh`, which installs a release after checking it against `SHA256SUMS`
  (ADR-034), and `peerharness demo`.

Protocol `0.1` (wire protocol `/peerharness/req/0.1.0`, schemas `*/0.1`). Database
schema 4. The schema's migrations only go forward.
