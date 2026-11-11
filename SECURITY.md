# Security policy

PeerHarness handles signing keys, private circle data and text that people type to
their coding agents, so we take reports seriously. Please read this before reporting.

## Status

* **No security audit has been done.** PeerHarness is a demo-grade, pre-1.0 project
  with automated tests but no independent review. Do not rely on it for sensitive or
  production use.
* The threat model, including the limits we know about, is in
  [`docs/security-model.md`](docs/security-model.md). Limits documented there (for
  example that revocation cannot claw back delivered data, that redaction is heuristic,
  that a majority of a circle can pass any rule, or that the founder's key can stall
  changes to a circle's charter) are known design limits, not vulnerabilities, though we
  welcome ideas for improving them.

## Supported versions

Only the latest release receives security fixes. Before 1.0 we do not backport fixes to
older minor versions.

| version | supported |
|---|---|
| latest `0.x` release | yes |
| older releases | no |
| `main` branch | best effort |

## Reporting a vulnerability

**Please report vulnerabilities privately. Do not put the details of a vulnerability in
a public issue, pull request or discussion.**

Open an issue that says only that you have a security report and asks for a private
contact. Give no details in it: no description, no affected command and no steps to
reproduce. Wait for an answer there that gives a private contact, and send the details
through that.

When the repository's **Security** tab offers **Report a vulnerability**
(<https://github.com/aryehlev/peerharness/security/advisories/new>), use that form
instead of an issue. It creates a private advisory visible only to you and the
maintainers. The form is a setting of the repository and was not switched on when
this was written (2026-11-11).

Please include:

* the affected version or commit, and your platform;
* a description of the problem and its impact (for example: what an unauthenticated
  peer, a circle member, or a local user can do that they should not);
* steps to reproduce, ideally a minimal test case or a sequence of `peerharness`
  commands using temporary homes;
* any suggested fix.

Do not include real secrets, real private keys or real personal data in a report. Use
synthetic values.

## What to expect

PeerHarness is maintained on a best-effort basis; there is no service-level agreement
and no bug bounty. We aim to:

* acknowledge a report within 7 days;
* agree with you on an assessment and a fix plan;
* publish a fixed release and a GitHub security advisory, crediting you unless you
  prefer otherwise.

We ask that you give us a reasonable time to fix the issue (we suggest 90 days) before
disclosing it publicly, and that you do not access data that is not yours, degrade other
people's nodes, or test against circles you are not a member of.

## In scope

* The `peerharness` binary and the crates in this repository.
* Protocol v0 as specified in [`docs/protocol-v0.md`](docs/protocol-v0.md), including
  signature, canonicalization, authorization and parsing flaws.
* Voting and the charter: anything that lets a key that is not on the roll vote, a
  member count more than once, a proposal pass below its threshold, a result or an old
  ballot be reused for something it did not sign, the root key or anyone else change the
  roll or the voting rules without a passed vote, or a vote override one of the rights
  listed in section 10.10 of [`docs/architecture.md`](docs/architecture.md).
* Leaks of private data (prompts, observations, keys, circle metadata) through the
  network, logs, error messages or advisory providers.
* Skill bundle validation and installation (path traversal, symlinks, overwrite of
  unmanaged files), and any way a shared skill can pre-approve tools or make a coding
  agent run a command when it loads.
* The release workflow and published artifacts.

## Out of scope

* Vulnerabilities in third-party services (Claude Code, Codex, Ollama) themselves.
* Attacks that require an already compromised user account, operating system or coding
  agent (see the threat model).
* Denial of service through sheer network volume.
