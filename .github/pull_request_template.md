## What changed, and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checks

Paste what each command printed, or say plainly that you did not run it.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo test --workspace --locked`

## Tests and docs

- [ ] Tests cover the change. Security behaviour has a negative test that shows the bad input being rejected.
- [ ] README, `docs/` and `CHANGELOG.md` say what the code now does, and a decision or a deviation has an ADR in `docs/decisions.md`.
- [ ] No invariant in `AGENTS.md` was loosened.

## Not done, and known limits

<!-- What this change leaves out, and anything you did not test. -->
