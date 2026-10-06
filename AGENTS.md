# Working rules for coding agents in this repo

## Comments — zero by default

- A comment survives only in one of three earned categories, 3 lines hard max:
  a `///` contract on a `pub`/`pub(crate)` item (behavior, panics, units — not
  implementation); a `// SAFETY:` block where required; a constraint note the
  code cannot express, carrying its proof (issue link, upstream reference, or
  the specific hidden coupling).
- Everything else is deleted outright, never rewritten shorter: restating the
  next line, section banners, change narration, commented-out code,
  TODO/FIXME, docs on private items, essays.
- If a name, type, assertion, or test can carry the meaning, it replaces the
  comment.

## Tests — writing vs running

- Do not write tests unless explicitly asked in plain language. A failing
  tool result is a signal to fix code, not a request for tests.
- Never modify, weaken, skip, or delete an existing test to make it pass. If
  a test fails and you believe the test is wrong, stop and report the
  conflict — a human decides.
- After any change, run the tests covering the changed code, not the whole
  suite on every iteration.
- New tests assert behavior from intent, never re-state what the code does.

## Gates before handing work back

```
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all --all-features --locked
```

CI additionally builds a release binary and runs cargo-deny/cargo-audit on a
3-OS matrix (stable + MSRV 1.88); do not break `--locked` or touch
`Cargo.lock` without saying so.
