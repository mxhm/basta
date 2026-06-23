# Contributing to basta

A small, security-sensitive Rust + Bash project; the bar is correctness and a
minimal, auditable surface. Shared as-is — contributions welcome, no guarantees.

## Build & test

Linux-only, static musl binary (no macOS/Windows build):

```
rustup target add x86_64-unknown-linux-musl   # rustc 1.85+ (edition 2024)
make build        # release build — no sudo
make test         # cargo test
make lint         # clippy -D warnings + shellcheck
```

`make test` / `make lint` run on any Linux. For the real sandbox checks:
`make install && basta-host-setup && basta-verify` — needs working unprivileged user
namespaces (not all CI runners qualify).

## Pull requests

- Keep it minimal — match surrounding style; delete dead code, don't rename it.
- Run `make lint` and `make test` first (clippy warning-clean); add or update a
  test for any behavior change.
- Security-sensitive paths (`egress.rs`, `seccomp.rs`, `argv.rs`, `netns.rs`,
  `lockset.rs`, `workspace.rs`) get extra scrutiny — explain the threat-model
  impact of changes to binds, the egress filter, the seccomp denylist, or the lock.
- A new host-autorun vector goes in the `DEFAULT_LOCK` table in `lockset.rs`
  (one row + reason). `basta-host-setup` changes keep the package-manager dispatch
  and userns-gate mechanisms intact.

Ordinary bugs → issue. Suspected sandbox escapes / egress bypasses → report
privately ([SECURITY.md](SECURITY.md)).

By contributing you agree to license your contribution under MIT.
