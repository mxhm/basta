# Changelog

All notable changes to basta are documented here. Versions follow SemVer; basta is pre-1.0.

## [0.1.0] — 2026-06

First public release. A rootless Linux sandbox for running coding agents as your
own user in a fresh tmpfs `$HOME`, with per-launch, kernel-enforced egress
filtering — bubblewrap + nftables-in-netns + pasta + seccomp, no daemon and no
privileged code path. Static x86_64 musl binary attached.

- **Workspaces** — read-write / read-only positional binds (fd-pinned); tmpfs `$HOME` with `--seed` / `--persist`.
- **Egress** — offline by default; `--allow` (IP/CIDR/port), `--allow-sni` (TLS-SNI, no termination), `--allow-loopback`; loopback and cloud-metadata refused.
- **Workspace lock** (default on) — git internals plus `.envrc`, `.vscode`, `.idea`, `.claude`, `.mcp.json` read-only.
- **seccomp** denylist; `--allow-syscall` / `--deny-syscall` / `--no-seccomp`.
- **GPU** off by default (`--gpu` binds `/dev/nvidia*`).
- **`basta-host-setup`** — multi-distro (apt/dnf/pacman/zypper/apk) with userns-gate detection.
- MIT licensed; provided as-is, no warranty.

Verified on Ubuntu 22.04 / 24.04 / 26.04, Debian 12, and Fedora 43 (incl. SELinux
enforcing). Agent recipes (Claude Code, Codex, Antigravity, local models) in
[docs/agent-recipes.md](docs/agent-recipes.md).
