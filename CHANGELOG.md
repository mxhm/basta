# Changelog

All notable changes to basta are documented here. Versions follow SemVer; basta is pre-1.0.

## [0.1.1] — 2026-06

- **AppArmor** — the `bwrap` profile attaches to every path `find_bin` resolves
  bwrap from, not just `/usr/bin/bwrap`, so a non-standard bwrap install is not
  left unconfined (which fails userns creation under the Ubuntu userns gate).
- **basta-host-setup** — use `pacman -S` instead of `pacman -Sy` (partial-upgrade
  hazard), with a hint to run `pacman -Syu` if a package is missing.
- **basta-verify** — probe that the installed bwrap profile covers the resolved
  bwrap path.
- **Docs** — describe the always-read-only `/usr` and `/etc` host surface and what
  `/etc` exposes; note `ptrace`/`perf_event_open` are kept by default and how to
  drop them; note basta-verify is not hermetic; clarify the workspace-lock exit
  warning is advisory.

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
