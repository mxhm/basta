# Changelog

All notable changes to basta are documented here. Versions follow SemVer; basta is pre-1.0.

## [0.1.2] — 2026-07

- **Workspaces** — a workspace at `$HOME` is refused: workspaces are bound last,
  so it would mask the sandbox's own tmpfs `$HOME`. A read-write workspace
  containing an earlier `:ro` one is refused too; `/tmp`, `/var/tmp` and `/run`
  warn. `$HOME` itself is validated before it is used as a mount destination.
- **`--publish PORT`** — forward host `127.0.0.1:PORT` into the sandbox so a host
  browser can reach a web UI served inside. One port, host loopback only; egress
  stays gated by `--allow*`. A published port is unauthenticated to every local
  user — see README "Security model".
- **Diagnostics** — a `pasta` startup failure now reports its actual error
  instead of a downstream "no default route in the sandbox netns".
- **basta-verify** — probe that `--publish` reaches the sandbox on host loopback
  and nowhere else.
- **Docs** — document `--publish`; add an OpenScience recipe; `make lint` now
  runs `cargo fmt --check`, matching CI.

## [0.1.1] — 2026-06

- **AppArmor** — the `bwrap` profile attaches to every path `find_bin` resolves
  bwrap from, not just `/usr/bin/bwrap`, so a non-standard bwrap install is no
  longer left unconfined (which broke userns creation under the Ubuntu gate).
- **basta-host-setup** — `pacman -S` instead of `pacman -Sy` (partial-upgrade
  hazard).
- **basta-verify** — probe that the installed bwrap profile covers the resolved
  bwrap path.
- **Docs** — describe the always-read-only `/usr` and `/etc` host surface; note
  `ptrace`/`perf_event_open` are on by default and how to drop them; note
  basta-verify is not hermetic and the workspace-lock exit warning is advisory.

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
