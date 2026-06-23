# basta

A rootless sandbox for running coding agents on Linux. The agent runs as your
own user in a fresh tmpfs `$HOME`, with network egress filtered per launch.

basta = [bubblewrap](https://github.com/containers/bubblewrap) + [pasta](https://passt.top). Also Italian for "that's enough."

Linux only. Tested on Ubuntu 24.04 (also 22.04 and 26.04) and Arch, running the
full sandbox/egress/seccomp probe suite. Also runs on Debian 12 and Fedora 43
(SELinux enforcing).

    basta [OPTIONS] [WORKSPACE...] -- COMMAND [ARGS...]

Run Claude Code in the current directory, allowed to reach only the Anthropic API:

    basta --allow-sni api.anthropic.com -- claude

More agents (Codex, Antigravity, local models): [docs/agent-recipes.md](docs/agent-recipes.md).

## What basta is for

basta sets a coding agent's permissions *before* you start it: which
directories it can read or write, which network destinations it can reach, and
nothing else. The policy is the set of flags passed at launch; there's no daemon
or config file. Isolation is kernel-enforced (user + mount namespaces,
an nftables egress filter, seccomp). Nothing persists on the host.

Prompt injection turns dangerous when an agent has all three of [Simon Willison's
lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/):
private data, untrusted content, and external communication. You can't stop an
LLM from following buried instructions, so basta controls the other two legs: a
fresh tmpfs `$HOME` and explicit binds decide what it reads; offline-by-default
egress decides where it connects.

The agent runs as your own user against plain read-write / read-only mounts, with
no nested per-tool sandbox to fight, and the kernel enforces the limits.
The tradeoff: basta fixes the boundary at launch rather than vetting each action
inside it. A few things are caught by watch-and-warn rather than blocked up
front (see [Security model](#security-model)).

First public release: self-reviewed, not independently audited.

I built basta mainly to understand agent sandboxes and my own needs. Once set
up, [nono](https://github.com/always-further/nono) and
[srt](https://github.com/anthropic-experimental/sandbox-runtime) are very close
and easier to install. nono in particular needs no dependencies or sudo, with
finer-grained egress rules. basta starts more locked down (allowlists rather
than denylists) and uses namespaces, so it also runs on older kernels.

## Related tools

Other tools that sandbox coding agents or processes:

- [Anthropic sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
  (`srt`): Linux (bubblewrap) and macOS (Seatbelt). Egress via a host-side
  proxy with a domain allowlist.
- [nono](https://github.com/always-further/nono): rootless, kernel-enforced via
  Landlock (Linux) / Seatbelt (macOS). Cross-platform, no daemon or VM. Blocks
  credential paths by default.
- [fence](https://github.com/fencesandbox/fence): rootless, container-free.
  Seatbelt (macOS) / bubblewrap (Linux). Network blocked by default, plus
  filesystem and command restrictions.
- [OpenAI Codex sandbox](https://developers.openai.com/codex/concepts/sandboxing):
  Landlock + seccomp on Linux, Seatbelt on macOS. On by default for the
  Codex CLI. Egress off by default, via a loopback HTTP/SOCKS proxy.
- [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) (`sbx`):
  hardware-virtualized microVMs per agent (stronger boundary, needs KVM). A
  TLS-intercepting proxy with a domain allowlist and credential injection.
- [microsandbox](https://github.com/microsandbox/microsandbox): rootless
  microVMs via libkrun (needs KVM). Domain/IP egress allowlist with secret
  substitution.
- [firejail](https://github.com/netblue30/firejail) /
  [bubblejail](https://github.com/igo95862/bubblejail): general desktop
  application sandboxes (firejail is SUID-root; bubblejail is bubblewrap).

basta's egress is an in-kernel nftables filter in the sandbox's own network
namespace: IP/CIDR/port plus TLS-SNI, rather than a userspace proxy or a
domain-name allowlist.

## Install

### Prebuilt binary (no toolchain)

Static x86_64 musl build, no runtime dependencies:

    curl -fsSL https://github.com/mxhm/basta/releases/latest/download/basta-x86_64-linux-musl.tar.gz | tar xz
    cd basta-*-x86_64-linux-musl
    install -Dm755 basta basta-host-setup basta-verify -t ~/.local/bin
    install -Dm644 share/apparmor.* -t ~/.local/share/basta
    basta-host-setup          # one-time host config (prompts for sudo)
    basta-verify              # expect: ALL PROBES PASSED

(Needs `~/.local/bin` on your `PATH`.)

### From source

    git clone https://github.com/mxhm/basta ~/basta && cd ~/basta
    rustup target add x86_64-unknown-linux-musl   # basta builds a static musl binary
    make build              # compile basta (no sudo)
    make install            # install to ~/.local
    basta-host-setup          # one-time host config (script prompts for sudo)
    basta-verify              # expect: ALL PROBES PASSED

`make install` writes to `~/.local/{bin,share/basta}`, no sudo needed. Only
`basta-host-setup` needs root. It installs `bubblewrap`, `nftables`, `passt` via
your package manager (apt / dnf / pacman / zypper / apk). On Ubuntu 24.04+ it
also installs the AppArmor profiles that `basta` and `bwrap` need, since that
release restricts unprivileged user namespaces by default (see
[LP #2046844](https://bugs.launchpad.net/ubuntu/+source/bubblewrap/+bug/2046844)).
It self-elevates with `sudo`.

### Manual host setup (skipping basta-host-setup)

`basta-host-setup` just wraps two root steps; run them yourself if you prefer:

1. **Packages:** `sudo apt-get install -y bubblewrap nftables passt` (same names on dnf / pacman / zypper / apk).
2. **Unprivileged user-namespace gate**, only where the kernel restricts it. On Ubuntu 24.04+ (AppArmor) load the two profiles `make install` placed in `~/.local/share/basta`:

       sudo install -m 0644 ~/.local/share/basta/apparmor.bwrap /etc/apparmor.d/bwrap
       sudo install -m 0644 ~/.local/share/basta/apparmor.basta /etc/apparmor.d/basta
       sudo apparmor_parser -r /etc/apparmor.d/{bwrap,basta}

   Debian / RHEL / Fedora gate it with a sysctl instead (usually already on; SELinux needs no profile). Confirm with `unshare --user --map-root-user true`.

Provisioned once, end users need no root: just `make install` + `basta-verify`.
System-wide install: `PREFIX=/usr/local sudo make install`. Agents are installed
host-side (e.g. via mise); basta RO-binds `~/.local/bin` and `~/.local/share/mise`
onto the sandbox PATH.

## Usage

**Workspaces** are positional: `PATH` binds read-write, `PATH:ro`
read-only; the first read-write one is the working directory (default
`$PWD`). Each is mounted at the same path inside the sandbox. A workspace's
canonical path (symlinks and `..` resolved) must fall under an allowed root
(`$HOME:/tmp:/mnt` by default). Set `BASTA_ALLOWED_ROOTS` (a `:`-separated list
that replaces the default) to permit other locations.

**`$HOME`** is a fresh tmpfs every run. `--seed SRC:DEST` copies a host
path in (discarded on exit); `--persist SRC:DEST` RW-binds
one (survives across runs). `DEST` resolves under `$HOME`.

### Options

| Flag | Meaning |
|---|---|
| `--allow HOST:PORT[-PORT][/tcp\|udp]` | Allow egress to an IP, CIDR, or DNS name; refuses unsafe forms (see [Network](#network)). Comma-separated, repeatable. |
| `--allow-sni HOST` | Allow TLS egress to `HOST:443` by ClientHello SNI. Comma-separated, repeatable. |
| `--allow-loopback PORT` | Allow the sandbox to reach a host service at `127.0.0.1:PORT`. Comma-separated, repeatable. |
| `--net none\|host` | `none` (default, offline) or `host` (no isolation). |
| `--seed SRC:DEST` | Copy a host path into `$HOME`; ephemeral. |
| `--persist SRC:DEST` | RW-bind a host path into `$HOME`; survives. |
| `--env KEY[=VAL]` | Set, or pass through, an environment variable. |
| `--gpu` | Bind `/dev/nvidia*` into the sandbox (off by default). |
| `--expose-local-share` | RO-bind all of `~/.local/share` (default: only the mise tool tree). |
| `--allow-syscall SYSCALL` | Un-block a syscall from the agent seccomp denylist. Comma-separated, repeatable. |
| `--deny-syscall SYSCALL` | Add a syscall to the seccomp denylist. Comma-separated, repeatable. |
| `--no-seccomp` | Disable the agent seccomp filter. |
| `--lock PATH` | Make a workspace-relative PATH read-only, on top of the default lock set. Comma-separated, repeatable. |
| `--unlock PATH` | Remove a PATH from the lock set, including a default (e.g. `--unlock .claude`). Comma-separated, repeatable. |
| `--no-lock` | Disable the default lock set (git internals + the IDE / agent-config autorun set). |
| `--lock-strict` | Exit non-zero (3) if the agent created a watched autorun file (e.g. a new `.envrc`) that couldn't be pre-blocked. Default: warn only. |
| `--dry-run` | Print the launch plan (bwrap argv + seccomp summary) and exit. |
| `--trace` | Print the launch plan to stderr, then run. |

## Network

The sandbox is offline by default. Egress is opt-in and scoped to one
launch:

- **`--allow`**: filter by IP / CIDR / port. A DNS name is resolved once
  at launch and pinned into `/etc/hosts`. For IP-stable destinations.
  **Refused:** a DNS name on TCP :443 (CDN edge IPs an IP-rule would
  over-authorise; use `--allow-sni`), loopback (use `--allow-loopback`),
  link-local/metadata (`169.254/16`), and a DNS name resolving into private
  space (SSRF; a literal private IP is allowed as intent).
- **`--allow-sni`**: filter by TLS SNI. An in-`basta` proxy joins the
  sandbox network namespace, redirects `:443`, reads the ClientHello,
  exact-matches the allowlist, and splices to the launch-resolved IP. No
  TLS termination. For CDN-fronted APIs that share IPs.
- **`--allow-loopback`**: reach a local model server on *this* machine
  (llama.cpp, vLLM). Always this flag, never `--allow`: the sandbox's netns carries
  the host's own addresses, so a same-machine service is only reachable by
  forwarding `127.0.0.1:PORT` to the host's. This is a broad grant: the agent gets
  whatever that (often unauthenticated) port exposes. (Different host → `--allow <ip>:PORT`.)
- **`--net host`**: share the host network; no isolation, no egress filtering.
  A last resort, not the fix for a local model (use `--allow-loopback`).

The filter is nftables loaded inside the sandbox's own network namespace,
owned by an outer user namespace. The agent cannot modify it.

`--allow-sni` caveats: the SNI is asserted by the (possibly compromised)
client; security reduces to launch-time DNS trust; IPv6 `:443` and
UDP/443 (QUIC) are dropped; TLS 1.3 0-RTT early data pipelined after the
ClientHello is rejected; pairing it with `--allow <resolver>:53/udp`
reopens a DNS exfiltration channel.

## Secrets

An agent's API key is visible inside the sandbox (`--env`'d in, or from a
post-start login into the tmpfs `$HOME`). basta scopes where it can be *sent*, not
whether it's readable, and doesn't broker or hide secrets. `--allow-sni
api.anthropic.com` limits egress to that endpoint, subject to its caveats above.

## Examples

Flag patterns. Complete, runnable per-agent commands (auth seeding + every
endpoint) are in [agent-recipes.md](docs/agent-recipes.md).

    # Read-write code + a read-only dataset, served by a local model on
    # this machine (e.g. llama.cpp llama-server on :8080; PATH = rw, PATH:ro = ro)
    basta --allow-loopback 8080 ~/proj /path/to/data:ro -- pi -p "<task>"

    # Model on another LAN host, current dir as rw working dir
    basta --allow 192.168.1.10:8000 -- omp

    # Seed auth in (ephemeral), keep a cache across runs (persists)
    basta --allow-sni api.openai.com \
        --seed ~/.codex/auth.json:.codex/auth.json \
        --persist ~/.basta-cache:.cache \
        ~/proj -- codex

    # Unlock a default lock target so the agent can write it
    basta --allow-sni api.anthropic.com --unlock .claude -- claude

### Wrap it in a function

Bake your policy in once (model endpoint, seeds, the persisted state dir), then
use the wrapper like the bare CLI. Leading `PATH` args are extra workspaces
(`PATH` rw, `PATH:ro` ro); the first flag (or `--`) hands the rest to the agent,
so `wpi --resume`, `wpi -p "…"`, and `wpi /data:ro -p "…"` all work as usual.

    # ~/.zshrc: pi under basta, local model + persisted sessions.
    wpi() {
      local -a ws args; local sep=0
      for a in "$@"; do
        if [[ $sep -eq 0 && $a == "--" ]]; then sep=1; continue; fi
        if [[ $sep -eq 0 && $a == -* ]]; then sep=1; fi
        if [[ $sep -eq 0 ]]; then ws+=("$a"); else args+=("$a"); fi
      done
      basta --allow-loopback 8000 \
        --seed ~/.config/pi:.config/pi \
        --persist ~/.pi/sessions:.pi/sessions \
        "$PWD" "${ws[@]}" -- pi "${args[@]}"
    }

`--persist`ing the session dir is what lets `--resume` survive the tmpfs `$HOME`.
If the agent blocks on a host or path it needs, add `--allow <host>` (or a
`PATH:ro` workspace) and `wpi --resume`. The same session continues.

## Verification

    basta-verify [--host|--network|--sni|--filesystem|--ephemeral|--namespaces|--seccomp|--gpu-absent|--gpu-present|--audit]

The `--network`, `--sni`, and `--audit` probes reach the public internet;
override the targets with `BASTA_PROBE_HOST` / `BASTA_PROBE_HOST_IP` /
`BASTA_PROBE_DNS` / `BASTA_PROBE_DNS_NAME`.

`basta --build-rev` prints the git rev the binary was built from.

## Security model

- Runs as the caller's uid, with no shared sandbox user, so file permissions
  behave exactly as on the host. The agent has `no_new_privs` and no capabilities in an
  unprivileged user namespace, so setuid-root binaries (`sudo`, `su`, `pkexec`)
  run as the unprivileged agent and can't elevate.
- In the bwrap mount namespace, only your explicit binds are visible; `$HOME` is
  a fresh tmpfs, and the host's `/proc/1`, terminals, and `/sys/fs/cgroup` are
  not.
- The egress filter runs in the sandbox's own network namespace, owned by an
  outer user namespace the agent can't reach, so it can't alter the filter. The
  SNI proxy self-sandboxes (seccomp, dropped capabilities). Services on the host
  itself are unreachable unless you open a port with `--allow-loopback`.
- The agent runs under a seccomp **denylist**: `io_uring`, kernel keyrings,
  `bpf`, `userfaultfd`, `mount`, `unshare`/`setns`, and module loading return
  `EPERM`, and 32-bit (i386-ABI) binaries are killed. Developer syscalls
  (`ptrace`, `perf_event_open`) are kept. Tune with `--allow-syscall` /
  `--deny-syscall`, or disable with `--no-seccomp`.
- **Workspace lock** (on by default): in each writable workspace, the files a
  tool would run on its own are read-only: git internals (`.git/config`,
  `.git/hooks`, …), `.envrc`, `.vscode`, `.idea`, `.claude`, and `.mcp.json`. So
  the agent can't plant a git hook, a direnv script, or an editor/MCP config the
  **host** would later run. Existing targets are locked read-only; open one
  knowingly with `--unlock` (e.g. `--unlock .claude`), add paths with `--lock`,
  or drop the set with `--no-lock`. A net-new file that didn't exist at launch
  can't be pre-blocked, so basta watches the locked set and warns at exit if the
  agent created one (`--lock-strict` makes that a non-zero exit). A locked target
  that is a symlink can't be read-only-bound, so basta refuses to launch rather
  than skip it.
- No privileged code path and no daemon; each launch leaves no host state behind
  except an opt-in `--persist`.

It does **not** defend against kernel exploits, hardware side channels, or a
compromised host account. For unknown malware, use a VM.

## Limits

- IPv4 only; IPv6 egress is dropped.
- `--allow-sni` trusts a client-asserted name (see caveats above).
- Resolve-at-launch DNS pins IPs for the session.
- GPU is off by default; `--gpu` binds all `/dev/nvidia*` (all-or-nothing,
  with no CPU / memory / PID limits).
- The sandbox shares the host time namespace, so host uptime / boot time
  are visible (bubblewrap cannot unshare it).
- **Ubuntu 22.04** ships no `passt` package, so from stock repos only offline
  sandboxing works (`basta-host-setup` warns and continues). Filtered egress
  (`--allow*`) works once `passt`/`pasta` is installed. [passt.top](https://passt.top)
  ships a static binary and a `.deb`; verified on 22.04 with full egress.
- **SELinux (Fedora/RHEL):** run basta from a normal login shell (`id -Z` =
  `unconfined_t`), where bubblewrap's mounts are allowed. From a *confined* domain
  (a confined user, or a systemd service / CI runner) SELinux denies bwrap's
  `mounton` and it won't start. Add a small opt-in policy:
  `sudo ausearch -m AVC -ts recent | audit2allow -M basta_local && sudo semodule -i basta_local.pp`.

## Uninstall

    make uninstall

Runs `basta-host-setup --uninstall` (host state: AppArmor profiles, sysctl
drop-in) then removes the user-prefix files. Idempotent.

## License

[MIT](LICENSE-MIT). Provided as-is, without warranty of any kind. Contributions
are accepted under the same license.
