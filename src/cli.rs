use anyhow::{Context, Result, bail};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "basta", version, about, long_about = None)]
pub struct Cli {
    /// Workspace path[:ro]. First RW one becomes cwd. Defaults to $PWD.
    #[arg(value_name = "WORKSPACE")]
    pub workspaces: Vec<String>,

    /// Bind /dev/nvidia* into the sandbox. Off by default (locked down);
    /// pass --gpu to expose the GPU device nodes — e.g. for local
    /// inference inside the sandbox. Most agents reach a model over the
    /// network and need no GPU device access.
    #[arg(long = "gpu", action = clap::ArgAction::SetTrue)]
    pub gpu: bool,

    /// RO-bind the host's entire ~/.local/share. Default exposes only
    /// the mise tool tree; this also exposes other apps' data.
    #[arg(long)]
    pub expose_local_share: bool,

    /// Network mode. `none` (default) is offline; `host` shares the host
    /// netns with no filtering. Filtered egress is opt-in via --allow.
    #[arg(long, value_enum, default_value_t = NetMode::None)]
    pub net: NetMode,

    /// Allow egress to HOST:PORT[-PORT][/tcp|/udp]. HOST is an IPv4
    /// address, an IPv4 CIDR, or a DNS name (resolved once, at launch).
    /// A DNS name is refused on TCP :443 — it may resolve to a shared CDN
    /// edge IP; use --allow-sni for HTTPS hosts. Repeatable. Any --allow
    /// enables filtered networking via pasta — no host setup, no
    /// persistent state.
    #[arg(
        long = "allow",
        value_name = "HOST:PORT[/PROTO]",
        value_delimiter = ','
    )]
    pub allow: Vec<String>,

    /// Allow TLS egress to HOST (port 443) by exact ClientHello SNI. HOST
    /// is a DNS name, resolved once at launch. Repeatable. Filtered by an
    /// in-netns SNI proxy. Cannot be combined with --net host.
    #[arg(long = "allow-sni", value_name = "HOST", value_delimiter = ',')]
    pub allow_sni: Vec<String>,

    /// Allow the sandboxed process to reach a service on the basta HOST
    /// itself, at 127.0.0.1:PORT. Repeatable / comma-separated. By
    /// default the sandbox cannot reach any host service; each
    /// --allow-loopback opens exactly one TCP port of the host's
    /// loopback — nothing else.
    #[arg(long = "allow-loopback", value_name = "PORT", value_delimiter = ',')]
    pub allow_loopback: Vec<u16>,

    /// Seed a host file or dir into the sandbox $HOME — writable but
    /// ephemeral (discarded on exit). SRC:DEST, repeatable. DEST is
    /// resolved under $HOME.
    #[arg(long = "seed", value_name = "SRC:DEST")]
    pub seed: Vec<String>,

    /// RW bind-mount a host path into the sandbox $HOME; survives across
    /// runs. SRC is created if missing. SRC:DEST, repeatable. DEST is
    /// resolved under $HOME.
    #[arg(long = "persist", value_name = "SRC:DEST")]
    pub persist: Vec<String>,

    /// Set or pass through env var. KEY=VAL sets it; KEY alone passes from caller.
    #[arg(long = "env", value_name = "KEY[=VAL]")]
    pub envs: Vec<String>,

    /// Print plan, don't exec.
    #[arg(long)]
    pub dry_run: bool,

    /// Print bwrap argv to stderr.
    #[arg(long)]
    pub trace: bool,

    /// Un-block a syscall from the agent seccomp denylist.
    /// Comma-separated and/or repeatable.
    #[arg(long = "allow-syscall", value_name = "SYSCALL", value_delimiter = ',')]
    pub allow_syscall: Vec<String>,

    /// Add a syscall to the agent seccomp denylist (block it).
    /// Comma-separated and/or repeatable.
    #[arg(long = "deny-syscall", value_name = "SYSCALL", value_delimiter = ',')]
    pub deny_syscall: Vec<String>,

    /// Disable the agent seccomp filter entirely.
    #[arg(long)]
    pub no_seccomp: bool,

    /// Make a workspace-relative PATH read-only inside the sandbox, on top
    /// of the default lock set (git internals + .envrc, .vscode, .idea,
    /// .claude, .mcp.json). Blocks the agent from planting an autorun file
    /// the host later executes. Comma-separated and/or repeatable.
    #[arg(long = "lock", value_name = "PATH", value_delimiter = ',')]
    pub lock: Vec<String>,

    /// Remove a PATH from the lock set, including a default (e.g.
    /// `--unlock .claude` to let a sandboxed agent manage its own config).
    /// Comma-separated and/or repeatable.
    #[arg(long = "unlock", value_name = "PATH", value_delimiter = ',')]
    pub unlock: Vec<String>,

    /// Disable the default lock set (git internals + .envrc, .vscode,
    /// .idea, .claude, .mcp.json). Explicit --lock still applies.
    #[arg(long = "no-lock")]
    pub no_lock: bool,

    /// Exit non-zero (code 3) if the agent created a watched autorun file
    /// that could not be pre-blocked (e.g. a new .envrc). Default: warn only.
    #[arg(long = "lock-strict")]
    pub lock_strict: bool,

    /// Command to run inside the sandbox. Use `--` to separate from options.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetMode {
    /// Offline — own empty netns. Default. (Same as omitting --allow.)
    None,
    /// Share the host netns. No isolation, no filtering. Escape hatch.
    Host,
}

impl Cli {
    /// Whether any flag requests filtered egress — the single source of
    /// truth shared by `preflight` and the launch path (`main::run`), so the
    /// two cannot drift on which flags enable the netns/pasta path.
    pub fn egress_requested(&self) -> bool {
        !self.allow.is_empty() || !self.allow_sni.is_empty() || !self.allow_loopback.is_empty()
    }

    pub fn preflight(&self) -> Result<()> {
        crate::netns::find_bin("bwrap")
            .context("bwrap not installed (run basta-host-setup first)")?;

        if self.egress_requested() {
            if self.net == NetMode::Host {
                bail!(
                    "--allow / --allow-sni / --allow-loopback cannot be combined \
                     with --net host (host mode shares the host netns — no \
                     egress filtering)"
                );
            }
            crate::netns::find_bin("nft")
                .context("nft not installed (run basta-host-setup first; package: nftables)")?;
            crate::netns::find_bin("pasta")
                .context("pasta not installed (run basta-host-setup first; package: passt)")?;
        }
        if self.allow_loopback.iter().any(|&p| p == 0) {
            bail!("--allow-loopback: port must be 1-65535");
        }

        // --lock / --unlock take workspace-relative paths; reject absolute
        // paths and any `..` component so a lock can't escape the workspace.
        for (flag, list) in [("--lock", &self.lock), ("--unlock", &self.unlock)] {
            for rel in list {
                let p = std::path::Path::new(rel);
                if p.is_absolute()
                    || p.components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                {
                    bail!("{flag} '{rel}': must be a workspace-relative path without '..'");
                }
            }
        }

        // seccomp flag validation — fail fast, before any sandbox setup.
        if self.no_seccomp && (!self.allow_syscall.is_empty() || !self.deny_syscall.is_empty()) {
            bail!("--no-seccomp cannot be combined with --allow-syscall / --deny-syscall");
        }
        // Resolving the effective list validates every user-supplied name.
        crate::seccomp::effective_denylist(self)
            .context("invalid --allow-syscall / --deny-syscall syscall name")?;

        Ok(())
    }
}
