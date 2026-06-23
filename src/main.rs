mod argv;
mod cli;
mod client_hello;
mod egress;
mod env;
mod lockset;
mod netns;
mod pty;
mod seccomp;
mod seed;
mod sni_proxy;
mod workspace;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    close_inherited_fds();

    // Internal re-exec: the SNI proxy. Detected after close_inherited_fds
    // (that call closes only fds >= 3 — the proxy's stdin/stdout/stderr at
    // 0/1/2 survive, and any stray inherited fd is correctly scrubbed),
    // and before clap (Cli is a flat struct with no subcommands).
    if std::env::args().nth(1).as_deref() == Some("__sni-proxy") {
        return sni_proxy::run();
    }

    // Provenance probe — print the git rev embedded at build time and exit.
    // Pre-clap so it doesn't trip the required-command contract; consumed by
    // the ansible deploy to detect a stale binary. `--version` stays bare.
    if std::env::args().nth(1).as_deref() == Some("--build-rev") {
        println!("{}", env!("BASTA_BUILD_REV"));
        return Ok(());
    }

    let cli = cli::Cli::parse();
    let exit = run(cli)?;
    std::process::exit(exit);
}

/// Close any fd >= 3 inherited from the caller before basta opens its own
/// (workspace fds, the args memfd, netns pipes, seed fds). bwrap does
/// not scrub inherited fds, so a leaked fd would otherwise pass straight
/// through into the sandbox.
fn close_inherited_fds() {
    // close_range(2) — Linux 5.9+ — closes the whole range in one call.
    let rc = unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) };
    if rc == 0 {
        return;
    }
    // close_range unavailable (pre-5.9) or blocked by an outer policy —
    // fall back to walking /proc/self/fd. Collect the fd numbers first;
    // closing them while the ReadDir is open would disturb its own fd.
    let fds: Vec<i32> = match std::fs::read_dir("/proc/self/fd") {
        Ok(rd) => rd
            .flatten()
            .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
            .filter(|&fd| fd >= 3)
            .collect(),
        Err(_) => return,
    };
    for fd in fds {
        // SAFETY: close(2) on an int fd; errors (incl. the already-closed
        // ReadDir handle) are intentionally ignored.
        unsafe {
            libc::close(fd);
        }
    }
}

fn run(cli: cli::Cli) -> Result<i32> {
    cli.preflight()?;

    let mut workspaces = if cli.workspaces.is_empty() {
        vec![workspace::Workspace::resolve(".")?]
    } else {
        cli.workspaces
            .iter()
            .map(|w| workspace::Workspace::resolve(w))
            .collect::<Result<Vec<_>>>()?
    };

    let cwd = workspaces
        .iter()
        .find(|w| !w.ro)
        .or_else(|| workspaces.first())
        .map(|w| w.path.clone())
        .expect("at least one workspace");

    // Lock set: RO-protect git autorun internals (+ any --lock paths) in each
    // writable workspace so the agent can't plant a hook/config the host later
    // executes. Appended AFTER cwd selection so a pin's RW `.git` bind never
    // becomes the working directory; emitted by the same fd-bind loop. The
    // watch set is the autorun paths that didn't exist at launch (so couldn't
    // be RO-bound) — checked after the run.
    let lock = lockset::plan_for(&workspaces, &cli)?;
    workspaces.extend(lock.binds);
    let watch = lock.watch;

    let envs = cli
        .envs
        .iter()
        .map(|e| env::EnvSpec::parse(e))
        .collect::<Result<Vec<_>>>()?;

    let home = env::host_home()?;
    let mut seeds = seed::SeedSet::build(&cli.seed, &home)?;

    // Any --allow / --allow-sni enables filtered egress. Resolve names
    // here, in the host netns, before any unshare — the sandbox gets no
    // resolver.
    let egress = if cli.egress_requested() {
        Some(egress::EgressSpec::resolve(&cli.allow, &cli.allow_sni)?)
    } else {
        None
    };
    if let Some(e) = &egress {
        if e.sni_enabled() && e.has_tcp443_rule() {
            // --allow-sni redirects all :443 to the proxy, so a --allow
            // rule on :443 is inert.
            eprintln!(
                "basta: WARNING --allow-sni redirects all :443 to the SNI \
                 proxy — your --allow rule(s) on TCP port 443 are shadowed."
            );
        }
        if e.sni_enabled() && e.has_udp_rule() {
            // A UDP --allow rule (esp. a :53 resolver) reintroduces an
            // egress channel the SNI proxy does not see.
            eprintln!(
                "basta: WARNING --allow-sni is combined with a UDP --allow \
                 rule. A reachable resolver/UDP service is an egress \
                 channel the SNI filter cannot inspect — a compromised \
                 agent can exfiltrate over it. Only do this deliberately."
            );
        }
        seeds.hosts = Some(seed::Seed::overlay(
            "/etc/hosts",
            e.hosts_file().as_bytes(),
        )?);
        let resolv_dest = argv::resolv_conf_target()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "/etc/resolv.conf".to_string());
        seeds.resolv = Some(seed::Seed::overlay(
            &resolv_dest,
            e.resolv_conf().as_bytes(),
        )?);
    }

    let argv = argv::build(&cli, &workspaces, &cwd, &envs, &seeds)?;

    if cli.dry_run {
        argv::print(&argv);
        eprintln!("{}", seccomp::describe(&cli)?);
        return Ok(0);
    }

    if cli.trace {
        argv::print(&argv);
        eprintln!("{}", seccomp::describe(&cli)?);
    }

    let exit = match egress {
        Some(e) => netns::run_egress(argv, &cli, workspaces, seeds, e)?,
        None => {
            if cli.net == cli::NetMode::Host {
                eprintln!(
                    "basta: WARNING --net host shares the host network namespace — \
                     no network isolation, no egress filtering."
                );
            }
            pty::run_plain(argv, &cli, workspaces, seeds)?
        }
    };

    // Post-run autorun detection: a watched path that didn't exist at launch
    // but does now was created inside the sandbox and would auto-execute on the
    // host later. Can't be pre-blocked (no source to bind); report it.
    let created: Vec<&lockset::WatchPath> = watch.iter().filter(|w| w.path.exists()).collect();
    if !created.is_empty() {
        eprintln!(
            "basta: WARNING the sandboxed agent created autorun file(s) the host may run later:"
        );
        for w in &created {
            eprintln!("  {} — {}", w.path.display(), w.reason);
        }
        eprintln!(
            "  Review before trusting this directory. (--unlock / --no-lock to stop watching.)"
        );
        if cli.lock_strict && exit == 0 {
            return Ok(3);
        }
    }
    Ok(exit)
}
