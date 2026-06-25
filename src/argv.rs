use anyhow::{Context, Result};
use nix::fcntl::{FcntlArg, SealFlag, fcntl};
use nix::sys::memfd::{MFdFlags, memfd_create};
use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use crate::cli::{Cli, NetMode};
use crate::env::EnvSpec;
use crate::seed::SeedSet;
use crate::workspace::Workspace;

/// Build the bwrap argv vector. Caller-side; written into a sealed
/// memfd by `to_memfd` before passing to bwrap via `--args FD`.
pub fn build(
    cli: &Cli,
    workspaces: &[Workspace],
    cwd: &std::path::Path,
    envs: &[EnvSpec],
    seeds: &SeedSet,
) -> Result<Vec<String>> {
    let home = crate::env::host_home()?;
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();

    let mut args: Vec<String> = vec![];

    // Canonical base.
    push(&mut args, &["--die-with-parent", "--new-session"]);
    push(&mut args, &["--hostname", "basta"]);

    // Read-only host mounts. /etc is bound whole because it is load-bearing
    // (TLS CA bundles, ld.so.cache, the Debian /etc/alternatives symlinks, NSS);
    // this also exposes world-readable host config (e.g. /etc/passwd usernames)
    // — a documented information-disclosure surface, not minimizable without a
    // synthetic /etc. See README "Security model" + research/external-review-findings.md.
    push(&mut args, &["--ro-bind", "/usr", "/usr"]);
    push(&mut args, &["--ro-bind", "/etc", "/etc"]);
    // /opt is absent on minimal images (Alpine, slim Debian); bind only if present.
    push(&mut args, &["--ro-bind-try", "/opt", "/opt"]);

    // usrmerge symlinks.
    push(&mut args, &["--symlink", "usr/bin", "/bin"]);
    push(&mut args, &["--symlink", "usr/sbin", "/sbin"]);
    push(&mut args, &["--symlink", "usr/lib", "/lib"]);
    push(&mut args, &["--symlink", "usr/lib64", "/lib64"]);

    // /proc + defense-in-depth null-binds (memfd args make these largely moot,
    // but keep the null-binds so accidental future regressions don't re-expose).
    push(&mut args, &["--proc", "/proc"]);
    push(&mut args, &["--ro-bind", "/dev/null", "/proc/1/cmdline"]);
    push(&mut args, &["--ro-bind", "/dev/null", "/proc/1/environ"]);
    push(
        &mut args,
        &["--ro-bind", "/dev/null", "/proc/1/task/1/cmdline"],
    );
    push(
        &mut args,
        &["--ro-bind", "/dev/null", "/proc/1/task/1/environ"],
    );

    // /dev (synthesised by bwrap) + null-bind tty/console.
    // Real stdio comes from the openpty()'d pty in pty.rs, not host tty.
    push(&mut args, &["--dev", "/dev"]);
    push(&mut args, &["--ro-bind", "/dev/null", "/dev/console"]);
    push(&mut args, &["--ro-bind", "/dev/null", "/dev/tty"]);
    // No per-binary sudo neutering: the sandbox sets no_new_privs and drops all
    // capabilities in an unprivileged userns, so the kernel ignores setuid/setcap
    // bits on execve — sudo, su, pkexec and every other setuid-root binary run as
    // the unprivileged agent and cannot elevate. A null-bind over /usr/bin/sudo
    // would be cosmetic, incomplete (misses su/pkexec/sudo-rs), and breaks where
    // sudo is an alternatives symlink (Ubuntu 26.04). basta-verify asserts NNP=1.

    // tmpfs scratch dirs + caller's $HOME (then re-bind specific subdirs RW).
    push(&mut args, &["--tmpfs", "/tmp"]);
    push(&mut args, &["--tmpfs", "/var/tmp"]);
    push(&mut args, &["--tmpfs", "/run"]);
    args.push("--dir".into());
    args.push(format!("/run/user/{uid}"));
    args.push("--tmpfs".into());
    args.push(home.clone());

    // Seed: writable-but-ephemeral config copied into the tmpfs $HOME.
    // Emitted before persist binds so a persist bind wins on overlap.
    for dir in &seeds.dirs {
        args.push("--dir".into());
        args.push(dir.clone());
    }
    for s in &seeds.files {
        args.push("--perms".into());
        args.push("0600".into());
        args.push("--file".into());
        args.push(s.fd.as_raw_fd().to_string());
        args.push(s.dest.clone());
    }

    // Persist: opt-in RW bind-mounts that survive across runs.
    for spec in &cli.persist {
        let (src, dest) = crate::seed::parse_src_dest(spec, "--persist")?;
        let src = prepare_persist_src(&src)?;
        let dest = crate::seed::resolve_home_dest(&home, &dest)?;
        args.push("--bind".into());
        args.push(src);
        args.push(dest);
    }

    // Surface host-installed coding agents (mise) into the sandbox: the
    // tool symlinks in ~/.local/bin and the mise install trees they
    // point at. The rest of ~/.local/share — other apps' data, logs,
    // history DBs — is NOT exposed by default (F34); --expose-local-share
    // opts into binding the whole directory.
    args.push("--ro-bind-try".into());
    args.push(format!("{home}/.local/bin"));
    args.push(format!("{home}/.local/bin"));
    args.push("--ro-bind-try".into());
    if cli.expose_local_share {
        args.push(format!("{home}/.local/share"));
        args.push(format!("{home}/.local/share"));
    } else {
        args.push(format!("{home}/.local/share/mise"));
        args.push(format!("{home}/.local/share/mise"));
    }
    // mise resolves a tool's version from its config: the global
    // ~/.config/mise(/config.toml) plus any per-dir mise.toml (the latter
    // arrives via the bound $PWD workspace). Without the global config a
    // shim in ~/.local/bin can't tell which installed version to exec, so
    // surface it read-only alongside the install tree above. Without this
    // bind, mise-managed agents only resolve when a local mise.toml happens
    // to pin them.
    args.push("--ro-bind-try".into());
    args.push(format!("{home}/.config/mise"));
    args.push(format!("{home}/.config/mise"));

    // /etc/hosts + /etc/resolv.conf:
    //   egress (--allow): bind the generated overlays (resolved --allow
    //     names + localhost; a resolver or a "no DNS" note) over the
    //     inherited files. main.rs sets resolv's DEST to the resolv.conf
    //     symlink TARGET so the inherited /etc/resolv.conf symlink resolves.
    //   --net host: keep the host's resolv.conf — bind its symlink target
    //     so the inherited symlink resolves.
    //   --net none: nothing; the host's /etc/* are inherited read-only and
    //     the empty netns makes a resolver moot.
    if let Some(h) = &seeds.hosts {
        args.push("--ro-bind-data".into());
        args.push(h.fd.as_raw_fd().to_string());
        args.push(h.dest.clone());
    }
    if let Some(r) = &seeds.resolv {
        args.push("--ro-bind-data".into());
        args.push(r.fd.as_raw_fd().to_string());
        args.push(r.dest.clone());
    }
    let host_resolv = (cli.net == NetMode::Host)
        .then(resolv_conf_target)
        .flatten();
    if let Some(target) = host_resolv {
        let target = target.to_string_lossy().into_owned();
        args.push("--ro-bind-try".into());
        args.push(target.clone());
        args.push(target);
    }

    // Namespaces. On the egress path the netns is unshared in the Rust
    // child *before* exec (so pasta can configure it); bwrap keeps it via
    // --share-net. --net host shares the host netns. Otherwise bwrap
    // makes its own empty netns.
    push(
        &mut args,
        &[
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-cgroup",
        ],
    );

    // Run the agent as a non-root, capability-less user — set explicitly,
    // never inherited from bwrap's default (which is the *invoking* uid).
    // On the egress path the Rust child is uid 0 in the netns-owning
    // userns; without --uid that uid 0 flows through bwrap to the agent,
    // handing it CAP_SYS_ADMIN over its own mount namespace (the F1
    // remount-to-host-write escape). bwrap holds its setup capabilities as
    // the *creator* of the sandbox userns regardless of its uid, so it
    // still builds the sandbox and then execs the agent unprivileged.
    // --cap-drop ALL makes the empty bounding set explicit rather than
    // left to bwrap's mode-dependent default. Offline mode is unchanged:
    // there the agent is already uid {uid} with an empty CapBnd.
    args.push("--uid".into());
    args.push(uid.to_string());
    args.push("--gid".into());
    args.push(gid.to_string());
    args.push("--cap-drop".into());
    args.push("ALL".into());

    if seeds.hosts.is_some() || cli.net == NetMode::Host {
        args.push("--share-net".into());
    } else {
        args.push("--unshare-net".into());
    }

    // GPU.
    if cli.gpu {
        for dev in [
            "nvidiactl",
            "nvidia-uvm",
            "nvidia-uvm-tools",
            "nvidia-modeset",
        ] {
            args.push("--dev-bind-try".into());
            args.push(format!("/dev/{dev}"));
            args.push(format!("/dev/{dev}"));
        }
        // /dev/nvidia0, /dev/nvidia1, ...
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let is_numbered = name
                    .strip_prefix("nvidia")
                    .and_then(|rest| rest.chars().next())
                    .is_some_and(|c| c.is_ascii_digit());
                if is_numbered {
                    args.push("--dev-bind".into());
                    args.push(format!("/dev/{name}"));
                    args.push(format!("/dev/{name}"));
                }
            }
        }
    }

    // Workspaces — bind by fd, dest path resolved inside sandbox.
    for w in workspaces {
        let flag = if w.ro { "--ro-bind-fd" } else { "--bind-fd" };
        args.push(flag.into());
        args.push(w.fd.as_raw_fd().to_string());
        args.push(w.path.to_string_lossy().into());
    }
    args.push("--chdir".into());
    args.push(cwd.to_string_lossy().into());

    // Env: --clearenv then re-set required + caller envs.
    args.push("--clearenv".into());
    let user = std::env::var("USER").unwrap_or_else(|_| {
        nix::unistd::User::from_uid(nix::unistd::geteuid())
            .ok()
            .flatten()
            .map(|u| u.name)
            .unwrap_or_else(|| "user".into())
    });
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
    let lang = std::env::var("LANG").unwrap_or_else(|_| "C.UTF-8".into());
    let lc_all = std::env::var("LC_ALL").unwrap_or_else(|_| "C.UTF-8".into());

    for (k, v) in [
        ("HOME", home.as_str()),
        ("USER", user.as_str()),
        ("LOGNAME", user.as_str()),
        ("TERM", term.as_str()),
        ("LANG", lang.as_str()),
        ("LC_ALL", lc_all.as_str()),
    ] {
        args.push("--setenv".into());
        args.push(k.into());
        args.push(v.into());
    }
    args.push("--setenv".into());
    args.push("PATH".into());
    args.push(format!("{home}/.local/bin:/usr/local/bin:/usr/bin:/bin"));
    args.push("--setenv".into());
    args.push("XDG_RUNTIME_DIR".into());
    args.push(format!("/run/user/{uid}"));

    for e in envs {
        args.push("--setenv".into());
        args.push(e.key.clone());
        args.push(e.value.clone());
    }

    // Agent command goes on bwrap's *command line*, not in the memfd
    // (bwrap requires the operand after `--` to be on argv proper).
    // The pty layer appends it during exec_argv construction.

    Ok(args)
}

fn push(args: &mut Vec<String>, items: &[&str]) {
    for s in items {
        args.push(s.to_string());
    }
}

/// Resolve a `--persist` SRC to a canonical host path, creating it as a
/// directory if it does not yet exist (the first run of a fresh persist
/// target). bwrap `--bind` then RW-mounts it into the sandbox.
fn prepare_persist_src(src: &str) -> Result<String> {
    let path = std::path::Path::new(src);
    if !path.exists() {
        std::fs::create_dir_all(path)
            .with_context(|| format!("--persist: cannot create SRC dir: {src}"))?;
    }
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("--persist: cannot resolve SRC: {src}"))?;
    Ok(canonical.to_string_lossy().into_owned())
}

/// /etc/resolv.conf is usually a symlink (systemd-resolved →
/// /run/systemd/resolve/...). Return the canonical target so an override
/// can be bound there and the inherited symlink resolves. None if it is
/// a plain file or absent.
pub fn resolv_conf_target() -> Option<std::path::PathBuf> {
    let is_symlink = std::fs::symlink_metadata("/etc/resolv.conf")
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    if is_symlink {
        std::fs::canonicalize("/etc/resolv.conf").ok()
    } else {
        None
    }
}

/// Loop write(2) until all bytes are flushed. Avoids the std::fs::File
/// double-ownership pattern that would risk double-closing the fd on
/// an early ? path (see sealed_memfd).
fn write_all(fd: &OwnedFd, mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        let n = nix::unistd::write(fd.as_fd(), bytes)?;
        bytes = &bytes[n..];
    }
    Ok(())
}

/// Create a sealed, rewound memfd containing `data`. Shared by the bwrap
/// `--args` argv blob and the `--seccomp` filter blob — one audited memfd
/// path.
pub fn sealed_memfd(name: &str, data: &[u8]) -> Result<OwnedFd> {
    let cname = CString::new(name)?;
    let fd: OwnedFd = memfd_create(
        cname.as_c_str(),
        MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
    )?;

    // I3: write via nix::unistd::write so `fd` remains the sole owner.
    // The previous approach wrapped the fd in std::fs::File then
    // mem::forget'd it on success — but on an early ? from write_all,
    // File would drop and close, leading to a double-close on the
    // OwnedFd's own drop.
    write_all(&fd, data)?;

    nix::unistd::lseek(&fd, 0, nix::unistd::Whence::SeekSet)?;

    fcntl(
        &fd,
        FcntlArg::F_ADD_SEALS(
            SealFlag::F_SEAL_SHRINK
                | SealFlag::F_SEAL_GROW
                | SealFlag::F_SEAL_WRITE
                | SealFlag::F_SEAL_SEAL,
        ),
    )?;

    Ok(fd)
}

/// Write argv to an anonymous memfd in bwrap `--args FD` wire format
/// (NUL-separated), seal the memfd, rewind, return the OwnedFd.
pub fn to_memfd(args: &[String]) -> Result<OwnedFd> {
    let mut blob: Vec<u8> = Vec::new();
    for arg in args {
        blob.extend_from_slice(arg.as_bytes());
        blob.push(0);
    }
    sealed_memfd("basta-bwrap-args", &blob)
}

/// Env keys basta sets itself (argv.rs) and that carry no secret — safe to
/// show verbatim in --dry-run / --trace. Any other `--setenv` value comes
/// from a caller `--env` (e.g. an API key) and is redacted.
const SAFE_SETENV: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "TERM",
    "LANG",
    "LC_ALL",
    "PATH",
    "XDG_RUNTIME_DIR",
];

/// Print bwrap argv to stderr for --dry-run / --trace. `--setenv KEY VALUE`
/// triples for caller-supplied env keys have their VALUE redacted so a
/// secret passed via `--env` is never echoed to the terminal/logs.
pub fn print(args: &[String]) {
    eprint!("+ env -i bwrap --args FD");
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--setenv" && i + 2 < args.len() {
            let key = &args[i + 1];
            let shown = if SAFE_SETENV.contains(&key.as_str()) {
                shell_quote(&args[i + 2])
            } else {
                "<redacted>".to_string()
            };
            eprint!(" --setenv {} {}", shell_quote(key), shown);
            i += 3;
        } else {
            eprint!(" {}", shell_quote(&args[i]));
            i += 1;
        }
    }
    eprintln!();
}

fn shell_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".into();
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "+,-./:=@_".contains(c))
    {
        return s.into();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}
