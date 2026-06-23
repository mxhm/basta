use anyhow::Result;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::pty::{OpenptyResult, Winsize, openpty};
use nix::sys::termios::{SetArg, Termios, cfmakeraw, tcgetattr, tcsetattr};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{
    ForkResult, Pid, dup2_stderr, dup2_stdin, dup2_stdout, fork, isatty, read, setsid, write,
};
use std::ffi::CString;
use std::io::{stdin, stdout};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::process::Child;

use crate::argv;
use crate::cli::Cli;
use crate::seed::SeedSet;
use crate::workspace::Workspace;

/// Kills and reaps the long-lived support processes (pasta, and the SNI
/// proxy when --allow-sni) on every exit path. `std::process::Child::drop`
/// neither kills nor reaps, so a naive "hold the Child, wait() later"
/// would leak them on any `?` error path.
struct StackGuard(Vec<Child>);

impl Drop for StackGuard {
    fn drop(&mut self) {
        // Signal all, THEN reap all — a slow-dying pasta must not delay
        // the proxy's SIGKILL.
        for c in &mut self.0 {
            let _ = c.kill();
        }
        for c in &mut self.0 {
            let _ = c.wait();
        }
    }
}

/// Restores the terminal to its saved mode on drop, so an error from
/// `relay` (or anything after raw-mode entry) cannot leave the user's
/// terminal stuck in raw mode.
struct TermiosGuard(Option<Termios>);

impl Drop for TermiosGuard {
    fn drop(&mut self) {
        if let Some(t) = &self.0 {
            let _ = tcsetattr(stdin(), SetArg::TCSANOW, t);
        }
    }
}

/// `--net none` / `--net host`: no support process, no pre-exec hook.
pub fn run_plain(
    argv: Vec<String>,
    cli: &Cli,
    workspaces: Vec<Workspace>,
    seeds: SeedSet,
) -> Result<i32> {
    run(argv, cli, workspaces, seeds, || Ok(()), |_| Ok(vec![]))
}

/// Common path.
/// - `pre_exec` runs in the child (post-fork, pre-exec) before exec'ing bwrap.
/// - `post_fork` runs in the parent (post-fork) before relaying; any
///   support processes it returns are killed+reaped via `StackGuard`.
pub fn run<F, G>(
    argv: Vec<String>,
    cli: &Cli,
    workspaces: Vec<Workspace>,
    seeds: SeedSet,
    pre_exec: F,
    post_fork: G,
) -> Result<i32>
where
    F: FnOnce() -> Result<()>,
    G: FnOnce(Pid) -> Result<Vec<Child>>,
{
    let winsize = current_winsize();

    let OpenptyResult { master, slave } =
        openpty(winsize.as_ref(), None).map_err(|e| anyhow::anyhow!("openpty: {e}"))?;

    let args_fd = argv::to_memfd(&argv)?;
    let seccomp_fd: Option<OwnedFd> = crate::seccomp::agent_filter_memfd(cli)?;

    // bwrap argv on cmd line: [bwrap, --args, N, (--seccomp, M,)? --, COMMAND...].
    // Resolve bwrap to an absolute path so exec never PATH-searches.
    let bwrap_abs =
        crate::netns::find_bin("bwrap").ok_or_else(|| anyhow::anyhow!("bwrap not found"))?;
    let bwrap_path = CString::new(bwrap_abs.as_os_str().as_bytes())?;
    let mut exec_argv = vec![
        bwrap_path.clone(),
        CString::new("--args")?,
        CString::new(args_fd.as_raw_fd().to_string())?,
    ];
    // bwrap installs --seccomp last, after all privileged setup, just
    // before execve — so the filter lands on the agent tree only.
    if let Some(ref fd) = seccomp_fd {
        exec_argv.push(CString::new("--seccomp")?);
        exec_argv.push(CString::new(fd.as_raw_fd().to_string())?);
    }
    exec_argv.push(CString::new("--")?);
    for c in &cli.command {
        exec_argv.push(CString::new(c.as_str())?);
    }
    let exec_env: Vec<CString> = vec![];

    let master_fd_raw = master.as_raw_fd();

    match unsafe { fork() }? {
        ForkResult::Child => {
            // Drop post_fork: fork copied its captured pipe ends (the
            // parent's `go` writer, `ready` reader) into this process.
            // If the child kept them, its own read of the `go` pipe
            // could never see EOF when the parent closes its end.
            drop(post_fork);

            // Run pre_exec FIRST so any errors print to the host stderr
            // (still the parent's tty). After we dup2 below, the child's
            // stderr is the pty slave and early errors get lost.
            if let Err(e) = pre_exec() {
                eprintln!("basta: pre_exec failed: {e:?}");
                std::process::exit(99);
            }

            setsid().expect("setsid");
            drop(master);

            dup2_stdin(&slave).expect("dup2 stdin");
            dup2_stdout(&slave).expect("dup2 stdout");
            dup2_stderr(&slave).expect("dup2 stderr");
            drop(slave);

            clear_cloexec_raw(args_fd.as_raw_fd()).expect("clear cloexec args_fd");
            std::mem::forget(args_fd);
            if let Some(fd) = seccomp_fd {
                clear_cloexec_raw(fd.as_raw_fd()).expect("clear cloexec seccomp_fd");
                std::mem::forget(fd);
            }
            for w in &workspaces {
                clear_cloexec_raw(w.fd.as_raw_fd()).expect("clear cloexec workspace");
            }
            std::mem::forget(workspaces);
            for s in seeds
                .files
                .iter()
                .chain(seeds.hosts.iter())
                .chain(seeds.resolv.iter())
            {
                clear_cloexec_raw(s.fd.as_raw_fd()).expect("clear cloexec seed");
            }
            std::mem::forget(seeds);

            nix::unistd::execve(&bwrap_path, &exec_argv, &exec_env).expect("execve bwrap");
            unreachable!()
        }
        ForkResult::Parent { child } => {
            drop(slave);
            drop(args_fd);
            drop(seccomp_fd);

            // Drop pre_exec: fork copied its captured pipe ends (the
            // child's `ready` writer, `go` reader) into this process.
            // If the parent kept them, its own read of the `ready` pipe
            // could never see EOF when the child closes its end.
            drop(pre_exec);

            // Scoped to the whole parent branch: the support process is
            // killed+reaped on normal return AND on every `?` below.
            let _stack = StackGuard(post_fork(child)?);

            let _termios = TermiosGuard(if isatty(stdin().as_fd()).unwrap_or(false) {
                let t = tcgetattr(stdin()).ok();
                if let Some(ref t) = t {
                    let mut raw = t.clone();
                    cfmakeraw(&mut raw);
                    let _ = tcsetattr(stdin(), SetArg::TCSANOW, &raw);
                }
                t
            } else {
                None
            });

            install_sigwinch_forward(master_fd_raw)?;

            // A relay error (e.g. our stdout closed) must not skip the reap —
            // we still want the agent's real exit status, not a lost child.
            // SIGTERM first so waitpid can't block on a child that won't see
            // its pty close (die-with-parent only fires when basta itself exits).
            if let Err(e) = relay(master.as_fd()) {
                eprintln!("basta: pty relay ended early: {e}");
                unsafe { nix::libc::kill(child.as_raw(), nix::libc::SIGTERM) };
            }

            let status = waitpid(child, None)?;
            Ok(match status {
                WaitStatus::Exited(_, code) => code,
                WaitStatus::Signaled(_, sig, _) => 128 + (sig as i32),
                _ => 128,
            })
        }
    }
}

/// Clear FD_CLOEXEC on a raw fd so it survives exec into bwrap.
pub fn clear_cloexec_raw(raw: RawFd) -> nix::Result<()> {
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    let borrowed = unsafe { BorrowedFd::borrow_raw(raw) };
    let flags = fcntl(borrowed, FcntlArg::F_GETFD)?;
    let new_flags = FdFlag::from_bits_truncate(flags) - FdFlag::FD_CLOEXEC;
    fcntl(borrowed, FcntlArg::F_SETFD(new_flags))?;
    Ok(())
}

fn current_winsize() -> Option<Winsize> {
    use nix::libc::{TIOCGWINSZ, ioctl};
    let mut ws = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let r = unsafe { ioctl(0, TIOCGWINSZ, &mut ws) };
    if r == 0 { Some(ws) } else { None }
}

/// Write the whole buffer, looping over short writes (legal on ptys and
/// pipes under backpressure) and EINTR.
fn write_all(fd: BorrowedFd<'_>, mut buf: &[u8]) -> nix::Result<()> {
    while !buf.is_empty() {
        match write(fd, buf) {
            Ok(0) => return Err(nix::errno::Errno::EIO),
            Ok(n) => buf = &buf[n..],
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn relay(master: BorrowedFd<'_>) -> Result<()> {
    let stdin = stdin();
    let stdout = stdout();
    let mut buf = [0u8; 8192];
    // Headless/non-interactive launches hit stdin EOF immediately (piped or
    // /dev/null). That must NOT end the relay — the child's output still has
    // to drain. Stop polling stdin on EOF and keep relaying master→stdout
    // until the master closes.
    let mut stdin_open = true;
    loop {
        let mut fds: Vec<PollFd> = Vec::with_capacity(2);
        fds.push(PollFd::new(master, PollFlags::POLLIN)); // index 0
        if stdin_open {
            fds.push(PollFd::new(stdin.as_fd(), PollFlags::POLLIN)); // index 1
        }
        match poll(&mut fds, PollTimeout::NONE) {
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }

        let master_revents = fds[0].revents().unwrap_or(PollFlags::empty());
        let stdin_revents = if stdin_open {
            fds[1].revents().unwrap_or(PollFlags::empty())
        } else {
            PollFlags::empty()
        };

        // Drain the child FIRST so its output is flushed even when we are
        // about to exit (master EOF/HUP in the same wakeup).
        if master_revents.contains(PollFlags::POLLIN) {
            match read(master, &mut buf) {
                Ok(0) => break,
                Ok(n) => write_all(stdout.as_fd(), &buf[..n])?,
                Err(nix::errno::Errno::EIO) => break,
                Err(nix::errno::Errno::EINTR) => {}
                Err(e) => return Err(e.into()),
            }
        }

        if stdin_open && stdin_revents.contains(PollFlags::POLLIN) {
            match read(stdin.as_fd(), &mut buf) {
                Ok(0) => {
                    // Host stdin EOF: stop watching it, and deliver EOF to the child
                    // by writing the pty's EOF char (^D) — otherwise a reader like
                    // `cat </dev/null` blocks forever while we keep draining output.
                    stdin_open = false;
                    let _ = write_all(master, &[0x04]);
                }
                Ok(n) => write_all(master, &buf[..n])?,
                Err(nix::errno::Errno::EINTR) => {}
                Err(e) => return Err(e.into()),
            }
        }

        if master_revents.intersects(PollFlags::POLLHUP | PollFlags::POLLERR) {
            break;
        }
    }
    Ok(())
}

fn install_sigwinch_forward(master_fd: RawFd) -> Result<()> {
    use signal_hook::consts::SIGWINCH;
    use signal_hook::iterator::Signals;

    let mut signals = Signals::new([SIGWINCH])?;
    std::thread::spawn(move || {
        for _ in &mut signals {
            let mut ws = nix::libc::winsize {
                ws_row: 0,
                ws_col: 0,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            unsafe {
                if nix::libc::ioctl(0, nix::libc::TIOCGWINSZ, &mut ws) == 0 {
                    let _ = nix::libc::ioctl(master_fd, nix::libc::TIOCSWINSZ, &ws);
                }
            }
        }
    });
    Ok(())
}
