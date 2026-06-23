use anyhow::{Context, Result, bail};
use nix::fcntl::OFlag;
use nix::sched::{CloneFlags, unshare};
use nix::unistd::{Pid, pipe2};
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::cli::Cli;
use crate::egress::{EgressSpec, PROXY_MARK, PROXY_PORT, SniRule};
use crate::pty;
use crate::seed::SeedSet;
use crate::workspace::Workspace;

/// Filtered egress (`--allow`). The Rust child unshares an unprivileged
/// userns+netns BEFORE bwrap exec, brings `lo` up, and loads a
/// netns-local nftables `output`-drop filter. The parent then spawns
/// `pasta` — unprivileged — attached to the child PID; pasta joins the
/// netns+userns and supplies connectivity. bwrap inherits the configured
/// netns via `--share-net`. No host privilege, no persistent state.
pub fn run_egress(
    argv: Vec<String>,
    cli: &Cli,
    workspaces: Vec<Workspace>,
    seeds: SeedSet,
    egress: EgressSpec,
) -> Result<i32> {
    // ready: child writes one byte after the netns is filtered; parent reads.
    // go:    parent writes one byte after pasta is spawned; child reads.
    // O_CLOEXEC so bwrap never inherits the pipe ends.
    let (ready_r, ready_w) = pipe2(OFlag::O_CLOEXEC)?;
    let (go_r, go_w) = pipe2(OFlag::O_CLOEXEC)?;
    let ruleset = egress.nft_ruleset();
    let proxy_sni = egress.sni_enabled().then(|| egress.sni.clone());
    let allow_loopback = cli.allow_loopback.clone();

    pty::run(
        argv,
        cli,
        workspaces,
        seeds,
        move || child_unshare_filter_wait(ready_w, go_r, &ruleset),
        move |child_pid| parent_spawn_support(child_pid, ready_r, go_w, proxy_sni, allow_loopback),
    )
}

/// Child side: unshare, filter, wait for pasta.
fn child_unshare_filter_wait(ready_w: OwnedFd, go_r: OwnedFd, ruleset: &str) -> Result<()> {
    // ORDER IS LOAD-BEARING: write the uid/gid maps before CLONE_NEWNET.
    // A netns created before the maps is owned by a userns with no root
    // mapping — the process then lacks CAP_NET_ADMIN over it.
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    unshare(CloneFlags::CLONE_NEWUSER).context("unshare CLONE_NEWUSER")?;
    std::fs::write("/proc/self/setgroups", "deny").context("writing /proc/self/setgroups")?;
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1"))
        .context("writing /proc/self/uid_map")?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1"))
        .context("writing /proc/self/gid_map")?;
    unshare(CloneFlags::CLONE_NEWNET).context("unshare CLONE_NEWNET")?;

    // A fresh netns has `lo` DOWN; the filter's `oifname "lo" accept` and
    // the /etc/hosts localhost lines are dead weight unless lo is UP.
    bring_loopback_up().context("bringing lo up in the sandbox netns")?;
    load_nft(ruleset).context("loading the netns egress filter")?;

    nix::unistd::write(ready_w.as_fd(), &[0u8]).context("signal netns ready")?;
    drop(ready_w);

    // A 0-byte read means the parent dropped go_w without signalling —
    // pasta failed to spawn. Bail instead of exec'ing into a netns with
    // a drop filter and no uplink (fail closed, and loudly).
    let mut buf = [0u8; 1];
    let n = nix::unistd::read(go_r.as_fd(), &mut buf).context("wait for pasta")?;
    if n == 0 {
        bail!("parent closed go pipe before pasta — netns setup failed");
    }

    // pasta's `--config-net` runs asynchronously; gate the exec on the
    // default route it installs actually being present.
    wait_for_default_route(Duration::from_secs(3))
        .context("pasta did not configure the sandbox netns")?;
    Ok(())
}

/// Parent side: wait for the filtered netns, spawn pasta (always) and the
/// SNI proxy (when --allow-sni), release the child. Returns the support
/// processes for StackGuard to kill+reap. Fail closed: any spawn failure
/// kills what was started and aborts the launch.
fn parent_spawn_support(
    child_pid: Pid,
    ready_r: OwnedFd,
    go_w: OwnedFd,
    proxy_sni: Option<Vec<SniRule>>,
    allow_loopback: Vec<u16>,
) -> Result<Vec<Child>> {
    let mut buf = [0u8; 1];
    let n = nix::unistd::read(ready_r.as_fd(), &mut buf).context("read child ready")?;
    if n == 0 {
        bail!("child closed ready pipe before signalling — unshare failed?");
    }

    let mut support: Vec<Child> = vec![];
    match spawn_pasta(child_pid, &allow_loopback) {
        Ok(c) => support.push(c),
        Err(e) => return Err(e),
    }
    if let Some(sni) = proxy_sni {
        match spawn_sni_proxy(child_pid, &sni) {
            Ok(c) => support.push(c),
            Err(e) => {
                kill_all(&mut support); // reap pasta before aborting
                return Err(e);
            }
        }
    }

    // Release the child. Its wait_for_default_route gates pasta; the proxy
    // confirmed both its listener AND its default route before LISTENING.
    nix::unistd::write(go_w.as_fd(), &[0u8]).context("signal child to proceed")?;
    Ok(support)
}

fn kill_all(children: &mut Vec<Child>) {
    for c in children.iter_mut() {
        let _ = c.kill();
    }
    for mut c in children.drain(..) {
        let _ = c.wait();
    }
}

/// pasta attached by bare PID joins the child's netns AND userns and
/// creates+configures a tap. `-f`: explicit foreground (the background
/// default is TTY-dependent). `-m 1500`: pasta's 65520 default stalls
/// real servers. The rest closes pasta's host-bridging defaults so it
/// only NAT-translates the sandbox's outbound connections:
///   --no-map-gw   don't map the gateway address to the host;
///   -t/-u none    no host->sandbox inbound port forwarding;
///   -T none / -T <ports>   sandbox->host-loopback TCP forwarding. `none`
///                 by default — the sandbox cannot reach host services
///                 on 127.0.0.1 (F17). `--allow-loopback PORT` re-enables
///                 it for exactly the listed ports.
///   -U none       no sandbox->host-loopback UDP forwarding.
fn spawn_pasta(child_pid: Pid, allow_loopback: &[u16]) -> Result<Child> {
    let pasta = find_bin("pasta").context("pasta not found")?;
    // -T: namespace->host TCP forwarding. `none` by default (F17 — the
    // sandbox cannot reach host loopback services). Each --allow-loopback
    // PORT adds exactly that port: the sandbox then reaches the host
    // service at 127.0.0.1:PORT, and nothing else on the host.
    let tcp_ns = if allow_loopback.is_empty() {
        "none".to_string()
    } else {
        allow_loopback
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    Command::new(&pasta)
        .args([
            "-f",
            "--config-net",
            "--no-map-gw",
            "-m",
            "1500",
            "-t",
            "none",
            "-u",
            "none",
            "-U",
            "none",
        ])
        .args(["-T", tcp_ns.as_str()])
        .arg(child_pid.as_raw().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", pasta.display()))
}

/// Re-exec this basta binary as `basta __sni-proxy`, hand it the config on
/// stdin, and block until it reports `LISTENING`. The proxy joins the
/// child's netns+userns itself. Fail closed.
fn spawn_sni_proxy(child_pid: Pid, sni: &[SniRule]) -> Result<Child> {
    // `/proc/self/exe` rather than current_exe(): the kernel resolves it
    // to the running binary's inode even if the file was renamed/removed
    // since launch (current_exe() would yield a "(deleted)" path).
    let mut child = Command::new("/proc/self/exe")
        .arg("__sni-proxy")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()) // surfaced on failure
        .spawn()
        .context("spawning /proc/self/exe __sni-proxy")?;

    let cfg = render_proxy_config(child_pid, sni);
    child
        .stdin
        .take()
        .expect("proxy stdin is piped")
        .write_all(cfg.as_bytes())
        .context("writing config to the SNI proxy")?;
    // stdin dropped here → EOF → the proxy stops reading config.

    let stdout = child.stdout.take().expect("proxy stdout is piped");
    // Timeout > the proxy's own <=5s default-route wait + setns + bind.
    match read_line_timeout(stdout, Duration::from_secs(8)) {
        Ok(Some(line)) if line.trim() == "LISTENING" => Ok(child),
        other => {
            let _ = child.kill();
            let _ = child.wait();
            // Drain the proxy's stderr so the real cause is visible.
            let mut err = String::new();
            if let Some(mut se) = child.stderr.take() {
                let _ = std::io::Read::read_to_string(&mut se, &mut err);
            }
            bail!(
                "SNI proxy did not come up ({other:?}){}",
                if err.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", err.trim())
                }
            );
        }
    }
}

fn render_proxy_config(child_pid: Pid, sni: &[SniRule]) -> String {
    let mut s = String::new();
    s.push_str(&format!("pid {}\n", child_pid.as_raw()));
    s.push_str(&format!("port {PROXY_PORT}\n"));
    s.push_str(&format!("mark {PROXY_MARK}\n"));
    for r in sni {
        s.push_str("host ");
        s.push_str(&r.host);
        for a in &r.addrs {
            s.push(' ');
            s.push_str(&a.to_string());
        }
        s.push('\n');
    }
    s
}

/// Read one line from the proxy's stdout, or time out (fail closed).
fn read_line_timeout(
    stdout: std::process::ChildStdout,
    timeout: Duration,
) -> Result<Option<String>> {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    let deadline = Instant::now() + timeout;
    let mut line: Vec<u8> = vec![];
    let mut byte = [0u8; 1];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        let ms = remaining.as_millis() as u16; // <= 8000, fits u16
        let mut fds = [PollFd::new(stdout.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::from(ms)) {
            Ok(0) => return Ok(None),
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
        match nix::unistd::read(stdout.as_fd(), &mut byte) {
            Ok(0) => return Ok(None), // EOF — proxy exited before LISTENING
            Ok(_) if byte[0] == b'\n' => {
                return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
            }
            Ok(_) => {
                line.push(byte[0]);
                if line.len() > 256 {
                    return Ok(None);
                }
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

const IFNAMSIZ: usize = 16;

/// `struct ifreq` — interface name plus a union. basta touches only
/// `ifr_flags` (a `c_short` at offset 16). The kernel copies the full
/// `sizeof(struct ifreq)` (40 bytes on 64-bit) from userspace, so the
/// struct must be padded to that size.
#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; IFNAMSIZ],
    ifr_flags: libc::c_short,
    // Pads the struct to the kernel's sizeof(struct ifreq); never read.
    #[allow(dead_code)]
    _pad: [u8; 22],
}

/// Bring `lo` UP via SIOCSIFFLAGS — no `ip` dependency. The child is
/// root in its userns and owns the netns, so it holds CAP_NET_ADMIN.
fn bring_loopback_up() -> Result<()> {
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error()).context("socket(AF_INET)");
    }
    let sock = unsafe { OwnedFd::from_raw_fd(raw) };
    let fd = sock.as_raw_fd();

    let mut req = IfReq {
        ifr_name: [0; IFNAMSIZ],
        ifr_flags: 0,
        _pad: [0; 22],
    };
    for (slot, &b) in req.ifr_name.iter_mut().zip(b"lo") {
        *slot = b as libc::c_char;
    }

    let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut req as *mut IfReq) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("SIOCGIFFLAGS lo");
    }
    req.ifr_flags |= libc::IFF_UP as libc::c_short;
    let rc = unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &req as *const IfReq) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("SIOCSIFFLAGS lo");
    }
    Ok(())
}

/// Load the egress filter by piping the ruleset to `nft -f -` over stdin
/// — no shell, no argv interpolation, no injection surface.
fn load_nft(ruleset: &str) -> Result<()> {
    let nft = find_bin("nft").context("nft not found")?;
    let mut child = Command::new(&nft)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", nft.display()))?;

    child
        .stdin
        .take()
        .expect("nft stdin is piped")
        .write_all(ruleset.as_bytes())
        .context("writing ruleset to nft stdin")?;

    let out = child.wait_with_output().context("waiting for nft")?;
    if !out.status.success() {
        bail!(
            "nft -f - failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Poll /proc/net/route until pasta has installed a default route, or
/// the timeout elapses (fail closed).
pub(crate) fn wait_for_default_route(timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if has_default_route() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("no default route in the sandbox netns after {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// /proc/net/route: a default route is a row with Destination `00000000`.
pub(crate) fn has_default_route() -> bool {
    let Ok(content) = std::fs::read_to_string("/proc/net/route") else {
        return false;
    };
    content.lines().skip(1).any(|line| {
        let mut cols = line.split_whitespace();
        cols.next(); // Iface
        cols.next().is_some_and(|dest| dest == "00000000")
    })
}

/// Resolve a support binary (bwrap/nft/pasta) to an absolute path in a
/// fixed set of standard system locations. PATH is deliberately NOT
/// consulted: these run pre-sandbox as the host user, so a poisoned PATH
/// must never get to shadow one with a hostile binary. basta-host-setup
/// installs the deps into these locations.
pub fn find_bin(name: &str) -> Option<PathBuf> {
    use nix::unistd::{AccessFlags, access};
    for dir in [
        "/usr/sbin",
        "/sbin",
        "/usr/bin",
        "/bin",
        "/usr/local/sbin",
        "/usr/local/bin",
    ] {
        let p = Path::new(dir).join(name);
        if p.is_file() && access(&p, AccessFlags::X_OK).is_ok() {
            return Some(p);
        }
    }
    None
}
