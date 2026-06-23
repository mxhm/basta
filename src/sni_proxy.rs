//! The basta SNI egress proxy — an internal re-exec (`basta __sni-proxy`).
//!
//! Spawned by the basta parent next to pasta, it joins the sandbox's
//! netns+userns (the pasta pattern) and, for every connection redirected
//! (or directly addressed) to 127.0.0.1:<port>:
//!
//! 1. reassembles + parses the TLS ClientHello, extracts the SNI;
//! 2. exact-matches it against the launch allowlist — fail closed on
//!    any miss, malformed input, non-TLS, no-SNI, or peek-deadline;
//! 3. dials the launch-resolved IP for that name with SO_MARK set;
//! 4. replays the buffered ClientHello and splices bytes both ways.
//!
//! No TLS termination, no certificate, no MITM.
//!
//! SECURITY: the listener is reachable directly by the sandboxed agent
//! (same netns) — the nft redirect gives transparency, not isolation.
//! Every input here is hostile; the proxy is hardened against connection-
//! flood, slow-drip, and idle-hold resource exhaustion (the agent's goal
//! includes denying the user a working session). After startup it
//! self-sandboxes (no_new_privs, capability-bounding-set reduction, a
//! seccomp allowlist) — see `harden`.

use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::client_hello::{MAX_PEEK, Scan, scan};

/// Max concurrent connections served; beyond this, accept-and-close.
const MAX_CONNS: usize = 256;
/// Absolute wall-clock budget to receive a complete ClientHello.
const PEEK_DEADLINE: Duration = Duration::from_secs(10);
/// Max read() syscalls peek_sni will make for one ClientHello. A
/// conformant client delivers it in a few reads; a byte-drip attacker
/// needs hundreds-plus. Capping the count bounds the whole-buffer re-scan
/// to O(MAX_PEEK_READS * MAX_PEEK) instead of O(n^2). 128 is ~8x headroom
/// over the worst realistic legitimate case (a ~24 KiB ClientHello over a
/// small-MSS link).
const MAX_PEEK_READS: usize = 128;
/// Per-IP upstream connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// A spliced connection idle (zero bytes BOTH ways) longer than this is
/// reclaimed. Generous — streaming responses keep it fresh; only truly
/// abandoned connections are closed.
const RELAY_IDLE_LIMIT: Duration = Duration::from_secs(30 * 60);
const RELAY_IDLE_CHECK: Duration = Duration::from_secs(60);

struct Config {
    pid: i32,
    port: u16,
    mark: u32,
    allow: HashMap<String, Vec<Ipv4Addr>>,
}

/// Entry point for `basta __sni-proxy`. Serves until killed by the parent's
/// StackGuard when the sandbox exits.
pub fn run() -> Result<()> {
    let cfg = read_config().context("reading SNI proxy config")?;
    join_namespaces(cfg.pid).context("joining the sandbox namespaces")?;

    // Wait for pasta's default route before declaring readiness, so a
    // launch cannot race a proxy that cannot yet reach upstream.
    crate::netns::wait_for_default_route(Duration::from_secs(5))
        .context("pasta default route not up in the sandbox netns")?;

    let listener = TcpListener::bind(("127.0.0.1", cfg.port))
        .with_context(|| format!("binding 127.0.0.1:{}", cfg.port))?;

    // Self-sandbox before serving — and before announcing readiness, so a
    // harden failure aborts the launch (fail closed).
    harden().context("hardening the SNI proxy process")?;

    // Readiness handshake — the parent gates the sandbox launch on this.
    println!("LISTENING");
    io::stdout().flush().ok();

    let cfg = Arc::new(cfg);
    let active = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let Ok(client) = conn else { continue }; // transient accept error
        // Connection cap — a flood must not exhaust the proxy.
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNS {
            active.fetch_sub(1, Ordering::SeqCst);
            drop(client);
            continue;
        }
        let cfg = Arc::clone(&cfg);
        let active = Arc::clone(&active);
        std::thread::spawn(move || {
            handle(client, &cfg);
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

/// Parse the line-oriented config delivered on stdin by the basta parent.
/// Trusted input, but still fail closed on anything unexpected.
fn read_config() -> Result<Config> {
    let mut text = String::new();
    io::stdin()
        .read_to_string(&mut text)
        .context("reading config from stdin")?;
    let (mut pid, mut port, mut mark) = (None, None, None);
    let mut allow: HashMap<String, Vec<Ipv4Addr>> = HashMap::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut t = line.split_whitespace();
        match t.next() {
            Some("pid") => pid = Some(t.next().context("pid value")?.parse()?),
            Some("port") => port = Some(t.next().context("port value")?.parse()?),
            Some("mark") => mark = Some(t.next().context("mark value")?.parse()?),
            Some("host") => {
                let host = t.next().context("host name")?.to_ascii_lowercase();
                let addrs = t
                    .map(str::parse)
                    .collect::<Result<Vec<Ipv4Addr>, _>>()
                    .context("host address")?;
                if addrs.is_empty() {
                    bail!("config: host '{host}' has no addresses");
                }
                allow.insert(host, addrs);
            }
            other => bail!("config: unrecognized line: {other:?}"),
        }
    }
    Ok(Config {
        pid: pid.context("config: missing pid")?,
        port: port.context("config: missing port")?,
        mark: mark.context("config: missing mark")?,
        allow,
    })
}

/// Join the sandbox child's user + network namespaces. userns first:
/// joining it grants the capability set that setns(net) and the per-
/// connection SO_MARK both require. Single-threaded — `run` has not
/// spawned a thread yet. (Same mechanism pasta uses to attach by PID.)
fn join_namespaces(pid: i32) -> Result<()> {
    use nix::sched::{CloneFlags, setns};
    let user = open_ns(pid, "user")?;
    let net = open_ns(pid, "net")?;
    setns(user, CloneFlags::CLONE_NEWUSER).context("setns user")?;
    setns(net, CloneFlags::CLONE_NEWNET).context("setns net")?;
    Ok(())
}

fn open_ns(pid: i32, kind: &str) -> Result<OwnedFd> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;
    let path = format!("/proc/{pid}/ns/{kind}");
    open(
        path.as_str(),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("open {path}"))
}

/// Self-sandbox the proxy AFTER startup (setns / route-check / bind done —
/// nothing below needs the filesystem or a privileged syscall). This
/// converts a hypothetical parser/dependency compromise from "code
/// execution as the host user" into "a process confined to moving bytes
/// between sockets it already holds." The only `unsafe` in this module is
/// the localized raw-prctl code reached from here.
fn harden() -> Result<()> {
    set_no_new_privs().context("PR_SET_NO_NEW_PRIVS")?;
    set_undumpable().context("PR_SET_DUMPABLE 0")?;
    // SO_MARK still needs CAP_NET_ADMIN; drop every OTHER capability from
    // the bounding set, then from the effective + permitted sets too.
    drop_cap_bounding_set_except_net_admin().context("cap bounding set")?;
    drop_caps_to_net_admin().context("cap effective/permitted set")?;
    install_seccomp().context("seccomp filter")?;
    Ok(())
}

/// `prctl(PR_SET_NO_NEW_PRIVS)` — required for an unprivileged seccomp
/// filter; also blocks setuid-binary escalation.
fn set_no_new_privs() -> Result<()> {
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS and constant scalar args.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// `prctl(PR_SET_DUMPABLE, 0)` — no core dumps, no same-uid `ptrace`.
fn set_undumpable() -> Result<()> {
    // SAFETY: prctl with PR_SET_DUMPABLE 0 and constant scalar args.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Reduce the capability bounding set to `CAP_NET_ADMIN` alone — the proxy
/// keeps it only for `SO_MARK`. Caps unknown to this kernel are skipped.
fn drop_cap_bounding_set_except_net_admin() -> Result<()> {
    const CAP_NET_ADMIN: i32 = 12;
    for cap in 0..=63i32 {
        if cap == CAP_NET_ADMIN {
            continue;
        }
        // SAFETY: prctl PR_CAPBSET_READ/_DROP with a scalar cap index.
        let present = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap as libc::c_ulong, 0, 0, 0) };
        if present <= 0 {
            continue; // unknown to this kernel, or already not present
        }
        // SAFETY: as above.
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("PR_CAPBSET_DROP cap {cap}"));
        }
    }
    Ok(())
}

/// Drop the effective + permitted capability sets to `CAP_NET_ADMIN`
/// alone (the proxy needs it for `SO_MARK`; nothing else).
/// `drop_cap_bounding_set_except_net_admin` handles `CapBnd`; this handles
/// `CapEff`/`CapPrm`, which it leaves untouched. Dropping `permitted` is
/// irreversible — fine, the proxy never raises another capability. The
/// per-connection `SO_MARK` dials happen after `harden()`, with
/// `CAP_NET_ADMIN` still effective.
fn drop_caps_to_net_admin() -> Result<()> {
    // _LINUX_CAPABILITY_VERSION_3 — the 64-bit (2 x 32-bit word) cap ABI.
    const VERSION_3: u32 = 0x2008_0522;
    const CAP_NET_ADMIN: u32 = 12;
    // PR_CAP_AMBIENT / PR_CAP_AMBIENT_CLEAR_ALL — not in `libc` for the
    // musl target (only L4Re/Android); the kernel ABI values are fixed.
    const PR_CAP_AMBIENT: libc::c_int = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_int = 4;

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let hdr = CapHeader {
        version: VERSION_3,
        pid: 0, // 0 = self
    };
    let bit = 1u32 << CAP_NET_ADMIN;
    let data = [
        CapData {
            effective: bit,
            permitted: bit,
            inheritable: 0,
        }, // caps 0-31
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }, // caps 32-63
    ];
    // SAFETY: capset(2) with a v3 header and a 2-element data array — the
    // ABI-required shapes; both pointers are to local #[repr(C)] structs.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &hdr as *const CapHeader, data.as_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("capset");
    }

    // The ambient set is already empty (the proxy never raises it); clear
    // it explicitly as belt-and-suspenders.
    // SAFETY: prctl with constant scalar args.
    unsafe {
        libc::prctl(
            PR_CAP_AMBIENT,
            PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
            0,
            0,
        );
    }
    Ok(())
}

/// Build + install the seccomp-bpf allowlist (`SECCOMP_RET_KILL_PROCESS`
/// on a syscall outside the set — fail closed). Load-bearing denials:
/// `execve`/`execveat` (no shell, no other binary); `open`/`openat`/
/// `openat2` (no filesystem — the proxy opens nothing post-startup);
/// `ptrace`/`mount`/`setns`; and AF_NETLINK/AF_UNIX socket creation —
/// `socket()` is pinned to `AF_INET`, so a compromised proxy cannot
/// reprogram the netns nft rules despite holding `CAP_NET_ADMIN`.
fn install_seccomp() -> Result<()> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
    use std::collections::BTreeMap;

    // Syscalls the accept loop, the thread-per-connection relays, and the
    // musl runtime need. Curated against the running proxy; KILL_PROCESS
    // catches anything outside it.
    let allowed: &[i64] = &[
        // socket I/O
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_recvfrom,
        libc::SYS_sendto,
        libc::SYS_recvmsg,
        libc::SYS_sendmsg,
        libc::SYS_accept4,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_shutdown,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        // fd / socket flag manipulation
        libc::SYS_fcntl,
        libc::SYS_ioctl,
        // event wait
        libc::SYS_ppoll,
        libc::SYS_poll,
        // threads + synchronization
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_futex,
        libc::SYS_set_robust_list,
        libc::SYS_set_tid_address,
        libc::SYS_rseq,
        libc::SYS_sched_yield,
        // memory
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_madvise,
        libc::SYS_brk,
        // signals (per-thread setup, panic=abort path)
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_tgkill,
        // time
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        // misc runtime
        libc::SYS_getrandom,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_restart_syscall,
    ];

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &sc in allowed {
        rules.insert(sc, vec![]);
    }
    // socket() — pinned to AF_INET so no AF_NETLINK / AF_UNIX socket can
    // be opened (the netlink lockdown that makes CAP_NET_ADMIN safe).
    rules.insert(
        libc::SYS_socket,
        vec![crate::seccomp::arg0_eq_rule(libc::AF_INET as u64)?],
    );

    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| anyhow::anyhow!("seccomp: unsupported arch: {e}"))?;
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess, // mismatch → fail closed
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e| anyhow::anyhow!("seccomp filter: {e}"))?;
    let prog: BpfProgram = filter
        .try_into()
        .map_err(|e| anyhow::anyhow!("seccomp compile: {e}"))?;
    seccompiler::apply_filter(&prog).map_err(|e| anyhow::anyhow!("seccomp apply: {e}"))?;
    Ok(())
}

/// One connection: peek the SNI, allowlist-check, dial, replay, splice.
/// Every failure path drops the connection — fail closed.
fn handle(mut client: TcpStream, cfg: &Config) {
    let Some((sni, hello)) = peek_sni(&mut client) else {
        return;
    };
    let Some(addrs) = cfg.allow.get(&sni) else {
        return; // not allowlisted
    };
    let Some(mut upstream) = dial_upstream(addrs, cfg.mark) else {
        return;
    };
    if upstream.write_all(&hello).is_err() {
        return; // replay the bytes consumed by the peek
    }
    relay(client, upstream);
}

/// Read until a complete ClientHello is parsed, under an ABSOLUTE
/// deadline (a per-read timeout never trips a 1-byte-per-N-seconds drip).
/// Returns the lowercased SNI and the raw bytes consumed (to replay
/// upstream), or None on any malformed / non-TLS / no-SNI / timeout /
/// oversize input.
fn peek_sni(client: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let deadline = Instant::now() + PEEK_DEADLINE;
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let mut reads = 0usize;
    loop {
        match scan(&buf) {
            Scan::Done(Some(sni)) => {
                client.set_read_timeout(None).ok()?; // blocking for the relay
                return Some((sni, buf));
            }
            Scan::Done(None) | Scan::Invalid => return None,
            Scan::Incomplete => {}
        }
        if buf.len() >= MAX_PEEK {
            return None;
        }
        reads += 1;
        if reads > MAX_PEEK_READS {
            return None; // byte-drip: too many reads for one ClientHello
        }
        // None once the absolute deadline has passed → fail closed.
        let remaining = deadline.checked_duration_since(Instant::now())?;
        client.set_read_timeout(Some(remaining)).ok()?;
        // F8c: clamp the read so buf can never exceed MAX_PEEK. The
        // `buf.len() >= MAX_PEEK` check above guarantees room >= 1.
        let room = MAX_PEEK - buf.len();
        let want = room.min(chunk.len());
        match client.read(&mut chunk[..want]) {
            Ok(0) => return None, // EOF before a complete ClientHello
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return None, // timeout / reset
        }
    }
}

/// Dial one of the launch-resolved IPs on :443, SO_MARK set BEFORE
/// connect. The destination comes only from the allowlisted name — never
/// from anything the client asserted.
fn dial_upstream(addrs: &[Ipv4Addr], mark: u32) -> Option<TcpStream> {
    addrs
        .iter()
        .find_map(|&ip| dial_one(ip, mark, CONNECT_TIMEOUT))
}

/// One marked, time-bounded connect. Non-blocking connect + poll, so a
/// black-holed IP cannot stall the launch (or a connection thread).
fn dial_one(ip: Ipv4Addr, mark: u32, timeout: Duration) -> Option<TcpStream> {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use nix::sys::socket::{
        AddressFamily, SockFlag, SockType, SockaddrIn, connect, getsockopt, setsockopt, socket,
        sockopt::{Mark, SocketError},
    };
    let fd = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        None,
    )
    .ok()?;
    setsockopt(&fd, Mark, &mark).ok()?;
    let o = ip.octets();
    let addr = SockaddrIn::new(o[0], o[1], o[2], o[3], 443);
    match connect(fd.as_raw_fd(), &addr) {
        Ok(()) => {}
        Err(nix::errno::Errno::EINPROGRESS) => {
            let ms = timeout.as_millis().min(60_000) as u16;
            let mut fds = [PollFd::new(fd.as_fd(), PollFlags::POLLOUT)];
            match poll(&mut fds, PollTimeout::from(ms)) {
                Ok(1) => {
                    // Connected or failed — SO_ERROR tells which.
                    if getsockopt(&fd, SocketError).ok()? != 0 {
                        return None;
                    }
                }
                _ => return None, // timeout or poll error
            }
        }
        Err(_) => return None,
    }
    let stream = TcpStream::from(fd);
    stream.set_nonblocking(false).ok()?; // blocking for the relay
    Some(stream)
}

/// Splice bytes both ways until each direction half-closes, or until the
/// connection has been fully idle (both directions) past RELAY_IDLE_LIMIT.
fn relay(client: TcpStream, upstream: TcpStream) {
    let Ok(client_rd) = client.try_clone() else {
        return;
    };
    let Ok(upstream_rd) = upstream.try_clone() else {
        return;
    };
    let last = Arc::new(Mutex::new(Instant::now()));
    let last2 = Arc::clone(&last);
    let t = std::thread::spawn(move || pipe(upstream_rd, client, &last2));
    pipe(client_rd, upstream, &last);
    let _ = t.join();
}

/// Copy src → dst until EOF; then half-close dst's write side. A read
/// timeout (RELAY_IDLE_CHECK) lets the thread re-check the shared last-
/// activity clock — it closes only when BOTH directions have been idle
/// past the limit, so a one-way streaming response is never cut.
/// (Rust's runtime sets SIGPIPE to SIG_IGN, so a write to a closed peer
/// returns Err rather than killing the proxy.)
fn pipe(mut src: TcpStream, mut dst: TcpStream, last: &Mutex<Instant>) {
    let _ = src.set_read_timeout(Some(RELAY_IDLE_CHECK));
    // Bound the write side too: without this a peer that stops reading
    // hangs the relay thread in write_all forever and the idle-reclaim
    // below never runs.
    let _ = dst.set_write_timeout(Some(RELAY_IDLE_CHECK));
    let mut buf = [0u8; 16 * 1024];
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if let Ok(mut g) = last.lock() {
                    *g = Instant::now();
                }
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                let idle = last.lock().map(|g| g.elapsed()).unwrap_or_default();
                if idle > RELAY_IDLE_LIMIT {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = dst.shutdown(Shutdown::Write);
}
