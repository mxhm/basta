//! Agent seccomp-bpf denylist. Built into a sealed memfd and handed to
//! bubblewrap via `--seccomp FD`; bwrap installs it on the agent just
//! before exec, and it is inherited across the agent's whole process
//! tree. Default-ALLOW with a curated set of dangerous syscalls denied
//! (-> EPERM). Configurable via --allow-syscall / --deny-syscall /
//! --no-seccomp. See research/agent-seccomp.md.
//!
//! seccompiler prefixes every compiled filter with an architecture
//! validation prologue that returns SECCOMP_RET_KILL_PROCESS on a
//! foreign ABI — so an i386 binary is killed the instant it issues any
//! syscall (`foreign_arch_is_killed`). The x32 ABI shares
//! AUDIT_ARCH_X86_64 and slips that prologue, so each denied syscall is
//! also denied under its x32 number `nr | X32_SYSCALL_BIT`
//! (`x32_denied_syscalls_are_twinned`) — a denial holds on both ABIs.
//!
//! Namespace scope: `unshare` and `setns` (the namespace-*entry/admin*
//! syscalls) are denied. `clone`/`clone3` are NOT — they are needed for
//! fork and threads, and `clone3`'s flags live in a userspace struct that
//! seccomp cannot dereference, so filtering its namespace bits is not
//! reliable. Creating a nested user namespace via `clone(CLONE_NEWUSER)`
//! is therefore possible, but grants no escape: this filter is inherited
//! into the new namespace, so `mount`/`setns`/etc. stay denied there; a new
//! mount ns cannot mount, and a new net ns has no uplink (the egress filter
//! lives on the configured netns). The boundary does not rely on blocking
//! namespace creation.

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::os::fd::OwnedFd;

use crate::cli::Cli;

/// Every syscall basta has a security opinion about — the toggle vocabulary
/// for --allow-syscall / --deny-syscall. A name outside this table is a
/// hard preflight error. NOT the full syscall list by design (research
/// §3.3): denying an arbitrary non-dangerous syscall is not a use case.
const KNOWN: &[(&str, i64)] = &[
    // --- Tier 1: capability-independent (default-denied) ---
    ("io_uring_setup", libc::SYS_io_uring_setup),
    ("io_uring_enter", libc::SYS_io_uring_enter),
    ("io_uring_register", libc::SYS_io_uring_register),
    ("add_key", libc::SYS_add_key),
    ("request_key", libc::SYS_request_key),
    ("keyctl", libc::SYS_keyctl),
    ("userfaultfd", libc::SYS_userfaultfd),
    ("bpf", libc::SYS_bpf),
    // --- Tier 2: capability-gated defense-in-depth (default-denied) ---
    ("mount", libc::SYS_mount),
    ("umount2", libc::SYS_umount2),
    ("pivot_root", libc::SYS_pivot_root),
    ("chroot", libc::SYS_chroot),
    ("mount_setattr", libc::SYS_mount_setattr),
    ("open_tree", libc::SYS_open_tree),
    ("move_mount", libc::SYS_move_mount),
    ("fsopen", libc::SYS_fsopen),
    ("fsconfig", libc::SYS_fsconfig),
    ("fsmount", libc::SYS_fsmount),
    ("fspick", libc::SYS_fspick),
    ("setns", libc::SYS_setns),
    ("unshare", libc::SYS_unshare),
    ("name_to_handle_at", libc::SYS_name_to_handle_at),
    ("open_by_handle_at", libc::SYS_open_by_handle_at),
    ("init_module", libc::SYS_init_module),
    ("finit_module", libc::SYS_finit_module),
    ("delete_module", libc::SYS_delete_module),
    ("kexec_load", libc::SYS_kexec_load),
    ("kexec_file_load", libc::SYS_kexec_file_load),
    ("acct", libc::SYS_acct),
    ("quotactl", libc::SYS_quotactl),
    ("swapon", libc::SYS_swapon),
    ("swapoff", libc::SYS_swapoff),
    ("syslog", libc::SYS_syslog),
    ("uselib", libc::SYS_uselib),
    // --- NOT default-denied: dev syscalls, toggle-able via --deny-syscall ---
    ("ptrace", libc::SYS_ptrace),
    ("process_vm_readv", libc::SYS_process_vm_readv),
    ("process_vm_writev", libc::SYS_process_vm_writev),
    ("perf_event_open", libc::SYS_perf_event_open),
    ("personality", libc::SYS_personality),
    ("move_pages", libc::SYS_move_pages),
    ("mbind", libc::SYS_mbind),
    ("migrate_pages", libc::SYS_migrate_pages),
    ("get_mempolicy", libc::SYS_get_mempolicy),
    ("set_mempolicy", libc::SYS_set_mempolicy),
];

/// The curated default denylist (names; all must be in KNOWN — asserted
/// by a unit test). Tier 1 + Tier 2 of plan §4.
const DEFAULT_DENYLIST: &[&str] = &[
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "add_key",
    "request_key",
    "keyctl",
    "userfaultfd",
    "bpf",
    "mount",
    "umount2",
    "pivot_root",
    "chroot",
    "mount_setattr",
    "open_tree",
    "move_mount",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "setns",
    "unshare",
    "name_to_handle_at",
    "open_by_handle_at",
    "init_module",
    "finit_module",
    "delete_module",
    "kexec_load",
    "kexec_file_load",
    "acct",
    "quotactl",
    "swapon",
    "swapoff",
    "syslog",
    "uselib",
];

/// x32 syscalls run under AUDIT_ARCH_X86_64 (the arch prologue does not
/// catch them) with this bit OR'd into the syscall number. Every denied
/// syscall is also denied under `nr | X32_SYSCALL_BIT` so a denial
/// cannot be bypassed via the x32 ABI.
const X32_SYSCALL_BIT: i64 = 0x4000_0000;

/// Resolve a syscall name to its number. Hard error on an unknown name.
pub fn resolve(name: &str) -> Result<i64> {
    KNOWN
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, nr)| *nr)
        .with_context(|| {
            format!(
                "unknown syscall name '{name}' — basta only recognises \
                 security-relevant syscalls for --allow-syscall/--deny-syscall"
            )
        })
}

/// Reverse lookup for human-readable output (--dry-run / --trace).
fn name_of(nr: i64) -> &'static str {
    KNOWN
        .iter()
        .find(|(_, n)| *n == nr)
        .map(|(name, _)| *name)
        .unwrap_or("?")
}

/// Compute the effective denylist: (DEFAULT ∪ --deny-syscall) ∖ --allow-syscall.
/// Sorted, deduplicated. --allow-syscall always wins.
pub fn effective_denylist(cli: &Cli) -> Result<Vec<i64>> {
    use std::collections::BTreeSet;
    let mut set: BTreeSet<i64> = BTreeSet::new();
    for name in DEFAULT_DENYLIST {
        set.insert(resolve(name)?);
    }
    for name in &cli.deny_syscall {
        set.insert(resolve(name)?);
    }
    for name in &cli.allow_syscall {
        set.remove(&resolve(name)?);
    }
    Ok(set.into_iter().collect())
}

/// One-line (plus list) human summary for --dry-run / --trace.
pub fn describe(cli: &Cli) -> Result<String> {
    if cli.no_seccomp {
        return Ok("seccomp: DISABLED (--no-seccomp)".to_string());
    }
    let denied = effective_denylist(cli)?;
    let names: Vec<&str> = denied.iter().map(|nr| name_of(*nr)).collect();
    Ok(format!(
        "seccomp: agent denylist — {} syscalls + socket(AF_ALG) -> EPERM; \
         foreign-arch (32-bit) -> KILL\n  {}",
        denied.len(),
        names.join(", ")
    ))
}

/// Build the filter and write it to a sealed memfd in bwrap `--seccomp FD`
/// wire format (a raw compiled cBPF program). None if --no-seccomp.
pub fn agent_filter_memfd(cli: &Cli) -> Result<Option<OwnedFd>> {
    if cli.no_seccomp {
        return Ok(None);
    }
    let denied = effective_denylist(cli)?;
    let prog = build_program(&denied).context("compiling the agent seccomp filter")?;
    // SAFETY: sock_filter is #[repr(C)] and 8 bytes; BpfProgram is
    // Vec<sock_filter>. The borrow lives only for the sealed_memfd copy
    // below, which reads `len` bytes — exactly size_of_val of the slice.
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            prog.as_ptr() as *const u8,
            std::mem::size_of_val(prog.as_slice()),
        )
    };
    let fd = crate::argv::sealed_memfd("basta-seccomp", bytes)
        .context("writing the seccomp filter memfd")?;
    Ok(Some(fd))
}

/// A `SeccompRule` matching `socket(2)`'s first argument exactly
/// (`arg0 == val`). Both seccomp sites that pin `socket` by address family
/// — the agent's `AF_ALG` denial here and the SNI proxy's `AF_INET`-only
/// allow — build their rule through this one helper, so the two are
/// provably the same construction. Built fresh per call (a rule is moved
/// into the filter map, and `socket` is inserted under two ABI numbers).
pub(crate) fn arg0_eq_rule(val: u64) -> Result<seccompiler::SeccompRule> {
    use seccompiler::{SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompRule};
    SeccompRule::new(vec![
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, val)
            .map_err(|e| anyhow::anyhow!("seccomp condition: {e}"))?,
    ])
    .map_err(|e| anyhow::anyhow!("seccomp rule: {e}"))
}

/// Compile the denylist into a cBPF program: default action ALLOW, every
/// denied syscall (and socket(AF_ALG)) -> ERRNO(EPERM), under both the
/// native and the x32 syscall number. seccompiler also emits an
/// arch-validation prologue that KILLs any foreign-ABI (i386) caller.
fn build_program(denied: &[i64]) -> Result<seccompiler::BpfProgram> {
    use seccompiler::{SeccompAction, SeccompFilter, SeccompRule};

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    // Empty rule vec == unconditional match -> the (match) action. Each
    // denied syscall is inserted under its native AND x32 number.
    for &nr in denied {
        rules.insert(nr, vec![]);
        rules.insert(nr | X32_SYSCALL_BIT, vec![]);
    }
    // Fixed arg-filtered rule: deny socket(AF_ALG, ...) specifically, on
    // both ABIs. Skipped if the user has whole-denied `socket` (not in
    // KNOWN, so it cannot happen today — defensive).
    if !denied.contains(&libc::SYS_socket) {
        rules.insert(libc::SYS_socket, vec![arg0_eq_rule(libc::AF_ALG as u64)?]);
        rules.insert(
            libc::SYS_socket | X32_SYSCALL_BIT,
            vec![arg0_eq_rule(libc::AF_ALG as u64)?],
        );
    }

    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| anyhow::anyhow!("seccomp: unsupported arch: {e}"))?;
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow, // unlisted syscall -> allow (denylist)
        SeccompAction::Errno(libc::EPERM as u32), // listed syscall   -> EPERM
        arch,
    )
    .map_err(|e| anyhow::anyhow!("seccomp filter: {e}"))?;
    filter
        .try_into()
        .map_err(|e| anyhow::anyhow!("seccomp compile: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn cli() -> Cli {
        Cli::parse_from(["basta", "--", "true"])
    }

    #[test]
    fn default_denylist_names_all_resolve() {
        for name in DEFAULT_DENYLIST {
            assert!(resolve(name).is_ok(), "default name {name} not in KNOWN");
        }
    }

    #[test]
    fn resolve_rejects_unknown() {
        assert!(resolve("definitely_not_a_syscall").is_err());
    }

    #[test]
    fn allow_removes_deny_adds_allow_wins() {
        let mut c = cli();
        let base = effective_denylist(&c).unwrap().len();
        c.allow_syscall = vec!["bpf".into()];
        assert_eq!(effective_denylist(&c).unwrap().len(), base - 1);
        c.allow_syscall = vec![];
        c.deny_syscall = vec!["ptrace".into()];
        assert_eq!(effective_denylist(&c).unwrap().len(), base + 1);
        // both -> allow wins
        c.allow_syscall = vec!["ptrace".into()];
        assert_eq!(effective_denylist(&c).unwrap().len(), base);
    }

    #[test]
    fn build_program_is_nonempty() {
        let denied = effective_denylist(&cli()).unwrap();
        assert!(!build_program(&denied).unwrap().is_empty());
    }

    /// The compiled filter MUST kill a foreign-arch (32-bit i386) caller.
    /// seccompiler prefixes every program with a 3-instruction arch
    /// validation: LD arch, JEQ x86_64, RET KILL_PROCESS. Pin it so a
    /// seccompiler bump cannot silently regress the 32-bit-kill guarantee.
    #[test]
    fn foreign_arch_is_killed() {
        let prog = build_program(&effective_denylist(&cli()).unwrap()).unwrap();
        // instr 0: BPF_LD|BPF_W|BPF_ABS @ seccomp_data.arch offset (4).
        assert_eq!(prog[0].code, 0x20);
        assert_eq!(prog[0].k, 4);
        // instr 2: BPF_RET|BPF_K = SECCOMP_RET_KILL_PROCESS (0x8000_0000).
        assert_eq!(prog[2].code, 0x06);
        assert_eq!(prog[2].k, 0x8000_0000);
    }

    /// Every denied syscall must also be denied under its x32 number, or
    /// the x32 ABI bypasses the denylist (it shares AUDIT_ARCH_X86_64, so
    /// the arch prologue does not catch it). BPF_JMP|BPF_JEQ|BPF_K = 0x15.
    #[test]
    fn x32_denied_syscalls_are_twinned() {
        let prog = build_program(&[libc::SYS_mount]).unwrap();
        let twin = (libc::SYS_mount | X32_SYSCALL_BIT) as u32;
        assert!(
            prog.iter().any(|i| i.code == 0x15 && i.k == twin),
            "x32 twin of a denied syscall is missing from the filter"
        );
    }
}
