use anyhow::{Context, Result, bail};
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

/// A workspace resolved to a canonical path and pinned by an O_PATH fd.
/// bwrap binds via the fd (`--bind-fd N DEST`), so a post-resolve symlink
/// swap on the source side can't redirect.
pub struct Workspace {
    pub fd: OwnedFd,
    pub path: PathBuf,
    pub ro: bool,
}

impl Workspace {
    pub fn resolve(spec: &str) -> Result<Self> {
        let (path_str, ro) = match spec.strip_suffix(":ro") {
            Some(p) => (p, true),
            None => (spec, false),
        };

        let canonical = std::fs::canonicalize(path_str)
            .with_context(|| format!("workspace not found: {path_str}"))?;

        check_allowed_root(&canonical)?;

        let fd = open(
            &canonical,
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("cannot open workspace fd: {}", canonical.display()))?;

        Ok(Workspace {
            fd,
            path: canonical,
            ro,
        })
    }
}

/// Refuse a workspace that would mask a mount basta manages itself.
///
/// bwrap applies operations in argv order and workspaces are emitted LAST
/// (argv.rs), so a workspace bind layers over everything before it. A
/// workspace at `$HOME` therefore puts the host home back over the fresh
/// tmpfs — exposing `~/.ssh` and letting the agent write `~/.local/bin`,
/// which is first on both the sandbox PATH and the caller's login PATH. That
/// silently defeats the sandbox's headline guarantee, so it is refused rather
/// than warned about. `$HOME` itself is the mount; an ancestor of it (`/`,
/// `/home`) would swallow it whole — both are rejected.
///
/// `/tmp`, `/var/tmp` and `/run` are also basta tmpfs mounts, but binding the
/// host's over them exposes no credentials and is an established way to hand
/// the sandbox a scratch dir, so those only warn.
pub fn reject_masking(workspaces: &[Workspace], home: &Path) -> Result<()> {
    for w in workspaces {
        if w.path == home || home.starts_with(&w.path) {
            bail!(
                "workspace '{}' is $HOME (or contains it): it would be bound over the \
                 sandbox's fresh tmpfs $HOME, exposing host credentials (~/.ssh) and \
                 letting the agent write ~/.local/bin, which is on your login PATH. \
                 Bind the specific project directory instead.",
                w.path.display()
            );
        }
        for masked in ["/tmp", "/var/tmp", "/run"] {
            if w.path == Path::new(masked) {
                eprintln!(
                    "basta: WARNING workspace '{masked}' replaces the sandbox's private \
                     tmpfs {masked} with the host's — host temp files are visible and \
                     writable. Bind a subdirectory instead for an isolated scratch space."
                );
            }
        }
    }
    // A later read-write workspace that contains an earlier `:ro` one silently
    // re-opens it for writing (same last-wins ordering), and lockset.rs skips
    // `:ro` workspaces, so the git-autorun lock does not cover it either.
    for (i, ro) in workspaces.iter().enumerate() {
        if !ro.ro {
            continue;
        }
        for rw in workspaces.iter().skip(i + 1).filter(|w| !w.ro) {
            if ro.path.starts_with(&rw.path) {
                bail!(
                    "workspace '{}' is read-write and contains the read-only workspace \
                     '{}': the later bind wins, so ':ro' would not hold. Reorder them or \
                     bind a narrower path.",
                    rw.path.display(),
                    ro.path.display()
                );
            }
        }
    }
    Ok(())
}

fn check_allowed_root(path: &Path) -> Result<()> {
    // Where a workspace may live. Generic FHS default; extend for site
    // paths (cluster NFS, scratch, data mounts) by exporting a custom
    // BASTA_ALLOWED_ROOTS, e.g. "$HOME:/tmp:/mnt:/nfs:/scratch:/data".
    let (roots, from_env) = match std::env::var("BASTA_ALLOWED_ROOTS") {
        Ok(v) => (v, true),
        Err(_) => {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/home".into());
            (format!("{home}:/tmp:/mnt"), false)
        }
    };
    // I2: refuse roots that subsume system directories (e.g. `/` would
    // otherwise let any path through). Applies to both an env-poisoned value
    // and a default computed from a system-dir $HOME (root user / unset HOME).
    reject_system_roots(&roots, from_env)?;
    if path_under_any_root(path, &roots) {
        return Ok(());
    }
    bail!(
        "workspace canonicalises outside BASTA_ALLOWED_ROOTS: {} (roots: {})",
        path.display(),
        roots
    );
}

fn path_under_any_root(path: &Path, roots: &str) -> bool {
    roots
        .split(':')
        .filter(|r| !r.is_empty())
        .any(|r| path == Path::new(r) || path.starts_with(r))
}

/// Reject any root that equals `/` or is a system directory. A root that
/// is a parent of a system dir (e.g., `/etc`'s parent `/`) is also
/// rejected. Caller-supplied roots may still cover those paths *as
/// children* of an explicit non-system prefix.
fn reject_system_roots(roots: &str, from_env: bool) -> Result<()> {
    const SYSTEM: &[&str] = &[
        "/", "/etc", "/usr", "/var", "/sys", "/proc", "/boot", "/root", "/dev", "/bin", "/sbin",
        "/lib", "/lib64", "/home",
    ];
    for r in roots.split(':').filter(|r| !r.is_empty()) {
        let p = Path::new(r);
        for sys in SYSTEM {
            if p == Path::new(sys) {
                if from_env {
                    bail!("BASTA_ALLOWED_ROOTS contains system directory '{r}'");
                }
                bail!(
                    "default workspace root '{r}' is a system directory (your \
                     $HOME?) — set BASTA_ALLOWED_ROOTS to an explicit non-system \
                     path, or run basta from a normal user account"
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_outside_root() {
        assert!(!path_under_any_root(Path::new("/etc"), "/tmp"));
    }

    #[test]
    fn accepts_within_root() {
        assert!(path_under_any_root(Path::new("/tmp"), "/tmp"));
        assert!(path_under_any_root(Path::new("/tmp/sub/dir"), "/tmp"));
    }

    #[test]
    fn empty_root_segment_ignored() {
        assert!(!path_under_any_root(Path::new("/etc"), "::"));
    }

    fn ws(path: &str, ro: bool) -> Workspace {
        let p = std::env::temp_dir().join(format!("basta-ws-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Workspace {
            fd: open(
                &p,
                OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .unwrap(),
            path: PathBuf::from(path),
            ro,
        }
    }

    #[test]
    fn home_workspace_is_refused() {
        let home = Path::new("/home/u");
        // $HOME itself, and any ancestor that would swallow it.
        assert!(reject_masking(&[ws("/home/u", false)], home).is_err());
        assert!(reject_masking(&[ws("/home", false)], home).is_err());
        assert!(reject_masking(&[ws("/", false)], home).is_err());
        // A project dir inside $HOME is the normal case and must still work.
        assert!(reject_masking(&[ws("/home/u/proj", false)], home).is_ok());
        // A read-only bind of $HOME masks the tmpfs just the same.
        assert!(reject_masking(&[ws("/home/u", true)], home).is_err());
    }

    #[test]
    fn rw_workspace_containing_an_ro_one_is_refused() {
        let home = Path::new("/home/u");
        let nested = [ws("/tmp/a/inner", true), ws("/tmp/a", false)];
        assert!(reject_masking(&nested, home).is_err());
        // The reverse order is fine: the :ro bind lands last and wins.
        let ordered = [ws("/tmp/a", false), ws("/tmp/a/inner", true)];
        assert!(reject_masking(&ordered, home).is_ok());
        // Siblings never conflict.
        let siblings = [ws("/tmp/a", true), ws("/tmp/b", false)];
        assert!(reject_masking(&siblings, home).is_ok());
    }

    #[test]
    fn matches_one_of_many_roots() {
        assert!(path_under_any_root(
            Path::new("/scratch/x"),
            "/tmp:/scratch:/data"
        ));
    }
}
