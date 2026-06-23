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

    #[test]
    fn matches_one_of_many_roots() {
        assert!(path_under_any_root(
            Path::new("/scratch/x"),
            "/tmp:/scratch:/data"
        ));
    }
}
