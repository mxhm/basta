use anyhow::{Context, Result, bail};
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Component, Path};

/// One file copied into the sandbox $HOME, writable but ephemeral.
pub struct Seed {
    pub fd: OwnedFd,
    pub dest: String,
}

impl Seed {
    /// An in-memory overlay file (a sealed memfd) bound read-only at an
    /// absolute DEST inside the sandbox — used for the generated
    /// /etc/hosts and /etc/resolv.conf on the egress path. DEST is taken
    /// verbatim (absolute), bypassing the $HOME-relative seed rules.
    pub fn overlay(dest: &str, content: &[u8]) -> Result<Seed> {
        let fd = crate::argv::sealed_memfd("basta-overlay", content)?;
        Ok(Seed {
            fd,
            dest: dest.to_string(),
        })
    }
}

/// All `--seed SRC:DEST` specs resolved: directories to create in the
/// sandbox $HOME, and files to copy in (each pinned by an O_RDONLY fd
/// that bwrap reads via `--file FD DEST`). `hosts`/`resolv` are the
/// generated /etc/hosts and /etc/resolv.conf overlays for the egress
/// path, bound via `--ro-bind-data`.
pub struct SeedSet {
    pub dirs: Vec<String>,
    pub files: Vec<Seed>,
    pub hosts: Option<Seed>,
    pub resolv: Option<Seed>,
}

impl SeedSet {
    pub fn build(specs: &[String], home: &str) -> Result<Self> {
        let mut set = SeedSet {
            dirs: vec![],
            files: vec![],
            hosts: None,
            resolv: None,
        };
        for spec in specs {
            let (src, dest) = parse_src_dest(spec, "--seed")?;
            let dest_abs = resolve_home_dest(home, &dest)?;
            let meta = std::fs::symlink_metadata(&src)
                .with_context(|| format!("--seed: SRC not found: {src}"))?;
            if meta.file_type().is_symlink() {
                bail!("--seed: SRC must not be a symlink: {src}");
            }
            if meta.is_file() {
                set.files.push(Seed {
                    fd: open_ro(Path::new(&src))?,
                    dest: dest_abs,
                });
            } else if meta.is_dir() {
                set.dirs.push(dest_abs.clone());
                let dir_fd = open(
                    Path::new(&src),
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .with_context(|| format!("--seed: cannot open SRC dir: {src}"))?;
                walk(&dir_fd, &dest_abs, &mut set, 0)?;
            } else {
                bail!("--seed: SRC is neither a file nor a directory: {src}");
            }
        }
        Ok(set)
    }
}

/// Cap on `--seed` directory nesting — guards against a pathological or
/// hostile deep tree blowing the stack or generating an enormous argv.
const MAX_SEED_DEPTH: usize = 64;

/// Recurse a seed directory top-down (directories before their contents,
/// so a `--dir` precedes the `--file`s inside it), fd-pinned: each level
/// is reached through `/proc/self/fd/<held-fd>`, so a directory cannot be
/// swapped for a symlink between the check and the open. The held fd is
/// pinned to its inode; `O_NOFOLLOW` rejects a symlink leaf.
fn walk(dir_fd: &OwnedFd, dest: &str, set: &mut SeedSet, depth: usize) -> Result<()> {
    if depth > MAX_SEED_DEPTH {
        bail!("--seed: directory tree deeper than {MAX_SEED_DEPTH}");
    }
    let fd_path = format!("/proc/self/fd/{}", dir_fd.as_raw_fd());
    let mut entries: Vec<std::ffi::OsString> = std::fs::read_dir(&fd_path)
        .with_context(|| format!("--seed: cannot read dir: {dest}"))?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("--seed: cannot read dir entries: {dest}"))?;
    entries.sort();
    for name in entries {
        let name = name
            .to_str()
            .with_context(|| format!("--seed: non-UTF8 entry name in SRC tree under {dest}"))?;
        let child_dest = format!("{dest}/{name}");
        let child_path = format!("{fd_path}/{name}");
        // lstat — does not follow the final component, so a symlink leaf
        // is caught; the parent dir cannot be swapped (it is fd-pinned).
        let meta = std::fs::symlink_metadata(&child_path)
            .with_context(|| format!("--seed: cannot stat: {child_dest}"))?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            bail!("--seed: symlink inside SRC tree not allowed: {child_dest}");
        } else if ft.is_dir() {
            set.dirs.push(child_dest.clone());
            let child_fd = open(
                Path::new(&child_path),
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .with_context(|| format!("--seed: cannot open dir: {child_dest}"))?;
            walk(&child_fd, &child_dest, set, depth + 1)?;
        } else if ft.is_file() {
            set.files.push(Seed {
                fd: open_ro(Path::new(&child_path))?,
                dest: child_dest,
            });
        }
        // Non-regular files (fifo, socket, device) are silently skipped.
    }
    Ok(())
}

/// Open a seed file O_RDONLY. O_NOFOLLOW guards against a symlink swap
/// between the stat above and this open (defence in depth).
fn open_ro(path: &Path) -> Result<OwnedFd> {
    open(
        path,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .with_context(|| format!("--seed: cannot open SRC file: {}", path.display()))
}

/// Split a `SRC:DEST` spec on the LAST colon, so SRC may contain colons.
pub fn parse_src_dest(spec: &str, flag: &str) -> Result<(String, String)> {
    let (src, dest) = spec
        .rsplit_once(':')
        .with_context(|| format!("{flag} needs SRC:DEST, got '{spec}'"))?;
    if src.is_empty() || dest.is_empty() {
        bail!("{flag} needs a non-empty SRC and DEST, got '{spec}'");
    }
    Ok((src.to_string(), dest.to_string()))
}

/// Resolve a DEST relative to the sandbox $HOME. DEST must be relative
/// and contain only normal components — no `.`, `..`, or leading `/` —
/// so it cannot escape $HOME.
pub fn resolve_home_dest(home: &str, dest: &str) -> Result<String> {
    let rel = Path::new(dest);
    if rel.is_absolute() {
        bail!("DEST must be relative to $HOME, got absolute path: {dest}");
    }
    for comp in rel.components() {
        if !matches!(comp, Component::Normal(_)) {
            bail!("DEST must not contain '.' or '..' components: {dest}");
        }
    }
    Ok(Path::new(home).join(rel).to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_splits_on_last_colon() {
        let (s, d) = parse_src_dest("/a/b:c/d", "--seed").unwrap();
        assert_eq!(s, "/a/b");
        assert_eq!(d, "c/d");
    }

    #[test]
    fn parse_src_may_contain_colon() {
        let (s, d) = parse_src_dest("/a:b/c:dest", "--seed").unwrap();
        assert_eq!(s, "/a:b/c");
        assert_eq!(d, "dest");
    }

    #[test]
    fn parse_rejects_missing_colon() {
        assert!(parse_src_dest("/no/colon", "--seed").is_err());
    }

    #[test]
    fn parse_rejects_empty_sides() {
        assert!(parse_src_dest(":dest", "--seed").is_err());
        assert!(parse_src_dest("src:", "--seed").is_err());
    }

    #[test]
    fn dest_resolves_under_home() {
        assert_eq!(
            resolve_home_dest("/home/u", ".omp/agent/config.yml").unwrap(),
            "/home/u/.omp/agent/config.yml"
        );
    }

    #[test]
    fn dest_rejects_escape() {
        assert!(resolve_home_dest("/home/u", "/etc/passwd").is_err());
        assert!(resolve_home_dest("/home/u", "../escape").is_err());
        assert!(resolve_home_dest("/home/u", "a/../../b").is_err());
        assert!(resolve_home_dest("/home/u", "./x").is_err());
    }
}
