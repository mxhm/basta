use anyhow::{Context, Result, bail};
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::cli::Cli;
use crate::workspace::Workspace;

/// Recursion cap when descending nested gitdirs (submodules under
/// `.git/modules`, linked worktrees under `.git/worktrees`).
const MAX_GITDIR_DEPTH: usize = 8;

/// Workspace-relative autorun paths locked read-only by default: each is a
/// location the HOST (not the sandbox) later executes code from, so a
/// sandboxed agent must not be able to plant or rewrite it. Present at launch
/// → RO-bound (edits and new files both blocked); absent → watched and
/// reported if the agent creates one. `--unlock PATH` opts a row back out per
/// launch; `--no-lock` drops the whole default set.
///
/// Git internals (`.git/config`, `.git/hooks`, nested submodule/worktree
/// gitdirs) are handled separately by `default_git_leaves` — they recurse and
/// need `.git` pinned as a mountpoint. Strict by default: whole directories
/// are locked, not just their executable leaves. Add a row in a PR when a new
/// host-autorun vector appears.
const DEFAULT_LOCK: &[(&str, &str)] = &[
    (
        ".envrc",
        "direnv auto-runs it on your next cd into this directory",
    ),
    (
        ".vscode",
        "VS Code runs tasks.json / launch.json / settings on folder open",
    ),
    (
        ".idea",
        "JetBrains runs saved run configurations on project open",
    ),
    (
        ".claude",
        "Claude Code loads hooks / settings / commands / agents the host may run",
    ),
    (
        ".mcp.json",
        "names MCP servers the host harness launches as subprocesses",
    ),
];

/// An autorun path that did not exist at launch (so couldn't be RO-bound) and
/// is watched for creation by the time the agent exits.
pub struct WatchPath {
    pub path: PathBuf,
    pub reason: String,
}

/// The lock plan for a launch: pre-block binds (emitted as workspaces) plus
/// the post-run watch set.
pub struct LockPlan {
    pub binds: Vec<Workspace>,
    pub watch: Vec<WatchPath>,
}

/// Build the lock-set binds for every writable workspace. Each is returned as
/// an extra fd-pinned `Workspace`, appended after the user workspaces so the
/// existing argv loop emits them in order: ancestor pins (RW mountpoints)
/// before the RO leaves they protect.
///
/// A locked directory is RO-bound (blocks new *and* existing files); a locked
/// existing file is RO-bound (blocks edits). Every directory strictly between
/// the workspace root and a locked leaf is re-bound RW as its own mountpoint —
/// a mountpoint cannot be renamed or removed (EBUSY), which closes the
/// "rename the parent out of the way, recreate it writable" bypass. The
/// workspace root is already a mountpoint (its own `--bind-fd`).
pub fn plan_for(workspaces: &[Workspace], cli: &Cli) -> Result<LockPlan> {
    let mut binds = Vec::new();
    let mut watch: Vec<WatchPath> = Vec::new();
    for w in workspaces {
        if w.ro {
            continue; // a RO workspace is already non-writable
        }
        let (leaves, mut absent) = locked_leaves(&w.path, cli)?;
        watch.append(&mut absent);

        if leaves.is_empty() {
            continue;
        }

        // Ancestor pins: every directory strictly between W and a leaf.
        let mut pins: BTreeSet<PathBuf> = BTreeSet::new();
        for leaf in &leaves {
            let mut cur = leaf.parent();
            while let Some(d) = cur {
                if d == w.path || !d.starts_with(&w.path) {
                    break;
                }
                pins.insert(d.to_path_buf());
                cur = d.parent();
            }
        }
        // A locked directory is already a RO mountpoint — never RW-pin it.
        for leaf in &leaves {
            pins.remove(leaf);
        }

        // Pins shallow→deep (parent mount before child mount), then leaves.
        let mut pin_vec: Vec<&PathBuf> = pins.iter().collect();
        pin_vec.sort_by_key(|p| p.components().count());
        for p in pin_vec {
            binds.push(open_bind(p, false, true)?);
        }
        for leaf in &leaves {
            let md = std::fs::symlink_metadata(leaf)
                .with_context(|| format!("lock: cannot stat {}", leaf.display()))?;
            // Fail closed: a symlinked lock target can't be RO-bound (bwrap
            // binds the symlink, not its target), and skipping it would leave
            // the autorun file both unlocked AND unwatched. Refuse, unless the
            // caller knowingly --unlocked it (already dropped above) or
            // --no-locked the set.
            if md.file_type().is_symlink() {
                let rel = leaf.strip_prefix(&w.path).unwrap_or(leaf);
                bail!(
                    "lock target {} is a symlink — basta will not lock through it (it \
                     could redirect an autorun file to a writable target). Replace \
                     the symlink, or pass `--unlock {}` / `--no-lock` to proceed.",
                    leaf.display(),
                    rel.display()
                );
            }
            binds.push(open_bind(leaf, true, md.is_dir())?);
        }
    }
    // Dedup watch by path (a --lock .envrc absent + the default .envrc watch).
    watch.sort_by(|a, b| a.path.cmp(&b.path));
    watch.dedup_by(|a, b| a.path == b.path);
    Ok(LockPlan { binds, watch })
}

/// Locked-leaf paths under `wroot` that exist now (→ RO-bound), plus the
/// absent `--lock` paths (→ watched). git defaults (unless `--no-lock`) +
/// `--lock` − `--unlock`.
fn locked_leaves(wroot: &Path, cli: &Cli) -> Result<(Vec<PathBuf>, Vec<WatchPath>)> {
    let mut leaves: Vec<PathBuf> = Vec::new();
    let mut watch: Vec<WatchPath> = Vec::new();
    if !cli.no_lock {
        let git_unlocked = cli.unlock.iter().any(|u| u == ".git");
        default_git_leaves(wroot, &mut leaves, git_unlocked)?;
        for (rel, reason) in DEFAULT_LOCK {
            if cli.unlock.iter().any(|u| u == rel) {
                continue;
            }
            // symlink_metadata, not exists(): a dangling symlink lock target (which
            // exists() reports absent) must reach plan_for's fail-closed symlink check,
            // not be silently watched.
            let p = wroot.join(rel);
            match p.symlink_metadata() {
                Ok(_) => leaves.push(p),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => watch.push(WatchPath {
                    path: p,
                    reason: (*reason).to_string(),
                }),
                Err(e) => {
                    return Err(e).with_context(|| format!("lock: cannot stat {}", p.display()));
                }
            }
        }
    }
    for rel in &cli.lock {
        let p = wroot.join(rel); // rel validated (no `..`/abs) in preflight
        match p.symlink_metadata() {
            Ok(_) => leaves.push(p),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => watch.push(WatchPath {
                path: p,
                reason: format!("in your --lock set ('{rel}')"),
            }),
            Err(e) => return Err(e).with_context(|| format!("lock: cannot stat {}", p.display())),
        }
    }
    if !cli.unlock.is_empty() {
        let drop: BTreeSet<PathBuf> = cli.unlock.iter().map(|r| wroot.join(r)).collect();
        leaves.retain(|l| !drop.contains(l));
        watch.retain(|w| !drop.contains(&w.path));
    }
    leaves.sort();
    leaves.dedup();
    Ok((leaves, watch))
}

/// Git autorun defaults under `wroot`, recursing into nested gitdirs.
/// Fails closed on a symlinked `.git` (unless `--unlock .git`): a symlink
/// can't be RO-bound and would otherwise silently disable the git lock.
fn default_git_leaves(wroot: &Path, out: &mut Vec<PathBuf>, unlocked: bool) -> Result<()> {
    let dotgit = wroot.join(".git");
    match std::fs::symlink_metadata(&dotgit) {
        Ok(m) if m.file_type().is_symlink() => {
            if !unlocked {
                bail!(
                    "{}/.git is a symlink — basta will not lock through it (a symlinked \
                     .git can redirect git's autorun set to a writable target). Pass \
                     `--unlock .git` to proceed without the git lock here, or `--no-lock`.",
                    wroot.display()
                );
            }
        }
        Ok(m) if m.is_dir() => collect_gitdir(&dotgit, out, 0),
        Ok(m) if m.is_file() => {
            // Linked-worktree / submodule pointer (`gitdir: …`). RO-bind the
            // pointer so it can't be repointed at a writable gitdir; the real
            // hooks live in the external gitdir, usually unmounted.
            out.push(dotgit);
        }
        _ => {}
    }
    Ok(())
}

fn collect_gitdir(gitdir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > MAX_GITDIR_DEPTH {
        return;
    }
    for name in ["config", "config.worktree"] {
        let f = gitdir.join(name);
        if f.is_file() {
            out.push(f);
        }
    }
    let hooks = gitdir.join("hooks");
    if hooks.is_dir() {
        out.push(hooks);
    }
    // Descend only into the two subtrees that hold nested gitdirs — never
    // objects/refs/etc.
    for sub in ["modules", "worktrees"] {
        if let Ok(rd) = std::fs::read_dir(gitdir.join(sub)) {
            for e in rd.flatten() {
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    collect_gitdir(&e.path(), out, depth + 1);
                }
            }
        }
    }
}

fn open_bind(p: &Path, ro: bool, dir: bool) -> Result<Workspace> {
    let mut flags = OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    if dir {
        flags |= OFlag::O_DIRECTORY;
    }
    let fd = open(p, flags, Mode::empty())
        .with_context(|| format!("lock: cannot open {} (use --no-lock to skip)", p.display()))?;
    Ok(Workspace {
        fd,
        path: p.to_path_buf(),
        ro,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    // The pre-block binds only — keeps the existing assertions terse.
    fn binds_for(ws: &[Workspace], cli: &Cli) -> Result<Vec<Workspace>> {
        Ok(plan_for(ws, cli)?.binds)
    }

    fn watch_rels(root: &Path, plan: &LockPlan) -> Vec<String> {
        plan.watch
            .iter()
            .map(|w| {
                w.path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    // A throwaway dir under /tmp (an allowed root) with a deterministic name
    // per test — avoids pulling in a tempdir dependency.
    fn scratch(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("basta-lockset-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn cli_with(lock: &[&str], unlock: &[&str], no_lock: bool) -> Cli {
        let mut argv: Vec<String> = vec!["basta".into()];
        for l in lock {
            argv.push("--lock".into());
            argv.push((*l).into());
        }
        for u in unlock {
            argv.push("--unlock".into());
            argv.push((*u).into());
        }
        if no_lock {
            argv.push("--no-lock".into());
        }
        argv.push("--".into());
        argv.push("true".into());
        <Cli as clap::Parser>::parse_from(argv)
    }

    fn fake_repo(root: &Path) {
        fs::create_dir_all(root.join(".git/hooks")).unwrap();
        fs::write(root.join(".git/config"), "[core]\n").unwrap();
        fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    }

    fn rel(root: &Path, w: &Workspace) -> (String, bool) {
        (
            w.path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            w.ro,
        )
    }

    #[test]
    fn git_repo_locks_config_and_hooks() {
        let root = scratch("repo");
        fake_repo(&root);
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        let binds = binds_for(&ws, &cli_with(&[], &[], false)).unwrap();
        let got: Vec<(String, bool)> = binds.iter().map(|b| rel(&root, b)).collect();
        // .git pin (RW) emitted before its RO leaves.
        assert_eq!(got[0], (".git".to_string(), false));
        assert!(got.contains(&(".git/config".to_string(), true)));
        assert!(got.contains(&(".git/hooks".to_string(), true)));
    }

    #[test]
    fn ro_workspace_skipped() {
        let root = scratch("ro");
        fake_repo(&root);
        let ws = vec![Workspace::resolve(&format!("{}:ro", root.to_str().unwrap())).unwrap()];
        assert!(
            binds_for(&ws, &cli_with(&[], &[], false))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn non_repo_empty() {
        let root = scratch("plain");
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        assert!(
            binds_for(&ws, &cli_with(&[], &[], false))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn dotgit_file_locks_pointer() {
        let root = scratch("worktree");
        fs::write(root.join(".git"), "gitdir: /elsewhere/.git/worktrees/w\n").unwrap();
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        let binds = binds_for(&ws, &cli_with(&[], &[], false)).unwrap();
        let got: Vec<(String, bool)> = binds.iter().map(|b| rel(&root, b)).collect();
        assert_eq!(got, vec![(".git".to_string(), true)]);
    }

    #[test]
    fn submodule_recursion() {
        let root = scratch("submod");
        fake_repo(&root);
        fs::create_dir_all(root.join(".git/modules/foo/hooks")).unwrap();
        fs::write(root.join(".git/modules/foo/config"), "[core]\n").unwrap();
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        let binds = binds_for(&ws, &cli_with(&[], &[], false)).unwrap();
        let got: Vec<(String, bool)> = binds.iter().map(|b| rel(&root, b)).collect();
        // pins (RW) for the ancestor chain, shallow→deep.
        for pin in [".git", ".git/modules", ".git/modules/foo"] {
            assert!(got.contains(&(pin.to_string(), false)), "missing pin {pin}");
        }
        // module leaves RO.
        assert!(got.contains(&(".git/modules/foo/config".to_string(), true)));
        assert!(got.contains(&(".git/modules/foo/hooks".to_string(), true)));
        // .git pin precedes .git/modules pin precedes .git/modules/foo pin.
        let idx = |s: &str| got.iter().position(|(p, _)| p == s).unwrap();
        assert!(idx(".git") < idx(".git/modules"));
        assert!(idx(".git/modules") < idx(".git/modules/foo"));
    }

    #[test]
    fn unlock_removes_default() {
        let root = scratch("unlock");
        fake_repo(&root);
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        let binds = binds_for(&ws, &cli_with(&[], &[".git/hooks"], false)).unwrap();
        let got: Vec<(String, bool)> = binds.iter().map(|b| rel(&root, b)).collect();
        assert!(!got.contains(&(".git/hooks".to_string(), true)));
        assert!(got.contains(&(".git/config".to_string(), true)));
    }

    #[test]
    fn lock_adds_custom() {
        let root = scratch("custom");
        fs::create_dir_all(root.join("ci")).unwrap();
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        let binds = binds_for(&ws, &cli_with(&["ci"], &[], true)).unwrap();
        let got: Vec<(String, bool)> = binds.iter().map(|b| rel(&root, b)).collect();
        // --no-lock drops git defaults; only the custom RO bind (no pin, its
        // parent is the workspace root).
        assert_eq!(got, vec![("ci".to_string(), true)]);
    }

    #[test]
    fn no_lock_drops_defaults() {
        let root = scratch("nolock");
        fake_repo(&root);
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        assert!(
            binds_for(&ws, &cli_with(&[], &[], true))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn symlinked_dotgit_fails_closed() {
        let root = scratch("symlink");
        let real = scratch("symlink-real");
        fake_repo(&real);
        symlink(real.join(".git"), root.join(".git")).unwrap();
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        // A symlinked .git can't be RO-bound — refuse rather than silently skip.
        assert!(plan_for(&ws, &cli_with(&[], &[], false)).is_err());
        // Knowingly proceed with --unlock .git or --no-lock.
        assert!(plan_for(&ws, &cli_with(&[], &[".git"], false)).is_ok());
        assert!(plan_for(&ws, &cli_with(&[], &[], true)).is_ok());
    }

    #[test]
    fn dangling_symlink_leaf_fails_closed() {
        let root = scratch("dangling");
        // .envrc -> a missing target: exists() reports absent, but it must still fail
        // closed (the agent could create the target, planting host-run content).
        symlink(root.join(".nope"), root.join(".envrc")).unwrap();
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        assert!(plan_for(&ws, &cli_with(&[], &[], false)).is_err());
        assert!(plan_for(&ws, &cli_with(&[], &[".envrc"], false)).is_ok());
    }

    #[test]
    fn symlinked_default_leaf_fails_closed() {
        let root = scratch("symleaf");
        let real = scratch("symleaf-real");
        fs::create_dir_all(&real).unwrap();
        // .claude is a symlink to a real dir — exists() is true, so it becomes
        // a locked leaf, but basta must refuse rather than RO-bind the symlink.
        symlink(&real, root.join(".claude")).unwrap();
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        assert!(plan_for(&ws, &cli_with(&[], &[], false)).is_err());
        assert!(plan_for(&ws, &cli_with(&[], &[".claude"], false)).is_ok());
    }

    #[test]
    fn absent_lock_is_watched() {
        let root = scratch("absentlock");
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        // --no-lock + --lock .envrc (absent): no binds, .envrc watched.
        let plan = plan_for(&ws, &cli_with(&[".envrc"], &[], true)).unwrap();
        assert!(plan.binds.is_empty());
        assert_eq!(watch_rels(&root, &plan), vec![".envrc".to_string()]);
    }

    #[test]
    fn default_watch_envrc_when_absent() {
        let root = scratch("defwatch");
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        let plan = plan_for(&ws, &cli_with(&[], &[], false)).unwrap();
        assert!(watch_rels(&root, &plan).contains(&".envrc".to_string()));
    }

    #[test]
    fn existing_envrc_not_watched() {
        let root = scratch("existsenvrc");
        fs::write(root.join(".envrc"), "export X=1\n").unwrap();
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        let plan = plan_for(&ws, &cli_with(&[], &[], false)).unwrap();
        assert!(!watch_rels(&root, &plan).contains(&".envrc".to_string()));
    }

    #[test]
    fn no_lock_drops_default_watch() {
        let root = scratch("nowatch");
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        let plan = plan_for(&ws, &cli_with(&[], &[], true)).unwrap();
        assert!(plan.watch.is_empty());
    }

    #[test]
    fn existing_envrc_is_locked() {
        let root = scratch("envrclock");
        fs::write(root.join(".envrc"), "export X=1\n").unwrap();
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        let binds = binds_for(&ws, &cli_with(&[], &[], false)).unwrap();
        let got: Vec<(String, bool)> = binds.iter().map(|b| rel(&root, b)).collect();
        assert!(got.contains(&(".envrc".to_string(), true)));
    }

    #[test]
    fn default_lock_dir_locked_when_present() {
        let root = scratch("vscodelock");
        fs::create_dir_all(root.join(".vscode")).unwrap();
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        let binds = binds_for(&ws, &cli_with(&[], &[], false)).unwrap();
        let got: Vec<(String, bool)> = binds.iter().map(|b| rel(&root, b)).collect();
        // Whole dir RO-bound; its parent is the workspace root so no pin.
        assert!(got.contains(&(".vscode".to_string(), true)));
    }

    #[test]
    fn default_lock_absent_all_watched() {
        let root = scratch("defabsent");
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        let plan = plan_for(&ws, &cli_with(&[], &[], false)).unwrap();
        let w = watch_rels(&root, &plan);
        for p in [".envrc", ".vscode", ".idea", ".claude", ".mcp.json"] {
            assert!(w.contains(&p.to_string()), "missing watch {p}");
        }
        assert!(plan.binds.is_empty());
    }

    #[test]
    fn unlock_removes_default_dir() {
        let root = scratch("unlockvscode");
        fs::create_dir_all(root.join(".vscode")).unwrap();
        let ws = vec![Workspace::resolve(root.to_str().unwrap()).unwrap()];
        let plan = plan_for(&ws, &cli_with(&[], &[".vscode"], false)).unwrap();
        let got: Vec<(String, bool)> = plan.binds.iter().map(|b| rel(&root, b)).collect();
        assert!(!got.contains(&(".vscode".to_string(), true)));
        assert!(!watch_rels(&root, &plan).contains(&".vscode".to_string()));
    }
}
