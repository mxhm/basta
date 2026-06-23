// build.rs — embed the short git rev so the binary self-reports its provenance.
// Exposed via `basta --build-rev`; the ansible deploy compares it to
// `git rev-parse HEAD` to decide whether a node needs a rebuild. No
// rerun-if-changed is emitted, so Cargo re-runs this whenever any tracked
// package file changes — i.e. whenever a pulled commit brings new content — and
// re-stamps the current HEAD. Falls back to "unknown" outside a git checkout
// (e.g. a source tarball with no .git).
use std::process::Command;

fn main() {
    let rev = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=BASTA_BUILD_REV={rev}");
}
