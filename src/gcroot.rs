//! Shared Nix GC-root protection for pipeline-input store paths.
//!
//! Every AMI pipeline (single-stage `pipeline.rs`, multi-layer
//! `multi_layer.rs`) reads Packer templates and config files that are Nix
//! store paths, baked in once at pipeline start, and re-touched minutes
//! later after a long Packer build. Nix's own closure-tracking of those
//! paths is correct (real `${...}` string interpolation on the Nix side
//! registers a real reference edge) — but a registered reference only
//! protects a path for as long as something holds a live GC root on the
//! *referencing* output, and `nix run`'s own protection does not survive
//! this pipeline's shape: `nix run` → a wrapper script → the `ami-forge`
//! binary, which then forks Packer as a child for the remaining ~15-30
//! minutes. Nothing in that chain keeps a persistent root past the initial
//! moment, so a concurrent GC (disk-pressure-triggered `nix-collect-garbage`
//! on the *evaluating* machine, not the remote AMI builder) can collect a
//! template path between phases — surfacing as `packer init failed: stat
//! ... no such file or directory`, long after the real cause (an unrelated
//! GC sweep) already happened. Root-caused live 2026-07-16; full analysis
//! in `pleme-io/theory/AMI-FORGE.md`.
//!
//! `root_paths` closes this structurally: every path given gets an
//! explicit, persistent `nix-store --add-root` for the returned
//! `TempDir`'s lifetime — the caller MUST hold it alive (never `_`-drop
//! it) until the pipeline finishes; dropping it removes the gcroots
//! directory and un-pins every path it protected.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

/// Pins a single nix store path alive via a real `nix-store --add-root`,
/// so a concurrent GC on the evaluating machine can never collect it while
/// this root exists.
pub fn add_gc_root(store_path: &Path, root_dir: &Path, root_name: &str) -> Result<()> {
    let root_link = root_dir.join(root_name);
    let status = Command::new("nix-store")
        .arg("--realise")
        .arg(store_path)
        .arg("--add-root")
        .arg(&root_link)
        .status()
        .with_context(|| format!("failed to invoke nix-store --add-root for {}", store_path.display()))?;
    if !status.success() {
        bail!(
            "nix-store --add-root failed for {} (exit {status}) -- \
             this path may be collected by a concurrent GC before the pipeline reaches it",
            store_path.display()
        );
    }
    Ok(())
}

/// Roots every `(name, path)` pair under one fresh `TempDir` for the whole
/// pipeline run. Returns the `TempDir` — the caller MUST hold it alive
/// until the pipeline finishes.
pub fn root_paths(paths: &[(&str, &Path)]) -> Result<tempfile::TempDir> {
    let root_dir = tempfile::Builder::new()
        .prefix("ami-forge-gcroots-")
        .tempdir()
        .context("failed to create gcroots tempdir")?;
    for (name, path) in paths {
        add_gc_root(path, root_dir.path(), name)?;
    }
    Ok(root_dir)
}

/// A real, always-present nix store path to exercise `add_gc_root` against
/// — resolved from the `nix-store` binary itself via `PATH`, not from a
/// test binary's own `current_exe()` (which sits under `target/debug/...`,
/// NOT `/nix/store`, when `cargo test` is invoked directly rather than via
/// `nix build`/`nix run` — silently skipping every gcroot test under a
/// plain `cargo test`, exactly the "green but proves nothing" class of
/// regression test this exists to avoid). `nix-store` itself must exist
/// under `/nix/store` for the rest of this pipeline to work at all, so
/// resolving it via `PATH` is a dependency already held either way.
///
/// Returns the TOP-LEVEL `/nix/store/<hash>-<name>` component, not a
/// nested file within it (e.g. `nix-store`'s own resolved binary lives at
/// `.../determinate-nix-3.17.0/bin/nix`, a file *inside* that package's
/// output). This distinction is load-bearing: `nix-store --realise
/// --add-root` on a nested file roots the *containing* top-level store
/// path, not the exact file — but every real path `add_gc_root` roots in
/// production (`build_template`/`test_template`, both `pkgs.writeText`
/// outputs) is already a bare top-level store path, so a top-level path
/// here matches that shape. `pub(crate)` (not test-only-private) so
/// sibling modules' own test suites (e.g. `pipeline`) can share it rather
/// than each re-deriving the same helper.
#[cfg(test)]
pub(crate) fn real_store_path_for_test() -> Option<std::path::PathBuf> {
    let which_output = Command::new("which").arg("nix-store").output().ok()?;
    if !which_output.status.success() {
        return None;
    }
    let nix_store_bin = std::path::PathBuf::from(String::from_utf8_lossy(&which_output.stdout).trim());
    let canon = std::fs::canonicalize(&nix_store_bin).ok()?;
    if !canon.starts_with("/nix/store") {
        return None;
    }
    let components: Vec<_> = canon.components().collect();
    if components.len() < 4 {
        None
    } else {
        Some(components[..4].iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_gc_root_creates_a_resolvable_root_pointing_at_the_target() {
        let Some(target) = real_store_path_for_test() else {
            return;
        };
        let root_dir = tempfile::Builder::new()
            .prefix("ami-forge-gcroot-test-")
            .tempdir()
            .expect("tempdir");

        add_gc_root(&target, root_dir.path(), "test-root")
            .expect("add_gc_root should succeed against a real store path");

        let root_link = root_dir.path().join("test-root");
        assert!(root_link.exists(), "GC root symlink was not created at {}", root_link.display());
        let resolved = std::fs::canonicalize(&root_link).expect("root link should resolve");
        assert_eq!(resolved, target);

        // Load-bearing regression proof: nix itself must consider this a
        // live GC root, not just "a symlink exists on disk".
        let output = Command::new("nix-store")
            .args(["--gc", "--print-roots"])
            .output()
            .expect("failed to run nix-store --gc --print-roots");
        let roots = String::from_utf8_lossy(&output.stdout);
        assert!(
            roots.contains(&*target.to_string_lossy()),
            "target path {} does not appear in nix-store's own GC roots listing",
            target.display()
        );
    }

    #[test]
    fn root_paths_roots_every_given_path() {
        let Some(target) = real_store_path_for_test() else {
            return;
        };
        let gcroots = root_paths(&[("a", &target), ("b", &target)])
            .expect("root_paths should succeed");
        assert!(gcroots.path().join("a").exists());
        assert!(gcroots.path().join("b").exists());
    }
}
