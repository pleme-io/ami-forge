//! Shared Packer invocation — `packer init` / `packer build`.
//!
//! Extracted from byte-identical copies previously duplicated in
//! `pipeline.rs` and `multi_layer.rs` (Prime Directive: solve once, in one
//! place). Every AMI pipeline stage — single-stage, multi-layer, and the
//! standalone `test-ami` subcommand — drives Packer through these two
//! functions only.

use anyhow::{bail, Context, Result};
use std::process::Command;

pub fn run_packer_init(template: &str) -> Result<()> {
    let status = Command::new("packer")
        .args(["init", template])
        .status()
        .context("failed to execute packer init")?;
    if !status.success() {
        bail!("packer init failed for {template}");
    }
    Ok(())
}

pub fn run_packer_build(template: &str, vars: &[String]) -> Result<()> {
    run_packer_build_with_secrets(template, vars, &[])
}

/// `packer build` where `secret_vars` are `name=value` pairs that must NEVER
/// reach argv.
///
/// ## The bug this exists to prevent (found live, 2026-07-31)
///
/// `vars` are passed as `-var name=value`, which puts the value in the process
/// command line. A GitHub PAT went through that path, and
/// `ps -axo command | grep github_token` printed the whole token in the clear
/// for the lifetime of the build — readable by ANY local user, and captured by
/// shell history and process accounting.
///
/// That breaks the fleet's zero-plaintext rule (never argv/env/logs), and argv
/// is the worst of the three: `/proc/<pid>/cmdline` is world-readable, unlike
/// `/proc/<pid>/environ` which is at least owner-only.
///
/// So secrets go through a temp HCL var-file instead: only the PATH lands on
/// argv. The file is created with mode 0600 BEFORE any bytes are written
/// (`OpenOptions::mode`, not a chmod afterwards — a create-then-chmod leaves a
/// window where the token is world-readable), lives under the process's own
/// temp dir, and is removed on every exit path including failure.
///
/// Non-secret `vars` keep using `-var`, because visible values are useful in
/// `ps` when debugging a build and there is nothing to protect.
pub fn run_packer_build_with_secrets(
    template: &str,
    vars: &[String],
    secret_vars: &[(String, String)],
) -> Result<()> {
    // Held for the whole call so the file outlives the child process; dropping
    // it removes the file.
    let secret_file = if secret_vars.is_empty() {
        None
    } else {
        Some(SecretVarFile::write(secret_vars)?)
    };

    let mut cmd = Command::new("packer");
    cmd.arg("build");
    // On error: clean up the builder instance instead of leaving it running.
    // This prevents orphaned instances when Packer encounters provisioner errors.
    cmd.args(["-on-error=cleanup"]);
    for var in vars {
        cmd.args(["-var", var]);
    }
    if let Some(ref f) = secret_file {
        // Only the PATH is visible in `ps`, never the value.
        cmd.arg("-var-file").arg(f.path());
    }
    cmd.arg(template);
    let status = cmd.status().context("failed to execute packer build")?;
    // Explicit drop before the error path so the secret is gone whether the
    // build succeeded or not.
    drop(secret_file);
    if !status.success() {
        bail!("packer build failed for {template}");
    }
    Ok(())
}

/// A mode-0600 HCL var-file holding secret Packer variables, deleted on drop.
struct SecretVarFile {
    path: std::path::PathBuf,
}

impl SecretVarFile {
    fn write(secret_vars: &[(String, String)]) -> Result<Self> {
        use std::io::Write as _;

        let mut path = std::env::temp_dir();
        // Unique per INSTANCE, not merely per process. The pid keeps two
        // concurrent ami-forge runs apart (concurrent bakes are not
        // hypothetical — one happened the day this was written); the counter
        // keeps two SecretVarFiles inside ONE process apart.
        //
        // The counter is not belt-and-braces: with a pid-only name, a second
        // instance truncates the first's file and the first's `Drop` then
        // deletes the second's — so one build silently loses its secret. The
        // unit tests below hit exactly that, which is how it was found.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        path.push(format!(
            "ami-forge-vars-{}-{seq}.pkrvars.hcl",
            std::process::id()
        ));

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            // 0600 AT CREATION. A create-then-chmod would leave the token
            // world-readable for the window in between.
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&path)
            .with_context(|| format!("creating packer secret var-file {}", path.display()))?;

        for (name, value) in secret_vars {
            // HCL string literal. Escape backslash first, then quote, so a
            // value containing either cannot break out of the literal.
            let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
            writeln!(f, "{name} = \"{escaped}\"")
                .context("writing packer secret var-file")?;
        }
        f.flush().context("flushing packer secret var-file")?;
        Ok(Self { path })
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for SecretVarFile {
    fn drop(&mut self) {
        // Best-effort: a failed unlink must not mask the build's own result,
        // and the file is 0600 in a process-scoped path either way.
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The file must be 0600 AT CREATION, not chmod'd afterwards — a
    /// create-then-chmod leaves a window where the token is world-readable.
    #[cfg(unix)]
    #[test]
    fn secret_var_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let f = SecretVarFile::write(&[("github_token".into(), "ghp_SECRET".into())])
            .expect("write var file");
        let mode = std::fs::metadata(f.path()).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the secret var-file must not be group/world readable");
    }

    /// The value must actually be in the file — otherwise packer gets nothing
    /// and the build fails in a confusing way rather than an obvious one.
    #[test]
    fn secret_var_file_contains_the_assignment() {
        let f = SecretVarFile::write(&[("github_token".into(), "ghp_SECRET".into())])
            .expect("write var file");
        let body = std::fs::read_to_string(f.path()).expect("read");
        assert_eq!(body.trim(), r#"github_token = "ghp_SECRET""#);
    }

    /// A value containing a quote or backslash must not break out of the HCL
    /// string literal — that would turn a secret into syntax and could change
    /// what packer parses.
    #[test]
    fn secret_values_are_escaped_not_injected() {
        let f = SecretVarFile::write(&[("t".into(), r#"a"b\c"#.into())]).expect("write");
        let body = std::fs::read_to_string(f.path()).expect("read");
        assert_eq!(body.trim(), r#"t = "a\"b\\c""#);
    }

    /// Dropping removes the file. A secret left in /tmp after the build is the
    /// same class of exposure as one left in argv, just slower to notice.
    #[test]
    fn the_secret_file_is_removed_on_drop() {
        let path = {
            let f = SecretVarFile::write(&[("t".into(), "v".into())]).expect("write");
            f.path().to_path_buf()
        };
        assert!(!path.exists(), "the secret var-file must not outlive the build");
    }

    /// Two concurrent ami-forge runs must not share a path. Concurrent bakes
    /// are not hypothetical — one happened the day this was written.
    #[test]
    fn the_path_is_process_scoped() {
        let f = SecretVarFile::write(&[("t".into(), "v".into())]).expect("write");
        let name = f.path().file_name().expect("name").to_string_lossy().to_string();
        assert!(name.contains(&std::process::id().to_string()));
    }
}
