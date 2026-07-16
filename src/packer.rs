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
    let mut cmd = Command::new("packer");
    cmd.arg("build");
    // On error: clean up the builder instance instead of leaving it running.
    // This prevents orphaned instances when Packer encounters provisioner errors.
    cmd.args(["-on-error=cleanup"]);
    for var in vars {
        cmd.args(["-var", var]);
    }
    cmd.arg(template);
    let status = cmd.status().context("failed to execute packer build")?;
    if !status.success() {
        bail!("packer build failed for {template}");
    }
    Ok(())
}
