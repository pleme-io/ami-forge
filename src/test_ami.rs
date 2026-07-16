//! Standalone AMI smoke test — boot an already-built AMI and run its test
//! template, without rebuilding it.
//!
//! Consumed by `substrate/lib/infra/ami-build.nix`'s `ami-test` app (was
//! previously hand-rolled bash calling `packer init`/`packer build`
//! directly — moved here so the SAME GC-root guard that protects
//! `pipeline-run`/`multi-layer-run` also protects this path, instead of a
//! second, unrooted place a template's store path can vanish mid-run).

use anyhow::Result;
use clap::Args;
use std::path::PathBuf;
use tracing::info;

use crate::gcroot;
use crate::packer::{run_packer_build, run_packer_init};

#[derive(Args)]
pub struct TestAmiArgs {
    /// Path to the Packer test template
    #[arg(long)]
    pub template: PathBuf,

    /// AMI ID to boot and test
    #[arg(long = "source-ami")]
    pub source_ami: String,

    /// AWS region (informational only here -- the template's own
    /// `region` variable/default governs where Packer actually launches;
    /// accepted for CLI-surface symmetry with the other subcommands)
    #[arg(long, default_value = "us-east-1")]
    pub region: String,
}

pub fn run(args: TestAmiArgs) -> Result<()> {
    if !args.template.exists() {
        anyhow::bail!("Test template not found: {}", args.template.display());
    }

    // Held for the whole test run -- see `crate::gcroot`.
    let _gcroot = gcroot::root_paths(&[("test-template", args.template.as_path())])?;

    let template = args.template.to_string_lossy();
    info!("Testing AMI: {} (region {})", args.source_ami, args.region);
    run_packer_init(&template)?;
    run_packer_build(&template, &[format!("source_ami={}", args.source_ami)])?;
    Ok(())
}
