//! Full AMI pipeline orchestrator: build → test → promote (or rollback).
//!
//! Replaces the shell script in substrate's `mkAmiBuildPipeline` with a
//! single Rust binary. Packer handles SSH, instance lifecycle, and cleanup.
//! This module orchestrates the Packer invocations and post-build actions.

use anyhow::{bail, Context, Result};
use clap::Args;
use std::path::PathBuf;
use std::process::Command;
use tracing::{error, info, warn};

#[derive(Args)]
pub struct PipelineRunArgs {
    /// Path to the Packer build template (.pkr.json)
    #[arg(long)]
    pub build_template: PathBuf,

    /// Path to the Packer test template (.pkr.json)
    #[arg(long)]
    pub test_template: PathBuf,

    /// SSM parameter path for the promoted AMI ID
    #[arg(long)]
    pub ssm: String,

    /// AMI name (used for rotation on failure)
    #[arg(long)]
    pub ami_name: String,

    /// AWS region
    #[arg(long, default_value = "us-east-1")]
    pub region: String,

    /// Packer manifest output path
    #[arg(long, default_value = "packer-manifest.json")]
    pub manifest: PathBuf,
}

pub async fn run(args: PipelineRunArgs) -> Result<()> {
    // Validate inputs
    if !args.build_template.exists() {
        bail!(
            "Build template not found: {}",
            args.build_template.display()
        );
    }
    if !args.test_template.exists() {
        bail!(
            "Test template not found: {}",
            args.test_template.display()
        );
    }

    // Validate AWS credentials early
    let config = crate::aws::load_config(&args.region).await;
    let arn = crate::aws::validate_credentials(&config).await?;
    info!("Pipeline starting as {arn}");

    let github_token = std::env::var("GITHUB_TOKEN").unwrap_or_default();
    let build_tpl = args.build_template.to_string_lossy();
    let test_tpl = args.test_template.to_string_lossy();
    let manifest_path = args.manifest.to_string_lossy().to_string();

    // ── Phase 1: Build AMI ──────────────────────────────────────
    info!("[1/4] Building AMI from base NixOS image");
    run_packer_init(&build_tpl)?;
    run_packer_build(
        &build_tpl,
        &[format!("github_token={github_token}")],
    )?;

    // ── Phase 2: Extract AMI ID ─────────────────────────────────
    info!("[2/4] Extracting AMI ID from manifest");
    let ami_id = crate::aws::parse_packer_manifest(&manifest_path)?;
    info!("Built AMI: {ami_id}");

    // ── Phase 3: Integration test ───────────────────────────────
    info!("[3/4] Running integration tests on {ami_id}");
    run_packer_init(&test_tpl)?;
    let test_result = run_packer_build(
        &test_tpl,
        &[format!("source_ami={ami_id}")],
    );

    if let Err(e) = test_result {
        error!("Integration test FAILED: {e}");
        info!("Deregistering failed AMI: {ami_id}");

        let ec2 = aws_sdk_ec2::Client::new(&config);
        match crate::rotate::run_rotate(&ec2, &args.ami_name).await {
            Ok(()) => info!("Failed AMI deregistered"),
            Err(re) => warn!("AMI deregistration also failed: {re}"),
        }

        cleanup_manifest(&manifest_path);
        bail!("AMI pipeline failed — integration tests did not pass, AMI deregistered");
    }

    // ── Phase 4: Promote ────────────────────────────────────────
    info!("[4/4] Promoting AMI {ami_id} to {}", args.ssm);
    let ssm_client = aws_sdk_ssm::Client::new(&config);
    crate::aws::put_ssm_parameter(&ssm_client, &args.ssm, &ami_id).await?;

    cleanup_manifest(&manifest_path);
    info!("Pipeline complete — AMI {ami_id} promoted to {}", args.ssm);

    Ok(())
}

fn run_packer_init(template: &str) -> Result<()> {
    let status = Command::new("packer")
        .args(["init", template])
        .status()
        .context("failed to execute packer init")?;

    if !status.success() {
        bail!("packer init failed for {template}");
    }
    Ok(())
}

fn run_packer_build(template: &str, vars: &[String]) -> Result<()> {
    let mut cmd = Command::new("packer");
    cmd.arg("build");

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

fn cleanup_manifest(path: &str) {
    if std::path::Path::new(path).exists() {
        if let Err(e) = std::fs::remove_file(path) {
            warn!("Failed to remove manifest: {e}");
        }
    }
}
