//! Full AMI pipeline orchestrator: build → test → cluster-test → promote (or rollback).
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

    /// Skip the multi-node cluster integration test (faster iteration)
    #[arg(long)]
    pub skip_cluster_test: bool,

    /// Instance type for cluster test nodes
    #[arg(long, default_value = "c7i.xlarge")]
    pub cluster_test_instance_type: String,

    /// Timeout for cluster test in seconds
    #[arg(long, default_value_t = 480)]
    pub cluster_test_timeout: u64,
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

    let total_phases = if args.skip_cluster_test { 4 } else { 5 };

    // Validate AWS credentials early
    let config = crate::aws::load_config(&args.region).await;
    let arn = crate::aws::validate_credentials(&config).await?;
    info!("Pipeline starting as {arn}");

    let github_token = std::env::var("GITHUB_TOKEN").unwrap_or_default();
    let build_tpl = args.build_template.to_string_lossy();
    let test_tpl = args.test_template.to_string_lossy();
    let manifest_path = args.manifest.to_string_lossy().to_string();

    // ── Phase 1: Build AMI ──────────────────────────────────────
    info!("[1/{total_phases}] Building AMI from base NixOS image");
    run_packer_init(&build_tpl)?;
    run_packer_build(&build_tpl, &[format!("github_token={github_token}")])?;

    // ── Phase 2: Extract AMI ID ─────────────────────────────────
    info!("[2/{total_phases}] Extracting AMI ID from manifest");
    let ami_id = crate::aws::parse_packer_manifest(&manifest_path)?;
    info!("Built AMI: {ami_id}");

    // ── Phase 3: Single-node smoke test (Packer) ────────────────
    info!("[3/{total_phases}] Running single-node integration test on {ami_id}");
    run_packer_init(&test_tpl)?;
    let test_result = run_packer_build(&test_tpl, &[format!("source_ami={ami_id}")]);

    if let Err(e) = test_result {
        error!("Single-node test FAILED: {e}");
        deregister_and_fail(&config, &args.ami_name, &manifest_path, &ami_id).await?;
    }

    // ── Phase 4: Multi-node cluster test ────────────────────────
    if !args.skip_cluster_test {
        info!("[4/{total_phases}] Running multi-node cluster integration test on {ami_id}");
        let cluster_args = crate::cluster_test::ClusterTestArgs {
            ami_id: ami_id.clone(),
            region: args.region.clone(),
            instance_type: args.cluster_test_instance_type.clone(),
            timeout: args.cluster_test_timeout,
        };
        if let Err(e) = crate::cluster_test::run(cluster_args).await {
            error!("Cluster test FAILED: {e}");
            deregister_and_fail(&config, &args.ami_name, &manifest_path, &ami_id).await?;
        }
    }

    // ── Phase 5: Promote ────────────────────────────────────────
    let promote_phase = if args.skip_cluster_test { 4 } else { 5 };
    info!("[{promote_phase}/{total_phases}] Promoting AMI {ami_id} to {}", args.ssm);
    let ssm_client = aws_sdk_ssm::Client::new(&config);
    crate::aws::put_ssm_parameter(&ssm_client, &args.ssm, &ami_id).await?;

    cleanup_manifest(&manifest_path);
    info!(
        "Pipeline complete — AMI {ami_id} promoted to {}",
        args.ssm
    );

    Ok(())
}

async fn deregister_and_fail(
    config: &aws_config::SdkConfig,
    ami_name: &str,
    manifest_path: &str,
    ami_id: &str,
) -> Result<()> {
    info!("Deregistering failed AMI: {ami_id}");
    let ec2 = aws_sdk_ec2::Client::new(config);
    match crate::rotate::run_rotate(&ec2, ami_name).await {
        Ok(()) => info!("Failed AMI deregistered"),
        Err(re) => warn!("AMI deregistration also failed: {re}"),
    }
    cleanup_manifest(manifest_path);
    bail!("AMI pipeline failed — AMI deregistered");
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
