use std::process::Command as StdCommand;

use anyhow::{bail, Context};
use clap::Args;
use tracing::info;

use crate::{aws, boot_test, rotate, vpn_test};

#[derive(Args)]
pub struct PackerArgs {
    /// Path to Packer JSON template
    #[arg(long)]
    template: String,

    /// SSM parameter to update with AMI ID
    #[arg(long)]
    ssm: String,

    /// AWS region
    #[arg(long, default_value = "us-east-1")]
    region: String,

    /// Packer variables (KEY=VALUE, repeatable)
    #[arg(long = "var", value_name = "KEY=VALUE")]
    vars: Vec<String>,

    /// Run boot test (binary/service checks) before promoting AMI
    #[arg(long)]
    boot_test: bool,

    /// Run VPN connectivity test before promoting AMI
    #[arg(long)]
    vpn_test: bool,

    /// Instance type for test instances
    #[arg(long, default_value = "t3.medium")]
    test_instance_type: String,

    /// Subnet ID for tests (uses default VPC if omitted)
    #[arg(long)]
    test_subnet: Option<String>,

    /// SSH username for tests (default: root)
    #[arg(long, default_value = "root")]
    test_ssh_user: String,
}

pub async fn run(args: PackerArgs) -> anyhow::Result<()> {
    info!("Running packer init...");
    let init_status = StdCommand::new("packer")
        .args(["init", &args.template])
        .status()
        .context("failed to run packer init")?;
    if !init_status.success() {
        bail!("packer init failed");
    }

    info!("Running packer build...");
    let mut cmd = StdCommand::new("packer");
    cmd.args(["build", "-color=false"]);
    for var in &args.vars {
        cmd.args(["-var", var]);
    }
    cmd.arg(&args.template);

    let build_status = cmd.status().context("failed to run packer build")?;
    if !build_status.success() {
        bail!("packer build failed");
    }

    // Parse manifest for AMI ID
    info!("Parsing packer manifest...");
    let manifest =
        std::fs::read_to_string("packer-manifest.json").context("failed to read packer-manifest.json")?;
    let manifest_json: serde_json::Value =
        serde_json::from_str(&manifest).context("failed to parse packer-manifest.json")?;

    let ami_id = manifest_json["builds"]
        .as_array()
        .and_then(|builds| builds.last())
        .and_then(|build| build["artifact_id"].as_str())
        .and_then(|artifact| artifact.split(':').nth(1))
        .context("could not extract AMI ID from packer manifest")?;

    info!("AMI created: {}", ami_id);

    // Run boot test if requested
    if args.boot_test {
        info!("Running boot test on AMI {ami_id}...");
        let test_args = boot_test::BootTestArgs {
            ami_id: ami_id.to_string(),
            region: args.region.clone(),
            subnet_id: args.test_subnet.clone(),
            instance_type: args.test_instance_type.clone(),
            timeout: 300,
            ssh_user: args.test_ssh_user.clone(),
            extra_checks: Vec::new(),
        };

        if let Err(e) = boot_test::run(test_args).await {
            deregister_on_failure(&args.region, ami_id).await;
            std::fs::remove_file("packer-manifest.json").ok();
            bail!("Boot test failed: {e}");
        }
        info!("Boot test PASSED");
    }

    // Run VPN test if requested
    if args.vpn_test {
        info!("Running VPN connectivity test on AMI {ami_id}...");
        let test_args = vpn_test::VpnTestArgs {
            ami_id: ami_id.to_string(),
            region: args.region.clone(),
            subnet_id: args.test_subnet.clone(),
            instance_type: args.test_instance_type.clone(),
            timeout: 300,
            ssh_user: args.test_ssh_user.clone(),
        };

        if let Err(e) = vpn_test::run(test_args).await {
            deregister_on_failure(&args.region, ami_id).await;
            std::fs::remove_file("packer-manifest.json").ok();
            bail!("VPN test failed: {e}");
        }
        info!("VPN test PASSED");
    }

    // Update SSM (only reached if all tests pass or no tests requested)
    let config = aws::load_config(&args.region).await;
    let ssm_client = aws_sdk_ssm::Client::new(&config);
    aws::put_ssm_parameter(&ssm_client, &args.ssm, ami_id).await?;

    // Cleanup manifest
    std::fs::remove_file("packer-manifest.json").ok();

    info!("AMI {ami_id} promoted successfully");
    Ok(())
}

/// Deregister an AMI after a failed test.
async fn deregister_on_failure(region: &str, ami_id: &str) {
    info!("Test FAILED — deregistering AMI {ami_id}");
    let config = aws::load_config(region).await;
    let ec2_client = aws_sdk_ec2::Client::new(&config);
    if let Err(e) = rotate::run_rotate(&ec2_client, ami_id).await {
        tracing::warn!(error = %e, "failed to deregister failed AMI");
    }
}
