use std::process::Command as StdCommand;

use anyhow::{bail, Context};
use clap::Args;
use tracing::info;

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

    // Update SSM
    let region = aws_config::Region::new(args.region.clone());
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region)
        .load()
        .await;
    let ssm_client = aws_sdk_ssm::Client::new(&config);

    ssm_client
        .put_parameter()
        .name(&args.ssm)
        .value(ami_id)
        .r#type(aws_sdk_ssm::types::ParameterType::String)
        .overwrite(true)
        .send()
        .await
        .context("failed to update SSM parameter")?;

    info!("SSM parameter {} updated to {}", args.ssm, ami_id);

    // Cleanup manifest
    std::fs::remove_file("packer-manifest.json").ok();

    Ok(())
}
