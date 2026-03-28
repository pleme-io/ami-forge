//! Shared AWS client construction, credential validation, and helpers.
//!
//! Every subcommand needs AWS SDK clients configured with a region.
//! This module eliminates the repeated boilerplate and provides
//! shared utilities for SSM, manifest parsing, and credential checks.

use anyhow::Context;
use aws_config::SdkConfig;
use tracing::info;

/// Load the shared AWS SDK config for a given region.
///
/// All clients are then constructed from this config via `Client::new(&config)`.
pub async fn load_config(region: &str) -> SdkConfig {
    let region = aws_config::Region::new(region.to_owned());
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region)
        .load()
        .await
}

/// Load AWS SDK config with an explicit SSO profile.
///
/// Uses the named profile for credential resolution — no env vars needed.
pub async fn load_config_with_profile(region: &str, profile: &str) -> SdkConfig {
    let region = aws_config::Region::new(region.to_owned());
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region)
        .profile_name(profile)
        .load()
        .await
}

/// Validate AWS credentials by calling `sts:GetCallerIdentity`.
///
/// Call this early in the pipeline to catch expired SSO tokens before
/// starting a 15-minute Packer build.
pub async fn validate_credentials(config: &SdkConfig) -> anyhow::Result<String> {
    let sts = aws_sdk_sts::Client::new(config);
    let resp = sts
        .get_caller_identity()
        .send()
        .await
        .context("AWS credential validation failed — are you logged in? (aws sso login)")?;

    let arn = resp.arn().unwrap_or("unknown").to_string();
    let account = resp.account().unwrap_or("unknown");
    info!(arn = %arn, account = %account, "AWS credentials valid");
    Ok(arn)
}

/// Update an SSM parameter with a string value.
pub async fn put_ssm_parameter(
    ssm: &aws_sdk_ssm::Client,
    name: &str,
    value: &str,
) -> anyhow::Result<()> {
    ssm.put_parameter()
        .name(name)
        .value(value)
        .r#type(aws_sdk_ssm::types::ParameterType::String)
        .overwrite(true)
        .send()
        .await
        .context("failed to update SSM parameter")?;

    info!("SSM parameter {name} updated to {value}");
    Ok(())
}

/// Parse a Packer manifest JSON file and extract the AMI ID.
///
/// The manifest format is: `{ "builds": [{ "artifact_id": "region:ami-xxx" }] }`
/// Returns the AMI ID from the last build entry.
pub fn parse_packer_manifest(path: &str) -> anyhow::Result<String> {
    let manifest = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {path}"))?;
    let json: serde_json::Value = serde_json::from_str(&manifest)
        .with_context(|| format!("failed to parse {path}"))?;

    let ami_id = json["builds"]
        .as_array()
        .and_then(|builds| builds.last())
        .and_then(|build| build["artifact_id"].as_str())
        .and_then(|artifact| artifact.split(':').nth(1))
        .with_context(|| {
            let builds = json["builds"].as_array().map(|b| b.len()).unwrap_or(0);
            format!(
                "could not extract AMI ID from {path} ({builds} builds found). \
                 Expected format: {{\"builds\": [{{\"artifact_id\": \"region:ami-xxx\"}}]}}"
            )
        })?
        .to_string();

    info!(ami = %ami_id, "parsed AMI ID from manifest");
    Ok(ami_id)
}
