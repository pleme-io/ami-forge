//! Shared AWS client construction.
//!
//! Every subcommand needs AWS SDK clients configured with a region.
//! This module eliminates the repeated boilerplate.

use aws_config::SdkConfig;

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

/// Update an SSM parameter with a string value.
pub async fn put_ssm_parameter(
    ssm: &aws_sdk_ssm::Client,
    name: &str,
    value: &str,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use tracing::info;

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
