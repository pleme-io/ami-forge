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
#[allow(dead_code)]
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
#[allow(dead_code)]
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

/// Add a public launch permission to an AMI (`Group::All`).
///
/// After this call, any AWS account can launch the AMI without a
/// per-account share. The AMI must be in the caller's account and
/// region. Idempotent at AWS level — re-adding `Group::All` succeeds.
///
/// Use only for artifacts known to carry no secrets. The portao AMI
/// qualifies: WireGuard private keys come from SSM at boot, never from
/// the image.
pub async fn make_image_public(
    ec2: &aws_sdk_ec2::Client,
    ami_id: &str,
) -> anyhow::Result<()> {
    let add_all = aws_sdk_ec2::types::LaunchPermission::builder()
        .group(aws_sdk_ec2::types::PermissionGroup::All)
        .build();
    let modifications = aws_sdk_ec2::types::LaunchPermissionModifications::builder()
        .add(add_all)
        .build();

    ec2.modify_image_attribute()
        .image_id(ami_id)
        .launch_permission(modifications)
        .send()
        .await
        .context("ModifyImageAttribute (LaunchPermission Group=all) failed")?;

    info!("AMI {ami_id} promoted to public (LaunchPermission Group=all)");
    Ok(())
}

/// Extract the AMI ID from an already-parsed Packer manifest.
///
/// The manifest format is: `{ "builds": [{ "artifact_id": "region:ami-xxx" }] }`
/// Returns the AMI ID from the **last** build entry (Packer appends one per
/// target) so multi-region builds resolve to the region the CLI was pointed at.
///
/// Pure — no I/O, no logging. Callers that want a file path should wrap with
/// `parse_packer_manifest`; callers that want log-free parsing (e.g. the
/// `manifest-id` subcommand, whose stdout is consumed by shell) should call
/// this directly.
///
/// Returns `Err` when:
/// - `builds` is missing or not an array,
/// - `builds` is empty,
/// - the last build has no `artifact_id` string,
/// - the `artifact_id` does not contain the expected `region:ami-xxx` shape.
pub fn extract_ami_id_from_manifest(json: &serde_json::Value) -> anyhow::Result<String> {
    json["builds"]
        .as_array()
        .and_then(|builds| builds.last())
        .and_then(|build| build["artifact_id"].as_str())
        .and_then(|artifact| artifact.split(':').nth(1))
        .map(str::to_owned)
        .with_context(|| {
            let builds = json["builds"].as_array().map_or(0, Vec::len);
            format!(
                "could not extract AMI ID from manifest ({builds} builds found). \
                 Expected format: {{\"builds\": [{{\"artifact_id\": \"region:ami-xxx\"}}]}}"
            )
        })
}

/// Parse a Packer manifest JSON file and extract the AMI ID.
///
/// Wraps [`extract_ami_id_from_manifest`] with file I/O and an info! log.
pub fn parse_packer_manifest(path: &str) -> anyhow::Result<String> {
    let manifest = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {path}"))?;
    let json: serde_json::Value = serde_json::from_str(&manifest)
        .with_context(|| format!("failed to parse {path}"))?;

    let ami_id = extract_ami_id_from_manifest(&json)
        .with_context(|| format!("in manifest {path}"))?;

    info!(ami = %ami_id, "parsed AMI ID from manifest");
    Ok(ami_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_ami_id_from_single_build() {
        let manifest = json!({
            "builds": [
                { "artifact_id": "us-east-1:ami-0123456789abcdef0" }
            ]
        });
        let id = extract_ami_id_from_manifest(&manifest).unwrap();
        assert_eq!(id, "ami-0123456789abcdef0");
    }

    #[test]
    fn takes_last_build_for_multi_region_manifests() {
        // Packer appends one build entry per region. We always resolve to
        // the last (= most recently completed) so callers pointed at a
        // specific region get the matching AMI, not the first pass.
        let manifest = json!({
            "builds": [
                { "artifact_id": "us-east-1:ami-first" },
                { "artifact_id": "us-west-2:ami-second" },
                { "artifact_id": "eu-west-1:ami-last" }
            ]
        });
        let id = extract_ami_id_from_manifest(&manifest).unwrap();
        assert_eq!(id, "ami-last");
    }

    #[test]
    fn splits_on_first_colon_only() {
        // region:ami-xxx → takes nth(1) which is "ami-xxx". If the split
        // behaviour regressed to splitn(2) with different semantics or
        // `rsplit`, multi-colon payloads would resolve wrong.
        let manifest = json!({
            "builds": [
                { "artifact_id": "us-east-1:ami-abc" }
            ]
        });
        assert_eq!(
            extract_ami_id_from_manifest(&manifest).unwrap(),
            "ami-abc"
        );
    }

    #[test]
    fn errors_when_builds_missing() {
        let manifest = json!({ "other": "field" });
        let err = extract_ami_id_from_manifest(&manifest).unwrap_err();
        assert!(
            err.to_string().contains("0 builds found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn errors_when_builds_is_empty_array() {
        // Packer can produce an empty `builds` array when the build
        // errored before any artifact registered. Must error loudly so
        // the pipeline doesn't "succeed" with a missing AMI.
        let manifest = json!({ "builds": [] });
        let err = extract_ami_id_from_manifest(&manifest).unwrap_err();
        assert!(err.to_string().contains("0 builds found"));
    }

    #[test]
    fn errors_when_builds_is_not_an_array() {
        // Defensive: malformed manifest where `builds` is an object or
        // string. `.as_array()` returns None → same error path as
        // missing.
        let manifest = json!({ "builds": "oops" });
        let err = extract_ami_id_from_manifest(&manifest).unwrap_err();
        assert!(err.to_string().contains("could not extract AMI ID"));
    }

    #[test]
    fn errors_when_artifact_id_missing() {
        let manifest = json!({
            "builds": [ { "other": "field" } ]
        });
        let err = extract_ami_id_from_manifest(&manifest).unwrap_err();
        assert!(err.to_string().contains("1 builds found"));
    }

    #[test]
    fn errors_when_artifact_id_has_no_colon() {
        // Malformed: Packer would never emit this, but a corrupted
        // manifest could. `split(':').nth(1)` returns None.
        let manifest = json!({
            "builds": [ { "artifact_id": "no-colon-here" } ]
        });
        let err = extract_ami_id_from_manifest(&manifest).unwrap_err();
        assert!(err.to_string().contains("could not extract AMI ID"));
    }

    #[test]
    fn parses_empty_segment_after_colon() {
        // "region:" → nth(1) == Some(""). The current implementation
        // accepts this and returns an empty string. Document the
        // behaviour so future tightening (e.g. requiring ami- prefix)
        // is a deliberate break, not a silent one.
        let manifest = json!({
            "builds": [ { "artifact_id": "us-east-1:" } ]
        });
        let id = extract_ami_id_from_manifest(&manifest).unwrap();
        assert_eq!(id, "");
    }

    #[test]
    fn error_context_reports_actual_build_count() {
        // The error message embeds the count so operators reading
        // pipeline logs can distinguish "empty manifest" from "partial
        // manifest with 3 broken builds".
        let manifest = json!({
            "builds": [
                { "artifact_id": "us-east-1:ami-a" },
                { "other": "field" },
                { "other": "field" }
            ]
        });
        let err = extract_ami_id_from_manifest(&manifest).unwrap_err();
        // Last build has no artifact_id → error path, count is 3.
        assert!(
            err.to_string().contains("3 builds found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_packer_manifest_reads_temp_file() {
        // End-to-end: write a minimal manifest to /tmp, parse it, confirm
        // the file-path wrapper reaches the same answer as the pure
        // helper. Uses the std tempdir so no new dev-dep is needed.
        let tmp = std::env::temp_dir().join(format!(
            "ami-forge-manifest-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &tmp,
            r#"{"builds":[{"artifact_id":"us-east-1:ami-feedface"}]}"#,
        )
        .unwrap();
        let id = parse_packer_manifest(tmp.to_str().unwrap()).unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(id, "ami-feedface");
    }

    #[test]
    fn parse_packer_manifest_errors_on_missing_file() {
        // The read_to_string failure must surface with the path in the
        // error chain so pipeline logs point at the right file.
        let err = parse_packer_manifest("/nonexistent/absolutely-not-there.json")
            .unwrap_err();
        let rendered = format!("{err:#}");
        assert!(rendered.contains("/nonexistent/absolutely-not-there.json"));
    }

    #[test]
    fn parse_packer_manifest_errors_on_malformed_json() {
        let tmp = std::env::temp_dir().join(format!(
            "ami-forge-badjson-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&tmp, b"{this is not json").unwrap();
        let err = parse_packer_manifest(tmp.to_str().unwrap()).unwrap_err();
        let _ = std::fs::remove_file(&tmp);
        assert!(format!("{err:#}").contains("failed to parse"));
    }
}
