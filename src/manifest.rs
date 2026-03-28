//! Parse Packer manifest and extract AMI ID.
//!
//! Prints the AMI ID to stdout for shell script consumption:
//!   AMI_ID=$(ami-forge manifest-id packer-manifest.json)

use clap::Args;

#[derive(Args)]
pub struct ManifestIdArgs {
    /// Path to packer-manifest.json
    pub path: String,
}

/// Parse manifest and print AMI ID to stdout (no logging).
pub fn run(args: ManifestIdArgs) -> anyhow::Result<()> {
    // Use direct parsing without aws::parse_packer_manifest to avoid info! log
    let manifest = std::fs::read_to_string(&args.path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", args.path))?;
    let json: serde_json::Value = serde_json::from_str(&manifest)
        .map_err(|e| anyhow::anyhow!("failed to parse {}: {e}", args.path))?;

    let ami_id = json["builds"]
        .as_array()
        .and_then(|builds| builds.last())
        .and_then(|build| build["artifact_id"].as_str())
        .and_then(|artifact| artifact.split(':').nth(1))
        .ok_or_else(|| anyhow::anyhow!("could not extract AMI ID from {}", args.path))?;

    // Print ONLY the AMI ID — no logging, no formatting
    print!("{ami_id}");
    Ok(())
}
