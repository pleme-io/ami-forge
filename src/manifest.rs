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
///
/// Uses the pure `aws::extract_ami_id_from_manifest` helper so the
/// extraction logic stays in lockstep with `parse_packer_manifest`.
/// The only divergence from that wrapper is the absent `info!` call —
/// this command's stdout is consumed by shell scripts (`AMI_ID=$(...)`)
/// so extra noise on stdout is off-limits; tracing goes to stderr and
/// is suppressed at the call site anyway.
pub fn run(args: ManifestIdArgs) -> anyhow::Result<()> {
    let manifest = std::fs::read_to_string(&args.path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", args.path))?;
    let json: serde_json::Value = serde_json::from_str(&manifest)
        .map_err(|e| anyhow::anyhow!("failed to parse {}: {e}", args.path))?;

    let ami_id = crate::aws::extract_ami_id_from_manifest(&json)
        .map_err(|e| anyhow::anyhow!("{}: {e}", args.path))?;

    print!("{ami_id}");
    Ok(())
}
