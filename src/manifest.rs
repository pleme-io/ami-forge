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

/// Parse manifest and print AMI ID to stdout.
pub fn run(args: ManifestIdArgs) -> anyhow::Result<()> {
    let ami_id = crate::aws::parse_packer_manifest(&args.path)?;
    println!("{ami_id}");
    Ok(())
}
