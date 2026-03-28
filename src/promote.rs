//! Promote an AMI by updating an SSM parameter.
//!
//! Called after successful build + test to make the AMI discoverable
//! by fleet management tools.

use clap::Args;

use crate::aws;

#[derive(Args)]
pub struct PromoteArgs {
    /// AMI ID to promote
    #[arg(long)]
    pub ami_id: String,

    /// SSM parameter to update
    #[arg(long)]
    pub ssm: String,

    /// AWS region
    #[arg(long, default_value = "us-east-1")]
    pub region: String,
}

/// Update SSM parameter with the AMI ID.
pub async fn run(args: PromoteArgs) -> anyhow::Result<()> {
    let config = aws::load_config(&args.region).await;
    let ssm = aws_sdk_ssm::Client::new(&config);
    aws::put_ssm_parameter(&ssm, &args.ssm, &args.ami_id).await
}
