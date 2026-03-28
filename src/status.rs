use anyhow::Context;
use clap::Args;
use tracing::info;

#[derive(Args)]
pub struct StatusArgs {
    /// SSM parameter to read current AMI ID
    #[arg(long)]
    ssm: Option<String>,

    /// Check AMI details by name
    #[arg(long)]
    ami_name: Option<String>,

    /// AWS region
    #[arg(long, default_value = "us-east-1")]
    region: String,
}

/// Read a value from SSM Parameter Store.
async fn get_ssm_value(client: &aws_sdk_ssm::Client, param: &str) -> anyhow::Result<String> {
    let resp = client
        .get_parameter()
        .name(param)
        .send()
        .await
        .with_context(|| format!("SSM GetParameter failed for {param}"))?;

    let value = resp
        .parameter()
        .and_then(|p| p.value())
        .context("SSM parameter has no value")?
        .to_string();

    Ok(value)
}

/// Describe an AMI by name or ID.
async fn describe_ami(
    client: &aws_sdk_ec2::Client,
    name_or_id: &str,
) -> anyhow::Result<Option<aws_sdk_ec2::types::Image>> {
    // Try as AMI ID first (starts with ami-)
    if name_or_id.starts_with("ami-") {
        let resp = client
            .describe_images()
            .image_ids(name_or_id)
            .send()
            .await
            .context("DescribeImages by ID failed")?;

        if let Some(img) = resp.images().first() {
            return Ok(Some(img.clone()));
        }
    }

    // Search by Name tag
    let resp = client
        .describe_images()
        .owners("self")
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name("tag:Name")
                .values(name_or_id)
                .build(),
        )
        .send()
        .await
        .context("DescribeImages by tag failed")?;

    if let Some(img) = resp.images().first() {
        return Ok(Some(img.clone()));
    }

    // Search by AMI name
    let resp = client
        .describe_images()
        .owners("self")
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name("name")
                .values(name_or_id)
                .build(),
        )
        .send()
        .await
        .context("DescribeImages by name failed")?;

    Ok(resp.images().first().cloned())
}

/// Print AMI details to stdout.
fn print_ami_details(image: &aws_sdk_ec2::types::Image) {
    let ami_id = image.image_id().unwrap_or("unknown");
    let name = image.name().unwrap_or("(no name)");
    let state = image
        .state().map_or_else(|| "unknown".to_string(), |s| s.as_str().to_string());
    let creation = image.creation_date().unwrap_or("unknown");
    let description = image.description().unwrap_or("(no description)");
    let architecture = image
        .architecture().map_or_else(|| "unknown".to_string(), |a| a.as_str().to_string());

    println!("AMI Details:");
    println!("  ID:           {ami_id}");
    println!("  Name:         {name}");
    println!("  State:        {state}");
    println!("  Architecture: {architecture}");
    println!("  Created:      {creation}");
    println!("  Description:  {description}");

    let snapshots: Vec<&str> = image
        .block_device_mappings()
        .iter()
        .filter_map(|bdm| bdm.ebs().and_then(|ebs| ebs.snapshot_id()))
        .collect();

    if !snapshots.is_empty() {
        println!("  Snapshots:    {}", snapshots.join(", "));
    }

    let tags: Vec<String> = image
        .tags()
        .iter()
        .map(|t| {
            format!(
                "{}={}",
                t.key().unwrap_or("?"),
                t.value().unwrap_or("?")
            )
        })
        .collect();

    if !tags.is_empty() {
        println!("  Tags:         {}", tags.join(", "));
    }
}

/// Entry point for the `status` subcommand.
pub async fn run(args: StatusArgs) -> anyhow::Result<()> {
    if args.ssm.is_none() && args.ami_name.is_none() {
        anyhow::bail!("At least one of --ssm or --ami-name is required");
    }

    let config = crate::aws::load_config(&args.region).await;
    let ec2_client = aws_sdk_ec2::Client::new(&config);
    let ssm_client = aws_sdk_ssm::Client::new(&config);

    // Show SSM value if requested
    if let Some(ref ssm_path) = args.ssm {
        match get_ssm_value(&ssm_client, ssm_path).await {
            Ok(value) => {
                println!("SSM Parameter: {ssm_path}");
                println!("  Value: {value}");

                // Also look up the AMI details for the stored ID
                if value.starts_with("ami-") {
                    info!("Looking up AMI details for {}", value);
                    if let Some(image) = describe_ami(&ec2_client, &value).await? {
                        println!();
                        print_ami_details(&image);
                    }
                }
            }
            Err(e) => {
                println!("SSM Parameter: {ssm_path}");
                println!("  Error: {e}");
            }
        }
    }

    // Show AMI details by name if requested
    if let Some(ref ami_name) = args.ami_name {
        if args.ssm.is_some() {
            println!();
        }
        match describe_ami(&ec2_client, ami_name).await? {
            Some(image) => print_ami_details(&image),
            None => println!("No AMI found with name/id: {ami_name}"),
        }
    }

    Ok(())
}
