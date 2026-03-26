use anyhow::{Context, bail};
use clap::Args;
use tracing::info;

#[derive(Args)]
pub struct RotateArgs {
    /// Deregister AMI with this name and delete its snapshots
    #[arg(long)]
    ami_name: String,

    /// AWS region
    #[arg(long, default_value = "us-east-1")]
    region: String,
}

/// Find an AMI by its Name tag.
async fn find_ami_by_name(
    client: &aws_sdk_ec2::Client,
    name: &str,
) -> anyhow::Result<Option<aws_sdk_ec2::types::Image>> {
    let resp = client
        .describe_images()
        .owners("self")
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name("name")
                .values(name)
                .build(),
        )
        .send()
        .await
        .context("DescribeImages failed")?;

    // Also search by tag:Name in case the AMI name differs from the Name tag
    let tag_resp = client
        .describe_images()
        .owners("self")
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name("tag:Name")
                .values(name)
                .build(),
        )
        .send()
        .await
        .context("DescribeImages (tag filter) failed")?;

    // Merge results, preferring name match
    let images = resp.images();
    if let Some(img) = images.first() {
        return Ok(Some(img.clone()));
    }

    let tag_images = tag_resp.images();
    if let Some(img) = tag_images.first() {
        return Ok(Some(img.clone()));
    }

    Ok(None)
}

/// Deregister an AMI.
async fn deregister_ami(client: &aws_sdk_ec2::Client, ami_id: &str) -> anyhow::Result<()> {
    info!("Deregistering AMI: {}", ami_id);

    client
        .deregister_image()
        .image_id(ami_id)
        .send()
        .await
        .context("DeregisterImage failed")?;

    Ok(())
}

/// Extract snapshot IDs from an AMI's block device mappings.
fn find_snapshots(image: &aws_sdk_ec2::types::Image) -> Vec<String> {
    image
        .block_device_mappings()
        .iter()
        .filter_map(|bdm| {
            bdm.ebs()
                .and_then(|ebs| ebs.snapshot_id())
                .map(String::from)
        })
        .collect()
}

/// Delete a list of EBS snapshots.
async fn delete_snapshots(
    client: &aws_sdk_ec2::Client,
    snapshot_ids: &[String],
) -> anyhow::Result<()> {
    for sid in snapshot_ids {
        info!("Deleting snapshot: {}", sid);
        client
            .delete_snapshot()
            .snapshot_id(sid)
            .send()
            .await
            .with_context(|| format!("DeleteSnapshot failed for {sid}"))?;
    }
    Ok(())
}

/// Core rotate logic shared between the `rotate` subcommand and `build`.
pub async fn run_rotate(client: &aws_sdk_ec2::Client, ami_name: &str) -> anyhow::Result<()> {
    let image = find_ami_by_name(client, ami_name)
        .await?
        .context("no AMI found with that name")?;

    let ami_id = image.image_id().context("AMI missing image_id")?;
    info!("Found AMI to rotate: {} ({})", ami_name, ami_id);

    let snapshot_ids = find_snapshots(&image);
    info!(
        "Found {} associated snapshot(s): {:?}",
        snapshot_ids.len(),
        snapshot_ids
    );

    // Deregister first, then delete snapshots
    deregister_ami(client, ami_id).await?;

    if snapshot_ids.is_empty() {
        info!("No snapshots to clean up");
    } else {
        delete_snapshots(client, &snapshot_ids).await?;
    }

    info!("Rotation complete for '{}'", ami_name);
    Ok(())
}

/// Entry point for the `rotate` subcommand.
pub async fn run(args: RotateArgs) -> anyhow::Result<()> {
    let region = aws_config::Region::new(args.region);
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region)
        .load()
        .await;

    let ec2_client = aws_sdk_ec2::Client::new(&config);

    match run_rotate(&ec2_client, &args.ami_name).await {
        Ok(()) => Ok(()),
        Err(e) => {
            bail!("Rotation failed: {e}");
        }
    }
}
