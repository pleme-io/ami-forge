use anyhow::Context;
use clap::Args;
use tracing::{info, warn};

#[derive(Args)]
pub struct ReaperArgs {
    /// AWS region
    #[arg(long, default_value = "us-east-1")]
    region: String,

    /// Dry-run mode: report what would be cleaned up without taking action
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

/// Find all running instances managed by ami-forge and terminate any past their TTL.
async fn reap_expired_instances(
    ec2: &aws_sdk_ec2::Client,
    dry_run: bool,
) -> anyhow::Result<u32> {
    let resp = ec2
        .describe_instances()
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name("tag:ManagedBy")
                .values("pangea")
                .build(),
        )
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name("instance-state-name")
                .values("running")
                .values("pending")
                .build(),
        )
        .send()
        .await
        .context("DescribeInstances failed")?;

    let now = chrono::Utc::now();
    let mut terminated = 0u32;
    let mut to_terminate = Vec::new();

    for reservation in resp.reservations() {
        for instance in reservation.instances() {
            let id = instance.instance_id().unwrap_or("unknown");
            let tags = instance.tags();

            let expires_at = tags
                .iter()
                .find(|t| t.key() == Some("ami-forge:expires-at"))
                .and_then(|t| t.value());

            let purpose = tags
                .iter()
                .find(|t| t.key() == Some("ami-forge:purpose"))
                .and_then(|t| t.value())
                .unwrap_or("unknown");

            let name = tags
                .iter()
                .find(|t| t.key() == Some("Name"))
                .and_then(|t| t.value())
                .unwrap_or("unnamed");

            match expires_at {
                Some(expiry_str) => {
                    let expiry = chrono::DateTime::parse_from_rfc3339(expiry_str)
                        .or_else(|_| {
                            // Also try the format used in tag creation
                            chrono::NaiveDateTime::parse_from_str(expiry_str, "%Y-%m-%dT%H:%M:%SZ")
                                .map(|naive| {
                                    naive.and_utc().fixed_offset()
                                })
                        })
                        .with_context(|| {
                            format!("failed to parse expires-at tag '{expiry_str}' on {id}")
                        })?;

                    let expiry_utc = expiry.with_timezone(&chrono::Utc);
                    if now > expiry_utc {
                        let hours_overdue =
                            (now - expiry_utc).num_hours();
                        info!(
                            "{id} ({name}, purpose={purpose}) expired {hours_overdue}h ago — {}",
                            if dry_run { "would terminate" } else { "terminating" }
                        );
                        to_terminate.push(id.to_string());
                    } else {
                        let hours_remaining =
                            (expiry_utc - now).num_hours();
                        info!("{id} ({name}, purpose={purpose}) still valid ({hours_remaining}h remaining)");
                    }
                }
                None => {
                    warn!("{id} ({name}) managed by ami-forge but missing expires-at tag — skipping");
                }
            }
        }
    }

    if !to_terminate.is_empty() {
        if dry_run {
            info!(
                "DRY RUN: would terminate {} instance(s): {:?}",
                to_terminate.len(),
                to_terminate
            );
        } else {
            ec2.terminate_instances()
                .set_instance_ids(Some(to_terminate.clone()))
                .send()
                .await
                .context("TerminateInstances failed")?;
            info!("Terminated {} expired instance(s)", to_terminate.len());
        }
        terminated = to_terminate.len() as u32;
    } else {
        info!("No expired ami-forge instances found");
    }

    Ok(terminated)
}

/// Find all AMIs managed by ami-forge, grouped by purpose prefix.
/// Keep only the newest AMI per prefix; deregister older ones and delete their snapshots.
async fn reap_stale_amis(
    ec2: &aws_sdk_ec2::Client,
    dry_run: bool,
) -> anyhow::Result<u32> {
    let resp = ec2
        .describe_images()
        .owners("self")
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name("tag:ManagedBy")
                .values("pangea")
                .build(),
        )
        .send()
        .await
        .context("DescribeImages failed")?;

    let images = resp.images();
    if images.is_empty() {
        info!("No ami-forge managed AMIs found");
        return Ok(0);
    }

    // Group AMIs by purpose prefix (e.g. "attic-cache", "nixos-k3s-cloud-server")
    // For timestamped names like "attic-cache-20260411-221304", the prefix is "attic-cache"
    let mut groups: std::collections::HashMap<String, Vec<&aws_sdk_ec2::types::Image>> =
        std::collections::HashMap::new();

    for image in images {
        let name = image.name().unwrap_or("unknown");
        // Extract prefix: strip trailing timestamp pattern (-YYYYMMDD-HHMMSS)
        let prefix = strip_timestamp_suffix(name);
        groups.entry(prefix).or_default().push(image);
    }

    let mut deregistered = 0u32;

    for (prefix, mut amis) in groups {
        if amis.len() <= 1 {
            if let Some(ami) = amis.first() {
                info!(
                    "AMI group '{}': 1 AMI ({}), keeping",
                    prefix,
                    ami.image_id().unwrap_or("?")
                );
            }
            continue;
        }

        // Sort by creation date descending (newest first)
        amis.sort_by(|a, b| {
            let a_date = a.creation_date().unwrap_or("");
            let b_date = b.creation_date().unwrap_or("");
            b_date.cmp(a_date)
        });

        let newest = &amis[0];
        info!(
            "AMI group '{}': {} AMIs, keeping newest {} ({})",
            prefix,
            amis.len(),
            newest.image_id().unwrap_or("?"),
            newest.name().unwrap_or("?"),
        );

        for old in &amis[1..] {
            let ami_id = old.image_id().unwrap_or("?");
            let ami_name = old.name().unwrap_or("?");

            // Collect snapshot IDs before deregistering
            let snapshot_ids: Vec<String> = old
                .block_device_mappings()
                .iter()
                .filter_map(|bdm| {
                    bdm.ebs()
                        .and_then(|ebs| ebs.snapshot_id())
                        .map(String::from)
                })
                .collect();

            if dry_run {
                info!(
                    "DRY RUN: would deregister {ami_id} ({ami_name}) + {} snapshot(s)",
                    snapshot_ids.len()
                );
            } else {
                info!("Deregistering {ami_id} ({ami_name})");
                ec2.deregister_image()
                    .image_id(ami_id)
                    .send()
                    .await
                    .with_context(|| format!("DeregisterImage failed for {ami_id}"))?;

                for sid in &snapshot_ids {
                    info!("Deleting snapshot {sid}");
                    if let Err(e) = ec2.delete_snapshot().snapshot_id(sid).send().await {
                        warn!("Failed to delete snapshot {sid}: {e}");
                    }
                }
            }
            deregistered += 1;
        }
    }

    Ok(deregistered)
}

/// Strip a trailing timestamp suffix like `-20260411-221304` from an AMI name.
///
/// Returns the prefix for grouping. If no timestamp suffix is found, returns
/// the full name (it's a group of one).
fn strip_timestamp_suffix(name: &str) -> String {
    // Match pattern: name-YYYYMMDD-HHMMSS  (-8-6 = 16 chars total)
    if name.len() >= 16 {
        let candidate = &name[name.len() - 16..]; // "-YYYYMMDD-HHMMSS"
        if candidate.starts_with('-')
            && candidate[1..9].chars().all(|c| c.is_ascii_digit())
            && candidate[9..10].starts_with('-')
            && candidate[10..].chars().all(|c| c.is_ascii_digit())
        {
            return name[..name.len() - 16].to_string();
        }
    }
    name.to_string()
}

/// Core reaper logic shared between the `reaper` subcommand and `pipeline-run`.
pub async fn run_reaper(ec2: &aws_sdk_ec2::Client) -> anyhow::Result<()> {
    let instances_reaped = reap_expired_instances(ec2, false).await?;
    let amis_reaped = reap_stale_amis(ec2, false).await?;
    info!(
        "Reaper complete: {} instance(s) terminated, {} AMI(s) deregistered",
        instances_reaped, amis_reaped
    );
    Ok(())
}

/// Entry point for the `reaper` subcommand.
pub async fn run(args: ReaperArgs) -> anyhow::Result<()> {
    let config = crate::aws::load_config(&args.region).await;
    let ec2_client = aws_sdk_ec2::Client::new(&config);

    if args.dry_run {
        info!("=== DRY RUN MODE — no resources will be modified ===");
    }

    info!("--- Reaping expired EC2 instances ---");
    let instances_reaped = reap_expired_instances(&ec2_client, args.dry_run).await?;

    info!("--- Reaping stale AMIs (keeping newest per group) ---");
    let amis_reaped = reap_stale_amis(&ec2_client, args.dry_run).await?;

    info!(
        "Reaper complete: {} instance(s) terminated, {} AMI(s) deregistered{}",
        instances_reaped,
        amis_reaped,
        if args.dry_run { " (dry run)" } else { "" }
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_timestamp_suffix() {
        assert_eq!(
            strip_timestamp_suffix("attic-cache-20260411-221304"),
            "attic-cache"
        );
        assert_eq!(
            strip_timestamp_suffix("attic-cache-20260331-020354"),
            "attic-cache"
        );
        assert_eq!(
            strip_timestamp_suffix("nixos-k3s-cloud-server"),
            "nixos-k3s-cloud-server"
        );
        assert_eq!(
            strip_timestamp_suffix("nixos-attic-server"),
            "nixos-attic-server"
        );
    }
}
