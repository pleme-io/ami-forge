//! Shared Attic ephemeral cache lifecycle: boot, health-check, snapshot, teardown.
//!
//! Used by both the single-pipeline (`pipeline-run`) and the multi-layer
//! pipeline (`multi-layer-run`).

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::time::{Duration, Instant};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Config + resource types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AtticConfig {
    /// SSM parameter storing the last-known-good Attic cache AMI ID.
    pub ssm: String,
    /// EC2 instance type for the ephemeral Attic cache server.
    #[serde(default = "default_attic_instance_type")]
    pub instance_type: String,
    /// Attic cache name (path component in the substituter URL).
    #[serde(default = "default_attic_cache_name")]
    pub cache_name: String,
}

fn default_attic_instance_type() -> String {
    "t3.medium".into()
}
fn default_attic_cache_name() -> String {
    "nexus".into()
}

/// Tracked resources for Attic ephemeral cache lifecycle.
///
/// Contains everything needed for health checks, build URL injection,
/// and cleanup (instance + security group).
pub struct AtticResources {
    pub instance_id: String,
    /// Private IP -- used for the substituter URL (build instance is in the same VPC).
    pub private_ip: String,
    /// Public IP -- used for health checks from the local machine.
    pub public_ip: String,
    /// Security group created for Attic (allows port 8080 ingress).
    pub sg_id: String,
}

// ---------------------------------------------------------------------------
// Lifecycle functions
// ---------------------------------------------------------------------------

/// Boot an Attic cache instance from the last-known-good AMI.
///
/// Creates a temporary security group that allows TCP 8080 from 0.0.0.0/0
/// (needed for the health check from the local machine), launches the instance,
/// and polls for both private and public IPs.
pub async fn attic_boot(
    ec2: &aws_sdk_ec2::Client,
    ssm: &aws_sdk_ssm::Client,
    config: &AtticConfig,
) -> Result<AtticResources> {
    // 1. Resolve Attic AMI ID from SSM
    let ami_id = ssm
        .get_parameter()
        .name(&config.ssm)
        .send()
        .await
        .context("failed to read Attic AMI from SSM")?
        .parameter()
        .and_then(|p| p.value().map(String::from))
        .context("SSM parameter for Attic AMI has no value")?;

    info!("Booting Attic cache from AMI {ami_id}");

    // 2. Create temporary security group for Attic (port 8080 open)
    let vpc_resp = ec2
        .describe_vpcs()
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name("isDefault")
                .values("true")
                .build(),
        )
        .send()
        .await?;
    let vpc_id = vpc_resp
        .vpcs()
        .first()
        .and_then(|v| v.vpc_id())
        .context("no default VPC")?;

    let sg_name = format!("ami-forge-attic-{}", std::process::id());
    let sg_resp = ec2
        .create_security_group()
        .group_name(&sg_name)
        .description("Temporary SG for Attic cache - allows port 8080")
        .vpc_id(vpc_id)
        .tag_specifications(
            aws_sdk_ec2::types::TagSpecification::builder()
                .resource_type(aws_sdk_ec2::types::ResourceType::SecurityGroup)
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("Name")
                        .value("ami-forge-attic-cache")
                        .build(),
                )
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("ManagedBy")
                        .value("ami-forge")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .context("CreateSecurityGroup for Attic failed")?;
    let sg_id = sg_resp.group_id().context("no SG ID")?.to_string();
    info!("Attic security group created: {sg_id}");

    // Allow TCP 8080 from anywhere (health check runs from local machine)
    ec2.authorize_security_group_ingress()
        .group_id(&sg_id)
        .ip_permissions(
            aws_sdk_ec2::types::IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(8080)
                .to_port(8080)
                .ip_ranges(
                    aws_sdk_ec2::types::IpRange::builder()
                        .cidr_ip("0.0.0.0/0")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .context("authorize_security_group_ingress (attic 8080) failed")?;

    // 3. Launch instance with the new SG
    let resp = ec2
        .run_instances()
        .image_id(&ami_id)
        .instance_type(aws_sdk_ec2::types::InstanceType::from(
            config.instance_type.as_str(),
        ))
        .min_count(1)
        .max_count(1)
        .security_group_ids(&sg_id)
        .tag_specifications(
            aws_sdk_ec2::types::TagSpecification::builder()
                .resource_type(aws_sdk_ec2::types::ResourceType::Instance)
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("Name")
                        .value("ami-forge-attic-cache")
                        .build(),
                )
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("ManagedBy")
                        .value("ami-forge")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .context("failed to launch Attic instance")?;

    let instance_id = resp
        .instances()
        .first()
        .and_then(|i| i.instance_id())
        .context("no instance ID in launch response")?
        .to_string();

    info!("Attic instance launched: {instance_id}");

    // 4. Poll for both private and public IPs (instance must be running)
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if Instant::now() > deadline {
            bail!("Attic instance {instance_id} did not get IPs within 120s");
        }
        let desc = ec2
            .describe_instances()
            .instance_ids(&instance_id)
            .send()
            .await?;
        let inst = desc
            .reservations()
            .first()
            .and_then(|r| r.instances().first());
        let private_ip = inst.and_then(|i| i.private_ip_address());
        let public_ip = inst.and_then(|i| i.public_ip_address());

        if let (Some(priv_ip), Some(pub_ip)) = (private_ip, public_ip) {
            info!(
                "Attic instance {instance_id} ready -- private={priv_ip}, public={pub_ip}"
            );
            return Ok(AtticResources {
                instance_id,
                private_ip: priv_ip.to_string(),
                public_ip: pub_ip.to_string(),
                sg_id,
            });
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Wait for the Attic HTTP service to become healthy (port 8080).
///
/// Accepts either a 200-level response or 404 (Attic returns 404 on `/`
/// when the cache is empty but the service is healthy).
pub async fn attic_wait_healthy(ip: &str, timeout_secs: u64) -> Result<()> {
    let url = format!("http://{ip}:8080/");
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    loop {
        if Instant::now() > deadline {
            bail!("Attic service at {url} not healthy after {timeout_secs}s");
        }
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() || resp.status().as_u16() == 404 => {
                info!("Attic service healthy at {url}");
                return Ok(());
            }
            _ => {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

/// Snapshot the Attic instance as a new AMI and promote to SSM.
///
/// Called unconditionally after the build phase -- even when tests fail the
/// cache still contains new nars that speed up the next build.
pub async fn attic_snapshot(
    ec2: &aws_sdk_ec2::Client,
    ssm_client: &aws_sdk_ssm::Client,
    instance_id: &str,
    ssm_param: &str,
) -> Result<()> {
    info!("Snapshotting Attic instance {instance_id}");

    let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let resp = ec2
        .create_image()
        .instance_id(instance_id)
        .name(format!("attic-cache-{ts}"))
        .description("Ephemeral Attic binary cache -- auto-generated by ami-forge")
        .no_reboot(false)
        .send()
        .await
        .context("failed to create Attic AMI")?;

    let ami_id = resp
        .image_id()
        .context("no AMI ID in create_image response")?;
    info!("Attic AMI created: {ami_id}, waiting for availability...");

    // Wait for AMI to become available
    let deadline = Instant::now() + Duration::from_secs(600);
    loop {
        if Instant::now() > deadline {
            bail!("Attic AMI {ami_id} did not become available within 600s");
        }
        let desc = ec2.describe_images().image_ids(ami_id).send().await?;
        if let Some(state) = desc.images().first().and_then(|i| i.state()) {
            if state.as_str() == "available" {
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }

    // Promote new Attic AMI to SSM
    crate::aws::put_ssm_parameter(ssm_client, ssm_param, ami_id).await?;
    info!("Attic AMI {ami_id} promoted to {ssm_param}");

    Ok(())
}

/// Terminate the ephemeral Attic instance and delete its security group.
pub async fn attic_teardown(ec2: &aws_sdk_ec2::Client, res: &AtticResources) -> Result<()> {
    info!("Terminating Attic instance {}", res.instance_id);
    ec2.terminate_instances()
        .instance_ids(&res.instance_id)
        .send()
        .await
        .context("failed to terminate Attic instance")?;

    // Wait for termination, then delete the security group.
    // SG deletion fails while instances are still using it.
    info!("Deleting Attic security group: {}", res.sg_id);
    for attempt in 0..5 {
        tokio::time::sleep(Duration::from_secs(10)).await;
        match ec2
            .delete_security_group()
            .group_id(&res.sg_id)
            .send()
            .await
        {
            Ok(_) => {
                info!("Attic security group {} deleted", res.sg_id);
                return Ok(());
            }
            Err(e) => {
                if attempt < 4 {
                    warn!(
                        "Attic SG delete attempt {}: {e} -- retrying",
                        attempt + 1
                    );
                } else {
                    warn!("Failed to delete Attic SG {}: {e}", res.sg_id);
                }
            }
        }
    }
    Ok(())
}
