//! Reusable EC2 test harness for AMI validation.
//!
//! Provides infrastructure lifecycle management for ephemeral test instances:
//! security group creation, instance launch, SSH readiness, and guaranteed
//! cleanup. Any AMI test (VPN connectivity, boot time, service health) can
//! use this harness.

use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use tracing::{info, warn};

use crate::ssh;

/// Configuration for launching test instances.
pub struct HarnessConfig {
    pub ami_id: String,
    pub instance_type: String,
    pub instance_count: i32,
    pub subnet_id: Option<String>,
    /// Maximum time to wait for instances to reach running state.
    pub max_wait: Duration,
}

/// A running test instance with its metadata.
pub struct TestInstance {
    pub instance_id: String,
    pub public_ip: String,
    pub private_ip: String,
    pub az: String,
}

/// Active test environment with ephemeral resources.
///
/// Call [`TestEnv::cleanup`] when done (or drop — but async cleanup
/// can't run in Drop, so explicit cleanup is preferred).
pub struct TestEnv {
    pub instances: Vec<TestInstance>,
    pub security_group_id: String,
    ec2: aws_sdk_ec2::Client,
    instance_ids: Vec<String>,
}

impl TestEnv {
    /// Establish an SSH session to the instance at `index`.
    ///
    /// Pushes the SSH key via EC2 Instance Connect (refreshes 60s TTL),
    /// then connects via openssh with multiplexing.
    pub async fn ssh_to(
        &self,
        index: usize,
        ec2ic: &aws_sdk_ec2instanceconnect::Client,
        ssh_key: &ssh::EphemeralSshKey,
        ssh_user: &str,
        max_wait: Duration,
    ) -> anyhow::Result<openssh::Session> {
        let inst = self.instances.get(index)
            .with_context(|| format!("instance index {index} out of bounds"))?;

        ssh::wait_for_ssh(
            ec2ic,
            &inst.instance_id,
            &inst.az,
            &inst.public_ip,
            ssh_user,
            ssh_key,
            max_wait,
        )
        .await
    }

    /// Terminate all instances and delete the security group.
    pub async fn cleanup(&self) {
        // Terminate instances
        if !self.instance_ids.is_empty() {
            info!(instances = ?self.instance_ids, "terminating test instances");
            if let Err(e) = self
                .ec2
                .terminate_instances()
                .set_instance_ids(Some(self.instance_ids.clone()))
                .send()
                .await
            {
                warn!(error = %e, "failed to terminate test instances");
            }

            wait_for_termination(&self.ec2, &self.instance_ids).await;
        }

        // Delete security group (retry — instances must be fully terminated first)
        info!(sg = %self.security_group_id, "deleting ephemeral security group");
        for attempt in 0..5 {
            match self
                .ec2
                .delete_security_group()
                .group_id(&self.security_group_id)
                .send()
                .await
            {
                Ok(_) => {
                    info!(sg = %self.security_group_id, "security group deleted");
                    return;
                }
                Err(e) => {
                    if attempt < 4 {
                        warn!(
                            sg = %self.security_group_id,
                            attempt = attempt + 1,
                            error = %e,
                            "SG deletion failed, retrying in 10s..."
                        );
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    } else {
                        warn!(
                            sg = %self.security_group_id,
                            error = %e,
                            "failed to delete security group after 5 attempts"
                        );
                    }
                }
            }
        }
    }
}

/// Stand up a test environment: create SG, launch instances, wait for them to be running.
pub async fn create(
    ec2: &aws_sdk_ec2::Client,
    config: &HarnessConfig,
) -> anyhow::Result<TestEnv> {
    // Resolve network
    let (vpc_id, subnet_id, az) = resolve_network(ec2, config.subnet_id.as_deref()).await?;
    info!(vpc = %vpc_id, subnet = %subnet_id, az = %az, "resolved network");

    // Create security group
    let sg_id = create_security_group(ec2, &vpc_id).await?;
    info!(sg = %sg_id, "created ephemeral security group");

    // Launch instances — cleanup SG if launch fails
    let instance_ids = match launch_instances(
        ec2, &config.ami_id, &config.instance_type, &subnet_id, &sg_id, config.instance_count,
    ).await {
        Ok(ids) => ids,
        Err(e) => {
            warn!(sg = %sg_id, error = %e, "instance launch failed, cleaning up SG");
            ec2.delete_security_group().group_id(&sg_id).send().await.ok();
            return Err(e.context("failed to launch test instances"));
        }
    };
    info!(instances = ?instance_ids, "launched test instances");

    // Wait for running + IPs — cleanup instances + SG if wait fails
    let instances = match wait_for_running(ec2, &instance_ids, &az, config.max_wait).await {
        Ok(inst) => inst,
        Err(e) => {
            warn!(error = %e, "instances failed to reach running state, cleaning up");
            let env = TestEnv {
                instances: Vec::new(),
                security_group_id: sg_id,
                ec2: ec2.clone(),
                instance_ids,
            };
            env.cleanup().await;
            return Err(e.context("instances did not reach running state"));
        }
    };
    info!(count = instances.len(), "all instances running with IPs");

    Ok(TestEnv {
        instances,
        security_group_id: sg_id,
        ec2: ec2.clone(),
        instance_ids: instance_ids.clone(),
    })
}

/// Resolve VPC, subnet, and AZ. Uses default VPC if no subnet specified.
async fn resolve_network(
    ec2: &aws_sdk_ec2::Client,
    subnet_id: Option<&str>,
) -> anyhow::Result<(String, String, String)> {
    if let Some(sid) = subnet_id {
        let resp = ec2
            .describe_subnets()
            .subnet_ids(sid)
            .send()
            .await
            .context("DescribeSubnets failed")?;

        let subnet = resp.subnets().first().context("subnet not found")?;
        let vpc_id = subnet.vpc_id().context("subnet missing vpc_id")?.to_string();
        let az = subnet
            .availability_zone()
            .context("subnet missing AZ")?
            .to_string();
        return Ok((vpc_id, sid.to_string(), az));
    }

    // Find default VPC
    let vpcs = ec2
        .describe_vpcs()
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name("isDefault")
                .values("true")
                .build(),
        )
        .send()
        .await
        .context("DescribeVpcs failed")?;

    let vpc = vpcs.vpcs().first().context("no default VPC found")?;
    let vpc_id = vpc.vpc_id().context("VPC missing vpc_id")?.to_string();

    // Find all default subnets, prefer AZs a-d (e/f often lack instance types)
    let subnets = ec2
        .describe_subnets()
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name("vpc-id")
                .values(&vpc_id)
                .build(),
        )
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name("default-for-az")
                .values("true")
                .build(),
        )
        .send()
        .await
        .context("DescribeSubnets (default VPC) failed")?;

    // Sort subnets by AZ name — a,b,c,d first (more likely to support all instance types)
    let mut sorted: Vec<_> = subnets.subnets().to_vec();
    sorted.sort_by_key(|s| s.availability_zone().unwrap_or("z").to_string());

    let subnet = sorted
        .first()
        .context("no default subnet found")?;
    let subnet_id = subnet.subnet_id().context("subnet missing id")?.to_string();
    let az = subnet
        .availability_zone()
        .context("subnet missing AZ")?
        .to_string();

    info!(az = %az, "selected AZ (preferred earliest alphabetical)");
    Ok((vpc_id, subnet_id, az))
}

/// Create a self-referencing security group for test instances.
///
/// Allows: SSH from anywhere (for EC2 Instance Connect), all internal
/// UDP/ICMP between instances in the group.
async fn create_security_group(
    ec2: &aws_sdk_ec2::Client,
    vpc_id: &str,
) -> anyhow::Result<String> {
    let group_name = format!("ami-forge-test-{}", epoch_secs());

    let resp = ec2
        .create_security_group()
        .group_name(&group_name)
        .description("Ephemeral SG for ami-forge test harness")
        .vpc_id(vpc_id)
        .tag_specifications(
            aws_sdk_ec2::types::TagSpecification::builder()
                .resource_type(aws_sdk_ec2::types::ResourceType::SecurityGroup)
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("ManagedBy")
                        .value("ami-forge-test")
                        .build(),
                )
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("Name")
                        .value(&group_name)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .context("CreateSecurityGroup failed")?;

    let sg_id = resp
        .group_id()
        .context("CreateSecurityGroup missing group_id")?
        .to_string();

    // Allow SSH from anywhere + all internal traffic between test instances
    ec2.authorize_security_group_ingress()
        .group_id(&sg_id)
        .ip_permissions(
            aws_sdk_ec2::types::IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(22)
                .to_port(22)
                .ip_ranges(
                    aws_sdk_ec2::types::IpRange::builder()
                        .cidr_ip("0.0.0.0/0")
                        .description("SSH (EC2 Instance Connect)")
                        .build(),
                )
                .build(),
        )
        .ip_permissions(
            aws_sdk_ec2::types::IpPermission::builder()
                .ip_protocol("-1")
                .user_id_group_pairs(
                    aws_sdk_ec2::types::UserIdGroupPair::builder()
                        .group_id(&sg_id)
                        .description("All traffic from self")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .context("AuthorizeSecurityGroupIngress failed")?;

    Ok(sg_id)
}

/// Launch N instances from an AMI.
async fn launch_instances(
    ec2: &aws_sdk_ec2::Client,
    ami_id: &str,
    instance_type: &str,
    subnet_id: &str,
    sg_id: &str,
    count: i32,
) -> anyhow::Result<Vec<String>> {
    let it = instance_type
        .parse::<aws_sdk_ec2::types::InstanceType>()
        .unwrap_or(aws_sdk_ec2::types::InstanceType::T3Medium);

    let resp = ec2
        .run_instances()
        .image_id(ami_id)
        .instance_type(it)
        .min_count(count)
        .max_count(count)
        .subnet_id(subnet_id)
        .security_group_ids(sg_id)
        .tag_specifications(
            aws_sdk_ec2::types::TagSpecification::builder()
                .resource_type(aws_sdk_ec2::types::ResourceType::Instance)
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("ManagedBy")
                        .value("ami-forge-test")
                        .build(),
                )
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("Name")
                        .value("ami-forge-test")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .with_context(|| format!(
            "RunInstances failed (ami={ami_id}, type={instance_type}, subnet={subnet_id}, sg={sg_id})"
        ))?;

    let ids: Vec<String> = resp
        .instances()
        .iter()
        .filter_map(|i| i.instance_id().map(String::from))
        .collect();

    #[allow(clippy::cast_sign_loss)]
    let expected = count as usize;
    if ids.len() != expected {
        bail!("expected {count} instances, got {}", ids.len());
    }

    Ok(ids)
}

/// Wait for instances to reach running state with public + private IPs.
async fn wait_for_running(
    ec2: &aws_sdk_ec2::Client,
    instance_ids: &[String],
    az: &str,
    max_wait: Duration,
) -> anyhow::Result<Vec<TestInstance>> {
    let start = Instant::now();
    let poll_interval = Duration::from_secs(5);

    loop {
        if start.elapsed() > max_wait {
            bail!(
                "instances did not reach running state within {}s",
                max_wait.as_secs()
            );
        }

        let resp = ec2
            .describe_instances()
            .set_instance_ids(Some(instance_ids.to_vec()))
            .send()
            .await
            .context("DescribeInstances failed")?;

        let mut ready: Vec<TestInstance> = Vec::new();

        for reservation in resp.reservations() {
            for instance in reservation.instances() {
                let state = instance
                    .state()
                    .and_then(|s| s.name())
                    .unwrap_or(&aws_sdk_ec2::types::InstanceStateName::Pending);

                if *state != aws_sdk_ec2::types::InstanceStateName::Running {
                    continue;
                }

                let id = instance.instance_id().unwrap_or_default();
                let public_ip = instance.public_ip_address().unwrap_or_default();
                let private_ip = instance.private_ip_address().unwrap_or_default();

                if !public_ip.is_empty() && !private_ip.is_empty() {
                    ready.push(TestInstance {
                        instance_id: id.to_string(),
                        public_ip: public_ip.to_string(),
                        private_ip: private_ip.to_string(),
                        az: az.to_string(),
                    });
                }
            }
        }

        if ready.len() == instance_ids.len() {
            return Ok(ready);
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// Wait for instances to reach terminated state.
async fn wait_for_termination(ec2: &aws_sdk_ec2::Client, instance_ids: &[String]) {
    let max_wait = Duration::from_secs(120);
    let start = Instant::now();

    loop {
        if start.elapsed() > max_wait {
            warn!("timed out waiting for instance termination");
            return;
        }

        match ec2
            .describe_instances()
            .set_instance_ids(Some(instance_ids.to_vec()))
            .send()
            .await
        {
            Ok(resp) => {
                let all_terminated = resp
                    .reservations()
                    .iter()
                    .flat_map(aws_sdk_ec2::types::Reservation::instances)
                    .all(|i| {
                        i.state()
                            .and_then(|s| s.name())
                            .is_some_and(|n| {
                                *n == aws_sdk_ec2::types::InstanceStateName::Terminated
                            })
                    });

                if all_terminated {
                    info!("all test instances terminated");
                    return;
                }
            }
            Err(e) => {
                warn!(error = %e, "DescribeInstances during cleanup failed");
            }
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Seconds since epoch for unique naming.
fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
