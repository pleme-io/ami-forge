//! Reusable EC2 test harness for AMI validation.
//!
//! Provides infrastructure lifecycle management for ephemeral test instances:
//! EC2 key pair creation, security group, instance launch, SSH readiness, and
//! guaranteed cleanup. Any AMI test (VPN, boot time, service health) can use
//! this harness.
//!
//! SSH access uses EC2 key pairs — the NixOS-native approach. NixOS AMIs
//! automatically read the key pair from IMDS and add it to root's
//! authorized_keys via amazon-image.nix. No agents, no user-data scripts.

use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use tracing::{info, warn};

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
/// Call [`TestEnv::cleanup`] when done. All resources (instances, SG, key pair)
/// are cleaned up even on failure.
pub struct TestEnv {
    pub instances: Vec<TestInstance>,
    pub security_group_id: String,
    /// Path to the ephemeral SSH private key file (EC2 key pair).
    pub ssh_private_key_path: std::path::PathBuf,
    ec2: aws_sdk_ec2::Client,
    instance_ids: Vec<String>,
    key_pair_name: String,
    _key_temp_dir: tempfile::TempDir,
}

impl TestEnv {
    /// Establish an SSH session to the instance at `index`.
    pub async fn ssh_to(
        &self,
        index: usize,
        ssh_user: &str,
        max_wait: Duration,
    ) -> anyhow::Result<openssh::Session> {
        let inst = self.instances.get(index)
            .with_context(|| format!("instance index {index} out of bounds"))?;

        crate::ssh::wait_for_ssh_direct(
            &inst.public_ip,
            ssh_user,
            &self.ssh_private_key_path,
            max_wait,
        )
        .await
    }

    /// Terminate all instances, delete security group and key pair.
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

        // Delete security group
        info!(sg = %self.security_group_id, "deleting ephemeral security group");
        for attempt in 0..5 {
            match self.ec2.delete_security_group().group_id(&self.security_group_id).send().await {
                Ok(_) => { info!(sg = %self.security_group_id, "security group deleted"); break; }
                Err(e) => {
                    if attempt < 4 {
                        warn!(sg = %self.security_group_id, attempt = attempt + 1, error = %e, "SG deletion failed, retrying in 10s...");
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    } else {
                        warn!(sg = %self.security_group_id, error = %e, "failed to delete SG after 5 attempts");
                    }
                }
            }
        }

        // Delete EC2 key pair
        info!(key = %self.key_pair_name, "deleting ephemeral key pair");
        if let Err(e) = self.ec2.delete_key_pair().key_name(&self.key_pair_name).send().await {
            warn!(key = %self.key_pair_name, error = %e, "failed to delete key pair");
        }
    }
}

/// Stand up a test environment: create key pair, SG, launch instances, wait for running.
pub async fn create(
    ec2: &aws_sdk_ec2::Client,
    config: &HarnessConfig,
) -> anyhow::Result<TestEnv> {
    // Resolve network
    let (vpc_id, subnet_id, az) = resolve_network(ec2, config.subnet_id.as_deref()).await?;
    info!(vpc = %vpc_id, subnet = %subnet_id, az = %az, "resolved network");

    // Create ephemeral EC2 key pair
    let key_name = format!("ami-forge-test-{}", epoch_secs());
    let (key_path, key_temp_dir) = create_key_pair(ec2, &key_name).await?;
    info!(key = %key_name, "created ephemeral EC2 key pair");

    // Create security group
    let sg_id = create_security_group(ec2, &vpc_id).await?;
    info!(sg = %sg_id, "created ephemeral security group");

    // Launch instances with key pair
    let instance_ids = match launch_instances(
        ec2, &config.ami_id, &config.instance_type, &subnet_id, &sg_id,
        config.instance_count, &key_name,
    ).await {
        Ok(ids) => ids,
        Err(e) => {
            warn!(sg = %sg_id, error = %e, "instance launch failed, cleaning up");
            ec2.delete_security_group().group_id(&sg_id).send().await.ok();
            ec2.delete_key_pair().key_name(&key_name).send().await.ok();
            return Err(e.context("failed to launch test instances"));
        }
    };
    info!(instances = ?instance_ids, "launched test instances");

    // Wait for running + IPs
    let instances = match wait_for_running(ec2, &instance_ids, &az, config.max_wait).await {
        Ok(inst) => inst,
        Err(e) => {
            warn!(error = %e, "instances failed to reach running state, cleaning up");
            let env = TestEnv {
                instances: Vec::new(),
                security_group_id: sg_id,
                ssh_private_key_path: key_path,
                ec2: ec2.clone(),
                instance_ids,
                key_pair_name: key_name,
                _key_temp_dir: key_temp_dir,
            };
            env.cleanup().await;
            return Err(e.context("instances did not reach running state"));
        }
    };
    info!(count = instances.len(), "all instances running with IPs");

    Ok(TestEnv {
        instances,
        security_group_id: sg_id,
        ssh_private_key_path: key_path,
        ec2: ec2.clone(),
        instance_ids: instance_ids.clone(),
        key_pair_name: key_name,
        _key_temp_dir: key_temp_dir,
    })
}

/// Create an EC2 key pair and write the private key to a temp file.
async fn create_key_pair(
    ec2: &aws_sdk_ec2::Client,
    key_name: &str,
) -> anyhow::Result<(std::path::PathBuf, tempfile::TempDir)> {
    let resp = ec2
        .create_key_pair()
        .key_name(key_name)
        .key_type(aws_sdk_ec2::types::KeyType::Ed25519)
        .tag_specifications(
            aws_sdk_ec2::types::TagSpecification::builder()
                .resource_type(aws_sdk_ec2::types::ResourceType::KeyPair)
                .tags(aws_sdk_ec2::types::Tag::builder().key("ManagedBy").value("ami-forge-test").build())
                .build(),
        )
        .send()
        .await
        .context("CreateKeyPair failed")?;

    let key_material = resp
        .key_material()
        .context("CreateKeyPair response missing key material")?;

    let temp_dir = tempfile::tempdir().context("failed to create temp dir for key")?;
    let key_path = temp_dir.path().join("id_ed25519");
    std::fs::write(&key_path, key_material).context("failed to write private key")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .context("failed to set key permissions")?;
    }

    Ok((key_path, temp_dir))
}

/// Resolve VPC, subnet, and AZ. Prefers early AZs (a-d) which support all instance types.
async fn resolve_network(
    ec2: &aws_sdk_ec2::Client,
    subnet_id: Option<&str>,
) -> anyhow::Result<(String, String, String)> {
    if let Some(sid) = subnet_id {
        let resp = ec2.describe_subnets().subnet_ids(sid).send().await.context("DescribeSubnets failed")?;
        let subnet = resp.subnets().first().context("subnet not found")?;
        let vpc_id = subnet.vpc_id().context("subnet missing vpc_id")?.to_string();
        let az = subnet.availability_zone().context("subnet missing AZ")?.to_string();
        return Ok((vpc_id, sid.to_string(), az));
    }

    // Find default VPC
    let vpcs = ec2
        .describe_vpcs()
        .filters(aws_sdk_ec2::types::Filter::builder().name("isDefault").values("true").build())
        .send().await.context("DescribeVpcs failed")?;
    let vpc = vpcs.vpcs().first().context("no default VPC found")?;
    let vpc_id = vpc.vpc_id().context("VPC missing vpc_id")?.to_string();

    // Find default subnets, prefer early AZs
    let subnets = ec2
        .describe_subnets()
        .filters(aws_sdk_ec2::types::Filter::builder().name("vpc-id").values(&vpc_id).build())
        .filters(aws_sdk_ec2::types::Filter::builder().name("default-for-az").values("true").build())
        .send().await.context("DescribeSubnets (default VPC) failed")?;

    let mut sorted: Vec<_> = subnets.subnets().to_vec();
    sorted.sort_by_key(|s| s.availability_zone().unwrap_or("z").to_string());

    let subnet = sorted.first().context("no default subnet found")?;
    let subnet_id = subnet.subnet_id().context("subnet missing id")?.to_string();
    let az = subnet.availability_zone().context("subnet missing AZ")?.to_string();
    info!(az = %az, "selected AZ (preferred earliest alphabetical)");
    Ok((vpc_id, subnet_id, az))
}

/// Create a self-referencing security group for test instances.
async fn create_security_group(ec2: &aws_sdk_ec2::Client, vpc_id: &str) -> anyhow::Result<String> {
    let group_name = format!("ami-forge-test-{}", epoch_secs());
    let resp = ec2
        .create_security_group()
        .group_name(&group_name)
        .description("Ephemeral SG for ami-forge test harness")
        .vpc_id(vpc_id)
        .tag_specifications(
            aws_sdk_ec2::types::TagSpecification::builder()
                .resource_type(aws_sdk_ec2::types::ResourceType::SecurityGroup)
                .tags(aws_sdk_ec2::types::Tag::builder().key("ManagedBy").value("ami-forge-test").build())
                .tags(aws_sdk_ec2::types::Tag::builder().key("Name").value(&group_name).build())
                .build(),
        )
        .send().await.context("CreateSecurityGroup failed")?;

    let sg_id = resp.group_id().context("CreateSecurityGroup missing group_id")?.to_string();

    ec2.authorize_security_group_ingress()
        .group_id(&sg_id)
        .ip_permissions(
            aws_sdk_ec2::types::IpPermission::builder()
                .ip_protocol("tcp").from_port(22).to_port(22)
                .ip_ranges(aws_sdk_ec2::types::IpRange::builder().cidr_ip("0.0.0.0/0").description("SSH").build())
                .build(),
        )
        .ip_permissions(
            aws_sdk_ec2::types::IpPermission::builder()
                .ip_protocol("-1")
                .user_id_group_pairs(aws_sdk_ec2::types::UserIdGroupPair::builder().group_id(&sg_id).description("All traffic from self").build())
                .build(),
        )
        .send().await.context("AuthorizeSecurityGroupIngress failed")?;

    Ok(sg_id)
}

/// Launch N instances from an AMI with an EC2 key pair.
async fn launch_instances(
    ec2: &aws_sdk_ec2::Client, ami_id: &str, instance_type: &str,
    subnet_id: &str, sg_id: &str, count: i32, key_name: &str,
) -> anyhow::Result<Vec<String>> {
    let it = instance_type.parse::<aws_sdk_ec2::types::InstanceType>()
        .unwrap_or(aws_sdk_ec2::types::InstanceType::T3Medium);

    let resp = ec2.run_instances()
        .image_id(ami_id).instance_type(it)
        .min_count(count).max_count(count)
        .subnet_id(subnet_id).security_group_ids(sg_id)
        .key_name(key_name)
        .tag_specifications(
            aws_sdk_ec2::types::TagSpecification::builder()
                .resource_type(aws_sdk_ec2::types::ResourceType::Instance)
                .tags(aws_sdk_ec2::types::Tag::builder().key("ManagedBy").value("ami-forge-test").build())
                .tags(aws_sdk_ec2::types::Tag::builder().key("Name").value("ami-forge-test").build())
                .build(),
        )
        .send().await
        .with_context(|| format!("RunInstances failed (ami={ami_id}, type={instance_type}, subnet={subnet_id}, sg={sg_id})"))?;

    let ids: Vec<String> = resp.instances().iter()
        .filter_map(|i| i.instance_id().map(String::from)).collect();

    #[allow(clippy::cast_sign_loss)]
    let expected = count as usize;
    if ids.len() != expected { bail!("expected {count} instances, got {}", ids.len()); }
    Ok(ids)
}

/// Wait for instances to reach running state with public + private IPs.
async fn wait_for_running(
    ec2: &aws_sdk_ec2::Client, instance_ids: &[String], az: &str, max_wait: Duration,
) -> anyhow::Result<Vec<TestInstance>> {
    let start = Instant::now();
    loop {
        if start.elapsed() > max_wait {
            bail!("instances did not reach running state within {}s", max_wait.as_secs());
        }

        let resp = ec2.describe_instances()
            .set_instance_ids(Some(instance_ids.to_vec()))
            .send().await.context("DescribeInstances failed")?;

        let mut ready: Vec<TestInstance> = Vec::new();
        for reservation in resp.reservations() {
            for instance in reservation.instances() {
                let state = instance.state().and_then(|s| s.name())
                    .unwrap_or(&aws_sdk_ec2::types::InstanceStateName::Pending);
                if *state != aws_sdk_ec2::types::InstanceStateName::Running { continue; }

                let public_ip = instance.public_ip_address().unwrap_or_default();
                let private_ip = instance.private_ip_address().unwrap_or_default();
                if !public_ip.is_empty() && !private_ip.is_empty() {
                    ready.push(TestInstance {
                        instance_id: instance.instance_id().unwrap_or_default().to_string(),
                        public_ip: public_ip.to_string(),
                        private_ip: private_ip.to_string(),
                        az: az.to_string(),
                    });
                }
            }
        }
        if ready.len() == instance_ids.len() { return Ok(ready); }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Wait for instances to reach terminated state.
async fn wait_for_termination(ec2: &aws_sdk_ec2::Client, instance_ids: &[String]) {
    let start = Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(120) { warn!("timed out waiting for termination"); return; }
        match ec2.describe_instances().set_instance_ids(Some(instance_ids.to_vec())).send().await {
            Ok(resp) => {
                let all = resp.reservations().iter()
                    .flat_map(aws_sdk_ec2::types::Reservation::instances)
                    .all(|i| i.state().and_then(|s| s.name())
                        .is_some_and(|n| *n == aws_sdk_ec2::types::InstanceStateName::Terminated));
                if all { info!("all test instances terminated"); return; }
            }
            Err(e) => { warn!(error = %e, "DescribeInstances during cleanup failed"); }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

fn epoch_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}
