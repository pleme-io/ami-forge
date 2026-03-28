//! Multi-node cluster integration test.
//!
//! Launches 2 EC2 instances (CP + worker) from a built AMI, injects test
//! userdata with cross-referenced WireGuard keys, validates VPN peering,
//! K3s 2-node cluster formation, and kubectl. Cleans up all resources
//! on success or failure.

use anyhow::{bail, Context, Result};
use clap::Args;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

use crate::wg;

#[derive(Args)]
pub struct ClusterTestArgs {
    /// AMI ID to test
    #[arg(long)]
    pub ami_id: String,

    /// AWS region
    #[arg(long, default_value = "us-east-1")]
    pub region: String,

    /// Instance type for test nodes
    #[arg(long, default_value = "c7i.xlarge")]
    pub instance_type: String,

    /// Total timeout in seconds for the cluster to form
    #[arg(long, default_value_t = 480)]
    pub timeout: u64,
}

struct TestResources {
    keypair_name: Option<String>,
    sg_id: Option<String>,
    instance_ids: Vec<String>,
    key_file: Option<PathBuf>,
}

impl TestResources {
    fn new() -> Self {
        Self {
            keypair_name: None,
            sg_id: None,
            instance_ids: Vec::new(),
            key_file: None,
        }
    }
}

pub async fn run(args: ClusterTestArgs) -> Result<()> {
    let config = crate::aws::load_config(&args.region).await;
    let ec2 = aws_sdk_ec2::Client::new(&config);

    let mut resources = TestResources::new();
    let result = run_inner(&ec2, &args, &mut resources).await;

    // Always cleanup, even on failure
    cleanup(&ec2, &resources).await;

    result
}

async fn run_inner(
    ec2: &aws_sdk_ec2::Client,
    args: &ClusterTestArgs,
    res: &mut TestResources,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(args.timeout);

    // 1. Generate WireGuard keypairs for both nodes
    info!("[cluster-test:1/7] Generating WireGuard keypairs");
    let cp_keys = wg::generate_keypair();
    let worker_keys = wg::generate_keypair();
    let psk = wg::generate_psk();

    // 2. Create temp EC2 keypair
    info!("[cluster-test:2/7] Creating temporary EC2 keypair");
    let keypair_name = format!(
        "ami-forge-cluster-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    );
    let key_resp = ec2
        .create_key_pair()
        .key_name(&keypair_name)
        .key_type(aws_sdk_ec2::types::KeyType::Ed25519)
        .send()
        .await
        .context("CreateKeyPair failed")?;
    res.keypair_name = Some(keypair_name.clone());

    let key_material = key_resp.key_material().context("no key material")?;
    let key_file = std::env::temp_dir().join(format!("{keypair_name}.pem"));
    std::fs::write(&key_file, key_material)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))?;
    }
    res.key_file = Some(key_file.clone());

    // 3. Create temp security group
    info!("[cluster-test:3/7] Creating temporary security group");
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

    let sg_name = format!("ami-forge-cluster-test-{}", std::process::id());
    let sg_resp = ec2
        .create_security_group()
        .group_name(&sg_name)
        .description("Temporary SG for AMI cluster integration test")
        .vpc_id(vpc_id)
        .tag_specifications(
            aws_sdk_ec2::types::TagSpecification::builder()
                .resource_type(aws_sdk_ec2::types::ResourceType::SecurityGroup)
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("ManagedBy")
                        .value("ami-forge")
                        .build(),
                )
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("Name")
                        .value("ami-forge-cluster-test")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .context("CreateSecurityGroup failed")?;
    let sg_id = sg_resp.group_id().context("no SG ID")?.to_string();
    res.sg_id = Some(sg_id.clone());

    // Allow all traffic within the SG (nodes need to talk to each other)
    ec2.authorize_security_group_ingress()
        .group_id(&sg_id)
        .ip_permissions(
            aws_sdk_ec2::types::IpPermission::builder()
                .ip_protocol("-1")
                .user_id_group_pairs(
                    aws_sdk_ec2::types::UserIdGroupPair::builder()
                        .group_id(&sg_id)
                        .build(),
                )
                .build(),
        )
        .send()
        .await?;

    // Allow SSH from anywhere (for our validation)
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
                        .build(),
                )
                .build(),
        )
        .send()
        .await?;

    // 4. Launch CP instance
    info!("[cluster-test:4/7] Launching control plane instance");
    let k3s_token = "ami-forge-cluster-test-token";
    let cp_userdata = generate_cp_userdata(
        &cp_keys.private_key,
        &worker_keys.public_key,
        &psk,
        k3s_token,
    );
    let cp_id =
        launch_instance(ec2, &args.ami_id, &cp_userdata, &keypair_name, &sg_id, &args.instance_type)
            .await?;
    res.instance_ids.push(cp_id.clone());

    // Wait for CP to get IPs
    let (cp_private_ip, cp_public_ip) = wait_for_ips(ec2, &cp_id, deadline).await?;
    info!("CP instance {cp_id}: private={cp_private_ip} public={cp_public_ip}");

    // 5. Launch worker instance (join_server = CP's private IP)
    info!("[cluster-test:5/7] Launching worker instance");
    let worker_userdata = generate_worker_userdata(
        &worker_keys.private_key,
        &cp_keys.public_key,
        &psk,
        k3s_token,
        &cp_private_ip,
    );
    let worker_id = launch_instance(
        ec2,
        &args.ami_id,
        &worker_userdata,
        &keypair_name,
        &sg_id,
        &args.instance_type,
    )
    .await?;
    res.instance_ids.push(worker_id.clone());

    let (worker_private_ip, _worker_public_ip) = wait_for_ips(ec2, &worker_id, deadline).await?;
    info!("Worker instance {worker_id}: private={worker_private_ip}");

    // 6. Wait for SSH on CP
    info!("[cluster-test:6/7] Waiting for SSH on control plane");
    wait_for_ssh(&cp_public_ip, &key_file, deadline).await?;

    // 7. Run validation checks via SSH
    info!("[cluster-test:7/7] Running cluster validation");
    let mut passed = 0;
    let mut total = 0;

    // Wait for kindling-init to complete on CP
    let init_ok = ssh_poll(
        &cp_public_ip,
        &key_file,
        "systemctl show kindling-init.service --property=ActiveState | grep -q active",
        deadline,
        Duration::from_secs(5),
    )
    .await;
    total += 1;
    if init_ok {
        passed += 1;
        info!("[PASS] cp-kindling-init: completed");
    } else {
        error!("[FAIL] cp-kindling-init: timed out");
        // Dump journal for debugging
        ssh_cmd(&cp_public_ip, &key_file, "journalctl -u kindling-init -n 30 --no-pager").await;
    }

    // Check WireGuard on CP
    total += 1;
    let wg_ok = ssh_check(
        &cp_public_ip,
        &key_file,
        "wg show all dump | grep -q wg-",
    )
    .await;
    if wg_ok {
        passed += 1;
        info!("[PASS] cp-wireguard: interface configured");
    } else {
        error!("[FAIL] cp-wireguard: no interface");
    }

    // Wait for K3s 2-node cluster (poll until 2 nodes Ready or timeout)
    total += 1;
    let k3s_ok = ssh_poll(
        &cp_public_ip,
        &key_file,
        "test $(kubectl get nodes --no-headers 2>/dev/null | grep -c Ready) -ge 2",
        deadline,
        Duration::from_secs(10),
    )
    .await;
    if k3s_ok {
        passed += 1;
        let node_info = ssh_output(
            &cp_public_ip,
            &key_file,
            "kubectl get nodes --no-headers",
        )
        .await;
        info!("[PASS] k3s-cluster: 2+ nodes Ready\n{node_info}");
    } else {
        error!("[FAIL] k3s-cluster: did not reach 2 nodes");
        let node_info = ssh_output(
            &cp_public_ip,
            &key_file,
            "kubectl get nodes --no-headers 2>&1; echo '---'; journalctl -u k3s -n 20 --no-pager",
        )
        .await;
        error!("K3s debug:\n{node_info}");
    }

    // Check VPN peering (handshake between CP and worker)
    total += 1;
    let peer_ok = ssh_check(
        &cp_public_ip,
        &key_file,
        "wg show all latest-handshakes | awk '{print $3}' | grep -v '^0$' | grep -q .",
    )
    .await;
    if peer_ok {
        passed += 1;
        info!("[PASS] vpn-peering: WireGuard handshake established");
    } else {
        error!("[FAIL] vpn-peering: no handshake");
    }

    // Check kubectl namespaces
    total += 1;
    let ns_ok = ssh_check(
        &cp_public_ip,
        &key_file,
        "test $(kubectl get namespaces --no-headers 2>/dev/null | wc -l) -ge 4",
    )
    .await;
    if ns_ok {
        passed += 1;
        info!("[PASS] kubectl-namespaces: 4+ namespaces");
    } else {
        error!("[FAIL] kubectl-namespaces: insufficient");
    }

    println!();
    if passed == total {
        info!("{passed}/{total} cluster integration checks passed");
        Ok(())
    } else {
        bail!("{}/{total} cluster integration checks failed", total - passed);
    }
}

fn generate_cp_userdata(
    cp_privkey: &str,
    worker_pubkey: &str,
    psk: &str,
    k3s_token: &str,
) -> String {
    serde_json::json!({
        "cluster_name": "cluster-test",
        "role": "server",
        "distribution": "k3s",
        "cluster_init": true,
        "node_index": 0,
        "skip_nix_rebuild": true,
        "vpn": {
            "require_liveness": false,
            "links": [{
                "name": "wg-test",
                "address": "10.99.0.1/24",
                "private_key_file": "/run/secrets.d/vpn-private-key",
                "listen_port": 51820,
                "profile": "k8s-control-plane",
                "peers": [{
                    "public_key": worker_pubkey,
                    "allowed_ips": ["10.99.0.0/24"],
                    "preshared_key_file": "/run/secrets.d/vpn-psk"
                }],
                "firewall": {
                    "trust_interface": false,
                    "allowed_tcp_ports": [6443, 10250],
                    "allowed_udp_ports": [51820],
                    "incoming_udp_port": 51820
                }
            }]
        },
        "bootstrap_secrets": {
            "vpn_private_key": cp_privkey,
            "vpn_psk": psk,
            "k3s_server_token": k3s_token
        }
    })
    .to_string()
}

fn generate_worker_userdata(
    worker_privkey: &str,
    cp_pubkey: &str,
    psk: &str,
    k3s_token: &str,
    cp_private_ip: &str,
) -> String {
    serde_json::json!({
        "cluster_name": "cluster-test",
        "role": "server",
        "distribution": "k3s",
        "cluster_init": false,
        "node_index": 1,
        "skip_nix_rebuild": true,
        "join_server": format!("https://{}:6443", cp_private_ip),
        "vpn": {
            "require_liveness": false,
            "links": [{
                "name": "wg-test",
                "address": "10.99.0.2/24",
                "private_key_file": "/run/secrets.d/vpn-private-key",
                "listen_port": 51820,
                "profile": "k8s-control-plane",
                "peers": [{
                    "public_key": cp_pubkey,
                    "allowed_ips": ["10.99.0.0/24"],
                    "preshared_key_file": "/run/secrets.d/vpn-psk",
                    "endpoint": format!("{}:51820", cp_private_ip)
                }],
                "firewall": {
                    "trust_interface": false,
                    "allowed_tcp_ports": [6443, 10250],
                    "allowed_udp_ports": [51820],
                    "incoming_udp_port": 51820
                }
            }]
        },
        "bootstrap_secrets": {
            "vpn_private_key": worker_privkey,
            "vpn_psk": psk,
            "k3s_server_token": k3s_token
        }
    })
    .to_string()
}

async fn launch_instance(
    ec2: &aws_sdk_ec2::Client,
    ami_id: &str,
    userdata: &str,
    keypair_name: &str,
    sg_id: &str,
    instance_type: &str,
) -> Result<String> {
    use base64::Engine;
    let userdata_b64 = base64::engine::general_purpose::STANDARD.encode(userdata);

    let it: aws_sdk_ec2::types::InstanceType = instance_type
        .parse()
        .unwrap_or(aws_sdk_ec2::types::InstanceType::T3Large);

    let resp = ec2
        .run_instances()
        .image_id(ami_id)
        .instance_type(it)
        .key_name(keypair_name)
        .security_group_ids(sg_id)
        .user_data(&userdata_b64)
        .min_count(1)
        .max_count(1)
        .tag_specifications(
            aws_sdk_ec2::types::TagSpecification::builder()
                .resource_type(aws_sdk_ec2::types::ResourceType::Instance)
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("ManagedBy")
                        .value("ami-forge")
                        .build(),
                )
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("Name")
                        .value("ami-forge-cluster-test")
                        .build(),
                )
                .build(),
        )
        .metadata_options(
            aws_sdk_ec2::types::InstanceMetadataOptionsRequest::builder()
                .http_tokens(aws_sdk_ec2::types::HttpTokensState::Required)
                .http_endpoint(aws_sdk_ec2::types::InstanceMetadataEndpointState::Enabled)
                .build(),
        )
        .send()
        .await
        .context("RunInstances failed")?;

    let id = resp
        .instances()
        .first()
        .and_then(|i| i.instance_id())
        .context("no instance ID")?
        .to_string();
    Ok(id)
}

async fn wait_for_ips(
    ec2: &aws_sdk_ec2::Client,
    instance_id: &str,
    deadline: Instant,
) -> Result<(String, String)> {
    loop {
        if Instant::now() >= deadline {
            bail!("Timed out waiting for IPs on {instance_id}");
        }
        let resp = ec2
            .describe_instances()
            .instance_ids(instance_id)
            .send()
            .await?;
        if let Some(inst) = resp
            .reservations()
            .first()
            .and_then(|r| r.instances().first())
        {
            if let (Some(priv_ip), Some(pub_ip)) =
                (inst.private_ip_address(), inst.public_ip_address())
            {
                return Ok((priv_ip.to_string(), pub_ip.to_string()));
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn wait_for_ssh(public_ip: &str, key_file: &PathBuf, deadline: Instant) -> Result<()> {
    loop {
        if Instant::now() >= deadline {
            bail!("Timed out waiting for SSH on {public_ip}");
        }
        let status = tokio::process::Command::new("ssh")
            .args(ssh_args(key_file, public_ip, "true"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;
        if let Ok(s) = status {
            if s.success() {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

fn ssh_args(key_file: &PathBuf, host: &str, cmd: &str) -> Vec<String> {
    vec![
        "-o".into(), "StrictHostKeyChecking=no".into(),
        "-o".into(), "UserKnownHostsFile=/dev/null".into(),
        "-o".into(), "ConnectTimeout=5".into(),
        "-o".into(), "LogLevel=ERROR".into(),
        "-i".into(), key_file.to_string_lossy().to_string(),
        format!("root@{host}"),
        cmd.to_string(),
    ]
}

// Workaround: ssh_args borrows, but we need owned strings for the format
async fn ssh_check(public_ip: &str, key_file: &PathBuf, cmd: &str) -> bool {
    let key_str = key_file.to_string_lossy().to_string();
    let host = format!("root@{public_ip}");
    tokio::process::Command::new("ssh")
        .args([
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-o", "LogLevel=ERROR",
            "-i", &key_str,
            &host,
            cmd,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn ssh_output(public_ip: &str, key_file: &PathBuf, cmd: &str) -> String {
    let key_str = key_file.to_string_lossy().to_string();
    let host = format!("root@{public_ip}");
    tokio::process::Command::new("ssh")
        .args([
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-o", "LogLevel=ERROR",
            "-i", &key_str,
            &host,
            cmd,
        ])
        .output()
        .await
        .map(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            format!("{stdout}{stderr}")
        })
        .unwrap_or_default()
}

async fn ssh_cmd(public_ip: &str, key_file: &PathBuf, cmd: &str) {
    let output = ssh_output(public_ip, key_file, cmd).await;
    if !output.is_empty() {
        info!("{output}");
    }
}

async fn ssh_poll(
    public_ip: &str,
    key_file: &PathBuf,
    cmd: &str,
    deadline: Instant,
    interval: Duration,
) -> bool {
    loop {
        if Instant::now() >= deadline {
            return false;
        }
        if ssh_check(public_ip, key_file, cmd).await {
            return true;
        }
        tokio::time::sleep(interval).await;
    }
}

async fn cleanup(ec2: &aws_sdk_ec2::Client, res: &TestResources) {
    info!("Cleaning up cluster test resources");

    // Terminate instances
    if !res.instance_ids.is_empty() {
        info!(
            "Terminating {} instance(s): {:?}",
            res.instance_ids.len(),
            res.instance_ids
        );
        let _ = ec2
            .terminate_instances()
            .set_instance_ids(Some(res.instance_ids.clone()))
            .send()
            .await;

        // Wait for termination before deleting SG (SG can't be deleted while in use)
        info!("Waiting for instances to terminate...");
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let resp = ec2
                .describe_instances()
                .set_instance_ids(Some(res.instance_ids.clone()))
                .send()
                .await;
            if let Ok(r) = resp {
                let all_terminated = r
                    .reservations()
                    .iter()
                    .flat_map(|r| r.instances())
                    .all(|i| {
                        i.state()
                            .and_then(|s| s.name())
                            .map(|n| n == &aws_sdk_ec2::types::InstanceStateName::Terminated)
                            .unwrap_or(false)
                    });
                if all_terminated {
                    break;
                }
            }
        }
    }

    // Delete security group
    if let Some(ref sg_id) = res.sg_id {
        info!("Deleting security group: {sg_id}");
        // Retry a few times — SG deletion can fail if instances are still terminating
        for attempt in 0..5 {
            match ec2
                .delete_security_group()
                .group_id(sg_id)
                .send()
                .await
            {
                Ok(_) => break,
                Err(e) => {
                    if attempt < 4 {
                        warn!("SG delete attempt {}: {e} — retrying", attempt + 1);
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    } else {
                        warn!("Failed to delete SG {sg_id}: {e}");
                    }
                }
            }
        }
    }

    // Delete keypair
    if let Some(ref kp) = res.keypair_name {
        info!("Deleting keypair: {kp}");
        let _ = ec2.delete_key_pair().key_name(kp).send().await;
    }

    // Delete temp key file
    if let Some(ref kf) = res.key_file {
        let _ = std::fs::remove_file(kf);
    }

    info!("Cleanup complete");
}
