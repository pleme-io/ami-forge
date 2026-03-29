//! Multi-node cluster integration test.
//!
//! Launches N EC2 instances from a built AMI based on a YAML config file,
//! injects test userdata with cross-referenced WireGuard keys, validates
//! VPN peering, K3s cluster formation, and kubectl. Cleans up all resources
//! on success or failure.

use anyhow::{bail, Context, Result};
use clap::Args;
use serde::Deserialize;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

use crate::wg;

#[derive(Args)]
pub struct ClusterTestArgs {
    /// Path to cluster test configuration YAML
    #[arg(long)]
    pub config: PathBuf,

    /// AMI ID to test
    #[arg(long)]
    pub ami_id: String,
}

#[derive(Deserialize)]
pub struct ClusterTestConfig {
    pub nodes: Vec<NodeConfig>,
    pub instance_type: String,
    pub timeout: u64,
    pub k3s_token: String,
    pub cluster_name: String,
    pub checks: CheckConfig,
    #[serde(default = "default_region")]
    pub region: String,
}

fn default_region() -> String {
    "us-east-1".into()
}

#[derive(Deserialize)]
pub struct NodeConfig {
    pub name: String,
    pub role: String,
    #[serde(default)]
    pub cluster_init: bool,
    #[serde(default)]
    pub vpn_address: Option<String>,
    pub node_index: u32,
}

impl NodeConfig {
    pub fn vpn_addr(&self) -> String {
        self.vpn_address
            .clone()
            .unwrap_or_else(|| format!("10.99.0.{}/24", self.node_index + 1))
    }
}

#[derive(Deserialize)]
pub struct CheckConfig {
    pub min_ready_nodes: u32,
    pub min_vpn_handshakes: u32,
    #[serde(default)]
    pub kubectl_from_client: bool,
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
    let config_content = std::fs::read_to_string(&args.config)
        .with_context(|| format!("failed to read cluster test config: {}", args.config.display()))?;
    let config: ClusterTestConfig = serde_yaml::from_str(&config_content)
        .context("failed to parse cluster test config YAML")?;

    if config.nodes.is_empty() {
        bail!("cluster test config has no nodes defined");
    }

    let aws_config = crate::aws::load_config(&config.region).await;
    let ec2 = aws_sdk_ec2::Client::new(&aws_config);

    let mut resources = TestResources::new();
    let result = run_inner(&ec2, &args, &config, &mut resources).await;

    // Always cleanup, even on failure
    cleanup(&ec2, &resources).await;

    result
}

async fn run_inner(
    ec2: &aws_sdk_ec2::Client,
    args: &ClusterTestArgs,
    config: &ClusterTestConfig,
    res: &mut TestResources,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(config.timeout);
    let node_count = config.nodes.len();
    let test_id = format!(
        "cluster-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    );

    // 1. Generate WireGuard keypairs for all nodes
    info!("[cluster-test:1/7] Generating WireGuard keypairs for {node_count} nodes");
    let keys: Vec<_> = (0..node_count).map(|_| wg::generate_keypair()).collect();
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
        .await
        .context("authorize_security_group_ingress (self) failed")?;

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
        .await
        .context("authorize_security_group_ingress (ssh) failed")?;

    // 4. Launch CP instance first (others need its IP)
    let role_summary: Vec<_> = config.nodes.iter().map(|n| format!("{} ({})", n.name, n.role)).collect();
    info!("[cluster-test:4/7] Launching {node_count}-node cluster: {}", role_summary.join(", "));

    // Find the CP node (cluster_init == true)
    let cp_index = config
        .nodes
        .iter()
        .position(|n| n.cluster_init)
        .context("no node with cluster_init: true in config")?;

    let cp_userdata = build_userdata(
        &config.nodes[cp_index],
        config,
        &keys[cp_index].private_key,
        &keys,
        &psk,
        None, // No CP IP yet (it IS the CP)
    );

    let cp_node = &config.nodes[cp_index];
    let cp_id = launch_instance(
        ec2, &args.ami_id, &cp_userdata, &keypair_name, &sg_id,
        &config.instance_type, &test_id, &cp_node.name, &cp_node.role,
    ).await?;
    res.instance_ids.push(cp_id.clone());

    let (cp_private_ip, cp_public_ip) = wait_for_ips(ec2, &cp_id, deadline).await?;
    info!("  {}: {cp_id} private={cp_private_ip} public={cp_public_ip}", config.nodes[cp_index].name);

    // Launch remaining nodes
    let mut node_ips: Vec<(String, String)> = Vec::new();
    // Pre-fill with empty entries so indexes align with config.nodes
    for _ in 0..node_count {
        node_ips.push((String::new(), String::new()));
    }
    node_ips[cp_index] = (cp_private_ip.clone(), cp_public_ip.clone());

    // Launch all non-CP instances (fire launches quickly, collect IDs)
    let mut pending: Vec<(usize, String, String)> = Vec::new(); // (config_index, node_name, instance_id)

    for (i, node) in config.nodes.iter().enumerate() {
        if i == cp_index {
            continue;
        }

        let userdata = build_userdata(
            node,
            config,
            &keys[i].private_key,
            &keys,
            &psk,
            Some(&cp_private_ip),
        );

        let id = launch_instance(
            ec2, &args.ami_id, &userdata, &keypair_name, &sg_id,
            &config.instance_type, &test_id, &node.name, &node.role,
        ).await?;
        res.instance_ids.push(id.clone());
        pending.push((i, node.name.clone(), id));
    }

    // Now wait for all IPs (instances are already booting in parallel)
    for (i, name, id) in &pending {
        let (priv_ip, pub_ip) = wait_for_ips(ec2, id, deadline).await?;
        info!("  {name}: {id} private={priv_ip}");
        node_ips[*i] = (priv_ip, pub_ip);
    }

    // 5. Wait for SSH on CP
    info!("[cluster-test:5/7] Waiting for SSH on control plane");
    wait_for_ssh(&cp_public_ip, &key_file, deadline).await?;

    // If kubectl_from_client is enabled, also wait for SSH on the last node (client)
    let client_index = node_count - 1;
    if config.checks.kubectl_from_client {
        let client_public_ip = &node_ips[client_index].1;
        info!("[cluster-test:6/7] Waiting for SSH on client node ({})", config.nodes[client_index].name);
        wait_for_ssh(client_public_ip, &key_file, deadline).await?;
    } else {
        info!("[cluster-test:6/7] Skipping client SSH (kubectl_from_client: false)");
    }

    // 7. Run validation checks
    info!("[cluster-test:7/7] Running cluster validation");
    let mut passed = 0;
    let mut total = 0;

    // Check 1: kindling-init completed on CP
    total += 1;
    let init_ok = ssh_poll(
        &cp_public_ip,
        &key_file,
        "systemctl show kindling-init.service --property=ActiveState | grep -q active",
        deadline,
        Duration::from_secs(5),
    ).await;
    if init_ok {
        passed += 1;
        info!("[PASS] cp-kindling-init: completed");
    } else {
        error!("[FAIL] cp-kindling-init: timed out");
        ssh_cmd(&cp_public_ip, &key_file, "journalctl -u kindling-init -n 30 --no-pager").await;
    }

    // Check 2: WireGuard on CP has peers
    total += 1;
    let wg_ok = ssh_check(&cp_public_ip, &key_file, "wg show all dump | grep -q wg-").await;
    if wg_ok {
        passed += 1;
        info!("[PASS] cp-wireguard: interface configured");
    } else {
        error!("[FAIL] cp-wireguard: no interface");
    }

    // Check 3: K3s cluster (FIRST — longest wait, gives VPN time to establish)
    total += 1;
    let min_ready = config.checks.min_ready_nodes;
    let k3s_check = format!(
        "test $(kubectl get nodes --no-headers 2>/dev/null | grep -c Ready) -ge {min_ready}"
    );
    let k3s_ok = ssh_poll(&cp_public_ip, &key_file, &k3s_check, deadline, Duration::from_secs(10)).await;
    if k3s_ok {
        passed += 1;
        let node_info = ssh_output(&cp_public_ip, &key_file, "kubectl get nodes --no-headers").await;
        info!("[PASS] k3s-cluster: {min_ready}+ nodes Ready\n{node_info}");
    } else {
        error!("[FAIL] k3s-cluster: did not reach {min_ready} Ready nodes");
        let node_info = ssh_output(
            &cp_public_ip,
            &key_file,
            "kubectl get nodes --no-headers 2>&1; echo '---'; journalctl -u k3s -n 20 --no-pager",
        ).await;
        error!("K3s debug:\n{node_info}");
    }

    // Check 4: VPN handshakes (runs AFTER K3s wait — by now keepalives are established)
    // Use `wg show all dump` which is machine-readable (tab-separated), and count
    // peers with non-zero latest-handshake (field 6 in peer lines).
    total += 1;
    let min_hs = config.checks.min_vpn_handshakes;
    // Count peers with "latest handshake" in human-readable wg show output.
    // This is the most reliable check — if "latest handshake" appears, the peer has connected.
    let vpn_ok = ssh_poll(
        &cp_public_ip,
        &key_file,
        &format!(
            "test $(wg show all 2>/dev/null | grep -c 'latest handshake') -ge {min_hs}"
        ),
        deadline,
        Duration::from_secs(5),
    ).await;
    if vpn_ok {
        passed += 1;
        let wg_info = ssh_output(&cp_public_ip, &key_file, "wg show all").await;
        info!("[PASS] vpn-peering: {min_hs}+ WireGuard handshakes\n{wg_info}");
    } else {
        error!("[FAIL] vpn-peering: insufficient WireGuard handshakes (need {min_hs})");
        let wg_info = ssh_output(&cp_public_ip, &key_file, "wg show all 2>&1").await;
        error!("WireGuard debug:\n{wg_info}");
    }

    // Check 5: kubectl from CP
    total += 1;
    let ns_ok = ssh_check(
        &cp_public_ip,
        &key_file,
        "test $(kubectl get namespaces --no-headers 2>/dev/null | wc -l) -ge 4",
    ).await;
    if ns_ok {
        passed += 1;
        info!("[PASS] kubectl-cp: namespaces accessible from CP");
    } else {
        error!("[FAIL] kubectl-cp: namespaces not accessible");
    }

    // Check 6: kubectl from client node via VPN
    // Copy kubeconfig from CP, rewrite server URL to CP's VPN IP, then run kubectl
    if config.checks.kubectl_from_client {
        total += 1;
        let client_public_ip = &node_ips[client_index].1;
        let cp_vpn_full = config.nodes[cp_index].vpn_addr();
        let cp_vpn_ip = cp_vpn_full.split('/').next().unwrap_or("10.99.0.1");

        // Copy kubeconfig from CP to client:
        // 1. Read kubeconfig from CP via SSH (to our machine)
        // 2. Rewrite server URL
        // 3. Write to client via SSH
        let kubeconfig = ssh_output(&cp_public_ip, &key_file, "cat /etc/rancher/k3s/k3s.yaml").await;
        if !kubeconfig.trim().is_empty() {
            let rewritten = kubeconfig.replace("127.0.0.1", cp_vpn_ip).replace("localhost", cp_vpn_ip);
            // Base64 encode to avoid shell escaping issues
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(rewritten.as_bytes());
            let _ = ssh_check(client_public_ip, &key_file, "mkdir -p /root/.kube").await;
            let _ = ssh_check(
                client_public_ip,
                &key_file,
                &format!("echo '{b64}' | base64 -d > /root/.kube/config"),
            ).await;
            info!("Copied kubeconfig to client (server rewritten to {cp_vpn_ip})");
        } else {
            warn!("Could not read kubeconfig from CP");
        }

        let client_kubectl_ok = ssh_poll(
            client_public_ip,
            &key_file,
            "kubectl get namespaces --no-headers 2>/dev/null | grep -q default",
            deadline,
            Duration::from_secs(10),
        ).await;
        if client_kubectl_ok {
            passed += 1;
            info!("[PASS] kubectl-client: client→VPN→CP K3s API works");
        } else {
            error!("[FAIL] kubectl-client: client cannot reach CP K3s API via VPN");
            let client_debug = ssh_output(
                client_public_ip,
                &key_file,
                "kubectl get namespaces 2>&1; echo '---'; wg show all 2>&1",
            ).await;
            error!("Client debug:\n{client_debug}");
        }
    }

    println!();
    if passed == total {
        info!("{passed}/{total} cluster integration checks passed — {node_count}-node cluster verified");
        Ok(())
    } else {
        bail!("{}/{total} cluster integration checks failed", total - passed);
    }
}

/// Build userdata JSON for a node from its config and runtime keypairs.
///
/// Each node gets a VPN config with the CP as hub. The CP listens (no endpoint),
/// all other nodes have the CP's private IP as endpoint with persistent_keepalive.
fn build_userdata(
    node: &NodeConfig,
    config: &ClusterTestConfig,
    privkey: &str,
    all_keys: &[wg::KeyPair],
    psk: &str,
    cp_private_ip: Option<&str>,
) -> String {
    // Build peer list: this node peers with all OTHER nodes
    let peers: Vec<serde_json::Value> = config.nodes.iter()
        .enumerate()
        .filter(|(i, _)| *i != node.node_index as usize)
        .map(|(i, other)| {
            // Each peer gets its specific VPN IP as allowed_ips (not the whole subnet).
            // WireGuard only allows one peer per allowed_ips range.
            let peer_ip_full = other.vpn_addr();
            let peer_ip = peer_ip_full.split('/').next().unwrap_or("10.99.0.0");
            let mut peer = serde_json::json!({
                "public_key": all_keys[i].public_key,
                "allowed_ips": [format!("{peer_ip}/32")],
                "preshared_key_file": "/run/secrets.d/vpn-psk",
                "persistent_keepalive": 25
            });
            // Non-CP nodes have CP's endpoint; CP has no endpoint (responds to incoming)
            if !node.cluster_init && other.cluster_init {
                if let Some(ip) = cp_private_ip {
                    peer["endpoint"] = serde_json::json!(format!("{ip}:51820"));
                }
            }
            peer
        })
        .collect();

    let mut data = serde_json::json!({
        "cluster_name": config.cluster_name,
        "role": node.role,
        "distribution": "k3s",
        "cluster_init": node.cluster_init,
        "node_index": node.node_index,
        "skip_nix_rebuild": true,
        "vpn": {
            "require_liveness": false,
            "links": [{
                "name": "wg-test",
                "address": node.vpn_addr(),
                "private_key_file": "/run/secrets.d/vpn-private-key",
                "listen_port": 51820,
                "persistent_keepalive": 25,
                "profile": "k8s-control-plane",
                "peers": peers,
                "firewall": {
                    "trust_interface": false,
                    "allowed_tcp_ports": [6443, 10250],
                    "allowed_udp_ports": [51820],
                    "incoming_udp_port": 51820
                }
            }]
        },
        "bootstrap_secrets": {
            "vpn_private_key": privkey,
            "vpn_psk": psk,
            "k3s_server_token": config.k3s_token
        }
    });

    // Non-CP nodes join the CP
    if !node.cluster_init {
        if let Some(ip) = cp_private_ip {
            data["join_server"] = serde_json::json!(format!("https://{ip}:6443"));
        }
    }

    data.to_string()
}

async fn launch_instance(
    ec2: &aws_sdk_ec2::Client,
    ami_id: &str,
    userdata: &str,
    keypair_name: &str,
    sg_id: &str,
    instance_type: &str,
    test_id: &str,
    node_name: &str,
    node_role: &str,
) -> Result<String> {
    use base64::Engine;
    let userdata_b64 = base64::engine::general_purpose::STANDARD.encode(userdata);

    let it: aws_sdk_ec2::types::InstanceType = instance_type
        .parse()
        .unwrap_or(aws_sdk_ec2::types::InstanceType::T3Large);

    // Use network_interfaces to ensure public IP assignment.
    // When specifying network_interfaces, security groups go in the
    // interface (not at the top level).
    let resp = ec2
        .run_instances()
        .image_id(ami_id)
        .instance_type(it)
        .key_name(keypair_name)
        .user_data(&userdata_b64)
        .min_count(1)
        .max_count(1)
        .network_interfaces(
            aws_sdk_ec2::types::InstanceNetworkInterfaceSpecification::builder()
                .device_index(0)
                .associate_public_ip_address(true)
                .groups(sg_id)
                .build(),
        )
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
                        .value(format!("ami-forge-{node_name}"))
                        .build(),
                )
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("ClusterTestId")
                        .value(test_id)
                        .build(),
                )
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("NodeRole")
                        .value(node_role)
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
        .with_context(|| format!("RunInstances failed for ami={ami_id} type={instance_type}"))?;

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
    // EC2 eventual consistency: instance may not be visible for 2-5s after launch
    tokio::time::sleep(Duration::from_secs(2)).await;

    loop {
        if Instant::now() >= deadline {
            bail!("Timed out waiting for IPs on {instance_id}");
        }
        let resp = ec2
            .describe_instances()
            .instance_ids(instance_id)
            .send()
            .await;

        match resp {
            Ok(r) => {
                if let Some(inst) = r.reservations().first().and_then(|r| r.instances().first()) {
                    if let (Some(priv_ip), Some(pub_ip)) =
                        (inst.private_ip_address(), inst.public_ip_address())
                    {
                        return Ok((priv_ip.to_string(), pub_ip.to_string()));
                    }
                }
            }
            Err(e) => {
                let err_str = format!("{e}");
                if err_str.contains("InvalidInstanceID") || err_str.contains("does not exist") {
                    info!("Instance {instance_id} not yet visible (eventual consistency), retrying...");
                } else {
                    return Err(anyhow::anyhow!("describe_instances for {instance_id}: {e:#}"));
                }
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
