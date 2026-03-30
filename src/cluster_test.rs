//! Multi-node cluster integration test.
//!
//! Launches N EC2 instances from a built AMI based on a YAML config file,
//! injects test userdata with cross-referenced WireGuard keys, validates
//! VPN peering, K3s cluster formation, and kubectl. Cleans up all resources
//! on success or failure.

use anyhow::{bail, Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

use crate::wg;

// ---------------------------------------------------------------------------
// P0.1 — Structured check result
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct CheckResult {
    name: String,
    passed: bool,
    message: String,
    duration_ms: u64,
    debug_output: Option<String>,
}

impl CheckResult {
    fn pass(name: &str, message: impl Into<String>, start: Instant) -> Self {
        Self {
            name: name.to_string(),
            passed: true,
            message: message.into(),
            duration_ms: start.elapsed().as_millis() as u64,
            debug_output: None,
        }
    }

    fn fail(name: &str, message: impl Into<String>, start: Instant, debug: Option<String>) -> Self {
        Self {
            name: name.to_string(),
            passed: false,
            message: message.into(),
            duration_ms: start.elapsed().as_millis() as u64,
            debug_output: debug,
        }
    }

    fn status_tag(&self) -> &str {
        if self.passed { "PASS" } else { "FAIL" }
    }
}

fn print_results_table(results: &[CheckResult]) {
    println!();
    info!("=== Cluster Test Results ===");
    for r in results {
        let suffix = if r.message.is_empty() {
            String::new()
        } else {
            format!(": {}", r.message)
        };
        info!(
            "[{}] {:<22} ({}ms){}",
            r.status_tag(),
            r.name,
            r.duration_ms,
            suffix,
        );
    }
    let passed = results.iter().filter(|r| r.passed).count();
    let total = results.len();
    info!("{passed}/{total} checks passed");

    // Dump debug output for failures
    for r in results.iter().filter(|r| !r.passed) {
        if let Some(ref dbg) = r.debug_output {
            error!("[{}] debug output:\n{dbg}", r.name);
        }
    }
}

// ---------------------------------------------------------------------------
// P0.3 — SSH session abstraction
// ---------------------------------------------------------------------------

struct SshSession {
    host: String,
    key_file: PathBuf,
}

impl SshSession {
    fn new(host: &str, key_file: &PathBuf) -> Self {
        Self {
            host: host.to_string(),
            key_file: key_file.clone(),
        }
    }

    fn ssh_args(&self, cmd: &str) -> Vec<String> {
        vec![
            "-o".into(), "StrictHostKeyChecking=no".into(),
            "-o".into(), "UserKnownHostsFile=/dev/null".into(),
            "-o".into(), "ConnectTimeout=10".into(),
            "-o".into(), "LogLevel=ERROR".into(),
            "-i".into(), self.key_file.to_string_lossy().to_string(),
            format!("root@{}", self.host),
            cmd.to_string(),
        ]
    }

    /// Run a command and return whether it exited successfully.
    async fn check(&self, cmd: &str) -> bool {
        tokio::process::Command::new("ssh")
            .args(self.ssh_args(cmd))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Run a command and return combined stdout+stderr.
    async fn output(&self, cmd: &str) -> String {
        tokio::process::Command::new("ssh")
            .args(self.ssh_args(cmd))
            .output()
            .await
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                let stderr = String::from_utf8_lossy(&o.stderr);
                format!("{stdout}{stderr}")
            })
            .unwrap_or_default()
    }

    /// Run a command, log its output.
    #[allow(dead_code)]
    async fn cmd(&self, cmd: &str) {
        let output = self.output(cmd).await;
        if !output.is_empty() {
            info!("{output}");
        }
    }

    /// Poll a command until it succeeds or the deadline expires.
    async fn poll(&self, cmd: &str, deadline: Instant, interval: Duration) -> bool {
        loop {
            if Instant::now() >= deadline {
                return false;
            }
            if self.check(cmd).await {
                return true;
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// Wait for SSH connectivity (short connect timeout).
    async fn wait_for_ssh(&self, deadline: Instant) -> Result<()> {
        let connect_args: Vec<String> = vec![
            "-o".into(), "StrictHostKeyChecking=no".into(),
            "-o".into(), "UserKnownHostsFile=/dev/null".into(),
            "-o".into(), "ConnectTimeout=5".into(),
            "-o".into(), "LogLevel=ERROR".into(),
            "-i".into(), self.key_file.to_string_lossy().to_string(),
            format!("root@{}", self.host),
            "true".into(),
        ];
        loop {
            if Instant::now() >= deadline {
                bail!("Timed out waiting for SSH on {}", self.host);
            }
            let status = tokio::process::Command::new("ssh")
                .args(&connect_args)
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
}

// ---------------------------------------------------------------------------
// Individual check functions (return CheckResult)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
async fn check_cp_kindling_init(cp: &SshSession, deadline: Instant) -> CheckResult {
    let start = Instant::now();
    let ok = cp.poll(
        "systemctl show kindling-init.service --property=ActiveState | grep -q active",
        deadline,
        Duration::from_secs(5),
    ).await;
    if ok {
        CheckResult::pass("cp-kindling-init", "completed", start)
    } else {
        let debug = cp.output("journalctl -u kindling-init -n 30 --no-pager").await;
        CheckResult::fail("cp-kindling-init", "timed out", start, Some(debug))
    }
}

async fn check_cp_wireguard(cp: &SshSession) -> CheckResult {
    let start = Instant::now();
    let ok = cp.check("wg show all dump | grep -q wg-").await;
    if ok {
        CheckResult::pass("cp-wireguard", "interface configured", start)
    } else {
        let debug = cp.output("wg show all 2>&1; ip link show 2>&1").await;
        CheckResult::fail("cp-wireguard", "no interface", start, Some(debug))
    }
}

async fn check_k3s_cluster(
    cp: &SshSession,
    min_ready: u32,
    agent_sessions: &[(&str, &SshSession)],
    deadline: Instant,
) -> CheckResult {
    let start = Instant::now();
    // Use the outer deadline but cap at 900s to avoid runaway waits
    let k3s_deadline = deadline.min(Instant::now() + Duration::from_secs(900));
    let k3s_check = format!(
        "test $(kubectl get nodes --no-headers 2>/dev/null | grep -c Ready) -ge {min_ready}"
    );
    let ok = cp.poll(&k3s_check, k3s_deadline, Duration::from_secs(10)).await;
    if ok {
        let node_info = cp.output("kubectl get nodes --no-headers").await;
        let ready_count = node_info.lines().filter(|l| l.contains("Ready")).count();
        CheckResult::pass("k3s-cluster", format!("{ready_count} nodes Ready"), start)
    } else {
        // Collect CP-side diagnostics
        let mut debug = cp.output(
            "kubectl get nodes --no-headers 2>&1; echo '---'; journalctl -u k3s -n 20 --no-pager",
        ).await;

        // Collect agent-side diagnostics from each non-CP node
        for (name, session) in agent_sessions {
            debug.push_str(&format!("\n\n=== Agent diagnostics: {} ===\n", name));
            debug.push_str("--- systemctl status k3s-agent ---\n");
            debug.push_str(&session.output("systemctl status k3s-agent.service 2>&1 || true").await);
            debug.push_str("\n--- journalctl -u k3s-agent (last 30 lines) ---\n");
            debug.push_str(&session.output("journalctl -u k3s-agent --no-pager -n 30 2>&1 || true").await);
            debug.push_str("\n--- /etc/rancher/k3s/config.yaml ---\n");
            debug.push_str(&session.output("cat /etc/rancher/k3s/config.yaml 2>&1 || echo 'FILE NOT FOUND'").await);
            debug.push_str("\n--- /var/lib/kindling/ sentinels ---\n");
            debug.push_str(&session.output("ls -la /var/lib/kindling/ 2>&1 || echo 'DIR NOT FOUND'").await);
            debug.push_str("\n--- kindling-init logs (last 15 lines) ---\n");
            debug.push_str(&session.output("journalctl -u kindling-init --no-pager -n 15 2>&1 || true").await);
            debug.push_str("\n--- WireGuard state ---\n");
            debug.push_str(&session.output("wg show all 2>&1 || echo 'NO WG'").await);
            debug.push_str("\n--- ip addr (VPN interfaces) ---\n");
            debug.push_str(&session.output("ip addr show 2>&1 | grep -A2 'wg-' || echo 'NO WG IFACE'").await);
            debug.push_str("\n--- connectivity to CP K3s API ---\n");
            debug.push_str(&session.output("timeout 3 bash -c 'echo | openssl s_client -connect $(grep server: /etc/rancher/k3s/config.yaml | head -1 | sed \"s|.*https://||\" | tr -d '\"') 2>&1 | head -5' || echo 'CONNECT FAILED'").await);
        }

        CheckResult::fail(
            "k3s-cluster",
            format!("did not reach {min_ready} Ready nodes"),
            start,
            Some(debug),
        )
    }
}

async fn check_vpn_peering(cp: &SshSession, min_hs: u32, deadline: Instant) -> CheckResult {
    let start = Instant::now();
    let ok = cp.poll(
        &format!(
            "test $(wg show all 2>/dev/null | grep -c 'latest handshake') -ge {min_hs}"
        ),
        deadline,
        Duration::from_secs(5),
    ).await;
    if ok {
        let wg_info = cp.output("wg show all").await;
        let hs_count = wg_info.lines().filter(|l| l.contains("latest handshake")).count();
        CheckResult::pass("vpn-peering", format!("{hs_count} handshakes"), start)
    } else {
        let debug = cp.output("wg show all 2>&1").await;
        CheckResult::fail(
            "vpn-peering",
            format!("insufficient handshakes (need {min_hs})"),
            start,
            Some(debug),
        )
    }
}

async fn check_kubectl_cp(cp: &SshSession) -> CheckResult {
    let start = Instant::now();
    let ok = cp.check(
        "test $(kubectl get namespaces --no-headers 2>/dev/null | wc -l) -ge 4",
    ).await;
    if ok {
        CheckResult::pass("kubectl-cp", "namespaces accessible from CP", start)
    } else {
        let debug = cp.output("kubectl get namespaces 2>&1").await;
        CheckResult::fail("kubectl-cp", "namespaces not accessible", start, Some(debug))
    }
}

async fn check_kubectl_client(
    cp: &SshSession,
    client: &SshSession,
    cp_vpn_ip: &str,
    deadline: Instant,
) -> CheckResult {
    let start = Instant::now();

    // Copy kubeconfig from CP to client, rewrite server URL to CP VPN IP
    let kubeconfig = cp.output("cat /etc/rancher/k3s/k3s.yaml 2>/dev/null").await;
    if kubeconfig.trim().is_empty() {
        return CheckResult::fail(
            "kubectl-client",
            "could not read kubeconfig from CP",
            start,
            None,
        );
    }

    let rewritten = kubeconfig.replace("127.0.0.1", cp_vpn_ip).replace("localhost", cp_vpn_ip);
    let tmp = std::env::temp_dir().join("cluster-test-kubeconfig");
    std::fs::write(&tmp, &rewritten).ok();
    let _ = client.check("mkdir -p /root/.kube").await;
    let scp_status = tokio::process::Command::new("scp")
        .args([
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-i", &client.key_file.to_string_lossy(),
            &tmp.to_string_lossy(),
            &format!("root@{}:/root/.kube/test-config", client.host),
        ])
        .status()
        .await;
    match scp_status {
        Ok(s) if s.success() => info!("Copied kubeconfig to client (server rewritten to {cp_vpn_ip})"),
        _ => warn!("Failed to scp kubeconfig to client"),
    }
    std::fs::remove_file(&tmp).ok();

    let ok = client.poll(
        "KUBECONFIG=/root/.kube/test-config kubectl get namespaces --no-headers 2>/dev/null | grep -q default",
        deadline,
        Duration::from_secs(10),
    ).await;
    if ok {
        CheckResult::pass("kubectl-client", "client->VPN->CP", start)
    } else {
        let debug = client.output(
            "KUBECONFIG=/root/.kube/test-config kubectl get namespaces 2>&1; echo '---'; wg show all 2>&1; echo '---'; cat /root/.kube/test-config 2>&1 | head -5",
        ).await;
        CheckResult::fail("kubectl-client", "client cannot reach CP K3s API via VPN", start, Some(debug))
    }
}

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
    /// IAM instance profile name for EC2 tag-based state reporting.
    /// Deployed via Pangea IaC. When set, instances can tag themselves
    /// with BootstrapPhase, enabling tag-based polling instead of SSH.
    #[serde(default)]
    pub instance_profile_name: Option<String>,
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
    profile_name: Option<String>,
    role_name: Option<String>,
}

impl TestResources {
    fn new() -> Self {
        Self {
            keypair_name: None,
            sg_id: None,
            instance_ids: Vec::new(),
            key_file: None,
            profile_name: None,
            role_name: None,
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
    let result = run_inner(&ec2, &aws_config, &args, &config, &mut resources).await;

    // Always cleanup, even on failure
    cleanup(&ec2, &aws_config, &resources).await;

    result
}

async fn run_inner(
    ec2: &aws_sdk_ec2::Client,
    aws_config: &aws_config::SdkConfig,
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

    // 3b. Resolve IAM instance profile — prefer pre-deployed (Pangea IaC),
    //     fall back to creating ephemeral IAM at runtime.
    let profile_name = if let Some(ref pre_deployed) = config.instance_profile_name {
        info!("Using pre-deployed IAM instance profile: {pre_deployed}");
        pre_deployed.clone()
    } else {
        info!("No instance_profile_name in config — creating ephemeral IAM");
        let iam = aws_sdk_iam::Client::new(aws_config);
        let role_name = format!("ami-forge-test-{}", test_id);
        let ephemeral_profile = role_name.clone();

        iam.create_role()
            .role_name(&role_name)
            .assume_role_policy_document(
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#,
            )
            .tags(
                aws_sdk_iam::types::Tag::builder()
                    .key("ManagedBy")
                    .value("ami-forge")
                    .build()
                    .context("failed to build IAM tag")?,
            )
            .send()
            .await
            .context("IAM CreateRole failed")?;
        res.role_name = Some(role_name.clone());

        iam.put_role_policy()
            .role_name(&role_name)
            .policy_name("tag-self")
            .policy_document(
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:CreateTags","Resource":"*","Condition":{"StringEquals":{"ec2:ResourceTag/ManagedBy":"ami-forge"}}}]}"#,
            )
            .send()
            .await
            .context("IAM PutRolePolicy failed")?;

        iam.create_instance_profile()
            .instance_profile_name(&ephemeral_profile)
            .send()
            .await
            .context("IAM CreateInstanceProfile failed")?;
        res.profile_name = Some(ephemeral_profile.clone());

        iam.add_role_to_instance_profile()
            .instance_profile_name(&ephemeral_profile)
            .role_name(&role_name)
            .send()
            .await
            .context("IAM AddRoleToInstanceProfile failed")?;

        // IAM is eventually consistent — wait for propagation
        info!("Waiting 10s for IAM propagation");
        tokio::time::sleep(Duration::from_secs(10)).await;

        ephemeral_profile
    };

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
        None, // No VPN IP needed for CP
    );

    let cp_node = &config.nodes[cp_index];
    let cp_id = launch_instance(
        ec2, &args.ami_id, &cp_userdata, &keypair_name, &sg_id,
        &config.instance_type, &test_id, &cp_node.name, &cp_node.role,
        Some(profile_name.as_str()),
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

    // CP VPN IP for join_server — agents join K3s through the VPN tunnel.
    let cp_vpn_full = config.nodes[cp_index].vpn_addr();
    let cp_vpn_ip = cp_vpn_full.split('/').next().unwrap_or("10.99.0.1");
    info!("  CP VPN IP for join_server: {cp_vpn_ip} (EC2 private: {cp_private_ip})");

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
            Some(cp_vpn_ip),
        );

        let id = launch_instance(
            ec2, &args.ami_id, &userdata, &keypair_name, &sg_id,
            &config.instance_type, &test_id, &node.name, &node.role,
            Some(profile_name.as_str()),
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
    let cp_ssh = SshSession::new(&cp_public_ip, &key_file);
    info!("[cluster-test:5/7] Waiting for SSH on control plane");
    cp_ssh.wait_for_ssh(deadline).await?;

    // If kubectl_from_client is enabled, also wait for SSH on the last node (client)
    let client_index = node_count - 1;
    let client_ssh = if config.checks.kubectl_from_client {
        let client_public_ip = &node_ips[client_index].1;
        let session = SshSession::new(client_public_ip, &key_file);
        info!("[cluster-test:6/7] Waiting for SSH on client node ({})", config.nodes[client_index].name);
        session.wait_for_ssh(deadline).await?;
        Some(session)
    } else {
        info!("[cluster-test:6/7] Skipping client SSH (kubectl_from_client: false)");
        None
    };

    // Create SSH sessions to all non-CP agent nodes for diagnostics.
    // These are used to capture k3s-agent logs if the cluster check fails.
    // We wait for SSH on each agent so diagnostic captures actually work.
    let mut agent_sessions: Vec<(String, SshSession)> = Vec::new();
    for (i, node) in config.nodes.iter().enumerate() {
        if i == cp_index {
            continue;
        }
        let pub_ip = &node_ips[i].1;
        if !pub_ip.is_empty() {
            let session = SshSession::new(pub_ip, &key_file);
            info!("Waiting for SSH on agent node {} ({pub_ip})", node.name);
            match session.wait_for_ssh(deadline).await {
                Ok(()) => {
                    agent_sessions.push((node.name.clone(), session));
                }
                Err(e) => {
                    warn!("SSH not available on agent {}: {e} -- diagnostics will be limited", node.name);
                }
            }
        }
    }

    // 7. Run validation checks
    info!("[cluster-test:7/7] Running cluster validation");
    let mut results: Vec<CheckResult> = Vec::new();

    // Check 1: Wait for ALL nodes to complete bootstrap via EC2 tags
    info!("Waiting for all nodes to complete bootstrap (via EC2 tags)...");
    let phase_start = Instant::now();
    match wait_for_phase_tags(ec2, &res.instance_ids, "complete", deadline).await {
        Ok(()) => {
            info!("[PASS] All nodes reached bootstrap phase 'complete'");
            results.push(CheckResult::pass(
                "bootstrap-phase-tags",
                format!("all {} nodes completed", res.instance_ids.len()),
                phase_start,
            ));
        }
        Err(e) => {
            error!("[FAIL] Tag-based bootstrap polling: {e}");
            results.push(CheckResult::fail(
                "bootstrap-phase-tags",
                format!("{e}"),
                phase_start,
                None,
            ));
        }
    }

    // Check 2: WireGuard on CP has peers
    results.push(check_cp_wireguard(&cp_ssh).await);

    // Check 3: K3s cluster (longest wait, gives VPN time to establish)
    let agent_refs: Vec<(&str, &SshSession)> = agent_sessions
        .iter()
        .map(|(name, session)| (name.as_str(), session))
        .collect();
    results.push(check_k3s_cluster(&cp_ssh, config.checks.min_ready_nodes, &agent_refs, deadline).await);

    // Check 4: VPN handshakes (runs AFTER K3s wait — keepalives established)
    results.push(check_vpn_peering(&cp_ssh, config.checks.min_vpn_handshakes, deadline).await);

    // Check 5: kubectl from CP
    results.push(check_kubectl_cp(&cp_ssh).await);

    // Check 6: kubectl from client node via VPN
    if let Some(ref client) = client_ssh {
        let cp_vpn_full = config.nodes[cp_index].vpn_addr();
        let cp_vpn_ip = cp_vpn_full.split('/').next().unwrap_or("10.99.0.1");
        results.push(check_kubectl_client(&cp_ssh, client, cp_vpn_ip, deadline).await);
    }

    // Print structured summary table
    print_results_table(&results);

    let passed = results.iter().filter(|r| r.passed).count();
    let total = results.len();
    if passed == total {
        info!("{passed}/{total} cluster integration checks passed — {node_count}-node cluster verified");
        Ok(())
    } else {
        bail!("{}/{total} cluster integration checks failed", total - passed);
    }
}

/// Poll EC2 tags until all instances have the expected `BootstrapPhase` tag.
///
/// Kindling-init writes `BootstrapPhase` tags on the instances as it progresses.
/// This function replaces SSH-based polling for init completion, which is fragile
/// and requires network access to each node.
async fn wait_for_phase_tags(
    ec2: &aws_sdk_ec2::Client,
    instance_ids: &[String],
    target_phase: &str,
    deadline: Instant,
) -> Result<()> {
    loop {
        if Instant::now() >= deadline {
            bail!("Timed out waiting for all nodes to reach phase '{target_phase}'");
        }

        let resp = ec2
            .describe_instances()
            .set_instance_ids(Some(instance_ids.to_vec()))
            .send()
            .await
            .context("DescribeInstances for tag polling failed")?;

        let mut ready_count = 0;
        for reservation in resp.reservations() {
            for instance in reservation.instances() {
                if let Some(phase) = instance
                    .tags()
                    .iter()
                    .find(|t| t.key() == Some("BootstrapPhase"))
                    .and_then(|t| t.value())
                {
                    if phase == target_phase {
                        ready_count += 1;
                    }
                }
            }
        }

        info!(
            "Phase poll: {ready_count}/{} nodes at '{target_phase}'",
            instance_ids.len()
        );

        if ready_count >= instance_ids.len() {
            return Ok(());
        }

        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

/// Build userdata JSON for a node from its config and runtime keypairs.
///
/// Each node gets a VPN config with the CP as hub. The CP listens (no endpoint),
/// all other nodes have the CP's private IP as endpoint with persistent_keepalive.
///
/// `cp_private_ip` -- the CP's EC2 private IP for WireGuard endpoint connectivity.
/// `cp_vpn_ip` -- the CP's VPN IP for K3s `join_server` URL. Agents join K3s via
/// the VPN tunnel so that the K3s server cert (which has VPN IPs as SANs) is valid.
fn build_userdata(
    node: &NodeConfig,
    config: &ClusterTestConfig,
    privkey: &str,
    all_keys: &[wg::KeyPair],
    psk: &str,
    cp_private_ip: Option<&str>,
    cp_vpn_ip: Option<&str>,
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

    // Non-CP nodes join the CP via its VPN address. Using VPN IP ensures the
    // K3s server TLS cert (which includes VPN addresses as SANs) is valid for
    // the connection. The WireGuard tunnel must be established first (the peer
    // endpoint uses cp_private_ip for layer-3 connectivity).
    if !node.cluster_init {
        if let Some(ip) = cp_vpn_ip {
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
    iam_profile_name: Option<&str>,
) -> Result<String> {
    use base64::Engine;
    let userdata_b64 = base64::engine::general_purpose::STANDARD.encode(userdata);

    let it: aws_sdk_ec2::types::InstanceType = instance_type
        .parse()
        .unwrap_or(aws_sdk_ec2::types::InstanceType::T3Large);

    // Safety: instance_initiated_shutdown_behavior = "terminate" ensures the
    // instance self-terminates on OS shutdown. Combined with TTL tags, orphaned
    // instances can be detected and reaped by a cleanup job.
    let ttl_expiry = (chrono::Utc::now() + chrono::Duration::hours(2))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let mut req = ec2
        .run_instances()
        .image_id(ami_id)
        .instance_type(it)
        .key_name(keypair_name)
        .user_data(&userdata_b64)
        .instance_initiated_shutdown_behavior(aws_sdk_ec2::types::ShutdownBehavior::Terminate);

    // Attach IAM instance profile if provided (Pangea IaC-deployed)
    if let Some(profile) = iam_profile_name {
        req = req.iam_instance_profile(
            aws_sdk_ec2::types::IamInstanceProfileSpecification::builder()
                .name(profile)
                .build(),
        );
    }

    let resp = req
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
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("ami-forge:ttl-hours")
                        .value("2")
                        .build(),
                )
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("ami-forge:expires-at")
                        .value(&ttl_expiry)
                        .build(),
                )
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("ami-forge:purpose")
                        .value("cluster-test")
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

async fn cleanup(ec2: &aws_sdk_ec2::Client, aws_config: &aws_config::SdkConfig, res: &TestResources) {
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

    // Delete IAM instance profile + role
    if let Some(ref profile) = res.profile_name {
        let iam = aws_sdk_iam::Client::new(aws_config);
        // Role name may differ from profile name in theory, but we use the same
        let role = res.role_name.as_deref().unwrap_or(profile);
        let _ = iam
            .remove_role_from_instance_profile()
            .instance_profile_name(profile)
            .role_name(role)
            .send()
            .await;
        let _ = iam
            .delete_instance_profile()
            .instance_profile_name(profile)
            .send()
            .await;
        let _ = iam
            .delete_role_policy()
            .role_name(role)
            .policy_name("tag-self")
            .send()
            .await;
        let _ = iam.delete_role().role_name(role).send().await;
        info!("Deleted IAM instance profile and role: {profile}");
    }

    // Delete temp key file
    if let Some(ref kf) = res.key_file {
        let _ = std::fs::remove_file(kf);
    }

    info!("Cleanup complete");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wg;

    /// Build a minimal `ClusterTestConfig` for unit tests.
    fn minimal_config(nodes: Vec<NodeConfig>) -> ClusterTestConfig {
        ClusterTestConfig {
            nodes,
            instance_type: "t3.xlarge".to_string(),
            timeout: 600,
            k3s_token: "test-token-00000000".to_string(),
            cluster_name: "unit-test".to_string(),
            checks: CheckConfig {
                min_ready_nodes: 1,
                min_vpn_handshakes: 0,
                kubectl_from_client: false,
            },
            region: "us-east-1".to_string(),
            instance_profile_name: None,
        }
    }

    fn cp_node() -> NodeConfig {
        NodeConfig {
            name: "cp".to_string(),
            role: "server".to_string(),
            cluster_init: true,
            vpn_address: Some("10.99.0.1/24".to_string()),
            node_index: 0,
        }
    }

    fn worker_node(index: u32) -> NodeConfig {
        NodeConfig {
            name: format!("worker{index}"),
            role: "agent".to_string(),
            cluster_init: false,
            vpn_address: Some(format!("10.99.0.{}/24", index + 1)),
            node_index: index,
        }
    }

    #[test]
    fn build_userdata_cp_has_cluster_init() {
        let nodes = vec![cp_node(), worker_node(1)];
        let config = minimal_config(nodes);
        let keys: Vec<_> = (0..2).map(|_| wg::generate_keypair()).collect();
        let psk = wg::generate_psk();

        let userdata = build_userdata(&config.nodes[0], &config, &keys[0].private_key, &keys, &psk, None, None);
        let parsed: serde_json::Value = serde_json::from_str(&userdata).unwrap();

        assert_eq!(parsed["cluster_init"], true);
        assert!(parsed["join_server"].is_null());
        assert_eq!(parsed["cluster_name"], "unit-test");
        assert_eq!(parsed["role"], "server");
    }

    #[test]
    fn build_userdata_worker_joins_via_vpn_ip() {
        let nodes = vec![cp_node(), worker_node(1)];
        let config = minimal_config(nodes);
        let keys: Vec<_> = (0..2).map(|_| wg::generate_keypair()).collect();
        let psk = wg::generate_psk();
        let cp_ec2_ip = "172.31.0.10";
        let cp_vpn_ip = "10.99.0.1";

        let userdata = build_userdata(&config.nodes[1], &config, &keys[1].private_key, &keys, &psk, Some(cp_ec2_ip), Some(cp_vpn_ip));
        let parsed: serde_json::Value = serde_json::from_str(&userdata).unwrap();

        assert_eq!(parsed["cluster_init"], false);
        // join_server uses VPN IP (not EC2 private IP) so K3s TLS cert SANs match
        assert_eq!(parsed["join_server"], format!("https://{cp_vpn_ip}:6443"));
        assert_eq!(parsed["role"], "agent");

        // WireGuard peer endpoint still uses EC2 private IP for layer-3 connectivity
        let peers = parsed["vpn"]["links"][0]["peers"].as_array().unwrap();
        let cp_peer = peers.iter().find(|p| p["endpoint"].is_string()).unwrap();
        assert_eq!(cp_peer["endpoint"], format!("{cp_ec2_ip}:51820"));
    }

    #[test]
    fn build_userdata_peer_list_excludes_self() {
        let nodes = vec![cp_node(), worker_node(1), worker_node(2)];
        let config = minimal_config(nodes);
        let keys: Vec<_> = (0..3).map(|_| wg::generate_keypair()).collect();
        let psk = wg::generate_psk();

        // Check each node's peer list does not include its own public key
        for (i, node) in config.nodes.iter().enumerate() {
            let cp_ip = if i == 0 { None } else { Some("172.31.0.10") };
            let cp_vpn = if i == 0 { None } else { Some("10.99.0.1") };
            let userdata = build_userdata(node, &config, &keys[i].private_key, &keys, &psk, cp_ip, cp_vpn);
            let parsed: serde_json::Value = serde_json::from_str(&userdata).unwrap();

            let peers = parsed["vpn"]["links"][0]["peers"].as_array().unwrap();
            let own_pubkey = &keys[i].public_key;
            for peer in peers {
                assert_ne!(
                    peer["public_key"].as_str().unwrap(),
                    own_pubkey,
                    "node {} should not have its own public key in peer list",
                    node.name
                );
            }
            // Peer count should be total nodes minus self
            assert_eq!(peers.len(), config.nodes.len() - 1);
        }
    }

    #[test]
    fn build_userdata_vpn_address_derived_from_index() {
        // When vpn_address is None, vpn_addr() derives from node_index
        let node = NodeConfig {
            name: "auto".to_string(),
            role: "agent".to_string(),
            cluster_init: false,
            vpn_address: None,
            node_index: 5,
        };
        assert_eq!(node.vpn_addr(), "10.99.0.6/24");

        // When vpn_address is Some, it uses the explicit value
        let node_explicit = NodeConfig {
            name: "explicit".to_string(),
            role: "server".to_string(),
            cluster_init: true,
            vpn_address: Some("10.88.0.1/24".to_string()),
            node_index: 0,
        };
        assert_eq!(node_explicit.vpn_addr(), "10.88.0.1/24");
    }
}
