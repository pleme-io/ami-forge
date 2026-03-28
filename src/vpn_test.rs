//! EC2 VPN integration test: launch two instances from an AMI and verify
//! `WireGuard` tunnel connectivity between them.
//!
//! Uses the [`ec2_harness`] for instance lifecycle (EC2 key pair for SSH)
//! and [`ssh`] for remote command execution. The test-specific logic is
//! `WireGuard` config generation and tunnel verification.

use std::time::{Duration, Instant};

use anyhow::Context;
use clap::Args;
use tracing::info;

use crate::{aws, ec2_harness, ssh, wg};

/// Tunnel IP addresses for the test.
const SERVER_TUNNEL_IP: &str = "10.99.0.1";
const CLIENT_TUNNEL_IP: &str = "10.99.0.2";
const SERVER_TUNNEL_ADDR: &str = "10.99.0.1/24";
const CLIENT_TUNNEL_ADDR: &str = "10.99.0.2/24";
const WG_PORT: u16 = 51899;
const WG_INTERFACE: &str = "wg-test";
const WG_CONFIG_PATH: &str = "/run/wireguard/wg-test.conf";

#[derive(Args)]
pub struct VpnTestArgs {
    /// AMI ID to test (launch instances from this AMI)
    #[arg(long)]
    pub ami_id: String,

    /// AWS region
    #[arg(long, default_value = "us-east-1")]
    pub region: String,

    /// Subnet ID (uses default VPC if omitted)
    #[arg(long)]
    pub subnet_id: Option<String>,

    /// Instance type for test instances
    #[arg(long, default_value = "t3.medium")]
    pub instance_type: String,

    /// Maximum test duration in seconds
    #[arg(long, default_value_t = 300)]
    pub timeout: u64,

    /// SSH username on the AMI
    #[arg(long, default_value = "root")]
    pub ssh_user: String,
}

/// Timing metrics collected during the test.
#[allow(clippy::struct_field_names)]
struct TestMetrics {
    launch_time: Duration,
    ssh_ready_time: Duration,
    tunnel_up_time: Duration,
    ping_success_time: Duration,
    total_time: Duration,
}

impl std::fmt::Display for TestMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "launch={:.1}s ssh={:.1}s tunnel={:.1}s ping={:.1}s total={:.1}s",
            self.launch_time.as_secs_f64(),
            self.ssh_ready_time.as_secs_f64(),
            self.tunnel_up_time.as_secs_f64(),
            self.ping_success_time.as_secs_f64(),
            self.total_time.as_secs_f64(),
        )
    }
}

/// Run the VPN connectivity test.
pub async fn run(args: VpnTestArgs) -> anyhow::Result<()> {
    let start = Instant::now();
    let max_duration = Duration::from_secs(args.timeout);

    info!(ami = %args.ami_id, "Starting VPN connectivity test");

    let config = aws::load_config(&args.region).await;
    let ec2 = aws_sdk_ec2::Client::new(&config);

    // Generate ephemeral WireGuard keys
    let server_kp = wg::generate_keypair();
    let client_kp = wg::generate_keypair();
    let psk = wg::generate_psk();
    info!("Generated ephemeral WireGuard keys");

    let harness_config = ec2_harness::HarnessConfig {
        ami_id: args.ami_id.clone(),
        instance_type: args.instance_type.clone(),
        instance_count: 2,
        subnet_id: args.subnet_id.clone(),
        max_wait: max_duration,
    };

    let env = ec2_harness::create(&ec2, &harness_config).await?;
    let launch_time = start.elapsed();
    info!(secs = launch_time.as_secs(), "test environment ready");

    let result = run_vpn_test(
        &env, &args.ssh_user,
        &server_kp, &client_kp, &psk,
        start, launch_time, max_duration,
    ).await;

    env.cleanup().await;
    result
}

#[allow(clippy::too_many_arguments)]
async fn run_vpn_test(
    env: &ec2_harness::TestEnv,
    ssh_user: &str,
    server_kp: &wg::KeyPair,
    client_kp: &wg::KeyPair,
    psk: &str,
    start: Instant,
    launch_time: Duration,
    max_duration: Duration,
) -> anyhow::Result<()> {
    let server = &env.instances[0];
    let client = &env.instances[1];

    // SSH readiness (using EC2 key pair)
    let ssh_start = Instant::now();
    let remaining = max_duration.saturating_sub(start.elapsed());
    let server_session = env.ssh_to(0, ssh_user, remaining).await
        .context("SSH to server instance failed")?;

    let remaining = max_duration.saturating_sub(start.elapsed());
    let client_session = env.ssh_to(1, ssh_user, remaining).await
        .context("SSH to client instance failed")?;

    let ssh_ready_time = ssh_start.elapsed();
    info!(secs = ssh_ready_time.as_secs(), "SSH ready on both instances");

    // Configure WireGuard server
    let tunnel_start = Instant::now();
    let server_config = wg::server_config(
        &server_kp.private_key, SERVER_TUNNEL_ADDR, WG_PORT,
        &client_kp.public_key, &format!("{CLIENT_TUNNEL_IP}/32"), psk,
    );
    ssh::write_file(&server_session, WG_CONFIG_PATH, &server_config).await?;
    ssh::run_cmd(&server_session, &format!("wg-quick up {WG_CONFIG_PATH}")).await?;
    info!("WireGuard server configured and up");

    // Configure WireGuard client
    let client_config = wg::client_config(
        &client_kp.private_key, CLIENT_TUNNEL_ADDR, &server_kp.public_key,
        &format!("{}:{WG_PORT}", server.private_ip),
        &format!("{SERVER_TUNNEL_IP}/32"), psk, 5,
    );
    ssh::write_file(&client_session, WG_CONFIG_PATH, &client_config).await?;
    ssh::run_cmd(&client_session, &format!("wg-quick up {WG_CONFIG_PATH}")).await?;
    let tunnel_up_time = tunnel_start.elapsed();
    info!(secs = tunnel_up_time.as_secs(), "WireGuard client configured and up");

    // Verify tunnel
    let ping_start = Instant::now();

    let wg_show = ssh::run_cmd(&client_session, &format!("wg show {WG_INTERFACE}")).await?;
    info!(output = %wg_show.trim(), "client wg show");
    let wg_show = ssh::run_cmd(&server_session, &format!("wg show {WG_INTERFACE}")).await?;
    info!(output = %wg_show.trim(), "server wg show");

    // Bidirectional ping
    ssh::run_cmd(&client_session, &format!("ping -c 3 -W 5 {SERVER_TUNNEL_IP}")).await
        .context("client -> server tunnel ping failed")?;
    info!("client ({}) -> server tunnel ping: OK", client.private_ip);

    ssh::run_cmd(&server_session, &format!("ping -c 3 -W 5 {CLIENT_TUNNEL_IP}")).await
        .context("server -> client tunnel ping failed")?;
    info!("server ({}) -> client tunnel ping: OK", server.private_ip);

    let ping_success_time = ping_start.elapsed();
    let metrics = TestMetrics {
        launch_time, ssh_ready_time, tunnel_up_time, ping_success_time,
        total_time: start.elapsed(),
    };
    info!("VPN test PASSED: {metrics}");

    server_session.close().await.ok();
    client_session.close().await.ok();
    Ok(())
}
