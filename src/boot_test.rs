//! EC2 boot test: launch one instance from an AMI and verify it boots
//! correctly with all expected binaries and services.
//!
//! Uses the [`ec2_harness`] for instance lifecycle and [`ssh`] for remote
//! command execution. Measures boot timing metrics.

use std::time::{Duration, Instant};

use anyhow::Context;
use clap::Args;
use tracing::info;

use crate::{aws, ec2_harness, ssh};

/// Default checks to run on a booted instance.
const DEFAULT_CHECKS: &[(&str, &str)] = &[
    ("kindling binary", "kindling --version"),
    ("k3s binary", "k3s --version"),
    ("wireguard tools", "wg --version"),
    ("systemd running", "systemctl is-system-running --wait || true"),
];

#[derive(Args)]
pub struct BootTestArgs {
    /// AMI ID to test
    #[arg(long)]
    pub ami_id: String,

    /// AWS region
    #[arg(long, default_value = "us-east-1")]
    pub region: String,

    /// Subnet ID (uses default VPC if omitted)
    #[arg(long)]
    pub subnet_id: Option<String>,

    /// Instance type
    #[arg(long, default_value = "t3.medium")]
    pub instance_type: String,

    /// Maximum test duration in seconds
    #[arg(long, default_value_t = 300)]
    pub timeout: u64,

    /// SSH username on the AMI
    #[arg(long, default_value = "root")]
    pub ssh_user: String,

    /// Additional commands to check (repeatable). Each is run via SSH and must exit 0.
    #[arg(long = "check", value_name = "CMD")]
    pub extra_checks: Vec<String>,
}

/// Run the boot test.
pub async fn run(args: BootTestArgs) -> anyhow::Result<()> {
    let start = Instant::now();
    let max_duration = Duration::from_secs(args.timeout);

    info!(ami = %args.ami_id, "Starting boot test");

    let config = aws::load_config(&args.region).await;
    let ec2 = aws_sdk_ec2::Client::new(&config);
    let ec2ic = aws_sdk_ec2instanceconnect::Client::new(&config);
    let ssh_key = ssh::EphemeralSshKey::generate()?;

    // Stand up one instance
    let harness_config = ec2_harness::HarnessConfig {
        ami_id: args.ami_id.clone(),
        instance_type: args.instance_type.clone(),
        instance_count: 1,
        subnet_id: args.subnet_id.clone(),
        max_wait: max_duration,
    };

    let env = ec2_harness::create(&ec2, &harness_config).await?;
    let launch_time = start.elapsed();
    info!(secs = launch_time.as_secs(), "instance running");

    // Run checks, ensuring cleanup
    let result = run_checks(&env, &ec2ic, &ssh_key, &args, start, launch_time, max_duration).await;
    env.cleanup().await;
    result
}

async fn run_checks(
    env: &ec2_harness::TestEnv,
    ec2ic: &aws_sdk_ec2instanceconnect::Client,
    ssh_key: &ssh::EphemeralSshKey,
    args: &BootTestArgs,
    start: Instant,
    launch_time: Duration,
    max_duration: Duration,
) -> anyhow::Result<()> {
    // Wait for SSH
    let ssh_start = Instant::now();
    let remaining = max_duration.saturating_sub(start.elapsed());
    let session = env
        .ssh_to(0, ec2ic, ssh_key, &args.ssh_user, remaining)
        .await
        .context("SSH to instance failed")?;
    let ssh_time = ssh_start.elapsed();
    info!(secs = ssh_time.as_secs(), "SSH ready");

    // Run default checks
    let check_start = Instant::now();
    let mut passed = 0;
    let mut failed = 0;

    for (name, cmd) in DEFAULT_CHECKS {
        match ssh::run_cmd(&session, cmd).await {
            Ok(output) => {
                let first_line = output.lines().next().unwrap_or("(no output)");
                info!(check = %name, output = %first_line.trim(), "PASS");
                passed += 1;
            }
            Err(e) => {
                info!(check = %name, error = %e, "FAIL");
                failed += 1;
            }
        }
    }

    // Run extra checks
    for cmd in &args.extra_checks {
        match ssh::run_cmd(&session, cmd).await {
            Ok(output) => {
                let first_line = output.lines().next().unwrap_or("(no output)");
                info!(check = %cmd, output = %first_line.trim(), "PASS");
                passed += 1;
            }
            Err(e) => {
                info!(check = %cmd, error = %e, "FAIL");
                failed += 1;
            }
        }
    }

    let check_time = check_start.elapsed();
    let total_time = start.elapsed();

    info!(
        "Boot test {}: {passed} passed, {failed} failed \
         (launch={:.1}s ssh={:.1}s checks={:.1}s total={:.1}s)",
        if failed == 0 { "PASSED" } else { "FAILED" },
        launch_time.as_secs_f64(),
        ssh_time.as_secs_f64(),
        check_time.as_secs_f64(),
        total_time.as_secs_f64(),
    );

    session.close().await.ok();

    if failed > 0 {
        anyhow::bail!("{failed} boot check(s) failed");
    }

    Ok(())
}
