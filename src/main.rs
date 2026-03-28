mod aws;
mod boot_test;
mod build;
mod ec2_harness;
mod packer;
mod rotate;
mod ssh;
mod status;
mod trigger;
mod vpn_test;
mod wg;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "ami-forge",
    about = "Rust CLI tool replacing shell scripts in the AMI build pipeline",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Boot-test an AMI: launch one instance, verify binaries and services
    BootTest(boot_test::BootTestArgs),

    /// Build an AMI from a nix disk image: upload, import, tag, and update SSM
    Build(build::BuildArgs),

    /// Build AMI via Packer — runs packer build on a JSON template
    Packer(packer::PackerArgs),

    /// Deregister an AMI by name and delete its orphaned EBS snapshots
    Rotate(rotate::RotateArgs),

    /// Show current AMI status from SSM and/or EC2
    Status(status::StatusArgs),

    /// Start a `CodeBuild` build and optionally wait for completion
    Trigger(trigger::TriggerArgs),

    /// Test VPN connectivity between two instances launched from an AMI
    VpnTest(vpn_test::VpnTestArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::BootTest(args) => boot_test::run(args).await,
        Command::Build(args) => build::run(args).await,
        Command::Packer(args) => packer::run(args).await,
        Command::Rotate(args) => rotate::run(args).await,
        Command::Status(args) => status::run(args).await,
        Command::Trigger(args) => trigger::run(args).await,
        Command::VpnTest(args) => vpn_test::run(args).await,
    }
}
