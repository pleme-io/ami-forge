mod build;
mod rotate;
mod status;
mod trigger;

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
    /// Build an AMI from a nix disk image: upload, import, tag, and update SSM
    Build(build::BuildArgs),

    /// Deregister an AMI by name and delete its orphaned EBS snapshots
    Rotate(rotate::RotateArgs),

    /// Show current AMI status from SSM and/or EC2
    Status(status::StatusArgs),

    /// Start a CodeBuild build and optionally wait for completion
    Trigger(trigger::TriggerArgs),
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
        Command::Build(args) => build::run(args).await,
        Command::Rotate(args) => rotate::run(args).await,
        Command::Status(args) => status::run(args).await,
        Command::Trigger(args) => trigger::run(args).await,
    }
}
