mod attic;
mod aws;
mod boot_check;
mod build;
mod cluster_test;
mod hardening_gate;
mod manifest;
mod multi_layer;
mod pipeline;
mod promote;
mod reaper;
mod rotate;
mod status;
mod trigger;
mod wg;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "ami-forge",
    about = "AMI build pipeline tool — called by Packer provisioners and Nix apps",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check binaries and services on the current machine (called by Packer)
    BootCheck(boot_check::BootCheckArgs),

    /// Build an AMI from a nix disk image: upload, import, tag, and update SSM
    Build(build::BuildArgs),

    /// Parse packer-manifest.json and print AMI ID to stdout
    ManifestId(manifest::ManifestIdArgs),

    /// Promote an AMI by updating SSM parameter
    Promote(promote::PromoteArgs),

    /// Terminate expired instances and deregister stale AMIs managed by ami-forge
    Reaper(reaper::ReaperArgs),

    /// Deregister an AMI by name and delete its orphaned EBS snapshots
    Rotate(rotate::RotateArgs),

    /// Show current AMI status from SSM and/or EC2
    Status(status::StatusArgs),

    /// Start a `CodeBuild` build and optionally wait for completion
    Trigger(trigger::TriggerArgs),

    /// Run the full AMI pipeline: build → test → promote (or rollback)
    PipelineRun(pipeline::PipelineRunArgs),

    /// Multi-node cluster integration test: 2 instances, VPN peering, K3s cluster
    ClusterTest(cluster_test::ClusterTestArgs),

    /// Run a multi-layer AMI pipeline: layer by layer with fingerprint caching
    MultiLayerRun(multi_layer::MultiLayerRunArgs),

    /// Verify a kindling hardening report + emit a signed attestation
    HardeningGate(hardening_gate::HardeningGateArgs),
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
        Command::BootCheck(args) => boot_check::run(args),
        Command::Build(args) => build::run(args).await,
        Command::ManifestId(args) => manifest::run(args),
        Command::Promote(args) => promote::run(args).await,
        Command::Reaper(args) => reaper::run(args).await,
        Command::Rotate(args) => rotate::run(args).await,
        Command::Status(args) => status::run(args).await,
        Command::Trigger(args) => trigger::run(args).await,
        Command::PipelineRun(args) => pipeline::run(args).await,
        Command::ClusterTest(args) => cluster_test::run(args).await,
        Command::MultiLayerRun(args) => multi_layer::run(args).await,
        Command::HardeningGate(args) => hardening_gate::run(args),
    }
}
