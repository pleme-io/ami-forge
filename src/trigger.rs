use std::time::Duration;

use anyhow::{Context, bail};
use aws_sdk_codebuild::types::{EnvironmentVariable, EnvironmentVariableType, StatusType};
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use tracing::info;

#[derive(Args)]
pub struct TriggerArgs {
    /// `CodeBuild` project name
    #[arg(long)]
    project: String,

    /// AWS region
    #[arg(long, default_value = "us-east-1")]
    region: String,

    /// Wait for build to complete (poll every 15s)
    #[arg(long)]
    wait: bool,

    /// Additional environment variable overrides (KEY=VALUE)
    #[arg(long = "env", value_name = "KEY=VALUE")]
    env: Vec<String>,
}

/// Parse a "KEY=VALUE" string into a `CodeBuild` `EnvironmentVariable`.
fn parse_env_var(s: &str) -> anyhow::Result<EnvironmentVariable> {
    let (key, value) = s
        .split_once('=')
        .with_context(|| format!("invalid env var format (expected KEY=VALUE): {s}"))?;

    EnvironmentVariable::builder()
        .name(key)
        .value(value)
        .r#type(EnvironmentVariableType::Plaintext)
        .build()
        .with_context(|| format!("failed to build environment variable from: {s}"))
}

/// Poll a `CodeBuild` build until it reaches a terminal state.
async fn poll_build(client: &aws_sdk_codebuild::Client, build_id: &str) -> anyhow::Result<()> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .expect("valid template"),
    );
    pb.enable_steady_tick(Duration::from_millis(200));
    pb.set_message("waiting for build to start...");

    let mut last_phase = String::new();

    loop {
        let resp = client
            .batch_get_builds()
            .ids(build_id)
            .send()
            .await
            .context("BatchGetBuilds failed")?;

        let build = resp
            .builds()
            .first()
            .context("build not found in BatchGetBuilds response")?;

        // Log phase transitions
        let current_phase = build
            .current_phase()
            .unwrap_or("UNKNOWN")
            .to_string();

        if current_phase != last_phase {
            if !last_phase.is_empty() {
                info!("phase transition: {} -> {}", last_phase, current_phase);
            }
            pb.set_message(format!("phase: {current_phase}"));
            last_phase.clone_from(&current_phase);
        }

        // Log individual phase completions
        for phase in build.phases() {
            if let (Some(name), Some(status)) =
                (phase.phase_type(), phase.phase_status())
            {
                info!(
                    "phase {} completed with status {}",
                    name.as_str(),
                    status.as_str()
                );
            }
        }

        // Check terminal status
        if let Some(status) = build.build_status() {
            match status {
                StatusType::Succeeded => {
                    pb.finish_with_message("build SUCCEEDED");
                    info!("Build {} succeeded", build_id);
                    return Ok(());
                }
                StatusType::Failed => {
                    pb.finish_with_message("build FAILED");
                    bail!("Build {build_id} failed");
                }
                StatusType::TimedOut => {
                    pb.finish_with_message("build TIMED_OUT");
                    bail!("Build {build_id} timed out");
                }
                StatusType::Stopped => {
                    pb.finish_with_message("build STOPPED");
                    bail!("Build {build_id} was stopped");
                }
                StatusType::Fault => {
                    pb.finish_with_message("build FAULT");
                    bail!("Build {build_id} encountered a fault error");
                }
                _ => {}
            }
        }

        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}

/// Start a `CodeBuild` build and optionally wait for completion.
pub async fn run(args: TriggerArgs) -> anyhow::Result<()> {
    let config = crate::aws::load_config(&args.region).await;
    let client = aws_sdk_codebuild::Client::new(&config);

    info!("Starting CodeBuild project: {}", args.project);

    let mut request = client.start_build().project_name(&args.project);

    // Add environment variable overrides if provided
    if !args.env.is_empty() {
        let env_vars: Vec<EnvironmentVariable> = args
            .env
            .iter()
            .map(|e| parse_env_var(e))
            .collect::<anyhow::Result<Vec<_>>>()
            .context("failed to parse environment variable overrides")?;

        for var in env_vars {
            request = request.environment_variables_override(var);
        }
    }

    let resp = request.send().await.context("StartBuild failed")?;

    let build = resp.build_value().context("StartBuild response missing build")?;
    let build_id = build.id().context("build missing id")?.to_string();

    info!("Build started: {}", build_id);

    if args.wait {
        info!("Polling build until completion...");
        poll_build(&client, &build_id).await?;
    } else {
        println!("{build_id}");
    }

    Ok(())
}
