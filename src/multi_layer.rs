//! Multi-layer AMI pipeline: each layer produces a checkpointed AMI.
//! Failures restart from the last good layer. Attic cache grows with each build.

use anyhow::{bail, Context, Result};
use clap::Args;
use serde::Deserialize;
use std::path::PathBuf;
use std::process::Command;
use tracing::{error, info, warn};

use crate::attic;

#[derive(Args)]
pub struct MultiLayerRunArgs {
    #[arg(long)]
    pub config: PathBuf,
}

#[derive(Deserialize)]
pub struct MultiLayerConfig {
    pub layers: Vec<LayerConfig>,
    #[serde(default)]
    pub test_layers: Vec<TestLayerConfig>,
    pub promote_ssm: String,
    pub ami_name: String,
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default)]
    pub attic: Option<attic::AtticConfig>,
}

#[derive(Deserialize)]
pub struct LayerConfig {
    pub template: PathBuf,
    pub name: String,
    pub ssm_parameter: String,
    #[serde(default)]
    pub fingerprint_inputs: Vec<String>,
}

#[derive(Deserialize)]
pub struct TestLayerConfig {
    pub template: PathBuf,
    pub name: String,
}

fn default_region() -> String {
    "us-east-1".into()
}

pub async fn run(args: MultiLayerRunArgs) -> Result<()> {
    let config_content = std::fs::read_to_string(&args.config)
        .with_context(|| format!("failed to read config: {}", args.config.display()))?;
    let config: MultiLayerConfig = serde_yaml::from_str(&config_content)
        .context("failed to parse multi-layer config")?;

    // Validate
    for layer in &config.layers {
        if !layer.template.exists() {
            bail!(
                "Layer template not found: {} ({})",
                layer.name,
                layer.template.display()
            );
        }
    }
    for test in &config.test_layers {
        if !test.template.exists() {
            bail!(
                "Test template not found: {} ({})",
                test.name,
                test.template.display()
            );
        }
    }

    let aws_config = crate::aws::load_config(&config.region).await;
    let arn = crate::aws::validate_credentials(&aws_config).await?;
    info!("Multi-layer pipeline starting as {arn}");

    let ec2 = aws_sdk_ec2::Client::new(&aws_config);
    let ssm = aws_sdk_ssm::Client::new(&aws_config);
    let github_token = std::env::var("GITHUB_TOKEN").unwrap_or_default();

    // Boot Attic (REQUIRED -- every run must use and contribute to the cache)
    let attic_res = if let Some(ref attic_cfg) = config.attic {
        info!("[attic] PRE-GATE: Booting ephemeral cache from {}", attic_cfg.ssm);
        let res = attic::attic_boot(&ec2, &ssm, attic_cfg).await
            .context("[attic] PRE-GATE FAILED: cache boot failed -- refusing to build without cache")?;
        attic::attic_wait_healthy(&res.public_ip, 180).await
            .map_err(|e| {
                // Teardown the instance we booted before bailing
                let ec2_clone = ec2.clone();
                let res_clone_id = res.instance_id.clone();
                tokio::spawn(async move {
                    let _ = ec2_clone.terminate_instances().instance_ids(&res_clone_id).send().await;
                });
                e
            })
            .context("[attic] PRE-GATE FAILED: cache not healthy -- refusing to build without cache")?;
        info!("[attic] PRE-GATE PASSED: cache ready at {}", res.private_ip);
        Some(res)
    } else {
        bail!("[attic] No Attic config -- multi-layer pipeline requires cache for every run");
    };

    // Run layers
    let result = run_layers(&config, &ec2, &ssm, &github_token, &attic_res).await;

    // Attic POST-GATE: verify cache is still alive after layers ran
    if let Some(ref res) = attic_res {
        info!("[attic] POST-GATE: verifying cache still healthy");
        if let Err(e) = attic::attic_wait_healthy(&res.public_ip, 30).await {
            error!("[attic] POST-GATE FAILED: cache died during build -- NARs may not have been pushed: {e:#}");
            let _ = attic::attic_teardown(&ec2, res).await;
            // Still return the layer result (layers may have succeeded)
            // but log the cache failure prominently
            if result.is_ok() {
                warn!("[attic] Layers passed but cache died -- this run did NOT contribute to the cache");
            }
        } else {
            info!("[attic] POST-GATE PASSED: cache alive, snapshotting");
        }

        // Attic snapshot (REQUIRED -- cache must grow every run)
        if let Some(ref attic_cfg) = config.attic {
            info!("[attic] Snapshotting cache");
            match attic::attic_snapshot(&ec2, &ssm, &res.instance_id, &attic_cfg.ssm).await {
                Ok(()) => info!("[attic] Snapshot succeeded -- cache enriched for next run"),
                Err(e) => {
                    error!("[attic] SNAPSHOT FAILED: {e:#}");
                    // Don't fail the pipeline if layers+tests passed,
                    // but log prominently so we know the cache didn't grow
                    warn!("[attic] This run did NOT enrich the cache -- next run will be slower");
                }
            }
        }
        let _ = attic::attic_teardown(&ec2, res).await;
    }

    result
}

async fn run_layers(
    config: &MultiLayerConfig,
    ec2: &aws_sdk_ec2::Client,
    ssm: &aws_sdk_ssm::Client,
    github_token: &str,
    attic_res: &Option<attic::AtticResources>,
) -> Result<()> {
    let total_layers = config.layers.len();
    let total_tests = config.test_layers.len();
    let total = total_layers + total_tests + 1; // +1 for promote
    let mut step = 0;
    let mut current_ami: Option<String> = None;

    // Build layers
    for layer in &config.layers {
        step += 1;
        info!("[{step}/{total}] Layer '{}' -- checking cache", layer.name);

        // Check fingerprint cache
        let fingerprint = compute_fingerprint(&layer.fingerprint_inputs, current_ami.as_deref());
        if let Some(cached_ami) =
            check_layer_cache(ssm, ec2, &layer.ssm_parameter, &fingerprint).await?
        {
            info!(
                "[{step}/{total}] Layer '{}' CACHED -- using {cached_ami}",
                layer.name
            );
            current_ami = Some(cached_ami);
            continue;
        }

        info!("[{step}/{total}] Layer '{}' -- building", layer.name);
        let tpl = layer.template.to_string_lossy();

        // Init packer
        run_packer_init(&tpl)?;

        // Build with vars
        let mut vars = vec![format!("github_token={github_token}")];
        if let Some(ref ami) = current_ami {
            vars.push(format!("source_ami={ami}"));
        }
        if let Some(res) = attic_res {
            let cache_name = config
                .attic
                .as_ref()
                .map(|a| a.cache_name.as_str())
                .unwrap_or("nexus");
            vars.push(format!(
                "attic_url=http://{}:8080/{cache_name}",
                res.private_ip
            ));
        }

        // Use per-layer manifest to avoid collision
        let manifest = format!("packer-manifest-{}.json", layer.name);
        // Clean old manifest
        let _ = std::fs::remove_file(&manifest);

        run_packer_build(&tpl, &vars)?;

        // Extract AMI ID
        let ami_id = crate::aws::parse_packer_manifest(&manifest)
            .or_else(|_| crate::aws::parse_packer_manifest("packer-manifest.json"))?;
        info!("[{step}/{total}] Layer '{}' built: {ami_id}", layer.name);

        // Tag with fingerprint
        let _ = ec2
            .create_tags()
            .resources(&ami_id)
            .tags(
                aws_sdk_ec2::types::Tag::builder()
                    .key("LayerFingerprint")
                    .value(&fingerprint)
                    .build(),
            )
            .tags(
                aws_sdk_ec2::types::Tag::builder()
                    .key("LayerName")
                    .value(&layer.name)
                    .build(),
            )
            .send()
            .await;

        // Store in SSM
        crate::aws::put_ssm_parameter(ssm, &layer.ssm_parameter, &ami_id).await?;
        info!(
            "[{step}/{total}] Layer '{}' stored in SSM: {}",
            layer.name, layer.ssm_parameter
        );

        current_ami = Some(ami_id);

        // Clean manifest
        let _ = std::fs::remove_file("packer-manifest.json");
        let _ = std::fs::remove_file(&manifest);
    }

    let final_ami = current_ami.context("no layers produced an AMI")?;

    // Run test layers
    for test in &config.test_layers {
        step += 1;
        info!("[{step}/{total}] Test '{}' on {final_ami}", test.name);
        let tpl = test.template.to_string_lossy();
        run_packer_init(&tpl)?;
        let test_result = run_packer_build(&tpl, &[format!("source_ami={final_ami}")]);
        if let Err(e) = test_result {
            error!("Test '{}' FAILED: {e:#}", test.name);
            // Deregister the release AMI
            info!("Deregistering failed AMI: {final_ami}");
            let _ = crate::rotate::run_rotate(
                &aws_sdk_ec2::Client::new(&crate::aws::load_config(&config.region).await),
                &config.ami_name,
            )
            .await;
            bail!("Test '{}' failed", test.name);
        }
    }

    // Promote
    step += 1;
    info!(
        "[{step}/{total}] Promoting {final_ami} to {}",
        config.promote_ssm
    );
    crate::aws::put_ssm_parameter(ssm, &config.promote_ssm, &final_ami).await?;
    info!(
        "Multi-layer pipeline complete -- {final_ami} promoted to {}",
        config.promote_ssm
    );

    Ok(())
}

fn compute_fingerprint(inputs: &[String], previous_ami: Option<&str>) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    for input in inputs {
        let path = std::path::Path::new(input);
        if path.exists() {
            if let Ok(contents) = std::fs::read(path) {
                contents.hash(&mut hasher);
            }
        } else {
            input.hash(&mut hasher);
        }
    }
    if let Some(ami) = previous_ami {
        ami.hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

async fn check_layer_cache(
    ssm: &aws_sdk_ssm::Client,
    ec2: &aws_sdk_ec2::Client,
    ssm_param: &str,
    expected_fingerprint: &str,
) -> Result<Option<String>> {
    // Get stored AMI from SSM
    let resp = ssm.get_parameter().name(ssm_param).send().await;
    let ami_id = match resp {
        Ok(r) => r.parameter().and_then(|p| p.value()).map(String::from),
        Err(_) => None,
    };
    let Some(ami_id) = ami_id else {
        return Ok(None);
    };

    // Check AMI exists
    let desc = ec2.describe_images().image_ids(&ami_id).send().await;
    let exists = desc
        .map(|d| {
            d.images()
                .first()
                .map(|i| {
                    i.state()
                        .map(|s| s.as_str() == "available")
                        .unwrap_or(false)
                })
                .unwrap_or(false)
        })
        .unwrap_or(false);
    if !exists {
        return Ok(None);
    }

    // Check fingerprint tag
    let tags = ec2
        .describe_tags()
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name("resource-id")
                .values(&ami_id)
                .build(),
        )
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name("key")
                .values("LayerFingerprint")
                .build(),
        )
        .send()
        .await;
    let stored_fp = tags
        .ok()
        .and_then(|t| t.tags().first().and_then(|tag| tag.value().map(String::from)));

    if stored_fp.as_deref() == Some(expected_fingerprint) {
        Ok(Some(ami_id))
    } else {
        Ok(None)
    }
}

fn run_packer_init(template: &str) -> Result<()> {
    let status = Command::new("packer")
        .args(["init", template])
        .status()
        .context("failed to execute packer init")?;
    if !status.success() {
        bail!("packer init failed for {template}");
    }
    Ok(())
}

fn run_packer_build(template: &str, vars: &[String]) -> Result<()> {
    let mut cmd = Command::new("packer");
    cmd.arg("build");
    for var in vars {
        cmd.args(["-var", var]);
    }
    cmd.arg(template);
    let status = cmd.status().context("failed to execute packer build")?;
    if !status.success() {
        bail!("packer build failed for {template}");
    }
    Ok(())
}
