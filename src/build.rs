use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use aws_sdk_ec2::types::ImportImageLicenseConfigurationRequest;
use aws_sdk_s3::primitives::ByteStream;
use bytesize::ByteSize;
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use tracing::{info, warn};

use crate::rotate;

#[derive(Args)]
pub struct BuildArgs {
    /// Path to nix build output directory (finds *.raw / *.img / *.vhd)
    #[arg(long)]
    image: PathBuf,

    /// S3 bucket for transit upload
    #[arg(long)]
    bucket: String,

    /// Constant AMI name (used for rotation + tagging)
    #[arg(long)]
    ami_name: String,

    /// SSM parameter path to update with AMI ID
    #[arg(long)]
    ssm: String,

    /// AWS region
    #[arg(long, default_value = "us-east-1")]
    region: String,

    /// IAM role for vmimport (default: derived from ami-name)
    #[arg(long)]
    role_name: Option<String>,

    /// Import polling timeout in seconds
    #[arg(long, default_value_t = 1800)]
    timeout: u64,
}

/// Locate the first disk image (*.raw, *.img, *.vhd) inside the given directory.
fn find_image(dir: &Path) -> anyhow::Result<PathBuf> {
    let extensions = ["raw", "img", "vhd"];

    if dir.is_file() {
        if let Some(ext) = dir.extension().and_then(|e| e.to_str())
            && extensions.contains(&ext) {
                return Ok(dir.to_path_buf());
            }
        bail!(
            "Path {} is a file but not a recognized disk image (*.raw, *.img, *.vhd)",
            dir.display()
        );
    }

    if !dir.is_dir() {
        bail!("Path {} is not a file or directory", dir.display());
    }

    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("reading directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_file()
            && let Some(ext) = path.extension().and_then(|e| e.to_str())
                && extensions.contains(&ext) {
                    return Ok(path);
                }
    }

    // Search one level deeper (nix store outputs often nest)
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            for sub in std::fs::read_dir(&path)? {
                let sub = sub?;
                let sub_path = sub.path();
                if sub_path.is_file()
                    && let Some(ext) = sub_path.extension().and_then(|e| e.to_str())
                        && extensions.contains(&ext) {
                            return Ok(sub_path);
                        }
            }
        }
    }

    bail!(
        "No disk image (*.raw, *.img, *.vhd) found in {}",
        dir.display()
    );
}

/// Upload a file to S3 with progress reporting.
async fn upload_s3(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
    path: &Path,
) -> anyhow::Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("reading metadata for {}", path.display()))?;
    let file_size = metadata.len();

    info!(
        "Uploading {} ({}) to s3://{}/{}",
        path.display(),
        ByteSize(file_size),
        bucket,
        key
    );

    let pb = ProgressBar::new(file_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .expect("valid template")
            .progress_chars("#>-"),
    );

    let body = ByteStream::from_path(path)
        .await
        .with_context(|| format!("opening {} for upload", path.display()))?;

    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(body)
        .send()
        .await
        .context("S3 PutObject failed")?;

    pb.finish_with_message("upload complete");
    info!("Upload complete");
    Ok(())
}

/// Start an EC2 import-image task.
async fn import_image(
    client: &aws_sdk_ec2::Client,
    bucket: &str,
    key: &str,
    role_name: &str,
) -> anyhow::Result<String> {
    info!("Starting EC2 import-image from s3://{}/{}", bucket, key);

    let format = if key.to_ascii_lowercase().ends_with(".vhd") {
        "VHD"
    } else {
        "RAW"
    };

    let disk_container = aws_sdk_ec2::types::ImageDiskContainer::builder()
        .format(format)
        .user_bucket(
            aws_sdk_ec2::types::UserBucket::builder()
                .s3_bucket(bucket)
                .s3_key(key)
                .build(),
        )
        .build();

    let resp = client
        .import_image()
        .disk_containers(disk_container)
        .role_name(role_name)
        .license_specifications(
            ImportImageLicenseConfigurationRequest::builder()
                .license_configuration_arn("AWS/vm-import-export")
                .build(),
        )
        .send()
        .await
        .context("EC2 ImportImage failed")?;

    let task_id = resp
        .import_task_id()
        .context("import-image response missing import_task_id")?
        .to_string();

    info!("Import task started: {}", task_id);
    Ok(task_id)
}

/// Poll the import task until it completes or times out.
async fn poll_import(
    client: &aws_sdk_ec2::Client,
    task_id: &str,
    timeout: Duration,
) -> anyhow::Result<String> {
    let start = Instant::now();
    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}% — {msg}")
            .expect("valid template")
            .progress_chars("#>-"),
    );
    pb.set_message("importing...");

    loop {
        if start.elapsed() > timeout {
            pb.abandon_with_message("TIMEOUT");
            bail!(
                "Import task {} timed out after {}s",
                task_id,
                timeout.as_secs()
            );
        }

        let resp = client
            .describe_import_image_tasks()
            .import_task_ids(task_id)
            .send()
            .await
            .context("DescribeImportImageTasks failed")?;

        let task = resp
            .import_image_tasks()
            .first()
            .context("import task not found in describe response")?;

        let status = task.status().unwrap_or_default();
        let status_msg = task.status_message().unwrap_or_default();
        let progress = task
            .progress()
            .and_then(|p| p.parse::<u64>().ok())
            .unwrap_or(0);

        pb.set_position(progress);
        pb.set_message(format!("{status}: {status_msg}"));

        match status {
            "completed" => {
                let ami_id = task
                    .image_id()
                    .context("completed import task missing image_id")?
                    .to_string();
                pb.finish_with_message(format!("completed: {ami_id}"));
                info!("Import complete: {}", ami_id);
                return Ok(ami_id);
            }
            "deleted" | "deleting" => {
                pb.abandon_with_message("FAILED");
                bail!("Import task {task_id} was deleted: {status_msg}");
            }
            _ => {}
        }

        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}

/// Tag the AMI with the constant name.
async fn tag_ami(
    client: &aws_sdk_ec2::Client,
    ami_id: &str,
    ami_name: &str,
) -> anyhow::Result<()> {
    info!("Tagging AMI {} with Name={}", ami_id, ami_name);

    let name_tag = aws_sdk_ec2::types::Tag::builder()
        .key("Name")
        .value(ami_name)
        .build();

    let managed_tag = aws_sdk_ec2::types::Tag::builder()
        .key("ManagedBy")
        .value("pangea")
        .build();

    client
        .create_tags()
        .resources(ami_id)
        .tags(name_tag)
        .tags(managed_tag)
        .send()
        .await
        .context("CreateTags failed")?;

    // Also set the Name via modify-image-attribute so it shows in the AMI list
    client
        .modify_image_attribute()
        .image_id(ami_id)
        .description(
            aws_sdk_ec2::types::AttributeValue::builder()
                .value(ami_name)
                .build(),
        )
        .send()
        .await
        .context("ModifyImageAttribute (description) failed")?;

    Ok(())
}

/// Delete the transit S3 object.
async fn cleanup_s3(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
) -> anyhow::Result<()> {
    info!("Deleting transit artifact s3://{}/{}", bucket, key);

    client
        .delete_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .context("S3 DeleteObject failed")?;

    Ok(())
}

/// Orchestrate the full AMI build pipeline.
pub async fn run(args: BuildArgs) -> anyhow::Result<()> {
    // Step 1: Find the disk image
    let image_path = find_image(&args.image)?;
    info!("Found disk image: {}", image_path.display());

    // Build AWS clients
    let config = crate::aws::load_config(&args.region).await;
    let ec2_client = aws_sdk_ec2::Client::new(&config);
    let s3_client = aws_sdk_s3::Client::new(&config);
    let ssm_client = aws_sdk_ssm::Client::new(&config);

    // S3 key for the transit upload
    let filename = image_path
        .file_name()
        .context("image path has no filename")?
        .to_str()
        .context("filename is not valid UTF-8")?;
    let s3_key = format!("ami-forge/{}/{}", args.ami_name, filename);

    // Step 2: Upload to S3
    upload_s3(&s3_client, &args.bucket, &s3_key, &image_path).await?;

    // Step 3: Rotate old AMI (deregister + delete snapshots)
    info!("Rotating any existing AMI named '{}'", args.ami_name);
    match rotate::run_rotate(&ec2_client, &args.ami_name).await {
        Ok(()) => info!("Old AMI rotation complete"),
        Err(e) => warn!("AMI rotation skipped or failed (may not exist yet): {e}"),
    }

    // Step 4: Import image
    let role_name = args
        .role_name
        .unwrap_or_else(|| format!("{}-vmimport", args.ami_name));
    let task_id = import_image(&ec2_client, &args.bucket, &s3_key, &role_name).await?;

    // Step 5: Poll until complete
    let timeout = Duration::from_secs(args.timeout);
    let ami_id = poll_import(&ec2_client, &task_id, timeout).await?;

    // Step 6: Tag the AMI
    tag_ami(&ec2_client, &ami_id, &args.ami_name).await?;

    // Step 7: Update SSM parameter
    crate::aws::put_ssm_parameter(&ssm_client, &args.ssm, &ami_id).await?;

    // Step 8: Delete transit S3 artifact
    cleanup_s3(&s3_client, &args.bucket, &s3_key).await?;

    info!("AMI build pipeline complete: {}", ami_id);
    Ok(())
}
