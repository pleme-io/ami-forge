//! Ephemeral SSH key generation and session management for VPN testing.
//!
//! Uses the `ssh-key` crate for pure-Rust Ed25519 key generation with OpenSSH
//! format export, and the `openssh` crate for multiplexed SSH sessions.
//!
//! Designed for EC2 Instance Connect: generate an ephemeral keypair, push the
//! public key via AWS API (60s TTL), then connect with the private key.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use tracing::{info, warn};

/// An ephemeral Ed25519 SSH key pair with the private key stored in a temp file.
///
/// The temp directory (and private key file) is automatically cleaned up when
/// this struct is dropped.
pub struct EphemeralSshKey {
    /// OpenSSH-formatted public key string (for EC2 Instance Connect API).
    pub openssh_public: String,

    /// Temp directory holding the private key file.
    _temp_dir: tempfile::TempDir,

    /// Path to the private key file within the temp directory.
    private_key_path: PathBuf,
}

impl EphemeralSshKey {
    /// Generate a new ephemeral Ed25519 SSH key pair.
    ///
    /// The private key is written to a temp file with 0o600 permissions.
    /// The public key is available as an OpenSSH-formatted string.
    pub fn generate() -> anyhow::Result<Self> {
        let private_key = ssh_key::PrivateKey::random(
            &mut rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .context("failed to generate Ed25519 key pair")?;

        let openssh_public = private_key
            .public_key()
            .to_openssh()
            .context("failed to encode public key in OpenSSH format")?;

        let openssh_private = private_key
            .to_openssh(ssh_key::LineEnding::LF)
            .context("failed to encode private key in OpenSSH format")?;

        let temp_dir = tempfile::tempdir().context("failed to create temp directory")?;
        let key_path = temp_dir.path().join("id_ed25519");

        std::fs::write(&key_path, openssh_private.as_bytes())
            .context("failed to write private key to temp file")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .context("failed to set private key permissions")?;
        }

        Ok(Self {
            openssh_public,
            _temp_dir: temp_dir,
            private_key_path: key_path,
        })
    }

    /// Path to the ephemeral private key file (for openssh `SessionBuilder::keyfile`).
    pub fn private_key_path(&self) -> &Path {
        &self.private_key_path
    }
}

/// Push an SSH public key to an EC2 instance via EC2 Instance Connect.
///
/// The key is available for 60 seconds. Connect within that window.
pub async fn push_ssh_key(
    client: &aws_sdk_ec2instanceconnect::Client,
    instance_id: &str,
    az: &str,
    os_user: &str,
    public_key: &str,
) -> anyhow::Result<()> {
    let resp = client
        .send_ssh_public_key()
        .instance_id(instance_id)
        .instance_os_user(os_user)
        .ssh_public_key(public_key)
        .availability_zone(az)
        .send()
        .await
        .context("EC2 Instance Connect SendSSHPublicKey failed")?;

    if !resp.success() {
        bail!("EC2 Instance Connect returned success=false for instance {instance_id}");
    }

    info!(instance = %instance_id, "SSH public key pushed (60s TTL)");
    Ok(())
}

/// Establish a multiplexed SSH session to a host using an ephemeral key.
///
/// Uses `ControlMaster` so all subsequent commands share one TCP connection,
/// surviving the 60s EC2 Instance Connect TTL after initial connect.
pub async fn connect(
    host: &str,
    user: &str,
    key: &EphemeralSshKey,
    timeout: Duration,
) -> anyhow::Result<openssh::Session> {
    let destination = format!("{user}@{host}");

    let session = openssh::SessionBuilder::default()
        .keyfile(key.private_key_path())
        .known_hosts_check(openssh::KnownHosts::Accept)
        .connect_timeout(timeout)
        .server_alive_interval(Duration::from_secs(15))
        .connect(&destination)
        .await
        .with_context(|| format!("SSH connect to {destination} failed"))?;

    info!(host = %host, "SSH session established");
    Ok(session)
}

/// Wait for SSH to become available on a host, retrying with backoff.
///
/// Pushes the SSH key before each attempt (refreshes the 60s TTL).
pub async fn wait_for_ssh(
    ec2ic_client: &aws_sdk_ec2instanceconnect::Client,
    instance_id: &str,
    az: &str,
    host: &str,
    os_user: &str,
    key: &EphemeralSshKey,
    max_wait: Duration,
) -> anyhow::Result<openssh::Session> {
    let start = std::time::Instant::now();
    let retry_interval = Duration::from_secs(5);

    loop {
        if start.elapsed() > max_wait {
            bail!(
                "SSH to {} not ready after {}s",
                host,
                max_wait.as_secs()
            );
        }

        // Push key before each attempt (refresh 60s TTL)
        if let Err(e) = push_ssh_key(ec2ic_client, instance_id, az, os_user, &key.openssh_public).await {
            warn!(error = %e, "failed to push SSH key, retrying...");
            tokio::time::sleep(retry_interval).await;
            continue;
        }

        match connect(host, os_user, key, Duration::from_secs(10)).await {
            Ok(session) => return Ok(session),
            Err(e) => {
                info!(
                    error = %e,
                    elapsed = ?start.elapsed(),
                    "SSH not ready yet, retrying..."
                );
                tokio::time::sleep(retry_interval).await;
            }
        }
    }
}

/// Run a shell command on a remote host and return stdout.
///
/// Bails if the command exits non-zero.
pub async fn run_cmd(session: &openssh::Session, cmd: &str) -> anyhow::Result<String> {
    let output = session
        .shell(cmd)
        .output()
        .await
        .with_context(|| format!("failed to execute remote command: {cmd}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "remote command failed (exit {}): {}\nstderr: {}",
            output.status.code().unwrap_or(-1),
            cmd,
            stderr.trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Write content to a file on the remote host via shell heredoc.
///
/// Sets permissions to 0600 after writing.
pub async fn write_file(
    session: &openssh::Session,
    path: &str,
    content: &str,
) -> anyhow::Result<()> {
    // Create parent directory
    let parent = Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    if !parent.is_empty() {
        run_cmd(session, &format!("mkdir -p {parent} && chmod 700 {parent}")).await?;
    }

    // Write via heredoc (avoids quoting issues with base64 keys)
    let cmd = format!(
        "cat > {path} << 'AMI_FORGE_EOF'\n{content}\nAMI_FORGE_EOF"
    );
    run_cmd(session, &cmd).await?;

    // Set restrictive permissions
    run_cmd(session, &format!("chmod 600 {path}")).await?;

    info!(path = %path, "wrote remote file");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ephemeral_key() {
        let key = EphemeralSshKey::generate().unwrap();

        // Public key should be in OpenSSH format
        assert!(
            key.openssh_public.starts_with("ssh-ed25519 "),
            "public key should start with 'ssh-ed25519 ', got: {}",
            &key.openssh_public[..30.min(key.openssh_public.len())]
        );

        // Private key file should exist
        assert!(key.private_key_path().exists());

        // Private key file should contain OpenSSH format
        let content = std::fs::read_to_string(key.private_key_path()).unwrap();
        assert!(
            content.contains("BEGIN OPENSSH PRIVATE KEY"),
            "private key should be in OpenSSH format"
        );
        assert!(
            content.contains("END OPENSSH PRIVATE KEY"),
            "private key should have end marker"
        );
    }

    #[test]
    fn ephemeral_keys_are_unique() {
        let key1 = EphemeralSshKey::generate().unwrap();
        let key2 = EphemeralSshKey::generate().unwrap();
        assert_ne!(
            key1.openssh_public, key2.openssh_public,
            "two generated keys should be different"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_key_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let key = EphemeralSshKey::generate().unwrap();
        let metadata = std::fs::metadata(key.private_key_path()).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private key should have 0600 permissions, got {mode:o}");
    }

    #[test]
    fn private_key_path_is_in_temp_dir() {
        let key = EphemeralSshKey::generate().unwrap();
        let path = key.private_key_path();
        assert!(
            path.file_name().unwrap() == "id_ed25519",
            "key file should be named id_ed25519"
        );
    }

    #[test]
    fn private_key_cleaned_up_on_drop() {
        let path;
        {
            let key = EphemeralSshKey::generate().unwrap();
            path = key.private_key_path().to_path_buf();
            assert!(path.exists(), "key should exist before drop");
        }
        // After drop, the temp dir (and key) should be cleaned up
        assert!(!path.exists(), "key should be cleaned up after drop");
    }
}
