//! Boot check: verify binaries and services on the current machine.
//!
//! Designed to be called BY Packer as a provisioner — runs on the EC2 instance
//! that Packer already SSHed into. No SSH, no instance management. Just checks.

use anyhow::bail;
use clap::Args;
use tracing::info;

/// Default checks when no extra checks are specified.
const DEFAULT_CHECKS: &[(&str, &[&str])] = &[
    ("kindling", &["kindling", "--version"]),
    ("k3s", &["k3s", "--version"]),
    ("wireguard-tools", &["wg", "--version"]),
];

#[derive(Args)]
pub struct BootCheckArgs {
    /// Additional commands to check (repeatable). Each must exit 0.
    #[arg(long = "check", value_name = "CMD")]
    pub extra_checks: Vec<String>,

    /// Skip default checks (kindling, k3s, wg)
    #[arg(long)]
    pub no_defaults: bool,
}

/// Run boot checks on the local machine.
pub fn run(args: BootCheckArgs) -> anyhow::Result<()> {
    let mut passed = 0u32;
    let mut failed = 0u32;

    // Default checks
    if !args.no_defaults {
        for (name, cmd) in DEFAULT_CHECKS {
            match std::process::Command::new(cmd[0]).args(&cmd[1..]).output() {
                Ok(output) if output.status.success() => {
                    let ver = String::from_utf8_lossy(&output.stdout);
                    let first = ver.lines().next().unwrap_or("ok");
                    info!("[PASS] {name}: {}", first.trim());
                    passed += 1;
                }
                Ok(output) => {
                    let err = String::from_utf8_lossy(&output.stderr);
                    info!("[FAIL] {name}: exit {}", output.status.code().unwrap_or(-1));
                    if !err.is_empty() {
                        info!("  stderr: {}", err.trim());
                    }
                    failed += 1;
                }
                Err(e) => {
                    info!("[FAIL] {name}: {e}");
                    failed += 1;
                }
            }
        }
    }

    // Extra checks
    for cmd in &args.extra_checks {
        match std::process::Command::new("sh").args(["-c", cmd]).output() {
            Ok(output) if output.status.success() => {
                info!("[PASS] {cmd}");
                passed += 1;
            }
            Ok(output) => {
                info!("[FAIL] {cmd}: exit {}", output.status.code().unwrap_or(-1));
                failed += 1;
            }
            Err(e) => {
                info!("[FAIL] {cmd}: {e}");
                failed += 1;
            }
        }
    }

    let total = passed + failed;
    info!("{passed}/{total} checks passed");

    if failed > 0 {
        bail!("{failed}/{total} boot checks failed");
    }

    Ok(())
}
