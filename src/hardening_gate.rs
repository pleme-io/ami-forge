//! Hardening gate — inspect a kindling `HardeningReport` and decide
//! whether an AMI is safe to promote.
//!
//! Designed for the pipeline-run flow: after `kindling harden` runs
//! during the Packer build, Packer uploads the report JSON from the
//! builder (via ami-forge's S3 sidecar or as an artifact) and this
//! subcommand decides whether the AMI may advance.
//!
//! Produces a signed attestation ("manifest") — the SHA-256 digest of
//! (ami-id || profile names || report status || invariant counters),
//! which the ami-forge promote step embeds as an SSM-adjacent
//! parameter. Anyone verifying a running AMI can re-compute the digest
//! from the sources of record and confirm the hardening provenance.

use anyhow::{bail, Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Debug, Args)]
pub struct HardeningGateArgs {
    /// Path to the kindling hardening-report JSON emitted by
    /// `kindling harden --format json`.
    #[arg(long)]
    pub report: PathBuf,

    /// AMI ID the report applies to. Included in the attestation.
    #[arg(long)]
    pub ami_id: String,

    /// Minimum acceptable report status. Default `pass`. Allowed:
    /// `pass`, `degraded`.
    #[arg(long, default_value = "pass")]
    pub min_status: String,

    /// Required invariants (repeatable). The gate fails if any is
    /// missing from the report's `invariants_passed` set.
    #[arg(long = "require-invariant", value_name = "NAME")]
    pub required_invariants: Vec<String>,

    /// Disallowed primitives — the report must NOT contain these
    /// primitive names. Useful to block e.g. `zero-fill` on long-lived
    /// instance test pipelines.
    #[arg(long = "forbid-primitive", value_name = "NAME")]
    pub forbidden_primitives: Vec<String>,

    /// Where to write the attestation JSON.
    #[arg(long, default_value = "hardening-attestation.json")]
    pub out: PathBuf,
}

// Subset of the kindling report — kept narrow so upstream kindling
// fields can grow without breaking us.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Report {
    profiles: Vec<String>,
    primitives: Vec<PrimitiveRecord>,
    #[serde(default)]
    totals: Totals,
    status: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Totals {
    #[serde(default)]
    bytes_freed: u64,
    #[serde(default)]
    entries_affected: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PrimitiveRecord {
    name: String,
    #[serde(default)]
    category: Option<String>,
    outcome: Outcome,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Outcome {
    #[serde(default)]
    invariants_passed: Vec<String>,
    #[serde(default)]
    invariants_failed: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Attestation<'a> {
    ami_id: &'a str,
    profiles: &'a [String],
    status: &'a str,
    primitive_count: usize,
    invariants_passed: usize,
    invariants_failed: usize,
    bytes_freed: u64,
    entries_affected: u64,
    report_sha256: String,
    attestation_sha256: String,
}

pub fn run(args: HardeningGateArgs) -> Result<()> {
    let raw = std::fs::read(&args.report)
        .with_context(|| format!("read {}", args.report.display()))?;
    let report: Report = serde_json::from_slice(&raw).context("parse hardening report json")?;

    info!(
        "hardening report: ami={} profiles=[{}] status={} primitives={}",
        args.ami_id,
        report.profiles.join(","),
        report.status,
        report.primitives.len()
    );

    // Status gate.
    let ok = match args.min_status.as_str() {
        "pass" => report.status == "pass",
        "degraded" => matches!(report.status.as_str(), "pass" | "degraded"),
        other => bail!("unknown --min-status `{other}` (want pass|degraded)"),
    };
    if !ok {
        bail!(
            "hardening gate: status `{}` below required `{}`",
            report.status,
            args.min_status
        );
    }

    // Collect invariants + primitive names across the report.
    let mut passed: Vec<&str> = Vec::new();
    let mut failed: Vec<&str> = Vec::new();
    let mut prim_names: Vec<&str> = Vec::new();
    for rec in &report.primitives {
        prim_names.push(&rec.name);
        for inv in &rec.outcome.invariants_passed { passed.push(inv); }
        for inv in &rec.outcome.invariants_failed { failed.push(inv); }
        if let Some(err) = &rec.error {
            warn!("primitive `{}` error: {}", rec.name, err);
        }
    }

    // Required invariants.
    let mut missing: Vec<String> = Vec::new();
    for req in &args.required_invariants {
        if !passed.iter().any(|p| p == req) {
            missing.push(req.clone());
        }
    }
    if !missing.is_empty() {
        bail!(
            "hardening gate: missing required invariants: {}",
            missing.join(", ")
        );
    }

    // Forbidden primitives.
    let mut forbidden_hits: Vec<String> = Vec::new();
    for bad in &args.forbidden_primitives {
        if prim_names.iter().any(|n| n == bad) {
            forbidden_hits.push(bad.clone());
        }
    }
    if !forbidden_hits.is_empty() {
        bail!(
            "hardening gate: forbidden primitives present: {}",
            forbidden_hits.join(", ")
        );
    }

    // Compute the report + attestation digests.
    use sha2::{Digest, Sha256};
    let report_sha = {
        let mut h = Sha256::new();
        h.update(&raw);
        hex::encode(h.finalize())
    };
    // Attestation digest covers (ami_id, profiles, status, report_sha)
    // — it's what consumers verify against.
    let attn_preimage = format!(
        "{}|{}|{}|{}",
        args.ami_id,
        report.profiles.join(","),
        report.status,
        report_sha,
    );
    let attn_sha = {
        let mut h = Sha256::new();
        h.update(attn_preimage.as_bytes());
        hex::encode(h.finalize())
    };

    let attestation = Attestation {
        ami_id: &args.ami_id,
        profiles: &report.profiles,
        status: &report.status,
        primitive_count: report.primitives.len(),
        invariants_passed: passed.len(),
        invariants_failed: failed.len(),
        bytes_freed: report.totals.bytes_freed,
        entries_affected: report.totals.entries_affected,
        report_sha256: report_sha,
        attestation_sha256: attn_sha,
    };
    let body = serde_json::to_vec_pretty(&attestation)?;
    std::fs::write(&args.out, &body)
        .with_context(|| format!("write {}", args.out.display()))?;
    info!(
        "gate: OK — attestation {} bytes → {}",
        body.len(),
        args.out.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_report() -> &'static str {
        r#"{
          "profiles": ["base", "hardened"],
          "primitives": [
            {"name": "sshd-strict", "category": "network",
             "outcome": {"invariants_passed": ["sshd.PermitRootLogin=no"]}}
          ],
          "totals": {"bytes_freed": 123, "entries_affected": 1},
          "status": "pass"
        }"#
    }

    #[test]
    fn gate_passes_on_clean_report() {
        let dir = tempdir().unwrap();
        let rpt = dir.path().join("r.json");
        std::fs::write(&rpt, sample_report()).unwrap();
        let out = dir.path().join("a.json");
        let args = HardeningGateArgs {
            report: rpt,
            ami_id: "ami-0deadbeef".into(),
            min_status: "pass".into(),
            required_invariants: vec!["sshd.PermitRootLogin=no".into()],
            forbidden_primitives: vec![],
            out: out.clone(),
        };
        run(args).unwrap();
        assert!(out.exists());
        let att: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out).unwrap()).unwrap();
        assert_eq!(att["ami_id"], "ami-0deadbeef");
        assert_eq!(att["status"], "pass");
        assert_eq!(att["invariants_passed"], 1);
    }

    #[test]
    fn gate_fails_on_missing_invariant() {
        let dir = tempdir().unwrap();
        let rpt = dir.path().join("r.json");
        std::fs::write(&rpt, sample_report()).unwrap();
        let args = HardeningGateArgs {
            report: rpt,
            ami_id: "ami-x".into(),
            min_status: "pass".into(),
            required_invariants: vec!["will-not-be-found".into()],
            forbidden_primitives: vec![],
            out: dir.path().join("a.json"),
        };
        let err = run(args).unwrap_err();
        assert!(format!("{err:#}").contains("missing required invariants"));
    }

    #[test]
    fn gate_fails_on_forbidden_primitive() {
        let dir = tempdir().unwrap();
        let rpt = dir.path().join("r.json");
        std::fs::write(&rpt, sample_report()).unwrap();
        let args = HardeningGateArgs {
            report: rpt,
            ami_id: "ami-x".into(),
            min_status: "pass".into(),
            required_invariants: vec![],
            forbidden_primitives: vec!["sshd-strict".into()],
            out: dir.path().join("a.json"),
        };
        let err = run(args).unwrap_err();
        assert!(format!("{err:#}").contains("forbidden primitives"));
    }
}
