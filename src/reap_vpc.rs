//! Reap orphan VPCs — duplicate VPCs left behind by failed IaC applies.
//!
//! A duplicate-CIDR VPC created by an aborted `magma`/`tofu` apply has no
//! owner in any workspace state, so no reconciler ever removes it. This
//! subcommand reaps that specific class: a VPC that matches a Name tag AND
//! a CIDR block, carries ZERO network interfaces (nothing is running in
//! it), is not the AWS default VPC, and is not in an explicit keep-list.
//!
//! ALL of those must hold — the decision is the pure function
//! [`vpc_is_reapable`], unit-tested with no live AWS, so the safety logic is
//! provable in isolation the way `reaper`'s TTL filter is. Dry-run is the
//! default; `--apply` is required to actually delete. The 0-ENI gate alone
//! spares any live VPC — a VPC with a running cluster in it always carries
//! interfaces — and the keep-list is a second, explicit belt-and-suspenders
//! guard.

use anyhow::Context;
use clap::Args;
use tracing::{info, warn};

#[derive(Args)]
pub struct ReapVpcArgs {
    /// AWS region
    #[arg(long, default_value = "us-east-2")]
    region: String,

    /// AWS SSO profile to use for credentials (optional; omit to use the
    /// ambient credential chain / `AWS_PROFILE`)
    #[arg(long)]
    profile: Option<String>,

    /// Only consider VPCs whose `Name` tag equals this
    #[arg(long, default_value = "camelot-eks-vpc")]
    name_tag: String,

    /// Only consider VPCs whose CIDR block equals this
    #[arg(long, default_value = "10.40.0.0/16")]
    cidr: String,

    /// VPC IDs to NEVER reap even if they otherwise qualify (belt-and-
    /// suspenders on top of the 0-ENI gate). Repeatable.
    #[arg(long = "keep")]
    keep: Vec<String>,

    /// Actually delete. Without this flag the command is a dry run that only
    /// reports what it would reap.
    #[arg(long, default_value_t = false)]
    apply: bool,
}

/// The minimal view of a VPC the reap decision needs — extracted from the
/// SDK type by the caller so the decision itself is pure and testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpcView {
    pub id: String,
    pub name_tag: Option<String>,
    pub cidr: String,
    pub is_default: bool,
    pub eni_count: usize,
}

/// The outcome of the pure safety check for one VPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReapDecision {
    Reap,
    /// Spared, with a human-readable reason for the log.
    Skip(String),
}

/// Decide whether a VPC is a reapable orphan. Every condition must hold:
/// not the default VPC, not keep-listed, `Name` tag matches, CIDR matches,
/// and zero attached ENIs. Any failure returns `Skip` with the reason.
/// Pure — no AWS, no I/O.
#[must_use]
pub fn vpc_is_reapable(
    vpc: &VpcView,
    want_name: &str,
    want_cidr: &str,
    keep: &[String],
) -> ReapDecision {
    if vpc.is_default {
        return ReapDecision::Skip("is the AWS default VPC".to_string());
    }
    if keep.iter().any(|k| k == &vpc.id) {
        return ReapDecision::Skip("in the explicit keep-list".to_string());
    }
    if vpc.name_tag.as_deref() != Some(want_name) {
        return ReapDecision::Skip(format!(
            "Name tag {:?} != {want_name:?}",
            vpc.name_tag
        ));
    }
    if vpc.cidr != want_cidr {
        return ReapDecision::Skip(format!("CIDR {} != {want_cidr}", vpc.cidr));
    }
    if vpc.eni_count != 0 {
        return ReapDecision::Skip(format!(
            "{} ENI(s) attached — in use",
            vpc.eni_count
        ));
    }
    ReapDecision::Reap
}

fn vpc_filter(name: &str, value: &str) -> aws_sdk_ec2::types::Filter {
    aws_sdk_ec2::types::Filter::builder()
        .name(name)
        .values(value)
        .build()
}

/// Count the ENIs attached to a VPC — the "is anything running here" signal.
async fn count_enis(ec2: &aws_sdk_ec2::Client, vpc_id: &str) -> anyhow::Result<usize> {
    let resp = ec2
        .describe_network_interfaces()
        .filters(vpc_filter("vpc-id", vpc_id))
        .send()
        .await
        .context("DescribeNetworkInterfaces failed")?;
    Ok(resp.network_interfaces().len())
}

/// Tear down a VPC's deletable dependencies then the VPC itself, in the
/// order AWS requires: internet gateways, subnets, non-main route tables,
/// non-default NACLs, non-default security groups, then the VPC. Subnets go
/// before route tables / NACLs so their associations clear first.
async fn teardown_vpc(ec2: &aws_sdk_ec2::Client, vpc_id: &str) -> anyhow::Result<()> {
    // VPC endpoints first — gateway endpoints (e.g. the S3 endpoint every
    // failed apply of this tf.json leaves behind) hold a route-table and the
    // VPC, so they must go before either. DeleteVpcEndpoints takes a batch.
    let eps = ec2
        .describe_vpc_endpoints()
        .filters(vpc_filter("vpc-id", vpc_id))
        .send()
        .await
        .context("DescribeVpcEndpoints failed")?;
    let ep_ids: Vec<String> = eps
        .vpc_endpoints()
        .iter()
        .filter_map(|e| e.vpc_endpoint_id().map(str::to_owned))
        .collect();
    if !ep_ids.is_empty() {
        ec2.delete_vpc_endpoints()
            .set_vpc_endpoint_ids(Some(ep_ids.clone()))
            .send()
            .await
            .context("DeleteVpcEndpoints failed")?;
        for id in &ep_ids {
            info!("  deleted vpc-endpoint {id}");
        }
    }

    let igws = ec2
        .describe_internet_gateways()
        .filters(vpc_filter("attachment.vpc-id", vpc_id))
        .send()
        .await
        .context("DescribeInternetGateways failed")?;
    for ig in igws.internet_gateways() {
        if let Some(id) = ig.internet_gateway_id() {
            ec2.detach_internet_gateway()
                .internet_gateway_id(id)
                .vpc_id(vpc_id)
                .send()
                .await
                .with_context(|| format!("DetachInternetGateway {id}"))?;
            ec2.delete_internet_gateway()
                .internet_gateway_id(id)
                .send()
                .await
                .with_context(|| format!("DeleteInternetGateway {id}"))?;
            info!("  deleted internet-gateway {id}");
        }
    }

    let subnets = ec2
        .describe_subnets()
        .filters(vpc_filter("vpc-id", vpc_id))
        .send()
        .await
        .context("DescribeSubnets failed")?;
    for s in subnets.subnets() {
        if let Some(id) = s.subnet_id() {
            ec2.delete_subnet()
                .subnet_id(id)
                .send()
                .await
                .with_context(|| format!("DeleteSubnet {id}"))?;
            info!("  deleted subnet {id}");
        }
    }

    let rts = ec2
        .describe_route_tables()
        .filters(vpc_filter("vpc-id", vpc_id))
        .send()
        .await
        .context("DescribeRouteTables failed")?;
    for rt in rts.route_tables() {
        // The main route table cannot be deleted independently — it goes
        // with the VPC.
        let is_main = rt.associations().iter().any(|a| a.main() == Some(true));
        if is_main {
            continue;
        }
        if let Some(id) = rt.route_table_id() {
            ec2.delete_route_table()
                .route_table_id(id)
                .send()
                .await
                .with_context(|| format!("DeleteRouteTable {id}"))?;
            info!("  deleted route-table {id}");
        }
    }

    let nacls = ec2
        .describe_network_acls()
        .filters(vpc_filter("vpc-id", vpc_id))
        .send()
        .await
        .context("DescribeNetworkAcls failed")?;
    for na in nacls.network_acls() {
        if na.is_default() == Some(true) {
            continue;
        }
        if let Some(id) = na.network_acl_id() {
            ec2.delete_network_acl()
                .network_acl_id(id)
                .send()
                .await
                .with_context(|| format!("DeleteNetworkAcl {id}"))?;
            info!("  deleted network-acl {id}");
        }
    }

    let sgs = ec2
        .describe_security_groups()
        .filters(vpc_filter("vpc-id", vpc_id))
        .send()
        .await
        .context("DescribeSecurityGroups failed")?;
    for sg in sgs.security_groups() {
        if sg.group_name() == Some("default") {
            continue;
        }
        if let Some(id) = sg.group_id() {
            ec2.delete_security_group()
                .group_id(id)
                .send()
                .await
                .with_context(|| format!("DeleteSecurityGroup {id}"))?;
            info!("  deleted security-group {id}");
        }
    }

    ec2.delete_vpc()
        .vpc_id(vpc_id)
        .send()
        .await
        .with_context(|| format!("DeleteVpc {vpc_id}"))?;
    Ok(())
}

/// Entry point for the `reap-vpc` subcommand.
pub async fn run(args: ReapVpcArgs) -> anyhow::Result<()> {
    let config = match &args.profile {
        Some(p) => crate::aws::load_config_with_profile(&args.region, p).await,
        None => crate::aws::load_config(&args.region).await,
    };
    crate::aws::validate_credentials(&config).await?;
    let ec2 = aws_sdk_ec2::Client::new(&config);

    if args.apply {
        info!("=== APPLY MODE — matching orphan VPCs will be deleted ===");
    } else {
        info!("=== DRY RUN — pass --apply to delete ===");
    }
    info!(
        "targeting VPCs with Name={:?}, CIDR={}, 0 ENIs (keep-list: {:?})",
        args.name_tag, args.cidr, args.keep
    );

    let resp = ec2
        .describe_vpcs()
        .send()
        .await
        .context("DescribeVpcs failed")?;

    let mut reaped = 0usize;
    for vpc in resp.vpcs() {
        let Some(id) = vpc.vpc_id() else {
            warn!("skipping a VPC with no id in the API response");
            continue;
        };
        let name_tag = vpc
            .tags()
            .iter()
            .find(|t| t.key() == Some("Name"))
            .and_then(|t| t.value())
            .map(str::to_owned);
        let view = VpcView {
            id: id.to_string(),
            name_tag,
            cidr: vpc.cidr_block().unwrap_or_default().to_string(),
            is_default: vpc.is_default().unwrap_or(false),
            eni_count: count_enis(&ec2, id).await?,
        };

        match vpc_is_reapable(&view, &args.name_tag, &args.cidr, &args.keep) {
            ReapDecision::Skip(reason) => info!("skip {id} ({}): {reason}", view.cidr),
            ReapDecision::Reap => {
                if args.apply {
                    teardown_vpc(&ec2, id)
                        .await
                        .with_context(|| format!("tearing down orphan {id}"))?;
                    info!("reaped orphan VPC {id}");
                } else {
                    info!("WOULD reap orphan VPC {id} (0 ENIs, Name={:?}, {})", view.name_tag, view.cidr);
                }
                reaped += 1;
            }
        }
    }

    info!(
        "reap-vpc complete: {reaped} orphan VPC(s) {}",
        if args.apply { "deleted" } else { "identified (dry run)" }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(id: &str, name: Option<&str>, cidr: &str, is_default: bool, enis: usize) -> VpcView {
        VpcView {
            id: id.to_string(),
            name_tag: name.map(str::to_owned),
            cidr: cidr.to_string(),
            is_default,
            eni_count: enis,
        }
    }

    const NAME: &str = "camelot-eks-vpc";
    const CIDR: &str = "10.40.0.0/16";

    #[test]
    fn reaps_an_empty_matching_orphan() {
        let v = view("vpc-orphan", Some(NAME), CIDR, false, 0);
        assert_eq!(vpc_is_reapable(&v, NAME, CIDR, &[]), ReapDecision::Reap);
    }

    #[test]
    fn spares_a_vpc_with_enis_even_if_it_matches() {
        // An in-use VPC matches Name + CIDR but carries ENIs — the 0-ENI
        // gate is what protects it, independent of the keep-list.
        let v = view("vpc-live", Some(NAME), CIDR, false, 7);
        match vpc_is_reapable(&v, NAME, CIDR, &[]) {
            ReapDecision::Skip(r) => assert!(r.contains("7 ENI"), "reason: {r}"),
            ReapDecision::Reap => panic!("must never reap a VPC with ENIs"),
        }
    }

    #[test]
    fn spares_the_default_vpc() {
        // A default VPC would never carry the camelot Name tag, but the
        // is_default guard fires first regardless.
        let v = view("vpc-default", None, "172.31.0.0/16", true, 0);
        match vpc_is_reapable(&v, NAME, CIDR, &[]) {
            ReapDecision::Skip(r) => assert!(r.contains("default")),
            ReapDecision::Reap => panic!("must never reap the default VPC"),
        }
    }

    #[test]
    fn spares_a_keep_listed_vpc() {
        // Belt-and-suspenders: even an otherwise-reapable empty match is
        // spared when explicitly kept.
        let v = view("vpc-live", Some(NAME), CIDR, false, 0);
        let keep = vec!["vpc-live".to_string()];
        match vpc_is_reapable(&v, NAME, CIDR, &keep) {
            ReapDecision::Skip(r) => assert!(r.contains("keep-list")),
            ReapDecision::Reap => panic!("keep-list must win"),
        }
    }

    #[test]
    fn spares_a_wrong_name() {
        let v = view("vpc-other", Some("some-other-vpc"), CIDR, false, 0);
        assert!(matches!(
            vpc_is_reapable(&v, NAME, CIDR, &[]),
            ReapDecision::Skip(_)
        ));
    }

    #[test]
    fn spares_an_untagged_vpc() {
        let v = view("vpc-notag", None, CIDR, false, 0);
        assert!(matches!(
            vpc_is_reapable(&v, NAME, CIDR, &[]),
            ReapDecision::Skip(_)
        ));
    }

    #[test]
    fn spares_a_wrong_cidr() {
        let v = view("vpc-diff", Some(NAME), "10.99.0.0/16", false, 0);
        match vpc_is_reapable(&v, NAME, CIDR, &[]) {
            ReapDecision::Skip(r) => assert!(r.contains("CIDR")),
            ReapDecision::Reap => panic!("wrong CIDR must be spared"),
        }
    }
}
