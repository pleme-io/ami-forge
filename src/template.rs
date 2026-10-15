#![allow(clippy::missing_errors_doc)]

use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

const REQUIRED_PLUGIN_SOURCE: &str = "github.com/hashicorp/amazon";
const REQUIRED_PLUGIN_VERSION: &str = ">= 1.3.0";
const DEFAULT_SOURCE_AMI_NAME: &str = "nixos/25.*";
const DEFAULT_SOURCE_AMI_OWNER: &str = "427812963091";
const TEST_TTL_HOURS: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateError {
    BothPathAndSpec {
        which: &'static str,
    },
    NeitherPathNorSpec {
        which: &'static str,
    },
    EmptyArgv,
    EmptyProvisioners {
        which: &'static str,
    },
    EmptyCommands,
    InvalidIdentifier(String),
    GoTemplateDelimiter(String),
    UndeclaredVariable {
        variable: String,
        which: &'static str,
    },
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BothPathAndSpec { which } => write!(
                f,
                "{which}: `{which}_template` and `{which}_spec` are mutually exclusive; name exactly one"
            ),
            Self::NeitherPathNorSpec { which } => write!(
                f,
                "{which}: one of `{which}_template` (a rendered template path) or `{which}_spec` (a typed spec) is required"
            ),
            Self::EmptyArgv => write!(f, "a command argv must name at least a program"),
            Self::EmptyProvisioners { which } => {
                write!(
                    f,
                    "{which}_spec: `provisioners` must hold at least one provisioner"
                )
            }
            Self::EmptyCommands => write!(f, "a provisioner must hold at least one command"),
            Self::InvalidIdentifier(s) => write!(
                f,
                "`{s}` is not a valid identifier (expected [A-Za-z_][A-Za-z0-9_]*)"
            ),
            Self::GoTemplateDelimiter(s) => write!(
                f,
                "`{s}` contains `{{{{`, which packer reads as a Go template action; pass it as a command argument instead"
            ),
            Self::UndeclaredVariable { variable, which } => write!(
                f,
                "{which}_spec: environment var references `var.{variable}`, which the {which} template does not declare"
            ),
        }
    }
}

impl std::error::Error for TemplateError {}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Ident(String);

impl TryFrom<String> for Ident {
    type Error = TemplateError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        let mut chars = s.chars();
        let head_ok = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
        if head_ok && chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            Ok(Self(s))
        } else {
            Err(TemplateError::InvalidIdentifier(s))
        }
    }
}

impl Ident {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Arg {
    Literal(String),
    Env { env: Ident },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "Vec<Arg>")]
pub struct Argv(Vec<Arg>);

impl TryFrom<Vec<Arg>> for Argv {
    type Error = TemplateError;
    fn try_from(v: Vec<Arg>) -> Result<Self, Self::Error> {
        if v.is_empty() {
            Err(TemplateError::EmptyArgv)
        } else {
            Ok(Self(v))
        }
    }
}

impl Argv {
    #[must_use]
    pub fn render_shell(&self) -> String {
        self.0
            .iter()
            .map(|a| match a {
                Arg::Literal(s) => shell_quote(s),
                Arg::Env { env } => format!("\"${}\"", env.as_str()),
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Placeholder {
    Vars,
    Path,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ExecArg {
    Literal(String),
    Placeholder { placeholder: Placeholder },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum EnvVar {
    Literal { name: Ident, value: String },
    Var { name: Ident, var: Ident },
}

impl EnvVar {
    fn render(&self) -> Result<String, TemplateError> {
        Ok(match self {
            Self::Literal { name, value } => {
                format!("{}={}", name.as_str(), packer_literal(value)?)
            }
            Self::Var { name, var } => format!("{}=${{var.{}}}", name.as_str(), var.as_str()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provisioner {
    pub commands: Vec<Argv>,
    #[serde(default)]
    pub environment_vars: Vec<EnvVar>,
    #[serde(default)]
    pub expect_disconnect: bool,
    #[serde(default)]
    pub execute_command: Option<Vec<ExecArg>>,
}

impl Provisioner {
    fn render(
        &self,
        standard_env: &[String],
        declared: &[&str],
        which: &'static str,
    ) -> Result<Value, TemplateError> {
        if self.commands.is_empty() {
            return Err(TemplateError::EmptyCommands);
        }
        for e in &self.environment_vars {
            if let EnvVar::Var { var, .. } = e
                && !declared.contains(&var.as_str())
            {
                return Err(TemplateError::UndeclaredVariable {
                    variable: var.as_str().to_owned(),
                    which,
                });
            }
        }
        let inline: Vec<String> = self.commands.iter().map(Argv::render_shell).collect();
        let env: Vec<String> = standard_env
            .iter()
            .cloned()
            .map(Ok)
            .chain(self.environment_vars.iter().map(EnvVar::render))
            .collect::<Result<_, _>>()?;
        let mut shell = Map::new();
        shell.insert("inline".into(), json!(inline));
        if !env.is_empty() {
            shell.insert("environment_vars".into(), json!(env));
        }
        shell.insert("expect_disconnect".into(), json!(self.expect_disconnect));
        if let Some(ref exec) = self.execute_command {
            shell.insert(
                "execute_command".into(),
                json!(render_execute_command(exec)),
            );
        }
        Ok(json!({ "shell": Value::Object(shell) }))
    }
}

fn render_execute_command(exec: &[ExecArg]) -> String {
    exec.iter()
        .map(|a| match a {
            ExecArg::Literal(s) => shell_quote(s),
            ExecArg::Placeholder {
                placeholder: Placeholder::Vars,
            } => "{{.Vars}}".to_owned(),
            ExecArg::Placeholder {
                placeholder: Placeholder::Path,
            } => "{{.Path}}".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[must_use]
pub fn shell_quote(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c));
    if safe {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', "'\\''").replace('{', "''{"))
    }
}

#[must_use]
pub fn hcl_escape(s: &str) -> String {
    s.replace("${", "$${").replace("%{", "%%{")
}

pub fn packer_literal(s: &str) -> Result<String, TemplateError> {
    if s.contains("{{") {
        Err(TemplateError::GoTemplateDelimiter(s.to_owned()))
    } else {
        Ok(hcl_escape(s))
    }
}

#[must_use]
pub fn is_inert(s: &str) -> bool {
    !(s.contains("${") || s.contains("%{") || s.contains("{{"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
pub enum Architecture {
    #[default]
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "arm64")]
    Arm64,
}

impl Architecture {
    fn ami_architecture(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Arm64 => "arm64",
        }
    }
    fn build_instance(self) -> &'static str {
        match self {
            Self::X86_64 => "c7i.4xlarge",
            Self::Arm64 => "c7g.4xlarge",
        }
    }
    fn test_instance(self) -> &'static str {
        match self {
            Self::X86_64 => "t3.medium",
            Self::Arm64 => "t4g.medium",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpTokens {
    Required,
    Optional,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Imds {
    pub http_tokens: HttpTokens,
    #[serde(default = "default_hop_limit")]
    pub http_put_response_hop_limit: u8,
    #[serde(default)]
    pub ami_imds_support_v2: bool,
}

fn default_hop_limit() -> u8 {
    1
}

impl Imds {
    fn apply(&self, source: &mut Map<String, Value>) {
        source.insert(
            "metadata_options".into(),
            json!({
                "http_endpoint": "enabled",
                "http_tokens": match self.http_tokens {
                    HttpTokens::Required => "required",
                    HttpTokens::Optional => "optional",
                },
                "http_put_response_hop_limit": self.http_put_response_hop_limit,
            }),
        );
        if self.ami_imds_support_v2 {
            source.insert("imds_support".into(), json!("v2.0"));
        }
    }
}

fn default_region() -> String {
    "us-east-1".into()
}
fn default_owner() -> String {
    "platform".into()
}
fn default_environment() -> String {
    "dev".into()
}
fn default_volume_size() -> u32 {
    30
}
fn default_iops() -> u32 {
    8000
}
fn default_throughput() -> u32 {
    500
}
fn default_ttl_hours() -> u32 {
    4
}
fn default_source_ami_name() -> String {
    DEFAULT_SOURCE_AMI_NAME.into()
}
fn default_source_ami_owners() -> Vec<String> {
    vec![DEFAULT_SOURCE_AMI_OWNER.into()]
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildSpec {
    pub ami_name: String,
    pub flake_ref: String,
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default)]
    pub architecture: Architecture,
    #[serde(default)]
    pub instance_type: Option<String>,
    #[serde(default = "default_volume_size")]
    pub volume_size: u32,
    #[serde(default = "default_iops")]
    pub iops: u32,
    #[serde(default = "default_throughput")]
    pub throughput: u32,
    #[serde(default = "default_source_ami_name")]
    pub source_ami_name: String,
    #[serde(default)]
    pub source_ami_filters: BTreeMap<String, String>,
    #[serde(default = "default_source_ami_owners")]
    pub source_ami_owners: Vec<String>,
    #[serde(default)]
    pub substituter_url: String,
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours: u32,
    pub nix_build_opts: String,
    #[serde(default = "default_owner")]
    pub owner: String,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default = "default_environment")]
    pub environment: String,
    #[serde(default)]
    pub extra_tags: BTreeMap<String, String>,
    #[serde(default)]
    pub imds: Option<Imds>,
    pub provisioners: Vec<Provisioner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestSpec {
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default)]
    pub architecture: Architecture,
    #[serde(default)]
    pub instance_type: Option<String>,
    #[serde(default)]
    pub user_data: Option<String>,
    #[serde(default = "default_owner")]
    pub owner: String,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default = "default_environment")]
    pub environment: String,
    #[serde(default)]
    pub imds: Option<Imds>,
    pub provisioners: Vec<Provisioner>,
}

fn finops_tags(
    owner: &str,
    purpose: &str,
    environment: &str,
    ephemeral_ttl: Option<u32>,
) -> Result<BTreeMap<String, String>, TemplateError> {
    let mut t = BTreeMap::new();
    t.insert("Owner".into(), packer_literal(owner)?);
    t.insert("Purpose".into(), packer_literal(purpose)?);
    t.insert("ManagedBy".into(), "pangea".into());
    t.insert("Environment".into(), packer_literal(environment)?);
    t.insert(
        "Ephemeral".into(),
        if ephemeral_ttl.is_some() {
            "true"
        } else {
            "false"
        }
        .into(),
    );
    if let Some(ttl) = ephemeral_ttl {
        t.insert("TtlHours".into(), ttl.to_string());
    }
    Ok(t)
}

fn source_defaults() -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("ssh_username".into(), json!("root"));
    m.insert("ssh_timeout".into(), json!("10m"));
    m.insert("shutdown_behavior".into(), json!("terminate"));
    m.insert("temporary_key_pair_type".into(), json!("ed25519"));
    m.insert("ssh_clear_authorized_keys".into(), json!(true));
    m.insert("associate_public_ip_address".into(), json!(true));
    m
}

fn required_plugins() -> Value {
    json!({ "required_plugins": { "amazon": {
        "source": REQUIRED_PLUGIN_SOURCE,
        "version": REQUIRED_PLUGIN_VERSION,
    }}})
}

fn render_provisioners(
    provisioners: &[Provisioner],
    standard_env: &[String],
    declared: &[&str],
    which: &'static str,
) -> Result<Vec<Value>, TemplateError> {
    if provisioners.is_empty() {
        return Err(TemplateError::EmptyProvisioners { which });
    }
    provisioners
        .iter()
        .map(|p| p.render(standard_env, declared, which))
        .collect()
}

#[must_use]
pub fn self_destruct_user_data(ttl_hours: u32) -> String {
    format!(
        "#!/bin/sh\nsystemd-run --on-active={ttl_hours}h --unit=ami-forge-ttl-guard systemctl poweroff\n"
    )
}

const BUILD_VARIABLES: &[&str] = &[
    "ami_name",
    "region",
    "instance_type",
    "volume_size",
    "github_token",
    "flake_ref",
    "attic_url",
];
const TEST_VARIABLES: &[&str] = &["source_ami", "region"];

impl BuildSpec {
    pub fn render(&self) -> Result<Value, TemplateError> {
        let instance_type = self
            .instance_type
            .clone()
            .unwrap_or_else(|| self.architecture.build_instance().to_owned());
        let purpose = self
            .purpose
            .clone()
            .unwrap_or_else(|| format!("NixOS base AMI build for {}", self.ami_name));

        let mut filters = BTreeMap::new();
        filters.insert("virtualization-type".to_owned(), "hvm".to_owned());
        filters.insert("root-device-type".to_owned(), "ebs".to_owned());
        filters.insert("name".to_owned(), hcl_escape(&self.source_ami_name));
        filters.insert(
            "architecture".to_owned(),
            self.architecture.ami_architecture().to_owned(),
        );
        for (k, v) in &self.source_ami_filters {
            filters.insert(k.clone(), hcl_escape(v));
        }

        let mut tags = BTreeMap::new();
        tags.insert("Name".to_owned(), "${var.ami_name}".to_owned());
        tags.insert("BuildTimestamp".to_owned(), "{{timestamp}}".to_owned());
        tags.insert("SourceFlake".to_owned(), "${var.flake_ref}".to_owned());
        tags.extend(finops_tags(&self.owner, &purpose, &self.environment, None)?);
        for (k, v) in &self.extra_tags {
            tags.insert(k.clone(), packer_literal(v)?);
        }

        let mut run_tags = BTreeMap::new();
        run_tags.insert("Name".to_owned(), "ami-forge-builder".to_owned());
        run_tags.insert("ami-forge:purpose".to_owned(), "ami-build".to_owned());
        run_tags.insert("ami-forge:ttl-hours".to_owned(), self.ttl_hours.to_string());
        run_tags.extend(finops_tags(
            &self.owner,
            &purpose,
            &self.environment,
            Some(self.ttl_hours),
        )?);

        let mut source = source_defaults();
        source.insert("ami_name".into(), json!("${var.ami_name}"));
        source.insert("region".into(), json!("${var.region}"));
        source.insert("instance_type".into(), json!("${var.instance_type}"));
        source.insert(
            "source_ami_filter".into(),
            json!({
                "filters": filters,
                "owners": self.source_ami_owners.iter().map(|o| hcl_escape(o)).collect::<Vec<_>>(),
                "most_recent": true,
            }),
        );
        source.insert(
            "launch_block_device_mappings".into(),
            json!([{
                "device_name": "/dev/xvda",
                "volume_size": "${var.volume_size}",
                "volume_type": "gp3",
                "iops": self.iops,
                "throughput": self.throughput,
                "delete_on_termination": true,
            }]),
        );
        source.insert("force_deregister".into(), json!(true));
        source.insert("force_delete_snapshot".into(), json!(true));
        source.insert("tags".into(), json!(tags));
        source.insert("run_tags".into(), json!(run_tags));
        source.insert(
            "user_data".into(),
            json!(self_destruct_user_data(self.ttl_hours)),
        );
        if let Some(ref imds) = self.imds {
            imds.apply(&mut source);
        }

        let standard_env = vec![
            "GITHUB_TOKEN=${var.github_token}".to_owned(),
            "FLAKE_REF=${var.flake_ref}".to_owned(),
            "ATTIC_URL=${var.attic_url}".to_owned(),
            format!("NIX_BUILD_OPTS={}", packer_literal(&self.nix_build_opts)?),
        ];
        let provisioner =
            render_provisioners(&self.provisioners, &standard_env, BUILD_VARIABLES, "build")?;

        Ok(json!({
            "variable": {
                "ami_name": { "type": "string", "default": hcl_escape(&self.ami_name) },
                "region": { "type": "string", "default": hcl_escape(&self.region) },
                "instance_type": { "type": "string", "default": hcl_escape(&instance_type) },
                "volume_size": { "type": "number", "default": self.volume_size },
                "github_token": { "type": "string", "default": "", "sensitive": true },
                "flake_ref": { "type": "string", "default": hcl_escape(&self.flake_ref) },
                "attic_url": { "type": "string", "default": hcl_escape(&self.substituter_url) },
            },
            "packer": required_plugins(),
            "source": { "amazon-ebs": { "nixos": Value::Object(source) } },
            "build": [{
                "sources": ["source.amazon-ebs.nixos"],
                "provisioner": provisioner,
                "post-processor": { "manifest": {
                    "output": "packer-manifest.json",
                    "strip_path": true,
                }},
            }],
        }))
    }
}

impl TestSpec {
    pub fn render(&self) -> Result<Value, TemplateError> {
        let instance_type = self
            .instance_type
            .clone()
            .unwrap_or_else(|| self.architecture.test_instance().to_owned());
        let purpose = self
            .purpose
            .clone()
            .unwrap_or_else(|| "AMI validation test instance".to_owned());

        let mut run_tags = BTreeMap::new();
        run_tags.insert("Name".to_owned(), "ami-forge-test".to_owned());
        run_tags.insert("ami-forge:purpose".to_owned(), "ami-test".to_owned());
        run_tags.insert("ami-forge:ttl-hours".to_owned(), TEST_TTL_HOURS.to_string());
        run_tags.extend(finops_tags(
            &self.owner,
            &purpose,
            &self.environment,
            Some(TEST_TTL_HOURS),
        )?);

        let mut source = source_defaults();
        source.insert("ami_name".into(), json!("ami-forge-test-{{timestamp}}"));
        source.insert("region".into(), json!("${var.region}"));
        source.insert("instance_type".into(), json!(hcl_escape(&instance_type)));
        source.insert("source_ami".into(), json!("${var.source_ami}"));
        source.insert("skip_create_ami".into(), json!(true));
        source.insert("run_tags".into(), json!(run_tags));
        if let Some(ref ud) = self.user_data {
            source.insert("user_data".into(), json!(packer_literal(ud)?));
        }
        if let Some(ref imds) = self.imds {
            imds.apply(&mut source);
        }

        let provisioner = render_provisioners(&self.provisioners, &[], TEST_VARIABLES, "test")?;

        Ok(json!({
            "variable": {
                "source_ami": { "type": "string" },
                "region": { "type": "string", "default": hcl_escape(&self.region) },
            },
            "packer": required_plugins(),
            "source": { "amazon-ebs": { "test": Value::Object(source) } },
            "build": [{
                "sources": ["source.amazon-ebs.test"],
                "provisioner": provisioner,
            }],
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateSource<S> {
    Path(PathBuf),
    Spec(Box<S>),
}

impl<S> TemplateSource<S> {
    pub fn resolve(
        path: Option<PathBuf>,
        spec: Option<S>,
        which: &'static str,
    ) -> Result<Self, TemplateError> {
        match (path, spec) {
            (Some(_), Some(_)) => Err(TemplateError::BothPathAndSpec { which }),
            (None, None) => Err(TemplateError::NeitherPathNorSpec { which }),
            (Some(p), None) => Ok(Self::Path(p)),
            (None, Some(s)) => Ok(Self::Spec(Box::new(s))),
        }
    }

    #[must_use]
    pub fn store_path(&self) -> Option<&Path> {
        match self {
            Self::Path(p) => Some(p.as_path()),
            Self::Spec(_) => None,
        }
    }
}

pub fn write_rendered(value: &Value, dir: &Path, file_name: &str) -> anyhow::Result<PathBuf> {
    use anyhow::Context as _;
    let path = dir.join(file_name);
    let body =
        serde_json::to_string_pretty(value).context("serializing rendered packer template")?;
    std::fs::write(&path, body)
        .with_context(|| format!("writing rendered packer template {}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng as _, SeedableRng as _};

    const CEU_BUILD_SPEC: &str = r#"
ami_name: pleme-ceu
flake_ref: "github:pleme-io/nix#ceu"
region: us-east-2
architecture: arm64
volume_size: 200
nix_build_opts: "--option max-jobs 8 --option cores 2"
owner: pleme-io
purpose: ceu akeyless relay AMI
provisioners:
  - expect_disconnect: false
    commands:
      - [kindling, ami-build, --flake, {env: FLAKE_REF}, --substituter, {env: ATTIC_URL}]
"#;

    const CEU_TEST_SPEC: &str = r"
region: us-east-2
architecture: arm64
owner: pleme-io
purpose: ceu AMI boot test
provisioners:
  - commands:
      - [kindling, ami-test]
";

    fn fixture(name: &str) -> Value {
        let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture")).expect("json")
    }

    fn without_provisioner(mut v: Value) -> Value {
        v["build"][0]
            .as_object_mut()
            .expect("build object")
            .remove("provisioner");
        v
    }

    #[test]
    fn build_spec_matches_substrate_template_except_provisioner() {
        let spec: BuildSpec = serde_yaml::from_str(CEU_BUILD_SPEC).expect("spec");
        let rendered = spec.render().expect("render");
        let golden = fixture("ceu-build-template.pkr.json");
        assert_eq!(
            without_provisioner(rendered.clone()),
            without_provisioner(golden.clone())
        );
        let r = &rendered["build"][0]["provisioner"][0]["shell"];
        let g = &golden["build"][0]["provisioner"][0]["shell"];
        assert_eq!(r["environment_vars"], g["environment_vars"]);
        assert_eq!(r["expect_disconnect"], g["expect_disconnect"]);
        assert_eq!(
            r["inline"],
            json!([r#"kindling ami-build --flake "$FLAKE_REF" --substituter "$ATTIC_URL""#])
        );
    }

    #[test]
    fn test_spec_matches_substrate_template_except_provisioner() {
        let spec: TestSpec = serde_yaml::from_str(CEU_TEST_SPEC).expect("spec");
        let rendered = spec.render().expect("render");
        assert_eq!(
            without_provisioner(rendered),
            without_provisioner(fixture("ceu-test-template.pkr.json"))
        );
    }

    #[test]
    fn path_and_spec_are_mutually_exclusive() {
        let both = TemplateSource::resolve(Some(PathBuf::from("/x")), Some(()), "build");
        assert_eq!(both, Err(TemplateError::BothPathAndSpec { which: "build" }));
        let neither = TemplateSource::<()>::resolve(None, None, "test");
        assert_eq!(
            neither,
            Err(TemplateError::NeitherPathNorSpec { which: "test" })
        );
    }

    #[test]
    fn empty_argv_and_bad_env_names_are_refused_at_parse() {
        assert!(serde_yaml::from_str::<Provisioner>("commands: [[]]").is_err());
        assert!(serde_yaml::from_str::<Provisioner>("commands: [[a, {env: 'A B'}]]").is_err());
        assert!(serde_yaml::from_str::<Provisioner>("commands: [[a]]\nshell: x").is_err());
    }

    #[test]
    fn undeclared_variable_reference_is_refused() {
        let spec: TestSpec = serde_yaml::from_str(
            "provisioners: [{commands: [[a]], environment_vars: [{name: T, var: github_token}]}]",
        )
        .expect("spec");
        assert!(matches!(
            spec.render(),
            Err(TemplateError::UndeclaredVariable { .. })
        ));
    }

    #[test]
    fn packer_interpolation_in_literals_is_inert() {
        let p: Provisioner = serde_yaml::from_str(
            r"
commands: [[sh, -c, 'echo ${GITHUB_TOKEN:+x} %{if}'], [echo, '{{timestamp}}']]
environment_vars: [{name: X, value: '${y}'}]
execute_command: [sudo, -E, {placeholder: vars}, sh, {placeholder: path}]
",
        )
        .expect("p");
        let v = p.render(&[], &[], "test").expect("render");
        assert_eq!(
            v["shell"]["inline"][0],
            json!("sh -c 'echo $''{GITHUB_TOKEN:+x} %''{if}'")
        );
        assert_eq!(v["shell"]["inline"][1], json!("echo '''{''{timestamp}}'"));
        assert_eq!(v["shell"]["environment_vars"][0], json!("X=$${y}"));
        assert_eq!(
            v["shell"]["execute_command"],
            json!("sudo -E {{.Vars}} sh {{.Path}}")
        );
        let go: Provisioner =
            serde_yaml::from_str("commands: [[a]]\nenvironment_vars: [{name: X, value: '{{x}}'}]")
                .expect("p");
        assert!(matches!(
            go.render(&[], &[], "test"),
            Err(TemplateError::GoTemplateDelimiter(_))
        ));
    }

    fn sh_argv(line: &str) -> Vec<String> {
        let out = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("printf '%s\\0' {line}"))
            .output()
            .expect("sh");
        assert!(out.status.success());
        let mut parts: Vec<String> = out
            .stdout
            .split(|b| *b == 0)
            .map(|b| String::from_utf8(b.to_vec()).expect("utf8"))
            .collect();
        parts.pop();
        parts
    }

    fn nasty_string(rng: &mut rand::rngs::StdRng) -> String {
        const ALPHABET: &[&str] = &[
            "${", "%{", "{{", "}}", "$", "{", "}", "'", "\"", " ", "\\", "\t", "\n", "`", "*", "?",
            "~", "#", ";", "&", "|", "<", ">", "(", ")", "!", "a", "Z", "0", "-", "=", "é",
            "${A:+b}",
        ];
        let len = rng.random_range(0..12);
        (0..len)
            .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())])
            .collect()
    }

    #[test]
    fn quoted_argv_round_trips_through_sh() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x00a1_f0e9);
        for _ in 0..400 {
            let n = rng.random_range(1..5);
            let args: Vec<String> = (0..n).map(|_| nasty_string(&mut rng)).collect();
            let rendered = Argv(args.iter().cloned().map(Arg::Literal).collect()).render_shell();
            assert!(is_inert(&rendered), "{rendered}");
            assert_eq!(sh_argv(&rendered), args, "line: {rendered}");
        }
    }

    fn packer() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("AMI_FORGE_TEST_PACKER") {
            return Some(PathBuf::from(p));
        }
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .map(|d| d.join("packer"))
            .find(|p| p.is_file())
    }

    #[test]
    fn rendered_templates_pass_packer_syntax_validation() {
        let Some(packer) = packer() else {
            eprintln!(
                "skipping: packer not found (set AMI_FORGE_TEST_PACKER or put packer on PATH)"
            );
            return;
        };
        let mut build: BuildSpec = serde_yaml::from_str(CEU_BUILD_SPEC).expect("spec");
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let nasty: Vec<Arg> = (0..40)
            .map(|_| Arg::Literal(nasty_string(&mut rng)))
            .collect();
        build.provisioners[0].commands.push(Argv(
            std::iter::once(Arg::Literal("printf".into()))
                .chain(nasty)
                .collect(),
        ));
        build.provisioners[0].commands.push(Argv(vec![
            Arg::Literal("sh".into()),
            Arg::Literal("-c".into()),
            Arg::Literal(
                "echo ${GITHUB_TOKEN:+--option access-tokens github.com=$GITHUB_TOKEN}".into(),
            ),
        ]));
        let test: TestSpec = serde_yaml::from_str(CEU_TEST_SPEC).expect("spec");
        let dir = tempfile::tempdir().expect("tmp");
        for (name, v) in [
            ("build.pkr.json", build.render().expect("render")),
            ("test.pkr.json", test.render().expect("render")),
        ] {
            let path = write_rendered(&v, dir.path(), name).expect("write");
            let out = std::process::Command::new(&packer)
                .args(["validate", "-syntax-only"])
                .arg(&path)
                .output()
                .expect("packer");
            assert!(
                out.status.success(),
                "{name}: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    fn local_template(inline: &Value) -> Value {
        json!({
            "source": { "null": { "local": { "communicator": "none" } } },
            "build": [{
                "sources": ["source.null.local"],
                "provisioner": [{ "shell-local": { "inline": inline } }],
            }],
        })
    }

    fn packer_run(packer: &Path, verb: &str, template: &Value, dir: &Path) -> std::process::Output {
        let path = write_rendered(template, dir, "local.pkr.json").expect("write");
        std::process::Command::new(packer)
            .arg(verb)
            .arg(&path)
            .env("PACKER_PLUGIN_PATH", dir.join("plugins"))
            .env("CHECKPOINT_DISABLE", "1")
            .current_dir(dir)
            .output()
            .expect("packer")
    }

    #[test]
    fn packer_full_validate_rejects_raw_interpolation_and_accepts_rendered() {
        let Some(packer) = packer() else {
            eprintln!("skipping: packer not found");
            return;
        };
        let dir = tempfile::tempdir().expect("tmp");
        let raw = packer_run(
            &packer,
            "validate",
            &local_template(&json!(["echo ${GITHUB_TOKEN:+x}"])),
            dir.path(),
        );
        assert!(
            !raw.status.success(),
            "packer accepted a raw ${{: this check proves nothing"
        );
        let argv = Argv(vec![
            Arg::Literal("echo".into()),
            Arg::Literal("${GITHUB_TOKEN:+x}".into()),
        ]);
        let ok = packer_run(
            &packer,
            "validate",
            &local_template(&json!([argv.render_shell()])),
            dir.path(),
        );
        assert!(
            ok.status.success(),
            "{}",
            String::from_utf8_lossy(&ok.stdout)
        );
    }

    #[test]
    fn packer_executes_rendered_argv_exactly() {
        let Some(packer) = packer() else {
            eprintln!("skipping: packer not found");
            return;
        };
        let dir = tempfile::tempdir().expect("tmp");
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5eed);
        let cases: Vec<Vec<String>> = (0..40)
            .map(|_| {
                let n = rng.random_range(1..6);
                (0..n).map(|_| nasty_string(&mut rng)).collect()
            })
            .collect();
        let commands: Vec<Argv> = cases
            .iter()
            .enumerate()
            .map(|(i, args)| {
                let out = dir.path().join(format!("case-{i}"));
                let mut v = vec![
                    Arg::Literal("sh".into()),
                    Arg::Literal("-c".into()),
                    Arg::Literal("printf '%s\\0' \"$@\" > \"$0\"".into()),
                    Arg::Literal(out.to_string_lossy().into_owned()),
                ];
                v.extend(args.iter().cloned().map(Arg::Literal));
                Argv(v)
            })
            .collect();
        let p = Provisioner {
            commands,
            environment_vars: vec![],
            expect_disconnect: false,
            execute_command: None,
        };
        let rendered = p.render(&[], &[], "test").expect("render");
        let out = packer_run(
            &packer,
            "build",
            &local_template(&rendered["shell"]["inline"]),
            dir.path(),
        );
        assert!(
            out.status.success(),
            "{}{}\ninline: {:#}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
            rendered["shell"]["inline"]
        );
        for (i, args) in cases.iter().enumerate() {
            let bytes = std::fs::read(dir.path().join(format!("case-{i}"))).expect("case output");
            let mut got: Vec<String> = bytes
                .split(|b| *b == 0)
                .map(|b| String::from_utf8(b.to_vec()).expect("utf8"))
                .collect();
            got.pop();
            assert_eq!(&got, args, "case {i}");
        }
    }
}
