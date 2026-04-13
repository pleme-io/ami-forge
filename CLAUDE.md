# ami-forge

AMI build pipeline tool -- called by Packer provisioners and Nix-generated apps.
Rust CLI, all orchestration logic, no shell scripts.

---

## Subcommands

| Command | Called by | Purpose |
|---------|-----------|---------|
| `pipeline-run` | `nix run .#ami-build` | Full pipeline: build, extract, single-node test, cluster test, promote |
| `cluster-test` | `pipeline-run` | N-node EC2 integration test (YAML config): VPN peering + K3s cluster + kubectl |
| `boot-check` | Packer provisioner | Validate binaries and services on a running instance |
| `build` | Manual/CI | Upload nix disk image, import as AMI, tag, update SSM |
| `manifest-id` | `pipeline-run` | Parse packer-manifest.json, print AMI ID to stdout |
| `promote` | `pipeline-run` | Update SSM parameter with AMI ID |
| `reaper` | Scheduled/manual | Terminate expired instances + deregister stale AMIs (keep newest per group) |
| `rotate` | `pipeline-run` (on failure) | Deregister AMI by name, delete orphaned EBS snapshots |
| `status` | `nix run .#ami-status` | Show current AMI from SSM and EC2 metadata |
| `trigger` | CI/CD | Start a CodeBuild build, optionally wait for completion |

---

## Pipeline Phases (`pipeline-run`)

```
Phase 1: packer build (base NixOS → nixos-rebuild → kindling ami-build → snapshot)
Phase 2: Extract AMI ID from packer-manifest.json
Phase 3: packer build test template (boot AMI with test userdata → kindling ami-integration-test)
Phase 4: cluster-test (N EC2 instances from YAML config, VPN peering, K3s, kubectl) [optional]
Phase 5: Promote AMI to SSM parameter
```

On **any test failure** (phase 3 or 4), the AMI is deregistered via `rotate`
and the pipeline exits non-zero. No bad AMIs reach production.

---

## Cluster Test (`cluster-test`)

Config-driven N-node test. Node topology is defined in a YAML file (`--config`),
not hardcoded in Rust. The CLI takes `--config <path>` and `--ami-id <id>`.

**Config format** (`ClusterTestConfig`):
```yaml
cluster_name: cluster-test
instance_type: c7i.xlarge
timeout: 600
k3s_token: ami-forge-cluster-test-token
region: us-east-1  # optional, defaults to us-east-1
nodes:
  - name: cp
    role: server
    cluster_init: true
    vpn_address: "10.99.0.1/24"
    node_index: 0
  - name: worker1
    role: agent
    cluster_init: false
    vpn_address: "10.99.0.2/24"
    node_index: 1
checks:
  min_ready_nodes: 2
  min_vpn_handshakes: 1
  kubectl_from_client: false
```

**Pipeline integration** -- `pipeline-run` config uses optional `cluster_test.config`
reference instead of `skip_cluster_test` bool:
```yaml
cluster_test:
  config: /path/to/cluster-test.yaml
```

**Execution flow**:
1. Read YAML config, generate ephemeral WireGuard keypairs + PSK (x25519-dalek)
2. Create temporary EC2 keypair and security group
3. Launch CP instance (the node with `cluster_init: true`)
4. Wait for CP IPs, launch remaining nodes with CP's IP injected
5. Wait for SSH on CP (and client node if `kubectl_from_client: true`)
6. Validate via SSH polling (driven by `checks` config):
   - `kindling-init.service` completed
   - WireGuard interface configured
   - K3s cluster (`min_ready_nodes` nodes Ready)
   - VPN peering (`min_vpn_handshakes` handshakes)
   - kubectl namespaces (4+ default namespaces)
   - kubectl from client node (if `kubectl_from_client: true`)
7. **Always cleanup**: terminate instances, delete SG (with retry), delete keypair

All instances use `skip_nix_rebuild: true` -- the AMI already has the full NixOS
config. kindling-init provisions secrets, writes K3s config.yaml, and K3s auto-starts
via `Before=k3s.service` systemd ordering.

---

## Dual-Sentinel Role Selection

cluster-test generates userdata with `"role": "server"` for control plane nodes
and `"role": "agent"` for workers. On boot, kindling-init reads the role from
userdata and writes exactly one sentinel file:

- `/var/lib/kindling/server-mode` -- written when `role == "server"`
- `/var/lib/kindling/agent-mode` -- written when `role == "agent"`

The opposite sentinel is always removed to prevent stale state. If neither file
exists (e.g. during AMI build with no userdata), neither K3s service starts.

The blackmatter-kubernetes K3s NixOS module uses systemd `ConditionPathExists`
on these files: `k3s.service` has `ConditionPathExists=/var/lib/kindling/server-mode`
and `k3s-agent.service` has `ConditionPathExists=/var/lib/kindling/agent-mode`.
systemd evaluates the condition before the service starts, so the correct K3s
binary runs without any imperative `systemctl mask/enable` calls.

**Why this replaced `systemctl mask/enable`:** The old approach called
`systemctl mask k3s-agent && systemctl enable k3s` (or vice versa) during
kindling-init. This raced with systemd's own service ordering -- if systemd
tried to start k3s-agent.service before kindling-init had masked it, the wrong
service could launch. Sentinel files with `ConditionPathExists` are evaluated
atomically by systemd at service start time, eliminating the race.

---

## Orphan Prevention

Multiple layers prevent EC2 instances from being left running after a failed build:

1. **Packer `-on-error=cleanup`** -- All Packer build invocations include this flag.
   When a provisioner fails, Packer terminates the builder instance and deletes
   temporary resources instead of leaving the instance running for debugging.

2. **`instance_initiated_shutdown_behavior = "terminate"`** -- Attic cache instances
   (and cluster-test instances) are launched with shutdown-behavior set to terminate.
   If the OS shuts down for any reason, the instance self-destructs.

3. **TTL tags + reaper** -- Every instance launched by ami-forge gets two tags:
   - `ami-forge:ttl-hours`: "4" (maximum expected lifetime)
   - `ami-forge:expires-at`: ISO 8601 timestamp (UTC)

   The `reaper` subcommand scans for instances with expired TTL tags and terminates
   them. It also deregisters stale AMIs, keeping only the newest per name prefix.
   Run `ami-forge reaper` (or `--dry-run` first) to clean up orphaned resources.

4. **Cluster test cleanup** -- The cluster-test code path always runs cleanup
   (terminate instances, delete security group, delete keypair) regardless of
   whether the test passed or failed. SG deletion retries up to 5 times with
   backoff because instances may still be in "shutting-down" state.

---

## Diagnostic SSH Capture for Cluster Test Failures

When the K3s cluster check fails during `cluster-test`, ami-forge captures
diagnostic information from both the control plane and all agent nodes:

**Control plane diagnostics** (always captured on failure):
- `kubectl get nodes --no-headers`
- `journalctl -u k3s -n 20`

**Agent diagnostics** (captured from each non-CP node via SSH):
- `systemctl status k3s-agent.service`
- `journalctl -u k3s-agent -n 30`
- `/etc/rancher/k3s/config.yaml` contents

SSH sessions to agent nodes are established before running checks. If SSH is
not available on an agent, a warning is logged but diagnostics from other
nodes are still collected. All diagnostic output is included in the error
message when the check fails, making it possible to debug cluster formation
issues from the pipeline output alone.

---

## Error Handling

- AWS credentials validated **before** any Packer invocation (fail fast)
- `deregister_and_fail()`: on test failure, deregister AMI via `rotate`, clean up
  packer manifest, then bail with descriptive error
- Cluster test cleanup runs in all code paths (success, failure, panic via Drop-like pattern)
- SG deletion retries up to 5 times with backoff (instances may still be terminating)

---

## Key Design Decisions

1. **Packer orchestrates instances** -- SSH keys, instance lifecycle, cleanup.
   ami-forge is a tool that Packer/pipeline calls, not a Packer replacement.
2. **No shell for logic** -- All pipeline orchestration is Rust. Shell usage is
   limited to PATH setup and exec in the Nix-generated wrapper scripts.
3. **Single pipeline, always tested** -- `nix run .#ami-build` = build + test +
   promote. There is no "build without testing" path.
4. **Ephemeral WireGuard keys** -- Cluster test generates fresh x25519 keys per
   run. Test instances are destroyed after validation.

---

## Dependencies

- AWS SDK (ec2, ssm, sts, s3, codebuild) via rustls (no C deps)
- x25519-dalek for WireGuard key generation
- Packer (invoked as subprocess, not linked)
