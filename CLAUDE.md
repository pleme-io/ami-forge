# ami-forge

AMI build pipeline tool -- called by Packer provisioners and Nix-generated apps.
Rust CLI, all orchestration logic, no shell scripts.

---

## Subcommands

| Command | Called by | Purpose |
|---------|-----------|---------|
| `pipeline-run` | `nix run .#ami-build` | Full pipeline: build, extract, single-node test, cluster test, promote |
| `cluster-test` | `pipeline-run` | 2-node EC2 integration test: VPN peering + K3s cluster + kubectl |
| `boot-check` | Packer provisioner | Validate binaries and services on a running instance |
| `build` | Manual/CI | Upload nix disk image, import as AMI, tag, update SSM |
| `manifest-id` | `pipeline-run` | Parse packer-manifest.json, print AMI ID to stdout |
| `promote` | `pipeline-run` | Update SSM parameter with AMI ID |
| `rotate` | `pipeline-run` (on failure) | Deregister AMI by name, delete orphaned EBS snapshots |
| `status` | `nix run .#ami-status` | Show current AMI from SSM and EC2 metadata |
| `trigger` | CI/CD | Start a CodeBuild build, optionally wait for completion |

---

## Pipeline Phases (`pipeline-run`)

```
Phase 1: packer build (base NixOS → nixos-rebuild → kindling ami-build → snapshot)
Phase 2: Extract AMI ID from packer-manifest.json
Phase 3: packer build test template (boot AMI with test userdata → kindling ami-integration-test)
Phase 4: cluster-test (2 EC2 instances, VPN peering, K3s 2-node, kubectl) [skippable]
Phase 5: Promote AMI to SSM parameter
```

On **any test failure** (phase 3 or 4), the AMI is deregistered via `rotate`
and the pipeline exits non-zero. No bad AMIs reach production.

---

## Cluster Test (`cluster-test`)

Launches 2 EC2 instances from the built AMI with cross-referenced WireGuard keys:

1. Generate ephemeral WireGuard keypairs + PSK (x25519-dalek)
2. Create temporary EC2 keypair and security group
3. Launch CP instance with server userdata (`cluster_init: true`, `node_index: 0`)
4. Wait for CP IPs, launch worker (`cluster_init: false`, `node_index: 1`, `join_server: CP`)
5. Wait for SSH on CP
6. Validate via SSH polling:
   - `kindling-init.service` completed
   - WireGuard interface configured
   - K3s 2-node cluster (2+ nodes Ready)
   - VPN peering (WireGuard handshake between nodes)
   - kubectl namespaces (4+ default namespaces)
7. **Always cleanup**: terminate instances, delete SG (with retry), delete keypair

Both instances use `skip_nix_rebuild: true` -- the AMI already has the full NixOS
config. kindling-init provisions secrets, writes K3s config.yaml, and K3s auto-starts
via `Before=k3s.service` systemd ordering.

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
