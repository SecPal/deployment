<!-- SPDX-FileCopyrightText: 2026 SecPal Contributors -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

# Fedora CoreOS provisioning foundation

Fedora CoreOS Stable is the primary Managed host reference under ADR-017/018/021.
This portable foundation prepares non-secret installation inputs. It cannot
inspect a provider, select a disk, activate a workload or install a host.
Historical Rocky qualification remains version-bound evidence; it does not
admit FCOS. Self-Hosted portability does not require FCOS.

## Maintained artifacts and authority

`config/fcos/artifacts.json` retains the accepted FCOS Stable release and the
architecture-specific Metal image digests for x86_64 and aarch64. Butane,
Ignition validation and the official coreos-installer OCI index/native child
manifests are pinned. Resolve neither `latest` nor a moving stream during an
installation. Verify each complete Metal image SHA-256 and detached Fedora
signature against the exact pinned full signer fingerprint, authenticated from
[Fedora Security](https://fedoraproject.org/security/).

`python3 scripts/verify_fcos_artifacts.py /private/verified-cache` checks local
cached images and preparation tools with a temporary GnuPG home. It never
changes host package/key databases. Its installer-index check proves only that
index digest: native child/blob and publisher admission remain separately
required before installation. An existing accepted signature/artifact record
can be reused while its bytes, pins, signer authority and verification inputs
are unchanged. A prompt, issue or another host cycle is not an invalidator.

The base introduces no additional VPN, package layer, enrollment service or
identity database. Reuse the already qualified native NetworkManager WireGuard
and restricted peer-generation lifecycle. Existing management identities,
address reservations, provider inventory and authorization policy remain outside
public Git. No NetBird setup key or alternate VPN is added by this renderer.

## Non-secret Butane and Ignition

`scripts/fcos_prepare.py` separates pure input admission/rendering from its
local-file CLI. Its exact settings are architecture, fresh installation ID,
hostname, approved Ed25519 public bootstrap key, observed MAC, IPv4/prefix/gateway,
IPv6/prefix/gateway and DNS server addresses. Extra fields, private keys,
credentials and arbitrary commands are rejected. The CLI creates a new output
file; it does not overwrite an existing installation input.

Render outside Git and validate the exact bytes with the pinned tools:

```sh
python3 scripts/fcos_prepare.py --settings /private/host-settings.json --output /private/host.bu.json
/verified/butane --strict --pretty /private/host.bu.json > /private/host.ign
/verified/ignition-validate /private/host.ign
```

JSON is valid Butane YAML. `--fixture x86_64` and `--fixture aarch64` use
synthetic keys and documentation addresses. Syntax validation is not target,
network, key or installation authorization.

The rootless account UID/GID and sub-ID ranges derive from the existing
`config/production/state-contract.json` owner. The generated host has a non-login
runtime account, lingering, administrator-owned Quadlet directory, external
`/srv` state, MAC-bound dual-stack NetworkManager, passwordless SSH and SELinux
Enforcing. Actual workload activation still requires canonical image, authority,
user-manager, namespace and persistent-label admission. Rendering does not prove
that any container runs or that a database is durable.

The renderer preserves the rebuild-qualified FirstBoot behavior: write
`uninitialized` to `/etc/machine-id` and supply the fresh nonzero identity via
`systemd.machine_id=`. Prefilling the final machine-id suppresses native systemd
FirstBoot/presets and must not return. The installation marker and eventual
machine-id must agree. A complete reinstall generates fresh SSH/WireGuard host
keys; an ordinary reboot preserves them.

Zincati is explicitly disabled during controlled qualification. Production
update/reboot authorization, rolling order, health admission and rollback remain
owned by the existing lifecycle and HA contracts; a time window alone does not
prove coordinated availability.

## Installation and bootstrap composition

Compose the existing mechanisms; do not add a workflow engine or privileged
arbitrary-command endpoint:

1. Independently protected provider custody and exact immutable-ID/type/CPU/IP
   read-back admit one authorized guest operation. Both delete and rebuild
   protection remain enabled. Retained provider resources cannot be deleted,
   replaced, returned or swept by an ephemeral-resource cleanup mechanism.
2. Enable Rescue and reboot only the admitted guest. Authenticate its fresh SSH
   host identity through the established provider Console/bootstrap authority.
   `ssh-keyscan` or an expected IP alone is not authentication. Never use
   `StrictHostKeyChecking=no`.
3. Observe the actual disk, size, sector size, mounts, boot mode, NIC and network
   facts. Bind them, verified image/installer identities, Ignition hash and fresh
   installation ID before any disk write. Do not guess a previous device name.
4. Run only the official native coreos-installer on that admitted guest disk.
   No provider rebuild, replacement resource or protection change is needed.
5. Authenticate the new SSH host key through the controlled bootstrap path;
   verify FCOS version/CPU, Ignition, machine-id, SELinux, underlay IPv4/IPv6 and
   DNS before direct peer registration.
6. Generate the WireGuard private key locally on the target. Retrieve only its
   public key through authenticated bootstrap and bind it to this installation.
   Existing restricted compare-and-swap registration replaces only its reserved
   slot, retires predecessor authority and preserves protected management peers.
7. Prove direct handshake, transfer counters, IPv4/IPv6 SSH with strict host-key
   authentication, split routes, unchanged DNS/defaults and no hub data relay.
   Independently check firewall rejection; timeout alone is not isolation proof.
8. Verify actual rootless Podman/Quadlet, mappings, pinned native OCI image,
   read-only root filesystem, least capabilities, non-host networking, external
   state and SELinux. Reboot once; require unchanged installation/SSH/WireGuard
   identities, automatic reconnection and persistent workload data.
9. Read back provider identity, primary IPs and protections, then record accepted
   installation/generation. Do not retry a partially replaced peer blindly.

Host Enrollment and Workload Activation remain separate. This transport/bootstrap
contract grants no deployment, DDL, secret, backup-decryption or recovery authority.
Keep independent Rescue/Console access when WireGuard is unavailable.

## Evidence and current acceptance limits

Existing private FCOS rebuild and multiarch reports establish their exact guest
installations, artifacts, native CPU/boot modes, direct networking, SELinux,
rootless Quadlet, reboot and persistent test state. Keep raw inventory and proof
private; record source hashes and report references there. Reuse unchanged proof
rather than reformatting accepted hosts merely to republish source.

This source consolidation incorporates the proven machine-id correction and
removes the obsolete alternate-VPN preparation from the original candidate.
Its newly rendered bytes require strict Butane/Ignition validation. They must
not be represented as the exact Ignition previously installed on accepted hosts.
A changed installation template/configuration is an invalidator for that
configuration's installation proof, not for unrelated existing host observations.

The independently privileged provider broker is a separate capability. A
same-user guard plus an exposed unrestricted token cannot establish isolation.
Actual administrator-owned installation, protected fresh credential handoff,
read-only acceptance and safe old-token revocation remain live boundaries.
The provider broker has no general SSH, Console forwarding or disk-writing API;
installation-bound bootstrap must retain its independently reviewed authority.

PostgreSQL 18 container durability/credentials, HAProxy/CrowdSec placement,
Patroni/etcd fencing, Barman/WAL, RecoverySets and Managed SINGLE/HA/CONTINUITY
acceptance remain owned by their existing delivery contracts. A fixture, host
boot or local CI pass is not their real-system or production qualification.
