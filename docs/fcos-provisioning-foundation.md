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

The pure `qualification(settings, lock)` helper prepares the existing disposable
rootless Quadlet fixture and persistent marker script. It selects the exact
native installer child digest already used for host qualification, uses
`Pull=never`, no network, a read-only root filesystem, no added privileges and
no Linux capabilities. Stage/admit that image in the runtime user's store before
using the fixture. Publish the unit only in its administrator-owned user Quadlet
directory and the script/state in the runtime-owned external qualification path.
The helper neither writes those files nor enables a unit. It is test workload
preparation, not product or database activation.

The system `multi-user.target` pulls in `network-online.target` so rootless
Quadlet's wait service can observe host network readiness. The guest reboot
proof checks this dependency through the ordinary boot path.

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

The independently privileged provider broker is administrator-installed and
has live read-only acceptance. Live mutation qualification, independently
authenticated Rescue bootstrap for the broker path and safe old-token
revocation remain separate acceptance boundaries.
The provider broker has no general SSH, Console forwarding or disk-writing API;
installation-bound bootstrap must retain its independently reviewed authority.

PostgreSQL 18 container durability/credentials, HAProxy/CrowdSec placement,
Patroni/etcd fencing, Barman/WAL, RecoverySets and Managed SINGLE/HA/CONTINUITY
acceptance remain owned by their existing delivery contracts. A fixture, host
boot or local CI pass is not their real-system or production qualification.

## Platform qualification plan

[SecPal/.github#1348](https://github.com/SecPal/.github/pull/1348) records the
accepted Managed reference. It uses FCOS Stable, SELinux Enforcing, rootless
Podman/Quadlet by default and PostgreSQL 18. Host Conformance, Host Enrollment
and Workload Activation are separate. Provider-specific inventory, access and
live Managed composition belong to the private operating environment.

The retained lab has evidence for x86_64 and aarch64 installations, two
successive rebuilds with peer replacement, direct WireGuard, rootless Quadlet
and state across reboot. The independent application PoC adds PostgreSQL 18
with TLS/SCRAM, separate frontend and API images, authenticated browser access
over private HTTPS, scoped cookies and a same-host logical restore. The operator
also verified the canonical application names from the workstation. These
observations qualify the exact tested installations and application inputs.
They do not establish qualification for different rendered bytes.

| Stage                        | Owned work and advancement criterion                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Portable host foundation     | [#425](https://github.com/SecPal/deployment/issues/425) and [#428](https://github.com/SecPal/deployment/pull/428) own reproducible host input, deployment composition and host evidence. Advance when the exact native installer, rendered input and installation-bound bootstrap are admitted and the supported lifecycle has real-system evidence. [#427](https://github.com/SecPal/deployment/pull/427) delivered broker source; live custody requires independent installation, read-only acceptance and safe credential transition.   |
| Reproducible application PoC | [#429](https://github.com/SecPal/deployment/issues/429) and [#430](https://github.com/SecPal/deployment/pull/430) compose the integration renderer and image pins under [#117](https://github.com/SecPal/deployment/issues/117). Admit the generated test bundle, start it on an authorized test slot using separate private runtime inputs, and prove readiness, authenticated data access, restart and teardown while preserving the installed stacks. This qualification can use already accepted lab hosts.                            |
| Isolated cross-host restore  | Transfer a consistent synthetic PostgreSQL archive over authenticated SSH, retain a protected off-source copy, and restore on an independent database and storage on a second authorized host. Compare schema and exact business records and prove authenticated API access and repeatability after container recreation. The restore proof supports the recovery program under [#91](https://github.com/SecPal/deployment/issues/91); production cross-state drills are owned by [#110](https://github.com/SecPal/deployment/issues/110). |
| Production acceptance        | Qualify the PG18 container seam under [#426](https://github.com/SecPal/deployment/issues/426), least-authority activation under [#100](https://github.com/SecPal/deployment/issues/100), and the state, edge, backup, update and recovery contracts under [#87](https://github.com/SecPal/deployment/issues/87). Require independent recovery-key custody, PostgreSQL WAL/PITR, private object recovery where applicable, and RecoverySet validation. HA and CONTINUITY require their own topology and failure-domain evidence.            |

Navigate by native issues and PRs for delivery status. The private FCOS audit
index groups the rebuild and multiarch reports, application PoC and restore
evidence, and canonical-domain browser qualification. Refer to those report
names from public source. Keep inventory, credentials, source/target read-backs,
archives and authenticator material private.

The application reproduction and cross-host logical-restore reports record a
fresh eight-role test stack and a successful restore on a different qualified
host. Both verified authenticated application reads after database container
recreation. The restore used encrypted off-source retention, an internal
network and independent PostgreSQL storage. These results cover synthetic data
and do not establish RecoverySet, WAL or production key recovery.

The private CX23 end-to-end reprovision report belongs to #425. It records a
fresh Ignition render from Foundation revision `d6bdfa7867ca`, a reinstall on
the existing protected resource, and new independently verified SSH and
WireGuard identities. The application was recreated from the merged PoC
with a fresh PostgreSQL 18 cluster, separated migration/runtime identities
and synthetic data. Authenticated HTTPS, the same committed application row,
the database roles, and both worker queues passed after container recreation
and a controlled guest reboot. The provider mutation path was the authorized
legacy test workflow. Broker mutation acceptance remains outstanding.

The run exposed an absent system network-online dependency on the fresh guest.
The operator added the persistent systemd wants link on the guest. The
renderer now declares the equivalent link, with strict Butane and Ignition
validation on both architectures. The private report retains the exact
installed Ignition and the subsequent guest correction.
