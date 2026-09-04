<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Production host contract

## Purpose and status

This document defines the provider-neutral admission contract for the first
SecPal production reference host. It is an input to later Phase D work, not a
host setup guide. The contract is versioned by the production inventory and is
validated only against supplied host-fact documents in D.1.

No host was provisioned. No production deployment was performed. No DNS, TLS,
firewall, SSH, provider, secret, storage, backup, or runtime resource was
created or changed by D.1.

## Supported topology

The first supported reference topology is `single-host`: one admitted Linux
host runs product and data roles through rootless Podman, systemd-user, and
native Quadlet, plus the public NGINX edge as a host system service. D.1 left
the future edge placement open; D.3 supersedes only that placeholder topology
and keeps the D.1 rootless product-runtime boundary intact. The historical
Phase B/C Docker/Compose integration proves the service relationships, one
scheduler, one `activity-hash-chain` worker, and explicit one-shot migration role. D.1 does
not claim Podman integration parity; [D.1a (#20)](https://github.com/SecPal/deployment/issues/20)
now owns the separate disposable migration and parity proof before D.2 builds
production state handling on the new runtime. The D.1 host contract itself
still makes no runtime-parity claim.

Multi-host and high availability are deferred and unsupported by schema
version 1. Kubernetes, clustering, multi-region operation, automatic failover,
and provider-managed replacements are also unsupported. This does not prevent
a reviewed future inventory version from adding a multi-host topology. Such a
version may assign roles to multiple independently admitted Podman hosts while
preserving the reviewed OCI image identities. Kubernetes remains a separate
future architecture if cross-host scheduling or self-healing is required.

## Platform and architecture

The only supported host OS is 64-bit Debian 13 `trixie`. Host facts require the
exact `/etc/os-release` identity `ID=debian`, `VERSION_ID=13`, and
`VERSION_CODENAME=trixie`; Debian point releases remain inside that major-release
identity. There is no invented Debian "server edition" assertion. Debian 12,
future Debian major releases, derivatives, testing, unstable, and `sid` fail
closed until a reviewed contract update adds them.

Release provenance is evidence, not a self-selected label. A future D.8
collector must combine `/etc/os-release`, active APT source configuration,
verified Debian `InRelease` metadata (the complete unique origin set is
`Debian`), and the installed `debian-archive-keyring` package. It normalizes the unique
configured suite selectors from all enabled Debian release sources. They must be exactly `trixie`,
`trixie-security`, and `trixie-updates`; source order and Debian point-release
updates are immaterial. Floating aliases such as `stable` and `oldstable`,
development aliases such as `testing`, `unstable`, and `sid`, and
`trixie-backports` are unsupported. A changed meaning of `stable` therefore
cannot trigger an implicit major upgrade.

Both `linux/amd64` and `linux/arm64` are equally supported host architectures.
The reviewed SecPal API and frontend OCI indexes each publish and smoke-test
both platforms, and Debian publishes Podman packages for both. The host-fact
architecture must equal the inventory architecture. Later installation work
must still resolve the reviewed OCI index for that architecture before any
container starts; a missing child platform is a hard failure, never a fallback
to another image, tag, repository, or emulator.

The current reviewed deployment identities remain unchanged:

- API OCI index:
  `ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e`
  from source commit `87d1432389adac3a02574b399322928a77c5e67f`.
- Frontend OCI index:
  `ghcr.io/secpal/frontend@sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077`
  from source commit `b755ca0d0ee5a85eca5ad5688d457241f070b1b4`.

Inventory cannot change either identity. Child manifests, discovery tags, a
source branch head, and a later publisher result are not deployment inputs.

## Kernel, filesystem, and basic tools

A conforming fact document reports all of the following:

- the Debian 13 Stable/Security Linux 6.12 series, owned by an installed Debian
  archive package from `trixie` or `trixie-security`;
- unified cgroup v2;
- OverlayFS support;
- AppArmor enabled with at least one loaded profile in enforce mode, plus
  seccomp available to Podman;
- writable local `ext4`, or writable local XFS with `ftype=1`, for every
  persistent state path and backup staging;
- working `d_type` directory-entry support; and
- the required commands `bash`, `curl`, `df`, `findmnt`, `getfacl`, `getent`, `gh`, `id`,
  `install`, `loginctl`, `mktemp`, `newgidmap`, `newuidmap`, `podman`,
  `python3`, `realpath`, `sha256sum`, `stat`, `systemctl`, and `timedatectl`.

Network filesystems, FUSE-backed remote state, remote runtime contexts, and
filesystems without reliable POSIX ownership and modes are unsupported. D.1
reads synthetic facts; D.8 owns any future fact collector.

The collector must join the running `uname` release to the package that owns
its installed kernel image and verify that package's authenticated APT origin
and suite. It must also read the installed package architecture and require it
to equal the admitted `amd64` or `arm64` host architecture; a release suffix is
not architecture evidence. Release candidates, local or mainline builds,
merely relabelled kernels, other kernel series, and backports fail closed.
Patch-level security updates within Linux 6.12 remain valid. Debian's standard
kernel supports AppArmor; admission still requires the effective AppArmor LSM
to be enabled, at least one loaded profile to be in enforce mode, and the
enforcing-profile count not to exceed the loaded-profile count. A future
collector derives those
counts from effective AppArmor status, not package presence. D.1a inspects the
effective profile of each disposable integration workload when AppArmor is
available; D.1 itself still does not claim production workload enforcement.
Seccomp must be reported as available to Podman from effective runtime facts
rather than inferred from installation.

## Operating-system lifecycle

Automatic security updates are required within Debian 13 through
`unattended-upgrades`. Its effective allowed origins must select
`trixie-security`, ordinary package updates must not be included in that
automatic policy, and the active release sources remain codename-pinned.
Normal package and Debian point-release maintenance is a controlled maintenance
operation. Automatic major-release upgrades are forbidden.

A future collector derives these facts from the installed mechanism, merged
APT periodic and unattended-upgrade configuration, enabled timers, allowed
origins, and reboot settings. Merely installing `unattended-upgrades` is not
sufficient. The same effective-state inspection must prove that the Podman
runtime stack is excluded from unattended updates and cannot automatically
restart services.

Automatic reboots are forbidden. A kernel or critical-library update may leave
the host in a `reboot required` state; later maintenance automation must surface
that state and a named operator controls the reboot. Because the reference
topology has one host, that reboot may cause planned short downtime; D.1 makes no
high-availability or zero-downtime claim.

Podman, crun, Netavark, Aardvark DNS, and passt are outside the unattended
Debian security-update set. Runtime-stack updates are reviewed maintenance;
urgent security fixes are applied through a bounded maintenance operation, not
deferred indefinitely. No package update automatically restarts SecPal units.
Host admission and SecPal acceptance must pass afterward. Podman 6 or another
major line requires a reviewed contract update before installation.

Debian 13 full support ends on 2028-08-09 and Debian LTS ends on 2030-06-30.
The successor schedule is deliberately ahead of the full-support boundary:

- 2027-08-09 (12 months before): start successor qualification;
- 2027-11-09 (9 months before): keep host-contract compatibility work active;
- 2028-02-09 (6 months before): prove the replacement or upgrade path in an
  isolated environment; and
- 2028-05-09 (3 months before): complete the production migration target.

LTS is a contingency and safety window, not the default migration date. A
Debian 13 to successor migration first requires a reviewed D.1 contract and
new host-fact evidence, compatibility evidence for every required component, a
successful D.7 backup/restore proof, a reproducible D.8 host installation, and
complete D.10 acceptance evidence.

The architectural preference is **Replace/rebuild before in-place major
upgrade**: validate a new supported host, install it through D.8, restore state
through D.7, verify the reviewed SecPal OCI identities, run acceptance, cut
over, and retire the previous host only after the evidence passes. Schema
version 1 does not claim an in-place major upgrade as a supported automatic
operations path; any later exception requires its own reviewed compatibility
and runbook contract.

## Rootless Podman and Quadlet

The only production runtime admitted by schema version 1 is rootless Podman
5.x, at least Podman 5.4.2 and below 6.0.0. Podman and its required components
come from authenticated Debian 13 archives for `trixie` or its reviewed
security-maintenance suite; external Podman repositories and backports are
unsupported. The narrow runtime matrix is `podman`, `conmon`, `crun`,
`netavark`, `aardvark-dns`, `passt`, `uidmap`, and `dbus-user-session`. Every
installed runtime package reports its effective APT suite, which must be
`trixie` or `trixie-security`; an installed `trixie-backports` package remains
unsupported even if its source entry was subsequently removed. Buildah is not
a production requirement. `podman-docker`, Docker Engine, Docker CLI aliases,
Docker Compose, `podman-compose`, and `podman compose` are not supported
production runtime paths. Rootful Podman is unsupported and fails closed.
The collector obtains Podman's effective OCI-runtime selection from the
effective `podman info` output; it must be `crun`. Installing the `crun` package
while selecting another runtime does not satisfy admission.

Podman is daemonless for this contract. The dedicated service account owns the
local rootless runtime, while host root remains a distinct authority. The
account has no sudo, system-unit, rootful-runtime, remote-runtime, raw-device,
or equivalent host authorization. The Podman API is not a production
dependency: system and user API services and socket activation are disabled,
TCP listeners and remote connections are forbidden, and product containers do
not receive a runtime socket.

Each account has exactly one contiguous `/etc/subuid` range and one contiguous
`/etc/subgid` range. Each contains 65536 identities, starts above the supported
host-account range, remains within Linux's 32-bit mapping limit, does not
overlap another account's range in the corresponding subordinate-ID namespace,
and matches the selected inventory range. A collector must parse every
effective entry and report exactly one selected entry per dimension;
it also rejects overlap with any effective host UID/GID or another account's
subordinate range.
`newuidmap` and `newgidmap` must be effective, not merely installed. A future
collector must prove that each helper can establish the selected mapping for a
short-lived user-namespace probe owned by the service account; executable
presence alone is insufficient.
This normal rootless namespace maps all reviewed container identities: API
`10001:10001`, frontend `101:101`, PostgreSQL `999:999`, and Valkey
`10002:10002`. D.2 maps them to host identities through the one default
single-range method; selecting an identity outside this namespace requires a
reviewed contract migration.

Production orchestration is the systemd user manager plus Quadlet. cgroup v2,
the Quadlet generator, the user manager, its DBus session, and boot startup are
required. Debian's rootless generator path is
`/usr/lib/systemd/user-generators/podman-user-generator`. The non-login service
account has linger enabled so its user manager
starts at boot without an interactive login. Its runtime boundary is
the local, service-account-owned `/run/user/<UID>` directory with mode `0700`.
Its transient, local Podman runroot is `/run/user/<UID>/containers`, also mode
`0700` and owned by the service account; neither is authoritative or backed up.
Their shared path-access facts prove canonical resolution, locality, ownership,
mode, and effective write access. The runtime directory itself is not
replaceable through an account-writable parent. The runroot deliberately has
an account-writable parent because it lives inside that account-owned runtime
directory; admission requires that exact relationship instead of treating it
as an operator-controlled path.

Root/operator-owned definitions live at
`/etc/containers/systemd/users/<SECPAL_UID>/`, mode `0755` on the directory,
with root-owned `0644` unit files. They are readable/traversable but not writable
by the service account. The shared path-access fact also proves that no
ancestor of the definition directory is writable by that account, so it cannot
rename and replace the reviewed tree through its parent. The effective Quadlet
generator search path is restricted to that one reviewed directory through an
administrator-owned, persistent
Quadlet search-path configuration that the service account cannot change.
Default user-writable runtime and home search paths are not effective inputs.
The complete reviewed tree, including drop-ins, contains no symlinks and all
unit content retains the stated root ownership and modes; its tree-wide access
facts must prove that the service account cannot mutate any entry. A future
collector must inspect the effective generator environment and dry-run output
rather than accept an empty user directory as proof. This uses Podman 5.4.2's
documented search-path restriction and administrator-managed rootless-user path. D.1a
keeps its disposable active Quadlets root-owned, and later D.8 work must keep
the search-path policy, production unit files, and drop-ins root-owned so a
product process cannot rewrite its definition. D.1 defines only this
capability and does not add production Quadlet files.

The rootless network contract is Netavark with Aardvark DNS and `pasta` from
Debian packages. Host networking is forbidden. D.1 does not change
`net.ipv4.ip_unprivileged_port_start`, firewall rules, forwarding, or ports
80/443. D.3 selects the NGINX host system service as the edge authority; D.4
must prove its public-port and protected loopback-backend paths without
weakening rootless isolation.

Effective Podman registry configuration is supply-chain state. SecPal image
references remain fully qualified and digest-only; no mirror, physical-location
rewrite, fallback, insecure GHCR transport, or short-name dependency may apply
to them. User-level and system-level configuration must be evaluated together.
No registry credential is introduced.

Podman auto-update and its timer are disabled for SecPal. Quadlet
`AutoUpdate=registry` and automatic newest-image selection are forbidden. The
later runtime implementation must pre-stage the exact reviewed OCI indexes,
verify the required publisher attestations, and only then permit units to
start. Its Quadlets must use `Pull=never` or an equivalently proven
no-opportunistic-pull policy. D.1 records that downstream invariant but does
not implement pulling, verification, or execution.

A future D.8 collector derives runtime facts from authenticated `dpkg`/APT
package records, `podman info`, merged system and user `containers.conf`,
`storage.conf` and `registries.conf`, the complete subordinate-ID databases,
an effective helper-backed mapping probe, `loginctl` plus the effective user
manager and runtime-directory metadata, the installed user generator, its
effective search-path configuration and dry-run output, the complete
administrator-owned Quadlet tree, and the mounts covering the service-account
home, runroot, and graphroot. It must report effective state rather than infer
compliance from package presence or copy declarative inventory values.

## Resource admission contract

CPU, storage, and inode values below are provisional admission floors. There is
no production workload measurement yet. Memory is therefore not assigned a
universal D.1 floor: every inventory still declares an explicit positive byte
requirement and host facts must meet it, but that operator-selected value is not
presented as an empirically proven SecPal minimum. The initial 8 GiB planning
share remains useful for the first measurement cycle without rejecting a host
solely because provider-reserved memory makes its guest-visible value smaller.

These D.1 inventory values are raw host-admission inputs, not named SecPal
capacity profiles and not provider-product mappings. The provider-neutral
[`M` capability](capacity-capabilities.md) reuses the defensible planning
envelope only when its effective resource, sustained-workload, storage-quality,
freshness, and headroom evidence all pass. A D.1 host is therefore not
implicitly `M`, and the recommended column below does not define `L` or a
commercial server size.

| Resource            |            Minimum |                   Recommended | Evidence and behavior below the floor                                                                                                                                    |
| ------------------- | -----------------: | ----------------------------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Logical CPU         |                  4 |                             8 | Scheduling floor for the current role set; admission fails below 4. Production load tests in D.10 must replace assumptions with measured concurrency.                    |
| RAM                 | Inventory-selected | 8 GiB initial planning target | Guest-visible memory is recorded and compared with the explicit inventory; D.10 must establish peak RSS and OOM margin before a universal floor is claimed.              |
| Total local storage |            100 GiB |                       250 GiB | Conservative first-host envelope for images plus state paths; admission fails below 100 GiB. D.2 and D.7 replace allocations with measured data growth and backup sizes. |
| Total inodes        |          1,000,000 |                     2,000,000 | Protects image layers, logs, framework cache files, and state trees; admission fails below 1,000,000. D.10 records peak inode consumption.                               |

### Initial unmeasured planning envelope

The CPU floor and initial RAM target use explicit planning shares for the
current eight long-lived roles. The RAM total is not a universal admission
floor and is not measured utilization:

| Role group                              | Logical CPU share | RAM share |
| --------------------------------------- | ----------------: | --------: |
| Host, Podman/systemd user runtime, edge |              1.00 |     2 GiB |
| PostgreSQL and Valkey                   |              1.00 |     2 GiB |
| API request role                        |              0.75 |   1.5 GiB |
| General and activity-hash-chain workers |              0.75 |   1.5 GiB |
| Scheduler and frontend                  |              0.50 |     1 GiB |
| **Initial planning envelope**           |          **4.00** | **8 GiB** |

The 100 GiB and 1,000,000-inode floor is likewise an explicit planning sum:

| Planning area                     |     Storage |        Inodes |
| --------------------------------- | ----------: | ------------: |
| Host OS, tools, and configuration |      20 GiB |       110,000 |
| Podman rootless storage reserve   |      20 GiB |       200,000 |
| PostgreSQL reserve                |      20 GiB |       200,000 |
| Private application storage       |      10 GiB |       100,000 |
| Public application storage        |       1 GiB |        20,000 |
| Logs                              |       5 GiB |        50,000 |
| Edge, ACME, and CrowdSec state    |       5 GiB |        90,000 |
| Backup staging                    |      10 GiB |        50,000 |
| Unassigned admission reserve      |       9 GiB |       180,000 |
| **Minimum admission envelope**    | **100 GiB** | **1,000,000** |

The recommended CPU and RAM tier doubles the minimum so that the admission
workload occupies at most half of those two capacities. Recommended storage is
the 100 GiB floor plus a 100 GiB first measurement window and 50 GiB reserve;
recommended inodes double the minimum. These are deliberately visible policy
assumptions and must be replaced by measured values through the evidence method
below, rather than presented as production observations, a provider SKU, or a
second capacity profile.

The evidence method is: record per-service CPU and peak RSS under D.10's
acceptance workload; measure OCI unpacked size; measure PostgreSQL plus private
and public storage growth over a stated retention window; measure log rotation;
and use the latest successful full-backup size from D.7. Recommended capacity
becomes `measured peak + stated growth window + at least 30% operational
margin`. The static values above remain conservative admission floors until a
reviewed migration note changes schema version 1.

## Disk and inode headroom

Each area fails if either its absolute reserve or 20% free-space and free-inode
reserve is breached. Sharing a backing device does not make the checks
additive; operators must evaluate every reported path and the device-wide total.
Each path reports its backing filesystem's byte and inode totals. Percentage
observations must be the whole-number floor derived from those totals, and no
backing-filesystem total may exceed the corresponding aggregate host total.
Contradictory evidence fails admission in either direction.

| Area                        | Absolute free bytes | Free inodes | Notes                                                                                  |
| --------------------------- | ------------------: | ----------: | -------------------------------------------------------------------------------------- |
| Podman graphroot            |              20 GiB |     200,000 | Reconstructable image/layer headroom; no automatic pruning contract.                   |
| PostgreSQL                  |              20 GiB |     200,000 | Admission reserve only; WAL and database sizing belong to D.2.                         |
| Private application storage |              10 GiB |     100,000 | Business-critical files remain separate from PostgreSQL.                               |
| Public application storage  |               1 GiB |      20,000 | Initial public-artifact reserve; publication and backup policy belong to D.2.          |
| Logs                        |               5 GiB |      50,000 | Rotation and retention are deferred; exhaustion fails admission.                       |
| Edge state                  |               2 GiB |      20,000 | Edge choice and sizing belong to D.3/D.4.                                              |
| ACME state                  |               1 GiB |      20,000 | Certificate lifecycle belongs to D.5.                                                  |
| CrowdSec state              |               2 GiB |      50,000 | Runtime selection and retention belong to D.6.                                         |
| Backup staging              |              10 GiB |      50,000 | This is only a floor. D.7 must require enough space for its measured backup operation. |

The validator compares these values to supplied facts and never runs `df`,
reads `/proc`, or inspects the developer machine.

Path-access facts contain the canonical path obtained by a future collector
using existence-requiring resolution and component-wise `lstat` checks. The
value must be byte-for-byte identical to the normalized inventory path. This
rejects a symlink at the namespace root, at any ancestor, or at the managed
leaf before ownership, mode, or mount facts are trusted. The same closed
`pathAccessFact` structure is used by filesystem-backed state, the systemd
runtime directory and Podman runroot, and the root-controlled service-account
home and Quadlet definition paths. Ownership, mode, locality, effective write
access, and expected ancestor access therefore have one validator
implementation. There is no parallel Quadlet-only or runtime-only ownership
model.

Filesystem facts remain separate from headroom facts. They cover every path
classified as persistent plus reconstructable backup staging and must match
the corresponding inventory path. This includes configuration and deployment
state even though those two paths have no separate capacity floor. Runtime
secrets are reconstructable state under `/run`; D.2 defines their filesystem,
canonicalization, ownership, mode materialization, and lifecycle in the
production state contract. Each represented path reports its effective
numeric UID, GID, and directory mode. D.1 compares fixed owners for
configuration, deployment state, logs, backup staging, and Podman graphroot;
owners delegated to later edge contracts are observed but not selected here. A
delegated path cannot report the service-account UID because every
delegated baseline mode grants its owner write access; such a fact would
contradict the required effective-access denial. Every baseline mode is fixed
and enforced, including for delegated-owner paths. Effective access facts must
be consistent with numeric ownership and mode and additionally prove that the
service account can write only its fixed service-owned paths and cannot replace
any represented path through a writable ancestor. The collector must evaluate
ACLs and all other effective permission sources in addition to the mandatory
UID/GID/mode consistency check. Every represented mount must explicitly
report `mount_read_only: false`; omission and a read-only mount both fail
closed. A future collector must derive this from the effective mount covering
the path and obtain ownership/mode with a non-following stat after canonical
path validation rather than infer either from the filesystem type.

## Network and clock assumptions

Inventory records one public-unicast-eligible address fact and at least one
non-loopback private address fact. Reserved documentation networks are accepted
only when the validator is invoked with the explicit `--synthetic` fixture
flag; reserved documentation DNS origins are gated by the same flag. Other
IANA special-use origin suffixes, including `.alt`, `.arpa`, `.local`, and
`.onion`, are never production origins and remain rejected in synthetic mode.
The normal production-validation path rejects all reserved inputs. IPv6
schema version 1 admits only `2000::/3` Global Unicast addresses. Both address
families then use one explicit exclusion policy derived from the IANA IPv4 and
IPv6 Special-Purpose Address Registries last updated on 2025-10-09 and reviewed
for this contract on 2026-08-09. It excludes private, loopback, link-local,
shared, benchmarking, multicast, reserved, protocol-assignment, anycast,
AS112, AMT, ORCHID, deprecated 6to4, documentation, and segment-routing
identities as applicable. Validation does not delegate this security decision
to a language runtime's changing `is_global` classification. Registry changes
require reviewed contract evidence; the validator performs no runtime registry
download. This classification is an admission prerequisite, not proof of DNS
publication, BGP routing, or reachability; D.4 owns that later evidence. Private
addresses are exactly RFC 1918 IPv4 or IPv6 ULA;
documentation and benchmarking ranges are not private-use substitutes.
IPv4-mapped IPv6 values are representations of IPv4 rather than accepted IPv6
host addresses and fail admission. Scoped IPv6 literals also fail because an
interface-zone suffix is not a stable inventory identity. Address facts are
strings and are never coerced from numeric or binary YAML values.
Private-address collection order is insignificant, but duplicates and
mismatches fail closed. The public NGINX host service is the only publicly
reachable boundary; product and data services remain on private rootless
container networks. Firewall mutation, routing, port
publication, cloud metadata, and public reachability checks are outside D.1.

The host has a stable DNS hostname distinct from both application origins. A
valid single-label host name such as `secpal-prod` is supported; it is a local
host identity, not a public origin. Frontend and API use separate, fully
qualified multi-label DNS names in their HTTPS origins. Origins cannot
contain userinfo, a path, query, fragment, IP literal, loopback name, or a
non-default port. Empty query, fragment, or port delimiters, ASCII control
characters, and parser-normalized scheme or port spellings are also rejected.

Time synchronization is mandatory because TLS, artifact attestations, audit
records, jobs, and backup evidence depend on trustworthy time. Facts must
report synchronized time and an absolute offset no greater than 1000 ms. The
contract is implementation-neutral between a correctly operating NTP client
such as `systemd-timesyncd` and `chrony`.

## Service account and operator boundary

Inventory selects the unprivileged account and primary group name plus numeric
UID/GID. Schema version 1 requires IDs from 1000 through 60000 and rejects
known container identities. `root` is forbidden as an account name. Known
privileged or sensitive Debian and runtime primary-group names are forbidden,
and facts must report no supplementary group membership.
Facts must report the effective name, primary group, UID, primary GID,
supplementary GIDs, home, home locality, shell,
interactive-login state, sudo-authorization state, and effective
host-privilege-authorization state. The name, group, IDs, and home must match
inventory. The shared path-access fact proves that the home is root-owned,
group-owned by the service account's primary GID, mode `0750`, not writable by
the account, and not replaceable through a writable ancestor. The home is local
and its containers configuration is not writable by the account. The remaining
facts must prove a
non-login shell, disabled interactive login, no sudo authorization, no
rootful or remote runtime authorization, no arbitrary system-unit authority,
and no other effective host-privilege grant.
That last denial covers privileged supplementary groups and grants through
device, file, ACL, capability, service-manager, or policy authorization. A
future collector must evaluate effective privilege and sudo policy, including
inherited groups and included policy, rather than grep one sudoers file. The
example uses
`secpal-deploy:20000:20000`, but that value is synthetic and not mandatory.

Root owns reviewed configuration, deployment metadata, and the service-account
home, with the account's primary group receiving read/execute access. The
account owns its rootless Podman graphroot, logs, and backup staging. Its home
is an absolute local state path but is not a user-writable Podman policy source;
its shell is `/usr/sbin/nologin`, interactive login is disabled, and it receives
no `sudo` authorization. It does not own PostgreSQL, Quadlet definitions, or
the `secpal-edge` host-service identity selected by D.3.

Named human operators authorize host changes. Their SSH keys, certificates,
hardware-backed credentials, and privilege policy live outside this
repository and outside inventory. Direct root SSH is unsupported, and supplied
facts must prove that it is not permitted. A future collector must evaluate the
effective daemon and authentication policy, including includes and drop-ins,
rather than inspect only one SSH configuration file. A human operator
authenticates as a named account and uses audited, explicit privilege
escalation for package, filesystem-owner, network, or service-manager
operations. D.1 creates no accounts, keys, SSH configuration, or sudoers file.

## Filesystem and mountpoint model

The example paths are provider-neutral defaults, not real host values. Every
inventory path must be absolute, normalized, unique, mutually non-overlapping,
non-root, outside `/tmp`, and separate from the service-account home. Null
UID/GID means the named later issue must select and migrate the runtime identity
before that component can be installed. Every path is limited to 4095 UTF-8
bytes in total and 255 UTF-8 bytes per component, matching the supported Linux
ext4/XFS representation limits. ASCII control characters are forbidden.

Schema version 1 also confines path selection by purpose: SecPal state paths
are strict children of `/srv/secpal`, runtime secrets are a strict child of
`/run/secpal`, the service-account home stays within its dedicated
`/var/lib/secpal` subtree, and the rootless Podman graphroot is a dedicated
strict child of `/srv/secpal`. Quadlet definitions are the sole exception:
their path is derived exactly as `/etc/containers/systemd/users/<UID>` and is
root-owned. State and runtime-secret namespace roots themselves are not
selectable. This structural allowlist rejects unrelated `/etc`, `/usr`, and
`/var/lib` trees without maintaining an incomplete directory blacklist.

| Inventory key                 | Example path                          | Owner and UID:GID                                  |   Mode | Class           | Decision owner       |
| ----------------------------- | ------------------------------------- | -------------------------------------------------- | -----: | --------------- | -------------------- |
| `configuration`               | `/srv/secpal/config`                  | root:service GID, runtime read-only                | `0750` | persistent      | D.1                  |
| `deployment_state`            | `/srv/secpal/deployment-state`        | root:service GID, runtime read-only                | `0750` | persistent      | D.1                  |
| `runtime_secrets`             | `/run/secpal/secrets`                 | root:`20000`                                       | `0710` | reconstructable | D.2                  |
| `postgresql_data`             | `/srv/secpal/postgresql`              | mapped `100998:200998`; container `999:999`        | `0700` | persistent      | D.2                  |
| `private_application_storage` | `/srv/secpal/private-storage`         | mapped `110000:210000`; container `10001:10001`    | `0750` | persistent      | D.2                  |
| `public_application_storage`  | `/srv/secpal/public-storage`          | mapped `110000:210000`; container `10001:10001`    | `0750` | persistent      | D.2                  |
| `valkey_data`                 | `/srv/secpal/valkey`                  | mapped `110001:210001`; container `10002:10002`    | `0700` | persistent      | D.2                  |
| `edge_state`                  | `/srv/secpal/edge`                    | root owner; `secpal-edge` group, runtime read-only | `0750` | persistent      | D.3 (#11)            |
| `acme_state`                  | `/srv/secpal/acme`                    | TLS contract, unset                                | `0700` | persistent      | D.5 (#13)            |
| `crowdsec_state`              | `/srv/secpal/crowdsec`                | CrowdSec contract, unset                           | `0750` | persistent      | D.6 (#14)            |
| `logs`                        | `/srv/secpal/logs`                    | service account, inventory UID:GID                 | `0750` | persistent      | D.1; retention later |
| `backup_staging`              | `/srv/secpal/backup-staging`          | service account, inventory UID:GID                 | `0700` | reconstructable | D.7 (#15)            |
| `podman_graph_root`           | `/srv/secpal/podman-storage`          | service account, inventory UID:GID                 | `0700` | reconstructable | D.1                  |
| `quadlet_definitions`         | `/etc/containers/systemd/users/<UID>` | operator root `0:0`                                | `0755` | reconstructable | D.1                  |

`/app/storage/app/private` is business-critical container state and retains the
verified API container owner `10001:10001`. Under rootless Podman those are host
UID/GID `110000:210000`, derived through the reviewed default single-range
mapping. The production state initializer materializes that mapping; `:U`,
`keep-id`, alternate idmapped mounts, and container-side recursive chown are not
supported. It is never merged with PostgreSQL data. The
frontend remains `101:101`, serves HTTP on 8080, has a read-only root filesystem
and writable `/tmp`, and does not own TLS, ACME, or API proxying.

D.2 classifies public application storage as durable, non-reconstructable,
restore-required state with container identity `10001:10001` and mapped host
identity `110000:210000`. It may hold only artifacts deliberately classified
for public delivery, never private uploads, credentials, or database state. It
is backed up with PostgreSQL and private storage; the edge must not expose the
host path directly.

Logs are persistent operational and security evidence, not reconstructable
state. D.10 owns retention, rotation, optional external shipping, and the
acceptance proof that exhaustion remains bounded.

The Podman graphroot contains reconstructable images, layers, and container
metadata. It is never the recovery authority for PostgreSQL, private or public
application storage, runtime secrets, or reviewed deployment policy. Loss of
graphroot must be recoverable by reinstalling the reviewed runtime state and
re-pulling and re-verifying the approved OCI identities; D.7/D.8 own that proof.

Valkey is queue/cache infrastructure, not a source of truth. D.2 enables AOF
persistence at `/srv/secpal/valkey` because queued-work loss is not generally
reconstructable even though cache loss is. PostgreSQL remains authoritative;
the Valkey AOF joins D.7's coordinated continuity backup and recovery policy.

The backup target is a non-secret external descriptor. Backup creation,
encryption, retention, credentials, and restore proof belong to D.7. The
staging path is not itself a backup.

## External dependency inventory

Every enabled path must use a documented fixed destination contract and may
not perform an undocumented moving runtime download. All optional application
features are fixed disabled by inventory schema version 1; a future reviewed
schema migration may enable one only after its owning contracts are complete.

| Dependency                               | Owner / default               | Destination or input contract                                                                                                                                                    | Credential boundary                             | Timeout and failure                                                                                                                   | Disabled behavior                                         | Phase                             |
| ---------------------------------------- | ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | --------------------------------- |
| GHCR image retrieval                     | image verification / required | HTTPS `ghcr.io`, `https://ghcr.io/token`, and HTTPS blob redirects under `pkg-containers.githubusercontent.com` for reviewed digests only                                        | anonymous; no registry credential               | current request timeout is 30 seconds; D.8/D.9 must add an overall operation bound; failure blocks execution                          | cannot be disabled for an install/update                  | maintenance only                  |
| GitHub artifact attestation verification | image verification / required | fixed `github.com` signer, repository, workflow, ref, and source digest against the local OCI index/bundle                                                                       | no GitHub token                                 | local-bundle verification must receive a 60-second operation bound in D.8; timeout or verification failure blocks execution           | cannot be disabled                                        | maintenance only                  |
| Mail delivery                            | mail / disabled               | one operator-selected SMTP or reviewed Laravel transport endpoint                                                                                                                | secret supplied by D.2, never inventory         | current null SMTP timeout is unsafe; enablement requires D.2 to set at most 30 seconds; failure queues/retries or alerts              | application uses a non-delivery/log policy selected later | runtime                           |
| OpenTimestamp calendars                  | OpenTimestamp / disabled      | calendars used by the pinned client embedded in the API image; no runtime package update                                                                                         | none expected for public calendars              | current submission boundary is 15 seconds; failure remains queued/retryable                                                           | no timestamp submission or upgrade traffic                | runtime                           |
| Bitcoin quorum providers                 | OpenTimestamp / disabled      | configured HTTPS provider quorum; current API defaults identify Blockstream and mempool.space inputs                                                                             | no credential in inventory                      | each header request is bounded to 10 seconds; quorum failure preserves an unverified state                                            | no Bitcoin-header provider traffic                        | runtime                           |
| Address-data imports                     | address data / disabled       | reviewed immutable HTTPS source or operator-supplied local input; the current upstream default at `raw.githubusercontent.com/.../refs/heads/main/...` is not production-eligible | any source credential belongs outside inventory | current download timeout is 600 seconds; failure keeps the prior active dataset                                                       | scheduled and setup imports make no network request       | maintenance and scheduled runtime |
| Android push delivery                    | Android push / disabled       | configured OAuth token endpoint and FCM API base                                                                                                                                 | FCM identity and key are D.2 secrets            | connect 5 seconds, request 10 seconds; delivery failure remains observable                                                            | channel is not advertised or dispatched                   | runtime                           |
| Web Push delivery                        | Web Push / disabled           | subscriber-provided HTTPS push endpoints                                                                                                                                         | VAPID private key is a D.2 secret               | connect 5 seconds, request 20 seconds; delivery failure remains observable                                                            | channel is not advertised or dispatched                   | runtime                           |
| Optional object storage                  | object storage / disabled     | one operator-selected S3-compatible endpoint descriptor                                                                                                                          | access credentials are D.2 secrets              | enablement requires D.2 bounds of at most 10 seconds to connect and 30 seconds per operation; failure cannot fall back to local state | local filesystem remains the selected application storage | runtime                           |

The required GHCR and attestation paths are maintenance-only. They do not
authorize a registry login, registry write, newest-image lookup, discovery-tag
lookup, or digest refresh. Enabling any optional feature requires its later
state/secret and runtime contract to be complete plus a reviewed inventory
schema migration.

The current API image contains two upstream behaviors that cannot be enabled by
inventory alone: its weekly OpenTimestamp status task can perform a moving
Python package-index update check, and its weekly address import uses a moving
branch URL without an application-level disable switch. D.8 must keep those
scheduled paths disabled until reviewed immutable behavior is present in a
future API digest. The remediation is tracked separately in
[`SecPal/api#1410`](https://github.com/SecPal/api/issues/1410) and
[`SecPal/api#1411`](https://github.com/SecPal/api/issues/1411); D.1 does not
change the reviewed API artifact identity.

## Failure semantics and non-goals

Unknown inventory or host-fact fields, unknown versions, Debian release or
update-policy drift, mismatched
architectures, effective service identities, service-account login, sudo, or
other host authority, direct root SSH, Podman provenance, rootless mapping,
Quadlet/user-manager, API exposure, registry rewrite, low resources, clock
drift, unsupported filesystems, and dependency
contradictions fail before any side effect. Validation errors name the safe
field location or invariant and never print classified field names, input
values, or full documents.

D.1 deliberately does not implement host setup, remote access, provider
selection, firewall or DNS changes, TLS/ACME, CrowdSec, secrets, persistent
volume creation, database initialization, backup/restore, Compose production
or Podman production orchestration, legacy integration migration,
install/update/rollback workflows, or container startup. Those
remain with #10 through #18 according to the parent epic.

## Evidence references

- [Debian 13 release information](https://www.debian.org/releases/trixie/)
- [Debian 13 release notes](https://www.debian.org/releases/stable/release-notes/)
- [Debian stable release update policy](https://www.debian.org/releases/stable/errata)
- [Debian security and LTS lifecycle](https://www.debian.org/security/faq#lifespan)
- [Debian `unattended-upgrades` package](https://packages.debian.org/trixie/unattended-upgrades)
- [Debian AppArmor guidance](https://www.debian.org/doc/manuals/debian-handbook/sect.apparmor.en.html)
- [Debian 13 Podman package](https://packages.debian.org/trixie/podman)
- [Debian 13 conmon package](https://packages.debian.org/trixie/conmon)
- [Debian 13 crun package](https://packages.debian.org/trixie/crun)
- [Debian 13 Netavark package](https://packages.debian.org/trixie/netavark)
- [Debian 13 Aardvark DNS package](https://packages.debian.org/trixie/aardvark-dns)
- [Debian 13 passt package](https://packages.debian.org/trixie/passt)
- [Debian 13 uidmap package](https://packages.debian.org/trixie/uidmap)
- [Debian 13 DBus user-session package](https://packages.debian.org/trixie/dbus-user-session)
- [Debian subordinate-ID format](https://manpages.debian.org/trixie/passwd/subuid.5.en.html)
- [Debian `newuidmap` behavior](https://manpages.debian.org/trixie/uidmap/newuidmap.1.en.html)
- [Debian systemd user runtime directory](https://manpages.debian.org/trixie/libpam-systemd/pam_systemd.8.en.html)
- [Podman 5.4.2 rootless requirements](https://docs.podman.io/en/v5.4.2/markdown/podman.1.html#rootless-mode)
- [Podman 5.4.2 Quadlet contract](https://docs.podman.io/en/v5.4.2/markdown/podman-systemd.unit.5.html)
- [Podman 5.4.2 networking](https://docs.podman.io/en/v5.4.2/markdown/podman-network.1.html)
- [Podman container storage](https://github.com/containers/storage/blob/main/docs/containers-storage.conf.5.md)
- [Podman auto-update](https://docs.podman.io/en/v5.4.2/markdown/podman-auto-update.1.html)
- [Podman API service security](https://docs.podman.io/en/v5.4.2/markdown/podman-system-service.1.html)
- [Containers registry configuration](https://github.com/containers/image/blob/main/docs/containers-registries.conf.5.md)
- [systemd lingering user managers](https://www.freedesktop.org/software/systemd/man/latest/loginctl.html#enable-linger%20USER%E2%80%A6)
- [IANA IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
- [IANA IPv6 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml)
- [IANA Special-Use Domain Names Registry](https://www.iana.org/assignments/special-use-domain-names/special-use-domain-names.xhtml)
- [`docs/api-image-consumption.md`](../api-image-consumption.md)
- [`docs/frontend-image-consumption.md`](../frontend-image-consumption.md)
