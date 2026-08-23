<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Production host contract

## Purpose and status

This document defines the provider-neutral admission contract for the first
SecPal production reference host. The active reference platform is Rocky Linux
10.2 with SELinux Enforcing and rootless Podman managed by systemd-user and
native Quadlet. Multi-host and high availability are deferred.

Issue #80 changes the host contract and its reviewable validation harness. It
does not provision a host or implement PostgreSQL, an edge proxy, nftables,
cloud infrastructure, provider inventory, application state, secrets, backup,
or recovery. The completed D.1 and D.1a work remains historical evidence for
distribution-independent rootless lifecycle concepts only. It is not current
Rocky Linux, package-provenance, x86-64-v3, or SELinux evidence.

Host-facts schema version 2 supersedes the historical version 1 Debian fact
shape without rewriting old evidence. The checked-in positive host documents
are marked `evidence_class: synthetic`.
They prove parser and admission behavior only. Native admission requires
`evidence_class: rocky-native`; the validator rejects a synthetic document in
native mode. Required Rocky evidence remains **NOT RUN** until the native
qualification harness executes on each reference architecture.

## One authoritative admission path

Host admission has one fact model and one decision owner:

1. trusted local system interfaces provide effective facts;
2. `schemas/production-host-facts.schema.json` rejects unknown or malformed
   fields and closed values;
3. `scripts/validate-production-contract.py` applies cross-field rules and
   compares facts with the reviewed inventory; and
4. diagnostics identify the first non-conforming fact.

Critical missing, unavailable, contradictory, or unknown facts fail closed.
An operator-supplied distribution string is not evidence. A native collector
must obtain OS identity from `/etc/os-release`, package and signature facts
from RPM/DNF state, kernel and architecture facts from the running system, and
runtime facts from the effective rootless Podman and systemd-user contexts.

## Rocky Linux version and architecture

The only currently qualified OS identity is:

- `/etc/os-release` `ID=rocky`;
- exact `VERSION_ID=10.2`; and
- 64-bit `x86_64` (`amd64` in inventory) or `aarch64` (`arm64` in inventory).

The schema recognizes the shape of later Rocky 10.x minors, but the validator
uses the reviewed allowlist `{10.2}`. A later minor is rejected until a contract
change adds that exact minor after package, runtime, application-platform, and
native evidence review. Rocky 10.0, Rocky 10.1, Rocky 9, other distributions,
derivatives, and malformed identities are rejected. In particular, Debian and
an AppArmor-only result cannot satisfy current production admission.

Rocky Linux 10 on x86_64 requires the x86-64-v3 microarchitecture baseline.
Admission uses Rocky's platform-supported glibc-loader check:

```text
/lib64/ld-linux-x86-64.so.2 --help
```

The effective output must mark `x86-64-v3 (supported, searched)`. This avoids a
second hand-maintained CPU-feature definition and rejects legacy x86 CPUs.

Arm64 is independently admitted as a native Rocky `aarch64` system. It does not
claim or translate an x86 microarchitecture level. Its package, kernel,
rootless runtime, Quadlet, and SELinux evidence must pass on a real aarch64
Rocky 10.2 host.

The inventory and effective host architecture must match. Image selection
remains digest-only and must resolve a reviewed child manifest for the admitted
architecture; emulation or fallback to another architecture is unsupported.

## Package provenance and updates

Only the default Rocky Linux 10 `baseos`, `appstream`, and `extras`
repositories signed by `RPM-GPG-KEY-Rocky-10` may be enabled. Required host
packages must resolve from `baseos` or `appstream`; issue #80 introduces no
dependency from `extras`. Enabled external repositories, COPR, CRB, arbitrary
installers, testing repositories, registry rewrites, or repository fallback
fail closed.

The package contract is:

| Component                | Required package                    | Repository  |
| ------------------------ | ----------------------------------- | ----------- |
| Container engine         | `podman`, `conmon`                  | `appstream` |
| OCI runtime              | `crun`                              | `appstream` |
| Networking               | `netavark`, `aardvark-dns`, `passt` | `appstream` |
| Rootless IDs             | `shadow-utils-subid`                | `baseos`    |
| User lifecycle           | `systemd`                           | `baseos`    |
| Container policy         | `container-selinux`                 | `appstream` |
| AVC evidence             | `audit`                             | `baseos`    |
| SELinux policy           | `selinux-policy-targeted`           | `baseos`    |
| SELinux tooling          | `policycoreutils`                   | `baseos`    |
| Persistent label tooling | `policycoreutils-python-utils`      | `appstream` |

The synthetic architecture fixtures record the exact Rocky 10.2 repository
NEVRAs observed during contract preparation for both x86_64 and aarch64. Those
values demonstrate the evidence shape; they are not native installed-package
qualification. Native evidence must record the actual installed NEVRA for
every package and prove its Rocky repository and verified RPM signature.

The contract does not permanently pin an incidental package build. Rocky
BaseOS DNF4 (`dnf` 4.x) updates are automatic-disabled and operator-reviewed.
`/etc/os-release` `VERSION_ID` admits the exact reviewed Rocky minor (currently
`10.2`), while RPM/DNF `system-release(releasever)` identifies the Rocky
repository line and is exactly `10`. Repositories remain constrained,
automatic reboots and service restarts are forbidden, and admission is rerun
after maintenance. DNF5 availability outside the reviewed repository set is
not a reason to expand the production repository allowlist. This distinction
does not admit an unreviewed Rocky minor: a new Rocky minor or Podman major
requires a reviewed contract update before production use.

## Kernel, resources, and basic host prerequisites

The running kernel must be a stable, RPM-owned Rocky BaseOS Linux 6.12 kernel
for the admitted architecture. Release candidates, local builds, unowned
kernels, and mismatched package architecture fail closed. Unified cgroup v2,
OverlayFS, effective Podman seccomp support, local `ext4` or XFS with `ftype=1`,
and working `d_type` are required.

The admission floors remain provider-neutral:

| Resource      |                           Minimum |
| ------------- | --------------------------------: |
| Logical CPUs  |                                 4 |
| RAM           | explicit positive inventory value |
| Local storage |                           100 GiB |
| Inodes        |                         1,000,000 |
| Clock offset  | at most 1,000 ms and synchronized |

Every managed filesystem also retains its inventory-defined free-byte,
free-inode, and percentage headroom. Network filesystems and remote rootless
storage are unsupported. The host must provide the tools named by the closed
fact contract, including SELinux inspection, audit, persistent labeling,
Podman, systemd-user, subordinate-ID, storage, time, and RPM tooling.

## SELinux admission

`getenforce` reporting `Enforcing` is necessary but insufficient. Admission
requires all of the following effective facts:

- SELinux enabled with the targeted policy in Enforcing mode;
- signed Rocky `container-selinux` policy present;
- representative rootless processes in `container_t` rather than an
  unconfined domain;
- representative mounted storage in `container_file_t`;
- the workload process and its private storage share one MCS range;
- intended access succeeds;
- a second rootless `container_t` process has a distinct MCS range;
- DAC permits and the target exists, but cross-boundary access fails; and
- a matching AVC proves SELinux, rather than DAC, a missing path, or harness
  failure, caused the denial.

`label=disable`, Permissive or Disabled mode, `unconfined_t`, `default_t`, a
missing policy package, a missing AVC, contradictory MCS facts, rootful or
privileged substitution, or global policy weakening all fail closed. The
contract does not accept `setenforce 0`, broad allow rules, or privilege
expansion as remediation.

Persistent host paths use an administrator-owned `semanage fcontext` rule and
`restorecon`. `chcon` alone is not authoritative because relabeling or policy
updates can discard it. Podman may assign the per-container MCS categories
needed for private mounts, but the durable path type remains owned by the
persistent file-context rule. Issue #80 proves this capability with disposable
fixture paths and does not pre-assign every later application storage path.

## Rootless service account and systemd-user

One dedicated service account owns application containers. It has:

- `/usr/sbin/nologin`, no interactive login, no sudo, no supplementary
  privileged groups, and no system-unit or host-privilege authority;
- exactly one non-overlapping 65,536-entry `/etc/subuid` range and one matching
  `/etc/subgid` range, with effective `newuidmap` and `newgidmap` probes;
- a local rootless graphroot and `/run/user/<UID>/containers` runroot;
- an effective systemd user manager, DBus session, and administrator-enabled
  lingering so it starts at boot without an interactive session; and
- no authority for rootful, privileged, remote-runtime, or socket/API fallback.

The rootless engine is the qualified Rocky Podman 5.x line at or above 5.8.2
and below 6.0.0, with effective `crun` and cgroup v2. Application processes are
non-root, seccomp uses the runtime default, no extra capabilities are admitted,
and `CAP_SYS_ADMIN`, `NET_ADMIN`, and broad capability sets are unsupported.

## Administrator-owned Quadlet authority

Production orchestration is native Quadlet through systemd-user. Authoritative
definitions live only in `/etc/containers/systemd/users/<UID>/`. The directory,
its ancestors, unit files, and drop-ins are administrator-owned; the service
account can read and traverse them but cannot write, replace, or redirect them.

Admission rejects a writable file or parent, symlinks, an alternate untrusted
search path, a writable search-path configuration, Docker Compose, Podman
Compose, `AutoUpdate=`, mutable image names, opportunistic pulls, host network,
privileged configuration, or `label=disable`. Images are fully qualified and
digest-only, and production Quadlets use `Pull=never` after separate image
verification and staging.

## Rootless networking and runtime API boundary

The Rocky Podman contract uses Netavark with Aardvark DNS and `pasta` supplied
by the Rocky `passt` package. `slirp4netns` is not the selected Rocky 10 path.
Host networking and a lowered unprivileged-port boundary are forbidden. This
host layer provides deterministic rootless networking without implementing
the later PostgreSQL loopback or edge-backend seams.

Podman remains daemonless. Application operation is:

```text
systemd-user -> generated Quadlet unit -> local Podman process execution
```

It is not an application or controller talking to an engine API. Podman system
and user API services, socket activation, TCP listeners, remote connections,
mounted Podman sockets, mounted Docker sockets, Docker APIs, and application
runtime-API dependencies fail closed. Presence of the local Podman CLI is not
a failure.

Effective registry configuration is evaluated across system and user layers.
SecPal references remain fully qualified and digest-only. Mirrors, physical
location rewrites, insecure GHCR transport, fallback registries, short-name
resolution, automatic image updates, and the Podman auto-update timer are
forbidden.

## Native qualification harness

`scripts/qualify-production-host.sh` is the Rocky-native required mode. On a
non-Rocky or unqualified minor it exits with status 2 and prints `NOT RUN`; it
never skips and reports PASS. The operator supplies a fully qualified,
digest-only fixture image that is already present in the service account's
rootless store. The harness never pulls an image.

On Rocky 10.2 the harness performs bounded checks of packages, architecture,
x86-64-v3 where applicable, cgroup v2, crun, Netavark, administrator-owned
Quadlet lifecycle, seccomp/no-new-privileges, SELinux process and storage
labels, intended access, and a distinct-MCS negative access with a matching
AVC. It creates uniquely named fixture containers, one exact Quadlet file, one
`mktemp` fixture tree, and one exact temporary fcontext rule. Signal and normal
cleanup remove only those resources. It never prunes Podman, touches production
data, loads broad policy, changes enforcing mode, provisions a provider, or
uses real SecPal secrets.

The native run remains required separately on x86_64 and aarch64. Repository
preflight on another distribution proves repository behavior only.

## Managed paths and operator boundary

The inventory remains the owner of exact provider-neutral paths, ownership,
modes, lifecycle, and resource headroom. Configuration, deployment state,
runtime secrets, application state, logs, backup staging, the rootless Podman
graphroot, and administrator Quadlets remain separate paths. Unknown paths,
overlap, traversal, symlinks, remote filesystems, inconsistent ownership, and
account-writable administrator paths fail closed.

The service account may write only paths explicitly delegated to its runtime
role. Host configuration, administrator Quadlets, host-native edge authority,
future host-native data services, firewall policy, and privileged operations
remain operator-owned. Direct root SSH is unsupported. Provider-specific
inventory, public reachability, and production installation remain outside
issue #80.

## Validation modes

### Fixture and static mode

Runs anywhere and proves schema closure, parser behavior, positive Rocky 10.2
decisions, and negative mutations. Synthetic facts are visibly labeled and
cannot become native evidence.

### Portable runtime regression mode

May run on a capable non-Rocky host. It proves only distribution-independent
rootless Podman or Quadlet behavior and must be reported as non-Rocky.

### Rocky native required mode

Runs only on a real Rocky 10.2 host with SELinux Enforcing. Absence of that
environment is `NOT RUN`, never PASS. A Rocky container on another host,
altered `/etc/os-release`, simulated SELinux state, or AppArmor behavior is not
native evidence.

## Primary references

- [Rocky Linux release lifecycle and current minors](https://docs.rockylinux.org/latest/releases/)
- [Rocky Linux 10 release notes and architecture baseline](https://docs.rockylinux.org/latest/releases/release_notes/10_0/)
- [Rocky Linux x86-64-v3 compatibility procedure](https://docs.rockylinux.org/gemstones/test_cpu_compat/)
- [Rocky Linux 10.2 x86_64 AppStream repository](https://download.rockylinux.org/pub/rocky/10.2/AppStream/x86_64/os/)
- [Rocky Linux 10.2 aarch64 AppStream repository](https://download.rockylinux.org/pub/rocky/10.2/AppStream/aarch64/os/)
- [Rocky Linux 10.2 x86_64 BaseOS repository](https://download.rockylinux.org/pub/rocky/10.2/BaseOS/x86_64/os/)
- [Rocky Linux 10.2 aarch64 BaseOS repository](https://download.rockylinux.org/pub/rocky/10.2/BaseOS/aarch64/os/)
- [Podman rootless mode](https://docs.podman.io/en/v5.8.2/markdown/podman.1.html#rootless-mode)
- [Podman Quadlet](https://docs.podman.io/en/v5.8.2/markdown/podman-systemd.unit.5.html)
- [Podman networking](https://docs.podman.io/en/v5.8.2/markdown/podman-network.1.html)
- [Podman SELinux volume labeling](https://docs.podman.io/en/v5.8.2/markdown/podman-run.1.html)
