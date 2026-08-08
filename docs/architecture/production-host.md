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

The first supported reference topology is `single-host`: one Linux host runs
the future Compose project, its data services, the product roles, and the
future public edge. This follows the existing single-project Compose contract,
its one scheduler, its one `activity-hash-chain` worker, and its explicit
one-shot migration role. A single host is the smallest topology whose current
service relationships are already integration-tested and does not invent a
distributed-state or quorum contract.

Multi-host and high availability are deferred and unsupported by schema
version 1. Kubernetes, clustering, multi-region operation, automatic failover,
and provider-managed replacements are also unsupported. This does not prevent
a reviewed future inventory version from adding a multi-host topology.

## Platform and architecture

The only supported host OS is the 64-bit Ubuntu Server 24.04 LTS `noble`
release (`ID=ubuntu`, `VERSION_ID=24.04`). Derivatives and later or earlier
Ubuntu releases fail closed until a reviewed contract update adds them. The
minimum kernel is Linux 6.8, the base kernel of Ubuntu 24.04 LTS.

Both `linux/amd64` and `linux/arm64` are equally supported host architectures.
The reviewed SecPal API and frontend OCI indexes each publish and smoke-test
both platforms, and Docker publishes Ubuntu packages for both. The host-fact
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

- a stable Linux 6.8 or newer Ubuntu kernel (release candidates fail closed);
- unified cgroup v2;
- OverlayFS support;
- enabled AppArmor and seccomp enforcement;
- local `ext4`, or local XFS with `ftype=1`, for every checked state path;
- working `d_type` directory-entry support; and
- the required commands `bash`, `curl`, `df`, `docker`, `findmnt`, `getent`,
  `gh`, `id`, `install`, `mktemp`, `python3`, `realpath`, `sha256sum`, `stat`,
  and `timedatectl`.

Network filesystems, FUSE-backed persistent state, remote Docker contexts,
Docker Desktop, and filesystems without reliable POSIX ownership and modes are
unsupported. D.1 reads synthetic facts; D.8 owns any future fact collector.

## Docker Engine and Compose

The supported daemon is rootful Docker Engine 29.x from the upstream Docker
Ubuntu package family, with Docker Engine 29.6.2 as the minimum security
baseline. Version 30 or later is not silently accepted. A reviewed contract
update must evaluate breaking changes before widening the range.

The supported orchestrator is the `docker compose` CLI plugin in the Compose
v2 line. Docker Compose 2.40.3 is the minimum, and version 3 or later fails
closed until reviewed. The legacy `docker-compose` standalone command is not
accepted. Version detection uses the three-part numeric output recorded in
synthetic facts; later collectors must derive it from `docker version` and
`docker compose version --short` without coercion.

Facts must also report the effective daemon endpoint as
`unix:///var/run/docker.sock`. A TCP, SSH, alternate Unix socket, or otherwise
remote Docker context fails admission even when its version and data-root
values appear compatible.

The Docker daemon and its socket are root-owned. Docker daemon authority is
privileged host authority: a user able to control the daemon can normally
obtain host-root-equivalent access. The unprivileged SecPal service account is
not a member of a Docker-authorized group. Operators use explicit privilege
escalation for daemon operations. No Docker socket is mounted into a product
container.

Rootless Docker Engine is deferred. The current repository has not validated
its bind-mount ownership, privileged-port edge behavior, networking, data-root
layout, or future CrowdSec integration. D.3 and D.4 may not silently enable it.
The Docker data root is inventory-controlled and defaults only in the example
to `/var/lib/docker`.

## Resource admission contract

The figures below are admission floors, not a claim about customer capacity.
There is no production workload measurement yet. The minimum deliberately
reserves room for the simultaneously present API, two worker classes,
scheduler, frontend, PostgreSQL, Valkey, and a future edge, while the
recommended tier doubles compute and memory and adds storage headroom for the
first measurement cycle.

| Resource            |   Minimum | Recommended | Evidence and behavior below the floor                                                                                                                                    |
| ------------------- | --------: | ----------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Logical CPU         |         4 |           8 | Scheduling floor for the current role set; admission fails below 4. Production load tests in D.10 must replace assumptions with measured concurrency.                    |
| RAM                 |     8 GiB |      16 GiB | Allows bounded concurrent services without treating swap as capacity; admission fails below 8 GiB. D.10 measures peak RSS and OOM margin.                                |
| Total local storage |   100 GiB |     250 GiB | Conservative first-host envelope for images plus state paths; admission fails below 100 GiB. D.2 and D.7 replace allocations with measured data growth and backup sizes. |
| Total inodes        | 1,000,000 |   2,000,000 | Protects image layers, logs, framework cache files, and state trees; admission fails below 1,000,000. D.10 records peak inode consumption.                               |

### Quantified minimum envelope

The CPU and RAM floor is the sum of explicit planning shares for the current
eight long-lived roles. These are admission budgets, not measured utilization:

| Role group                              | Logical CPU share | RAM share |
| --------------------------------------- | ----------------: | --------: |
| Host, Docker daemon, and future edge    |              1.00 |     2 GiB |
| PostgreSQL and Valkey                   |              1.00 |     2 GiB |
| API request role                        |              0.75 |   1.5 GiB |
| General and activity-hash-chain workers |              0.75 |   1.5 GiB |
| Scheduler and frontend                  |              0.50 |     1 GiB |
| **Minimum admission envelope**          |          **4.00** | **8 GiB** |

The 100 GiB and 1,000,000-inode floor is likewise an explicit planning sum:

| Planning area                     |     Storage |        Inodes |
| --------------------------------- | ----------: | ------------: |
| Host OS, tools, and configuration |      20 GiB |       110,000 |
| Docker data reserve               |      20 GiB |       200,000 |
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
below, rather than presented as production observations.

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

| Area                        | Absolute free bytes | Free inodes | Notes                                                                                  |
| --------------------------- | ------------------: | ----------: | -------------------------------------------------------------------------------------- |
| Docker data                 |              20 GiB |     200,000 | Image pull and unpack headroom; no automatic pruning contract.                         |
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

## Network and clock assumptions

Inventory records one globally routable public address fact and at least one
non-loopback private address fact. Only reserved documentation networks are
accepted in synthetic examples; carrier-grade NAT and other non-global address
ranges fail admission. Private addresses are exactly RFC 1918 IPv4 or IPv6 ULA;
documentation and benchmarking ranges are not private-use substitutes.
Address facts are strings and are never coerced from numeric or binary YAML
values. Private-address collection order is insignificant, but duplicates and
mismatches fail closed. The public edge will be the only publicly reachable
container boundary; product and data services remain on private container
networks. Firewall mutation, routing, port publication, cloud metadata, and
public reachability checks are outside D.1.

The host has a stable DNS hostname distinct from both application origins.
Frontend and API use separate DNS-name-only HTTPS origins. Origins cannot
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
known container identities. The example uses `secpal-deploy:20000:20000`, but
that value is synthetic and not mandatory.

The account owns reviewed configuration, deployment metadata, logs, and
backup staging. Its home is an absolute state path, its shell is
`/usr/sbin/nologin`, interactive login is disabled, it has no Docker authority,
and it receives no blanket `sudo` rule. It does not own PostgreSQL, the Docker
data root, or undecided edge identities.

Named human operators authorize host changes. Their SSH keys, certificates,
hardware-backed credentials, and privilege policy live outside this
repository and outside inventory. Direct root SSH is unsupported. A human
operator authenticates as a named account and uses audited, explicit privilege
escalation for package, filesystem-owner, daemon, network, or service-manager
operations. D.1 creates no accounts, keys, SSH configuration, or sudoers file.

## Filesystem and mountpoint model

The example paths are provider-neutral defaults, not real host values. Every
inventory path must be absolute, normalized, unique, mutually non-overlapping,
non-root, outside `/tmp`, and separate from the service-account home. Null
UID/GID means the named later issue must select and migrate the runtime identity
before that component can be installed. Every path is limited to 4095 UTF-8
bytes in total and 255 UTF-8 bytes per component, matching the supported Linux
ext4/XFS representation limits. ASCII control characters are forbidden.

| Inventory key                 | Example path                   | Owner and UID:GID                  |   Mode | Class           | Decision owner       |
| ----------------------------- | ------------------------------ | ---------------------------------- | -----: | --------------- | -------------------- |
| `configuration`               | `/srv/secpal/config`           | service account, inventory UID:GID | `0750` | persistent      | D.1                  |
| `deployment_state`            | `/srv/secpal/deployment-state` | service account, inventory UID:GID | `0750` | persistent      | D.1                  |
| `runtime_secrets`             | `/run/secpal/secrets`          | state contract, unset              | `0750` | reconstructable | D.2 (#10)            |
| `postgresql_data`             | `/srv/secpal/postgresql`       | state contract, unset              | `0700` | persistent      | D.2 (#10)            |
| `private_application_storage` | `/srv/secpal/private-storage`  | API runtime `10001:10001`          | `0750` | persistent      | D.1/D.2              |
| `public_application_storage`  | `/srv/secpal/public-storage`   | API runtime `10001:10001`          | `0750` | persistent      | D.2 (#10)            |
| `edge_state`                  | `/srv/secpal/edge`             | edge contract, unset               | `0750` | persistent      | D.3 (#11)            |
| `acme_state`                  | `/srv/secpal/acme`             | TLS contract, unset                | `0700` | persistent      | D.5 (#13)            |
| `crowdsec_state`              | `/srv/secpal/crowdsec`         | CrowdSec contract, unset           | `0750` | persistent      | D.6 (#14)            |
| `logs`                        | `/srv/secpal/logs`             | service account, inventory UID:GID | `0750` | persistent      | D.1; retention later |
| `backup_staging`              | `/srv/secpal/backup-staging`   | service account, inventory UID:GID | `0700` | reconstructable | D.7 (#15)            |
| `docker_data_root`            | `/var/lib/docker`              | Docker daemon `0:0`                | `0711` | persistent      | D.1                  |

`/app/storage/app/private` is business-critical container state and retains the
verified API owner `10001:10001`. It is never merged with PostgreSQL data. The
frontend remains `101:101`, serves HTTP on 8080, has a read-only root filesystem
and writable `/tmp`, and does not own TLS, ACME, or API proxying.

D.1 fixes public application storage as persistent host state on a separate
`10001:10001` path. It may hold only artifacts deliberately classified for
public delivery, never private uploads, credentials, or database state. D.2
must decide its backup and publication lifecycle before it is mounted in
production; the edge must not expose the host path directly.

Logs are persistent operational and security evidence, not reconstructable
state. D.10 owns retention, rotation, optional external shipping, and the
acceptance proof that exhaustion remains bounded.

Valkey is queue/cache infrastructure, not a source of truth. D.1 does not
require a persistent Valkey host path. D.2 decides whether to add one; no
business-backup guarantee follows from that choice.

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

Unknown inventory or host-fact fields, unknown versions, mismatched
architectures, low resources, clock drift, unsupported filesystems, and
dependency contradictions fail before any side effect. Validation errors name
the field or invariant and never print input values or full documents.

D.1 deliberately does not implement host setup, remote access, provider
selection, firewall or DNS changes, TLS/ACME, CrowdSec, secrets, persistent
volume creation, database initialization, backup/restore, Compose production
orchestration, install/update/rollback workflows, or container startup. Those
remain with #10 through #18 according to the parent epic.

## Evidence references

- [Docker Engine Ubuntu platform support](https://docs.docker.com/engine/install/ubuntu/)
- [Docker Engine 29 release notes](https://docs.docker.com/engine/release-notes/29/)
- [Docker Compose plugin installation](https://docs.docker.com/compose/install/linux/)
- [Ubuntu 24.04 LTS release notes](https://documentation.ubuntu.com/release-notes/24.04/)
- [Ubuntu time synchronization](https://documentation.ubuntu.com/server/explanation/networking/about-time-synchronisation/)
- [`docs/api-image-consumption.md`](../api-image-consumption.md)
- [`docs/frontend-image-consumption.md`](../frontend-image-consumption.md)
