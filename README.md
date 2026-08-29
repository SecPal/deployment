<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# SecPal Deployment

SecPal Deployment is the public home for SecPal integration, self-hosting,
deployment contracts, edge and security integration, and operational recovery
design.

> This repository does not yet provide a production-ready deployment. Its one
> runnable application topology is a disposable integration fixture.

## What is implemented now

The current local integration uses rootless Podman, native Quadlet-generated
systemd user services, and reviewed immutable API and frontend images. It has
no Docker or Compose fallback, no runtime socket/API dependency, no host
networking, and no Valkey or Redis service.

The renderer creates nine containers, two internal networks, three disposable
volumes, and one systemd user target:

- secret initialization;
- a PostgreSQL 18.6 integration fixture;
- one explicit one-shot migration;
- API and frontend product roles;
- a general worker;
- exactly one dedicated `activity-hash-chain` worker;
- exactly one scheduler; and
- a narrowly scoped Caddy test gateway on loopback.

The application roles use `CACHE_STORE=database`,
`QUEUE_CONNECTION=database`, and `SESSION_DRIVER=database`. The PostgreSQL
container, its `/var/lib/postgresql/18/docker` data directory, the test gateway,
and integration storage are disposable test infrastructure. They are not the
production database, edge, or durable private-file design.

Run the integration only on a host that satisfies the documented test-runtime
prerequisites and root-owned Quadlet search-path policy:

```bash
python3 scripts/quadlet-integration.py
```

See the [current integration contract](docs/quadlet-integration.md) for its
closed topology, lifecycle, security, and cleanup rules.

## Current production target

The production architecture below is the current target, not an implemented
administrator runbook. Its owning issues remain authoritative for technical
decisions and delivery state:

- [#80](https://github.com/SecPal/deployment/issues/80) owns the Rocky Linux
  10.2+ host contract, SELinux enforcing confinement, and the rootless Podman,
  systemd, and Quadlet application boundary.
- [#81](https://github.com/SecPal/deployment/issues/81) owns host-native
  PostgreSQL 18 under systemd/SELinux. Production PostgreSQL is infrastructure,
  not a SecPal product container, and the repository does not yet provide that
  runnable production path.
- The production application topology has no Valkey. PostgreSQL owns relational
  state plus the initial database-backed sessions, durable queues, and shared
  cache. API, frontend, general workers, the dedicated hash-chain worker,
  scheduler, and one-shot migration remain distinct roles.
- [#89](https://github.com/SecPal/deployment/issues/89) owns the host-native
  HAProxy production edge, external Certbot ACME, trusted-client identity, and
  layered nftables, CrowdSec, and AppSec/Coraza security seams. Caddy remains a
  disposable integration gateway, and nginx-unprivileged remains frontend
  product-image userspace; neither is the production public edge.
- [#85](https://github.com/SecPal/deployment/issues/85) owns layered production
  security, including socketless runtime detection. Product containers do not
  receive public TLS, firewall authority, or a runtime socket/API.
- [#91](https://github.com/SecPal/deployment/issues/91) and its descendants own
  Barman PostgreSQL recovery, Borg private-file recovery, topology-independent
  Recovery Sets, and isolated restore drills. Disposable integration volumes
  are not production storage or backup evidence.
- [#117](https://github.com/SecPal/deployment/issues/117) and its descendants
  own current Rocky/SELinux cloud conformance. Completed Debian/AppArmor cloud
  evidence is historical and is not a supported production or compatibility
  path.

No manual workaround in this repository completes these target contracts.
Follow each owning issue and its native GitHub relationships for current
implementation status.

## Known implementation boundaries

The former containerized production database path was retired before its
host-native replacement landed. Until #81 is delivered, there is intentionally
no runnable production PostgreSQL procedure here; the disposable PostgreSQL 18
fixture must not be promoted as a workaround.

The local integration renderer now emits the 15-artifact, no-Valkey topology.
The downstream cloud workload/evidence client still expects the superseded
16-artifact interface. [#119](https://github.com/SecPal/deployment/issues/119)
owns that migration and remains blocked by
[#118](https://github.com/SecPal/deployment/issues/118). Local integration
success therefore does not claim current cloud-workload conformance.

## Historical evidence

Phase B/C and the completed D.1/D.1a/D.2/D.3 records describe earlier
pre-production contracts. They are retained as immutable design and validation
evidence, not as administrator instructions or compatibility paths.

- Phase B/C delivery is recorded by deployment merge commit
  `4fc2796409b7c37a541f515ccf29236f143fc132`, Repository Quality run
  `31264563173`, and Local Integration run `31264562902`.
- [Issue #125](https://github.com/SecPal/deployment/issues/125) removed the
  executable Compose-era stack from current `main`; Git, the closed issue, and
  its merged delivery preserve that evidence.
- [PR #204](https://github.com/SecPal/deployment/pull/204) delivered the current
  PostgreSQL 18, database-backed, no-Valkey disposable integration. The current
  required runtime checks are `Quadlet Contract (amd64)` and
  `Quadlet Contract (arm64)`.
- Historical Debian host, inventory, state, secret, edge, and cloud documents
  are indexed as superseded records in the
  [architecture scope](docs/architecture/scope.md).

## Documentation navigation

- [Deployment roadmap](docs/roadmap.md): implemented versus target versus
  historical status.
- [Architecture scope](docs/architecture/scope.md): document authority,
  ownership, and current/historical navigation.
- [API image consumption](docs/api-image-consumption.md) and
  [frontend image consumption](docs/frontend-image-consumption.md): reviewed
  immutable product-image identities and their Phase C evidence.
- [Rocky cloud qualification](docs/rocky-cloud-qualification.md): in-progress
  engineering evidence, not completed production or cloud-conformance support.

## Security and development

Never commit secrets, `.env` files, private keys, certificates, tokens, cloud
credentials, or customer data. Security reports follow the organization-wide
[SecPal security process](https://github.com/SecPal/.github/security/policy).

Run deterministic repository validation without starting the integration
fixture or accessing a container runtime:

```bash
./scripts/preflight.sh
```

The preflight requires the locally installed tools named by its error messages;
it does not install dependencies.

## Repository boundary

Product code remains in [`SecPal/api`](https://github.com/SecPal/api) and
[`SecPal/frontend`](https://github.com/SecPal/frontend). SecPal-owned current
build contracts use `Containerfile` terminology. Product Containerfiles and
build logic are not copied into this repository. Technically accurate Docker
Registry, OCI, historical Compose, and third-party terminology remains where it
describes those exact protocols or records.

## License

The repository project license is GNU AGPL 3.0 or later. File-level SPDX and
REUSE metadata apply the repository licensing matrix.
