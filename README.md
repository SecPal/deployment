<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# SecPal Deployment

SecPal Deployment is the public reference for reproducible SecPal integration,
self-hosting, deployment contracts, container orchestration, edge and security
integration, and operational procedures for backup, restore, and updates.

## Implemented disposable integration

The implemented stack is a test-only integration fixture built with rootless
Podman, native Quadlet, and systemd user services. Its constrained renderer
creates a disposable PostgreSQL 18 container, API, frontend, general worker,
one `activity-hash-chain` worker, one scheduler, a one-shot migration, and a
test-only routing gateway. Sessions, durable queues, and shared cache behavior
are database-backed; the fixture has no Valkey service.

Only the gateway publishes one controlled loopback port. The fixture exercises
image admission, health, browser behavior, service ordering, restarts, and exact
cleanup. It does not provision a tenant, expose a public service, persist
production data, or define the production Edge.

It is not a production-ready deployment.

Run it explicitly after installing its documented prerequisites:

```bash
python3 scripts/quadlet-integration.py
```

See the [integration contract](docs/quadlet-integration.md) for its service map,
security boundaries, and lifecycle evidence.

## Accepted production architecture

The accepted production direction is Rocky Linux 10.2+ with SELinux enforcing,
rootless Podman/Quadlet application workloads, and host-native PostgreSQL 18.
PostgreSQL initially owns relational data, sessions, durable queues, and shared
cache; Valkey is not part of the production baseline.

[ADR-019](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-production-edge-layered-security-adr019.md)
is the normative owner of the two accepted Edge modes and their Viewer/Origin
trust boundaries:

- **DIRECT:** HAProxy is the Viewer Edge. ADR-019 and
  [deployment #89](https://github.com/SecPal/deployment/issues/89) own the
  decision; the [DIRECT delivery subtree](https://github.com/SecPal/deployment/issues/90)
  owns implementation.
- **PROTECTED:** CloudFront Multi-Tenant is the Viewer Edge and HAProxy remains
  the Origin/backend boundary. ADR-019 owns the architecture; the
  [#209 descendants](https://github.com/SecPal/deployment/issues/209) own the
  portable implementation.

Architecture acceptance does not establish implementation. DIRECT and
PROTECTED have separate implementation owners: the #90 and #209 native graphs
are authoritative for their current delivery state.

The public [portable provider capability contract](docs/provider-capability-contract.md)
defines bounded create, inspect, rebuild, and delete adapter mechanics without
embedding provider selection, customer/fleet state, or commercial policy.

The general PROTECTED Sandbox PoC is complete and retired. Portable production
implementation is separately owned by #209; its native graph is authoritative
for current delivery state. ADR-019 and Git history retain the durable PoC
evidence; temporary cloud resources and test credentials are not repository
documentation.

See the [roadmap](docs/roadmap.md) for delivery ownership and
[architecture scope](docs/architecture/scope.md) for navigation. Those documents
do not replace ADR-019, the owning delivery contracts, or their native graphs.

## Architecture principles

- Public and managed installations use the same reviewed product images.
- The API and frontend remain deployment-neutral and use separate images.
- PostgreSQL is the persistent source of truth.
- The `activity-hash-chain` role and scheduler each have exactly one instance.
- Product containers do not own public routing or Viewer TLS.
- Production secrets never enter this repository or product images.
- Published images are admitted only through reviewed immutable digests.
- Private managed-hosting inventory, policy, credentials, and automation remain
  outside this public repository.

## Historical evidence

### Phase B/C

Phase B completed in the required check context
`Local Integration / Compose Contract`. Phase C is complete. The historical
Compose/Valkey/Caddy lifecycle, immutable image digests, merge commits, and
hosted run records remain evidence in Git and GitHub; they are not maintained as
an executable compatibility runtime or current production direction.

The active checks are `Local Integration / Quadlet Contract (amd64)` and
`Local Integration / Quadlet Contract (arm64)`. The current integration runtime
is exclusively rootless Podman, systemd-user, and native Quadlet.

### Ephemeral Debian 13 cloud conformance

The repository retains the historical
[Debian 13 cloud conformance](docs/ci-cloud-conformance.md) contract and evidence.
It is non-production and does not define the current production OS direction.
Current ephemeral host qualification is the separate
[Rocky Linux 10.2 contract](docs/rocky-cloud-qualification.md). Neither record
claims production provisioning or operation.

## Security

Never commit secrets, `.env` files, private keys, certificates, tokens, or cloud
credentials. Security reports follow the organization-wide
[SecPal security process](https://github.com/SecPal/.github/security/policy).
The repository contents are not approved for production operation.

## Development

Run deterministic repository checks without starting the integration stack:

```bash
./scripts/preflight.sh
```

The preflight installs nothing and does not access production infrastructure.

## Repository boundary

Product code remains in [`SecPal/api`](https://github.com/SecPal/api) and
[`SecPal/frontend`](https://github.com/SecPal/frontend). Their Containerfiles and
build logic are not copied here. This repository consumes reviewed immutable
artifacts and does not fork product build logic.

## License

The repository project license is GNU AGPL 3.0 or later. File-level SPDX and
REUSE metadata apply the current SecPal licensing matrix.
