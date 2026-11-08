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

- **DIRECT:** Host-native HAProxy is the Viewer Edge. The
  [accepted DIRECT decision](docs/architecture/decisions/direct-viewer-edge.md)
  records [#89](https://github.com/SecPal/deployment/issues/89) under ADR-019;
  the [#90 subtree](https://github.com/SecPal/deployment/issues/90) owns
  implementation.
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
The [PROTECTED provider-firewall adapter contract](docs/provider-firewall-contract.md)
consumes #214 accepted CloudFront Origin state and defines #169-correlated,
ownership-scoped planning, verification, and fresh-state-bound semantic rollback.
The [portable endpoint-switch contract](docs/endpoint-switch.md) adds exact-state
routing changes without owning writer fencing or Managed rollout policy.
The [PROTECTED CloudFront Viewer Edge contract](docs/cloudfront-viewer-edge.md)
implements the bounded Multi-Tenant Distribution, Distribution Tenant, and
managed Viewer-certificate lifecycle without performing provider mutation.
The [PROTECTED shared WAF contract](docs/cloudfront-waf.md) implements the
distribution-level Anti-DDoS and privacy-minimized logging baseline without
performing provider mutation.

The [public finding and notification contract](docs/public-findings.md) exposes
bounded producer evidence and independent Self-Hosted delivery without granting
detectors, findings or notification adapters production action authority.

The general PROTECTED Sandbox PoC is complete and retired. Portable production
implementation is separately owned by #209; its native graph is authoritative
for current delivery state. ADR-019 and Git history retain the durable PoC
evidence; temporary cloud resources and test credentials are not repository
documentation.

See the [roadmap](docs/roadmap.md) for delivery ownership and
[architecture scope](docs/architecture/scope.md) for navigation. Those documents
do not replace ADR-019, the owning delivery contracts, or their native graphs.

The [Phase-1 public host-base procedure](docs/standard-installation.md) implements
explicit installation and verification for #92. Independent native/OCI admission
remains required before Host Enrollment.

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

### Native Rocky qualification and retained cloud cleanup

Native Rocky Linux 10.2+/SELinux qualification and the accepted AMD64/ARM64
reference-host evidence remain required. See the
[maintained qualification and recovery boundaries](docs/rocky-cloud-qualification.md).

Active GCP provisioning/qualification is retired. GCP and multi-provider
portability #123 are deferred, not completed. The former cloud workflow accepts
only exact retained-state `destroy`; scheduled janitors and all three pinned
provider roots remain until external resource/state obligations are independently
discharged. Source retirement is not proof of provider absence and performs no
cloud, IAM, production or reference-host operation.

## Security

Never commit secrets, `.env` files, private keys, certificates, tokens, or cloud
credentials. Security reports follow the organization-wide
[SecPal security process](https://github.com/SecPal/.github/security/policy).
The repository contents are not approved for production operation.

Repository Quality runs the immutable organization Trivy repository-scan action
against the exact checked-out commit before the required Repository Contract
check can pass. Only a successful CLEAN result is admitted; actionable,
review-required, unknown/stale, malformed, missing, failed, cancelled and skipped
evidence cannot authorize source acceptance. The action has only contents-read
permission and retains bounded, redacted evidence for 14 days.

The shared vulnerability, secret and misconfiguration scanners cover supported
source formats in the complete immutable Git snapshot. Current inputs include
OpenTofu modules/provider declarations, the npm lockfile, the integration
Containerfile and GitHub workflows. Quadlet, systemd, HAProxy, SELinux, shell and
Python sources remain included in the source/secret scan; their specialized
semantic validation remains with existing preflight and conformance owners.
Trivy does not establish semantic coverage for every configuration format.
No deployment-local scanner policy, exception or ignore mechanism is introduced.

The accepted organization v5 contract binds every current Terraform/OpenTofu
source file to its raw Git blob and pinned Trivy's complete native evaluation.
Its evidence explicitly reports REPOSITORY_STATIC coverage, unresolved inputs
and NOT_EXECUTED concrete cloud operations.
Actual run inputs, exact-peer management access, cloud-identity removal and
bounded lifetime/cleanup remain mandatory in the existing trusted-control path.
A source scan supplies no fabricated Terraform values and authorizes no cloud
operation.

[Shared #1236](https://github.com/SecPal/.github/issues/1236) retains historical
evidence only; its expired dispositions are not renewed. The retired GCP
resource definitions are absent from current source; historical findings retain
their original scope. Any finding in retained cleanup source remains blocking
under the unchanged central policy. The gateway image
and Quadlet use the same bounded readiness probe. Missing or unbound source,
incomplete evaluation, invalid diagnostics and stale databases fail closed.
The action and closed v5 schema come from the same immutable accepted shared
revision; no finding is suppressed or declared unaffected.

Repository source security is distinct from native runtime security, Rocky
provider qualification and production acceptance. CLEAN source evidence proves
none of those outcomes and grants no infrastructure or production authority.

## Development

Run deterministic repository checks without starting the integration stack:

```bash
./scripts/preflight.sh
```

The preflight does not install system tools or access production infrastructure.
Install pinned OpenTofu 1.12.5 alongside the existing validation tools for the
retained recovery roots. Exact provider constraints accept both `x.y.z` and
`= x.y.z`; version ranges and manifest/lock disagreement remain forbidden.
The retired GCP insertion/metadata tests are not part of current validation.
Native host, PostgreSQL, backend, failure and cleanup contracts remain in the
preflight. A reported native capability skip is not a passed real-host test.

## Repository boundary

Product code remains in [`SecPal/api`](https://github.com/SecPal/api) and
[`SecPal/frontend`](https://github.com/SecPal/frontend). Their Containerfiles and
build logic are not copied here. This repository consumes reviewed immutable
artifacts and does not fork product build logic.

## License

The repository project license is GNU AGPL 3.0 or later. File-level SPDX and
REUSE metadata apply the current SecPal licensing matrix.
