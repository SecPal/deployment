<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Deployment roadmap

This roadmap points to current owners and preserves completed phase evidence.
Native GitHub relationships and issue state are authoritative for delivery
progress; this summary is not a second work graph.

## Current production direction

The accepted production baseline is Rocky Linux 10.2+ with SELinux enforcing,
rootless Podman/Quadlet application workloads, and host-native PostgreSQL 18.
Application sessions, durable queues, and shared cache are initially
PostgreSQL-backed; Valkey is not part of this baseline.

Production Edge mode is exactly **DIRECT** or **PROTECTED**.
[ADR-019](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-production-edge-layered-security-adr019.md)
owns the normative Edge architecture and trust boundaries.

- **DIRECT:** HAProxy is the Viewer Edge. ADR-019 and
  [#89](https://github.com/SecPal/deployment/issues/89) own the decision;
  [#90](https://github.com/SecPal/deployment/issues/90) and its descendants own
  delivery.
- **PROTECTED:** CloudFront Multi-Tenant is the Viewer Edge; HAProxy is the
  authenticated Origin/backend boundary. The
  [#209 subtree](https://github.com/SecPal/deployment/issues/209) owns portable
  implementation.

The general PROTECTED Sandbox PoC is complete and retired. Its architecture is
accepted. Portable PROTECTED implementation is in progress, with current status
owned by the #209 native graph.

## Active delivery areas

- **Rocky host and SELinux:** current host qualification and production-host work
  are owned by the Rocky/platform delivery graph rooted at
  [#134](https://github.com/SecPal/deployment/issues/134).
- **Native PostgreSQL 18:** the production database contract is owned by
  [#81](https://github.com/SecPal/deployment/issues/81). The containerized
  PostgreSQL 18 used by integration remains disposable test infrastructure.
- **Rootless integration:** the current PostgreSQL 18/no-Valkey fixture is
  implemented in `scripts/quadlet-integration.py`; it is not production
  orchestration.
- **DIRECT:** implementation belongs to the #90 delivery subtree and remains
  distinct from PROTECTED.
- **PROTECTED:** portable capabilities are being delivered by #209 descendants;
  this roadmap does not duplicate their contracts.
- **Recovery:** backup, restore, Recovery Set, and drill work remains with the
  recovery delivery graph rooted at
  [#91](https://github.com/SecPal/deployment/issues/91).
- **Acceptance and runbooks:** production acceptance and operator lifecycle are
  owned by [#115](https://github.com/SecPal/deployment/issues/115) and
  [#116](https://github.com/SecPal/deployment/issues/116).

Production architecture is therefore accepted but not fully implemented. A
capability is current only when its owning delivery contract and evidence say
so; acceptance of the architecture is not an implementation claim.

## Historical phase evidence

The phase descriptions below record what was proven at the time. They do not
define the current production architecture.

### Phase A — Governance bootstrap (complete)

Phase A established repository governance, licensing, deterministic preflight,
and protected `main`. No deployment implementation existed at completion.

### Phase B — Local container integration stack (complete)

Phase B proved the former test-only Docker Compose integration, including its
PostgreSQL/Valkey behavior, Caddy test gateway, browser flow, worker roles,
singleton cardinality, migration, and cleanup. The preserved Phase-B completion
record names `Local Integration / Compose Contract` and shows the historical
check was enforced for `main` at that time. The executable Compose stack has
since been retired; these names remain accurate historical evidence.

### Phase C — Immutable image publishing (complete)

Phase C proved reviewed API and frontend image publication and fail-closed,
digest-only consumption. Phase C is complete, and its GitHub runs and immutable
Git history retain the detailed evidence.

### Former Phase D.1/D.2/D.3 sequence (historical / superseded)

The former sequence recorded a Debian 13/AppArmor production host, D.1a
integration parity, production state/secrets, and a Debian NGINX production
Edge. Those documents and runs remain historical evidence. They are not the
current Rocky/SELinux, PostgreSQL 18, or ADR-019 Edge authority.

The retained non-production Debian cloud-conformance work likewise records its
original environment and evidence honestly. Current Rocky qualification has a
separate owner; history is not rewritten as though Rocky had always been the
decision.

### Former Phase E edge selection (historical / superseded)

The old plan deferred selection of one production Edge until a later phase.
ADR-019 supersedes that planning assumption by accepting DIRECT and PROTECTED.
Implementation now follows the separate owner graphs above.

### Recovery and operations history

Earlier Phase F/G headings described future backup, restore, update, rollback,
and private managed automation. Current recovery, acceptance, and runbook work
uses the owner links above. Private customer inventory, credentials, placement,
rollout, and commercial policy remain outside this public repository.
