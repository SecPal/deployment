<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Deployment architecture scope

This document is the deployment documentation index and ownership map. It
identifies current guidance, implemented integration contracts, planned
production authorities, and historical records. It does not restate the
technical contracts owned by their issues, and it does not mirror GitHub graph
or progress state.

## Current implemented authority

The repository has one implemented application runtime:
[the disposable rootless Podman/Quadlet integration](../quadlet-integration.md).
It uses reviewed immutable API and frontend images, a PostgreSQL 18.6 test
fixture, database-backed cache/queue/session behavior, one general worker, one
dedicated hash-chain worker, one scheduler, one-shot migration, disposable
private storage, and a narrowly scoped Caddy test gateway.

The integration is test-only. Its PostgreSQL container is not production
PostgreSQL, its private-storage volume is not durable production storage, and
its Caddy gateway is not a public edge. The frontend image's
nginx-unprivileged process is product-image userspace and is likewise not
production ingress.

The current immutable product-image authorities are:

- [API image consumption](../api-image-consumption.md); and
- [frontend image consumption](../frontend-image-consumption.md).

Those documents retain explicitly labelled Phase C Docker Registry and Compose
evidence where technically accurate. That historical/protocol terminology does
not create a current Docker/Compose deployment path.

## Current production target owners

Production architecture is a target, not a runnable capability on current
`main`. Follow the owning issue for technical content and native delivery state:

- [#80 — Rocky Linux 10.2+ / SELinux production
  host](https://github.com/SecPal/deployment/issues/80);
- [#81 — host-native PostgreSQL 18 under
  systemd/SELinux](https://github.com/SecPal/deployment/issues/81);
- [#85 — layered security and socketless runtime
  detection](https://github.com/SecPal/deployment/issues/85);
- accepted [ADR-019 — production-edge mode
  authority](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-production-edge-layered-security-adr019.md),
  which makes `DIRECT` and `PROTECTED` orthogonal to deployment topology;
- [#89 — `DIRECT` host-native HAProxy Viewer Edge, external Certbot, and
  trusted-client boundary](https://github.com/SecPal/deployment/issues/89);
- [#209 — portable `PROTECTED` public Viewer Edge and authenticated Origin
  coordination](https://github.com/SecPal/deployment/issues/209);
- [#91 — Barman, Borg, Recovery Sets, and restore-drill
  coordination](https://github.com/SecPal/deployment/issues/91); and
- [#117 — current Rocky/SELinux cloud
  conformance](https://github.com/SecPal/deployment/issues/117).

Together these owners define a Rocky Linux 10.2+ host with SELinux enforcing,
rootless Podman/systemd/Quadlet application containers, host-native PostgreSQL
18, no Valkey, private product backends, an ADR-019-selected production-edge
mode, layered nftables/CrowdSec/AppSec security, socketless runtime detection,
durable private files, Barman/Borg recovery, Recovery Sets, and isolated
restore evidence.

This index does not claim those owner contracts are implemented. In particular,
Issue #81 has not yet supplied the runnable native production PostgreSQL path. The
disposable PostgreSQL fixture must not be promoted to fill that gap.

## Current cloud boundary

[Rocky cloud qualification](../rocky-cloud-qualification.md) records in-progress
engineering evidence and explicitly outstanding real-system proof. It is not a
production provisioning guide.

The local #126 renderer emits the current 15-artifact no-Valkey integration
topology. The downstream cloud workload/evidence client still expects the old
16-artifact interface. [#119](https://github.com/SecPal/deployment/issues/119)
owns that migration and is blocked by
[#118](https://github.com/SecPal/deployment/issues/118). Until it lands, local
integration evidence cannot be presented as migrated Rocky cloud-workload
evidence.

## Historical architecture records

The following files preserve completed pre-rebaseline decisions. Their status
banners are authoritative for navigation; their bodies remain accurate
historical records and are not current administrator instructions:

- [D.1 Debian/AppArmor host](production-host.md);
- [D.1 inventory](production-inventory.md);
- [D.2 state](production-state.md);
- [D.2 secrets](production-secrets.md);
- [superseded Debian/NGINX production-edge ADR](decisions/production-edge.md);
  and
- [Debian cloud conformance](../ci-cloud-conformance.md).

Git history, closed issues and pull requests, and immutable workflow runs
preserve Phase B/C and D.1/D.1a evidence. The repository intentionally keeps no
runnable historical Compose stack or compatibility directory.

## Trust boundaries

### Disposable integration

- The test client reaches one loopback-only gateway using separate frontend and
  API origins.
- The Caddy fixture terminates disposable local TLS and routes only within the
  test networks.
- Frontend has no database credential or private-file authority.
- API handles application HTTP and remains separate from public-edge duties.
- General worker and dedicated hash-chain worker have distinct queue ownership.
- Exactly one scheduler and one hash-chain worker exist.
- Migration is explicit, one-shot, and never initiated by an entrypoint or
  health check.
- PostgreSQL 18 and private-file storage are disposable fixtures destroyed by
  exact cleanup.

### Production target

- In `DIRECT`, host-native HAProxy is the public Viewer Edge and external
  Certbot owns Viewer TLS under #89.
- In `PROTECTED`, the portable edge under #209 is the public Viewer Edge;
  HAProxy is the authenticated Origin/backend and does not terminate public
  Viewer traffic.
- Product containers remain private in both modes.
- PostgreSQL 18 is host-native infrastructure, not a product container.
- PostgreSQL is the initial relational, session, durable-queue, and shared-cache
  authority; there is no Valkey service.
- Durable private files are distinct from container layers and integration
  volumes.
- nftables, CrowdSec host decisioning, AppSec/Coraza, and socketless detection
  are layered host security rather than product-container authority.
- Barman, Borg, independent recovery copies, Recovery Sets, and isolated drills
  own recoverability rather than runtime volumes or replication alone.

## Repository responsibilities

This repository owns portable deployment contracts, the disposable integration
runtime, current/historical navigation, provider-neutral conformance, and public
self-hosting evidence. It does not own Laravel, React, or Android product logic;
product Containerfiles; customer inventories or data; production credentials;
private keys; provider-specific managed fleet orchestration; or internal SecPal
operations policy.
