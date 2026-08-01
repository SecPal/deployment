<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Deployment architecture scope

This document defines ownership and trust boundaries for the SecPal deployment
reference. Phase B implements only the test-only local integration subset.

## Repository responsibilities

This repository owns:

- integration contracts;
- the Phase B local Compose orchestration;
- service dependencies;
- service roles and singleton contracts;
- local health checks;
- ephemeral runtime-secret contracts; and
- integration-test documentation.

Later phases will add immutable publication, the public reference deployment,
the selected production edge and CrowdSec, persistent-volume contracts,
backup/restore, update/rollback, and production operator guidance.

## Out of scope

This repository does not own:

- Laravel product logic;
- React product logic;
- Android code;
- product Dockerfiles;
- private customer inventories;
- private hosting credentials;
- DNS-provider or cloud-provider credentials;
- internal SecPal operations automation; or
- customer data.

## Trust boundaries

The architecture separates the following trust zones:

- **Local test client:** reaches only the loopback-bound test TLS gateway at
  `127.0.0.1:8443` using `secpal.example.invalid`.
- **Test gateway:** terminates disposable local TLS and routes over the internal
  edge network. It is not the selected production edge.
- **Frontend container:** serves the frontend image and has no direct database
  or secret-store authority.
- **API HTTP container:** handles authenticated application requests and is
  distinct from public-edge responsibilities.
- **Worker containers:** execute explicitly assigned queue roles without public
  ingress.
- **Scheduler container:** initiates scheduled work under a singleton contract.
- **PostgreSQL:** persistent source of truth on a private data boundary.
- **Valkey:** private queue and cache service containing no authoritative
  replacement for PostgreSQL data.
- **Ephemeral secret volume:** runtime-generated, least-authority inputs that
  never enter images, command lines, logs, or repository history.
- **Ephemeral application storage:** per-container test state that is destroyed
  after integration testing. Persistent private storage is deferred.
- **External services:** separately authenticated dependencies outside the
  deployment trust domain.

The API, frontend, workers, scheduler, PostgreSQL, and Valkey publish no ports.
Only the gateway joins the host-access bridge; the product-facing edge and
application networks remain internal. Production traffic and public exposure
are not implemented.

## Singleton invariants

The Phase B orchestration contract enforces:

```text
activity-hash-chain worker: exactly one
scheduler: exactly one
```

The default worker may be scaled deliberately. The single forensics worker is
the only consumer of `activity-hash-chain`, `merkle`, and `opentimestamp` in
Phase B. Migrations are an explicit `tools` profile operation and run exactly
once in the integration script, never from an entrypoint or health check.

## Step A bootstrap contract

Step A established governance, documentation, local validation, and quality CI.
Phase B deliberately revised its temporary absence contract through a regular
feature branch while keeping production settings, committed secrets,
certificates, infrastructure-as-code, and deployment automation forbidden.

## Phase B local integration contract

Phase B:

- builds the API and frontend locally from pinned Git commits;
- avoids a GHCR dependency;
- uses a local test-only TLS gateway and disposable internal CA;
- avoids a final edge-technology decision;
- exposes only a loopback host port; and
- generates disposable runtime secrets inside an isolated volume.

The API liveness endpoint, frontend document, runtime API origin, private data
services, explicit migration, and singleton cardinalities are exercised by
`scripts/local-integration.sh`. Tenant provisioning, API readiness, public TLS,
CrowdSec, durable storage, backups, updates, and rollback remain outside Phase
B.

## Configuration classes

- **Public template:** `compose.yaml`, the test Caddyfile, and validation
  scripts.
- **Local user configuration:** none is required by the canonical test; no
  `.env` file is read.
- **Secrets:** generated at runtime in the `local-secrets` volume and mounted
  read-only into long-running services.
- **Runtime state:** the temporary PostgreSQL volume and per-container tmpfs
  mounts.
- **Generated artifacts:** project-scoped locally built images and the
  disposable internal CA, all outside Git history and removed by the explicit
  integration test.
