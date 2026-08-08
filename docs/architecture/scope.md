<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Deployment architecture scope

This document defines ownership and trust boundaries for the SecPal deployment
reference. Phase B implements the test-only local integration subset, and
Phase C supplies its reviewed API and frontend digests and is complete. Phase
D has not started.

## Repository responsibilities

This repository owns:

- integration contracts;
- the Phase B local Compose orchestration;
- service dependencies;
- service roles and singleton contracts;
- local health checks;
- ephemeral runtime-secret contracts; and
- integration-test documentation.

The reviewed immutable API and frontend images are already consumed here.
Later phases will add the public reference deployment, the selected production
edge and CrowdSec, persistent-volume contracts, backup/restore, update/rollback,
and production operator guidance.

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

- **Local test client:** reaches only the loopback-bound test TLS gateway using
  the separate `app.secpal.example.invalid` and
  `api.secpal.example.invalid` origins on one dynamic port.
- **Test gateway:** terminates disposable local TLS and routes over the internal
  edge network. The API uses Laravel's immediate-peer trust token so gateway
  HTTPS and client metadata survive dynamic bridge addressing. All Phase B
  network peers are stack-owned services. The gateway is not the selected
  production edge.
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
- **Ephemeral private application storage:** a shared named volume mounted by
  the API, both worker roles, scheduler, and migration role. It is destroyed
  after integration testing; durable production storage is deferred.
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

The general worker may be scaled deliberately. Explicit container names make
Compose reject attempts to scale either singleton role; the integration script
derives project-scoped names so parallel canonical runs remain isolated. The
`worker-hash-chain` singleton consumes only `activity-hash-chain`.
`worker-general` consumes `merkle`, `opentimestamp`, and `default` and has no
fixed container name or singleton label. Migrations are an explicit `tools`
profile operation and run exactly once in the integration script, never from
an entrypoint or health check.

## Step A bootstrap contract

Step A established governance, documentation, local validation, and quality CI.
Phase B deliberately revised its temporary absence contract through a regular
feature branch while keeping production settings, committed secrets,
certificates, infrastructure-as-code, and deployment automation forbidden.

## Phase B local integration contract

Phase B:

- consumes the API from one reviewed GHCR OCI index digest;
- consumes the frontend only from its reviewed public OCI index digest after
  anonymous pull and fixed-identity attestation verification;
- uses a local test-only TLS gateway and disposable internal CA;
- exposes separate local frontend and API HTTPS origins;
- avoids a final edge-technology decision;
- exposes only a loopback host port; and
- generates disposable runtime secrets inside an isolated volume;
- uses Valkey for both queues and cache; and
- shares disposable private files between API-based roles.

Before any API-based role or frontend container runs, the real integration
runner validates both resolved Compose images, anonymously pulls each exact
digest with a separate empty Docker configuration, retrieves and validates
each digest-bound OCI Sigstore bundle, raw index, and registry digest header,
and verifies each local digest-matching index against its bundle and fixed
repository, workflow, source ref, source commit, and signer without reopening
the registry. It then exercises
liveness, the frontend document, runtime API origin, CORS, Sanctum CSRF and
cookie behavior, Valkey cache and queue round trips, worker ownership, shared
private storage, explicit migration, browser CSP and service-worker behavior,
singleton cardinalities, and cleanup. The same runner executes on
GitHub-hosted Ubuntu in
`Local Integration / Compose Contract`. Tenant provisioning, API readiness,
public TLS, CrowdSec, durable storage, backups, updates, and rollback remain
outside Phase B.

## Configuration classes

- **Public template:** `compose.yaml`, the test Caddyfile, and validation
  scripts.
- **Local user configuration:** none is required by the canonical test; no
  `.env` file is read.
- **Secrets:** generated at runtime in the `local-secrets` volume, rolled back
  as a set if publication is interrupted, and mounted read-only into
  long-running services.
- **Runtime state:** the temporary PostgreSQL and shared private-storage
  volumes plus per-container tmpfs mounts.
- **Generated artifacts:** the project-scoped locally built gateway image and
  disposable internal CA, both outside Git history and removed by the explicit
  integration test. The published API and frontend digests are never treated
  as local cleanup artifacts.
