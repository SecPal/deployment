<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Deployment architecture scope

This document defines ownership and trust boundaries for the SecPal deployment
reference. Phase B implemented the original test-only local integration
subset, Phase C supplied its reviewed API and frontend digests, and D.1a moves
the active disposable runtime to native rootless Podman and Quadlet. D.1 and
D.1a do not implement a production deployment.

## Repository responsibilities

This repository owns:

- integration contracts;
- the active D.1a rootless Podman/Quadlet integration orchestration;
- the historical Phase B local Compose orchestration and evidence;
- service dependencies;
- service roles and singleton contracts;
- local health checks;
- ephemeral runtime-secret contracts; and
- integration-test documentation.

The reviewed immutable API and frontend images are already consumed here.
Later Phase-D work will add production persistence and secret contracts, the
selected production edge and CrowdSec, backup/restore, update/rollback, and
production operator guidance.

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
In the active D.1a runtime only the gateway joins the internal edge network and
publishes the controlled loopback fixture port; the application and edge
networks remain separate and internal. The retained Compose evidence used its
historical host-access bridge. Production traffic and public exposure are not
implemented.

## Singleton invariants

Both the historical Phase B and active D.1a contracts enforce:

```text
activity-hash-chain worker: exactly one
scheduler: exactly one
```

The historical Compose contract allowed deliberate general-worker scaling and
used explicit container names to reject singleton scaling. The active closed
Quadlet set generates one instance of each role with run-scoped names so
parallel canonical runs remain isolated. The
`worker-hash-chain` singleton consumes only `activity-hash-chain`.
`worker-general` consumes `merkle`, `opentimestamp`, and `default` and has no
singleton label. In D.1a migration is an explicit one-shot systemd dependency
and runs exactly once, never from an entrypoint or health check.

## Step A bootstrap contract

Step A established governance, documentation, local validation, and quality CI.
Phase B deliberately revised its temporary absence contract through a regular
feature branch while keeping production settings, committed secrets,
certificates, infrastructure-as-code, and deployment automation forbidden.

## Phase B local integration contract

This section is the historical completion record. Phase B:

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

## Active D.1a integration contract

The active runner retains the Phase B/C behavioral proof while replacing the
execution layer with rootless Podman, native Quadlet-generated user services,
and a native systemd user target. Both product images pass the same exact OCI
index and fixed-publisher attestation gates before either image can execute;
then their Quadlets use `Pull=never`.

PostgreSQL and Valkey readiness gates the one-shot migration, successful
migration gates API-based application roles, and healthy API/frontend gates
the integration gateway. Runtime inspection proves `crun`, exact non-root
identities, read-only roots, bounded writable paths, dropped capabilities,
`no-new-privileges`, AppArmor when available, exact network membership, and
the absence of unintended host ports or sockets. Cleanup addresses only the
run's deterministic names and labels and verifies unrelated resources survive.
The full service, security, lifecycle, and hosted-evidence contract is in
[`../quadlet-integration.md`](../quadlet-integration.md).

## Configuration classes

- **Active integration definitions:** constrained generated Quadlets, a native
  systemd user target, the test Caddyfile, and validation scripts.
- **Historical template:** `compose.yaml` and its original runner remain Phase
  B/C evidence, not the active runtime.
- **Local user configuration:** none is required by the canonical test; no
  `.env` file is read.
- **Secrets:** generated at runtime in the `local-secrets` volume, rolled back
  as a set if publication is interrupted, and mounted read-only into
  long-running services.
- **Runtime state:** the temporary PostgreSQL and shared private-storage
  volumes plus per-container tmpfs mounts.
- **Generated artifacts:** the run-scoped locally built gateway image and
  disposable internal CA, both outside Git history and removed by the explicit
  integration test. The published API and frontend digests are never treated
  as local cleanup artifacts.
