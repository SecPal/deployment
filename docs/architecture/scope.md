<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Deployment architecture scope

This document defines the intended ownership and trust boundaries for the
future SecPal deployment reference. It does not describe a runnable stack.

## Repository responsibilities

In later phases, this repository will own:

- integration contracts;
- Compose orchestration;
- service dependencies;
- service roles and singleton contracts;
- edge configuration and CrowdSec integration;
- health checks;
- secret-mount contracts;
- persistent data volumes;
- backup and restore procedures;
- update and rollback procedures; and
- operator documentation.

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

The future architecture separates the following trust zones:

- **Public client:** untrusted traffic entering through the public edge only.
- **Public edge:** terminates public routing and TLS, applies edge policy, and
  later hosts CrowdSec integration.
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
- **Secret mounts:** runtime-only, least-authority inputs that never enter images
  or repository history.
- **Persistent private storage:** non-public application data protected by
  explicit backup and restore contracts.
- **External services:** separately authenticated dependencies outside the
  deployment trust domain.

Public traffic must not bypass the edge. Data services, workers, the scheduler,
secret mounts, and persistent private storage must not be publicly exposed.

## Singleton invariants

The future orchestration contract must enforce:

```text
activity-hash-chain worker: exactly one
scheduler: exactly one
```

General-purpose workers may later be scaled deliberately. Migrations will be
explicit one-time operations, never entrypoint or health-check side effects.

## Step A bootstrap contract

Step A contains governance, documentation, local validation, and quality CI
only. Compose files, Dockerfiles, container definitions, production settings,
secrets, certificates, infrastructure-as-code, and deployment automation are
forbidden. The repository contract encodes this temporary absence policy and
must be deliberately revised when Step B begins.

## Initial integration strategy

Future Step B will:

- build the API and frontend locally from pinned Git commits;
- avoid a GHCR dependency;
- use a local test-only TLS gateway;
- avoid a final edge-technology decision;
- expose no service publicly; and
- use no production secrets.

These are future acceptance constraints, not current capabilities.
