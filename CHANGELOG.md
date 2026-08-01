<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Changelog

## 2026-08-01 - Local Container Integration Stack

### Added

- A test-only Compose stack built from pinned API and frontend Git revisions.
- An API role, a scalable general worker, a dedicated hash-chain singleton,
  scheduler singleton, and explicit migration role.
- Private PostgreSQL and Valkey services pinned by version and digest.
- A loopback-only TLS gateway with separate app/API origins and a disposable
  internal CA.
- Runtime-only secret initialization and deterministic Phase B contracts.
- Isolated local test projects, image tags, and loopback ports with fail-closed
  process-group signal forwarding and cleanup.
- Port-aware SPA session configuration and immediate-peer proxy trust for the
  local TLS gateway.
- Compose scaling guards and instance-level validation for the singleton worker
  and scheduler.
- Rollback and automatic recovery for interrupted runtime-secret publication.
- Bounded automatic loopback-port reselection after bind collisions, strict
  Compose v2 validation, and absolute runtime-secret path enforcement.
- A shared sensitive-path contract covering tracked, untracked, and ignored
  repository paths.
- Valkey-backed cache and queue contracts with worker-specific runtime probes.
- Shared disposable private storage with cross-role visibility and permission
  checks.
- A real Playwright Chromium contract for CORS, Sanctum CSRF, secure cookies,
  runtime routing, CSP, and service-worker behavior.
- The `Local Integration / Compose Contract` hosted workflow for the actual
  Compose lifecycle.

### Not included

- No public deployment, production edge, GHCR publication, production secret,
  tenant provisioning, durable production storage, backup, update, or rollback
  automation is included.

## 2026-08-01 - Bootstrap Deployment Repository

### Added

- Repository governance and security boundaries.
- SecPal licensing and REUSE metadata.
- Architecture scope and acceptance-driven roadmap documentation.
- A local Step A repository contract and deterministic preflight validation.
- Minimal repository-quality CI without deployment execution.

### Not included

- No deployment, Compose, container, image, edge, secret, or production
  configuration is included.
