<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Changelog

## 2026-08-03 - Consume Verified API Image Digest

### Added

- A canonical SecPal API OCI index digest shared by all API-based roles.
- An anonymous digest pull and GitHub Artifact Attestation gate before any API
  execution.
- Static and lifecycle contracts for digest identity, signer identity,
  fail-closed ordering, credential absence, and temporary configuration
  cleanup.
- Reviewed digest update and rollback documentation.

### Changed

- The local integration runner builds only the pinned frontend and test
  gateway inputs; the API source-build and project-local API tag are removed.
- The public OCI Sigstore bundle and raw digest-matching index are retrieved
  through GHCR's anonymous Distribution flow. GitHub CLI verifies the private
  local index without reopening the registry.
- GHCR blob redirects use their real, tightly validated CDN path shape, and the
  verifier fixes `github.com`, removes inherited GitHub host and token inputs,
  logs the effective GitHub CLI version, and requires the attestation command.
- The anonymous API pull uses an empty private Docker configuration and removes
  inherited `DOCKER_AUTH_CONFIG` from the exact pull process.
- The hosted verifier uses the official GitHub CLI 2.97.0 release archive,
  pinned by its published SHA-256 checksum and enforced again at runtime.
- The one-shot migration uses Compose's explicit non-interactive mode so the
  same lifecycle runs without a TTY on hosted CI.

### Not included

- Frontend publication, Phase D, production host automation, real
  infrastructure changes, and production readiness remain outside this work.

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
