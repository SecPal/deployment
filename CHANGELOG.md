<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Changelog

## 2026-08-01 - Local Container Integration Stack

### Added

- A test-only Compose stack built from pinned API and frontend Git revisions.
- Explicit API, worker, singleton forensics-worker, scheduler, and migration
  roles.
- Private PostgreSQL and Valkey services pinned by version and digest.
- A loopback-only TLS gateway with a disposable internal CA.
- Runtime-only secret initialization and deterministic Phase B contracts.

### Not included

- No public deployment, production edge, GHCR publication, production secret,
  tenant provisioning, durable application storage, backup, update, or rollback
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
