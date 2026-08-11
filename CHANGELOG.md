<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Changelog

## Unreleased

### Added

- A manual, protected Debian 13 cloud-conformance workflow for an immutable
  full target SHA with separate credentialed apply, uncredentialed remote test,
  bounded evidence, and independent exact cleanup phases.
- A locked DigitalOcean OpenTofu root for one allowlisted Intel or AMD host,
  per-run Ed25519 access, deterministic ownership/TTL tags, and restricted
  ingress from the active runner.
- A fail-closed scheduled TTL janitor for expired, completely revalidated
  owned Droplets plus static mutation tests for credential, input, provider,
  SSH-state, metadata, cleanup, action-pin, and evidence boundaries.
- Schema-validated, failure-atomically published bootstrap-failure evidence
  with orchestration timestamps and bounded cloud-init diagnostics when a
  disposable host fails before the full conformance collector can run.
- Rendered cloud-init schema admission for both providers and a root-owned,
  closed host-setup stage marker that diagnoses early failures without raw
  logs or credentials.

- A provider-neutral production host and inventory contract.
- A versioned, non-secret production inventory schema, a closed synthetic
  host-facts schema, and examples for both supported architectures.
- Fail-closed inventory and synthetic host-prerequisite validation without
  host access or production mutation.
- An exact Debian 13/trixie host identity and reviewed security-update, reboot,
  rootless Podman/Quadlet maintenance, and major-release lifecycle contract.
- A closed subordinate-ID, systemd user-manager, local Podman graphroot,
  runtime-API denial, and registry-redirection denial contract while preserving
  the historical Docker/Compose integration evidence.
- Effective runtime-package suite, mapping-helper, user-runtime-directory, and
  administrator-only Quadlet search-path evidence.
- Shared path-access admission for host policy and rootless runtime paths, explicit AppArmor
  enforcement evidence, and distinct host-name versus public-origin rules.

### Fixed

- Deferred disposable-operator SSH-key activation until trusted host setup has
  finished, preventing remote bootstrap observation from racing subordinate-ID
  normalization while retaining bounded diagnostic access after setup failure.
- Fail-closed effective SSH-policy admission, a prioritized provider-independent
  drop-in, and username-scoped authorized-key publication before operator access.

## 2026-08-08 - Consume Verified Frontend Image Digest

### Added

- A canonical SecPal frontend OCI index digest and fixed publisher identity.
- Anonymous frontend digest pull, raw OCI index and registry-header binding,
  and offline GitHub Artifact Attestation verification before container
  execution.
- Static, mutation, OCI, credential-isolation, lifecycle, update, and rollback
  contracts for Phase C.4.

### Changed

- Compose now consumes the verified public frontend image and no longer builds
  frontend source or accepts a frontend image override.
- The hardened image verifier receives explicit image, digest, repository,
  workflow, ref, source, signer, and registry-path identities for both API and
  frontend without weakening the existing API contract.
- The integration runner builds only the project-scoped test gateway after
  both published SecPal images have passed verification.

### Post-merge evidence

- Deployment PR `SecPal/deployment#6` merged as
  `4fc2796409b7c37a541f515ccf29236f143fc132`.
- Push-triggered Repository Quality run `31264563173` and Local Integration
  run `31264562902`, Compose Contract job `93120504279`, passed on `main`.
- The hosted integration run verified frontend OCI index digest
  `sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077`
  and API OCI index digest
  `sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e`
  before runtime, then passed the real Compose lifecycle, Playwright, and
  complete project cleanup.
- Phase C is complete. Phase D has not started.

### Not included

- Production deployment, registry writes, API digest updates, Phase D
  implementation, and public infrastructure remain outside this work.

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
