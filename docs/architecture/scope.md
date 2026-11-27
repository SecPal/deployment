<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Deployment architecture scope

This document is navigation for deployment ownership and trust boundaries. It
does not define another production architecture or duplicate native GitHub
progress state.

## Current architecture navigation

[ADR-017](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-postgresql-18-canonical-baseline-adr017.md)
owns the PostgreSQL 18 baseline.
[ADR-018](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-production-host-container-runtime-adr018.md)
owns Fedora CoreOS Stable, rootless Podman, Quadlet and SELinux Enforcing for
Managed. It admits independently qualified infrastructure containers. The
[Self-Hosted boundary](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-public-self-hosting-private-managed-operations-adr023.md)
keeps public deployment contracts portable and separate from the Managed control
plane.

[ADR-019](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-production-edge-layered-security-adr019.md)
owns two Edge modes. DIRECT uses HAProxy as Viewer Edge. PROTECTED uses
CloudFront Multi-Tenant as Viewer Edge and HAProxy as Origin. Each mode has
its own implementation graph and qualification.
[DIRECT](https://github.com/SecPal/deployment/issues/90) ·
[PROTECTED](https://github.com/SecPal/deployment/issues/209)

[ADR-020](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-production-state-recovery-authority-separation-adr020.md)
owns state and recovery authority. Its failure-class-specific recovery evidence
and [ADR-022 topology rules](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-deployment-topology-high-availability-adr022.md)
apply independently of the platform adapter.

Use the [deployment roadmap](../roadmap.md) for current FCOS qualification and
Production Acceptance. The retained [Rocky host contract](production-host.md)
and [native PostgreSQL contract](native-postgresql.md) bind earlier evidence
to its original subjects. [Retained cloud recovery](../rocky-cloud-qualification.md)
has its own exact-run scope.

## Repository responsibilities

This repository owns public, portable deployment contracts and their evidence,
including:

- reviewed immutable API and frontend artifact consumption;
- the active disposable rootless Podman/Quadlet integration;
- service roles, dependencies, singleton rules, health, and cleanup;
- production implementation delivered by its owning issue subtrees; and
- public recovery, acceptance, and operator contracts.

The reviewed immutable API and frontend images are already consumed here.
Product logic, product Containerfiles, private customer inventories, private
hosting credentials, internal operations automation, and customer data remain
outside this repository.

## Trust boundaries

- **Disposable integration:** the test gateway alone exposes a loopback fixture
  port. API, frontend, workers, scheduler, migration, and PostgreSQL stay inside
  the test networks. PostgreSQL 18 and private files are destroyed during exact
  cleanup. This is not production evidence.
- **Product workloads:** API, frontend, workers, and scheduler remain separate
  rootless workloads. They do not own public TLS, public routing, runtime
  sockets, or production database authority.
- **Production database:** PostgreSQL 18 is the persistent source of truth. The
  Managed reference uses a separately qualified container. Backup and recovery
  retain their independent authorities.
- **Production Edge:** Viewer identity, Viewer TLS, Origin TLS, Origin
  authentication, WAF/AMR, caching, and the PROTECTED evidence boundary belong
  to ADR-019. This navigation does not restate them.
- **External systems:** providers, DNS, certificates, and cloud resources are
  accessed only by their explicitly authorized implementation contracts. No
  credentials or mutable live state belong in Git.

## Singleton invariants

The active integration preserves:

```text
activity-hash-chain worker: exactly one
scheduler: exactly one
```

Migration is an explicit one-shot dependency and never runs from an entrypoint
or health check. The general worker remains independently scalable.

## Current disposable integration

[`scripts/quadlet-integration.py`](../../scripts/quadlet-integration.py) renders
the closed no-Valkey topology using rootless Podman, native Quadlet, and a
systemd user target. Product images pass reviewed digest and publisher gates
before execution and start with `Pull=never`. The test-only Caddy gateway and
frontend `nginx-unprivileged` userspace are not production Viewer-Edge choices.

The full service, security, lifecycle, and evidence contract is in
[`docs/quadlet-integration.md`](../quadlet-integration.md).
