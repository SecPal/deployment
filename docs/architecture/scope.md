<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Deployment architecture scope

This document is navigation for deployment ownership and trust boundaries. It
does not define another production architecture or duplicate native GitHub
progress state.

## Current architecture navigation

The accepted production direction uses Rocky Linux 10.2+ with SELinux
enforcing, rootless Podman/Quadlet application workloads, and host-native
PostgreSQL 18. PostgreSQL initially supplies sessions, durable queues, and shared
cache as well as relational persistence; the current baseline has no Valkey.

[ADR-019](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-production-edge-layered-security-adr019.md)
owns the normative DIRECT/PROTECTED Edge architecture.

- In **DIRECT**, HAProxy is the Viewer Edge. ADR-019 and
  [deployment #89](https://github.com/SecPal/deployment/issues/89) own the
  decision; [#90](https://github.com/SecPal/deployment/issues/90) descendants
  own implementation.
- In **PROTECTED**, CloudFront Multi-Tenant is the Viewer Edge and HAProxy is the
  Origin/backend boundary. [#209](https://github.com/SecPal/deployment/issues/209)
  descendants own portable implementation.

The general PROTECTED Sandbox PoC is complete and retired. PROTECTED architecture
is accepted; portable implementation is in progress. The old
[Debian/NGINX decision](decisions/production-edge.md) is retained only as a
historical, superseded record.

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
- **Production database:** PostgreSQL 18 is host-native and is the persistent
  source of truth. Its implementation and backup contracts have separate owners.
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

## Historical evidence

### Step A bootstrap contract

Step A established governance, documentation, local validation, and quality CI.

### Phase B/C and former D.1/D.2/D.3

Git and GitHub retain accurate historical evidence for the former Compose,
Valkey, Caddy, Debian, AppArmor, production-state, and Debian NGINX contracts.
Those terms remain valid when describing what the historical work actually
proved. They are not current production authority and no executable Compose
compatibility runtime is maintained.

The former D.1a label described the transition of disposable integration to
rootless Podman/Quadlet. Current documentation names the implemented integration
directly rather than treating D.1a or D.3 as present architecture ownership.
