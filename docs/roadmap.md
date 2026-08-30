<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Deployment roadmap

This roadmap distinguishes implementation on current `main`, current target
architecture, and historical completion evidence. It is navigation, not a
second work graph: native GitHub parent, dependency, issue, and pull-request
state is authoritative.

## Implemented foundation on current main

The repository currently provides:

- reviewed immutable API and frontend image-consumption contracts;
- one disposable rootless Podman, systemd-user, and native Quadlet integration
  runtime;
- a canonical PostgreSQL 18.6 test fixture using
  `/var/lib/postgresql/18/docker`;
- database-backed cache, durable queue, and session behavior with no Valkey;
- distinct API, frontend, general-worker, dedicated hash-chain-worker,
  scheduler, and one-shot migration roles;
- a loopback-only disposable Caddy browser/origin gateway that is not the
  production edge; and
- static, hosted amd64, and hosted arm64 integration evidence with exact
  cleanup.

This is integration infrastructure, not a production deployment. It provides
no current production host installer, native PostgreSQL service, public edge,
durable private-file system, backup/recovery implementation, DNS, or
certificate procedure.

## Current production target

The following links identify the technical owners. Their presence here states
the target and ownership only; it does not claim their open work is implemented.

- [Rocky Linux 10.2+ and SELinux host contract
  (#80)](https://github.com/SecPal/deployment/issues/80): rootless Podman,
  systemd/Quadlet application runtime, no Docker/Compose path, no host
  networking, and no runtime socket/API dependency.
- [Host-native PostgreSQL 18
  (#81)](https://github.com/SecPal/deployment/issues/81): production database
  under systemd/SELinux, outside the SecPal product-container layer. The
  disposable integration database is not a temporary production alternative.
- Accepted
  [ADR-019](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-production-edge-layered-security-adr019.md)
  defines `DIRECT` and `PROTECTED` production-edge modes independently of
  deployment topology. [#89](https://github.com/SecPal/deployment/issues/89)
  owns the `DIRECT` host-native HAProxy Viewer Edge and external Certbot;
  [#209](https://github.com/SecPal/deployment/issues/209) owns coordination of
  the portable `PROTECTED` public Viewer Edge, where HAProxy is the
  authenticated Origin/backend rather than the public Viewer Edge. The old
  Debian/NGINX edge ADR is a superseded historical record.
- [Layered security
  (#85)](https://github.com/SecPal/deployment/issues/85): SELinux, seccomp,
  capabilities, rootless confinement, nftables, CrowdSec/AppSec, and
  socketless runtime detection.
- [Production state and private files
  (#87)](https://github.com/SecPal/deployment/issues/87): no Valkey, explicit
  durable private-file authority, and topology-specific state contracts.
- [Backup and recovery
  (#91)](https://github.com/SecPal/deployment/issues/91): Barman for PostgreSQL,
  Borg for `single` private files, independent HA object recovery copies,
  Recovery Sets, and isolated restore drills.
- [Rocky cloud conformance
  (#117)](https://github.com/SecPal/deployment/issues/117): current
  Rocky/SELinux host and application-workload evidence, replacing the completed
  Debian/AppArmor track.

## Delivery boundaries

### Production PostgreSQL

The executable production PostgreSQL product-container path has been retired.
The approved target is host-native PostgreSQL 18, but #81 still owns its
implementation. Administrator-facing production PostgreSQL steps do not exist
yet, and this roadmap does not invent a manual substitute.

### Cloud workload evidence

The current local renderer emits the 15-artifact PostgreSQL 18, no-Valkey
integration topology. The downstream cloud fixture/evidence client still
expects the older 16-artifact interface. #119 owns that migration and is
blocked by #118; this roadmap does not claim the downstream path has migrated
or modify its client.

### Production edge and recovery

The Caddy integration gateway cannot satisfy production-edge evidence.
`DIRECT` HAProxy/Certbot implementation belongs to #89/#90 descendants;
portable `PROTECTED` implementation belongs to #209 descendants. Neither path
is claimed complete here. Likewise, disposable integration storage cannot
satisfy production durability or recovery; Barman, Borg, independent object
recovery, Recovery Sets, and drills belong to #91 descendants.

## Historical milestones

### Phase A — Governance bootstrap (completed history)

Phase A established repository governance, licensing/REUSE metadata,
deterministic preflight, and protected `main`. It intentionally contained no
deployment implementation.

### Phase B — Compose integration (completed history)

Phase B proved the first API/frontend browser, worker, migration, and cleanup
contract with Compose, PostgreSQL 16, Valkey, and a disposable Caddy gateway.
Those technologies describe the completed evidence only. Issue
[#125](https://github.com/SecPal/deployment/issues/125) removed the executable
stack; no current command or compatibility path reproduces it. Immutable Git,
the merged delivery, and Local Integration run `31264562902` retain the
evidence.

### Phase C — Immutable image publishing (completed history)

Phase C established digest-only API/frontend consumption and fixed publisher
attestation. Deployment merge commit
`4fc2796409b7c37a541f515ccf29236f143fc132`, Repository Quality run
`31264563173`, and Local Integration run `31264562902` preserve the completion
record. Historical Docker Registry/configuration and Compose terms in those
records are accurate protocol and evidence language, not deployment support.

### D.1, D.1a, D.2, and D.3 (completed historical contracts)

D.1 recorded the Debian/AppArmor host and inventory contract. D.1a moved the
disposable integration to rootless Podman/Quadlet. D.2 recorded the old
container-state and secret model. D.3 selected Debian NGINX as the then-current
edge. These completed contracts remain historical evidence, but they do not
define current production support.

The current integration semantics were subsequently rebaselined by
[#126](https://github.com/SecPal/deployment/issues/126) and merged in
[PR #204](https://github.com/SecPal/deployment/pull/204). Current production
replacement contracts are #80, #81, ADR-019 with #89 for `DIRECT` and #209 for
`PROTECTED`, #91 descendants, and #117 descendants.
The [architecture scope](architecture/scope.md) indexes the retained historical
documents without presenting them as active runbooks.

## Private managed operations

Public `SecPal/deployment` owns portable self-hosting contracts and conformance.
Customer inventory, credentials, fleet policy, provider-specific managed
orchestration, economics, escalation, and customer lifecycle remain outside
this repository. Secrets, customer data, private keys, and production
credentials belong in neither Git repository.
