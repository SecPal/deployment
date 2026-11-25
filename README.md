<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# SecPal Deployment

SecPal Deployment is the public reference for reproducible SecPal integration,
self-hosting, deployment contracts, container orchestration, edge and security
integration, and operational procedures for backup, restore, and updates.

## Current platform

Fedora CoreOS Stable is the Managed reference host. It runs rootless Podman
and Quadlet with SELinux Enforcing. PostgreSQL 18 is the active database major
and owns persistent application state, sessions, durable queues and shared
cache. Managed uses independently qualified infrastructure containers for
PostgreSQL, HAProxy and CrowdSec where suitable. AMD64 and ARM64 qualification
uses native systems. Self-Hosted installations consume the portable contracts
and can use other qualified platform adapters.

[Architecture scope](docs/architecture/scope.md) routes to the accepted decisions
for runtime, Edge, state and recovery. [Current delivery](docs/roadmap.md) records
which contracts are implemented, what the FCOS lab has qualified, and which
production acceptance evidence remains open. There are no production customer
installations.

## Integration and FCOS lab

The [disposable integration fixture](docs/quadlet-integration.md) exercises
reviewed API and frontend artifacts, PostgreSQL 18, worker and scheduler roles,
explicit migration and private routing. It exposes a controlled loopback port.
Run `python3 scripts/quadlet-integration.py` on a host meeting the documented
fixture prerequisites.

The [FCOS application proof](docs/fcos-application-poc.md) exercises private HTTPS
and persistent rootless volumes with synthetic data. The
[FCOS lab rollout](docs/fcos-lab-rollout.md) documents the admitted update and
recovery paths. Lab qualification and Managed Production Acceptance have
separate evidence.

## Repository boundaries

- Product images are built by [API](https://github.com/SecPal/api) and
  [frontend](https://github.com/SecPal/frontend). This repository consumes
  reviewed immutable artifacts.
- Public interfaces and recovery procedures belong here. Managed inventory,
  credentials, orchestration and customer data belong to their separate owners.
- The runtime has one `activity-hash-chain` worker and one scheduler per
  application installation. Migrations use an explicit one-shot operation.
  The selected Edge owns public routing and Viewer TLS.

## Development and security

Run `./scripts/preflight.sh` for deterministic repository validation. Use
[the contribution instructions](AGENTS.md) for the applicable tools and checks.
The required repository security check evaluates the exact Git source snapshot.
Runtime qualification and recovery use their own evidence.

Report vulnerabilities through the [SecPal security process](https://github.com/SecPal/.github/security/policy).
Keep credentials, private keys, certificates and mutable provider state outside Git.

## License

The repository project license is GNU AGPL 3.0 or later. File-level SPDX and
REUSE metadata apply the SecPal licensing matrix.
