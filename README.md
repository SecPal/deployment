<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# SecPal Deployment

SecPal Deployment is the public reference for reproducible SecPal
integration, self-hosting, deployment contracts, container orchestration,
edge and security integration, and operational procedures for backup,
restore, and updates.

> The active test-only integration stack uses rootless Podman, native Quadlet,
> and systemd user services with reviewed API and frontend image consumption.
> It is not a production-ready deployment.

## Architecture principles

The following statements are architecture invariants. Phase B implements the
local integration subset; later phases remain targets:

- Public and managed installations use the same product images.
- The API and frontend remain deployment-neutral and use separate images.
- PostgreSQL is the persistent source of truth.
- Valkey provides queue and cache services; it does not replace PostgreSQL.
- The `activity-hash-chain` role has exactly one worker.
- The scheduler has exactly one instance.
- The public edge remains separate from product containers.
- CrowdSec will be integrated at the public edge.
- Production secrets are never stored in this repository or in images.
- Published images are introduced only through reviewed immutable digests.
- The public self-hosting contract forms the technical basis for private
  managed-hosting automation.

## Roadmap status

1. Governance bootstrap: complete.
2. Local API/frontend integration: complete.
3. Immutable image publishing: complete. API and frontend publication and
   digest-only consumption are operationally verified. Deployment merge
   commit `4fc2796409b7c37a541f515ccf29236f143fc132` passed post-merge
   Repository Quality run `31264563173` and Local Integration run
   `31264562902` on `main`.
4. Public rootless Podman/Quadlet reference deployment: the D.1 host contract,
   D.1a integration-runtime parity, and D.2 production state/secret boundary are
   implemented; installation, public-edge, backup/restore, and later Phase-D
   work are not.
5. Public edge, TLS, and CrowdSec: not implemented.
6. Backup, restore, update, and rollback: not implemented.
7. Private managed-hosting automation: permanently outside this public
   repository.

See [the roadmap](docs/roadmap.md) for acceptance criteria and explicit
non-goals.

## Active rootless Podman and Quadlet integration

The active integration runtime is
[`scripts/quadlet-integration.py`](scripts/quadlet-integration.py). It admits
only rootless Podman `>=5.4.2,<6` with `crun`, `catatonit`, Netavark/Aardvark,
`pasta`, and a systemd user manager using the D.1 root-owned Quadlet search
path. It verifies both SecPal product OCI indexes and their fixed publisher
identities before staging them in local Podman storage. The generated product
units use the exact reviewed digest references and `Pull=never`, so systemd
startup cannot perform an opportunistic pull.

The constrained renderer creates separate PostgreSQL, Valkey, API, general
worker, hash-chain singleton worker, scheduler singleton, frontend, and
integration-gateway containers plus an explicit one-shot migration. Only the
gateway publishes one controlled loopback port. Runtime inspection, real API
and frontend health, Playwright, failure ordering, signal handling, parallel
fixtures, restart behavior, resource observations, and exact cleanup are part
of the active contract.

Run it explicitly after installing the documented runtime prerequisites and
root-owned search-path policy:

```bash
python3 scripts/quadlet-integration.py
```

See [the complete integration contract](docs/quadlet-integration.md) for the
service map, supply-chain order, security invariants, lifecycle behavior,
hosted-runner limits, and parallel-run inputs.

## Historical Phase B/C evidence

Phase B/C completion is preserved in immutable Git and GitHub evidence, not in
a maintained compatibility runtime. Deployment merge commit
`4fc2796409b7c37a541f515ccf29236f143fc132` and its push-triggered Local
Integration run `31264562902` recorded the completed lifecycle and cleanup.
The reviewed API OCI index was
`ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e`;
the reviewed frontend OCI index was
`ghcr.io/secpal/frontend@sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077`,
published from `b755ca0d0ee5a85eca5ad5688d457241f070b1b4` by run
`31247196734` (attempt `1`).

The current integration runtime is exclusively rootless Podman, systemd-user,
and native Quadlet. It preserves the relevant disposable PostgreSQL, Valkey,
browser, worker, migration, and cleanup coverage without retaining a runnable
Docker/Compose stack.

Phase B completed in the required check context
`Local Integration / Compose Contract`: the technical implementation head
passed that hosted check and the check was enforced for `main`. D.1a does not
rewrite that evidence. The active checks are `Local Integration / Quadlet
Contract (amd64)` and `Local Integration / Quadlet Contract (arm64)`; changing
branch protection from the historical name is an explicit governance cutover
when this migration merges.

This stack proves integration only. It does not provision a tenant, claim
`/health/ready`, expose a public service, persist production data, use
production credentials, or select the future production edge.

## Ephemeral Debian 13 cloud conformance

The repository now contains a manual, protected
[`Debian 13 cloud conformance`](docs/ci-cloud-conformance.md) foundation. It
can provision one short-lived official Debian 13 host using a closed
DigitalOcean Intel/AMD or Google C4A/Axion profile, run an exact 40-character
deployment commit SHA without exposing cloud-control credentials to that
commit, collect bounded host/runtime evidence, and destroy the exact OpenTofu
state. Metadata-gated TTL janitors protect billable compute fixtures.

The exact target implements only the fixed versioned `host`, workload
publication, and workload cleanup phases. It derives the fixture identity and
loopback port from the admitted commit, verifies the reviewed API and frontend
attestations before staging immutable local digest identities, and crosses the
root-owned Quadlet boundary only through the fixed unprivileged fixture
client. Activation and evidence collection stay in the main-controlled
collector; target code cannot choose either operation.

This CI infrastructure is non-production. It contains no customer data,
production inventory, DNS, certificate, backup, or service credential and is
not part of the production installation path. Google authentication uses
repository- and workflow-scoped Workload Identity Federation without a JSON
key or useful VM identity. GitHub-hosted Ubuntu integration evidence remains
distinct from Debian 13 host admission.

Phase C is complete. API and frontend publication, token-free fail-closed
digest consumption, pre-execution attestation verification, and hosted
post-merge integration evidence are operationally verified. This does not
claim a production deployment or public infrastructure. Phase D has begun
only with the provider-neutral, contract-only
[`production host`](docs/architecture/production-host.md) and
[`production inventory`](docs/architecture/production-inventory.md)
definitions. Schema version 1 admits only Debian 13/trixie hosts and defines
its security-update, controlled-reboot, reviewed major-upgrade, rootless
Podman, systemd/Quadlet, subordinate-ID, and local runtime-storage boundaries.
The D.1a integration runtime now re-proves those behaviors on native rootless
Podman/Quadlet. The Phase B/C immutable records remain historical evidence and
Docker/Compose is not a supported production runtime. D.1a is
still disposable integration evidence: no production orchestration or
infrastructure exists. Digest
provenance, reviewed updates, and rollback are detailed in
[`docs/api-image-consumption.md`](docs/api-image-consumption.md) and
[`docs/frontend-image-consumption.md`](docs/frontend-image-consumption.md).

## Security

Never commit secrets, `.env` files, private keys,
certificates, tokens, or cloud credentials. Security reports follow the
organization-wide [SecPal security process](https://github.com/SecPal/.github/security/policy).
The current branch and repository contents are not approved for production
operation.

## Development

Run deterministic repository checks without Docker or network access:

```bash
./scripts/preflight.sh
```

The preflight requires the locally installed tools documented by its error
messages; it never installs dependencies or starts the integration stack. The
real rootless Podman/Quadlet integration is a separate, explicit command.

## Repository boundary

Product code remains in [`SecPal/api`](https://github.com/SecPal/api) and
[`SecPal/frontend`](https://github.com/SecPal/frontend). Their Dockerfiles and
build logic are not copied here. The API follows the reviewed Phase C digest
contract, and the frontend follows the equivalent reviewed Phase C digest
contract. This repository neither fetches frontend source nor forks product
build logic.

The detailed ownership and trust boundaries are documented in
[`docs/architecture/scope.md`](docs/architecture/scope.md).

## License

The repository project license is GNU AGPL 3.0 or later. File-level SPDX and
REUSE metadata apply the current SecPal licensing matrix, including the SecPal
attribution addendum where applicable.
