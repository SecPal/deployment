<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# SecPal Deployment

SecPal Deployment is the public reference for reproducible SecPal
integration, self-hosting, deployment contracts, container orchestration,
edge and security integration, and operational procedures for backup,
restore, and updates.

> Phase B provides a runnable, test-only local integration stack.
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
- Published images will be referenced by immutable digest.
- The public self-hosting contract forms the technical basis for private
  managed-hosting automation.

## Roadmap status

1. Governance bootstrap: complete.
2. Local API/frontend integration: complete.
3. Immutable image publishing: not implemented.
4. Public Compose reference deployment: not implemented.
5. Public edge, TLS, and CrowdSec: not implemented.
6. Backup, restore, update, and rollback: not implemented.
7. Private managed-hosting automation: permanently outside this public
   repository.

See [the roadmap](docs/roadmap.md) for acceptance criteria and explicit
non-goals.

## Phase B local integration

The public [`compose.yaml`](compose.yaml) builds the API and frontend directly
from these immutable Git revisions:

- API: `6fead9cef910314304048056a7ebed4f10bf5381`;
- frontend: `fcd427d9b55d7945c439c670077e12928e47ddd6`.

PostgreSQL, Valkey, and the test-only Caddy base are pinned by version and
digest. The stack exposes only `127.0.0.1:8443` and uses the reserved origin
`https://secpal.example.invalid:8443`. API, frontend, workers, scheduler, and
data services have no published ports.

Run the explicit integration test with Docker Engine, Docker Compose v2,
`curl`, GitHub access for the pinned source contexts, and registry access for
the pinned build inputs:

```bash
./scripts/local-integration.sh
```

The script builds the pinned images, generates random test-only secrets inside
a private runtime volume without printing them, starts private PostgreSQL and
Valkey services, runs migrations exactly once, starts the explicit service
roles, and verifies API/frontend routing through local TLS. Successful
completion means its containers, networks, database data, certificates, and
secrets were removed. Failure paths and handled signals trigger best-effort
cleanup before returning.

This stack proves integration only. It does not provision a tenant, claim
`/health/ready`, expose a public service, persist production data, use
production credentials, or select the future production edge.

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
messages; it never installs dependencies or starts the Phase B stack. The
Docker-backed integration test is a separate, explicit command.

## Repository boundary

Product code remains in [`SecPal/api`](https://github.com/SecPal/api) and
[`SecPal/frontend`](https://github.com/SecPal/frontend). Their Dockerfiles and
build logic are not copied here. Phase B builds their existing Dockerfiles from
exactly pinned source revisions. Future published images and their provenance
contract belong to Phase C. This repository does not fork product build logic.

The detailed ownership and trust boundaries are documented in
[`docs/architecture/scope.md`](docs/architecture/scope.md).

## License

The repository project license is GNU AGPL 3.0 or later. File-level SPDX and
REUSE metadata apply the current SecPal licensing matrix, including the SecPal
attribution addendum where applicable.
