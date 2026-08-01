<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# SecPal Deployment

SecPal Deployment is the future public reference for reproducible SecPal
integration, self-hosting, deployment contracts, container orchestration,
edge and security integration, and operational procedures for backup,
restore, and updates.

> This repository is in its governance bootstrap phase.
> It does not yet contain a runnable or production-ready deployment.

## Architecture principles

The following statements are architecture targets, not implemented features:

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

## Planned phases

1. Governance bootstrap.
2. Local API/frontend integration.
3. Immutable image publishing.
4. Public Compose reference deployment.
5. Public edge, TLS, and CrowdSec.
6. Backup, restore, update, and rollback.
7. Private managed-hosting automation outside this public repository.

See [the roadmap](docs/roadmap.md) for entry and completion criteria. Only the
governance bootstrap is in scope today.

## Security

Never commit secrets, `.env` files containing real values, private keys,
certificates, tokens, or cloud credentials. Security reports follow the
organization-wide [SecPal security process](https://github.com/SecPal/.github/security/policy).
The current branch and repository contents are not approved for production
operation.

## Development

Run the deterministic local repository checks without Docker or network access:

```bash
./scripts/preflight.sh
```

The preflight requires the locally installed tools documented by its error
messages; it never installs dependencies.

## Repository boundary

Product code remains in [`SecPal/api`](https://github.com/SecPal/api) and
[`SecPal/frontend`](https://github.com/SecPal/frontend). Their Dockerfiles and
build logic are not copied here. A future deployment contract will orchestrate
published images or build exactly pinned source revisions for local integration.
This repository does not fork product build logic.

The detailed ownership and trust boundaries are documented in
[`docs/architecture/scope.md`](docs/architecture/scope.md).

## License

The repository project license is GNU AGPL 3.0 or later. File-level SPDX and
REUSE metadata apply the current SecPal licensing matrix, including the SecPal
attribution addendum where applicable.
