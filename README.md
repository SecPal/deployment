<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# SecPal Deployment

SecPal Deployment is the public reference for reproducible SecPal
integration, self-hosting, deployment contracts, container orchestration,
edge and security integration, and operational procedures for backup,
restore, and updates.

> Phase B and the API image-consumption part of Phase C provide a runnable,
> test-only local integration stack.
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
3. Immutable image publishing: in progress. API publication and API digest
   consumption are implemented; frontend publication remains outstanding.
4. Public Compose reference deployment: not implemented.
5. Public edge, TLS, and CrowdSec: not implemented.
6. Backup, restore, update, and rollback: not implemented.
7. Private managed-hosting automation: permanently outside this public
   repository.

See [the roadmap](docs/roadmap.md) for acceptance criteria and explicit
non-goals.

## Phase B local integration and Phase C API image consumption

The public [`compose.yaml`](compose.yaml) consumes the verified API OCI index
by this canonical digest reference:

- `ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e`

The frontend remains a source build pinned to Git revision
`fcd427d9b55d7945c439c670077e12928e47ddd6`. Frontend publication remains
outstanding. PostgreSQL, Valkey, and the test-only Caddy base remain pinned by
version and digest.

The stack exposes one dynamic port on `127.0.0.1` and uses two reserved HTTPS
origins on that port:

- `https://app.secpal.example.invalid:<port>` for the frontend;
- `https://api.secpal.example.invalid:<port>` for the API.

API, frontend, workers, scheduler, and data services have no published ports.

The intended explicit integration test requires Docker Engine, Docker Compose
v2, GitHub CLI with `gh attestation verify`, Python 3, `curl`, util-linux
`setsid`, Node.js 22.22.2, npm dependencies installed with `npm ci`, Playwright
Chromium installed, GitHub access for the pinned frontend source context, and
anonymous registry access for the pinned inputs:

```bash
./scripts/local-integration.sh
```

GitHub CLI currently applies its GitHub authentication gate to the direct
`--bundle-from-oci` mode. The runner does not provide a GitHub token to bypass
that gate. Instead, it retrieves the public Sigstore bundle through GHCR's
anonymous OCI Distribution flow, validates the referrer, manifest, subject,
layer digests, sizes, and media types, and supplies the private temporary
bundle to `gh attestation verify --bundle`. Verification runs with an empty
GitHub CLI configuration and both GitHub token variables unset. The temporary
bundle is removed on success, failure, and signals.

The sequence validates every API role against the canonical digest, pulls it
with a new empty Docker configuration, retrieves and validates its public OCI
attestation bundle, and requires successful GitHub Artifact Attestation
verification before any API-based role may run. Only after that gate succeeds
does the script build the project-scoped frontend and gateway images, generate
random test-only secrets inside a private runtime volume without printing them,
start private PostgreSQL and Valkey services, run migrations exactly once, and
start the explicit service roles. The published API image is not a local
cleanup artifact. The runner then proves Valkey cache and queue
round trips, worker-to-queue ownership, shared visibility of the disposable
private-storage volume, exact credentialed CORS, and the separate app/API
origins. Playwright Chromium exercises the actual Compose frontend and API,
including the Sanctum CSRF handshake, an intentionally unsuccessful login,
secure cookie attributes, CSP, service-worker registration, and runtime API
routing. Successful completion means its containers, networks, volumes,
images, database data, private files, certificates, and secrets were removed.
Failure paths trigger best-effort cleanup; handled signals are forwarded to the
active integration process group and stop the run with a non-success status
after cleanup. Interrupted secret publication rolls back partial files, and a
later run replaces any legacy partial set.

For a deterministic caller-assigned port, including parallel test scheduling,
set a distinct loopback port for each run:

```bash
SECPAL_PHASE_B_PORT=18443 ./scripts/local-integration.sh
```

The public Compose template retains `8443` and reserved singleton container
names as its single-project direct-use defaults. One validated port setting
drives gateway publication and both HTTPS origins. The integration script
derives unique values for parallel runs. The runner requires the
`docker compose` v2 plugin and does not fall back to the legacy standalone
Compose v1 command.

Valkey is the queue and cache backend. `worker-hash-chain` is the guarded
singleton consumer of only `activity-hash-chain`; `worker-general` consumes
`merkle`, `opentimestamp`, and `default` without a fixed container name. The
scheduler remains a guarded singleton. All API-based roles mount the same
`private-storage` volume at `/app/storage/app/private`; this volume is
disposable test state, not a production persistence contract.

Pull requests also run the real lifecycle in the required check context
`Local Integration / Compose Contract`. Phase B is complete: the technical
implementation head passed that hosted check, and the check is enforced for
`main`. Every subsequent pull-request head must pass it again.

This stack proves integration only. It does not provision a tenant, claim
`/health/ready`, expose a public service, persist production data, use
production credentials, or select the future production edge.

Phase C is in progress. API publication and token-free, fail-closed API digest
consumption are implemented. Frontend publication remains outstanding. Digest
provenance, reviewed updates, and rollback are detailed in
[`docs/api-image-consumption.md`](docs/api-image-consumption.md).

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
build logic are not copied here. The API follows the reviewed Phase C digest
contract; the frontend still builds its existing Dockerfile from an exactly
pinned source revision. This repository does not fork product build logic.

The detailed ownership and trust boundaries are documented in
[`docs/architecture/scope.md`](docs/architecture/scope.md).

## License

The repository project license is GNU AGPL 3.0 or later. File-level SPDX and
REUSE metadata apply the current SecPal licensing matrix, including the SecPal
attribution addendum where applicable.
