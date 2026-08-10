<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# SecPal Deployment

SecPal Deployment is the public reference for reproducible SecPal
integration, self-hosting, deployment contracts, container orchestration,
edge and security integration, and operational procedures for backup,
restore, and updates.

> Phase B and the completed Phase C provide a runnable, test-only local
> integration stack with reviewed API and frontend image consumption.
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
4. Public rootless Podman/Quadlet reference deployment: host contract only;
   runtime integration remains to be migrated.
5. Public edge, TLS, and CrowdSec: not implemented.
6. Backup, restore, update, and rollback: not implemented.
7. Private managed-hosting automation: permanently outside this public
   repository.

See [the roadmap](docs/roadmap.md) for acceptance criteria and explicit
non-goals.

## Phase B local integration and Phase C image consumption

The public [`compose.yaml`](compose.yaml) consumes the verified API OCI index
by this canonical digest reference:

- `ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e`

The frontend is consumed only through its verified canonical OCI index:

- `ghcr.io/secpal/frontend@sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077`

Its source commit is `b755ca0d0ee5a85eca5ad5688d457241f070b1b4`,
published by run `31247196734` (attempt `1`). The frontend source build and
image override have been removed. PostgreSQL, Valkey, and the test-only Caddy
base remain pinned by version and digest.

Phase C completion is bound to deployment merge commit
`4fc2796409b7c37a541f515ccf29236f143fc132`. Its push-triggered Local
Integration run `31264562902` verified the frontend OCI index digest
`sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077`
and API OCI index digest
`sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e`
before runtime, then passed the real Compose lifecycle, Playwright, and full
project cleanup.

The stack exposes one dynamic port on `127.0.0.1` and uses two reserved HTTPS
origins on that port:

- `https://app.secpal.example.invalid:<port>` for the frontend;
- `https://api.secpal.example.invalid:<port>` for the API.

API, frontend, workers, scheduler, and data services have no published ports.

The intended explicit integration test requires Docker Engine, Docker Compose
v2, GitHub CLI 2.97.0 with `gh attestation verify`, Python 3, `curl`, util-linux
`setsid`, Node.js 22.22.2, npm dependencies installed with `npm ci`, Playwright
Chromium installed, and anonymous registry access for the pinned inputs:

```bash
./scripts/local-integration.sh
```

GitHub CLI currently applies its GitHub authentication gate to the direct
`--bundle-from-oci` mode. The runner does not provide a GitHub token to bypass
that gate. Instead, it retrieves both the public Sigstore bundle and the exact
raw OCI index through GHCR's anonymous OCI Distribution flow. The runner
validates the referrer, manifests, subject, layer digests, sizes, and media
types, then gives the private, digest-matching local index and bundle to
`gh attestation verify --bundle`. GitHub CLI therefore hashes the reviewed
local index instead of reopening the registry. Verification uses the exact
reviewed GitHub CLI 2.97.0, runs against an empty GitHub configuration, fixes
the host to `github.com`, disables prompting, updates, and telemetry, and
removes all GitHub, Docker, and registry configuration variables. The temporary
index and bundle are removed on success, failure, and signals.

The sequence validates every API role and the frontend against their canonical
digests. It pulls each image with its own new empty Docker configuration while
removing inherited `DOCKER_AUTH_CONFIG` from each exact pull process. For each
image it verifies the raw index byte digest and `Docker-Content-Digest` header,
retrieves and validates the public OCI attestation bundle, and requires
successful GitHub Artifact Attestation verification. Only after both gates
succeed does the script build the project-scoped gateway image, generate
random test-only secrets inside a private runtime volume without printing them,
start private PostgreSQL and Valkey services, run migrations exactly once, and
start the explicit service roles. Neither published SecPal image is a local
cleanup artifact. The runner then proves Valkey cache and queue round trips,
worker-to-queue ownership, shared visibility of the disposable private-storage
volume, exact credentialed CORS, and the separate app/API origins. Playwright
Chromium exercises the actual Compose frontend and API, including the Sanctum
CSRF handshake, an intentionally unsuccessful login, secure cookie attributes,
CSP, service-worker registration, and runtime API routing. Successful
completion means its containers, networks, volumes, project-built images,
database data, private files, certificates, and secrets were removed. Failure
paths trigger best-effort cleanup; handled signals are forwarded to the active
integration process group and stop the run with a non-success status after
cleanup. Interrupted secret publication rolls back partial files, and a later
run replaces any legacy partial set.

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

## Ephemeral Debian 13 cloud conformance

The repository now contains a manual, protected
[`Debian 13 cloud conformance`](docs/ci-cloud-conformance.md) foundation. It
can provision one short-lived official Debian 13 host using a closed
DigitalOcean Intel/AMD or Google C4A/Axion profile, run an exact 40-character
deployment commit SHA without exposing cloud-control credentials to that
commit, collect bounded host/runtime evidence, and destroy the exact OpenTofu
state. Metadata-gated TTL janitors protect billable compute fixtures.

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
The Phase B/C Docker/Compose integration remains historical evidence while a
dedicated [D.1a follow-up (#20)](https://github.com/SecPal/deployment/issues/20)
migrates and re-proves runtime parity. Docker/Compose
is not a supported production runtime. No production orchestration or
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
messages; it never installs dependencies or starts the Phase B stack. The
Docker-backed integration test is a separate, explicit command.

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
