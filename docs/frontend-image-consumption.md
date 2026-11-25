<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Verified frontend image consumption

The local integration contract consumes the public SecPal frontend image by
its reviewed OCI index digest. This is a test-only, loopback-only, disposable
integration stack, not a production deployment.

The [disposable integration runner](quadlet-integration.md) verifies and stages
the reviewed OCI digest in rootless Podman before it starts native Quadlets
with `Pull=never`.

## Current API companion

The current Quadlet fixture uses the Nginx and PHP-FPM pair recorded in
[API image consumption](api-image-consumption.md).

## Current accepted frontend release

The source deployment and disposable integration contract now select:

- Image: `ghcr.io/secpal/frontend@sha256:d893b3b5fc3861485f56460e85ba29e7e221cda0a729a192d3749c4c85a7342f`.
- Source: `d1c5b82f9f07ce4fb6bdac2054eeaa70149e2e38`.
- Publisher run: `42809674397` (attempt `1`), workflow
  `SecPal/frontend/.github/workflows/publish-container.yml` on protected main,
  GitHub-hosted runners only.
- Accepted build evidence: `ghcr.io/secpal/frontend@sha256:27cc637c5fc799d237ea640da0fdf27aa86021025ad648aeed3399b911bb1e34`.

The existing OCI/attestation fetcher independently verifies this exact index and
source before staging. The frontend release monitor re-evaluates the signed
publisher's authoritative Syft SPDX with Grype and each exact native subject with
Trivy through SecPal/.github#636. Scanner failures or stale databases cannot
qualify deployment.

These pins describe source acceptance. The
[public reference publisher](public-reference-updates.md) and
[FCOS Lab rollout procedure](fcos-lab-rollout.md) each record target activation
independently.

## Pre-execution verification

The active runner resolves the closed integration runtime contract first. It
requires every API role and the frontend to use their reviewed digest references
in native Quadlet units with `Pull=never`. It then verifies the API, followed by
the frontend, before `secrets-init` or any long-running container can execute.

Each image has a separate, newly created empty Podman authentication file. The
exact `podman pull --authfile` process cannot reuse a registry login, GitHub
token, GHCR credential, credential helper, or fallback. The caller's Docker and
Podman authentication configuration is never read or modified.

For the frontend, the anonymous OCI Distribution verifier:

1. requests only the fixed `secpal/frontend` pull scope;
2. retrieves the raw reviewed OCI index and requires HTTP success and the OCI
   image-index media type;
3. requires the response bytes to hash to the canonical digest and requires
   the `Docker-Content-Digest` header to equal that same digest;
4. retrieves exactly one SLSA v1 Sigstore bundle through the hardened,
   host-bound public registry flow;
5. validates the OCI descriptor chain and the signed statement subject name
   and digest; and
6. writes private mode-`0600` local index and bundle files for offline
   cryptographic verification.

The [hosted fixture workflow](../.github/workflows/local-integration.yml)
pins the GitHub CLI binaries. Verification checks the raw local index and bundle against
`SecPal/frontend`, its publisher workflow and protected main, the exact source
commit, and the GitHub-hosted runner policy.

Only after both published SecPal images pass these gates does the runner build
the local test gateway, initialize disposable secrets, start the disposable
PostgreSQL 18 fixture, run the migration once, start the database-backed API
roles and frontend, expose the loopback gateway, and run the browser contract. The published frontend retains
UID/GID `101:101`, a read-only root filesystem, all capabilities dropped,
`no-new-privileges`, only `/tmp` writable, and only the private edge network.
`SECPAL_API_URL` remains runtime configuration; no deployment-time frontend
build exists.

## Reviewed update and rollback

A frontend update requires a new successful publisher run and separate
evidence for a new OCI index digest.
Changing the fixture pin requires a reviewed deployment pull request.
Public reference and Lab updates use their linked target-specific contracts.

Rollback requires a new reviewed pull request and fresh verification of a
still-supported OCI index. Verify API compatibility and target admission
under [deployment #93][recovery]. Use the reviewed registry, repository and
immutable digest for every update or rollback. Tags, environment overrides,
configurable registry or repository values, and registry
fallbacks are never update or rollback inputs.

[recovery]: https://github.com/SecPal/deployment/issues/93#issuecomment-7126107302

The deployment repository performs registry reads only. It does not push an
image or manifest, generate an attestation, mutate a tag, or request registry
write permission.
