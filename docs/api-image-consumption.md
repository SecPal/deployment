<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Verified API image consumption

The public local integration contract consumes the verified SecPal API image
by canonical OCI index digest. It is a test-only, loopback-only, disposable
integration contract, not a production deployment.

The Docker/Compose language below records the completed Phase C evidence. The
active disposable runner preserves the same OCI and attestation verifier, uses a new
mode-`0700` empty Podman authentication file for each pull, stages the exact
digest in rootless local storage, and starts only native Quadlet units with
`Pull=never`. The historical evidence is not rewritten as Podman evidence.

## Current accepted PHP-FPM/Nginx pair

Production and the disposable Quadlet integration now consume the same accepted
pair from source `30a326d6c2e32a9e1251d75bfe603b3026babfc1`:

- PHP-FPM: `ghcr.io/secpal/api@sha256:e6bd9bb7608298e2d4ac807883cbb378d58134025a9b5e8dbec88af919112024`.
- Nginx: `ghcr.io/secpal/api@sha256:4bfeca7ead5436c5c4b9d51823d2438be91e5f88c25d07b8695a0a5c614a8b90`.
- Attested pair artifact: `ghcr.io/secpal/api@sha256:b95c184cfc999d8be7a36c3d9f8a8b9bf402856a0d0923c095fe828e20a3d80a`.
- Publisher run: [`42987289933`](https://github.com/SecPal/api/actions/runs/42987289933/attempts/2),
  candidate attempt `1`, qualification/acceptance attempt `2`; workflow `SecPal/api/.github/workflows/publish-container.yml`.

This source includes [API security fix #1615](https://github.com/SecPal/api/pull/1615).
The operator confirms this pair is already activated on `secpal.dev`. This change
synchronizes repository declarations only; it neither performs another activation
nor treats repository or CI results as observations of running demo containers.
The accepted frontend identity remains unchanged.

The existing anonymous OCI fetcher verifies the pair artifact's digest and
signed publisher identity, its exact source and both index references, then
verifies and stages each image separately. It rejects swapped companions and
requires renewed central qualification when the current exact-subject SQLite
OpenVEX horizon expires at `2026-11-23T00:00:00Z`. No newer digest or tag is
selected and no scanner policy is implemented here. The existing reviewed
statements apply only to the published FPM manifests, not future rebuilds.

The HTTP role `api` runs Nginx and retains the HAProxy backend port. The new
`php-fpm` role owns application/database secrets and the private socket.
Migrations, workers and scheduler use PHP CLI from that same PHP image.
Production retains PostgreSQL 18 on the host with verify-full TLS/SCRAM.
Integration uses the existing disposable PostgreSQL 18 fixture with TLS/SCRAM
and the unchanged production PHP secret bootstrap. No application secrets are
exported by a custom runtime entrypoint or mounted into Nginx.

Source integration is not activation authority. A later switch still requires
a valid Recovery Set, actual schema/data compatibility, migration/deployment
locks, current OCI/security evidence and separately authorized activation.
Known-vulnerable historical FrankenPHP images remain recovery identities, not
safe automatic rollback targets. A new accepted source does not relabel any
older PostgreSQL, cloud, or browser result as current qualification.

## Previous accepted pair (historical publication)

The preceding source contract selected the accepted pair from source `da806926a754d7446cdfa9f6f19ed331e5dbee31`:

- PHP-FPM: `ghcr.io/secpal/api@sha256:1a84eb5224750efefbb609a1801acce84c8b5e8b8d6e2ec5514b77a8fe3ccd73`.
- Nginx: `ghcr.io/secpal/api@sha256:f912cd93778454b7c3910e559a5773c9c0532347e07d8e99ee7be231b5f9795c`.
- Attested pair artifact: `ghcr.io/secpal/api@sha256:f2b09c90d60973af84bbcba87e89fa98531cae53a0c6600ff24534688517a911`.
- Publisher run: `42757690047`, candidate attempt `2`, qualification/acceptance
  attempt `3`; workflow `SecPal/api/.github/workflows/publish-container.yml`.

These original publication identities remain recorded for historical and recovery
reference. This entry does not declare retirement or approve automatic rollback.

## Historical single-image integration identity

The approved API image reference for the existing application integration
fixture is:

```text
ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e
```

Its recorded publisher identity is:

- Source repository: `SecPal/api`
- Source commit: `87d1432389adac3a02574b399322928a77c5e67f`
- Publisher workflow: `SecPal/api/.github/workflows/publish-container.yml`
- Publisher run: `30833321334` (attempt `1`)
- Subject digest:
  `sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e`
- Source ref: `refs/heads/main`
- Runner policy: GitHub-hosted only

The publisher verified the multi-architecture OCI index for `linux/amd64` and
`linux/arm64`, the SBOM and SLSA provenance for both platforms, and runtime
smokes for both platforms. It created and verified a GitHub Artifact
Attestation. An anonymous public pull by digest was also confirmed externally.
The deployment integration runner repeats the anonymous digest pull and
requires the fixed-identity attestation verification before it permits any
API-based role to execute.

The separate native PostgreSQL qualifier and its #81 consumer use the scoped
runtime identity below. Existing integration fixture consumers retain their
approved digest and evidence contract.

## Historical native PostgreSQL application identity

The trusted native PostgreSQL qualification contract consumes an existing
accepted API runtime that supplies verified PHP/PDO transport and separate
application readiness/liveness. It fixes
`ghcr.io/secpal/api@sha256:ac97416f3feac5c57204421059105389c9add2cfbcda1b063eadf4c6ad7647ab`
from accepted API source `7da77556e7a4896940b6c50ccf6ba2c3fb9a8653`, publisher
run `36992636604`, attempt `1`, workflow `publish-container.yml`, on protected
`main`. Its architecture identities are:

- `linux/amd64`: `sha256:8d0d960306c6989be55a9c7bc41937699e55dbdbc6193bff870f38a1b19605a3`
- `linux/arm64`: `sha256:ed91caa822e189187d57e0ff322c54e3b9837aa679cc087015933dcda9a3be7e`

This identity remains bound to the original #81 qualification and is not the current production image authority. The current renderer reads the accepted pair from `integration_runtime_contract.py`; the archived declaration is not rewritten.
The declaration binds it for the #81 consumer. The qualifier verifies its OCI
index and GitHub artifact attestation before a rootless application executes,
using the same anonymous bundle retrieval and fixed GitHub CLI authority as
the integration fixture. See
[native PostgreSQL qualification](postgresql-qualification.md) for application
observations, evidence admission and cleanup.

## Existing fixture verification

The image pull uses a new mode-`0700`, empty `DOCKER_CONFIG` directory and
removes inherited `DOCKER_AUTH_CONFIG` only from the exact `docker pull`
process. The runner therefore cannot reuse either file-backed or environment-
provided Docker registry credentials for the reviewed API digest.

At Phase C completion, the hosted workflow installed the official GitHub CLI `2.97.0`
Linux AMD64 release archive and verified its published SHA-256 checksum
`a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112`
before use. The integration runner requires that exact version, checks for
`gh attestation verify`, and fails closed before the API pull if either contract
does not match. The active hosted matrix also verifies the official ARM64
archive checksum
`73ea440ecad9c9e284429997ee6f93577bc6f7bc6fba357ef62c53ad8fb641a5`.
Neither path introduces a GitHub token.

## Token-free OCI bundle verification

GitHub CLI applies its GitHub authentication gate before direct
`--bundle-from-oci` verification. The integration runner keeps GitHub token
variables unset and uses the OCI Distribution contract directly instead. It:

1. requests only the fixed public `secpal/api` pull scope from GHCR's anonymous
   token service;
2. reads the OCI Referrers endpoint or its digest-derived standard fallback;
3. requires exactly one SLSA v1 Sigstore bundle descriptor;
4. accepts only default-port HTTPS blob redirects to GitHub's exact
   `pkg-containers.githubusercontent.com/ghcrblobs<number>/blobs/sha256:<digest>`
   path shape, without forwarding registry authorization;
5. fetches the raw canonical OCI index and verifies that its SHA-256 is exactly
   the reviewed subject digest;
6. verifies the descriptor, manifest, subject, layer digests, sizes, and media
   types against that canonical API digest;
7. writes the raw index and bundle to separate mode-`0600` files in the private
   integration temporary directory; and
8. invokes `gh attestation verify --bundle` on the private local index with the
   fixed GitHub.com hostname, repository, workflow, ref, commit, digest, and
   GitHub-hosted-runner policy.

The anonymous registry bearer and signed blob redirect exist only in process
memory. They are neither account credentials nor persisted configuration and
are never logged. Cross-host redirects are restricted to GitHub's container
blob host, default HTTPS port, and canonical GHCR blob path shape, and the
registry Authorization header is removed before following the redirect.
Verification removes GitHub.com and GitHub Enterprise token variables, Docker
configuration variables, and any inherited `GH_HOST`; it passes
`--hostname github.com` and disables prompting, update notifications, and
telemetry. Because the artifact argument is the digest-validated local OCI
index rather than an `oci://` reference, GitHub CLI does not reopen the
registry. The temporary index, bundle, and empty Docker/GitHub configurations
are removed on success, failure, and signals.

The digest-derived OCI Referrers fallback is metadata transport only. It is
never an API image, deployment, discovery, or rollback reference.

## Discovery tag

The historical discovery tag
`ghcr.io/secpal/api:build-87d1432389adac3a02574b399322928a77c5e67f-30833321334-1`
is not a deployment reference, rollback reference, or trust anchor. It is not
an allowed Compose value. Only the canonical digest above is consumed.

## Reviewed updates and rollback

Changing the digest requires a new successful publisher run, a newly verified
digest, recorded source and attestation identity, a dedicated deployment pull
request, static contract checks, and the current rootless Podman/Quadlet
integration lifecycle:

```bash
python3 scripts/quadlet-integration.py
```

Review and merge remain required. There is no automatic move to a newest image.

Every integration fixture digest update requires a new reviewed deployment pull request.

Rollback also requires a new reviewed pull request. It sets the API reference
to a previously recorded and freshly reverified digest and reruns the same
contracts. `latest`, `main`, release tags, build tags, SHA tags, unchecked
environment variables, and manual tag changes are never rollback inputs.

## Scope status

Phase C is complete. API and frontend publication and token-free, fail-closed
digest consumption are implemented and operationally verified. Deployment
merge commit `4fc2796409b7c37a541f515ccf29236f143fc132` passed post-merge Local
Integration run `31264562902`; the final dual-image evidence is recorded in
[`frontend-image-consumption.md`](frontend-image-consumption.md).

At Phase C completion, Phase D had not started. D.1 now defines the production
host contract and the active runner provides only disposable Podman/Quadlet
integration parity. No production orchestration, cloud resource, DNS, TLS, production
secret, persistent production data, backup, restore, or managed-hosting
automation is implemented here.
