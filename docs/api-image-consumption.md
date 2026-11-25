<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Verified API image consumption

The public local integration contract consumes the verified SecPal API image
by canonical OCI index digest. It is a test-only, loopback-only, disposable
integration contract, not a production deployment.

The [disposable integration runner](quadlet-integration.md) stages reviewed
OCI digests in rootless Podman and launches native Quadlets with `Pull=never`.

## Current accepted PHP-FPM/Nginx pair

The production renderer and disposable Quadlet fixture share the pair pinned
in [the runtime contract](../scripts/integration_runtime_contract.py) from source `30a326d6c2e32a9e1251d75bfe603b3026babfc1`:

- PHP-FPM: `ghcr.io/secpal/api@sha256:e6bd9bb7608298e2d4ac807883cbb378d58134025a9b5e8dbec88af919112024`.
- Nginx: `ghcr.io/secpal/api@sha256:4bfeca7ead5436c5c4b9d51823d2438be91e5f88c25d07b8695a0a5c614a8b90`.
- Attested pair artifact: `ghcr.io/secpal/api@sha256:b95c184cfc999d8be7a36c3d9f8a8b9bf402856a0d0923c095fe828e20a3d80a`.
- Publisher run: [`42987289933`](https://github.com/SecPal/api/actions/runs/42987289933/attempts/2),
  candidate attempt `1`, qualification/acceptance attempt `2`; workflow `SecPal/api/.github/workflows/publish-container.yml`.

This source includes [API security fix #1615](https://github.com/SecPal/api/pull/1615).
These identities describe the source contract. The
[public reference](public-reference-updates.md) and [FCOS Lab](fcos-lab-rollout.md)
record their selected releases and activation evidence separately.

The existing anonymous OCI fetcher verifies the pair artifact's digest and
signed publisher identity, its exact source and both index references, then
verifies and stages each image separately. It rejects swapped companions.
The stored SQLite OpenVEX horizon of `2026-11-23T00:00:00Z` applies to
the exact PHP-FPM subjects and has passed. The verifier rejects this pair for
cloud and other non-reference admission paths after the horizon. Renew central
security qualification before admitting it there. Only the closed, local
loopback reference fixture can exercise the exact pinned pair after expiry.
The [OCI verifier tests](../tests/oci-attestation-bundle-contract.py) cover both
paths. The documentation consistency check confirms the stored value alone.

The HTTP role `api` runs Nginx and retains the HAProxy backend port. The
`php-fpm` role owns application/database secrets and the private socket.
Migrations, workers and scheduler use PHP CLI from that same PHP image.
The application uses PostgreSQL 18 with verify-full TLS and SCRAM. Separate
[production state](architecture/production-state.md) and
[disposable PostgreSQL](quadlet-integration.md) contracts own its placement and
lifecycle. Application secrets stay in the PHP-FPM boundary.

Source integration alone does not authorize activation. A later switch requires
the applicable recovery evidence, actual schema/data compatibility,
migration/deployment locks, current OCI/security evidence and authorized
activation. Production, customer data and state-changing work require the
verified Recovery Set under [deployment #109][recovery-set]. The
[synthetic public reference contract](public-reference-updates.md) applies
only to the enrolled, migration-free image switch and the exact verified
rollback predecessor.
Use an accepted PHP-FPM/Nginx pair for deployment, rollback and recovery. Verify
compatibility with the enrolled schema, data and recovery point under
[deployment #93][recovery]. If rollback compatibility cannot be established,
use the approved forward-fix or recovery path. The historical qualification
records retain their original source, artifacts and scope.

## Previous accepted pair (historical publication)

The preceding source contract selected the accepted pair from source `da806926a754d7446cdfa9f6f19ed331e5dbee31`:

- PHP-FPM: `ghcr.io/secpal/api@sha256:1a84eb5224750efefbb609a1801acce84c8b5e8b8d6e2ec5514b77a8fe3ccd73`.
- Nginx: `ghcr.io/secpal/api@sha256:f912cd93778454b7c3910e559a5773c9c0532347e07d8e99ee7be231b5f9795c`.
- Attested pair artifact: `ghcr.io/secpal/api@sha256:f2b09c90d60973af84bbcba87e89fa98531cae53a0c6600ff24534688517a911`.
- Publisher run: `42757690047`, candidate attempt `2`, qualification/acceptance
  attempt `3`; workflow `SecPal/api/.github/workflows/publish-container.yml`.

These identities record the preceding paired publication. This pair requires
fresh admission and recovery compatibility under [deployment #93][recovery]
before it can be selected for a rollback.

## Existing fixture verification

The runner verifies both images with the pinned GitHub CLI and pulls through
fresh, empty Podman authentication files. The
[fixture toolchain contract](quadlet-integration.md) describes the runner
requirements. The [hosted workflow](../.github/workflows/local-integration.yml)
pins the GitHub CLI version and checksums for both native architectures.

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
configuration variables, and any inherited `GH_HOST`, passes
`--hostname github.com` and disables prompting, update notifications, and
telemetry. Because the artifact argument is the digest-validated local OCI
index rather than an `oci://` reference, GitHub CLI does not reopen the
registry. The temporary index, bundle, and authentication state
are removed on success, failure, and signals.

The digest-derived OCI Referrers fallback is metadata transport only. It is
never an API image, deployment, discovery, or rollback reference.

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

The current accepted PHP-FPM/Nginx pair documented above is the supported
recovery baseline. Rollback requires a new reviewed pull request, fresh
verification of the pair and component digests, and schema and data
compatibility under [deployment #93][recovery]. An older pair requires
fresh admission before it can be selected. Tags, unchecked environment
variables and manual tag changes are never rollback inputs.

[recovery]: https://github.com/SecPal/deployment/issues/93#issuecomment-7126107302
[recovery-set]: https://github.com/SecPal/deployment/issues/109
