<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Verified frontend image consumption

The local integration contract consumes the public SecPal frontend image by
its reviewed OCI index digest. This is a test-only, loopback-only, disposable
integration stack, not a production deployment.

The Docker/Compose wording below is the retained Phase C completion record.
The active disposable runner repeats the same token-free OCI and attestation gates,
stages the reviewed digest through a new empty Podman authentication file, and
uses the canonical digest from native Quadlet with `Pull=never`. It does not
reinterpret the historical Compose run as Podman evidence.

## Current API companion

The current Quadlet HTTP companion is Nginx at
`ghcr.io/secpal/api@sha256:4bfeca7ead5436c5c4b9d51823d2438be91e5f88c25d07b8695a0a5c614a8b90`,
paired with the accepted PHP-FPM index as documented in
[API image consumption](api-image-consumption.md). The older Phase C identities
below remain historical evidence and do not qualify this new deployment pair.

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

This is source-contract acceptance, not activation. The operator confirmed that
the demo frontend remained at
`ghcr.io/secpal/frontend@sha256:1c737d692e633d355f2ee92e82f0d78929c4dcf43f959e3e17d1cdc6c41fb0c9`
during the API cutover on 2026-11-10. Its independent monitoring is retained.
No complete cross-environment inventory of historical consumers or permitted
recovery/rollback targets exists. Historical CVE findings remain open unless
subject-specific remediation or complete retirement is established; neither a
new publication nor this source change proves retirement.

## Historical Phase C.3 identity and evidence

The completed Phase C.3 integration used:

```text
ghcr.io/secpal/frontend@sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077
```

The completed Phase C.3 publication recorded:

- Source repository: `SecPal/frontend`
- Source commit: `b755ca0d0ee5a85eca5ad5688d457241f070b1b4`
- Publisher workflow:
  `SecPal/frontend/.github/workflows/publish-container.yml`
- Publisher run: `31247196734` (attempt `1`)
- Source ref: `refs/heads/main`
- Canonical OCI index digest:
  `sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077`
- Artifact Attestation ID: `39567451`
- Rekor index: `2381180038`
- Runner policy: GitHub-hosted only

Phase C.3 publisher run: `31247196734`. Phase C.3 canonical digest:
`sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077`.
Phase C.3 status: COMPLETE.

The recorded platform manifests are
`sha256:9448c394cb43f4885b269c91d8df15db21d6bc33459800392136b7dcb917dfd1`
for `linux/amd64` and
`sha256:17b828013eeebd3f83b82b993a10f30b8c8957688fcf480bdd46d899e8cfe1`
for `linux/arm64`. They are publication evidence only. The registry-hosted
attestation artifact digest
`sha256:45f5e0c76e38c63efd483f2f8571c910a93aa528c31968a11b1960b330534b78`
is also evidence only. None of these three digests is an image, deployment,
trust, update, or rollback reference.

The historical discovery tag is evidence only and is never used by Compose.
Tags, child manifests, and attestation artifacts cannot replace the canonical
OCI index digest.

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

At Phase C completion, the hosted workflow installed GitHub CLI `2.97.0` and
verified the official Linux AMD64 archive checksum
`a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112`.
The active matrix additionally verifies the official Linux ARM64 archive
checksum
`73ea440ecad9c9e284429997ee6f93577bc6f7bc6fba357ef62c53ad8fb641a5`.
The runner requires that exact version. GitHub CLI verifies the local raw index
and bundle with exact bindings to `SecPal/frontend`, the publisher workflow,
`refs/heads/main`, the current source digest and signer digest
`d1c5b82f9f07ce4fb6bdac2054eeaa70149e2e38`, and GitHub-hosted runners only.
It does not reopen the registry during cryptographic verification.

Only after both published SecPal images pass these gates does the runner build
the local test gateway, initialize disposable secrets, start the disposable
PostgreSQL 18 fixture, run the migration once, start the database-backed API
roles and frontend, expose the
loopback gateway, and run the browser contract. The published frontend retains
UID/GID `101:101`, a read-only root filesystem, all capabilities dropped,
`no-new-privileges`, only `/tmp` writable, and only the private edge network.
`SECPAL_API_URL` remains runtime configuration; no deployment-time frontend
build exists.

## Reviewed update and rollback

A frontend update requires a new successful publisher run and separate
evidence for a new OCI index digest.
A new digest requires a new reviewed deployment pull request. There is no
automatic selection of a newer publication.

Rollback also requires a new reviewed pull request and fresh verification of
a previously recorded OCI index digest. `latest`, `main`, release, source-SHA,
branch, discovery, or other tags, environment overrides, manual Docker tags,
configurable registry or repository values, and registry fallbacks are never
update or rollback inputs.

The deployment repository performs registry reads only. It does not push an
image or manifest, generate an attestation, mutate a tag, or request registry
write permission.

## Phase C completion evidence

- Phase C.4 deployment PR: `SecPal/deployment#6`
- Deployment merge commit:
  `4fc2796409b7c37a541f515ccf29236f143fc132`
- Post-merge Repository Quality run: `31264563173`
- Post-merge Local Integration run: `31264562902`
- Compose Contract job: `93120504279`
- Canonical frontend OCI index digest:
  `sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077`
- Canonical API OCI index digest:
  `sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e`

Both push-triggered runs completed successfully on `main` for the merge
commit. The Local Integration run verified both published images before the
gateway build or SecPal product runtime, then passed secrets initialization,
PostgreSQL and Valkey health, migrations, the API, workers, scheduler,
frontend, gateway, Playwright browser contract, and complete project cleanup.

Phase C is complete. This status covers immutable publication, post-merge
verification, digest-only deployment consumption, pre-execution attestation
verification, and hosted integration evidence. It does not claim production
deployment or public infrastructure. At that completion point, Phase D had
not started; D.1a adds disposable runtime parity rather than production
deployment.
