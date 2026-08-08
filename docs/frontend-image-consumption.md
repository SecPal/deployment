<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Verified frontend image consumption

The local integration contract consumes the public SecPal frontend image by
its reviewed OCI index digest. This is a test-only, loopback-only, disposable
integration stack, not a production deployment.

## Canonical identity and evidence

The only approved frontend deployment reference is:

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

The runner resolves the static Compose contract first. It requires every API
role and the frontend to resolve to their reviewed digest references without a
build block. It then verifies the API, followed by the frontend, before
`secrets-init` or any long-running container can execute.

Each image has a separate, newly created mode-`0700`, empty `DOCKER_CONFIG`.
The exact `docker pull` process unsets `DOCKER_AUTH_CONFIG`; no registry login,
GitHub token, GHCR credential, credential helper, or fallback is introduced.
The caller's Docker configuration is never read or modified.

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

The hosted workflow installs GitHub CLI `2.97.0` and verifies the official
Linux AMD64 archive checksum
`a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112`.
The runner requires that exact version. GitHub CLI verifies the local raw
index and bundle with exact bindings to `SecPal/frontend`, the publisher
workflow, `refs/heads/main`, source digest and signer digest
`b755ca0d0ee5a85eca5ad5688d457241f070b1b4`, and GitHub-hosted runners only.
It does not reopen the registry during cryptographic verification.

Only after both published SecPal images pass these gates does the runner build
the local test gateway, initialize disposable secrets, start PostgreSQL and
Valkey, run the migration once, start the API roles and frontend, expose the
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

## Scope status

Phase C.4 implementation is ready for review. Phase C remains in progress.
It cannot be marked complete until this change is merged and the merge commit
passes the required post-merge local integration evidence. Phase D and all
production deployment work remain out of scope.
