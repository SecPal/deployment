<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Verified API image consumption

The public local integration contract consumes the verified SecPal API image
by canonical OCI index digest. It is a test-only, loopback-only, disposable
integration contract, not a production deployment.

## Canonical identity

The only approved API image reference is:

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

The image pull uses a new mode-`0700`, empty `DOCKER_CONFIG` directory and
removes inherited `DOCKER_AUTH_CONFIG` only from the exact `docker pull`
process. The runner therefore cannot reuse either file-backed or environment-
provided Docker registry credentials for the reviewed API digest.

The hosted workflow installs the official GitHub CLI `2.97.0` Linux AMD64
release archive and verifies its published SHA-256 checksum
`a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112`
before use. The integration runner requires that exact version, checks for
`gh attestation verify`, and fails closed before the API pull if either contract
does not match. It does not introduce a GitHub token.

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
request, static contract checks, the real Compose integration lifecycle,
review, and merge. There is no automatic move to a newest image.

Every digest update requires a new reviewed deployment pull request.

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

Phase D has not started. Production host automation remains outside this
change. No real host, cloud resource, DNS, TLS, secret, inventory, persistent
production data, backup, restore, or managed hosting automation is changed
here.
