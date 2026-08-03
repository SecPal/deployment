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
API-based role to execute. The present CLI limitation described below prevents
that gate from succeeding; it does not permit the runner to skip the gate.

The hosted runner uses the GitHub CLI already provided by GitHub's hosted
Ubuntu image. The integration script checks for `gh attestation verify`, logs
the effective `gh` version, and fails closed if the capability is missing. It
does not install an unpinned CLI or introduce a token.

## Known token-free verification blocker

The real local check with GitHub CLI `2.97.0`, which is the current official
release for this review, confirmed that
`gh attestation verify --bundle-from-oci` still stops at the GitHub CLI
authentication gate when no token is available. This is tracked upstream in
[`cli/cli#11803`](https://github.com/cli/cli/issues/11803). The anonymous image
pull succeeds, but the integration runner then exits before `secrets-init`,
migration, API, workers, or scheduler can run. No token or registry credential
is introduced, and the verification policy is not weakened. The repository
therefore implements a blocked fail-closed target contract, not a successfully
completed real integration. It cannot satisfy the real Compose acceptance gate
until GitHub CLI supports the required public token-free verification.

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

Phase C is in progress. API publication and the fail-closed API digest
consumption target contract are implemented. The real integration remains
blocked at token-free attestation verification.

Frontend publication remains outstanding.

Phase D and production host automation remain outside this change. No real
host, cloud resource, DNS, TLS, secret, inventory, persistent production data,
backup, restore, or managed hosting automation is changed here.
