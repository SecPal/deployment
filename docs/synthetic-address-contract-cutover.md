<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# One-time synthetic address contract cutover

The operator authorizes one attended schema-changing cutover for the enrolled
SecPal-owned synthetic reference pair `app.secpal.dev` / `api.secpal.dev` and
Lab guests CX23 (163965414), CX33 (163717938), and CAX21 (169716995).
Use [deployment #93](https://github.com/SecPal/deployment/issues/93) for the
activation and recovery controls. The routine timers retain the
migration-free [Lab](fcos-lab-rollout.md) and
[public reference](public-reference-updates.md) contracts. The operator accepts
the fenced, independently verified logical recovery point below for this
single cutover on the four named synthetic installations. All other
state-changing rollouts retain their existing recovery rules, including the
production [RecoverySet](https://github.com/SecPal/deployment/issues/109).

## Exact inputs

Use the publisher-verified OCI candidates for [API #3114][api] at
`ea83e8ccdf7a4b0d3bcf503a8d5e60cd84ea88c9` and [Frontend #2280][frontend]
at `0a5bcc9f218703c5a602556f7cbfad82a254f722`. Verify the signed receipt and
the OCI bytes before staging.

| Input                                  | SHA-256                                                            |
| -------------------------------------- | ------------------------------------------------------------------ |
| API pair receipt                       | `9b765d3ae13eff11108c7083ae1e30dfbd6efa8b23371aeaa5f8580824509604` |
| API PHP-FPM OCI index                  | `5fe917e5087d3568e7fbe071b1f25a548f489b15f778321e9de86074364def9d` |
| API Nginx OCI index                    | `1d31a36df99f0a6b1c5004fc4477a839fc1a573f5c9a8a85ac863a629f97031c` |
| Frontend OCI index                     | `3c859855647284cbeee9ddf26dee547265d992e86f8e6630b8fd8a727205cb15` |
| OpenPLZ/DE input authorized by the API | `1066a96a6b3a16629a94c834fca49fe58a2bb01558e17242c53a12d68b290088` |

Bind the actual installed predecessor for each target. Require the applicable
publisher attestations, SBOM associations, independent Source Security,
equivalent current per-platform scanner evidence and the existing
`component-update-v1` decision for each changed component. Include the
public reference exposure in that decision. A candidate attestation leaves
official registry release approval to its existing contract.

## Recovery and activation

1. Verify target identity and synthetic data classification, the PostgreSQL 18
   cluster and migration ledger, fixture identities, and the active OpenPLZ
   import. Verify the complete off-host logical restore for each database using
   the existing [restore procedure](fcos-application-poc.md#cross-host-logical-restore).
   Verify that there are no private objects to recover and that all existing
   key generations and their credentials remain recoverable. This scoped
   logical recovery path cannot authorize a cutover if private objects exist,
   a key generation is unaccounted for, or the data classification is uncertain.
   Keep the installed artifacts, unit definitions and credential material
   recoverable.
2. Rehearse the new API migration and seed over the recovered state with the
   staged candidate and independent AMD64 and ARM64 qualification. The only
   pending Laravel migration must be
   `2026_11_25_210000_include_customer_house_number_in_duplicate_guard`.
   Verify the new index and existing organization, user and witness data.
3. Stage both components by digest. In the maintenance window, hold the
   existing deployment locks and pause the affected activations. Stop API HTTP
   and verify it is no longer accepting requests. Drain and stop the scheduler,
   both workers and PHP-FPM, then verify that all five roles are inactive.
   Capture the final encrypted logical dump under this write fence. Record its
   hash, PostgreSQL system identity, WAL position, timestamp and exact
   migration ledger, then independently verify the fenced restore before
   mutating the database.
   Use the existing separate migration unit and database role to apply the
   Laravel migration exactly once. Seed the test fixtures in place and explicitly
   run the API's checksum-bound OpenPLZ import if the approved data are absent or
   stale. Reuse an active import with the exact authorized checksum. Preserve
   database, volume, test account, organization, witness and key identities.
4. Activate the API and qualify readiness and address lookups before enabling
   the corresponding frontend. Check login, organization access, exact and
   prefix postal-code lookup, separate house-number handling, and worker and
   scheduler cardinality. Repeat on each target before reopening writes.
5. If a check fails, maintain the write fence and use the verified pre-cutover
   restore with an admissible predecessor, or keep the target fenced for a
   forward fix. The migration cannot be reversed by Laravel. Never restore a
   pre-cutover snapshot over writes accepted after the fence was lifted.
6. Adopt the verified running artifact and schema identities through the
   existing enrollment and protected deployment state before resuming the
   migration-free timers. Record the observed result for each target in #93.

[api]: https://github.com/SecPal/api/pull/3114
[frontend]: https://github.com/SecPal/frontend/pull/2280
