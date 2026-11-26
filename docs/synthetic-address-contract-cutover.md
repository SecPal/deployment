<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# One-time synthetic address contract cutover

The operator authorizes one attended schema-changing cutover for the enrolled
SecPal-owned synthetic reference pair `app.secpal.dev` / `api.secpal.dev` and
Lab guests CX23 (163965414), CX33 (163717938), and CAX21 (169716995).
Use [deployment #93](https://github.com/SecPal/deployment/issues/93) for the
activation and recovery controls. Routine timers use the [Lab](fcos-lab-rollout.md) and
[public reference](public-reference-updates.md) contracts for later changes. The operator accepts
the fenced, independently verified logical recovery point below for this
single cutover on the four named synthetic installations. All other
state-changing rollouts retain their existing recovery rules, including the
production [RecoverySet](https://github.com/SecPal/deployment/issues/109).

## Exact inputs

Use the publisher-verified OCI candidates for [API #3114][api] as included in
protected main at `abb3bed3db54aa20335e054342ffa5f55b09b1be`, and [Frontend #2280][frontend]
at `0a5bcc9f218703c5a602556f7cbfad82a254f722`. Bind the API pair receipt to
[API publisher run 45748341064][api-run], attempt 1, and the frontend
pre-registry receipt to [Frontend publisher run 45712000616][frontend-run],
attempt 1. Verify both signatures against their repository's protected
`main` and `.github/workflows/publish-container.yml` identity. Rehash and
verify the associated OCI bytes before staging.

Require the existing archived-candidate selectors to admit these exact
identities before staging. API requires the successful protected-main push
publisher. For the frontend, the selector requires successful independent
source security, publisher authentication, image validation, both native
builds, the container contract and pre-registry qualification. Its existing
registry-job allowlist permits this archived candidate only because the
failure is confined to the official registry preparation gate. A failed or
missing qualification job stops the cutover.

| Input                                  | SHA-256                                                            |
| -------------------------------------- | ------------------------------------------------------------------ |
| API pair receipt                       | `fec1bf683cc4cb545d0b7e1af7038b0b5f317499388b22f828c9b5735c3e4c1e` |
| API PHP-FPM OCI index                  | `dcef68d7be40e8b4810e10cc526cd05b14562f80a30cb24b225a931a65555c41` |
| API Nginx OCI index                    | `375679b2174e507feb195bea2f9015d7210773bbdc597b170c72926656486dac` |
| Frontend pre-registry receipt          | `6141f2576f80a5b7341bf17f631e11a97a0a63ed33be180935455a2704706c98` |
| Frontend OCI index                     | `3c859855647284cbeee9ddf26dee547265d992e86f8e6630b8fd8a727205cb15` |
| OpenPLZ/DE input authorized by the API | `1066a96a6b3a16629a94c834fca49fe58a2bb01558e17242c53a12d68b290088` |

Bind the actual installed predecessor for each target. Require the applicable
publisher attestations, SBOM associations, independent Source Security,
equivalent current per-platform scanner evidence and the existing
`component-update-v1` decision for each changed component. Include the
public reference exposure in that decision. A candidate attestation leaves
official registry release approval to its existing contract.

The following encrypted off-host archives were independently restored on
840G11. Use them as rehearsal inputs. The activation authority binds a
separate final restore captured and verified under the write fence in step 3.

| Target    | PostgreSQL system identity | Rehearsal archive SHA-256                                          |
| --------- | -------------------------- | ------------------------------------------------------------------ |
| Reference | `7711085157316866085`      | `7f75556f9293a75faed17164d9cde49170de0f92d756f387f83b9cd4fb5e32b4` |
| CX23      | `7710251108046708761`      | `da1a6fb40974c92ac67fafee41fa263bc570db1cb2400b458d9e441a67a9a8ad` |
| CX33      | `7710259205002502169`      | `f13f49c34df129238841d8fcf5ef1b71085cec88137ec6e26c7f51bd8e77fb9a` |
| CAX21     | `7710253390870708249`      | `8f02bc0edcddf4b81a82d861bc4c53f2faa35a33dc77d0d468dcc1640322f5e7` |

## Recovery and activation

1. Verify target identity and synthetic data classification, the PostgreSQL 18
   cluster and migration ledger, fixture identities, and the active OpenPLZ
   import. Verify the complete off-host logical restore for each database using
   the existing [restore procedure](fcos-application-poc.md#cross-host-logical-restore).
   Verify that both private and public durable file storage contain no
   application objects or other file dependencies. Verify that all existing
   key generations and their credentials are recoverable. This scoped logical
   recovery path cannot authorize a cutover if either storage area has
   non-reconstructable contents, a key generation is unaccounted for, or the
   data classification is uncertain.
   Keep the installed artifacts, unit definitions and credential material
   recoverable.
2. Rehearse the new API migration and seed over the recovered state with the
   staged candidate and independent AMD64 and ARM64 qualification. The only
   pending Laravel migration must be
   `2026_11_25_210000_include_customer_house_number_in_duplicate_guard`.
   Verify the new index and existing organization, user and witness data.
3. Stage both components by digest. In the maintenance window, hold the
   existing deployment locks and pause the affected activations. Fence viewer
   traffic to the frontend and API, including cached clients with existing
   sessions, while retaining the private acceptance route. Stop both HTTP
   services. Drain and stop the scheduler, both workers and PHP-FPM, and verify
   that all six roles are inactive. Verify that the migration unit is inactive
   or successfully exited, with no migration process still running.
   Capture the final encrypted logical dump under this write fence. Before
   mutating the database, independently restore that exact archive and bind
   activation to its verified hash and off-host location, the cluster identity,
   WAL position, timestamp, schema and migration-ledger digests, and the
   recorded key-generation and file inventories. Keep credential material and
   private archive locations in the existing protected custody.
   Use the existing separate migration unit and database role. Stop any
   exited oneshot left by the predecessor, reload the candidate unit, verify
   the staged PHP-FPM digest and confirm the unit is inactive. Start it once
   and verify a new successful invocation and the exact new migration ledger.
   Seed the test fixtures in place and explicitly
   run the API's checksum-bound OpenPLZ import if the approved data are absent or
   stale. Reuse an active import with the exact authorized checksum. Preserve
   database, volume, test account, organization, witness and key identities.
4. Start PHP-FPM, then API HTTP. Qualify readiness and address lookups through
   the private acceptance route. Start the corresponding frontend, then both
   workers and the scheduler. Before removing the viewer fence, verify login,
   organization access, exact and prefix postal-code lookup, separate
   house-number handling, and the health and cardinality of all six roles.
5. If a check fails, maintain the write fence. An image rollback requires an
   admissible predecessor and separate compatibility evidence against the
   exact fenced recovery point after restoring it. Otherwise keep the target
   fenced for a forward fix or the existing recovery procedure. The migration
   cannot be reversed by Laravel. Never restore a pre-cutover snapshot over
   writes accepted after the viewer fence was lifted.
6. Adopt the verified running artifact and schema identities through the
   existing enrollment and protected deployment state before resuming the
   component update timers. Record the observed result for each target in #93.

## Post-cutover enrollment

The Lab pins adopt the already-running API pair and Frontend index in this
contract. The combined pin change authorizes enrollment of this observed state.
It carries no compatibility pin for starting a new backend activation. Future
updates use the ordinary independently admitted component transactions.

On each of the three guests and the public reference, verify the native signed
publisher subjects, the running exact image pins, application readiness, and
the unchanged PostgreSQL system identity recorded above. The approved
post-cutover schema hash is
`62126b55ff35c255997e59c4a4356f360b8990a36a3b085a597141bfdd3aa889` and the
migration ledger hash is
`650271e203e03a473618dbe7f7bcb1e9e9a26e4627ce4a27cef2c7f932e87e93`. Reuse
the existing schema and ledger hash procedures. Keep the migration login closed.

Keep both update timers stopped and wait for their services to finish. Use the
protected-main revision containing this enrollment procedure and verify the
GitHub commit signature. Retain the verified OCI archives in the existing Lab
archive store with both native platforms, their SPDX data and attestations.

1. On each Lab guest, run
   [the attended enrollment](../scripts/fcos-lab-adopt-address-baseline.sh)
   as the existing administrator. Pass the target slug, root-owned staging
   directory from the cutover, exact protected revision and SHA-256 of the
   proof tar on stdin. The tar contains `api-proof.txt` and
   `frontend-proof.txt` in that order. In the API file, put the unpublished
   runtime-pair receipt, bundle and source-security report on three separate
   base64 lines. In the frontend file, put the pre-registry receipt, its bundle,
   the prepared document and OCI index on four separate base64 lines.
   The procedure holds the existing guest lock, verifies runtime and PostgreSQL
   identities and preserves the previous journal, policy and migration
   override. It removes only the idle override left by this cutover.
2. When all three guests report the same protected fingerprint, archive the
   previous idle coordinator journal and update `SECPAL_FCOS_BASELINE` to
   the same protected revision. Run the existing coordinator in
   `--component-updates` mode with the installed adapter and state directory,
   omitting `--archive-proposals` on this first run. Its initialization requires
   matching observations from all three guests. Run the regular rollout service
   and start its timer after success.
3. On the reference, run
   [the attended enrollment](../scripts/reference_adopt_address_baseline.py)
   using the existing root-managed reference venv with `-I`. Pass the same
   protected revision. The procedure holds the existing reference lock and
   verifies publisher signatures, running native artifacts, public exposure,
   authenticated readiness and PostgreSQL identity before adopting the
   observed state. Run the ordinary reference update service and start its
   timer after success.

Enrollment preserves running image and database identities. A failure leaves
the affected timer stopped for investigation.

[api]: https://github.com/SecPal/api/pull/3114
[frontend]: https://github.com/SecPal/frontend/pull/2280
[api-run]: https://github.com/SecPal/api/actions/runs/45748341064
[frontend-run]: https://github.com/SecPal/frontend/actions/runs/45712000616
