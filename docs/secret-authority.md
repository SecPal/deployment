<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Secret Authority and Deployment Activation

Owner: [#100](https://github.com/SecPal/deployment/issues/100).
Implementation: `scripts/secret_authority.py`. This is a callable trust
boundary with a small Self-Hosted reference adapter, not a fleet service,
installer, alternate Enrollment implementation or synchronous request dependency.
OpenBao remains the preferred Managed adapter; Self-Hosted is not tied to it.

## Authority separation

Trusted control constructs `DeploymentActivation` with the actual accepted
`host_enrollment.EnrollmentVerifier`. It supplies authenticated serialized
`current_identity()` read-back and independent provider, management-transcript
and installation-incarnation observations as defined by
[Host Enrollment](host-enrollment.md). Secret Authority receives the public CA
and verifier, never the Enrollment CA private key or enrollment-table mutation
rights. A durable current Host Identity remains usable after its temporary
bootstrap certificate expires.

`authorize(identity, purpose, generation_metadata)` is an independent trusted
policy admission supplied by the existing installation/operations owner. It must
raise on denial and return `None` on success; there is no default success and a
boolean claim is rejected. Host requests cannot provide that callback, the
verifier, recovery authority, unseal access or delivery adapter.

Secret Administration is a separate trusted administrative interface. Its key,
database-issuance and recovery methods are never host-request dispatch methods.
The SDK adds no network listener, provider credential, daemon or privilege.

## Activation

1. Trusted policy selects an exact service purpose and explicit authority IDs
   and generation IDs. Secret Authority creates a fresh 32-byte challenge,
   UUID session and lifetime of at most 300 seconds.
2. The actual host calls `host.prove_identity(identity, challenge)`.
3. `activate(session_id, identity, proof, delivery=...)` uses the accepted
   `EnrollmentVerifier.authenticate`, current registration and fresh independent
   management observation. The entire identity is bound: deployment, Host ID,
   generation, key, provider resource, topology role and installation incarnation.
4. Native PostgreSQL serialization atomically consumes that exact session.
   Expired, unknown, consumed, altered and concurrent reuses fail closed. Policy,
   custody and exact current secret generations are re-admitted at redemption.
5. An acknowledged commit precedes secret release. Current host possession is
   rechecked before publishing only the selected purpose's credentials.

Rotation uses the same session/possession mechanism through
`challenge_rotation(..., candidate=ref)`. It additionally requires the
independent `authorize_rotation` callback; ordinary authorization cannot enable
it. Durable rotation-pending intent must already exist before issuing or
redeeming a candidate session. The session binds both the exact candidate and
operation ID, so a rollback/retry cannot reuse an earlier attempt's authorization.
Candidate APP_KEY delivery includes the accepted key for decryption. Normal Activation cannot retrieve a
candidate.

A copied session/challenge is not a bearer credential. It cannot replace host
possession or authorize another purpose. A failed or ambiguous commit releases
nothing. A failed materialization consumes the session and requires fresh
authorization; it never overwrites a prior accepted delivery.

Frontend is secretless. API, workers and scheduler can receive application,
tenant and runtime database/Object credentials; migration receives its separate
DDL identity. Neither can obtain Root KEK, PostgreSQL CA or backup-decryption
authority. HAProxy PROTECTED receives only its Origin Authentication material.
Native PostgreSQL, monitoring, Barman and backup purposes are separate. Every
rotatable credential is additionally bound to its exact Host ID and admitted
purpose set. Independently trusted policy remains mandatory even for a class
allowed by this maximum-authority boundary.

## Native storage and runtime delivery

`PostgresStore` is a deliberately small per-deployment reference backend.
It uses the accepted Enrollment module's native PG18 transport, identity,
durability, timeout and transaction admission. It creates a separate
`secpal_secrets` schema once under explicit DBA authority. Runtime needs only
schema USAGE and table SELECT/UPDATE; it has no Enrollment schema access or DDL.

Values, generation metadata and session state are AES-256-GCM authenticated
ciphertext in PostgreSQL, using native PyCA primitives, random 96-bit nonces and
deployment/domain binding. The key comes from separately protected unseal
authority; it is never stored in the database or returned to a host. An external
private SHA-256 freshness pin rejects stale restored state and database-only
tampering. It belongs outside the database backup/restore domain. A failed
commit with an unmatched pin stays closed; there is no automatic repair.
A native table constraint bounds ciphertext at storage, and the SELECT excludes
oversized data before Psycopg materializes it. Plaintext state is bounded to
4 MiB; this reference backend is not a
Managed customer-capacity claim.

`ProtectedCredentials` writes one private, authority-owned directory per
Activation. It stages and fsyncs the complete selected set and publishes it with
one rename. Names are closed; files contain values rather than shell/env
assignments. Tenant KEK retains its existing 0600 file contract; other credential
files are read-only. No general environment, process argument, rendered unit or
public result contains a value. Public results contain IDs, fingerprints and
paths only.

The existing #92 installer/privileged credential adapter owns native
`LoadCredential=` consumption or the existing individually mounted rootless
delivery, mapped owners, SELinux admission, unit changes and public routing.
It must give each service only its own files. The frontend receives none.
This SDK never publishes a route or silently installs an incomplete host.
It does not replace the existing
[production secret delivery](architecture/production-secrets.md) contract.

Once materialized, accepted workloads use their local protected credentials.
No normal request, read of an already delivered credential or running workload
depends on Secret Authority availability. An outage blocks new authorization,
rotation and recovery; it does not delete existing deliveries.

## Generations, rotation and retention

Every authority has a stable UUID, monotonically allocated generation IDs,
class, creation time, fingerprint, lifecycle status and explicit retention
owners. Existing deployment-wide business classes have one stable authority;
rotation must identify that authority rather than create an unlinked successor. Retired generation IDs are never reused. Initial bootstrap creates
Root KEK, tenant KEK, backup encryption key, Laravel APP_KEY and native PostgreSQL
signing authority before first use. Tenant KEK is wrapped under Root KEK using
RFC 3394; root rewrap changes only wrapped key material, never customer
ciphertext. The signing key stays in the encrypted authority; a PostgreSQL
server generates its own local private key and submits a signed CSR for the
exact `db.secpal.internal` identity.

Native PG18 login issuance consumes existing #81 NOLOGIN privilege groups.
It creates distinct host-bound runtime/migration SCRAM principals with no
superuser, role/database creation, replication or bypass-RLS authority.
Runtime membership inherits only its declared group with no ADMIN/SET
authority. Migration preserves the accepted #81 SET path to its NOLOGIN owner
role for DDL, without granting ADMIN authority.
New logins remain disabled until the existing reviewed start/acceptance adapter
activates them. Native statement, parameter and error-query logging is disabled
before credential SQL, which carries a libpq-generated SCRAM verifier rather
than a plaintext password. Unqualified pgaudit fails closed. No production DB
is modified by repository tests.

A candidate cannot be retrieved by normal Activation. Rotation requires explicit
validation, start/reload, readiness, acceptance, old-credential revocation and
rollback callbacks. None defaults to success. Failed validation/readiness
retains the previous current generation and invokes rollback. An existing private filesystem lock serializes rotations. Before external
callbacks, the candidate durably records rotation-pending and its operation ID
and previous generation. Process termination leaves that obligation visible and
blocks new release or an automatic retry. The same trusted administrative
`rollback_rotation` callback must restore and independently verify the prior
service state before clearing intent; no boolean or default success is accepted.
A lost commit acknowledgment never invokes a speculative rollback across a
possibly committed Current transition. Pin/state read-back establishes the
outcome or fails closed.

Current changes only after acceptance; a failed old-credential revocation is reported
incomplete, never reported as rolled back or successful. Its old generation
remains revocation-pending across restart and blocks new release until explicit
revocation completion; a new custody snapshot cannot bypass that obligation.
Historical keys remain
retained, and any material change requires refreshed independent custody before
another Activation. Normal host replacement does not rotate business keys.

The APP_KEY predecessor limit is checked before any external rotation callback,
not just on a later delivery.

Existing Backup/RecoverySet owners supply their stable IDs to `retain`.
Retirement rejects current, retention-owned, rotation/revocation-pending or
still-wrapping generations and requires
separate explicit authorization after retention obligations end. It does not
implement Barman, Object Backup or a second RecoverySet registry. APP_KEY
delivery includes the existing bounded previous-key set; it never silently
drops a retained key to fit that bound.

## Independent custody and total-loss recovery

`RecoveryCustody` is an independent actor, not an acknowledgment flag.
`checkpoint` first blocks new secret use, exports authenticated encrypted
authority state and the complete generation/fingerprint manifest, then requires
actual recovery of exactly that snapshot and its independently held key.
Only a successful decrypt/required-generation read-back marks that material
revision eligible for Activation. A missing custody actor, key, generation or
concurrent material change fails closed.

The encrypted recovery snapshot does not contain its own recovery key or live
unseal key. Managed custody must use independent split/offline authority and
separate encrypted state retention. The reference API deliberately does not
invent a split-secret scheme or pretend that one local file proves independent
operational custody. External custody evidence must establish its real
administrative, failure-domain and retention separation.

`restore_authority` requires independent Recovery Authority admission and an
authenticated required-generation manifest, then initializes a fresh authority
with separate new unseal authority. Missing historical generations fail; they
are never regenerated. No saved challenge, Activation Session or rotatable
runtime credential is reauthorized by restoration. The operational owner must
fence the lost authority before restoring fresh authority and issue fresh
runtime credentials. Existing accepted runtime can continue during the outage;
restoration does not automatically stop it or assert that external revocation
has happened. Fresh custody is required before any new Activation.

## Validation and acceptance boundary

`tests/secret-authority.py` reuses the existing isolated native PostgreSQL 18
fixture and real host-local OpenSSL Enrollment implementation. It additionally
executes native AES-GCM, RFC 3394 rewrap, X.509 issuance, PostgreSQL SCRAM
issuance and protected file publication. Provider/readiness/policy, service
operations and the custody actor are explicitly synthetic. The suite proves
portable executable behavior, not real provider, production, split-custody,
systemd installation or customer recovery acceptance.

CI runs it in the existing AMD64/ARM64 job with Psycopg 3.3.6 and PyCA
cryptography 50.0.2. Operational custody, native service/rotation adapters and
external recovery fencing need independent evidence before claiming full production acceptance for issue #100. Existing #80/#81/#171/#241 and completed #248
evidence remains valid within its original inputs and scope.
