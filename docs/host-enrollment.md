<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Host Enrollment and Workload Identity

Owner: [#241](https://github.com/SecPal/deployment/issues/241).
Implementation: `scripts/host_enrollment.py`. This is a callable trust boundary,
not an installer, provider adapter, fleet service or Secret Authority.

## Admission and custody

Trusted construction/control code supplies the existing #80/#92 readiness
admission. It must reject a host that has not completed Standard Installation
and Host Conformance, or already contains deployment authority. There is no
default successful admission and no host-supplied "conformant" flag.

`LocalHost.create(..., ready=admit_local_readiness)` calls that admission before
creating any state. The host then generates a fresh P-256 private key with the
native OpenSSL installation. Its private directory is mode 0700; the key is mode
0600 and never returned by the API. Do not copy this directory into an image,
snapshot, evidence bundle or replacement host. Interrupted initial creation
fails closed and never silently regenerates a key.

`LocalHost.request()` returns only a signed CSR, public-key fingerprint, fresh
Host ID, deployment/resource/role binding, timestamps and local machine/SSH
host-key correlation facts. Those facts alone are not provider authority.

The separately held `EnrollmentAuthority` takes:

- An Enrollment CA certificate and its private signing key, outside host state.
- One expected deployment, exact #169 `ResourceTarget` and topology role.
- `observe(document)`: independently authenticated provider INSPECT read-back
  plus authenticated management observation of the exact document and machine.
- `ready(observation)`: the existing trusted readiness admission.
- `connect()`: a bounded Psycopg 3 connection to dedicated PostgreSQL 18 state.
- Optional `recovery(request, previous_identity)`: explicit, independent
  recovery authorization, checked at both grant issuance and consumption.

Admission callbacks return `None` on success and raise on rejection; boolean
claims are rejected. They are trusted in-process interfaces, never wire fields.
The #169 contract owns provider request/result admission. Its resource versions are transient
inspection preconditions, not permanent host fingerprints. IP addresses,
unsigned metadata and a caller-constructed dictionary cannot substitute for the
trusted provider/management boundary.

## Grant, possession and commit

`authority.grant(request)` issues a signed grant with a maximum 300-second
lifetime. It binds deployment, exact provider resource, role, Host ID, machine
facts, fresh public key, request hash, grant ID, generation and Enrollment CA.
It contains no deployment data, credentials or business/backup encryption keys.

`host.prove(grant, ca_certificate)` verifies the grant and signs its
domain-separated transcript with the host-local private key.
`authority.consume(request, grant, proof)` repeats fresh independent
provider/management/readiness admission, verifies possession, and atomically
records the enrollment and consumes the grant. Duplicate, expired, altered,
unknown or consumed grants fail closed. Concurrent consumers serialize in a
PostgreSQL transaction; only one generation can commit.

The returned X.509 credential is client-authentication-only, bound to the exact
grant and host public key, and expires with the grant. Caller CSR extensions
cannot grant extra certificate authority. `host.accept(credential, ca)`
validates the pinned chain and bindings before atomically publishing public
enrollment state. ENROLLED is asserted only after complete verification.

A pre-commit issuance failure rolls back. A committed but lost response does
not make the grant reusable: obtain a fresh, explicitly authorized recovery
grant. Recovery uses the same protocol, advances the generation and invalidates
the previous credential in current-state verification. Rebuild, replacement,
lost/compromised key or changed machine identity needs fresh local identity and
explicit recovery authority. Ordinary reboot retains the original identity.
No weaker recovery endpoint or permanent bootstrap secret exists.

## PostgreSQL state and authority separation

ADR-017 applies: PostgreSQL 18 is the sole state engine. Psycopg 3 is required
only by the Enrollment Authority; host-side key operations use the native
OpenSSL tools and Python standard library. Use distribution-controlled libpq
and verify-full for a remote database (runtime rejects unverified or unencrypted network connections); a private, authenticated Unix socket is
also appropriate. Local socket admission checks canonical paths, every parent
directory, non-writable directory permissions, socket type and trusted ownership
(root, the authority user or the local PostgreSQL administrator). A shared
`/tmp` socket or a symlink alias is rejected. The trusted connection factory owns
credentials and bounded connection timeouts; they never enter requests, grants
or evidence.

The DBA explicitly calls `initialize_authority_store(connect, ca_certificate)`
once on a dedicated authority database. Runtime never initializes, recreates or
repairs missing replay state. State is pinned to the CA fingerprint. Preserve
it across authority restarts and recover it under independently owned database
durability/recovery requirements; restoring an older replay ledger must never
silently re-enable consumed grants.

Keep schema ownership separate from the runtime role. Grant runtime USAGE on
`secpal_enrollment`, SELECT on its tables, INSERT on `grants`/`enrollments`,
and UPDATE of only `grants.consumed`. Do not grant DELETE, schema ownership,
DDL, application-database access or Secret Authority permissions. Transactions
require durable synchronous commits. The database holds public identities,
certificates and grant consumption state, not host private keys.

Database rows alone cannot assert ENROLLED. Both authority read-back and the
public verifier authenticate the existing signed grant and CA-issued client
certificate, its exact identity/generation/scope and registered public key.
The certificate proves completed registration at its original issuance time
even after its temporary bootstrap validity ends. Live grant consumption and
bootstrap certificate admission still enforce current expiration. Direct
database write access without the Enrollment CA key cannot forge a registration;
malformed state fails closed rather than falling back to an older identity.

## Consumer interface for #100

`current_identity()` returns only the current public identity, CSR, machine
correlation facts and existing public grant/certificate for the authority's exact
resource scope. `EnrollmentVerifier` needs the public CA,
trusted provider/management observation, and authenticated current-identity
read-back; it does not need the Enrollment CA private key or database write
authority.

Secret Authority #100 supplies a fresh, single-use 32-byte challenge and verifies
`host.prove_identity(identity, challenge)` with
`verifier.authenticate(identity, challenge, proof)`. The current-state callback
must return the complete authenticated `current_identity()` record from the
Enrollment Authority, never host-supplied registration data. It supplies the
registered public key without granting signing or write authority. The durable
Host Identity survives expiration of its bootstrap certificate and normal
restarts; new proof still requires fresh provider/management correlation and
current-generation read-back. `verify(credential, challenge, proof)` additionally
validates the temporary certificate and grant during their validity window.
A certificate without the private key, a stale generation, a changed resource
or a copied Host Identity cannot authenticate. #100 separately owns
challenge/session replay protection,
purpose-bounded Activation Sessions, Secret delivery and subsequent
re-authorization. Enrollment grants none of those authorities.

## Validation scope

`python3 tests/host-enrollment.py` requires OpenSSL, Psycopg 3 and native
PostgreSQL 18 binaries. It runs as an unprivileged user, starts a disposable
PG18 cluster behind a private Unix socket with no TCP listener, and removes it
afterward. It exercises real signing, certificate validation, database
transactions, races, rollback and restricted database privileges. The existing
AMD64/ARM64 integration job runs it; no new required check is introduced.

Provider/readiness adapters in this suite are explicitly synthetic. Passing it
is not authenticated blank-host enrollment or production Host Conformance.
Real-system acceptance additionally requires trusted management/provider
observation and existing #80/#92 admission for an isolated, genuinely ready
host. Existing activated-host application evidence remains applicable only
within its original source, host and qualification scope.
