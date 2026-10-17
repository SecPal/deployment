<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Authoritative Private Object Storage

Owner: [#99](https://github.com/SecPal/deployment/issues/99).
Callable implementation: `scripts/private_objects.py`.
This is a storage contract, not Secret Authority, an installer, a provider
framework, a replication worker or a backup service.

## Construction and trust

Trusted deployment construction supplies PostgreSQL 18 connection parameters,
one deployment/tenant scope, an API/Worker purpose, a backend namespace identity,
required replication targets and three independent admissions:

- `authorize(action, metadata)` applies the existing authenticated tenant,
  business-reference and service policy. It returns `None` or raises.
- `admit_ciphertext(bytes, crypto, tenant_id)` comes from the established
  encryption boundary. It validates the exact already-encrypted representation
  and its public scheme, generation, key reference and wrapped-DEK metadata.
  There is no plaintext mode, key generation or Secret Authority implementation.
- `admit_backend(adapter, mode)` authenticates namespace, credentials, independent
  recovery requirements and qualified adapter semantics. A provider label, an
  `S3-compatible` claim or successful GET alone is insufficient.

Tenant scope is the canonical opaque application tenant identifier (for example
the existing API tenant key ID rendered as a string), not a newly invented
parallel tenant UUID or registry.

These are trusted in-process interfaces, never request-supplied callbacks or
boolean wire assertions. No candidate-local #100 implementation is imported.
Accepted #100 authority can later supply this interface; the portable storage
contract and native graph do not acquire a blanket #100 dependency.

Managed admission rejects any backend whose locality is not `off-host-object`.
The locality declaration is necessary, not sufficient: independent adapter
admission must authenticate it. Managed Single has the same off-host boundary.
An unavailable or unqualified backend fails construction; local files are never
selected automatically.

The shipped `SelfHostedDirectory` is exclusively an explicit Self-Hosted
adapter. Its root must already be private, owned, canonical and admitted for
independent recovery. It is not a Managed fallback or evidence of HA/provider
qualification. Runtime should receive a scoped storage interface/credential,
never authority over unrelated paths or a host-wide secret bundle. Frontend and
HAProxy are rejected as object-runtime purposes.

## Adapter semantics

The small equivalent-storage port has exactly these runtime operations:

| Operation                  | Required result                                                                                            |
| -------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `create(key, ciphertext)`  | Create-only durable final bytes, atomically visible; raise on any collision, overwrite or uncertain result |
| `stat(key)`                | Exact stored-byte size, or `FileNotFoundError` for absence                                                 |
| `read(key, maximum_bytes)` | Exact bytes within the supplied allocation bound; authenticated namespace and normal transport security    |

Private opaque keys are random UUID bytes rendered as 32 lowercase hex digits.
They contain no tenant, business filename, directory, user-controlled prefix or
provider path. Finalized bytes are immutable. A changed document gets a new
object/key; there is no runtime overwrite method. Provider ETags are not consumed.

The Self-Hosted adapter uses private staging, file fsync, atomic exclusive
hard-link publication and directory fsync. It rejects symlinks, unsafe ownership,
noncanonical roots, nonregular files, unexpected modes and path-valued keys.
A sync failure cannot publish READY. Interrupted private staging files are not
authoritative objects and require exact-owned storage cleanup, not broad pruning.

All adapters must enforce authenticated transport, least-authority credentials,
create-only access and independent durability. Qualification must exercise actual
available service implementations and the exact namespace configuration. This
source does not include or qualify a Managed commercial provider adapter.

## PostgreSQL publication

`reserve(ciphertext, crypto)` validates encryption and commits PENDING metadata:
object/deployment/tenant identity, backend/key, scheme/generation/wrapped-DEK
metadata, exact byte count and SHA-256 over **all stored ciphertext bytes**.

`publish(object_id, ciphertext, reference_id=..., attach=...)` locks that row,
reauthorizes the exact scope, repeats encryption admission, creates immutable
durable bytes, and independently reads/stat-verifies exact size/hash. Only then
does one acknowledged native transaction publish READY, the unique business
reference and every required ReplicationIntent. `attach(db, ready_metadata)`
may bind real application rows through the **same** connection/transaction. It
must not commit, open another transaction or perform external side effects.
A failed binding rolls back READY, references and intents together.
A native Psycopg transaction context rejects callback commit()/rollback() before
either can act; attachment code remains trusted SQL, not a sandbox for adversarial code.

The transaction reuses accepted PG18 transport admission, verify-full/secure
Unix socket identity, durability settings, SERIALIZABLE isolation, bounded locks
and failure handling from Host Enrollment. This reference serializes catalog
operations using that existing transaction boundary; it makes no throughput SLA.
Adapter calls must use bounded timeouts. Large-object streaming and application
upload limits belong to concrete adapter/product integration, not guessed host
resource minimums.

A database failure after successful PUT leaves a PENDING orphan with an opaque
reserved key. A failed or lost PUT acknowledgement never triggers an automatic
overwrite/retry or infers durability from later GET. An ambiguous final DB commit
returns an error: reconcile through independent catalog/reference read-back,
never blind publication replay. Concurrent publishers cannot both commit.
Database triggers reject changes to finalized identity, ciphertext metadata and
illegal lifecycle transitions.

`read` requires READY and tenant/service admission and verifies exact bytes
again. A separate `continuity` purpose can `export` READY or retained tombstoned
bytes and public metadata for #128/#109 without decrypting or re-encrypting.
Normal runtime cannot invoke export; continuity cannot write business objects.

## Deletion and independent retention

Business `tombstone` marks the object's references deleted without deleting bytes.
Normal reads then stop. The catalog keeps the original metadata.

`ObjectRetention` is separately constructed with the existing retention/
replication authority. Recovery/backup owners install explicit UUID holds and
release only their own admitted holds. Replication completion is accepted only
by that authority, not API/Worker. No recovery or replication worker is introduced.

`ObjectGarbageCollector` alone receives an exact-key destroy adapter and an
independent retention/horizon admission. Collection requires:

- PENDING orphan or TOMBSTONED state, older than the independently chosen cutoff;
- no live business reference, retention hold or unaccepted replication intent;
- current independent admission of backup/RecoverySet horizons and orphan grace;
- actual confirmed absence after exact-key physical destruction.

The row lock serializes publication, holds and collection. A failed destruction
or uncertain database acknowledgement retains safe metadata for read-back.
DELETED keys remain reserved forever; they cannot be reused for different bytes.
Retention admission cannot be replaced by age alone. No generic runtime delete
credential is created.

## Installation-owned database privilege boundary

`initialize_catalog` is an explicit migration/DDL-authority operation and never
runs from an application entrypoint. It grants nothing to PUBLIC or runtime.
Use existing #81 stable NOLOGIN privilege roles and separately issued LOGIN
identities; do not use the migration connection for ordinary runtime.

The reviewed runtime SQL grant envelope is USAGE on `secpal_objects`,
SELECT/INSERT on objects, business_references and replication_intents,
UPDATE(state) on objects and UPDATE(tombstoned) on business_references.
Runtime has no table ownership, DDL, object-row DELETE, immutable-column UPDATE,
retention-hold changes or replication-acceptance authority. Trusted application
tenant authorization remains required; database privilege groups do not replace
tenant policy. Retention/GC receive separate independently administered authority.

## Evidence and remaining acceptance

`tests/private-objects.py` uses native PostgreSQL 18, real AES-GCM synthetic
ciphertext and real fsync/exclusive filesystem publication. It exercises integrity
failure, collisions, concurrent application nodes, database rollback/lost ACK,
privilege separation, tombstones/retention, physical-GC failure and exact
ciphertext export. The existing AMD64/ARM64 native integration jobs run it.

Provider/policy/encryption admissions in that suite are synthetic. The
`off-host-object` composition probe deliberately wraps a local adapter and
proves only interface behavior, **never** real off-host durability or HA.
Two catalog instances prove concurrent catalog semantics, not two production
application nodes. No customer keys, live providers or accepted test hosts
are used.

Full #99 acceptance remains conditional on an independently qualified Managed
adapter/namespace, real off-host multi-node/replacement evidence, least-authority
service credentials and representative product integration. Current API services
still use Laravel's local disk and do not yet consume this new port; that existing
API source is read-only in this deployment delivery. Existing disabled inventory
gates and runtime fixtures remain unchanged. No local-authoritative Managed path
is enabled to conceal those outstanding requirements.
