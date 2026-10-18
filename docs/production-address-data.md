<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Release-bound address reconciliation

Deployment [#344](https://github.com/SecPal/deployment/issues/344) extends the
existing explicit `secpal-migrate.service` one-shot. It does not implement a
new installation or update controller. The API owns source admission, session
locking, CSV validation, activation and retention; see its
[address-data contract](https://github.com/SecPal/api/blob/791f14bdc24ee723a05b99a8482c7affab8ec483/docs/ADDRESS_DATA.md).

## Supported execution seam

`scripts/production-migrate.php` bootstraps Laravel once and admits the selected
release's source configuration using the API's `AddressDataSourceAdmission`.
It runs migrations as `secpal_owner`, closes that connection, loads the separately
mounted runtime credentials through the existing strict secret-file admission,
and creates a new runtime-only connection. It then calls:

```text
addresses:import --no-interaction
addresses:check --no-interaction
```

No source URL, expected digest, force, empty-only or setup-only option is supplied
by the default caller. The API's release configuration remains authoritative.
The API skips HEAD and GET when the approved hash is already active. A changed
pin must pass checksum and CSV admission before transactional activation. All
nonzero command results propagate out of the one-shot. Diagnostics identify the
failed operation without printing exception messages or buffered Artisan output.

`addresses:check` is diagnostic: it can return zero with no activated dataset.
The caller also consumes the API's active-import selector and requires a
successful, nonempty import matching the selected release's expected hash.
This proves the caller's success condition; it does not prove product HTTP
readiness or authorize routing.

## Installation, update and rollback owners

Fresh activation starts the existing target dependency graph: API, workers and
scheduler require and follow successful `secpal-migrate.service`. Import failure
therefore fails this startup prerequisite. A failed candidate must not receive
production routing. This is not a traffic cutover implementation.

The one-shot retains `RemainAfterExit=yes`. Merely starting an already-active
target, restarting an API unit, changing an image declaration or reloading
systemd does **not** execute it again. Full construction
[#92](https://github.com/SecPal/deployment/issues/92) and routine application
update/rollback [#93](https://github.com/SecPal/deployment/issues/93) are open.
They must consume this seam under their existing deployment/migration lock:

1. Admit the exact selected API artifact, compatible schema/data transition,
   credentials, storage, network policy and current Recovery Set.
2. Stage the selected immutable artifact and generated declarations. Keep
   incompatible mutable application roles stopped under the owner's maintenance
   and traffic policy.
3. Explicitly re-execute `secpal-migrate.service` for that release, including when
   the unit previously exited successfully. A synchronous
   `systemctl --user restart secpal-migrate.service` is the existing systemd
   operation; never use a start-only or asynchronous/no-block result as success.
4. Require its zero result and release-data agreement, then complete the owner's
   application readiness, worker cardinality and routing/promotion gates.

Re-running that explicit operation after correcting a failure is the retry.
The importer owns its additional data lock; it does not serialize schema
migrations. Exactly-once migration execution per update still belongs to #93's
deployment lock, not the importer's lock or `RemainAfterExit`.

The API retains at least one prior successful dataset. Download, parse or
activation failure must leave the active valid reference dataset intact. An
application rollback requires #93's schema/data compatibility and Recovery Set
admission before selecting the old immutable release and re-executing this same
one-shot. Supply that release's exact CSV offline or authorize its pinned source.
Retention alone does not switch the active pointer; a verified reimport may be
needed. Never delete address tables, reset PGDATA or restore a whole customer
database just to change reference data. Failed/interrupted inactive candidates
and their eventual pruning remain API-owned.

Managed private rollout automation must implement these same ordered commands,
explicit re-execution, identity/readiness gate, credentials, timeout, session,
storage and source-policy requirements under its own owner. It is not modified
here. End-to-end installation, repeated update promotion and rollback remain
unproven until their owners integrate and qualify these operations.

## Timeout, storage and connection constraints

The migration/import unit has `TimeoutStartSec=3600`, `Restart=no` and the existing
30-second container stop budget. One hour allows the API's optional 30-second
HEAD, 600-second download and additional migration, parsing, approximately
1.2-million-row insertion, activation and pruning work. It is a bounded initial
operational budget, not a measured production performance guarantee. Qualify the
complete operation on the selected host/artifact before acceptance. Timeout,
out-of-memory or storage exhaustion is a failure, never permission to promote
or retry automatically.

Laravel's local disk root is `/app/storage/app/private`, mounted from
`/srv/secpal/private-storage`. The one-shot overlays only
`/app/storage/app/private/address-data/tmp` with a private 128 MiB tmpfs,
mode `0700`, mapped to the existing `10001:10001` container identity, with
`nosuid,nodev,noexec`. This is more than twice the reviewed approximately 55 MB
CSV size. Parsing is streamed in chunks; database rows and indexes consume
native PGDATA capacity rather than CSV scratch space. A larger future dataset
requires renewed resource admission, not automatic growth. Existing unrelated
tmpfs mounts are unchanged. Host admission still owns memory and PGDATA byte
and inode headroom; full-size qualification must observe peak memory, scratch
use and database growth, including retained prior rows and concurrent workloads.

The API unlinks ordinary successful/failed snapshots. The tmpfs additionally
discards interrupted snapshots when the one-shot container is removed, without
deleting shared private files or racing another importer over a shared directory.
A process interruption may leave an inactive database candidate; it cannot make
that partial candidate active. Retry obtains a new database session and the
API's advisory lock. This scratch design does not redefine the authoritative
Private Object Storage contract owned by #99.

No new database role or grant is introduced. Migrations retain their temporary
DDL authority. The import uses the existing `secpal_runtime` membership with
table DML, sequence usage and schema usage, including cache invalidation; it
does not need owner/DDL privileges. Migration secrets remain absent from all
ordinary runtime roles. The one-shot alone mounts runtime delivery additionally
at `/run/secpal/secrets/import`; it never exports credentials into the OS
environment or command arguments. Secret issuance and membership enforcement
remain #100 and the canonical PostgreSQL qualification contract.

The connection uses the existing direct PostgreSQL 18 loopback mapping,
`db.secpal.internal:5432`, SCRAM and `verify-full`. No transaction-mode pooler or
read/write split is introduced. The API's session advisory lock spans download,
staging, activation and pruning. Laravel reconnect is disabled for this import
connection: session loss fails the operation instead of resuming without its
lock. Competing importer calls fail and can be retried; a deployment lock is
still required for schema and promotion operations.

## Source egress and offline installation

The source is read only from the selected API's reviewed `config/address_data.php`.
Its admission accepts an immutable HTTPS GitHub raw URL. Authorize HEAD/GET only
to that exact release-owned OpenPLZ URL on `raw.githubusercontent.com:443`, plus
the existing resolver path. Do not substitute a branch, mirror, redirect,
download service or environment-supplied digest. The one-shot disables HTTP
redirects through Laravel's HTTP client; a redirect fails import. TLS validation
and the API's full expected SHA-256 remain mandatory.

The existing pasta and [host firewall](host-firewall.md) owners permit ordinary
outbound DNS/HTTPS and restrict privileged loopback/metadata paths. This change
adds no firewall exception or broader egress grant. Those declarations are not
an exact-host/path outbound firewall. A restricted installation must have its
existing network-policy owner authorize and qualify this exact source, or use
offline input. Repository tests do not prove live DNS, TLS or source reachability.

For an approved offline installation/update, stage the exact selected release
CSV as `/srv/secpal/private-storage/address-data/release.csv`, readable only by
the mapped application identity (file `0400`, private parent `0700`). It is a
temporary reference-data handoff, not a customer Object. Render the existing
units with:

```sh
python3 scripts/render-production-quadlets.py \
  --quadlet-output /reviewed-staging/quadlet \
  --systemd-output /reviewed-staging/systemd \
  --offline-address-data
```

This sets only the one-shot's `ADDRESS_DATA_SETUP_SOURCE_PATH` to the fixed
in-container CSV path. The API snapshots and hashes the file using the same
release checksum. There is no digest override. Missing, malformed or mismatching
input fails and blocks this gate. Offline input does not need source egress;
the API may snapshot matching offline bytes before deciding they are unchanged.
Keep the reviewed source available for explicit retry, then have the staging
owner remove it when retention requirements allow. The importer never deletes
the supplied source, only its private snapshot.

## Executable evidence and remaining artifact dependency

`python3 tests/production-address-reconciliation.py` executes the actual PHP
caller with relocated mount paths and bounded application doubles. It covers
ordering, repeated explicit invocation, nonzero propagation/retry, session-loss
failure, missing/wrong active hash, release admission before migration, real
secret-file admission and generated online/offline resource/transport contracts.
It is included in maintained preflight. Existing production-state and native
PostgreSQL suites cover rendered parity, credential isolation and canonical
transport/role consumption.

Importer semantics are owned by the API's
[feature tests at the inspected revision](https://github.com/SecPal/api/blob/791f14bdc24ee723a05b99a8482c7affab8ec483/tests/Feature/AddressDataImportCommandTest.php):
fresh import, unchanged hash without HTTP, changed-pin upgrade/retention,
network failure/retry, concurrent session lock, offline checksum admission and
activation rollback. Deployment doubles do not replace those PostgreSQL tests
or prove actual CSV activation. No production/customer database, real download,
container registry or cloud operation is required by this repository change.

The retained production API declaration is still
`ghcr.io/secpal/api@sha256:ac97416f3feac5c57204421059105389c9add2cfbcda1b063eadf4c6ad7647ab`,
source `7da77556e7a4896940b6c50ccf6ba2c3fb9a8653`. Its default address configuration
predates the release pin from [api#1603](https://github.com/SecPal/api/pull/1603).
This change deliberately preserves that reviewed image. With its default
configuration, source admission fails before migration. A compatible immutable
API image must pass the maintained publisher/attestation and application/PG18
qualification process before activation. Do not use a current tag, local build,
or unreviewed digest to make this dependency appear satisfied.

Independent review and native merge gates remain required after draft feedback.
Frontend attribution is implemented, but actual deployed client attribution,
availability of the selected release's alterations offer and external
[legal authorization](https://github.com/SecPal/.github/issues/46) remain public
rollout gates. Repository validation is neither legal clearance nor production
acceptance.
