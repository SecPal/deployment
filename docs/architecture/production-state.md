<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Production state contract

## Status and authority

This is the implemented D.2 persistence contract for the Debian 13
single-host reference deployment. It uses rootless Podman, the systemd user
manager, and native Quadlet. It is not a live-host installation or a backup
implementation.

[`config/production/state-contract.json`](../../config/production/state-contract.json)
is the one authoritative persistence matrix. The checked Quadlets are generated
from it, and the production-state tests reject drift between the matrix,
renderer, inventory, and checked declarations. This document explains the
contract; it does not create a second metadata authority.

The matrix uses strict JSON so the production host reads it with Python's
standard library and D.2 adds no undeclared PyYAML runtime dependency. The
loader rejects duplicate keys, unknown structure, and any supplied matrix whose
canonical semantic digest differs from the reviewed matrix.

## Classification summary

| Object                                             | Authority and classification                                                                                                                            | Loss, restore, and D.7 boundary                                                |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| PostgreSQL                                         | Durable, authoritative, non-reconstructable business data at `/srv/secpal/postgresql`                                                                   | Loss is unacceptable; restore and backup are required                          |
| Private application storage                        | Durable, authoritative, non-reconstructable business files at `/srv/secpal/private-storage`                                                             | Loss is unacceptable; restore and backup with PostgreSQL are required          |
| Public application storage                         | Classified now as durable and non-reconstructable at `/srv/secpal/public-storage`; “public” describes application authorization, not reconstructability | Loss is unacceptable; restore and backup with PostgreSQL are required          |
| Valkey                                             | Durable AOF queue/cache continuity state at `/srv/secpal/valkey`; never the source of truth                                                             | Included in coordinated D.7 backup and recovery, with PostgreSQL authoritative |
| ACME                                               | Reserved durable TLS-operator state at `/srv/secpal/acme`; D.2 mounts it nowhere                                                                        | Backup becomes required after the future edge activates it                     |
| CrowdSec                                           | Reserved durable security state at `/srv/secpal/crowdsec`; D.2 mounts it nowhere                                                                        | Later CrowdSec work decides its activated restore policy                       |
| Logs                                               | Bounded rootless-Podman `k8s-file` operational state at `/srv/secpal/logs`, with one canonical 10 MB file per production container                      | Not an authoritative restore input; excluded from D.7 data backup              |
| Configuration                                      | Root-owned, non-secret declarative state at `/srv/secpal/config`                                                                                        | Reconstructable from reviewed deployment inputs; D.7 inclusion recommended     |
| Deployment state                                   | Root-owned release/rollback records at `/srv/secpal/deployment-state`                                                                                   | Reconstructable by reconciliation; D.7 inclusion recommended                   |
| Application and data-service secrets               | Stable external secrets delivered to the tmpfs-backed `/run/secpal/secrets` boundary                                                                    | Recovered from their separate external authority, never from product data      |
| TLS, backup, SSH, GitHub, and registry credentials | Infrastructure or operator authority outside product containers                                                                                         | Never stored only in the state they unlock; outside the product backup payload |

There is no anonymous production volume. Podman's graphroot and runroot remain
reconstructable runtime state. Phase B/C named volumes and `local-secrets` are
disposable integration mechanisms and are not production evidence.

## Exact host paths and ownership

The admitted inventory uses service account `20000:20000`, subordinate UID
range `100000:65536`, and subordinate GID range `200000:65536`. The reviewed
default rootless mapping is:

```text
container ID 0     -> service-account host ID
container ID 1..N  -> subordinate start + container ID - 1
```

It produces these host identities:

| Consumer   | Container identity | Host identity   |
| ---------- | ------------------ | --------------- |
| Frontend   | `101:101`          | `100100:200100` |
| PostgreSQL | `999:999`          | `100998:200998` |
| API roles  | `10001:10001`      | `110000:210000` |
| Valkey     | `10002:10002`      | `110001:210001` |

Container IDs are never treated as host IDs. A changed, missing, multiple, or
short subordinate range fails before state preparation. No `--userns=keep-id`,
rootful fallback, alternate mapping method, Podman socket, or remote API exists.

| Host path                      | Exact host owner | Mode   | Runtime use                                                       |
| ------------------------------ | ---------------- | ------ | ----------------------------------------------------------------- |
| `/srv/secpal/postgresql`       | `100998:200998`  | `0700` | PostgreSQL read/write bind to `/var/lib/postgresql/data`          |
| `/srv/secpal/private-storage`  | `110000:210000`  | `0750` | Read/write bind for migrate, API, both workers, and scheduler     |
| `/srv/secpal/public-storage`   | `110000:210000`  | `0750` | Read/write bind for the same API roles                            |
| `/srv/secpal/valkey`           | `110001:210001`  | `0700` | Valkey read/write bind to `/data`                                 |
| `/srv/secpal/config`           | `0:20000`        | `0750` | Selected non-secret files bind-mounted read-only                  |
| `/srv/secpal/deployment-state` | `0:20000`        | `0750` | Operator release and rollback state; no product mount             |
| `/srv/secpal/logs`             | `20000:20000`    | `0750` | Bounded host-side operational logs; containers cannot mount it    |
| `/run/secpal/secrets`          | `0:20000`        | `0710` | Reconstructable boot-time delivery root, never a backup authority |

ACME and CrowdSec paths stay reserved and unmounted until their owning work
selects reviewed container identities. D.2 does not guess those identities or
activate those services.

Installation later copies the checked matrix to
`/srv/secpal/config/state-contract.json`, the PHP/Valkey bootstrap files below
`/srv/secpal/config/runtime/`, and the PHP INI fragment below
`/srv/secpal/config/php/`. These are non-secret, root-controlled inputs; product
containers see only the exact read-only files declared in their units.

## Preparation and fail-closed validation

`scripts/production-state.py` has separate authorities:

- `--initialize-production` is an operator/root operation. It creates a missing
  managed directory once with its final owner and mode. It requires the
  separate `--acknowledge-first-install` decision and accepts an externally
  prepared complete tree through `--initial-secret-source`. It atomically
  publishes that tree, validates it, and writes
  `/srv/secpal/deployment-state/state-layout-v1`. It never changes an existing
  directory and never creates secret values. A normal start or recovery never
  invokes this operation.
- `--validate-production` checks the host view, including exact mapped owners,
  modes, file types, canonical ancestors, hard-link restrictions for secrets,
  ACLs, secret bytes and grammar, and equality of credential delivery copies.
- `--validate-namespace` runs through `podman unshare` in
  `secpal-state-ready.service`. It checks state and secret metadata plus each
  expected consumer-visible path from the D.1 user namespace. It deliberately
  does not read mode-`0400` files owned by other mapped consumers; host
  authority validates bytes and each consumer validates its own seam. Every
  product/data unit also repeats this namespace admission as `ExecStartPre`, so
  restarting one role cannot reuse a stale successful oneshot result.
- Fixture operations require an explicit disposable root. They cannot resolve
  to `/`. The supplied root and every existing descendant are inspected with
  `lstat` before resolution or writes, symlink redirection is rejected, and
  cleanup refuses a symlinked root before recursive ownership changes.

The validator permits only base user/group/other ACL entries and no default or
named ACL. Mode bits and effective ACL access must therefore agree. `/srv`,
`/srv/secpal`, `/run`, and `/run/secpal` are bounded root-owned trusted
ancestors with no named ACL and no group/world write authority. Independent
secret publication proves `/run/secpal` is exactly `0:20000`, mode `0710`, and
ACL-free before creating a staging directory. A symlink, non-directory
substitution, writable or non-root trusted ancestor, unexpected hard link,
wrong owner/group/mode, or inaccessible ACL is a hard failure.

A valid existing directory is preserved byte-for-byte. A missing state leaf
may be created only during the explicitly acknowledged first installation.
Once the layout marker exists, initialization becomes validation-only and a
missing authoritative path fails instead of being recreated. An invalid
existing leaf is never silently repaired. After state and secret validation,
`secpal-postgres-init.service` initializes only an empty PostgreSQL directory;
an existing valid cluster is preserved, while non-empty incomplete state fails
instead of being repaired or overwritten. A missing, partial, malformed, or
extra secret set prevents `secpal-state-ready.service` from succeeding. Ordinary
stop, rollback, container removal, or recreation never removes a host state
path. Layout changes need a separately reviewed migration with explicit rollback
and orphan detection.

## PostgreSQL and application recovery boundary

PostgreSQL, private application storage, and public application storage form one
business recovery boundary. D.7 must capture and restore a transactionally
appropriate PostgreSQL point plus both file trees, bind the evidence to the
target release, and prove metadata after restore. Restoring only one member is
not a successful SecPal recovery. No initializer may silently create a new
PostgreSQL cluster or empty application tree after loss and call the system
recovered.

All five API roles that can run migrations, serve requests, schedule work, or
execute queues receive the same two application-storage binds. This preserves
inode metadata and cross-role visibility across native systemd-user stop/start
and container recreation. Frontend, PostgreSQL, Valkey, and future edge roles
receive neither application-storage bind.

PostgreSQL initialization writes a transient HBA policy in container tmpfs.
Local administration remains socket-local, while every TCP connection requires
SCRAM. Existing and recovered clusters are admitted only after the delivered
credential authenticates over TCP at `127.0.0.1`; a trust-only socket success
is insufficient. The steady server listens on its container interfaces, but it
belongs only to the internal application network, has no published port or edge
membership, and accepts API traffic through the `postgres` alias with SCRAM.

## Valkey decision

Valkey persistence is enabled. The immutable Valkey image writes append-only
files to `/srv/secpal/valkey` with `appendonly yes`, `appendfsync everysec`, and
RDB snapshots disabled. Cache loss alone is acceptable because PostgreSQL is
authoritative, but queued work can represent committed work that has not yet
executed; treating all queue loss as harmless is not justified.

A controlled stop persists the AOF before the container exits. An abrupt crash
has Valkey's documented `everysec` bounded loss window, which is an accepted
single-host limitation rather than a no-loss claim. Host loss requires the D.7
coordinated backup. Recovery validates the AOF before workers start, restores
PostgreSQL first as the authority, and treats possible missing or duplicate jobs
as an operator reconciliation event. Cache entries may be discarded; queue
state may not be discarded without an explicit recovery decision.

## Native lifecycle evidence

`tests/production-state-contract.py` derives the checked Quadlets, creates only
an explicit fixture root, records PostgreSQL/private/Valkey inode and ownership
metadata, models every lifecycle phase, and proves bounded fixture cleanup.
`tests/production-state-native-lifecycle.sh` additionally runs the checked
production set through Podman 5.4.2's native user generator. Its disposable
service is rendered from the canonical private-storage row, exact API
`10001:10001` identity, and production `/app/storage/app/private` bind target.
Through the real systemd user manager it performs controlled stop/start,
removes and recreates the rootless container, and verifies the same bind-source
bytes, inode, mapped owner/group, mode, and size. Generic validation reports an
explicit unavailable result if the admitted generator, reviewed local image,
or user bus is absent. The native Local Integration job sets the required-mode
gate after staging reviewed images, so any missing or invalid native capability
there fails instead of becoming a skip. The lifecycle proof never contacts a
registry itself. D.1a remains the complete product-role parity proof.

## D.7 handoff

D.7 must implement, not redefine, these boundaries:

- required coordinated recovery: PostgreSQL, private storage, public storage,
  and Valkey AOF;
- separately recoverable external secrets: APP key history, tenant KEK,
  PostgreSQL/Valkey credentials, and backup decryption credentials;
- activated edge state: ACME and the later-reviewed CrowdSec policy;
- recommended declarative records: configuration and deployment state; and
- excluded data: Podman graphroot/runroot, tmpfs secret deliveries, caches,
  ordinary logs, images, and containers.

D.2 creates no backup job, performs no restore, and makes no production recovery
claim.
