<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Native PostgreSQL 18

The production declaration is
[`postgresql-contract.json`](../../config/production/postgresql-contract.json).
It consumes the accepted native PostgreSQL qualification interface. PostgreSQL
runs as the Rocky distribution `postgresql.service`, under the distribution's
`postgres:postgres` identity and SELinux `postgresql_t` domain. No product
Quadlet, Podman user namespace, container graphroot or anonymous volume owns it.
The current supply path is Rocky Linux 10.2+ signed Application Stream RPMs on
both amd64 and arm64. PG16/17, PGDG and container compatibility paths are absent.

## First installation and configuration

General host installation remains #92. The PostgreSQL portion consumes the
exact package version/release and configuration bytes in the declaration;
rendering performs no host mutation:

```sh
python3 -I scripts/render-native-postgresql.py --runtime-uid 20000
```

The numeric UID is the admitted host service account, which owns the rootless
pasta processes; it is not the mapped container UID. The JSON envelope contains
`postgresql.conf`, `pg_hba.conf`, `roles.sql`, `loopback.nft` and `service.conf`.
An operator installs those exact bytes as files, never evaluates the envelope
as shell code and never substitutes arbitrary SQL, HBA, systemd or nft input.

On an explicitly admitted fresh host, install the three exact NEVRAs for the
host's RPM architecture with `dnf4`, enabling only reviewed Rocky
`baseos,appstream,extras` repositories. Record installed NEVRA, repository and
Rocky signature identity. Same-major package maintenance requires a reviewed
version/release update and requalification; production never discovers a newer
version at startup.

Resolve the installed `postgres` account from the host account database.
Before initialization inspect the actual native data filesystem, not Podman
graphroot: retain the existing minimum of 20 GiB and 200,000 free inodes, with
at least 20% byte and inode headroom. Installation must fail if that physical
precondition is absent; a historical #80 artifact does not assert new PGDATA
filesystem observations.
Initialize only an absent or empty `/var/lib/pgsql/data` owned by that account,
mode `0700`, using the distribution `initdb` with UTF-8, `C.UTF-8`, local peer
authentication and host SCRAM. Refuse any symlink, existing initialized cluster,
nonempty directory or incompatible major. Installation, restart and recovery
never remove, reset, recursively re-own or recreate existing PGDATA. A missing
cluster after installation is data loss and requires its separate recovery
contract. No production operation is executed by repository validation.

Install `postgresql.conf` and `pg_hba.conf` as `postgres:postgres`, mode `0600`,
in PGDATA. Install `service.conf` as root-owned mode `0644` at
`/etc/systemd/system/postgresql.service.d/secpal.conf`. It bounds startup and
shutdown and sets `UMask=0077`; service ownership remains distribution-owned.
Install the exact UID-bound nft table before any application role starts and
install it root-owned, mode `0600`, at
`/etc/nftables/secpal-postgresql.nft`. The rendered host systemd unit owns only
that exact table. Its user-manager drop-in requires and binds the service
account manager to the firewall unit, so stopping the boundary first stops
product processes. Conflicting tables fail startup. The native DB dependency
is only Wants/After: a DB outage leaves the application running to report
unavailable readiness. Install host units separately from systemd-user units:

```sh
python3 scripts/render-production-quadlets.py \
  --quadlet-output config/production/quadlet \
  --systemd-output config/production/systemd \
  --host-systemd-output config/production/host-systemd
```

The host installer copies `host-systemd` under `/etc/systemd/system`, preserves
other nft tables and must keep this table across unrelated firewall reloads.
It enables the boundary before enabling the service-account user manager. A conflicting
existing `inet secpal_postgresql` table is an admission failure, not permission
to flush other firewall state. Host construction owns persistence and boot
ordering; rootless roles receive no firewall privilege.

The external #100 authority delivers the active server material generation at
`/etc/secpal/postgresql/current/{server.crt,server.key,ca.crt}`. Each file is
`postgres:postgres`, mode `0600`; the generation directory is `0700`. The server
certificate covers `db.secpal.internal`. Its matching private key belongs only
to native PostgreSQL. CA signing keys remain outside PGDATA, server delivery and
product containers. No production issuer, rotation, escrow or recovery system
is implemented here.

Apply the distribution PGDATA SELinux policy and the persistent file-context
mapping `postgresql_db_t` for `/etc/secpal/postgresql(/.*)?`, then `restorecon`
those exact trees. Require enforcing SELinux, effective `postgresql_db_t` data
and TLS files, and `postgresql_t` process labeling; never disable labeling or
SELinux. Reload systemd and enable/start the native service only after server
material, configuration and the firewall boundary are admitted.

Run `roles.sql` exactly once through the native `postgres` peer-authenticated
administrative path with `psql -X -v ON_ERROR_STOP=1`. It creates the stable
NOLOGIN privilege roles and the owner-controlled `secpal` database. Existing
roles/database are a first-install conflict, not an implicit destructive reset.
Production issuance of LOGIN identities and their SCRAM credentials remains
with issue #100. Do not place passwords in command arguments, environment, SQL evidence
or logs.

## Transport and identity

PostgreSQL listens only on `127.0.0.1:5432` and `[::1]:5432`. Local administrative
access accepts only the native postgres peer. HBA permits TLS/SCRAM connections
to `secpal` from exact loopback addresses and membership in runtime or migration
roles, then rejects all other local/TCP access. TLS starts with initialization;
plaintext application TCP is never a bootstrap compatibility mode.

Every database-consuming product role uses:

```text
Network=pasta:--no-map-gw,--map-guest-addr,none,--map-host-loopback,169.254.81.1
AddHost=db.secpal.internal:169.254.81.1
```

The special address is a reviewed pasta loopback mapping, not a host gateway.
The UID-filtered host output table allows that service account only PostgreSQL
TCP 5432 on loopback and rejects its other loopback destinations. Apply both
parts together. No generic gateway mapping, host networking, PG Unix socket,
runtime API/socket or NET_ADMIN capability is granted. Private database
hostname semantics remain stable for later explicitly owned replacement/HA
contracts; those contracts alone may introduce private replication listeners.
No API/frontend publication or Edge composition is implemented here.

Application PHP/PDO/libpq uses `DB_HOST=db.secpal.internal`, `verify-full`, the
issued client CA file and SCRAM credentials. The production PHP bootstrap
clears libpq service/host/TLS overrides and test database/schema selectors,
then fixes the canonical transport policy in process configuration. Server TLS
alone does not prove client verification. The independently trusted qualifier
exercises actual PDO certificate/hostname failures and downgrade rejection.
Channel binding is not required without supported PHP/PDO qualification.

## Database authority and application state

`secpal_owner` owns the database/schema and objects, has NOLOGIN and cannot be a
runtime identity. `secpal_runtime` grants only database CONNECT, schema USAGE,
table SELECT/INSERT/UPDATE/DELETE and sequence USAGE/SELECT. Default privileges
are attached to the owner so subsequent explicit migrations preserve those
rights. PUBLIC has no database/schema privileges or default function EXECUTE.
`secpal_migration` can explicitly SET ROLE to owner, with no inherited owner
DDL and no ADMIN membership. Neither application group is superuser,
CREATEDB, CREATEROLE, REPLICATION or BYPASSRLS.

Externally issued runtime LOGIN identities inherit runtime membership with
ADMIN false and SET false. Migration LOGIN identities use NOINHERIT and only
the explicit migration membership, ADMIN false, INHERIT true, SET true. They
can connect but must explicitly assume owner for DDL. They receive no runtime
mount. The explicit migration oneshot boots the fixed application and sets
owner on its PDO session before invoking its real migrations once. Migration
execution is absent from application entrypoints and health checks.

The stable NOLOGIN backup role has owner-default SELECT on tables and schema
USAGE, with no DDL or replication privilege. The stable NOLOGIN replication
role has only the PostgreSQL REPLICATION attribute. No backup or replication
LOGIN, HBA entry, connection credential, listener or backup job is activated.
The owning backup/HA contracts must grant and qualify their exact future
consumption, without borrowing runtime or migration authority.

Sessions, durable queues, shared cache, scheduler heartbeat and tenant key state
remain PostgreSQL-backed. Valkey/Redis units, state and credentials are absent
from production. Durable jobs are business state; container replacement must
not discard them. PostgreSQL plus private/public application files retain their
coordinated backup/recovery boundary without implementing Barman or recovery.

The fixed application provides `/health/ready` and `/health/live`. Readiness
requires PostgreSQL, tenant KEK/key state, shared cache and scheduler/worker
heartbeats. Liveness tests the running HTTP process independently of the DB.
A PostgreSQL outage must produce readiness 503 while liveness remains 200;
restoration must recover readiness in the same application process. Podman
health uses process liveness, so a DB outage does not replace application
processes or run migrations. Initial tenant setup and operational heartbeat
provisioning remain their existing application/setup contracts.

## Evidence and lifecycle boundaries

The accepted-main `native-postgresql-18` mechanism composes frozen #80 host
admission with separate native infrastructure and PHP/PDO application evidence.
The frozen host target/harness and its historical meaning remain unchanged.
Current production rootless inventory and state preparation no longer claim
ownership of PostgreSQL or Valkey paths; the native declaration owns PGDATA.

Repository contracts prove configuration consumption and fail-closed metadata.
The #119/#126 disposable PG18 fixture proves application persistence and
restart semantics. Only exact-run, independently admitted real Rocky evidence
on both supported architectures proves package provenance, systemd/SELinux,
transport/roles/network and application availability. Candidate executables
never gain root, provider credentials or evidence authority during qualification.
Retain candidate/control identity, actual observations and guest/provider
cleanup plus absence read-back. See [qualification authority](../postgresql-qualification.md).

The [primary #81 delivery PR](https://github.com/SecPal/deployment/pull/286)
is the evidence index for the exact candidate. It records both admitted Rocky
architecture runs, candidate/control bindings, artifact digests, guest cleanup,
provider cleanup and authoritative absence read-back. The underlying closed
non-secret artifacts are retained with the workflow and workspace evidence;
a caller-authored index cannot grant qualification PASS.
