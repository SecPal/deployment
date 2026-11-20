<!-- SPDX-FileCopyrightText: 2026 SecPal Contributors -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

# Reproduce the SecPal FCOS application proof

This fixture exercises the application on an already qualified FCOS lab host.
It composes the maintained [integration Quadlets](quadlet-integration.md)
with private HTTPS and persistent rootless volumes. The fixture is synthetic.
Use the normal Host Enrollment, Workload Activation and recovery contracts
for deployments with customer data.

## Upstream release candidates

The **FCOS Lab Release Discovery** workflow on protected main compares SecPal
publish runs against the admitted product source commits. A result of
`ahead` identifies an upgrade candidate. The workflow also reports exact
stable tags from the PostgreSQL 18 Bookworm and HAProxy 3.2 Trixie Docker
Official Images catalog, and the upstream CrowdSec Engine/AppSec, SPOA and
OWASP CRS release catalogs. The report can be reproduced with
`python3 scripts/fcos_lab_discovery.py` using the GitHub CLI.

The report grants no deployment authority. A reviewed change still needs the
admitted product attestations, exact immutable digests, native amd64 and
arm64 children, and the signed CRS release assets where applicable. The
workflow creates only a run summary. Preparing and reviewing pin changes
continues through the existing GitHub pull request workflow.

## Render and stage

Record the exact reviewed Git revision and retain the private inputs and bundle
digest in the restricted qualification record. The renderer writes a fresh
directory outside Git. Its input is a unique fixture instance, a per-deployment
DNS parent, an RFC 1918 bind address and the approved ingress ports.

```bash
python3 scripts/render-fcos-application-poc.py \
  --profile stack --instance labpoc01 --domain lab.example.invalid \
  --bind-ipv4 10.0.0.28 --port 18443 --https-port 443 \
  --output /private/qualification/stack
```

The gateway is the only published role and listens on the supplied private
address. Use the site's existing WireGuard ingress approval for the external
port. Supply the matching TLS chain and key separately. Use the existing
publicly trusted certificate for the actual lab names. The gateway's HTTPS
health check and the testing client both require a trusted issuer. The
`example.invalid` names above are syntax examples. Use native digest and
publisher admission for each existing image pin before staging it into the
runtime user's Podman store. Build the generated gateway Containerfile using
the pinned base, `--pull=never` and `--network=none`. Tag it
`localhost/secpal-integration-gateway-labpoc01:2.10.2` for this instance.

Authenticate the host and admit an empty slot before transferring the bundle.
Stop on any existing fixture unit, container, named volume, network or staging
directory for the selected instance. Put `assets/` under
`/var/lib/secpal-application-poc/labpoc01`, with traversable root-owned
directories and read-only, SELinux container-readable files. Supply the
chain at `tls/fullchain.pem` and the private key at `tls/leaf.key` with read
access for only the mapped gateway identity as needed. Install the generated
units as administrator-owned files in the existing rootless user's Quadlet
directory, with its normal SELinux labels. Keep real TLS material and test
passwords outside the rendered bundle and logs.

### Private HAProxy gateway

Use `--gateway haproxy` with `--least-privilege` for the FCOS HAProxy
variant. Set `--port` to the host's admitted WireGuard listener and
`--https-port` to the port visible to clients. The existing lab firewall
can retain its private 443-to-18443 translation. Give a disposable slot a
different instance and socket port, even if it carries the same hostnames.
The Caddy variant remains available for the earlier fixture and rollback.

Stage the usual product and database assets and Quadlets. In addition:

1. Pre-stage the native HAProxy image in the rootless user store. The
   renderer pins Docker Official Images `library/haproxy` 3.2.27-trixie at
   `sha256:5ddf08c89c95a311f4bfb761d74016597fdca76ecfcdf169ed1bab117f3da1ea`.
   Check the [Official Images packaging revision](https://github.com/docker-library/haproxy/tree/e8a1db5b5042e4209697fdac2e203b26ad641b2f/3.2),
   registry index and corresponding provenance statement for each native
   child. The admitted `linux/amd64` child is `sha256:e397c53f7f74a33b4048abdbfb52784f86cfe6099f038a053e137b12c3f6707a`
   and the `linux/arm64/v8` child is `sha256:54d2863bf03952254b2d3abe371615534f80a19d799089752b3ac5625baaaebf`.
   This is the third-party publisher's lab input, under the separate
   [image-supply contract](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-oci-supply-chain-vulnerability-evidence-adr021.md).
2. Install `edge/haproxy.cfg` in the fixture's `edge/` directory as
   administrator-owned, read-only to the runtime, with SELinux type
   `container_file_t`. Install `edge/<prefix>-gateway.socket` as an
   administrator-owned user-systemd unit under `/etc/systemd/user/`. The
   Quadlet starts the socket when the rootless user manager starts the gateway.
3. Stage the matching certificate chain and key as `tls/viewer.pem`, on the
   guest. Permit only the mapped container UID 99 to read it and apply the
   SELinux container-readable type. Keep the directory traversable by that
   UID. Mount the directory read-only as defined by the Quadlet.
4. For a fresh slot, follow the separate-authority bootstrap below and seed
   its synthetic tenant keys and account. API readiness includes tenant keys,
   backend state and worker/scheduler checks. HAProxy uses HTTP readiness to
   admit API traffic. Neither migration nor credential initialization is
   ordered into ordinary gateway startup.

Systemd passes the bound TCP listener to HAProxy, which accepts the client
connection directly. This preserves peer identity across the rootless network
boundary. HAProxy strips
caller forwarding headers and regenerates them from the peer, TLS and the
admitted host. The fixed `frontend` and `api` aliases on the private Podman
edge network are the only upstreams. The gateway has no application network,
database port, host networking, host capabilities or runtime socket. The lab
gateway uses the existing TLS material and firewall. Production certificate
automation and security inspection have their existing contract owners.

For an existing slot, stage the candidate beside the working configuration.
Compare the generated product and database units with the installed units
before a gateway-only cutover. Preserve their volumes and migration state.
Keep the working gateway unit, certificate and configuration for rollback.
When changing gateway implementation, stop the old listener immediately
before starting the new one and verify both canonical HTTPS endpoints.

For a HAProxy configuration update, put `candidate.cfg` beside `haproxy.cfg`
with the same ownership, mode and label. From the runtime account validate it
using the admitted running image:

```bash
podman exec --user 99:99 --env "SECPAL_TLS_SOCKET=127.0.0.1:$edge_port" "$prefix-gateway" \
  haproxy -c -f /usr/local/etc/haproxy/candidate.cfg
```

The placeholder socket is used only for config checking. The actual service
receives the fixed systemd listener at FD 3. On validation success preserve
the currently admitted file and atomically rename the new file into place.
`systemctl --user reload "$prefix-gateway.service"` rechecks the active file
before signaling the HAProxy master. Check both HTTPS backends after reload.
On failure atomically restore the saved file and reload it. A rejected
candidate leaves the active file and worker alone. For disposal stop both the
gateway service and socket, then remove their administrator-owned units and
the exact fixture-owned resources as described below.

### Private CrowdSec and AppSec

Add `--appsec` to the private HAProxy command. The additional `security-units/`
Quadlets run in a separate unprivileged, lingering user manager, under an
administrator-allocated UID with its own subordinate IDs. Stage them in
`/etc/containers/systemd/users/<security-uid>/`. HAProxy and the product keep
their existing runtime. The internal security network carries only Engine/LAPI,
AppSec and SPOA requests. SPOA accepts HAProxy through one Unix socket. The
security network publishes no ports and needs no external service while running.

Use CrowdSec 1.8.2 Debian and SPOA 0.3.1. The generated Quadlets contain their
exact indexes. Verify the selected native child, its config architecture and
publisher source revision before staging both images into the security user's
store. The releases map to [CrowdSec `3d369d64`](https://github.com/crowdsecurity/crowdsec/commit/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c)
and [SPOA `4705eac0`](https://github.com/crowdsecurity/cs-haproxy-spoa-bouncer/commit/4705eac0452d406d26f31bdc575763f54c55f858).

Before startup, stage the generated `security-config/` as `security/config/`
under the fixture root, owned by the guest administrator and readable by the
mapped security identity. Copy `patterns/` from `/staging/etc/crowdsec/patterns`
of the admitted engine image. Create an empty `postoverflows/` and write `{}`
to `hub/.index.json`. Use the configuration directly with the engine binary.
That keeps dependencies local and avoids a moving Hub or Central registration.
The pinned [Engine's acquisition schema](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/acquisition/modules/appsec/config.go)
supports `appsec_configs`. Its local item discovery loads the staged
`appsec-configs/` and `appsec-rules/` directories independently of a remote
Hub catalog. Keep both directories in the staged configuration and verify
real rule rejection after startup.

Use the [signed OWASP CRS 4.30.0 minimal release](https://github.com/coreruleset/coreruleset/releases/tag/v4.30.0).
Verify the detached signature with the [pinned publisher fingerprint](https://coreruleset.org/docs/1-getting-started/1-1-crs-installation/)
`36006F0E0BA167832158821138EEACA1AB8A6E72` and verify the compressed SHA-256
`3d678a41fd5aade34760127fef5dd64fd7a77848913fc0f70dde0cf467c94427`.
Stage the release's `rules/` files and copy `crs-setup.conf.example` as
`crs-setup.conf` under `security/state/data/`. Keep the rules administrator
owned, with `state/data/trace/` writable by the mapped Engine UID. The config
requires request-body inspection and turns off raw audit capture. External
GeoIP and request fingerprint dumps are outside this private fixture.

Keep the security state and credentials directories at mode `0700`, owned by
the host-mapped security UID for container UID 65532. Use read-only bind mounts
for configuration and apply the shared SELinux `container_file_t` label:

| Relative path                    | Host-side authority                                                                                                                                                                   |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `security/spoe/`                 | Mapped SPOA UID owns it. Setgid mode `2750`, group equal to the HAProxy container's mapped GID 99. SPOA creates `spoa.sock` with mode `0660`. HAProxy mounts the directory read-only. |
| `security/audit/haproxy.log`     | Runtime account owns the file. Mode `0640`, group equal to the security container's mapped GID 65532. Stage the file before startup. Engine reads only the audit directory.           |
| `security/state/`                | SQLite and machine credential file. Keep across container recreation.                                                                                                                 |
| `security/credentials/spoa.yaml` | Mode `0400` or `0600` for the mapped security UID. Only SPOA mounts this directory.                                                                                                   |

Use the host subordinate GIDs for the two ownership assignments. Run the
first command in the application account and the second in the security
account, each with its own Podman store:

```bash
podman unshare cat /proc/self/gid_map | awk '$1 <= 99 && 99 < $1 + $3 {print $2 + 99 - $1}'
podman unshare cat /proc/self/gid_map | awk '$1 <= 65532 && 65532 < $1 + $3 {print $2 + 65532 - $1}'
```

The administrator gives `spoe/` the first GID so `spoa.sock` inherits that
group. Give `audit/haproxy.log` the second GID so Engine can read the record.
Use the security account's `uid_map` to derive the host owner for its mapped
UID 65532. Verify the socket's actual group and mode after startup. Verify the
runtime account cannot read the SPOA credential file.

For a fresh security slot, use `/usr/local/bin/cscli` from the exact admitted
engine image. Run it with `--network=none`, `--user 65532:65532`, internal
`/state:rw` and `/etc/crowdsec:ro` mounts, and
`-c /etc/crowdsec/config.yaml`. Run `machines add --auto --file
/state/machine.yaml --url http://127.0.0.1:8080`, then
`bouncers add <fixture-bouncer-name> --output json`. Capture the key in protected
runtime custody and supply the following shape as `spoa.yaml`. Keep command
tracing off. Validate the engine configuration with the same image and mounts
using `/usr/local/bin/crowdsec -c /etc/crowdsec/config.yaml -t`.

```yaml
log_mode: stdout
log_level: info
api_url: http://engine:8080/
api_key: <protected fixture credential>
update_frequency: 10s
insecure_skip_verify: false
listen_unix: /run/secpal-spoa/spoa.sock
appsec_url: http://engine:7422/
appsec_timeout: 500ms
prometheus:
  enabled: false
```

In the **security** user manager run `systemctl --user daemon-reload` and
`systemctl --user start "$prefix-spoa.service"`. Start the gateway via the
**application** user manager with the generated `edge/spoe.cfg` staged beside
its HAProxy configuration. Check the valid HTTPS backends and a controlled
AppSec rejection. The engine's read-only log acquisition uses the fixed HAProxy
metadata record to detect repeated authentication failures. That detection
generates local alerts without sending firewall rules. Host nftables owns all
host network enforcement.

The lab body limit is 32 KiB. Larger requests send metadata and record
`appsec_headers_only`. A WAF block returns 403. If the SPOA listener is down,
the gateway logs `security_degraded` and continues application traffic. If
SPOA is online but AppSec is unreachable, SPOA 0.3.1 records the AppSec failure
in its own journal and retains existing remediation. Treat this diagnostic as
Security DEGRADED. Gateway `accepted` describes routing and does not certify
inspection. Check the security health independently of `/health/ready`.

At cleanup stop the gateway and socket, then stop the exact security slot's
SPOA and Engine user services. Remove only that slot's security units, internal
network and `security/` directory after preserving the bounded evidence. A
disposable security account can then be removed if it owns no other slots.

## Initialize, verify and restart

Run through the host's admitted runtime user and user manager. The examples
assume the PoC instance and namespace above.

```bash
prefix=secpal-int-labpoc01
systemctl --user daemon-reload
systemctl --user start "$prefix-secrets-init.service"
systemctl --user start "$prefix-postgres.service"
systemctl --user start "$prefix-migrate.service"
systemctl --user start "$prefix-gateway.service" "$prefix-scheduler.service" \
  "$prefix-worker-general.service" "$prefix-worker-hash-chain.service"
```

Only initialize a fresh fixture. The initializer creates disposable local
credentials and PostgreSQL TLS material. It uses the same database role for
runtime and migration as the synthetic integration fixture. The two explicit
one-shots are outside the normal boot dependency chain. The worker, scheduler
and gateway units start through the existing lingering user manager.

Create a random 48-character hexadecimal synthetic account password in a
private file. Run `scripts/seed-fcos-application-poc.php` with PHP inside the
admitted fixture's FPM container, supplying the password on stdin. For example,
on the guest with the reviewed script available to the runtime user:

```bash
podman exec -i "$prefix-php-fpm" php -r "$(tail -n +2 /private/seed-fcos-application-poc.php)" \
  < /private/fixture-password
```

Verify PostgreSQL readiness and TLS/SCRAM, HTTPS with normal certificate
validation, and login and authenticated organization reads with the synthetic
account. Verify the same organization ID in PostgreSQL. For a persistence
check, stop the exact eight running role services, start PostgreSQL, then start
the gateway and background services as above. Check that the database
container was recreated, the cluster identifier and volume stayed the same
and the authenticated record remains. The restart skips both one-shots.

For teardown, verify the fixture instance, container/volume ownership and
database identity. Stop only its services, including both one-shots. Remove
only its named volumes, private networks, added gateway tag, unit files and
staged directory, then reload the user manager. Verify that the fixture is
absent and the pre-existing applications and volumes are healthy.

## Separate runtime and migration authority on a fresh fixture

Add `--least-privilege --evidence-validator /reviewed/governance/scripts/secpal-evidence-architecture.py`
to the stack render command and use a new instance. Select the validator
from the maintained governance checkout. Rendering requires dispatch
admission for this source and fails closed if a trusted operation lacks its
declared semantic diagnostic. The validator, its checked-in parser sources
and dependency lock must match the accepted governance source pin. Use the
maintained parser dependencies in that checkout. Stage only the admitted bundle. The guest
helper returns the bounded failure stage while suppressing command output.
The resulting bundle implements the lab portion of
[#426](https://github.com/SecPal/deployment/issues/426), using the role pattern
from [#100](https://github.com/SecPal/deployment/issues/100). Follow the
HTTPS and host admission steps above. Use this startup sequence in place of
the shared-role startup:

```bash
prefix=secpal-int-labpoc01
roles=/var/lib/secpal-application-poc/labpoc01/assets/fcos-poc-db-roles.sh
systemctl --user daemon-reload
systemctl --user start "$prefix-secrets-init.service"
bash "$roles" prepare labpoc01
systemctl --user start "$prefix-postgres.service"
bash "$roles" migrate labpoc01
systemctl --user start "$prefix-gateway.service" "$prefix-scheduler.service" \
  "$prefix-worker-general.service" "$prefix-worker-hash-chain.service"
```

Seed the synthetic user as above. Wait for API readiness before login. The
helper accepts only a rootless slot with the generated separation label. It
prepares credential subpaths before PostgreSQL starts and requires an empty
cluster for the initial role installation. If the migration fails, diagnose
the returned stage within the disposable slot and check that the migration
login was retired before any retry. This initial bootstrap is for fresh
fixtures, not an upgrade procedure for existing databases.

- `secpal_owner` owns the database, application schema and migration-created
  tables. It has no login. The migration login can explicitly assume the
  owner role through `secpal_migration`; it has no cluster-wide administrative
  attributes.
- `secpal_poc_runtime` inherits `secpal_runtime` only. It can connect to
  `secpal`, use `public`, perform application DML and use sequences. Defaults
  apply to new tables and sequences created by `secpal_owner`. The runtime
  grant on the migration ledger is read-only. The runtime has no schema
  creation, ownership, temporary-object, cluster-wide or unrelated database
  privileges. [PostgreSQL default privileges](https://www.postgresql.org/docs/18/sql-alterdefaultprivileges.html)
- Bootstrap administration uses the isolated DB container's local socket.
  Runtime and migration connections use `DB_SSLMODE=verify-full` with the
  fixture PostgreSQL CA from the role-specific mount. They authenticate
  with SCRAM. Only the migrator mounts the migration credential subpath. The
  migration login has a ten-minute maximum initial validity. The helper
  starts the explicit Laravel migration, records its success, disables and
  clears the migration login, stops the unit and removes the credential
  files. Ordinary FPM, worker and scheduler units mount only their own
  runtime database and application credential subpaths.

### Execute the database and application checks

From the isolated PostgreSQL container using its local fixture administrator,
create an empty witness as the owner after the migration:

```bash
podman exec -i "$prefix-postgres" psql -X -v ON_ERROR_STOP=1 \
  -U secpal_fixture_admin -d secpal <<'SQL'
SET ROLE secpal_owner;
CREATE TABLE public.fcos_privilege_witness (
  id bigint GENERATED ALWAYS AS IDENTITY, marker text NOT NULL
);
SQL
podman exec -i "$prefix-php-fpm" php \
  < tests/fcos-poc-database-authority.php
```

The PHP probe uses the actual application PDO session and runtime credential.
It requires TLS and verifies that the future table and its identity sequence
support runtime DML. It runs each denied SQL operation in its own rollback
transaction and requires SQLSTATE `42501`. This covers table creation,
alteration, drop and truncate, schema/function/sequence/temp creation,
migration ledger writes, role assumption, superuser promotion and auth
catalog reads. It also requires PostgreSQL to reject plaintext and
unrelated-database connections.

Using the normal private HTTPS endpoint, log in with the synthetic user, call
`/v1/me`, read the seeded organization and create a separate synthetic holding
through `POST /v1/organizational-units`. Refresh the CSRF token after login
before the POST. Read back the exact ID through the API and through the
runtime's PostgreSQL connection. Dispatch one synthetic job to each existing
worker queue and observe consumption. Check the scheduler's normal service.
Capture the migration login authorization, ledger and object owners from
PostgreSQL. Verify that the retired login and credential mount are absent from
ordinary runtime processes.

Repeat the API, SQL and permission checks after recreating the application
containers, then after recreating PostgreSQL with its retained volume.
Compare the original cluster ID, ledger and roles and verify that the
migration unit stayed inactive. The observed PostgreSQL 18.6 lab run applied
86 Laravel migrations in one batch. It passed the application and worker
checks and rejected all 15 SQL denial probes before and after recreation.
The raw qualification report remains in private evidence.

The bootstrap socket is local to this disposable database container. The
test uses one rootless host operator and synthetic, filesystem-scoped
credentials. Production credential issuance and custody, rotation of an
activated deployment, per-workload policy, and broader PG18 infrastructure
qualification retain their existing owners.

## ARM64 PostgreSQL process-crash qualification

Use the least-privilege procedure above for a disposable slot on an admitted
aarch64 FCOS host. Render a new instance and omit the gateway's
`PublishPort` setting before staging. Require empty `podman port` output
for all slot containers. Run frontend and API probes inside the isolated
gateway network namespace with certificate validation and the expected
HTTPS hostname. Keep the established application and its database running.

Resolve the reviewed PostgreSQL OCI index to its `linux/arm64/v8` child,
verify both manifest digests and the child configuration digest, and compare
that configuration identity and architecture with the image used by the
running container. In the PostgreSQL 18.6 run, the Docker Official
`docker.io/library/postgres` index was
`sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af`.
The native image manifest was
`sha256:4d155aa3f2c2cc1838bb70e81396f76373ec7275ec9ce9cf32873cd677c9a992`.
Its configuration digest was
`sha256:b85269e8c6aa961524542eb4dcca44c4aa1deba2cf507e9e28d5ba8f971aeab9`.
The fixture's Podman start event identified the exact index reference.
Podman resolved that reference to the configuration digest and reported
`linux/arm64`. To check a running fixture, use its admitted container ID:

```bash
image_id="$(podman container inspect --format '{{.Image}}' "$container_id")"
podman image inspect --format '{{.Id}} {{.Os}}/{{.Architecture}}' "$image_id"
```

Require the image ID to match the child configuration digest with or without
the `sha256:` prefix, and require the platform to be `linux/arm64`.

Use the application's PostgreSQL connection for both test transactions.
Require `fsync`, `full_page_writes` and `synchronous_commit` to be on
and the witness table to be permanent and WAL-logged. In one runtime
session, begin a transaction, insert a unique marker into the witness table
and keep the session open. Capture its transaction ID and WAL insert LSN.
In another runtime session, insert a different marker, commit, wait for
the successful client acknowledgment and record the WAL flush LSN. Before
signaling, verify that the held transaction is still active, its insert LSN
is covered by the flush LSN and only the acknowledged row is visible to a
third session. Keep the test window bounded.
[PostgreSQL WAL settings](https://www.postgresql.org/docs/18/runtime-config-wal.html)

Immediately before the crash, verify the authenticated host, immutable
container ID, independent database system identifier, distinct external
named volume, private PID namespace and internal Podman network. Compare
these with the live application's database and abort on any ambiguity.
Within the verified disposable container ID, read the postmaster PID from
`$PGDATA/postmaster.pid`, compare its executable with the installed
PostgreSQL binary and send SIGKILL only to that process. Capture the
container's exit status and the PostgreSQL journal/log lines establishing
automatic WAL recovery with redo start, redo completion and readiness.
Distinguish the automatic Quadlet/systemd restart from the subsequent
controlled container recreation.

Compare the database system identifier, schema dump with randomized
`pg_dump` restriction delimiters excluded, migration ledger, object
ownership and effective grants. Read back the exact acknowledged witness
and synthetic API record. Verify the open transaction's marker is absent.
Repeat the runtime denial probe and verify that the migration unit is
inactive, its login is disabled, and its credentials remain absent from
the runtime. Repeat the authenticated API, worker, scheduler and persistence
checks after the controlled recreation. Preserve bounded private evidence
before cleaning up only the disposable slot.

The ARM64 run recorded one Podman exit with status 137 and one automatic
systemd restart. PostgreSQL replayed WAL and opened the same cluster on the
same volume. The acknowledged transaction and exact synthetic API record
survived. The uncommitted marker was absent despite its WAL insert LSN
being covered by the pre-crash flush LSN. The schema, 86-entry migration
ledger, role memberships, object ownership and grants matched after WAL
recovery and clean container recreation. The runtime still received
SQLSTATE `42501` for all 15 denied SQL operations. PostgreSQL rejected both
plaintext and unrelated database connections. The migration login stayed
disabled and neither restart ran a migration. The private HTTPS API and
both workers passed their functional checks after both restarts.
SELinux remained Enforcing and the slot was removed after qualification.

This run qualifies recovery from a PostgreSQL process crash with the guest
kernel and backing storage still running. Host power loss, loss of the
storage device, PostgreSQL HA, archive recovery and production secret
authority require separate evidence. Issue #426 retains the broader
PostgreSQL acceptance and the reference to the private report.
[PostgreSQL infrastructure qualification](https://github.com/SecPal/deployment/issues/426)

## Cross-host logical restore

The restore bundle runs only PostgreSQL, API and FPM on a new internal network
and separate volumes. It has no published port, boot activation, frontend,
scheduler or workers. Render it from the same reviewed source:

```bash
python3 scripts/render-fcos-application-poc.py \
  --profile restore --instance labrestore01 --output /private/qualification/restore
```

Select a synthetic record already confirmed through the source API and SQL.
Capture the schema, record and any file dependencies. Stream a consistent
`pg_dump --format=custom` through pinned SSH into encrypted off-source
storage. Keep decryption material separately protected. Verify the archive
digest, table of contents and full decoding before admitting a restore.

Stage the restore bundle on a different authenticated host. Wait for
`secrets-init` to complete successfully before starting `postgres`.
Check a fresh empty schema, independent cluster
identity and named volume, then stream the authenticated archive to
`pg_restore --single-transaction --exit-on-error --no-owner --no-acl` on that
cluster. Apply the schema from the archive. Compare the schema and exact
synthetic record, start the API and verify unauthenticated rejection and an
authenticated read within its internal network. Use an isolated test token
and revoke it after the read. Recreate the PostgreSQL container and repeat
the checks. Preserve bounded evidence and follow the scoped cleanup above.

This checks logical restoration of the exercised state. It leaves WAL/PITR,
retention, independent recovery-crypto custody, private object recovery,
RecoverySets and production activation to their existing contracts.
